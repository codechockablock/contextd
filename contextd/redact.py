"""The immutable secret-redaction floor.

Two rules, both load-bearing (docs/SECURITY.md §6):

1. **The floor always runs.** User configuration under ``[gate.redact]`` is
   *additive*. A config entry cannot remove a floor class, and a config entry
   reusing a floor class name does not replace it — both patterns apply. The
   old semantics ("overriding [gate.redact] replaces the whole set") let a
   caller who could write config.toml switch redaction off; under the current
   threat model that caller is the attacker.

2. **The floor is a pinned list, not a completeness claim.** Each class here
   has a planted-positive and a negative test in tests/test_privacy_boundary.py.
   A secret of an unlisted shape passes through. Regex redaction is a floor;
   nothing in this package may describe it as complete privacy.
"""

import re
import unicodedata
from types import MappingProxyType

# name -> pattern. Immutable at runtime; adding a class requires adding its
# tests in the same change.
FLOOR: MappingProxyType = MappingProxyType({
    "api_key": r"\b(?:sk|pk)-[A-Za-z0-9_-]{16,}",
    "openai_key": r"\bsk-proj-[A-Za-z0-9_-]{16,}",
    "anthropic_key": r"\bsk-ant-[A-Za-z0-9_-]{16,}",
    "google_api_key": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "aws_key": r"\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\b",
    "github_token": r"\b(?:ghp|gho|ghs|ghu|ghr|github_pat)_[A-Za-z0-9_]{22,}\b",
    "slack_token": r"\bxox[bpars]-[A-Za-z0-9-]{10,}\b",
    "jwt": r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "private_key": (
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[A-Za-z0-9+/=\r\n]*"
        r"(?:-----END [A-Z ]*PRIVATE KEY-----)?"
    ),
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    # auth-shaped query params in URLs (?code=, &access_token=, ...), including
    # %-encoded ones nested in redirect values (%26state%3D...)
    "url_param": (
        r"(?i)(?:[?&#]|%26|%3f|%23)[a-z0-9_.-]*"
        r"(?:code|token|auth|nonce|state|secret|passw|pwd|sig|session|key|otp|"
        r"ticket|csrf|xsrf|sso|jwt|bearer)[a-z0-9_.-]*(?:=|%3d)[^&\s\"'<>]+"
    ),
    "card": r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,4}\b",
    "bearer_header": r"(?i)\b(?:authorization\s*:\s*)?bearer\s+[A-Za-z0-9._~+/=-]{16,}",
    "basic_auth_url": r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:[^\s/@]+@",
    "password_assignment": (
        r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|"
        r"client[_-]?secret)\b\s*[:=]\s*[\"']?[^\s\"',;}\]]{8,}"
    ),
})

_FLOOR_COMPILED = tuple(
    (name, re.compile(pattern)) for name, pattern in FLOOR.items()
)

# Bounds applied to every declared free-text field before persistence. Long
# strings are both a disclosure surface and a denial-of-service surface.
MAX_TEXT = 2000
MAX_LABEL = 64


class RedactionError(ValueError):
    """A configured extension pattern is not a usable regex."""


def _extras(cfg) -> tuple:
    """Config-supplied patterns, applied *after* the floor and never instead
    of it. A config key colliding with a floor name is kept under a distinct
    display name so the floor class stays legible in output."""
    table = ((cfg or {}).get("gate") or {}).get("redact") or {}
    out = []
    for name, pattern in table.items():
        label = f"config.{name}" if name in FLOOR else str(name)
        try:
            out.append((label, re.compile(pattern)))
        except (re.error, TypeError) as exc:
            raise RedactionError(f"invalid [gate.redact] pattern {name!r}: {exc}") from exc
    return tuple(out)


def redact(cfg, text: str) -> str:
    """Apply the immutable floor, then any configured extensions."""
    if not text:
        return text
    for name, rx in _FLOOR_COMPILED:
        text = rx.sub(f"[REDACTED:{name}]", text)
    for name, rx in _extras(cfg):
        text = rx.sub(f"[REDACTED:{name}]", text)
    return text


_CONTROL_RX = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class SanitizationError(ValueError):
    """A declared field carried a value the schema cannot sanitize."""


def sanitize_text(cfg, text, max_len: int = MAX_TEXT) -> str:
    """Field-specific sanitization for a *declared* free-text field.

    Redaction floor, then control-character removal (control bytes smuggle
    terminal escapes into `ctx audit` output and split patterns across a
    match boundary), then NFC normalization, then a hard length bound.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        raise SanitizationError(f"expected text, got {type(text).__name__}")
    value = unicodedata.normalize("NFC", text)
    value = _CONTROL_RX.sub("", value)
    value = redact(cfg, value)
    if len(value) > max_len:
        value = value[:max_len] + "…[truncated]"
    return value


_LABEL_RX = re.compile(r"[^A-Za-z0-9._:-]+")


def sanitize_label(cfg, text, max_len: int = MAX_LABEL) -> str:
    """A bounded, charset-restricted diagnostic label (``claimed_client``).

    The floor runs first, then the charset filter, then a hard 64-character
    bound. The charset filter — not merely redaction — is what makes a
    fully caller-controlled field safe: a secret of an *unlisted* shape still
    loses every character outside ``[A-Za-z0-9._:-]`` and is cut at 64, so it
    cannot survive intact. Nothing here claims it survives *unrecognisably*;
    the claim is only that this field is bounded and floor-redacted.
    """
    if not text:
        return ""
    if not isinstance(text, str):
        raise SanitizationError(f"expected label, got {type(text).__name__}")
    value = unicodedata.normalize("NFC", text)
    value = _CONTROL_RX.sub("", value)
    value = redact(cfg, value)
    value = _LABEL_RX.sub("-", value).strip("-")
    return value[:max_len]
