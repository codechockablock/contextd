"""Canonical byte encoding for signed objects.

Signature substitution bugs live in the gap between "these two structures are
equal" and "these two structures encode to the same bytes". JSON is the usual
source: number formatting, escaping, key ordering, and Unicode normalization
all vary across languages, and each variance is a place where a signature over
one structure verifies against a different one.

This encoding removes the ambiguity class:

    canonical(domain, value) := utf8(domain) || b"\\n" || enc(value)

    enc(str)   := b"s" || u64_be(len(utf8)) || utf8      # NFC required
    enc(int)   := b"i" || i64_be(value)                  # bool is NOT an int
    enc(list)  := b"l" || u64_be(n) || enc(v) for each v
    enc(map)   := b"m" || u64_be(n) || (enc_key || enc(v)) for keys sorted by
                  their UTF-8 bytes; enc_key is the string form above

Every value is length-prefixed and type-tagged, so no two distinct structures
share an encoding, and a decoder is never required (the verifier re-encodes the
structure it was given and compares).

Refused unconditionally:

    float       IEEE-754 round-tripping is not reproducible across languages,
                and no field in OperatorActionV1 needs one
    bool        would otherwise encode identically to 0/1
    None        absence must be expressed by omitting the key, not by a value
    bytes       every field is text or an integer by construction
    non-NFC     two visually identical strings with different code points must
                not produce two different signatures
    int outside int64
    non-string map keys

`tests/vectors/operator_action_v1.json` freezes input → bytes → digest so a
second implementation in another language can be checked against these exact
bytes, and so any change to this file breaks visibly.
"""

import hashlib
import struct
import unicodedata

MAX_DEPTH = 8
MAX_ITEMS = 4096


class CanonicalError(ValueError):
    """A value cannot be canonically encoded."""


def _u64(n: int) -> bytes:
    if not (0 <= n < 2**64):
        raise CanonicalError("length out of range")
    return struct.pack(">Q", n)


def _enc_str(value: str) -> bytes:
    if unicodedata.normalize("NFC", value) != value:
        raise CanonicalError(
            "string is not NFC-normalized; two visually identical strings must "
            "not produce two different signatures"
        )
    raw = value.encode("utf-8")
    return b"s" + _u64(len(raw)) + raw


def _enc(value, depth: int = 0) -> bytes:
    if depth > MAX_DEPTH:
        raise CanonicalError("structure exceeds the canonical depth bound")
    if isinstance(value, bool):
        raise CanonicalError(
            "bool is refused: it would encode identically to an integer"
        )
    if isinstance(value, float):
        raise CanonicalError(
            "float is refused: IEEE-754 round-tripping is not reproducible "
            "across languages"
        )
    if value is None:
        raise CanonicalError("None is refused: omit the key instead")
    if isinstance(value, bytes):
        raise CanonicalError("bytes is refused: every field is text or integer")
    if isinstance(value, str):
        return _enc_str(value)
    if isinstance(value, int):
        if not (-(2**63) <= value < 2**63):
            raise CanonicalError("integer out of int64 range")
        return b"i" + struct.pack(">q", value)
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_ITEMS:
            raise CanonicalError("list exceeds the canonical item bound")
        return b"l" + _u64(len(value)) + b"".join(
            _enc(v, depth + 1) for v in value
        )
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS:
            raise CanonicalError("map exceeds the canonical item bound")
        for key in value:
            if not isinstance(key, str):
                raise CanonicalError("map keys must be strings")
        # sort by UTF-8 bytes, not by locale or code point order
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-8"))
        return b"m" + _u64(len(items)) + b"".join(
            _enc_str(k) + _enc(v, depth + 1) for k, v in items
        )
    raise CanonicalError(f"unsupported type {type(value).__name__}")


def canonical_bytes(domain: str, value) -> bytes:
    """The exact bytes a signature covers.

    ``domain`` is a fixed domain separator, so a signature over one object type
    can never verify as another.
    """
    if not domain or "\n" in domain:
        raise CanonicalError("domain separator must be non-empty and newline-free")
    return domain.encode("utf-8") + b"\n" + _enc(value)


def canonical_digest(domain: str, value) -> str:
    return hashlib.sha256(canonical_bytes(domain, value)).hexdigest()
