"""OperatorActionV1: the only thing in contextd that grounds "the operator".

Design and responsibilities: docs/adr/0001-two-plane-authority.md §2.
Threat model and excluded claims: docs/SECURITY.md §5.

Shape of the mechanism:

1. A caller asks the authority plane to *prepare* an action. The caller
   proposes an intent; the authority plane decides the exact bytes — it mints
   the nonce and the monotonic sequence, canonicalizes the scope, normalizes
   the arguments, and digests the content and reason. A caller that could
   choose the nonce could pre-collect signatures; a caller that could pass
   `arguments` through verbatim could smuggle unnormalized scope past the
   schema.
2. The operator signs those exact canonical bytes with a non-exportable
   Secure Enclave P-256 key, which the platform releases only after a fresh
   user-presence gesture. Cancelling the gesture produces no signature, and
   therefore no append.
3. The authority plane verifies the signature against a registered key,
   re-deriving the canonical bytes from the action it was given rather than
   trusting any digest the caller supplied.
4. The nonce is consumed **inside the same critical section as the append**,
   so one authorization can never produce two events.

What a verified action proves is exactly one sentence, and it is not authorship,
comprehension, truth, or provider receipt — see docs/SECURITY.md §5.
"""

import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key

from . import home
from .assurance import INSECURE_TEST_SIGNER, OPERATOR_AUTHORIZED, Attestation
from .canonical import CanonicalError, canonical_bytes, canonical_digest

DOMAIN = "contextd.OperatorActionV1"
PROTOCOL_VERSION = 1

#: Exactly these twelve keys, all required. Unknown keys are refused.
ACTION_FIELDS = (
    "domain", "version", "archive_uuid", "key_id", "nonce", "sequence",
    "issued_at", "expires_at", "action", "scope", "arguments",
    "content_digest", "reason_digest",
)

#: Closed action-class registry. A class not listed here cannot be authorized.
ACTION_CLASSES = frozenset({
    "note.deliberate",
    "loop.add", "loop.confirm", "loop.close", "loop.reopen", "loop.dismiss",
    "grant.add", "grant.revoke",
    "decision.supersede",
    "outcome.judge",
    "archive.raw_read", "archive.export", "archive.backup", "archive.restore",
    "security.policy", "security.key_register", "security.key_revoke",
})

DEFAULT_TTL_SECONDS = 300
MAX_TTL_SECONDS = 900
EMPTY_DIGEST = hashlib.sha256(b"").hexdigest()

SIGNER_SECURE_ENCLAVE = "secure_enclave"
SIGNER_TEST = INSECURE_TEST_SIGNER

#: Set to "1" to permit the software test signer. Refused unless the archive is
#: also an isolated temporary one (see `_assert_test_mode_ok`).
TEST_MODE_ENV = "CONTEXTD_INSECURE_TEST_SIGNER"


class AttestationError(RuntimeError):
    """An operator action could not be prepared, signed, or verified."""


# --- state --------------------------------------------------------------

def state() -> sqlite3.Connection:
    """A connection to the archive, which is also where authority state lives.

    The nonce table sits in the same SQLite file as `events` so that consuming
    an authorization and appending the event it authorizes are one transaction
    (contextd/db.py SCHEMA explains why). In a hardened deployment that file is
    owned by the service UID and unreadable from the client plane; that is what
    makes the key registry meaningful. In development it is same-UID, and
    `ctx security doctor` reports that rather than letting it pass silently.
    """
    from .db import connect
    return connect()


def archive_uuid(conn: sqlite3.Connection | None = None) -> str:
    """A stable identifier for this archive, minted once.

    It binds a signature to *this* archive, so an action captured from one
    archive cannot be replayed into another.
    """
    own = conn is None
    conn = conn or state()
    try:
        row = conn.execute(
            "SELECT uuid FROM archive_identity WHERE singleton = 1"
        ).fetchone()
        if row:
            return row["uuid"]
        value = secrets.token_hex(16)
        conn.execute(
            "INSERT OR IGNORE INTO archive_identity(singleton, uuid) VALUES (1, ?)",
            (value,),
        )
        conn.commit()
        return conn.execute(
            "SELECT uuid FROM archive_identity WHERE singleton = 1"
        ).fetchone()["uuid"]
    finally:
        if own:
            conn.close()


# --- key registry -------------------------------------------------------

def key_id_for(public_der: bytes) -> str:
    """SHA-256 of the SubjectPublicKeyInfo. Naming a key by its own bytes means
    a registry entry cannot claim to be a key it is not."""
    return hashlib.sha256(public_der).hexdigest()


def register_key(public_der: bytes, signer: str, conn=None) -> str:
    own = conn is None
    conn = conn or state()
    try:
        key = load_der_public_key(public_der)
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise AttestationError(
                "operator keys are P-256 (Secure Enclave). An Ed25519 or "
                "RSA key is not an equivalent substitute."
            )
        if signer not in (SIGNER_SECURE_ENCLAVE, SIGNER_TEST):
            raise AttestationError(f"unknown signer kind {signer!r}")
        if signer == SIGNER_TEST:
            _assert_test_mode_ok()
        kid = key_id_for(public_der)
        conn.execute(
            "INSERT OR REPLACE INTO operator_keys(key_id, public_der, signer, "
            "registered, revoked) VALUES (?,?,?,?, NULL)",
            (kid, public_der, signer, _now_iso()),
        )
        conn.commit()
        return kid
    finally:
        if own:
            conn.close()


def revoke_key(key_id: str, conn=None) -> None:
    own = conn is None
    conn = conn or state()
    try:
        conn.execute(
            "UPDATE operator_keys SET revoked = ? WHERE key_id = ? AND revoked IS NULL",
            (_now_iso(), key_id),
        )
        conn.commit()
    finally:
        if own:
            conn.close()


def registered_keys(conn=None) -> list[dict]:
    own = conn is None
    conn = conn or state()
    try:
        return [
            {"key_id": r["key_id"], "signer": r["signer"],
             "registered": r["registered"], "revoked": r["revoked"]}
            for r in conn.execute("SELECT * FROM operator_keys ORDER BY registered")
        ]
    finally:
        if own:
            conn.close()


def _lookup_key(conn, key_id: str):
    row = conn.execute(
        "SELECT * FROM operator_keys WHERE key_id = ?", (key_id,)
    ).fetchone()
    if row is None:
        raise AttestationError(f"no registered operator key {key_id[:12]}…")
    if row["revoked"] is not None:
        raise AttestationError(
            f"operator key {key_id[:12]}… was revoked at {row['revoked']}"
        )
    return row


# --- building the exact bytes ------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _digest(text) -> str:
    """Digest of the exact bytes the archive will store — i.e. post-redaction.

    Digesting the pre-redaction text would make the signature cover something
    the archive never holds, and the verifier's `matches()` would then have to
    be given the raw secret to check against.
    """
    if text is None or text == "":
        return EMPTY_DIGEST
    if not isinstance(text, str):
        raise AttestationError("only text can be digested into an action")
    from .redact import redact
    normalized = redact(None, unicodedata.normalize("NFC", text))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def canonical_scope(scope: str) -> str:
    """The exact scope string that gets signed.

    The floor runs *here*, before signing, for two reasons. First, a repo path
    is caller-influenced text and the signed action is persisted verbatim in
    the event's attestation block — an unredacted scope would walk straight
    past the closed schema's own scope redaction. Second, signer and verifier
    must agree on the bytes, so redaction has to happen on one side of the
    signature, and "before" is the only side that keeps the archive clean.
    """
    from .redact import redact
    if not isinstance(scope, str) or not (
        scope == "global" or scope.startswith("repo:")
    ):
        raise AttestationError("scope must be 'global' or 'repo:<path>'")
    return redact(None, unicodedata.normalize("NFC", scope))[:4096]


def _normalize_arguments(arguments: dict | None) -> dict:
    """Arguments are normalized by the authority plane, never taken verbatim.

    Only strings and integers, keys sorted by the canonical encoder, strings
    NFC-normalized and bounded. Anything else is refused rather than coerced —
    a coercion is a place where the signed bytes and the executed act can drift
    apart.
    """
    out: dict = {}
    for key, value in (arguments or {}).items():
        if not isinstance(key, str) or len(key) > 64:
            raise AttestationError("argument names must be short strings")
        if isinstance(value, bool) or value is None:
            raise AttestationError(f"argument {key!r} must be a string or integer")
        if isinstance(value, int):
            out[key] = value
        elif isinstance(value, str):
            if len(value) > 512:
                raise AttestationError(f"argument {key!r} exceeds its bound")
            # same reasoning as canonical_scope: redact before signing
            from .redact import redact
            out[key] = redact(None, unicodedata.normalize("NFC", value))
        else:
            raise AttestationError(
                f"argument {key!r} has unsupported type {type(value).__name__}"
            )
    return out


def prepare_action(
    key_id: str,
    action: str,
    scope: str = "global",
    arguments: dict | None = None,
    content: str | None = None,
    reason: str | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    conn=None,
) -> dict:
    """Mint the exact action the operator will be asked to sign.

    Returns ``{"action": <map>, "canonical": <hex>, "digest": <hex>,
    "human_summary": <str>}``. The caller displays the summary; the daemon
    keeps the nonce.
    """
    own = conn is None
    conn = conn or state()
    try:
        if action not in ACTION_CLASSES:
            raise AttestationError(
                f"unknown action class {action!r}; registry: "
                f"{', '.join(sorted(ACTION_CLASSES))}"
            )
        if not (0 < ttl_seconds <= MAX_TTL_SECONDS):
            raise AttestationError(
                f"ttl must be in (0, {MAX_TTL_SECONDS}]; an authorization that "
                f"never expires is a standing signature"
            )
        _lookup_key(conn, key_id)
        scope = canonical_scope(scope)

        issued = int(time.time())
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT value FROM operator_sequence WHERE singleton = 1"
        ).fetchone()
        sequence = (row["value"] if row else 0) + 1
        conn.execute(
            "INSERT INTO operator_sequence(singleton, value) VALUES (1, ?) "
            "ON CONFLICT(singleton) DO UPDATE SET value = excluded.value",
            (sequence,),
        )
        act = {
            "domain": DOMAIN,
            "version": PROTOCOL_VERSION,
            "archive_uuid": archive_uuid(conn),
            "key_id": key_id,
            "nonce": secrets.token_hex(32),
            "sequence": sequence,
            "issued_at": issued,
            "expires_at": issued + int(ttl_seconds),
            "action": action,
            "scope": scope,
            "arguments": _normalize_arguments(arguments),
            "content_digest": _digest(content),
            "reason_digest": _digest(reason),
        }
        digest = canonical_digest(DOMAIN, act)
        conn.execute(
            "INSERT INTO operator_nonces(nonce, key_id, sequence, issued_at, "
            "expires_at, action, digest, consumed_event) "
            "VALUES (?,?,?,?,?,?,?, NULL)",
            (act["nonce"], key_id, sequence, act["issued_at"],
             act["expires_at"], action, digest),
        )
        conn.commit()
        return {
            "action": act,
            "canonical": canonical_bytes(DOMAIN, act).hex(),
            "digest": digest,
            "human_summary": human_summary(act),
        }
    except BaseException:
        conn.rollback()
        raise
    finally:
        if own:
            conn.close()


def human_summary(act: dict) -> str:
    """What the client shows before asking for the presence gesture.

    This is a convenience for the human, not an assurance: docs/SECURITY.md §5
    is explicit that a signature is not evidence the human read anything.
    """
    args = ", ".join(f"{k}={v!r}" for k, v in sorted(act["arguments"].items()))
    expires = datetime.fromtimestamp(
        act["expires_at"], timezone.utc
    ).isoformat(timespec="seconds")
    return (
        f"{act['action']} on {act['scope']}"
        + (f" ({args})" if args else "")
        + f" — archive {act['archive_uuid'][:8]}…, seq {act['sequence']}, "
        + f"expires {expires}"
    )


# --- verification -------------------------------------------------------

@dataclass(frozen=True)
class Authorization:
    """A verified operator authorization, ready to be consumed exactly once."""

    action: dict
    signature: bytes
    key_id: str
    signer: str
    verified_at: str

    @property
    def assurance(self) -> str:
        return (
            OPERATOR_AUTHORIZED if self.signer == SIGNER_SECURE_ENCLAVE
            else INSECURE_TEST_SIGNER
        )

    @property
    def digest(self) -> str:
        return canonical_digest(DOMAIN, self.action)

    @property
    def nonce(self) -> str:
        return self.action["nonce"]

    def stored_block(self) -> dict:
        """The attestation block persisted in the event's metadata."""
        return {
            "action": self.action,
            "signature": self.signature.hex(),
            "key_id": self.key_id,
            "signer": self.signer,
            "verified_at": self.verified_at,
        }

    def attestation(self) -> Attestation:
        return Attestation(
            key_id=self.key_id, action_digest=self.digest,
            signer=self.signer, verified_at=self.verified_at,
        )

    def matches(self, action: str, scope: str, arguments: dict | None = None,
                content: str | None = None, reason: str | None = None) -> bool:
        """Does this authorization cover *exactly* the act about to happen?

        Content and reason are compared by digest of the post-redaction text
        the archive will actually store, so a canary in either cannot ride
        into the attestation block.
        """
        act = self.action
        return (
            act["action"] == action
            and act["scope"] == canonical_scope(scope)
            and act["arguments"] == _normalize_arguments(arguments)
            and act["content_digest"] == _digest(content)
            and act["reason_digest"] == _digest(reason)
        )


def _validate_action_shape(act) -> None:
    if not isinstance(act, dict):
        raise AttestationError("action must be a mapping")
    unknown = set(act) - set(ACTION_FIELDS)
    if unknown:
        raise AttestationError(
            f"action has unknown field(s): {', '.join(sorted(unknown))}"
        )
    missing = set(ACTION_FIELDS) - set(act)
    if missing:
        raise AttestationError(
            f"action is missing field(s): {', '.join(sorted(missing))}"
        )
    if act["domain"] != DOMAIN:
        raise AttestationError("wrong domain separator")
    if act["version"] != PROTOCOL_VERSION:
        raise AttestationError(f"unsupported action version {act['version']!r}")
    if act["action"] not in ACTION_CLASSES:
        raise AttestationError(f"unknown action class {act['action']!r}")
    for field in ("issued_at", "expires_at", "sequence", "version"):
        if isinstance(act[field], bool) or not isinstance(act[field], int):
            raise AttestationError(f"{field} must be an integer")
    if act["expires_at"] <= act["issued_at"]:
        raise AttestationError("expiry must be after issue")
    if act["expires_at"] - act["issued_at"] > MAX_TTL_SECONDS:
        raise AttestationError("authorization lifetime exceeds the maximum")


def verify_action(action: dict, signature: bytes, conn=None,
                  now: int | None = None) -> Authorization:
    """Verify a signed action. Raises on anything that is not exactly right.

    The canonical bytes are re-derived here from the action itself; a digest
    supplied by the caller is never trusted, because trusting it would let a
    caller present one action and have another verified.
    """
    own = conn is None
    conn = conn or state()
    try:
        _validate_action_shape(action)
        now = now if now is not None else int(time.time())
        if action["archive_uuid"] != archive_uuid(conn):
            raise AttestationError(
                "action was issued for a different archive"
            )
        if now < action["issued_at"] - 5:
            raise AttestationError("action is issued in the future")
        if now >= action["expires_at"]:
            raise AttestationError("authorization has expired")

        row = _lookup_key(conn, action["key_id"])
        nonce_row = conn.execute(
            "SELECT * FROM operator_nonces WHERE nonce = ?", (action["nonce"],)
        ).fetchone()
        if nonce_row is None:
            raise AttestationError(
                "nonce was not issued by this archive; an operator action "
                "cannot be self-minted"
            )
        if nonce_row["consumed_event"] is not None:
            raise AttestationError(
                f"nonce already consumed by event #{nonce_row['consumed_event']}"
            )
        if nonce_row["key_id"] != action["key_id"] or \
                nonce_row["sequence"] != action["sequence"]:
            raise AttestationError("nonce does not match this key/sequence")

        try:
            message = canonical_bytes(DOMAIN, action)
        except CanonicalError as exc:
            raise AttestationError(f"action is not canonically encodable: {exc}") from exc
        if canonical_digest(DOMAIN, action) != nonce_row["digest"]:
            raise AttestationError(
                "signed action does not match the action this nonce was "
                "issued for (a field was mutated after preparation)"
            )

        public = load_der_public_key(bytes(row["public_der"]))
        try:
            public.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise AttestationError("signature does not verify") from exc

        if row["signer"] == SIGNER_TEST:
            _assert_test_mode_ok()
        return Authorization(
            action=action, signature=signature, key_id=action["key_id"],
            signer=row["signer"], verified_at=_now_iso(),
        )
    finally:
        if own:
            conn.close()


def consume_nonce(conn, authorization: Authorization, event_id: int) -> None:
    """Mark the authorization used. MUST run inside the append transaction.

    The UPDATE is conditional on the nonce still being unconsumed, so two
    concurrent appends racing on one authorization cannot both succeed: the
    loser's UPDATE matches zero rows and it raises.
    """
    cursor = conn.execute(
        "UPDATE operator_nonces SET consumed_event = ? "
        "WHERE nonce = ? AND consumed_event IS NULL",
        (event_id, authorization.nonce),
    )
    if cursor.rowcount != 1:
        raise AttestationError(
            "authorization was already consumed; one signature authorizes "
            "exactly one append"
        )


_TEST_KEYS: dict = {}


def test_mode_authorization(conn, action: str, scope: str = "global",
                            arguments: dict | None = None,
                            content: str | None = None,
                            reason: str | None = None):
    """Mint a signed authorization with the TEST-ONLY software signer.

    Reachable only when all three conditions the security contract requires
    hold at once (`_assert_test_mode_ok`): the explicit opt-in environment
    variable, an isolated temporary archive, and an assurance level of the
    literal string INSECURE_TEST_SIGNER on every resulting event.

    This exists so operator-simulating harnesses and fixtures can build worlds
    without a hardware key. It is NOT a production fallback: in production the
    first condition alone already refuses, and the marking means an event
    produced this way can never be mistaken for an operator act.
    """
    _assert_test_mode_ok()
    root = str(home().resolve())
    private = _TEST_KEYS.get(root)
    if private is None:
        private = load_test_signer(root.encode())
        _TEST_KEYS[root] = private
    key_id = register_key(public_der(private), SIGNER_TEST, conn=conn)
    prepared = prepare_action(
        key_id, action, scope=scope, arguments=arguments, content=content,
        reason=reason, conn=conn,
    )
    signature = sign_with_test_key(private, bytes.fromhex(prepared["canonical"]))
    return verify_action(prepared["action"], signature, conn=conn)


def authorized_append(conn, source: str, kind: str, authorization: Authorization,
                      action: str, scope: str = "global",
                      arguments: dict | None = None, content: str | None = None,
                      reason: str | None = None, meta: dict | None = None,
                      uri: str | None = None) -> int:
    """Append an operator-authorized event, consuming the authorization atomically.

    Two checks, in this order, and both matter:

    1. The authorization must cover *exactly* this act — same action class,
       same canonical scope, same normalized arguments, same content and
       reason digests. An authorization for one act must not be redeemable
       against another.
    2. The nonce is consumed inside the same transaction as the insert, so a
       crash cannot separate them and a concurrent replay cannot double-spend.
    """
    from .db import append_event_checked

    if not authorization.matches(action, scope, arguments, content, reason):
        raise AttestationError(
            "the authorization does not cover this exact act (action, scope, "
            "arguments, content digest, and reason digest must all match)"
        )
    meta = {
        **(meta or {}),
        "assurance": authorization.assurance,
        "attestation": authorization.stored_block(),
    }

    def bind(locked_conn, _ts, event_id):
        consume_nonce(locked_conn, authorization, event_id)

    return append_event_checked(
        conn, source, kind, uri=uri, content=content, meta=meta, bind=bind,
    )


# --- signers ------------------------------------------------------------

SIGNER_HELPER = Path(__file__).resolve().parent.parent / "native" / "contextd-signer"


def _assert_test_mode_ok() -> None:
    """The software signer exists only for tests, and must be unmistakable.

    Three conditions, all required: the explicit env opt-in, an archive that is
    a temporary directory (never the real one), and the resulting assurance
    level is the literal string INSECURE_TEST_SIGNER.
    """
    if os.environ.get(TEST_MODE_ENV) != "1":
        raise AttestationError(
            "software signing keys are test-only and require "
            f"{TEST_MODE_ENV}=1. There is no production file-key, "
            "environment-key, HMAC, prompt-only, TTY, or parent-process "
            "fallback (docs/SECURITY.md §3)."
        )
    root = str(home().resolve())
    tmp_roots = (
        str(Path(os.environ.get("TMPDIR", "/tmp")).resolve()),
        "/tmp", "/private/tmp", "/private/var/folders", "/var/folders",
    )
    if not any(root.startswith(prefix) for prefix in tmp_roots):
        raise AttestationError(
            f"the test signer refuses to operate on {root}: it requires an "
            f"isolated temporary archive so a test key can never sign against "
            f"a real one"
        )


def sign_with_secure_enclave(canonical: bytes, key_id: str,
                             summary: str = "", timeout: int = 120) -> bytes:
    """Ask the macOS helper to sign these exact bytes with user presence.

    The helper holds a non-exportable Secure Enclave P-256 key and requests a
    fresh presence gesture per signature. If the operator cancels, the helper
    exits nonzero and this raises — nothing is appended.
    """
    if not SIGNER_HELPER.exists():
        raise AttestationError(
            f"no production signer at {SIGNER_HELPER}. Build it with "
            f"native/build.sh and enroll a key; there is no software fallback."
        )
    proc = subprocess.run(
        [str(SIGNER_HELPER), "sign", "--key-id", key_id, "--summary", summary],
        input=canonical, capture_output=True, timeout=timeout,
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()[:200]
        raise AttestationError(f"signer refused or was cancelled: {detail}")
    return proc.stdout


def load_test_signer(seed: bytes | None = None):
    """A software P-256 key for tests only. Never reachable in production."""
    _assert_test_mode_ok()
    private = ec.generate_private_key(ec.SECP256R1())
    if seed is not None:  # deterministic keys are still test-only
        private = ec.derive_private_key(
            int.from_bytes(hashlib.sha256(seed).digest(), "big") % (
                0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 - 1
            ) + 1,
            ec.SECP256R1(),
        )
    return private


def public_der(private) -> bytes:
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat,
    )
    return private.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )


def sign_with_test_key(private, canonical: bytes) -> bytes:
    _assert_test_mode_ok()
    return private.sign(canonical, ec.ECDSA(hashes.SHA256()))


def export_vectors(path: Path) -> dict:
    """Freeze input → canonical bytes → digest, for cross-language checking."""
    from .canonical import canonical_bytes as cb
    vectors = []
    for name, act in _VECTOR_INPUTS.items():
        vectors.append({
            "name": name,
            "action": act,
            "canonical_hex": cb(DOMAIN, act).hex(),
            "digest": canonical_digest(DOMAIN, act),
        })
    payload = {"domain": DOMAIN, "version": PROTOCOL_VERSION, "vectors": vectors}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return payload


_VECTOR_INPUTS = {
    "minimal_global_note": {
        "domain": DOMAIN, "version": 1,
        "archive_uuid": "00112233445566778899aabbccddeeff",
        "key_id": "a" * 64, "nonce": "b" * 64, "sequence": 1,
        "issued_at": 1770000000, "expires_at": 1770000300,
        "action": "note.deliberate", "scope": "global", "arguments": {},
        "content_digest": EMPTY_DIGEST, "reason_digest": EMPTY_DIGEST,
    },
    "repo_scope_with_arguments": {
        "domain": DOMAIN, "version": 1,
        "archive_uuid": "00112233445566778899aabbccddeeff",
        "key_id": "c" * 64, "nonce": "d" * 64, "sequence": 42,
        "issued_at": 1770000000, "expires_at": 1770000600,
        "action": "grant.add", "scope": "repo:/srv/demo/ledgerd",
        "arguments": {"class": "loop.confirm", "expires": "2026-04-10T00:00:00+00:00",
                      "ttl_seconds": 3600},
        "content_digest": hashlib.sha256(b"reason text").hexdigest(),
        "reason_digest": hashlib.sha256(b"because").hexdigest(),
    },
    "unicode_and_ordering": {
        "domain": DOMAIN, "version": 1,
        "archive_uuid": "ffeeddccbbaa99887766554433221100",
        "key_id": "e" * 64, "nonce": "f" * 64, "sequence": 7,
        "issued_at": 1770000000, "expires_at": 1770000060,
        "action": "loop.confirm", "scope": "repo:/srv/démo/café",
        "arguments": {"z": "last", "a": "first", "loop": 12, "é": "accent"},
        "content_digest": EMPTY_DIGEST,
        "reason_digest": hashlib.sha256("réson".encode()).hexdigest(),
    },
}
