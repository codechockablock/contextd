"""Service attestation: the integrity layer a chain recomputation cannot defeat.

`docs/SECURITY.md` §3 lists three integrity layers. The first two —
the SQLite hash chain and the local witness tip — are *tamper-evident against
accident*. Against the modeled attacker they are not evidence of anything: a
process running as the desktop UID can rewrite an event, recompute every
downstream `chain_hash`, and rewrite `chain-witness.json` to match. Everything
then verifies, because everything the verifier consults is under the attacker's
control.

This module adds the layer that is not. The service holds a P-256 key the
client plane cannot read, and signs:

* **event envelopes** for authoritative events — the exact fields that make an
  event mean something, not a hash of the whole row; and
* **chain tips** — (archive, tip id, chain hash), so truncation and
  wholesale replacement are detectable.

An attacker who recomputes the chain still cannot produce the signature, so
`verify_ledger` reports the forgery. That is the whole claim, and it is worth
stating what it is *not*: the service key lives beside the archive, so in a
**development** deployment the same UID owns both and this layer buys nothing
against a determined local attacker. It becomes real when the service account
owns the key. `ctx security doctor` reports which case applies.

Key rotation is supported with historical verification: a rotated-out key stays
in the registry marked `retired`, so signatures it made before rotation still
verify while it can no longer make new ones.
"""

import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import home
from .canonical import canonical_bytes, canonical_digest

ENVELOPE_DOMAIN = "contextd.ServiceEnvelopeV1"
TIP_DOMAIN = "contextd.ServiceTipV1"
CHECKPOINT_DOMAIN = "contextd.ProtectedCheckpointV1"

KEY_NAME = "service-key.pem"

# --- algorithm registry -----------------------------------------------------
#
# Every signature record names the scheme that produced it, and verification
# dispatches on that name rather than assuming one. This is the piece that is
# expensive to retrofit: once a million records exist with no algorithm field,
# the only way to introduce a second scheme is to guess which rows are which.
#
# Names are lowercase, hyphenated, and stable — they are written into archives
# and must never be re-pointed at a different scheme. Adding a scheme means
# adding a name; it never means reinterpreting one.

#: The per-append scheme. Unchanged, and deliberately so: it is fast, it is
#: what every existing archive contains, and nothing here rotates it out.
ALG_ECDSA_P256 = "ecdsa-p256-sha256"

#: ML-DSA (FIPS 204), the NIST post-quantum signature standard, provided
#: natively by ``cryptography``/OpenSSL. Used for checkpoints only — a 2,420
#: byte ML-DSA-44 signature against a ~64 byte ECDSA one is roughly 38x per
#: event, which a per-event ledger cannot carry, and does not need to: the
#: chain hash at event N already commits to every event beneath it.
ALG_MLDSA_44 = "ml-dsa-44"
ALG_MLDSA_65 = "ml-dsa-65"
ALG_MLDSA_87 = "ml-dsa-87"

#: The scheme assumed for any record written before algorithm identifiers
#: existed. Every such record *is* ECDSA P-256; there was no other option.
CLASSICAL_ALG = ALG_ECDSA_P256
PQ_ALGS = (ALG_MLDSA_44, ALG_MLDSA_65, ALG_MLDSA_87)
SUPPORTED_ALGS = (CLASSICAL_ALG, *PQ_ALGS)

try:  # pragma: no cover - exercised by whichever branch this build takes
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa
except ImportError:  # pragma: no cover
    _mldsa = None

#: alg -> (private key class, public key class). Empty for ML-DSA on a build
#: whose ``cryptography`` predates native support; the checkpoint path reports
#: that as a refusal rather than silently signing classical-only.
_PQ_CLASSES = {}
if _mldsa is not None:
    _PQ_CLASSES = {
        ALG_MLDSA_44: (_mldsa.MLDSA44PrivateKey, _mldsa.MLDSA44PublicKey),
        ALG_MLDSA_65: (_mldsa.MLDSA65PrivateKey, _mldsa.MLDSA65PublicKey),
        ALG_MLDSA_87: (_mldsa.MLDSA87PrivateKey, _mldsa.MLDSA87PublicKey),
    }


_PQ_PROBE: bool | None = None


def pq_available() -> bool:
    """Whether this build can actually make post-quantum signatures.

    Deliberately a capability probe rather than a version check. The ``mldsa``
    module imports on any `cryptography` >= 47, but the schemes it exposes are
    implemented by the linked OpenSSL: a build against an OpenSSL without
    ML-DSA imports cleanly and then raises on first use. Asking for a key once
    and caching the answer is the only claim about this build that is true by
    observation instead of by inference.
    """
    global _PQ_PROBE
    if _PQ_PROBE is None:
        if not _PQ_CLASSES:
            _PQ_PROBE = False
        else:
            try:
                _PQ_CLASSES[ALG_MLDSA_44][0].generate()
                _PQ_PROBE = True
            except Exception:
                _PQ_PROBE = False
    return _PQ_PROBE


SCHEMA = """
CREATE TABLE IF NOT EXISTS service_keys (
  key_id     TEXT PRIMARY KEY,
  public_pem TEXT NOT NULL,
  created    INTEGER NOT NULL,
  retired    INTEGER,
  alg        TEXT NOT NULL DEFAULT 'ecdsa-p256-sha256'
);
CREATE TABLE IF NOT EXISTS service_signatures (
  event_id   INTEGER PRIMARY KEY,
  key_id     TEXT NOT NULL,
  digest     TEXT NOT NULL,
  signature  TEXT NOT NULL,
  signed_at  INTEGER NOT NULL,
  alg        TEXT NOT NULL DEFAULT 'ecdsa-p256-sha256'
);
CREATE TABLE IF NOT EXISTS service_tips (
  tip_id     INTEGER PRIMARY KEY,
  chain_hash TEXT NOT NULL,
  key_id     TEXT NOT NULL,
  signature  TEXT NOT NULL,
  signed_at  INTEGER NOT NULL,
  cutover    INTEGER NOT NULL DEFAULT 0,
  alg        TEXT NOT NULL DEFAULT 'ecdsa-p256-sha256'
);
CREATE TABLE IF NOT EXISTS service_checkpoints (
  tip_id     INTEGER NOT NULL,
  alg        TEXT NOT NULL,
  chain_hash TEXT NOT NULL,
  key_id     TEXT NOT NULL,
  signature  TEXT NOT NULL,
  signed_at  INTEGER NOT NULL,
  PRIMARY KEY (tip_id, alg)
);
"""

#: Columns added to pre-existing tables after those tables shipped. The
#: migration applies these with ``ALTER TABLE ... ADD COLUMN``; ``executescript``
#: of ``CREATE TABLE IF NOT EXISTS`` cannot, because the table already exists.
#: The constant default backfills every historical row with the only scheme
#: that could have produced it.
ADDED_COLUMNS = (
    ("service_keys", "alg", "TEXT NOT NULL DEFAULT 'ecdsa-p256-sha256'"),
    ("service_signatures", "alg", "TEXT NOT NULL DEFAULT 'ecdsa-p256-sha256'"),
    ("service_tips", "alg", "TEXT NOT NULL DEFAULT 'ecdsa-p256-sha256'"),
)


class LedgerSignatureError(RuntimeError):
    """A service signature is missing, malformed, or does not verify."""


def _ensure(conn) -> None:
    """Require the signature schema without mutating the archive.

    Verification must never create the evidence it is checking.  Fresh archives
    receive these tables from ``contextd.db.SCHEMA`` and legacy archives receive
    them only through the explicit security migration.
    """
    from .backends import table_names

    required = {"service_keys", "service_signatures", "service_tips"}
    missing = required - table_names(conn)
    if missing:
        raise LedgerSignatureError("service-signature schema is not installed")


def _require_alg(alg: str) -> str:
    if alg not in SUPPORTED_ALGS:
        raise LedgerSignatureError(f"unsupported signature algorithm {alg!r}")
    if alg in PQ_ALGS and not pq_available():
        raise LedgerSignatureError(
            f"{alg} is not available here: native ML-DSA needs `cryptography` "
            f">= 47 linked against an OpenSSL that implements it"
        )
    return alg


def _row_alg(row) -> str:
    """The algorithm named by a signature row.

    A row from an archive written before algorithm identifiers existed has no
    ``alg`` column at all, and there is exactly one scheme it can be. Returning
    the classical name is a statement of fact about those rows, not a default
    that could ever mislabel a post-quantum signature — none existed.
    """
    try:
        value = row["alg"]
    except (IndexError, KeyError):
        return CLASSICAL_ALG
    return value or CLASSICAL_ALG


def _sign_with(private, alg: str, message: bytes) -> bytes:
    """Produce a signature under the named scheme. No scheme is improvised."""
    if alg == CLASSICAL_ALG:
        return private.sign(message, ec.ECDSA(hashes.SHA256()))
    if alg in _PQ_CLASSES:
        return private.sign(message)
    raise LedgerSignatureError(f"cannot sign under {alg!r}")


def _verify_with(public, alg: str, signature: bytes, message: bytes) -> None:
    """Check a signature under the named scheme, raising on failure."""
    if alg == CLASSICAL_ALG:
        public.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return
    if alg in _PQ_CLASSES:
        public.verify(signature, message)
        return
    raise LedgerSignatureError(f"cannot verify under {alg!r}")


def key_path(alg: str = CLASSICAL_ALG) -> Path:
    """Where the private key for a scheme lives.

    The classical key keeps its original filename: every existing deployment
    has one at that path, and moving it would strand archives whose signatures
    only that key can continue.
    """
    if alg == CLASSICAL_ALG:
        return home() / KEY_NAME
    return home() / f"service-key-{alg}.pem"


def _matches_alg(key, alg: str, *, public: bool) -> bool:
    if alg == CLASSICAL_ALG:
        base = ec.EllipticCurvePublicKey if public else ec.EllipticCurvePrivateKey
        return isinstance(key, base) and isinstance(key.curve, ec.SECP256R1)
    classes = _PQ_CLASSES.get(alg)
    if classes is None:
        return False
    return isinstance(key, classes[1] if public else classes[0])


def _read_private_key(path: Path, alg: str = CLASSICAL_ALG):
    """Open the service key without following an attacker-planted symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise LedgerSignatureError("service signing key cannot be opened safely") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise LedgerSignatureError("service signing key is not a regular file")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise LedgerSignatureError("service signing key must have mode 0600")
        if info.st_uid != os.geteuid():
            raise LedgerSignatureError("service signing key is owned by another uid")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise LedgerSignatureError("service signing key is unexpectedly large")
    finally:
        os.close(fd)
    try:
        private = serialization.load_pem_private_key(raw, None)
    except (TypeError, ValueError) as exc:
        raise LedgerSignatureError("service signing key is malformed") from exc
    if not _matches_alg(private, alg, public=False):
        if alg == CLASSICAL_ALG:
            raise LedgerSignatureError("service signing key must be P-256")
        raise LedgerSignatureError(f"service signing key must be {alg}")
    return private


def _generate_private_key(alg: str):
    if alg == CLASSICAL_ALG:
        return ec.generate_private_key(ec.SECP256R1())
    return _PQ_CLASSES[_require_alg(alg)][0].generate()


def _load_or_create_key(conn, alg: str = CLASSICAL_ALG):
    """The service signing key for one scheme.

    0600, and in a hardened deployment owned by the service account so the
    client plane cannot read it. `_assert_service_plane` is what makes that
    boundary explicit rather than incidental.

    Each scheme gets its own key and its own file. A key is never reused across
    schemes, which is what makes the registered ``alg`` authoritative: a key id
    resolves to exactly one algorithm, so a verifier cannot be talked into
    checking an ML-DSA signature against a P-256 key or the reverse.
    """
    _require_alg(alg)
    _ensure(conn)
    path = key_path(alg)
    if path.exists():
        if path.is_symlink():
            raise LedgerSignatureError("service signing key may not be a symlink")
        private = _read_private_key(path, alg)
    else:
        private = _generate_private_key(alg)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            fd = os.open(
                path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError:
            # A concurrent process won the O_EXCL race between our exists()
            # check and this open (concurrent migrations do exactly this).
            # Its key is the key; ours was never persisted anywhere and is
            # discarded. Symlink and permission checks still apply to what
            # we read back.
            if path.is_symlink():
                raise LedgerSignatureError(
                    "service signing key may not be a symlink"
                ) from None
            private = _read_private_key(path, alg)
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ))
                stream.flush()
                os.fsync(stream.fileno())
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    # Derivation is unchanged across schemes on purpose: SubjectPublicKeyInfo
    # already carries the algorithm OID, so the digest binds the scheme without
    # a separate field — and every key id minted before this change keeps its
    # value, which archives depend on.
    key_id = canonical_digest("contextd.ServiceKeyV1", {"pem": public_pem})[:32]
    # Registration must be race-safe, not merely idempotent-by-inspection.
    # A SELECT-then-INSERT lets a second process read "absent" while the
    # first's row is uncommitted, then fail the primary key after it commits
    # (observed under four concurrent migrations in CI). ON CONFLICT DO
    # NOTHING makes the insert itself the arbiter; the read-back keeps the
    # different-bytes collision check, which the conflict clause would
    # otherwise silently swallow.
    conn.execute(
        "INSERT INTO service_keys (key_id, public_pem, created, retired, alg) "
        "VALUES (?,?,?, NULL, ?) ON CONFLICT(key_id) DO NOTHING",
        (key_id, public_pem, int(time.time()), alg))
    conn.commit()
    stored = conn.execute(
        "SELECT public_pem FROM service_keys WHERE key_id = ?", (key_id,)
    ).fetchone()
    if stored is None or stored["public_pem"] != public_pem:
        raise LedgerSignatureError("service key id collides with different key bytes")
    return private, key_id


@dataclass(frozen=True)
class KeyHandle:
    """One loaded private key and the scheme it signs under."""

    private: object
    key_id: str
    alg: str


@dataclass(frozen=True)
class SigningContext:
    """A key loaded before the append transaction and used only inside it."""

    private: ec.EllipticCurvePrivateKey
    key_id: str
    alg: str = CLASSICAL_ALG
    #: Non-empty exactly when this append lands on a checkpoint boundary. The
    #: keys are loaded with the rest of the context — *before* the transaction,
    #: because minting one may need its own commit — and used only inside it.
    checkpoint_keys: tuple = ()


def cutover_tip_id(conn) -> int | None:
    """Return the sole signed cutover tip, or ``None`` before migration."""
    _ensure(conn)
    rows = conn.execute(
        "SELECT tip_id FROM service_tips WHERE cutover = 1 ORDER BY tip_id"
    ).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise LedgerSignatureError("archive has multiple service-signature cutovers")
    return int(rows[0]["tip_id"])


def prepare_append_signing(conn) -> SigningContext | None:
    """Load the signing keys iff this archive has crossed the signed cutover.

    Runs *before* ``BEGIN IMMEDIATE`` because minting a key commits its
    registry row. Everything it returns is used inside the transaction and
    nowhere else.
    """
    if cutover_tip_id(conn) is None:
        return None
    private, key_id = _load_or_create_key(conn)
    checkpoint_keys: tuple = ()
    if _checkpoint_due(conn):
        handles = [KeyHandle(private=private, key_id=key_id, alg=CLASSICAL_ALG)]
        for alg in checkpoint_algorithms():
            pq_private, pq_key_id = _load_or_create_key(conn, alg)
            handles.append(
                KeyHandle(private=pq_private, key_id=pq_key_id, alg=alg)
            )
        checkpoint_keys = tuple(handles)
    return SigningContext(
        private=private,
        key_id=key_id,
        alg=CLASSICAL_ALG,
        checkpoint_keys=checkpoint_keys,
    )


def rotate_key(conn, alg: str = CLASSICAL_ALG) -> str:
    """Retire the current key for a scheme and mint a new one.

    The retired key stays in the registry so signatures it made before
    rotation still verify — rotation must not invalidate history, or every
    rotation would look like tampering. This is also what makes an *algorithm*
    change survivable: records signed under the old scheme keep resolving to a
    key registered under that scheme, so a verifier reading a mixed-algorithm
    archive is never guessing.
    """
    _require_alg(alg)
    _ensure(conn)
    path = key_path(alg)
    if path.exists():
        _private, old_id = _load_or_create_key(conn, alg)
        conn.execute("UPDATE service_keys SET retired = ? WHERE key_id = ?",
                     (int(time.time()), old_id))
        conn.commit()
        path.unlink()
    _private, new_id = _load_or_create_key(conn, alg)
    return new_id


def active_key_id(conn, alg: str = CLASSICAL_ALG) -> str:
    _private, key_id = _load_or_create_key(conn, alg)
    return key_id


def _public(conn, key_id: str, expect_alg: str | None = None):
    """The registered public key, and the scheme the registry says it uses.

    ``expect_alg`` is the algorithm named by the *signature record*. It must
    agree with the algorithm named by the *key registry*, or the record is
    refused: a signature that names one scheme while its key is registered
    under another is exactly the confusion an algorithm identifier exists to
    prevent, and answering it with "verify anyway" would give it back.
    """
    # a verifier must work against an archive that has never signed anything —
    # returning "unknown key" is a refusal, crashing on a missing table is not
    _ensure(conn)
    row = conn.execute("SELECT * FROM service_keys WHERE key_id = ?",
                       (key_id,)).fetchone()
    if row is None:
        raise LedgerSignatureError(f"unknown service key {key_id!r}")
    expected = canonical_digest(
        "contextd.ServiceKeyV1", {"pem": row["public_pem"]}
    )[:32]
    if expected != key_id:
        raise LedgerSignatureError("service key registry id does not match key bytes")
    alg = _row_alg(row)
    if alg not in SUPPORTED_ALGS:
        raise LedgerSignatureError(f"service key uses unsupported algorithm {alg!r}")
    if expect_alg is not None and expect_alg != alg:
        raise LedgerSignatureError(
            f"signature names {expect_alg!r} but its key is registered as {alg!r}"
        )
    if alg in PQ_ALGS and alg not in _PQ_CLASSES:
        raise LedgerSignatureError(
            f"{alg} signatures cannot be verified by this build: `cryptography` "
            f"was built without native ML-DSA support"
        )
    try:
        public = serialization.load_pem_public_key(row["public_pem"].encode())
    except (TypeError, ValueError) as exc:
        raise LedgerSignatureError("service public key is malformed") from exc
    if not _matches_alg(public, alg, public=True):
        if alg == CLASSICAL_ALG:
            raise LedgerSignatureError("service public key must be P-256")
        raise LedgerSignatureError(f"service public key must be {alg}")
    return public, alg


# --- event envelopes --------------------------------------------------------

def envelope(row) -> dict:
    """The exact fields a service signature covers for one event.

    Deliberately the semantic fields, not the raw row: signing
    ``chain_hash`` would make the signature depend on a value the attacker
    recomputes anyway, and signing nothing but a row hash would make a
    mismatch uninformative about *what* changed.
    """
    return {
        "id": int(row["id"]),
        "ts": row["ts"],
        "source": row["source"],
        "kind": row["kind"],
        "uri": row["uri"] or "",
        "content_hash": row["content_hash"] or "",
        "meta": row["meta"] or "",
    }


def _insert_event_signature(conn, row, signing: SigningContext) -> dict:
    """Insert an event signature without committing the caller's transaction."""
    if not conn.in_transaction:
        raise LedgerSignatureError("event signing must run inside a transaction")
    payload = envelope(row)
    message = canonical_bytes(ENVELOPE_DOMAIN, payload)
    signature = _sign_with(signing.private, signing.alg, message)
    digest = canonical_digest(ENVELOPE_DOMAIN, payload)
    conn.execute(
        "INSERT INTO service_signatures "
        "(event_id, key_id, digest, signature, signed_at, alg) VALUES (?,?,?,?,?,?)",
        (int(row["id"]), signing.key_id, digest, signature.hex(),
         int(time.time()), signing.alg),
    )
    return {
        "event": int(row["id"]),
        "key_id": signing.key_id,
        "signature": signature.hex(),
        "alg": signing.alg,
    }


def _archive_uuid_existing(conn) -> str:
    row = conn.execute(
        "SELECT uuid FROM archive_identity WHERE singleton = 1"
    ).fetchone()
    if row is None:
        raise LedgerSignatureError("archive identity is missing after cutover")
    return row["uuid"]


def _insert_tip_signature(
    conn,
    tip_id: int,
    chain_hash: str,
    signing: SigningContext,
    *,
    cutover: bool = False,
) -> dict:
    """Insert a chain-tip signature without committing the transaction."""
    if not conn.in_transaction:
        raise LedgerSignatureError("tip signing must run inside a transaction")
    payload = tip_payload(_archive_uuid_existing(conn), tip_id, chain_hash)
    signature = _sign_with(
        signing.private, signing.alg, canonical_bytes(TIP_DOMAIN, payload)
    )
    conn.execute(
        "INSERT INTO service_tips "
        "(tip_id, chain_hash, key_id, signature, signed_at, cutover, alg) "
        "VALUES (?,?,?,?,?,?,?)",
        (
            int(tip_id),
            chain_hash,
            signing.key_id,
            signature.hex(),
            int(time.time()),
            1 if cutover else 0,
            signing.alg,
        ),
    )
    return {
        "tip_id": int(tip_id),
        "chain_hash": chain_hash,
        "key_id": signing.key_id,
        "signature": signature.hex(),
        "cutover": bool(cutover),
        "alg": signing.alg,
    }


def sign_accepted_append(
    conn, row: dict, chain_hash: str, signing: SigningContext
) -> dict:
    """Sign an accepted event and its resulting tip in the append transaction.

    When this append lands on a checkpoint boundary the checkpoint is signed
    here too — inside the same transaction, from keys loaded before it. A
    checkpoint written after the commit instead would be a checkpoint a crash
    can lose while the event it covers survives.
    """
    event = _insert_event_signature(conn, row, signing)
    tip = _insert_tip_signature(
        conn, int(row["id"]), chain_hash, signing, cutover=False
    )
    result = {"event": event, "tip": tip}
    if signing.checkpoint_keys:
        result["checkpoint"] = _insert_checkpoint_signatures(
            conn, int(row["id"]), chain_hash, signing.checkpoint_keys
        )
    return result


def sign_event(conn, event_id: int) -> dict:
    """Sign one accepted authoritative event. Called by the authority plane."""
    _ensure(conn)
    private, key_id = _load_or_create_key(conn)
    cutover = cutover_tip_id(conn)
    if cutover is not None and event_id <= cutover:
        raise LedgerSignatureError(
            "refusing to retroactively sign an event at or before the cutover"
        )
    row = conn.execute(
        "SELECT id, ts, source, kind, uri, content_hash, meta FROM events "
        "WHERE id = ?", (event_id,)).fetchone()
    if row is None:
        raise LedgerSignatureError(f"no event #{event_id}")
    conn.execute("BEGIN IMMEDIATE")
    try:
        result = _insert_event_signature(
            conn, row, SigningContext(private=private, key_id=key_id)
        )
        conn.commit()
        return result
    except BaseException:
        conn.rollback()
        raise


def verify_event(conn, event_id: int) -> dict:
    _ensure(conn)
    stored = conn.execute(
        "SELECT * FROM service_signatures WHERE event_id = ?",
        (event_id,)).fetchone()
    if stored is None:
        return {"event": event_id, "signed": False, "ok": False,
                "why": "no service signature"}
    row = conn.execute(
        "SELECT id, ts, source, kind, uri, content_hash, meta FROM events "
        "WHERE id = ?", (event_id,)).fetchone()
    if row is None:
        return {"event": event_id, "signed": True, "ok": False,
                "why": "signed event no longer exists"}
    payload = envelope(row)
    digest = canonical_digest(ENVELOPE_DOMAIN, payload)
    if stored["digest"] != digest:
        return {
            "event": event_id,
            "signed": True,
            "ok": False,
            "why": "signature does not verify: stored digest does not match "
            "the event envelope",
        }
    message = canonical_bytes(ENVELOPE_DOMAIN, payload)
    alg = _row_alg(stored)
    try:
        public, _ = _public(conn, stored["key_id"], alg)
        _verify_with(public, alg, bytes.fromhex(stored["signature"]), message)
    except (InvalidSignature, ValueError, LedgerSignatureError) as exc:
        return {"event": event_id, "signed": True, "ok": False, "alg": alg,
                "why": f"signature does not verify: {type(exc).__name__}"}
    return {"event": event_id, "signed": True, "ok": True,
            "key_id": stored["key_id"], "alg": alg}


# --- chain tips -------------------------------------------------------------

def tip_payload(archive_uuid: str, tip_id: int, chain_hash: str) -> dict:
    return {"archive_uuid": archive_uuid, "tip_id": int(tip_id),
            "chain_hash": chain_hash}


def sign_tip(conn, cutover: bool = False) -> dict:
    """Sign the current chain tip.

    ``cutover=True`` marks the append-only adoption of a legacy tip: the
    service records that it observed this tip at this time. It does **not**
    retroactively authenticate anything before it, and nothing in this module
    treats a cutover signature as evidence about earlier events.
    """
    _ensure(conn)
    from .attest import archive_uuid
    from .db import _db_tip
    private, key_id = _load_or_create_key(conn)
    # Manual pre-cutover signing is still supported for diagnostics/tests.  Mint
    # the archive identity before opening the signature transaction; post-cutover
    # appends require it to exist already and never create it implicitly.
    archive_uuid(conn)
    tip = _db_tip(conn)
    existing = conn.execute(
        "SELECT * FROM service_tips WHERE tip_id = ?", (tip["id"],)
    ).fetchone()
    if existing is not None:
        verified = verify_tip(conn, tip["id"])
        if not verified["ok"] or bool(existing["cutover"]) != bool(cutover):
            raise LedgerSignatureError(
                "the current tip already has a conflicting service signature"
            )
        return {
            "tip_id": int(existing["tip_id"]),
            "chain_hash": existing["chain_hash"],
            "key_id": existing["key_id"],
            "signature": existing["signature"],
            "cutover": bool(existing["cutover"]),
        }
    conn.execute("BEGIN IMMEDIATE")
    try:
        result = _insert_tip_signature(
            conn,
            int(tip["id"]),
            tip["chain_hash"],
            SigningContext(private=private, key_id=key_id),
            cutover=cutover,
        )
        conn.commit()
        return result
    except BaseException:
        conn.rollback()
        raise


def verify_tip(conn, tip_id: int) -> dict:
    _ensure(conn)
    stored = conn.execute("SELECT * FROM service_tips WHERE tip_id = ?",
                          (tip_id,)).fetchone()
    if stored is None:
        return {"tip_id": tip_id, "ok": False, "why": "no signed tip"}
    if tip_id == 0:
        current = ""
    else:
        row = conn.execute(
            "SELECT chain_hash FROM events WHERE id = ?", (tip_id,)
        ).fetchone()
        current = row["chain_hash"] if row else None
    payload = tip_payload(
        _archive_uuid_existing(conn), tip_id, stored["chain_hash"]
    )
    alg = _row_alg(stored)
    try:
        public, _ = _public(conn, stored["key_id"], alg)
        _verify_with(public, alg, bytes.fromhex(stored["signature"]),
                     canonical_bytes(TIP_DOMAIN, payload))
    except (InvalidSignature, ValueError, LedgerSignatureError) as exc:
        return {"tip_id": tip_id, "ok": False, "alg": alg,
                "why": f"tip signature does not verify: {type(exc).__name__}"}
    if current is not None and current != stored["chain_hash"]:
        return {"tip_id": tip_id, "ok": False,
                "why": "the chain hash at this tip has changed since it was "
                       "signed — the chain was rewritten"}
    if current is None:
        return {"tip_id": tip_id, "ok": False,
                "why": "the signed tip no longer exists — the ledger was "
                       "truncated"}
    return {"tip_id": tip_id, "ok": True, "key_id": stored["key_id"],
            "cutover": bool(stored["cutover"]), "alg": alg}


def verify_ledger(conn) -> dict:
    """Verify signatures *and complete post-cutover coverage*.

    Looking only at rows already present in ``service_signatures`` turns absence
    into a pass.  The cutover defines the required set: every event after it must
    have a valid signature and the current chain tip must be signed.
    """
    _ensure(conn)
    cutover_rows = conn.execute(
        "SELECT tip_id FROM service_tips WHERE cutover = 1 ORDER BY tip_id"
    ).fetchall()
    cutover_anomalies = []
    cutover = None
    if len(cutover_rows) == 1:
        cutover = int(cutover_rows[0]["tip_id"])
    elif not cutover_rows:
        cutover_anomalies.append("no signed coverage cutover")
    else:
        cutover_anomalies.append("multiple signed coverage cutovers")

    required_ids = []
    if cutover is not None:
        required_ids = [
            int(r["id"])
            for r in conn.execute(
                "SELECT id FROM events WHERE id > ? ORDER BY id", (cutover,)
            )
        ]
    signed_ids = {
        int(r["event_id"])
        for r in conn.execute("SELECT event_id FROM service_signatures")
    }
    missing_events = [event_id for event_id in required_ids if event_id not in signed_ids]
    checked_ids = sorted(signed_ids | set(required_ids))
    events = [verify_event(conn, event_id) for event_id in checked_ids]
    tips = [verify_tip(conn, r["tip_id"]) for r in conn.execute(
        "SELECT tip_id FROM service_tips ORDER BY tip_id")]
    bad_events = [e for e in events if not e["ok"]]
    bad_tips = [t for t in tips if not t["ok"]]
    from .db import _db_tip
    current_tip = int(_db_tip(conn)["id"])
    current_tip_result = verify_tip(conn, current_tip)
    if not current_tip_result["ok"] and not any(
        t.get("tip_id") == current_tip for t in bad_tips
    ):
        bad_tips.append(current_tip_result)
    bad_checkpoints = verify_recorded_checkpoints(conn)
    coverage_ok = (
        not cutover_anomalies
        and not missing_events
        and current_tip_result["ok"]
    )
    algorithms = sorted({
        _row_alg(r) for r in conn.execute("SELECT * FROM service_signatures")
    } | {
        _row_alg(r) for r in conn.execute("SELECT * FROM service_tips")
    })
    return {
        "signed_events": len(signed_ids), "checked_events": len(events),
        "signed_tips": len(tips),
        "bad_events": bad_events, "bad_tips": bad_tips,
        "bad_checkpoints": bad_checkpoints,
        "cutover_tip": cutover,
        "cutover_anomalies": cutover_anomalies,
        "required_events": len(required_ids),
        "missing_events": missing_events,
        "current_tip": current_tip,
        "coverage_ok": coverage_ok,
        # every scheme present in this archive; a mixed list is the normal and
        # expected shape after an algorithm change, not an anomaly
        "algorithms": algorithms,
        "ok": (coverage_ok and not bad_events and not bad_tips
               and not bad_checkpoints),
    }


# --- protected checkpoint ---------------------------------------------------
#
# Why checkpoints carry the post-quantum signature and events do not:
#
# An ML-DSA-44 signature is 2,420 bytes against roughly 64 for ECDSA P-256 —
# about 38x per event, which a per-event ledger cannot carry. It does not have
# to. The chain hash at event N already commits to every event beneath it, so
# one signature over a tip transitively covers the whole prefix. This is the
# signed-tree-head model from Certificate Transparency, and it is the reason
# per-event signing can stay classical and fast while the long-lived evidence
# gets a scheme meant to outlive P-256.


def _security_config() -> dict:
    """The `[security]` table, via the append-path config cache.

    `_checkpoint_due` runs on every append, and `load_config()` re-reads and
    re-parses config.toml on every call — a bulk ingest appends thousands of
    times, so consulting it directly here would put a file read and a TOML
    parse inside the chain lock. `db._append_config` already caches on
    (home, config mtime) for exactly this reason; an edited interval takes
    effect on the next append rather than the next process.
    """
    from .db import _append_config
    try:
        return _append_config().get("security") or {}
    except Exception:
        return {}


def checkpoint_algorithms() -> tuple:
    """Additional schemes each checkpoint is signed under, beyond classical.

    Empty by default: a base install must not start depending on ML-DSA just
    by upgrading. Configuring one turns hybrid mode on.

    This names an *algorithm*, never a key. Selecting among registered keys
    would be a signer choice, which config is deliberately not allowed to make
    (`test_config_and_env_cannot_name_a_signer`); choosing a scheme the service
    then mints its own key for authorizes nothing.
    """
    configured = _security_config().get("checkpoint_algorithms") or []
    if isinstance(configured, str):
        configured = [configured]
    chosen = []
    for alg in configured:
        if not isinstance(alg, str):
            raise LedgerSignatureError("checkpoint_algorithms must be strings")
        alg = alg.strip().lower()
        if alg == CLASSICAL_ALG:
            # always present; listing it is a no-op rather than an error
            continue
        if alg not in SUPPORTED_ALGS:
            raise LedgerSignatureError(
                f"unknown checkpoint algorithm {alg!r}; supported: "
                f"{', '.join(SUPPORTED_ALGS)}"
            )
        _require_alg(alg)
        if alg not in chosen:
            chosen.append(alg)
    return tuple(chosen)


def checkpoint_interval() -> int:
    """How many events may pass before the tip is checkpointed again.

    Zero or negative disables automatic checkpointing. The default is an
    exposure-window decision, argued in `docs/SECURITY.md`: events appended
    since the last checkpoint are covered only by local state, so the interval
    is the size of the window an attacker can roll back without contradicting
    a signature they could not forge.
    """
    raw = _security_config().get("checkpoint_interval_events", 0)
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise LedgerSignatureError(
            "checkpoint_interval_events must be an integer"
        ) from None


def last_checkpoint_tip(conn) -> int | None:
    """The highest tip id with a recorded checkpoint, or None."""
    if not _has_checkpoint_table(conn):
        return None
    row = conn.execute(
        "SELECT MAX(tip_id) AS tip FROM service_checkpoints"
    ).fetchone()
    if row is None or row["tip"] is None:
        return None
    return int(row["tip"])


def _has_checkpoint_table(conn) -> bool:
    # sqlite_master is not a portable way to ask (backends/base.py says so at
    # the seam built for exactly this): on Postgres the raw probe raised
    # UndefinedTable from inside prepare_append_signing, so every append to a
    # post-cutover Postgres archive crashed at the shipped default interval,
    # and verify_ledger crashed on every Postgres archive unconditionally.
    from .backends import backend_for
    return "service_checkpoints" in backend_for(conn).table_names(conn)


def _checkpoint_due(conn) -> bool:
    """Whether the append about to happen lands on a checkpoint boundary."""
    interval = checkpoint_interval()
    if interval <= 0 or not _has_checkpoint_table(conn):
        return False
    last = last_checkpoint_tip(conn)
    if last is None:
        # the cutover is the first thing a checkpoint could cover
        last = cutover_tip_id(conn)
        if last is None:
            return False
    from .db import _db_tip
    return (int(_db_tip(conn)["id"]) + 1) - last >= interval


def checkpoint_payload(archive_uuid: str, tip_id: int, chain_hash: str,
                       key_id: str, alg: str | None = None) -> dict:
    """The bytes a checkpoint signature covers.

    The classical signature omits ``alg`` so that its message is byte-identical
    to every checkpoint signed before algorithm identifiers existed — those
    records must keep verifying, and a verifier must not need to know which
    build wrote one. Every non-classical signature *includes* ``alg``, which
    both binds the scheme into what it signs and guarantees its message can
    never collide with a classical one: the canonical encoding length-prefixes
    the field count, so a four-field map and a five-field map cannot encode
    alike.
    """
    payload = {"archive_uuid": archive_uuid, "tip_id": int(tip_id),
               "chain_hash": chain_hash, "key_id": key_id}
    if alg is not None and alg != CLASSICAL_ALG:
        payload["alg"] = alg
    return payload


def _insert_checkpoint_signatures(
    conn, tip_id: int, chain_hash: str, handles: tuple
) -> dict:
    """Record a checkpoint under every configured scheme, inside the caller's
    transaction."""
    if not conn.in_transaction:
        raise LedgerSignatureError("checkpoint signing must run inside a transaction")
    uuid = _archive_uuid_existing(conn)
    signed = []
    stamp = int(time.time())
    for handle in handles:
        payload = checkpoint_payload(
            uuid, tip_id, chain_hash, handle.key_id, handle.alg
        )
        signature = _sign_with(
            handle.private, handle.alg, canonical_bytes(CHECKPOINT_DOMAIN, payload)
        )
        conn.execute(
            # ON CONFLICT DO UPDATE is the portable upsert (SQLite >= 3.24,
            # Postgres native). INSERT OR REPLACE was SQLite-only: a Postgres
            # append landing on a checkpoint boundary died on SyntaxError
            # inside the append transaction, and because the boundary
            # condition persists, every later append was still "due" — the
            # archive wedged at the boundary.
            "INSERT INTO service_checkpoints "
            "(tip_id, alg, chain_hash, key_id, signature, signed_at) "
            "VALUES (?,?,?,?,?,?) "
            "ON CONFLICT (tip_id, alg) DO UPDATE SET "
            "chain_hash = excluded.chain_hash, key_id = excluded.key_id, "
            "signature = excluded.signature, signed_at = excluded.signed_at",
            (int(tip_id), handle.alg, chain_hash, handle.key_id,
             signature.hex(), stamp),
        )
        signed.append({"alg": handle.alg, "key_id": handle.key_id,
                       "signature": signature.hex()})
    return {"tip_id": int(tip_id), "chain_hash": chain_hash,
            "signatures": signed}


def checkpoint_record(conn) -> dict:
    """The whole content of a protected checkpoint.

    Five fields at minimum, deliberately: archive UUID, tip id, chain hash, key
    id, and the signature. Nothing about *what* the archive contains leaves
    with it — a checkpoint destination is by definition somewhere the operator
    does not fully control, so it must not carry archive content.

    In hybrid mode two further keys appear: ``alg``, naming the scheme of the
    top-level signature, and ``hybrid``, carrying one entry per additional
    scheme. The five original fields keep their original meaning and their
    original bytes, so a verifier that predates this change still checks the
    classical signature and still reaches the right answer. That is the whole
    point of a transition mode — it must not strand the verifiers already
    deployed. With no scheme configured the record is byte-for-byte what it was
    before, extra keys included nowhere.
    """
    from .attest import archive_uuid
    from .db import _db_tip
    private, key_id = _load_or_create_key(conn)
    tip = _db_tip(conn)
    uuid = archive_uuid(conn)
    payload = checkpoint_payload(uuid, tip["id"], tip["chain_hash"], key_id)
    signature = _sign_with(
        private, CLASSICAL_ALG, canonical_bytes(CHECKPOINT_DOMAIN, payload)
    )
    record = {**payload, "signature": signature.hex()}
    extra = checkpoint_algorithms()
    if not extra:
        return record
    hybrid = []
    for alg in extra:
        pq_private, pq_key_id = _load_or_create_key(conn, alg)
        pq_payload = checkpoint_payload(
            uuid, tip["id"], tip["chain_hash"], pq_key_id, alg
        )
        pq_signature = _sign_with(
            pq_private, alg, canonical_bytes(CHECKPOINT_DOMAIN, pq_payload)
        )
        hybrid.append({"alg": alg, "key_id": pq_key_id,
                       "signature": pq_signature.hex()})
    return {**record, "alg": CLASSICAL_ALG, "hybrid": hybrid}


def _verify_checkpoint_signatures(conn, record: dict) -> str | None:
    """Check every signature a checkpoint carries. Returns a reason, or None.

    Every signature present must verify. A record is not accepted because one
    of its signatures checked out — a hybrid checkpoint whose ML-DSA half fails
    is a broken checkpoint, not a classical one.
    """
    payload = {k: record[k] for k in
               ("archive_uuid", "tip_id", "chain_hash", "key_id")}
    top_alg = record.get("alg", CLASSICAL_ALG)
    if top_alg != CLASSICAL_ALG:
        return ("the top-level checkpoint signature must be the classical "
                "scheme so older verifiers keep working")
    try:
        public, _ = _public(conn, record["key_id"], CLASSICAL_ALG)
        _verify_with(public, CLASSICAL_ALG, bytes.fromhex(record["signature"]),
                     canonical_bytes(CHECKPOINT_DOMAIN, payload))
    except (InvalidSignature, ValueError, LedgerSignatureError) as exc:
        return f"checkpoint signature does not verify: {type(exc).__name__}"
    for entry in record.get("hybrid", []):
        if not isinstance(entry, dict) or set(entry) != {"alg", "key_id", "signature"}:
            return "malformed hybrid checkpoint signature"
        alg = entry["alg"]
        if alg == CLASSICAL_ALG or alg not in SUPPORTED_ALGS:
            return f"hybrid checkpoint names unusable algorithm {alg!r}"
        pq_payload = checkpoint_payload(
            record["archive_uuid"], record["tip_id"], record["chain_hash"],
            entry["key_id"], alg,
        )
        try:
            public, _ = _public(conn, entry["key_id"], alg)
            _verify_with(public, alg, bytes.fromhex(entry["signature"]),
                         canonical_bytes(CHECKPOINT_DOMAIN, pq_payload))
        except (InvalidSignature, ValueError, LedgerSignatureError) as exc:
            return (f"{alg} checkpoint signature does not verify: "
                    f"{type(exc).__name__}")
    return None


def verify_checkpoint(conn, record: dict) -> dict:
    """Check a checkpoint against the archive's current state.

    A checkpoint whose tip is *ahead* of the archive is the rollback signal:
    the archive has fewer events than something the attacker could not rewrite
    said it had.
    """
    from .attest import archive_uuid
    from .db import _db_tip
    required = {"archive_uuid", "tip_id", "chain_hash", "key_id", "signature"}
    optional = {"alg", "hybrid"}
    if not isinstance(record, dict) or not required <= set(record) \
            or set(record) - required - optional:
        return {"ok": False, "why": "malformed checkpoint record"}
    if "hybrid" in record and not isinstance(record["hybrid"], list):
        return {"ok": False, "why": "malformed checkpoint record"}
    _ensure(conn)
    why = _verify_checkpoint_signatures(conn, record)
    if why is not None:
        return {"ok": False, "why": why}
    if record["archive_uuid"] != archive_uuid(conn):
        return {"ok": False, "why": "checkpoint belongs to a different archive"}
    tip = _db_tip(conn)
    if tip["id"] < record["tip_id"]:
        return {"ok": False, "rollback": True,
                "why": f"ROLLBACK: the archive ends at #{tip['id']} but a "
                       f"protected checkpoint recorded #{record['tip_id']}"}
    row = conn.execute("SELECT chain_hash FROM events WHERE id = ?",
                       (record["tip_id"],)).fetchone()
    if row is None or row["chain_hash"] != record["chain_hash"]:
        return {"ok": False, "rewritten": True,
                "why": f"the chain hash at #{record['tip_id']} does not match "
                       f"the protected checkpoint — history was rewritten"}
    algs = [record.get("alg", CLASSICAL_ALG)]
    algs += [e["alg"] for e in record.get("hybrid", [])]
    return {"ok": True, "tip_id": record["tip_id"], "algs": algs}


def verify_recorded_checkpoints(conn) -> list:
    """Verify every checkpoint the archive recorded for itself.

    These rows are *not* the rollback defence — they live in the archive an
    attacker owns, so an attacker who truncates the ledger can drop them too.
    What they are is the durable, transactional record that a checkpoint was
    taken at a given tip under a given scheme, and the material
    `write_checkpoint` exports somewhere the desktop uid cannot rewrite. They
    are verified here so that a checkpoint which stopped verifying is reported
    rather than quietly carried forward.
    """
    if not _has_checkpoint_table(conn):
        return []
    try:
        uuid = _archive_uuid_existing(conn)
    except LedgerSignatureError:
        return []
    bad = []
    for row in conn.execute(
        "SELECT * FROM service_checkpoints ORDER BY tip_id, alg"
    ):
        alg = row["alg"] or CLASSICAL_ALG
        payload = checkpoint_payload(
            uuid, int(row["tip_id"]), row["chain_hash"], row["key_id"], alg
        )
        entry = {"tip_id": int(row["tip_id"]), "alg": alg}
        try:
            public, _ = _public(conn, row["key_id"], alg)
            _verify_with(public, alg, bytes.fromhex(row["signature"]),
                         canonical_bytes(CHECKPOINT_DOMAIN, payload))
        except (InvalidSignature, ValueError, LedgerSignatureError) as exc:
            bad.append({**entry, "ok": False,
                        "why": f"checkpoint signature does not verify: "
                               f"{type(exc).__name__}"})
            continue
        current = conn.execute(
            "SELECT chain_hash FROM events WHERE id = ?", (int(row["tip_id"]),)
        ).fetchone()
        if current is None:
            bad.append({**entry, "ok": False,
                        "why": "the checkpointed tip no longer exists — the "
                               "ledger was truncated"})
        elif current["chain_hash"] != row["chain_hash"]:
            bad.append({**entry, "ok": False,
                        "why": "the chain hash at the checkpointed tip changed "
                               "— history was rewritten"})
    return bad


def write_checkpoint(conn, destination: Path | str) -> Path:
    """Write a checkpoint to a configured destination.

    The destination must be somewhere the client plane cannot rewrite for this
    to mean anything; this function does not and cannot verify that, which is
    why `ctx security doctor` reports rollback resistance separately.

    This writes exactly one record and replaces whatever was there. For a
    history of checkpoints — which is what detects a rollback to a state that
    was itself once checkpointed — use `append_checkpoint_log`.
    """
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    record = checkpoint_record(conn)
    destination.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    os.chmod(destination, 0o600)
    return destination


# --- the exported checkpoint log ---------------------------------------
#
# The hole this closes, and the exact size of it.
#
# `service_checkpoints` rows live inside the archive being attested. Against
# the modeled attacker — someone who owns the storage, whether that is the
# SQLite file or a Postgres superuser — they are worth nothing on their own:
# rewriting the chain and rewriting the checkpoint rows are the same privilege,
# so the attacker produces an archive that is internally consistent at a state
# of their choosing.
#
# The fix is not cryptographic, because there is nothing wrong with the
# cryptography. It is *positional*: the same signed records, kept somewhere the
# archive's owner cannot rewrite. Then a rollback stops being self-consistent —
# the archive says it ends at #400, and a signature the attacker could not forge
# says it once reached #900.
#
# Which is why this is a log and not a file. A single-record checkpoint that the
# attacker can also overwrite proves nothing; a single record they *cannot*
# overwrite proves one thing. An append-only log of them proves it continuously,
# and makes the gap between "last checkpoint" and "now" visible instead of
# assumed.
#
# The honest scope is stated at `checkpoint_log_claim` and repeated in
# docs/FORMAT.md §11: on one machine under one uid this is ADVISORY. It detects
# accident, bug, and partial compromise. It does not withstand an attacker with
# write access to the destination, because nothing in this file can give a
# destination a property the filesystem did not.

#: Record-format version of one log line. Bumped only if a line's byte layout
#: changes; new optional keys do not bump it.
CHECKPOINT_LOG_VERSION = 1

#: Keys a log line adds around the checkpoint record itself. Neither is covered
#: by any signature — see `checkpoint_log_claim`.
CHECKPOINT_LOG_ENVELOPE = ("v", "exported_at")


def checkpoint_log_claim(destination: Path | str = "") -> dict:
    """Exactly what an exported checkpoint log does and does not prove.

    Returned as data, like `migrate.cutover_claim`, so a caller cannot
    paraphrase it into something stronger than it is. `ctx security doctor`
    already reports whether the destination is writable by this uid; that
    report, not this function, is what tells an operator which case they are in.
    """
    return {
        "destination": str(destination),
        "attests": "the service signed these (archive, tip, chain hash) "
                   "records, and the archive's history is consistent with "
                   "every one of them",
        "does_not_attest": [
            "that the log is complete — an attacker who can write the "
            "destination can truncate it, and a truncated log verifies",
            "that any record was exported when its `exported_at` says; that "
            "field is outside every signature and is operator convenience, "
            "not evidence",
            "that the archive was not rolled back to a state OLDER than the "
            "first exported checkpoint",
            "anything at all about content — a checkpoint carries no archive "
            "data by design",
        ],
        "advisory_on_one_machine": (
            "Under one uid on one machine this is ADVISORY. The uid that can "
            "rewrite the archive can rewrite this log, so it detects accident, "
            "bug, and partial compromise — not an attacker who owns the "
            "account. Its value is realized only when the destination is "
            "somewhere the archive's owner cannot write: another host, an "
            "append-only cloud bucket, a different uid, or immutable storage."
        ),
    }


def append_checkpoint_log(conn, destination: Path | str) -> dict:
    """Append one signed checkpoint record to a log outside the archive.

    Append-friendly by construction: one JSON object per line, written with
    `O_APPEND` and fsynced, so a concurrent appender interleaves whole lines
    rather than corrupting one, and an interrupted write costs at most the
    trailing line. Nothing is ever rewritten — reading the log needs no state
    from this process, and a destination that only permits appends (the whole
    point) is enough.

    The line is the checkpoint record plus `v` and `exported_at`. Those two are
    deliberately *outside* the signed payload: `checkpoint_payload` is frozen
    (docs/FORMAT.md §5) and every record signed before this existed must keep
    verifying byte-for-byte. So the timestamp is unauthenticated, and
    `checkpoint_log_claim` says so rather than letting it read as evidence.
    """
    # Never sign a tip the backend itself would refuse. On Postgres the one
    # tamper signal the archive has is chain_tip disagreeing with events —
    # the exact state create_backup refuses to launder into a bundle — and
    # this export was signing the events-derived tip without looking, which
    # laundered that divergence into the external anti-tampering log instead.
    # On SQLite the same call checks the witness, so an unwitnessed tip is
    # refused for the same reason.
    from .backends import backend_for
    backend_for(conn).verify_tip(conn)
    record = checkpoint_record(conn)
    entry = {"v": CHECKPOINT_LOG_VERSION, "exported_at": int(time.time()),
             **record}
    line = json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n"

    path = Path(destination).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as stream:
        stream.write(line)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.chmod(path, 0o600)
    except OSError:
        # Best effort, and non-fatal on purpose: the destinations where this
        # log is actually worth something — another host, a mounted share, a
        # different uid's directory — are exactly the ones where this process
        # may not own the file. Failing the export there would push the
        # operator back to a local destination, which is the weaker choice.
        pass
    return entry


def read_checkpoint_log(destination: Path | str) -> dict:
    """Parse a checkpoint log. Reports damage rather than skipping it.

    A line that does not parse is the signature of truncation or tampering, so
    it is returned in `malformed` with its line number and never silently
    dropped. An empty or absent log is not an error here — it is a fact for the
    caller to judge, and `verify_checkpoint_log` judges it.
    """
    path = Path(destination).expanduser()
    if not path.exists():
        return {"exists": False, "entries": [], "malformed": []}
    entries, malformed = [], []
    for number, raw in enumerate(path.read_text().splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            malformed.append({"line": number, "why": "not valid JSON"})
            continue
        if not isinstance(entry, dict):
            malformed.append({"line": number, "why": "line is not an object"})
            continue
        entry["_line"] = number
        entries.append(entry)
    return {"exists": True, "entries": entries, "malformed": malformed}


def verify_checkpoint_log(conn, destination: Path | str) -> dict:
    """Check the archive against EVERY checkpoint the log records.

    Every record must verify. Passing because the newest one checked out would
    reintroduce the hole: an attacker who rolls the archive back to tip #400
    and appends a fresh checkpoint there produces a log whose last line is
    perfectly valid — and whose earlier lines, at #900, are the evidence.

    `rollback` is raised loudly and separately from `ok`, because the two are
    different events for an operator: a signature that fails is a broken or
    foreign record, while a *valid* signature over a tip the archive no longer
    reaches is the archive having lost history it once had.
    """
    parsed = read_checkpoint_log(destination)
    claim = checkpoint_log_claim(destination)

    def _empty(why: str) -> dict:
        """Same key set as a real result, so no caller has to special-case it.

        `ok` is False on purpose: a log that is absent or empty has verified
        nothing, and the one way this mechanism could quietly fail open is by
        letting "nothing to check" read as "checked out".
        """
        return {"ok": False, "checked": 0, "failures": [], "rollback": False,
                "highest_checkpointed_tip": 0, "records": [], "claim": claim,
                "why": why}

    if not parsed["exists"]:
        return _empty(f"no checkpoint log at {destination}")

    results, failures = [], []
    rollback = False
    highest = 0
    for entry in parsed["entries"]:
        line = entry.pop("_line")
        version = entry.pop("v", None)
        exported_at = entry.pop("exported_at", None)
        if version != CHECKPOINT_LOG_VERSION:
            failures.append({"line": line,
                             "why": f"unknown log record version {version!r}"})
            continue
        outcome = verify_checkpoint(conn, entry)
        outcome.update({"line": line, "exported_at": exported_at})
        results.append(outcome)
        if outcome.get("rollback"):
            rollback = True
        if not outcome["ok"]:
            failures.append({"line": line, "why": outcome["why"]})
        highest = max(highest, int(entry.get("tip_id") or 0))

    for bad in parsed["malformed"]:
        failures.append(bad)

    if not results and not failures:
        return _empty(f"the checkpoint log at {destination} is empty")

    why = None
    if rollback:
        why = ("ROLLBACK: the archive no longer reaches a tip that a signed, "
               "exported checkpoint says it once had")
    elif failures:
        why = f"{len(failures)} checkpoint record(s) did not verify"
    return {
        "ok": not failures,
        "checked": len(results),
        "failures": failures,
        "rollback": rollback,
        "highest_checkpointed_tip": highest,
        "records": results,
        "claim": claim,
        "why": why,
    }
