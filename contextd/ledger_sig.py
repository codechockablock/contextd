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

SCHEMA = """
CREATE TABLE IF NOT EXISTS service_keys (
  key_id     TEXT PRIMARY KEY,
  public_pem TEXT NOT NULL,
  created    INTEGER NOT NULL,
  retired    INTEGER
);
CREATE TABLE IF NOT EXISTS service_signatures (
  event_id   INTEGER PRIMARY KEY,
  key_id     TEXT NOT NULL,
  digest     TEXT NOT NULL,
  signature  TEXT NOT NULL,
  signed_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS service_tips (
  tip_id     INTEGER PRIMARY KEY,
  chain_hash TEXT NOT NULL,
  key_id     TEXT NOT NULL,
  signature  TEXT NOT NULL,
  signed_at  INTEGER NOT NULL,
  cutover    INTEGER NOT NULL DEFAULT 0
);
"""


class LedgerSignatureError(RuntimeError):
    """A service signature is missing, malformed, or does not verify."""


def _ensure(conn) -> None:
    """Require the signature schema without mutating the archive.

    Verification must never create the evidence it is checking.  Fresh archives
    receive these tables from ``contextd.db.SCHEMA`` and legacy archives receive
    them only through the explicit security migration.
    """
    required = {"service_keys", "service_signatures", "service_tips"}
    present = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    missing = required - present
    if missing:
        raise LedgerSignatureError("service-signature schema is not installed")


def key_path() -> Path:
    return home() / KEY_NAME


def _read_private_key(path: Path):
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
    if not isinstance(private, ec.EllipticCurvePrivateKey) or not isinstance(
        private.curve, ec.SECP256R1
    ):
        raise LedgerSignatureError("service signing key must be P-256")
    return private


def _load_or_create_key(conn):
    """The service signing key.

    0600, and in a hardened deployment owned by the service account so the
    client plane cannot read it. `_assert_service_plane` is what makes that
    boundary explicit rather than incidental.
    """
    _ensure(conn)
    path = key_path()
    if path.exists():
        if path.is_symlink():
            raise LedgerSignatureError("service signing key may not be a symlink")
        private = _read_private_key(path)
    else:
        private = ec.generate_private_key(ec.SECP256R1())
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
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
    key_id = canonical_digest("contextd.ServiceKeyV1", {"pem": public_pem})[:32]
    existing = conn.execute(
        "SELECT public_pem FROM service_keys WHERE key_id = ?", (key_id,)
    ).fetchone()
    if existing is not None and existing["public_pem"] != public_pem:
        raise LedgerSignatureError("service key id collides with different key bytes")
    if existing is None:
        conn.execute(
            "INSERT INTO service_keys (key_id, public_pem, created, retired) "
            "VALUES (?,?,?, NULL)", (key_id, public_pem, int(time.time())))
        conn.commit()
    return private, key_id


@dataclass(frozen=True)
class SigningContext:
    """A key loaded before the append transaction and used only inside it."""

    private: ec.EllipticCurvePrivateKey
    key_id: str


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
    """Load the service key iff this archive has crossed the signed cutover."""
    if cutover_tip_id(conn) is None:
        return None
    private, key_id = _load_or_create_key(conn)
    return SigningContext(private=private, key_id=key_id)


def rotate_key(conn) -> str:
    """Retire the current key and mint a new one.

    The retired key stays in the registry so signatures it made before
    rotation still verify — rotation must not invalidate history, or every
    rotation would look like tampering.
    """
    _ensure(conn)
    path = key_path()
    if path.exists():
        _private, old_id = _load_or_create_key(conn)
        conn.execute("UPDATE service_keys SET retired = ? WHERE key_id = ?",
                     (int(time.time()), old_id))
        conn.commit()
        path.unlink()
    _private, new_id = _load_or_create_key(conn)
    return new_id


def active_key_id(conn) -> str:
    _private, key_id = _load_or_create_key(conn)
    return key_id


def _public(conn, key_id: str):
    # a verifier must work against an archive that has never signed anything —
    # returning "unknown key" is a refusal, crashing on a missing table is not
    _ensure(conn)
    row = conn.execute("SELECT public_pem FROM service_keys WHERE key_id = ?",
                       (key_id,)).fetchone()
    if row is None:
        raise LedgerSignatureError(f"unknown service key {key_id!r}")
    expected = canonical_digest(
        "contextd.ServiceKeyV1", {"pem": row["public_pem"]}
    )[:32]
    if expected != key_id:
        raise LedgerSignatureError("service key registry id does not match key bytes")
    try:
        public = serialization.load_pem_public_key(row["public_pem"].encode())
    except (TypeError, ValueError) as exc:
        raise LedgerSignatureError("service public key is malformed") from exc
    if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(
        public.curve, ec.SECP256R1
    ):
        raise LedgerSignatureError("service public key must be P-256")
    return public


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
    signature = signing.private.sign(message, ec.ECDSA(hashes.SHA256()))
    digest = canonical_digest(ENVELOPE_DOMAIN, payload)
    conn.execute(
        "INSERT INTO service_signatures "
        "(event_id, key_id, digest, signature, signed_at) VALUES (?,?,?,?,?)",
        (int(row["id"]), signing.key_id, digest, signature.hex(), int(time.time())),
    )
    return {
        "event": int(row["id"]),
        "key_id": signing.key_id,
        "signature": signature.hex(),
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
    signature = signing.private.sign(
        canonical_bytes(TIP_DOMAIN, payload), ec.ECDSA(hashes.SHA256())
    )
    conn.execute(
        "INSERT INTO service_tips "
        "(tip_id, chain_hash, key_id, signature, signed_at, cutover) "
        "VALUES (?,?,?,?,?,?)",
        (
            int(tip_id),
            chain_hash,
            signing.key_id,
            signature.hex(),
            int(time.time()),
            1 if cutover else 0,
        ),
    )
    return {
        "tip_id": int(tip_id),
        "chain_hash": chain_hash,
        "key_id": signing.key_id,
        "signature": signature.hex(),
        "cutover": bool(cutover),
    }


def sign_accepted_append(
    conn, row: dict, chain_hash: str, signing: SigningContext
) -> dict:
    """Sign an accepted event and its resulting tip in the append transaction."""
    event = _insert_event_signature(conn, row, signing)
    tip = _insert_tip_signature(
        conn, int(row["id"]), chain_hash, signing, cutover=False
    )
    return {"event": event, "tip": tip}


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
    try:
        _public(conn, stored["key_id"]).verify(
            bytes.fromhex(stored["signature"]), message,
            ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, LedgerSignatureError) as exc:
        return {"event": event_id, "signed": True, "ok": False,
                "why": f"signature does not verify: {type(exc).__name__}"}
    return {"event": event_id, "signed": True, "ok": True,
            "key_id": stored["key_id"]}


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
    try:
        _public(conn, stored["key_id"]).verify(
            bytes.fromhex(stored["signature"]),
            canonical_bytes(TIP_DOMAIN, payload), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, LedgerSignatureError) as exc:
        return {"tip_id": tip_id, "ok": False,
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
            "cutover": bool(stored["cutover"])}


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
    coverage_ok = (
        not cutover_anomalies
        and not missing_events
        and current_tip_result["ok"]
    )
    return {
        "signed_events": len(signed_ids), "checked_events": len(events),
        "signed_tips": len(tips),
        "bad_events": bad_events, "bad_tips": bad_tips,
        "cutover_tip": cutover,
        "cutover_anomalies": cutover_anomalies,
        "required_events": len(required_ids),
        "missing_events": missing_events,
        "current_tip": current_tip,
        "coverage_ok": coverage_ok,
        "ok": coverage_ok and not bad_events and not bad_tips,
    }


# --- protected checkpoint ---------------------------------------------------

def checkpoint_record(conn) -> dict:
    """The whole content of a protected checkpoint.

    Five fields, deliberately: archive UUID, tip id, chain hash, key id, and
    the signature. Nothing about *what* the archive contains leaves with it —
    a checkpoint destination is by definition somewhere the operator does not
    fully control, so it must not carry archive content.
    """
    from .attest import archive_uuid
    from .db import _db_tip
    private, key_id = _load_or_create_key(conn)
    tip = _db_tip(conn)
    payload = {"archive_uuid": archive_uuid(conn), "tip_id": tip["id"],
               "chain_hash": tip["chain_hash"], "key_id": key_id}
    signature = private.sign(canonical_bytes(CHECKPOINT_DOMAIN, payload),
                             ec.ECDSA(hashes.SHA256()))
    return {**payload, "signature": signature.hex()}


def verify_checkpoint(conn, record: dict) -> dict:
    """Check a checkpoint against the archive's current state.

    A checkpoint whose tip is *ahead* of the archive is the rollback signal:
    the archive has fewer events than something the attacker could not rewrite
    said it had.
    """
    from .attest import archive_uuid
    from .db import _db_tip
    required = {"archive_uuid", "tip_id", "chain_hash", "key_id", "signature"}
    if not isinstance(record, dict) or set(record) != required:
        return {"ok": False, "why": "malformed checkpoint record"}
    _ensure(conn)
    payload = {k: record[k] for k in
               ("archive_uuid", "tip_id", "chain_hash", "key_id")}
    try:
        _public(conn, record["key_id"]).verify(
            bytes.fromhex(record["signature"]),
            canonical_bytes(CHECKPOINT_DOMAIN, payload),
            ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, LedgerSignatureError) as exc:
        return {"ok": False, "why": f"checkpoint signature does not verify: "
                                    f"{type(exc).__name__}"}
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
    return {"ok": True, "tip_id": record["tip_id"]}


def write_checkpoint(conn, destination: Path | str) -> Path:
    """Write a checkpoint to a configured destination.

    The destination must be somewhere the client plane cannot rewrite for this
    to mean anything; this function does not and cannot verify that, which is
    why `ctx security doctor` reports rollback resistance separately.
    """
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    record = checkpoint_record(conn)
    destination.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    os.chmod(destination, 0o600)
    return destination
