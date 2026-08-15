"""Dispatch capabilities: what replaces ``CONTEXTD_DERIVATION_SOURCE``.

The old binding was an **integer in an environment variable**. A harness set
``CONTEXTD_DERIVATION_SOURCE=41837`` on a model subprocess, and any note that
subprocess wrote was recorded as derived from egress #41837. Three things were
wrong with that, and all three are exploitable by the process it was meant to
constrain:

1. **Enumerable.** Event ids are small consecutive integers. A process that
   wants lineage it did not earn can simply try numbers until one is an egress
   with an item list.
2. **Forgeable by the holder.** The subprocess owns its own environment. It can
   overwrite the variable and claim a *different* disclosure — including one
   with a larger item set, which widens the anchors it may cite.
3. **Unbounded and reusable.** Nothing expired, nothing was consumed. One value
   authorized any number of derived writes, forever.

A capability fixes each of those by being opaque, bound, expiring, and
single-use. The daemon mints it; the client cannot construct one because it is
looked up by id in daemon-owned state, not parsed.

Bound fields, and what each one stops:

    archive_uuid    a capability from one archive is inert in another
    principal_uid   the dispatching principal, from kernel peer credentials
    dispatcher      the harness/session that requested it
    egress_id       the exact disclosure ...
    egress_digest   ... and the exact bytes of it, so a later disclosure
                    reusing the id cannot inherit the capability
    allowed_write   the single (source, kind) this may produce
    dispatch_state  the observed state at issue time; a capability issued for
                    a live dispatch is not usable after that dispatch failed
    nonce           consumed atomically with the write it authorizes

The anchor-membership and semantic-boundary checks that already existed are
preserved and still run: a capability says *this write may happen*, never
*these claims are supported*.
"""

import hashlib
import json
import secrets
import time

from .canonical import canonical_digest

DOMAIN = "contextd.DispatchCapabilityV1"

#: Capabilities are short-lived by construction. A dispatch that takes longer
#: than this should request a new one rather than hold a long-lived write token.
DEFAULT_TTL_SECONDS = 900
MAX_TTL_SECONDS = 3600

#: The writes a dispatch capability may authorize. A capability cannot be used
#: to append a grant, a decision, or anything else authority-bearing.
ALLOWED_WRITES = frozenset({
    ("note", "note"),
    ("loop", "loop"),
})

DISPATCH_STATES = ("issued", "dispatched", "succeeded", "failed", "timeout")

SCHEMA = """
CREATE TABLE IF NOT EXISTS dispatch_capabilities (
  capability_id  TEXT PRIMARY KEY,
  secret_hash    TEXT NOT NULL,
  archive_uuid   TEXT NOT NULL,
  principal_uid  INTEGER NOT NULL,
  dispatcher     TEXT NOT NULL,
  egress_id      INTEGER NOT NULL,
  egress_digest  TEXT NOT NULL,
  write_source   TEXT NOT NULL,
  write_kind     TEXT NOT NULL,
  dispatch_state TEXT NOT NULL,
  issued_at      INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  nonce          TEXT NOT NULL,
  consumed_event INTEGER
);
"""


class CapabilityError(RuntimeError):
    """A dispatch capability was refused."""


def _ensure(conn) -> None:
    conn.executescript(SCHEMA)


def _egress_digest(conn, egress_id: int) -> str:
    row = conn.execute(
        "SELECT kind, content, meta FROM events WHERE id = ?", (egress_id,)
    ).fetchone()
    if row is None or row["kind"] != "egress":
        raise CapabilityError(f"#{egress_id} is not a disclosure")
    meta = json.loads(row["meta"]) if row["meta"] else {}
    if not isinstance(meta.get("items"), list):
        raise CapabilityError(
            f"disclosure #{egress_id} carries no item list, so there is "
            f"nothing to bind anchors against"
        )
    return hashlib.sha256((row["content"] or "").encode()).hexdigest()


def issue(conn, egress_id: int, principal_uid: int, dispatcher: str,
          write: tuple[str, str] = ("note", "note"),
          ttl_seconds: int = DEFAULT_TTL_SECONDS) -> dict:
    """Mint a capability. Only the authority plane calls this.

    Returns ``{"capability_id", "secret", ...}``. The **secret is returned
    once** and only its hash is stored, so a reader of the capability table
    cannot use what it finds there.
    """
    _ensure(conn)
    if tuple(write) not in ALLOWED_WRITES:
        raise CapabilityError(
            f"{write[0]}/{write[1]} is not a permissible dispatch write; "
            f"a capability cannot authorize authority-bearing events"
        )
    if not (0 < ttl_seconds <= MAX_TTL_SECONDS):
        raise CapabilityError(
            f"ttl must be in (0, {MAX_TTL_SECONDS}]; a dispatch capability "
            f"that does not expire is an ambient permission"
        )
    if not isinstance(dispatcher, str) or not dispatcher or len(dispatcher) > 128:
        raise CapabilityError("dispatcher must be a bounded, non-empty label")

    from .attest import archive_uuid
    digest = _egress_digest(conn, egress_id)
    issued = int(time.time())
    capability_id = secrets.token_hex(32)
    secret = secrets.token_hex(32)
    conn.execute(
        "INSERT INTO dispatch_capabilities (capability_id, secret_hash, "
        "archive_uuid, principal_uid, dispatcher, egress_id, egress_digest, "
        "write_source, write_kind, dispatch_state, issued_at, expires_at, "
        "nonce, consumed_event) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?, NULL)",
        (capability_id, hashlib.sha256(secret.encode()).hexdigest(),
         archive_uuid(conn), int(principal_uid), dispatcher, int(egress_id),
         digest, write[0], write[1], "issued", issued, issued + int(ttl_seconds),
         secrets.token_hex(32)),
    )
    conn.commit()
    return {"capability_id": capability_id, "secret": secret,
            "egress_id": egress_id, "expires_at": issued + int(ttl_seconds),
            "write": list(write), "dispatcher": dispatcher}


def mark_dispatched(conn, capability_id: str, state: str) -> None:
    """Record the observed dispatch state.

    A capability issued for a dispatch that then failed or timed out must not
    still authorize a write: the model never saw the bytes, so anything it
    writes is not derived from them.
    """
    _ensure(conn)
    if state not in DISPATCH_STATES:
        raise CapabilityError(f"unknown dispatch state {state!r}")
    conn.execute(
        "UPDATE dispatch_capabilities SET dispatch_state = ? "
        "WHERE capability_id = ?", (state, capability_id))
    conn.commit()


def _row(conn, capability_id: str):
    _ensure(conn)
    return conn.execute(
        "SELECT * FROM dispatch_capabilities WHERE capability_id = ?",
        (capability_id,)).fetchone()


def verify(conn, capability_id: str, secret: str, principal_uid: int,
           dispatcher: str, write: tuple[str, str],
           now: int | None = None) -> dict:
    """Check a capability against every field it is bound to.

    Raises :class:`CapabilityError` on any mismatch. Returns the row so the
    caller can bind anchors to ``egress_id``.
    """
    now = now if now is not None else int(time.time())
    row = _row(conn, capability_id)
    if row is None:
        raise CapabilityError(
            "no such dispatch capability; a capability is issued by the "
            "authority plane and cannot be constructed by a client"
        )
    if not secrets.compare_digest(
        hashlib.sha256((secret or "").encode()).hexdigest(), row["secret_hash"]
    ):
        raise CapabilityError("capability secret does not match")
    if row["consumed_event"] is not None:
        raise CapabilityError(
            f"capability already consumed by event #{row['consumed_event']}; "
            f"one dispatch capability authorizes one write"
        )
    if now >= row["expires_at"]:
        raise CapabilityError("capability has expired")

    from .attest import archive_uuid
    if row["archive_uuid"] != archive_uuid(conn):
        raise CapabilityError("capability was issued for a different archive")
    if int(principal_uid) != row["principal_uid"]:
        raise CapabilityError("capability belongs to a different principal")
    if dispatcher != row["dispatcher"]:
        raise CapabilityError("capability belongs to a different dispatch session")
    if tuple(write) != (row["write_source"], row["write_kind"]):
        raise CapabilityError(
            f"capability permits {row['write_source']}/{row['write_kind']}, "
            f"not {write[0]}/{write[1]}"
        )
    if row["dispatch_state"] in ("failed", "timeout"):
        raise CapabilityError(
            f"the dispatch this capability was issued for {row['dispatch_state']}; "
            f"the model never saw the disclosed bytes, so nothing it writes is "
            f"derived from them"
        )
    # the disclosure must still be the one the capability was bound to
    if _egress_digest(conn, row["egress_id"]) != row["egress_digest"]:
        raise CapabilityError(
            "the bound disclosure's bytes have changed since issue"
        )
    return {k: row[k] for k in row.keys() if k != "secret_hash"}


def consume(conn, capability_id: str, event_id: int) -> None:
    """Mark a capability used. MUST run inside the append transaction.

    Conditional on it still being unconsumed, so two concurrent writers racing
    on one capability cannot both succeed.
    """
    cursor = conn.execute(
        "UPDATE dispatch_capabilities SET consumed_event = ? "
        "WHERE capability_id = ? AND consumed_event IS NULL",
        (event_id, capability_id))
    if cursor.rowcount != 1:
        raise CapabilityError(
            "capability was already consumed; one dispatch capability "
            "authorizes exactly one write"
        )


def digest(capability_id: str) -> str:
    """A stable, non-secret reference recorded in the derived event."""
    return canonical_digest(DOMAIN, {"capability_id": capability_id})


def token(capability: dict) -> str:
    """The opaque string handed to a dispatched process.

    Opaque on purpose: it is a random id plus a random secret, carrying no
    event id, no item list, and nothing an attacker can enumerate toward.
    """
    return f"{capability['capability_id']}.{capability['secret']}"


def parse_token(raw: str) -> tuple[str, str]:
    if not isinstance(raw, str) or raw.count(".") != 1:
        raise CapabilityError("malformed dispatch capability token")
    capability_id, secret = raw.split(".", 1)
    if len(capability_id) != 64 or len(secret) != 64:
        raise CapabilityError("malformed dispatch capability token")
    return capability_id, secret
