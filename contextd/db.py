"""Event store: one append-only table, FTS index, content-addressed blobs."""

import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
import threading
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import fcntl

from . import home, load_config
from .redact import redact
from .schemas import validate_egress_meta, validate_event_meta

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY,
  ts TEXT NOT NULL,
  source TEXT NOT NULL,
  kind TEXT NOT NULL,
  uri TEXT,
  content TEXT,
  content_hash TEXT,
  meta TEXT,
  prev_hash TEXT,
  chain_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_uri ON events(uri, id);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
CREATE UNIQUE INDEX IF NOT EXISTS idx_egress_outcome_once
ON events(json_extract(meta, '$.egress_id')) WHERE kind = 'egress_outcome';
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
  content, content='events', content_rowid='id', tokenize='porter unicode61'
);
CREATE TRIGGER IF NOT EXISTS events_fts_insert AFTER INSERT ON events
WHEN new.content IS NOT NULL AND new.kind != 'egress'
BEGIN INSERT INTO events_fts(rowid, content) VALUES (new.id, new.content); END;
CREATE TABLE IF NOT EXISTS cursors (
  source TEXT PRIMARY KEY,
  state TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chain_state (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  witness_initialized INTEGER NOT NULL CHECK (witness_initialized = 1)
);

-- Authority-plane state (contextd/attest.py) lives in THIS database on
-- purpose: a nonce must be consumed inside the same transaction as the append
-- it authorizes, and a transaction cannot span two SQLite files. Putting them
-- apart would leave a window where a crash consumes a nonce with no event, or
-- appends an event with the nonce still live. The append-only triggers apply
-- to `events` only, so these tables remain mutable as their semantics require.
CREATE TABLE IF NOT EXISTS operator_keys (
  key_id      TEXT PRIMARY KEY,
  public_der  BLOB NOT NULL,
  signer      TEXT NOT NULL,
  registered  TEXT NOT NULL,
  revoked     TEXT
);
CREATE TABLE IF NOT EXISTS operator_nonces (
  nonce          TEXT PRIMARY KEY,
  key_id         TEXT NOT NULL,
  sequence       INTEGER NOT NULL,
  issued_at      INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  action         TEXT NOT NULL,
  digest         TEXT NOT NULL,
  consumed_event INTEGER
);
CREATE TABLE IF NOT EXISTS operator_sequence (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  value     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS archive_identity (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  uuid      TEXT NOT NULL
);
"""

WITNESS_VERSION = 1
SCHEMA_VERSION = 1
_PROCESS_CHAIN_LOCK = threading.RLock()


class ChainStateError(RuntimeError):
    """The database, recovery journal, and external tip cannot be reconciled."""


class InjectedCrash(BaseException):
    """Deterministic test-only interruption that deliberately skips cleanup."""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


_CONFIG_CACHE: dict = {}


def _append_config() -> dict:
    """Config for the capture-side floor, cached on (home, config mtime).

    Every append consults it, and a bulk ingest appends thousands of times, so
    re-reading config.toml per event is a real cost. The cache key includes the
    mtime, so an edited config takes effect on the next append rather than the
    next process — it can only ever *add* patterns (contextd/redact.py), so a
    stale read cannot weaken the floor.
    """
    root = home()
    path = root / "config.toml"
    try:
        stamp = path.stat().st_mtime_ns
    except OSError:
        stamp = 0
    key = (str(root), stamp)
    cached = _CONFIG_CACHE.get(key)
    if cached is None:
        cached = load_config()
        _CONFIG_CACHE.clear()
        _CONFIG_CACHE[key] = cached
    return cached


class DirectAccessRefused(RuntimeError):
    """Hardened mode: the client plane may not open the archive directly."""


def _guard_direct_access() -> None:
    """In hardened mode only the authority plane opens the production archive.

    In a real hardened deployment the enforcement is the operating system: the
    database is owned by the service UID with mode 0600, so a client process
    physically cannot open it. This check exists for two reasons, neither of
    which is "it is the security boundary":

    * it makes development mode able to *simulate* the boundary, so the
      client-plane code paths are exercised against a refusal; and
    * it turns what would otherwise be an opaque `sqlite3.OperationalError:
      unable to open database file` into a refusal that says which path was
      taken and what the caller should have used instead.

    A hostile same-UID process can set the marker this consults. That does not
    matter: in a hardened deployment it still cannot read the file, and in a
    development deployment there is no boundary to defeat.
    """
    from .authd import hardened, is_service_process
    if not hardened() or is_service_process():
        return
    raise DirectAccessRefused(
        "hardened mode: this process is in the client plane and may not open "
        "the archive directly. Use the authority service RPC surface "
        "(contextd/service.py). There is no direct-SQLite fallback — see "
        "docs/SECURITY.md, Deployment states."
    )


class SchemaVersionError(RuntimeError):
    """The archive was written by a newer contextd than this one."""


def assert_supported_schema(path: Path | None = None) -> int:
    """Refuse an unsupported future schema **before touching anything**.

    Order matters here and is the whole point of the function. The archive is
    opened read-only to read `user_version`, and every mutating step —
    `mkdir`, `chmod`, `PRAGMA journal_mode=WAL`, `executescript(SCHEMA)` —
    happens only after this returns. Previously a newer archive was opened,
    upgraded in place with this version's schema, and used: an older binary
    would silently write rows a newer one might not be able to interpret, and
    the damage was done before anyone could notice.

    A missing database is not a version problem; there is nothing to refuse.
    """
    path = path or (home() / "contextd.db")
    if not path.exists():
        return 0
    probe = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        version = probe.execute("PRAGMA user_version").fetchone()[0]
    finally:
        probe.close()
    if version > SCHEMA_VERSION:
        raise SchemaVersionError(
            f"{path} was written by a newer contextd (schema version "
            f"{version}; this build supports {SCHEMA_VERSION}). Refusing "
            f"before any filesystem or database change — upgrade contextd "
            f"rather than letting an older build write to it."
        )
    return version


def connect() -> sqlite3.Connection:
    _guard_direct_access()
    # BEFORE mkdir, chmod, WAL, or schema application
    assert_supported_schema()
    home().mkdir(parents=True, exist_ok=True)
    os.chmod(home(), 0o700)
    conn = sqlite3.connect(home() / "contextd.db")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    # stamp legacy (user_version 0) archives; a pragma write touches no event
    # bytes, so the chain and witness never see it. Never downgrades.
    if conn.execute("PRAGMA user_version").fetchone()[0] == 0:
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    _migrate_chain(conn)
    _bootstrap_witness(conn)
    recover_chain_state(conn)
    _reap_scratch()
    for f in home().glob("contextd.db*"):
        try:
            os.chmod(f, 0o600)
        except OSError:
            pass
    return conn


def _reap_scratch() -> None:
    """Startup recovery for scratch a killed process left behind.

    Only positively identified, sufficiently old contextd scratch directly
    under this archive's scratch root qualifies (contextd/scratch.py) — never a
    glob over a shared temp directory, never a symlink target. A failure here
    warns on stderr instead of raising: an undeletable stale directory must be
    visible, but it must not make the archive unopenable.
    """
    from .scratch import ScratchCleanupError, reap_stale
    try:
        for name in reap_stale():
            print(f"contextd: removed stale scratch {name}", file=sys.stderr)
    except (OSError, ScratchCleanupError) as exc:
        print(f"contextd: WARNING stale scratch not removed: {exc}",
              file=sys.stderr)


def chain_state_paths(root: Path | None = None) -> dict[str, Path]:
    root = root or home()
    return {
        "witness": root / "chain-witness.json",
        "recovery": root / "chain-recovery.json",
        "lock": root / "chain-witness.lock",
    }


def _connection_root(conn: sqlite3.Connection) -> Path:
    row = conn.execute("PRAGMA database_list").fetchone()
    database = row["file"] if isinstance(row, sqlite3.Row) else row[2]
    if not database:
        raise ChainStateError("the event ledger has no filesystem path")
    return Path(database).resolve().parent


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(raw)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    finally:
        if tmp.exists():
            tmp.unlink()


def _unlink_durable(path: Path) -> None:
    if path.exists():
        path.unlink()
        _fsync_dir(path.parent)


@contextmanager
def _chain_lock(root: Path | None = None):
    paths = chain_state_paths(root)
    paths["lock"].parent.mkdir(parents=True, exist_ok=True)
    with _PROCESS_CHAIN_LOCK, paths["lock"].open("a+", encoding="utf-8") as stream:
        os.chmod(paths["lock"], 0o600)
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield paths


def _db_tip(conn: sqlite3.Connection) -> dict:
    row = conn.execute(
        "SELECT id, chain_hash FROM events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return (
        {"id": int(row["id"]), "chain_hash": row["chain_hash"] or ""}
        if row
        else {"id": 0, "chain_hash": ""}
    )


def _read_state(path: Path, label: str) -> dict | None:
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ChainStateError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ChainStateError(f"malformed {label}")
    if value.get("version") != WITNESS_VERSION:
        raise ChainStateError(f"unsupported {label} version")
    return value


def _read_tip(value, label: str) -> dict:
    if not isinstance(value, dict) or set(value) != {"id", "chain_hash"}:
        raise ChainStateError(f"malformed {label}")
    event_id, chain_hash = value["id"], value["chain_hash"]
    if not isinstance(event_id, int) or isinstance(event_id, bool) or event_id < 0:
        raise ChainStateError(f"invalid event id in {label}")
    valid_hash = (
        chain_hash == ""
        if event_id == 0
        else (
            isinstance(chain_hash, str)
            and re.fullmatch(r"[0-9a-f]{64}", chain_hash) is not None
        )
    )
    if not valid_hash:
        raise ChainStateError(f"invalid chain hash in {label}")
    return value


def _witness_value(tip: dict) -> dict:
    return {"version": WITNESS_VERSION, **tip}


def _bootstrap_witness(conn: sqlite3.Connection) -> None:
    """Start external witnessing without changing any historical event bytes."""
    with _chain_lock(_connection_root(conn)) as paths:
        marked = conn.execute(
            "SELECT 1 FROM chain_state WHERE singleton = 1"
        ).fetchone()
        if paths["witness"].exists():
            if not marked:
                conn.execute(
                    "INSERT INTO chain_state(singleton, witness_initialized) "
                    "VALUES (1, 1)"
                )
                conn.commit()
            return
        if marked:
            raise ChainStateError("chain witness is missing after initialization")
        if paths["recovery"].exists():
            raise ChainStateError("recovery journal exists without a chain witness")
        _atomic_json(paths["witness"], _witness_value(_db_tip(conn)))
        conn.execute(
            "INSERT INTO chain_state(singleton, witness_initialized) VALUES (1, 1)"
        )
        conn.commit()


def _recover_locked(conn: sqlite3.Connection, paths: dict[str, Path]) -> dict:
    witness = _read_state(paths["witness"], "chain witness")
    if witness is None:
        raise ChainStateError("chain witness is missing")
    if set(witness) != {"version", "id", "chain_hash"}:
        raise ChainStateError("malformed chain witness")
    current = _db_tip(conn)
    recovery = _read_state(paths["recovery"], "chain recovery journal")
    witnessed = _read_tip(
        {"id": witness.get("id"), "chain_hash": witness.get("chain_hash")},
        "chain witness",
    )

    if recovery is None:
        if current != witnessed:
            raise ChainStateError(
                f"database tip {current['id']} does not match witnessed tip "
                f"{witnessed['id']}"
            )
        return current

    if set(recovery) != {"version", "previous", "target"}:
        raise ChainStateError("malformed chain recovery journal")
    previous = _read_tip(recovery.get("previous"), "recovery previous tip")
    target = _read_tip(recovery.get("target"), "recovery target tip")
    if target["id"] != previous["id"] + 1:
        raise ChainStateError("recovery journal does not describe one append")
    if previous != witnessed:
        if target == witnessed and current == witnessed:
            _unlink_durable(paths["recovery"])
            return current
        raise ChainStateError("recovery journal does not extend the witnessed tip")

    if current == previous:
        # Interrupted before SQLite commit: closing the dead connection rolled
        # back the row. The append has zero durable effect.
        _unlink_durable(paths["recovery"])
        return current
    if current == target:
        # SQLite committed but the witness was not finalized. Complete exactly
        # that already-durable append; never insert it again.
        _atomic_json(paths["witness"], _witness_value(current))
        _unlink_durable(paths["recovery"])
        return current
    raise ChainStateError("database tip matches neither side of recovery journal")


def recover_chain_state(conn: sqlite3.Connection, root: Path | None = None) -> dict:
    with _chain_lock(root or _connection_root(conn)) as paths:
        return _recover_locked(conn, paths)


def _chain_hash(
    prev, eid, ts, source, kind, uri, content, content_hash, meta_json
) -> str:
    h = hashlib.sha256()
    for part in (
        prev,
        str(eid),
        ts,
        source,
        kind,
        uri or "",
        content or "",
        content_hash or "",
        meta_json or "",
    ):
        h.update(part.encode())
        h.update(b"\x1f")
    return h.hexdigest()


def _migrate_chain(conn):
    """One-time: add chain columns and backfill over a pristine pre-chain
    archive. Rows that later appear without a chain are never auto-healed —
    ctx verify flags them instead."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(events)")}
    if "chain_hash" not in cols:
        conn.execute("ALTER TABLE events ADD COLUMN prev_hash TEXT")
        conn.execute("ALTER TABLE events ADD COLUMN chain_hash TEXT")
        conn.commit()
    if not conn.execute(
        "SELECT 1 FROM events WHERE chain_hash IS NULL LIMIT 1"
    ).fetchone():
        return
    nulls = conn.execute(
        "SELECT COUNT(*) FROM events WHERE chain_hash IS NULL"
    ).fetchone()[0]
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    if nulls != total:
        return  # partial gaps are evidence of tampering, not a migration
    conn.execute("BEGIN IMMEDIATE")
    try:
        if conn.execute(
            "SELECT 1 FROM events WHERE chain_hash IS NULL LIMIT 1"
        ).fetchone():
            conn.execute("DROP TRIGGER IF EXISTS events_no_update")
            prev = ""
            for r in conn.execute(
                "SELECT id, ts, source, kind, uri, content, content_hash, meta "
                "FROM events ORDER BY id"
            ).fetchall():
                ch = _chain_hash(
                    prev,
                    r["id"],
                    r["ts"],
                    r["source"],
                    r["kind"],
                    r["uri"],
                    r["content"],
                    r["content_hash"],
                    r["meta"],
                )
                conn.execute(
                    "UPDATE events SET prev_hash = ?, chain_hash = ? WHERE id = ?",
                    (prev, ch, r["id"]),
                )
                prev = ch
            conn.execute(
                "CREATE TRIGGER IF NOT EXISTS events_no_update "
                "BEFORE UPDATE ON events "
                "BEGIN SELECT RAISE(ABORT, 'events are append-only'); END"
            )
        conn.commit()
    except BaseException:
        conn.rollback()
        raise


def _verify_rows(conn) -> dict:
    """Recompute the whole chain. Detects rewrites, deletions, insertions, and
    unchained rows. Tamper-evident, not tamper-proof: an owner-level process
    that recomputes every hash defeats it (see the trust model)."""
    prev, last_ts = "", ""
    checked = ts_warnings = 0
    for r in conn.execute(
        "SELECT id, ts, source, kind, uri, content, content_hash, meta, "
        "prev_hash, chain_hash FROM events ORDER BY id"
    ):
        expect = _chain_hash(
            prev,
            r["id"],
            r["ts"],
            r["source"],
            r["kind"],
            r["uri"],
            r["content"],
            r["content_hash"],
            r["meta"],
        )
        if (
            r["chain_hash"] is None
            or (r["prev_hash"] or "") != prev
            or r["chain_hash"] != expect
        ):
            return {
                "ok": False,
                "checked": checked,
                "first_bad": r["id"],
                "ts_warnings": ts_warnings,
            }
        if r["ts"] < last_ts:
            ts_warnings += 1
        last_ts, prev = r["ts"], r["chain_hash"]
        checked += 1
    return {
        "ok": True,
        "checked": checked,
        "first_bad": None,
        "ts_warnings": ts_warnings,
    }


def verify_chain(conn, root: Path | None = None) -> dict:
    """Verify event hashes and that SQLite still ends at the witnessed tip."""
    result = _verify_rows(conn)
    if not result["ok"]:
        return result
    try:
        recover_chain_state(conn, root=root)
    except ChainStateError as exc:
        tip = _db_tip(conn)
        return {
            "ok": False,
            "checked": result["checked"],
            "first_bad": tip["id"] + 1,
            "ts_warnings": result["ts_warnings"],
            "witness_error": str(exc),
        }
    return result


def append_event_checked(
    conn,
    source,
    kind,
    uri=None,
    content=None,
    content_hash=None,
    meta=None,
    check: Callable[[sqlite3.Connection, str], None] | None = None,
    prepare: Callable[[sqlite3.Connection, str], dict] | None = None,
    bind: Callable[[sqlite3.Connection, str, int], None] | None = None,
    fault: Callable[[str], None] | None = None,
) -> int:
    """Append under one witness-first lock/transaction with crash recovery.

    ``check`` executes after ``BEGIN IMMEDIATE`` and immediately before the
    insert. The gate uses it for an atomic spend check.

    ``prepare`` runs under the chain lock, *before* the chain hash is computed,
    and returns extra metadata to merge into the row. It exists because the
    witness-first protocol has to know the exact bytes before it opens the
    transaction, so anything that must be resolved atomically with the append
    and then *written into it* — the covering grant for a delegated act — has
    to be resolved here. The chain lock is exclusive, so a concurrent revoke
    either committed before this call (and is seen) or commits after this
    append (and does not precede it).

    ``bind`` also runs inside that transaction, and additionally receives the
    id the new event will have. It exists so that consuming a single-use
    authorization (contextd/attest.py) and appending the event it authorizes
    are one atomic step: a crash between them is not representable, and two
    concurrent appends racing on one authorization cannot both commit.

    ``fault`` is an explicit deterministic test hook; raising
    :class:`InjectedCrash` leaves the journal in the state a killed process
    would leave behind.
    """
    # append_event historically committed any caller transaction. End it before
    # taking the witness lock so every writer observes the one global lock
    # order (witness, then SQLite) and cannot deadlock another appender.
    if conn.in_transaction:
        conn.commit()
    # The one capture-side privacy choke point. Every write to the archive
    # passes here, so applying the redaction floor and the closed schema at
    # this exact spot is what makes "no credential of a pinned class reaches
    # storage" a structural property rather than a convention each caller has
    # to remember (docs/SECURITY.md §6). Historical rows are never touched:
    # this runs only on the bytes of a new append.
    cfg = _append_config()
    if content is not None:
        content = redact(cfg, content)
    if uri is not None:
        uri = redact(cfg, uri)

    def _validated(raw):
        if kind == "egress":
            return validate_egress_meta(cfg, raw)
        return validate_event_meta(cfg, source, kind, raw)

    raw_meta = meta
    meta = _validated(meta)
    if content is not None and content_hash is None:
        content_hash = hashlib.sha256(content.encode()).hexdigest()
    meta_json = json.dumps(meta) if meta else None
    fault = fault or (lambda _phase: None)
    with _chain_lock(_connection_root(conn)) as paths:
        previous = _recover_locked(conn, paths)
        ts = now_iso()
        if prepare is not None:
            extra = prepare(conn, ts) or {}
            meta = _validated({**(raw_meta or {}), **extra})
            meta_json = json.dumps(meta) if meta else None
        eid = previous["id"] + 1
        chain = _chain_hash(
            previous["chain_hash"],
            eid,
            ts,
            source,
            kind,
            uri,
            content,
            content_hash,
            meta_json,
        )
        target = {"id": eid, "chain_hash": chain}
        _atomic_json(
            paths["recovery"],
            {
                "version": WITNESS_VERSION,
                "previous": previous,
                "target": target,
            },
        )
        committed = False
        try:
            conn.execute("BEGIN IMMEDIATE")
            if check is not None:
                check(conn, ts)
            if bind is not None:
                bind(conn, ts, eid)
            conn.execute(
                "INSERT INTO events (id, ts, source, kind, uri, content, "
                "content_hash, meta, prev_hash, chain_hash) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    eid,
                    ts,
                    source,
                    kind,
                    uri,
                    content,
                    content_hash,
                    meta_json,
                    previous["chain_hash"],
                    chain,
                ),
            )
            fault("before_db_commit")
            conn.commit()
            committed = True
            fault("after_db_commit")
            fault("before_witness_finalize")
            _atomic_json(paths["witness"], _witness_value(target))
            _unlink_durable(paths["recovery"])
            return eid
        except InjectedCrash:
            # Deliberately mirror abrupt process death. An uncommitted row is
            # rolled back when the test closes the connection; durable state is
            # reconciled by the next connect/append/verify.
            raise
        except BaseException:
            if not committed:
                conn.rollback()
                _unlink_durable(paths["recovery"])
            # Once SQLite commits, the recovery journal is the durable bridge
            # to the old witness. Preserve it on every later I/O failure so a
            # future connect can finish the already-committed append exactly
            # once instead of mistaking a stale witness for tampering.
            raise


def append_event(
    conn, source, kind, uri=None, content=None, content_hash=None, meta=None
) -> int:
    return append_event_checked(
        conn,
        source,
        kind,
        uri=uri,
        content=content,
        content_hash=content_hash,
        meta=meta,
    )


def last_hash(conn, uri):
    row = conn.execute(
        "SELECT kind, content_hash FROM events WHERE uri = ? ORDER BY id DESC LIMIT 1",
        (uri,),
    ).fetchone()
    # after a file_delete the hash must not match, or restorations are skipped
    if not row or row["kind"] == "file_delete":
        return None
    return row["content_hash"]


def store_blob(data: bytes) -> str:
    """Content-addressed blob storage, floor-redacted when the bytes are text.

    An oversized watched file is stored here instead of in `events.content`,
    which made the blob store a way around capture-side redaction. Anything
    that decodes as UTF-8 goes through the same floor as event content; binary
    blobs are stored as-is and are *not* covered by the redaction claim.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    else:
        data = redact(_append_config(), text).encode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    path = home() / "store" / digest[:2] / digest
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        os.chmod(path, 0o600)
    return digest


def get_cursor(conn, source) -> dict:
    row = conn.execute(
        "SELECT state FROM cursors WHERE source = ?", (source,)
    ).fetchone()
    return json.loads(row["state"]) if row else {}


def set_cursor(conn, source, state: dict):
    conn.execute(
        "INSERT INTO cursors (source, state) VALUES (?, ?) "
        "ON CONFLICT(source) DO UPDATE SET state = excluded.state",
        (source, json.dumps(state)),
    )
    conn.commit()
