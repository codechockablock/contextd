"""Event store: one append-only table, FTS index, content-addressed blobs."""

import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import sys
import tempfile
import threading
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import fcntl

from . import home, load_config
from .redact import redact, sanitize_content, sanitize_label
from .schemas import SchemaError, validate_egress_meta, validate_event_meta

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

WITNESS_VERSION = 1
SCHEMA_VERSION = 2
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


class SchemaMigrationRequired(SchemaVersionError):
    """An older archive must pass the explicit, audited migration first."""


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
    if path.is_symlink() or not path.is_file():
        raise SchemaVersionError("archive database must be a regular non-symlink file")
    # Do not use SQLite's ``immutable=1`` here: a live archive may hold the
    # committed version stamp in its WAL, and immutable readers deliberately
    # ignore that WAL and misclassify the archive as legacy.
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


def open_archive_for_migration(
    path: Path | None = None, *, read_only: bool = False
) -> sqlite3.Connection:
    """Open an existing archive without applying schema or touching files.

    This is the only supported way for the migration planner to inspect an old
    archive.  In particular it does not call ``connect()``, create tables, stamp
    ``user_version``, switch journal mode, recover a witness, or reap scratch.
    """
    _guard_direct_access()
    path = path or (home() / "contextd.db")
    if not path.exists() or path.is_symlink():
        raise SchemaVersionError("migration requires a regular existing archive")
    assert_supported_schema(path)
    mode = "ro" if read_only else "rw"
    conn = sqlite3.connect(f"file:{path}?mode={mode}", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def connect() -> sqlite3.Connection:
    _guard_direct_access()
    # BEFORE mkdir, chmod, WAL, or schema application
    database = home() / "contextd.db"
    existed = database.exists()
    version = assert_supported_schema(database)
    if existed and version < SCHEMA_VERSION:
        raise SchemaMigrationRequired(
            f"{database} uses schema version {version}; this build requires "
            f"{SCHEMA_VERSION}. Refusing to mutate or append before the explicit "
            "security migration. Run `ctx security migrate --dry-run`, inspect "
            "the plan, then run `ctx security migrate` from the authority plane."
        )
    home().mkdir(parents=True, exist_ok=True)
    os.chmod(home(), 0o700)
    conn = sqlite3.connect(home() / "contextd.db")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    # Only a brand-new archive is stamped here. Existing older archives must go
    # through the explicit cutover migration above; otherwise an old binary can
    # keep writing rows whose required signature coverage it does not know.
    if not existed:
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
    if path.is_symlink():
        raise ChainStateError(f"invalid {label}: symlinks are refused")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ChainStateError(f"invalid {label}: not a regular file")
            with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as stream:
                raw = stream.read(64 * 1024 + 1)
            if len(raw) > 64 * 1024:
                raise ChainStateError(f"invalid {label}: file is too large")
        finally:
            os.close(fd)
        value = json.loads(raw)
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


def verify_chain_read_only(conn, root: Path | None = None) -> dict:
    """Verify rows and the external witness without recovery or mutation."""
    result = _verify_rows(conn)
    if not result["ok"]:
        return result
    try:
        archive_root = root or _connection_root(conn)
        witness = _read_state(
            chain_state_paths(archive_root)["witness"], "chain witness"
        )
        if witness is None or set(witness) != {"version", "id", "chain_hash"}:
            raise ChainStateError("chain witness is missing or malformed")
        witnessed = _read_tip(
            {"id": witness.get("id"), "chain_hash": witness.get("chain_hash")},
            "chain witness",
        )
        current = _db_tip(conn)
        if current != witnessed:
            raise ChainStateError(
                f"database tip {current['id']} does not match witnessed tip "
                f"{witnessed['id']}"
            )
    except ChainStateError as exc:
        return {
            "ok": False,
            "checked": result["checked"],
            "first_bad": _db_tip(conn)["id"] + 1,
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
    for routing_value in (source, kind):
        if (
            not isinstance(routing_value, str)
            or not routing_value
            or len(routing_value) > 64
            or sanitize_label(cfg, routing_value) != routing_value
        ):
            # Routing columns are outside the closed metadata schemas, so they
            # must not become tiny arbitrary-content channels of their own.
            # The error deliberately does not echo the rejected value.
            raise SchemaError("event routing label is invalid")
    try:
        if content is not None:
            content = sanitize_content(cfg, content)
        if uri is not None:
            uri = sanitize_content(cfg, uri)
    except (TypeError, ValueError) as exc:
        raise SchemaError("event content field is invalid") from exc

    def _validated(raw):
        if kind == "egress":
            return validate_egress_meta(cfg, raw)
        return validate_event_meta(cfg, source, kind, raw)

    raw_meta = meta
    meta = _validated(meta)
    if content is not None:
        # A caller-supplied digest of pre-sanitization bytes would make the
        # archive claim to contain bytes it does not.  The stored digest is
        # always derived here from the exact stored content instead.
        content_hash = hashlib.sha256(content.encode()).hexdigest()
    elif content_hash is not None and not (
        isinstance(content_hash, str)
        and re.fullmatch(r"[0-9a-f]{64}", content_hash)
    ):
        raise SchemaError("event content digest is invalid")
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
        # The cutover defines complete signature coverage.  Load/create the key
        # before BEGIN (the key registry may need one setup commit), then insert
        # both the event and its service signatures in the single append
        # transaction below.  A crash can therefore produce neither or both,
        # never an accepted-but-unsigned event.
        from .ledger_sig import prepare_append_signing
        signing = prepare_append_signing(conn)
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
            if signing is not None:
                from .ledger_sig import sign_accepted_append
                sign_accepted_append(
                    conn,
                    {
                        "id": eid,
                        "ts": ts,
                        "source": source,
                        "kind": kind,
                        "uri": uri,
                        "content_hash": content_hash,
                        "meta": meta_json,
                    },
                    chain,
                    signing,
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


class BlobPrivacyError(ValueError):
    """A blob cannot cross the persistence privacy boundary safely."""


def _binary_blob_has_secret(cfg: dict, data: bytes) -> bool:
    """Detect floor/config secrets embedded in otherwise binary bytes.

    A single invalid byte used to turn off the UTF-8 redaction path for the
    entire blob.  Scan lossy UTF-8 and both UTF-16 byte orders so an attacker
    cannot hide a credential-shaped canary behind that encoding switch.  We
    refuse instead of rewriting binary offsets and silently corrupting data.
    """
    views = [data.decode("utf-8", errors="ignore")]
    if len(data) >= 2:
        views.extend(
            (
                data[: len(data) - len(data) % 2].decode(
                    "utf-16-le", errors="ignore"
                ),
                data[: len(data) - len(data) % 2].decode(
                    "utf-16-be", errors="ignore"
                ),
            )
        )
    if len(data) >= 4:
        aligned = data[: len(data) - len(data) % 4]
        views.extend(
            (
                aligned.decode("utf-32-le", errors="ignore"),
                aligned.decode("utf-32-be", errors="ignore"),
            )
        )
    return any(redact(cfg, view) != view for view in views)


def _open_private_blob_directory(shard: str) -> tuple[int, int, int]:
    """Open ``home/store/<shard>`` without following directory symlinks."""
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    root_fd = os.open(home(), flags)
    opened = [root_fd]
    try:
        parent_fd = root_fd
        for component in ("store", shard):
            try:
                os.mkdir(component, 0o700, dir_fd=parent_fd)
            except FileExistsError:
                pass
            child_fd = os.open(component, flags, dir_fd=parent_fd)
            opened.append(child_fd)
            info = os.fstat(child_fd)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise BlobPrivacyError("blob directory boundary is unsafe")
            parent_fd = child_fd
        return tuple(opened)  # type: ignore[return-value]
    except BaseException:
        for fd in reversed(opened):
            os.close(fd)
        raise


def _verify_existing_blob(shard_fd: int, digest: str) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(digest, flags, dir_fd=shard_fd)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            raise BlobPrivacyError("stored blob boundary is unsafe")
        observed = hashlib.sha256()
        while chunk := os.read(fd, 1024 * 1024):
            observed.update(chunk)
        if observed.hexdigest() != digest:
            raise BlobPrivacyError("stored blob digest does not verify")
    finally:
        os.close(fd)


def store_blob(data: bytes) -> str:
    """Content-addressed blob storage with a no-follow privacy boundary.

    An oversized watched file is stored here instead of in `events.content`,
    which made the blob store a way around capture-side redaction. Anything
    that is ordinary UTF-8 goes through the same sanitizer as event content.
    Binary/multibyte data is stored byte-identically only after lossy UTF-8 and
    UTF-16/32 views contain no pinned/configured credential match; a match is
    refused because rewriting offsets would corrupt the object.
    """
    if not isinstance(data, bytes):
        raise BlobPrivacyError("blob payload must be bytes")
    cfg = _append_config()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        if _binary_blob_has_secret(cfg, data):
            raise BlobPrivacyError("binary blob was rejected by the privacy floor")
    else:
        # ASCII encoded as UTF-16 is also valid UTF-8 (a NUL follows or
        # precedes every character), so decode success alone cannot select the
        # text path.  Treat BOMs or a high NUL density as an encoding switch
        # and refuse credential matches rather than preserving them verbatim.
        looks_utf16 = data.startswith((b"\xff\xfe", b"\xfe\xff")) or (
            data and data.count(b"\x00") * 4 >= len(data)
        )
        if looks_utf16 and _binary_blob_has_secret(cfg, data):
            raise BlobPrivacyError("encoded blob was rejected by the privacy floor")
        data = sanitize_content(cfg, text).encode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    root_fd, store_fd, shard_fd = _open_private_blob_directory(digest[:2])
    temp_name = f".{digest}.{os.getpid()}.{threading.get_ident()}.tmp"
    temp_fd = None
    try:
        try:
            _verify_existing_blob(shard_fd, digest)
            return digest
        except FileNotFoundError:
            pass
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        temp_fd = os.open(temp_name, flags, 0o600, dir_fd=shard_fd)
        view = memoryview(data)
        while view:
            written = os.write(temp_fd, view)
            if written <= 0:
                raise OSError("short blob write")
            view = view[written:]
        os.fsync(temp_fd)
        os.close(temp_fd)
        temp_fd = None
        try:
            os.link(
                temp_name,
                digest,
                src_dir_fd=shard_fd,
                dst_dir_fd=shard_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            _verify_existing_blob(shard_fd, digest)
        os.fsync(shard_fd)
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        try:
            os.unlink(temp_name, dir_fd=shard_fd)
        except FileNotFoundError:
            pass
        os.close(shard_fd)
        os.close(store_fd)
        os.close(root_fd)
    return digest


def _cursor_source(source) -> str:
    cfg = _append_config()
    if not isinstance(source, str) or not source or len(source) > 4096:
        raise SchemaError("cursor source is invalid")
    sanitized = sanitize_content(cfg, source, max_len=4096)
    if sanitized != source:
        raise SchemaError("cursor source is rejected by the privacy floor")
    return source


def _sanitize_cursor_value(cfg, value, *, depth=0, budget=None):
    if budget is None:
        budget = [100_000]
    budget[0] -= 1
    if budget[0] < 0 or depth > 12:
        raise SchemaError("cursor state exceeds its structural bound")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not (-(2**63) <= value < 2**63):
            raise SchemaError("cursor state integer is out of range")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise SchemaError("cursor state number is invalid")
        return value
    if isinstance(value, str):
        return sanitize_content(cfg, value, max_len=4096)
    if isinstance(value, list):
        return [
            _sanitize_cursor_value(cfg, item, depth=depth + 1, budget=budget)
            for item in value
        ]
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise SchemaError("cursor state contains a non-string key")
            safe_key = sanitize_content(cfg, key, max_len=256)
            if not safe_key or safe_key in out:
                raise SchemaError("cursor state contains an unsafe key")
            out[safe_key] = _sanitize_cursor_value(
                cfg, item, depth=depth + 1, budget=budget
            )
        return out
    raise SchemaError("cursor state contains an unsupported value")


def get_cursor(conn, source) -> dict:
    source = _cursor_source(source)
    row = conn.execute(
        "SELECT state FROM cursors WHERE source = ?", (source,)
    ).fetchone()
    if row is None:
        return {}
    try:
        state = json.loads(row["state"])
        if not isinstance(state, dict):
            raise ValueError("cursor root is not a mapping")
        sanitized = _sanitize_cursor_value(_append_config(), state)
        if sanitized != state:
            raise ValueError("cursor is not privacy-clean")
        return state
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise SchemaError("stored cursor state is invalid") from exc


def set_cursor(conn, source, state: dict):
    source = _cursor_source(source)
    if not isinstance(state, dict):
        raise SchemaError("cursor state must be a mapping")
    state = _sanitize_cursor_value(_append_config(), state)
    conn.execute(
        "INSERT INTO cursors (source, state) VALUES (?, ?) "
        "ON CONFLICT(source) DO UPDATE SET state = excluded.state",
        (source, json.dumps(state, allow_nan=False, separators=(",", ":"))),
    )
    conn.commit()
