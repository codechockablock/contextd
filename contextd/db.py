"""Event store: one append-only table, FTS index, content-addressed blobs."""

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone

from . import home

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
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect() -> sqlite3.Connection:
    home().mkdir(parents=True, exist_ok=True)
    os.chmod(home(), 0o700)
    conn = sqlite3.connect(home() / "contextd.db")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    _migrate_chain(conn)
    for f in home().glob("contextd.db*"):
        try:
            os.chmod(f, 0o600)
        except OSError:
            pass
    return conn


def _chain_hash(prev, eid, ts, source, kind, uri, content, content_hash, meta_json) -> str:
    h = hashlib.sha256()
    for part in (prev, str(eid), ts, source, kind, uri or "", content or "",
                 content_hash or "", meta_json or ""):
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
            "SELECT 1 FROM events WHERE chain_hash IS NULL LIMIT 1").fetchone():
        return
    nulls = conn.execute(
        "SELECT COUNT(*) FROM events WHERE chain_hash IS NULL").fetchone()[0]
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    if nulls != total:
        return  # partial gaps are evidence of tampering, not a migration
    conn.execute("BEGIN IMMEDIATE")
    try:
        if conn.execute("SELECT 1 FROM events WHERE chain_hash IS NULL LIMIT 1").fetchone():
            conn.execute("DROP TRIGGER IF EXISTS events_no_update")
            prev = ""
            for r in conn.execute(
                    "SELECT id, ts, source, kind, uri, content, content_hash, meta "
                    "FROM events ORDER BY id").fetchall():
                ch = _chain_hash(prev, r["id"], r["ts"], r["source"], r["kind"],
                                 r["uri"], r["content"], r["content_hash"], r["meta"])
                conn.execute("UPDATE events SET prev_hash = ?, chain_hash = ? WHERE id = ?",
                             (prev, ch, r["id"]))
                prev = ch
            conn.execute("CREATE TRIGGER IF NOT EXISTS events_no_update "
                         "BEFORE UPDATE ON events "
                         "BEGIN SELECT RAISE(ABORT, 'events are append-only'); END")
        conn.commit()
    except BaseException:
        conn.rollback()
        raise


def verify_chain(conn) -> dict:
    """Recompute the whole chain. Detects rewrites, deletions, insertions, and
    unchained rows. Tamper-evident, not tamper-proof: an owner-level process
    that recomputes every hash defeats it (see the trust model)."""
    prev, last_ts = "", ""
    checked = ts_warnings = 0
    for r in conn.execute(
            "SELECT id, ts, source, kind, uri, content, content_hash, meta, "
            "prev_hash, chain_hash FROM events ORDER BY id"):
        expect = _chain_hash(prev, r["id"], r["ts"], r["source"], r["kind"],
                             r["uri"], r["content"], r["content_hash"], r["meta"])
        if r["chain_hash"] is None or (r["prev_hash"] or "") != prev \
                or r["chain_hash"] != expect:
            return {"ok": False, "checked": checked, "first_bad": r["id"],
                    "ts_warnings": ts_warnings}
        if r["ts"] < last_ts:
            ts_warnings += 1
        last_ts, prev = r["ts"], r["chain_hash"]
        checked += 1
    return {"ok": True, "checked": checked, "first_bad": None,
            "ts_warnings": ts_warnings}


def append_event(conn, source, kind, uri=None, content=None, content_hash=None, meta=None) -> int:
    if content is not None and content_hash is None:
        content_hash = hashlib.sha256(content.encode()).hexdigest()
    meta_json = json.dumps(meta) if meta else None
    ts = now_iso()
    # read-prev + insert under a write lock so concurrent appenders chain cleanly
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT id, chain_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
        prev = (row["chain_hash"] or "") if row else ""
        eid = (row["id"] + 1) if row else 1
        chain = _chain_hash(prev, eid, ts, source, kind, uri, content, content_hash, meta_json)
        conn.execute(
            "INSERT INTO events (id, ts, source, kind, uri, content, content_hash, meta, "
            "prev_hash, chain_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (eid, ts, source, kind, uri, content, content_hash, meta_json, prev, chain))
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return eid


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
    digest = hashlib.sha256(data).hexdigest()
    path = home() / "store" / digest[:2] / digest
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        os.chmod(path, 0o600)
    return digest


def get_cursor(conn, source) -> dict:
    row = conn.execute("SELECT state FROM cursors WHERE source = ?", (source,)).fetchone()
    return json.loads(row["state"]) if row else {}


def set_cursor(conn, source, state: dict):
    conn.execute(
        "INSERT INTO cursors (source, state) VALUES (?, ?) "
        "ON CONFLICT(source) DO UPDATE SET state = excluded.state",
        (source, json.dumps(state)),
    )
    conn.commit()
