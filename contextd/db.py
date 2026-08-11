"""Event store: one append-only table, FTS index, content-addressed blobs."""

import hashlib
import json
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
  meta TEXT
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
    conn = sqlite3.connect(home() / "contextd.db")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def append_event(conn, source, kind, uri=None, content=None, content_hash=None, meta=None) -> int:
    if content is not None and content_hash is None:
        content_hash = hashlib.sha256(content.encode()).hexdigest()
    cur = conn.execute(
        "INSERT INTO events (ts, source, kind, uri, content, content_hash, meta) VALUES (?,?,?,?,?,?,?)",
        (now_iso(), source, kind, uri, content, content_hash, json.dumps(meta) if meta else None),
    )
    conn.commit()
    return cur.lastrowid


def last_hash(conn, uri):
    row = conn.execute(
        "SELECT content_hash FROM events WHERE uri = ? AND kind != 'file_delete' "
        "ORDER BY id DESC LIMIT 1",
        (uri,),
    ).fetchone()
    return row["content_hash"] if row else None


def store_blob(data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    path = home() / "store" / digest[:2] / digest
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
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
