"""Write chain-consistent rows that today's closed schema would refuse.

Two different defences exist against malformed metadata, and each needs its
own fixtures:

1. **The closed schema** (contextd/schemas.py) refuses malformed metadata at
   the front door, so it never enters a hardened archive.
2. **The verifier** (contextd/provenance.py) catches malformed records that
   are *already inside* — written before this hardening existed, or inserted
   by a process with direct SQLite access.

Tests for layer 2 cannot construct their fixtures through ``append_event``,
because layer 1 correctly stops them. This helper writes the row the way a
legacy archive or a tampering process leaves one: straight into SQLite, with
the hash chain and witness kept consistent so nothing *else* looks tampered.

Test-only. It is deliberately not importable from the ``contextd`` package —
a production escape hatch around the schema is exactly what this work removes.
"""

import hashlib
import json
import os
from pathlib import Path

from contextd import home
from contextd.db import (
    _atomic_json,
    _chain_hash,
    _chain_lock,
    _db_tip,
    _witness_value,
    now_iso,
)


def insert_legacy_event(
    conn,
    source: str,
    kind: str,
    uri: str | None = None,
    content: str | None = None,
    meta: dict | None = None,
    ts: str | None = None,
) -> int:
    """Append one event bypassing the closed schema and the redaction floor.

    The chain hash and the external witness are still extended correctly, so
    ``verify_chain`` stays green: the row is *unvalidated*, not *tampered*.
    """
    meta_json = json.dumps(meta) if meta else None
    content_hash = (
        hashlib.sha256(content.encode()).hexdigest() if content is not None else None
    )
    with _chain_lock(home()) as paths:
        previous = _db_tip(conn)
        eid = previous["id"] + 1
        stamp = ts or now_iso()
        chain = _chain_hash(
            previous["chain_hash"], eid, stamp, source, kind, uri, content,
            content_hash, meta_json,
        )
        if conn.in_transaction:
            conn.commit()
        conn.execute(
            "INSERT INTO events (id, ts, source, kind, uri, content, "
            "content_hash, meta, prev_hash, chain_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (eid, stamp, source, kind, uri, content, content_hash, meta_json,
             previous["chain_hash"], chain),
        )
        conn.commit()
        _atomic_json(paths["witness"], _witness_value({"id": eid, "chain_hash": chain}))
    return eid


def legacy_note(conn, text: str, derivation=None, actor: str = "mcp") -> int:
    """A note carrying a derivation record the schema would refuse."""
    meta = {"actor": actor}
    if derivation is not None:
        meta["derivation"] = derivation
    return insert_legacy_event(conn, "note", "note", content=text, meta=meta)


# --- the frozen legacy archive fixture --------------------------------------

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "legacy_archive.json"

#: The pre-hardening schema, reproduced verbatim. Deliberately written out
#: rather than imported from contextd.db: the point of a frozen fixture is that
#: it stays what it was even when the current schema moves on.
LEGACY_SCHEMA = """
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
CREATE TABLE IF NOT EXISTS chain_state (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  witness_initialized INTEGER NOT NULL CHECK (witness_initialized = 1)
);
"""


def build_legacy_archive(root):
    """Materialize the frozen fixture into a legacy archive at ``root``.

    Writes the database, the chain witness, and the `chain_state` marker the
    way the pre-hardening code did, so `connect()` opens it as a real legacy
    archive rather than as a fresh one.
    """
    import sqlite3

    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    spec = json.loads(FIXTURE.read_text())

    database = root / "contextd.db"
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(LEGACY_SCHEMA)

    prev = ""
    for event in spec["events"]:
        content = event["content"]
        content_hash = (hashlib.sha256(content.encode()).hexdigest()
                        if content is not None else None)
        meta_json = json.dumps(event["meta"]) if event.get("meta") else None
        chain = _chain_hash(prev, event["id"], event["ts"], event["source"],
                            event["kind"], event["uri"], content,
                            content_hash, meta_json)
        conn.execute(
            "INSERT INTO events (id, ts, source, kind, uri, content, "
            "content_hash, meta, prev_hash, chain_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (event["id"], event["ts"], event["source"], event["kind"],
             event["uri"], content, content_hash, meta_json, prev, chain))
        prev = chain
    conn.execute("INSERT OR IGNORE INTO chain_state(singleton, "
                 "witness_initialized) VALUES (1, 1)")
    conn.execute(f"PRAGMA user_version = {spec['schema_version']}")
    conn.commit()
    tip = conn.execute(
        "SELECT id, chain_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()

    (root / "chain-witness.json").write_text(
        json.dumps({"version": 1, "id": int(tip["id"]),
                    "chain_hash": tip["chain_hash"]},
                   sort_keys=True, separators=(",", ":")) + "\n")
    return {"root": root, "database": database,
            "events": len(spec["events"]),
            "tip": {"id": int(tip["id"]), "chain_hash": tip["chain_hash"]}}
