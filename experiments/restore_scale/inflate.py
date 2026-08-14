"""Deterministic bulk inflator for the restore scale trial.

Deliberately crude: bulk realism is not the point, honest bytes are. Given a
target payload size and a shape, it writes a synthetic contextd archive —
schema, chained events, FTS via the real triggers, content-addressed blobs,
witness — directly with SQLite, seeded, model-free. Chain hashes are computed
with the kernel's own `_chain_hash`, so `ctx verify`, backup, and the drill
treat the result exactly like a real archive. Never pointed at a real one.
"""

import hashlib
import random
import sqlite3
import struct
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from contextd.db import (  # noqa: E402
    SCHEMA, SCHEMA_VERSION, WITNESS_VERSION, _atomic_json, _chain_hash,
)

GIB = 1024 ** 3
BATCH = 20_000
BLOB_BYTES = 64 * 1024 * 1024
EVENT_HEAVY_BLOBS = 4          # a token store/ presence, 4 MiB each
BLOB_HEAVY_EVENTS = 2_000      # a token ledger under the blob pile
START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _pool(rng: random.Random, paragraphs=512, words=180) -> list[str]:
    vocab = [f"term{i:04d}" for i in range(4096)]
    return [" ".join(rng.choice(vocab) for _ in range(words))
            for _ in range(paragraphs)]


def _open_db(home: Path) -> sqlite3.Connection:
    home.mkdir(parents=True, exist_ok=True)
    (home / "store").mkdir(exist_ok=True)
    (home / "config.toml").write_text("[gate]\ndaily_token_budget = 200000\n")
    conn = sqlite3.connect(home / "contextd.db")
    # rollback journal, not WAL, so the db file size is the honest payload
    # size while inflating; the first real connect() flips it to WAL
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA synchronous=OFF")  # synthetic data; speed over crash
    conn.executescript(SCHEMA)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    conn.execute("INSERT OR IGNORE INTO chain_state(singleton, "
                 "witness_initialized) VALUES (1, 1)")
    return conn


class _Chain:
    """Append rows with real chain hashes, in batches."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn, self.prev, self.next_id, self.rows = conn, "", 1, []

    def add(self, source, kind, uri=None, content=None, meta_json=None):
        eid = self.next_id
        ts = (START + timedelta(seconds=eid)).isoformat(timespec="seconds")
        chain = _chain_hash(self.prev, eid, ts, source, kind, uri, content,
                            None, meta_json)
        self.rows.append((eid, ts, source, kind, uri, content, None,
                          meta_json, self.prev, chain))
        self.prev, self.next_id = chain, eid + 1
        if len(self.rows) >= BATCH:
            self.flush()

    def flush(self):
        if self.rows:
            self.conn.executemany(
                "INSERT INTO events (id, ts, source, kind, uri, content, "
                "content_hash, meta, prev_hash, chain_hash) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)", self.rows)
            self.conn.commit()
            self.rows = []


def _write_blob(home: Path, rng: random.Random, index: int, size: int) -> str:
    chunk = rng.randbytes(1024 * 1024)
    digest = hashlib.sha256()
    header = struct.pack(">QQ", index, size)
    digest.update(header)
    body_chunks, remainder = divmod(size - len(header), len(chunk))
    for _ in range(body_chunks):
        digest.update(chunk)
    digest.update(chunk[:remainder])
    name = digest.hexdigest()
    path = home / "store" / name[:2] / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as out:
        out.write(header)
        for _ in range(body_chunks):
            out.write(chunk)
        out.write(chunk[:remainder])
    return name


def tree_bytes(root: Path) -> int:
    return sum(p.stat().st_size for p in root.rglob("*")
               if p.is_file() and not p.is_symlink())


def inflate(home: Path, target_bytes: int, shape: str, seed: str) -> dict:
    """Build a synthetic archive of ~target_bytes total payload."""
    started = time.monotonic()
    rng = random.Random(f"restore-scale:{seed}")
    pool = _pool(rng)
    conn = _open_db(home)
    chain = _Chain(conn)
    db_path = home / "contextd.db"
    blobs = 0

    if shape == "blob_heavy":
        for i in range(BLOB_HEAVY_EVENTS):
            chain.add("note", "note",
                      content=f"synthetic event {i:09d} {pool[i % len(pool)]}")
        while tree_bytes(home) + BLOB_BYTES <= target_bytes:
            digest = _write_blob(home, rng, blobs, BLOB_BYTES)
            chain.add("fs", "file_write", uri=f"/synthetic/blob{blobs:05d}",
                      meta_json='{"blob": "%s"}' % digest)
            blobs += 1
    elif shape == "event_heavy":
        for i in range(EVENT_HEAVY_BLOBS):
            digest = _write_blob(home, rng, i, 4 * 1024 * 1024)
            chain.add("fs", "file_write", uri=f"/synthetic/blob{i:05d}",
                      meta_json='{"blob": "%s"}' % digest)
            blobs += 1
        i = 0
        while True:
            for _ in range(BATCH):
                chain.add("note", "note",
                          content=f"synthetic event {i:09d} "
                                  f"marker{i % 997:03d} {pool[i % len(pool)]}")
                i += 1
            chain.flush()
            if db_path.stat().st_size + tree_bytes(home / "store") \
                    >= target_bytes:
                break
    else:
        raise ValueError(f"unknown shape {shape!r}")

    chain.flush()
    tip_id, tip_hash = chain.next_id - 1, chain.prev
    conn.execute("PRAGMA optimize")
    conn.close()
    _atomic_json(home / "chain-witness.json",
                 {"version": WITNESS_VERSION, "id": tip_id,
                  "chain_hash": tip_hash})
    return {"events": tip_id, "blobs": blobs,
            "archive_bytes": tree_bytes(home),
            "inflate_seconds": round(time.monotonic() - started, 1)}
