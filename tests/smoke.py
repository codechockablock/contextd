"""Smoke test: run with  .venv/bin/python tests/smoke.py
Uses a throwaway CONTEXTD_HOME so it never touches the real archive."""

import os
import sqlite3
import sys
import tempfile
from pathlib import Path

os.environ["CONTEXTD_HOME"] = tempfile.mkdtemp(prefix="contextd-test-")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contextd import load_config
from contextd.db import append_event, connect
from contextd.gate import GateError, assemble, spent_today
from contextd.ingest import scan_fs
from contextd.search import search

conn = connect()
cfg = load_config()

# 1. append + FTS round trip
append_event(conn, "note", "note", content="the quarterly xylophone report is ready")
hits = search(conn, "xylophone report")
assert len(hits) == 1, f"expected 1 hit, got {len(hits)}"

# 2. append-only enforcement
for stmt in ("UPDATE events SET content='rewritten' WHERE id=1",
             "DELETE FROM events WHERE id=1"):
    try:
        conn.execute(stmt)
        raise AssertionError(f"append-only trigger failed to block: {stmt}")
    except sqlite3.DatabaseError as e:
        assert "append-only" in str(e), e

# 3. fs scan: ingest, dedup, modify, delete
watch = Path(tempfile.mkdtemp(prefix="contextd-watch-"))
(watch / "a.md").write_text("alpha beaver notes")
cfg["ingest"]["watch_dirs"] = [str(watch)]
r = scan_fs(conn, cfg)
assert r["file_write"] == 1, r
r = scan_fs(conn, cfg)
assert r["file_write"] == 0, f"dedup failed: {r}"
(watch / "a.md").write_text("alpha beaver notes, revised")
r = scan_fs(conn, cfg)
assert r["file_write"] == 1, f"modify not seen: {r}"
(watch / "a.md").unlink()
r = scan_fs(conn, cfg)
assert r["file_delete"] == 1, f"deletion not recorded: {r}"

# 4. gate: redaction + egress logging
append_event(conn, "note", "note",
             content="deploy uses key sk-abcdefghijklmnop1234 for the zebra service")
result = assemble(conn, cfg, "zebra service", budget=4000, purpose="smoke test")
assert "[REDACTED:api_key]" in result["bundle"], result["bundle"]
assert "sk-abcdefghijklmnop" not in result["bundle"]
egress = conn.execute("SELECT * FROM events WHERE kind='egress'").fetchall()
assert len(egress) == 1
assert spent_today(conn) > 0

# 5. budget enforcement
cfg["gate"]["daily_token_budget"] = 1
try:
    assemble(conn, cfg, "zebra", budget=100)
    raise AssertionError("budget not enforced")
except GateError:
    pass
cfg["gate"]["daily_token_budget"] = 200_000

# 6. never_leave: findable locally, never bundled
append_event(conn, "fs", "file_write", uri="~/.ssh/id_rsa",
             content="private wombat credential material")
assert len(search(conn, "wombat")) == 1, "should be searchable locally"
result = assemble(conn, cfg, "wombat", budget=4000)
assert "wombat" not in result["bundle"], "never_leave path escaped the gate"

# 7. egress events are not searchable (no recursive recall)
assert all(h["kind"] != "egress" for h in search(conn, "zebra", limit=50))

print("ALL SMOKE TESTS PASSED")
