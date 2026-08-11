"""Smoke test: run with  .venv/bin/python tests/smoke.py
Uses a throwaway CONTEXTD_HOME so it never touches the real archive."""

import os
import sqlite3
import sys
import tempfile
from pathlib import Path

os.environ["CONTEXTD_HOME"] = tempfile.mkdtemp(prefix="contextd-test-")
Path(os.environ["CONTEXTD_HOME"], "config.toml").write_text(
    '[browser]\nskip_domains = ["blocked.test"]\n'
    '[gate]\nnever_leave = ["*/.ssh/*", "*/.aws/*", "*.pem", "*/.env*", "*blocked.test*"]\n'
)

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

# 8. gate: auth-shaped URL params are redacted, in content and in the uri field
leaky = ("https://example.com/login/steam-auth?code=ea65e288710f322a&state=04ffd06c"
         "&redir=https%3A%2F%2Fx.test%2Flogin%3Fclient_id%3D638D%26state%3Ddeadbeef1234")
append_event(conn, "chrome", "page_visit", uri=leaky,
             content=f"PoE2 Trade - Path of Exile {leaky}")
result = assemble(conn, cfg, "steam-auth login", budget=4000, purpose="smoke")
assert "ea65e288710f322a" not in result["bundle"], "oauth code leaked via content"
assert "04ffd06c" not in result["bundle"], "state param leaked via uri header"
assert "deadbeef1234" not in result["bundle"], "encoded state leaked via redirect"
assert "[REDACTED:url_param]" in result["bundle"], result["bundle"]

# 9. the egress record itself holds only the redacted bundle (choke point)
row = conn.execute("SELECT content FROM events WHERE id = ?",
                   (result["egress_id"],)).fetchone()
assert "ea65e288710f322a" not in row["content"], "unredacted secret in egress log"

# 10. MCP surface: uri redacted in search/timeline; egress hidden unless asked
from contextd.mcp_server import search as mcp_search
from contextd.mcp_server import timeline as mcp_timeline

out = mcp_search("steam-auth login")
assert "ea65e288710f322a" not in out, "oauth code leaked via mcp search uri"
out = mcp_timeline(limit=50)
assert "ea65e288710f322a" not in out, "oauth code leaked via mcp timeline"
assert "gate/egress" not in out, "egress events echoed into timeline"
out = mcp_timeline(source="gate", limit=10)
assert "gate/egress" in out, "source='gate' should still audit disclosures"

# 11. never_leave URL globs hold across every disclosure path
append_event(conn, "chrome", "page_visit", uri="https://www.blocked.test/watch?v=1",
             content="private kumquat viewing https://www.blocked.test/watch?v=1")
assert len(search(conn, "kumquat")) == 1, "local search should still see it"
r = assemble(conn, cfg, "kumquat viewing", budget=4000)
assert "kumquat" not in r["bundle"], "never_leave domain escaped recall"
out = mcp_search("kumquat viewing")
assert "kumquat" not in out and "blocked.test" not in out, "escaped mcp search"
out = mcp_timeline(limit=100)
assert "blocked.test" not in out, "never_leave domain escaped mcp timeline"

# 12. domain policy: suffix match, globs, blocklist files, gate enforcement
from contextd.domains import blocked, load_skip_domains
from contextd.gate import never_leave

sd = load_skip_domains(cfg)
assert blocked(sd, "https://sub.blocked.test/x")
assert blocked(sd, "http://blocked.test:8080/y")
assert not blocked(sd, "https://notblocked.test/z")

blfile = Path(os.environ["CONTEXTD_HOME"]) / "extra-blocked.txt"
blfile.write_text("# comment\n0.0.0.0 fromfile.test\nlocalhost\n")
cfg2 = load_config()
cfg2["browser"]["skip_domains"].append("mirror*.test")
cfg2["browser"]["skip_domain_files"] = [str(blfile)]
sd2 = load_skip_domains(cfg2)
assert blocked(sd2, "https://mirror7.test/a"), "glob entry should match mirrors"
assert blocked(sd2, "https://www.mirror7.test/a"), "glob should match via suffix walk"
assert blocked(sd2, "https://x.fromfile.test/b"), "file entry should match"
assert not blocked(sd2, "http://localhost:3000/dev"), "hosts-file noise must not block"

cfg3 = load_config()
cfg3["gate"]["never_leave"] = []
assert never_leave(cfg3, "https://sub.blocked.test/x"), \
    "gate must enforce domain policy even with no globs"

print("ALL SMOKE TESTS PASSED")
