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

# 13. FTS highlight brackets must not break redaction (mcp search leak regression)
append_event(conn, "note", "note", content="gateway key sk-zzzzzzzzzzzzzzzz9876 in use")
out = mcp_search("sk gateway")
assert "zzzzzzzzzzzzzzzz9876" not in out, "highlight brackets split the key past redaction"
assert "[REDACTED:api_key]" in out, out

# 14. missing watch root is not a mass deletion; restores are re-recorded
(watch / "b.md").write_text("gamma heron notes")
scan_fs(conn, cfg)
hidden = watch.rename(watch.with_name(watch.name + "-away"))
r = scan_fs(conn, cfg)
assert r["file_delete"] == 0, "unreachable root recorded as mass deletion"
hidden.rename(watch)
r = scan_fs(conn, cfg)
assert r["file_write"] == 0, "unchanged files re-ingested after root returned"
(watch / "b.md").unlink()
assert scan_fs(conn, cfg)["file_delete"] == 1
(watch / "b.md").write_text("gamma heron notes")
r = scan_fs(conn, cfg)
assert r["file_write"] == 1, "restored file skipped because pre-delete hash matched"

# 15. symlinks are never followed into unwatched territory
outside = Path(tempfile.mkdtemp(prefix="contextd-outside-"))
(outside / "hush.md").write_text("linked ocelot secret")
(watch / "alias.md").symlink_to(outside / "hush.md")
r = scan_fs(conn, cfg)
assert r["file_write"] == 0 and not search(conn, "ocelot"), "symlink followed"

# 16. mcp notes carry provenance; budget refusals are prospective
import json

from contextd.gate import check_budget
from contextd.mcp_server import note as mcp_note

nid = int(mcp_note("model-written test note").rsplit("#", 1)[1])
row = conn.execute("SELECT meta FROM events WHERE id = ?", (nid,)).fetchone()
assert json.loads(row["meta"])["actor"] == "mcp", "mcp note missing provenance"
cfg_low = load_config()
cfg_low["gate"]["daily_token_budget"] = 10
try:
    check_budget(conn, cfg_low, upcoming=10_000)
    raise AssertionError("prospective budget not enforced")
except GateError:
    pass

# 17. URLs are stored stripped: tracking + auth params gone, q/v kept, no fragment
from contextd.ingest import clean_url

assert clean_url("https://x.test/s?q=colab&gs_lcrp=blob&code=sekrit123#access_token=tok") == \
    "https://x.test/s?q=colab"
assert clean_url("https://y.test/watch?v=abc123&si=tracker") == "https://y.test/watch?v=abc123"

# 18. recall pays for each url once, and never twice for repeat visits
for _ in range(3):
    append_event(conn, "chrome", "page_visit", uri="https://news.test/lemur-society",
                 content="Lemur Society Quarterly https://news.test/lemur-society",
                 meta={"visited_unix": 1750000000})
r = assemble(conn, cfg, "lemur society", budget=4000)
assert len(r["items"]) == 1, f"repeat visits not deduped: {r['items']}"
assert r["bundle"].count("https://news.test/lemur-society") == 1, "url paid for twice"

# 19. recall windows filter by occurrence (visit) time, not ingest time
append_event(conn, "chrome", "page_visit", uri="https://a.test/quokka-march",
             content="Quokka March Report https://a.test/quokka-march",
             meta={"visited_unix": 1741000000})   # 2025-03
append_event(conn, "chrome", "page_visit", uri="https://a.test/quokka-june",
             content="Quokka June Festival https://a.test/quokka-june",
             meta={"visited_unix": 1750500000})   # 2025-06
r = assemble(conn, cfg, "quokka", budget=4000, since="2025-06-01", until="2025-07-01")
assert "quokka-june" in r["bundle"] and "quokka-march" not in r["bundle"], r["bundle"]

# 20. an every-term AND miss degrades to any-term OR instead of returning nothing
assert len(search(conn, "xylophone zzznope")) == 1, "OR fallback missing"

# 21. claude code ingestion: mechanical dialogue filter, roles, redaction, watermark
from contextd.ingest import scan_claude

claude_root = Path(tempfile.mkdtemp(prefix="contextd-claude-"))
(claude_root / "-Users-test").mkdir()
sess = claude_root / "-Users-test" / "sess-aaaa-bbbb.jsonl"
lines = [
    {"type": "summary", "summary": "skip me"},
    {"type": "user", "message": {"role": "user", "content": "let's fix the gateway"},
     "uuid": "u1000000", "timestamp": "2026-06-15T12:00:00Z"},
    {"type": "assistant", "message": {"role": "assistant", "content": [
        {"type": "thinking", "thinking": "skip"},
        {"type": "text", "text": "rotating key sk-abcdefghijklmnop9876 now"},
        {"type": "tool_use", "id": "t1", "name": "Task",
         "input": {"prompt": "explore the auth walrus module"}}]},
     "uuid": "a1000000", "timestamp": "2026-06-15T12:01:00Z"},
    {"type": "user", "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t1",
         "content": [{"type": "text", "text": "auth walrus uses bcrypt"}]}]},
     "uuid": "u2000000", "timestamp": "2026-06-15T12:02:00Z"},
    {"type": "user", "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t9", "content": "plain tool noise"}]},
     "uuid": "u3000000"},
    {"type": "assistant", "isSidechain": True, "message": {"role": "assistant",
     "content": [{"type": "text", "text": "sidechain interior monologue"}]},
     "uuid": "s1000000"},
    {"type": "user", "message": {"role": "user",
     "content": "<system-reminder>noise</system-reminder>"}, "uuid": "u4000000"},
]
sess.write_text("\n".join(json.dumps(ln) for ln in lines) + "\n")
cfg["claude"]["projects_dir"] = str(claude_root)
cfg["claude"]["quiet_seconds"] = 0
r = scan_claude(conn, cfg)
assert r["message"] == 4, r  # user, assistant, delegation, subagent
assert r["epoch"] == 0, "backfilled file must not open an epoch"
rows = conn.execute(
    "SELECT content, json_extract(meta,'$.role') AS role FROM events "
    "WHERE source='claude_code' AND kind='message' ORDER BY id").fetchall()
assert [x["role"] for x in rows] == ["user", "assistant", "delegation", "subagent"]
assert "sk-abcdefghijklmnop9876" not in rows[1]["content"], "credential stored raw"
assert "[REDACTED:api_key]" in rows[1]["content"]
assert all("sidechain" not in x["content"] and "noise" not in x["content"] for x in rows)
assert scan_claude(conn, cfg)["message"] == 0, "watermark failed"

# 22. live growth opens an epoch, quiet closes it, replayed fork uuids dedup
with open(sess, "a") as f:
    f.write(json.dumps({"type": "user", "message": {"role": "user",
        "content": "walrus decision: bcrypt stays"}, "uuid": "u5000000",
        "timestamp": "2026-06-15T12:30:00Z"}) + "\n")
    f.write(json.dumps(lines[1]) + "\n")  # a forked session replays an old uuid
r = scan_claude(conn, cfg)
assert r["message"] == 1, f"fork uuid dedup failed: {r}"
r = scan_claude(conn, cfg)  # no growth + quiet_seconds=0 -> epoch closes
assert r["epoch"] == 1, r
epmeta = json.loads(conn.execute(
    "SELECT meta FROM events WHERE kind='epoch'").fetchone()["meta"])
assert epmeta["end_event_id"] > epmeta["start_event_id"]

# 23. reconciler: too-small and self-documented epochs never reach a model
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "hooks"))
import reconcile as rec

pending = rec.unreconciled_epochs(conn)
assert len(pending) == 1
out = rec.reconcile(conn, *pending[0])
assert out["skipped"] == "too_small", out  # one message < MIN_MESSAGES
with open(sess, "a") as f:
    for i in range(6):
        f.write(json.dumps({"type": "user", "message": {"role": "user",
            "content": f"pelican planning point {i}"}, "uuid": f"p{i}000000",
            "timestamp": "2026-06-15T13:00:00Z"}) + "\n")
assert scan_claude(conn, cfg)["message"] == 6
for i in range(3):
    append_event(conn, "note", "note", content=f"live pelican note {i}",
                 meta={"actor": "mcp"})
assert scan_claude(conn, cfg)["epoch"] == 1
out = rec.reconcile(conn, *rec.unreconciled_epochs(conn)[-1])
assert out["skipped"] == "self_documented", out

# 24. client attribution: egress records who drew on the archive, notes get actor
r = assemble(conn, cfg, "zebra service", budget=2000, purpose="attrib", client="openclaw")
egmeta = json.loads(conn.execute(
    "SELECT meta FROM events WHERE id = ?", (r["egress_id"],)).fetchone()["meta"])
assert egmeta["client"] == "openclaw", egmeta
from contextd.ingest import ingest_note as _note
nid = _note(conn, "client-tagged note", actor="openclaw")
assert json.loads(conn.execute("SELECT meta FROM events WHERE id=?", (nid,)).fetchone()["meta"])["actor"] == "openclaw"

# 25. model-written notes are redacted at capture; human CLI notes stay raw,
# but the gate still redacts them at egress
nid = int(mcp_note("rotate gateway key sk-qqqqqqqqqqqqqqqq1234 tomorrow").rsplit("#", 1)[1])
row = conn.execute("SELECT content FROM events WHERE id = ?", (nid,)).fetchone()
assert "sk-qqqqqqqqqqqqqqqq1234" not in row["content"], "model note stored a credential"
assert "[REDACTED:api_key]" in row["content"]
hid = _note(conn, "human kept raw key sk-wwwwwwwwwwwwwwww5678 on purpose")
raw = conn.execute("SELECT content FROM events WHERE id = ?", (hid,)).fetchone()["content"]
assert "sk-wwwwwwwwwwwwwwww5678" in raw, "human deliberate notes should stay raw"
r = assemble(conn, cfg, "human kept purpose", budget=2000)
assert "sk-wwwwwwwwwwwwwwww5678" not in r["bundle"], "egress redaction failed on raw note"

print("ALL SMOKE TESTS PASSED")
