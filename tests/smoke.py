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
r_eg = assemble(conn, cfg, "human kept purpose", budget=2000)
assert "sk-wwwwwwwwwwwwwwww5678" not in r_eg["bundle"], "egress redaction failed on raw note"

# 26. every event chains to its predecessor; verify detects rewrites exactly
from contextd.db import verify_chain

r = verify_chain(conn)
assert r["ok"] and r["checked"] > 50, r
orig = conn.execute("SELECT content FROM events WHERE id = 1").fetchone()["content"]
conn.execute("DROP TRIGGER events_no_update")
conn.execute("UPDATE events SET content = 'rewritten history' WHERE id = 1")
conn.commit()
r = verify_chain(conn)
assert not r["ok"] and r["first_bad"] == 1, "rewrite not detected"
conn.execute("UPDATE events SET content = ? WHERE id = 1", (orig,))
conn.executescript("CREATE TRIGGER events_no_update BEFORE UPDATE ON events "
                   "BEGIN SELECT RAISE(ABORT, 'events are append-only'); END")
assert verify_chain(conn)["ok"], "restoring original bytes should restore the chain"

# 27. outcomes: judged recalls land in the append-only tally
import argparse as _ap

from contextd.cli import cmd_backup, cmd_outcome

cmd_outcome(_ap.Namespace(egress_id=r_eg["egress_id"], verdict="hit", note="smoke"))
last = json.loads(conn.execute(
    "SELECT meta FROM events WHERE kind='outcome' ORDER BY id DESC LIMIT 1"
).fetchone()["meta"])
assert last == {"egress_id": r_eg["egress_id"], "verdict": "hit", "note": "smoke"}

# 28. backup is a complete WAL-safe bundle, and retention prunes bundles only
bdir = Path(os.environ["CONTEXTD_HOME"]) / "bk"
cmd_backup(_ap.Namespace(dest=str(bdir), keep=0))
bk = list(bdir.glob("contextd-*.ctxbackup"))
assert len(bk) == 1
bconn = sqlite3.connect(bk[0] / "contextd.db")
n_live = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
assert bconn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == n_live
assert bconn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
bconn.close()
(bdir / "contextd-20200101-000000.db").write_bytes(b"old")
(bdir / "contextd-20200102-000000.db").write_bytes(b"old")
cmd_backup(_ap.Namespace(dest=str(bdir), keep=2))
cmd_backup(_ap.Namespace(dest=str(bdir), keep=2))
left = sorted(p.name for p in bdir.glob("contextd-*.ctxbackup"))
assert len(left) == 2, left
assert (bdir / "contextd-20200101-000000.db").read_bytes() == b"old"
assert (bdir / "contextd-20200102-000000.db").read_bytes() == b"old"

# 29. experiments: freeze is exactly what recall would disclose
from contextd.experiment import (apply_arm, attribute_facts, build_report,
                                 disclose_for_run, freeze, p_floor, perm_test,
                                 provenance_class, register_experiment,
                                 record_run, render_bundle, score_output,
                                 validate_rubric, verdict)

frozen = freeze(conn, cfg, "zebra service", budget=4000)
ref = assemble(conn, cfg, "zebra service", budget=4000, purpose="parity check")
assert [it["id"] for it in frozen["items"]] == ref["items"], "freeze/recall diverged"
assert render_bundle(frozen["items"]) == ref["bundle"], "frozen bytes != recall bytes"
assert "[REDACTED:api_key]" in render_bundle(frozen["items"]), "freeze skipped redaction"

# 30. provenance classes derive from what ingestion already recorded
assert provenance_class("note", "note", {"actor": "human"}) == "human"
assert provenance_class("note", "note", {"actor": "mcp"}) == "model"
assert provenance_class("claude_code", "message", {"role": "user"}) == "human"
assert provenance_class("claude_code", "message", {"role": "assistant"}) == "model"
assert provenance_class("claude_code", "message", {"role": "subagent"}) == "model"
assert provenance_class("chrome", "page_visit", {}) == "activity"
assert provenance_class("fs", "file_write", {}) == "human"

# 31. interventions: drop by id, drop by class, no context, substitute
append_event(conn, "note", "note", content="ferret decision: ship the v2 parser",
             meta={"actor": "human"})
append_event(conn, "note", "note", content="ferret summary: parser rewrite planned",
             meta={"actor": "mcp"})
fz = freeze(conn, cfg, "ferret parser", budget=4000)
assert len(fz["items"]) == 2
provs = {it["id"]: it["provenance"] for it in fz["items"]}
human_id = next(i for i, p in provs.items() if p == "human")
kept = apply_arm(fz["items"], {"name": "d", "drop_ids": [human_id]})
assert [it["provenance"] for it in kept] == ["model"]
kept = apply_arm(fz["items"], {"name": "nh", "drop_classes": ["human"]})
assert all(it["provenance"] != "human" for it in kept)
assert apply_arm(fz["items"], {"name": "none", "no_context": True}) == []
kept = apply_arm(fz["items"], {"name": "sub", "replace": {
    "text": "distilled: ferret parser work", "provenance": "model", "origin": "test"}})
assert len(kept) == 1 and kept[0]["id"] is None and "distilled" in kept[0]["text"]

# 32. disclosure for a run passes the real gate; drift is a refusal
d = disclose_for_run(conn, cfg, 999, {"name": "full"}, 0, fz["items"])
assert d["egress_id"] is not None
egmeta = json.loads(conn.execute("SELECT meta FROM events WHERE id = ?",
                                 (d["egress_id"],)).fetchone()["meta"])
assert egmeta["type"] == "experiment" and egmeta["arm"] == "full"
d = disclose_for_run(conn, cfg, 999, {"name": "none", "no_context": True}, 0, fz["items"])
assert d["egress_id"] is None, "no-context arm must disclose nothing"
tampered = [dict(it) for it in fz["items"]]
tampered[0]["text"] += " drifted"
try:
    disclose_for_run(conn, cfg, 999, {"name": "full"}, 1, tampered)
    raise AssertionError("drifted frozen item not refused")
except ValueError:
    pass

# 33. scorer: deterministic, self-testing; a rubric without fixtures is refused
rubric = {
    "facts": [
        {"id": "decision", "all": [["ship"], ["v2 parser|parser v2"]]},
        {"id": "plan", "all": [["rewrite"]]},
    ],
    "fixtures": [
        {"text": "we will ship the v2 parser after the rewrite",
         "expect": {"decision": True, "plan": True}},
        {"text": "I do not know anything about this project",
         "expect": {"decision": False, "plan": False}},
    ],
}
assert validate_rubric(rubric) == [], validate_rubric(rubric)
s = score_output(rubric, "decision was to ship the V2 parser; rewrite planned")
assert s["score"] == 1.0 and s["hits"]["decision"]
s = score_output(rubric, "the parser exists")
assert s["score"] == 0.0
bad = {"facts": rubric["facts"], "fixtures": [rubric["fixtures"][0]]}
assert any("no positive fact hits" in p for p in validate_rubric(bad)), \
    "missing-miss fixture accepted"

# 34. attribution names which frozen items carry which facts
att = attribute_facts(fz["items"], rubric)
assert att["decision"] == [human_id], att
assert att["plan"] != [], att

# 35. the null is measured: exact permutation p, and the design's floor
assert perm_test([1, 1, 1, 1], [0, 0, 0, 0]) == round(2 / 70, 4)
assert perm_test([0.5, 0.5], [0.5, 0.5]) == 1.0
assert p_floor(4, 4) == round(2 / 70, 4)
assert p_floor(3, 3) == 0.1, "3v3 can never reach p=0.05 and must say so"
assert verdict(0.02) == "distinguishable" and verdict(0.1) == "suggestive"
assert verdict(0.5) == "within noise"

# 36. registration refuses a broken rubric, records a valid one; runs and
# reports are ledger events; a no-effect world yields 'within noise'
spec = {
    "task_id": "smoke-task", "title": "smoke", "prompt_template": "answer: {context}",
    "query": "ferret parser", "budget": 4000, "model": "haiku",
    "model_settings": {"note": "test"}, "n_per_arm": 2,
    "arms": [{"name": "full"}, {"name": "no_context", "no_context": True},
             {"name": "drop_human", "drop_ids": [human_id]}],
    "rubric": rubric, "frozen": fz, "attribution": att,
    "expectation": "smoke only",
}
try:
    register_experiment(conn, {**spec, "rubric": bad})
    raise AssertionError("broken rubric registered")
except ValueError:
    pass
exp_id = register_experiment(conn, spec)
assert not search(conn, "smoke-task"), "experiment record leaked into FTS"
for arm, scores in [("full", [1.0, 1.0]), ("no_context", [0.0, 0.5]),
                    ("drop_human", [1.0, 0.5])]:
    for i, sc in enumerate(scores):
        record_run(conn, exp_id, {
            "arm": arm, "run": i, "egress_id": None, "session_id": f"t-{arm}-{i}",
            "model": "haiku", "duration_ms": 1, "exit": 0, "output": "x",
            "output_sha": "x", "score": sc,
            "hits": {"decision": sc >= 1.0, "plan": sc > 0}})
rep = build_report(conn, exp_id)
assert rep["arms"]["full"]["mean"] == 1.0
none_cmp = next(c for c in rep["comparisons"] if c["arm"] == "no_context")
assert none_cmp["estimated_contribution"] == 0.75
drop_cmp = next(c for c in rep["comparisons"] if c["arm"] == "drop_human")
assert drop_cmp["verdict"] == "within noise", \
    "a 2v2 wiggle must not be reported as a detected effect"
assert rep["not_licensed"], "report missing its scope statement"
from contextd.experiment import format_report, record_report
record_report(conn, exp_id, rep)
assert "within noise" in format_report(rep)
assert verify_chain(conn)["ok"], "experiment events broke the chain"

# 37. penalty facts: negative weights subtract, clamp at zero, and a rubric
# whose penalties are never exercised by a fixture is refused
pen_rubric = {
    "facts": [
        {"id": "good", "all": [["measured null"]], "weight": 1.0},
        {"id": "bullshit", "all": [["guarantees? 100%|fully secure"]], "weight": -0.5},
    ],
    "fixtures": [
        {"text": "thresholds trace to a measured null",
         "expect": {"good": True, "bullshit": False}},
        {"text": "no idea", "expect": {"good": False, "bullshit": False}},
        {"text": "this is fully secure, guaranteed",
         "expect": {"good": False, "bullshit": True}},
    ],
}
assert validate_rubric(pen_rubric) == [], validate_rubric(pen_rubric)
assert score_output(pen_rubric, "the measured null says otherwise")["score"] == 1.0
assert score_output(pen_rubric, "measured null; also fully secure")["score"] == 0.5
assert score_output(pen_rubric, "it is fully secure")["score"] == 0.0, "no clamp"
unexercised = {"facts": pen_rubric["facts"], "fixtures": pen_rubric["fixtures"][:2]}
assert any("never exercised" in p for p in validate_rubric(unexercised)), \
    "unexercised penalty fact accepted"

# 38. two-layer provenance: transport class stays mechanical; assessed origin
# overrides are recorded with their reason and ablatable independently
from contextd.experiment import epistemic_type

fz_ov = freeze(conn, cfg, "ferret parser", budget=4000,
               origin_overrides={human_id: {
                   "origin": "mixed", "reason": "harness prompt quoting model text"}})
ov_item = next(it for it in fz_ov["items"] if it["id"] == human_id)
assert ov_item["provenance"] == "human", "transport class must not change"
assert ov_item["origin"] == "mixed" and ov_item["origin_basis"].startswith("assessed")
plain = next(it for it in fz_ov["items"] if it["id"] != human_id)
assert plain["origin"] == plain["provenance"] and plain["origin_basis"] == "recorded"
kept = apply_arm(fz_ov["items"], {"name": "x", "drop_origins": ["mixed"]})
assert human_id not in [it["id"] for it in kept], "drop_origins missed override"
kept = apply_arm(fz_ov["items"], {"name": "y", "drop_classes": ["human"]})
assert human_id not in [it["id"] for it in kept], "drop_classes broke"
assert epistemic_type("chrome", "page_visit", {}) == "observation"
assert epistemic_type("note", "note", {"actor": "human"}) == "human_assertion"
assert epistemic_type("claude_code", "message", {"role": "assistant"}) == "model_inference"
assert epistemic_type("gate", "egress", {}) == "system"

# 39. v2 specs: named context sets, ladder analysis with marginal-per-1k,
# token efficiency, compression-loss classification, origin caveats in report
fz_irr = freeze(conn, cfg, "lemur society", budget=4000)
lad_rubric = {
    "facts": [
        {"id": "decision", "all": [["ship"], ["v2 parser|parser v2"]],
         "loss_class": "rationale"},
        {"id": "plan", "all": [["rewrite"]], "loss_class": "factual_detail"},
    ],
    "fixtures": rubric["fixtures"],
}
spec2 = {
    "task_id": "smoke-ladder", "title": "ladder", "prompt_template": "t {context}",
    "prompt": "t", "model": "haiku", "model_settings": {}, "n_per_arm": 2,
    "context_sets_spec": {"detail": {"query": "ferret parser", "budget": 4000}},
    "arms": [
        {"name": "no_history", "no_context": True},
        {"name": "distilled", "replace": {
            "text": "summary: a rewrite is planned", "provenance": "model",
            "origin": "test distillation"}},
        {"name": "retrieved", "context_set": "detail"},
        {"name": "irrelevant", "context_set": "irrelevant"},
    ],
    "rubric": lad_rubric,
    "frozen_sets": {"detail": fz_ov, "irrelevant": fz_irr},
    "attribution": {"detail": attribute_facts(fz_ov["items"], lad_rubric),
                    "irrelevant": attribute_facts(fz_irr["items"], lad_rubric)},
    "baseline_arm": "retrieved", "detail_arm": "retrieved",
    "ladder": ["no_history", "distilled", "retrieved"],
    "expectation": "smoke only",
}
exp2 = register_experiment(conn, spec2)
fake = {"no_history": ([0.0, 0.0], 0), "distilled": ([0.5, 0.5], 100),
        "retrieved": ([1.0, 1.0], 400), "irrelevant": ([0.0, 0.0], 400)}
for arm, (scores, tok) in fake.items():
    for i, sc in enumerate(scores):
        record_run(conn, exp2, {
            "arm": arm, "run": i, "egress_id": None, "context_est_tokens": tok,
            "session_id": f"s-{arm}-{i}", "model": "haiku", "duration_ms": 1,
            "exit": 0, "output": "x", "output_sha": "x", "score": sc,
            "hits": {"decision": sc >= 1.0, "plan": sc >= 0.5},
            "citations": {"cited": [human_id], "valid": [human_id]}})
rep2 = build_report(conn, exp2)
steps = {(s["from"], s["to"]): s for s in rep2["ladder"]}
assert steps[("distilled", "retrieved")]["marginal_per_1k"] == round(0.5 / 0.3, 3)
assert rep2["arms"]["retrieved"]["score_per_1k_ctx"] == 2.5
assert rep2["arms"]["no_history"]["score_per_1k_ctx"] is None
cl = rep2["compression_loss"]
assert [e["fact"] for e in cl["kept_in_distillation"]] == ["plan"]
assert [e["fact"] for e in cl["lost_in_distillation"]] == ["decision"]
assert cl["lost_by_class"] == {"rationale": ["decision"]}
assert any("41050" not in c and str(human_id) in c for c in rep2["origin_caveats"]), \
    rep2["origin_caveats"]
irr_cmp = next(c for c in rep2["comparisons"] if c["arm"] == "irrelevant")
assert irr_cmp["estimated_contribution"] == 1.0
assert "smoke-ladder" in format_report(rep2), "task id missing from report"
assert "ctx ~400tok" in format_report(rep2), "efficiency missing from format"
assert verify_chain(conn)["ok"]

# 40. synthesis recall: anchors verified, both disclosures logged, refusal
# on unresolvable anchors — pipeline exercised with a fake distiller binary
from contextd.gate import verify_anchors

a = verify_anchors("claims [12] and [34], again [12]", [12, 34, 56])
assert a == {"ids": [12, 34], "valid": [12, 34], "invalid": []}
a = verify_anchors("claim [12] and bogus [99]", [12])
assert a["invalid"] == [99], a
assert verify_anchors("no anchors here", [1]) == {"ids": [], "valid": [], "invalid": []}

home = Path(os.environ["CONTEXTD_HOME"])
fake_py = home / "fake_distiller.py"
fake_py.write_text(
    "import sys, json, re\n"
    "data = sys.stdin.read()\n"
    "ids = re.findall(r'--- \\[(\\d+)\\]', data)[:2]\n"
    "out = 'Fused claim citing [' + ids[0] + '] and also [' + ids[1] + '].'\n"
    "print(json.dumps({'result': out, 'total_cost_usd': 0.0}))\n")
fake_bin = home / "fake_claude"
fake_bin.write_text(f"#!/bin/sh\nexec {sys.executable} {fake_py}\n")
os.chmod(fake_bin, 0o755)
hook = Path(__file__).resolve().parent.parent / "hooks" / "synthesis_recall.py"
env = os.environ.copy()
env["SYNTH_CLAUDE_BIN"] = str(fake_bin)
r = __import__("subprocess").run(
    [sys.executable, str(hook), "ferret", "parser", "--purpose", "smoke"],
    capture_output=True, text=True, env=env)
assert r.returncode == 0, r.stderr
assert "Fused claim citing [" in r.stdout, r.stdout
assert "anchors" in r.stderr and "both logged" in r.stderr, r.stderr
syn = [json.loads(x["meta"]) for x in conn.execute(
    "SELECT meta FROM events WHERE kind='egress' ORDER BY id").fetchall()
    if json.loads(x["meta"]).get("mode") in ("synthesis", "synthesis_source")]
assert len(syn) == 2, f"expected source+served egress pair, got {len(syn)}"
served = next(m for m in syn if m["mode"] == "synthesis")
source = next(m for m in syn if m["mode"] == "synthesis_source")
assert served["anchors"] and set(served["anchors"]) <= set(served["items"])
assert served["source_egress"] and served["distiller"]
assert source["items"] == served["items"]

bad_py = home / "bad_distiller.py"
bad_py.write_text("import json,sys; sys.stdin.read(); "
                  "print(json.dumps({'result': 'Claim [999999].'}))\n")
bad_bin = home / "bad_claude"
bad_bin.write_text(f"#!/bin/sh\nexec {sys.executable} {bad_py}\n")
os.chmod(bad_bin, 0o755)
env["SYNTH_CLAUDE_BIN"] = str(bad_bin)
n_before = conn.execute("SELECT COUNT(*) FROM events WHERE kind='egress' AND "
                        "json_extract(meta,'$.mode')='synthesis'").fetchone()[0]
r = __import__("subprocess").run(
    [sys.executable, str(hook), "ferret", "parser", "--retries", "0"],
    capture_output=True, text=True, env=env)
assert r.returncode != 0, "unresolvable anchor served"
assert "anchor verification" in r.stderr + r.stdout
n_after = conn.execute("SELECT COUNT(*) FROM events WHERE kind='egress' AND "
                       "json_extract(meta,'$.mode')='synthesis'").fetchone()[0]
assert n_after == n_before, "refused distillate still logged as served"

# dispatch: ctx recall --mode synthesis delegates to the hook
os.environ["SYNTH_CLAUDE_BIN"] = str(fake_bin)
from contextd.cli import cmd_recall
try:
    cmd_recall(_ap.Namespace(query=["ferret", "parser"], budget=6000,
                             purpose="dispatch", since="", until="",
                             mode="synthesis"))
    raise AssertionError("dispatch should sys.exit with hook's code")
except SystemExit as e:
    assert (e.code or 0) == 0, f"dispatch failed: {e.code}"
assert verify_chain(conn)["ok"]

# 41. external ranking hook: reorders the match set, cannot extend it,
# and every gate rule still applies
from contextd.gate import select_items

default_order = [it["id"] for it in select_items(conn, cfg, "ferret parser", 4000)]
assert len(default_order) == 2
flipped = list(reversed(default_order))
got = [it["id"] for it in select_items(conn, cfg, "ferret parser", 4000,
                                       ranked_ids=flipped)]
assert got == flipped, f"ranked_ids not respected: {got}"
got = [it["id"] for it in select_items(conn, cfg, "ferret parser", 4000,
                                       ranked_ids=[flipped[0], 999999])]
assert got == [flipped[0]], "id outside the match set was not ignored"
assert select_items(conn, cfg, "wombat", 4000, ranked_ids=[]) == [], \
    "an empty external ranking must select nothing"
assert "wombat" not in "".join(
    it["text"] for it in select_items(conn, cfg, "wombat", 4000)), \
    "never_leave must hold regardless of ranking"


# 42. the ctx loop CLI layer: parse-level add/list/close/reopen round trip,
# idempotent retry, and nonzero refusals (kernel logic is pytest-covered;
# this exercises the argparse surface a refactor could silently break)
import contextlib
import io
from contextd.cli import cmd_loop


def _loop_cli(**kw):
    defaults = {"repo": None, "global_scope": False, "source_event": [],
                "all": False, "reason": ""}
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cmd_loop(_ap.Namespace(**{**defaults, **kw}))
    return buf.getvalue()


out = _loop_cli(action="add", text=["smoke:", "verify", "the", "loop", "cli"],
                repo="/synthetic/smoke")
assert "opened loop#" in out, out
loop_id = out.split("loop#")[1].split(" ")[0]
assert "already open" in _loop_cli(
    action="add", text=["smoke: verify the loop cli"], repo="/synthetic/smoke")
assert "smoke: verify the loop cli" in _loop_cli(
    action="list", repo="/synthetic/smoke")
assert "-> closed" in _loop_cli(action="close", loop_id=loop_id)
assert "already closed" in _loop_cli(action="close", loop_id=loop_id)
assert "-> open" in _loop_cli(action="reopen", loop_id=loop_id,
                              reason="smoke reopen")
assert "reopened" in _loop_cli(action="show", loop_id=f"loop#{loop_id}")
try:
    _loop_cli(action="dismiss", loop_id=loop_id)
    raise AssertionError("dismissing an open loop must refuse nonzero")
except SystemExit as e:
    assert e.code not in (0, None)
try:
    _loop_cli(action="confirm", loop_id="424242")
    raise AssertionError("confirming a missing loop must refuse nonzero")
except SystemExit as e:
    assert e.code not in (0, None)
assert "no candidates" in _loop_cli(action="candidates",
                                    repo="/synthetic/smoke")
assert verify_chain(conn)["ok"]

# 43. capture liveness: status always shows per-source ages; a thresholded
# source past its threshold warns and stamps the compiled checkpoint package
# AND its egress meta; fresh or unthresholded stamps nothing
from datetime import datetime, timedelta

import contextd.liveness as liveness
from contextd.cli import cmd_status
from contextd.handoff import compile_checkpoint

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cmd_status(_ap.Namespace())
status_out = buf.getvalue()
print("\n".join(ln for ln in status_out.splitlines()
                if "last event" in ln or "events ever" in ln
                or ln == "capture liveness:"))
assert "capture liveness:" in status_out
assert "chrome: last event" in status_out and "note: last event" in status_out
# smoke never ingests safari, so the only warning is the never-events one
warns = [ln for ln in status_out.splitlines() if ln.startswith("WARNING")]
assert warns == ["WARNING: safari no events ever (threshold 48h) "
                 "— capture may be stalled"], warns

_real_now = liveness.now_iso
last_chrome = conn.execute(
    "SELECT MAX(ts) AS t FROM events WHERE source='chrome'").fetchone()["t"]
fake_now = (datetime.fromisoformat(last_chrome)
            + timedelta(hours=96)).isoformat(timespec="seconds")
liveness.now_iso = lambda: fake_now  # injected clock: no wall-clock dependence
cfg_live = load_config()
cfg_live["liveness"]["stale_after_hours"] = {"chrome": 48}
stale = [r for r in liveness.capture_liveness(conn, cfg_live) if r["stale"]]
assert [r["source"] for r in stale] == ["chrome"], stale
ck = compile_checkpoint(conn, cfg_live, budget=2000)
assert ck["package"].startswith(
    "CAPTURE STALENESS: chrome last event 4.0d ago (threshold 48h)"), \
    ck["package"][:120]
ckmeta = json.loads(conn.execute(
    "SELECT meta FROM events WHERE id = ?",
    (ck["egress_id"],)).fetchone()["meta"])
assert ckmeta["staleness"] == [{"source": "chrome", "age_hours": 96.0}], ckmeta
liveness.now_iso = _real_now
ck2 = compile_checkpoint(conn, cfg_live, budget=2000)
assert "CAPTURE STALENESS" not in ck2["package"], "fresh source stamped stale"
assert "staleness" not in json.loads(conn.execute(
    "SELECT meta FROM events WHERE id = ?",
    (ck2["egress_id"],)).fetchone()["meta"])

# 44. resumption tally: a checkpoint egress judged with a failure class lands
# in the stratified scoreboard; hit + class refuses nonzero and appends nothing
cmd_outcome(_ap.Namespace(egress_id=ck["egress_id"], verdict="miss",
                          failure_class="not-selected", note="smoke"))
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cmd_outcome(_ap.Namespace(egress_id=None, verdict=None, note="",
                              failure_class=None))
board = buf.getvalue()
print(board.rstrip())
assert "recalls:" in board and "(v0.1 bar: 30%)" in board
assert "checkpoints: 2  judged: 1  unjudged: 1" in board, board
assert "failure classes: not-selected 1" in board, board
n_outcomes = conn.execute(
    "SELECT COUNT(*) FROM events WHERE kind='outcome'").fetchone()[0]
try:
    cmd_outcome(_ap.Namespace(egress_id=ck2["egress_id"], verdict="hit",
                              failure_class="drowned", note=""))
    raise AssertionError("hit + --failure-class must refuse nonzero")
except SystemExit as e:
    assert e.code not in (0, None)
assert conn.execute("SELECT COUNT(*) FROM events WHERE kind='outcome'"
                    ).fetchone()[0] == n_outcomes, "refusal appended an event"
assert verify_chain(conn)["ok"]

# 45. lineage gauge: depth-1 archive is quiet; a note citing a note trips
# the DEPTH ALERT, exits nonzero, and warns in ctx status
from contextd.cli import cmd_lineage
from contextd.gate import disclose as _disclose
from contextd.lineage import lineage_stats

lin_ids = [append_event(conn, "claude_code", "message",
                        content=f"lineage smoke dialogue {i}",
                        meta={"role": "user", "session_id": "lin"})
           for i in range(2)]
lin_eg = _disclose(conn, cfg, "\n".join(f"[{i}] line" for i in lin_ids),
                   {"type": "reconcile_dialogue", "items": lin_ids})["egress_id"]
lin_note = append_event(conn, "note", "note",
                        content=f"lineage smoke note [{lin_ids[0]}][{lin_ids[1]}]",
                        meta={"actor": "mcp", "derivation": {
                            "source_egress": lin_eg, "anchors": lin_ids}})
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cmd_lineage(_ap.Namespace(action=None, full=False))
assert "DEPTH ALERT" not in buf.getvalue(), buf.getvalue()
assert "depth 1" in buf.getvalue()

lin_eg2 = _disclose(conn, cfg, f"[{lin_note}] the note",
                    {"type": "reconcile_dialogue",
                     "items": [lin_note]})["egress_id"]
lin_note2 = append_event(conn, "note", "note",
                         content=f"summary of a summary [{lin_note}]",
                         meta={"actor": "mcp", "derivation": {
                             "source_egress": lin_eg2, "anchors": [lin_note]}})
buf = io.StringIO()
try:
    with contextlib.redirect_stdout(buf):
        cmd_lineage(_ap.Namespace(action=None, full=True))
    raise AssertionError("depth-2 archive must exit nonzero")
except SystemExit as e:
    assert e.code == 2, e.code
assert "DEPTH ALERT" in buf.getvalue(), buf.getvalue()
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cmd_status(_ap.Namespace())
assert "lineage: max note depth 2 (limit 1)" in buf.getvalue()
assert any(ln.startswith("WARNING") and "a note is citing notes" in ln
           for ln in buf.getvalue().splitlines()), buf.getvalue()
assert lineage_stats(conn, cfg)["max_note_depth_observed"] == 2

# 46. lineage audit hook (stubbed dispatcher) + ctx lineage report:
# verdicts land content-NULL, invisible to search/recall, and the report
# shows them next to the judge's calibration matrix
import lineage_audit as laud

lin_cal = {
    "verdict": "AUDIT EARNED",
    "judge_sha": laud.judge_sha(laud.PROMPT_VERSION),
    "judge_model": "haiku", "corpus_digest": "d" * 64, "prereg_id": 0,
    "n_heldout": 150,
    "per_class": {"faithful": {"n": 30, "detected": 1, "rate": 0.033,
                               "ci": [0.001, 0.17], "bar": 0.1,
                               "metric": "false_alarm"}},
}


def _stub_judge(payload):
    return {"status": "succeeded", "exit": 0, "duration_ms": 1,
            "text": json.dumps({"verdict": "dropped-caveat",
                                "spans": ["lineage smoke dialogue 0"]})}


lin_results = laud.run_audit(conn, cfg, lin_cal, dispatcher=_stub_judge, n=2)
assert all("audit_event" in r for r in lin_results), lin_results
for r in lin_results:
    row = conn.execute("SELECT content FROM events WHERE id = ?",
                       (r["audit_event"],)).fetchone()
    assert row["content"] is None, "audit verdict stored content, not NULL"
assert all(h["kind"] != "lineage_audit"
           for h in search(conn, "dropped caveat", limit=50))
r_aud = assemble(conn, cfg, "lineage smoke note", budget=4000)
assert "dropped-caveat" not in r_aud["bundle"], "verdict leaked into recall"
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cmd_lineage(_ap.Namespace(action="report", full=False))
rep_out = buf.getvalue()
print(rep_out.splitlines()[0])
assert "dropped-caveat: 2" in rep_out, rep_out
assert "calibration (AUDIT EARNED" in rep_out, rep_out
assert "advisory" in rep_out
assert verify_chain(conn)["ok"]

print("ALL SMOKE TESTS PASSED")
