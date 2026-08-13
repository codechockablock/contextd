"""The candidate scanner's gate discipline, deterministically: the exact
dispatched payload is a receipted redacted egress; failure and timeout are
recorded against that receipt (observable in `ctx audit`); the disclosed
board names dismissed loops so the model is told what not to re-propose."""

import json
from types import SimpleNamespace

import hooks.loop_scan as scanner
from contextd import load_config
from contextd.db import append_event, connect
from contextd.loops import add_candidate, make_scope, transition

REPO = "/synthetic/amberlight"


def _dialogue(conn, n=4):
    for i in range(n):
        append_event(
            conn, "claude_code", "message", uri=f"claude://scan{i}",
            content=("please re-run the drift correction "
                     "sk-abcdefghijklmnop1234" if i == 0
                     else f"work chatter {i}"),
            meta={"role": "user" if i % 2 == 0 else "assistant",
                  "session_id": "scan-test"})


def test_scan_dispatches_only_receipted_redacted_payload(monkeypatch):
    conn = connect()
    _dialogue(conn)
    dead = add_candidate(conn, "learn per-feed cadence",
                         make_scope(REPO))["loop"]
    transition(conn, dead["id"], "dismiss", "operator", reason="noise")
    observed = {}

    def fake_run(*args, **kwargs):
        observed["input"] = kwargs["input"]
        return SimpleNamespace(returncode=0, stdout=json.dumps(
            {"result": "DONE"}), stderr="")

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)
    out = scanner.scan(conn, load_config(), repo=REPO,
                       session_id="scan-test")

    assert out["dispatch_status"] == "succeeded"
    assert "abcdefghijklmnop1234" not in observed["input"]
    assert "[REDACTED:api_key]" in observed["input"]
    assert "dismissed: learn per-feed cadence" in observed["input"]
    receipt = conn.execute(
        "SELECT content, meta FROM events WHERE id = ?",
        (out["egress_id"],)).fetchone()
    assert receipt["content"] == observed["input"]
    meta = json.loads(receipt["meta"])
    assert meta["type"] == "loop_scan" and meta["repo"] == REPO
    assert dead["id"] in meta["items"]
    outcome = conn.execute(
        "SELECT meta FROM events WHERE kind='egress_outcome'").fetchone()
    assert json.loads(outcome["meta"])["status"] == "succeeded"


def test_scan_failure_and_timeout_are_receipted(monkeypatch):
    conn = connect()
    _dialogue(conn)
    monkeypatch.setattr(
        scanner.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=9, stdout="", stderr="x"))
    out = scanner.scan(conn, load_config(), repo=REPO,
                       session_id="scan-test")
    assert out["dispatch_status"] == "failed" and out["exit"] == 9

    def boom(*a, **k):
        raise scanner.subprocess.TimeoutExpired(a[0], 600)
    monkeypatch.setattr(scanner.subprocess, "run", boom)
    out2 = scanner.scan(conn, load_config(), repo=REPO,
                        session_id="scan-test")
    assert out2["dispatch_status"] == "timeout"

    statuses = [json.loads(r["meta"])["status"] for r in conn.execute(
        "SELECT meta FROM events WHERE kind='egress_outcome' ORDER BY id")]
    assert statuses == ["failed", "timeout"]
    assert conn.execute(
        "SELECT COUNT(*) FROM events WHERE kind='loop'").fetchone()[0] == 0


def test_scan_with_no_dialogue_skips_without_disclosure(monkeypatch):
    conn = connect()
    called = {}
    monkeypatch.setattr(scanner.subprocess, "run",
                        lambda *a, **k: called.setdefault("ran", True))
    out = scanner.scan(conn, load_config(), repo=REPO, session_id="empty")
    assert out["dispatch_status"] == "skipped" and "ran" not in called
    assert conn.execute(
        "SELECT COUNT(*) FROM events WHERE kind='egress'").fetchone()[0] == 0
