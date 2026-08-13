"""The standing audit hook against a stubbed dispatcher: calibration gate,
verdict-event shape, content-NULL enforcement (audit events must never feed
search or recall), idempotent sampling, and retryable failures. No model is
ever dispatched in this suite."""

import json

import pytest

import hooks.lineage_audit as hook
from contextd import load_config
from contextd.cli import cmd_lineage
from contextd.db import append_event, connect
from contextd.gate import assemble, disclose
from contextd.lineage import audit_report
from contextd.search import search

CAL = {
    "verdict": "AUDIT EARNED",
    "judge_sha": None,  # filled per-test with the live sha
    "judge_model": "haiku",
    "corpus_digest": "d" * 64,
    "prereg_id": 76,
    "n_heldout": 150,
    "per_class": {
        "faithful": {"n": 30, "detected": 1, "rate": 0.033,
                     "ci": [0.001, 0.17], "bar": 0.1, "metric": "false_alarm"},
        "dropped-caveat": {"n": 30, "detected": 27, "rate": 0.9,
                           "ci": [0.73, 0.98], "bar": 0.8, "metric": "recall"},
    },
}


def _calibration():
    return {**CAL, "judge_sha": hook.judge_sha(hook.PROMPT_VERSION)}


def _stub(verdict="faithful", spans=("quoted evidence",)):
    def dispatcher(payload):
        reply = json.dumps({"verdict": verdict, "spans": list(spans)})
        return {"status": "succeeded", "exit": 0, "text": reply,
                "duration_ms": 1}
    return dispatcher


def _archive_with_notes(conn, n_notes=3, distinct_word="capybara"):
    cfg = load_config()
    ids = [append_event(conn, "claude_code", "message",
                        content=f"dialogue about the {distinct_word} "
                                f"pipeline, line {i}",
                        meta={"role": "user" if i % 2 == 0 else "assistant",
                              "session_id": "s"})
           for i in range(2 * n_notes)]
    egress = disclose(conn, cfg, "\n".join(f"[{i}] line" for i in ids),
                      {"type": "reconcile_dialogue", "items": ids})["egress_id"]
    notes = []
    for k in range(n_notes):
        a, b = ids[2 * k], ids[2 * k + 1]
        notes.append(append_event(
            conn, "note", "note",
            content=f"decision {k} on the {distinct_word} pipeline [{a}][{b}]",
            meta={"actor": "mcp",
                  "derivation": {"source_egress": egress, "anchors": [a, b]}}))
    return notes


def test_refuses_without_earned_calibration(tmp_path):
    missing = tmp_path / "nope.json"
    with pytest.raises(hook.AuditRefused, match="no calibration result"):
        hook.load_calibration(str(missing))
    not_earned = tmp_path / "not-earned.json"
    not_earned.write_text(json.dumps({**_calibration(),
                                      "verdict": "AUDIT NOT EARNED"}))
    with pytest.raises(hook.AuditRefused, match="not earned"):
        hook.load_calibration(str(not_earned))
    drifted = tmp_path / "drifted.json"
    drifted.write_text(json.dumps({**_calibration(), "judge_sha": "a" * 64}))
    with pytest.raises(hook.AuditRefused, match="drifted"):
        hook.load_calibration(str(drifted))
    good = tmp_path / "good.json"
    good.write_text(json.dumps(_calibration()))
    assert hook.load_calibration(str(good))["verdict"] == "AUDIT EARNED"


def test_audit_event_shape_and_receipted_egress():
    conn = connect()
    notes = _archive_with_notes(conn, 2)
    results = hook.run_audit(conn, load_config(), _calibration(),
                             dispatcher=_stub("dropped-caveat"), n=2)
    assert {r["note_id"] for r in results} == set(notes)
    for r in results:
        meta = json.loads(conn.execute(
            "SELECT meta FROM events WHERE id = ?",
            (r["audit_event"],)).fetchone()["meta"])
        assert meta["verdict"] == "dropped-caveat"
        assert meta["note_id"] == r["note_id"]
        assert meta["judge_sha"] == _calibration()["judge_sha"]
        assert meta["spans"] == ["quoted evidence"]
        assert meta["note_age_days"] >= 0
        # the judged bundle exists as a receipted, succeeded egress
        eg = conn.execute("SELECT content, meta FROM events WHERE id = ?",
                          (meta["egress_id"],)).fetchone()
        egmeta = json.loads(eg["meta"])
        assert egmeta["type"] == "lineage_audit"
        assert r["note_id"] in egmeta["items"]
        assert "EVIDENCE" in eg["content"] and "NOTE" in eg["content"]
        outcome = conn.execute(
            "SELECT meta FROM events WHERE kind='egress_outcome' AND "
            "json_extract(meta,'$.egress_id') = ?",
            (meta["egress_id"],)).fetchone()
        assert json.loads(outcome["meta"])["status"] == "succeeded"


def test_audit_events_are_content_null_and_absent_from_search_and_recall():
    conn = connect()
    cfg = load_config()
    _archive_with_notes(conn, 2, distinct_word="axolotl")
    hook.run_audit(conn, cfg, _calibration(),
                   dispatcher=_stub("unsupported-claim",
                                    spans=("axolotl pipeline",)), n=2)
    rows = conn.execute("SELECT id, content FROM events "
                        "WHERE kind IN ('lineage_audit', 'lineage_judge')"
                        ).fetchall()
    assert rows, "no audit events written"
    for r in rows:
        # content-NULL is the enforcement: the FTS insert trigger fires only
        # WHEN new.content IS NOT NULL, so a NULL-content event cannot enter
        # the index at all (external-content FTS has no row of its own)
        assert r["content"] is None, "audit events must be content-NULL"
    # verdict vocabulary never surfaces through search or a gated recall
    assert all(h["kind"] not in ("lineage_audit", "lineage_judge")
               for h in search(conn, "unsupported claim verdict", limit=50))
    bundle = assemble(conn, cfg, "axolotl pipeline", budget=4000)["bundle"]
    assert "unsupported-claim" not in bundle
    assert "verdict" not in bundle


def test_verdicts_never_mutate_or_hide_the_audited_note():
    conn = connect()
    cfg = load_config()
    notes = _archive_with_notes(conn, 1, distinct_word="quoll")
    before = conn.execute("SELECT content, meta FROM events WHERE id = ?",
                          (notes[0],)).fetchone()
    hook.run_audit(conn, cfg, _calibration(),
                   dispatcher=_stub("quantitative-shift"), n=1)
    after = conn.execute("SELECT content, meta FROM events WHERE id = ?",
                         (notes[0],)).fetchone()
    assert (before["content"], before["meta"]) == \
        (after["content"], after["meta"]), "audit mutated the note"
    # a flagged note is still selected by recall exactly as before
    bundle = assemble(conn, cfg, "quoll pipeline", budget=4000)["bundle"]
    assert "decision 0 on the quoll pipeline" in bundle, \
        "a verdict changed retrieval of the audited note"


def test_idempotence_unaudited_candidates_come_first():
    conn = connect()
    cfg = load_config()
    notes = _archive_with_notes(conn, 4)
    cal = _calibration()
    first = hook.run_audit(conn, cfg, cal, dispatcher=_stub(), n=2)
    audited = {r["note_id"] for r in first}
    second = hook.run_audit(conn, cfg, cal, dispatcher=_stub(), n=2)
    assert {r["note_id"] for r in second} == set(notes) - audited, \
        "audited notes were re-sampled while unaudited candidates remained"
    # once everything is audited, re-sampling the population is allowed
    third = hook.run_audit(conn, cfg, cal, dispatcher=_stub(), n=2)
    assert {r["note_id"] for r in third} <= set(notes)


def test_failed_dispatch_is_receipted_retryable_and_writes_no_verdict():
    conn = connect()
    cfg = load_config()
    notes = _archive_with_notes(conn, 1)
    cal = _calibration()

    def broken(payload):
        return {"status": "failed", "exit": 3, "text": "", "duration_ms": 1}

    results = hook.run_audit(conn, cfg, cal, dispatcher=broken, n=1)
    assert results[0]["failed"] == "failed" and results[0]["retryable"]
    assert conn.execute("SELECT COUNT(*) FROM events WHERE "
                        "kind='lineage_audit'").fetchone()[0] == 0
    outcome = conn.execute(
        "SELECT meta FROM events WHERE kind='egress_outcome' AND "
        "json_extract(meta,'$.egress_id') = ?",
        (results[0]["egress_id"],)).fetchone()
    assert json.loads(outcome["meta"])["status"] == "failed"
    # the note stays eligible: a later healthy run picks it up
    retry = hook.run_audit(conn, cfg, cal, dispatcher=_stub(), n=1)
    assert retry[0]["note_id"] == notes[0] and "audit_event" in retry[0]


def test_unparseable_reply_is_retryable_not_recorded():
    conn = connect()
    cfg = load_config()
    _archive_with_notes(conn, 1)

    def chatty(payload):
        return {"status": "succeeded", "exit": 0,
                "text": "I think this note seems fine overall!",
                "duration_ms": 1}

    results = hook.run_audit(conn, cfg, _calibration(), dispatcher=chatty, n=1)
    assert results[0]["failed"] == "unparseable" and results[0]["retryable"]
    assert conn.execute("SELECT COUNT(*) FROM events WHERE "
                        "kind='lineage_audit'").fetchone()[0] == 0


def test_judge_registered_once_with_calibration_matrix():
    conn = connect()
    cfg = load_config()
    _archive_with_notes(conn, 2)
    cal = _calibration()
    hook.run_audit(conn, cfg, cal, dispatcher=_stub(), n=1)
    hook.run_audit(conn, cfg, cal, dispatcher=_stub(), n=1)
    regs = conn.execute("SELECT meta FROM events WHERE "
                        "kind='lineage_judge'").fetchall()
    assert len(regs) == 1, "judge registration must be once per sha"
    meta = json.loads(regs[0]["meta"])
    assert meta["calibration"]["verdict"] == "AUDIT EARNED"
    assert "per_class" in meta["calibration"]


def test_report_reads_verdicts_next_to_calibration(capsys):
    conn = connect()
    cfg = load_config()
    _archive_with_notes(conn, 3)
    hook.run_audit(conn, cfg, _calibration(),
                   dispatcher=_stub("dropped-caveat"), n=3)
    rep = audit_report(conn)
    assert rep["audits"] == 3 and rep["coverage"] == 1.0
    sha = _calibration()["judge_sha"]
    assert rep["by_judge_sha"][sha]["dropped-caveat"] == 3
    import argparse
    cmd_lineage(argparse.Namespace(action="report", full=False))
    out = capsys.readouterr().out
    assert "dropped-caveat: 3" in out
    assert "calibration (AUDIT EARNED" in out
    assert "advisory" in out
