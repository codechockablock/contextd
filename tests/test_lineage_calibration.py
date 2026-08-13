"""The calibration protocol's deterministic layer: corpus generation is
frozen by digest, mutations do what their labels claim, the scorer and CI
math are exact, and the protocol machinery (prereg-before-heldout, tuning
cap, resumability) refuses violations. No model is ever dispatched here."""

import json
import re

import pytest

from experiments.lineage_calibration import calibrate
from experiments.lineage_calibration.corpus import (CLASSES, FROZEN_DIGEST,
                                                    build_corpus, digest,
                                                    render_evidence, split)


def test_corpus_is_deterministic_and_digest_frozen():
    a, b = build_corpus(), build_corpus()
    assert a == b, "two generations differ: corpus is not deterministic"
    assert digest(a) == FROZEN_DIGEST, (
        "corpus drifted from its frozen digest — the calibration verdict "
        "no longer describes this corpus")


def test_per_class_counts_and_split():
    items = build_corpus()
    for cls in CLASSES:
        assert sum(1 for i in items if i["class"] == cls) >= 60
    tuning, heldout = split(items)
    assert len(tuning) == len(heldout) == len(items) // 2
    assert not ({i["scenario"] for i in tuning}
                & {i["scenario"] for i in heldout}), "scenario leaked across split"


def _by_class(items, scenario):
    return {i["class"]: i for i in items if i["scenario"] == scenario}


def test_mutations_do_what_their_labels_claim():
    items = build_corpus()
    for scenario in (0, 17, 59):
        v = _by_class(items, scenario)
        evidence = render_evidence(v["faithful"])
        # faithful is a paraphrase: no note sentence appears verbatim in
        # the dialogue
        assert v["faithful"]["note"] not in evidence
        # dropped-caveat: strictly the faithful note minus the caveat clause
        assert len(v["dropped-caveat"]["note"]) < len(v["faithful"]["note"])
        assert "It holds" in v["faithful"]["note"]
        assert "It holds" not in v["dropped-caveat"]["note"]
        # emphasis-inversion swaps major/minor; same length shape
        assert v["emphasis-inversion"]["note"] != v["faithful"]["note"]
        assert "chief blocker" in v["emphasis-inversion"]["note"]
        # unsupported-claim adds a sign-off sentence absent from evidence
        extra = v["unsupported-claim"]["note"].replace(v["faithful"]["note"], "")
        assert "signed off" in extra and "signed off" not in evidence
        # quantitative-shift: some number differs, everything else equal
        assert v["quantitative-shift"]["note"] != v["faithful"]["note"]
        nums = lambda s: re.findall(r"\d+", s)  # noqa: E731
        assert nums(v["quantitative-shift"]["note"]) != nums(v["faithful"]["note"])
        # every anchored id in every note resolves to a dialogue message
        ids = {m["id"] for m in v["faithful"]["dialogue"]}
        for it in v.values():
            cited = {int(x) for x in re.findall(r"\[(\d+)\]", it["note"])}
            assert cited <= ids, "note cites an id outside its dialogue"


def test_parse_reply_accepts_json_and_rejects_garbage():
    ok = calibrate.parse_reply(
        '{"verdict": "dropped-caveat", "spans": ["but only after"]}')
    assert ok == {"verdict": "dropped-caveat", "spans": ["but only after"]}
    fenced = calibrate.parse_reply(
        '```json\n{"verdict": "faithful", "spans": []}\n```')
    assert fenced["verdict"] == "faithful"
    chatty = calibrate.parse_reply(
        'Sure! Here is my analysis: {"verdict": "faithful", "spans": []} hope')
    assert chatty["verdict"] == "faithful"
    assert calibrate.parse_reply("no json at all") is None
    assert calibrate.parse_reply('{"verdict": "made-up-class"}') is None
    assert calibrate.parse_reply('{"spans": []}') is None


def test_clopper_pearson_matches_known_values():
    lo, hi = calibrate.clopper_pearson(24, 30)
    assert abs(lo - 0.6143) < 0.002 and abs(hi - 0.9229) < 0.002
    assert calibrate.clopper_pearson(0, 30)[0] == 0.0
    assert calibrate.clopper_pearson(30, 30)[1] == 1.0
    lo, hi = calibrate.clopper_pearson(0, 30)
    assert hi < 0.14  # rule of three-ish upper bound


def test_scoring_rule_detection_and_decision():
    runs = []
    #  faithful: 29 correct, 1 false alarm -> FA 1/30 <= 0.1 PASS
    runs += [{"class": "faithful", "verdict": "faithful"}] * 29
    runs += [{"class": "faithful", "verdict": "dropped-caveat"}]
    #  dropped-caveat: 25/30 detected (any non-faithful verdict counts)
    runs += [{"class": "dropped-caveat", "verdict": "dropped-caveat"}] * 20
    runs += [{"class": "dropped-caveat", "verdict": "unsupported-claim"}] * 5
    runs += [{"class": "dropped-caveat", "verdict": "faithful"}] * 5
    #  unsupported-claim: 24/30 (unparseable counts as a miss)
    runs += [{"class": "unsupported-claim", "verdict": "unsupported-claim"}] * 24
    runs += [{"class": "unsupported-claim", "verdict": "faithful"}] * 4
    runs += [{"class": "unsupported-claim", "verdict": "unparseable"}] * 2
    #  emphasis-inversion: 21/30 = 0.7 exactly -> PASS (bar is >=)
    runs += [{"class": "emphasis-inversion", "verdict": "emphasis-inversion"}] * 21
    runs += [{"class": "emphasis-inversion", "verdict": "faithful"}] * 9
    #  quantitative-shift: 3/30 — terrible, but no bar: never fails the verdict
    runs += [{"class": "quantitative-shift", "verdict": "quantitative-shift"}] * 3
    runs += [{"class": "quantitative-shift", "verdict": "faithful"}] * 27
    matrix = calibrate.confusion(runs)
    assert matrix["unsupported-claim"]["unparseable"] == 2
    per = calibrate.rates(matrix)
    assert per["dropped-caveat"]["rate"] == round(25 / 30, 4)
    # the two unparseables are misses: 24 detected, not 26
    assert per["unsupported-claim"]["detected"] == 24
    assert per["faithful"]["detected"] == 1  # the one false alarm


def test_unparseable_counts_against_the_instrument_both_ways():
    matrix = calibrate.confusion([
        {"class": "unsupported-claim", "verdict": "unparseable"},
        {"class": "faithful", "verdict": "unparseable"},
    ])
    per = calibrate.rates(matrix)
    assert per["unsupported-claim"]["detected"] == 0, "unparseable must miss"
    assert per["faithful"]["detected"] == 1, "unparseable must false-alarm"


def test_decision_rule_earned_and_not_earned():
    def uniform(rate_by_class):
        runs = []
        for cls, rate in rate_by_class.items():
            k = round(rate * 30)
            wrong = cls if cls != "faithful" else "dropped-caveat"
            runs += [{"class": cls, "verdict": wrong}] * k
            runs += [{"class": cls, "verdict": "faithful"}] * (30 - k)
        return runs

    good = calibrate.apply_decision_rule(calibrate.rates(calibrate.confusion(
        uniform({"faithful": 0.1, "dropped-caveat": 0.8,
                 "unsupported-claim": 0.9, "emphasis-inversion": 0.7,
                 "quantitative-shift": 0.0}))))
    assert good["verdict"] == "AUDIT EARNED", good
    # quantitative-shift at 0.0 must not fail the verdict: no bar
    bad = calibrate.apply_decision_rule(calibrate.rates(calibrate.confusion(
        uniform({"faithful": 0.1, "dropped-caveat": 0.77,
                 "unsupported-claim": 0.9, "emphasis-inversion": 0.7,
                 "quantitative-shift": 1.0}))))
    assert bad["verdict"] == "AUDIT NOT EARNED"
    assert [c for c in bad["checks"]
            if not c["pass"]][0]["class"] == "dropped-caveat"


def test_judge_sha_is_stable_and_prompt_sensitive(monkeypatch):
    a = calibrate.judge_sha("v1")
    assert a == calibrate.judge_sha("v1")
    monkeypatch.setitem(calibrate.PROMPTS, "vX", calibrate.PROMPTS["v1"] + "!")
    assert calibrate.judge_sha("vX") != a


def test_guard_refuses_live_archive(monkeypatch):
    monkeypatch.delenv("CONTEXTD_HOME", raising=False)
    with pytest.raises(SystemExit):
        calibrate._guard_home()


def test_payload_carries_evidence_and_note():
    item = build_corpus()[0]
    payload = calibrate.render_payload(item, "v1")
    assert item["note"] in payload
    assert render_evidence(item) in payload
    assert "EVIDENCE" in payload and "NOTE" in payload


def _fake_bin(tmp_path, script_body: str) -> str:
    py = tmp_path / "fake_judge.py"
    py.write_text(script_body)
    sh = tmp_path / "fake_claude"
    import sys
    sh.write_text(f"#!/bin/sh\nexec {sys.executable} {py}\n")
    sh.chmod(0o755)
    return str(sh)


ORACLE = '''
import json, re, sys
data = sys.stdin.read()
note = data.split("NOTE:")[-1]
# an oracle judge that reads the item's true class out of nothing —
# impossible for a real model, perfect for exercising the machinery
verdict = "faithful"
if "signed off" in note: verdict = "unsupported-claim"
elif "It holds" not in note: verdict = "dropped-caveat"
print(json.dumps({"result": json.dumps({"verdict": verdict, "spans": []}),
                  "total_cost_usd": 0.0}))
'''


def test_run_items_records_receipts_and_runs(tmp_path, monkeypatch):
    from contextd import load_config
    from contextd.db import connect
    monkeypatch.setattr(calibrate, "CLAUDE_BIN",
                        _fake_bin(tmp_path, ORACLE))
    conn, cfg = connect(), load_config()
    items = [i for i in build_corpus()[:10]
             if i["class"] in ("faithful", "dropped-caveat",
                               "unsupported-claim")]
    runs = calibrate.run_items(conn, cfg, items, "tune", "v1",
                               {"iteration": 1})
    assert len(runs) == len(items)
    for r in runs:
        assert r["dispatch_status"] == "succeeded"
        assert r["verdict"] == r["class"], "oracle mismatch: machinery bug"
        outcome = conn.execute(
            "SELECT meta FROM events WHERE kind='egress_outcome' AND "
            "json_extract(meta,'$.egress_id') = ?", (r["egress_id"],)
        ).fetchone()
        assert json.loads(outcome["meta"])["status"] == "succeeded"
    # run events are content-NULL: never in FTS, never recallable
    row = conn.execute("SELECT content FROM events WHERE "
                       "kind='lineage_cal_run' LIMIT 1").fetchone()
    assert row["content"] is None
    from contextd.search import search
    assert search(conn, "dropped caveat unsupported") == []


def test_failed_dispatch_gets_one_receipted_retry(tmp_path, monkeypatch):
    from contextd import load_config
    from contextd.db import connect
    flaky = f'''
import json, sys, os
marker = {json.dumps(str(tmp_path / "flaky-once"))}
sys.stdin.read()
if not os.path.exists(marker):
    open(marker, "w").write("x"); sys.exit(3)
print(json.dumps({{"result": json.dumps({{"verdict": "faithful",
                                          "spans": []}})}}))
'''
    monkeypatch.setattr(calibrate, "CLAUDE_BIN", _fake_bin(tmp_path, flaky))
    conn, cfg = connect(), load_config()
    runs = calibrate.run_items(conn, cfg, build_corpus()[:1], "tune", "v1",
                               {"iteration": 1})
    assert runs[0]["dispatch_status"] == "succeeded"
    statuses = [json.loads(r["meta"])["status"] for r in conn.execute(
        "SELECT meta FROM events WHERE kind='egress_outcome' ORDER BY id")]
    assert statuses == ["failed", "succeeded"], statuses
