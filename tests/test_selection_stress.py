"""Selection-stress harness: generator determinism, scorer classes,
validity-gate mechanics, rubric scoring, and the stats helpers. Everything
here is model-free and runs on the tiny tier."""

from experiments.selection_stress import stats, validity
from experiments.selection_stress.behavior import scanned_text, score_output
from experiments.selection_stress.carriage import score_topic
from experiments.selection_stress.generator import build_archive


def test_generator_determinism(tmp_path):
    m1 = build_archive(tmp_path / "a1", "tiny", 7, mini=True)
    m2 = build_archive(tmp_path / "a2", "tiny", 7, mini=True)
    m3 = build_archive(tmp_path / "a3", "tiny", 8, mini=True)
    assert m1["digest"] == m2["digest"]
    assert m1["digest"] != m3["digest"]
    assert m1["n_events"] == m2["n_events"]


def test_generator_rank_fidelity(tmp_path):
    m = build_archive(tmp_path / "a", "tiny", 7, mini=True)
    for tp in m["topics"]:
        for key in ("plant", "v2", "twin"):
            if tp.get(key):
                delta = abs(tp[key]["achieved_rank"] - tp[key]["target_rank"])
                assert delta <= 1, (tp["stratum"], tp["age"], key, tp[key])


def _vrow(band, rank, seed=1, ctx="x"):
    return {"tier": "t", "seed": seed, "stratum": ctx, "age": "recent",
            "band": band, "distractor": "none", "rank": rank}


def test_ordering_consistency_strict_and_ties():
    rows = [_vrow("near", 1), _vrow("mid", 5), _vrow("far", None)]
    cons = validity.ordering_consistency(rows)
    assert cons["near<mid"]["rate"] == 1.0
    assert cons["mid<far"]["rate"] == 1.0
    # both absent = a tie, counted against strict ordering
    rows = [_vrow("near", 2), _vrow("mid", None), _vrow("far", None)]
    cons = validity.ordering_consistency(rows)
    assert cons["mid<far"]["rate"] == 0.0
    assert cons["near<far"]["rate"] == 1.0


def test_validity_gate_fails_below_bar():
    rows = []
    for i in range(10):
        rows.append(_vrow("near", 5, ctx=f"c{i}"))
        rows.append(_vrow("mid", 1 if i < 5 else 9, ctx=f"c{i}"))
        rows.append(_vrow("far", None, ctx=f"c{i}"))
    cons = validity.ordering_consistency(rows)
    gate = validity.gate(cons)
    assert not gate["passed"]
    assert "near<mid" in gate["failing_pairs"]


def _topic(**over):
    tp = {"distractor": "none", "scope": "task", "opt_a": "two-phase",
          "plant": {"event_id": 10}, "decoys": []}
    tp.update(over)
    return tp


def _compiled(items, package="", sections=None):
    return {"items": set(items), "package": package,
            "sections": sections or {"notes": set(items), "tail": set(),
                                     "episodes": set(), "recall": set(),
                                     "loops": set()}}


def test_score_topic_carried_and_silent():
    s = score_topic(_topic(), _compiled([10], "…two-phase…"))
    assert s["carried"] and s["via"] == "notes" and not s["silently_absent"]
    s = score_topic(_topic(), _compiled([99]))
    assert not s["carried"] and s["silently_absent"] and not s["omitted_named"]


def test_score_topic_omitted_named_is_not_silent():
    pkg = "BUDGET OMITTED: 1 item: 10 — see ctx"
    s = score_topic(_topic(), _compiled([99], pkg))
    assert s["omitted_named"] and not s["silently_absent"]


def test_score_topic_stale_resurrection():
    tp = _topic(distractor="super", v2={"event_id": 20})
    s = score_topic(tp, _compiled([10]))
    assert s["stale_resurrected"] and not s["superseded_honored"]
    s = score_topic(tp, _compiled([10, 20]))
    assert not s["stale_resurrected"] and s["superseded_honored"]
    s = score_topic(tp, _compiled([20]))
    assert not s["stale_resurrected"] and s["superseded_honored"]


def test_rubric_sections_and_token_forms():
    out = ("OBJECTIVE: ship it\nSETTLED DECISIONS: we keep the two phase "
           "strategy [12]\nCONSTRAINTS IN FORCE: none\nNEXT ACTION: start")
    text, parse_ok = scanned_text(out)
    assert parse_ok and "two phase" in text and "ship it" not in text
    s = score_output(out, {"kind": "absent", "opt_a": "two-phase"})
    assert s["honors"] and s["parse_ok"]
    s = score_output("no sections at all, two-phase mentioned",
                     {"kind": "absent", "opt_a": "two-phase"})
    assert s["honors"] and not s["parse_ok"]


def test_rubric_supersession():
    cell = {"kind": "super", "opt_a": "two-phase", "opt_c": "hash-ring"}
    s = score_output("SETTLED DECISIONS: the two-phase call stands\n"
                     "NEXT ACTION: go", cell)
    assert s["resurrects"] and not s["honors"]
    s = score_output("SETTLED DECISIONS: superseded — use hash-ring now\n"
                     "NEXT ACTION: go", cell)
    assert s["honors"] and not s["resurrects"]


def test_stats_helpers_deterministic():
    lo, hi = stats.wilson(9, 10)
    assert 0.55 < lo < 0.7 and 0.95 < hi <= 1.0
    ci1 = stats.bootstrap_ci([0.2, 0.4, 0.6])
    ci2 = stats.bootstrap_ci([0.2, 0.4, 0.6])
    assert ci1 == ci2 and ci1["n_clusters"] == 3
    p = stats.perm_test([1, 1, 1, 1], [0, 0, 0, 0])
    assert p["method"].startswith("exact") and p["p"] <= 0.05
    same = stats.perm_test([1, 0, 1, 0], [0, 1, 0, 1])
    assert same["p"] == 1.0
