"""The open-loops benchmark instrument, self-tested before any model run:
matching rule, capture/burden arithmetic, false-promotion detection, the
byte-identical-pair discipline, the carriage checker, split integrity, and
the honest-null property (a mechanism that does nothing earns nothing)."""

from experiments.open_loops import scoring
from experiments.open_loops.fixtures import (ALL_FIXTURES, PROJECTS,
                                             fixture_digest, split_fixtures)

MUST_SHAPES = ("explicit_request", "conditional_ack", "continuous_flow",
               "closure_mask")


def by_fid(fid):
    return next(f for f in ALL_FIXTURES if f["fid"] == fid)


# --- matching rule ----------------------------------------------------------

def test_covers_requires_every_term():
    plant = {"match": ["drift correction", "July batch"]}
    assert scoring.covers(
        "re-run the DRIFT   correction against the july batch", plant)
    assert not scoring.covers("re-run the drift correction", plant)
    assert not scoring.covers("the july batch numbers look off", plant)
    assert not scoring.covers("", plant)


def test_capture_perfect_and_empty_mechanisms():
    fixtures = [by_fid("er-gauge-1"), by_fid("nu-gauge-1")]
    perfect = {"er-gauge-1": [
        "re-run the drift correction against the July batch with the "
        "sniffer on"]}
    s = scoring.score_capture(fixtures, perfect)
    assert s["n_must"] == 1 and s["captured"] == 1
    assert s["capture_rate"] == 1.0 and s["burden_mean"] == 0.0

    empty = scoring.score_capture(fixtures, {})
    assert empty["captured"] == 0 and empty["capture_rate"] == 0.0
    assert empty["burden_mean"] == 0.0  # silence costs no dismissals


def test_capture_counts_burden_and_distractor_hits():
    fixtures = [by_fid("mu-amber-1")]
    noisy = {"mu-amber-1": [
        "build the plugin api and community registry",   # distractor plant
        "investigate the weather"]}                      # matches nothing
    s = scoring.score_capture(fixtures, noisy)
    assert s["n_must"] == 0 and s["capture_rate"] is None
    assert s["burden_mean"] == 2.0
    assert s["distractor_hits"] == 1


def test_pair_excluded_from_capture_aggregates():
    pair = [f for f in ALL_FIXTURES if f["shape"] == "identical_pair"]
    s = scoring.score_capture(pair, {pair[0]["fid"]: ["dead-letter shelf "
                                                      "after five times"]})
    assert s["n_must"] == 0 and s["burden_by_dialogue"] == []


# --- false promotion --------------------------------------------------------

def test_false_promotion_flags_model_openings_only():
    ok = [{"id": 1, "created_authority": "model", "created_state": "candidate",
           "state": "candidate"},
          {"id": 2, "created_authority": "operator", "created_state": "open",
           "state": "open"},
          {"id": 3, "created_authority": "model", "created_state": "candidate",
           "state": "open", "promoted_authority": "operator"}]
    assert scoring.score_false_promotion(ok)["pass"]

    bad_creation = [{"id": 4, "created_authority": "model",
                     "created_state": "open", "state": "open"}]
    assert not scoring.score_false_promotion(bad_creation)["pass"]

    bad_promotion = [{"id": 5, "created_authority": "model",
                      "created_state": "candidate", "state": "open",
                      "promoted_authority": "model"}]
    assert not scoring.score_false_promotion(bad_promotion)["pass"]


# --- the byte-identical pair ------------------------------------------------

def test_pair_requires_identical_bytes_and_opposite_labels():
    pair = [f for f in ALL_FIXTURES if f["shape"] == "identical_pair"]
    assert len(pair) == 2
    assert pair[0]["messages"] == pair[1]["messages"]
    clean = {f["fid"]: {"false_promotions": 0, "asserted_certainty": False}
             for f in pair}
    assert scoring.score_pair(pair, clean)["pass"]

    certain = dict(clean)
    certain[pair[0]["fid"]] = {"false_promotions": 0,
                               "asserted_certainty": True}
    verdict = scoring.score_pair(pair, certain)
    assert not verdict["pass"] and "certainty" in verdict["why"]

    broken = [pair[0], dict(pair[1], messages=[{"role": "user", "text": "x"}])]
    assert not scoring.score_pair(broken, clean)["pass"]


# --- carriage checker -------------------------------------------------------

PACKAGE_WITH_SECTION = """=== CONTEXTD CHECKPOINT ===

== ACTIVE OPEN LOOPS (operator-confirmed, lifecycle-selected) ==
[loop#12] opened 2026-08-01: re-run the drift correction against the July batch
[loop#40] opened 2026-08-10, reopened 2026-08-12: fix the banner hash collision

== OPERATOR NOTES (deliberate, human-written) ==
--- [90] 2026-08-12 note/note ---
decision: keep the gate an audit layer
"""


def test_carriage_finds_present_and_absent():
    r = scoring.check_carriage(
        PACKAGE_WITH_SECTION,
        expect_present=["drift correction against the July batch",
                        "banner hash collision"],
        expect_absent=["rotate the SMTP app password"])
    assert r["pass"], r["problems"]

    r2 = scoring.check_carriage(
        PACKAGE_WITH_SECTION,
        expect_present=["a loop that is not there"],
        expect_absent=[])
    assert not r2["pass"]

    r3 = scoring.check_carriage(
        PACKAGE_WITH_SECTION,
        expect_present=[],
        expect_absent=["keep the gate an audit layer"])
    assert not r3["pass"], "absence check must scan the whole package"


def test_carriage_omission_line_contract():
    pkg = PACKAGE_WITH_SECTION.replace(
        "\n== OPERATOR NOTES",
        "\nBUDGET OMITTED: 2 active loop(s): loop#77, loop#78 — run "
        "'ctx loop list'\n\n== OPERATOR NOTES")
    ok = scoring.check_carriage(pkg, ["drift correction"], [],
                                expect_omitted_ids=[77, 78])
    assert ok["pass"], ok["problems"]
    wrong_ids = scoring.check_carriage(pkg, [], [], expect_omitted_ids=[77])
    assert not wrong_ids["pass"]
    unexpected = scoring.check_carriage(pkg, [], [], expect_omitted_ids=None)
    assert not unexpected["pass"], "silent omission line must be flagged"
    missing = scoring.check_carriage(PACKAGE_WITH_SECTION, [], [],
                                     expect_omitted_ids=[9])
    assert not missing["pass"]


# --- decision rule ----------------------------------------------------------

BARS = {"capture_min": 0.75, "burden_max": 1.0}


def test_decision_rule_is_conjunctive_and_honest_null_fails():
    good = scoring.decide_capture(0.9, 0.4, 0, True, BARS)
    assert good["earned"]
    for bad in (
        scoring.decide_capture(0.9, 0.4, 1, True, BARS),
        scoring.decide_capture(0.9, 0.4, 0, False, BARS),
        scoring.decide_capture(0.5, 0.4, 0, True, BARS),
        scoring.decide_capture(0.9, 3.0, 0, True, BARS),
        scoring.decide_capture(None, 0.0, 0, True, BARS),
    ):
        assert not bad["earned"] and bad["reasons"]


# --- fixture integrity ------------------------------------------------------

def test_split_is_disjoint_covers_all_and_strands_no_shape():
    split = split_fixtures()
    cal = {f["fid"] for f in split["calibration"]}
    held = {f["fid"] for f in split["heldout"]}
    assert not cal & held
    assert cal | held == {f["fid"] for f in ALL_FIXTURES}
    for side in (split["calibration"], split["heldout"]):
        shapes = {f["shape"] for f in side}
        assert {"explicit_request", "conditional_ack", "continuous_flow",
                "closure_mask", "musing", "completed", "null"} <= shapes
        assert len({f["project"] for f in side}) >= 2
    pair_fids = {f["fid"] for f in ALL_FIXTURES
                 if f["shape"] == "identical_pair"}
    assert pair_fids <= held, "the pair is evaluation-only"


def test_heldout_wordings_are_unseen_in_calibration():
    split = split_fixtures()
    cal_text = scoring.normalize(
        " ".join(m["text"] for f in split["calibration"]
                 for m in f["messages"]))
    for f in split["heldout"]:
        for p in f["planted"]:
            if p["label"] != "must_capture":
                continue
            assert not all(scoring.normalize(t) in cal_text
                           for t in p["match"]), \
                f"held-out plant {p['pid']} wording appears in calibration"


def test_every_must_capture_dialogue_has_matchable_plant():
    for f in ALL_FIXTURES:
        dialogue = scoring.normalize(
            " ".join(m["text"] for m in f["messages"]))
        for p in f["planted"]:
            for term in p["match"]:
                assert scoring.normalize(term) in dialogue, \
                    f"{f['fid']}/{p['pid']}: match term {term!r} not in " \
                    "dialogue - the scorer could never fire"
    counts = {}
    for f in ALL_FIXTURES:
        for p in f["planted"]:
            counts[p["label"]] = counts.get(p["label"], 0) + 1
    assert counts["must_capture"] == 24
    assert counts["distractor"] == 6
    assert counts["ambiguous"] == 2


def test_projects_and_digest_are_frozen():
    assert set(PROJECTS) == {"amberlight", "gaugepost", "quartzfeed"}
    assert len(fixture_digest()) == 64


def test_trial_scorer_math_on_a_synthetic_window(isolated_contextd_home):
    """The v2 trial scorer, pinned before the window: path stratification,
    the honest denominator, carriage from ledger meta alone, burden per
    session-day, and the named-omission loud failure."""
    from contextd import load_config
    from contextd.db import append_event, connect
    from contextd.handoff import compile_checkpoint
    from contextd.loops import add_candidate, add_loop, make_scope, transition
    from experiments.open_loops.trial import score_window

    conn = connect()
    start = append_event(conn, "note", "note", content="window start",
                         meta={"actor": "human"})
    scope = make_scope("/synthetic/amberlight")
    a = add_loop(conn, "re-run the drift correction", scope)["loop"]
    cand = add_candidate(conn, "audit the sitemap generator", scope)["loop"]
    transition(conn, cand["id"], "confirm")
    junk = add_candidate(conn, "polish every docstring", scope)["loop"]
    transition(conn, junk["id"], "dismiss", reason="noise")
    append_event(conn, "claude_code", "message", uri="claude://t1",
                 content="working", meta={"role": "user", "session_id": "s1"})
    ck = compile_checkpoint(conn, load_config(), budget=4000,
                            repo={"path": "/synthetic/amberlight"})
    end = append_event(conn, "note", "note", content="window end",
                       meta={"actor": "human"})

    r = score_window(conn, start, end, missed=1)
    assert r["paths"]["A_direct_add"] == [a["id"]]
    assert r["paths"]["B_candidate_confirmed"] == [cand["id"]]
    assert r["capture"]["denominator"] == 3
    assert r["capture"]["rate"] == round(2 / 3, 4)
    assert not r["capture"]["pass"], "denominator floor of 5 must gate"
    assert r["carriage"]["pass"] is True
    assert r["carriage"]["checks"][0]["egress"] == ck["egress_id"]
    assert sorted(r["carriage"]["checks"][0]["expected"]) == \
        sorted([a["id"], cand["id"]])
    assert r["burden"]["dismissals"] == 1 and r["burden"]["session_days"] == 1
    assert r["burden"]["pass"]
    assert r["false_promotion"]["pass"]

    # a checkpoint that omits an active loop must fail carriage loudly
    r2 = score_window(conn, start, end, missed=0)
    assert r2["capture"]["rate"] == 1.0
