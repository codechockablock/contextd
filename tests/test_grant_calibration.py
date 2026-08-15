"""The grant-calibration instrument, self-tested before any model run:
world determinism, gated disclosure, the frozen parse rule, the scorers on
known-answer judges, the executable validity gate, the exact-binomial bar
machinery, and the read-only field tally against a synthetic archive."""

import hashlib
import json
from pathlib import Path

from datetime import datetime, timedelta, timezone

import pytest


from experiments.grant_calibration import calibrate, judge, scoring, worlds
from experiments.grant_calibration.field_tally import (FIELD_BARS,
                                                       VETO_HARMFUL_PREFIX,
                                                       VETO_PREFIX, tally)
from experiments.grant_calibration.fixtures import (ALL_FIXTURES, PROJECTS,
                                                    fixture_digest,
                                                    split_fixtures)
from experiments.handoff.common import contextd_home


def _soon(hours: int = 8) -> str:
    """A finite, timezone-aware expiry. Grants without one are refused."""
    return (datetime.now(timezone.utc)
            + timedelta(hours=hours)).isoformat(timespec="seconds")

REPO = Path(__file__).resolve().parent.parent

CONFIRM_FX = next(f for f in ALL_FIXTURES if f["cls"] == "should_confirm")
DISMISS_FX = next(f for f in ALL_FIXTURES if f["cls"] == "should_dismiss")


# --- fixtures and split -----------------------------------------------------

def test_fixture_inventory_and_digest_stability():
    assert len(ALL_FIXTURES) == 36
    assert sum(1 for f in ALL_FIXTURES if f["cls"] == "should_confirm") == 12
    assert sum(1 for f in ALL_FIXTURES if f["cls"] == "should_dismiss") == 24
    # hard negatives present on both sides of the split
    split = split_fixtures()
    for side in (split["calibration"], split["heldout"]):
        subtypes = {f["subtype"] for f in side}
        assert {"near_miss", "superseded"} <= subtypes
    assert fixture_digest() == fixture_digest()
    assert split_fixtures() == split_fixtures()  # seeded => stable


def test_split_stratified_and_disjoint():
    split = split_fixtures()
    cal = {f["fid"] for f in split["calibration"]}
    held = {f["fid"] for f in split["heldout"]}
    assert not cal & held
    assert len(cal) == len(held) == 18
    from collections import Counter
    for side in (split["calibration"], split["heldout"]):
        assert all(v == 2 for v in
                   Counter(f["subtype"] for f in side).values())


# --- worlds -----------------------------------------------------------------

def test_world_determinism_same_seed_same_digest(tmp_path):
    worlds.build_world(tmp_path / "a", CONFIRM_FX)
    worlds.build_world(tmp_path / "b", CONFIRM_FX)
    assert worlds.world_digest(tmp_path / "a") == \
        worlds.world_digest(tmp_path / "b")
    worlds.build_world(tmp_path / "c", DISMISS_FX)
    assert worlds.world_digest(tmp_path / "a") != \
        worlds.world_digest(tmp_path / "c")


def test_world_candidate_is_model_candidate(tmp_path):
    w = worlds.build_world(tmp_path / "w", CONFIRM_FX)
    with contextd_home(tmp_path / "w"):
        from contextd.db import connect
        from contextd.loops import reduce_loops
        conn = connect()
        lp = reduce_loops(conn)["loops"][w["loop_id"]]
        conn.close()
    assert lp["state"] == "candidate"
    assert lp["created_authority"] == "model"
    assert lp["text"] == CONFIRM_FX["candidate"]


def test_bundles_are_gated_egress_in_their_world(tmp_path):
    w = worlds.build_world(tmp_path / "w", DISMISS_FX)
    b_full = worlds.disclose_bundle(w, "full", DISMISS_FX["fid"])
    b_no = worlds.disclose_bundle(w, "nocontext", DISMISS_FX["fid"])
    assert worlds.world_egress_count(tmp_path / "w") == 2
    assert DISMISS_FX["candidate"] in b_full["content"]
    assert DISMISS_FX["messages"][0]["text"] in b_full["content"]
    assert DISMISS_FX["messages"][0]["text"] not in b_no["content"]
    assert "(dialogue unavailable)" in b_no["content"]
    with pytest.raises(ValueError):
        worlds.disclose_bundle(w, "bogus", DISMISS_FX["fid"])


# --- parse rule -------------------------------------------------------------

def test_parse_verdict_frozen_rule():
    p = judge.parse_verdict
    assert p("CONFIRM") == {"verdict": "CONFIRM", "malformed": False}
    assert p("  dismiss.\n") == {"verdict": "DISMISS", "malformed": False}
    assert p("ABSTAIN\nCONFIRM")["verdict"] == "CONFIRM"  # last sole line
    assert p("the answer is ABSTAIN here")["verdict"] == "ABSTAIN"
    assert not p("the answer is ABSTAIN here")["malformed"]
    assert p("CONFIRM or DISMISS?") == {"verdict": "ABSTAIN",
                                        "malformed": True}
    assert p("") == {"verdict": "ABSTAIN", "malformed": True}
    assert p("sounds good") == {"verdict": "ABSTAIN", "malformed": True}


# --- scorers on known-answer judges ----------------------------------------

BARS = {"false_confirm_fixtures_max": 1, "false_confirm_max": 0.10,
        "false_dismiss_max": 0.34, "abstain_max": 0.50,
        "confirm_coverage_min": 0.50, "control_abstain_min": 0.50,
        "control_decided_accuracy_max": 0.65}


def _rows(fixtures, rule, arm="full", reps=1):
    return [{"fid": f["fid"], "arm": arm, "rep": i, "verdict": rule(f),
             "malformed": False}
            for f in fixtures for i in range(reps)]


def _oracle(f):
    return "CONFIRM" if f["cls"] == "should_confirm" else "DISMISS"


def test_oracle_judge_meets_bars():
    held = split_fixtures()["heldout"]
    full = scoring.score_trials(held, _rows(held, _oracle, reps=3))
    assert full["false_confirm"]["rate"] == 0.0
    assert full["false_dismiss"]["rate"] == 0.0
    assert full["confirm_coverage"]["rate"] == 1.0
    assert full["false_confirm_fixtures"]["k"] == 0
    noctx = scoring.score_trials(
        held, _rows(held, lambda f: "ABSTAIN", arm="nocontext"), "nocontext")
    d = scoring.decide(full, noctx, BARS)
    assert d["synthetic_bars_met"], d["reasons"]


def test_rubber_stamp_fails_harmful_direction():
    held = split_fixtures()["heldout"]
    full = scoring.score_trials(held, _rows(held, lambda f: "CONFIRM"))
    assert full["false_confirm"]["rate"] == 1.0
    assert full["false_confirm_fixtures"]["k"] == \
        full["false_confirm_fixtures"]["n"]
    noctx = scoring.score_trials(
        held, _rows(held, lambda f: "ABSTAIN", arm="nocontext"), "nocontext")
    d = scoring.decide(full, noctx, BARS)
    assert not d["synthetic_bars_met"]
    assert any("false-confirm" in r for r in d["reasons"])


def test_always_abstain_fails_usefulness_floor():
    held = split_fixtures()["heldout"]
    full = scoring.score_trials(held, _rows(held, lambda f: "ABSTAIN"))
    assert full["abstain"]["rate"] == 1.0
    noctx = scoring.score_trials(
        held, _rows(held, lambda f: "ABSTAIN", arm="nocontext"), "nocontext")
    d = scoring.decide(full, noctx, BARS)
    assert not d["synthetic_bars_met"]
    assert any("coverage" in r for r in d["reasons"])


def test_single_any_rep_confirm_counts_fixture_level():
    held = split_fixtures()["heldout"]
    dis_fid = next(f["fid"] for f in held if f["cls"] == "should_dismiss")
    rows = _rows(held, _oracle, reps=3)
    for r in rows:
        if r["fid"] == dis_fid and r["rep"] == 2:
            r["verdict"] = "CONFIRM"  # one bad rep out of three
    full = scoring.score_trials(held, rows)
    assert full["false_confirm_fixtures"]["k"] == 1
    assert full["false_confirm_fixtures"]["fids"] == [dis_fid]


# --- validity gate (executable) ---------------------------------------------

def test_validity_gate_unit():
    s = scoring.surface_separability(ALL_FIXTURES)
    assert s["best_token_accuracy"] <= s["majority_baseline"] + 0.10, s
    leaky = [dict(f, candidate=f["candidate"]
                  + (" pendingitem" if f["cls"] == "should_confirm"
                     else " droppeditem")) for f in ALL_FIXTURES]
    s_bad = scoring.surface_separability(leaky)
    assert s_bad["best_token_accuracy"] > \
        s_bad["majority_baseline"] + 0.10


def test_control_pass_logic():
    held = split_fixtures()["heldout"]
    leak = scoring.score_trials(held, _rows(held, _oracle, arm="nocontext"),
                                "nocontext")
    assert not scoring.control_pass(leak, BARS)["pass"]
    quiet = scoring.score_trials(
        held, _rows(held, lambda f: "ABSTAIN", arm="nocontext"), "nocontext")
    assert scoring.control_pass(quiet, BARS)["pass"]


def test_length_balance_reported():
    lb = scoring.length_balance(ALL_FIXTURES)
    assert set(lb) == {"should_confirm", "should_dismiss"}
    # gross imbalance would let length stand in for the label
    a = lb["should_confirm"]["mean_chars"]
    b = lb["should_dismiss"]["mean_chars"]
    assert 0.5 <= a / b <= 2.0, lb


# --- exact-binomial bar machinery -------------------------------------------

def test_binomial_bar_machinery():
    assert calibrate.binom_cdf(20, 20, 0.5) == pytest.approx(1.0)
    assert calibrate.pass_probability(1, 20, 0.2) == pytest.approx(0.0692)
    assert calibrate.pass_probability(1, 20, 0.02) == pytest.approx(0.9401)
    j = calibrate.bar_justification("x", 1, 12, 0.05, 0.25)
    assert j["pass_given_good"] > 0.85 and j["pass_given_bad"] < 0.20
    floor = calibrate.n_floor(lambda n: max(1, n // 12), 0.05, 0.25)
    assert floor["floor"] is not None


def test_field_bar_justification_matches_doc():
    f = calibrate.field_bar_justification(FIELD_BARS["min_confirms"],
                                          FIELD_BARS["max_vetoes"])
    doc = (REPO / "docs" / "GRANT_CALIBRATION.md").read_text()
    assert str(f["pass_curve_at_min_sample"]["0.2"]) in doc
    assert str(f["pass_curve_at_min_sample"]["0.02"]) in doc


# --- field tally ------------------------------------------------------------

def _build_field_archive(home: Path) -> dict:
    """Synthetic live-archive stand-in: a loop.confirm grant, candidates,
    model-granted confirms, one agree-close, one veto, one harmful veto,
    one still-open."""
    with contextd_home(home):
        from contextd.db import connect
        from contextd.grants import add_grant
        from contextd.loops import add_candidate, make_scope, transition
        conn = connect()
        scope = make_scope("/synthetic/fieldrepo")
        g = add_grant(conn, "loop.confirm", scope, expires=_soon(),
                      reason="field window")
        gid = g["grant"]["id"]
        ids = {}
        for name, text in (("agree", "ship the parser fix"),
                           ("veto", "rework the docs page"),
                           ("harmful", "rotate the staging keys"),
                           ("open", "profile the ingest path")):
            lp = add_candidate(conn, text, scope, client="scanner")["loop"]
            transition(conn, lp["id"], "confirm",
                       client="mcp", grant=gid)
            ids[name] = lp["id"]
        # an operator-confirmed loop must NOT count toward the tally
        op = add_candidate(conn, "write the release notes", scope,
                           client="scanner")["loop"]
        transition(conn, op["id"], "confirm")
        transition(conn, ids["agree"], "close",
                   reason="done this morning")
        transition(conn, ids["veto"], "close",
                   reason=f"{VETO_PREFIX} enthusiasm was not commitment")
        transition(conn, ids["harmful"], "close",
                   reason=f"{VETO_HARMFUL_PREFIX} keys rotated before "
                          "review, real cost")
        conn.close()
    return ids


def test_field_tally_counts_and_classifies(tmp_path):
    home = tmp_path / "field-home"
    ids = _build_field_archive(home)
    t = tally(home)
    assert t["model_granted_confirms"] == 4
    assert t["agrees_closed"] == [ids["agree"]]
    assert t["vetoes"] == [ids["veto"]]
    assert t["harmful_vetoes"] == [ids["harmful"]]
    assert t["open_agree_or_unreviewed"] == [ids["open"]]
    assert t["veto_rate_of_reviewed"] == pytest.approx(2 / 3, abs=1e-3)
    assert t["grant_active_days"] >= 1
    assert t["state"]["harmful_block"] is True
    assert "REFUSED" in t["state"]["status"]
    assert t["state"]["sample_met"] is False


def test_field_tally_since_filter_and_readonly(tmp_path):
    home = tmp_path / "field-home"
    _build_field_archive(home)
    db = home / "contextd.db"
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    t = tally(home, since="2099-01-01")
    assert t["model_granted_confirms"] == 0
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before
    # the tally's connection mode refuses writes outright
    from experiments.grant_calibration.field_tally import open_readonly
    conn = open_readonly(home)
    with pytest.raises(Exception):
        conn.execute("INSERT INTO events (ts, source, kind) "
                     "VALUES ('x', 'y', 'z')")
    conn.close()


def test_field_bars_pinned_to_doc():
    doc = (REPO / "docs" / "GRANT_CALIBRATION.md").read_text()
    assert f'--reason "{VETO_PREFIX} <why>"' in doc
    assert f'--reason "{VETO_HARMFUL_PREFIX} <why>"' in doc
    assert f">= {FIELD_BARS['min_confirms']}** model-granted" in doc
    assert f">= {FIELD_BARS['min_grant_days']}** distinct grant-active" in doc
    assert f"at most {FIELD_BARS['max_vetoes']} veto**" in doc
    assert "CALIBRATION NOT EARNED" in doc
    assert "CALIBRATION EARNED — loop.confirm" in doc


# --- spec instrument identity ----------------------------------------------

def test_spec_hashes_measurement_not_renderer():
    from experiments.grant_calibration import spec
    s = spec.build_spec()
    hashed = set(s["instrument"])
    assert hashed == {"fixtures_sha", "worlds_sha", "judge_sha",
                      "scoring_sha", "calibrate_sha"}
    assert s["fixture_digest"] == fixture_digest()
    assert s["judge_prompt_sha"] == judge.prompt_sha()
    assert s["dispatch_plan"]["max_total"] <= s["dispatch_plan"][
        "ceiling_total"]
    assert json.dumps(s, sort_keys=True)  # spec is JSON-serializable


def test_projects_are_synthetic():
    for p in PROJECTS.values():
        assert p["repo"].startswith("/synthetic/")
