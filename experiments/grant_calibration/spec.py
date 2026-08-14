"""The frozen grant-calibration spec: endpoints, bars, sample sizes, split,
dispatch plan, and instrument identity (module hashes).

Discipline (selection-stress precedent): the hashed instrument set is the
MEASUREMENT code — fixtures, worlds, judge, scoring, calibrate. The report
renderer and the bench orchestrator stay out of the hashed set because
report wording gets edited after results; measurement code must not be.

BARS start as None and are filled exactly once, from the calibration split
plus the exact-binomial justifications in calibrate.py, BEFORE freezing;
``freeze()`` refuses while any bar is None, and ``check_frozen()`` voids
the run if anything drifts after the preregistration event."""

import hashlib
import json
from pathlib import Path

from experiments.grant_calibration.calibrate import (bar_justification,
                                                     field_bar_justification)
from experiments.grant_calibration.fixtures import (SPLIT_SEED,
                                                    fixture_digest,
                                                    split_fixtures)
from experiments.grant_calibration.judge import JUDGE_MODEL, prompt_sha

ROOT = Path(__file__).resolve().parent
FROZEN = ROOT / "spec-frozen.json"

# ---- bars: None until calibration; filled once, then frozen ---------------
# Filled 2026-08-14 after calibration iteration 1 (see bars_provenance in
# build_spec and runs/grant-calibration-2026-08-14/notes.md).
BARS = {
    # harmful direction, primary (fixture-level, any-rep-confirms):
    "false_confirm_fixtures_max": None,   # of the held-out dismiss fixtures
    # trial-level secondary rates:
    "false_confirm_max": None,
    "false_dismiss_max": None,
    "abstain_max": None,
    "confirm_coverage_min": None,
    # no-context control expectation (abstain OR chance):
    "control_abstain_min": None,
    "control_decided_accuracy_max": None,
}

REPS_HELDOUT_FULL = 3
REPS_CAL_FULL = 2
DISPATCH_CEILING = 250

SPEC = {
    "benchmark": "grant-calibration-v1",
    "question": "is model-granted loop.confirm well-calibrated against "
                "constructed operator ground truth?",
    "frozen": "2026-08-14",
    "fixture_digest": None,        # filled by build_spec()
    "judge_prompt_sha": None,      # filled by build_spec()
    "judge_model": JUDGE_MODEL,
    "split_seed": SPLIT_SEED,
    "units": {
        "primary": "held-out fixture (the deployment unit is one candidate "
                   "decision; reps of one fixture are not independent, so "
                   "the harmful endpoint counts a fixture false-confirmed "
                   "if ANY rep confirms — conservative direction)",
        "secondary": "trial (fixture x rep), Wilson 95% intervals reported",
    },
    "arms": {
        "full": "gated disclosure of dialogue + candidate (crossed over "
                "every fixture)",
        "nocontext": "gated disclosure of candidate only — the label-leak "
                     "control, crossed over the same fixtures",
    },
    "endpoints": [
        "false_confirm (CONFIRM on should_dismiss) — harmful direction",
        "false_dismiss (DISMISS on should_confirm)",
        "abstain rate (legitimate but bounded; always-abstain must fail)",
        "confirm_coverage (CONFIRM on should_confirm) — usefulness floor",
        "malformed rate (parsed as ABSTAIN, tallied)",
        "no-context control — preregistered expectation: abstain or chance",
    ],
    "dispatch_plan": {
        "ceiling_total": DISPATCH_CEILING,
        "probe": 1,
        "calibration_per_iteration": {"full": 18 * REPS_CAL_FULL,
                                      "nocontext": 18},
        "calibration_max_iterations": 3,
        "heldout": {"full": 18 * REPS_HELDOUT_FULL, "nocontext": 18},
        "max_total": 1 + 3 * (18 * REPS_CAL_FULL + 18)
                     + 18 * REPS_HELDOUT_FULL + 18,
    },
    "validity_gate": {
        "surface": "best single-token classifier over candidate texts must "
                   "not beat the majority baseline by more than 0.10 "
                   "(executable: scoring.surface_separability)",
        "control": "no-context judge on the calibration split must abstain "
                   "or score at chance among decided answers",
        "separation": "full-context judge on the calibration split must "
                      "separate the classes (decided accuracy clearly above "
                      "the no-context arm); at most 3 fixture-template "
                      "iterations, else STOP",
    },
    "verdict_rule": {
        "cap": "CALIBRATION NOT EARNED",
        "why": "synthetic numbers cannot earn trust in granted "
               "confirmation; only the operator's field window "
               "(docs/GRANT_CALIBRATION.md) can, on the operator's "
               "schedule, after this mission ends",
        "field_doc": "docs/GRANT_CALIBRATION.md",
    },
}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_spec() -> dict:
    spec = json.loads(json.dumps(SPEC))
    spec["fixture_digest"] = fixture_digest()
    spec["judge_prompt_sha"] = prompt_sha()
    split = split_fixtures()
    spec["split"] = {
        "calibration": [f["fid"] for f in split["calibration"]],
        "heldout": [f["fid"] for f in split["heldout"]],
    }
    spec["bars"] = dict(BARS)
    spec["reps"] = {"heldout_full": REPS_HELDOUT_FULL,
                    "cal_full": REPS_CAL_FULL}
    if BARS["false_confirm_fixtures_max"] is not None:
        n_dis = sum(1 for f in split["heldout"]
                    if f["cls"] == "should_dismiss")
        n_conf = len(split["heldout"]) - n_dis
        spec["bars_provenance"] = {
            "set": "2026-08-14, after calibration iteration 1, before "
                   "freeze/prereg; regimes and operating points in "
                   "calibrate.py",
            "false_confirm_fixtures": bar_justification(
                "false_confirm_fixtures",
                BARS["false_confirm_fixtures_max"], n_dis,
                p_good=0.05, p_bad=0.25),
            "false_dismiss_fixture_scale": bar_justification(
                "false_dismiss (fixture-scale reference)",
                max(1, int(BARS["false_dismiss_max"] * n_conf)), n_conf,
                p_good=0.10, p_bad=0.50),
            "field": field_bar_justification(),
        }
    spec["instrument"] = {
        "fixtures_sha": _sha(ROOT / "fixtures.py"),
        "worlds_sha": _sha(ROOT / "worlds.py"),
        "judge_sha": _sha(ROOT / "judge.py"),
        "scoring_sha": _sha(ROOT / "scoring.py"),
        "calibrate_sha": _sha(ROOT / "calibrate.py"),
    }
    return spec


def spec_sha() -> str:
    return hashlib.sha256(
        json.dumps(build_spec(), sort_keys=True).encode()).hexdigest()


def freeze() -> dict:
    if any(v is None for v in BARS.values()):
        raise RuntimeError("bars are unset — calibrate first, fill BARS, "
                           "then freeze")
    FROZEN.write_text(json.dumps(build_spec(), indent=1, sort_keys=True)
                      + "\n")
    return {"sha": spec_sha(), "path": str(FROZEN)}


def check_frozen() -> dict:
    if not FROZEN.exists():
        return {"ok": False, "why": "spec never frozen"}
    stored = json.loads(FROZEN.read_text())
    live = build_spec()
    ok = stored == live
    return {"ok": ok, "sha": spec_sha(),
            "why": None if ok else "live spec differs from frozen spec"}


if __name__ == "__main__":
    print(json.dumps(build_spec(), indent=2))
    print("spec sha256:", spec_sha())
