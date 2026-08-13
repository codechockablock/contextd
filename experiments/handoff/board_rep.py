#!/usr/bin/env python
"""Board-stratum replication — total score as the PRIMARY endpoint.

What licensed this (ledger): the board-externalization trial (prereg #42127,
report #42163) failed its next_check endpoint but produced the series' first
distinguishable gain on the preregistered secondary comparison — r2 total
score 0.67 ± 0.00 (board) vs 0.46 ± 0.08 (baseline), Δ +0.21 at the 4v4
design floor. A single-case secondary licenses exactly one thing: a
replication with that comparison promoted to primary. This is it.

Replication scope — the PIPELINE, not the artifact: fresh frozen views,
fresh independent board passes (a new pass writes a different board; pass
stochasticity is part of the mechanism), fresh control compiles, n=5 per
arm per case (5v5 p-floor 0.0079, so p<=0.05 is reachable with room).

Honest threats, named before running:
- Regression to the mean: the original r2 baseline (0.46) ran LOW against
  its own history (0.54-0.67 across four earlier experiments' v1 arms). If
  the new baseline reverts, the delta shrinks — that is the point of
  replicating, not a nuisance.
- Board-realization luck: the original gain may belong to one fortunate
  board text. A fresh pass tests the distribution.
- Cutoff dependence: r1 was within noise (-0.04) originally; if r2 gains
  and r1 stays flat again, board utility is a property of wrap-point
  cutoffs (where reconciled episode notes are thin), which narrows any
  future feature to that condition.

Primary endpoint: r2 total-score delta (ckpt_board - ckpt_v1), permutation
p <= 0.05. Secondary: r1 delta; per-fact rates. next_check is expected to
stay 0.00 (the prior trial showed the target never enters the board; that
question is closed and is not re-litigated here)."""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from contextd.experiment import p_floor, perm_test, verdict  # noqa: E402
from experiments.handoff import board as B  # noqa: E402
from experiments.handoff.bench import _mean, _sd  # noqa: E402
from experiments.handoff.cases import CASES  # noqa: E402
from experiments.handoff.common import RESULTS, record  # noqa: E402


def main():
    n, jobs = 5, 3
    views = Path("runs/handoff-20260812/views-board-rep")
    views.mkdir(parents=True, exist_ok=True)
    spec = {
        "task_id": "handoff-board-replication-v1", "track": "board-replication",
        "replicates": 42127, "resume_model": B.MODEL, "pass_model": B.MODEL,
        "n_per_arm": n,
        "cases": {"r2-ranker-verdict": {"cutoff": CASES["r2-ranker-verdict"]["cutoff"],
                  "role": "primary"},
                  "r1-decomposition": {"cutoff": CASES["r1-decomposition"]["cutoff"],
                  "role": "secondary / cutoff-dependence probe"}},
        "arms": {"ckpt_v1": "kernel compiler baseline, fresh view, pre-pass",
                 "ckpt_board": "BOARD stratum from a FRESH independent pass"},
        "primary_endpoint": ("r2 total-score delta ckpt_board - ckpt_v1, "
                             "permutation p <= 0.05"),
        "expectation": (
            "Preregistered before any pass dispatch or arm run. Original "
            "effect: Δ +0.21 (p=0.0286 at the 4v4 floor). Success: a "
            "positive r2 delta at p <= 0.05 with n=5 (floor 0.0079). Named "
            "threats: regression to the mean (the original baseline 0.46 "
            "ran low vs its own 0.54-0.67 history), board-realization luck "
            "(fresh pass samples the mechanism, not the artifact), cutoff "
            "dependence (r1 within noise originally; a flat r1 with a "
            "replicated r2 gain narrows board utility to wrap-point "
            "cutoffs). A null here retires the board stratum on current "
            "evidence; a replicated gain earns a kernel-side design "
            "discussion, not an automatic ship."),
        "registered": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
    }
    exp_id = record("experiment", spec)
    print(f"preregistered board replication as live event #{exp_id}")
    outdir = RESULTS / f"handoff-board-rep-exp{exp_id}"
    outdir.mkdir(parents=True, exist_ok=True)

    all_results, pass_info = [], {}
    for case_name in ("r2-ranker-verdict", "r1-decomposition"):
        res, stats = B.run_case(case_name, views / case_name, n, jobs,
                                exp_id, outdir)
        all_results += res
        pass_info[case_name] = {k: v for k, v in stats.items()
                                if k != "final_board"}

    rep = {"exp_id": exp_id, "task_id": spec["task_id"],
           "track": "board-replication", "replicates": 42127,
           "pass": pass_info, "cases": {}}
    for case_name in ("r2-ranker-verdict", "r1-decomposition"):
        by_arm = {}
        for r in all_results:
            if r["case"] == case_name:
                by_arm.setdefault(r["arm"], []).append(r)
        entry = {}
        for arm, rs in by_arm.items():
            scores = [r["score"] for r in rs]
            entry[arm] = {
                "n": len(rs), "mean": round(_mean(scores), 4),
                "sd": round(_sd(scores), 4), "scores": scores,
                "ctx_tokens": rs[0]["ctx_tokens"],
                "fact_rates": {f["id"]: round(
                    sum(1 for r in rs if r["hits"].get(f["id"])) / len(rs), 3)
                    for f in CASES[case_name]["rubric"]["facts"]}}
        a = entry["ckpt_v1"]["scores"]
        b = entry["ckpt_board"]["scores"]
        p = perm_test(a, b)
        entry["comparison"] = {"delta": round(_mean(b) - _mean(a), 4),
                               "p": p, "p_floor": p_floor(len(a), len(b)),
                               "verdict": verdict(p)}
        rep["cases"][case_name] = entry
    rep["not_licensed"] = [
        "a model-maintained board simulates the workflow; an operator-"
        "maintained board is the real feature",
        "two cutoffs from one project on one model pair; replication across "
        "projects is untested",
        "'within noise' means not detected at this n, never 'no effect'",
    ]
    rep_id = record("exp_report", rep)
    (outdir / "report.json").write_text(json.dumps(rep, indent=2))
    print(f"\nreport -> live event #{rep_id}")
    for case_name, entry in rep["cases"].items():
        print(f"\n{case_name}:")
        for arm in ("ckpt_v1", "ckpt_board"):
            e = entry[arm]
            print(f"  {arm:<12} {e['mean']:.2f} ± {e['sd']:.2f} "
                  f"ctx ~{e['ctx_tokens']}tok")
        c = entry["comparison"]
        print(f"  Δ {c['delta']:+.2f}  p={c['p']} (floor {c['p_floor']})  "
              f"{c['verdict']}")


if __name__ == "__main__":
    main()
