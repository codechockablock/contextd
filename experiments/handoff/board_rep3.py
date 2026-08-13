#!/usr/bin/env python
"""Board-stratum replication, third cutoff — a third interruption TYPE.

Standing evidence: the board stratum is retired on r1/r2 evidence (original
r2 gain Δ +0.21 did not replicate: Δ +0.10, p=0.28, report #42199; the
original was substantially baseline regression). This trial asks the
remaining licensed question: is board utility a property of interruption
TYPE? r1 = mid-thread (board ≈ 0 or negative twice), r2 = wrap point
(positive twice, once at floor, once within noise). The third type:
seconds after an experiment completes, when the outcome exists only as
content-NULL ledger records that no context stratum can surface
(case r3-p2-interruption, cutoff #41699 — see cases.py for the rubric's
state-awareness design and its named threats).

Same pipeline as the replication: fresh frozen view, fresh independent
board pass, kernel-baseline control compiled pre-pass, n=5 per arm
(5v5 p-floor 0.0079). Primary endpoint: total-score delta ckpt_board -
ckpt_v1, permutation p <= 0.05. An uninformative null (both arms floored
on the state-awareness fact) is a named acceptable outcome."""

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

CASE = "r3-p2-interruption"


def main():
    n, jobs = 5, 3
    case = CASES[CASE]
    views = Path("runs/handoff-20260812/views-board-r3")
    views.mkdir(parents=True, exist_ok=True)
    spec = {
        "task_id": "handoff-board-replication-r3-v1",
        "track": "board-replication-r3", "replicates": [42127, 42199],
        "resume_model": B.MODEL, "pass_model": B.MODEL, "n_per_arm": n,
        "case": CASE, "cutoff": case["cutoff"], "commit": case["commit"],
        "moment": case["moment"], "rubric": case["rubric"],
        "arms": {"ckpt_v1": "kernel compiler baseline, fresh view, pre-pass",
                 "ckpt_board": "BOARD stratum from a fresh independent pass"},
        "primary_endpoint": ("total-score delta ckpt_board - ckpt_v1, "
                             "permutation p <= 0.05"),
        "expectation": case["expectation"],
        "registered": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
    }
    exp_id = record("experiment", spec)
    print(f"preregistered r3 board replication as live event #{exp_id}")
    outdir = RESULTS / f"handoff-board-r3-exp{exp_id}"
    outdir.mkdir(parents=True, exist_ok=True)

    results, pass_stats = B.run_case(CASE, views / CASE, n, jobs,
                                     exp_id, outdir)

    by_arm = {}
    for r in results:
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
                for f in case["rubric"]["facts"]}}
    a, b = entry["ckpt_v1"]["scores"], entry["ckpt_board"]["scores"]
    p = perm_test(a, b)
    comparison = {"delta": round(_mean(b) - _mean(a), 4), "p": p,
                  "p_floor": p_floor(len(a), len(b)), "verdict": verdict(p)}
    rep = {"exp_id": exp_id, "task_id": spec["task_id"],
           "track": "board-replication-r3", "case": CASE,
           "pass": {k: v for k, v in pass_stats.items() if k != "final_board"},
           "arms": entry, "comparison": comparison,
           "not_licensed": [
               "one new cutoff; interruption-type conclusions need more than "
               "three points",
               "a model-maintained board simulates the workflow",
               "'within noise' means not detected at this n, never 'no effect'",
           ]}
    rep_id = record("exp_report", rep)
    (outdir / "report.json").write_text(json.dumps(rep, indent=2))
    print(f"\nreport -> live event #{rep_id}\n")
    for arm in ("ckpt_v1", "ckpt_board"):
        e = entry[arm]
        print(f"  {arm:<12} score {e['mean']:.2f} ± {e['sd']:.2f}  "
              f"ctx ~{e['ctx_tokens']}tok")
        print(f"    facts: {e['fact_rates']}")
    print(f"\n  Δ {comparison['delta']:+.2f}  p={comparison['p']} "
          f"(floor {comparison['p_floor']})  {comparison['verdict']}")


if __name__ == "__main__":
    main()
