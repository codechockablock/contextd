"""Report renderer for the decisions-lifecycle contrast. Deliberately
OUTSIDE the contrast-spec instrument hash: the renderer formats durable
records and may be edited after runs; the measurement path may not.
"""

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))

from experiments.selection_stress.contrast import (  # noqa: E402
    CONTRAST, FROZEN_CONTRAST, contrast_sha)


# --- report -----------------------------------------------------------------

RUN_DIR = REPO / "runs" / "decisions-lifecycle-2026-08-14"


def render_report(prereg_id: int) -> str:
    doc = json.loads(FROZEN_CONTRAST.read_text())
    a = json.loads((CONTRAST / "analysis.json").read_text())
    b = json.loads((CONTRAST / "behavior-results.json").read_text())
    reg = json.loads((CONTRAST / "kernel-regression.json").read_text())
    bars = {**a["bar_results"], **b["bar_results"]}
    all_met = all(bars.values())
    L = []
    w = L.append
    w("# Decisions-lifecycle contrast — final report")
    w("")
    w(f"Contract `docs/DECISIONS.md` (sha `{doc['contract_sha']}`); "
      f"contrast prereg ledger event `#{prereg_id}` (spec sha "
      f"`{contrast_sha(doc)}`); baseline: selection-stress r2 (spec sha "
      f"`{doc['baseline_spec_sha']}`). Rebuild with "
      f"`experiments/selection_stress/bench.py contrast-report "
      f"{prereg_id}`.")
    w("")
    w("## Verdict")
    w("")
    if all_met:
        w("**FIX DECLARED.** Every preregistered bar was met; the surface "
          "moved and the residue is loud. The declaration extends exactly "
          "as far as the bars do — see the license section.")
    else:
        failed = [k for k, v in bars.items() if not v]
        w(f"**FIX NOT DECLARED.** Failed bars: {', '.join(failed)}. The "
          f"numbers below stand either way.")
    w("")
    w("## Preregistered bars")
    w("")
    w("| bar | requirement | result |")
    w("|---|---|---|")
    e1 = a["endpoint1_silent_resurrection"]
    e2 = a["endpoint2_unmarked_served"]
    e3 = a["endpoint3_surface"]
    e4 = a["endpoint4_nonregression"]
    w(f"| 1 silent resurrection | 0 occurrences | {e1['k']}/{e1['n']} — "
      f"{'MET' if bars['1_silent'] else 'NOT MET'} |")
    w(f"| 2 unmarked superseded served | 0 occurrences | {e2['k']}/"
      f"{e2['n']} — {'MET' if bars['2_unmarked'] else 'NOT MET'} |")
    w(f"| 3 surface movement | resurrection <= 0.05 (baseline "
      f"{e3['baseline']['rate']}) | lifecycle {e3['lifecycle']['rate']} "
      f"(seed-bootstrap {e3['lifecycle_seed_bootstrap']}) — "
      f"{'MET' if bars['3_surface'] else 'NOT MET'} |")
    w(f"| 4a pooled non-regression | <= 0.02 | {e4['pooled_delta']} — "
      f"{'MET' if bars['4a_pooled'] else 'NOT MET'} |")
    w(f"| 4b unpaid losses (reserve not engaged) | 0 | "
      f"{e4['n_unpaid_losses']} — "
      f"{'MET' if bars['4b_unpaid'] else 'NOT MET'} |")
    w(f"| 4c taxed-pair pooled delta | <= 0.10 | "
      f"{e4['taxed_pooled_delta']} over {e4['taxed_pairs']} pairs — "
      f"{'MET' if bars['4c_taxed'] else 'NOT MET'} |")
    w(f"| 5 behavioral resurrects | pooled <= 0.3, p <= 0.05 | pooled "
      f"{b['pooled_lifecycle_resurrects']} "
      f"(p={b['pooled_perm']['p']}, {b['pooled_perm']['method']}) — "
      f"{'MET' if bars['5_resurrects'] else 'NOT MET'} |")
    w(f"| 5 behavioral v2-honors | pooled >= 0.5 | pooled "
      f"{b['pooled_lifecycle_honors']} — "
      f"{'MET' if bars['5_honors'] else 'NOT MET'} |")
    w("")
    w("## Measurements")
    w("")
    w(f"Kernel regression: the new kernel reproduced the stored r2 rows on "
      f"edge-less archives exactly ({reg['rows']} rows, "
      f"{reg['n_mismatches']} mismatches) before any lifecycle world was "
      f"built — the arms share one kernel and the baseline is unchanged "
      f"by construction.")
    w("")
    w(f"Supersession mechanics at the default budget (lifecycle arm, "
      f"hinted): v2 carried when v1 carried in "
      f"{a['v2_carried_given_v1_carried']['k']}/"
      f"{a['v2_carried_given_v1_carried']['n']} compiles "
      f"(rate {a['v2_carried_given_v1_carried']['rate']}); loud "
      f"SUPERSESSION OMITTED lines in {a['loud_omissions']['k']}/"
      f"{a['loud_omissions']['n']}; marked-but-unnamed (a contract defect "
      f"class, expected 0): {a['marked_but_unnamed']['k']}.")
    w("")
    w("Behavioral cells (baseline arm reused from prereg #36 by ledger "
      "reference):")
    w("")
    w("| cell | baseline resurrects | lifecycle resurrects | baseline "
      "v2-honors | lifecycle v2-honors | p (resurrects) |")
    w("|---|---|---|---|---|---|")
    for c in b["cells"]:
        w(f"| c{c['cell_index']} | {c['baseline_resurrects']} | "
          f"{c['lifecycle_resurrects']} | {c['baseline_honors']} | "
          f"{c['lifecycle_honors']} | {c['perm_resurrects']['p']} |")
    w("")
    w("## Honest annotations")
    w("")
    w("- This is round 2. Round 1 (prereg #253, outcome #254) ran the r1 "
      "mechanism and FAILED bars 2 and 4: the scorer's block extractor "
      "split on episode-note anchor citations (instrument artifact — the "
      "kernel was verified compliant on every flagged row), and the "
      "unconditional reserve taxed compiles that owed nothing (real "
      "mechanism cost, one cell lost 0.6). Fix was not declared; the "
      "mechanism was revised to two-pass, the bars were re-frozen with "
      "the unpaid/taxed distinction, and round 2 re-preregistered "
      "(#255) before any round-2 data existed. Zero behavioral "
      "dispatches were spent on round 1.")
    w("- After all 24 round-2 dispatches completed and were scored, the "
      "results aggregator crashed reading prereg #36's stored rows "
      "(key-name mismatch) and was fixed post-run; the fix touches only "
      "the stored-row reader — every per-run score was computed at "
      "dispatch time, before the crash. Recorded as a harness note in "
      "the experiment ledger with the post-fix module sha.")
    w("- Bar 4c's taxed-pair delta is measured on planted items only; the "
      "reserve may displace organic (unscored) content. The bound it "
      "certifies is about the measured surface, not every token.")
    w("- Lifecycle worlds append every supersession edge after the full "
      "event stream (digest-verified copies of the r2 worlds), not at the "
      "moment v2 was written. Edge position never enters selection or "
      "reduction order for distinct-old edges, so this cannot affect the "
      "endpoints; it is a timing-realism simplification, recorded here.")
    w("- The baseline worlds carry egress events accumulated by earlier "
      "grid compiles. Selection excludes egress rows by construction and "
      "the kernel-regression check confirmed identical scoring; recorded "
      "for completeness.")
    w("- The behavioral baseline arm is reused from prereg #36 rather than "
      "re-dispatched (24 new calls instead of 48). Identical archives, "
      "model, rubric, and protocol; the reuse was preregistered. Model "
      "drift between the two run dates is uncontrolled and would bias in "
      "an unknown direction; the carriage-level endpoints (1–4) do not "
      "share this caveat.")
    w("- The contract only covers RECORDED edges. Unrecorded supersessions "
      "behave exactly as the baseline measured (0.269 resurrection); this "
      "mechanism moves the surface only where an operator drew the edge.")
    w("- Plain recall (`ctx recall`) still serves superseded events "
      "unmarked — a recorded non-goal (docs/DECISIONS.md), not an "
      "oversight.")
    w("")
    w("## What these results do and do not license")
    w("")
    w("They **do** license: treating checkpoint-path stale resurrection as "
      "structurally loud *for recorded chains* — a superseded item cannot "
      "be served unmarked, and its current version is carried or named; "
      "and treating the mechanism as cost-bounded (a 6%/min-120-token "
      "reserve, only when edges exist, with measured non-regression "
      "elsewhere on the surface).")
    w("")
    w("They do **not** license: any claim about unrecorded supersessions "
      "(operator diligence remains the input); extending the contract to "
      "the plain recall path (separate decision, unmeasured); or the "
      "model-proposed-edge design (a possible later mission with its own "
      "authority questions). The behavioral confirmation is three cells "
      "and one model; the carriage endpoints are the load-bearing "
      "evidence.")
    w("")
    return "\n".join(L) + "\n"


def cmd_contrast_report(args) -> int:
    text = render_report(args.prereg_id)
    path = RUN_DIR / "final-report.md"
    if args.write:
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        print(f"wrote {path}")
        return 0
    if not path.exists():
        print(f"no stored report at {path}; use --write first")
        return 1
    if path.read_text() == text:
        print(f"report rebuild matches stored report ({path})")
        return 0
    print("REPORT MISMATCH: rebuild differs from stored report")
    return 1
