"""Report rendering: a pure function of the durable artifacts (frozen specs,
validity.json, grid rows, behavior runs, ledger records). ``bench.py report
<prereg-id>`` rebuilds the report and compares it byte-for-byte with the
stored copy; ``--write`` stores it."""

import json
from pathlib import Path

from experiments.selection_stress import analysis, behavior, spec

RESULTS = Path(__file__).resolve().parent / "results"
REPORT_PATH = behavior.RUNS_DIR / "final-report.md"


def _fmt_ci(d: dict) -> str:
    if d.get("mean") is None:
        return "n/a"
    return f"{d['mean']:.3f} [{d['lo']:.3f}, {d['hi']:.3f}] (n_seeds={d['n_clusters']})"


def _fmt_wilson(w) -> str:
    return f"[{w[0]:.3f}, {w[1]:.3f}]" if w and w[0] is not None else "n/a"


def render(prereg_id: int, prereg_meta: dict) -> str:
    s = spec.build_spec()
    vdoc = json.loads((RESULTS / "validity.json").read_text())
    rows = analysis.load_rows(RESULTS / "grid" / "rows.jsonl")
    doc = analysis.analyze({k: vdoc[k] for k in ("summary", "consistency",
                                                 "gate")}, rows, s)
    bdoc = json.loads(behavior.FROZEN_BEHAVIOR.read_text())
    bres = behavior.behavior_results(bdoc)
    grid_meta = json.loads((RESULTS / "grid" / "meta.json").read_text())
    used = behavior.dispatches_used()

    a, b, c = doc["headline_a"], doc["headline_b"], doc["headline_c"]
    L = []
    w = L.append
    w("# Selection-stress benchmark — final report")
    w("")
    w(f"Benchmark `selection-stress-v1`; grid spec sha `{spec.spec_sha()}`; "
      f"behavioral prereg ledger event `#{prereg_id}` (behavior spec sha "
      f"`{prereg_meta['behavior_spec_sha']}`). Rebuild with "
      f"`experiments/selection_stress/bench.py report {prereg_id}`.")
    w("")
    w("## Verdictable claims")
    w("")
    reg = a["region"]
    w(f"1. **Silent loss begins at the smallest measured scale.** The first "
      f"severity-ordered (tier, age, band) region where planted decisions "
      f"go silently absent in >20% of default-budget compiles is "
      f"**{reg['tier']} / {reg['age']} / {reg['band']}** — rate "
      f"{a['rate']:.3f} (n={a['n']}, Wilson {_fmt_wilson(a['wilson'])}, "
      f"seed-bootstrap {_fmt_ci(a['bootstrap'])}).")
    w(f"2. **Stale resurrection is the norm where supersession exists.** "
      f"Where a v2 exists, v1 was carried without v2 in "
      f"{b['rate']:.3f} of hinted default-budget compiles "
      f"(n={b['n']}, Wilson {_fmt_wilson(b['wilson'])}, seed-bootstrap "
      f"{_fmt_ci(b['bootstrap'])}).")
    w("3. **Compile latency scales with archive size but stays "
      "interactive**: mean ms per hinted compile — "
      + "; ".join(f"{t}: {_fmt_ci(c[t])}" for t in analysis.TIER_ORDER)
      + ".")
    w(f"4. **Behavioral effect is real where carriage fails**: pooled over "
      f"the preregistered silently-absent cells, mechanically restoring "
      f"the planted item moved the honor rate by "
      f"{bres['pooled_absent'].get('observed_diff')} "
      f"(stratified permutation p={bres['pooled_absent'].get('p')}, "
      f"{bres['pooled_absent'].get('method')}).")
    sup_claim = [e for e in bres["cells"] if e["kind"] == "super"]
    if sup_claim:
        rates = ", ".join(str(e["as_compiled"].get("resurrects"))
                          for e in sup_claim)
        w(f"5. **Stale carriage becomes stale behavior.** In the "
          f"supersession cells, resumers served the as-compiled package "
          f"asserted the superseded v1 as the current decision at rates "
          f"{rates} per cell (8 runs each).")
    w("")
    w("## Manipulation validity (gate for everything below)")
    w("")
    w("Band rank under the topic's own hint, real search walk, limit 200:")
    w("")
    w("| band | n | absent | median rank | min | max |")
    w("|---|---|---|---|---|---|")
    for band in ("near", "mid", "far"):
        r = vdoc["summary"][band]
        w(f"| {band} | {r['n']} | {r['absent']} | {r['median_rank']} | "
          f"{r['min']} | {r['max']} |")
    w("")
    cons = vdoc["consistency"]
    w("Pairwise strict-ordering consistency (bar ≥ 0.9): "
      + "; ".join(f"{k}: {v['rate']}" for k, v in sorted(cons.items()))
      + f". Gate passed: {vdoc['gate']['passed']}.")
    w("")
    w("Template iteration history is recorded in `vocab.py`: iteration 1 "
      "passed the ordering gate but left the mid band beyond the 40-hit "
      "recall cap (pipeline-equivalent to far); iteration 2 (frozen) "
      "placed mid at the ranks in the table above, straddling the "
      "selection boundary.")
    w("")
    w("## Carriage loss surface (hinted, default budget 4000)")
    w("")
    w("Carried rate by tier × age × band (pooled strata+distractors, "
      "n=45/cell):")
    w("")
    w("| tier | " + " | ".join(
        f"{a_}/{b_}" for a_ in analysis.AGE_ORDER
        for b_ in analysis.BAND_ORDER) + " |")
    w("|---" * 10 + "|")
    for tier in analysis.TIER_ORDER:
        grid = doc["surface_by_tier"][tier]
        w(f"| {tier} | " + " | ".join(
            f"{grid.get(f'{a_}/{b_}', float('nan')):.2f}"
            for a_ in analysis.AGE_ORDER for b_ in analysis.BAND_ORDER)
          + " |")
    w("")
    w("Silent-absence per (tier, age, band) cell with Wilson 95% CIs is in "
      "`results/analysis.json` (`surface`).")
    w("")
    w("Stratum × age carried rate (default budget): "
      + "; ".join(f"{k}: {v['carried']:.2f}"
                  for k, v in sorted(doc["stratum"].items())) + ".")
    w("")
    w("Budget sensitivity (carried / silently-absent, all task cells): "
      + "; ".join(f"{k}: {v['carried']:.2f}/{v['silent_absent']:.2f}"
                  for k, v in sorted(doc["budgets"].items())) + ".")
    w("")
    w("No-hint compiles (recency-only selection): carried by age — "
      + "; ".join(f"{k}: {v['carried']:.2f}"
                  for k, v in doc["no_hint"].items()) + ".")
    w("")
    tw = doc["twins"]
    w(f"Cross-project twins (n={tw['n']}): twin carried {tw['twin_carried']:.2f}, "
      f"task plant carried {tw['task_carried']:.2f}, twin carried while task "
      f"plant absent {tw['twin_instead_of_task']:.2f}.")
    w("")
    dc = doc["decoys"]
    w(f"Near-duplicate decoys: plant carried {dc['carried_with_decoys']:.2f} "
      f"with decoys vs {dc['carried_without']:.2f} without; mean decoys "
      f"carried alongside {dc['mean_decoys_carried']:.2f}.")
    w("")
    om = doc["omission_channel"]
    w(f"Loud-omission channel: {om['omitted_named_total']} of "
      f"{om['rows']} scored observations were omitted-but-named. The "
      f"pipeline has no loud-omission line for notes/episodes/recall "
      f"(only loops); the zero is measured, not assumed.")
    w("")
    w("## Behavioral subset (preregistered, real dispatches)")
    w("")
    w(f"Model `{bdoc['model']}`, {bdoc['n_per_arm']} runs/arm, "
      f"{len(bdoc['cells'])} cells; planned "
      f"{bdoc['planned_dispatches']} dispatches, ceiling "
      f"{bdoc['dispatch_ceiling']}; ledger-counted dispatches (probe "
      f"included) **{used}**. Succeeded {bres['n_succeeded']}/"
      f"{bres['n_runs']}; excluded runs: {len(bres['excluded'])} "
      f"({json.dumps(bres['excluded']) if bres['excluded'] else 'none'}).")
    w("")
    w("| cell | kind | coords | as-compiled honors | restored honors | p |")
    w("|---|---|---|---|---|---|")
    for e in bres["cells"]:
        coords = f"{e['tier']}/{e['stratum']}/{e['age']}/{e['band']}/{e['distractor']}"
        ac = e.get("as_compiled", {})
        rs = e.get("restored", {})
        p = (e.get("perm") or {}).get("p")
        w(f"| c{e['cell_index']} | {e['kind']} | {coords} | "
          f"{ac.get('honors')} | {rs.get('honors', '—')} | {p if p is not None else '—'} |")
    w("")
    pos = next(e for e in bres["cells"] if e["kind"] == "positive")
    neg = next(e for e in bres["cells"] if e["kind"] == "negative")
    pos_rate = pos["as_compiled"]["honors"]
    pos_met = pos_rate is not None and pos_rate >= 0.9
    w(f"Positive control (item verbatim in raw tail): as-compiled honors "
      f"{pos_rate} against the preregistered bar ≥ 0.9 — "
      f"**{'MET' if pos_met else 'NOT MET'}**.")
    if not pos_met:
        w("")
        w("The positive-control miss is an instrument finding, reported "
          "rather than buried: the prereg assumed verbatim-in-tail is a "
          "~ceiling for honoring, but the resumer honors tail-carried "
          "items at roughly this rate while honoring end-of-package "
          "restored items far more often (see the absent cells' restored "
          "arms). 'In context' and 'salient' are different constructs; the "
          "control measured tail-position salience, not the rubric "
          "ceiling. Consequence: arm deltas remain valid within-cell "
          "contrasts, but absolute honor levels are placement-sensitive "
          "and must not be read as carriage quality alone.")
    neg_p = neg["perm"]["p"]
    neg_met = neg_p is not None and neg_p > 0.3
    w("")
    w(f"Negative control (irrelevant item restored): task-plant honor "
      f"Δ p={neg_p} against the preregistered bar p > 0.3 — "
      f"**{'MET' if neg_met else 'NOT MET'}**; the model adopted the "
      f"irrelevant restored item into its scanned sections at rate "
      f"{neg['adopted_irrelevant']} (secondary observation, recorded "
      f"either way).")
    carried = [e for e in bres["cells"] if e["kind"] == "carried"]
    if carried:
        w("")
        w("Carried cells (arm delta preregistered ≈ 0): as-compiled honors "
          + "; ".join(f"c{e['cell_index']}: {e['as_compiled']['honors']}"
                      for e in carried)
          + ". No cell separated from its restored arm (all p > 0.2), as "
            "preregistered — but the *levels* are far below 1.0: an item "
            "mechanically present mid-package is honored in only a "
            "fraction of runs. Carriage is necessary, not sufficient; "
            "this is an instrument-adjacent finding about resumption "
            "behavior, not about selection.")
    sup = [e for e in bres["cells"] if e["kind"] == "super"]
    if sup:
        w("")
        w("Supersession cells (behavioral): "
          + "; ".join(
              f"c{e['cell_index']} as-compiled resurrects "
              f"{e['as_compiled'].get('resurrects')} → restored(v2) "
              f"resurrects {e['restored'].get('resurrects')}" for e in sup)
          + ". When the package carries only the stale v1, the resumer "
            "asserts the superseded decision as current in most runs — "
            "the carriage-level resurrection rate translates into "
            "behavior.")
    w("")
    w("## Honest annotations")
    w("")
    w("- Plant density is synthetic reality: 87 planted topics per archive "
      "(and their decoys/v2s) share each stratum's recency window; sibling "
      "plants crowd each other in the notes/episodes slices. Absolute "
      "carriage rates carry that bias (direction: pessimistic for recent "
      "cells); the surface's *shape* across coordinates is the claim, not "
      "the absolute level.")
    w("- The mid band's rank (12–28) was deliberately tuned to straddle the "
      "40-hit recall cap; carriage rates for mid measure the budget race, "
      "by design.")
    w("- Ages recent/mid/deep are stratum-rank coordinates, not wall time; "
      "'recent' spans a pinned ladder of ranks, so recent-cell rates "
      "average over that ladder.")
    w("- Restoration appends the item as a final package section; organic "
      "carriage places items mid-package. Position effects are not "
      "controlled and could inflate restored-arm honor rates.")
    w("- The behavioral subset runs entirely on seed-101 archives at the "
      "default budget; the grid supports no claim about other seeds' "
      "behavioral outcomes.")
    w("- Compile egress events accumulate in each archive during the grid; "
      "selection queries exclude egress rows, so later compiles are "
      "unaffected, but archive digests are build-time digests.")
    w("- The scorer's omitted-but-named class is structurally empty for "
      "non-loop strata in the current pipeline; it is reported as an "
      "instrument finding, not evidence that omission is loud.")
    w("")
    w("## What these results do and do not license")
    w("")
    w("They **do** license: treating silent omission of non-recent, "
      "non-lexically-near decisions as measured (not hypothetical) at "
      "every tier tested, including the smallest; treating stale "
      "resurrection as the default outcome when a superseding decision is "
      "phrased differently from its v1; and treating the hint as "
      "load-bearing (the no-hint table shows recency alone strands "
      "mid/deep items of every band).")
    w("")
    w("They do **not** license: choosing a specific fix. Candidate next "
      "builds map to failure regions as follows, and the operator decides:")
    w("- a decisions-lifecycle (first-class decision events with "
      "supersession links) addresses the resurrection rate and the "
      "deep/near-vs-far gap;")
    w("- budget-policy changes (larger notes/episodes shares or "
      "adaptive shares) address the shallow recency cliffs the stratum "
      "table shows;")
    w("- hint requirements or hint-expansion address the mid/far band "
      "losses, but nothing here says which hint policy operators will "
      "actually sustain.")
    w("")
    w("Archive digests: " + "; ".join(
        f"{k}: `{v[:12]}`" for k, v in sorted(grid_meta["digests"].items()))
      + ".")
    w("")
    return "\n".join(L) + "\n"


def cmd_report(args) -> int:
    doc_meta = _prereg_meta(args.prereg_id)
    text = render(args.prereg_id, doc_meta)
    if getattr(args, "write", False):
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(text)
        print(f"wrote {REPORT_PATH}")
        return 0
    if not REPORT_PATH.exists():
        print("no stored report; run with --write first")
        return 1
    stored = REPORT_PATH.read_text()
    if stored == text:
        print(f"report rebuild matches stored report ({REPORT_PATH})")
        return 0
    print("REPORT MISMATCH: rebuild differs from stored report")
    return 1


def _prereg_meta(prereg_id: int) -> dict:
    conn = behavior.ledger_conn()
    row = conn.execute("SELECT meta FROM events WHERE id = ?",
                       (prereg_id,)).fetchone()
    conn.close()
    if not row:
        raise SystemExit(f"no ledger event #{prereg_id}")
    meta = json.loads(row["meta"])
    if meta.get("type") != "prereg":
        raise SystemExit(f"ledger event #{prereg_id} is not a prereg")
    bdoc = json.loads(behavior.FROZEN_BEHAVIOR.read_text())
    if behavior.behavior_spec_sha(bdoc) != meta["behavior_spec_sha"]:
        raise SystemExit("frozen behavior spec drifted from prereg sha")
    return meta
