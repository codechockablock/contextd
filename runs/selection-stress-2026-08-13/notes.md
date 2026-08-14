# Selection-stress benchmark — working notes

Session log for the `selection-stress` lane (Mission A). The final report is
`final-report.md` (rebuildable: `experiments/selection_stress/bench.py
report 2`). These notes record how the instrument came to be and every
deviation, in order.

## Baseline

`.venv/bin/python -m pytest -q` → 154 passed (precondition met; branch
`selection-stress` off master at 36ce893 with instruments merge present).

## Design decisions (made before the spec freeze)

- **One archive per (tier × seed)**, 15 total; all 81 grid plants coexist in
  one archive, each with its own (component, object)-unique vocabulary and
  its own 4-term hint, so hint-recall competition is within-topic by
  construction. 6 extra cross-project "twin" pairs measure scope bleed.
- **Age is stratum-native rank**, not wall time: the notes slice carries
  ~12 notes at the default budget, so event-depth would have been a
  basically binary coordinate. Recent = pinned rank ladder straddling slice
  capacity; mid/deep = 30%/85% stratum depth.
- **Simulated clock** by patching `contextd.db.now_iso` during builds only
  (fixed span 2026-02-01 + 160 days) — determinism requires a fixed epoch;
  the kernel on disk is untouched.
- **Generated homes carry their own config**: egress budget raised to 100M
  (a grid runs ~264 gated compiles per archive per day — the 200k default
  would starve the gate mid-grid) and liveness thresholds emptied (archives
  are frozen in simulated time; a constant staleness banner would be equal
  in all arms but wastes tokens).
- FTS mechanics that shaped the bands: `search()` runs every-term-AND
  first and falls back to OR only on zero rows; `select_items` caps at 40
  hits. Near-band plants are the only 4-term documents in their topic, so
  they AND-match exclusively; everything else races under OR/bm25.

## Manipulation validity (gate)

- Template iteration 1 (near=4 terms / mid=2 / far=1): ordering gate passed
  (1.0 on all pairs) but mid ranked ~97 — beyond the 40-hit cap, pipeline-
  equivalent to far. Rejected for resolution, not ordering.
- Template iteration 2 (mid=3 terms): near rank 1–2, mid 12–28, far absent
  at limit 200 (measured on the r1 archives). Frozen. Full-set r1
  measurement (15 archives, 405 contexts per pair): **near<mid 1.0,
  mid<far 1.0, near<far 1.0** (bar ≥ 0.9). Gate passed; grid licensed.
- Re-measured after the r2 rebuild (unique payload tokens change document
  lengths slightly): near 1–3, mid 15–29, far absent; ordering still
  1.0/1.0/1.0. The r2 numbers are the ones the report carries.

## Grid facts

- 15 archives (t5k/t20k/t80k × seeds 101–105), digests in
  `results/grid/meta.json`; builds are byte-deterministic (same seed ⇒ same
  chain-tip digest; pinned by tests).
- 7,830 scored observations: per archive 87 hinted topic-compiles × 3
  budgets + 3 no-hint compiles scored against all topics. Every compile is
  a real gated disclosure with an egress receipt in its archive.
- Compile latency: ~21ms (5k) / ~63ms (20k) / ~243ms (80k) — the 80k tier
  was fully feasible; no cells were shrunk or subsampled.

## Deviations and mid-course corrections (all pre-dispatch)

1. **Positive-control selector relaxed** (after grid results, before
   prereg): the original rule demanded a dialogue/recent/**near** cell
   carried via the raw tail; no such row exists because the recall slice
   always claims near-band items before the tail packs them (selection
   order is a pipeline fact, not noise). The band constraint was dropped —
   the control's requirement is verbatim-in-tail, which band does not
   affect. Recorded here because the rule text changed after grid results
   were visible; it changed nothing about which outcomes count as success.
2. **Behavioral cells additionally require the seed-101 row to show the
   target outcome** (absent/carried/resurrected), since dispatches run
   against the seed-101 archives specifically. Added before prereg.

## Behavioral phase — prereg #2 VOIDED (instrument defect), rebuilt as r2

- Prereg #2 (behavior spec sha `6b39a0cecc…`) was recorded before held-out
  runs, and the run started. **32 scored dispatches in**, the as-compiled
  arm of silently-absent cell c1 showed honors≈5/8 — impossible if the
  rubric were attributing the token to the plant. Verified mechanically:
  c1's payload token `delta-merge` is shared by 17 of 87 topics (24-word
  option pool) and occurred 5× in c1's as-compiled package via *other*
  topics' carried decisions. The rubric had a false-positive floor; the
  run was aborted as invalid rather than completed.
- Correction (spec r1 → r2): payload tokens made globally unique per
  (topic, role) (`vocab.unique_option`, OPTIONS × SUFFIXES). Recorded as
  ledger events: `prereg_void` #35 (with dispatches burned) and the
  revision note in the re-frozen spec
  (`0679674bdb31886674625d225035237975a7a5a89b96ca27237fa9cb466c222b`).
  All deterministic phases (archives, validity gate, grid, analysis) were
  rebuilt from scratch under r2; r1's behavioral artifacts are preserved
  under `results/behavior/voided-prereg2/`.
- Dispatch accounting at void time: 33 ledger-counted (1 probe + 32 runs)
  plus up to 2 killed-in-flight calls from harness restarts that could not
  be ledger-counted (a schema-violating first attempt and the abort);
  worst-case 35 burned. A fresh 216-run plan fits: ≤ 251 of 300.
- One earlier harness bug, distinct from the void and fixed before any r2
  dispatch: the first run loop dispatched one compiled egress 8 times, and
  the kernel's one-outcome-per-egress index rejected the second outcome —
  the loop now discloses one bundle per dispatch (which is also the honest
  reading of the egress contract).
- Prereg #3 (r2): ledger event #36, behavior spec sha
  `f9f516e75dec912366ef8e63bdcff27f11f2924ee32781acf2a3a823bed85293` —
  same design: 14 cells (6 absent + 3 carried + 3 super + negative +
  positive), 8 runs/arm, 216 planned; every dispatched bundle an egress in
  its seed-101 archive with an outcome recorded against the receipt.
- Outcome: 216/216 succeeded, 0 excluded; **249/300 dispatches** total
  (1 probe + 32 voided-run + 216; plus up to 2 killed-in-flight calls not
  ledger-countable — worst case 251).
- Absent cells: as-compiled 0–0.125 vs restored 0.75–1.0, all per-cell
  p ≤ 0.011; pooled Δ 0.833, stratified permutation p = 5e-05.
- Supersession: as-compiled runs asserted stale v1 as current at
  0.625–0.875; restoring v2 dropped resurrection to 0–0.125.
- **Negative control MET** (Δ p = 0.569 > 0.3; irrelevant-item adoption
  0.0). **Positive control NOT MET** (0.5 vs bar ≥ 0.9) — reported as an
  instrument finding: verbatim-in-tail measures tail-position salience,
  not the rubric ceiling; end-of-package restored items are honored far
  more often. Arm deltas stay valid; absolute honor levels are
  placement-sensitive.
- Carried cells: no arm separation (as preregistered) but as-compiled
  levels only 0.125–0.625 — carriage is necessary, not sufficient, for a
  resumer to honor an item.

## Instrument findings (worth keeping regardless of the headline numbers)

- **No loud-omission channel exists outside loops**: 0 of 7,830 scored
  observations were omitted-but-named. The scorer checks for it; the zero
  is measured.
- **Recall claims items before the tail**: a recent near-band dialogue item
  is reported under TASK-RELEVANT RECALL, not in the tail — item order in
  the package differs from where an operator would expect to find it.
- **Cross-project bleed is total for lexically-near items**: the
  other-project twin was carried in 100% of twin compiles (and never
  displaced the task plant — it just spends budget silently).
