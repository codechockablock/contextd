# Decisions-lifecycle — working notes

Session log for the `decisions-lifecycle` lane, chartered by the operator
2026-08-14 after reading the three mission reports. Charter constraints:
pick the single most expensive failure under the thesis; preserve the
measurement discipline (silent omission measurable, loud omission required
where claimed); no fix declared without a preregistered contrast moving the
surface. Final report: `final-report.md` (rebuildable:
`experiments/selection_stress/bench.py contrast-report 255`).

## Failure selection

Stale resurrection, over silent absence, because absence degrades the
resumer to ignorance while resurrection hands it a confidently wrong
current-state claim carrying archive provenance — measured behaviorally at
0.625–0.875 v1-asserted-as-current. The other failure regions (recency
cliffs, hint losses) are held by the two open loops the operator added and
were deliberately not touched.

## Order of work

1. Baseline on master post-merge: 219 passed.
2. Contract `docs/DECISIONS.md` frozen **before** implementation
   (loops-precedent order), including all evaluation bars.
3. Kernel: `contextd/decisions.py` (edges, reduction, anomalies),
   compile contract in `handoff.py`, `ctx decision` CLI, 6 tests → 225.
4. Contrast harness added to the selection-stress instrument **without
   touching its r2-frozen modules** (new `contrast.py`; renderer kept in
   unhashed `report_contrast.py` — a Mission-A lesson: report wording gets
   edited after results, measurement code must not be).
5. Lifecycle worlds = digest-verified copies of r2 baseline worlds + one
   operator edge per planted pair via the real `record_supersession` path.

## Round 1 (prereg #253 → outcome #254): fix NOT declared

- Bars 1, 3 met decisively (silent resurrection 0/405; 0.269 → 0.000).
- Bar 2 failed 1/405: **instrument artifact** — the block extractor split
  on the first bare `[id]`, which matches episode-note anchor citations;
  the kernel was verified compliant on the flagged row (marker present in
  the true block). 4 affected rows across all budgets.
- Bar 4 failed with one cell at Δ0.6 (t20k/note/deep/mid/none, lost recall
  carriage in 3/5 seeds): **real mechanism cost** — the r1 reserve was
  subtracted unconditionally once any edge existed, taxing every compile.
- Per the frozen rule the fix was not declared. Behavioral dispatches were
  gated on carriage bars, so round 1 spent zero.

## Revision r2 (before any round-2 data)

- Mechanism: two-pass selection — reserve-free first; reserve engaged only
  when a carried chain's current version is owed. Owe-nothing compiles are
  byte-identical to baseline selection, which makes "unpaid loss" a
  structural zero and lets the bars separate the tax from defects.
- Scorer: header-anchored block extraction (`--- [id]`).
- Bar 4 → 4a pooled ≤ 0.02 / 4b unpaid = 0 (structural) / 4c taxed ≤ 0.10
  (ex ante: the price of a 6% reserve). Contract revision history in
  DECISIONS.md; re-frozen, re-preregistered as ledger event #255.

## Round 2 (prereg #255): all bars MET — fix declared

- Kernel regression gate: 7,830 rescored baseline rows, 0 mismatches
  against stored r2 rows (two-pass on edge-less archives is the identity).
- Carriage: silent resurrection 0/405; unmarked served 0/405; resurrection
  0.269 → 0.000 (seed-bootstrap degenerate at 0); pooled non-super delta
  0.0; unpaid losses 0; 51 taxed pairs, planted-item delta 0.0.
- Behavioral (24 dispatches, lifecycle as-compiled vs prereg #36 baseline
  as-compiled, reuse preregistered): resurrects 0.875/0.625/0.75 →
  0/0/0.125 per cell, pooled 0.042 (bar ≤ 0.3), stratified p = 5e-05;
  v2-honors 0 → 1.0/1.0/0.875, pooled 0.958 (bar ≥ 0.5).
- Dispatch ceiling: cumulative selection-stress total **273/300**
  (249 from Mission A + 24 here; round 1 spent none).

## Deviations, in order

1. Round-1 scorer artifact and reserve tax (above) — led to r2, not
   patched silently.
2. Post-run aggregation fix: after all 24 round-2 dispatches completed and
   were scored at dispatch time, `behavioral_baseline_runs` crashed on
   prereg #36's row key names (`dispatch_status`/`i` vs `status`/`run`).
   Reader-only fix; recorded as ledger harness note #280 with the
   post-fix module sha. The prereg-time `_check_prereg` live-sha guard
   would now refuse a fresh `contrast-behavior` invocation by design;
   aggregation ran directly against the stored rows.

## Instrument findings worth keeping

- The kernel-regression gate earned its place: it proved arm comparability
  by identity rather than assumption, and it is what made the round-1
  bar-4 failure attributable to the reserve rather than to noise.
- Episode-note anchor citations are a standing hazard for any package-text
  scorer that greps bare `[id]`; header-anchored extraction is the rule.
- The reserve tax was invisible to the pooled statistic (0.0086) and
  dramatic at one cell (0.6) — per-cell bars catch what pooled bars
  cannot, and are worth the false-alarm risk they carry.
