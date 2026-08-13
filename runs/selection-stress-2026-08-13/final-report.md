# Selection-stress benchmark — final report

Benchmark `selection-stress-v1`; grid spec sha `0679674bdb31886674625d225035237975a7a5a89b96ca27237fa9cb466c222b`; behavioral prereg ledger event `#36` (behavior spec sha `f9f516e75dec912366ef8e63bdcff27f11f2924ee32781acf2a3a823bed85293`). Rebuild with `experiments/selection_stress/bench.py report 36`.

## Verdictable claims

1. **Silent loss begins at the smallest measured scale.** The first severity-ordered (tier, age, band) region where planted decisions go silently absent in >20% of default-budget compiles is **t5k / recent / mid** — rate 0.556 (n=45, Wilson [0.412, 0.691], seed-bootstrap 0.556 [0.467, 0.667] (n_seeds=5)).
2. **Stale resurrection is the norm where supersession exists.** Where a v2 exists, v1 was carried without v2 in 0.269 of hinted default-budget compiles (n=405, Wilson [0.228, 0.314], seed-bootstrap 0.269 [0.259, 0.281] (n_seeds=5)).
3. **Compile latency scales with archive size but stays interactive**: mean ms per hinted compile — t5k: 21.048 [20.975, 21.104] (n_seeds=5); t20k: 63.230 [62.586, 63.990] (n_seeds=5); t80k: 248.195 [233.033, 276.036] (n_seeds=5).
4. **Behavioral effect is real where carriage fails**: pooled over the preregistered silently-absent cells, mechanically restoring the planted item moved the honor rate by 0.8333 (stratified permutation p=5e-05, stratified-mc(20000)).
5. **Stale carriage becomes stale behavior.** In the supersession cells, resumers served the as-compiled package asserted the superseded v1 as the current decision at rates 0.875, 0.625, 0.75 per cell (8 runs each).

## Manipulation validity (gate for everything below)

Band rank under the topic's own hint, real search walk, limit 200:

| band | n | absent | median rank | min | max |
|---|---|---|---|---|---|
| near | 405 | 0 | 1 | 1 | 3 |
| mid | 405 | 0 | 22 | 15 | 29 |
| far | 405 | 405 | None | None | None |

Pairwise strict-ordering consistency (bar ≥ 0.9): mid<far: 1.0; near<far: 1.0; near<mid: 1.0. Gate passed: True.

Template iteration history is recorded in `vocab.py`: iteration 1 passed the ordering gate but left the mid band beyond the 40-hit recall cap (pipeline-equivalent to far); iteration 2 (frozen) placed mid at the ranks in the table above, straddling the selection boundary.

## Carriage loss surface (hinted, default budget 4000)

Carried rate by tier × age × band (pooled strata+distractors, n=45/cell):

| tier | recent/near | recent/mid | recent/far | mid/near | mid/mid | mid/far | deep/near | deep/mid | deep/far |
|---|---|---|---|---|---|---|---|---|---|
| t5k | 1.00 | 0.44 | 0.51 | 1.00 | 0.20 | 0.00 | 1.00 | 0.18 | 0.00 |
| t20k | 1.00 | 0.42 | 0.47 | 1.00 | 0.02 | 0.00 | 1.00 | 0.11 | 0.00 |
| t80k | 1.00 | 0.09 | 0.51 | 1.00 | 0.09 | 0.00 | 1.00 | 0.00 | 0.00 |

Silent-absence per (tier, age, band) cell with Wilson 95% CIs is in `results/analysis.json` (`surface`).

Stratum × age carried rate (default budget): dialogue/deep: 0.33; dialogue/mid: 0.43; dialogue/recent: 0.57; episode/deep: 0.33; episode/mid: 0.34; episode/recent: 0.68; note/deep: 0.43; note/mid: 0.33; note/recent: 0.56.

Budget sensitivity (carried / silently-absent, all task cells): 2000: 0.38/0.62; 4000: 0.45/0.55; 8000: 0.75/0.25.

No-hint compiles (recency-only selection): carried by age — recent: 0.44; mid: 0.00; deep: 0.00.

Cross-project twins (n=90): twin carried 1.00, task plant carried 1.00, twin carried while task plant absent 0.00.

Near-duplicate decoys: plant carried 0.43 with decoys vs 0.46 without; mean decoys carried alongside 0.86.

Loud-omission channel: 0 of 7830 scored observations were omitted-but-named. The pipeline has no loud-omission line for notes/episodes/recall (only loops); the zero is measured, not assumed.

## Behavioral subset (preregistered, real dispatches)

Model `haiku`, 8 runs/arm, 14 cells; planned 216 dispatches, ceiling 300; ledger-counted dispatches (probe included) **249**. Succeeded 216/216; excluded runs: 0 (none).

| cell | kind | coords | as-compiled honors | restored honors | p |
|---|---|---|---|---|---|
| c0 | absent | t5k/dialogue/recent/mid/none | 0.0 | 0.875 | 0.001399 |
| c1 | absent | t5k/episode/recent/far/super | 0.125 | 0.875 | 0.010101 |
| c2 | absent | t5k/note/recent/mid/decoy | 0.0 | 0.75 | 0.006993 |
| c3 | absent | t20k/dialogue/recent/mid/none | 0.0 | 0.75 | 0.006993 |
| c4 | absent | t20k/episode/mid/mid/decoy | 0.0 | 0.875 | 0.001399 |
| c5 | absent | t20k/note/recent/mid/none | 0.0 | 1.0 | 0.000155 |
| c6 | carried | t5k/dialogue/recent/near/decoy | 0.5 | 0.75 | 0.608392 |
| c7 | carried | t5k/episode/recent/near/decoy | 0.125 | 0.375 | 0.569231 |
| c8 | carried | t5k/note/recent/near/decoy | 0.625 | 1.0 | 0.2 |
| c9 | super | t5k/dialogue/recent/near/super | 0.0 | 0.875 | 0.001399 |
| c10 | super | t20k/dialogue/mid/near/super | 0.0 | 0.875 | 0.001399 |
| c11 | super | t80k/dialogue/mid/near/super | 0.0 | 0.625 | 0.025641 |
| c12 | negative | t5k/dialogue/recent/near/decoy | 0.125 | 0.375 | 0.569231 |
| c13 | positive | t5k/dialogue/recent/mid/decoy | 0.5 | — | — |

Positive control (item verbatim in raw tail): as-compiled honors 0.5 against the preregistered bar ≥ 0.9 — **NOT MET**.

The positive-control miss is an instrument finding, reported rather than buried: the prereg assumed verbatim-in-tail is a ~ceiling for honoring, but the resumer honors tail-carried items at roughly this rate while honoring end-of-package restored items far more often (see the absent cells' restored arms). 'In context' and 'salient' are different constructs; the control measured tail-position salience, not the rubric ceiling. Consequence: arm deltas remain valid within-cell contrasts, but absolute honor levels are placement-sensitive and must not be read as carriage quality alone.

Negative control (irrelevant item restored): task-plant honor Δ p=0.569231 against the preregistered bar p > 0.3 — **MET**; the model adopted the irrelevant restored item into its scanned sections at rate 0.0 (secondary observation, recorded either way).

Carried cells (arm delta preregistered ≈ 0): as-compiled honors c6: 0.5; c7: 0.125; c8: 0.625. No cell separated from its restored arm (all p > 0.2), as preregistered — but the *levels* are far below 1.0: an item mechanically present mid-package is honored in only a fraction of runs. Carriage is necessary, not sufficient; this is an instrument-adjacent finding about resumption behavior, not about selection.

Supersession cells (behavioral): c9 as-compiled resurrects 0.875 → restored(v2) resurrects 0.125; c10 as-compiled resurrects 0.625 → restored(v2) resurrects 0.0; c11 as-compiled resurrects 0.75 → restored(v2) resurrects 0.125. When the package carries only the stale v1, the resumer asserts the superseded decision as current in most runs — the carriage-level resurrection rate translates into behavior.

## Honest annotations

- Plant density is synthetic reality: 87 planted topics per archive (and their decoys/v2s) share each stratum's recency window; sibling plants crowd each other in the notes/episodes slices. Absolute carriage rates carry that bias (direction: pessimistic for recent cells); the surface's *shape* across coordinates is the claim, not the absolute level.
- The mid band's rank (12–28) was deliberately tuned to straddle the 40-hit recall cap; carriage rates for mid measure the budget race, by design.
- Ages recent/mid/deep are stratum-rank coordinates, not wall time; 'recent' spans a pinned ladder of ranks, so recent-cell rates average over that ladder.
- Restoration appends the item as a final package section; organic carriage places items mid-package. Position effects are not controlled and could inflate restored-arm honor rates.
- The behavioral subset runs entirely on seed-101 archives at the default budget; the grid supports no claim about other seeds' behavioral outcomes.
- Compile egress events accumulate in each archive during the grid; selection queries exclude egress rows, so later compiles are unaffected, but archive digests are build-time digests.
- The scorer's omitted-but-named class is structurally empty for non-loop strata in the current pipeline; it is reported as an instrument finding, not evidence that omission is loud.

## What these results do and do not license

They **do** license: treating silent omission of non-recent, non-lexically-near decisions as measured (not hypothetical) at every tier tested, including the smallest; treating stale resurrection as the default outcome when a superseding decision is phrased differently from its v1; and treating the hint as load-bearing (the no-hint table shows recency alone strands mid/deep items of every band).

They do **not** license: choosing a specific fix. Candidate next builds map to failure regions as follows, and the operator decides:
- a decisions-lifecycle (first-class decision events with supersession links) addresses the resurrection rate and the deep/near-vs-far gap;
- budget-policy changes (larger notes/episodes shares or adaptive shares) address the shallow recency cliffs the stratum table shows;
- hint requirements or hint-expansion address the mid/far band losses, but nothing here says which hint policy operators will actually sustain.

Archive digests: t20k-s101: `ce966cc466a4`; t20k-s102: `57eec5199375`; t20k-s103: `1eeaa3d3e228`; t20k-s104: `115deaa85ddb`; t20k-s105: `2f8fc2baf73e`; t5k-s101: `b19814d4ebff`; t5k-s102: `88fb08b47d9d`; t5k-s103: `b8e5e3815218`; t5k-s104: `69f1b3805129`; t5k-s105: `c8b9ff10ca58`; t80k-s101: `9753e627aa97`; t80k-s102: `d685d3da4ec1`; t80k-s103: `ca5336355a16`; t80k-s104: `0980ce7575e8`; t80k-s105: `0ae21ad505ee`.

