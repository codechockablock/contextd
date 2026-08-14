# Decision supersession: making stale resurrection structurally loud

Contract frozen 2026-08-14, before implementation. The evaluation bars in
this document are preregistered against the selection-stress instrument
(`experiments/selection_stress/`, spec r2) and recorded as a ledger event in
that experiment's dedicated home before any contrast run.

## The problem (measured, not hypothesized)

The selection-stress benchmark (runs/selection-stress-2026-08-13/) measured
checkpoint compilation against archives with planted supersession pairs: a
decision v1, later superseded by a v2 phrased differently. At the default
budget, **v1 was carried without v2 in 0.269 of hinted compiles** (n=405,
Wilson [0.228, 0.314]) — recency favors neither version at depth, and the
hint's lexical match favors whichever phrasing happens to sit nearer the
hint, which for a v1-near/v2-far pair is systematically the stale one.
Behaviorally, resuming models served such packages **asserted the
superseded decision as current in 0.625–0.875 of runs** per cell.

This is the most expensive failure under the thesis. The checkpoint's
authority is exactly the archive events it cites; silent omission degrades
the resumer to ignorance, but resurrection hands it a confidently wrong
current-state claim *carrying archive provenance*. Ignorance re-asks;
resurrection acts. The other measured failure regions (shallow recency
cliffs; mid/far-band hint losses) are held by open loops for separate
budget-policy and hint-policy decisions and are deliberately not touched
here.

## The mechanism

One new append-only record and one compile-time contract. Nothing else.

### Supersession edges

An operator records that event NEW supersedes event OLD:

    ctx decision supersede OLD NEW [-m reason]

This appends one event (source `decision`, kind `decision`, meta
`{op: "supersede", old, new, authority: "operator", client}`, content =
the optional reason). Validation at write time: both ids exist and are
content-bearing archive events (an egress or blob can never be a decision
version); OLD ≠ NEW; re-recording an existing edge is a no-op that appends
nothing. Current state is the reduction of edge events in id order — no
UPDATE, no DELETE, same event-sourcing rule as loops.

**Authority:** recording a supersession is a human CLI act. There is
deliberately no model-mediated path — the same boundary open loops settled:
a model may *know* about an edge only because the operator recorded it.
(Model-proposed supersession candidates are a possible later mission; they
are a non-goal here and nothing in this contract anticipates them.)

### Reduction

Edges form a directed graph old → new. The *current version* of an event X
is the terminal node reached by following edges from X. Determinism rules:
if one event has several outgoing edges, the latest edge (highest event id)
wins and earlier ones are kept as anomalies; a cycle is an anomaly — the
walk stops at the first repeated node, marks the chain `cyclic`, and the
compile contract treats every member as superseded-with-unresolvable-
current (marked, never silently served).

### The checkpoint compile contract

Enforced in `select_checkpoint_context` / `compile_checkpoint` only (the
measured surface). Two clauses, both loud:

1. **No unmarked superseded item.** Any selected item whose id has an
   outgoing supersession edge is rendered with a marker line naming the
   superseding event and the edge:
   `[SUPERSEDED by <new-id> — edge <edge-id>]`.
2. **Current version carried or named.** If any version of a chain is
   carried, the chain's current version must also be carried. When the
   archive holds at least one edge, a supersession reserve (6% of budget,
   min 120 est. tokens) is subtracted before the strata shares, and owed
   current versions are packed into a dedicated package section, oldest
   carried id first. Any owed current version that does not fit is named:
   `SUPERSESSION OMITTED: current version [<id>] of carried [<id>] — run
   'ctx recall'`. Silent resurrection of a *recorded* chain is thereby
   structurally impossible; the reserve exists so the loud line is always
   affordable (same design as the loops omission reserve).

Unrecorded supersessions — where the operator never drew the edge — remain
exactly as measured in the baseline. The mechanism does not infer edges
from text similarity, recency, or anything else; that refusal is the
authority boundary, not a limitation to be fixed later.

### Explicit non-goals

- No enforcement on the plain recall path (`ctx recall` may still serve a
  superseded event unmarked; recorded boundary, separate decision).
- No first-class decision registration, no revocation-without-replacement.
- No model-proposed edges.
- No change to strata shares or hint behavior (held by open loops).

## Evaluation (preregistered contrast; bars frozen here)

Instrument: selection-stress spec r2, extended with a `lifecycle` generator
arm — archives identical to baseline except one operator supersession edge
appended immediately after each planted v2 (27 edges per archive; new
digests recorded in the contrast spec). Both arms, full grid, all budgets,
seeds 101–105.

Endpoints and bars, in order of authority:

1. **Silent resurrection** (v1 carried, v2 absent, no marker on v1 and no
   loud line naming v2): baseline re-measured; lifecycle bar **0** — the
   contract is structural, so a single occurrence is a defect, not noise.
2. **Unmarked superseded served**: lifecycle bar **0** (same reasoning).
3. **Surface movement** (the fix-declaration gate): stale-resurrection
   rate as defined by the *baseline* scorer (v1 carried ∧ v2 not carried)
   drops from 0.269 to ≤ 0.05 in the lifecycle arm at default budget; the
   residue must consist only of loudly-named omissions (endpoint 1 = 0).
4. **Non-regression**: for non-supersession cells, pooled carried rate
   differs by ≤ 0.02 absolute between arms, and no single cell moves by
   more than 0.2 (one seed-flip at n=5). The 27 extra events per archive
   must not disturb the rest of the surface.
5. **Behavioral confirmation** (haiku, deterministic rubric unchanged from
   prereg #36): the three supersession cells of prereg #36, lifecycle-arm
   as-compiled packages, 8 runs/cell (24 dispatches). Baseline arm =
   prereg #36's as-compiled supersession runs, reused by ledger reference
   (identical archives, model, rubric, protocol). Bars: pooled
   v1-as-current rate ≤ 0.3 (baseline 0.625–0.875) with stratified
   permutation p ≤ 0.05; v2-honors pooled ≥ 0.5 (baseline 0.0). Dispatch
   ceiling: this mission adds ≤ 51 calls, keeping the cumulative
   selection-stress total ≤ 300.

If any structural bar (1, 2) fails, the mechanism is defective and the fix
is **not declared**, whatever the rates say. If bar 3 or 5 fails, the
surface did not move and the report says so. Bar 4 failing means the
instrument's arms are not comparable and the contrast is void.

## CLI surface

    ctx decision supersede OLD NEW [-m reason]   # operator act, appends edge
    ctx decision list                            # edges + anomalies
    ctx decision current <id>                    # follow chain, print terminal
