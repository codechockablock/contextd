# Decision supersession: making stale resurrection structurally loud

Contract r2, 2026-08-14. Revision history:

- **r1** (frozen before implementation; committed at 6a94488, sha16
  `cfbc676af854afce`): unconditional reserve; bar 4 as a flat per-cell
  cap. Round-1 contrast (prereg #253, outcome #254 in the experiment
  ledger): bars 1 and 3 met decisively (silent resurrection 0/405;
  resurrection 0.269 → 0.000); bar 2 failed on 1/405 — diagnosed as an
  instrument artifact (the scorer's block extractor split on anchor
  citations of v1's id; the kernel was verified compliant on the flagged
  row); bar 4 failed with one cell at Δ0.6 — diagnosed as the
  unconditional reserve taxing every compile once any edge exists. **Fix
  not declared**, per the frozen rule.
- **r2** (this document): two-pass selection so only compiles that owe
  work pay the reserve; scorer block extraction anchored on the header
  form; bar 4 split into 4a/4b/4c with the unpaid/taxed distinction the
  two-pass design makes measurable. Bars 1–3 and 5 unchanged. Re-frozen
  and re-preregistered before the round-2 run; no round-2 data existed
  when these bars were set.

Contract r1 was frozen before implementation. The evaluation bars in
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
   carried, the chain's current version must also be carried. Selection is
   **two-pass** (r2): the strata are packed reserve-free first; only when
   that selection carries a chain whose current version is missing does
   selection re-run with a supersession reserve (6% of budget, min 120
   est. tokens) subtracted before the strata shares, from which owed
   current versions are packed into a dedicated package section, oldest
   carried id first. A compile that owes nothing pays nothing — its
   selection is identical to the no-edges selection (r1 subtracted the
   reserve unconditionally, and the round-1 contrast measured the tax:
   marginal recall items lost carriage in cells that owed no work). Any
   owed current version that does not fit is named: `SUPERSESSION
   OMITTED: current version ev <id> of carried ev <id> — run 'ctx
   recall'`. Silent resurrection of a *recorded* chain is thereby
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
4. **Non-regression** (r2 formulation; see revision history):
   - **4a** pooled carried rate over non-supersession cells differs by
     ≤ 0.02 absolute between arms;
   - **4b** zero *unpaid* losses: in row-pairs where the lifecycle
     compile did **not** engage the reserve, its selection is identical
     to the baseline's by construction, so any lost carriage there is a
     mechanism defect — structural bar, 0;
   - **4c** among row-pairs where the reserve **was** engaged, pooled
     carried-rate loss ≤ 0.10 — justified ex ante: the reserve diverts
     6% of budget, so same-order marginal loss is the expected price of
     carrying the current version; materially more indicates displacement
     beyond the reserve's size.
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

## Addendum 2026-08-15: grant-gated supersession (docs/GRANTS.md)

The authority statement above ("there is deliberately no model-mediated
path") is amended, not retracted, the same way OPEN_LOOPS.md amended its
confirmation boundary on 2026-08-14. Nothing infers an edge from text,
recency, or anything else — that refusal stands. What exists now is the
explicit delegation mechanism: the operator may record a class-level,
global-scoped, expiring, revocable grant (`ctx grant add decision.supersede
--for 8h ...`), after which the MCP `decision_supersede` tool stops
refusing — and every edge it records carries authority `model-granted` plus
the grant's event id, permanently distinguishable from an operator act.
Without an active covering grant the tool refuses exactly as before.
Model-proposed *candidate* edges (proposal, not recording) remain a
possible later mission and nothing here anticipates them.
