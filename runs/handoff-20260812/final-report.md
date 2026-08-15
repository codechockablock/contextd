# Cognitive Checkpoint/Restore — Final Mission Report

2026-08-12 → 08-13 · commits `b76d358`→`c2622a6` · ledger events #41823–#42258
· 13 preregistered experiments · rendered version:
https://claude.ai/code/artifact/<artifact-id-redacted>

## Verdict

A model can die and the work survives. A fresh model resuming from a
~520-token compiled checkpoint matched the full-transcript ceiling (1.00)
and outscored the continuous session it replaced (0.92) on the staged
interrupted-implementation task — code finished, dialogue-only constraints
passed via holdout tests, rejected alternative recited. Sonnet and Codex
(genuine cross-vendor) resumed from the same haiku-written checkpoint at
1.00. Continuity gap ≤ 0.

## Shipped

`ctx checkpoint [--mode distill]`: frozen views (truncated archive copies —
the future mechanically absent; what made every experiment honest) + the
stratified context compiler (raw tail / reconciled episode notes / operator
notes / task recall / live repo state, every line anchored) + the distilled
OBJECTIVE/STATE/DECISIONS/REJECTED/OPEN/NEXT mode, anchor-verified,
`ctx why`-walkable. The checkpoint is a view for resumption; the archive
stays canonical.

## Benchmark headlines

- Staged (exp #41823): checkpoint_distilled 1.00 @ 522 tok; same-size naive
  summary 0.93 (lost the decision knowledge); continuous 0.92. Preregistered
  instrument observations both proved out (repo TODO leak; continuous
  under-recitation).
- Cross (#41853): sonnet/codex 1.00 from the haiku checkpoint — compatibility
  evidence (codex no-history also 1.00; easy task at high tiers).
- History (#41864 @ #41485, #41905 @ #41586): every contextd arm beat
  no-history at the design floor; 0/96 resurrections of the rejected ranker;
  checkpoints most stable across cutoffs (naive summary swung 0.92→0.33).
  Interactive MCP resume 0.88 @ 5–20k metered tokens.
- Ablations (#41939/#41949): DECISIONS/REJECTED load-bearing (−0.35);
  anchor-strip effect did not replicate — anchors buy inspectability, not
  lexical score.

## The open-loops series (the one measured gap)

next_check ([41376]/[41379]: old, unresolved, lexically far from the hint)
stayed 0.00 across all 8 arms of #41905. Seven follow-ups:

| mechanism | report | verdict |
|---|---|---|
| lexical deferral-density stratum | #42011 | not earned — density finds boilerplate |
| retro structural extraction | #42067 | not earned — closure narratives mask undischarged items |
| live open/discharge tracking | #42123 | not earned — no episode boundary in continuous work; openness observer-relative |
| board externalization | #42163 | endpoint failed; Δ +0.21 secondary; provenance held over 12 rewrites |
| board replication (total primary) | #42199 | not replicated — baseline regression; capture ≈0.5 × use ≈0.4 ≈ 0.2 |
| operator explicitness | #42221 | CONFIRMED 5/5 (p=0.0079); +0.30 total; specificity holds; wrong note free |
| third-cutoff board rep | #42256 | retirement stands; baseline aces post-completion cutoffs alone |

## The recommendation (measured, not asserted)

    ctx note "board: <the thing> [event-id]"

at the moment something goes on your mental board. P(thread survives model
death): ≈0.2 by inference, 1.0 by that sentence. Salience follows
provenance: identical content used ~2/5 from a board lane, 5/5 as a
deliberate operator note.

## Open, honestly

Real forgetting vs suppression (#41373 axes); the P2c serving-format
experiment; embeddings still deferred pending a documented lexical failure.
The admission rule fired eight times this mission without an exception.

Receipts: `experiments/handoff/bench.py report <exp_id>` rebuilds any report
from the ledger alone; `ctx verify` — chain intact at 42,262 events;
full narrative with warts in `notes.md` beside this file.
