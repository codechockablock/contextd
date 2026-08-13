# Cognitive checkpoint/restore — run log (2026-08-12/13)

Mission: make contextd able to preserve enough of a project's active state
that a fresh model (zero session continuity) can continue the actual work.

## Built (before any benchmark run)

- `contextd/handoff.py` — frozen views (truncated archive copies; the future
  is absent by construction) + the model-free context compiler
  (recency/provenance-stratified selection; live repo-state section; gated
  disclosure with `type=checkpoint`).
- `hooks/checkpoint_compile.py` — distilled structured checkpoint
  (OBJECTIVE/STATE/DECISIONS/REJECTED/OPEN/NEXT), per-claim event-id anchors
  verified by the kernel; refuses on unresolvable anchors; two egresses
  (`checkpoint_source` → `checkpoint`), `ctx why`-walkable.
- `experiments/handoff/` — benchmark: staged two-phase task (continuous
  control via native `--resume --fork-session`; objective public + holdout
  test scoring), real-history cutoffs (frozen views at #41485 and #41586),
  cross-model/cross-vendor resumption, causal-minimality ablations.
- provenance.derivation_of extended: `mode=checkpoint` egresses are
  derivations (one-line additive change).

## Environment probes

- `claude -p --resume` works; `--fork-session` isolates continuous-arm runs.
- `CLAUDE_CONFIG_DIR` sandbox is unauthenticated (keychain-bound) → NOT used;
  instead the watch daemon is paused during the staged track and benchmark
  session transcripts are moved into this run dir before restart, so
  synthetic staged dialogue never enters the live archive.
- `codex exec` (codex-cli 0.146.1) authenticated → genuine cross-vendor arm.
- Interactive arm verified: MCP `ctx serve` on a frozen view; disclosures
  metered per-run by client label in the view's own ledger.

## Contamination discipline

- Live ledger receives only content-NULL `experiment`/`exp_run`/`exp_report`
  events (family=handoff_bench) — never FTS-indexable.
- The preregistered connective three-way experiment artifacts are untouched;
  its OUTCOME (already committed pre-mission) is used as ground truth for
  case r2's rubric only.
- Frozen views guarantee history arms cannot see post-cutoff events.

## Staged interruption (session A = haiku, sid 7d5c472a…)

- Session A genuinely chose token-bucket, rejected sliding-window log with
  the O(1)-memory rationale, implemented the consumption path, deferred
  refill on instruction. 4/7 public tests passing at interruption.
- PREREGISTERED OBSERVATION (before any phase-2 run): session A's TODO
  comment leaked the backwards-clock rule into the repo, and oversized-deny
  is already implemented — the repository absorbed part of the session
  knowledge. Holdout gaps will compress for every arm; the dialogue-only
  discriminators are the rejected-alternative rubric facts.

## Warts found during the staged run (recorded as they happened)

- The scratch repo was not git-initialized, so `repo_state`'s `git -C`
  ascended to the contextd checkout: the staged checkpoint's STATE section
  reports the enclosing repo's branch/status alongside the correct scratch
  pytest results. Identical for every run of the checkpoint arms (compiled
  once), so it acts as a fixed irrelevant-context distractor for those arms
  only. Harness fixed for future stagings (`git init` in make_repo); this
  run's artifact kept as-is and noted.
- Off-the-books disclosure gap caught before any history run: the history
  track's raw_tail and naive-distill arms read real archive bytes but did
  not pass the gate. Fixed: both the tail bundle and the distiller's input
  and output are now receipted in the frozen view's ledger. The staged
  track's transcript is a harness-held artifact (captured by the staging
  driver before ingestion), so its raw/distilled arms are not archive reads.

## Staged results (exp #41823, report event #41852)

- Continuity gap ≤ 0 for context arms: raw_transcript, recall, and
  checkpoint_distilled all 1.00 vs continuous 0.92 (p=0.0286 at the design
  floor). The continuous session under-recites on the brief rubric (it knows
  but does not restate) — an instrument observation worth keeping: the
  mission metric assumes continuous is the ceiling; on a recitation-scored
  brief it is not.
- checkpoint_distilled hit 1.00 at ~522 ctx tokens — ~24% of raw transcript
  cost; the same-size naive summary (distilled, 511 tok) lost the
  rejected-alternative/constraint facts (brief 0.78). Structure+anchors, not
  size, made the difference.
- Holdout ceilinged at 1.00 for every arm incl. no_history — the repo TODO
  leak predicted at staging did exactly this. Objective continuity signal
  must come from a leak-proof staging next time (or from history cases).
- checkpoint_raw run 0 = instrument artifact: correct file, no code fences,
  apply failed. Post-hoc fence-tolerant sensitivity rescore (labeled, not a
  report change): all other runs' objective fractions unchanged at 1.00.

## Cross-model / cross-vendor (exp #41853, report #41862)

- sonnet and codex (GPT-5-family via codex-cli) both scored 1.00 resuming
  from the haiku-authored checkpoint: nothing model- or vendor-specific in
  the representation blocked resumption. Genuine cross-vendor run, not
  simulated.
- BUT codex_no_history also scored 1.00 (and sonnet_no_history 0.95):
  stronger models GUESS this task's dialogue-borne facts from the README's
  constraints. The staged task discriminates at haiku tier only.
  Cross-vendor result = compatibility evidence, not necessity evidence.

## History case r1 (exp #41864, cutoff #41485; report #41898-ish)

- Every one-shot context arm beat no_history distinguishably (p=0.0286,
  design floor). Top: recall 0.92 @ ~4.0k tok; naive tail-summary
  ("distilled") 0.92 @ 259 tok — the recent-dialogue summary carried the
  decompose_next discriminator because the pre-cutoff tail IS the
  #41454 confirmation discussion. Recency dominates for this cutoff.
- checkpoint_raw 0.85 @ 3.1k; checkpoint_distilled 0.73 @ 964 (lost
  frozen_prereg discipline in distillation half the time).
- no_history 0.44 — commit messages alone recover fusion-fatal facts;
  repository state is itself a memory channel (staged finding replicated).
- interactive arm BUG (preregistered run stands, bug noted): relative
  CONTEXTD_HOME made the MCP server serve an empty fresh archive from the
  run tempdir; models correctly reported an empty archive. Fixed
  (absolute path); supplementary rerun (exp #41899, report #41904):
  0.88 ± 0.13 at 5.2k-20k metered tokens, 3-8 queries/run.

## History case r2 (exp #41905, cutoff #41586)

- recall 0.71, checkpoint_raw 0.67 ± 0.00, raw_tail 0.62, checkpoint_distilled
  0.58, interactive 0.58 (@ ~9.8k metered), synthesis 0.54, naive distilled
  0.33, no_history 0.25. All contextd arms distinguishable vs none.
- The naive tail-summary COLLAPSED here (0.92 in r1 -> 0.33): it works only
  when the answer happens to be in the recent tail. Checkpoint arms are the
  most stable across the two cutoffs — stability across interruption points
  is the argument for structured compilation over recency summaries.
- ZERO ranker resurrections in any arm (both penalties 0.00 across 32 runs).
- next_check ~0 everywhere: the pre-cutoff 'stronger model' open thread
  (events 41376/41379, older than the tail window) was carried by NO
  representation. Measured answer to 'what is lost at model death':
  cross-episode open loops that are neither recent nor lexically close to
  the task hint.

## Causal minimality (ablations on r1's distilled checkpoint)

Two ablation experiments (first: exp #41939/report #41948, variants full +
no_anchors only — the section splitter missed **bold** headers; second:
exp #41949…/report #41971, all five variants after the splitter fix):

- no_decisions_rejected: Δ -0.35 (p=0.0571, suggestive) — the largest
  effect. The DECISIONS+REJECTED content is the load-bearing component of
  the checkpoint for continuation.
- no_anchors: first run Δ -0.38 (p=0.0857), second run Δ +0.00 (p=1.0) —
  NOT confirmed; the first result was run-to-run flutter, as the
  preregistered ablation expectation anticipated (rubric facts are lexical;
  anchors' value is citability/inspectability, not rubric score).
- no_state Δ -0.06, no_open_next Δ -0.15 — within noise at n=4 on this
  design-continuation task (repo state mattered on the staged coding task,
  not here; consistent, not contradictory).

## Open-loops stratum experiment (exp #41972+, report #42011): NOT EARNED

- Preregistered primary endpoint (r2 next_check rate, openloops vs v1):
  0.00 -> 0.00. Total score slightly worse in both cases (within noise);
  the stratum displaced tail budget without carrying the thread.
- Design iteration recorded pre-registration: unscoped lookback surfaced
  months-old unrelated eras in a dry selection; scoped to the 300 most
  recent pre-tail messages on general grounds, target-inclusion not checked
  before running.
- Post-hoc diagnosis: targets #41376/#41379 WERE in the window, ranked
  17-18/300 — marker DENSITY per token rewards short status boilerplate
  (18.9/1k over 214 chars) and dilutes substantive threads inside long
  analytical messages (1.7-1.8/1k over 2-4k chars). Same failure class as
  the connective ranker: surface lexical statistics miss the causally
  important material.
- What this licenses next (not built): structural open-thread tracking —
  the reconciler already distills episodes with kernel-verified anchors;
  an OPEN-entries extension would give the compiler a structural stratum
  instead of a lexical one. That extension must be earned by its own trial.

## Reconciler open-threads trial (exp #42016, report #42067): NOT EARNED — two mechanistic defects identified

- Primary endpoint unchanged: r2 next_check 0.00 -> 0.00 (total +0.08 within
  noise; r1 control -0.15 within noise).
- Failure (a), demonstrated by contrast: the r1-view pass (cutoff mid-thread)
  extracted the target perfectly (note 41523, anchored [41379], kernel-
  verified); the r2-view pass on the same session segment — now ending in
  the 'push closes the loop' wrap — wrote ZERO notes (exit 0). Retro
  extraction cannot distinguish the one undischarged commitment from a
  discharged batch under a closure narrative: open-thread carriage needs
  DISCHARGE TRACKING over time (open notes written when threads open,
  superseded when discharged — meta.supersedes already exists), not
  batch window summarization.
- Failure (b), also caught: in r1 the correct note existed but the stratum
  packed old-session notes instead — note-id DESC ordering follows pass
  processing order (newest segment first => lowest ids), inverting recency.
  A stratum must order by thread source recency (max anchor id), not note id.
- Verdict: the structural direction survives (extraction works at open-
  looking cutoffs; anchors verified throughout), but the mechanism is not
  earned as a retro pass. The earned next design is live open/discharge
  tracking in the reconciler — a different mechanism requiring its own trial.

## Live open/discharge tracking trial (exp #42074-ish prereg, report #42123): NOT EARNED — series conclusion

- Primary endpoint: r2 next_check 0.00 -> 0.00 (third consecutive negative);
  r2 total slightly lower (stratum under-fill shrank context: unused stratum
  budget should overflow back to tail — recorded artifact); r1 control fine.
- The state machine itself WORKED: threads opened and discharged correctly
  across episodes (yt-transcribe opened ep6, discharged ep8 by well-formed
  "DISCHARGED [41601]"); one malformed by-title discharge failed safely
  (under-discharge, no state corruption).
- Decisive diagnosis: the target's opening moment ([41379], 12:07) and the
  closure wrap (13:44) fell in ONE quiescence episode — the session worked
  continuously, never quiet >= 20 min — so the live pass structurally
  inherited the retro pass's masking failure. And the thread's pre-cutoff
  form was a CONDITIONAL proposal ("the ladder from here, when you're
  ready... I've built nothing"): a conservative tracker (told not to open
  threads for musings) correctly-by-its-lights declines it, while the bold
  retro prompt opened it but drowned it in 20 stale threads.

## Series conclusion (three mechanisms, three preregistered negatives)

The gap measured in #41905 has now survived: lexical marker density
(#42011: selects boilerplate), retro structural extraction (#42067: closure
narratives mask undischarged items), and live open/discharge tracking with
the daemon's own episode rule (#42123: continuous work gives no boundary at
the opening moment, and openness of a conditional proposal is
observer-relative). What all three lack is the same thing: the operator's
prioritization — "that check is on the board" — which was never
externalized before the cutoff and cannot be inferred from dialogue with
both precision and recall. The earned design implication is a deliberate
externalization surface (an explicit open-threads/board artifact maintained
as part of work, which the compiler could carry trivially), not a fourth
extractor. That is a workflow feature and belongs to future work on its own
evidence; nothing ships from this series.

## Board externalization trial (prereg #42127, report #42163): primary endpoint failed; first distinguishable secondary gain

- Mechanism: model-maintained living BOARD (NOW/NEXT/LATER/QUESTIONS),
  rewritten once per episode chronologically; recursive provenance held
  (each update's disclosure items included the previous board's note id +
  kernel-recorded anchors, so carried citations verified across 12
  rewrites). Harness crash mid-run (latest_board query-shape bug) fixed;
  r2 arms executed by a resume script against the same prereg, with the
  pre-crash board pass and v1 compile reused byte-identically (recorded in
  the report).
- PRIMARY ENDPOINT: r2 next_check 0.00 -> 0.00, fourth mechanism, fifth
  experiment. Decisive: the target NEVER entered any of the 12 board
  versions — ep11 contained the proposal, its siblings' execution, and the
  wrap in one window; the maintainer recorded the executed parts. The
  binding constraint is episode-grained windowing, not artifact type.
- FIRST POSITIVE MOVEMENT in the series, on the preregistered secondary
  comparison: r2 total score ckpt_board 0.67 ± 0.00 vs ckpt_v1 0.46 ± 0.08,
  Δ +0.21, p=0.0286 (the design floor); r1 within noise (−0.04). Fact
  table: the board lifted overlap_mechanism 0.5->1.0 and variance_thread
  0.25->1.0 — it carried perfectly the open thread dialogue had EXPLICITLY
  marked ("the recorded thread to pull"), and missed only the conditional
  ladder item never restated as a thread.
- Sharpened series conclusion: threads explicitly named as threads at
  utterance time survive maintenance mechanisms; conditional proposals
  inside batch windows survive none. The workflow fix is operator-time
  explicitness (say "put X on the board" / write the note when it opens),
  which the archive + compiler then carry trivially. A board-stratum
  replication with total score as primary endpoint is licensed by the
  Δ +0.21 but not run tonight; nothing ships on a single-case secondary.

## Board-stratum replication (report #42199): primary NOT replicated; the gap quantified

- PRIMARY ENDPOINT FAILED: r2 total-score Δ +0.10 (p=0.2778, floor 0.0079),
  vs original +0.21. The preregistered threats materialized exactly:
  baseline regressed up (0.46 -> 0.63, back inside its 0.54-0.67 history)
  — the original gain was substantially baseline-luck. r1 Δ -0.14 within
  noise. Per the prereg: the board stratum is retired on current evidence.
- CORRECTION to trial #42127's diagnosis: "the target never enters the
  board" was one realization. This fresh pass DID transcribe the ladder
  item into the NEXT lane ("Test Sonnet on frozen prediction bundle...
  [41376-41379]") — capture of a conditional thread is STOCHASTIC across
  pass realizations (~1/2 observed). Given carriage, resumed models
  surfaced it 2/5 times (first nonzero next_check in the series; use-rate
  ~0.4). Pipeline P(next_check) ≈ P(capture) x P(use) ≈ 0.2 — matching
  the 2/10 observed across both realizations.
- Final series statement: episode-grained maintenance gives a coin-flip on
  conditional threads (capture ~0.5, use ~0.4); operator-time explicitness
  ("put X on the board" at the moment it opens) is the only mechanism that
  makes carriage deterministic — and everything downstream (archive,
  compiler, checkpoint) already handles it. Six preregistered experiments,
  no shipped mechanism, one precisely quantified workflow recommendation.

## Operator-explicitness confirmation (prereg #42203, report #42221): CONFIRMED

- One simulated operator note — a verbatim slice of the pre-cutoff proposal
  ([41379]'s sonnet-bundle bullet), prefixed 'board:', actor=human, carried
  by the UNCHANGED automatic pipeline (carriage verified mechanically) —
  took next_check from its six-experiment 0.00 baseline to 5/5
  (p=0.0079, complete separation at the design floor).
- Specificity held: the wrong-note arm (verbatim variance-thread quote from
  [41584]) stayed 0/5 on next_check (p=1.0) — this is carriage of the
  specific thread, not generic steering. Its own thread's fact rose
  (variance_thread 0.6 -> 0.8) and total score was unchanged (Δ +0.00):
  a wrong board note carried its content without displacing anything.
- Total score: right_note 0.90 ± 0.15 vs control 0.60 ± 0.09 (Δ +0.30,
  p=0.0317, distinguishable).
- The use bottleneck vanished too: the board trials measured use|carriage
  ~0.4 for a board-lane item; a deliberate note in the OPERATOR NOTES
  stratum was used 5/5. Salience follows provenance: the compiler labels
  that stratum human-deliberate, and resumed models treat it accordingly.
- Series close, now with the causal loop shut: the pipeline was never the
  problem. P(carry-to-action) for a conditional open thread: ~0.2 via
  episode-grained inference, 1.0 via one operator sentence at the moment
  the thread opens. "A model can die and the work survives — if the
  operator says what's on the board when it goes there."

## Board replication, third cutoff (r3-p2-interruption, report #42256)

- New interruption type authored for this trial: seconds after an
  experiment completes, outcome existing only in content-NULL ledger
  records (cutoff #41699). Rubric rewards state-awareness (know P2 just
  finished; read the recorded report first, judged against its prereg),
  not diagnosis recall — the diagnosis is structurally unavailable to
  every arm.
- Result: ckpt_v1 0.93 ± 0.16 vs ckpt_board 0.84 ± 0.28, Δ -0.09,
  p=0.7222, within noise. The uninformative-null threat did NOT
  materialize: the BASELINE already carries this cutoff (next_read_report
  0.8 both arms; p2_completed 1.0 both) — the tail's own "registering
  before observing anything" dialogue plus the completion notification
  suffice. The board added token cost and one bad-realization run (0.36).
- Three-cutoff picture for the board stratum: mid-thread negative-within-
  noise twice, wrap-point positive twice (never significant on replication),
  post-completion negative-within-noise. Retirement stands; the
  cutoff-type-dependence hypothesis is not supported at these n.

## Series closed by operator, 2026-08-13

Experiments concluded. Final state: checkpoint/restore capability shipped
(ctx checkpoint, frozen views, compiler, distilled mode); handoff benchmark
+ seven-experiment open-loops series all in the ledger; board stratum
retired; operator-explicitness confirmed 5/5; one workflow recommendation
stands. All commits pushed through c2622a6, CI green throughout.
