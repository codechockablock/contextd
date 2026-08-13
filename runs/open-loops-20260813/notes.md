# Open loops / prospective state — mission run log (2026-08-13)

Mission: `/Users/joseph/.codex/visualizations/2026/08/13/019ff978-670f-76d1-94d4-9dac3ba027b5/open-loops-claude-code-mission.md`
Orchestrator: Claude Code (Fable 5), autonomous session.

## Phase 1 — audit (verified vs unavailable)

Starting state: clean `master` @ `da6b5f5` — exactly the mission's expected
start. `ctx verify`: chain intact, 42315 events. Baseline gates green:
`ruff check .` clean, `pytest -q` 100 passed.

### Verified against the cited artifacts

- `experiments/results/handoff-r2-ranker-verdict-exp41905/report.json`
  L237-248: `next_check` rates are raw_tail **0.25**, recall **0.25**, and
  0.0 for the other six arms. The prose claim "stayed 0.00 across all 8
  arms" (`runs/handoff-20260812/final-report.md:46`) is therefore an
  overstatement; the accurate baseline is **not reliably recovered**. The
  frozen report and run log are evidence and stay unedited; the correction
  lands in `docs/OPEN_LOOPS.md` and README.
- `runs/handoff-20260812/notes.md` L210-224: three retired inference
  mechanisms (lexical markers #42011, retro extraction #42067, live
  open/discharge #42123) plus the board externalization trial (#42127/#42163,
  replications #42168/#42240): primary endpoint failed. Shared missing datum:
  the operator's prioritization, never externalized pre-cutoff.
- `experiments/results/handoff-opnote-exp42203/report.json`: one simulated
  explicit operator note moved next_check 0/5 -> 5/5 (p=0.0079); wrong-note
  control stayed 0/5; total +0.30 (p=0.0317). Licenses an explicit/confirmed
  state channel only; caveats recorded in `not_licensed`.
- `contextd/cli.py` L56-61 + `contextd/handoff.py` L185-242: production has
  generic `ctx note` and a newest-first human-note stratum at 15% of budget —
  the crowd-out mechanism is real. No loop entity, reducer, scope, or
  lifecycle commands exist.
- `contextd/db.py`: append-only enforced by SQLite triggers (no UPDATE/DELETE),
  witness+recovery journal, `append_event`/`append_event_checked` the only
  write paths, `InjectedCrash` fault hook for deterministic crash tests.
- `contextd/mcp_server.py`: four tools; server-enforced allowlist (registry
  omission, not client filtering); `CONTEXTD_CLIENT` is attribution not
  authentication; `CONTEXTD_DERIVATION_SOURCE` gives kernel-verified
  note-to-disclosure binding (anchors checked against the egress item list).
- `tests/test_model_egress_inventory.py`: every non-test subprocess call site
  must be classified; archive-bearing model callers must `disclose(` and
  `record_dispatch_outcome(`. New harness code must register there.
- Experiment discipline (contextd/experiment.py + experiments/handoff/*):
  preregistration as a ledger event before any run; content-NULL
  family-tagged records (never enter FTS); `validate_rubric` known-answer
  fixtures; exact permutation test + `p_floor`; frozen views for honest
  cutoffs; `run_claude` with `--no-session-persistence`, `--setting-sources
  ""`, `--strict-mcp-config`, tempdir cwd (zero hidden continuity). Synthetic
  `claude -p` runs under this pattern persist no transcripts, so the
  staged-session contamination protocol is not triggered.

### Repository identity in dialogue events (scoping ground truth)

`claude_code/message` events carry meta `role`, `session_id`, `visited_unix`
— **no repository identity in the append-only record**. The mutable
`cursors` table keys (`claude_code:<project-slug>/<session>.jsonl`, 252
distinct slugs) encode the transcript directory name, which is a Claude Code
path convention outside the event chain. Consequence adopted for the design:
**loop scope is declared at the loop event's creation** (CLI flag, cwd git
root, or the harness's repo argument). Historical dialogue events are never
retro-scoped; source anchors point at dialogue events for provenance, but
scope authority comes from the declaring act.

### Claude Code hook capabilities (capture-moment surface)

- `~/.claude/settings.json` (read-only inspection): **no hooks configured**;
  no `~/.claude/hooks` directory. No UserPromptSubmit/Stop hook exists that
  could mechanically capture an operator utterance at the moment it happens.
- Mission forbids editing personal Claude settings; repo-local
  `.claude/settings.local.json` holds only a permissions allow for
  `ctx audit`. Installing hooks there would alter the operator's interactive
  sessions — out of scope; recorded as a capability gap, not fabricated.
- Available capture surfaces, verified: (1) human CLI (`ctx note` today,
  `ctx loop ...` after this mission); (2) the contextd MCP server in the
  operator's sessions (the four production tools are connected in this very
  session); (3) the watch daemon's transcript ingestion (~120s scan), which
  lands operator utterances as `role=user` dialogue events — usable as
  after-the-fact mechanical evidence that specific words were uttered at a
  specific archive position, with ingestion lag as a documented failure mode.

### Other verified facts

- No `AGENTS.md` or `CLAUDE.md` exists in the repo (mission said to read
  AGENTS.md; recorded as absent).
- `.gitignore` excludes `runs/` and `experiments/results/`; the prior
  mission force-added its `final-report.md`/`notes.md`. Reports remain
  rebuildable from ledger events, raw artifacts stay local.
- Live archive has 3 human notes today; crowd-out is mechanically real
  (15% x 4000-token default = ~600 tokens for the whole stratum) even if not
  yet acute in production.
- `hooks/checkpoint_compile.py` distill prompt already asks for an OPEN
  section; the raw compiler is the deterministic carriage path this mission
  must extend.
- Cross-vendor runner (`run_codex`) exists for genuinely-distinct-model
  claims if needed.

## Decisions taken at audit exit

1. Correction target for the overstatement: `docs/OPEN_LOOPS.md` (+ README
   wording), never the frozen evidence files.
2. Scope is declared, not inferred (see above).
3. No Claude Code hook installation; capture = CLI + gated MCP tools, with
   the ingested-utterance binding as the only mechanical post-candidate
   confirmation evidence available on this install.
4. Experiment artifacts: code + frozen fixtures/spec committed under
   `experiments/open_loops/`; raw run records under
   `experiments/open_loops/results/` (gitignored, mirroring convention);
   durable record in the live ledger via public append paths.

## Phase 2 — contract frozen + assumption audit

`docs/OPEN_LOOPS.md` written: authority boundary (operator / model /
operator_via_model with utterance binding), five-state transition table with
idempotent no-ops and explicit refusals, declared-scope rule, dedicated
checkpoint section with loud overflow, harness-only candidate generation,
threat model, refusal list, seven separated eval endpoints, CLI/MCP surface.

Assumption-checker pass (trigger: prereg/endpoint finalization) findings:
1. MOST DANGEROUS: model-run wiring for the NEW MCP tool name unverified in
   this session -> run the repo's read-only wiring probe BEFORE
   preregistration (void-at-birth defense).
2. Anchor-integrity collision caught against tests/test_handoff.py:130 —
   loop ids must join the checkpoint egress items list; source refs render
   non-bracketed. Contract corrected.
3. Daemon liveness for the utterance binding: verify ingestion recency
   read-only before claiming the path usable; CLI fallback holds regardless.
4. Policy constants (12-char quote min, 15% slice, min 200, oldest-first)
   labeled policy-under-test in the contract.
5. Byte-identical-pair scoring defined for a nondeterministic generator: no
   run may assert beyond candidate/uncertain (mechanical + textual bar).
6. Capture/burden matching rule to be frozen mechanically in the bench spec
   (planted anchor-phrase containment) before any run.
7. Retry-dedupe boundary (post-terminal retry creates a fresh loop)
   documented, not hidden.
8. Value-if-false: every branch survives its hypothesis failing.

Implementation priority protects the licensed core: lifecycle+carriage
first, binding second, autonomous capture last.

## Phase 3 — instrument: fixtures, scorer, calibration, frozen spec

Order of construction (discipline record): 36 dialogue fixtures written
FIRST (24 must-capture across 4 shapes x 3 projects, 6 distractor, 4 null,
1 byte-identical pair) — before any generator prompt exists, so held-out
wording cannot leak into prompt tuning. Stratified seeded split: 16
calibration / 20 held-out (12 held-out must-capture plants, 18 scorable
held-out dialogues; pair is evaluation-only). Scorer (scoring.py) with the
frozen matching rule passed 13 known-answer tests including the honest-null
(silent mechanism earns nothing, costs nothing) and the pair discipline.

Synthetic calibration (calibrate.py, seeded, rebuildable):
- capture: bar 10/12 (0.8333). Coin-flip regime (0.5, the prior series'
  measured capture) passes with p=0.0193; a 0.95 mechanism flips 0.0196.
  Separating 0.5 from 0.9 would need n=13; at n=12 a true-0.9 mechanism
  under-credits with p~0.11 — the conservative direction. Recorded.
- burden: bar 1.0 false candidate/dialogue; quiet regime passes 1.0, noisy
  (lambda 2) passes 0.0003.
- use: 4 worlds x 2 crossed arms, stratified permutation; n=4/arm/world
  gives power 0.953 vs (0.25, 0.9) regimes, null FPR 0.01. Regimes are the
  measured #41905 raw-tail rate and the #42203 explicit-channel rate.
- false promotion bar: 0.

spec.py frozen with fixture digest + split + bars; sha recorded at prereg.
Deviation note: lifecycle implementation (Phase 4) proceeds next because
worlds/bench pipeline checks require it; no model call happens before
preregistration, and every bar above was fixed before any implementation
result existed.

## Phase 4+5 — lifecycle, carriage, MCP surface, generator (all deterministic gates green)

- contextd/loops.py: event-sourced reducer (kind='loop', meta.op), frozen
  transition table, per-scope dedupe, anomaly-safe replay, utterance
  binding verifier, loop-section selector with loud overflow.
- CLI `ctx loop add/list/show/close/reopen/candidates/confirm/dismiss`;
  refusals nonzero, retries no-op silently, add promotes a matching pending
  candidate as an operator confirm.
- handoff.py: ACTIVE OPEN LOOPS as first archive section; reserved slice
  (15%/min 200) with under-fill overflow to tail; loop ids join the egress
  items list; omitted ids named in-package and in egress meta.
- hooks/checkpoint_compile.py distill mode re-attaches the raw section
  verbatim (carriage never depends on the distiller).
- MCP: loop_candidate/loop_list (gated read)/loop_confirm/loop_dismiss —
  the last two only under the post-candidate utterance binding; registry
  allowlist extended; openclaw config untouched and pinned by test.
- hooks/loop_scan.py: gated+receipted generator, loop_candidate-only grant,
  derivation-bound anchors, scope pinned via env, dispatch outcomes
  recorded; silence is an explicit uncertainty channel.
- Tests: test_loops.py (14) incl. crash-retry both sides of durability and
  the byte-identical-dialogue reduction; backup/restore loop survival; MCP
  capability tests prove candidate-only grants cannot promote. Full suite
  130 passed; ruff clean; smoke OK.

## Pre-prereg probes (calibration split only)

- Wiring probe: claude -p (haiku) reached mcp__contextd__loop_candidate
  under --strict-mcp-config against a scratch world: succeeded, 1 candidate
  on a 1-plant fixture. The assumption-checker's most-dangerous assumption
  is discharged.
- Calibration pilot (7 fixtures, one per shape): 4/4 must-capture captured,
  burden 0.0, distractor hits 0; musing/completed/null all silent.
  PROMPT frozen as written — zero tuning iterations needed or taken.

## Preregistration and run (Phase 6)

- Prereg: live event #42331 (spec 5b95ed44..., prompt 5fbc7eef...,
  use worlds cf-amber-1 / cf-gauge-2 / cm-amber-1 / cm-gauge-2). Recorded
  BEFORE any held-out run; wiring probe and 7-fixture calibration pilot ran
  before prereg, on the calibration split only.
- Capture endpoint executed: 20/20 held-out scans dispatch-succeeded,
  14 candidates total (scoring deferred to the report builder).
- Use endpoint: 4 worlds x 2 arms x 4 runs, mechanical carriage
  preconditions verified per arm before each model run.

## Mid-run code review (medium, 8 angles inline)

Six findings, all fixed and re-gated (131 tests, ruff, smoke, selftest):
1. build_report could vacuously PASS false-promotion/pair when artifacts
   were missing -> evidence now comes from ledger loops_summary, falls back
   to artifacts, and refuses (explicit evidence-missing failure) otherwise.
   For run #42331 (recorded pre-fix) the artifacts are the evidence source.
2. Dedupe TOCTOU: creation now re-checks under the witness/append lock
   (_DuplicateRace), so racing same-key writers cannot fork duplicates.
3. Selftest read hardcoded bars; now reads the live frozen spec.
4. Duplicate omit branches merged in select_loop_section.
5. Dead `useful` set removed from score_capture.
6. `ctx loop` argparse layer added to tests/smoke.py (section 42).
Plus: tests/test_loop_scan_gate.py pins the scanner's receipted payload,
failure/timeout observability, dismissed-board disclosure, and
skip-without-disclosure on empty dialogue.

## Phase 6 results (prereg #42331, report #42390) and Phase 7 close-out

- capture 11/12 (bar 10/12) — machine-side pass; the miss is a frozen
  matching-rule artifact (candidate quoted the operator's ack verbatim,
  lacked one term drawn from the assistant's wording); stands as scored.
- false promotion 0/0; burden 0.167 (3 false candidates, 2 of them
  end-of-session imperatives with unrecorded execution); distractor hits 0.
- identical pair: scanner silent on BOTH byte-identical elements — pass.
- use: 0.75 vs 0.00, stratified perm p=0.0001; per-world 4,4,3,1 of 4;
  weak world autopsy: all four outputs discussed the loop (one leads STILL
  OPEN with "loop#6, urgent"), three paraphrased past the substring
  indicator — endpoint stands, annotation recorded with receipts.
- 52/52 dispatches succeeded; report rebuilds from durable records and
  matches the stored report event.
- VERDICT: NOT EARNED (operator trial pending by preregistered rule).
- docs/OPEN_LOOPS.md measured results + limitations filled; README
  corrected (overstatement fixed, loops section added); final-report.md
  written; operator protocol frozen in the contract doc and presented.
