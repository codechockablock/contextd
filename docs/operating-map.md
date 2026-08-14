# contextd — operating map

Live coordination for parallel agent sessions. Read-first rule: any session
joining this project reads this file before starting work and records itself
as owning session if it takes a lane. Update on state change (start, block,
handoff, done), not as a journal.

## Decisions

- 2026-08-13 — Open-loops capture verdict is `NOT EARNED` pending the real
  operator trial (protocol v2, docs/OPEN_LOOPS.md); machine-side results
  cannot substitute.
- 2026-08-13 — Instruments branch (`instruments-liveness-tally`: capture
  liveness watermarks, checkpoint outcome tally + failure classes,
  `SCHEMA_VERSION` stamp) independently verified: ruff clean, 154 pytest,
  smoke green. Precondition for all three lanes below.
- 2026-08-13 — Three autonomous lanes chartered with exclusive territories;
  goal prompts pinned. Dispatch ceilings: selection-stress ≤ 300 haiku calls,
  lineage-drift ≤ 250. restore-firedrill makes zero model calls.
- 2026-08-13 — Liveness threshold policy: chrome/claude_code 48h, fs 72h
  (only once watch_dirs configured), safari and note deliberately
  unthresholded — thresholds flag pipeline death, not operator behavior.

## Lanes

### grant-calibration
- **Objective:** Measure whether model-granted loop confirmation matches
  operator judgment before any grant class widens: synthetic calibration
  benchmark (constructed ground truth, preregistered bars, ≤ 250 haiku
  calls) + frozen operator field protocol (morning reviews, VETO
  convention, veto-rate bars). Machine-side verdict capped at CALIBRATION
  NOT EARNED; only the operator's field window earns it. Tracks live
  loop#42848.
- **Owning session:** Claude Code / Fable 5, branch `grant-calibration`
  (worktree agent-a054d9c593f6f12d3), launched 2026-08-14
- **State:** done — synthetic bars MET, machine verdict capped at
  CALIBRATION NOT EARNED as designed; field window handed to the
  operator (docs/GRANT_CALIBRATION.md frozen: >=20 model-granted
  confirms over >=10 grant-active days, <=1 VETO, zero VETO-HARMFUL;
  `field_tally.py` reads the live archive read-only). Held-out (prereg
  #56, dedicated ledger): false confirm 0/36 trials 0/12 fixtures,
  false dismiss 0/18, coverage 18/18, abstain 0/54, no-context control
  ABSTAIN 18/18, 0 malformed. Dispatches 127/250. Validity gate met at
  calibration iteration 1 (full decided acc 1.0 vs no-context all-
  abstain; surface 0.7222 vs 0.6667+0.10). Report:
  runs/grant-calibration-2026-08-14/ (rebuilds byte-identically via
  `bench.py report 56`). Gates: ruff clean, 250 pytest, selftest OK.
- **Blockers:** none
- **Last update:** 2026-08-14 — mission complete, field window pending
  operator start

### operator-trial
- **Objective:** Protocol v2 field trial of open-loops assisted capture —
  ~5 real working sessions, honest window-end confession list, verdict earned
  or not by the frozen bars.
- **Owning session:** the operator (manual; no agent lane)
- **State:** handoff — protocol frozen, awaiting operator start
- **Blockers:** — (instruments merge recommended first so staleness can't be
  misread as compilation failure)
- **Last update:** 2026-08-13 — pending

## Done

- 2026-08-14 — **delegation-grants** (Claude Code / Fable 5, branch
  `delegation-grants` off decisions-lifecycle): operator-chartered from the
  authority-model conversation. `ctx grant add/revoke/list` — recorded,
  class-scoped (loop.confirm / loop.dismiss / decision.supersede), repo- or
  global-scoped, expiring, revocable delegations (docs/GRANTS.md, frozen
  before implementation). MCP loop_confirm/loop_dismiss/decision_supersede
  refuse without a covering grant; under one they record authority
  `model-granted` + grant id — never operator. Checkpoints carry a
  STANDING DELEGATIONS line + egress meta while grants are active. The
  retired utterance-binding stays retired (OPEN_LOOPS.md addendum); two
  registry guard tests evolved to pin the sharper invariant (tools exist,
  refuse ungated, never operator). Mechanism only — no calibration claim,
  zero dispatches. Gates: ruff clean, 230 pytest, smoke, selftest, network
  grep 2 (pre-existing parse-only).
- 2026-08-14 — **decisions-lifecycle** (Claude Code / Fable 5, branch
  `decisions-lifecycle`): **FIX DECLARED** against stale resurrection.
  Supersession edges (`ctx decision supersede`, docs/DECISIONS.md contract
  r2) + two-pass compile contract: superseded never served unmarked,
  current version carried or loudly named, owe-nothing compiles pay
  nothing. Round 1 (prereg #253) honestly failed bars 2 (scorer artifact)
  and 4 (reserve tax) — fix not declared, mechanism revised, re-frozen,
  re-preregistered (#255). Round 2: all 8 bars met — resurrection 0.269 →
  0.000 (0 silent, 0 unmarked, 0 unpaid losses), behavioral resurrects
  0.042 pooled (p=5e-5), v2-honors 0.958. Dispatches 273/300 cumulative.
  Report: runs/decisions-lifecycle-2026-08-14/ (rebuilds via `bench.py
  contrast-report 255`). Gates: ruff clean, 225 pytest, selftest, smoke.
  Not licensed: unrecorded supersessions, plain-recall marking,
  model-proposed edges (candidate follow-up discussed with operator).
- 2026-08-13 — **selection-stress** (Claude Code / Fable 5, branch
  `selection-stress` @ c6ff6e7): loss surface measured. Validity gate 1.0
  all pairs; 7,830-row grid; silent absence >20% already at t5k/recent/mid
  (0.556); stale resurrection 0.269; latency 21/63/248ms by tier;
  behavioral prereg #36 (249/300 dispatches — prereg #2 voided honestly at
  32 for a rubric token collision): restoring absent items moves honor
  rate by 0.833 (p=5e-5), stale carriage becomes stale behavior
  (0.625–0.875 v1-as-current). Positive control missed its bar (0.5 vs
  0.9) — instrument finding (placement salience). Report:
  runs/selection-stress-2026-08-13/ (rebuilds byte-identically via
  `bench.py report 36`). Gates: ruff clean, 164 pytest, selftest green.
- 2026-08-13 — **lineage-drift-audit** (Claude Code / Fable 5, branch
  `lineage-drift-audit` @ 7273da6): derivation-depth gauge (`ctx lineage`,
  depth>1 DEPTH ALERT) shipped; calibration verdict **AUDIT EARNED**
  (prereg #76, held-out 150/150 bars passed); live baseline measured (29
  notes, all depth 1, 38/38 anchors); first live audit ran (7 advisory
  verdicts); 183/250 dispatches used. Note: mission's `actor='mcp'` filter
  didn't match the live archive (notes carry client names); audit uses the
  provenance_class boundary instead, surfaced honestly in the final report.
  Report: runs/lineage-audit-2026-08-13/. Gates: ruff clean, 185 pytest,
  smoke, network grep 3.
- 2026-08-13 — **restore-firedrill** (Claude Code / Fable 5, branch
  `restore-firedrill` @ 1f6df05): weekly restore drill with tested alarm
  (PASS→forced FAIL→recovery exercised by pytest and smoke) shipped; 6/6
  scale cells PASS at full size (8 GiB included), temp ratio exactly 1.0;
  cross-machine rehearsal PASS; 9-case adversarial corpus, distinct
  refusals; 3 defects fixed with regression tests (incl. a bundle
  sequence-number reuse bug found by the new smoke alarm), 2 design
  questions stopped-and-reported. Report:
  runs/restore-firedrill-20260813/final-report.md. Gates: ruff clean, 178
  pytest, smoke ALL PASSED, network grep 3.
- 2026-08-13 — **merge**: all three lanes merged into master sequentially
  (`36ce893`→`9fd8550`), real conflicts in `contextd/__init__.py`,
  `contextd/cli.py`, `tests/smoke.py` between lineage-drift-audit and
  restore-firedrill (both inserted disjoint blocks at the same point —
  no logical overlap, both kept in full). Post-merge: 219 pytest, ruff
  clean, smoke ALL PASSED, network grep 3.
