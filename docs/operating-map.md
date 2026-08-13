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

### selection-stress
- **Objective:** Measure the loss surface of checkpoint compilation — planted
  load-bearing items across archive size × age × lexical distance ×
  distractors; deterministic carriage grid + preregistered behavioral subset.
- **Owning session:** Claude Code, branch `selection-stress`
  (goal prompt: mission-a-selection-stress.md)
- **State:** handoff — prompt ready, not yet launched
- **Blockers:** `instruments-liveness-tally` merged to master (lane verifies
  154-test baseline at start)
- **Last update:** 2026-08-13 — chartered

### lineage-drift-audit
- **Objective:** Deterministic derivation-depth gauge (`ctx lineage`, depth>1
  alert) + judge-calibrated sampled fidelity audit of model-written notes,
  advisory-only, `AUDIT NOT EARNED` shipped honestly if calibration bars miss.
- **Owning session:** Claude Code, branch `lineage-drift-audit`
  (goal prompt: mission-b-lineage-drift.md)
- **State:** handoff — prompt ready, not yet launched
- **Blockers:** same instruments-merge precondition
- **Last update:** 2026-08-13 — chartered

### restore-firedrill
- **Objective:** Weekly restore drill with behavioral-equivalence battery and
  a tested alarm path, multi-GB scale trial with cliff-hunting, expanded
  adversarial bundle corpus.
- **Owning session:** Claude Code (Fable 5), worktree `/Users/joseph/ctx-c`,
  branch `restore-firedrill` (goal prompt: mission-c-restore-firedrill.md)
- **State:** done — branch ready for review/merge. Drill + tested alarm +
  status line shipped; 6/6 scale cells PASS at full size (8 GiB included)
  with temp ratio exactly 1.0 (preflight pinned 1.5×); cross-machine
  rehearsal PASS; 9-case adversarial corpus, distinct refusals; 3 defects
  fixed with regression tests (incl. a kernel retention/ordering bug found
  by the new smoke alarm), 2 design questions stopped-and-reported. Gates:
  ruff clean, 178 pytest, smoke ALL PASSED, network grep 3. Report:
  runs/restore-firedrill-20260813/final-report.md
- **Blockers:** — (launchd plist install is an operator act, post-merge)
- **Last update:** 2026-08-13 — mission complete on branch

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

(empty — finished lanes move here with a one-line outcome)
