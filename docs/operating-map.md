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
- **Owning session:** Claude Code (Fable 5), worktree `/Users/joseph/ctx-b`,
  branch `lineage-drift-audit` (goal prompt: mission-b-lineage-drift.md)
- **State:** done — ready for review/merge. Gauge + calibrated audit shipped;
  calibration verdict **AUDIT EARNED** (prereg #76, held-out 150/150 bars
  passed, quantitative-shift ceiling 1.00); live baseline measured (29 notes,
  all depth 1, 38/38 anchors); first live audit ran (7 advisory verdicts);
  183/250 dispatches used. Report: runs/lineage-audit-2026-08-13/.
  Note: mission's `actor='mcp'` filter didn't match the live archive
  (notes carry client names); audit uses the provenance_class boundary —
  surfaced in the final report, not silently adapted.
- **Blockers:** —
- **Last update:** 2026-08-13 — mission complete, gates green (185 pytest,
  smoke, ruff, network grep 3)

### restore-firedrill
- **Objective:** Weekly restore drill with behavioral-equivalence battery and
  a tested alarm path, multi-GB scale trial with cliff-hunting, expanded
  adversarial bundle corpus.
- **Owning session:** Claude Code, branch `restore-firedrill`
  (goal prompt: mission-c-restore-firedrill.md)
- **State:** handoff — prompt ready, not yet launched
- **Blockers:** same instruments-merge precondition; 8 GB tier needs local
  disk headroom (environment-limited fallback is in the prompt)
- **Last update:** 2026-08-13 — chartered

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
