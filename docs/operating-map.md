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
