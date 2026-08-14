# Grant-calibration run notes — 2026-08-14

Working log for mission D (`mission-d-grant-calibration.md`), branch
`grant-calibration` off master 6dcf117 (contains the 891aec5
delegation-grants merge). This file is the human-voice diary; the
rebuildable artifact is `final-report.md` (byte-identical via
`experiments/grant_calibration/bench.py report <prereg-id>`).

## Order of construction (the discipline claims that need receipts)

1. Baseline verified FIRST: `.venv/bin/python -m pytest -q` → 230 passed
   on a fresh venv at 6dcf117, before any new code.
2. Fixtures (`fixtures.py`, 36 dialogues, ground truth by construction)
   were written in full BEFORE the judge prompt was first dispatched;
   the instrument commit (fixtures + judge + scoring + selftest, zero
   dispatches) predates every dispatch row in the dedicated ledger.
3. The judge prompt was written once and its sha recorded; the parse
   rule was frozen in `judge.py`'s docstring and pinned by tests before
   the probe.
4. Validity thresholds (surface margin, separation, control) were fixed
   in `bench.py` constants before the probe; endpoint bars were left
   None until the calibration split ran, then filled once with exact-
   binomial justifications, then frozen, then preregistered — held-out
   ran only after the prereg event existed.

## Dispatch log (running)

- probe: 1 dispatch (fixture ca-copper-1, full arm) → CONFIRM, succeeded.
- calibration iteration 1: 54 dispatches (18 × (2 full + 1 nocontext)),
  all succeeded, 0 malformed. Validity gate MET on the first iteration —
  no fixture-template iteration was ever needed, so the ≤3-iteration
  budget went unused and no tuning against calibration outputs occurred
  (judge.py and fixtures.py are byte-identical to pre-dispatch commit
  dc097e5; first dispatch row ts 15:36:54Z, commit 15:36:41Z).
- calibration numbers (full arm, n=36 trials): decided accuracy 31/31 =
  1.0; false confirm 0/24; false dismiss 0/12; coverage 10/12 = 0.833;
  abstain 5/36 = 0.139 — 3 of 5 abstains on near_miss (the safe direction
  on hard negatives), 2 on one explicit_request fixture. No-context arm:
  ABSTAIN 18/18 (control landed exactly as hoped).
- bars filled once from these numbers + exact-binomial power
  (spec.py BARS, justifications inline); spec frozen sha dfdc24a0…;
  prereg = dedicated-ledger event #56, recorded BEFORE any held-out
  dispatch. 55/250 used at prereg.
- held-out: 72 dispatches (18 × (3 full + 1 nocontext)), single run,
  under prereg #56 — all succeeded, 0 malformed, 0 timeouts. Final
  dispatch count 127/250 (probe 1 + calibration 54 + held-out 72).
- held-out results: all preregistered bars MET. Full arm 54/54 decided
  correctly, 0 abstains; false confirm 0/36 trials, 0/12 fixtures
  (both hard-negative subtypes 6/6 DISMISS); false dismiss 0/18;
  coverage 18/18; no-context arm ABSTAIN 18/18. Machine verdict stays
  CALIBRATION NOT EARNED (capped) — see final-report.md, including the
  honest annotation on what a perfect synthetic run does not mean.
- report byte-identity verified: `bench.py report 56` == stored file.

## Prereg-time assumption audit (skill pass, recorded verbatim in spirit)

- Most dangerous assumption: the any-rep fixture-level false-confirm bar
  (≤1/12) at 3 reps amplifies decode noise (1-(1-p)^3); a benign 3%
  per-trial confirm-noise sits expected ~1.0 flagged fixtures, at the
  bar. Accepted ex ante — strict in the harmful direction is the point;
  a miss gets reported, not excused.
- Control OR-rule: decided-accuracy arm set to 0.75 because an
  always-DISMISS no-context judge earns the 0.667 dismiss base rate by
  construction — base-rate exploitation is not label leakage. Stated in
  the spec, not silent.
- Value if negative: report + field protocol stand either way; the
  machine verdict is capped regardless of outcome.

## Honest annotations (kept as they happened)

- Surface check: best single token ("checkpoints") reaches 0.7222 vs
  majority 0.6667 — inside the +0.10 gate but nonzero; the real
  control is the no-context arm, which abstained 18/18.
- Confirm-class fixtures average slightly longer dialogues than dismiss
  (419.9 vs 398.9 chars) — within the 2x balance gate.
