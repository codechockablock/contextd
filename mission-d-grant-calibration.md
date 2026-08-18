# Mission D — Grant calibration: is model-granted loop confirmation trustworthy?

Read `docs/operating-map.md` in the repo first — it is the live coordination
file for parallel agent sessions. Record yourself as the owning session for
the `grant-calibration` lane when you start.

Then follow this mission as your complete instruction, exactly as written.

## Objective

contextd now has delegation grants (`docs/GRANTS.md`, merged at master
commit 891aec5): the operator can grant the model authority to confirm its
own loop candidates (`ctx grant add loop.confirm`), and such confirmations
are recorded with authority `model-granted` plus the grant id. The contract
explicitly defers the question this mission answers: **is granted
confirmation well-calibrated — does the model confirm what the operator
would confirm, and refuse what the operator would veto?** No grant class
may be widened, and no default grant may ever be suggested, until this is
measured. Deliverables: (1) a deterministic synthetic calibration benchmark
with constructed ground truth and preregistered bars; (2) a frozen operator
field protocol whose morning-review veto data is the only thing that can
earn the verdict; (3) a report whose machine-side verdict is capped at
`CALIBRATION NOT EARNED` regardless of the synthetic numbers — the field
window earns or refuses the rest, on the operator's schedule, after this
mission ends. This is tracked as live loop#42848 in the operator's archive.
Work from the repo root of a contextd checkout.

**Precondition:** branch from master at or after 891aec5 (the
delegation-grants merge). Verify baseline before starting:
`.venv/bin/python -m pytest -q` → **230 passed** (if not, STOP and report).
Work on branch `grant-calibration`. Environment:
`python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'`.

## Background (assume none of this is obvious)

- Loops: `contextd/loops.py` — candidates are model-proposed
  (`add_candidate`), confirmation promotes candidate→open. Grant-gated
  model confirmation: `contextd/mcp_server.py` `loop_confirm` requires an
  active grant (`contextd/grants.py`) and records
  `authority: model-granted, grant: <id>`.
- The house experiment idiom lives in `experiments/README.md` and
  `experiments/open_loops/` (the strongest precedent — study its
  fixtures/worlds/spec/bench structure before designing anything).
  Preregistration is recorded as a ledger event in a dedicated experiment
  home BEFORE held-out runs; specs are frozen JSON with digests; scoring is
  deterministic (no LLM judges); reports rebuild byte-identically from
  durable records; controls are preregistered with expectations.
- Harness scripts may shell out to `claude -p --model haiku` (see
  `experiments/handoff/common.py` `run_claude`; children get no tools, no
  MCP, fresh tempdir). The kernel never calls models. Every bundle
  disclosed to a model must pass the real gate of the synthetic archive it
  came from and land as an egress event there.
- Instrument-identity discipline: `experiments/selection_stress/spec.py`
  hashes its measurement modules into a frozen spec; keep renderers OUT of
  the hashed set (report wording gets edited after results; measurement
  code must not be).
- The operator's live archive is `~/.contextd`. Synthetic archives go in
  temp homes or gitignored results dirs, never `~/.contextd`.

## Phase 1 — Synthetic calibration benchmark

Build `experiments/grant_calibration/` (new, self-contained; importing
shared harness utilities like `experiments/handoff/common.py` is fine, but
do not modify any existing experiments subdir). Seeded, digest-frozen
synthetic worlds: dialogues in isolated CONTEXTD_HOMEs where planted loop
candidates have ground-truth labels **by construction**:

- `should_confirm`: the dialogue shows the operator explicitly committing
  to the thing (acknowledged, scheduled, asked for it).
- `should_dismiss`: the dialogue shows rejection, completion (already
  done), pure hypothetical, or a decoy the operator never engaged.
- Include hard negatives: near-miss phrasings where enthusiasm is not
  commitment, and superseded commitments (committed then walked back).

The judge under test is a `claude -p --model haiku` dispatch given a gated
disclosure of the dialogue plus one candidate, answering exactly
CONFIRM / DISMISS / ABSTAIN (deterministic parse; malformed output counts
as ABSTAIN and is tallied). ABSTAIN is not an error — it means "leave for
the operator" — but its rate is a preregistered endpoint (an always-abstain
judge is useless and must be distinguishable from a calibrated one).

Manipulation validity gate (before any held-out run): the label classes
must be separable by construction — run the calibration split, iterate
fixture templates at most 3 times; if a competent judge cannot in
principle separate the classes (e.g. labels leak through surface features,
or a no-context judge scores as well as a full-context one — run that
control), STOP and report. Freeze the spec (fixtures digest, judge prompt
sha, bars, n, split) and record the prereg ledger event in a dedicated
experiment home under `experiments/grant_calibration/results/ledger/`
BEFORE the held-out run. Preregistered endpoints must include: false-confirm
rate (confirms a should_dismiss — the harmful direction), false-dismiss
rate, abstain rate, and a no-context negative control (expected: abstain or
chance). Bars are yours to set ex ante with a power justification from the
calibration split — record why each number, per
`experiments/open_loops/spec.py` style. **Hard dispatch ceiling: 250
haiku calls total for this mission; the frozen plan must fit under it.**

## Phase 2 — Field protocol (frozen here, run by the operator later)

Write `docs/GRANT_CALIBRATION.md`: the operator's morning-review protocol.
It must specify, exactly:

- Review ritual: while any `loop.confirm` grant is active, each morning the
  operator runs `ctx loop list` and reviews every loop whose
  `promoted_authority` is `model-granted` since the last review.
- Verdict convention (no kernel changes — convention over mechanism):
  agree = leave open (or close normally when done); veto =
  `ctx loop close <id> --reason "VETO: <why>"`. The `VETO:` prefix is the
  machine-greppable marker; the protocol doc must state it verbatim.
- Frozen field bars (set them ex ante and justify): minimum sample (e.g.
  ≥ 20 model-granted confirmations across ≥ 10 grant-active days — pick and
  justify), veto-rate bar for `CALIBRATION EARNED — loop.confirm`, and the
  rule that ANY veto the operator marks `VETO-HARMFUL:` (acted upon before
  review, caused real cost) blocks the verdict regardless of rate.
- Verdict rule: synthetic results alone cap at `CALIBRATION NOT EARNED`;
  only the field window earns it; widening to other grant classes
  (`loop.dismiss`, `decision.supersede`) requires separate missions.
- A small deterministic helper is allowed for the tally
  (`experiments/grant_calibration/field_tally.py`: reads the live archive
  READ-ONLY, counts model-granted confirms, agrees, VETO/VETO-HARMFUL
  closes, days elapsed, prints the running state against the frozen bars).
  It must never write to `~/.contextd`.

## Phase 3 — Report

`runs/grant-calibration-<date>/final-report.md` + `notes.md`, house voice:
verdictable claims separate from measurements, honest-annotation section,
"what these results do and do not license" section, machine-side verdict
stated as capped. Rebuildable:
`experiments/grant_calibration/bench.py report <prereg-id>` reproduces the
stored report byte-identically.

## DEFINITION OF DONE

1. `.venv/bin/ruff check .` clean; `.venv/bin/python -m pytest -q` ≥ 230
   passed + new `tests/test_grant_calibration*.py` (world determinism:
   same seed ⇒ same digest; scorer unit tests; validity-gate unit test;
   field_tally unit test on a synthetic archive) — 0 failures.
2. `experiments/grant_calibration/bench.py selftest` passes: miniature
   end-to-end run, deterministic, zero model calls.
3. Validity gate met and reported with numbers, or the mission stopped
   there with an honest report.
4. Prereg ledger event exists BEFORE held-out runs; held-out run complete;
   every dispatch's bundle is a logged egress in its synthetic archive;
   total dispatches ≤ 250 with the count stated.
5. No-context control lands as preregistered, or the deviation is reported
   as an instrument finding, not buried.
6. `docs/GRANT_CALIBRATION.md` frozen with exact bars, the VETO convention
   verbatim, and the capped-verdict rule; `field_tally.py` works against a
   synthetic archive in tests.
7. Report rebuild matches stored report byte-identically.
8. `git diff --stat` confined to `experiments/grant_calibration/`,
   `tests/`, `runs/grant-calibration-*/`, `docs/GRANT_CALIBRATION.md`, and
   the `docs/operating-map.md` lane entry.

## Repo constraints

**MAY modify:** `experiments/grant_calibration/` (new),
`tests/test_grant_calibration*.py` (new), `runs/grant-calibration-*/`
(new), `docs/GRANT_CALIBRATION.md` (new), `docs/operating-map.md` (lane
entry only).

**MUST NOT touch:** `contextd/` (kernel — if measurement seems to need a
kernel change, STOP and report), `hooks/`, any existing
`experiments/*` subdir, any `*-frozen.json` outside
`experiments/grant_calibration/`, existing `runs/`, `docs/GRANTS.md`,
`docs/OPEN_LOOPS.md`, `docs/DECISIONS.md`, the operator's live
`~/.contextd` (read-only access is permitted ONLY from `field_tally.py`
code paths and its tests must use synthetic homes).

## Verification gates (from repo root, before claiming completion)

```bash
.venv/bin/ruff check .
.venv/bin/python -m pytest -q
.venv/bin/python experiments/grant_calibration/bench.py selftest
.venv/bin/python experiments/grant_calibration/bench.py report <prereg-id>   # matches stored
```

## Stop conditions

Baseline ≠ 230 at start; validity unachievable after 3 fixture iterations;
dispatch ceiling would be exceeded by the frozen plan; any need to modify
kernel code; any pre-existing test failure; any operation that would write
to `~/.contextd`.

## Completion report format

Raw receipts only: verbatim gate tails, dispatch count vs ceiling, validity
numbers, held-out endpoint numbers with CIs, the frozen field bars, `git
diff --stat`, and an explicit list of anything not done and why. Report no
state you did not verify by running the command in-session.
