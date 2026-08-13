# Lineage topology gauge + calibrated note-drift audit — Final Mission Report

2026-08-13 · branch `lineage-drift-audit` · calibration ledger
`runs/lineage-audit-2026-08-13/calibration-home/` (prereg event #76) · live
archive events #42536–#42563 · rebuild:
`CONTEXTD_HOME=runs/lineage-audit-2026-08-13/calibration-home
.venv/bin/python experiments/lineage_calibration/calibrate.py report 76`

## Verdict

**AUDIT EARNED**, by the preregistered rule alone: on the 150-item held-out
half the judge (haiku, spec sha `b5249d9da05b…`) detected 30/30
dropped-caveat (bar ≥ 0.8), 30/30 unsupported-claim (bar ≥ 0.8), 30/30
emphasis-inversion (bar ≥ 0.7), false-alarmed 0/30 on faithful paraphrases
(bar ≤ 0.1), with 0 unparseable replies. The `quantitative-shift` honest
ceiling — no bar, reported whatever it is — came back **1.00 [0.88, 1.00]**
at this corpus's shift magnitudes. And the standing worry the gauge was
built for is now a measured number: **every model-written note in the live
archive is depth 1** — the reconciler cites raw dialogue only, verified,
not assumed.

## Shipped

- **`ctx lineage`** (kernel, model-free, pure reads): chain-depth
  distribution over every derivation-bearing event (leaf = 0; note citing
  leaves = 1), anchor-resolution health, notes-per-epoch, cited-evidence
  age; `--full` per-note table. Any note past `lineage.max_note_depth`
  (config, default 1) exits nonzero with a `DEPTH ALERT`; `ctx status`
  carries a one-line summary and mirrors the warning. Walks a constructed
  80k-event archive in well under a second (pytest-pinned < 10 s).
- **`experiments/lineage_calibration/`**: seeded deterministic corruption
  generator — 5 classes × 60 items, all paraphrases (so the judge can't
  score by detecting paraphrase), corrupted notes keeping *valid anchors*
  (the laundering shape the mechanical verifier can't catch); corpus
  digest-frozen at `58655276a4ed…` and pinned by test. Calibration
  protocol: ≤ 3 tuning iterations on a fixed 25-item tuning subset, prereg
  ledger event before the one resumable held-out shot, exact
  Clopper-Pearson CIs, verdict by the preregistered rule alone.
- **`hooks/lineage_audit.py`**: age-stratified sample (default 8/run,
  config) of model-written derivation-bearing notes → closure walk to leaf
  evidence → receipted, budgeted, redacted disclosure through the real
  gate → calibrated judge → content-NULL `eval/lineage_audit` verdict
  event. Refuses to run at all unless the frozen calibration says
  `AUDIT EARNED` for the *exact* judge sha it would dispatch. Failed or
  unparseable audits record their linked outcome and stay retryable.
- **`ctx lineage report`**: verdict time-series by note-age bucket and by
  judge sha, coverage, every reading printed beside the judge's measured
  confusion matrix.
- **`launchd/com.contextd.lineage-audit.plist`**: weekly, shipped
  **disabled by default** (README documents the opt-in).

## Calibration receipts (prereg #76, rebuildable)

Protocol integrity: prereg event #76 precedes the first held-out run event
(`prereg_precedes_heldout: true` in the rebuilt report); corpus digest
verified against `FROZEN_DIGEST` at prereg and at held-out time; judge spec
sha re-derived and matched before dispatch; **1 of 3** allowed tuning
iterations used (25/25 on the tuning subset; prompt v1 frozen unchanged).

| class | held-out | rate | 95% CI | bar | result |
|---|---|---|---|---|---|
| faithful (false alarm) | 0/30 | 0.00 | [0.00, 0.12] | ≤ 0.1 | PASS |
| dropped-caveat | 30/30 | 1.00 | [0.88, 1.00] | ≥ 0.8 | PASS |
| unsupported-claim | 30/30 | 1.00 | [0.88, 1.00] | ≥ 0.8 | PASS |
| emphasis-inversion | 30/30 | 1.00 | [0.88, 1.00] | ≥ 0.7 | PASS |
| quantitative-shift | 30/30 | 1.00 | [0.88, 1.00] | none | ceiling |

Preregistered scoring rule: detected iff parsed verdict ≠ `faithful`;
unparseable/failed dispatches score against the instrument both ways. The
5×5 confusion matrix is diagonal (every detection also named the correct
class); rebuild it with the report command above.

## First live audit (advisory readings, not findings)

7 of 8 sampled notes dispatched (one skipped: no leaf evidence with
content); verdicts: 5 unsupported-claim, 1 emphasis-inversion,
1 quantitative-shift, 0 faithful. Coverage 7/29 eligible notes (24%).

**Read this through the instrument's limits, not as "86% of notes are
corrupted":** the calibration corpus is templated, single-mutation, and
self-contained, while real reconciler notes compress long multi-message
dialogues whose supporting context may exceed the audit's per-leaf evidence
render (2,400 chars). A synthesizing-but-honest note can therefore
legitimately read as "unsupported" against its truncated evidence. The
ceiling-perfect calibration bounds this judge on *this corpus's*
explicitness; the corpus-to-field validity gap is the instrument's next
measurement, not a solved problem. The verdicts mutate nothing, quarantine
nothing, and re-rank nothing — pinned by test.

## Live-archive baseline (the gauge's first real reading)

30 derived events (29 notes + 1 synthesis egress), all notes depth 1,
38/38 anchors resolved and in disclosure, 0 orphans; 24 epochs, 4 with
derived notes (mean 7.25/epoch); cited evidence median age 0.03 d.
`ctx lineage` exits 0; the day a note cites a note, it exits 2 loudly
(demonstrated in-session on constructed depth-1/depth-2 fixtures: exit 0 →
exit 2 with `DEPTH ALERT`, `ctx status` warning only in the second).

## Dispatch accounting

| phase | dispatches | receipts |
|---|---|---|
| wiring probe (no archive bytes) | 1 | none (pre-machinery smoke) |
| tuning (iteration 1) | 25 | calibration-home egress+outcome |
| held-out | 150 | calibration-home egress+outcome |
| first live audit | 7 | live-archive egress+outcome |
| **total** | **183 / 250 ceiling** | 175 + 7 receipted, 0 failed, 0 retries |

Every judge input bundle exists as a receipted egress in its owning
archive (verified by count: 175 succeeded outcomes in the calibration
home, 7 lineage-audit outcomes in the live archive).

## Discrepancy surfaced (not silently adapted)

The mission brief said model-written notes carry `meta.actor='mcp'`. The
live archive's 29 derivation-bearing model notes carry their
`CONTEXTD_CLIENT` as actor (`claude-code`); the literal-`mcp` filter would
have made the audit population empty. The audit now uses the boundary the
codebase has always documented (`experiment.provenance_class`: human iff
`actor == 'human'`). The derivation walk itself matched
`docs/PROVENANCE.md` exactly — no escalation-stop condition was met.

## This result does not license

- Judge performance on corruptions subtler than the corpus's operators
  (the quantitative-shift "ceiling" is a ceiling *at these magnitudes*:
  dates +2–3 days, durations −4–8 h, versions ±0.1).
- Any claim about the true fidelity rate of live notes — the live readings
  are advisory, uncorrected for the corpus-to-field gap, n=7.
- Certification of any note. The semantic-entailment boundary did not
  move; this instrument samples and estimates, the kernel still asserts
  only mechanical properties.
- One model (haiku via `claude -p`), one prompt, one corpus generation.

## Not done

- No corpus-to-field validation (e.g. hand-labeling a sample of live
  notes against full un-truncated evidence to measure the real-world
  false-alarm rate). This is the obvious next preregistration.
- The `no_leaf_evidence` skip (1/8 sampled) is re-sampled every run rather
  than classified; a persistent-skip counter would make dead candidates
  visible.
- Weekly schedule not loaded (ships disabled by default, by design).
- The live audit covered 7/29 eligible notes; coverage grows per run.

## Gates (verbatim tails, run in-session from repo root)

```
$ .venv/bin/ruff check .
All checks passed!
$ .venv/bin/python -m pytest -q
185 passed in 7.61s
$ .venv/bin/python tests/smoke.py
ALL SMOKE TESTS PASSED
$ grep -rn "http\|socket\|urllib\|requests" contextd/*.py | wc -l
       3
$ ctx lineage   # depth-1 fixture → exit 0; depth-2 fixture → exit 2, DEPTH ALERT
```

Baseline at mission start: 154 passed (verified before any change).
Diff confined to: contextd/{lineage.py,cli.py,__init__.py},
hooks/lineage_audit.py, launchd/, experiments/lineage_calibration/,
tests/, README.md, runs/lineage-audit-2026-08-13/.
