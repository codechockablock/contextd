# Decisions-lifecycle contrast — final report

Contract `docs/DECISIONS.md` (sha `d2af25fb471d8e25d4d82d1fb115c8a5b90c152eea6685f15b5722a89bcb6d52`); contrast prereg ledger event `#255` (spec sha `f86dadd5f7e339db9e382d0addc203a8552779a3c56c4fb6ad0904b66db4790b`); baseline: selection-stress r2 (spec sha `0679674bdb31886674625d225035237975a7a5a89b96ca27237fa9cb466c222b`). Rebuild with `experiments/selection_stress/bench.py contrast-report 255`.

## Verdict

**FIX DECLARED.** Every preregistered bar was met; the surface moved and the residue is loud. The declaration extends exactly as far as the bars do — see the license section.

## Preregistered bars

| bar | requirement | result |
|---|---|---|
| 1 silent resurrection | 0 occurrences | 0/405 — MET |
| 2 unmarked superseded served | 0 occurrences | 0/405 — MET |
| 3 surface movement | resurrection <= 0.05 (baseline 0.2691) | lifecycle 0.0 (seed-bootstrap {'hi': 0.0, 'lo': 0.0, 'mean': 0.0, 'n_clusters': 5}) — MET |
| 4a pooled non-regression | <= 0.02 | 0.0 — MET |
| 4b unpaid losses (reserve not engaged) | 0 | 0 — MET |
| 4c taxed-pair pooled delta | <= 0.10 | 0.0 over 51 pairs — MET |
| 5 behavioral resurrects | pooled <= 0.3, p <= 0.05 | pooled 0.0417 (p=5e-05, stratified-mc(20000)) — MET |
| 5 behavioral v2-honors | pooled >= 0.5 | pooled 0.9583 — MET |

## Measurements

Kernel regression: the new kernel reproduced the stored r2 rows on edge-less archives exactly (7830 rows, 0 mismatches) before any lifecycle world was built — the arms share one kernel and the baseline is unchanged by construction.

Supersession mechanics at the default budget (lifecycle arm, hinted): v2 carried when v1 carried in 179/179 compiles (rate 1.0); loud SUPERSESSION OMITTED lines in 0/405; marked-but-unnamed (a contract defect class, expected 0): 0.

Behavioral cells (baseline arm reused from prereg #36 by ledger reference):

| cell | baseline resurrects | lifecycle resurrects | baseline v2-honors | lifecycle v2-honors | p (resurrects) |
|---|---|---|---|---|---|
| c9 | 0.875 | 0.0 | 0.0 | 1.0 | 0.001399 |
| c10 | 0.625 | 0.0 | 0.0 | 1.0 | 0.025641 |
| c11 | 0.75 | 0.125 | 0.0 | 0.875 | 0.040559 |

## Honest annotations

- This is round 2. Round 1 (prereg #253, outcome #254) ran the r1 mechanism and FAILED bars 2 and 4: the scorer's block extractor split on episode-note anchor citations (instrument artifact — the kernel was verified compliant on every flagged row), and the unconditional reserve taxed compiles that owed nothing (real mechanism cost, one cell lost 0.6). Fix was not declared; the mechanism was revised to two-pass, the bars were re-frozen with the unpaid/taxed distinction, and round 2 re-preregistered (#255) before any round-2 data existed. Zero behavioral dispatches were spent on round 1.
- After all 24 round-2 dispatches completed and were scored, the results aggregator crashed reading prereg #36's stored rows (key-name mismatch) and was fixed post-run; the fix touches only the stored-row reader — every per-run score was computed at dispatch time, before the crash. Recorded as a harness note in the experiment ledger with the post-fix module sha.
- Bar 4c's taxed-pair delta is measured on planted items only; the reserve may displace organic (unscored) content. The bound it certifies is about the measured surface, not every token.
- Lifecycle worlds append every supersession edge after the full event stream (digest-verified copies of the r2 worlds), not at the moment v2 was written. Edge position never enters selection or reduction order for distinct-old edges, so this cannot affect the endpoints; it is a timing-realism simplification, recorded here.
- The baseline worlds carry egress events accumulated by earlier grid compiles. Selection excludes egress rows by construction and the kernel-regression check confirmed identical scoring; recorded for completeness.
- The behavioral baseline arm is reused from prereg #36 rather than re-dispatched (24 new calls instead of 48). Identical archives, model, rubric, and protocol; the reuse was preregistered. Model drift between the two run dates is uncontrolled and would bias in an unknown direction; the carriage-level endpoints (1–4) do not share this caveat.
- The contract only covers RECORDED edges. Unrecorded supersessions behave exactly as the baseline measured (0.269 resurrection); this mechanism moves the surface only where an operator drew the edge.
- Plain recall (`ctx recall`) still serves superseded events unmarked — a recorded non-goal (docs/DECISIONS.md), not an oversight.

## What these results do and do not license

They **do** license: treating checkpoint-path stale resurrection as structurally loud *for recorded chains* — a superseded item cannot be served unmarked, and its current version is carried or named; and treating the mechanism as cost-bounded (a 6%/min-120-token reserve, only when edges exist, with measured non-regression elsewhere on the surface).

They do **not** license: any claim about unrecorded supersessions (operator diligence remains the input); extending the contract to the plain recall path (separate decision, unmeasured); or the model-proposed-edge design (a possible later mission with its own authority questions). The behavioral confirmation is three cells and one model; the carriage endpoints are the load-bearing evidence.

