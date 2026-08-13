# Open loops / prospective state — mission report (2026-08-13)

Mission: make every operator-recognized unresolved commitment survive
session death, model replacement, time, and unrelated work as scoped,
inspectable, actionable state until explicitly discharged — earning capture
honestly or demonstrating its boundary. Contract, threat model, transition
table, measured results, and limitations: [docs/OPEN_LOOPS.md](../../docs/OPEN_LOOPS.md).
Run log: [notes.md](notes.md). Preregistration: live ledger event #42331;
stored report event #42390; rebuild (verified matching):

```bash
.venv/bin/python experiments/open_loops/bench.py report 42331
```

## VERDICT: `NOT EARNED`

By the preregistered rule, no capture verdict — `ASSISTED` or `AUTONOMOUS` —
can be earned without the real-operator trial (fixed protocol in
docs/OPEN_LOOPS.md, presented and pending). Machine-side results cannot
substitute for the operator, and were not allowed to. The deterministic
lifecycle and checkpoint carriage ship regardless, on their own green gates
plus the prior explicit-channel license (exp #42203).

## What shipped

- **Event-sourced loop lifecycle** (`contextd/loops.py`): candidate / open /
  closed / dismissed / reopened as a pure reduction of append-only `loop`
  events; frozen transition table; idempotent no-op retries; locked dedupe
  against racing duplicates; explicit nonzero refusals; anomaly-safe replay.
- **CLI**: `ctx loop add | list | show | close | reopen | candidates |
  confirm | dismiss`, scope = repo (default: cwd's git toplevel) or global.
- **Checkpoint carriage**: a dedicated `ACTIVE OPEN LOOPS` section, first
  archive section in every compiled checkpoint, selected by lifecycle state
  and scope only; reserved budget slice with under-fill overflow to the
  tail; omitted loop ids named in-package and in the egress meta (silent
  loss structurally forbidden); closed/dismissed/candidates/wrong-project
  excluded; reopened return; distilled checkpoints re-attach the section
  verbatim.
- **MCP surface** (server-enforced allowlist): `loop_candidate`,
  `loop_list` (gated read), and `loop_confirm`/`loop_dismiss` only under a
  kernel-verified post-candidate operator-utterance binding — attribution,
  not authentication; no model-facing add/close/reopen. Restricted configs
  (openclaw) gain nothing implicitly (pinned by test).
- **Candidate scanner** (`hooks/loop_scan.py`): harness-side, gated,
  receipted, derivation-bound, dispatch-outcome-recorded, mechanically
  incapable of promotion (its grant contains one tool), silent-by-design
  when uncertain.
- **Docs**: docs/OPEN_LOOPS.md (contract + results); README corrected —
  including the overstated "0.00 across all 8 arms" claim, now stated as
  0.25 raw-tail/recall and 0.0 elsewhere per the raw #41905 report.

Gates at completion: `ruff` clean; **135 pytest tests** green (lifecycle,
carriage, MCP capability, backup/restore, crash recovery, scanner gate,
benchmark instrument); `tests/smoke.py` ALL PASSED (incl. the `ctx loop`
CLI layer); `bench.py selftest` and `validate-spec` OK; `ctx verify` chain
intact; report reconstruction matches the stored report.

## Endpoint results (preregistered #42331; separate by contract)

| endpoint | result | bar | pass |
|---|---|---|---|
| capture (held-out, unseen wording) | 11/12 = 0.917 | >= 10/12 | yes (machine-side) |
| false promotion | 0 | 0 | yes |
| confirmation burden | 0.167 false cand./dialogue; 0 distractor hits | <= 1.0 | yes |
| identical pair | silence on both; no certainty | no certainty | yes |
| lifecycle correctness | deterministic gates | all pass | yes |
| carriage / stale resurrection | deterministic gates | all pass | yes |
| fresh-model use | 0.75 vs 0.00, p=0.0001 (stratified perm.) | p <= 0.05 | yes |

Honest annotations, receipts in docs/OPEN_LOOPS.md and raw artifacts: the
one capture miss is a frozen-matching artifact (the scanner proposed the
item in the operator's words); the use-arm 0.75 is conservative (all four
weak-world outputs discussed the loop; three paraphrased past the strict
substring indicator); the without-arm never mentioned any target in 16
runs. All 52 dispatches succeeded; no exclusions.

## What these results do not license

- No capture verdict of any kind — the operator trial has not run.
- No claim beyond haiku on these synthetic worlds: not other models, not
  real archives, not real operator wording or timing.
- The autonomous-capture numbers, though above bar, are a property of one
  generator prompt on designer-written fixtures; ecological validity is
  exactly what the operator trial exists to test.
- The utterance binding is not authentication and never claims the semantic
  link between utterance and candidate.

## The ask (the only remaining gate)

Run the fixed operator-trial protocol in docs/OPEN_LOOPS.md — ~5 normal
working sessions, externalize real loops in your own words as they arise,
resume normally, close/dismiss as reality dictates, then list what you
recognized but never externalized. The session that scores it applies the
same preregistered bars. Until then the verdict stays `NOT EARNED`, and the
assisted workflow it gates is already shipped and usable.
