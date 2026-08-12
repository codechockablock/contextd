# experiments/ — does the context actually matter?

Provenance answers "where did this come from?" This harness answers the harder
question: **which pieces of recorded context materially changed a downstream
result?** It replays one task through a model under controlled context
interventions and estimates the marginal effect of specific events, groups,
and provenance classes — with the null measured, not assumed.

Harness-side tooling, deliberately outside the contextd package (same rule as
`hooks/`): this directory invokes models on your existing subscription; the
kernel never does. Everything model-free — freezing, interventions, gate-logged
disclosure, scoring, statistics, ledger records — lives in
`contextd/experiment.py` and is covered by the smoke suite.

## The distinctions the design enforces

| Claim | How it is established |
|---|---|
| context was **present** | event exists in the archive; query matched it (`matched_not_included` lists hits that lost the budget race) |
| context was **retrieved** | event is in the frozen set — the exact items recall would have disclosed, frozen once so arms never re-retrieve |
| context was **used** | the fact appears in output when its source item is supplied, at a rate above the no-context baseline (per-fact table) |
| context appears **causally relevant** | removing it moves the score beyond what relabeling the observed runs produces (exact permutation p) |
| context appears **irrelevant** | its removal lands within noise — reported as "not detected at this n", never as "no effect" |
| context appears **harmful** | its removal *raises* the score, beyond noise |

## Anatomy of an experiment

1. **Freeze**: one or more named retrievals (`gate.select_items`, the same
   walk `recall` uses), frozen with rendered bytes and two provenance layers
   per item: the transport class (`human` / `model` / `activity`, mechanical,
   from `meta.actor`/`meta.role`) and an assessed **origin** (`mixed`,
   `uncertain`, …) recorded with its reason wherever the channel misstates
   substance — e.g. a reconciler prompt or skill-file text arriving on the
   user channel. Class ablations can target either layer, and reports say
   which one a claim rests on. Items also carry a derived epistemic type
   (observation / human_assertion / model_inference / system).
2. **Preregister**: task prompt, arms, rubric, model, and n are recorded as an
   `experiment` event *before* any run. The rubric must pass its own
   known-answer fixtures (a perfect answer, an empty answer, and ideally a
   plausible-bullshit answer) or registration refuses.
3. **Intervene**: each arm drops events, drops transport classes or assessed
   origins, substitutes a distilled summary, references a different frozen
   set (an irrelevant, token-matched control), or supplies nothing. Arms are
   subsets of frozen sets — intervention effects are never confounded with
   retrieval variance. A declared **ladder** (no_history → distilled →
   retrieved_detail → full_relevant) gets consecutive contrasts with
   marginal-score-per-1k-context-tokens, so "more history stopped helping"
   is a measured row, not an impression.
4. **Disclose honestly**: every bundle an arm sends passes the real gate —
   budgeted, redacted, logged as an `egress` event. Experiments cannot
   disclose off the books.
5. **Run**: `claude -p` with `--tools "" --strict-mcp-config` — the child gets
   no tools and no MCP, otherwise a run could call contextd's own recall and
   quietly refill an ablated arm. Fresh tempdir cwd, no settings, no session
   persistence. Temperature is not exposed; repeated runs measure the variance
   instead.
6. **Score**: deterministic lexical rubric, no LLM judge. Facts may carry
   negative weights — penalties for recommending a recorded settled-negative
   or flagging a planted decoy — so shallow flag-everything or generic
   product-brain answers lose points instead of passing. Per-fact hits feed
   the used/knowable analysis; the no-context arm measures each fact's
   guessability directly. Each positive fact carries a preregistered
   `loss_class` (rationale, rejected_alternative, causal_relationship,
   negative_evidence, …) so when distillation costs points, the report can
   say what *kind* of information the compression destroyed. Outputs' bracketed
   event-id citations are checked against the ids actually supplied to that
   run; citations of never-supplied ids are counted as hallucinated.
7. **Report**: exact permutation test per comparison, the design's p-floor
   stated (4v4 runs bottom out at p=0.0286; 3v3 can never reach 0.05), verdict
   tiers (distinguishable ≤0.05 / suggestive ≤0.15 / within noise) reported
   alongside raw p, and a mandatory "this result does not license" block.
   Everything lands in the ledger (`exp_run`, `exp_report` events) with
   content=NULL so experiment artifacts can never enter FTS and contaminate a
   later recall or the next experiment.

## Running

```bash
# see what an experiment would hold — no model calls, nothing disclosed
.venv/bin/python experiments/runner.py plan experiments/tasks/contextd-decisions.json

# register + run all arms x n, score, record, report
.venv/bin/python experiments/runner.py run experiments/tasks/contextd-decisions.json --jobs 3

# afterwards, from the ledger alone
.venv/bin/ctx exp list
.venv/bin/ctx exp show 41054
.venv/bin/ctx exp report 41054
```

Results (transcripts, report.txt/json) land in `experiments/results/` —
gitignored, since bundles contain archive content.

## Writing a task

Copy a spec in `tasks/`. The discipline that matters:

- **Preregister an expectation** — including the ways the design might show
  nothing, and any known construct warts. Write it before looking at results.
- **Fixtures before runs**: the third fixture should be a *plausible wrong
  answer* — if generic competence can match your patterns, the rubric measures
  eloquence, not context.
- **Always keep a `no_context` arm**: it is the knowability baseline that
  stops you crediting the archive for what the model already knew.
- **n=4 minimum per arm** if you want p≤0.05 to be reachable at all.
- **Run the negative control** (`control-sqlite-wal-v1`) after harness
  changes: a task the model aces cold must come back "within noise", or the
  harness itself is manufacturing effects.

## provenance/ — adversarial laundering suite and model trials

`provenance/cases.py` + `provenance/adversarial.py`: nineteen deterministic
laundering cases (ground truth by construction, each in its own throwaway
synthetic archive) evaluated under three crossed verification layers; the
catch matrix is pinned in `tests/test_adversarial_matrix.py`, and the
`semantic` family passing every layer is the measured boundary, documented in
[docs/PROVENANCE.md](../docs/PROVENANCE.md).

`provenance/model_trials.py`: preregistered model trials — reconciler anchor
compliance (p1), injection persistence under provenance-visible serving (p2),
recursive compression closure (p3). Synthetic archives only; the live ledger
receives content-NULL preregistrations, runs, and reports, reconstructable
with `model_trials.py report <exp_id>`.

## What this is not

Not causal inference over the world — causal attribution over *this frozen
retrieval, this task, this model, this decoding noise*. A single changed
output proves nothing; that is why runs repeat, why the permutation test uses
only the observed runs, and why every report states what it does not license.
"No, this context barely matters" is an equally valid result, and the control
task exists to prove the harness can say it.
