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

1. **Freeze**: one retrieval (`gate.select_items`, the same walk `recall`
   uses), frozen with rendered bytes and per-item provenance
   (`human` / `model` / `activity` derived from `meta.actor` and `meta.role`).
2. **Preregister**: task prompt, arms, rubric, model, and n are recorded as an
   `experiment` event *before* any run. The rubric must pass its own
   known-answer fixtures (a perfect answer, an empty answer, and ideally a
   plausible-bullshit answer) or registration refuses.
3. **Intervene**: each arm drops events, drops provenance classes, or
   substitutes a distilled summary. Arms are subsets of the frozen set —
   intervention effects are never confounded with retrieval variance.
4. **Disclose honestly**: every bundle an arm sends passes the real gate —
   budgeted, redacted, logged as an `egress` event. Experiments cannot
   disclose off the books.
5. **Run**: `claude -p` with `--tools "" --strict-mcp-config` — the child gets
   no tools and no MCP, otherwise a run could call contextd's own recall and
   quietly refill an ablated arm. Fresh tempdir cwd, no settings, no session
   persistence. Temperature is not exposed; repeated runs measure the variance
   instead.
6. **Score**: deterministic lexical rubric, no LLM judge. Per-fact hits feed
   the used/knowable analysis; the no-context arm measures each fact's
   guessability directly.
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

## What this is not

Not causal inference over the world — causal attribution over *this frozen
retrieval, this task, this model, this decoding noise*. A single changed
output proves nothing; that is why runs repeat, why the permutation test uses
only the observed runs, and why every report states what it does not license.
"No, this context barely matters" is an equally valid result, and the control
task exists to prove the harness can say it.
