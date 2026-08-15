# contextd

A personal context daemon: an **append-only life log** + **index** + **gate**,
served to AI clients over **MCP**. One local daemon, a SQLite ledger plus a
small crash-recovery witness, no cloud.

The four kernel jobs, each in its smallest honest form:

| Job | v0 implementation |
|---|---|
| **Log** | Append-only `events` table (SQLite WAL); DB triggers enforce immutability; each event extends a hash chain whose external tip detects loss of the final row; oversized files use a content-addressed blob store |
| **Index** | FTS5 over event content (embeddings are v0.1, only after lexical search fails you in a documented way) |
| **Gate** | Every archive-derived outbound payload passes one disclosure primitive: never-leave rules, redaction, exact-byte token metering, and a pre-dispatch `egress` receipt committed atomically with the budget decision |
| **Scheduler** | The budget counter, derived entirely from egress events in the log itself |

Four ingesters, on purpose: watched text/markdown directories, deliberate
notes (`ctx note`), a read-only sip of Chrome/Safari history (titles+URLs;
`browser.skip_domains` never enters the archive at all, because append-only
means ingestion is forever), and Claude Code dialogue — user and assistant
text, delegation prompts, and subagent reports, with tool noise dropped,
secrets redacted before storage, and every message role-tagged for provenance.

**Zero network code.** Nothing in this package opens a socket except the MCP
stdio server talking to a local client. Verify: `grep -rn "http\|socket\|urllib\|requests" contextd/`.

## Security

The threat model is a **hostile same-UID agent**: an untrusted model or agent
running as the normal desktop user, controlling every MCP argument and
environment variable. Under that model no caller-supplied string —
`CONTEXTD_CLIENT`, `actor`, `authority`, `role` — establishes anything.
Operator-authoritative acts require a verified `OperatorActionV1` signature
from a presence-bound Secure Enclave key.

**Production is not hardened.** Read [`docs/SECURITY.md`](docs/SECURITY.md) for
the contract, its "Implementation status" table for what is actually enforced
today, and [`docs/adr/0001-two-plane-authority.md`](docs/adr/0001-two-plane-authority.md)
for the architecture and the exact signed bytes.

## Quickstart

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/ctx init          # creates ~/.contextd (db, config, blob store)
# edit ~/.contextd/config.toml -> set watch_dirs
.venv/bin/ctx ingest        # one-shot scan
.venv/bin/ctx note "first entry: contextd is alive"
.venv/bin/ctx search contextd
.venv/bin/ctx recall "contextd" --purpose "trying recall"
.venv/bin/ctx audit         # what has left the machine, when, for what
.venv/bin/ctx status
```

Run the daemon in the foreground with `ctx watch`, or install the launchd
agent so it survives reboots:

```bash
cp launchd/com.contextd.watch.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.contextd.watch.plist
```

## Hook it into Claude

```bash
claude mcp add contextd -- __CONTEXTD_REPO__/.venv/bin/ctx serve
```

Tools exposed: `recall(query, budget, purpose, since, until)`, `search(query)`,
`note(text)`, `timeline(since, until, source)`. Recall's window filters by
occurrence time (visit time for browser history), not ingest time.

An operator can restrict a server process at the registry itself:

```bash
ctx serve --tools recall search timeline
```

Disallowed tools are absent from MCP `tools/list`. This is a capability
allowlist, not authentication: `CONTEXTD_CLIENT` is a self-asserted audit
label. The committed OpenClaw configuration uses this server-side read-only
surface (and retains its client filter only as defense in depth).

Other clients (OpenClaw, Codex) connect the same way — see [clients/](clients/).
Each sets `CONTEXTD_CLIENT`, so the audit trail attributes who took what. Every
MCP read is redacted and logged as an egress event; `ctx audit` shows the full
disclosure history and any locally observable dispatch outcome.

## AI-session pipeline

The daemon tails Claude Code transcripts live and ingests dialogue as
evidence. When a session goes quiet for `claude.quiet_seconds` (20 min), the
daemon marks an *epoch* — sessions mostly end by abandonment, so quiescence,
not exit, is the episode boundary. A harness-side janitor
(`hooks/reconcile.py`, launchd every 10 min) distills unreconciled epochs
into notes via `claude -p --model haiku`, skipping episodes that already
self-documented with live notes. The kernel never calls a model; the janitor
is a client like any other, and its notes land with `actor=mcp` provenance.
(`hooks/` shells out to your Claude subscription; the contextd package itself
still opens no sockets.)

The exact reconciler prompt is redacted, budgeted, and receipted before the
subprocess starts. A separate linked `egress_outcome` event records success,
nonzero exit, or timeout. Failed attempts do not mark an epoch reconciled, so
they remain retryable; a successful run that writes zero notes is recorded as
such rather than confused with dispatch failure.

```bash
cp launchd/com.contextd.reconcile.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.contextd.reconcile.plist
```

## Design commitments

- **Append-only, and tamper-evident**: `UPDATE`/`DELETE` on `events` abort at
  the SQLite level, and every event commits to the hash of the one before it.
  `chain-witness.json` records the external chain tip, so `ctx verify` detects
  rewrites, middle or tail deletion, and insertion/reordering. Appends use a
  durable recovery journal and the lock order witness → SQLite; after a crash,
  recovery resolves the interrupted append to zero or exactly one committed
  event. This remains tamper-evident, not tamper-proof (see Trust model).
- **Self-auditing gate**: the archive records the exact redacted payload it
  intended to disclose before returning it or starting a model subprocess.
  The actual token charge and receipt append share one SQLite write
  transaction, so concurrent readers cannot overspend the daily cap.
  Subprocesses add a linked immutable outcome when their result is observable.
  A receipt proves a local dispatch attempt, not delivery or receipt by a
  remote model.
  Egress events are excluded from search, recall, and the timeline tool
  (audit disclosures with `ctx audit`, or MCP `timeline` with
  `source='gate'`), so disclosures never feed on themselves.
- **Local search is free; egress is metered.** `ctx search` is yours and
  unlogged. Anything shaped for a model (`recall`, all MCP reads) is gated,
  budgeted, and logged.
- **Data lives in `~/.contextd/`, never in this repo.**

## Trust model

The gate is an **audit layer, not a security boundary** (decided 2026-08-11).
It redacts, meters, and logs every disclosure made through recall and the MCP
tools — but it governs only that path. Any local process with filesystem
access can read the SQLite directly; `0700`/`0600` permissions keep other
accounts out, not your own software. Hard isolation is deliberately not a v0
goal. The promise is narrower and kept: everything a well-behaved client
sees is redacted, budgeted, and on the record.

The chain witness has the same owner and filesystem trust boundary as the
database. It catches DB-only loss and makes interrupted appends recoverable;
an owner-level process that rewrites both the database and witness can still
forge a consistent history. Likewise, a server tool allowlist limits that
process's MCP capabilities but does not prove who launched it.

Models may write notes. Every note records its author in `meta.actor`
(`human` from the CLI, `mcp` from model clients), so the archive always
distinguishes what you said from what a model said. No approval workflow
until a real incident earns one.

Model-derived events additionally carry **derivation lineage**. The
reconciler binds its notes to the exact disclosed dialogue
(`CONTEXTD_DERIVATION_SOURCE`); the `note` tool kernel-verifies proposed
anchors against that disclosure and refuses citations of undisclosed events.
`ctx why <event_id>` walks the full derivation closure — claim → source
disclosure → cited events → recursively → leaf evidence — and reports what
is mechanically verified (anchors, disclosure membership, quote spans, hash
integrity, chain shape) as distinct from what remains a semantic judgment
(whether a claim's wording is actually supported by its evidence — which the
kernel never asserts). The exact boundary between the two is measured and
pinned by an adversarial suite; see [docs/PROVENANCE.md](docs/PROVENANCE.md).

## Deliberately not in v0

No sync, no multi-device, no encryption-at-rest, no plugin system, no UI, no
screen capture, no embeddings, no cloud anything. Each of these gets built
only when a concrete, logged failure demands it.

## The only evaluation that matters

For one month, every time you think "what was that thing I read/wrote about
X?", ask `ctx recall` first and keep the tally in the archive itself:

```bash
ctx outcome <egress-id> hit      # or: partial | miss  (add --note "why")
ctx outcome                      # the scoreboard
```

If it beats grep and your own memory ≥30% of the time, v0.1 is earned — and
the misses tell you *what* to build (vocabulary mismatch → embeddings earn
their place; time confusion → better windows; and so on).

Resumptions are judged the same way: every `ctx checkpoint` egress takes the
same verdict, plus `--failure-class` on a miss or partial — `not-in-archive`
(never captured), `not-selected` (in the archive, absent from the package),
`drowned` (in the package, buried), `superseded` (selected, but a later
decision made it stale). The scoreboard stratifies by egress type; the class
distribution of real misses is what licenses the next selection work.

Back up the archive as a complete versioned bundle:

```bash
ctx backup                         # writes ~/.contextd/backups/*.ctxbackup
ctx backup /safe/location --keep 8
ctx restore /safe/location/contextd-….ctxbackup /new/empty/contextd-home
```

The manifest-hashed bundle contains an online WAL-consistent database
snapshot, config when present, chain witness/recovery state, and every blob
referenced by that snapshot. Restore treats the bundle as hostile input:
unexpected, missing, traversing, symlinked, or hash-mismatched payloads are
refused; it stages and verifies SQLite, FTS, event chain, witness, and blobs
before one final publish rename. It never merges into a non-empty destination.
Retention removes complete `.ctxbackup` directories only, never legacy files.
The live database is versioned too: init (or the first write-capable connect)
stamps `PRAGMA user_version = 1` (`SCHEMA_VERSION`), complementing the
`BUNDLE_VERSION` the bundle manifests already carry.

A backup that has never been restored is a hope, not a backup. The weekly
restore fire-drill (`hooks/restore_drill.py --once`, scheduled by
`launchd/com.contextd.restore-drill.plist`) restores the newest bundle into a
throwaway temp destination — after a free-space preflight pinned to the
measured peak temp usage — and runs a verification battery on the restored
copy: chain + witness, event count and tip against the manifest snapshot,
every blob re-hashed, and FTS + behavioral equivalence (a fixed probe set of
search / timeline / loop-reduction / liveness / audit reads answered
byte-identically by the bundle's snapshot and the restored copy). The
verdict lands in the live ledger as a content-NULL `restore_drill` event
(never searchable, never recallable), `ctx status` prints the last verdict
and its age, and warns when the last drill FAILED or none has run within
`[backup].drill_stale_after_hours` (default 192) — the alarm path itself is
exercised by test and smoke. Scale behavior (1–8 GiB, event-heavy and
blob-heavy) is measured, not assumed: `experiments/restore_scale/trial.py`
holds the inflator, the measurements, and the cross-machine rehearsal.

## The health sweep

A daemon that degrades quietly is supervised, restarted, logged — and
invisible (the 2026-08-15 specimen: 42 identical reconciler refusals into a
log nobody read). `hooks/health_sweep.py` (launchd, every 30 min, zero
model dispatches) reduces existing evidence — ledger liveness watermarks,
unreconciled-backlog age, launchd states, log-tail failure fingerprints,
backup and drill ages, grant-reduction anomalies — into one content-NULL
`health` event per run. `ctx status` prints the last verdict; a local
notification fires only on a NEW degradation, naming check names only,
never detail strings (attacker-influenceable text stays out of trusted
prompts). These structured verdicts are deliberately free-text-free: they
are the future coordinator's entire input feed
([docs/AGENTS.md](docs/AGENTS.md), the frozen agent-plane contract —
non-convertibility, the trifecta rule, workflows as promoted artifacts).

```bash
cp launchd/com.contextd.health.plist ~/Library/LaunchAgents/   # then sed the __PLACEHOLDERS__
launchctl load ~/Library/LaunchAgents/com.contextd.health.plist
```

## Synthesis-mode recall

Plain recall serves raw items. Synthesis mode serves a ~150-word distillate
in which **every claim carries a bracketed event id that resolves** — the
representation the ablation experiments found carries cross-item synthesis
capability at ~12% of the raw tokens, and the one thing that could not be
compressed away (exps #41325–#41485: id-free summaries scored zero;
id-anchored ones matched per-item granular bundles).

```bash
ctx recall --mode synthesis "what did we decide about the trust model" --purpose "..."
```

The kernel never calls models, so `--mode synthesis` delegates to
[hooks/synthesis_recall.py](hooks/synthesis_recall.py) (same rule as the
reconciler), which shells out to `claude -p` for the distillation. Honesty
properties, enforced not promised: the raw bundle disclosed *to the
distiller* is itself a logged egress; the served distillate is a second
logged egress linking back to the first; and `gate.verify_anchors` refuses
any distillate whose anchors don't all resolve to supplied events — an
anchor pointing nowhere launders authority the archive never granted.
Judge it like any recall: `ctx outcome <egress-id> hit|partial|miss`.

## Checkpoint/restore: the work survives the model

`ctx checkpoint` compiles the **active state** of a project — not a summary
of its past — so a fresh model with zero session continuity can continue the
actual work:

```bash
ctx checkpoint --repo ~/myproject --test-cmd 'pytest -q' --hint "what I was doing"
ctx checkpoint --mode distill ...   # model-compressed, anchor-verified (hooks/)
```

The compiler is stratified, not a search box: the raw dialogue tail of the
interrupted session (freshest working state, verbatim), reconciled episode
notes (the archive's own anchored compression of earlier episodes), operator
notes, an optional task-hint recall, and a live repository section (branch,
status, diff, failing tests) — every item keeps its `[event-id]`, so each
line stays inspectable with `ctx why`. Compilation is a gated, logged egress
like any other disclosure; `--mode distill` adds a structured
OBJECTIVE/STATE/DECISIONS/REJECTED/OPEN/NEXT compression whose anchors the
kernel verifies before serving (same rule as synthesis recall: the kernel
never calls models, and a checkpoint is a **view for resumption**, never
re-ingested as truth — the archive stays canonical).

Measured basis (handoff benchmark, ledger exps #41823/#41853/#41864/#41899/#41905;
rebuild with `experiments/handoff/bench.py report <id>`): on a staged
interrupted implementation, a fresh model resuming from a ~520-token
distilled checkpoint matched the full-transcript ceiling (1.00), preserved
dialogue-only constraints, finished the code, and passed held-out tests —
while a same-size naive summary lost the rejected-alternative and constraint
knowledge; sonnet and codex (cross-vendor, real runs) resumed from the same
haiku-written checkpoint at 1.00. At two frozen real-history interruption
points (`contextd/handoff.py` frozen views make post-cutoff events
mechanically invisible), every contextd arm beat no-history distinguishably
(p at the design floor), zero runs out of 96 resurrected the
recorded-rejected alternative, and compiled checkpoints were the most
*stable* representation across cutoffs — a naive recency summary swung
0.92 → 0.33 between cutoffs while checkpoints held. Component ablations
(exps #41939, #41949) found the DECISIONS/REJECTED content load-bearing
(removing it: Δ −0.35, the only near-threshold effect); anchor-stripping
showed no stable rubric effect, as preregistered — anchors buy
inspectability, not lexical score. Known measured gap, stated precisely: no
representation *reliably* carried an open thread that was neither recent nor
lexically near the task hint — `next_check` was recovered at 0.25 by the
raw-tail and recall arms and 0.0 by the other six (exp #41905 raw report;
an earlier run-log summary saying "0.00 across all 8 arms" overstated this).
Cross-episode open loops are what still died with the session; the open-loops
mechanism below is the earned answer, built on the measured fix (exp #42203:
one explicit operator note moved the lost target from 0/5 to 5/5).

## Open loops: acknowledged work that must survive the session

Four preregistered attempts to *infer* open commitments from dialogue failed
(lexical markers, retro extraction, live tracking, a model-maintained board —
exps #42011/#42067/#42123/#42127..#42240): the missing datum was always the
operator's own prioritization, which is not reliably present in the
observable record. So contextd does not mind-read. It gives the operator a
one-line externalization act and makes that act indestructible:

```bash
ctx loop add "re-run the drift correction on the July batch"   # scoped to cwd's repo
ctx loop list            # active loops for this repo
ctx loop close 42317 --reason "ran clean"
ctx loop reopen 42317 --reason "regressed"
ctx loop candidates      # model-proposed, awaiting your confirm/dismiss
ctx loop confirm 42410   # operator act; candidates never activate themselves
```

Loops are event-sourced (state is a pure reduction of append-only `loop`
events; invalid transitions refuse; retries are no-ops), scoped to a
repository or global, and carried into every `ctx checkpoint` for their repo
in a dedicated `ACTIVE OPEN LOOPS` section selected by lifecycle state — not
recency, not lexical luck, never competing with newer notes. If the budget
cannot hold every active loop, the omitted ids are named in the package;
silent loss is structurally forbidden. Closed and dismissed loops leave the
checkpoint; reopened ones return; distilled checkpoints re-attach the section
verbatim so carriage never depends on a model's choices.

Models may *propose* (`loop_candidate` over MCP, or the gated
`hooks/loop_scan.py` scanner): proposals are labeled, deduplicated,
suppressed against dismissed/closed loops, and inert until the operator
confirms **by CLI** — there is no model-facing add, close, reopen, confirm,
or dismiss. (A model-relayed confirmation bound to ingested operator
utterances was built and retired before field use: verifying that words
were uttered cannot distinguish assent from rejection, so it could launder
rejecting words into authority — the negative result is recorded in the
contract.) No calendars, no recurrence, no notifications — this is durable
operator state, not a planner. Contract, threat model, and measured limits:
[docs/OPEN_LOOPS.md](docs/OPEN_LOOPS.md).

## Measuring whether context matters

The outcome tally judges recalls by hand. The experiment layer asks the harder
question with controls: **which recorded context actually changed a downstream
result?** `contextd/experiment.py` freezes one retrieval, intervenes on it
(drop an event, drop a provenance class, substitute a distilled summary), and
records the whole design — task, arms, rubric, frozen items, model, planned n —
as ledger events *before* any run. The harness in [experiments/](experiments/)
replays the task through `claude -p` per arm, scores outputs against a
preregistered deterministic rubric, and reports marginal effects with an exact
permutation test against the measured run-to-run noise. Every bundle an arm
discloses passes the real gate and lands as an egress event; experiment records
are content-NULL so they can never leak into FTS and feed a later recall.

```bash
.venv/bin/python experiments/runner.py plan experiments/tasks/contextd-decisions.json
.venv/bin/python experiments/runner.py run  experiments/tasks/contextd-decisions.json
.venv/bin/ctx exp list      # every experiment, from the ledger
.venv/bin/ctx exp report 41054
```

A negative control task (one the model aces with no archive) ships alongside
the real one, and came back Δ 0.00, p=1.0 — the harness demonstrably can
answer "this context barely matters," which keeps the positive answers honest.
See [experiments/README.md](experiments/README.md) for the method and its
stated limits.

## Lineage: measuring note drift instead of worrying about it

Model-written notes are paraphrases, and paraphrases drift. Two standing
instruments turn that worry into numbers:

**The topology gauge** (kernel, model-free). `ctx lineage` walks every
derivation-bearing event and reports chain depth (leaf dialogue = 0, a note
citing only leaves = 1), anchor-resolution health, notes-per-epoch, and the
age of cited evidence; `--full` prints the per-note table. Today the
reconciler cites raw dialogue only — the gauge *measures* that instead of
assuming it, and the day any note exceeds `lineage.max_note_depth`
(default 1: a note citing notes, where compounding-summary drift becomes
structurally possible) `ctx lineage` exits nonzero with a `DEPTH ALERT` and
`ctx status` warns.

**The sampled fidelity audit** (harness-side, calibrated, advisory-only).
`hooks/lineage_audit.py` samples model-written notes stratified by age,
walks each to its leaf evidence, disclosures the bundle through the real
gate, and asks a judge model whether the note is faithful. The judge earned
that job first: it was validated against a seeded corpus of deliberately
corrupted notes with known ground truth
([experiments/lineage_calibration/](experiments/lineage_calibration/)),
with preregistered per-class sensitivity/specificity bars — an uncalibrated
judge is vibes. Verdicts land as content-NULL `lineage_audit` events: they
never enter FTS, never feed a recall, never quarantine or re-rank a note,
and `ctx lineage report` always prints them next to the judge's measured
confusion matrix. The semantic-entailment boundary does not move: this
instrument samples and *estimates* fidelity; it never certifies it.

The weekly schedule (`launchd/com.contextd.lineage-audit.plist`) ships
**disabled by default** — load it only after the calibration verdict in
`experiments/lineage_calibration/calibration_result.json` reads
`AUDIT EARNED` (the hook refuses to run otherwise, and it stays mandatorily
disabled if calibration was NOT EARNED):

```bash
launchctl load ~/Library/LaunchAgents/com.contextd.lineage-audit.plist
```

## Tests

```bash
.venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check .
.venv/bin/python -m pytest -q
.venv/bin/python tests/smoke.py
```

The pytest suite includes deterministic 32-way budget and append races, crash
fault injection, a real stdio MCP capability test, model-call inventory, and
corrupt-backup restore cases. It always installs a temporary `CONTEXTD_HOME`;
the legacy smoke suite does the same. CI runs pytest, smoke, and Ruff on Python
3.11 and 3.13. A weekly launchd job
(`launchd/com.contextd.backup.plist`) runs `ctx backup --keep 8`.

## License

Apache-2.0 — see [LICENSE](LICENSE).
