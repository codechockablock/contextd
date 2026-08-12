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
claude mcp add contextd -- /Users/joseph/contextd/.venv/bin/ctx serve
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
