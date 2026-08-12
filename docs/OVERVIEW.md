# contextd — Executive Summary

*A personal context daemon: an append-only life log, index, and disclosure gate,
served to AI clients over MCP. One local daemon, a SQLite ledger plus a small
chain-tip witness, no cloud.*

Written 2026-08-11, at the end of the build.

---

## Origin

contextd was born on **2026-08-10**, out of a conversation about what its author
would change about computers. The answer — *undo everywhere, all the way down* —
is preserved as the first note in the archive itself (event #1). That instinct,
a wish for computing where nothing happens without a way back to the truth of
it, is the whole project in miniature: not a memory that helps you, but a record
you can trust and account for.

The first working version was built the following night, 2026-08-11, in a single
session — and then, unusually, that session's own transcript became the archive's
richest data source. The tool spent the night watching itself be built.

## What it is

Four kernel jobs, each in its smallest honest form:

| Job | Implementation |
|---|---|
| **Log** | Append-only `events` table; immutability enforced by SQLite triggers, not discipline. `UPDATE`/`DELETE` abort at the database level. |
| **Index** | FTS5 lexical search over event content. Embeddings are deferred until lexical search fails in a documented way. |
| **Gate** | Every archive-derived model payload passes one disclosure primitive: never-leave rules, redaction, exact-byte metering, and an atomic pre-dispatch `egress` receipt. |
| **Scheduler** | The budget counter, derived entirely from egress events in the log itself. |

Four ingesters feed it: watched text directories, deliberate notes, a read-only
sip of browser history, and — added the same night — **Claude Code dialogue**,
tailed live and filtered to user/assistant text, delegation prompts, and
subagent reports.

## The defining decision: the gate is an audit layer

The single most important architectural commitment is what the gate *is not*.
It is an **audit layer, not a security boundary**. It redacts, meters, and logs
every disclosure made through recall and the MCP tools — but it governs only
that path. Any local process can read the SQLite directly. `0700`/`0600`
permissions keep other accounts out, not the owner's own software.

This was decided deliberately, and written into the README as a documented
commitment, after the author's own testing demonstrated the bypass. The promise
is narrow and kept: *everything a well-behaved client sees is redacted,
budgeted, and on the record.* The value is not walls — it is receipts.

## The night's arc (11 commits)

1. **`74ba60b` v0** — the kernel: append-only log, FTS5, gated egress over MCP.
2. **`0112e5c` gate leak** — browser-history OAuth tokens were leaking through
   URL fields; redaction moved to a single choke point, URL-param patterns added.
3. **`e084a87` domain policy** — one blocklist (suffix + glob + list-file),
   enforced at both ingest and gate; catches mirror domains, retroactive at the gate.
4. **`0f418a4` external-review hardening** — an outside review (Codex) found the
   load-bearing claim "every read is redacted and budgeted" false three ways:
   FTS highlight brackets split credentials past redaction, search/timeline
   never checked the budget, and the runtime dir was world-readable. All
   reproduced, then fixed with tests.
5. **`0f32727` trust model** — the audit-layer decision, documented.
6. **`62dbb32` token efficiency** — strip tracking/auth params at ingest (also
   the "never store credentials" fix), emit each URL once, dedup, add
   occurrence-time windows to recall. Database 15.8MB → 5.7MB; a "what was I
   reading in June" query went from ~10.6k tokens over nine calls to ~0.8k in one.
7. **`23a4bed` AI-session pipeline** — the daemon learns to hear its richest
   stream: live dialogue ingestion with redaction and role-tagging, plus an
   epoch/reconciler loop (quiescence marks episode boundaries; a harness-side
   janitor distills them via a cheap model — the kernel never calls a model).
8–11. **client attribution + wiring** — every disclosure gets a named client;
   OpenClaw and Codex join Claude Code as clients through the one gate.

## Verified: one gate, three clients, two vendors

By the end, three AI clients drew on the archive, each attributed in the audit
trail, none operating the gate:

- **`claude-code`** (Anthropic, full tool surface)
- **`openclaw`** (OpenAI GPT-5.4, read-only — completed a gated recall and
  delivered an accurate June summary to the author's Telegram, every claim
  independently verifiable against the ledger)
- **`codex`** (OpenAI, full surface — interactive recall confirmed, egress #40939)

This is the thesis made operational: a neutral local substrate that multiple
counterparty model vendors read through customs, with the only complete record
of who-took-what held in a file the models can draw from but never edit. The
structural argument for why this can be a durable position: a model vendor is a
counterparty on the far side of the gate, and so is disqualified from operating
it — neutrality is the moat, verification is the product, and the code was never
the moat.

## Design commitments that held

- **Append-only means forever** — so credentials are never *stored*, not merely
  redacted on the way out. Capture-side exclusion beats egress redaction.
- **Local search is free; egress is metered** — what's yours is unlogged; what's
  shaped for a model is gated, budgeted, and logged.
- **Features are earned by documented failure** — embeddings, workspace scope,
  and screen capture were all declined for v0 because nothing had failed yet.
- **The kernel never calls a model** — models call the kernel; interpretation
  (distillation) lives in harness-side clients, keeping the daemon network-free.

## Where v0 stands

The code is complete; the *evaluation* has just begun. v0 was never a feature
list — it is an instrument, and the README defines its completion as a
measurement: for one month, every "what was that thing…" question tries `recall`
first, and if it beats grep and memory ≥30% of the time, v0.1 is earned. That
clock started 2026-08-11. Early signal is promising — a June-reading question
won twice, the second time at a quarter the cost.

## Reliability hardening — 2026-08-12

The original summary above describes the first build. The following gaps are
now closed in the current source and supersede the old “honestly open” list:

- Daily egress accounting and the exact redacted receipt now commit in one
  SQLite write transaction. Deterministic 32-client tests show concurrent reads
  cannot exceed the cap.
- Archive-bearing harness paths (synthesis, reconciliation, and experiment
  arms) receipt their exact subprocess input before dispatch and append a
  linked success/failure/timeout outcome. No-context experiment controls carry
  no archive bytes. A call-site inventory makes new unreviewed model
  subprocesses fail CI.
- The event chain has a local external tip plus recovery journal. This detects
  DB-tail deletion and resolves interrupted appends to zero or one event. It is
  still an owner-controlled audit witness, not remote anchoring or tamper-proof
  security.
- `ctx serve --tools …` builds only the allowed MCP registry. OpenClaw's
  read-only surface is server-enforced; `CONTEXTD_CLIENT` remains self-asserted
  attribution, not authentication.
- `ctx backup` creates a complete manifest-hashed bundle containing the
  WAL-consistent database, config when present, witness/recovery state, and
  referenced blobs;
  `ctx restore` verifies hostile input in a staging directory before publishing
  to an empty destination.
- Recall outcomes, pytest/Ruff CI, and weekly whole-bundle backups now exist.

Still operational rather than code-complete: populate `watch_dirs`, grant
Safari Full Disk Access if desired, and continue the month-long recall outcome
measurement. Still deliberately deferred until evidence earns them:
embeddings, sync, encryption at rest, supersession relations, and hard OS
isolation.

## Semantic provenance — 2026-08-12 (later the same day)

The anchor experiments proved a distillate's event ids must resolve; the
provenance work asked the harder question: does the claim *carrying* the id
actually rest on that event? The answer is split honestly in two. The
structural half is closed: derived events carry kernel-written derivation
records binding them to the exact disclosed bytes, `ctx why` reconstructs the
full closure to leaf evidence, and a pinned adversarial suite shows forged
chains mechanically rejected and provenance-visibility laundering flagged.
The semantic half — whether a claim's wording is entailed by its evidence —
is deliberately NOT claimed: the kernel's level vocabulary cannot express
semantic support, and the boundary cases that pass every mechanical layer are
pinned in tests so no future change can quietly overclaim. Measured trials:
the reconciler now anchors its notes (88.9% compliance, no coverage cost);
recursive distillation's one observed failure mode — citing transitive ids
the model never read — is refused loudly; and serving the verified evidence
next to a laundered claim dropped a downstream model's poison-following
from 1.00 to 0.20 (earned for further development, not yet for production
serving). See [PROVENANCE.md](PROVENANCE.md) for the full boundary
statement.

## One line

> Twenty-five hours from a sentence about undo to a running daemon that records
> so anything can be proven — including what the AI clients reading it did.
