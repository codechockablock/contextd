# contextd

A personal context daemon: an **append-only life log** + **index** + **gate**,
served to AI clients over **MCP**. One Python process, one SQLite file, no cloud.

The four kernel jobs, each in its smallest honest form:

| Job | v0 implementation |
|---|---|
| **Log** | Append-only `events` table (SQLite WAL); immutability enforced by DB triggers, not discipline; content-addressed blob store for oversized files |
| **Index** | FTS5 over event content (embeddings are v0.1, only after lexical search fails you in a documented way) |
| **Gate** | Every outbound bundle passes `assemble()`: never-leave path rules, secret redaction, a daily token budget — and the exact disclosed bundle is logged back into the archive as an `egress` event |
| **Scheduler** | The budget counter, derived entirely from egress events in the log itself |

Three ingesters, on purpose: watched text/markdown directories, deliberate
notes (`ctx note`), and a read-only sip of Chrome/Safari history (titles+URLs;
`browser.skip_domains` never enters the archive at all — the only pre-ingest
filter, because append-only means ingestion is forever).

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

Tools exposed: `recall(query, budget, purpose)`, `search(query)`, `note(text)`,
`timeline(since, until, source)`. Every MCP read is redacted and logged as an
egress event; `ctx audit` shows the full disclosure history.

## Design commitments

- **Append-only**: `UPDATE`/`DELETE` on `events` abort at the SQLite level.
  Try it: `sqlite3 ~/.contextd/contextd.db "DELETE FROM events"` → refuses.
- **Self-auditing gate**: the archive records what the archive disclosed.
  Egress events are excluded from search, recall, and the timeline tool
  (audit disclosures with `ctx audit`, or MCP `timeline` with
  `source='gate'`), so disclosures never feed on themselves.
- **Local search is free; egress is metered.** `ctx search` is yours and
  unlogged. Anything shaped for a model (`recall`, all MCP reads) is gated,
  budgeted, and logged.
- **Data lives in `~/.contextd/`, never in this repo.**

## Deliberately not in v0

No sync, no multi-device, no encryption-at-rest, no plugin system, no UI, no
screen capture, no embeddings, no cloud anything. Each of these gets built
only when a concrete, logged failure demands it.

## The only evaluation that matters

For one month, every time you think "what was that thing I read/wrote about
X?", ask `ctx recall` first and keep a tally: did it beat grep and your own
memory? If it wins ≥30% of the time, v0.1 is earned.

## Tests

```bash
.venv/bin/python tests/smoke.py
```
