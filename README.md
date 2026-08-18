# contextd

**contextd is a detailed ledger of what humans and AIs do on a computer — one
that can't be quietly rewritten, and that an AI's authorization is spent
*inside*, in the same transaction as the act. Nothing happens off the books.**

One local daemon. A SQLite ledger (or PostgreSQL, for multi-host), an FTS
index, a disclosure gate, and an authority plane. No cloud, no account, no
hosted service.

Most systems in this space record a decision *next to* the act. contextd makes
the authorization a row that the act consumes: the single-use nonce is spent by
a conditional `UPDATE` inside the same transaction that appends the event. The
nonce cannot be spent twice, so a second act cannot be recorded against it —
the **refusal** is, as a durable chained row written by the core itself.

---

## The one property that is demonstrated, not asserted

Eight OS processes race to redeem one single-use operator authorization against
one ledger. Exactly one wins. The seven losers are refused **inside the append
transaction**, and each refusal is a durable, chained ledger row.

```
$ python examples/gate_proof/concurrent_redemption.py
RESULT: 1 success, 7 refused
BASELINE: 7 double-redemption(s) (8 redemptions of one single-use authorization)
```

The same script runs a naive decide-then-record baseline against an identical
barrier, identical schema, and the same minted authorization — the only
difference is whether the check and the record are one transaction or three.
The baseline double-redeems on the first attempt of every run.

| Proof | Recorded result | Re-run it |
|---|---|---|
| Single host, 8 OS processes | 21/21 runs: 1 success, 7 durable redemption-stage refusals, `verify_chain` ok | `python examples/gate_proof/concurrent_redemption.py` |
| Two hosts, separate archive roots, one database | 20/20 runs, chain one unforked line | `python examples/gate_proof/multihost_redemption.py --hosts 2 --database-url …` |

The single-host campaign's method, machine, and per-run outcome table are
recorded in `examples/gate_proof/RESULTS.md`. The multi-host figure has no
written campaign record — re-run the loop above to reproduce it. The demos
themselves are frozen: they are the evidence, so they are not edited to keep
passing.

The multi-host proof matters because it removes the file lock. Each worker gets
its own `CONTEXTD_HOME` — its own witness, its own recovery journal, its own
lock inode — and shares only the database. `fcntl.flock` is a kernel-local
advisory lock on a local inode, so across hosts it does nothing; what is left
holding the guarantee up is in-transaction conditional consumption plus a
`FOR UPDATE` row lock on the singleton tip row. Test:
`tests/test_postgres_backend.py::test_multihost_single_use_authorization_is_redeemed_exactly_once`.

**What this is not.** The ledger prevents double-*recording*. If the authorized
act has an external effect — an email, a payment, an API call — a crash between
the commit and the effect is the classic dual-write problem, and it is not
solved here. See [Known limits](#known-limits).

---

## Quickstart

Verified from a clean clone in a `python:3.12` container. No system packages,
no local knowledge, nothing outside `pip`.

```bash
git clone <this-repo> contextd && cd contextd
python3 -m venv .venv
.venv/bin/pip install -e .

.venv/bin/ctx init                       # creates ~/.contextd (db, config, blobs)
.venv/bin/ctx note "first entry: contextd is alive"
.venv/bin/ctx search contextd            # FTS through the gate — redacted and receipted
.venv/bin/ctx verify                     # recompute the whole hash chain
.venv/bin/ctx status
```

Then watch the property prove itself — the demo builds its own throwaway
archive and refuses to run against a real one:

```bash
.venv/bin/python examples/gate_proof/concurrent_redemption.py
```

Ingest, disclosure, and audit:

```bash
# edit ~/.contextd/config.toml -> set [ingest] watch_dirs
.venv/bin/ctx ingest                     # one-shot scan
.venv/bin/ctx recall "contextd" --purpose "trying recall"   # gated + logged
.venv/bin/ctx audit                      # what left the machine, when, for what
.venv/bin/ctx compliance                 # EU AI Act logging evidence (§ below)
```

Run the daemon in the foreground with `ctx watch`, or install the launchd agent:

```bash
cp launchd/com.contextd.watch.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.contextd.watch.plist
```

### Hook it into a model

```bash
claude mcp add contextd -- /absolute/path/to/contextd/.venv/bin/ctx serve
```

Tools: `recall`, `search`, `note`, `timeline`, `loop_candidate`, `loop_list`,
and the grant-gated `loop_confirm` / `loop_dismiss` / `decision_supersede`
(these refuse without an active operator delegation). An operator can restrict
the registry itself — disallowed tools are absent from `tools/list`:

```bash
ctx serve --tools recall search timeline
```

This is a capability allowlist, not authentication. `CONTEXTD_CLIENT` is a
self-asserted audit label and proves nothing. Other clients connect the same
way — see [clients/](clients/).

---

## Install

```bash
pip install -e .                 # base: mcp, cryptography
pip install -e '.[dev]'          # pytest, ruff
pip install -e '.[pqc]'          # cryptography >= 47 — ML-DSA checkpoints
pip install -e '.[postgres]'     # psycopg — multi-host archives
```

Base dependencies are exactly `mcp` and `cryptography`. The extras:

- **`pqc`** is a **version floor, not a new library.** `cryptography` ≥ 47
  exposes ML-DSA (FIPS 204) natively through OpenSSL — no third-party PQC
  package, no C toolchain. The base install stays at ≥ 42 so nothing regresses;
  checkpoint signing degrades to classical-only and says so rather than failing.
- **`postgres`** is for multi-host archives only. SQLite is the default and
  requires nothing extra. Installing this extra migrates nothing.
- **`dev`** is the test and lint toolchain.

Python ≥ 3.11. CI runs 3.11 and 3.13.

---

## Backends

| | SQLite (default) | PostgreSQL |
|---|---|---|
| Setup | none | `[postgres]` extra + `CONTEXTD_DATABASE_URL` |
| Hosts | one | many, sharing one database |
| Append exclusion | `fcntl.flock` on a local lock file | `FOR UPDATE` on a singleton tip row, inside the append transaction |
| Chain tip | external `chain-witness.json`, fsync'd | a row in the database |
| Immutability | `BEFORE UPDATE`/`BEFORE DELETE` triggers raise `ABORT` | PL/pgSQL trigger **plus** privilege revocation: the app role has `INSERT`/`SELECT` and no `UPDATE`/`DELETE`/`TRUNCATE` |
| Search | FTS5 | **refuses** — `SearchUnsupported`, rather than silently ranking differently |
| Backup, handoff, ingest, schema migration | yes | **not yet** — all four are SQLite-only |

Nothing is auto-migrated. An existing single-host install is unaffected by the
Postgres backend existing. The one-time SQLite→Postgres archive migration is
implemented and tested (`test_migration_sqlite_to_postgres_preserves_the_chain`);
what does not exist is ongoing *schema* migration of a live Postgres archive.

**The trade is real and runs in the honest direction.** On SQLite the database
and the witness are two files in one directory under one uid: whoever can
rewrite events can rewrite the witness a microsecond later. Postgres removes
that adjacency and gives the *application credential* a privilege separation
SQLite never had — contextd's own credential cannot rewrite history or forge
the tip. But a Postgres superuser, the table owner, or root on the database
host can disable the triggers, rewrite `events`, and set the tip to match in
one internally consistent transaction, and there is no external witness there
to contradict them. Against that actor SQLite was strictly better, because the
same actor would additionally need write access to a *different machine's*
filesystem. Closing it needs a periodic signed checkpoint exported off the
database host. **Not built. Still owed.** See
[docs/SECURITY.md](docs/SECURITY.md) §10.

---

## What is in the ledger

Every record is a row in one append-only table, chained to the one before it,
validated against a **closed** metadata registry — an unregistered event type
cannot carry metadata at all, and undeclared fields are refused rather than
dropped.

- **Ingest**: watched text/markdown directories, deliberate notes, a read-only
  sip of Chrome/Safari history (titles + URLs), and Claude Code dialogue —
  role-tagged, tool noise dropped, secrets redacted before storage.
  `browser.skip_domains` never enters the archive at all, because append-only
  means ingestion is forever.
- **Disclosures**: every archive-derived outbound payload passes one gate —
  never-leave rules, redaction, and a pre-dispatch `egress` receipt recording
  the exact disclosed bytes, committed atomically with the budget decision.
- **Authorizations**: `mandate.bind` consumes the nonce; `tx.execute`,
  `tx.refuse`, and `tx.inflight` record what became of it.
- **Instruction positions**: `pin` and `act` events digest the skills, tool
  definitions, and prompt fragments an act was taken under.
- **Operator acts**: notes, loops, grants, decisions, key registry changes —
  each carrying a verified `OperatorActionV1` signature or nothing.

The byte-level format is specified independently of this codebase in
**[docs/FORMAT.md](docs/FORMAT.md)** (`contextd-record-format v1`): the row
shape, the chain-hash computation, the canonical encoding and why it refuses
floats, the signing domains, the witness and recovery journals, and the closed
vocabulary. An adjudicator in 2035 should be able to parse a record written
today with a SHA-256 implementation and a signature verifier, and nothing else.
`tests/test_format_spec.py` re-derives the chain hash and the canonical
encoding from that document's own prose and checks them against real rows and
the frozen vectors, so the spec cannot drift from the code in silence.

---

## Integrity, in three layers

1. **Hash chain** — every event commits to the one before it. Detects naive
   rewrites, deletion, insertion, reordering. Defeated by an attacker who
   recomputes the chain.
2. **External witness** — `chain-witness.json` records the tip, fsync'd, with
   a durable recovery journal. Detects loss of the final row; makes an
   interrupted append resolve to zero or exactly one committed event. Defeated
   by the same attacker, who can rewrite the file.
3. **Service signatures** — over accepted envelopes and chain tips, under a
   key the attacker is not assumed to hold. **Not** defeated by chain
   recomputation.

Every signature record names the scheme that produced it (`ecdsa-p256-sha256`,
`ml-dsa-44/65/87`), and verification dispatches on that name rather than
assuming one. This is the piece that is expensive to retrofit: once a million
records exist with no algorithm field, introducing a second scheme means
guessing which rows are which. Checkpoints — not events — carry the
post-quantum signature, because an ML-DSA-44 signature is ~38× an ECDSA one per
event and the chain hash at event *N* already commits to everything beneath it.
That is Certificate Transparency's signed-tree-head model.
Tests: `tests/test_crypto_agility.py` (21 tests).

**The window you must know about.** `checkpoint_interval_events` (default 100)
is how many events may pass before the tip is checkpointed again, and that
number *is* the exposure window: events appended since the last checkpoint are
covered by local state alone. `ctx compliance` reports that window as
`uncovered_events` rather than leaving you to assume it away.

This is tamper-**evident**, not tamper-proof. Read
[docs/SECURITY.md](docs/SECURITY.md) — especially its "Implementation status"
table, which says what is actually enforced on this tree — before treating any
of it as a security boundary.

---

## Compliance evidence

```bash
ctx compliance              # JSON to stdout
ctx compliance -o report.json
```

A deterministic, read-only artifact: event span, count, chain verification
result, and checkpoint coverage, keyed to the EU AI Act articles that actually
govern logging. It appends nothing, calls no model, and returns **no
pass/fail verdict**. Two runs over an unchanged archive are byte-identical
(`now` is an explicit argument, not an ambient clock read), so quarterly
artifacts diff cleanly.

Three things it is careful to get right, because the surrounding industry
frequently does not:

- **Article 12** is a *logging-capability* design requirement on high-risk
  systems. It is not a retention period.
- The **six-month figure is a retention floor** in **Art. 19(1)** (providers)
  and **Art. 26(6)** (deployers) — both limited to logs under that party's
  control, both displaceable by other Union or national law.
- **The Regulation nowhere requires append-only or tamper-evident storage.** An
  ordinary rotated log file can satisfy Articles 12, 19(1) and 26(6). This
  ledger is *one way* to satisfy them and an evidentiary advantage — it makes
  "these logs were not edited" checkable rather than asserted. Anyone telling
  you the Regulation mandates a tamper-evident ledger is selling something.

Applicability: 2 Aug 2026 for Annex III (Art. 6(2)); 2 Aug 2027 for Art. 6(1)
product-embedded systems.

---

## The rest of the daemon

Beyond the authority plane, contextd is a working personal context system.
Briefly, with pointers:

- **Every archive read is gated.** `ctx search`, `ctx recall`, and every MCP
  read go through one disclosure primitive and land as an `egress` receipt —
  including `search`, which used to be a raw local FTS read that printed
  unredacted snippets and logged nothing. That bypass is closed; the only
  reads that stay unlogged are the ones that disclose no archive content
  (`ctx why`, `ctx lineage`, `ctx verify`). `recall --mode synthesis` serves a
  distillate in which every claim carries a bracketed event id that resolves.
- **Provenance.** `ctx why <id>` walks claim → disclosure → cited events →
  leaf evidence, and reports what is *mechanically verified* separately from
  what remains a semantic judgment — which the kernel never asserts.
  [docs/PROVENANCE.md](docs/PROVENANCE.md)
- **Checkpoint/restore.** `ctx checkpoint` compiles a project's *active state*
  so a fresh model can continue the work. Measured against full-transcript
  ceilings; limits stated in [docs/DECISIONS.md](docs/DECISIONS.md).
- **Open loops.** Operator-declared commitments that survive the session, with
  model proposals inert until confirmed. Four preregistered attempts to
  *infer* them from dialogue failed; contextd does not mind-read.
  [docs/OPEN_LOOPS.md](docs/OPEN_LOOPS.md)
- **Delegation grants.** Class-scoped, expiring, revocable, never grantable by
  a model. [docs/GRANTS.md](docs/GRANTS.md)
- **Backup and restore drill.** Manifest-hashed bundles, plus a weekly drill
  that actually restores one and verifies chain, blobs, and behavioral
  equivalence — a backup that has never been restored is a hope.
- **Health sweep and lineage gauge.** Content-NULL verdict events; advisory,
  never quarantining.
- **Experiments.** `contextd/experiment.py` preregisters designs as ledger
  events *before* any run, with a negative control that came back Δ 0.00,
  p = 1.0 — the harness can demonstrably answer "this context barely matters."

---

## Deliberately not here

- **No hosted service, no sync, no multi-device, no account.** Multi-host means
  several of your machines sharing one database you run.
- **No LLM in the kernel.** The kernel never calls a model. Everything that
  does — the reconciler, synthesis, the lineage judge — lives in `hooks/` and
  is a *client* like any other, subject to the same gate. `ctx compliance`
  contains no model call of any kind.
- **No network code in the SQLite path.** Every file allowed to mention
  network vocabulary is pinned in `tests/network_surface.txt` and
  `scripts/gates.sh` fails on a new match. Note the scope honestly: that gate
  is **lexical**, and `psycopg` is not in its vocabulary — the PostgreSQL
  backend is the one change that genuinely gives contextd network capability,
  and the grep cannot see it. The zero-network claim is true of the **default
  SQLite backend only**.
- **No encryption at rest, no plugin system, no UI, no screen capture, no
  embeddings.** Each gets built when a concrete, logged failure demands it.
- **No trajectory scoring.** Advisory trajectory-evidence scoring was built and
  is deliberately **held unmerged**: its detector's calibrated true-positive
  rate did not transfer from the development corpus to a held-out slice, and
  the honest version was judged worth more than the feature line. It is not in
  this package and its numbers are not product claims.

---

## Known limits

Stated first-person, because a README with no limits section should not be
believed. The full list, with the alternatives that beat contextd on each,
is in [COMPARISON.md](COMPARISON.md).

- **I cannot make your counterparty idempotent.** Exactly-once *effects*
  require an idempotent receiver or a reconciliation loop. I supply neither.
- **I have a single-operator authority plane.** One human, one key registry.
  No roles, no quorums, no separation between who grants and who audits.
- **A mandate can get stuck in flight.** If the act's callback raises an
  unknown exception or returns an oversized outcome, the mandate is consumed
  with no recorded outcome and there is no operator-facing way to resolve it.
  That is deliberate — the core will not guess an outcome — but it is a dead
  end today.
- **Pinning binds the caller's claim, not the file.** contextd never opens the
  artifact; it pins the bytes the caller said it read. Four attacks survive:
  TOCTOU between digest and read, an incomplete artifact list, malice present
  at first sight, and renaming the position. None is unique to contextd — the
  same four hold for every registration-time digest scheme.
- **Postgres archives cannot be backed up or handed off**, and a Postgres
  superuser is outside the trust model entirely (see [Backends](#backends)).
- **This tree is `development`, not `hardened`.** No dedicated service UID, no
  enrolled hardware signer on a fresh clone. `ctx security doctor --strict`
  exits nonzero here, correctly.

---

## Tests

```bash
.venv/bin/pip install -e '.[dev]'
sh scripts/gates.sh            # ruff + pytest + smoke + network-surface grep
```

The suite includes deterministic 32-way budget and append races and 16-way
redemption races (**threads** — the cross-*process* evidence is the gate-proof
demo above), crash fault injection at three interruption points
(`before_db_commit`, `after_db_commit`, `before_witness_finalize`) via an
injected fault hook rather than a killed process, a real stdio MCP capability
test, a model-call inventory, and corrupt-backup restore cases. It always
installs a temporary `CONTEXTD_HOME`.

Postgres tests **skip** unless you point them at a throwaway server — so a
default run is green whether or not that backend works. Switch them on:

```bash
python -m pytest tests/test_postgres_backend.py --postgres-url "postgresql://…"
```

## Security disclosure

See [SECURITY.md](SECURITY.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).
