# GOAL PROMPT — Lane 4: Multi-host backend

**Lane:** `gate-v1-lane-4` · **Depends on Lane 1 (landed).** Parallel with Lanes 2, 3, 6.
**Repo:** `~/contextd`. If it is not there, halt and report — do not search or infer a path.
You are working in an **isolated git worktree** branched from `07f8998`. Do not commit.

## The program's premise for this lane is REFUTED. Read this first.

The program states: *"the flock is belt-and-braces on a single host — SQLite's own writer
serialization would order those appends anyway. The load-bearing mechanism is conditional
consumption inside the append transaction, and that idiom ports to a shared database unchanged.
The multi-host gap is therefore a backend swap, not a redesign."*

**Half of that is right and the other half is wrong, and the difference is this lane.**

**Confirmed by direct experiment before you were dispatched.** The conditional-consumption idiom
does port unchanged. Eight spawn-started OS processes raced one single-use row in PostgreSQL 18.6
using the exact `consume_nonce` shape —
`UPDATE ... WHERE nonce = %s AND consumed_event IS NULL`, with the event INSERT in the same
transaction — five runs, 1 winner and 7 refusals every time, on default `READ COMMITTED`, with
**no advisory locks, no `SELECT ... FOR UPDATE`, and no serializable retry loop.** You do not need
to re-derive that; you may re-run it (`/private/tmp/.../scratchpad/pg_idiom_spike.py`) but it is
settled.

**What does not port is everything around it.** The chain-construction protocol is single-host by
construction, in five independent ways:

1. **The protocol cannot even initialize on Postgres.** `db._connection_root` derives the archive
   file root from the SQLite database's filesystem path (`PRAGMA database_list`) and raises if
   there is none. A Postgres connection has no file path. The first line of the append path fails.
   An explicit archive-root parameter must exist before any interesting question is reachable.
2. **`flock` is a kernel-local advisory lock on a local inode.** `chain_state_paths` puts the
   witness, the recovery journal, and the lock under `home()`, which is a per-process environment
   variable. Two hosts each `flock` **their own file** and both enter the critical section
   simultaneously. The mutual exclusion the entire append protocol rests on evaporates.
3. **Hosts collide on the primary key, they do not merely diverge.** The next event id and the
   `prev_hash` both come from the **local witness file**. Two hosts each compute
   `eid = previous['id'] + 1` from their own stale copy. Best case, one INSERT fails a PK-unique
   violation. Worst case the hash chain **forks**: two events claiming id N+1 with different
   `chain_hash` over the same `prev_hash`, which `_verify_rows` (walking `ORDER BY id` and
   requiring `prev_hash` continuity) cannot represent.
4. **Recovery false-alarms on every normal cross-host append, with no crash involved.** Host A
   appends event 5 and finalizes its witness to 5. Host B's witness still says 4. Host B's next
   connect/append/verify sees `current={id:5}` vs `witnessed={id:4}` and raises `ChainStateError`
   — a healthy two-host system reports its own ledger as tampered.
5. **Lane 1's v2 journal makes it worse, not better.** Its safety argument assumes the enumerated
   outcomes are the only tips any process could have committed. Under two hosts, host B's commit
   is by construction outside host A's outcome set, so host A declares tampering — and in the case
   where host A's stale witness happens to name a tip host B produced,
   `if witnessed in outcomes and current == witnessed` **silently deletes the recovery journal and
   accepts a tip it did not write.**

**So: this lane is a protocol redesign with a backend swap attached.** Say that plainly in your
report. Do not let a delegate-brain "port the driver" and believe it works — items 2–5 all pass a
naive smoke test on one machine.

### The actual design question

The witness-first protocol's safety argument is: an exclusive **local** lock serializes appenders;
the journal is written to durable **local** storage *before* the DB transaction opens; the
**local** witness is finalized *after* the DB commits — so a crash leaves a two-sided state the
local files can adjudicate. All three steps assume one host.

The state must therefore move **into** the database. But the external witness exists precisely so
that the tip is not attested solely by the thing being attested. Moving it into Postgres makes it
strong against concurrency and weaker against a compromised database.

**That trade-off is the deliverable of this lane, and an honest analysis of it is worth more than
a rushed implementation.** Options to weigh explicitly: tip state as a Postgres table updated in
the same transaction as the INSERT (concurrency-safe, self-attesting); tip state in the DB *plus*
a periodic external witness/checkpoint (Lane 3 is building checkpoint signing — coordinate rather
than duplicate); or a DB sequence owning id assignment with the chain hash computed under a
transaction-scoped lock.

## Stop condition, restated and still binding

If the guarantee cannot be preserved across hosts **without adding coordination infrastructure**
— consensus, an external lock service, two-phase commit — stop and report. That would violate the
zero-hosting-cost constraint the product rests on, and the finding is worth more than a
workaround. Note that using PostgreSQL's own transactions is **not** such infrastructure; that is
the database doing its job.

## Environment — already prepared for you

PostgreSQL **18.6** is installed (Homebrew, keg-only) and verified working. Two gotchas that cost
an hour to find:

- **Binaries are not on `PATH`.** They live at `/opt/homebrew/opt/postgresql@18/bin`.
- **`LC_ALL` must be set** or the postmaster dies at startup with
  *"postmaster became multithreaded during startup"*.

A verified test-scoped recipe (does not touch the default cluster, registers no service):

```bash
export PGBIN=/opt/homebrew/opt/postgresql@18/bin LC_ALL="en_US.UTF-8"
D=$(mktemp -d /private/tmp/pg-XXXX)
$PGBIN/initdb -D "$D/data" -U postgres -E UTF8
$PGBIN/pg_ctl -D "$D/data" -o "-p 55432 -k $D" -l "$D/log" -w start
$PGBIN/createdb -h "$D" -p 55432 -U postgres contextd_test
# ... work ...
$PGBIN/pg_ctl -D "$D/data" stop && rm -rf "$D"
```

`psycopg 3.3.4` is installed in the venv. **Verified already:** two independent connections work
concurrently, and DB-level append-only immutability works via a PL/pgSQL `RAISE EXCEPTION` trigger
— both `UPDATE` and `DELETE` on a committed row were refused by the database.

## Definition of done

- [ ] A storage backend interface exists, with SQLite as the default implementation. **Existing
      behavior is unchanged for single-host users; no forced migration.** Note that `sqlite3` is
      bound directly in five modules — `db.py` (18 uses), `attest.py` (10), `backup.py` (18),
      `handoff.py` (5), `ingest.py` (3) — so name the abstraction boundary explicitly or the
      import leaks.
- [ ] A PostgreSQL backend implements the same guarantee using the database's own transaction
      isolation rather than a file lock, with conditional consume + `rowcount` assertion inside
      the transaction.
- [ ] **Chain construction is safe under concurrent writers across hosts** — no forked chains, no
      in-process or in-file `_last_hash` assumption. State the design explicitly; this is the
      failure mode items 3–5 above describe.
- [ ] Append-only immutability enforced at the database level (PL/pgSQL trigger + `REVOKE UPDATE,
      DELETE`), not by convention. A test attempts an `UPDATE` on a committed event row and
      asserts it fails. **Note this is where Postgres is genuinely stronger than SQLite**, whose
      trigger any owner-level process can `DROP` — say so.
- [ ] A **new** `examples/gate_proof/multihost_redemption.py` (operator ruling) runs against the
      Postgres backend from ≥ 2 distinct processes standing in for distinct hosts, ≥ 20 runs, same
      invariant: 1 success, N−1 refusals, all refusals durable, chain verification green.
- [ ] Chain verification works across the whole history regardless of backend.
- [ ] A documented, tested migration path from SQLite to Postgres preserving chain verifiability.

## Known obstacles you will hit

- **`PRAGMA user_version` has no Postgres equivalent.** The whole schema-version refusal path —
  "refuse a newer archive *before touching anything*" — must be redesigned as a metadata table,
  and that table is itself schema the refusal is supposed to run before. Solve it deliberately.
- **`BEGIN IMMEDIATE` has no Postgres equivalent.** MVCC can raise `serialization_failure`, which
  nothing in the codebase retries. The consume idiom is proven safe under `READ COMMITTED` (above);
  anything you add beyond it is yours to prove.
- **FTS5 has no Postgres equivalent.** Swapping backends silently changes search ranking
  (bm25 → ts_rank) and snippet output. **Declare search out of scope** or accept and document the
  divergence — do not let a gate assert retrieval parity.
- **`pytest --backend=postgres` does not parse today.** No `pytest_addoption` exists anywhere.
  Worse, `tests/conftest.py` has an autouse fixture binding every test to a fresh local temp home,
  and that fixture is a **security control** (it is what makes `_assert_test_mode_ok` accept the
  test signer). A multi-host test needs two homes sharing one DB, i.e. it must deliberately
  weaken that isolation. Do this narrowly and visibly, never globally.

## Repo constraints

**MUST NOT touch:** `examples/gate_proof/concurrent_redemption.py` — **frozen, byte-identical**,
global stop condition (note it imports `sqlite3` directly; leave it). `COMPARISON.md` and
`docs/reviews/` (Lane 5 / pre-flight). Files owned by Lanes 2, 3, 6 without coordination. Git
history, tags, remotes. **Do not commit.**

## Verification gates

```bash
cd <your worktree>
python -m pytest -q                                    # SQLite path unchanged; baseline 685
python -m pytest tests/ -q -k "immutability or migration or multihost or backend"
python examples/gate_proof/concurrent_redemption.py    # frozen demo, EXPECT exit 0
# with a test-scoped server running (recipe above):
python examples/gate_proof/multihost_redemption.py --hosts 2
for i in $(seq 1 20); do python examples/gate_proof/multihost_redemption.py --hosts 2 >/dev/null 2>&1 || echo "FAIL $i"; done
```

## Report format

Raw tool output, never a summary of state you did not observe. Include: each gate's output; the
full 20-run multi-host table, every run; the **explicit design decision** on where tip/witness
state lives and what security property that trades away; and one honest paragraph on what a
two-host deployment still cannot guarantee. **If the answer is that the guarantee cannot be
preserved without coordination infrastructure, that report is the deliverable and the lane
succeeded.**
