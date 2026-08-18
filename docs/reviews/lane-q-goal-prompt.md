# GOAL PROMPT — Lane Q: Authority-plane follow-ups

**Program:** gate-v1.1 (gaps closure) · **Repo:** `~/contextd` worktree, branch from the commit
carrying this brief. Baseline: **802 passed + 18 skipped**. Confirm first; halt if it differs.
**Do not commit.** Parallel with Lanes P and R — you own `attest.py`, `ledger_sig.py`,
`schemas.py`, `migrate.py`; they do not touch them.

## Four gaps, all recorded during the Gate v1.0 program

### 1. Exported signed checkpoint (the DB-owner hole — flagged by Lanes 3 AND 4)

Checkpoint signatures live in `service_checkpoints`, inside the archive being attested. An
attacker who owns the storage (SQLite file, or Postgres superuser) rewrites chain and
checkpoints together, consistently. Build `ctx checkpoint export <dest>`: append checkpoint
records (tip id, chain hash, algorithm-tagged signatures, timestamps) to a destination OUTSIDE
the archive, in an append-friendly, `docs/FORMAT.md`-documented form, plus
`ctx checkpoint verify <dest>` proving the archive's history is consistent with every exported
checkpoint (and screaming on rollback). **Scope honestly:** on one machine under one uid this is
advisory — the export's value is realized when `<dest>` is somewhere the archive's owner cannot
write (another host, cloud sync, `chattr`/other-uid). Say exactly that in the docs; do not
oversell. Document the format as a FORMAT.md addendum (bump the spec doc version; keep
`tests/test_format_spec.py` green and extend it).

### 2. In-flight mandate resolve path

A `perform()` that raises an unknown exception, or returns an oversized outcome, leaves a
mandate in-flight forever — no operator-facing resolution exists (pinned by
`tests/test_commerce_redemption.py::test_an_unknown_failure_leaves_the_mandate_in_flight`).
Build the operator act: a new `ACTION_CLASS` (e.g. `mandate.resolve`) redeemed through the
existing `OperatorActionV1` machinery — never a second authorization path — that records the
operator's attested resolution (`succeeded` or `failed`, with reason) as a ledger event and
transitions the redemption row. The core never guesses an outcome: resolution is the operator
asserting what they verified externally. Replay after resolution serves the attested outcome;
re-execution stays impossible. Wire `ctx mandate resolve` in `cli.py`.

### 3. Refusal-row growth channel

The refusal branch deliberately never consumes the nonce (a refused act must not burn the
operator's signature), so one valid authorization can mint unbounded core-recorded refusal rows
(merge-audit finding). Design a minimal mitigation that does NOT weaken evidence — e.g. after N
durable refusals for one nonce, further attempts refuse WITHOUT appending (the first N are the
evidence; the flood adds nothing). Whatever you choose: justify it in the code comment, cap
configurable, default stated, tested including the boundary, and the refusal-counting query must
stay cheap inside the append transaction.

### 4. `migrate --dry-run` under-report

`migrate._REQUIRED_TABLES` omits `redemptions`, so plan output under-reports what apply creates
(audit finding). Add it, plus a test that diffs `plan()`'s table set against `db.SCHEMA`'s
`CREATE TABLE` statements so the two can never drift again.

## Constraints

MUST NOT touch: `examples/gate_proof/` (frozen), `backends/` and `backup.py`/`handoff.py`/
`ingest.py` (Lane P owns), `ci.yml` (Lane P), `scripts/gates.sh` (Lane R), `pinning.py`,
`README.md`, `COMPARISON.md`, `docs/reviews/`. `db.py` only if the refusal cap genuinely needs
it — flag every hunk. Crash-recovery semantics are sacred: nothing you add may move a signature
or a write outside the append transaction, and `_recover_locked`'s tamper alarm is untouchable.
Never `pip install -e .` into the shared venv.

## Gates

```bash
python -m pytest -q                                    # no regressions vs 802+18
python -m pytest tests/ -q -k "checkpoint_export or resolve or refusal_cap or required_tables"
sh scripts/gates.sh                                    # note: R may change gates.sh in parallel — run the pinned copy from YOUR worktree
python examples/gate_proof/concurrent_redemption.py    # exit 0, unmodified
git status --porcelain examples/gate_proof/ docs/reviews/ README.md COMPARISON.md   # empty
```

Stop conditions: any change would touch the recovery protocol or move signing out of the append
transaction (report the design conflict instead); the demo fails; baseline already failing.
Report: raw gates, each gap with its closing test id, the refusal-cap design you chose and what
an attacker can still do, one honest paragraph on what checkpoint export does NOT prove on a
single machine.
