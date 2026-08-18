# GOAL PROMPT — Lane P: PostgreSQL parity

**Program:** gate-v1.1 (gaps closure) · **Repo:** `~/contextd` worktree, branch from the commit
carrying this brief. Baseline: **802 passed + 18 skipped** (820 with Postgres attached, zero
skips). Confirm before your first change; halt if it differs. **Do not commit.**

## Objective

A PostgreSQL archive currently cannot be backed up, handed off, or ingested into, and migration
is SQLite-only. Close that. The operator's ruling: fix Postgres backup, handoff, and ingest.
SQLite remains the default and its behavior must be byte-for-byte unchanged.

## Verified facts you inherit

- `contextd/backup.py` (~834–839) uses `sqlite3` `conn.backup()`; `PGConnection` has no `backup`
  attribute (verified). The `.ctxbackup` bundle format is deterministic tar (`export.py`
  `_deterministic`/`pack_bundle`) — for Postgres, produce the SAME bundle format from row/blob
  export rather than file copy, so `validate_bundle` and restore work identically and chain
  verifiability is preserved across backends. A bundle made from a Postgres archive must restore
  into a SQLite archive and verify (and state plainly if the reverse is out of scope).
- `contextd/handoff.py` hardcodes `"version": 1` for the witness (flagged in the Lane 1 era);
  a Postgres archive has NO witness/recovery files at all (`docs/FORMAT.md` §9 says so) — handoff
  must derive equivalent state from the database tip.
- `contextd/ingest.py` binds `sqlite3` directly (3 sites).
- `contextd/migrate.py` drives `PRAGMA user_version`, which has no Postgres analogue; the
  Postgres backend keeps its own versioning — find it in `contextd/backends/postgres.py` and
  extend rather than invent.
- The backend seam is `contextd/backends/` (`AppendScope`); Lane 4's design notes are in
  `docs/reviews/lane-4-goal-prompt.md`. Postgres 18.6 is keg-only at
  `/opt/homebrew/opt/postgresql@18/bin`, **`LC_ALL` must be set**, socket dirs must be SHORT
  (103-byte limit) — working recipe in that brief.
- **CI blindness is part of this lane:** the 18 Postgres tests skip in CI. Add a `postgres`
  service container to `.github/workflows/ci.yml` and pass `--postgres-url` so they RUN. You are
  the only lane allowed to touch `ci.yml`.

## Definition of done

- [ ] `create_backup` / `restore_backup` / `validate_bundle` work against a Postgres archive;
      round-trip test on BOTH backends (create on A, restore, `verify_chain` green).
- [ ] Handoff works from a Postgres archive; test proves the received archive verifies.
- [ ] Ingest paths work against Postgres (the cursor/watermark machinery included).
- [ ] `ctx security migrate` handles a Postgres archive (or refuses with an exact, tested
      message if migration-in-place is deliberately unsupported — a tested refusal is an
      acceptable answer; silent wrong behavior is not).
- [ ] CI runs the Postgres suite via a service container.
- [ ] SQLite paths byte-identical in behavior: full suite without Postgres still 802+18 plus
      your new tests.

## Constraints

MUST NOT touch: `examples/gate_proof/` (both demos frozen, must keep passing), `attest.py`,
`ledger_sig.py`, `schemas.py`, `pinning.py`, `compliance.py`, `docs/reviews/`, `README.md`,
`COMPARISON.md`. `db.py` only where the seam genuinely requires it — flag every `db.py` hunk
loudly in your report. Never `pip install -e .` into the shared venv. Use test-scoped Postgres
instances on temp datadirs; never a brew service.

## Gates

```bash
python -m pytest -q                       # SQLite-only: no regressions
# with a test server up:
python -m pytest -q --postgres-url "$URL" # zero skips, all green
sh scripts/gates.sh
python examples/gate_proof/concurrent_redemption.py
python examples/gate_proof/multihost_redemption.py --hosts 2 --database-url "$URL"
git status --porcelain examples/gate_proof/ docs/reviews/ README.md COMPARISON.md   # empty
```

Stop conditions: a gate-proof demo fails or needs modification; backup parity requires changing
the bundle format version (report the design instead); the suite was already failing. Report
format: raw gate output, the round-trip evidence both directions you support, every `db.py` hunk
justified, one honest paragraph on what a Postgres archive still cannot do.
