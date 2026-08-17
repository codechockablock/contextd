# GOAL PROMPT — Lane 1: Commerce semantics and core-recorded refusal

**Lane:** `gate-v1-lane-1` · **Status on delivery:** unstarted · **Blocking:** Lanes 2–6 wait on this.
**Repo:** `~/contextd`, master @ `a34ac8a` (verify with `git rev-parse --short HEAD`; if it differs,
record what you actually saw). **If the repo is not at that path, halt and report — do not search
the filesystem, do not consult memory, do not proceed at an inferred path.**

## Mission context (the receiving session has none of the originating conversation)

`contextd` is a local-first, append-only SQLite ledger with an authorization plane. Its
distinguishing property, already proven under adversarial test, is that **authorization is
resolved inside the same database transaction as the append**.

Verified, and not up for re-litigation:

- `attest.authorized_append` (attest.py ~919–957) passes a `bind` callback that runs inside
  `BEGIN IMMEDIATE`; it re-verifies the authorization, then `consume_nonce` (attest.py ~828–856)
  performs a conditional `UPDATE ... AND consumed_event IS NULL` whose `rowcount != 1` raises. The
  event `INSERT` is in the same transaction. Both commit or neither does.
- `db.append_event_checked` (db.py ~680–864) provides that transaction; `_chain_lock`
  (db.py ~359–366) is an `fcntl.flock` exclusive lock.
- Under 8 spawn-started OS processes racing one single-use authorization, across 43 runs:
  1 success, 7 refusals, chain verification green, zero invariant violations. The control arm
  (check/act/record as three transactions) double-redeemed on the first attempt of every run.

Your job is to give that plane the vocabulary and replay semantics a transaction path needs, and
to move refusal recording from the caller into the core.

## Objective

Today the core refuses by **raising**; the durable refusal row is the caller's own second append
(that is what `examples/gate_proof/concurrent_redemption.py` does, and it is why the shipped
`COMPARISON.md` lists caller-appended refusals as a known gap). For adjudication the refusal must
be the **core's** act, not an integration's good manners.

## Definition of done

- [ ] `EVENT_SCHEMAS` in `schemas.py` gains a commerce vocabulary. At minimum: `mandate.bind`,
      `tx.execute`, `tx.refuse`, `tx.inflight`. The registry stays **closed** — unregistered types
      must still refuse metadata (`validate_event_meta`).
- [ ] Redemption outcome is **three-state, not boolean**:
  - `unconsumed` → execute, record outcome, return it
  - `consumed, same act digest` → return the **stored outcome** (benign replay)
  - `consumed, different act digest` → refuse, and **the core records the refusal**
  - `consumed, outcome unknown` → return an explicit **in-flight** state; never guess, never
    re-execute
- [ ] The act digest compared on replay covers **intent** and provably excludes envelope fields.
      A test asserts two honest retries of the same act produce identical digests. **See E1 below —
      this is the single most likely way to get this lane wrong.**
- [ ] The stored outcome is **persisted**, not just an event id. A replay returns the actual
      recorded result.
- [ ] Replayable outcomes have a **configurable TTL**. After it lapses, replay demands
      re-authorization rather than serving a stale receipt. The evidence row is permanent
      regardless; only the replayable result expires.
- [ ] Refusals are appended by the core, inside the transaction that detects them, with **no
      caller cooperation**. Prove it by calling the public API and asserting the refusal row exists
      without the test having appended it.
- [ ] Crash-consistency test: kill a worker between external-act simulation and outcome recording;
      assert the state resolves to **in-flight**, not to a phantom success or a silent
      re-execution. (`db.InjectedCrash` and the existing `fault` hook in `append_event_checked`
      are the intended mechanism; see `tests/test_crash_recovery.py`.)

## Two findings from pre-flight that change how you must build this

Both were verified against the code before this prompt was written. Read
`docs/reviews/gate-v1-preflight.md` §E for the full evidence.

### E1 — The replay digest **cannot** be `prepare_action`'s digest

The mission's original wording pointed at "`prepare_action`'s existing binding". That binding is
**nonce-bound**: the signed action map includes `nonce`, `sequence`, `issued_at`, `expires_at`,
`archive_uuid`, and `key_id`, so `Authorization.digest` differs on **every** retry by construction
— which is exactly what makes it single-use. The intent-only comparison exists today only as a
boolean in `Authorization.matches` (attest.py ~663–678): `action`, `scope`, `arguments`,
`content_digest`, `reason_digest`.

**You must introduce a new intent-only digest** over those five fields (a distinct domain
separator; reuse `canonical.canonical_digest`). Conflating it with the existing action digest
breaks either replay detection or single-use — there is no version that does both. A test must
assert the intent digest is stable across two independently prepared authorizations for the same
act, and that it changes when any of the five intent fields changes.

### E2 — Core-recorded refusal collides with the witness-first recovery protocol

This is why your scope was widened (see below). A naive implementation converts a benign crash
into a **false tamper alarm on the entire ledger**:

- The recovery journal is written **before** `BEGIN`, naming a single `target = {id, chain_hash}`
  computed for **the act's** bytes (db.py ~794–801).
- `_recover_locked` (db.py ~488–499) accepts a committed tip only if it equals `previous`
  (rolled back) or `target` (committed), and otherwise raises **"database tip matches neither side
  of recovery journal"** — the tamper alarm.
- A refusal event has different bytes, hence a different chain hash. Committing it under the act's
  journal means a crash between commit and witness-finalize leaves a tip matching neither side.

The intended shape: a journal that **enumerates both permissible outcomes** (e.g.
`{previous, target_act, target_refuse}`), with recovery accepting either and finalizing whichever
actually committed. This is a **versioned** change: bump `WITNESS_VERSION` (currently `1`, db.py
~115) and handle reading a v1 journal left behind by an older process. Preserve the invariant that
**exactly one** of the enumerated outcomes is durable.

## Repo constraints

**MAY create / modify:** `contextd/schemas.py`, `contextd/attest.py`, `contextd/capability.py`,
`contextd/gate.py`, `contextd/db.py` (**scope widened by operator ruling 2026-08-17 — you may
change the witness/recovery protocol and bump `WITNESS_VERSION`; the earlier "migration only —
additive" restriction is lifted**), `tests/`, `migrations/` (does not exist yet; create if needed).

**MUST NOT touch:**

- `examples/gate_proof/` — **frozen reference point.** It must keep passing **unmodified**.
- `COMPARISON.md` and `docs/reviews/` — owned by Lane 5 / pre-flight.
- Git history, tags, remotes. **Do not commit** — the operator makes his own commits.

## Verification gates

Run from the repo root with the repo's `.venv` python. All must pass.

```bash
cd ~/contextd
python -m pytest -q                                    # baseline is 646 passed; expect no new failures
python examples/gate_proof/concurrent_redemption.py    # EXPECT exit 0, "1 success, 7 refused"
for i in $(seq 1 20); do python examples/gate_proof/concurrent_redemption.py >/dev/null 2>&1 || echo "FAIL $i"; done
python -m pytest tests/ -q -k "replay or three_state or refusal or digest or inflight"
git status --porcelain examples/gate_proof/            # EXPECT empty
git status --porcelain COMPARISON.md docs/reviews/     # EXPECT empty
```

**The gate-proof demo passing unmodified is the single most important signal.** If it needs
changes to pass, the semantics changed underneath the proven claim — that is a stop condition, not
a fix.

## Stop conditions — halt and report, do not improvise past

- The repo is not at `~/contextd`.
- The gate-proof demo fails, or would require modification to pass.
- Any invariant violation in any concurrency test — **including one run in twenty**. Capture the
  process count, timing, and ledger state; report prominently; do **not** retry until it passes and
  report only the pass.
- The existing suite was already failing before your first change (capture the baseline first).
- The work requires touching a file owned by another lane.
- You cannot record the refusal in-transaction without breaking crash recovery — report the exact
  conflict rather than weakening `_recover_locked`'s tamper check. **Weakening that check to make a
  test pass is the worst possible outcome of this lane**; it silently disarms the ledger's
  tamper-evidence.
- Scope pressure toward: a hosted service, an LLM call in the transaction path, custom
  cryptography, or multi-host locking (that is Lane 4). Note and move on.

## Completion report format

Report **raw tool output**, never a summary of state you did not directly observe.

1. Exact output of each verification gate, pasted.
2. The 20-run gate-proof table — every run, not a summary line.
3. New tests added, by name, and what each one would catch if it regressed.
4. What had to be worked around, and how.
5. One honest paragraph: did the three-state semantics survive contact, and does the
   crash-consistency test genuinely exercise the in-flight path? "Survived under these conditions
   and not those" is a better answer than "survived."
