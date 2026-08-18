# GOAL PROMPT — Lane 3: Crypto agility and checkpoint signing

**Lane:** `gate-v1-lane-3` · **Depends on Lane 1 (landed).** Parallel with Lanes 2, 4, 6.
**Repo:** `~/contextd`. If it is not there, halt and report — do not search or infer a path.
You are working in an **isolated git worktree** branched from `07f8998`. Lane 2 is editing
`contextd/schemas.py` elsewhere; you should not need that file. Do not commit.

## Objective

Evidence meant to survive a dispute in 2035 cannot rest on a signature scheme that may be
forgeable by then. Per-event post-quantum signing is unaffordable — ML-DSA-44 signatures are
2,420 bytes with 1,312-byte public keys (verified against FIPS 204) against a 64/32-byte
classical signature, roughly 38× on a per-event ledger. The chain hash at event N already commits
to every event beneath it, so **sign checkpoints, not events**. This is Certificate
Transparency's signed-tree-head model.

## Scout findings that change this lane — read before designing

All verified against the code at `07f8998`. Several contradict the original program text.

### 1. liboqs is NOT needed. Delete it from your plan.

The program specified ML-DSA behind an optional `[pqc]` extra using liboqs, and warned about its
C dependency and upstream production disclaimer. That is obsolete: **`cryptography` 50.0.0 with
OpenSSL 4.0.1 — already installed in this venv — provides ML-DSA natively.**

```
ML-DSA AVAILABLE natively: MLDSA44PrivateKey, MLDSA44PublicKey, MLDSA65..., MLDSA87..., MLDSAMuHasher
```

**Gate zero:** confirm this yourself before designing (`from cryptography.hazmat.primitives.asymmetric import mldsa`).
If confirmed, there is no third-party PQC dependency, no C toolchain, and no optional-extra
portability cost. An `[pqc]` extra may still be the right packaging if you need to pin a
`cryptography` minimum, but it is a version floor, not a new library.

### 2. The per-append signature is ECDSA P-256, not Ed25519.

The program says "Ed25519 stays on the per-append path." The repo does not use Ed25519 anywhere.
`ledger_sig.py` signs with `ec.ECDSA(hashes.SHA256())` over SECP256R1 and **asserts P-256 in four
places** (~128–131, ~149, ~255–258), refusing anything else. Write the brief's intent, not its
wording: the fast classical signature stays as it is.

### 3. Three signing domains, not one. Partial coverage fails the suite.

`ledger_sig.py` signs three object types, each with its own domain separator (~45–47):

- `contextd.ServiceEnvelopeV1` — event envelopes, 7 semantic fields (`envelope()` ~264–280)
- `contextd.ServiceTipV1` — chain tips (`tip_payload()` ~424–426)
- `contextd.ProtectedCheckpointV1` — **a checkpoint record already exists** (~580–596)

`verify_ledger` (~513) checks events *and* tips. An agility change covering only envelopes leaves
tips and checkpoints on the old scheme and fails the existing suite. Read `checkpoint_record()`
before designing a checkpoint — you may be extending something rather than inventing it.

### 4. No algorithm identifier exists anywhere. This is the piece that must land.

Verbatim schema — note there is no `alg` column in any of the three tables:

```sql
CREATE TABLE IF NOT EXISTS service_keys (
  key_id TEXT PRIMARY KEY, public_pem TEXT NOT NULL, created INTEGER NOT NULL, retired INTEGER);
CREATE TABLE IF NOT EXISTS service_signatures (
  event_id INTEGER PRIMARY KEY, key_id TEXT NOT NULL, digest TEXT NOT NULL,
  signature TEXT NOT NULL, signed_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS service_tips (
  tip_id INTEGER PRIMARY KEY, chain_hash TEXT NOT NULL, key_id TEXT NOT NULL,
  signature TEXT NOT NULL, signed_at INTEGER NOT NULL, cutover INTEGER NOT NULL DEFAULT 0);
```

**This DDL is duplicated in two files** — `contextd/db.py` (~115–135) and `contextd/ledger_sig.py`
(~51–73) — and both are executed by `migrate()`. Edit both together or new archives and migrated
archives diverge. Also: `migrate()` applies schema only via `executescript` of
`CREATE TABLE IF NOT EXISTS` and **has no column-addition path**, so adding a column is real
migration work, not a no-op.

### 5. Hybrid mode is a primary-key change, not a column addition.

`service_signatures.event_id` and `service_tips.tip_id` are **PRIMARY KEY**, permitting exactly
one signature row per object, and the verifier assumes a single row
(`SELECT * FROM service_signatures WHERE event_id = ?`). Storing a classical *and* a PQC
signature is structurally impossible without one of: a composite PK, a parallel table, or packing
both into the one TEXT column. **Pick one explicitly and justify it.** "Add an `alg` column"
alone buys single-algorithm agility, not hybrid.

### 6. Hard constraint from Lane 1: the signature must commit inside the append transaction.

`prepare_append_signing(conn)` is called once per append **inside the chain lock, after the chain
hash, before the recovery journal and before `BEGIN IMMEDIATE`** — because key loading may need
its own commit. `sign_accepted_append` then runs **inside** the transaction, and the same signing
context is reused on the refusal branch after `ROLLBACK TO SAVEPOINT`.

Lane 1's v2 recovery journal enumerates outcomes as `(id, chain_hash)` pairs and says nothing
about signatures. That is sound **only** because the signature insert is transactional with the
row: `_recover_locked` completes whichever outcome is durable without re-checking that a
signature exists. **Moving any signature to a file, a post-commit countersign, or an external
signer daemon silently breaks crash recovery** — a crash would leave a witnessed, chain-valid
event with no PQC signature and recovery would report success. Keep key loading outside the
transaction and signing inside it.

### 7. Two environment facts that will bite.

- **`cryptography` is not declared as a dependency.** `pyproject.toml` line 7 is
  `dependencies = ["mcp>=2"]`, yet `ledger_sig.py`, `attest.py`, `backup.py`, `export_crypto.py`
  and 6+ test files import it unguarded. `pip install -e ".[dev]"` — what CI runs — does not
  install it. This is a pre-existing bug. Fixing it is in scope and correct; **say so loudly in
  your report** rather than slipping it in.
- **CI does not cover this venv.** `.github/workflows/ci.yml` runs Python 3.11 and 3.13; the venv
  is 3.14.3. An ML-DSA gate verified locally is *untested in CI* unless you pin a `cryptography`
  minimum that exposes `mldsa` on those versions and confirm it. State the residual risk.

## Definition of done

- [ ] Every signature record carries an **algorithm identifier**, and verification dispatches on
      it. This is the piece that is expensive to retrofit once records exist — **it lands even if
      nothing else in this lane does.**
- [ ] The existing classical scheme stays on the per-append path, unchanged and fast.
- [ ] A checkpoint signs the chain tip on a configurable interval. The default is **justified in
      the docs as an exposure-window decision**: events not yet covered by a checkpoint are
      protected only by local state.
- [ ] ML-DSA checkpoint signing available, using `cryptography`'s native ML-DSA. Base install must
      not regress.
- [ ] Hybrid mode: checkpoints signed with both schemes during transition, so classical-only
      verifiers still work. Requires the PK decision in finding 5.
- [ ] Verification of historical records works **across an algorithm change**: write under A,
      rotate to B, verify the whole chain.
- [ ] Docs state plainly what a checkpoint does and does not prove, including the uncovered window.

## Explicitly out of scope

Any novel or custom cryptography. Signature-size reduction is **not** an engineering target — the
bits are the security, and a transform that reliably shrank an ML-DSA signature would be a
distinguisher, which is an attack. NIST-standardized schemes only. What makes a 2035 record
credible to an adjudicator is a scheme that survived years of public cryptanalysis, not clever
compression.

## Verification gates

```bash
cd <your worktree>
python -m pytest -q                                     # baseline 685; no new failures
python -m pytest tests/ -q -k "checkpoint or agility or rotation or signature or ledger_sig"
python examples/gate_proof/concurrent_redemption.py     # EXPECT exit 0, "1 success, 7 refused"
git status --porcelain examples/gate_proof/ COMPARISON.md docs/reviews/   # EXPECT empty
```

## Stop conditions — halt and report

- The gate-proof demo fails or needs modification. `examples/gate_proof/` is **frozen**.
- The baseline suite was already failing before your first change.
- Native ML-DSA turns out not to be usable and the only path is a third-party C library — report
  rather than vendoring one.
- You cannot add hybrid support without a schema change you are not confident in — report the
  three options and your recommendation instead of guessing.
- Any impulse toward custom cryptography, or toward moving a signature outside the append
  transaction.

## Report format

Raw tool output, never a summary of state you did not observe. Include: each gate's output; the
PK decision you made for hybrid and why; whether `cryptography` was added to `dependencies` and
what that changes for CI; and one honest paragraph on what the checkpoint does **not** prove.
