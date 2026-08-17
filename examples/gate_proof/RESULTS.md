# gate-proof: concurrent redemption results

- **Date:** 2026-08-17
- **Machine:** macOS 26.5.2 on Apple Silicon (`macOS-26.5.2-arm64-arm-64bit-Mach-O`, Darwin 25.5.0)
- **Python:** 3.14.3 (the repo's `.venv`) — **SQLite:** 3.53.4
- **Repo state:** `master` @ `a34ac8a`
- **Script:** `examples/gate_proof/concurrent_redemption.py` (final version;
  earlier drafts produced identical outcome counts in 22 additional runs)
- **N (concurrent OS processes):** 8 per side, `multiprocessing` spawn start
  method. Each run asserts 8 distinct PIDs reported, all worker exit codes 0,
  and no worker alive after join.
- **Run count:** 21 default-mode runs of the final script (1 verification run
  + a 20-run campaign; every default-mode run executes both the atomic path
  and the naive baseline against fresh temporary archives), plus
  `--baseline-only` runs recorded below.

## Claim under test

One single-use operator authorization, shared by 8 OS processes racing to
redeem it against the same ledger file, must produce exactly 1 successful
redemption and 7 refusals; every refusal must exist as a durable ledger row
after the workers exit; and the ledger's own integrity verification
(`verify_chain`) must pass.

The run's `ok` predicate is stricter than the headline: it also requires the
nonce row to name exactly the winning event as its consumer, and every
refusal row's stage to be `redemption` — i.e. each loser was refused *inside
the append transaction*, after its preflight verification of the same
authorization had already succeeded. A run refused at preflight would not
have exercised the property under test and is counted as a failure.

## What this proves, precisely

The demonstrated guarantee belongs to the composed system, and two layered
mechanisms produce it: appends serialize on an exclusive `fcntl.flock` chain
lock (`db.py`, `_chain_lock`), so racing processes enter the critical
section one at a time, and the in-transaction re-verification plus
conditional nonce UPDATE (`attest.py`, `reverify_for_use` / `consume_nonce`)
is what actually refuses the losers — and would also protect a code path
that reached nonce consumption without the chain lock (`consume_nonce` is a
public primitive; custom appenders call it directly). This demo proves the
end-to-end property under process concurrency; it does not isolate either
mechanism alone, because the shipped system deliberately layers them.

## Outcome table — 20-run campaign (final script)

| run | atomic: successes | atomic: durable refusal rows | refusal stages | verify_chain | atomic wall | baseline: redemptions of 1 authorization | baseline: doubles | baseline wall | exit |
|----:|---:|---:|:---|:---|---:|---:|---:|---:|---:|
|  1 | 1 | 7 | redemption only | ok | 0.16s | 8 | 7 | 0.19s | 0 |
|  2 | 1 | 7 | redemption only | ok | 0.15s | 8 | 7 | 0.18s | 0 |
|  3 | 1 | 7 | redemption only | ok | 0.15s | 8 | 7 | 0.18s | 0 |
|  4 | 1 | 7 | redemption only | ok | 0.15s | 8 | 7 | 0.19s | 0 |
|  5 | 1 | 7 | redemption only | ok | 0.15s | 8 | 7 | 0.19s | 0 |
|  6 | 1 | 7 | redemption only | ok | 0.15s | 8 | 7 | 0.19s | 0 |
|  7 | 1 | 7 | redemption only | ok | 0.15s | 8 | 7 | 0.19s | 0 |
|  8 | 1 | 7 | redemption only | ok | 0.16s | 8 | 7 | 0.19s | 0 |
|  9 | 1 | 7 | redemption only | ok | 0.15s | 8 | 7 | 0.19s | 0 |
| 10 | 1 | 7 | redemption only | ok | 0.16s | 8 | 7 | 0.20s | 0 |
| 11 | 1 | 7 | redemption only | ok | 0.16s | 8 | 7 | 0.20s | 0 |
| 12 | 1 | 7 | redemption only | ok | 0.16s | 8 | 7 | 0.18s | 0 |
| 13 | 1 | 7 | redemption only | ok | 0.15s | 8 | 7 | 0.19s | 0 |
| 14 | 1 | 7 | redemption only | ok | 0.16s | 8 | 7 | 0.19s | 0 |
| 15 | 1 | 7 | redemption only | ok | 0.15s | 8 | 7 | 0.19s | 0 |
| 16 | 1 | 7 | redemption only | ok | 0.15s | 8 | 7 | 0.19s | 0 |
| 17 | 1 | 7 | redemption only | ok | 0.14s | 8 | 7 | 0.19s | 0 |
| 18 | 1 | 7 | redemption only | ok | 0.15s | 8 | 7 | 0.19s | 0 |
| 19 | 1 | 7 | redemption only | ok | 0.15s | 8 | 7 | 0.18s | 0 |
| 20 | 1 | 7 | redemption only | ok | 0.15s | 8 | 7 | 0.19s | 0 |

Zero occurrences of a `preflight`-stage refusal across the whole campaign
(verified by grep over the captured logs). The verification run before the
campaign produced the identical outcome. `--baseline-only` runs
double-redeemed on their first attempt every time (8 redemptions, 7 doubles,
exit 0).

## Invariant violations

**None.** 21 of 21 final-script runs (and 22 earlier-draft runs): exactly 1
success, exactly 7 durable redemption-stage refusal rows, nonce consumed by
the winner's event id, `verify_chain` `ok=True`, all workers exited 0.

## Notes on the baseline

- The naive decide-then-record baseline double-redeemed on the **first
  attempt of every run** (7 doubles out of 8 workers). No artificial
  narrowing of the race window was needed — but be clear about why: the
  workers synchronize on a barrier immediately before the sub-millisecond
  check, while each act is a slower serialized append, so at N=8 the
  all-pass-the-check outcome is essentially deterministic by construction.
  The barrier is the honest analogue of several requests arriving at once;
  the repetition count adds little evidence beyond the first run, and the
  claim is only that the failure mode is real and easily reached, not that
  it is subtle.
- The same barrier is applied to both paths, so the comparison is
  symmetric: identical concurrency, identical schema, identical minted
  authorization — the only difference is whether the check and the record
  are one transaction or three.
- The baseline's bookkeeping UPDATE is the maximally naive unconditional
  variant (last writer wins), mirroring the UPDATE-by-trace-id audit model
  described in `COMPARISON.md`. A less naive baseline with a conditional
  mark (`AND consumed_event IS NULL`) would *detect* the race after the
  fact — its late workers' marks would fail — but every worker has already
  performed and recorded the act by then, so the double-redemption counts
  would be identical. The atomic path differs in preventing the act, not
  in noticing it.
- After the baseline race the nonce row points at one consuming event and
  looks internally consistent. Only counting the redemption events reveals
  that one authorization was redeemed eight times. That asymmetry — the
  bookkeeping heals, the acts remain — is the observable difference between
  decide-then-record and deciding inside the record.

## Reproduce

From the repo root, using the repo's `.venv` python:

```bash
python examples/gate_proof/concurrent_redemption.py            # atomic + baseline, exit 0 iff invariant holds
python examples/gate_proof/concurrent_redemption.py --baseline-only
for i in $(seq 1 20); do python examples/gate_proof/concurrent_redemption.py > /dev/null 2>&1 || echo "FAILED on run $i"; done
```

The pass/fail loop above discards output; the outcome table in this file was
produced by capturing each run's stdout and reading its `SUMMARY` line:

```bash
for i in $(seq 1 20); do python examples/gate_proof/concurrent_redemption.py; done | grep ^SUMMARY
```

All archives are fresh temporary directories; the test-only signer refuses to
operate on a non-temporary `CONTEXTD_HOME`, so the demo is structurally unable
to touch a real archive.
