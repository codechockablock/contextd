#!/usr/bin/env python
"""Concurrent redemption proof for contextd's authorization plane.

The claim under test: a single-use operator authorization cannot be redeemed
twice, even when N independent OS processes race to redeem it against the same
ledger file — and the failed redemptions are durably recorded in the ledger
itself.

Why this holds (contextd/attest.py, contextd/db.py): ``authorized_append``
passes a ``bind`` callback into ``append_event_checked``. That callback runs
inside the append's own ``BEGIN IMMEDIATE`` transaction, re-verifies the
authorization against the locked connection, and consumes the nonce with a
conditional UPDATE (``... AND consumed_event IS NULL``). The event INSERT is
in the same transaction: both commit or neither does.

What this run demonstrates is the COMPOSED system's guarantee, and it is
honest to name both mechanisms behind it: appends first serialize on an
exclusive ``fcntl.flock`` chain lock (db.py, ``_chain_lock``), so the racing
processes take the critical section one at a time, and the in-transaction
re-verify + conditional UPDATE is the second line of defense — the one that
refuses the losers and would also protect a code path that reached nonce
consumption without holding the chain lock (``consume_nonce`` is a public
primitive; its own docstring notes custom appenders call it directly). This
script proves the end-to-end property under process concurrency; it does not
isolate which of the two mechanisms fires first, because in the shipped
system they are deliberately layered.

The naive baseline (``--baseline-only`` or the second half of a default run)
performs the same redemption as decide-then-record — check the nonce in one
transaction, append the act in a second, mark the nonce in a third — against
the same schema in a separate throwaway archive. It exists to show the race
is real, not theoretical: under the same barrier-synchronized concurrency the
naive shape double-redeems, the atomic shape does not.

Every archive this script touches is a fresh temporary directory. It never
opens a real archive: the test-only signer refuses non-temporary homes.

Exit status: 0 iff every invariant below held; 1 otherwise.
  - exactly 1 successful redemption, exactly N-1 refusals
  - every refusal present as a durable ledger row after the workers exited
  - the ledger's own integrity verification (verify_chain) passes
  - (--baseline-only) the naive baseline produced >= 1 double-redemption
"""

import argparse
import json
import multiprocessing
import os
import platform
import shutil
import sqlite3
import sys
import tempfile
import time

ACT_CONTENT = "gate-proof: the one authorized act"
ACTION_CLASS = "note.deliberate"
TEST_SIGNER_SEED = b"gate-proof-operator"


def _fresh_home(tag: str) -> str:
    """A throwaway archive under the system temp root.

    The test signer refuses to operate outside a temporary directory
    (attest._assert_test_mode_ok), so this is also what keeps the demo
    physically incapable of touching a real archive.
    """
    home = tempfile.mkdtemp(prefix=f"contextd-gate-proof-{tag}-")
    os.environ["CONTEXTD_HOME"] = home
    os.environ["CONTEXTD_INSECURE_TEST_SIGNER"] = "1"
    return home


def _connect():
    from contextd.db import connect

    conn = connect()
    # Workers contend on the same file; the chain lock serializes appends but
    # the baseline's naive UPDATE runs outside it and can meet a busy database.
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def _mint_shared_authorization(conn):
    """One signed single-use authorization, in wire form (plain JSON + hex)."""
    from contextd import attest

    private = attest.load_test_signer(TEST_SIGNER_SEED)
    key_id = attest.register_key(
        attest.public_der(private), attest.SIGNER_TEST, conn=conn
    )
    prepared = attest.prepare_action(
        key_id, ACTION_CLASS, scope="global", content=ACT_CONTENT,
        ttl_seconds=900, conn=conn,
    )
    signature = attest.sign_with_test_key(
        private, bytes.fromhex(prepared["canonical"])
    )
    # Sanity: the authorization verifies before any redemption is attempted.
    attest.verify_action(prepared["action"], signature, conn=conn)
    return prepared["action"], signature.hex()


def _record_refusal(conn, kind: str, payload: dict) -> int:
    """A refusal as a durable ledger row.

    The (source, kind) pair is unregistered, so the row may carry no metadata
    (contextd/schemas.py: an unregistered type must never become an
    arbitrary-content channel); the detail travels in ``content`` instead and
    is chained and witnessed like any other event.
    """
    from contextd.db import append_event

    return append_event(
        conn, "gate_proof", kind, content=json.dumps(payload, sort_keys=True)
    )


def atomic_worker(index, action_json, signature_hex, barrier, queue):
    """One OS process racing to redeem the shared authorization atomically."""
    from contextd import attest

    pid = os.getpid()
    conn = _connect()
    authorization = None
    preflight_error = None
    try:
        # Preflight verification happens BEFORE the barrier, while the nonce is
        # untouched, so every worker enters the race holding a fully verified
        # Authorization. The race is then purely about in-transaction
        # consumption — the property under test.
        try:
            authorization = attest.verify_action(
                json.loads(action_json), bytes.fromhex(signature_hex), conn=conn
            )
        except attest.AttestationError as exc:
            preflight_error = str(exc)

        barrier.wait(timeout=60)

        if authorization is None:
            refusal_event = _record_refusal(conn, "refusal", {
                "worker": index, "pid": pid, "stage": "preflight",
                "error": preflight_error,
            })
            queue.put({"worker": index, "pid": pid, "outcome": "refused",
                       "stage": "preflight", "refusal_event": refusal_event,
                       "error": preflight_error})
            return
        try:
            event_id = attest.authorized_append(
                conn, "note", "note", authorization, ACTION_CLASS, "global",
                content=ACT_CONTENT,
            )
            queue.put({"worker": index, "pid": pid, "outcome": "appended",
                       "event": event_id})
        except attest.AttestationError as exc:
            refusal_event = _record_refusal(conn, "refusal", {
                "worker": index, "pid": pid, "stage": "redemption",
                "error": str(exc),
            })
            queue.put({"worker": index, "pid": pid, "outcome": "refused",
                       "stage": "redemption", "refusal_event": refusal_event,
                       "error": str(exc)})
    except Exception as exc:  # noqa: BLE001 - reported, then asserted on
        queue.put({"worker": index, "pid": pid, "outcome": "crashed",
                   "error": f"{type(exc).__name__}: {exc}"})
    finally:
        conn.close()


def naive_worker(index, nonce, barrier, queue):
    """Decide-then-record: the same redemption as three separate transactions.

    This is the common shape the comparison document describes: check a
    policy, act, then write bookkeeping about what was decided. Nothing ties
    the three together, so two processes that both pass step 1 both perform
    step 2.
    """
    pid = os.getpid()
    conn = _connect()
    try:
        barrier.wait(timeout=60)

        # Transaction 1: the check. Every worker that reads before any worker
        # writes sees an unconsumed nonce and concludes it is authorized.
        row = conn.execute(
            "SELECT consumed_event FROM operator_nonces WHERE nonce = ?",
            (nonce,),
        ).fetchone()
        if row is None or row["consumed_event"] is not None:
            refusal_event = _record_refusal(conn, "baseline_refusal", {
                "worker": index, "pid": pid,
                "error": "nonce already consumed at check time",
            })
            queue.put({"worker": index, "pid": pid, "outcome": "refused",
                       "refusal_event": refusal_event})
            return

        # Transaction 2: the act, recorded on the same schema.
        event_id = _record_refusal(conn, "baseline_redemption", {
            "worker": index, "pid": pid, "nonce": nonce,
        })

        # Transaction 3: the bookkeeping. Unconditional, like an audit-status
        # UPDATE; last writer wins, and afterwards the nonce row even looks
        # consistent — only counting the redemption events reveals the race.
        conn.execute(
            "UPDATE operator_nonces SET consumed_event = ? WHERE nonce = ?",
            (event_id, nonce),
        )
        conn.commit()
        queue.put({"worker": index, "pid": pid, "outcome": "appended",
                   "event": event_id})
    except Exception as exc:  # noqa: BLE001
        queue.put({"worker": index, "pid": pid, "outcome": "crashed",
                   "error": f"{type(exc).__name__}: {exc}"})
    finally:
        conn.close()


def _spawn_and_join(target, n, args_for):
    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(n)
    queue = ctx.Queue()
    workers = [
        ctx.Process(target=target, args=args_for(i, barrier, queue))
        for i in range(n)
    ]
    started = time.monotonic()
    for w in workers:
        w.start()
    for w in workers:
        w.join(timeout=120)
    elapsed = time.monotonic() - started
    outcomes = []
    while not queue.empty():
        outcomes.append(queue.get())
    still_alive = sum(1 for w in workers if w.is_alive())
    exit_codes = [w.exitcode for w in workers]
    return outcomes, exit_codes, still_alive, elapsed


def run_atomic(n: int) -> dict:
    """The contextd path: N processes, one authorization, atomic consumption."""
    home = _fresh_home("atomic")
    print(f"\n=== atomic path: {n} OS processes, one single-use authorization")
    print(f"    archive: {home}")
    try:
        conn = _connect()
        action, signature_hex = _mint_shared_authorization(conn)
        nonce = action["nonce"]
        conn.close()

        outcomes, exit_codes, still_alive, elapsed = _spawn_and_join(
            atomic_worker, n,
            lambda i, b, q: (i, json.dumps(action), signature_hex, b, q),
        )

        # The ledger, not the workers' self-reports, is the source of truth.
        # All queries below run on a fresh connection after every worker exited.
        conn = _connect()
        success_ids = [r[0] for r in conn.execute(
            "SELECT id FROM events WHERE source='note' AND kind='note' "
            "AND content = ? ORDER BY id", (ACT_CONTENT,),
        ).fetchall()]
        successes = len(success_ids)
        consumed_by = conn.execute(
            "SELECT consumed_event FROM operator_nonces WHERE nonce = ?",
            (nonce,),
        ).fetchone()[0]
        refusal_rows = conn.execute(
            "SELECT id, ts, content FROM events "
            "WHERE source='gate_proof' AND kind='refusal' ORDER BY id",
        ).fetchall()
        refusal_stages = sorted(
            {json.loads(row["content"]).get("stage") for row in refusal_rows}
        )

        from contextd.db import verify_chain
        chain = verify_chain(conn)
        conn.close()

        pids = sorted(o["pid"] for o in outcomes)
        print(f"    workers: {len(outcomes)} reported, distinct pids: "
              f"{len(set(pids))}, exit codes: {sorted(set(exit_codes))}, "
              f"alive after join: {still_alive}, {elapsed:.2f}s")
        print(f"    ledger: {successes} redemption event(s) "
              f"{success_ids}; nonce consumed by event #{consumed_by}")
        print(f"    refusal rows ({len(refusal_rows)}, "
              f"stages: {refusal_stages}):")
        for row in refusal_rows:
            print(f"      #{row['id']} {row['ts']} {row['content']}")
        print(f"    verify_chain: {dict(chain)}")

        crashed = [o for o in outcomes if o["outcome"] == "crashed"]
        ok = (
            successes == 1
            # the nonce must name the winner, not merely be consumed
            and success_ids and consumed_by == success_ids[0]
            and len(refusal_rows) == n - 1
            # every refusal must come from inside the append transaction:
            # a preflight refusal would mean the race never reached the
            # in-transaction consumption this demo exists to exercise
            and refusal_stages == ["redemption"]
            and len(outcomes) == n
            and len(set(pids)) == n
            and not crashed
            and all(code == 0 for code in exit_codes)
            and still_alive == 0
            and chain["ok"]
        )
        if ok:
            print(f"RESULT: 1 success, {n - 1} refused")
        else:
            print(f"RESULT: INVARIANT VIOLATED — {successes} success(es), "
                  f"{len(refusal_rows)} durable refusal(s) of {n - 1} "
                  f"expected (stages: {refusal_stages}), nonce consumed by "
                  f"#{consumed_by} vs winners {success_ids}, "
                  f"{len(crashed)} crashed, exit codes "
                  f"{sorted(set(exit_codes))}, alive {still_alive}, "
                  f"chain ok={chain['ok']}")
            for o in crashed:
                print(f"      crashed: {o}")
            print(f"    forensics kept: {home}")
        return {"mode": "atomic", "n": n, "successes": successes,
                "refusals": len(refusal_rows), "crashed": len(crashed),
                "chain_ok": bool(chain["ok"]), "elapsed_s": round(elapsed, 2),
                "ok": ok, "home": home}
    finally:
        if os.environ.get("GATE_PROOF_KEEP") != "1":
            shutil.rmtree(home, ignore_errors=True)


def run_baseline(n: int) -> dict:
    """The naive path on the same schema: check, then append, then mark."""
    home = _fresh_home("baseline")
    print(f"\n=== naive baseline: {n} OS processes, decide-then-record")
    print(f"    archive: {home}")
    try:
        conn = _connect()
        action, _signature_hex = _mint_shared_authorization(conn)
        nonce = action["nonce"]
        conn.close()

        outcomes, exit_codes, still_alive, elapsed = _spawn_and_join(
            naive_worker, n, lambda i, b, q: (i, nonce, b, q),
        )

        conn = _connect()
        redemptions = conn.execute(
            "SELECT COUNT(*) FROM events "
            "WHERE source='gate_proof' AND kind='baseline_redemption'",
        ).fetchone()[0]
        refusals = conn.execute(
            "SELECT COUNT(*) FROM events "
            "WHERE source='gate_proof' AND kind='baseline_refusal'",
        ).fetchone()[0]
        consumed_by = conn.execute(
            "SELECT consumed_event FROM operator_nonces WHERE nonce = ?",
            (nonce,),
        ).fetchone()[0]
        conn.close()

        crashed = [o for o in outcomes if o["outcome"] == "crashed"]
        doubles = max(0, redemptions - 1)
        print(f"    workers: {len(outcomes)} reported, exit codes: "
              f"{sorted(set(exit_codes))}, alive after join: {still_alive}, "
              f"{elapsed:.2f}s")
        print(f"    ledger: {redemptions} redemption event(s) from ONE "
              f"authorization, {refusals} refusal(s), {len(crashed)} crashed")
        print(f"    nonce row afterwards points at event #{consumed_by} — "
              f"it looks consistent; the {redemptions} redemption rows are "
              f"the only trace of the race")
        print(f"BASELINE: {doubles} double-redemption(s) "
              f"({redemptions} redemptions of one single-use authorization)")
        return {"mode": "baseline", "n": n, "redemptions": redemptions,
                "doubles": doubles, "refusals": refusals,
                "crashed": len(crashed), "elapsed_s": round(elapsed, 2)}
    finally:
        if os.environ.get("GATE_PROOF_KEEP") != "1":
            shutil.rmtree(home, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--workers", type=int, default=8,
                        help="concurrent OS processes (default 8, minimum 2)")
    parser.add_argument("--baseline-only", action="store_true",
                        help="run only the naive baseline; exit 0 iff it "
                             "double-redeems at least once (up to 5 attempts)")
    args = parser.parse_args()
    n = max(2, args.workers)

    print(f"machine: {platform.platform()} / {platform.machine()}")
    print(f"python:  {sys.version.split()[0]}  sqlite: {sqlite3.sqlite_version}")

    if args.baseline_only:
        for attempt in range(1, 6):
            result = run_baseline(n)
            if result["doubles"] >= 1:
                print(f"\nSUMMARY {json.dumps(result, sort_keys=True)}")
                return 0
            print(f"    (attempt {attempt}: no double-redemption; retrying)")
        print("\nBASELINE NEVER DOUBLE-REDEEMED after 5 attempts — the demo "
              "proves nothing at this concurrency; raise --workers")
        return 1

    atomic = run_atomic(n)
    baseline = run_baseline(n)
    print(f"\nSUMMARY {json.dumps({'atomic': atomic, 'baseline': baseline}, sort_keys=True)}")
    return 0 if atomic["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
