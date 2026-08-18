#!/usr/bin/env python
"""Multi-host redemption proof for contextd's authorization plane.

The claim under test is the one `concurrent_redemption.py` makes, moved across a
machine boundary: a single-use operator authorization cannot be redeemed twice
even when the processes racing for it **do not share a filesystem** — and the
failed redemptions are durably recorded in the ledger itself.

`concurrent_redemption.py` is frozen and unchanged; this is a separate script by
operator ruling (gate-v1 pre-flight, D1). It has to be separate because it is
not the same proof. The frozen demo names two layered mechanisms — an exclusive
`fcntl.flock` chain lock, and in-transaction conditional consumption — and is
honest that it does not isolate which fires first. **Across hosts the first
mechanism does not exist**, so this script is the one that shows what is left
holding the guarantee up.

# What makes a worker here a "host" rather than a thread

Each worker gets its **own** ``CONTEXTD_HOME``: its own archive root, its own
`chain-witness.json`, its own `chain-recovery.json`, its own
`chain-witness.lock` inode. They share exactly one thing, the Postgres database.
That is the whole distinction, and it is the distinction that matters, because
every part of the single-host protocol that silently fails across machines fails
on precisely this axis:

* `fcntl.flock` is a kernel-local advisory lock on a *local inode*, so two
  workers with distinct roots lock different files and both enter what is
  supposed to be a critical section. ``--show-single-host-failure`` demonstrates
  this directly, with two processes and a barrier.
* the next event id and `prev_hash` come from the *local* witness, so two hosts
  compute the same ``previous["id"] + 1`` — a primary-key collision at best, a
  forked chain at worst.
* a host whose witness is one append behind reports the other host's healthy
  append as ledger tampering.

None of that is visible if the workers share a home, which is why they do not.

# What replaces the file lock

Nothing outside the database. The Postgres backend takes its exclusion from a
``FOR UPDATE`` row lock on the singleton `chain_tip` row, acquired inside the
append's own transaction, and a ``BEFORE INSERT`` trigger re-derives chain
continuity from that row so a client cannot fork the chain even if it tries.
There is no advisory lock, no consensus, no external lock service, and no
two-phase commit — see `contextd/backends/postgres.py`.

Exit status: 0 iff every invariant below held; 1 otherwise.
  - exactly 1 successful redemption, exactly N-1 refusals
  - every refusal present as a durable ledger row after the workers exited
  - the nonce records the winning event, and only it
  - the chain is one unforked line: contiguous ids, `prev_hash` continuity
  - `verify_chain` passes, and `chain_tip` agrees with the last row
  - the workers really did run from distinct archive roots
"""

import argparse
import json
import multiprocessing
import os
import secrets
import sys
import tempfile
import time
from urllib.parse import urlparse, urlunparse

# This script proves things about the checkout it lives in, so that checkout has
# to win over any installed copy of contextd — including in spawned children,
# which re-import this module by path.
_REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
os.environ["PYTHONPATH"] = os.pathsep.join(
    p for p in (_REPO_ROOT, os.environ.get("PYTHONPATH", "")) if p
)

ACT_CONTENT = "multihost gate-proof: the one authorized act"
ACTION_CLASS = "note.deliberate"
TEST_SIGNER_SEED = b"multihost-gate-proof-operator"
DEFAULT_URL = "postgresql://postgres@127.0.0.1:55432/contextd_test"


# --------------------------------------------------------------------------
# per-run database isolation
# --------------------------------------------------------------------------

def _with_database(url: str, name: str) -> str:
    parts = urlparse(url)
    return urlunparse(parts._replace(path=f"/{name}"))


def _admin_execute(url: str, statement: str) -> None:
    import psycopg

    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(statement)


def _create_run_database(url: str) -> tuple[str, str]:
    """A fresh database per run, so runs cannot contaminate each other."""
    name = f"contextd_mh_{os.getpid()}_{secrets.token_hex(4)}"
    _admin_execute(url, f'CREATE DATABASE "{name}"')
    return name, _with_database(url, name)


def _drop_run_database(url: str, name: str) -> None:
    try:
        _admin_execute(url, f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    except Exception as exc:  # noqa: BLE001 - cleanup is best effort, but loud
        print(f"    warning: could not drop {name}: {exc}", file=sys.stderr)


# --------------------------------------------------------------------------
# host setup
# --------------------------------------------------------------------------

def _become_host(tag: str, url: str) -> str:
    """Adopt a private archive root and the shared database. Returns the root.

    Must run before contextd is imported in this process: the archive root is
    read from the environment at import time, and the test signer refuses any
    root that is not a temporary directory.
    """
    home = tempfile.mkdtemp(prefix=f"contextd-multihost-{tag}-")
    os.environ["CONTEXTD_HOME"] = home
    os.environ["CONTEXTD_INSECURE_TEST_SIGNER"] = "1"
    os.environ["CONTEXTD_DATABASE_URL"] = url
    return home


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
    attest.verify_action(prepared["action"], signature, conn=conn)
    return prepared["action"], signature.hex()


def _record_refusal(conn, payload: dict) -> int:
    """A refusal as a durable ledger row, on the same chain as the act."""
    from contextd.db import append_event

    return append_event(
        conn, "gate_proof", "refusal", content=json.dumps(payload, sort_keys=True)
    )


def multihost_worker(index, url, action_json, signature_hex, barrier, queue):
    """One simulated host: private archive root, shared database."""
    home = _become_host(f"h{index}", url)
    pid = os.getpid()

    from contextd import attest
    from contextd.db import connect

    conn = connect()
    authorization = None
    preflight_error = None
    try:
        # Preflight verification happens BEFORE the barrier, while the nonce is
        # untouched, so every host enters the race holding a fully verified
        # Authorization and the race is purely about consumption.
        try:
            authorization = attest.verify_action(
                json.loads(action_json), bytes.fromhex(signature_hex), conn=conn
            )
        except attest.AttestationError as exc:
            preflight_error = str(exc)

        barrier.wait(timeout=60)

        if authorization is None:
            event = _record_refusal(conn, {
                "host": index, "pid": pid, "stage": "preflight",
                "error": preflight_error,
            })
            queue.put({"host": index, "pid": pid, "home": home,
                       "outcome": "refused", "stage": "preflight",
                       "refusal_event": event, "error": preflight_error})
            return
        try:
            event_id = attest.authorized_append(
                conn, "note", "note", authorization, ACTION_CLASS, "global",
                content=ACT_CONTENT,
            )
            queue.put({"host": index, "pid": pid, "home": home,
                       "outcome": "appended", "event": event_id})
        except attest.AttestationError as exc:
            event = _record_refusal(conn, {
                "host": index, "pid": pid, "stage": "redemption",
                "error": str(exc),
            })
            queue.put({"host": index, "pid": pid, "home": home,
                       "outcome": "refused", "stage": "redemption",
                       "refusal_event": event, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001 - reported, then asserted on
        queue.put({"host": index, "pid": pid, "home": home,
                   "outcome": "crashed", "error": f"{type(exc).__name__}: {exc}"})
    finally:
        conn.close()


def _spawn_and_join(target, n, args_for, timeout=180):
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
        w.join(timeout=timeout)
    elapsed = time.monotonic() - started
    outcomes = []
    while not queue.empty():
        outcomes.append(queue.get())
    still_alive = sum(1 for w in workers if w.is_alive())
    return outcomes, [w.exitcode for w in workers], still_alive, elapsed


# --------------------------------------------------------------------------
# the proof
# --------------------------------------------------------------------------

def run_multihost(hosts: int, url: str) -> dict:
    name, run_url = _create_run_database(url)
    print(f"\n=== multi-host: {hosts} hosts, distinct archive roots, one database")
    print(f"    database: {name}")
    try:
        _become_host("mint", run_url)
        from contextd.db import connect, verify_chain

        conn = connect()
        action, signature_hex = _mint_shared_authorization(conn)
        nonce = action["nonce"]
        conn.close()

        outcomes, exit_codes, still_alive, elapsed = _spawn_and_join(
            multihost_worker, hosts,
            lambda i, b, q: (i, run_url, json.dumps(action), signature_hex, b, q),
        )

        # The ledger, not the workers' self-reports, is the source of truth.
        conn = connect()
        success_ids = [r[0] for r in conn.execute(
            "SELECT id FROM events WHERE source='note' AND kind='note' "
            "AND content = ? ORDER BY id", (ACT_CONTENT,),
        ).fetchall()]
        consumed_by = conn.execute(
            "SELECT consumed_event FROM operator_nonces WHERE nonce = ?",
            (nonce,),
        ).fetchone()[0]
        refusal_rows = conn.execute(
            "SELECT id, content FROM events "
            "WHERE source='gate_proof' AND kind='refusal' ORDER BY id"
        ).fetchall()
        chain_rows = conn.execute(
            "SELECT id, prev_hash, chain_hash FROM events ORDER BY id"
        ).fetchall()
        tip_row = conn.execute(
            "SELECT id, chain_hash FROM chain_tip WHERE singleton = 1"
        ).fetchone()
        chain = verify_chain(conn)
        conn.close()

        ids = [int(r["id"]) for r in chain_rows]
        contiguous = ids == list(range(1, len(ids) + 1))
        linked = all(
            (chain_rows[i]["prev_hash"] or "") == chain_rows[i - 1]["chain_hash"]
            for i in range(1, len(chain_rows))
        )
        homes = {o.get("home") for o in outcomes if o.get("home")}
        tip_agrees = bool(chain_rows) and (
            int(tip_row["id"]) == ids[-1]
            and tip_row["chain_hash"] == chain_rows[-1]["chain_hash"]
        )

        checks = {
            "exactly one success": len(success_ids) == 1,
            f"exactly {hosts - 1} refusals": len(refusal_rows) == hosts - 1,
            "refusals durable in ledger": len(refusal_rows) == sum(
                1 for o in outcomes if o["outcome"] == "refused"
            ),
            "nonce records the winner": (
                len(success_ids) == 1 and consumed_by == success_ids[0]
            ),
            "chain ids contiguous (no fork)": contiguous,
            "chain prev_hash continuous": linked,
            "chain_tip agrees with last row": tip_agrees,
            "verify_chain ok": chain["ok"],
            "no worker crashed": all(c == 0 for c in exit_codes)
            and still_alive == 0
            and not any(o["outcome"] == "crashed" for o in outcomes),
            "hosts had distinct roots": len(homes) == hosts,
        }

        print(f"    elapsed {elapsed:.2f}s   exit codes {exit_codes}")
        for o in sorted(outcomes, key=lambda x: x["host"]):
            detail = (
                f"event {o['event']}" if o["outcome"] == "appended"
                else f"{o.get('stage', '-')}: {o.get('error', '')[:58]}"
            )
            print(f"    host {o['host']} pid {o['pid']:<7} {o['outcome']:<9} {detail}")
        print(f"    chain: {len(ids)} rows, tip "
              f"{tip_row['id']}/{(tip_row['chain_hash'] or '')[:12]}, "
              f"verify_chain={chain}")
        for label, ok in checks.items():
            print(f"    [{'PASS' if ok else 'FAIL'}] {label}")

        return {"ok": all(checks.values()), "checks": checks,
                "outcomes": outcomes, "chain": chain, "elapsed": elapsed}
    finally:
        _drop_run_database(url, name)


# --------------------------------------------------------------------------
# the negative control
# --------------------------------------------------------------------------

def _flock_holder(index, root, barrier, queue, events):
    """Hold the single-host chain lock for a root, then report at the barrier."""
    from pathlib import Path

    root = Path(root)
    # This host's archive root *is* the root whose chain lock it takes — the
    # ordinary single-host arrangement, just one of two of them.
    os.environ["CONTEXTD_HOME"] = str(root)
    os.environ["CONTEXTD_INSECURE_TEST_SIGNER"] = "1"
    os.environ.pop("CONTEXTD_DATABASE_URL", None)
    from contextd.db import _chain_lock, append_event, chain_state_paths, connect

    try:
        conn = connect()          # creates the archive and its witness
        for n in range(events):
            append_event(conn, "gate_proof", "note", content=f"seed {n}")
        conn.close()
        with _chain_lock(root):
            # If flock excluded across roots, only one process could be inside
            # here, and the barrier would time out instead of releasing.
            barrier.wait(timeout=15)
            witness = json.loads(chain_state_paths(root)["witness"].read_text())
            queue.put({"host": index, "root": str(root), "entered": True,
                       "witnessed_id": witness["id"],
                       "next_event_id": witness["id"] + 1})
    except Exception as exc:  # noqa: BLE001
        queue.put({"host": index, "entered": False,
                   "error": f"{type(exc).__name__}: {exc}"})


def show_single_host_failure() -> dict:
    """Demonstrate findings 2 and 3 directly, with two processes.

    Two hosts, two archive roots. Both take *the* chain lock — each on its own
    inode — and both are inside the critical section at the same time, which the
    barrier proves by releasing. Then both read their own witness and compute the
    same next event id, which against one shared ledger is a primary-key
    collision or a forked chain.
    """
    print("\n=== negative control: the single-host protocol across two roots")
    roots = [tempfile.mkdtemp(prefix=f"contextd-neg-{i}-") for i in range(2)]
    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(2)
    queue = ctx.Queue()
    # Both hosts append the same number of events, as two hosts sharing one
    # ledger would have observed. Their witnesses therefore agree, which is the
    # healthy case — and is exactly when the id collision bites.
    procs = [
        ctx.Process(target=_flock_holder, args=(i, roots[i], barrier, queue, 3))
        for i in range(2)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)
    results = []
    while not queue.empty():
        results.append(queue.get())

    both_entered = (
        len(results) == 2 and all(r.get("entered") for r in results)
    )
    next_ids = {r.get("next_event_id") for r in results if "next_event_id" in r}
    collide = len(results) == 2 and len(next_ids) == 1

    for r in sorted(results, key=lambda x: x.get("host", -1)):
        print(f"    host {r.get('host')}: {r}")
    print(f"    [{'CONFIRMED' if both_entered else 'not shown'}] "
          f"finding 2 — both hosts held 'the' chain lock simultaneously; "
          f"flock is a local-inode lock and excludes nothing across roots")
    print(f"    [{'CONFIRMED' if collide else 'not shown'}] "
          f"finding 3 — both hosts computed next event id {next_ids}; "
          f"against one shared ledger that is a PK collision or a forked chain")
    return {"both_entered": both_entered, "id_collision": collide}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hosts", type=int, default=2,
                        help="simulated hosts, each with its own archive root")
    parser.add_argument("--database-url",
                        default=os.environ.get("CONTEXTD_DATABASE_URL")
                        or DEFAULT_URL,
                        help="a Postgres database this script may create "
                             "per-run databases from")
    parser.add_argument("--show-single-host-failure", action="store_true",
                        help="only run the negative control")
    args = parser.parse_args()

    if args.show_single_host_failure:
        result = show_single_host_failure()
        return 0 if result["both_entered"] and result["id_collision"] else 1

    if args.hosts < 2:
        print("--hosts must be at least 2 for a multi-host proof",
              file=sys.stderr)
        return 2

    print(f"contextd multi-host redemption proof — {args.hosts} hosts")
    print(f"    python {sys.version.split()[0]}   repo {_REPO_ROOT}")
    result = run_multihost(args.hosts, args.database_url)
    print(f"\n{'PASS' if result['ok'] else 'FAIL'}: multi-host single-use "
          f"redemption across {args.hosts} hosts")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
