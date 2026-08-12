from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from contextd.db import (
    InjectedCrash,
    append_event,
    append_event_checked,
    connect,
    recover_chain_state,
    verify_chain,
)


@pytest.mark.parametrize(
    ("phase", "expected"),
    [
        ("before_db_commit", 0),
        ("after_db_commit", 1),
        ("before_witness_finalize", 1),
    ],
)
def test_recovery_has_zero_or_one_effect_at_every_append_phase(phase, expected):
    conn = connect()

    def crash(here):
        if here == phase:
            raise InjectedCrash(here)

    with pytest.raises(InjectedCrash):
        append_event_checked(conn, "test", "note", content="once", fault=crash)
    conn.close()

    recovered = connect()
    recover_chain_state(recovered)
    rows = recovered.execute("SELECT id, content FROM events").fetchall()
    assert len(rows) == expected
    if rows:
        assert rows[0]["id"] == 1 and rows[0]["content"] == "once"
    assert verify_chain(recovered)["ok"]

    new_id = append_event(recovered, "test", "note", content="after recovery")
    assert new_id == expected + 1
    assert verify_chain(recovered)["ok"]


def test_thirty_two_concurrent_appenders_are_contiguous_and_witnessed():
    connect().close()
    barrier = Barrier(32)

    def worker(i):
        conn = connect()
        barrier.wait()
        try:
            return append_event(conn, "worker", "note", content=f"worker {i}")
        finally:
            conn.close()

    with ThreadPoolExecutor(max_workers=32) as pool:
        ids = list(pool.map(worker, range(32)))

    assert sorted(ids) == list(range(1, 33))
    conn = connect()
    stored = [r["id"] for r in conn.execute("SELECT id FROM events ORDER BY id")]
    assert stored == list(range(1, 33))
    assert verify_chain(conn)["ok"]


def test_post_commit_io_failure_preserves_recovery_bridge():
    conn = connect()

    def fail_after_commit(phase):
        if phase == "after_db_commit":
            raise OSError("simulated witness I/O failure")

    with pytest.raises(OSError, match="witness I/O"):
        append_event_checked(
            conn, "test", "note", content="durably committed", fault=fail_after_commit
        )
    conn.close()

    recovered = connect()
    assert recovered.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    assert verify_chain(recovered)["ok"]
