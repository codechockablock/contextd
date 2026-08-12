import json
import os
import subprocess
import sys

import pytest

from contextd.db import (
    ChainStateError,
    append_event,
    chain_state_paths,
    connect,
    verify_chain,
)


def _seed(count=4):
    conn = connect()
    for i in range(count):
        append_event(conn, "test", "note", content=f"event {i}")
    assert verify_chain(conn)["ok"]
    return conn


def test_witness_tracks_the_exact_tip():
    conn = _seed()
    tip = conn.execute(
        "SELECT id, chain_hash FROM events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    witness = json.loads(chain_state_paths()["witness"].read_text())
    assert (witness["id"], witness["chain_hash"]) == (tip["id"], tip["chain_hash"])


def test_witness_bootstrap_does_not_rewrite_existing_event_rows():
    conn = _seed(2)
    before = [tuple(row) for row in conn.execute("SELECT * FROM events ORDER BY id")]

    # Simulate an already-chained archive from before the external witness was
    # introduced. Only the witness marker/state is absent; event bytes and
    # hashes are authoritative and must remain untouched by bootstrap.
    conn.execute("DELETE FROM chain_state")
    conn.commit()
    conn.close()
    chain_state_paths()["witness"].unlink()

    reopened = connect()
    after = [tuple(row) for row in reopened.execute("SELECT * FROM events ORDER BY id")]

    assert after == before
    assert verify_chain(reopened)["ok"]


@pytest.mark.parametrize(
    "tamper", ["rewrite", "middle_delete", "tail_delete", "insert", "reorder"]
)
def test_verify_detects_database_only_tampering(tamper):
    conn = _seed()
    if tamper == "rewrite":
        conn.execute("DROP TRIGGER events_no_update")
        conn.execute("UPDATE events SET content='forged' WHERE id=2")
    elif tamper in {"middle_delete", "tail_delete"}:
        conn.execute("DROP TRIGGER events_no_delete")
        target = 2 if tamper == "middle_delete" else 4
        conn.execute("DELETE FROM events WHERE id=?", (target,))
    elif tamper == "insert":
        conn.execute(
            "INSERT INTO events(id,ts,source,kind,content) "
            "VALUES(99,'2099-01-01T00:00:00+00:00','forged','note','inserted')"
        )
    else:
        conn.execute("DROP TRIGGER events_no_update")
        conn.execute("UPDATE events SET id=99 WHERE id=2")
        conn.execute("UPDATE events SET id=2 WHERE id=3")
        conn.execute("UPDATE events SET id=3 WHERE id=99")
    conn.commit()

    result = verify_chain(conn)

    assert not result["ok"], (tamper, result)


def test_missing_initialized_witness_is_refused():
    conn = _seed(1)
    conn.close()
    chain_state_paths()["witness"].unlink()

    with pytest.raises(Exception, match="witness is missing"):
        connect()


def test_non_object_witness_is_a_controlled_chain_state_error():
    conn = _seed(1)
    conn.close()
    chain_state_paths()["witness"].write_text("[]\n")

    with pytest.raises(ChainStateError, match="malformed chain witness"):
        connect()


def test_non_utf8_witness_is_a_controlled_chain_state_error():
    conn = _seed(1)
    conn.close()
    chain_state_paths()["witness"].write_bytes(b"\xff")

    with pytest.raises(ChainStateError, match="invalid chain witness"):
        connect()


def test_ctx_verify_reports_tail_truncation_after_restart():
    conn = _seed(2)
    conn.execute("DROP TRIGGER events_no_delete")
    conn.execute("DELETE FROM events WHERE id=2")
    conn.commit()
    conn.close()

    result = subprocess.run(
        [sys.executable, "-m", "contextd.cli", "verify"],
        capture_output=True,
        text=True,
        env=os.environ.copy(),
        check=False,
    )

    assert result.returncode != 0
    assert "CHAIN BROKEN" in result.stderr
    assert "does not match witnessed tip" in result.stderr


def test_owner_can_still_rewrite_database_and_witness_if_they_choose():
    """The local witness narrows failures; it is deliberately not remote trust."""
    conn = _seed(1)
    assert verify_chain(conn)["ok"]
    # This test documents the boundary rather than providing forgery machinery:
    # both authoritative artifacts are owner-writable local files.
    assert chain_state_paths()["witness"].is_file()
    assert chain_state_paths()["witness"].stat().st_mode & 0o200


def test_open_connection_keeps_its_own_witness_when_environment_changes(
    tmp_path, monkeypatch
):
    first = tmp_path / "first"
    second = tmp_path / "second"
    monkeypatch.setenv("CONTEXTD_HOME", str(first))
    first_conn = connect()
    append_event(first_conn, "test", "note", content="first archive")

    monkeypatch.setenv("CONTEXTD_HOME", str(second))
    second_conn = connect()
    append_event(second_conn, "test", "note", content="second archive")
    append_event(first_conn, "test", "note", content="still first archive")

    assert verify_chain(first_conn)["ok"]
    assert verify_chain(second_conn)["ok"]
    first_witness = json.loads(chain_state_paths(first)["witness"].read_text())
    second_witness = json.loads(chain_state_paths(second)["witness"].read_text())
    assert first_witness["id"] == 2
    assert second_witness["id"] == 1
