"""SCHEMA_VERSION stamps the live database via PRAGMA user_version: set at
init, backfilled on first write-capable connect to a legacy archive, and
never a chain disturbance."""

from contextd.db import SCHEMA_VERSION, append_event, connect, verify_chain


def _user_version(conn):
    return conn.execute("PRAGMA user_version").fetchone()[0]


def test_fresh_init_is_stamped(isolated_contextd_home):
    conn = connect()
    assert _user_version(conn) == SCHEMA_VERSION == 1
    assert verify_chain(conn)["ok"]


def test_legacy_archive_stamped_on_connect_without_chain_disturbance(
        isolated_contextd_home):
    conn = connect()
    append_event(conn, "note", "note", content="pre-stamp fact")
    conn.execute("PRAGMA user_version = 0")  # simulate a legacy archive
    conn.close()
    conn = connect()
    assert _user_version(conn) == 1
    assert verify_chain(conn)["ok"]


def test_future_versions_are_never_downgraded(isolated_contextd_home):
    conn = connect()
    conn.execute("PRAGMA user_version = 7")
    conn.close()
    assert _user_version(connect()) == 7
