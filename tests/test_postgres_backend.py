"""The Postgres backend: immutability, multihost chain safety, migration.

Requires a throwaway Postgres server, passed as ``--postgres-url`` or
``CONTEXTD_TEST_POSTGRES_URL``; the whole module skips without one. Every test
gets a freshly created database and drops it afterwards.

These tests deliberately do something the rest of the suite must not: they open
**two archive roots against one database**. That is the multi-host shape, and it
is the shape under which the single-host protocol silently fails. It is done
here, per test, in the test body — never as a global fixture, because the
suite-wide home isolation in `conftest.py` is a security control rather than a
convenience.
"""

import secrets
import threading
from urllib.parse import urlparse, urlunparse

import pytest

pytestmark = pytest.mark.usefixtures("postgres_url")

ACT = "postgres backend: the one authorized act"
ACTION_CLASS = "note.deliberate"


# --- fixtures -------------------------------------------------------------

def _with_database(url: str, name: str) -> str:
    return urlunparse(urlparse(url)._replace(path=f"/{name}"))


@pytest.fixture
def pg_url(postgres_url):
    """A fresh, empty database for one test."""
    import psycopg

    name = f"contextd_t_{secrets.token_hex(6)}"
    with psycopg.connect(postgres_url, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    try:
        yield _with_database(postgres_url, name)
    finally:
        with psycopg.connect(postgres_url, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@pytest.fixture
def pg_conn(pg_url, monkeypatch):
    from contextd.db import connect

    monkeypatch.setenv("CONTEXTD_DATABASE_URL", pg_url)
    conn = connect()
    yield conn
    conn.close()


def _authorization(conn):
    from contextd import attest

    private = attest.load_test_signer(b"postgres-backend-test")
    key_id = attest.register_key(
        attest.public_der(private), attest.SIGNER_TEST, conn=conn
    )
    prepared = attest.prepare_action(
        key_id, ACTION_CLASS, scope="global", content=ACT, ttl_seconds=900,
        conn=conn,
    )
    signature = attest.sign_with_test_key(
        private, bytes.fromhex(prepared["canonical"])
    )
    return attest.verify_action(prepared["action"], signature, conn=conn)


# --- database-enforced immutability --------------------------------------

def test_backend_immutability_update_on_a_committed_event_is_refused(pg_conn):
    """Where Postgres is genuinely stronger than SQLite.

    SQLite has the same triggers, but any owner-level process can
    ``DROP TRIGGER`` them first. Here the trigger fires even for the table
    owner, and `harden_roles` additionally removes the privilege outright from
    the role contextd actually runs as.
    """
    from contextd.db import append_event

    append_event(pg_conn, "test", "note", content="original")
    with pytest.raises(Exception, match="append-only"):
        pg_conn.execute("UPDATE events SET content = 'tampered' WHERE id = 1")
    pg_conn.rollback()
    row = pg_conn.execute("SELECT content FROM events WHERE id = 1").fetchone()
    assert row["content"] == "original"


def test_backend_immutability_delete_is_refused(pg_conn):
    from contextd.db import append_event

    append_event(pg_conn, "test", "note", content="keep me")
    with pytest.raises(Exception, match="append-only"):
        pg_conn.execute("DELETE FROM events WHERE id = 1")
    pg_conn.rollback()
    assert pg_conn.execute("SELECT count(*) AS n FROM events").fetchone()["n"] == 1


def test_backend_immutability_truncate_is_refused(pg_conn):
    """A row-level trigger alone would not fire for TRUNCATE."""
    from contextd.db import append_event

    append_event(pg_conn, "test", "note", content="keep me")
    with pytest.raises(Exception, match="append-only"):
        pg_conn.execute("TRUNCATE events")
    pg_conn.rollback()
    assert pg_conn.execute("SELECT count(*) AS n FROM events").fetchone()["n"] == 1


def test_backend_immutability_appender_role_has_no_update_privilege(
    pg_url, pg_conn, monkeypatch
):
    """The credential contextd runs as cannot rewrite history, by privilege.

    This is the property the in-database tip trade-off is bought with, so it is
    asserted directly rather than inferred from the grant script.
    """
    import psycopg

    from contextd.backends.postgres import harden_roles
    from contextd.db import append_event

    append_event(pg_conn, "test", "note", content="original")
    role = f"contextd_app_{secrets.token_hex(4)}"
    pg_conn.execute(f'CREATE ROLE "{role}" LOGIN')
    harden_roles(pg_conn, role)
    pg_conn.commit()

    app_url = urlunparse(urlparse(pg_url)._replace(netloc=(
        f"{role}@{urlparse(pg_url).hostname}:{urlparse(pg_url).port}"
    )))
    try:
        with psycopg.connect(app_url, autocommit=True) as app:
            # Refused by privilege, before the trigger is even consulted.
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute("UPDATE events SET content = 'x' WHERE id = 1")
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute("DELETE FROM events WHERE id = 1")
            # ...and it cannot forge the tip either: the tip is advanced only by
            # the SECURITY DEFINER insert trigger.
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute("UPDATE chain_tip SET id = 99 WHERE singleton = 1")
            # It can still do its job.
            assert app.execute("SELECT count(*) FROM events").fetchone()[0] == 1
    finally:
        pg_conn.execute(f'DROP OWNED BY "{role}"')
        pg_conn.execute(f'DROP ROLE IF EXISTS "{role}"')
        pg_conn.commit()


# --- declared scope boundary ---------------------------------------------

def test_backend_search_refuses_rather_than_ranking_differently(pg_conn):
    """Out of scope must mean a refusal, not quietly different results."""
    from contextd.db import append_event
    from contextd.search import SearchUnsupported, search, timeline

    append_event(pg_conn, "test", "note", content="findable haystack needle")
    with pytest.raises(SearchUnsupported, match="bm25"):
        search(pg_conn, "needle")
    # The backend-independent read still works, and is what callers are pointed at.
    rows = timeline(pg_conn, limit=10)
    assert [r["content"] for r in rows] == ["findable haystack needle"]


# --- chain construction safety -------------------------------------------

def test_backend_chain_fork_is_refused_by_the_database(pg_conn):
    """A client cannot fork the chain even by inserting directly.

    Chain continuity is enforced by ``events_chain_advance``, not by client
    cooperation, so a stale or hostile appender is refused rather than believed.
    """
    from contextd.db import append_event

    append_event(pg_conn, "test", "note", content="first")
    pg_conn.execute("BEGIN")
    with pytest.raises(Exception, match="does not extend chain tip"):
        pg_conn.execute(
            "INSERT INTO events (id, ts, source, kind, prev_hash, chain_hash) "
            "VALUES (?,?,?,?,?,?)",
            (1, "2026-01-01T00:00:00+00:00", "fork", "note", "aa" * 32, "bb" * 32),
        )
    pg_conn.rollback()


def test_backend_chain_refuses_a_row_that_does_not_chain_onto_the_tip(pg_conn):
    from contextd.db import append_event

    append_event(pg_conn, "test", "note", content="first")
    pg_conn.execute("BEGIN")
    with pytest.raises(Exception, match="does not chain onto"):
        pg_conn.execute(
            "INSERT INTO events (id, ts, source, kind, prev_hash, chain_hash) "
            "VALUES (?,?,?,?,?,?)",
            (2, "2026-01-01T00:00:00+00:00", "fork", "note", "aa" * 32, "bb" * 32),
        )
    pg_conn.rollback()


def test_backend_refuses_to_open_when_append_only_enforcement_is_missing(
    pg_conn, pg_url, monkeypatch
):
    """Dropping a trigger must be loud, not silently repaired on next connect."""
    from contextd.backends.postgres import PostgresBackend
    from contextd.db import ChainStateError

    pg_conn.execute("DROP TRIGGER events_no_update ON events")
    pg_conn.commit()
    monkeypatch.setenv("CONTEXTD_DATABASE_URL", pg_url)
    with pytest.raises(ChainStateError, match="append-only enforcement"):
        PostgresBackend().connect()


def test_backend_refuses_a_newer_schema_version(pg_conn, pg_url, monkeypatch):
    """The refusal runs before any DDL, as the SQLite path's does."""
    from contextd.backends.postgres import PostgresBackend
    from contextd.db import SchemaVersionError

    pg_conn.execute("UPDATE schema_meta SET version = 99 WHERE singleton = 1")
    pg_conn.commit()
    monkeypatch.setenv("CONTEXTD_DATABASE_URL", pg_url)
    with pytest.raises(SchemaVersionError, match="newer contextd"):
        PostgresBackend().connect()


def test_backend_verify_detects_a_tip_that_diverges_from_history(pg_conn):
    """Owner-level tampering that bypasses the trigger is still visible."""
    from contextd.db import append_event, verify_chain_read_only

    append_event(pg_conn, "test", "note", content="first")
    assert verify_chain_read_only(pg_conn)["ok"]
    pg_conn.execute("UPDATE chain_tip SET id = 7 WHERE singleton = 1")
    pg_conn.commit()
    result = verify_chain_read_only(pg_conn)
    assert not result["ok"]
    assert "does not match recorded tip" in result["witness_error"]


# --- multi-host -----------------------------------------------------------

def test_multihost_two_archive_roots_share_one_chain(pg_url, tmp_path, monkeypatch):
    """Two hosts, two archive roots, one ledger — appends interleave cleanly.

    Under the single-host protocol these two would each `flock` their own inode,
    each read their own witness, and both compute the same next event id.
    """
    from contextd.db import append_event, connect, verify_chain_read_only

    monkeypatch.setenv("CONTEXTD_DATABASE_URL", pg_url)
    conns = []
    for name in ("host-a", "host-b"):
        root = tmp_path / name
        root.mkdir()
        monkeypatch.setenv("CONTEXTD_HOME", str(root))
        conns.append(connect())
    a, b = conns
    assert a.archive_root != b.archive_root

    ids = []
    for i in range(6):
        ids.append(append_event(conns[i % 2], "test", "note", content=f"e{i}"))

    assert ids == [1, 2, 3, 4, 5, 6]
    assert verify_chain_read_only(a)["ok"]
    assert verify_chain_read_only(b)["ok"]
    for conn in conns:
        conn.close()


def test_multihost_concurrent_appends_do_not_fork_the_chain(
    pg_url, tmp_path, monkeypatch
):
    from contextd.db import append_event, connect, verify_chain_read_only

    monkeypatch.setenv("CONTEXTD_DATABASE_URL", pg_url)
    hosts = []
    for name in ("host-a", "host-b", "host-c"):
        root = tmp_path / name
        root.mkdir()
        monkeypatch.setenv("CONTEXTD_HOME", str(root))
        hosts.append(connect())

    errors: list[BaseException] = []
    barrier = threading.Barrier(len(hosts))

    def worker(conn, tag):
        try:
            barrier.wait(timeout=30)
            for i in range(5):
                append_event(conn, "test", "note", content=f"{tag}-{i}")
        except BaseException as exc:  # noqa: BLE001 - surfaced below
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(conn, tag))
        for conn, tag in zip(hosts, "abc")
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert not errors, errors
    rows = hosts[0].execute(
        "SELECT id, prev_hash, chain_hash FROM events ORDER BY id"
    ).fetchall()
    assert [int(r["id"]) for r in rows] == list(range(1, 16))
    for i in range(1, len(rows)):
        assert rows[i]["prev_hash"] == rows[i - 1]["chain_hash"]
    assert verify_chain_read_only(hosts[0])["ok"]
    for conn in hosts:
        conn.close()


def test_multihost_single_use_authorization_is_redeemed_exactly_once(
    pg_url, tmp_path, monkeypatch
):
    """The gate-proof invariant, across two archive roots and one database."""
    from contextd import attest
    from contextd.db import connect, verify_chain_read_only

    monkeypatch.setenv("CONTEXTD_DATABASE_URL", pg_url)
    conns = []
    for name in ("host-a", "host-b"):
        root = tmp_path / name
        root.mkdir()
        monkeypatch.setenv("CONTEXTD_HOME", str(root))
        conns.append(connect())
    a, b = conns
    assert a.archive_root != b.archive_root

    auth = _authorization(a)
    results: dict[str, object] = {}
    barrier = threading.Barrier(2)

    def redeem(conn, tag):
        try:
            barrier.wait(timeout=30)
            results[tag] = attest.authorized_append(
                conn, "note", "note", auth, ACTION_CLASS, "global", content=ACT
            )
        except attest.AttestationError as exc:
            results[tag] = exc

    threads = [
        threading.Thread(target=redeem, args=(conn, tag))
        for conn, tag in ((a, "a"), (b, "b"))
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    outcomes = [results["a"], results["b"]]
    successes = [o for o in outcomes if isinstance(o, int)]
    refusals = [o for o in outcomes if isinstance(o, attest.AttestationError)]
    assert len(successes) == 1, outcomes
    assert len(refusals) == 1, outcomes
    assert isinstance(refusals[0], attest.AlreadyConsumedError)

    consumed = a.execute(
        "SELECT consumed_event FROM operator_nonces WHERE nonce = ?",
        (auth.nonce,),
    ).fetchone()["consumed_event"]
    assert consumed == successes[0]

    acts = a.execute(
        "SELECT count(*) AS n FROM events WHERE source='note' AND content = ?",
        (ACT,),
    ).fetchone()["n"]
    assert acts == 1
    # The refusal is durable, written by the core inside the same transaction
    # that detected it.
    refusal_rows = a.execute(
        "SELECT count(*) AS n FROM events WHERE kind = 'refuse'"
    ).fetchone()["n"]
    assert refusal_rows == 1
    assert verify_chain_read_only(a)["ok"]
    for conn in conns:
        conn.close()


# --- migration ------------------------------------------------------------

def _sqlite_archive(tmp_path, monkeypatch, root_name, events=5):
    from contextd.db import append_event, connect

    root = tmp_path / root_name
    root.mkdir()
    monkeypatch.delenv("CONTEXTD_DATABASE_URL", raising=False)
    monkeypatch.setenv("CONTEXTD_HOME", str(root))
    conn = connect()
    for i in range(events):
        append_event(conn, "test", "note", content=f"sqlite event {i}")
    return conn


def test_migration_sqlite_to_postgres_preserves_the_chain(
    pg_url, tmp_path, monkeypatch
):
    """Every chain hash survives the move, so history verifies unchanged."""
    from contextd.backends.postgres import PostgresBackend
    from contextd.backends.transfer import migrate_sqlite_to_postgres
    from contextd.db import verify_chain_read_only

    source = _sqlite_archive(tmp_path, monkeypatch, "sqlite-home", events=5)
    before = source.execute(
        "SELECT id, chain_hash FROM events ORDER BY id"
    ).fetchall()

    monkeypatch.setenv("CONTEXTD_DATABASE_URL", pg_url)
    dest = PostgresBackend().connect()
    summary = migrate_sqlite_to_postgres(source, dest)

    assert summary["events"] == 5
    after = dest.execute("SELECT id, chain_hash FROM events ORDER BY id").fetchall()
    assert [(int(r["id"]), r["chain_hash"]) for r in after] == [
        (int(r["id"]), r["chain_hash"]) for r in before
    ]
    assert verify_chain_read_only(dest)["ok"]
    assert summary["destination_verification"]["checked"] == 5
    # The tip moved with the history rather than being asserted separately.
    tip = dest.execute(
        "SELECT id, chain_hash FROM chain_tip WHERE singleton = 1"
    ).fetchone()
    assert int(tip["id"]) == 5
    assert tip["chain_hash"] == before[-1]["chain_hash"]
    source.close()
    dest.close()


def test_migration_carries_the_authority_plane(pg_url, tmp_path, monkeypatch):
    """A migrated archive must not resurrect an already-spent authorization."""
    from contextd import attest
    from contextd.backends.postgres import PostgresBackend
    from contextd.backends.transfer import migrate_sqlite_to_postgres

    source = _sqlite_archive(tmp_path, monkeypatch, "sqlite-home", events=0)
    auth = _authorization(source)
    attest.authorized_append(
        source, "note", "note", auth, ACTION_CLASS, "global", content=ACT
    )

    monkeypatch.setenv("CONTEXTD_DATABASE_URL", pg_url)
    dest = PostgresBackend().connect()
    migrate_sqlite_to_postgres(source, dest)

    consumed = dest.execute(
        "SELECT consumed_event FROM operator_nonces WHERE nonce = ?",
        (auth.nonce,),
    ).fetchone()
    assert consumed is not None and consumed["consumed_event"] is not None
    with pytest.raises(attest.AlreadyConsumedError):
        attest.authorized_append(
            dest, "note", "note", auth, ACTION_CLASS, "global", content=ACT
        )
    source.close()
    dest.close()


def test_migration_refuses_a_source_whose_chain_does_not_verify(
    pg_url, tmp_path, monkeypatch
):
    from contextd.backends.postgres import PostgresBackend
    from contextd.backends.transfer import MigrationError, migrate_sqlite_to_postgres

    source = _sqlite_archive(tmp_path, monkeypatch, "sqlite-home", events=3)
    source.execute("DROP TRIGGER events_no_update")
    source.execute("UPDATE events SET content = 'tampered' WHERE id = 2")
    source.commit()

    monkeypatch.setenv("CONTEXTD_DATABASE_URL", pg_url)
    dest = PostgresBackend().connect()
    with pytest.raises(MigrationError, match="does not verify"):
        migrate_sqlite_to_postgres(source, dest)
    assert dest.execute("SELECT count(*) AS n FROM events").fetchone()["n"] == 0
    source.close()
    dest.close()


def test_migration_refuses_a_non_empty_destination(pg_url, tmp_path, monkeypatch):
    from contextd.backends.postgres import PostgresBackend
    from contextd.backends.transfer import MigrationError, migrate_sqlite_to_postgres
    from contextd.db import append_event

    source = _sqlite_archive(tmp_path, monkeypatch, "sqlite-home", events=2)
    monkeypatch.setenv("CONTEXTD_DATABASE_URL", pg_url)
    dest = PostgresBackend().connect()
    append_event(dest, "test", "note", content="pre-existing")
    with pytest.raises(MigrationError, match="non-empty archive"):
        migrate_sqlite_to_postgres(source, dest)
    source.close()
    dest.close()


def test_migration_leaves_the_source_archive_usable(pg_url, tmp_path, monkeypatch):
    """No forced cutover: the SQLite archive still works after a migration."""
    from contextd.backends.postgres import PostgresBackend
    from contextd.backends.transfer import migrate_sqlite_to_postgres
    from contextd.db import append_event, verify_chain_read_only

    source = _sqlite_archive(tmp_path, monkeypatch, "sqlite-home", events=3)
    monkeypatch.setenv("CONTEXTD_DATABASE_URL", pg_url)
    dest = PostgresBackend().connect()
    migrate_sqlite_to_postgres(source, dest)

    monkeypatch.delenv("CONTEXTD_DATABASE_URL", raising=False)
    assert append_event(source, "test", "note", content="still working") == 4
    assert verify_chain_read_only(source)["ok"]
    source.close()
    dest.close()
