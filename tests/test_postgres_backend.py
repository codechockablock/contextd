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


def test_migration_carries_the_signature_algorithm_tags(
    pg_url, tmp_path, monkeypatch
):
    """A signature record whose scheme tag is lost falls back to "the only
    scheme that existed before the column did", so dropping `alg` in transit
    would relabel a post-quantum key as P-256 and every signature under it
    would stop verifying on the far side.
    """
    from contextd.backends.postgres import PostgresBackend
    from contextd.backends.transfer import migrate_sqlite_to_postgres

    source = _sqlite_archive(tmp_path, monkeypatch, "sqlite-home", events=1)
    source.execute(
        "INSERT INTO service_keys (key_id, public_pem, created, retired, alg) "
        "VALUES (?,?,?,NULL,?)",
        ("f" * 32, "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----\n",
         1, "ml-dsa-65"))
    source.execute(
        "INSERT INTO service_checkpoints "
        "(tip_id, alg, chain_hash, key_id, signature, signed_at) "
        "VALUES (?,?,?,?,?,?)",
        (1, "ml-dsa-65", "ab" * 32, "f" * 32, "cd" * 32, 2))
    source.commit()

    monkeypatch.setenv("CONTEXTD_DATABASE_URL", pg_url)
    dest = PostgresBackend().connect()
    summary = migrate_sqlite_to_postgres(source, dest)
    assert summary["carried"]["service_checkpoints"] == 1
    assert dest.execute(
        "SELECT alg FROM service_keys WHERE key_id = ?", ("f" * 32,)
    ).fetchone()["alg"] == "ml-dsa-65"
    assert dest.execute(
        "SELECT alg FROM service_checkpoints WHERE tip_id = 1"
    ).fetchone()["alg"] == "ml-dsa-65"
    source.close()
    dest.close()


# --- schema parity --------------------------------------------------------

def test_a_postgres_archive_can_register_a_service_key(pg_conn):
    """Schema version 3. Without the `alg` column `_load_or_create_key`'s
    INSERT fails, which silently left every backup manifest unsigned."""
    from contextd.ledger_sig import CLASSICAL_ALG, _load_or_create_key

    _private, key_id = _load_or_create_key(pg_conn)
    row = pg_conn.execute(
        "SELECT key_id, alg FROM service_keys WHERE key_id = ?", (key_id,)
    ).fetchone()
    assert row["alg"] == CLASSICAL_ALG


def test_an_older_postgres_archive_is_upgraded_without_reinstalling_triggers(
    pg_url, monkeypatch
):
    """Additive DDL only. Re-running the trigger DDL to lift a schema version
    would recreate a dropped append-only trigger and repair away the only
    evidence that history was writable in the interval."""
    from contextd.backends.postgres import PostgresBackend
    from contextd.db import ChainStateError

    monkeypatch.setenv("CONTEXTD_DATABASE_URL", pg_url)
    conn = PostgresBackend().connect()
    conn.execute("ALTER TABLE service_keys DROP COLUMN alg")
    conn.execute("DROP TABLE service_checkpoints")
    conn.execute("UPDATE schema_meta SET version = 2 WHERE singleton = 1")
    conn.commit()
    conn.close()

    upgraded = PostgresBackend().connect()
    assert upgraded.execute("SELECT alg FROM service_keys").fetchall() == []
    assert upgraded.execute(
        "SELECT to_regclass('service_checkpoints') AS t"
    ).fetchone()["t"] is not None
    from contextd.backends.postgres import SCHEMA_VERSION as PG_SCHEMA_VERSION
    assert int(upgraded.execute(
        "SELECT version FROM schema_meta WHERE singleton = 1"
    ).fetchone()["version"]) == PG_SCHEMA_VERSION

    # ...and lifting the version still refuses an archive whose enforcement is
    # gone, rather than quietly reinstalling it on the way past.
    upgraded.execute("DROP TRIGGER events_no_update ON events")
    upgraded.execute("UPDATE schema_meta SET version = 2 WHERE singleton = 1")
    upgraded.commit()
    upgraded.close()
    with pytest.raises(ChainStateError, match="append-only enforcement"):
        PostgresBackend().connect()


def test_a_fresh_postgres_archive_creates_its_archive_root(
    pg_url, tmp_path, monkeypatch
):
    """A server-backed archive still has a filesystem side — the blob store,
    scratch, the service signing key, and the directory a backup names as its
    source all live under the archive root."""
    from contextd.backends.postgres import PostgresBackend

    root = tmp_path / "never-created"
    monkeypatch.setenv("CONTEXTD_DATABASE_URL", pg_url)
    monkeypatch.setenv("CONTEXTD_HOME", str(root))
    assert not root.exists()
    conn = PostgresBackend().connect()
    try:
        assert root.is_dir()
        assert root.stat().st_mode & 0o777 == 0o700
    finally:
        conn.close()


# --- backup: same bundle format, produced from rows -----------------------
#
# `PGConnection` has no ``backup()`` and never will: SQLite's online backup API
# copies a file, and there is no file. The bundle is produced instead by
# rendering the archive as a SQLite archive (`backends/transfer.py`), so the
# `.ctxbackup` format does not fork per backend — which is what lets every
# adversarial-bundle test, the retention pass, and the restore drill keep
# applying to a bundle whichever backend made it.

def _history(conn, events=4):
    from contextd.db import append_event

    return [append_event(conn, "test", "note", content=f"pg event {i}")
            for i in range(events)]


def test_backup_from_postgres_restores_into_a_verifying_sqlite_archive(
    pg_conn, tmp_path, monkeypatch
):
    """The round trip this lane exists for: create on Postgres, restore, and
    have the received archive verify as an ordinary archive."""
    from contextd import home
    from contextd.backup import create_backup, restore_backup, validate_bundle
    from contextd.db import connect, verify_chain
    from contextd.search import search

    _history(pg_conn, events=4)
    source_home = home()
    result = create_backup(pg_conn, source_home, tmp_path / "backups")
    assert result["events"] == 4

    bundle = result["bundle"]
    trust = source_home / "backup-trust.json"
    verified = validate_bundle(bundle, trust_store=trust)
    # Not "unsigned but tolerated": the manifest carries a real service
    # signature and authenticates against pins taken from the live archive.
    assert verified["authentication"]["authenticated"] is True
    assert verified["snapshot"]["events"] == 4

    destination = tmp_path / "restored"
    restore_backup(bundle, destination, trust_store=trust)

    monkeypatch.delenv("CONTEXTD_DATABASE_URL", raising=False)
    monkeypatch.setenv("CONTEXTD_HOME", str(destination))
    restored = connect()
    try:
        chain = verify_chain(restored)
        assert chain["ok"] and chain["checked"] == 4
        # FTS is rebuilt by the ordinary insert trigger during the export, so
        # the restored archive is searchable even though the Postgres archive
        # it came from declares search out of scope.
        assert [row["id"] for row in search(restored, "event")] == [1, 2, 3, 4]
    finally:
        restored.close()


def test_backup_from_postgres_carries_referenced_blobs(pg_conn, tmp_path):
    """Blob payloads live on the filesystem on both backends, so the bundle
    must carry the ones its events reference."""
    from contextd import home
    from contextd.backup import create_backup, validate_bundle
    from contextd.db import append_event, store_blob

    digest = store_blob(b"an oversized payload that lives outside the rows" * 64)
    append_event(pg_conn, "fs", "file_write", uri="/x/big.md",
                 content_hash=digest, meta={"size": 3072, "blob": digest})
    result = create_backup(pg_conn, home(), tmp_path / "backups")
    assert result["blobs"] == 1
    verified = validate_bundle(result["bundle"],
                               trust_store=home() / "backup-trust.json")
    assert verified["manifest"]["blobs"] == [digest]
    assert (result["bundle"] / "store" / digest[:2] / digest).is_file()


def test_backup_from_postgres_refuses_a_tip_that_diverges_from_history(
    pg_conn, tmp_path
):
    """`chain_tip` disagreeing with `events` is the one signal a Postgres
    archive has that history was written with the continuity trigger
    disabled. A backup must refuse it, not render it into a valid bundle."""
    from contextd import home
    from contextd.backup import create_backup
    from contextd.db import ChainStateError

    _history(pg_conn, events=2)
    pg_conn.execute("UPDATE chain_tip SET id = 9 WHERE singleton = 1")
    pg_conn.commit()
    with pytest.raises(ChainStateError, match="does not match recorded tip"):
        create_backup(pg_conn, home(), tmp_path / "backups")


def test_backup_refuses_a_postgres_connection_from_another_archive_root(
    pg_conn, tmp_path
):
    """A Postgres connection has no file to identify it, so the archive root it
    carries is what binds it to a home — and that is checked, not trusted."""
    from contextd.backup import BackupError, create_backup

    _history(pg_conn, events=1)
    other = tmp_path / "not-this-archive"
    other.mkdir()
    with pytest.raises(BackupError, match="does not belong to the source archive"):
        create_backup(pg_conn, other, tmp_path / "backups")


def test_backup_from_postgres_ignores_a_stale_sqlite_witness_in_the_root(
    pg_conn, tmp_path
):
    """A root that used to hold a SQLite archive still has a witness file
    naming a tip from a different history. Copying it into the bundle would
    present it as an attestation of THIS one."""
    import json

    from contextd import home
    from contextd.backup import create_backup, validate_bundle

    _history(pg_conn, events=3)
    stale = {"version": 2, "id": 999, "chain_hash": "ab" * 32}
    (home() / "chain-witness.json").write_text(json.dumps(stale))
    (home() / "chain-recovery.json").write_text(json.dumps(
        {"version": 2, "previous": stale,
         "outcomes": [{"id": 1000, "chain_hash": "cd" * 32}]}))

    bundle = create_backup(pg_conn, home(), tmp_path / "backups")["bundle"]
    assert not (bundle / "chain-recovery.json").exists()
    assert json.loads((bundle / "chain-witness.json").read_text())["id"] == 3
    assert validate_bundle(
        bundle, trust_store=home() / "backup-trust.json"
    )["snapshot"]["head_id"] == 3


def test_backup_bundles_from_both_backends_have_the_same_shape(
    pg_conn, tmp_path, monkeypatch
):
    """One format, two producers. If these diverge, every consumer of a bundle
    has to learn which backend made it."""
    from contextd import home
    from contextd.backup import create_backup
    from contextd.db import append_event, connect

    _history(pg_conn, events=2)
    pg_bundle = create_backup(pg_conn, home(), tmp_path / "pg-backups")["bundle"]
    pg_files = sorted(p.relative_to(pg_bundle).as_posix()
                      for p in pg_bundle.rglob("*") if p.is_file())

    monkeypatch.delenv("CONTEXTD_DATABASE_URL", raising=False)
    sqlite_home = tmp_path / "sqlite-home"
    sqlite_home.mkdir()
    monkeypatch.setenv("CONTEXTD_HOME", str(sqlite_home))
    sconn = connect()
    for i in range(2):
        append_event(sconn, "test", "note", content=f"sqlite event {i}")
    sq_bundle = create_backup(
        sconn, sqlite_home, tmp_path / "sq-backups")["bundle"]
    sq_files = sorted(p.relative_to(sq_bundle).as_posix()
                      for p in sq_bundle.rglob("*") if p.is_file())
    sconn.close()

    assert pg_files == sq_files == [
        "chain-witness.json", "contextd.db", "manifest.json", "manifest.sha256",
    ]


# --- handoff --------------------------------------------------------------

def test_handoff_freezes_a_postgres_archive_into_a_verifying_view(
    pg_conn, tmp_path, monkeypatch
):
    """A Postgres archive has no witness file to read a tip from, so the view's
    chain state is derived from the database. The received view is an ordinary
    SQLite archive — a handoff must not require the receiver to run a cluster."""
    from contextd.db import connect, verify_chain
    from contextd.handoff import freeze_view_from_connection

    ids = _history(pg_conn, events=5)
    cutoff = ids[2]
    view = tmp_path / "view"
    info = freeze_view_from_connection(pg_conn, view, cutoff)

    assert info["tip"] == cutoff and info["events"] == cutoff
    assert info["source_tip"] == ids[-1]

    monkeypatch.delenv("CONTEXTD_DATABASE_URL", raising=False)
    monkeypatch.setenv("CONTEXTD_HOME", str(view))
    vconn = connect()
    try:
        chain = verify_chain(vconn)
        assert chain["ok"] and chain["checked"] == cutoff
        # the future is unreachable because the rows are absent, not filtered
        assert vconn.execute(
            "SELECT COUNT(*) c FROM events WHERE id > ?", (cutoff,)
        ).fetchone()["c"] == 0
    finally:
        vconn.close()


def test_checkpoint_compilation_refuses_postgres_and_names_the_route(
    pg_conn, tmp_path, monkeypatch
):
    """Selection reads SQLite JSON and FTS5, which this backend declares out of
    scope. The refusal has to name the route that works, because there is one:
    freeze a view — an ordinary SQLite archive — and compile from that."""
    from contextd import load_config
    from contextd.db import append_event, connect
    from contextd.handoff import (HandoffError, compile_checkpoint,
                                  freeze_view_from_connection)

    for i in range(3):
        append_event(pg_conn, "claude_code", "message", uri=f"claude://x{i}",
                     content=f"dialogue line {i}", meta={"role": "user"})

    with pytest.raises(HandoffError, match="compilation is SQLite-only"):
        compile_checkpoint(pg_conn, load_config())

    # the route the refusal names actually works
    view = tmp_path / "view"
    freeze_view_from_connection(pg_conn, view, 3)
    monkeypatch.delenv("CONTEXTD_DATABASE_URL", raising=False)
    monkeypatch.setenv("CONTEXTD_HOME", str(view))
    vconn = connect()
    try:
        out = compile_checkpoint(vconn, load_config(), budget=2000)
        assert "dialogue line 2" in out["package"]
        assert out["tip"] == 3
    finally:
        vconn.close()


# --- ingest ---------------------------------------------------------------

def test_ingest_runs_against_postgres_including_cursor_watermarks(
    pg_conn, tmp_path, monkeypatch
):
    """`ingest.py` imports sqlite3 for the BROWSER history file, not for the
    archive. Everything it writes goes through the backend-neutral db surface,
    so the whole ingest surface — including the cursor and watermark machinery
    that decides what has already been seen — runs here unchanged."""
    import json
    import sqlite3

    from contextd import load_config
    from contextd.db import get_cursor, verify_chain_read_only
    from contextd.ingest import ingest_note, scan_chrome, scan_claude, scan_fs

    cfg = load_config()
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "one.md").write_text("the first watched body")
    (watched / "two.md").write_text("the second watched body")
    cfg["ingest"]["watch_dirs"] = [str(watched)]
    cfg["ingest"]["text_extensions"] = [".md"]
    cfg["ingest"]["never_ingest"] = []
    cfg["ingest"]["max_file_bytes"] = 1024 * 1024

    assert scan_fs(pg_conn, cfg)["file_write"] == 2
    # the cursor is what makes the second pass a no-op rather than a re-ingest
    assert scan_fs(pg_conn, cfg)["file_write"] == 0
    assert sorted(get_cursor(pg_conn, "fs")["seen"]) == [
        str(watched / "one.md"), str(watched / "two.md")]
    (watched / "one.md").unlink()
    assert scan_fs(pg_conn, cfg)["file_delete"] == 1

    # browser watermark: a synthetic Chrome history file, scanned twice
    history = tmp_path / "History"
    browser = sqlite3.connect(history)
    browser.execute(
        "CREATE TABLE urls (url TEXT, title TEXT, last_visit_time INTEGER)")
    browser.execute("INSERT INTO urls VALUES "
                    "('https://example.org/a', 'A', 13300000000000000)")
    browser.commit()
    browser.close()
    monkeypatch.setattr("contextd.ingest.CHROME_HISTORY", str(history))
    assert scan_chrome(pg_conn, cfg)["page_visit"] == 1
    assert get_cursor(pg_conn, "chrome")["watermark"] == 13300000000000000
    assert scan_chrome(pg_conn, cfg)["page_visit"] == 0

    # claude transcript cursor: byte offsets survive in the archive's cursors
    projects = tmp_path / "projects" / "p"
    projects.mkdir(parents=True)
    (projects / "sess.jsonl").write_text(json.dumps({
        "type": "user", "uuid": "u" * 20,
        "timestamp": "2026-01-01T00:00:00Z",
        "message": {"content": "a transcript line worth keeping"}}) + "\n")
    cfg["claude"]["projects_dir"] = str(tmp_path / "projects")
    assert scan_claude(pg_conn, cfg)["message"] == 1
    assert scan_claude(pg_conn, cfg)["message"] == 0
    assert get_cursor(pg_conn, "claude_code:p/sess.jsonl")["o"] > 0

    ingest_note(pg_conn, "a deliberate note")
    assert verify_chain_read_only(pg_conn)["ok"]
