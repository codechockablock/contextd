"""Schema cutovers are explicit and older binaries fail before mutation."""

import pytest

from contextd.db import (
    SCHEMA_VERSION,
    SchemaMigrationRequired,
    append_event,
    connect,
    open_archive_for_migration,
    verify_chain,
)
from contextd.migrate import migrate


def _user_version(conn):
    return conn.execute("PRAGMA user_version").fetchone()[0]


def test_fresh_init_is_stamped(isolated_contextd_home):
    conn = connect()
    assert _user_version(conn) == SCHEMA_VERSION == 2
    assert verify_chain(conn)["ok"]


def test_legacy_archive_requires_explicit_cutover_without_chain_disturbance(
        isolated_contextd_home):
    conn = connect()
    append_event(conn, "note", "note", content="pre-stamp fact")
    conn.execute("PRAGMA user_version = 0")  # simulate a legacy archive
    conn.close()
    with pytest.raises(SchemaMigrationRequired):
        connect()
    migration = open_archive_for_migration()
    migrate(migration)
    migration.close()
    conn = connect()
    assert _user_version(conn) == SCHEMA_VERSION
    assert verify_chain(conn)["ok"]


def test_future_versions_are_refused_not_silently_adopted(isolated_contextd_home):
    """An archive from a newer contextd must not be opened by an older build.

    The old behaviour accepted it, applied this version's schema over it, and
    carried on — so the damage landed before anyone could notice.
    """
    from contextd.db import SchemaVersionError

    conn = connect()
    conn.execute("PRAGMA user_version = 7")
    conn.close()
    with pytest.raises(SchemaVersionError) as exc:
        connect()
    assert "newer contextd" in str(exc.value)
    assert "Refusing before any filesystem or database change" in str(exc.value)


def test_pre_hardening_binary_version_cannot_open_current_archive(monkeypatch):
    """The prior build advertised schema 1; the hardening cutover is version 2."""
    import contextd.db as db

    connect().close()
    monkeypatch.setattr(db, "SCHEMA_VERSION", 1)
    with pytest.raises(db.SchemaVersionError):
        db.assert_supported_schema()
