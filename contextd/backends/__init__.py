"""Storage backend selection.

Selection is by the ``CONTEXTD_DATABASE_URL`` environment variable and nothing
else. Absent — which is every existing install — means SQLite, on the same path,
with the same protocol, and no migration. There is deliberately no
auto-detection and no "upgrade if a server is reachable": moving an archive to
Postgres changes where the chain tip is attested, and that is an operator
decision (see `postgres.py`, "The security decision").
"""

from __future__ import annotations

from .base import AppendScope, StorageBackend
from .sqlite import SQLiteBackend

__all__ = [
    "AppendScope",
    "StorageBackend",
    "SQLiteBackend",
    "active_backend",
    "backend_for",
    "postgres_configured",
    "table_names",
]


def table_names(conn) -> set[str]:
    """Tables present on ``conn``, without mutating it."""
    return backend_for(conn).table_names(conn)


def postgres_configured() -> bool:
    from .postgres import database_url

    return database_url() is not None


def active_backend() -> StorageBackend:
    """The backend this process is configured to open archives with."""
    if postgres_configured():
        from .postgres import PostgresBackend

        return PostgresBackend()
    return SQLiteBackend()


def backend_for(conn) -> StorageBackend:
    """The backend that owns an already-open connection.

    Dispatch is on the connection object, not on the environment, so a process
    holding both a SQLite archive and a Postgres one routes each correctly.
    """
    from .pgdriver import PGConnection

    if isinstance(conn, PGConnection):
        from .postgres import PostgresBackend

        return PostgresBackend()
    return SQLiteBackend()
