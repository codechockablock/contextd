"""A ``sqlite3``-shaped surface over psycopg 3, so call sites do not fork.

The codebase reads rows as both ``row["chain_hash"]`` and ``row[0]``, calls
``conn.execute(sql, params)`` on the *connection*, checks
``conn.in_transaction``, and writes ``?`` placeholders. psycopg does none of
those. This module supplies exactly that surface and nothing more — it is a
compatibility shim, not an ORM, and every method here exists because a specific
line in `db.py`, `attest.py`, or `ledger_sig.py` calls it.

**Transactions are explicit.** The connection is opened with
``autocommit=True`` so psycopg never injects a ``BEGIN`` of its own, and every
transaction boundary in the codebase — which are already explicit, because
SQLite needed them to be — is the only one. The alternative (psycopg's implicit
transactions) would silently open a snapshot on the first incidental ``SELECT``
and hold it until commit, which is precisely the wrong behavior for a protocol
whose correctness depends on when the tip row is locked.
"""

from __future__ import annotations

from typing import Iterator, Sequence

from .paramstyle import to_pyformat


class Row:
    """A result row addressable by column name or position, like ``sqlite3.Row``."""

    __slots__ = ("_columns", "_values")

    def __init__(self, columns: tuple[str, ...], values: tuple):
        self._columns = columns
        self._values = values

    def __getitem__(self, key):
        if isinstance(key, str):
            try:
                return self._values[self._columns.index(key)]
            except ValueError:
                raise IndexError(f"no such column: {key}") from None
        return self._values[key]

    def keys(self) -> list[str]:
        return list(self._columns)

    def __iter__(self) -> Iterator:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __contains__(self, key) -> bool:
        return key in self._columns

    def __eq__(self, other) -> bool:
        if isinstance(other, Row):
            return self._columns == other._columns and self._values == other._values
        return tuple(self._values) == other

    def __repr__(self) -> str:
        pairs = ", ".join(f"{c}={v!r}" for c, v in zip(self._columns, self._values))
        return f"<Row {pairs}>"


class PGCursor:
    """The subset of the sqlite3 cursor API the archive actually uses."""

    def __init__(self, cursor):
        self._cursor = cursor
        description = cursor.description
        self._columns: tuple[str, ...] = (
            tuple(d.name for d in description) if description else ()
        )

    def _wrap(self, values):
        return None if values is None else Row(self._columns, tuple(values))

    def fetchone(self):
        return self._wrap(self._cursor.fetchone())

    def fetchall(self) -> list[Row]:
        return [self._wrap(v) for v in self._cursor.fetchall()]

    def fetchmany(self, size: int | None = None) -> list[Row]:
        rows = self._cursor.fetchmany(size) if size else self._cursor.fetchmany()
        return [self._wrap(v) for v in rows]

    def __iter__(self) -> Iterator[Row]:
        for values in self._cursor:
            yield self._wrap(values)

    @property
    def rowcount(self) -> int:
        """Rows the statement affected.

        Load-bearing: ``attest.consume_nonce`` asserts ``rowcount == 1`` to
        refuse a double-spend. psycopg reports this the same way sqlite3 does
        for a plain ``UPDATE``.
        """
        return self._cursor.rowcount

    def close(self) -> None:
        self._cursor.close()


class PGConnection:
    """A ``sqlite3.Connection``-shaped wrapper over a psycopg connection."""

    def __init__(self, connection, *, archive_root=None):
        self._connection = connection
        self._in_transaction = False
        #: Postgres has no filesystem path, so the archive root that SQLite
        #: derives from ``PRAGMA database_list`` must be supplied explicitly;
        #: without it the very first line of the append path raises.
        self.archive_root = archive_root
        #: Accepted and ignored; rows are always :class:`Row`.
        self.row_factory = None

    # -- transaction control ---------------------------------------------

    @property
    def in_transaction(self) -> bool:
        return self._in_transaction

    def execute(self, sql: str, params: Sequence | None = None) -> PGCursor:
        statement = sql.strip()
        upper = statement.upper()
        # SQLite spells the exclusive-write intent ``BEGIN IMMEDIATE``; Postgres
        # has no equivalent and does not need one, because the append protocol
        # takes its exclusion from a row lock instead (see postgres.py).
        if upper.startswith("BEGIN"):
            if self._in_transaction:
                raise RuntimeError("a transaction is already open")
            self._raw("BEGIN")
            self._in_transaction = True
            return PGCursor(self._connection.cursor())
        if upper in ("COMMIT", "END"):
            return self._finish("COMMIT")
        if upper == "ROLLBACK":
            return self._finish("ROLLBACK")

        cursor = self._connection.cursor()
        cursor.execute(to_pyformat(sql), tuple(params) if params else None)
        return PGCursor(cursor)

    def _raw(self, sql: str) -> None:
        self._connection.execute(sql)

    def _finish(self, verb: str) -> PGCursor:
        if self._in_transaction:
            self._raw(verb)
            self._in_transaction = False
        return PGCursor(self._connection.cursor())

    def executescript(self, script: str) -> None:
        """Run a multi-statement DDL script, as ``sqlite3.executescript`` does.

        sqlite3 commits any open transaction first; this mirrors that so schema
        application has the same visible effect on both backends.
        """
        if self._in_transaction:
            self.commit()
        self._connection.execute(script)

    def run_ddl(self, script: str) -> None:
        """Run a multi-statement script *inside* the open transaction.

        Postgres DDL is transactional, and schema bootstrap has to be: two hosts
        starting at once both apply it, and ``CREATE OR REPLACE`` from two
        sessions raises *"tuple concurrently updated"* on the shared catalog
        row. Bootstrap therefore runs under an advisory lock in one transaction
        (see `postgres.PostgresBackend.connect`), which `executescript` would
        break by committing it out from under the lock.
        """
        self._connection.execute(script)

    def commit(self) -> None:
        self._finish("COMMIT")

    def rollback(self) -> None:
        self._finish("ROLLBACK")

    def close(self) -> None:
        try:
            if self._in_transaction:
                self.rollback()
        finally:
            self._connection.close()

    # -- misc parity ------------------------------------------------------

    def cursor(self) -> PGCursor:
        return PGCursor(self._connection.cursor())

    @property
    def closed(self) -> bool:
        return self._connection.closed

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is None:
            self.commit()
        else:
            self.rollback()
