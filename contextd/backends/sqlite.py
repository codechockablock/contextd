"""The default backend: one SQLite file, witnessed by two local files.

This is the shipped single-host protocol, moved behind the backend interface
**without changing a step of it**. Every call below delegates to the function in
`contextd.db` that already implemented it, in the same order, so a single-host
archive sees byte-identical behavior and no migration.

The protocol's safety argument, restated so the Postgres backend can be compared
against it honestly: an exclusive `flock` serializes appenders; a recovery
journal naming every permissible outcome is fsynced *before* the transaction
opens; the witness naming the new tip is fsynced *after* the database commits.
A crash therefore always lands in a state the two local files can adjudicate.

All three steps assume one host, and that is not a defect here — it is the
deployment this backend is for.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .base import AppendScope, StorageBackend


class SQLiteAppendScope(AppendScope):
    """Witness-first append: journal before, database, witness after."""

    def __init__(self, conn, paths: dict[str, Path]):
        self._conn = conn
        self._paths = paths
        self.previous = {"id": 0, "chain_hash": ""}

    def acquire(self) -> dict:
        # The flock is already held by the enclosing context manager; this
        # completes any append a previous process died in the middle of, and
        # returns the tip that survived it.
        from ..db import _recover_locked

        self.previous = _recover_locked(self._conn, self._paths)
        return self.previous

    def declare(self, outcomes: list[dict]) -> None:
        from ..db import WITNESS_VERSION, _atomic_json

        _atomic_json(
            self._paths["recovery"],
            {
                "version": WITNESS_VERSION,
                "previous": self.previous,
                "outcomes": outcomes,
            },
        )

    def open_transaction(self) -> None:
        self._conn.execute("BEGIN IMMEDIATE")

    def record_tip(self, tip: dict) -> None:
        """No-op: SQLite's tip *is* the highest row, published by ``publish``."""

    def publish(self, tip: dict) -> None:
        from ..db import _atomic_json, _unlink_durable, _witness_value

        _atomic_json(self._paths["witness"], _witness_value(tip))
        _unlink_durable(self._paths["recovery"])

    def abandon(self, *, committed: bool) -> None:
        from ..db import _unlink_durable

        if not committed:
            self._conn.rollback()
            _unlink_durable(self._paths["recovery"])
        # Once SQLite has committed, the journal is the durable bridge to the
        # stale witness and must survive: a later connect finishes the append
        # exactly once instead of reading a mismatched tip as tampering.


class SQLiteBackend(StorageBackend):
    name = "sqlite"
    supports_search = True
    #: SQLite's append-only triggers are real, but any owner-level process can
    #: ``DROP TRIGGER`` them and then rewrite history. They raise the cost of a
    #: careless mutation; they are not a privilege boundary. See `postgres.py`,
    #: which is genuinely stronger on exactly this point.
    enforces_append_only_in_db = False

    def connect(self) -> Any:
        from ..db import connect_sqlite

        return connect_sqlite()

    def db_tip(self, conn) -> dict:
        from ..db import _db_tip

        return _db_tip(conn)

    def table_names(self, conn) -> set[str]:
        return {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }

    @contextmanager
    def append_scope(self, conn) -> Iterator[SQLiteAppendScope]:
        from ..db import _chain_lock, _connection_root

        with _chain_lock(_connection_root(conn)) as paths:
            yield SQLiteAppendScope(conn, paths)

    def verify_tip(self, conn, root: Path | None = None) -> None:
        from ..db import (
            ChainStateError,
            _connection_root,
            _db_tip,
            _read_state,
            _read_tip,
            chain_state_paths,
        )

        archive_root = root or _connection_root(conn)
        witness = _read_state(
            chain_state_paths(archive_root)["witness"], "chain witness"
        )
        if witness is None or set(witness) != {"version", "id", "chain_hash"}:
            raise ChainStateError("chain witness is missing or malformed")
        witnessed = _read_tip(
            {"id": witness.get("id"), "chain_hash": witness.get("chain_hash")},
            "chain witness",
        )
        current = _db_tip(conn)
        if current != witnessed:
            raise ChainStateError(
                f"database tip {current['id']} does not match witnessed tip "
                f"{witnessed['id']}"
            )

    def reconcile(self, conn, root: Path | None = None) -> dict:
        from ..db import _chain_lock, _connection_root, _recover_locked

        with _chain_lock(root or _connection_root(conn)) as paths:
            return _recover_locked(conn, paths)
