"""The storage-backend boundary, and where it deliberately stops.

`contextd` binds ``sqlite3`` directly in five modules — `db` (18 uses),
`attest` (10), `backup` (18), `handoff` (5), `ingest` (3). Abstracting all of
them would be a rewrite of the whole product. This boundary is drawn around one
thing instead: **the append protocol and the chain state it maintains**, which
is the only part whose guarantee is claimed to hold across hosts.

Explicitly **inside** the boundary:

* opening a connection and applying schema
* the schema-version refusal that must run before anything is mutated
* acquiring the chain tip, and the mutual exclusion that makes an append atomic
* recording the new tip, and verifying the chain against it

Explicitly **outside**, and still SQLite-only:

* full-text search. FTS5 has no Postgres equivalent, and `ts_rank` is not
  `bm25` — swapping backends would silently change ranking and snippets. Search
  is **out of scope** for the Postgres backend and `supports_search` is False,
  so a caller gets a refusal rather than quietly different results.
* `backup.py`'s bundle machinery, `handoff.py`, and `ingest.py`, all of which
  address the archive as a file on disk.

Naming that stop line is the point of this module. A backend that claimed the
whole surface and delivered the append path would be the more dangerous
artifact.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


class AppendScope(ABC):
    """One append's critical section, from tip acquisition to tip publication.

    The single-host protocol and the multi-host protocol differ *only* here, and
    they differ in where the exclusion comes from and when the tip becomes
    readable:

    ``sqlite`` — an ``fcntl.flock`` on a local file excludes other appenders, a
    recovery journal on local disk names every outcome this append may commit,
    and a witness file is finalized after the database commits. The tip is known
    *before* the transaction opens, and the two local files exist to adjudicate
    a crash landing between the commit and the witness write.

    ``postgres`` — the exclusion is a row lock on the singleton tip row, taken
    inside the append's own transaction, and the tip is advanced by an ``UPDATE``
    in that same transaction. The tip is therefore only knowable *after* the
    transaction opens. There is no journal and no witness file because there is
    no two-sided state to adjudicate: the event row and the tip it produces
    commit together or not at all.

    The ordering below is what both protocols have to agree on, and it is the
    reason the phases are separate calls rather than one method::

        acquire()            # postgres: BEGIN + SELECT ... FOR UPDATE
        <compute chain hashes from .previous>
        declare(outcomes)    # sqlite: write the recovery journal
        open_transaction()   # sqlite: BEGIN IMMEDIATE
        <check / bind / INSERT>
        record_tip(tip)      # postgres: UPDATE chain_tip
        <COMMIT>
        publish(tip)         # sqlite: finalize witness, unlink journal
    """

    #: The tip this append extends: ``{"id": int, "chain_hash": str}``.
    #: Only valid after :meth:`acquire`.
    previous: dict

    @abstractmethod
    def acquire(self) -> dict:
        """Take exclusion and read the authoritative tip. Sets ``previous``."""

    def declare(self, outcomes: list[dict]) -> None:
        """Durably name every tip this append is permitted to leave behind."""

    def open_transaction(self) -> None:
        """Open the write transaction, if the backend has not already."""

    def record_tip(self, tip: dict) -> None:
        """Advance the tip inside the append transaction."""

    def publish(self, tip: dict) -> None:
        """Publish the tip after the database has committed."""

    def abandon(self, *, committed: bool) -> None:
        """Release durable scratch state after a failure.

        ``committed`` says whether the database transaction got through. Once it
        has, a backend that keeps a journal must **keep** it: it is the only
        durable bridge back to the stale witness, and discarding it turns an
        already-committed append into an unexplainable tip.
        """


class StorageBackend(ABC):
    """A place an archive's events can live, and the append protocol for it."""

    #: Short stable identifier used in errors and test parametrization.
    name: str = "abstract"
    #: Whether this backend implements the FTS surface (see module docstring).
    supports_search: bool = False
    #: Whether history is protected by the database rather than by convention.
    enforces_append_only_in_db: bool = False

    @abstractmethod
    def connect(self) -> Any:
        """Open a connection with schema applied and chain state reconciled."""

    @abstractmethod
    def db_tip(self, conn: Any) -> dict:
        """The highest event row, as ``{"id", "chain_hash"}``."""

    def json_field(self, column: str, key: str) -> str:
        """SQL for reading one text field out of a JSON ``column``.

        The two engines spell this differently (SQLite ``json_extract``,
        Postgres ``->>`` over a cast), and the difference is invisible until a
        query written on one backend runs inside the other's append
        transaction — which is exactly where the refusal-budget count runs, on
        the path an attacker controls the frequency of. ``key`` must be a
        static identifier from code, never caller input; the assertion is the
        contract.
        """
        assert key.isidentifier(), key
        raise NotImplementedError

    @abstractmethod
    def table_names(self, conn: Any) -> set[str]:
        """Tables present, for schema-presence checks that must not mutate.

        `ledger_sig._ensure` needs this on the append path: verification must
        never create the evidence it is checking, so it probes rather than
        applying schema. ``sqlite_master`` is not a portable way to ask.
        """

    @abstractmethod
    @contextmanager
    def append_scope(self, conn: Any) -> Iterator[AppendScope]:
        """The critical section for exactly one append."""

    @abstractmethod
    def verify_tip(self, conn: Any, root: Path | None = None) -> None:
        """Raise ``ChainStateError`` if the tip is not the attested one.

        This is the half of verification that is *not* recomputing row hashes.
        Recomputation alone cannot catch a truncation or a wholesale rewrite by
        an actor who also recomputes; comparing against an independently held
        tip can. What "independently held" means is exactly what differs between
        backends, and is argued in `postgres.py`.
        """

    def reconcile(self, conn: Any, root: Path | None = None) -> dict:
        """Complete any interrupted append. Returns the reconciled tip."""
        return self.db_tip(conn)
