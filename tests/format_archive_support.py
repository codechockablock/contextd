"""Build a small archive that exercises every layer `docs/FORMAT.md` describes.

This is fixture construction, deliberately kept out of the test bodies: the
independent verifier in `scripts/verify_format_independent.mjs` is only
evidence about the *format* if the archive it reads actually contains one of
everything the format specifies. An archive of three unsigned notes would let
a verifier that silently skips signatures look exactly like one that checks
them.

So the archive built here carries, on purpose:

* a pre-cutover event, so the cutover tip's "authenticates nothing before it"
  claim has something to be true about,
* several signed events, each with a `service_signatures` row,
* signed chain tips, including the `cutover = 1` one,
* checkpoints at a short interval, hybrid (classical + ML-DSA) when this build
  can produce them, so the four-field/five-field payload asymmetry in
  section 5 is exercised in both directions,
* one operator-attested event, so section 4 and section 10 step 6 are live,
* a witness file naming the tip.

Nothing here is imported by the verifier. The verifier gets a directory.
"""

import json
import shutil
import sqlite3
from pathlib import Path

GOOD_SKILL = "# triage\n\nRead the ticket. Ask before escalating.\n"
UPDATED_SKILL = "# triage\n\nRead the ticket. Ask twice before escalating.\n"


def configure_security(home: Path, **security) -> None:
    """Write a ``[security]`` block into an isolated archive home."""
    home.mkdir(parents=True, exist_ok=True)
    lines = ["[security]"]
    for key, value in security.items():
        lines.append(f"{key} = {json.dumps(value)}")
    (home / "config.toml").write_text("\n".join(lines) + "\n")


def append_health_sweep(conn) -> int:
    """Append the `(health, sweep)` row a real archive accumulates on a timer.

    This is not an exotic event invented to trip a verifier. It is the shipped
    health sweep: `hooks/health_sweep.py:243` calls
    ``append_event(conn, "health", "sweep", meta=meta)``, the type is
    registered in ``schemas.HARNESS_SCHEMAS`` (`schemas.py:566`), and
    ``launchd/com.contextd.health.plist`` runs the hook on a schedule. Any
    archive that has been running as a daily driver has these rows.

    It is in the fixture because `docs/FORMAT.md` section 1 does not list
    ``health`` among the producing planes, and a finding about a real archive
    should be demonstrated against real bytes rather than read off schemas.py.
    """
    from contextd.db import append_event

    return append_event(
        conn, "health", "sweep",
        meta={"verdict": "ok", "checks": {"chain": "ok", "witness": "ok"},
              "degraded": [], "new_degradations": [], "grant_anomalies": 0},
    )


def build_archive(home: Path, *, hybrid: bool = True) -> dict:
    """Populate ``home`` with a fully-featured archive and return a summary.

    The caller must already have pointed ``CONTEXTD_HOME`` at ``home``; this
    imports contextd only to *write* the archive. The verification side never
    imports any of it.
    """
    from contextd import pinning
    from contextd.db import connect
    from contextd.ingest import ingest_note
    from contextd.ledger_sig import ALG_MLDSA_44, pq_available, sign_tip

    algs = [ALG_MLDSA_44] if (hybrid and pq_available()) else []
    configure_security(
        home, checkpoint_interval_events=2, checkpoint_algorithms=algs
    )

    conn = connect()
    ingest_note(conn, "a note appended before the signing cutover")
    # Crossing the cutover is what turns per-append signing on: everything
    # appended after this line carries an event signature and a tip signature.
    sign_tip(conn, cutover=True)
    ingest_note(conn, "the first signed note")
    ingest_note(conn, "a note with a non-ASCII body: café, démo, 日本語")

    art = pinning.artifact("skill", "skills/triage.md", GOOD_SKILL)
    pinning.observe(conn, [art])
    pinning.pinned_append(conn, artifacts=[art], session="fixture")

    moved = pinning.artifact("skill", "skills/triage.md", UPDATED_SKILL)
    pinning.observe(conn, [moved])
    # An operator-signed adoption: the one event here that carries a
    # `meta.attestation` block, which is what makes section 10 step 6 live.
    adopt = pinning.adopt(conn, moved, reason="deliberate skill update")

    ingest_note(conn, "a final note, after the adoption")
    health_event = append_health_sweep(conn)

    summary = {
        "health_event": health_event,
        "events": conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"],
        "signatures": conn.execute(
            "SELECT COUNT(*) AS n FROM service_signatures").fetchone()["n"],
        "tips": conn.execute(
            "SELECT COUNT(*) AS n FROM service_tips").fetchone()["n"],
        "checkpoints": conn.execute(
            "SELECT COUNT(*) AS n FROM service_checkpoints").fetchone()["n"],
        "checkpoint_algs": sorted(
            r["alg"] for r in conn.execute(
                "SELECT DISTINCT alg FROM service_checkpoints")),
        "adopt_event": adopt["event"],
        "hybrid": bool(algs),
    }
    # An adjudicator gets files, not a live connection. Fold the WAL back into
    # the database so the bytes on disk are the whole archive.
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.commit()
    conn.close()
    return summary


def operator_fixture(conn):
    """Enable the test-only signer for this process (see authorization_support)."""
    from tests.authorization_support import operator

    return operator(conn)


# --- mutation helpers -------------------------------------------------------
#
# Every mutation below is applied with the *stdlib* `sqlite3` module, never
# through contextd. A mutation test whose corruption ran through the same code
# the verifier is checking would be measuring agreement between two halves of
# one implementation, which is the thing this whole lane exists to stop doing.


def copy_archive(source: Path, destination: Path) -> Path:
    """Copy an archive directory wholesale, so the original stays pristine."""
    shutil.copytree(source, destination)
    return destination


def _raw(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    # The append-only triggers are exactly what an owner-level attacker drops
    # first (see tests/test_service_attestation.py::_rewrite_event). Dropping
    # them here models that attacker rather than pretending they stop one.
    conn.execute("DROP TRIGGER IF EXISTS events_no_update")
    conn.execute("DROP TRIGGER IF EXISTS events_no_delete")
    return conn


def mutate_event_content(db_path: Path, event_id: int, content: str) -> None:
    """Rewrite one row's content and leave the chain hashes alone."""
    conn = _raw(db_path)
    conn.execute("UPDATE events SET content = ? WHERE id = ?", (content, event_id))
    conn.commit()
    conn.close()


def mutate_event_and_repair_chain(db_path: Path, event_id: int, content: str) -> None:
    """The full same-UID attack: rewrite a row, then recompute every hash after
    it and rewrite the witness, so nothing that only recomputes the chain can
    still tell. This is the mutation the service signature exists to catch."""
    import hashlib

    conn = _raw(db_path)
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    conn.execute(
        "UPDATE events SET content = ?, content_hash = ? WHERE id = ?",
        (content, digest, event_id),
    )
    prev = ""
    for row in conn.execute(
        "SELECT id, ts, source, kind, uri, content, content_hash, meta "
        "FROM events ORDER BY id"
    ).fetchall():
        h = hashlib.sha256()
        for part in (
            prev, str(row["id"]), row["ts"], row["source"], row["kind"],
            row["uri"] or "", row["content"] or "", row["content_hash"] or "",
            row["meta"] or "",
        ):
            h.update(part.encode("utf-8"))
            h.update(b"\x1f")
        chain = h.hexdigest()
        conn.execute(
            "UPDATE events SET prev_hash = ?, chain_hash = ? WHERE id = ?",
            (prev, chain, row["id"]),
        )
        prev = chain
    conn.commit()
    tip = conn.execute(
        "SELECT id, chain_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    witness = db_path.parent / "chain-witness.json"
    if witness.exists():
        doc = json.loads(witness.read_text())
        doc["id"], doc["chain_hash"] = tip["id"], tip["chain_hash"]
        witness.write_text(json.dumps(doc))


def delete_last_event(db_path: Path) -> None:
    """Truncate the chain by one row, leaving the witness naming the old tip."""
    conn = _raw(db_path)
    conn.execute("DELETE FROM events WHERE id = (SELECT MAX(id) FROM events)")
    conn.commit()
    conn.close()


def drop_append_only_triggers(db_path: Path) -> None:
    conn = _raw(db_path)
    conn.commit()
    conn.close()


def flip_signature_byte(db_path: Path, table: str, where: str) -> None:
    """Corrupt one hex nibble of a stored signature."""
    conn = _raw(db_path)
    row = conn.execute(
        f"SELECT rowid AS rid, signature FROM {table} WHERE {where} LIMIT 1"
    ).fetchone()
    assert row is not None, f"no row in {table} matching {where}"
    sig = row["signature"]
    # Flip a byte in the middle of the DER body, past the header.
    index = len(sig) // 2
    swapped = "0" if sig[index] != "0" else "1"
    conn.execute(
        f"UPDATE {table} SET signature = ? WHERE rowid = ?",
        (sig[:index] + swapped + sig[index + 1:], row["rid"]),
    )
    conn.commit()
    conn.close()


def relabel_checkpoint_alg(
    db_path: Path,
    new_alg: str = "ml-dsa-65",
    current_alg: str = "ecdsa-p256-sha256",
) -> None:
    """Re-point a checkpoint row's algorithm tag at a different scheme.

    Section 5: verification dispatches on the recorded name, and "a signature
    naming one scheme while its key is registered under another is refused,
    never verified under whichever scheme happened to load". The row's
    signature bytes stay a perfectly valid ECDSA P-256 signature; only the
    label moves. A verifier that tried schemes until one worked would pass
    this mutation, which is exactly why it is here.

    ``new_alg`` defaults to a scheme the archive does not already carry for
    that tip: ``service_checkpoints`` has primary key ``(tip_id, alg)``
    (section 5), so relabelling onto an occupied scheme is refused by the
    database itself.
    """
    conn = _raw(db_path)
    row = conn.execute(
        "SELECT rowid AS rid FROM service_checkpoints WHERE alg = ? "
        "ORDER BY tip_id LIMIT 1", (current_alg,)
    ).fetchone()
    assert row is not None, f"no {current_alg} checkpoint to relabel"
    conn.execute(
        "UPDATE service_checkpoints SET alg = ? WHERE rowid = ?",
        (new_alg, row["rid"]))
    conn.commit()
    conn.close()


def mutate_attestation_argument(db_path: Path, event_id: int) -> None:
    """Change what a signed operator action says it authorized.

    The chain is repaired afterwards, so this is the attack that a chain-only
    parser cannot see: the ledger is internally consistent and the signature is
    over different bytes than the row now claims.
    """
    conn = _raw(db_path)
    row = conn.execute(
        "SELECT meta FROM events WHERE id = ?", (event_id,)).fetchone()
    meta = json.loads(row["meta"])
    meta["attestation"]["action"]["arguments"]["artifact"] = "skills/attacker.md"
    conn.execute(
        "UPDATE events SET meta = ? WHERE id = ?",
        (json.dumps(meta), event_id))
    conn.commit()
    conn.close()
    _repair_chain(db_path)


def _repair_chain(db_path: Path) -> None:
    import hashlib

    conn = _raw(db_path)
    prev = ""
    for row in conn.execute(
        "SELECT id, ts, source, kind, uri, content, content_hash, meta "
        "FROM events ORDER BY id"
    ).fetchall():
        h = hashlib.sha256()
        for part in (
            prev, str(row["id"]), row["ts"], row["source"], row["kind"],
            row["uri"] or "", row["content"] or "", row["content_hash"] or "",
            row["meta"] or "",
        ):
            h.update(part.encode("utf-8"))
            h.update(b"\x1f")
        chain = h.hexdigest()
        conn.execute(
            "UPDATE events SET prev_hash = ?, chain_hash = ? WHERE id = ?",
            (prev, chain, row["id"]))
        prev = chain
    conn.commit()
    tip = conn.execute(
        "SELECT id, chain_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    witness = db_path.parent / "chain-witness.json"
    if witness.exists():
        doc = json.loads(witness.read_text())
        doc["id"], doc["chain_hash"] = tip["id"], tip["chain_hash"]
        witness.write_text(json.dumps(doc))
