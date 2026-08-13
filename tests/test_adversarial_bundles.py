"""Adversarial restore corpus: more ways a bundle can be hostile or damaged.

One row per attack. Every case must be refused loudly (nonzero through the
CLI), with a reason distinct enough to identify the case from the refusal
alone, without a publish rename and without touching the destination. These
rows extend tests/test_backup_restore.py's matrix; none of them may ever be
made to pass by weakening an existing refusal."""

import hashlib
import json
import os
import sqlite3
from argparse import Namespace
from pathlib import Path

import pytest

from contextd.backup import BackupError, create_backup, restore_backup
from contextd.cli import cmd_restore
from contextd.db import append_event, connect, store_blob


def _bundle(tmp_path: Path) -> Path:
    archive = Path(os.environ["CONTEXTD_HOME"])
    conn = connect()
    append_event(conn, "note", "note", content="hostile corpus seed")
    digest = store_blob(b"corpus blob payload\x00\xff" * 64)
    append_event(conn, "fs", "file_write", uri="/archive/corpus.bin",
                 content_hash=digest, meta={"blob": digest})
    result = create_backup(conn, archive, tmp_path / "backups")
    conn.close()
    return result["bundle"]


def _rewrite_manifest(bundle: Path, mutate) -> None:
    manifest = json.loads((bundle / "manifest.json").read_text())
    mutate(manifest)
    raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":"))
           + "\n").encode()
    (bundle / "manifest.json").write_bytes(raw)
    (bundle / "manifest.sha256").write_text(
        hashlib.sha256(raw).hexdigest() + "\n")


def _refresh_entry(bundle: Path, relative: str) -> None:
    path = bundle / relative

    def mutate(manifest):
        entry = next(e for e in manifest["files"] if e["path"] == relative)
        entry["size"] = path.stat().st_size
        entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

    _rewrite_manifest(bundle, mutate)


def _blob_relative(bundle: Path) -> str:
    return next(p for p in (bundle / "store").rglob("*/*")
                ).relative_to(bundle).as_posix()


def truncated_blob(bundle: Path) -> None:
    """Cut a blob mid-file and launder the manifest to match: the payload
    inventory passes, the content-addressing check must still refuse."""
    relative = _blob_relative(bundle)
    blob = bundle / relative
    blob.write_bytes(blob.read_bytes()[: blob.stat().st_size // 2])
    _refresh_entry(bundle, relative)


def truncated_db(bundle: Path) -> None:
    db = bundle / "contextd.db"
    db.write_bytes(db.read_bytes()[: db.stat().st_size // 2])
    _refresh_entry(bundle, "contextd.db")


def zero_byte_db(bundle: Path) -> None:
    (bundle / "contextd.db").write_bytes(b"")
    _refresh_entry(bundle, "contextd.db")


def version_skew_past(bundle: Path) -> None:
    _rewrite_manifest(bundle, lambda m: m.update(version=0))


def version_from_future(bundle: Path) -> None:
    """A bundle written by a future contextd must be refused as too new,
    never half-read with today's parser."""
    _rewrite_manifest(bundle, lambda m: m.update(version=99))


def duplicate_manifest_entry(bundle: Path) -> None:
    _rewrite_manifest(
        bundle, lambda m: m["files"].append(dict(m["files"][0])))


def manifest_lists_missing_file(bundle: Path) -> None:
    _rewrite_manifest(bundle, lambda m: m["files"].append(
        {"path": "store/aa/" + "a" * 64, "size": 1, "sha256": "0" * 64}))


def extra_unlisted_file(bundle: Path) -> None:
    (bundle / "smuggled.bin").write_bytes(b"stowaway")


def symlinked_blob_dir(bundle: Path) -> None:
    relative = _blob_relative(bundle)
    shard = (bundle / relative).parent
    outside = bundle.parent / "outside-store"
    outside.mkdir()
    (outside / Path(relative).name).write_bytes((bundle / relative).read_bytes())
    (bundle / relative).unlink()
    shard.rmdir()
    shard.symlink_to(outside)


# case -> (mutation, the identifying fragment of the refusal reason)
CASES = {
    "truncated_blob": (truncated_blob, "blob content digest mismatch"),
    "truncated_db": (truncated_db, "invalid SQLite snapshot"),
    "zero_byte_db": (zero_byte_db, "FTS index check failed"),
    "version_skew_past": (version_skew_past, "version=0"),
    "version_from_future": (version_from_future, "version=99"),
    "duplicate_manifest_entry": (duplicate_manifest_entry,
                                 "duplicate manifest path"),
    "manifest_lists_missing_file": (manifest_lists_missing_file,
                                    "bundle is missing files: store/aa/"),
    "extra_unlisted_file": (extra_unlisted_file,
                            "unexpected files: smuggled.bin"),
    "symlinked_blob_dir": (symlinked_blob_dir, "bundle contains a symlink"),
}


@pytest.mark.parametrize("name", CASES)
def test_hostile_bundle_is_refused_loudly_without_publish(tmp_path, name):
    corrupt, expected = CASES[name]
    bundle = _bundle(tmp_path)
    corrupt(bundle)
    destination = tmp_path / "never-published"

    with pytest.raises(BackupError) as refusal:
        restore_backup(bundle, destination)
    assert expected in str(refusal.value), refusal.value

    # the CLI maps the same refusal to a nonzero, traceback-free exit
    with pytest.raises(SystemExit) as bail:
        cmd_restore(Namespace(bundle=str(bundle), dest=str(destination)))
    assert bail.value.code, "refusal must be nonzero"
    assert expected in str(bail.value.code)

    assert not destination.exists(), "destination must be left untouched"
    assert not list(tmp_path.glob(".never-published.restore-*")), \
        "staging directory leaked"


def test_refusal_reasons_identify_each_case_distinctly(tmp_path):
    reasons = {}
    for name, (corrupt, _expected) in CASES.items():
        bundle = _bundle(tmp_path / name)
        corrupt(bundle)
        with pytest.raises(BackupError) as refusal:
            restore_backup(bundle, tmp_path / name / "never")
        reasons[name] = str(refusal.value)
    assert len(set(reasons.values())) == len(reasons), reasons


def test_zero_byte_db_really_reaches_the_semantic_check(tmp_path):
    """Belt and braces for the strangest case: a zero-byte file is a valid
    *empty* SQLite database, so the refusal must come from the archive's
    schema being absent, not from a hash mismatch a mutator forgot to
    launder."""
    bundle = _bundle(tmp_path)
    zero_byte_db(bundle)
    conn = sqlite3.connect(f"file:{bundle / 'contextd.db'}?mode=ro&immutable=1",
                           uri=True)
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    conn.close()
    with pytest.raises(BackupError, match="FTS index check failed"):
        restore_backup(bundle, tmp_path / "never")
