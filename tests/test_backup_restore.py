import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from contextd import load_config
from contextd.backup import (
    BackupError,
    create_backup,
    restore_backup,
    validate_bundle,
)
from contextd.db import (
    InjectedCrash,
    append_event,
    append_event_checked,
    connect,
    store_blob,
    verify_chain,
)
from contextd.gate import assemble
from contextd.search import search


def _seed_archive() -> tuple[Path, sqlite3.Connection, str, bytes]:
    archive = Path(os.environ["CONTEXTD_HOME"])
    conn = connect()
    append_event(conn, "note", "note", content="durable narwhal decision")
    blob_bytes = b"blob payload that must survive restore\x00\xff"
    digest = store_blob(blob_bytes)
    append_event(
        conn,
        "fs",
        "file_write",
        uri="/archive/large.bin",
        content_hash=digest,
        meta={"blob": digest, "size": len(blob_bytes)},
    )
    (archive / "config.toml").write_text("[gate]\ndaily_token_budget = 200000\n")
    return archive, conn, digest, blob_bytes


def _bundle(tmp_path: Path) -> tuple[Path, str, bytes]:
    archive, conn, digest, blob_bytes = _seed_archive()
    result = create_backup(conn, archive, tmp_path / "backups")
    conn.close()
    return result["bundle"], digest, blob_bytes


def _rewrite_manifest(bundle: Path, mutate) -> None:
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    mutate(manifest)
    raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    manifest_path.write_bytes(raw)
    (bundle / "manifest.sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n")


def _refresh_entry(bundle: Path, relative: str) -> None:
    path = bundle / relative

    def mutate(manifest):
        entry = next(item for item in manifest["files"] if item["path"] == relative)
        entry["size"] = path.stat().st_size
        entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

    _rewrite_manifest(bundle, mutate)


def test_complete_bundle_restores_search_recall_chain_witness_blobs_and_append(
    tmp_path, monkeypatch
):
    bundle, digest, blob_bytes = _bundle(tmp_path)
    manifest = validate_bundle(bundle)["manifest"]
    paths = {entry["path"] for entry in manifest["files"]}
    assert {
        "contextd.db",
        "config.toml",
        "chain-witness.json",
        f"store/{digest[:2]}/{digest}",
    } <= paths

    destination = tmp_path / "restored"
    destination.mkdir()
    result = restore_backup(bundle, destination)
    assert result["events"] == 2
    assert result["blobs"] == 1
    assert (destination / "store" / digest[:2] / digest).read_bytes() == blob_bytes

    monkeypatch.setenv("CONTEXTD_HOME", str(destination))
    conn = connect()
    assert verify_chain(conn)["ok"]
    assert search(conn, "narwhal decision")[0]["id"] == 1
    recalled = assemble(
        conn, load_config(), "narwhal decision", purpose="restore verification"
    )
    assert "durable narwhal decision" in recalled["bundle"]
    appended = append_event(conn, "note", "note", content="post restore append")
    assert appended == recalled["egress_id"] + 1
    assert verify_chain(conn)["ok"]


def test_online_snapshot_contains_committed_wal_rows(tmp_path):
    archive, conn, _, _ = _seed_archive()
    writer = connect()
    append_event(writer, "note", "note", content="committed in the WAL")
    writer.close()

    result = create_backup(conn, archive, tmp_path / "backups")
    snapshot = sqlite3.connect(result["bundle"] / "contextd.db")
    assert (
        snapshot.execute(
            "SELECT COUNT(*) FROM events WHERE content='committed in the WAL'"
        ).fetchone()[0]
        == 1
    )
    snapshot.close()


@pytest.mark.parametrize(
    ("phase", "expected_events"),
    [("before_db_commit", 0), ("after_db_commit", 1)],
)
def test_backup_preserves_and_restores_recoverable_crash_state(
    tmp_path, monkeypatch, phase, expected_events
):
    archive = Path(os.environ["CONTEXTD_HOME"])
    conn = connect()

    def fault(current):
        if current == phase:
            raise InjectedCrash(current)

    with pytest.raises(InjectedCrash):
        append_event_checked(
            conn, "test", "note", content="interrupted append", fault=fault
        )
    # An abrupt process close rolls back the pre-commit case. Mirror that
    # SQLite effect while retaining this connection so create_backup receives
    # the recovery file before the normal connect-time recovery path consumes it.
    if conn.in_transaction:
        conn.rollback()
    recovery = archive / "chain-recovery.json"
    original_recovery = recovery.read_bytes()

    result = create_backup(conn, archive, tmp_path / "backups")
    conn.close()
    bundle = result["bundle"]
    assert recovery.read_bytes() == original_recovery
    assert (bundle / "chain-recovery.json").read_bytes() == original_recovery
    assert "chain-recovery.json" in {
        entry["path"] for entry in validate_bundle(bundle)["manifest"]["files"]
    }

    destination = tmp_path / "restored"
    restore_backup(bundle, destination)
    monkeypatch.setenv("CONTEXTD_HOME", str(destination))
    restored = connect()
    assert verify_chain(restored)["ok"]
    assert (
        restored.execute("SELECT COUNT(*) FROM events").fetchone()[0] == expected_events
    )
    assert not (destination / "chain-recovery.json").exists()
    assert (
        append_event(restored, "test", "note", content="after restore")
        == expected_events + 1
    )


def test_ctx_restore_cli_publishes_verified_bundle(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    destination = tmp_path / "cli-restored"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "contextd.cli",
            "restore",
            str(bundle),
            str(destination),
        ],
        capture_output=True,
        text=True,
        env=os.environ.copy(),
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "restored 2 events and 1 blobs" in result.stdout
    assert (destination / "contextd.db").is_file()


@pytest.mark.parametrize(
    "relative",
    [
        "manifest.json",
        "manifest.sha256",
        "contextd.db",
        "config.toml",
        "chain-witness.json",
    ],
)
def test_corrupt_manifest_or_payload_is_refused_without_publish(tmp_path, relative):
    bundle, _, _ = _bundle(tmp_path)
    path = bundle / relative
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 1
    path.write_bytes(data)
    destination = tmp_path / "not-published"

    with pytest.raises(BackupError):
        restore_backup(bundle, destination)

    assert not destination.exists()


def test_rehashed_nonobject_manifest_is_a_controlled_cli_refusal(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    raw = b"[]\n"
    (bundle / "manifest.json").write_bytes(raw)
    (bundle / "manifest.sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n")
    destination = tmp_path / "not-published"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "contextd.cli",
            "restore",
            str(bundle),
            str(destination),
        ],
        capture_output=True,
        text=True,
        env=os.environ.copy(),
        check=False,
    )

    assert result.returncode != 0
    assert "restore refused: manifest.json root must be an object" in result.stderr
    assert "Traceback" not in result.stderr
    assert not destination.exists()


def test_rehashed_nonobject_witness_is_refused_without_publish(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    witness = bundle / "chain-witness.json"
    witness.write_text('["version","id","chain_hash"]\n')
    _refresh_entry(bundle, "chain-witness.json")
    destination = tmp_path / "not-published"

    with pytest.raises(BackupError, match="chain witness is malformed"):
        restore_backup(bundle, destination)

    assert not destination.exists()


def test_one_byte_blob_corruption_is_refused_without_publish(tmp_path):
    bundle, digest, _ = _bundle(tmp_path)
    blob = bundle / "store" / digest[:2] / digest
    data = bytearray(blob.read_bytes())
    data[0] ^= 1
    blob.write_bytes(data)
    destination = tmp_path / "not-published"

    with pytest.raises(BackupError):
        restore_backup(bundle, destination)

    assert not destination.exists()


def test_semantically_corrupt_db_is_refused_even_with_updated_file_hash(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    conn = sqlite3.connect(bundle / "contextd.db")
    conn.execute("DROP TRIGGER events_no_update")
    conn.execute("UPDATE events SET content='rewritten' WHERE id=1")
    conn.commit()
    conn.close()
    _refresh_entry(bundle, "contextd.db")

    with pytest.raises(BackupError, match="event chain is broken"):
        restore_backup(bundle, tmp_path / "restored")


def test_semantically_corrupt_config_witness_recovery_and_blob_are_refused(tmp_path):
    bundle, digest, _ = _bundle(tmp_path)

    (bundle / "config.toml").write_text("[unterminated")
    _refresh_entry(bundle, "config.toml")
    with pytest.raises(BackupError, match="config.toml is invalid"):
        validate_bundle(bundle)

    bundle, digest, _ = _bundle(tmp_path / "witness-case")
    (bundle / "chain-witness.json").write_text("{}\n")
    _refresh_entry(bundle, "chain-witness.json")
    with pytest.raises(BackupError, match="chain witness"):
        validate_bundle(bundle)

    bundle, digest, _ = _bundle(tmp_path / "recovery-case")
    recovery = bundle / "chain-recovery.json"
    recovery.write_text('{"version":1,"previous":{},"target":{}}\n')

    def add_recovery(manifest):
        manifest["files"].append(
            {
                "path": "chain-recovery.json",
                "size": recovery.stat().st_size,
                "sha256": hashlib.sha256(recovery.read_bytes()).hexdigest(),
            }
        )
        manifest["files"].sort(key=lambda item: item["path"])

    _rewrite_manifest(bundle, add_recovery)
    with pytest.raises(BackupError, match="chain recovery"):
        validate_bundle(bundle)

    bundle, digest, _ = _bundle(tmp_path / "blob-case")
    blob = bundle / "store" / digest[:2] / digest
    blob.write_bytes(b"different bytes")
    _refresh_entry(bundle, f"store/{digest[:2]}/{digest}")
    with pytest.raises(BackupError, match="blob content digest mismatch"):
        validate_bundle(bundle)


@pytest.mark.parametrize("relative", ["contextd.db", "config.toml"])
def test_missing_payload_is_refused(tmp_path, relative):
    bundle, _, _ = _bundle(tmp_path)
    (bundle / relative).unlink()
    with pytest.raises(BackupError, match="missing files"):
        restore_backup(bundle, tmp_path / "restored")
    assert not (tmp_path / "restored").exists()


def test_manifest_cannot_legitimize_a_missing_witness(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    (bundle / "chain-witness.json").unlink()

    def omit_witness(manifest):
        manifest["files"] = [
            entry
            for entry in manifest["files"]
            if entry["path"] != "chain-witness.json"
        ]

    _rewrite_manifest(bundle, omit_witness)

    with pytest.raises(BackupError, match="chain witness"):
        restore_backup(bundle, tmp_path / "restored")


def test_unexpected_file_and_path_traversal_are_refused(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    (bundle / "surprise.txt").write_text("not in the inventory")
    with pytest.raises(BackupError, match="unexpected files"):
        validate_bundle(bundle)

    bundle, _, _ = _bundle(tmp_path / "traversal-case")

    def add_traversal(manifest):
        manifest["files"].append({"path": "../escape", "size": 0, "sha256": "0" * 64})

    _rewrite_manifest(bundle, add_traversal)
    with pytest.raises(BackupError, match="unsafe bundle path"):
        restore_backup(bundle, tmp_path / "escape-destination")
    assert not (tmp_path / "escape").exists()
    assert not (tmp_path / "escape-destination").exists()


def test_nonempty_destination_is_refused_and_left_unchanged(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    destination = tmp_path / "existing"
    destination.mkdir()
    sentinel = destination / "keep.txt"
    sentinel.write_text("untouched")

    with pytest.raises(BackupError, match="not empty"):
        restore_backup(bundle, destination)

    assert sentinel.read_text() == "untouched"
    assert list(destination.iterdir()) == [sentinel]


def test_destination_inside_bundle_is_refused_without_mutating_bundle(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    before = {
        path.relative_to(bundle).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in bundle.rglob("*")
        if path.is_file()
    }

    with pytest.raises(BackupError, match="cannot be inside"):
        restore_backup(bundle, bundle / "restored-inside-bundle")

    after = {
        path.relative_to(bundle).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in bundle.rglob("*")
        if path.is_file()
    }
    assert after == before
    validate_bundle(bundle)


def test_retention_prunes_only_complete_bundles_without_sleeps(tmp_path):
    archive, conn, _, _ = _seed_archive()
    backups = tmp_path / "backups"
    legacy = backups / "contextd-legacy.db"
    note = backups / "operator-note.txt"
    backups.mkdir()
    legacy.write_bytes(b"legacy")
    note.write_text("keep")
    start = datetime(2026, 8, 12, tzinfo=timezone.utc)
    for offset in range(3):
        create_backup(
            conn,
            archive,
            backups,
            keep=2,
            created_at=start + timedelta(seconds=offset),
        )

    assert len(list(backups.glob("*.ctxbackup"))) == 2
    assert legacy.read_bytes() == b"legacy"
    assert note.read_text() == "keep"


def test_retention_preserves_incomplete_bundle_directories(tmp_path):
    archive, conn, _, _ = _seed_archive()
    backups = tmp_path / "backups"
    backups.mkdir()
    partial = backups / "contextd-20200101-000000.ctxbackup"
    partial.mkdir()
    raw = b"{}\n"
    (partial / "manifest.json").write_bytes(raw)
    (partial / "manifest.sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n")

    result = create_backup(
        conn,
        archive,
        backups,
        keep=1,
        created_at=datetime(2026, 8, 12, tzinfo=timezone.utc),
    )

    assert partial.is_dir()
    assert result["bundle"].is_dir()
    assert result["pruned"] == []


def test_same_second_retention_keeps_newest_sequence_numbers(tmp_path):
    archive, conn, _, _ = _seed_archive()
    backups = tmp_path / "backups"
    when = datetime(2026, 8, 12, tzinfo=timezone.utc)
    created = []
    for index in range(3):
        if index:
            append_event(conn, "note", "note", content=f"later {index}")
        created.append(
            create_backup(conn, archive, backups, keep=2, created_at=when)["bundle"]
        )

    assert not created[0].exists()
    assert created[1].exists() and created[2].exists()


def test_negative_retention_is_refused_before_bundle_publish(tmp_path):
    archive, conn, _, _ = _seed_archive()
    backups = tmp_path / "backups"

    with pytest.raises(BackupError, match="cannot be negative"):
        create_backup(conn, archive, backups, keep=-1)

    assert not backups.exists()


def test_backup_refuses_database_and_state_from_different_archives(tmp_path):
    archive, conn, _, _ = _seed_archive()

    with pytest.raises(BackupError, match="does not belong"):
        create_backup(conn, archive / "different", tmp_path / "backups")

    assert not (tmp_path / "backups").exists()
