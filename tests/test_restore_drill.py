"""Restore fire-drill: PASS on a real-shaped bundle, loud FAIL receipts that
name the broken stage, status warnings derived from the ledger, temp cleanup
on every path, and drill receipts that can never reach FTS or a recall. A
monitoring system whose alarm has never fired is decoration; these tests fire
it on purpose."""

import argparse
import json
import os
import sqlite3
from pathlib import Path

import pytest

import hooks.restore_drill as drill
from contextd import load_config
from contextd.backup import create_backup
from contextd.cli import cmd_status
from contextd.db import append_event, connect, store_blob, verify_chain
from contextd.gate import assemble
from contextd.loops import add_loop, make_scope
from contextd.search import search

NOW = "2026-08-13T12:00:00+00:00"
OLD = "2026-08-01T12:00:00+00:00"  # 288h before NOW, past the 192h default


def _seed_and_bundle(tmp_path) -> tuple[Path, Path]:
    """A real-shaped archive: notes, a blob, a loop, an egress with an
    audit trail — enough that every battery stage has something to chew."""
    archive = Path(os.environ["CONTEXTD_HOME"])
    conn = connect()
    append_event(conn, "note", "note", content="durable narwhal decision",
                 meta={"actor": "human"})
    digest = store_blob(b"drill blob payload\x00\xff")
    append_event(conn, "fs", "file_write", uri="/archive/asset.bin",
                 content_hash=digest, meta={"blob": digest, "size": 20})
    add_loop(conn, "re-run the tide tables", make_scope("/synthetic/drill"))
    assemble(conn, load_config(), "narwhal decision", purpose="drill seed")
    (archive / "config.toml").write_text("[gate]\ndaily_token_budget = 200000\n")
    backups = tmp_path / "backups"
    create_backup(conn, archive, backups)
    conn.close()
    return archive, backups


def _drill(tmp_path, backups) -> dict:
    temp = tmp_path / "drill-temp"
    temp.mkdir(exist_ok=True)
    meta = drill.run_drill(backup_dir=backups, temp_dir=temp)
    assert list(temp.iterdir()) == [], "temp destination leaked"
    return meta


def _drill_rows(conn):
    return conn.execute(
        "SELECT * FROM events WHERE kind='restore_drill' ORDER BY id"
    ).fetchall()


def _status_lines(capsys):
    cmd_status(argparse.Namespace())
    return capsys.readouterr().out.splitlines()


def _newest_blob(backups: Path) -> Path:
    bundle = drill.newest_bundle(backups)
    return next((bundle / "store").rglob("*/*"))


def test_pass_receipt_carries_verdict_timings_and_peak_temp(tmp_path):
    _, backups = _seed_and_bundle(tmp_path)
    meta = _drill(tmp_path, backups)

    assert meta["verdict"] == "PASS"
    assert set(meta["stages"]) == set(drill.STAGES)
    assert all(t >= 0 for t in meta["stages"].values())
    assert meta["bundle"].endswith(".ctxbackup")
    assert len(meta["manifest_sha256"]) == 64
    # the restored copy is the bundle payload without the two manifest files
    assert 0 < meta["peak_temp_bytes"] <= meta["bundle_bytes"]
    assert meta["peak_temp_bytes"] > meta["bundle_bytes"] * 0.9
    assert meta["probes"] > len(drill.BASE_PROBES)

    conn = connect()
    rows = _drill_rows(conn)
    assert len(rows) == 1 and rows[0]["id"] == meta["event_id"]
    assert rows[0]["source"] == "eval"
    stored = json.loads(rows[0]["meta"])
    assert stored["verdict"] == "PASS" and stored["bundle"] == meta["bundle"]
    assert verify_chain(conn)["ok"]


def test_flipped_blob_byte_fails_loudly_at_restore_naming_the_blob(tmp_path):
    _, backups = _seed_and_bundle(tmp_path)
    blob = _newest_blob(backups)
    data = bytearray(blob.read_bytes())
    data[0] ^= 1
    blob.write_bytes(data)

    meta = _drill(tmp_path, backups)
    assert meta["verdict"] == "FAIL"
    assert meta["failed_stage"] == "restore"
    assert "store/" in meta["reason"] and "mismatch" in meta["reason"]


def test_truncated_db_fails_with_a_reason_distinct_from_the_blob_case(tmp_path):
    _, backups = _seed_and_bundle(tmp_path)
    bundle = drill.newest_bundle(backups)
    db = bundle / "contextd.db"
    db.write_bytes(db.read_bytes()[: db.stat().st_size // 2])

    meta = _drill(tmp_path, backups)
    assert meta["verdict"] == "FAIL"
    assert meta["failed_stage"] == "restore"
    assert "contextd.db" in meta["reason"] and "store/" not in meta["reason"]


def test_missing_bundle_dir_and_empty_dir_fail_at_locate(tmp_path):
    connect().close()  # a live archive must exist to receive the receipt
    meta = _drill(tmp_path, tmp_path / "nowhere")
    assert meta["verdict"] == "FAIL" and meta["failed_stage"] == "locate"
    (tmp_path / "empty").mkdir()
    meta = _drill(tmp_path, tmp_path / "empty")
    assert meta["failed_stage"] == "locate"
    assert "no .ctxbackup bundle" in meta["reason"]


def test_preflight_refuses_with_required_vs_available_numbers(
        tmp_path, monkeypatch):
    _, backups = _seed_and_bundle(tmp_path)
    real_usage = drill.shutil.disk_usage

    def cramped(path):
        real = real_usage(path)
        return type(real)(real.total, real.used, 1024)

    monkeypatch.setattr(drill.shutil, "disk_usage", cramped)
    meta = _drill(tmp_path, backups)
    assert meta["verdict"] == "FAIL" and meta["failed_stage"] == "preflight"
    assert f"need {int(meta['bundle_bytes'] * drill.DRILL_TEMP_MULTIPLE)}" in \
        meta["reason"]
    assert "only 1024 available" in meta["reason"]


def test_post_restore_chain_tamper_fails_the_chain_witness_stage(
        tmp_path, monkeypatch):
    """The battery's own alarm: corruption that appears after restore's
    verification is still caught, and named, by the battery."""
    _, backups = _seed_and_bundle(tmp_path)
    real_restore = drill.restore_backup

    def sabotage(bundle, destination):
        result = real_restore(bundle, destination)
        conn = sqlite3.connect(destination / "contextd.db")
        conn.execute("DROP TRIGGER events_no_update")
        conn.execute("UPDATE events SET content='rewritten' WHERE id=1")
        conn.commit()
        conn.close()
        return result

    monkeypatch.setattr(drill, "restore_backup", sabotage)
    meta = _drill(tmp_path, backups)
    assert meta["verdict"] == "FAIL"
    assert meta["failed_stage"] == "chain_witness"
    assert "chain is broken" in meta["reason"]


def test_fts_shadow_divergence_fails_the_probe_stage(tmp_path, monkeypatch):
    """FTS is the one state that can diverge without touching the chained
    rows; the probe stage exists exactly for it."""
    _, backups = _seed_and_bundle(tmp_path)
    real_restore = drill.restore_backup

    def sabotage(bundle, destination):
        result = real_restore(bundle, destination)
        conn = sqlite3.connect(destination / "contextd.db")
        conn.execute(
            "INSERT INTO events_fts(events_fts, rowid, content) "
            "VALUES ('delete', 1, 'durable narwhal decision')")
        conn.commit()
        conn.close()
        return result

    monkeypatch.setattr(drill, "restore_backup", sabotage)
    meta = _drill(tmp_path, backups)
    assert meta["verdict"] == "FAIL"
    assert meta["failed_stage"] == "fts_probe"
    assert "answers differently" in meta["reason"]


def test_derived_probes_stay_memory_bounded_and_deduplicated():
    """Regression for a cliff the scale trial found: probe derivation once
    fetched every content row (2.9 GB RSS at the 4 GiB tier) and produced
    eight copies of the same whole-corpus probe. It must sample by id in
    O(1) memory and dedupe."""
    import tracemalloc

    conn = connect()
    conn.executemany(
        "INSERT INTO events (id, ts, source, kind, content) "
        "VALUES (?, ?, 'note', 'note', ?)",
        [(i, f"2026-01-01T00:00:{i % 60:02d}+00:00",
          f"shared prefix words event{i:05d} " + "filler " * 40)
         for i in range(1, 5001)])
    conn.commit()

    tracemalloc.start()
    probes = drill._derived_probes(conn)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert probes and len(probes) <= 8
    assert len(set(probes)) == len(probes), "probes must be deduplicated"
    assert probes == drill._derived_probes(conn), "must be deterministic"
    # the ledger above is ~1.5 MB of content; fetching it all would show up
    assert peak < 256 * 1024, f"probe derivation held {peak} bytes"


def test_status_never_run_is_quiet(capsys):
    connect().close()
    lines = _status_lines(capsys)
    assert "restore drill: never run" in lines
    assert not any("WARNING" in ln and "drill" in ln for ln in lines)


def test_status_pass_fail_stale_cycle(tmp_path, capsys, monkeypatch):
    _, backups = _seed_and_bundle(tmp_path)
    monkeypatch.setattr("contextd.liveness.now_iso", lambda: NOW)

    _drill(tmp_path, backups)
    lines = _status_lines(capsys)
    assert any(ln.startswith("restore drill: PASS") for ln in lines)
    assert not any("restore drill" in ln for ln in lines if "WARNING" in ln)

    blob = _newest_blob(backups)
    blob.write_bytes(b"corrupted")
    _drill(tmp_path, backups)
    lines = _status_lines(capsys)
    warning = next(ln for ln in lines
                   if ln.startswith("WARNING: restore drill FAILED"))
    assert "at stage restore" in warning and "backups may not restore" in warning

    # a clean re-backup and a PASS drill clear the alarm (last verdict wins)
    conn = connect()
    create_backup(conn, Path(os.environ["CONTEXTD_HOME"]), backups)
    conn.close()
    assert _drill(tmp_path, backups)["verdict"] == "PASS"
    lines = _status_lines(capsys)
    assert any(ln.startswith("restore drill: PASS") for ln in lines)
    assert not any("restore drill" in ln for ln in lines if "WARNING" in ln)


def test_status_warns_when_the_drill_itself_goes_stale(capsys, monkeypatch):
    conn = connect()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("contextd.db.now_iso", lambda: OLD)
        append_event(conn, "eval", "restore_drill",
                     meta={"verdict": "PASS", "stages": {}})
    conn.close()
    monkeypatch.setattr("contextd.liveness.now_iso", lambda: NOW)
    lines = _status_lines(capsys)
    assert "restore drill: PASS 12.0d ago" in lines
    warning = next(ln for ln in lines
                   if ln.startswith("WARNING: restore drill last ran"))
    assert "(threshold 192h)" in warning and "stalled" in warning


def test_drill_receipts_are_content_null_and_unreachable_by_fts_or_recall(
        tmp_path):
    """Pin the honesty property: the drill writes bookkeeping, never memory.
    Its receipts carry loaded words ('ctxbackup', 'manifest', paths) that
    must be invisible to search and recall forever."""
    _, backups = _seed_and_bundle(tmp_path)
    _drill(tmp_path, backups)
    blob = _newest_blob(backups)
    blob.write_bytes(b"corrupted")
    _drill(tmp_path, backups)  # a FAIL receipt carries reason text too

    conn = connect()
    rows = _drill_rows(conn)
    assert len(rows) == 2
    assert all(r["content"] is None for r in rows)
    # external-content FTS proxies rowid lookups to the events table, so
    # check the index's own docsize shadow: no indexed doc for the receipts
    assert all(
        conn.execute("SELECT COUNT(*) FROM events_fts_docsize WHERE id = ?",
                     (r["id"],)).fetchone()[0] == 0 for r in rows)
    for term in ("ctxbackup", "manifest mismatch", "restore drill"):
        hits = search(conn, term, limit=50)
        assert not any(h["id"] in {r["id"] for r in rows} for h in hits), term
    recalled = assemble(conn, load_config(), "ctxbackup manifest restore",
                        purpose="leak probe")
    assert all(i not in {r["id"] for r in rows} for i in recalled["items"])
    assert "ctxbackup" not in recalled["bundle"]
