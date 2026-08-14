#!/usr/bin/env python
"""Restore fire-drill: prove the newest backup actually restores, weekly.

A backup that has never been restored is a hope, not a backup. This hook
takes the newest `.ctxbackup` bundle, restores it into a throwaway temp
destination, and runs a verification battery against the restored copy:

- chain + witness (the `ctx verify` equivalent, on the restored files);
- event count and chain tip against the manifest's recorded snapshot;
- every manifest blob re-hashed and matched;
- FTS probe equivalence: a fixed probe query set answered identically by
  the bundle's snapshot DB and the restored DB;
- behavioral equivalence: read-only search / timeline / loop reduction /
  liveness / audit outputs, compared byte-wise between the two.

The verdict is appended to the LIVE archive as a content-NULL eval event
(kind `restore_drill`), so it can never enter FTS or a later recall; `ctx
status` derives its "restore drill:" line and staleness warning from that
receipt. Harness-side on purpose (hooks/, scheduled by launchd) — but unlike
its neighbors this hook calls no models and opens no sockets: it is pure
kernel plumbing on a timer. The temp destination is deleted on every path,
including failure. The live archive is only ever appended to, never restored
over.

The preflight refuses to start without temp headroom. The scale trial
(experiments/restore_scale) measured restore's peak temp usage at exactly
1.00x the bundle size across 1-8 GiB tiers and both shapes (the stage directory is
renamed into place, never double-copied); DRILL_TEMP_MULTIPLE pins that
measurement with margin for WAL/scratch surprises.
"""

import argparse
import json
import re
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contextd import DEFAULTS, home, load_config  # noqa: E402
from contextd import backup as backup_module  # noqa: E402
from contextd.backup import BackupError, restore_backup  # noqa: E402
from contextd.db import append_event, connect  # noqa: E402
from contextd.liveness import capture_liveness  # noqa: E402
from contextd.loops import reduce_loops  # noqa: E402
from contextd.search import search, timeline  # noqa: E402

# Measured in experiments/restore_scale (results.json, 2026-08-13): peak
# temp bytes during restore+battery / bundle bytes was exactly 1.00 in all
# six tier x shape cells (1-8 GiB) — the stage directory is renamed into
# place, never double-copied. Pinned at the measurement + 50% margin:
DRILL_TEMP_MULTIPLE = 1.5

# Battery order is the diagnosis: a FAIL names the first stage that broke.
STAGES = ("locate", "preflight", "restore", "chain_witness",
          "snapshot_state", "blobs", "fts_probe", "behavioral")

# Fixed base probes plus content-derived ones; the set only needs to be the
# same for both databases, and derived probes keep it non-vacuous on any
# archive. FIXED_NOW makes the liveness comparison deterministic.
BASE_PROBES = ("decision", "backup restore", "report", "note", "the")
FIXED_NOW = "2026-01-01T00:00:00+00:00"


class DrillFailure(RuntimeError):
    """A battery stage found the restored copy wanting."""


def _tree_bytes(root: Path) -> int:
    total = 0
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            total += path.stat().st_size
    return total


class _PeakSampler(threading.Thread):
    """Samples the temp tree size; bundle payloads are few large files, so a
    walk every 0.2s is cheap and the peak is a measurement, not an estimate."""

    def __init__(self, root: Path):
        super().__init__(daemon=True)
        self.root, self.peak, self._stop_event = root, 0, threading.Event()

    def run(self):
        while not self._stop_event.is_set():
            try:
                self.peak = max(self.peak, _tree_bytes(self.root))
            except OSError:
                pass
            self._stop_event.wait(0.2)

    def stop(self) -> int:
        self._stop_event.set()
        self.join()
        try:
            self.peak = max(self.peak, _tree_bytes(self.root))
        except OSError:
            pass
        return self.peak


def newest_bundle(backup_dir: Path) -> Path:
    """Newest by the bundle's own name stamp; full validation is restore's
    job, so a partial directory here surfaces as a loud restore FAIL rather
    than being silently skipped for an older bundle that would pass."""
    candidates = []
    for path in backup_dir.iterdir():
        match = backup_module._BUNDLE_NAME_RE.fullmatch(path.name)
        if match and path.is_dir() and not path.is_symlink():
            candidates.append(((match["stamp"], int(match["sequence"] or 0)),
                               path))
    if not candidates:
        raise DrillFailure(f"no .ctxbackup bundle found in {backup_dir}")
    return max(candidates)[1]


def _ro(database: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{database}?mode=ro&immutable=1", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _jrows(rows) -> list:
    return [{key: row[key] for key in row.keys()} for row in rows]


def _derived_probes(conn) -> list[str]:
    """Up to eight deduplicated probes from evenly spaced events, in O(1)
    memory. The scale trial caught the first draft of this function holding
    2.9 GB of RSS at the 4 GiB tier (it fetched every content row) and
    deriving eight identical probes that each made search() snippet the
    whole corpus — sample by id instead, and vary the word offset per row
    so probes discriminate."""
    bounds = conn.execute(
        "SELECT MIN(id) AS lo, MAX(id) AS hi FROM events "
        "WHERE content IS NOT NULL AND kind != 'egress'").fetchone()
    if bounds["lo"] is None:
        return []
    probes = []
    for step in range(8):
        target = bounds["lo"] + (bounds["hi"] - bounds["lo"]) * step // 8
        row = conn.execute(
            "SELECT id, content FROM events WHERE content IS NOT NULL "
            "AND kind != 'egress' AND id >= ? ORDER BY id LIMIT 1",
            (target,)).fetchone()
        words = re.findall(r"[A-Za-z0-9]{4,}", row["content"])
        if not words:
            continue
        offset = row["id"] % max(1, len(words) - 1)
        probe = " ".join(words[offset:offset + 2])
        if probe and probe not in probes:
            probes.append(probe)
    return probes


def _battery_outputs(conn, probes: list[str]) -> dict:
    """Every read surface an operator would trust after a real restore."""
    out = {"search": {q: _jrows(search(conn, q, limit=20)) for q in probes},
           "timeline": _jrows(timeline(conn, limit=200)),
           "loops": reduce_loops(conn),
           "liveness": capture_liveness(
               conn, json.loads(json.dumps(DEFAULTS)), now=FIXED_NOW)}
    audit = []
    for row in timeline(conn, kind="egress", limit=50):
        outcome = conn.execute(
            "SELECT meta FROM events WHERE kind='egress_outcome' "
            "AND json_extract(meta,'$.egress_id')=? ORDER BY id DESC LIMIT 1",
            (row["id"],)).fetchone()
        audit.append({"id": row["id"], "ts": row["ts"], "meta": row["meta"],
                      "dispatch": (json.loads(outcome["meta"])["status"]
                                   if outcome else "attempted")})
    out["audit"] = audit
    return out


def _compare(label: str, snapshot_value, restored_value) -> None:
    if (json.dumps(snapshot_value, sort_keys=True)
            != json.dumps(restored_value, sort_keys=True)):
        raise DrillFailure(
            f"{label}: restored copy answers differently from the snapshot")


def run_drill(backup_dir: Path | None = None,
              temp_dir: Path | None = None) -> dict:
    """Run the full drill once; append the receipt to the live archive.

    Returns the receipt meta. Never raises for a failed battery — a FAIL is
    a recorded outcome, not a crash; only being unable to record the receipt
    itself propagates.
    """
    cfg = load_config()
    if backup_dir is None:
        configured = cfg.get("backup", {}).get("dir", "")
        backup_dir = (Path(configured).expanduser() if configured
                      else home() / "backups")
    started = time.monotonic()
    stages: dict[str, float] = {}
    meta: dict = {"verdict": "FAIL", "stages": stages, "peak_temp_bytes": 0}
    temp_root: Path | None = None
    sampler: _PeakSampler | None = None
    stage = "locate"
    try:
        mark = time.monotonic()
        bundle = newest_bundle(Path(backup_dir).expanduser())
        manifest, _entries = backup_module._manifest(bundle)
        meta["bundle"] = str(bundle)
        meta["manifest_sha256"] = (
            (bundle / backup_module.MANIFEST_HASH_NAME).read_text().strip())
        bundle_bytes = _tree_bytes(bundle)
        meta["bundle_bytes"] = bundle_bytes
        stages[stage] = round(time.monotonic() - mark, 3)

        stage, mark = "preflight", time.monotonic()
        temp_root = Path(tempfile.mkdtemp(
            prefix="contextd-restore-drill-",
            dir=str(temp_dir) if temp_dir else None))
        required = int(bundle_bytes * DRILL_TEMP_MULTIPLE)
        free = shutil.disk_usage(temp_root).free
        if free < required:
            raise DrillFailure(
                f"not enough temp space for a safe restore: need {required} "
                f"bytes ({DRILL_TEMP_MULTIPLE}x the {bundle_bytes}-byte "
                f"bundle), only {free} available under {temp_root}")
        stages[stage] = round(time.monotonic() - mark, 3)
        sampler = _PeakSampler(temp_root)
        sampler.start()

        stage, mark = "restore", time.monotonic()
        restored = temp_root / "restored"
        restore_backup(bundle, restored)
        stages[stage] = round(time.monotonic() - mark, 3)

        stage, mark = "chain_witness", time.monotonic()
        snapshot = backup_module._validate_database(restored / "contextd.db")
        backup_module._validate_chain_state(restored, snapshot)
        stages[stage] = round(time.monotonic() - mark, 3)

        stage, mark = "snapshot_state", time.monotonic()
        if snapshot != manifest["snapshot"]:
            raise DrillFailure(
                f"restored event count/tip {snapshot} does not match the "
                f"manifest's recorded snapshot {manifest['snapshot']}")
        stages[stage] = round(time.monotonic() - mark, 3)

        stage, mark = "blobs", time.monotonic()
        for digest in manifest["blobs"]:
            path = restored / "store" / digest[:2] / digest
            if (not path.is_file() or path.is_symlink()
                    or backup_module._sha256(path) != digest):
                raise DrillFailure(f"restored blob missing or corrupt: {digest}")
        stages[stage] = round(time.monotonic() - mark, 3)

        stage, mark = "fts_probe", time.monotonic()
        snap_conn = _ro(bundle / "contextd.db")
        rest_conn = _ro(restored / "contextd.db")
        try:
            probes = list(BASE_PROBES) + _derived_probes(snap_conn)
            meta["probes"] = len(probes)
            for query in probes:
                _compare(f"fts probe {query!r}",
                         _jrows(search(snap_conn, query, limit=20)),
                         _jrows(search(rest_conn, query, limit=20)))
            stages[stage] = round(time.monotonic() - mark, 3)

            stage, mark = "behavioral", time.monotonic()
            _compare("behavioral battery",
                     _battery_outputs(snap_conn, probes),
                     _battery_outputs(rest_conn, probes))
            stages[stage] = round(time.monotonic() - mark, 3)
        finally:
            snap_conn.close()
            rest_conn.close()

        meta["verdict"] = "PASS"
    except (DrillFailure, BackupError, OSError, sqlite3.Error) as exc:
        stages[stage] = round(time.monotonic() - mark, 3)
        meta["failed_stage"] = stage
        meta["reason"] = str(exc)[:500]
    finally:
        if sampler is not None:
            meta["peak_temp_bytes"] = sampler.stop()
        if temp_root is not None:
            shutil.rmtree(temp_root, ignore_errors=True)
    meta["total_seconds"] = round(time.monotonic() - started, 3)

    conn = connect()
    try:
        meta["event_id"] = append_event(conn, "eval", "restore_drill",
                                        meta={k: v for k, v in meta.items()})
    finally:
        conn.close()
    return meta


def main() -> int:
    parser = argparse.ArgumentParser(
        description="restore the newest backup into a temp destination and "
                    "verify it end to end; log PASS/FAIL to the ledger")
    parser.add_argument("--once", action="store_true",
                        help="run one drill now (required; there is no "
                             "daemon mode — launchd is the scheduler)")
    parser.add_argument("--backup-dir",
                        help="bundle directory (default: [backup].dir from "
                             "config, else ~/.contextd/backups)")
    parser.add_argument("--temp-dir",
                        help="parent for the throwaway restore destination")
    parser.add_argument("--json", action="store_true",
                        help="print the receipt meta as JSON")
    args = parser.parse_args()
    if not args.once:
        parser.error("nothing to do: pass --once")
    meta = run_drill(
        backup_dir=Path(args.backup_dir) if args.backup_dir else None,
        temp_dir=Path(args.temp_dir) if args.temp_dir else None)
    if args.json:
        print(json.dumps(meta, sort_keys=True))
    elif meta["verdict"] == "PASS":
        print(f"restore drill PASS: {meta['bundle']} "
              f"({meta['bundle_bytes']} bytes) restored and verified in "
              f"{meta['total_seconds']}s (event #{meta['event_id']})")
    else:
        print(f"restore drill FAIL at stage {meta['failed_stage']}: "
              f"{meta['reason']} (event #{meta['event_id']})",
              file=sys.stderr)
    return 0 if meta["verdict"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
