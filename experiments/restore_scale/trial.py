#!/usr/bin/env python
"""Restore scale trial: find the cliffs before reality does.

Inflates synthetic archives (inflate.py) at three tiers x two shapes, runs
backup -> restore fire-drill (full battery) on each, and measures what the
docs only promised: wall time per stage, peak temp space (sampled, not
estimated), and peak RSS of the backup and drill processes (os.wait4). The
drill's preflight safety multiple is pinned from the measured peak
temp-space ratio. Results persist to results.json next to this script;
`report` renders the 6-cell table and flags the cliff conditions (any FAIL,
temp ratio > 2.5x bundle, super-linear stage time across tiers).

A measurement script, not a pytest fixture — the suite stays fast. Runs only
against synthetic archives under an explicit --work-dir; it refuses to look
at a real CONTEXTD_HOME by always exporting its own.

Usage:
    trial.py run --work-dir /big/scratch [--cells 1g:event_heavy,...]
    trial.py rehearse --work-dir /big/scratch     # cross-machine, spaced paths
    trial.py report
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from experiments.restore_scale.inflate import (  # noqa: E402
    GIB, inflate, tree_bytes,
)

ROOT = Path(__file__).resolve().parent.parent.parent
RESULTS = Path(__file__).resolve().parent / "results.json"
TIERS = {"1g": 1 * GIB, "4g": 4 * GIB, "8g": 8 * GIB}
SHAPES = ("event_heavy", "blob_heavy")
CELLS = [f"{tier}:{shape}" for tier in TIERS for shape in SHAPES]


class _DirSampler(threading.Thread):
    def __init__(self, root: Path):
        super().__init__(daemon=True)
        self.root, self.peak, self._stop = root, 0, threading.Event()

    def run(self):
        while not self._stop.is_set():
            try:
                self.peak = max(self.peak, tree_bytes(self.root))
            except OSError:
                pass
            self._stop.wait(0.5)

    def stop(self) -> int:
        self._stop.set()
        self.join()
        return self.peak


def _measured(cmd: list[str], env: dict, sample: Path) -> dict:
    """Run a child, returning wall seconds, its peak RSS (bytes, from
    os.wait4), exit code, output, and the sampled peak size of `sample`."""
    sampler = _DirSampler(sample)
    sampler.start()
    started = time.monotonic()
    child = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
    output = child.stdout.read()
    _, status, usage = os.wait4(child.pid, 0)
    child.returncode = os.waitstatus_to_exitcode(status)
    return {"seconds": round(time.monotonic() - started, 1),
            "peak_rss": usage.ru_maxrss,  # bytes on macOS
            "exit": child.returncode, "output": output,
            "sampled_peak": sampler.stop()}


def _load() -> dict:
    if RESULTS.exists():
        return json.loads(RESULTS.read_text())
    return {"cells": {}, "rehearsal": None}


def _save(results: dict) -> None:
    RESULTS.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")


def _env(home: Path) -> dict:
    env = os.environ.copy()
    env["CONTEXTD_HOME"] = str(home)
    return env


def run_cell(cell: str, work_dir: Path) -> dict:
    tier, shape = cell.split(":")
    target = TIERS[tier]
    work = work_dir / cell.replace(":", "-")
    if work.exists():
        shutil.rmtree(work)
    home, backups, temp = work / "home", work / "backups", work / "temp"
    temp.mkdir(parents=True)

    free = shutil.disk_usage(work_dir).free
    if free < target * 4:
        raise SystemExit(
            f"{cell}: refusing to run with {free} bytes free; the cell needs "
            f"~4x the {target}-byte tier (archive + bundle + restore + slack)")

    print(f"[{cell}] inflating ~{target // GIB} GiB {shape} ...", flush=True)
    row = {"cell": cell, "target_bytes": target,
           **inflate(home, target, shape, seed=cell)}
    print(f"[{cell}] archive: {row['archive_bytes']} bytes, "
          f"{row['events']} events, {row['blobs']} blobs "
          f"in {row['inflate_seconds']}s", flush=True)

    backup = _measured(
        [sys.executable, "-m", "contextd.cli", "backup", str(backups)],
        _env(home), backups)
    if backup["exit"] != 0:
        row["backup"] = backup
        return row
    bundle = next(backups.glob("*.ctxbackup"))
    row["backup"] = {k: backup[k] for k in ("seconds", "peak_rss")}
    row["backup"]["dest_peak_bytes"] = backup["sampled_peak"]
    row["bundle_bytes"] = tree_bytes(bundle)
    print(f"[{cell}] backup: {backup['seconds']}s, "
          f"rss {backup['peak_rss']}", flush=True)

    drill = _measured(
        [sys.executable, str(ROOT / "hooks" / "restore_drill.py"), "--once",
         "--json", "--backup-dir", str(backups), "--temp-dir", str(temp)],
        _env(home), temp)
    receipt = json.loads(drill["output"].strip().splitlines()[-1])
    row["drill"] = {"seconds": drill["seconds"], "peak_rss": drill["peak_rss"],
                    "exit": drill["exit"], "verdict": receipt["verdict"],
                    "stages": receipt["stages"],
                    "peak_temp_bytes": receipt["peak_temp_bytes"]}
    if receipt["verdict"] != "PASS":
        row["drill"]["failed_stage"] = receipt.get("failed_stage")
        row["drill"]["reason"] = receipt.get("reason")
    row["temp_ratio"] = round(
        receipt["peak_temp_bytes"] / row["bundle_bytes"], 3)
    print(f"[{cell}] drill: {receipt['verdict']} in {drill['seconds']}s, "
          f"rss {drill['peak_rss']}, temp ratio {row['temp_ratio']}",
          flush=True)

    shutil.rmtree(work)
    return row


def cmd_run(args) -> None:
    work_dir = Path(args.work_dir).expanduser()
    work_dir.mkdir(parents=True, exist_ok=True)
    results = _load()
    for cell in (args.cells.split(",") if args.cells else CELLS):
        if cell not in CELLS:
            raise SystemExit(f"unknown cell {cell!r} (choose from {CELLS})")
        results["cells"][cell] = run_cell(cell, work_dir)
        _save(results)
    print(f"saved -> {RESULTS}")


def cmd_rehearse(args) -> None:
    """Cross-machine rehearsal: a tier-1 bundle restored under a different
    HOME with every operative path containing spaces. Any absolute-path
    leakage in the bundle or the battery surfaces here as a FAIL."""
    work_dir = Path(args.work_dir).expanduser()
    work = work_dir / "rehearsal"
    if work.exists():
        shutil.rmtree(work)
    home = work / "source home"
    backups = work / "bundle shelf with spaces"
    temp = work / "re store temp"
    fake_home = work / "other machine home"
    live = work / "live archive with spaces"
    for path in (temp, fake_home):
        path.mkdir(parents=True)

    row = {"target_bytes": TIERS["1g"],
           **inflate(home, TIERS["1g"], "blob_heavy", seed="rehearsal")}
    backup = _measured(
        [sys.executable, "-m", "contextd.cli", "backup", str(backups)],
        _env(home), backups)
    if backup["exit"] != 0:
        raise SystemExit(f"rehearsal backup failed:\n{backup['output']}")

    env = _env(live)
    env["HOME"] = str(fake_home)
    drill = _measured(
        [sys.executable, str(ROOT / "hooks" / "restore_drill.py"), "--once",
         "--json", "--backup-dir", str(backups), "--temp-dir", str(temp)],
        env, temp)
    receipt = json.loads(drill["output"].strip().splitlines()[-1])
    row["drill"] = {"seconds": drill["seconds"], "verdict": receipt["verdict"],
                    "stages": receipt["stages"],
                    "failed_stage": receipt.get("failed_stage"),
                    "reason": receipt.get("reason")}
    row["paths"] = {"home": str(fake_home), "backups": str(backups),
                    "temp": str(temp), "live": str(live)}
    results = _load()
    results["rehearsal"] = row
    _save(results)
    shutil.rmtree(work)
    print(f"rehearsal: {receipt['verdict']}"
          + ("" if receipt["verdict"] == "PASS"
             else f" at {receipt.get('failed_stage')}: "
                  f"{receipt.get('reason')}"))
    if receipt["verdict"] != "PASS":
        raise SystemExit(2)


def _fmt_bytes(n) -> str:
    return f"{n / GIB:.2f}G" if n else "-"


def cmd_report(_args) -> None:
    results = _load()
    if not results["cells"]:
        raise SystemExit("no results yet: run `trial.py run` first")
    header = (f"{'cell':<16} {'archive':>8} {'bundle':>8} {'backup':>8} "
              f"{'drill':>8} {'restore':>8} {'peak tmp':>9} {'ratio':>6} "
              f"{'drill RSS':>10} verdict")
    print(header)
    print("-" * len(header))
    ratios = []
    findings = []
    for cell in CELLS:
        row = results["cells"].get(cell)
        if row is None:
            print(f"{cell:<16} (not run)")
            continue
        drill = row.get("drill", {})
        ratio = row.get("temp_ratio")
        if ratio:
            ratios.append((cell, ratio))
            if ratio > 2.5:
                findings.append(f"{cell}: temp ratio {ratio} exceeds 2.5x")
        verdict = drill.get("verdict", "NO RUN")
        if verdict != "PASS":
            findings.append(
                f"{cell}: {verdict} at {drill.get('failed_stage')}: "
                f"{drill.get('reason')}")
        print(f"{cell:<16} {_fmt_bytes(row.get('archive_bytes')):>8} "
              f"{_fmt_bytes(row.get('bundle_bytes')):>8} "
              f"{row.get('backup', {}).get('seconds', '-'):>8} "
              f"{drill.get('seconds', '-'):>8} "
              f"{drill.get('stages', {}).get('restore', '-'):>8} "
              f"{_fmt_bytes(drill.get('peak_temp_bytes')):>9} "
              f"{ratio if ratio is not None else '-':>6} "
              f"{drill.get('peak_rss', 0) // (1024 * 1024):>9}M "
              f"{verdict}")
    print("\nper-stage drill seconds:")
    for cell in CELLS:
        row = results["cells"].get(cell)
        if row and "drill" in row:
            stages = " ".join(f"{k}={v}" for k, v in
                              row["drill"]["stages"].items())
            print(f"  {cell:<16} {stages}")
    if ratios:
        worst = max(ratios, key=lambda item: item[1])
        print(f"\nmeasured peak temp ratio: {worst[1]} ({worst[0]}); "
              "drill preflight pins DRILL_TEMP_MULTIPLE from this "
              "measurement plus margin")
    rehearsal = results.get("rehearsal")
    if rehearsal:
        print(f"cross-machine rehearsal: {rehearsal['drill']['verdict']} "
              f"(different HOME, spaced paths)")
    print("\nfindings:" if findings else "\nfindings: none")
    for finding in findings:
        print(f"  - {finding}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="run cells (default: all six)")
    run.add_argument("--work-dir", required=True,
                     help="scratch volume with ~4x tier headroom; "
                          "never a real archive")
    run.add_argument("--cells", help="comma-separated tier:shape subset")
    reh = sub.add_parser("rehearse", help="cross-machine tier-1 rehearsal")
    reh.add_argument("--work-dir", required=True)
    sub.add_parser("report", help="render the results table")
    args = parser.parse_args()
    {"run": cmd_run, "rehearse": cmd_rehearse, "report": cmd_report}[args.cmd](args)


if __name__ == "__main__":
    main()
