"""The health sweep: model-free senses for the machinery around the archive.

docs/AGENTS.md stage 1. A daemon that degrades quietly — a reconciler
refusing every run into a log nobody reads, an ingester denied file access
for days — is supervised, restarted, and logged by launchd, and still
invisible. This sweep turns the existing evidence (the ledger's own
liveness watermarks, unreconciled backlog age, launchd exit statuses, log
tails, backup and drill ages, the grant reduction's anomaly list) into one
verdict event per run.

Discipline, matching the instrument events it joins:

* Zero model dispatches, ever. Every check is arithmetic over local state.
* The verdict is a content-NULL ``health``/``sweep`` event with a closed
  meta schema — never in FTS, never recallable, and free-text-free by
  construction, because these events are the future coordinator's entire
  input feed (docs/AGENTS.md: the coordinator is starved, not hardened).
* The operator is interrupted only on a NEW degradation (compared to the
  previous sweep), by local notification; steady state is silence. The
  notification carries check NAMES from the fixed registry below, never
  detail strings — details can quote filenames and log lines, and
  attacker-influenceable text does not belong in a trusted prompt.
* Check states are ``ok`` | ``degraded`` | ``unknown``. Unknown (a check
  that cannot run here — launchctl on CI, say) is not a degradation.
"""

import fcntl
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contextd import load_config  # noqa: E402
from contextd.db import append_event, connect, home, now_iso  # noqa: E402
from contextd.grants import reduce_grants  # noqa: E402
from contextd.liveness import capture_liveness, stale_line  # noqa: E402
from hooks.reconcile import unreconciled_epochs  # noqa: E402

#: The closed set of check names; the notification path may speak these
#: words and no others.
CHECK_NAMES = (
    "ingestion", "reconcile_backlog", "reconcile_errors", "launchd",
    "backup_age", "restore_drill", "grant_anomalies",
)

_ERROR_LINE = re.compile(r"^[\w.]+(?:Error|Exception|Required):")


def _cfg_health(cfg) -> dict:
    section = cfg.get("health", {}) or {}
    return {
        "reconcile_backlog_hours": section.get("reconcile_backlog_hours", 24),
        "backup_stale_after_hours": section.get("backup_stale_after_hours", 192),
        "notify": section.get("notify", True),
    }


def check_ingestion(conn, cfg, now: str) -> dict:
    rows = capture_liveness(conn, cfg, now=now)
    stale = [r for r in rows if r["stale"]]
    if stale:
        return {"name": "ingestion", "state": "degraded",
                "detail": "; ".join(stale_line(r) for r in stale)}
    return {"name": "ingestion", "state": "ok",
            "detail": f"{len(rows)} sources live"}


def check_reconcile_backlog(conn, hcfg, now: str) -> dict:
    epochs = unreconciled_epochs(conn)
    if not epochs:
        return {"name": "reconcile_backlog", "state": "ok", "detail": "empty"}
    oldest_id = epochs[0][0]
    ts = conn.execute(
        "SELECT ts FROM events WHERE id = ?", (oldest_id,)
    ).fetchone()["ts"]
    age_h = (datetime.fromisoformat(now)
             - datetime.fromisoformat(ts)).total_seconds() / 3600
    threshold = hcfg["reconcile_backlog_hours"]
    state = "degraded" if age_h > threshold else "ok"
    return {"name": "reconcile_backlog", "state": state,
            "detail": f"{len(epochs)} unreconciled, oldest {age_h:.1f}h "
                      f"(threshold {threshold:g}h)"}


def check_reconcile_errors(log_path: Path) -> dict:
    """Three or more identical trailing exception lines mean the same
    failure is repeating every run — the 2026-08-15 specimen was 42 of
    them, unread. The backlog check sees the symptom eventually; this one
    names the disease while the backlog is still young."""
    try:
        tail = log_path.read_text(errors="replace")[-16384:]
    except OSError:
        return {"name": "reconcile_errors", "state": "unknown",
                "detail": "log unreadable"}
    errors: list[tuple[int, str]] = []
    last_success = -1
    for index, raw in enumerate(tail.splitlines()):
        line = raw.strip()
        if _ERROR_LINE.match(line):
            errors.append((index, line))
        elif line.startswith("{"):
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if "epoch" in record and "error" not in record:
                last_success = index
    # an error streak cured by later successful runs is history, not disease
    recent = [line for index, line in errors if index > last_success]
    if len(recent) >= 3 and len(set(recent[-3:])) == 1:
        return {"name": "reconcile_errors", "state": "degraded",
                "detail": f"same failure repeating: {recent[-1][:200]}"}
    return {"name": "reconcile_errors", "state": "ok",
            "detail": "no repeating failure"}


def check_launchd(plist_dir: Path, launchctl_output: str | None) -> dict:
    """Installed com.contextd.* agents must be loaded and exiting zero.
    ``launchctl_output`` is injectable for tests; None means launchctl is
    unavailable here, which is unknown, not degraded."""
    expected = sorted(p.stem for p in plist_dir.glob("com.contextd.*.plist"))
    if launchctl_output is None:
        return {"name": "launchd", "state": "unknown",
                "detail": "launchctl unavailable"}
    seen: dict[str, tuple[str, str]] = {}
    for line in launchctl_output.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[2].startswith("com.contextd."):
            seen[parts[2]] = (parts[0], parts[1])
    problems = []
    for label in expected:
        if label not in seen:
            problems.append(f"{label} installed but not loaded")
            continue
        pid, status = seen[label]
        # a live PID means the agent is running now; a nonzero "last exit"
        # then describes the PREVIOUS incarnation (a deliberate kickstart
        # reads -15 forever) and is not a degradation
        if pid == "-" and status not in ("0", "-"):
            problems.append(f"{label} last exit {status}")
    if problems:
        return {"name": "launchd", "state": "degraded",
                "detail": "; ".join(problems)}
    return {"name": "launchd", "state": "ok",
            "detail": f"{len(expected)} agents loaded, all exit 0"}


def check_backup_age(backup_dir: Path, hcfg, now: str) -> dict:
    bundles = sorted(backup_dir.glob("*.ctxbackup"),
                     key=lambda p: p.stat().st_mtime) \
        if backup_dir.is_dir() else []
    if not bundles:
        # never-backed-up stays quiet, like the never-run drill: the agent
        # is installed per machine, and nagging every fresh archive helps
        # nobody
        return {"name": "backup_age", "state": "unknown",
                "detail": "no bundles yet"}
    age_h = (datetime.fromisoformat(now).timestamp()
             - bundles[-1].stat().st_mtime) / 3600
    threshold = hcfg["backup_stale_after_hours"]
    state = "degraded" if age_h > threshold else "ok"
    return {"name": "backup_age", "state": state,
            "detail": f"newest bundle {age_h:.1f}h old (threshold {threshold:g}h)"}


def check_restore_drill(conn, cfg, now: str) -> dict:
    row = conn.execute(
        "SELECT ts, meta FROM events WHERE kind='restore_drill' "
        "ORDER BY id DESC LIMIT 1").fetchone()
    if row is None:
        return {"name": "restore_drill", "state": "unknown",
                "detail": "never run"}
    verdict = (json.loads(row["meta"] or "{}")).get("verdict", "?")
    age_h = (datetime.fromisoformat(now)
             - datetime.fromisoformat(row["ts"])).total_seconds() / 3600
    threshold = cfg["backup"]["drill_stale_after_hours"]
    if verdict != "PASS":
        return {"name": "restore_drill", "state": "degraded",
                "detail": f"last verdict {verdict} {age_h:.1f}h ago"}
    if age_h > threshold:
        return {"name": "restore_drill", "state": "degraded",
                "detail": f"PASS but {age_h:.1f}h ago (threshold {threshold:g}h)"}
    return {"name": "restore_drill", "state": "ok",
            "detail": f"PASS {age_h:.1f}h ago"}


def check_grant_anomalies(conn, previous_count: int | None) -> dict:
    count = len(reduce_grants(conn)["anomalies"])
    if previous_count is not None and count > previous_count:
        return {"name": "grant_anomalies", "state": "degraded",
                "detail": f"{count - previous_count} new anomaly event(s) "
                          f"since last sweep (total {count})",
                "count": count}
    return {"name": "grant_anomalies", "state": "ok",
            "detail": f"{count} known", "count": count}


def previous_sweep(conn) -> dict | None:
    row = conn.execute(
        "SELECT meta FROM events WHERE source='health' AND kind='sweep' "
        "ORDER BY id DESC LIMIT 1").fetchone()
    return json.loads(row["meta"]) if row else None


def run_sweep(conn, cfg, now: str | None = None, *,
              launchctl_output: str | None = None,
              plist_dir: Path | None = None) -> dict:
    """One sweep: every check, one verdict, one appended event. Inputs are
    injectable for deterministic tests; production callers pass none."""
    now = now or now_iso()
    hcfg = _cfg_health(cfg)
    prior = previous_sweep(conn)
    prior_degraded = set((prior or {}).get("degraded", []))
    prior_anomalies = (prior or {}).get("grant_anomalies")

    checks = [
        check_ingestion(conn, cfg, now),
        check_reconcile_backlog(conn, hcfg, now),
        check_reconcile_errors(home() / "reconcile.log"),
        check_launchd(plist_dir or Path.home() / "Library" / "LaunchAgents",
                      launchctl_output),
        check_backup_age(home() / "backups", hcfg, now),
        check_restore_drill(conn, cfg, now),
        check_grant_anomalies(conn, prior_anomalies),
    ]
    degraded = sorted(c["name"] for c in checks if c["state"] == "degraded")
    new_degradations = sorted(set(degraded) - prior_degraded)
    anomaly_count = next(c["count"] for c in checks
                         if c["name"] == "grant_anomalies")
    verdict = "DEGRADED" if degraded else "OK"
    meta = {
        "verdict": verdict,
        "checks": {c["name"]: {"state": c["state"], "detail": c["detail"]}
                   for c in checks},
        "degraded": degraded,
        "new_degradations": new_degradations,
        "grant_anomalies": anomaly_count,
    }
    append_event(conn, "health", "sweep", meta=meta)
    return meta


def notify(new_degradations: list, enabled: bool) -> None:
    """Interrupt the operator only for what just broke, naming only check
    names from the fixed registry — never detail strings, which can quote
    attacker-influenceable text. Failure to notify never fails the sweep."""
    names = [n for n in new_degradations if n in CHECK_NAMES]
    if not (enabled and names):
        return
    message = "degraded: " + ", ".join(names)
    try:
        subprocess.run(
            ["osascript", "-e",
             f'display notification "{message}" with title "contextd health"'],
            capture_output=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"notification failed: {exc}", file=sys.stderr)


def _live_launchctl() -> str | None:
    try:
        r = subprocess.run(["launchctl", "list"], capture_output=True,
                           text=True, timeout=15)
        return r.stdout if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def main() -> int:
    archive = home()
    archive.mkdir(parents=True, exist_ok=True)
    lock = open(archive / "health.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return 0  # another sweep is in flight
    cfg = load_config()
    conn = connect()
    try:
        meta = run_sweep(conn, cfg, launchctl_output=_live_launchctl())
    finally:
        conn.close()
    notify(meta["new_degradations"], _cfg_health(cfg)["notify"])
    print(json.dumps({"verdict": meta["verdict"],
                      "degraded": meta["degraded"],
                      "new": meta["new_degradations"]}), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
