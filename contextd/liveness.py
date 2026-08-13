"""Capture liveness: ledger-derived per-source watermarks.

A dead pipeline writes nothing, so its last event going stale IS the signal —
no heartbeat files, no daemon monitoring, no launchd awareness. Thresholds
flag pipeline death, never operator behavior: `note` is a deliberate human
act, so it ships with no threshold — its age is displayed, its silence never
warns. A source with no threshold never warns; a thresholded source that has
never produced an event warns as "no events ever".
"""

from datetime import datetime

from .db import now_iso


def capture_liveness(conn, cfg, now: str | None = None) -> list[dict]:
    """One row per source present in the ledger, plus one per thresholded
    source that has never produced an event (last_ts None). ``now`` is an ISO
    timestamp, injectable for deterministic tests; thresholds come from
    cfg["liveness"]["stale_after_hours"] (hours per source)."""
    thresholds = cfg.get("liveness", {}).get("stale_after_hours", {}) or {}
    now_dt = datetime.fromisoformat(now or now_iso())
    rows = conn.execute(
        "SELECT source, MAX(ts) AS last_ts FROM events GROUP BY source"
    ).fetchall()
    out = []
    for r in rows:
        age = (now_dt - datetime.fromisoformat(r["last_ts"])).total_seconds() / 3600
        threshold = thresholds.get(r["source"])
        out.append({"source": r["source"], "last_ts": r["last_ts"],
                    "age_hours": round(age, 1), "threshold_hours": threshold,
                    "stale": threshold is not None and age > threshold})
    for source in set(thresholds) - {r["source"] for r in rows}:
        out.append({"source": source, "last_ts": None, "age_hours": None,
                    "threshold_hours": thresholds[source], "stale": True})
    out.sort(key=lambda r: r["source"])
    return out


def format_age(hours: float) -> str:
    return f"{hours / 24:.1f}d" if hours >= 48 else f"{hours:.1f}h"


def describe(row: dict) -> str:
    if row["last_ts"] is None:
        return "no events ever"
    return f"last event {format_age(row['age_hours'])} ago"


def stale_line(row: dict) -> str:
    return f"{row['source']} {describe(row)} (threshold {row['threshold_hours']:g}h)"
