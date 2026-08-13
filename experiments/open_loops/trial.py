#!/usr/bin/env python
"""Operator-trial scorer for protocol v2 (docs/OPEN_LOOPS.md).

Committed BEFORE the trial window opened so the scoring procedure is
pinned, not improvised after seeing the data. Deterministic, model-free,
read-only over the live ledger (local and unlogged, like ctx search).

Pinned procedure decisions (anything not listed here defers to the frozen
protocol text):

- window: events strictly after the start marker and at-or-before the end
  marker (ledger note events written at window open/close); pass their ids.
- path A: a loop created in-window by op=add (operator authority).
- path B: a loop created in-window by op=candidate and promoted by an
  in-window operator confirm. An unconfirmed or dismissed candidate is not
  an externalized loop.
- assisted capture = externalized / (externalized + missed), where missed
  is the count of recognized-but-never-externalized priorities from the
  operator's window-end list (--missed). Bar 0.8, denominator >= 5.
- carriage: for every in-window checkpoint egress carrying a loop_scope,
  the loops that were open for that scope at that egress (reduced from
  loop events with id < egress id) must appear in the egress's items.
  A loop named in loops_omitted is a LOUD failure (named_omission) — the
  bar requires presence; silent absence is a plain failure. Bar: 100%.
- burden: in-window dismiss transitions of model-created candidates,
  divided by session-days = distinct (claude session_id, UTC day) pairs
  with >= 1 ingested message in-window. Bar <= 1.0. Path B only.
- false promotion: scoring.score_false_promotion over loops created
  in-window. Bar 0.
- the operator's explicit acceptability answer arrives as
  --operator-accepts yes|no; without it the verdict line reports PENDING.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from experiments.open_loops.scoring import score_false_promotion  # noqa: E402

BARS = {"capture_min": 0.8, "denominator_min": 5,
        "burden_max": 1.0, "false_promotion": 0}


def _loop_events(conn, until_id=None):
    q = "SELECT id, ts, content, meta FROM events WHERE kind='loop'"
    args = []
    if until_id is not None:
        q += " AND id < ?"
        args.append(until_id)
    return [(r["id"], r["ts"], r["content"], json.loads(r["meta"] or "{}"))
            for r in conn.execute(q + " ORDER BY id", args)]


def _reduce(events):
    """Minimal replay mirroring contextd.loops.reduce_loops for scoring."""
    loops = {}
    for eid, ts, content, meta in events:
        op = meta.get("op")
        if op in ("add", "candidate"):
            loops[eid] = {"id": eid, "text": (content or "").strip(),
                          "scope": meta.get("scope") or {"global": True},
                          "state": "open" if op == "add" else "candidate",
                          "created_state":
                              "open" if op == "add" else "candidate",
                          "created_authority": meta.get("authority"),
                          "created_op": op, "created_ts": ts,
                          "promoted_authority": None, "events": [eid]}
            continue
        lp = loops.get(meta.get("loop"))
        if lp is None:
            continue
        allowed = {"confirm": ("candidate",), "close": ("open",),
                   "reopen": ("closed",), "dismiss": ("candidate",)}.get(op)
        if not allowed or lp["state"] not in allowed:
            continue
        lp["events"].append(eid)
        if op == "confirm":
            lp["state"] = "open"
            lp["promoted_authority"] = meta.get("authority")
        elif op == "close":
            lp["state"] = "closed"
        elif op == "reopen":
            lp["state"] = "open"
        elif op == "dismiss":
            lp["state"] = "dismissed"
    return loops


def _scope_str(scope):
    return "global" if scope.get("global") else f"repo:{scope['repo']}"


def score_window(conn, start_id: int, end_id: int, missed: int) -> dict:
    events = _loop_events(conn)
    in_window = [e for e in events if start_id < e[0] <= end_id]
    all_reduced = _reduce(events)

    created = [all_reduced[eid] for eid, *_ in in_window
               if eid in all_reduced]
    path_a = [lp for lp in created if lp["created_op"] == "add"]
    path_b = [lp for lp in created if lp["created_op"] == "candidate"
              and lp["promoted_authority"] == "operator"
              and any(start_id < e <= end_id for e in lp["events"][1:])]
    externalized = path_a + path_b
    denominator = len(externalized) + missed
    capture = (len(externalized) / denominator) if denominator else None

    # carriage over in-window checkpoint egresses that declare a loop scope
    checks = []
    for r in conn.execute(
            "SELECT id, meta FROM events WHERE kind='egress' AND id > ? "
            "AND id <= ? ORDER BY id", (start_id, end_id)):
        meta = json.loads(r["meta"] or "{}")
        if meta.get("type") != "checkpoint" or "loop_scope" not in meta:
            continue
        scope = meta["loop_scope"]
        want_scope = ("global" if scope == "global"
                      else f"repo:{scope}")
        at_time = _reduce(_loop_events(conn, until_id=r["id"]))
        expected = [lp for lp in at_time.values()
                    if lp["state"] == "open"
                    and _scope_str(lp["scope"]) == want_scope]
        items = set(meta.get("items") or [])
        omitted = set(meta.get("loops_omitted") or [])
        missing = [lp["id"] for lp in expected
                   if lp["id"] not in items and lp["id"] not in omitted]
        named_omission = [lp["id"] for lp in expected if lp["id"] in omitted]
        checks.append({"egress": r["id"], "scope": scope,
                       "expected": [lp["id"] for lp in expected],
                       "missing": missing,
                       "named_omission": named_omission,
                       "ok": not missing and not named_omission})
    carriage_ok = all(c["ok"] for c in checks) if checks else None

    # burden: dismissals of model candidates per session-day
    dismissals = 0
    for eid, ts, content, meta in in_window:
        if meta.get("op") == "dismiss":
            target = all_reduced.get(meta.get("loop"))
            if target and target["created_authority"] == "model":
                dismissals += 1
    days = {(json.loads(r["meta"])["session_id"], r["ts"][:10])
            for r in conn.execute(
                "SELECT ts, meta FROM events WHERE source='claude_code' "
                "AND kind='message' AND id > ? AND id <= ?",
                (start_id, end_id))}
    burden = dismissals / len(days) if days else 0.0

    fp = score_false_promotion(created)

    return {
        "window": [start_id, end_id],
        "paths": {
            "A_direct_add": [lp["id"] for lp in path_a],
            "B_candidate_confirmed": [lp["id"] for lp in path_b],
        },
        "capture": {"externalized": len(externalized), "missed": missed,
                    "denominator": denominator,
                    "rate": round(capture, 4) if capture is not None else None,
                    "bar": BARS["capture_min"],
                    "denominator_min": BARS["denominator_min"],
                    "pass": (capture is not None
                             and denominator >= BARS["denominator_min"]
                             and capture >= BARS["capture_min"])},
        "carriage": {"checks": checks, "pass": carriage_ok},
        "burden": {"dismissals": dismissals, "session_days": len(days),
                   "per_session_day": round(burden, 4),
                   "bar": BARS["burden_max"],
                   "pass": burden <= BARS["burden_max"]},
        "false_promotion": fp,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--start", type=int, required=True,
                   help="window-start marker event id (loops must be > it)")
    p.add_argument("--end", type=int, required=True,
                   help="window-end marker event id")
    p.add_argument("--missed", type=int, required=True,
                   help="count of recognized-but-never-externalized "
                        "priorities from the operator's window-end list")
    p.add_argument("--operator-accepts", choices=["yes", "no"],
                   help="the operator's explicit workflow-cost answer")
    args = p.parse_args()
    from contextd.db import connect
    result = score_window(connect(), args.start, args.end, args.missed)
    print(json.dumps(result, indent=2))
    gates = [result["capture"]["pass"], result["carriage"]["pass"] in (True, None),
             result["burden"]["pass"], result["false_promotion"]["pass"]]
    if result["carriage"]["pass"] is None:
        print("\nNOTE: no in-window checkpoint compilations found — "
              "carriage untested, which blocks EARNED.", file=sys.stderr)
    if args.operator_accepts is None:
        print("VERDICT: PENDING — operator acceptability answer missing")
        return
    earned = (all(gates) and result["carriage"]["pass"] is True
              and args.operator_accepts == "yes")
    print("VERDICT:", "ASSISTED CAPTURE EARNED" if earned else "NOT EARNED")


if __name__ == "__main__":
    main()
