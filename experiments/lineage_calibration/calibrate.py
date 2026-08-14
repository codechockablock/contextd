#!/usr/bin/env python
"""Judge calibration for the lineage fidelity audit.

An uncalibrated judge is vibes; this protocol is the mission. The judge
(prompt + model + output schema, frozen by sha) is validated against the
seeded corruption corpus (corpus.py) with preregistered per-class bars
BEFORE it earns the right to read one real note:

  1. tune      — at most MAX_TUNE_ITERATIONS prompt iterations against a
                 fixed 25-item subset of the tuning half (5 scenarios x 5
                 classes). Iterating past that is protocol violation, not
                 diligence.
  2. prereg    — freeze the spec, bars, split, scoring rule, and decision
                 rule as a ledger event in THIS calibration archive, before
                 any held-out dispatch.
  3. heldout   — one shot at the 150-item held-out half. Resumable (items
                 with a recorded run are never re-dispatched), because a
                 rerun that double-spends the dispatch ceiling is worse
                 than a partial run.
  4. report    — rebuild everything from ledger events alone: per-class
                 confusion matrix, exact binomial CIs, the EARNED /
                 NOT EARNED verdict by the preregistered rule, and the
                 dispatch count.

Preregistered scoring rule: an item counts as DETECTED iff the parsed
verdict != 'faithful'. Unparseable replies and failed dispatches score
against the instrument: a corrupted item becomes a miss, a faithful item
becomes a false alarm. `quantitative-shift` carries no bar — it is measured
to establish the instrument's honest ceiling and reported whatever it is.

Harness-side tooling (models call the kernel; the kernel never calls
models). Runs only against a dedicated CONTEXTD_HOME — never the live
archive."""

import argparse
import hashlib
import json
import math
import os
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from contextd import home, load_config  # noqa: E402
from contextd.db import append_event, connect  # noqa: E402
from contextd.gate import disclose, record_dispatch_outcome  # noqa: E402

from experiments.lineage_calibration import corpus as corpus_mod  # noqa: E402
from experiments.lineage_calibration.corpus import (CLASSES,  # noqa: E402
                                                    FROZEN_DIGEST,
                                                    build_corpus, digest,
                                                    render_evidence, split)

CLAUDE_BIN = os.environ.get("LINEAGE_CAL_CLAUDE_BIN", "claude")
MODEL = os.environ.get("LINEAGE_JUDGE_MODEL", "haiku")
TIMEOUT = 240
TUNE_SCENARIOS = 5        # scenarios 0..4 of the tuning half: 25 items/iteration
MAX_TUNE_ITERATIONS = 3
DISPATCH_WORKERS = 6

BARS = {
    "dropped-caveat": {"metric": "recall", "min": 0.8},
    "unsupported-claim": {"metric": "recall", "min": 0.8},
    "emphasis-inversion": {"metric": "recall", "min": 0.7},
    "faithful": {"metric": "false_alarm", "max": 0.1},
    # quantitative-shift: no bar on purpose — honest ceiling, reported as-is
}

PROMPTS = {
    "v1": """You are a note-fidelity auditor for a personal archive. Below is
EVIDENCE — the complete dialogue a note-writer saw — and one NOTE written
from it. Bracketed ids like [1042] cite evidence messages; a citation
pointing at a real message does NOT make a claim true.

Classify the note as exactly one of:
- faithful: every claim is supported by the evidence; conditions or caveats
  the evidence attaches to a decision are preserved; what the evidence
  treats as the major vs minor concern is preserved; every number, date,
  amount, and version matches the evidence exactly. Paraphrasing is fine
  and expected — wording differences alone never make a note unfaithful.
- quantitative-shift: a number, date, percentage, count, or version in the
  note differs from the evidence.
- unsupported-claim: the note asserts something the evidence never states
  (an approval, a sign-off, a fact that appears nowhere in the dialogue).
- dropped-caveat: the note reports a decision or plan but omits a condition
  or limitation the evidence attaches to it.
- emphasis-inversion: the note swaps which concern the evidence treats as
  major vs minor, or turns a hedged statement into a confident one.

Check in this order and report the FIRST that applies: quantitative-shift,
unsupported-claim, dropped-caveat, emphasis-inversion, faithful. Compare
every number in the note against the evidence digit by digit.

Reply with ONLY a JSON object on one line, no code fences, no commentary:
{"verdict": "<one of the five labels>", "spans": ["short verbatim quote(s) \
from the EVIDENCE grounding your judgment"]}""",
}

SCHEMA = ('{"verdict": one of ' + "|".join(CLASSES)
          + ', "spans": [verbatim evidence quotes]}')


def judge_sha(prompt_version: str) -> str:
    spec = {"prompt": PROMPTS[prompt_version], "model": MODEL,
            "schema": SCHEMA, "verdicts": list(CLASSES)}
    return hashlib.sha256(
        json.dumps(spec, sort_keys=True).encode()).hexdigest()


def render_payload(item: dict, prompt_version: str) -> str:
    return (f"{PROMPTS[prompt_version]}\n\nEVIDENCE:\n{render_evidence(item)}"
            f"\n\nNOTE:\n{item['note']}\n")


def parse_reply(text: str) -> dict | None:
    """Strict-ish: find the JSON object, require a known verdict."""
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`").removeprefix("json").strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        out = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
    if not isinstance(out, dict) or out.get("verdict") not in CLASSES:
        return None
    spans = out.get("spans")
    return {"verdict": out["verdict"],
            "spans": [s for s in spans if isinstance(s, str)][:6]
            if isinstance(spans, list) else []}


def dispatch(payload: str) -> dict:
    """One `claude -p` call, synthesis_recall's isolation flags. Returns
    {status, exit, text, duration_ms}; never raises on model failure."""
    env = os.environ.copy()
    env["MCP_CONNECTION_NONBLOCKING"] = "false"
    env["ENABLE_TOOL_SEARCH"] = "off"
    t0 = time.monotonic()
    try:
        r = subprocess.run(
            [CLAUDE_BIN, "-p", "--model", MODEL, "--tools", "",
             "--strict-mcp-config", "--no-session-persistence",
             "--setting-sources", "", "--output-format", "json",
             "--max-budget-usd", "0.50"],
            input=payload, capture_output=True, text=True, timeout=TIMEOUT,
            cwd=tempfile.mkdtemp(prefix="ctx-lineage-cal-"), env=env)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "exit": None, "text": "",
                "duration_ms": int((time.monotonic() - t0) * 1000)}
    duration = int((time.monotonic() - t0) * 1000)
    if r.returncode != 0:
        return {"status": "failed", "exit": r.returncode, "text": "",
                "duration_ms": duration}
    try:
        envelope = json.loads(r.stdout)
        text = (envelope.get("result") or "").strip()
    except json.JSONDecodeError:
        text = r.stdout.strip()
    return {"status": "succeeded", "exit": 0, "text": text,
            "duration_ms": duration}


def _guard_home():
    if not os.environ.get("CONTEXTD_HOME"):
        sys.exit("refused: set CONTEXTD_HOME to a dedicated calibration "
                 "archive first — this protocol never runs against the "
                 "live archive")
    if home() == Path("~/.contextd").expanduser():
        sys.exit("refused: CONTEXTD_HOME points at the live archive")


def _done_items(conn, phase: str, key: str, value) -> set:
    done = set()
    for r in conn.execute(
            "SELECT meta FROM events WHERE kind = 'lineage_cal_run'"):
        m = json.loads(r["meta"])
        if m.get("phase") == phase and m.get(key) == value:
            done.add(m["item_id"])
    return done


def run_items(conn, cfg, items, phase: str, prompt_version: str,
              extra_meta: dict) -> list[dict]:
    """Disclose every payload through the real gate, dispatch in parallel
    (DB strictly on this thread), record linked outcomes and one
    content-NULL run event per item. One retry (a fresh disclosure) on
    dispatch failure; unparseable successes are never retried."""
    sha = judge_sha(prompt_version)
    pending = []
    for it in items:
        d = disclose(conn, cfg, render_payload(it, prompt_version), {
            "type": "lineage_calibration", "phase": phase,
            "item_id": it["item_id"], "class": it["class"],
            "judge_sha": sha, "client": "lineage-calibration", **extra_meta})
        pending.append((it, d))
    results = []
    with ThreadPoolExecutor(max_workers=DISPATCH_WORKERS) as pool:
        futures = [(it, d, pool.submit(dispatch, d["content"]))
                   for it, d in pending]
        for it, d, fut in futures:
            out = fut.result()
            egress_id = d["egress_id"]
            if out["status"] != "succeeded":
                record_dispatch_outcome(
                    conn, egress_id, out["status"], exit=out["exit"],
                    **({"timeout_seconds": TIMEOUT}
                       if out["status"] == "timeout" else {}))
                # one receipted retry with a fresh disclosure
                d2 = disclose(conn, cfg, render_payload(it, prompt_version), {
                    "type": "lineage_calibration", "phase": phase,
                    "item_id": it["item_id"], "class": it["class"],
                    "judge_sha": sha, "retry_of": egress_id,
                    "client": "lineage-calibration", **extra_meta})
                out = dispatch(d2["content"])
                egress_id = d2["egress_id"]
                if out["status"] != "succeeded":
                    record_dispatch_outcome(
                        conn, egress_id, out["status"], exit=out["exit"],
                        **({"timeout_seconds": TIMEOUT}
                           if out["status"] == "timeout" else {}))
            if out["status"] == "succeeded":
                record_dispatch_outcome(conn, egress_id, "succeeded", exit=0)
            parsed = parse_reply(out["text"]) if out["status"] == "succeeded" \
                else None
            run = {"phase": phase, "item_id": it["item_id"],
                   "class": it["class"], "judge_sha": sha,
                   "prompt_version": prompt_version, "egress_id": egress_id,
                   "dispatch_status": out["status"],
                   "duration_ms": out["duration_ms"],
                   "verdict": parsed["verdict"] if parsed else "unparseable",
                   "spans": parsed["spans"] if parsed else [],
                   **extra_meta}
            append_event(conn, "eval", "lineage_cal_run", meta=run)
            results.append(run)
            print(f"  {it['item_id']:<28} {it['class']:<20} -> "
                  f"{run['verdict']}", flush=True)
    return results


def confusion(runs: list[dict]) -> dict:
    """true class -> {judged verdict (or 'unparseable') -> count}."""
    matrix = {c: {} for c in CLASSES}
    for r in runs:
        row = matrix.setdefault(r["class"], {})
        row[r["verdict"]] = row.get(r["verdict"], 0) + 1
    return matrix


def rates(matrix: dict) -> dict:
    """Per-class detection with exact binomial CI, under the preregistered
    asymmetry: an unparseable reply is a MISS on a corrupted class (the
    instrument failed to flag) but a FALSE ALARM on faithful (the instrument
    failed to clear) — unparseable always scores against the instrument."""
    out = {}
    for cls in CLASSES:
        row = matrix.get(cls, {})
        n = sum(row.values())
        if cls == "faithful":
            detected = n - row.get("faithful", 0)
        else:
            detected = sum(v for k, v in row.items()
                           if k in CLASSES and k != "faithful")
        bar = BARS.get(cls)
        out[cls] = {
            "n": n, "detected": detected,
            "rate": round(detected / n, 4) if n else None,
            "ci": [round(x, 4) for x in clopper_pearson(detected, n)]
            if n else None,
            "bar": (bar.get("min") if bar and bar["metric"] == "recall"
                    else bar.get("max") if bar else None),
            "metric": bar["metric"] if bar else "ceiling",
        }
    return out


def _binom_cdf(k: int, n: int, p: float) -> float:
    return sum(math.comb(n, i) * p**i * (1 - p) ** (n - i)
               for i in range(0, k + 1))


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    """Exact binomial CI, stdlib-only (bisection on the binomial tails)."""
    def solve(f, lo, hi):
        for _ in range(200):
            mid = (lo + hi) / 2
            if f(mid):
                hi = mid
            else:
                lo = mid
        return (lo + hi) / 2
    lower = 0.0 if k == 0 else solve(
        lambda p: 1 - _binom_cdf(k - 1, n, p) > alpha / 2, 0.0, 1.0)
    upper = 1.0 if k == n else solve(
        lambda p: _binom_cdf(k, n, p) < alpha / 2, 0.0, 1.0)
    return lower, upper


def apply_decision_rule(per_class: dict) -> dict:
    checks = []
    for cls, bar in BARS.items():
        row = per_class[cls]
        if bar["metric"] == "recall":
            ok = row["rate"] is not None and row["rate"] >= bar["min"]
            checks.append({"class": cls, "metric": "recall",
                           "observed": row["rate"], "bar": f">= {bar['min']}",
                           "pass": ok})
        else:
            ok = row["rate"] is not None and row["rate"] <= bar["max"]
            checks.append({"class": cls, "metric": "false_alarm",
                           "observed": row["rate"], "bar": f"<= {bar['max']}",
                           "pass": ok})
    verdict = ("AUDIT EARNED" if all(c["pass"] for c in checks)
               else "AUDIT NOT EARNED")
    return {"checks": checks, "verdict": verdict}


def _tune_items():
    tuning, _ = split(build_corpus())
    return [it for it in tuning if it["scenario"] < TUNE_SCENARIOS]


def cmd_tune(args):
    _guard_home()
    conn, cfg = connect(), load_config()
    prior = {json.loads(r["meta"]).get("iteration")
             for r in conn.execute(
                 "SELECT meta FROM events WHERE kind='lineage_cal_run'")
             if json.loads(r["meta"]).get("phase") == "tune"}
    prior.discard(None)
    if args.iteration in prior:
        sys.exit(f"refused: tuning iteration {args.iteration} already ran")
    if len(prior) >= MAX_TUNE_ITERATIONS:
        sys.exit(f"refused: {MAX_TUNE_ITERATIONS} tuning iterations already "
                 "spent — the protocol does not allow more")
    if conn.execute("SELECT 1 FROM events WHERE kind = "
                    "'lineage_calibration_prereg'").fetchone():
        sys.exit("refused: prereg exists; tuning after preregistration is "
                 "protocol violation")
    items = _tune_items()
    print(f"tuning iteration {args.iteration}: prompt {args.prompt}, "
          f"{len(items)} items, judge {judge_sha(args.prompt)[:12]}")
    runs = run_items(conn, cfg, items, "tune", args.prompt,
                     {"iteration": args.iteration})
    _print_rates(confusion(runs))


def cmd_prereg(args):
    _guard_home()
    conn = connect()
    if conn.execute("SELECT 1 FROM events WHERE kind = "
                    "'lineage_calibration_prereg'").fetchone():
        sys.exit("refused: a prereg event already exists in this archive")
    corpus = build_corpus()
    if digest(corpus) != FROZEN_DIGEST:
        sys.exit("refused: corpus digest drifted from FROZEN_DIGEST")
    tuning, heldout = split(corpus)
    meta = {
        "kind_note": "preregistration for the lineage-audit judge calibration",
        "corpus_digest": FROZEN_DIGEST,
        "corpus_counts": {c: sum(1 for i in corpus if i["class"] == c)
                          for c in CLASSES},
        "split_rule": f"by scenario: 0..{corpus_mod.SCENARIOS // 2 - 1} tune, "
                      f"{corpus_mod.SCENARIOS // 2}..{corpus_mod.SCENARIOS - 1}"
                      " held-out",
        "n_tuning": len(tuning), "n_heldout": len(heldout),
        "tune_subset": f"scenarios 0..{TUNE_SCENARIOS - 1} "
                       f"({TUNE_SCENARIOS * len(CLASSES)} items/iteration), "
                       f"max {MAX_TUNE_ITERATIONS} iterations",
        "judge_prompt_version": args.prompt,
        "judge_prompt": PROMPTS[args.prompt],
        "judge_model": MODEL,
        "judge_schema": SCHEMA,
        "judge_sha": judge_sha(args.prompt),
        "bars": BARS,
        "scoring_rule": "detected iff parsed verdict != 'faithful'; "
                        "unparseable replies and failed dispatches count "
                        "against the instrument (miss for corrupted classes, "
                        "false alarm for faithful); one receipted retry per "
                        "dispatch failure, none for unparseable successes",
        "decision_rule": "AUDIT EARNED iff every bar in `bars` passes on the "
                         "held-out point estimate; quantitative-shift has no "
                         "bar and is reported as the honest ceiling",
        "dispatch_ceiling_mission": 250,
        "ci": "exact Clopper-Pearson, alpha=0.05",
    }
    eid = append_event(conn, "eval", "lineage_calibration_prereg", meta=meta)
    print(f"preregistered as event #{eid} (judge {meta['judge_sha'][:12]}, "
          f"corpus {FROZEN_DIGEST[:12]})")


def _prereg(conn, prereg_id: int) -> dict:
    row = conn.execute(
        "SELECT meta FROM events WHERE id = ? AND kind = "
        "'lineage_calibration_prereg'", (prereg_id,)).fetchone()
    if not row:
        sys.exit(f"no prereg event #{prereg_id}")
    return json.loads(row["meta"])


def cmd_heldout(args):
    _guard_home()
    conn, cfg = connect(), load_config()
    pre = _prereg(conn, args.prereg_id)
    corpus = build_corpus()
    if digest(corpus) != pre["corpus_digest"]:
        sys.exit("refused: corpus digest no longer matches the prereg")
    if judge_sha(pre["judge_prompt_version"]) != pre["judge_sha"]:
        sys.exit("refused: judge spec drifted since preregistration")
    _, heldout = split(corpus)
    done = _done_items(conn, "heldout", "prereg_id", args.prereg_id)
    todo = [it for it in heldout if it["item_id"] not in done]
    if not todo:
        print("held-out run already complete; nothing to dispatch")
        return
    print(f"held-out run: {len(todo)} of {len(heldout)} items remaining "
          f"(judge {pre['judge_sha'][:12]})")
    run_items(conn, cfg, todo, "heldout", pre["judge_prompt_version"],
              {"prereg_id": args.prereg_id})
    print("held-out dispatch complete; build the verdict with: "
          f"calibrate.py report {args.prereg_id}")


def _print_rates(matrix: dict):
    per = rates(matrix)
    for cls in CLASSES:
        row, m = per[cls], matrix.get(cls, {})
        misread = {k: v for k, v in sorted(m.items()) if k != cls}
        bar = ("" if row["bar"] is None
               else f"  bar {'>=' if row['metric'] == 'recall' else '<='} "
                    f"{row['bar']}")
        label = "flagged" if cls == "faithful" else "detected"
        print(f"  {cls:<20} {label} {row['detected']}/{row['n']}"
              + (f" = {row['rate']:.2f}" if row["rate"] is not None else "")
              + bar + (f"  judged-as: {misread}" if misread else ""))


def cmd_report(args):
    _guard_home()
    conn = connect()
    pre = _prereg(conn, args.prereg_id)
    runs = []
    for r in conn.execute("SELECT id, meta FROM events WHERE kind = "
                          "'lineage_cal_run' ORDER BY id"):
        m = json.loads(r["meta"])
        if m.get("phase") == "heldout" and m.get("prereg_id") == args.prereg_id:
            runs.append(m)
    if not runs:
        sys.exit("no held-out runs recorded for this prereg")
    prereg_row = conn.execute(
        "SELECT id FROM events WHERE kind='lineage_calibration_prereg'"
    ).fetchone()
    first_heldout = conn.execute(
        "SELECT MIN(id) AS i FROM events WHERE kind='lineage_cal_run' AND "
        "json_extract(meta,'$.phase')='heldout'").fetchone()["i"]
    matrix = confusion(runs)
    per_class = rates(matrix)
    decision = apply_decision_rule(per_class)
    dispatches = conn.execute(
        "SELECT COUNT(*) FROM events WHERE kind='egress_outcome'"
    ).fetchone()[0]
    tune_runs = conn.execute(
        "SELECT COUNT(*) FROM events WHERE kind='lineage_cal_run' AND "
        "json_extract(meta,'$.phase')='tune'").fetchone()[0]
    report = {
        "prereg_id": args.prereg_id,
        "prereg_precedes_heldout": bool(prereg_row and first_heldout
                                        and prereg_row["id"] < first_heldout),
        "judge_sha": pre["judge_sha"],
        "judge_model": pre["judge_model"],
        "corpus_digest": pre["corpus_digest"],
        "n_heldout": len(runs),
        "unparseable": sum(1 for r in runs if r["verdict"] == "unparseable"),
        "confusion": matrix,
        "per_class": per_class,
        "decision": decision,
        "verdict": decision["verdict"],
        "dispatch_outcomes_in_archive": dispatches,
        "tune_runs": tune_runs,
    }
    if args.json:
        print(json.dumps(report, indent=2))
        return
    print(f"LINEAGE JUDGE CALIBRATION — prereg #{args.prereg_id}  "
          f"judge {pre['judge_sha'][:12]}  model {pre['judge_model']}")
    print(f"corpus {pre['corpus_digest'][:12]}  held-out n={len(runs)}  "
          f"unparseable {report['unparseable']}  prereg-precedes-heldout: "
          f"{report['prereg_precedes_heldout']}")
    print()
    _print_rates(matrix)
    print()
    for c in decision["checks"]:
        print(f"  {'PASS' if c['pass'] else 'FAIL'}  {c['class']} "
              f"{c['metric']} {c['observed']} (bar {c['bar']})")
    qs = per_class["quantitative-shift"]
    print(f"  CEILING  quantitative-shift detection {qs['rate']} "
          f"[{qs['ci'][0]}, {qs['ci'][1]}] — no bar; this is the "
          "instrument's honest ceiling on subtle numeric drift")
    print()
    print(f"VERDICT: {decision['verdict']} (by the preregistered rule alone)")
    print(f"dispatch outcomes recorded in this archive: {dispatches} "
          f"(mission ceiling 250 includes the live audit)")


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("corpus", help="print corpus counts and digest")
    sp = sub.add_parser("tune", help="one tuning iteration (25 items)")
    sp.add_argument("--iteration", type=int, required=True)
    sp.add_argument("--prompt", default="v1", choices=sorted(PROMPTS))
    sp = sub.add_parser("prereg", help="freeze spec + bars as a ledger event")
    sp.add_argument("--prompt", default="v1", choices=sorted(PROMPTS))
    sp = sub.add_parser("heldout", help="the one held-out run (resumable)")
    sp.add_argument("prereg_id", type=int)
    sp = sub.add_parser("report", help="rebuild verdict from the ledger")
    sp.add_argument("prereg_id", type=int)
    sp.add_argument("--json", action="store_true")
    args = p.parse_args()
    if args.cmd == "corpus":
        corpus = build_corpus()
        print(json.dumps({"items": len(corpus), "digest": digest(corpus),
                          "frozen": digest(corpus) == FROZEN_DIGEST},
                         indent=2))
        return
    {"tune": cmd_tune, "prereg": cmd_prereg, "heldout": cmd_heldout,
     "report": cmd_report}[args.cmd](args)


if __name__ == "__main__":
    main()
