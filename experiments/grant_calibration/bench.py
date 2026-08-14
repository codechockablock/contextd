#!/usr/bin/env python
"""Grant-calibration benchmark runner.

Subcommands, in mission order:
  selftest      deterministic instrument checks: world determinism, gated
                disclosure, parse rules, scripted judges (oracle / always-
                abstain / rubber-stamp) through the full decision machinery,
                surface-leak gate, render determinism. Zero model calls.
  validate      executable validity gate summary (surface, lengths, split);
                spec/frozen consistency once frozen.
  probe         one tiny haiku dispatch proving the pipeline end-to-end
                (counts against the ceiling; run BEFORE calibrate).
  calibrate N   run calibration split iteration N (full x2 + nocontext x1
                per fixture); prints the validity-gate numbers that either
                clear template iteration or stop the mission.
  freeze        freeze the spec (refuses while bars are unset).
  prereg        record the preregistration event in the DEDICATED experiment
                home (results/ledger — never the live archive).
  run ID        the held-out evaluation under prereg ID (full x3 +
                nocontext x1 per fixture), then build + store the report.
  report ID     rebuild the report from durable records and compare it
                byte-for-byte with the stored copy (--write stores).

Hard rules enforced here: every dispatch is preceded by a ceiling check
against the durable dispatch count (250 total for the mission); every
dispatched bundle is a gate-logged egress in its own synthetic world; the
live archive (~/.contextd) is never touched."""

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))

from experiments.grant_calibration import (judge, report, scoring,  # noqa: E402
                                           spec, worlds)
from experiments.grant_calibration.fixtures import (ALL_FIXTURES,  # noqa: E402
                                                    split_fixtures)
from experiments.handoff.common import contextd_home, run_claude  # noqa: E402

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
LEDGER_HOME = RESULTS / "ledger"
WORLDS = RESULTS / "worlds"

# executable validity-gate thresholds (instrument gate, fixed before any
# dispatch; distinct from the preregistered endpoint bars):
SURFACE_MARGIN = 0.10        # best token acc <= majority + this
SEP_MIN_FULL_ACC = 0.75      # calibration full-context decided accuracy
SEP_MARGIN = 0.20            # ...and above nocontext decided accuracy by this
CTRL_ABSTAIN_MIN = 0.50      # nocontext abstains this much, OR
CTRL_ACC_MAX = 0.65          # nocontext decided accuracy at/below chance-ish


def _ledger_conn(home: Path | None = None):
    with contextd_home(home or LEDGER_HOME):
        from contextd.db import connect
        return connect()


def record(kind: str, meta: dict, home: Path | None = None) -> int:
    conn = _ledger_conn(home)
    from contextd.db import append_event
    eid = append_event(conn, "eval", kind,
                       meta={"family": "grant_calibration", **meta})
    conn.close()
    return eid


def load_rows(home: Path | None = None) -> list:
    conn = _ledger_conn(home)
    rows = []
    for r in conn.execute(
            "SELECT id, meta FROM events WHERE kind='exp_run' ORDER BY id"):
        m = json.loads(r["meta"] or "{}")
        if m.get("family") == "grant_calibration":
            rows.append(m)
    conn.close()
    return rows


def dispatches_used(home: Path | None = None) -> int:
    return sum(1 for m in load_rows(home) if m.get("dispatched"))


def _fresh(path: Path) -> Path:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


def _dispatch(bundle_content: str) -> dict:
    used = dispatches_used()
    if used >= spec.DISPATCH_CEILING:
        sys.exit(f"DISPATCH CEILING: {used} >= {spec.DISPATCH_CEILING} — "
                 "stopping (mission stop condition)")
    r = run_claude(judge.build_prompt(bundle_content), judge.JUDGE_MODEL,
                   timeout=300)
    v = judge.parse_verdict(r["text"])
    return {**v, "dispatch_status": r["dispatch_status"], "exit": r["exit"],
            "duration_ms": r["duration_ms"], "output": (r["text"] or "")[:2000]}


def _judge_fixture(fixture: dict, world: dict, arm: str, rep: int,
                   phase: str, extra: dict) -> dict:
    b = worlds.disclose_bundle(world, arm, fixture["fid"])
    d = _dispatch(b["content"])
    row = {"phase": phase, "fid": fixture["fid"], "arm": arm, "rep": rep,
           "verdict": d["verdict"], "malformed": d["malformed"],
           "dispatch_status": d["dispatch_status"], "exit": d["exit"],
           "duration_ms": d["duration_ms"], "output": d["output"],
           "egress_id": b["egress_id"], "egress_tokens": b["est_tokens"],
           "dispatched": 1, **extra}
    record("exp_run", row)
    return row


def _run_split(fixtures: list, phase: str, worlds_dir: Path,
               full_reps: int, extra: dict) -> list:
    rows = []
    for f in fixtures:
        world = worlds.build_world(_fresh(worlds_dir / f["fid"]), f)
        for rep in range(full_reps):
            r = _judge_fixture(f, world, "full", rep, phase, extra)
            rows.append(r)
            print(f"  {f['fid']}/full#{rep}: {r['verdict']}"
                  f"{' (malformed)' if r['malformed'] else ''}"
                  f" [{r['dispatch_status']}]")
        r = _judge_fixture(f, world, "nocontext", 0, phase, extra)
        rows.append(r)
        print(f"  {f['fid']}/nocontext#0: {r['verdict']}"
              f"{' (malformed)' if r['malformed'] else ''}"
              f" [{r['dispatch_status']}]")
    return rows


# --------------------------------------------------------------------------
# selftest (zero model calls)
# --------------------------------------------------------------------------

def cmd_selftest(_args) -> int:
    failures = []

    def check(name, ok, detail=""):
        print(f"  {'PASS' if ok else 'FAIL'}  {name}"
              + (f" — {detail}" if detail and not ok else ""))
        if not ok:
            failures.append(name)

    print("[1/6] split discipline")
    split = split_fixtures()
    cal, held = split["calibration"], split["heldout"]
    check("36 fixtures, 18/18 split",
          len(ALL_FIXTURES) == 36 and len(cal) == 18 and len(held) == 18)
    from collections import Counter
    for side, name in ((cal, "calibration"), (held, "heldout")):
        c = Counter(f["subtype"] for f in side)
        check(f"{name} has 2 of every subtype",
              all(v == 2 for v in c.values()) and len(c) == 9, str(c))
    check("split disjoint",
          not {f["fid"] for f in cal} & {f["fid"] for f in held})

    print("[2/6] world determinism + gated disclosure")
    base = _fresh(WORLDS / "selftest")
    fx_c = next(f for f in cal if f["cls"] == "should_confirm")
    fx_d = next(f for f in cal if f["cls"] == "should_dismiss")
    w1 = worlds.build_world(base / "a", fx_c)
    worlds.build_world(base / "b", fx_c)
    w3 = worlds.build_world(base / "c", fx_d)
    d1, d2 = worlds.world_digest(base / "a"), worlds.world_digest(base / "b")
    check("same fixture => same world digest", d1 == d2)
    check("different fixture => different digest",
          d1 != worlds.world_digest(base / "c"))
    b_full = worlds.disclose_bundle(w1, "full", fx_c["fid"])
    b_no = worlds.disclose_bundle(w3, "nocontext", fx_d["fid"])
    check("full bundle carries dialogue + candidate",
          fx_c["candidate"] in b_full["content"]
          and fx_c["messages"][0]["text"] in b_full["content"])
    check("nocontext bundle carries candidate, not dialogue",
          fx_d["candidate"] in b_no["content"]
          and fx_d["messages"][0]["text"] not in b_no["content"])
    check("each disclosure is an egress event in its own world",
          worlds.world_egress_count(base / "a") == 1
          and worlds.world_egress_count(base / "c") == 1)

    print("[3/6] parse rules")
    p = judge.parse_verdict
    check("sole-line verdict", p("CONFIRM")["verdict"] == "CONFIRM")
    check("last sole line wins",
          p("ABSTAIN\nDISMISS")["verdict"] == "DISMISS")
    check("lowercase + punctuation",
          p("confirm.")["verdict"] == "CONFIRM" and not p("confirm.")["malformed"])
    check("single embedded token",
          p("I think DISMISS is right")["verdict"] == "DISMISS")
    m = p("either CONFIRM or DISMISS")
    check("ambiguous => malformed ABSTAIN",
          m["verdict"] == "ABSTAIN" and m["malformed"])
    m2 = p("")
    check("empty => malformed ABSTAIN",
          m2["verdict"] == "ABSTAIN" and m2["malformed"])

    print("[4/6] scripted judges through the decision machinery")
    bars = {"false_confirm_fixtures_max": 1, "false_confirm_max": 0.10,
            "false_dismiss_max": 0.34, "abstain_max": 0.50,
            "confirm_coverage_min": 0.50, "control_abstain_min": 0.50,
            "control_decided_accuracy_max": 0.65}

    def scripted(fixtures, rule, arm):
        return [{"fid": f["fid"], "arm": arm, "rep": 0,
                 "verdict": rule(f), "malformed": False} for f in fixtures]

    oracle = scripted(held, lambda f: "CONFIRM"
                      if f["cls"] == "should_confirm" else "DISMISS", "full")
    abstainer_no = scripted(held, lambda f: "ABSTAIN", "nocontext")
    d_ok = scoring.decide(scoring.score_trials(held, oracle),
                          scoring.score_trials(held, abstainer_no,
                                               "nocontext"), bars)
    check("oracle + abstaining control meets synthetic bars",
          d_ok["synthetic_bars_met"], str(d_ok["reasons"]))

    stamp = scripted(held, lambda f: "CONFIRM", "full")
    d_stamp = scoring.decide(scoring.score_trials(held, stamp),
                             scoring.score_trials(held, abstainer_no,
                                                  "nocontext"), bars)
    check("rubber-stamp fails on the harmful direction",
          not d_stamp["synthetic_bars_met"]
          and any("false-confirm" in r for r in d_stamp["reasons"]))

    silent = scripted(held, lambda f: "ABSTAIN", "full")
    d_silent = scoring.decide(scoring.score_trials(held, silent),
                              scoring.score_trials(held, abstainer_no,
                                                   "nocontext"), bars)
    check("always-abstain fails the usefulness floor (honest null)",
          not d_silent["synthetic_bars_met"]
          and any("coverage" in r for r in d_silent["reasons"]))

    oracle_no = scripted(held, lambda f: "CONFIRM"
                         if f["cls"] == "should_confirm" else "DISMISS",
                         "nocontext")
    d_leak = scoring.decide(scoring.score_trials(held, oracle),
                            scoring.score_trials(held, oracle_no,
                                                 "nocontext"), bars)
    check("label-reading control is caught as a leak",
          not d_leak["synthetic_bars_met"]
          and any("control" in r for r in d_leak["reasons"]))

    print("[5/6] surface-leak gate")
    s = scoring.surface_separability(ALL_FIXTURES)
    check("real candidates pass the surface gate",
          s["best_token_accuracy"] <= s["majority_baseline"] + SURFACE_MARGIN,
          str(s))
    leaky = [dict(f, candidate=f["candidate"]
                  + (" pendingitem" if f["cls"] == "should_confirm"
                     else " droppeditem")) for f in ALL_FIXTURES]
    s_bad = scoring.surface_separability(leaky)
    check("planted leak is caught",
          s_bad["best_token_accuracy"] > s_bad["majority_baseline"]
          + SURFACE_MARGIN, str(s_bad))

    print("[6/6] report render determinism (fake ledger, no dispatches)")
    fake_home = _fresh(RESULTS / "selftest-ledger")
    fake_spec = spec.build_spec()
    if any(v is None for v in fake_spec["bars"].values()):
        fake_spec["bars"] = bars
    pid = record("experiment", {"task_id": "selftest",
                                "spec_sha": "selftest-sha"}, home=fake_home)
    for m in (oracle[:4] + abstainer_no[:4]):
        record("exp_run", {**m, "phase": "heldout", "dispatched": 0},
               home=fake_home)
    rows = load_rows(home=fake_home)
    r1 = report.render({"spec_sha": "selftest-sha"}, pid, rows, fake_spec, 0)
    r2 = report.render({"spec_sha": "selftest-sha"}, pid, rows, fake_spec, 0)
    check("render is byte-deterministic", r1 == r2)
    check("render states the cap", "CALIBRATION NOT EARNED" in r1)

    shutil.rmtree(base, ignore_errors=True)
    shutil.rmtree(fake_home, ignore_errors=True)
    print("selftest:", "OK" if not failures else f"FAILED ({failures})")
    return 0 if not failures else 1


# --------------------------------------------------------------------------
# validate / probe / calibrate
# --------------------------------------------------------------------------

def cmd_validate(_args) -> int:
    problems = []
    s = scoring.surface_separability(ALL_FIXTURES)
    print(f"surface: best token {s['best_token']!r} acc "
          f"{s['best_token_accuracy']} vs majority {s['majority_baseline']} "
          f"(margin {SURFACE_MARGIN})")
    if s["best_token_accuracy"] > s["majority_baseline"] + SURFACE_MARGIN:
        problems.append("surface leak: candidate texts separate the labels")
    print(f"lengths: {scoring.length_balance(ALL_FIXTURES)}")
    live = spec.build_spec()
    if live["fixture_digest"] != json.loads(json.dumps(
            live["fixture_digest"])):
        problems.append("digest not stable")  # pragma: no cover
    if spec.FROZEN.exists():
        chk = spec.check_frozen()
        print(f"frozen spec: {'ok' if chk['ok'] else chk['why']} "
              f"(sha {chk['sha'][:16]})")
        if not chk["ok"]:
            problems.append(chk["why"])
    else:
        print("frozen spec: not yet frozen")
    for p in problems:
        print(f"  FAIL  {p}")
    print("validate:", "OK" if not problems else "FAILED")
    return 0 if not problems else 1


def cmd_probe(_args) -> int:
    fx = split_fixtures()["calibration"][0]
    world = worlds.build_world(_fresh(WORLDS / "probe" / fx["fid"]), fx)
    r = _judge_fixture(fx, world, "full", 0, "probe", {})
    print(json.dumps({k: r[k] for k in ("verdict", "malformed",
                                        "dispatch_status", "exit")}, indent=2))
    ok = r["dispatch_status"] == "succeeded"
    print(f"probe: {'OK' if ok else 'FAILED'} "
          f"(dispatches used: {dispatches_used()})")
    return 0 if ok else 1


def cmd_calibrate(args) -> int:
    it = args.iteration
    if it > 3:
        sys.exit("STOP: more than 3 fixture-template iterations (mission "
                 "stop condition)")
    cal = split_fixtures()["calibration"]
    prior = [r for r in load_rows() if r.get("phase") == "calibration"
             and r.get("iteration") == it]
    if prior:
        sys.exit(f"calibration iteration {it} already recorded "
                 f"({len(prior)} rows) — bump the iteration number")
    print(f"[calibrate iter {it}] {len(cal)} fixtures x "
          f"({spec.REPS_CAL_FULL} full + 1 nocontext)")
    rows = _run_split(cal, "calibration", WORLDS / f"cal-i{it}",
                      spec.REPS_CAL_FULL, {"iteration": it})
    full = scoring.score_trials(cal, rows, "full")
    noctx = scoring.score_trials(cal, rows, "nocontext")
    print(json.dumps({"full": full, "nocontext": noctx}, indent=2))

    acc_f = full["decided_accuracy"]["rate"] or 0.0
    acc_n = noctx["decided_accuracy"]["rate"]
    ab_n = noctx["abstain"]["rate"] or 0.0
    sep = acc_f >= SEP_MIN_FULL_ACC and (acc_n is None
                                         or acc_f >= acc_n + SEP_MARGIN)
    ctrl = ab_n >= CTRL_ABSTAIN_MIN or acc_n is None or acc_n <= CTRL_ACC_MAX
    surf = scoring.surface_separability(ALL_FIXTURES)
    surf_ok = surf["best_token_accuracy"] <= (surf["majority_baseline"]
                                              + SURFACE_MARGIN)
    print(f"\nvalidity gate: separation "
          f"{'PASS' if sep else 'FAIL'} (full decided acc {acc_f} vs "
          f"nocontext {acc_n}, bar {SEP_MIN_FULL_ACC} and +{SEP_MARGIN}); "
          f"control {'PASS' if ctrl else 'FAIL'} (nocontext abstain {ab_n} "
          f"/ acc {acc_n}); surface {'PASS' if surf_ok else 'FAIL'}")
    print(f"dispatches used: {dispatches_used()} / {spec.DISPATCH_CEILING}")
    if sep and ctrl and surf_ok:
        print("validity gate: MET — fill BARS in spec.py, freeze, prereg")
        return 0
    print("validity gate: NOT MET — iterate fixture templates (<= 3) or "
          "STOP per mission")
    return 1


# --------------------------------------------------------------------------
# freeze / prereg / run / report
# --------------------------------------------------------------------------

def cmd_freeze(_args) -> int:
    out = spec.freeze()
    print(f"spec frozen: sha {out['sha']} -> {out['path']}")
    return 0


def cmd_prereg(_args) -> int:
    chk = spec.check_frozen()
    if not chk["ok"]:
        sys.exit(f"cannot prereg: {chk['why']}")
    s = spec.build_spec()
    cal_iters = sorted({r.get("iteration", 1) for r in load_rows()
                       if r.get("phase") == "calibration"})
    meta = {
        "task_id": s["benchmark"],
        "spec_sha": spec.spec_sha(),
        "judge_prompt_sha": s["judge_prompt_sha"],
        "fixture_digest": s["fixture_digest"],
        "judge_model": s["judge_model"],
        "bars": s["bars"],
        "split": s["split"],
        "reps": s["reps"],
        "dispatch_plan": s["dispatch_plan"],
        "calibration_iterations_used": cal_iters,
        "dispatches_used_at_prereg": dispatches_used(),
        "registered": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
    }
    eid = record("experiment", meta)
    print(f"preregistered as ledger event #{eid} (dedicated home "
          f"{LEDGER_HOME})")
    print(f"  spec sha    {meta['spec_sha'][:16]}")
    print(f"  prompt sha  {meta['judge_prompt_sha'][:16]}")
    print(f"  bars        {json.dumps(meta['bars'])}")
    return 0


def _load_prereg(exp_id: int) -> dict:
    conn = _ledger_conn()
    row = conn.execute(
        "SELECT meta FROM events WHERE id=? AND kind='experiment'",
        (exp_id,)).fetchone()
    conn.close()
    if not row:
        sys.exit(f"no experiment event #{exp_id} in {LEDGER_HOME}")
    meta = json.loads(row["meta"])
    if meta.get("family") != "grant_calibration":
        sys.exit(f"event #{exp_id} is not a grant_calibration prereg")
    if meta["spec_sha"] != spec.spec_sha():
        sys.exit("spec changed since preregistration — the run is void")
    chk = spec.check_frozen()
    if not chk["ok"]:
        sys.exit(f"frozen spec invalid: {chk['why']}")
    return meta


def cmd_run(args) -> int:
    _load_prereg(args.exp_id)
    if any(r.get("phase") == "heldout" and r.get("exp_id") == args.exp_id
           for r in load_rows()):
        sys.exit(f"held-out rows for prereg #{args.exp_id} already exist — "
                 "the evaluation runs once")
    held = split_fixtures()["heldout"]
    print(f"[heldout] {len(held)} fixtures x "
          f"({spec.REPS_HELDOUT_FULL} full + 1 nocontext), prereg "
          f"#{args.exp_id}")
    _run_split(held, "heldout", WORLDS / "held",
               spec.REPS_HELDOUT_FULL, {"exp_id": args.exp_id})
    print(f"dispatches used: {dispatches_used()} / {spec.DISPATCH_CEILING}")
    return cmd_report(argparse.Namespace(exp_id=args.exp_id, write=True))


def _render(exp_id: int, prereg: dict) -> str:
    rows = [r for r in load_rows()
            if r.get("phase") != "heldout" or r.get("exp_id") == exp_id]
    return report.render(prereg, exp_id, rows, spec.build_spec(),
                         dispatches_used())


def cmd_report(args) -> int:
    prereg = _load_prereg(args.exp_id)
    rendered = _render(args.exp_id, prereg)
    path = report.report_path(spec.build_spec())
    if getattr(args, "write", False):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered)
        import hashlib
        record("exp_report", {"exp_id": args.exp_id,
                              "report_sha":
                                  hashlib.sha256(rendered.encode()).hexdigest(),
                              "path": str(path)})
        print(f"report written: {path}")
        return 0
    if not path.exists():
        print(f"no stored report at {path} — run with --write first")
        return 1
    stored = path.read_text()
    if stored == rendered:
        print(f"report rebuild: byte-identical to {path}")
        return 0
    print(f"report rebuild: DRIFT against {path}")
    return 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    sub.add_parser("validate")
    sub.add_parser("probe")
    c = sub.add_parser("calibrate")
    c.add_argument("iteration", type=int)
    sub.add_parser("freeze")
    sub.add_parser("prereg")
    r = sub.add_parser("run")
    r.add_argument("exp_id", type=int)
    rp = sub.add_parser("report")
    rp.add_argument("exp_id", type=int)
    rp.add_argument("--write", action="store_true")
    args = p.parse_args()
    fn = {"selftest": cmd_selftest, "validate": cmd_validate,
          "probe": cmd_probe, "calibrate": cmd_calibrate,
          "freeze": cmd_freeze, "prereg": cmd_prereg,
          "run": cmd_run, "report": cmd_report}[args.cmd]
    sys.exit(fn(args))


if __name__ == "__main__":
    main()
