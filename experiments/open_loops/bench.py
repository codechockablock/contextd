#!/usr/bin/env python
"""Open-loops benchmark runner.

Subcommands (the mission's evaluation-instrument gates):
  selftest       deterministic instrument checks: known-positive and honest-
                 null worlds, oracle/silent/spam mechanisms, pipeline
                 carriage, pair discipline, decision machinery. No models.
  validate-spec  frozen-spec integrity: fixture digest, split discipline,
                 calibration consistency, crossed use-world construction,
                 no-curation and no-leakage checks, prereg hash match.
  probe          read-only wiring probe: one tiny `claude -p` run against a
                 scratch archive proving the loop_candidate MCP tool is
                 reachable (run BEFORE prereg; costs one haiku call).
  prereg         record the preregistration event in the live ledger
                 (content-NULL, family=open_loops) with spec + prompt hashes.
  run <exp_id>   execute the preregistered evaluation: capture on held-out
                 worlds via hooks/loop_scan.py, use via crossed resumption
                 arms. Records every run durably; raw artifacts to results/.
  report <exp_id> rebuild the full report from durable records alone.

Endpoints stay separate by contract (docs/OPEN_LOOPS.md); the capture
verdict is capped at NOT EARNED without the real-operator trial, whatever
the machine-side numbers say."""

import argparse
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))

from experiments.handoff.common import (contextd_home, live_conn,  # noqa: E402
                                        run_claude)
from experiments.open_loops import scoring, worlds  # noqa: E402
from experiments.open_loops.calibrate import _stratified_perm_p  # noqa: E402
from experiments.open_loops.fixtures import (ALL_FIXTURES,  # noqa: E402
                                             fixture_digest, split_fixtures)
from experiments.open_loops.spec import build_spec, spec_sha  # noqa: E402

RESULTS = Path(__file__).resolve().parent / "results"
FROZEN_SPEC = Path(__file__).resolve().parent / "spec-frozen.json"
FROZEN_CAL = Path(__file__).resolve().parent / "calibration-frozen.json"
WORLDS_DIR = REPO / "runs" / "open-loops-20260813" / "worlds"
USE_SHAPES = ("continuous_flow", "closure_mask")
RESUME_MODEL = "haiku"

TASK_TEMPLATE = """You are a fresh model resuming work on {blurb} after the \
previous working session was destroyed. Below is a checkpoint compiled \
automatically from the project archive; bracketed [id]s are archive event \
ids.

{context_block}

=== YOUR TASK ===
Continue the work — do not merely summarize it. Without asking questions, \
state:
1. OBJECTIVE: what the project is currently working toward;
2. JUST DONE: the most recent completed work;
3. STILL OPEN: everything that must still happen before this phase is \
complete — most urgent first, each concrete enough to execute;
4. NEXT ACTION: the single step you would take first.
Cite bracketed event ids when you rely on archive material."""


def record(kind: str, meta: dict) -> int:
    conn = live_conn()
    from contextd.db import append_event
    return append_event(conn, "eval", kind,
                        meta={"family": "open_loops", **meta})


def prompt_sha() -> str:
    scan = REPO / "hooks" / "loop_scan.py"
    if not scan.exists():
        return "absent"
    import ast
    tree = ast.parse(scan.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", "") == "PROMPT" for t in node.targets):
            return hashlib.sha256(
                ast.literal_eval(node.value).encode()).hexdigest()
    return "missing-PROMPT"


def use_fixtures() -> list:
    """The four preregistered use worlds: the two measured killer shapes,
    first two projects alphabetically within each — deterministic."""
    held = split_fixtures()["heldout"]
    chosen = []
    for shape in USE_SHAPES:
        of_shape = sorted((f for f in held if f["shape"] == shape),
                          key=lambda f: f["project"])
        chosen.extend(of_shape[:2])
    return chosen


def _fresh(path: Path) -> Path:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


# --------------------------------------------------------------------------
# selftest
# --------------------------------------------------------------------------

def cmd_selftest(_args) -> int:
    split = split_fixtures()
    cal = split["calibration"]
    # the live bars, never a copy: selftest must validate what run will use
    spec = build_spec()
    bars = {"capture_min": spec["endpoints"]["capture"]["bar"]["capture_min"],
            "burden_max":
                spec["endpoints"]["confirmation_burden"]["bar"]["burden_max"]}
    failures = []

    def check(name, ok, detail=""):
        print(f"  {'PASS' if ok else 'FAIL'}  {name}" +
              (f" — {detail}" if detail and not ok else ""))
        if not ok:
            failures.append(name)

    print("[1/5] scorer on known mechanisms (calibration split)")
    oracle = {}
    for f in cal:
        oracle[f["fid"]] = [" and ".join(p["match"]) + " — proposed"
                            for p in f["planted"]
                            if p["label"] == "must_capture"]
    s = scoring.score_capture(cal, oracle)
    check("oracle captures everything at zero burden",
          s["capture_rate"] == 1.0 and s["burden_mean"] == 0.0, str(s))
    d = scoring.decide_capture(s["capture_rate"], s["burden_mean"], 0, True,
                               bars)
    check("oracle earns the decision", d["earned"], str(d))

    silent = scoring.score_capture(cal, {})
    check("silent mechanism captures nothing, costs nothing",
          silent["capture_rate"] == 0.0 and silent["burden_mean"] == 0.0)
    check("silent mechanism does not earn (honest null)",
          not scoring.decide_capture(silent["capture_rate"],
                                     silent["burden_mean"], 0, True,
                                     bars)["earned"])

    spam = {f["fid"]: ["tighten the type hints", "rework the logging",
                       "profile the hot path"] for f in cal}
    sp = scoring.score_capture(cal, spam)
    check("spam mechanism fails on burden",
          not scoring.decide_capture(sp["capture_rate"], sp["burden_mean"],
                                     0, True, bars)["earned"], str(sp))

    print("[2/5] null world returns 'nothing works'")
    nulls = [f for f in cal if f["shape"] == "null"]
    ns = scoring.score_capture(nulls, {f["fid"]: [] for f in nulls})
    nd = scoring.decide_capture(ns["capture_rate"], ns["burden_mean"], 0,
                                True, bars)
    check("no plants -> capture undefined -> not earned",
          ns["capture_rate"] is None and not nd["earned"])

    print("[3/5] pipeline carriage on a calibration use-world")
    fx = next(f for f in cal if f["shape"] == "continuous_flow")
    base = _fresh(WORLDS_DIR / "selftest")
    w_with = worlds.build_use_world(base / "with", fx, with_loop=True)
    w_without = worlds.build_use_world(base / "without", fx, with_loop=False)
    p_with = worlds.compile_use_package(w_with)["package"]
    p_without = worlds.compile_use_package(w_without)["package"]
    check("with-arm precondition (loop carried, section present)",
          worlds.verify_use_contrast(w_with, p_with, True) == [],
          str(worlds.verify_use_contrast(w_with, p_with, True)))
    check("without-arm precondition (no section, no leak)",
          worlds.verify_use_contrast(w_without, p_without, False) == [],
          str(worlds.verify_use_contrast(w_without, p_without, False)))
    fp = scoring.score_false_promotion(
        worlds.reduce_world_loops(w_with["home"]))
    check("operator add is not a false promotion", fp["pass"], str(fp))

    print("[4/5] terminal/wrong-scope exclusion in the same pipeline")
    with contextd_home(w_with["home"]):
        from contextd.db import connect
        from contextd.loops import add_candidate, add_loop, make_scope, transition
        conn = connect()
        dead = add_loop(conn, "a finished migration step",
                        make_scope(w_with["repo"]))["loop"]
        transition(conn, dead["id"], "close", "operator")
        cand = add_candidate(conn, "an unconfirmed idea",
                             make_scope(w_with["repo"]))["loop"]
        other = add_loop(conn, "an item for a different project",
                         make_scope("/synthetic/elsewhere"))["loop"]
        conn.close()
    p2 = worlds.compile_use_package(w_with)["package"]
    cc = scoring.check_carriage(
        p2, [w_with["ack_text"]],
        [dead["text"], cand["text"], other["text"]])
    check("closed/candidate/wrong-project absent, active still carried",
          cc["pass"], str(cc["problems"]))

    print("[5/5] identical-pair discipline")
    pair = [f for f in ALL_FIXTURES if f["shape"] == "identical_pair"]
    clean = {f["fid"]: {"false_promotions": 0, "asserted_certainty": False}
             for f in pair}
    check("clean pair passes", scoring.score_pair(pair, clean)["pass"])
    dirty = dict(clean)
    dirty[pair[0]["fid"]] = {"false_promotions": 1,
                             "asserted_certainty": False}
    check("certainty on either element fails",
          not scoring.score_pair(pair, dirty)["pass"])

    shutil.rmtree(base, ignore_errors=True)
    print("selftest:", "OK" if not failures else f"FAILED ({failures})")
    return 0 if not failures else 1


# --------------------------------------------------------------------------
# validate-spec
# --------------------------------------------------------------------------

def cmd_validate_spec(_args) -> int:
    problems = []
    spec = build_spec()

    if not FROZEN_SPEC.exists():
        problems.append("spec-frozen.json missing — freeze the spec first")
    else:
        frozen = json.loads(FROZEN_SPEC.read_text())
        if frozen != spec:
            problems.append("spec drifted from its frozen copy")
    if not FROZEN_CAL.exists():
        problems.append("calibration-frozen.json missing")
    else:
        cal = json.loads(FROZEN_CAL.read_text())
        cap = spec["endpoints"]["capture"]["bar"]
        if cal["capture"]["capture_min"] != cap["capture_min"] or \
                cal["capture"]["pass_threshold_count"] != cap["pass_count"]:
            problems.append("capture bar does not match calibration")
        if cal["burden"]["burden_max"] != \
                spec["endpoints"]["confirmation_burden"]["bar"]["burden_max"]:
            problems.append("burden bar does not match calibration")
        if cal["use"]["n_per_arm_per_world"] != \
                spec["endpoints"]["use"]["n_per_arm_per_world"]:
            problems.append("use n does not match calibration")

    if spec["fixture_digest"] != fixture_digest():
        problems.append("fixture digest drifted")

    split = split_fixtures()
    cal_fids = {f["fid"] for f in split["calibration"]}
    held_fids = {f["fid"] for f in split["heldout"]}
    if cal_fids & held_fids:
        problems.append("split overlaps")
    if spec["split"]["heldout"] != sorted(held_fids):
        problems.append("held-out split drifted from spec")
    cal_corpus = scoring.normalize(" ".join(
        m["text"] for f in split["calibration"] for m in f["messages"]))
    for f in split["heldout"]:
        for p in f["planted"]:
            if p["label"] == "must_capture" and all(
                    scoring.normalize(t) in cal_corpus for t in p["match"]):
                problems.append(f"held-out wording leaked: {p['pid']}")

    use = use_fixtures()
    if len(use) != 4 or {f["shape"] for f in use} != set(USE_SHAPES):
        problems.append("use worlds are not 2 shapes x 2 projects")
    if len({f["project"] for f in use}) < 2:
        problems.append("use worlds span fewer than 2 projects")
    for f in use:
        plant = next(p for p in f["planted"] if p["label"] == "must_capture")
        try:
            worlds.ack_message(f, plant)
        except ValueError as e:
            problems.append(str(e))
        for term in plant["match"]:
            if scoring.normalize(term) in scoring.normalize(worlds.TASK_HINT):
                problems.append(f"task hint overlaps loop wording: {term!r}")

    # crossed construction: identical bytes except the single operator act
    base = _fresh(WORLDS_DIR / "validate")
    fx = use[0]
    a = worlds.build_use_world(base / "a", fx, with_loop=True)
    b = worlds.build_use_world(base / "b", fx, with_loop=False)

    def stream(home):
        with contextd_home(home):
            from contextd.db import connect
            conn = connect()
            rows = conn.execute(
                "SELECT source, kind, content FROM events "
                "WHERE kind != 'egress' ORDER BY id").fetchall()
            conn.close()
        return [(r["source"], r["kind"], r["content"]) for r in rows]

    sa, sb = stream(a["home"]), stream(b["home"])
    only_a = [r for r in sa if r not in sb]
    if [r for r in sb if r not in sa]:
        problems.append("without-arm has events the with-arm lacks")
    if len(only_a) != 1 or only_a[0][1] != "loop":
        problems.append(f"arms differ by more than the loop add: {only_a!r}")

    # no post-cutoff leakage: every bracketed id resolves at or before tip
    pkg = worlds.compile_use_package(a)
    from contextd.gate import ANCHOR_RX
    bad = [int(m) for m in ANCHOR_RX.findall(pkg["package"])
           if int(m) > pkg["tip"]]
    if bad:
        problems.append(f"package cites post-tip ids: {bad}")
    shutil.rmtree(base, ignore_errors=True)

    # prereg consistency, once one exists
    conn = live_conn()
    rows = conn.execute(
        "SELECT id, meta FROM events WHERE kind='experiment' "
        "ORDER BY id DESC").fetchall()
    prereg = None
    for r in rows:
        m = json.loads(r["meta"] or "{}")
        if m.get("family") == "open_loops":
            prereg = (r["id"], m)
            break
    if prereg:
        pid, m = prereg
        if m.get("spec_sha") != spec_sha():
            problems.append(f"spec sha differs from prereg #{pid}")
        if m.get("prompt_sha") != prompt_sha():
            problems.append(f"generator prompt differs from prereg #{pid}")
        print(f"prereg found: live event #{pid} (hashes checked)")
    else:
        print("prereg: not yet recorded")

    for p in problems:
        print(f"  FAIL  {p}")
    print("validate-spec:", "OK" if not problems else "FAILED")
    return 0 if not problems else 1


# --------------------------------------------------------------------------
# probe / prereg
# --------------------------------------------------------------------------

def cmd_probe(_args) -> int:
    """One tiny model run against a scratch archive: proves claude -p can
    list and call loop_candidate through --strict-mcp-config before the
    design is locked. Read-only with respect to the live archive."""
    base = _fresh(WORLDS_DIR / "probe")
    fx = split_fixtures()["calibration"][0]
    worlds.build_dialogue_world(base / "arch", fx)
    from experiments.open_loops.scan_lib import run_scan
    out = run_scan(base / "arch", repo="/synthetic/probe",
                   session=fx["fid"], model=RESUME_MODEL)
    print(json.dumps({k: out[k] for k in
                      ("dispatch_status", "candidates", "exit")}, indent=2))
    ok = out["dispatch_status"] == "succeeded"
    print("probe:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def cmd_prereg(_args) -> int:
    if not FROZEN_SPEC.exists():
        sys.exit("freeze the spec first (python -m experiments.open_loops.spec)")
    if prompt_sha() in ("absent", "missing-PROMPT"):
        sys.exit("hooks/loop_scan.py PROMPT missing — write the generator "
                 "before preregistering")
    spec = build_spec()
    use = use_fixtures()
    meta = {
        "task_id": "open-loops-v1",
        "spec_sha": spec_sha(),
        "prompt_sha": prompt_sha(),
        "fixture_digest": spec["fixture_digest"],
        "use_fixtures": [f["fid"] for f in use],
        "capture_fixtures": spec["split"]["heldout"],
        "resume_model": RESUME_MODEL,
        "generator_model": RESUME_MODEL,
        "n_use_per_arm_per_world":
            spec["endpoints"]["use"]["n_per_arm_per_world"],
        "bars": {"capture": spec["endpoints"]["capture"]["bar"],
                 "burden":
                     spec["endpoints"]["confirmation_burden"]["bar"],
                 "false_promotion": 0, "use_p": 0.05},
        "verdict_rule": spec["verdict_rule"],
        "registered": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
    }
    exp_id = record("experiment", meta)
    print(f"preregistered open-loops evaluation as live event #{exp_id}")
    print(f"  spec sha    {meta['spec_sha'][:16]}")
    print(f"  prompt sha  {meta['prompt_sha'][:16]}")
    print(f"  use worlds  {meta['use_fixtures']}")
    return 0


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------

def _load_prereg(exp_id: int) -> dict:
    conn = live_conn()
    row = conn.execute(
        "SELECT meta FROM events WHERE id=? AND kind='experiment'",
        (exp_id,)).fetchone()
    if not row:
        sys.exit(f"no experiment event #{exp_id}")
    meta = json.loads(row["meta"])
    if meta.get("family") != "open_loops":
        sys.exit(f"event #{exp_id} is not an open_loops preregistration")
    if meta["spec_sha"] != spec_sha():
        sys.exit("spec changed since preregistration — the run is void")
    if meta["prompt_sha"] != prompt_sha():
        sys.exit("generator prompt changed since preregistration — void")
    return meta


def cmd_run(args) -> int:
    prereg = _load_prereg(args.exp_id)
    outdir = RESULTS / f"open-loops-exp{args.exp_id}"
    outdir.mkdir(parents=True, exist_ok=True)
    split = split_fixtures()
    held = split["heldout"]
    from experiments.open_loops.scan_lib import run_scan

    # ---- capture endpoint -------------------------------------------------
    print(f"[capture] {len(held)} held-out worlds, one scan each")
    candidates_by_fid: dict = {}
    world_loops: dict = {}
    for f in held:
        wdir = _fresh(WORLDS_DIR / f"cap-{f['fid']}")
        worlds.build_dialogue_world(wdir, f)
        repo = worlds.PROJECTS[f["project"]]["repo"]
        out = run_scan(wdir, repo=repo, session=f["fid"],
                       model=prereg["generator_model"])
        reduced = worlds.reduce_world_loops(wdir)
        candidates_by_fid[f["fid"]] = [lp["text"] for lp in reduced
                                       if lp["created_authority"] == "model"]
        world_loops[f["fid"]] = reduced
        row = {"exp_id": args.exp_id, "endpoint": "capture", "fid": f["fid"],
               "dispatch_status": out["dispatch_status"],
               "exit": out["exit"], "duration_ms": out["duration_ms"],
               "candidates": candidates_by_fid[f["fid"]],
               "n_loop_events": len(reduced),
               "loops_summary": reduced,
               "scan_egress_in_world": out.get("egress_id")}
        record("exp_run", row)
        (outdir / f"capture-{f['fid']}.json").write_text(
            json.dumps({**row, "loops": reduced, "raw": out}, indent=2))
        print(f"  {f['fid']}: {out['dispatch_status']}, "
              f"{len(candidates_by_fid[f['fid']])} candidate(s)")

    # ---- use endpoint -----------------------------------------------------
    n = prereg["n_use_per_arm_per_world"]
    use = [f for f in ALL_FIXTURES if f["fid"] in prereg["use_fixtures"]]
    print(f"[use] {len(use)} worlds x 2 arms x {n}")
    use_rows = []
    for f in use:
        plant = next(p for p in f["planted"] if p["label"] == "must_capture")
        blurb = worlds.PROJECTS[f["project"]]["blurb"]
        for arm, with_loop in (("with_loop", True), ("without_loop", False)):
            wdir = _fresh(WORLDS_DIR / f"use-{f['fid']}-{arm}")
            world = worlds.build_use_world(wdir, f, with_loop)
            pkg = worlds.compile_use_package(world)
            problems = worlds.verify_use_contrast(world, pkg["package"],
                                                  with_loop)
            if problems:
                sys.exit(f"INVALID TRIAL {f['fid']}/{arm}: {problems}")
            (outdir / f"use-{f['fid']}-{arm}-context.txt").write_text(
                pkg["package"])
            prompt = TASK_TEMPLATE.format(
                blurb=blurb,
                context_block="=== PROJECT MEMORY (contextd checkpoint) ===\n"
                              + pkg["package"])
            for i in range(n):
                r = run_claude(prompt, prereg["resume_model"])
                hit = scoring.covers(r["text"], plant)
                row = {"exp_id": args.exp_id, "endpoint": "use",
                       "fid": f["fid"], "arm": arm, "run": i,
                       "hit": int(hit), "exit": r["exit"],
                       "dispatch_status": r["dispatch_status"],
                       "duration_ms": r["duration_ms"],
                       "output": r["text"][:20000]}
                record("exp_run", row)
                use_rows.append(row)
                (outdir / f"use-{f['fid']}-{arm}-{i}.md").write_text(
                    f"# use / {f['fid']} / {arm} / {i}\nhit {hit}\n\n"
                    f"{r['text']}\n")
                print(f"  {f['fid']}/{arm}#{i}: hit={int(hit)} "
                      f"({r['dispatch_status']})")

    report = build_report(args.exp_id)
    rep_id = record("exp_report", report)
    (outdir / "report.json").write_text(json.dumps(report, indent=2))
    print(f"\nreport -> live event #{rep_id}; rebuild with: "
          f"bench.py report {args.exp_id}")
    print_report(report)
    return 0


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------

def build_report(exp_id: int) -> dict:
    prereg = _load_prereg(exp_id)
    conn = live_conn()
    rows = []
    for r in conn.execute(
            "SELECT id, meta FROM events WHERE kind='exp_run' ORDER BY id"):
        m = json.loads(r["meta"] or "{}")
        if m.get("family") == "open_loops" and m.get("exp_id") == exp_id:
            rows.append(m)
    cap_rows = [m for m in rows if m.get("endpoint") == "capture"]
    use_rows = [m for m in rows if m.get("endpoint") == "use"]

    split = split_fixtures()
    held = split["heldout"]
    by_fid = {m["fid"]: m for m in cap_rows}
    candidates_by_fid = {fid: m.get("candidates", [])
                         for fid, m in by_fid.items()}
    capture = scoring.score_capture(held, candidates_by_fid)

    # false promotion, recomputed from evidence — never vacuously passed.
    # Ledger loops_summary is the durable source; older rows fall back to
    # the raw artifact file; a fid with neither is an explicit evidence gap
    # that fails the endpoint rather than certifying it.
    outdir = RESULTS / f"open-loops-exp{exp_id}"

    def loop_evidence(fid):
        row = by_fid.get(fid)
        if row and "loops_summary" in row:
            return row["loops_summary"]
        art = outdir / f"capture-{fid}.json"
        if art.exists():
            return json.loads(art.read_text())["loops"]
        return None

    fp_records, evidence_missing = [], []
    for fid in by_fid:
        recs = loop_evidence(fid)
        if recs is None:
            evidence_missing.append(fid)
        else:
            fp_records.extend(recs)
    fp = scoring.score_false_promotion(fp_records)
    if evidence_missing:
        fp = {"count": None, "pass": False,
              "violations": [{"loop": None,
                              "why": f"no evidence for {evidence_missing}"}]}

    pair = [f for f in ALL_FIXTURES if f["shape"] == "identical_pair"]
    pair_results = {}
    for f in pair:
        recs = loop_evidence(f["fid"])
        if recs is None:
            pair_results[f["fid"]] = {"false_promotions": 1,
                                      "asserted_certainty": True,
                                      "why": "evidence missing"}
            continue
        pair_results[f["fid"]] = {
            "false_promotions": sum(
                1 for lp in recs
                if lp["created_authority"] == "model"
                and lp["created_state"] != "candidate"),
            "asserted_certainty": any(
                lp["state"] not in ("candidate", "dismissed")
                for lp in recs if lp["created_authority"] == "model"),
        }
    pair_verdict = scoring.score_pair(pair, pair_results)

    bars = {"capture_min": prereg["bars"]["capture"]["capture_min"],
            "burden_max": prereg["bars"]["burden"]["burden_max"]}
    capture_decision = scoring.decide_capture(
        capture["capture_rate"], capture["burden_mean"],
        fp["count"] if fp["count"] is not None else 1,
        pair_verdict["pass"], bars)
    if evidence_missing:
        capture_decision = {"earned": False,
                            "reasons": capture_decision["reasons"]
                            + [f"loop evidence missing for "
                               f"{evidence_missing}"]}

    # use endpoint: stratified permutation, exactly the calibrated design
    use_worlds = prereg["use_fixtures"]
    strata_with, strata_without = [], []
    per_world = {}
    for fid in use_worlds:
        w = [m["hit"] for m in use_rows
             if m["fid"] == fid and m["arm"] == "with_loop"]
        wo = [m["hit"] for m in use_rows
              if m["fid"] == fid and m["arm"] == "without_loop"]
        strata_with.append(w)
        strata_without.append(wo)
        per_world[fid] = {"with": w, "without": wo}
    use_result = None
    if any(strata_with) and any(strata_without):
        import random as _random
        p = _stratified_perm_p(strata_with, strata_without,
                               len(use_worlds), _random.Random(0),
                               trials=20000)
        with_rate = (sum(sum(w) for w in strata_with)
                     / max(sum(len(w) for w in strata_with), 1))
        without_rate = (sum(sum(w) for w in strata_without)
                        / max(sum(len(w) for w in strata_without), 1))
        use_result = {"with_rate": round(with_rate, 4),
                      "without_rate": round(without_rate, 4),
                      "p": p, "p_bar": prereg["bars"]["use_p"],
                      "distinguishable": p <= prereg["bars"]["use_p"],
                      "per_world": per_world}

    failures = [m for m in rows if m.get("dispatch_status") not in
                ("succeeded", None)]
    verdict = "NOT EARNED"
    verdict_why = ("the real-operator capture trial has not run; "
                   "machine-side results cannot earn a capture verdict "
                   "(prereg verdict_rule)")
    return {
        "exp_id": exp_id,
        "task_id": prereg["task_id"],
        "spec_sha": prereg["spec_sha"],
        "prompt_sha": prereg["prompt_sha"],
        "fixture_digest": prereg["fixture_digest"],
        "endpoints": {
            "capture": {k: capture[k] for k in
                        ("n_must", "captured", "capture_rate",
                         "burden_mean", "distractor_hits")},
            "capture_decision": capture_decision,
            "false_promotion": {"count": fp["count"], "pass": fp["pass"],
                                "violations": fp["violations"]},
            "confirmation_burden": {
                "burden_mean": capture["burden_mean"],
                "bar": prereg["bars"]["burden"]["burden_max"],
                "pass": capture["burden_mean"]
                <= prereg["bars"]["burden"]["burden_max"]},
            "identical_pair": pair_verdict,
            "use": use_result,
            "lifecycle_correctness": "deterministic gate: pytest "
                                     "tests/test_loops.py (see repo CI)",
            "carriage": "deterministic gate: bench selftest + pytest",
            "stale_resurrection": "deterministic gate: kernel suppression "
                                  "+ checkpoint exclusion (tests)",
        },
        "dispatch_failures": [
            {k: m.get(k) for k in ("endpoint", "fid", "arm", "run",
                                   "dispatch_status")} for m in failures],
        "raw_artifacts": str(RESULTS / f"open-loops-exp{exp_id}"),
        "verdict": verdict,
        "verdict_why": verdict_why,
        "not_licensed": [
            "no capture verdict without the preregistered real-operator "
            "trial (unseen wording and timing)",
            "use results are a haiku-tier property of these four synthetic "
            "worlds; not a claim about other models or real archives",
            "capture results measure this generator prompt on synthetic "
            "dialogues; 'within noise' never means 'no effect'",
        ],
    }


def print_report(rep: dict):
    e = rep["endpoints"]
    print(f"\n=== open-loops evaluation #{rep['exp_id']} ===")
    c = e["capture"]
    print(f"capture: {c['captured']}/{c['n_must']} "
          f"({c['capture_rate']}), burden {c['burden_mean']}, "
          f"distractor hits {c['distractor_hits']}")
    print(f"capture decision: "
          f"{'EARNED (machine-side)' if e['capture_decision']['earned'] else 'not earned'}"
          + (f" — {e['capture_decision']['reasons']}"
             if e["capture_decision"]["reasons"] else ""))
    print(f"false promotion: {e['false_promotion']['count']} "
          f"(pass={e['false_promotion']['pass']})")
    print(f"identical pair: {e['identical_pair']}")
    if e["use"]:
        u = e["use"]
        print(f"use: with {u['with_rate']} vs without {u['without_rate']}, "
              f"p={u['p']} ({'distinguishable' if u['distinguishable'] else 'not distinguishable'})")
    print(f"VERDICT: {rep['verdict']} — {rep['verdict_why']}")


def cmd_report(args) -> int:
    rep = build_report(args.exp_id)
    stored = None
    conn = live_conn()
    for r in conn.execute(
            "SELECT meta FROM events WHERE kind='exp_report' ORDER BY id"):
        m = json.loads(r["meta"] or "{}")
        if m.get("family") == "open_loops" and m.get("exp_id") == args.exp_id:
            stored = m
    print_report(rep)
    print(f"\nspec sha {rep['spec_sha'][:16]}, prompt sha "
          f"{rep['prompt_sha'][:16]}, fixtures {rep['fixture_digest'][:16]}")
    print(f"raw artifacts: {rep['raw_artifacts']}")
    if rep["dispatch_failures"]:
        print(f"dispatch failures: {rep['dispatch_failures']}")
    else:
        print("dispatch failures: none")
    for line in rep["not_licensed"]:
        print(f"  not licensed: {line}")
    if stored:
        drift = {k for k in ("verdict", "spec_sha", "prompt_sha")
                 if stored.get(k) != rep.get(k)}
        print("stored report:", "matches rebuild" if not drift
              else f"DRIFT in {drift}")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    sub.add_parser("validate-spec")
    sub.add_parser("probe")
    sub.add_parser("prereg")
    r = sub.add_parser("run")
    r.add_argument("exp_id", type=int)
    rp = sub.add_parser("report")
    rp.add_argument("exp_id", type=int)
    args = p.parse_args()
    fn = {"selftest": cmd_selftest, "validate-spec": cmd_validate_spec,
          "probe": cmd_probe, "prereg": cmd_prereg, "run": cmd_run,
          "report": cmd_report}[args.cmd]
    sys.exit(fn(args))


if __name__ == "__main__":
    main()
