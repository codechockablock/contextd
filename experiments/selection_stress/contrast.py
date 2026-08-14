"""Decisions-lifecycle contrast: does the supersession contract move the
measured surface? Bars frozen in docs/DECISIONS.md before implementation;
preregistered in the dedicated experiment ledger before any contrast run.

Instrument-identity discipline: the r2 grid modules (vocab, generator,
carriage, validity, stats) are byte-identical to their frozen hashes — this
module adds the lifecycle arm WITHOUT touching them. Lifecycle worlds are
copies of the r2 baseline worlds (digest-verified at their build tip) plus
one operator supersession edge per planted pair, appended through the real
``contextd.decisions.record_supersession`` path. The arms therefore differ
by exactly the edge events (plus egress accumulated by compiles, which
selection ignores by construction).

Endpoints (docs/DECISIONS.md, in order of authority):
  1 silent resurrection (v1 carried, v2 absent, no marker, no loud line): 0
  2 unmarked superseded served: 0
  3 surface movement: baseline-scorer resurrection 0.269 -> <= 0.05,
    residue loudly named
  4 non-regression: non-super cells pooled |delta| <= 0.02, no cell > 0.2
  5 behavioral: pooled v1-as-current <= 0.3 (p <= 0.05), v2-honors >= 0.5;
    baseline arm reused from prereg #36 by ledger reference
"""

import hashlib
import json
import re
import shutil
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))

from experiments.handoff.common import run_claude  # noqa: E402
from experiments.selection_stress import behavior, spec, stats  # noqa: E402
from experiments.selection_stress.carriage import score_topic  # noqa: E402
from experiments.selection_stress.generator import contextd_home  # noqa: E402

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
WORLDS = RESULTS / "worlds"
LIFE_WORLDS = RESULTS / "worlds-lifecycle"
CONTRAST = RESULTS / "contrast"
FROZEN_CONTRAST = ROOT / "spec-contrast-frozen.json"

BARS = {
    "silent_resurrection": 0,
    "unmarked_superseded_served": 0,
    "surface_movement_max": 0.05,
    "nonreg_pooled_max": 0.02,
    "nonreg_taxed_max": 0.10,
    "behavior_resurrects_max": 0.3,
    "behavior_p_max": 0.05,
    "behavior_v2_honors_min": 0.5,
}


def _sha_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_contrast_spec() -> dict:
    baseline_meta = json.loads((RESULTS / "grid" / "meta.json").read_text())
    behavior_doc = json.loads(behavior.FROZEN_BEHAVIOR.read_text())
    super_cells = [{"cell_index": i, **c}
                   for i, c in enumerate(behavior_doc["cells"])
                   if c["kind"] == "super"]
    return {
        "benchmark": "decisions-lifecycle-contrast-v1",
        "frozen": "2026-08-14",
        "contract_sha": _sha_file(REPO / "docs" / "DECISIONS.md"),
        "baseline_spec_sha": spec.spec_sha(),
        "baseline_grid_digests": baseline_meta["digests"],
        "kernel": {
            "decisions_sha": _sha_file(REPO / "contextd" / "decisions.py"),
            "handoff_sha": _sha_file(REPO / "contextd" / "handoff.py"),
        },
        "harness": {"contrast_sha": _sha_file(ROOT / "contrast.py"),
                    "behavior_sha": _sha_file(ROOT / "behavior.py")},
        "arms": {
            "baseline": "r2 worlds as stored (results/worlds), rescored "
                        "under the new kernel as a regression check "
                        "against the stored r2 rows",
            "lifecycle": "digest-verified copies + one operator edge per "
                         "planted supersession pair via "
                         "record_supersession (client sim-operator)",
        },
        "bars": BARS,
        "behavioral": {
            "cells": [{"cell_index": c["cell_index"], "tier": c["tier"],
                       "topic": c["topic"]} for c in super_cells],
            "n_per_cell": behavior.N_PER_ARM,
            "model": "haiku",
            "baseline_arm": "prereg #36 as-compiled supersession runs, "
                            "reused by ledger reference (identical "
                            "archives, model, rubric, protocol)",
            "planned_dispatches": behavior.N_PER_ARM * len(super_cells),
        },
        "stats": {"perm": "exact per cell (8v8), stratified-mc pooled",
                  "bootstrap": "seed-cluster, as r2"},
    }


def contrast_sha(doc: dict | None = None) -> str:
    return hashlib.sha256(json.dumps(doc or build_contrast_spec(),
                                     sort_keys=True).encode()).hexdigest()


# --- lifecycle worlds -------------------------------------------------------

def _verify_build_digest(home: Path, manifest: dict) -> None:
    import sqlite3
    conn = sqlite3.connect(f"file:{home / 'contextd.db'}?mode=ro", uri=True)
    row = conn.execute("SELECT chain_hash FROM events WHERE id = ?",
                       (manifest["n_events"],)).fetchone()
    conn.close()
    if row is None or row[0] != manifest["digest"]:
        raise RuntimeError(f"{home}: build-tip digest mismatch — baseline "
                           f"world does not match its manifest")


def build_lifecycle_worlds() -> list[dict]:
    out = []
    for src in sorted(WORLDS.iterdir()):
        manifest = json.loads((src / "manifest.json").read_text())
        home = src / "home"
        _verify_build_digest(home, manifest)
        dst = LIFE_WORLDS / src.name
        if dst.exists():
            shutil.rmtree(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, dst)
        edges = {}
        with contextd_home(dst / "home"):
            from contextd.db import _db_tip, connect
            from contextd.decisions import record_supersession
            conn = connect()
            for tp in manifest["topics"]:
                if tp["distractor"] == "super" and tp.get("v2"):
                    r = record_supersession(
                        conn, tp["plant"]["event_id"], tp["v2"]["event_id"],
                        reason="operator supersession (simulated)",
                        client="sim-operator")
                    edges[str(tp["topic"])] = r["edge"]["edge"]
            tip = _db_tip(conn)
            conn.close()
        manifest["edges"] = edges
        manifest["lifecycle_digest"] = tip["chain_hash"]
        manifest["home"] = str(dst / "home")
        (dst / "manifest.json").write_text(
            json.dumps(manifest, indent=1, sort_keys=True) + "\n")
        out.append({"world": src.name, "edges": len(edges),
                    "digest": tip["chain_hash"][:12]})
        print(f"lifecycle {src.name}: {len(edges)} edges, "
              f"tip {tip['chain_hash'][:12]}")
    return out


# --- contract-aware scoring -------------------------------------------------

def _v1_block(package: str, v1: int) -> str:
    """The item's own block, anchored on its HEADER form `--- [id]`.
    Round 1 split on the first bare `[id]` occurrence and landed inside
    other episode notes' anchor citations (4 false unmarked-served rows);
    the kernel was verified compliant on every flagged row."""
    parts = package.split(f"--- [{v1}]")
    return parts[1].split("\n\n")[0] if len(parts) > 1 else ""


def _compile(home: str, hint: str, budget: int) -> dict:
    """Contrast's own compile wrapper (r2's carriage.compile_for_topic is
    hash-frozen and cannot expose the reserve flag). Same real pipeline."""
    with contextd_home(home):
        from contextd import load_config
        from contextd.db import connect
        from contextd.handoff import compile_checkpoint
        conn = connect()
        t0 = time.perf_counter()
        out = compile_checkpoint(conn, load_config(), budget=budget,
                                 task_hint=hint,
                                 client="decisions-lifecycle-contrast")
        latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        conn.close()
    sel = out["selection"]
    keys = ("tail", "episodes", "notes", "recall", "loops", "supersessions")
    sections = {k: {it["id"] for it in sel.get(k) or [] if it["id"] is not None}
                for k in keys}
    return {"package": out["package"], "items": set(out["items"]),
            "egress_id": out["egress_id"], "est_tokens": out["est_tokens"],
            "sections": sections, "latency_ms": latency_ms,
            "reserve_engaged":
                bool(sel.get("supersession_reserve_engaged"))}


def contract_fields(topic: dict, compiled: dict) -> dict:
    """The DECISIONS.md contract checks, computed mechanically per super
    topic against one compiled package."""
    if topic["distractor"] != "super" or not topic.get("v2"):
        return {}
    v1 = topic["plant"]["event_id"]
    v2 = topic["v2"]["event_id"]
    pkg = compiled["package"]
    v1_carried = v1 in compiled["items"]
    v2_carried = v2 in compiled["items"]
    marker = bool(re.search(r"SUPERSEDED by ev \d+", _v1_block(pkg, v1)))
    loud = f"SUPERSESSION OMITTED: current version ev {v2}" in pkg
    return {
        "v1_carried": v1_carried, "v2_carried": v2_carried,
        "marker_on_v1": marker, "loud_omission": loud,
        "unmarked_superseded_served": v1_carried and not marker,
        "silent_resurrection": (v1_carried and not v2_carried
                                and not marker and not loud),
        "marked_but_unnamed": (v1_carried and not v2_carried
                               and marker and not loud),
        "baseline_resurrected": v1_carried and not v2_carried,
    }


def grid_rows(worlds_dir: Path, arm: str) -> list[dict]:
    """Same walk as the r2 grid (all topics x budgets + no-hint), with the
    contract fields added; r2 modules are reused, never modified."""
    budgets = spec.GRID_SPEC["budgets"]
    rows = []
    for src in sorted(worlds_dir.iterdir()):
        manifest = json.loads((src / "manifest.json").read_text())
        home = manifest.get("home") or str(src / "home")
        base = {"arm": arm, "tier": manifest["tier"],
                "seed": manifest["seed"]}
        for budget in budgets:
            for tp in manifest["topics"]:
                compiled = _compile(home, tp["hint"], budget)
                rows.append({**base, "budget": budget, "hinted": True,
                             "topic": tp["topic"], "stratum": tp["stratum"],
                             "age": tp["age"], "band": tp["band"],
                             "distractor": tp["distractor"],
                             "scope": tp["scope"],
                             "latency_ms": compiled["latency_ms"],
                             "reserve_engaged": compiled["reserve_engaged"],
                             **score_topic(tp, compiled),
                             **contract_fields(tp, compiled)})
            compiled = _compile(home, "", budget)
            for tp in manifest["topics"]:
                rows.append({**base, "budget": budget, "hinted": False,
                             "topic": tp["topic"], "stratum": tp["stratum"],
                             "age": tp["age"], "band": tp["band"],
                             "distractor": tp["distractor"],
                             "scope": tp["scope"],
                             "latency_ms": compiled["latency_ms"],
                             "reserve_engaged": compiled["reserve_engaged"],
                             **score_topic(tp, compiled),
                             **contract_fields(tp, compiled)})
        print(f"{arm} grid {src.name}: done")
    return rows


def _write_rows(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")


def _read_rows(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text().splitlines()]


# --- kernel regression check ------------------------------------------------

COMPARE_FIELDS = ("carried", "silently_absent", "omitted_named", "via",
                  "stale_resurrected", "v2_carried", "decoys_carried",
                  "twin_carried", "payload_in_text")


def kernel_regression(baseline_rows: list[dict]) -> dict:
    """The new kernel on edge-less archives must reproduce the stored r2
    rows exactly on every scoring field (latency and receipts excepted)."""
    stored = _read_rows(RESULTS / "grid" / "rows.jsonl")
    key = ("tier", "seed", "budget", "hinted", "topic")
    stored_by = {tuple(r[k] for k in key): r for r in stored}
    mismatches = []
    for r in baseline_rows:
        s = stored_by.get(tuple(r[k] for k in key))
        if s is None:
            mismatches.append({"row": {k: r[k] for k in key},
                               "why": "no stored counterpart"})
            continue
        for f in COMPARE_FIELDS:
            if r.get(f) != s.get(f):
                mismatches.append({"row": {k: r[k] for k in key},
                                   "field": f, "stored": s.get(f),
                                   "rerun": r.get(f)})
    return {"rows": len(baseline_rows), "mismatches": mismatches[:50],
            "n_mismatches": len(mismatches)}


# --- analysis ---------------------------------------------------------------

def _rate(rows, field):
    n = len(rows)
    k = sum(1 for r in rows if r.get(field))
    return {"rate": round(k / n, 4) if n else None, "k": k, "n": n}


def analyze(baseline_rows: list[dict], lifecycle_rows: list[dict]) -> dict:
    d = spec.GRID_SPEC["default_budget"]

    def supers(rows):
        return [r for r in rows if r["distractor"] == "super"
                and r["scope"] == "task" and r["hinted"]
                and r["budget"] == d]

    def nonsuper(rows):
        return [r for r in rows if r["distractor"] != "super"
                and r["scope"] == "task" and r["hinted"]
                and r["budget"] == d]

    lsup, bsup = supers(lifecycle_rows), supers(baseline_rows)
    silent = _rate(lsup, "silent_resurrection")
    unmarked = _rate(lsup, "unmarked_superseded_served")
    unnamed = _rate(lsup, "marked_but_unnamed")
    base_res = _rate(bsup, "stale_resurrected")
    life_res = _rate(lsup, "baseline_resurrected")
    seeds = sorted({r["seed"] for r in lsup})
    life_by_seed = [
        sum(1 for r in lsup if r["seed"] == s and r["baseline_resurrected"])
        / max(1, sum(1 for r in lsup if r["seed"] == s)) for s in seeds]
    boot = stats.bootstrap_ci(life_by_seed)

    bn, ln = nonsuper(baseline_rows), nonsuper(lifecycle_rows)
    pooled_delta = abs(_rate(ln, "carried")["rate"]
                       - _rate(bn, "carried")["rate"])
    # row-paired comparison: identical coordinates, one row per arm
    pair_key = ("tier", "seed", "topic")
    b_by = {tuple(r[k] for k in pair_key): r for r in bn}
    unpaid_losses = []
    taxed_pairs, untaxed_worst = [], 0.0
    untaxed_worst_cell = None
    cell_key = ("tier", "stratum", "age", "band", "distractor")
    cells: dict = {}
    for r in ln:
        b = b_by.get(tuple(r[k] for k in pair_key))
        if b is None:
            continue
        if r["reserve_engaged"]:
            taxed_pairs.append((b["carried"], r["carried"]))
        else:
            if b["carried"] and not r["carried"]:
                unpaid_losses.append({k: r[k] for k in pair_key})
            k = tuple(r[k_] for k_ in cell_key)
            cells.setdefault(k, []).append(
                (1 if r["carried"] else 0) - (1 if b["carried"] else 0))
    for k, deltas in cells.items():
        d = abs(sum(deltas) / len(deltas))
        if d > untaxed_worst:
            untaxed_worst, untaxed_worst_cell = d, k
    taxed_delta = (abs(sum(r for _, r in taxed_pairs) / len(taxed_pairs)
                       - sum(b for b, _ in taxed_pairs) / len(taxed_pairs))
                   if taxed_pairs else 0.0)
    v2_given_v1 = _rate([r for r in lsup if r["v1_carried"]], "v2_carried")

    return {
        "endpoint1_silent_resurrection": silent,
        "endpoint2_unmarked_served": unmarked,
        "marked_but_unnamed": unnamed,
        "endpoint3_surface": {"baseline": base_res, "lifecycle": life_res,
                              "lifecycle_seed_bootstrap": boot},
        "endpoint4_nonregression": {
            "pooled_delta": round(pooled_delta, 4),
            "unpaid_losses": unpaid_losses[:20],
            "n_unpaid_losses": len(unpaid_losses),
            "untaxed_worst_cell_delta": round(untaxed_worst, 4),
            "untaxed_worst_cell": untaxed_worst_cell,
            "taxed_pairs": len(taxed_pairs),
            "taxed_pooled_delta": round(taxed_delta, 4)},
        "v2_carried_given_v1_carried": v2_given_v1,
        "loud_omissions": _rate(lsup, "loud_omission"),
        "bars": BARS,
        "bar_results": {
            "1_silent": silent["k"] == BARS["silent_resurrection"],
            "2_unmarked": unmarked["k"] == BARS["unmarked_superseded_served"],
            "3_surface": (life_res["rate"] is not None
                          and life_res["rate"]
                          <= BARS["surface_movement_max"]
                          and silent["k"] == 0),
            "4a_pooled": pooled_delta <= BARS["nonreg_pooled_max"],
            "4b_unpaid": len(unpaid_losses) == 0,
            "4c_taxed": taxed_delta <= BARS["nonreg_taxed_max"],
        },
    }


# --- behavioral confirmation ------------------------------------------------

def behavioral_baseline_runs(doc: dict) -> dict:
    """Prereg #36's as-compiled supersession runs, from durable records."""
    runs = [json.loads(x) for x in
            (RESULTS / "behavior" / "runs.jsonl").read_text().splitlines()]
    out = {}
    for c in doc["behavioral"]["cells"]:
        ci = c["cell_index"]
        rows = [r for r in runs if r["cell_index"] == ci
                and r["arm"] == "as_compiled"
                and r["dispatch_status"] == "succeeded"]
        out[ci] = rows
    return out


def run_behavioral(prereg_id: int, doc: dict) -> int:
    behavior_doc = json.loads(behavior.FROZEN_BEHAVIOR.read_text())
    runs_path = CONTRAST / "behavior-runs.jsonl"
    runs_path.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if runs_path.exists():
        for x in runs_path.read_text().splitlines():
            r = json.loads(x)
            done.add((r["cell_index"], r["run"]))
    tdir = CONTRAST / "transcripts"
    tdir.mkdir(parents=True, exist_ok=True)
    with runs_path.open("a") as fh:
        for c in doc["behavioral"]["cells"]:
            cell = {"cell_index": c["cell_index"],
                    **behavior_doc["cells"][c["cell_index"]]}
            home = (LIFE_WORLDS / f"{cell['tier']}-s{cell['seed']}" / "home")
            for i in range(doc["behavioral"]["n_per_cell"]):
                if (cell["cell_index"], i) in done:
                    continue
                if behavior.dispatches_used() >= behavior.DISPATCH_CEILING:
                    print("STOP: dispatch ceiling reached")
                    return 5
                with contextd_home(home):
                    from contextd import load_config
                    from contextd.db import connect
                    from contextd.handoff import compile_checkpoint
                    conn = connect()
                    out = compile_checkpoint(
                        conn, load_config(), budget=behavior_doc["budget"],
                        task_hint=cell["hint"],
                        client="decisions-lifecycle-contrast",
                        purpose=f"contrast cell c{cell['cell_index']} "
                                f"run {i}")
                    conn.close()
                prompt = behavior.TASK_TEMPLATE.format(
                    comp=cell["comp"], obj=cell["obj"],
                    package=out["package"])
                t0 = time.time()
                res = run_claude(prompt, doc["behavioral"]["model"],
                                 timeout=300)
                status = res["dispatch_status"]
                behavior.record_outcome(
                    str(home), out["egress_id"],
                    status if status in ("succeeded", "failed", "timeout")
                    else "failed",
                    run=f"contrast/c{cell['cell_index']}/{i}")
                score = behavior.score_output(res["text"], cell)
                row = {"cell_index": cell["cell_index"], "arm": "lifecycle",
                       "run": i, "status": status,
                       "egress_id": out["egress_id"],
                       "wall_s": round(time.time() - t0, 1),
                       "output_sha": hashlib.sha256(
                           res["text"].encode()).hexdigest(), **score}
                (tdir / f"c{cell['cell_index']}-r{i}.txt").write_text(
                    res["text"])
                fh.write(json.dumps(row, sort_keys=True) + "\n")
                fh.flush()
                behavior.record("behavior_run",
                                {"prereg": prereg_id, "contrast": True,
                                 **row})
                print(f"contrast c{cell['cell_index']} r{i}: {status} "
                      f"honors={score.get('honors')} "
                      f"resurrects={score.get('resurrects')}")
    return 0


def behavioral_results(doc: dict) -> dict:
    base = behavioral_baseline_runs(doc)
    life_rows = [json.loads(x) for x in
                 (CONTRAST / "behavior-runs.jsonl").read_text().splitlines()
                 if json.loads(x)["status"] == "succeeded"]
    cells_out, strat = [], []
    for c in doc["behavioral"]["cells"]:
        ci = c["cell_index"]
        b = base[ci]
        lf = [r for r in life_rows if r["cell_index"] == ci]
        b_res = [1.0 if r["resurrects"] else 0.0 for r in b]
        l_res = [1.0 if r["resurrects"] else 0.0 for r in lf]
        b_hon = [1.0 if r["honors"] else 0.0 for r in b]
        l_hon = [1.0 if r["honors"] else 0.0 for r in lf]
        perm = stats.perm_test(l_res, b_res) if b_res and l_res else None
        cells_out.append({
            "cell_index": ci, "n_baseline": len(b), "n_lifecycle": len(lf),
            "baseline_resurrects": round(sum(b_res) / len(b_res), 4),
            "lifecycle_resurrects": round(sum(l_res) / len(l_res), 4)
            if l_res else None,
            "baseline_honors": round(sum(b_hon) / len(b_hon), 4),
            "lifecycle_honors": round(sum(l_hon) / len(l_hon), 4)
            if l_hon else None,
            "perm_resurrects": perm})
        strat.append({"a": l_res, "b": b_res})
    pooled = stats.stratified_perm_test(strat)
    n_l = sum(c["n_lifecycle"] for c in cells_out)
    pooled_res = (sum(c["lifecycle_resurrects"] * c["n_lifecycle"]
                      for c in cells_out) / n_l) if n_l else None
    pooled_hon = (sum(c["lifecycle_honors"] * c["n_lifecycle"]
                      for c in cells_out) / n_l) if n_l else None
    return {"cells": cells_out, "pooled_perm": pooled,
            "pooled_lifecycle_resurrects": round(pooled_res, 4)
            if pooled_res is not None else None,
            "pooled_lifecycle_honors": round(pooled_hon, 4)
            if pooled_hon is not None else None,
            "bar_results": {
                "5_resurrects": (pooled_res is not None and pooled_res
                                 <= BARS["behavior_resurrects_max"]
                                 and pooled["p"] is not None
                                 and pooled["p"] <= BARS["behavior_p_max"]),
                "5_honors": (pooled_hon is not None and pooled_hon
                             >= BARS["behavior_v2_honors_min"]),
            }}


# --- commands ---------------------------------------------------------------

def cmd_contrast_prereg(_args) -> int:
    doc = build_contrast_spec()
    sha = contrast_sha(doc)
    if FROZEN_CONTRAST.exists():
        stored = json.loads(FROZEN_CONTRAST.read_text())
        if stored != doc:
            print("REFUSED: contrast spec drifted from frozen copy")
            return 1
    else:
        FROZEN_CONTRAST.write_text(
            json.dumps(doc, indent=1, sort_keys=True) + "\n")
    eid = behavior.record("experiment", {
        "type": "contrast_prereg", "benchmark": doc["benchmark"],
        "contrast_sha": sha, "contract_sha": doc["contract_sha"],
        "baseline_spec_sha": doc["baseline_spec_sha"], "bars": doc["bars"],
        "planned_dispatches": doc["behavioral"]["planned_dispatches"]})
    print(f"contrast preregistered as ledger event #{eid} (sha {sha})")
    return 0


def _check_prereg(prereg_id: int) -> dict:
    conn = behavior.ledger_conn()
    row = conn.execute("SELECT meta FROM events WHERE id = ?",
                       (prereg_id,)).fetchone()
    conn.close()
    meta = json.loads(row["meta"]) if row and row["meta"] else {}
    if meta.get("type") != "contrast_prereg":
        raise SystemExit(f"event #{prereg_id} is not a contrast prereg")
    doc = json.loads(FROZEN_CONTRAST.read_text())
    if contrast_sha(doc) != meta["contrast_sha"]:
        raise SystemExit("frozen contrast spec does not match prereg sha")
    live = build_contrast_spec()
    if contrast_sha(live) != meta["contrast_sha"]:
        raise SystemExit("live instrument drifted from the preregistered "
                         "spec (module or contract hash changed after "
                         "prereg) — contrast void")
    return doc


def cmd_contrast_run(args) -> int:
    _check_prereg(args.prereg_id)
    chk = spec.check_frozen()
    if not chk["ok"]:
        print(f"REFUSED: r2 grid spec drifted: {chk['why']}")
        return 1
    baseline_rows = grid_rows(WORLDS, "baseline")
    _write_rows(baseline_rows, CONTRAST / "baseline-rows.jsonl")
    reg = kernel_regression(baseline_rows)
    (CONTRAST / "kernel-regression.json").write_text(
        json.dumps(reg, indent=1, sort_keys=True) + "\n")
    print(f"kernel regression: {reg['n_mismatches']} mismatches over "
          f"{reg['rows']} rows")
    if reg["n_mismatches"]:
        print("REFUSED: new kernel does not reproduce stored r2 rows on "
              "edge-less archives — contrast void, fix first")
        return 1
    build_lifecycle_worlds()
    lifecycle_rows = grid_rows(LIFE_WORLDS, "lifecycle")
    _write_rows(lifecycle_rows, CONTRAST / "lifecycle-rows.jsonl")
    analysis = analyze(baseline_rows, lifecycle_rows)
    (CONTRAST / "analysis.json").write_text(
        json.dumps(analysis, indent=1, sort_keys=True) + "\n")
    for k, v in analysis["bar_results"].items():
        print(f"bar {k}: {'MET' if v else 'NOT MET'}")
    print(json.dumps({k: analysis[k] for k in
                      ("endpoint1_silent_resurrection",
                       "endpoint2_unmarked_served", "endpoint3_surface",
                       "endpoint4_nonregression")}, indent=1))
    return 0


def cmd_contrast_behavior(args) -> int:
    doc = _check_prereg(args.prereg_id)
    rc = run_behavioral(args.prereg_id, doc)
    if rc:
        return rc
    res = behavioral_results(doc)
    (CONTRAST / "behavior-results.json").write_text(
        json.dumps(res, indent=1, sort_keys=True) + "\n")
    print(json.dumps(res["bar_results"], indent=1))
    print(f"dispatches used {behavior.dispatches_used()}"
          f"/{behavior.DISPATCH_CEILING}")
    return 0
