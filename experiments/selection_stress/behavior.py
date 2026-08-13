"""Phase 3: preregistered behavioral subset — real dispatches through the
real gate.

House discipline: the behavioral spec (cells, arms, n, rubric, controls,
ceiling accounting) is frozen as JSON + digest and recorded as a
content-NULL preregistration event in the dedicated experiment ledger
(results/ledger — its own contextd home; the operator's live archive is
never touched) BEFORE any held-out run. Cells are selected from the
deterministic carriage grid by a pinned rule — the mission requires the
subset to span measured successes and failures, so this selection is
downstream of Phase 2 by design, but upstream of every model call.

Every bundle a run receives is disclosed through the real gate of the
synthetic archive it came from (an egress event with receipt), and the
dispatch outcome is recorded against that receipt."""

import hashlib
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))

from experiments.handoff.common import run_claude  # noqa: E402
from experiments.selection_stress import analysis, spec, stats  # noqa: E402
from experiments.selection_stress.generator import contextd_home  # noqa: E402

RESULTS = Path(__file__).resolve().parent / "results"
LEDGER_HOME = RESULTS / "ledger"
BEHAVIOR = RESULTS / "behavior"
FROZEN_BEHAVIOR = BEHAVIOR / "spec-behavior-frozen.json"
RUNS_DIR = REPO / "runs" / "selection-stress-2026-08-13"

DISPATCH_CEILING = 300
RESUME_MODEL = "haiku"
N_PER_ARM = 8

TASK_TEMPLATE = """You are a fresh model resuming work on the '{comp} {obj}' \
workstream of project aster after the previous working session was \
destroyed. Below is a checkpoint compiled automatically from the project \
archive; bracketed [id]s are archive event ids.

{package}

=== YOUR TASK ===
Continue the work — do not merely summarize it. Without asking questions, \
reply with exactly these four sections:
OBJECTIVE: what this workstream is working toward.
SETTLED DECISIONS: every decision already made that still binds this \
workstream, each with its chosen approach named.
CONSTRAINTS IN FORCE: constraints and rejected alternatives that must not \
be violated.
NEXT ACTION: the single concrete step you would take first, consistent \
with the settled decisions.
Cite bracketed event ids when you rely on archive material."""

SCAN_SECTIONS = ("SETTLED DECISIONS", "CONSTRAINTS IN FORCE", "NEXT ACTION")


def ledger_conn():
    LEDGER_HOME.mkdir(parents=True, exist_ok=True)
    with contextd_home(LEDGER_HOME):
        from contextd.db import connect
        return connect()


def record(kind: str, meta: dict) -> int:
    conn = ledger_conn()
    from contextd.db import append_event
    eid = append_event(conn, "eval", kind,
                       meta={"family": "selection_stress", **meta})
    conn.close()
    return eid


# --- rubric -----------------------------------------------------------------

def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def scanned_text(output: str) -> tuple[str, bool]:
    """The rubric scans only the settled-decisions / constraints /
    next-action sections; if the headers are missing the whole output is
    scanned and the parse failure is recorded."""
    pattern = re.compile(
        r"^\s*\**\s*(OBJECTIVE|SETTLED DECISIONS|CONSTRAINTS IN FORCE|"
        r"NEXT ACTION)\s*:?\**\s*$|^\s*\**\s*(OBJECTIVE|SETTLED DECISIONS|"
        r"CONSTRAINTS IN FORCE|NEXT ACTION)\s*:\**\s*(.*)$",
        re.MULTILINE)
    sections: dict[str, list[str]] = {}
    current = None
    for line in (output or "").splitlines():
        m = pattern.match(line)
        if m:
            current = (m.group(1) or m.group(2)).upper()
            sections[current] = []
            rest = m.group(3)
            if rest:
                sections[current].append(rest)
        elif current:
            sections[current].append(line)
    if not any(k in sections for k in SCAN_SECTIONS):
        return normalize(output), False
    text = " ".join(" ".join(v) for k, v in sections.items()
                    if k in SCAN_SECTIONS)
    return normalize(text), True


def _token_rx(token: str) -> re.Pattern:
    return re.compile(re.escape(token.lower()).replace(r"\-", "[ -]?"))


def score_output(output: str, cell_spec: dict) -> dict:
    text, parse_ok = scanned_text(output)
    kind = cell_spec["kind"]
    opt_a = cell_spec["opt_a"]
    row = {"parse_ok": parse_ok}
    if kind == "super":
        opt_c = cell_spec["opt_c"]
        has_c = bool(_token_rx(opt_c).search(text))
        has_a = bool(_token_rx(opt_a).search(text))
        row["honors"] = has_c
        row["resurrects"] = has_a and not has_c
    else:
        row["honors"] = bool(_token_rx(opt_a).search(text))
    return row


# --- cell selection (pinned rule) -------------------------------------------

def _cell_key(r: dict) -> tuple:
    return (r["tier"], r["stratum"], r["age"], r["band"], r["distractor"])


def select_cells(rows: list[dict], default_budget: int) -> dict:
    """Deterministic, pinned BEFORE any model run (the behavioral phase
    dispatches from the seed-101 archives, so each cell must also show the
    target outcome in that exact archive, not only on the pooled rate):
    - absent6: first 6 cells in severity order with pooled silent-absence
      >= 0.8 AND the seed-101 row silently absent, no two sharing
      (tier, stratum) when avoidable (greedy diversity);
    - carried3: first 3 cells with pooled carriage == 1.0 and seed-101
      carried, distinct strata;
    - super3: first 3 supersession cells with pooled stale-resurrection
      >= 0.6 AND the seed-101 row stale-resurrected, distinct tiers when
      avoidable;
    - negative control: the first fully-carried near/recent cell, restored
      item taken from the last deep/far topic of the same archive;
    - positive control: the first dialogue/recent cell carried via the raw
      tail in seed 101 (any band — near-band items are always claimed by
      the recall slice before the tail packs them, so via==tail only
      occurs for mid/far bands; the control needs verbatim-in-tail, which
      band does not affect).
    Ties broken by the canonical (tier, stratum, age, band, distractor)
    sort. Seed for every behavioral world: 101 (pinned)."""
    s101: dict[tuple, dict] = {}
    agg: dict[tuple, dict] = {}
    for r in rows:
        if not (r["hinted"] and r["budget"] == default_budget
                and r["scope"] == "task"):
            continue
        key = _cell_key(r)
        if r["seed"] == 101:
            s101[key] = r
        a = agg.setdefault(key, {"n": 0, "carried": 0, "silent": 0,
                                 "resur": 0, "resur_n": 0})
        a["n"] += 1
        a["carried"] += bool(r["carried"])
        a["silent"] += bool(r["silently_absent"])
        if "stale_resurrected" in r:
            a["resur_n"] += 1
            a["resur"] += bool(r["stale_resurrected"])

    def order(keys):
        t = {"t5k": 0, "t20k": 1, "t80k": 2}
        ages = {"recent": 0, "mid": 1, "deep": 2}
        bands = {"near": 0, "mid": 1, "far": 2}
        return sorted(keys, key=lambda k: (t[k[0]], k[1], ages[k[2]],
                                           bands[k[3]], k[4]))

    absent6, seen_ts = [], set()
    for k in order(agg):
        a = agg[k]
        if (a["silent"] / a["n"] >= 0.8 and s101[k]["silently_absent"]
                and len(absent6) < 6):
            ts = (k[0], k[1])
            if ts in seen_ts and len(seen_ts) < 6:
                continue
            absent6.append(k)
            seen_ts.add(ts)
    carried3, seen_s = [], set()
    for k in order(agg):
        a = agg[k]
        if (a["carried"] == a["n"] and s101[k]["carried"]
                and k[1] not in seen_s and len(carried3) < 3):
            carried3.append(k)
            seen_s.add(k[1])
    super3, seen_t = [], set()
    for k in order(agg):
        a = agg[k]
        if (k[4] == "super" and a["resur_n"]
                and a["resur"] / a["resur_n"] >= 0.6
                and s101[k].get("stale_resurrected") and len(super3) < 3):
            if k[0] in seen_t and len(seen_t) < 3:
                continue
            super3.append(k)
            seen_t.add(k[0])
    neg = next(k for k in order(agg)
               if agg[k]["carried"] == agg[k]["n"] and s101[k]["carried"]
               and k[2] == "recent" and k[3] == "near")
    pos = next(k for k in order(agg)
               if k[1] == "dialogue" and k[2] == "recent"
               and s101[k].get("via") == "tail")
    return {"absent": absent6, "carried": carried3, "super": super3,
            "negative": neg, "positive": pos}


def _topic_for(manifest: dict, key: tuple) -> dict:
    tier, stratum, age, band, distr = key
    for tp in manifest["topics"]:
        if (tp["scope"] == "task" and tp["stratum"] == stratum
                and tp["age"] == age and tp["band"] == band
                and tp["distractor"] == distr):
            return tp
    raise KeyError(key)


def build_behavior_spec() -> dict:
    grid_rows = analysis.load_rows(RESULTS / "grid" / "rows.jsonl")
    s = spec.build_spec()
    sel = select_cells(grid_rows, s["default_budget"])
    cells = []
    manifests = {}

    def manifest(tier):
        if tier not in manifests:
            p = RESULTS / "worlds" / f"{tier}-s101" / "manifest.json"
            manifests[tier] = json.loads(p.read_text())
        return manifests[tier]

    def add(kind, key, arms):
        m = manifest(key[0])
        tp = _topic_for(m, key)
        cells.append({
            "kind": kind, "tier": key[0], "stratum": key[1], "age": key[2],
            "band": key[3], "distractor": key[4], "seed": 101,
            "topic": tp["topic"], "hint": tp["hint"], "comp": tp["comp"],
            "obj": tp["obj"], "opt_a": tp["opt_a"], "opt_c": tp.get("opt_c"),
            "plant_event_id": tp["plant"]["event_id"],
            "v2_event_id": (tp.get("v2") or {}).get("event_id"),
            "restore_event_id": (tp.get("v2") or {}).get("event_id")
            if kind == "super" else tp["plant"]["event_id"],
            "arms": arms, "archive_digest": m["digest"],
        })

    for k in sel["absent"]:
        add("absent", k, ["as_compiled", "restored"])
    for k in sel["carried"]:
        add("carried", k, ["as_compiled", "restored"])
    for k in sel["super"]:
        add("super", k, ["as_compiled", "restored"])
    # negative control: restore an item irrelevant to the dispatched task
    m = manifest(sel["negative"][0])
    neg_tp = _topic_for(m, sel["negative"])
    donor = [tp for tp in m["topics"] if tp["scope"] == "task"
             and tp["age"] == "deep" and tp["band"] == "far"][-1]
    cells.append({
        "kind": "negative", "tier": sel["negative"][0],
        "stratum": neg_tp["stratum"], "age": neg_tp["age"],
        "band": neg_tp["band"], "distractor": neg_tp["distractor"],
        "seed": 101, "topic": neg_tp["topic"], "hint": neg_tp["hint"],
        "comp": neg_tp["comp"], "obj": neg_tp["obj"],
        "opt_a": neg_tp["opt_a"], "opt_c": None,
        "irrelevant_opt": donor["opt_a"],
        "plant_event_id": neg_tp["plant"]["event_id"],
        "v2_event_id": None,
        "restore_event_id": donor["plant"]["event_id"],
        "arms": ["as_compiled", "restored"], "archive_digest": m["digest"],
    })
    # positive control: item verbatim in the raw tail; single arm (ceiling)
    m = manifest(sel["positive"][0])
    pos_tp = _topic_for(m, sel["positive"])
    cells.append({
        "kind": "positive", "tier": sel["positive"][0],
        "stratum": pos_tp["stratum"], "age": pos_tp["age"],
        "band": pos_tp["band"], "distractor": pos_tp["distractor"],
        "seed": 101, "topic": pos_tp["topic"], "hint": pos_tp["hint"],
        "comp": pos_tp["comp"], "obj": pos_tp["obj"],
        "opt_a": pos_tp["opt_a"], "opt_c": None,
        "plant_event_id": pos_tp["plant"]["event_id"], "v2_event_id": None,
        "restore_event_id": pos_tp["plant"]["event_id"],
        "arms": ["as_compiled"], "archive_digest": m["digest"],
    })
    planned = sum(len(c["arms"]) for c in cells) * N_PER_ARM
    return {
        "benchmark": "selection-stress-behavior-v1",
        "grid_spec_sha": spec.spec_sha(),
        "model": RESUME_MODEL, "n_per_arm": N_PER_ARM,
        "budget": s["default_budget"],
        "dispatch_ceiling": DISPATCH_CEILING,
        "planned_dispatches": planned,
        "ceiling_accounting": "every claude -p invocation counts, including "
                              "failures, timeouts, and the wiring probe",
        "rubric": {
            "scan": "SETTLED DECISIONS + CONSTRAINTS IN FORCE + NEXT ACTION "
                    "sections (whole output when headers absent; parse_ok "
                    "recorded)",
            "honors": "adopted-option token present (hyphen or space form)",
            "super": "honors = v2 option present; resurrects = v1 option "
                     "present without v2 option",
            "negative_outcome": "task-plant honor delta ~ 0 (p > 0.3); "
                                "adoption of the irrelevant restored item "
                                "recorded as a secondary observation",
            "positive_bar": "as-compiled honor rate >= 0.9",
        },
        "restoration": "restored arm appends the planted item under a final "
                       "'== RESTORED ITEM ==' section with its true event "
                       "header; position-of-restoration is a recorded "
                       "confound (organic carriage sits mid-package)",
        "stats": {"per_cell": "exact permutation on arm means",
                  "pooled": "stratified permutation, fixed seed 20260813"},
        "cells": cells,
    }


def behavior_spec_sha(doc: dict) -> str:
    return hashlib.sha256(
        json.dumps(doc, sort_keys=True).encode()).hexdigest()


# --- package assembly -------------------------------------------------------

def _render_item(conn, cfg, event_id: int) -> str:
    from contextd.handoff import _render
    row = conn.execute("SELECT * FROM events WHERE id = ?",
                       (event_id,)).fetchone()
    it = _render(cfg, row)
    return it["header"] + "\n" + it["text"]


def compile_arm(cell: dict, arm: str, budget: int) -> dict:
    """Compile the package for one arm inside the cell's archive home,
    disclosing the exact dispatched bundle through the real gate."""
    home = RESULTS / "worlds" / f"{cell['tier']}-s{cell['seed']}" / "home"
    with contextd_home(home):
        from contextd import load_config
        from contextd.db import connect
        from contextd.gate import disclose
        from contextd.handoff import compile_checkpoint
        conn = connect()
        cfg = load_config()
        out = compile_checkpoint(conn, cfg, budget=budget,
                                 task_hint=cell["hint"],
                                 client="selection-stress-behavior",
                                 purpose=f"arm={arm}")
        package, egress_id = out["package"], out["egress_id"]
        if arm == "restored":
            block = _render_item(conn, cfg, cell["restore_event_id"])
            package = (package + "\n\n== RESTORED ITEM (mechanically "
                       "re-attached by the harness) ==\n" + block)
            d = disclose(conn, cfg, package,
                         {"type": "selection_stress_arm", "arm": arm,
                          "cell_topic": cell["topic"],
                          "items": sorted(set(out["items"])
                                          | {cell["restore_event_id"]})})
            package, egress_id = d["content"], d["egress_id"]
        conn.close()
    return {"package": package, "egress_id": egress_id,
            "items": out["items"], "home": str(home)}


def record_outcome(home: str, egress_id: int, status: str, **details) -> None:
    with contextd_home(home):
        from contextd.db import connect
        from contextd.gate import record_dispatch_outcome
        conn = connect()
        record_dispatch_outcome(conn, egress_id, status, **details)
        conn.close()


def dispatches_used() -> int:
    conn = ledger_conn()
    n = conn.execute(
        "SELECT COUNT(*) FROM events WHERE kind IN "
        "('behavior_run', 'probe_run')").fetchone()[0]
    conn.close()
    return n


# --- commands ---------------------------------------------------------------

def cmd_probe(_args) -> int:
    out = run_claude("Reply with exactly: PROBE-OK", RESUME_MODEL,
                     timeout=240)
    record("probe_run", {"status": out["dispatch_status"],
                         "exit": out["exit"],
                         "text_sha": hashlib.sha256(
                             out["text"].encode()).hexdigest()})
    print(f"probe: {out['dispatch_status']} text={out['text']!r} "
          f"(dispatches used now {dispatches_used()}/{DISPATCH_CEILING})")
    return 0 if out["dispatch_status"] == "succeeded" else 1


def cmd_prereg(_args) -> int:
    chk = spec.check_frozen()
    if not chk["ok"]:
        print(f"REFUSED: {chk['why']}")
        return 2
    doc = build_behavior_spec()
    if doc["planned_dispatches"] + dispatches_used() > DISPATCH_CEILING:
        print(f"REFUSED: planned {doc['planned_dispatches']} + used "
              f"{dispatches_used()} exceeds ceiling {DISPATCH_CEILING}")
        return 4
    BEHAVIOR.mkdir(parents=True, exist_ok=True)
    FROZEN_BEHAVIOR.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    sha = behavior_spec_sha(doc)
    eid = record("experiment", {
        "type": "prereg", "benchmark": doc["benchmark"],
        "grid_spec_sha": doc["grid_spec_sha"], "behavior_spec_sha": sha,
        "planned_dispatches": doc["planned_dispatches"],
        "n_cells": len(doc["cells"]), "model": doc["model"]})
    print(f"preregistered as ledger event #{eid} (behavior spec sha {sha})")
    print(f"planned dispatches {doc['planned_dispatches']} "
          f"(+{dispatches_used()} used) / {DISPATCH_CEILING}")
    return 0


def _load_prereg(prereg_id: int) -> dict:
    conn = ledger_conn()
    row = conn.execute("SELECT meta FROM events WHERE id = ?",
                       (prereg_id,)).fetchone()
    conn.close()
    if not row:
        raise SystemExit(f"no ledger event #{prereg_id}")
    meta = json.loads(row["meta"])
    doc = json.loads(FROZEN_BEHAVIOR.read_text())
    if behavior_spec_sha(doc) != meta["behavior_spec_sha"]:
        raise SystemExit("frozen behavior spec does not match prereg sha — "
                         "run voided")
    return doc


def cmd_run(args) -> int:
    doc = _load_prereg(args.prereg_id)
    runs_path = BEHAVIOR / "runs.jsonl"
    done = set()
    if runs_path.exists():
        for r in analysis.load_rows(runs_path):
            done.add((r["cell_index"], r["arm"], r["i"]))
    with runs_path.open("a") as fh:
        for ci, cell in enumerate(doc["cells"]):
            for arm in cell["arms"]:
                for i in range(doc["n_per_arm"]):
                    if (ci, arm, i) in done:
                        continue
                    if dispatches_used() >= DISPATCH_CEILING:
                        print("STOP: dispatch ceiling reached")
                        return 5
                    # one disclosure per dispatch: the schema binds exactly
                    # one outcome to one egress receipt, and the contract is
                    # that every dispatched bundle is its own logged egress
                    compiled = compile_arm(cell, arm, doc["budget"])
                    prompt = TASK_TEMPLATE.format(comp=cell["comp"],
                                                  obj=cell["obj"],
                                                  package=compiled["package"])
                    out = run_claude(prompt, doc["model"], timeout=300)
                    score = score_output(out["text"], cell)
                    record_outcome(compiled["home"], compiled["egress_id"],
                                   out["dispatch_status"]
                                   if out["dispatch_status"] in
                                   ("succeeded", "failed", "timeout")
                                   else "failed",
                                   run=f"{ci}/{arm}/{i}")
                    row = {"cell_index": ci, "kind": cell["kind"],
                           "arm": arm, "i": i,
                           "egress_id": compiled["egress_id"],
                           "dispatch_status": out["dispatch_status"],
                           "output_sha": hashlib.sha256(
                               out["text"].encode()).hexdigest(),
                           **score}
                    if cell["kind"] == "negative":
                        text, _ = scanned_text(out["text"])
                        row["adopted_irrelevant"] = bool(
                            _token_rx(cell["irrelevant_opt"]).search(text))
                    fh.write(json.dumps(row, sort_keys=True) + "\n")
                    fh.flush()
                    tdir = BEHAVIOR / "transcripts" / f"c{ci}" / arm
                    tdir.mkdir(parents=True, exist_ok=True)
                    (tdir / f"r{i}.json").write_text(json.dumps(
                        {"prompt_sha": hashlib.sha256(
                            prompt.encode()).hexdigest(),
                         "output": out["text"],
                         "status": out["dispatch_status"]}, indent=1) + "\n")
                    record("behavior_run", {"prereg": args.prereg_id, **row})
                    print(f"c{ci} {cell['kind']} {arm} r{i}: "
                          f"{out['dispatch_status']} "
                          f"honors={score.get('honors')}", flush=True)
    print(f"runs complete; dispatches used {dispatches_used()}"
          f"/{DISPATCH_CEILING}")
    return 0


def behavior_results(doc: dict) -> dict:
    rows = analysis.load_rows(BEHAVIOR / "runs.jsonl")
    ok = [r for r in rows if r["dispatch_status"] == "succeeded"]
    excluded = [r for r in rows if r["dispatch_status"] != "succeeded"]
    cells_out = []
    pooled_absent = []
    for ci, cell in enumerate(doc["cells"]):
        crows = [r for r in ok if r["cell_index"] == ci]
        entry = {"cell_index": ci, "kind": cell["kind"], "tier": cell["tier"],
                 "stratum": cell["stratum"], "age": cell["age"],
                 "band": cell["band"], "distractor": cell["distractor"]}
        for arm in cell["arms"]:
            arows = [r for r in crows if r["arm"] == arm]
            entry[arm] = {
                "n": len(arows),
                "honors": round(sum(r["honors"] for r in arows)
                                / len(arows), 4) if arows else None}
            if cell["kind"] == "super" and arows:
                entry[arm]["resurrects"] = round(
                    sum(r["resurrects"] for r in arows) / len(arows), 4)
        if len(cell["arms"]) == 2:
            a = [float(r["honors"]) for r in crows if r["arm"] == "restored"]
            b = [float(r["honors"]) for r in crows
                 if r["arm"] == "as_compiled"]
            entry["perm"] = stats.perm_test(a, b)
            if cell["kind"] == "absent":
                pooled_absent.append({"a": a, "b": b})
        if cell["kind"] == "negative":
            adopt = [r for r in crows if r["arm"] == "restored"]
            entry["adopted_irrelevant"] = round(
                sum(r.get("adopted_irrelevant", False) for r in adopt)
                / len(adopt), 4) if adopt else None
        cells_out.append(entry)
    pooled = stats.stratified_perm_test(pooled_absent)
    return {"cells": cells_out, "pooled_absent": pooled,
            "n_runs": len(rows), "n_succeeded": len(ok),
            "excluded": [{k: r[k] for k in ("cell_index", "arm", "i",
                                            "dispatch_status")}
                         for r in excluded]}


def cmd_report(args) -> int:
    from experiments.selection_stress import report as report_mod
    return report_mod.cmd_report(args)
