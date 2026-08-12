#!/usr/bin/env python
"""Ablation harness: replay one task through `claude -p` under controlled
context interventions and record every arm, run, and score into the ledger.

Harness-side tooling, deliberately outside the contextd package: this script
invokes a model on your existing subscription; the kernel never does. All
retrieval, intervention, disclosure accounting, scoring, and statistics live
in contextd.experiment — this file only moves prompts to a model and results
back into the ledger.

Two modes:
  plan <task.json>   freeze the retrieval(s) and show what an experiment
                     would hold (items, provenance/origin mix, attribution,
                     p-floor) — no registration, no model calls
  run  <task.json>   register the experiment, run every arm x n, score,
                     record, and print the report

Task specs come in two shapes. v1: one top-level query/budget and arms that
subset it. v2: named context_sets plus a ladder — arms reference a set by
name ("context_set"), replace one with a distillation ("replace_from":
{"distill_of": set}), or supply no context. Per-item origin_overrides record
designer assessments where transport metadata misstates substantive origin.

The child claude processes get no tools and no MCP servers — otherwise a run
could call contextd's own recall and quietly refill an ablated arm."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contextd import load_config  # noqa: E402
from contextd.db import connect, now_iso  # noqa: E402
from contextd.experiment import (attribute_facts, build_report,  # noqa: E402
                                 disclose_for_run, format_report, freeze,
                                 p_floor, record_report, record_run,
                                 register_experiment, render_bundle,
                                 score_output, validate_rubric)
from contextd.gate import check_budget, est_tokens, log_egress  # noqa: E402

CLAUDE_BIN = os.environ.get("EXP_CLAUDE_BIN", "claude")
RESULTS = Path(__file__).resolve().parent / "results"

CONTEXT_WRAPPER = """{prompt}

Context retrieved from the operator's personal archive follows. It may be
incomplete or partly irrelevant; use whatever in it helps. When you rely on
a context item, cite its bracketed event id (e.g. [41003]).

<archive-context>
{bundle}
</archive-context>"""

DISTILL_PROMPT = """Distill the following context items into one compact
summary of at most 150 words. Preserve concrete decisions, names, numbers,
and mechanisms; drop narrative and repetition. Reply with only the summary.

{bundle}"""


def run_model(prompt: str, model: str, timeout: int = 600) -> dict:
    """One claude -p invocation: fresh tempdir cwd (no CLAUDE.md pickup), no
    tools, no MCP, no settings, no session persistence. Returns text + accounting."""
    sid = str(uuid.uuid4())
    tmp = tempfile.mkdtemp(prefix="ctx-exp-")
    env = os.environ.copy()
    env["MCP_CONNECTION_NONBLOCKING"] = "false"
    env["ENABLE_TOOL_SEARCH"] = "off"
    cmd = [CLAUDE_BIN, "-p", "--model", model, "--tools", "",
           "--strict-mcp-config", "--no-session-persistence",
           "--setting-sources", "", "--output-format", "json",
           "--session-id", sid, "--max-budget-usd", "0.50"]
    t0 = time.time()
    r = subprocess.run(cmd, input=prompt, capture_output=True, text=True,
                       timeout=timeout, cwd=tmp, env=env)
    duration_ms = int((time.time() - t0) * 1000)
    text, cost, usage = "", None, None
    if r.stdout.strip():
        try:
            out = json.loads(r.stdout)
            text = out.get("result") or ""
            cost = out.get("total_cost_usd")
            usage = out.get("usage")
        except json.JSONDecodeError:
            text = r.stdout
    return {"text": text, "session_id": sid, "exit": r.returncode,
            "duration_ms": duration_ms, "cost_usd": cost, "usage": usage,
            "stderr": r.stderr[-2000:] if r.returncode else ""}


def extract_citations(text: str, supplied: list) -> dict:
    """Event ids the output cites ([41003] or #41003) vs the ids actually
    supplied to that run. A citation outside the supplied set is hallucinated
    (or recalled from elsewhere) — worth counting either way."""
    cited = sorted({int(m) for m in
                    re.findall(r"(?:\[|#)(\d{3,6})\]?", text)})
    supplied_set = {i for i in supplied if i is not None}
    return {"cited": cited,
            "valid": [c for c in cited if c in supplied_set]}


def load_task(path: str) -> dict:
    task = json.loads(Path(path).read_text())
    problems = validate_rubric(task["rubric"])
    if problems:
        sys.exit("task rubric failed validation:\n  " + "\n  ".join(problems))
    if "context_sets" not in task:  # v1 shape: one implicit set
        task["context_sets"] = {"default": {
            "query": task["query"], "budget": task["budget"],
            "since": task.get("since", ""), "until": task.get("until", "")}}
        for arm in task["arms"]:
            if not arm.get("no_context") and "replace_from" not in arm:
                arm.setdefault("context_set", "default")
    return task


def freeze_sets(conn, cfg, task) -> dict:
    ov = task.get("origin_overrides", {})
    return {name: freeze(conn, cfg, cs["query"], cs["budget"],
                         cs.get("since", ""), cs.get("until", ""),
                         origin_overrides=ov)
            for name, cs in task["context_sets"].items()}


def cmd_plan(args):
    conn, cfg = connect(), load_config()
    task = load_task(args.task)
    sets = freeze_sets(conn, cfg, task)
    n = task["n_per_arm"]
    print(f"task {task['task_id']!r}")
    for name, fz in sets.items():
        att = attribute_facts(fz["items"], task["rubric"])
        print(f"set '{name}': query={fz['query']!r} budget={fz['budget']} "
              f"window=[{fz['since'] or '-'} .. {fz['until'] or '-'}] -> "
              f"{len(fz['items'])} items ~{sum(it['est_tokens'] for it in fz['items'])}tok "
              f"(+{len(fz['matched_not_included'])} matched-not-included)")
        for it in fz["items"]:
            facts = [fid for fid, ids in att.items() if it["id"] in ids]
            origin = (it["origin"] if it["origin_basis"] == "recorded"
                      else f"{it['origin']}*")
            print(f"  [{it['id']}] {it['provenance']:<8} origin={origin:<9} "
                  f"{it['epistemic_type']:<15} ~{it['est_tokens']:>4}tok  "
                  f"facts: {', '.join(facts) or '-'}")
            print(f"      {it['text'][:120].replace(chr(10), ' ')}")
        orphans = [fid for fid, ids in att.items() if not ids]
        if orphans:
            print(f"  facts with NO source in set '{name}': {', '.join(orphans)}")
    print(f"arms: {[a['name'] for a in task['arms']]}, n={n}/arm "
          f"-> {len(task['arms']) * n} runs, p-floor {p_floor(n, n)} per comparison")


def resolve_arms(conn, cfg, task, sets):
    """Materialize any 'replace_from: {distill_of: set}' arm by generating the
    summary now, before registration — the distillation is itself a disclosure
    and a model artifact, so it is gated, logged, and recorded in the spec."""
    arms = []
    for arm in task["arms"]:
        rf = arm.get("replace_from")
        if rf:
            src = rf["distill_of"] if isinstance(rf, dict) else "default"
            if isinstance(rf, str) and rf == "distill":
                src = next(iter(sets))
            bundle = render_bundle(sets[src]["items"])
            check_budget(conn, cfg, upcoming=est_tokens(bundle))
            log_egress(conn, cfg, bundle, {
                "type": "experiment", "arm": "_distill", "task_id": task["task_id"],
                "items": [it["id"] for it in sets[src]["items"]],
                "client": "exp-runner"})
            r = run_model(DISTILL_PROMPT.format(bundle=bundle), task["model"])
            if r["exit"] != 0 or not r["text"].strip():
                sys.exit(f"distillation failed: exit {r['exit']} {r['stderr']}")
            arm = {**{k: v for k, v in arm.items() if k != "replace_from"},
                   "replace": {
                       "text": r["text"].strip(), "provenance": "model",
                       "origin": f"claude -p {task['model']} distillation of set '{src}'"}}
        arms.append(arm)
    return arms


def arm_items(arm, sets):
    if arm.get("no_context") or arm.get("replace") is not None:
        return []
    return sets[arm.get("context_set", next(iter(sets)))]["items"]


def cmd_run(args):
    conn, cfg = connect(), load_config()
    task = load_task(args.task)
    if os.environ.get("ANTHROPIC_API_KEY"):
        print("note: ANTHROPIC_API_KEY is set — runs will bill the API key, "
              "not the subscription", file=sys.stderr)
    sets = freeze_sets(conn, cfg, task)
    for name, fz in sets.items():
        if not fz["items"] and not args.allow_empty:
            sys.exit(f"set '{name}' froze empty; refusing (--allow-empty to override)")
    arms = resolve_arms(conn, cfg, task, sets)
    attribution = {name: attribute_facts(fz["items"], task["rubric"])
                   for name, fz in sets.items()}
    n = task["n_per_arm"]
    cli_version = subprocess.run([CLAUDE_BIN, "--version"], capture_output=True,
                                 text=True).stdout.strip()
    spec = {
        "task_id": task["task_id"], "title": task.get("title", ""),
        "prompt_template": CONTEXT_WRAPPER, "prompt": task["prompt"],
        "context_sets_spec": task["context_sets"],
        "model": task["model"],
        "model_settings": {"cli": cli_version,
                           "temperature": "not exposed by claude -p",
                           "flags": "--tools '' --strict-mcp-config "
                                    "--no-session-persistence --setting-sources ''"},
        "n_per_arm": n, "arms": arms, "rubric": task["rubric"],
        "frozen_sets": sets, "attribution": attribution,
        "baseline_arm": task.get("baseline_arm", "full"),
        "detail_arm": task.get("detail_arm"),
        "ladder": task.get("ladder", []),
        "origin_overrides": task.get("origin_overrides", {}),
        "expectation": task.get("expectation", ""),
        "registered": now_iso(),
    }
    exp_id = register_experiment(conn, spec)
    print(f"registered experiment #{exp_id} "
          f"({len(arms)} arms x {n} runs, model {task['model']})")

    outdir = RESULTS / f"{task['task_id']}-exp{exp_id}"
    (outdir / "transcripts").mkdir(parents=True, exist_ok=True)

    # disclose sequentially (each bundle is a gated egress event, logged
    # before anything reaches a model), then fan the model calls out
    jobs = []
    for arm in arms:
        items = arm_items(arm, sets)  # replace/no_context arms need no set
        for i in range(n):
            d = disclose_for_run(conn, cfg, exp_id, arm, i, items,
                                 client="exp-runner")
            prompt = (CONTEXT_WRAPPER.format(prompt=task["prompt"], bundle=d["bundle"])
                      if d["bundle"] else task["prompt"])
            jobs.append({"arm": arm["name"], "run": i, "egress_id": d["egress_id"],
                         "bundle_sha": d["sha"], "items": d["items"],
                         "context_est_tokens": d["est_tokens"], "prompt": prompt})
    print(f"disclosed {sum(1 for j in jobs if j['egress_id'])} bundles "
          f"through the gate; running {len(jobs)} model calls "
          f"(jobs={args.jobs})...")

    done = 0
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = {ex.submit(run_model, j["prompt"], task["model"]): j for j in jobs}
        for fut in as_completed(futs):
            j = futs[fut]
            try:
                r = fut.result()
            except Exception as e:
                r = {"text": "", "session_id": "?", "exit": -1,
                     "duration_ms": 0, "cost_usd": None, "usage": None,
                     "stderr": str(e)}
            sc = score_output(task["rubric"], r["text"])
            cites = extract_citations(r["text"], j["items"])
            record_run(conn, exp_id, {
                "arm": j["arm"], "run": j["run"], "egress_id": j["egress_id"],
                "bundle_sha": j["bundle_sha"], "items": j["items"],
                "context_est_tokens": j["context_est_tokens"],
                "session_id": r["session_id"], "model": task["model"],
                "duration_ms": r["duration_ms"], "cost_usd": r["cost_usd"],
                "usage": r["usage"], "exit": r["exit"], "stderr": r["stderr"],
                "output": r["text"][:20000],
                "output_sha": hashlib.sha256(r["text"].encode()).hexdigest(),
                "score": sc["score"], "hits": sc["hits"], "citations": cites})
            (outdir / "transcripts" / f"{j['arm']}-{j['run']}.md").write_text(
                f"# {task['task_id']} / {j['arm']} / run {j['run']}\n\n"
                f"session {r['session_id']}  exit {r['exit']}  "
                f"{r['duration_ms']}ms  score {sc['score']}\n"
                f"hits: {json.dumps(sc['hits'])}\ncitations: {json.dumps(cites)}\n\n"
                f"## Prompt\n\n{j['prompt']}\n\n## Output\n\n{r['text']}\n")
            done += 1
            flag = "" if r["exit"] == 0 else f"  EXIT {r['exit']}"
            print(f"  [{done}/{len(jobs)}] {j['arm']}#{j['run']} "
                  f"score {sc['score']:.2f}  {r['duration_ms']}ms{flag}", flush=True)

    report = build_report(conn, exp_id)
    rep_id = record_report(conn, exp_id, report)
    text = format_report(report)
    (outdir / "report.txt").write_text(text + "\n")
    (outdir / "report.json").write_text(json.dumps(report, indent=2))
    print(f"\nreport recorded as event #{rep_id}; written to {outdir}/report.txt\n")
    print(text)


def main():
    p = argparse.ArgumentParser(description="contextd ablation harness")
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("plan", help="freeze + show, no model calls, no registration")
    sp.add_argument("task")
    sp = sub.add_parser("run", help="register and run the full experiment")
    sp.add_argument("task")
    sp.add_argument("--jobs", type=int, default=3)
    sp.add_argument("--allow-empty", action="store_true")
    args = p.parse_args()
    {"plan": cmd_plan, "run": cmd_run}[args.cmd](args)


if __name__ == "__main__":
    main()
