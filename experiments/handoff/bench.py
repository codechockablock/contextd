#!/usr/bin/env python
"""Checkpoint/resume benchmark orchestrator.

    stage                        run session A on the staged task, capture its
                                 dialogue into a synthetic archive, interrupt
    run-staged <staged-dir>      preregister + run all resumption arms on the
                                 interrupted staged task, score, report
    run-history <case>           freeze the live archive at the case's cutoff,
                                 build arm contexts, preregister, run, score
    cross <staged-dir>           cross-model (sonnet) and cross-vendor (codex)
                                 resumption from the same checkpoints
    report <exp_id>              rebuild a report from the live ledger

Continuity gap = continuous-arm mean minus fresh-arm mean (staged track; the
real-history track has no continuous arm — its ceiling is the raw tail).
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from contextd.experiment import (p_floor, perm_test, score_output,  # noqa: E402
                                 validate_rubric, verdict)
from experiments.handoff import staged as st  # noqa: E402
from experiments.handoff.cases import CASES, TASK_TEMPLATE  # noqa: E402
from experiments.handoff.common import (REPO, RESULTS, contextd_home,  # noqa: E402
                                        egress_spent_by_client,
                                        extract_citations, record, run_claude,
                                        run_codex, view_conn, write_mcp_config)

# contextd.gate dispatches retrieval through a provider that contextd.search
# registers at import time (lane T). A process that assembles a disclosure
# without importing it gets an empty candidate set, not an error — importing it
# here is what keeps this script's recall working. Pinned by
# tests/test_gate_retrieval_hook.py::test_every_retrieval_caller_registers.
import contextd.search  # noqa: F401

LIVE_DB = Path("~/.contextd/contextd.db").expanduser()

NAIVE_DISTILL = """Distill the following project history into one compact
summary of at most 150 words. Preserve concrete decisions, names, numbers,
and mechanisms; drop narrative and repetition. Reply with only the summary.

{text}"""


def _mean(xs):
    return sum(xs) / len(xs) if xs else 0.0


def _sd(xs):
    if len(xs) < 2:
        return 0.0
    m = _mean(xs)
    return (sum((x - m) ** 2 for x in xs) / (len(xs) - 1)) ** 0.5


def naive_summary(text: str, model: str) -> str:
    r = run_claude(NAIVE_DISTILL.format(text=text), model)
    if r["dispatch_status"] != "succeeded" or not r["text"].strip():
        raise RuntimeError(f"naive distillation failed: {r['stderr']}")
    return r["text"].strip()


def est_tokens(text: str) -> int:
    return max(1, len(text) // 4)


# --- staged track ------------------------------------------------------------

def cmd_stage(args):
    work = Path(args.dir or tempfile.mkdtemp(prefix="handoff-staged-"))
    work.mkdir(parents=True, exist_ok=True)
    print(f"staging session A ({args.model}) in {work} ...")
    info = st.stage_session_a(work, model=args.model)
    arch = st.build_synthetic_archive(work / "archive", info["transcript"],
                                      info["session_id"])
    state = {**{k: v for k, v in info.items() if k != "transcript"},
             "archive": arch, "staged_at": time.time()}
    (work / "staged.json").write_text(json.dumps(state, indent=2))
    t = info["tests_at_interruption"]
    print(f"interrupted: public tests {t['passed']}/{t['total']} passing "
          f"(refill deferred by design)")
    print(f"session {info['session_id']}  archive {arch['home']} "
          f"(events {arch['first']}..{arch['last']})")
    print(f"state -> {work / 'staged.json'}")


def staged_arm_contexts(work: Path, state: dict, model: str) -> dict:
    """Build every fresh arm's context block, automatically, from the
    synthetic archive / transcript / repo. Returns {arm: {text, ids, tokens,
    desc}}. The continuous arm needs no context (that is the point)."""
    transcript = json.loads((work / "transcript.json").read_text())
    repo = Path(state["repo"])
    arch_home = Path(state["archive"]["home"])
    arms = {}

    full = "\n\n".join(f"--- {role} ---\n{text}" for role, text in transcript)
    arms["raw_transcript"] = {"text": full, "ids": [],
                              "desc": "the complete session-A transcript, verbatim"}

    arms["distilled"] = {"text": naive_summary(full, model), "ids": [],
                         "desc": "a 150-word static summary of the transcript"}

    with contextd_home(arch_home):
        from contextd import load_config
        from contextd.db import connect
        from contextd.gate import assemble
        from contextd.handoff import compile_checkpoint, repo_state
        conn, cfg = connect(), load_config()
        rec = assemble(conn, cfg, st.TASK_HINT, budget=3000,
                       purpose="handoff-bench staged recall arm",
                       client="handoff-bench")
        arms["recall"] = {"text": rec["bundle"], "ids": rec["items"],
                          "desc": "contextd plain recall (query = task hint)"}
        rst = repo_state(repo, test_cmd=[sys.executable, "-m", "pytest", "-q",
                                        "test_ratelimit.py"])
        ck = compile_checkpoint(conn, cfg, budget=3000, task_hint=st.TASK_HINT,
                                repo=rst, client="handoff-bench")
        arms["checkpoint_raw"] = {"text": ck["package"], "ids": ck["items"],
                                  "desc": "contextd compiled checkpoint (model-free)"}
    with contextd_home(arch_home):
        sys.path.insert(0, str(REPO / "hooks"))
        import checkpoint_compile as cc
        from contextd import load_config
        from contextd.db import connect
        conn, cfg = connect(), load_config()
        ckd = cc.compile_distilled(conn, cfg, raw_budget=6000,
                                   task_hint=st.TASK_HINT, repo=rst,
                                   model=model, client="handoff-bench")
        arms["checkpoint_distilled"] = {
            "text": ckd["package"], "ids": ckd["anchors"],
            "desc": "contextd distilled checkpoint (structured, anchor-verified)"}

    arms["no_history"] = {"text": "", "ids": [],
                          "desc": "repository only, no project memory"}
    for a in arms.values():
        a["tokens"] = est_tokens(a["text"])
    return arms


def staged_prompt(arm_name: str, ctx: dict, state: dict) -> str:
    repo = Path(state["repo"])
    current = (repo / "ratelimit.py").read_text()
    if arm_name == "continuous":
        return (f"=== REPOSITORY (current) ===\n=== ratelimit.py ===\n{current}\n\n"
                + st.PHASE2_INSTRUCTION)
    block = ("(No project memory is available. Only the repository below.)"
             if not ctx["text"] else
             f"=== PROJECT MEMORY ({ctx['desc']}) ===\n{ctx['text']}")
    return st.RESUME_PREFIX.format(
        context_block=block, readme=st.README, tests=st.PUBLIC_TESTS,
        current_impl=current, instruction=st.PHASE2_INSTRUCTION)


def cmd_run_staged(args):
    work = Path(args.staged_dir)
    state = json.loads((work / "staged.json").read_text())
    model = args.model
    n = args.n
    print("building arm contexts ...")
    contexts = staged_arm_contexts(work, state, model)
    arm_names = ["continuous"] + list(contexts)
    rubric_problems = validate_rubric(st.RUBRIC)
    if rubric_problems:
        sys.exit("staged rubric failed validation:\n  " + "\n  ".join(rubric_problems))

    spec = {
        "task_id": "handoff-staged-ratelimit-v1",
        "track": "staged",
        "session_a": {"model": state["model"], "session_id": state["session_id"],
                      "tests_at_interruption": state["tests_at_interruption"]},
        "resume_model": model, "n_per_arm": n,
        "arms": {a: {"desc": (contexts[a]["desc"] if a in contexts
                              else "native session resume (continuous control)"),
                     "ctx_tokens": contexts[a]["tokens"] if a in contexts else None}
                 for a in arm_names},
        "weights": st.WEIGHTS, "rubric": st.RUBRIC,
        "holdout_tests_sha": __import__("hashlib").sha256(
            st.HOLDOUT_TESTS.encode()).hexdigest(),
        "expectation": (
            "Preregistered before any phase-2 run. Continuous is the ceiling. "
            "Holdout tests carry the dialogue-only constraints: no_history "
            "measures their guessability; the gap between checkpoint arms and "
            "no_history on the holdout fraction is the continuity signal. "
            "Failure modes this design can show: the constraints are guessable "
            "(no_history holdout high -> staged task weak), or checkpoints "
            "lose the constraints (checkpoint holdout ~ no_history). "
            "OBSERVED AT STAGING, before any phase-2 run: session A's "
            "interrupted file carries a TODO that restates the backwards-clock "
            "rule and already implements the oversized-deny rule — the "
            "repository absorbed part of the session knowledge, which will "
            "compress the holdout gap for every arm (itself a finding: repo "
            "state is a continuity channel). The remaining dialogue-only "
            "discriminators are the rejected-alternative facts "
            "(rejected_sliding_window, why_not_memory) in the brief rubric."),
        "registered": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
    }
    exp_id = record("experiment", spec)
    print(f"preregistered as live ledger event #{exp_id}")
    outdir = RESULTS / f"handoff-staged-exp{exp_id}"
    (outdir / "transcripts").mkdir(parents=True, exist_ok=True)
    for a, c in contexts.items():
        (outdir / f"context-{a}.txt").write_text(c["text"])

    jobs = []
    for arm in arm_names:
        for i in range(n):
            jobs.append((arm, i))

    def one(arm, i):
        prompt = staged_prompt(arm, contexts.get(arm, {}), state)
        if arm == "continuous":
            r = run_claude(prompt, model, resume=state["session_id"], persist=True)
        else:
            r = run_claude(prompt, model)
        sc = st.score_phase2(Path(state["repo"]),
                             Path(tempfile.mkdtemp(prefix=f"handoff-{arm}-")),
                             r["text"])
        return r, sc

    results = []
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = {ex.submit(one, a, i): (a, i) for a, i in jobs}
        for fut in as_completed(futs):
            arm, i = futs[fut]
            try:
                r, sc = fut.result()
            except Exception as e:
                r = {"text": "", "exit": -1, "duration_ms": 0, "cost_usd": None,
                     "stderr": str(e), "dispatch_status": "failed"}
                sc = {"applied": False, "score": 0.0,
                      "public": {"frac": 0}, "holdout": {"frac": 0},
                      "brief": {"score": 0, "hits": {}}}
            run_meta = {
                "exp_id": exp_id, "arm": arm, "run": i,
                "ctx_tokens": contexts.get(arm, {}).get("tokens"),
                "score": sc["score"],
                "public_frac": sc["public"]["frac"],
                "holdout_frac": sc["holdout"]["frac"],
                "brief_score": sc["brief"]["score"],
                "brief_hits": sc["brief"]["hits"],
                "applied": sc["applied"], "exit": r["exit"],
                "duration_ms": r["duration_ms"], "cost_usd": r.get("cost_usd"),
                "resume_model": model, "output": r["text"][:20000],
            }
            rid = record("exp_run", run_meta)
            results.append(run_meta)
            (outdir / "transcripts" / f"{arm}-{i}.md").write_text(
                f"# staged / {arm} / run {i}\nscore {sc['score']} "
                f"(pub {sc['public']['frac']:.2f} hold {sc['holdout']['frac']:.2f} "
                f"brief {sc['brief']['score']:.2f})\n\n## Output\n\n{r['text']}\n")
            print(f"  [{len(results)}/{len(jobs)}] {arm}#{i} score {sc['score']:.2f} "
                  f"(hold {sc['holdout']['frac']:.2f}) run event #{rid}", flush=True)

    rep = staged_report(spec, exp_id, results)
    rep_id = record("exp_report", rep)
    (outdir / "report.json").write_text(json.dumps(rep, indent=2))
    text = format_staged_report(rep)
    (outdir / "report.txt").write_text(text + "\n")
    print(f"\nreport -> live event #{rep_id}, {outdir}/report.txt\n")
    print(text)


def staged_report(spec, exp_id, results) -> dict:
    by_arm = {}
    for r in results:
        by_arm.setdefault(r["arm"], []).append(r)
    arms = {}
    for name, rs in by_arm.items():
        arms[name] = {
            "n": len(rs),
            "mean": round(_mean([r["score"] for r in rs]), 4),
            "sd": round(_sd([r["score"] for r in rs]), 4),
            "scores": [r["score"] for r in rs],
            "holdout_mean": round(_mean([r["holdout_frac"] for r in rs]), 4),
            "public_mean": round(_mean([r["public_frac"] for r in rs]), 4),
            "brief_mean": round(_mean([r["brief_score"] for r in rs]), 4),
            "ctx_tokens": rs[0].get("ctx_tokens"),
        }
    cont = arms.get("continuous")
    gaps = []
    for name, a in arms.items():
        if name == "continuous" or not cont:
            continue
        p = perm_test(cont["scores"], a["scores"])
        gaps.append({"arm": name,
                     "continuity_gap": round(cont["mean"] - a["mean"], 4),
                     "holdout_gap": round(cont["holdout_mean"] - a["holdout_mean"], 4),
                     "p": p, "p_floor": p_floor(len(cont["scores"]), len(a["scores"])),
                     "verdict": verdict(p),
                     "ctx_tokens": a["ctx_tokens"]})
    gaps.sort(key=lambda g: g["continuity_gap"])
    return {"exp_id": exp_id, "task_id": spec["task_id"], "track": "staged",
            "resume_model": spec["resume_model"], "arms": arms,
            "continuity_gaps": gaps,
            "not_licensed": [
                "one staged task, one resumption model; nothing generalizes "
                "beyond them without replication",
                "n per arm is small; p-floors are reported",
                "holdout tests measure two planted constraints, not all "
                "session knowledge",
            ]}


def format_staged_report(rep) -> str:
    out = [f"HANDOFF BENCH (staged) exp #{rep['exp_id']} "
           f"resume_model={rep['resume_model']}", ""]
    w = max(len(a) for a in rep["arms"])
    for name, a in sorted(rep["arms"].items(), key=lambda kv: -kv[1]["mean"]):
        tok = f"{a['ctx_tokens']:>6}" if a.get("ctx_tokens") is not None else "native"
        out.append(f"  {name:<{w}}  score {a['mean']:.2f} ± {a['sd']:.2f}  "
                   f"holdout {a['holdout_mean']:.2f}  public {a['public_mean']:.2f}  "
                   f"brief {a['brief_mean']:.2f}  ctx {tok}")
    out.append("")
    out.append("  continuity gap (continuous minus arm; negative = arm beat "
               "the continuous session):")
    for g in rep["continuity_gaps"]:
        out.append(f"    {g['arm']:<{w}}  gap {g['continuity_gap']:+.2f}  "
                   f"holdout-gap {g['holdout_gap']:+.2f}  p={g['p']} "
                   f"(floor {g['p_floor']})  {g['verdict']}")
    out.append("")
    out.append("This result does not license:")
    for line in rep["not_licensed"]:
        out.append(f"  - {line}")
    return "\n".join(out)


# --- real-history track ------------------------------------------------------

def history_arm_contexts(case: dict, view_home: Path, model: str,
                         outdir: Path) -> dict:
    """Every arm context, compiled automatically from the frozen view."""
    from contextd.handoff import compile_checkpoint
    arms = {}
    hint = case["task_hint"]
    conn, cfg = view_conn(view_home)
    with contextd_home(view_home):
        from contextd.gate import assemble
        from experiments.handoff.common import disclose_text, render_tail
        tail_text, tail_ids = render_tail(conn, cfg, budget=12000)
        # archive-derived bytes never reach a model off the books: the tail
        # bundle (and below, the distiller's input) get their own receipts in
        # the view's ledger, exactly like recall/checkpoint arms already do
        disclose_text(conn, cfg, tail_text, {
            "type": "experiment", "arm": "raw_tail", "items": tail_ids,
            "client": "handoff-bench"})
        arms["raw_tail"] = {"text": tail_text, "ids": tail_ids,
                            "desc": "the most recent dialogue, verbatim (~12k tokens)"}
        rec = assemble(conn, cfg, hint, budget=4000,
                       purpose="handoff-bench recall arm", client="handoff-bench")
        arms["recall"] = {"text": rec["bundle"], "ids": rec["items"],
                          "desc": "contextd plain recall (query = task hint)"}
        repo_hist = {
            "branch": "master", "commit": case["commit"],
            "log": subprocess.run(
                ["git", "-C", str(REPO), "log", "--oneline", "-8", case["commit"]],
                capture_output=True, text=True).stdout.strip(),
            "status": "", "diffstat": ""}
        ck = compile_checkpoint(conn, cfg, budget=4000, task_hint=hint,
                                repo=repo_hist, client="handoff-bench")
        arms["checkpoint_raw"] = {"text": ck["package"], "ids": ck["items"],
                                  "desc": "contextd compiled checkpoint (model-free)"}
    with contextd_home(view_home):
        distill_input = NAIVE_DISTILL.format(text=tail_text)
        d = disclose_text(conn, cfg, distill_input, {
            "type": "experiment", "arm": "_naive_distill", "items": tail_ids,
            "client": "handoff-bench"})
        r = run_claude(d["content"], model)
        if r["dispatch_status"] != "succeeded" or not r["text"].strip():
            raise RuntimeError(f"naive distillation failed: {r['stderr']}")
        summary = r["text"].strip()
        disclose_text(conn, cfg, summary, {
            "type": "experiment", "arm": "distilled", "items": tail_ids,
            "source_egress": d["egress_id"], "client": "handoff-bench"})
    arms["distilled"] = {"text": summary, "ids": [],
                         "desc": "a 150-word static summary of the recent dialogue"}
    with contextd_home(view_home):
        sys.path.insert(0, str(REPO / "hooks"))
        import checkpoint_compile as cc
        conn2, cfg2 = view_conn(view_home)
        ckd = cc.compile_distilled(conn2, cfg2, raw_budget=9000, task_hint=hint,
                                   repo=repo_hist, model=model,
                                   client="handoff-bench")
        arms["checkpoint_distilled"] = {
            "text": ckd["package"], "ids": ckd["anchors"],
            "desc": "contextd distilled checkpoint (structured, anchor-verified)"}
        synth = subprocess.run(
            [sys.executable, str(REPO / "hooks" / "synthesis_recall.py"),
             hint, "--budget", "6000", "--retries", "2",
             "--purpose", "handoff-bench synthesis arm"],
            capture_output=True, text=True, timeout=900,
            env={**__import__("os").environ, "CONTEXTD_HOME": str(view_home)})
    if synth.returncode == 0 and synth.stdout.strip():
        arms["synthesis"] = {"text": synth.stdout.strip(), "ids": [],
                             "desc": "contextd synthesis recall (fused-with-ids "
                                     "distillate, anchor-verified)"}
    else:
        print(f"  synthesis arm unavailable: {synth.stderr.strip()[-200:]}",
              file=sys.stderr)
    arms["no_history"] = {"text": "", "ids": [],
                          "desc": "repository only, no project memory"}
    arms["interactive"] = {"text": None, "ids": [],
                           "desc": "MCP tools on the frozen view, metered"}
    for name, a in arms.items():
        a["tokens"] = est_tokens(a["text"]) if a["text"] else 0
        if a["text"]:
            (outdir / f"context-{name}.txt").write_text(a["text"])
    return arms, repo_hist


INTERACTIVE_BLOCK = """=== PROJECT MEMORY (interactive) ===
You have MCP tools querying the project's contextd archive, frozen at the
interruption point: recall(query, budget, purpose), search(query), and
timeline(since, until, source). Every read is metered and logged. Query what
you need (a handful of focused calls beats many broad ones), then answer."""


def history_prompt(arm_name: str, ctx: dict, case: dict, log: str) -> str:
    if arm_name == "interactive":
        block = INTERACTIVE_BLOCK
    elif not ctx["text"]:
        block = "(No project memory is available. Only the repository state below.)"
    else:
        block = f"=== PROJECT MEMORY ({ctx['desc']}) ===\n{ctx['text']}"
    return TASK_TEMPLATE.format(context_block=block, commit=case["commit"],
                                log=log)


def cmd_run_history(args):
    case_name = args.case
    case = CASES[case_name]
    model = args.model
    n = args.n
    problems = validate_rubric(case["rubric"])
    if problems:
        sys.exit(f"{case_name} rubric failed validation:\n  " + "\n  ".join(problems))

    views_root = Path(args.views_root or tempfile.mkdtemp(prefix="handoff-views-"))
    view_home = views_root / case_name
    if view_home.exists():
        shutil.rmtree(view_home)
    from contextd.handoff import freeze_view
    info = freeze_view(LIVE_DB, view_home, case["cutoff"])
    print(f"frozen view: {info['events']} events, tip #{info['tip']} "
          f"(live tip #{info['source_tip']})")

    outdir_tmp = Path(tempfile.mkdtemp(prefix="handoff-ctx-"))
    contexts, repo_hist = history_arm_contexts(case, view_home, model, outdir_tmp)

    spec = {
        "task_id": f"handoff-{case_name}-v1", "track": "history",
        "cutoff": case["cutoff"], "commit": case["commit"],
        "moment": case["moment"], "task_hint": case["task_hint"],
        "resume_model": model, "n_per_arm": n,
        "arms": {a: {"desc": c["desc"], "ctx_tokens": c["tokens"]}
                 for a, c in contexts.items()},
        "rubric": case["rubric"], "expectation": case["expectation"],
        "registered": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
    }
    exp_id = record("experiment", spec)
    print(f"preregistered as live ledger event #{exp_id}")
    outdir = RESULTS / f"handoff-{case_name}-exp{exp_id}"
    (outdir / "transcripts").mkdir(parents=True, exist_ok=True)
    for f in outdir_tmp.glob("context-*.txt"):
        shutil.copy(f, outdir / f.name)

    log = repo_hist["log"]
    jobs = [(a, i) for a in contexts for i in range(n)]

    def one(arm, i):
        prompt = history_prompt(arm, contexts[arm], case, log)
        if arm == "interactive":
            client = f"interactive-{case_name}-{i}"
            mcp_cfg = write_mcp_config(
                Path(tempfile.mkdtemp()) / "mcp.json", view_home, client)
            r = run_claude(prompt, model, mcp_config=mcp_cfg,
                           allowed_tools="mcp__contextd__recall,"
                                         "mcp__contextd__search,"
                                         "mcp__contextd__timeline",
                           max_turns=15)
            vconn, _ = view_conn(view_home)
            r["metered"] = egress_spent_by_client(vconn, client)
        return arm, i, (r if arm == "interactive"
                        else run_claude(prompt, model))

    results = []
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = [ex.submit(one, a, i) for a, i in jobs]
        for fut in as_completed(futs):
            arm, i, r = fut.result()
            sc = score_output(case["rubric"], r["text"])
            supplied = contexts[arm]["ids"]
            cites = extract_citations(r["text"], supplied)
            run_meta = {
                "exp_id": exp_id, "arm": arm, "run": i,
                "ctx_tokens": (r.get("metered", {}).get("est_tokens")
                               if arm == "interactive"
                               else contexts[arm]["tokens"]),
                "metered": r.get("metered"),
                "score": sc["score"], "hits": sc["hits"],
                "citations": cites, "exit": r["exit"],
                "duration_ms": r["duration_ms"], "cost_usd": r.get("cost_usd"),
                "resume_model": model, "output": r["text"][:20000],
            }
            rid = record("exp_run", run_meta)
            results.append(run_meta)
            (outdir / "transcripts" / f"{arm}-{i}.md").write_text(
                f"# {case_name} / {arm} / run {i}\nscore {sc['score']}\n"
                f"hits: {json.dumps(sc['hits'])}\n\n## Output\n\n{r['text']}\n")
            print(f"  [{len(results)}/{len(jobs)}] {arm}#{i} "
                  f"score {sc['score']:.2f} run event #{rid}", flush=True)

    rep = history_report(spec, exp_id, results)
    rep_id = record("exp_report", rep)
    (outdir / "report.json").write_text(json.dumps(rep, indent=2))
    text = format_history_report(rep)
    (outdir / "report.txt").write_text(text + "\n")
    print(f"\nreport -> live event #{rep_id}, {outdir}/report.txt\n")
    print(text)
    if not args.keep_view:
        from contextd.handoff import drop_view
        drop_view(view_home)


def history_report(spec, exp_id, results) -> dict:
    by_arm = {}
    for r in results:
        by_arm.setdefault(r["arm"], []).append(r)
    arms = {}
    for name, rs in by_arm.items():
        cited = [len(r["citations"]["cited"]) for r in rs]
        valid = [len(r["citations"]["valid"]) for r in rs]
        arms[name] = {
            "n": len(rs), "mean": round(_mean([r["score"] for r in rs]), 4),
            "sd": round(_sd([r["score"] for r in rs]), 4),
            "scores": [r["score"] for r in rs],
            "ctx_tokens": round(_mean([r["ctx_tokens"] or 0 for r in rs])),
            "citations_mean": round(_mean(cited), 1),
            "hallucinated_citations": sum(c - v for c, v in zip(cited, valid)),
        }
    base = arms.get("no_history")
    ceiling = arms.get("raw_tail")
    comparisons = []
    for name, a in arms.items():
        entry = {"arm": name, "ctx_tokens": a["ctx_tokens"]}
        if base and name != "no_history":
            p = perm_test(a["scores"], base["scores"])
            entry.update(vs_no_history=round(a["mean"] - base["mean"], 4),
                         p_vs_none=p, verdict_vs_none=verdict(p))
        if ceiling and name not in ("raw_tail",):
            p2 = perm_test(a["scores"], ceiling["scores"])
            entry.update(vs_raw_tail=round(a["mean"] - ceiling["mean"], 4),
                         p_vs_ceiling=p2, verdict_vs_ceiling=verdict(p2))
        comparisons.append(entry)
    comparisons.sort(key=lambda c: -(arms[c["arm"]]["mean"]))
    fact_rates = {}
    for f in spec["rubric"]["facts"]:
        fid = f["id"]
        fact_rates[fid] = {
            "weight": f.get("weight", 1.0),
            "rates": {arm: round(sum(1 for r in rs if r["hits"].get(fid))
                                 / len(rs), 3)
                      for arm, rs in by_arm.items()}}
    return {"exp_id": exp_id, "task_id": spec["task_id"], "track": "history",
            "cutoff": spec["cutoff"], "resume_model": spec["resume_model"],
            "arms": arms, "comparisons": comparisons, "fact_rates": fact_rates,
            "p_floor": p_floor(spec["n_per_arm"], spec["n_per_arm"]),
            "not_licensed": [
                "one historical cutoff, one resumption model, lexical rubric "
                "facts; paraphrases the patterns miss score as absent",
                "the raw tail is a ceiling on recency-carried context only; "
                "older evidence could in principle beat it",
                "'within noise' means not detected at this n, never 'no effect'",
            ]}


def format_history_report(rep) -> str:
    out = [f"HANDOFF BENCH (history) {rep['task_id']} exp #{rep['exp_id']} "
           f"cutoff #{rep['cutoff']} resume_model={rep['resume_model']}", ""]
    w = max(len(a) for a in rep["arms"])
    for name, a in sorted(rep["arms"].items(), key=lambda kv: -kv[1]["mean"]):
        out.append(f"  {name:<{w}}  score {a['mean']:.2f} ± {a['sd']:.2f}  "
                   f"ctx ~{a['ctx_tokens']}tok  cites {a['citations_mean']} "
                   f"(hallucinated {a['hallucinated_citations']})")
    out.append("")
    out.append(f"  comparisons (p-floor {rep['p_floor']}):")
    for c in rep["comparisons"]:
        bits = [f"    {c['arm']:<{w}}"]
        if "vs_no_history" in c:
            bits.append(f"vs none {c['vs_no_history']:+.2f} (p={c['p_vs_none']}, "
                        f"{c['verdict_vs_none']})")
        if "vs_raw_tail" in c:
            bits.append(f"vs raw-tail {c['vs_raw_tail']:+.2f} "
                        f"(p={c['p_vs_ceiling']}, {c['verdict_vs_ceiling']})")
        out.append("  ".join(bits))
    out.append("")
    arm_names = sorted(rep["arms"])
    out.append("  fact                        " + "  ".join(
        f"{a[:9]:>9}" for a in arm_names))
    for fid, row in rep["fact_rates"].items():
        rates = "  ".join(f"{row['rates'].get(a, 0):>9.2f}" for a in arm_names)
        pen = "  [penalty]" if row["weight"] < 0 else ""
        out.append(f"  {fid:<27} {rates}{pen}")
    out.append("")
    out.append("This result does not license:")
    for line in rep["not_licensed"]:
        out.append(f"  - {line}")
    return "\n".join(out)


# --- cross-model / cross-vendor ---------------------------------------------

def cmd_cross(args):
    """Resume the SAME staged interruption with a different tier (sonnet) and
    a different vendor (codex), from the same automatically compiled
    checkpoint. Small n, reported descriptively — existence evidence for
    model-independent resumption, not a powered comparison."""
    work = Path(args.staged_dir)
    state = json.loads((work / "staged.json").read_text())
    ckpt = (RESULTS / args.context_from / "context-checkpoint_distilled.txt")
    if not ckpt.exists():
        sys.exit(f"no stored checkpoint context at {ckpt} (run run-staged first)")
    ctx = {"text": ckpt.read_text(),
           "desc": "contextd distilled checkpoint (structured, anchor-verified)"}
    none_ctx = {"text": "", "desc": "repository only"}
    runners = {
        "sonnet_checkpoint": lambda p: run_claude(p, "sonnet"),
        "sonnet_no_history": lambda p: run_claude(p, "sonnet"),
        "codex_checkpoint": run_codex,
        "codex_no_history": run_codex,
    }
    spec = {"task_id": "handoff-staged-cross-v1", "track": "cross",
            "staged_dir": str(work), "n_per_arm": args.n,
            "checkpoint_from": args.context_from,
            "arms": {k: {"desc": ("checkpoint" if "checkpoint" in k
                                  else "no history")} for k in runners},
            "expectation": (
                "Existence test, preregistered before runs: can a different "
                "tier and a different vendor resume from the same contextd "
                "checkpoint? Success = checkpoint arms preserve the dialogue-"
                "only constraints (holdout tests) where the paired no-history "
                "arms do not. Small n; descriptive."),
            "registered": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())}
    exp_id = record("experiment", spec)
    print(f"preregistered cross-resumption as live event #{exp_id}")
    outdir = RESULTS / f"handoff-cross-exp{exp_id}"
    (outdir / "transcripts").mkdir(parents=True, exist_ok=True)

    def one(arm, i):
        c = ctx if "checkpoint" in arm else none_ctx
        prompt = staged_prompt(arm, c, state)
        return arm, i, runners[arm](prompt)

    jobs = [(a, i) for a in runners for i in range(args.n)]
    results = []
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = [ex.submit(one, a, i) for a, i in jobs]
        for fut in as_completed(futs):
            arm, i, r = fut.result()
            sc = st.score_phase2(Path(state["repo"]),
                                 Path(tempfile.mkdtemp(prefix=f"cross-{arm}-")),
                                 r["text"])
            run_meta = {"exp_id": exp_id, "arm": arm, "run": i,
                        "score": sc["score"],
                        "public_frac": sc["public"]["frac"],
                        "holdout_frac": sc["holdout"]["frac"],
                        "brief_score": sc["brief"]["score"],
                        "applied": sc["applied"], "exit": r["exit"],
                        "duration_ms": r["duration_ms"],
                        "output": r["text"][:20000]}
            rid = record("exp_run", run_meta)
            results.append(run_meta)
            (outdir / "transcripts" / f"{arm}-{i}.md").write_text(
                f"# cross / {arm} / run {i}\nscore {sc['score']}\n\n"
                f"## Output\n\n{r['text']}\n")
            print(f"  {arm}#{i} score {sc['score']:.2f} "
                  f"(hold {sc['holdout']['frac']:.2f}) event #{rid}", flush=True)

    by_arm = {}
    for r in results:
        by_arm.setdefault(r["arm"], []).append(r)
    rep = {"exp_id": exp_id, "task_id": spec["task_id"], "track": "cross",
           "arms": {a: {"n": len(rs),
                        "mean": round(_mean([r["score"] for r in rs]), 4),
                        "holdout_mean": round(_mean([r["holdout_frac"] for r in rs]), 4),
                        "public_mean": round(_mean([r["public_frac"] for r in rs]), 4),
                        "brief_mean": round(_mean([r["brief_score"] for r in rs]), 4)}
                    for a, rs in by_arm.items()},
           "not_licensed": ["small-n existence evidence, not a powered comparison"]}
    rep_id = record("exp_report", rep)
    (outdir / "report.json").write_text(json.dumps(rep, indent=2))
    print(f"\ncross report -> live event #{rep_id}")
    for a, s in sorted(rep["arms"].items()):
        print(f"  {a:<22} score {s['mean']:.2f}  holdout {s['holdout_mean']:.2f} "
              f" public {s['public_mean']:.2f}  brief {s['brief_mean']:.2f}")


# --- causal minimality: attack the winning checkpoint ------------------------

ANCHOR_STRIP = __import__("re").compile(r"\s*\[\d+(?:[,\s-]+\d+)*\]")
SECTION_RX = __import__("re").compile(
    r"^(?:#+\s*|\*\*\s*)?(OBJECTIVE|STATE|DECISIONS|REJECTED|OPEN|NEXT)\b.*$",
    __import__("re").M | __import__("re").I)


def split_sections(text: str) -> list:
    """Split a distilled checkpoint into (section_name, text) spans; text
    before the first recognized header is ('_head', ...)."""
    marks = list(SECTION_RX.finditer(text))
    out = []
    if not marks or marks[0].start() > 0:
        out.append(("_head", text[: marks[0].start() if marks else len(text)]))
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        out.append((m.group(1).upper(), text[m.start():end]))
    return out


def ablate_variants(text: str) -> dict:
    """Component removals for a distilled checkpoint. Also works loosely on
    the raw package (== headers won't match section names; only the generic
    variants apply there)."""
    sections = split_sections(text)

    def drop(names):
        return "".join(t for n, t in sections if n not in names)

    variants = {
        "full": text,
        "no_anchors": ANCHOR_STRIP.sub("", text),
    }
    present = {n for n, _ in sections}
    if {"STATE"} & present:
        variants["no_state"] = drop({"STATE"})
    if {"DECISIONS", "REJECTED"} & present:
        variants["no_decisions_rejected"] = drop({"DECISIONS", "REJECTED"})
    if {"OPEN", "NEXT"} & present:
        variants["no_open_next"] = drop({"OPEN", "NEXT"})
    return variants


def cmd_ablate(args):
    case = CASES[args.case]
    src = RESULTS / args.context_from / "context-checkpoint_distilled.txt"
    if not src.exists():
        sys.exit(f"no stored checkpoint at {src}")
    text = src.read_text()
    variants = ablate_variants(text)
    log = subprocess.run(
        ["git", "-C", str(REPO), "log", "--oneline", "-8", case["commit"]],
        capture_output=True, text=True).stdout.strip()
    spec = {"task_id": f"handoff-{args.case}-ablation-v1", "track": "ablation",
            "cutoff": case["cutoff"], "resume_model": args.model,
            "n_per_arm": args.n, "context_from": args.context_from,
            "arms": {name: {"ctx_tokens": est_tokens(t)}
                     for name, t in variants.items()},
            "rubric": case["rubric"],
            "expectation": (
                "Preregistered before runs: which checkpoint components carry "
                "continuation? Prior synthesis evidence (#41325..#41485) "
                "predicts no_anchors costs citability but may not cost rubric "
                "score (facts are lexical); section removals test whether the "
                "structured state/decisions/open-loop content is load-bearing "
                "or padding. Any variant statistically indistinguishable from "
                "full at a fraction of tokens argues for deleting the rest."),
            "registered": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())}
    exp_id = record("experiment", spec)
    print(f"preregistered ablation as live event #{exp_id} "
          f"({len(variants)} variants x {args.n})")
    outdir = RESULTS / f"handoff-{args.case}-ablation-exp{exp_id}"
    (outdir / "transcripts").mkdir(parents=True, exist_ok=True)
    for name, t in variants.items():
        (outdir / f"variant-{name}.txt").write_text(t)

    def one(name, i):
        block = (f"=== PROJECT MEMORY (contextd distilled checkpoint, "
                 f"variant {name}) ===\n{variants[name]}")
        prompt = TASK_TEMPLATE.format(context_block=block,
                                      commit=case["commit"], log=log)
        return name, i, run_claude(prompt, args.model)

    results = []
    jobs = [(v, i) for v in variants for i in range(args.n)]
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = [ex.submit(one, v, i) for v, i in jobs]
        for fut in as_completed(futs):
            name, i, r = fut.result()
            sc = score_output(case["rubric"], r["text"])
            meta = {"exp_id": exp_id, "arm": name, "run": i,
                    "ctx_tokens": est_tokens(variants[name]),
                    "score": sc["score"], "hits": sc["hits"],
                    "exit": r["exit"], "duration_ms": r["duration_ms"],
                    "resume_model": args.model, "output": r["text"][:20000]}
            record("exp_run", meta)
            results.append(meta)
            (outdir / "transcripts" / f"{name}-{i}.md").write_text(
                f"# ablation {name} run {i}\nscore {sc['score']}\n\n"
                f"{r['text']}\n")
            print(f"  [{len(results)}/{len(jobs)}] {name}#{i} "
                  f"score {sc['score']:.2f}", flush=True)

    by_arm = {}
    for r in results:
        by_arm.setdefault(r["arm"], []).append(r["score"])
    full = by_arm.get("full", [])
    rows = []
    for name, scores in by_arm.items():
        row = {"variant": name, "n": len(scores),
               "mean": round(_mean(scores), 4), "sd": round(_sd(scores), 4),
               "ctx_tokens": est_tokens(variants[name])}
        if name != "full" and full:
            p = perm_test(full, scores)
            row.update(delta_vs_full=round(_mean(scores) - _mean(full), 4),
                       p=p, verdict=verdict(p))
        rows.append(row)
    rep = {"exp_id": exp_id, "task_id": spec["task_id"], "track": "ablation",
           "rows": sorted(rows, key=lambda r: -r["mean"]),
           "p_floor": p_floor(args.n, args.n),
           "not_licensed": [
               "component effects at one cutoff, one model; lexical rubric",
               "'within noise' means not detected at this n, never 'no effect'",
           ]}
    rep_id = record("exp_report", rep)
    (outdir / "report.json").write_text(json.dumps(rep, indent=2))
    print(f"\nablation report -> live event #{rep_id}")
    for row in rep["rows"]:
        extra = (f"  Δ {row['delta_vs_full']:+.2f} p={row['p']} {row['verdict']}"
                 if "p" in row else "  (baseline)")
        print(f"  {row['variant']:<22} {row['mean']:.2f} ± {row['sd']:.2f} "
              f" ctx ~{row['ctx_tokens']}tok{extra}")


def cmd_report(args):
    import sqlite3
    conn = sqlite3.connect(f"file:{LIVE_DB}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT meta FROM events WHERE kind='exp_report' "
        "AND json_extract(meta,'$.exp_id')=? ORDER BY id DESC LIMIT 1",
        (args.exp_id,)).fetchone()
    if not row:
        sys.exit(f"no handoff report for experiment #{args.exp_id}")
    rep = json.loads(row["meta"])
    if rep.get("track") == "history":
        print(format_history_report(rep))
    elif rep.get("track") == "staged":
        print(format_staged_report(rep))
    else:
        print(json.dumps(rep, indent=2))


def main():
    p = argparse.ArgumentParser(description="checkpoint/resume benchmark")
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("stage")
    sp.add_argument("--dir")
    sp.add_argument("--model", default="haiku")
    sp = sub.add_parser("run-staged")
    sp.add_argument("staged_dir")
    sp.add_argument("--model", default="haiku")
    sp.add_argument("--n", type=int, default=4)
    sp.add_argument("--jobs", type=int, default=3)
    sp = sub.add_parser("run-history")
    sp.add_argument("case", choices=sorted(CASES))
    sp.add_argument("--model", default="haiku")
    sp.add_argument("--n", type=int, default=4)
    sp.add_argument("--jobs", type=int, default=3)
    sp.add_argument("--views-root")
    sp.add_argument("--keep-view", action="store_true")
    sp = sub.add_parser("cross")
    sp.add_argument("staged_dir")
    sp.add_argument("context_from",
                    help="results dir name holding context-checkpoint_distilled.txt")
    sp.add_argument("--n", type=int, default=2)
    sp.add_argument("--jobs", type=int, default=2)
    sp = sub.add_parser("ablate")
    sp.add_argument("case", choices=sorted(CASES))
    sp.add_argument("context_from",
                    help="results dir name holding context-checkpoint_distilled.txt")
    sp.add_argument("--model", default="haiku")
    sp.add_argument("--n", type=int, default=4)
    sp.add_argument("--jobs", type=int, default=3)
    sp = sub.add_parser("report")
    sp.add_argument("exp_id", type=int)
    args = p.parse_args()
    {"stage": cmd_stage, "run-staged": cmd_run_staged,
     "run-history": cmd_run_history, "cross": cmd_cross,
     "ablate": cmd_ablate, "report": cmd_report}[args.cmd](args)


if __name__ == "__main__":
    main()
