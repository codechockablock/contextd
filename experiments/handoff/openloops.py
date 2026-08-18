#!/usr/bin/env python
"""The open-loops compiler stratum — UNDER TEST, outside the kernel until an
experiment earns it (the same admission rule that kept the connective ranker
out when it lost its trial).

Motivating measurement (exp #41905, r2-ranker-verdict): across ALL eight
resumption arms — including a 12k-token raw tail and interactive MCP recall —
the `next_check` rubric fact scored ~0. The open thread that was neither
recent nor lexically near the task hint (the pre-cutoff 'stronger model'
question) survived in no representation. Hypothesis: a checkpoint stratum
that selects OLD-BUT-OPEN material can carry such threads.

Policy under test, model-free: among dialogue messages OLDER than the raw
tail window, rank by density of generic deferral/open-loop language
(markers below) per 1k estimated tokens and pack a fixed budget share,
deduplicated against every other stratum. Nothing in the policy names the
target thread's subject matter.

Design iteration, recorded before preregistration: the first draft ranked
ALL pre-tail messages and a dry selection run (no model calls, no scoring)
surfaced months-old material from unrelated eras (#16581, #26915, #31729,
#31877, #38646). Rejected at design time on general grounds: resumption
cares about the active project era's open loops, not the life log's. The
candidate window is therefore the most recent WORKING_ERA pre-tail messages.
The designer did NOT check whether any particular event (including the known
target thread) falls inside that window before running.

Lexicon provenance and circularity caveat, recorded before any run: the
designer has read the r2 TAIL (which contains the phrase 'recorded thread to
pull' in the verdict message) and has seen grep SNIPPETS of the pre-tail
target events #41376/#41379 (matched on 'stronger model'). The lexicon
deliberately contains no domain terms from that thread (no 'model', 'tier',
'sonnet', 'prediction', 'bundle'); it is generic deferral language. The test
is whether generic open-loop language surfaces the thread. If it does not,
that is itself the finding: open loops are not reliably lexically marked,
and carrying them needs structural tracking (e.g. reconciler-noted open
threads) rather than surface markers.
"""

import json
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from contextd.experiment import p_floor, perm_test, score_output, verdict  # noqa: E402
from experiments.handoff.bench import TASK_TEMPLATE, _mean, _sd  # noqa: E402
from experiments.handoff.cases import CASES  # noqa: E402
from experiments.handoff.common import (REPO, RESULTS, contextd_home,  # noqa: E402
                                        extract_citations, record, run_claude,
                                        view_conn)

# contextd.gate dispatches retrieval through a provider that contextd.search
# registers at import time (lane T). A process that assembles a disclosure
# without importing it gets an empty candidate set, not an error — importing it
# here is what keeps this script's recall working. Pinned by
# tests/test_gate_retrieval_hook.py::test_every_retrieval_caller_registers.
import contextd.search  # noqa: F401

MARKERS = [
    r"\bopen (?:question|thread|loop|item|issue)s?\b",
    r"\bremains? (?:open|unresolved|unanswered|untested|to be)\b",
    r"\bunresolved\b", r"\bunanswered\b", r"\bnot yet\b", r"\byet to\b",
    r"\bdefer(?:red|s)?\b", r"\bpostpon", r"\bpark(?:ed|ing)\b",
    r"\brevisit\b", r"\bfollow[- ]up\b", r"\bTODO\b", r"\bbacklog\b",
    r"\bpending\b", r"\bworth (?:testing|checking|trying)\b",
    r"\bif .{0,40}\bever\b", r"\bwould (?:settle|answer|confirm|tell)\b",
    r"\bstill (?:need|needs|unknown|unclear|open)\b",
    r"\bnext (?:step|check|experiment|run)s?\b",
    r"\bthread to pull\b", r"\bhaven'?t\b", r"\bdidn'?t (?:yet|get to)\b",
    r"\bplan(?:ned)? to\b", r"\bwe(?:'ll| will) (?:need|want|run|test)\b",
    r"\beventually\b", r"\bto be (?:determined|decided|tested)\b",
    r"\buntested\b", r"\bquestion (?:is|remains)\b",
]
_RX = [re.compile(m, re.I) for m in MARKERS]

# candidate horizon: the most recent pre-tail messages that plausibly belong
# to the active project era (a few days of work), not the whole life log —
# see the design-iteration note in the module docstring
WORKING_ERA = 300


def loop_density(text: str) -> float:
    n = max(1, len(text) // 4)
    return sum(len(rx.findall(text)) for rx in _RX) / n * 1000


def select_v2(conn, cfg, budget: int, task_hint: str) -> dict:
    """The kernel's stratification plus an open_loops stratum carved out of
    the tail share: recall .20, notes .10, episodes .20, open_loops .20,
    tail .30 (control keeps the kernel's own shares at the same total)."""
    from contextd.gate import select_items
    from contextd.handoff import _pack, _render
    shares = {"tail": 0.30, "episodes": 0.20, "notes": 0.10,
              "recall": 0.20, "open_loops": 0.20}
    budgets = {k: int(budget * v) for k, v in shares.items()}
    taken: set = set()

    recall_items = []
    if task_hint:
        for it in select_items(conn, cfg, task_hint, budgets["recall"]):
            if it["id"] not in taken:
                recall_items.append({"id": it["id"], "header": it["header"],
                                     "text": it["text"],
                                     "est_tokens": it["est_tokens"]})
                taken.add(it["id"])

    rows = conn.execute
    notes = _pack((_render(cfg, r) for r in rows(
        "SELECT * FROM events WHERE kind='note' "
        "AND json_extract(meta,'$.actor')='human' ORDER BY id DESC")),
        budgets["notes"], taken)
    episodes = _pack((_render(cfg, r) for r in rows(
        "SELECT * FROM events WHERE kind='note' "
        "AND json_extract(meta,'$.actor')!='human' "
        "AND json_extract(meta,'$.derivation') IS NOT NULL "
        "ORDER BY id DESC")),
        budgets["episodes"], taken)
    tail_rows = rows(
        "SELECT * FROM events WHERE source='claude_code' AND kind='message' "
        "ORDER BY id DESC LIMIT 400").fetchall()
    tail = _pack(
        (_render(cfg, r, extra=f" role={json.loads(r['meta'] or '{}').get('role', '?')}")
         for r in tail_rows), budgets["tail"], taken)

    tail_start = min((it["id"] for it in tail), default=0)
    candidates = rows(
        "SELECT * FROM events WHERE source='claude_code' AND kind='message' "
        "AND id < ? AND length(COALESCE(content,'')) >= 200 "
        "ORDER BY id DESC LIMIT ?",
        (tail_start, WORKING_ERA)).fetchall()
    scored = sorted(
        ((loop_density(r["content"] or ""), r) for r in candidates),
        key=lambda t: (-t[0], -t[1]["id"]))
    open_loops = _pack(
        (_render(cfg, r, extra=f" role={json.loads(r['meta'] or '{}').get('role', '?')}"
                               " [pre-tail, open-loop-ranked]")
         for _, r in scored),
        budgets["open_loops"], taken)
    open_loops.sort(key=lambda it: it["id"])

    for section in (notes, episodes, tail):
        section.reverse()
    return {"tail": tail, "episodes": episodes, "notes": notes,
            "recall": recall_items, "open_loops": open_loops,
            "tail_start": tail_start}


def compile_v2(conn, cfg, budget: int, task_hint: str, repo: dict) -> dict:
    from contextd.db import _db_tip
    from contextd.gate import disclose
    from contextd.handoff import render_package
    sel = select_v2(conn, cfg, budget, task_hint)
    tip = _db_tip(conn)["id"]
    base = render_package({k: sel[k] for k in
                           ("tail", "episodes", "notes", "recall")},
                          repo=repo, tip=tip)
    if sel["open_loops"]:
        body = "\n\n".join(it["header"] + "\n" + it["text"]
                           for it in sel["open_loops"])
        section = ("== OPEN THREADS (older material ranked by open-loop "
                   "language; may contain unresolved commitments) ==\n" + body)
        marker = "== RAW DIALOGUE TAIL"
        base = (base.replace(marker, section + "\n\n" + marker, 1)
                if marker in base else base + "\n\n" + section)
    ids = sorted({it["id"] for k in ("tail", "episodes", "notes", "recall",
                                     "open_loops") for it in sel[k]})
    d = disclose(conn, cfg, base, {
        "type": "checkpoint", "mode": "checkpoint_v2_openloops", "tip": tip,
        "task_hint": task_hint, "items": ids, "client": "openloops-exp"})
    return {"package": d["content"], "items": ids, "tip": tip,
            "egress_id": d["egress_id"], "est_tokens": d["est_tokens"],
            "open_loop_ids": [it["id"] for it in sel["open_loops"]]}


def build_contexts(case_name: str, view_home: Path) -> dict:
    from contextd.handoff import compile_checkpoint
    case = CASES[case_name]
    repo_hist = {"branch": "master", "commit": case["commit"],
                 "log": subprocess.run(
                     ["git", "-C", str(REPO), "log", "--oneline", "-8",
                      case["commit"]], capture_output=True, text=True
                 ).stdout.strip(),
                 "status": "", "diffstat": ""}
    conn, cfg = view_conn(view_home)
    with contextd_home(view_home):
        v1 = compile_checkpoint(conn, cfg, budget=4000,
                                task_hint=case["task_hint"], repo=repo_hist,
                                client="openloops-exp")
        v2 = compile_v2(conn, cfg, 4000, case["task_hint"], repo_hist)
    return {"ckpt_v1": {"text": v1["package"], "ids": v1["items"]},
            "ckpt_openloops": {"text": v2["package"], "ids": v2["items"],
                               "open_loop_ids": v2["open_loop_ids"]},
            "log": repo_hist["log"]}


def run_case(case_name: str, view_home: Path, model: str, n: int,
             jobs: int, exp_id: int, outdir: Path) -> list:
    case = CASES[case_name]
    contexts = build_contexts(case_name, view_home)
    for arm in ("ckpt_v1", "ckpt_openloops"):
        (outdir / f"context-{case_name}-{arm}.txt").write_text(
            contexts[arm]["text"])
    ol = contexts["ckpt_openloops"].get("open_loop_ids", [])
    print(f"  {case_name}: open-loop stratum selected events {ol}")

    def one(arm, i):
        block = (f"=== PROJECT MEMORY (contextd compiled checkpoint, "
                 f"variant {arm}) ===\n{contexts[arm]['text']}")
        prompt = TASK_TEMPLATE.format(context_block=block,
                                      commit=case["commit"],
                                      log=contexts["log"])
        return arm, i, run_claude(prompt, model)

    results = []
    jobs_list = [(a, i) for a in ("ckpt_v1", "ckpt_openloops")
                 for i in range(n)]
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        futs = [ex.submit(one, a, i) for a, i in jobs_list]
        for fut in as_completed(futs):
            arm, i, r = fut.result()
            sc = score_output(case["rubric"], r["text"])
            cites = extract_citations(r["text"], contexts[arm]["ids"])
            meta = {"exp_id": exp_id, "case": case_name, "arm": arm, "run": i,
                    "ctx_tokens": max(1, len(contexts[arm]["text"]) // 4),
                    "score": sc["score"], "hits": sc["hits"],
                    "citations": cites, "exit": r["exit"],
                    "duration_ms": r["duration_ms"],
                    "output": r["text"][:20000]}
            record("exp_run", meta)
            results.append(meta)
            (outdir / f"{case_name}-{arm}-{i}.md").write_text(
                f"# openloops / {case_name} / {arm} / run {i}\n"
                f"score {sc['score']}\nhits: {json.dumps(sc['hits'])}\n\n"
                f"{r['text']}\n")
            print(f"  [{len(results)}/{len(jobs_list)}] {case_name}/{arm}#{i} "
                  f"score {sc['score']:.2f} next_check="
                  f"{sc['hits'].get('next_check')}", flush=True)
    return results


def main():
    model, n, jobs = "haiku", 4, 3
    views = Path("runs/handoff-20260812/views")
    spec = {
        "task_id": "handoff-openloops-stratum-v1", "track": "openloops-stratum",
        "resume_model": model, "n_per_arm": n,
        "cases": {"r2-ranker-verdict": {"cutoff": CASES["r2-ranker-verdict"]["cutoff"],
                  "role": "primary"},
                  "r1-decomposition": {"cutoff": CASES["r1-decomposition"]["cutoff"],
                  "role": "non-degradation control"}},
        "arms": {"ckpt_v1": "kernel compiler, baseline shares",
                 "ckpt_openloops": "same 4000-token budget; open_loops .20 "
                                   "carved from tail: the most recent "
                                   f"{WORKING_ERA} pre-tail messages ranked "
                                   "by generic deferral-language density"},
        "design_iteration": (
            "Unscoped lookback rejected at design time: a dry selection (no "
            "model calls, no scoring) surfaced months-old unrelated-era "
            "events #16581 #26915 #31729 #31877 #38646. Candidate window "
            f"scoped to the {WORKING_ERA} most recent pre-tail messages on "
            "general active-era grounds; target-inclusion was not checked "
            "before running."),
        "lexicon": MARKERS,
        "lexicon_caveat": (
            "Designer read the r2 tail and grep snippets of the pre-tail "
            "target thread (#41376/#41379, matched on 'stronger model') "
            "before writing the lexicon; the lexicon contains only generic "
            "deferral language, no domain terms from that thread. Recorded "
            "per the connective-ranker precedent."),
        "expectation": (
            "Preregistered before any run. PRIMARY ENDPOINT: r2 next_check "
            "hit rate, ckpt_openloops vs ckpt_v1 (v1 baseline was 0.00 in exp "
            "#41905). Success: next_check rises with total score not "
            "degrading beyond noise. Interpretable failures: (a) the stratum "
            "selects wrap-up boilerplate, displacing tail content and "
            "lowering verdict facts — stratum not earned; (b) next_check "
            "stays 0 because the thread is not lexically marked by generic "
            "deferral language — open loops need structural tracking "
            "(reconciler-noted threads), not surface markers; that negative "
            "is as valuable as the positive. r1 is a non-degradation "
            "control: its answer lives in the tail, so ckpt_openloops "
            "should not lose to ckpt_v1 beyond noise there."),
        "registered": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
    }
    exp_id = record("experiment", spec)
    print(f"preregistered openloops-stratum experiment as live event #{exp_id}")
    outdir = RESULTS / f"handoff-openloops-exp{exp_id}"
    outdir.mkdir(parents=True, exist_ok=True)

    all_results = []
    for case_name in ("r2-ranker-verdict", "r1-decomposition"):
        all_results += run_case(case_name, views / case_name, model, n, jobs,
                                exp_id, outdir)

    rep = {"exp_id": exp_id, "task_id": spec["task_id"],
           "track": "openloops-stratum", "cases": {}}
    for case_name in ("r2-ranker-verdict", "r1-decomposition"):
        by_arm = {}
        for r in all_results:
            if r["case"] == case_name:
                by_arm.setdefault(r["arm"], []).append(r)
        entry = {}
        for arm, rs in by_arm.items():
            scores = [r["score"] for r in rs]
            entry[arm] = {
                "n": len(rs), "mean": round(_mean(scores), 4),
                "sd": round(_sd(scores), 4), "scores": scores,
                "ctx_tokens": rs[0]["ctx_tokens"],
                "fact_rates": {f["id"]: round(
                    sum(1 for r in rs if r["hits"].get(f["id"])) / len(rs), 3)
                    for f in CASES[case_name]["rubric"]["facts"]},
            }
        if len(entry) == 2:
            a, b = entry["ckpt_v1"]["scores"], entry["ckpt_openloops"]["scores"]
            p = perm_test(a, b)
            entry["comparison"] = {
                "delta": round(_mean(b) - _mean(a), 4), "p": p,
                "p_floor": p_floor(len(a), len(b)), "verdict": verdict(p)}
        rep["cases"][case_name] = entry
    rep["not_licensed"] = [
        "one lexicon, one model, two cutoffs; the primary endpoint is a "
        "single lexical fact",
        "'within noise' means not detected at this n, never 'no effect'",
    ]
    rep_id = record("exp_report", rep)
    (outdir / "report.json").write_text(json.dumps(rep, indent=2))
    print(f"\nreport -> live event #{rep_id}")
    for case_name, entry in rep["cases"].items():
        print(f"\n{case_name}:")
        for arm in ("ckpt_v1", "ckpt_openloops"):
            e = entry[arm]
            nc = e["fact_rates"].get("next_check")
            nc_s = f"  next_check {nc:.2f}" if nc is not None else ""
            print(f"  {arm:<16} {e['mean']:.2f} ± {e['sd']:.2f} "
                  f"ctx ~{e['ctx_tokens']}tok{nc_s}")
        c = entry.get("comparison")
        if c:
            print(f"  Δ {c['delta']:+.2f}  p={c['p']} (floor {c['p_floor']})  "
                  f"{c['verdict']}")


if __name__ == "__main__":
    main()
