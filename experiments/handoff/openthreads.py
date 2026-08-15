#!/usr/bin/env python
"""The reconciler open-threads pass — STRUCTURAL open-loop tracking, under
test, outside the kernel until this trial earns it.

Lineage of the question (all in the ledger): exp #41905 measured that no
resumption representation carried an open thread that was neither recent nor
lexically near the task hint (next_check 0.00 across eight arms). The
lexical fix — a deferral-marker density stratum — failed its preregistered
trial (report #42011): per-token density surfaces status boilerplate, not
substantive threads. The licensed alternative is structural: let a
reconciler-style pass READ each episode and RECORD open threads as notes
with kernel-verified anchors, then give the checkpoint compiler a stratum
that selects those notes by their structural identity (actor tag), not by
any surface lexicon.

The pass mirrors hooks/reconcile.py exactly where it matters: the episode
dialogue is a gated, receipted disclosure; the note-writing model runs under
a single-use dispatch capability, so every note's anchors are verified by the
kernel against the disclosed bytes and invalid anchors are refused. Notes
land in the FROZEN VIEW (never the live archive) with actor =
CONTEXTD_CLIENT = 'openthreads', which is how the compiler stratum — and the
control arm's exclusion — identify them structurally.

Two segment kinds, on purpose: closed epochs (≥ MIN_MESSAGES dialogue
messages), and the UNCLOSED per-session segment between a session's last
epoch end and the cutoff — measured fact from the r2 view: the target
thread lives in exactly such an unclosed segment (its epoch closed at
#41369, three events before the thread), and its closed epoch was skipped
as self-documented, so closed-epoch notes alone cannot carry it. A daemon
that tracked open threads continuously would have covered both.

Comparison hygiene: the control checkpoint (ckpt_v1) is compiled BEFORE any
retro note exists in the view, and the v3 compiler excludes actor
'openthreads' from its episodes stratum, so the ONLY difference between
arms is the open-threads stratum itself.
"""

import json
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from contextd.capability import issue as issue_capability  # noqa: E402
from contextd.capability import token as capability_token  # noqa: E402
from contextd.experiment import p_floor, perm_test, score_output, verdict  # noqa: E402
from experiments.handoff.bench import TASK_TEMPLATE, _mean, _sd  # noqa: E402
from experiments.handoff.cases import CASES  # noqa: E402
from experiments.handoff.common import (REPO, RESULTS, contextd_home,  # noqa: E402
                                        extract_citations, record, run_claude,
                                        view_conn)

CLAUDE_BIN = "claude"
MODEL = "haiku"
MIN_MESSAGES = 6
MAX_SEGMENTS = 10  # newest-first; the active era's threads matter most
MAX_DIALOGUE_CHARS = 300_000
CLIENT = "openthreads"

PASS_PROMPT = """You are the archivist for a personal context daemon. Below is
the dialogue from one work episode (roles: user, assistant, delegation,
subagent); each message is prefixed with its bracketed archive event id,
e.g. [41234]. Your ONLY job is to record OPEN THREADS: questions raised but
not answered in this episode, checks or experiments planned or requested but
not yet run, work explicitly deferred to later, and commitments made but not
discharged. Do NOT record completed work, decisions, or facts — only what
remains open at the episode's end. For each open thread, write one note via
the contextd note tool, formatted as: "OPEN THREAD: <what remains to be
done, concretely> — status when last discussed: <one sentence>." Immediately
after each claim, cite the bracketed event id(s) that support it, exactly as
given — cite only ids that appear in this dialogue; never invent one. If
nothing is open, write no notes. When finished, reply with only: DONE"""


def segments(conn, cutoff: int) -> list:
    """Closed epochs plus unclosed per-session trailing segments, newest
    first. Every segment is a (label, session_id, start_id, end_id) span of
    pre-cutoff dialogue."""
    out = []
    last_end = {}
    for r in conn.execute(
            "SELECT id, meta FROM events WHERE kind='epoch' AND id <= ? "
            "ORDER BY id", (cutoff,)):
        m = json.loads(r["meta"])
        sid = m["session_id"]
        out.append((f"epoch-{r['id']}", sid,
                    m.get("start_event_id") or 0, m.get("end_event_id") or 0))
        last_end[sid] = max(last_end.get(sid, 0), m.get("end_event_id") or 0)
    for r in conn.execute(
            "SELECT DISTINCT json_extract(meta,'$.session_id') AS sid "
            "FROM events WHERE source='claude_code' AND kind='message' "
            "AND id <= ?", (cutoff,)):
        sid = r["sid"]
        start = last_end.get(sid, 0)
        tail_row = conn.execute(
            "SELECT MAX(id) AS m FROM events WHERE source='claude_code' "
            "AND kind='message' AND json_extract(meta,'$.session_id')=? "
            "AND id <= ?", (sid, cutoff)).fetchone()
        if tail_row["m"] and tail_row["m"] > start:
            out.append((f"unclosed-{sid[:8]}", sid, start, tail_row["m"]))
    def n_msgs(seg):
        _, sid, a, b = seg
        return conn.execute(
            "SELECT COUNT(*) FROM events WHERE source='claude_code' AND "
            "kind='message' AND json_extract(meta,'$.session_id')=? "
            "AND id > ? AND id <= ?", (sid, a, b)).fetchone()[0]
    out = [s for s in out if n_msgs(s) >= MIN_MESSAGES]
    out.sort(key=lambda s: -s[3])
    return out[:MAX_SEGMENTS]


def run_pass(view_home: Path, cutoff: int) -> dict:
    """Dispatch the open-threads pass over every segment of a frozen view.
    Notes land in the view under actor 'openthreads' with kernel-verified
    derivation; every dialogue disclosure is receipted in the view."""
    conn, cfg = view_conn(view_home)
    from contextd.gate import disclose, record_dispatch_outcome
    mcp_cfg = Path(tempfile.mkdtemp()) / "mcp.json"
    mcp_cfg.write_text(json.dumps({"mcpServers": {"contextd": {
        "command": str(REPO / ".venv" / "bin" / "ctx"),
        "args": ["serve", "--tools", "note"],
    }}}))
    stats = []
    with contextd_home(view_home):
        for label, sid, a, b in segments(conn, cutoff):
            msgs = conn.execute(
                "SELECT id, content, json_extract(meta,'$.role') AS role "
                "FROM events WHERE source='claude_code' AND kind='message' "
                "AND json_extract(meta,'$.session_id')=? AND id > ? AND id <= ? "
                "ORDER BY id", (sid, a, b)).fetchall()
            dialogue = "\n\n".join(
                f"[{m['id']}] {m['role']}: {m['content']}"
                for m in msgs)[:MAX_DIALOGUE_CHARS]
            disclosure = disclose(conn, cfg, f"{PASS_PROMPT}\n\n{dialogue}", {
                "type": "openthreads_dialogue", "segment": label,
                "model": MODEL, "items": [m["id"] for m in msgs],
                "client": CLIENT})
            import os
            env = os.environ.copy()
            env["CONTEXTD_HOME"] = str(Path(view_home).resolve())
            # a dispatch capability, not an event id: opaque, bound to this
            # disclosure's exact bytes and this session, single-use and
            # expiring (contextd/capability.py). The bare integer binding is
            # retired and now refuses rather than silently mis-binding.
            _cap = issue_capability(conn, disclosure["egress_id"],
                                    os.getuid(), "openthreads")
            env["CONTEXTD_DISPATCH_CAPABILITY"] = capability_token(_cap)
            env["CONTEXTD_DISPATCH_SESSION"] = "openthreads"
            env.pop("CONTEXTD_DERIVATION_SOURCE", None)
            env["CONTEXTD_CLIENT"] = CLIENT
            before = conn.execute(
                "SELECT COUNT(*) FROM events WHERE kind='note'").fetchone()[0]
            try:
                r = subprocess.run(
                    [CLAUDE_BIN, "-p", "--model", MODEL,
                     "--strict-mcp-config", "--mcp-config", str(mcp_cfg),
                     "--allowedTools", "mcp__contextd__note",
                     "--no-session-persistence"],
                    input=disclosure["content"], env=env,
                    capture_output=True, text=True, timeout=600,
                    cwd=tempfile.mkdtemp(prefix="ctx-openthreads-"))
            except subprocess.TimeoutExpired:
                record_dispatch_outcome(conn, disclosure["egress_id"], "timeout")
                stats.append({"segment": label, "error": "timeout"})
                continue
            record_dispatch_outcome(
                conn, disclosure["egress_id"],
                "succeeded" if r.returncode == 0 else "failed",
                exit=r.returncode)
            after = conn.execute(
                "SELECT COUNT(*) FROM events WHERE kind='note'").fetchone()[0]
            stats.append({"segment": label, "messages": len(msgs),
                          "notes": after - before, "exit": r.returncode})
            print(f"    pass {label}: {len(msgs)} msgs -> {after - before} notes",
                  flush=True)
    return {"segments": stats,
            "total_notes": sum(s.get("notes", 0) for s in stats)}


def select_v3(conn, cfg, budget: int, task_hint: str) -> dict:
    """The kernel stratification with an OPEN THREADS stratum selected by
    structural identity (actor = 'openthreads'), 20% carved from the tail —
    the same share the failed lexical stratum used, for comparability."""
    from contextd.gate import select_items
    from contextd.handoff import _pack, _render
    shares = {"tail": 0.30, "episodes": 0.20, "notes": 0.10,
              "recall": 0.20, "open_threads": 0.20}
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
        "AND json_extract(meta,'$.actor') NOT IN ('human', ?) "
        "AND json_extract(meta,'$.derivation') IS NOT NULL "
        "ORDER BY id DESC", (CLIENT,))),
        budgets["episodes"], taken)
    open_threads = _pack((_render(cfg, r) for r in rows(
        "SELECT * FROM events WHERE kind='note' "
        "AND json_extract(meta,'$.actor') = ? ORDER BY id DESC", (CLIENT,))),
        budgets["open_threads"], taken)
    tail = _pack(
        (_render(cfg, r, extra=f" role={json.loads(r['meta'] or '{}').get('role', '?')}")
         for r in rows(
             "SELECT * FROM events WHERE source='claude_code' "
             "AND kind='message' ORDER BY id DESC LIMIT 400")),
        budgets["tail"], taken)
    for section in (notes, episodes, open_threads, tail):
        section.reverse()
    return {"tail": tail, "episodes": episodes, "notes": notes,
            "recall": recall_items, "open_threads": open_threads}


def compile_v3(conn, cfg, budget: int, task_hint: str, repo: dict,
               cutoff: int) -> dict:
    from contextd.db import _db_tip
    from contextd.gate import disclose
    from contextd.handoff import render_package
    sel = select_v3(conn, cfg, budget, task_hint)
    base = render_package({k: sel[k] for k in
                           ("tail", "episodes", "notes", "recall")},
                          repo=repo, tip=cutoff)
    if sel["open_threads"]:
        body = "\n\n".join(it["header"] + "\n" + it["text"]
                           for it in sel["open_threads"])
        section = ("== OPEN THREADS (recorded by the episode reconciler; "
                   "unresolved at the interruption) ==\n" + body)
        marker = "== RAW DIALOGUE TAIL"
        base = (base.replace(marker, section + "\n\n" + marker, 1)
                if marker in base else base + "\n\n" + section)
    ids = sorted({it["id"] for k in sel for it in sel[k]})
    d = disclose(conn, cfg, base, {
        "type": "checkpoint", "mode": "checkpoint_v3_openthreads",
        "tip": _db_tip(conn)["id"], "task_hint": task_hint, "items": ids,
        "client": CLIENT})
    return {"package": d["content"], "items": ids,
            "egress_id": d["egress_id"], "est_tokens": d["est_tokens"],
            "open_thread_ids": [it["id"] for it in sel["open_threads"]]}


def run_case(case_name: str, view_home: Path, n: int, jobs: int,
             exp_id: int, outdir: Path) -> tuple:
    case = CASES[case_name]
    repo_hist = {"branch": "master", "commit": case["commit"],
                 "log": subprocess.run(
                     ["git", "-C", str(REPO), "log", "--oneline", "-8",
                      case["commit"]], capture_output=True, text=True
                 ).stdout.strip(), "status": "", "diffstat": ""}
    conn, cfg = view_conn(view_home)
    # control FIRST: compiled while zero retro notes exist in the view
    from contextd.handoff import compile_checkpoint
    with contextd_home(view_home):
        v1 = compile_checkpoint(conn, cfg, budget=4000,
                                task_hint=case["task_hint"], repo=repo_hist,
                                client=CLIENT)
    print(f"  {case_name}: running open-threads pass ...")
    pass_stats = run_pass(view_home, case["cutoff"])
    conn, cfg = view_conn(view_home)
    with contextd_home(view_home):
        v3 = compile_v3(conn, cfg, 4000, case["task_hint"], repo_hist,
                        case["cutoff"])
    contexts = {"ckpt_v1": {"text": v1["package"], "ids": v1["items"]},
                "ckpt_openthreads": {"text": v3["package"], "ids": v3["items"]}}
    for arm, c in contexts.items():
        (outdir / f"context-{case_name}-{arm}.txt").write_text(c["text"])
    print(f"  {case_name}: pass wrote {pass_stats['total_notes']} notes; "
          f"stratum selected {v3['open_thread_ids']}")

    def one(arm, i):
        block = (f"=== PROJECT MEMORY (contextd compiled checkpoint, "
                 f"variant {arm}) ===\n{contexts[arm]['text']}")
        prompt = TASK_TEMPLATE.format(context_block=block,
                                      commit=case["commit"],
                                      log=repo_hist["log"])
        return arm, i, run_claude(prompt, MODEL)

    results = []
    jobs_list = [(a, i) for a in contexts for i in range(n)]
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        futs = [ex.submit(one, a, i) for a, i in jobs_list]
        for fut in as_completed(futs):
            arm, i, r = fut.result()
            sc = score_output(case["rubric"], r["text"])
            meta = {"exp_id": exp_id, "case": case_name, "arm": arm, "run": i,
                    "ctx_tokens": max(1, len(contexts[arm]["text"]) // 4),
                    "score": sc["score"], "hits": sc["hits"],
                    "citations": extract_citations(r["text"], contexts[arm]["ids"]),
                    "exit": r["exit"], "duration_ms": r["duration_ms"],
                    "output": r["text"][:20000]}
            record("exp_run", meta)
            results.append(meta)
            (outdir / f"{case_name}-{arm}-{i}.md").write_text(
                f"# openthreads / {case_name} / {arm} / run {i}\n"
                f"score {sc['score']}\nhits: {json.dumps(sc['hits'])}\n\n"
                f"{r['text']}\n")
            print(f"  [{len(results)}/{len(jobs_list)}] {case_name}/{arm}#{i} "
                  f"score {sc['score']:.2f} next_check="
                  f"{sc['hits'].get('next_check')}", flush=True)
    return results, pass_stats


def main():
    n, jobs = 4, 3
    views = Path("runs/handoff-20260812/views")
    spec = {
        "task_id": "handoff-openthreads-reconciler-v1",
        "track": "openthreads-structural", "resume_model": MODEL,
        "n_per_arm": n, "pass_model": MODEL,
        "cases": {"r2-ranker-verdict": {"cutoff": CASES["r2-ranker-verdict"]["cutoff"],
                  "role": "primary"},
                  "r1-decomposition": {"cutoff": CASES["r1-decomposition"]["cutoff"],
                  "role": "non-degradation control"}},
        "arms": {"ckpt_v1": "kernel compiler baseline, compiled before any "
                            "retro note exists in the view",
                 "ckpt_openthreads": "same 4000-token budget; open_threads "
                                     ".20 carved from tail, selected "
                                     "STRUCTURALLY (actor=openthreads notes "
                                     "written by a reconciler-style pass with "
                                     "kernel-verified anchors)"},
        "pass_prompt": PASS_PROMPT,
        "segments_policy": (f"closed epochs and unclosed per-session trailing "
                            f"segments, >= {MIN_MESSAGES} messages, newest "
                            f"{MAX_SEGMENTS} first. Unclosed segments are "
                            "load-bearing by design: the r2 target thread "
                            "sits after its session's last closed epoch."),
        "expectation": (
            "Preregistered before any pass dispatch or arm run. PRIMARY "
            "ENDPOINT: r2 next_check rate, ckpt_openthreads vs ckpt_v1 "
            "(baseline 0.00 in exps #41905 and #42011-report runs). The "
            "extraction model is generic (told to record open threads, "
            "nothing about the rubric or the thread's subject). Success: "
            "next_check > 0 with total score not degrading beyond noise. "
            "Interpretable failures: (a) the pass writes no note about the "
            "thread — structural extraction misses it too, and open-loop "
            "carriage needs live tracking rather than retro distillation; "
            "(b) the note exists but the stratum's packing or the resumed "
            "model fails to use it — selection vs use dissociation; (c) "
            "boilerplate open-thread notes displace tail and cost verdict "
            "facts, as the lexical stratum did. r1 is a non-degradation "
            "control. Circularity note: the designer knows the target "
            "thread; the pass prompt and segments policy contain no "
            "domain terms from it and apply uniformly to all segments."),
        "registered": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
    }
    exp_id = record("experiment", spec)
    print(f"preregistered openthreads-reconciler trial as live event #{exp_id}")
    outdir = RESULTS / f"handoff-openthreads-exp{exp_id}"
    outdir.mkdir(parents=True, exist_ok=True)

    all_results, pass_info = [], {}
    for case_name in ("r2-ranker-verdict", "r1-decomposition"):
        res, stats = run_case(case_name, views / case_name, n, jobs,
                              exp_id, outdir)
        all_results += res
        pass_info[case_name] = stats

    rep = {"exp_id": exp_id, "task_id": spec["task_id"],
           "track": "openthreads-structural", "pass": pass_info, "cases": {}}
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
                    for f in CASES[case_name]["rubric"]["facts"]}}
        if len(entry) == 2:
            a = entry["ckpt_v1"]["scores"]
            b = entry["ckpt_openthreads"]["scores"]
            p = perm_test(a, b)
            entry["comparison"] = {"delta": round(_mean(b) - _mean(a), 4),
                                   "p": p, "p_floor": p_floor(len(a), len(b)),
                                   "verdict": verdict(p)}
        rep["cases"][case_name] = entry
    rep["not_licensed"] = [
        "retro pass over frozen views approximates continuous tracking; a "
        "live daemon pass could behave differently",
        "one pass model, one resumption model, two cutoffs; the primary "
        "endpoint is a single lexical fact",
        "'within noise' means not detected at this n, never 'no effect'",
    ]
    rep_id = record("exp_report", rep)
    (outdir / "report.json").write_text(json.dumps(rep, indent=2))
    print(f"\nreport -> live event #{rep_id}")
    for case_name, entry in rep["cases"].items():
        print(f"\n{case_name}:  (pass: "
              f"{pass_info[case_name]['total_notes']} notes)")
        for arm in ("ckpt_v1", "ckpt_openthreads"):
            e = entry[arm]
            nc = e["fact_rates"].get("next_check")
            nc_s = f"  next_check {nc:.2f}" if nc is not None else ""
            print(f"  {arm:<18} {e['mean']:.2f} ± {e['sd']:.2f} "
                  f"ctx ~{e['ctx_tokens']}tok{nc_s}")
        c = entry.get("comparison")
        if c:
            print(f"  Δ {c['delta']:+.2f}  p={c['p']} (floor {c['p_floor']})  "
                  f"{c['verdict']}")


if __name__ == "__main__":
    main()
