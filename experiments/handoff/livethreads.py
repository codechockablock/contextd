#!/usr/bin/env python
"""Live open/discharge thread tracking — the third mechanism aimed at the
handoff benchmark's one measured gap, under test outside the kernel.

Lineage (all in the ledger): the gap was measured in #41905 (no resumption
representation carried an open thread that was neither recent nor lexically
near the task hint); the lexical stratum failed (#42011 — density surfaces
boilerplate); the retro structural pass failed (#42067) but localized the
problem: extraction WORKS at open-looking moments (it caught the exact
target thread at the r1 cutoff) and fails when a later closure narrative
masks the one undischarged commitment in a batch-summarized window. The
missing piece is DISCHARGE STATE — a join over time.

Mechanism under test: a chronological simulation of a live janitor. The
pre-cutoff active era is split into episodes by the daemon's own quiescence
rule (>= claude.quiet_seconds of silence within a session), episodes are
processed in wall-clock order, and each dispatch sees (1) the currently
surviving open-thread notes and (2) the new episode's dialogue — both inside
one gated disclosure whose item list carries dialogue ids AND open-note ids,
so the kernel's derivation binding verifies every citation either way. The
model writes two note forms only:

    OPEN THREAD: <concrete> — status: <one sentence>   [dialogue ids]
    DISCHARGED [note-id]: <what discharged it>         [dialogue ids]

State is deterministic: surviving = OPEN notes not named by any later
DISCHARGED note. At the cutoff, the compiler's stratum is the surviving set,
ordered by max-anchor recency (fixing the packing inversion #42067 caught),
at the same 20% share the failed strata used.

Design constants, fixed before registration on general grounds:
- HORIZON_HOURS = 24: the active era (the whole experimental program fits);
  threads opened before the horizon are invisible — a stated limitation.
- MIN_MESSAGES = 2 (not the reconciler's 6): thread-openings happen in small
  exchanges; a 4-message "here's the ladder" reply is exactly the kind of
  moment batch passes lose. Cost per small dispatch is trivial.
- Fresh frozen views are rebuilt from the live archive so no prior trial's
  notes exist in either arm's database.

Zero future leakage: every episode, every open-set state, and every note
derives from pre-cutoff bytes inside a frozen view, in chronological order.
"""

import json
import re
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
CLIENT = "livethreads"
HORIZON_HOURS = 24
MIN_MESSAGES = 2
QUIET_SECONDS = 1200  # the daemon's own episode rule
LIVE_DB = Path("~/.contextd/contextd.db").expanduser()

PASS_PROMPT = """You are the live thread-tracker for a personal context
daemon. Below are (1) the CURRENTLY OPEN THREADS recorded from earlier
episodes, each with its bracketed note id, and (2) the dialogue of the
newest episode, each message with its bracketed event id.

Duties, in order:
A. DISCHARGE: for each currently-open thread that this episode resolved,
   executed, completed, or explicitly abandoned, write one note via the
   contextd note tool: "DISCHARGED [note-id]: <what discharged it>" — cite
   the open thread's note id exactly as listed, plus the dialogue event
   id(s) showing the discharge.
B. OPEN: for each thread this episode opened and did NOT itself resolve —
   questions raised but unanswered, checks or experiments proposed or
   requested but not run, work explicitly deferred, commitments not yet
   discharged — write one note: "OPEN THREAD: <what remains to be done,
   concretely> — status: <one sentence>" citing the dialogue event id(s).

Be conservative in both directions: do not discharge a thread unless this
dialogue shows it done or dropped, and do not open threads for vague
musings. Cite only bracketed ids that appear above; never invent one. If
nothing to record, write no notes. When finished, reply with only: DONE"""


def episodes(conn, cutoff: int) -> list:
    """Quiescence-split episodes across all sessions within the horizon,
    ordered chronologically by end time. Uniform rule; recorded epochs are
    deliberately ignored so every session is segmented identically."""
    rows = conn.execute(
        "SELECT id, json_extract(meta,'$.session_id') sid, "
        "COALESCE(json_extract(meta,'$.visited_unix'), "
        "CAST(strftime('%s', ts) AS INTEGER)) t "
        "FROM events WHERE source='claude_code' AND kind='message' "
        "AND id <= ? ORDER BY id", (cutoff,)).fetchall()
    tmax = max(r["t"] for r in rows)
    lo = tmax - HORIZON_HOURS * 3600
    by_sess = {}
    for r in rows:
        if r["t"] >= lo:
            by_sess.setdefault(r["sid"], []).append(r)
    eps = []
    for sid, ms in by_sess.items():
        cur = []
        for m in ms:
            if cur and m["t"] - cur[-1]["t"] >= QUIET_SECONDS:
                if len(cur) >= MIN_MESSAGES:
                    eps.append((sid, [x["id"] for x in cur], cur[-1]["t"]))
                cur = []
            cur.append(m)
        if len(cur) >= MIN_MESSAGES:
            eps.append((sid, [x["id"] for x in cur], cur[-1]["t"]))
    eps.sort(key=lambda e: e[2])
    return eps


DISCHARGE_RX = re.compile(r"DISCHARGED[:\s]*\[(\d+)\]", re.I)


def surviving_open(conn) -> list:
    """Deterministic state: OPEN notes by this client not named by any later
    DISCHARGED note. Returns rows ordered by max-anchor recency."""
    notes = conn.execute(
        "SELECT id, content, meta FROM events WHERE kind='note' "
        "AND json_extract(meta,'$.actor') = ? ORDER BY id", (CLIENT,)).fetchall()
    discharged = set()
    for n in notes:
        m = DISCHARGE_RX.search(n["content"] or "")
        if m:
            discharged.add(int(m.group(1)))
    out = []
    for n in notes:
        text = n["content"] or ""
        if DISCHARGE_RX.search(text) or n["id"] in discharged:
            continue
        if not text.upper().startswith("OPEN THREAD"):
            continue
        meta = json.loads(n["meta"] or "{}")
        anchors = (meta.get("derivation") or {}).get("anchors") or [0]
        out.append({"id": n["id"], "text": text, "recency": max(anchors)})
    out.sort(key=lambda n: -n["recency"])
    return out


def run_pass(view_home: Path, cutoff: int) -> dict:
    conn, cfg = view_conn(view_home)
    from contextd.gate import disclose, record_dispatch_outcome
    mcp_cfg = Path(tempfile.mkdtemp()) / "mcp.json"
    mcp_cfg.write_text(json.dumps({"mcpServers": {"contextd": {
        "command": str(REPO / ".venv" / "bin" / "ctx"),
        "args": ["serve", "--tools", "note"],
    }}}))
    stats = []
    with contextd_home(view_home):
        for k, (sid, msg_ids, _end) in enumerate(episodes(conn, cutoff)):
            open_now = surviving_open(conn)
            open_block = ("\n".join(f"[{n['id']}] {n['text']}"
                                    for n in open_now) or "(none yet)")
            msgs = conn.execute(
                "SELECT id, content, json_extract(meta,'$.role') AS role "
                "FROM events WHERE id IN (%s) ORDER BY id"
                % ",".join("?" * len(msg_ids)), msg_ids).fetchall()
            dialogue = "\n\n".join(
                f"[{m['id']}] {m['role']}: {m['content']}" for m in msgs)
            payload = (f"{PASS_PROMPT}\n\n=== CURRENTLY OPEN THREADS ===\n"
                       f"{open_block}\n\n=== EPISODE DIALOGUE ===\n"
                       f"{dialogue}")[:400_000]
            items = msg_ids + [n["id"] for n in open_now]
            disclosure = disclose(conn, cfg, payload, {
                "type": "livethreads_dialogue", "episode": k, "session": sid,
                "model": MODEL, "items": items, "client": CLIENT})
            import os
            env = os.environ.copy()
            env["CONTEXTD_HOME"] = str(Path(view_home).resolve())
            # a dispatch capability, not an event id: opaque, bound to this
            # disclosure's exact bytes and this session, single-use and
            # expiring (contextd/capability.py). The bare integer binding is
            # retired and now refuses rather than silently mis-binding.
            _cap = issue_capability(conn, disclosure["egress_id"],
                                    os.getuid(), "livethreads")
            env["CONTEXTD_DISPATCH_CAPABILITY"] = capability_token(_cap)
            env["CONTEXTD_DISPATCH_SESSION"] = "livethreads"
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
                    cwd=tempfile.mkdtemp(prefix="ctx-livethreads-"))
            except subprocess.TimeoutExpired:
                record_dispatch_outcome(conn, disclosure["egress_id"], "timeout")
                stats.append({"episode": k, "error": "timeout"})
                continue
            record_dispatch_outcome(
                conn, disclosure["egress_id"],
                "succeeded" if r.returncode == 0 else "failed",
                exit=r.returncode)
            after = conn.execute(
                "SELECT COUNT(*) FROM events WHERE kind='note'").fetchone()[0]
            stats.append({"episode": k, "session": sid[:8],
                          "messages": len(msg_ids), "open_before": len(open_now),
                          "notes": after - before, "exit": r.returncode})
            print(f"    ep{k} ({sid[:8]}, {len(msg_ids)} msgs, "
                  f"{len(open_now)} open) -> {after - before} notes", flush=True)
    final = surviving_open(view_conn(view_home)[0])
    return {"episodes": stats, "surviving": [n["id"] for n in final],
            "surviving_texts": [n["text"][:160] for n in final]}


def compile_v4(conn, cfg, budget: int, task_hint: str, repo: dict,
               cutoff: int) -> dict:
    from contextd.db import _db_tip
    from contextd.gate import disclose, est_tokens, select_items
    from contextd.handoff import _pack, _render, render_package
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
    episodes_sec = _pack((_render(cfg, r) for r in rows(
        "SELECT * FROM events WHERE kind='note' "
        "AND json_extract(meta,'$.actor') NOT IN ('human', ?) "
        "AND json_extract(meta,'$.derivation') IS NOT NULL "
        "ORDER BY id DESC", (CLIENT,))),
        budgets["episodes"], taken)
    open_rows = surviving_open(conn)  # already max-anchor-recency ordered
    by_id = {r["id"]: r for r in rows(
        "SELECT * FROM events WHERE kind='note' "
        "AND json_extract(meta,'$.actor') = ?", (CLIENT,)).fetchall()}
    open_threads = _pack((_render(cfg, by_id[n["id"]]) for n in open_rows
                          if n["id"] in by_id),
                         budgets["open_threads"], taken)
    tail = _pack(
        (_render(cfg, r, extra=f" role={json.loads(r['meta'] or '{}').get('role', '?')}")
         for r in rows(
             "SELECT * FROM events WHERE source='claude_code' "
             "AND kind='message' ORDER BY id DESC LIMIT 400")),
        budgets["tail"], taken)
    for section in (notes, episodes_sec, tail):
        section.reverse()
    base = render_package({"tail": tail, "episodes": episodes_sec,
                           "notes": notes, "recall": recall_items},
                          repo=repo, tip=cutoff)
    if open_threads:
        body = "\n\n".join(it["header"] + "\n" + it["text"]
                           for it in open_threads)
        section = ("== OPEN THREADS (live-tracked; still undischarged at the "
                   "interruption, most recently touched first) ==\n" + body)
        marker = "== RAW DIALOGUE TAIL"
        base = (base.replace(marker, section + "\n\n" + marker, 1)
                if marker in base else base + "\n\n" + section)
    ids = sorted({it["id"] for sec in (tail, episodes_sec, notes,
                                       recall_items, open_threads)
                  for it in sec})
    d = disclose(conn, cfg, base, {
        "type": "checkpoint", "mode": "checkpoint_v4_livethreads",
        "tip": _db_tip(conn)["id"], "task_hint": task_hint, "items": ids,
        "client": CLIENT})
    return {"package": d["content"], "items": ids,
            "egress_id": d["egress_id"], "est_tokens": est_tokens(base),
            "open_thread_ids": [it["id"] for it in open_threads]}


def run_case(case_name: str, view_home: Path, n: int, jobs: int,
             exp_id: int, outdir: Path) -> tuple:
    case = CASES[case_name]
    from contextd.handoff import compile_checkpoint, freeze_view
    import shutil
    if view_home.exists():
        shutil.rmtree(view_home)
    info = freeze_view(LIVE_DB, view_home, case["cutoff"])
    print(f"  {case_name}: fresh view, {info['events']} events, "
          f"tip #{info['tip']}")
    repo_hist = {"branch": "master", "commit": case["commit"],
                 "log": subprocess.run(
                     ["git", "-C", str(REPO), "log", "--oneline", "-8",
                      case["commit"]], capture_output=True, text=True
                 ).stdout.strip(), "status": "", "diffstat": ""}
    conn, cfg = view_conn(view_home)
    with contextd_home(view_home):
        v1 = compile_checkpoint(conn, cfg, budget=4000,
                                task_hint=case["task_hint"], repo=repo_hist,
                                client=CLIENT)
    print(f"  {case_name}: running live pass ...")
    pass_stats = run_pass(view_home, case["cutoff"])
    conn, cfg = view_conn(view_home)
    with contextd_home(view_home):
        v4 = compile_v4(conn, cfg, 4000, case["task_hint"], repo_hist,
                        case["cutoff"])
    contexts = {"ckpt_v1": {"text": v1["package"], "ids": v1["items"]},
                "ckpt_livethreads": {"text": v4["package"], "ids": v4["items"]}}
    for arm, c in contexts.items():
        (outdir / f"context-{case_name}-{arm}.txt").write_text(c["text"])
    print(f"  {case_name}: surviving open threads {pass_stats['surviving']}; "
          f"stratum packed {v4['open_thread_ids']}")

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
                f"# livethreads / {case_name} / {arm} / run {i}\n"
                f"score {sc['score']}\nhits: {json.dumps(sc['hits'])}\n\n"
                f"{r['text']}\n")
            print(f"  [{len(results)}/{len(jobs_list)}] {case_name}/{arm}#{i} "
                  f"score {sc['score']:.2f} next_check="
                  f"{sc['hits'].get('next_check')}", flush=True)
    return results, pass_stats


def main():
    n, jobs = 4, 3
    views = Path("runs/handoff-20260812/views-live")
    views.mkdir(parents=True, exist_ok=True)
    spec = {
        "task_id": "handoff-livethreads-v1", "track": "livethreads",
        "resume_model": MODEL, "pass_model": MODEL, "n_per_arm": n,
        "cases": {"r2-ranker-verdict": {"cutoff": CASES["r2-ranker-verdict"]["cutoff"],
                  "role": "primary"},
                  "r1-decomposition": {"cutoff": CASES["r1-decomposition"]["cutoff"],
                  "role": "non-degradation control"}},
        "arms": {"ckpt_v1": "kernel compiler baseline on a FRESH view "
                            "(no prior trial notes exist), compiled pre-pass",
                 "ckpt_livethreads": "same 4000-token budget; open_threads "
                                     ".20 = the SURVIVING open set after a "
                                     "chronological open/discharge pass, "
                                     "ordered by max-anchor recency"},
        "pass_prompt": PASS_PROMPT,
        "constants": {"horizon_hours": HORIZON_HOURS,
                      "min_messages": MIN_MESSAGES,
                      "quiet_seconds": QUIET_SECONDS,
                      "rationale": (
                          "24h covers the active experimental era at ~12 "
                          "episodes/view; MIN 2 because thread-openings "
                          "happen in small exchanges — the retro pass's "
                          "MIN 6 would skip exactly such moments; 1200s is "
                          "the daemon's own episode rule, applied uniformly "
                          "to every session. All fixed before registration.")},
        "expectation": (
            "Preregistered before any pass dispatch or arm run. PRIMARY "
            "ENDPOINT: r2 next_check rate, ckpt_livethreads vs ckpt_v1 "
            "(0.00 baseline across three prior experiments). Mechanism "
            "prediction from #42067's contrast: extraction catches the "
            "target when its opening episode is processed (r1 evidence); "
            "the discharge step must then NOT discharge it while its two "
            "sibling ladder items are discharged by the trial/verdict/push "
            "episodes. Interpretable failures: (a) over-discharge — the "
            "wrap episode discharges the sonnet thread too, showing "
            "discharge judgment needs evidence stronger than narrative "
            "closure; (b) under-discharge — the surviving set bloats with "
            "stale threads and displaces budget; (c) the opening episode is "
            "smaller than MIN_MESSAGES or outside the horizon; (d) carriage "
            "succeeds but the resumed model ignores the thread (use "
            "failure). r1 is a non-degradation control. Circularity note: "
            "the designer knows the target thread; prompt and constants "
            "contain no domain terms from it and apply uniformly."),
        "registered": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
    }
    exp_id = record("experiment", spec)
    print(f"preregistered livethreads trial as live event #{exp_id}")
    outdir = RESULTS / f"handoff-livethreads-exp{exp_id}"
    outdir.mkdir(parents=True, exist_ok=True)

    all_results, pass_info = [], {}
    for case_name in ("r2-ranker-verdict", "r1-decomposition"):
        res, stats = run_case(case_name, views / case_name, n, jobs,
                              exp_id, outdir)
        all_results += res
        pass_info[case_name] = stats

    rep = {"exp_id": exp_id, "task_id": spec["task_id"],
           "track": "livethreads", "pass": pass_info, "cases": {}}
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
            b = entry["ckpt_livethreads"]["scores"]
            p = perm_test(a, b)
            entry["comparison"] = {"delta": round(_mean(b) - _mean(a), 4),
                                   "p": p, "p_floor": p_floor(len(a), len(b)),
                                   "verdict": verdict(p)}
        rep["cases"][case_name] = entry
    rep["not_licensed"] = [
        "a chronological simulation over a frozen view approximates a live "
        "daemon; a truly live pass sees partial episodes and retries",
        "one pass model, one resumption model, two cutoffs; the primary "
        "endpoint is a single lexical fact",
        "'within noise' means not detected at this n, never 'no effect'",
    ]
    rep_id = record("exp_report", rep)
    (outdir / "report.json").write_text(json.dumps(rep, indent=2))
    print(f"\nreport -> live event #{rep_id}")
    for case_name, entry in rep["cases"].items():
        surv = pass_info[case_name]["surviving"]
        print(f"\n{case_name}:  (surviving open threads: {len(surv)})")
        for arm in ("ckpt_v1", "ckpt_livethreads"):
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
