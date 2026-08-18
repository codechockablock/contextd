#!/usr/bin/env python
"""Board externalization — the fourth mechanism aimed at the handoff gap,
under test outside the kernel.

Why a board, and why now (series in the ledger): the gap is an open thread
that was neither recent nor lexically near the task hint (#41905). Lexical
density failed (#42011). Retro structural extraction failed — closure
narratives mask undischarged items (#42067). Live open/discharge tracking
failed — continuous work gives no episode boundary at the opening moment,
and the thread's pre-cutoff form was a CONDITIONAL proposal ("when you're
ready"), which forces an open/closed judgment no tracker can make with both
precision and recall (#42123). The shared missing state was prioritization:
"that check is on the board."

The mechanism under test therefore refuses the open/closed judgment
entirely: a BOARD is a living prioritization document with lanes — NOW /
NEXT / LATER / QUESTIONS — where a conditional proposal is simply a LATER
item, transcribed rather than adjudicated. A maintainer model rewrites the
whole board once per episode, chronologically. If a faithfully maintained
board carries the thread to the cutoff, the workflow surface is earned as a
design direction (an operator-maintained board is strictly stronger); if
the board loses it, that localizes further: either transcription failure at
the opening episode, or COMPACTION LOSS across rewrites — the recursive-
distillation decay P3 measured, now on a working artifact.

Provenance is preserved recursively with existing machinery: each board
update is one note written under a dispatch capability, whose
disclosure items include the episode's dialogue ids, the previous board's
note id, AND the previous board's kernel-recorded anchors — so an anchor
carried forward through N rewrites still verifies, and an invented one is
refused by the kernel (the note is then not written and the previous board
stands; a safe failure).

Compiler v5: a BOARD stratum (the latest board, verbatim) at the same 20%
share the failed strata used — with unused stratum budget overflowing back
to the tail, fixing the under-fill artifact #42123 recorded.
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
from experiments.handoff.livethreads import episodes  # noqa: E402  (same

# contextd.gate dispatches retrieval through a provider that contextd.search
# registers at import time (lane T). A process that assembles a disclosure
# without importing it gets an empty candidate set, not an error — importing it
# here is what keeps this script's recall working. Pinned by
# tests/test_gate_retrieval_hook.py::test_every_retrieval_caller_registers.
import contextd.search  # noqa: F401
# horizon/quiescence constants: 24h, >=2 msgs, 1200s — fixed by that trial)

CLAUDE_BIN = "claude"
MODEL = "haiku"
CLIENT = "board"
LIVE_DB = Path("~/.contextd/contextd.db").expanduser()

BOARD_PROMPT = """You maintain the BOARD for an ongoing project — one living
document that serves as its working memory. Below are (1) the CURRENT BOARD
(possibly empty) and (2) the dialogue of the newest work episode, each
message with its bracketed archive event id.

Rewrite the COMPLETE board, at most 350 words, with exactly these lanes:
NOW: what is actively being worked on.
NEXT: specific actions agreed or requested to run soon.
LATER: options, proposals, and checks explicitly raised but deferred or
awaiting a go-ahead — transcribe these faithfully even when phrased
conditionally; a board's job is to remember what is on deck, not to judge
whether it is officially committed.
QUESTIONS: unresolved questions.

Rules: keep every item from the current board unless this episode shows it
completed or dropped — then remove it; move items between lanes as status
changes; merge duplicates. Every item ends with the bracketed event id(s)
supporting it; when you keep an item, keep its ids. Cite only ids that
appear in the current board or in this episode's dialogue; never invent
one. Write the new board as ONE note via the contextd note tool, starting
with "BOARD:". When finished, reply with only: DONE"""


def latest_board(conn):
    # full row: _render needs ts/source/kind alongside id/content/meta
    return conn.execute(
        "SELECT * FROM events WHERE kind='note' "
        "AND json_extract(meta,'$.actor') = ? ORDER BY id DESC LIMIT 1",
        (CLIENT,)).fetchone()


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
            board = latest_board(conn)
            board_text = board["content"] if board else "(empty — first episode)"
            board_items = []
            if board:
                bm = json.loads(board["meta"] or "{}")
                board_items = [board["id"]] + list(
                    (bm.get("derivation") or {}).get("anchors") or [])
            msgs = conn.execute(
                "SELECT id, content, json_extract(meta,'$.role') AS role "
                "FROM events WHERE id IN (%s) ORDER BY id"
                % ",".join("?" * len(msg_ids)), msg_ids).fetchall()
            dialogue = "\n\n".join(
                f"[{m['id']}] {m['role']}: {m['content']}" for m in msgs)
            payload = (f"{BOARD_PROMPT}\n\n=== CURRENT BOARD ===\n"
                       f"{board_text}\n\n=== EPISODE DIALOGUE ===\n"
                       f"{dialogue}")[:400_000]
            items = sorted(set(msg_ids) | set(board_items))
            disclosure = disclose(conn, cfg, payload, {
                "type": "board_dialogue", "episode": k, "session": sid,
                "model": MODEL, "items": items, "client": CLIENT})
            import os
            env = os.environ.copy()
            env["CONTEXTD_HOME"] = str(Path(view_home).resolve())
            # a dispatch capability, not an event id: opaque, bound to this
            # disclosure's exact bytes and this session, single-use and
            # expiring (contextd/capability.py). The bare integer binding is
            # retired and now refuses rather than silently mis-binding.
            _cap = issue_capability(conn, disclosure["egress_id"],
                                    os.getuid(), "board")
            env["CONTEXTD_DISPATCH_CAPABILITY"] = capability_token(_cap)
            env["CONTEXTD_DISPATCH_SESSION"] = "board"
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
                    cwd=tempfile.mkdtemp(prefix="ctx-board-"))
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
            nb = latest_board(conn)
            stats.append({"episode": k, "session": sid[:8],
                          "messages": len(msg_ids), "notes": after - before,
                          "board_words": len((nb["content"] or "").split())
                          if nb else 0, "exit": r.returncode})
            print(f"    ep{k} ({sid[:8]}, {len(msg_ids)} msgs) -> "
                  f"{after - before} note(s), board "
                  f"{stats[-1]['board_words']}w", flush=True)
    final = latest_board(view_conn(view_home)[0])
    return {"episodes": stats,
            "final_board_note": final["id"] if final else None,
            "final_board": (final["content"] or "")[:4000] if final else None}


def compile_v5(conn, cfg, budget: int, task_hint: str, repo: dict,
               cutoff: int) -> dict:
    from contextd.db import _db_tip
    from contextd.gate import disclose, est_tokens, select_items
    from contextd.handoff import _pack, _render, render_package
    shares = {"tail": 0.30, "episodes": 0.20, "notes": 0.10,
              "recall": 0.20, "board": 0.20}
    budgets = {k: int(budget * v) for k, v in shares.items()}
    taken: set = set()
    board = latest_board(conn)
    board_item = None
    if board:
        board_item = _render(cfg, board)
        if board_item["est_tokens"] > budgets["board"]:
            board_item = None  # oversized board is a refusal, not a truncation
        else:
            taken.add(board["id"])
            # the under-fill fix #42123 recorded: unused share returns to tail
            budgets["tail"] += budgets["board"] - board_item["est_tokens"]
    else:
        budgets["tail"] += budgets["board"]
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
    if board_item:
        section = ("== PROJECT BOARD (maintained during the work; the state "
                   "of play at the interruption) ==\n"
                   + board_item["header"] + "\n" + board_item["text"])
        marker = "== RAW DIALOGUE TAIL"
        base = (base.replace(marker, section + "\n\n" + marker, 1)
                if marker in base else base + "\n\n" + section)
    ids = sorted({it["id"] for sec in (tail, episodes_sec, notes, recall_items)
                  for it in sec} | ({board["id"]} if board_item else set()))
    d = disclose(conn, cfg, base, {
        "type": "checkpoint", "mode": "checkpoint_v5_board",
        "tip": _db_tip(conn)["id"], "task_hint": task_hint, "items": ids,
        "client": CLIENT})
    return {"package": d["content"], "items": ids,
            "egress_id": d["egress_id"], "est_tokens": est_tokens(base),
            "board_included": bool(board_item)}


def run_case(case_name: str, view_home: Path, n: int, jobs: int,
             exp_id: int, outdir: Path) -> tuple:
    case = CASES[case_name]
    import shutil
    from contextd.handoff import compile_checkpoint, freeze_view
    if view_home.exists():
        shutil.rmtree(view_home)
    info = freeze_view(LIVE_DB, view_home, case["cutoff"])
    print(f"  {case_name}: fresh view, {info['events']} events")
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
    print(f"  {case_name}: running board pass ...")
    pass_stats = run_pass(view_home, case["cutoff"])
    conn, cfg = view_conn(view_home)
    with contextd_home(view_home):
        v5 = compile_v5(conn, cfg, 4000, case["task_hint"], repo_hist,
                        case["cutoff"])
    contexts = {"ckpt_v1": {"text": v1["package"], "ids": v1["items"]},
                "ckpt_board": {"text": v5["package"], "ids": v5["items"]}}
    for arm, c in contexts.items():
        (outdir / f"context-{case_name}-{arm}.txt").write_text(c["text"])
    (outdir / f"final-board-{case_name}.txt").write_text(
        pass_stats["final_board"] or "(no board)")
    print(f"  {case_name}: final board note "
          f"#{pass_stats['final_board_note']}, included="
          f"{v5['board_included']}")

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
                f"# board / {case_name} / {arm} / run {i}\n"
                f"score {sc['score']}\nhits: {json.dumps(sc['hits'])}\n\n"
                f"{r['text']}\n")
            print(f"  [{len(results)}/{len(jobs_list)}] {case_name}/{arm}#{i} "
                  f"score {sc['score']:.2f} next_check="
                  f"{sc['hits'].get('next_check')}", flush=True)
    return results, pass_stats


def main():
    n, jobs = 4, 3
    views = Path("runs/handoff-20260812/views-board")
    views.mkdir(parents=True, exist_ok=True)
    spec = {
        "task_id": "handoff-board-externalization-v1", "track": "board",
        "resume_model": MODEL, "pass_model": MODEL, "n_per_arm": n,
        "cases": {"r2-ranker-verdict": {"cutoff": CASES["r2-ranker-verdict"]["cutoff"],
                  "role": "primary"},
                  "r1-decomposition": {"cutoff": CASES["r1-decomposition"]["cutoff"],
                  "role": "non-degradation control"}},
        "arms": {"ckpt_v1": "kernel compiler baseline on a fresh view, "
                            "compiled pre-pass",
                 "ckpt_board": "same 4000-token budget; BOARD stratum .20 = "
                               "the latest maintained board verbatim; unused "
                               "share overflows to tail (fixing #42123's "
                               "under-fill artifact)"},
        "board_prompt": BOARD_PROMPT,
        "mechanism_difference": (
            "Unlike every prior mechanism, the board makes NO open/closed "
            "judgment: LATER-lane items are transcribed prioritization "
            "state, which is exactly the state the series found dies with "
            "the session. Provenance survives rewrites recursively: each "
            "update's disclosure items include the previous board's note id "
            "and kernel-recorded anchors, so carried-forward citations "
            "verify and invented ones are refused (P3's lesson applied to a "
            "living artifact)."),
        "expectation": (
            "Preregistered before any pass dispatch or arm run. PRIMARY "
            "ENDPOINT: r2 next_check, ckpt_board vs ckpt_v1 (0.00 across "
            "four prior experiments). Mechanism predictions: the ladder "
            "proposal should enter the board's LATER lane at its episode "
            "(transcription, not judgment); the risk is COMPACTION LOSS — "
            "each rewrite may drop it, especially in the closure-wrap "
            "episode (P3 measured recursive decay; this is its workflow "
            "analogue). Interpretable failures: (a) never enters the board "
            "— even prioritization surfaces need operator authorship; (b) "
            "enters then is dropped by rewrite N — compaction loss, "
            "measurable per-episode from the stored board sequence; (c) "
            "survives to the final board but the resumed model ignores it "
            "— use failure; (d) anchor decay across rewrites — kernel "
            "refusals recorded per episode. r1 is a non-degradation "
            "control. Circularity note: the designer knows the target; the "
            "prompt contains no domain terms and applies uniformly to all "
            "episodes; the LATER-lane design follows from the series "
            "diagnosis, recorded as such."),
        "registered": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
    }
    exp_id = record("experiment", spec)
    print(f"preregistered board-externalization trial as live event #{exp_id}")
    outdir = RESULTS / f"handoff-board-exp{exp_id}"
    outdir.mkdir(parents=True, exist_ok=True)

    all_results, pass_info = [], {}
    for case_name in ("r2-ranker-verdict", "r1-decomposition"):
        res, stats = run_case(case_name, views / case_name, n, jobs,
                              exp_id, outdir)
        all_results += res
        pass_info[case_name] = {k: v for k, v in stats.items()
                                if k != "final_board"}

    rep = {"exp_id": exp_id, "task_id": spec["task_id"], "track": "board",
           "pass": pass_info, "cases": {}}
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
            b = entry["ckpt_board"]["scores"]
            p = perm_test(a, b)
            entry["comparison"] = {"delta": round(_mean(b) - _mean(a), 4),
                                   "p": p, "p_floor": p_floor(len(a), len(b)),
                                   "verdict": verdict(p)}
        rep["cases"][case_name] = entry
    rep["not_licensed"] = [
        "a model-maintained board simulates the workflow; an operator-"
        "maintained board is the real feature and could differ in content",
        "one pass model, one resumption model, two cutoffs; the primary "
        "endpoint is a single lexical fact",
        "'within noise' means not detected at this n, never 'no effect'",
    ]
    rep_id = record("exp_report", rep)
    (outdir / "report.json").write_text(json.dumps(rep, indent=2))
    print(f"\nreport -> live event #{rep_id}")
    for case_name, entry in rep["cases"].items():
        print(f"\n{case_name}:")
        for arm in ("ckpt_v1", "ckpt_board"):
            e = entry[arm]
            nc = e["fact_rates"].get("next_check")
            nc_s = f"  next_check {nc:.2f}" if nc is not None else ""
            print(f"  {arm:<12} {e['mean']:.2f} ± {e['sd']:.2f} "
                  f"ctx ~{e['ctx_tokens']}tok{nc_s}")
        c = entry.get("comparison")
        if c:
            print(f"  Δ {c['delta']:+.2f}  p={c['p']} (floor {c['p_floor']})  "
                  f"{c['verdict']}")


if __name__ == "__main__":
    main()
