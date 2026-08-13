#!/usr/bin/env python
"""Operator-explicitness confirmation — the series' closing causal claim,
tested on the unchanged pipeline.

Six experiments (ledger: #41905, #42011, #42067, #42123, #42127-#42163,
#42199) converged on one statement: episode-grained inference carries a
conditional open thread with P≈0.5 capture × P≈0.4 use, while a single
deliberate operator note at the moment the thread opens would make carriage
deterministic. That statement is causal and testable, so it does not get to
remain a recommendation.

THE CURATION BOUNDARY, stated plainly: the benchmark's rule is that the
operator may not hand-select the context a resumed model receives. This
trial does not select context — it simulates the TREATMENT the series
recommends: one `ctx note` the operator would have typed when the thread
opened. Its content is a VERBATIM quotation of the pre-cutoff proposal
(event #41379's third ladder bullet), mechanically sliced, so the designer
contributes no wording; choosing WHICH item to note is precisely the
operator's prioritization act being simulated, and is documented as such.
Everything downstream — selection strata, budgets, gating, the resumed
model's prompt — is the unchanged automatic pipeline.

Arms (r2 only; the endpoint lives there), all on fresh frozen views:
  control      — no note; the pipeline as measured six times before.
  right_note   — the simulated operator note (verbatim [41379] bullet).
  wrong_note   — an equally era-plausible note quoting the OTHER recorded
                 thread (the variance nuance, verbatim from [41584]).
                 Specificity control: if next_check fires here too, the
                 effect is generic steering, not carriage; and its total
                 score prices the cost of a WRONG operator note (the
                 channel is high-gain in both directions or it isn't).

Carriage is verified mechanically before any run: the note's text must
appear in the compiled package (the human-notes stratum selects newest
deliberate notes first), or the trial aborts as invalid.

Primary endpoint: permutation test on the next_check indicator, right_note
vs control, p <= 0.05 (with an expected 0/5 control, this requires >= 4/5 —
a deterministic-carriage-high-use claim should meet that bar; a lower
nonzero rate quantifies USE as the residual bottleneck, which is an
intermediate result, not a confirmation)."""

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import subprocess  # noqa: E402

from contextd.experiment import p_floor, perm_test, score_output, verdict  # noqa: E402
from experiments.handoff.bench import TASK_TEMPLATE, _mean, _sd  # noqa: E402
from experiments.handoff.cases import CASES  # noqa: E402
from experiments.handoff.common import (REPO, RESULTS, contextd_home,  # noqa: E402
                                        extract_citations, record, run_claude,
                                        view_conn)

MODEL = "haiku"
LIVE_DB = Path("~/.contextd/contextd.db").expanduser()
CASE = "r2-ranker-verdict"

RIGHT_SRC = 41379
RIGHT_START = "**Sonnet on the frozen prediction bundle**"
RIGHT_END = "?"
WRONG_SRC = 41584
WRONG_START = "connective ranking **halved the run-to-run variance**"
WRONG_END = "this time."


def verbatim_slice(conn, event_id: int, start: str, end: str) -> str:
    text = conn.execute("SELECT content FROM events WHERE id = ?",
                        (event_id,)).fetchone()[0]
    i = text.index(start)
    j = text.index(end, i) + len(end)
    return text[i:j]


def build_view(dest: Path, note_src: int | None, start: str = "",
               end: str = "") -> tuple:
    import shutil
    from contextd.handoff import freeze_view
    from contextd.ingest import ingest_note
    if dest.exists():
        shutil.rmtree(dest)
    freeze_view(LIVE_DB, dest, CASES[CASE]["cutoff"])
    conn, cfg = view_conn(dest)
    note_text = None
    if note_src is not None:
        with contextd_home(dest):
            quoted = verbatim_slice(conn, note_src, start, end)
            note_text = f"board: {quoted} [{note_src}]"
            ingest_note(conn, note_text, actor="human")
    return conn, cfg, note_text


def main():
    n, jobs = 5, 3
    case = CASES[CASE]
    views = Path("runs/handoff-20260812/views-opnote")
    views.mkdir(parents=True, exist_ok=True)
    spec = {
        "task_id": "handoff-operator-explicitness-v1", "track": "operator-note",
        "resume_model": MODEL, "n_per_arm": n, "case": CASE,
        "cutoff": case["cutoff"],
        "arms": {
            "control": "fresh view, no note — the pipeline as previously measured",
            "right_note": f"one simulated operator note: verbatim slice of "
                          f"[{RIGHT_SRC}] ('{RIGHT_START}...'), prefixed "
                          f"'board:', actor=human — the treatment",
            "wrong_note": f"same, but quoting the other recorded thread "
                          f"[{WRONG_SRC}] — specificity and steering-cost "
                          f"control"},
        "curation_boundary": (
            "The note simulates the recommended operator ACT; its wording is "
            "a mechanical verbatim quotation of pre-cutoff bytes; choosing "
            "the item IS the simulated prioritization. Selection, budgets, "
            "gating, and prompts are the unchanged automatic pipeline; "
            "carriage is verified mechanically pre-run."),
        "primary_endpoint": ("perm test on next_check indicator, right_note "
                             "vs control, p <= 0.05"),
        "expectation": (
            "Preregistered before any run. Prediction from the series: "
            "carriage becomes 1.0 by construction (verified); the open "
            "question is use. Confirmation: right_note next_check >= 4/5 "
            "with control at its six-experiment baseline of 0. Intermediate "
            "(still informative): nonzero but < 4/5 — use is the residual "
            "bottleneck and operator explicitness alone is necessary but "
            "not sufficient at this model tier. Specificity: wrong_note "
            "next_check should stay 0; its variance_thread fact should "
            "rise (it carries that thread) — if wrong_note lifts "
            "next_check, the mechanism is generic steering and the series' "
            "carriage interpretation is wrong. Steering cost: wrong_note "
            "total score vs control prices a bad operator note."),
        "registered": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
    }
    exp_id = record("experiment", spec)
    print(f"preregistered operator-explicitness trial as live event #{exp_id}")
    outdir = RESULTS / f"handoff-opnote-exp{exp_id}"
    outdir.mkdir(parents=True, exist_ok=True)

    from contextd.handoff import compile_checkpoint
    repo_log = subprocess.run(
        ["git", "-C", str(REPO), "log", "--oneline", "-8", case["commit"]],
        capture_output=True, text=True).stdout.strip()
    repo_hist = {"branch": "master", "commit": case["commit"], "log": repo_log,
                 "status": "", "diffstat": ""}

    contexts = {}
    for arm, (src, s, e) in {
            "control": (None, "", ""),
            "right_note": (RIGHT_SRC, RIGHT_START, RIGHT_END),
            "wrong_note": (WRONG_SRC, WRONG_START, WRONG_END)}.items():
        conn, cfg, note_text = build_view(views / arm, src, s, e)
        with contextd_home(views / arm):
            ck = compile_checkpoint(conn, cfg, budget=4000,
                                    task_hint=case["task_hint"],
                                    repo=repo_hist, client="opnote")
        if note_text is not None and note_text.split("[")[0].strip() \
                not in ck["package"]:
            sys.exit(f"INVALID TRIAL: {arm} note not carried into the "
                     "compiled package — carriage precondition failed")
        contexts[arm] = {"text": ck["package"], "ids": ck["items"],
                         "note": note_text}
        (outdir / f"context-{arm}.txt").write_text(ck["package"])
        print(f"  {arm}: compiled ~{ck['est_tokens']}tok, "
              f"note carried: {note_text is not None}")

    def one(arm, i):
        block = (f"=== PROJECT MEMORY (contextd compiled checkpoint) ===\n"
                 f"{contexts[arm]['text']}")
        prompt = TASK_TEMPLATE.format(context_block=block,
                                      commit=case["commit"], log=repo_log)
        return arm, i, run_claude(prompt, MODEL)

    results = []
    jobs_list = [(a, i) for a in contexts for i in range(n)]
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        futs = [ex.submit(one, a, i) for a, i in jobs_list]
        for fut in as_completed(futs):
            arm, i, r = fut.result()
            sc = score_output(case["rubric"], r["text"])
            meta = {"exp_id": exp_id, "arm": arm, "run": i,
                    "ctx_tokens": max(1, len(contexts[arm]["text"]) // 4),
                    "score": sc["score"], "hits": sc["hits"],
                    "citations": extract_citations(r["text"], contexts[arm]["ids"]),
                    "exit": r["exit"], "duration_ms": r["duration_ms"],
                    "output": r["text"][:20000]}
            record("exp_run", meta)
            results.append(meta)
            (outdir / f"{arm}-{i}.md").write_text(
                f"# opnote / {arm} / run {i}\nscore {sc['score']}\n"
                f"hits: {json.dumps(sc['hits'])}\n\n{r['text']}\n")
            print(f"  [{len(results)}/{len(jobs_list)}] {arm}#{i} "
                  f"score {sc['score']:.2f} next_check="
                  f"{sc['hits'].get('next_check')}", flush=True)

    by_arm = {}
    for r in results:
        by_arm.setdefault(r["arm"], []).append(r)
    entry = {}
    for arm, rs in by_arm.items():
        entry[arm] = {
            "n": len(rs),
            "mean": round(_mean([r["score"] for r in rs]), 4),
            "sd": round(_sd([r["score"] for r in rs]), 4),
            "scores": [r["score"] for r in rs],
            "next_check": [1 if r["hits"].get("next_check") else 0 for r in rs],
            "fact_rates": {f["id"]: round(
                sum(1 for r in rs if r["hits"].get(f["id"])) / len(rs), 3)
                for f in case["rubric"]["facts"]}}
    prim = perm_test(entry["right_note"]["next_check"],
                     entry["control"]["next_check"])
    spec_p = perm_test(entry["wrong_note"]["next_check"],
                       entry["control"]["next_check"])
    cost_p = perm_test(entry["wrong_note"]["scores"],
                       entry["control"]["scores"])
    total_p = perm_test(entry["right_note"]["scores"],
                        entry["control"]["scores"])
    rep = {"exp_id": exp_id, "task_id": spec["task_id"],
           "track": "operator-note", "arms": entry,
           "primary": {"endpoint": "next_check right_note vs control",
                       "right_rate": round(sum(entry["right_note"]["next_check"]) / n, 2),
                       "control_rate": round(sum(entry["control"]["next_check"]) / n, 2),
                       "p": prim, "p_floor": p_floor(n, n),
                       "verdict": verdict(prim)},
           "secondary": {
               "wrong_note_next_check_p": spec_p,
               "wrong_note_total_vs_control": {
                   "delta": round(entry["wrong_note"]["mean"]
                                  - entry["control"]["mean"], 4), "p": cost_p},
               "right_note_total_vs_control": {
                   "delta": round(entry["right_note"]["mean"]
                                  - entry["control"]["mean"], 4), "p": total_p}},
           "not_licensed": [
               "the operator act is simulated; a real operator's notes vary "
               "in wording and timing",
               "one cutoff, one thread, one model; the use-rate is a "
               "haiku-tier property",
               "'within noise' means not detected at this n, never 'no effect'",
           ]}
    rep_id = record("exp_report", rep)
    (outdir / "report.json").write_text(json.dumps(rep, indent=2))
    print(f"\nreport -> live event #{rep_id}\n")
    for arm in ("control", "right_note", "wrong_note"):
        e = entry[arm]
        print(f"  {arm:<12} score {e['mean']:.2f} ± {e['sd']:.2f}  "
              f"next_check {sum(e['next_check'])}/{n}")
    print(f"\n  PRIMARY next_check right vs control: p={prim} "
          f"({verdict(prim)})")
    print(f"  specificity (wrong vs control next_check): p={spec_p}")
    print(f"  right total Δ {rep['secondary']['right_note_total_vs_control']['delta']:+.2f} "
          f"(p={total_p});  wrong total Δ "
          f"{rep['secondary']['wrong_note_total_vs_control']['delta']:+.2f} (p={cost_p})")


if __name__ == "__main__":
    main()
