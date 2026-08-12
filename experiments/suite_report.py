#!/usr/bin/env python
"""Cross-family suite report: aggregate several experiments' ledger records
into one document answering the reasoning-value questions. Reads only from
the ledger (build_report per experiment), writes markdown. No model calls.

Usage: suite_report.py <exp_id> [<exp_id> ...] [-o out.md]"""

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contextd.db import connect  # noqa: E402
from contextd.experiment import build_report, get_experiment  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exp_ids", nargs="+", type=int)
    ap.add_argument("-o", "--out")
    args = ap.parse_args()
    conn = connect()
    reports = []
    for eid in args.exp_ids:
        spec = get_experiment(conn, eid)
        reports.append((eid, spec, build_report(conn, eid)))

    L = []
    L.append("# Does rich historical context improve reasoning beyond fact retrieval?")
    L.append("")
    L.append(f"Suite report over experiments "
             f"{', '.join('#' + str(e) for e, _, _ in reports)} — generated "
             f"{datetime.now(timezone.utc).isoformat(timespec='seconds')}, "
             "rebuilt entirely from ledger events.")
    L.append("")
    L.append("Hypothesis under test: accumulated, provenance-rich context contains "
             "decision-relevant information that ordinary model distillation does not "
             "preserve, and that materially improves novel reasoning. The null — a "
             "competent distillation retains nearly all useful information — is an "
             "equally acceptable outcome, and each family's preregistered expectation "
             "is recorded in its experiment event.")
    L.append("")

    # per-family tables
    for eid, spec, rep in reports:
        L.append(f"## {spec['task_id']} (exp #{eid})")
        if spec.get("title"):
            L.append(f"*{spec['title']}*")
        L.append("")
        L.append("| arm | score | sd | n | ctx tokens | score/1k ctx |")
        L.append("|---|---|---|---|---|---|")
        for name, a in sorted(rep["arms"].items(), key=lambda kv: -kv[1]["mean"]):
            L.append(f"| {name} | {a['mean']:.2f} | {a['sd']:.2f} | {a['n']} | "
                     f"{a['context_tokens']} | "
                     f"{a['score_per_1k_ctx'] if a['score_per_1k_ctx'] is not None else '—'} |")
        if rep.get("ladder"):
            L.append("")
            L.append("Ladder: " + "; ".join(
                f"{s['from']}→{s['to']}: Δ{s['delta']:+.2f} "
                f"({s['added_ctx_tokens']:+d} tok, p={s['p']}, {s['verdict']})"
                for s in rep["ladder"]))
        irr = rep["arms"].get("irrelevant")
        none_arm = rep["arms"].get("no_history") or rep["arms"].get("no_context")
        if irr and none_arm:
            from contextd.experiment import perm_test, verdict as vd
            p = perm_test(irr["scores"], none_arm["scores"])
            L.append("")
            L.append(f"Irrelevant-history control: {irr['mean']:.2f} vs "
                     f"no-history {none_arm['mean']:.2f} at the same token count "
                     f"as retrieved_detail (p={p}, {vd(p)}).")
        if rep.get("compression_loss"):
            cl = rep["compression_loss"]
            lost = ", ".join(f"{e['fact']} [{e['loss_class']}]"
                             for e in cl["lost_in_distillation"]) or "nothing"
            kept = ", ".join(e["fact"] for e in cl["kept_in_distillation"]) or "nothing"
            L.append("")
            L.append(f"Distillation kept: {kept}. Lost: {lost}.")
        halluc = {n: a.get("hallucinated_citations", 0) for n, a in rep["arms"].items()}
        if any(halluc.values()):
            L.append("")
            L.append("Hallucinated citations (cited ids never supplied to that run): "
                     + ", ".join(f"{n}: {v}" for n, v in halluc.items() if v))
        L.append("")
        for line in rep["interpretation"]:
            L.append(f"- {line}")
        L.append("")

    # cross-family rollups
    L.append("## Across families")
    L.append("")
    steps = {}
    for _, _, rep in reports:
        for s in rep.get("ladder", []):
            steps.setdefault((s["from"], s["to"]), []).append(s)
    for (lo, hi), ss in steps.items():
        wins = sum(1 for s in ss if s["delta"] > 0)
        detected = sum(1 for s in ss if s["verdict"] != "within noise" and s["delta"] > 0)
        det_neg = sum(1 for s in ss if s["verdict"] != "within noise" and s["delta"] < 0)
        L.append(f"- **{lo} → {hi}**: positive in {wins}/{len(ss)} families, "
                 f"beyond noise in {detected} (negative beyond noise in {det_neg}). "
                 + " ".join(f"[Δ{s['delta']:+.2f} p={s['p']}]" for s in ss))
    L.append("")
    loss_classes = {}
    for _, _, rep in reports:
        cl = rep.get("compression_loss")
        if cl:
            for e in cl["lost_in_distillation"]:
                loss_classes.setdefault(e["loss_class"], []).append(e["fact"])
    if loss_classes:
        L.append("Information destroyed by distillation, by preregistered class: "
                 + "; ".join(f"**{k}** ({', '.join(v)})"
                             for k, v in sorted(loss_classes.items())))
        L.append("")
    caveats = [c for _, _, rep in reports for c in rep.get("origin_caveats", [])]
    if caveats:
        L.append("Origin caveats (transport role vs assessed origin): "
                 f"{len(caveats)} item-instances carry assessed origins; no clean "
                 "human-vs-model attribution is claimed where origin is mixed.")
        L.append("")
    L.append("## This suite does not license")
    L.append("")
    for line in reports[0][2]["not_licensed"]:
        L.append(f"- {line}")
    L.append("- cross-family counts are descriptive; families share a model and "
             "an operator's archive, so they are not independent replications")
    text = "\n".join(L) + "\n"
    if args.out:
        Path(args.out).write_text(text)
        print(f"written to {args.out}")
    else:
        print(text)


if __name__ == "__main__":
    main()
