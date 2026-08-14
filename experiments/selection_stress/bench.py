#!/usr/bin/env python
"""Selection-stress benchmark runner.

Subcommands:
  freeze        write spec-frozen.json (refuses if already frozen and drifted)
  selftest      end-to-end miniature run on the tiny tier: build twice
                (determinism), validity, a small carriage pass, scoring
                classes exercised. Deterministic, zero model calls.
  build         build all (tier x seed) archives under results/worlds/
  validity      measure band ranks on every archive; write validity.json;
                exit nonzero if the ordering gate fails
  grid          run the full carriage grid (validity gate enforced first);
                stream rows to results/grid/rows.jsonl
  analyze       aggregate artifacts into results/analysis.json
  prereg        freeze the behavioral spec + record the preregistration
                event in the dedicated experiment ledger (results/ledger)
  probe         one tiny claude -p call proving the dispatch path (haiku);
                counts toward the 300-dispatch ceiling
  run-behavior <prereg-id>   execute the preregistered behavioral subset
  report <prereg-id>         rebuild the full report from durable artifacts
                             (byte-identical to the stored report)
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))

from experiments.selection_stress import (analysis, carriage,  # noqa: E402
                                          generator, spec, validity)

RESULTS = Path(__file__).resolve().parent / "results"
WORLDS = RESULTS / "worlds"


def _log(msg: str) -> None:
    print(msg, flush=True)


def world_paths(tier: str, seed: int) -> tuple[Path, Path]:
    d = WORLDS / f"{tier}-s{seed}"
    return d / "home", d / "manifest.json"


def iter_worlds():
    s = spec.build_spec()
    for tier in s["tiers"]:
        for seed in s["seeds"]:
            yield tier, seed


def cmd_freeze(_args) -> int:
    if spec.FROZEN.exists():
        chk = spec.check_frozen()
        _log(f"already frozen: ok={chk['ok']} sha={chk.get('sha')}")
        return 0 if chk["ok"] else 1
    out = spec.freeze()
    _log(f"frozen spec sha256 {out['sha']}")
    return 0


def _require_frozen() -> dict:
    chk = spec.check_frozen()
    if not chk["ok"]:
        _log(f"REFUSED: {chk['why']} — run freeze first / do not edit "
             f"frozen modules")
        raise SystemExit(2)
    return chk


def cmd_build(_args) -> int:
    _require_frozen()
    for tier, seed in iter_worlds():
        home, mpath = world_paths(tier, seed)
        if mpath.exists():
            m = json.loads(mpath.read_text())
            _log(f"{tier}-s{seed}: exists (digest {m['digest'][:12]})")
            continue
        if home.exists():
            shutil.rmtree(home)
        m = generator.build_archive(home, tier, seed)
        generator.write_manifest(m, mpath)
        _log(f"{tier}-s{seed}: built n={m['n_events']} "
             f"digest {m['digest'][:12]}")
    return 0


def cmd_validity(_args) -> int:
    _require_frozen()
    rows = []
    for tier, seed in iter_worlds():
        _home, mpath = world_paths(tier, seed)
        m = json.loads(mpath.read_text())
        rows.extend(validity.measure_archive(m))
        _log(f"validity measured {tier}-s{seed}")
    cons = validity.ordering_consistency(rows)
    doc = {"rows": rows, "summary": validity.rank_summary(rows),
           "consistency": cons, "gate": validity.gate(cons),
           "spec_sha": spec.spec_sha()}
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "validity.json").write_text(
        json.dumps(doc, indent=1, sort_keys=True) + "\n")
    _log(f"summary: {json.dumps(doc['summary'])}")
    _log(f"consistency: { {k: v['rate'] for k, v in cons.items()} }")
    _log(f"gate passed: {doc['gate']['passed']}")
    return 0 if doc["gate"]["passed"] else 3


def cmd_grid(_args) -> int:
    _require_frozen()
    vdoc = json.loads((RESULTS / "validity.json").read_text())
    if not vdoc["gate"]["passed"]:
        _log("REFUSED: manipulation validity gate not passed — no grid "
             "results may exist without it")
        return 3
    s = spec.build_spec()
    out = RESULTS / "grid"
    out.mkdir(parents=True, exist_ok=True)
    rows_path = out / "rows.jsonl"
    done = set()
    if rows_path.exists():
        for r in analysis.load_rows(rows_path):
            done.add((r["tier"], r["seed"]))
    with rows_path.open("a") as fh:
        for tier, seed in iter_worlds():
            if (tier, seed) in done:
                _log(f"grid {tier}-s{seed}: already present, skipping")
                continue
            _home, mpath = world_paths(tier, seed)
            m = json.loads(mpath.read_text())
            rows = carriage.grid_rows_for_archive(m, s["budgets"])
            for r in rows:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
            fh.flush()
            _log(f"grid {tier}-s{seed}: {len(rows)} rows")
    meta = {"spec_sha": spec.spec_sha(),
            "digests": {f"{t}-s{sd}": json.loads(
                world_paths(t, sd)[1].read_text())["digest"]
                for t, sd in iter_worlds()}}
    (out / "meta.json").write_text(json.dumps(meta, indent=1, sort_keys=True) + "\n")
    _log("grid complete")
    return 0


def cmd_analyze(_args) -> int:
    _require_frozen()
    s = spec.build_spec()
    vdoc = json.loads((RESULTS / "validity.json").read_text())
    vdoc.pop("rows", None)
    rows = analysis.load_rows(RESULTS / "grid" / "rows.jsonl")
    doc = analysis.analyze(vdoc, rows, s)
    (RESULTS / "analysis.json").write_text(
        json.dumps(doc, indent=1, sort_keys=True) + "\n")
    for key in ("headline_a", "headline_b"):
        _log(f"{key}: {json.dumps(doc[key])}")
    _log(f"latency: {json.dumps(doc['headline_c'])}")
    return 0


def cmd_selftest(_args) -> int:
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="selstress-selftest-"))
    m1 = generator.build_archive(d / "a1", "tiny", 7, mini=True)
    m2 = generator.build_archive(d / "a2", "tiny", 7, mini=True)
    m3 = generator.build_archive(d / "a3", "tiny", 8, mini=True)
    assert m1["digest"] == m2["digest"], "same seed must give same digest"
    assert m1["digest"] != m3["digest"], "different seed must differ"
    _log(f"determinism ok (digest {m1['digest'][:12]})")

    rows = validity.measure_archive(m1)
    cons = validity.ordering_consistency(rows)
    near_far = cons.get("near<far", {})
    assert near_far.get("total"), "validity must compare near/far pairs"
    _log(f"validity measured: near<far rate {near_far['rate']}")

    scored = []
    for tp in m1["topics"]:
        c = carriage.compile_for_topic(m1["home"], tp["hint"], 4000)
        assert c["egress_id"], "compile must land an egress receipt"
        scored.append(carriage.score_topic(tp, c))
    carried = sum(1 for s_ in scored if s_["carried"])
    absent = sum(1 for s_ in scored if s_["silently_absent"])
    assert carried and absent, (
        "tiny grid must exercise both carried and silently-absent classes")
    supers = [s_ for s_ in scored if "stale_resurrected" in s_]
    assert supers, "supersession cells must be scored"
    _log(f"carriage classes ok: {carried} carried / {absent} absent / "
         f"{len(supers)} supersession-scored over {len(scored)} topics")

    # scoring is deterministic: same compile inputs, same classes
    tp = m1["topics"][0]
    c1 = carriage.compile_for_topic(m1["home"], tp["hint"], 4000)
    c2 = carriage.compile_for_topic(m1["home"], tp["hint"], 4000)
    assert carriage.score_topic(tp, c1) == carriage.score_topic(tp, c2)
    _log("selftest passed (no model calls)")
    shutil.rmtree(d)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("freeze", "build", "validity", "grid", "analyze",
                 "selftest", "probe", "prereg"):
        sub.add_parser(name)
    p_run = sub.add_parser("run-behavior")
    p_run.add_argument("prereg_id", type=int)
    p_rep = sub.add_parser("report")
    p_rep.add_argument("prereg_id", type=int)
    p_rep.add_argument("--write", action="store_true",
                       help="write the report to runs/ instead of comparing")
    sub.add_parser("contrast-prereg")
    for name in ("contrast-run", "contrast-behavior"):
        cp = sub.add_parser(name)
        cp.add_argument("prereg_id", type=int)
    c_rep = sub.add_parser("contrast-report")
    c_rep.add_argument("prereg_id", type=int)
    c_rep.add_argument("--write", action="store_true")
    args = ap.parse_args()
    if args.cmd.startswith("contrast"):
        from experiments.selection_stress import contrast, report_contrast
        return {"contrast-prereg": contrast.cmd_contrast_prereg,
                "contrast-run": contrast.cmd_contrast_run,
                "contrast-behavior": contrast.cmd_contrast_behavior,
                "contrast-report": report_contrast.cmd_contrast_report,
                }[args.cmd](args)
    if args.cmd in ("probe", "prereg", "run-behavior", "report"):
        from experiments.selection_stress import behavior
        return {"probe": behavior.cmd_probe,
                "prereg": behavior.cmd_prereg,
                "run-behavior": behavior.cmd_run,
                "report": behavior.cmd_report}[args.cmd](args)
    return {"freeze": cmd_freeze, "build": cmd_build,
            "validity": cmd_validity, "grid": cmd_grid,
            "analyze": cmd_analyze, "selftest": cmd_selftest}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
