"""The frozen selection-stress spec: grid coordinates, scoring classes,
headline definitions, and instrument identity (module hashes). Frozen before
the grid runs; the behavioral preregistration additionally freezes its own
cell selection, arms, rubric, and dispatch plan (built AFTER the carriage
grid by design — the mission requires cells spanning measured successes and
failures — but BEFORE any model run).

Nothing here may change after ``bench.py freeze`` without voiding the run
(the stored digest is compared on every later command)."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent

GRID_SPEC = {
    "benchmark": "selection-stress-v1",
    "frozen": "2026-08-13",
    "revision": 2,
    "revision_history": [
        "r1 frozen 2026-08-13 sha 9d8a36729926437a5a69eb5f513b0c240d21302f"
        "e5371d904dc846c9e71ebecd; superseded same day: payload option "
        "tokens were reused across topics, giving the behavioral rubric a "
        "false-positive floor (prereg #2 voided, ledger event #35). r2 "
        "makes payload tokens globally unique per (topic, role); all "
        "deterministic phases rebuilt from scratch under r2.",
    ],
    "tiers": {"t5k": 5000, "t20k": 20000, "t80k": 80000},
    "seeds": [101, 102, 103, 104, 105],
    "budgets": [4000, 2000, 8000],
    "default_budget": 4000,
    "coordinates": {
        "strata": ["note", "episode", "dialogue"],
        "ages": {
            "recent": "pinned stratum-rank ladder (generator.RECENT_KS), "
                      "rotated per seed across the 9 band x distractor "
                      "cells of each stratum",
            "mid": "~30% stratum depth, cell-spread, seed-jittered",
            "deep": "~85% stratum depth, cell-spread, seed-jittered",
        },
        "bands": {
            "near": "all 4 hint terms (AND-exclusive)",
            "mid": "3 hint terms: verb comp obj (template iteration 2; "
                   "iteration 1's 2-term mid ranked ~97, beyond the 40-hit "
                   "recall cap — pipeline-equivalent to far, rejected for "
                   "resolution before any grid run)",
            "far": "1 hint term (obj); component replaced by synonym phrase",
        },
        "distractors": ["none", "decoy(2 near-duplicates at ranks k-1,k+2)",
                        "super(v1 at cell coords; v2 younger at 0.4k, "
                        "phrased differently, lexically far)"],
        "twins": "6 extra near-band pairs (task plant + other-project twin "
                 "one rank younger, same vocabulary) measuring cross-project "
                 "bleed; reported separately from the 81-cell grid",
    },
    "scoring": {
        "carried": "plant event id in compiled package item list",
        "omitted_named": "absent but id named in a loud-omission line "
                         "(measured, expected structurally ~0 outside loops)",
        "silently_absent": "absent and unnamed",
        "stale_resurrected": "supersession cells: v1 carried and v2 absent",
        "no_hint": "one extra compile per (archive, budget) with empty hint, "
                   "scored against every topic",
    },
    "validity_gate": {
        "measure": "plant rank under its own hint via contextd.search.search "
                   "limit=200 (absent = worse than any rank)",
        "bar": "each band pair strictly ordered in >= 0.9 of matched "
               "contexts, pooled per pair over all tiers and seeds",
    },
    "headlines": {
        "a": "smallest (tier, age, band) region — severity order: tier "
             "ascending, age recent<mid<deep, band near<mid<far — where "
             "silent absence of planted decisions exceeds 20% at the "
             "default budget (hinted compiles, all distractors pooled), "
             "with a bootstrap CI over generator seeds",
        "b": "overall stale-resurrection rate where v2 exists (hinted, "
             "default budget), bootstrap CI over seeds",
        "c": "compile latency vs tier (mean ms, bootstrap CI over seeds)",
    },
    "stats": {"bootstrap": {"seed": 20260813, "n": 2000, "cluster": "seed"},
              "cell_intervals": "Wilson 95%"},
}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_spec() -> dict:
    spec = json.loads(json.dumps(GRID_SPEC))
    spec["instrument"] = {
        "vocab_sha": _sha(ROOT / "vocab.py"),
        "generator_sha": _sha(ROOT / "generator.py"),
        "carriage_sha": _sha(ROOT / "carriage.py"),
        "validity_sha": _sha(ROOT / "validity.py"),
        "stats_sha": _sha(ROOT / "stats.py"),
    }
    return spec


def spec_sha() -> str:
    return hashlib.sha256(
        json.dumps(build_spec(), sort_keys=True).encode()).hexdigest()


FROZEN = ROOT / "spec-frozen.json"


def freeze() -> dict:
    spec = build_spec()
    FROZEN.write_text(json.dumps(spec, indent=1, sort_keys=True) + "\n")
    return {"sha": spec_sha(), "path": str(FROZEN)}


def check_frozen() -> dict:
    if not FROZEN.exists():
        return {"ok": False, "why": "spec never frozen"}
    stored = json.loads(FROZEN.read_text())
    live = build_spec()
    ok = stored == live
    return {"ok": ok, "sha": spec_sha(),
            "why": None if ok else "live spec differs from frozen spec"}
