#!/usr/bin/env python
"""Run the adversarial provenance suite and print the catch matrix.

Deterministic: no models, no statistics, ground truth by construction. Each
case builds inside its own throwaway synthetic archive (CONTEXTD_HOME in a
temp dir), so nothing here can touch or contaminate the live archive, FTS,
or any recall. The same matrix is pinned as a regression test in
tests/test_adversarial_matrix.py — this script exists to show the result and
the boundary, not to compute anything the test does not.

    .venv/bin/python experiments/provenance/adversarial.py
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from contextd import load_config  # noqa: E402
from contextd.db import connect  # noqa: E402
from experiments.provenance.cases import CASES, evaluate  # noqa: E402

LAYERS = ("anchor_only", "closure", "closure_quotes")


def run_all():
    """Each case builds inside its own throwaway archive; ids and outcomes
    are fully deterministic."""
    results = []
    for name, family, build, expected in CASES:
        with tempfile.TemporaryDirectory(prefix="ctx-adversarial-") as tmp:
            os.environ["CONTEXTD_HOME"] = tmp
            conn = connect()
            derived = build(conn, load_config())
            got = evaluate(conn, derived)
            conn.close()
        results.append((name, family, expected, got))
    return results


def main():
    results = run_all()
    w = max(len(n) for n, *_ in results)
    print(f"{'case':<{w}}  {'family':<16}  " +
          "  ".join(f"{layer:<14}" for layer in LAYERS))
    mismatches = 0
    for name, family, expected, got in results:
        cells = []
        for layer in LAYERS:
            mark = "" if got[layer] == expected[layer] else " *DRIFT*"
            cells.append(f"{got[layer] + mark:<14}")
        print(f"{name:<{w}}  {family:<16}  " + "  ".join(cells))
        mismatches += sum(got[la] != expected[la] for la in LAYERS)

    fams = {}
    for name, family, expected, got in results:
        fams.setdefault(family, []).append(got)
    print()
    for family, rows in fams.items():
        caught = {la: sum(1 for r in rows if r[la] in ("rejected", "flagged"))
                  for la in LAYERS}
        print(f"{family:<18} n={len(rows)}  " +
              "  ".join(f"{la} {caught[la]}/{len(rows)}" for la in LAYERS))
    print()
    print("semantic family 'caught 0/n' is the measured boundary, not a "
          "failure: no mechanical layer can decide natural-language "
          "entailment, and the kernel refuses to pretend otherwise.")
    if mismatches:
        sys.exit(f"\n{mismatches} cell(s) drifted from the pinned matrix")


if __name__ == "__main__":
    main()
