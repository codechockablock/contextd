"""Pin the adversarial provenance catch matrix.

The expected outcomes in experiments/provenance/cases.py are ground truth by
construction. Any drift — a laundering case that starts passing, a positive
control that starts failing, or a semantic-boundary case that a future
change claims to 'catch' mechanically — fails here and must be argued for
explicitly rather than slipping in."""

from experiments.provenance.adversarial import LAYERS, run_all


def test_adversarial_matrix_matches_pinned_ground_truth():
    for name, family, expected, got in run_all():
        assert got == expected, f"{name}: expected {expected}, got {got}"


def test_families_summarize_as_documented():
    """The headline numbers docs/PROVENANCE.md quotes, derived not asserted."""
    by_family = {}
    for name, family, expected, got in run_all():
        by_family.setdefault(family, []).append(got)

    def caught(family, layer):
        rows = by_family[family]
        return sum(1 for r in rows if r[layer] in ("rejected", "flagged"))

    # fabricated/forged chains: fully caught by the closure verifier
    assert caught("fabrication", "closure_quotes") == len(by_family["fabrication"])
    # the quote layer is load-bearing for exactly the fabricated-quote case
    assert caught("fabrication", "closure") == len(by_family["fabrication"]) - 1
    # visibility laundering: invisible to the baseline, fully flagged now
    assert caught("visibility", "anchor_only") == 0
    assert caught("visibility", "closure") == len(by_family["visibility"])
    # the semantic boundary: no mechanical layer catches these, by design
    for layer in LAYERS:
        assert caught("semantic", layer) == 0
    # a verifier that rejects everything is useless: controls always pass
    for layer in LAYERS:
        assert caught("positive_control", layer) == 0
