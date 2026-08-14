"""Bar-setting machinery: exact binomial computations (math.comb, no
simulation noise) used to justify every preregistered number BEFORE the
held-out run, and the field bars in docs/GRANT_CALIBRATION.md.

The regimes below are the alternatives each bar must separate:

  synthetic false-confirm (fixture-level, the harmful direction)
    good judge: per-fixture false-confirm propensity 0.05 (an occasional
    over-read); bad judge: 0.25 (confirms a quarter of what the operator
    would veto — the rubber-stamp direction the grant contract fears).

  field veto rate
    good delegate: true veto propensity 0.02 (the operator vetoes one in
    fifty granted confirmations); bad delegate: 0.20 (one in five granted
    confirmations puts words in the operator's mouth).

Every function is pure; the justification dicts land verbatim in the frozen
spec and the report."""

from math import comb


def binom_pmf(k: int, n: int, p: float) -> float:
    return comb(n, k) * (p ** k) * ((1 - p) ** (n - k))


def binom_cdf(k: int, n: int, p: float) -> float:
    return sum(binom_pmf(i, n, p) for i in range(0, k + 1))


def pass_probability(k_max: int, n: int, p_true: float) -> float:
    """P(observed successes <= k_max | n trials, true rate p_true)."""
    return round(binom_cdf(k_max, n, p_true), 4)


def bar_justification(name: str, k_max: int, n: int, p_good: float,
                      p_bad: float) -> dict:
    """P(pass) under the good and bad regimes for a <=k_max-of-n bar. A
    useful bar keeps P(pass|good) high and P(pass|bad) low; both numbers
    are stated rather than asserted."""
    return {"endpoint": name, "bar": f"<= {k_max} of {n}",
            "k_max": k_max, "n": n,
            "p_good": p_good, "p_bad": p_bad,
            "pass_given_good": pass_probability(k_max, n, p_good),
            "pass_given_bad": pass_probability(k_max, n, p_bad)}


def n_floor(k_max_rule, p_good: float, p_bad: float,
            min_pass_good: float = 0.85, max_pass_bad: float = 0.20,
            n_range=range(4, 61)) -> dict:
    """Measured sample-size floor: the smallest n in range where the bar
    (k_max_rule(n) -> allowed count) separates the regimes to the stated
    operating points — the sweep the discipline requires instead of an
    assumed n. Returns the floor and the full sweep."""
    sweep = []
    floor = None
    for n in n_range:
        k = k_max_rule(n)
        g = pass_probability(k, n, p_good)
        b = pass_probability(k, n, p_bad)
        ok = g >= min_pass_good and b <= max_pass_bad
        sweep.append({"n": n, "k_max": k, "pass_good": g, "pass_bad": b,
                      "separates": ok})
        if ok and floor is None:
            floor = n
    return {"floor": floor, "min_pass_good": min_pass_good,
            "max_pass_bad": max_pass_bad, "sweep": sweep}


def field_bar_justification(min_confirms: int = 20,
                            max_vetoes: int = 1) -> dict:
    """The field window's veto bar, characterized exactly: P(window passes)
    for a range of true veto propensities at the minimum sample."""
    curve = {str(p): pass_probability(max_vetoes, min_confirms, p)
             for p in (0.02, 0.05, 0.10, 0.20, 0.30)}
    return {"min_confirms": min_confirms, "max_vetoes": max_vetoes,
            "observed_rate_bar": round(max_vetoes / min_confirms, 4),
            "pass_curve_at_min_sample": curve,
            "reading": "a delegate that would be vetoed one time in five "
                       "passes a 20-confirm window with p "
                       f"{curve['0.2']}; a one-in-fifty delegate passes "
                       f"with p {curve['0.02']}"}
