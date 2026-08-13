"""Synthetic calibration: derive decision bars and sample sizes from
simulated null/positive mechanism behavior — never from observed model
results and never copied from the prior series' n.

Regimes simulated (both grounded in the measured record, neither in hoped
results):
- capture null-alternative: the prior series' inference mechanisms carried
  the target with P ~= 0.5 (runs/handoff-20260812/notes.md); an autonomous
  claim must be separable from that coin-flip regime, not from zero.
- use without-arm: the best automatic representation recovered the older
  conditional target at 0.25 (exp #41905 raw-tail/recall); the with-arm
  regime worth claiming is >= 0.9 (exp #42203 measured 5/5 with an explicit
  note; we do not assume our format matches it, we require the design to
  detect it if true).

Everything here is deterministic (seeded) and rebuildable; `calibrate`
writes calibration.json next to this file's results dir and prints the
frozen proposal."""

import json
import math
import random
from itertools import combinations
from pathlib import Path

RESULTS = Path(__file__).resolve().parent / "results"

CAPTURE_NULL_P = 0.5      # prior-failure coin-flip regime
CAPTURE_POS_P = 0.95      # a mechanism worth calling autonomous
USE_WITHOUT_P = 0.25      # measured best automatic arm (#41905)
USE_WITH_P = 0.9          # explicit-channel regime the design must detect
FLIP_BOUND = 0.05


def _binom_tail(n: int, k: int, p: float) -> float:
    """P(X >= k) for X ~ Binomial(n, p)."""
    total = 0.0
    for i in range(k, n + 1):
        total += math.comb(n, i) * p**i * (1 - p) ** (n - i)
    return total


def calibrate_capture(n_plants: int) -> dict:
    """Choose the smallest passing count k such that the coin-flip regime
    passes with probability <= FLIP_BOUND, then report the positive regime's
    stability at that bar and the regime pair the design separates."""
    k = next(k for k in range(n_plants + 1)
             if _binom_tail(n_plants, k, CAPTURE_NULL_P) <= FLIP_BOUND)
    null_pass = _binom_tail(n_plants, k, CAPTURE_NULL_P)
    pos_pass = _binom_tail(n_plants, k, CAPTURE_POS_P)
    # the smallest n at which BOTH flip sides drop under the bound for the
    # 0.5 / 0.9 pair — reported so the n we actually have is honest about
    # what it can and cannot separate
    n_for_09 = None
    for n in range(6, 61):
        kk = next(k2 for k2 in range(n + 1)
                  if _binom_tail(n, k2, CAPTURE_NULL_P) <= FLIP_BOUND)
        if 1 - _binom_tail(n, kk, 0.9) <= FLIP_BOUND:
            n_for_09 = n
            break
    return {
        "n_plants": n_plants,
        "pass_threshold_count": k,
        "capture_min": round(k / n_plants, 4),
        "null_regime_p": CAPTURE_NULL_P,
        "null_pass_prob": round(null_pass, 4),
        "positive_regime_p": CAPTURE_POS_P,
        "positive_pass_prob": round(pos_pass, 4),
        "positive_flip_prob": round(1 - pos_pass, 4),
        "stable_for_regimes": [CAPTURE_NULL_P, CAPTURE_POS_P],
        "n_needed_to_separate_0.5_from_0.9": n_for_09,
        "note": ("verdict stable (<=5% flip both sides) for the "
                 f"{CAPTURE_NULL_P} vs {CAPTURE_POS_P} pair at this n; a true "
                 "0.85-0.9 mechanism risks under-crediting — the conservative "
                 "direction for an autonomous claim"),
    }


def calibrate_burden(n_dialogues: int, seed: int = 0) -> dict:
    """Burden bar: mean false candidates per dialogue. A silent mechanism
    scores 0; the retro extractor drowned one target in ~20 stale threads.
    Bar 1.0 (one dismissal per dialogue on average) separates a Poisson(0.3)
    'occasionally wrong' regime from Poisson(2) 'noisy' with the flip
    probabilities reported."""
    rng = random.Random(seed)
    bar = 1.0

    def pass_prob(lam):
        passes = 0
        for _ in range(4000):
            mean = sum(_poisson(rng, lam) for _ in range(n_dialogues)) / n_dialogues
            passes += mean <= bar
        return passes / 4000

    return {"n_dialogues": n_dialogues, "burden_max": bar,
            "quiet_regime_lambda": 0.3,
            "quiet_pass_prob": round(pass_prob(0.3), 4),
            "noisy_regime_lambda": 2.0,
            "noisy_pass_prob": round(pass_prob(2.0), 4)}


def _poisson(rng, lam):
    l_exp, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= l_exp:
            return k
        k += 1


def _stratified_perm_p(with_runs, without_runs, n_strata, rng, trials=2000):
    """Permutation p for the pooled mean difference, permuting arm labels
    within each stratum (world). with_runs/without_runs: list per stratum."""
    obs = (sum(sum(w) for w in with_runs) / sum(len(w) for w in with_runs)
           - sum(sum(w) for w in without_runs) / sum(len(w) for w in without_runs))
    extreme = 0
    for _ in range(trials):
        d_with, d_without = [], []
        for s in range(n_strata):
            pool = list(with_runs[s]) + list(without_runs[s])
            rng.shuffle(pool)
            d_with.append(pool[:len(with_runs[s])])
            d_without.append(pool[len(with_runs[s]):])
        d = (sum(sum(w) for w in d_with) / sum(len(w) for w in d_with)
             - sum(sum(w) for w in d_without) / sum(len(w) for w in d_without))
        if abs(d) >= abs(obs) - 1e-12:
            extreme += 1
    return extreme / trials


def calibrate_use(n_worlds: int = 4, seed: int = 1) -> dict:
    """Smallest per-world-per-arm n where the stratified permutation design
    detects USE_WITH_P vs USE_WITHOUT_P with power >= 0.9 at p <= 0.05, with
    the null's false-positive rate verified <= 0.05 by simulation."""
    rng = random.Random(seed)
    out = {}
    chosen = None
    for n in (4, 5, 6, 7, 8):
        power_hits = null_hits = 0
        sims = 300
        for _ in range(sims):
            w = [[1 if rng.random() < USE_WITH_P else 0 for _ in range(n)]
                 for _ in range(n_worlds)]
            wo = [[1 if rng.random() < USE_WITHOUT_P else 0 for _ in range(n)]
                  for _ in range(n_worlds)]
            if _stratified_perm_p(w, wo, n_worlds, rng, trials=400) <= 0.05:
                power_hits += 1
            wn = [[1 if rng.random() < USE_WITHOUT_P else 0 for _ in range(n)]
                  for _ in range(n_worlds)]
            won = [[1 if rng.random() < USE_WITHOUT_P else 0 for _ in range(n)]
                   for _ in range(n_worlds)]
            if _stratified_perm_p(wn, won, n_worlds, rng, trials=400) <= 0.05:
                null_hits += 1
        power = power_hits / sims
        fpr = null_hits / sims
        out[n] = {"power": round(power, 3), "null_fpr": round(fpr, 3)}
        if chosen is None and power >= 0.9 and fpr <= 0.05:
            chosen = n
    return {"n_worlds": n_worlds, "regimes": [USE_WITHOUT_P, USE_WITH_P],
            "per_n": out, "n_per_arm_per_world": chosen,
            "primary_p_bar": 0.05}


def exact_min_p_floor(n_a: int, n_b: int) -> float:
    return round(2 / math.comb(n_a + n_b, n_a), 6)


def run(n_heldout_plants: int, n_heldout_dialogues: int) -> dict:
    cal = {
        "capture": calibrate_capture(n_heldout_plants),
        "burden": calibrate_burden(n_heldout_dialogues),
        "use": calibrate_use(),
        "false_promotion_bar": 0,
        "derivation": ("bars derived from simulated regimes grounded in "
                       "measured priors (see module docstring), computed "
                       "before any implementation results or model runs"),
    }
    return cal


if __name__ == "__main__":
    from experiments.open_loops.fixtures import split_fixtures
    split = split_fixtures()
    held = split["heldout"]
    n_plants = sum(1 for f in held for p in f["planted"]
                   if p["label"] == "must_capture")
    n_dialogues = sum(1 for f in held if f["shape"] != "identical_pair")
    cal = run(n_plants, n_dialogues)
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "calibration.json").write_text(json.dumps(cal, indent=2))
    print(json.dumps(cal, indent=2))


# used by combinations import guard (kept for exact small-split designs)
_ = combinations
