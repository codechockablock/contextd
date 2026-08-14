"""Statistics for the selection-stress benchmark. Stdlib only, all
deterministic: bootstrap uses a fixed seed pinned in the spec; permutation
tests enumerate exactly when the label space is small enough and otherwise
use a fixed-seed Monte Carlo sample with the count reported."""

import itertools
import math
import random

BOOT_SEED = 20260813
BOOT_N = 2000


def wilson(successes: int, n: int, z: float = 1.959964) -> tuple:
    """Wilson 95% interval for a binomial proportion."""
    if n == 0:
        return (None, None)
    p = successes / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, round(center - half, 4)), min(1.0, round(center + half, 4)))


def bootstrap_ci(values: list[float], n_boot: int = BOOT_N,
                 seed: int = BOOT_SEED) -> dict:
    """Percentile bootstrap over cluster-level values (typically one value
    per generator seed). Honest about tiny cluster counts: the width is the
    evidence, never hidden."""
    if not values:
        return {"mean": None, "lo": None, "hi": None, "n_clusters": 0}
    rng = random.Random(seed)
    means = []
    for _ in range(n_boot):
        sample = [values[rng.randrange(len(values))] for _ in values]
        means.append(sum(sample) / len(sample))
    means.sort()
    return {"mean": round(sum(values) / len(values), 4),
            "lo": round(means[int(0.025 * n_boot)], 4),
            "hi": round(means[min(n_boot - 1, int(0.975 * n_boot))], 4),
            "n_clusters": len(values)}


def perm_test(a: list[float], b: list[float], seed: int = BOOT_SEED,
              max_exact: int = 200_000) -> dict:
    """Two-sided exact permutation test on the difference of means;
    enumerates when C(n, |a|) <= max_exact, else fixed-seed Monte Carlo."""
    pooled = list(a) + list(b)
    n, k = len(pooled), len(a)
    if n == 0 or k == 0 or k == n:
        return {"p": None, "method": "degenerate"}
    obs = abs(sum(a) / len(a) - sum(b) / len(b))
    total = sum(pooled)

    def diff_for(idx_sum: float, size: int) -> float:
        mean_a = idx_sum / size
        mean_b = (total - idx_sum) / (n - size)
        return abs(mean_a - mean_b)

    n_comb = math.comb(n, k)
    if n_comb <= max_exact:
        hits = 0
        for combo in itertools.combinations(range(n), k):
            s = sum(pooled[i] for i in combo)
            if diff_for(s, k) >= obs - 1e-12:
                hits += 1
        return {"p": round(hits / n_comb, 6), "method": f"exact({n_comb})",
                "p_floor": round(1 / n_comb, 6)}
    rng = random.Random(seed)
    hits = 1  # observed labelling counts
    draws = 20_000
    idx = list(range(n))
    for _ in range(draws):
        rng.shuffle(idx)
        s = sum(pooled[i] for i in idx[:k])
        if diff_for(s, k) >= obs - 1e-12:
            hits += 1
    return {"p": round(hits / (draws + 1), 6), "method": f"mc({draws})",
            "p_floor": round(1 / (draws + 1), 6)}


def stratified_perm_test(cells: list[dict], seed: int = BOOT_SEED,
                         draws: int = 20_000) -> dict:
    """Pooled mean arm-difference with within-cell label shuffles. Each cell:
    {"a": [...], "b": [...]}. Deterministic via fixed seed."""
    valid = [c for c in cells if c["a"] and c["b"]]
    if not valid:
        return {"p": None, "method": "degenerate"}

    def pooled_diff(pairs) -> float:
        diffs = [sum(a) / len(a) - sum(b) / len(b) for a, b in pairs]
        return sum(diffs) / len(diffs)

    obs = abs(pooled_diff([(c["a"], c["b"]) for c in valid]))
    rng = random.Random(seed)
    hits = 1
    for _ in range(draws):
        shuffled = []
        for c in valid:
            pool = list(c["a"]) + list(c["b"])
            rng.shuffle(pool)
            shuffled.append((pool[:len(c["a"])], pool[len(c["a"]):]))
        if abs(pooled_diff(shuffled)) >= obs - 1e-12:
            hits += 1
    return {"p": round(hits / (draws + 1), 6), "method": f"stratified-mc({draws})",
            "observed_diff": round(obs, 4), "n_cells": len(valid)}
