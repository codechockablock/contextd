"""Aggregation and report rendering. Every function is a pure function of
the durable artifacts (validity.json, grid/rows.jsonl, behavior records), so
``bench.py report`` reproduces the stored report byte-identically; nothing
here reads a clock or an unseeded RNG."""

import json
from pathlib import Path

from experiments.selection_stress import stats

TIER_ORDER = ["t5k", "t20k", "t80k"]
AGE_ORDER = ["recent", "mid", "deep"]
BAND_ORDER = ["near", "mid", "far"]


def load_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def _rate(rows: list[dict], key: str) -> tuple[int, int]:
    hits = sum(1 for r in rows if r.get(key))
    return hits, len(rows)


def _seed_rates(rows: list[dict], key: str) -> list[float]:
    by_seed: dict[int, list[dict]] = {}
    for r in rows:
        by_seed.setdefault(r["seed"], []).append(r)
    return [sum(1 for r in g if r.get(key)) / len(g)
            for _, g in sorted(by_seed.items())]


def default_hinted(rows: list[dict], budget: int) -> list[dict]:
    return [r for r in rows if r["hinted"] and r["budget"] == budget
            and r["scope"] == "task"]


def surface(rows: list[dict], budget: int) -> list[dict]:
    """Carriage / silent-absence per (tier, age, band), pooled over strata,
    distractors, seeds; Wilson 95% per cell."""
    base = default_hinted(rows, budget)
    out = []
    for tier in TIER_ORDER:
        for age in AGE_ORDER:
            for band in BAND_ORDER:
                cell = [r for r in base if r["tier"] == tier
                        and r["age"] == age and r["band"] == band]
                if not cell:
                    continue
                c, n = _rate(cell, "carried")
                s, _ = _rate(cell, "silently_absent")
                out.append({"tier": tier, "age": age, "band": band, "n": n,
                            "carried": round(c / n, 4),
                            "silent_absent": round(s / n, 4),
                            "silent_ci": stats.wilson(s, n)})
    return out


def headline_a(rows: list[dict], budget: int) -> dict:
    """First severity-ordered (tier, age, band) region whose silent-absence
    rate exceeds 0.20 at the default budget."""
    base = default_hinted(rows, budget)
    for tier in TIER_ORDER:
        for age in AGE_ORDER:
            for band in BAND_ORDER:
                cell = [r for r in base if r["tier"] == tier
                        and r["age"] == age and r["band"] == band]
                if not cell:
                    continue
                s, n = _rate(cell, "silently_absent")
                if n and s / n > 0.20:
                    return {"region": {"tier": tier, "age": age, "band": band},
                            "rate": round(s / n, 4), "n": n,
                            "wilson": stats.wilson(s, n),
                            "bootstrap": stats.bootstrap_ci(
                                _seed_rates(cell, "silently_absent"))}
    return {"region": None}


def headline_b(rows: list[dict], budget: int) -> dict:
    base = [r for r in default_hinted(rows, budget)
            if r["distractor"] == "super"]
    s, n = _rate(base, "stale_resurrected")
    return {"rate": round(s / n, 4) if n else None, "n": n,
            "wilson": stats.wilson(s, n),
            "bootstrap": stats.bootstrap_ci(
                _seed_rates(base, "stale_resurrected"))}


def headline_c(rows: list[dict]) -> dict:
    out = {}
    for tier in TIER_ORDER:
        sub = [r for r in rows if r["tier"] == tier and r["hinted"]]
        by_seed: dict[int, list[float]] = {}
        for r in sub:
            by_seed.setdefault(r["seed"], []).append(r["latency_ms"])
        seed_means = [sum(v) / len(v) for _, v in sorted(by_seed.items())]
        out[tier] = stats.bootstrap_ci(seed_means)
    return out


def band_x_age_by_tier(rows: list[dict], budget: int) -> dict:
    base = default_hinted(rows, budget)
    tables = {}
    for tier in TIER_ORDER:
        grid = {}
        for age in AGE_ORDER:
            for band in BAND_ORDER:
                cell = [r for r in base if r["tier"] == tier
                        and r["age"] == age and r["band"] == band]
                if cell:
                    c, n = _rate(cell, "carried")
                    grid[f"{age}/{band}"] = round(c / n, 4)
        tables[tier] = grid
    return tables


def stratum_table(rows: list[dict], budget: int) -> dict:
    base = default_hinted(rows, budget)
    out = {}
    for stratum in ("note", "episode", "dialogue"):
        for age in AGE_ORDER:
            cell = [r for r in base if r["stratum"] == stratum
                    and r["age"] == age]
            if cell:
                c, n = _rate(cell, "carried")
                out[f"{stratum}/{age}"] = {"carried": round(c / n, 4), "n": n}
    return out


def budget_sensitivity(rows: list[dict], budgets: list[int]) -> dict:
    out = {}
    for b in budgets:
        base = default_hinted(rows, b)
        c, n = _rate(base, "carried")
        s, _ = _rate(base, "silently_absent")
        out[str(b)] = {"carried": round(c / n, 4),
                       "silent_absent": round(s / n, 4), "n": n}
    return out


def no_hint_table(rows: list[dict], budget: int) -> dict:
    base = [r for r in rows if not r["hinted"] and r["budget"] == budget
            and r["scope"] == "task"]
    out = {}
    for age in AGE_ORDER:
        cell = [r for r in base if r["age"] == age]
        if cell:
            c, n = _rate(cell, "carried")
            out[age] = {"carried": round(c / n, 4), "n": n}
    return out


def twins_table(rows: list[dict], budget: int) -> dict:
    base = [r for r in rows if r["hinted"] and r["budget"] == budget
            and r["scope"] == "twin"]
    if not base:
        return {}
    twin_c, n = _rate(base, "twin_carried")
    task_c, _ = _rate(base, "carried")
    displaced = sum(1 for r in base
                    if r.get("twin_carried") and not r.get("carried"))
    return {"n": n, "twin_carried": round(twin_c / n, 4),
            "task_carried": round(task_c / n, 4),
            "twin_instead_of_task": round(displaced / n, 4)}


def decoy_table(rows: list[dict], budget: int) -> dict:
    base = default_hinted(rows, budget)
    decoy = [r for r in base if r["distractor"] == "decoy"]
    none = [r for r in base if r["distractor"] == "none"]
    dc, dn = _rate(decoy, "carried")
    nc, nn = _rate(none, "carried")
    with_decoy_carried = sum(r.get("decoys_carried", 0) for r in decoy)
    return {"carried_with_decoys": round(dc / dn, 4) if dn else None,
            "carried_without": round(nc / nn, 4) if nn else None,
            "mean_decoys_carried": round(with_decoy_carried / dn, 4) if dn else None,
            "n": dn}


def omission_channel(rows: list[dict]) -> dict:
    named = sum(1 for r in rows if r.get("omitted_named"))
    return {"omitted_named_total": named, "rows": len(rows)}


def analyze(validity_doc: dict, rows: list[dict], spec: dict) -> dict:
    budgets = spec["budgets"]
    default = spec["default_budget"]
    return {
        "validity": validity_doc,
        "surface": surface(rows, default),
        "surface_by_tier": band_x_age_by_tier(rows, default),
        "stratum": stratum_table(rows, default),
        "budgets": budget_sensitivity(rows, budgets),
        "no_hint": no_hint_table(rows, default),
        "twins": twins_table(rows, default),
        "decoys": decoy_table(rows, default),
        "omission_channel": omission_channel(rows),
        "headline_a": headline_a(rows, default),
        "headline_b": headline_b(rows, default),
        "headline_c": headline_c(rows),
        "n_rows": len(rows),
    }
