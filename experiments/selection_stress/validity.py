"""Manipulation validity: do the lexical bands actually separate under the
real search walk? Measured, never assumed — the grid is forbidden without
this gate.

For every task-scoped grid topic, the plant's rank under its own hint is
measured via ``contextd.search.search`` (the exact function recall and the
checkpoint hint slice use), with a deep limit so far-band items can still be
observed. A plant absent even at the deep limit gets rank None (treated as
worse than any observed rank). The gate: within every matched context
(tier, seed, stratum, age, distractor), each band pair must be strictly
ordered near < mid < far in ≥ 0.9 of comparisons, pooled per pair across
the whole build set."""

from experiments.selection_stress.generator import contextd_home

DEEP_LIMIT = 200


def plant_rank(conn, hint: str, event_id: int) -> int | None:
    from contextd.search import search
    hits = search(conn, hint, limit=DEEP_LIMIT, highlight=False)
    for i, h in enumerate(hits):
        if h["id"] == event_id:
            return i + 1
    return None


def measure_archive(manifest: dict) -> list[dict]:
    """One row per task-scoped grid topic: coordinates + measured rank."""
    rows = []
    with contextd_home(manifest["home"]):
        from contextd.db import connect
        conn = connect()
        for tp in manifest["topics"]:
            if tp["scope"] != "task":
                continue
            rows.append({
                "tier": manifest["tier"], "seed": manifest["seed"],
                "stratum": tp["stratum"], "age": tp["age"],
                "band": tp["band"], "distractor": tp["distractor"],
                "rank": plant_rank(conn, tp["hint"], tp["plant"]["event_id"]),
            })
        conn.close()
    return rows


BAND_PAIRS = [("near", "mid"), ("mid", "far"), ("near", "far")]


def ordering_consistency(rows: list[dict]) -> dict:
    """Pairwise strict-ordering rate per band pair, pooled over matched
    contexts. None (absent) is worse than any rank; two absents are a tie
    and count against consistency."""
    by_ctx: dict[tuple, dict] = {}
    for r in rows:
        ctx = (r["tier"], r["seed"], r["stratum"], r["age"], r["distractor"])
        by_ctx.setdefault(ctx, {})[r["band"]] = r["rank"]
    out = {}
    for a, b in BAND_PAIRS:
        ok = total = 0
        for bands in by_ctx.values():
            if a not in bands or b not in bands:
                continue
            total += 1
            ra, rb = bands[a], bands[b]
            if ra is None and rb is None:
                continue  # tie: not strictly ordered
            if rb is None or (ra is not None and ra < rb):
                ok += 1
        out[f"{a}<{b}"] = {"consistent": ok, "total": total,
                           "rate": round(ok / total, 4) if total else None}
    return out


def rank_summary(rows: list[dict]) -> dict:
    """Median observed rank per band (None counted separately)."""
    out = {}
    for band in ("near", "mid", "far"):
        ranks = sorted(r["rank"] for r in rows
                       if r["band"] == band and r["rank"] is not None)
        absent = sum(1 for r in rows if r["band"] == band and r["rank"] is None)
        out[band] = {
            "n": len(ranks) + absent, "absent": absent,
            "median_rank": ranks[len(ranks) // 2] if ranks else None,
            "min": ranks[0] if ranks else None,
            "max": ranks[-1] if ranks else None,
        }
    return out


def gate(consistency: dict, bar: float = 0.9) -> dict:
    fails = {pair: v for pair, v in consistency.items()
             if v["total"] and v["rate"] is not None and v["rate"] < bar}
    return {"bar": bar, "passed": not fails, "failing_pairs": fails}
