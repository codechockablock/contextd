"""The connective ranker UNDER TEST — lives in experiments/, not the kernel,
until the three-way retrieval trial earns it (or doesn't).

Lexicon provenance: written 2026-08-12 for the step-0 ranking probe, BEFORE
the three-way causal trial this module feeds; the step-0 result (carriers
2.1x density on the synthesis match set, p=0.0011; sign REVERSED on the
constraint-flavored family) is correlational only. Known circularity caveat,
recorded: the analyst had read excerpts of some carrier items before writing
the lexicon; the discriminant sign-reversal argues against overfitting, a
held-out replication would settle it. Density is computed on raw stored
content per 1k estimated tokens; items under 80 chars are unranked (tiny
titles distort per-token rates)."""

import re

MARKERS = [
    r"\bbecause\b", r"\bsince\b", r"\btherefore\b", r"\bso that\b",
    r"\binstead of\b", r"\brather than\b", r"\breject(?:ed|s)?\b",
    r"\brefus(?:ed|es)\b", r"\balternativ", r"\btrade-?off", r"\bwhy not\b",
    r"\bwould have\b", r"\bcould have\b", r"\bshould have\b",
    r"\bdidn'?t\b", r"\bdid not\b", r"\bfail(?:ed|ure|s)?\b", r"\bdead end",
    r"\babandon", r"\bdefer(?:red)?\b", r"\buntil\b", r"\bearn(?:ed|s)?\b",
    r"\bwrong\b", r"\bmistake", r"\bhowever\b", r"\bbut\b", r"\bversus\b",
    r"\bhonest", r"\botherwise\b", r"\bthe reason\b", r"\bnot (?:a|the|because)\b",
]
_RX = [re.compile(m, re.I) for m in MARKERS]


def density(text: str) -> float:
    """Connective-marker occurrences per 1k estimated tokens."""
    n = max(1, len(text) // 4)
    return sum(len(rx.findall(text)) for rx in _RX) / n * 1000


def rank_candidates(conn, query: str, until: str = "", descending: bool = True):
    """Rank the bm25 match set (top 40) by connective density. Returns
    [(id, density), ...]; ids only — selection, rendering, never_leave, and
    budget packing all stay in the kernel walk (select_items ranked_ids)."""
    from contextd.search import search
    scored = []
    for h in search(conn, query, limit=40, highlight=False,
                    until=until or None):
        row = conn.execute("SELECT content FROM events WHERE id = ?",
                           (h["id"],)).fetchone()
        text = row["content"] or ""
        if len(text) < 80:
            continue
        scored.append((h["id"], round(density(text), 2)))
    scored.sort(key=lambda t: -t[1] if descending else t[1])
    return scored
