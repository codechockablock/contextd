"""Frozen vocabulary for the selection-stress synthetic archives.

Pools are chosen so that (component, object) pairs are unique per topic and
porter stems never collide across pools or with filler text. The task hint
for a topic is exactly four content terms — ``{verb} {comp} {obj} {qual}`` —
and the lexical bands are defined by how many of those terms the planted
item's text carries:

  near  all 4 terms (the only documents in a topic that can AND-match)
  mid   comp + obj  (2 terms; competes with topical dialogue under OR)
  far   obj only    (comp replaced by a synonym phrase; 1 term)

Cluster dialogue lines carry at most two hint terms and never the qualifier,
so the FTS every-term-AND path can only ever return near-band planted items;
every other topic query degrades to the OR walk, which is where the bm25
budget race happens.
"""

COMPONENTS = [
    "billing", "telemetry", "scheduler", "paywall", "onboarding", "sandbox",
    "ledgerette", "notifier", "importer", "gateway", "replicator", "throttler",
]

OBJECTS = [
    "manifest", "quota", "snapshot", "highwater", "rollup", "checksum",
    "backfill", "cursorline",
]

VERBS = [
    "migrate", "refactor", "harden", "consolidate", "deprecate", "partition",
    "instrument", "streamline",
]

QUALS = [
    "canary", "fallback", "offline", "regional", "quarterly", "staging",
    "legacy", "burst",
]

# far-band paraphrase: the component named without its pool word
SYNONYM = {
    "billing": "invoice pipeline",
    "telemetry": "usage signal feed",
    "scheduler": "job timing engine",
    "paywall": "subscription barrier",
    "onboarding": "first-run flow",
    "sandbox": "isolated trial env",
    "ledgerette": "append log",
    "notifier": "alert fanout",
    "importer": "intake path",
    "gateway": "edge router",
    "replicator": "copy machinery",
    "throttler": "rate limiter",
}

# decision payload options: rare hyphenated tokens, matched verbatim by the
# deterministic rubric. optA = adopted, optB = rejected, optC = the v2
# replacement in supersession pairs, optD/optE = decoy payloads.
#
# Revision 2: payload tokens are made globally unique per (topic, role) by
# suffixing a base option with a topic-derived suffix (OPTIONS x SUFFIXES =
# 576 combos > 87 topics x 5 roles). Revision 1 reused the bare 24-word pool
# across 87 topics; behavioral prereg #2 had to be voided when as-compiled
# runs in silently-absent cells matched the scored token via OTHER topics'
# carried decisions (false-positive floor ~5/8). The rubric needs token
# uniqueness to attribute a payload to its plant; this is an instrument
# identity change, recorded in the ledger (prereg_void event) and in the
# re-frozen spec.
OPTIONS = [
    "two-phase", "shadow-table", "copy-on-write", "single-writer",
    "event-sourced", "pull-based", "push-based", "lease-based",
    "chunked-scan", "columnar-swap", "fanout-tree", "gossip-sync",
    "write-behind", "read-repair", "hash-ring", "epoch-fence",
    "delta-merge", "tombstone-sweep", "vector-stamp", "quorum-read",
    "warm-standby", "cold-spill", "lazy-seal", "eager-flush",
]

SUFFIXES = [
    "atlas", "bramble", "cobalt", "dune", "ember", "fjord", "garnet",
    "harbor", "iris", "juniper", "krill", "lumen", "marrow", "nectar",
    "onyx", "pumice", "quartz", "rushes", "saffron", "tarn", "umber",
    "vellum", "wicker", "yarrow",
]


def unique_option(index: int) -> str:
    """Globally unique payload token for flat index = topic*5 + role."""
    return (OPTIONS[index % len(OPTIONS)] + "-"
            + SUFFIXES[(index // len(OPTIONS)) % len(SUFFIXES)])


REASONS = [
    "it doubles write amplification on the hot path",
    "it blocks rollback for a full release cycle",
    "it breaks the downstream audit trail",
    "it couples deploys to storage layout changes",
    "it starves the worker pool under load spikes",
    "it leaks tenant boundaries in shared caches",
    "it makes replay nondeterministic after crashes",
    "it triples the on-call surface for one quarter",
]

# filler vocabulary: deliberately disjoint stems from every pool above
FILLER_TOPICS = [
    "renaming internal config keys for consistency",
    "tightening type annotations in helper modules",
    "reworking log output into structured lines",
    "profiling the parse table and caching results",
    "cleaning up CLI help texts and usage examples",
    "moving test doubles to the builder helpers",
    "documenting release steps in the runbook",
    "flattening the error hierarchy into one module",
    "triaging flaky teardown ordering in the suite",
    "bumping pinned dependencies and re-locking",
]

PROJECT_NAMES = ["aster", "brontide", "corvid"]  # aster is the task project


def topic_terms(index: int) -> dict:
    """Deterministic topic vocabulary; (comp, obj) unique for index < 96."""
    comp = COMPONENTS[index % len(COMPONENTS)]
    obj = OBJECTS[(index // len(COMPONENTS)) % len(OBJECTS)]
    verb = VERBS[(index * 5 + 3) % len(VERBS)]
    qual = QUALS[(index * 3 + 1) % len(QUALS)]
    return {"comp": comp, "obj": obj, "verb": verb, "qual": qual}


def topic_hint(t: dict) -> str:
    return f"{t['verb']} {t['comp']} {t['obj']} {t['qual']}"


# --- planted item templates ---------------------------------------------------
# Template iteration record (manipulation-validity loop, ≤3 allowed):
#   it.1 (measured on t5k seed 101): near=4 terms / mid=2 / far=1. Ordering
#        gate PASSED (1.0/1.0/1.0; near median rank 1, mid ~97, far absent),
#        but mid's rank sits far beyond the pipeline's 40-hit recall cap, so
#        mid was pipeline-equivalent to far — a dead band. Rejected for
#        resolution, not for ordering.
#   it.2 (current): mid raised to 3 terms (verb comp obj, no qual) to place
#        it near the top-of-list boundary while near keeps the AND-exclusive
#        4-term profile. Re-measured before any grid run; see the validity
#        artifact for the numbers that admitted it.

def plant_text(band: str, t: dict, opt_a: str, opt_b: str, reason: str) -> str:
    if band == "near":
        return (f"Decision ({t['comp']} {t['obj']}): we will {t['verb']} the "
                f"{t['comp']} {t['obj']} on the {t['qual']} track — adopting "
                f"the {opt_a} strategy over the {opt_b} approach; {opt_b} "
                f"was rejected because {reason}.")
    if band == "mid":
        return (f"Decision: we chose to {t['verb']} the {t['comp']} "
                f"{t['obj']} — adopting the {opt_a} strategy over the "
                f"{opt_b} approach; {opt_b} was rejected because {reason}.")
    if band == "far":
        return (f"Decision: for the {SYNONYM[t['comp']]} effort we settled "
                f"on the {opt_a} strategy over the {opt_b} approach; {opt_b} "
                f"was rejected because {reason}. This also bounds the "
                f"{t['obj']} work.")
    raise ValueError(f"unknown band {band!r}")


def v2_text(t: dict, opt_a: str, opt_c: str) -> str:
    """The supersession: phrased differently and lexically far from the hint
    (obj only), which is exactly the stale-resurrection trap."""
    return (f"Revisited and superseded: we now go with the {opt_c} strategy "
            f"instead of the earlier {opt_a} call for this workstream; the "
            f"previous decision is void. Applies to the {t['obj']} path.")


def decoy_text(band: str, t: dict, opt_d: str, opt_e: str, reason: str) -> str:
    """Near-duplicate decoy: same band term profile, different payload."""
    return plant_text(band, t, opt_d, opt_e, reason)


def cluster_line(t: dict, i: int, filler: str) -> tuple[str, str]:
    """(role, text) for topical dialogue; at most 2 hint terms, never qual."""
    pats = [
        ("user", f"next step on the {t['comp']} {t['obj']}: {filler}"),
        ("assistant", f"{t['comp']} {t['obj']} progress: applied the change, "
                      f"tests green, continuing"),
        ("user", f"can we {t['verb']} the {t['comp']} piece after {filler}?"),
        ("assistant", f"looked at the {t['obj']} edge cases while {filler}"),
        ("user", f"status check on the {t['comp']} work"),
        ("assistant", f"the {t['obj']} side is stable; {filler} next"),
    ]
    return pats[i % len(pats)]
