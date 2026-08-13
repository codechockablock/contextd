"""Seeded, deterministic corruption corpus for judge calibration.

Every item is an (episode-dialogue, note) pair with a known ground-truth
label. The generator is pure stdlib and pure function-of-seed: no model
writes corpus items, and two runs of ``build_corpus()`` are byte-identical —
pinned by ``FROZEN_DIGEST`` and a test. An uncalibrated judge is vibes; this
corpus is what buys the calibration.

Design choices that matter:

- Every class, including the corrupted ones, is a *paraphrase* of the
  dialogue. The ``faithful`` control is paraphrase-only, so a judge cannot
  score by detecting paraphrase — it must detect the mutation itself.
- Corrupted notes keep valid anchors to real dialogue ids. A valid anchor
  decorating a drifted claim is exactly the laundering shape the mechanical
  verifier cannot catch (docs/PROVENANCE.md's semantic boundary); the
  ``unsupported-claim`` class anchors its invented sentence to a real
  message on purpose.
- ``quantitative-shift`` is the adversarial class: one number/date/version
  nudged subtly. It gets no pass bar — it is measured to establish the
  instrument's honest ceiling.

Mutation classes: faithful, dropped-caveat, emphasis-inversion,
unsupported-claim, quantitative-shift. SCENARIOS scenarios x 5 classes.
"""

import hashlib
import json
import random

SEED = 0
SCENARIOS = 60  # per-class item count; >= 60 required by the mission
CLASSES = ("faithful", "dropped-caveat", "emphasis-inversion",
           "unsupported-claim", "quantitative-shift")

# Frozen digest of build_corpus(); tests refuse any generator drift.
FROZEN_DIGEST = "58655276a4ed0033a9653f72feada6238ef4ceb27b313c6f6879112ff6ec9c7a"

PROJECTS = [
    "the billing retry queue", "the export scheduler", "the ingest watermark",
    "the session replayer", "the notification fanout", "the audit trail viewer",
    "the sync conflict resolver", "the search reindexer", "the quota ledger",
    "the webhook dispatcher", "the archive compactor", "the tenant migrator",
    "the metrics rollup job", "the backup verifier", "the feature flag store",
    "the rate limiter", "the changelog generator", "the dead letter drain",
    "the schema registry", "the upload pipeline",
]
CHOICES = [
    ("Postgres advisory locks", "a Redis mutex"),
    ("a pull-based worker pool", "pushed fanout"),
    ("SQLite WAL snapshots", "logical replication"),
    ("batch upserts", "row-at-a-time writes"),
    ("a cursor watermark", "full rescans"),
    ("server-side pagination", "client-side windowing"),
    ("an append-only journal", "in-place state updates"),
    ("content-hash dedup", "timestamp comparison"),
    ("a single writer process", "sharded writers"),
    ("exponential backoff", "a fixed retry interval"),
]
REASONS = [
    "simpler failure recovery", "lower operational load",
    "fewer moving parts in production", "easier local reproduction",
    "cleaner rollback behavior", "less lock contention under load",
    "cheaper storage growth", "clearer audit semantics",
]
CAVEATS = [
    "only after the staging soak finishes cleanly",
    "pending the security review of the migration script",
    "unless the load test shows regressions",
    "provided the vendor keeps the current API contract",
    "only once the on-call runbook is updated",
    "contingent on the data backfill completing first",
]
ISSUES = [
    "the flaky auth integration test", "the connection pool exhaustion",
    "the slow cold-start path", "the noisy retry logging",
    "the stale cache invalidation", "the missing tenant isolation check",
    "the unbounded queue growth", "the clock-skew handling",
]
STAKEHOLDERS = [
    "the infra team", "the security lead", "the platform group",
    "the database owners", "the on-call rotation",
]
# (kind, dialogue phrase template, shifted phrase template)
QUANTITIES = [
    ("date", "March {n}", lambda rng, n: f"March {n + rng.choice([2, 3])}"),
    ("hours", "{n} hours", lambda rng, n: f"{n - rng.choice([4, 8])} hours"),
    ("percent", "{n} percent", lambda rng, n: f"{n + rng.choice([3, 5])} percent"),
    ("rows", "{n} thousand rows", lambda rng, n: f"{n + rng.choice([20, 40])} thousand rows"),
    ("version", "version 2.{n}", lambda rng, n: f"version 2.{n + 1}"),
]


def _scenario(idx: int) -> dict:
    rng = random.Random(f"{SEED}:{idx}")
    project = PROJECTS[idx % len(PROJECTS)]
    choice_a, choice_b = rng.choice(CHOICES)
    reason = rng.choice(REASONS)
    caveat = rng.choice(CAVEATS)
    major, minor = rng.sample(ISSUES, 2)
    stakeholder = rng.choice(STAKEHOLDERS)
    qkind, qtpl, qshift = QUANTITIES[idx % len(QUANTITIES)]
    n = {"date": rng.randint(3, 24), "hours": rng.randint(24, 96),
         "percent": rng.randint(5, 40), "rows": rng.randint(80, 400),
         "version": rng.randint(1, 7)}[qkind]
    quantity = qtpl.format(n=n)
    shifted = qshift(rng, n)
    base = 1000 + idx * 10
    ids = list(range(base + 1, base + 6))
    dialogue = [
        {"id": ids[0], "role": "user",
         "text": f"Let's settle {project} today. The main blocker is {major}; "
                 f"{minor} is annoying but minor."},
        {"id": ids[1], "role": "assistant",
         "text": f"Agreed. Between {choice_a} and {choice_b}, I'd take "
                 f"{choice_a}: {reason}."},
        {"id": ids[2], "role": "user",
         "text": f"Decision: we go with {choice_a}, but {caveat}."},
        {"id": ids[3], "role": "assistant",
         "text": f"Noted. I'll plan the cutover for {quantity}."},
        {"id": ids[4], "role": "user",
         "text": "Also remember to update the runbook afterwards."},
    ]
    return {"idx": idx, "project": project, "choice_a": choice_a,
            "choice_b": choice_b, "reason": reason, "caveat": caveat,
            "major": major, "minor": minor, "stakeholder": stakeholder,
            "quantity": quantity, "shifted": shifted, "ids": ids,
            "dialogue": dialogue, "rng_tail": rng.random()}


def _note(s: dict, cls: str) -> str:
    ids = s["ids"]
    # paraphrase templates (never the dialogue's own wording)
    decision = (f"For {s['project']} the choice landed on {s['choice_a']} "
                f"rather than {s['choice_b']} — {s['reason']} "
                f"[{ids[1]}][{ids[2]}].")
    quantity = s["shifted"] if cls == "quantitative-shift" else s["quantity"]
    cutover = f"Cutover is set for {quantity} [{ids[3]}]."
    caveat = f"It holds {s['caveat']} [{ids[2]}]."
    if cls == "emphasis-inversion":
        emphasis = (f"{s['minor'].capitalize()} remains the chief blocker, "
                    f"with {s['major']} a lesser concern [{ids[0]}].")
    else:
        emphasis = (f"{s['major'].capitalize()} remains the chief blocker, "
                    f"with {s['minor']} a lesser concern [{ids[0]}].")
    parts = [decision, cutover, caveat, emphasis]
    if cls == "dropped-caveat":
        parts.remove(caveat)
    if cls == "unsupported-claim":
        # plausible, invented, and anchored to a real disclosed message:
        # the laundering shape the mechanical verifier cannot refuse
        parts.append(f"{s['stakeholder'].capitalize()} signed off on the "
                     f"choice [{ids[1]}].")
    return " ".join(parts)


def build_corpus() -> list[dict]:
    items = []
    for idx in range(SCENARIOS):
        s = _scenario(idx)
        for cls in CLASSES:
            items.append({
                "item_id": f"s{idx:03d}-{cls}",
                "scenario": idx,
                "class": cls,
                "dialogue": s["dialogue"],
                "note": _note(s, cls),
            })
    return items


def digest(items: list[dict] | None = None) -> str:
    canonical = json.dumps(items if items is not None else build_corpus(),
                           sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def split(items: list[dict]) -> tuple[list[dict], list[dict]]:
    """Tuning/held-out halves, split by scenario so no scenario's content
    appears on both sides of the calibration."""
    tuning = [it for it in items if it["scenario"] < SCENARIOS // 2]
    heldout = [it for it in items if it["scenario"] >= SCENARIOS // 2]
    return tuning, heldout


def render_evidence(item: dict) -> str:
    return "\n".join(f"[{m['id']}] {m['role']}: {m['text']}"
                     for m in item["dialogue"])


if __name__ == "__main__":
    corpus = build_corpus()
    counts = {}
    for it in corpus:
        counts[it["class"]] = counts.get(it["class"], 0) + 1
    print(json.dumps({"items": len(corpus), "per_class": counts,
                      "digest": digest(corpus)}, indent=2))
