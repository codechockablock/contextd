"""Deterministic synthetic-archive generator for the selection-stress grid.

Fully seeded and model-free: same (tier, seed, mode) ⇒ byte-identical event
sequence ⇒ identical chain-tip digest. Archives are built into isolated
CONTEXTD_HOME directories through the public ``contextd.db.append_event``
path only; timestamps are simulated by patching the db module's clock for
the duration of the build (harness-side patching — the kernel on disk is
untouched).

Coordinates of a planted item:

  stratum    note (human) / episode (reconciled model note) / dialogue
  age        stratum-native rank of the plant (k-th most recent item of its
             stratum): recent = a pinned ladder of shallow ranks straddling
             the slice capacity, mid = ~30% stratum depth, deep = ~85%
  band       lexical distance from the topic's 4-term hint (vocab.py)
  distractor none / two near-duplicate decoys / a supersession pair (the
             plant is v1; v2 is younger, phrased differently, lexically far)

Each topic owns unique (component, object) vocabulary and its own hint, so
recall competition is within-topic by construction. Six extra "twin" pairs
plant the same vocabulary in another project to measure cross-project bleed;
they are reported separately from the 81-cell grid.
"""

import json
import random
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from experiments.selection_stress import vocab

TIERS = {"tiny": 700, "t5k": 5000, "t20k": 20000, "t80k": 80000}

BANDS = ["near", "mid", "far"]
AGES = ["recent", "mid", "deep"]
STRATA = ["note", "episode", "dialogue"]
DISTRACTORS = ["none", "decoy", "super"]

MINI = {"bands": ["near", "far"], "ages": ["recent", "deep"],
        "strata": ["note", "dialogue"], "distractors": ["none", "super"]}

CLUSTER_LINES = 20
MINI_CLUSTER_LINES = 5
TWIN_CLUSTER_LINES = 8

# recent-age rank ladders (stratum-native, straddling slice capacity at the
# default budget); rotated per seed so cell↔rank assignment is not confounded
RECENT_KS = {
    "note": [2, 4, 6, 8, 11, 14, 18, 24, 30],
    "episode": [2, 4, 6, 8, 11, 14, 18, 24, 30],
    "dialogue": [8, 16, 26, 38, 52, 68, 90, 120, 160],
}

SIM_START = datetime(2026, 2, 1, tzinfo=timezone.utc)
SIM_SPAN_DAYS = 160

HOME_CONFIG = """# synthetic selection-stress archive — generated config
[gate]
daily_token_budget = 100000000

[liveness]
stale_after_hours = {}
"""


@contextmanager
def simulated_clock(n_events: int):
    """Patch contextd.db.now_iso with an index-based deterministic clock."""
    import contextd.db as db
    state = {"i": 0}
    step = SIM_SPAN_DAYS * 86400 / max(n_events, 1)
    real = db.now_iso

    def fake() -> str:
        state["i"] += 1
        t = SIM_START + timedelta(seconds=round(state["i"] * step))
        return t.isoformat(timespec="seconds")

    db.now_iso = fake
    try:
        yield
    finally:
        db.now_iso = real


@contextmanager
def contextd_home(path):
    import os
    old = os.environ.get("CONTEXTD_HOME")
    os.environ["CONTEXTD_HOME"] = str(path)
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("CONTEXTD_HOME", None)
        else:
            os.environ["CONTEXTD_HOME"] = old


def grid_cells(mini: bool = False) -> list[dict]:
    bands = MINI["bands"] if mini else BANDS
    ages = MINI["ages"] if mini else AGES
    strata = MINI["strata"] if mini else STRATA
    distractors = MINI["distractors"] if mini else DISTRACTORS
    cells, idx = [], 0
    for stratum in strata:
        for age in ages:
            for band in bands:
                for distr in distractors:
                    cells.append({"topic": idx, "stratum": stratum,
                                  "age": age, "band": band,
                                  "distractor": distr, "scope": "task"})
                    idx += 1
    return cells


def twin_cells(start_index: int) -> list[dict]:
    combos = [(s, a) for a in ("recent", "mid")
              for s in ("note", "dialogue", "episode")]
    return [{"topic": start_index + i, "stratum": s, "age": a, "band": "near",
             "distractor": "none", "scope": "twin"}
            for i, (s, a) in enumerate(combos)]


# --- organic stream ---------------------------------------------------------

def _organic_stream(rng: random.Random, n_organic: int, cells: list[dict],
                    mini: bool) -> list[dict]:
    """Sort-key construction: every organic event gets a float key in [0,1];
    cluster lines get keys packed near their cluster's anchor so a cluster
    reads as a working session. Returns descriptors sorted by key."""
    events = []
    lines_per = MINI_CLUSTER_LINES if mini else CLUSTER_LINES
    fillers = vocab.FILLER_TOPICS
    for cell in cells:
        t = vocab.topic_terms(cell["topic"])
        anchor = 0.10 + 0.78 * rng.random()
        n_lines = lines_per
        for i in range(n_lines):
            role, text = vocab.cluster_line(
                t, i, fillers[rng.randrange(len(fillers))])
            events.append({"key": anchor + i * 1e-5 + rng.random() * 5e-6,
                           "type": "dialogue", "role": role, "text": text,
                           "project": "aster"})
        if cell["scope"] == "twin":
            anchor2 = 0.10 + 0.78 * rng.random()
            for i in range(TWIN_CLUSTER_LINES):
                role, text = vocab.cluster_line(
                    t, i, fillers[rng.randrange(len(fillers))])
                events.append({"key": anchor2 + i * 1e-5,
                               "type": "dialogue", "role": role,
                               "text": "(brontide) " + text,
                               "project": "brontide"})
    n_cluster = len(events)
    n_rest = max(n_organic - n_cluster, 0)
    shares = [("dialogue", 0.55), ("note", 0.12), ("episode", 0.08),
              ("fs", 0.15), ("visit", 0.10)]
    counts = {kind: int(n_rest * share) for kind, share in shares}
    counts["dialogue"] += n_rest - sum(counts.values())
    counts["episode"] //= 2  # each episode unit appends two events
    for i in range(counts["dialogue"]):
        topic = fillers[rng.randrange(len(fillers))]
        proj = "aster" if rng.random() < 0.6 else rng.choice(
            ["brontide", "corvid"])
        if i % 2 == 0:
            role, text = "user", (f"next chunk of {topic} — step {i}: "
                                  f"review and keep moving")
        else:
            role, text = "assistant", (f"step {i} of {topic} done: applied, "
                                       f"tests green, continuing")
        events.append({"key": rng.random(), "type": "dialogue", "role": role,
                       "text": text, "project": proj})
    for i in range(counts["note"]):
        topic = fillers[rng.randrange(len(fillers))]
        events.append({"key": rng.random(), "type": "note",
                       "text": f"note {i}: {topic} — approach accepted "
                               f"after review"})
    for i in range(counts["episode"]):
        topic = fillers[rng.randrange(len(fillers))]
        events.append({"key": rng.random(), "type": "episode",
                       "text": f"episode {i}: reconciled a session of "
                               f"{topic}; no open decisions left behind"})
    for i in range(counts["fs"]):
        word = fillers[rng.randrange(len(fillers))].split()[0]
        proj = rng.choice(vocab.PROJECT_NAMES)
        events.append({"key": rng.random(), "type": "fs",
                       "uri": f"/home/sim/{proj}/docs/{word}-{i}.md",
                       "text": f"working doc {i}: "
                               f"{fillers[rng.randrange(len(fillers))]}"})
    for i in range(counts["visit"]):
        slug = fillers[rng.randrange(len(fillers))].split()[0]
        events.append({"key": rng.random(), "type": "visit",
                       "uri": f"https://docs.simexample.com/{slug}/{i}",
                       "text": f"reference page {i} about {slug}"})
    events.sort(key=lambda e: (e["key"], e.get("text", "")))
    return events


# --- planted placement ------------------------------------------------------

def _target_rank(cell: dict, rng: random.Random, stratum_len: int,
                 recent_ks: list[int], cell_j: int) -> int:
    if cell["age"] == "recent":
        return recent_ks[cell_j % len(recent_ks)]
    frac = 0.30 if cell["age"] == "mid" else 0.85
    spacing = max(2, stratum_len // 120)
    base = max(2, round(stratum_len * frac))
    return base + (cell_j - 4) * spacing + rng.randint(0, spacing - 1)


def _resolve_ranks(items: list[dict]) -> None:
    """Make target ranks distinct (stable, deterministic)."""
    used = set()
    for it in sorted(items, key=lambda x: (x["rank"], x["order"])):
        r = max(1, it["rank"])
        while r in used:
            r += 1
        it["rank"] = r
        used.add(r)


def _take_opts(topic: int, k: int) -> list[str]:
    # globally unique per (topic, role): the behavioral rubric attributes a
    # payload token to its plant only if no other topic can carry it
    return [vocab.unique_option(topic * 5 + j) for j in range(k)]


def _plan_planted(rng: random.Random, cells: list[dict],
                  stream: list[dict]) -> list[dict]:
    """Compute every planted event descriptor with its stratum target rank,
    then map ranks to stream insertion positions. Rank 1 = most recent item
    of the stratum in the final interleaved sequence."""
    strata_organic = {
        s: [i for i, e in enumerate(stream) if e["type"] == t]
        for s, t in (("note", "note"), ("episode", "episode"),
                     ("dialogue", "dialogue"))
    }
    by_stratum: dict[str, list[dict]] = {s: [] for s in strata_organic}
    order = 0

    ks_rot = {}
    for stratum in strata_organic:
        ks = list(RECENT_KS[stratum])
        rot = rng.randrange(len(ks))
        ks_rot[stratum] = ks[rot:] + ks[:rot]

    cell_j_counter: dict[tuple, int] = {}
    for cell in cells:
        t = vocab.topic_terms(cell["topic"])
        stratum = cell["stratum"]
        stratum_len = len(strata_organic[stratum])
        key = (stratum, cell["age"], cell["scope"])
        cell_j = cell_j_counter.get(key, 0)
        cell_j_counter[key] = cell_j + 1
        opt_a, opt_b, opt_c, opt_d, opt_e = _take_opts(cell["topic"], 5)
        reason = vocab.REASONS[cell["topic"] % len(vocab.REASONS)]
        rank = _target_rank(cell, rng, stratum_len, ks_rot[stratum], cell_j)
        group = [{"cell": cell, "role": "plant", "rank": max(2, rank),
                  "order": order, "stratum": stratum, "project": "aster",
                  "text": vocab.plant_text(cell["band"], t, opt_a, opt_b,
                                           reason)}]
        order += 1
        if cell["distractor"] == "decoy":
            for dr in (rank - 1, rank + 2):
                group.append({"cell": cell, "role": "decoy", "rank": dr,
                              "order": order, "stratum": stratum,
                              "project": "aster",
                              "text": vocab.decoy_text(cell["band"], t,
                                                       opt_d, opt_e, reason)})
                order += 1
        if cell["distractor"] == "super":
            group.append({"cell": cell, "role": "v2",
                          "rank": max(1, round(rank * 0.4)), "order": order,
                          "stratum": stratum, "project": "aster",
                          "text": vocab.v2_text(t, opt_a, opt_c)})
            order += 1
        if cell["scope"] == "twin":
            group.append({"cell": cell, "role": "twin",
                          "rank": max(1, rank - 1), "order": order,
                          "stratum": stratum, "project": "brontide",
                          "text": "(brontide) " + vocab.plant_text(
                              cell["band"], t, opt_d, opt_e, reason)})
            order += 1
        by_stratum[stratum].extend(group)

    inserts = []
    for stratum, items in by_stratum.items():
        if not items:
            continue
        _resolve_ranks(items)
        organic = strata_organic[stratum]
        n_org = len(organic)
        ranks_taken = sorted(it["rank"] for it in items)
        for it in items:
            shallower_planted = sum(1 for r in ranks_taken if r < it["rank"])
            o_after = max(0, min(it["rank"] - 1 - shallower_planted, n_org))
            pos = len(stream) if o_after == 0 else organic[n_org - o_after]
            inserts.append({**it, "pos": pos})
    return inserts


# --- append -----------------------------------------------------------------

def _append(conn, ev: dict, sess_counter: dict) -> int:
    from contextd.db import append_event
    kind = ev["type"]
    if kind == "dialogue":
        proj = ev.get("project", "aster")
        n = sess_counter["n"] = sess_counter["n"] + 1
        sid = f"{proj}-s{n // 40}"
        return append_event(conn, "claude_code", "message",
                            uri=f"claude://{sid}-{n}", content=ev["text"],
                            meta={"role": ev.get("role", "assistant"),
                                  "session_id": sid})
    if kind == "note":
        return append_event(conn, "note", "note", content=ev["text"],
                            meta={"actor": "human"})
    if kind == "episode":
        tip = conn.execute(
            "SELECT MAX(id) AS m FROM events").fetchone()["m"] or 1
        anchor = max(1, tip - (tip % 37) - 1)
        egress = append_event(conn, "gate", "egress",
                              content=f"(reconciler disclosure over "
                                      f"[{anchor}])",
                              meta={"type": "recall", "items": [anchor],
                                    "client": "reconciler"})
        return append_event(conn, "note", "note",
                            content=f"{ev['text']} [{anchor}]",
                            meta={"actor": "reconciler",
                                  "derivation": {"source_egress": egress,
                                                 "anchors": [anchor]}})
    if kind == "fs":
        return append_event(conn, "fs", "file_write", uri=ev["uri"],
                            content=ev["text"], meta={"size": len(ev["text"])})
    if kind == "visit":
        return append_event(conn, "chrome", "page_visit", uri=ev["uri"],
                            content=f"{ev['text']} {ev['uri']}",
                            meta={"visited_unix": 0})
    raise ValueError(kind)


def _append_planted(conn, it: dict, sess: dict) -> int:
    kind = {"note": "note", "episode": "episode",
            "dialogue": "dialogue"}[it["stratum"]]
    ev = {"type": kind, "text": it["text"], "role": "assistant",
          "project": it["project"]}
    eid = _append(conn, ev, sess)
    it["event_id"] = eid
    return eid


STRATUM_SQL = {
    "note": ("SELECT COUNT(*) FROM events WHERE kind='note' "
             "AND json_extract(meta,'$.actor')='human' AND id > ?"),
    "episode": ("SELECT COUNT(*) FROM events WHERE kind='note' "
                "AND json_extract(meta,'$.actor')!='human' "
                "AND json_extract(meta,'$.derivation') IS NOT NULL "
                "AND id > ?"),
    "dialogue": ("SELECT COUNT(*) FROM events WHERE source='claude_code' "
                 "AND kind='message' AND id > ?"),
}


def achieved_rank(conn, stratum: str, event_id: int) -> int:
    return 1 + conn.execute(STRATUM_SQL[stratum], (event_id,)).fetchone()[0]


def build_archive(home: Path, tier: str, seed: int, mini: bool = False) -> dict:
    """Build one synthetic archive at ``home``; returns the manifest."""
    home = Path(home)
    n_total = TIERS[tier]
    rng = random.Random(f"selection-stress:{tier}:{seed}:{int(mini)}")
    cells = grid_cells(mini)
    if not mini:
        cells = cells + twin_cells(len(cells))
    extras = {"none": 0, "decoy": 2, "super": 1}
    n_planted = sum(1 + extras[c["distractor"]]
                    + (1 if c["scope"] == "twin" else 0) for c in cells)
    stream = _organic_stream(rng, n_total - n_planted, cells, mini)
    planted = _plan_planted(rng, cells, stream)

    by_pos: dict[int, list[dict]] = {}
    for it in planted:
        by_pos.setdefault(it["pos"], []).append(it)
    for items in by_pos.values():
        items.sort(key=lambda x: (-x["rank"], x["order"]))

    with contextd_home(home):
        from contextd.db import _db_tip, connect
        with simulated_clock(n_total + n_total // 5):
            conn = connect()
            sess = {"n": 0}
            for pos, ev in enumerate(stream):
                for it in by_pos.get(pos, ()):
                    _append_planted(conn, it, sess)
                _append(conn, ev, sess)
            for it in by_pos.get(len(stream), ()):
                _append_planted(conn, it, sess)
            tip = _db_tip(conn)
            topics = _manifest_topics(conn, cells, planted)
            conn.close()
    (home / "config.toml").write_text(HOME_CONFIG)
    return {"tier": tier, "seed": seed, "mini": mini, "n_events": tip["id"],
            "digest": tip["chain_hash"], "home": str(home), "topics": topics}


def _manifest_topics(conn, cells: list[dict], planted: list[dict]) -> list[dict]:
    out = []
    for cell in cells:
        items = [it for it in planted if it["cell"] is cell]
        t = vocab.topic_terms(cell["topic"])
        opt_a, opt_b, opt_c, opt_d, opt_e = _take_opts(cell["topic"], 5)
        entry = {**cell, **t, "hint": vocab.topic_hint(t),
                 "opt_a": opt_a, "opt_b": opt_b, "opt_c": opt_c,
                 "opt_d": opt_d, "opt_e": opt_e, "decoys": []}
        for it in items:
            info = {"event_id": it["event_id"], "target_rank": it["rank"],
                    "achieved_rank": achieved_rank(conn, it["stratum"],
                                                   it["event_id"])}
            if it["role"] == "decoy":
                entry["decoys"].append(info)
            else:
                entry[it["role"]] = info
        out.append(entry)
    return out


def write_manifest(manifest: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
