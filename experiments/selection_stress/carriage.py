"""Deterministic carriage scoring: compile a checkpoint through the real
pipeline (real gate, egress logged in the synthetic archive) and classify
every planted item's fate mechanically. No models anywhere in this module.

Classes per planted item:
  carried          the plant's event id is in the compiled package's items
  omitted-named    absent, but the package names the id in a loud-omission
                   line (structurally possible only for loops today; the
                   scorer still checks, so the zero is measured, not assumed)
  silently-absent  absent and unnamed — the failure the mission maps

Supersession extras (distractor == "super"):
  stale-resurrected   v1 carried while v2 absent
  superseded-honored  v2 carried (v1 may legitimately accompany it)
"""

import re
import time

from experiments.selection_stress.generator import contextd_home


def _named_in_package(package: str, event_id: int) -> bool:
    """A loud omission names the id outside a carried item's own header."""
    return bool(re.search(rf"(?<!\[){event_id}(?!\])",
                          package_omission_lines(package)))


def package_omission_lines(package: str) -> str:
    return "\n".join(line for line in package.splitlines()
                     if "OMITTED" in line.upper())


def compile_for_topic(home: str, hint: str, budget: int) -> dict:
    """One real compile against the archive at ``home``. Returns the package,
    the selected ids, per-stratum fill, latency, and the egress receipt id."""
    with contextd_home(home):
        from contextd import load_config
        from contextd.db import connect
        from contextd.handoff import compile_checkpoint
        conn = connect()
        cfg = load_config()
        t0 = time.perf_counter()
        out = compile_checkpoint(conn, cfg, budget=budget, task_hint=hint,
                                 client="selection-stress")
        latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        conn.close()
    sel = out["selection"]
    fill = {k: sum(it.get("est_tokens", 0) for it in sel[k])
            for k in ("tail", "episodes", "notes", "recall")}
    sections = {k: {it["id"] for it in sel[k] if it["id"] is not None}
                for k in ("tail", "episodes", "notes", "recall", "loops")}
    return {"package": out["package"], "items": set(out["items"]),
            "egress_id": out["egress_id"], "est_tokens": out["est_tokens"],
            "fill": fill, "sections": sections, "latency_ms": latency_ms}


def score_topic(topic: dict, compiled: dict) -> dict:
    """Classify one topic's planted items against one compiled package."""
    items = compiled["items"]
    package = compiled["package"]
    pid = topic["plant"]["event_id"]
    carried = pid in items
    via = [k for k, ids in compiled["sections"].items() if pid in ids]
    named = (not carried) and _named_in_package(package, pid)
    row = {
        "carried": carried,
        "via": via[0] if via else None,
        "omitted_named": named,
        "silently_absent": not carried and not named,
        "payload_in_text": topic["opt_a"] in package,
    }
    if topic["distractor"] == "super" and topic.get("v2"):
        v2_carried = topic["v2"]["event_id"] in items
        row["v2_carried"] = v2_carried
        row["stale_resurrected"] = carried and not v2_carried
        row["superseded_honored"] = v2_carried
    if topic["distractor"] == "decoy":
        row["decoys_carried"] = sum(
            1 for d in topic["decoys"] if d["event_id"] in items)
    if topic["scope"] == "twin" and topic.get("twin"):
        row["twin_carried"] = topic["twin"]["event_id"] in items
    return row


def grid_rows_for_archive(manifest: dict, budgets: list[int],
                          include_no_hint: bool = True) -> list[dict]:
    """All carriage observations for one archive: per (topic-hint, budget)
    compile scored on that topic, plus a no-hint compile per budget scored
    on every task topic (recency-only carriage)."""
    rows = []
    base = {"tier": manifest["tier"], "seed": manifest["seed"]}
    for budget in budgets:
        for tp in manifest["topics"]:
            compiled = compile_for_topic(manifest["home"], tp["hint"], budget)
            rows.append({**base, "budget": budget, "hinted": True,
                         "topic": tp["topic"], "stratum": tp["stratum"],
                         "age": tp["age"], "band": tp["band"],
                         "distractor": tp["distractor"], "scope": tp["scope"],
                         "latency_ms": compiled["latency_ms"],
                         "est_tokens": compiled["est_tokens"],
                         "fill": compiled["fill"],
                         "egress_id": compiled["egress_id"],
                         **score_topic(tp, compiled)})
        if include_no_hint:
            compiled = compile_for_topic(manifest["home"], "", budget)
            for tp in manifest["topics"]:
                rows.append({**base, "budget": budget, "hinted": False,
                             "topic": tp["topic"], "stratum": tp["stratum"],
                             "age": tp["age"], "band": tp["band"],
                             "distractor": tp["distractor"],
                             "scope": tp["scope"],
                             "latency_ms": compiled["latency_ms"],
                             "est_tokens": compiled["est_tokens"],
                             "fill": compiled["fill"],
                             "egress_id": compiled["egress_id"],
                             **score_topic(tp, compiled)})
    return rows
