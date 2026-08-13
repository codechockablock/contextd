"""Lineage gauge: deterministic derivation-graph topology over the archive.

The reconciler writes notes that cite raw dialogue only — today. That fact is
load-bearing (depth > 1 is where compounding-summary drift becomes
structurally possible: a note citing a note inherits its paraphrase errors
with no leaf evidence in sight), so it is measured here, not assumed. This
module walks every derivation-bearing event and reports chain depth, anchor
resolution health, notes-per-epoch, and the age of cited evidence. Pure
reads, model-free, O(events) for the scan plus O(closure) per derived event.

Depth convention (docs/PROVENANCE.md's chain, counted): a leaf archive event
(dialogue, file, page) is depth 0; a note citing only leaves is depth 1; a
note citing a depth-1 note is depth 2, and so on. The cited set of a derived
event is the union of its kernel-stamped derivation anchors and the bracketed
anchors parsed from its content — either channel claiming lineage counts, so
neither can hide a note-citing-note edge from the gauge.

This gauge measures topology and mechanical anchor health. It never judges
whether a note's wording is supported by its evidence — that semantic
boundary stays where docs/PROVENANCE.md pinned it; the sampled fidelity
audit (hooks/lineage_audit.py) *estimates* it with a calibrated judge and
never certifies it.
"""

import json
from datetime import datetime

from .provenance import derivation_of, parse_claims

# Verdicts a calibrated judge may report for one audited note. Advisory
# instrument readings only: they are logged, never acted on by the kernel.
AUDIT_VERDICTS = ("faithful", "dropped-caveat", "emphasis-inversion",
                  "unsupported-claim", "quantitative-shift")

# note age at audit time, bucketed for the report's time series
AGE_BUCKETS = ((7, "<7d"), (30, "7-30d"), (90, "30-90d"), (None, ">90d"))


def _cited_ids(record: dict, content: str | None) -> list[int]:
    """Union of record-stamped anchors and content-parsed anchors."""
    ids = {a for a in record.get("anchors", [])
           if isinstance(a, int) and not isinstance(a, bool)}
    for claim in parse_claims(content or ""):
        ids.update(claim["anchors"])
    return sorted(ids)


def _ts_days(later: str, earlier: str) -> float:
    delta = datetime.fromisoformat(later) - datetime.fromisoformat(earlier)
    return delta.total_seconds() / 86400


def lineage_stats(conn, cfg) -> dict:
    """One deterministic pass over the archive's derivation graph.

    Scan every event carrying meta, keep the derivation-bearing ones, then
    resolve exactly the rows the chains touch (cited events, source egresses)
    instead of loading the whole archive's content.
    """
    limit = cfg.get("lineage", {}).get("max_note_depth", 1)
    derived = {}  # id -> {kind, ts, record}
    epoch_count = 0
    for r in conn.execute(
            "SELECT id, ts, kind, meta FROM events WHERE meta IS NOT NULL"):
        meta = json.loads(r["meta"])
        if r["kind"] == "epoch":
            epoch_count += 1
        record = derivation_of(r["kind"], meta)
        if record is not None:
            derived[r["id"]] = {"kind": r["kind"], "ts": r["ts"],
                                "record": record}

    # fetch content only for derived events; parse their cited sets
    for eid, d in derived.items():
        row = conn.execute("SELECT content FROM events WHERE id = ?",
                           (eid,)).fetchone()
        d["cited"] = _cited_ids(d["record"], row["content"])

    # resolve every row the chains touch: cited events and source egresses
    touched = {c for d in derived.values() for c in d["cited"]}
    sources = {d["record"].get("source_egress") for d in derived.values()
               if isinstance(d["record"].get("source_egress"), int)}
    resolved = {}   # id -> {ts, kind}
    egress_items = {}  # egress id -> set(items) or None if malformed
    for eid in touched | sources:
        row = conn.execute("SELECT id, ts, kind, meta FROM events WHERE id = ?",
                           (eid,)).fetchone()
        if row is None:
            continue
        resolved[eid] = {"ts": row["ts"], "kind": row["kind"]}
        if eid in sources and row["kind"] == "egress":
            meta = json.loads(row["meta"]) if row["meta"] else {}
            items = meta.get("items")
            egress_items[eid] = ({i for i in items if isinstance(i, int)}
                                 if isinstance(items, list) else None)
            if meta.get("epoch_id") is not None:
                resolved[eid]["epoch_id"] = meta["epoch_id"]

    def depth(eid, stack=frozenset()):
        d = derived.get(eid)
        if d is None:
            return 0
        if "depth" in d:
            return d["depth"]
        if eid in stack:
            return 0  # structurally impossible without forgery; never recurse
        child = [depth(c, stack | {eid}) for c in d["cited"] if c in resolved]
        d["depth"] = 1 + max(child, default=0)
        return d["depth"]

    per_event, ages = [], []
    anchors = {"total": 0, "resolved": 0, "in_disclosure": 0}
    orphaned = []
    notes_by_epoch = {}
    for eid in sorted(derived):
        d = derived[eid]
        src = d["record"].get("source_egress")
        src_ok = isinstance(src, int) and egress_items.get(src) is not None
        if not src_ok:
            orphaned.append(eid)
        n_res = sum(1 for c in d["cited"] if c in resolved)
        n_disc = (sum(1 for c in d["cited"] if c in (egress_items.get(src) or ()))
                  if src_ok else 0)
        anchors["total"] += len(d["cited"])
        anchors["resolved"] += n_res
        anchors["in_disclosure"] += n_disc
        cited_notes = [c for c in d["cited"]
                       if resolved.get(c, {}).get("kind") == "note"]
        for c in d["cited"]:
            if c in resolved:
                ages.append(_ts_days(d["ts"], resolved[c]["ts"]))
        if d["kind"] == "note" and src_ok:
            ep = resolved.get(src, {}).get("epoch_id")
            if ep is not None:
                notes_by_epoch[ep] = notes_by_epoch.get(ep, 0) + 1
        per_event.append({
            "id": eid, "kind": d["kind"], "ts": d["ts"],
            "depth": depth(eid), "source_egress": src if src_ok else None,
            "anchors_total": len(d["cited"]), "anchors_resolved": n_res,
            "anchors_in_disclosure": n_disc, "cites_notes": cited_notes,
        })

    depth_counts = {}
    for e in per_event:
        depth_counts[e["depth"]] = depth_counts.get(e["depth"], 0) + 1
    note_depths = [e["depth"] for e in per_event if e["kind"] == "note"]
    alert_notes = [e for e in per_event
                   if e["kind"] == "note" and e["depth"] > limit]
    ages.sort()
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    return {
        "total_events": total,
        "derived_events": len(per_event),
        "derived_notes": sum(1 for e in per_event if e["kind"] == "note"),
        "depth_counts": depth_counts,
        "max_depth": max((e["depth"] for e in per_event), default=0),
        "max_note_depth_observed": max(note_depths, default=0),
        "max_note_depth_limit": limit,
        "alert_notes": alert_notes,
        "anchors": {
            **anchors,
            "unresolved": anchors["total"] - anchors["resolved"],
            "outside_disclosure": anchors["resolved"] - anchors["in_disclosure"],
            "resolution_rate": (round(anchors["resolved"] / anchors["total"], 4)
                                if anchors["total"] else None),
        },
        "orphaned_derivations": orphaned,
        "epochs": {
            "total": epoch_count,
            "with_notes": len(notes_by_epoch),
            "notes_per_epoch_max": max(notes_by_epoch.values(), default=0),
            "notes_per_epoch_mean": (
                round(sum(notes_by_epoch.values()) / len(notes_by_epoch), 2)
                if notes_by_epoch else None),
        },
        "evidence_age_days": {
            "n": len(ages),
            "min": round(ages[0], 2) if ages else None,
            "median": round(ages[len(ages) // 2], 2) if ages else None,
            "max": round(ages[-1], 2) if ages else None,
        },
        "per_event": per_event,
    }


def status_line(stats: dict) -> str:
    """The one-line summary `ctx status` prints, liveness-style."""
    a = stats["anchors"]
    anchor_bit = ("no anchored derivations yet" if not a["total"] else
                  f"anchors {a['resolved']}/{a['total']} resolved, "
                  f"{a['in_disclosure']} in disclosure")
    return (f"max note depth {stats['max_note_depth_observed']} "
            f"(limit {stats['max_note_depth_limit']}); {anchor_bit}"
            + (f"; {len(stats['orphaned_derivations'])} orphaned derivation(s)"
               if stats["orphaned_derivations"] else ""))


def alert_line(stats: dict) -> str:
    worst = max(stats["alert_notes"], key=lambda e: e["depth"])
    cites = ",".join(f"#{c}" for c in worst["cites_notes"]) or "a derived event"
    return (f"note #{worst['id']} at depth {worst['depth']} cites {cites} — "
            f"a note is citing notes (limit lineage.max_note_depth="
            f"{stats['max_note_depth_limit']}); compounding-summary drift is "
            "now structurally possible")


def format_stats(stats: dict, full: bool = False) -> str:
    out = [f"events: {stats['total_events']}  derived: "
           f"{stats['derived_events']} ({stats['derived_notes']} notes)"]
    if stats["depth_counts"]:
        dist = "  ".join(f"depth {k}: {v}"
                         for k, v in sorted(stats["depth_counts"].items()))
        out.append(f"chain depth: {dist}  (max {stats['max_depth']})")
    a = stats["anchors"]
    if a["total"]:
        out.append(f"anchors: {a['resolved']}/{a['total']} resolved "
                   f"({a['resolution_rate']:.0%}), {a['in_disclosure']} in "
                   f"disclosure, {a['unresolved']} unresolved, "
                   f"{a['outside_disclosure']} outside disclosure")
    else:
        out.append("anchors: none recorded")
    if stats["orphaned_derivations"]:
        out.append("orphaned derivations (source egress missing/malformed): "
                   + ", ".join(f"#{i}" for i in stats["orphaned_derivations"]))
    ep = stats["epochs"]
    if ep["with_notes"]:
        out.append(f"epochs: {ep['total']} total, {ep['with_notes']} with "
                   f"derived notes (mean {ep['notes_per_epoch_mean']}/epoch, "
                   f"max {ep['notes_per_epoch_max']})")
    else:
        out.append(f"epochs: {ep['total']} total, none with derived notes")
    ages = stats["evidence_age_days"]
    if ages["n"]:
        out.append(f"cited evidence age: median {ages['median']}d "
                   f"(min {ages['min']}d, max {ages['max']}d, "
                   f"n={ages['n']} citations)")
    if full and stats["per_event"]:
        out.append("")
        out.append(f"{'id':>8}  {'kind':<8} {'depth':>5}  {'anchors':<12} "
                   f"{'egress':>8}  cites notes")
        for e in stats["per_event"]:
            anc = (f"{e['anchors_resolved']}/{e['anchors_total']} "
                   f"({e['anchors_in_disclosure']} disc)")
            notes = ",".join(f"#{c}" for c in e["cites_notes"]) or "-"
            src = f"#{e['source_egress']}" if e["source_egress"] else "ORPHAN"
            out.append(f"{e['id']:>8}  {e['kind']:<8} {e['depth']:>5}  "
                       f"{anc:<12} {src:>8}  {notes}")
    for e in stats["alert_notes"]:
        out.append("")
        out.append(f"DEPTH ALERT: note #{e['id']} at depth {e['depth']} "
                   f"exceeds lineage.max_note_depth="
                   f"{stats['max_note_depth_limit']} — a model-written note "
                   "cites model-written notes; its claims can compound "
                   "paraphrase drift without touching leaf evidence")
    return "\n".join(out)


# --- the sampled fidelity audit's ledger records ------------------------------
# The hook (hooks/lineage_audit.py) appends these; the kernel only reads them.
# Audit events are content-NULL on purpose (the experiment-record precedent):
# they never enter FTS, so a verdict can never feed a later recall.


def eligible_notes(conn) -> list[dict]:
    """Model-written, derivation-bearing notes — the audit's population."""
    out = []
    for r in conn.execute(
            "SELECT id, ts, meta FROM events WHERE kind = 'note' "
            "AND meta IS NOT NULL ORDER BY id"):
        meta = json.loads(r["meta"])
        if meta.get("actor") == "mcp" and isinstance(meta.get("derivation"), dict):
            out.append({"id": r["id"], "ts": r["ts"],
                        "derivation": meta["derivation"]})
    return out


def audit_events(conn) -> list[dict]:
    return [{"event_id": r["id"], "ts": r["ts"], **json.loads(r["meta"])}
            for r in conn.execute(
                "SELECT id, ts, meta FROM events WHERE kind = 'lineage_audit' "
                "ORDER BY id")]


def judge_registrations(conn) -> dict:
    """judge_sha -> registration meta (calibration matrix rides along)."""
    out = {}
    for r in conn.execute(
            "SELECT meta FROM events WHERE kind = 'lineage_judge' ORDER BY id"):
        meta = json.loads(r["meta"])
        out[meta["judge_sha"]] = meta
    return out


def _bucket(age_days: float) -> str:
    for limit, label in AGE_BUCKETS:
        if limit is None or age_days < limit:
            return label
    return AGE_BUCKETS[-1][1]


def audit_report(conn) -> dict:
    """Verdict time-series from the ledger, always shown next to the judge's
    measured calibration error — a reading without its instrument's confusion
    matrix would invite over-trust."""
    audits = audit_events(conn)
    judges = judge_registrations(conn)
    eligible = eligible_notes(conn)
    audited_notes = {a["note_id"] for a in audits}
    by_sha, by_bucket = {}, {}
    for a in audits:
        sha = a.get("judge_sha", "?")
        by_sha.setdefault(sha, {}).setdefault(a["verdict"], 0)
        by_sha[sha][a["verdict"]] += 1
        b = _bucket(a.get("note_age_days", 0.0))
        by_bucket.setdefault(b, {}).setdefault(a["verdict"], 0)
        by_bucket[b][a["verdict"]] += 1
    return {
        "audits": len(audits),
        "eligible_notes": len(eligible),
        "audited_notes": len(audited_notes),
        "coverage": (round(len(audited_notes) / len(eligible), 4)
                     if eligible else None),
        "by_judge_sha": by_sha,
        "by_age_bucket": by_bucket,
        "judges": judges,
        "events": audits,
    }


def format_audit_report(report: dict) -> str:
    if not report["audits"]:
        return ("no lineage audits recorded (hooks/lineage_audit.py appends "
                "them; the schedule ships disabled by default)")
    cov = (f"{report['coverage']:.0%}" if report["coverage"] is not None
           else "n/a")
    out = [f"lineage audits: {report['audits']} verdicts over "
           f"{report['audited_notes']}/{report['eligible_notes']} eligible "
           f"notes (coverage {cov})", ""]

    def dist(counts):
        n = sum(counts.values())
        return "  ".join(f"{v}: {counts[v]} ({counts[v] / n:.0%})"
                         for v in AUDIT_VERDICTS if v in counts) or "(none)"

    out.append("by note age at audit time:")
    for _, label in AGE_BUCKETS:
        if label in report["by_age_bucket"]:
            out.append(f"  {label:<7} {dist(report['by_age_bucket'][label])}")
    out.append("")
    for sha, counts in report["by_judge_sha"].items():
        out.append(f"judge {sha[:12]}: {dist(counts)}")
        reg = report["judges"].get(sha)
        if reg and reg.get("calibration"):
            cal = reg["calibration"]
            out.append(f"  calibration ({cal.get('verdict', '?')}, held-out "
                       f"n={cal.get('n_heldout', '?')}):")
            for cls, row in cal.get("per_class", {}).items():
                ci = row.get("ci", [None, None])
                out.append(
                    f"    {cls:<20} detect {row['detected']}/{row['n']} "
                    f"= {row['rate']:.2f}  "
                    f"[{ci[0]:.2f}, {ci[1]:.2f}]"
                    + (f"  bar {row['bar']}" if row.get("bar") is not None
                       else "  (no bar: honest ceiling)"))
        else:
            out.append("  calibration: NOT FOUND in this archive — readings "
                       "from this judge cannot be interpreted against a "
                       "measured error rate")
    out.append("")
    out.append("verdicts are advisory instrument readings. They never mutate "
               "archive state, never quarantine notes, and are themselves "
               "estimates filtered through the calibration error above.")
    return "\n".join(out)
