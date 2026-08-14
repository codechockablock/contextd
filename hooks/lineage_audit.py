#!/usr/bin/env python
"""Standing lineage fidelity audit: sample old model-written notes, walk
their derivation to leaf evidence, and ask a CALIBRATED judge whether the
note is faithful to what the evidence actually says.

Harness-side tooling, deliberately outside the contextd package (same rule
as reconcile.py): this script invokes a model via `claude -p`; the kernel
never does. The judge spec is imported from the calibration experiment so
the sha dispatched here is byte-identical to the sha that was calibrated —
and this hook REFUSES to run at all unless the frozen calibration result
says AUDIT EARNED for exactly that sha. An uncalibrated judge is vibes.

Verdicts are advisory instrument readings, nothing more: each lands as a
content-NULL eval/lineage_audit event (the experiment-record precedent), so
it can never enter FTS, never feed a recall, and never outrank the note it
describes. Nothing here mutates, quarantines, or re-ranks any note; models
gain zero new authority. The kernel's semantic-entailment boundary
(docs/PROVENANCE.md) does not move: this instrument samples and estimates
fidelity; it never certifies it.

Every judged bundle passes the real gate (receipted, budgeted, redacted)
with a linked dispatch outcome; failed audits stay unaudited and are
retried on a later run, never silently skipped."""

import fcntl
import json
import os
import random
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contextd import home, load_config  # noqa: E402
from contextd.db import append_event, connect, now_iso  # noqa: E402
from contextd.gate import GateError, disclose, record_dispatch_outcome  # noqa: E402
from contextd.lineage import eligible_notes, judge_registrations  # noqa: E402
from contextd.provenance import closure  # noqa: E402

from experiments.lineage_calibration.calibrate import (PROMPTS,  # noqa: E402
                                                       dispatch, judge_sha,
                                                       parse_reply)

PROMPT_VERSION = "v1"
CALIBRATION_RESULT = os.environ.get(
    "LINEAGE_CALIBRATION_RESULT",
    str(Path(__file__).resolve().parent.parent / "experiments"
        / "lineage_calibration" / "calibration_result.json"))
MAX_EVIDENCE_CHARS = 2400  # per leaf, before gate redaction
AGE_STRATA = 3


class AuditRefused(RuntimeError):
    pass


def load_calibration(path: str | None = None) -> dict:
    """The frozen held-out result this instrument was earned by. Refuses to
    return anything unless the verdict is AUDIT EARNED for exactly the judge
    spec this hook would dispatch — a drifted prompt is an uncalibrated
    judge, whatever the file says."""
    p = Path(path or CALIBRATION_RESULT)
    if not p.exists():
        raise AuditRefused(
            f"no calibration result at {p} — run the calibration protocol "
            "(experiments/lineage_calibration/calibrate.py) first")
    result = json.loads(p.read_text())
    if result.get("verdict") != "AUDIT EARNED":
        raise AuditRefused(
            f"calibration verdict is {result.get('verdict')!r} — the audit "
            "is not earned and this hook stays disabled")
    current = judge_sha(PROMPT_VERSION)
    if result.get("judge_sha") != current:
        raise AuditRefused(
            f"judge spec drifted: calibrated {str(result.get('judge_sha'))[:12]} "
            f"!= current {current[:12]} — recalibrate before auditing")
    return result


def register_judge(conn, calibration: dict) -> None:
    """Once per archive per sha: a content-NULL registration event carrying
    the calibration confusion matrix, so `ctx lineage report` can rebuild
    every reading next to its instrument's measured error from the ledger
    alone."""
    sha = calibration["judge_sha"]
    if sha in judge_registrations(conn):
        return
    append_event(conn, "eval", "lineage_judge", meta={
        "judge_sha": sha,
        "model": calibration.get("judge_model"),
        "prompt_version": PROMPT_VERSION,
        "corpus_digest": calibration.get("corpus_digest"),
        "prereg_id": calibration.get("prereg_id"),
        "calibration": {
            "verdict": calibration["verdict"],
            "n_heldout": calibration.get("n_heldout"),
            "per_class": calibration.get("per_class"),
        },
    })


def audited_note_ids(conn, sha: str) -> set:
    return {json.loads(r["meta"]).get("note_id") for r in conn.execute(
        "SELECT meta FROM events WHERE kind = 'lineage_audit' AND "
        "json_extract(meta, '$.judge_sha') = ?", (sha,))}


def sample_notes(conn, cfg, sha: str, n: int | None = None) -> list[dict]:
    """Deterministic stratified sample by note age: unaudited candidates
    (under this judge sha) are split into oldest/middle/newest strata and
    drawn round-robin, so old notes — the ones drift theory worries about —
    are always represented. A note audited under this sha is not re-sampled
    while unaudited candidates remain."""
    n = n or cfg.get("lineage", {}).get("audit_sample_per_run", 8)
    eligible = eligible_notes(conn)
    done = audited_note_ids(conn, sha)
    pool = [e for e in eligible if e["id"] not in done] or eligible
    if not pool:
        return []
    pool.sort(key=lambda e: e["ts"])  # oldest first
    k = min(AGE_STRATA, len(pool))
    strata = [pool[i * len(pool) // k:(i + 1) * len(pool) // k]
              for i in range(k)]
    tip = conn.execute("SELECT MAX(id) FROM events").fetchone()[0]
    rng = random.Random(f"{sha}:{tip}")
    for s in strata:
        rng.shuffle(s)
    picked, i = [], 0
    while len(picked) < min(n, len(pool)):
        stratum = strata[i % k]
        if stratum:
            picked.append(stratum.pop())
        i += 1
        if all(not s for s in strata):
            break
    return picked


def leaf_evidence(conn, note_id: int) -> list[dict]:
    """Terminal events of the note's derivation closure — the raw dialogue
    (or other leaves) its claims must answer to."""
    leaves, seen = [], set()

    def walk(node):
        if node.get("terminal") and node.get("exists"):
            if node["event"] not in seen:
                seen.add(node["event"])
                leaves.append(node["event"])
            return
        for child in node.get("children", {}).values():
            walk(child)

    walk(closure(conn, note_id))
    out = []
    for eid in sorted(leaves):
        row = conn.execute("SELECT * FROM events WHERE id = ?",
                           (eid,)).fetchone()
        if row is None or row["content"] is None:
            continue
        meta = json.loads(row["meta"]) if row["meta"] else {}
        role = meta.get("role") or meta.get("actor") or row["source"]
        text = row["content"][:MAX_EVIDENCE_CHARS]
        out.append({"id": eid, "role": role, "text": text})
    return out


def render_audit_payload(note_text: str, evidence: list[dict]) -> str:
    ev = "\n".join(f"[{e['id']}] {e['role']}: {e['text']}" for e in evidence)
    return (f"{PROMPTS[PROMPT_VERSION]}\n\nEVIDENCE:\n{ev}\n\n"
            f"NOTE:\n{note_text}\n")


def _age_days(note_ts: str, now: str | None = None) -> float:
    delta = (datetime.fromisoformat(now or now_iso())
             - datetime.fromisoformat(note_ts))
    return round(delta.total_seconds() / 86400, 2)


def audit_note(conn, cfg, note: dict, sha: str, dispatcher=dispatch) -> dict:
    """One sampled note through the full path: evidence walk, gated
    disclosure, dispatch, parse, content-NULL verdict event. Returns a
    result dict; failures record their linked outcome and append NO audit
    event, leaving the note eligible for retry."""
    row = conn.execute("SELECT content FROM events WHERE id = ?",
                       (note["id"],)).fetchone()
    evidence = leaf_evidence(conn, note["id"])
    if not evidence:
        return {"note_id": note["id"], "skipped": "no_leaf_evidence"}
    payload = render_audit_payload(row["content"] or "", evidence)
    try:
        d = disclose(conn, cfg, payload, {
            "type": "lineage_audit", "note_id": note["id"],
            "items": [e["id"] for e in evidence] + [note["id"]],
            "judge_sha": sha, "client": "lineage-audit"})
    except GateError as e:
        return {"note_id": note["id"], "skipped": f"gate refused: {e}"}
    out = dispatcher(d["content"])
    if out["status"] != "succeeded":
        record_dispatch_outcome(
            conn, d["egress_id"], out["status"], exit=out.get("exit"))
        return {"note_id": note["id"], "failed": out["status"],
                "egress_id": d["egress_id"], "retryable": True}
    record_dispatch_outcome(conn, d["egress_id"], "succeeded", exit=0)
    parsed = parse_reply(out["text"])
    if parsed is None:
        return {"note_id": note["id"], "failed": "unparseable",
                "egress_id": d["egress_id"], "retryable": True}
    eid = append_event(conn, "eval", "lineage_audit", meta={
        "note_id": note["id"], "verdict": parsed["verdict"],
        "spans": parsed["spans"], "judge_sha": sha,
        "egress_id": d["egress_id"],
        "note_age_days": _age_days(note["ts"]),
        "evidence_ids": [e["id"] for e in evidence],
    })
    return {"note_id": note["id"], "verdict": parsed["verdict"],
            "audit_event": eid, "egress_id": d["egress_id"]}


def run_audit(conn, cfg, calibration: dict, dispatcher=dispatch,
              n: int | None = None) -> list[dict]:
    register_judge(conn, calibration)
    sha = calibration["judge_sha"]
    results = []
    for note in sample_notes(conn, cfg, sha, n):
        results.append(audit_note(conn, cfg, note, sha, dispatcher))
    return results


def main():
    try:
        calibration = load_calibration()
    except AuditRefused as e:
        sys.exit(f"lineage audit refused: {e}")
    archive = home()
    archive.mkdir(parents=True, exist_ok=True)
    lock = open(archive / "lineage-audit.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return  # another run is in flight
    conn, cfg = connect(), load_config()
    for r in run_audit(conn, cfg, calibration):
        print(json.dumps(r), flush=True)


if __name__ == "__main__":
    main()
