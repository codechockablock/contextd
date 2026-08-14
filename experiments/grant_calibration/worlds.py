"""Synthetic worlds: one isolated CONTEXTD_HOME per fixture, built through
public append paths only. The dialogue lands as message events; the planted
candidate lands through ``add_candidate`` (model authority, state candidate)
exactly as a background scanner would have left it. Ground truth (the
fixture's cls label) is returned to the harness, never stored in the world.

Every bundle a judge sees is disclosed through the world's own real gate
(``contextd.gate.disclose``) and lands as an egress event there — the world's
log records what the world disclosed."""

import hashlib
import json
from pathlib import Path

from experiments.grant_calibration.fixtures import PROJECTS
from experiments.handoff.common import contextd_home


def _connect_here():
    from contextd.db import connect
    return connect()


def _msg(conn, role, text, session):
    from contextd.db import append_event
    n = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    return append_event(conn, "claude_code", "message",
                        uri=f"claude://{session}-{n}", content=text,
                        meta={"role": role, "session_id": session})


def build_world(home: Path, fixture: dict) -> dict:
    """Build the fixture's archive: dialogue messages then the planted
    candidate. Returns ids and the candidate loop id; never the label."""
    home = Path(home)
    with contextd_home(home):
        from contextd.loops import add_candidate, make_scope
        conn = _connect_here()
        ids = [_msg(conn, m["role"], m["text"], fixture["fid"])
               for m in fixture["messages"]]
        repo = PROJECTS[fixture["project"]]["repo"]
        r = add_candidate(conn, fixture["candidate"], make_scope(repo),
                          client="gc-scan", source_events=[ids[-1]])
        if r["result"] != "created":
            raise RuntimeError(f"{fixture['fid']}: candidate not created "
                               f"({r['result']})")
        loop_id = r["loop"]["id"]
        conn.close()
    return {"home": str(home), "message_ids": ids, "loop_id": loop_id,
            "repo": repo}


def world_digest(home: Path) -> str:
    """Deterministic content digest of a world: ordered (source, kind,
    content, role/op/authority meta), timestamps and chain hashes excluded —
    two builds of the same fixture must agree byte-for-byte here."""
    with contextd_home(Path(home)):
        conn = _connect_here()
        rows = conn.execute(
            "SELECT source, kind, content, meta FROM events "
            "WHERE kind != 'egress' ORDER BY id").fetchall()
        conn.close()
    stream = []
    for r in rows:
        meta = json.loads(r["meta"] or "{}")
        stream.append((r["source"], r["kind"], r["content"] or "",
                       meta.get("role", ""), meta.get("op", ""),
                       meta.get("authority", "")))
    return hashlib.sha256(
        json.dumps(stream, sort_keys=True).encode()).hexdigest()


def render_dialogue(world: dict) -> str:
    """The dialogue exactly as the world's archive holds it, bracketed ids
    included, newest-last."""
    with contextd_home(Path(world["home"])):
        conn = _connect_here()
        rows = conn.execute(
            "SELECT id, content, meta FROM events "
            "WHERE kind='message' ORDER BY id").fetchall()
        conn.close()
    lines = []
    for r in rows:
        role = json.loads(r["meta"] or "{}").get("role", "?")
        lines.append(f"[{r['id']}] {role}: {r['content']}")
    return "\n".join(lines)


def render_candidate(world: dict) -> str:
    with contextd_home(Path(world["home"])):
        conn = _connect_here()
        row = conn.execute(
            "SELECT id, content FROM events WHERE id=?",
            (world["loop_id"],)).fetchone()
        conn.close()
    return f"[loop#{row['id']}] (state: candidate) {row['content']}"


def disclose_bundle(world: dict, arm: str, fid: str) -> dict:
    """Gate the judge's bundle through the world's own archive. The
    full-context arm disclosed the dialogue plus the candidate; the
    no-context arm disclosed the candidate only. Returns the redacted
    content (the ONLY bytes a dispatch may carry) and the egress id."""
    if arm == "full":
        body = ("=== DIALOGUE ===\n" + render_dialogue(world)
                + "\n\n=== CANDIDATE ===\n" + render_candidate(world))
    elif arm == "nocontext":
        body = ("=== DIALOGUE ===\n(dialogue unavailable)"
                + "\n\n=== CANDIDATE ===\n" + render_candidate(world))
    else:
        raise ValueError(f"unknown arm {arm!r}")
    with contextd_home(Path(world["home"])):
        from contextd import load_config
        from contextd.gate import disclose
        conn = _connect_here()
        receipt = disclose(conn, load_config(), body,
                           {"type": "grant_calibration_judge", "arm": arm,
                            "fid": fid, "client": "grant-calibration-bench"})
        conn.close()
    return {"content": receipt["content"], "egress_id": receipt["egress_id"],
            "est_tokens": receipt["est_tokens"]}


def world_egress_count(home: Path) -> int:
    with contextd_home(Path(home)):
        conn = _connect_here()
        n = conn.execute(
            "SELECT COUNT(*) FROM events WHERE kind='egress'").fetchone()[0]
        conn.close()
    return n
