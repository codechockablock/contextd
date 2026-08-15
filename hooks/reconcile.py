#!/usr/bin/env python
"""Epoch reconciler: the janitor that distills quiet Claude Code episodes into
archive notes. Harness-side tooling, deliberately outside the contextd package:
this script invokes a model (via `claude -p` on your existing subscription);
the kernel never does. Models call the kernel; the kernel never calls models.

The reconciler reads dialogue the daemon already ingested (redacted at ingest),
skips epochs whose dialogue is already cited by live anchored notes, and asks a
cheap model to write 3-10 standalone notes for the rest. Every outcome is
recorded back into the archive as a claude_code/reconcile event referencing its
epoch."""

import fcntl
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contextd import home, load_config  # noqa: E402
from contextd.db import append_event, connect  # noqa: E402
from contextd.capability import issue as issue_capability  # noqa: E402
from contextd.capability import token as capability_token  # noqa: E402
from contextd.gate import disclose, record_dispatch_outcome  # noqa: E402
from contextd.redact import sanitize_content  # noqa: E402

CLAUDE_BIN = os.environ.get("RECONCILE_CLAUDE_BIN", "claude")
MODEL = os.environ.get("RECONCILE_MODEL", "haiku")
MIN_MESSAGES = 6        # tiny epochs aren't worth a model call
LIVE_NOTE_SKIP = 3      # epochs already documented by citing notes are skipped
MAX_EPOCHS_PER_RUN = 5
MAX_DIALOGUE_CHARS = 300_000
MAX_DIALOGUE_MESSAGES = 1024   # the registry's items bound (schemas._COMMON)

PROMPT = """You are the archivist for a personal context daemon. Below is the \
dialogue from one work episode (roles: user, assistant, delegation, subagent); \
each message is prefixed with its bracketed archive event id, e.g. [41234]. \
Using the contextd note tool, write 3-10 standalone notes capturing only what \
is durable: decisions made, facts established, preferences the user expressed, \
artifacts built, and open questions. Each note must make sense on its own, \
months from now, to a reader without this transcript. Immediately after each \
claim in a note, cite the bracketed event id(s) of the message(s) that support \
it, exactly as given — cite only ids that appear in this dialogue; never \
invent one. Skip pleasantries, process chatter, and anything transient. Never \
include credentials. If nothing durable happened, write no notes. When \
finished, reply with only: DONE"""


def unreconciled_epochs(conn):
    done = set()
    for r in conn.execute(
            "SELECT meta FROM events WHERE source='claude_code' AND kind='reconcile'"):
        done.add(json.loads(r["meta"]).get("epoch_id"))
    epochs = conn.execute(
        "SELECT id, meta FROM events WHERE source='claude_code' AND kind='epoch' "
        "ORDER BY id").fetchall()
    return [(r["id"], json.loads(r["meta"])) for r in epochs if r["id"] not in done]


def epoch_messages(conn, meta):
    return conn.execute(
        "SELECT id, content, json_extract(meta,'$.role') AS role FROM events "
        "WHERE source='claude_code' AND kind='message' "
        "AND json_extract(meta,'$.session_id') = ? AND id > ? AND id <= ? "
        "ORDER BY id",
        (meta["session_id"], meta.get("start_event_id") or 0,
         meta.get("end_event_id") or 0),
    ).fetchall()


def cited_live_notes(conn, start_id: int, end_id: int) -> int:
    """Notes that demonstrably document THIS episode.

    A note counts only when its kernel-verified anchors cite into the epoch's
    event window. Sharing the id window is not enough: with parallel sessions
    writing into one archive, an unrelated note routinely lands between
    another episode's events, and counting it marked epochs self-documented
    that nobody had documented — silently never distilled. Counting by
    citation also lets a crashed run's own notes stand: the retry sees them
    and skips instead of double-distilling the same dialogue."""
    count = 0
    for r in conn.execute(
            "SELECT meta FROM events WHERE kind='note' AND id > ?",
            (start_id,)):
        meta = json.loads(r["meta"] or "{}")
        anchors = (meta.get("derivation") or {}).get("anchors") or []
        if any(start_id < a <= end_id for a in anchors):
            count += 1
    return count


def reconcile(conn, epoch_id, meta) -> dict:
    msgs = epoch_messages(conn, meta)
    if len(msgs) < MIN_MESSAGES:
        return {"skipped": "too_small", "messages": len(msgs)}
    start_id = meta.get("start_event_id") or 0
    end_id = meta.get("end_event_id") or 0
    if cited_live_notes(conn, start_id, end_id) >= LIVE_NOTE_SKIP:
        return {"skipped": "self_documented", "messages": len(msgs)}
    # Whole messages only, oldest first, until the size or count cap; the
    # disclosure's item list is exactly what the payload carries, so an anchor
    # can never resolve to dialogue the model was never shown.
    included, size = [], 0
    for m in msgs:
        entry = f"[{m['id']}] {m['role']}: {m['content']}"
        if included and (size + len(entry) + 2 > MAX_DIALOGUE_CHARS
                         or len(included) >= MAX_DIALOGUE_MESSAGES):
            break
        included.append((m["id"], entry))
        size += len(entry) + 2
    omitted = len(msgs) - len(included)
    dialogue = "\n\n".join(entry for _, entry in included)
    if omitted:
        dialogue += (f"\n\n[reconciler: {omitted} later message(s) omitted "
                     "for size — their ids are not in this disclosure and "
                     "cannot be cited]")
    payload = f"{PROMPT}\n\n{dialogue}"
    disclosure = disclose(conn, load_config(), payload, {
        "type": "reconcile_dialogue", "epoch_id": epoch_id,
        "model": MODEL, "items": [i for i, _ in included],
        "omitted_messages": omitted,
        "client": "reconciler",
    })
    # The model subprocess (and the ctx serve it spawns) inherits this env:
    # every note written during this dispatch is kernel-bound to the exact
    # disclosed dialogue, and its anchors are verified against that egress.
    env = os.environ.copy()
    # a dispatch capability, not an event id: opaque, bound to this
    # disclosure's exact bytes and this session, single-use, expiring
    # (contextd/capability.py). The old integer binding is retired.
    _cap = issue_capability(conn, disclosure["egress_id"], os.getuid(),
                            "reconcile")
    env["CONTEXTD_DISPATCH_CAPABILITY"] = capability_token(_cap)
    env["CONTEXTD_DISPATCH_SESSION"] = "reconcile"
    env.pop("CONTEXTD_DERIVATION_SOURCE", None)
    env["CONTEXTD_CLIENT"] = "reconciler"
    before = conn.execute("SELECT COUNT(*) FROM events WHERE kind='note'").fetchone()[0]
    try:
        r = subprocess.run(
            [CLAUDE_BIN, "-p", "--model", MODEL,
             "--allowedTools", "mcp__contextd__note"],
            input=disclosure["content"], env=env,
            capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        record_dispatch_outcome(
            conn, disclosure["egress_id"], "timeout", timeout_seconds=600,
        )
        raise
    except BaseException:
        # the exception's own text is deliberately not persisted: a failing
        # subprocess must not be a channel into the archive
        record_dispatch_outcome(conn, disclosure["egress_id"], "failed")
        raise
    if r.returncode != 0:
        record_dispatch_outcome(
            conn, disclosure["egress_id"], "failed", exit=r.returncode,
        )
        raise RuntimeError(f"reconciler model failed with exit {r.returncode}")
    record_dispatch_outcome(
        conn, disclosure["egress_id"], "succeeded", exit=r.returncode,
    )
    after = conn.execute("SELECT COUNT(*) FROM events WHERE kind='note'").fetchone()[0]
    return {"messages": len(msgs), "notes": after - before, "exit": r.returncode,
            "egress_id": disclosure["egress_id"]}


def main():
    archive = home()
    archive.mkdir(parents=True, exist_ok=True)
    lock = open(archive / "reconcile.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return  # another run is in flight
    conn = connect()
    cfg = load_config()
    for epoch_id, meta in unreconciled_epochs(conn)[:MAX_EPOCHS_PER_RUN]:
        try:
            result = reconcile(conn, epoch_id, meta)
        except Exception as e:  # no marker written: the epoch retries next run
            error = sanitize_content(cfg, str(e), max_len=500)
            print(json.dumps({"epoch": epoch_id, "error": error}), flush=True)
            continue
        append_event(conn, "claude_code", "reconcile",
                     meta={"epoch_id": epoch_id, "model": MODEL, **result})
        print(json.dumps({"epoch": epoch_id, **result}), flush=True)


if __name__ == "__main__":
    main()
