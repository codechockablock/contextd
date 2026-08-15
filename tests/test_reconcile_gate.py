import json
from types import SimpleNamespace

import pytest

import hooks.reconcile as reconciler
from contextd.db import append_event, connect


def _epoch(conn):
    message_ids = []
    session_id = "reconcile-test-session"
    for index in range(reconciler.MIN_MESSAGES):
        message_ids.append(
            append_event(
                conn,
                "claude_code",
                "message",
                content=(
                    "decision text sk-abcdefghijklmnop1234"
                    if index == 0
                    else f"dialogue {index}"
                ),
                meta={
                    "role": "user" if index % 2 == 0 else "assistant",
                    "session_id": session_id,
                },
            )
        )
    meta = {
        "session_id": session_id,
        "start_event_id": message_ids[0] - 1,
        "end_event_id": message_ids[-1],
    }
    return append_event(conn, "claude_code", "epoch", meta=meta), meta


def test_reconciler_dispatches_only_receipted_redacted_payload(monkeypatch):
    conn = connect()
    epoch_id, meta = _epoch(conn)
    observed = {}

    def fake_run(*args, **kwargs):
        observed["input"] = kwargs["input"]
        return SimpleNamespace(returncode=0, stdout="DONE", stderr="")

    monkeypatch.setattr(reconciler.subprocess, "run", fake_run)
    result = reconciler.reconcile(conn, epoch_id, meta)

    assert "abcdefghijklmnop1234" not in observed["input"]
    assert "[REDACTED:api_key]" in observed["input"]
    receipt = conn.execute(
        "SELECT content, meta FROM events WHERE id = ?", (result["egress_id"],)
    ).fetchone()
    assert receipt["content"] == observed["input"]
    assert json.loads(receipt["meta"])["epoch_id"] == epoch_id
    outcome = conn.execute(
        "SELECT meta FROM events WHERE kind='egress_outcome'"
    ).fetchone()
    assert json.loads(outcome["meta"])["status"] == "succeeded"


def test_reconciler_nonzero_exit_is_receipted_and_epoch_remains_retryable(monkeypatch):
    conn = connect()
    epoch_id, meta = _epoch(conn)
    monkeypatch.setattr(
        reconciler.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=17, stdout="", stderr="failed"
        ),
    )

    with pytest.raises(RuntimeError, match="exit 17"):
        reconciler.reconcile(conn, epoch_id, meta)

    assert (
        conn.execute("SELECT COUNT(*) FROM events WHERE kind='reconcile'").fetchone()[0]
        == 0
    )
    assert epoch_id in {eid for eid, _ in reconciler.unreconciled_epochs(conn)}
    outcome = json.loads(
        conn.execute("SELECT meta FROM events WHERE kind='egress_outcome'").fetchone()[
            "meta"
        ]
    )
    assert outcome["status"] == "failed"
    assert outcome["exit"] == 17


def test_reconciler_timeout_is_linked_and_retryable(monkeypatch):
    conn = connect()
    epoch_id, meta = _epoch(conn)

    def timeout(*args, **kwargs):
        raise reconciler.subprocess.TimeoutExpired(args[0], 600)

    monkeypatch.setattr(reconciler.subprocess, "run", timeout)
    with pytest.raises(reconciler.subprocess.TimeoutExpired):
        reconciler.reconcile(conn, epoch_id, meta)

    outcome = json.loads(
        conn.execute("SELECT meta FROM events WHERE kind='egress_outcome'").fetchone()[
            "meta"
        ]
    )
    assert outcome["status"] == "timeout"
    assert epoch_id in {eid for eid, _ in reconciler.unreconciled_epochs(conn)}


def test_reconcile_marker_passes_the_closed_registry_and_marks_the_epoch():
    """Regression: the per-epoch marker main() appends must validate.

    The 2026-08 hardening closed the metadata registry without declaring
    ("claude_code", "reconcile"), so every launchd run dispatched the model
    successfully and then crashed appending the marker — the epoch was never
    marked reconciled, and the next run re-dispatched it. This pins the exact
    meta shape main() writes.
    """
    conn = connect()
    epoch_id, _ = _epoch(conn)
    assert epoch_id in {eid for eid, _ in reconciler.unreconciled_epochs(conn)}
    append_event(
        conn,
        "claude_code",
        "reconcile",
        meta={
            "epoch_id": epoch_id,
            "model": reconciler.MODEL,
            "messages": reconciler.MIN_MESSAGES,
            "notes": 2,
            "exit": 0,
            "egress_id": 7,
        },
    )
    assert epoch_id not in {eid for eid, _ in reconciler.unreconciled_epochs(conn)}
    # the skip paths write a marker with no dispatch fields at all
    epoch2_id, _ = _epoch(conn)
    append_event(
        conn,
        "claude_code",
        "reconcile",
        meta={"epoch_id": epoch2_id, "model": reconciler.MODEL,
              "skipped": "too_small", "messages": 1},
    )
    assert epoch2_id not in {eid for eid, _ in reconciler.unreconciled_epochs(conn)}


def _fake_done(observed=None):
    def run(*args, **kwargs):
        if observed is not None:
            observed["input"] = kwargs["input"]
        return SimpleNamespace(returncode=0, stdout="DONE", stderr="")
    return run


def test_unrelated_concurrent_notes_do_not_mark_self_documented(monkeypatch):
    """A parallel session's notes share the id window but cite nothing here;
    the epoch must still be distilled (previously: silently skipped forever)."""
    conn = connect()
    session_id = "epoch-under-test"
    message_ids = []
    for index in range(reconciler.MIN_MESSAGES):
        message_ids.append(
            append_event(conn, "claude_code", "message",
                         content=f"dialogue {index}",
                         meta={"role": "user", "session_id": session_id}))
        if index == 2:
            for n in range(reconciler.LIVE_NOTE_SKIP):
                append_event(conn, "note", "note",
                             content=f"unrelated concurrent note {n}",
                             meta={"actor": "human"})
    meta = {"session_id": session_id,
            "start_event_id": message_ids[0] - 1,
            "end_event_id": message_ids[-1]}
    epoch_id = append_event(conn, "claude_code", "epoch", meta=meta)

    monkeypatch.setattr(reconciler.subprocess, "run", _fake_done())
    result = reconciler.reconcile(conn, epoch_id, meta)
    assert "skipped" not in result
    assert result["egress_id"]


def test_citing_notes_mark_self_documented_even_after_the_epoch(monkeypatch):
    """Notes whose kernel-stamped anchors cite into the window count — and a
    crashed run's own post-epoch notes count too, so the retry does not
    double-distill."""
    conn = connect()
    epoch_id, meta = _epoch(conn)
    first_msg = meta["start_event_id"] + 1
    for n in range(reconciler.LIVE_NOTE_SKIP):
        append_event(conn, "note", "note",
                     content=f"distilled claim {n} [{first_msg}]",
                     meta={"actor": "reconciler",
                           "derivation": {"source_egress": 1,
                                          "anchors": [first_msg]}})
    dispatched = []
    monkeypatch.setattr(reconciler.subprocess, "run",
                        lambda *a, **k: dispatched.append(1))
    result = reconciler.reconcile(conn, epoch_id, meta)
    assert result == {"skipped": "self_documented",
                      "messages": reconciler.MIN_MESSAGES}
    assert not dispatched


def test_size_cap_discloses_only_included_messages(monkeypatch):
    conn = connect()
    epoch_id, meta = _epoch(conn)
    all_ids = list(range(meta["start_event_id"] + 1,
                         meta["end_event_id"] + 1))
    monkeypatch.setattr(reconciler, "MAX_DIALOGUE_CHARS", 80)
    observed = {}
    monkeypatch.setattr(reconciler.subprocess, "run", _fake_done(observed))
    result = reconciler.reconcile(conn, epoch_id, meta)

    receipt = conn.execute(
        "SELECT content, meta FROM events WHERE id = ?", (result["egress_id"],)
    ).fetchone()
    rmeta = json.loads(receipt["meta"])
    items = rmeta["items"]
    assert 0 < len(items) < len(all_ids)
    assert rmeta["omitted_messages"] == len(all_ids) - len(items)
    assert "omitted for size" in receipt["content"]
    for kept in items:
        assert f"[{kept}]" in receipt["content"]
    for missing in set(all_ids) - set(items):
        assert f"[{missing}]" not in receipt["content"]


def test_message_count_cap_bounds_the_item_list(monkeypatch):
    conn = connect()
    epoch_id, meta = _epoch(conn)
    monkeypatch.setattr(reconciler, "MAX_DIALOGUE_MESSAGES", 4)
    monkeypatch.setattr(reconciler.subprocess, "run", _fake_done())
    result = reconciler.reconcile(conn, epoch_id, meta)
    rmeta = json.loads(conn.execute(
        "SELECT meta FROM events WHERE id = ?", (result["egress_id"],)
    ).fetchone()["meta"])
    assert len(rmeta["items"]) == 4
    assert rmeta["omitted_messages"] == reconciler.MIN_MESSAGES - 4
