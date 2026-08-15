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
