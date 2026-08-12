import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from contextd import load_config
from contextd import db as event_db
from contextd.db import connect
from contextd.gate import (
    GateError,
    disclose,
    est_tokens,
    record_dispatch_outcome,
    redact,
    spent_on_day,
    spent_today,
)


def test_disclose_redacts_exact_bytes_and_records_linked_outcome():
    conn = connect()
    cfg = load_config()
    raw = "send sk-abcdefghijklmnop1234 to the model"
    intent = {"type": "test", "purpose": "exact bytes"}

    result = disclose(conn, cfg, raw, intent)

    expected = redact(cfg, raw)
    assert result["content"] == expected
    assert result["est_tokens"] == est_tokens(expected)
    row = conn.execute(
        "SELECT content, meta FROM events WHERE id = ?", (result["egress_id"],)
    ).fetchone()
    assert row["content"] == expected
    assert "abcdefghijklmnop1234" not in row["content"]
    assert json.loads(row["meta"]) == {
        **intent,
        "est_tokens": est_tokens(expected),
    }

    outcome_id = record_dispatch_outcome(conn, result["egress_id"], "succeeded", exit=0)
    outcome = conn.execute(
        "SELECT content, meta FROM events WHERE id = ?", (outcome_id,)
    ).fetchone()
    assert outcome["content"] is None
    assert json.loads(outcome["meta"]) == {
        "egress_id": result["egress_id"],
        "status": "succeeded",
        "exit": 0,
    }
    with pytest.raises(sqlite3.IntegrityError):
        record_dispatch_outcome(conn, result["egress_id"], "failed", exit=1)


def test_exactly_at_cap_is_accepted_and_next_byte_is_refused():
    conn = connect()
    cfg = load_config()
    payload = "12345678"
    cfg["gate"]["daily_token_budget"] = est_tokens(payload)

    accepted = disclose(conn, cfg, payload, {"type": "cap"})
    assert spent_today(conn) == accepted["est_tokens"]
    with pytest.raises(GateError):
        disclose(conn, cfg, "x", {"type": "over-cap"})
    assert (
        conn.execute("SELECT COUNT(*) FROM events WHERE kind='egress'").fetchone()[0]
        == 1
    )


def test_32_callers_cannot_overspend_and_refusals_disclose_nothing():
    seed = connect()
    seed.close()
    cfg = load_config()
    raw = "archive secret sk-abcdefghijklmnop1234 payload"
    actual = est_tokens(redact(cfg, raw))
    accepted_limit = 7
    cfg["gate"]["daily_token_budget"] = actual * accepted_limit
    barrier = threading.Barrier(32)

    def caller(index):
        conn = connect()
        try:
            barrier.wait()
            result = disclose(conn, cfg, raw, {"type": "barrier", "caller": index})
            return ("accepted", result["egress_id"])
        except GateError as exc:
            return ("refused", str(exc))
        finally:
            conn.close()

    with ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(caller, range(32)))

    accepted = [value for status, value in results if status == "accepted"]
    refused = [value for status, value in results if status == "refused"]
    assert len(accepted) == accepted_limit
    assert len(refused) == 32 - accepted_limit
    assert all(
        "archive" not in error and "abcdefghijklmnop" not in error for error in refused
    )

    conn = connect()
    rows = conn.execute(
        "SELECT content, meta FROM events WHERE kind='egress' ORDER BY id"
    ).fetchall()
    assert len(rows) == accepted_limit
    assert (
        sum(json.loads(row["meta"])["est_tokens"] for row in rows)
        == cfg["gate"]["daily_token_budget"]
    )
    assert spent_today(conn) == cfg["gate"]["daily_token_budget"]
    assert all("abcdefghijklmnop1234" not in row["content"] for row in rows)


def test_daily_charge_uses_the_receipt_timestamp_day(monkeypatch):
    conn = connect()
    cfg = load_config()
    payload = "12345678"
    cfg["gate"]["daily_token_budget"] = est_tokens(payload)

    monkeypatch.setattr(event_db, "now_iso", lambda: "2026-08-12T23:59:59+00:00")
    disclose(conn, cfg, payload, {"type": "day-one"})
    monkeypatch.setattr(event_db, "now_iso", lambda: "2026-08-13T00:00:00+00:00")
    disclose(conn, cfg, payload, {"type": "day-two"})

    assert spent_on_day(conn, "2026-08-12") == est_tokens(payload)
    assert spent_on_day(conn, "2026-08-13") == est_tokens(payload)
