"""The lineage gauge: chain depth, anchor health, the DEPTH ALERT, and the
status line — measured on constructed archives, never assumed."""

import argparse
import contextlib
import io
import json
import time

import pytest

from contextd import load_config
from contextd.cli import cmd_lineage, cmd_status
from contextd.db import append_event, connect
from contextd.gate import disclose
from contextd.lineage import alert_line, format_stats, lineage_stats, status_line


def _leaves(conn, n=2, session="s"):
    return [append_event(conn, "claude_code", "message",
                         content=f"dialogue line {i}",
                         meta={"role": "user" if i % 2 == 0 else "assistant",
                               "session_id": session})
            for i in range(n)]


def _disclose(conn, ids, **extra):
    payload = "\n\n".join(f"--- [{i}] x claude_code/message  ---\nline {i}"
                          for i in ids)
    return disclose(conn, load_config(), payload,
                    {"type": "reconcile_dialogue", "items": ids,
                     **extra})["egress_id"]


def _note(conn, text, egress, anchors):
    return append_event(conn, "note", "note", content=text,
                        meta={"actor": "mcp",
                              "derivation": {"source_egress": egress,
                                             "anchors": anchors}})


def _depth1_archive(conn):
    ids = _leaves(conn)
    eg = _disclose(conn, ids)
    nid = _note(conn, f"gate stays model-free [{ids[0]}][{ids[1]}]", eg, ids)
    return ids, eg, nid


def _depth2_archive(conn):
    ids, eg, nid = _depth1_archive(conn)
    eg2 = _disclose(conn, [nid])
    nid2 = _note(conn, f"summary of the summary [{nid}]", eg2, [nid])
    return ids, nid, nid2


def test_depth1_archive_is_healthy_and_quiet():
    conn = connect()
    ids, eg, nid = _depth1_archive(conn)
    stats = lineage_stats(conn, load_config())
    assert stats["derived_events"] == 1 and stats["derived_notes"] == 1
    assert stats["depth_counts"] == {1: 1}
    assert stats["max_note_depth_observed"] == 1
    assert stats["alert_notes"] == []
    a = stats["anchors"]
    assert a["total"] == 2 and a["resolved"] == 2 and a["in_disclosure"] == 2
    assert a["resolution_rate"] == 1.0
    assert stats["orphaned_derivations"] == []
    assert "DEPTH ALERT" not in format_stats(stats)


def test_depth2_note_citing_note_raises_the_alert():
    conn = connect()
    ids, nid, nid2 = _depth2_archive(conn)
    stats = lineage_stats(conn, load_config())
    assert stats["depth_counts"] == {1: 1, 2: 1}
    assert stats["max_note_depth_observed"] == 2
    assert [e["id"] for e in stats["alert_notes"]] == [nid2]
    assert stats["alert_notes"][0]["cites_notes"] == [nid]
    out = format_stats(stats)
    assert "DEPTH ALERT" in out and f"#{nid2}" in out
    assert f"#{nid}" in alert_line(stats)


def test_cli_exit_codes_mirror_the_alert():
    conn = connect()
    _depth1_archive(conn)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cmd_lineage(argparse.Namespace(action=None, full=False))
    assert "DEPTH ALERT" not in buf.getvalue()

    _depth2_archive(conn)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), pytest.raises(SystemExit) as exc:
        cmd_lineage(argparse.Namespace(action=None, full=True))
    assert exc.value.code == 2
    out = buf.getvalue()
    assert "DEPTH ALERT" in out
    # --full lists every derivation-bearing event
    assert out.count("note") >= 3


def test_status_shows_the_line_and_warns_only_past_the_limit():
    conn = connect()
    _depth1_archive(conn)

    def status_out():
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cmd_status(argparse.Namespace())
        return buf.getvalue()

    out = status_out()
    assert "lineage: max note depth 1 (limit 1)" in out
    assert not any("a note is citing notes" in ln for ln in out.splitlines()
                   if ln.startswith("WARNING")), out

    _depth2_archive(conn)
    out = status_out()
    assert "lineage: max note depth 2 (limit 1)" in out
    assert any(ln.startswith("WARNING") and "a note is citing notes" in ln
               for ln in out.splitlines()), out


def test_config_limit_is_respected():
    conn = connect()
    _depth2_archive(conn)
    cfg = load_config()
    cfg["lineage"]["max_note_depth"] = 2
    stats = lineage_stats(conn, cfg)
    assert stats["alert_notes"] == []
    assert "limit 2" in status_line(stats)


def test_broken_anchor_and_orphan_are_counted_not_hidden():
    conn = connect()
    ids, eg, nid = _depth1_archive(conn)
    # a note citing a fabricated id, and one bound to a missing egress
    bad = _note(conn, "claims a ghost [999999]", eg, [999999])
    orphan = _note(conn, f"bound to nothing [{ids[0]}]", 888888, [ids[0]])
    stats = lineage_stats(conn, load_config())
    a = stats["anchors"]
    assert a["unresolved"] == 1  # the ghost
    assert a["outside_disclosure"] == 1  # orphan's real anchor has no items
    assert stats["orphaned_derivations"] == [orphan]
    out = format_stats(stats, full=True)
    assert "ORPHAN" in out and "orphaned derivations" in out
    per = {e["id"]: e for e in stats["per_event"]}
    assert per[bad]["anchors_resolved"] == 0
    assert per[bad]["anchors_total"] == 1


def test_notes_per_epoch_and_evidence_age():
    conn = connect()
    ids = _leaves(conn, 4)
    epoch = append_event(conn, "claude_code", "epoch",
                         meta={"session_id": "s", "start_event_id": ids[0],
                               "end_event_id": ids[-1]})
    eg = _disclose(conn, ids, epoch_id=epoch)
    for i in range(3):
        _note(conn, f"note {i} [{ids[i]}]", eg, [ids[i]])
    stats = lineage_stats(conn, load_config())
    assert stats["epochs"]["total"] == 1
    assert stats["epochs"]["with_notes"] == 1
    assert stats["epochs"]["notes_per_epoch_max"] == 3
    assert stats["evidence_age_days"]["n"] == 3
    assert stats["evidence_age_days"]["min"] >= 0


def test_synthesis_egress_counts_as_derived_but_never_note_alerts():
    conn = connect()
    ids, eg, nid = _depth1_archive(conn)
    # a distilled serve citing the note: depth 2 event, but not a note —
    # the alert is about notes citing notes, not about serving distillates
    append_event(conn, "gate", "egress",
                 content=f"fused claim [{nid}]",
                 meta={"mode": "synthesis", "source_egress": eg,
                       "anchors": [nid], "items": [nid], "est_tokens": 5})
    stats = lineage_stats(conn, load_config())
    assert stats["max_depth"] == 2
    assert stats["max_note_depth_observed"] == 1
    assert stats["alert_notes"] == []


def test_scales_to_80k_events_in_seconds():
    conn = connect()
    # bulk rows bypass the witnessed append path on purpose: the gauge reads
    # topology; chain integrity is verify's job, not this test's
    rows = [("2026-01-01T00:00:00+00:00", "claude_code", "message",
             f"leaf {i}", json.dumps({"role": "user", "session_id": "s"}))
            for i in range(79_000)]
    conn.executemany(
        "INSERT INTO events (ts, source, kind, content, meta) "
        "VALUES (?, ?, ?, ?, ?)", rows)
    conn.commit()
    base = conn.execute("SELECT MAX(id) FROM events").fetchone()[0]
    derived_rows = []
    for k in range(500):
        cited = [base - 3 * k - j for j in range(3)]
        eg_meta = json.dumps({"type": "reconcile_dialogue", "items": cited,
                              "est_tokens": 1})
        derived_rows.append(("2026-01-02T00:00:00+00:00", "gate", "egress",
                             "bundle", eg_meta))
    conn.executemany(
        "INSERT INTO events (ts, source, kind, content, meta) "
        "VALUES (?, ?, ?, ?, ?)", derived_rows)
    conn.commit()
    first_eg = base + 1
    note_rows = []
    for k in range(500):
        cited = [base - 3 * k - j for j in range(3)]
        text = "note " + "".join(f"[{c}]" for c in cited)
        meta = json.dumps({"actor": "mcp", "derivation": {
            "source_egress": first_eg + k, "anchors": cited}})
        note_rows.append(("2026-01-03T00:00:00+00:00", "note", "note",
                          text, meta))
    conn.executemany(
        "INSERT INTO events (ts, source, kind, content, meta) "
        "VALUES (?, ?, ?, ?, ?)", note_rows)
    conn.commit()
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] >= 80_000
    t0 = time.monotonic()
    stats = lineage_stats(conn, load_config())
    elapsed = time.monotonic() - t0
    assert stats["derived_notes"] == 500
    assert stats["max_note_depth_observed"] == 1
    assert stats["anchors"]["total"] == 1500  # 500 notes x 3 anchors
    assert stats["anchors"]["resolution_rate"] == 1.0
    assert elapsed < 10.0, f"lineage walk took {elapsed:.1f}s on 80k events"
