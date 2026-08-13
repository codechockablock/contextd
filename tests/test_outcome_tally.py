"""Resumption outcome tally: failure classes on miss/partial verdicts, the
type-stratified scoreboard, and unchanged recall-section output."""

import argparse
import json
import sys

import pytest

from contextd.cli import cmd_outcome, main
from contextd.db import append_event, connect


def _ns(**kw):
    defaults = {"egress_id": None, "verdict": None, "note": "",
                "failure_class": None}
    return argparse.Namespace(**{**defaults, **kw})


def _egress(conn, egress_type):
    return append_event(conn, "gate", "egress", content="disclosed",
                        meta={"type": egress_type, "est_tokens": 2})


def test_failure_class_stored_and_tallied(isolated_contextd_home, capsys):
    conn = connect()
    ck = _egress(conn, "checkpoint")
    cmd_outcome(_ns(egress_id=ck, verdict="miss",
                    failure_class="not-selected", note="needed the decision"))
    m = json.loads(conn.execute(
        "SELECT meta FROM events WHERE kind='outcome' ORDER BY id DESC LIMIT 1"
    ).fetchone()["meta"])
    assert m == {"egress_id": ck, "verdict": "miss",
                 "failure_class": "not-selected",
                 "note": "needed the decision"}
    cmd_outcome(_ns())
    out = capsys.readouterr().out
    assert "checkpoints: 1  judged: 1  unjudged: 0" in out
    assert "hit 0  partial 0  miss 1" in out
    assert "failure classes: not-selected 1" in out


def test_hit_with_failure_class_refuses_nonzero(isolated_contextd_home):
    conn = connect()
    ck = _egress(conn, "checkpoint")
    with pytest.raises(SystemExit) as e:
        cmd_outcome(_ns(egress_id=ck, verdict="hit", failure_class="drowned"))
    assert e.value.code not in (0, None)
    assert not conn.execute(
        "SELECT 1 FROM events WHERE kind='outcome'").fetchone()


def test_scoreboard_with_failure_class_refuses(isolated_contextd_home):
    connect()
    with pytest.raises(SystemExit) as e:
        cmd_outcome(_ns(failure_class="drowned"))
    assert e.value.code not in (0, None)


def test_unknown_class_refused_at_parse(isolated_contextd_home, monkeypatch):
    monkeypatch.setattr(sys, "argv",
                        ["ctx", "outcome", "1", "miss",
                         "--failure-class", "bogus"])
    with pytest.raises(SystemExit) as e:
        main()
    assert e.value.code not in (0, None)


def test_recall_section_output_unchanged(isolated_contextd_home, capsys):
    conn = connect()
    r1, r2 = _egress(conn, "recall"), _egress(conn, "recall")
    _egress(conn, "recall")
    cmd_outcome(_ns(egress_id=r1, verdict="hit"))
    cmd_outcome(_ns(egress_id=r2, verdict="miss"))
    capsys.readouterr()
    cmd_outcome(_ns())
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "recalls: 3  judged: 2  unjudged: 1"
    assert lines[1] == ("  hit 1  partial 0  miss 1"
                       "  — hit rate 50% (v0.1 bar: 30%)")


def test_other_judged_types_get_a_generic_line(isolated_contextd_home, capsys):
    conn = connect()
    sr = _egress(conn, "search")
    _egress(conn, "timeline")  # unjudged: no line
    cmd_outcome(_ns(egress_id=sr, verdict="partial"))
    capsys.readouterr()
    cmd_outcome(_ns())
    out = capsys.readouterr().out
    assert "search: 1  judged: 1  hit 0  partial 1  miss 0" in out
    assert "timeline" not in out


def test_last_verdict_wins_including_its_class(isolated_contextd_home, capsys):
    conn = connect()
    ck = _egress(conn, "checkpoint")
    cmd_outcome(_ns(egress_id=ck, verdict="miss", failure_class="drowned"))
    cmd_outcome(_ns(egress_id=ck, verdict="hit"))
    capsys.readouterr()
    cmd_outcome(_ns())
    out = capsys.readouterr().out
    assert "checkpoints: 1  judged: 1  unjudged: 0" in out
    assert "hit 1  partial 0  miss 0" in out
    assert "failure classes" not in out
