"""`ctx security doctor` reports each invariant separately and fails honestly.

The failure mode this suite exists to prevent is a doctor that returns "ok"
because a component is *absent*. An unimplemented checkpoint is a failing
`protected_checkpoint`, not an exemption from it; development mode is a failing
`protected_daemon`, not a different rubric. A green doctor on this tree would
itself be the bug.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from contextd import home
from contextd.db import connect
from contextd.doctor import INVARIANTS, format_report, run
from tests.authorization_support import operator

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_cli(*argv, env_extra=None):
    env = {**os.environ, "CONTEXTD_HOME": str(home()), **(env_extra or {})}
    return subprocess.run(
        [sys.executable, "-m", "contextd.cli", "security", *argv],
        capture_output=True, text=True, env=env, timeout=180,
    )


@pytest.fixture
def hardened_config():
    connect().close()
    config = home() / "config.toml"
    config.write_text('[security]\nmode = "hardened"\n')
    yield config
    config.unlink(missing_ok=True)


# --- shape ------------------------------------------------------------------

def test_every_invariant_is_reported_separately():
    connect().close()
    report = run()
    assert set(report["invariants"]) == set(INVARIANTS)
    for name, result in report["invariants"].items():
        assert isinstance(result["ok"], bool), name
        assert result["detail"], f"{name} reports no detail"
        if not result["ok"]:
            assert result.get("remedy"), f"{name} fails with no remedy"


def test_a_failing_invariant_names_what_was_observed_not_what_was_wanted():
    connect().close()
    report = run()
    daemon = report["invariants"]["protected_daemon"]
    assert daemon["ok"] is False
    assert "development" in daemon["detail"]
    assert "docs/DEPLOYMENT.md" in daemon["remedy"]


def test_development_mode_is_not_hardened():
    connect().close()
    report = run()
    assert report["mode"] == "development"
    assert report["hardened"] is False
    assert report["failing"], "development mode reported no failing invariants"
    assert "NOT hardened" in report["summary"]


# --- each invariant fails for its own reason -------------------------------

def test_protected_daemon_fails_without_a_service_boundary():
    connect().close()
    result = run()["invariants"]["protected_daemon"]
    assert result["ok"] is False


def test_production_signer_fails_without_an_enrolled_hardware_key():
    conn = connect()
    operator(conn)                      # registers a TEST key, not a hardware one
    result = run(conn)["invariants"]["production_signer"]
    assert result["ok"] is False
    assert "signer helper" in result["detail"] or "Secure Enclave" in result["detail"]


def test_raw_archive_inaccessible_fails_while_the_client_can_read_it():
    connect().close()
    result = run()["invariants"]["raw_archive_inaccessible"]
    assert result["ok"] is False
    assert os.access(home() / "contextd.db", os.R_OK)


def test_service_signatures_fails_while_nothing_is_signed():
    """An unsigned ledger must report as failing, never as ok."""
    conn = connect()
    result = run(conn)["invariants"]["service_signatures"]
    assert result["ok"] is False
    assert "nothing has been service-signed" in result["detail"]
    assert "recompute" in result["detail"]      # says WHY the chain is not enough


def test_service_signatures_passes_once_the_ledger_is_signed():
    from contextd.ingest import ingest_note
    from contextd.ledger_sig import sign_event, sign_tip
    conn = connect()
    eid = ingest_note(conn, "an event worth signing")
    sign_event(conn, eid)
    sign_tip(conn)
    result = run(conn)["invariants"]["service_signatures"]
    assert result["ok"] is True
    assert "verify" in result["detail"]


def test_service_signatures_fails_loudly_on_a_bad_signature():
    from contextd.ingest import ingest_note
    from contextd.ledger_sig import sign_event
    from tests.test_service_attestation import _rewrite_event
    conn = connect()
    eid = ingest_note(conn, "original")
    sign_event(conn, eid)
    _rewrite_event(conn, eid, "tampered")
    result = run(conn)["invariants"]["service_signatures"]
    assert result["ok"] is False
    assert "altered after acceptance" in result["detail"]
    assert "compromised" in result["remedy"]


def test_protected_checkpoint_fails_when_the_checkpoint_is_writable(tmp_path):
    """A checkpoint this uid can rewrite proves nothing about rollback."""
    from contextd.ingest import ingest_note
    from contextd.ledger_sig import write_checkpoint
    conn = connect()
    ingest_note(conn, "x")
    destination = tmp_path / "checkpoint.json"
    write_checkpoint(conn, destination)
    (home() / "config.toml").write_text(
        f'[security]\ncheckpoint_destination = "{destination}"\n')
    try:
        result = run(conn)["invariants"]["protected_checkpoint"]
        assert result["ok"] is False
        assert "WRITABLE by this uid" in result["detail"]
    finally:
        (home() / "config.toml").unlink(missing_ok=True)


def test_protected_checkpoint_detects_rollback(tmp_path):
    from contextd.ingest import ingest_note
    from contextd.ledger_sig import write_checkpoint
    from tests.test_service_attestation import _recompute_chain
    conn = connect()
    for i in range(4):
        ingest_note(conn, f"event {i}")
    destination = tmp_path / "checkpoint.json"
    write_checkpoint(conn, destination)
    (home() / "config.toml").write_text(
        f'[security]\ncheckpoint_destination = "{destination}"\n')
    try:
        conn.execute("DROP TRIGGER IF EXISTS events_no_delete")
        conn.execute("DELETE FROM events WHERE id >= (SELECT MAX(id) FROM events)")
        conn.commit()
        _recompute_chain(conn)
        result = run(conn)["invariants"]["protected_checkpoint"]
        assert result["ok"] is False
        assert "ROLLBACK" in result["detail"]
    finally:
        (home() / "config.toml").unlink(missing_ok=True)


def test_protected_checkpoint_reports_rollback_resistance_incomplete():
    connect().close()
    result = run()["invariants"]["protected_checkpoint"]
    assert result["ok"] is False
    assert "rollback_resistance: incomplete" in result["detail"]


def test_no_insecure_fallback_fails_while_the_test_signer_is_enabled():
    conn = connect()
    result = run(conn)["invariants"]["no_insecure_fallback"]
    assert result["ok"] is False
    # the suite runs with the test signer on, and the doctor must say so
    detail = result["detail"]
    assert ("test-only software signer" in detail
            or "software key" in detail
            or "development mode" in detail)


def test_no_plaintext_scratch_passes_when_nothing_is_at_rest():
    connect().close()
    result = run()["invariants"]["no_plaintext_scratch"]
    assert result["ok"] is True


def test_no_plaintext_scratch_fails_when_scratch_is_left_behind():
    from contextd.scratch import scratch_root
    connect().close()
    leftover = scratch_root() / "contextd-loop-scan-LEFTOVER"
    leftover.mkdir()
    try:
        result = run()["invariants"]["no_plaintext_scratch"]
        assert result["ok"] is False
        assert "plaintext may be on disk" in result["detail"]
    finally:
        leftover.rmdir()


# --- the CLI contract -------------------------------------------------------

def test_strict_exits_nonzero_while_any_invariant_fails():
    connect().close()
    result = _run_cli("doctor", "--strict")
    assert result.returncode != 0, result.stdout
    assert "NOT hardened" in result.stdout


def test_non_strict_exits_zero_and_still_reports_failures():
    connect().close()
    result = _run_cli("doctor")
    assert result.returncode == 0
    assert "FAIL" in result.stdout


def test_json_output_is_machine_readable_and_lists_every_invariant():
    connect().close()
    result = _run_cli("doctor", "--json")
    payload = json.loads(result.stdout)
    assert set(payload["invariants"]) == set(INVARIANTS)
    assert payload["hardened"] is False
    assert isinstance(payload["failing"], list) and payload["failing"]


def test_strict_json_together_exit_nonzero():
    connect().close()
    result = _run_cli("doctor", "--strict", "--json")
    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["hardened"] is False


def test_report_never_claims_hardened_while_anything_fails():
    """The one claim the doctor must never get wrong."""
    connect().close()
    report = run()
    if report["failing"]:
        assert report["hardened"] is False
        assert "production is hardened" not in report["summary"]


def test_formatted_report_shows_every_invariant_and_its_remedy():
    connect().close()
    text = format_report(run())
    for name in INVARIANTS:
        assert name in text
    assert text.count("->") >= 1        # at least one remedy is offered
    assert "NOT hardened" in text


def test_doctor_survives_an_unopenable_archive(hardened_config):
    """Hardened mode without a service must still produce a report, not a
    traceback: the operator needs the diagnosis precisely when it is broken."""
    report = run()
    assert set(report["invariants"]) == set(INVARIANTS)
    assert report["hardened"] is False
    signer = report["invariants"]["production_signer"]
    assert signer["ok"] is False
    assert "cannot inspect" in signer["detail"] or "signer helper" in signer["detail"]


def test_doctor_output_carries_no_archive_content():
    from contextd.ingest import ingest_note
    conn = connect()
    ingest_note(conn, "private text sk-canary0000000000zzz1 in an event")
    text = format_report(run(conn)) + json.dumps(run(conn))
    assert "canary0000000000zzz1" not in text
    assert "private text" not in text
