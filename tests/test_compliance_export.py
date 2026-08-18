"""The EU AI Act logging-evidence export: deterministic, read-only, no verdict.

Three properties carry this module, and each has a test that fails loudly if
someone later trades it away for convenience:

1. **Determinism.** Two runs over an unchanged archive must be byte-identical,
   because an artifact that cannot be diffed cannot be reviewed. The generator
   takes ``now`` as a required argument for exactly this reason.
2. **Read-only.** Generating evidence must not change the thing it describes.
   The export must not append an event, must not move the chain tip, and must
   not complete an interrupted append as a side effect.
3. **No verdict, and the right articles.** The artifact reports measurements
   keyed to Articles 12, 19(1) and 26(6), and states in its own body that the
   Regulation does not mandate append-only storage. A compliance artifact that
   overclaims is worse than none.
"""

import json

import pytest

from contextd.compliance import (
    REPORT_DOMAIN,
    REPORT_VERSION,
    RETENTION_FLOOR_DAYS,
    ComplianceError,
    compliance_record,
    compliance_report,
    render,
)
from contextd.canonical import canonical_digest
from contextd.db import _db_tip, connect
from contextd.ingest import ingest_note

#: A fixed instant, so every assertion below is about the archive rather than
#: about what time the suite happened to run. 2026-08-17T12:00:00Z.
FIXED_NOW = 1787054400


def _archive(n=3):
    conn = connect()
    for i in range(n):
        ingest_note(conn, f"compliance fixture note {i}")
    return conn


# --- 1. determinism --------------------------------------------------------


def test_two_runs_over_an_unchanged_archive_are_byte_identical():
    conn = _archive()
    first = compliance_report(conn, now=FIXED_NOW)
    second = compliance_report(conn, now=FIXED_NOW)
    assert first == second


def test_the_generator_refuses_to_read_the_clock_itself():
    """``now`` is required. A default would make the artifact undiffable."""
    conn = _archive()
    with pytest.raises(TypeError):
        compliance_record(conn)


def test_a_non_integer_instant_is_refused():
    conn = _archive()
    for bad in (FIXED_NOW + 0.5, "2026-08-17", True, None):
        with pytest.raises((ComplianceError, TypeError)):
            compliance_record(conn, now=bad)


def test_only_the_time_dependent_fields_move_when_the_instant_moves():
    conn = _archive()
    early = compliance_record(conn, now=FIXED_NOW)
    later = compliance_record(conn, now=FIXED_NOW + 400 * 86_400)
    assert early["archive"] == later["archive"]
    assert early["integrity"] == later["integrity"]
    assert early["checkpoints"] == later["checkpoints"]
    assert early["report"]["generated_at"] != later["report"]["generated_at"]
    # the retention *measurement* is relative to now; the floor never is
    assert early["retention"]["floor_days"] == later["retention"]["floor_days"]
    assert (later["retention"]["oldest_event_age_days"]
            > early["retention"]["oldest_event_age_days"])


def test_the_digest_covers_the_whole_record_and_recomputes():
    conn = _archive()
    record = compliance_record(conn, now=FIXED_NOW)
    claimed = record["report"].pop("digest")
    assert claimed == canonical_digest(REPORT_DOMAIN, record)


def test_the_report_domain_is_not_a_signing_domain():
    """A report digest must never be substitutable for a signature over an act
    or a chain tip."""
    from contextd import attest, ledger_sig

    assert REPORT_DOMAIN not in {
        attest.DOMAIN, attest.INTENT_DOMAIN,
        ledger_sig.ENVELOPE_DOMAIN, ledger_sig.TIP_DOMAIN,
        ledger_sig.CHECKPOINT_DOMAIN,
    }


def test_the_rendering_is_stable_json_with_sorted_keys():
    record = {"b": 1, "a": {"d": 2, "c": 3}}
    assert render(record) == json.dumps(
        record, sort_keys=True, indent=2, ensure_ascii=False
    ) + "\n"
    assert render(record).endswith("\n")


# --- 2. read-only ----------------------------------------------------------


def test_generating_the_artifact_appends_nothing_and_moves_no_tip():
    conn = _archive()
    before_tip = _db_tip(conn)
    before_count = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]

    compliance_record(conn, now=FIXED_NOW)

    after_tip = _db_tip(conn)
    after_count = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
    assert (before_count, before_tip["id"], before_tip["chain_hash"]) == (
        after_count, after_tip["id"], after_tip["chain_hash"]
    )


def test_an_archive_with_no_events_still_produces_an_artifact():
    """A brand-new archive is a legitimate thing to ask about; it must not
    crash, and it must not claim a retention span it does not have."""
    conn = connect()
    record = compliance_record(conn, now=FIXED_NOW)
    assert record["archive"]["events"] == 0
    assert record["retention"]["status"] == "no_events"
    assert record["retention"]["span_days"] == 0


# --- 3. what it claims, and what it refuses to claim ------------------------


def test_the_artifact_carries_no_pass_fail_verdict():
    conn = _archive()
    text = compliance_report(conn, now=FIXED_NOW).lower()
    for forbidden in ("compliant", "non-compliant", "certified", "approved"):
        assert forbidden not in text, f"artifact must not adjudicate: {forbidden}"


def test_the_six_month_floor_is_keyed_to_articles_19_and_26_not_article_12():
    conn = _archive()
    framing = compliance_record(conn, now=FIXED_NOW)["framing"]
    assert "six months" in framing["article_19_1"]
    assert "six months" in framing["article_26_6"]
    # Article 12 is the logging-capability design requirement, not a period.
    assert "six months" not in framing["article_12"]
    assert "record" in framing["article_12"]


def test_the_artifact_states_that_append_only_is_not_legally_required():
    conn = _archive()
    record = compliance_record(conn, now=FIXED_NOW)
    claim = record["framing"]["append_only_is_not_required"]
    assert "nowhere requires append-only" in claim
    assert "not a legal mandate" in claim


def test_both_retention_articles_are_limited_to_logs_under_that_partys_control():
    conn = _archive()
    framing = compliance_record(conn, now=FIXED_NOW)["framing"]
    assert "control" in framing["article_19_1"]
    assert "limitations" in framing["article_26_6"]


def test_the_applicability_dates_are_the_corrected_ones():
    conn = _archive()
    dates = compliance_record(conn, now=FIXED_NOW)["framing"]["applicability"]
    assert dates["annex_iii_article_6_2"].startswith("2026-08-02")
    assert dates["product_embedded_article_6_1"].startswith("2027-08-02")


def test_the_limitations_travel_inside_the_artifact():
    """A report separated from its documentation must still carry its caveats."""
    conn = _archive()
    limits = " ".join(compliance_record(conn, now=FIXED_NOW)["limitations"]).lower()
    assert "not legal advice" in limits
    assert "tamper-evidence, not tamper-proofing" in limits
    assert "under that party's" in limits or "under their control" in limits


def test_a_young_archive_reports_a_shortfall_as_expected_not_as_a_finding():
    conn = _archive()
    retention = compliance_record(conn, now=FIXED_NOW)["retention"]
    assert retention["status"] == "archive_younger_than_floor"
    assert retention["floor_days"] == RETENTION_FLOOR_DAYS
    assert "not a finding of non-compliance" in retention["note"]


def test_an_archive_older_than_the_floor_says_so():
    conn = _archive()
    future = FIXED_NOW + (RETENTION_FLOOR_DAYS + 5) * 86_400
    retention = compliance_record(conn, now=future)["retention"]
    assert retention["status"] == "retained_span_reaches_floor"
    assert retention["oldest_event_age_days"] >= RETENTION_FLOOR_DAYS


# --- what the ledger actually measures --------------------------------------


def test_the_measurements_match_the_archive():
    conn = _archive(n=5)
    record = compliance_record(conn, now=FIXED_NOW)
    row = conn.execute(
        "SELECT COUNT(*) AS n, MIN(ts) AS lo, MAX(ts) AS hi FROM events"
    ).fetchone()
    assert record["archive"]["events"] == row["n"]
    assert record["archive"]["earliest_event"] == row["lo"]
    assert record["archive"]["latest_event"] == row["hi"]
    assert record["archive"]["tip_event_id"] == _db_tip(conn)["id"]
    assert record["report"]["version"] == REPORT_VERSION


def test_an_intact_chain_is_reported_intact():
    conn = _archive()
    assert compliance_record(conn, now=FIXED_NOW)["integrity"]["chain"] == "intact"
    assert compliance_record(conn, now=FIXED_NOW)["integrity"]["events_checked"] > 0


def test_a_rewritten_row_is_reported_as_a_broken_chain():
    """The artifact must not launder a tampered archive into clean evidence."""
    conn = _archive()
    conn.execute("DROP TRIGGER IF EXISTS events_no_update")
    conn.execute("UPDATE events SET content = 'rewritten' WHERE id = 1")
    conn.commit()

    integrity = compliance_record(conn, now=FIXED_NOW)["integrity"]
    assert integrity["chain"] in {"broken", "unverifiable"}
    assert integrity["first_bad_event"] == 1


def test_the_uncovered_checkpoint_window_is_reported_not_hidden():
    """Events since the last checkpoint are protected by local state alone.
    That window is the number a reader is most likely to assume away."""
    conn = _archive(n=4)
    checkpoints = compliance_record(conn, now=FIXED_NOW)["checkpoints"]
    assert checkpoints["uncovered_events"] == _db_tip(conn)["id"]
    assert checkpoints["last_checkpoint_tip"] == 0


def test_the_artifact_names_the_record_format_a_reader_would_need():
    conn = _archive()
    assert (compliance_record(conn, now=FIXED_NOW)["archive"]["record_format"]
            == "contextd-record-format v1")
