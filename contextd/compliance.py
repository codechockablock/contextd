"""Deterministic EU AI Act logging-and-retention evidence, read from the ledger.

What this module is
-------------------------------------------------------------------------

A pure function from (archive state, an instant) to a JSON artifact describing
what the archive can *evidence* about Article 12 logging and the Article
19(1)/26(6) retention floor. It reads; it never appends, never mutates, and
never calls a model. Nothing in it is a legal conclusion.

Why it is a pure function
-------------------------------------------------------------------------

``now`` is a required argument with no default. A compliance artifact that
changes between two runs over an unchanged archive cannot be diffed, archived,
or handed to a reviewer who wants to know what changed since last quarter, so
the wall clock is an input rather than an ambient read.
``tests/test_compliance_export.py::test_two_runs_over_an_unchanged_archive_are_byte_identical``
is the test that keeps it that way.

What the Regulation actually says, and what it does not
-------------------------------------------------------------------------

The program this module was written for carried three wrong beliefs about
Regulation (EU) 2024/1689. All three are corrected here, because a compliance
artifact citing the wrong article is worse than no artifact.

* **Article 12 is a design requirement on the system, not a retention rule.**
  It requires that a high-risk AI system technically allow for the automatic
  recording of events over its lifetime. It is about the *capability to log*.
* **The six-month figure is a retention floor, and it lives in Articles 19(1)
  and 26(6)** — 19(1) binds providers, 26(6) binds deployers. Both say logs
  are kept for a period appropriate to the intended purpose and *at least six
  months*, both are limited to logs **under that party's control**, and both
  are displaceable by other Union or national law (data-protection law in
  particular). A retention floor can therefore be *shortened* by a competing
  legal obligation, which is why this module reports a span and refuses to
  return a verdict.
* **The Regulation nowhere requires append-only or tamper-evident storage.**
  No article in it mandates a hash chain, a signature, or immutability. An
  ordinary rotated log file can satisfy Articles 12, 19(1), and 26(6).

So the honest positioning, which the generated artifact states in its own
``framing`` block rather than leaving to a reader's charity: contextd's ledger
is **one way** to satisfy those articles, and its append-only chain is an
**evidentiary** advantage — it makes "these logs were not edited" checkable
rather than asserted — and is **not** a legal requirement. Anyone claiming the
Regulation demands a tamper-evident ledger is selling something.

Applicability, since it decides whether any of this binds yet:

* **2 August 2026** — Article 6(2), the Annex III high-risk classifications.
* **2 August 2027** — Article 6(1), high-risk AI as a safety component of, or
  itself, a product under the Union harmonisation legislation in Annex I.

What the artifact deliberately does not do
-------------------------------------------------------------------------

It returns no pass/fail. Whether a system is high-risk, whether the operator
is a provider or a deployer, which logs are "under their control", and whether
another instrument displaces the floor are all questions about the deployment
and not about the bytes. This module reports measurements and names the
article each measurement bears on. The ``limitations`` block in every artifact
says so in the artifact itself, so a report separated from this docstring
still carries its own caveats.
"""

import json

from .canonical import canonical_digest

#: Bumped only for a breaking change to the artifact's shape. A reader that
#: understands v1 must keep understanding every artifact stamped v1.
REPORT_VERSION = 1

#: Domain separator for the artifact digest. Distinct from every signing domain
#: in `attest.py` and `ledger_sig.py` on purpose: this digest identifies a
#: report, and must never be substitutable for a signature over an act or a tip.
REPORT_DOMAIN = "contextd.ComplianceReportV1"

#: Six months expressed in days. The Regulation says "six months"; a day count
#: has to pick a reading, and 183 is the conservative one (the longer half-year)
#: — it can only make the artifact report a shortfall sooner, never later.
RETENTION_FLOOR_DAYS = 183

#: Seconds per day, for turning an event-timestamp span into whole days.
_DAY_SECONDS = 86_400

#: Article 6(2) — Annex III high-risk classification. Unix seconds, UTC.
#: Pinned by ``test_the_applicability_dates_are_the_corrected_ones``, which
#: caught both of these constants being four days wrong when first written.
APPLICABILITY_ANNEX_III = 1785628800  # 2026-08-02T00:00:00Z
#: Article 6(1) — high-risk as/in a product under Annex I harmonisation law.
APPLICABILITY_PRODUCT_EMBEDDED = 1817164800  # 2027-08-02T00:00:00Z


class ComplianceError(RuntimeError):
    """The archive could not be read for a compliance artifact."""


def _iso(unix_seconds: int) -> str:
    """UTC ISO-8601, second resolution, no local timezone anywhere."""
    from datetime import datetime, timezone

    return datetime.fromtimestamp(int(unix_seconds), timezone.utc).isoformat()


def _parse_ts(value: str) -> int | None:
    """Ledger ``ts`` to unix seconds, or None if it does not parse.

    Returns None rather than raising: an unparseable historical timestamp is a
    fact about the archive that the artifact should report, not an error that
    denies the operator every other measurement in it.
    """
    from datetime import datetime

    try:
        return int(datetime.fromisoformat(value).timestamp())
    except (TypeError, ValueError):
        return None


def _event_span(conn) -> dict:
    row = conn.execute(
        "SELECT COUNT(*) AS n, MIN(ts) AS lo, MAX(ts) AS hi FROM events"
    ).fetchone()
    count = int(row["n"] or 0)
    return {
        "count": count,
        "earliest": (row["lo"] or "") if count else "",
        "latest": (row["hi"] or "") if count else "",
    }


def _archive_uuid(conn, tables: set) -> str:
    if "archive_identity" not in tables:
        return ""
    row = conn.execute(
        "SELECT uuid FROM archive_identity WHERE singleton = 1"
    ).fetchone()
    return str(row["uuid"]) if row else ""


def _checkpoint_coverage(conn, tables: set, tip_id: int) -> dict:
    """How much of the ledger a signed checkpoint actually reaches.

    The uncovered window is the number that matters and the one a reader is
    most likely to assume away: events appended since the last checkpoint are
    protected by local state alone (docs/SECURITY.md §9, "The exposure
    window"), so a checkpoint is silent about them.
    """
    from .ledger_sig import checkpoint_interval

    if "service_checkpoints" not in tables:
        return {
            "supported": "no",
            "configured_interval_events": 0,
            "recorded": 0,
            "last_checkpoint_tip": 0,
            "uncovered_events": int(tip_id),
            "algorithms": [],
        }
    row = conn.execute(
        "SELECT COUNT(*) AS n, MAX(tip_id) AS tip FROM service_checkpoints"
    ).fetchone()
    recorded = int(row["n"] or 0)
    last_tip = int(row["tip"] or 0)
    algs = sorted({
        str(r["alg"])
        for r in conn.execute("SELECT DISTINCT alg FROM service_checkpoints")
    })
    try:
        interval = int(checkpoint_interval())
    except Exception:
        interval = 0
    return {
        "supported": "yes",
        "configured_interval_events": interval,
        "recorded": recorded,
        "last_checkpoint_tip": last_tip,
        "uncovered_events": max(int(tip_id) - last_tip, 0),
        "algorithms": algs,
    }


def _integrity(conn, root) -> dict:
    """Chain verification, read-only.

    ``verify_chain_read_only`` rather than ``verify_chain``: generating a
    report must not complete an interrupted append as a side effect. A
    compliance artifact is an observation, and an observation that mutates the
    thing observed is a bad instrument.
    """
    from .db import verify_chain_read_only

    try:
        result = verify_chain_read_only(conn, root=root)
    except Exception as exc:  # a broken chain is a finding, not a crash
        return {
            "chain": "unverifiable",
            "events_checked": 0,
            "first_bad_event": 0,
            "detail": str(exc)[:200],
        }
    return {
        "chain": "intact" if result.get("ok") else "broken",
        "events_checked": int(result.get("checked") or 0),
        "first_bad_event": int(result.get("first_bad") or 0),
        "detail": str(result.get("witness_error") or "")[:200],
    }


def _retention(span: dict, now: int) -> dict:
    """Measured coverage against the Article 19(1)/26(6) floor.

    Deliberately reports a measurement and a floor, never a verdict. A span
    shorter than six months is the expected state of an archive younger than
    six months, which is not a finding of non-compliance about anything.
    """
    lo = _parse_ts(span["earliest"]) if span["earliest"] else None
    hi = _parse_ts(span["latest"]) if span["latest"] else None
    if lo is None or hi is None:
        return {
            "floor_days": RETENTION_FLOOR_DAYS,
            "span_days": 0,
            "oldest_event_age_days": 0,
            "status": "no_events",
            "note": "the archive holds no event with a parseable timestamp",
        }
    span_days = max((hi - lo) // _DAY_SECONDS, 0)
    age_days = max((int(now) - lo) // _DAY_SECONDS, 0)
    if age_days >= RETENTION_FLOOR_DAYS:
        status = "retained_span_reaches_floor"
        note = (
            "the oldest event still present is at least the floor's age; with "
            "the chain intact, no event has been removed in that window"
        )
    else:
        status = "archive_younger_than_floor"
        note = (
            "the oldest event is younger than the floor; for an archive that "
            "has not yet existed six months this is expected and is not a "
            "finding of non-compliance"
        )
    return {
        "floor_days": RETENTION_FLOOR_DAYS,
        "span_days": int(span_days),
        "oldest_event_age_days": int(age_days),
        "status": status,
        "note": note,
    }


def _framing() -> dict:
    """The positioning block, stated in the artifact rather than around it."""
    return {
        "article_12": (
            "Logging capability. Requires that a high-risk AI system "
            "technically allow automatic recording of events over its "
            "lifetime. It is a design requirement on the system, not a "
            "retention period."
        ),
        "article_19_1": (
            "Provider retention. Logs automatically generated by the "
            "high-risk AI system, to the extent they are under the "
            "provider's control, kept for a period appropriate to the "
            "intended purpose and at least six months, unless other Union "
            "or national law provides otherwise."
        ),
        "article_26_6": (
            "Deployer retention. The same floor of at least six months and "
            "the same two limitations — logs under the deployer's control, "
            "displaceable by other Union or national law — binding the "
            "deployer instead of the provider."
        ),
        "append_only_is_not_required": (
            "The Regulation nowhere requires append-only or tamper-evident "
            "storage. An ordinary rotated log file can satisfy Articles 12, "
            "19(1) and 26(6). contextd's chain is one way to satisfy them "
            "and an evidentiary advantage — it makes 'these logs were not "
            "edited' checkable rather than asserted — not a legal mandate."
        ),
        "applicability": {
            "annex_iii_article_6_2": _iso(APPLICABILITY_ANNEX_III),
            "product_embedded_article_6_1": _iso(APPLICABILITY_PRODUCT_EMBEDDED),
        },
    }


def _limitations() -> list:
    """Travels with the artifact, because artifacts get separated from docs."""
    return [
        "This artifact contains no pass/fail verdict and is not legal advice.",
        "Whether the system is high-risk, and whether the operator is a "
        "provider or a deployer, are facts about the deployment that this "
        "archive cannot observe.",
        "Both retention articles are limited to logs under that party's "
        "control; logs held elsewhere are outside this archive and outside "
        "this measurement.",
        "The six-month floor is displaceable by other Union or national law, "
        "data-protection law in particular.",
        "Chain verification is tamper-evidence, not tamper-proofing: an "
        "owner-level process that recomputes every hash defeats it. See "
        "docs/SECURITY.md.",
        "Events appended since the last checkpoint are covered by local state "
        "alone; 'uncovered_events' is that window, and a checkpoint is silent "
        "about it.",
        "An event's presence evidences that it was recorded and not removed. "
        "It does not evidence that its content is true.",
    ]


def compliance_record(conn, *, now: int, root=None) -> dict:
    """Build the artifact. Pure in (archive state, ``now``).

    ``now`` has no default on purpose — see the module docstring.
    """
    if not isinstance(now, int) or isinstance(now, bool):
        raise ComplianceError("now must be an int (unix seconds)")
    from .backends import postgres_configured, table_names
    from .db import SCHEMA_VERSION, _db_tip

    tables = set(table_names(conn))
    if "events" not in tables:
        raise ComplianceError("archive has no events table")

    span = _event_span(conn)
    try:
        tip_id = int(_db_tip(conn)["id"])
    except Exception:
        tip_id = span["count"]

    record = {
        "report": {
            "kind": "contextd-eu-ai-act-logging-evidence",
            "version": REPORT_VERSION,
            "generated_at": _iso(now),
            "regulation": "Regulation (EU) 2024/1689 (EU AI Act)",
        },
        "archive": {
            "uuid": _archive_uuid(conn, tables),
            "backend": "postgres" if postgres_configured() else "sqlite",
            "schema_version": int(SCHEMA_VERSION),
            "record_format": "contextd-record-format v1",
            "events": span["count"],
            "earliest_event": span["earliest"],
            "latest_event": span["latest"],
            "tip_event_id": int(tip_id),
        },
        "retention": _retention(span, now),
        "integrity": _integrity(conn, root),
        "checkpoints": _checkpoint_coverage(conn, tables, tip_id),
        "framing": _framing(),
        "limitations": _limitations(),
    }
    # The digest covers everything above it. Canonical encoding refuses floats,
    # bools, and None, so a record that digests at all is also one a second
    # implementation can re-encode byte-identically (docs/FORMAT.md §3).
    record["report"]["digest"] = canonical_digest(REPORT_DOMAIN, record)
    return record


def render(record: dict) -> str:
    """Stable bytes for the artifact: sorted keys, two-space indent, one LF."""
    return json.dumps(record, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def compliance_report(conn, *, now: int, root=None) -> str:
    """The artifact as text. What ``ctx compliance`` prints."""
    return render(compliance_record(conn, now=now, root=root))
