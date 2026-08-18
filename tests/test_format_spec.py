"""`docs/FORMAT.md` is checked against the code, not trusted.

The format spec exists so an adjudicator in 2035 can parse a record written
today without this codebase. That promise is worthless if the document drifts
from the implementation, and documentation drifts silently by default. So the
load-bearing constants in the spec are asserted here against their sources: a
change to the chain hash, a domain separator, a TTL, the closed action
registry, or the schema version breaks this file, and whoever makes that change
has to update the document in the same commit.

Two of these tests are stronger than string-matching. `test_the_documented_
chain_hash_recipe_reproduces_a_real_row` reimplements §2 from the document's
own prose and checks the result against a row the real appender wrote, and
`test_the_documented_canonical_rules_reproduce_the_frozen_vectors` does the
same for §3 against the frozen vectors. If the document's recipe is wrong,
those fail even if every constant still matches.
"""

import hashlib
import json
import re
import struct
from pathlib import Path

import pytest

from contextd import attest, ledger_sig, schemas
from contextd.canonical import canonical_bytes
from contextd.db import (
    MAX_RECOVERY_OUTCOMES,
    SCHEMA_VERSION,
    SUPPORTED_STATE_VERSIONS,
    WITNESS_VERSION,
    _chain_hash,
    connect,
)
from contextd.ingest import ingest_note

SPEC = Path(__file__).resolve().parents[1] / "docs" / "FORMAT.md"


@pytest.fixture(scope="module")
def spec_text():
    assert SPEC.exists(), "docs/FORMAT.md is missing"
    return SPEC.read_text()


# --- the spec's identity ----------------------------------------------------


def test_the_spec_declares_its_identifier_and_the_schema_version_it_describes(
    spec_text,
):
    assert "contextd-record-format v1" in spec_text
    assert f"**Archive schema version:** {SCHEMA_VERSION}" in spec_text


def test_the_spec_declares_a_document_revision_distinct_from_the_format(
    spec_text,
):
    """Revision 2 added §11 and two vocabulary entries and changed no bytes.

    The three version numbers in the header answer different questions and the
    document says which is which — the format identifier is what a parser keys
    on, the schema version is the DDL, and the revision is this document. A
    change that moved the wrong one would mislead exactly the reader this file
    exists for.
    """
    assert "**Document revision:** 2" in spec_text
    assert "an archive written before revision 2 parses identically" in spec_text


def test_the_compliance_export_names_the_same_format_identifier():
    """A reader handed only the compliance artifact must be able to find the
    document that tells them how to parse the archive it describes."""
    from contextd.compliance import compliance_record

    conn = connect()
    ingest_note(conn, "format spec fixture")
    record = compliance_record(conn, now=1787054400)
    assert record["archive"]["record_format"] == "contextd-record-format v1"
    assert record["archive"]["schema_version"] == SCHEMA_VERSION


# --- §2 the chain hash ------------------------------------------------------


def test_the_documented_chain_hash_recipe_reproduces_a_real_row():
    """Reimplement §2 from the document's prose and check it against a row the
    real appender wrote. This is the test that catches a wrong recipe."""
    conn = connect()
    ingest_note(conn, "chain recipe fixture one")
    ingest_note(conn, "chain recipe fixture two")

    prev = ""
    rows = conn.execute(
        "SELECT id, ts, source, kind, uri, content, content_hash, meta, "
        "prev_hash, chain_hash FROM events ORDER BY id"
    ).fetchall()
    assert rows, "fixture produced no events"

    for row in rows:
        # nine fields, each terminated by 0x1F, NULL as "", id as decimal
        digest = hashlib.sha256()
        for part in (
            prev,
            str(row["id"]),
            row["ts"],
            row["source"],
            row["kind"],
            row["uri"] or "",
            row["content"] or "",
            row["content_hash"] or "",
            row["meta"] or "",
        ):
            digest.update(part.encode("utf-8"))
            digest.update(b"\x1f")
        computed = digest.hexdigest()

        assert (row["prev_hash"] or "") == prev
        assert row["chain_hash"] == computed
        assert re.fullmatch(r"[0-9a-f]{64}", computed)
        prev = row["chain_hash"]


def test_the_separator_is_a_terminator_not_a_delimiter():
    """Documented as terminating *every* field including the last. If it were
    a delimiter, dropping the trailing one would still hash the same."""
    args = ("", 1, "2026-01-01T00:00:00+00:00", "note", "note", None, "x", None, None)
    parts = ["", "1", "2026-01-01T00:00:00+00:00", "note", "note", "", "x", "", ""]
    with_trailing = hashlib.sha256()
    for part in parts:
        with_trailing.update(part.encode())
        with_trailing.update(b"\x1f")
    assert _chain_hash(*args) == with_trailing.hexdigest()

    without_trailing = hashlib.sha256(b"\x1f".join(p.encode() for p in parts))
    assert _chain_hash(*args) != without_trailing.hexdigest()


# --- §3 canonical encoding --------------------------------------------------


def test_the_documented_canonical_rules_reproduce_the_frozen_vectors():
    """Reimplement §3 from the document and check against the frozen vectors."""
    vectors = json.loads(
        (Path(__file__).resolve().parents[1]
         / "tests" / "vectors" / "operator_action_v1.json").read_text()
    )

    def enc(value):
        if isinstance(value, bool) or value is None or isinstance(value, float):
            raise AssertionError("refused type reached the encoder")
        if isinstance(value, str):
            raw = value.encode("utf-8")
            return b"s" + struct.pack(">Q", len(raw)) + raw
        if isinstance(value, int):
            return b"i" + struct.pack(">q", value)
        if isinstance(value, list):
            return b"l" + struct.pack(">Q", len(value)) + b"".join(
                enc(v) for v in value
            )
        if isinstance(value, dict):
            items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-8"))
            return b"m" + struct.pack(">Q", len(items)) + b"".join(
                enc(k) + enc(v) for k, v in items
            )
        raise AssertionError(f"unhandled {type(value)}")

    domain = vectors["domain"]
    assert domain == attest.DOMAIN
    checked = 0
    for vector in vectors["vectors"]:
        act = vector["action"] if "action" in vector else vector["act"]
        mine = domain.encode("utf-8") + b"\n" + enc(act)
        assert mine.hex() == vector["canonical_hex"], "documented rules diverged"
        assert hashlib.sha256(mine).hexdigest() == vector["digest"]
        checked += 1
    assert checked, "no vectors exercised"


def test_the_spec_lists_every_action_field_and_gets_the_count_right(spec_text):
    for field in attest.ACTION_FIELDS:
        assert f"| `{field}` |" in spec_text, f"§4 omits {field}"
    # the spec calls out that the source comment's "twelve" is wrong
    assert len(attest.ACTION_FIELDS) == 13
    assert "thirteen keys" in spec_text


def test_the_spec_lists_every_intent_field(spec_text):
    for field in attest.INTENT_FIELDS:
        assert f"`{field}`" in spec_text


def test_the_spec_records_the_real_ttls(spec_text):
    assert f"Default {attest.DEFAULT_TTL_SECONDS} s" in spec_text
    assert f"maximum {attest.MAX_TTL_SECONDS} s" in spec_text
    assert str(attest.DEFAULT_REPLAY_TTL_SECONDS) in spec_text
    assert "86 400" in spec_text and attest.MAX_REPLAY_TTL_SECONDS == 86_400


def test_the_spec_lists_the_whole_closed_action_registry(spec_text):
    for action in attest.ACTION_CLASSES:
        assert f"`{action}`" in spec_text, f"§4 omits action class {action}"


def test_the_spec_lists_the_stored_attestation_fields(spec_text):
    for field in attest.ATTESTATION_FIELDS:
        assert f"`{field}`" in spec_text


# --- §5 signing domains and algorithms --------------------------------------


def test_every_signing_domain_appears_in_the_spec(spec_text):
    for domain in (
        attest.DOMAIN,
        attest.INTENT_DOMAIN,
        ledger_sig.ENVELOPE_DOMAIN,
        ledger_sig.TIP_DOMAIN,
        ledger_sig.CHECKPOINT_DOMAIN,
    ):
        assert f"`{domain}`" in spec_text, f"undocumented domain {domain}"


def test_the_domains_are_all_distinct():
    domains = [
        attest.DOMAIN, attest.INTENT_DOMAIN, ledger_sig.ENVELOPE_DOMAIN,
        ledger_sig.TIP_DOMAIN, ledger_sig.CHECKPOINT_DOMAIN,
    ]
    assert len(set(domains)) == len(domains)


def test_every_supported_algorithm_appears_in_the_spec(spec_text):
    for alg in ledger_sig.SUPPORTED_ALGS:
        assert f"`{alg}`" in spec_text, f"undocumented algorithm {alg}"


def test_the_documented_checkpoint_payload_matches_the_implementation():
    """§5's asymmetry claim: the classical payload has four fields and omits
    `alg`; every other scheme adds it as a fifth."""
    classical = ledger_sig.checkpoint_payload(
        "uuid", 7, "a" * 64, "k1", ledger_sig.CLASSICAL_ALG
    )
    assert set(classical) == {"archive_uuid", "tip_id", "chain_hash", "key_id"}
    assert ledger_sig.checkpoint_payload("uuid", 7, "a" * 64, "k1", None) == classical

    pq = ledger_sig.checkpoint_payload(
        "uuid", 7, "a" * 64, "k1", ledger_sig.ALG_MLDSA_44
    )
    assert set(pq) == set(classical) | {"alg"}
    # length-prefixed field counts make the two messages non-colliding
    assert canonical_bytes(ledger_sig.CHECKPOINT_DOMAIN, classical) != canonical_bytes(
        ledger_sig.CHECKPOINT_DOMAIN, pq
    )


def test_the_documented_tip_payload_matches_the_implementation():
    assert set(ledger_sig.tip_payload("uuid", 3, "b" * 64)) == {
        "archive_uuid", "tip_id", "chain_hash"
    }


# --- §6 witness and recovery journal ----------------------------------------


def test_the_spec_records_the_witness_and_journal_versions(spec_text):
    assert f'"version": {WITNESS_VERSION}' in spec_text
    assert WITNESS_VERSION == 2
    assert set(SUPPORTED_STATE_VERSIONS) == {1, 2}
    assert f"1..{MAX_RECOVERY_OUTCOMES}" in spec_text


def test_the_spec_names_the_three_chain_state_files(spec_text):
    from contextd.db import chain_state_paths

    for path in chain_state_paths(Path("/x")).values():
        assert path.name in spec_text, f"undocumented state file {path.name}"


# --- §7 the closed vocabulary -----------------------------------------------


def test_every_registered_event_type_appears_in_the_spec(spec_text):
    for source, kind in schemas.EVENT_SCHEMAS:
        assert f"({source}, {kind})" in spec_text, (
            f"§7 omits the registered event type ({source}, {kind})"
        )


def test_every_ingest_type_appears_in_the_spec(spec_text):
    for source, kind in schemas.INGEST_SCHEMAS:
        assert kind in spec_text, f"§7 omits ingest kind {kind}"


def test_the_spec_lists_the_closed_refusal_and_pin_vocabularies(spec_text):
    for reason in schemas.REFUSAL_REASONS:
        assert f"`{reason}`" in spec_text
    for reason in schemas.PIN_REFUSAL_REASONS:
        assert f"`{reason}`" in spec_text
    for kind in schemas.PIN_ARTIFACT_KINDS:
        assert f"`{kind}`" in spec_text
    for status in schemas.PIN_STATUSES:
        assert f"`{status}`" in spec_text


def test_the_spec_lists_every_field_kind(spec_text):
    for kind in (
        "ident", "text", "keyed", "int", "number", "bool", "int_list",
        "str_list", "digest", "scope", "scope_obj", "instant", "enum",
        "json", "derivation", "attestation", "artifact",
    ):
        assert f"`{kind}`" in spec_text, f"§7 omits field kind {kind}"


# --- §9 stated omissions ----------------------------------------------------


# --- §11 the exported checkpoint log ----------------------------------------


def test_the_spec_documents_the_exported_checkpoint_log_envelope(spec_text):
    """§11's envelope keys and version, checked against the implementation."""
    section = spec_text.split("## 11. The exported checkpoint log")[1]
    for key in ledger_sig.CHECKPOINT_LOG_ENVELOPE:
        assert f"`{key}`" in section, f"§11 omits envelope key {key}"
    assert f"currently `{ledger_sig.CHECKPOINT_LOG_VERSION}`" in section
    assert "JSON Lines" in section


def test_the_spec_records_that_the_export_timestamp_is_unsigned(spec_text):
    """The single most over-readable field in the format.

    `exported_at` is outside `checkpoint_payload` — §5's payload is frozen — so
    it is not evidence of when anything happened, and the document has to say
    so where a reader will meet it.
    """
    section = spec_text.split("## 11. The exported checkpoint log")[1]
    assert "**Unsigned" in section
    assert "`exported_at` is unauthenticated" in section
    assert "not evidence of when anything happened" in section
    # and the implementation agrees: the signed payload has no timestamp
    payload = ledger_sig.checkpoint_payload("uuid", 1, "a" * 64, "k")
    assert "exported_at" not in payload and "v" not in payload


def test_the_spec_states_the_exported_logs_advisory_scope(spec_text):
    """The honest-scope paragraph is load-bearing and must match the code.

    `checkpoint_log_claim` returns the same limitations as data; if the
    document and the claim drift, one of them is lying to an operator.
    """
    section = spec_text.split("## 11. The exported checkpoint log")[1]
    assert "advisory" in section.lower()
    assert "another host" in section
    claim = ledger_sig.checkpoint_log_claim()
    assert "ADVISORY" in claim["advisory_on_one_machine"]
    for fragment in ("truncated", "older than the first exported checkpoint"):
        assert fragment in section, f"§11 does not disclaim {fragment}"
    # every record must be checked, not only the newest — the whole point
    assert "Every record must be checked, not just the newest" in section


def test_the_spec_documents_the_refusal_cap_as_a_floor_not_a_total(spec_text):
    """A reader counting `tx/refuse` rows must know the count is capped.

    Without this, an adjudicator would read "8 refusals" as "8 attempts",
    which is exactly wrong: attempts are unbounded and only the record is
    capped.
    """
    from contextd import attest

    assert f"default {attest.DEFAULT_MAX_REFUSALS_PER_NONCE}" in spec_text
    assert attest.REFUSAL_CAP_KEY in spec_text
    assert "count as a floor, not a total" in spec_text


def test_the_spec_distinguishes_an_attested_resolution_from_an_observed_one(
    spec_text,
):
    """`(mandate, resolve)` is an assertion about the world; `(tx, execute)` is
    contextd's own observation. Conflating them is the misreading this section
    exists to prevent."""
    from contextd import attest

    assert f'`{attest.RESOLVED_BY_OPERATOR}`' in spec_text or \
        f'"{attest.RESOLVED_BY_OPERATOR}"' in spec_text
    assert "mandate_nonce" in spec_text
    assert "assertion about the world" in spec_text
    for status in attest.RESOLUTION_STATUSES:
        assert f"`{status}`" in spec_text


# --- §9 stated omissions (continued) ----------------------------------------


def test_the_spec_states_what_it_does_not_cover(spec_text):
    omissions = spec_text.split("## 9. What this format does NOT specify")[1]
    for topic in (
        "PostgreSQL wire and storage details",
        "Egress payload schemas",
        "blob store layout",
        "Backup bundle",
        "Secure Enclave",
        "FTS5 index",
    ):
        assert topic in omissions, f"§9 does not disclaim {topic}"
