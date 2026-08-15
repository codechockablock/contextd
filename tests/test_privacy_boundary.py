"""Credential canaries must not survive anywhere, and the schema must be closed.

Every test here corresponds to a supported claim in docs/SECURITY.md §4 and
fails against the pre-hardening tree. The canaries are planted literals of the
**pinned** classes in contextd/redact.py — this suite is not, and does not
claim to be, a test that arbitrary PII is removed.

The persistence surfaces checked are exactly those named in the Definition of
Done: event content, URI, serialized metadata, the SQLite file and its WAL and
SHM sidecars, the blob store, logs, error strings, `ctx audit` output, backup
manifests and bundles, and scratch/temp files.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from contextd import home, load_config
from contextd.backup import create_backup
from contextd.db import append_event, connect, store_blob
from contextd.gate import GateError, assemble, disclose, record_dispatch_outcome
from contextd.ingest import ingest_note
from contextd.redact import (
    FLOOR,
    redact,
    sanitize_content,
    sanitize_label,
    sanitize_text,
)
from contextd.schemas import SchemaError, validate_egress_meta, validate_event_meta

# One planted literal per pinned class. None was ever a valid credential.
CANARIES = {
    "api_key": "sk-canary0000000000zzz1",
    "openai_key": "sk-proj-canary0000000000zz",
    "anthropic_key": "sk-ant-canary0000000000zz",
    "google_api_key": "AIza" + "Canary" + "0" * 29,
    "aws_key": "AKIACANARY0000000000",
    "github_token": "ghp_canary0000000000000000000000000000",
    "slack_token": "xoxb-canary000000000-abc",
    "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjYW5hcnkiOnRydWV9.c2lnbmF0dXJl",
    "ssn": "123-45-6789",
    "card": "4111 1111 1111 1111",
    "bearer_header": "Authorization: Bearer canary000000000000000000",
    "basic_auth_url": "https://canaryuser:canarypass@example.invalid/",
    "password_assignment": "password=canarypassword123",
    "url_param": "https://example.invalid/cb?access_token=canary0000000000",
    "private_key": (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "Q0FOQVJZQ0FOQVJZQ0FOQVJZQ0FOQVJZQ0FOQVJZ\n"
        "-----END RSA PRIVATE KEY-----"
    ),
}

# The distinctive substring of each canary. A surface is dirty if any appears.
NEEDLES = [
    "canary0000000000zzz1", "AIzaCanary0000000000", "AKIACANARY0000000000",
    "ghp_canary000000000", "xoxb-canary000000000", "123-45-6789",
    "4111 1111 1111 1111", "canarypass", "canarypassword123",
    "Q0FOQVJZQ0FOQVJZ", "eyJjYW5hcnkiOnRydWV9",
]


def _assert_clean(blob: bytes | str, where: str) -> None:
    text = blob.decode("utf-8", errors="replace") if isinstance(blob, bytes) else blob
    for needle in NEEDLES:
        assert needle not in text, f"canary survived in {where}"


# --- the floor --------------------------------------------------------------

@pytest.mark.parametrize("name,canary", sorted(CANARIES.items()))
def test_every_pinned_class_is_redacted(name, canary):
    """Planted positive: each pinned class must be caught by the floor."""
    out = redact({}, f"before {canary} after")
    assert canary not in out, f"{name} passed the floor unredacted"
    assert "[REDACTED:" in out


def test_ordinary_text_is_not_mangled():
    """Negative control. A floor that redacts everything is useless; these
    strings look credential-adjacent and must survive intact."""
    for benign in (
        "the meeting is at 4pm in room 302",
        "commit 7a94e637b337 fixed the parser",
        "https://example.invalid/docs/getting-started?q=append+only",
        "sk- is the prefix convention",
        "card game night, bring 4 decks",
    ):
        assert redact({}, benign) == benign, benign


def test_config_cannot_weaken_the_floor():
    """The old contract let [gate.redact] replace the whole table. Under the
    current threat model whoever writes config.toml is the attacker."""
    hostile = {"gate": {"redact": {}}}
    assert CANARIES["api_key"] not in redact(hostile, CANARIES["api_key"])

    # even re-declaring a floor class under its own name cannot displace it
    shadow = {"gate": {"redact": {"api_key": r"THIS_MATCHES_NOTHING_XYZ"}}}
    assert CANARIES["api_key"] not in redact(shadow, CANARIES["api_key"])

    # ... and config CAN still add a class
    extended = {"gate": {"redact": {"internal": r"PROJECT-[0-9]{4}"}}}
    assert "PROJECT-1234" not in redact(extended, "see PROJECT-1234")


def test_config_pattern_names_and_errors_cannot_echo_secrets():
    secret_name = CANARIES["api_key"]
    valid = {"gate": {"redact": {secret_name: r"PROJECT-[0-9]{4}"}}}
    output = redact(valid, "PROJECT-1234")
    assert secret_name not in output and output == "[REDACTED:config.0]"

    invalid = {"gate": {"redact": {secret_name: "(" + secret_name}}}
    with pytest.raises(ValueError) as exc:
        redact(invalid, "ordinary")
    assert secret_name not in str(exc.value)


def test_floor_is_immutable_at_runtime():
    with pytest.raises(TypeError):
        FLOOR["api_key"] = "nope"          # type: ignore[index]
    with pytest.raises((TypeError, AttributeError)):
        FLOOR.pop("api_key")               # type: ignore[attr-defined]


def test_sanitizers_bound_and_redact():
    long_text = CANARIES["api_key"] + "x" * 10_000
    out = sanitize_text({}, long_text, max_len=100)
    assert len(out) <= 120 and CANARIES["api_key"] not in out
    label = sanitize_label({}, "client\x00name\n" + CANARIES["aws_key"])
    assert "\x00" not in label and "\n" not in label
    assert CANARIES["aws_key"] not in label and len(label) <= 64


def test_sanitizer_removes_terminal_control_families():
    hostile = "ok\x07\x1b]52;c;payload\x07\x1b[31mred\x9b32m\x80\u202edone"
    clean = sanitize_content({}, hostile)
    assert clean == "okreddone"
    assert not any(ord(ch) < 32 and ch not in "\t\n\r" for ch in clean)
    assert not any(0x7F <= ord(ch) <= 0x9F for ch in clean)


# --- closed schema ----------------------------------------------------------

def test_unknown_disclosure_field_is_refused_not_dropped():
    cfg = load_config()
    with pytest.raises(SchemaError) as exc:
        validate_egress_meta(cfg, {"type": "recall", "smuggled": "payload"})
    assert "smuggled" not in str(exc.value)


def test_unknown_disclosure_type_is_refused():
    with pytest.raises(SchemaError):
        validate_egress_meta(load_config(), {"type": "invented_type"})


def test_unknown_event_field_is_refused():
    with pytest.raises(SchemaError):
        validate_event_meta(load_config(), "note", "note", {"actor": "x", "extra": 1})


def test_unregistered_event_type_cannot_carry_metadata():
    with pytest.raises(SchemaError):
        validate_event_meta(load_config(), "invented", "kind", {"anything": 1})
    assert validate_event_meta(load_config(), "invented", "kind", {}) == {}


def test_schema_error_never_quotes_the_offending_value():
    """A refusal message is a log line and a display surface. Naming the field
    is necessary; echoing its value would move the secret into the error."""
    cfg = load_config()
    with pytest.raises(SchemaError) as exc:
        validate_egress_meta(cfg, {"type": "recall", "leak": CANARIES["api_key"]})
    _assert_clean(str(exc.value), "SchemaError message")


def test_nested_schema_errors_never_echo_attacker_keys_or_types():
    cfg = load_config()
    canary_key = CANARIES["api_key"]
    cases = [
        {"op": "add", "scope": {"global": True, canary_key: 1}},
        {"op": "add", "derivation": {canary_key: object()}},
    ]
    for meta in cases:
        with pytest.raises(SchemaError) as exc:
            validate_event_meta(cfg, "loop", "loop", meta)
        assert canary_key not in str(exc.value)
        assert "object" not in str(exc.value)


def test_nested_scope_strings_strip_terminal_sequences():
    out = validate_event_meta(
        load_config(),
        "loop",
        "loop",
        {"op": "add", "scope": {"repo": "/safe/\x1b[31mrepo"}},
    )
    assert out["scope"] == {"repo": "/safe/repo"}


def test_verbatim_derivation_quote_cannot_bypass_privacy_floor():
    meta = {
        "derivation": {
            "source_egress": 1,
            "support": [{"event": 1, "quote": CANARIES["api_key"]}],
        }
    }
    with pytest.raises(SchemaError) as exc:
        validate_event_meta(load_config(), "note", "note", meta)
    _assert_clean(str(exc.value), "derivation refusal")


def test_signed_attestation_strings_cannot_bypass_privacy_floor():
    block = {
        "action": {"reason": CANARIES["api_key"]},
        "signature": "00",
        "key_id": "a" * 64,
        "signer": "secure_enclave",
        "verified_at": "2026-08-15T00:00:00+00:00",
    }
    with pytest.raises(SchemaError) as exc:
        validate_event_meta(
            load_config(),
            "note",
            "note",
            {"assurance": "operator_authorized", "attestation": block},
        )
    _assert_clean(str(exc.value), "attestation refusal")


def test_disclose_refuses_undeclared_intent_and_appends_nothing():
    conn = connect()
    cfg = load_config()
    before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    with pytest.raises(SchemaError):
        disclose(conn, cfg, "payload", {"type": "recall", "exfil": "data"})
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == before


def test_outcome_details_channel_is_closed():
    """record_dispatch_outcome used to persist **details verbatim: that is how
    stderr and exception text reached the archive."""
    conn = connect()
    cfg = load_config()
    egress = disclose(conn, cfg, "x", {"type": "probe", "label": "outcome"})
    with pytest.raises(TypeError):
        record_dispatch_outcome(
            conn, egress["egress_id"], "failed", stderr=CANARIES["api_key"]
        )
    eid = record_dispatch_outcome(conn, egress["egress_id"], "failed", exit=1)
    meta = json.loads(
        conn.execute("SELECT meta FROM events WHERE id=?", (eid,)).fetchone()["meta"]
    )
    assert set(meta) == {"egress_id", "status", "exit"}


def test_raw_query_is_not_stored_and_correlates_by_keyed_id():
    conn = connect()
    cfg = load_config()
    ingest_note(conn, "an ordinary note about append-only ledgers")
    secret_query = f"ledgers {CANARIES['api_key']}"
    first = assemble(conn, cfg, secret_query, budget=2000, purpose="probe")
    second = assemble(conn, cfg, secret_query, budget=2000, purpose="probe")
    metas = [
        json.loads(
            conn.execute("SELECT meta FROM events WHERE id=?", (r["egress_id"],))
            .fetchone()["meta"]
        )
        for r in (first, second)
    ]
    for meta in metas:
        assert "query" not in meta, "the raw query is still being persisted"
        _assert_clean(json.dumps(meta), "recall egress meta")
    # same query -> same id, so correlation survives without the plaintext
    assert metas[0]["query_id"] == metas[1]["query_id"]
    other = assemble(conn, cfg, "a different query entirely", budget=2000)
    other_meta = json.loads(
        conn.execute("SELECT meta FROM events WHERE id=?", (other["egress_id"],))
        .fetchone()["meta"]
    )
    assert other_meta.get("query_id") != metas[0]["query_id"]


# --- persistence surfaces ---------------------------------------------------

def _plant_everything(conn, cfg):
    """Push a canary through every caller-reachable field the DoD names."""
    ingest_note(conn, f"note body {CANARIES['api_key']}")
    append_event(
        conn, "note", "note",
        uri=f"file:///tmp/{CANARIES['github_token']}.md",
        content=f"uri-bearing note {CANARIES['aws_key']}",
        meta={"actor": "human", "tags": [CANARIES["slack_token"]]},
    )
    store_blob(f"blob body {CANARIES['jwt']}".encode())
    assemble(
        conn, cfg, f"query {CANARIES['card']}", budget=2000,
        purpose=f"purpose {CANARIES['ssn']}", client=f"client-{CANARIES['api_key']}",
    )
    disclose(conn, cfg, f"payload {CANARIES['private_key']}", {
        "type": "checkpoint",
        "task_hint": f"hint {CANARIES['bearer_header']}",
        "purpose": f"why {CANARIES['password_assignment']}",
        "loop_scope": f"repo:/srv/{CANARIES['basic_auth_url']}",
        "staleness": {
            "nested": {
                "deep": [CANARIES["openai_key"], CANARIES["google_api_key"]]
            }
        },
    })
    from contextd.loops import add_loop, make_scope
    add_loop(
        conn,
        f"loop text {CANARIES['anthropic_key']}",
        make_scope("/srv/demo/privacy-floor"),
    )


def test_no_canary_survives_in_any_persistence_surface(tmp_path):
    conn = connect()
    cfg = load_config()
    _plant_everything(conn, cfg)

    for row in conn.execute("SELECT id, uri, content, meta FROM events"):
        for column in ("uri", "content", "meta"):
            _assert_clean(row[column] or "", f"events.{column} row {row['id']}")

    # audit output is a display surface
    audit = subprocess.run(
        [sys.executable, "-m", "contextd.cli", "audit"],
        capture_output=True, text=True, env={**os.environ, "CONTEXTD_HOME": str(home())},
    )
    _assert_clean(audit.stdout + audit.stderr, "ctx audit output")

    conn.close()  # flush WAL content into the checked files
    root = home()
    for path in sorted(root.rglob("*")):
        if path.is_file():
            _assert_clean(path.read_bytes(), f"file {path.relative_to(root)}")

    # backup bundle: manifest, database copy, and blobs
    conn = connect()
    bundle = create_backup(conn, home(), tmp_path / "bk")["bundle"]
    for path in sorted(Path(bundle).rglob("*")):
        if path.is_file():
            _assert_clean(path.read_bytes(), f"backup {path.name}")


def test_sqlite_sidecars_are_covered_by_the_sweep():
    """Guard against the sweep silently checking nothing: the WAL/SHM sidecars
    the DoD names must actually exist while the archive is open."""
    conn = connect()
    ingest_note(conn, "force a write so the WAL exists")
    names = {p.name for p in home().iterdir()}
    assert "contextd.db" in names
    assert {"contextd.db-wal", "contextd.db-shm"} & names, names
    conn.close()


def test_gate_refusal_error_carries_only_accounting():
    conn = connect()
    cfg = load_config()
    cfg["gate"]["daily_token_budget"] = 4
    disclose(conn, cfg, "x" * 8, {"type": "probe", "label": "fill"})
    with pytest.raises(GateError) as exc:
        disclose(conn, cfg, f"secret {CANARIES['api_key']}",
                 {"type": "probe", "label": "refused"})
    _assert_clean(str(exc.value), "GateError message")
