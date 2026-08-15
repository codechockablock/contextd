"""No caller-controlled string produces authenticated human/operator provenance.

The defect this suite pins: provenance used to be carried by
``CONTEXTD_CLIENT``, ``meta.actor``, ``meta.authority``, and ``meta.role``.
Every one of those is written by the caller, and under the current threat model
the caller is the attacker (docs/SECURITY.md §1). ``authority="operator"`` was
therefore the attacker asserting it was the operator.

Each test below fails against the pre-hardening tree.
"""

import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from contextd import attest, home, load_config
from contextd.assurance import (
    AUTHENTICATED_HUMAN,
    AssuranceError,
    INSECURE_TEST_SIGNER,
    LEGACY_UNVERIFIED,
    OPERATOR_AUTHORIZED,
    UNVERIFIED,
    assurance_of,
    is_authenticated_human,
)
from contextd.canonical import CanonicalError, canonical_bytes, canonical_digest
from contextd.db import append_event, connect
from contextd.decisions import record_supersession
from contextd.experiment import epistemic_type
from contextd.grants import add_grant
from contextd.ingest import ingest_note
from contextd.loops import LoopError, add_candidate, add_loop, make_scope, transition
from tests.authorization_support import operator
from tests.legacy_support import insert_legacy_event

VECTORS = Path(__file__).resolve().parent / "vectors" / "operator_action_v1.json"


def _events(conn):
    return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]


# --- caller strings establish nothing --------------------------------------

@pytest.mark.parametrize("label", ["human", "operator", "user", "owner", "admin"])
def test_no_caller_label_yields_authenticated_provenance(label):
    """CONTEXTD_CLIENT=human, actor=human, authority=operator, role=user."""
    for meta in (
        {"actor": label}, {"authority": label}, {"claimed_client": label},
        {"role": "user", "actor": label},
    ):
        assert not is_authenticated_human(meta), meta
        assert assurance_of(meta) not in AUTHENTICATED_HUMAN, meta


def test_contextd_client_human_is_only_a_redacted_label(monkeypatch):
    monkeypatch.setenv("CONTEXTD_CLIENT", "human")
    conn = connect()
    eid = ingest_note(conn, "a note", claimed_client="mcp")
    meta = json.loads(
        conn.execute("SELECT meta FROM events WHERE id=?", (eid,)).fetchone()["meta"]
    )
    assert meta["assurance"] == UNVERIFIED
    assert not is_authenticated_human(meta)


def test_domain_mutators_refuse_free_form_authority():
    conn = connect()
    with pytest.raises(AssuranceError):
        ingest_note(conn, "forged", actor="human")
    with pytest.raises(AssuranceError):
        transition(conn, 1, "close", authority="operator")


def test_direct_ingest_note_cannot_forge_operator_authority():
    conn = connect()
    eid = ingest_note(conn, "a direct call", claimed_client="anything")
    meta = json.loads(
        conn.execute("SELECT meta FROM events WHERE id=?", (eid,)).fetchone()["meta"]
    )
    assert meta["assurance"] == UNVERIFIED
    assert "attestation" not in meta


def test_epistemic_type_separates_claimed_from_attested():
    claimed = {"actor": "human"}
    assert epistemic_type("note", "note", claimed) == "claimed_human_assertion"
    assert epistemic_type("claude_code", "message", {"role": "user"}) \
        == "claimed_human_assertion"
    # Self-describing stored metadata is never enough to reach an attested
    # level; reducers must call verify_stored_authorization against the row.
    attested = {"actor": "human",
                "attestation": {"signer": attest.SIGNER_SECURE_ENCLAVE}}
    assert epistemic_type("note", "note", attested) == "claimed_human_assertion"
    # ... and the test signer never does
    testish = {"actor": "human", "attestation": {"signer": INSECURE_TEST_SIGNER}}
    assert epistemic_type("note", "note", testish) == "claimed_human_assertion"


def test_legacy_authority_rows_resolve_legacy_unverified():
    conn = connect()
    eid = insert_legacy_event(
        conn, "loop", "loop", content="an old operator loop",
        meta={"op": "add", "authority": "operator", "client": "cli"},
    )
    row = conn.execute("SELECT meta FROM events WHERE id=?", (eid,)).fetchone()
    meta = json.loads(row["meta"])
    assert assurance_of(meta) == LEGACY_UNVERIFIED
    assert not is_authenticated_human(meta)


# --- the signed object -----------------------------------------------------

def test_frozen_canonicalization_vectors_still_hold():
    """Any change to the encoding must break visibly, in both directions."""
    payload = json.loads(VECTORS.read_text())
    assert payload["domain"] == attest.DOMAIN
    for vector in payload["vectors"]:
        actual = canonical_bytes(attest.DOMAIN, vector["action"]).hex()
        assert actual == vector["canonical_hex"], vector["name"]
        assert canonical_digest(attest.DOMAIN, vector["action"]) == vector["digest"]


def test_canonicalization_refuses_floats_bools_and_unknown_types():
    for bad in ({"a": 1.5}, {"a": True}, {"a": None}, {"a": b"x"}, {1: "x"}):
        with pytest.raises(CanonicalError):
            canonical_bytes(attest.DOMAIN, bad)


def test_canonicalization_distinguishes_structures_that_json_would_blur():
    a = canonical_bytes(attest.DOMAIN, {"a": "1"})
    b = canonical_bytes(attest.DOMAIN, {"a": 1})
    assert a != b
    nested = canonical_bytes(attest.DOMAIN, {"a": {"b": "c"}})
    flat = canonical_bytes(attest.DOMAIN, {"a": "b", "c": ""})
    assert nested != flat
    # key order cannot change the bytes
    assert canonical_bytes(attest.DOMAIN, {"z": 1, "a": 2}) == \
        canonical_bytes(attest.DOMAIN, {"a": 2, "z": 1})


def test_unknown_or_missing_action_fields_are_refused():
    conn = connect()
    op = operator(conn)
    auth = op.authorize("note.deliberate", "global", content="x")
    for mutate in (
        lambda a: {**a, "extra": "field"},
        lambda a: {k: v for k, v in a.items() if k != "nonce"},
    ):
        with pytest.raises(attest.AttestationError):
            attest.verify_action(mutate(auth.action), auth.signature, conn=conn)


# --- every way a bad authorization must append nothing ---------------------

@pytest.mark.parametrize("field,value", [
    ("action", "grant.add"),
    ("scope", "repo:/elsewhere"),
    ("sequence", 999),
    ("issued_at", 1),
    ("expires_at", 2**31),
    ("archive_uuid", "0" * 32),
    ("key_id", "f" * 64),
    ("content_digest", "a" * 64),
    ("reason_digest", "b" * 64),
    ("nonce", "c" * 64),
])
def test_mutating_any_signed_field_appends_nothing(field, value):
    conn = connect()
    op = operator(conn)
    auth = op.authorize("note.deliberate", "global", content="the exact content")
    before = _events(conn)
    tampered = {**auth.action, field: value}
    with pytest.raises(attest.AttestationError):
        attest.verify_action(tampered, auth.signature, conn=conn)
    assert _events(conn) == before, f"mutating {field} still appended"


def test_wrong_key_appends_nothing():
    conn = connect()
    first = operator(conn, seed=b"key-one")
    second = operator(conn, seed=b"key-two")
    prepared = first.prepare("note.deliberate", scope="global", content="x")
    signature = second.sign(prepared["canonical"])  # signed by the wrong key
    before = _events(conn)
    with pytest.raises(attest.AttestationError):
        attest.verify_action(prepared["action"], signature, conn=conn)
    assert _events(conn) == before


def test_wrong_archive_appends_nothing(tmp_path, monkeypatch):
    conn = connect()
    op = operator(conn)
    auth = op.authorize("note.deliberate", "global", content="x")
    monkeypatch.setenv("CONTEXTD_HOME", str(tmp_path / "other-archive"))
    other = connect()
    before = _events(other)
    with pytest.raises(attest.AttestationError):
        attest.verify_action(auth.action, auth.signature, conn=other)
    assert _events(other) == before


def test_expired_and_future_authorizations_append_nothing():
    conn = connect()
    op = operator(conn)
    auth = op.authorize("note.deliberate", "global", content="x", ttl_seconds=60)
    with pytest.raises(attest.AttestationError):
        attest.verify_action(auth.action, auth.signature, conn=conn,
                             now=auth.action["expires_at"])
    with pytest.raises(attest.AttestationError):
        attest.verify_action(auth.action, auth.signature, conn=conn,
                             now=auth.action["issued_at"] - 3600)


def test_revoked_key_appends_nothing():
    conn = connect()
    op = operator(conn)
    auth = op.authorize("note.deliberate", "global", content="x")
    attest.revoke_key(op.key_id, conn=conn)
    before = _events(conn)
    with pytest.raises(attest.AttestationError):
        attest.verify_action(auth.action, auth.signature, conn=conn)
    assert _events(conn) == before


def test_authorization_for_one_act_is_not_redeemable_against_another():
    conn = connect()
    op = operator(conn)
    auth = op.authorize("note.deliberate", "global", content="the approved text")
    before = _events(conn)
    with pytest.raises(attest.AttestationError):
        attest.authorized_append(
            conn, "note", "note", auth, "note.deliberate", "global",
            content="a DIFFERENT text",
        )
    assert _events(conn) == before


def test_verified_authorization_is_deeply_immutable():
    conn = connect()
    auth = operator(conn).authorize(
        "archive.raw_read", "global", arguments={"event_id": 1}
    )
    with pytest.raises(TypeError):
        auth.action["action"] = "archive.backup"
    with pytest.raises(TypeError):
        auth.action["arguments"]["event_id"] = 2


def test_revocation_between_preflight_and_append_is_rechecked_atomically():
    conn = connect()
    op = operator(conn)
    auth = op.authorize("note.deliberate", "global", content="stale")
    attest.revoke_key(op.key_id, conn=conn)
    with pytest.raises(attest.AttestationError):
        attest.authorized_append(
            conn, "note", "note", auth, "note.deliberate", "global",
            content="stale",
        )
    assert conn.execute(
        "SELECT consumed_event FROM operator_nonces WHERE nonce = ?",
        (auth.nonce,),
    ).fetchone()["consumed_event"] is None


def test_replay_of_one_authorization_appends_once():
    conn = connect()
    op = operator(conn)
    auth = op.authorize("note.deliberate", "global", content="once only")
    first = attest.authorized_append(
        conn, "note", "note", auth, "note.deliberate", "global",
        content="once only",
    )
    assert first
    before = _events(conn)
    with pytest.raises(attest.AttestationError):
        attest.authorized_append(
            conn, "note", "note", auth, "note.deliberate", "global",
            content="once only",
        )
    assert _events(conn) == before


def test_concurrent_replay_yields_exactly_one_success():
    conn = connect()
    op = operator(conn)
    auth = op.authorize("note.deliberate", "global", content="contended")
    results, errors = [], []
    barrier = threading.Barrier(6)

    def attempt():
        own = connect()
        barrier.wait()
        try:
            results.append(attest.authorized_append(
                own, "note", "note", auth, "note.deliberate", "global",
                content="contended",
            ))
        except Exception as exc:            # noqa: BLE001 - recorded, then asserted
            errors.append(exc)
        finally:
            own.close()

    threads = [threading.Thread(target=attempt) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert len(results) == 1, f"{len(results)} appends from one authorization"
    assert len(errors) == 5
    rows = conn.execute(
        "SELECT COUNT(*) FROM events WHERE content = 'contended'"
    ).fetchone()[0]
    assert rows == 1


# --- test signer containment ------------------------------------------------

def test_test_signer_requires_explicit_mode(monkeypatch):
    monkeypatch.delenv(attest.TEST_MODE_ENV, raising=False)
    with pytest.raises(attest.AttestationError) as exc:
        attest.load_test_signer(b"nope")
    assert "test-only" in str(exc.value)


def test_test_signer_refuses_a_non_temporary_archive(monkeypatch, tmp_path):
    """The second condition: a test key must never sign against a real archive."""
    fake_home = Path.home() / ".contextd-not-a-temp-dir"
    monkeypatch.setenv("CONTEXTD_HOME", str(fake_home))
    monkeypatch.setenv(attest.TEST_MODE_ENV, "1")
    with pytest.raises(attest.AttestationError) as exc:
        attest.load_test_signer(b"nope")
    assert "isolated temporary archive" in str(exc.value)


def test_test_signed_events_are_never_operator_authorized():
    conn = connect()
    op = operator(conn)
    auth = op.authorize("note.deliberate", "global", content="marked")
    assert auth.assurance == INSECURE_TEST_SIGNER
    assert auth.assurance != OPERATOR_AUTHORIZED
    eid = attest.authorized_append(
        conn, "note", "note", auth, "note.deliberate", "global", content="marked",
    )
    meta = json.loads(
        conn.execute("SELECT meta FROM events WHERE id=?", (eid,)).fetchone()["meta"]
    )
    assert meta["assurance"] == INSECURE_TEST_SIGNER
    assert not is_authenticated_human(meta)
    assert meta["attestation"]["signer"] == INSECURE_TEST_SIGNER


def test_stored_authorization_requires_crypto_nonce_binding_and_exact_semantics():
    conn = connect()
    op = operator(conn)
    auth = op.authorize("note.deliberate", "global", content="bound")
    event_id = attest.authorized_append(
        conn, "note", "note", auth, "note.deliberate", "global",
        content="bound",
    )
    row = conn.execute(
        "SELECT id, ts, content, meta FROM events WHERE id = ?", (event_id,)
    ).fetchone()
    assert attest.verify_stored_authorization(
        conn, row, action="note.deliberate", scope="global", content="bound"
    ) is not None
    assert attest.verify_stored_authorization(
        conn, row, action="note.deliberate", scope="global", content="changed"
    ) is None

    forged_meta = json.loads(row["meta"])
    forged_meta["attestation"]["signature"] = "00"
    forged = {"id": row["id"], "ts": row["ts"], "content": row["content"],
              "meta": json.dumps(forged_meta)}
    assert attest.verify_stored_authorization(
        conn, forged, action="note.deliberate", content="bound"
    ) is None


def test_control_sequences_bind_to_exact_sanitized_persisted_content():
    conn = connect()
    raw = "approve \x1b[31mred\x1b[0m\x07 text"
    stored = "approve red text"
    auth = operator(conn).authorize(
        "note.deliberate", "global", content=raw
    )
    assert auth.action["content_digest"] == hashlib.sha256(
        stored.encode()
    ).hexdigest()
    event_id = attest.authorized_append(
        conn, "note", "note", auth, "note.deliberate", "global", content=raw
    )
    row = conn.execute(
        "SELECT id, ts, content, meta FROM events WHERE id = ?", (event_id,)
    ).fetchone()
    assert row["content"] == stored
    assert attest.verify_stored_authorization(
        conn, row, action="note.deliberate", content=stored
    ) is not None


def test_software_keys_cannot_be_registered_in_production_mode(monkeypatch):
    conn = connect()
    op = operator(conn)
    der = attest.public_der(op.private)
    monkeypatch.delenv(attest.TEST_MODE_ENV, raising=False)
    with pytest.raises(attest.AttestationError):
        attest.register_key(der, attest.SIGNER_TEST, conn=conn)


def test_ed25519_is_not_accepted_as_a_p256_substitute():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    conn = connect()
    der = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(attest.AttestationError) as exc:
        attest.register_key(der, attest.SIGNER_TEST, conn=conn)
    assert "P-256" in str(exc.value)


# --- domain paths -----------------------------------------------------------

def test_loop_add_requires_an_authorization_covering_that_exact_loop():
    conn = connect()
    scope = make_scope("/srv/demo/ledgerd")
    op = operator(conn)
    wrong = op.authorize("loop.add", "repo:/srv/demo/ledgerd", content="other text")
    before = _events(conn)
    with pytest.raises(attest.AttestationError):
        add_loop(conn, "the real text", scope, authorization=wrong)
    assert _events(conn) == before

    right = op.authorize("loop.add", "repo:/srv/demo/ledgerd", content="the real text")
    result = add_loop(conn, "the real text", scope, authorization=right)
    assert result["result"] == "created"
    assert result["loop"]["created_assurance"] == INSECURE_TEST_SIGNER


def test_loop_transition_without_authorization_or_grant_refuses():
    conn = connect()
    scope = make_scope("/srv/demo/ledgerd")
    cand = add_candidate(conn, "a proposal", scope)["loop"]
    from contextd import attest as attest_module
    original = attest_module.test_mode_authorization

    def refuse(*_a, **_k):
        raise attest_module.AttestationError("no signer in this scenario")

    attest_module.test_mode_authorization = refuse
    try:
        before = _events(conn)
        with pytest.raises(LoopError) as exc:
            transition(conn, cand["id"], "confirm")
        assert "operator act" in str(exc.value)
        assert _events(conn) == before
    finally:
        attest_module.test_mode_authorization = original


def test_grant_and_decision_paths_record_resolved_assurance():
    conn = connect()
    a = append_event(conn, "note", "note", content="old decision",
                     meta={"claimed_client": "cli"})
    b = append_event(conn, "note", "note", content="new decision",
                     meta={"claimed_client": "cli"})
    grant = add_grant(conn, "decision.supersede", {"global": True},
                      expires=(datetime.now(timezone.utc)
                               + timedelta(hours=8)).isoformat(timespec="seconds"))
    assert grant["result"] == "created"
    edge = record_supersession(conn, a, b, grant=grant["grant"]["id"])
    meta = json.loads(
        conn.execute("SELECT meta FROM events WHERE id=?",
                     (edge["edge"]["edge"],)).fetchone()["meta"]
    )
    # a delegated act stays delegated; it never upgrades to operator-signed
    assert assurance_of(meta) == "model_granted"
    assert not is_authenticated_human(meta)


# --- process boundary -------------------------------------------------------

def test_a_separate_process_cannot_mint_authority_from_the_environment():
    """The whole point, exercised the way an attacker would try it."""
    script = (
        "import json, os, sys\n"
        "sys.path.insert(0, %r)\n"
        "from contextd.db import connect\n"
        "from contextd.ingest import ingest_note\n"
        "from contextd.assurance import AssuranceError, is_authenticated_human\n"
        "conn = connect()\n"
        "refused = False\n"
        "try:\n"
        "    ingest_note(conn, 'hostile', claimed_client='human')\n"
        "except AssuranceError:\n"
        "    refused = True\n"
        "eid = ingest_note(conn, 'hostile note', claimed_client='some-agent')\n"
        "meta = json.loads(conn.execute('SELECT meta FROM events WHERE id=?',\n"
        "                               (eid,)).fetchone()['meta'])\n"
        "print(json.dumps({'authenticated': is_authenticated_human(meta),\n"
        "                  'assurance': meta.get('assurance'),\n"
        "                  'human_label_refused': refused}))\n"
    ) % str(Path(__file__).resolve().parent.parent)
    env = {
        **os.environ,
        "CONTEXTD_HOME": str(home()),
        "CONTEXTD_CLIENT": "human",
        "CONTEXTD_DERIVATION_SOURCE": "1",
    }
    result = subprocess.run([sys.executable, "-c", script],
                            capture_output=True, text=True, env=env, timeout=120)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload["authenticated"] is False
    assert payload["assurance"] == UNVERIFIED
    # claiming to be "human" is not merely ineffective, it is refused outright
    assert payload["human_label_refused"] is True


def test_nonce_cannot_be_self_minted():
    """An attacker who fabricates a whole action still has no issued nonce."""
    conn = connect()
    op = operator(conn)
    prepared = op.prepare("note.deliberate", scope="global", content="x")
    forged = {**prepared["action"], "nonce": "0" * 64}
    signature = op.sign(canonical_bytes(attest.DOMAIN, forged).hex())
    with pytest.raises(attest.AttestationError) as exc:
        attest.verify_action(forged, signature, conn=conn)
    assert "not issued by this archive" in str(exc.value)


def test_prepared_action_expires_and_cannot_be_stockpiled():
    conn = connect()
    op = operator(conn)
    with pytest.raises(attest.AttestationError):
        op.authorize("note.deliberate", "global", content="x",
                     ttl_seconds=attest.MAX_TTL_SECONDS + 1)
    auth = op.authorize("note.deliberate", "global", content="x", ttl_seconds=1)
    time.sleep(1.1)
    with pytest.raises(attest.AttestationError):
        attest.verify_action(auth.action, auth.signature, conn=conn)


def test_no_production_signer_means_no_operator_authorized_event():
    """The strongest honest claim when the hardware signer is absent."""
    conn = connect()
    op = operator(conn)
    auth = op.authorize("note.deliberate", "global", content="x")
    assert auth.assurance != OPERATOR_AUTHORIZED
    keys = attest.registered_keys(conn)
    assert all(k["signer"] != attest.SIGNER_SECURE_ENCLAVE for k in keys)
    rows = conn.execute(
        "SELECT meta FROM events WHERE json_extract(meta,'$.assurance') = ?",
        (OPERATOR_AUTHORIZED,),
    ).fetchall()
    assert rows == [], "an operator_authorized event exists with no hardware key"


def test_config_and_env_cannot_name_a_signer(monkeypatch):
    """No file-key, env-key, HMAC, TTY, or parent-process fallback exists."""
    source = (Path(__file__).resolve().parent.parent / "contextd" / "attest.py").read_text()
    # code constructs, not prose: the refusal message legitimately *names* the
    # fallbacks that do not exist
    code = "\n".join(
        line for line in source.splitlines()
        if not line.lstrip().startswith(("#", '"', "'"))
    )
    for forbidden in ("import hmac", "hmac.", "isatty", "getppid",
                      "os.ttyname", "input("):
        assert forbidden not in code, f"attest.py uses {forbidden}"
    cfg = load_config()
    assert "signer" not in json.dumps(cfg).lower()
