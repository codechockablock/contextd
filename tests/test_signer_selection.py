"""Choosing which enrolled key signs an operator act.

The default — most recently registered active key — silently breaks once a
spare is enrolled on a second device, because an Enclave handle is
device-bound and cannot travel (docs/SECURITY.md §8). These tests pin the
override, its precedence, and the refusal that names the remedy instead of
leaving the operator with a bare "no Secure Enclave key for tag".

Selection is not authorization: every candidate here is a key the registry
already trusts, and using any of them still costs a presence gesture.
"""

import pytest

from contextd import cli

KEYS = [
    {"key_id": "aaaa1111" + "0" * 56, "signer_tag": "default", "signer": "se"},
    {"key_id": "bbbb2222" + "0" * 56, "signer_tag": "spare", "signer": "se"},
]


def test_default_is_the_most_recently_registered_key():
    assert cli._select_signer(KEYS, "")["signer_tag"] == "spare"


def test_selects_by_enrollment_tag():
    assert cli._select_signer(KEYS, "default")["key_id"] == KEYS[0]["key_id"]
    assert cli._select_signer(KEYS, "spare")["key_id"] == KEYS[1]["key_id"]


def test_selects_by_key_id_prefix():
    """Either column of `ctx security key list` is a usable handle."""
    assert cli._select_signer(KEYS, "aaaa1111")["signer_tag"] == "default"


def test_unknown_key_refuses_and_names_what_is_available():
    with pytest.raises(SystemExit) as excinfo:
        cli._select_signer(KEYS, "offsite")
    message = str(excinfo.value)
    assert "no active operator key matches" in message
    # the refusal has to be actionable: both real tags, and how to pick one
    assert "default" in message and "spare" in message
    assert "--signer-key" in message


def test_selection_is_per_act_and_never_ambient(monkeypatch):
    """The flag is the only source. Config deliberately cannot name a signer —
    test_config_and_env_cannot_name_a_signer keeps signer semantics off the
    config surface, so this knob stays non-ambient."""
    import json

    from contextd import DEFAULTS

    monkeypatch.setattr(cli, "_SIGNER_KEY_FLAG", "")
    assert cli._signer_choice() == ""

    # even a config that tries to name one is ignored: nothing reads it
    cli.home().mkdir(parents=True, exist_ok=True)
    (cli.home() / "config.toml").write_text(
        '[security]\nsigner_key = "default"\n'
    )
    assert cli._signer_choice() == "", "config must not select a signer"
    assert "signer" not in json.dumps(DEFAULTS).lower()

    monkeypatch.setattr(cli, "_SIGNER_KEY_FLAG", "spare")
    assert cli._signer_choice() == "spare"


def test_missing_local_handle_explains_the_device_binding(monkeypatch):
    """The second-device failure mode gets the remedy, not just the error."""
    from contextd.attest import AttestationError

    monkeypatch.setattr("contextd.attest.local_signer_tags", lambda: ["default"])
    message = cli._signing_failure(
        AttestationError("signer refused or was cancelled: no Secure Enclave "
                         "key for tag offsite"),
        "offsite",
    )
    assert "device-bound and cannot be copied" in message
    assert "handles on this machine: default" in message
    assert "--signer-key" in message


def test_unrelated_signing_failures_are_not_reinterpreted(monkeypatch):
    """A cancelled prompt is not a missing-handle problem and must not claim to be."""
    from contextd.attest import AttestationError

    monkeypatch.setattr("contextd.attest.local_signer_tags",
                        lambda: pytest.fail("must not be consulted"))
    message = cli._signing_failure(
        AttestationError("signer refused or was cancelled: userCancel"), "spare"
    )
    assert "userCancel" in message
    assert "device-bound" not in message
