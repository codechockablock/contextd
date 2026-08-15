"""The development-mode first-key bootstrap boundary.

The hardened ceremony (docs/OPERATOR_CEREMONY.md) requires the _contextd
service account, which a development machine does not have — and without a
first key every operator act refuses. These tests pin the substitute
boundary: development bootstrap works exactly once, against a privately-moded
archive owned by the invoking uid, never on a hardened archive, and the
hardened path's own refusals are unchanged by its existence.
"""

import os

import pytest

from contextd.attest import AttestationError, bootstrap_key
from contextd.db import connect, home


def _p256_der() -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def test_development_bootstrap_enrolls_once_then_closes_forever():
    conn = connect()
    kid = bootstrap_key(
        _p256_der(), "default", conn=conn,
        acknowledge_first_key=True, development=True,
    )
    row = conn.execute(
        "SELECT signer, revoked FROM operator_keys WHERE key_id = ?", (kid,)
    ).fetchone()
    assert row is not None and row["revoked"] is None

    with pytest.raises(AttestationError, match="permanently closed"):
        bootstrap_key(
            _p256_der(), "default", conn=conn,
            acknowledge_first_key=True, development=True,
        )


def test_development_bootstrap_requires_the_acknowledgement_flag():
    conn = connect()
    with pytest.raises(AttestationError, match="acknowledge-first-key"):
        bootstrap_key(_p256_der(), "default", conn=conn, development=True)


def test_development_bootstrap_refuses_a_hardened_archive(monkeypatch):
    import contextd.authd

    conn = connect()
    monkeypatch.setattr(contextd.authd, "hardened", lambda: True)
    with pytest.raises(AttestationError, match="configured hardened"):
        bootstrap_key(
            _p256_der(), "default", conn=conn,
            acknowledge_first_key=True, development=True,
        )


def test_development_bootstrap_refuses_an_open_archive():
    conn = connect()
    os.chmod(home(), 0o775)  # group-writable: the boundary must refuse
    try:
        with pytest.raises(AttestationError, match="too broad"):
            bootstrap_key(
                _p256_der(), "default", conn=conn,
                acknowledge_first_key=True, development=True,
            )
    finally:
        os.chmod(home(), 0o700)


def test_hardened_bootstrap_path_is_unchanged():
    # without the development flag, the service-admin boundary still governs:
    # outside a service process this refuses before touching anything
    conn = connect()
    with pytest.raises(AttestationError, match="out-of-band"):
        bootstrap_key(
            _p256_der(), "default", conn=conn, acknowledge_first_key=True,
        )
