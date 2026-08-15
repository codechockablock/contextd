"""Mint verified operator authorizations inside tests.

Operator-authoritative acts now require a verified ``OperatorActionV1``
signature, so a test that wants to say "the operator did this" needs a real
signature over the real canonical bytes — not a mock, and not a bypass.

This helper produces one using the **test-only software signer**, which:

  * requires ``CONTEXTD_INSECURE_TEST_SIGNER=1``,
  * refuses to operate on anything but a temporary archive, and
  * stamps every resulting event with assurance ``INSECURE_TEST_SIGNER``,

so nothing produced here can be mistaken for production assurance. Tests that
care about the *production* distinction assert on that literal.

There is deliberately no way to obtain ``operator_authorized`` from this file:
that level requires ``signer == "secure_enclave"``, which only the hardware
helper can produce.
"""

import os

import pytest

from contextd import attest


@pytest.fixture
def test_mode(monkeypatch):
    monkeypatch.setenv(attest.TEST_MODE_ENV, "1")
    return True


class OperatorFixture:
    """A registered test key plus a one-call way to authorize an exact act."""

    def __init__(self, conn, seed: bytes = b"test-operator"):
        self.conn = conn
        self.private = attest.load_test_signer(seed)
        self.key_id = attest.register_key(
            attest.public_der(self.private), attest.SIGNER_TEST, conn=conn
        )

    def authorize(self, action: str, scope: str = "global",
                  arguments: dict | None = None, content: str | None = None,
                  reason: str | None = None, ttl_seconds: int = 300):
        """Prepare, sign, and verify one authorization for exactly this act."""
        prepared = attest.prepare_action(
            self.key_id, action, scope=scope, arguments=arguments,
            content=content, reason=reason, ttl_seconds=ttl_seconds,
            conn=self.conn,
        )
        signature = attest.sign_with_test_key(
            self.private, bytes.fromhex(prepared["canonical"])
        )
        return attest.verify_action(prepared["action"], signature, conn=self.conn)

    def prepare(self, action: str, **kwargs):
        """The prepared action without signing — for tamper/expiry tests."""
        return attest.prepare_action(self.key_id, action, conn=self.conn, **kwargs)

    def sign(self, canonical_hex: str) -> bytes:
        return attest.sign_with_test_key(self.private, bytes.fromhex(canonical_hex))


def operator(conn, seed: bytes = b"test-operator") -> OperatorFixture:
    """Enable test-signing mode for this process and return the fixture."""
    os.environ[attest.TEST_MODE_ENV] = "1"
    return OperatorFixture(conn, seed)


def authorize_loop_add(conn, text: str, scope: dict, op=None):
    """The most common shape: authorize adding exactly this loop."""
    from contextd.loops import scope_str
    op = op or operator(conn)
    return op.authorize("loop.add", scope_str(scope), content=text)


def authorize_transition(conn, loop_id: int, action: str, scope: dict,
                         reason: str = "", op=None):
    from contextd.loops import scope_str
    op = op or operator(conn)
    return op.authorize(f"loop.{action}", scope_str(scope),
                        arguments={"loop": loop_id}, reason=reason)
