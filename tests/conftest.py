"""Global test isolation: the live archive is never a possible default."""

import os
import tempfile

import pytest


# pytest imports conftest before collecting test modules, so contextd can never
# be imported with ~/.contextd as its implicit home during this suite.
os.environ["CONTEXTD_HOME"] = tempfile.mkdtemp(prefix="contextd-pytest-bootstrap-")

# Operator-authoritative acts require a verified OperatorActionV1 signature.
# The suite has no Secure Enclave, so it opts into the TEST-ONLY software
# signer. This is safe here and impossible in production because
# contextd.attest._assert_test_mode_ok also requires the archive to be an
# isolated temporary directory, and every event it authorizes is stamped with
# the assurance level INSECURE_TEST_SIGNER — see tests/test_authenticated_
# provenance.py, which asserts both halves of that guarantee.
os.environ["CONTEXTD_INSECURE_TEST_SIGNER"] = "1"


@pytest.fixture(autouse=True)
def isolated_contextd_home(tmp_path, monkeypatch):
    archive = tmp_path / "contextd-home"
    monkeypatch.setenv("CONTEXTD_HOME", str(archive))
    return archive


def pytest_addoption(parser):
    """Opt in to the Postgres backend tests by pointing at a test server.

    Deliberately **not** a ``--backend=postgres`` switch that reroutes the whole
    suite. The autouse fixture above is a security control — it is what makes
    `attest._assert_test_mode_ok` accept the test signer — and a global backend
    switch would quietly change what every test in the suite is exercising while
    leaving that control's assumptions unexamined.

    The multi-host tests do need two archive roots sharing one database, which
    is a real weakening of that isolation. They do it explicitly, per test, in
    `test_postgres_backend.py`, where it is visible in the test body rather than
    applied to 685 tests that never asked for it.
    """
    parser.addoption(
        "--postgres-url",
        action="store",
        default=None,
        help="Postgres URL for backend tests (also CONTEXTD_TEST_POSTGRES_URL). "
             "The tests create and drop a fresh database per test, so this must "
             "point at a throwaway server, never a real archive.",
    )


@pytest.fixture(scope="session")
def postgres_url(request):
    """A Postgres server to test against, or skip."""
    url = request.config.getoption("--postgres-url") or os.environ.get(
        "CONTEXTD_TEST_POSTGRES_URL"
    )
    if not url:
        pytest.skip(
            "no Postgres server configured (--postgres-url or "
            "CONTEXTD_TEST_POSTGRES_URL)"
        )
    pytest.importorskip("psycopg")
    return url
