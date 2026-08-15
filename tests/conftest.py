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
