"""Global test isolation: the live archive is never a possible default."""

import os
import tempfile

import pytest


# pytest imports conftest before collecting test modules, so contextd can never
# be imported with ~/.contextd as its implicit home during this suite.
os.environ["CONTEXTD_HOME"] = tempfile.mkdtemp(prefix="contextd-pytest-bootstrap-")


@pytest.fixture(autouse=True)
def isolated_contextd_home(tmp_path, monkeypatch):
    archive = tmp_path / "contextd-home"
    monkeypatch.setenv("CONTEXTD_HOME", str(archive))
    return archive
