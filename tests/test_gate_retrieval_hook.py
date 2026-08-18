"""The gate's retrieval provider: registered by the daemon, absent-safe.

`gate.select_items` used to import contextd.search directly. Retrieval is a
consumer of the record rather than part of its lifecycle, so the gate now
dispatches through a provider the daemon registers at its own import time
(lane T, ruling R1/R5). What matters is the direction of the default: an
unregistered gate must disclose LESS, never more.
"""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from contextd import load_config
from contextd.db import append_event, connect
from contextd.gate import assemble, select_items


def _seed(conn):
    append_event(conn, "note", "note", content="pangolin telemetry regression",
                 uri="note://pangolin")
    return load_config()


def test_registered_provider_is_what_the_gate_retrieves_through(
    isolated_contextd_home,
):
    conn = connect()
    cfg = _seed(conn)
    assert select_items(conn, cfg, "pangolin", budget=2000)


def test_an_unregistered_gate_discloses_nothing(
    isolated_contextd_home, monkeypatch,
):
    """The fail-closed direction: no provider means no candidates, not a crash
    and not an unfiltered dump."""
    conn = connect()
    cfg = _seed(conn)
    monkeypatch.setattr("contextd.gate._RETRIEVAL", None)

    assert select_items(conn, cfg, "pangolin", budget=2000) == []
    result = assemble(conn, cfg, "pangolin", budget=2000, purpose="hook test")
    assert result["items"] == []


@pytest.mark.parametrize("entry_point",
                         ["cli", "mcp_server", "service", "authd"])
def test_every_daemon_entry_point_has_a_retrieval_provider(entry_point):
    """In a fresh interpreter — inside this suite contextd.search is already
    imported by other modules and would mask a missing registration."""
    result = subprocess.run(
        [sys.executable, "-c",
         f"import contextd.{entry_point}\n"
         "from contextd.gate import _RETRIEVAL\n"
         "assert _RETRIEVAL is not None, 'no retrieval provider registered'\n"
         "print('ok')\n"],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_importing_the_gate_alone_registers_nothing():
    """The boundary, stated as a test: the core does not carry retrieval."""
    result = subprocess.run(
        [sys.executable, "-c",
         "import contextd.gate\n"
         "import sys\n"
         "assert contextd.gate._RETRIEVAL is None, 'gate self-registered'\n"
         "assert 'contextd.search' not in sys.modules, 'gate imported search'\n"
         "print('ok')\n"],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _registers_search(tree) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(a.name == "contextd.search" for a in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if node.module == "contextd.search":
                return True
            if node.module == "contextd" and any(
                a.name == "search" for a in node.names
            ):
                return True
    return False


def _retrieves(tree) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = (func.id if isinstance(func, ast.Name)
                else func.attr if isinstance(func, ast.Attribute) else None)
        if name in ("select_items", "assemble"):
            return True
    return False


def test_every_retrieval_caller_registers():
    """Out-of-package processes must import the provider they retrieve through.

    The gate's unregistered default returns no candidates rather than raising,
    which is right for the core and silent for a caller that forgot — a script
    that assembles without importing contextd.search reports "no matching
    events" and looks like an empty archive. This is the guard that turns that
    into a test failure instead. It caught hooks/synthesis_recall.py, which the
    four daemon entry points do not cover.
    """
    root = Path(__file__).resolve().parents[1]
    offenders = []
    for directory in ("hooks", "experiments"):
        for path in sorted((root / directory).rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(), filename=str(path))
            if _retrieves(tree) and not _registers_search(tree):
                offenders.append(str(path.relative_to(root)))
    assert not offenders, (
        "these retrieve through the gate but never import contextd.search, so "
        "they will silently find nothing: " + ", ".join(offenders)
    )
