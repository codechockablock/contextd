"""The import-level network gate, and proof that it is not a rubber stamp.

`scripts/gates.sh` has defended "zero network code" with a grep since the
beginning. The grep is worth keeping and is kept — but it matches vocabulary,
so it is wrong in both directions at once: `import psycopg` is full network
reach containing none of the words it looks for, and `from urllib.parse import
urlparse` is no network reach at all while containing one. Most of
`tests/network_surface.txt` is pinned to suppress the second kind.

`scripts/network_imports.py` answers the other question — what can a module
actually reach — by parsing every file under `contextd/` with `ast`, following
package-internal imports transitively, and diffing the result against
`tests/network_imports.txt`.

The tests below are in three groups:

1. the manifest is accurate right now, and is honest about what it claims;
2. the checker FIRES — a gate that has only ever been observed passing is not
   evidence of anything, so a synthetic package with a smuggled import is run
   through it and must be caught, including through a transitive chain and a
   function-local import;
3. the checker does not pretend to be the grep, and vice versa.
"""

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "network_imports.py"
MANIFEST = REPO_ROOT / "tests" / "network_imports.txt"
LEXICAL_MANIFEST = REPO_ROOT / "tests" / "network_surface.txt"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import network_imports as gate  # noqa: E402


# --- the manifest is accurate ----------------------------------------------


def test_the_pinned_import_manifest_matches_the_tree():
    """The gate, run exactly as `scripts/gates.sh` runs it."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=120,
    )
    assert result.returncode == 0, (
        f"the import-level network surface changed and "
        f"tests/network_imports.txt was not updated in the same commit:\n"
        f"{result.stdout}{result.stderr}"
    )


def test_every_manifest_entry_names_how_the_capability_arrived():
    """Each line must say `direct` or name the modules it inherits from.

    A manifest that only listed module names would tell a reviewer that
    something reaches the network without telling them where it enters, which
    is the only part anyone can act on.
    """
    for line in gate.read_manifest():
        module, _, caps = line.partition(": ")
        assert module.startswith("contextd"), line
        assert caps, f"{line}: no capability recorded"
        for clause in caps.split(", "):
            name, _, how = clause.partition("=")
            assert name, line
            assert how == "direct" or how.startswith("via:"), (
                f"{line}: {name} must be `direct` or `via:<modules>`"
            )


def test_the_direct_entry_points_are_the_four_that_are_documented():
    """The load-bearing claim: capability enters at exactly four places.

    Everything else in the manifest inherits. If a fifth appears, this fails
    before anyone has to notice a new `via:` line in a 29-line diff.
    """
    surface = gate.current_surface()
    entries = {
        (module, capability)
        for module, caps in surface.items()
        for capability, how in caps.items()
        if how == "direct"
    }
    assert entries == {
        ("contextd.authd", "socket"),          # AF_UNIX authority-plane listener
        ("contextd.rpc", "socket"),            # its client half
        ("contextd.backends.postgres", "psycopg"),   # real remote TCP
        ("contextd.mcp_server", "mcp"),        # MCP SDK, ships HTTP transports
    }, entries


def test_the_manifest_explains_each_direct_entry():
    """Every entry point is annotated, because an unexplained allowance is
    indistinguishable from one nobody reviewed."""
    text = MANIFEST.read_text()
    for module in ("contextd.authd", "contextd.rpc",
                   "contextd.backends.postgres", "contextd.mcp_server"):
        assert module in text
    assert "ENTRY 1/4" in text and "ENTRY 4/4" in text
    assert "AF_UNIX" in text, "the socket entries must record that they are local"
    import re as _re
    m = _re.search(r"postgres\.py:(\d+)", text)
    assert m, "the psycopg entry must cite its import site"
    # the cited line must actually BE the import site, so it cannot go stale
    src = (REPO_ROOT / "contextd" / "backends" / "postgres.py").read_text().splitlines()
    assert "import psycopg" in src[int(m.group(1)) - 1], (
        f"manifest cites postgres.py:{m.group(1)} but the import is not there")


def test_the_pure_data_modules_reach_nothing():
    """The claim the manifest closes with, asserted rather than narrated.

    canonical.py is the encoder every signature is computed over and
    schemas.py is the closed event registry. "They cannot reach the network"
    is a much stronger statement than "they contain no network code", and it
    is the one this gate can actually make.
    """
    surface = gate.current_surface()
    # search left this list when the resolver was corrected: it imports
    # contextd.backends (function-locally, to refuse on Postgres), and that
    # package reaches psycopg. Its reach was ALWAYS real; the old scanner
    # dropped the edge. The remaining seven are clean under correct
    # resolution, which is a stronger claim than the old list ever made.
    for module in ("contextd.canonical", "contextd.schemas", "contextd.redact",
                   "contextd.domains", "contextd.correlate",
                   "contextd.export_crypto", "contextd.scratch"):
        assert module not in surface, (
            f"{module} can now reach {surface.get(module)}; it could not before"
        )


def test_pgdriver_is_network_free_despite_being_about_psycopg():
    """The case that proves the gate follows imports rather than names.

    `backends/pgdriver.py` is a psycopg compatibility shim — its docstring's
    first line says so — and it never imports psycopg. The capability enters
    one module over. An audit by file name, docstring, or vocabulary puts the
    surface in the wrong place; this one does not.
    """
    surface = gate.current_surface()
    assert "contextd.backends.pgdriver" not in surface
    assert surface["contextd.backends.postgres"]["psycopg"] == "direct"


# --- the checker fires ------------------------------------------------------


def _package(tmp_path: Path, files: dict[str, str]) -> Path:
    """Write a synthetic package and point the checker at it."""
    root = tmp_path / "fake"
    (root / "contextd").mkdir(parents=True)
    for name, body in files.items():
        target = root / "contextd" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(textwrap.dedent(body))
    (root / "tests").mkdir()
    return root


def _surface_of(tmp_path: Path, files: dict[str, str], monkeypatch) -> dict:
    root = _package(tmp_path, files)
    monkeypatch.setattr(gate, "REPO_ROOT", root)
    monkeypatch.setattr(gate, "PACKAGE", root / "contextd")
    monkeypatch.setattr(gate, "MANIFEST", root / "tests" / "network_imports.txt")
    return gate.current_surface()


def test_a_smuggled_direct_import_is_caught(tmp_path, monkeypatch):
    surface = _surface_of(tmp_path, {
        "__init__.py": "",
        "quiet.py": "import json\n",
        "loud.py": "import requests\n",
    }, monkeypatch)
    assert surface == {"contextd.loud": {"requests": "direct"}}


def test_a_transitively_inherited_import_is_caught(tmp_path, monkeypatch):
    """The property the grep cannot have: capability is followed through the
    package, so a module with a clean file still reports what it can reach."""
    surface = _surface_of(tmp_path, {
        "__init__.py": "",
        "base.py": "import httpx\n",
        "middle.py": "from . import base\n",
        "top.py": "from . import middle\n",
    }, monkeypatch)
    assert surface["contextd.base"] == {"httpx": "direct"}
    assert surface["contextd.middle"] == {"httpx": "via:contextd.base"}
    assert surface["contextd.top"] == {"httpx": "via:contextd.base"}


def test_a_function_local_import_is_caught(tmp_path, monkeypatch):
    """How contextd actually imports psycopg (postgres.py:318). A checker that
    only read the top of a file would report zero network surface for the one
    module that has the most."""
    surface = _surface_of(tmp_path, {
        "__init__.py": "",
        "lazy.py": """
            def connect(url):
                import psycopg
                return psycopg.connect(url)
        """,
    }, monkeypatch)
    assert surface["contextd.lazy"] == {"psycopg": "direct"}


def test_url_parsing_is_not_treated_as_network_reach(tmp_path, monkeypatch):
    """The false positive that made the lexical manifest thirteen lines long.

    `urllib.parse` performs no I/O. Flagging it would make this gate as noisy
    as the grep and it would stop being read.
    """
    surface = _surface_of(tmp_path, {
        "__init__.py": "",
        "domains.py": "from urllib.parse import urlparse\n",
        "fetch.py": "from urllib.request import urlopen\n",
    }, monkeypatch)
    assert "contextd.domains" not in surface
    assert surface["contextd.fetch"] == {"urllib.request": "direct"}


def test_a_module_that_starts_importing_directly_stops_saying_via(
    tmp_path, monkeypatch,
):
    """The subtle regression the manifest format exists to catch.

    A module that already inherited `socket` and then imports it itself has
    not changed its *reach* at all — a set-of-modules manifest would show no
    diff. Recording `direct` versus `via:` makes it a visible change, which is
    the point: a new call site for a capability is worth a review even when
    the capability was already present.
    """
    files = {
        "__init__.py": "",
        "base.py": "import socket\n",
        "user.py": "from . import base\n",
    }
    before = _surface_of(tmp_path / "a", files, monkeypatch)
    assert before["contextd.user"] == {"socket": "via:contextd.base"}

    files["user.py"] = "import socket\nfrom . import base\n"
    after = _surface_of(tmp_path / "b", files, monkeypatch)
    assert after["contextd.user"] == {"socket": "direct"}
    assert gate.surface_lines(before) != gate.surface_lines(after)


def test_the_gate_exits_non_zero_when_the_manifest_is_stale(tmp_path):
    """End to end, through the real CLI, with a real stale manifest."""
    root = _package(tmp_path, {
        "__init__.py": "",
        "sneaky.py": "import requests\n",
    })
    (root / "tests" / "network_imports.txt").write_text(
        "# nothing is allowed to reach the network\n")
    (root / "scripts").mkdir()
    (root / "scripts" / "network_imports.py").write_text(SCRIPT.read_text())

    result = subprocess.run(
        [sys.executable, str(root / "scripts" / "network_imports.py")],
        capture_output=True, text=True, cwd=str(root), timeout=120,
    )
    assert result.returncode == 1, result.stdout
    assert "+ contextd.sneaky: requests=direct" in result.stdout
    assert "SAME commit" in result.stdout, (
        "the failure must tell the reader what to do about it"
    )


def test_a_removed_capability_also_fails_until_the_manifest_is_updated(tmp_path):
    """The gate is a diff, not a ceiling. Deleting a network import without
    updating the manifest is also a mismatch — otherwise the file rots into a
    list of things that used to be true."""
    root = _package(tmp_path, {"__init__.py": "", "clean.py": "import json\n"})
    (root / "tests" / "network_imports.txt").write_text(
        "contextd.clean: requests=direct\n")
    (root / "scripts").mkdir()
    (root / "scripts" / "network_imports.py").write_text(SCRIPT.read_text())

    result = subprocess.run(
        [sys.executable, str(root / "scripts" / "network_imports.py")],
        capture_output=True, text=True, cwd=str(root), timeout=120,
    )
    assert result.returncode == 1
    assert "- contextd.clean: requests=direct" in result.stdout


# --- the two gates are not each other ---------------------------------------


def test_the_two_gates_disagree_and_both_are_kept():
    """The justification for running both, as a test rather than a comment.

    If the two manifests ever became the same set, one of them would be
    redundant. They are not the same set, and the specific disagreements are
    the argument: files with network vocabulary and no capability, and files
    with capability that the grep's four words do not appear in.
    """
    lexical = {
        line.strip() for line in LEXICAL_MANIFEST.read_text().splitlines()
        if line.strip()
    }
    lexical_modules = {
        path[: -len(".py")].replace("/", ".") for path in lexical
    }
    lexical_modules = {
        m[: -len(".__init__")] if m.endswith(".__init__") else m
        for m in lexical_modules
    }
    capability_modules = set(gate.current_surface())

    vocabulary_only = lexical_modules - capability_modules
    assert vocabulary_only, (
        "the lexical gate should still be pinning files that mention networks "
        "without being able to reach one"
    )
    assert "contextd.domains" in vocabulary_only

    capability_only = capability_modules - lexical_modules
    assert capability_only, (
        "the import gate should be finding reach the grep's four words miss"
    )
    # The headline case: psycopg gives postgres.py real remote TCP, and the
    # capability it inherits is not what the grep matched on.
    assert "contextd.backends.pgdriver" not in capability_modules


def test_the_gate_script_imports_nothing_outside_the_standard_library():
    """A gate that needs the package built cannot run on the day the build
    breaks, which is a day it is especially worth running.

    Checked by parsing the script rather than grepping it — the script's own
    docstring contains the phrase "does not import contextd", and a substring
    check reports that as a violation. Which is a small live demonstration of
    why the gate this file tests parses instead of matching text.
    """
    import ast

    tree = ast.parse(SCRIPT.read_text(), filename=str(SCRIPT))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    assert "contextd" not in imported, (
        f"the gate imports contextd; it must run against a broken tree: {imported}"
    )
    assert imported <= set(sys.stdlib_module_names), (
        f"non-stdlib imports in the gate: {imported - set(sys.stdlib_module_names)}"
    )


@pytest.mark.parametrize("flag", ["--list", "--explain"])
def test_the_reporting_modes_run(flag):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), flag],
        capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "contextd.backends.postgres" in result.stdout
