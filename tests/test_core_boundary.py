"""The core/daemon boundary, enforced by AST rather than by intention.

The gate/evidence core is the surface a future extraction takes with it. That
extraction is only a `git archive` if the core never reaches back into the
daemon — not at import time, not inside a function body, not under
``TYPE_CHECKING``, and not through a string handed to ``importlib``. This test
computes the core's transitive import closure and fails if any daemon module
appears in it, which is the same question as "does the core still import when
the daemon's files are deleted", asked without deleting anything.

``CORE`` below is a deliberate literal, not a computed set. Membership is the
product surface, so moving a module across this line must show up as a diff in
this file that somebody chose to write.
"""

import ast
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1] / "contextd"

#: The future Terminus surface. ``__init__`` is here because importing any core
#: module executes it: if it ever grows a daemon import, every core import dies
#: with the daemon absent, no matter how clean the rest of this set is.
CORE = frozenset({
    "__init__",
    "attest",
    # the two authority-plane predicates db.connect and attest consult before
    # they will open or bootstrap an archive (lane T, ruling R6)
    "authority_mode",
    "canonical",
    "capability",
    "compliance",
    "db",
    "export",
    "export_crypto",
    "gate",
    "grants",
    "ledger_sig",
    "migrate",
    "pinning",
    "provenance",
    "schemas",
    # the backend seam travels with the core; every submodule of it is core
    "backends",
    "backends.base",
    "backends.paramstyle",
    "backends.pgdriver",
    "backends.postgres",
    "backends.sqlite",
    "backends.transfer",
})

#: Everything the daemon keeps. Listed explicitly so that a module which is
#: neither core nor daemon — a new file — fails `test_every_module_is_classified`
#: rather than silently defaulting to one side of the boundary.
DAEMON = frozenset({
    "assurance",
    "authd",
    "backup",
    "cli",
    "correlate",
    "decisions",
    "doctor",
    "domains",
    "experiment",
    "handoff",
    "ingest",
    "lineage",
    "liveness",
    "loops",
    "mcp_server",
    "redact",
    "rpc",
    "scratch",
    "search",
    "service",
})


def _module_name(path: Path) -> str:
    parts = list(path.relative_to(PKG).parts)
    if parts[-1] == "__init__.py":
        return ".".join(parts[:-1]) or "__init__"
    parts[-1] = parts[-1][:-len(".py")]
    return ".".join(parts)


def discover_modules() -> dict[str, Path]:
    return {
        _module_name(p): p
        for p in sorted(PKG.rglob("*.py"))
        if "__pycache__" not in p.parts
    }


MODULES = discover_modules()


class _Edges(ast.NodeVisitor):
    """Every in-package import a module performs, however it performs it."""

    def __init__(self, modname: str):
        self.package = modname.split(".")[:-1]
        self.edges: list[tuple[str, int, str, str]] = []   # target, line, how, text
        self._in_function = 0
        self._in_type_checking = 0

    # --- context -----------------------------------------------------------
    def _how(self) -> str:
        if self._in_type_checking:
            return "TYPE_CHECKING"
        if self._in_function:
            return "function-local"
        return "top-level"

    def visit_FunctionDef(self, node):
        self._in_function += 1
        self.generic_visit(node)
        self._in_function -= 1

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_If(self, node):
        test = node.test
        guarded = (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
            isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
        )
        if not guarded:
            self.generic_visit(node)
            return
        self._in_type_checking += 1
        for child in node.body:
            self.visit(child)
        self._in_type_checking -= 1
        for child in node.orelse:
            self.visit(child)

    # --- resolution --------------------------------------------------------
    @staticmethod
    def _longest_known(candidate: str) -> str | None:
        """Map a dotted in-package path onto the module that actually owns it.

        ``contextd.backends.sqlite.connect`` resolves to ``backends.sqlite``;
        an attribute of a module resolves to the module, never past it.
        """
        if candidate == "contextd":
            return "__init__"
        if not candidate.startswith("contextd."):
            return None
        rest = candidate[len("contextd."):]
        while rest:
            if rest in MODULES:
                return rest
            if "." not in rest:
                return None
            rest = rest.rsplit(".", 1)[0]
        return None

    def _record(self, target, node, how, text):
        if target:
            self.edges.append((target, node.lineno, how, text))

    def visit_Import(self, node):
        for alias in node.names:
            self._record(self._longest_known(alias.name), node, self._how(),
                         f"import {alias.name}")

    def visit_ImportFrom(self, node):
        names = [a.name for a in node.names]
        if node.level:
            base = self.package[: len(self.package) - (node.level - 1)]
            if node.module:
                target = self._longest_known(
                    "contextd." + ".".join(base + node.module.split("."))
                )
                self._record(target, node, self._how(),
                             f"from {'.' * node.level}{node.module} import "
                             f"{', '.join(names)}")
            else:
                # `from . import a, b` — each name may itself be a submodule
                for name in names:
                    target = self._longest_known(
                        "contextd." + ".".join(base + [name])
                    )
                    self._record(target, node, self._how(),
                                 f"from {'.' * node.level} import {name}")
            return
        if node.module == "contextd":
            for name in names:
                self._record(self._longest_known(f"contextd.{name}") or "__init__",
                             node, self._how(), f"from contextd import {name}")
            return
        if node.module:
            self._record(self._longest_known(node.module), node, self._how(),
                         f"from {node.module} import {', '.join(names)}")

    def visit_Call(self, node):
        """`importlib.import_module("contextd.ingest")` is an import edge too.

        Only a literal argument can be resolved here. A computed one is caught
        by `test_no_computed_in_package_imports`, which refuses the construct
        outright rather than pretending to analyse it.
        """
        func = node.func
        dynamic = (
            (isinstance(func, ast.Attribute) and func.attr == "import_module")
            or (isinstance(func, ast.Name) and func.id in ("import_module",
                                                           "__import__"))
        )
        if dynamic and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                self._record(self._longest_known(first.value), node, self._how(),
                             f"import_module({first.value!r})")
        self.generic_visit(node)


def edges_of(modname: str) -> list[tuple[str, int, str, str]]:
    visitor = _Edges(modname)
    visitor.visit(ast.parse(MODULES[modname].read_text(), filename=str(MODULES[modname])))
    return visitor.edges


ALL_EDGES = {name: edges_of(name) for name in MODULES}


def core_closure() -> set[str]:
    seen = set(CORE & MODULES.keys())
    stack = list(seen)
    while stack:
        for target, *_ in ALL_EDGES.get(stack.pop(), ()):
            if target not in seen:
                seen.add(target)
                stack.append(target)
    return seen


def test_every_module_is_classified():
    """A new file under contextd/ must be put on one side of the line."""
    unclassified = sorted(MODULES.keys() - CORE - DAEMON)
    assert not unclassified, (
        "these modules are neither CORE nor DAEMON in tests/test_core_boundary.py: "
        + ", ".join(unclassified)
        + " — classify them deliberately; the boundary is the product surface."
    )
    assert not (CORE & DAEMON), "a module cannot be both core and daemon"
    missing = sorted((CORE | DAEMON) - MODULES.keys())
    assert not missing, (
        "these classified modules no longer exist: " + ", ".join(missing)
    )


def test_core_never_reaches_the_daemon():
    """The severance itself: no daemon module in the core's import closure."""
    leaked = sorted(core_closure() & DAEMON)
    if not leaked:
        return

    direct = [
        (src, target, line, how, text)
        for src in sorted(CORE & MODULES.keys())
        for (target, line, how, text) in ALL_EDGES[src]
        if target in DAEMON
    ]
    indirect = sorted(set(leaked) - {t for _s, t, *_r in direct})
    report = [
        f"{len(leaked)} daemon module(s) in the core closure: {', '.join(leaked)}",
        f"{len(direct)} direct core -> daemon edge(s):",
    ]
    report += [
        f"  contextd/{src.replace('.', '/')}.py:{line} [{how}] -> {target}: {text}"
        for (src, target, line, how, text) in direct
    ]
    if indirect:
        report.append("reached only transitively: " + ", ".join(indirect))
    pytest.fail("\n".join(report))


def test_no_computed_in_package_imports():
    """Refuse the construct this test cannot analyse.

    A computed `importlib.import_module(...)` of an in-package module would let
    a daemon dependency re-enter the core without changing the import graph any
    static checker can see. There are none today; this keeps it that way.
    """
    offenders = []
    for name, path in MODULES.items():
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            is_dynamic = (
                (isinstance(func, ast.Attribute) and func.attr == "import_module")
                or (isinstance(func, ast.Name) and func.id in ("import_module",
                                                              "__import__"))
            )
            if not is_dynamic or not node.args:
                continue
            first = node.args[0]
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                offenders.append(f"contextd/{name.replace('.', '/')}.py:{node.lineno}")
    assert not offenders, (
        "computed module imports defeat the boundary check: " + ", ".join(offenders)
    )
