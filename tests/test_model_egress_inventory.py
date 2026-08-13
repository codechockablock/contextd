import ast
from concurrent.futures import Future
from pathlib import Path
from types import SimpleNamespace

import pytest

import experiments.runner as runner
from contextd.gate import GateError


ROOT = Path(__file__).resolve().parent.parent
SUBPROCESS_METHODS = {"run", "call", "Popen", "check_call", "check_output"}

# Every non-test subprocess call is classified here. Adding one forces a CI
# review of whether it can carry archive-derived bytes to a model.
EXPECTED_SUBPROCESS_CALLS = {
    ("contextd/cli.py", "cmd_recall", "call"): "local harness delegation",
    ("experiments/runner.py", "run_model", "run"): "model",
    ("experiments/runner.py", "cmd_run", "run"): "model CLI version only",
    ("hooks/reconcile.py", "reconcile", "run"): "model",
    ("hooks/synthesis_recall.py", "distill", "run"): "model",
    ("experiments/provenance/model_trials.py", "dispatch_note_writer", "run"):
        "model (note-writing trials; archive bytes pass the synthetic "
        "archive's gate first)",
    ("experiments/provenance/model_trials.py", "cmd_probe", "run"):
        "model (read-only MCP wiring probe; search tool only)",
    ("contextd/handoff.py", "_git", "run"): "local git read, no archive bytes",
    ("contextd/handoff.py", "repo_state", "run"):
        "local test command in the caller's repo, no archive bytes",
    ("hooks/checkpoint_compile.py", "distill", "run"):
        "model (checkpoint distiller; payload passes the gate first)",
    ("experiments/handoff/common.py", "run_claude", "run"):
        "model (handoff bench resumption; every bundle passes the "
        "archive-under-test's gate before prompt assembly)",
    ("experiments/handoff/common.py", "run_codex", "run"):
        "model (cross-vendor resumption, same gated bundles)",
    ("experiments/handoff/staged.py", "run_pytest", "run"):
        "local pytest in the staged scratch repo, no archive bytes",
    ("experiments/handoff/bench.py", "history_arm_contexts", "run"):
        "local git log + delegation to hooks/synthesis_recall.py "
        "(which gates and models under its own inventory entry)",
    ("experiments/handoff/bench.py", "cmd_ablate", "run"): "local git log only",
    ("experiments/handoff/staged.py", "make_repo", "run"):
        "local git init in the scratch repo, no archive bytes",
    ("contextd/cli.py", "cmd_checkpoint", "call"): "local harness delegation",
    ("experiments/handoff/openloops.py", "build_contexts", "run"):
        "local git log only",
}
MODEL_CALLERS = {
    ("experiments/runner.py", "run_model"),
    ("hooks/reconcile.py", "reconcile"),
    ("hooks/synthesis_recall.py", "distill"),
    ("hooks/checkpoint_compile.py", "distill"),
    ("experiments/provenance/model_trials.py", "dispatch_note_writer"),
}


class SubprocessInventory(ast.NodeVisitor):
    def __init__(self, relative_path):
        self.relative_path = relative_path
        self.functions = []
        self.calls = set()
        self.module_aliases = {"subprocess"}
        self.function_aliases = {}

    def visit_Module(self, node):
        # Resolve aliases before walking function bodies; Python permits an
        # import later in a module than the function that uses it.
        for child in ast.walk(node):
            if isinstance(child, ast.Import):
                self.visit_Import(child)
            elif isinstance(child, ast.ImportFrom):
                self.visit_ImportFrom(child)
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name == "subprocess":
                self.module_aliases.add(alias.asname or alias.name)

    def visit_ImportFrom(self, node):
        if node.module == "subprocess":
            for alias in node.names:
                if alias.name in SUBPROCESS_METHODS:
                    self.function_aliases[alias.asname or alias.name] = alias.name

    def visit_FunctionDef(self, node):
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node):
        fn = node.func
        method = None
        if (
            isinstance(fn, ast.Attribute)
            and isinstance(fn.value, ast.Name)
            and fn.value.id in self.module_aliases
            and fn.attr in SUBPROCESS_METHODS
        ):
            method = fn.attr
        elif isinstance(fn, ast.Name) and fn.id in self.function_aliases:
            method = self.function_aliases[fn.id]
        if method is not None:
            owner = self.functions[-1] if self.functions else "<module>"
            self.calls.add((self.relative_path, owner, method))
        self.generic_visit(node)


def test_inventory_detects_aliased_modules_and_imported_entry_points():
    visitor = SubprocessInventory("example.py")
    visitor.visit(
        ast.parse(
            "import subprocess as proc\n"
            "from subprocess import Popen as launch\n"
            "def first(): proc.run(['model'])\n"
            "def second(): launch(['model'])\n"
        )
    )
    assert visitor.calls == {
        ("example.py", "first", "run"),
        ("example.py", "second", "Popen"),
    }


def test_all_non_test_subprocesses_are_inventory_classified():
    observed = set()
    for path in ROOT.rglob("*.py"):
        relative = path.relative_to(ROOT).as_posix()
        # runs/ holds benchmark artifacts (including model-written scratch
        # repos), not shipped code; it is gitignored and not inventoried
        if relative.startswith(("tests/", ".venv/", "runs/")):
            continue
        visitor = SubprocessInventory(relative)
        visitor.visit(ast.parse(path.read_text(), filename=str(path)))
        observed |= visitor.calls
    assert observed == set(EXPECTED_SUBPROCESS_CALLS)


def test_every_archive_bearing_model_caller_has_gate_and_outcome_path():
    for relative, function in MODEL_CALLERS:
        source = (ROOT / relative).read_text()
        assert "disclose(" in source, relative
        assert "record_dispatch_outcome(" in source, relative

    runner = (ROOT / "experiments/runner.py").read_text()
    assert 'disclosure.get("payload")' in runner
    assert 'run_model(disclosure["content"]' in runner
    reconcile = (ROOT / "hooks/reconcile.py").read_text()
    assert 'input=disclosure["content"]' in reconcile
    synthesis = (ROOT / "hooks/synthesis_recall.py").read_text()
    assert 'distill(source["content"]' in synthesis


def test_experiment_submits_each_receipt_before_preparing_the_next(
    monkeypatch, tmp_path
):
    order = []
    disclosures = 0

    class ImmediateExecutor:
        def __init__(self, max_workers):
            assert max_workers == 1

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def submit(self, fn, *args):
            order.append("submit")
            future = Future()
            future.set_result(fn(*args))
            return future

    def fake_disclose(*args, **kwargs):
        nonlocal disclosures
        disclosures += 1
        order.append(f"disclose-{disclosures}")
        if disclosures == 2:
            raise GateError("cap reached")
        return {
            "bundle": "archive bundle",
            "payload": "wrapped archive payload",
            "egress_id": 101,
            "sha": "bundle-sha",
            "items": [7],
            "est_tokens": 5,
        }

    def fake_model(prompt, model):
        order.append("model")
        assert prompt == "wrapped archive payload"
        return {
            "text": "answer",
            "session_id": "session",
            "exit": 0,
            "duration_ms": 1,
            "cost_usd": 0.0,
            "usage": {},
            "stderr": "",
            "dispatch_status": "succeeded",
        }

    outcomes = []
    monkeypatch.setattr(runner, "ThreadPoolExecutor", ImmediateExecutor)
    monkeypatch.setattr(runner, "RESULTS", tmp_path / "results")
    monkeypatch.setattr(
        runner,
        "load_task",
        lambda _: {
            "task_id": "dispatch-order",
            "prompt": "question",
            "model": "fake",
            "n_per_arm": 1,
            "context_sets": {"default": {}},
            "arms": [{"name": "first"}, {"name": "second"}],
            "rubric": {"facts": []},
        },
    )
    monkeypatch.setattr(
        runner,
        "freeze_sets",
        lambda *args: {
            "default": {"items": [{"id": 7}]},
        },
    )
    monkeypatch.setattr(
        runner, "resolve_arms", lambda conn, cfg, task, sets: task["arms"]
    )
    monkeypatch.setattr(runner, "attribute_facts", lambda *args: {})
    monkeypatch.setattr(runner, "register_experiment", lambda *args: 1)
    monkeypatch.setattr(runner, "disclose_for_run", fake_disclose)
    monkeypatch.setattr(runner, "run_model", fake_model)
    monkeypatch.setattr(
        runner,
        "record_dispatch_outcome",
        lambda conn, eid, status, **details: outcomes.append((eid, status)),
    )
    monkeypatch.setattr(
        runner, "score_output", lambda rubric, text: {"score": 1.0, "hits": {}}
    )
    monkeypatch.setattr(runner, "record_run", lambda *args: None)
    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout="fake version"),
    )

    args = SimpleNamespace(
        task="unused",
        reuse_frozen=None,
        allow_empty=False,
        jobs=1,
    )
    with pytest.raises(GateError, match="cap reached"):
        runner.cmd_run(args)

    assert order == ["disclose-1", "submit", "model", "disclose-2"]
    assert outcomes == [(101, "succeeded")]
