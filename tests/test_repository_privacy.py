"""The repository privacy scanner: planted positives, clean negatives, and the
guarantee that it never emits a matched value.

A scanner nobody tests is a scanner that silently stops matching. Each detected
class gets a planted positive (it must fire) and a near-miss negative (it must
not), so a regex that decays into matching nothing — or everything — is caught.

The strings below are deliberate fixtures. `scripts/repository_privacy_allow.json`
records this file as `synthetic` for exactly that reason.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCANNER = REPO_ROOT / "scripts" / "audit_repository_privacy.py"
GENERATOR = REPO_ROOT / "scripts" / "generate_retrieval_fixtures.py"
TASKS = REPO_ROOT / "experiments" / "tasks"

sys.path.insert(0, str(REPO_ROOT))
import scripts.audit_repository_privacy as privacy_scanner  # noqa: E402
from scripts.audit_repository_privacy import scan_bytes, scan_text  # noqa: E402

OWNERS = {"exampleowner"}

# --- planted positives: one per detected class ------------------------------
POSITIVES = {
    "home_path": "see /Users/realperson/projects/thing for the config",
    "session_uuid": "ingested as claude://a1b2c3d4e5f60718",
    "archive_dialogue": (
        '{"id": 40944, "source": "claude_code", "kind": "message", '
        '"content": "what the operator actually said"}'
    ),
    "private_repo": "cloned from github.com/exampleowner/private-thing",
    "credential": "export KEY=sk-planted00000000000000",
    "email": "private.person@example.invalid",
}

# --- negatives: near misses that must NOT fire ------------------------------
NEGATIVES = {
    "home_path": "see /Users/you/projects/thing and ~/notes and $HOME/x "
                 "and /home/sim/aster for fixtures",
    "session_uuid": "the tests use claude://d and claude://staged-1 as fixtures",
    "archive_dialogue": (
        '{"id": 1001, "source": "note", "kind": "note", "text": "synthetic"}'
    ),
    "private_repo": "cloned from github.com/python/cpython",
    "credential": "sk- is the prefix; commit 7a94e637b337; card game at 4pm",
    "email": "use person-at-example dot invalid in prose",
}


@pytest.mark.parametrize("cls", sorted(POSITIVES))
def test_planted_positive_is_detected(cls):
    counts = scan_text(POSITIVES[cls], OWNERS)
    assert counts.get(cls, 0) >= 1, f"{cls} detector did not fire: {counts}"


@pytest.mark.parametrize("cls", sorted(NEGATIVES))
def test_clean_negative_does_not_fire(cls):
    counts = scan_text(NEGATIVES[cls], OWNERS)
    assert counts.get(cls, 0) == 0, f"{cls} false positive: {counts}"


def test_scan_returns_counts_only_never_values():
    """The API cannot leak a value because it never returns one."""
    counts = scan_text("\n".join(POSITIVES.values()), OWNERS)
    blob = json.dumps(counts)
    for value in POSITIVES.values():
        assert value not in blob
    assert all(isinstance(n, int) for n in counts.values())


def test_binary_and_large_files_are_scanned_without_skip_cliffs():
    canary = POSITIVES["credential"]
    binary = b"\x00\xffprefix " + canary.encode() + b" suffix\x00"
    assert scan_bytes(binary, OWNERS).get("credential", 0) >= 1
    large = b"x" * (8 * 1024 * 1024 + 1) + canary.encode()
    assert scan_bytes(large, OWNERS).get("credential", 0) >= 1


@pytest.mark.parametrize(
    "encoding",
    ["utf-16-le", "utf-16-be", "utf-16", "utf-32-le", "utf-32-be", "utf-32"],
)
def test_multibyte_encoded_credentials_are_scanned(encoding):
    raw = POSITIVES["credential"].encode(encoding)
    assert scan_bytes(raw, OWNERS).get("credential", 0) >= 1


def test_exact_approval_does_not_cover_second_or_relocated_match():
    first = privacy_scanner._occurrences(POSITIVES["credential"], OWNERS)[0]
    entry = {
        "matches": [
            {
                "class": first[0],
                "line": first[1],
                "sha256": first[2],
                "count": 1,
            }
        ]
    }
    counts, missing = privacy_scanner._approved_counts([first, first], entry)
    assert missing == 0 and counts == {"credential": 1}
    relocated = (first[0], first[1] + 1, first[2])
    counts, missing = privacy_scanner._approved_counts([relocated], entry)
    assert missing == 1 and counts == {"credential": 1}


def test_sensitive_or_control_bearing_location_is_not_emitted():
    secret = "sk-" + "z" * 20
    location = privacy_scanner._safe_location(f"bad\x1b[31m/{secret}", OWNERS)
    assert secret not in location and "\x1b" not in location
    assert location.startswith("<sensitive-path:")


def test_tracked_symlink_reader_scans_link_text_not_target_bytes(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.write_bytes(b"private target bytes")
    link = tmp_path / "link"
    link.symlink_to(target)
    monkeypatch.setattr(privacy_scanner, "REPO_ROOT", tmp_path)
    raw = privacy_scanner._read_tracked_path(link)
    assert raw == str(target).encode()
    assert b"private target bytes" not in raw


def _run(*args, cwd=None):
    return subprocess.run(
        [sys.executable, str(SCANNER), *args],
        capture_output=True, text=True, cwd=cwd or REPO_ROOT,
    )


def test_scanner_output_contains_no_matched_values(tmp_path):
    report = tmp_path / "report.json"
    result = _run("--tracked", "--redact-output", "--report", str(report))
    assert result.returncode == 0, result.stderr
    combined = result.stdout + result.stderr + report.read_text()
    for value in POSITIVES.values():
        assert value not in combined
    # the planted fixtures in THIS file must not appear in the report either
    assert "sk-planted00000000000000" not in combined
    assert "claude://a1b2c3d4e5f60718" not in combined


def test_report_is_owner_only_readable(tmp_path):
    report = tmp_path / "report.json"
    _run("--tracked", "--redact-output", "--report", str(report))
    assert (os.stat(report).st_mode & 0o777) == 0o600


def test_report_refuses_symlink_destination(tmp_path):
    target = tmp_path / "target.json"
    target.write_text("keep")
    report = tmp_path / "report.json"
    report.symlink_to(target)
    result = _run("--tracked", "--report", str(report))
    assert result.returncode == 2
    assert result.stderr == "report write failed\n"
    assert target.read_text() == "keep"


def test_tracked_tree_passes_the_gate():
    """The publish gate: exit 0 with no unapproved findings."""
    result = _run("--worktree", "--fail-on-findings", "--redact-output")
    assert result.returncode == 0, result.stdout + result.stderr


def _throwaway_repo(tmp_path, monkeypatch):
    """A git repo the scanner treats as its own root, with no allowlist.

    Pointing ALLOWLIST_PATH at a file that does not exist is load-bearing:
    otherwise this repository's own approvals would be consulted for the
    planted findings below, and an approval is the one thing these tests must
    not have. The baseline content is staged but not committed, which is the
    state an author is actually in when they run the gate.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    (repo / "clean.txt").write_text("nothing private here")
    subprocess.run(["git", "add", "clean.txt"], cwd=repo, check=True)
    monkeypatch.setattr(privacy_scanner, "REPO_ROOT", repo)
    monkeypatch.setattr(privacy_scanner, "ALLOWLIST_PATH", tmp_path / "absent.json")
    return repo


def test_untracked_file_is_scanned_and_fails_the_gate(
    tmp_path, monkeypatch, capsys
):
    """The blind spot that put two unscanned files into this repository.

    An author writes a file, runs the gate, is told "clean", and ships — the
    scan enumerated what git already tracked, and a file written thirty
    seconds ago is not that. The gate has to fail on it BEFORE it is staged,
    because that is when the author asks.
    """
    repo = _throwaway_repo(tmp_path, monkeypatch)

    # Baseline: the same repo without the new file is clean, so the failure
    # below is attributable to that file and not to ambient noise.
    assert privacy_scanner.scan_worktree(set()) == []

    planted = repo / "tests" / "test_new_thing.py"
    planted.parent.mkdir()
    planted.write_text(POSITIVES["credential"] + "\n")
    listed = subprocess.run(
        ["git", "ls-files"], cwd=repo, capture_output=True, text=True, check=True
    ).stdout
    assert "test_new_thing.py" not in listed, "fixture is staged; gap not exercised"

    findings = privacy_scanner.scan_worktree(set())
    assert [
        f for f in findings
        if f["class"] == "credential" and f["location"] == "tests/test_new_thing.py"
    ], findings

    for flag in ("--worktree", "--tracked"):
        # the former spelling must not keep the old coverage
        monkeypatch.setattr(
            sys, "argv", ["audit", flag, "--fail-on-findings", "--redact-output"]
        )
        assert privacy_scanner.main() == 1, flag
        printed = capsys.readouterr().out
        assert "tests/test_new_thing.py" in printed
        assert POSITIVES["credential"] not in printed


def test_ignored_paths_stay_out_of_the_gate(tmp_path, monkeypatch):
    """Coverage grows to everything git will publish and stops there. An
    ignored tree is not publishable, and pulling it in would bury the gate
    under a virtualenv."""
    repo = _throwaway_repo(tmp_path, monkeypatch)
    (repo / ".gitignore").write_text("junk/\n")
    (repo / "junk").mkdir()
    (repo / "junk" / "local.txt").write_text(POSITIVES["credential"] + "\n")

    assert privacy_scanner.scan_worktree(set()) == []


def test_undescended_directory_is_reported_not_skipped(tmp_path, monkeypatch):
    """git refuses to descend into an untracked nested repository and lists the
    directory instead. Reading nothing from it and reporting nothing is the
    same failure in a different shape, so the gate names it."""
    repo = _throwaway_repo(tmp_path, monkeypatch)
    nested = repo / "vendored"
    nested.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=nested, check=True)
    (nested / "inner.txt").write_text(POSITIVES["credential"] + "\n")

    findings = privacy_scanner.scan_worktree(set())
    assert {
        "class": "unscanned_directory", "location": "vendored/", "count": 1
    } in findings


def test_clean_verdict_states_what_it_covered(tmp_path, monkeypatch, capsys):
    """A bare "clean" is what made the blind spot survivable. Every verdict
    carries its own coverage count now."""
    repo = _throwaway_repo(tmp_path, monkeypatch)
    (repo / "note.md").write_text("untracked and harmless")

    coverage: dict = {}
    assert privacy_scanner.scan_worktree(set(), None, coverage) == []
    assert coverage["tracked"] == 1 and coverage["untracked_not_ignored"] == 1

    monkeypatch.setattr(sys, "argv", ["audit", "--worktree", "--redact-output"])
    assert privacy_scanner.main() == 0
    assert "1 tracked + 1 untracked-not-ignored" in capsys.readouterr().out


def test_outstanding_findings_stay_visible():
    """An `awaiting_operator` entry is approved for the gate but must still be
    printed, so a real unfixed finding cannot quietly become the baseline."""
    result = _run("--tracked", "--redact-output")
    allow = json.loads(
        (REPO_ROOT / "scripts" / "repository_privacy_allow.json").read_text()
    )
    outstanding = [
        name for name, entry in allow["tracked"].items()
        if entry.get("status") == "awaiting_operator"
    ]
    if outstanding:
        assert "OUTSTANDING" in result.stdout
        for name in outstanding:
            assert name in result.stdout


def test_every_allowlist_entry_documents_itself():
    allow = json.loads(
        (REPO_ROOT / "scripts" / "repository_privacy_allow.json").read_text()
    )
    for name, entry in allow["tracked"].items():
        assert entry.get("matches"), f"{name}: no exact matches listed"
        assert entry.get("status") in {"synthetic", "awaiting_operator"}, name
        assert len(entry.get("reason", "")) > 40, f"{name}: reason too thin"
        for match in entry["matches"]:
            assert set(match) == {"class", "line", "sha256", "count"}
            assert match["line"] >= 0 and match["count"] >= 1
            assert len(match["sha256"]) == 64


def test_history_scans_commit_metadata(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Private Person"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", POSITIVES["email"]], cwd=repo, check=True
    )
    (repo / "clean.txt").write_text("clean")
    subprocess.run(["git", "add", "clean.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "clean message"], cwd=repo, check=True)
    monkeypatch.setattr(privacy_scanner, "REPO_ROOT", repo)

    findings = privacy_scanner.scan_history(set())

    assert any(
        finding["class"] == "email"
        and finding["location"] == "commit_metadata"
        for finding in findings
    )


# --- the synthetic fixtures -------------------------------------------------

FIXTURES = ("retrieval-contradiction-sets.json", "retrieval-synthesis-sets.json")


def test_retrieval_fixtures_match_the_generator_byte_for_byte(tmp_path):
    """The fixtures' provenance claim is only worth anything if the tracked
    bytes are actually what the tracked generator produces."""
    before = {name: (TASKS / name).read_bytes() for name in FIXTURES}
    result = subprocess.run(
        [sys.executable, str(GENERATOR)], capture_output=True, text=True,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stderr
    for name in FIXTURES:
        assert (TASKS / name).read_bytes() == before[name], (
            f"{name} differs from generator output — it is not the synthetic "
            f"fixture its manifest claims"
        )


def test_retrieval_fixtures_declare_synthetic_provenance():
    manifest = json.loads((TASKS / "retrieval-sets-provenance.json").read_text())
    assert manifest["provenance"] == "synthetic"
    assert manifest["derived_from_live_archive"] is False
    assert manifest["contains_personal_data"] is False
    assert set(manifest["files"]) == set(FIXTURES)


def test_retrieval_fixtures_carry_no_private_material():
    for name in FIXTURES:
        counts = scan_text((TASKS / name).read_text(), OWNERS)
        assert counts == {}, f"{name}: {counts}"


def test_retrieval_fixtures_still_have_the_structure_experiments_need():
    """A synthetic fixture that lost its shape would silently void the
    experiments that consume it."""
    for name in FIXTURES:
        data = json.loads((TASKS / name).read_text())
        assert set(data) == {"bm25", "connective", "stripped"}, name
        for set_name, frozen in data.items():
            assert frozen["items"], f"{name}/{set_name} has no items"
            assert isinstance(frozen["matched_not_included"], list)
            for item in frozen["items"]:
                assert set(item) >= {
                    "id", "ts", "source", "kind", "uri", "provenance",
                    "transport_role", "origin", "origin_basis",
                    "epistemic_type", "est_tokens", "header", "text", "sha",
                }, f"{name}/{set_name} item lost fields"
                assert item["header"].startswith(f"--- [{item['id']}] ")


def test_no_tracked_config_carries_an_absolute_personal_path():
    """launchd/ and clients/ are templates; rendering happens locally."""
    for source in ("launchd", "clients"):
        for path in (REPO_ROOT / source).iterdir():
            if not path.is_file():
                continue
            counts = scan_text(path.read_text(), OWNERS)
            assert counts.get("home_path", 0) == 0, f"{path.name}: {counts}"


def test_deployment_templates_render_to_real_paths(tmp_path):
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "render_deployment.py"),
         "--print", "launchd/com.contextd.watch.plist"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stderr
    assert "__CONTEXTD_REPO__" not in result.stdout
    assert str(REPO_ROOT) in result.stdout


# --- history credential triage ----------------------------------------------

def test_triage_never_emits_a_matched_value(tmp_path):
    """The triage reads real values in-process; it must never emit one.

    Both surfaces are checked: stdout and the JSON report. A tool that helpfully
    shows you the secret it found puts that secret into CI logs and scrollback.
    """
    report = tmp_path / "triage.json"
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "triage_history_credentials.py"),
         "--report", str(report)],
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=900,
    )
    combined = result.stdout + result.stderr + report.read_text()
    # every planted canary this repository knows about must be absent
    for needle in ("canary0000000000zzz1", "AKIACANARY0000000000",
                   "ghp_canary000000000", "xoxb-canary000000000",
                   "123-45-6789", "4111 1111 1111 1111",
                   "Q0FOQVJZQ0FOQVJZ", "eyJjYW5hcnkiOnRydWV9",
                   "sk-planted00000000000000"):
        assert needle not in combined, "the triage emitted a matched value"
    payload = json.loads(report.read_text())

    def keys(node):
        """Every key name anywhere in the report."""
        if isinstance(node, dict):
            for k, v in node.items():
                yield k
                yield from keys(v)
        elif isinstance(node, list):
            for v in node:
                yield from keys(v)

    # no field CARRIES a value; the word appears only in the report's own prose
    assert not {"value", "secret", "match", "matched"} & set(keys(payload))
    for item in payload["unclassified"]:
        assert set(item) == {"pattern", "path", "object", "line", "length",
                             "entropy_bits_per_char"}


def test_triage_accounts_for_every_history_credential_finding():
    """The triage must explain every finding, or exit nonzero saying it cannot."""
    sys.path.insert(0, str(REPO_ROOT))
    from scripts.triage_history_credentials import triage
    result = triage()
    assert result["total"] > 0, "no findings to triage — has the scanner broken?"
    assert sum(result["by_class"].values()) == result["total"]
    assert not result["unclassified"], (
        f"{len(result['unclassified'])} history finding(s) have no innocent "
        f"explanation; see docs/REPOSITORY_HISTORY_REMEDIATION.md"
    )


def test_triage_classifiers_reject_a_realistic_secret():
    """The classifier must not explain away something that looks real.

    Without this, a classifier that returns 'planted_canary' for everything
    would pass the suite above while proving nothing.
    """
    sys.path.insert(0, str(REPO_ROOT))
    from scripts.triage_history_credentials import classify
    realistic = "sk-" + "T9xQm2vHpL4wZ7cR8nK1yB6dF3gJ5sA0eU"
    assert classify(realistic, "contextd/thing.py", "key = load()") == \
        "UNCLASSIFIED"
    assert classify(realistic, "docs/notes.md", "we used it") == "UNCLASSIFIED"


def test_oversized_file_fails_closed_instead_of_silent_skip(tmp_path, monkeypatch):
    path = tmp_path / "large.bin"
    path.write_bytes(b"12345")
    monkeypatch.setattr(privacy_scanner, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(privacy_scanner, "MAX_SCAN_BYTES", 4)
    with pytest.raises(privacy_scanner.UnscannedOversized):
        privacy_scanner._read_tracked_path(path)
