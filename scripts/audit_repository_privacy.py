#!/usr/bin/env python3
"""Scan this repository for private material, without printing any of it.

Two surfaces, deliberately separate:

    --tracked   the current working tree, as tracked by git. This is the gate
                that must stay clean: it is what a `git push` publishes today.
    --history   every blob reachable from any ref. Findings here cannot be
                fixed without rewriting published history, which is a separate,
                operator-authorized decision (docs/REPOSITORY_HISTORY_REMEDIATION.md).
                A nonzero count here is expected and is NOT a build failure.

**Nothing this script prints contains a matched value.** With --redact-output
(the default for anything credential-shaped, and forced for every class) a
finding is reported as class + location + count only. That rule exists because
the alternative — a scanner that helpfully shows you the secret it found — puts
the secret into CI logs, terminal scrollback, and any report file it writes.

Detected classes (`--list-classes` prints these):

    home_path         an absolute personal home directory (/Users/<name>/…)
    session_uuid      a live Claude Code session identifier (claude:// or a
                      bare v4 UUID inside an event/fixture context)
    archive_dialogue  raw archive dialogue: gate bundle headers, or fixture
                      records carrying source/kind/content triples
    private_repo      a repository under a non-public owner namespace
    credential        anything matching the immutable redaction floor
                      (contextd/redact.py). Reported by class and count only;
                      never printed, never copied, never rotated by this tool.

Exit codes: 0 clean (or history mode without --fail-on-findings), 1 findings
with --fail-on-findings, 2 usage/environment error.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from contextd.redact import FLOOR  # noqa: E402

ALLOWLIST_PATH = REPO_ROOT / "scripts" / "repository_privacy_allow.json"

# A personal home directory. Placeholder and synthetic namespaces this repo
# uses on purpose are excluded by name rather than by per-file exception, so a
# new file using them is clean without needing an allowlist entry:
#   /Users/you, /home/user, $HOME, ~        documentation placeholders
#   /home/sim/…                             the synthetic corpus generator
#   /srv/demo/…                             synthetic fixture paths
#   /Users/_name                            a macOS SERVICE account (the
#                                           leading underscore is the platform
#                                           convention for them); the daemon
#                                           runs as one, and naming it in a
#                                           deployment runbook identifies
#                                           nobody
HOME_PATH_RX = re.compile(
    r"/(?:Users|home)/(?!you\b|USER\b|user\b|sim/|_)[A-Za-z0-9._-]{2,}"
)

# A real session URI is `claude://` + the first 16 hex characters of the
# transcript UUID (contextd/ingest.py). Short alphabetic forms are the test
# suite's synthetic fixtures and are not session identifiers.
SESSION_URI_RX = re.compile(r"claude://[0-9a-f]{12,}")
UUID_RX = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"
)
# a gate disclosure header, i.e. real archive bytes pasted into a file
BUNDLE_HEADER_RX = re.compile(r"^--- \[\d+\] \d{4}-\d\d-\d\dT[\d:+-]+ \w+/\w+ ", re.M)
# a serialized archive event: an id + ts + source + content in one object
# A serialized *dialogue* event: transcript turns are the class that carries
# private conversation. note/fs/browser records are archive-shaped but are not
# dialogue, and the synthetic fixtures use exactly that shape on purpose.
EVENT_RECORD_RX = re.compile(
    r'"source"\s*:\s*"claude_code"[^}]{0,400}?"(?:content|text)"\s*:'
)

TEXT_SUFFIXES = {
    ".py", ".md", ".json", ".toml", ".txt", ".yml", ".yaml", ".plist", ".cfg",
    ".ini", ".sh", ".swift", ".html", ".css", ".js", ".ts", ".rst", ".jsonl",
}
MAX_BLOB_BYTES = 8 * 1024 * 1024


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def private_owners() -> set[str]:
    """Owner namespaces treated as private. Derived from the configured remote
    rather than hardcoded, so this file names nobody."""
    owners = set()
    try:
        remotes = _git("remote", "-v")
    except RuntimeError:
        return owners
    for match in re.finditer(r"[:/]([A-Za-z0-9_.-]+)/[A-Za-z0-9_.-]+(?:\.git)?\s", remotes):
        owners.add(match.group(1))
    return owners


def _load_allowlist() -> dict:
    if not ALLOWLIST_PATH.exists():
        return {"tracked": {}}
    return json.loads(ALLOWLIST_PATH.read_text())


def scan_text(text: str, owners: set[str]) -> dict[str, int]:
    """Return {class: count}. The matched substrings are intentionally
    discarded here rather than returned — a caller cannot print what it was
    never given."""
    counts: dict[str, int] = {}

    def bump(cls: str, n: int) -> None:
        if n:
            counts[cls] = counts.get(cls, 0) + n

    bump("home_path", len(HOME_PATH_RX.findall(text)))
    bump("session_uuid", len(SESSION_URI_RX.findall(text)) + len(UUID_RX.findall(text)))
    bump(
        "archive_dialogue",
        len(BUNDLE_HEADER_RX.findall(text)) + len(EVENT_RECORD_RX.findall(text)),
    )
    repo_hits = 0
    for owner in owners:
        repo_hits += len(
            re.findall(rf"github\.com[:/]{re.escape(owner)}/[A-Za-z0-9_.-]+", text)
        )
    bump("private_repo", repo_hits)
    cred = 0
    for pattern in FLOOR.values():
        cred += len(re.findall(pattern, text))
    bump("credential", cred)
    return counts


def _decode(raw: bytes) -> str | None:
    if b"\x00" in raw[:8192] or len(raw) > MAX_BLOB_BYTES:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def scan_tracked(owners: set[str], outstanding: list | None = None) -> list[dict]:
    findings = []
    outstanding = outstanding if outstanding is not None else []
    allow = _load_allowlist().get("tracked", {})
    for name in _git("ls-files", "-z").split("\0"):
        if not name:
            continue
        path = REPO_ROOT / name
        if path.suffix and path.suffix not in TEXT_SUFFIXES:
            continue
        try:
            text = _decode(path.read_bytes())
        except OSError:
            continue
        if text is None:
            continue
        counts = scan_text(text, owners)
        entry = allow.get(name) or {}
        allowed = set(entry.get("classes", []))
        for cls, n in sorted(counts.items()):
            if cls in allowed:
                # approved, but an outstanding real finding stays visible
                if entry.get("status") == "awaiting_operator":
                    outstanding.append(
                        {"class": cls, "location": name, "count": n,
                         "reason": entry.get("reason", "")}
                    )
                continue
            findings.append({"class": cls, "location": name, "count": n})
    return findings


def scan_history(owners: set[str]) -> list[dict]:
    """Scan every blob reachable from any ref.

    Blobs are addressed by their object id, and the *path* reported is the one
    git recorded for that object — enough for remediation planning, with no
    content in the output.
    """
    listing = _git("rev-list", "--all", "--objects")
    blobs: dict[str, str] = {}
    for line in listing.splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[1].strip():
            blobs.setdefault(parts[0], parts[1].strip())
    findings = []
    proc = subprocess.Popen(
        ["git", "-C", str(REPO_ROOT), "cat-file", "--batch"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    )
    try:
        for oid, path in sorted(blobs.items(), key=lambda kv: kv[1]):
            proc.stdin.write(f"{oid}\n".encode())
            proc.stdin.flush()
            header = proc.stdout.readline().decode(errors="replace").split()
            if len(header) != 3:
                continue  # "<oid> missing"
            size = int(header[2])
            # The payload must be drained even for non-blob objects: leaving it
            # in the pipe desynchronizes every subsequent read and the loop
            # blocks forever on a body it mistakes for a header.
            raw = proc.stdout.read(size)
            proc.stdout.read(1)  # trailing newline
            if header[1] != "blob":
                continue
            text = _decode(raw)
            if text is None:
                continue
            for cls, n in sorted(scan_text(text, owners).items()):
                findings.append(
                    {"class": cls, "location": path, "object": oid[:12], "count": n}
                )
    finally:
        proc.stdin.close()
        proc.wait()
    return findings


def _summarize(findings: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f["class"]] = out.get(f["class"], 0) + f["count"]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tracked", action="store_true",
                    help="scan the tracked working tree (the publish gate)")
    ap.add_argument("--history", action="store_true",
                    help="scan every blob reachable from any ref")
    ap.add_argument("--fail-on-findings", action="store_true",
                    help="exit 1 if any unapproved finding is present")
    ap.add_argument("--redact-output", action="store_true",
                    help="never print matched values (always enforced; the "
                         "flag exists so callers can state the requirement)")
    ap.add_argument("--report", metavar="PATH",
                    help="write a JSON report (classes, locations, counts only)")
    ap.add_argument("--list-classes", action="store_true")
    args = ap.parse_args()

    if args.list_classes:
        for cls in ("home_path", "session_uuid", "archive_dialogue",
                    "private_repo", "credential"):
            print(cls)
        return 0
    if not (args.tracked or args.history):
        ap.error("choose --tracked and/or --history")

    owners = private_owners()
    outstanding: list = []
    result = {"tracked_findings": [], "legacy_findings": [],
              "outstanding_approved": outstanding, "owners_checked": len(owners)}
    if args.tracked:
        result["tracked_findings"] = scan_tracked(owners, outstanding)
    if args.history:
        result["legacy_findings"] = scan_history(owners)
    result["tracked_summary"] = _summarize(result["tracked_findings"])
    result["legacy_summary"] = _summarize(result["legacy_findings"])

    for label, key in (("tracked", "tracked_findings"), ("legacy_history", "legacy_findings")):
        findings = result[key]
        if not findings and (args.tracked if label == "tracked" else args.history):
            print(f"{label}: clean (0 findings)")
            continue
        for f in findings:
            where = f["location"] + (f" @{f['object']}" if "object" in f else "")
            # class, location, count. Never the value.
            print(f"{label}: {f['class']} x{f['count']} in {where}")
        if findings:
            summary = ", ".join(
                f"{c}={n}" for c, n in sorted(_summarize(findings).items())
            )
            print(f"{label}: {len(findings)} finding(s) — {summary}")

    if outstanding:
        print()
        print("OUTSTANDING (approved as `awaiting_operator`, still real):")
        for f in outstanding:
            print(f"  {f['class']} x{f['count']} in {f['location']}")
            print(f"    {f['reason']}")

    if args.report:
        path = Path(args.report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, indent=2, sort_keys=True))
        os.chmod(path, 0o600)
        print(f"report written: {path}")

    if args.fail_on_findings and result["tracked_findings"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
