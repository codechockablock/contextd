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
    email             an email address, including commit/tag authorship fields

Exit codes: 0 clean (or history mode without --fail-on-findings), 1 findings
with --fail-on-findings, 2 usage/environment error.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from contextd.redact import FLOOR  # noqa: E402

ALLOWLIST_PATH = REPO_ROOT / "scripts" / "repository_privacy_allow.json"
MAX_SCAN_BYTES = 64 * 1024 * 1024

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

EMAIL_RX = re.compile(
    r"(?i)\b[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,253}\.[A-Z]{2,63}\b"
)


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("git repository read failed")
    return result.stdout.decode("utf-8", errors="surrogateescape")


def private_owners() -> set[str]:
    """Owner namespaces treated as private. Derived from the configured remote
    rather than hardcoded, so this file names nobody."""
    owners = set()
    remotes = _git("remote", "-v")
    for match in re.finditer(r"[:/]([A-Za-z0-9_.-]+)/[A-Za-z0-9_.-]+(?:\.git)?\s", remotes):
        owners.add(match.group(1))
    return owners


def _load_allowlist() -> dict:
    if not ALLOWLIST_PATH.exists():
        return {"tracked": {}}
    return json.loads(ALLOWLIST_PATH.read_text())


_SAFE_LOCATION_RX = re.compile(r"[^A-Za-z0-9._/@+-]")


class UnscannedOversized(OSError):
    """A blob is too large for bounded in-memory scanning; the gate must fail."""


def _safe_location(value: str, owners: set[str]) -> str:
    """Make a report location terminal-safe and non-secret-bearing."""
    if _occurrences(value, owners):
        return f"<sensitive-path:{_fingerprint(value)[:12]}>"
    return _SAFE_LOCATION_RX.sub("?", value)[:4096]


def _open_directory_path(path: Path) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise OSError("platform lacks no-follow directory opens")
    absolute = Path(os.path.abspath(os.fspath(path)))
    fd = os.open(os.sep, os.O_RDONLY | directory)
    try:
        for component in absolute.parts[1:]:
            next_fd = os.open(
                component, os.O_RDONLY | directory | nofollow, dir_fd=fd
            )
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_tracked_path(path: Path) -> bytes:
    """Read a tracked file without following a symlink or racing its inode."""
    relative = path.relative_to(REPO_ROOT)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise OSError("platform lacks no-follow opens")
    parent_fd = _open_directory_path(REPO_ROOT)
    try:
        for component in relative.parts[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | nofollow,
                dir_fd=parent_fd,
            )
            os.close(parent_fd)
            parent_fd = next_fd
        name = relative.parts[-1]
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode):
            return os.readlink(name, dir_fd=parent_fd).encode(
                "utf-8", errors="surrogateescape"
            )
        if not stat.S_ISREG(before.st_mode):
            raise OSError("tracked path is not a regular file")
        if before.st_size > MAX_SCAN_BYTES:
            raise UnscannedOversized("tracked blob exceeds scan memory bound")
        flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(name, flags, dir_fd=parent_fd)
        try:
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise OSError("tracked path changed during open")
            if after.st_size > MAX_SCAN_BYTES:
                raise UnscannedOversized("tracked blob exceeds scan memory bound")
            chunks = []
            total = 0
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    return b"".join(chunks)
                total += len(chunk)
                if total > MAX_SCAN_BYTES:
                    raise UnscannedOversized(
                        "tracked blob grew beyond scan memory bound"
                    )
                chunks.append(chunk)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _write_private_report(path: Path, payload: dict) -> None:
    """Create a new 0600 report through symlink-free parent descriptors."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise OSError("platform lacks safe report creation")
    absolute = Path(os.path.abspath(os.fspath(path)))
    if absolute.name in ("", ".", ".."):
        raise OSError("invalid report destination")
    parent_fd = _open_directory_path(absolute.parent)
    try:
        report_fd = os.open(
            absolute.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
            0o600,
            dir_fd=parent_fd,
        )
        try:
            data = json.dumps(payload, indent=2, sort_keys=True).encode()
            view = memoryview(data)
            while view:
                written = os.write(report_fd, view)
                if written <= 0:
                    raise OSError("short report write")
                view = view[written:]
            os.fsync(report_fd)
        except BaseException:
            os.close(report_fd)
            report_fd = -1
            os.unlink(absolute.name, dir_fd=parent_fd)
            raise
        finally:
            if report_fd >= 0:
                os.close(report_fd)
    finally:
        os.close(parent_fd)


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()


def _occurrences(text: str, owners: set[str]) -> list[tuple[str, int, str]]:
    """Return class, 1-based line, and a one-way match fingerprint."""
    found: list[tuple[str, int, str]] = []

    def add(cls: str, match) -> None:
        line = text.count("\n", 0, match.start()) + 1
        found.append((cls, line, _fingerprint(match.group(0))))

    for rx, cls in (
        (HOME_PATH_RX, "home_path"),
        (SESSION_URI_RX, "session_uuid"),
        (UUID_RX, "session_uuid"),
        (BUNDLE_HEADER_RX, "archive_dialogue"),
        (EVENT_RECORD_RX, "archive_dialogue"),
        (EMAIL_RX, "email"),
    ):
        for match in rx.finditer(text):
            add(cls, match)
    for owner in owners:
        rx = re.compile(rf"github\.com[:/]{re.escape(owner)}/[A-Za-z0-9_.-]+")
        for match in rx.finditer(text):
            add("private_repo", match)
    for pattern in FLOOR.values():
        for match in re.finditer(pattern, text):
            add("credential", match)
    return found


def scan_text(text: str, owners: set[str]) -> dict[str, int]:
    """Return counts only; raw matches never cross this API boundary."""
    counts: dict[str, int] = {}
    for cls, _line, _digest in _occurrences(text, owners):
        counts[cls] = counts.get(cls, 0) + 1
    return counts


def _decode_views(raw: bytes) -> list[str]:
    """Decode every blob without binary- or size-based skip cliffs."""
    views = [raw.decode("utf-8", errors="replace")]
    if raw.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        encodings = ("utf-32",)
    elif raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        encodings = ("utf-16",)
    elif b"\x00" in raw[:8192]:
        encodings = ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be")
    else:
        encodings = ()
    if len(raw) >= 2:
        for encoding in encodings:
            try:
                value = raw.decode(encoding)
            except UnicodeError:
                continue
            if value not in views:
                views.append(value)
    return views


def _decode(raw: bytes) -> str:
    """Compatibility view for the credential-triage tool.

    Unlike the retired implementation this never returns ``None`` for binary,
    undecodable, or oversized input, so its caller cannot silently skip one.
    """
    return raw.decode("utf-8", errors="replace")


def scan_bytes(raw: bytes, owners: set[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for text in _decode_views(raw):
        for cls, n in scan_text(text, owners).items():
            counts[cls] = counts.get(cls, 0) + n
    return counts


def _byte_occurrences(raw: bytes, owners: set[str]) -> list[tuple[str, int, str]]:
    found = []
    for text in _decode_views(raw):
        found.extend(_occurrences(text, owners))
    return found


def _approved_counts(occurrences, entry: dict) -> tuple[dict[str, int], int]:
    """Subtract only exact class+line+fingerprint+count approvals."""
    actual: dict[tuple[str, int, str], int] = {}
    for occurrence in occurrences:
        actual[occurrence] = actual.get(occurrence, 0) + 1
    missing = 0
    for expected in entry.get("matches", []):
        key = (
            expected.get("class"),
            expected.get("line"),
            expected.get("sha256"),
        )
        count = expected.get("count")
        if not isinstance(count, int) or count < 1 or actual.get(key, 0) < count:
            missing += 1
            continue
        actual[key] -= count
    counts: dict[str, int] = {}
    for (cls, _line, _digest), count in actual.items():
        if count:
            counts[cls] = counts.get(cls, 0) + count
    return counts, missing


def scan_tracked(owners: set[str], outstanding: list | None = None) -> list[dict]:
    findings = []
    outstanding = outstanding if outstanding is not None else []
    allow = _load_allowlist().get("tracked", {})
    scanned = set()
    for name in _git("ls-files", "-z").split("\0"):
        if not name:
            continue
        scanned.add(name)
        location = _safe_location(name, owners)
        path = REPO_ROOT / name
        try:
            raw = _read_tracked_path(path)
        except UnscannedOversized:
            findings.append(
                {"class": "unscanned_oversized", "location": location, "count": 1}
            )
            continue
        except OSError:
            findings.append(
                {"class": "unreadable", "location": location, "count": 1}
            )
            continue
        occurrences = _byte_occurrences(raw, owners)
        occurrences.extend(
            (cls, 0, digest) for cls, _line, digest in _occurrences(name, owners)
        )
        entry = allow.get(name) or {}
        if entry and (
            entry.get("status") not in {"synthetic", "awaiting_operator"}
            or not isinstance(entry.get("reason"), str)
            or len(entry["reason"]) <= 40
            or not isinstance(entry.get("matches"), list)
        ):
            findings.append(
                {"class": "stale_approval", "location": location, "count": 1}
            )
            entry = {}
        counts, missing = _approved_counts(occurrences, entry)
        if missing:
            findings.append(
                {"class": "stale_approval", "location": location, "count": missing}
            )
        for cls, n in sorted(counts.items()):
            findings.append({"class": cls, "location": location, "count": n})
        if entry.get("status") == "awaiting_operator" and entry.get("matches"):
            by_class: dict[str, int] = {}
            for expected in entry["matches"]:
                cls = expected["class"]
                by_class[cls] = by_class.get(cls, 0) + expected["count"]
            for cls, n in sorted(by_class.items()):
                outstanding.append(
                    {
                        "class": cls,
                        "location": location,
                        "count": n,
                    }
                )
    for name in sorted(set(allow) - scanned):
        findings.append(
            {
                "class": "stale_approval",
                "location": _safe_location(name, owners),
                "count": 1,
            }
        )
    return findings


def scan_history(owners: set[str]) -> list[dict]:
    """Scan every blob reachable from any ref.

    Blobs are addressed by their object id, and the *path* reported is the one
    git recorded for that object — enough for remediation planning, with no
    content in the output.
    """
    listing = _git("rev-list", "--all", "--objects")
    blobs: dict[str, str] = {}
    findings = []
    for line in listing.splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[1].strip():
            oid, path = parts[0], parts[1].strip()
            blobs.setdefault(oid, path)
            for cls, n in sorted(scan_text(path, owners).items()):
                findings.append(
                    {
                        "class": cls,
                        "location": _safe_location(path, owners),
                        "object": oid[:12],
                        "count": n,
                    }
                )
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
                findings.append(
                    {
                        "class": "unreadable",
                        "location": _safe_location(path, owners),
                        "object": oid[:12],
                        "count": 1,
                    }
                )
                continue  # "<oid> missing"
            size = int(header[2])
            # The payload must be drained even for non-blob objects: leaving it
            # in the pipe desynchronizes every subsequent read and the loop
            # blocks forever on a body it mistakes for a header.
            if size > MAX_SCAN_BYTES:
                remaining = size
                while remaining:
                    chunk = proc.stdout.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                proc.stdout.read(1)
                if header[1] == "blob":
                    findings.append(
                        {
                            "class": "unscanned_oversized",
                            "location": _safe_location(path, owners),
                            "object": oid[:12],
                            "count": 1,
                        }
                    )
                continue
            raw = proc.stdout.read(size)
            proc.stdout.read(1)  # trailing newline
            if header[1] != "blob":
                continue
            for cls, n in sorted(scan_bytes(raw, owners).items()):
                findings.append(
                    {
                        "class": cls,
                        "location": _safe_location(path, owners),
                        "object": oid[:12],
                        "count": n,
                    }
                )
    finally:
        proc.stdin.close()
        proc.wait()
    # Blob scans omit commit/tag identity fields and messages.  Scan those
    # reachable objects explicitly so private authorship metadata is visible.
    metadata = [
        (oid, "commit_metadata") for oid in _git("rev-list", "--all").splitlines()
    ]
    refs = _git(
        "for-each-ref", "--format=%(objectname) %(objecttype) %(refname)"
    )
    for line in refs.splitlines():
        parts = line.split(" ", 2)
        if len(parts) != 3:
            continue
        oid, object_type, refname = parts
        for cls, n in sorted(scan_text(refname, owners).items()):
            findings.append(
                {
                    "class": cls,
                    "location": _safe_location(refname, owners),
                    "object": oid[:12],
                    "count": n,
                }
            )
        if object_type == "tag":
            metadata.append((oid, "tag_metadata"))
    for oid, location in metadata:
        try:
            object_size = int(_git("cat-file", "-s", oid).strip())
        except (RuntimeError, ValueError):
            object_size = MAX_SCAN_BYTES + 1
        if object_size > MAX_SCAN_BYTES:
            findings.append(
                {
                    "class": "unscanned_oversized",
                    "location": location,
                    "object": oid[:12],
                    "count": 1,
                }
            )
            continue
        result = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "cat-file", "-p", oid],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            findings.append(
                {
                    "class": "unreadable",
                    "location": location,
                    "object": oid[:12],
                    "count": 1,
                }
            )
            continue
        for cls, n in sorted(scan_bytes(result.stdout, owners).items()):
            findings.append(
                {
                    "class": cls,
                    "location": location,
                    "object": oid[:12],
                    "count": n,
                }
            )
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
        for cls in (
            "home_path",
            "session_uuid",
            "archive_dialogue",
            "private_repo",
            "credential",
            "email",
        ):
            print(cls)
        return 0
    if not (args.tracked or args.history):
        ap.error("choose --tracked and/or --history")

    try:
        owners = private_owners()
        outstanding: list = []
        result = {"tracked_findings": [], "legacy_findings": [],
                  "outstanding_approved": outstanding,
                  "owners_checked": len(owners)}
        if args.tracked:
            result["tracked_findings"] = scan_tracked(owners, outstanding)
        if args.history:
            result["legacy_findings"] = scan_history(owners)
    except (RuntimeError, OSError, ValueError, json.JSONDecodeError):
        print("repository scan failed", file=sys.stderr)
        return 2
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

    if args.report:
        path = Path(args.report)
        try:
            _write_private_report(path, result)
        except OSError:
            print("report write failed", file=sys.stderr)
            return 2
        print("report written")

    if args.fail_on_findings and result["tracked_findings"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
