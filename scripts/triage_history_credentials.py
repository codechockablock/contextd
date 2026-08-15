#!/usr/bin/env python3
"""Classify the `credential` findings in git history WITHOUT emitting any.

`scripts/audit_repository_privacy.py --history` reports that N credential-shaped
strings exist in history. That number is not actionable on its own: a planted
test canary, a regex that matches its own definition, and a real leaked key all
count as one finding each, and only the third matters.

This script closes that gap. It reads the matched values in-process, classifies
each one, and reports **class + location + count only**. A matched value is
never printed, never written to the report, and never copied anywhere. That is
a hard property of this file, asserted by
`tests/test_repository_privacy.py::test_triage_never_emits_a_matched_value`.

Classification, most-confident first. Each rule answers "is there an
explanation for this string other than 'someone leaked a secret'?"

    pattern_definition   the match is regex source — it contains character
                         classes or quantifiers, i.e. this is the code that
                         DEFINES the detector matching itself
    documented_example   a docs/README placeholder: contains an ellipsis,
                         angle-bracket placeholder, or an explicit
                         [REDACTED:...] marker
    planted_canary       a test literal: a long run of one repeated character,
                         a sequential alphabet/digit run, or an explicit
                         marker word (canary/example/placeholder/...)
    reserved_domain      the value points at an RFC 2606 / RFC 6761 reserved
                         documentation or test domain, so it cannot be a
                         working credential for anything
    code_identifier      the regex matched source code, not data: an
                         assignment whose right-hand side is an expression
    pem_header_only      a "-----BEGIN ... KEY-----" delimiter with no base64
                         body — a header carries no key material
    low_entropy          Shannon entropy below the threshold a real key of
                         that length would have — keys are random, canaries
                         usually are not
    UNCLASSIFIED         none of the above. THESE are the ones a human must
                         look at, and the only ones worth rotating over.

The bar is deliberately conservative: anything that does not clearly have an
innocent explanation lands in UNCLASSIFIED. Over-reporting costs an operator a
few minutes; under-reporting costs them a live credential.
"""

import argparse
import collections
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from contextd.redact import FLOOR  # noqa: E402
from scripts.audit_repository_privacy import _decode, _git  # noqa: E402

#: Words that only appear in a value someone invented on purpose.
MARKERS = (
    "canary", "example", "placeholder", "dummy", "fake", "sample", "test",
    "your", "redacted", "changeme", "xxxx", "notreal", "invalid", "demo",
)

#: Regex-source tells. If the "secret" contains these, it is a pattern.
REGEX_TELLS = (
    "[A-Za-z", "[0-9", "[a-z", "{16,", "{10,", "{20,", "{22,", "{35}", "{36}",
    "\\b", "(?:", "(?i)", "[^", "]+", "]{", "\\d", "\\s", ".*", "|",
)

#: Domains RFC 2606 / RFC 6761 reserve for documentation and testing. A value
#: pointing at one of these cannot be a working credential for anything.
RESERVED_DOMAINS = ("example.com", "example.org", "example.net", "example.edu",
                    ".test", ".invalid", ".localhost", ".example")

#: Tells that the regex matched CODE rather than a literal — an assignment whose
#: right-hand side is an expression (a call, an attribute access, a name) has no
#: secret in it at all. `capability_id, secret = raw.split(".", 1)` is the case
#: that motivated this: the pattern sees `secret = raw.split(...)`.
CODE_TELLS = ("(", ")", ".split", ".get", ".pop", "self.", "os.", "args.",
              "kwargs", "[", "]")

#: Documentation placeholder tells.
DOC_TELLS = ("...", "…", "<", ">", "[REDACTED:", "$(", "${", "%s", "{}")

ENTROPY_FLOOR = 3.0          # bits/char; below this a random key is unlikely


def shannon(text: str) -> float:
    if not text:
        return 0.0
    counts = collections.Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def has_repeat_run(text: str, length: int = 6) -> bool:
    return re.search(r"(.)\1{" + str(length - 1) + r",}", text) is not None


def decodes_to_marker(text: str) -> bool:
    """A canary that base64-encodes a marker word is still a canary.

    JWTs and PEM bodies carry base64, so a planted one can say "canary" in a
    form no plain substring search will see. Decoding is the only way to tell
    it apart from a real token of the same shape.
    """
    import base64
    for segment in re.split(r"[.\s\-]+", text):
        if len(segment) < 8:
            continue
        padded = segment + "=" * (-len(segment) % 4)
        try:
            decoded = base64.b64decode(padded, validate=False).decode(
                "utf-8", errors="ignore").lower()
        except Exception:                       # noqa: BLE001
            continue
        if any(marker in decoded for marker in MARKERS):
            return True
    return False


def has_sequential_run(text: str, length: int = 6) -> bool:
    # separators are formatting, not entropy: 123-45-6789 is the canonical
    # placeholder SSN and is sequential once they are removed
    text = re.sub(r"[^A-Za-z0-9]", "", text)
    lowered = text.lower()
    for alphabet in ("abcdefghijklmnopqrstuvwxyz", "0123456789"):
        for i in range(len(alphabet) - length + 1):
            if alphabet[i:i + length] in lowered:
                return True
    return False


#: Tells that the LINE a match sits on is a regex definition rather than data.
#: This matters because a pattern like url_param matches a *fragment* of its own
#: source (`?code=` inside the alternation), and that fragment carries no regex
#: metacharacters — so judging the matched text alone misfiles the definition of
#: the detector as a leak.
LINE_REGEX_TELLS = (
    're.compile', 'r"', "r'", '(?i)', '(?:', '\\b', '[A-Za-z', '[a-z0-9',
    '{16,', '{10,', '{20,', '{22,', '{35}', '"redact"', 'FLOOR', 'pattern',
    'rx =', '_RX', 'MATCH', 'regex',
)

#: Tells that the line is a test asserting on a planted value.
LINE_TEST_TELLS = ('assert', 'CANARIES', 'canary', 'monkeypatch', 'def test_',
                   'planted', 'fixture', 'skip_domains', 'never_leave')


def classify(value: str, path: str, line_text: str = "") -> str:
    """Return a class name. Never returns or logs the value itself.

    Both the match and the line it sits on are considered: a credential-shaped
    fragment inside a regex definition or a test assertion has an explanation
    that the fragment alone does not reveal.
    """
    if any(tell in value for tell in REGEX_TELLS):
        return "pattern_definition"
    if any(tell in line_text for tell in LINE_REGEX_TELLS):
        return "pattern_definition"
    # A match sitting on a comment line is prose, not data. This is how the
    # redaction table's own explanatory comments — "auth-shaped query params in
    # URLs (?code=, &access_token=, ...)" — kept being reported as leaks: the
    # comment illustrates the shape the pattern below it detects.
    stripped = line_text.lstrip()
    if stripped.startswith(("#", "//", "*", "--")) or stripped.startswith('"""'):
        return "documented_example"
    lowered = value.lower()
    # The host is checked on the LINE, not the match: a url_param hit starts at
    # the "?" and so never contains the domain it belongs to.
    if any(domain in lowered or domain in line_text.lower()
           for domain in RESERVED_DOMAINS):
        return "reserved_domain"
    # `name = expression` is code. Split on the first separator and ask whether
    # what follows looks like a Python expression rather than a literal.
    rhs = re.split(r"[:=]", value, maxsplit=1)
    if len(rhs) == 2 and any(tell in rhs[1] for tell in CODE_TELLS) \
            and '"' not in rhs[1] and "'" not in rhs[1]:
        return "code_identifier"
    suffix = Path(path).suffix.lower()
    if suffix in {".md", ".rst", ".txt", ".json"} and (
        any(t in value for t in DOC_TELLS) or "`" in line_text
        or "reason" in line_text or "user:pass" in value
    ):
        return "documented_example"
    if any(marker in lowered for marker in MARKERS):
        return "planted_canary"
    if path.startswith("tests/") and any(t in line_text for t in LINE_TEST_TELLS):
        return "planted_canary"
    # A PEM delimiter with no base64 body carries no key material at all. This
    # happens whenever the header and the body are separate source literals:
    # the pattern matches the header line alone.
    if value.strip().startswith("-----BEGIN") and not re.search(
        r"[A-Za-z0-9+/]{20,}", value.split("-----", 2)[-1]
    ):
        return "pem_header_only"
    if has_repeat_run(value) or has_sequential_run(value) \
            or decodes_to_marker(value):
        return "planted_canary"
    # strip the well-known prefix before measuring; "sk-" is not entropy
    body = re.sub(r"^(?:sk-proj-|sk-ant-|sk-|pk-|ghp_|gho_|ghs_|ghu_|xox[bpars]-|AKIA|ASIA|AIza)",
                  "", value)
    if len(body) >= 12 and shannon(body) < ENTROPY_FLOOR:
        return "low_entropy"
    return "UNCLASSIFIED"


def history_blobs() -> dict:
    listing = _git("rev-list", "--all", "--objects")
    blobs = {}
    for line in listing.splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[1].strip():
            blobs.setdefault(parts[0], parts[1].strip())
    return blobs


def triage() -> dict:
    compiled = [(name, re.compile(pattern)) for name, pattern in FLOOR.items()]
    blobs = history_blobs()
    by_class = collections.Counter()
    by_class_path = collections.defaultdict(collections.Counter)
    unclassified = []

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
                continue
            size = int(header[2])
            raw = proc.stdout.read(size)
            proc.stdout.read(1)
            if header[1] != "blob":
                continue
            text = _decode(raw)
            if text is None:
                continue
            for pattern_name, rx in compiled:
                for match in rx.finditer(text):
                    value = match.group(0)
                    line_start = text.rfind("\n", 0, match.start()) + 1
                    line_end = text.find("\n", match.end())
                    line_text = text[line_start:
                                     line_end if line_end != -1 else len(text)]
                    verdict = classify(value, path, line_text)
                    by_class[verdict] += 1
                    by_class_path[verdict][path] += 1
                    if verdict == "UNCLASSIFIED":
                        line_no = text.count("\n", 0, match.start()) + 1
                        unclassified.append({
                            "pattern": pattern_name,
                            "path": path,
                            "object": oid[:12],
                            "line": line_no,
                            "length": len(value),
                            "entropy_bits_per_char": round(shannon(value), 2),
                        })
    finally:
        proc.stdin.close()
        proc.wait()

    return {
        "total": sum(by_class.values()),
        "by_class": dict(by_class),
        "by_class_and_path": {k: dict(v) for k, v in by_class_path.items()},
        "unclassified": unclassified,
        "note": "No matched value appears anywhere in this report. Locations "
                "are given so a human can inspect them directly.",
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", metavar="PATH")
    args = ap.parse_args()

    result = triage()
    print(f"credential findings in history: {result['total']}")
    print()
    for name, count in sorted(result["by_class"].items(),
                              key=lambda kv: -kv[1]):
        print(f"  {count:5d}  {name}")
        for path, n in sorted(result["by_class_and_path"][name].items(),
                              key=lambda kv: -kv[1])[:6]:
            print(f"         {n:4d}  {path}")
    print()
    if result["unclassified"]:
        print(f"NEEDS HUMAN REVIEW: {len(result['unclassified'])} finding(s) "
              f"have no innocent explanation.")
        for item in result["unclassified"]:
            print(f"  {item['pattern']:20s} {item['path']}:{item['line']} "
                  f"@{item['object']} (len {item['length']}, "
                  f"{item['entropy_bits_per_char']} bits/char)")
        print()
        print("Inspect these yourself; this tool deliberately does not print "
              "them. If any is real, ROTATE IT FIRST — a secret in a pushed "
              "repository must be assumed compromised regardless of whether "
              "the commit is later removed.")
    else:
        print("No finding lacks an innocent explanation.")

    if args.report:
        path = Path(args.report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, indent=2, sort_keys=True))
        os.chmod(path, 0o600)
        print(f"\nreport written: {path}")
    return 1 if result["unclassified"] else 0


if __name__ == "__main__":
    sys.exit(main())
