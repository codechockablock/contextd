#!/usr/bin/env python3
"""The import-level companion to `scripts/gates.sh`'s network grep.

WHY A SECOND GATE
-----------------
"Zero network code" is a README commitment, and the gate defending it greps
`contextd/` for the words `http`, `socket`, `urllib`, `requests`. That gate is
worth keeping — it catches a raw `socket.socket()` the moment it is typed, and
it catches vocabulary in comments and strings that an import graph never sees.

But it is lexical, and it therefore cannot see the thing that actually matters:
**capability arrives through dependencies, not through spelling.** A module
that writes ``import psycopg`` has full network reach and contains none of the
four words. A module that writes ``from urllib.parse import urlparse`` has no
network reach at all and contains one of them. The grep gets both backwards,
and the second case is why its manifest has thirteen entries that are mostly
false positives it had to be told to ignore.

So this walks the import graph instead:

* every ``*.py`` under ``contextd/`` is parsed with ``ast``, and every
  ``Import``/``ImportFrom`` node is collected — including ones inside function
  bodies, which is where the interesting ones live (`db.py` imports
  ``.backends`` inside a function; `postgres.py` imports its driver inside
  one);
* imports of other ``contextd`` modules become edges in a graph, and each
  module's reach is the transitive closure over those edges — so a module that
  imports a module that imports ``psycopg`` is reported as reaching ``psycopg``,
  with the path that got it there;
* anything reaching the socket-capable set is diffed against
  ``tests/network_imports.txt``. A new entry fails the gate until the manifest
  is updated in the same commit, exactly like the lexical gate.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It does not execute anything, it does not import contextd, and it uses only
the standard library — a gate that has to build the thing it is auditing is a
gate that stops running the day the build breaks. It also does not resolve
imports *inside* third-party packages: ``mcp`` is flagged by name because of
what it is, not because this script traced its internals. Doing otherwise
would mean parsing site-packages, which changes with every environment and
would make the manifest unpinnable.

USAGE
    python scripts/network_imports.py            # check against the manifest
    python scripts/network_imports.py --list     # print the current surface
    python scripts/network_imports.py --explain  # print it with import paths
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE = REPO_ROOT / "contextd"
MANIFEST = REPO_ROOT / "tests" / "network_imports.txt"

# --- what counts as network capability --------------------------------------
#
# Keyed by the most specific dotted prefix that carries the capability, so that
# a submodule which does NOT carry it can be excluded by simply not appearing.
# `urllib.parse` versus `urllib.request` is the whole reason this is a prefix
# table and not a set of top-level names: the lexical gate cannot tell them
# apart, and eight of its thirteen pinned files are there only because they
# parse URLs.

NETWORK_STDLIB = {
    "socket": "raw sockets (AF_INET or AF_UNIX; the module cannot tell you which)",
    "socketserver": "socket server framework",
    "ssl": "TLS over a socket",
    "asyncio": "event loop with open_connection/start_server",
    "http": "HTTP; http.client dials out and http.server listens",
    "urllib.request": "opens URLs over the network",
    "urllib.error": "errors from urllib.request; implies it",
    "ftplib": "FTP client",
    "smtplib": "SMTP client",
    "poplib": "POP3 client",
    "imaplib": "IMAP client",
    "nntplib": "NNTP client",
    "telnetlib": "telnet client",
    "xmlrpc": "XML-RPC over HTTP",
    "webbrowser": "hands a URL to a browser process, which then dials out",
}

# Deliberately NOT network-capable. Listed rather than merely omitted, so that
# each exclusion is a decision on the record instead of a gap someone has to
# guess at. A prefix here overrides a less specific entry above.
NETWORK_STDLIB_EXEMPT = {
    "urllib.parse": "URL parsing; performs no I/O. This is the distinction the "
                    "lexical gate cannot draw, and the reason most of its "
                    "thirteen pinned files are pinned",
    "http.cookies": "cookie header parsing; performs no I/O",
    "email": "message parsing; performs no I/O",
    "ipaddress": "address parsing; performs no I/O",
    "select": "readiness on file descriptors; opens nothing itself",
    "selectors": "readiness on file descriptors; opens nothing itself",
}

NETWORK_THIRD_PARTY = {
    "psycopg": "PostgreSQL wire protocol over TCP",
    "psycopg2": "PostgreSQL wire protocol over TCP",
    "requests": "HTTP client",
    "httpx": "HTTP client",
    "urllib3": "HTTP client",
    "aiohttp": "async HTTP client and server",
    "websockets": "WebSocket client and server",
    "grpc": "gRPC over HTTP/2",
    "boto3": "AWS API client",
    "botocore": "AWS API client",
    "paramiko": "SSH client",
    "redis": "Redis wire protocol over TCP",
    "pymongo": "MongoDB wire protocol over TCP",
    "mcp": "MCP transport; ships stdio and HTTP/SSE server transports",
}


def capability_for(dotted: str) -> tuple[str, str] | None:
    """Return (capability name, why) if `dotted` reaches the network.

    Matches on dotted prefixes, longest first, so a specific exemption beats a
    general capability.
    """
    parts = dotted.split(".")
    prefixes = [".".join(parts[: i + 1]) for i in range(len(parts))]
    for prefix in reversed(prefixes):
        if prefix in NETWORK_STDLIB_EXEMPT:
            return None
        if prefix in NETWORK_STDLIB:
            return prefix, NETWORK_STDLIB[prefix]
        if prefix in NETWORK_THIRD_PARTY:
            return prefix, NETWORK_THIRD_PARTY[prefix]
    return None


# --- the import graph -------------------------------------------------------


def module_name(path: Path) -> str:
    """`contextd/backends/postgres.py` -> `contextd.backends.postgres`."""
    rel = path.relative_to(REPO_ROOT).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _resolve_relative(node: ast.ImportFrom, current: str) -> str:
    """Turn a relative import into an absolute dotted name.

    `current` is the importing module. A level-1 import inside
    `contextd.backends.postgres` is relative to `contextd.backends`; inside a
    package `__init__` it is relative to the package itself.
    """
    base = current.split(".")
    # `contextd.backends.postgres` at level 1 -> `contextd.backends`
    for _ in range(node.level):
        if base:
            base.pop()
    if node.module:
        base.append(node.module)
    return ".".join(base)


def imports_of(path: Path) -> set[str]:
    """Every dotted name this file imports, from anywhere in the file.

    Function-local imports are included on purpose: they are how contextd keeps
    optional dependencies optional, which makes them exactly the ones a network
    audit must not miss.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    current = module_name(path)
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                base = _resolve_relative(node, current)
            if not base:
                continue
            found.add(base)
            # `from contextd.backends import postgres` names a module, while
            # `from contextd import home` names one too. Record both readings;
            # the graph keeps only those that resolve to real files.
            for alias in node.names:
                found.add(f"{base}.{alias.name}")
    return found


def build_graph() -> tuple[dict[str, set[str]], dict[str, set[str]], dict[str, Path]]:
    """Return (internal edges, external imports, module -> path)."""
    paths = sorted(
        p for p in PACKAGE.rglob("*.py") if "__pycache__" not in p.parts
    )
    by_name = {module_name(p): p for p in paths}
    internal: dict[str, set[str]] = {}
    external: dict[str, set[str]] = {}
    for path in paths:
        name = module_name(path)
        internal[name], external[name] = set(), set()
        for dotted in imports_of(path):
            if dotted in by_name and dotted != name:
                internal[name].add(dotted)
            elif not dotted.startswith("contextd"):
                external[name].add(dotted)
    return internal, external, by_name


def direct_capabilities(
    external: dict[str, set[str]],
) -> dict[str, set[str]]:
    """Capabilities each module imports itself, with no help from a neighbour.

    This is the set that matters most: it is where network capability *enters*
    the package. Everything else is inheritance.
    """
    direct: dict[str, set[str]] = {}
    for module, imports in external.items():
        for dotted in imports:
            hit = capability_for(dotted)
            if hit is not None:
                direct.setdefault(module, set()).add(hit[0])
    return direct


def reachable_capabilities(
    internal: dict[str, set[str]], direct: dict[str, set[str]],
) -> dict[str, dict[str, str]]:
    """For each module, each capability it reaches and how it got there.

    The value is either ``"direct"`` — the module imports it itself — or a
    ``+``-joined list of the internal modules where that capability enters, in
    sorted order.

    Naming the *entry points* rather than a shortest path is what makes the
    manifest stable: a refactor that reroutes an import does not churn the
    file, while adding a genuinely new way for capability to enter the package
    does. And a module that starts importing something directly flips from
    ``via:...`` to ``direct``, so the gate fires even for a module that already
    reached that capability by inheritance.
    """
    result: dict[str, dict[str, str]] = {}
    for start in internal:
        # Transitive closure over internal edges only.
        seen = {start}
        queue = [start]
        while queue:
            node = queue.pop()
            for nxt in internal.get(node, ()):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)

        entries: dict[str, set[str]] = {}
        for node in seen:
            for capability in direct.get(node, ()):
                entries.setdefault(capability, set()).add(node)
        if not entries:
            continue
        described: dict[str, str] = {}
        for capability, sources in entries.items():
            if start in sources:
                described[capability] = "direct"
            else:
                described[capability] = "via:" + "+".join(sorted(sources))
        result[start] = described
    return result


# --- manifest -------------------------------------------------------------


def surface_lines(surface: dict[str, dict[str, str]]) -> list[str]:
    """The machine-diffable form: one line per module, capabilities sorted."""
    lines = []
    for module in sorted(surface):
        caps = ", ".join(
            f"{name}={surface[module][name]}" for name in sorted(surface[module])
        )
        lines.append(f"{module}: {caps}")
    return lines


def read_manifest() -> list[str]:
    if not MANIFEST.exists():
        return []
    return [
        line.strip()
        for line in MANIFEST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def current_surface() -> dict[str, dict[str, str]]:
    internal, external, _ = build_graph()
    return reachable_capabilities(internal, direct_capabilities(external))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true",
                        help="print the current surface in manifest form")
    parser.add_argument("--explain", action="store_true",
                        help="print the current surface with import paths")
    args = parser.parse_args(argv)

    surface = current_surface()

    if args.explain:
        entries = sorted(
            (m for m in surface if "direct" in surface[m].values()),
        )
        print("WHERE NETWORK CAPABILITY ENTERS contextd/")
        print("")
        for module in entries:
            for capability, how in sorted(surface[module].items()):
                if how != "direct":
                    continue
                why = (NETWORK_STDLIB.get(capability)
                       or NETWORK_THIRD_PARTY.get(capability, ""))
                print(f"  {module}")
                print(f"      imports {capability} directly - {why}")
        print("")
        print("WHAT INHERITS IT")
        print("")
        for module in sorted(surface):
            inherited = {c: h for c, h in surface[module].items()
                         if h != "direct"}
            if not inherited:
                continue
            for capability, how in sorted(inherited.items()):
                print(f"  {module:<34} {capability:<10} {how}")
        return 0

    lines = surface_lines(surface)
    if args.list:
        print("\n".join(lines))
        return 0

    pinned = read_manifest()
    if lines == pinned:
        print(f"network imports: {len(lines)} module(s) match "
              f"tests/network_imports.txt OK")
        return 0

    print("network imports: the import-level network surface CHANGED.")
    print("")
    current, expected = set(lines), set(pinned)
    for line in sorted(expected - current):
        print(f"  - {line}")
    for line in sorted(current - expected):
        print(f"  + {line}")
    print("")
    print("A `+` line is a module that can now reach the network and could not")
    print("before. If that is intended, add it to tests/network_imports.txt in")
    print("the SAME commit, with a comment saying why it is allowed. Run")
    print("`python scripts/network_imports.py --explain` for the import path.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
