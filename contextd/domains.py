"""One domain policy, two enforcement points: ingest never writes a blocked
domain, and the gate never discloses one — so extending the list also blocks
disclosure of anything that slipped in before the list knew about it.

Entries are bare domains (suffix match, covers subdomains) or fnmatch globs
against the host (mirror families: "xhamster*.com"). skip_domain_files adds
one-entry-per-line files, accepting hosts-file format ("0.0.0.0 domain")."""

import fnmatch
import os
from pathlib import Path
from urllib.parse import urlsplit

_NOT_DOMAINS = {"localhost", "localhost.localdomain", "broadcasthost", "local",
                "0.0.0.0", "127.0.0.1", "::1", "ip6-localhost", "ip6-loopback"}

_file_cache = {}


def load_skip_domains(cfg):
    exact, globs = set(), []
    for entry in cfg["browser"]["skip_domains"]:
        entry = entry.lower()
        if any(c in entry for c in "*?["):
            globs.append(entry)
        else:
            exact.add(entry)
    for path in cfg["browser"]["skip_domain_files"]:
        p = Path(os.path.expanduser(path))
        if not p.exists():
            continue
        mtime = p.stat().st_mtime
        cached = _file_cache.get(str(p))
        if not cached or cached[0] != mtime:
            entries = set()
            for line in p.read_text().splitlines():
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    entries.add(line.split()[-1])
            _file_cache[str(p)] = (mtime, entries - _NOT_DOMAINS)
        exact |= _file_cache[str(p)][1]
    return exact, globs


def blocked(domains, url: str) -> bool:
    exact, globs = domains
    host = urlsplit(url).netloc.rsplit("@", 1)[-1].split(":")[0].lower()
    if not host:
        return False
    parts = host.split(".")
    suffixes = [".".join(parts[i:]) for i in range(len(parts))]
    if any(s in exact for s in suffixes):
        return True
    return any(fnmatch.fnmatch(s, g) for s in suffixes for g in globs)
