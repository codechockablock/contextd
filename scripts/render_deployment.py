#!/usr/bin/env python3
"""Render the tracked launchd/client templates for this machine.

The tracked files under `launchd/` and `clients/` carry placeholders instead of
absolute paths, because an absolute path is a personal home directory and these
files are published. Rendering happens locally, into a directory git ignores.

    .venv/bin/python scripts/render_deployment.py            # -> build/deploy/
    .venv/bin/python scripts/render_deployment.py --print launchd/com.contextd.watch.plist

Placeholders:

    __CONTEXTD_REPO__     this repository's root
    __CONTEXTD_ARCHIVE__  the archive home (CONTEXTD_HOME, default ~/.contextd)
    __HOME__              the current user's home directory

Rendering writes files, it does not install them. Installing a launchd job or
changing a live client configuration is an operator action; this script
deliberately does not run `launchctl`.
"""

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCES = ("launchd", "clients")
DEFAULT_OUT = REPO_ROOT / "build" / "deploy"


def substitutions() -> dict[str, str]:
    archive = Path(os.environ.get("CONTEXTD_HOME", "~/.contextd")).expanduser()
    return {
        "__CONTEXTD_REPO__": str(REPO_ROOT),
        "__CONTEXTD_ARCHIVE__": str(archive),
        "__HOME__": str(Path.home()),
    }


def render(text: str) -> str:
    for key, value in substitutions().items():
        text = text.replace(key, value)
    return text


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(DEFAULT_OUT),
                    help=f"output directory (default {DEFAULT_OUT})")
    ap.add_argument("--print", dest="show", metavar="PATH",
                    help="render one file to stdout instead of writing")
    args = ap.parse_args()

    if args.show:
        path = REPO_ROOT / args.show
        if not path.is_file():
            print(f"no such template: {args.show}", file=sys.stderr)
            return 2
        sys.stdout.write(render(path.read_text()))
        return 0

    out = Path(args.out)
    written = 0
    for source in SOURCES:
        for path in sorted((REPO_ROOT / source).iterdir()):
            if not path.is_file() or path.name == "README.md":
                continue
            target = out / source / path.name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(render(path.read_text()))
            os.chmod(target, 0o600)
            print(f"rendered {target}")
            written += 1
    print(f"\n{written} file(s) rendered into {out}.")
    print("Nothing was installed. To install a launchd agent, copy it into")
    print("~/Library/LaunchAgents/ and run launchctl yourself.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
