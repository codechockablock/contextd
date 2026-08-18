#!/bin/sh
# The gate battery, as one command. Mirrors .github/workflows/ci.yml exactly;
# a lane that passes this locally passes CI. Run from the repo root.
#
#   scripts/gates.sh          # full battery
#   scripts/gates.sh fast     # ruff + pytest only (inner loop)
set -eu

cd "$(dirname "$0")/.."

# Prefer the repo venv, fall back to whatever is on PATH. The hardcoded
# `.venv/bin/python` made this script unrunnable from a git worktree, where
# the venv lives in the main checkout and not beside the source: every stage
# reported "No such file or directory" and the battery exited FAILED without
# having run a single check. A gate that cannot run is worse than no gate,
# because it fails loudly enough to look like it worked.
if [ -x .venv/bin/python ]; then
    PY=.venv/bin/python
    RUFF=.venv/bin/ruff
else
    PY=$(command -v python3 || command -v python)
    RUFF=$(command -v ruff)
    echo "note: no .venv here; using $PY and ${RUFF:-<no ruff>}"
fi

fail=0

echo "== ruff =="
"$RUFF" check . || fail=1

echo "== pytest =="
"$PY" -m pytest -q || fail=1

if [ "${1:-full}" != "fast" ]; then
    echo "== smoke =="
    "$PY" tests/smoke.py || fail=1

    echo "== network grep =="
    # Zero network code is a README commitment. The files allowed to mention
    # network vocabulary (parse-only URL detection, the authority-plane unix
    # socket) are pinned in tests/network_surface.txt; a new match means a
    # new socket surface to justify — by editing the manifest in the same
    # commit that adds it.
    if grep -rl "http\|socket\|urllib\|requests" contextd/ --include='*.py' \
            | sort | diff -u tests/network_surface.txt - ; then
        echo "network grep: matches pinned surface OK"
    else
        echo "network grep: surface changed vs tests/network_surface.txt"
        fail=1
    fi

    echo "== network imports =="
    # The companion to the grep above, and deliberately NOT a replacement for
    # it. The grep is lexical: it sees `socket.socket(...)` the moment it is
    # typed, and it sees network vocabulary in comments and strings. It also
    # cannot tell that `import psycopg` is full network reach with none of its
    # four words in it, or that `urllib.parse` is no network reach at all —
    # which is why most of tests/network_surface.txt is pinned false
    # positives. This one walks the import graph instead and pins capability.
    # Two gates, two failure modes, both cheap.
    "$PY" scripts/network_imports.py || fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "GATES: FAILED"
    exit 1
fi
echo "GATES: ALL PASSED"
