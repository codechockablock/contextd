#!/bin/sh
# The gate battery, as one command. Mirrors .github/workflows/ci.yml exactly;
# a lane that passes this locally passes CI. Run from the repo root.
#
#   scripts/gates.sh          # full battery
#   scripts/gates.sh fast     # ruff + pytest only (inner loop)
set -eu

cd "$(dirname "$0")/.."
PY=.venv/bin/python

fail=0

echo "== ruff =="
.venv/bin/ruff check . || fail=1

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
fi

if [ "$fail" -ne 0 ]; then
    echo "GATES: FAILED"
    exit 1
fi
echo "GATES: ALL PASSED"
