"""The assurance-resolver registration point, and what happens without it.

`assurance.known_event_assurance` used to reach into contextd/loops.py and
contextd/decisions.py through function-local imports — the evidence core
calling the daemon to find out what its own events mean. Those two branches
now dispatch through a registry the owning modules populate at import time
(lane T, ruling R5/R6).

None of this was covered before the hook existed: the whole suite passes with
both branches deleted outright, which is exactly why the mechanism needs its
own tests rather than trusting the suite to notice.
"""

import subprocess
import sys

import pytest

from contextd.assurance import (
    AUTHENTICATED_HUMAN,
    CAN_DELEGATE,
    RESOLVER_REQUIRED,
    ResolverNotRegistered,
    _RESOLVERS,
    known_event_assurance,
    register_assurance_resolver,
)
from contextd.db import append_event, connect
from contextd.loops import add_loop, make_scope, stored_loop_assurance

REPO = make_scope("/synthetic/lane-t")


def _loop_row(conn, event_id):
    return conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()


def test_known_event_assurance_dispatches_to_the_registered_resolver(
    isolated_contextd_home,
):
    conn = connect()
    loop = add_loop(conn, "verify the resolver actually fires", REPO)["loop"]
    row = _loop_row(conn, loop["id"])

    assert known_event_assurance(conn, row) == stored_loop_assurance(
        conn, loop["id"]
    )


def test_a_reducer_backed_type_without_its_resolver_raises(
    isolated_contextd_home, monkeypatch,
):
    """R9: it must not answer "unverified" as though it had checked.

    Falling back would be true of the BUILD and read as a fact about the
    EVENT — a loop the reducer would resolve to operator_authorized reported
    as unverified, with nothing in the output distinguishing the two.
    """
    conn = connect()
    loop = add_loop(conn, "what happens with an empty registry", REPO)["loop"]
    row = _loop_row(conn, loop["id"])

    monkeypatch.setattr("contextd.assurance._RESOLVERS", {})
    with pytest.raises(ResolverNotRegistered, match="register_assurance_resolver"):
        known_event_assurance(conn, row)


def test_a_type_that_needs_no_reducer_still_falls_back_quietly(
    isolated_contextd_home, monkeypatch,
):
    """The other half of R9: absence is only loud where it changes an answer.

    For a type with no reducer behind it, "nothing checked it" is the whole
    truth rather than a gap, so the metadata-only fallback stands — and it
    still cannot ground a human claim or authorize a delegation.
    """
    conn = connect()
    event_id = append_event(conn, "note", "note", content="an ordinary note")
    row = _loop_row(conn, event_id)

    monkeypatch.setattr("contextd.assurance._RESOLVERS", {})
    level = known_event_assurance(conn, row)

    assert ("note", "note") not in RESOLVER_REQUIRED
    assert level not in AUTHENTICATED_HUMAN
    assert level not in CAN_DELEGATE


@pytest.mark.parametrize("module,source,kind", [
    ("contextd.loops", "loop", "loop"),
    ("contextd.decisions", "decision", "decision"),
])
def test_importing_the_owning_module_registers_its_own_resolver(
    module, source, kind,
):
    """Each module registers its own type, and only its own.

    In a fresh interpreter, because inside this suite the registry is already
    populated by whatever else has been imported — which would make this pass
    without proving anything.
    """
    result = subprocess.run(
        [sys.executable, "-c",
         f"import {module}\n"
         "from contextd.assurance import _RESOLVERS\n"
         f"assert ('{source}', '{kind}') in _RESOLVERS, 'own type unregistered'\n"
         "print('ok')\n"],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("entry_point",
                         ["cli", "mcp_server", "service", "authd"])
def test_every_daemon_entry_point_registers_the_resolvers(entry_point):
    """Registration must not depend on import order elsewhere in the process.

    Run in a fresh interpreter: inside this suite `contextd.loops` is already
    imported by other modules, which would mask a missing registration at the
    entry point itself.
    """
    result = subprocess.run(
        [sys.executable, "-c",
         f"import contextd.{entry_point}\n"
         "from contextd.assurance import _RESOLVERS\n"
         "assert ('loop', 'loop') in _RESOLVERS, 'loop resolver missing'\n"
         "assert ('decision', 'decision') in _RESOLVERS, 'decision missing'\n"
         "print('ok')\n"],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_registration_is_idempotent_and_last_wins():
    original = _RESOLVERS[("loop", "loop")]
    try:
        register_assurance_resolver("loop", "loop", lambda conn, eid: "sentinel")
        assert _RESOLVERS[("loop", "loop")]("x", 1) == "sentinel"
    finally:
        register_assurance_resolver("loop", "loop", original)
    assert _RESOLVERS[("loop", "loop")] is original
