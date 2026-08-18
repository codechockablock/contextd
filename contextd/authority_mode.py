"""The two predicates that say whether the authority plane is in force.

Both of these are authority-plane questions, not daemon-session questions, so
they belong to the evidence core: `db.connect` consults them to decide whether
this process may open the archive at all, and `attest` consults them to decide
whether a first-key bootstrap is standing on the out-of-band boundary it
claims. Code that decides who may write the record is part of the record's
lifecycle.

They used to live in contextd/authd.py. Everything else about `authd` — the
socket, the tiers, the RPC operation table, the session handling — stays in the
daemon, and `authd` re-exports these names so its own callers are unchanged.

**Fail-closed defaults with the daemon absent.** ``is_service_process`` reads a
marker that only the daemon sets, so with no daemon in the process it is False.
False is the *stricter* answer at both core call sites, by construction:

    db._refuse_direct_access      `if not hardened() or is_service_process()`
                                  → False keeps the refusal
    attest._assert_bootstrap_boundary
                                  `if not is_service_process(): raise`
                                  → False raises

So a hardened archive with no authority service running refuses to open rather
than falling back to direct SQLite, which is the behaviour docs/SECURITY.md
already specifies. ``hardened()`` reads configuration rather than daemon state;
its "development" default is the operator's setting, unchanged by this move.
"""

import threading

from . import load_config


def hardened() -> bool:
    """Whether this archive is configured to require the authority plane."""
    return ((load_config().get("security") or {}).get("mode") or
            "development") == "hardened"


# --- the service process ----------------------------------------------------

#: Set only inside the daemon process, before it opens the archive. It is a
#: *marker*, not a security control: a hostile same-UID process can set it too.
#: The real boundary in a hardened deployment is filesystem ownership — the DB
#: is owned by the service UID and mode 0600, so a client cannot open it at all.
#: This flag exists so development mode can simulate the boundary and so the
#: failure is a clear refusal instead of an opaque permission error.
#:
#: Nothing in the core ever sets it. With the daemon absent it stays False,
#: which is the refusing side of every branch that reads it (see the module
#: docstring) — the core cannot mistake its own absence of a daemon for
#: permission it was never granted.
_SERVICE_PROCESS = threading.local()


def is_service_process() -> bool:
    return getattr(_SERVICE_PROCESS, "value", False)


class service_context:
    """Mark the current thread as the authority plane."""

    def __enter__(self):
        self._previous = getattr(_SERVICE_PROCESS, "value", False)
        _SERVICE_PROCESS.value = True
        return self

    def __exit__(self, *_exc):
        _SERVICE_PROCESS.value = self._previous
