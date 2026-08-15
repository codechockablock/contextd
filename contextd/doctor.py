"""`ctx security doctor` — report each hardening invariant separately.

The design rule here is that a doctor which prints one aggregate verdict is
useless: the operator needs to know *which* property is missing, because the
remedies are different and some of them are "you have not installed the service
yet" rather than "you are under attack".

So every invariant is reported on its own, with:

    ok        the invariant holds
    detail    what was actually observed, not what was expected
    remedy    the exact next action when it does not hold

``--strict`` exits nonzero unless **every** invariant holds. Nothing here
degrades to a pass because a component is absent — an absent protected
checkpoint is a failure of `rollback_resistance`, not an exemption from it.
"""

import json
import os
import stat
from pathlib import Path

from . import home, load_config
from .attest import (DEVELOPMENT_SIGNER_HELPER, INSTALLED_SIGNER_HELPER,
                     SIGNER_SECURE_ENCLAVE, registered_keys)
from .authd import hardened, inspect_deployment, socket_path

INVARIANTS = (
    "protected_daemon",
    "production_signer",
    "raw_archive_inaccessible",
    "service_signatures",
    "protected_checkpoint",
    "no_plaintext_scratch",
    "no_insecure_fallback",
)


def _check(ok: bool, detail: str, remedy: str = "") -> dict:
    out = {"ok": bool(ok), "detail": detail}
    if not ok and remedy:
        out["remedy"] = remedy
    return out


def _protected_daemon(deployment: dict) -> dict:
    """Root-owned installed code, a dedicated service UID, and an archive this
    UID does not own."""
    if not hardened():
        return _check(
            False,
            "security.mode is 'development': the client plane opens the "
            "archive directly and there is no service boundary",
            "set [security] mode = \"hardened\" and install the daemon "
            "(docs/DEPLOYMENT.md §4)",
        )
    code = deployment["installed_code"]
    archive = deployment["archive"]
    if not deployment["service_uid_present"]:
        return _check(False, "no _contextd service account exists",
                      "create the service account (docs/DEPLOYMENT.md §4)")
    if not code.get("exists") or code.get("uid") != 0:
        return _check(
            False,
            f"installed code at /usr/local/libexec/contextd is "
            f"{'absent' if not code.get('exists') else 'not root-owned'}",
            "install the daemon from root-owned code (docs/DEPLOYMENT.md §4)",
        )
    if archive.get("owned_by_caller"):
        return _check(
            False,
            f"the archive is owned by this uid ({deployment['uid']}), so the "
            f"client plane can read and rewrite it",
            "move the archive under the service account "
            "(docs/DEPLOYMENT.md §4)",
        )
    return _check(True, "root-owned installed code, dedicated service uid, "
                        "archive not owned by the calling uid")


def _production_signer(conn) -> dict:
    keys = [k for k in registered_keys(conn)
            if k["signer"] == SIGNER_SECURE_ENCLAVE and not k["revoked"]]
    helper = INSTALLED_SIGNER_HELPER if hardened() else DEVELOPMENT_SIGNER_HELPER
    try:
        helper_info = helper.lstat()
    except OSError:
        return _check(False, f"no signer helper at {helper}",
                      "native/build.sh && sudo native/install.sh, then follow "
                      "docs/OPERATOR_CEREMONY.md")
    if (helper.is_symlink() or not stat.S_ISREG(helper_info.st_mode)
            or (hardened() and (helper_info.st_uid != 0
                                or helper_info.st_mode & 0o022))):
        return _check(
            False, f"signer helper at {helper} is not a protected regular file",
            "reinstall it root-owned and non-writable with sudo native/install.sh",
        )
    if not keys:
        return _check(
            False,
            "no unrevoked Secure Enclave key is registered, so no event can "
            "be operator_authorized",
            "follow docs/OPERATOR_CEREMONY.md for bootstrap or rotation",
        )
    test_keys = [k for k in registered_keys(conn)
                 if k["signer"] != SIGNER_SECURE_ENCLAVE and not k["revoked"]]
    if test_keys:
        return _check(
            False,
            f"{len(test_keys)} non-hardware key(s) are registered; a test "
            f"signer must never be present in a production archive",
            "ctx security key revoke <key-id> for each",
        )
    return _check(True, f"{len(keys)} presence-bound Secure Enclave key(s) "
                        f"registered, no software keys")


def _raw_archive_inaccessible(deployment: dict) -> dict:
    """Can this process, right now, read the raw database?"""
    path = home() / "contextd.db"
    readable = os.access(path, os.R_OK)
    if not hardened():
        return _check(False,
                      "development mode: the raw archive is readable from the "
                      "client boundary",
                      "switch to hardened mode and move the archive under the "
                      "service account")
    if readable:
        return _check(
            False,
            "the raw archive is readable by this uid; the gate can be bypassed "
            "by opening the file",
            "chown the archive to the service account and chmod 0600",
        )
    return _check(True, "the raw archive is not readable from this boundary")


def _service_signatures(conn) -> dict:
    """Service-signed authoritative envelopes and chain tips.

    Two ways this fails, and they mean different things: a *bad* signature is
    tampering, while *no* signatures at all means the layer is present in the
    code but nothing has been signed yet — so integrity still rests on the
    chain and witness, which a same-uid attacker recomputes.
    """
    from .ledger_sig import LedgerSignatureError, key_path, verify_ledger
    try:
        report = verify_ledger(conn)
    except LedgerSignatureError as exc:
        return _check(
            False,
            f"service-signature verification is unavailable: {exc}",
            "run the explicit security migration from the authority plane",
        )
    if report["cutover_anomalies"]:
        return _check(
            False,
            "; ".join(report["cutover_anomalies"]),
            "do not append; establish or repair the signed cutover from a "
            "known-good authority service",
        )
    if report["missing_events"]:
        sample = ", ".join(f"#{n}" for n in report["missing_events"][:8])
        suffix = "…" if len(report["missing_events"]) > 8 else ""
        return _check(
            False,
            f"{len(report['missing_events'])} post-cutover event(s) lack a "
            f"required service signature: {sample}{suffix}",
            "treat the unsigned tail as unaccepted and investigate the "
            "authority append path before any further write",
        )
    if report["bad_events"] or report["bad_tips"]:
        return _check(
            False,
            f"{len(report['bad_events'])} event signature(s) and "
            f"{len(report['bad_tips'])} tip signature(s) do not verify — the "
            f"ledger was altered after acceptance",
            "treat the archive as compromised and restore from a verified "
            "backup before appending anything further",
        )
    if not report["signed_events"] and not report["signed_tips"]:
        return _check(
            False,
            "nothing has been service-signed, so integrity rests on the "
            "SQLite hash chain and the local witness — both of which a "
            "same-uid attacker can recompute",
            "run the authority service so accepted events and chain tips are "
            "signed as they are appended",
        )
    if not key_path().exists():
        return _check(False, "the service signing key is missing",
                      "the authority plane cannot sign; investigate before use")
    if not report["coverage_ok"]:
        return _check(
            False,
            f"signature coverage does not reach current tip "
            f"#{report['current_tip']}",
            "stop the service and investigate the lagging or missing signed tip",
        )
    return _check(
        True,
        f"all {report['required_events']} post-cutover event(s) and current "
        f"tip #{report['current_tip']} are service-signed and verify",
    )


def _protected_checkpoint(conn) -> dict:
    destination = ((load_config().get("security") or {})
                   .get("checkpoint_destination") or "").strip()
    if not destination:
        return _check(
            False,
            "rollback_resistance: incomplete — no independently protected "
            "checkpoint destination is configured, so truncation or wholesale "
            "replacement of the archive is not detectable from local state",
            "select a destination the desktop uid cannot rewrite and set "
            "[security] checkpoint_destination",
        )
    path = Path(destination).expanduser()
    if not path.exists():
        return _check(False,
                      f"no checkpoint has been written to {destination}",
                      "ctx security checkpoint --write")
    try:
        record = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return _check(False, f"the checkpoint at {destination} is unreadable: "
                             f"{type(exc).__name__}",
                      "rewrite it from a known-good archive")
    from .ledger_sig import verify_checkpoint
    result = verify_checkpoint(conn, record)
    if not result["ok"]:
        return _check(False, result["why"],
                      "treat the archive as compromised and investigate before "
                      "appending anything further")
    # A checkpoint the desktop uid can rewrite proves nothing, and this process
    # cannot tell whether the destination is protected — so say so.
    writable = os.access(path, os.W_OK)
    if writable:
        return _check(
            False,
            f"the checkpoint at {destination} verifies but is WRITABLE by this "
            f"uid, so an attacker could roll the archive back and rewrite the "
            f"checkpoint to match",
            "move the checkpoint somewhere this uid cannot rewrite",
        )
    return _check(True, f"checkpoint at tip #{result['tip_id']} verifies and is "
                        f"not writable by this uid")


def _no_plaintext_scratch() -> dict:
    from .scratch import scratch_root
    root = scratch_root()
    leftovers = []
    for entry in root.iterdir():
        if entry.name.startswith("contextd-"):
            leftovers.append(entry.name)
    if leftovers:
        return _check(
            False,
            f"{len(leftovers)} scratch director(ies) present: plaintext may be "
            f"on disk outside service-owned storage",
            "no process should hold scratch at rest; investigate before "
            "removing, then `ctx security doctor` again",
        )
    mode = stat.S_IMODE(os.stat(root).st_mode)
    if mode != 0o700:
        return _check(False, f"scratch root mode is {oct(mode)}, not 0o700",
                      f"chmod 700 {root}")
    return _check(True, "no scratch at rest, scratch root is 0700")


def _no_insecure_fallback(conn) -> dict:
    """Nothing in the tree provides a non-hardware path to operator authority."""
    from . import attest
    problems = []
    if os.environ.get(attest.TEST_MODE_ENV) == "1":
        problems.append(
            f"{attest.TEST_MODE_ENV}=1 is set in this environment: the "
            f"test-only software signer is enabled"
        )
    software = [k for k in registered_keys(conn)
                if k["signer"] != SIGNER_SECURE_ENCLAVE and not k["revoked"]]
    if software:
        problems.append(f"{len(software)} software key(s) registered")
    if not hardened():
        problems.append("development mode permits direct SQLite access")
    if problems:
        return _check(False, "; ".join(problems),
                      "unset the test-signer variable, revoke software keys, "
                      "and switch to hardened mode")
    return _check(True, "no test signer, no software keys, no direct-SQLite "
                        "path")


def run(conn=None) -> dict:
    """Evaluate every invariant. Never raises for a failing invariant — a
    failure is a reported result, not an exception."""
    own = conn is None
    if own:
        try:
            from .db import connect
            conn = connect()
        except Exception as exc:            # noqa: BLE001
            conn = None
            open_error = f"{type(exc).__name__}: {exc}"
        else:
            open_error = ""
    else:
        open_error = ""

    deployment = inspect_deployment()
    try:
        checks = {
            "protected_daemon": _protected_daemon(deployment),
            "production_signer": (
                _production_signer(conn) if conn is not None
                else _check(False, f"cannot inspect the key registry: "
                                   f"{open_error}",
                            "run this from the authority plane")),
            "raw_archive_inaccessible": _raw_archive_inaccessible(deployment),
            "service_signatures": (
                _service_signatures(conn) if conn is not None
                else _check(False, "not implemented", "implement Mission 6")),
            "protected_checkpoint": (
                _protected_checkpoint(conn) if conn is not None
                else _check(False, "cannot inspect the archive",
                            "run this from the authority plane")),
            "no_plaintext_scratch": _no_plaintext_scratch(),
            "no_insecure_fallback": (
                _no_insecure_fallback(conn) if conn is not None
                else _check(False, "cannot inspect the key registry",
                            "run this from the authority plane")),
        }
    finally:
        if own and conn is not None:
            conn.close()

    failing = [name for name, result in checks.items() if not result["ok"]]
    return {
        "mode": "hardened" if hardened() else "development",
        "socket": str(socket_path()),
        "invariants": checks,
        "failing": failing,
        "hardened": not failing,
        "summary": (
            "production is hardened"
            if not failing else
            f"NOT hardened: {len(failing)} of {len(checks)} invariants fail "
            f"({', '.join(failing)})"
        ),
    }


def format_report(report: dict) -> str:
    lines = [f"contextd security doctor — mode: {report['mode']}", ""]
    for name in INVARIANTS:
        result = report["invariants"][name]
        mark = "ok  " if result["ok"] else "FAIL"
        lines.append(f"  [{mark}] {name}")
        lines.append(f"         {result['detail']}")
        if result.get("remedy"):
            lines.append(f"         -> {result['remedy']}")
    lines.append("")
    lines.append(report["summary"])
    return "\n".join(lines)


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="report hardening invariants")
    parser.add_argument("--strict", action="store_true",
                        help="exit nonzero unless every invariant holds")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    report = run()
    print(json.dumps(report, indent=2, sort_keys=True) if args.json
          else format_report(report))
    if args.strict and report["failing"]:
        return 1
    return 0


def checkpoint_path() -> Path:                  # pragma: no cover - interface
    """Where a protected checkpoint would live. Interface only; Mission 6."""
    return home() / "checkpoint.json"
