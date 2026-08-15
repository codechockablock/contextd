"""contextd: append-only personal event log + index + gate, served over MCP."""

import json
import os
import tomllib
from pathlib import Path

__version__ = "0.0.1"

DEFAULTS = {
    "ingest": {
        "watch_dirs": [],
        "scan_interval_seconds": 120,
        "never_ingest": ["*/.ssh/*", "*/.aws/*", "*.pem", "*/.env*"],
        "text_extensions": [".md", ".markdown", ".txt", ".text", ".org", ".rst"],
        "max_file_bytes": 2_000_000,
    },
    "browser": {"chrome": True, "safari": True,
                "skip_domains": [], "skip_domain_files": []},
    "claude": {"enabled": True, "projects_dir": "~/.claude/projects",
               "quiet_seconds": 1200, "max_message_chars": 8000},
    "liveness": {
        # staleness thresholds in hours; a stale last event flags pipeline
        # death, never operator behavior — `note` is a deliberate human act
        # and deliberately ships with no threshold. Overriding this table in
        # config.toml replaces the whole set (same rule as [gate.redact]).
        "stale_after_hours": {"chrome": 48, "safari": 48,
                              "claude_code": 48, "fs": 72},
    },
    "lineage": {
        # chain depth of a model-written note: leaf dialogue = 0, a note
        # citing only leaves = 1, a note citing a depth-1 note = 2. Any note
        # past max_note_depth makes `ctx lineage` exit nonzero (DEPTH ALERT)
        # and `ctx status` warn — depth > 1 is where compounding-summary
        # drift becomes structurally possible. audit_sample_per_run sizes
        # hooks/lineage_audit.py's stratified sample. Overriding [lineage]
        # in config.toml replaces this whole table (same rule as [liveness]).
        "max_note_depth": 1,
        "audit_sample_per_run": 8,
    },
    "backup": {
        # where `ctx backup` bundles live for the restore drill ("" means
        # ~/.contextd/backups). The drill is the monitor's monitor: `ctx
        # status` warns when the last drill FAILED, or when a drill has run
        # before but none within this many hours (weekly cadence + one grace
        # day). An archive that has never drilled shows "never run" without
        # warning — staleness flags a drill that died, not one never installed.
        "dir": "",
        "drill_stale_after_hours": 192,
    },
    "security": {
        # "development": the client plane opens the archive directly and the
        # only assurance is attribution. "hardened": only the authority service
        # (contextd/authd.py) opens the archive, every client goes through its
        # closed RPC surface, and a missing service fails closed rather than
        # falling back to SQLite. Switching this on without installing the
        # service makes every archive call fail loudly, which is the intended
        # behaviour — see docs/DEPLOYMENT.md.
        "mode": "development",
        "socket": "",                    # default: <home>/authd.sock
        # An independently protected checkpoint destination the desktop uid
        # cannot rewrite. Empty means rollback resistance is INCOMPLETE, and
        # `ctx security doctor` says so rather than passing.
        "checkpoint_destination": "",
        # Path to the X25519 public key that `ctx security export` seals to,
        # as DER or PEM, mode 0600. Empty means export refuses; export never
        # emits plaintext as a fallback.
        #
        # This names the recipient, it does not AUTHORIZE it: config.toml is
        # writable by the modeled attacker, so the operator's signed action
        # covers the key's sha256 and a swapped file makes the export refuse
        # rather than redirect (contextd/authd.py:_export_action_arguments).
        #
        # The private half belongs on ANOTHER machine. Encryption here protects
        # the bundle once it leaves this host; against a same-UID attacker
        # holding the private key it protects nothing.
        "export_recipient": "",
    },
    "gate": {
        "daily_token_budget": 200_000,
        "max_recall_budget": 32_000,
        "never_leave": ["*/.ssh/*", "*/.aws/*", "*.pem", "*/.env*"],
        # EXTENSION ONLY. The built-in secret-redaction floor lives in
        # contextd/redact.py and always runs; entries here are applied in
        # addition to it. Configuration can add a pattern, never remove or
        # weaken one — under the current threat model whoever can write
        # config.toml is the attacker (docs/SECURITY.md §6).
        "redact": {},
    },
}


def home() -> Path:
    return Path(os.environ.get("CONTEXTD_HOME", "~/.contextd")).expanduser()


def load_config() -> dict:
    cfg = json.loads(json.dumps(DEFAULTS))
    path = home() / "config.toml"
    if path.exists():
        user = tomllib.loads(path.read_text())
        for section, values in user.items():
            if isinstance(values, dict):
                cfg.setdefault(section, {}).update(values)
            else:
                cfg[section] = values
    return cfg
