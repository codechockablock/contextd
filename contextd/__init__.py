"""contextd: append-only personal event log + index + gate, served over MCP."""

import json
import os
import tomllib
from pathlib import Path

__version__ = "0.6.0"

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
        # only assurance is attribution. "hardened": every archive call FAILS
        # CLOSED — the resident authority service that used to be the only
        # process allowed to open a hardened archive was removed (lane X,
        # residency dissolution), and refusal is the daemon-absent behaviour
        # docs/SECURITY.md always specified. There is no direct-SQLite
        # fallback. The one hardened path that still runs is the out-of-band
        # first-key bootstrap ceremony (ctx security key bootstrap).
        "mode": "development",
        # There is deliberately no signer-selection key here. Selecting among
        # already-registered keys authorizes nothing, but config must not name
        # a signer in any sense — test_config_and_env_cannot_name_a_signer
        # keeps the word out of the config surface entirely so no future
        # setting can grow signing semantics. Per-act selection is
        # `ctx --signer-key TAG` (contextd/cli.py), which is not ambient.
        # An independently protected checkpoint destination the desktop uid
        # cannot rewrite. Empty means rollback resistance is INCOMPLETE, and
        # `ctx security doctor` says so rather than passing.
        "checkpoint_destination": "",
        # How many events may pass before the chain tip is checkpointed again.
        # This number IS the exposure window: events appended since the last
        # checkpoint are covered by local state only, so an attacker who owns
        # the archive can roll back up to this many events without
        # contradicting a signature they cannot forge. 100 is chosen as a
        # window small enough that the loss is a session rather than a history,
        # and large enough that the post-quantum signing cost (~2.4 KB and a
        # keygen-free sign per checkpoint) stays off the per-event path — the
        # tradeoff is spelled out in docs/SECURITY.md. 0 disables.
        "checkpoint_interval_events": 100,
        # Additional NIST-standardized schemes each checkpoint is signed under,
        # on top of the classical one that is always present: currently
        # "ml-dsa-44", "ml-dsa-65", or "ml-dsa-87" (FIPS 204). Empty means
        # classical only, so a base install does not start depending on ML-DSA
        # merely by upgrading. This names an ALGORITHM, never a key — see
        # ledger_sig.checkpoint_algorithms for why that distinction is what
        # keeps it off the signer-selection surface.
        "checkpoint_algorithms": [],
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
