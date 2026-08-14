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
    "gate": {
        "daily_token_budget": 200_000,
        "max_recall_budget": 32_000,
        "never_leave": ["*/.ssh/*", "*/.aws/*", "*.pem", "*/.env*"],
        # Overriding [gate.redact] in config.toml replaces this whole set.
        "redact": {
            "api_key": r"\b(?:sk|pk)-[A-Za-z0-9_-]{16,}",
            "aws_key": r"\bAKIA[0-9A-Z]{16}\b",
            "github_token": r"\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{36}\b",
            "slack_token": r"\bxox[bpars]-[A-Za-z0-9-]{10,}\b",
            "jwt": r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
            "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----[A-Za-z0-9+/=\r\n]*(?:-----END [A-Z ]*PRIVATE KEY-----)?",
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            # auth-shaped query params in URLs (?code=, &access_token=, ...),
            # including %-encoded ones nested in redirect values (%26state%3D...)
            "url_param": r"(?i)(?:[?&#]|%26|%3f|%23)[a-z0-9_.-]*(?:code|token|auth|nonce|state|secret|passw|pwd|sig|session|key|otp|ticket|csrf|xsrf|sso|jwt|bearer)[a-z0-9_.-]*(?:=|%3d)[^&\s\"'<>]+",
            "card": r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,4}\b",
        },
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
