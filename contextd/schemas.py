"""Closed metadata schemas.

Before this module, ``gate.disclose(conn, cfg, payload, intent: dict)`` wrote
whatever mapping a caller handed it straight into ``events.meta``. Under the
current threat model (docs/SECURITY.md §1) the caller is the attacker, so that
was an arbitrary-content write into an append-only archive: unbounded, never
redacted, and permanent.

Every event type now declares its fields. The rules:

- **Unknown fields are refused**, not dropped. Dropping teaches a caller that
  the field was accepted; refusing tells them it was not.
- **Declared free-text fields are length-bounded and pass the immutable
  redaction floor** (contextd/redact.py) before they reach SQLite, a log, an
  error string, or a display surface.
- **Low-entropy correlation fields are keyed, not hashed.** A plain
  ``sha256(query)`` over a short query is reversible by anyone who can guess
  the query — the same attacker. Such fields declare ``kind="keyed"`` and are
  persisted under a ``*_id`` name (see ``Field.stored_as``); the raw value
  never reaches storage.
- **Nothing here is a semantic filter.** The schema bounds shape and known
  secret classes. It does not and cannot detect arbitrary PII.

The registry below is ground truth, not aspiration: it was built by recording
every ``(source, kind, field)`` triple the suite actually writes. Adding a
field means adding it here, deliberately.
"""

from dataclasses import dataclass

from .correlate import keyed_id
from .redact import (
    MAX_LABEL,
    MAX_TEXT,
    SanitizationError,
    sanitize_label,
    sanitize_text,
)


class SchemaError(ValueError):
    """Metadata does not match the closed schema for its event type."""


@dataclass(frozen=True)
class Field:
    """One declared metadata field.

    kind:
      ``ident``     bounded charset-restricted token (client labels, modes)
      ``text``      free text: floor-redacted, control-stripped, bounded
      ``keyed``     persisted only as a keyed correlation id under
                    ``stored_as``; the raw value is never written
      ``int``       integer (bools refused — ``True`` is not ``1`` here)
      ``number``    int or float (costs, durations, ages)
      ``bool``      real bool
      ``int_list``  list of integers, bounded length
      ``str_list``  list of idents, bounded length
      ``digest``    64-character lowercase hex
      ``scope``     canonical scope string: ``global`` or ``repo:<path>``
      ``scope_obj`` the reducer-facing scope mapping: ``{"global": true}``
                    or ``{"repo": "<path>"}``
      ``instant``   timezone-aware ISO-8601, normalized to UTC
      ``enum``      one of ``choices``
      ``json``      bounded, depth-limited structure; every string inside is
                    floor-redacted and bounded. Declared, not arbitrary.
      ``derivation``  kernel-stamped lineage record (fixed shape)
      ``attestation`` authority-plane authorization block (fixed shape)
    """

    kind: str
    required: bool = False
    max_len: int = 0
    choices: tuple = ()
    max_items: int = 256
    stored_as: str = ""


# --- shared field groups ----------------------------------------------------

# `est_tokens` is stamped by the gate after redaction, never by a caller.
# `client` is a caller-chosen string: it is retained ONLY as the bounded,
# redacted `claimed_client` diagnostic label and carries zero assurance.
_COMMON = {
    "type": Field("ident", required=True, max_len=MAX_LABEL),
    "est_tokens": Field("int"),
    "client": Field("ident", max_len=MAX_LABEL, stored_as="claimed_client"),
    "claimed_client": Field("ident", max_len=MAX_LABEL),
    "items": Field("int_list", max_items=1024),
}

_MODES = ("synthesis", "synthesis_source", "checkpoint", "checkpoint_source")

_DERIVED = {
    "mode": Field("enum", choices=_MODES),
    "source_egress": Field("int"),
    "anchors": Field("int_list", max_items=1024),
    "distiller": Field("ident", max_len=MAX_LABEL),
    "attempt": Field("int"),
    "distill_cost_usd": Field("number"),
    "capability_id": Field("digest"),
}

_SELECTION = {
    # the raw query is never stored: caller-controlled, unbounded, and
    # typically the most sensitive string in the request
    "query": Field("keyed", stored_as="query_id"),
    "query_id": Field("digest"),
    "purpose": Field("text", max_len=512),
    "budget": Field("int"),
    "window": Field("str_list", max_items=4),
}

_CHECKPOINT = {
    **_COMMON, **_SELECTION, **_DERIVED,
    "tip": Field("int"),
    "task_hint": Field("keyed", stored_as="task_hint_id"),
    "task_hint_id": Field("digest"),
    "loop_scope": Field("scope"),
    "scope": Field("scope"),
    "loops_omitted": Field("int_list"),
    "supersessions_omitted": Field("json"),
    "staleness": Field("json"),
    "delegations": Field("json"),
}

# --- egress (disclosure) schemas -------------------------------------------

EGRESS_TYPES: dict = {
    "recall": {**_COMMON, **_SELECTION, **_DERIVED},
    "search": {**_COMMON, **_SELECTION},
    "timeline": {**_COMMON, "window": Field("str_list", max_items=4)},
    "loop_list": {**_COMMON, "scope": Field("scope")},
    "checkpoint": _CHECKPOINT,
    "synthesis": {**_COMMON, **_SELECTION, **_DERIVED},
    # A distillate disclosed with no `type` at all. Registered explicitly so
    # "untyped" is a declared shape rather than an unchecked hole.
    None: {**{k: v for k, v in _COMMON.items() if k != "type"},
           "type": Field("ident", max_len=MAX_LABEL), **_DERIVED},
    # --- harness / experiment disclosure types --------------------------
    "reconcile_dialogue": {
        **_COMMON,
        "arm": Field("ident", max_len=MAX_LABEL),
        "epoch_id": Field("int"),
        "model": Field("ident", max_len=MAX_LABEL),
        "replay_of": Field("int"),
        "session": Field("ident", max_len=128, stored_as="session_id"),
        "session_id": Field("ident", max_len=128),
    },
    "loop_scan": {
        **_COMMON,
        "model": Field("ident", max_len=MAX_LABEL),
        "repo": Field("scope"),
        "session_id": Field("ident", max_len=128),
    },
    "lineage_audit": {
        **_COMMON,
        "judge_sha": Field("digest"),
        "note_id": Field("int"),
    },
    "lineage_calibration": {
        **_COMMON,
        "class": Field("ident", max_len=MAX_LABEL),
        "item_id": Field("ident", max_len=MAX_LABEL),
        "iteration": Field("int"),
        "judge_sha": Field("digest"),
        "phase": Field("ident", max_len=MAX_LABEL),
        "retry_of": Field("int"),
    },
    "experiment": {
        **_COMMON,
        "arm": Field("ident", max_len=MAX_LABEL),
        "exp_id": Field("int"),
        "fixture": Field("ident", max_len=MAX_LABEL),
        "run": Field("int"),
        "task_id": Field("ident", max_len=MAX_LABEL),
    },
    "selection_stress_arm": {
        **_COMMON,
        "arm": Field("ident", max_len=MAX_LABEL),
        "cell_topic": Field("ident", max_len=MAX_LABEL),
    },
    "grant_calibration_judge": {
        **_COMMON,
        "arm": Field("ident", max_len=MAX_LABEL),
        "fid": Field("ident", max_len=MAX_LABEL),
    },
    "openthreads_dialogue": {
        **_COMMON,
        "model": Field("ident", max_len=MAX_LABEL),
        "segment": Field("ident", max_len=MAX_LABEL),
    },
    # A minimal type for tests and one-off probes: one bounded label and no
    # payload fields, so it cannot become a smuggling channel.
    "probe": {**_COMMON, "label": Field("ident", max_len=MAX_LABEL)},
}

for _dialogue in ("board_dialogue", "livethreads_dialogue"):
    EGRESS_TYPES[_dialogue] = {
        **_COMMON,
        "episode": Field("ident", max_len=MAX_LABEL),
        "model": Field("ident", max_len=MAX_LABEL),
        "session": Field("ident", max_len=128, stored_as="session_id"),
        "session_id": Field("ident", max_len=128),
    }

for _variant in ("checkpoint_v2_openloops", "checkpoint_v3_openthreads",
                 "checkpoint_v4_livethreads", "checkpoint_v5_board"):
    EGRESS_TYPES[_variant] = {
        **_CHECKPOINT,
        "arm": Field("ident", max_len=MAX_LABEL),
        "episode": Field("ident", max_len=MAX_LABEL),
        "model": Field("ident", max_len=MAX_LABEL),
        "segment": Field("ident", max_len=MAX_LABEL),
        "session": Field("ident", max_len=128, stored_as="session_id"),
        "session_id": Field("ident", max_len=128),
    }

# --- non-egress event schemas ----------------------------------------------

DISPATCH_STATUSES = ("succeeded", "failed", "timeout")

_AUTHORITY = {
    "authority": Field("ident", max_len=MAX_LABEL),
    "assurance": Field("ident", max_len=MAX_LABEL),
    "client": Field("ident", max_len=MAX_LABEL, stored_as="claimed_client"),
    "claimed_client": Field("ident", max_len=MAX_LABEL),
    "attestation": Field("attestation"),
}

EVENT_SCHEMAS: dict = {
    ("gate", "egress_outcome"): {
        "egress_id": Field("int", required=True),
        "status": Field("enum", required=True, choices=DISPATCH_STATUSES),
        # `exit` and `timeout_seconds` are integers, so they cannot carry
        # text. stdout/stderr/exception strings are refused outright — they
        # were the widest arbitrary-content channel into the archive.
        "exit": Field("int"),
        "timeout_seconds": Field("int"),
    },
    ("eval", "outcome"): {
        "egress_id": Field("int", required=True),
        "verdict": Field("enum", required=True, choices=("hit", "partial", "miss")),
        "failure_class": Field("ident", max_len=MAX_LABEL),
        "note": Field("text", max_len=512),
    },
    ("note", "note"): {
        **_AUTHORITY,
        "actor": Field("ident", max_len=MAX_LABEL),
        "tags": Field("str_list", max_items=32),
        "derivation": Field("derivation"),
        "supersedes": Field("int"),
    },
    ("loop", "loop"): {
        **_AUTHORITY,
        "op": Field("enum", required=True,
                    choices=("add", "candidate", "confirm", "close",
                             "reopen", "dismiss")),
        "loop": Field("int"),
        "scope": Field("scope_obj"),
        "dedupe": Field("ident", max_len=MAX_LABEL),
        "source_events": Field("int_list"),
        "grant": Field("int"),
        "grant_digest": Field("digest"),
        "derivation": Field("derivation"),
    },
    ("grant", "grant"): {
        **_AUTHORITY,
        "op": Field("enum", required=True, choices=("grant", "revoke")),
        "class": Field("ident", max_len=MAX_LABEL),
        "scope": Field("scope_obj"),
        "expires": Field("instant"),
        "grant": Field("int"),
    },
    ("decision", "decision"): {
        **_AUTHORITY,
        "op": Field("enum", required=True, choices=("supersede",)),
        "old": Field("int", required=True),
        "new": Field("int", required=True),
        "grant": Field("int"),
        "grant_digest": Field("digest"),
    },
}

# Ingest-side kinds whose metadata the kernel constructs from what it observed.
INGEST_SCHEMAS: dict = {
    ("fs", "file_write"): {"size": Field("int"), "blob": Field("digest")},
    ("fs", "file_delete"): {},
    ("claude_code", "message"): {
        "role": Field("enum", required=True,
                      choices=("user", "assistant", "delegation", "subagent")),
        "session_id": Field("ident", max_len=128),
        "visited_unix": Field("number"),
    },
    ("claude_code", "epoch"): {
        "session_id": Field("ident", max_len=128),
        "start_event_id": Field("int"),
        "end_event_id": Field("int"),
    },
}
for _browser in ("chrome", "safari"):
    INGEST_SCHEMAS[(_browser, "page_visit")] = {"visited_unix": Field("number")}

# Harness bookkeeping written by experiments/ and hooks/. These are not model
# disclosures, but they are still archive writes, so they are declared and
# bounded like everything else.
HARNESS_SCHEMAS: dict = {
    ("eval", "lineage_audit"): {
        "egress_id": Field("int"), "evidence_ids": Field("int_list"),
        "judge_sha": Field("digest"), "note_age_days": Field("number"),
        "note_id": Field("int"), "spans": Field("json"),
        "verdict": Field("ident", max_len=MAX_LABEL),
    },
    ("eval", "lineage_cal_run"): {
        "class": Field("ident", max_len=MAX_LABEL),
        "dispatch_status": Field("ident", max_len=MAX_LABEL),
        "duration_ms": Field("number"), "egress_id": Field("int"),
        "item_id": Field("ident", max_len=MAX_LABEL),
        "iteration": Field("int"), "judge_sha": Field("digest"),
        "phase": Field("ident", max_len=MAX_LABEL),
        "prompt_version": Field("ident", max_len=MAX_LABEL),
        "spans": Field("json"), "verdict": Field("ident", max_len=MAX_LABEL),
    },
    ("eval", "lineage_judge"): {
        "calibration": Field("json"), "corpus_digest": Field("digest"),
        "judge_sha": Field("digest"), "model": Field("ident", max_len=MAX_LABEL),
        "prereg_id": Field("int"),
        "prompt_version": Field("ident", max_len=MAX_LABEL),
    },
    # The ablation-experiment registry (contextd/experiment.py). These are
    # operator-authored designs and their measured results, not model
    # disclosures — but they are still archive writes, so the key set is
    # closed and every nested string passes the floor. A new spec key must be
    # declared here before it can be preregistered.
    ("eval", "experiment"): {
        "task_id": Field("ident", max_len=128),
        "title": Field("text", max_len=512),
        "model": Field("ident", max_len=MAX_LABEL),
        "spec_sha": Field("digest"),
        "n_per_arm": Field("int"),
        "budget": Field("int"),
        "baseline_arm": Field("ident", max_len=MAX_LABEL),
        "detail_arm": Field("ident", max_len=MAX_LABEL),
        "query": Field("text", max_len=MAX_TEXT),
        "prompt": Field("text", max_len=MAX_TEXT),
        "prompt_template": Field("text", max_len=MAX_TEXT),
        "design_notes": Field("text", max_len=MAX_TEXT),
        "expectation": Field("text", max_len=MAX_TEXT),
        "arms": Field("json"), "rubric": Field("json"),
        "context_sets": Field("json"), "origin_overrides": Field("json"),
        "bm25": Field("json"), "connective": Field("json"),
        "ladder": Field("json"), "stripped": Field("json"),
        "attribution": Field("json"), "frozen": Field("json"),
        "model_settings": Field("json"),
        "context_sets_spec": Field("json"), "frozen_sets": Field("json"),
    },
    ("eval", "exp_run"): {
        "exp_id": Field("int"), "arm": Field("ident", max_len=MAX_LABEL),
        "run": Field("int"), "egress_id": Field("int"),
        "bundle_sha": Field("digest"), "items": Field("int_list", max_items=1024),
        "context_est_tokens": Field("int"),
        "session_id": Field("ident", max_len=128),
        "model": Field("ident", max_len=MAX_LABEL),
        "duration_ms": Field("number"), "cost_usd": Field("number"),
        "usage": Field("json"), "exit": Field("int"),
        # the model's answer is the measurement, so it is retained — bounded
        # and floor-redacted. `stderr` is NOT declared: a subprocess's error
        # stream is the widest arbitrary-content channel there was, and
        # contextd/experiment.py drops it before it reaches here.
        "output": Field("text", max_len=20000),
        "output_sha": Field("digest"), "score": Field("number"),
        "hits": Field("json"), "citations": Field("json"),
    },
    ("eval", "exp_report"): {
        "exp_id": Field("int"), "task_id": Field("ident", max_len=128),
        "model": Field("ident", max_len=MAX_LABEL), "spec_sha": Field("digest"),
        "n_runs": Field("int"), "arms": Field("json"),
        "comparisons": Field("json"), "ladder": Field("json"),
        "fact_rates": Field("json"), "compression_loss": Field("json"),
        "origin_caveats": Field("json"), "interpretation": Field("json"),
        "not_licensed": Field("json"),
    },
    ("eval", "restore_drill"): {
        "bundle": Field("text", max_len=512), "bundle_bytes": Field("int"),
        "failed_stage": Field("ident", max_len=MAX_LABEL),
        "manifest_sha256": Field("digest"), "peak_temp_bytes": Field("int"),
        "probes": Field("int"), "reason": Field("text", max_len=512),
        "stages": Field("json"), "total_seconds": Field("number"),
        "verdict": Field("ident", max_len=MAX_LABEL),
    },
}

_HEX64 = frozenset("0123456789abcdef")
_JSON_MAX_DEPTH = 5
_JSON_MAX_NODES = 512


def _check_int(name, value):
    if isinstance(value, bool) or not isinstance(value, int):
        raise SchemaError(f"field {name!r} must be an integer")
    if not (-(2**63) <= value < 2**63):
        raise SchemaError(f"field {name!r} is out of range")
    return value


def _check_digest(name, value):
    if not isinstance(value, str) or len(value) != 64 or set(value) - _HEX64:
        raise SchemaError(
            f"field {name!r} must be a 64-character lowercase hex digest"
        )
    return value


def _check_scope(name, value):
    """Canonical scope strings only, floor-redacted. A repo path is a private
    name and an arbitrary-content channel; it is bounded and redacted like any
    other declared free-text field."""
    from .redact import redact
    if isinstance(value, dict):
        value = "global" if value.get("global") else f"repo:{value.get('repo', '')}"
    if not isinstance(value, str):
        raise SchemaError(f"field {name!r} must be a scope string")
    if len(value) > 4096:
        raise SchemaError(f"field {name!r} exceeds the scope length bound")
    if value == "global" or value.startswith("repo:") or value.startswith("/"):
        return redact(None, value)
    raise SchemaError(f"field {name!r} must be 'global' or a repo path")


def _check_scope_obj(cfg, name, value):
    """The reducer-facing scope mapping. Closed: exactly one of `global` or
    `repo`, with the path bounded and floor-redacted."""
    from .redact import redact
    if not isinstance(value, dict):
        raise SchemaError(f"field {name!r} must be a scope mapping")
    unknown = set(value) - {"global", "repo"}
    if unknown:
        raise SchemaError(
            f"field {name!r} has unknown key(s): {', '.join(sorted(unknown))}"
        )
    if value.get("global"):
        if not isinstance(value["global"], bool):
            raise SchemaError(f"field {name!r}.global must be a boolean")
        return {"global": True}
    repo = value.get("repo")
    if not isinstance(repo, str) or not repo or len(repo) > 4096:
        raise SchemaError(f"field {name!r} needs a bounded repo path or global=true")
    return {"repo": redact(cfg, repo)}


def _check_instant(name, value):
    """Timezone-aware ISO-8601, normalized to UTC. Naive timestamps are refused
    here so no downstream comparison can silently mix zones."""
    from datetime import datetime, timezone
    if not isinstance(value, str) or len(value) > 64:
        raise SchemaError(f"field {name!r} must be an ISO-8601 instant")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise SchemaError(f"field {name!r} is not a valid instant: {exc}") from exc
    if parsed.tzinfo is None:
        raise SchemaError(
            f"field {name!r} is a naive timestamp; a timezone-aware UTC "
            f"instant is required"
        )
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")


def _check_json(cfg, name, value, depth=0, budget=None):
    """A bounded, depth-limited structure. Every string inside passes the
    redaction floor and the text bound; keys are label-sanitized. This is a
    *declared* structural field, not an arbitrary-content channel."""
    if budget is None:
        budget = [_JSON_MAX_NODES]
    budget[0] -= 1
    if budget[0] < 0:
        raise SchemaError(f"field {name!r} exceeds the structure node bound")
    if depth > _JSON_MAX_DEPTH:
        raise SchemaError(f"field {name!r} exceeds the structure depth bound")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return _check_int(name, value)
    if isinstance(value, float):
        return value
    if isinstance(value, str):
        return sanitize_text(cfg, value, MAX_TEXT)
    if isinstance(value, list):
        return [_check_json(cfg, name, v, depth + 1, budget) for v in value]
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise SchemaError(f"field {name!r} has a non-string key")
            out[sanitize_label(cfg, k, MAX_LABEL)] = _check_json(
                cfg, name, v, depth + 1, budget
            )
        return out
    raise SchemaError(
        f"field {name!r} contains an unsupported type {type(value).__name__}"
    )


def _check_derivation(cfg, name, value):
    """The kernel-stamped lineage record. Its shape is fixed by
    provenance.derivation_of; a caller cannot add keys to it."""
    if not isinstance(value, dict):
        raise SchemaError(f"field {name!r} must be a derivation record")
    allowed = {"source_egress", "anchors", "support", "capability_id"}
    unknown = set(value) - allowed
    if unknown:
        raise SchemaError(
            f"field {name!r} has unknown key(s): {', '.join(sorted(unknown))}"
        )
    out = {}
    if "source_egress" in value:
        out["source_egress"] = _check_int(
            f"{name}.source_egress", value["source_egress"]
        )
    if "anchors" in value:
        anchors = value["anchors"]
        if not isinstance(anchors, list) or len(anchors) > 1024:
            raise SchemaError(f"field {name!r}.anchors must be a bounded list")
        out["anchors"] = [_check_int(f"{name}.anchors", a) for a in anchors]
    if "capability_id" in value:
        out["capability_id"] = _check_digest(
            f"{name}.capability_id", value["capability_id"]
        )
    if "support" in value:
        support = value["support"]
        if not isinstance(support, list) or len(support) > 512:
            raise SchemaError(f"field {name!r}.support must be a bounded list")
        entries = []
        for entry in support:
            if not isinstance(entry, dict) or set(entry) - {
                "event", "quote", "relation"
            }:
                raise SchemaError(f"field {name!r}.support has a malformed entry")
            item = {"event": _check_int(f"{name}.support.event", entry.get("event"))}
            quote = entry.get("quote")
            if not isinstance(quote, str) or not quote or len(quote) > MAX_TEXT:
                raise SchemaError(
                    f"field {name!r}.support.quote must be bounded text"
                )
            # the quote must match disclosed bytes verbatim, so it is bounded
            # but not rewritten; the disclosure it is checked against was
            # itself floor-redacted before it was ever served
            item["quote"] = quote
            if "relation" in entry:
                if entry["relation"] not in ("supports", "contradicts"):
                    raise SchemaError(
                        f"field {name!r}.support.relation is not a known relation"
                    )
                item["relation"] = entry["relation"]
            entries.append(item)
        out["support"] = entries
    return out


def _check_attestation(name, value):
    """The stored operator-authorization block. Written only by the authority
    plane; its exact shape lives in contextd/attest.py."""
    if not isinstance(value, dict):
        raise SchemaError(f"field {name!r} must be an attestation record")
    allowed = {"action", "signature", "key_id", "signer", "verified_at"}
    unknown = set(value) - allowed
    if unknown:
        raise SchemaError(
            f"field {name!r} has unknown key(s): {', '.join(sorted(unknown))}"
        )
    return value


def _coerce(cfg, name: str, spec: Field, value):
    kind = spec.kind
    if kind == "int":
        return _check_int(name, value)
    if kind == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SchemaError(f"field {name!r} must be a number")
        return value
    if kind == "bool":
        if not isinstance(value, bool):
            raise SchemaError(f"field {name!r} must be a boolean")
        return value
    if kind == "digest":
        return _check_digest(name, value)
    if kind == "scope":
        return _check_scope(name, value)
    if kind == "scope_obj":
        return _check_scope_obj(cfg, name, value)
    if kind == "instant":
        return _check_instant(name, value)
    if kind == "json":
        return _check_json(cfg, name, value)
    if kind == "derivation":
        return _check_derivation(cfg, name, value)
    if kind == "attestation":
        return _check_attestation(name, value)
    if kind == "enum":
        if value not in spec.choices:
            raise SchemaError(
                f"field {name!r} must be one of: "
                f"{', '.join(map(str, spec.choices))}"
            )
        return value
    if kind == "ident":
        return sanitize_label(cfg, value, spec.max_len or MAX_LABEL)
    if kind == "text":
        return sanitize_text(cfg, value, spec.max_len or MAX_TEXT)
    if kind == "keyed":
        if isinstance(value, str) and len(value) == 64 and not (set(value) - _HEX64):
            return value  # already a keyed id (re-validation must be stable)
        return keyed_id(spec.stored_as or name, value)
    if kind == "int_list":
        if not isinstance(value, list) or len(value) > spec.max_items:
            raise SchemaError(
                f"field {name!r} must be a list of at most "
                f"{spec.max_items} integers"
            )
        return [_check_int(name, v) for v in value]
    if kind == "str_list":
        if not isinstance(value, list) or len(value) > spec.max_items:
            raise SchemaError(
                f"field {name!r} must be a list of at most "
                f"{spec.max_items} labels"
            )
        return [sanitize_label(cfg, v, spec.max_len or MAX_LABEL) for v in value]
    raise SchemaError(f"field {name!r} has unimplemented kind {kind!r}")


def _validate(cfg, label: str, schema: dict, meta) -> dict:
    if meta is None:
        meta = {}
    if not isinstance(meta, dict):
        raise SchemaError(f"{label} metadata must be a mapping")
    unknown = [k for k in meta if k not in schema]
    if unknown:
        raise SchemaError(
            f"{label} metadata has undeclared field(s): "
            f"{', '.join(sorted(map(str, unknown)))}. Closed schemas refuse "
            f"unknown fields; declare it in contextd/schemas.py or drop it."
        )
    out = {}
    for name, spec in schema.items():
        if name not in meta or meta[name] is None:
            if spec.required:
                raise SchemaError(
                    f"{label} metadata is missing required field {name!r}"
                )
            continue
        try:
            out[spec.stored_as or name] = _coerce(cfg, name, spec, meta[name])
        except SanitizationError as exc:
            raise SchemaError(f"{label} field {name!r}: {exc}") from exc
    return out


def validate_egress_meta(cfg, meta) -> dict:
    """Validate and sanitize one disclosure's metadata against its closed
    schema. Returns the exact mapping that may be persisted."""
    if meta is None:
        meta = {}
    if not isinstance(meta, dict):
        raise SchemaError("disclosure metadata must be a mapping")
    kind = meta.get("type")
    if kind not in EGRESS_TYPES:
        raise SchemaError(
            f"unknown disclosure type {kind!r}; registered types: "
            f"{', '.join(sorted(str(t) for t in EGRESS_TYPES))}"
        )
    return _validate(cfg, f"disclosure {kind!r}", EGRESS_TYPES[kind], meta)


def schema_for(source: str, kind: str) -> dict | None:
    for registry in (EVENT_SCHEMAS, INGEST_SCHEMAS, HARNESS_SCHEMAS):
        if (source, kind) in registry:
            return registry[(source, kind)]
    return None


def validate_event_meta(cfg, source: str, kind: str, meta) -> dict:
    """Validate and sanitize a non-egress event's metadata.

    An event type with no registered schema may not carry metadata at all: an
    unregistered type must never become an arbitrary-content channel.
    """
    schema = schema_for(source, kind)
    if schema is None:
        if meta:
            raise SchemaError(
                f"event type {source}/{kind} has no registered metadata "
                f"schema; register one in contextd/schemas.py before writing "
                f"metadata"
            )
        return {}
    return _validate(cfg, f"event {source}/{kind}", schema, meta)
