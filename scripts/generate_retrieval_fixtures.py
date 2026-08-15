#!/usr/bin/env python3
"""Regenerate the two retrieval fixtures from deterministic synthetic data.

`experiments/tasks/retrieval-contradiction-sets.json` and
`retrieval-synthesis-sets.json` were frozen selections taken from the
operator's live archive. Tracked in git, they carried real event ids, real
`claude://` session identifiers, absolute personal paths, and verbatim private
dialogue — permanently, in published history.

The fixtures exist to exercise *retrieval structure*: a contradiction set needs
two items that disagree plus distractors; a synthesis set needs items whose
combination says more than either alone. None of that requires real data.

This generator emits the same schema from a fixed corpus about a fictional
project, with:

  - synthetic event ids in a low range that cannot collide with a real archive
  - fixed UTC timestamps
  - no session identifiers, no personal paths, no private repository names
  - `sha` and `est_tokens` computed exactly as ``contextd.experiment.freeze``
    computes them, so a consumer cannot tell the difference structurally

Output is byte-stable: running it twice produces identical files. It also
writes `retrieval-sets-provenance.json`, a machine-readable manifest recording
that these files are synthetic, what generated them, and the digest of each.

    .venv/bin/python scripts/generate_retrieval_fixtures.py
"""

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TASKS = REPO_ROOT / "experiments" / "tasks"
GENERATOR_VERSION = 1

# A fictional project. Deliberately not the operator's own work, and using the
# house-standard generic names (sample_store / demo_hardware).
CORPUS = [
    # --- the contradiction pair -------------------------------------------
    dict(
        id=1001, ts="2026-03-02T09:14:00+00:00", source="note", kind="note",
        uri=None, provenance="model", transport_role="mcp", origin="model",
        epistemic_type="model_inference",
        text=(
            "ledgerd design call 2026-03-02: the write path will fsync on every "
            "append. Durability is the product; a lost tail event is worse than "
            "a slow one. Measured cost on demo_hardware: 1.9ms per append, "
            "which the 40/second ceiling absorbs."
        ),
    ),
    dict(
        id=1042, ts="2026-03-19T16:40:00+00:00", source="note", kind="note",
        uri=None, provenance="model", transport_role="mcp", origin="model",
        epistemic_type="model_inference",
        text=(
            "ledgerd design reversal 2026-03-19: per-append fsync is out. The "
            "sample_store pilot appends in bursts of 300 and the 1.9ms figure "
            "was measured single-threaded; under burst load it compounds to a "
            "9 second stall. Group commit every 50ms replaces it, and the "
            "durability window is now documented as 50ms rather than zero."
        ),
    ),
    # --- the synthesis pair (neither item alone carries the conclusion) ----
    dict(
        id=1067, ts="2026-04-04T11:02:00+00:00", source="note", kind="note",
        uri=None, provenance="model", transport_role="mcp", origin="model",
        epistemic_type="model_inference",
        text=(
            "sample_store pilot telemetry week 3: 82% of reads request the most "
            "recent 40 events. The tail is hot and the body is cold; nothing "
            "older than a week was read more than twice."
        ),
    ),
    dict(
        id=1071, ts="2026-04-05T08:25:00+00:00", source="note", kind="note",
        uri=None, provenance="model", transport_role="mcp", origin="model",
        epistemic_type="model_inference",
        text=(
            "ledgerd index cost review: the full-text index is 61% of on-disk "
            "size and is rebuilt over the whole corpus on every schema change, "
            "which now takes 22 minutes on demo_hardware."
        ),
    ),
    # --- distractors: on-topic, retrievable, carrying no conclusion -------
    dict(
        id=1015, ts="2026-03-08T13:30:00+00:00", source="fs", kind="file_write",
        uri="/srv/demo/ledgerd/NOTES.md", provenance="human",
        transport_role="fs", origin="human", epistemic_type="observation",
        text=(
            "# ledgerd notes\n\nAppend-only store for the sample_store pilot. "
            "Open question: whether the index belongs in the same file as the "
            "log or beside it."
        ),
    ),
    dict(
        id=1023, ts="2026-03-11T10:05:00+00:00", source="chrome",
        kind="page_visit", uri="https://example.invalid/docs/wal-format",
        provenance="activity", transport_role="chrome", origin="activity",
        epistemic_type="observation",
        text="Write-Ahead Logging format https://example.invalid/docs/wal-format",
    ),
    dict(
        id=1030, ts="2026-03-14T15:47:00+00:00", source="note", kind="note",
        uri=None, provenance="human", transport_role="cli", origin="human",
        epistemic_type="claimed_human_assertion",
        text=(
            "Decision for the pilot: no network code in the ledgerd core. The "
            "sync layer, if it ever exists, is a separate binary with its own "
            "review."
        ),
    ),
    dict(
        id=1055, ts="2026-03-27T09:00:00+00:00", source="note", kind="note",
        uri=None, provenance="model", transport_role="mcp", origin="model",
        epistemic_type="model_inference",
        text=(
            "ledgerd backup format v1: a directory bundle with a hashed "
            "manifest. Restore is verified by comparing the restored tip "
            "against the manifest's recorded snapshot."
        ),
    ),
    dict(
        id=1060, ts="2026-04-01T14:20:00+00:00", source="note", kind="note",
        uri=None, provenance="model", transport_role="mcp", origin="model",
        epistemic_type="model_inference",
        text=(
            "Retention policy draft: nothing is deleted; superseding entries "
            "outrank their predecessors and the predecessor stays readable. "
            "This is the same rule the audit trail relies on."
        ),
    ),
]

BY_ID = {item["id"]: item for item in CORPUS}

# Ids present in the corpus but deliberately excluded from a given set: they
# stand in for "the search matched these, the budget did not take them".
DISTRACTOR_POOL = [1015, 1023, 1030, 1055, 1060]

SETS = {
    "retrieval-contradiction-sets.json": {
        "bm25": dict(
            query="ledgerd fsync durability append group commit burst stall",
            budget=2200, items=[1001, 1042, 1055, 1023],
        ),
        "connective": dict(
            query="ledgerd fsync durability reversal measured burst pilot",
            budget=2200, items=[1001, 1042, 1030, 1055, 1060],
        ),
        "stripped": dict(
            query="ledgerd durability append",
            budget=2200, items=[1001, 1015, 1023, 1030, 1055, 1060, 1067, 1071, 1042],
        ),
    },
    "retrieval-synthesis-sets.json": {
        "bm25": dict(
            query="ledgerd index size rebuild read distribution tail hot cold",
            budget=2200, items=[1067, 1071, 1015, 1055, 1060],
        ),
        "connective": dict(
            query="ledgerd index cost recent reads pilot telemetry",
            budget=2200, items=[1067, 1071, 1030, 1023],
        ),
        "stripped": dict(
            query="ledgerd index reads",
            budget=2200, items=[1067, 1071, 1055],
        ),
    },
}

UNTIL = "2026-04-10T00:00:00"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _est_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def _render(item: dict) -> dict:
    """Reproduce exactly what contextd.experiment.freeze records per item."""
    header = (
        f"--- [{item['id']}] {item['ts']} {item['source']}/{item['kind']} "
        f"{item['uri'] or ''} ---"
    )
    text = item["text"]
    return {
        "id": item["id"], "ts": item["ts"], "source": item["source"],
        "kind": item["kind"], "uri": item["uri"],
        "provenance": item["provenance"],
        "transport_role": item["transport_role"],
        "origin": item["origin"], "origin_basis": "recorded",
        "epistemic_type": item["epistemic_type"],
        "est_tokens": _est_tokens(header + text),
        "header": header, "text": text,
        "sha": _sha(header + "\n" + text),
    }


def build(name: str) -> dict:
    out = {}
    for set_name, spec in SETS[name].items():
        included = list(spec["items"])
        out[set_name] = {
            "query": spec["query"],
            "budget": spec["budget"],
            "since": "",
            "until": UNTIL,
            "items": [_render(BY_ID[i]) for i in included],
            "matched_not_included": [
                i for i in DISTRACTOR_POOL if i not in included
            ],
        }
    return out


def main() -> int:
    written = {}
    for name in SETS:
        path = TASKS / name
        payload = json.dumps(build(name), sort_keys=True, separators=(",", ":"))
        path.write_text(payload + "\n")
        written[name] = _sha(payload + "\n")
        print(f"wrote {path.relative_to(REPO_ROOT)} ({len(payload)} bytes)")

    manifest = {
        "provenance": "synthetic",
        "generated_by": "scripts/generate_retrieval_fixtures.py",
        "generator_version": GENERATOR_VERSION,
        "deterministic": True,
        "derived_from_live_archive": False,
        "contains_personal_data": False,
        "corpus_event_ids": sorted(BY_ID),
        "files": written,
        "note": (
            "These fixtures replaced frozen selections taken from a live "
            "personal archive. They exercise retrieval structure only: a "
            "contradiction pair (1001/1042), a synthesis pair (1067/1071), and "
            "on-topic distractors. Regenerate with the command above; output "
            "is byte-stable."
        ),
    }
    manifest_path = TASKS / "retrieval-sets-provenance.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"wrote {manifest_path.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
