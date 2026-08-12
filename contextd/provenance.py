"""Derivation closure: mechanical provenance verification for derived events.

A derived event is one a model wrote from a gated disclosure — a reconciler
note, a served synthesis distillate. Its derivation record binds it to the
exact bytes the model saw: the ``source_egress`` event, whose content is the
post-redaction, post-truncation payload and whose ``meta.items`` is the
supplied-event set. Provenance therefore binds to what was disclosed, never
silently to a different raw version of the underlying events.

The verifier here is deterministic and model-free. It can establish, for each
claim in a derived text, exactly three levels:

    unanchored            the claim cites nothing
    anchored              every cited event id resolves, was actually in the
                          source disclosure, and predates it
    structurally_grounded anchored, plus every cited id carries a verbatim
                          quote that appears in that event's segment of the
                          disclosed bytes

and it can refuse malformed provenance outright (fabricated ids, wrong or
missing disclosures, cycles, hash mismatches, chains that never reach
grounded evidence).

What it can NOT establish — and never claims — is that a claim's natural
language is entailed by its evidence. ``semantically_supported`` and
``contradicted`` are judgments; they are deliberately absent from
MECHANICAL_LEVELS and this module never emits them. A valid anchor with a
verified quote can still decorate a false claim; the verifier's job is to
make that laundering *legible* (the evidence sits next to the claim, checked)
rather than to pretend it is impossible. See docs/PROVENANCE.md.

Trust boundary, unchanged: same-owner processes are trusted. An owner-level
forger can write a well-formed derivation record; the chain witness and this
verifier detect after-the-fact tampering and structural fabrication, not a
dishonest owner.
"""

import hashlib
import json
import re

from .experiment import epistemic_type

# Levels this module can assign, weakest to strongest. Semantic levels
# (semantically_supported, contradicted, unresolved) are intentionally not
# representable here: no kernel code path may claim them.
MECHANICAL_LEVELS = ("unanchored", "anchored", "structurally_grounded")

# Mechanical error taxonomy. Every entry is detectable without a model.
ERRORS = frozenset({
    "fabricated_event",         # cited event id has no row
    "not_in_disclosure",        # cited event exists but was not in the source egress
    "missing_source_egress",    # derivation names an egress id with no row
    "not_an_egress",            # source_egress resolves to a non-egress event
    "undisclosed_source",       # source egress carries no item list to bind against
    "non_monotonic",            # cited >= egress, or egress >= derived event
    "cycle",                    # derivation meta loops (impossible if monotonic)
    "content_hash_mismatch",    # stored content no longer matches its hash
    "quote_missing_event",      # support entry names an event the claim text never cites
    "quote_not_in_disclosure",  # quote is not a substring of that event's disclosed segment
    "unsegmentable_disclosure", # egress content has no segment for the cited event
    "source_dispatch_failed",   # the disclosure's linked outcome is failed/timeout
    "malformed_derivation",     # derivation record itself is not well-formed
})

ANCHOR_RX = re.compile(r"\[(\d+)\]")
_HEADER_RX = re.compile(r"^--- \[(\d+)\] .*? ---$", re.M)

GROUNDED_TYPES = ("observation", "human_assertion")


def parse_claims(text: str) -> list:
    """Deterministic claim segmentation: a claim is the maximal run of text up
    to and including its trailing anchor group. This is a lexical convention,
    not semantic parsing — documented as such. Trailing text with no anchors
    is one final unanchored claim."""
    claims, pos = [], 0
    for m in re.finditer(r"(?:\s*\[\d+\])+", text):
        chunk = text[pos:m.start()].strip()
        ids = [int(i) for i in ANCHOR_RX.findall(m.group(0))]
        if re.search(r"\w", chunk) or ids:
            claims.append({"text": chunk, "anchors": ids})
        pos = m.end()
    tail = text[pos:].strip()
    if re.search(r"\w", tail):  # bare punctuation after an anchor is not a claim
        claims.append({"text": tail, "anchors": []})
    return claims


def disclosure_segments(content: str) -> dict:
    """Split a gated bundle (or a prompt wrapping one) back into per-event
    byte segments using the selection walk's header convention. Returns
    {event_id: exact disclosed text for that event}. Text before the first
    header (e.g. a distiller prompt) belongs to no event."""
    headers = list(_HEADER_RX.finditer(content))
    segments = {}
    for i, h in enumerate(headers):
        end = headers[i + 1].start() if i + 1 < len(headers) else len(content)
        segments[int(h.group(1))] = content[h.end():end].strip()
    return segments


def derivation_of(kind: str, meta: dict) -> dict | None:
    """Normalize the derivation record of an event, or None for leaves.

    Two recorded shapes exist:
      - explicit: meta["derivation"] = {"source_egress": int,
        "anchors": [...], "support": [{"event": int, "quote": str,
        "relation": "supports"|"contradicts"}, ...]?}   (reconciler notes)
      - synthesis egress: meta {mode: "synthesis", source_egress, anchors}
    """
    if isinstance(meta.get("derivation"), dict):
        return meta["derivation"]
    if kind == "egress" and meta.get("mode") == "synthesis" \
            and meta.get("source_egress") is not None:
        return {"source_egress": meta["source_egress"],
                "anchors": meta.get("anchors", [])}
    return None


def _row(conn, event_id):
    return conn.execute("SELECT * FROM events WHERE id = ?",
                        (event_id,)).fetchone()


def _meta(row) -> dict:
    return json.loads(row["meta"]) if row["meta"] else {}


def _hash_ok(row) -> bool:
    if row["content"] is None or row["content_hash"] is None:
        return True  # blob events hash raw bytes; nothing to recompute here
    return hashlib.sha256(
        row["content"].encode()).hexdigest() == row["content_hash"]


def _dispatch_status(conn, egress_id) -> str | None:
    r = conn.execute(
        "SELECT meta FROM events WHERE kind='egress_outcome' "
        "AND json_extract(meta,'$.egress_id') = ?", (egress_id,)).fetchone()
    return json.loads(r["meta"]).get("status") if r else None


def superseded_by(conn, event_id) -> list:
    """Later events that declare meta.supersedes = this id. Supersession is an
    append-only annotation — history is never deleted, only outranked."""
    return [r["id"] for r in conn.execute(
        "SELECT id FROM events WHERE json_extract(meta,'$.supersedes') = ? "
        "AND id > ? ORDER BY id", (event_id, event_id))]


def verify_derivation(conn, event_id: int, quotes: bool = True) -> dict:
    """Verify one derived event against its recorded source disclosure.
    Returns {"derived": False} for leaf events. For derived events, returns
    per-claim mechanical levels and every structural error found. Never
    invokes a model; never emits a semantic judgment. quotes=False evaluates
    structure only, ignoring span grounding (claims then cap at 'anchored') —
    the experiment suite uses it to measure the two layers separately."""
    row = _row(conn, event_id)
    if row is None:
        return {"derived": False, "exists": False,
                "errors": ["fabricated_event"]}
    meta = _meta(row)
    derivation = derivation_of(row["kind"], meta)
    if derivation is None:
        return {"derived": False, "exists": True, "errors": []}

    errors, claim_reports = [], []
    src_id = derivation.get("source_egress")
    if not isinstance(src_id, int) or isinstance(src_id, bool):
        return {"derived": True, "exists": True, "source_egress": src_id,
                "errors": ["malformed_derivation"], "claims": [],
                "level": "unanchored"}

    src = _row(conn, src_id)
    items, segments = set(), {}
    if src is None:
        errors.append("missing_source_egress")
    elif src["kind"] != "egress":
        errors.append("not_an_egress")
    else:
        src_meta = _meta(src)
        if not isinstance(src_meta.get("items"), list):
            errors.append("undisclosed_source")
        else:
            items = {i for i in src_meta["items"] if isinstance(i, int)}
        segments = disclosure_segments(src["content"] or "")
        if not _hash_ok(src):
            errors.append("content_hash_mismatch")
        status = _dispatch_status(conn, src_id)
        if status in ("failed", "timeout"):
            errors.append("source_dispatch_failed")
    if src_id >= event_id:
        errors.append("non_monotonic")
    if not _hash_ok(row):
        errors.append("content_hash_mismatch")

    verified_quotes = {}  # event id -> verified quote status
    for entry in derivation.get("support", []) if quotes else []:
        if not isinstance(entry, dict) or "event" not in entry \
                or not entry.get("quote"):
            errors.append("malformed_derivation")
            continue
        ev = entry["event"]
        if ev not in segments:
            verified_quotes[ev] = "unsegmentable_disclosure"
            errors.append("unsegmentable_disclosure")
        elif entry["quote"] in segments[ev]:
            verified_quotes[ev] = "verified"
        else:
            verified_quotes[ev] = "quote_not_in_disclosure"
            errors.append("quote_not_in_disclosure")

    for claim in parse_claims(row["content"] or ""):
        claim_errors = []
        for anchor in claim["anchors"]:
            cited = _row(conn, anchor)
            if cited is None:
                claim_errors.append("fabricated_event")
                continue
            if anchor not in items:
                claim_errors.append("not_in_disclosure")
            if anchor >= src_id:
                claim_errors.append("non_monotonic")
            if not _hash_ok(cited):
                claim_errors.append("content_hash_mismatch")
        if not claim["anchors"]:
            level = "unanchored"
        elif claim_errors:
            level = None  # malformed, not merely weak
        elif all(verified_quotes.get(a) == "verified"
                 for a in claim["anchors"]):
            level = "structurally_grounded"
        else:
            level = "anchored"
        claim_reports.append({"text": claim["text"], "anchors": claim["anchors"],
                              "errors": claim_errors, "level": level})
        errors.extend(claim_errors)

    # a support entry for an event the text never anchors is itself suspect:
    # evidence attached to nothing launders by adjacency
    anchored_ids = {a for c in claim_reports for a in c["anchors"]}
    for ev in verified_quotes:
        if ev not in anchored_ids:
            errors.append("quote_missing_event")

    levels = [c["level"] for c in claim_reports if c["level"]]
    overall = ("structurally_grounded"
               if levels and all(lv == "structurally_grounded" for lv in levels)
               else "anchored" if any(lv in ("anchored", "structurally_grounded")
                                      for lv in levels)
               else "unanchored")
    return {"derived": True, "exists": True, "source_egress": src_id,
            "errors": sorted(set(errors)), "claims": claim_reports,
            "quotes": verified_quotes, "level": overall}


def closure(conn, event_id: int, quotes: bool = True, _visited=None) -> dict:
    """Walk the full derivation closure of an event down to leaf archive
    events. Each node reports its own verification, its epistemic type, any
    supersession, and its children (one per distinct cited event). The
    closure-level verdict:

        malformed   any structural error anywhere in the closure
        grounded    every terminal is an observation or human assertion
        ungrounded  no error, but no path reaches grounded evidence —
                    the chain terminates only in unattributed model claims
        mixed       some terminals grounded, some not
    """
    visited = _visited or set()
    row = _row(conn, event_id)
    if row is None:
        return {"event": event_id, "exists": False, "verdict": "malformed",
                "errors": ["fabricated_event"], "children": {}}
    meta = _meta(row)
    node = {
        "event": event_id, "exists": True,
        "ts": row["ts"], "source": row["source"], "kind": row["kind"],
        "epistemic_type": epistemic_type(row["source"], row["kind"], meta),
        "superseded_by": superseded_by(conn, event_id),
        "children": {},
    }
    if event_id in visited:
        node.update(verdict="malformed", errors=["cycle"])
        return node
    visited = visited | {event_id}

    report = verify_derivation(conn, event_id, quotes=quotes)
    if not report["derived"]:
        grounded = node["epistemic_type"] in GROUNDED_TYPES
        node.update(
            verdict="grounded" if grounded else "ungrounded",
            errors=report.get("errors", []),
            terminal=True,
        )
        if node["errors"]:
            node["verdict"] = "malformed"
        return node

    node.update(derivation=report, errors=list(report["errors"]),
                terminal=False)
    cited = sorted({a for c in report["claims"] for a in c["anchors"]})
    verdicts = set()
    for child_id in cited:
        child = closure(conn, child_id, quotes=quotes, _visited=visited)
        node["children"][child_id] = child
        verdicts.add(child["verdict"])
    if any(c["text"] and not c["anchors"] for c in report["claims"]):
        # an uncited claim inside a cited note is where invented detail rides
        # along; it caps the closure at mixed, never grounded
        verdicts.add("ungrounded")
    if node["errors"] or "malformed" in verdicts:
        node["verdict"] = "malformed"
    elif not cited:
        node["verdict"] = "ungrounded"  # derived, but cites nothing at all
    elif verdicts == {"grounded"}:
        node["verdict"] = "grounded"
    elif verdicts & {"grounded", "mixed"}:
        # a mixed child reaches SOME grounded leaves; the parent inherits
        # partial grounding, it does not collapse to ungrounded (bug found
        # by the P3 recursion trial: two-generation chains through mixed
        # notes were being reported as reaching no evidence at all)
        node["verdict"] = "mixed"
    else:
        node["verdict"] = "ungrounded"
    return node


def format_closure(node: dict, depth: int = 0) -> str:
    """Render a closure tree for `ctx why`: what is mechanically verified on
    each edge, what each terminal is, and where the chain stops being
    checkable. Semantic support is deliberately never asserted."""
    pad = "  " * depth
    if not node.get("exists"):
        return f"{pad}#{node['event']}: DOES NOT EXIST (fabricated_event)"
    line = (f"{pad}#{node['event']} {node['source']}/{node['kind']} "
            f"[{node['epistemic_type']}]")
    if node.get("superseded_by"):
        line += f"  superseded by {node['superseded_by']}"
    out = [line]
    if node.get("terminal"):
        out[-1] += f"  <- {node['verdict']} terminal"
    else:
        d = node["derivation"]
        out.append(f"{pad}  derived via egress #{d['source_egress']} "
                   f"(level: {d['level']}; verdict: {node['verdict']})")
        if node["errors"]:
            out.append(f"{pad}  ERRORS: {', '.join(node['errors'])}")
        for c in d["claims"]:
            mark = c["level"] or "MALFORMED:" + ",".join(sorted(set(c["errors"])))
            text = (c["text"][:80] + "…") if len(c["text"]) > 80 else c["text"]
            out.append(f"{pad}  - [{mark}] {text!r} -> {c['anchors'] or 'nothing'}")
        for child in node["children"].values():
            out.append(format_closure(child, depth + 1))
    if depth == 0:
        out.append("")
        out.append("mechanically verified: anchor resolution, disclosure "
                   "membership, quote-span membership, hash integrity, "
                   "chain shape. NOT verified (semantic judgment): whether "
                   "any claim's wording is actually supported by its evidence.")
    return "\n".join(out)
