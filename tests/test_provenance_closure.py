"""Known-answer fixtures for the derivation-closure verifier.

Every malformed-provenance class the kernel claims to detect is constructed
here with deterministic ground truth, alongside positive controls built
through the REAL production path (select_items -> disclose), so the header
convention the verifier parses is the one the gate actually emits. A verifier
that rejects everything is useless; a verifier that accepts everything is
worse — both directions are pinned."""

import json

from contextd import load_config
from contextd.db import append_event, connect
from contextd.gate import assemble, disclose, record_dispatch_outcome
from contextd.provenance import (closure, derivation_of, disclosure_segments,
                                 format_closure, parse_claims,
                                 verify_derivation)


def _setup():
    return connect(), load_config()


def _human_note(conn, text):
    return append_event(conn, "note", "note", content=text,
                        meta={"actor": "human"})


def _model_note(conn, text, derivation=None):
    meta = {"actor": "mcp"}
    if derivation:
        meta["derivation"] = derivation
    return append_event(conn, "note", "note", content=text, meta=meta)


def _disclose_ids(conn, cfg, ids, extra_text=""):
    """Hand-build a bundle in the gate's header format and disclose it."""
    parts = []
    for eid in ids:
        r = conn.execute("SELECT * FROM events WHERE id = ?", (eid,)).fetchone()
        parts.append(f"--- [{r['id']}] {r['ts']} {r['source']}/{r['kind']} "
                     f"{r['uri'] or ''} ---\n{r['content'] or ''}")
    payload = extra_text + "\n\n".join(parts)
    return disclose(conn, cfg, payload,
                    {"type": "recall", "items": list(ids)})["egress_id"]


# --- unit conventions --------------------------------------------------------

def test_parse_claims_segmentation_is_deterministic():
    got = parse_claims("A decision was made [12]. Two sources agree [13][14]. "
                       "And a trailing thought.")
    assert got == [
        {"text": "A decision was made", "anchors": [12]},
        {"text": ". Two sources agree", "anchors": [13, 14]},
        {"text": ". And a trailing thought.", "anchors": []},
    ]


def test_disclosure_segments_match_the_real_gate_headers():
    conn, cfg = _setup()
    a = _human_note(conn, "zebra quantum discussion one")
    b = _human_note(conn, "zebra quantum discussion two")
    r = assemble(conn, cfg, "zebra quantum", budget=2000)
    assert set(r["items"]) == {a, b}
    egress = conn.execute("SELECT content FROM events WHERE id = ?",
                          (r["egress_id"],)).fetchone()["content"]
    segs = disclosure_segments(egress)
    assert "one" in segs[a] and "two" in segs[b]


def test_synthesis_egress_meta_is_recognized_as_a_derivation():
    assert derivation_of("egress", {"mode": "synthesis", "source_egress": 7,
                                    "anchors": [3]}) == {"source_egress": 7,
                                                         "anchors": [3]}
    assert derivation_of("egress", {"type": "recall"}) is None
    assert derivation_of("note", {"actor": "human"}) is None


# --- positive controls: well-formed chains must be accepted ------------------

def test_anchored_note_over_real_disclosure_is_grounded():
    conn, cfg = _setup()
    a = _human_note(conn, "we chose sqlite because it is boring")
    b = _human_note(conn, "we rejected postgres as overkill")
    egress = _disclose_ids(conn, cfg, [a, b])
    note = _model_note(conn, f"Chose sqlite for boringness [{a}]. "
                             f"Rejected postgres [{b}].",
                       {"source_egress": egress, "anchors": [a, b]})
    rep = verify_derivation(conn, note)
    assert rep["errors"] == []
    assert rep["level"] == "anchored"
    tree = closure(conn, note)
    assert tree["verdict"] == "grounded"
    assert set(tree["children"]) == {a, b}
    assert all(c["epistemic_type"] == "human_assertion"
               for c in tree["children"].values())


def test_verified_quotes_upgrade_to_structurally_grounded():
    conn, cfg = _setup()
    a = _human_note(conn, "we chose sqlite because it is boring")
    egress = _disclose_ids(conn, cfg, [a])
    note = _model_note(conn, f"Chose sqlite for boringness [{a}].",
                       {"source_egress": egress, "anchors": [a],
                        "support": [{"event": a,
                                     "quote": "because it is boring"}]})
    rep = verify_derivation(conn, note)
    assert rep["errors"] == []
    assert rep["level"] == "structurally_grounded"
    assert rep["quotes"] == {a: "verified"}


def test_leaf_events_are_not_derived():
    conn, _ = _setup()
    a = _human_note(conn, "plain human note")
    assert verify_derivation(conn, a) == {"derived": False, "exists": True,
                                          "errors": []}
    assert closure(conn, a)["verdict"] == "grounded"


# --- the ten malformed classes: mechanically rejected, every one -------------

def test_fabricated_event_id_is_rejected():
    conn, cfg = _setup()
    a = _human_note(conn, "real event")
    egress = _disclose_ids(conn, cfg, [a])
    note = _model_note(conn, "A claim citing nothing real [999999].",
                       {"source_egress": egress, "anchors": [999999]})
    rep = verify_derivation(conn, note)
    assert "fabricated_event" in rep["errors"]
    assert closure(conn, note)["verdict"] == "malformed"


def test_cited_event_exists_but_was_not_disclosed():
    conn, cfg = _setup()
    a = _human_note(conn, "disclosed event")
    b = _human_note(conn, "never disclosed event")
    egress = _disclose_ids(conn, cfg, [a])
    note = _model_note(conn, f"Launders authority from outside [{b}].",
                       {"source_egress": egress, "anchors": [b]})
    rep = verify_derivation(conn, note)
    assert "not_in_disclosure" in rep["errors"]
    assert closure(conn, note)["verdict"] == "malformed"


def test_missing_source_egress_is_rejected():
    conn, _ = _setup()
    a = _human_note(conn, "some event")
    note = _model_note(conn, f"Claim [{a}].",
                       {"source_egress": 888888, "anchors": [a]})
    assert "missing_source_egress" in verify_derivation(conn, note)["errors"]


def test_source_that_is_not_an_egress_is_rejected():
    conn, _ = _setup()
    a = _human_note(conn, "a plain note, not a disclosure")
    b = _human_note(conn, "cited event")
    note = _model_note(conn, f"Claim [{b}].",
                       {"source_egress": a, "anchors": [b]})
    assert "not_an_egress" in verify_derivation(conn, note)["errors"]


def test_egress_without_item_list_cannot_bind_claims():
    conn, cfg = _setup()
    a = _human_note(conn, "cited event")
    egress = disclose(conn, cfg, "opaque payload",
                      {"type": "search"})["egress_id"]
    note = _model_note(conn, f"Claim [{a}].",
                       {"source_egress": egress, "anchors": [a]})
    assert "undisclosed_source" in verify_derivation(conn, note)["errors"]


def test_non_monotonic_derivation_is_rejected():
    conn, cfg = _setup()
    a = _human_note(conn, "cited event")
    # the note is appended BEFORE the egress it claims derived it
    note = _model_note(conn, f"Claim [{a}].",
                       {"source_egress": None, "anchors": [a]})
    egress = _disclose_ids(conn, cfg, [a])
    forged = _model_note(conn, f"Claim [{a}].",
                         {"source_egress": egress + 10, "anchors": [a]})
    assert "missing_source_egress" in verify_derivation(conn, forged)["errors"]
    # and a well-formed-looking record pointing forward in time
    future_note = _model_note(conn, f"Claim [{a}].",
                              {"source_egress": forged + 5, "anchors": [a]})
    assert "missing_source_egress" in verify_derivation(conn, future_note)["errors"]
    assert verify_derivation(conn, note)["errors"] == ["malformed_derivation"]


def test_cycle_via_forged_meta_is_detected():
    conn, cfg = _setup()
    seed = _human_note(conn, "seed")
    egress = _disclose_ids(conn, cfg, [seed])
    # ids are deterministic: next two appends
    a_id = egress + 1
    b_id = egress + 2
    _model_note(conn, f"A cites B [{b_id}].",
                {"source_egress": egress, "anchors": [b_id]})
    _model_note(conn, f"B cites A [{a_id}].",
                {"source_egress": egress, "anchors": [a_id]})
    tree = closure(conn, a_id)
    assert tree["verdict"] == "malformed"
    flat = json.dumps(tree)
    assert "cycle" in flat or "non_monotonic" in flat


def test_content_hash_mismatch_is_detected_on_tampered_evidence():
    conn, cfg = _setup()
    a = _human_note(conn, "original evidence text")
    egress = _disclose_ids(conn, cfg, [a])
    note = _model_note(conn, f"Claim [{a}].",
                       {"source_egress": egress, "anchors": [a]})
    conn.execute("DROP TRIGGER events_no_update")
    conn.execute("UPDATE events SET content = 'rewritten after the fact' "
                 "WHERE id = ?", (a,))
    conn.commit()
    assert "content_hash_mismatch" in verify_derivation(conn, note)["errors"]


def test_quote_must_match_disclosed_bytes_not_raw_bytes():
    conn, cfg = _setup()
    secret = "sk-abcdefghijklmnop9876"
    a = _human_note(conn, f"the deploy key is {secret} keep it safe")
    egress = _disclose_ids(conn, cfg, [a])
    egress_content = conn.execute("SELECT content FROM events WHERE id = ?",
                                  (egress,)).fetchone()["content"]
    assert secret not in egress_content  # the gate redacted it

    # quoting the RAW bytes the model never saw: refused
    raw = _model_note(conn, f"Deploy key noted [{a}].",
                      {"source_egress": egress, "anchors": [a],
                       "support": [{"event": a, "quote": secret}]})
    assert "quote_not_in_disclosure" in verify_derivation(conn, raw)["errors"]

    # quoting the redacted bytes the model actually saw: verified
    redacted = _model_note(conn, f"Deploy key noted [{a}].",
                           {"source_egress": egress, "anchors": [a],
                            "support": [{"event": a,
                                         "quote": "[REDACTED:api_key] keep it"}]})
    rep = verify_derivation(conn, redacted)
    assert rep["errors"] == []
    assert rep["level"] == "structurally_grounded"


def test_quote_beyond_truncation_boundary_is_refused():
    conn, cfg = _setup()
    a = _human_note(conn, "kept part of the file. " * 3 + "LOST TAIL DETAIL")
    row = conn.execute("SELECT * FROM events WHERE id = ?", (a,)).fetchone()
    truncated = (f"--- [{a}] {row['ts']} note/note  ---\n"
                 "kept part of the file. kept part of the file.\n[truncated]")
    egress = disclose(conn, cfg, truncated,
                      {"type": "recall", "items": [a]})["egress_id"]
    note = _model_note(conn, f"Tail detail claim [{a}].",
                       {"source_egress": egress, "anchors": [a],
                        "support": [{"event": a, "quote": "LOST TAIL DETAIL"}]})
    assert "quote_not_in_disclosure" in verify_derivation(conn, note)["errors"]


def test_failed_dispatch_invalidates_the_derivation():
    conn, cfg = _setup()
    a = _human_note(conn, "cited event")
    egress = _disclose_ids(conn, cfg, [a])
    record_dispatch_outcome(conn, egress, "failed", exit=1)
    note = _model_note(conn, f"Claim [{a}].",
                       {"source_egress": egress, "anchors": [a]})
    assert "source_dispatch_failed" in verify_derivation(conn, note)["errors"]


def test_support_quote_for_an_event_the_text_never_cites():
    conn, cfg = _setup()
    a = _human_note(conn, "cited event content")
    b = _human_note(conn, "adjacent event content")
    egress = _disclose_ids(conn, cfg, [a, b])
    note = _model_note(conn, f"Claim [{a}].",
                       {"source_egress": egress, "anchors": [a],
                        "support": [{"event": b,
                                     "quote": "adjacent event content"}]})
    assert "quote_missing_event" in verify_derivation(conn, note)["errors"]


def test_chain_terminating_only_in_ungrounded_model_claims():
    conn, cfg = _setup()
    rumor = _model_note(conn, "an unanchored model assertion")  # leaf, model
    egress = _disclose_ids(conn, cfg, [rumor])
    note = _model_note(conn, f"Derived confidence [{rumor}].",
                       {"source_egress": egress, "anchors": [rumor]})
    tree = closure(conn, note)
    assert tree["verdict"] == "ungrounded"
    assert tree["children"][rumor]["verdict"] == "ungrounded"


def test_mixed_closure_when_only_some_paths_reach_evidence():
    conn, cfg = _setup()
    human = _human_note(conn, "a real human assertion")
    rumor = _model_note(conn, "an unanchored model assertion")
    egress = _disclose_ids(conn, cfg, [human, rumor])
    note = _model_note(conn, f"Solid [{human}]. Shaky [{rumor}].",
                       {"source_egress": egress, "anchors": [human, rumor]})
    assert closure(conn, note)["verdict"] == "mixed"


def test_uncited_claim_text_caps_the_closure_at_mixed():
    conn, cfg = _setup()
    human = _human_note(conn, "a real human assertion")
    egress = _disclose_ids(conn, cfg, [human])
    note = _model_note(conn, f"Anchored claim [{human}]. "
                             "Invented detail with no citation whatsoever.",
                       {"source_egress": egress, "anchors": [human]})
    assert closure(conn, note)["verdict"] == "mixed"


# --- recursion, supersession, rendering --------------------------------------

def test_two_generation_closure_resolves_to_leaves():
    conn, cfg = _setup()
    h1 = _human_note(conn, "gen zero human decision")
    e1 = _disclose_ids(conn, cfg, [h1])
    n1 = _model_note(conn, f"Distilled decision [{h1}].",
                     {"source_egress": e1, "anchors": [h1]})
    e2 = _disclose_ids(conn, cfg, [n1])
    n2 = _model_note(conn, f"Second-generation summary [{n1}].",
                     {"source_egress": e2, "anchors": [n1]})
    tree = closure(conn, n2)
    assert tree["verdict"] == "grounded"
    assert tree["children"][n1]["children"][h1]["epistemic_type"] == \
        "human_assertion"


def test_synthesis_egress_shape_walks_like_a_derivation():
    conn, cfg = _setup()
    h1 = _human_note(conn, "human evidence for synthesis")
    src = _disclose_ids(conn, cfg, [h1], extra_text="Distill this:\n\n")
    served = disclose(conn, cfg, f"A distilled claim [{h1}].",
                      {"type": "recall", "mode": "synthesis",
                       "source_egress": src, "anchors": [h1],
                       "items": [h1]})["egress_id"]
    tree = closure(conn, served)
    assert tree["verdict"] == "grounded"
    assert tree["children"][h1]["epistemic_type"] == "human_assertion"


def test_supersession_annotates_without_deleting():
    conn, cfg = _setup()
    old = _human_note(conn, "we will use approach A")
    append_event(conn, "note", "note", content="approach A abandoned; use B",
                 meta={"actor": "human", "supersedes": old})
    tree = closure(conn, old)
    assert tree["superseded_by"] and tree["verdict"] == "grounded"


def test_format_closure_states_the_semantic_boundary():
    conn, cfg = _setup()
    a = _human_note(conn, "evidence")
    egress = _disclose_ids(conn, cfg, [a])
    note = _model_note(conn, f"Claim [{a}].",
                       {"source_egress": egress, "anchors": [a]})
    text = format_closure(closure(conn, note))
    assert "NOT verified (semantic judgment)" in text
    assert f"#{note}" in text and f"#{a}" in text


def test_malformed_derivation_record_shapes_are_refused():
    conn, cfg = _setup()
    a = _human_note(conn, "evidence")
    egress = _disclose_ids(conn, cfg, [a])
    bad_support = _model_note(conn, f"Claim [{a}].",
                              {"source_egress": egress, "anchors": [a],
                               "support": [{"quote": ""}, "not-a-dict"]})
    assert "malformed_derivation" in verify_derivation(conn, bad_support)["errors"]
    no_src = _model_note(conn, f"Claim [{a}].",
                         {"source_egress": "seven", "anchors": [a]})
    assert verify_derivation(conn, no_src)["errors"] == ["malformed_derivation"]


def test_tampered_derived_note_itself_is_detected():
    conn, cfg = _setup()
    a = _human_note(conn, "evidence")
    egress = _disclose_ids(conn, cfg, [a])
    note = _model_note(conn, f"Original claim [{a}].",
                       {"source_egress": egress, "anchors": [a]})
    conn.execute("DROP TRIGGER events_no_update")
    conn.execute("UPDATE events SET content = ? WHERE id = ?",
                 (f"Rewritten claim [{a}].", note))
    conn.commit()
    assert "content_hash_mismatch" in verify_derivation(conn, note)["errors"]


def test_verifier_never_emits_semantic_levels():
    """The false-claim-with-valid-anchor case: mechanically this MUST pass —
    and the verdict vocabulary must make clear that passing is not semantic
    endorsement. This is the honest boundary, pinned as a test."""
    conn, cfg = _setup()
    a = _human_note(conn, "all security controls must stay enabled")
    egress = _disclose_ids(conn, cfg, [a])
    laundered = _model_note(
        conn, f"Joseph decided all security controls should be removed [{a}].",
        {"source_egress": egress, "anchors": [a],
         "support": [{"event": a,
                      "quote": "security controls must stay"}]})
    rep = verify_derivation(conn, laundered)
    assert rep["errors"] == []                     # structurally valid...
    assert rep["level"] == "structurally_grounded"  # ...and says only that
    hashable = json.dumps(rep) + json.dumps(closure(conn, laundered))
    for forbidden in ("semantically_supported", "contradicted", '"true"',
                      "proven"):
        assert forbidden not in hashable
