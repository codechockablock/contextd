"""Instruction-position pinning, and what was in the context of each act.

A poisoned skill is untrusted content arriving *as instruction*, before a
session starts, in the position the operator's own policy should occupy.
Taint tracking on retrieved data does not touch it: nothing gets tainted, the
agent is following what it correctly believes are its instructions, and the
record is honest all the way down. A skill is a delegation the operator never
signed, and ``contextd/grants.py`` already refuses that shape for grants.

Prior art, stated plainly rather than worked around
-----------------------------------------------------------------------

**Microsoft's ``agent-governance-toolkit`` already built this mechanism**, and
this module is deliberately convergent with it. At commit ``7d0cef5``:

* ``agent-governance-rust/agentmesh-mcp/src/mcp/security.rs`` (~124-130)
  computes ``description_hash = sha256_hex(&tool.description)`` and
  ``schema_hash = sha256_hex(&serde_json::to_string(&tool.input_schema)?)`` when
  a tool registers; ``check_rug_pull`` (~153-181) compares both later and
  reports which of description/schema changed.
* ``agent-governance-python/agent-os/modules/control-plane/src/
  agent_control_plane/tool_registry.py``: ``verify_tool_integrity`` (~361-375)
  re-hashes the handler's source and compares it against the registration-time
  hash. It runs **before execution** (~265) and on mismatch it **blocks** —
  returning ``{"success": False, "error": "Tool integrity verification failed:
  ..."}``. It does not merely warn.
* ``agent-marketplace`` signs plugin manifests with Ed25519 and binds the
  artifact SHA-256 into the signed bytes; the installer fails closed.

Digest-pinning an instruction-position artifact and enforcing it before
execution is therefore **not novel here**, and nothing in this file claims it
is. Two independent implementations arriving at the same shape is evidence the
shape is right; the error would have been inventing a different one to look
different. Their code was read as prior art and none of it was copied.

Citation provenance, since it matters more than the citations: the four bullets
above were verified firsthand against a read-only clone at ``7d0cef5`` during
this repo's gate-v1 pre-flight, and are reproduced here from that record. They
were **not** re-verified while this module was written — no checkout was
present. Line numbers are approximate and named by enclosing function so they
survive upstream edits.

The one thing that is actually different
-----------------------------------------------------------------------

Where the pin *lives*. Theirs is ``registry: Mutex::new(HashMap::new())``
(security.rs ~114) — per-process memory, with ``_integrity_violations`` an
in-memory Python list on the other side. **That is entirely reasonable for a
per-session MCP security scanner and is not a defect in their scope.** Its one
consequence is structural: a process restart re-TOFUs from scratch, so an
artifact mutated across a restart presents as first sight rather than as
divergence.

Here a pin is an ordinary contextd event: chained, witnessed, and reconstructed
by folding the ledger in id order (:func:`pin_state`), with no in-process cache
anywhere in this module. That is what
``tests/test_instruction_pinning.py::test_pin_survives_process_restart`` earns,
and it is the only claim in this file that a competitor's design cannot make.

What the pin does NOT bind
-----------------------------------------------------------------------

Stated here rather than discovered later, because an over-read of this module
is more dangerous than not having it. An attacker who controls a skill file but
not the ledger still has all of the following:

* **The body is supplied by the caller, not read by contextd.** A pin binds the
  bytes the caller said it read. It does not bind the bytes on disk, and it
  certainly does not bind the bytes the model received in its context window.
  Mutating the file between the digest and the read is a live TOCTOU.
* **Completeness of the label is not verifiable.** An act names the artifacts
  its caller chose to name. Presenting three of four loaded skills produces an
  honest-looking act with an incomplete provenance label, and nothing here can
  tell. What the ledger guarantees is that the claim is durable, chained, and
  atomic with the act — not that it was complete.
* **First sight is trust.** TOFU catches *mutation*, never malice that was
  present the first time. A skill that arrived poisoned gets pinned poisoned in
  record mode. Gate mode's refusal of unknown digests is the answer to that,
  and it is the reason gate mode exists.
* **Renaming defeats the key.** ``skills/triage.md`` moved to
  ``skills/triage-v2.md`` is a different artifact and first-sights cleanly. The
  pin is on a position, so an attacker who can create positions can pick a new
  one.

None of these is unique to contextd; the same four hold for every registration-
time digest scheme, including the prior art above. The tests named
``test_a_renamed_artifact_is_a_new_first_sight`` and
``test_record_mode_pins_an_artifact_that_arrived_poisoned`` pin two of them so
they stay documented rather than quietly assumed away.

Shape of the mechanism
-----------------------------------------------------------------------

1. An artifact is ``(kind, name, body)``; its digest binds all three
   (:func:`artifact`). Bodies are never stored — only digests.
2. First sight pins it, with no key and no setup (TOFU). A later mutation is a
   ``("pin", "pin")`` event with ``op="diverge"``, or a ``diverged`` entry in
   the provenance label of the act it preceded.
3. **Only an operator signature moves a pin** (:func:`adopt`, action class
   ``pin.adopt``). The fold refuses to move a pin for any other reason, so a
   direct append cannot re-pin a poisoned skill onto itself.
4. Record mode and gate mode write the *same rows*. Mode decides one thing:
   whether an unknown or diverged digest also refuses. Exports never have to
   care which produced them.
5. Provenance is transitive by reduction, not by a flag anyone writes
   (:func:`reduce_provenance`) — the same shape as ``grants.reduce_grants``.
   A chain break is an operator act too (``pin.barrier``); a break the model
   could write itself would be a laundering primitive.
"""

import hashlib
import json
import unicodedata
from dataclasses import dataclass

from .assurance import assurance_for_event
from .attest import AttestationError, authorized_append, test_mode_authorization
from .canonical import canonical_digest
from .db import Refusal, append_event_checked
from .schemas import (
    MAX_ARTIFACT_NAME,
    MAX_PIN_ARTIFACTS,
    MAX_SOURCE_LABEL,
    MAX_UNTRUSTED_SOURCES,
    PIN_ARTIFACT_KINDS,
    PIN_REFUSAL_REASONS,
    schema_for,
)

#: Domain separators. The artifact digest and the context digest answer
#: different questions and must never be substitutable for one another.
PIN_DOMAIN = "contextd.InstructionPinV1"
CONTEXT_DOMAIN = "contextd.InstructionContextV1"

PIN_SOURCE = "pin"
PIN_KIND = "pin"
REFUSE_KIND = "refuse"
ACT_SOURCE = "act"
ACT_KIND = "act"
BARRIER_KIND = "barrier"

#: Record mode observes and records; gate mode additionally refuses. One ledger
#: schema, two policies.
MODE_RECORD = "record"
MODE_GATE = "gate"
MODES = (MODE_RECORD, MODE_GATE)

ADOPT_ACTION = "pin.adopt"
BARRIER_ACTION = "pin.barrier"

#: The assurance levels that count as "the operator said so". Identical to
#: ``grants.OPERATOR_LEVELS`` and identical for the same reason: the test-only
#: software signer is a distinguishable level, never a silent equivalent.
OPERATOR_LEVELS = ("operator_authorized", "INSECURE_TEST_SIGNER")


class PinError(RuntimeError):
    """A pin could not be computed, recorded, or adopted."""


class PinRefused(PinError):
    """Gate mode refused an act over its instruction-position context."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class Artifact:
    """One instruction-position artifact, reduced to what is safe to store."""

    kind: str
    name: str
    digest: str

    def as_dict(self) -> dict:
        return {"kind": self.kind, "name": self.name, "digest": self.digest}


# --- digesting ---------------------------------------------------------------

def artifact(kind: str, name: str, body: str) -> Artifact:
    """Digest one artifact. The body is digested and then discarded.

    The digest binds ``kind`` and ``name`` as well as the body, so moving one
    skill's bytes into another skill's file is a divergence for both rather
    than a match for neither. That is the same registry shape ``security.rs``
    uses — keyed by tool name, digest over the definition.

    Unlike ``attest._digest``, which digests the *post-redaction* text because
    the archive stores those exact bytes, this digests the body as it arrived.
    Nothing here persists the body, so there is no archive-bytes-versus-signed-
    bytes gap to close — and pinning the raw bytes is the only way the pin binds
    what the agent will actually read. A mutation confined to a region the
    privacy floor would have rewritten is still a mutation.
    """
    if kind not in PIN_ARTIFACT_KINDS:
        raise PinError(
            f"unknown artifact kind {kind!r}; registry: "
            f"{', '.join(PIN_ARTIFACT_KINDS)}"
        )
    if not isinstance(body, str):
        raise PinError("an instruction-position artifact must be text")
    name = _artifact_name(name)
    return Artifact(kind, name, canonical_digest(PIN_DOMAIN, {
        "kind": kind,
        "name": name,
        "body_sha256": _sha256(body),
    }))


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _artifact_name(name: str) -> str:
    """Refuse a name the archive would have to rewrite, rather than rewriting it.

    ``schemas._check_artifact_name`` enforces the same rule at the storage
    boundary; this is the fail-fast copy, so a caller learns at digest time
    rather than at append time.
    """
    from . import load_config
    from .redact import sanitize_text
    if not isinstance(name, str) or not name or len(name) > MAX_ARTIFACT_NAME:
        raise PinError(
            f"an artifact name must be non-empty text of at most "
            f"{MAX_ARTIFACT_NAME} characters"
        )
    normalized = unicodedata.normalize("NFC", name)
    if sanitize_text(load_config(), normalized, MAX_ARTIFACT_NAME) != normalized:
        raise PinError(
            "artifact name contains redacted or control-sequence data and is "
            "refused; a pin whose subject was silently renamed pins nothing"
        )
    return normalized


def context_digest(artifacts) -> str:
    """A stable digest of exactly the instruction-position context presented.

    Recorded on the act *and* on gate mode's refusal row, so a refusal names
    which context was refused without reproducing anything the caller wrote.
    Order-independent: two orderings of the same set are the same context.
    """
    return canonical_digest(CONTEXT_DOMAIN, {
        "artifacts": sorted(
            [[a.kind, a.name, a.digest] for a in artifacts]
        ),
    })


# --- the pin registry, folded out of the ledger ------------------------------

def _meta(row) -> dict:
    try:
        parsed = json.loads(row["meta"] or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _pin_rows(conn, up_to_event=None):
    query = (
        "SELECT id, ts, source, kind, content, meta FROM events "
        "WHERE (source='pin' AND kind='pin') OR (source='act' AND kind='act')"
    )
    parameters: tuple = ()
    if up_to_event is not None:
        query += " AND id <= ?"
        parameters = (int(up_to_event),)
    return conn.execute(query + " ORDER BY id", parameters).fetchall()


def pin_state(conn, up_to_event: int | None = None) -> dict:
    """``{"pins": {(kind, name): record}, "anomalies": [...]}``, id order.

    There is no cache. Every call reconstructs the registry from the ledger,
    which is what makes a pin survive the process that took it — and what makes
    an archive copied to another machine carry its pins with it.

    A direct append never corrupts the reduction, it just gets named:

    * an ``observe`` of an already-pinned artifact under a *different* digest
      is a divergence and an anomaly. It does not move the pin. Without this,
      re-observation would be a free re-pin and the whole mechanism would be
      decorative.
    * an ``adopt`` without a verified operator authorization covering exactly
      that artifact and digest is an anomaly. It does not move the pin.
    * an act claiming ``status="pinned"`` for an already-pinned artifact, or
      ``status="matched"`` against a digest that is not the live pin, is an
      anomaly. A row's self-description is never taken on trust.
    """
    pins: dict = {}
    anomalies: list = []

    def note(event_id, why):
        anomalies.append({"event": event_id, "why": why})

    def diverge(event_id, key, digest):
        pins[key]["divergences"].append({"event": event_id, "digest": digest})

    for row in _pin_rows(conn, up_to_event):
        meta = _meta(row)
        event_id = row["id"]
        if row["source"] == PIN_SOURCE:
            op = meta.get("op")
            kind, name = meta.get("artifact_kind"), meta.get("artifact")
            digest = meta.get("digest")
            if kind not in PIN_ARTIFACT_KINDS or not name or not digest:
                note(event_id, "pin event does not name a known artifact")
                continue
            key = (kind, name)
            current = pins.get(key)
            if op == "observe":
                if current is None:
                    pins[key] = _new_pin(kind, name, digest, event_id)
                elif current["digest"] != digest:
                    diverge(event_id, key, digest)
                    note(event_id,
                         "observe of an already-pinned artifact under a "
                         "different digest; only pin.adopt moves a pin")
            elif op == "diverge":
                if current is None:
                    note(event_id, "divergence from an artifact that is not pinned")
                elif current["digest"] == digest:
                    note(event_id, "divergence recorded against the live pin")
                else:
                    diverge(event_id, key, digest)
            elif op == "adopt":
                body = row["content"] or None
                level = assurance_for_event(
                    conn, row, action=ADOPT_ACTION, scope="global",
                    arguments={"artifact": name, "artifact_kind": kind,
                               "digest": digest},
                    content=body, reason=body,
                )
                if level not in OPERATOR_LEVELS:
                    note(event_id,
                         "adopt lacks a verified operator authorization for "
                         "exactly this artifact and digest; the model cannot "
                         "re-pin a skill onto itself")
                    continue
                history = current["divergences"] if current else []
                pins[key] = _new_pin(kind, name, digest, event_id,
                                     adopted_by=event_id,
                                     divergences=history)
            else:
                note(event_id, "unknown pin operation")
            continue

        # ("act", "act"): an act's own provenance label is pin evidence too —
        # first sight inside a transaction is still first sight.
        provenance = meta.get("provenance") or {}
        for entry in provenance.get("instructions") or []:
            kind, name = entry.get("kind"), entry.get("name")
            digest, status = entry.get("digest"), entry.get("status")
            if kind not in PIN_ARTIFACT_KINDS or not name or not digest:
                note(event_id, "act names an artifact that is not well-formed")
                continue
            key = (kind, name)
            current = pins.get(key)
            if status == "pinned":
                if current is None:
                    pins[key] = _new_pin(kind, name, digest, event_id)
                elif current["digest"] != digest:
                    diverge(event_id, key, digest)
                    note(event_id,
                         "act claims first sight of an already-pinned artifact")
                else:
                    note(event_id,
                         "act claims first sight of an artifact already pinned "
                         "to this digest")
            elif status == "matched":
                if current is None:
                    note(event_id, "act claims a match against no pin")
                elif current["digest"] != digest:
                    diverge(event_id, key, digest)
                    note(event_id, "act claims a match against a stale digest")
            elif status == "diverged":
                if current is None:
                    note(event_id, "act names a divergence from no pin")
                elif current["digest"] == digest:
                    note(event_id, "act names a divergence from the live pin")
                else:
                    diverge(event_id, key, digest)
    return {"pins": pins, "anomalies": anomalies}


def _new_pin(kind, name, digest, event_id, adopted_by=None, divergences=None):
    return {
        "kind": kind, "name": name, "digest": digest,
        "pin_event": event_id, "adopted_by": adopted_by,
        "divergences": list(divergences or []),
    }


def resolve(pins: dict, artifacts) -> list[dict]:
    """How each presented artifact stands against the registry. Pure.

    Separated from every append path on purpose: the same function decides what
    a record-mode act labels itself with and what a gate-mode act refuses over,
    so the two modes cannot drift apart in what they consider a divergence.
    """
    entries = []
    for art in artifacts:
        current = pins.get((art.kind, art.name))
        entry = art.as_dict()
        if current is None:
            entry["status"] = "pinned"
        else:
            entry["status"] = (
                "matched" if current["digest"] == art.digest else "diverged"
            )
            entry["pinned"] = current["digest"]
            entry["pin_event"] = current["pin_event"]
        entries.append(entry)
    return entries


# --- recording ---------------------------------------------------------------

def _normalize_artifacts(artifacts) -> list:
    items = list(artifacts or [])
    if len(items) > MAX_PIN_ARTIFACTS:
        raise PinError(
            f"an act may name at most {MAX_PIN_ARTIFACTS} instruction-position "
            f"artifacts"
        )
    for item in items:
        if not isinstance(item, Artifact):
            raise PinError(
                "artifacts must be built by pinning.artifact(); a caller-shaped "
                "mapping would let the digest and the body disagree"
            )
    if len({(a.kind, a.name) for a in items}) != len(items):
        raise PinError("the same artifact was presented twice in one context")
    return items


def _normalize_sources(untrusted) -> list:
    items = list(untrusted or [])
    if len(items) > MAX_UNTRUSTED_SOURCES:
        raise PinError(
            f"an act may name at most {MAX_UNTRUSTED_SOURCES} untrusted sources"
        )
    out = []
    for source in items:
        if not isinstance(source, str) or not source or \
                len(source) > MAX_SOURCE_LABEL:
            raise PinError(
                f"an untrusted source is a name of at most {MAX_SOURCE_LABEL} "
                f"characters, not its content"
            )
        if source not in out:
            out.append(source)
    return out


def _check_mode(mode: str) -> str:
    if mode not in MODES:
        raise PinError(f"mode must be one of: {', '.join(MODES)}")
    return mode


def observe(conn, artifacts, *, session: str | None = None) -> list[dict]:
    """Trust on first sight; record divergence on any sight after that.

    Zero setup: no key, no enrollment, no configuration. This is the honest
    default for a mechanism whose alternative is nothing at all — and it is
    exactly the property gate mode withdraws, because TOFU on a path that moves
    money is just trust.

    Returns one record per artifact: ``status`` in ``pinned`` / ``unchanged`` /
    ``diverged``, with the event id where an append happened.
    """
    results = []
    for art in _normalize_artifacts(artifacts):
        current = pin_state(conn)["pins"].get((art.kind, art.name))
        if current is not None and current["digest"] == art.digest:
            results.append({"status": "unchanged", "artifact": art,
                            "digest": art.digest, "event": None,
                            "pin_event": current["pin_event"]})
            continue
        holder: dict = {}

        def stamp(locked_conn, _ts, _art=art, _holder=holder):
            """Under the chain lock: decide observe-vs-diverge for real.

            The pre-flight read above is not the boundary — it exists to skip a
            no-op append. This runs against the locked connection, before the
            chain hash is computed, so the op the row actually carries is the
            one the ledger's own state implies at the append timestamp.
            """
            live = pin_state(locked_conn)["pins"].get((_art.kind, _art.name))
            if live is None:
                _holder["status"] = "pinned"
                return {"op": "observe"}
            if live["digest"] == _art.digest:
                _holder["status"] = "unchanged"
                return {"op": "observe"}
            _holder["status"] = "diverged"
            _holder["pinned"] = live["digest"]
            return {"op": "diverge", "pinned_digest": live["digest"],
                    "pin_event": live["pin_event"]}

        meta = {"op": "observe", "artifact_kind": art.kind,
                "artifact": art.name, "digest": art.digest}
        if session:
            meta["session"] = session
        event_id = append_event_checked(
            conn, PIN_SOURCE, PIN_KIND, meta=meta, prepare=stamp,
        )
        results.append({
            "status": holder.get("status", "pinned"), "artifact": art,
            "digest": art.digest, "event": event_id,
            "pinned": holder.get("pinned"),
        })
    return results


def _authorize(conn, authorization, action: str, scope: str, **covered):
    """Operator authorization, reusing the one OperatorActionV1 path.

    Deliberately identical to ``grants._authorize``: a second way to say "the
    operator approved this" is a second way to be wrong about it.
    """
    if authorization is None:
        try:
            return test_mode_authorization(conn, action, scope, **covered)
        except AttestationError as exc:
            raise PinError(
                f"{action} is an operator act and requires a verified "
                f"authorization (contextd/attest.py). Moving a pin is how a "
                f"poisoned artifact would become policy. ({exc})"
            ) from exc
    if not authorization.matches(action, scope, **covered):
        raise PinError(
            f"the authorization does not cover exactly {action} on {scope}"
        )
    return authorization


def adopt(conn, art: Artifact, *, reason: str = "",
          authorization=None) -> dict:
    """"Yes, I meant to update that." The only thing that moves a pin.

    Humans appear here and nowhere else in this module: first sight is
    automatic, matching is silent, and divergence is recorded without asking
    anyone. A signature is required only at the exception.

    The signed action names the artifact, its kind, and the exact digest being
    adopted, so an authorization to adopt one version of a skill cannot be
    redeemed against another.
    """
    if not isinstance(art, Artifact):
        raise PinError("adopt takes an Artifact built by pinning.artifact()")
    arguments = {"artifact": art.name, "artifact_kind": art.kind,
                 "digest": art.digest}
    body = reason.strip() or None
    authorization = _authorize(conn, authorization, ADOPT_ACTION, "global",
                               arguments=arguments, content=body, reason=body)
    event_id = authorized_append(
        conn, PIN_SOURCE, PIN_KIND, authorization, ADOPT_ACTION, "global",
        arguments=arguments, content=body, reason=body,
        meta={"op": "adopt", "artifact_kind": art.kind, "artifact": art.name,
              "digest": art.digest},
    )
    return {"event": event_id, "artifact": art,
            "pin": pin_state(conn)["pins"].get((art.kind, art.name))}


def break_chain(conn, session: str, *, reason: str = "",
                authorization=None) -> int:
    """Explicitly end one session's inherited provenance. Operator-signed.

    Transitive taint that anyone can clear is not transitive taint. This is the
    "unless something explicitly breaks the chain" clause, and it is an operator
    act for the same reason ``grant.add`` is.
    """
    if not isinstance(session, str) or not session:
        raise PinError("a chain break names the session it ends")
    arguments = {"session": session}
    body = reason.strip() or None
    authorization = _authorize(conn, authorization, BARRIER_ACTION, "global",
                               arguments=arguments, content=body, reason=body)
    return authorized_append(
        conn, ACT_SOURCE, BARRIER_KIND, authorization, BARRIER_ACTION, "global",
        arguments=arguments, content=body, reason=body,
        meta={"session": session},
    )


def pinned_append(conn, source: str = ACT_SOURCE, kind: str = ACT_KIND, *,
                  artifacts=(), session: str | None = None, untrusted=(),
                  content: str | None = None, meta: dict | None = None,
                  mode: str = MODE_RECORD) -> int:
    """Append one act, labeled with the context that produced it.

    The verification and the act are one transaction, and that is the whole
    design:

    * ``prepare`` runs under the exclusive chain lock, *before* the chain hash
      is computed, and resolves every presented artifact against the pin
      registry as of the append timestamp. What it returns is written into this
      row. So the act's own bytes name which instruction-position digests were
      in force, and a divergence is not adjacent to the act — it is *in* it,
      chained and witnessed with it. Same mechanism ``grants.granted_append``
      uses to stamp the covering grant into a delegated act.
    * in gate mode ``bind`` raises a pre-declared :class:`~contextd.db.Refusal`,
      so the refusal row is committed by the same transaction that detected it,
      after the act has been rolled back. Exactly one of {act, refusal} is ever
      durable, and the caller never had to cooperate to get evidence written.

    ``mode`` decides only whether refusal happens. Both modes write the same
    ``("act", "act")`` row with the same schema, so an export never has to know
    which one produced it.
    """
    mode = _check_mode(mode)
    arts = _normalize_artifacts(artifacts)
    sources = _normalize_sources(untrusted)
    schema = schema_for(source, kind)
    if schema is None or "provenance" not in schema:
        raise PinError(
            f"event type {source}/{kind} does not declare a provenance field; "
            f"the closed registry decides what may carry one"
        )
    presented = [art.as_dict() for art in arts]
    context = context_digest(arts)
    holder: dict = {}

    def stamp(locked_conn, _ts):
        entries = resolve(pin_state(locked_conn)["pins"], arts)
        holder["instructions"] = entries
        return {"provenance": {"instructions": entries, "untrusted": sources,
                               "context_digest": context}}

    def gate(_locked_conn, _ts, _event_id):
        if mode != MODE_GATE:
            return
        entries = holder["instructions"]
        diverged = [e for e in entries if e["status"] == "diverged"]
        if diverged:
            raise Refusal("pin_diverged", PinRefused(
                "pin_diverged",
                f"REFUSED: {len(diverged)} instruction-position artifact(s) "
                f"diverged from their pins. This is an operator decision — "
                f"adopt the new digest, or restore the pinned bytes.",
            ))
        unknown = [e for e in entries if e["status"] == "pinned"]
        if unknown:
            raise Refusal("pin_unknown", PinRefused(
                "pin_unknown",
                f"REFUSED: {len(unknown)} instruction-position artifact(s) "
                f"are unpinned. Trust-on-first-sight is a record-mode "
                f"affordance; a transaction path requires an existing pin.",
            ))

    refusals = None
    if mode == MODE_GATE:
        # The refusal rows' exact bytes are fixed here, before the lock, because
        # the recovery journal has to name the chain hash of every outcome this
        # append may leave behind. Everything in them is known pre-lock: the
        # presented context and its digest. Which artifact diverged is *not*
        # reproduced — it is recovered deterministically by folding the pin
        # registry up to this event, which is evidence the refused caller had no
        # hand in.
        refusals = {
            reason: {
                "source": PIN_SOURCE, "kind": REFUSE_KIND,
                "meta": {"reason": reason, "context": presented,
                         "context_digest": context,
                         **({"session": session} if session else {})},
            }
            for reason in PIN_REFUSAL_REASONS
        }

    payload = {**(meta or {}), "provenance": {
        # A pre-flight value, replaced by `stamp` under the lock. It exists
        # because `append_event_checked` validates the row's metadata once
        # before it takes the lock, and `provenance` is a required field.
        # It is never what gets written.
        "instructions": resolve(pin_state(conn)["pins"], arts),
        "untrusted": sources, "context_digest": context,
    }}
    if session:
        payload["session"] = session
    # On refusal `append_event_checked` commits the refusal row, then re-raises
    # the cause — the PinRefused built above — so the caller learns nothing the
    # ledger does not already hold.
    return append_event_checked(
        conn, source, kind, content=content, meta=payload,
        prepare=stamp, bind=gate, refusals=refusals,
    )


# --- provenance, as a reduction ----------------------------------------------

def _extend(existing: list, additions) -> list:
    """Ordered-unique union. Order is evidence: it is the order acts happened."""
    out = list(existing)
    for item in additions:
        if item not in out:
            out.append(item)
    return out


def reduce_provenance(conn, up_to_event: int | None = None) -> dict:
    """Fold acts in id order into what each one inherited.

    ``{"acts": [...], "anomalies": [...]}``. Same shape and same reasoning as
    ``grants.reduce_grants``: nothing is stored pre-reduced, so a direct append
    cannot pre-declare itself clean.

    Transitivity is the point. If untrusted content entered at step 3, every
    later act in that session inherits it — including acts that never mention
    it again — until an operator-signed ``("act", "barrier")`` breaks the chain.
    A barrier without a verified authorization is an anomaly and breaks nothing.
    """
    acts: list = []
    anomalies: list = []
    carried: dict = {}

    query = "SELECT id, ts, source, kind, content, meta FROM events WHERE source='act'"
    parameters: tuple = ()
    if up_to_event is not None:
        query += " AND id <= ?"
        parameters = (int(up_to_event),)

    for row in conn.execute(query + " ORDER BY id", parameters).fetchall():
        meta = _meta(row)
        session = meta.get("session_id") or meta.get("session") or ""
        event_id = row["id"]
        if row["kind"] == BARRIER_KIND:
            body = row["content"] or None
            level = assurance_for_event(
                conn, row, action=BARRIER_ACTION, scope="global",
                arguments={"session": session}, content=body, reason=body,
            )
            if level not in OPERATOR_LEVELS:
                anomalies.append({
                    "event": event_id,
                    "why": "barrier lacks a verified operator authorization; a "
                           "chain break the model can write itself is a "
                           "laundering primitive",
                })
                continue
            carried[session] = {"instructions": [], "untrusted": [],
                                "diverged": []}
            acts.append({"event": event_id, "kind": BARRIER_KIND,
                         "session": session, "ts": row["ts"]})
            continue
        if row["kind"] != ACT_KIND:
            continue
        provenance = meta.get("provenance") or {}
        instructions = provenance.get("instructions") or []
        direct = [e.get("digest") for e in instructions if e.get("digest")]
        diverged = [e.get("digest") for e in instructions
                    if e.get("status") == "diverged" and e.get("digest")]
        untrusted = list(provenance.get("untrusted") or [])
        inherited = carried.get(session) or {"instructions": [], "untrusted": [],
                                             "diverged": []}
        acts.append({
            "event": event_id, "kind": ACT_KIND, "session": session,
            "ts": row["ts"], "label": meta.get("label", ""),
            "direct": {"instructions": direct, "untrusted": untrusted},
            "inherited": {"instructions": list(inherited["instructions"]),
                          "untrusted": list(inherited["untrusted"])},
            "diverged": {"direct": diverged,
                         "inherited": list(inherited["diverged"])},
            "tainted": bool(untrusted or diverged or inherited["untrusted"]
                            or inherited["diverged"]),
        })
        carried[session] = {
            "instructions": _extend(inherited["instructions"], direct),
            "untrusted": _extend(inherited["untrusted"], untrusted),
            "diverged": _extend(inherited["diverged"], diverged),
        }
    return {"acts": acts, "anomalies": anomalies}


def acts_touched_by(conn, digest: str, up_to_event: int | None = None) -> list:
    """Every act a digest touched, in id order.

    Given a digest later identified as malicious — a skill's poisoned revision,
    say — this answers "what did it reach?" exactly, by folding the ledger
    rather than by searching text. An act qualifies if it named the digest
    itself (``direct``) or if it ran after one that did, in the same session,
    with no operator-signed barrier in between (``inherited``).

    Acts *before* the mutation are never in the answer: the fold is forward-only
    in id order, so a digest cannot reach backwards in time.
    """
    if not isinstance(digest, str) or len(digest) != 64:
        raise PinError("a lineage query takes one 64-character hex digest")
    touched = []
    for record in reduce_provenance(conn, up_to_event)["acts"]:
        if record["kind"] != ACT_KIND:
            continue
        if digest in record["direct"]["instructions"]:
            relation = "direct"
        elif digest in record["inherited"]["instructions"]:
            relation = "inherited"
        else:
            continue
        touched.append({"event": record["event"], "session": record["session"],
                        "label": record["label"], "relation": relation,
                        "tainted": record["tainted"]})
    return touched
