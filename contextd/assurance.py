"""Typed provenance vocabulary: five separate things that were one string.

The original design carried provenance in caller-chosen metadata —
``CONTEXTD_CLIENT``, ``meta.actor``, ``meta.authority``, ``meta.role`` — and
read those strings back as if they meant something. Under the current threat
model (docs/SECURITY.md §1) the caller is the attacker, so ``authority =
"operator"`` is a claim by the attacker about the attacker.

This module makes the distinctions explicit and un-collapsible:

    origin_claim   what the caller said it was            zero assurance
    transport      the channel the bytes arrived on       observed, weak
    principal      the authenticated identity of the      OS-level, a UID —
                   RPC peer                                never a human
    attestation    a verified OperatorActionV1 signature  the only thing that
                                                          grounds "operator"
    integrity      whether stored bytes are unaltered     chain / witness /
                                                          service signature

Nothing here promotes one to another. There is deliberately no function that
turns a `transport` or an `origin_claim` into an `attestation`, because the
absence of that function is the security property.
"""

from dataclasses import dataclass, field

# --- assurance levels, weakest to strongest ---------------------------------

#: A caller said so. Nothing checked it.
UNVERIFIED = "unverified"

#: Written before this hardening existed. Its `actor`/`authority`/`role` labels
#: are preserved byte-for-byte and mean exactly nothing about authentication.
#: A legacy event can never authorize a grant or ground a human claim.
LEGACY_UNVERIFIED = "legacy_unverified"

#: The receiving component observed the channel itself (an ingester saw a file
#: change; the daemon saw an RPC arrive). Not attributable to a human.
TRANSPORT_OBSERVED = "transport_observed"

#: Taken under a verified delegation. Traceable to an operator-authorized grant
#: but performed by a model — never equivalent to an operator act.
MODEL_GRANTED = "model_granted"

#: A verified OperatorActionV1 from a registered, presence-bound hardware key.
#: The only level that grounds authenticated-human provenance.
OPERATOR_AUTHORIZED = "operator_authorized"

#: A test-only software signer produced this. Impossible in production mode;
#: named so loudly that it cannot be mistaken for the real thing.
INSECURE_TEST_SIGNER = "INSECURE_TEST_SIGNER"

ASSURANCE_LEVELS = (
    UNVERIFIED,
    LEGACY_UNVERIFIED,
    TRANSPORT_OBSERVED,
    MODEL_GRANTED,
    OPERATOR_AUTHORIZED,
    INSECURE_TEST_SIGNER,
)

#: Levels that may ground an authenticated-human claim. Exactly one entry, and
#: it stays exactly one entry.
AUTHENTICATED_HUMAN = frozenset({OPERATOR_AUTHORIZED})

#: Levels that may authorize a delegated act.
CAN_DELEGATE = frozenset({OPERATOR_AUTHORIZED})

# Caller-supplied strings that used to be read as authority. They are now
# recognised only so they can be explicitly refused.
FORGEABLE_AUTHORITY_LABELS = frozenset({
    "operator", "human", "user", "operator_via_model", "owner", "admin",
})


#: Assurance resolvers for event types whose level is established by a reducer
#: that does not live here — a loop's by replaying the loop reduction, a
#: supersession's by verifying the edge. The module that owns the event type
#: registers its own resolver at import time; nothing in this module imports
#: those modules, which is what keeps the evidence core free of the daemon.
#:
#: **A type in RESOLVER_REQUIRED with no resolver RAISES** (ruling R9, applied
#: uniformly to every hook in this boundary). Falling through to
#: `assurance_of` would answer "unverified" — technically true of THIS BUILD,
#: and read by an adjudicator as a fact about the EVENT. A loop the daemon's
#: reducer would have resolved to operator_authorized would be reported as
#: unverified by a build that merely forgot to register, and nothing in the
#: output would distinguish the two. That is a silent wrong answer, which this
#: codebase does not ship.
#:
#: Types NOT in RESOLVER_REQUIRED keep the metadata-only fallback, because for
#: them "nothing checked it" is the whole truth rather than a gap.
_RESOLVERS: dict[tuple[str, str], object] = {}

#: (source, kind) pairs whose assurance is established by replaying a reducer,
#: and therefore cannot be read off metadata at all. Named as strings, never
#: imported: contextd/schemas.py already carries the same vocabulary, and the
#: core must be able to say "I cannot verify this" without depending on the
#: module that could.
RESOLVER_REQUIRED = frozenset({("loop", "loop"), ("decision", "decision")})


def register_assurance_resolver(source: str, kind: str, resolver) -> None:
    """Declare how one event type's stored assurance is verified.

    `resolver(conn, event_id) -> str` must return a level from
    ASSURANCE_LEVELS. Registration is idempotent and last-wins so a reload
    does not fail; there is deliberately no unregister, because a build that
    can verify a type should not be able to forget how mid-process.
    """
    _RESOLVERS[(source, kind)] = resolver


class AssuranceError(RuntimeError):
    """An action claimed an assurance level it has not established."""


class ResolverNotRegistered(AssuranceError):
    """A reducer-backed event type was resolved with no resolver registered."""


# --- the five concepts ------------------------------------------------------

@dataclass(frozen=True)
class OriginClaim:
    """What the caller said about itself. Bounded, redacted, and never trusted."""

    claimed_client: str = ""

    def __post_init__(self):
        if self.claimed_client and len(self.claimed_client) > 64:
            raise ValueError("claimed_client exceeds its bound")


@dataclass(frozen=True)
class Transport:
    """The channel the receiving component observed."""

    channel: str = "unknown"          # mcp | cli | fs | chrome | safari | claude_code
    observed_by: str = "client"       # client | service


@dataclass(frozen=True)
class Principal:
    """The authenticated identity of an RPC peer.

    Established from OS-level peer credentials on the Unix socket, never from
    anything in the request body. **A principal is a UID, not a person.** Under
    this threat model the desktop UID is exactly as likely to be the attacker
    as the operator, which is why a principal alone authorizes nothing that
    matters.
    """

    uid: int = -1
    pid: int = -1
    kind: str = "unknown"             # service | client | unknown

    @property
    def authenticated(self) -> bool:
        return self.uid >= 0 and self.kind in ("service", "client")


@dataclass(frozen=True)
class Attestation:
    """A verified OperatorActionV1 signature. See contextd/attest.py."""

    key_id: str
    action_digest: str
    signer: str                       # secure_enclave | INSECURE_TEST_SIGNER
    verified_at: str

    @property
    def production(self) -> bool:
        return self.signer == "secure_enclave"


@dataclass(frozen=True)
class Integrity:
    """Whether stored bytes are unaltered since acceptance, and by what."""

    chain_ok: bool = False
    witness_ok: bool = False
    service_signed: bool = False

    @property
    def level(self) -> str:
        if self.service_signed:
            return "service_signed"
        if self.chain_ok and self.witness_ok:
            return "tamper_evident_same_uid"
        return "unverified"


@dataclass(frozen=True)
class Provenance:
    """The whole picture for one event, with the parts kept apart."""

    origin_claim: OriginClaim = field(default_factory=OriginClaim)
    transport: Transport = field(default_factory=Transport)
    principal: Principal = field(default_factory=Principal)
    assurance: str = UNVERIFIED
    attestation: Attestation | None = None
    integrity: Integrity = field(default_factory=Integrity)

    @property
    def authenticated_human(self) -> bool:
        """True only for a verified production attestation. A test signer is
        never authenticated-human, however loudly it is labelled."""
        return (
            self.assurance in AUTHENTICATED_HUMAN
            and self.attestation is not None
            and self.attestation.production
        )

    def as_dict(self) -> dict:
        out = {
            "origin_claim": {"claimed_client": self.origin_claim.claimed_client},
            "transport": {"channel": self.transport.channel,
                          "observed_by": self.transport.observed_by},
            "principal": {"uid": self.principal.uid, "kind": self.principal.kind,
                          "authenticated": self.principal.authenticated},
            "assurance": self.assurance,
            "integrity": self.integrity.level,
            "authenticated_human": self.authenticated_human,
        }
        if self.attestation is not None:
            out["attestation"] = {
                "key_id": self.attestation.key_id,
                "signer": self.attestation.signer,
                "production": self.attestation.production,
            }
        return out


# --- resolving stored events ------------------------------------------------

def assurance_of(meta: dict | None) -> str:
    """Resolve metadata-only claims without granting cryptographic assurance.

    This function has no connection, event bytes, key registry, nonce row, or
    service signature, so it is structurally incapable of verifying an
    attestation.  In particular, ``{"attestation": {"signer":
    "secure_enclave"}}`` is just more caller-controlled JSON.  Reducers that
    enforce authority must use :func:`assurance_for_event` with exact action
    semantics instead.
    """
    meta = meta or {}
    if meta.get("attestation") is not None:
        return UNVERIFIED
    recorded = meta.get("assurance")
    if recorded in (MODEL_GRANTED, TRANSPORT_OBSERVED, LEGACY_UNVERIFIED):
        return recorded
    if meta.get("grant") is not None:
        return MODEL_GRANTED
    # Anything whose only claim to authority is a caller-written label is
    # legacy/unverified — including, deliberately, `authority="operator"`.
    if meta.get("authority") in FORGEABLE_AUTHORITY_LABELS:
        return LEGACY_UNVERIFIED
    if meta.get("actor") in FORGEABLE_AUTHORITY_LABELS:
        return LEGACY_UNVERIFIED
    return UNVERIFIED


def assurance_for_event(conn, event_row, *, action: str, scope: str = "global",
                        arguments: dict | None = None,
                        content: str | None = None,
                        reason: str | None = None) -> str:
    """Cryptographically resolve one stored event and its exact semantics.

    A verified operator signature is necessary but, after a service cutover,
    not sufficient: the event must also carry the authority service's
    signature.  Events at or before a cutover stay legacy evidence because the
    cutover explicitly does not authenticate prior history.
    """
    from .attest import verify_stored_authorization

    authorization = verify_stored_authorization(
        conn,
        event_row,
        action=action,
        scope=scope,
        arguments=arguments,
        content=content,
        reason=reason,
    )
    if authorization is None:
        try:
            import json

            raw = event_row["meta"]
            meta = json.loads(raw or "{}") if isinstance(raw, str) else raw
        except (KeyError, TypeError, ValueError):
            meta = {}
        return assurance_of(meta)

    # Once the archive has an integrity cutover, a row absent from the
    # service-signed coverage set was not accepted by the authority daemon.
    import sqlite3

    from .ledger_sig import LedgerSignatureError, cutover_tip_id, verify_event

    try:
        cutover = cutover_tip_id(conn)
    except sqlite3.OperationalError:  # pre-schema legacy inspection only
        cutover = None
    except LedgerSignatureError:
        return UNVERIFIED
    event_id = int(event_row["id"])
    if cutover is not None:
        if event_id <= cutover:
            return LEGACY_UNVERIFIED
        verification = verify_event(conn, event_id)
        if not verification.get("signed") or not verification.get("ok"):
            return UNVERIFIED
    return authorization.assurance


def is_authenticated_human(meta: dict | None) -> bool:
    """Metadata alone never authenticates a human.

    Kept as a deliberately fail-closed compatibility helper.  Code with an
    event row must use :func:`is_authenticated_event` instead.
    """
    del meta
    return False


def is_authenticated_event(conn, event_row, **semantics) -> bool:
    """True only for a production operator signature over this exact event."""
    return assurance_for_event(conn, event_row, **semantics) in AUTHENTICATED_HUMAN


def known_event_assurance(conn, event_row) -> str:
    """Resolve assurance for event types with a closed action mapping.

    This is the bridge used by provenance/experiment displays.  Unknown event
    types stay metadata-only and therefore unverified; adding a new operator
    action requires adding its exact semantic mapping here or in its reducer.
    """
    import json

    try:
        raw = event_row["meta"]
        meta = json.loads(raw or "{}") if isinstance(raw, str) else raw
        if not isinstance(meta, dict):
            return UNVERIFIED
        source, kind = event_row["source"], event_row["kind"]
        if source == "note" and kind == "note":
            return assurance_for_event(
                conn,
                event_row,
                action="note.deliberate",
                scope="global",
                content=event_row["content"] or None,
            )
        resolver = _RESOLVERS.get((source, kind))
        if resolver is not None:
            return resolver(conn, int(event_row["id"]))
        if (source, kind) in RESOLVER_REQUIRED:
            raise ResolverNotRegistered(
                f"{source}/{kind} events carry an assurance that only its "
                f"reducer can establish, and no resolver is registered — this "
                f"build cannot say what this event's assurance is and will not "
                f"report 'unverified' as though it had checked. Register one "
                f"with contextd.assurance.register_assurance_resolver(); the "
                f"daemon registers its own when contextd.{source}s is imported."
            )
        return assurance_of(meta)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return UNVERIFIED


def refuse_forged_authority(**caller_fields) -> None:
    """Refuse any attempt to pass authority as a free-form string.

    Domain mutators used to accept ``actor="human"`` / ``authority="operator"``
    from anyone who could call them. They now take a verified authorization
    object or nothing; this is the guard that makes the old call shape fail
    loudly instead of silently minting authority.
    """
    for name, value in caller_fields.items():
        if isinstance(value, str) and value.lower() in FORGEABLE_AUTHORITY_LABELS:
            raise AssuranceError(
                f"refused: {name}={value!r} is a caller-supplied string and "
                f"cannot establish authority. Operator-authoritative acts "
                f"require a verified authorization object "
                f"(contextd/attest.py); see docs/SECURITY.md §3."
            )


def describe(level: str) -> str:
    """One honest sentence per level, for CLI help and `ctx why` output."""
    return {
        UNVERIFIED: "a caller said so; nothing checked it",
        LEGACY_UNVERIFIED:
            "written before authenticated provenance existed; its authority "
            "labels are preserved but mean nothing about authentication",
        TRANSPORT_OBSERVED:
            "the receiving component observed the channel; not attributable "
            "to a human",
        MODEL_GRANTED:
            "taken by a model under a verified operator delegation; traceable "
            "to a grant, never equivalent to an operator act",
        OPERATOR_AUTHORIZED:
            "a verified signature from a registered presence-bound hardware "
            "key over exactly these bytes; not proof of authorship, "
            "comprehension, or truth",
        INSECURE_TEST_SIGNER:
            "produced by a test-only software signer; carries no assurance "
            "and is impossible in production mode",
    }.get(level, "unknown assurance level")
