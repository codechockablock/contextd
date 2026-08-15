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


class AssuranceError(RuntimeError):
    """An action claimed an assurance level it has not established."""


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
    """The honest assurance level of a stored event.

    The rule that matters: a stored ``authority``/``actor``/``role`` string is
    **never** promoted. An event reaches OPERATOR_AUTHORIZED only by carrying a
    verified attestation block, which only the authority plane writes.
    """
    meta = meta or {}
    attestation = meta.get("attestation")
    if isinstance(attestation, dict):
        signer = attestation.get("signer")
        if signer == "secure_enclave":
            return OPERATOR_AUTHORIZED
        if signer == INSECURE_TEST_SIGNER:
            return INSECURE_TEST_SIGNER
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


def is_authenticated_human(meta: dict | None) -> bool:
    """The single question every caller should ask instead of reading strings."""
    if assurance_of(meta) not in AUTHENTICATED_HUMAN:
        return False
    attestation = (meta or {}).get("attestation") or {}
    return attestation.get("signer") == "secure_enclave"


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
