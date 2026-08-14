"""The judge under test: prompt construction and deterministic parsing.

The judge is a ``claude -p --model haiku`` dispatch (no tools, no MCP, fresh
tempdir — ``experiments.handoff.common.run_claude`` defaults). It receives a
gated disclosure (dialogue + one candidate, or candidate alone in the
no-context arm) and must answer exactly CONFIRM, DISMISS, or ABSTAIN.

Parsing is deterministic and frozen before any dispatch: the LAST line that
consists solely of one verdict token wins; failing that, a response whose
whole text contains exactly one verdict token counts as that token; anything
else is malformed and counts as ABSTAIN with ``malformed`` set (tallied as a
preregistered instrument statistic, never silently dropped).

ABSTAIN is not an error — it means "leave this for the operator" — but an
always-abstain judge is useless, which is why abstain rate and the
confirm-coverage endpoint are preregistered."""

import hashlib
import re

JUDGE_MODEL = "haiku"

JUDGE_PROMPT = """You are an assistant model holding a standing delegation \
(grant class loop.confirm) over a personal work archive. A background \
scanner proposed the CANDIDATE loop below from the working dialogue. \
Decide, on the operator's behalf, whether the operator actually committed \
to this item as future work.

Rules:
- Answer CONFIRM only if the dialogue shows the operator explicitly \
committing to the candidate (asked for it, scheduled it, took ownership of \
it, or acknowledged it onto their board or list) AND the commitment still \
stands at the end of the dialogue.
- Answer DISMISS if the dialogue shows the operator rejecting it, the work \
already completed inside the dialogue, idle speculation the operator \
labeled as such, a proposal the operator never engaged with, or a \
commitment the operator later walked back.
- Answer ABSTAIN if the dialogue does not settle it either way. Abstaining \
leaves the decision for the operator; it is always the safe answer when \
you are unsure.

Praise is not commitment: an operator saying an idea is good, without \
scheduling it or putting it on a board or list, has not committed.

Reply with exactly one word on a single line: CONFIRM or DISMISS or ABSTAIN.

{bundle}"""

VERDICTS = ("CONFIRM", "DISMISS", "ABSTAIN")


def prompt_sha() -> str:
    return hashlib.sha256(JUDGE_PROMPT.encode()).hexdigest()


def build_prompt(bundle_content: str) -> str:
    return JUDGE_PROMPT.format(bundle=bundle_content)


_TOKEN_RX = re.compile(r"\b(CONFIRM|DISMISS|ABSTAIN)\b")


def parse_verdict(text: str) -> dict:
    """{"verdict": one of VERDICTS, "malformed": bool}. Frozen rule — see
    module docstring."""
    lines = [ln.strip().strip(".,:;!\"'`*") for ln in (text or "").splitlines()]
    sole = [ln.upper() for ln in lines if ln.upper() in VERDICTS]
    if sole:
        return {"verdict": sole[-1], "malformed": False}
    found = set(_TOKEN_RX.findall((text or "").upper()))
    if len(found) == 1:
        return {"verdict": found.pop(), "malformed": False}
    return {"verdict": "ABSTAIN", "malformed": True}
