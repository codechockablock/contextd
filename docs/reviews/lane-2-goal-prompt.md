# GOAL PROMPT — Lane 2: Instruction-position pinning and provenance

**Lane:** `gate-v1-lane-2` · **Status on delivery:** unstarted · **Depends on Lane 1.**
Parallel with Lanes 3, 4, 6. Feeds Lane 5.
**Repo:** `~/contextd`. **If the repo is not at that path, halt and report — do not search the
filesystem, do not consult memory, do not proceed at an inferred path.**

## Read this first: you are building something a competitor already built, on purpose

An earlier draft of this lane claimed the position was unoccupied. **That was false and has been
retracted.** Microsoft's `agent-governance-toolkit` already does tool-definition digest pinning and
already enforces it before execution. Verified firsthand at commit `7d0cef5`:

- `agent-governance-rust/agentmesh-mcp/src/mcp/security.rs` (~124–130): on `register_tool` it
  computes `description_hash = sha256_hex(&tool.description)` and
  `schema_hash = sha256_hex(&serde_json::to_string(&tool.input_schema)?)`. `check_rug_pull`
  (~153–181) compares both and reports which of `description` / `schema` changed; its caller
  (~191) raises the threat.
- `agent-governance-python/agent-os/modules/control-plane/src/agent_control_plane/tool_registry.py`:
  `verify_tool_integrity` (~361–375) re-hashes the handler's source and compares it to the
  registration-time hash. It runs **before execution** (~265) and on mismatch **blocks** —
  returning `{"success": False, "error": "Tool integrity verification failed: …"}` and recording to
  `self._integrity_violations`.
- `agent-marketplace`: Ed25519-signed plugin manifests with the artifact SHA-256 bound into the
  signed bytes, and an installer that fails closed on a missing or untrusted signature.

**Operator ruling (2026-08-17):** *"it doesn't have to be different from what microsoft. if
tool-definition digest pinning and fires it before execution is the correct path then thats what
we'll do too alongside our differentiators."*

So: **build the same mechanism.** Convergence with an independent implementation is evidence the
design is correct. Do not contort the design to look different, do not invent a novel scheme to
avoid overlap, and do not describe this as new. Where their shape is good, borrow the shape and say
so — in code comments and in your report. **Do not copy, vendor, or adapt their code**; read it as
prior art, implement independently in contextd's idiom.

## Objective

A poisoned skill is untrusted content arriving as instruction, before a session starts, in the
position the operator's own policy should occupy. Taint tracking on retrieved data does not touch
it: nothing gets tainted, the agent is following what it correctly believes are its instructions,
and the record is honest all the way down. A skill is a delegation the operator never signed.
`grants.py` already refuses that shape for grants; extend the same refusal to instruction-position
content.

## What is already solved vs. what you must earn

| | Prior art (Microsoft) | What Lane 2 adds |
|---|---|---|
| Digest tool/skill definitions at registration | Yes | Same. Borrow the shape. |
| Verify before execution, refuse on mismatch | Yes — blocks | Same. Borrow the shape. |
| Signed distribution of definitions | Yes (Ed25519 manifests) | Out of scope this lane. |
| **Pin survives process restart** | **No** — `registry: Mutex::new(HashMap::new())` (security.rs ~114) is per-process; `_integrity_violations` is an in-memory list. A restart re-TOFUs, so a definition mutated across a restart presents as first sight, not divergence. | **Yes** — the pin is a ledger event: durable, chained, witnessed. |
| **Divergence is evidence, not a log line** | No — an in-memory violation list | The divergence is an appended, chained event, bound into the same transaction as the act it preceded. |
| **Lineage: which acts did a bad digest touch?** | No | Fold over events in id order; exact answer. |

**The in-memory registry is not a defect in their scope** — a per-session MCP security scanner
reasonably keeps per-session state. Say that plainly wherever this contrast appears. The contrast
is durability and evidentiary weight, not correctness.

**This is a claim, not yet a capability.** Under the program's one rule — *no competitive claim
ships without a test id behind it* — none of the right-hand column may enter `COMPARISON.md` until
a test substantiates it. `COMPARISON.md` currently concedes this row to Microsoft outright and
**stays that way** until you produce the test below. Lane 5 writes the words; you produce the
evidence.

### The test that earns the claim

A restart test, because that is exactly what an in-process registry structurally cannot pass:

1. Pin a skill/tool definition. 2. Tear down the process entirely. 3. In a **new** process, present
a mutated definition. 4. Assert the divergence is detected, that it is detected *as divergence from
the pinned value* and not as first sight, and that the resulting event is present in the ledger and
survives `verify_chain`.

Name it something a reviewer can find (e.g. `test_pin_survives_process_restart`), and report the
test id in your completion report. That id is what Lane 5 is permitted to cite.

## Definition of done

- [ ] Skills, tool definitions, and system-prompt fragments are digested and pinned on first sight
      (TOFU). Zero-setup: no key required to begin.
- [ ] A digest change on a pinned artifact is an **event**. In record mode the act proceeds and the
      divergence lands in the ledger with the act that followed it. In gate mode an unknown or
      changed digest in a transaction path refuses.
- [ ] An operator signature can override a pin ("yes, I meant to update that"). Humans appear only
      at exceptions — never in the happy path. Reuse the existing `OperatorActionV1` machinery
      (`attest.prepare_action` / `authorized_append`); do not invent a second authorization path.
- [ ] Every act carries a provenance label: which instruction-position digests, and which untrusted
      content sources, were in the context that produced it.
- [ ] Provenance is **transitive**. If untrusted content entered at step 3, everything after
      inherits it unless something explicitly breaks the chain. Implement as a fold over events in
      id order — the same reduction shape as `grants.reduce_grants`.
- [ ] Lineage query: given a digest later identified as malicious, return **every** act it touched.
      Test with a synthetic poisoned-skill fixture; the query must return exactly the acts that
      followed the mutation — no more, no fewer.
- [ ] `test_pin_survives_process_restart` (above) passes.
- [ ] Record mode and gate mode share one ledger schema, so exports never care which produced them.

## Repo constraints

**MAY create / modify:** a new pinning/provenance module under `contextd/`, `contextd/schemas.py`
(new event types — **coordinate with Lane 1, which is adding the commerce vocabulary to the same
closed registry; rebase onto its work rather than racing it**), `tests/`, `docs/` (except
`docs/reviews/`).

**MUST NOT touch:**

- `examples/gate_proof/` — frozen reference point; must keep passing unmodified.
- `COMPARISON.md` and `docs/reviews/` — owned by Lane 5 / pre-flight.
- Files owned by Lanes 1, 3, 4, 6 without coordination.
- Git history, tags, remotes. **Do not commit** — the operator makes his own commits.

## Verification gates

```bash
cd ~/contextd
python -m pytest -q                                    # no new failures vs. the baseline you captured
python -m pytest tests/ -q -k "pinning or tofu or provenance or lineage or restart"
python examples/gate_proof/concurrent_redemption.py    # EXPECT exit 0, "1 success, 7 refused"
git status --porcelain examples/gate_proof/ COMPARISON.md docs/reviews/   # EXPECT empty
```

Plus the poisoned-skill fixture: a pinned skill mutated mid-session, with the lineage query
returning exactly the acts that followed the mutation.

## Stop conditions — halt and report

- The repo is not at `~/contextd`.
- The gate-proof demo fails or would require modification to pass.
- The existing suite was already failing before your first change (capture the baseline first).
- Lane 1's schema work conflicts with yours in a way you cannot rebase onto — report the collision
  rather than editing around it.
- Any impulse to claim novelty for the pinning mechanism itself, or to describe Microsoft's
  implementation as merely warning (it blocks), or to omit that their design is reasonable for its
  scope. All three would fail the program's honesty bar.
- Any impulse to copy or adapt code from the Microsoft repo. Read as prior art only.
- A behavioral detector that returns a verdict, an LLM in the transaction path, custom
  cryptography, or a hosted service. All four are out of scope by design.

## Completion report format

Report **raw tool output**, never a summary of state you did not directly observe.

1. Exact output of each verification gate, pasted.
2. The test id that earns the durability claim, plus what it would catch if it regressed.
3. The lineage fixture result — the exact set of acts returned, and why that set is exactly right.
4. Every citation you make about the Microsoft implementation, with a verified/unverified verdict.
5. One honest paragraph: does the pin actually bind what you think it binds? Name what an attacker
   who controls the skill file but not the ledger can still do.
