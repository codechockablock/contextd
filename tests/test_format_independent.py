"""`docs/FORMAT.md` is checked by an implementation that is not this one.

`tests/test_format_spec.py` already checks the document against the code, and
two of its tests reimplement the document's prose rather than string-matching
it. That is real evidence and this file does not replace it. But it is evidence
of a specific, limited kind: same repository, same language, same author's
reading of their own document, and — decisively — it imports the very module
whose behaviour it is confirming. A rule that is stated ambiguously, or omitted
entirely, is invisible to a checker that already knows the answer.

So `scripts/verify_format_independent.mjs` is a second implementation in
JavaScript that imports nothing from contextd: Node's SQLite driver, Node's
OpenSSL, an encoder written from FORMAT.md section 3's prose, and a chain hash
written from section 2's. This file builds an archive, hands the verifier a
directory, and checks what it says.

Three things are being pinned here, in descending order of importance:

1. **The disagreement it found.** FORMAT.md section 1 enumerates the values of
   the `source` column and omits `health`, which is a registered event source
   (`schemas.py:566`) written on a launchd timer by `hooks/health_sweep.py`.
   `test_the_independent_verifier_reports_the_documented_source_disagreement`
   pins that finding so it cannot be lost, and pins its exact shape so that
   fixing the document is what makes the test change.

2. **The verifier actually verifies.** A checker that returns success is worth
   nothing until it has been shown returning failure. The mutation battery
   below corrupts one thing at a time and requires a specific complaint each
   time — including the same-UID attack that repairs the chain and the witness,
   which is precisely the attack the chain cannot see and the signature can.

3. **Its independence is structural, not promised.** The verifier is executed
   from a working directory outside the repository, and its source is checked
   to import nothing but `node:` builtins.
"""

import json
import re
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

from tests.format_archive_support import (
    build_archive,
    copy_archive,
    delete_last_event,
    flip_signature_byte,
    mutate_attestation_argument,
    mutate_event_and_repair_chain,
    mutate_event_content,
    relabel_checkpoint_alg,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFIER = REPO_ROOT / "scripts" / "verify_format_independent.mjs"
VECTORS = REPO_ROOT / "tests" / "vectors" / "operator_action_v1.json"

NODE = shutil.which("node")

requires_node = pytest.mark.skipif(
    NODE is None,
    reason=(
        "the independent format verifier is written in JavaScript precisely so "
        "that it shares no runtime with contextd; without a node binary there is "
        "no second implementation to run and this evidence is simply absent"
    ),
)


def run_verifier(archive: Path, *, cwd: Path | None = None,
                 verifier: Path = VERIFIER, extra: tuple[str, ...] = ()):
    """Run the verifier and return (exit code, parsed findings, output).

    ``cwd`` defaults to the archive's own parent — never the repository — so
    nothing the verifier reports can have arrived by a relative path into
    contextd. ``verifier`` exists so a test can run a copy of the script from a
    directory with no vendored files beside it; ``extra`` appends flags.
    """
    result = subprocess.run(
        [NODE, str(verifier), str(archive), "--vectors", str(VECTORS), "--json",
         *extra],
        capture_output=True, text=True, timeout=300,
        cwd=str(cwd or archive.parent),
    )
    payload = None
    text = result.stdout
    # `--json` appends the findings object after the human report; the
    # top-level brace is the only one at column zero.
    brace = text.find("\n{\n")
    if brace != -1:
        payload = json.loads(text[brace:])
    return result.returncode, payload, text + result.stderr


@pytest.fixture
def archive(isolated_contextd_home):
    """A small archive carrying one of everything FORMAT.md specifies."""
    home = isolated_contextd_home
    summary = build_archive(home)
    assert summary["events"] >= 8
    assert summary["signatures"] >= 1, "fixture produced no service signatures"
    assert summary["checkpoints"] >= 1, "fixture produced no checkpoints"
    return home, summary


# --- the headline finding ---------------------------------------------------


@requires_node
def test_the_independent_verifier_agrees_with_the_documented_source_vocabulary(
    archive,
):
    """FORMAT.md section 1's `source` enumeration admits every value in a live
    archive — including `health`, which it used to omit.

    This test previously asserted the opposite. It was written to pin a
    finding: section 1 listed fourteen producing planes and left out `health`,
    even though ``("health", "sweep")`` is registered in
    ``schemas.HARNESS_SCHEMAS`` (`contextd/schemas.py:566`), is appended by
    ``hooks/health_sweep.py:243``, and is written roughly 48 times a day by
    ``launchd/com.contextd.health.plist`` — and even though section 8 rule 1
    named `health` while section 1 did not.

    Section 1 has been corrected and the drift is recorded in FORMAT.md's
    Errata. So the assertion flips, which is exactly what a test that pins a
    finding is supposed to do when the finding is fixed. What does NOT change
    is the check itself: the verifier still compares section 1's transcribed
    list against the archive's actual sources on every run, so the next
    omission fails here rather than in 2035.
    """
    home, _ = archive
    code, findings, text = run_verifier(home)

    assert findings is not None, f"verifier emitted no JSON:\n{text}"
    # The fixture must still contain the row that exposed the original bug, or
    # this test would pass by never exercising the case.
    assert "health" in findings["info"]["sources"], (
        "the fixture must contain a (health, sweep) row; without it this test "
        "would agree with section 1 for the wrong reason"
    )

    assert findings["spec_mismatch"] == [], (
        f"the document and the archive should now agree: {findings['spec_mismatch']}"
    )
    assert "source-vocabulary" in {p["check"] for p in findings["pass"]}
    assert findings["fail"] == [], (
        f"the archive itself should verify cleanly: {findings['fail']}"
    )
    assert code == 0, f"expected a clean exit now that section 1 is correct, got {code}"


def test_section_one_lists_every_source_the_registries_can_produce():
    """The document's list is checked against the registry it claims to mirror.

    Section 1 now says its enumeration is "exactly the set of first elements of
    the `(source, kind)` registry keys in §7". That is a checkable claim, and
    checking it here closes the loop that the original omission slipped
    through: the verifier catches a source that reaches a real archive, and
    this catches one that is merely *registered* and has not been written yet.
    """
    from contextd import schemas

    registered = {
        source
        for registry in (schemas.EVENT_SCHEMAS, schemas.INGEST_SCHEMAS,
                         schemas.HARNESS_SCHEMAS)
        for source, _ in registry
    }
    spec = (REPO_ROOT / "docs" / "FORMAT.md").read_text()
    source_row = [
        line for line in spec.splitlines()
        if line.startswith("| `source` |")
    ]
    assert len(source_row) == 1, "could not find section 1's `source` row"
    documented = {
        word.strip(" `,.")
        for word in source_row[0].split("Producing plane:")[1].split("`")
        if word.strip(" `,.") and not word.strip().startswith(("Fifteen", "and"))
    }
    missing = registered - documented
    assert not missing, (
        f"§1's source enumeration omits registered producing plane(s) {missing}; "
        f"this is the exact defect the Errata records, recurring"
    )


@requires_node
def test_the_document_reproduces_every_layer_it_does_specify(archive):
    """The positive result, stated as plainly as the negative one.

    A second implementation written from the prose alone recomputes the chain,
    reproduces the frozen canonical vectors byte-for-byte, and verifies event,
    tip, checkpoint and operator signatures. Sections 2, 3, 5 and 6 are correct
    and usable by a stranger; that is worth asserting rather than assuming.
    """
    home, summary = archive
    _, findings, text = run_verifier(home)
    assert findings is not None, text
    checks = {p["check"] for p in findings["pass"]}
    for required in (
        "chain-hash",            # section 2, recomputed from prose
        "chain-contiguity",      # section 10 step 1
        "vectors",               # section 3 against the frozen vectors
        "vector-refusal",        # section 3's refusals are load-bearing
        "witness-shape",         # section 6
        "witness-tip",           # section 10 step 3
        "service-signature",     # section 5 envelope, section 10 step 4
        "service-tip",           # section 5 tip payload
        "checkpoint",            # section 5 checkpoint payload, step 5
        "attestation",           # section 4, section 10 step 6
        "events-columns",        # section 1's ten columns, in order
    ):
        assert required in checks, f"{required} did not pass; findings: {findings}"

    assert findings["info"]["events"] == summary["events"]
    assert findings["info"]["service_signatures_verified"] == summary["signatures"]
    assert findings["info"]["service_checkpoints_verified"] == summary["checkpoints"]

    # The checkpoint asymmetry in section 5 -- `alg` present if and only if the
    # scheme is not the classical one -- is only exercised if both kinds are in
    # the archive. Say so rather than quietly covering one.
    if summary["hybrid"]:
        assert findings["info"]["checkpoint_algs"] == [
            "ecdsa-p256-sha256", "ml-dsa-44",
        ], "the hybrid fixture should exercise both sides of the alg asymmetry"


@requires_node
def test_the_verifier_no_longer_has_to_look_past_the_document(archive):
    """Section 10's recipe is now executable from the prose alone.

    Two things it needed were previously unstated, and the verifier recorded a
    spec gap for each: `archive_uuid`'s home (`archive_identity.uuid`), needed
    by step 5, and the `operator_keys` schema plus the fact that `public_der`
    is raw DER rather than the PEM `service_keys` uses, needed by step 6. Both
    are now written down in section 4 and named in section 5, so the verifier
    transcribes them instead of inferring them.

    Zero spec gaps is the assertion. If a future edit removes one of those
    statements, this test fails and the document stops claiming a recipe it
    cannot supply.
    """
    home, _ = archive
    _, findings, text = run_verifier(home)
    assert findings is not None, text
    assert findings["spec_gap"] == [], (
        f"the document should now supply everything section 10 needs: "
        f"{findings['spec_gap']}"
    )
    # And the steps those gaps used to block actually ran.
    checks = {p["check"] for p in findings["pass"]}
    assert {"service-tip", "checkpoint", "attestation"} <= checks, findings["pass"]


def test_the_document_states_the_der_versus_pem_asymmetry_in_both_directions():
    """The trap that made step 6 a guess: two key tables, two encodings.

    `service_keys.public_pem` is PEM and `operator_keys.public_der` is raw DER
    SubjectPublicKeyInfo. A verifier that assumes one from the other fails to
    load a key and has no idea why. The document has to say so from both
    sides — a reader arriving at either table must learn that the other is
    different — so both directions are asserted here.
    """
    spec = (REPO_ROOT / "docs" / "FORMAT.md").read_text()
    assert "public_der" in spec and "public_pem" in spec
    assert "raw DER SubjectPublicKeyInfo" in spec, "§4 must name the encoding"
    assert "not PEM" in spec or "*not* PEM" in spec
    # §5 must warn the reader coming the other way.
    section5 = spec.split("## 5. Service signatures")[1].split("\n## 6.")[0]
    assert "public_der" in section5, (
        "§5 documents public_pem; a reader who stops there must still be told "
        "operator_keys uses a different encoding"
    )
    # §10 step 6 must not send a verifier off without the encoding.
    assert "**raw DER, not PEM**" in spec


@requires_node
def test_the_verifier_reports_the_test_signer_rather_than_only_the_maths(archive):
    """Section 4: a record whose `signer` names the test signer must never be
    read as an operator act. An independent verifier that confirmed the ECDSA
    and said nothing else would hand an adjudicator a verified forgery-shaped
    record with no warning attached."""
    home, _ = archive
    _, findings, text = run_verifier(home)
    assert findings is not None, text
    assert findings["info"]["attestations_verified"] >= 1
    warnings = " ".join(w["detail"] for w in findings["warn"])
    assert "INSECURE_TEST_SIGNER" in warnings
    assert "secure_enclave" in warnings


# --- independence, as a property rather than a promise ----------------------


def test_the_verifier_imports_nothing_but_node_builtins():
    """The one property this whole file rests on, checked mechanically.

    An `import` of anything that is not a `node:` builtin would mean the second
    implementation shares state, code, or constants with the first, and every
    result above would collapse back into self-confirmation. The one permitted
    reach beyond node: builtins is a *dynamic* import of the vendored pure-JS
    ML-DSA verifier under scripts/vendor/ — third-party, pinned, hashed in
    scripts/vendor/PROVENANCE.md, and still zero contextd.
    """
    source = VERIFIER.read_text()
    imports = [
        line.strip() for line in source.splitlines()
        if line.strip().startswith("import ") or " from '" in line
    ]
    assert imports, "no imports found; did the verifier move?"
    for line in imports:
        if " from '" not in line:
            continue
        module = line.split(" from '")[1].split("'")[0]
        assert module.startswith("node:"), (
            f"the independent verifier imports {module!r}; it may import only "
            f"node: builtins, or it is no longer independent"
        )
    # The domain separators ("contextd.ServiceEnvelopeV1") and the table names
    # necessarily contain the string "contextd", so its presence proves
    # nothing either way. What must never appear is a reach into the package
    # itself — by import, by require, or by path.
    for forbidden in ("../contextd/", "contextd/db.py", "contextd/canonical.py",
                      "require('contextd", 'require("contextd'):
        assert forbidden not in source, f"the verifier reaches into {forbidden}"


def test_the_vendored_tree_is_self_contained_and_wired_verify_only():
    """The vendored ML-DSA verifier extends the trusted base; pin its shape.

    Three mechanical properties: (1) every vendored file imports only relative
    paths within scripts/vendor/ — a bare specifier would mean node_modules
    resolution, i.e. an install step, i.e. no longer a self-contained artifact;
    (2) nothing vendored reaches into contextd; (3) the verifier wires nothing
    from the vendored module except `.verify` — the vendored code exposes
    signing and keygen, and a verifier that can produce signatures has a
    strictly larger attack surface than one that cannot.
    """
    vendor = REPO_ROOT / "scripts" / "vendor"
    js_files = sorted(vendor.rglob("*.js"))
    assert len(js_files) >= 9, f"expected the vendored tree, found {js_files}"
    for path in js_files:
        for line in path.read_text().splitlines():
            if not line.startswith("import") or " from '" not in line:
                continue
            module = line.split(" from '")[1].split("'")[0]
            assert module.startswith(("./", "../")), (
                f"{path.name} imports {module!r}; vendored files must resolve "
                f"with no package manager, so only relative imports are allowed"
            )
            assert "contextd" not in module
    assert (vendor / "PROVENANCE.md").exists(), "vendored code with no provenance"

    source = VERIFIER.read_text()
    assert "./vendor/noble-post-quantum/ml-dsa.js" in source
    # Verify-only wiring: the ML-DSA module's sign/keygen surface is never
    # touched. `.verify(` appears; `.sign(` and keygen must not.
    assert re.search(r"\.sign\(", source) is None, (
        "the verifier calls a .sign(); it must be incapable of producing "
        "signatures"
    )
    assert "keygen" not in source.replace("generateKeyPairSync", ""), (
        "the verifier reaches for vendored keygen"
    )


@requires_node
def test_the_verifier_runs_from_outside_the_repository(archive, tmp_path):
    """Executed with a working directory that is not the repo, so no relative
    path into contextd can be helping it."""
    home, _ = archive
    elsewhere = tmp_path / "somewhere-else"
    elsewhere.mkdir()
    code, findings, text = run_verifier(home, cwd=elsewhere)
    assert findings is not None, text
    assert findings["info"]["events"] >= 8
    assert code == 0, text


# --- the mutation battery ---------------------------------------------------
#
# Every mutation is applied with the stdlib `sqlite3` module, never through
# contextd, and each one asserts a SPECIFIC complaint. Asserting only "exit
# code was non-zero" would pass against a verifier that failed for an unrelated
# reason, which is the usual way a mutation test ends up proving nothing.


def _mutated(home: Path, tmp_path: Path, name: str) -> Path:
    return copy_archive(home, tmp_path / name)


def _fail_checks(findings) -> set:
    return {f["check"] for f in findings["fail"]}


@requires_node
def test_mutating_one_row_breaks_the_chain_at_that_row(archive, tmp_path):
    """The base case: corrupt content, leave the hashes alone."""
    home, _ = archive
    target = _mutated(home, tmp_path, "content")
    mutate_event_content(target / "contextd.db", 3, "a substituted claim")

    code, findings, text = run_verifier(target)
    assert code == 1, text
    assert "chain-hash" in _fail_checks(findings), findings["fail"]
    detail = " ".join(f["detail"] for f in findings["fail"])
    assert "event 3" in detail, f"the verifier must name the first bad id: {detail}"


@requires_node
def test_deleting_the_last_event_is_caught_by_the_witness(archive, tmp_path):
    """The chain still verifies after a truncation — every remaining row is
    internally consistent. Section 10 step 3 is what catches it."""
    home, _ = archive
    target = _mutated(home, tmp_path, "truncated")
    delete_last_event(target / "contextd.db")

    code, findings, text = run_verifier(target)
    assert code == 1, text
    fails = _fail_checks(findings)
    assert "witness-tip" in fails, findings["fail"]
    # The chain itself is undisturbed: this is exactly why the witness exists.
    assert "chain-hash" not in fails
    assert "chain-contiguity" not in fails


@requires_node
def test_the_same_uid_attack_survives_the_chain_and_dies_at_the_signature(
    archive, tmp_path,
):
    """The attack docs/SECURITY.md section 3 is about, checked by a program
    that shares no code with the one that made the signature.

    Rewrite a row, recompute every downstream chain hash, rewrite the witness.
    Everything a chain-only parser can check now passes. The service signature
    is the thing the attacker could not produce, and an independent verifier
    reaching that conclusion is worth more than the same claim made by the
    module that signs.
    """
    home, _ = archive
    target = _mutated(home, tmp_path, "same-uid")
    mutate_event_and_repair_chain(
        target / "contextd.db", 3, "the substituted claim")

    code, findings, text = run_verifier(target)
    assert code == 1, text
    fails = _fail_checks(findings)
    # The chain and the witness were repaired, and they verify.
    assert "chain-hash" not in fails, findings["fail"]
    assert "witness-tip" not in fails, findings["fail"]
    # The signature layer is what is left, and it catches it.
    assert fails & {"service-signature", "service-signature-digest"}, findings["fail"]
    detail = " ".join(f["detail"] for f in findings["fail"])
    assert "event 3" in detail


@requires_node
def test_a_corrupted_event_signature_does_not_verify(archive, tmp_path):
    home, _ = archive
    target = _mutated(home, tmp_path, "bad-event-sig")
    flip_signature_byte(target / "contextd.db", "service_signatures", "1=1")

    code, findings, text = run_verifier(target)
    assert code == 1, text
    assert "service-signature" in _fail_checks(findings), findings["fail"]


@requires_node
def test_a_corrupted_tip_signature_does_not_verify(archive, tmp_path):
    home, _ = archive
    target = _mutated(home, tmp_path, "bad-tip-sig")
    flip_signature_byte(target / "contextd.db", "service_tips", "cutover = 0")

    code, findings, text = run_verifier(target)
    assert code == 1, text
    assert "service-tip" in _fail_checks(findings), findings["fail"]


@requires_node
def test_a_corrupted_checkpoint_signature_does_not_verify(archive, tmp_path):
    """Section 5: all signatures present on a checkpoint must verify. A hybrid
    checkpoint whose one half fails is a broken checkpoint, not a good one
    under the other scheme."""
    home, _ = archive
    target = _mutated(home, tmp_path, "bad-checkpoint")
    flip_signature_byte(
        target / "contextd.db", "service_checkpoints", "alg = 'ecdsa-p256-sha256'")

    code, findings, text = run_verifier(target)
    assert code == 1, text
    assert "checkpoint" in _fail_checks(findings), findings["fail"]


@requires_node
def test_repointing_a_checkpoints_algorithm_tag_is_refused_not_retried(
    archive, tmp_path,
):
    """Section 5: "Verification dispatches on the recorded name. A signature
    naming one scheme while its key is registered under another is refused,
    never verified under whichever scheme happened to load."

    A verifier that tried schemes until one worked would pass this mutation,
    and the document's central crypto-agility claim would be unevidenced by any
    implementation but the one that wrote it.
    """
    home, _ = archive
    target = _mutated(home, tmp_path, "relabelled")
    # Only the label moves: the signature bytes remain a valid ECDSA P-256
    # signature over the very payload the row describes.
    relabel_checkpoint_alg(target / "contextd.db", "ml-dsa-65")

    code, findings, text = run_verifier(target)
    assert code == 1, text
    assert "checkpoint" in _fail_checks(findings), findings["fail"]
    detail = " ".join(f["detail"] for f in findings["fail"])
    assert "ml-dsa-65" in detail and "key is ecdsa-p256-sha256" in detail, (
        f"the refusal must name the scheme/key disagreement rather than merely "
        f"failing to parse: {detail}"
    )


@requires_node
def test_editing_what_an_operator_signed_does_not_verify(archive, tmp_path):
    """Change the artifact a `pin.adopt` authorization names, then repair the
    chain. The ledger is internally consistent and the operator signature is
    over different bytes than the row now claims."""
    home, summary = archive
    target = _mutated(home, tmp_path, "forged-attestation")
    mutate_attestation_argument(target / "contextd.db", summary["adopt_event"])

    code, findings, text = run_verifier(target)
    assert code == 1, text
    fails = _fail_checks(findings)
    assert "chain-hash" not in fails, "the chain was repaired; it should verify"
    assert "attestation" in fails, findings["fail"]


@requires_node
def test_corrupting_a_frozen_vector_is_caught(archive, tmp_path):
    """The vectors are the part a second implementation should pass before it
    is trusted against a real archive (section 10's closing paragraph). If the
    vector file can be edited without the verifier noticing, it freezes
    nothing."""
    home, _ = archive
    doctored = tmp_path / "doctored_vectors.json"
    doc = json.loads(VECTORS.read_text())
    doc["vectors"][0]["digest"] = "0" * 64
    doctored.write_text(json.dumps(doc))

    result = subprocess.run(
        [NODE, str(VERIFIER), str(home), "--vectors", str(doctored), "--json"],
        capture_output=True, text=True, timeout=300, cwd=str(tmp_path),
    )
    assert result.returncode == 1
    assert "vector-digest" in result.stdout


@requires_node
def test_dropping_the_append_only_triggers_is_reported(archive, tmp_path):
    """Section 1: "A parser that finds no such trigger is looking at an archive
    whose append-only property was removed ... the DDL guarantee is gone and
    should be reported as such." Every other mutation here starts by dropping
    them, so the report must not be silent about it."""
    home, _ = archive
    target = _mutated(home, tmp_path, "no-triggers")
    # delete_last_event drops both triggers as a side effect of the attack it
    # models; any of the mutators would do.
    delete_last_event(target / "contextd.db")

    _, findings, text = run_verifier(target)
    assert findings is not None, text
    warned = " ".join(w["detail"] for w in findings["warn"])
    assert "events_no_update" in warned or "events_no_delete" in warned, findings["warn"]
    assert "append-only" in warned.lower()


@requires_node
def test_the_unmutated_archive_produces_no_verification_failures(archive):
    """The control. Every mutation above must be the reason its test failed,
    which is only true if the un-mutated archive fails nothing."""
    home, _ = archive
    _, findings, text = run_verifier(home)
    assert findings is not None, text
    assert findings["fail"] == [], findings["fail"]
    assert len(findings["pass"]) >= 14


# --- ML-DSA across runtimes: two tiers, and a verdict that is neither -------
#
# node:crypto verifies ML-DSA only from the OpenSSL 3.5 line (Node >= 24), and
# "independent, if your Node is new enough" is not the independence claim. So
# the verifier carries a vendored pure-JS ML-DSA implementation
# (scripts/vendor/, provenance pinned) as its default, probes node:crypto as
# the fallback, and when it has NEITHER it says so with a distinct verdict and
# a distinct exit code. These tests pin all three rungs — and, mattering most,
# that no rung ever converts "couldn't check" into "checked and passed".

UNVERIFIABLE_EXIT_CODE = 3  # pinned in the verifier header and FORMAT.md §5


def _node_supports_mldsa() -> bool:
    if NODE is None:
        return False
    probe = ("try{require('node:crypto').generateKeyPairSync('ml-dsa-44');"
             "process.exit(0)}catch{process.exit(1)}")
    return subprocess.run(
        [NODE, "-e", probe], capture_output=True, timeout=60,
    ).returncode == 0


def _verifier_with_no_vendor_beside_it(tmp_path: Path) -> Path:
    """A byte-identical copy of the verifier in a directory with no vendor/.

    This is the honest way to model "the vendored files are absent": the
    script resolves scripts/vendor/ relative to itself, so a copy elsewhere
    genuinely cannot find them — no flag, no monkeypatching, the files are
    simply not there.
    """
    lonely = tmp_path / "lonely"
    lonely.mkdir()
    copied = lonely / "verify_format_independent.mjs"
    copied.write_bytes(VERIFIER.read_bytes())
    return copied


@requires_node
def test_ml_dsa_checkpoints_verify_through_the_vendored_implementation(archive):
    """The default path: pure-JS ML-DSA from scripts/vendor/, on any Node.

    The backend attribution matters as much as the pass: on a new Node,
    node:crypto could silently be doing the work and this suite would prove
    nothing about the runtime the independence claim is actually for.
    """
    home, summary = archive
    if not summary["hybrid"]:
        pytest.skip("no ML-DSA checkpoints in this build's fixture")
    code, findings, text = run_verifier(home)
    assert findings is not None, text
    assert findings["info"]["ml_dsa_backend"] == "vendored", (
        f"the vendored implementation must be the default; this run used "
        f"{findings['info']['ml_dsa_backend']}"
    )
    assert "checkpoint" in {p["check"] for p in findings["pass"]}, findings
    assert findings["fail"] == [] and findings["unverifiable"] == []
    assert code == 0, text


@requires_node
def test_a_corrupted_ml_dsa_signature_fails_via_the_vendored_path(
    archive, tmp_path,
):
    """The negative control. A verifier that cannot fail is not a verifier:
    one flipped byte in an ML-DSA checkpoint signature must be a FAIL from the
    vendored implementation, exit 1 — the same complaint the OpenSSL path
    would raise on a newer Node."""
    home, summary = archive
    if not summary["hybrid"]:
        pytest.skip("no ML-DSA checkpoints in this build's fixture")
    target = _mutated(home, tmp_path, "bad-mldsa-checkpoint")
    flip_signature_byte(
        target / "contextd.db", "service_checkpoints", "alg = 'ml-dsa-44'")

    code, findings, text = run_verifier(target)
    assert findings is not None, text
    assert findings["info"]["ml_dsa_backend"] == "vendored"
    assert code == 1, text
    assert "checkpoint" in _fail_checks(findings), findings["fail"]
    detail = " ".join(f["detail"] for f in findings["fail"])
    assert "ml-dsa-44" in detail, detail
    # Not UNVERIFIABLE: the implementation ran and REFUTED the signature.
    assert findings["unverifiable"] == []


@requires_node
def test_without_any_ml_dsa_implementation_the_verdict_is_unverifiable(
    archive, tmp_path,
):
    """Delete the vendored files, deny node:crypto: the degraded verdict.

    Every ML-DSA checkpoint must report a distinct UNVERIFIABLE-ON-THIS-RUNTIME
    line — not PASS, not FAIL — and the process must exit with the pinned
    exit code 3, so a caller checking only the exit status cannot read
    "couldn't check" as "checked and passed". Everything classical still
    verifies: the degradation is exactly as wide as the missing capability.
    """
    home, summary = archive
    if not summary["hybrid"]:
        pytest.skip("no ML-DSA checkpoints in this build's fixture")
    lonely_verifier = _verifier_with_no_vendor_beside_it(tmp_path)

    code, findings, text = run_verifier(
        home, verifier=lonely_verifier, extra=("--no-native-mldsa",))
    assert findings is not None, text
    assert findings["info"]["ml_dsa_backend"] == "unavailable"
    assert code == UNVERIFIABLE_EXIT_CODE, (
        f"'couldn't check' must exit {UNVERIFIABLE_EXIT_CODE}, got {code}:\n{text}"
    )
    assert findings["fail"] == [], "nothing was refuted, so nothing may FAIL"
    assert len(findings["unverifiable"]) >= 1
    for entry in findings["unverifiable"]:
        assert "UNVERIFIABLE-ON-THIS-RUNTIME" in entry["detail"]
    assert "UNVERIFIABLE-ON-THIS-RUNTIME" in text
    # The count is exact: one line per ML-DSA checkpoint row, none swallowed.
    with_db = home / "contextd.db"
    n_mldsa = sqlite3.connect(with_db).execute(
        "SELECT COUNT(*) FROM service_checkpoints WHERE alg LIKE 'ml-dsa-%'"
    ).fetchone()[0]
    assert len(findings["unverifiable"]) == n_mldsa
    # Classical layers were unaffected by the missing capability.
    checks = {p["check"] for p in findings["pass"]}
    assert {"chain-hash", "service-signature", "service-tip", "attestation"} <= checks
    # And no checkpoint pass line was emitted for a partially-checked table.
    assert "checkpoint" not in checks


@requires_node
@pytest.mark.skipif(
    not _node_supports_mldsa(),
    reason="this node:crypto has no ML-DSA, so the native fallback tier "
           "cannot be exercised here — the vendored-path tests above still "
           "pin tampering detection on this runtime",
)
def test_the_native_fallback_is_not_a_bypass(archive, tmp_path):
    """Vendored files absent, node:crypto capable: a tampered ML-DSA
    checkpoint must still FAIL. The capability ladder chooses which
    implementation runs; it must never decide that no implementation needs
    to."""
    home, summary = archive
    if not summary["hybrid"]:
        pytest.skip("no ML-DSA checkpoints in this build's fixture")
    lonely_verifier = _verifier_with_no_vendor_beside_it(tmp_path)
    target = _mutated(home, tmp_path, "bad-mldsa-native")
    flip_signature_byte(
        target / "contextd.db", "service_checkpoints", "alg = 'ml-dsa-44'")

    code, findings, text = run_verifier(target, verifier=lonely_verifier)
    assert findings is not None, text
    assert findings["info"]["ml_dsa_backend"] == "node:crypto"
    assert code == 1, text
    assert "checkpoint" in _fail_checks(findings), findings["fail"]
    assert findings["unverifiable"] == []


# --- the errata note has to exist -------------------------------------------


def test_format_md_keeps_the_errata_after_fixing_what_it_records():
    """The drift is fixed and the record of it survives.

    Deleting the errata along with the bugs would leave the document claiming
    something it cannot support: "this document currently agrees with the code"
    is true, "this document has never disagreed with the code" is not, and a
    reader deciding how much to trust §1 in 2035 needs the second answer too.

    So the errata must still name the omission, the code that contradicted it,
    and the verifier that caught it — and must now also say it is fixed.
    """
    spec = (REPO_ROOT / "docs" / "FORMAT.md").read_text()
    assert "## Errata" in spec, "no errata section in docs/FORMAT.md"
    errata = spec.split("## Errata", 1)[1].split("\n## 1.", 1)[0]
    assert "health" in errata
    assert "schemas.py:566" in errata
    assert "verify_format_independent" in errata
    assert "FIXED" in errata, "the errata must record that the drift was closed"
    assert "E1" in errata and "E2" in errata
    # The fixes themselves have to be in the body, not only claimed here.
    body = spec.split("\n## 1. The `events` table", 1)[1]
    assert "`health`" in body.split("## 2.")[0], "§1 still omits health"
