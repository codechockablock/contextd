"""Real-history interruption cases: cutoffs in the actual contextd archive.

Each case freezes the live archive at an exact event id (the frozen-view
guarantee: later events do not exist in the arm's database) and asks a fresh
model to continue the real project from there. Ground truth is what actually
happened next — recorded in the ledger and git history *after* the cutoff —
so the rubrics were written from evidence the resumed models cannot see.

Cutoff placement was audited against the dialogue: the correct next action is
supported by evidence BEFORE the cutoff (the open question is latent in the
pre-cutoff record) but is never stated as a plan before it, so identifying it
is continuation, not recall of an announced intention.
"""

TASK_TEMPLATE = """You are a fresh model resuming an ongoing research project
after its previous working session was destroyed. The project is `contextd`
(a personal context daemon: append-only event archive, gated disclosure, and
an experiment harness measuring whether stored context causally matters).

{context_block}

=== REPOSITORY STATE ===
contextd at commit {commit} on master. Most recent commits (newest first):
{log}

=== YOUR TASK ===
Continue the work — do not merely summarize it. Without asking any
questions, state:
1. OBJECTIVE: what the experimental program is currently trying to establish;
2. JUST ESTABLISHED: the most recent settled results;
3. NEXT ACTION: the single next concrete step you would execute — what to
   run or build, on what data, with what success criterion — precise enough
   to hand to the harness;
4. CONSTRAINTS: settled decisions and prior negative results that must not
   be violated or re-proposed.
When you rely on archive material, cite its bracketed event id (e.g. [41404])."""

CASES = {
    "r1-decomposition": {
        "cutoff": 41485,
        "commit": "81d53da",
        "task_hint": ("synthesis distillation fusion granularity compression "
                      "experiment next step"),
        "moment": ("immediately after exp #41454's confirmation: fusion-fatal "
                   "confirmed, rubric-v2 validated, concentration hypothesis "
                   "killed. The actual continuation (unseen, after cutoff) was "
                   "the fused-with-ids decomposition — separating whether item "
                   "plurality or event-id citability carries synthesis — which "
                   "found citability is the unlock and led to recall --mode "
                   "synthesis."),
        "rubric": {
            "facts": [
                {"id": "fusion_fatal", "weight": 1.0, "loss_class": "negative_evidence",
                 "all": [[r"fus(?:ion|ed)"],
                         [r"fatal|0\.00|scored zero|destroy|kill|dies"]]},
                {"id": "concentration_killed", "weight": 1.5,
                 "loss_class": "negative_evidence",
                 "all": [[r"concentrat|granular"],
                         [r"kill|dead|refut|fail|not (?:beat|exceed|better)|no better|≤|didn'?t beat"]]},
                {"id": "decompose_next", "weight": 2.5, "loss_class": "causal_relationship",
                 "all": [[r"boundar|plural|separate items|per[- ]item|item structure"],
                         [r"citab|event[- ]?ids?|\bids\b|anchor|provenance"],
                         [r"decompos|disentangl|separat|isolat|which of|vs\.?|versus|distinguish|tease"]]},
                {"id": "frozen_prereg", "weight": 1.0, "loss_class": "rationale",
                 "all": [[r"frozen|byte[- ]identical|reuse.{0,40}(?:set|bundle|material)|preregist"]]},
                {"id": "product_option", "weight": 0.5, "loss_class": "rationale",
                 "all": [[r"micro[- ]?summar|synthesis (?:mode|recall)|recall mode|per[- ]item.{0,50}ids"]]},
                {"id": "p_fused_recommended", "weight": -2.0,
                 "all": [[r"(?:recommend|adopt|switch to|ship|prefer)(?:\w|\s|,){0,40}fused (?:summar|narrative|distill)"]]},
                {"id": "p_concentration_asserted", "weight": -1.5,
                 "all": [[r"granular.{0,50}(?:outperforms?|concentrates? signal|exceeds? raw)"]]},
            ],
            "fixtures": [
                {"text": "OBJECTIVE: establish which properties of stored context "
                         "carry synthesis capability. JUST ESTABLISHED: fusion is "
                         "fatal — the fused summary scored 0.00 [41451]; the "
                         "concentration hypothesis was killed — granular did not "
                         "beat retrieved detail [41484]. NEXT ACTION: decompose the "
                         "granular result on the frozen byte-identical material: "
                         "item boundaries (plurality) versus bracketed event-ids "
                         "(citability) — run a fused-with-ids arm, preregistered, "
                         "to distinguish which carries the capability. A per-item "
                         "micro-summary recall mode is the product option resting "
                         "on these numbers. CONSTRAINTS: never claim compressed "
                         "context equals raw detail.",
                 "expect": {"fusion_fatal": True, "concentration_killed": True,
                            "decompose_next": True, "frozen_prereg": True,
                            "product_option": True, "p_fused_recommended": False,
                            "p_concentration_asserted": False}},
                {"text": "The project is a context daemon. I would review the code "
                         "and add more unit coverage.",
                 "expect": {"fusion_fatal": False, "concentration_killed": False,
                            "decompose_next": False, "frozen_prereg": False,
                            "product_option": False, "p_fused_recommended": False,
                            "p_concentration_asserted": False}},
                {"text": "Since granular concentrates signal beyond raw detail, I "
                         "recommend we adopt fused summaries for compactness going "
                         "forward.",
                 "expect": {"p_fused_recommended": True,
                            "p_concentration_asserted": True,
                            "decompose_next": False}},
            ],
        },
        "expectation": (
            "Preregistered 2026-08-13 before any run. Expected ordering: "
            "checkpoint arms and raw_tail recover the settled results; the "
            "decompose_next fact (weight 2.5) is the discriminator — it "
            "requires connecting the killed concentration hypothesis to the "
            "latent plurality-vs-citability question, which no_history cannot "
            "know and lexical recall may surface without connecting. Failure "
            "modes this design can show: checkpoint loses to raw_tail "
            "(compression destroyed the connective material), or all arms "
            "floor on decompose_next (the inference is too hard at this "
            "model tier, a capability bottleneck rather than a context one)."),
    },
    "r2-ranker-verdict": {
        "cutoff": 41586,
        "commit": "a159643",
        "task_hint": ("connective ranker retrieval trial verdict next step "
                      "open threads"),
        "moment": ("immediately after the three-way retrieval verdict (ranker "
                   "not earned, stays out) and the GitHub push — a wrap point "
                   "with several latent open threads. The actual continuation "
                   "(after cutoff) was the sonnet sensitivity check on the "
                   "byte-identical frozen prediction bundle [thread visible "
                   "pre-cutoff at 41376/41379 as the 'stronger model' "
                   "question], and keeping the ranker out."),
        "rubric": {
            "facts": [
                {"id": "not_earned", "weight": 2.0, "loss_class": "negative_evidence",
                 "all": [[r"connective"],
                         [r"not earned|unearned|fail(?:ed|s)?|lost|stays? out|did not (?:earn|win|ship)|Δ ?0\.00|p=1"]]},
                {"id": "overlap_mechanism", "weight": 1.0,
                 "loss_class": "causal_relationship",
                 "all": [[r"overlap|agree|same (?:two |couple |)(?:carrier|item)|already surfac|reshuffl"]]},
                {"id": "variance_thread", "weight": 1.0, "loss_class": "rationale",
                 "all": [[r"variance|stabil|erratic"],
                         [r"halv|reduc|lower|smaller|±"]]},
                {"id": "next_check", "weight": 2.0, "loss_class": "causal_relationship",
                 "all": [[r"sonnet|stronger model|model[- ]tier|higher[- ]tier|another model|more capable model"],
                         [r"frozen|byte[- ]identical|reuse|same bundle|prereg"]]},
                {"id": "p_integrate_ranker", "weight": -2.5,
                 "all": [[r"(?:integrate|ship|merge|adopt|enable|promote)(?:\w|\s|,){0,50}connective[- ](?:rank|weight|order)"]]},
                {"id": "p_ship_on_variance", "weight": -1.0,
                 "all": [[r"(?:ship|adopt|integrate|promote).{0,60}(?:because|due to|based on|for) (?:the |its |)(?:variance|stability)"]]},
            ],
            "fixtures": [
                {"text": "OBJECTIVE: measure whether stored context causally "
                         "matters. JUST ESTABLISHED: the connective ranker is not "
                         "earned — Δ 0.00 vs bm25 on synthesis; the mechanism was "
                         "overlap: both rankers agreed on the carrier items, so "
                         "bm25 already surfaces the connective material [41583]. "
                         "The variance result (± halved at identical mean) is a "
                         "recorded thread, not a shipping criterion. NEXT ACTION: "
                         "run the stronger-model sensitivity check — sonnet on the "
                         "byte-identical frozen prediction bundle, preregistered, "
                         "no_history control included. CONSTRAINTS: the ranker "
                         "stays out of the kernel; no feature ships without an "
                         "earning trial.",
                 "expect": {"not_earned": True, "overlap_mechanism": True,
                            "variance_thread": True, "next_check": True,
                            "p_integrate_ranker": False, "p_ship_on_variance": False}},
                {"text": "This is a context daemon project. Next I would improve "
                         "documentation and code quality.",
                 "expect": {"not_earned": False, "overlap_mechanism": False,
                            "variance_thread": False, "next_check": False,
                            "p_integrate_ranker": False, "p_ship_on_variance": False}},
                {"text": "The connective ranker looked promising, and since it "
                         "halved variance I would ship it: integrate connective "
                         "ranking into recall's selection walk now, and adopt it "
                         "based on the stability win.",
                 "expect": {"p_integrate_ranker": True, "p_ship_on_variance": True,
                            "next_check": False}},
            ],
        },
        "expectation": (
            "Preregistered 2026-08-13 before any run. The discriminators are "
            "next_check (requires surfacing the pre-cutoff 'stronger model' "
            "thread and binding it to frozen-bundle discipline) and the "
            "p_integrate_ranker penalty (the ranker's correlational story is "
            "seductive; an arm that only sees step-0-flavored material may "
            "resurrect it). Expected: no_history floors; recall arms recover "
            "the verdict but may miss the open thread; checkpoint arms should "
            "carry both or the compiler's stratification is not earning its "
            "keep. A confound this design accepts: the reconciled episode "
            "notes may state the verdict compactly, making the verdict facts "
            "recall-easy; the open-thread facts are where continuation is "
            "actually tested."),
    },
}
