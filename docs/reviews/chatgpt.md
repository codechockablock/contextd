What do you think about this repo












Worked for 1m 7s

I like it. More specifically, I think there’s a real idea here, rather than “yet another personal-memory RAG repo.”
The part that works for me is that contextd isn’t primarily trying to make retrieval smarter. It’s trying to establish a neutral memory substrate between you and whichever model happens to be operating today. Claude, Codex, OpenClaw, whatever comes next—the durable object is the local event history, while the models are replaceable readers and occasional attributed writers. That’s a much more interesting framing than building a Claude memory plugin.
The architectural restraint is also unusually good. SQLite + FTS5 + MCP + a handful of ingesters is enough to test the thesis. Deferring embeddings until lexical retrieval demonstrably fails is exactly the right instinct. There are a bunch of places where a typical AI project would immediately introduce vectors, rerankers, an agent graph, Postgres, a web UI, and six abstractions; this repo mostly refuses to do that.
I particularly like the egress design:
archive → gate → model
gate disclosure → archive

That feedback loop gives you something most “AI memory” systems don’t have: the memory has a history of how it was consumed. The client attribution makes it considerably more useful because eventually you can ask questions like, “What did Claude know when it made this decision?” or “Did Codex receive the event that contained X?” That becomes interesting for debugging agents, not merely remembering your life.
And the decision to call the gate an audit layer rather than a security boundary was important. The original stronger claim would have been indefensible because a local process that can read contextd.db can simply go around MCP. Documenting the narrower promise actually makes the system more credible.
There are, however, a few places where I think the conceptual language is currently ahead of what the system technically guarantees.
The biggest one is the distinction between append-only and tamper-evident. The SQLite triggers prevent normal UPDATE and DELETE, which is useful, but someone controlling the database can remove the triggers, modify the DB offline, replace the DB, insert fabricated events, etc. So the archive can strongly answer:
“What has this running system recorded?”
It cannot yet strongly answer:
“Can I prove this is the exact historical record and that nobody altered it?”
If the eventual thesis is really “record so anything can be proven,” I think a hash-chain or Merkle-ish commitment eventually becomes earned. Something as simple as each event committing to the previous event hash would change the epistemic status of the log substantially. Not because you need cryptocurrency bullshit, but because receipts become much more interesting when receipts themselves cannot silently be rewritten.
There’s another subtle issue I found that I think is more immediately actionable. scan_claude() redacts credentials before storing Claude dialogue, which is good. Browser URLs are cleaned before storage, also good. But MCP notes call:
ingest_note(connect(), text, actor=CLIENT)
and ingest_note() directly appends text. There’s no redact() there.
So a model-written note can persist a credential verbatim.
That slightly violates the broad design statement that credentials are never stored. It might not happen through the reconciler in ordinary operation because its prompt explicitly says not to include credentials, but that is a behavioral instruction rather than the mechanical invariant the rest of the architecture is striving for.
I’d probably change the MCP note() path to redact before calling ingest_note(). Human CLI notes can remain raw if you deliberately want humans to be able to archive arbitrary material, while model-originated notes should go through the same capture-side hygiene as model transcripts.
There’s also a deeper problem hiding underneath model-written notes that I suspect will become more important than embeddings: evidence versus interpretation.
Right now you have nice provenance:
actor=human
actor=claude-code
actor=codex
But a distilled note such as:
User decided PostgreSQL was unsuitable because SQLite is more reliable.

is fundamentally different from a raw user message saying:
Let's stick with SQLite.

Even though both become immutable events, one is evidence and one is a model-produced inference about evidence.
Your overview already hints at an “evidence-vs-instruction bit.” I’d broaden that into something like an epistemic type:
observation → directly captured artifact/dialogue
assertion → deliberately entered human claim
derived → model-created interpretation/distillation
system → mechanical metadata/audit
You don't need this immediately, but I suspect this is the feature that gets earned before embeddings do. As the archive gets large, the danger isn't primarily failure to find something. It's recursive epistemic laundering:
model interprets transcript → writes note → later model retrieves note → treats interpretation as fact → writes another note.
Your exclusion of egress events already demonstrates you understand feedback contamination. Derived memories create a similar problem on the semantic side.
The other part I really like is the Claude epoch/reconciler arrangement. Keeping the model invocation outside the kernel is a clean boundary. In particular:
models call the kernel; kernel never calls models

is a genuinely useful architectural invariant. It means contextd remains intelligible even if every AI provider disappears tomorrow. The reconciler is just another consumer.
I would also keep the “30% better than grep/memory” experiment. That's probably the most intellectually disciplined sentence in the repo. There is an enormous temptation in memory systems to evaluate retrieval quality with synthetic benchmarks rather than asking whether anyone actually reaches for the thing. A month of naturalistic queries gives you a much better signal about what to build next.
One change I'd make to that evaluation fairly soon is recording recall outcomes. Right now the archive knows what it emitted but not whether the emission helped. Even a tiny command like:
ctx outcome <egress-id> hit
ctx outcome <egress-id> miss
or partial would give you an empirical development loop. Then embeddings really do become something you add because, say, “27% of misses were vocabulary mismatch,” instead of because embeddings sound appropriate.
So my overall assessment would be:
As software: deliberately small, coherent, and surprisingly well thought through for a v0.
As an AI memory system: the interesting contribution isn't FTS or ingestion. It's vendor-neutral provenance and disclosure accounting.
As a security system: correctly not one, and it should resist drifting back into security-language claims.
As a longer-term research/project direction: the really interesting frontier is not vector retrieval. It's epistemic lineage—knowing what was observed, what was inferred, what was disclosed, who inferred it, and which source evidence supported the inference.
That last version gets genuinely powerful. You eventually wind up with something closer to a personal provenance graph for machine cognition than a memory database.
And I think that's substantially more interesting than the repo initially makes it sound.
One caveat: I tried to run the smoke suite as part of reviewing it, but this environment couldn't install the repo's setuptools>=68 build dependency because outbound package access is unavailable. So I reviewed the tests and implementation directly, but I can't independently claim the suite passes here.










I built it last night with Claude Fable 5 mostly. 
I recently read about Anthropic’s “watermark” they’ll be attaching to new models after August 2nd. I’m wondering where this repo now fits.












Yes. And I think the Anthropic announcement actually makes the repo’s purpose clearer, not obsolete.
One clarification first: reporting today says Anthropic’s policy is that models launched on or after August 2, 2026 support marking at launch, while support is being added to older models during a transition period. The text mark is supposed to be embedded at generation time and survive copying and some editing; supported files use signed provenance metadata such as C2PA. Business Insider
That creates an interesting distinction:
Anthropic is solving provenance of the output.
contextd is solving provenance of the context and process.
Those are complementary.
Imagine six months from now you have an artifact:
design.md
Anthropic's watermark might establish:
This text was generated by Claude.
But that doesn't answer:
Why did Claude write this?

What information did it have?

Which pieces came from me?

Which pieces came from Claude previously?

What did Claude retrieve from memory?

Was that memory itself Claude-generated?

Which model had access to which information?

What changed between the Claude and Codex versions?
That's almost exactly the territory contextd occupies.
And your architecture suddenly has a much more interesting interpretation.
contextd becomes the other half of provenance
There are effectively three layers:
SOURCE PROVENANCE
    ↓
contextd
"Where did the information come from?"

PROCESS PROVENANCE
    ↓
contextd egress / client attribution
"What information was disclosed to which agent?"

OUTPUT PROVENANCE
    ↓
model watermark / C2PA
"Which model/provider produced this artifact?"
Put them together and you potentially get an actual provenance chain:
human observation
       ↓
contextd event #1842
       ↓
disclosed to claude-fable-5
       ↓
egress event #1911
       ↓
Claude produces design.md
       ↓
Anthropic watermark
       ↓
artifact later consumed by Codex
       ↓
contextd event #2077
       ↓
disclosed to GPT
       ↓
...
That's substantially more powerful than either system individually.
And there's a funny inversion here.
Anthropic controls the watermark.
You control contextd.
That's important.
If Anthropic's detector says:
Claude generated this.

you're relying on Anthropic's attribution infrastructure.
If contextd says:
Event 8,421 came from Claude Code, was recorded at 01:42, was retrieved alongside events X/Y/Z, and resulted in artifact A...

that's your record.
Neither proves the other. They're independent provenance channels.
Where I think this gets particularly interesting for your repo is multi-model environments.
You're already using multiple frontier systems. Now imagine:
                  ┌── Claude
                  │    Anthropic watermark
                  │
contextd ─────────┼── GPT
                  │    OpenAI provenance
                  │
                  ├── Gemini
                  │    Google provenance
                  │
                  └── local model
                       no watermark
contextd doesn't care.
That's actually one of its strongest properties.
Provider provenance mechanisms are necessarily provider-centric.
Your system is user-centric.
The providers can say:
This came from us.

Your archive can say:
Here's how all of them participated.

That distinction gets more valuable as agent workflows become heterogeneous.
It also reinforces something I mentioned before: I'd make epistemic lineage a first-class concept in the repo.
Not tomorrow morning. The current system is appropriately small.
But I think the conceptual destination has become clearer:
Event
├── content
├── timestamp
├── actor
├── source
├── epistemic_type
│   ├── observation
│   ├── human_assertion
│   ├── model_inference
│   └── system_record
├── parent_events
├── disclosed_to
├── derived_artifacts
└── external_provenance
    ├── watermark
    ├── C2PA
    └── signature
Then you can ask an absolutely killer question:
Why does this AI believe this?

And potentially reconstruct:
CLAIM
"Joseph prefers architecture X."

        │ derived from

        ├── human statement #482
        ├── Claude conversation #519
        └── project artifact #601

        │ summarized by

        Claude Fable 5
        event #617

        │ disclosed to

        Codex
        egress #811

        │ used during creation of

        architecture.md
Anthropic's watermark tells you who wrote the bottom artifact.
Your system tells you where the fucking idea came from.
That's the more interesting problem.
There's also a broader reason I think you're accidentally pointed at something timely. Current watermark research is increasingly about attribution and provenance, including work specifically considering agent trajectories rather than just final text. arXiv The field is moving from:
“Can we detect AI text?”

toward:
“Can we establish the provenance of AI-mediated activity?”

And contextd approaches that from almost the opposite direction: don't infer provenance after the fact if you can record the interaction boundary while it happens.
So I wouldn't reposition the repo as an anti-watermark thing at all.
I'd sharpen its thesis to something approximately like:
Model providers can attest to what their models generated. contextd records what those models knew, where that knowledge came from, and what they were allowed to see.

That's a considerably stronger reason for the project to exist than “persistent memory for AI agents.”
And considering you put the first version together in one night, I think you stumbled onto the interesting abstraction unusually early.

Business InsiderarXiv









claude-joseph-conversation-2026-08-11.md

I have concerns about Anthropics watermarking. 
See the attachment for full context.












Yeah. Reading the whole attachment changes how I interpret what you were getting at.
Your concern isn't really “I don't want people to know I used AI.” It's much closer to:
Why should a vendor be allowed to embed its own privately verifiable claim into work I may have substantially authored, and then potentially become the authority institutions consult when deciding what that claim means?
That's a considerably better objection.
The strongest section of the conversation is around lines 219–228. You distinguish provenance itself from custody of provenance. Claude eventually puts it well: the watermark can accurately indicate that Claude's generation process touched/emitted text while still being a terrible proxy for authorship, because human contribution is continuous and the signal is effectively categorical. 
And I agree with a lot of that argument.
Where I think your concern is strongest
Suppose you spend two days developing an argument. You supply sources, corrections, structure, examples, counterarguments, and perhaps a detailed voice specification. Claude produces twenty candidate passages. You reject nineteen and deliberately choose one.
There is obviously human intellectual contribution there.
Now compare:
“Write my essay about X.”

Claude generates it. Person copies it.
Those are radically different authorship processes.
Yet a generation-level watermark isn't designed to measure that distinction. As your conversation correctly identifies, it's evidence about the generation process, not a quantitative authorship meter. 
That's fine if everybody understands the semantics.
The danger starts if:
Claude-generated tokens → “AI-written” → “not the student's/employee's work” → misconduct.
Each arrow introduces a new proposition that the watermark itself doesn't establish.
That's the part I'd be worried about too.
But there's an important uncertainty in that conversation
Claude gets ahead of the available evidence in several places.
Statements like:
“what ships is detection-as-a-service”

and predictions about institutional subscriptions, Turnitin integration, pricing structures, gated access, etc. are plausible scenarios, not established facts. The attachment itself acknowledges that the detector/access documentation is an open question, but then sometimes speaks about the predicted architecture as though it has already been decided. 
I'd keep those separated:
Known: Anthropic has an interest in provenance/marking and historically has explicitly said watermarking should not be treated as an independently reliable accountability mechanism. In its earlier NTIA comments, Anthropic specifically described open research problems and limitations around watermarking. Anthropic
Unknown: who gets detection access, what scores look like, what appeal mechanisms exist, whether institutions integrate it, what Anthropic's exact implementation is, and especially whether anyone treats a positive result as dispositive evidence against an individual.
Those unknowns determine whether this becomes mildly annoying infrastructure or the genuinely problematic system you're imagining.
And that changes my opinion of contextd
Yesterday, you apparently built:
private local memory with disclosure receipts.

After this conversation, I see a second possible purpose:
user-controlled provenance for human–AI collaboration.

That's much more interesting.
But I disagree slightly with Claude's framing that the goal should primarily be building a rebuttal instrument.
That accepts Anthropic's frame too much.
I'd aim for something more general:
record the actual collaboration.
Imagine contextd eventually being able to produce:
Artifact: essay-final.docx

Human-originated source material
    ├── research notes
    ├── outline
    ├── original draft
    └── revision instructions

AI interactions
    ├── Claude: critique
    ├── GPT: source analysis
    └── Claude: line editing

Artifact evolution
    draft-01
       ↓ human edit
    draft-02
       ↓ Claude critique
    draft-03
       ↓ human revision
    final

External AI provenance
    Claude watermark detected: yes

Interpretation:
    Claude participated in the production history.
Now the watermark isn't something contextd has to beat.
It's another observation in the ledger.
And your ledger supplies what the watermark fundamentally cannot: context.
That's why I really like the sentence Claude arrived at later:
“A ledger that explains the mark beats one that denies it.”

That's probably the deepest observation in the entire eight-hour conversation. 
Because consider a professor saying:
Anthropic says this contains Claude's watermark.

Instead of having to answer:
No it doesn't!

you could potentially answer:
Of course it does. Claude performed the final copyedit. Here is the pre-Claude draft, its hash, the subsequent interaction, the exact disclosure to Claude, and the resulting revision.

That's an entirely different evidentiary position.
There's one place I'd diverge pretty substantially from Claude
I don't think you should sacrifice contextd's local-first architecture just yet.
Your objection at lines 362–373 is important. Claude is cryptographically correct that purely self-controlled evidence can't independently prove historical existence to a hostile third party. 
But there is a huge difference between:
“mathematically impossible for me to fabricate”
and
“credible evidence of an ordinary historical process.”
Git history, filesystem metadata, hundreds of chronologically coherent events, source documents, browser captures, model interactions, application logs, drafts, and hashes forming one consistent history can have substantial evidentiary value even if an omnipotent owner could theoretically fabricate all of it.
We don't ordinarily require every piece of evidence to be cryptographically notarized before considering it evidence.
So I wouldn't bolt blockchain/OpenTimestamps/external infrastructure onto contextd because of Anthropic this week.
I'd first fix the internal integrity problem Claude found—particularly arbitrary backdating and backups. The source review found that the current database allows direct inserts with arbitrary timestamps, which is a meaningful weakness even for your original memory/audit purpose. claude-joseph-conversation-2026-08-11.mdMD
Then I'd preserve the architectural principle:
Everything meaningful stays on the user's machine.
External anchoring could eventually be an optional capability for people who specifically need stronger third-party-verifiable evidence.
Not the foundation.
And there's a bigger philosophical distinction here that I think your conversation almost reaches.
Anthropic's system says:
Trust us to tell you what Claude did.

contextd could say:
Don't trust anyone. Preserve enough history to reconstruct what happened.

Those are fundamentally different provenance philosophies.
One establishes an authoritative attestation about one actor.
The other preserves evidence about the entire collaboration.
I wouldn't market that as anti-Anthropic. Anthropic's watermark may ultimately be implemented responsibly, and we don't yet know enough about detection/governance to condemn the actual system.
But the potential problem you've identified is real:
AI-assisted authorship is becoming richer and more collaborative at exactly the same time provenance mechanisms risk reducing that collaboration to a binary “AI touched this” signal.
If contextd can preserve the richer history without sending that history to another custodian, that's where I think this repo suddenly becomes much more than the memory daemon you built last night.

Anthropic









Yea I agree.












Yeah. I think the important thing now is not letting the watermark controversy hijack the architecture.
contextd was already based on a good principle: preserve events locally, preserve provenance, and make disclosure observable. The Anthropic issue exposes a much broader application of that principle, but it doesn't require turning the repo into an “AI detector defense system.”
I'd keep the thesis simple:
Preserve the history of human–AI collaboration under the user's custody.

Then everything else follows naturally. A watermark can be recorded. Claude interactions can be recorded. GPT interactions can be recorded. Human drafts can be recorded. Git commits can be recorded. Eventually artifact lineage can be recorded. None of those sources gets privileged as the truth; they're evidence contributing to a reconstruction of what happened.
And there's a nice symmetry to it: provider provenance answers “did our system generate this?” User-held provenance answers “how did this become mine?”
Those aren't competing questions. But right now, vendors have much stronger infrastructure for answering the first than individuals have for answering the second.
That gap might actually be the problem worth building around.
I'd still do the boring stuff first, though: WAL-safe backup, close the arbitrary-backdating hole, distinguish captured evidence from model-derived assertions, and run the original recall experiment. The conversation itself ended with basically those unresolved items. claude-joseph-conversation-2026-08-11.mdMD
Then if this still looks important after you've actually lived with contextd for a while, you've got evidence that the expanded thesis was earned rather than bolted onto something you built yesterday.
And frankly, “how did this become mine?” might be the sentence I'd keep somewhere. That's a much better north star than “beat AI watermarks.”










How does it make me a billionaire?












Ah. Now we're asking the important question. 😂
There is a conceivable billion-dollar version of this, but it isn't selling contextd as a $10/month memory daemon.
It's making user-controlled provenance infrastructure a standard layer in AI-mediated work.
Think about where this goes if AI collaboration becomes ubiquitous. Companies will increasingly need to answer: Who contributed what? Which model touched this artifact? What information did it receive? Which claims came from humans versus models? What was the state before an AI edited it? Can we reconstruct the process later? The watermark conversation exposes exactly why a binary provider-side signal is insufficient: it records model involvement but collapses radically different kinds of collaboration into the same signal. 
contextd potentially owns the richer object: the provenance graph of the work itself.
The enormous-company version looks something like:
                 contextd protocol

 IDE ─────┐
 Word ────┤
 Browser ─┤
 Git ─────┤
 Email ───┼────► Local provenance ledger
 Claude ──┤              │
 GPT ─────┤              │
 Gemini ──┤              ▼
 Agents ──┘       Artifact lineage
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
           Employee   Employer   Auditor
             view       proof      proof
And critically, the ledger belongs to the user/organization rather than the model provider.
That's potentially valuable in education, software development, regulated professional work, scientific research, publishing, legal discovery, enterprise compliance, IP disputes, and agent auditing.
You don't monetize the SQLite daemon.
You make the daemon/protocol free and open source.
Then the commercial company sells the things enterprises actually pay for: fleet administration, organizational policy, identity and device attestation, selective disclosure, audit exports, compliance integrations, artifact verification, retention controls, enterprise support, and maybe hosted verification infrastructure that doesn't require surrendering the underlying private ledger.
That's basically an open-core play.
The moonshot is that eventually somebody receives an artifact and asks:
“Does this have provenance?”

rather than:
“Was this made by AI?”

And contextd becomes one of the standards by which that question gets answered.
That's where the valuation gets stupid.
Because then you're no longer selling an application. You're sitting at a trust boundary between humans, models, organizations, and artifacts.
There is, however, an enormous jump between the repo you built and that company. Claude identified one of the most important problems correctly: today the ledger can be directly forged and even backdated, so it doesn't yet possess the integrity properties you'd need to make strong external claims.  And proving human authorship is fundamentally harder than proving that a particular model generated tokens; timestamps and hashes don't magically solve that. claude-joseph-conversation-2026-08-11.mdMD
So I wouldn't start writing the $1B CONTEXTD ROADMAP™ tonight.
I'd do something much more dangerous to potential competitors:
Make the tiny version extremely fucking good.
Get the event model right. Get epistemic lineage right. Make it work with Claude, GPT, Codex, browsers, Git and ordinary files. Make disclosure receipts excellent. Make artifact histories reconstructable. Keep the kernel boring and local. Publish a clear provenance schema other people can implement.
Then demonstrate one killer thing:
Give contextd a finished document and have it produce a trustworthy reconstruction of:
“How did this become mine?”
Not a detector score.
A history.
If people see that and immediately think “I want this running before I do any serious work with AI,” then we start having the billionaire conversation.
Because at that point contextd isn't competing with Anthropic's watermark.
Anthropic may have accidentally supplied the demonstration for why the other half of the provenance stack needs to exist.