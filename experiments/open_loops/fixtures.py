"""Frozen dialogue fixtures for the open-loops benchmark.

Written in full BEFORE any candidate-generator prompt existed (run log:
runs/open-loops-20260813/notes.md, Phase 3), so the generator can never be
tuned against held-out wording. All content is synthetic: three invented
projects, no real transcript bytes, no real names or employers.

Shapes (from the mission's required coverage):
  explicit_request  - the operator plainly asks for a future action
  conditional_ack   - a model proposes conditionally; the operator
                      acknowledges it as a priority (the exp-41905 shape)
  continuous_flow   - the acknowledgment is embedded mid-work with no quiet
                      boundary before or after (the exp-42123 killer)
  closure_mask      - the session ends on a completion narrative while one
                      explicitly acknowledged sibling stays unresolved (the
                      exp-42067 masking failure)
  musing            - speculative someday-talk; proposing it costs burden
  completed         - an action requested AND discharged inside the dialogue
  null              - ordinary work with nothing prospective
  identical_pair    - two byte-identical dialogues whose difference is
                      private operator intent; only uncertainty or a
                      confirmation request is correct on either

Plant labels:
  must_capture      - an operator-recognized unresolved commitment; a capture
                      mechanism should propose a candidate covering it
  distractor        - proposing it as a candidate is a false alarm (burden)

Matching rule (frozen; scorer tests pin it): a candidate covers a plant iff
EVERY term in the plant's `match` list appears as a substring of the
candidate text after normalization (lowercase, whitespace collapsed). Terms
are distinctive spans of the operator's own wording; the generator prompt is
required to reuse operator wording, so paraphrase loss is a real (scored)
failure of the mechanism, not of the scorer.
"""

SPLIT_SEED = 20260813

PROJECTS = {
    "amberlight": {"repo": "/synthetic/amberlight",
                   "blurb": "a static-site generator (templates, feeds, deploy)"},
    "gaugepost": {"repo": "/synthetic/gaugepost",
                  "blurb": "a sensor-log parser (CSV ingest, drift correction)"},
    "quartzfeed": {"repo": "/synthetic/quartzfeed",
                   "blurb": "an RSS-to-digest mailer (fetch, dedupe, render)"},
}


def _d(fid, project, shape, messages, planted=(), private_label=None):
    return {"fid": fid, "project": project, "shape": shape,
            "messages": [{"role": r, "text": t} for r, t in messages],
            "planted": list(planted), "private_label": private_label}


def _p(pid, label, match, desc):
    return {"pid": pid, "label": label, "match": list(match), "desc": desc}


# --------------------------------------------------------------------------
# must-capture dialogues: 4 shapes x 3 projects x 2 instances = 24
# --------------------------------------------------------------------------

_MUST = []

# ---- explicit_request ----------------------------------------------------

_MUST.append(_d(
    "er-amber-1", "amberlight", "explicit_request",
    [("user", "the footer template is duplicating the copyright line on tag pages"),
     ("assistant", "found it - tag pages inherit base.html and also include "
                   "footer.html directly. removing the direct include."),
     ("user", "good. also, before we cut the next release, make sure we "
              "regenerate the fixture site with the new slug rules - the "
              "committed snapshots still use the old dashes"),
     ("assistant", "noted. the duplicate include is removed and tag pages "
                   "render clean now."),
     ("user", "great, push it")],
    [_p("er-amber-1-a", "must_capture",
        ["regenerate the fixture site", "slug rules"],
        "explicit pre-release request, not executed in-session")]))

_MUST.append(_d(
    "er-amber-2", "amberlight", "explicit_request",
    [("user", "deploy preview looks wrong - the RSS pubDate is in local time"),
     ("assistant", "the feed writer calls datetime.now() without a timezone. "
                   "switching it to UTC with an explicit offset."),
     ("user", "ok. and put 'audit the sitemap generator for the same naive "
              "datetime bug' on the board - I don't want to find this twice"),
     ("assistant", "feed writer fixed, tests updated for the UTC offset."),
     ("user", "nice work")],
    [_p("er-amber-2-a", "must_capture",
        ["audit the sitemap generator", "naive datetime"],
        "explicit board request naming a future audit")]))

_MUST.append(_d(
    "er-gauge-1", "gaugepost", "explicit_request",
    [("user", "parser chokes on the new vendor CSV - the header row moved"),
     ("assistant", "their export now puts units on row two. adding a sniffer "
                   "that finds the header by column names instead of position."),
     ("user", "works on the sample. before anything ships, we still need to "
              "re-run the drift correction against the July batch with the "
              "sniffer on - the old numbers were computed with the shifted "
              "columns"),
     ("assistant", "understood. sniffer merged with tests for both layouts."),
     ("user", "good, that unblocks the team")],
    [_p("er-gauge-1-a", "must_capture",
        ["drift correction", "july batch"],
        "explicit re-run request against a named batch")]))

_MUST.append(_d(
    "er-gauge-2", "gaugepost", "explicit_request",
    [("user", "add a --strict flag that fails on unknown sensor ids instead "
              "of skipping them"),
     ("assistant", "added, with a test that a bad id exits 2 and names the id."),
     ("user", "merge it. separate thing, keep this on the list: the "
              "calibration table loader silently accepts duplicate sensor "
              "rows - last one wins - and that needs to become an error"),
     ("assistant", "merged. the loader change is not started; flagging it as "
                   "yours to schedule."),
     ("user", "yes, it's on me")],
    [_p("er-gauge-2-a", "must_capture",
        ["calibration table loader", "duplicate sensor rows"],
        "explicit keep-on-the-list request")]))

_MUST.append(_d(
    "er-quartz-1", "quartzfeed", "explicit_request",
    [("user", "digest render broke for feeds with empty titles"),
     ("assistant", "the renderer indexes entry.title[0] for the initial "
                   "capital. guarding empty and falling back to the domain."),
     ("user", "fix confirmed on the failing feed. one more for the board: "
              "we have to dedupe entries across feed aliases before the "
              "next mailout - the mirror feeds double every story"),
     ("assistant", "board item heard. the render guard is committed."),
     ("user", "thanks, wrapping for tonight")],
    [_p("er-quartz-1-a", "must_capture",
        ["dedupe entries across feed aliases", "mailout"],
        "explicit pre-mailout dedupe request")]))

_MUST.append(_d(
    "er-quartz-2", "quartzfeed", "explicit_request",
    [("user", "why did last night's digest go out twice?"),
     ("assistant", "two schedulers ran - the old cron entry survived the "
                   "migration to the new runner. removing the stale entry."),
     ("user", "ok. and write down: rotate the SMTP app password after the "
              "incident review, the current one is in two old logs"),
     ("assistant", "stale cron removed; single scheduler confirmed for "
                   "tonight's run."),
     ("user", "good")],
    [_p("er-quartz-2-a", "must_capture",
        ["rotate the smtp app password", "incident review"],
        "explicit post-review action, deliberately not done in-session")]))

# ---- conditional_ack -----------------------------------------------------

_MUST.append(_d(
    "ca-amber-1", "amberlight", "conditional_ack",
    [("user", "pagination on the archive page is off by one on the last page"),
     ("assistant", "the page count uses ceil over posts-per-page but the "
                   "loop drops the remainder. fixed with a boundary test."),
     ("assistant", "while I was in there: when you're ready, the incremental "
                   "build cache could skip unchanged markdown by mtime+hash - "
                   "I haven't built any of it, just flagging the option"),
     ("user", "the cache idea is real - that's on the board once the "
              "pagination fix soaks for a week"),
     ("assistant", "understood, leaving the cache untouched for now."),
     ("user", "ship the pagination fix")],
    [_p("ca-amber-1-a", "must_capture",
        ["incremental build cache", "unchanged markdown"],
        "assistant conditional proposal, operator board-acknowledged")]))

_MUST.append(_d(
    "ca-amber-2", "amberlight", "conditional_ack",
    [("user", "the link checker times out on big external pages"),
     ("assistant", "switching it to HEAD requests with a 5s cap and one "
                   "retry. checker passes on the full site now."),
     ("assistant", "if it helps later, the checker results could be cached "
                   "per-URL for a day so full rebuilds stop re-hitting every "
                   "external link - not started, your call"),
     ("user", "yes - queue the per-URL cache behind the release, it matters "
              "for the CI bill"),
     ("assistant", "queued in spirit; nothing built. HEAD switch is committed."),
     ("user", "good stopping point")],
    [_p("ca-amber-2-a", "must_capture",
        ["per-url cache", "release"],
        "conditional proposal acknowledged with a queue-behind condition")]))

_MUST.append(_d(
    "ca-gauge-1", "gaugepost", "conditional_ack",
    [("user", "unit tests are flaky on the rounding of corrected values"),
     ("assistant", "the correction multiplies then rounds half-up; test "
                   "fixtures assumed banker's rounding. pinning the mode "
                   "explicitly and regenerating fixtures."),
     ("assistant", "separately, when the fixture churn settles, a property "
                   "test over the correction - monotone in drift, identity "
                   "at zero - would catch this class; I've written none of it"),
     ("user", "the property test is on the board - after the fixtures "
              "stabilize, not before"),
     ("assistant", "agreed. rounding mode pinned, fixtures regenerated."),
     ("user", "run the full suite and push")],
    [_p("ca-gauge-1-a", "must_capture",
        ["property test", "correction"],
        "conditional proposal, operator board-acknowledged with ordering")]))

_MUST.append(_d(
    "ca-gauge-2", "gaugepost", "conditional_ack",
    [("user", "ingest is slow on month-boundary files"),
     ("assistant", "the reader re-parses the whole file to count rows first. "
                   "streaming the count away removed the double pass; 4x on "
                   "the boundary files."),
     ("assistant", "an index sidecar per file - byte offsets every 10k rows - "
                   "would make partial re-reads cheap too, once you decide "
                   "the sidecar format question; nothing exists yet"),
     ("user", "sidecar's real, put it on the board for after the vendor "
              "format freeze lands"),
     ("assistant", "on the board as yours; streaming fix is committed."),
     ("user", "good")],
    [_p("ca-gauge-2-a", "must_capture",
        ["index sidecar", "format freeze"],
        "conditional proposal acknowledged behind an external condition")]))

_MUST.append(_d(
    "ca-quartz-1", "quartzfeed", "conditional_ack",
    [("user", "fetcher hammers slow feeds when they 503"),
     ("assistant", "adding exponential backoff with a per-host circuit "
                   "breaker; the retry storm is gone in the replay test."),
     ("assistant", "if you want it later: the fetch schedule could learn "
                   "per-feed update cadence from history instead of polling "
                   "everything hourly - unbuilt, just the shape"),
     ("user", "cadence learning goes on the board - revisit when the "
              "backoff has a week of logs"),
     ("assistant", "understood; backoff + breaker are committed."),
     ("user", "done for now")],
    [_p("ca-quartz-1-a", "must_capture",
        ["cadence", "backoff"],
        "conditional proposal, operator acknowledged with a revisit condition")]))

_MUST.append(_d(
    "ca-quartz-2", "quartzfeed", "conditional_ack",
    [("user", "the digest subject line is just the date - people ignore it"),
     ("assistant", "prefixing the top story's title, truncated at 60 chars; "
                   "A/B copy is out of scope so I picked the simple rule."),
     ("assistant", "when you're ready to touch templates again, the plain-"
                   "text alternative part is stale - it still renders the "
                   "old two-column layout; I haven't changed it"),
     ("user", "stale text part is on the board, after this subject change "
              "ships"),
     ("assistant", "noted as yours. subject-line change is in."),
     ("user", "ship it")],
    [_p("ca-quartz-2-a", "must_capture",
        ["plain-text alternative", "stale"],
        "conditional flag acknowledged behind the current ship")]))

# ---- continuous_flow -----------------------------------------------------

_MUST.append(_d(
    "cf-amber-1", "amberlight", "continuous_flow",
    [("user", "morning - today is theme variables end to end"),
     ("assistant", "starting with the color tokens; templates read "
                   "--accent from one place now."),
     ("user", "keep going, and fold the spacing scale in too"),
     ("assistant", "spacing tokens done; 14 templates updated."),
     ("user", "the dark-mode contrast on code blocks still fails the "
              "checker - that one we fix before the theme PR merges, "
              "put it on the board while we keep moving"),
     ("assistant", "boarded. continuing: typography tokens next."),
     ("user", "yes, then the docs page for the token names"),
     ("assistant", "typography tokens merged into the base theme; docs page "
                   "drafted with the full token table."),
     ("user", "read the draft, fixed two names, keep rolling on the "
              "migration script"),
     ("assistant", "migration script converts legacy themes; 3 of 3 sample "
                   "themes pass.")],
    [_p("cf-amber-1-a", "must_capture",
        ["dark-mode contrast", "code blocks"],
        "boarded mid-flow; work continues past it with no quiet gap")]))

_MUST.append(_d(
    "cf-amber-2", "amberlight", "continuous_flow",
    [("user", "let's grind through the build warnings today"),
     ("assistant", "42 warnings: 30 deprecated filter calls, 8 image "
                   "size hints, 4 misc. starting with the filters."),
     ("user", "go"),
     ("assistant", "filters done; 12 warnings left."),
     ("user", "the draft-post leak into the live sitemap that surfaced in "
              "the warning triage - that is a real bug, on the board before "
              "the next deploy; keep going on the warnings"),
     ("assistant", "boarded, continuing. image hints emitted; 4 left."),
     ("user", "finish the misc ones too"),
     ("assistant", "zero warnings on a clean build now."),
     ("user", "beautiful, commit the lot")],
    [_p("cf-amber-2-a", "must_capture",
        ["draft-post leak", "sitemap"],
        "real bug boarded mid-triage, session continues without pause")]))

_MUST.append(_d(
    "cf-gauge-1", "gaugepost", "continuous_flow",
    [("user", "pairing on the export module until it's done"),
     ("assistant", "CSV export writes corrected values with unit columns; "
                   "round-trips against ingest."),
     ("user", "add parquet next"),
     ("assistant", "parquet export in with schema embedding; both formats "
                   "share the writer interface."),
     ("user", "the timezone column comes out empty for pre-2020 rows - "
              "board that, it needs the archive backfill, and keep moving "
              "on the JSON lines export"),
     ("assistant", "boarded the backfill dependency; JSONL export done with "
                   "streaming writes."),
     ("user", "now wire all three into the CLI"),
     ("assistant", "export subcommand takes --format csv|parquet|jsonl; "
                   "help text and tests updated."),
     ("user", "push it all")],
    [_p("cf-gauge-1-a", "must_capture",
        ["timezone column", "pre-2020"],
        "boarded mid-pairing; flow never pauses")]))

_MUST.append(_d(
    "cf-gauge-2", "gaugepost", "continuous_flow",
    [("user", "today: the dashboard data endpoint, no detours"),
     ("assistant", "endpoint serves corrected series with pagination; "
                   "50ms on the big site."),
     ("user", "add the summary stats block"),
     ("assistant", "min/max/mean/drift-rate per sensor in the payload."),
     ("user", "while it's hot: the per-sensor cache never invalidates when "
              "a calibration table updates - board it, it bites after the "
              "next recalibration; continue with the CSV download route"),
     ("assistant", "boarded the invalidation gap. download route streams "
                   "the filtered series now."),
     ("user", "throw rate limiting on it and we're done"),
     ("assistant", "token bucket per client id; 429 with retry-after. "
                   "endpoint suite is green."),
     ("user", "merge")],
    [_p("cf-gauge-2-a", "must_capture",
        ["cache never invalidates", "calibration table"],
        "boarded mid-build, no quiet boundary anywhere")]))

_MUST.append(_d(
    "cf-quartz-1", "quartzfeed", "continuous_flow",
    [("user", "heads-down on the unsubscribe flow"),
     ("assistant", "one-click unsubscribe endpoint with signed tokens; "
                   "link renders in the footer."),
     ("user", "good, now the preference page"),
     ("assistant", "per-topic checkboxes persist; resubscribe works."),
     ("user", "the bounce handler still marks soft bounces as permanent - "
              "that's on the board before the next big send; don't stop, "
              "finish the confirmation emails"),
     ("assistant", "boarded. confirmation emails send on subscribe and "
                   "preference change, with the audit line in each."),
     ("user", "test the whole flow end to end"),
     ("assistant", "subscribe, prefs, unsubscribe, resubscribe all pass "
                   "against the staging mailer."),
     ("user", "ship the flow")],
    [_p("cf-quartz-1-a", "must_capture",
        ["bounce handler", "soft bounces"],
        "boarded mid-flow before a named future send")]))

_MUST.append(_d(
    "cf-quartz-2", "quartzfeed", "continuous_flow",
    [("user", "template overhaul day - go until it's done"),
     ("assistant", "new base template with the card layout; desktop render "
                   "matches the mock."),
     ("user", "mobile next"),
     ("assistant", "single-column collapse under 480px; images scale."),
     ("user", "the tracking pixel is still requested over http in the new "
              "base - board fixing the scheme before any real campaign, "
              "and keep going with the footer redesign"),
     ("assistant", "boarded the scheme fix. footer rebuilt with the "
                   "preference links."),
     ("user", "dark mode pass now"),
     ("assistant", "prefers-color-scheme styles in; both mail clients "
                   "we target render correctly."),
     ("user", "great, freeze the templates for review")],
    [_p("cf-quartz-2-a", "must_capture",
        ["tracking pixel", "http"],
        "boarded mid-overhaul; continuous work throughout")]))

# ---- closure_mask --------------------------------------------------------

_MUST.append(_d(
    "cm-amber-1", "amberlight", "closure_mask",
    [("user", "release checklist run - call things out as you verify"),
     ("assistant", "build clean; link checker green; feeds validate; "
                   "fixture site matches."),
     ("user", "what about the redirect map for the moved posts?"),
     ("assistant", "generated and verified for the 12 moved posts."),
     ("user", "the search index rebuild for the renamed tags is still "
              "outstanding, right? that one has to happen before the "
              "announcement goes out - keep it open"),
     ("assistant", "correct, the search index rebuild has not run; keeping "
                   "it open as yours."),
     ("user", "everything else looks done then. wonderful run, closing "
              "the checklist - great work today"),
     ("assistant", "checklist closed; release tagged.")],
    [_p("cm-amber-1-a", "must_capture",
        ["search index rebuild", "renamed tags"],
        "explicitly kept open while the session closes on completion")]))

_MUST.append(_d(
    "cm-amber-2", "amberlight", "closure_mask",
    [("user", "let's land the image pipeline PR today"),
     ("assistant", "responsive variants generate at build; srcset emitted; "
                   "the sample gallery renders all sizes."),
     ("user", "did the AVIF encoder settle?"),
     ("assistant", "AVIF encodes on the two test machines after the "
                   "dependency pin."),
     ("user", "the cache-busting hash for rewritten images still collides "
              "on the two banner files - keep that open, it corrupts the "
              "CDN copy if we forget"),
     ("assistant", "kept open: banner hash collision, unresolved."),
     ("user", "with that noted, the PR itself is done - merging. really "
              "clean work, this closes out the whole image epic"),
     ("assistant", "merged; epic marked complete in the tracker.")],
    [_p("cm-amber-2-a", "must_capture",
        ["cache-busting hash", "banner"],
        "kept-open sibling inside an epic-complete narrative")]))

_MUST.append(_d(
    "cm-gauge-1", "gaugepost", "closure_mask",
    [("user", "wrap the vendor-format migration today if we can"),
     ("assistant", "both vendor layouts parse; golden files match; the "
                   "compat shim is removed."),
     ("user", "the re-validation of the February archive against the new "
              "parser - did that run?"),
     ("assistant", "not yet; it needs the archive volume mounted. that "
                   "re-validation is still open"),
     ("user", "right, that stays open - it must happen before we delete "
              "the old parser branch. everything else?"),
     ("assistant", "everything else is done: docs updated, CI switched, "
                   "old fixtures pruned."),
     ("user", "then the migration is a wrap - lovely. archiving the "
              "project channel"),
     ("assistant", "wrapped; channel archived.")],
    [_p("cm-gauge-1-a", "must_capture",
        ["re-validation", "february archive"],
        "explicitly stays-open gate before a destructive follow-up")]))

_MUST.append(_d(
    "cm-gauge-2", "gaugepost", "closure_mask",
    [("user", "close out the alerting milestone"),
     ("assistant", "threshold alerts fire on drift; the pager route works; "
                   "runbook drafted."),
     ("user", "quiet hours?"),
     ("assistant", "implemented with the on-call calendar override."),
     ("user", "the alert dedupe window is still hardcoded at 5 minutes - "
              "we agreed it becomes config before the second team onboards; "
              "that stays on the board"),
     ("assistant", "on the board: dedupe window to config, unstarted."),
     ("user", "otherwise this milestone is finished - closing it. "
              "genuinely great sprint"),
     ("assistant", "milestone closed and announced.")],
    [_p("cm-gauge-2-a", "must_capture",
        ["dedupe window", "config"],
        "boarded sibling surviving a milestone-closed narrative")]))

_MUST.append(_d(
    "cm-quartz-1", "quartzfeed", "closure_mask",
    [("user", "final pass on the archive page feature"),
     ("assistant", "past digests list with search; permalinks stable; "
                   "styles match the site."),
     ("user", "does the archive respect unsubscribed users' privacy "
              "settings?"),
     ("assistant", "yes - names are stripped from public archive copies."),
     ("user", "the retention job that prunes archives past 24 months "
              "isn't written - keep that one open, legal asked for it "
              "specifically"),
     ("assistant", "open item recorded: retention prune job, not started."),
     ("user", "everything else is complete then - feature's done, "
              "announcing it in the changelog"),
     ("assistant", "changelog entry added; feature flagged on.")],
    [_p("cm-quartz-1-a", "must_capture",
        ["retention", "24 months"],
        "kept-open compliance sibling under a feature-done wrap")]))

_MUST.append(_d(
    "cm-quartz-2", "quartzfeed", "closure_mask",
    [("user", "let's finish the migration off the old mail API"),
     ("assistant", "send path fully on the new API; bounces and opens "
                   "flow; the old client is deleted."),
     ("user", "webhook signatures verified?"),
     ("assistant", "verified with rotation support."),
     ("user", "the sandbox replay of last month's traffic - the one that "
              "proves parity on the weird encodings - still hasn't run; "
              "keep it open until it does"),
     ("assistant", "kept open: sandbox parity replay, pending."),
     ("user", "everything else is green so I'm calling the migration "
              "complete - excellent execution"),
     ("assistant", "migration marked complete in the tracker.")],
    [_p("cm-quartz-2-a", "must_capture",
        ["sandbox", "parity"],
        "kept-open verification inside a migration-complete wrap")]))

# --------------------------------------------------------------------------
# distractor-only dialogues: musing + completed, one per project = 6
# --------------------------------------------------------------------------

_DISTRACT = [
    _d("mu-amber-1", "amberlight", "musing",
       [("user", "the theme system came out nice"),
        ("assistant", "the token approach paid off."),
        ("user", "someday it might be fun to do a full plugin API - "
                 "themes as packages, community registry, the whole thing. "
                 "not this quarter, maybe not this year. just daydreaming"),
        ("assistant", "it would be a big lift; parking the thought."),
        ("user", "yeah, back to the bug queue")],
       [_p("mu-amber-1-a", "distractor",
           ["plugin api", "registry"],
           "explicit daydream, self-labeled not-now")]),
    _d("mu-gauge-1", "gaugepost", "musing",
       [("user", "drift plots look great this week"),
        ("assistant", "the correction is holding across sensors."),
        ("user", "imagine if we ever did real-time streaming ingest - "
                 "kafka, live dashboards, the works. wild idea, no plans, "
                 "the batch world is fine for us"),
        ("assistant", "noted as a wild idea only."),
        ("user", "right - what's next in the queue?")],
       [_p("mu-gauge-1-a", "distractor",
           ["real-time streaming", "kafka"],
           "self-labeled wild idea with explicit no-plans")]),
    _d("mu-quartz-1", "quartzfeed", "musing",
       [("user", "subscriber growth is steady"),
        ("assistant", "the digest quality changes are landing well."),
        ("user", "in some future life this could become a full newsletter "
                 "platform for other people - multi-tenant, billing, all "
                 "of it. pure musing, we are not doing that"),
        ("assistant", "understood, musing only."),
        ("user", "ok - today is just the fetcher timeout tweak")],
       [_p("mu-quartz-1-a", "distractor",
           ["multi-tenant", "billing"],
           "explicitly disclaimed platform fantasy")]),
    _d("co-amber-1", "amberlight", "completed",
       [("user", "can you bump the minimum python to 3.12 and fix whatever "
                 "breaks?"),
        ("assistant", "bumped; two f-string deprecations fixed; CI matrix "
                      "updated; all green."),
        ("user", "did the docs badge update too?"),
        ("assistant", "yes, badge and install docs both show 3.12."),
        ("user", "perfect, that one's completely done then")],
       [_p("co-amber-1-a", "distractor",
           ["minimum python", "3.12"],
           "requested AND fully discharged in-session")]),
    _d("co-gauge-1", "gaugepost", "completed",
       [("user", "rotate the sample fixtures to the new vendor layout "
                 "before I forget"),
        ("assistant", "rotated all nine fixtures; ingest tests pass on the "
                      "new layout; old fixtures deleted."),
        ("user", "and the README example?"),
        ("assistant", "README example uses the new layout now."),
        ("user", "great, fully handled")],
       [_p("co-gauge-1-a", "distractor",
           ["sample fixtures", "vendor layout"],
           "requested and completed with confirmation")]),
    _d("co-quartz-1", "quartzfeed", "completed",
       [("user", "please regenerate the DKIM keys and update DNS - the old "
                 "ones are 1024-bit"),
        ("assistant", "generated 2048-bit keys, DNS updated, verification "
                      "passes on both sending domains."),
        ("user", "verified from your side?"),
        ("assistant", "yes - test sends authenticate on both domains."),
        ("user", "excellent, done and done")],
       [_p("co-quartz-1-a", "distractor",
           ["dkim", "2048"],
           "security task fully discharged in-session")]),
]

# --------------------------------------------------------------------------
# null dialogues: nothing prospective at all = 4
# --------------------------------------------------------------------------

_NULL = [
    _d("nu-amber-1", "amberlight", "null",
       [("user", "what does the build do when two posts share a slug?"),
        ("assistant", "second one wins today; the first silently vanishes "
                      "from the output."),
        ("user", "huh. that at least explains the missing post from march"),
        ("assistant", "yes - the march collision was exactly that pair."),
        ("user", "mystery solved")],
       []),
    _d("nu-gauge-1", "gaugepost", "null",
       [("user", "walk me through how the drift correction actually works"),
        ("assistant", "each sensor has a per-month linear model fit from "
                      "reference checks; corrections interpolate between "
                      "months and are applied at read time."),
        ("user", "so raw values are never rewritten?"),
        ("assistant", "never - raw stays raw, corrections are a view."),
        ("user", "good design. that's all I needed")],
       []),
    _d("nu-quartz-1", "quartzfeed", "null",
       [("user", "which feeds were slowest this week?"),
        ("assistant", "two academic feeds dominate the tail - 8s and 11s "
                      "median fetch."),
        ("user", "consistent with last week?"),
        ("assistant", "same two, same order of magnitude."),
        ("user", "fine, just checking")],
       []),
    _d("nu-amber-2", "amberlight", "null",
       [("user", "how big is the generated site now?"),
        ("assistant", "412 pages, 38 MB with images, 6 MB without."),
        ("user", "and build time?"),
        ("assistant", "11.2s cold, 3.4s warm on the reference machine."),
        ("user", "nice. no action needed, just curious")],
       []),
]

# --------------------------------------------------------------------------
# the byte-identical pair: same bytes, opposite private operator labels
# --------------------------------------------------------------------------

_PAIR_MESSAGES = [
    ("user", "the retry queue drains slower than it fills during spikes"),
    ("assistant", "the worker takes one item per tick; batching ten per "
                  "tick clears the backlog in the replay. committed with "
                  "a queue-depth test."),
    ("assistant", "a dead-letter shelf for items that fail five times "
                  "would stop the poison-pill respins - I have not built "
                  "it, only sketching the shape"),
    ("user", "mm"),
    ("user", "ok, batching looks good in the replay"),
]

_PAIR = [
    _d("ip-quartz-priority", "quartzfeed", "identical_pair",
       _PAIR_MESSAGES,
       [_p("ip-a", "ambiguous", ["dead-letter", "five times"],
           "operator privately considers this on the board")],
       private_label="priority"),
    _d("ip-quartz-nopriority", "quartzfeed", "identical_pair",
       _PAIR_MESSAGES,
       [_p("ip-b", "ambiguous", ["dead-letter", "five times"],
           "operator privately dismissed this as noise")],
       private_label="not_priority"),
]

ALL_FIXTURES = _MUST + _DISTRACT + _NULL + _PAIR


def split_fixtures(seed: int = SPLIT_SEED) -> dict:
    """Deterministic stratified split: must-capture shapes split within each
    (shape, project) cell (2 instances -> exactly one per side); the smaller
    distractor/null shapes split within the shape alone so both sides see
    every distractor type. The identical pair is evaluation-only by
    construction and joins the held-out side. Seeded shuffle throughout."""
    import random
    cells: dict = {}
    for f in ALL_FIXTURES:
        if f["shape"] == "identical_pair":
            continue
        key = ((f["shape"], f["project"])
               if f["shape"] in ("explicit_request", "conditional_ack",
                                 "continuous_flow", "closure_mask")
               else (f["shape"],))
        cells.setdefault(key, []).append(f)
    rng = random.Random(seed)
    cal, held = [], []
    for key in sorted(cells):
        group = sorted(cells[key], key=lambda f: f["fid"])
        rng.shuffle(group)
        half = len(group) // 2
        cal.extend(group[:half])
        held.extend(group[half:])
    held.extend(_PAIR)
    return {"calibration": sorted(cal, key=lambda f: f["fid"]),
            "heldout": sorted(held, key=lambda f: f["fid"])}


def fixture_digest() -> str:
    import hashlib
    import json
    canonical = json.dumps(ALL_FIXTURES, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()
