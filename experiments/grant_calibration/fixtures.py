"""Frozen dialogue fixtures for the grant-calibration benchmark.

Ground truth is BY CONSTRUCTION: each fixture is a synthetic working dialogue
plus exactly one planted loop candidate (the text a background scanner would
have proposed), labeled by how the dialogue was written:

  should_confirm  - the dialogue shows the operator explicitly committing to
                    the candidate as future work, and the commitment still
                    stands at the end of the dialogue. Subtypes:
      explicit_request - the operator plainly asks for the future action
      conditional_ack  - a model proposes; the operator acknowledges it onto
                         the board (possibly behind a condition)
      self_assigned    - the operator assigns the item to themselves and asks
                         for it to stay open

  should_dismiss  - confirming the candidate would put words in the
                    operator's mouth. Subtypes:
      rejected     - the operator explicitly declined the proposal
      completed    - the action was requested AND discharged in-dialogue
      hypothetical - speculative someday-talk, self-labeled as such
      decoy        - a model aside the operator never engaged with
      near_miss    - HARD NEGATIVE: operator enthusiasm without commitment
                     (praise, then moves on; nothing is scheduled or boarded)
      superseded   - HARD NEGATIVE: the operator committed, then walked the
                     commitment back later in the same dialogue

Anti-leak rules observed while writing (checked mechanically by
``validity.surface_separability`` and the no-context control):
  - candidate texts are imperative action phrases in every class; no class
    marker words (no "someday", "done", "rejected") appear in candidates;
  - commitment vocabulary ("board", "list", "keep it open") appears in
    dismiss-class dialogues too (superseded commits before reversing;
    near_miss praises proposals);
  - dialogue lengths are comparable (5-9 messages) across classes.

All content is synthetic: three invented projects, no real transcript bytes,
no real names or employers. Fixtures were written in full before the judge
prompt was first dispatched (run log: runs/grant-calibration-2026-08-14/
notes.md).
"""

SPLIT_SEED = 20260814

PROJECTS = {
    "copperline": {"repo": "/synthetic/copperline",
                   "blurb": "a log-shipping daemon (tailers, batching, retry)"},
    "fernpress": {"repo": "/synthetic/fernpress",
                  "blurb": "a recipe-site publisher (markdown, images, index)"},
    "tidegate": {"repo": "/synthetic/tidegate",
                 "blurb": "a coastal-conditions API (ingest, cache, forecast)"},
}


def _f(fid, project, cls, subtype, messages, candidate, why):
    return {"fid": fid, "project": project, "cls": cls, "subtype": subtype,
            "messages": [{"role": r, "text": t} for r, t in messages],
            "candidate": candidate, "why": why}


# --------------------------------------------------------------------------
# should_confirm / explicit_request (4)
# --------------------------------------------------------------------------

_CONFIRM = []

_CONFIRM.append(_f(
    "er-copper-1", "copperline", "should_confirm", "explicit_request",
    [("user", "the uploader drops whole batches when the vendor 429s "
              "mid-stream"),
     ("assistant", "the retry path only covered connection errors. added "
                   "backoff-and-requeue for 429 and 503; the replay test "
                   "keeps every batch."),
     ("user", "good. also, before the next rollout, add a disk-quota check "
              "to the spool dir - one noisy host filled a partition last "
              "month and took the box down"),
     ("assistant", "understood; the backoff fix is merged, quota check not "
                   "started."),
     ("user", "ship the backoff fix today")],
    "add a disk-quota check to the spool dir before the next rollout",
    "explicit pre-rollout request, deliberately not done in-session"))

_CONFIRM.append(_f(
    "er-copper-2", "copperline", "should_confirm", "explicit_request",
    [("user", "a power loss on host 12 corrupted its checkpoint file again"),
     ("assistant", "the writer truncated in place. switched to write-temp-"
                   "then-atomic-rename; the kill-test no longer corrupts."),
     ("user", "write this down: we still need to migrate the old plaintext "
              "checkpoints across the fleet before we can delete the legacy "
              "parser"),
     ("assistant", "noted as outstanding; the rename fix is committed with "
                   "the kill-test."),
     ("user", "good, push it")],
    "migrate the old plaintext checkpoints across the fleet",
    "explicit write-this-down request naming future fleet work"))

_CONFIRM.append(_f(
    "er-fern-1", "fernpress", "should_confirm", "explicit_request",
    [("user", "screenshots come out enormous after the webp switch"),
     ("assistant", "the scaler used photo quality settings for everything. "
                   "added a screenshot heuristic - flat-color images now "
                   "encode 8x smaller."),
     ("user", "put 'regenerate the archive images with the new scaler "
              "settings' on the list - everything published before today is "
              "still bloated"),
     ("assistant", "on the list as outstanding; the heuristic is committed."),
     ("user", "great, deploy the scaler fix")],
    "regenerate the archive images with the new scaler settings",
    "explicit on-the-list request covering already-published images"))

_CONFIRM.append(_f(
    "er-tide-1", "tidegate", "should_confirm", "explicit_request",
    [("user", "station 21 and 33 report levels a foot off since tuesday"),
     ("assistant", "the datum conversion picked the wrong epoch table after "
                   "the upstream format change. pinned the epoch; both "
                   "stations agree with the reference gauge now."),
     ("user", "ok. and keep this open: backfill the corrected datums for "
              "march before the researchers pull the quarterly numbers"),
     ("assistant", "kept open; the epoch pin is deployed to staging."),
     ("user", "promote it to prod")],
    "backfill the corrected datums for march",
    "explicit keep-this-open request with a named deadline context"))

# --------------------------------------------------------------------------
# should_confirm / conditional_ack (4)
# --------------------------------------------------------------------------

_CONFIRM.append(_f(
    "ca-copper-1", "copperline", "should_confirm", "conditional_ack",
    [("user", "spool usage keeps creeping on the fleet dashboard"),
     ("assistant", "decommissioned hosts leave checkpoints behind forever. "
                   "cleaned the worst 40 by hand for now."),
     ("assistant", "a dead-host reaper that expires checkpoints for hosts "
                   "silent past 30 days would stop the creep - I have not "
                   "built any of it, just flagging the option"),
     ("user", "the reaper is real - on the board once the quota check "
              "lands"),
     ("assistant", "understood, leaving it untouched until then."),
     ("user", "good, back to the dashboard")],
    "build a dead-host reaper that expires stale checkpoints",
    "model proposal, operator board-acknowledged behind a condition"))

_CONFIRM.append(_f(
    "ca-fern-1", "fernpress", "should_confirm", "conditional_ack",
    [("user", "the shopping-list export mangles amounts like ½ cup"),
     ("assistant", "the exporter assumes ascii digits. escaped the unicode "
                   "for now so exports stop truncating."),
     ("assistant", "the ingredient parser could normalize unicode fractions "
                   "properly at ingest - nothing built, flagging it only"),
     ("user", "yes - queue the fraction normalization behind this release, "
              "it keeps breaking the export every season"),
     ("assistant", "queued in spirit, nothing started; the escape fix is "
                   "committed."),
     ("user", "ship the escape fix")],
    "normalize unicode fractions in the ingredient parser",
    "model proposal, operator queued it behind the release"))

_CONFIRM.append(_f(
    "ca-fern-2", "fernpress", "should_confirm", "conditional_ack",
    [("user", "a reader mailed a photo of a printed recipe - the tag chips "
              "render as black boxes"),
     ("assistant", "the print stylesheet never got the chip colors. forced "
                   "outline style under @media print as a stopgap."),
     ("assistant", "the print stylesheet really needs a full pass - "
                   "headers, chips, page breaks; I can rework it later if "
                   "you want it"),
     ("user", "board it for after the index migration - print matters for "
              "the cookbook crowd"),
     ("assistant", "boarded; the outline stopgap is live."),
     ("user", "good stopping point")],
    "rework the print stylesheet end to end",
    "model proposal, operator boarded it behind the migration"))

_CONFIRM.append(_f(
    "ca-tide-1", "tidegate", "should_confirm", "conditional_ack",
    [("user", "station 07 shows outage-flagged but it has been reporting "
              "clean since yesterday"),
     ("assistant", "flags only clear manually today. cleared 07 by hand; "
                   "readings flow again."),
     ("assistant", "outage flags could auto-clear after three consecutive "
                   "clean readings - not built, your call whether it is "
                   "worth it"),
     ("user", "auto-clear is on the board - after the alerting rewrite "
              "settles, not before"),
     ("assistant", "on the board with that ordering; manual clear stands "
                   "for now."),
     ("user", "fine, next item")],
    "auto-clear station outage flags after consecutive clean readings",
    "model proposal, operator boarded it with explicit ordering"))

# --------------------------------------------------------------------------
# should_confirm / self_assigned (4)
# --------------------------------------------------------------------------

_CONFIRM.append(_f(
    "sa-copper-1", "copperline", "should_confirm", "self_assigned",
    [("user", "support got three tickets this week about the rate limiter "
              "config - people set burst below sustained and nothing ships"),
     ("assistant", "the config docs never explain the relationship. added a "
                   "startup warning when burst < sustained as a guard."),
     ("user", "the docs rewrite for the limiter config is mine - keep it on "
              "my list until I get to it, the warning alone will not stop "
              "the tickets"),
     ("assistant", "kept on your list; the startup warning is merged."),
     ("user", "release the warning in the patch build")],
    "rewrite the rate limiter configuration docs",
    "operator self-assigned the rewrite and asked to keep it open"))

_CONFIRM.append(_f(
    "sa-fern-1", "fernpress", "should_confirm", "self_assigned",
    [("user", "the fall menu goes up in six weeks and the season-menu "
              "template is still the 2023 layout"),
     ("assistant", "confirmed - it predates the card redesign and hardcodes "
                   "four columns."),
     ("user", "I'll own the season-menu template cleanup - leave it open, I "
              "want it finished before the fall menu goes up"),
     ("assistant", "left open as yours; nothing changed in the template "
                   "today."),
     ("user", "right - today is just the image bug backlog"),
     ("assistant", "starting on the backlog: three of nine images fixed so "
                   "far.")],
    "clean up the season-menu template",
    "operator took ownership and asked for it to stay open"))

_CONFIRM.append(_f(
    "sa-tide-1", "tidegate", "should_confirm", "self_assigned",
    [("user", "the security review flagged our NOAA keys as two years old"),
     ("assistant", "both keys predate the key-scoping change upstream; "
                   "rotation needs the account owner, which is you."),
     ("user", "the NOAA key rotation is on me - hold it open until I do it "
              "after thursday's audit call"),
     ("assistant", "holding it open as yours; no key changes made today."),
     ("user", "meanwhile fix the cache header bug we found"),
     ("assistant", "cache-control now carries max-age from the station "
                   "config; verified on staging.")],
    "rotate the noaa api keys",
    "operator self-assigned rotation with explicit timing"))

_CONFIRM.append(_f(
    "sa-tide-2", "tidegate", "should_confirm", "self_assigned",
    [("user", "stations 44 and 51 drift against the harmonic predictions "
              "again - third month running"),
     ("assistant", "their constituent sets were last fit in 2021; the drift "
                   "pattern matches an outdated fit, not sensor fault."),
     ("user", "the harmonics re-fit for the two drifting stations is mine - "
              "keep it open, it has to land before the spring tide tables "
              "publish"),
     ("assistant", "kept open as yours; no re-fit run today."),
     ("user", "for now just annotate the drift on the station pages"),
     ("assistant", "annotation shipped - both pages show the drift notice "
                   "with the last-fit date.")],
    "re-fit the harmonic constituents for the drifting stations",
    "operator self-assigned the re-fit with a publish deadline"))

# --------------------------------------------------------------------------
# should_dismiss / rejected (4)
# --------------------------------------------------------------------------

_DISMISS = []

_DISMISS.append(_f(
    "rj-copper-1", "copperline", "should_dismiss", "rejected",
    [("user", "the vendor endpoint was flaky again this morning"),
     ("assistant", "backoff absorbed it - zero data loss, delays under two "
                   "minutes."),
     ("assistant", "we could add a kafka output alongside the vendor "
                   "endpoint as an escape hatch for outages like this"),
     ("user", "no - we are not adding kafka, the vendor path is the "
              "product. drop it"),
     ("assistant", "dropped; no changes made."),
     ("user", "just tighten the alert threshold for delay spikes"),
     ("assistant", "alert now fires at 60s sustained delay instead of "
                   "300s.")],
    "add a kafka output alongside the vendor endpoint",
    "operator explicitly rejected the proposal in the dialogue"))

_DISMISS.append(_f(
    "rj-copper-2", "copperline", "should_dismiss", "rejected",
    [("user", "spool compression - is zstd worth revisiting? someone asked "
              "at standup"),
     ("assistant", "zstd would cut spool size ~30% but adds a native "
                   "dependency to the agent build for every platform we "
                   "ship."),
     ("user", "not worth it - gzip stays, decision made, do not bring it "
              "back"),
     ("assistant", "understood; gzip stays, nothing changed."),
     ("user", "ok, on to the journald parsing bug"),
     ("assistant", "the parser mis-read multiline units; fixed with the "
                   "boundary test.")],
    "switch spool compression from gzip to zstd",
    "operator considered and explicitly closed the question as no"))

_DISMISS.append(_f(
    "rj-fern-1", "fernpress", "should_dismiss", "rejected",
    [("user", "search traffic report came in - mobile is 70% now"),
     ("assistant", "the mobile render is already responsive; largest gap is "
                   "image weight on 3g."),
     ("assistant", "we could generate AMP versions of recipe pages for the "
                   "mobile search carousel"),
     ("user", "hard no on AMP - we killed that idea twice already and "
              "nothing has changed. it stays dead"),
     ("assistant", "understood, staying with the responsive pages."),
     ("user", "put the effort into the image weight instead, starting with "
              "lazy loading"),
     ("assistant", "lazy loading added below the fold; 3g load time drops "
                   "40%.")],
    "generate amp versions of the recipe pages",
    "operator rejected the proposal, explicitly and finally"))

_DISMISS.append(_f(
    "rj-tide-1", "tidegate", "should_dismiss", "rejected",
    [("user", "a partner asked if we expose the forecast blend over "
              "graphql"),
     ("assistant", "we could stand a graphql surface next to the REST api - "
                   "schema sketch would take a day"),
     ("user", "no graphql. REST is the contract, that is final - tell them "
              "the answer is the existing endpoints"),
     ("assistant", "will do; no schema work started."),
     ("user", "what is the cache hit rate on the forecast endpoint lately?"),
     ("assistant", "94% over the last week, steady.")],
    "stand up a graphql surface next to the rest api",
    "operator rejected the proposal with a final decision"))

# --------------------------------------------------------------------------
# should_dismiss / completed (4)
# --------------------------------------------------------------------------

_DISMISS.append(_f(
    "co-copper-1", "copperline", "should_dismiss", "completed",
    [("user", "the vendor rotated their cert - bump the TLS pins and verify "
              "against staging before anything else today"),
     ("assistant", "pins updated for the new intermediate and leaf; staging "
                   "handshake verified on both upload endpoints."),
     ("user", "prod too?"),
     ("assistant", "prod verified - all agents reconnected clean, zero "
                   "handshake failures in the last hour."),
     ("user", "confirmed on my dashboard as well - that one is fully done")],
    "bump the tls pins for the rotated vendor cert",
    "requested and fully discharged inside the dialogue"))

_DISMISS.append(_f(
    "co-fern-1", "fernpress", "should_dismiss", "completed",
    [("user", "regenerate the search index with the new stemmer before "
              "tonight's publish"),
     ("assistant", "index regenerated - 2,340 recipes, new stemmer, "
                   "build clean."),
     ("user", "spot check 'braised' and 'braising' - that was the broken "
              "pair"),
     ("assistant", "both resolve to the same results now; checked six more "
                   "stem pairs, all merged correctly."),
     ("user", "search works on my end too, that item is wrapped")],
    "regenerate the search index with the new stemmer",
    "requested and completed with double confirmation"))

_DISMISS.append(_f(
    "co-tide-1", "tidegate", "should_dismiss", "completed",
    [("user", "purge the stale cache entries for the renamed stations - "
              "old names still resolve and confuse the map"),
     ("assistant", "purged 18 stale entries; renamed stations now resolve "
                   "only under the new ids."),
     ("user", "does the map view agree?"),
     ("assistant", "map shows the new names everywhere; cache hit rate "
                   "recovered to normal after the purge."),
     ("user", "verified here - done and dusted")],
    "purge the stale cache entries for the renamed stations",
    "requested and discharged, operator verified"))

_DISMISS.append(_f(
    "co-tide-2", "tidegate", "should_dismiss", "completed",
    [("user", "add the two new gulf stations to ingest today - the permit "
              "finally cleared"),
     ("assistant", "both stations added; first readings flowing, datum "
                   "conversion validated against their published reference."),
     ("user", "dashboards?"),
     ("assistant", "both appear on the dashboard with live sparklines and "
                   "correct units."),
     ("user", "I see data on both - that task is complete")],
    "add the two new gulf stations to ingest",
    "requested and completed in-session, operator confirmed"))

# --------------------------------------------------------------------------
# should_dismiss / hypothetical (4)
# --------------------------------------------------------------------------

_DISMISS.append(_f(
    "hy-copper-1", "copperline", "should_dismiss", "hypothetical",
    [("user", "fleet stats look healthy this week"),
     ("assistant", "spool sizes flat, retry rate under 1%."),
     ("user", "someday it might be fun to do a full agent mesh - peers "
              "sharing spool during outages, gossip protocol, the works. "
              "pure daydream, not this year, maybe not ever"),
     ("assistant", "it would be a large lift; parking the thought."),
     ("user", "yeah - back to the ticket queue"),
     ("assistant", "next ticket: a tailer wedged on a rotated symlink; "
                   "reproducing now.")],
    "build peer-to-peer spool sharing between agents",
    "self-labeled daydream with explicit not-this-year"))

_DISMISS.append(_f(
    "hy-fern-1", "fernpress", "should_dismiss", "hypothetical",
    [("user", "reader mail is up since the redesign, mostly happy"),
     ("assistant", "the card layout tested well across clients."),
     ("user", "imagine a phone app with offline recipes and a cooking "
              "timer - just musing, we are a website and staying one"),
     ("assistant", "understood, musing only."),
     ("user", "ok - today is the ingredient scaling bug"),
     ("assistant", "scaling doubled fractional ounces; fixed with the "
                   "rounding table and a regression test.")],
    "build a phone app with offline recipes",
    "explicitly disclaimed musing, we-are-staying-a-website"))

_DISMISS.append(_f(
    "hy-fern-2", "fernpress", "should_dismiss", "hypothetical",
    [("user", "three readers submitted recipes by email this month"),
     ("assistant", "all three imported cleanly after light formatting."),
     ("user", "a community submission portal could be neat one day - "
              "accounts, moderation queue, the lot. thinking out loud, not "
              "committing to anything"),
     ("assistant", "noted as thinking-out-loud only."),
     ("user", "for now just document the email submission format"),
     ("assistant", "format doc added to the contributing page with two "
                   "examples.")],
    "build a community recipe submission portal",
    "explicit thinking-out-loud, not-committing"))

_DISMISS.append(_f(
    "hy-tide-1", "tidegate", "should_dismiss", "hypothetical",
    [("user", "the quarterly usage report is strong - api calls doubled"),
     ("assistant", "growth is concentrated on the forecast blend endpoint."),
     ("user", "in some future life this becomes a full marine-forecast "
              "product - subscriptions, mobile alerts, the whole business. "
              "wild idea, no plans"),
     ("assistant", "noted as a wild idea only."),
     ("user", "right - what is next in the queue?"),
     ("assistant", "the webhook retry bug: alerts double-fire when a "
                   "subscriber times out; fix is scoped.")],
    "turn tidegate into a subscription marine-forecast product",
    "self-labeled wild idea with explicit no-plans"))

# --------------------------------------------------------------------------
# should_dismiss / decoy (4)
# --------------------------------------------------------------------------

_DISMISS.append(_f(
    "de-copper-1", "copperline", "should_dismiss", "decoy",
    [("user", "the file tailer misses lines when logs rotate twice in a "
              "second"),
     ("assistant", "the inode check raced the second rotation. now tracking "
                   "rotation generations; the double-rotate test passes."),
     ("assistant", "in passing: the journald input could eventually use the "
                   "same batching path as the file tailer, which would "
                   "delete some duplicate code"),
     ("user", "the rotation fix looks right - run it on the canary hosts "
              "overnight and show me the numbers tomorrow"),
     ("assistant", "canary rollout started on 20 hosts; report tomorrow.")],
    "move the journald input to the shared batching path",
    "model aside; the operator never engaged with it at all"))

_DISMISS.append(_f(
    "de-copper-2", "copperline", "should_dismiss", "decoy",
    [("user", "why did host 31 stall yesterday at 14:00?"),
     ("assistant", "backpressure: the vendor slowed and the spool hit its "
                   "cap, so the tailer paused - by design. it drained "
                   "clean by 14:20."),
     ("assistant", "side thought: backpressure metrics could feed an "
                   "autoscaler for the uploader pool someday"),
     ("user", "so no action needed on host 31 - good. what about the "
              "checkpoint fix, did it land in the patch release?"),
     ("assistant", "yes, the atomic-rename fix shipped in 4.2.1 to the "
                   "whole fleet.")],
    "feed backpressure metrics into an uploader autoscaler",
    "model side-thought; operator moved on without engaging"))

_DISMISS.append(_f(
    "de-fern-1", "fernpress", "should_dismiss", "decoy",
    [("user", "the unit converter renders '2 sticks butter' as 226.8g - "
              "too many decimals for a recipe"),
     ("assistant", "added cooking-friendly rounding: weights round to 5g "
                   "under a kilo. the butter line reads 225g now."),
     ("assistant", "the conversion table could also grow imperial-to-metric "
                   "volume pairs both directions at some point"),
     ("user", "225g reads right. publish the rounding change with tonight's "
              "batch"),
     ("assistant", "queued for tonight's publish with the regression "
                   "tests.")],
    "extend the unit conversion table with bidirectional volume pairs",
    "model aside; operator responded only to the rounding fix"))

_DISMISS.append(_f(
    "de-tide-1", "tidegate", "should_dismiss", "decoy",
    [("user", "the outage flag for station 12 stuck through the whole "
              "weekend"),
     ("assistant", "the flag-clear job crashed on a null reading and never "
                   "restarted. added the null guard and a supervisor "
                   "restart; flags clear again."),
     ("assistant", "webhook alerts could carry station metadata too, so "
                   "subscribers stop joining against the station list"),
     ("user", "the outage fix looks good - ship it and close the incident"),
     ("assistant", "shipped; incident closed with the postmortem link.")],
    "include station metadata in webhook alert payloads",
    "model aside; operator shipped the fix without engaging"))

# --------------------------------------------------------------------------
# should_dismiss / near_miss (4)  - enthusiasm is not commitment
# --------------------------------------------------------------------------

_DISMISS.append(_f(
    "nm-copper-1", "copperline", "should_dismiss", "near_miss",
    [("user", "anything risky in the spool design review notes?"),
     ("assistant", "one reviewer noted spool files are plaintext on disk."),
     ("assistant", "we could encrypt the spool at rest with a per-host key "
                   "- I have a rough shape in mind"),
     ("user", "ooh, I like that a lot - clever, and it would calm the "
              "reviewer down"),
     ("user", "anyway - back to the retry bug, what is the actual fix?"),
     ("assistant", "the retry counter reset on partial success; now it only "
                   "resets on a full batch ack. replay test passes.")],
    "encrypt the spool files at rest with per-host keys",
    "praise without commitment; operator changed subject unscheduled"))

_DISMISS.append(_f(
    "nm-fern-1", "fernpress", "should_dismiss", "near_miss",
    [("user", "the redesign feedback thread has some feature asks"),
     ("assistant", "most common ask is nutritional info per serving."),
     ("assistant", "a nutrition generator off the ingredient parser could "
                   "cover the common ask automatically"),
     ("user", "that is a genuinely great idea, love it"),
     ("user", "ok - today is the image bug, let us stay on it"),
     ("assistant", "the webp fallback chain mis-ordered sources; fixed and "
                   "verified on the four affected templates.")],
    "generate nutritional info from the ingredient parser",
    "love-it praise, then an explicit stay-on-task pivot; no commitment"))

_DISMISS.append(_f(
    "nm-tide-1", "tidegate", "should_dismiss", "near_miss",
    [("user", "the sailing club asked what is coming next quarter"),
     ("assistant", "nothing public yet beyond stability work."),
     ("assistant", "tide-window notifications - alert when conditions "
                   "match a saved window - would be the obvious headline "
                   "feature"),
     ("user", "very cool concept, honestly. people would use that"),
     ("user", "right - the cache fix first, nothing else today"),
     ("assistant", "cache fix done: TTLs now respect per-station update "
                   "cadence; hit rate up four points on staging.")],
    "build tide-window notifications for saved conditions",
    "very-cool praise, then explicit nothing-else-today; no commitment"))

_DISMISS.append(_f(
    "nm-tide-2", "tidegate", "should_dismiss", "near_miss",
    [("user", "the station map got compliments at the demo"),
     ("assistant", "the clustering change made dense coasts readable."),
     ("user", "a heatmap view of current conditions would be slick, would "
              "it not"),
     ("assistant", "it could reuse the map tiles; nontrivial but doable."),
     ("user", "fun to think about. so - the datum bug on station 21, walk "
              "me through the fix"),
     ("assistant", "the epoch table pin: conversion now selects by station "
                   "commissioning date, verified against the reference "
                   "gauge.")],
    "build a heatmap view of current conditions",
    "operator's own slick-idea remark, then pivot; nothing committed"))

# --------------------------------------------------------------------------
# should_dismiss / superseded (4)  - committed, then walked back
# --------------------------------------------------------------------------

_DISMISS.append(_f(
    "su-copper-1", "copperline", "should_dismiss", "superseded",
    [("user", "put the vendor failover endpoint on the board - we need it "
              "before the contract renewal"),
     ("assistant", "boarded; nothing built yet."),
     ("user", "meanwhile, how did the canary rollout go?"),
     ("assistant", "clean - 20 hosts, zero rotation misses, latency flat."),
     ("user", "actually, scratch the failover item - legal says "
              "single-endpoint is contractual, we cannot ship a failover "
              "path at all"),
     ("assistant", "scratched; no failover work will be started."),
     ("user", "promote the canary rollout to the full fleet then"),
     ("assistant", "fleet rollout scheduled for tonight's window.")],
    "add a vendor failover endpoint before the contract renewal",
    "boarded early, explicitly scratched later in the same dialogue"))

_DISMISS.append(_f(
    "su-fern-1", "fernpress", "should_dismiss", "superseded",
    [("user", "board the per-tag RSS feeds - readers keep asking in the "
              "survey"),
     ("assistant", "boarded; the feed writer can be parameterized by tag."),
     ("user", "while you are in there, did the survey say anything else?"),
     ("assistant", "second ask is print quality, third is search speed."),
     ("user", "drop the per-tag feeds idea - I re-read the numbers and it "
              "was 4 responses out of 900. not doing it"),
     ("assistant", "dropped; no feed work started."),
     ("user", "put the survey summary in the planning doc instead"),
     ("assistant", "summary added with the response counts per ask.")],
    "add per-tag rss feeds",
    "boarded on a misread, explicitly dropped after re-reading the data"))

_DISMISS.append(_f(
    "su-fern-2", "fernpress", "should_dismiss", "superseded",
    [("user", "queue the webp fallback for old browsers - the support "
              "inbox had another complaint"),
     ("assistant", "queued; the picture-element fallback is a day of work."),
     ("user", "actually pull the analytics first - how many legacy browser "
              "sessions last month?"),
     ("assistant", "0.2% of sessions, trending down month over month."),
     ("user", "forget the webp fallback then - I am killing that item, the "
              "numbers do not justify a day"),
     ("assistant", "killed; no fallback work will happen."),
     ("user", "answer the support thread with the numbers"),
     ("assistant", "reply drafted with the session stats and the modern-"
                   "browser recommendation.")],
    "add a webp fallback for legacy browsers",
    "queued, then explicitly killed on the analytics"))

_DISMISS.append(_f(
    "su-tide-1", "tidegate", "should_dismiss", "superseded",
    [("user", "the harmonic re-fit for station 44 goes on the list - "
              "before the spring tables"),
     ("assistant", "on the list; the fit pipeline supports single-station "
                   "runs."),
     ("user", "did the NOAA bulletin from yesterday say anything about our "
              "stations?"),
     ("assistant", "yes - station 44 is scheduled for decommissioning next "
                   "month."),
     ("user", "cancel the station 44 re-fit then - refitting a station "
              "they are about to remove is wasted work"),
     ("assistant", "cancelled; no re-fit will run for 44."),
     ("user", "note the decommission date on the station page instead"),
     ("assistant", "notice added with the bulletin link.")],
    "re-fit the harmonic constituents for station 44",
    "listed, then explicitly cancelled on the decommission news"))

ALL_FIXTURES = _CONFIRM + _DISMISS

SUBTYPES = ("explicit_request", "conditional_ack", "self_assigned",
            "rejected", "completed", "hypothetical", "decoy", "near_miss",
            "superseded")


def split_fixtures(seed: int = SPLIT_SEED) -> dict:
    """Deterministic stratified split: within each subtype (4 fixtures),
    a seeded shuffle sends half to calibration and half to held-out, so
    both sides see every subtype including both hard-negative families."""
    import random
    cells: dict = {}
    for f in ALL_FIXTURES:
        cells.setdefault(f["subtype"], []).append(f)
    rng = random.Random(seed)
    cal, held = [], []
    for subtype in sorted(cells):
        group = sorted(cells[subtype], key=lambda f: f["fid"])
        rng.shuffle(group)
        half = len(group) // 2
        cal.extend(group[:half])
        held.extend(group[half:])
    return {"calibration": sorted(cal, key=lambda f: f["fid"]),
            "heldout": sorted(held, key=lambda f: f["fid"])}


def fixture_digest() -> str:
    import hashlib
    import json
    canonical = json.dumps(ALL_FIXTURES, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()
