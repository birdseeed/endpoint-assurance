# Assessment report drafting run (PAT-1502)

You are drafting one Endpoint Assurance assessment report from real
collected evidence. This is a paid deliverable in progress, not a
demo. The judgement stays with the specialist who reviews your draft;
your job is the transcription and the honest bookkeeping of what the
evidence does and does not support.

Run this with:

```
EVIDENCE_BUNDLE_PATH=<path to evidence-*.json> \
REPORT_TEMPLATE_PATH=docs/endpoint-assurance/report-template.md \
OUTPUT_DRAFT_PATH=<path to write the draft> \
claude --dangerously-skip-permissions -p "$(cat docs/endpoint-assurance/scripts/draft-report-prompt.md)"
```

`EVIDENCE_BUNDLE_PATH` and `OUTPUT_DRAFT_PATH` are required. If
`REPORT_TEMPLATE_PATH` is unset, use `docs/endpoint-assurance/report-template.md`
relative to the current working directory. If any required environment
variable is missing, stop and say so rather than guessing a path.

## Step 1 - Read your inputs

1. Read the file at `$EVIDENCE_BUNDLE_PATH`. It is a JSON object with this
   shape (produced by `docs/endpoint-assurance/scripts/fetch-evidence.sh`):

   ```
   {
     "tenant_id": "...",
     "generated_at": "...",             // UTC timestamp the bundle was fetched
     "source": { "api_base_url": "...", "local_admin_via": "..." },
     "devices": {
       "total": N, "devices": [
         { "id", "hostname", "serial", "os", "os_version", "last_seen",
           "primary_user_account",
           "compliance": {"pass","fail","not_applicable","error","compliance_pct"},
           "hardware": {...}, "backup": {...} }
       ]
     },
     "device_apps": {
       "<device_id>": {
         "device_id": "...", "total": N,
         "apps": [
           { "name","version","identifier","publisher","signer","team_id",
             "architecture","notarized","size_bytes","first_seen","last_seen",
             "last_used_at","launch_count" }
         ]
       }
     },
     "device_cve_findings": {
       "<device_id>": { "findings": [
         { "cve_id","description","cvss_v3_score","severity","published_at",
           "app_name","app_version","match_confidence","last_seen_at" }
       ], "total": N }
     },
     "cis_findings": {
       "findings": [
         { "device_id","hostname","rule_key","title","severity","status",
           "evaluated_at" }
       ]
     },
     "shadow_it_findings": {
       "findings": [ { "shadow_it_label","category","shadow_it_name",
         "device_id","hostname","app_name","identifier","policy",
         "first_seen","last_seen" } ],
       "exceptions": [...], "total": N
     },
     "local_admin": [
       { "device_id","hostname","os","admin_count_raw" }
     ]
   }
   ```

   A device with no matching entry in `device_apps`, `device_cve_findings`,
   or `local_admin` has **no data**, not zero findings. Say so explicitly
   for that device rather than treating a missing key the same as an
   empty list - a missing collector run is not evidence of a clean
   result. `cis_findings.findings` is a filtered list (the API only
   returns non-passing rules in this route in current use); a rule with
   no entry for a device was either not evaluated or passed - if you
   cannot tell which from the bundle, say that, do not assume pass.

2. Read the full report template at `$REPORT_TEMPLATE_PATH`. It already
   states its own bracket convention, evidence limits, and section
   structure - follow that document's own instructions, not a paraphrase
   of them. Do not restructure its sections, add a fourth finding class,
   or remove the worked examples (they are there to show format; leave
   them in place above your own findings unless the template's own text
   says to remove them).

## Step 2 - The confidence and scope rules for this evidence source

These map the ticket's general evidence-limit rule onto this specific
data. Apply them to every finding you write, and state the confidence
and scope in the finding itself - not as a footnote, and not only a
severity number.

**CVE findings (`device_cve_findings`).**
`match_confidence` is either `version_confirmed` or `version_unverified`.
- `version_confirmed`: the installed version was matched against the
  vulnerable range with a version comparison. State the finding as a
  real vulnerability match at that confidence.
- `version_unverified`: the application name matched a known-vulnerable
  product but the installed version could not be confirmed against the
  vulnerable range (a display-name match, in the ticket's own words).
  State this explicitly in the finding - "present, version match
  unconfirmed" or equivalent - and do not present it with the same
  certainty as a confirmed match. Do not drop it either; an unverified
  match is still worth a specialist's eyes, just not worth the same
  sentence as a confirmed one.
Two entries for the same `cve_id` on one device (e.g. "Microsoft Teams"
and "Microsoft Teams classic") are two distinct installed products the
agent found, not a duplicate - report both if their confidence or
version differs, and say plainly if they look like the same underlying
install reported under two names (worth a `[specialist input required]`
note asking which is correct, since only a human who knows this estate
can resolve that).

**CIS / configuration findings (`cis_findings`).**
Each entry is one rule failing on one device at the time it was last
evaluated. State the count of affected devices out of total devices in
scope, and don't imply broader coverage than what was evaluated - if
`cis_findings` covers fewer devices than `devices.devices`, name which
devices have no CIS result rather than assuming they passed everything.

**Standing local-admin (`local_admin`).**
`admin_count_raw` is a string form of the last-reported count; it can be
`null` if a device never reported the signal - a null is "not observed",
never "zero" and never "compliant." Apply the template's own
compliant/at-risk/critical framing (≤2 / 3-4 / ≥5) only to devices with a
real number; call out any device with a null count by name as evidence
gap, not as a finding of any severity.

**Licence and usage signal (`device_apps`).**
`last_used_at` and `launch_count` are the metering signal. This ticket's
own hard rule: a launch timestamp alone does not on its own prove a
licence is wasted. Before calling anything "unused" or "reclaimable":
- Check `generated_at` in the bundle against each app's `first_seen`.
  If the observation period covered by this bundle is under three weeks
  (the delivery runbook's stated minimum for metering confidence - see
  `docs/endpoint-assurance/delivery-runbook.md` Phase 4 if you want the
  reasoning), do not present a "never used" or "reclaimable seat" finding
  with confidence. Say explicitly that the window is too short for a
  metering conclusion and mark it `[specialist input required: confirm
  actual observation window length and whether it meets the 3-week
  minimum before treating this as a reclaim finding]`.
- Even inside a long-enough window, `device_apps` alone has no seat-count
  or licence-cost data - this bundle cannot tell you how many seats are
  licensed, so any seat/licence figure in Section 2.3 or its worked
  example is a `[specialist input required]` item by definition; you can
  report install count and last-used date, not licence compliance.
- Shadow-IT findings (`shadow_it_findings`) are the separate, real signal
  for unapproved software - use those for Section 2.3's shadow-IT half,
  and keep it visibly separate from the metering/licence half, per the
  template's own instruction not to conflate them.

**General rule for every section.** If the evidence for a template
subsection is genuinely absent (an empty list, a missing key, a null
value, a window too short to trust) - do not guess, do not invent a
plausible-sounding number, and do not silently delete the section. Write
the sentence the template itself asks for when there is nothing to
report ("no shadow-IT applications identified in the assessment period"
is the template's own example), or, when the gap is that evidence exists
but is insufficient for a confident conclusion, use
`[specialist input required: ...]` stating exactly what is missing and
what would resolve it. These are different situations and should read
differently: "nothing found" is a finding; "not enough evidence yet" is
a gap.

## Step 3 - What stays a judgement call, not yours to make

Leave these as `[specialist input required: ...]` even when the data is
complete, using the exact convention already in
`docs/endpoint-assurance/scoping-questionnaire.md`:

- Severity ranking and remediation order across findings, beyond what the
  template's own default sequencing (Section 3) already states.
- What to recommend the customer do first, and what to leave alone (for
  example a standing-admin account that is a genuine operational
  requirement - the evidence bundle has no way to know that).
- Anything commercial: customer name, specialist name, dates, the 90-day
  credit terms, device-count framing on the cover page.
- The executive summary's specific plain-language judgement calls (what
  this would cost, what an auditor would write up) - draft the prose
  shape and voice, but mark the figures and specific claims that need the
  specialist's own judgement rather than inventing them from the
  evidence bundle, which was never designed to produce a cost figure.

## Step 4 - Draft the management summary in prose, not tool output

Section 1 of the template is explicit about its audience and voice: a
finance director or MLRO, not an engineer, no tool names, no CVE IDs, no
version numbers. Write it as connected prose paragraphs. Do not write it
as a bullet list of findings restated from Section 2 - that is exactly
the tool-export style the template's own opening warns against ("if a
paragraph in this report could have come out of the free scan, cut it").
Where the underlying number is genuinely known (device counts, CIS pass
rate, confirmed CVE count) state it in the prose. Where the judgement
requires the specialist (cost figures, what an auditor would specifically
write up), leave the `[specialist input required: ...]` marker inline in
the paragraph rather than blocking the whole section.

## Step 5 - Write the draft

Write the completed document to `$OUTPUT_DRAFT_PATH`, following
`report-template.md`'s own section order and heading structure exactly.
Keep the template's own front-matter instruction line and worked examples
in place (do not delete them; the human editing this draft still needs
them as reference until they finish the report). Fill the Cover table's
`[N] devices ([N] macOS, [N] Windows)` line from `devices.devices` counts
- that one is always answerable from the bundle regardless of window
length. Do not fabricate a customer name, specialist name, or date; leave
those bracketed exactly as the template has them if the bundle gives you
no way to know them (it never will - those are commercial facts, not
telemetry).

No em dashes anywhere in the draft. Use " - " (space-hyphen-space), matching
every other document in `docs/endpoint-assurance/`. Say "estate", never
"fleet". Do not add a section, framework mapping, or finding class beyond
what `report-template.md` already defines.

## Step 6 - Report what you did

After writing the file, print a short summary: which sections were filled
with real findings versus left as `[specialist input required: ...]`, and
why in each case (no data at all, vs. data present but confidence/window
insufficient, vs. genuinely a judgement call). This is what lets whoever
ran this compare the draft's honesty against the underlying bundle without
re-reading the whole report.

## Re-running this

This prompt is stateless with respect to any prior draft: point
`EVIDENCE_BUNDLE_PATH` at a fresh bundle (re-run
`docs/endpoint-assurance/scripts/fetch-evidence.sh` first) and
`OUTPUT_DRAFT_PATH` at a new file, and it produces a new draft from
scratch. It never reads a previous draft and never needs one - that is
what keeps a retainer's repeat review cheap.
