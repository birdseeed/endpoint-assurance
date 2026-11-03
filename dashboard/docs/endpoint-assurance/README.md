# Endpoint Assurance documents

Templates for the paid Endpoint Assurance assessment (from £2,500, published
at patched.im/#offer, credited against onboarding within 90 days) and its
catalogue onboarding motion:

| Document | Ticket | Status |
|---|---|---|
| `report-template.md` | PAT-1299 | Written template |
| Scoping questionnaire and engagement letter | PAT-1300 | Written templates |
| Delivery runbook | PAT-1301 | Written, live dry run in progress (started 2026-09-04) |
| `catalogue-onboarding.md` | PAT-1298 | Operating contract |
| Report drafting run (`scripts/`) | PAT-1502 | Built, proven against a partial-window dry run |

A specialist fills the bracketed placeholders in `report-template.md` and
sends it as the assessment deliverable. It does not replace a scoping call -
that is PAT-1300's job.

Use `catalogue-onboarding.md` whenever the questionnaire or live estate
identifies an application that is not already covered by the Patched software
catalogue. It defines the evidence required before coverage is claimed and the
boundary between included specialist time and separately scoped project work.

Separately scoped project work itself (endpoint security review, software
governance, policy and configuration, patching strategy, automated
deployment, SCCM to Intune migration, Intune and Jamf tenant setup) is
written up in `../scoped-projects.md`.

## Report drafting run (PAT-1502)

Filling `report-template.md`'s brackets by hand is the largest single cost in
delivering a £2,500 assessment. `scripts/` turns that into a two-step,
operator-run tool - not a dashboard feature, no new route, no UI, no
scheduled job:

1. `scripts/fetch-evidence.sh <tenant-id>` pulls one tenant's evidence
   (devices, per-device apps with usage signal, CIS findings, CVE findings
   with match confidence, shadow-IT findings, standing local-admin) from the
   patched.im admin API and a read-only local-admin query, into one JSON
   bundle under `runs/` (gitignored - real tenant data never gets committed).
2. `scripts/draft-report-prompt.md` is a self-contained Claude Code prompt
   that takes that bundle plus `report-template.md` and produces a filled
   draft report, respecting the evidence limits this pack already publishes
   (a missing record is not proof of absence, a `version_unverified` CVE
   match is not a confirmed vulnerability, a launch timestamp alone is not
   proof a licence is wasted) and leaving every judgement call marked
   `[specialist input required: ...]` for the report's actual author.

`scripts/run-assessment.sh <tenant-id>` runs both steps as one command,
requiring `ADMIN_API_TOKEN` in the environment (see the header of
`fetch-evidence.sh` for how to obtain it) and the `claude` CLI on `PATH`.

Output always lands under `runs/` (gitignored), timestamped per run, so a
retainer's periodic re-review is cheap: re-run against fresh evidence, get a
new draft, never hand-edit the tool's output back into it.
