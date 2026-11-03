# Customer report and digest email wrappers (PAT-2354)

## Current inventory

Audited all `_send_email` call sites in dashboard `main.py` on 3 October 2026.
These five current report/digest paths use `report_email.render_report_email`,
`report_email_base.html` and `report_email_macros.html`:

| Sender | HTML and text templates | Data and navigation retained |
| --- | --- | --- |
| `_run_cert_digest_tick` | `cert_digest_email.{html,txt}` | Severity filter, four counts, sorted certificate fields, abbreviated device ID; `/certs?tenant_id=<tenant>` |
| `_run_stale_digest_tick` | `stale_digest_email.{html,txt}` | Threshold, count, hostname, last-seen date, stale days and sorting; `/console#tenant/<tenant>/device-health` |
| `_run_report_tick` | `report_attachment_email.{html,txt}` | Catalogue-selected PDF bytes, frequency, recipient override and primary-contact fallback |
| `_check_tenant_report_schedules` | `report_download_email.{html,txt}` | Daily/weekly/monthly/quarterly periods, existing generation request, per-recipient single-use XLSX link, 30-day expiry |
| `proxy_report_email` | `report_attachment_email.{html,txt}` | On-demand catalogue PDF bytes, explicit recipient, confirmation/audit/send-intent and dry-run refusal |

The authenticated portal has no report-mail sender in the supplied inventory;
no portal file changes are part of this patch. Public scans are no longer offered,
but their code remains live pending separate decommissioning. Read-only inspection
of the canonical portal source on 3 October 2026 identified these excluded mails;
all construct HTML and plain text inline, with no email template file:

| Excluded public-scan mail | Canonical portal source |
| --- | --- |
| Intune device estate report attachment | `scan/router.py`, `public_upload_post`, `csv_type == "devices"` branch |
| Intune application CVE report attachment | `scan/router.py`, `public_upload_post`, application branch |
| CVE scan verification OTP | `scan/router.py`, `public_scan_submit` |
| Successful CVE assessment with attachment, download and deletion links | `scan/shared.py`, `_run_public_scan` |
| CVE scan failure (timeout or generic error) | `scan/shared.py`, `_send_scan_failure_email` |

These variants have not been rebranded. Trial expiry, portal welcome, Calendly
confirmation/follow-up and operational mail remain outside this change. Legacy
Calendly copy still mentions public scans; that separate retirement issue is not
silently fixed here. PAT-2218's held PDF layout and all report-generation code
remain unchanged.

## Presentation contract

A shared fluid presentation table has a 600px maximum width, inline core styles,
an Outlook conditional fixed-width wrapper, Arial/Helvetica system fallbacks,
and no external CSS, web fonts, scripts, flex or grid. The certificate table
uses two columns with labelled details instead of squeezing six columns onto
mobile. The stale table keeps its three columns. All fields remain available;
long identifiers wrap. Semantic status words accompany colour.

Blue actions (`#2563eb`), navy (`#0f172a`), body (`#334155`), secondary text
(`#475569`), surfaces (`#f8fafc`, `#f1f5f9`) and semantic red/amber/green
(`#b91c1c`, `#a15c07`, `#15803d`) follow the pinned Brand v3 kit. Orange
(`#f5530a`) is a decorative wordmark dot, never status text or a link colour.
The supplied acceptance contract explicitly requires the older neutral paper
`#f5f5f3` and ink `#0f1115`; these are retained only for the outer email canvas
and heading ink. They are an email adaptation, not a claim that the pinned v3
kit defines those two tokens. No vendored brand tokens were changed.

The existing public 180px PNG app mark is displayed at 44px, alongside a visible
Patched wordmark and meaningful alt text. The asset, existing website copy and
pinned branding source are byte-identical. See [provenance](brand-provenance.json)
and the pre-existing `../operator-preview/evidence/brand-provenance.json`.
No SVG compatibility claim, invented URL, new website asset or staff login is
involved. An unauthenticated descriptive-user-agent GET returned PNG/200;
Python's default User-Agent returned 403. Mail proxies or recipients can still
block remote images, so the text brand and all content/actions remain readable
without the image. This is not proof of delivery or universal mail-client support.

## Copy, escaping and preserved boundaries

Subjects use `Patched | <estate> | <report/digest type> | <date or period>`.
Digests and frequency PDFs use the tick date; on-demand PDFs use the UTC request
date. XLSX schedules use the actual period start/end, not a misleading month for
a daily or weekly report. Empty, whitespace, missing and UUID-only names become
`Your estate`. UUIDs embedded in display labels, including case-insensitive
`urn:uuid:` wrappers, are removed; empty bracket/brace/parenthesis remnants are
cleaned up when a UUID was removed. Control characters
and line breaks are normalised. PDF attachment display filenames use the same
fallback; normal filenames and PDF bytes are preserved.

Jinja autoescapes every HTML interpolation, including company, catalogue and
schedule labels, hostnames, certificate fields and href attributes. Plain text
stays plain text. The helper operates only on display copy. Tenant IDs in existing
hrefs/API paths, recipient selection, attachment bytes, token ownership and
expiry, period computation, generated report-record names, send gates, retries,
audit identity and dry-run bookkeeping are unchanged. Single-use tokens are
still generated and stored by the original sender, once per recipient.

## Local verification and evidence

All captures use synthetic `Acme Estate` / `recipient@example.test`, disposable
SQLite, strict upstream stubs and a mocked `_send_email`. The suite's HTTP and
socket guard blocks provider/network access. No real tenant data, credentials,
mail ticks against production, customer sends or host mutations were used.

Commands (all final exits 0):

```sh
/opt/homebrew/bin/python3 -m pytest tests/test_pat2354_email_branding.py -q -p no:cacheprovider
/opt/homebrew/bin/python3 -m pytest tests/test_pat2354_email_branding.py tests/test_pat2354_email_safety.py tests/test_pat697.py tests/test_pat1010_email_dry_run_tristate.py tests/test_pat1847_report_catalogue.py tests/test_certs.py -q -p no:cacheprovider
/Users/example/.local/bin/ruff check --no-cache .
npm run test:console
/opt/homebrew/bin/python3 -m pytest tests/ -q -p no:cacheprovider
```

Results before the bounded review correction: acceptance **30 passed**; focused set **138 passed**;
full Python suite **2521 passed**; console **343 passed**; Ruff **passed**. Local Python is 3.14;
CI Python 3.12 remains for the parent to verify. Parent acceptance correction freezes
the fixture UTC clock at 2026-10-03, preserving every original assertion and
production date calculation. CHECK-MODIFIED: test setup only, correcting a
wall-clock dependency; the original red receipt remains 25 failed / 5 passed.
The bounded review correction added eight UUID-wrapper cases and one delimiter
preservation case. Before the production correction, all nine UUID-removal
checks failed; after it, the focused set passed **147 tests** and Ruff passed.
CHECK-MODIFIED: the supplemental `Acme () Estate` expectation was corrected to
`Acme Estate`; no original acceptance assertion or parent UTC clock fixture was
changed. The correction does not change the captured synthetic `Acme Estate`
fixtures, templates or layout, so existing render evidence remains applicable.
The full suite and console suite were not repeated for this bounded correction.
Receipts: `review-labels-red.log`, `review-labels-focused-green-final.log` and
`review-labels-lint.log` in the same local evidence directory below.

Full-suite execution kept the
SQLite database disposable but set `DASHBOARD_STATE_DIR` to this isolated
worktree because legacy PAT-572/PAT-865 fixtures create synthetic `nvd.db` beside
`scanner.py`. The initial temporary-state run failed five tests plus one teardown
network guard because those fixture paths differed. No network escaped; no
scan code or tests were changed to obtain the subsequent full pass.

[Render results](render-results.json) cover 25 intercepted Chromium cases:
five variants at 640px/360px, the same ten cases with long labels, and five
360px cases with images blocked. All passed: no horizontal overflow, minimum
non-decorative text contrast **4.794:1**, one fulfilled PNG request per normal
case, and readable text branding with images blocked. The orange decorative
dot and logo artwork are excluded from the text-contrast measure. There are no
style blocks to strip; layout and type are inline. The 12 PNGs below were
visually inspected. Browser rendering does not substitute for Outlook/Gmail
inbox verification or delivery evidence.

| Variant | Desktop 640px | Mobile 360px |
| --- | --- | --- |
| Certificate digest | [PNG](previews/cert-640.png) | [PNG](previews/cert-360.png) |
| Stale digest | [PNG](previews/stale-640.png) | [PNG](previews/stale-360.png) |
| Frequency PDF | [PNG](previews/pdf-tick-640.png) | [PNG](previews/pdf-tick-360.png) |
| On-demand PDF | [PNG](previews/pdf-on-demand-640.png) | [PNG](previews/pdf-on-demand-360.png) |
| Scheduled XLSX | [PNG](previews/xlsx-schedule-640.png) | [PNG](previews/xlsx-schedule-360.png) |

Additional proofs: [blocked logo](previews/cert-360-images-blocked.png) and
[long labels](previews/stale-360-long-labels.png).

Full local logs, exact command/exit receipts, capture HTML/text and reproducible
export/render scripts are in `/tmp/pat2354-implementation-20261003-leaf`:
`run_checks.py`, `export_previews.py`, `render.mjs`, `acceptance.log`,
`regressions.log`, `lint.log`, `console-regressions.log`, `full-pytest.log` (initial fixture mismatch),
`full-pytest-worktree-state.log`, `export-previews.log`, `renders.log` and
`render-results.json`. The render script used the already installed Chromium
headless shell build 1243 through Playwright 1.62.1, with every browser request
intercepted; only the verified PNG bytes were fulfilled. An initial installed
Chrome run did not load its image requests and was rejected, not counted as
passing evidence. No render dependency was installed or shared environment
modified.

Parent accepted the final diff after NVIDIA review and recorded adjudication.
Final full Python suite: 2530 passed; console: 343 passed; focused: 147 passed.
PR #522 passed all three CI checks and merged; approved workflow 37152766896
deployed main 840089d on 3 October 2026. Installed helper hash and synthetic
rendering of all four shared template families plus UUID fallback matched the
contract with networking forbidden and no delivery invoked. See architecture
Current state for exact operating evidence. Inbox receipt was not tested.
