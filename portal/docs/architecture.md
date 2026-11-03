# Portal production state

## Current state

This is the canonical production snapshot and deploy interlock for both
services on `example-portal-host`. Check it before every deploy and update it
afterward. The deployment procedure is in [DEPLOY.md](DEPLOY.md).

**Verified deploy: 2026-10-06 23:14:31 UTC (PAT-2566; PR #261; run 37544858646; source `34e482a83bc84e30aefa51a0fdd329d8ada25526`).**

- **Deployment:** the workflow succeeded. Independent on-box receipts and `/healthz` responses for portal and scan report `34e482a83bc84e30aefa51a0fdd329d8ada25526`; both report status `ok`, and both services are active/running with zero restarts.
- **Public footer:** installed `scan/templates/_site_footer.html` SHA-256 `7655cb8f58ceb4773da32995eb8aa43c187a3abc1728accc344bf5cd546ec19a` matches reviewed source. Live Chromium checked `/public/waitlist` (200), `/public/privacy` (200), `/public/scan` (503), `/public/intune-instructions` (503) and `/public/intune-upload` (503). All five rendered the canonical eight-link footer without blog links or horizontal overflow at 1280px.
- **Route boundary:** the three 503 responses retain the existing PAT-2564 upload-retirement behaviour. Waitlist was checked with GET only; no form submission or email delivery was tested. Authenticated production portal routes were not touched or live-walked for this task.
- **Review and CI:** all five PR checks passed, including the 22m23s E2E check and authenticated CI walk. A fresh NVIDIA review reported no findings.
- **Scope:** no forms were submitted, customer data or messages were changed, or environment configuration was changed. Evidence: `.claude/linear-runs/evidence/blog-removal-20261006/portal-installed-proof.json` and `scan-live-verification.json`.

### Dated history: 2026-10-06 PAT-2542 snapshot

**Verified deploy: 2026-10-06 14:20:35 UTC (PAT-2542; run 37476768486; source `ef39542bdf7fcc7bb2915fe12009f289e0c9a8fc`).**

- **What's New revert installed:** portal and scan deployment receipts and health responses match the source; both services are active with zero restarts. Installed hashes for `main.py`, `templates/base.html`, `templates/whats_new.html`, `static/css/portal.css` and `data/changelog.json` match the source. The authenticated What's New page returns 200 with 88 individual dated entries grouped by month and labelled per change. Its served stylesheet uses `?v=38a786e8d17d`, and the authenticated response matches the installed CSS. Evidence: `.claude/linear-runs/evidence/PAT-2542-revert-20261006/installed-proof.json`.
- **Production walk:** four desktop page loads across 1440px and 1280px in light and dark themes checked 23 links; the only findings were two existing low-severity pages unavailable to the read-only identity (`/local-admins` and `/software/add`, both 403). A separate authenticated 390px page load returned 200. No new route, console, layout or copy findings. CI passed all five checks, including 2,814 unit and 981 browser tests. The independent review used one owner-approved combined review across five valid NVIDIA chunks from identical-source runs; this is not a same-run review pass.

### Dated history: 2026-10-06 CVE paging snapshot

**Verified deploy: 2026-10-06 10:14:26 UTC (PAT-2454; run 37447742535; source `31a77a533c1e625a029577687eed2efac3da853a`).**

- **CVE paging installed:** both deployment receipts and local/public health responses match this source SHA. Installed `main.py` SHA-256 `dfad57156fb6e903e88f574b34eee7009637e75cc7aade65c08a2e3edf48e2bd` matches the merged source. Both services are active with zero restarts. Overview reads all findings pages within its explicit cap, including high-severity rows with no CVSS score; partial evidence does not produce an authoritative action count.
- **Production Overview walk:** the approved read-only identity loaded six width/theme combinations and checked 70 links. Its exit 1 records only the existing admin-only `/local-admins` link returning 403. Overview itself had no finding. This does not prove matching counts on the linked device view; PAT-2454 remains blocked on the grouped finding model in PAT-2459.

### Dated history: 2026-10-04 snapshot

**Verified deploy: 2026-10-04 03:31:25 UTC (PAT-2347; run 37174067792; source `3166121e741815f0efe65a83c7be5eae0e25485b`).**

- **Support and Feedback installed:** the approved workflow succeeded for the merged frontend source on `app.patched.im`. The deployment receipt matches the expected merge SHA. All 15 installed source-file SHA-256 values match; both served assets (`portal.css` and `feedback.js`) return HTTP 200 with SHA-256 values matching the deployed files. `/healthz` returns HTTP 200 with the expected SHA; `patched-portal.service` and `patched-scan.service` are active with zero restarts. The existing platform release `8c48c03256707bb19a3b15695c7a82ea5c98d416` carries the reviewed feedback intake backend.
- **Production walk:** an authenticated read-only production walk loaded `/support`, `/feedback`, `/requests` and `/whats-new` across 20 page loads at 1440px and 1280px in both themes, plus 390px for Feedback and Requests. The walker exited 1 solely because the linked admin-only `/local-admins` page returned 403 to the service identity; the touched pages had no route, console, layout or copy finding. This is read-only service-account evidence, not a real submission or named-person identity proof. No intake submissions, customer messages or admin grants have been made as part of this deployment evidence.
- **Certificate admin acceptance remains owner-blocked:** the final installed certificate flow still requires real authorised-admin upload proof. No credentials, grants or new database fixture are authorised; retain the existing owner blocker and do not claim human identity proof.
- **Public scan:** the independent public scan service remains active. Retirement was assessed only; it was neither implemented nor authorised. The public scan source remains unchanged.
- **Previous certificate-page evidence:** the authenticated read-only walk loaded `/certificates` at 1440px and 1280px in light and dark themes (four actual page loads), displaying agent-reported inventory and current expiry states. The walker exited 1 for its sole expected finding: the read-only identity received 403 from the linked admin-only `/local-admins` page. This is not a certificate-route failure; the walk did not have zero findings. `/certificates` is not phone-supported, so there is no live 390px claim. Six local synthetic browser width/theme checks remain the phone and layout evidence. The platform API release `de33f825f3ced4a6ebcc9f7caa10fe90a7eb5674` (migration 0223) was installed by run 37158837260. Staff PR #526 release `29d71c9e2ae3947b29185f216ca02afd2685acb2` was installed by run 37159489433. Existing reminder preferences are unchanged; no reminders or notifications were sent. PAT-2389 remains Blocked (comment `7aa1f284-aebf-4f7a-9770-d691063acf8d`), not Done.

### Dated history: 2026-10-02 snapshot

**Verified deploy: 2026-10-02 14:38:16 UTC**

- **Live:** `a5f58c4aae80c1926b034ce8fcbc0f7a32a9f9ac` on both
  `app.patched.im` and `scan.patched.im`; workflow
  37020638773
  completed successfully. The API's separate release
  `25547e40f9fc3fde019d7344ce704f5785ea33a8` was deployed by workflow
  36999490694.
- **Operating evidence:** both portal services are active; their local
  `/healthz` endpoints return HTTP 200 with status `ok` and the same SHA as
  their `DEPLOYED_SHA` receipts, recorded at `2026-10-02T14:38:16Z`. The
  deployed portal files match the installed source by SHA-256: `main.py`
  `6880259217ce733ed0905fb682de2eb23f3e5f44b57128e89f46c43cfccf3edf`,
  `templates/ce_readiness.html`
  `612e3e615e1cbfc7b883ead4eb67851f94be15ac9cff54cfdcdd9e48c593d29f`, and
  `data/changelog.json`
  `23fedd3cc36c89a6c360ef8e90a7a27c16b3c124631fc0093deca35d8bd96e29`.
- **Empty-tenant Overview (PAT-2366):** Robert's active admin mapping to
  BobbyG.com and successful authenticated platform reads were verified before
  the fix. The portal's empty high-risk software model was missing urgency
  counts, crashing the home page after authentication. An isolated full-page
  render using the installed code and templates reproduced that exact
  `UndefinedError` before deployment and returned status 200 (13,880 bytes)
  afterward. The fixture makes no live authenticated HTTP request and changes
  no tenant or user data; Robert's own post-release browser session has not
  been exercised here. Public `app.patched.im/healthz` also reports the new
  SHA and status `ok`. PR #232 passed all checks, including browser E2E;
  local full-suite verification passed 2,202 tests. The CE readiness evidence
  below was collected for the earlier 12:04:47 UTC release and is retained
  for that unchanged feature.
- **Cyber Essentials readiness:** the live page retains its approved
  question-to-evidence mapping and read-only platform calls. It reports
  evidence and gaps; it does not issue an estate-wide verdict or certification.
  Due dates use advisory publication plus 14 days as a conservative proxy;
  the stored evidence does not supply the vendor's actual fix-release date.
  This does not claim to close the Cyber Essentials update obligation. The page and PDF action rendered at 1440px/light,
  1280px/dark and 390px/light; the full readiness content is easiest to review
  on a larger screen.
- **PDF and walk evidence:** `/ce-readiness.pdf` returned HTTP 200 as
  `application/pdf`, with private/no-store caching and a dated attachment for
  `2026-10-02`. Its 337,901-byte response passed PDF header and EOF checks
  (SHA-256 `862dd3d4b4d7d9b388f26605307c42a8ac22f78f72a71945b69330745410d137`).
  The PDF body remained in on-box memory and its production visual layout was
  not inspected; local visual QA covered synthetic four- and 39-page reports.
  The HTML-only walk covered 12 page loads: CE readiness had no findings across
  six loads. Its one overall finding was the expected 403 for the admin-only
  `/local-admins` link under the read-only walker identity on `/software`; do
  not describe the whole walk as having zero findings. The PDF was excluded
  from that browser walk and checked separately on-box.

## Certificate expiry surface (PAT-2389, implementation contract)

`GET /certificates` reads the authenticated platform's
`GET /v1/portal/certificates` (bare array or legacy `certificates` envelope).
All viewers see source, subject, issuer, validity, fingerprint and current expiry;
only an exact fresh `admin` role can upload or manage uploaded records. Agent
observations retain safe UUID device links and have no edit/remove controls;
uploads never acquire device provenance. Unknown or malformed dates cannot
render healthy, regardless of a stale platform status or collection-time count.
The platform contract is `patched.im/contracts/portal-api.md`, section
“Customer-managed certificate expiry”.

HTML forms POST to `/certificates/upload`, `/{id}/update` and `/{id}/delete`
under `/certificates`. The bounded parser reuses the portal's same-origin and
session CSRF validation, checks actual streamed bytes against 96 KiB before
multipart parsing, and caps the one public certificate at 64 KiB. PEM must
contain exactly one certificate and no headers or other content; DER must
round-trip exactly. Private keys, mixed files, containers, invalid certificates
and reversed validity are refused before forwarding. Parsed files stay below
the multipart parser's in-memory spool limit, are closed on every parsed path,
and no raw file, parser exception or upstream error body is logged or persisted.
An empty optional browser file input means a label-only edit.
The standard multipart parser must signal completion and the envelope must end
at its closing boundary before form parsing, so an unfinished replacement file
cannot silently become a label-only edit.

The forwarded JWT is unchanged; no submitted tenant or actor field is forwarded.
The platform independently enforces tenant ownership, current administrator role,
deduplication and audit. The portal sends POST JSON with label and base64 public
certificate bytes, PATCH JSON with label and optional replacement, and DELETE
without a body. All successful writes redirect to the view with HTTP 303.
Failures use fixed text and a return link. No alert recipients or preferences
are created or changed. Local verification does not establish deployment;
the production snapshot above remains the last verified release.
