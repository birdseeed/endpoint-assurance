# API VPS deploy and current-state log: api.patched.im

Source implementation note (PAT-2004, not production evidence): migration 0204
adds durable agent release authority, canary observations/rate evidence and
append-only audit, with portal admin writes, signed channel projection, CI
stable-envelope promotion and the Graph P0 notice worker. See
[the release contract](../../contracts/agent-release-control.md). This note does
not change the live deployment snapshot below; box and 72h canary proof remain
required after deployment.

**Architecture now lives in `docs/architecture-overview.md`.** That document is
the canonical System Overview: topology, stack, trust and auth model, data
model, network posture, hosting, backup/DR, deployment process, secrets and
tenancy. This file is no longer the architecture doc. It is the running
deploy and current-state log for `example-api-host`: the `## Current state`
block below is the production snapshot rewritten on every deploy (the deploy
interlock named in both root and repo `AGENTS.md`, checked before every deploy
and updated after), and `## Built reality` is the dated provisioning baseline.
For anything architectural, read the overview first.

**Status:** Final (lifted from Draft after Go service deployed and end-to-end smoke verified)
**Build started:** 
**Build complete:**. API box on the tailnet, public SSH closed perimeter-wide, Caddy + Postgres + Tailscale healthy
**Go service deployed:**. `POST /v1/inventory` (HMAC + bearer auth) and `POST /admin/tenants` live on `example-api-host`. Two end-to-end smoke-test rows in `raw_payloads` (local + via public `https://api.patched.im`)
**Last enhanced:**. Exec-summary endpoint, full T2 compliance pipeline (52 CIS rules), tenant-rules admin API, Prometheus observability, and Restic/R2 backup all live on `example-api-host` (binary `c7b4cd7`).
**Backlog items addressed:** 4 (Multi-VPS scaling), with overlap into 1 (VPS architecture) and 8 (Network topology)

_Migrated from Notion: https://www.notion.so/35d054a759188156a19ec985ef00c4af_

---

## Current state

**Verified API deploy with explicit unknown-OS Jamf coverage: 2026-10-06**

- **Live:** workflow 37458778734, including its deploy job, succeeded for `9fc52dc9f18ba8b0fb284d8fce33b5acc56b2144` (PR #753, PAT-2539). The receipt records `2026-10-06T11:53:46Z`; migration head remains `0230_portal_invitations_and_access_audit`.
- **Installed and running:** API SHA-256 `1933a08821a1fd1c722e3422b5fc534a0b7f20dd40f45a751aba982999dc681f`, extractor `a398d408f7b3a2ec494ba084430f10307ae1712d63289d91b7759c3b17bb3fe0`, and CVE sync `35aca533cf01287b44e3b13b9574af022a5f7427db6102be1c9ede0cbf9122f7` match the downloaded artifact, receipt and installed binaries. API/extractor running executables also match; both services and the CVE timer are active. Local `/health` and `/ready` return HTTP 200. An initial probe of the nonexistent `/health/ready` returned 404; the source-defined `/ready` was then checked successfully.
- **Acceptance:** unknown, blank and whitespace-only OS values remain explicitly `os_not_reported`; they are not counted as known non-macOS. Coverage diagnostics may overlap matched serial/UDID coverage. Synthetic tests preserve retired-device exclusion and unpaged 21-column CSV exports. The real chi registration parity check covers all 123 routes; report fixtures execute 14 report types, 28 downloads, 65 GET routes and 82 requests, including roster, application, Homebrew and tooling child rows. Full gates and the canonical NVIDIA review passed, and all PR checks were green.
- **Read-only production page:** the official scoped walk loaded `/devices/jamf` across four 1440/1280 light/dark cases with successful page responses and no page/status/layout/copy/console findings. Its exit was 1 solely for source-verified linked restrictions: `/local-admins` and the service-restricted Jamf coverage PDF returned 403. PAT-2545 tracks their walker classification; the PDF was not downloaded or verified. The current page shows the connector not connected, so this is not proof of a live Jamf feed.
- **Limits:** this proves installation and the executed synthetic contracts, not a newly collected customer device or a production unknown-OS fixture. Startup still records self-service signup disabled; no production reports, memberships or device data were written.

> **Single source of volatile state.** This block is the canonical production snapshot for `api.patched.im`: current binary and what is live. Update it after every deploy. Linear issues are the coordination record for ticket work.

**Verified API deploy with bounded self-service access lists, still disabled: 2026-10-06**

- **Live:** normal workflow 37456659577, including the deploy job, succeeded for `72ffa8f57e60cc7eb9a9410902cfd48a48a95036` (PR #752, PAT-2544). The receipt records `2026-10-06T11:34:37Z`; migration head remains `0230_portal_invitations_and_access_audit`.
- **Installed proof:** downloaded artifact, receipt and all three installed files agree: API `ef555ca23736b15e4f59129be590c109232ea0c1bebcbb30ec3d7a5c58de4959`, extractor `4d1f0558e4807dc92e332d57bd1339ee03a37ef139868f3bf45e747101f2150c`, and CVE sync `f3e7b820aaef9e63cbc2f5f819171855136e0f59ed9102edff034e227bd38e89`. Running API/extractor executable hashes also agree. API/extractor and the CVE timer are active; `/health` and `/ready` return HTTP 200.
- **Contract:** access member pages default to 100 and cap at 500, with stable ordering, exact total/offset/limit and explicit page incompleteness. Disabled members remain visible. Invitations retain a separate newest-500 bound, exact total and truncation marker. Counts and lists use one read-only repeatable-read transaction. Actual synthetic 505-member/503-invitation tests, full gates, independent NVIDIA adjudication and all PR checks passed.
- **Activation:** the actual startup record is `enabled=false`. This verifies installed backend preparation, not a live enabled member-management journey. No signup flag, membership or invitation was changed. The new portal consumer is being prepared under PAT-1884 and must consume both completeness contracts; customer activation still needs its separate gates.

**Verified API deploy with self-service signup installed but disabled: 2026-10-06**

- **Live:** workflow 37449236379, including its deploy job, succeeded for `f7f92b132ead72e1099cfd1a0c5e5e2dad998be9` (PR #749, PAT-1883). The receipt records `2026-10-06T10:27:43Z`; migration head is `0230_portal_invitations_and_access_audit`.
- **Installed binaries:** API SHA-256 `ca8313083b694e022d7ad62c50892a8ffb37c263de19d295dc88ed2bc53ccc99`, extractor `88ad8d84bf47e0d6e47f0f58eaf363e22b4762c3aa80acd432c7b429ab65efe5`, and CVE sync `f89006c32ad8c483d95f172ad424601471efb1faa241c279469e5178b84c563f` match the downloaded workflow artifact, installed files and receipt. API/extractor services and the CVE timer are active; public `/health` and `/ready` return HTTP 200.
- **Activation remains gated:** the actual startup log records self-service signup `enabled=false`. PAT-1883's backend preparation is installed and verified; isolated enabled-route and migration checks do not prove a customer signup, invitation acceptance or useful report in production. The full journey remains PAT-1884, with billing, abuse controls and bounded access lists as activation prerequisites. No flag was enabled and no production organisation or invitation was created.
- **Insurance encryption evidence (PAT-2496):** the approved read-only production walk loaded `/reports/insurance-evidence` and the roster-linked Windows device page across ten width/theme loads. The pack and device page agree: two of four devices encrypted, WINDOWS11 explicitly not encrypted, one unknown. Existing CSV and PDF GET downloads both returned HTTP 200; the actual CSV and extracted PDF text carry the same corrected counts and name the device whose encryption is off. No report-generation POST or production data change was made.
- **Role restrictions remain explicit:** the Reports index and admin-only links return 403 to this identity. The touched-page walk exited 1 solely for its existing `/local-admins` link restriction, tracked separately in PAT-2545; it did not report a failure on the insurance or device page. This is not a generic Cloudflare authentication outage.
- **Other insurance answers checked:** EDR retains recognised coverage and explicit unknowns; local-admin evidence retains assessed counts; patching, unsupported software, remote access and inventory retain their stated evidence limits. MFA, email security, backups, incident response and training remain not evidenced. The current pack has no dedicated firewall question.

**Historical verified API deploy with nullable device fields handled in reports: 2026-10-06**

- **Live:** deploy workflow 37437568812 and its deploy job succeeded for `67c54698ff25afdfc02d89b7d8c98d0bbe57c753` (PR #746, PAT-2538). The receipt records `2026-10-06T08:46:17Z`; migration head remains `0228_audit_ledger_purge_redaction`.
- **Installed binaries and runtime:** API SHA-256 `ada0fe0625bd1d56b4618067ed238b830e37fa839326721643092d9271d17eff`, extractor `91fe46140836b2d79badaf0bc44ab65c10a88fbeb4b5d854213fd1736414779d`, and CVE sync `0e39b7757529a701533a7b92ecd7059fbca849be02f947364b71b0a12c341eb3` match the on-box receipt. API/extractor services and both CVE timers are active. Public `/health` and `/ready` return HTTP 200.
- **Acceptance scope:** disposable database tests generated all 14 report types and read all 28 downloads; the production-router test covered 63 GET routes and 80 requests. No reports were generated in production. A fresh combined-code run after the following sign-up rebase covered 65 routes and 82 requests locally. Unknown-OS Jamf classification and child-row coverage remain PAT-2539; the local audit-role test mismatch is tracked in PAT-2541.
- **Portal evidence limitation:** the intended read-only service identity currently receives HTTP 403 at the Cloudflare edge. The report fix's deployment is hash-proven, but this run cannot claim an authenticated production report walk.

**Historical verified API deploy with the alert join bound to its tenant: 2026-10-06**

- **Live:** deploy workflow 37429954116 succeeded for `1025e6e55f19e4208e8d0d7a78c64bf48c949757` (PR #745, PAT-2442), and its deploy job ran. The installed receipt records `2026-10-06T07:35:56Z`; migration head is unchanged at `0228_audit_ledger_purge_redaction`.
- **Installed binary and services:** the API and extractor are active with zero restarts; `/health` and `/ready` return HTTP 200. The installed API binary contains the new join predicate (`a.tenant_id = ad.tenant_id`, read with `grep -ac`). The extractor and CVE sync hashes were not re-read in this check.
- **Behaviour:** at about `07:40Z`, through the portal as the read-only service identity, tenant zero's own alerts (`/software/alerts/1` and `/2`) returned 200 and ids that do not exist (`/3`, `/999999`) returned 404. Production holds alerts for one tenant only, so another tenant's id could not be requested live; that case is proven by `TestSoftwareAlertForeignIDIsIndistinguishableFromAbsent` in CI, which fails when either tenant filter is removed.
- **Retained limits:** unchanged from the entries below. Alert and device-list entry ids are still one global sequence (PAT-2535).

**Historical verified API deploy with the version sprawl reference rules and one encryption-state definition: 2026-10-06**

- **Live:** deploy workflow 37423153696 succeeded for `4c40e77ffa9f0dcc7957e831c5661cf05a866bfb` (PR #743, PAT-2509, and PR #744, PAT-2496), and its deploy job ran. The installed receipt records `2026-10-06T06:26:39Z`; migration head is unchanged at `0228_audit_ledger_purge_redaction`. An earlier run for #743 alone, 37392861754 at 00:13Z, was refused by the deploy script because the nightly `patched-cve-sync` run was in progress (it starts at 00:03 UTC). That refusal is the guard working: nothing was installed, and the box stayed on `c1a705e` until this run.
- **Installed binaries and services:** the running API executable hash `e5739b4fb2f5dba8bd576a49347360e222208f09b301745d1cc3fe83258ba576` and extractor hash `b2a42d0bb9f50c9d7e4c96d4d250247b743bbaadbad3412f8cb1e6e9e8a79369` match the receipt. Both services are active with zero restarts; `/health` and `/ready` return HTTP 200. The CVE sync binary on disk was not hashed in this check.
- **Version sprawl reference (PAT-2509):** at about `2026-10-06T06:32Z` the tenant zero CSV, fetched through the portal as the read-only service identity, carried the appended `latest_released_checked_at` column and no occurrence of `curated_catalogue`. Of 272 products one had a reference: Firefox on macOS, `157.0` from endoflife.date, checked `2026-10-06T00:52:35Z`, against `151.0.4` installed. Chrome, zoom.us, Excel, Word and Microsoft Teams on macOS, which previously showed a stale or wrong figure from the frozen list, showed none.
- **Encryption state (PAT-2496):** at the same time the tenant zero insurance evidence page read "2 of 4 devices (50.0%) report FileVault or BitLocker full-disk encryption turned on. 1 device reports encryption turned off. Encryption is turned off on: WINDOWS11. 1 device is unknown (1 reported no encryption state) and is not counted in your favour." Before this deploy it reported both Windows devices as unknown.
- **Retained limits:** unchanged from the entries below. The other readers of `app_catalog_entries` still match on signer alone (PAT-2533).

**Historical verified API deploy with the trial provisioning rate limit: 2026-10-05**

- **Live:** deploy workflow 37388041017 succeeded for `c1a705e96d904ff93c9bd15931e626603acbfdfd` (PR #742, PAT-2529), and its deploy job ran. The installed receipt records `2026-10-05T23:27:00Z`; migration head is unchanged at `0228_audit_ledger_purge_redaction`.
- **Installed binaries and services:** receipt SHA-256 values are API `952d5e71e3b5ec846e8b9928a55a8e84b0b5cf0c169356846eaca64d3370a561`, extractor `2ed8e3661331b143c007bbd5ccac7ba924b90351ab0a0d897d88a1dc2889440b`, and CVE sync `1d13f8b89a941063c94901f3827b4f3a1dc0cfac32d234548e3e95192a46d239`. The running API and extractor executable hashes match the receipt. Both services are active with zero restarts; `/health` and `/ready` return HTTP 200. The CVE sync binary on disk was not hashed in this check.
- **Trial provisioning rate limit (PAT-2529):** at `2026-10-05T23:48:58Z`, seven requests with an empty JSON body were sent to `POST /v1/trial/provision` on `api.patched.im` from one address. The first five answered 400 (validation, each counted against the limit) and the sixth and seventh answered 429 with `Retry-After: 719`. No tenant can be created by an empty body, and none was. Both limits are at their defaults (5 an hour per client address, 30 an hour for the route); no `TRIAL_PROVISION_*` variable is set on the box.
- **Still open on that route:** it remains public and unauthenticated, and for an email that already has an active trial it mints an enrolment token without proving the caller owns the address. Production has never held a trial tenant (zero rows, counted read-only on 2026-10-05). Switching the route off is an owner decision recorded on PAT-2529.
- **Retained limits:** unchanged from the entries below.

**Historical verified API deploy with device identity endpoint: 2026-10-05**

- **Live:** deploy workflow 37381595466 succeeded for `955f0ada1ba4dd391d72c37fc95edc06d3d9c3a7` (PR #741), and its deploy job ran rather than being skipped. The installed receipt records `2026-10-05T22:24:42Z`; migration head is `0228_audit_ledger_purge_redaction`. It replaces run 37363471188, which never got a runner during the GitHub Actions outage of 5 October and deployed nothing (PAT-2528). That run still shows as a failure in the run list; it was not re-run, because a re-run would only redeploy the same commit.
- **Installed binaries and services:** receipt SHA-256 values are API `4ca4c9b7b9562df6b54fe4aefc3f5c31145cd039eb79b5867f94f7cc8dc90f03`, extractor `b6f9b30ae51d271275f641dd52e52868ffa191433f1c7b3fc5682bd062bb9a01`, and CVE sync `fe47d1b888e1e52338b48b7a37f843e2155c0d07d45f6cfa2cc44a4f987cc0a6`. The running API and extractor executable hashes match the receipt. Both services are active with zero restarts since `2026-10-05T22:24:37Z`; `/health` and `/ready` return HTTP 200. The CVE sync binary on disk was not hashed in this check and no sync by it has been measured.
- **Device identity endpoint (PAT-2424):** at about `2026-10-05T22:26Z` an unauthenticated `GET /v1/device/identity` on `api.patched.im` returned HTTP 401. It returned 404 at 21:45Z, before this deploy, and a route that does not exist still returns 404. This shows the route is served. It does not show that an agent can use it: the agent half of PAT-2424 is unmerged and unproven on a device.
- **Gap in this block:** the deploys between the 4 October entry below and this one were not written up here. They are in the run list (`gh run list --workflow deploy-api-01.yml`), and the migration head moved from `0223` to `0228` across them. Treat the entry below as history, not as the state before this deploy.
- **Retained limits:** unchanged from the entry below.

**Historical verified API deploy with service exceptions endpoint: 2026-10-04**

- **Live:** deploy workflow 37164336269 succeeded for `8c48c03256707bb19a3b15695c7a82ea5c98d416` (PR #723). The installed receipt records `2026-10-04T00:19:46Z`; migration head remains `0223_manual_certificate_expiry`.
- **Installed binaries and services:** all three installed binary hashes match the receipt: API `de3b0287911954eb26284ad60de9285c155893d57908588ee8694b80cec4f0e3`, extractor `f99f833588e287d195e6d9459376c307ac05b9d8963700865bbe7c04b4a91a71`, and CVE sync `f6934f24a6d502327997e085e1063b15652dfdcf244d615331a73fcfc3386f50`. Running API and extractor executable hashes match. Both services are active with zero restarts; `/health` and `/ready` return HTTP 200. The CVE one-shot is inactive/dead and its timer activation succeeded; a full sync by the newly installed CVE binary has not been measured.
- **Service exceptions API:** at `2026-10-04T00:29:49Z`, `GET /admin/service-exceptions` returned HTTP 200 with `Cache-Control: no-store`. The response covered 11 categories with partial coverage and one stale active-customer device-receipt exception. It does not establish that every service is healthy: several sources remain unavailable, and the exception onset and next-due time are null. No tenant or customer identifiers are reproduced here. This is API operating evidence only; PAT-1966's full frontend remains unimplemented, pending the PAT-2373 operator-console chain.
- **Certificate boundary:** all three components are now deployed with the certificate changes. Staff deploy workflow 37159489433 and portal deploy workflow 37162108252 succeeded; seven installed portal-file hashes and four rendered read-only `/certificates` pages across desktop widths and themes were verified. Final real admin upload, replacement and removal audit remains owner-blocked under PAT-2389; this is not full-ticket completion. PAT-2347 remains portal implementation in an unshipped worktree, not done or installed.
- **Retained limits:** PAT-2379's real disabled-membership proof remains pending; PAT-2380 remains explicitly paused. Public scan retirement is assessment only, with no implementation or shutdown. Existing backup-restore, endpoint-rollout, report-delivery and customer holds remain unchanged.

**Historical verified API deploy with certificate metadata schema and feedback support/design types: 2026-10-03**

- **Live:** normal deploy workflow 37158837260 completed successfully for `de33f825f3ced4a6ebcc9f7caa10fe90a7eb5674` (PR #704 feedback support/design schema and PR #721 admin-uploaded public certificate metadata). The on-box receipt records `2026-10-03T22:38:28Z`, with migrations `0222_feedback_support_design_types` and `0223_manual_certificate_expiry` at the head. Read-only schema inspection confirms both certificate tables, their columns, indexes, foreign keys and constraints.
- **Installed binaries:** receipt SHA-256 values are API `9d7b3b7003ad5f081c345a6ef8185602dfb715d31c3589a90d5eafb90179260d`, extractor `4bf5665f5b1481ca63385b638d43ad3b16d33b0861e2a4f1c2c5342b9cc1d365`, and CVE sync `eb20d16de9827503f6a76b8a1420c257720907b0394374cf9433cd87fa9043f0`. The running API and extractor process executables match their receipt hashes. API and extractor services are active with zero restarts since `2026-10-03T22:38:23Z` (23:38:23 BST); `/health` and `/ready` both return HTTP 200. The CVE timer is active and waiting; its latest full sync completed successfully at `2026-10-03T00:19:05Z`, before this installation. No full sync by the newly installed CVE binary is claimed.
- **Feedback contract:** live schema permits types `bug`, `feature`, `question`, `support` and `design`; support categories are `not_working`, `findings_or_reports` and `account_billing`. Category is required for support and forbidden for other types. Severity is required for bugs and null for the other types. These are database constraints, not proof of the complete customer-facing workflow.
- **Certificate boundary:** migration 0223 stores tenant-scoped public certificate metadata and metadata-only audit history. It does not establish that the admin upload operating flow has been exercised; do not claim that flow is operationally verified. PR #235 portal CI is running and staff PR #526 deploy workflow 37159489433 completed successfully; installed staff readback is being verified. Customer-facing portal deployment/use is not established. PAT-2347's portal forms are not yet implemented; do not describe the full ticket as done.
- **Retained limits:** PAT-2379's real disabled-membership denial proof remains pending. PAT-2380 remains explicitly paused. Backup restore, endpoint rollout, report delivery and customer holds remain unresolved; API installation does not prove them.

**Historical verified API deploy with disabled-membership proof pending: 2026-10-03**

- **Live:** workflow 37150447411 completed its `deploy` job successfully for `fe4cce4ff3dc2ee72c2b33e67535622a2ca2da39` (PR #719, PAT-2379). The receipt records `2026-10-03T20:13:52Z`, migration `0221_app_usage_evidence`.
- **Installed provenance:** API SHA-256 `31147f8ec3098762ff40518e37e9b9b226a80e20a9fd181221fc04a0a3d63809`, extractor `2fa0d53ca7b38408107933dcdc018f4ef5a6a1caf0bd677d6edd8292f466c5ab`, CVE sync `d1c89346bea6e505e23d0e65dd736267958fbc5461040bac09a8dc0958d87a5c`. All match the receipt. Actual running API and extractor executables match; build metadata on all three names the deployed revision. Extractor path is `/opt/patched-extractor/bin/patched-extractor`.
- **Service evidence:** read back at `20:23:12Z`; API and extractor active since `20:13:46Z`, `/health` and `/ready` both HTTP 200. CVE timer enabled and active; latest scheduled CVE execution completed successfully at `00:19:05Z`, before this installation. No fresh full CVE execution of the newly installed binary is claimed.
- **Security boundary:** retained explicit portal memberships, including disabled or revoked mappings, now fail closed before domain fallback. Fresh owned synthetic PostgreSQL denial/data-isolation and DB-error tests passed, with independent NVIDIA review. A real controlled identity's deployed denial remains unverified; PAT-2379 stays open. No production membership, tenant, credential or customer data was changed for verification.
- **Retained limits:** endpoint rollout, customer report delivery and isolated real-backup restore are not established by API binary installation. PAT-2380 remains explicitly paused. Earlier application-usage observations below are dated historical evidence, not a fresh endpoint readback.

**Historical verified API deploy with agent-rollout and portal limits: 2026-10-02**

- **Live:** normal deploy workflow 36999490694 completed its deploy job successfully for `25547e40f9fc3fde019d7344ce704f5785ea33a8`. On `example-api-host`, the receipt records that SHA at `2026-10-02T11:16:49Z` with `MIGRATION_HEAD=0221_app_usage_evidence`. All three installed binary hashes match the receipt: API `75a88bb96f1c3aa82e5c58bff5941412fb572f57fb625a59e33810a3bf2a0d01`, extractor `82d44a63805a8a1af0308d691a8ed004de2b5bc7cc8843a1966f9823e08ea86f`, and CVE sync `4ea8467b17d9e091af1afd09866e7ff0166997c3a5901bc28b2a661df7ea413c`. Migration 0221 is present; API and extractor are active, the CVE timer is active, `/health` returns 200, and the full CVE activation succeeded at `11:49:41Z`.
- **CVE execution:** the latest scheduled execution started at `11:19:01Z`, finished successfully, and left the one-shot inactive/dead with its timer active. OSV completed at `11:49:39Z` with 2 inputs, 2 package queries and 2 advisories; no pipeline failure was recorded. The separate missing `LINEAR_API_TOKEN` digest soft failure remains PAT-2138; no secret was changed.
- **Application usage:** schema and platform support are live, but rollout to endpoint agents is not established. The tenant readback has 105 apps and all 105 report usage as not reported; this does not prove whether an agent version was installed or why evidence is absent. Do not turn zero usage evidence into an unused-software conclusion. The installed binaries prove server deployment only, not an agent rollout.
- **Freshness evidence:** the actual source query found 105 installations, 2 unused and 0 stale (including 0 stale-but-unused). Fifteen synthetic truth cases passed; they validate predicate arithmetic only, not production endpoint behaviour.
- **Portal boundary:** this API deploy installed the reviewed Cyber Essentials evidence PDF source at `25547e40f9fc3fde019d7344ce704f5785ea33a8`, but this API receipt alone does not prove customer PDF delivery or the complete product flow. At the 11:51 UTC API verification boundary, portal installation and PDF response proof were still pending; subsequent portal deployment evidence belongs in its own production snapshot.
- **Recovery history:** the first two 2026-10-02 attempts, workflows 36981305524 and 36989396286, installed binaries but failed CVE activation (the first hit the inherited OSV wire HTTP 400; the second hit MSRC HTTP 503 after bounded retries). They were partial deployments, not accepted successes. Workflow 36999490694 supersedes them. The previous fully activated release `d075adc00f1d75b3df35bad21200a85afa10d361` is historical, not the current release.

**Verified deploy: 2026-09-30 21:57:55 UTC (PR #703 PAT-2318)**

- **Live:** `d075adc00f1d75b3df35bad21200a85afa10d361`; workflow 36782085152 completed its deploy job successfully. `MIGRATION_HEAD=0220_compliance_customer_copy`.
- **What changed:** eight exact shipped compliance descriptions no longer expose internal tracking references. Private migration provenance preserves rollback ownership; custom descriptions, rule identity, assessment semantics and evaluation history are unchanged. Tenant-owned software justifications are outside this migration.
- **Operating evidence:** all three installed binary hashes match `/opt/patched-api/DEPLOYED_BINARIES`: API `213eb187ae9223a845351821d53fbcd8f90667fe49863233bd6d0f5f9cad9084`, extractor `4e2ea3870cdb97f25dbe17f7fc33760167fd830dd82d771c382bda9b5fb978d9`, CVE sync `20ec600ed4d87a5e145772a4f3d3221d41b74c5883eb64a6320eecf16bca3972`. API/extractor and CVE timer are active; health returns 200. The workflow's enforcing schema-drift check passed before migration. All four live device compliance sections return 200 and contain no internal ticket, PAT-number or backfill references.
- **Retained OS evidence:** explicit collected OS-update verdicts take precedence over legacy pending-update lists in device status, Overview and executive totals. Unknown or stale verdicts remain unconfirmed. The authenticated Overview response and portal agree on 2 current, 0 pending, 0 failed and 2 unknown devices. A fresh executive report generated at 20:06 UTC records 2 current, 0 pending, 0 failed and 2 not reported, with its aggregate legend parsed on the host. This proves evidence handling, not vendor latest-version availability.
- **Portal boundary:** portal deployment and customer changelog evidence belong to its own production snapshot; do not infer them from the API receipt.

**Deploy: 2026-09-30 (run 36707394929)**

- **Live:** `45bcbf8b242aab07204ff3b12c13d93bf3e02156`, deployed at `2026-09-30T11:21:27Z`; `MIGRATION_HEAD=0219_lifecycle_publish_browser_mappings`.
- **Operating evidence:** `patched-api` and `patched-extractor` are active and `/health` returns 200. SHA-256 receipts match the installed binaries: `patched-api` `ebbabc87312043c16abcd651181feb41d86ac74a378489e9668a73f2816ac84a`, `patched-extractor` `8f1d13caa82085a3bca4be48d92cce8ba452ba67715e287037427fe3597ebe9e`, and `patched-cve-sync` `ce02436db9233e5d45f6ce2f3cef4cbabb4d2d41a590e11b2f933223c39afe4c`.

**Deploy: 2026-10-05 evening (PR #737: PAT-2403 audit ledgers redacted on tenant purge)**

- **Live:** `bb884afd64a32d284e9a2a8a629325201ce05da1` (deploy run `37354205122`), deployed at `2026-10-05T18:18:37Z`. `MIGRATION_HEAD=0228_audit_ledger_purge_redaction`, authorised by Andy the same day.
- **What changed:** migration `0228` adds a `BEFORE DELETE` trigger on `tenants` that redacts the purged tenant's rows in seven audit ledgers and stamps `tenant_purge_anonymized_at`. No existing row was rewritten.
- **Operating evidence:** the trigger is enabled and the marker column is on all seven tables. A throwaway-tenant purge committed; its `tenant_shadow_it_policy_changes` row was kept with `claimed_actor`, `source_addr` and `reason` nulled, no other tenant's row was marked, and an UPDATE on the redacted row is still refused. **Not proven in production:** the other six ledgers, which are covered by integration tests only. The tables this does not cover are in PAT-2419.

**Deploy: 2026-10-05 midday (PR #738: PAT-2408 internal admin listener requires the Bearer scheme)**

- **Live:** `8748f62ce0b2d090591d0f9a3b085c478d50755e` (deploy run `37298411909`), deployed at `2026-10-05T10:49:59Z`. `MIGRATION_HEAD` unchanged at `0227_report_records_csv`.
- **What changed:** `requireInternalToken` no longer accepts the admin token without the `Bearer` scheme. The scheme is matched case-insensitively and followed by exactly one space.
- **Operating evidence:** `DEPLOYED_BINARIES` records the SHA above; service active with no error-level lines. On the live internal listener a bare token, a wrong token, `Basic` and no header answer 401; `Bearer <token>` answers 200. No 401 on `/admin/*` from the console since it was redeployed. PAT-2410 was also proven the same morning by a throwaway-tenant purge (report directory removed, quarantine empty).

**Deploy: 2026-10-05 (PR #734: PAT-2410 tenant purge removes generated report files)**

- **Live:** `81e8fcf098c2f588c882be0691fb7fa0e95e6abb` (deploy run `37247485898`). Two earlier runs were refused by `deploy.sh` because `patched-cve-sync` was due, then running; wait for that service to finish before deploying around 00:00 UTC. `MIGRATION_HEAD` unchanged at `0227_report_records_csv`.
- **What changed:** the purge quarantines `<REPORT_STORAGE_ROOT>/<tenantID>` (generated report PDFs and CSVs) with the same quarantine, restore and post-commit removal as assessment artefacts.
- **Operating evidence:** `DEPLOYED_SHA` matches; service active with no error-level lines; the storage root holds two tenant report directories, both for live tenants (no orphans). **Not yet proven in production:** no tenant has been purged since this deploy.

**Deploy: 2026-10-04 late (PR #733: PAT-2407 enrolment token admin only; PR #732: PAT-2405 list export PDF renderer)**

- **Live:** `c9d01e2d68315e226afab090b316302fe4fbf34d` (deploy run `37241780010`; `49b9c54f` went out first in run `37237964110`). `MIGRATION_HEAD` is unchanged at `0227_report_records_csv`.
- **What changed:** (PAT-2407) `POST /v1/portal/enrolment` requires the portal admin role, re-read inside the transaction that inserts the token; a non-admin gets 403 `admin_role_required` and writes nothing. (PAT-2405) `POST /v1/portal/exports/table-pdf` renders a table the portal posts as a branded PDF: 16 allow-listed exports, tenant from the identity only, stores nothing, every role except `local-admins` (admin only). It is the one non-GET portal route a viewer may call.
- **Operating evidence:** `DEPLOYED_SHA` matches; services active with no error-level lines. The boundary harness, re-run on these commits, shows viewer and domain-fallback callers refused on the enrolment route and the table render answering for viewer and admin. **Not yet proven in production:** no list PDF has been rendered by a signed-in person (the read-only service identity is refused on every non-GET, so it cannot), and no viewer account has posted to the enrolment route.

**Deploy: 2026-10-04 evening (PR #731: PAT-2075 legacy user-located app hold; PR #730: PAT-2405 report CSV; PR #729: PAT-2367 boundary harness, no product code)**

- **Live:** `157dd96c6d46fe58a041d495de2e889b36247a8f` (deploy run `37233989701`). `MIGRATION_HEAD` is `0227_report_records_csv`.
- **What changed:** (PAT-2405) every generated report also stores a CSV built from the same data as its PDF; `GET /v1/portal/reports/{id}?format=pdf|csv`; history entries list `formats`; `report_records.csv_path` and `csv_sha256`. (PAT-2075) `collection_status.apps_users[].home` is accepted; a machine-scope app row located in a user's home is held until that user reports, re-homed when listed under the user, pruned only under the owner's complete authority; held rows are counted in the run's coverage. Reports without `apps_users` are unaffected.
- **Operating evidence:** `DEPLOYED_SHA` matches; `0227` recorded and both columns present; services active with no error-level lines; the 33 existing report records have no CSV, as expected. **Not yet proven in production:** no report has been generated since the deploy, so no CSV exists yet; no agent sends `apps_users[].home` yet. The agent half of PAT-2075 (updater#702) must not be released before this deploy, which it now follows.

**Deploy: 2026-10-04 later (PR #728: PAT-2404 staff review of observed software identities)**

- **Live:** `1813d524939400051873676e7c26be376c2cee1e` (deploy run `37220888780`). `MIGRATION_HEAD` is `0226_software_catalogue_review`.
- **What changed:** internal routes `/admin/software-catalogue/{candidates,aliases,reviews}` and `/aliases/{id}/retire` let staff promote an identity devices report, with signing evidence, into a reviewed catalogue alias and withdraw one. `software_product_aliases.retired_at`, the append-only `software_catalogue_audit`, and `effective_tenant_app_policies` replaced by the 0224 body plus one exclusion for approvals declared through a retired alias. A reviewed alias resolves installations for every tenant on their next report.
- **Operating evidence:** `DEPLOYED_SHA` matches; `0226` recorded; services active with no error-level lines; the candidates route answers 401 without the admin token on `:8081` and 404 on `:8080`; with the token it lists 135 macOS and 58 Windows candidates, 60 and 23 promotable; tenant zero's effective policy count is unchanged at 7. **Not yet proven in production:** no identity has been reviewed, so `software_catalogue_audit` is empty and the portal lookup still returns nothing.

**Deploy: 2026-10-04 (PR #727: PAT-2393 software declarations; PR #726: PAT-2380 purge redaction of the software alert ledger)**

- **Live:** `27cb110ac8620c4bcbc1b602723377552b51ab1b` (deploy run `37205563794`); PAT-2380 shipped first as `16f2f34ddd65a5ce7eba31fc95cf3d538f3f3963` (run `37203613592`). `MIGRATION_HEAD` is `0225_software_alert_purge_redaction`; `0224_software_declarations` was applied after it and is recorded. Deploys between 2026-09-30 and this one were not written up here; `DEPLOYED_BINARIES` on the box and the Actions run list are the record for those.
- **What changed:** (PAT-2393) tenant admins can declare approved software before any device reports it: `tenant_software_declarations`, the append-only `software_declaration_decisions`, and `effective_tenant_app_policies(tenant)`, which every policy reader now goes through; new `/v1/portal/software-products` and `/v1/portal/software-declarations` routes. (PAT-2380) a `BEFORE DELETE` trigger on `tenants` nulls `actor` and `note` in `software_unapproved_alert_transitions` for the purged tenant, inside the purge transaction.
- **Operating evidence:** `DEPLOYED_SHA` on the box matches; `schema_migrations` holds both `0224` and `0225`; `patched-api` and `patched-extractor` active with no error-level log lines after restart; the two new portal routes answer 401 unauthenticated; `trg_tenants_redact_software_alert_before_purge` is enabled and the ledger's 5 rows are unmarked. **Not yet proven in production:** no declaration has been created by a real admin, and no tenant has been purged since, so the redaction trigger has not fired (PAT-2393 and PAT-2380 are held open for that).

**Deploy: 2026-09-30 later (PR #698: PAT-2312, patched is a service account with no login or sudo; ACL #697)**

- **Live:** `df846f5b3e020020da750448129f21adb659dbf9` (deploy run `36692462853`).
- **What changed:** `deploy/api-01/service-account-hygiene.sh` runs `apply` then `check` on every deploy, piped from the runner. **`patched` is the API's service user only.** It has no sudoers rule and no admin group, its shell is `nologin`, and it has no SSH key. The tailnet ACL (#697) admits admins over Tailscale SSH as `root` only. **Admin access is `ssh root@example-api-host` and nothing else.**
- **Operating evidence:** `apply` removed `/etc/sudoers.d/patched`, the `sudo` membership, the key files and leftover session artefacts, and set the shell to `/usr/sbin/nologin`. Then `check` reported `ok`. `sudo -l -U patched` says it is not allowed to run sudo. `patched-api` logged `df846f5`, `NRestarts=0`, and `/health` returns 200.

**Deploy: 2026-09-30 (PR #694: PAT-2310 root-owned deploy files and ownership guard, deployed through the normal workflow)**

- **Live:** `56888e4203e874714598fab9cc3ece83bf16c52b` (deploy run `36655041665`). `MIGRATION_HEAD` is unchanged at `0219`. Later merges (#693 PAT-2296 and #695 PAT-2313/2312) are a test change and a prod-01 backup change, so neither needs an api-01 deploy.
- **What changed:** every rsync to a root-run path passes `--chown=root:root`. A Reclaim step fixed the two files placed after the first check. `deploy/api-01/deploy-ownership-guard.sh` runs from the runner before anything root executes and again after every file is placed. **A deploy now fails if a root-run path under the checked trees is a symlink, owned by an orphan or non-root uid, or group/other-writable.** There are two exceptions: `create-partitions.sh` (owned and run by `patched`) and the legacy `patched-extractor.bak-*` files.
- **Operating evidence:** both guard runs logged `ok`. `find ... -uid 1001` over the checked trees and `/etc/apt/apt.conf.d` returns 0 (it was 5, including the apt drop-in `52-automatic-reboot.conf`). `patched-api` logged `56888e4`, `NRestarts=0`, and `/health` returns 200.

**Deploy: 2026-09-29 night (PRs #686-#692: PAT-2290, PAT-2294, PAT-2246, PAT-2171, PAT-2295, PAT-2303, PAT-2249; five deploys through the normal workflow, 17:02-23:02 UTC)**

- **Live:** `fe6039f20360ff99b9a4cc968c89841b40b9e7cd` (deploy run `36642969780`). Earlier runs in the sequence deployed `d9434d0`, `b771cac`, `b498888`, `7cba217` and `f0a6288`, each read back on the box. `MIGRATION_HEAD=0219_lifecycle_publish_browser_mappings`.
- **What changed:** the maintenance-facts unit is classified in the hardening ceilings (PAT-2290). The portal gets the Windows OS-update verdict and device summary (PAT-2294). The signed catalogue is retired in the platform: the catalogue routes return 410/404 and the publish route, token reader and rollout readers are gone (PAT-2246, PAT-2249). A rolling-release lifecycle rule ships, and five browser CPE mappings are published (PAT-2171, migration 0219). The staff OS-update rollup counts only real verdicts as behind (PAT-2295). The duplicate-tools caveat is written as customer copy (PAT-2303).
- **Operating evidence:** the running `patched-api` logged `fe6039f` at start. `patched-api` and `patched-extractor` are active with `NRestarts=0`, and `/health` returns 200 (read back 2026-09-30 00:20 UTC). Still open, and not part of this deploy: removing `CATALOGUE_PUBLISHER_TOKEN` from `/etc/patched-api/env` (PAT-2246) and dropping the retired catalogue tables (PAT-2248/2249) are Andy's.

**Deploy: 2026-09-29 evening (PR #685: PAT-2287 revoke and list unused enrolment tokens, deployed through the normal workflow)**

- **Live:** `53ef18edd9dfd634426c15926ab72e84708957d5`. Deploy run `36601226079` ran its real `deploy` job successfully. The running `patched-api` logged that SHA at start (18:01:20 BST). `MIGRATION_HEAD=0217_bootstrap_token_revoke`, and `schema_migrations` agrees. Two deploys earlier the same day (runs at 08:31 and 10:55 UTC) are not itemised here.
- **What changed:** `POST /admin/tenants/{tenantID}/bootstrap-tokens/{tokenID}/revoke` and `GET /admin/tenants/{tenantID}/bootstrap-tokens` on the admin listener. `/v1/enrol` refuses a revoked token exactly as it refuses an expired one. Migration 0217 is additive: `bootstrap_tokens.revoked_at`, plus `enrollment_token_audit.action` and `.actor` with checks.
- **Operating evidence:** `patched-api` and `patched-extractor` are active with `NRestarts=0`, `/health` returns 200, and there are no post-deploy warnings. The list route returns 401 without the admin token and 200 with it, and never returns a hash. The first live revoke is pending on PAT-2287.

**Deploy: 2026-09-27 (PR #651: PAT-2169 CVE queue retry and tenant observability follow-ups, deployed through the normal workflow)**

- **Live:** `6cd0dd18b257c5b0f11beba87af75bff88f042cd`. Deploy run `36286960111` completed its real `deploy` job successfully. `MIGRATION_HEAD=0203_drop_redundant_cve_match_queue_tenant_index` and the migration receipt agree.
- **What changed:** mapping-publish re-expansion now preserves an existing observation's retry count and last error, so permanently failing rows can reach and remain at `MaxAttempts`; direct inventory refresh still resets retry state. Queue-cap refusals now have a tenant-attributed counter, and Prometheus evaluates a per-tenant oldest-age alert using the existing 30-minute threshold and two-minute hold. Migration 0203 removes 0161's tenant-only partial index after production-shaped integration coverage proved the 0194 composite index covers capacity, metrics, tenant-walk and ordered-drain access paths; rollback restores the exact 0161 definition.
- **Operating evidence:** read back from `example-api-host` after deploy. The exact merge SHA is installed, the old tenant index is absent, and `idx_cve_match_queue_tenant_order (tenant_id, enqueued_at, id) WHERE kind = 'observation'` is present. `/health` is OK; API and extractor are active with zero restarts; the completed CVE sync has zero restarts and its timer is active. The post-deploy error journal is empty. Prometheus accepted `CVEMatchQueueTenantBacklog` and reports it healthy and inactive. The queue is empty, so no per-tenant metric series exists yet; that absence is expected until a tenant experiences a cap refusal or backlog.

**Deploy: 2026-09-27 (PR #655: PAT-2035 portal feedback, deployed through the normal workflow)**

- **Live:** `daff11dec0c178e44a47b9feb048dfb5e22dfcca`. Deployment workflow run `36316109190` completed its actual deploy job successfully at `2026-09-27T11:39:15Z`. Migration head is `0206_portal_feedback`.
- **What shipped:** canonical `GET`/`POST /v1/portal/feedback`, with the portal feedback table, constraints, indexes and grants verified on-box. `FEEDBACK_ENABLED` is absent and therefore defaults to `false`; `LINEAR_API_KEY` is present. The route remains disabled by default until the feature gate is deliberately enabled.
- **Operating evidence:** `patched-api` and `patched-extractor` are active with `NRestarts=0`; `/health` is OK; there are no recent warnings. The same-day R2 database backup was verified. PR CI, PostgreSQL acceptance and fresh integration tests, independent non-author review and the security scan all passed.

**Deploy: 2026-09-22 evening (PRs #574-575: PAT-1984 deterministic CVE-tables test fix, PAT-1985 deploy.sh EXIT trap binary rollback; deployed through the normal workflow)**

- **Live:** `2de8a3b2fde2346d15e3b8e8fe40a327a28b476f`. Deploy run `35759743567` succeeded, all jobs green. `MIGRATION_HEAD=0160_local_admin_pii_and_windows_rule`, unchanged — neither ticket in this deploy carries a migration.
- **What changed (PAT-1984):** test-only fix, `TestFetchPortalCVEFindingsPage_TablesNotMigrated` (report + handlers) now uses a schema-only search_path so it deterministically exercises `isUndefinedTable` regardless of what has run against `public` earlier in the same test session. No production code changed.
- **What changed (PAT-1985):** `deploy/api-01/deploy.sh`'s `EXIT` trap now rolls back binaries when a fatal bash-level failure (a trap-string parse error, PAT-1938's shape) kills the interpreter mid-swap before the `ERR` trap can run — previously the exit path restored the timer and recorded migration evidence while silently leaving new, unverified binaries installed. This deploy is itself the operating evidence that the fix is live on the box: the next genuine mid-deploy interpreter death (not something to manufacture against production) will be the first real exercise of the new path; the deliberate-defect test suite is the maximum evidence obtainable before then.
- **Operating evidence:** read back from the box after the deploy. `DEPLOYED_BINARIES` matches `2de8a3b` across all three binaries. `/health` returns 200. All four services (`patched-api`, `patched-extractor`, `patched-cve-sync.timer`, `patched-maintenance-facts.timer`) active.
- **CVE pipeline:** re-ran its full NVD resync again on this deploy (~33+ minutes), the third observed instance this session of the activation step resyncing on every deploy rather than only the first. Filed as PAT-1995 rather than just a doc note this time, since it's now a confirmed pattern adding real time to every deploy.

**Deploy: 2026-09-22 afternoon (PR #573: PAT-1974 server-side half — standing local admin roster storage, Windows CE rule; deployed through the normal workflow)**

- **Live:** `12f6db862ffd497a310747803c7021d832ba28fa`. Deploy run `35728973738` succeeded, all jobs green. `MIGRATION_HEAD=0160_local_admin_pii_and_windows_rule`, applied by this deploy (0159 creates `local_admin_accounts`; 0160 corrects the stale macOS-only PII comment and seeds `cis_win_5_8_local_admin_count`).
- **What changed:** new top-level `local_admins` payload object (roster of names behind the existing `local_admin_count` signal) ingested, validated and stored on both platforms — the updater half already sends it (Patched-LTD/updater#631). `ce_uac_admin_count` now lists both `cis_macos_5_8_local_admin_count` and `cis_win_5_8_local_admin_count`, closing the `macOSOnly` interlock in `pat1973_ce_platform_coverage_test.go`. Non-author review caught two real gaps fixed before merge: a `complete`-status payload with no `accounts` key at all was schema-valid but would have wiped the stored roster to a fabricated zero (now rejected at the 400 validation gate); the new migration's `local_admin_accounts` table had no `GRANT ... TO patched` (caught again by CI's `check-grants.sh` guard after merge, fixed in a follow-up commit before this deploy).
- **Operating evidence:** read back from the box after the deploy. `DEPLOYED_BINARIES` matches `12f6db8` across all three binaries; `/health` returns 200; all four services active. `local_admin_accounts` table exists with `patched=arwdDxt/patched` confirmed via `\dp`. `compliance_rules` has both `cis_macos_5_8_local_admin_count` and `cis_win_5_8_local_admin_count` rows. `GET /admin/tenants/{Windows staging}/ce-status`'s `ce_uac_admin_count` control now carries `rule_keys: [cis_macos_5_8_local_admin_count, cis_win_5_8_local_admin_count]` — the wiring is proven live.
- **Not yet evidenced:** a real pass/fail resolution from Windows evidence. The Windows staging tenant currently reads `total_count: 0` for this control because its installed agent predates the updater PAT-1974 collector (Patched-LTD/updater#631) — that needs an updated agent build on the Windows staging VM to report `local_admin_count` under the new rule, a separate step from this server-side deploy. `pat1973_ce_platform_coverage_test.go`'s own `TestCEControlStatusWindowsOnlyEstateResolvesAdminCount` already proves the resolution logic itself is correct against synthetic evidence.
- **CVE pipeline:** re-ran its full NVD resync again on this deploy (~378k records, ~57 minutes) despite having activated four hours earlier in the prior deploy — the activation step appears to resync on every deploy rather than being a one-time step; worth a follow-up ticket if that turns out to be intentional-but-undocumented rather than a bug.

**Deploy: 2026-09-22 (PRs #566 to #570: PAT-1969 portal finding-lifecycle contract, PAT-1975 endpoint-protection coexistence source, PAT-1953 CVE attention on portal overview; deployed through the normal workflow, includes the PAT-1970 split — this is the first deploy run since `api-build.yml` was separated out, and the run titled itself `deploy-api-01: SHIPPING to example-api-host (main)` exactly as designed)**

- **Live:** `da0a73819113cd69f02c6668a6daa19f8a21fbae`. Deploy run `35718910194` succeeded, all jobs green. `MIGRATION_HEAD=0158_device_class`, unchanged — none of the three tickets in this deploy carry a migration.
- **What changed (PAT-1969):** new tenant-scoped `GET /v1/portal/finding-lifecycle[/history]`, mirroring the existing admin pair's SQL/shapes/pagination exactly, tenant taken from `portalauth.FromContext` only. Unblocks PAT-1879's portal rendering.
- **What changed (PAT-1975):** `ce.go` gained a third CE control source, `ceSourceAutoWithAttestationFallback` — evidence wins when present, falls back to the stored attestation otherwise. Applied to `ce_mal_endpoint_protection`, scoped to `cis_win_18_9_45_defender_realtime` only (not EDR-presence matches). `attestationControlIDs` still accepts writes for it; the response now names which source (`resolved_via`) actually decided the result, and a superseded attestation is shown, never silently dropped.
- **What changed (PAT-1953, platform half):** new `cve_attention: {available, critical, high}` field on `/v1/portal/overview` — distinct confirmed-match CVE count, kept separate from the CIS `findings_open` field. `available: false` (not a false zero) when the CVE matcher tables aren't migrated yet.
- **Operating evidence:** read back from the box after the deploy. `DEPLOYED_BINARIES`: API `6993b60d5cd3411fc5cd8e79b395b58ff703b9fb5445e689f7d08915954c0b11`, extractor `8336c37126749f02e70fc619574c568bc4f7bb1481ddcc483f0c43dc83614986`, CVE sync `e83fca86622ddca4a17df84b62ae0ff4bfb11b50cdd99314d2844da26f49b5fd`. `/health` returns 200. `finding-lifecycle` and `cve_attention` strings confirmed present in the live binary via `grep -ac`. Admin equivalents live-verified against real tenant-zero data: `GET /admin/tenants/{id}/finding-lifecycle` returns a genuine current row (`CVE-2026-65769`); `GET /admin/tenants/{id}/ce-status` shows `ce_mal_endpoint_protection` resolving `resolved_via: attestation_fallback` correctly (no Windows Defender evidence exists yet for this tenant). CVE pipeline reactivation completed as part of this deploy (a full NVD resync, ~378k records, ~70 minutes — the deploy run's own duration) and `CVE_PIPELINE_ACTIVATED` confirms it against this same commit SHA. All four services (`patched-api`, `patched-extractor`, `patched-cve-sync.timer`, `patched-maintenance-facts.timer`) active.
- **Not yet evidenced:** the portal-facing halves of PAT-1953 and PAT-1879 are deployed to `example-portal-host` (`a83ee9c`) but have not been exercised by a real authenticated browser session — the underlying platform data path is proven live via the admin equivalents above, but no portal server log shows a call to either new route yet. Both tickets are In Review, not Done, pending that one check.

**Deploy: 2026-09-21 evening (PRs #563 to #565: PAT-1956 dead-letter address normalisation, PAT-1960 Windows device class, PAT-1973 Cyber Essentials Windows rule keys; deployed through the normal workflow)**

- **Live:** `66ba23bc`. Deploy run `35639866049` succeeded: build-test 3m41s, deploy 41m50s including the serial CVE pipeline activation. `MIGRATION_HEAD=0158_device_class`, applied by this deploy (PAT-1960's migration; PAT-1973 and PAT-1956 carry none).
- **What changed (PAT-1973):** `ceModel` in `internal/handlers/ce.go` listed only `cis_macos_*` rule keys, because the engine was written before the Windows CIS rules were seeded on the 15th and 20th. Since `ceControlStatus` sums counts across a control's rule keys and the tenant's devices, a mixed estate resolved each control from the Mac evidence alone and excluded every Windows device from both sides of the ratio: a control could report `pass` for the host firewall while every Windows firewall in the estate was off. A Windows-only estate returned `unknown`, which was safe. Windows keys added to `ce_fw_host` (all three profiles), `ce_cfg_screen_lock` and `ce_patch_auto_updates`. Six controls stay macOS-only with the reason recorded in the file. Regression tests are pure functions over `ceModel` and `ceControlStatus`, so they run without `TEST_DATABASE_URL`.
- **What changed (PAT-1960):** `devices.device_class` plus the `compliance_rules.device_class` filter, so a Windows Server is no longer scored against the Windows 11 pack and reports as not assessed rather than passing or failing against the wrong benchmark.
- **What changed (PAT-1956):** a blocked-destination notification failure no longer stores the resolved internal address or hostname in `last_error`, removing the internal-DNS oracle ahead of tenant owners being able to read their own deliveries.
- **Operating evidence:** read back from the box in the deploy run. `DEPLOYED_BINARIES` records API `4a2fdcbd497d3e1bf46e92690d9df577017feccf97234d34ef2ebffdb0adcf88`, extractor `cf3198326d5c054351e8021bb1bf13d64ce1a20eafcd82759d3f4d186defdf89`, CVE sync `148a00af785633168cf26efafc297f2d975f244989029a9df66072b9fc389f5e`. `patched-cve-sync.timer` reads `enabled` and `active`. The deploy step reported "services active, /health returned 200, device_agent_health present, CVE timer retained". `patched-maintenance-facts.timer` enabled and active; `52-automatic-reboot.conf` present and hash-matched.
- **Open at the time of writing:** PAT-1956's acceptance asks for a re-run of the PAT-1888 hostname probe on production showing the sanitised text, and for the two disabled probe channels in the `Endpoint Assurance cycle` tenant (`82a2561a…`, `50a88ade…`) to be deleted once verified. Neither has been done; both need box or admin-API access. PAT-1960 and PAT-1956 were both moved to Done on merge at 15:30 and 16:20, before this deploy ran, so their Done predated any operating evidence; this deploy is that evidence, recorded after the fact.

**Deploy: 2026-09-21 (PRs #554 to #560: PAT-1872 HMAC compatibility telemetry, PAT-1874 evidence catalogue, PAT-1921 signed Windows evidence targets, PAT-1878 finding lifecycle, PAT-1888 notification channels, PAT-1937 deploy-harness fix; deployed through the normal workflow)**

- **Live:** `7ec168a7b576dede3c8cdf362c861e778b6054d6`. Deploy run `35576195946` succeeded, 22 of 22 steps, including the serial CVE pipeline activation. `MIGRATION_HEAD=0157_notification_channels`; migrations 0155, 0156 and 0157 were applied by this deploy. Migration 0154 and PR #554 had gone live earlier, on 2026-09-20 at 09:54 UTC as `82b3985`, and that deploy was not recorded in this block; it is recorded here.
- **What changed:** `hmac_compatibility_telemetry` (aggregate signing form and agent version, no secrets); the signed `windows_installation_evidence` block in `GET /v1/agent-config` with an empty target set; the append-only finding lifecycle (first observed through verified fixed and recurred) with the 0156 dispositions constraints; tenant-owned notification channels, webhook and email, with idempotent enqueue, a sweeper, bounded retry, dead-letter and SSRF refusal at configuration and delivery time. New Go package `graphmail` sends email through Microsoft Graph.
- **Operating evidence:** `DEPLOYED_BINARIES` records API `5590355076b70c71c87a63fad4668e9d74d16dd46db020f34be185172933f08e`, extractor `31915cf60ab99b11b2d5935fdceff8fc6a47444eab00896f45b342642e208aa9` and CVE sync `62d529d6a00e753488c48fe996dad68c3a351bab5626eef4d15dfb858d75dfad`. `patched-api`, `patched-extractor` and `patched-cve-sync.timer` are active; the CVE sync run finished `success`; loopback `/health` returns 200. Production wrote lifecycle rows for CIS and CVE findings on real staging tenants from 08:10 UTC. A real webhook delivery and a failure then recovery (attempt 2) were read back from `notification_deliveries`, and a real test email was delivered and received. The tenant-zero Mac accepted a signed agent config carrying the new evidence block with `targets = []`.
- **Environment change after the deploy:** at 2026-09-21 09:06 UTC the four `GRAPH_MAIL_*` variables (`GRAPH_MAIL_TENANT_ID`, `GRAPH_MAIL_CLIENT_ID`, `GRAPH_MAIL_CLIENT_SECRET`, `GRAPH_MAIL_FROM`) were added to `/etc/patched-api/env`, copied from the dashboard's Mailer settings, and `patched-api` was restarted. The prior env is backed up outside the config directory at `/root/.env-change-backups/`. Until they were set, email channels dead-lettered as `undeliverable_configuration`.
- **Open at the time of writing:** PAT-1888 is not Done: no real lifecycle-triggered notification has yet been observed in production (an enabled sink channel on the cycle tenant is waiting for the first one). PAT-1921 needs an updater release containing PR #625 on a staging endpoint. PAT-1956 tracks the resolved internal IP echoed in a dead-letter error.

**Deploy: 2026-09-20 (PR #552, PAT-1869 tenant-wide portal software inventory, deployed - 2026-09-20 queue-run)**

- **Live:** `385584fa4827fc5113cf807f10b07ce51296fba0`. GitHub Actions was unavailable at run admission (`startup_failure` with zero jobs, tracked in PAT-1920), so the exact merge checkout was built locally with the workflow's Linux/amd64 commands, bound to its full binary and migration manifest, and shipped through the same guarded box-side deploy script. `MIGRATION_HEAD=0153_exploitation_evidence`; no migration was pending or applied.
- **What changed:** authenticated tenant-derived `GET /v1/portal/software` now returns uncapped current software inventory with exact searched pagination, whole-estate metering coverage, evidence time, truthful used/unused/unmetered/mixed/stale/unknown states, and reviewed platform-scoped canonical identity. Removal candidates require every current installation to have fresh authoritative unused evidence; partial, stale and unavailable evidence never becomes a candidate.
- **Operating evidence:** `DEPLOYED_BINARIES` records API `5276a610e2ab52b7751050017f2e905138f712e498352b6c9e048da69bbaa681`, extractor `dd2b9adb8f4eda3d33976aa43137949afd63c7332c062b453c0de1766c563a35`, and CVE sync `1424f231293ad4e7772f9910c3b7bf041060a422331f27aa76935b497629450e`. `patched-api`, `patched-extractor` and `patched-cve-sync.timer` are active; loopback `/health` returns 200; the new route returns 401 without a verified portal identity rather than falling through to 404. Authenticated response rendering is the coupled PAT-1870 closure gate.

**Deploy: 2026-09-18 (PR #536/#535/#534, PAT-1862 os_update contract-drift fix + nullable-evidence regression coverage + PAT-1828 notarized NULL fix, deployed — 2026-09-18 queue-run)**

- **Live:** `4d45f83e4135507086e7080379c35a6678477941`. Deploy run `35293864033` succeeded after the active CVE-sync interlock cleared. `MIGRATION_HEAD=0147_device_os_update_checked_at` confirms the migration applied.
- **What changed (PAT-1862):** PAT-1806's os_update schema had drifted substantially from the real `updater` contract — corrected `required`/nullability on `target_os`/`severity`/`deferrals_remaining`/`latest_os`, added the required `checked_at` field, and fixed a real already-deployed bug: the rollup hardcoded `state = 'current'` but the real agent only ever sends `up_to_date` — every genuinely current device would have misclassified as "behind" the moment an agent sent real data. Also fixed `device_os_update.latest_os` from `NOT NULL` to nullable (a real SOFA/WUA-outage scenario the old constraint would have rejected outright). Confirmed live on the real production table.
- **What changed (PAT-1828):** `device_apps.notarized`/`software_observations.observed_notarized` now genuinely persist NULL (not a false zero-value) when a payload never reports the field — every Windows app payload, since Windows has no codesign concept.
- **Operating evidence:** on-box `\d device_os_update` confirms `latest_os` nullable and `checked_at` present on the real production table. `DEPLOYED_BINARIES` records the exact live SHA and three binary hashes; `patched-api`, `patched-extractor` and `patched-cve-sync.timer` are active, API and extractor have zero restarts, loopback `/health` returns `ok`, and the post-deploy error journal is empty.

**Deploy: 2026-09-17 (PR #533/#532, PAT-1829 findings disposition tracking + PAT-1831 CVE match-confidence aggregate, deployed — 2026-09-17 queue-run batch 4)**

- **Live:** `5fa31b06c810ba15e45d0e690cad69755aba667e`. Deploy run `35280247052` succeeded. `MIGRATION_HEAD=0146_finding_dispositions` confirms the migration applied, not just the binary.
- **What changed (PAT-1829):** new `finding_dispositions` table (0146), append-only-with-supersede, same guard-trigger discipline as `device_dispositions` (0143). One table with a `finding_kind` discriminator carries two identity shapes: CIS `(tenant_id, device_id, rule_key)`, CVE `(tenant_id, cve_id)` (aggregated per `TenantCVEFindingsHandler`'s own per-tenant-not-per-device shape). `POST`/`GET /admin/tenants/{id}/finding-dispositions`. Dashboard UI is a deliberately separate follow-up (PAT-1861).
- **What changed (PAT-1831, deployed same batch):** `GET /admin/tenants/{id}/cve-findings` gains a worst-case `match_confidence` aggregate — one unverified device among a CVE's affected devices makes the whole row read unverified.
- **Operating evidence:** full write path exercised against real production data on tenant-zero — created a disposition against a real live CVE finding (`CVE-2026-33823`), confirmed it in the active list, then superseded it with a correction and confirmed the `supersedes_id` chain. PAT-1831's `match_confidence` confirmed present on 3 real CVE findings on the same tenant.

**Deploy: 2026-09-17 (PR #530, PAT-1800 portal decision provenance, deployed — 2026-09-17 queue-run batch 4)**

- **Live:** `1ec917cf545dd946741d2db555f21d2ed525847e`. Deploy run `35265827405` succeeded, no migration.
- **What changed:** `GET /v1/portal/applications` and `GET /v1/portal/extensions` gain `decided_by`/`decided_at`/`justification` per row (policy rows from `tenant_app_policies`/`tenant_extension_policies`, undecided application rows from `tenant_new_apps`). All three null when there's genuinely no decision record; empty-string DB sentinels converted to null via `NULLIF`, never surfaced as a real decision. `decided_by` always null on `applications` policy rows — `tenant_app_policies` has no actor column, a real documented gap not a bug.
- **Notable:** rebased past a real conflict with #529 (PAT-1728, same session) in `portal_applications.go` — both additive, merged by hand, full suite re-verified green after.
- **Operating evidence:** on-box `DEPLOYED_BINARIES` confirms the SHA. Same Cloudflare-Access constraint as PAT-1728 — correctness verified via the full integration suite, not a live curl.

**Deploy: 2026-09-17 (PR #529, PAT-1728 portal devices-behind-catalog, deployed — 2026-09-17 queue-run batch 4)**

- **Live:** `903aa5055b276825664dc45c597ad2e2514d2327`. Deploy run `35263355861` succeeded, no migration.
- **What changed:** `GET /v1/portal/applications` policy rows with `policy_state` `approved`/`mandatory` gain `latest_known_version`/`devices_behind_count`, comparing installed versions against `app_catalog_entries` via real semantic comparison, matched by the same identity rule `needs_attention.go`'s `catalog_out_of_date` uses. Null (never a guessed zero) when no catalog match or on any other row.
- **Operating evidence:** on-box `DEPLOYED_BINARIES` confirms the SHA. `/v1/portal/*` sits behind Cloudflare Access (JWKS-verified JWT) — confirmed the route fails closed (`401`) pre-handler, same as every path in that group, same limitation PAT-1613 recorded ("needs a signed-in session"). Functional correctness verified instead via the full integration suite against a fresh Postgres.

**Config deploy: 2026-09-17 (PR #528, PAT-1636 Alertmanager retemplate — severity routing, inhibit rules, firing/resolved content, real title_link — config-only, no binary change, deployed — 2026-09-17 queue-run batch 4)**

- **Live:** `/etc/prometheus/alertmanager.yml` rendered from `api-vps-artefacts/alerting/alertmanager.yml.template` at commit `6c21a00`. Backup at `/etc/prometheus/alertmanager.yml.bak-pat1636-...`. `amtool check-config` passed pre- and post-reload.
- **Operating evidence:** live firing→resolved round trip via `amtool alert add` (one `warning`, one `critical`) — Slack notification counter 47→49 (4 real deliveries: 2 firing + 2 resolved), zero `alertmanager_notifications_failed_total` throughout.
- **Not done:** item 6 (`--web.external-url`) — no Alertmanager systemd unit tracked in this repo to add it to; split to PAT-1840. Latent risk only, nothing in the new template falls back to `.ExternalURL`.

Also deployed same session: PAT-1634 (prod-01 shell alerter, `/usr/local/bin/patched-prod-alerts.sh` on `example-prod-host`, live-fire verified via a real `BackupMissed` alert).

**Deploy: 2026-09-17 (PR #526, PAT-1776 internal report consumers stop counting undetermined evidence as fails, deployed — 2026-09-17 queue-run batch 4)**

- **Live:** `654c8044f3f73b0148ec2561c0baebc5aa447aa1`. Deploy run `35257352879` succeeded, no migration.
- **What changed:** extends PAT-1758/PAT-1762's undetermined-vs-real-fail split to CE attestation, XLSX export, admin overview/findings, health admin, trial admin. Includes a fix for a real pre-existing test regression this PR's own diff exposed (`TestHomeMetricsExcludeRevokedTenantsDB` never set `observed_value`), caught by CI's `integration` job, not local verification. PAT-1838 subsequently standardised its DB gate on `TEST_DATABASE_URL`.
- **Operating evidence:** `/admin/health` returns 200 post-deploy; binary confirmed carrying the new `undetermined_count`/`UndeterminedCount` fields.

**Deploy: 2026-09-17 (PR #523, PAT-1836 GET endpoint for device dispositions, deployed — 2026-09-17 queue-run batch 4)**

- **Live:** `e0341e4de98a2675d17722225f6eedddc7dd1982`. Deploy run `35253197386` succeeded, no migration.
- **What changed:** `GET /admin/tenants/{id}/device-dispositions` (PAT-1825 shipped write-only; console PAT-1609 needs to read). Operating evidence: baseline chi-404 `404 page not found`, real route returns `{"dispositions":[],"total":0}`.

**Deploy: 2026-09-17 (PRs #520/#521/#522, PAT-1825 device dispositions + migration 0143, PAT-1806 OS update currency + migration 0144, PAT-1598 authorised removal platform layer + migration 0145, deployed — 2026-09-17 queue-run batch 4)**

- **Live:** `6c76e006c07efbe2d5a94f20c708d75410a44019`. Deploy run `35249900802` succeeded; migration head is `0145_removal_campaigns`. `/opt/patched-api/DEPLOYED_BINARIES` confirms `DEPLOYED_SHA=6c76e00...`, `DEPLOYED_AT=2026-09-17T17:03:31Z`.
- **What changed:** `POST /admin/tenants/{id}/device-dispositions` (PAT-1825, append-only-with-supersede, wired into `ClassifyState`'s `activeDisposition`); `GET /admin/tenants/{id}/os-update-status` (PAT-1806, platform receiving/persisting/rollup only — no agent sends `os_update` yet, follow-up PAT-1833); `POST/GET .../removal-campaigns[...]` (PAT-1598, campaign/dry-run/authorization model with zero agent-facing delivery route anywhere in the diff — structurally cannot reach a customer endpoint, pending PAT-112's MSA clause + follow-up PAT-1834).
- **Operating evidence:** on-box, all three compared against chi's baseline 404 — each returns a genuine validation error specific to its own handler (`category must be one of...`, `tenant not found`, `at least one of team_id, bundle_id, name must be provided`), proving real routing rather than 404 fallthrough.
- **Migration numbering note:** all three PRs independently branched from the same base and each initially claimed migration `0143`. Resolved by renumbering to `0143`/`0144`/`0145` in merge order; PAT-1806's renumbering edit introduced an unescaped apostrophe inside a SQL string literal, caught by CI's integration job (not by local `go build`) and fixed before merge.

- **Live:** `a4941f26d7ca96feada9b34895e904ea2c5b68a3`. Deploy run `35243915543` succeeded; migration head is `0142_software_exceptions` (applied by hand first, additive-only: three new tables, no existing table touched). `/opt/patched-api/DEPLOYED_BINARIES` confirms `DEPLOYED_SHA=a4941f2...`, `DEPLOYED_AT=2026-09-17T16:08:31Z`; `patched-api` active since 17:08 BST with local `/health` returning `ok`.
- **What changed:** `GET /v1/portal/exceptions` (public listener, portal-JWT), and the specialist-recorded admin write surface — `POST /admin/tenants/{id}/exceptions[/{id}/accept|/review-date]` (internal listener, `ADMIN_API_TOKEN`) — for the software exception register (pinned/accepted-risk products). Unblocks PAT-1785 (portal, already merged) re-verification — the portal page has been rendering its upstream-error page in production until this endpoint existed.
- **Operating evidence:** on-box, compared against chi's default 404 on a bogus route (`404 page not found`) — the real create route returns a genuine validation error (`product, version and requested_by are required`, HTTP 400) proving it's routed and executing, not a 404 fallthrough; the public read route returns `unauthorized` (401, portal-auth-gated) rather than a 404. Compiled binary carries the new handler symbols (`ExceptionCreateHandler`/`ExceptionAcceptHandler`/`ExceptionReviewDateHandler`/`PortalExceptionsHandler`, 9 string matches).
- **Batch note:** this deploy also brings live everything merged since the last recorded entry below (`d5ef59a`) that hadn't yet gotten its own dated block here — PAT-1772, PAT-1738, PAT-1599, PAT-1758, PAT-1805, PAT-1801, PAT-1817, PAT-1595, PAT-1549, PAT-1684, PAT-1799, PAT-1823 — each already individually verified operating on this box and closed Done in Linear (with its own on-box evidence recorded as a Linear comment) at the time it shipped; PAT-1801/1823/1799/etc. were live on the box well before this final deploy captured the doc snapshot. Recorded here as one consolidated catch-up entry rather than back-dating individual blocks for deploys this doc's rolling log missed during a fast queue-run sequence.

**Deploy: 2026-09-16 (PR #507, PAT-1796 Ubuntu Pro attachment availability, deployed)**

- **Live:** `d5ef59abdc6e5ccdf72b7fba926d089bfe689f59`. Deploy run `35083021420` succeeded; migration head is `0135_seed_t2_baseline`. `/opt/patched-api/DEPLOYED_BINARIES` records the exact SHA, `patched-api` and `patched-extractor` are active, the maintenance timer is active, and loopback `/health` returns `ok`.
- **What changed:** the hardened maintenance collector now uses the bounded `u.pro.status.is_attached.v1` API. It emits `false` only for a successful explicit detached response and preserves missing, timed-out, malformed, errored or contract-invalid observations as `null` with an availability warning.
- **Operating evidence:** a real hardened unit run completed successfully at `2026-09-16T10:14:01Z` with `pro_attached: true` and `esm_updates: 0`. The deliberately hand-provisioned `/etc/patched-api/artefact-manifest.json` was refreshed per PAT-1544; all eight tracked artefacts, including the changed script and unit, read back `match`.

**Deploy: 2026-09-15 (PR #504, PAT-1770 migration 0133 + PAT-1780 migration 0134: rule outcomes for not-configured Windows signals, deployed, queue-run standing authorization)**

- **Live:** `5a392d20d2bb9bdfae23d8303cb24fc7c38f3a6c`. Migrations `0133_mandatory_aslr_fail_closed` and `0134_auto_updates_pass_on_os_default` applied by the deploy (rule data only; 0132 is claimed by the unmerged draft #497, so the numbering has a deliberate gap). Deploy run 35034612987 succeeded (build-test, deploy). Confirmed on the box: `DEPLOYED_SHA=5a392d20...`, `MIGRATION_HEAD=0134_auto_updates_pass_on_os_default`, `DEPLOYED_AT=2026-09-15T23:16:46Z`, `patched-api` active with no error lines; `nist_win_si16_mandatory_aslr` now `treat_not_configured_as=fail` with corrected title, `cis_win_18_9_102_auto_updates` now `treat_not_configured_as=pass`.
- **Live outcome check (WIN-STAGING, agent 0.13.39):** `cis_win_18_9_102_auto_updates` evaluates `pass`/`NotConfigured` (23:17:56Z). `nist_win_si16_mandatory_aslr` is `collection_tier=T2`, so it only evaluates for tenants with a `tenant_rules` opt-in; enabling it for the staging tenant via `PUT /admin/tenant-rules` gave `fail`/`NotConfigured` (23:19:44Z), and the opt-in was removed again.
- **Note on the previous entry:** the box was running `114747d` (PR #501, PAT-1788) before this deploy, which no entry here recorded. This deploy of `main` therefore also shipped that work and everything merged up to `5a392d20`. A push run of `deploy-api-01` goes green while skipping its deploy job, so a green push run is not a deploy.

**Deploy: 2026-09-15 (PR #496, PAT-1767 migration 0131: three-state compliance signal contract, treat_not_configured_as, deployed, queue-run standing authorization)**

- **Live:** `4ae391cd9a18ec86e2ee26660e41d189dd0d281e`. Migration `0131_treat_not_configured_as` applied by the deploy: nullable `compliance_rules.treat_not_configured_as` (NULL = use `treat_unknown_as`), and the six Windows TLS rules plus `nist_win_si16_mandatory_aslr` split to `treat_not_configured_as=pass`, `treat_unknown_as=fail`. Deploy run 34959140062 succeeded (build-test, deploy). Confirmed on the box: `DEPLOYED_SHA=4ae391c...`, `MIGRATION_HEAD=0131_treat_not_configured_as`, `DEPLOYED_AT=2026-09-15T10:48:05Z`, binary sha256 matches the manifest, `patched-api` active since 10:48Z with no error lines; rule counts now 7 split, 153 fail/NULL, 3 pass/NULL.
- **Rollout order:** the server now accepts and evaluates `"NotConfigured"`. Agents that emit it (PAT-1767 macOS and Windows halves) ship after this deploy, never before.

**Deploy: 2026-09-15 (PR #495, PAT-1753 migration 0130: CIS macOS 2.10.1 screen saver inactivity rule, deployed, queue-run standing authorization)**

- **Live:** `90b569099d0ab52352e762d02b0cd35187b29e31`. Migration `0130_macos_2_10_1_screensaver_inactivity` applied by the deploy (rule data only). Deploy run 34906311975 succeeded. Confirmed on the box: `DEPLOYED_SHA=90b5690...`, `MIGRATION_HEAD=0130_macos_2_10_1_screensaver_inactivity`, `DEPLOYED_AT=2026-09-14T23:01:44Z`; `patched-api` and `patched-extractor` active; local `/health` 200; `compliance_rules` shows `cis_macos_2_10_1_screensaver_inactivity` enabled `screensaver_idle_seconds lte {1200}` unknown=fail, and the old `cis_macos_2_10_1_screensaver_timeout` still `enabled=f`. Evaluates from macOS agent 0.19.15 (`macos-agent-v0.19.15`); older agents never send the key and fail the rule.

**Deploy: 2026-09-14 (PR #494, PAT-1757: mint and enrol refuse a tenant with an active decommission directive, deployed, queue-run standing authorization)**

- **Live:** `c4c483954254b4e8505b06d3e467d6eaa337de93`. No migration (`MIGRATION_HEAD=0129_macos_2_10_2_password_after_screensaver_delay`). Deploy run 34902670006 succeeded (build-test, deploy). Confirmed on the box: `DEPLOYED_SHA=c4c4839...`, `DEPLOYED_AT=2026-09-14T22:17:35Z`; `patched-api` and `patched-extractor` active; local `/health` 200. Live check: `POST /admin/tenants/5fca6dc1-.../bootstrap-tokens` for `Patched Staging (decommission test)` (mode `immediate`) returned 409 naming the mode and `set_at`, `bootstrap_tokens` rows for that tenant 0 before and after, and `patched-api` logged `mint rejected: tenant has an active decommission directive`.

**Deploy: 2026-09-14 (PR #493, PAT-1746 migration 0129: CIS macOS 2.10.2 password-delay rule added, mislabelled 2.10.1 row disabled, deployed, queue-run standing authorization)**

- **Live:** `c8bc51563c4b56adb80f1f958db4874b8345e299`. Migration `0129_macos_2_10_2_password_after_screensaver_delay` applied by the deploy (rule data only). Deploy run 34839717894 succeeded. Confirmed on the box: `DEPLOYED_SHA=c8bc515...`, `MIGRATION_HEAD=0129_macos_2_10_2_password_after_screensaver_delay`, `DEPLOYED_AT=2026-09-14T11:52:49Z`; `patched-api` and `patched-extractor` active; `compliance_rules` shows `cis_macos_2_10_2_password_after_screensaver_delay` enabled T1 `lte {5}` and `cis_macos_2_10_1_screensaver_timeout` `enabled=f`.

**Deploy: 2026-09-14 (PRs #489, #492: PAT-1736 one-off stale FriendlyName disk prune on Windows; PAT-1748 deploy guard accepts a never-run-since-boot CVE oneshot, deployed, queue-run standing authorization)**

- **Live:** `ebce9e2c5b044cfc0c3bdd946a90f0dd39b1c1e5`. No migration (`MIGRATION_HEAD=0128_devices_collection_status`). The first attempt at `e6172340` (run 34828838818) refused before changing anything: api-01 had rebooted at 10:04 BST and `patched-cve-sync.service` had an empty InvocationID (PAT-1748). Deploy run 34836539130 on `ebce9e2c` took the new path (`patched-cve-sync.service has not run since boot (empty InvocationID, loaded, inactive/dead); requiring it to stay empty`) and succeeded. Confirmed on the box: `/opt/patched-api/DEPLOYED_BINARIES` reads `DEPLOYED_SHA=ebce9e2c...`, `DEPLOYED_AT=2026-09-14T11:15:15Z`; `patched-api` and `patched-extractor` active; local `/health` 200; cve-sync InvocationID still empty and its timer active.

**Deploy: 2026-09-14 (PR #486, PAT-1732 certificates collection_status + migration 0128 devices.collection_status, deployed, queue-run standing authorization)**

- **Live:** `820e31667d958b79babd06f7bb99cd67595d81af`. Migration `0128_devices_collection_status` applied first by hand (`sudo -u postgres psql -v ON_ERROR_STOP=1 -d patched -f ...`: `ALTER TABLE` / `COMMENT` / `INSERT 0 1` / `COMMIT`; additive, catalog-only). Deploy run 34792059248: first attempt failed in `Verify production binary deployment inventory` on a timing flake in `test_hup_int_and_term_after_swap_roll_back_everything` (the push run on the same commit passed that step); rerun of the failed job succeeded. Confirmed on the box: `/opt/patched-api/DEPLOYED_BINARIES` reads `DEPLOYED_SHA=820e316...`, `MIGRATION_HEAD=0128_devices_collection_status`; `patched-api` logged `"sha":"820e316..."`; `patched-api` and `patched-extractor` active; no extractor errors after deploy.
- **What shipped at runtime:** optional top-level `collection_status.certificates` (partial upserts and prunes nothing; unavailable writes nothing); every ingest merges reported collection statuses (certificates and hardware_health sections) into `devices.collection_status`.
- **Not yet exercised by a real payload:** tenant-zero uploads daily around 18:00 UTC and its installed agent predates collection_status; the column is NULL on every device until an agent carrying updater #571/#574 reports.
- **Previous live:** `b0647c6789facdf050e03df5cb46e1c5f2dd5926`.

**Deploy: 2026-09-14 (PRs #484 + #485, PAT-1726 portal removal_state + PAT-1727 GET /v1/portal/applications, deployed, queue-run standing authorization)**

- **Live:** `b0647c6789facdf050e03df5cb46e1c5f2dd5926`. Deploy runs 34787206454 (`3d371e3`, #484) then 34789600957 (`b0647c6`, #485). Confirmed on the box: `DEPLOYED_SHA=b0647c6...`, `patched-api` active, binary contains the new code. No migration.
- **What shipped at runtime:** `removal_state` on `/v1/portal/extensions` (`not_requested`/`requested`/`in_progress`/`removal_completed`, from verified removal evidence only) and `/v1/portal/unapproved-apps` (`not_available`); new `GET /v1/portal/applications` (policy rows for every policy value plus capped `undecided` rows). The shared app-policy report now groups by platform.
- **Exercised live without writing:** unauthenticated `GET /v1/portal/extensions` and `/v1/portal/applications` return 401. Read-only derivations against production for tenant-zero: 4 active extension removal requests, all `requested` (0 targets completed, still installed); applications = 19 approved + 1 mandatory + 2 unapproved policy rows and 69 undecided groups. No signed-in portal GET yet (needs a CF Access session).
- **Previous live:** `b20b68c6477bc7b5865e399396079760d82037c9`.

**Deploy: 2026-09-13 (PRs #482 + #483, PAT-1720 hardware-health collection_status + PAT-1725 portal evidence_basis, deployed, queue-run standing authorization)**

- **Live:** `b20b68c6477bc7b5865e399396079760d82037c9`. Deploy runs 34785098954 (`f217f48`, #482) then 34785889164 (`b20b68c`, #483). Confirmed on the box: `DEPLOYED_SHA=b20b68c...`, `patched-api` logged `"sha":"b20b68c..."`, active; the api binary contains `hardware_health.collection_status` and `evidence_basis`, the extractor binary contains `collection_status.battery`. No migration (MIGRATION_HEAD unchanged at `0127`).
- **What shipped at runtime:** `hardware_health.collection_status {battery,storage,disks}` accepted; a non-complete section no longer deletes stored storage/disk rows or overwrites battery values (agents emit it from updater #571 onward, not yet released). `GET /v1/portal/unapproved-apps` and `/v1/portal/extensions` carry `evidence_basis` (plus identifier/name matched-device counts on apps).
- **Exercised live without writing:** unauthenticated `GET /v1/portal/unapproved-apps` on 127.0.0.1:8081 returns 401 (route live, auth intact). The evidence-basis query run `READ ONLY` against production: tenant-zero's two unapproved policies (Android Studio, AppCleaner) match 0 devices, so both grade `unknown`. A signed-in portal GET has not been made (needs a CF Access session).
- **Previous live:** `1ee7687dae77ee76f06ce00afba0dba2676bc94c`.

**Deploy: 2026-09-13 (PRs #480 + #481, PAT-1711 kek-backfill verify pass + PAT-1685 report corrections and frozen findings, deployed, queue-run standing authorization)**

- **Live:** `1ee7687dae77ee76f06ce00afba0dba2676bc94c`. Deploy run 34777028188. Confirmed on the box: `DEPLOYED_SHA=1ee7687...`, `MIGRATION_HEAD=0127_applied_config_snapshots` (unchanged, no migration), `DEPLOYED_AT=2026-09-13T19:17:53Z`; `patched-api` logged `"sha":"1ee7687..."`, active, `NRestarts=0`, no `-p err` lines.
- **What shipped at runtime:** `POST /admin/tenants/{tenantID}/report-records/generate` accepts optional `supersedes_report_id` (same-tenant, issued, not-already-superseded; issuance and forward link in one transaction). Issuance freezes `findings_total`/`findings_by_severity` into `coverage_snapshot`. PAT-1711 changes `cmd/patched-kek-backfill` only, which this workflow does not deploy.
- **Exercised live without writing:** on the internal listener (127.0.0.1:8081), tenant-zero, `supersedes_report_id` = a random UUID returned `404 report record not found`, a malformed id returned `400 supersedes_report_id must be a UUID`; `report_records` count 19 before and after. The success path (a real correction) is left to PAT-1613's dashboard round-trip, since it creates two permanent immutable records.
- **Previous live:** `3afae68021a28edc63562d657f1d8e50ac2c0989`.

**Deploy: 2026-09-13 (PRs #469/#471/#478 + Actions majors #467/#468/#470/#473/#475, PAT-1713 — first dependabot batch, deployed, queue-run standing authorization)**

- **Live:** `3afae68021a28edc63562d657f1d8e50ac2c0989`. Deploy run 34772521125 (`workflow_dispatch`, `deploy=true`, success). Confirmed on the box: `/opt/patched-api/DEPLOYED_BINARIES` reads `DEPLOYED_SHA=3afae68...`, `MIGRATION_HEAD=0127_applied_config_snapshots` (unchanged), `DEPLOYED_AT=2026-09-13T17:49:17Z`; `patched-api` logged `"sha":"3afae68..."` on restart at 18:49:11 BST; `patched-api` and `patched-extractor` active, `NRestarts=0`, no `-p err` journal lines, local `/health` 200.
- **What shipped at runtime:** chi 5.3.0 -> 5.3.2, prometheus/client_golang 1.23.2 -> 1.24.1, x/sys 0.47.0 -> 0.48.0, x/time 0.15.0 -> 0.16.0, pgx 5.9.2 -> 5.11.0. No application code change. pgx 5.11.0's behaviour changes (text-format timestamptz location, case-insensitive db tags, `Rows.TypeMap`) were checked against this service and do not reach it (PR #478 body).
- **CI:** checkout 4->7, setup-go 5->7, upload-artifact 4->7, download-artifact 4->8, setup-dotnet 4->6. `go-test`, `codeql-go`, both `deploy-api-01` runs green on `3afae68`; `go-integration-test` (pull_request only) green on #478 with all five bumps in its tree.
- **Also carried:** PAT-1596 Caddy drop-ins tracked in `api-vps-artefacts/` (#477, #479), config only, applied on the box by hand the same session.
- **Previous live:** `7a8b35e1dfb2fbbe6908a713dbc51469790ddcd9`.

**Deploy: 2026-09-13 (PR #466, PAT-1695 — govulncheck baseline dependency and toolchain bumps, deployed, queue-run standing authorization)**

- **Live:** `7a8b35e1dfb2fbbe6908a713dbc51469790ddcd9`. Deploy run 34768849045 (build-test + deploy jobs both `success`, deploy not skipped). Confirmed on the box: `/opt/patched-api/DEPLOYED_BINARIES` reads `DEPLOYED_SHA=7a8b35e...`, `MIGRATION_HEAD=0127_applied_config_snapshots`, `DEPLOYED_AT=2026-09-13T16:39:25Z`; `patched-api` logged `"sha":"7a8b35e..."` on restart at 17:39:19 BST, `patched-api` and `patched-extractor` active with `NRestarts=0`, no `-p err` journal lines, local `/health` 200. Binary strings show `go1.26.6` and `jackc/pgx/v5 v5.9.2`.
- **What shipped at runtime:** Go 1.26.3 -> 1.26.6 (stdlib vulns), chi 5.1.0 -> 5.3.0, pgx 5.7.2 -> 5.9.2 (GO-2026-5004), x/text 0.39.0, x/net 0.56.0, excelize 2.11.0. No application code change. Also carried: PAT-1700 (docs/workflow only) and PAT-1697 (kek-backfill tests plus a behaviour-preserving extraction in a binary this workflow does not deploy).
- **CI gates added:** blocking `govulncheck` over both Go modules in `go-test.yml`; weekly dependabot; advisory `codeql-go.yml`.
- **Previous live:** `40bd1f81c9514dd16b2582aed06012ccfef9e46f` (deployed 2026-09-13T15:39:24Z, not recorded in this block at the time).

**Deploy: 2026-09-13 (PR #461, PAT-1668 — macOS applied-configuration change detection, deployed, queue-run standing authorization)**

- **Live:** `fd375e46fc0a266825eaa3c6c64dbc2960689ad4`. Deploy run 34753118771. Confirmed on the box: `patched-api` and `patched-extractor` both logged `"sha":"fd375e4..."` on restart at 12:01:35 BST; no errors in either service's journal since.
- **What shipped:** `applied_config_snapshots`/`applied_config_profiles` (migration `0127`, append-only, no policy identity or actor — same shape as `intune_config_snapshots`), a `Diff`/`Rollup` pair in `internal/appliedconfig` that compares two `ok` snapshots of a device and groups changes estate-wide, and `internal/configdiff` extracted from `internal/intune/diff.go` so both the Intune authored-policy path and this applied-configuration path share one comparison engine (`intune.SettingChange` is now a type alias onto it; the pre-existing `internal/intune` suite passes unchanged).
- **Migration `0127` applied via `psql -v ON_ERROR_STOP=1`** on `example-api-host`; `schema_migrations` and `\dt applied_config_*` confirmed.
- **Not yet operating evidence:** `applied_config_snapshots` has 0 rows — nothing has reported `applied_configuration` (PAT-1667 agent field) against this box yet. Code and schema are live and verified; the first real snapshot row is the remaining proof. No scheduler calls `EstateChanges`/`TenantEstateChanges` yet, matching how PAT-1664's Intune diff engine shipped storage-and-diff-only first.
- **Verification:** full `go test ./...` including the unchanged `internal/intune` suite; non-author review (`nvidia/nemotron-3-ultra-550b-a55b`, top tier, escalated) exit 0, 4 findings all dismissed with reason (PR #461 body).

**Deploy: 2026-09-13 (PRs #457-#460, PAT-1662/1663/1664/1613 — Intune config-object snapshotting, setting-ID resolution, diff engine, report-immutability, deployed; catch-up for a gap this doc had not recorded)**

- **Live at this point:** `d3423da728dc17a3ff56631432da1826d5a5e9bb`, superseded by `fd375e4` above the same session.
- **Found:** all four PRs had merged to `main` hours earlier but were never deployed — `example-api-host`'s `schema_migrations` was still at `0122` while `main` carried migrations through `0126`. Merged status had been read as done without checking the box.
- **Fixed:** fetched migrations `0123_msgraph_device_snapshots.sql` through `0126_report_records_issuance_integrity.sql` from `origin/main`, applied in order via `psql -v ON_ERROR_STOP=1` on `example-api-host`, then deployed the binary via `deploy-api-01.yml`. `schema_migrations` and the running binary's `sha` log line both confirmed on the box afterward.
- **Correction to this doc:** this entry is being added retroactively in the same session as the PAT-1668 deploy above — the doc was not updated at the time. Recorded here so the gap doesn't repeat itself.

**Migration applied: 2026-09-12 (`0122_catalogue_identity_backfill_prefix_fix.sql`, PR #449, PAT-1556 — deployed, queue-run standing authorization)**

- **Fixed a silent no-op in production.** Migration `0120_catalogue_identity_backfill.sql` (PR #440) was already applied on `example-api-host` but had linked **zero** of its intended 7 `catalogue_products` rows: it matched bare identity literals (e.g. `{1f01007b-...}`) while every live `catalogue_platform_targets.identity` value carries a scheme prefix (`catalogueIdentityPrefixes` in `internal/handlers/catalogue_review.go`) — all 7 target rows carry `bundle:`. `schema_migrations` showed 0120 as applied with no error, indistinguishable from success.
- **0120 left untouched** (already applied and recorded; editing it in place would never re-run). `0122` is a new forward-only migration using the correct `bundle:`-prefixed literals, stripping the prefix before storing `identity_value_normalized` to match what `software_inventory.go`'s resolver compares against.
- **Applied via `psql -f` on `example-api-host`** (`sudo -u postgres psql -d patched -f 0122_catalogue_identity_backfill_prefix_fix.sql`): `INSERT 0 7 / SELECT 7 / INSERT 0 7 / INSERT 0 7 / UPDATE 7`, clean commit.
- **Operating evidence, not just applied:** re-queried live — exactly 7 `catalogue_products` rows now show `software_product_id IS NOT NULL` (was 0), matching `.NET SDK`, VC++ Redistributable, Patched Agent, QEMU guest agent, Tailscale, OpenOffice, UTM Guest Tools by name. The two decoy fake-`bundle:` rows (Copilot, Microsoft Edge — display names lowercased with a `bundle:` prefix, not real identifiers) correctly remain unlinked, per ADR-0011 §3's identity-purity rule.
- **Verification:** full `go test ./...` clean against a fresh local Postgres with all 122 migrations applied; migration idempotency verified via double-apply; non-author review (`nvidia/nemotron-3-ultra-550b-a55b`, top-tier, escalated for touching `migrations/`) — 2 findings addressed with a defensive guard, remainder dismissed with reasoning (see PR #449 body).
- **PAT-1556's remaining scope (the other 38 catalogue_products rows) is deliberately parked** — see the ticket's own 2026-09-12 banner: deferred until PAT-1595 (device/product identity reconciliation) lands or a real tenant needs resolved product identity.

**PAT-1561 (ADR-0011 §9 — retire duplicate legacy catalogue stores), 2026-09-11: code written, not yet merged/deployed.**

- **`tenant_catalogue` fully removed.** Migration `0121_retire_tenant_catalogue.sql` drops the table (rollback `0121_retire_tenant_catalogue_rollback.sql` recreates the exact 0067 schema). Live-data survey (example-api-host, 2026-09-11) found 2 rows total, both belonging to Patched.im's own internal tenant (`tenant_kind='internal'`, PAT-1562) — no real customer ever used it. Removed with it: `TenantCatalogueGetHandler` / `TenantCatalogueAddHandler` / `TenantCatalogueDeleteHandler` (`internal/handlers/catalogue_admin.go`, deleted) and their three `/admin/tenants/{tenantID}/catalogue...` routes in `cmd/patched-api/main.go`.
- **`GET /v1/allowlist/pending-installs` (catalogue_agent.go) kept as a permanent no-op, not removed.** Both of its production write paths were already hard-disabled before this ticket, independent of table contents: `legacyExecutionEnabled` was compiled `false` at both call sites (`PendingInstallsHandler`, `TenantCatalogueAddHandler`), so the endpoint always returned `{"installs":[]}` without reading `tenant_catalogue` or writing the `tenant_allowlists` pre-approval side-effect — `integration/catalogue_test.go`'s `TestCatalogueAgentPendingInstalls` already asserted this fail-closed behaviour with live rows present. With no live-agent dependency on the endpoint's data (only on its shape/auth), the endpoint is simplified to drop the DB read/write entirely and always return the same empty response after the same auth/rate-limit/tier checks — the least disruptive option for any still-polling agent, since that is exactly the response it already got.
- **`tenant_allowlists` untouched except the dead catalogue-agent side-effect write.** Its real, kept feature — allowlist-violation reporting (`internal/handlers/allowlist.go` / `allowlist_agent.go`) — is unmodified (confirmed via `git diff --stat` on both files: empty). Only the `INSERT INTO tenant_allowlists` inside the now-removed `loadPendingInstalls` (catalogue_agent.go) went away, and it never fired in production regardless.
- **`app_catalog_entries` left untouched, with one new documentation note.** Still 16 rows from the one-time `catalog.json` seed (migration `0030`), still read live by `GET /v1/posture`, `needs_attention.go`, `report.go`, `tenant_apps.go` — no Go write site exists (`grep -rn "INSERT INTO app_catalog_entries|UPDATE app_catalog_entries"` returns zero). ADR-0011 §9 asks for this to become "a read-only projection of verified global-catalogue releases" if posture still needs it, but that is not buildable right now: `catalogue_platform_targets` (the ADR-0011 successor table PAT-1556 backfilled identity into) has no version-tracking field at all. Building one would be a new catalogue-domain feature, not a cleanup, so it is explicitly out of scope here. Added a "KNOWN LIMITATION" note to the top of `migrations/0030_app_catalog_entries.sql` recording the staleness and the missing data source, so this doesn't read as solved.
- **Verification:** `go build ./...`, `go vet ./...`, `gofmt -l .` (clean), `go test ./...` all green with no `DATABASE_URL` set. Additionally ran the full migration set (`0001`-`0121`) from zero against a scratch local Postgres and re-ran `go test ./...` with `DATABASE_URL` set, plus `go test -tags=integration ./integration/...` against the same fresh DB (`TestCatalogueAgentPendingInstalls` and the `TestLegacyQueueReads_*` suite all pass) — confirms the new migration/rollback pair applies cleanly on top of full history and the simplified endpoint behaves identically to before. Not yet merged or deployed — no PR/commit SHA yet, so no on-box verification is possible until the orchestrator merges and deploys.

**Deploy: 2026-09-11 (PR #437, PAT-1570 — health_signals_recompute ingest-lull starvation fix, deployed, Andy-authorized)**

- **Live:** `c16fd44295e9289302c1625f6a27fb6413a4494d`. Deploy run `34618448610` (workflow_dispatch, under the same "merge and deploy all" authorization as PAT-1562 above).
- **Found:** investigating an "OVERDUE" `health_signals_recompute` state on the dashboard's Automations page (Andy: "does this need to be brought up to date"). The recompute's schedule check lived below `Worker.Run()`'s `len(batch) == 0` early-continue, so any quiet ingest period silently blocked it from ever re-checking its 24h interval — now the normal case with all 6 tenants classified `internal` (PAT-1562). Same PAT-912/837/960 shape: correctly wired in isolation, structurally starved by a condition the code never anticipated.
- **Fixed:** hoisted the check above the empty-batch guard so it evaluates every poll cycle (5s) regardless of batch content. Still self-throttled to at most once/hour via `lastHealthSignalsCheck`.
- **Operating evidence, not just deployed:** `patched-extractor` restarted at 16:56:17 BST and its very first poll cycle logged `"health signals recompute starting"` → `"health signals recompute done","tenants":6,"errors":0,"elapsed_ms":23` — fired immediately, with zero inbound ingest traffic at the time (proving the fix; under the old code this would never have fired without a non-empty batch first). `scheduled_job_runs` confirms a fresh row: `2026-09-11 15:56:17 UTC, status=success`.
- **Verification:** full `go test ./...` passed pre-merge; CI (`build-test-vet`, `integration`, `gitleaks`) green before merge; independent non-author review (NVIDIA/nemotron) — NO FINDINGS (took 4 attempts due to transient reviewer overload, not a review problem). No new unit test — `Worker.Run()` has no existing loop-level test harness; verified live instead.

**Deploy: 2026-09-11 (PR #436, PAT-1562 — tenant_kind classification, deployed, Andy-authorized)**

- **Live:** `7ee429cdb1f52dd1830f947e3ee7368ea5ead90b`. Deploy run `34605575697` (workflow_dispatch, explicitly authorized by Andy — "merge and deploy all" — after this session flagged `deploy-api-01`'s manual trigger as the repo's own documented "Andy-gate" and stopped short of triggering it unprompted). Confirmed on the box, not just the green run: `patched-api.service` journal shows startup log `"sha":"7ee429cdb1f52dd1830f947e3ee7368ea5ead90b"`, restarted 14:45:03 BST; migration `0119_tenant_kind` present in `schema_migrations`; `tenants.tenant_kind` column confirmed via `information_schema.columns`.
- **What changed:** migration 0119 adds `tenant_kind TEXT NOT NULL DEFAULT 'customer'` (customer/internal). Threaded through `FetchTenantsOverview`/`/admin/tenants/overview`. New `PUT /admin/tenants/{tenantID}/kind`. `queryIngestionFreshness` (health_admin.go) now excludes non-customer tenants from the stalest-tenant ranking — root fix for PAT-1541.
- **Operating evidence, not just deployed:** ran the full post-deploy data step in the same session — all 6 known internal/test tenants (`Endpoint Assurance cycle 2026-09-03`, `macOS staging surface review 2026-08-17`, `Patched.im`, `Patched Staging (decommission test)`, `Queue run mac staging 2026-08-08`, `Queue run Windows staging 2026-08-08`) flipped to `tenant_kind='internal'` via the new endpoint (all 6 calls returned `200`), verified by re-querying `tenants` directly. Then called `GET /admin/health` live: `ingestion_freshness.stalest_tenant` is now `null` — zero tenants classified `'customer'` exist yet, so PAT-1541's original bug (a decommissioned test tenant winning "worst ingest lag") is now structurally impossible, not just improved. Also confirmed `/admin/tenants/overview` returns `tenant_kind: "internal"` for all 6, which is the dashboard's actual data source — the consuming side (PAT-1562, `dashboard` PR #467, deployed 2026-09-11) reads this correctly.
- **Verification:** full `go test ./...` passed pre-merge (both with and without `DATABASE_URL`); CI (`build-test-vet`, `integration`, `check-grants`, `check-hygiene`, `gitleaks`) green before merge; independent non-author review (NVIDIA/nemotron) — 6 findings, all either matching existing codebase convention or explicitly-documented-as-intentional, none required code changes.

**Deploy: 2026-09-10 (PAT-1481 + PAT-1538 — macOS execution catalogue, first two increments)**

- **PAT-1481** (#431, `dafbbdf`): typed Winget discovery identity, quarantine anti-rollback generation (`agent_config.legacy_execution_quarantine_version`, `agent_config_legacy_execution_activations`, migrations 0113/0114).
- **PAT-1538** (#434, `30f2a93`): ADR-0011's phased schema — `catalogue_products.software_product_id` link to canonical `software_products` (nullable, backfill deferred), `catalogue_target_operations` (per-target/operation verification state machine), `tenant_app_execution_policies` (tenant authorization side), `catalogue_verification_requests` (coalescing verification outbox). Migrations 0115-0118. Additive/non-actuating — nothing yet reads this state to gate execution.
- **On-box verification:** `patched-api` restarted, running SHA `30f2a93e226ce4222144fce606b6798104235bb3`, `schema_migrations` confirms 0113 through 0118 applied, all new tables present.
- **Deliberately not done in this pass:** curated core-set app list. Checked real inventory data on this box directly — every tenant with macOS records is an internal test/pilot fixture (tenant-zero, mac-staging pilots, the PAT-1301 assessment device), zero real customers. Curating from that data would mean curating around personal dev-machine software presented as customer-driven. Left for when real signal exists.

**Artefact deploy: 2026-09-10 (PAT-1543 — api-vps-artefacts/backup.sh re-provisioned to match reviewed main)**

- **Found:** PAT-993 (`069f352`, PR #345) added `report_automation_run`/`report_run` to `api-vps-artefacts/backup.sh` — POSTs a completed-run record to `/admin/automations/api01_backup/record` (local loopback, `ADMIN_API_TOKEN` from `/etc/patched-api/env`) so the job shows up in the dashboard's Automations tab. That code has been on `main` since PAT-993 merged, but `/opt/patched-api/bin/backup.sh` on `example-api-host` was never updated to receive it — confirmed by diffing the deployed file against the repo (deployed file was 78 lines with none of the PAT-993 instrumentation; repo version is 194 lines with it).
- **Correction to this doc, same session:** initially cited "the portal-01 gap noted below (PAT-949: marked Done, never deployed)" as a second instance of this pattern, based on the collapsed 2026-07-27 snapshot's "Known gap" note further down this file. That note is stale — verified live on `example-portal-host` today: `restic`, `/opt/patched-portal-backup/bin/portal-backup.sh`, and `patched-portal-backup.timer` all exist and the timer last fired successfully at 04:07 BST 2026-09-10 (`/srv/backup/health/portal-r2.json` status `ok`). PAT-949 shipped at some point after that 2026-07-27 note was written; the note itself was never updated. Left the historical `<details>` snapshot below as-is (point-in-time record, correct for when it was written) — the error was in trusting a stale note as current fact instead of checking the box, not in the note itself.
- **Fixed:** deployed `api-vps-artefacts/backup.sh` (current `main`, unchanged from repo — no code edit needed, just provisioning) to `/opt/patched-api/bin/backup.sh` on `example-api-host`. Old version backed up alongside as `backup.sh.bak-pat1543-20260910T190346Z`. `bash -n` syntax-checked; byte-for-byte diff against repo confirms exact match. `chown root:root`, `chmod 750` preserved from the original.
- **Not yet operating evidence:** this only fixes the code path — no run has exercised it yet (next real trigger is tomorrow's `patched-backup.timer` at 03:02 BST 2026-09-11, or a manual run if Andy wants it sooner). `scheduled_job_runs` should show a first-ever row for `api01_backup` after that. Don't mark PAT-1543 fully Done until that row is confirmed.
- **Did not fix in this pass:** `prod01_backup` has the equivalent instrumentation already deployed and running on `example-prod-host` (then at the dashboard-checkout path), but every run since at least 2026-09-01 logs `automations record POST skipped (ADMIN_API_TOKEN not set in backup.env)` — `/etc/patched-dashboard/backup.env` is missing the token. This needs the same `ADMIN_API_TOKEN` value already in `/etc/patched-api/env` on api-01 copied into prod-01's `backup.env`. Left as an open recommendation to Andy (PAT-1543) rather than done here — box-level secret placement, per dashboard `AGENTS.md`'s own "Andy's console, Andy's credentials" boundary, not a script deploy.

**Provenance reconciliation: 2026-08-15 (PAT-1215)**

- **Exact current live SHA:** not asserted until `/admin/ops/version`, the installed binary and service state are read back together on `example-api-host`. The snapshot below predates PAT-1215 PRs #386 and #387, and local `origin/main` is not deployment evidence.
- **Latest PAT-1215 deployment evidence:** the issue records API PR #386 commit `111e4c33e6cdd73ada6e0af34f892219c272690c` and the subsequent alerting/config PR #387 commit `1ff3e1c1e9cc66fcb5cd11f0f67ac5cdfa17d2de` deployed on 2026-08-14. It also records public `/ready` returning HTTP 200 with the bounded database check, `patched_api_ready_up` scraped as `1`, all 17 Prometheus rules loaded successfully, and both new timer rules healthy after bounded fire and suppression tests. This is historical operating evidence, not a claim that either commit is still current.

**Ring rollout creation boundary (PAT-1397, not yet deployed):** the internal
owner-held admin token can create one staged rollout from an exact reviewed
product target and the current independently signed global catalogue. The API
cryptographically revalidates the stored envelope at write time, records
immutable evidence and impact counts, rejects revocation/platform/version/
downgrade drift, and commits the first configured band, scoped agent
projection and audit together. This is authority state only. Dashboard
approval UX and endpoint execution remain outside this route. Windows
creation returns explicit `501 Not Implemented` while the signed catalogue
has no Windows platform attestation. Still on branch
`andy/pat-1397-rollout-create-api` as of this note; update this bullet (or
fold it into a dated snapshot above) once it ships to `example-api-host`.

**Mandatory install intent boundary (PAT-1399, not yet deployed):** additive
migration 0110 and the API hold durable per-device mandatory intent, signed
delivery and authenticated state evidence. Normal evaluation follows the exact
PAT-1397 rollout band; Emergency is a separate reasoned owner action. Policy
removal cancels only unstarted work and never uninstalls. This server change
contains no endpoint installer or privileged execution path. Operating proof
requires migration, API deploy and a compatible endpoint consumer, so source
and tests alone do not satisfy deployment acceptance. macOS retains the
PAT-1397 signed-label authority. Windows consumes only a platform-bound
`platform_targets.windows` entry in the same Ed25519 catalogue envelope and
cross-checks the current published review's Authenticode signer, SHA, version,
product, label and verification time. The coordinated producer is updater PR
#533, based on commit `d81e2558` plus the coordinated PAT-1399 amendment: its
daily verifier persists conflict-safe reviewed Windows-runner evidence and
emits `platform_targets.windows` before the existing signer signs those exact
bytes. Signed entries additionally bind an artifact-specific installed
identity: `bundle:<CFBundleIdentifier>` from an accepted macOS app or
`winget:<winget_id>` from Windows runner evidence. Package-only or ambiguous
artifacts omit mandatory identity and remain ineligible. The consumer still fails closed until
the actually published signed catalogue contains that evidence; an unsigned
mirror manifest or registry publisher is never signing authority.
Windows delivery is additionally blocked until PAT-1401 collectors declare
authenticated inventory capability schema 1 with complete canonical Winget
enumeration and per-app identifier kind. Existing registry-only agents fail
closed with an explicit exclusion; app absence alone is never authority.
False, partial, unsupported, or non-Windows declarations are still ingested as
inventory but clear/withhold that authority. Migration 0110 rollback preserves
the dormant reviewed `tenant_app_policies.winget_id` column and expanded
uniqueness key rather than destroying real Winget-only policy data. It also
adds the legacy four-field unique arbiter needed by old binaries' exact
`ON CONFLICT` expression; rollback refuses explicitly if distinct Winget rows
would collide under that older identity instead of dropping data.
Normal evaluation holds its tenant authority lock for at most 500 devices and
returns a deterministic device-id continuation cursor, bounding both DB work
and policy-mutation exclusion without weakening repeated-evaluation
idempotency.
Every unexpired active directive candidate is revalidated against the same current
authority before each signed response. Invalid unstarted work is cancelled;
started work is retained as history but omitted rather than receiving renewed
authority. Exact identity and signer matches classify installed versions as
equal/compliant, older/upgrade-eligible, newer/downgrade-refused, or
ambiguous/fail-closed on both platforms.
The signed response carries server state with intent, delivery and attempt. An
endpoint persists that tuple and resumes the exact attempt after restart rather
than reinstalling. Authenticated check-in may automatically redeliver only an
expired never-started attempt, using a fresh delivery ID while retaining the old
binding in append-only history; started attempts keep the explicit duplicate-risk
recovery boundary. Automatic redelivery stops after three attempts and parks the
row for audited operator recovery. Migration 0110 rollback refuses while any
durable intent/event evidence exists rather than destroying that history.

**Previous independently verified snapshot: 2026-08-14 (PR #384, PAT-1354 audited Shadow IT exceptions deployed)**

- **Binary:** `patched-api` is built from main SHA `21be15eb01f3766c2f4dbe356d939cd83d416870` (PR #384; API build time 2026-08-14 09:06:54 UTC; deployed by workflow run `31786708157`). `patched-api` and `patched-extractor` are active, and `/admin/ops/version` reports the exact SHA with schema `0104_shadow_it_exception_audit`.
- **Three-binary deploy gap:** read-only inspection on 2026-08-15 confirmed `patched-cve-sync` exists as `root:root` mode 0755, its timer is enabled and active, and the oneshot is `inactive/dead` with InvocationID `c243142522d54b1996cef3b945d494d6`. Effective unit inspection also confirmed all three services run as `patched` with `ProtectSystem=strict`; API and CVE sync use `/opt/patched-api`, extractor uses `/opt/patched-extractor`, and none exposes an `/opt` writable path. The API and extractor files, `/opt/patched-api`, `/opt/patched-extractor` and both `bin` directories remain `patched:patched` mode 0755. PAT-1396's manifest, common receipt and root-owned directory/file invariant are not live until the updated manual workflow is merged and dispatched.
- **Shadow IT evidence:** current catalogue matches now retain hostname, immutable device ID, application identifier and first/last observation. Allowed matches remain in the current evidence and every recorded exception is returned separately, including applications no longer installed.
- **Exception audit:** allowing an exception requires a reason; allow and revoke writes update current policy and append the old/new policy, reason, server-established actor, caller claim and observed source address atomically. The API does not claim that policy blocks, removes or pushes software to endpoints.
- **Live acceptance:** the production Patched.im tenant returned one current ChatGPT catalogue match on MacBook-Pro and the corresponding legacy allowed exception. The response preserved `com.openai.codex`, the immutable device ID and first/last observation; legacy rows are labelled honestly as having no recorded reason.
- **Verification:** `go test ./...`, `go vet ./...`, migration hygiene/grant checks and repository CI passed before deployment. Migration 0104 and the exact binary SHA were read back on `example-api-host` after both services restarted healthy.

<details>
<summary>Previous snapshot: 2026-08-14 (PR #382, PAT-1352 enforcement-evidence query deployed)</summary>

**Snapshot: 2026-08-14 (PR #382, PAT-1352 enforcement-evidence query deployed)**

- **Binary:** `patched-api` is built from main SHA `9a4cccb6f502bdd8f0a086768271ee13c0cb21f7` (PR #382; API build time 2026-08-14 08:31:22 UTC; deployed by workflow run `31784167664`). The service is active and `/admin/ops/version` reports the exact SHA with schema `0103_canonicalize_enforcement_tier`.
- **Enforcement evidence:** `GET /admin/tenants/{tenantID}/enforcement-audit` now returns the observed hostname and supports tenant-scoped filtering by exact `device_id`, partial machine identity and validated repeatable or comma-separated `event_type` values. Invalid event types fail with HTTP 400.
- **Live acceptance:** the production Patched.im tenant returned an empty evidence set for `event_type=extension_removed`, consistent with Application Control being off, while an invalid event type returned the expected HTTP 400. No evidence is invented when endpoint enforcement has not run.
- **Verification:** `go vet ./...`, the full Go test suite and both repository CI jobs passed before deployment. The dashboard consumes these filters in its compact Enforcement Evidence workspace.

</details>

<details>
<summary>Previous snapshot: 2026-08-11 (PR #368, PAT-1238 incident-safe blocked-version mutation deployed)</summary>

**Snapshot: 2026-08-11 (PR #368, PAT-1238 incident-safe blocked-version mutation deployed)**

- **Binaries:** `patched-api` and `patched-extractor` built from main SHA `e77d02e24709029cdbac311bb34ef2f5241bf7a8` (PR #368; API build time 2026-08-11 09:15:32 UTC; deployed 2026-08-11 10:17:02 BST by workflow run `31476882275`). Both services are active and `/admin/ops/version` reports the exact SHA.
- **Schema:** migration `0100_audit_events_version_blocked` is live. The closed audit-event constraint and API handler now accept `version_blocked` endpoint evidence.
- **Incident mutation:** `PATCH /admin/agent-config/{tenantID}/blocked-versions` changes one label/version pair atomically without full-replacing the signed configuration. It rejects uninitialised configs, preserves unrelated and unknown JSON fields, avoids version bumps on effective no-ops, and records the server-established `admin_shared_token` actor.
- **Rollout dependency:** updater agents that emit `version_blocked` may now be released. Endpoint refusal and reversible live block/remove acceptance remain to be proven before PAT-1238 is Done.

</details>

<details>
<summary>Previous snapshot: 2026-08-10 (PR #356, PAT-1118 automatic macOS ring mutation deployed)</summary>

**Snapshot: 2026-08-10 (PR #356, PAT-1118 automatic macOS ring mutation deployed)**

- **Binaries:** `patched-api` and `patched-extractor` built from main SHA `f9061d79cb1710f91fb3d93d9a3b76ff0d1fa73a` (PR #356; build time 2026-08-09 23:59:02 UTC; deployed 2026-08-10 01:00:33 BST by workflow run `31343219849`). Both services are active; `/admin/ops/version` reports the exact SHA and schema remains `0096_audit_append_only_guards`.
- **Automatic mutation:** the extractor now observes successful versions once per ring tick, then automatically advances, completes or failure-pauses macOS rollouts with compare-and-set state changes and signed-config publication in the same transaction. Windows remains manual-only because its provenance cannot satisfy the per-device evidence gate. Non-monotonic vendor versions fail closed for operator resolution.
- **Live scheduler acceptance:** the first real scheduler tick at 2026-08-10 01:00:33 BST created two genuine rows from existing successful macOS provenance without a manual database write: Google Chrome `150.0.7871.115` completed immediately at ring 3, and Zoom `7.1.0.83064` is rolling at ring 0. Zoom correctly did not advance: the live estate currently has zero devices assigned to ring 0, so the extractor logged that it cannot gather evidence there rather than treating an empty sample as healthy. The second tick at 01:05:34 BST left both rows, their timestamps and agent-config version 7 unchanged, proving observation and publication are idempotent.
- **Published contract:** agent-config version 7 contains authoritative scoped `macos.zoom` version `7.1.0.83064` with `approval: "up_to_ring"` and `approved_ring: 0`. The conservative legacy projection carries the same Zoom version at ring 0; completed Chrome is absent from both active gates.
- **Endpoint acceptance:** the installed local macOS endpoint naturally polled at 2026-08-10 01:03:12 BST, verified the signed response, and cached config version 7 with the exact scoped and legacy projections above. The post-deploy service journal contains no restart, authentication, publication or database failures; its only rollout warning is the truthful zero-devices-at-ring-0 stall above.

</details>

<details>
<summary>Previous snapshot: 2026-08-09 (PR #354, PAT-1134 platform-aware ring promotions deployed)</summary>

**Snapshot: 2026-08-09 (PR #354, PAT-1134 platform-aware ring promotions deployed)**

- **Binary:** `patched-api` built from main SHA `cbd7c4e8b4bdff864f8147b23935a125f9887356` (platform PR #354; deployed 2026-08-09; exact SHA embedded and live; service active). No migration or extractor deployment was required.
- **Ring promotion contract:** `ring_promotions_scoped` is now the authoritative platform-aware projection. The legacy projection remains conservative for older clients. For scoped clients, a paused first ring means nobody is approved. Automatic ring mutation remains disabled.
- **Live state:** production currently has zero `ring_version_approvals`, so the signed live agent-config correctly returned `ring_promotions_scoped: null`.
- **Endpoint acceptance:** updater PR #410 shipped endpoint 0.2.9, installed on local macOS staging. A poll at 2026-08-09 10:02:26 BST received and verified the signed live payload, updated the heartbeat, and cached bytes whose SHA-256 matched the recorded value.

</details>

<details>
<summary>Previous snapshot: 2026-08-08 (main `e6a071c`, PAT-1048 managed-tier mapping deployed)</summary>

**Snapshot: 2026-08-08 (main `e6a071c`, PAT-1048 managed-tier mapping deployed)**

- **Binary:** `patched-api` built from main HEAD `e6a071cdfbcd05f6c1834cf87403fb2826bef8b9` (built 2026-08-08 09:14 UTC; deployed 10:16 BST; service active). Schema remains `0096_audit_append_only_guards`; no migration or extractor deployment was required.
- **PAT-1048:** the `full_endpoint` subscription tier now projects as `managed` in signed agent-config. Live staging acceptance moved tenant `bd7d7d92-c602-4fc4-9856-ed3593b1987f` from `patch` to `managed`; macOS agent 0.19.0 verified the split gate: `patch` allowed reversible browser blocklist actuation while refusing destructive admin/extension removal, and `managed` allowed both gates.
- **PAT-1109 acceptance:** the same isolated staging tenant issued an immediate purge directive to device `a8ec326e-b104-4d59-9220-9130e004a278`. The device reported `acknowledged`, removed both endpoint bundles, LaunchDaemons, credentials and queue, then reported `removed`; `terminal_without_acknowledgement=false` on the live API.
- **Verification:** workflow run `31250145292` passed build, full short Go tests, shellcheck and deploy. `/admin/ops/version` reports the exact binary SHA above, build time `2026-08-08T09:14:58Z` and migration `0096_audit_append_only_guards`.

</details>

<details>
<summary>Previous snapshot: 2026-08-04 (PRs #336 and #337, PAT-1160 truthful tenant update evidence, deployed)</summary>

**Snapshot: 2026-08-04 (PRs #336 and #337, PAT-1160 truthful tenant update evidence, deployed)**

- **Binary:** `patched-api` built from main HEAD `df5a26c` (built 2026-08-04 16:53 UTC; deployed 16:54 UTC; service active). Schema remains `0091_agent_decommission`; no migration or data write was required.
- **Truthful app evidence:** `GET /admin/tenants/{tenantID}/apps` now requires product-name identity before optional signer equality, so a shared publisher can no longer cross-match unrelated products. Stale Firefox/Zoom helpers remain inventory evidence but cannot become actionable. The response adds verified target, catalogue label, evidence age/state and per-device evidence while preserving compatibility fields. Missing versions fail closed as `evidence_unavailable`; installed versions are actionable only when numerically older than the target, never when equal or newer.
- **Live acceptance:** tenant `5c048e12-db4a-460c-b7c5-d64677a3168a` returns 103 app records: 1 verified update, 19 current and 83 not catalogued, with zero unknown-version updates. Chrome 149/150 is correctly current against the stale catalogue target 126 rather than being offered a downgrade. `/admin/ops/version` reports exact binary SHA `df5a26cf0551eee94d11aa1e29c7d0455da727e0`, build time `2026-08-04T16:53:55Z` and migration 0091.
- **Verification:** full Go tests, vet and build passed locally and in GitHub CI, including the database-backed integration suite. Independent non-author review found no issues in either release. The GitHub-Non-Author-Review external status failed only at the known PAT-491 credential/execution gate; repo-owned CI was green.

</details>

<details>
<summary>Previous snapshot: 2026-07-28 (PRs #317-#321, PAT-495/995/997/999/1002/1003/1007 deployed, queue-run)</summary>

**Snapshot: 2026-07-28 (PRs #317-#321, PAT-495/995/997/999/1002/1003/1007 deployed, queue-run)**

- **Binaries:** `patched-api` and `patched-extractor` both built from main HEAD `bdafe96` (built + deployed 2026-07-28 ~20:20 UTC; both services active). Previous live binaries were `patched-api` at `b2c36d1` (2026-07-27) and `patched-extractor` unchanged since 2026-07-17; this deploy was overdue, picking up 8 merged PRs at once (#317 PAT-495, #318 PAT-995, #319 PAT-997, #320 PAT-1003, #321 PAT-1007; #995/#997 also carried PAT-999/PAT-1002 as part of the same squash-merged PR).
- **PAT-1003: `rebuildRingPromotions` no longer bumps `config_version` on a no-op tick.** `IS DISTINCT FROM` guard on the UPDATE; only writes when `ring_promotions` content actually changed. Live verification limited: rings has zero active `ring_version_approvals` rows for the sole tenant and the extractor's scheduler currently shows no `rings:` activity at all in its journal since restart (consistent with PAT-1002's deliberate disabling of automatic ring advancement), so "static across ticks" is confirmed but for the same reason nothing is exercising the code path yet, and "bumps on a real manual change" could not be observed live (no rollout exists to pause/resume). Correctness verified locally against real Postgres during implementation (both directions, with a negative control). Will re-verify live once rings has real activity.
- **PAT-1007: device patch_history now carries real outcome data.** Confirmed live against a real device: `MacBook-Pro` (device `a573dcbc-7b0e-4424-9831-63179930cf3a`) shows a genuine failed provenance-derived entry (`slack | outcome: error | failure_reason: app_store_managed`), correctly merged alongside OS-patch rows (which correctly carry no outcome field). Ticket's evidence bar met.
- **PAT-995/997/999/1002 (prior queue-run day, confirmed still live post-restart):** rings query fixes and ring-observation parsing, already verified in those PRs' own commit messages against production before this deploy.
- **Rollback:** previous binaries at `/opt/patched-api/bin/patched-api.bak-pat1003-1007-<timestamp>` and `/opt/patched-api/bin/patched-extractor.bak-pat1003-1007-<timestamp>` on the box.

</details>

<details>
<summary>Previous snapshot: 2026-07-27 (PRs #310, #315, PAT-957 + PAT-954 deployed)</summary>

- **Binary:** `patched-api` built from main HEAD `b2c36d1` (built + deployed 2026-07-27 09:06 UTC; service active since 09:07:55). `patched-extractor` unchanged.
- **PAT-957: enrol deadlock fixed.** The diagnostic read in `EnrolHandler` (`internal/handlers/enrolment.go`) now runs on the open `tx` rather than acquiring a second pooled connection. The nested acquire deadlocked the pool under concurrent single-use-token contention. Correctness depends on READ COMMITTED, which lets the statement still see a peer's committed `consumed_at`/`superseded_at`; noted here because moving this tx to REPEATABLE READ would silently regress the diagnosis to stale state.
- **PAT-954: backup-health heartbeat ingest live.** New `POST /v1/backup-health` on the public `:8080` listener. Dedicated `BACKUP_HEARTBEAT_TOKEN` (constant-time compare, **fails closed 503** when unset; never reuses `ADMIN_API_TOKEN` or a tenant bearer), 4 KiB body cap, dedicated rate-limit bucket, job allowlist via `BACKUP_HEARTBEAT_ALLOWED_JOBS` (set to `portal-r2`), HTML-metacharacter and control-character rejection on every field that reaches the staff console, atomic temp-file + rename write into `PATCHED_BACKUP_HEALTH_DIR`. `readBackupJobs` required no change.
- **Box config changed for PAT-954: two things the repo alone would not have given you.** `patched-api.service` now carries `/srv/backup/health` in `ReadWritePaths` (under `ProtectSystem=strict` the directory was otherwise read-only, so every POST would have 500'd on `EROFS`), and `/srv/backup/health` was `chgrp patched` + `chmod 0775` because the service user had r-x but not w. Both were verified as real on the box before deploying, not assumed.
- **Verification:** end-to-end from `example-portal-host` over public 443: authorised POST **200**, wrong token **401**, non-allowlisted `job: prod-r2` **403**, unconfigured **503**, `GET` on the route **405** (proving the new binary serves it). Handler execution confirmed in the journal (`backup heartbeat accepted` / `auth failed` / `job not allowlisted`). The synthetic probe file was removed immediately; `/srv/backup/health/` holds only the two genuine heartbeats. Zero panic/deadlock/timeout lines since restart.
- **Known gap: the heartbeat has no producer yet.** `example-portal-host` has no backup infrastructure at all: no restic, no `portal-backup.sh`, no timer, no `/srv/backup/health`. PAT-949 was marked Done on 2026-07-24 but never deployed to the box, so portal-01's env files, scan SQLite, uploads and origin cert are currently unprotected. PAT-949 has been reopened. The ingest side is finished and proven; the moment that leg is deployed its heartbeat will flow with no further work here.
- **Rollback:** previous binary at `/root/patched-api.bin.bak-pat954`, previous env at `/root/patched-api.env.bak-pat954`, previous unit at `/root/patched-api.service.bak-pat954`.

</details>

<details>
<summary>Previous snapshot: 2026-07-24 (PR #311, PAT-945; PAT-962 recovery)</summary>

**Snapshot: 2026-07-24 (PR #311, PAT-945 deployed; PAT-962 recovery)**

- **Binary:** `patched-api` at main HEAD `acfe5a1` (built + deployed 2026-07-24). Durable discovery jobs expose their target identity so the updater can map each job to the correct catalogue label. `patched-extractor` unchanged.
- **Migrations:** `0086_drop_mirror_eula_approvals`, `0087_device_backup_status`, and `0088_discovery_job_model` applied. Migration 0087 was initially missed while 0088 was present; the resulting `column d.backup_status does not exist` errors broke tenant overview and device posture. The exact committed 0087 migration was applied transactionally on 2026-07-24. PAT-962 tracks fail-closed deploy migration checks to prevent another non-contiguous gap.
- **Verification:** `patched-api`, `patched-extractor`, and `patched-dashboard` active. Dashboard-authenticated `GET /admin/tenants/overview` returns HTTP 200 with the Patched.im tenant, and `GET /admin/tenants/{id}/devices` returns HTTP 200 with all three devices. Internal and public health remain green. Manual macOS and Windows durable-job workflow runs `30129989806` / `30129989957` completed successfully with zero open jobs.
- **Not re-verified this session:** everything below this line and the routes/migrations/rule-count sections that follow are the snapshot, carried forward unaudited; several other sessions have shipped to this box since (see the Working state doc for the fuller history: PAT-651/668/676/677/708 health+fleet, PAT-659/660/713/722 catalogue, PAT-709/710 posture+ops-panel, among others). Treat the "Compliance rules: 161" and route-inventory lines below as stale; a full re-audit wasn't in scope for this session's two fixes.
- **Superseded language kept for history below:** `patched-api` at main HEAD `0328bab` (built deployed ~19:44 UTC). Adds device revocation + enrolled-devices list (PAT-549) and enrollment-token audit log + delivery-path param (PAT-550). PAT-590 tier3 mapping regex change is build-tool only; `patched-api` binary is functionally current for all API paths as of that date.
- **Public endpoints:** `POST /v1/inventory`: bearer + HMAC + rate limit + replay (PAT-338). `POST /v1/provenance`: same auth chain (PAT-46). `GET /v1/agent-config`: Ed25519-signed response (PAT-281). `GET /v1/allowlist/pending-removals`: device-authenticated; pending-removal list for agent uninstall engine (PAT-376). `GET /v1/posture`: device-authenticated (device-specific bearer from `device_credentials` + HMAC; rate-limited); returns compliance posture snapshot: CIS findings, CVE findings, update-availability (catalog diff), app-policy drift (mandatory_missing + unapproved_present), evidence digest (PAT-466 + PAT-468 + PAT-472 + PAT-469 + PAT-473 + PAT-470). All enforce: per-tenant rate limit (60 rpm, burst 10), `X-Patched-Timestamp` freshness ±300 s, `X-Patched-Nonce` replay rejection.
- **Internal `:8081` (Tailscale-only):** tenant-rules, per-OS master switch, device-certs, agent-config write, credential rotation, platform read-API (overview/devices/device/findings, PAT-340), health + metrics (PAT-347), exec-summary PDF, software-metering aggregates (PAT-366), app-update policy store (PAT-364: `GET/PUT /admin/tenant-app-policy/{id}`, `PUT …/default`, `PUT/DELETE …/apps/{id}`), estate app-update aggregated view (PAT-588: `GET /admin/tenants/{id}/apps`), software allowlist store + scan engine (PAT-375: `GET/POST /admin/tenants/{id}/allowlist`, `PUT/DELETE …/{id}`, `PUT …/allowlist-policy`, `GET …/allowlist/scan`), CE attestations (PAT-367), CVE scan endpoints, Prometheus `/metrics`, tenant lifecycle (PAT-431), app-policy CRUD (`GET/PUT /admin/tenants/{id}/app-policies`, `DELETE …/{entryID}`, PAT-470), app-policy drift (`GET /admin/tenants/{id}/app-policy-drift`, PAT-479), new-apps discovery (`GET /admin/tenants/{id}/new-apps`, `PUT …/{appId}`, PAT-167), device revocation (`POST /admin/devices/{id}/revoke`, PAT-549), enrolled-devices list (`GET /admin/tenants/{id}/enrolled-devices`, PAT-549), needs-attention risk view (`GET /admin/tenants/{id}/needs-attention`, PAT-458), bootstrap-token generation with audit (`POST /admin/tenants/{id}/bootstrap-tokens` with delivery_path param, PAT-550).
- **Auth hot path:** `LookupTenantByBearer` queries `tenant_credentials` joined to `tenants` (migration `0017`). Device-specific credentials (migration `0029`, device_id NOT NULL) gate `GET /v1/posture`. Supports multiple concurrently-valid credentials for zero-downtime rotation. Revoked-tenant check blocks agents immediately on revoke. Device revocation (PAT-549) sets `revoked_at` on matching `tenant_credentials` rows and appends an audit row to `device_revocations`; gated by `tc.revoked_at IS NULL` on next auth.
- **Migrations applied:** `0001`–`0041` (all applied). `0040_device_revocations`: PAT-549 audit table. `0040_enrollment_audit_log`: PAT-550 audit table. `0040_macos_cis_l1_expansion`: 38 macOS T2 rules (PAT-586). `0041_windows_nist_l1_expansion`: 19 Windows T2 rules (NIST SP 800-53 Rev 5 Moderate; PAT-590).
- **Compliance rules:** this retained pre- inventory note is not a
  current rule-count claim. Rules are migration-managed data and the current
  enabled inventory must be obtained by applying ordered migrations then
  grouping the live `compliance_rules` table, as documented in
  [`contracts/portal-api.md`](../../contracts/portal-api.md#rule-count-source-of-truth).
  The evaluator filters by payload platform. Payload schema v2–v3.
- **Software allowlist:** `allowlist_baseline_apps` (69 macOS + Windows OS-baseline seeds), `tenant_allowlists`, `tenant_allowlist_changes` audit log, `tenants.allowlist_default_deny` (migration `0023`). Scan engine derives device platform from `devices.os` (`LIKE 'windows%'`). Each `/allowlist/scan` app carries installed-evidence `team_id` and legacy-compatible `bundle_id` plus `app_identity`, derived server-side with Team ID first, then typed Winget ID on Windows, then bundle ID and name; it also preserves `identifier_kind` and emits `winget_id` only for explicitly typed, valid Windows Winget identifiers. Publisher text never supplies a Team ID.
- **App-policy model:** `tenant_app_policies` table (migration `0032`). Per-tenant, per-app policy: mandatory | approved | unapproved | unmanaged; enforcement_tier: report | app_management | managed. Matched by team_id > bundle_id > name. Drift computed at query time and surfaced in `GET /v1/posture`.
- **Agent config:** `agent_config` table (migration `0015`). Ed25519 signing key loaded at startup (`key_id=ecd47f2c5b3d5705`).
- **Observability:** Prometheus scraping `:8081/metrics`. Grafana + Alertmanager still open.
- **Backup:** Restic nightly to Cloudflare R2; first snapshot verified.
- **Internal proxy path:** dashboard → Caddy `example-api-host.example-tailnet.ts.net:8443` → Go `:8081` over Tailscale (`api-internal.patched.im` retired).

</details>

### Production binary deployment contract

The manually dispatched `deploy-api-01.yml` workflow owns all three installed
production commands: `patched-api`, `patched-extractor` and
`patched-cve-sync`. `deploy/api-01/production-binaries.tsv` is the checked
recursive inventory of every `package main` under `go-service/cmd`; nested
commands are keyed by their full path relative to `cmd`, so equal basenames do
not collapse. Operator-only utilities must be explicitly classified as separately deployed, so adding a new command
without deciding its production path fails CI.

One workflow checkout builds all three binaries and produces a manifest tied
to `GITHUB_SHA`, containing the commit, SHA-256 for each binary, the artifact's
highest forward migration and a SHA-256 entry for every conventioned forward
migration the deploy can execute. The box verifies the complete staged
migration set before installation and re-hashes each pending SQL file
immediately before `psql`; it verifies the head is recorded in
`schema_migrations` both after the migration pass and immediately before the
receipt commit. This detects accidental CI-to-host transfer or installation
corruption and creates a build receipt; it is not a signature or protection
from an attacker controlling the workflow, artifact and SSH channel. The
local/PR deployment inventory gate validates every top-level forward and
rollback SQL filename against the same convention before manifest production,
so a historical filename cannot first break a main-branch deploy run.
The box-side deploy creates timestamped backups under root-only `/root/patched-deploy-backups`,
records their SHA-256 values in a root-only rollback digest file, and refuses
rollback from bytes whose ownership, mode or digest no longer agrees. It atomically swaps each
binary, verifies installed bytes against the manifest, restarts and
smoke-tests only the long-running API and extractor, then writes
`/opt/patched-api/DEPLOYED_BINARIES` with the common commit SHA and all three
installed hashes. Any install or smoke failure restores all three binaries and
the prior receipt. Database migrations remain forward-only. If this run applied
a migration before failing, rollback deliberately leaves the Persistent CVE
timer disabled and writes root-only `RECOVERY_REQUIRED` evidence in the retained
staging directory. The evidence records the migration count/head and actual
restored CVE hash; the verified full deploy must succeed before the timer is
enabled again.
The deploy establishes root-owned mode-0755 invariants on both `/opt` service
directories, both binary directories, the receipt directory and all three
managed executables. The current live `patched:patched` parent ownership remains
recorded above until the first dispatch.
Every rsync to the box passes `--chown=root:root`, and
`deploy/api-01/deploy-ownership-guard.sh`, piped from the runner rather than
run from a box copy, fails the deploy before root runs anything staged and
again after the last file is placed if a path root runs, installs or reads is
a symlink, owned by a non-root or unknown uid, or writable by group or other
(PAT-2310; exceptions and runbook in `api-vps-artefacts/OPERATIONS.md`).
`patched` on api-01 is a service account with no login shell, no sudo and no
SSH key; admin access is root over Tailscale only. The last step before the
readback pipes `deploy/api-01/service-account-hygiene.sh` the same way,
`apply` then `check`: `apply` removes any sudo rule, privileged group, login
shell, key file or listed leftover that has come back, and `check` fails the
deploy if `patched` can still log in or use sudo. It never touches a running
service (PAT-2312; runbook in `api-vps-artefacts/OPERATIONS.md`).
Both normal and emergency paths verify the effective systemd sandbox before
parent mutation. The normal path checks API, extractor and CVE sync; the
emergency path checks API. Expected service user, WorkingDirectory and
`ProtectSystem=strict` must match, and neither `ReadWritePaths` nor
`ReadWriteDirectories` may grant a path under `/opt`.
The fixed staging directory must itself be `root:root` mode 0755 before any
timer, migration or installation mutation. Read-only live inspection on
2026-08-15 confirmed this exact contract for all
three units. Root deploy code never sources the patched-owned API environment;
it parses one exact unquoted `DATABASE_URL=` line without shell evaluation.
A value-redacted live check confirmed the current file has exactly one line in
that strict format. Production invocation starts Bash through `env -i` with a
fixed root-controlled `PATH`; the scripts also unset `BASH_ENV`, `ENV` and
`CDPATH` before starting child commands. CI runs the root/fixed-path harness in
a networkless disposable container with a read-only checkout, never as host
root on pull-request-controlled code. `DATABASE_URL` must be an absolute
`postgres://` or `postgresql://` DSN and is supplied to libpq only through the
per-process `PGDATABASE` environment, so it is neither an argv value nor
interpretable as another psql option. Direct root invocation with an inherited `BASH_ENV`
is unsupported because Bash evaluates it before the script starts; the only
supported workflow/manual entrypoint is the documented clean `env -i` command.

`patched-cve-sync.service` remains a timer-owned oneshot. Deploy refuses to
replace it while a sync is active or within 15 minutes of its next trigger,
quiesces only its timer before migrations, and uses EXIT/HUP/INT/TERM cleanup to
restore the timer. While the timer is stopped it requires an unchanged
InvocationID (empty is accepted only for a loaded `inactive/dead` unit that has
not run since boot, PAT-1748) and exactly one resolved `ExecStart` entry for the managed binary. Invocation proof is completed
before timer restart, so a legitimate Persistent run after restoration cannot
create a false rollback.
The explicit non-running states are `inactive/dead`, `active/exited` and
`failed/failed`; activating, running and unknown combinations fail closed. HUP
uses the same restoration path as EXIT, INT and TERM.
The next-trigger safety window reads the timer's D-Bus
`NextElapseUSecRealtime` microsecond integer through `busctl`, avoiding locale
and timezone parsing. `USEC_INFINITY` is rejected before signed Bash arithmetic.
This interface was verified on live systemd 255. Signals
received after installation begins invoke full binary, receipt, directory-mode
and timer rollback before returning 129, 130 or 143; pre-install signals only
restore the quiesced timer. Stop marks restoration required before invoking
systemd, and signals received while either timer stop or start is in flight are
queued until its success/failure and `TIMER_STOPPED` state are recorded, then
run the same rollback path.
It never starts or restarts the oneshot on an unrelated API deployment. This
contract describes the deployment mechanism; the dated snapshot above remains
the source of truth for what is currently live until a dispatch is verified.
The normal deploy also requires all three binaries and the CVE units to be
pre-existing. The explicit one-time host bootstrap is documented in
`api-vps-artefacts/OPERATIONS.md`; routine releases never create or enable
systemd units implicitly.
If those prerequisites are broken, or the oneshot is not loaded or in an
unexpected state,
`deploy/api-01/emergency-api-only.sh` is the break-glass route. It deploys only
a manifest-verified API with atomic backup/rollback. It backs up and rewrites
the primary receipt with the new API hash, current extractor/CVE hashes, a
reduced-scope marker and prior-receipt pointer, so on-box evidence remains
truthful without weakening the normal contract.
Its rollback sources and digest record live under root-only
`/root/patched-emergency-api-backups`; inherited path/command overrides are
rejected for root invocation.
The dispatch input defaults to `deploy=true`, but the deploy job additionally
requires `refs/heads/main`. CI retains artifacts for 14 days and supports
explicit `deploy=false` dispatches against arbitrary refs to rebuild expired
artifacts without entering the deploy job. The
emergency path tolerates absent extractor/CVE binaries and records `MISSING`
rather than inventing hashes.
API-only emergency deployment requires explicit acknowledgement of the
manifest migration head and verifies it already exists in live
`schema_migrations`; it never runs migrations. EXIT/HUP/INT/TERM after its API
swap restore the prior binary, receipt and directory ownership/mode before
returning the original failure or signal status.

---

## Built reality (current)

| Item | Value |
|---|---|
| API box hostname | `example-api-host` |
| API box spec | Hetzner CPX22: 3 vCPU x86, 4 GB RAM, 80 GB NVMe |
| API box location | Helsinki (HEL1) |
| API box public IPv4 | 203.0.113.20 |
| API box tailnet IPv4 | 100.64.10.1 |
| Main box hostname | `example-prod-host` |
| Main box location | Nuremberg (NBG1) |
| Main box public IPv4 | 203.0.113.10 |
| Main box tailnet IPv4 | 100.64.10.2 |
| Tailnet | `patched` (MagicDNS suffix `.example-tailnet.ts.net`) |
| Public ports open | 80, 443 (TCP 22 closed at Hetzner FW for both boxes) |
| Hetzner snapshot | Taken as clean baseline |
| Go service version | v0.1.0, deployed as systemd unit `patched-api`. Redeployed from main HEAD (commit `c7b4cd7`): exec-summary endpoint, pending-updates extraction in `patched-extractor`, T2 compliance pipeline (52 CIS rules), tenant-rules admin API on `:8081`, and Prometheus `GET /metrics` on `:8081`. |
| First production smoke test | UTC. Mac → https://api.patched.im → row in `raw_payloads` (tenant `local-test`) |
