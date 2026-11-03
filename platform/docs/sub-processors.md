# Sub-processors

**Audience:** customer due diligence, supplier take-on questionnaires, Cyber Essentials and ISO assessors, the DPA in PAT-112.
**Owner:** Patched.im Ltd (139269C), Isle of Man.
**Status:** first published draft, 3 September 2026 (PAT-1498). Items marked *confirm* are accurate to the estate as documented but need a commercial or contractual check before this goes to a customer.

Every third party below either processes customer or customer-derived data, or holds something a buyer would reasonably expect to see named. Publishing the list is deliberate: a published list is easier to keep true than one that lives inside a proposal.

## Processing customer data

| Sub-processor | What it does for Patched | Customer data involved | Location | Notes |
|---|---|---|---|---|
| Hetzner Online GmbH | Virtual servers. `example-api-host` holds the PostgreSQL 16 system of record; `example-prod-host` holds the internal ops dashboard and its SQLite store and generated reports | All device, inventory, software, compliance and tenancy data. Generated PDF reports | Helsinki, Finland and Nuremberg, Germany. EU only | Two separate data centres for physical separation. Public ports reachable only from Cloudflare ranges; SSH closed to the internet |
| Cloudflare, Inc. | DNS and edge proxy for every public hostname; WAF and DDoS; Cloudflare Access identity gating for the internal dashboard and the customer portal; Cloudflare Pages hosting for `patched.im` and `docs.patched.im`; Cloudflare R2 for off-provider backups | All ingress traffic in transit. Encrypted backup ciphertext at rest in the `patched-backups` bucket. The email address of each person who signs in to the portal | Global edge for proxy and CDN; R2 bucket in the EU | Backups reach R2 already encrypted client-side with AES-256, so R2 holds ciphertext only |
| Microsoft Corporation (Microsoft 365) | All transactional email, sent through Microsoft Graph from the `noreply@patched.im` mailbox in Patched's own Microsoft 365 tenant: report-ready notifications, signed download links, scan results. The same mailbox receives replies | Recipient name and email address, message subject and body, signed link identifiers, and the full content of any reply a customer or vendor sends to that mailbox | Patched's Microsoft 365 tenant, hosted in the UK — outside the Hetzner/EU estate | Sending uses the `Mail.Send` permission and reply ingestion uses `Mail.Read`, both held by a single app registration ("Patched.im Mailer") whose client secret lives on `example-prod-host`. An Exchange ApplicationAccessPolicy scopes the app to that one mailbox, so `Mail.Read` cannot reach any other. Outbound delivery went live in production 3 September 2026 (PAT-1346) |
| Better Stack, s.r.o. | External uptime probes, hosted public status page and incident timeline | Public hostnames and public health-response bodies and incident metadata. No endpoint inventory, report or customer payload is sent. The free-tier status page does not collect subscriber email | EU regions by default, according to Better Stack's security statement | Free-tier uptime monitoring is configured as email-only. The status page exposes only customer-facing service components |

## Holding no customer data, named because a buyer will ask

| Third party | What it does | Why it is listed |
|---|---|---|
| GitHub, Inc. | Source control and CI for all Patched repositories | Holds the code that runs on customer endpoints, so a security reviewer will ask about branch protection and who can merge. No customer data |
| Linear | Issue tracking and internal documents | Operational record only. **Standing rule: no customer data, no device inventory, no report content in Linear.** Prospect and customer names appear as ordinary commercial context |
| Anthropic PBC | AI assistance in software development | Named because the AI use policy commits to disclosing it. Development-time only; no customer data is sent, and no Patched product feature calls an AI service at runtime |
| Tailscale Inc. | Private administrative network. All SSH, the admin API on `:8081` and PostgreSQL are reachable only over the tailnet | Control plane. Customer data traverses the tailnet in transit between the ops dashboard and the admin API, inside the WireGuard tunnel |
| Backblaze B2 | Named fallback backup destination | Not currently in use. Listed so the fallback is not a surprise if it is ever activated |

## Customer-controlled identity

Portal sign-in runs through Cloudflare Access against the customer's own Microsoft or Google identity. That identity provider is the customer's, not a Patched sub-processor, but it is named here because supplier questionnaires ask how authentication works and the honest answer is that Patched never holds a customer password.

## What Patched does not use

No analytics or tracking service on any public site. No advertising network. No customer relationship or marketing automation platform holding customer data. No third-party AI service in any runtime product path. The website sets only essential cookies and local storage, as its cookie policy states.

**Twilio SendGrid is not a sub-processor.** Patched transactional email is sent through Microsoft Graph from Patched's Microsoft 365 tenant; Twilio SendGrid does not process customer email or customer data for this service.

**Calendly is not a sub-processor.** A booking link was live and appeared in several pages' content security policy; PAT-1527 (2026-09-03) replaced every Calendly CTA on the public site with a `mailto:hello@patched.im` link. Inbound booking now stops at email, so no prospect name or address reaches Calendly. The dashboard's existing Calendly webhook/lead pipeline was left in place but has no live source feeding it (flagged, not actioned, under PAT-1527).

## Data residency

All customer **device** data is processed and stored in the EU, on Hetzner infrastructure in Finland and Germany. A documented relocation playbook moves the estate from Hetzner to a UK provider within one working day if a customer's own obligations require UK residency.

Email is the exception a careful reader will spot, and it is stated here rather than left to be found. Report notifications, signed links and any replies sent to `noreply@patched.im` are held in Patched's own Microsoft 365 tenant, hosted in the **UK**, not on the Hetzner estate. The public security page (`security.html`, "Where your data lives") and the scan.patched.im funnel pages (`public_scan.html`, `public_upload.html`, `public_privacy.html`) now state this exception explicitly — see PAT-1506.

## Retention

| Data | Retention |
|---|---|
| Raw device payloads and derived inventory | Held for the life of the tenancy; deleted on offboarding |
| Audit events | Append-only, minimum 90 days |
| Encrypted backups in R2 | 7 daily, 4 weekly, 3 monthly snapshots |
| Assessment artifacts and their delivery audit | *Confirm:* an explicit retention and erasure policy is still open (PAT-1407, PAT-1410) and must be settled before the first paid assessment, because the answer belongs in the DPA |

## Changes

Material changes to this list are notified to customers before the change takes effect, and the notice period will be stated in the customer agreement (PAT-112). This document is the authoritative version; any copy inside a proposal is a snapshot.
