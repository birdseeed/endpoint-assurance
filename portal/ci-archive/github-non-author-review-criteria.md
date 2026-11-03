# GitHub-Non-Author-Review criteria — portal

The reviewer is a separate, clean-context pass — adversarially re-derive findings, don't rubber-stamp. Review **only** the PR diff against its base branch. Mark **failure** if any blocking issue exists; otherwise **success**. Surface nits separately.

This repo ships **two** FastAPI services that share the box `example-portal-host` but nothing else:

- **portal** (`main.py`, `:8000`, `app.patched.im`) — the customer-facing portal (PAT-330/PAT-331): a **read-only, stateless, customer-scoped** app. It holds no database and no estate state; every read forwards the caller's Cloudflare Access JWT verbatim to the platform, which derives the tenant from the verified identity. A deliberately separate trust boundary from the staff console — they share no auth session, box, or trust domain.
- **scan** (`scan/`, `:8001`, `scan.patched.im`) — the public CVE-scan / Intune-upload funnel (PAT-457), **unauthenticated by design**. Extracted out of the dashboard so the staff console no longer carries a public surface. Own SQLite + files under `/var/lib/patched-scan`; holds only mail + Turnstile credentials.

The portal criteria below apply to `main.py` / `auth.py` / `upstream.py` and the portal deploy files; the **Scan service** section applies to anything under `scan/` and the `*-scan.*` deploy files.

## Authentication (fail closed, always)

- **Server-side JWT verification only.** Every non-public request must carry a valid CF Access JWT, verified in `auth.py` against the team JWKS: signature, audience (AUD), issuer, expiry, and an email claim. Never trust the `Cf-Access-Authenticated-User-Email` header (or any CF-set header) on its own — anything reaching the origin around Cloudflare can forge it.
- **Fail closed.** Any verification failure, JWKS fetch failure, or missing auth config must refuse the request (401 / distinct 503 for config), never fall through to a rendered page. Flag any fail-open path.
- **Public surface is frozen.** `/healthz` and `/static/*` are the *only* unauthenticated paths. Any new route must be authenticated; flag any change that widens the unauthenticated surface.
- **No JWKS amplification.** The forced JWKS refresh on unknown `kid` stays rate-limited (cooldown) so a flood of garbage tokens can't turn the portal into a JWKS-fetch amplifier.

## Tenant isolation

- **The portal never sends, accepts, or infers a tenant identifier.** Tenancy is derived upstream from the verified JWT. Flag any code that introduces a tenant/customer/estate id into a request path, query, body, or header — that reintroduces a cross-tenant tampering surface that the design deliberately removed.
- The caller's JWT is forwarded **verbatim** upstream; it is never rewritten, re-signed, or substituted.

## Read-only invariant

- The portal makes **no customer writes** except the `mailto:` support link and the three bounded proxied calls the platform owns and validates (report generate POST, report schedule PUT, and agent enrolment-token mint POST — `POST /install/enrolment` → `/v1/portal/enrolment`, PAT-453; the platform mints a single-use token scoped to the tenant it derives from the verified JWT, and rate-limits it). Flag any new local state, database, cache-of-record, cookie beyond the CF session, or write path.

## Output / template safety

- **Jinja2 autoescaping stays on.** Flag any `| safe`, `Markup(...)`, `autoescape=False`, or f-string HTML that renders upstream- or user-derived data unescaped — the estate data is customer-influenced. Inline SVG charts must not interpolate untrusted values into attributes/markup without escaping.
- No untrusted value flows into a redirect target, `Location` header, filename, or shell/subprocess call. CSV export must guard against formula injection (leading `= + - @`) in exported cells.
- Report downloads stream (chunked) — don't buffer whole PDFs in memory.

## Secrets & deploy posture

- No secrets, tokens, keys, or credentials committed. **No platform secrets belong on this box** (no DB creds, no admin tokens, no broad Tailscale keys); `/etc/patched-portal/env` is never overwritten by the installer.
- Changes under `deploy/` preserve the network posture: nginx serves Cloudflare ranges only, `real_ip_header CF-Connecting-IP` is set before any allow/deny, the systemd unit stays sandboxed (`ProtectSystem=strict`, no needless write access, non-root `portal` user), and the data path never traverses the tailnet (no `:8081`/`:8443`/`:5432`).

## Upstream client

- Every upstream call is bounded by a timeout and maps failures to the correct page (401 → re-auth, 403 → not-linked with no re-auth CTA, 503 → not-enabled, config-missing → distinct 503). Flag any unbounded call or a failure mode that leaks a stack trace / internal detail to the customer.

## Dependencies

- Any added/changed dependency in `requirements.txt` / `pyproject.toml` is a first-party or well-known package pinned appropriately; flag new transitive risk or an unpinned/loosened constraint.

## Scan service (`scan/`, scan.patched.im) — public by design, tightly bounded

This service is intentionally unauthenticated. **Do not flag "no auth" or "no CF Access" as a finding** — instead verify the abuse controls and blast-radius limits below. Note the portal invariant is unchanged: PAT-457 adds **no** routes to `main.py`, so `/healthz` + `/static/*` remain the portal's only unauthenticated paths.

- **Abuse controls, enforced before work is done.** Turnstile server-side verify on every form POST (skipped only when `TURNSTILE_SECRET` is unset, i.e. dev). Per-email (3) and per-IP (10) per-24h rate limits on both funnels. OTP: 6 digits, 15-min expiry, max 5 attempts, constant-time compare (`secrets.compare_digest`), single-use (cleared on success). File size caps (25 MB scan / 10 MB upload) enforced *before* the file is fully buffered. Flag any weakening: longer OTP validity, removed attempt cap, `==` compare, OTP logged/returned, or a size check after buffering.
- **Writes confined to the state dir.** The service may write only under `/var/lib/patched-scan` (systemd `StateDirectory`, resolved via `$STATE_DIRECTORY` / `SCAN_STATE_DIR`): `scan.db`, `uploads/`, `reports/`, `nvd.db`. Flag any write outside it, any on-disk path built from an attacker-controlled upload filename without `_safe_filename` **and** the resolve-inside-scan-dir check (PAT-456), and any relaxation of `ProtectSystem=strict` / `StateDirectory` in the unit.
- **No platform secrets on this box.** The scan service holds NO platform API key, tenant credentials, admin token, or `dashboard.db` connection — only mail (Graph/SendGrid) + Turnstile. Flag any such credential added to `scan/`, `deploy/env-scan.template`, or the unit; `/etc/patched-scan/env` must never be overwritten by the installer.
- **NVD dataset is never fetched mid-request.** `nvd_available()` gates submissions to a 503; the only downloader is `bin/refresh-nvd.py` (operator tool). Flag any request path that calls `sync_nvd_local_dataset` or otherwise blocks on a network fetch during a scan.
- **PII retention actually runs.** Uploads are deleted once the report is generated; reports + rows are purged by the retention sweep after `PUBLIC_RETENTION_DAYS`. Flag any change that leaves uploads or PII on disk indefinitely.
- **SQL + output safety.** Parameterised queries only. User-supplied values rendered into HTML / email / docx go through Jinja autoescaping / `neutralise_formula` (spreadsheet formula injection). Flag raw interpolation of upload content into a report cell, email body, filename, or `Location` header.
- **Deploy posture.** `nginx-scan.conf` serves Cloudflare ranges only (ufw is the CF filter; `real_ip_header CF-Connecting-IP` before allow/deny), runs as the non-root `scan` user, and must **not** front `scan.patched.im` with a CF Access application.

## Ticket fit

- The change meets its Linear ticket's acceptance criteria and stays within scope — no smuggled-in behaviour, route, or trust-boundary change the ticket doesn't declare. UK English, "estate" never "fleet" in customer-facing copy. In particular, PAT-457 must not add routes to the portal app or place platform/admin credentials on the scan box.
