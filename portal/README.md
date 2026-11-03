# Patched customer portal

The customer-facing portal at `https://app.patched.im` (PAT-331): a read-only,
customer-scoped view of a tenant's own estate — live CIS L1 posture, open CVE
findings, device roster, and audit-ready report downloads. Auth is Cloudflare
Access — Microsoft (Entra) or Google SSO, offered to every tenant, with email
one-time PIN as the fallback (PAT-127) — verified server-side; all data comes
from the platform's customer-scoped `/v1/portal/*` API (PAT-693). No
database, no estate state on this box.

A verified SSO login resolves to a tenant by the tenant's registered email
domain (`tenant_email_domains`, platform migration 0075), with a manual
per-email override (`portal_users`) for edge cases such as a consultant on a
shared admin email. Onboarding a new tenant for SSO is a config + one API
call step, not a code change — see
`docs/ANDY-TODO-sso-cf-access-setup.md`. Customer-facing "how do I sign in"
copy is out of scope here (PAT-115).

## Develop

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-test.txt ruff
.venv/bin/python -m pytest      # JWT failure modes + stubbed-upstream pages
.venv/bin/ruff check .
```

Run locally (you will see the fail-closed 401 page without a real CF Access
JWT, which is correct):

```bash
PORTAL_ACCESS_TEAM_DOMAIN=team.cloudflareaccess.com PORTAL_ACCESS_AUD=dev \
  .venv/bin/uvicorn main:app --reload
```

## Deploy

The latest verified production release and evidence limits are recorded in
[docs/architecture.md](docs/architecture.md#current-state). PAT-2454's paging
fix is installed on both services; linked device-count agreement still awaits
PAT-2459.

`deploy/RUNBOOK.md` is the full bring-up (Hetzner CPX11 → Tailscale →
`deploy/install.sh` → Cloudflare DNS/Origin cert/Access app → smoke test).
`deploy/install.sh` is idempotent and doubles as the upgrade path.

## Two services in this repo

This repo now ships **two** independent FastAPI services that share the
`example-portal-host` box but nothing else — no auth session, no database, no
trust domain:

- **portal** (`main.py`, `:8000`, `app.patched.im`) — the authenticated,
  read-only customer portal described above. Its invariant is unchanged:
  `/healthz` and `/static/*` are its only unauthenticated paths.
- **scan** (`scan/`, `:8001`, `scan.patched.im`) — the **public** CVE-scan /
  Intune-upload funnel (PAT-457/PAT-121), extracted out of the dashboard so the
  staff console no longer carries an unauthenticated surface. Own FastAPI app,
  templates, static, and SQLite + report files under `/var/lib/patched-scan`.
  Unauthenticated by design; security is Turnstile + per-email/per-IP rate
  limits + OTP email verification + file-size caps. Holds only mail + Turnstile
  credentials — no platform secrets. Deploy: `deploy/install-scan.sh` +
  `deploy/RUNBOOK-scan.md`. Seed its NVD dataset with `scan/bin/refresh-nvd.py`
  (the app never downloads it mid-request).

`pytest` runs both suites (`tests/` for the portal, `scan/tests/` for the scan
service); `ruff check .` covers the whole repo.

## Docs

- Spec: Linear PAT-330 (locked); build: PAT-331; platform seam: PAT-693;
  network hardening: PAT-410; public scan service: PAT-457/PAT-121; shared brand-token contract with `dashboard`: PAT-953

`static/vendor/brand/` is the Patched brand kit, vendored verbatim from
`Patched-LTD/branding` and pinned to v2.0.0 — byte-identical to the
dashboard repo's copy.
