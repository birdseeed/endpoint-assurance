# Testing strategy

## Short version

**There is an automated `pytest` suite** (`tests/`, 23 files, 300+ tests) covering route-level behaviour, auth/RBAC, and specific regression fixes. Run it before every deploy. A manual smoke-test checklist (below) covers the things the suite deliberately doesn't — real Graph/NVD calls, and eyeballing the rendered UI.

Console interaction behaviour also has a dependency-free Node test harness. It loads the browser-shipped helper from `static/js/console-work.js` against explicit fake DOM objects, so Work selection and service-health classification are covered without a browser or a second test framework.

This supersedes the older "no automated tests, deliberately" stance from early in the project (see "History" below) — the suite grew feature-by-feature as routes and tabs shipped, largely as regression coverage pinned to specific tickets.

## Running the suite

```bash
python3 -m venv venv && source venv/bin/activate   # if not already set up — see SETUP.md
pip install -r requirements.txt
DASHBOARD_API_KEY=test-key python3 -m pytest tests/ -q
npm run test:console
```

Most test files set `DASHBOARD_API_KEY` themselves via `os.environ.setdefault(...)` at import time, but set it in the shell too if you're running a single file in isolation and hit `"Server auth not configured"` 500s.

Tests use `fastapi.testclient.TestClient` against the real `main:app` with a temp SQLite DB (no live Graph/NVD calls, no live Tailscale connection to `example-api-host` — those calls are mocked or expected to fail closed and are asserted accordingly). A few tests print benign lines to stdout during teardown (e.g. `[scheduler] Error: no such table: kv`) — that's the background scheduler thread hitting tables that only exist against the real production DB, not the test fixture DB; it doesn't fail the test run.

## What's covered

Roughly one file per feature area or regression ticket:

| File | Covers |
|---|---|
| `test_agent_config.py` | `GET`/`PATCH /api/tenant/{id}/agent-config` |
| `test_app_control_tab.py` | Application Control is not navigable or activated; its three proxy routes remain registered |
| `test_catalogue_tier_degradation.py` | Software Catalogue tab graceful degradation when a tenant lacks the catalogue tier (PAT-722) |
| `test_certs.py` | Cert inventory classification + expiry endpoints |
| `test_cve_findings_tab.py` | CVE Findings tab data + tab-list consistency |
| `test_deploy_agent_tab.py` | PAT-776 — Deploy Agent tab's generated artifacts (enrollment command/token display) stay readable in both light and dark theme |
| `test_enforcement_audit_tab.py` | Enforcement Evidence is not navigable or activated; its proxy contract remains covered |
| `test_estate_page.py` | PAT-810 — asserts the old standalone "Fleet"/"Estate" nav page (a duplicate of what Home already showed) is gone: no nav item, no section, no `_loadFleet()`, no `<h1>Estate</h1>`/`<h1>Fleet</h1>`. Confirms Home is the sole owner of the estate-wide summary surface. |
| `test_intune_upload.py` | Public Intune CSV upload flow |
| `test_needs_attention_tab.py` | Needs Attention tab + tab-list consistency |
| `test_pat456.py` | Path-traversal filename sanitisation; Bearer middleware on `/admin/*` |
| `test_pat572_upload_scan.py` | CVE-upload-only scan engine (no Graph credentials) |
| `test_pat695.py` | Session-cookie auth (mint on `/console`, accept alongside Bearer) |
| `test_pat696.py` | RBAC — owner vs consultant role, write allow-list |
| `test_pat697.py` | Shared device-freshness threshold config |
| `test_pat698.py` | Cross-tenant triage Home (`build_triage_queue`, `/api/home/triage` graceful degradation), telemetry panels, and confirms `dashboard.html`/old CVE mock scaffolding are actually gone |
| `test_pat783.py` | New Apps triage folded into the Software Catalogue tab (PAT-783/PAT-167) — table rendering, actions column, active-tab detection |
| `test_pat785.py` | Managed CIS Controls view rendering a Windows section even when the upstream returns zero Windows rules for a tenant |
| `test_pat790.py` | Tenant Overview using one consistent tenant-data source (`/admin/tenants/overview`), not a mix of cached + live metrics |
| `test_pat796_791_dashboard.py` | Dashboard-level regression coverage for PAT-791/796 |
| `test_pat798.py` | Freshness wording/thresholds consistently reading the shared `DEVICE_FRESHNESS` config (PAT-697) instead of stale hard-coded values |
| `test_pat815_816_818_silent_failures.py` | Silent-failure hardening for PAT-815/816/818 |
| `test_trial_expiry.py` | Trial-expiry email check |

Several tab-specific tests assert the **actual current tab list** in `console.html` as part of their setup/fixtures. Retired surfaces instead assert absence from navigation and activation while preserving their backend contract coverage. Update these fixtures in the same change as any tab retirement.

`fixtures/` holds sample CSV files (`devices_valid.csv`, `apps_valid.csv`, `malformed.csv`, `wrong_file.csv`) used by the upload-flow tests.

## Manual smoke-test checklist (run after every deploy)

In the browser at `https://dashboard.patched.im`:

1. **CF Access login flow** — incognito window, navigate to `/`, expect the Cloudflare Access challenge → email OTP → redirect through to `/console/{build}`.
2. **Home** — estate-wide stats populate (scans, CVEs, devices, needs-attention rollup).
3. **Customers → pick a tenant → Overview** — tenant workspace loads, sidebar tab list matches the inventory in `docs/API_REFERENCE.md`.
4. **Devices tab** — device list loads (Graph-backed tenants take a few seconds).
5. **CVE Findings / Software Catalogue / CIS Controls** — each tab renders without a console error; CIS Controls shows T2 rule toggles working for a test tenant.
6. **Reports tab → generate + download** — `.docx`/PDF downloads; open it and confirm it renders.
7. **Impersonation** — start a support-impersonation session from a tenant, confirm the read-only banner, confirm write actions are blocked until write mode is explicitly enabled.

On the box (`ssh root@example-prod-host`):

8. `systemctl status patched-dashboard` — `Active: active (running)`.
9. `journalctl -u patched-dashboard --since '5 minutes ago' | grep -iE 'error|exception|traceback'` — should be empty.

If 1–9 pass and `pytest tests/` was green before deploy, the deploy is good.

## History — why there used to be no automated tests

Early in the project (pre-PAT-462-ish) this doc argued against automated tests: single-developer, hard-to-mock Graph/NVD surface, internal-only deployment, trivial schema. That reasoning held while the app was small. It stopped holding once the console grew a dozen-plus tabs and 150+ routes across `/admin/*` — regressions in tab wiring or RBAC are exactly the kind of thing a route-level test catches cheaply and a human clicking through can miss. The suite that exists today grew organically, ticket-by-ticket, rather than from a big-bang test-writing project — that's still consistent with the original "don't chase 80% coverage for its own sake" instinct, just applied per-feature instead of never.

## If you're adding a new tab or route

- Add (or extend) a route-level test in `tests/` — follow the pattern in `test_needs_attention_tab.py` or similar: assert the tab id appears in `console.html`'s tab list, and hit the backing route(s) with `TestClient`.
- Don't add end-to-end browser tests — CF Access in front makes them need service tokens, and the cost still exceeds the value at current scale.
- Keep mocking Graph/NVD out of scope — those integration points remain smoke-tested manually (fixtures cover the upload-only CVE path, which needs neither).
