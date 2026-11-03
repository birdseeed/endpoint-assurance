# Local development setup

Clone-to-running-on-laptop in ~5 commands. Tested on macOS (Andy's Mac), should work the same on Linux.

## Prerequisites

- **Python 3.12** (`python3 --version` should report 3.12.x).
  - macOS: `brew install python@3.12`.
  - Linux: distro packages or `pyenv`.
- **git**, **sqlite3** (preinstalled on macOS; `apt install sqlite3` on Debian/Ubuntu).
- No Docker, no Node, no build step.

## 1. Clone + venv

```bash
git clone git@github.com:patched-im/dashboard.git
cd dashboard
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 2. Environment

Set these in the current shell, in a `.env` file (not git-tracked, not auto-loaded — `main.py` doesn't use python-dotenv), or in your shell rc:

| Var | Required? | Purpose |
|---|---|---|
| `DASHBOARD_API_KEY` | **Yes** | Shared Bearer token for `/api/*`/`/admin/*` middleware (also the auto-fallback when no CF Access identity is present). Any random string for local dev — e.g. `openssl rand -hex 32`. |
| `DASHBOARD_ENV` | For UI login locally | Set to `dev` or `local` to have `/console/{rev}` mint a session cookie as `dev@local` when there's no CF Access header (there never is locally). Without this, the page still renders but you'll need the Bearer token for every `/api/*`/`/admin/*` call — see below. |
| `NVD_API_KEY` | For real scans | NIST NVD API key. Free at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key). Without it, NVD heavily rate-limits and scans take forever. Local-only UI work doesn't need it. |

Quick set:

```bash
export DASHBOARD_API_KEY="$(openssl rand -hex 32)"
export DASHBOARD_ENV="local"
export NVD_API_KEY=""   # leave empty for UI-only work
```

## 3. Initialise the database

`main.py`'s `init_db()` runs at every startup (it's idempotent via `CREATE TABLE IF NOT EXISTS` + try/except ALTERs), so you don't strictly need a separate init step. But to verify everything works before serving:

```bash
python3 -c "from main import init_db; init_db()"
ls -lh dashboard.db
```

The DB now has well beyond the original `scans`/`clients` pair — see the staleness note in [SCHEMA.md](SCHEMA.md); `init_db()` is the authoritative table list.

## 4. Run

```bash
uvicorn main:app --reload --port 8000
```

`--reload` watches for changes and restarts. Open `http://localhost:8000` — it redirects to `/console/{build}`. Cloudflare Access is NOT in front of you locally, so requests go straight to the app.

With `DASHBOARD_ENV=local` (or `dev`) set, the page mints a `dev@local` session cookie automatically and the console works end-to-end without you touching the Bearer token. Without it, `/api/*`/`/admin/*` calls 401 unless you attach `Authorization: Bearer $DASHBOARD_API_KEY` yourself (e.g. via a browser extension, or by scripting against the API directly rather than clicking through the UI).

If `/api/*` calls return `{"error":"Unauthorized"}` from your own browser, confirm:
- `DASHBOARD_API_KEY` is set in the shell that started uvicorn,
- `DASHBOARD_ENV` is `dev` or `local` if you want cookie auth to Just Work locally,
- the page reloaded after the env vars were set (cookie minting happens at request time on `/console/{rev}`, so a plain restart + reload is enough — no template-render-time caching to worry about here).

## What works locally vs what needs real external data

The scanner is upload-only (PAT-572 removed the Microsoft Graph pipeline) — there is no "real Intune tenant" dependency for the CVE scan path any more. What's left needing real external data is narrower:

| Surface | Works locally? | Notes |
|---|---|---|
| Console render (`/console/{rev}`) | ✅ | Renders with an empty DB |
| Home / estate-wide metrics | ✅ | Empty until scans/tenants exist |
| Launch a CVE scan via upload | ✅ | Fully local — upload a devices CSV (see `tests/fixtures/devices_valid.csv` for a valid sample), matched against a local NVD SQLite dataset. Set `NVD_API_KEY` to avoid rate-limiting on a real run. |
| Scan status polling / report download | ✅ | Works once a scan has been submitted |
| Per-tenant Devices / CVE Findings / most console tabs | ✅ for UI, proxy calls will fail closed | These proxy to the Go admin API on `example-api-host` over Tailscale — locally that connection doesn't exist, so proxied reads/writes return an error, but the tab itself renders |
| Certificate view (`/certs`, in-console) | ⚠️ | Same as above — proxies to the go-service `device_certificates` table |

**For meaningful end-to-end testing of the tenant-proxy surfaces** (devices, findings, cert data, etc.), you need either Tailscale access to `example-api-host` or a local instance of the Go admin API from the `patched.im` repo. For most dashboard-side UI/API work, an empty local DB plus the upload-based CVE scan flow is enough — you don't need any of that.

## Optional: hot-reload templates only

The default `--reload` watches `.py` files only. To watch the template too:

```bash
uvicorn main:app --reload --reload-include='*.html' --port 8000
```

## Common issues

- **`ModuleNotFoundError: No module named 'X'`** — venv not activated, or `pip install -r requirements.txt` didn't finish. Re-source the venv.
- **`OperationalError: no such table: scans`** — `init_db()` didn't run. Step 3.
- **Port 8000 already in use** — change `--port 8001` or `lsof -ti:8000 | xargs kill`.
- **`/api/*` returns 401 in the browser** — env var not set in the shell that started uvicorn. See step 2.

## What's intentionally NOT covered here

- **Deploying to the box.** See `AGENTS.md` — push-to-mirror via `deploy.yml` is the primary path; scp is a manual fallback.
- **Editing the production DB.** See OPERATIONS.md.
- **Running/adding tests.** See TESTING.md — there is a `pytest` suite; this doc is about running the app locally, not the test suite.
