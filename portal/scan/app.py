"""app.py — standalone public CVE-scan service (scan.patched.im, PAT-457/PAT-121).

Extracted from the dashboard's public funnel into its own FastAPI app on its own
box (patched-portal-01 sibling), so the staff console no longer carries an
unauthenticated public surface. Everything here is public by design: security is
Turnstile + per-email/per-IP rate limits + OTP email verification + file-size
caps, never Cloudflare Access or a bearer token.

Runs as `uvicorn app:app` on 127.0.0.1:8001 (systemd unit patched-scan.service),
behind nginx for scan.patched.im. State (scan.db, uploads/, reports/, nvd.db)
lives under /var/lib/patched-scan; the app code dir is read-only.
"""

import datetime
import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from db import init_db
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from router import router
from scanner import NVD_DB_PATH, nvd_available, nvd_last_refreshed, nvd_stale
from shared import (
    BASE,
    PUBLIC_SCAN_ENABLED,
    TURNSTILE_DEV_BYPASS,
    TURNSTILE_SECRET,
    _public_retention_loop,
    templates,
    waitlist_unnotified_count,
)
from starlette.types import ASGIApp, Receive, Scope, Send

# PAT-1176: deploy/deploy-portal-01.sh writes this file, atomically, as the
# last step of a successful deploy (same DEPLOYED_SHA=<sha> / DEPLOYED_AT=
# <UTC ISO8601> convention main.py reads for the portal service, PAT-1151).
# Overridable so tests never touch the real repo checkout.
DEPLOYED_SHA_FILE = Path(os.getenv("DEPLOYED_SHA_FILE", str(BASE / "DEPLOYED_SHA")))


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    if not nvd_available():
        # Do NOT block startup or attempt a mid-request download of the NVD feed
        # (the box may have no outbound internet). Scan submissions return a
        # 503-style "temporarily unavailable" until the operator seeds nvd.db
        # via scan/bin/refresh-nvd.py. See deploy/RUNBOOK-scan.md.
        print(f"[startup] WARNING: NVD dataset missing at {NVD_DB_PATH} — "
              f"scan submissions will be refused (503) until it is seeded. "
              f"Run scan/bin/refresh-nvd.py to build it.")
    else:
        print(f"[startup] NVD dataset present at {NVD_DB_PATH}")
    threading.Thread(target=_public_retention_loop, daemon=True).start()
    yield


class PublicScanAvailability:
    """Refuse new work before FastAPI binds Form/File or consumes the body."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        path = scope.get("path", "").rstrip("/")
        creation = path in {
            "/public/scan", "/public/intune-upload", "/public/intune-instructions",
        } or path.startswith("/public/scan/verify/")
        if scope["type"] == "http" and not PUBLIC_SCAN_ENABLED and creation:
            response = templates.TemplateResponse(
                request=Request(scope), name="public_scan_unavailable.html", context={},
                status_code=503, headers={"Cache-Control": "no-store"},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


app = FastAPI(title="Patched public scan", docs_url=None, redoc_url=None,
              openapi_url=None, lifespan=lifespan)
app.add_middleware(PublicScanAvailability)
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")


def _deployed_sha_info() -> dict:
    """PAT-1176: read the DEPLOYED_SHA record written by deploy/deploy-
    portal-01.sh for this service (mirrors main.py's _deployed_sha_info for
    the portal). A missing or unparsable file is reported as null fields,
    never an error: before the first automated deploy runs, or immediately
    after a fresh install, no SHA has been recorded yet - a legitimate
    state, not a bug."""
    sha = None
    deployed_at = None
    try:
        content = DEPLOYED_SHA_FILE.read_text()
    except OSError:
        return {"deployed_sha": None, "deployed_at": None}
    for line in content.splitlines():
        if line.startswith("DEPLOYED_SHA="):
            sha = line[len("DEPLOYED_SHA="):].strip() or None
        elif line.startswith("DEPLOYED_AT="):
            deployed_at = line[len("DEPLOYED_AT="):].strip() or None
    return {"deployed_sha": sha, "deployed_at": deployed_at}


@app.get("/healthz")
def healthz():
    """Unauthenticated liveness probe. Reports whether the NVD dataset is
    present AND actually fresh, so ops can distinguish 'up but cannot scan'
    from a hard outage from 'present but the refresh timer silently died'.
    Also reports Turnstile config state (PAT-893) so ops can tell 'bot
    protection genuinely off for a deliberate local/dev run' from 'operator
    forgot to set TURNSTILE_SECRET' at a glance, without needing shell access.
    deployed_sha/deployed_at (PAT-1176) mirror the portal service's /healthz
    so ops can confirm SHA parity between the two services after a deploy.
    waitlist_unnotified (PAT-2560) is how many waitlist sign ups were stored
    without their notification email being accepted: 0 when mail works. It is
    a count of failures, never the size of the list."""
    last_refreshed = nvd_last_refreshed()
    return JSONResponse({
        "status": "ok",
        "nvd": nvd_available(),
        "nvd_last_refreshed": (
            datetime.datetime.fromtimestamp(last_refreshed, tz=datetime.UTC).isoformat()
            if last_refreshed is not None else None
        ),
        "nvd_stale": nvd_stale(),
        "turnstile_configured": bool(TURNSTILE_SECRET),
        "turnstile_dev_bypass": TURNSTILE_DEV_BYPASS,
        "waitlist_unnotified": waitlist_unnotified_count(),
        **_deployed_sha_info(),
    })


app.include_router(router)
