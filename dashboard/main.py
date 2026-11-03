#!/usr/bin/env python3
"""
Patched.im Dashboard — dashboard.patched.im
============================================
FastAPI backend with:
  - CVE scan engine (Intune export upload → local NVD match → .docx report)
  - Background scheduler for digests, alerts, and scheduled report sends
  - Scan history and client config persistence

The anonymous public CVE-scan / Intune-upload funnel (PAT-233) was removed
under PAT-866 — it now lives at scan.patched.im (portal repo), so this
process no longer carries an unauthenticated public surface.

Usage:
    pip install fastapi uvicorn python-multipart requests python-docx aiofiles jinja2
    python main.py
"""

import email.encoders
import gzip
import hashlib
import hmac
import html as _html
import json
import os
import re
import uuid
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64
import xml.etree.ElementTree as _ET
import calendar
from datetime import datetime, timezone, timedelta, date
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html.parser import HTMLParser as _HTMLParser
from pathlib import Path
from contextlib import contextmanager
from urllib.parse import urlparse, urlsplit, quote, unquote

import tempfile
import requests
import dashboard_access
import requests as http
import jinja2 as _jinja2
import markdown as _markdown
from fastapi import Depends, FastAPI, Request, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, Response, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from starlette.routing import Match

from intune_upload import (
    parse_csv_safe, detect_csv_type,
    parse_devices_rows, parse_apps_rows,
    generate_devices_report, generate_apps_cve_report,
    neutralise_formula, MAX_UPLOAD_BYTES,
)
from scanner import run_scan_from_upload
from certs import classify_cert_type, compute_days_until_expiry, ALL_CERT_TYPES
import truth
from report_email import email_display_label, render_report_email

# Shared resources (database, templates, mail/config constants+helpers).
from shared import (
    BASE, DB_PATH, REPORTS_DIR,
    _email_env, templates,
    get_db, _open_db_connection,
    NVD_API_KEY, DASHBOARD_API_KEY,
    EMAIL_DRY_RUN,
    PUBLIC_RETENTION_DAYS,
    _EMAIL_RE,
    PUBLIC_BASE_URL,
    EMAIL_RE,
    _send_email, email_delivery_status, email_delivery_check,
    MAIL_SENDER,
    _cleanup_old_public_uploads,
    _public_retention_loop,
    _safe_filename,
)

# ── Config unique to main.py ──
# Connect via MagicDNS FQDN so the address tracks the node across any provider
# migration or tailnet renumber. Caddy's :8443 block is bare (no hostname
# constraint) — security is the Tailscale bind + ACL (tag:main → tag:api:8443).
# verify=False: Caddy presents its internal CA cert; WireGuard is the
# transport-security layer.
# Env-overridable (PAT-740) so the local E2E harness can point at a local
# platform stack; the default keeps prod behaviour unchanged.
PATCHED_API_INTERNAL = os.getenv(
    "PATCHED_API_INTERNAL", "https://patched-api-01.example-tailnet.ts.net:8443"
)
_VERIFY_INTERNAL = False

# PAT-687 / H1: the internal admin API now requires `Authorization: Bearer <ADMIN_API_TOKEN>`
# (defence-in-depth behind the Tailscale bind). We attach that header ONLY on calls to
# PATCHED_API_INTERNAL — never on external calls (Slack, Graph) — via a Session
# subclass. When ADMIN_API_TOKEN is unset the header is omitted, so this is a no-op until the
# token is provisioned on both this box and patched-api-01 (lets the rollout be sequenced safely).
ADMIN_API_TOKEN = os.getenv("ADMIN_API_TOKEN", "")

# ── PAT-695: session-cookie auth + owner/consultant RBAC ──
# DASHBOARD_OPERATORS: comma-separated emails (case-insensitive) that get the
# `owner` role. Every other authenticated email is a `consultant`, including
# when the list is unset or empty. Bearer administration is authenticated separately.
DASHBOARD_OPERATORS = frozenset(
    e.strip().lower() for e in os.getenv("DASHBOARD_OPERATORS", "").split(",") if e.strip()
)
# DASHBOARD_ENV: {dev, local} lets local dev mint a session cookie as dev@local
# when the CF-Access header is absent. Anything else (incl. unset) = production.
DASHBOARD_ENV = os.getenv("DASHBOARD_ENV", "").strip().lower()
_DEV_ENV = DASHBOARD_ENV in ("dev", "local")
SESSION_COOKIE  = "patched_session"
SESSION_MAX_AGE = 12 * 60 * 60  # 12h, re-minted on every /console load
CONSOLE_BUILD_ID = "2026-10-04-pat2404"


# PAT-1369: an unreachable/timed-out PATCHED_API_INTERNAL let a bare
# requests.ConnectionError/Timeout escape every `/admin/*` proxy route (neither
# stacked BaseHTTPMiddleware in this file catches it), taking down the whole
# process for the request's duration, including unrelated requests on other
# connections, which is far worse than one failed panel. Every call the proxy
# family makes goes through this one Session subclass (already the choke point
# for PATCHED_API_INTERNAL-only Bearer-token injection above), so that's also
# the one place to make connection/timeout failures degrade instead of crash.
# Scoped to PATCHED_API_INTERNAL only, same as the Bearer injection: external
# calls (Slack, Telegram, Graph, Cloudflare) already carry their own
# try/except and are untouched here.
# PAT-1813: ConnectionError/Timeout only covers a connection that never
# happens. One that happens and then dies mid-response-body (peer reset,
# a Tailscale path drop after headers are already in) raises
# ChunkedEncodingError/ContentDecodingError instead, from inside the same
# try block (see _ApiSession.request below) — added to the same except.
def _degraded_upstream_response(url: str, detail: str, status_code: int = 503) -> "requests.Response":
    """Synthesize a requests.Response standing in for a PATCHED_API_INTERNAL
    call that never got a real answer. Every proxy route already treats a
    non-2xx requests.Response as "forward this to the client" (via
    `_proxy_json` or its own status_code check), so this lets that existing
    handling run unchanged instead of every call site needing its own
    try/except. The body carries `degraded: true` so a route (or the console)
    can tell "upstream is down" apart from "upstream answered with nothing",
    the PAT-912/PAT-837/PAT-960 shape this estate does not want repeated."""
    resp = requests.Response()
    resp.status_code = status_code
    resp.url = url
    resp.encoding = "utf-8"
    resp._content = json.dumps(
        {"error": "upstream unreachable", "degraded": True, "detail": detail}
    ).encode("utf-8")
    resp.headers["Content-Type"] = "application/json"
    return resp


# PAT-2408: nothing a caller supplies may change which upstream admin-API path
# carries the admin bearer. Two controls, both here:
#   * `_seg` percent-encodes every caller-influenced path segment before it is
#     placed in an upstream URL (and refuses "", "." and "..", which encoding
#     does not neutralise: urllib3 decodes %2e and removes dot-segments, so
#     `%2e%2e` once turned `/admin/tenants/<id>/agent-health` into
#     `/admin/agent-health`);
#   * `_ApiSession.request` refuses any upstream URL whose path still holds a
#     dot-segment, as the backstop for a call site that forgets `_seg`.
# Tenant ids are additionally required to be canonical UUIDs at the edge
# (`_require_canonical_tenant_id`, attached app-wide below).
class UnsafePathSegment(ValueError):
    """A caller-supplied value cannot safely be one upstream path segment."""


def _seg(value) -> str:
    """Percent-encode one caller-influenced upstream path segment."""
    s = str(value)
    if s in ("", ".", "..") or "\x00" in s:
        raise UnsafePathSegment("invalid path segment")
    return quote(s, safe="")


def _is_canonical_uuid(value) -> bool:
    """True only for the canonical lowercase hyphenated UUID form."""
    if not isinstance(value, str):
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _upstream_path_has_dot_segment(url: str) -> bool:
    try:
        path = urlsplit(url).path
    except ValueError:
        return True
    for part in path.split("/"):
        # Decode twice: one layer for this client, one for a proxy in between.
        if unquote(unquote(part)) in (".", ".."):
            return True
    return False


class _ApiSession(http.Session):
    utils = http.utils  # preserve `http.utils.quote(...)` call sites

    def request(self, method, url, *args, **kwargs):
        if (
            isinstance(url, str)
            and url.startswith(PATCHED_API_INTERNAL)
            and _upstream_path_has_dot_segment(url)
        ):
            print(f"[admin-proxy] refused {method} with a dot-segment in the upstream path")
            resp = requests.Response()
            resp.status_code = 400
            resp.url = url
            resp.encoding = "utf-8"
            resp._content = json.dumps({"error": "Invalid identifier."}).encode("utf-8")
            resp.headers["Content-Type"] = "application/json"
            return resp
        if ADMIN_API_TOKEN and isinstance(url, str) and url.startswith(PATCHED_API_INTERNAL):
            headers = dict(kwargs.get("headers") or {})
            headers.setdefault("Authorization", f"Bearer {ADMIN_API_TOKEN}")
            kwargs["headers"] = headers
        if isinstance(url, str) and url.startswith(PATCHED_API_INTERNAL):
            try:
                return super().request(method, url, *args, **kwargs)
            except (
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                # PAT-1813: requests' Session.send() eagerly reads
                # `r.content` for every non-streamed call (the default here
                # — no proxy route passes stream=True), and that read
                # happens INSIDE this same try block, not after it returns.
                # When the TCP connection dies mid-body (peer reset,
                # Tailscale path drop) rather than never connecting at all,
                # requests raises ChunkedEncodingError/ContentDecodingError
                # from that read — both plain requests.RequestException
                # subclasses, NOT ConnectionError/Timeout — so they escaped
                # this except clause and reached FastAPI as a bare 500.
                # Reproduced directly: a raw socket that accepts the
                # connection, sends a partial body, then resets raises
                # exactly requests.exceptions.ChunkedEncodingError here.
                # Same "upstream did not answer" shape as the two caught
                # above, so it gets the same degraded treatment.
                requests.exceptions.ChunkedEncodingError,
                requests.exceptions.ContentDecodingError,
            ) as e:
                print(f"[admin-proxy] {method} {url} unreachable: {e}")
                return _degraded_upstream_response(url, str(e))
        return super().request(method, url, *args, **kwargs)


http = _ApiSession()
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

# PAT-837: portal Cloudflare Access AUD-drift monitor. Detects the exact
# 2026-07-12 incident (app.patched.im login broken for every user for ~9 days,
# nothing alerted) — the CF Access app's AUD rotated and PORTAL_ACCESS_AUD on
# patched-portal-01/patched-api-01 went stale. The first four vars
# (CLOUDFLARE_API_TOKEN/CLOUDFLARE_ACCOUNT_ID/CLOUDFLARE_ACCESS_APP_ID/
# PORTAL_ACCESS_AUD) must be set for the AUD comparison to run at all; it
# no-ops (logs once per tick, reports portal_auth "unconfigured", never a
# false positive) if any of those are missing. Alert delivery is different
# (PAT-988, repointed to Slack under PAT-1010): the AUD comparison still runs
# without SLACK_WEBHOOK_URL, but portal_auth is forced to "degraded" — even
# on a currently-passing comparison — because a monitor that can't tell
# anyone about a break is not healthy. This alert was originally emailed to
# OPS_ALERT_EMAIL (never set on prod-01) and moved to Slack because
# EMAIL_DRY_RUN=1 on prod-01 makes _send_email() report success without ever
# sending — an unconfigured mail path would have silently satisfied this
# guard instead of tripping it. See docs/RUNBOOK-portal-auth-healthcheck.md
# for what each var is, how to provision it, and the restart required after
# setting SLACK_WEBHOOK_URL.
CLOUDFLARE_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN", "")
CLOUDFLARE_ACCOUNT_ID = os.getenv("CLOUDFLARE_ACCOUNT_ID", "")
CLOUDFLARE_ACCESS_APP_ID = os.getenv("CLOUDFLARE_ACCESS_APP_ID", "")
# Dashboard's own copy of the value patched-portal-01 and patched-api-01 are
# each independently configured with — same var name, so it's a direct
# copy-paste from either box's env file. This check compares Cloudflare's
# live AUD against THIS value, not against the other two boxes directly, so
# it still catches drift even if both boxes went stale in the same way.
PORTAL_ACCESS_AUD_EXPECTED = os.getenv("PORTAL_ACCESS_AUD", "")
# PAT-435: Calendly webhook HMAC-SHA256 signing secret.
# Get from Calendly portal: Integrations → Webhooks → subscription → Signing key.
# CF Access must bypass /webhooks/calendly so Calendly can reach this endpoint.
CALENDLY_WEBHOOK_SECRET = os.getenv("CALENDLY_WEBHOOK_SECRET", "")

# ── PAT-780: global Docs section ────────────────────────────────────────────
# v1 reads Markdown straight out of this repo's own checkout (the "static
# clone refreshed by deploy" option from the ticket) rather than calling the
# GitHub API — the box's checkout under /opt/patched-dashboard IS a mirror of
# this GitHub repo, refreshed on every deploy, so no token/API round-trip is
# needed to satisfy "read-only cached mirror of a GitHub documentation repo".
# DOCS_ROOT_DIR lets ops point at a different in-checkout folder without a
# code change; DOCS_GITHUB_REPO/DOCS_GITHUB_BRANCH only drive the "View on
# GitHub" link, no credentials involved.
DOCS_ROOT_DIR = os.getenv("DOCS_ROOT_DIR", "docs")
DOCS_GITHUB_REPO = os.getenv("DOCS_GITHUB_REPO", "Patched-LTD/dashboard")
DOCS_GITHUB_BRANCH = os.getenv("DOCS_GITHUB_BRANCH", "main")
_DOCS_ROOT = (BASE / DOCS_ROOT_DIR).resolve()

# ── PAT-992: deploy-drift check ─────────────────────────────────────────────
# DASHBOARD_REPO_DIR is the box's own git checkout (the same path
# scripts/deploy.sh calls REPO_DIR and uses it in _ops_dashboard_version());
# DEPLOYED_SHA_FILE is where scripts/deploy.sh records the commit it
# last confirmed running (see that script's own header comment). Both are
# purely local paths — nothing here ever reaches GitHub.
DASHBOARD_REPO_DIR = os.getenv("DASHBOARD_REPO_DIR", "/opt/patched-dashboard")
DEPLOYED_SHA_FILE = os.getenv(
    "DEPLOYED_SHA_FILE", os.path.join(DASHBOARD_REPO_DIR, "DEPLOYED_SHA")
)
# When this process itself started. scripts/deploy.sh writes DEPLOYED_SHA_FILE
# deliberately LAST — after the restart, after the smoke suite — because that
# ordering is the correctness property PAT-992 exists for; it must not be
# traded away for tidier reporting. That means there is a real window, every
# successful deploy, between "this process came up on the new commit" and
# "the record catches up to say so" — the drift check below uses this
# timestamp to recognise that window instead of reporting a false positive
# inside it (see _DEPLOY_INFLIGHT_GRACE and _run_deploy_drift_check_tick).
_PROCESS_STARTED_AT = datetime.now(timezone.utc)
# Bound on how long a mismatch is given the benefit of the doubt as "still
# deploying" before it's treated as a real problem (PAT-992, FIX 2 from
# independent review). Chosen well above the slowest normal phase of a
# deploy — `pip install -r requirements.txt` can run tens of seconds,
# restart_service's own bounded wait is up to ~10s of retries, and the smoke
# suite adds more — while staying short enough that a deploy which is
# actually stuck (smoke hung, or crashed before ever reaching the write) gets
# flagged the same hour it broke rather than sitting silently plausible for
# the rest of the day. Ten minutes comfortably covers the slow end of a real
# deploy on this box without giving a stuck one anywhere near that long to
# hide.
_DEPLOY_INFLIGHT_GRACE = timedelta(minutes=10)

# ── PAT-1427: fast path for local/bounded checks + row freshness ───────────
# scheduler_loop's hourly cadence is right for digests/reports/alerts, but it
# meant every check_statuses row -- including deploy_drift and
# maintenance_prod01, both cheap local reads with no network involved -- was
# never more than an hour fresh, and nothing on a served row said how old it
# was. Two live incidents on 2026-08-19 showed the cost of that: a
# just-restarted process stayed `unconfigured` (a false SHA-mismatch claim)
# ten minutes after DEPLOYED_SHA had already been corrected, and a stale
# maintenance_prod01 row asserted "stray config backups: not reported by
# this emitter" a full tick after prod-01's own emitter started reporting it
# -- inventing a false absence, not merely under-reporting a stale ok. See
# fast_check_loop (near scheduler_loop) for which checks qualify for the fast
# path and why, and _get_check_statuses/_check_status_freshness for the
# age_seconds/stale fields every row now carries.
_FAST_CHECK_INTERVAL = timedelta(minutes=2)
# Checks recomputed by fast_check_loop in addition to the hourly
# scheduler_loop -- both are local file reads (deploy_drift also runs a
# bounded, already-fail-closed local `git status`), never a network call.
_FAST_PATH_CHECK_NAMES = frozenset({"deploy_drift", "maintenance_prod01"})
# "Sensible threshold" (PAT-1427) for the `stale` flag on a served row: a
# generous multiple of whichever loop actually recomputes that row, so a row
# that's merely a bit behind its own cadence isn't flagged, but one that has
# stopped updating is. Rows not on the fast path (including
# maintenance_api01/maintenance_portal01, which reach another box over HTTP,
# and every tick_* heartbeat) are only ever recomputed by the hourly
# scheduler_loop, hence the much longer default. Note the three daily-gated
# scheduler_loop ticks (tick_public_uploads_cleanup/report_schedules/
# trial_expiry, each guarded by `now.hour == N`) will read `stale: true` for
# most of the day under this default -- expected for a once-a-day job, not a
# regression; this ticket's scope is the checks that should read current
# within minutes, not modelling every tick's own cadence.
_FAST_CHECK_STALE_AFTER = _FAST_CHECK_INTERVAL * 3
_DEFAULT_CHECK_STALE_AFTER = timedelta(hours=2)

# ── PAT-989: maintenance-facts drift check (prod-01 + api-01 + portal-01) ──
# MAINTENANCE_FACTS_FILE is where deploy/patched-maintenance-facts.sh (this
# box) writes its hourly patch/reboot/timer snapshot — read directly since
# this process runs on patched-prod-01 itself. api-01 and portal-01 run their
# own emitters against the identical JSON schema; this box reaches them over
# HTTP (see _run_maintenance_drift_check_tick for the internal-vs-public-
# endpoint split and why portal-01's shape is reduced).
MAINTENANCE_FACTS_FILE = os.getenv(
    "MAINTENANCE_FACTS_FILE", "/var/lib/patched/maintenance.json"
)
# A source's facts are only trusted for this long before the check reports
# unconfigured ("the facts timer stopped running") rather than silently
# acting on a stale snapshot as if it were current.
_MAINTENANCE_STALE_AFTER = timedelta(hours=3)
# ── PAT-137: Impersonation session ──────────────────────────────────────────
IMP_COOKIE   = "pat_imp"
IMP_MAX_AGE  = 3600  # 1 hour

def _imp_encode(payload: dict) -> str:
    """Encode + HMAC-sign an impersonation session payload."""
    j = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    b = base64.urlsafe_b64encode(j.encode()).decode().rstrip("=")
    mac = hmac.new((DASHBOARD_API_KEY or "").encode(), b.encode(), hashlib.sha256).hexdigest()
    return f"{b}.{mac}"

def _imp_decode(token: str) -> dict | None:
    """Verify HMAC + decode. Returns None if invalid or expired."""
    if not token or "." not in token:
        return None
    idx = token.rfind(".")
    b, mac = token[:idx], token[idx + 1:]
    expected = hmac.new((DASHBOARD_API_KEY or "").encode(), b.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected):
        return None
    try:
        padded = b + "=" * (-len(b) % 4)
        j = base64.urlsafe_b64decode(padded.encode()).decode()
        return json.loads(j)
    except Exception:
        return None

def _imp_get(request: Request) -> dict | None:
    """Read + verify the impersonation cookie. Returns None if missing/invalid/expired."""
    token = request.cookies.get(IMP_COOKIE)
    if not token:
        return None
    data = _imp_decode(token)
    if not data:
        return None
    try:
        exp = datetime.fromisoformat(data["expires_at"])
        if exp < datetime.now(timezone.utc):
            return None
    except Exception:
        return None
    return data

def _imp_log(session_id: str, tenant_id: str, actor_email: str, action: str,
             started_at: str, ended_at: str | None = None, duration_seconds: int | None = None):
    """Write one row to impersonation_audit_log."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO impersonation_audit_log "
            "(id, session_id, tenant_id, actor_email, action, started_at, ended_at, duration_seconds, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), session_id, tenant_id, actor_email, action,
             started_at, ended_at, duration_seconds, now),
        )


# ══════════════════════════════════════════════════════════════════════════════
# PAT-695: session cookie, RBAC classifier, destructive confirmation, audit log
# ══════════════════════════════════════════════════════════════════════════════
# Session cookie: base64url(email|expiry).HMAC-SHA256(dashboard-session-v2:payload).
# The MAC domain invalidates all legacy cookies minted from unverified headers.
# keyed with DASHBOARD_API_KEY (no new secret to provision). Minted on /console
# from the verified CF-Access identity; accepted by the auth middleware in place of the
# shared Bearer token, so the token no longer needs to be embedded in the page.

def _session_encode(email: str, expiry: int) -> str:
    # base64url the `email|expiry` payload so the cookie value carries only
    # cookie-safe chars (an email's `@` would otherwise force header-quoting).
    b = base64.urlsafe_b64encode(f"{email}|{expiry}".encode()).decode().rstrip("=")
    mac = hmac.new((DASHBOARD_API_KEY or "").encode(), f"dashboard-session-v2:{b}".encode(), hashlib.sha256).hexdigest()
    return f"{b}.{mac}"


def _session_decode(token: str) -> str | None:
    """Verify HMAC + expiry. Returns the email on success, else None."""
    if not DASHBOARD_API_KEY or not token or len(token) > 4096 or "." not in token:
        return None
    idx = token.rfind(".")
    b, mac = token[:idx], token[idx + 1:]
    if not re.fullmatch(r"[0-9a-f]{64}", mac):
        return None
    expected = hmac.new((DASHBOARD_API_KEY or "").encode(), f"dashboard-session-v2:{b}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected):
        return None
    try:
        padded = b + "=" * (-len(b) % 4)
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
    except Exception:
        return None
    jdx = raw.rfind("|")
    if jdx < 0:
        return None
    email, expiry_s = raw[:jdx], raw[jdx + 1:]
    try:
        if int(expiry_s) < int(time.time()):
            return None
    except ValueError:
        return None
    return email or None


def _cf_email(request: Request) -> str | None:
    """Email from a verified dashboard Access JWT, cached for this request."""
    return dashboard_access.resolve_email(request)


def _role_for_email(email: str | None) -> str:
    """Grant owner only to an explicitly configured operator email.

    Missing or empty configuration leaves session users as consultants. The
    separately authenticated Bearer administration path does not use this helper.
    """
    if email and email.strip().lower() in DASHBOARD_OPERATORS:
        return "owner"
    return "consultant"


def _compile(rules):
    return [(m, re.compile(p)) for (m, p) in rules]


# Writes a consultant IS allowed to perform (report generate/email, account
# notes, delivery contacts, report schedules). Everything else that mutates is
# owner-only — "when unsure, owner-only for writes" is the safe default.
_CONSULTANT_WRITE_ALLOW = _compile([
    ("POST",   r"^/admin/tenants/[^/]+/report-records/generate$"),
    ("POST",   r"^/admin/tenants/[^/]+/reports/email$"),
    ("POST",   r"^/admin/tenants/[^/]+/account$"),
    ("PUT",    r"^/admin/tenants/[^/]+/service-engagement$"),
    ("POST",   r"^/admin/tenants/[^/]+/delivery-contacts$"),
    ("PUT",    r"^/admin/tenants/[^/]+/delivery-contacts/[^/]+$"),
    ("DELETE", r"^/admin/tenants/[^/]+/delivery-contacts/[^/]+$"),
    ("POST",   r"^/admin/tenants/[^/]+/report-schedules$"),
    ("PUT",    r"^/admin/tenants/[^/]+/report-schedules/[^/]+$"),
    ("DELETE", r"^/admin/tenants/[^/]+/report-schedules/[^/]+$"),
    ("POST",   r"^/admin/conversion-events$"),
    ("POST",   r"^/api/tenant/[^/]+/signal$"),  # PAT-676: dashboard-login signal — benign, any authenticated role
])

# PAT-1481: broad endpoint execution is not a Dashboard capability.  Keep the
# historical read/cancel/delete routes for evidence and recovery, but reject
# every legacy mutation that can add delivery authority in one place before a
# handler can contact patched-api-01.  This is intentionally path/method
# based: the handlers remain available as read-only compatibility
# documentation, while the middleware is the single fail-closed enforcement
# point for browser and Bearer callers.  PAT-2249 removed the local catalogue
# and vendor-outreach routes this list also used to cover, so their rules went
# with them.  PAT-2299 removed the rollout-create proxy, and its rule with it.
_LEGACY_EXECUTION_QUARANTINE_RULES = _compile([
    ("POST",  r"^/admin/automations/installomator_sync/trigger$"),
    ("POST",  r"^/admin/devices/[^/]+/removals$"),
    ("PUT",   r"^/admin/tenants/[^/]+/ring-config$"),
    ("PUT",   r"^/admin/tenants/[^/]+/ring-devices/[^/]+$"),
    ("POST",  r"^/admin/tenants/[^/]+/ring-rollouts/[^/]+/(?:resume|skip|emergency)$"),
    ("PATCH", r"^/admin/tenants/[^/]+/app-rings/.*$"),
])
_LEGACY_EXECUTION_QUARANTINE_BODY = {
    "error": "Legacy execution is quarantined.",
    "code": "legacy_execution_quarantined",
    "detail": "Dashboard permits read-only evidence and authority-reducing cancellation or deletion, not legacy package, rollout, self-service, mirror, hosting, or app-removal execution.",
}


class _StrictJSONBodyError(ValueError):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code


def _reject_nonstandard_json_constant(value: str):
    raise ValueError(f"non-standard JSON constant: {value}")


async def _read_strict_new_app_decision_body(
    request: Request, max_bytes: int = 4096
) -> tuple[bytes, str]:
    """Read one canonical decision field without Go's ambiguous key matching.

    Preserve object pairs so case-variant and exact duplicate keys cannot be
    collapsed before validation. The bound matches the existing strict PUT
    proxy convention and rejects overflow before buffering an unbounded body.
    """
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > max_bytes:
                raise _StrictJSONBodyError(
                    413, f"Request body exceeds the {max_bytes}-byte route limit."
                )
            body.extend(chunk)
    except _StrictJSONBodyError:
        raise
    except Exception as exc:
        raise _StrictJSONBodyError(400, "Could not read request body.") from exc

    try:
        text = bytes(body).decode("utf-8")
        payload = json.loads(
            text,
            object_pairs_hook=tuple,
            parse_constant=_reject_nonstandard_json_constant,
        )
    except (TypeError, ValueError, UnicodeDecodeError) as exc:
        raise _StrictJSONBodyError(
            400, "Request body must be one valid JSON object with no trailing data."
        ) from exc
    if not isinstance(payload, tuple):
        raise _StrictJSONBodyError(400, "Request body must be a JSON object.")

    decision_fields = [
        (key, value) for key, value in payload
        if isinstance(key, str) and key.casefold() == "decision"
    ]
    if len(decision_fields) != 1:
        raise _StrictJSONBodyError(400, "decision must appear exactly once.")
    key, decision = decision_fields[0]
    if key != "decision":
        raise _StrictJSONBodyError(400, "decision field name is case-sensitive.")
    if not isinstance(decision, str):
        raise _StrictJSONBodyError(400, "decision must be a string.")
    return bytes(body), decision


async def _read_strict_allowlist_body(request: Request, max_bytes: int) -> tuple[bytes, bool]:
    """Read one allowlist JSON object under the upstream route's exact limit.

    The legacy Go handlers read only 8192 bytes for POST and 4096 for PUT. A
    valid JSON object ending exactly at that boundary could therefore hide
    trailing attacker-controlled bytes from the upstream decoder. Read one
    byte beyond the route limit, reject overflow, and reject any input whose
    meaning could differ under Go's case-insensitive struct-field matching.
    """
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > max_bytes:
                raise _StrictJSONBodyError(
                    413, f"Request body exceeds the {max_bytes}-byte route limit."
                )
            body.extend(chunk)
    except _StrictJSONBodyError:
        raise
    except Exception as exc:
        raise _StrictJSONBodyError(400, "Could not read request body.") from exc

    try:
        text = bytes(body).decode("utf-8")
        payload = json.loads(
            text,
            object_pairs_hook=tuple,
            parse_constant=_reject_nonstandard_json_constant,
        )
    except (TypeError, ValueError, UnicodeDecodeError) as exc:
        raise _StrictJSONBodyError(
            400, "Request body must be one valid JSON object with no trailing data."
        ) from exc
    if not isinstance(payload, tuple):
        raise _StrictJSONBodyError(400, "Request body must be a JSON object.")

    enforcement_fields = [
        (key, value) for key, value in payload
        if isinstance(key, str) and key.casefold() == "enforcement"
    ]
    requests_uninstall = any(
        value == "marked_for_uninstall" for _key, value in enforcement_fields
    )
    # Preserve quarantine semantics for every recognisable uninstall request,
    # including the case-variant/duplicate shapes Go would otherwise accept.
    if requests_uninstall:
        return bytes(body), True
    if len(enforcement_fields) > 1:
        raise _StrictJSONBodyError(400, "enforcement must appear exactly once.")
    if enforcement_fields and enforcement_fields[0][0] != "enforcement":
        raise _StrictJSONBodyError(400, "enforcement field name is case-sensitive.")
    return bytes(body), False


async def _read_strict_app_policy_body(request: Request, max_bytes: int = 8192) -> tuple[bytes, dict]:
    """Read one bounded, unambiguous app-policy upsert body."""
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > max_bytes:
                raise _StrictJSONBodyError(413, f"Request body exceeds the {max_bytes}-byte route limit.")
            body.extend(chunk)
    except _StrictJSONBodyError:
        raise
    except Exception as exc:
        raise _StrictJSONBodyError(400, "Could not read request body.") from exc
    try:
        payload = json.loads(bytes(body).decode("utf-8"), object_pairs_hook=tuple,
                             parse_constant=_reject_nonstandard_json_constant)
    except (TypeError, ValueError, UnicodeDecodeError) as exc:
        raise _StrictJSONBodyError(400, "Request body must be one valid JSON object with no trailing data.") from exc
    if not isinstance(payload, tuple):
        raise _StrictJSONBodyError(400, "Request body must be a JSON object.")

    allowed = {"team_id", "bundle_id", "winget_id", "name", "platform", "policy", "enforcement_tier", "notes", "min_version"}
    result = {}
    seen = set()
    for key, value in payload:
        if not isinstance(key, str) or key.casefold() in seen:
            raise _StrictJSONBodyError(400, "Request body contains duplicate or case-colliding fields.")
        seen.add(key.casefold())
        if key not in allowed:
            raise _StrictJSONBodyError(400, "Request body contains an unsupported app-policy field.")
        nullable = {"team_id", "bundle_id", "winget_id", "name", "min_version"}
        if not isinstance(value, str) and not (key in nullable and value is None):
            raise _StrictJSONBodyError(400, f"{key} must be a string{', or null' if key in nullable else ''}.")
        result[key] = value
    if result.get("platform") not in {"any", "macos", "windows"}:
        raise _StrictJSONBodyError(400, "platform must be one of any, macos or windows.")
    if result.get("policy") not in {"mandatory", "approved", "unapproved", "unmanaged"}:
        raise _StrictJSONBodyError(400, "policy must be mandatory, approved, unapproved or unmanaged.")
    if not any(isinstance(result.get(key), str) and result[key].strip()
               for key in ("team_id", "bundle_id", "winget_id", "name")):
        raise _StrictJSONBodyError(400, "An app-policy identity is required.")
    return json.dumps(result, separators=(",", ":"), sort_keys=True).encode("utf-8"), result


def _app_policy_audit_context(tenant_id: str, body: dict) -> dict:
    identity = {key: body[key] for key in ("team_id", "bundle_id", "winget_id", "name") if body.get(key)}
    return {"tenant_id": tenant_id, "software": {**identity, "platform": body["platform"]},
            "requested_policy": body["policy"]}


def _app_policy_matches_upsert(policy: dict, body: dict) -> bool:
    """Mirror the platform's complete app-policy conflict tuple."""
    if policy.get("platform") != body["platform"]:
        return False
    for key in ("team_id", "bundle_id", "winget_id"):
        prior = policy.get(key) or ""
        requested = body.get(key) or ""
        if key == "winget_id":
            prior = str(prior).strip().lower()
            requested = str(requested).strip().lower()
        if prior != requested:
            return False
    return str(policy.get("name") or "").lower() == str(body.get("name") or "").lower()


async def _app_policy_before_snapshot(tenant_id: str, body: dict) -> str:
    """Best-effort bounded prior-state lookup which never gates the write."""
    context = _app_policy_audit_context(tenant_id, body)
    try:
        r = await run_in_threadpool(
            http.get, f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/app-policies",
            timeout=5, verify=_VERIFY_INTERNAL,
        )
        if r.status_code != 200:
            return json.dumps({**context, "prior_state": "unavailable", "lookup_status": r.status_code}, sort_keys=True)
        policies = r.json().get("policies", [])
        if not isinstance(policies, list):
            raise ValueError("invalid policy list")
        matches = [p for p in policies if isinstance(p, dict) and _app_policy_matches_upsert(p, body)]
        return json.dumps({**context, "prior_state": matches[0] if len(matches) == 1 else None}, sort_keys=True)
    except Exception:
        return json.dumps({**context, "prior_state": "unavailable"}, sort_keys=True)


# Destructive/high-risk routes: logged to the audit trail (allowed or denied).
_DESTRUCTIVE_RULES = _compile([
    # PAT-1371: manually triggering the one endpoint-supported automation
    # can change catalogue state, so it is owner-only, audited and confirmed.
    ("POST",   r"^/admin/automations/installomator_sync/trigger$"),
    ("POST",   r"^/admin/tenants$"),
    ("DELETE", r"^/admin/tenants/[^/]+/purge$"),
    ("DELETE", r"^/admin/tenants/[^/]+$"),
    ("POST",   r"^/admin/tenants/[^/]+/restore$"),
    ("DELETE", r"^/admin/tenants/[^/]+/devices/[^/]+$"),
    ("POST",   r"^/admin/devices/[^/]+/revoke$"),
    ("POST",   r"^/admin/tenants/[^/]+/enrollment-tokens$"),
    # PAT-1405: approval and recipient-link issue mutate immutable commercial
    # evidence and therefore always enter the privileged audit trail.
    ("POST",   r"^/admin/tenants/[^/]+/assessment-artifacts/approve$"),
    ("POST",   r"^/admin/tenants/[^/]+/assessment-artifacts/[^/]+/download-tokens$"),
    # PAT-2046: Homebrew CVE mapping review queue writes — curate (map or
    # accept-suggestion) or dismiss a queued formula/cask, which changes what
    # CVE findings the whole estate sees. Audit-logged.
    ("POST",   r"^/admin/homebrew/review/[^/]+/map$"),
    ("POST",   r"^/admin/homebrew/review/[^/]+/accept-suggestion$"),
    ("POST",   r"^/admin/homebrew/review/[^/]+/dismiss$"),
    # PAT-2404: reviewing a reported software identity into the curated
    # catalogue, and withdrawing one, change what the platform treats as a
    # known product for every tenant. Owner-only (not in
    # _CONSULTANT_WRITE_ALLOW) and audit-logged, like the Homebrew writes.
    ("POST",   r"^/admin/software-catalogue/reviews$"),
    ("POST",   r"^/admin/software-catalogue/aliases/[^/]+/retire$"),
    # PAT-2097: acknowledging a cross-tenant Unapproved-software alert is a
    # tenant-state write (records that staff has seen it) even though it
    # resolves nothing on its own. Audit-logged like the other tenant
    # governance writes below.
    ("POST",   r"^/admin/tenants/[^/]+/software-alerts/[^/]+/acknowledge$"),
    # PAT-832: browser-extension removal — queues destructive file deletion on
    # endpoints (agent PAT-829). Audit-logged, incl. consultant RBAC denials.
    ("POST",   r"^/admin/tenants/[^/]+/extension-removals$"),
    ("DELETE", r"^/admin/tenants/[^/]+/extension-removals/[^/]+$"),
    # PAT-128: customer portal access grant/revoke — directly controls who can
    # sign in to a tenant's customer portal. Audit-logged, incl. RBAC denials.
    ("POST",   r"^/admin/tenants/[^/]+/portal-users$"),
    ("DELETE", r"^/admin/tenants/[^/]+/portal-users/[^/]+$"),
    # PAT-1990: sending the portal welcome email is an outbound message to a
    # named customer individual carrying sign-in instructions. It is not
    # reversible once delivered, so it carries the same central audit row and
    # the same typed-confirmation bar as the grant/revoke above.
    ("POST",   r"^/admin/tenants/[^/]+/portal-users/[^/]+/welcome$"),
    ("POST",   r"^/api/credentials$"),
    ("PUT",    r"^/api/credentials/[^/]+$"),
    ("DELETE", r"^/api/credentials/[^/]+$"),
    ("POST",   r"^/admin/impersonation/write-mode$"),
    ("POST",   r"^/admin/tenants/[^/]+/webhooks$"),
    ("DELETE", r"^/admin/tenants/[^/]+/webhooks/[^/]+$"),
    # PAT-710: Ops panel guarded triggers — always audit-logged.
    ("POST",   r"^/api/ops/firewall-apply$"),
    # PAT-799: config-style high-risk writes named in the safety audit — no
    # named-resource echo needed (nothing is deleted), but every one of these
    # now gets a confirmation modal client-side and an audit row with a
    # before/after snapshot server-side.
    ("PATCH",  r"^/admin/billing/rates$"),
    ("PUT",    r"^/admin/tenants/[^/]+/app-control/admins$"),
    ("PUT",    r"^/admin/tenants/[^/]+/app-control/allowlist$"),
    # PAT-1481: governance writes are audited centrally so a body-dependent
    # uninstall quarantine rejection produces one pre-dispatch row that is
    # updated in place, never a second route-local audit record.
    ("POST",   r"^/admin/tenants/[^/]+/allowlist$"),
    ("PUT",    r"^/admin/tenants/[^/]+/allowlist/[^/]+$"),
    ("PUT",    r"^/admin/tenants/[^/]+/ring-config$"),
    ("PUT",    r"^/admin/tenants/[^/]+/ring-devices/[^/]+$"),
    ("PUT",    r"^/admin/tenants/[^/]+/webhooks/[^/]+$"),
    ("POST",   r"^/admin/tenants/[^/]+/webhooks/[^/]+/test$"),
    # PAT-799: app-removal / new-app triage decisions (approve / restrict /
    # defer / remove) — the UI already gates these behind dangerConfirm
    # (PAT-797); this just gets them into the local audit trail too.
    ("PUT",    r"^/admin/tenants/[^/]+/new-apps/[^/]+$"),
    # App-policy records govern the effective software policy seen by the
    # platform. Upsert and removal both need the same single, terminal central
    # audit row as the other tenant governance writes.
    ("PUT",    r"^/admin/tenants/[^/]+/app-policies$"),
    ("DELETE", r"^/admin/tenants/[^/]+/app-policies/[^/]+$"),
    # PAT-799: plan-tier change — commercial/entitlement config, updates the
    # agent config pushed to every device on the tenant.
    ("PUT",    r"^/admin/tenants/[^/]+/subscription-tier$"),
    ("PUT",    r"^/admin/tenants/[^/]+/service-engagement$"),
    ("DELETE", r"^/admin/tenants/[^/]+/service-engagement$"),
    ("DELETE", r"^/admin/tenants/[^/]+/service-engagement/orphan$"),
    ("GET",    r"^/admin/tenants/[^/]+/service-engagement/orphan$"),
    # PAT-1111: schedules or immediately issues the irreversible endpoint
    # agent-decommission directive. The platform also writes its append-only
    # audit row; this keeps the dashboard's operator audit complete.
    ("PUT",    r"^/admin/tenants/[^/]+/decommission$"),
    # PAT-1612: authorising a removal campaign is the trust boundary for a
    # governance decision to remove software from customer endpoints -- no
    # agent-facing delivery path exists yet (PAT-1598 deliberately built
    # platform-only; PAT-1834 is the gated delivery follow-up), so this write
    # is currently inert on its own, but the platform's own append-only
    # authorization row is not a substitute for this console's own audit
    # trail of who triggered it. Cancelling is a lesser but still
    # audit-relevant action (abandoning a campaign someone drafted), so it is
    # destructive-logged too, but per the X-Confirm-Resource split below it
    # does not carry the same typed-confirmation bar as authorize.
    ("POST",   r"^/admin/tenants/[^/]+/removal-campaigns/[^/]+/authorize$"),
    ("POST",   r"^/admin/tenants/[^/]+/removal-campaigns/[^/]+/cancel$"),
])

# Routes requiring the X-Confirm-Resource echo-back. The capture group is the
# path identifier used to resolve the expected value server-side.
_CONFIRM_RULES = [
    ("POST", re.compile(r"^/admin/automations/(installomator_sync)/trigger$"), "automation"),
    ("DELETE", re.compile(r"^/admin/tenants/([^/]+)/service-engagement$"), "tenant"),
    ("DELETE", re.compile(r"^/admin/tenants/([^/]+)/service-engagement/orphan$"), "tenant"),
    ("DELETE", re.compile(r"^/admin/tenants/([^/]+)/purge$"),          "tenant"),
    ("DELETE", re.compile(r"^/admin/tenants/([^/]+)$"),                "tenant"),
    ("DELETE", re.compile(r"^/admin/tenants/[^/]+/devices/([^/]+)$"),  "device"),
    ("POST",   re.compile(r"^/admin/devices/([^/]+)/revoke$"),         "device"),
    # PAT-1820: audited per-tenant opt-out of a shared baseline protection.
    # Irreversible from the console's perspective (re-adding requires a fresh
    # add-protection call), same bar as the other tenant-scoped destructive
    # writes above.
    ("POST", re.compile(r"^/admin/tenants/[^/]+/protected-software/([^/]+)/override-remove$"), "protected_software"),
    # PAT-1612: authorising a removal campaign records the decision to remove
    # software from customer endpoints -- no agent-facing delivery path
    # exists yet (PAT-1598 built platform-only, deliberately; delivery is a
    # gated follow-up, PAT-1834), so this write is currently inert on its own,
    # but it is still the highest-consequence write this console makes: it is
    # the governance record a future delivery mechanism will act on. The
    # operator must type the campaign's target product name to confirm, same
    # typed-confirmation bar as a tenant/device delete.
    ("POST", re.compile(r"^/admin/tenants/[^/]+/removal-campaigns/([^/]+)/authorize$"), "removal_campaign"),
    # PAT-1990: the operator echoes back the recipient's exact email address
    # before the portal welcome email goes out. The address IS the identity
    # here -- One-time PIN is the only login method enabled on the
    # app.patched.im Access application, so there is no SSO account behind it
    # to disambiguate a typo, and a welcome sent to the wrong address hands
    # portal sign-in instructions to the wrong person.
    ("POST", re.compile(r"^/admin/tenants/[^/]+/portal-users/([^/]+)/welcome$"), "portal_recipient"),
]

# GET routes that stay owner-only even though consultants get every other GET
# by default (see the RBAC comment above _CONSULTANT_WRITE_ALLOW). Reserved
# for reads sensitive enough to warrant the same bar as a destructive write —
# today, only the unified admin/logs feed, which includes impersonation
# session records. A route added here also needs a matching class="owner-only"
# nav link / element in console.html so a consultant doesn't see a dead link —
# but THIS list is what actually enforces the denial server-side.
_OWNER_ONLY_GET = _compile([
    ("GET", r"^/admin/logs$"),
    ("GET", r"^/admin/tenants/[^/]+/service-engagement/orphan$"),
])


def _match_rules(rules, method: str, path: str) -> bool:
    return any(m == method and rx.match(path) for (m, rx) in rules)


def _is_owner_only_get(method: str, path: str) -> bool:
    return _match_rules(_OWNER_ONLY_GET, method, path)


def _consultant_write_allowed(method: str, path: str) -> bool:
    return _match_rules(_CONSULTANT_WRITE_ALLOW, method, path)


def _is_destructive(method: str, path: str) -> bool:
    return _match_rules(_DESTRUCTIVE_RULES, method, path)


def _is_legacy_execution_quarantined(method: str, path: str) -> bool:
    return _match_rules(_LEGACY_EXECUTION_QUARANTINE_RULES, method, path)


def _confirm_rule(method: str, path: str):
    """Returns (kind, identifier) if this route needs echo-back confirmation, else None."""
    for (m, rx, kind) in _CONFIRM_RULES:
        if m == method:
            mt = rx.match(path)
            if mt:
                return kind, mt.group(1)
    return None


def _resolve_confirm_resource(kind: str, ident: str, path: str = "") -> set[str]:
    """The set of acceptable X-Confirm-Resource values (trimmed, lowercased),
    resolved server-side from the upstream API (and the local clients table for
    tenants). The resource's own id is always acceptable — echoing the exact id
    demonstrates intent as clearly as the display name, and covers UI labels that
    fall back to the id when a name is absent. A wrong value still fails closed."""
    vals: set[str] = {ident.strip().lower()}
    if kind == "automation":
        return vals
    if kind == "portal_recipient":
        # PAT-1990: purely local, no upstream lookup -- the acceptable value is
        # the recipient address itself. `ident` comes off the request path,
        # which may or may not still be percent-encoded depending on how the
        # ASGI server built scope["path"], so accept the decoded form too. That
        # only ever adds the same address spelled the other way; a wrong
        # address still fails closed.
        try:
            vals.add(unquote(ident).strip().lower())
        except Exception:
            pass
        return vals
    try:
        if kind == "tenant":
            with get_db() as db:
                row = db.execute(
                    "SELECT company FROM clients WHERE tenant_id=?", (ident,)
                ).fetchone()
            if row and row["company"]:
                vals.add(str(row["company"]).strip().lower())
            # Check BOTH the active and the revoked tenant lists — purge targets
            # tenants that are already offboarded, which only appear in /revoked.
            for list_path in ("/admin/tenants", "/admin/tenants/revoked"):
                r = http.get(f"{PATCHED_API_INTERNAL}{list_path}", timeout=10, verify=_VERIFY_INTERNAL)
                if r.status_code != 200:
                    continue
                data = r.json()
                items = data if isinstance(data, list) else (data.get("tenants") or data.get("items") or [])
                for t in items:
                    if not isinstance(t, dict):
                        continue
                    if str(t.get("id")) == ident or str(t.get("tenant_id")) == ident:
                        for k in ("name", "company", "display_name", "tenant_name"):
                            if t.get(k):
                                vals.add(str(t[k]).strip().lower())
        elif kind == "device":
            r = http.get(f"{PATCHED_API_INTERNAL}/admin/devices/{_seg(ident)}", timeout=10, verify=_VERIFY_INTERNAL)
            if r.status_code == 200:
                data = r.json()
                dev = data.get("device", data) if isinstance(data, dict) else {}
                if isinstance(dev, dict):
                    for k in ("hostname", "computer_name", "serial", "serial_number", "name", "device_name"):
                        if dev.get(k):
                            vals.add(str(dev[k]).strip().lower())
        elif kind == "protected_software":
            # PAT-1820: baseline rows are shared (tenant_id IS NULL) but the
            # only read route is tenant-scoped, so pull tenant_id back out of
            # the request path rather than adding a second capture group that
            # every other _CONFIRM_RULES kind would have to thread through.
            m = re.match(r"^/admin/tenants/([^/]+)/protected-software/", path)
            if m:
                r = http.get(
                    f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(m.group(1))}/protected-software",
                    timeout=10, verify=_VERIFY_INTERNAL,
                )
                if r.status_code == 200:
                    data = r.json()
                    items = data.get("entries") or data.get("items") or (data if isinstance(data, list) else [])
                    for entry in items:
                        if not isinstance(entry, dict):
                            continue
                        if str(entry.get("id")) == ident:
                            for k in ("product_name", "vendor"):
                                if entry.get(k):
                                    vals.add(str(entry[k]).strip().lower())
                            if entry.get("vendor") and entry.get("product_name"):
                                vals.add(f"{entry['vendor']} {entry['product_name']}".strip().lower())
        elif kind == "removal_campaign":
            # PAT-1612: the acceptable confirmation values are the campaign's
            # own target identity -- whichever of name/bundle_id/team_id it
            # was created against -- so the operator confirms the product
            # being removed, not an opaque campaign id (though the id itself
            # remains acceptable, same as every other kind above).
            m = re.match(r"^/admin/tenants/([^/]+)/removal-campaigns/", path)
            if m:
                r = http.get(
                    f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(m.group(1))}/removal-campaigns/{_seg(ident)}",
                    timeout=10, verify=_VERIFY_INTERNAL,
                )
                if r.status_code == 200:
                    data = r.json()
                    campaign = data.get("campaign") if isinstance(data, dict) else None
                    if isinstance(campaign, dict):
                        for k in ("name", "bundle_id", "team_id"):
                            if campaign.get(k):
                                vals.add(str(campaign[k]).strip().lower())
    except Exception:
        pass
    return vals


def _resolve_decommission_tenant(ident: str) -> tuple[set[str], str]:
    """Resolve an immediate-removal confirmation against known tenant data.

    Unlike the shared destructive-route resolver, the path id alone is not
    enough here: the dashboard must establish that the tenant still exists in
    either its local customer record or one of the platform tenant indexes.
    """
    vals: set[str] = set()
    matched_without_name = False
    try:
        with get_db() as db:
            row = db.execute(
                "SELECT company FROM clients WHERE tenant_id=?", (ident,)
            ).fetchone()
        if row is not None:
            company = str(row["company"] or "").strip().lower()
            if company:
                vals.add(company)
            else:
                matched_without_name = True
    except Exception:
        pass

    valid_lists = 0
    for list_path in ("/admin/tenants", "/admin/tenants/revoked"):
        try:
            response = http.get(
                f"{PATCHED_API_INTERNAL}{list_path}", timeout=10, verify=_VERIFY_INTERNAL
            )
            if response.status_code != 200:
                continue
            data = response.json()
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                items = data.get("tenants") or data.get("items") or []
            else:
                continue
            if not isinstance(items, list):
                continue
            valid_lists += 1
            for tenant in items:
                if not isinstance(tenant, dict):
                    continue
                if str(tenant.get("id")) != ident and str(tenant.get("tenant_id")) != ident:
                    continue
                for key in ("name", "company", "display_name", "tenant_name"):
                    name = str(tenant.get(key) or "").strip().lower()
                    if name:
                        vals.add(name)
                if not vals:
                    matched_without_name = True
        except Exception:
            continue

    if vals:
        return vals, "resolved"
    if matched_without_name:
        return set(), "unavailable"
    if valid_lists == 2:
        return set(), "not_found"
    return set(), "unavailable"


def _decommission_audit_snapshot(response, tenant_id: str, *, after: bool = False) -> str:
    """Return a bounded, tenant-bound snapshot without logging upstream errors."""
    fallback = "invalid_upstream_response" if after else "unavailable"
    if response is None or (response.status_code >= 400 if after else response.status_code != 200):
        return json.dumps({"read_error": fallback}, sort_keys=True)
    try:
        data = response.json()
    except Exception:
        return json.dumps({"read_error": fallback}, sort_keys=True)
    if not isinstance(data, dict):
        return json.dumps({"read_error": fallback}, sort_keys=True)
    if str(data.get("tenant_id")) != tenant_id:
        marker = "invalid_upstream_response" if after else "tenant_mismatch"
        return json.dumps({"read_error": marker}, sort_keys=True)
    return json.dumps(data, sort_keys=True)


def _resource_from_path(path: str) -> str:
    for pat in (r"/tenants/([^/]+)", r"/devices/([^/]+)", r"/credentials/([^/]+)"):
        m = re.search(pat, path)
        if m:
            return m.group(1)
    return ""


def _audit_write(actor_email: str, role: str, method: str, path: str, outcome: str, *,
                  resource_name: str | None = None, reason: str | None = None,
                  before: str | None = None, after: str | None = None) -> str | None:
    """Append one row to admin_audit_log. Best-effort — never breaks the request.
    Returns the new row's id (for a later _audit_update), or None on failure.

    PAT-799: resource_name/reason/before/after are optional context beyond the
    original (actor, route, outcome) tuple — a tenant/customer display name,
    an operator-supplied reason, and a before/after snapshot for config-style
    writes. All four default to None so every pre-existing call site keeps
    working unchanged."""
    now = datetime.now(timezone.utc).isoformat()
    row_id = str(uuid.uuid4())
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO admin_audit_log "
                "(id, ts, actor_email, role, method, path, resource, outcome, "
                " resource_name, reason, before_value, after_value) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (row_id, now, actor_email or "", role or "",
                 method, path, _resource_from_path(path), outcome,
                 resource_name, reason, before, after),
            )
        return row_id
    except Exception:
        return None


def _audit_update(row_id: str | None, outcome: str, *,
                   resource_name: str | None = None, reason: str | None = None,
                   before: str | None = None, after: str | None = None):
    """PAT-799: best-effort UPDATE of a previously-written audit row — used to
    enrich the pre-dispatch "in_progress" row (written before call_next, so a
    crash/cancellation/hung subprocess still leaves a row) with the real
    outcome and any resource_name/reason/before/after the handler computed
    (e.g. firewall-apply only learns the target edge partway through its own
    body). COALESCE keeps whatever was already stored if this call has
    nothing new to add. No-ops silently if row_id is None (the initial write
    itself failed)."""
    if not row_id:
        return
    try:
        with get_db() as db:
            db.execute(
                "UPDATE admin_audit_log SET outcome=?, "
                "resource_name=COALESCE(?, resource_name), "
                "reason=COALESCE(?, reason), "
                "before_value=COALESCE(?, before_value), "
                "after_value=COALESCE(?, after_value) WHERE id=?",
                (outcome, resource_name, reason, before, after, row_id),
            )
    except Exception:
        pass


def _tenant_name_from_path(path: str) -> str | None:
    """Best-effort tenant display name for the audit log, resolved from the
    local clients table by the tenant id embedded in the path. Returns the raw
    id if the tenant isn't found locally (still more useful in a log line than
    nothing), or None if the path has no tenant segment at all. Never raises —
    this only feeds an audit-log column, never a security decision."""
    m = re.search(r"/tenants/([^/]+)", path)
    if not m:
        return None
    tid = m.group(1)
    try:
        with get_db() as db:
            row = db.execute("SELECT company FROM clients WHERE tenant_id=?", (tid,)).fetchone()
        return (row["company"] if row and row["company"] else tid)
    except Exception:
        return tid


# ══════════════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════════════
# PAT-814: shadow shared.get_db() with a version that resolves *this module's*
# DB_PATH name, not shared.py's. `from shared import DB_PATH` above copied the
# value at import time rather than aliasing it, so shared.get_db() (which reads
# the bare name DB_PATH against shared.py's own globals) never saw the swap when
# tests do `monkeypatch.setattr(dashboard, "DB_PATH", tmp_path)` — every route
# in this file was silently hitting the real on-disk dashboard.db instead of the
# test's tmp path. Redefining get_db() here, after the shared import, makes
# every subsequent `get_db()` call in main.py resolve against main.py's own
# (patchable) DB_PATH.
@contextmanager
def get_db():
    conn = _open_db_connection(DB_PATH)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS public_uploads (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                ip TEXT NOT NULL,
                upload_type TEXT NOT NULL,
                status TEXT DEFAULT 'processing',
                report_path TEXT,
                error TEXT,
                created_at TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                company TEXT NOT NULL,
                tenant_id TEXT DEFAULT '',
                started_at TEXT NOT NULL,
                completed_at TEXT,
                status TEXT DEFAULT 'running',
                total_devices INTEGER DEFAULT 0,
                total_cves INTEGER DEFAULT 0,
                os_cves INTEGER DEFAULT 0,
                app_cves INTEGER DEFAULT 0,
                report_path TEXT,
                error TEXT,
                triggered_by TEXT DEFAULT 'manual'
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS clients (
                id TEXT PRIMARY KEY,
                company TEXT NOT NULL,
                tenant_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                last_scan_at TEXT,
                last_scan_id TEXT
            )
        """)
        # Migrate: add columns if upgrading from earlier schema
        for col, definition in [
            ("triggered_by", "TEXT DEFAULT 'manual'"),
            ("tenant_id", "TEXT DEFAULT ''"),
        ]:
            try:
                db.execute(f"ALTER TABLE clients ADD COLUMN {col} {definition}")
            except: pass
            try:
                db.execute(f"ALTER TABLE scans ADD COLUMN {col} {definition}")
            except: pass

        # PAT-572: Microsoft Graph scan pipeline retired — drop the Graph-only
        # columns from `clients`. This is a real migration (not just a schema-
        # file edit) specifically to wipe the plaintext client_secret values
        # sitting in the production DB today. DROP COLUMN needs SQLite 3.35+;
        # guard each drop individually so an older SQLite fails soft rather
        # than crashing startup (matches this function's existing style).
        _graph_cols = {r[1] for r in db.execute("PRAGMA table_info(clients)").fetchall()}
        for col in ("client_id", "client_secret", "secret_expiry", "schedule_enabled", "next_scan_at"):
            if col in _graph_cols:
                try:
                    db.execute(f"ALTER TABLE clients DROP COLUMN {col}")
                except Exception as _drop_err:
                    print(f"[init_db] Could not drop clients.{col} (SQLite < 3.35?): {_drop_err}")

        # PAT-218: cert digest config — idempotent, guarded by PRAGMA table_info
        _clients_cols = {r[1] for r in db.execute("PRAGMA table_info(clients)").fetchall()}
        for col, definition in [
            ("cert_digest_enabled",   "INTEGER NOT NULL DEFAULT 1"),
            ("cert_digest_recipient", "TEXT NULL"),
            ("cert_digest_severity",  "TEXT NOT NULL DEFAULT 'expired_plus_critical'"),
            ("cert_digest_frequency", "TEXT NOT NULL DEFAULT 'daily'"),
            ("last_cert_digest_sent_at", "TEXT NULL"),
        ]:
            if col not in _clients_cols:
                db.execute(f"ALTER TABLE clients ADD COLUMN {col} {definition}")

        # PAT-283: agent config (tier + proxy) — write-through to platform
        _ac_cols = {r[1] for r in db.execute("PRAGMA table_info(clients)").fetchall()}
        for col, definition in [
            ("agent_config_tier",                "TEXT NOT NULL DEFAULT 'report_deploy'"),
            ("agent_proxy_mode",                 "TEXT NOT NULL DEFAULT 'system'"),
            ("agent_proxy_type",                 "TEXT NULL"),
            ("agent_proxy_host",                 "TEXT NULL"),
            ("agent_proxy_port",                 "INTEGER NULL"),
            ("agent_proxy_pac_url",              "TEXT NULL"),
            ("agent_proxy_auth_ref",             "TEXT NULL"),
            ("agent_proxy_bypass_when_off_corp", "INTEGER NOT NULL DEFAULT 0"),
            ("agent_config_version",             "INTEGER NULL"),
            ("agent_config_issued_at",           "TEXT NULL"),
        ]:
            if col not in _ac_cols:
                db.execute(f"ALTER TABLE clients ADD COLUMN {col} {definition}")

        # PAT-432: account business record columns
        _ac2_cols = {r[1] for r in db.execute("PRAGMA table_info(clients)").fetchall()}
        for col, definition in [
            ("primary_contact_name",    "TEXT NULL"),
            ("primary_contact_email",   "TEXT NULL"),
            ("onboarding_state",        "TEXT NULL DEFAULT 'prospect'"),
            ("contract_notes",          "TEXT NULL"),
            ("account_notes",           "TEXT NULL"),
            ("technical_contact_name",  "TEXT NULL"),
            ("technical_contact_email", "TEXT NULL"),
            ("billing_contact_name",    "TEXT NULL"),
            ("billing_contact_email",   "TEXT NULL"),
            ("company_phone",           "TEXT NULL"),
            ("contract_renewal_date",   "TEXT NULL"),
        ]:
            if col not in _ac2_cols:
                db.execute(f"ALTER TABLE clients ADD COLUMN {col} {definition}")

        # PAT-444: stale-endpoint weekly digest config — mirrors the cert-digest cols
        _stale_cols = {r[1] for r in db.execute("PRAGMA table_info(clients)").fetchall()}
        for col, definition in [
            ("stale_digest_enabled",        "INTEGER NOT NULL DEFAULT 1"),
            ("stale_digest_threshold_days", "INTEGER NULL"),  # null = STALE_THRESHOLD_DEFAULT_DAYS
            ("stale_digest_recipient",      "TEXT NULL"),     # null = primary_contact_email
            ("last_stale_digest_sent_at",   "TEXT NULL"),
            # PAT-575: optional fixed schedule. day_of_week 0=Mon..6=Sun, hour 0-23 UTC.
            # Both null = legacy behaviour (weekly; first eligible tick 7 days after last send).
            ("stale_digest_day_of_week",    "INTEGER NULL"),
            ("stale_digest_hour",           "INTEGER NULL"),
        ]:
            if col not in _stale_cols:
                db.execute(f"ALTER TABLE clients ADD COLUMN {col} {definition}")

        # PAT-445: commercial billing fields. Distinct from agent_config_tier,
        # which only knows report_deploy/patch and can't express Full or Application Control.
        _bill_cols = {r[1] for r in db.execute("PRAGMA table_info(clients)").fetchall()}
        for col, definition in [
            ("billing_tier",          "TEXT NOT NULL DEFAULT 'report'"),  # report | patch | full
            ("app_control_enabled",   "INTEGER NOT NULL DEFAULT 0"),
            ("billing_frequency",     "TEXT NOT NULL DEFAULT 'annual'"),  # annual | monthly
        ]:
            if col not in _bill_cols:
                db.execute(f"ALTER TABLE clients ADD COLUMN {col} {definition}")

        # PAT-108: bootstrap loader — update channel + pinned version
        _av_cols = {r[1] for r in db.execute("PRAGMA table_info(clients)").fetchall()}
        for col, definition in [
            ("agent_update_channel", "TEXT NOT NULL DEFAULT 'stable'"),
            ("agent_pinned_version", "TEXT NULL"),
        ]:
            if col not in _av_cols:
                db.execute(f"ALTER TABLE clients ADD COLUMN {col} {definition}")

        # Rename legacy pam_enabled → app_control_enabled (Application Control reframe).
        _bill_cols2 = {r[1] for r in db.execute("PRAGMA table_info(clients)").fetchall()}
        if "pam_enabled" in _bill_cols2 and "app_control_enabled" not in _bill_cols2:
            db.execute("ALTER TABLE clients RENAME COLUMN pam_enabled TO app_control_enabled")

        # PAT-1100: time ledger — advisory-hours consumption tracked against a
        # tenant's banded allowance, plus service_integrity work that must
        # NEVER be able to move the advisory balance (that separation is the
        # whole safety point: hours-based advisory support gives customers a
        # reason not to report a broken agent unless service_integrity work
        # is billed/tracked distinctly and stays out of the consumed figure).
        db.execute("""
            CREATE TABLE IF NOT EXISTS time_ledger (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                entry_date TEXT NOT NULL,
                duration_minutes INTEGER NOT NULL,
                note TEXT,
                class TEXT NOT NULL,
                created_by TEXT,
                created_at TEXT NOT NULL
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_time_ledger_tenant ON time_ledger(tenant_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_time_ledger_tenant_date ON time_ledger(tenant_id, entry_date)")

        # PAT-1101: billing_contracts — the source of truth for what a signed
        # tenant is ACTUALLY billed. PAT-1100's band lookup (_compute_monthly)
        # derives a live figure from (current endpoint count, current band
        # table) on every read, which is correct for pre-sale quoting but
        # wrong for a signed customer: a twelve-month commitment must not
        # silently reprice itself just because rate config changed or the
        # tenant's endpoint count drifted across a band edge. A contract
        # freezes the figures that applied at signature time; only the
        # explicit POST endpoint (a human action) ever writes one.
        # advisory_hours_at_signature is stored separately from the CURRENT
        # band's allowance for the same reason — it can differ if the band
        # table changed mid-term.
        #
        # Named billing_contracts, not contracts: this dashboard.db is shared
        # with the unrelated Jarvis Job Scout bot, which already owns a table
        # literally named `contracts` (job-application tracking — role_id,
        # client, agency, day_rate...). A same-named CREATE TABLE IF NOT
        # EXISTS silently no-ops against that table, then every subsequent
        # query against "our" contracts hits the wrong schema entirely —
        # this crashed the first PAT-1101 deploy attempt at CREATE INDEX
        # ...(tenant_id), auto-rolled-back, never actually shipped.
        db.execute("""
            CREATE TABLE IF NOT EXISTS billing_contracts (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                tier_at_signature TEXT NOT NULL,
                band_endpoints_at_signature INTEGER NOT NULL,
                monthly_at_signature REAL NOT NULL,
                billing_frequency TEXT NOT NULL,
                annual_discount_at_signature REAL,
                term_start TEXT NOT NULL,
                term_length_months INTEGER NOT NULL DEFAULT 12,
                renewal_date TEXT NOT NULL,
                advisory_hours_at_signature REAL NOT NULL,
                named_specialist TEXT,
                named_customer_contact TEXT,
                assessment_credit_applies INTEGER NOT NULL DEFAULT 0,
                assessment_credit_value REAL,
                assessment_credit_expires_at TEXT,
                note TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                created_by TEXT
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_billing_contracts_tenant ON billing_contracts(tenant_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_billing_contracts_renewal_date ON billing_contracts(renewal_date)")

        # PAT-1051: consultancy service engagement, deliberately separate from
        # billing_contracts and every technical tier/entitlement field. This is
        # one current operating snapshot per customer, not a CRM or task store.
        # Project and escalation references remain links to their source system.
        db.execute("""
            CREATE TABLE IF NOT EXISTS service_engagements (
                tenant_id TEXT PRIMARY KEY,
                service_name TEXT NOT NULL,
                named_specialist TEXT,
                service_cadence TEXT,
                posture_review_status TEXT,
                next_review_date TEXT,
                plan_status TEXT NOT NULL DEFAULT 'not_started',
                plan_start_date TEXT,
                plan_summary TEXT,
                decisions_json TEXT NOT NULL DEFAULT '[]',
                owners_json TEXT NOT NULL DEFAULT '[]',
                exceptions_json TEXT NOT NULL DEFAULT '[]',
                project_links_json TEXT NOT NULL DEFAULT '[]',
                escalation_links_json TEXT NOT NULL DEFAULT '[]',
                updated_at TEXT NOT NULL,
                updated_by TEXT
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_service_engagements_review ON service_engagements(next_review_date)")

        # PAT-1103: billing_drift_checks — monthly history of band drift for
        # every tenant with an active contract. The ruling (2026-08-11,
        # recorded on the ticket) is "re-band at renewal only, both
        # directions": a signed contract's price never changes mid-term no
        # matter which way the tenant's live endpoint count has drifted
        # relative to the band it was signed at. Drift is purely advisory —
        # information fed into the renewal conversation — so this table is a
        # read-only observability log: the ONLY writer is the scheduler tick
        # (_run_band_drift_check_tick), and nothing here ever feeds back into
        # billing_contracts.monthly_at_signature or any other billed figure.
        #
        # One row per tenant per calendar month (UNIQUE(tenant_id,
        # checked_month) — also the tenant+month idempotency check the tick
        # uses to skip a tenant it already recorded this month, which is what
        # makes it safe to call on every hourly tick without duplicating
        # rows). There is no historical endpoint-count record anywhere else
        # in this codebase — api_billing_summary/api_billing_renewals always
        # compute from LIVE current counts — so "consecutive months
        # drifted" can only accumulate forward from whenever this table
        # starts being populated; it cannot be backfilled for time before
        # this ticket shipped.
        #
        # Named billing_drift_checks (billing_-prefixed), following the
        # collision precaution PAT-1101 learned the hard way: dashboard.db is
        # shared with the unrelated Jarvis Job Scout bot. Verified against
        # the live production schema before this migration shipped — no
        # existing `billing_drift_checks` table.
        db.execute("""
            CREATE TABLE IF NOT EXISTS billing_drift_checks (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                checked_month TEXT NOT NULL,
                direction TEXT NOT NULL,
                endpoints INTEGER NOT NULL,
                band_would_produce REAL NOT NULL,
                checked_at TEXT NOT NULL,
                UNIQUE(tenant_id, checked_month)
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_billing_drift_checks_tenant ON billing_drift_checks(tenant_id)")

        # PAT-1102: billing_charges — non-recurring one-off charges (assessment,
        # onboarding, audit pack, advisory overflow) that sit alongside the
        # recurring band/contract model above. Every one of these is still a
        # manual Xero invoice today (PAT-654 — Xero integration — is entirely
        # unbuilt and explicitly blocked pending this ticket ruling the shape
        # first); this table just tracks that the charge exists, its status,
        # and the one genuinely sharp rule: an Endpoint Assurance assessment
        # charge is credited in full against an onboarding charge IF a
        # retainer starts within 90 days of the assessment. credit_expires_at
        # is computed server-side at creation (date_raised + 90 days) and is
        # never client-suppliable. Applying a credit is never automatic — see
        # billing_charge_credits below and the /apply-credit endpoint, which
        # requires an explicit human action and leaves an audit row.
        #
        # xero_invoice_reference is a free-text note field, not a live
        # integration — there is nothing to poll or reconcile against yet, so
        # `status` stays a manually-set column. That IS the "degrades
        # gracefully to manual status" behaviour the ticket asks for: there is
        # nothing to degrade FROM, since no Xero API integration exists.
        #
        # Named billing_charges, not charges: same collision class PAT-1101's
        # hotfix addressed for billing_contracts (dashboard.db is shared with
        # the unrelated Jarvis Job Scout bot). Verified against the live
        # production schema before this migration shipped (PAT-1102) — no
        # existing `billing_charges` or `billing_charge_credits` table.
        db.execute("""
            CREATE TABLE IF NOT EXISTS billing_charges (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                charge_type TEXT NOT NULL,
                amount REAL NOT NULL,
                date_raised TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'draft',
                xero_invoice_reference TEXT,
                note TEXT,
                credit_expires_at TEXT,
                credit_consumed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                created_by TEXT
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_billing_charges_tenant ON billing_charges(tenant_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_billing_charges_type ON billing_charges(charge_type)")

        # billing_charge_credits — append-only audit trail for the
        # assessment-credit mechanism above. Every application of a credit is
        # a new row here (never an UPDATE/DELETE of a prior one), plus
        # billing_charges.credit_consumed=1 on the source charge, so "who
        # applied what, to which charge, when, and why" is always
        # reconstructable. source_charge_id is nullable: a credit could in
        # principle be manual/discretionary rather than the assessment-credit
        # mechanism, so it isn't hard-required.
        db.execute("""
            CREATE TABLE IF NOT EXISTS billing_charge_credits (
                id TEXT PRIMARY KEY,
                charge_id TEXT NOT NULL,
                source_charge_id TEXT,
                amount REAL NOT NULL,
                reason TEXT,
                applied_at TEXT NOT NULL,
                applied_by TEXT
            )
        """)
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_billing_charge_credits_charge ON billing_charge_credits(charge_id)"
        )

        # Public CVE-scan requests (patched.im/cve-scan). Lifecycle:
        #   pending_verify → verified → scanning → complete | error → deleted
        # Files (devices_path, apps_path, report_path) and DB rows are purged
        # after PUBLIC_RETENTION_DAYS by the retention sweep.
        db.execute("""
            CREATE TABLE IF NOT EXISTS public_scans (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                company TEXT NOT NULL,
                ip TEXT,
                status TEXT NOT NULL DEFAULT 'pending_verify',
                otp_code TEXT,
                otp_attempts INTEGER DEFAULT 0,
                otp_expires_at TEXT,
                devices_path TEXT,
                apps_path TEXT,
                report_path TEXT,
                download_token TEXT,
                delete_token TEXT,
                job_id TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                verified_at TEXT,
                completed_at TEXT,
                deleted_at TEXT,
                report_emailed_at TEXT,
                otp_delivery_status TEXT
            )
        """)
        # PAT-1010 (round 4): the actual outcome of the OTP send attempt
        # ("sent" / "dry_run" / "failed"), captured once in public_scan_submit
        # right after _send_email() runs. The verify page reads this instead
        # of re-deriving a generic "is a provider configured" status, which
        # would show "everything's fine" for e.g. a Graph token that expired
        # mid-request: a real per-send
        # failure, not dry-run, that a config-presence check can't see.
        _pub_scan_cols = {r[1] for r in db.execute("PRAGMA table_info(public_scans)").fetchall()}
        if "otp_delivery_status" not in _pub_scan_cols:
            db.execute("ALTER TABLE public_scans ADD COLUMN otp_delivery_status TEXT")
        db.execute("CREATE INDEX IF NOT EXISTS idx_public_scans_email ON public_scans(email)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_public_scans_ip ON public_scans(ip)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_public_scans_status ON public_scans(status)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_public_scans_created_at ON public_scans(created_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_public_scans_download ON public_scans(download_token)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_public_scans_delete ON public_scans(delete_token)")
        # Generic key-value store (used for scheduler heartbeat, etc.)
        db.execute("""
            CREATE TABLE IF NOT EXISTS kv (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        # PAT-539: per-tenant, per-report-type scheduled report subscriptions.
        # Bridge types (cert-expiry, stale-endpoints) share the existing
        # clients.cert_digest_* / stale_digest_* columns to avoid double-sends.
        db.execute("""
            CREATE TABLE IF NOT EXISTS report_subscriptions (
                tenant_id    TEXT NOT NULL,
                report_type  TEXT NOT NULL,
                enabled      INTEGER NOT NULL DEFAULT 0,
                frequency    TEXT NOT NULL DEFAULT 'monthly',
                recipient    TEXT NULL,
                last_sent_at TEXT NULL,
                PRIMARY KEY (tenant_id, report_type)
            )
        """)

        # PAT-562: delivery log for all generated/emailed reports.
        # Populated by _log_report_delivery() each time a PDF is downloaded or emailed.
        db.execute("""
            CREATE TABLE IF NOT EXISTS report_deliveries (
                id           TEXT PRIMARY KEY,
                tenant_id    TEXT NOT NULL,
                tenant_name  TEXT,
                report_type  TEXT NOT NULL,
                subject_scope TEXT NOT NULL DEFAULT 'tenant',
                subject_id   TEXT,
                recipient    TEXT,
                generated_at TEXT NOT NULL,
                sent_at      TEXT,
                status       TEXT NOT NULL DEFAULT 'generated'
            )
        """)
        # PAT-1847: a generic PDF may now be scoped to one device rather than
        # a tenant. Keep the legacy tenant columns for existing delivery views,
        # while recording the exact subject for new audit entries. Old rows are
        # unambiguously tenant-scoped and backfilled in place.
        report_delivery_columns = {
            row["name"] for row in db.execute("PRAGMA table_info(report_deliveries)").fetchall()
        }
        if "subject_scope" not in report_delivery_columns:
            db.execute("ALTER TABLE report_deliveries ADD COLUMN subject_scope TEXT NOT NULL DEFAULT 'tenant'")
        if "subject_id" not in report_delivery_columns:
            db.execute("ALTER TABLE report_deliveries ADD COLUMN subject_id TEXT")
        db.execute(
            "UPDATE report_deliveries SET subject_id=tenant_id "
            "WHERE subject_id IS NULL OR subject_id=''"
        )

        # PAT-558: per-app deploy-ring assignment (pilot|general|deferred), stored locally
        # because the Go API has no ring-per-app concept yet. Enforcement is future work.
        db.execute("""
            CREATE TABLE IF NOT EXISTS app_deploy_rings (
                identifier TEXT NOT NULL,
                tenant_id  TEXT NOT NULL,
                ring       TEXT NOT NULL DEFAULT 'general',
                updated_at TEXT NOT NULL,
                PRIMARY KEY (identifier, tenant_id)
            )
        """)

        # PAT-215: credential expiry tracker — metadata only, no secret values stored.
        db.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id                  TEXT PRIMARY KEY,
                name                TEXT NOT NULL,
                service             TEXT NOT NULL,
                description         TEXT,
                expires_at          TEXT,
                auto_refresh_source TEXT,
                notes               TEXT,
                created_at          TEXT NOT NULL,
                updated_at          TEXT NOT NULL,
                deleted_at          TEXT
            )
        """)
        _now = datetime.now(timezone.utc).isoformat()
        _seed_creds = [
            ("cred-graph-mail",    "Microsoft Graph mailer",               "Microsoft Graph",      "Email delivery for reports and digests",                  None),
            ("cred-nvd",           "NVD API Key",                         "NVD / NIST",          "CVE database lookups",                                    None),
            ("cred-cf-api",        "Cloudflare API Token",                "Cloudflare",          "DNS and firewall management",                             None),
            ("cred-hetzner",       "Hetzner Cloud API Token",             "Hetzner",             "Cloud firewall rule management (patched-prod-01, patched-api-01)", None),
            ("cred-dashboard-key", "Dashboard API Key",                   "Patched Dashboard",   "Bearer token for dashboard /api/* routes",                None),
            ("cred-stripe",        "Stripe Restricted Key",               "Stripe",              "Billing integration",                                     None),
            ("cred-tailscale",     "Tailscale Auth Key",                  "Tailscale",           "Device enrolment auth key",                               None),
        ]
        for _cid, _name, _svc, _desc, _ars in _seed_creds:
            db.execute("""
                INSERT OR IGNORE INTO credentials (id, name, service, description, auto_refresh_source, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (_cid, _name, _svc, _desc, _ars, _now, _now))
        # PAT-1507: preserve the audit trail but hide the retired mail vendor
        # from existing installations as well as new database seeds.
        db.execute("""
            UPDATE credentials SET deleted_at=?, updated_at=?
            WHERE id='cred-sendgrid' AND deleted_at IS NULL
        """, (_now, _now))

        # PAT-572: cred-graph-api is no longer seeded (Graph scan pipeline retired) and
        # nothing refreshes its expires_at anymore. Soft-delete any pre-existing row so
        # it doesn't freeze at its last-known expiry and drift into a false "Expired"
        # credential card in the console with no way to refresh or retire it.
        db.execute("""
            UPDATE credentials SET deleted_at=? WHERE id='cred-graph-api' AND deleted_at IS NULL
        """, (_now,))

        # PAT-137: impersonation audit log
        db.execute("""
            CREATE TABLE IF NOT EXISTS impersonation_audit_log (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                actor_email TEXT NOT NULL,
                action TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                duration_seconds INTEGER,
                created_at TEXT NOT NULL
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_imp_log_tenant ON impersonation_audit_log(tenant_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_imp_log_session ON impersonation_audit_log(session_id)")
        # Unified admin/logs feed sorts newest-first on created_at (row-write
        # time, not started_at/ended_at — every _imp_log() call writes a new
        # row, so created_at is the one column present and monotonic on all of them).
        db.execute("CREATE INDEX IF NOT EXISTS idx_imp_log_created ON impersonation_audit_log(created_at)")

        # PAT-695: destructive-write audit log
        db.execute("""
            CREATE TABLE IF NOT EXISTS admin_audit_log (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                actor_email TEXT NOT NULL,
                role TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                resource TEXT,
                outcome TEXT NOT NULL
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_admin_audit_ts ON admin_audit_log(ts)")

        # PAT-799: richer audit context — the tenant/customer display name (not
        # just the raw path id), a free-text operator reason, and a before/after
        # snapshot for config-style writes (billing rates, ring config, App
        # Control lists, webhook toggles). All four are nullable/additive — old
        # rows and old _audit_write(...) call sites are unaffected.
        _audit_cols = {r[1] for r in db.execute("PRAGMA table_info(admin_audit_log)").fetchall()}
        for col, definition in [
            ("resource_name", "TEXT"),
            ("reason",        "TEXT"),
            ("before_value",  "TEXT"),
            ("after_value",   "TEXT"),
        ]:
            if col not in _audit_cols:
                db.execute(f"ALTER TABLE admin_audit_log ADD COLUMN {col} {definition}")

        # PAT-801: audit log for every report-send attempt (success or failure).
        # Separate from report_deliveries — that table records successful sends
        # only (its existing, narrower purpose) and stays untouched by this ticket.
        db.execute("""
            CREATE TABLE IF NOT EXISTS report_send_audit_log (
                id                  TEXT PRIMARY KEY,
                ts                  TEXT NOT NULL,
                actor_email         TEXT NOT NULL,
                tenant_id           TEXT NOT NULL,
                tenant_name         TEXT,
                report_type         TEXT NOT NULL,
                recipient           TEXT NOT NULL,
                recipient_category  TEXT,
                outcome             TEXT NOT NULL,
                detail              TEXT
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_report_send_audit_tenant ON report_send_audit_log(tenant_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_report_send_audit_ts ON report_send_audit_log(ts)")

        # PAT-1990: portal welcome email. Two tables, deliberately, mirroring
        # the PAT-801 report_send_audit_log / report_deliveries split:
        #
        #   portal_welcome_audit_log  every ATTEMPT, whatever the outcome --
        #                             refused, dry-run, failed or sent. This is
        #                             the access audit trail the ticket asks
        #                             for, and a refusal is exactly as worth
        #                             recording as a send.
        #   portal_user_welcomes      state, and ONLY on a real send. PAT-815's
        #                             bug was recording a failed send as
        #                             success; the split makes that impossible
        #                             to do by accident, because the only
        #                             writer of this table sits after a
        #                             confirmed-ok _send_email().
        db.execute("""
            CREATE TABLE IF NOT EXISTS portal_welcome_audit_log (
                id            TEXT PRIMARY KEY,
                ts            TEXT NOT NULL,
                actor_email   TEXT NOT NULL,
                tenant_id     TEXT NOT NULL,
                tenant_name   TEXT,
                recipient     TEXT NOT NULL,
                outcome       TEXT NOT NULL,
                detail        TEXT
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_portal_welcome_audit_tenant ON portal_welcome_audit_log(tenant_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_portal_welcome_audit_ts ON portal_welcome_audit_log(ts)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS portal_user_welcomes (
                tenant_id     TEXT NOT NULL,
                email         TEXT NOT NULL,
                welcomed_at   TEXT NOT NULL,
                welcomed_by   TEXT NOT NULL,
                PRIMARY KEY (tenant_id, email)
            )
        """)

        # PAT-137: support access opt-out (Tier 3 tenants only)
        _imp_cols = {r[1] for r in db.execute("PRAGMA table_info(clients)").fetchall()}
        if "support_access_opt_out" not in _imp_cols:
            db.execute("ALTER TABLE clients ADD COLUMN support_access_opt_out INTEGER NOT NULL DEFAULT 0")

        # PAT-370: external-recipient single-use download tokens.
        # These live in SQLite (not Postgres) — the dashboard issues them and
        # redeems them, fetching the XLSX from the Go service on redemption.
        db.execute("""
            CREATE TABLE IF NOT EXISTS report_ext_tokens (
                token       TEXT PRIMARY KEY,
                tenant_id   TEXT NOT NULL,
                record_id   TEXT NOT NULL,
                email       TEXT NOT NULL,
                expires_at  TEXT NOT NULL,
                redeemed_at TEXT
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_ret_record ON report_ext_tokens(record_id)")

        # PAT-370: idempotency ledger for the daily schedule send loop.
        # One row per (tenant, schedule, period_start) — prevents double-sends
        # on re-runs within the same day.
        db.execute("""
            CREATE TABLE IF NOT EXISTS report_schedule_sends (
                id           TEXT PRIMARY KEY,
                tenant_id    TEXT NOT NULL,
                schedule_id  TEXT NOT NULL,
                period_start TEXT NOT NULL,
                period_end   TEXT NOT NULL,
                record_id    TEXT NOT NULL,
                sent_at      TEXT NOT NULL,
                UNIQUE (tenant_id, schedule_id, period_start)
            )
        """)

        # PAT-817: local idempotency ledger for trial-expiry milestone emails.
        # The platform's upgrade_email_sent_at flag is the primary "already
        # notified" signal, but the POST that sets it (trial-notify) can fail
        # independently of the email send that already went out — recording the
        # send locally too means a downstream API hiccup can't cause a duplicate
        # customer-facing email tomorrow.
        db.execute("""
            CREATE TABLE IF NOT EXISTS trial_expiry_notifications (
                tenant_id TEXT NOT NULL,
                milestone TEXT NOT NULL,
                sent_at   TEXT NOT NULL,
                PRIMARY KEY (tenant_id, milestone)
            )
        """)

        # PAT-2249: the local Software Catalogue (catalogue_apps, PAT-500/1349)
        # and its hosting-operations companions (catalogue_hosting_reviews,
        # catalogue_hosting_events, catalogue_hosting_messages, PAT-960) are
        # retired with the catalogue review, hosting and discovery pipeline.
        # No CREATE TABLE, ALTER TABLE or seed here any more. An existing
        # box's leftover tables, including their historical hosting events,
        # are harmless and intentionally left alone rather than dropped,
        # the same way as PAT-627's catalogue_suggestions (retired in
        # PAT-852) and PAT-847's catalogue_mirror_approvals before them.

        # PAT-643: idempotency table for automation failure Slack alerts.
        # One row per (job_name, run_id) — ensures each failed run triggers exactly one alert.
        db.execute("""
            CREATE TABLE IF NOT EXISTS automation_alerts_sent (
                job_name   TEXT NOT NULL,
                run_id     INTEGER NOT NULL,
                alerted_at TEXT NOT NULL,
                PRIMARY KEY (job_name, run_id)
            )
        """)
        # Unified admin/logs feed sort/filter column.
        db.execute("CREATE INDEX IF NOT EXISTS idx_aas_alerted_at ON automation_alerts_sent(alerted_at)")

        # Automation staleness alerts: idempotency keyed by (job_name, calendar
        # date) rather than run_id, because the whole point of a staleness alert
        # is that there IS no new run to key off — the job has stopped producing
        # them. A separate table (rather than overloading automation_alerts_sent,
        # whose run_id column is a real run identifier) keeps that distinction
        # explicit and avoids stuffing a synthetic string into an INTEGER column.
        # Caps staleness alerts at one per job per UTC day even though the
        # scheduler ticks hourly.
        db.execute("""
            CREATE TABLE IF NOT EXISTS automation_stale_alerts_sent (
                job_name   TEXT NOT NULL,
                alert_date TEXT NOT NULL,
                alerted_at TEXT NOT NULL,
                PRIMARY KEY (job_name, alert_date)
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_asas_alerted_at ON automation_stale_alerts_sent(alerted_at)")

        # Daily automation health digest: one positive-confirmation Slack post
        # per UTC day, so a healthy silent night reads as "confirmed healthy"
        # rather than "maybe nobody's watching". One row per calendar date.
        db.execute("""
            CREATE TABLE IF NOT EXISTS automation_digest_sent (
                digest_date TEXT NOT NULL PRIMARY KEY,
                sent_at     TEXT NOT NULL
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_ads_sent_at ON automation_digest_sent(sent_at)")

        # Durable availability state for scheduled checks. A monitor that cannot
        # run must be distinguishable from one that ran and found no problem.
        # One row per check is enough: operators need the latest evaluation, not
        # a second event log.
        db.execute("""
            CREATE TABLE IF NOT EXISTS check_statuses (
                name         TEXT NOT NULL PRIMARY KEY,
                state        TEXT NOT NULL CHECK(state IN ('ok', 'degraded', 'unconfigured')),
                reason       TEXT NOT NULL DEFAULT '',
                evaluated_at TEXT NOT NULL
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_cs_evaluated_at ON check_statuses(evaluated_at)")

        # PAT-1171: idempotency table for check_statuses transition alerts.
        # Same shape as health_alerts_sent below (PAT-678/PAT-1011): one row
        # per check `name`, storing the last state an alert decision was made
        # for plus whether that alert was actually confirmed delivered. Keyed
        # generically by `name` -- not by any specific check -- so any row
        # ever written to check_statuses (portal_auth, deploy_drift, a future
        # check nobody has written yet) gets alert-on-transition coverage for
        # free, with no per-check registration step. See
        # _maybe_alert_check_status_transition() for how last_state/
        # alert_delivered gate the retry -- a persistently-degraded check
        # does not re-alert every scheduler tick, but an alert Slack never
        # confirmed delivered is retried the next time the check reports.
        db.execute("""
            CREATE TABLE IF NOT EXISTS check_status_alerts_sent (
                name            TEXT NOT NULL PRIMARY KEY,
                last_state      TEXT NOT NULL,
                alerted_at      TEXT NOT NULL,
                alert_delivered INTEGER NOT NULL DEFAULT 0
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_csas_alerted_at ON check_status_alerts_sent(alerted_at)")

        # PAT-1481 retired the Installomator-backed catalogue-orphan monitor
        # and its scheduler tick; PAT-1640 retired the GitHub Actions org
        # budget check (Andy's call: remove cleanly rather than provision the
        # scoped GitHub token it needed -- prod-01 never had one, so it had
        # read "unconfigured" in every digest since it shipped). Remove their
        # durable latest-state and alert bookkeeping rows so an old degraded/
        # unconfigured result cannot live forever in Service Health or the
        # daily digest after its producer is deliberately gone. These are
        # replaceable singleton status records, not historical run evidence;
        # restoring the check would recreate them.
        retired_check_names = (
            "catalogue_orphan",
            "tick_catalogue_orphan_check",
            "tick_catalogue_replies",
            "github-budget-check",
            "tick_github_budget_check",
        )
        placeholders = ",".join("?" for _ in retired_check_names)
        db.execute(
            f"DELETE FROM check_statuses WHERE name IN ({placeholders})",
            retired_check_names,
        )
        db.execute(
            f"DELETE FROM check_status_alerts_sent WHERE name IN ({placeholders})",
            retired_check_names,
        )

        # PAT-1303: observations reported by the truth-report.sh push-reporter
        # (deploy/truth-report.{sh,service,timer}), for manifest entries whose
        # scope is a box this app cannot read locally (api-01, portal-01).
        # One row per (scope, entry_id) -- latest observation only, same
        # "durable latest state, not an event log" shape as check_statuses
        # above. Until the reporter is installed on a box, its entries simply
        # have no row here, which truth.py's collection layer reads as "no
        # observation" -- amber, never fabricated. See truth.py's module
        # docstring for the full state-machine this feeds.
        db.execute("""
            CREATE TABLE IF NOT EXISTS truth_reports (
                scope        TEXT NOT NULL,
                entry_id     TEXT NOT NULL,
                success      INTEGER,
                detail       TEXT NOT NULL DEFAULT '',
                observed_at  TEXT NOT NULL,
                PRIMARY KEY (scope, entry_id)
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_tr_observed_at ON truth_reports(observed_at)")

        # PAT-1716: latest reported result per nightly uninstall E2E job
        # (macOS PAT-1714, Windows PAT-1715, future level-2 canaries). One
        # row per job -- durable latest state, not an event log, same shape
        # as check_statuses/truth_reports above. Fed into a check_statuses
        # row per job (see _evaluate_nightly_job_check) so staleness and
        # failure show up on the same automation surface as everything else,
        # including when a job stops reporting entirely and no new row ever
        # arrives here.
        db.execute("""
            CREATE TABLE IF NOT EXISTS nightly_job_results (
                job         TEXT NOT NULL PRIMARY KEY,
                platform    TEXT NOT NULL,
                level       INTEGER NOT NULL,
                run_url     TEXT NOT NULL DEFAULT '',
                status      TEXT NOT NULL CHECK(status IN ('pass', 'fail')),
                finished_at TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_njr_finished_at ON nightly_job_results(finished_at)")

        # PAT-678: idempotency table for at-risk health transition alerts.
        # Stores the LAST bucket seen per tenant; alert fires only on transition INTO at_risk.
        db.execute("""
            CREATE TABLE IF NOT EXISTS health_alerts_sent (
                tenant_id  TEXT NOT NULL PRIMARY KEY,
                bucket     TEXT NOT NULL,
                alerted_at TEXT NOT NULL
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_has_alerted_at ON health_alerts_sent(alerted_at)")

        # PAT-1011: track whether the at_risk alert for the CURRENT episode was
        # actually confirmed delivered, separately from which bucket the tenant
        # is in. Before this column, the bucket write happened unconditionally
        # every tick, so a tenant that entered at_risk while Slack delivery was
        # broken got the "prev_bucket == at_risk" gate stuck closed forever --
        # the alert that most needed to reach someone would silently never
        # retry. Same shape as portal_auth_recovery_pending (PAT-988): a
        # still-owed notification is tracked independently of the state it
        # describes, so it survives until it actually sends.
        _has_cols = {r[1] for r in db.execute("PRAGMA table_info(health_alerts_sent)").fetchall()}
        if "alert_delivered" not in _has_cols:
            # DEFAULT 0 (not 1) deliberately: a pre-existing row predates
            # this column entirely, so there is no way to know whether its
            # alert was ever actually confirmed delivered under the old
            # (broken, 200-is-enough) logic -- defaulting to "not delivered"
            # forces a one-time retry rather than silently keeping the gate
            # closed forever for exactly the historical cases this ticket
            # exists to fix. Non-at_risk rows are unaffected either way --
            # the retry gate only ever consults alert_delivered when
            # bucket == 'at_risk'. Using the column DEFAULT itself (rather
            # than a separate one-time backfill UPDATE gated on this same
            # migration guard) also survives this deploy model's
            # auto-rollback: if this ALTER TABLE runs during a deploy that
            # later gets rolled back on a failed smoke test, the column
            # persists in the live db (deploys don't touch data files) but
            # a one-time UPDATE guarded on "column doesn't exist yet" would
            # never run again on the eventual successful redeploy, silently
            # reproducing the exact bug this migration fixes. A safe
            # default has no such window.
            db.execute(
                "ALTER TABLE health_alerts_sent ADD COLUMN alert_delivered INTEGER NOT NULL DEFAULT 0"
            )

        # PAT-288: on-demand agent log request tracking.
        # Stores the request_id issued to the agent so the UI can show
        # "requested → uploaded → expired" state before/after the bundle arrives.
        db.execute("""
            CREATE TABLE IF NOT EXISTS device_log_requests (
                request_id   TEXT PRIMARY KEY,
                tenant_id    TEXT NOT NULL,
                device_id    TEXT NOT NULL,
                device_name  TEXT NOT NULL DEFAULT '',
                requested_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_dlr_device ON device_log_requests(tenant_id, device_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_dlr_requested_at ON device_log_requests(requested_at)")

        # PAT-435: Calendly booking leads.
        # One row per invitee.created webhook event. email is the lookup key for
        # linking to public_scans and for the follow-up scheduler.
        db.execute("""
            CREATE TABLE IF NOT EXISTS calendly_leads (
                id              TEXT PRIMARY KEY,
                email           TEXT NOT NULL,
                name            TEXT NOT NULL DEFAULT '',
                event_type      TEXT NOT NULL DEFAULT '',
                event_uri       TEXT NOT NULL DEFAULT '',
                booked_at       TEXT NOT NULL,
                meeting_at      TEXT,
                initial_email_sent_at TEXT,
                converted_at    TEXT
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_cl_email ON calendly_leads(email)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_cl_booked ON calendly_leads(booked_at)")

        # PAT-435: idempotency table for follow-up emails.
        # One row per (lead_id, day_number) — ensures each step fires exactly once.
        db.execute("""
            CREATE TABLE IF NOT EXISTS calendly_followup_sends (
                lead_id    TEXT NOT NULL,
                day_number INTEGER NOT NULL,
                sent_at    TEXT NOT NULL,
                PRIMARY KEY (lead_id, day_number)
            )
        """)

        # PAT-779: per-tenant operator runbook/notes. Internal-only — never
        # proxied to the customer-facing portal. Soft-deleted via deleted_at
        # (matches the credentials table pattern) so history isn't lost.
        db.execute("""
            CREATE TABLE IF NOT EXISTS tenant_runbook_notes (
                id          TEXT PRIMARY KEY,
                tenant_id   TEXT NOT NULL,
                title       TEXT NOT NULL,
                body        TEXT NOT NULL DEFAULT '',
                category    TEXT NOT NULL DEFAULT 'other',
                pinned      INTEGER NOT NULL DEFAULT 0,
                created_by  TEXT NOT NULL,
                updated_by  TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL,
                deleted_at  TEXT
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_trn_tenant ON tenant_runbook_notes(tenant_id, deleted_at)")

    # PAT-812: Needs Attention tab conversion-tracking events.
    # One row per _naTrackClick fire — tenant_id/event_name are required by
    # the endpoint; category/severity are sent by some call sites and null
    # for others. recorded_at is server-stamped, not client-supplied.
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS conversion_events (
                id           TEXT PRIMARY KEY,
                tenant_id    TEXT NOT NULL,
                event_name   TEXT NOT NULL,
                category     TEXT,
                severity     TEXT,
                recorded_at  TEXT NOT NULL
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_ce_recorded_at ON conversion_events(recorded_at)")


def _record_check_status(
    name: str,
    state: str,
    reason: str = "",
    evaluated_at: datetime | None = None,
    alert_on_transition: bool = True,
) -> None:
    """Persist the latest scheduled-check availability without breaking its caller.

    PAT-1171: also evaluates whether this write is a transition worth a
    Slack alert (see _maybe_alert_check_status_transition), generic across
    every check name by default -- `alert_on_transition` defaults True so
    any check, including ones that don't exist yet, gets that coverage for
    free with zero code change. Pass alert_on_transition=False ONLY from a
    call site whose surrounding tick already sends its own dedicated Slack
    alert for this exact transition (as of this writing: portal_auth's
    _check_portal_access_aud/_run_portal_auth_healthcheck_tick, PAT-837/988;
    automation_alerts' _run_automation_alerts_tick, PAT-643/1018;
    health_alert_delivery's _send_health_alert/_run_health_alerts_tick,
    PAT-678/1011/1017) -- a second, generic alert on top of an
    already-tested, richer, check-specific notification (24h throttle,
    runbook links, recovery-pending persistence, etc.) would be pure
    duplicate Slack noise, not new coverage. This is a per-call-site
    declaration made by code that already owns its own alerting story, not
    a name lookup inside the generic mechanism itself -- every OTHER check
    name, known or future, is covered with no such opt-out required.

    PAT-1427: for the two checks in _FAST_PATH_CHECK_NAMES (deploy_drift,
    maintenance_prod01 -- the only ones written by both fast_check_loop,
    every _FAST_CHECK_INTERVAL, and the hourly scheduler_loop), the UPSERT
    below only applies its update when the incoming evaluated_at is >= the
    row's current one -- newest evaluation wins on wall-clock time, not on
    write-commit order. scheduler_loop captures its own `now` once at the
    top of its iteration and then runs many other ticks before reaching
    these two, so its write can commit to SQLite several minutes after it
    was "evaluated" -- by which point a fast-path tick may already have
    recorded a later, fresher result. Without this guard that slow, stale
    hourly write would silently replace the fresher one -- exactly the fast
    path being undone by the slow path, in the ticket whose purpose is
    making these rows reflect current reality. WAL + `busy_timeout=10000`
    (both set on every connection in shared.py's _open_db_connection) is the
    complementary SQLite-level guarantee that a concurrent write from
    another thread never blocks or errors -- the two are not alternatives
    to each other.

    The guard is deliberately scoped to just those two names, NOT every
    check (verified against the full suite: a global guard breaks real,
    pre-existing behaviour). Several checks legitimately call
    _record_check_status more than once for the same name within a single
    tick's own execution -- e.g. portal_auth: _check_portal_access_aud()
    records an intermediate ok/degraded reading with an implicit, freshly-
    captured `datetime.now()`, and _run_portal_auth_healthcheck_tick() may
    then record a final, more-authoritative degraded verdict using the
    tick's OWN earlier-captured `now` parameter. That final write is
    correct and must win despite carrying an earlier timestamp than the
    intermediate one -- this is single-threaded, sequential, "last call
    wins" logic that has nothing to do with the fast/hourly-loop race a
    global guard would (wrongly) also apply itself to, silently dropping
    the authoritative write. Only deploy_drift/maintenance_prod01 have an
    actual cross-thread race to protect against.

    A write the guard drops (this call's evaluated_at was older than what's
    already stored) also skips alert-transition evaluation below -- without
    that, a losing write could still fire (or mis-record, in
    check_status_alerts_sent) an alert for a state/reason that was never
    actually persisted to check_statuses, which would misrepresent the row
    the alert claims to describe.
    """
    if state not in {"ok", "degraded", "unconfigured"}:
        print(f"[check-status] invalid state {state!r} for {name!r}")
        return
    when = (evaluated_at or datetime.now(timezone.utc)).isoformat()
    guarded = (
        " WHERE excluded.evaluated_at >= check_statuses.evaluated_at"
        if name in _FAST_PATH_CHECK_NAMES else ""
    )
    try:
        with get_db() as db:
            cur = db.execute(
                "INSERT INTO check_statuses (name, state, reason, evaluated_at) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET "
                "state=excluded.state, reason=excluded.reason, evaluated_at=excluded.evaluated_at"
                + guarded,
                (name, state, reason, when),
            )
            applied = cur.rowcount > 0
    except Exception as e:
        print(f"[check-status] failed to record {name!r}: {e}")
        return

    if not applied:
        # Only reachable for a guarded (fast-path) name that lost the
        # max(evaluated_at) race -- the persisted row is already newer than
        # this write, so nothing changed. See the docstring note above for
        # why alert-transition must not run against a value that was never
        # actually written. Every non-fast-path name always applies (no
        # WHERE clause), so this never fires for them.
        return

    if not alert_on_transition:
        return

    # PAT-1171: only evaluate alert-worthiness once the row itself is safely
    # persisted, and never let a Slack hiccup here turn into a failure this
    # function's callers have to handle -- same "without breaking its
    # caller" contract as the write above.
    try:
        _maybe_alert_check_status_transition(name, state, reason, when)
    except Exception as e:
        print(f"[check-status] failed to evaluate alert transition for {name!r}: {e}")


_CHECK_STATUS_CONSOLE_URL = "https://dashboard.patched.im/console#ops"


def _send_check_status_alert(name: str, new_state: str, reason: str) -> bool:
    """PAT-1171: Slack notification for a check_statuses transition, via the
    already-confirmed-delivery helper (PAT-1011) -- never a bare POST that
    only checks for HTTP 200. `new_state` is either "degraded" (entering)
    or "ok" (recovering); _maybe_alert_check_status_transition below is the
    only caller and only invokes this on an actual transition.
    """
    if new_state == "degraded":
        title = f"Check degraded: {name}"
        severity, resolved = "critical", False
        detail = reason or "no reason recorded"
    else:
        title = f"Check recovered: {name}"
        severity, resolved = "warning", True
        detail = "back to ok" + (f": {reason}" if reason else "")
    blocks = _build_alert_blocks(
        severity, title, detail,
        links=[(_CHECK_STATUS_CONSOLE_URL, "View Infrastructure")],
        resolved=resolved,
    )
    return _post_slack_blocks_confirmed(blocks, "check-status-alerts")


def _maybe_alert_check_status_transition(name: str, state: str, reason: str, when: str) -> None:
    """Fire a Slack alert exactly once per transition INTO `degraded`, and
    once on recovery back to `ok`, for ANY check_statuses row -- generic
    across every check name (portal_auth, deploy_drift, a future check
    nobody has written yet), never hardcoded to a specific one. Whatever
    calls _record_check_status() gets this for free.

    Idempotency mirrors health_alerts_sent (PAT-678/PAT-1011):
    check_status_alerts_sent.last_state is the state an alert decision was
    last made for (NOT necessarily the check's raw current state -- see the
    recovery branch below), and alert_delivered tracks whether that
    decision's Slack post was actually confirmed delivered. A check stuck
    degraded across many ticks does not re-alert every cycle (last_state
    stays "degraded" with alert_delivered=1); a degraded alert Slack never
    confirmed IS retried next tick (alert_delivered=0 forces should_alert
    True again, exactly like the at_risk retry gate).
    """
    with get_db() as db:
        row = db.execute(
            "SELECT last_state, alert_delivered FROM check_status_alerts_sent WHERE name=?",
            (name,),
        ).fetchone()
    prev_state = row["last_state"] if row else None
    # No row yet means no alert obligation has ever failed -- treat a
    # first-seen check as "delivered" (nothing owed), same default
    # health_alerts_sent uses for a tenant seen for the first time.
    prev_delivered = bool(row["alert_delivered"]) if row else True

    if state == "degraded":
        should_alert = prev_state != "degraded" or not prev_delivered
        delivered = _send_check_status_alert(name, "degraded", reason) if should_alert else True
        new_last_state = "degraded"
    elif prev_state == "degraded":
        # Was degraded; only an actual "ok" reading counts as recovered.
        # Anything else (e.g. unconfigured) neither alerts nor forgives the
        # outstanding degraded obligation -- carry last_state/delivered
        # forward unchanged so a later "ok" or "degraded" still evaluates
        # correctly against what was really last alerted.
        if state == "ok":
            delivered = _send_check_status_alert(name, "ok", reason)
            # Keep last_state "degraded" until the recovery post is actually
            # confirmed delivered, so an unconfirmed recovery alert retries
            # on the next "ok" reading instead of silently going unsent.
            new_last_state = "ok" if delivered else "degraded"
        else:
            delivered = prev_delivered
            new_last_state = prev_state
    else:
        # Was not degraded and isn't degraded now -- nothing owed.
        delivered = True
        new_last_state = state

    with get_db() as db:
        db.execute(
            "INSERT INTO check_status_alerts_sent (name, last_state, alerted_at, alert_delivered) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET last_state=excluded.last_state, "
            "alerted_at=excluded.alerted_at, alert_delivered=excluded.alert_delivered",
            (name, new_last_state, when, 1 if delivered else 0),
        )


def _check_status_freshness(
    name: str, evaluated_at_raw: str | None, now: datetime
) -> tuple[int | None, bool]:
    """PAT-1427: turn a check_statuses row's evaluated_at into age_seconds +
    a stale boolean, so a consumer of /admin/check-status (or anything else
    reading _get_check_statuses) can tell "this was true an hour ago" from
    "this is true now" without doing its own date arithmetic -- see the
    _FAST_CHECK_INTERVAL/_FAST_PATH_CHECK_NAMES comment above for why the
    threshold differs by check. A missing or unparseable evaluated_at is
    treated as maximally stale (age_seconds None, stale True) rather than
    silently reading as fresh -- same "don't no-op into looking healthy"
    discipline as every check_statuses writer in this file."""
    if not evaluated_at_raw:
        return None, True
    try:
        evaluated_at = datetime.fromisoformat(evaluated_at_raw)
    except ValueError:
        return None, True
    if evaluated_at.tzinfo is None:
        evaluated_at = evaluated_at.replace(tzinfo=timezone.utc)
    age_seconds = max(0, int((now - evaluated_at).total_seconds()))
    threshold = (
        _FAST_CHECK_STALE_AFTER if name in _FAST_PATH_CHECK_NAMES
        else _DEFAULT_CHECK_STALE_AFTER
    )
    return age_seconds, age_seconds > threshold.total_seconds()


def _get_check_statuses(
    states: tuple[str, ...] | None = None, now: datetime | None = None
) -> list[dict]:
    """Return latest check states, optionally restricted to selected states.

    PAT-1427: every row also carries `age_seconds` and `stale` (see
    _check_status_freshness) computed against `now` -- defaults to the real
    current time; a caller (tests, mainly) can pass a fixed `now` to get a
    deterministic result. This is deliberately computed here, in the one
    function every reader of check_statuses (the /admin/check-status
    endpoint, the ops-data tile, the truth page) already goes through,
    rather than in just the HTTP route -- so nothing that reads a row can
    silently skip the freshness signal.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    try:
        with get_db() as db:
            if states:
                placeholders = ",".join("?" for _ in states)
                rows = db.execute(
                    f"SELECT name, state, reason, evaluated_at FROM check_statuses "
                    f"WHERE state IN ({placeholders}) ORDER BY name",
                    states,
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT name, state, reason, evaluated_at "
                    "FROM check_statuses ORDER BY name"
                ).fetchall()
    except Exception as e:
        print(f"[check-status] failed to read statuses: {e}")
        return []
    out = []
    for row in rows:
        d = dict(row)
        age_seconds, stale = _check_status_freshness(d["name"], d["evaluated_at"], now)
        d["age_seconds"] = age_seconds
        d["stale"] = stale
        out.append(d)
    return out


# ── PAT-1303: operational truth page ────────────────────────────────────────
# Declared inventory (truth_manifest.yaml) joined against observed evidence.
# See truth.py's module docstring for the full architecture and the state
# rules; this section is just main.py's wiring of it (manifest load/cache,
# evidence gathering for the entries this box can observe, and the two
# routes). GITHUB_TOKEN is read from the environment only -- unset here, and
# nothing in this file sets it, so github_workflow entries render amber "no
# GitHub token configured" until an operator adds one. No new secret is
# added by this ticket to make them green.
TRUTH_MANIFEST_PATH = os.getenv(
    "TRUTH_MANIFEST_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "truth_manifest.yaml")
)
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

_truth_manifest_cache: list[dict] | None = None


def _load_truth_manifest() -> list[dict]:
    """Cached manifest load. A bad manifest is a loud, visible error on the
    /admin/truth route (500 with the validation errors) rather than a
    reason to fail the whole app's startup -- this is one ops page among
    150+ routes, not core scan functionality."""
    global _truth_manifest_cache
    if _truth_manifest_cache is None:
        _truth_manifest_cache = truth.load_manifest(TRUTH_MANIFEST_PATH)
    return _truth_manifest_cache


def _get_truth_reports() -> dict:
    """Latest reported observation per (scope, entry_id), from the
    truth-report.sh push-reporter (deploy/truth-report.{sh,service,timer}).
    Empty until that reporter is installed on api-01/portal-01 -- see
    POST /admin/truth/report below."""
    try:
        with get_db() as db:
            rows = db.execute(
                "SELECT scope, entry_id, success, detail, observed_at FROM truth_reports"
            ).fetchall()
    except Exception as e:
        print(f"[truth] failed to read truth_reports: {e}")
        return {}
    out = {}
    for row in rows:
        observed_at = truth._parse_iso(row["observed_at"])
        success = None if row["success"] is None else bool(row["success"])
        out[(row["scope"], row["entry_id"])] = truth.Observation(
            observed_at=observed_at, success=success, detail=row["detail"] or "",
        )
    return out


def _build_truth_page() -> dict:
    manifest = _load_truth_manifest()
    check_statuses_by_name = {row["name"]: row for row in _get_check_statuses()}
    ctx = truth.CollectionContext(
        now=datetime.now(timezone.utc),
        is_local_prod01=True,  # this app runs on prod-01; see AGENTS.md
        check_statuses_by_name=check_statuses_by_name,
        github_token=GITHUB_TOKEN or None,
        reported_observations=_get_truth_reports(),
    )
    return truth.build_truth_page(manifest, ctx)


# ── PAT-1716: nightly uninstall E2E verification heartbeat ──────────────────
# Something that fails safe looks exactly like something healthy (PAT-912,
# PAT-837, PAT-960) -- the nightly macOS/Windows uninstall E2E jobs must be
# visible on this same automation surface when they STOP running, not only
# when they fail outright. This is data, not code: add a row here (and a
# matching truth_manifest.yaml `check_status` entry, scope github:patched.im)
# when a new job -- a future level-2 canary -- starts reporting.
#
# check_statuses only has three states ('ok' / 'degraded' / 'unconfigured',
# enforced by that table's own CHECK constraint) -- there is no fourth
# 'failing' state to add. This reuses the exact mapping truth.py already
# documents for that table: 'degraded' is a real, evaluated failure (a
# forced-failing nightly run) and 'unconfigured' is "this check cannot
# currently attest anything" (no result within the last 36h, including a job
# that has never once reported) -- amber on the Operational Truth page
# either way, distinct from a hard failure.
NIGHTLY_UNINSTALL_JOBS = [
    {"job": "nightly-uninstall-e2e-macos",   "platform": "macos",   "level": 1,
     "check_name": "nightly_uninstall_e2e_macos"},
    {"job": "nightly-uninstall-e2e-windows", "platform": "windows", "level": 1,
     "check_name": "nightly_uninstall_e2e_windows"},
]
_NIGHTLY_UNINSTALL_JOBS_BY_NAME = {j["job"]: j for j in NIGHTLY_UNINSTALL_JOBS}
_NIGHTLY_STALE_AFTER_SECONDS = 36 * 3600  # 36h, per the ticket brief
# A finished_at in the future (clock skew, a bad workflow `date`, a typo'd
# year) would otherwise give a negative age, and a negative age is never
# ">" the staleness threshold -- the job would read ok forever even after
# it stops reporting. Rejected at ingest (400) and, for a row already
# stored some other way, caught again at evaluation time as unconfigured.
_NIGHTLY_FUTURE_SKEW_TOLERANCE_SECONDS = 5 * 60


def _record_nightly_job_result(
    job: str, platform: str, level: int, run_url: str, status: str, finished_at: str, now: datetime,
) -> None:
    """Persist the latest reported result for one nightly job, then
    immediately re-evaluate its check_statuses row -- a fresh pass/fail is
    reflected right away, not only on the next hourly sweep."""
    with get_db() as db:
        db.execute(
            "INSERT INTO nightly_job_results (job, platform, level, run_url, status, finished_at, recorded_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(job) DO UPDATE SET "
            "platform=excluded.platform, level=excluded.level, run_url=excluded.run_url, "
            "status=excluded.status, finished_at=excluded.finished_at, recorded_at=excluded.recorded_at",
            (job, platform, level, run_url, status, finished_at, now.isoformat()),
        )
    _evaluate_nightly_job_check(job, now)


def _evaluate_nightly_job_check(job: str, now: datetime) -> None:
    """Recompute one nightly job's check_statuses row from its latest
    reported result. Called both on ingestion (POST /admin/nightly-checks/report)
    and every scheduler tick (_run_nightly_uninstall_checks_tick), so a job
    that simply stops reporting still transitions to unconfigured (stale)
    without needing a new report to trigger it."""
    entry = _NIGHTLY_UNINSTALL_JOBS_BY_NAME.get(job)
    if not entry:
        return
    check_name = entry["check_name"]
    with get_db() as db:
        row = db.execute(
            "SELECT platform, level, run_url, status, finished_at FROM nightly_job_results WHERE job = ?",
            (job,),
        ).fetchone()

    if not row:
        _record_check_status(
            check_name, "unconfigured",
            f"{job}: no nightly result has ever been recorded", now,
        )
        return

    finished_at = truth._parse_iso(row["finished_at"])
    if finished_at is None:
        _record_check_status(
            check_name, "unconfigured",
            f"{job}: last recorded finished_at {row['finished_at']!r} could not be parsed", now,
        )
        return

    skew_seconds = (finished_at - now).total_seconds()
    if skew_seconds > _NIGHTLY_FUTURE_SKEW_TOLERANCE_SECONDS:
        # Defence in depth: post_nightly_check_report already rejects a
        # future finished_at at ingest, but a row could reach this table
        # some other way (a direct DB write, a stored row from before this
        # guard existed). A future timestamp must never read as fresh.
        _record_check_status(
            check_name, "unconfigured",
            f"{job}: recorded finished_at {row['finished_at']} is "
            f"{truth._human_seconds(skew_seconds)} in the future -- clock skew or a bad timestamp, "
            f"not evidence of a recent run", now,
        )
        return

    if row["status"] == "fail":
        _record_check_status(
            check_name, "degraded",
            f"{job} (level {row['level']}) FAILED at {row['finished_at']} -- {row['run_url']}", now,
        )
        return

    age_seconds = (now - finished_at).total_seconds()
    if age_seconds > _NIGHTLY_STALE_AFTER_SECONDS:
        _record_check_status(
            check_name, "unconfigured",
            f"{job} (level {row['level']}): last passing result is "
            f"{truth._human_seconds(age_seconds)} old, no result within 36h -- {row['run_url']}", now,
        )
        return

    _record_check_status(
        check_name, "ok",
        f"{job} (level {row['level']}) passed at {row['finished_at']} -- {row['run_url']}", now,
    )


def _run_nightly_uninstall_checks_tick(now: datetime) -> None:
    """Scheduler tick (registered in scheduler_loop): re-evaluate every
    registered nightly job's check_statuses row every hour, independent of
    whether a new report arrived -- this is what turns "the workflow was
    disabled two days ago" into a visible degraded state rather than a row
    that just quietly stops updating."""
    for entry in NIGHTLY_UNINSTALL_JOBS:
        _evaluate_nightly_job_check(entry["job"], now)


# get_db is imported from shared.py

# ══════════════════════════════════════════════════════════════
# SCHEDULER
# ══════════════════════════════════════════════════════════════
JOBS = {}


# PAT-697: ONE server-owned device-freshness vocabulary. The UI bucket helper
# (_dhFreshnessBucket in console.html), the weekly stale-endpoint digest default,
# the platform-owned report catalogue's "stale-endpoints" description, and any
# future consumer all read these thresholds — injected into the /console template
# context and served at GET /api/config/freshness — so the email digest and the
# on-screen estate view can never disagree about what "stale" means.
#
#   Active   last_seen  < active_max_days          (7d)
#   Stale    active_max_days ≤ last_seen < silent_min_days   (7–30d)
#   Silent   last_seen ≥ silent_min_days, or never seen      (≥30d)
#
# NOTE: "stale" here refers exclusively to *device* freshness. Infra/job lag
# (ingest, backups, automations) is deliberately labelled "lagging"/"overdue"
# so the two concepts never blur together.
DEVICE_FRESHNESS = {"active_max_days": 7, "silent_min_days": 30}

# The weekly stale-endpoint digest default derives from the shared vocabulary so
# the email and the UI agree. PAT-697 dropped this from 14 → 7 (== active_max_days);
# tenants without an explicit per-tenant stale_digest_threshold_days override now
# get "stale" flagged sooner, matching the estate view. Per-tenant overrides still win.
STALE_THRESHOLD_DEFAULT_DAYS = DEVICE_FRESHNESS["active_max_days"]

_CERT_FREQ_HOURS = {"daily": 24, "weekly": 168, "monthly": 720}

# ── Automation staleness detection ───────────────────────────────────────────
# Expected max hours between runs, per job_name. This is a "silent stop" guard,
# distinct from the run-FAILURE alert below: a job whose last_status is stuck
# at "success" because it simply stopped running looks identical to a healthy
# job unless something checks how long ago it last ran.
#
# The remaining scheduled job is believed to run daily. This map has no
# visibility into the actual cron/systemd-timer definitions in the API repo,
# so its 24h value is a best-effort placeholder rather than a schedule source
# of truth.
_AUTOMATION_EXPECTED_INTERVAL_HOURS = {
    "health_signals_recompute": 24,
}

# These persisted names can still arrive from patched-api-01, but they are not
# scheduled Dashboard automation. They must never be counted as healthy,
# failed, or overdue 24-hour work.
_QUARANTINED_AUTOMATIONS = {
    "installomator_sync": "quarantined legacy execution",
    "daily_vendor_verify": "retired daily vendor verification",
    "mirror_pipeline": "retired mirror pipeline",
    "mirror_pipeline_windows": "retired Windows mirror pipeline",
}

# DEFAULT for any job_name NOT in the map above — covers newly-registered jobs
# (e.g. a future registered job) before anyone remembers to add an entry.
# Every existing daily tick in this scheduler_loop (cert digest, stale-endpoint
# digest, report tick, trial-expiry) already runs on a 24h cadence, so "expect
# at least one run every 24h" is the least-surprising default for a brand-new
# automation — it will not nag on a job that legitimately runs less often
# without also having gone a full silent week first.
_AUTOMATION_DEFAULT_INTERVAL_HOURS = 24

# Multiplier applied to the expected interval before declaring staleness —
# absorbs ordinary schedule jitter (a 06:00 UTC job that lands at 08:00 one
# day is not an outage) while still catching a genuinely dead job well before
# a human would otherwise notice. 1.5x turns a 24h daily job into a 36h alert.
_AUTOMATION_STALE_MULTIPLIER = 1.5

# Optional hint used ONLY for jobs not present in the explicit map above — a
# few common cadence keywords read out of the freeform `schedule` string.
# Deliberately not a general schedule parser: the explicit map always wins,
# this is just a better-than-nothing fallback for a job nobody has mapped yet.
_AUTOMATION_SCHEDULE_HINT_HOURS = {"hourly": 1, "daily": 24, "weekly": 168, "monthly": 720}

# Build-id-independent console deep link — /console 302s to /console/{CONSOLE_BUILD_ID}
# but browsers re-attach the original URL fragment across a same-origin redirect
# whose Location has no fragment of its own, so this link never needs to embed
# (or drift from) a build id. #automations opens the Service Health ▸ Automations
# tab (see templates/console.html `consoleNav('automations')`).
_AUTOMATIONS_CONSOLE_URL = "https://dashboard.patched.im/console#automations"


def _automation_expected_interval_hours(job_name: str, schedule: str = "") -> float | None:
    """Expected max hours between runs for `job_name`. The explicit map always
    wins; `schedule` (freeform, e.g. "Daily (06:00 UTC)") is only consulted for
    jobs not yet in the map, and only for a few common cadence keywords.

    Quarantined legacy execution jobs deliberately have no expected cadence.
    """
    if job_name in _QUARANTINED_AUTOMATIONS:
        return None
    if job_name in _AUTOMATION_EXPECTED_INTERVAL_HOURS:
        return _AUTOMATION_EXPECTED_INTERVAL_HOURS[job_name]
    lower = (schedule or "").lower()
    for keyword, hours in _AUTOMATION_SCHEDULE_HINT_HOURS.items():
        if keyword in lower:
            return hours
    return _AUTOMATION_DEFAULT_INTERVAL_HOURS


def _fmt_duration_hours(hours: float) -> str:
    """Human-readable duration from a float hour count, e.g. 2.3 -> '2h', 30 -> '1d 6h'."""
    total_minutes = int(round(hours * 60))
    days, rem_minutes = divmod(total_minutes, 24 * 60)
    hrs, minutes = divmod(rem_minutes, 60)
    if days:
        return f"{days}d {hrs}h" if hrs else f"{days}d"
    if hrs:
        return f"{hrs}h {minutes}m" if minutes else f"{hrs}h"
    return f"{minutes}m"


# PAT-1847: platform owns report metadata and admin PDF paths. The dashboard
# deliberately keeps only a short-lived, validated copy so a registry outage
# cannot cause it to invent a stale local list or send a report down a guessed
# path. The platform client below adds ADMIN_API_TOKEN automatically.
_REPORT_CATALOGUE_TTL_SECONDS = 60
# A failed platform request is also cached briefly. Without this, every report
# panel, download, email send and scheduler tick retries the same unavailable
# dependency, turning one outage into avoidable traffic and noisy logs.
_REPORT_CATALOGUE_FAILURE_TTL_SECONDS = 10
_REPORT_CATALOGUE_CACHE = {
    "entries": None,
    "fetched_at": 0.0,
    "failure_reason": None,
    "failure_at": 0.0,
}
_REPORT_CATALOGUE_LOCK = threading.Lock()
_REPORT_FREQUENCIES = frozenset({"daily", "weekly", "monthly", "quarterly", "ad_hoc"})
_REPORT_TYPE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


class ReportCatalogueUnavailable(RuntimeError):
    """The platform registry cannot safely be used for this request."""


def _validated_report_catalogue(payload) -> tuple[dict, ...]:
    """Validate platform report metadata before it can drive dashboard routes.

    The catalogue supplies a server-side URL template, so accepting a partial
    or malformed response would turn an upstream contract failure into a
    potentially surprising internal request. Reject the whole response rather
    than quietly dropping entries: an explicit unavailable UI is safer than a
    plausible but incomplete reports workspace.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("reports"), list):
        raise ReportCatalogueUnavailable("platform returned an invalid report catalogue")
    entries = payload["reports"]
    if not entries:
        raise ReportCatalogueUnavailable("platform returned an empty report catalogue")

    seen = set()
    validated = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ReportCatalogueUnavailable("platform report catalogue contains a malformed entry")
        report_type = entry.get("type")
        label = entry.get("label")
        description = entry.get("description")
        frequency = entry.get("default_frequency")
        customer_facing = entry.get("customer_facing")
        scope = entry.get("subject_scope")
        admin_pdf_path = entry.get("admin_pdf_path")
        if (
            not isinstance(report_type, str) or not _REPORT_TYPE_RE.fullmatch(report_type)
            or report_type in seen
            or not isinstance(label, str) or not label.strip()
            or not isinstance(description, str) or not description.strip()
            or not isinstance(frequency, str) or frequency not in _REPORT_FREQUENCIES
            or type(customer_facing) is not bool
            or scope not in {"tenant", "device"}
            or not isinstance(admin_pdf_path, str)
        ):
            raise ReportCatalogueUnavailable("platform report catalogue contains an invalid entry")
        if (
            not admin_pdf_path.startswith("/admin/reports/")
            or "?" in admin_pdf_path or "#" in admin_pdf_path
            or ".." in admin_pdf_path or "//" in admin_pdf_path
            # Templates are product-controlled paths, not values. Reject any
            # encoded form rather than trying to normalise it: `%2e`, `%2f`
            # and `%5c` variants could otherwise become traversal/separators
            # in a later URL-handling layer before the internal request.
            or "%" in admin_pdf_path or "\\" in admin_pdf_path
            or not admin_pdf_path.endswith(".pdf")
        ):
            raise ReportCatalogueUnavailable("platform report catalogue contains an unsafe PDF path")
        tenant_tokens = admin_pdf_path.count("{tenantID}")
        device_tokens = admin_pdf_path.count("{deviceID}")
        if (
            (scope == "tenant" and (tenant_tokens != 1 or device_tokens != 0))
            or (scope == "device" and (device_tokens != 1 or tenant_tokens != 0))
            or "{" in admin_pdf_path.replace("{tenantID}", "").replace("{deviceID}", "")
        ):
            raise ReportCatalogueUnavailable("platform report catalogue has an invalid subject template")
        seen.add(report_type)
        validated.append({
            "type": report_type,
            "label": label.strip(),
            "description": description.strip(),
            "default_frequency": frequency,
            "customer_facing": customer_facing,
            "subject_scope": scope,
            "admin_pdf_path": admin_pdf_path,
        })
    # The generic dashboard proxy accepts both the stable report type and a
    # legacy first path segment. Neither namespace is allowed to shadow a
    # different report: otherwise a valid catalogue could make a pre-existing
    # `/admin/reports/<reference>/<subject>` link fetch a different PDF.
    reference_owners = {}
    for definition in validated:
        first_segment = definition["admin_pdf_path"].removeprefix("/admin/reports/").split("/", 1)[0]
        for reference in {definition["type"], first_segment}:
            owner = reference_owners.setdefault(reference, definition["type"])
            if owner != definition["type"]:
                raise ReportCatalogueUnavailable("platform report catalogue has ambiguous proxy references")
    return tuple(validated)


def _report_catalogue() -> tuple[dict, ...]:
    """Return the bounded platform registry cache, or fail explicitly.

    The positive cache is only populated after complete validation. A separate
    short negative cache bounds retries during a platform outage without making
    an old dashboard-owned report list a fallback source of truth.
    """
    now = time.monotonic()
    with _REPORT_CATALOGUE_LOCK:
        cached = _REPORT_CATALOGUE_CACHE["entries"]
        if cached is not None and now - _REPORT_CATALOGUE_CACHE["fetched_at"] < _REPORT_CATALOGUE_TTL_SECONDS:
            return cached
        failure_reason = _REPORT_CATALOGUE_CACHE["failure_reason"]
        if failure_reason and now - _REPORT_CATALOGUE_CACHE["failure_at"] < _REPORT_CATALOGUE_FAILURE_TTL_SECONDS:
            raise ReportCatalogueUnavailable(failure_reason)
        try:
            response = http.get(
                f"{PATCHED_API_INTERNAL}/admin/reports/catalogue",
                timeout=5,
                verify=_VERIFY_INTERNAL,
                headers={"User-Agent": "Patched-Dashboard/1.0"},
            )
        except requests.RequestException as exc:
            failure = ReportCatalogueUnavailable("platform report catalogue is unreachable")
            _REPORT_CATALOGUE_CACHE.update(entries=None, failure_reason=str(failure), failure_at=now)
            raise failure from exc
        try:
            if response.status_code != 200:
                raise ReportCatalogueUnavailable(
                    f"platform report catalogue returned {response.status_code}"
                )
            entries = _validated_report_catalogue(response.json())
        except ReportCatalogueUnavailable as exc:
            _REPORT_CATALOGUE_CACHE.update(entries=None, failure_reason=str(exc), failure_at=now)
            raise
        except (ValueError, TypeError, requests.RequestException) as exc:
            failure = ReportCatalogueUnavailable("platform returned an unreadable report catalogue")
            _REPORT_CATALOGUE_CACHE.update(entries=None, failure_reason=str(failure), failure_at=now)
            raise failure from exc
        _REPORT_CATALOGUE_CACHE.update(
            entries=entries, fetched_at=now, failure_reason=None, failure_at=0.0,
        )
        return entries


def _report_definition(report_type: str, *, subject_scope: str | None = None) -> dict | None:
    for definition in _report_catalogue():
        if definition["type"] == report_type and (
            subject_scope is None or definition["subject_scope"] == subject_scope
        ):
            return definition
    return None


def _report_definition_for_reference(reference: str) -> dict | None:
    """Resolve a current type or legacy first-path-segment without a local map."""
    definitions = _report_catalogue()
    for definition in definitions:
        if definition["type"] == reference:
            return definition
    for definition in definitions:
        remainder = definition["admin_pdf_path"].removeprefix("/admin/reports/")
        first_segment = remainder.split("/", 1)[0]
        if first_segment == reference:
            return definition
    return None


def _report_platform_path(definition: dict, *, tenant_id: str | None = None, device_id: str | None = None) -> str:
    """Substitute exactly the subject identifier authorised by the registry."""
    scope = definition["subject_scope"]
    if scope == "tenant":
        if not tenant_id or device_id is not None:
            raise ValueError("tenant report requires exactly one tenant id")
        return definition["admin_pdf_path"].replace("{tenantID}", _seg(tenant_id))
    if scope == "device":
        if not device_id or tenant_id is not None:
            raise ValueError("device report requires exactly one device id")
        return definition["admin_pdf_path"].replace("{deviceID}", _seg(device_id))
    raise ValueError("unknown report subject scope")

# Bridge: these two catalog types reuse existing per-tenant digest columns so the
# standalone ticks (cert/stale) remain the senders — no double-sends.
_REPORT_BRIDGE_CERT  = "cert-expiry"
_REPORT_BRIDGE_STALE = "stale-endpoints"

_CERT_SEVERITY_PARAMS = {
    "expired_only":           None,
    "expired_plus_critical":  7,
    "expired_plus_warning":   30,
    "all_categorised":        None,
}


def _cert_digest_recipient_for(client: dict) -> str | None:
    if client.get("cert_digest_recipient"):
        return client["cert_digest_recipient"]
    # Fallback: look up tenant contact email from go-service /admin/tenants
    try:
        r = http.get(f"{PATCHED_API_INTERNAL}/admin/tenants", timeout=10, verify=_VERIFY_INTERNAL)
        if r.status_code == 200:
            for t in (r.json().get("tenants") or []):
                if t.get("id") == client["tenant_id"]:
                    return t.get("contact_email") or t.get("email") or None
    except Exception as e:
        print(f"[cert-digest] tenant email lookup failed: {e}")
    return None


def _enrich_certificates(raw: list) -> list[dict]:
    """Share current expiry and provenance across staff reads and digests."""
    enriched = []
    for original in raw:
        if not isinstance(original, dict):
            continue
        cert = dict(original)
        days = compute_days_until_expiry(cert)
        cert["type"] = classify_cert_type(cert)
        cert["source"] = "uploaded" if cert.get("source") == "uploaded" else "agent"
        cert["days_until_expiry"] = days
        cert["status"] = (
            "unknown" if days is None else
            "expired" if days < 0 else
            "critical" if days <= 7 else
            "warning" if days <= 30 else "healthy"
        )
        enriched.append(cert)
    return enriched


def _run_cert_digest_tick(now: datetime):
    """Send due cert digest emails. Called once per scheduler tick."""
    with get_db() as db:
        due_clients = db.execute(
            "SELECT * FROM clients WHERE cert_digest_enabled=1"
        ).fetchall()

    for client in due_clients:
        client = dict(client)
        freq_hours = _CERT_FREQ_HOURS.get(client.get("cert_digest_frequency") or "daily", 24)
        last_sent = client.get("last_cert_digest_sent_at")
        if last_sent:
            try:
                last_dt = datetime.fromisoformat(last_sent.replace("Z", "+00:00"))
                if (now - last_dt).total_seconds() < freq_hours * 3600:
                    continue
            except Exception:
                pass

        tenant_id = client["tenant_id"]
        severity = client.get("cert_digest_severity") or "expired_plus_critical"
        expiring_days = _CERT_SEVERITY_PARAMS.get(severity)

        try:
            params = {}
            if expiring_days is not None:
                params["expiring_within_days"] = str(expiring_days)
            r = http.get(
                f"{PATCHED_API_INTERNAL}/admin/tenant/{_seg(tenant_id)}/certs",
                params=params,
                timeout=15,
                verify=_VERIFY_INTERNAL,
            )
            if r.status_code != 200:
                print(f"[cert-digest] go-service returned {r.status_code} for tenant {tenant_id}")
                continue
            raw_certs = r.json() if isinstance(r.json(), list) else []
        except Exception as e:
            print(f"[cert-digest] fetch failed for tenant {tenant_id}: {e}")
            continue

        enriched = _enrich_certificates(raw_certs)

        if severity == "expired_only":
            certs_to_send = [c for c in enriched if c["status"] == "expired"]
        elif severity == "expired_plus_critical":
            certs_to_send = [c for c in enriched if c["status"] in {"expired", "critical"}]
        elif severity == "expired_plus_warning":
            certs_to_send = [c for c in enriched if c["status"] in {"expired", "critical", "warning"}]
        else:
            certs_to_send = enriched

        if not certs_to_send and severity != "all_categorised":
            continue

        recipient = _cert_digest_recipient_for(client)
        if not recipient:
            print(f"[cert-digest] no recipient for tenant {tenant_id} — skipping")
            continue

        counts = {
            status: sum(1 for c in certs_to_send if c["status"] == status)
            for status in ("expired", "critical", "warning", "healthy", "unknown")
        }
        severity_labels = {
            "expired_only": "Expired Only",
            "expired_plus_critical": "Expired + Critical (≤7d)",
            "expired_plus_warning": "Expired + Warning (≤30d)",
            "all_categorised": "All Categorised",
        }
        ctx = {
            "estate_name": client.get("company"),
            "certs": sorted(certs_to_send, key=lambda c: (c["days_until_expiry"] is None,
                                                        c["days_until_expiry"] or 0)),
            "band": severity,
            "severity_label": severity_labels.get(severity, severity),
            "cert_view_url": f"{PUBLIC_BASE_URL}/certs?tenant_id={tenant_id}",
            "counts": counts,
        }

        subject, html, text = render_report_email(
            "cert_digest_email", report_label="Certificate Expiry Digest",
            period=now.date().isoformat(), **ctx,
        )

        ok = _send_email(recipient, subject, html, text)
        # PAT-1010 (round 4): cert-digest frequency can be weekly/monthly
        # (cert_digest_frequency), so marking last_cert_digest_sent_at under
        # EMAIL_DRY_RUN doesn't just delay the real send to "next tick" --
        # it skips it until the next scheduled occurrence of that cadence,
        # the same shape of defect already fixed on report_schedule_sends.
        if ok and email_delivery_status() == "dry_run":
            print(f"[cert-digest] EMAIL_DRY_RUN active, not marking tenant {tenant_id} "
                  f"sent (no email actually sent to {recipient})")
        elif ok:
            with get_db() as db:
                db.execute(
                    "UPDATE clients SET last_cert_digest_sent_at=? WHERE tenant_id=?",
                    (now.isoformat(), tenant_id),
                )
            print(f"[cert-digest] sent to {recipient} for tenant {tenant_id}")
        else:
            print(f"[cert-digest] send failed for {recipient} tenant {tenant_id} — will retry next tick")


def _stale_digest_recipient_for(client: dict) -> str | None:
    """Recipient = explicit override, else the tenant's primary contact."""
    if client.get("stale_digest_recipient"):
        return client["stale_digest_recipient"]
    return client.get("primary_contact_email") or None


def _report_recipient_for(sub: dict, client: dict) -> str | None:
    """Recipient for a scheduled report: per-subscription override → primary contact."""
    if sub.get("recipient"):
        return sub["recipient"]
    return client.get("primary_contact_email") or None


def _run_stale_digest_tick(now: datetime):
    """Send due weekly stale-endpoint digests. Called once per scheduler tick.

    Mirrors _run_cert_digest_tick: list active (non-revoked) tenants from the
    overview proxy, find endpoints whose last_seen exceeds the tenant threshold,
    and email the primary contact at most once per 7 days. A fully-fresh estate
    gets no email (no-noise rule).
    """
    # Active tenants only — the overview endpoint already excludes revoked/offboarded.
    try:
        r = http.get(
            f"{PATCHED_API_INTERNAL}/admin/tenants/overview",
            timeout=15,
            verify=_VERIFY_INTERNAL,
        )
        if r.status_code != 200:
            print(f"[stale-digest] overview returned {r.status_code} — skipping tick")
            return
        active_tenants = r.json().get("tenants") or []
    except Exception as e:
        print(f"[stale-digest] overview fetch failed: {e}")
        return
    active_ids = {t.get("id") for t in active_tenants if t.get("id")}

    with get_db() as db:
        candidates = db.execute(
            "SELECT * FROM clients WHERE stale_digest_enabled=1"
        ).fetchall()

    for client in candidates:
        client = dict(client)
        tenant_id = client["tenant_id"]
        if tenant_id not in active_ids:
            continue  # revoked/offboarded — don't email

        # Send gate. Two modes:
        #   * Scheduled (PAT-575): a day_of_week and/or hour is configured — fire
        #     only on that weekday/hour (scheduler ticks hourly), with a 23h guard
        #     so a single slot can't double-send.
        #   * Legacy weekly: neither set — fire on the first tick 7 days after the
        #     last send.
        last_sent = client.get("last_stale_digest_sent_at")
        dow  = client.get("stale_digest_day_of_week")
        hour = client.get("stale_digest_hour")
        if dow is not None or hour is not None:
            if dow is not None and now.weekday() != dow:
                continue
            if hour is not None and now.hour != hour:
                continue
            if last_sent:
                try:
                    last_dt = datetime.fromisoformat(last_sent.replace("Z", "+00:00"))
                    if (now - last_dt).total_seconds() < 23 * 3600:
                        continue
                except Exception:
                    pass
        else:
            if last_sent:
                try:
                    last_dt = datetime.fromisoformat(last_sent.replace("Z", "+00:00"))
                    if (now - last_dt).total_seconds() < 7 * 24 * 3600:
                        continue
                except Exception:
                    pass

        threshold_days = client.get("stale_digest_threshold_days") or STALE_THRESHOLD_DEFAULT_DAYS
        cutoff = now - timedelta(days=threshold_days)

        try:
            dr = http.get(
                f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/devices",
                timeout=15,
                verify=_VERIFY_INTERNAL,
            )
            if dr.status_code != 200:
                print(f"[stale-digest] devices returned {dr.status_code} for tenant {tenant_id}")
                continue
            devices = dr.json().get("devices") or []
        except Exception as e:
            print(f"[stale-digest] devices fetch failed for tenant {tenant_id}: {e}")
            continue

        stale = []
        for d in devices:
            ls_raw = d.get("last_seen")
            if not ls_raw:
                continue
            try:
                ls = datetime.fromisoformat(ls_raw.replace("Z", "+00:00"))
            except Exception:
                continue
            if ls < cutoff:
                days_stale = int((now - ls).total_seconds() // 86400)
                stale.append({
                    "hostname": d.get("hostname") or d.get("serial") or d.get("id") or "(unknown)",
                    "last_seen": ls_raw,
                    "last_seen_date": ls_raw[:10],
                    "days_stale": days_stale,
                })

        # No-noise rule: a fully-fresh estate gets no email.
        if not stale:
            continue

        recipient = _stale_digest_recipient_for(client)
        if not recipient:
            # No contact on file — log + record the gap so staff can see it.
            print(f"[stale-digest] no contact on file for tenant {tenant_id} "
                  f"({client.get('company', tenant_id)}) — {len(stale)} stale, skipping")
            continue

        stale.sort(key=lambda s: s["days_stale"], reverse=True)
        ctx = {
            "estate_name": client.get("company"),
            "devices": stale,
            "threshold_days": threshold_days,
            "stale_count": len(stale),
            "console_url": f"{PUBLIC_BASE_URL}/console#tenant/{tenant_id}/device-health",
        }
        subject, html, text = render_report_email(
            "stale_digest_email", report_label="Stale Endpoint Digest",
            period=now.date().isoformat(), **ctx,
        )

        ok = _send_email(recipient, subject, html, text)
        # PAT-1010 (round 4): stale digest is fixed weekly, so marking
        # last_stale_digest_sent_at under EMAIL_DRY_RUN doesn't just delay
        # the real send to "next tick" -- it skips it for a full week, the
        # same shape of defect already fixed on report_schedule_sends.
        if ok and email_delivery_status() == "dry_run":
            print(f"[stale-digest] EMAIL_DRY_RUN active, not marking tenant {tenant_id} "
                  f"sent (no email actually sent to {recipient})")
        elif ok:
            with get_db() as db:
                db.execute(
                    "UPDATE clients SET last_stale_digest_sent_at=? WHERE tenant_id=?",
                    (now.isoformat(), tenant_id),
                )
            print(f"[stale-digest] sent to {recipient} for tenant {tenant_id} ({len(stale)} stale)")
        else:
            print(f"[stale-digest] send failed for {recipient} tenant {tenant_id} — will retry next tick")


def _run_report_tick(now: datetime):
    """PAT-539: send due scheduled report PDFs. Called once per scheduler tick (hourly).

    For each tenant, for each enabled subscription in report_subscriptions, gate on the
    configured frequency, fetch the PDF from the Go service, attach it via _send_email(),
    and log to report_deliveries. Bridge types (cert-expiry, stale-endpoints) are driven
    by the existing dedicated ticks and are excluded here to avoid double-sends.
    """
    try:
        definitions = {entry["type"]: entry for entry in _report_catalogue()}
    except ReportCatalogueUnavailable as exc:
        # Resolve the catalogue before reading or updating subscriptions. A later
        # hourly tick can therefore retry every due delivery unchanged.
        print(f"[report-tick] platform catalogue unavailable — skipping tick: {exc}")
        return f"platform catalogue unavailable: {exc}"

    with get_db() as db:
        subs = db.execute(
            "SELECT rs.tenant_id, rs.report_type, rs.enabled, rs.frequency, "
            "rs.recipient, rs.last_sent_at, "
            "c.company, c.primary_contact_email "
            "FROM report_subscriptions rs "
            "JOIN clients c ON c.tenant_id = rs.tenant_id "
            "WHERE rs.enabled = 1 AND rs.report_type NOT IN (?, ?)",
            (_REPORT_BRIDGE_CERT, _REPORT_BRIDGE_STALE),
        ).fetchall()

    for sub in subs:
        sub = dict(sub)
        tenant_id   = sub["tenant_id"]
        report_type = sub["report_type"]
        freq_hours  = _CERT_FREQ_HOURS.get(sub.get("frequency") or "monthly", 720)

        last_sent = sub.get("last_sent_at")
        if last_sent:
            try:
                last_dt = datetime.fromisoformat(last_sent.replace("Z", "+00:00"))
                if (now - last_dt).total_seconds() < freq_hours * 3600:
                    continue
            except Exception:
                pass

        definition = definitions.get(report_type)
        if not definition or definition["subject_scope"] != "tenant":
            print(f"[report-tick] no tenant report definition for {report_type!r} — skipping")
            continue
        platform_path = _report_platform_path(definition, tenant_id=tenant_id)

        try:
            r = http.get(
                f"{PATCHED_API_INTERNAL}{platform_path}",
                timeout=30, verify=_VERIFY_INTERNAL,
            )
        except Exception as e:
            print(f"[report-tick] fetch failed for {report_type}/{tenant_id}: {e}")
            continue
        if r.status_code != 200:
            print(f"[report-tick] go-service {r.status_code} for {report_type}/{tenant_id} — skipping")
            continue

        client_ctx = {"primary_contact_email": sub.get("primary_contact_email")}
        recipient  = _report_recipient_for(sub, client_ctx)
        if not recipient:
            print(f"[report-tick] no recipient for {report_type}/{tenant_id} — skipping")
            continue

        label = definition["label"]
        tname = sub.get("company") or tenant_id
        subject, html_body, text_body = render_report_email(
            "report_attachment_email", estate_name=sub.get("company"),
            report_label=label, period=now.date().isoformat(),
        )
        display_name = email_display_label(sub.get("company"))
        fname = f"{report_type}-{display_name.lower().replace(' ', '-')}-{now.strftime('%Y%m%d')}.pdf"

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp.write(r.content)
            tmp_path = tmp.name

        try:
            ok = _send_email(recipient, subject, html_body, text_body,
                             attachment_path=tmp_path, attachment_name=fname)
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

        if ok and email_delivery_status() == "dry_run":
            # PAT-1010: _send_email() returns True under EMAIL_DRY_RUN, but
            # last_sent_at gates the *next* real send (this tenant would be
            # silently skipped next period) and _log_report_delivery() writes
            # a "sent" row straight into the Reports > Delivery Log the
            # console UI renders. Treat dry-run like the existing
            # send-failure path below: don't record it, so a real send still
            # happens once dry-run is off.
            print(f"[report-tick] EMAIL_DRY_RUN active, not marking {report_type}/{tenant_id} "
                  f"sent (no email actually sent)")
        elif ok:
            with get_db() as db:
                db.execute(
                    "UPDATE report_subscriptions SET last_sent_at=? "
                    "WHERE tenant_id=? AND report_type=?",
                    (now.isoformat(), tenant_id, report_type),
                )
            _log_report_delivery(tenant_id, report_type, tenant_name=tname, recipient=recipient)
            print(f"[report-tick] sent {report_type} to {recipient} for tenant {tenant_id}")
        else:
            print(f"[report-tick] send failed for {report_type}/{tenant_id} — will retry next tick")


# ── PAT-370: Report schedule email send loop ─────────────────────────────────

def _is_schedule_due(sched: dict, today) -> bool:
    """Return True if this schedule should fire today.

    Cadence rules:
      daily     — always.
      weekly    — fires on the configured day_of_week (1=Mon … 7=Sun, ISO-week convention).
      monthly   — fires on cadence_config.day_of_month, clamped to the last day of the month.
      quarterly — fires only in March, June, September, December (fixed-quarter model),
                  on cadence_config.day_of_month, clamped to the last day of the month.
      ad_hoc    — never (triggered manually only).
    """
    cadence = sched.get("cadence", "monthly")
    config  = sched.get("cadence_config") or {}
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except Exception:
            config = {}

    if cadence == "daily":
        return True

    if cadence == "weekly":
        dow = int(config.get("day_of_week", 1))  # 1=Monday, 7=Sunday (ISO)
        return today.weekday() == (dow - 1)       # Python: Mon=0 … Sun=6

    if cadence in ("monthly", "quarterly"):
        if cadence == "quarterly" and today.month not in (3, 6, 9, 12):
            return False
        dom = int(config.get("day_of_month", 1))
        # Clamp to last day of the current month so day=31 works in Feb etc.
        if today.month == 12:
            last_day = 31
        else:
            from datetime import date as _date_cls
            last_day = (_date_cls(today.year, today.month + 1, 1) - timedelta(days=1)).day
        return today.day == min(dom, last_day)

    # ad_hoc or unknown
    return False


def _period_for_schedule(sched: dict, today) -> "tuple[str, str]":
    """Return (period_start, period_end) ISO date strings for the schedule's current period."""
    from datetime import date as _date_cls
    cadence = sched.get("cadence", "monthly")

    def _last_day(year, month):
        if month == 12:
            return _date_cls(year + 1, 1, 1) - timedelta(days=1)
        return _date_cls(year, month + 1, 1) - timedelta(days=1)

    if cadence == "daily":
        return today.isoformat(), today.isoformat()

    if cadence == "weekly":
        monday = today - timedelta(days=today.weekday())
        return monday.isoformat(), (monday + timedelta(days=6)).isoformat()

    if cadence == "monthly":
        first = today.replace(day=1)
        last  = _last_day(today.year, today.month)
        return first.isoformat(), last.isoformat()

    if cadence == "quarterly":
        # Fixed-quarter model: Q1=Jan-Mar, Q2=Apr-Jun, Q3=Jul-Sep, Q4=Oct-Dec.
        q_start_month = ((today.month - 1) // 3) * 3 + 1
        q_end_month   = q_start_month + 2
        first = today.replace(month=q_start_month, day=1)
        last  = _last_day(today.year, q_end_month)
        return first.isoformat(), last.isoformat()

    return today.isoformat(), today.isoformat()


def _resolve_schedule_recipients(tenant_id: str, sched: dict) -> "list[str]":
    """Resolve recipient email addresses from a schedule's recipient_ids + ad_hoc_emails.

    recipient_ids: JSON array of {type:"contact", id:"<uuid>"} or {type:"user", email:"..."}
    ad_hoc_emails: JSON array of plain email strings.

    Fetches delivery contacts from the Go service when contact refs are present.
    Returns a deduplicated, lowercased list.
    """
    def _parse_json(v):
        if isinstance(v, list):   return v
        if isinstance(v, str):
            try: return json.loads(v)
            except Exception: return []
        return []

    recipient_ids = _parse_json(sched.get("recipient_ids"))
    ad_hoc_emails = _parse_json(sched.get("ad_hoc_emails"))

    emails: set[str] = set()

    for e in ad_hoc_emails:
        if isinstance(e, str) and e.strip():
            emails.add(e.strip().lower())

    user_refs    = [r for r in recipient_ids if isinstance(r, dict) and r.get("type") == "user"]
    contact_refs = [r for r in recipient_ids if isinstance(r, dict) and r.get("type") == "contact"]

    for u in user_refs:
        e = (u.get("email") or "").strip()
        if e:
            emails.add(e.lower())

    if contact_refs:
        try:
            cr = http.get(
                f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/delivery-contacts",
                timeout=10, verify=_VERIFY_INTERNAL,
            )
            if cr.status_code == 200:
                contacts_by_id = {c["id"]: c for c in (cr.json() or [])}
                for ref in contact_refs:
                    c = contacts_by_id.get(ref.get("id", ""))
                    if c:
                        e = (c.get("email") or "").strip()
                        if e:
                            emails.add(e.lower())
        except Exception as exc:
            print(f"[report-sched] delivery-contacts fetch failed for {tenant_id}: {exc}")

    return list(emails)


def _check_tenant_report_schedules(tenant_id: str, company: str, today) -> None:
    """Check and execute any report schedules due today for a single tenant."""
    log = f"[report-sched/{company}]"
    try:
        r = http.get(
            f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/report-schedules",
            timeout=10, verify=_VERIFY_INTERNAL,
        )
    except Exception as exc:
        print(f"{log} schedule fetch error: {exc}")
        return
    if r.status_code != 200:
        print(f"{log} schedule fetch returned {r.status_code}")
        return

    schedules = r.json()
    if not isinstance(schedules, list):
        schedules = []

    for sched in schedules:
        if not _is_schedule_due(sched, today):
            continue

        schedule_id  = sched.get("id", "")
        period_start, period_end = _period_for_schedule(sched, today)

        # Idempotency: skip if the scheduler already sent this period today.
        with get_db() as db:
            already = db.execute(
                "SELECT 1 FROM report_schedule_sends "
                "WHERE tenant_id=? AND schedule_id=? AND period_start=?",
                (tenant_id, schedule_id, period_start),
            ).fetchone()
        if already:
            continue

        recipients = _resolve_schedule_recipients(tenant_id, sched)
        if not recipients:
            print(f"{log} schedule {schedule_id!r} has no recipients — skipping")
            continue

        # Generate the report via the Go service.
        month_label  = today.strftime("%B %Y")
        report_name  = f"{company} — {sched.get('name', 'Report')} — {month_label}"
        content_type = sched.get("content_type") or "full"
        try:
            gr = http.post(
                f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/report-records/generate",
                json={
                    "name":         report_name,
                    "content_type": content_type,
                    "period_start": period_start,
                    "period_end":   period_end,
                },
                timeout=120, verify=_VERIFY_INTERNAL,
            )
        except Exception as exc:
            print(f"{log} generate failed for schedule {schedule_id!r}: {exc}")
            continue

        if gr.status_code not in (200, 201):
            print(f"{log} generate {gr.status_code} for schedule {schedule_id!r}: {gr.text[:200]}")
            continue

        record    = gr.json()
        record_id = record.get("id", "")
        if not record_id:
            print(f"{log} generate returned no record id for schedule {schedule_id!r}")
            continue

        print(f"{log} generated record {record_id} for schedule {schedule_id!r} "
              f"— {len(recipients)} recipient(s)")

        # Issue single-use download tokens and email each recipient.
        now_utc    = datetime.now(timezone.utc)
        expires_at = (now_utc + timedelta(days=30)).isoformat()
        period_label = period_start if period_start == period_end else f"{period_start} to {period_end}"
        sent_to: list[str] = []

        for email_addr in recipients:
            token        = str(uuid.uuid4())
            download_url = f"{PUBLIC_BASE_URL}/reports/download/{token}"

            subject, html_body, text_body = render_report_email(
                "report_download_email", estate_name=company,
                report_label="Security Report", period=period_label,
                schedule_name=email_display_label(sched.get("name"), "Report"),
                period_start=period_start, period_end=period_end,
                download_url=download_url,
            )

            with get_db() as db:
                db.execute(
                    "INSERT OR IGNORE INTO report_ext_tokens "
                    "(token, tenant_id, record_id, email, expires_at) VALUES (?, ?, ?, ?, ?)",
                    (token, tenant_id, record_id, email_addr, expires_at),
                )

            ok = _send_email(email_addr, subject, html_body, text_body)
            if ok:
                sent_to.append(email_addr)
                print(f"{log} emailed {email_addr} (token {token[:8]}…)")
            else:
                print(f"{log} email failed for {email_addr}")

        # Record the send so the next scheduler tick skips this period — but only
        # once EVERY recipient succeeded. report_schedule_sends has no per-recipient
        # tracking (UNIQUE on tenant_id/schedule_id/period_start), so marking the
        # period done on a partial failure would permanently skip the failed
        # recipients until the next cadence window. Leaving it unmarked means the
        # whole tick retries next time — already-succeeded recipients may get a
        # duplicate, which is acceptable since email delivery isn't exactly-once here.
        #
        # PAT-1010: _send_email() returns True under EMAIL_DRY_RUN for every
        # recipient, so `ok` alone can't distinguish a real send from a
        # suppressed one. This tick runs once a day (not hourly like the
        # other digests this ticket touched), so marking the period sent
        # here would not just delay the real send until next tick, it would
        # permanently skip every recipient for this entire cadence period
        # (monthly/weekly/etc) once dry-run is off, exactly the same shape
        # of defect as every other site this ticket gates.
        #
        # Known limitation (assessed, not fixed, under this ticket): leaving
        # the period unmarked means the real send retries on this schedule's
        # NEXT scheduled occurrence of its cadence, not the next daily tick,
        # because _is_schedule_due() gates on day-of-month/day-of-week
        # before this dry-run check ever runs, and check_report_schedules
        # itself only runs once daily regardless. The identical gap applies
        # to cert-digest and stale-digest above (same "the eligibility gate,
        # not the dry-run check, decides retry cadence" shape). It also means
        # a same-day restart of this tick while still due (e.g. the process
        # bounces and check_report_schedules runs again before midnight) will
        # regenerate a fresh report record and new single-use download
        # tokens rather than reusing the ones from the earlier, unmarked
        # attempt -- duplicate report generation on that one calendar day,
        # not just delayed delivery. A cadence-independent "owed" retry that
        # avoided both (remembering the already-generated record_id and
        # original period, bypassing the day-gate on catch-up) would need a
        # new table and a new retry code path -- that's new infrastructure,
        # out of scope for this ticket.
        if sent_to and len(sent_to) == len(recipients) and email_delivery_status() == "dry_run":
            print(f"{log} schedule {schedule_id!r} EMAIL_DRY_RUN active, not marking period "
                  f"sent (no email actually sent to {len(sent_to)} recipient(s))")
        elif sent_to and len(sent_to) == len(recipients):
            with get_db() as db:
                db.execute(
                    "INSERT OR IGNORE INTO report_schedule_sends "
                    "(id, tenant_id, schedule_id, period_start, period_end, record_id, sent_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), tenant_id, schedule_id,
                     period_start, period_end, record_id, now_utc.isoformat()),
                )
            print(f"{log} schedule {schedule_id!r} sent to {len(sent_to)} recipient(s)")
        elif sent_to:
            print(f"{log} schedule {schedule_id!r} sent to {len(sent_to)}/{len(recipients)} "
                  f"recipient(s) — period NOT marked sent, will retry remaining next tick")


def check_report_schedules() -> None:
    """PAT-370: daily email send loop. Iterates all tenants, checks their Go-service
    report schedules, and sends XLSX download links to configured recipients.

    Called once at startup and then every day at 07:00 UTC from scheduler_loop().
    Idempotent: the report_schedule_sends table prevents double-sends.
    """
    today = datetime.now(timezone.utc).date()
    print(f"[report-sched] running for {today}")
    with get_db() as db:
        tenants = db.execute("SELECT company, tenant_id FROM clients").fetchall()
    for row in tenants:
        try:
            _check_tenant_report_schedules(row["tenant_id"], row["company"], today)
        except Exception as exc:
            print(f"[report-sched] unhandled error for tenant {row['tenant_id']}: {exc}")
    print("[report-sched] done")


def check_trial_expiry_emails() -> None:
    """PAT-670: daily upgrade email loop. Calls the platform trial endpoint and sends
    an upgrade email to each trial tenant expiring within 2 days whose upgrade email
    has not yet been sent.

    Called once at startup and then every day at 08:00 UTC from scheduler_loop().
    Idempotent: the platform marks upgrade_email_sent_at on success via trial-notify,
    AND the local trial_expiry_notifications table records the send independently
    (PAT-817) — the local record is written right after a successful send and does
    not depend on trial-notify also succeeding, so a downstream API hiccup can't
    cause a duplicate customer-facing email tomorrow.
    Logs expired trials for operational visibility (ingestion already blocked by 402).
    """
    log = "[trial-expiry]"
    _MILESTONE = "expires_2d"
    today = datetime.now(timezone.utc).date()
    print(f"{log} running for {today}")
    try:
        r = http.get(
            f"{PATCHED_API_INTERNAL}/admin/tenants/trials",
            params={"state": "expiring_soon"},
            timeout=10,
            verify=_VERIFY_INTERNAL,
        )
        if r.status_code != 200:
            print(f"{log} platform returned {r.status_code} — skipping")
            return
        trials = r.json().get("trials", [])
    except Exception as exc:
        print(f"{log} failed to fetch trials: {exc}")
        return

    for t in trials:
        tid = t.get("tenant_id")
        name = t.get("name", tid)

        if not tid:
            # Guard for malformed platform data: tenant_id is a NOT NULL primary-key
            # column on trial_expiry_notifications (PAT-817) — without this guard a
            # missing tid would raise on the local-ledger INSERT below and abort the
            # whole loop (silently skipping every remaining trial in the batch).
            print(f"{log} trial entry with no tenant_id — skipping: {t!r}")
            continue

        # Log expired trials for operational visibility (ingestion already blocked by 402).
        # The ?state=expiring_soon filter excludes expired trials server-side, but guard
        # anyway in case the contract changes or no filter is used.
        if t.get("state") == "expired":
            print(f"{log} tenant {name!r} ({tid}) trial has expired")
            continue

        # Only email trials that have not yet been notified (duplicate prevention).
        # Two independent signals are checked: the platform's flag (set via the
        # trial-notify POST below) AND the local ledger (PAT-817) — the local one
        # is the source of truth for "did we actually send", since a trial-notify
        # POST failure can't roll back an email already sent.
        if t.get("upgrade_email_sent_at") is not None:
            print(f"{log} tenant {name!r} ({tid}) upgrade email already sent — skipping")
            continue

        with get_db() as db:
            already_local = db.execute(
                "SELECT 1 FROM trial_expiry_notifications WHERE tenant_id=? AND milestone=?",
                (tid, _MILESTONE),
            ).fetchone()
        if already_local:
            print(f"{log} tenant {name!r} ({tid}) already notified locally — skipping")
            continue

        to_email = t.get("trial_email")
        if not to_email:
            print(f"{log} tenant {name!r} ({tid}) has no trial_email — skipping")
            continue

        expires_at_raw = t.get("trial_expires_at", "")
        try:
            expires_dt = datetime.fromisoformat(expires_at_raw.replace("Z", "+00:00"))
            expiry_str = expires_dt.strftime("%-d %B %Y")
        except Exception:
            expiry_str = expires_at_raw

        device_count = t.get("device_count", 0)
        cve_count = t.get("failing_eval_count", 0)
        first_name = name.split()[0] if name else "there"
        device_word = "device" if device_count == 1 else "devices"
        cve_word = "CVE finding" if cve_count == 1 else "CVE findings"

        subject = "Your Patched trial expires in 2 days"
        html = (
            f"<p>Hi {first_name},</p>"
            f"<p>Your Patched.im trial for <strong>{name}</strong> expires on "
            f"<strong>{expiry_str}</strong>. To keep your estate protected, please "
            f"upgrade before then to avoid any interruption to your service.</p>"
            f"<p>Your estate summary:</p>"
            f"<ul>"
            f"<li>{device_count} {device_word} enrolled</li>"
            f"<li>{cve_count} {cve_word} detected</li>"
            f"</ul>"
            f"<p>Upgrade your plan at "
            f"<a href='https://patched.im/pricing'>patched.im/pricing</a> "
            f"- it only takes a couple of minutes.</p>"
            f"<p>If you have any questions, just reply to this email.</p>"
            f"<p>Andy @ Patched.im</p>"
        )
        text = (
            f"Hi {first_name},\n\n"
            f"Your Patched.im trial for {name} expires on {expiry_str}. "
            f"To keep your estate protected, please upgrade before then to avoid "
            f"any interruption to your service.\n\n"
            f"Your estate summary:\n"
            f"  - {device_count} {device_word} enrolled\n"
            f"  - {cve_count} {cve_word} detected\n\n"
            f"Upgrade your plan at https://patched.im/pricing "
            f"- it only takes a couple of minutes.\n\n"
            f"If you have any questions, just reply to this email.\n\n"
            f"Andy @ Patched.im"
        )

        ok = _send_email(to_email, subject, html, text)
        if not ok:
            print(f"{log} email to {to_email!r} failed — not marking sent")
            continue
        if email_delivery_status() == "dry_run":
            # PAT-1010: _send_email() returns True under EMAIL_DRY_RUN, but the
            # ledger insert + trial-notify POST below tell this dashboard's own
            # idempotency table AND the platform API that the customer was
            # notified. Under dry-run that's false in both places: the local
            # ledger would permanently skip this tenant/milestone, and the
            # platform's own reminder logic would believe it already fired.
            # Skip both so a real send (once dry-run is off) still happens.
            print(f"{log} EMAIL_DRY_RUN active, not marking {to_email!r} notified "
                  f"or advancing trial-notify for tenant {tid} (no email actually sent)")
            continue

        # Record the send locally (PAT-817) immediately after a successful send,
        # independent of whether the trial-notify POST below succeeds — this is
        # the guard against duplicate sends if that POST fails/throws.
        with get_db() as db:
            db.execute(
                "INSERT OR IGNORE INTO trial_expiry_notifications (tenant_id, milestone, sent_at) "
                "VALUES (?, ?, ?)",
                (tid, _MILESTONE, datetime.now(timezone.utc).isoformat()),
            )

        # Mark the trial as notified via the platform API
        try:
            nr = http.post(
                f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tid)}/trial-notify",
                timeout=10,
                verify=_VERIFY_INTERNAL,
            )
            if nr.status_code != 200:
                print(f"{log} trial-notify for {tid} returned {nr.status_code}")
            else:
                print(
                    f"{log} upgrade email sent to {to_email!r} and trial marked "
                    f"notified for {name!r}"
                )
        except Exception as exc:
            print(f"{log} trial-notify POST failed for {tid}: {exc}")

    print(f"{log} done")


# ── PAT-1635: shared Slack alert-block builder ──────────────────────────────
#
# All five Slack senders in this file (_send_check_status_alert,
# _run_automation_alerts_tick, _run_automation_digest_tick, _send_health_alert,
# _send_portal_auth_alert) used to each build their own Block Kit payload
# before handing it to _post_slack_blocks_confirmed below. That let them
# drift independently: a raw datetime.timedelta repr could reach a channel
# unrounded, a long string could get truncated mid-word, and the emoji/
# severity shown was decided ad hoc per call site rather than from one
# shared vocabulary. _build_alert_blocks is now the one place that turns
# (severity, title, detail, ...) into an actual blocks list; every sender
# composes its own content and calls this instead of hand-rolling
# {"type": "header", ...} blocks itself.
#
# Severity -> visual treatment. Slack's Block Kit "header"/"section" blocks
# (unlike the legacy "attachments" shape) carry no colour of their own, so
# the only "colour" available here is the leading emoji -- that is what
# "key color/emoji off severity" means for this payload shape.
#
#   ad hoc state word (as used elsewhere in this file)   severity   icon
#   -------------------------------------------------------------------------
#   check_statuses "degraded" (entering)                 critical   :red_circle:
#   automation run "failed"                               critical   :red_circle:
#   portal_auth AUD "broken" (drifted)                    critical   :red_circle:
#   automation "lagging" (stale, not failed)               warning    :warning:
#   check_statuses "unconfigured"                          warning    :warning:
#   health bucket transition into "at_risk"                warning    :warning:
#
# Only "critical"/"warning" are real severities -- they answer "how bad is
# the thing that IS happening". Whether something is firing or has resolved
# is a separate axis (`resolved=True`), which always renders as
# :white_check_mark: regardless of the severity passed in: a recovery
# message communicates "back to normal", not the severity of the outage
# that just ended, so treating "recovered" as a third severity tier would
# conflate two different questions. "recovered", in the ticket's own ad
# hoc-word list, resolves to `resolved=True` on a "warning"-severity call
# (degraded -> ok is not as urgent to re-read as an active critical failure,
# but still worth a visible checkmark); portal_auth's recovery uses the same
# shape.
_ALERT_SEVERITY_ICONS = {"critical": ":red_circle:", "warning": ":warning:"}


def _format_alert_value(value) -> str:
    """Render one Slack field value. A bare datetime.timedelta's default
    repr (e.g. '8:35:16.811440') must never reach a rendered message --
    round to whole minutes/hours via the same helper the automation ticks
    already use for duration text (_fmt_duration_hours), never seconds or
    microseconds."""
    if isinstance(value, timedelta):
        total_minutes = max(0, int(round(value.total_seconds() / 60)))
        if total_minutes < 60:
            return f"{total_minutes}m"
        return _fmt_duration_hours(total_minutes / 60)
    return str(value)


def _truncate_alert_text(text: str, limit: int = 500) -> str:
    """Cap Slack section text at `limit` chars on a word boundary, never
    mid-token -- a plain text[:limit] slice can cut a word in half, which is
    exactly the failure mode this ticket (PAT-1635) exists to close."""
    if len(text) <= limit:
        return text
    truncated = text[:limit]
    cut = truncated.rfind(" ")
    if cut > 0:
        truncated = truncated[:cut]
    return truncated.rstrip() + "…"


def _build_alert_blocks(
    severity: str,
    title: str,
    detail: str = "",
    *,
    fields: list | None = None,
    extra_lines: list | None = None,
    links: list | None = None,
    resolved: bool = False,
) -> list:
    """Build one Slack Block Kit blocks list, shared by all five alert
    senders in this file (PAT-1635). `fields` is a list of (label, value)
    pairs; a value may be a datetime.timedelta -- formatted via
    _format_alert_value, never a raw repr. `detail` is truncated on a word
    boundary via _truncate_alert_text if it runs long. `links` renders as
    one section, "<url|label>" entries joined with " · ", matching the
    multi-link automation-failure block that existed before this ticket.
    `extra_lines` are additional mrkdwn section blocks appended verbatim
    (already-composed text such as the digest's per-check summary, which
    manages its own line-level truncation via _dedupe_check_lines). See the
    severity/icon table above this function for what maps to what and why.
    """
    icon = ":white_check_mark:" if resolved else _ALERT_SEVERITY_ICONS.get(severity, ":warning:")
    blocks = [{"type": "header", "text": {"type": "plain_text", "text": f"{icon} {title}"}}]
    if fields:
        blocks.append({"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*{label}*\n{_format_alert_value(value)}"}
            for label, value in fields
        ]})
    if detail:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": _truncate_alert_text(detail)}})
    for line in extra_lines or []:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": line}})
    if links:
        link_text = " · ".join(f"<{url}|{label}>" for url, label in links)
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": link_text}})
    return blocks


def _dedupe_check_lines(checks: list, limit: int = 500) -> list:
    """Collapse check_statuses rows that report a byte-identical (state,
    reason) body into one Slack line (PAT-1635). maintenance_prod01,
    tick_maintenance_prod01_fast and tick_maintenance_drift_check all wrap
    the same underlying maintenance-facts read and emit identical reason
    text whenever it degrades -- the automation digest used to print that
    same body three times in a row for a single incident."""
    order: list = []
    names_by_body: dict = {}
    for check in checks:
        key = (check["state"], check["reason"])
        if key not in names_by_body:
            names_by_body[key] = []
            order.append(key)
        names_by_body[key].append(check["name"])
    lines = []
    for key in order:
        state, reason = key
        primary, *others = names_by_body[key]
        suffix = (
            f" (also reported by {len(others)} other check{'s' if len(others) != 1 else ''})"
            if others else ""
        )
        lines.append(f"• `{primary}` ({state}): {_truncate_alert_text(reason, limit)}{suffix}")
    return lines


def _post_slack_blocks_confirmed(blocks: list, log_prefix: str, timeout: int = 10) -> bool:
    """PAT-1011: shared Slack incoming-webhook send plus delivery confirmation.

    Extracted after four call sites (automation failure/staleness alerts,
    the daily automation digest, the health-alert Slack fallback) each
    treated a bare HTTP 200 as proof the message reached Slack. A
    syntactically valid but wrong webhook URL (a rotated Slack app, a
    copy-paste error, a misrouted proxy) can be answered with a 200 by
    something else entirely, so 200 alone is not proof of delivery. Slack's
    own contract for a successfully delivered incoming webhook is HTTP 200
    with a plain-text body of exactly "ok"
    (https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/);
    require both. This is the same rule PAT-988/_send_portal_auth_alert
    already applied to a single call site; with five sites now needing it,
    a shared helper replaces five independent (and, until this ticket,
    inconsistent) copies of the same contract.

    Deliberately does not log resp.text anywhere (untrusted response body,
    a log-injection risk, the same surface removed from the portal-auth
    path under PAT-988); only the status code is logged on failure.

    Callers MUST gate any de-duplication / "already sent" state write on
    this function's return value, not on the POST merely being issued.
    A False return means Slack did not confirm delivery and the caller
    should treat the alert as not sent (safe to retry next tick).
    """
    if not SLACK_WEBHOOK_URL:
        print(f"[{log_prefix}] SLACK_WEBHOOK_URL not set, alert not sent")
        return False
    try:
        resp = http.post(SLACK_WEBHOOK_URL, json={"blocks": blocks}, timeout=timeout)
    except Exception as e:
        # Deliberately log only the exception type, not str(e). A Slack
        # incoming-webhook URL's path segments ARE the credential (there is
        # no separate secret), and requests' connection/TLS exceptions often
        # embed the full request URL in their string form -- logging str(e)
        # here could put the live webhook secret into application logs.
        print(f"[{log_prefix}] Slack POST failed: {type(e).__name__}")
        return False
    if resp.status_code != 200 or resp.text.strip() != "ok":
        print(f"[{log_prefix}] Slack webhook did not confirm delivery (status {resp.status_code})")
        return False
    return True


def _run_automation_alerts_tick(now: datetime) -> str | None:
    """PAT-643: post a Slack alert for each automation whose most recent run failed,
    once per unique run_id (idempotent via automation_alerts_sent table).

    Additive: also detects STALENESS — a job that has simply stopped running
    (last_status stuck at "success" forever, or never run at all) — which the
    failure check above cannot see since there is no new failed run to notice.
    Staleness alerts are deduped once per (job_name, UTC calendar day) via
    automation_stale_alerts_sent, and are visually distinct (":warning:" +
    "lagging", vs ":red_circle:" + "failure") so the two problems are never
    confused in the Slack channel.

    Records its availability before preserving the existing alert behaviour.

    PAT-1018: since PAT-1011 both the failure and staleness sections below
    already gate their de-duplication writes on _post_slack_blocks_confirmed's
    return value, so a send that Slack didn't confirm correctly stays
    retryable. But nothing told the caller (_run_tick, via scheduler_loop)
    that a send failed here, so tick_automation_alerts read ok even while
    every alert this tick tried to post went nowhere. Returns a reason
    naming how many sends across both sections did not confirm; a tick with
    nothing to send (or SLACK_WEBHOOK_URL unset) is not degraded.

    PAT-1018 also fixed a second, earlier problem in the same tick: the
    automation_alerts check used to be written "ok" immediately after the
    SLACK_WEBHOOK_URL check, before the /admin/automations fetch even ran.
    A failed, non-200, or unparseable fetch meant no job was ever inspected
    and no alert could have been sent, yet automation_alerts already said
    ok and the tick itself returned None (also read as ok) -- the exact
    "ran but did nothing, reported healthy" shape this ticket exists to
    close. automation_alerts is now written once, after the fetch and both
    send sections, from what this tick actually managed to do -- the same
    "write once at the end" move PAT-1017 made for health_alert_delivery.
    A fetch failure is also distinguished by cause (request exception,
    non-200/empty body, or a body that doesn't parse as JSON), matching
    _run_health_alerts_tick's tenants-overview handling, so an operator
    reading the reason knows which of the three happened.
    """
    if not SLACK_WEBHOOK_URL:
        # PAT-1171: alert_on_transition=False -- this check's own tick
        # already sends dedicated, richer Slack alerts per failing/stale
        # job (automation_alerts_sent/automation_stale_alerts_sent below);
        # a generic alert on top would duplicate that, not add coverage.
        _record_check_status(
            "automation_alerts",
            "unconfigured",
            "SLACK_WEBHOOK_URL not set",
            now,
            alert_on_transition=False,
        )
        return None

    jobs = []
    automations_fetch_error = ""
    try:
        r = http.get(f"{PATCHED_API_INTERNAL}/admin/automations", timeout=10, verify=_VERIFY_INTERNAL)
    except Exception as e:
        automations_fetch_error = f"automations request failed: {e}"
        print(f"[automation-alerts] {automations_fetch_error}")
    else:
        if r.status_code == 200 and r.content:
            try:
                jobs = r.json().get("jobs", [])
            except Exception as e:
                automations_fetch_error = f"automations response was not valid JSON: {e}"
                print(f"[automation-alerts] {automations_fetch_error}")
        else:
            automations_fetch_error = f"automations request returned HTTP {r.status_code}"
            print(f"[automation-alerts] {automations_fetch_error}")

    # A failed, non-200, or malformed fetch means "did any job need an
    # alert" is unknown, not "nothing needed sending" -- that is not ok,
    # and it is written here (not skipped) so this tick's state doesn't
    # read as the previous tick's stale-but-fine result.
    if automations_fetch_error:
        _record_check_status(
            "automation_alerts", "degraded", automations_fetch_error, now,
            alert_on_transition=False,
        )
        return automations_fetch_error

    unconfirmed_sends = 0
    for job in jobs:
        if job.get("job_name") in _QUARANTINED_AUTOMATIONS:
            continue
        runs = job.get("recent_runs") or []
        if not runs:
            continue
        latest = runs[0]
        if latest.get("status") != "failed":
            continue
        run_id = latest.get("id")
        if run_id is None:
            continue

        with get_db() as db:
            exists = db.execute(
                "SELECT 1 FROM automation_alerts_sent WHERE job_name=? AND run_id=?",
                (job["job_name"], run_id),
            ).fetchone()
            if exists:
                continue

        started = latest.get("started_at", "")
        dur_s = latest.get("duration_s")
        dur = f"{dur_s:.0f}s" if dur_s is not None else "not recorded"
        output = latest.get("output") or ""
        error = latest.get("error_msg") or ""
        run_link = output if output.startswith("https://") else ""

        links = [(_AUTOMATIONS_CONSOLE_URL, "View in Dashboard")]
        if run_link:
            links.append((run_link, "GitHub Actions run"))

        blocks = _build_alert_blocks(
            "critical",
            f"Automation failure: {job['job_name']}",
            f"*Error*\n```{error}```" if error else "",
            fields=[
                ("Job", f"`{job['job_name']}`"),
                ("Schedule", job.get("schedule") or "not scheduled"),
                ("Started", started or "unknown"),
                ("Duration", dur),
            ],
            links=links,
        )

        if _post_slack_blocks_confirmed(blocks, "automation-alerts"):
            with get_db() as db:
                db.execute(
                    "INSERT OR IGNORE INTO automation_alerts_sent (job_name, run_id, alerted_at) VALUES (?, ?, ?)",
                    (job["job_name"], run_id, now.isoformat()),
                )
            print(f"[automation-alerts] alerted on {job['job_name']} run {run_id}")
        else:
            unconfirmed_sends += 1

    # ── Staleness detection (additive — does not touch the failure logic above) ──
    # A job whose last run FAILED is caught above. A job that has simply STOPPED
    # RUNNING is not: last_status stays whatever it last was (often "success")
    # forever, so it looks identical to a healthy job unless something checks
    # how long ago it actually last ran. That is exactly this failure mode.
    today = now.strftime("%Y-%m-%d")
    for job in jobs:
        job_name = job.get("job_name")
        if not job_name or job_name in _QUARANTINED_AUTOMATIONS:
            continue

        last_run_raw = job.get("last_run")
        threshold_h = (
            _automation_expected_interval_hours(job_name, job.get("schedule", ""))
            * _AUTOMATION_STALE_MULTIPLIER
        )

        age_h = None
        if last_run_raw:
            try:
                last_run_dt = datetime.fromisoformat(last_run_raw.replace("Z", "+00:00"))
                age_h = (now - last_run_dt).total_seconds() / 3600
            except Exception:
                # Unparsable timestamp — skip rather than risk a false alarm.
                continue

        # No runs at all (age_h is None) is stale by definition — a job
        # registered with an empty recent_runs / null last_run has never once
        # proven it works.
        is_stale = age_h is None or age_h > threshold_h
        if not is_stale:
            continue

        with get_db() as db:
            exists = db.execute(
                "SELECT 1 FROM automation_stale_alerts_sent WHERE job_name=? AND alert_date=?",
                (job_name, today),
            ).fetchone()
            if exists:
                continue

        expected_h = threshold_h / _AUTOMATION_STALE_MULTIPLIER
        if age_h is None:
            last_run_text = "never"
            age_value = "no runs recorded"
        else:
            last_run_text = last_run_raw
            age_value = timedelta(hours=age_h)

        stale_blocks = _build_alert_blocks(
            "warning",
            f"Automation lagging: {job_name}",
            "This automation has not been seen running recently and may have "
            "silently stopped. This is *not* a run failure: the job simply "
            "has not run at all.",
            fields=[
                ("Job", f"`{job_name}`"),
                ("Schedule", job.get("schedule") or "not scheduled"),
                ("Last run", last_run_text),
                ("Time since", age_value),
                ("Expected every", f"~{_fmt_duration_hours(expected_h)}"),
            ],
            links=[(_AUTOMATIONS_CONSOLE_URL, "View in Dashboard")],
        )

        if _post_slack_blocks_confirmed(stale_blocks, "automation-alerts"):
            with get_db() as db:
                db.execute(
                    "INSERT OR IGNORE INTO automation_stale_alerts_sent (job_name, alert_date, alerted_at) "
                    "VALUES (?, ?, ?)",
                    (job_name, today, now.isoformat()),
                )
            print(f"[automation-alerts] stale alert on {job_name} (last run {last_run_text})")
        else:
            unconfirmed_sends += 1

    # Written once, after both the failure and staleness sections have had
    # their chance to send, so automation_alerts reflects what this tick
    # actually did rather than the "ok" it used to claim before any of this
    # ran. The two checks agreeing (this and tick_automation_alerts) is the
    # property PAT-1018 exists to establish.
    if unconfirmed_sends:
        reason = f"{unconfirmed_sends} Slack alert send(s) did not confirm delivery"
        _record_check_status(
            "automation_alerts", "degraded", reason, now, alert_on_transition=False,
        )
        return reason
    _record_check_status("automation_alerts", "ok", "", now, alert_on_transition=False)
    return None


def _run_rbac_operators_check_tick(now: datetime) -> str | None:
    """Record missing session-owner configuration without granting privileges.

    An empty operator list leaves every session user a consultant. Keep the
    named check and scheduler tick degraded together so this configuration gap
    remains visible; Bearer administration retains its separate authentication.
    Evaluating this here keeps the request-time role helper side-effect free.
    """
    if not DASHBOARD_OPERATORS:
        reason = (
            "DASHBOARD_OPERATORS unset or empty — no session owners configured; "
            "authenticated session users resolve to consultant"
        )
        _record_check_status("rbac_operators", "degraded", reason, now)
        return reason
    # Count only — never record the addresses themselves.
    _record_check_status(
        "rbac_operators", "ok",
        f"{len(DASHBOARD_OPERATORS)} operators configured", now,
    )
    return None


def _run_email_delivery_check_tick(now: datetime) -> str | None:
    """PAT-1010: record whether outbound email delivery is actually live.

    EMAIL_DRY_RUN=1 makes _send_email() log-and-return-True for every
    ordinary feature-email caller (cert/stale digests, trial-expiry nudges,
    Calendly confirmations, scheduled reports, etc.), which is correct dry-run
    behaviour for them but invisible estate-wide: nothing showed outbound
    email was suppressed short of reading the env file on the box.

    Delegates to email_delivery_check() (shared.py), which goes beyond "is a
    provider configured" and actually validates the Graph credential (a real
    but cached OAuth token request) when Graph is the active path, so an
    expired/wrong-scope credential shows up as degraded instead of a false
    "ok" the way a config-presence-only check would report it.

    PAT-1045: this recorded email_delivery but always returned None, so
    tick_email_delivery_check read ok on exactly the ticks where
    email_delivery read degraded. Now returns the same reason only when
    state == "degraded" -- unconfigured is unchanged (a standing
    configuration gap reported by email_delivery itself, not a tick
    failure), matching the policy already applied elsewhere in this file.
    """
    state, reason = email_delivery_check()
    _record_check_status("email_delivery", state, reason, now)
    if state == "degraded":
        return reason
    return None


def _run_automation_digest_tick(now: datetime) -> str | None:
    """Daily positive-confirmation Slack digest: total automations, how many
    are green, and any currently failing or stale. Converts silence into an
    affirmative signal ("we checked and it's fine") instead of leaving it
    ambiguous whether "no alerts" means "all healthy" or "alerting is broken".

    Fires at most once per UTC calendar day (automation_digest_sent), at
    09:00 UTC — chosen to land after the known daily jobs' 06:00 UTC schedule
    (see _AUTOMATION_EXPECTED_INTERVAL_HOURS) so the digest reflects that
    morning's run rather than racing it. Silently skips if SLACK_WEBHOOK_URL
    is not configured, or if a digest for today has already been sent.

    PAT-1018: since PAT-1011 the digest send below is already gated on
    _post_slack_blocks_confirmed's return value, so a send Slack didn't
    confirm correctly stays retryable tomorrow's tick. But that failure
    never reached _run_tick, so tick_automation_digest read ok even when
    the digest never posted. Returns a reason when that happens; a tick
    that has nothing to send today (not due, already sent, unconfigured) is
    not degraded. A fetch failure is distinguished by cause (request
    exception, non-200/empty body, or an unparseable body), matching
    _run_health_alerts_tick's tenants-overview handling.

    The single 09:00 UTC window means a fetch failure at 09:00 is not
    retried until tomorrow's 09:00 -- the scheduler only visits this branch
    once an hour and the `now.hour != 9` gate shuts it again immediately
    after. Widening the gate (e.g. to "09:00 or later, until sent today")
    was considered so a later hour could retry, but test_digest_skips_
    outside_gate_hour (tests/test_automation_staleness.py) encodes a
    deliberate existing invariant -- the digest is a fixed-time morning
    signal, not "whenever it's due" -- and a consumer may reasonably expect
    it near 09:00, not at an arbitrary hour hours later. Changing that is a
    product decision this ticket did not ask for, so the gate is left as
    `!= 9`; a fetch failure still costs the rest of the day. Flagged for
    Andy rather than decided here.
    """
    if not SLACK_WEBHOOK_URL:
        # PAT-1215: mirrors _run_automation_alerts_tick's own unconfigured
        # recording above -- a missing webhook must read as "we don't know"
        # (unconfigured), not silently look identical to a healthy tick.
        _record_check_status(
            "automation_digest",
            "unconfigured",
            "SLACK_WEBHOOK_URL not set",
            now,
            alert_on_transition=False,
        )
        return None
    if now.hour != 9:
        return None

    today = now.strftime("%Y-%m-%d")
    with get_db() as db:
        already_sent = db.execute(
            "SELECT 1 FROM automation_digest_sent WHERE digest_date=?", (today,)
        ).fetchone()
    if already_sent:
        return None

    jobs = []
    automations_fetch_error = ""
    try:
        r = http.get(f"{PATCHED_API_INTERNAL}/admin/automations", timeout=10, verify=_VERIFY_INTERNAL)
    except Exception as e:
        automations_fetch_error = f"automations request failed: {e}"
        print(f"[automation-digest] {automations_fetch_error}")
    else:
        if r.status_code == 200 and r.content:
            try:
                jobs = r.json().get("jobs", [])
            except Exception as e:
                automations_fetch_error = f"automations response was not valid JSON: {e}"
                print(f"[automation-digest] {automations_fetch_error}")
        else:
            automations_fetch_error = f"automations request returned HTTP {r.status_code}"
            print(f"[automation-digest] {automations_fetch_error}")

    if automations_fetch_error:
        return automations_fetch_error

    failing, stale, healthy = [], [], []
    scheduled_jobs = [
        job for job in jobs
        if job.get("job_name") and job["job_name"] not in _QUARANTINED_AUTOMATIONS
    ]
    for job in scheduled_jobs:
        job_name = job.get("job_name")
        if not job_name:
            continue
        runs = job.get("recent_runs") or []
        latest_status = runs[0].get("status") if runs else job.get("last_status")

        if latest_status == "failed":
            failing.append(job_name)
            continue

        last_run_raw = job.get("last_run")
        threshold_h = (
            _automation_expected_interval_hours(job_name, job.get("schedule", ""))
            * _AUTOMATION_STALE_MULTIPLIER
        )
        age_h = None
        if last_run_raw:
            try:
                age_h = (now - datetime.fromisoformat(last_run_raw.replace("Z", "+00:00"))).total_seconds() / 3600
            except Exception:
                age_h = None
        if age_h is None or age_h > threshold_h:
            stale.append(job_name)
        else:
            healthy.append(job_name)

    total = len(scheduled_jobs)
    if total == 0:
        history_count = len(jobs)
        summary_text = (
            "No active automations."
            + (f" Showing {history_count} quarantined/retired historical job(s)." if history_count else "")
        )
    elif not failing and not stale:
        summary_text = f"All {total} automations green. :white_check_mark:"
    else:
        parts = [f"{len(healthy)}/{total} green"]
        if failing:
            parts.append(f"{len(failing)} failing")
        if stale:
            parts.append(f"{len(stale)} lagging")
        summary_text = " · ".join(parts)

    unavailable_checks = _get_check_statuses(("unconfigured", "degraded"))
    extra_lines = []
    if failing:
        extra_lines.append(":red_circle: *Failing:* " + ", ".join(f"`{j}`" for j in failing))
    if stale:
        extra_lines.append(":warning: *Lagging:* " + ", ".join(f"`{j}`" for j in stale))
    if unavailable_checks:
        check_lines = _dedupe_check_lines(unavailable_checks)
        extra_lines.append(":warning: *Checks needing attention:*\n" + "\n".join(check_lines))

    # Severity/resolved for the digest's own header icon: any actual failure
    # is critical, any lagging job or check needing attention is a warning,
    # and a totally clean day is a resolved (checkmark) post -- "we checked
    # and it's fine" per this function's own docstring, not merely silence.
    if failing:
        severity, resolved = "critical", False
    elif stale or unavailable_checks:
        severity, resolved = "warning", False
    else:
        severity, resolved = "warning", total > 0

    blocks = _build_alert_blocks(
        severity,
        "Automation health: daily digest",
        summary_text,
        extra_lines=extra_lines,
        links=[(_AUTOMATIONS_CONSOLE_URL, "View in Dashboard")],
        resolved=resolved,
    )

    if _post_slack_blocks_confirmed(blocks, "automation-digest"):
        with get_db() as db:
            db.execute(
                "INSERT OR IGNORE INTO automation_digest_sent (digest_date, sent_at) VALUES (?, ?)",
                (today, now.isoformat()),
            )
        print(f"[automation-digest] sent digest for {today}: {summary_text}")
        return None
    return "automation digest Slack post did not confirm delivery"


# ── PAT-678: at-risk health transition alert ─────────────────────────────────

def _send_health_alert(tenant_name: str, bucket: str, prev_bucket: str, compliance_pct) -> bool:
    """Send a health-drop alert via Telegram (if configured) or Slack (fallback).
    Returns True on success.
    NOTE: Telegram token (@patchedim2_bot) must be provisioned in TELEGRAM_BOT_TOKEN +
    TELEGRAM_CHAT_ID env vars on prod-01 — not yet configured, so Slack is the live channel.
    """
    score = int(round(float(compliance_pct))) if compliance_pct is not None else "?"
    message = (
        f"⚠️ Health alert: {tenant_name}\n"
        f"Score: {score} (compliance-based heuristic)\n"
        f"Bucket: {prev_bucket} → {bucket}\n"
        f"Action: review tenant in Estate Overview on dashboard.patched.im"
    )

    missing = []
    if not TELEGRAM_BOT_TOKEN:
        missing.append("TELEGRAM_BOT_TOKEN")
    if not TELEGRAM_CHAT_ID:
        missing.append("TELEGRAM_CHAT_ID")
    if not SLACK_WEBHOOK_URL:
        missing.append("SLACK_WEBHOOK_URL")
    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID) and not SLACK_WEBHOOK_URL:
        # PAT-1171: alert_on_transition=False throughout this function and
        # _run_health_alerts_tick below -- this IS the tenant at_risk
        # alert-sending path; a generic second alert about the channel
        # itself would duplicate the tenant alert this same call is trying
        # (and, here, failing) to send.
        _record_check_status(
            "health_alert_delivery",
            "unconfigured",
            "missing " + ", ".join(missing),
            alert_on_transition=False,
        )
        return False

    # Prefer Telegram if configured
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        try:
            r = http.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={"chat_id": TELEGRAM_CHAT_ID, "text": message},
                timeout=10,
            )
            # PAT-1017: the Telegram Bot API answers HTTP 200 with a JSON
            # body carrying "ok": false for real failures (bad chat id, bot
            # removed from the chat, rate limited), so 200 alone is not
            # proof of delivery -- same rule PAT-1011 applied to the Slack
            # webhook contract above. A body that fails to parse as JSON is
            # a failure too, not a success.
            confirmed = False
            if r.status_code == 200:
                try:
                    confirmed = bool(r.json().get("ok"))
                except Exception:
                    confirmed = False
            if confirmed:
                _record_check_status("health_alert_delivery", "ok", alert_on_transition=False)
                return True
            # Deliberately do not log r.text/the parsed body (untrusted
            # response content, a log-injection risk) -- only the status code.
            print(f"[health-alerts] Telegram did not confirm delivery (status {r.status_code})")
        except Exception as e:
            # Deliberately log only the exception type, not str(e).
            # TELEGRAM_BOT_TOKEN is embedded in the request URL path, so it
            # IS the credential, exactly like a Slack webhook URL, and
            # requests' connection/TLS exceptions often embed the full
            # request URL in their string form -- logging str(e) here could
            # put the live bot token into application logs.
            print(f"[health-alerts] Telegram POST failed: {type(e).__name__}")

    # Fallback: Slack (same channel as PAT-643 automation alerts)
    if SLACK_WEBHOOK_URL:
        # PAT-1036: the #fleet URL fragment, the /api/admin/fleet-* route
        # paths, the last_ingest_across_fleet response key and the
        # [fleet-*] log prefixes are all deliberately NOT renamed. They are
        # identifiers, not copy: the anchor is bookmarkable and is this
        # link's own target, the routes and the response key are consumed
        # by templates/console.html, and the wire format is PAT-1058's
        # decision, not this ticket's. Only the human-readable label
        # changed. Not a miss.
        blocks = _build_alert_blocks(
            "warning",
            f"Health alert: {tenant_name}",
            fields=[
                ("Score", score),
                ("Bucket", f"{prev_bucket} → {bucket}"),
            ],
            links=[("https://dashboard.patched.im/console#fleet", "View Estate Overview")],
        )
        if _post_slack_blocks_confirmed(blocks, "health-alerts"):
            _record_check_status("health_alert_delivery", "ok", alert_on_transition=False)
            return True

    _record_check_status(
        "health_alert_delivery",
        "degraded",
        "configured alert delivery channels failed",
        alert_on_transition=False,
    )
    return False


def _run_health_alerts_tick(now: datetime) -> str | None:
    """PAT-678: check each tenant's health bucket and fire an alert on transition INTO at_risk.
    Idempotent via health_alerts_sent table, one alert per tenant per at_risk episode.
    Records itself as unconfigured if neither Telegram nor Slack is configured.

    PAT-1011: "one alert per episode" must not mean "one alert ATTEMPT per
    episode" -- health_alerts_sent.alert_delivered tracks whether that
    attempt actually landed, separately from which bucket the tenant is in.
    A tenant that stays at_risk while its last alert failed to deliver is
    retried on the next tick rather than going permanently silent.

    PAT-1017: health_alert_delivery must reflect what this tick actually
    delivered, not just that TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID/
    SLACK_WEBHOOK_URL are set. Recording "ok" up front, before any send is
    attempted, is the same "reports healthy while delivering nothing" shape
    PAT-912/PAT-988/PAT-1010/PAT-1011 already fixed elsewhere -- an operator
    would see health_alert_delivery: ok while every send this tick failed.
    So when the channel is configured, the final state is written once
    below, after the tenant loop, from what was actually attempted: ok if
    the tenants overview was fetched successfully and nothing needed
    sending or everything sent confirmed, degraded if anything attempted
    this tick did not confirm. A tick that attempts no sends because no
    tenant needed one is not a failure and stays ok.

    A tenants-overview fetch that fails, returns non-200, or can't be
    parsed is a THIRD outcome, distinct from "nothing needed sending":
    whether any tenant needed an alert this tick is simply unknown, and
    that is not healthy. It is recorded degraded with a reason naming the
    cause, not silently folded into "no sends attempted" (which would read
    as ok) and not skipped (which would leave the previous tick's state
    standing and read as stale-but-fine).

    PAT-1018: health_alert_delivery being written correctly (PAT-1017,
    above) was not enough -- that write never reached _run_tick, so
    tick_health_alerts kept reporting ok on exactly the ticks where
    health_alert_delivery had just been recorded degraded. The two checks
    disagreed about the same tick. This function now returns the same
    reason it records against health_alert_delivery in the degraded cases
    below (tenants-overview fetch failure, or an unconfirmed send), so the
    two checks agree. The unconfigured case is unchanged -- an unset
    channel isn't a tick failure, it's a standing configuration gap
    reported by health_alert_delivery itself.
    """
    missing = []
    if not TELEGRAM_BOT_TOKEN:
        missing.append("TELEGRAM_BOT_TOKEN")
    if not TELEGRAM_CHAT_ID:
        missing.append("TELEGRAM_CHAT_ID")
    if not SLACK_WEBHOOK_URL:
        missing.append("SLACK_WEBHOOK_URL")
    channel_configured = bool((TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID) or SLACK_WEBHOOK_URL)
    if not channel_configured:
        _record_check_status(
            "health_alert_delivery",
            "unconfigured",
            "missing " + ", ".join(missing),
            now,
            alert_on_transition=False,
        )
        # Preserve the existing partial-configuration behaviour: if either
        # Telegram value is present, the tenant-state evaluation still runs.
        if not TELEGRAM_BOT_TOKEN and not TELEGRAM_CHAT_ID:
            return None
    # else: health_alert_delivery is recorded below, once this tick's actual
    # delivery attempts (if any) are known -- not here, based on
    # configuration presence alone.
    attempted_this_tick = False
    any_failed_this_tick = False
    tenants = []
    tenants_fetch_error = ""
    try:
        r = http.get(f"{PATCHED_API_INTERNAL}/admin/tenants/overview", timeout=15, verify=_VERIFY_INTERNAL)
    except Exception as e:
        tenants_fetch_error = f"tenants overview request failed: {e}"
        print(f"[health-alerts] {tenants_fetch_error}")
    else:
        if r.status_code == 200 and r.content:
            try:
                tenants = r.json().get("tenants") or []
            except Exception as e:
                tenants_fetch_error = f"tenants overview response was not valid JSON: {e}"
                print(f"[health-alerts] {tenants_fetch_error}")
        else:
            tenants_fetch_error = f"tenants overview request returned HTTP {r.status_code}"
            print(f"[health-alerts] {tenants_fetch_error}")
    # A failed, non-200, or malformed tenants-overview fetch leaves `tenants`
    # empty, so the loop below is a no-op -- but that means "whether any
    # tenant needed an alert" is unknown, not "nothing needed sending".
    # tenants_fetch_error carries that distinction through to the final
    # write below rather than letting an empty tenant list read as ok.

    for t in tenants:
        tid = t.get("id")
        if not tid:
            continue
        bucket, _ = _resolve_health_bucket(t)
        with get_db() as db:
            row = db.execute(
                "SELECT bucket, alert_delivered FROM health_alerts_sent WHERE tenant_id=?", (tid,)
            ).fetchone()
            prev_bucket = row["bucket"] if row else None
            # No row yet means no alert obligation has ever failed, so treat
            # a first-seen tenant as "delivered" (nothing owed) rather than
            # forcing a spurious alert.
            prev_alert_delivered = bool(row["alert_delivered"]) if row else True

        # PAT-1011: alert on transition INTO at_risk, same as before, but ALSO
        # retry a still-at_risk tenant whose last alert attempt was never
        # confirmed delivered (e.g. Slack webhook was broken that tick) --
        # same shape as portal_auth_recovery_pending: a still-owed
        # notification is tracked independently of the bucket transition and
        # survives until it actually sends.
        should_alert = bucket == "at_risk" and (prev_bucket != "at_risk" or not prev_alert_delivered)

        if should_alert:
            delivered = _send_health_alert(
                t.get("name", tid), bucket, prev_bucket or "unknown", t.get("compliance_pct")
            )
            print(f"[health-alerts] at_risk transition for {t.get('name')}, alert sent: {delivered}")
            attempted_this_tick = True
            if not delivered:
                any_failed_this_tick = True
        else:
            # Unchanged from the last recorded outcome (nothing attempted
            # this tick), including for tenants who were never at_risk.
            delivered = prev_alert_delivered

        with get_db() as db:
            db.execute(
                "INSERT INTO health_alerts_sent (tenant_id, bucket, alerted_at, alert_delivered) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(tenant_id) DO UPDATE SET bucket=excluded.bucket, "
                "alerted_at=excluded.alerted_at, alert_delivered=excluded.alert_delivered",
                (tid, bucket, now.isoformat(), 1 if delivered else 0),
            )

    # PAT-1017: the authoritative write for this tick. _send_health_alert()
    # also records health_alert_delivery per attempt (existing behaviour,
    # relied on by callers that invoke it directly), but with more than one
    # tenant needing an alert in the same tick, whichever attempt runs last
    # would otherwise silently decide the tick's overall state -- a later
    # success could mask an earlier tenant's failed delivery. Writing once
    # here, from what the whole tick attempted, removes that ordering
    # dependency. Skipped entirely in the partial-configuration branch
    # above (channel_configured False but evaluation still ran) so that
    # case keeps reporting "unconfigured", unchanged from today.
    if channel_configured:
        if tenants_fetch_error:
            # Whether any tenant needed an alert this tick is unknown, not
            # "nothing needed sending" -- that is not ok, and it is written
            # here (not skipped) so this tick's state doesn't read as the
            # previous tick's stale-but-fine result.
            _record_check_status(
                "health_alert_delivery",
                "degraded",
                tenants_fetch_error,
                now,
                alert_on_transition=False,
            )
            return tenants_fetch_error
        elif attempted_this_tick and any_failed_this_tick:
            reason = "a health alert send this tick did not confirm delivery"
            _record_check_status(
                "health_alert_delivery",
                "degraded",
                reason,
                now,
                alert_on_transition=False,
            )
            return reason
        else:
            _record_check_status("health_alert_delivery", "ok", "", now, alert_on_transition=False)
    return None


# ── PAT-435: Calendly follow-up email sequence ─────────────────────────────

_FOLLOWUP_STEPS = [
    (3,  "Following up on your Patched.im booking"),
    (7,  "Checking in — Patched.im"),
]


def _calendly_followup_html(name: str, day: int) -> tuple[str, str]:
    """Return (html, text) for day-N follow-up."""
    first = name.split()[0] if name else "there"
    if day == 3:
        html = (
            f"<p>Hi {first},</p>"
            f"<p>Just a quick note ahead of your Patched.im consultation — "
            f"if you'd like to get a head start, you can run a free CVE scan on your "
            f"Intune estate at <a href='https://patched.im'>patched.im</a>. "
            f"It only takes a couple of minutes and gives us something concrete to "
            f"discuss on the call.</p>"
            f"<p>Looking forward to speaking with you.</p>"
            f"<p>— Andy @ Patched.im</p>"
        )
        text = (
            f"Hi {first},\n\nJust a quick note ahead of your Patched.im consultation. "
            f"If you'd like to get a head start, you can run a free CVE scan at "
            f"https://patched.im.\n\nLooking forward to speaking with you.\n\n— Andy @ Patched.im"
        )
    else:
        html = (
            f"<p>Hi {first},</p>"
            f"<p>Following up on your Patched.im session — I hope you found it useful. "
            f"If you have any questions or would like to explore next steps, just reply "
            f"to this email and I'll get back to you.</p>"
            f"<p>— Andy @ Patched.im</p>"
        )
        text = (
            f"Hi {first},\n\nFollowing up on your Patched.im session — I hope you found "
            f"it useful. If you have any questions or want to explore next steps, just "
            f"reply and I'll get back to you.\n\n— Andy @ Patched.im"
        )
    return html, text


def _check_portal_access_aud() -> tuple[bool, str] | None:
    """PAT-837: compare the live Cloudflare Access AUD for app.patched.im
    against PORTAL_ACCESS_AUD_EXPECTED. Returns (drifted, detail) — drifted
    True means the two disagree (the exact 2026-07-12 incident: every real
    login gets rejected as an invalid-audience token). Returns None if any
    required config is missing, so the caller can no-op cleanly rather than
    ever false-positive on an unconfigured box."""
    required_config = {
        "CLOUDFLARE_API_TOKEN": CLOUDFLARE_API_TOKEN,
        "CLOUDFLARE_ACCOUNT_ID": CLOUDFLARE_ACCOUNT_ID,
        "CLOUDFLARE_ACCESS_APP_ID": CLOUDFLARE_ACCESS_APP_ID,
        "PORTAL_ACCESS_AUD": PORTAL_ACCESS_AUD_EXPECTED,
    }
    # PAT-1171: every _record_check_status("portal_auth", ...) call in this
    # function and in _run_portal_auth_healthcheck_tick below passes
    # alert_on_transition=False -- portal_auth already has its own
    # dedicated Slack alerting (_send_portal_auth_alert, PAT-837/988/1011:
    # 24h re-alert throttle, runbook link, recovery-pending persistence). A
    # second generic alert here would duplicate that, not add coverage.
    missing = [name for name, value in required_config.items() if not value]
    if missing:
        _record_check_status(
            "portal_auth",
            "unconfigured",
            "missing " + ", ".join(missing),
            alert_on_transition=False,
        )
        return None
    try:
        r = http.get(
            f"https://api.cloudflare.com/client/v4/accounts/{CLOUDFLARE_ACCOUNT_ID}"
            f"/access/apps/{CLOUDFLARE_ACCESS_APP_ID}",
            headers={"Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}"},
            timeout=15,
        )
    except Exception as e:
        print(f"[portal-auth-check] Cloudflare API request failed: {e}")
        _record_check_status(
            "portal_auth",
            "degraded",
            f"Cloudflare API request failed: {e}",
            alert_on_transition=False,
        )
        return None
    if r.status_code != 200:
        print(f"[portal-auth-check] Cloudflare API returned {r.status_code}: {r.text[:200]}")
        _record_check_status(
            "portal_auth",
            "degraded",
            f"Cloudflare API returned {r.status_code}",
            alert_on_transition=False,
        )
        return None
    try:
        live_aud = (r.json().get("result") or {}).get("aud", "")
    except Exception as e:
        print(f"[portal-auth-check] Cloudflare API response unparseable: {e}")
        _record_check_status(
            "portal_auth",
            "degraded",
            f"Cloudflare API response unparseable: {e}",
            alert_on_transition=False,
        )
        return None
    if not live_aud:
        print("[portal-auth-check] Cloudflare API returned no aud on the Access app")
        _record_check_status(
            "portal_auth",
            "degraded",
            "Cloudflare API returned no aud on the Access app",
            alert_on_transition=False,
        )
        return None
    if live_aud == PORTAL_ACCESS_AUD_EXPECTED:
        _record_check_status("portal_auth", "ok", alert_on_transition=False)
        return False, ""
    detail = (
        f"Live Cloudflare Access AUD for app.patched.im ({live_aud[:12]}…) does not "
        f"match PORTAL_ACCESS_AUD configured on patched-portal-01/patched-api-01 "
        f"({PORTAL_ACCESS_AUD_EXPECTED[:12]}…). Every real customer login will be "
        f"rejected as an invalid-audience token until this is fixed."
    )
    _record_check_status("portal_auth", "degraded", detail, alert_on_transition=False)
    return True, detail


def _alert_channel_missing_detail(var_name: str) -> str:
    """PAT-988: standard, human-actionable detail text for a monitor whose
    alert-delivery channel env var is unset. Shared so every such guard says
    the same thing (names the variable, states plainly that alerts cannot be
    delivered) instead of each call site inventing its own wording."""
    return f"{var_name} is not set — alerts cannot be delivered"


def _send_portal_auth_alert(subject: str, detail: str, *, severity: str = "critical", resolved: bool = False) -> bool:
    """PAT-837: post to SLACK_WEBHOOK_URL about a portal auth outage/recovery.
    No-ops (returns False) if SLACK_WEBHOOK_URL isn't configured. PAT-988: the
    caller (_run_portal_auth_healthcheck_tick) is responsible for surfacing
    that no-op as a degraded portal_auth check — this function only owns the
    send attempt itself.

    PAT-1010: this alert was originally emailed to OPS_ALERT_EMAIL. Moved to
    Slack (same webhook/channel as the PAT-643 automation alerts) because (a)
    OPS_ALERT_EMAIL was never set on prod-01, and (b) prod-01 also runs with
    EMAIL_DRY_RUN=1, under which _send_email() logs and returns True without
    sending anything — so simply setting OPS_ALERT_EMAIL would have made this
    check believe it could deliver, flip portal_auth back to "ok", and alert
    no one. Slack is already configured and delivering on prod-01, so it
    doesn't share that failure mode.

    PAT-1011: the delivery-confirmation logic (200 status AND body == "ok",
    no response body logged on failure) originated here and has moved into
    the shared _post_slack_blocks_confirmed() helper, now also used by
    _run_automation_alerts_tick/_run_automation_digest_tick/_send_health_alert
    so there is one delivery contract rather than five copies of it.

    PAT-1635: block construction moved into the shared _build_alert_blocks;
    `subject`/`severity`/`resolved` replace the caller-embedded emoji this
    function used to accept as part of `subject` itself."""
    if not SLACK_WEBHOOK_URL:
        print(f"[portal-auth-check] {_alert_channel_missing_detail('SLACK_WEBHOOK_URL')}")
        return False
    blocks = _build_alert_blocks(
        severity, subject, detail,
        extra_lines=["Runbook: docs/RUNBOOK-portal-auth-healthcheck.md in the dashboard repo."],
        resolved=resolved,
    )
    return _post_slack_blocks_confirmed(blocks, "portal-auth-check")


def _run_portal_auth_healthcheck_tick(now: datetime) -> str | None:
    """PAT-837: hourly AUD-drift check for the customer portal's Cloudflare
    Access app. Idempotent via kv keys portal_auth_state/portal_auth_alerted_at
    — alerts once when it breaks, re-alerts at most once per 24h while still
    broken, and sends exactly one recovery Slack post when it clears.

    PAT-988: _check_portal_access_aud() above records portal_auth purely from
    the AUD comparison, with no idea whether an alert could ever be delivered.
    A monitor that is structurally incapable of alerting is not healthy just
    because the thing it watches happens to be fine right now, so once we have
    a real AUD reading we re-check the alert channel and, separately, whether
    every alert this tick actually needed to send made it out — including a
    still-owed recovery notification (kv portal_auth_recovery_pending) — and
    downgrade portal_auth to degraded if not, regardless of whether drift was
    also detected. Every known problem is folded into one detail string
    rather than the last write clobbering the others.

    A recovery send failure must NOT be swallowed: the AUD comparison result
    (drifted/not) is still recorded accurately — silently pinning
    portal_auth_state at "broken" to force a retry would make the *next*
    genuinely new break look like a continuation of this one under the 24h
    re-alert dedup window. Instead, an unsent recovery is tracked in its own
    kv flag (portal_auth_recovery_pending) that persists independently of
    portal_auth_state until a recovery Slack post actually sends, so a
    channel that comes back later still gets a real recovery notification
    rather than the obligation being silently dropped.

    PAT-1045: this function never returned anything, so tick_portal_auth_check
    always recorded ok even on ticks where portal_auth had just been recorded
    degraded — AUD drift, a missing alert channel, or a failed recovery send.
    It now returns the same reason recorded against portal_auth for that run
    so the two agree. _check_portal_access_aud() returns None for two
    different reasons: required config missing (portal_auth recorded
    unconfigured — a standing config gap, not a tick failure, unchanged by
    policy) and a live Cloudflare API error reading the AUD (portal_auth
    recorded degraded). Those must not collapse to the same tick outcome, so
    on a None result we read back what was actually just recorded for
    portal_auth rather than assuming "unconfigured" for every None.
    """
    result = _check_portal_access_aud()
    if result is None:
        portal_auth_status = next(
            (c for c in _get_check_statuses() if c["name"] == "portal_auth"), None
        )
        if portal_auth_status and portal_auth_status["state"] == "degraded":
            return portal_auth_status["reason"]
        return None
    drifted, detail = result

    channel_missing = not SLACK_WEBHOOK_URL
    channel_detail = _alert_channel_missing_detail("SLACK_WEBHOOK_URL") if channel_missing else ""
    recovery_send_failed_detail = ""

    with get_db() as db:
        row = db.execute("SELECT value FROM kv WHERE key='portal_auth_state'").fetchone()
        prev_state = row["value"] if row else "ok"
        last_alerted_row = db.execute(
            "SELECT value FROM kv WHERE key='portal_auth_alerted_at'"
        ).fetchone()
        last_alerted_at = (
            datetime.fromisoformat(last_alerted_row["value"]) if last_alerted_row else None
        )
        recovery_pending = db.execute(
            "SELECT 1 FROM kv WHERE key='portal_auth_recovery_pending'"
        ).fetchone() is not None

        if drifted:
            due = last_alerted_at is None or (now - last_alerted_at) >= timedelta(hours=24)
            if due:
                sent = _send_portal_auth_alert(
                    "Portal auth broken: Cloudflare Access AUD drift on app.patched.im",
                    detail,
                    severity="critical",
                )
                if sent:
                    now_iso = now.isoformat()
                    db.execute(
                        "INSERT INTO kv(key, value, updated_at) VALUES('portal_auth_alerted_at', ?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                        (now_iso, now_iso),
                    )
                    print(f"[portal-auth-check] Slack ALERT sent: {detail}")
            new_state = "broken"
        else:
            # A recovery notification is owed whenever we were previously
            # broken, or an earlier recovery attempt failed to send and is
            # still outstanding.
            if prev_state == "broken" or recovery_pending:
                sent = _send_portal_auth_alert(
                    "Portal auth recovered: app.patched.im AUD matches again",
                    "Cloudflare's live Access AUD for app.patched.im now matches "
                    "PORTAL_ACCESS_AUD on both boxes. Recovered.",
                    severity="warning",
                    resolved=True,
                )
                now_iso = now.isoformat()
                if sent:
                    print("[portal-auth-check] recovery Slack post sent")
                    db.execute("DELETE FROM kv WHERE key='portal_auth_recovery_pending'")
                else:
                    print(
                        "[portal-auth-check] AUD recovered but the recovery "
                        "notification failed to send — will retry next tick"
                    )
                    db.execute(
                        "INSERT INTO kv(key, value, updated_at) VALUES('portal_auth_recovery_pending', '1', ?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                        (now_iso,),
                    )
                    recovery_send_failed_detail = (
                        "the recovery notification for the prior outage has not "
                        "been delivered yet (send failed) — will retry next tick"
                    )
            new_state = "ok"

        if new_state != prev_state:
            now_iso = now.isoformat()
            db.execute(
                "INSERT INTO kv(key, value, updated_at) VALUES('portal_auth_state', ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                (new_state, now_iso),
            )

    if channel_missing or recovery_send_failed_detail:
        facts = []
        if drifted:
            facts.append(detail)
        if channel_missing:
            facts.append(channel_detail)
        if recovery_send_failed_detail:
            facts.append(recovery_send_failed_detail)
        combined_detail = " ALSO: ".join(facts) if len(facts) > 1 else facts[0]
        _record_check_status(
            "portal_auth", "degraded", combined_detail, now, alert_on_transition=False,
        )
        return combined_detail

    if drifted:
        # No channel/recovery problem this tick, so the block above never
        # ran -- but _check_portal_access_aud() already recorded portal_auth
        # degraded for the drift itself (its own "live_aud != expected"
        # branch). Return the same detail so tick_portal_auth_check agrees
        # with what portal_auth is actually holding for this run, instead of
        # reading ok because this function's own _record_check_status call
        # never fired.
        return detail

    return None


def _run_band_drift_check_tick(now: datetime) -> str | None:
    """PAT-1103: record one billing_drift_checks row per tenant per calendar
    month, for every tenant with an active contract. Read-only observability
    — never writes billing_contracts or any other billed figure; see the
    ruling recorded on billing_drift_checks' migration comment.

    Idempotency (safe to call on every hourly tick): a row already exists
    for (tenant_id, current_month) -> that tenant is skipped this tick, same
    "does a row already exist for this period" shape _run_stale_digest_tick
    uses for its weekly gate. UNIQUE(tenant_id, checked_month) is the
    backstop if two tick invocations ever raced (single-threaded scheduler
    loop, so not expected in practice, but the constraint makes a duplicate
    insert fail loudly rather than silently double-count).
    """
    current_month = now.strftime("%Y-%m")
    rates = _billing_rates()
    device_counts, _ = _billing_tenant_overview()
    if not device_counts:
        # _billing_tenant_overview() already logs the underlying fetch
        # failure; degrade this tick too rather than silently recording
        # nothing for every tenant this hour.
        return "tenant overview fetch returned no data — skipped this tick"

    with get_db() as db:
        contracts = [
            dict(r) for r in db.execute(
                "SELECT * FROM billing_contracts WHERE status='active'"
            ).fetchall()
        ]
        already_checked = {
            r["tenant_id"] for r in db.execute(
                "SELECT tenant_id FROM billing_drift_checks WHERE checked_month=?",
                (current_month,),
            ).fetchall()
        }

    inserted = 0
    skipped_no_endpoints = 0
    for c in contracts:
        tid = c["tenant_id"]
        if tid in already_checked:
            continue  # already recorded this tenant for this calendar month
        if tid not in device_counts:
            # Best-effort: a tenant absent from the overview response (e.g.
            # offboarded, or a transient platform-side gap) gets no row
            # rather than a misleading endpoints=0 entry recorded as fact.
            skipped_no_endpoints += 1
            continue
        endpoints = device_counts[tid]
        drift = _tenant_band_drift(tid, endpoints, c, rates)
        now_iso = now.isoformat()
        with get_db() as db:
            db.execute(
                "INSERT INTO billing_drift_checks "
                "(id, tenant_id, checked_month, direction, endpoints, band_would_produce, checked_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), tid, current_month, drift["direction"], endpoints,
                 drift["band_would_produce"], now_iso),
            )
        inserted += 1

    if inserted:
        print(f"[band-drift-check] recorded {inserted} tenant(s) for {current_month}")
    if skipped_no_endpoints:
        return f"{skipped_no_endpoints} contracted tenant(s) missing from tenant overview this tick"
    return None


def _run_calendly_followups_tick(now: datetime):
    """Send due follow-up emails for Calendly leads. Called once per scheduler tick."""
    with get_db() as db:
        leads = db.execute(
            "SELECT id, email, name, booked_at FROM calendly_leads WHERE converted_at IS NULL"
        ).fetchall()

    for lead in leads:
        lead_id = lead["id"]
        booked_at = datetime.fromisoformat(lead["booked_at"])
        if booked_at.tzinfo is None:
            booked_at = booked_at.replace(tzinfo=timezone.utc)

        # PAT-1010 (round 6): pick only the LATEST due step for this lead,
        # not every overdue step. If EMAIL_DRY_RUN suppressed an earlier
        # step's send (calendly_followup_sends never got its row) and a
        # later step becomes due before dry-run is turned off, sending every
        # unsent overdue step in one catch-up tick would mail stale
        # pre-meeting D+3 copy alongside post-meeting D+7 copy -- wrong
        # content, not just late. Re-derived every tick (not persisted) from
        # "is a later step also due", not "was a later step already sent",
        # so an earlier step stays permanently superseded even if catch-up
        # spans more than one tick (e.g. the D+7 send itself fails and
        # retries next tick -- D+3 must not sneak out in the meantime).
        applicable = None
        for day, subject in _FOLLOWUP_STEPS:
            send_after = booked_at + timedelta(days=day)
            if now < send_after:
                continue  # not due yet
            if applicable is None or day > applicable[0]:
                applicable = (day, subject)
        if applicable is None:
            continue
        day, subject = applicable

        with get_db() as db:
            already = db.execute(
                "SELECT 1 FROM calendly_followup_sends WHERE lead_id=? AND day_number=?",
                (lead_id, day),
            ).fetchone()
        if already:
            continue

        html, text = _calendly_followup_html(lead["name"], day)
        ok = _send_email(lead["email"], subject, html, text)
        if ok and email_delivery_status() == "dry_run":
            # PAT-1010: calendly_followup_sends is the idempotency gate for
            # this exact day-N step and also drives the Leads tab's
            # "D+day" checkmarks; recording it under dry-run would both
            # permanently skip the real follow-up for this lead and show
            # an operator a follow-up that was never sent.
            print(f"[calendly-followup] day-{day} EMAIL_DRY_RUN active for "
                  f"{lead['email']}, not marking sent")
        elif ok:
            with get_db() as db:
                db.execute(
                    "INSERT OR IGNORE INTO calendly_followup_sends (lead_id, day_number, sent_at) "
                    "VALUES (?, ?, ?)",
                    (lead_id, day, now.isoformat()),
                )
            print(f"[calendly-followup] day-{day} sent to {lead['email']}")
        else:
            print(f"[calendly-followup] day-{day} FAILED for {lead['email']}")


def _run_deploy_drift_check_tick(now: datetime) -> str | None:
    """PAT-992: record whether the code actually running on this box matches
    what the last deploy confirmed as deployed.

    The estate's dominant failure mode is "merged but never deployed", and
    until this ticket the on-box signal for that (DEPLOYED_SHA) was a file
    nothing wrote — hand-created once, asserting a wrong answer ever since.
    scripts/deploy.sh now writes DEPLOYED_SHA_FILE (DEPLOYED_SHA=<full sha> /
    DEPLOYED_AT=<UTC timestamp>) atomically, and only as the last step of a
    forward deploy that passed its smoke suite (or restarted cleanly with no
    smoke runner present) or a completed rollback — on a rollback it records
    what the box actually rolled BACK to, not what it tried to deploy. A
    no-op deploy (nothing to do) deliberately does NOT write this file — it
    verified nothing, and the checkout could be sitting on a commit a prior
    smoke failure left behind under .no-auto-rollback, so writing there
    would risk recording a known-bad commit as confirmed. See that script's
    header comment for the full contract.

    This check only ever compares that recorded value against this
    checkout's own `git rev-parse HEAD` and verifies that no tracked files
    differ from that HEAD. It does not and must not reach
    origin/main. Deploy keys are disabled org-wide (PAT-617) and the box
    cannot fetch from GitHub; giving this check a GitHub dependency would
    both violate that and silently reintroduce the "the box thinks it can
    see something it can't" failure shape. So "N commits behind
    origin/main" is a claim this check never makes — only "the checkout
    matches (or doesn't) the last deploy this box's own tooling confirmed."

    This tracked-file check is what makes an scp hotfix visible: copying a
    tracked file into the checkout leaves HEAD and DEPLOYED_SHA agreeing with
    each other, but the running content no longer agrees with either. Untracked
    runtime files are deliberately excluded. Both git commands are bounded;
    an error or timeout is degraded rather than an implicit healthy result.

    Every branch that cannot positively confirm a match records
    unconfigured or degraded with a specific reason — never ok. A check
    that no-ops into a green tick because it found nothing to compare is
    exactly the class of bug this ticket exists to close; reporting ok
    because nothing was checked is not the same as reporting ok because a
    match was confirmed.

    A missing DEPLOYED_SHA_FILE is treated as unconfigured (a standing gap —
    no deploy has run under this tooling yet, expected to self-resolve on
    the next real deploy) rather than degraded, matching the convention
    already established for health_alert_delivery/portal_auth: an
    unconfigured check does not itself degrade its tick's heartbeat (see
    _run_tick's docstring and test_health_alerts_tick_unconfigured_channel_
    does_not_degrade_tick). An existing-but-unreadable-or-unparseable file,
    or a checkout HEAD this box cannot read at all, is a real break rather
    than a mere configuration gap, so those record degraded and DO return
    the reason here — required so tick_deploy_drift_check agrees with
    deploy_drift instead of reading ok while the check reads degraded (the
    PAT-1045 shape this ticket must not reproduce).

    A mismatch is a special case (PAT-992, FIX 2 from independent review):
    every deploy restarts the service BEFORE the record catches up (see
    _PROCESS_STARTED_AT above — that ordering is deliberate and does not
    change), so there is a real window, every successful deploy, where this
    process is already running new code but DEPLOYED_SHA_FILE still names
    the previous commit. Reporting that window as degraded is safe-direction
    but still wrong: a check that cries wolf after every good deploy for up
    to an hour is a check operators learn to ignore, and a false "degraded"
    landing in the 09:00 UTC digest is exactly that. So a mismatch where the
    recorded timestamp predates this process's own start, and we're still
    inside _DEPLOY_INFLIGHT_GRACE of that start, is reported unconfigured
    ("can't tell yet, still might be finishing") rather than degraded, and
    does not degrade the tick either — same convention as the missing-file
    case, because this too is a transient, self-resolving condition, not a
    tick failure. Past the grace window a mismatch is no longer explained by
    "still deploying" and reports degraded as normal; this is what stops a
    genuinely stuck or crashed deploy (smoke hung, write never happened)
    from hiding in the maybe-in-flight state indefinitely.
    """
    if not os.path.isfile(DEPLOYED_SHA_FILE):
        reason = (
            f"{DEPLOYED_SHA_FILE} does not exist — no deploy has recorded a "
            f"SHA yet under the current deploy.sh"
        )
        _record_check_status("deploy_drift", "unconfigured", reason, now)
        return None

    try:
        with open(DEPLOYED_SHA_FILE, "r") as f:
            content = f.read()
    except OSError as e:
        reason = f"{DEPLOYED_SHA_FILE} could not be read: {e}"
        _record_check_status("deploy_drift", "degraded", reason, now)
        return reason

    recorded_sha = ""
    recorded_at_raw = ""
    for line in content.splitlines():
        if line.startswith("DEPLOYED_SHA="):
            recorded_sha = line[len("DEPLOYED_SHA="):].strip()
        elif line.startswith("DEPLOYED_AT="):
            recorded_at_raw = line[len("DEPLOYED_AT="):].strip()

    if not recorded_sha:
        reason = (
            f"{DEPLOYED_SHA_FILE} exists but has no DEPLOYED_SHA= line — "
            f"cannot parse a recorded SHA"
        )
        _record_check_status("deploy_drift", "degraded", reason, now)
        return reason

    import subprocess
    try:
        local_head = subprocess.check_output(
            ["git", "-C", DASHBOARD_REPO_DIR, "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL, timeout=5, text=True,
        ).strip()
    except Exception as e:
        reason = f"could not read local checkout HEAD at {DASHBOARD_REPO_DIR}: {e}"
        _record_check_status("deploy_drift", "degraded", reason, now)
        return reason

    if not local_head:
        reason = f"git rev-parse HEAD at {DASHBOARD_REPO_DIR} returned nothing"
        _record_check_status("deploy_drift", "degraded", reason, now)
        return reason

    try:
        tracked_status = subprocess.check_output(
            [
                "git", "-C", DASHBOARD_REPO_DIR, "status", "--porcelain=v1",
                "--untracked-files=no",
            ],
            stderr=subprocess.DEVNULL, timeout=5, text=True,
        ).strip()
    except subprocess.TimeoutExpired:
        reason = (
            f"timed out after 5 seconds while checking tracked-file state at "
            f"{DASHBOARD_REPO_DIR}"
        )
        _record_check_status("deploy_drift", "degraded", reason, now)
        return reason
    except Exception as e:
        reason = (
            f"could not inspect tracked-file state at {DASHBOARD_REPO_DIR}: {e}"
        )
        _record_check_status("deploy_drift", "degraded", reason, now)
        return reason

    if tracked_status:
        changed_count = len(tracked_status.splitlines())
        reason = (
            f"checkout has {changed_count} tracked-file change(s) outside HEAD "
            f"({local_head[:12]}); an scp/manual hotfix may be running without "
            f"recorded provenance"
        )
        _record_check_status("deploy_drift", "degraded", reason, now)
        return reason

    if recorded_sha == local_head:
        _record_check_status(
            "deploy_drift", "ok",
            f"running checkout matches last recorded deploy ({local_head[:12]})",
            now,
        )
        return None

    # Mismatch. Before calling this degraded, rule out "a deploy is plausibly
    # still finishing" — see the docstring above and _PROCESS_STARTED_AT's
    # own comment for why this window exists and why the fix belongs here,
    # not in write-earlier.
    recorded_at = None
    if recorded_at_raw:
        try:
            recorded_at = datetime.fromisoformat(recorded_at_raw.replace("Z", "+00:00"))
        except ValueError:
            recorded_at = None  # unparseable timestamp — fall through to degraded below

    if (
        recorded_at is not None
        and recorded_at < _PROCESS_STARTED_AT
        and (now - _PROCESS_STARTED_AT) < _DEPLOY_INFLIGHT_GRACE
    ):
        reason = (
            f"checkout HEAD ({local_head[:12]}) does not yet match DEPLOYED_SHA "
            f"({recorded_sha[:12]} recorded {recorded_at.isoformat()}), but this "
            f"process only started {_PROCESS_STARTED_AT.isoformat()} — a deploy "
            f"may still be finishing; re-checking next tick"
        )
        _record_check_status("deploy_drift", "unconfigured", reason, now)
        return None

    reason = (
        f"checkout HEAD ({local_head[:12]}) does not match the last deployed "
        f"SHA ({recorded_sha[:12]}) recorded by scripts/deploy.sh — compared "
        f"locally only, this box cannot reach origin/main on GitHub"
    )
    _record_check_status("deploy_drift", "degraded", reason, now)
    return reason


def _truncate_check_reason(reason: str, limit: int = 200) -> str:
    """Cap a check_statuses reason string at `limit` chars, same rule the
    exception path in _run_tick has always used. Shared so a tick-returned
    reason and an exception's str() truncate identically instead of each
    call site keeping its own copy of the same 200-char rule."""
    if len(reason) > limit:
        return reason[:limit] + "…"
    return reason


def _maintenance_counts(facts: dict) -> dict:
    """Normalize either shape maintenance facts can arrive in into the same
    three integer counts, so _maintenance_facts_degraded_reasons only has to
    encode the degraded-decision logic once instead of three times.

    prod-01/api-01 hand over the full detail (a `timers` array with one
    {unit, enabled, last_trigger, last_result} entry per timer, and a
    `third_party_pending` array of {package, installed, candidate, origin}).
    portal-01's public /healthz cannot expose that much detail (see
    _run_maintenance_drift_check_tick's docstring) and instead hands over
    pre-summed `timers_failed_count` / `timers_disabled_count` /
    `third_party_pending_count` integers. Detected by presence of the
    `timers` key, since the full shape always includes it (even as `[]`)
    while the counts-only shape never does.
    """
    if "timers" in facts:
        timers = facts.get("timers") or []
        third_party = facts.get("third_party_pending") or []
        timers_failed = sum(1 for t in timers if t.get("last_result") == "failed")
        timers_disabled = sum(
            1 for t in timers
            if t.get("enabled") in ("disabled", "not-found")
        )
        return {
            "timers_failed": timers_failed,
            "timers_disabled": timers_disabled,
            "third_party_pending": len(third_party),
        }
    return {
        "timers_failed": int(facts.get("timers_failed_count") or 0),
        "timers_disabled": int(facts.get("timers_disabled_count") or 0),
        "third_party_pending": int(facts.get("third_party_pending_count") or 0),
    }


def _as_count(value) -> int | None:
    """Coerce a facts-file value expected to be a non-negative count into an
    int, or None if it isn't one — never raises. Guards against a malformed
    emitter write (e.g. a string) being silently treated as "0/absent"
    instead of surfaced as a data-quality problem; see
    _maintenance_facts_degraded_reasons' security_updates handling."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _maintenance_facts_degraded_reasons(facts: dict) -> list[str]:
    """The one shared 'does this look degraded' decision (PAT-989), applied
    identically to all three boxes regardless of which shape their facts
    arrived in — see _maintenance_counts for the normalization that makes
    that possible.

    Deliberately does NOT fold in _stray_config_backup_findings' degraded
    half — its only caller (_run_maintenance_drift_check_tick) needs BOTH
    halves of that function's return value (degraded_reasons for this list,
    info_note for the reason string regardless of state), so it calls
    _stray_config_backup_findings itself, once, and merges the degraded
    half in there. Calling it a second time here would mean the same
    read-and-classify logic living at two call sites — exactly the
    divergence risk PAT-1408 non-author review flagged: someone edits one
    copy's classification (e.g. what counts as "readable") and not the
    other, and the two never notice they've drifted.
    """
    counts = _maintenance_counts(facts)
    reasons: list[str] = []

    if facts.get("reboot_required"):
        reasons.append("reboot required")

    pro_attached = facts.get("pro_attached")
    if pro_attached is False:
        # Andy ruled 2026-08-02 that Pro should be attached estate-wide —
        # until it is everywhere, this is a real, active gap, not a settled
        # absence, so it counts as degraded rather than merely informational.
        reasons.append("Pro not attached")

    esm = _as_count(facts.get("esm_updates"))
    if pro_attached is True and esm is not None and esm > 0:
        reasons.append(f"{esm} ESM update(s) pending")

    security = _as_count(facts.get("security_updates"))
    if security is not None and security > 0:
        reasons.append(f"{security} security update(s) pending")
    elif facts.get("security_updates") is not None and security is None:
        # A non-null value that didn't coerce to a count (e.g. a string from
        # a malformed emitter write) is itself a data-quality problem — flag
        # it rather than silently treating it as zero.
        reasons.append(
            f"security_updates has an unreadable value: {facts.get('security_updates')!r}"
        )

    if counts["timers_failed"] > 0:
        reasons.append(f"{counts['timers_failed']} timer(s) failed")
    if counts["timers_disabled"] > 0:
        reasons.append(f"{counts['timers_disabled']} timer(s) unexpectedly disabled/not-found")
    if counts["third_party_pending"] > 0:
        reasons.append(f"{counts['third_party_pending']} third-party package(s) pending")

    return reasons


def _stray_config_backup_findings(facts: dict) -> tuple[list[str], str]:
    """PAT-1408: surface stray `*.bak*`/`*.pre-*` config-backup copies that
    deploy/patched-maintenance-facts.sh finds under
    /etc/patched-{dashboard,api,portal}. These were never written by any
    automated path -- grepping deploy/scripts across dashboard/patched.im/
    portal for anything writing into /etc/patched-* turns up nothing, and
    the historical filenames (bak-pat687, pre-pat909-..., bak-20260723-pat936)
    encode ticket ids, meaning ad-hoc per-ticket human/session commands wrote
    them, not a script. This is a detective guard against that recurring by
    hand again, not a fix to a writer that doesn't exist.

    Returns (degraded_reasons, info_note):

      - degraded_reasons: entries naming every group/world-readable stray,
        and separately every stray whose permissions could NOT be read at
        all (`mode_unknown`, PAT-1408 non-author review round 3). That
        permission bit is the property that actually matters -- a 0640
        root:www-data copy of a live env file is a secret leak to the
        service account, not merely untidy -- so a confirmed-readable stray
        always escalates the row to degraded, distinct from a merely-untidy
        0600 root:root copy. A stray whose mode the emitter's `stat` call
        could not parse gets the SAME escalation, fail-closed: an
        unreadable-permissions result must never be silently folded into
        "root-only, safe" just because the fallback happened to compute
        "000" -- that is the unknown-reads-as-clean shape this ticket
        exists to close, one level below the missing-field case below. Its
        reason text says "could not be determined", never "readable", so a
        reader can tell a confirmed leak from an unconfirmed one. PAT-1433:
        the emitter now reports JSON null (not false) for group_readable/
        world_readable whenever mode_unknown is true, and this function
        checks `is None` on both fields independently of mode_unknown --
        a null boolean escalates to unknown_mode_paths even if mode_unknown
        were ever missing or wrong, never silently reads as "not readable".
      - info_note: a line to append to the reason string regardless of
        whether the row ends up "ok" or "degraded", so a 0600 root:root
        stray is still visible (lower severity, not silence) without itself
        forcing a false-alarm degraded. Also the mechanism that keeps "no
        strays found" and "this box's emitter doesn't report this field
        yet" from reading the same -- a missing key is deliberately NOT an
        empty list. That absence-reads-as-clean shape is exactly what PAT-
        912/837/960 already caught this estate doing elsewhere; a missing
        field here must read as unknown, never as a clean scan.

    PAT-1440: `facts` arrives in one of two shapes, exactly like
    _maintenance_counts() already normalises for timers/third_party_pending:

      - prod-01/api-01: the full `stray_config_backups` array (branch below,
        unchanged from PAT-1408/1433) -- every entry named and classified
        here.
      - portal-01: pre-summed `stray_config_backups_count`/`_readable_
        count`/`_unknown_count` integers (see portal's main.py
        _stray_config_backups_counts(), which applies the identical
        mode_unknown/null-boolean fail-closed classification before
        reducing to counts -- /healthz cannot carry filenames, so the
        degraded reasons in that branch report counts only, never paths).

    Detected by presence of the `stray_config_backups` key (the full shape
    always includes it, even as `[]`) vs. `stray_config_backups_count`
    (the counts shape) -- same detection convention _maintenance_counts
    uses for `timers`. Neither key present means neither box reported it:
    "not reported", never a fabricated zero.
    """
    if not isinstance(facts, dict):
        return [], "stray config backups: not reported by this emitter"

    if "stray_config_backups" in facts:
        raw = facts.get("stray_config_backups")
        if not isinstance(raw, list):
            return [], "stray config backups: not reported by this emitter"

        if not raw:
            return [], "stray config backups: none found"

        readable_paths: list[str] = []
        unknown_mode_paths: list[str] = []
        root_only_paths: list[str] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            path = entry.get("path") or "<unknown path>"
            group_readable = entry.get("group_readable")
            world_readable = entry.get("world_readable")
            # PAT-1433: the emitter reports JSON null (not false) for both
            # booleans whenever it couldn't parse the file's mode. This `or`
            # chain has two independent triggers, not one redundant with the
            # other: `entry.get("mode_unknown")` short-circuits the whole
            # condition when mode_unknown is true (today's emitter, the
            # common case) -- but it is falsy whenever mode_unknown is false
            # or absent, and in exactly that case the chain falls through to
            # the `is None` checks, which are what actually stop a
            # never-determined value being read as safe. That is the
            # defence-in-depth: a malformed or future entry with null
            # booleans but mode_unknown missing/false still escalates, on
            # the `is None` checks alone. A consumer that only inspected
            # these two fields (skipping mode_unknown entirely, e.g.
            # `entry.get("group_readable") or entry.get("world_readable")`)
            # would see `None or None` -> falsy -> "not readable" -- the
            # exact unknown-reads-as-clean shape this ticket exists to
            # close, one level below the missing-field case.
            if entry.get("mode_unknown") or group_readable is None or world_readable is None:
                # Fail closed: permissions we couldn't read are treated as
                # potentially readable, never as confirmed root-only-safe.
                unknown_mode_paths.append(path)
            elif group_readable or world_readable:
                readable_paths.append(path)
            else:
                root_only_paths.append(path)

        # Kept short deliberately: this feeds into a reason string capped at
        # _truncate_check_reason's 200-char limit alongside whatever else is
        # already in it, and a truncated filename is as useless as a
        # missing one -- see _truncate_check_reason's callers.
        degraded_reasons: list[str] = []
        if readable_paths:
            degraded_reasons.append(
                f"{len(readable_paths)} stray config backup(s) readable beyond owner: "
                + ", ".join(readable_paths)
            )
        if unknown_mode_paths:
            degraded_reasons.append(
                f"{len(unknown_mode_paths)} stray config backup(s) with permissions "
                "that could not be determined: " + ", ".join(unknown_mode_paths)
            )

        if root_only_paths:
            info_note = (
                f"stray config backups: {len(root_only_paths)} root-only 0600 (untidy, "
                "not a permission leak): " + ", ".join(root_only_paths)
            )
        else:
            # Nothing left to say beyond the degraded_reasons entries above,
            # which already name the readable/unknown ones.
            info_note = ""

        return degraded_reasons, info_note

    if "stray_config_backups_count" in facts:
        # portal-01's reduced shape (PAT-1440). Fail closed on an
        # unparseable count the same way _as_count's other callers do --
        # available:present-but-malformed is a data-quality problem, not a
        # zero.
        total = _as_count(facts.get("stray_config_backups_count"))
        readable = _as_count(facts.get("stray_config_backups_readable_count"))
        unknown = _as_count(facts.get("stray_config_backups_unknown_count"))
        if total is None or readable is None or unknown is None:
            return [], "stray config backups: not reported by this emitter"

        if total == 0:
            return [], "stray config backups: none found"

        degraded_reasons = []
        if readable:
            degraded_reasons.append(
                f"{readable} stray config backup(s) readable beyond owner "
                "(portal-01: names withheld -- see /healthz's disclosure policy)"
            )
        if unknown:
            degraded_reasons.append(
                f"{unknown} stray config backup(s) with permissions that could "
                "not be determined (portal-01: names withheld)"
            )

        root_only = total - readable - unknown
        if root_only > 0:
            info_note = (
                f"stray config backups: {root_only} root-only 0600 (untidy, "
                "not a permission leak)"
            )
        else:
            info_note = ""

        return degraded_reasons, info_note

    return [], "stray config backups: not reported by this emitter"


def _systemd_hardening_findings(facts: dict) -> tuple[list[str], str]:
    """PAT-1237: surface systemd units breaching patched.im/docs/systemd-
    hardening-floor.md's per-class `systemd-analyze security` ceiling, or
    that patched-maintenance-facts.sh scored but this estate's class mapping
    doesn't recognise. Modeled closely on _stray_config_backup_findings
    above -- same (degraded_reasons, info_note) return shape, same "absence
    must not read as clean" discipline for both the whole field and each
    unit's own unclassified/unjudged state.

    Built because nothing checked live units against the floor doc's
    ceilings: a manual survey on 2026-08-19 found patched-maintenance-
    facts.service (the very emitter that writes the JSON this function
    reads) shipping unhardened and breaching its own 6.0 scheduled-
    maintenance ceiling on all three boxes -- undetected for 12 days. This
    function is that guard's dashboard-side half; deploy/patched-
    maintenance-facts.sh's PARITY-BLOCK is the other half (which unit
    belongs to which class, and each class's ceiling).

    Returns (degraded_reasons, info_note):

      - degraded_reasons: one entry per unit in any of three buckets, each
        worded distinctly so a reader can tell them apart:

          * over ceiling: a unit whose live score exceeds its class's
            ceiling (`over_ceiling` is True). Names the unit, its score, and
            the ceiling it breached.
          * unclassified: a unit systemd-analyze scored (score/rating
            present) but that isn't in the class mapping at all (`class` is
            None). This is deliberately checked FIRST and independently of
            `over_ceiling`'s value -- a brand-new unit landing unclassified
            is the single most important case this guard exists to catch,
            and the emitter always reports over_ceiling as null for an
            unclassified unit, but a malformed or future entry with a
            non-null over_ceiling and a null class must still escalate on
            the null class alone, not be read as "somehow judged fine".
            Same defence-in-depth shape PAT-1433 non-author review already
            established for stray_config_backups' null group_readable/
            world_readable booleans.
          * could not be judged: a unit WITH a known class/ceiling (so not
            unclassified) whose `over_ceiling` is still None -- the emitter
            knew which ceiling applies but couldn't parse a live score for
            it. Distinct wording from "unclassified" so a reader isn't told
            a real, mapped unit is a brand-new one.

      - info_note: a line to append to the reason string regardless of
        whether the row ends up "ok" or "degraded" (same convention as
        _stray_config_backup_findings' info_note): "not reported" when the
        field or its `units` array is absent/malformed, "not available"
        when the emitter positively reported `available: false` (systemd-
        analyze missing or broken on that box -- must read as unknown, never
        as a clean scan), or a short summary otherwise. A missing field must
        never read the same as "confirmed nothing over ceiling" -- the exact
        absence-reads-as-clean shape PAT-912/837/960 already caught this
        estate doing elsewhere.

    PAT-1440: `facts` arrives in one of two shapes, exactly like
    _stray_config_backup_findings above:

      - prod-01/api-01: the full `systemd_hardening` object (branch below,
        unchanged from PAT-1237) -- `available` plus a `units` array naming
        every unit and its score.
      - portal-01: `systemd_hardening_available` plus pre-summed `_over_
        ceiling_count`/`_unclassified_count`/`_unjudged_count` integers (see
        portal's main.py _systemd_hardening_counts()). No unit names or
        scores -- a public unauthenticated response naming exactly which
        service is unhardened, with its exposure score, is a target list.
        Because portal's reduction never exposes score/ceiling, the
        contradicts_flag cross-check below (verifying over_ceiling against
        the raw numbers) has nothing to check against on this branch --
        portal's own main.py does that verification before reducing, so the
        count it hands over already reflects it.

    Detected by presence of `systemd_hardening` (full shape) vs.
    `systemd_hardening_available` (counts shape) -- same convention
    _stray_config_backup_findings uses. Neither key present means neither
    box reported it: "not reported", never a fabricated zero.
    """
    if not isinstance(facts, dict):
        return [], "systemd hardening: not reported by this emitter"

    if "systemd_hardening" in facts:
        raw = facts.get("systemd_hardening")
        if not isinstance(raw, dict):
            return [], "systemd hardening: not reported by this emitter"

        if raw.get("available") is not True:
            # Covers available=false (systemd-analyze missing/broken on the
            # box, reported explicitly by the emitter) AND any malformed/
            # missing `available` value -- fail closed to "not available"
            # rather than assuming a scan happened.
            return [], "systemd hardening: not available on this box"

        units = raw.get("units")
        if not isinstance(units, list):
            return [], "systemd hardening: not reported by this emitter"

        if not units:
            return [], "systemd hardening: no patched-owned units found to score"

        over_ceiling: list[str] = []
        unclassified: list[str] = []
        unjudged: list[str] = []
        for entry in units:
            if not isinstance(entry, dict):
                continue
            unit = entry.get("unit") or "<unknown unit>"
            unit_class = entry.get("class")
            over = entry.get("over_ceiling")

            score = entry.get("score")
            ceiling = entry.get("ceiling")

            # Don't take over_ceiling on trust when the numbers to check it
            # against are right here (PAT-1237 non-author review). The
            # emitter computes this boolean, but a consumer that believes a
            # False while holding score=9.6 and ceiling=6.0 would report a
            # breaching unit as passing -- the one outcome this guard
            # exists to make impossible. Same defence-in-depth PAT-1433
            # already established for stray_config_backups' null booleans:
            # verify what you can verify, and let the emitter's own flag
            # decide only what you can't.
            contradicts_flag = (
                over is False
                and isinstance(score, (int, float))
                and isinstance(ceiling, (int, float))
                and score > ceiling
            )

            if unit_class is None:
                unclassified.append(unit)
            elif over is None:
                unjudged.append(unit)
            elif over is True or contradicts_flag:
                over_ceiling.append(f"{unit} ({score} > ceiling {ceiling})")
            # over is False, class known, numbers agree: genuinely passes.

        degraded_reasons: list[str] = []
        if over_ceiling:
            degraded_reasons.append(
                f"{len(over_ceiling)} unit(s) over their hardening ceiling: "
                + ", ".join(over_ceiling)
            )
        if unclassified:
            degraded_reasons.append(
                f"{len(unclassified)} unit(s) unclassified (not in the "
                "systemd-hardening-floor.md class mapping): " + ", ".join(unclassified)
            )
        if unjudged:
            degraded_reasons.append(
                f"{len(unjudged)} unit(s) could not be judged against their "
                "ceiling (no parseable live score): " + ", ".join(unjudged)
            )

        if degraded_reasons:
            info_note = ""
        else:
            info_note = f"systemd hardening: {len(units)} unit(s) scored, none over ceiling"

        return degraded_reasons, info_note

    if "systemd_hardening_available" in facts:
        # portal-01's reduced shape (PAT-1440). available:false must be
        # checked before looking for any count key -- it travels alone,
        # with no count keys at all, precisely so it can never be confused
        # with a clean scan of zero units.
        if facts.get("systemd_hardening_available") is not True:
            return [], "systemd hardening: not available on this box"

        over_ceiling_count = _as_count(facts.get("systemd_hardening_over_ceiling_count"))
        unclassified_count = _as_count(facts.get("systemd_hardening_unclassified_count"))
        unjudged_count = _as_count(facts.get("systemd_hardening_unjudged_count"))
        if over_ceiling_count is None or unclassified_count is None or unjudged_count is None:
            # available:true with an unparseable count is itself a
            # data-quality problem from this emitter -- fail closed to "not
            # reported" rather than guessing 0.
            return [], "systemd hardening: not reported by this emitter"

        degraded_reasons = []
        if over_ceiling_count:
            degraded_reasons.append(
                f"{over_ceiling_count} unit(s) over their hardening ceiling "
                "(portal-01: names withheld -- see /healthz's disclosure policy)"
            )
        if unclassified_count:
            degraded_reasons.append(
                f"{unclassified_count} unit(s) unclassified (not in the "
                "systemd-hardening-floor.md class mapping) (portal-01: names withheld)"
            )
        if unjudged_count:
            degraded_reasons.append(
                f"{unjudged_count} unit(s) could not be judged against their "
                "ceiling (no parseable live score) (portal-01: names withheld)"
            )

        if degraded_reasons:
            info_note = ""
        else:
            info_note = "systemd hardening: 0 unit(s) over ceiling (portal-01 reduced counts)"

        return degraded_reasons, info_note

    return [], "systemd hardening: not reported by this emitter"


def _artefact_drift_findings(facts: dict) -> tuple[list[str], str]:
    """PAT-1544: surface drift between the 8 hand-provisioned
    api-vps-artefacts/ files patched-maintenance-facts.sh checks on api-01
    (backup.sh, patched-backup.service/.timer, patched-maintenance-facts.sh/
    .service/.timer, create-partitions.sh, 52-automatic-reboot.conf) and the
    checksums recorded for them in api-vps-artefacts/artefact-manifest.json.
    Modeled closely on _stray_config_backup_findings/_systemd_hardening_findings
    above -- same (degraded_reasons, info_note) return shape, same
    absence-must-not-read-as-clean discipline.

    Built because merging a PR to one of these files does not put it on the
    box: PAT-993 updated backup.sh and merged it, but api-01 ran the
    pre-PAT-993 copy for weeks until found by accident. This field is the
    periodic checksum comparison PAT-1544 asked for, so that gap is visible
    in /admin/check-status instead of invisible.

    api-01 only for this pass (see patched-maintenance-facts.sh's own
    artefact_drift comment block for the full rationale) -- prod-01 and
    portal-01 do not emit this field yet, so its absence there must read as
    "not reported", never as "confirmed no drift".

    Per-artefact `status` values, as emitted by the shell script:
      - "match": on-box sha256 equals the manifest's recorded sha256.
      - "drift": on-box sha256 does not match the manifest -- the box is
        running something other than the last intentional deploy.
      - "missing": the on-box file does not exist at all. Reported FIRST
        and worded distinctly, and always a degraded finding same as
        "drift" (at least as severe) -- this is the exact PAT-949/portal-01
        shape (a hand-provisioned script silently absent) PAT-1544 exists
        to catch.
      - "unknown" (or any other/malformed value): the emitter could not
        positively confirm a verdict (manifest missing/unreadable, no
        manifest entry for this path, or the on-box file exists but
        couldn't be hashed). Reported as an info note, not a degraded
        finding -- an "unknown" is a data-quality gap in the check itself
        (e.g. the manifest hasn't been copied to the box yet), not a
        positive finding that something on the box is wrong. Fails closed
        to "could not be judged" rather than ever being read as a match.

    Returns (degraded_reasons, info_note) -- same convention as its two
    siblings above.
    """
    if not isinstance(facts, dict):
        return [], "artefact drift: not reported by this emitter"

    drift = facts.get("artefact_drift")
    if not isinstance(drift, list):
        return [], "artefact drift: not reported by this emitter"

    if not drift:
        return [], "artefact drift: no artefacts checked"

    missing: list[str] = []
    drifted: list[str] = []
    unknown: list[str] = []
    matched = 0

    for entry in drift:
        if not isinstance(entry, dict):
            continue
        on_box_path = entry.get("on_box_path") or entry.get("path") or "<unknown artefact>"
        status = entry.get("status")

        if status == "missing":
            missing.append(on_box_path)
        elif status == "drift":
            drifted.append(on_box_path)
        elif status == "match":
            matched += 1
        else:
            # Covers "unknown" and any unrecognised/malformed status value --
            # fail closed to "could not be judged", never to "match".
            unknown.append(on_box_path)

    degraded_reasons: list[str] = []
    if missing:
        degraded_reasons.append(
            f"{len(missing)} hand-provisioned artefact(s) missing from the box entirely: "
            + ", ".join(missing)
        )
    if drifted:
        degraded_reasons.append(
            f"{len(drifted)} hand-provisioned artefact(s) drifted from the repo: "
            + ", ".join(drifted)
        )

    if unknown:
        info_note = (
            f"artefact drift: {len(unknown)} artefact(s) could not be judged "
            "(no manifest entry, unreadable manifest, or unhashable file): "
            + ", ".join(unknown)
        )
    elif degraded_reasons:
        info_note = ""
    else:
        info_note = f"artefact drift: {matched} artefact(s) checked, all match"

    return degraded_reasons, info_note


def _maintenance_facts_from_local_file(path: str) -> tuple[dict | None, str | None]:
    """Load prod-01's own maintenance-facts snapshot straight off disk.
    Returns (facts, error) — error is a human-readable reason distinguishing
    missing/unreadable/unparseable, None on success. Mirrors the read-a-local-
    file discipline _run_deploy_drift_check_tick already uses for
    DEPLOYED_SHA_FILE."""
    if not os.path.isfile(path):
        return None, f"{path} does not exist — the facts timer may never have run"
    try:
        with open(path, "r") as f:
            raw = f.read()
    except OSError as e:
        return None, f"{path} could not be read: {e}"
    try:
        return json.loads(raw), None
    except ValueError as e:
        return None, f"{path} is not valid JSON: {e}"


def _maintenance_facts_from_url(url: str, timeout: int = 8, verify: bool = True) -> tuple[dict | None, str | None]:
    """Fetch a maintenance-facts JSON body over HTTP — api-01's internal
    admin endpoint or portal-01's public /healthz. Returns (facts, error).

    `verify` defaults to True (full certificate validation) because the only
    caller that needs it False is the internal api-01 call, which passes
    _VERIFY_INTERNAL explicitly for its self-signed cert. portal-01's
    /healthz is a public internet-facing HTTPS endpoint behind a real CF
    Origin Cert — reusing _VERIFY_INTERNAL there would silently disable TLS
    verification on a request that leaves the tailnet, opening a MITM
    window. Caught in non-author review; do not collapse this back to a
    single shared default."""
    try:
        r = http.get(url, timeout=timeout, verify=verify)
    except Exception as e:
        return None, f"{url} unreachable: {e}"
    if not r.ok:
        return None, f"{url} returned HTTP {r.status_code}"
    try:
        return r.json(), None
    except ValueError as e:
        return None, f"{url} did not return valid JSON: {e}"


def _run_maintenance_drift_check_tick(now: datetime) -> str | None:
    """PAT-989: record whether each of the three production boxes
    (patched-prod-01, patched-api-01, patched-portal-01) has current, healthy
    patch/reboot/timer facts — three separate check_statuses rows
    (maintenance_prod01/maintenance_api01/maintenance_portal01), modeled
    directly on _run_deploy_drift_check_tick's tri-state discipline above:
    every branch that cannot positively confirm health records unconfigured
    or degraded with a specific reason, never ok on partial information. A
    check that no-ops into a green tick because it couldn't actually look is
    exactly the failure this initiative exists to close.

    Each box's hourly deploy/patched-maintenance-facts.sh (or the api-01/
    portal-01 equivalents, built to the identical JSON schema — see that
    script's header comment) writes a snapshot this tick reads:

      - prod-01:   read MAINTENANCE_FACTS_FILE directly — this process runs
                   on that box.
      - api-01:    GET {PATCHED_API_INTERNAL}/admin/ops/maintenance, the same
                   internal-Tailscale-bind convention as every other
                   PATCHED_API_INTERNAL call in this file (see
                   api_ops_data()'s /admin/ops/version call).
      - portal-01: GET https://app.patched.im/healthz. That route is locked
                   to exactly /healthz + /static/* unauthenticated (portal's
                   own AGENTS.md — no new route there), so being public it
                   cannot expose the full per-timer/per-package detail the
                   other two boxes hand over directly. It exposes a reduced
                   "maintenance" key instead — *_count integers in place of
                   the full timers/third_party_pending arrays.
                   _maintenance_counts() normalizes both shapes into the same
                   three integers so _maintenance_facts_degraded_reasons()
                   (the shared "does this look degraded" decision) is written
                   once, not three times.

    unconfigured fires whenever a source cannot be positively read as current
    and healthy — unreachable, missing, unparseable JSON, a portal-01 body
    with no "maintenance" object, unavailable/non-boolean Pro attachment
    status, or generated_at older than
    _MAINTENANCE_STALE_AFTER (the facts timer may have stopped running). Each
    branch records a specific, distinguishable reason string, the same
    discipline _run_deploy_drift_check_tick already established for
    deploy_drift.

    degraded fires on any of: reboot_required; an explicitly false Pro
    attachment status (an active gap per Andy's 2026-08-02 ruling that Pro
    should be attached estate-wide, not a settled absence); positively
    attached Pro with esm_updates > 0;
    security_updates > 0; any timer with last_result "failed"; any timer
    "disabled"/"not-found"; any third-party package pending; any
    group/world-readable `stray_config_backups` entry (PAT-1408 -- see
    _stray_config_backup_findings); or any `systemd_hardening` unit over its
    class ceiling or unclassified (PAT-1237 -- see
    _systemd_hardening_findings). A timer that is deliberately retired
    must be removed from the emitted inventory and the canonical
    operational-truth manifest, not hidden behind a consumer allowlist that
    makes an accidental disable look healthy.

    `stray_config_backups` is PAT-1408: deploy/patched-maintenance-facts.sh
    scans /etc/patched-{dashboard,api,portal} for `*.bak*`/`*.pre-*` files
    left behind by ad-hoc per-ticket commands (never an automated writer --
    see that script's own comment) and reports each one's readability. A
    group/world-readable stray is a secret leak to the service account and
    degrades the row; a 0600 root:root stray is merely untidy and is
    reported in the reason string without forcing degraded. prod-01/api-01
    hand over the full per-stray array; portal-01's public /healthz cannot
    (PAT-1440 -- see portal's AGENTS.md/main.py) and instead hands over
    pre-summed `stray_config_backups_count`/`_readable_count`/`_unknown_
    count` integers, absent entirely (not zeroed) whenever portal-01's own
    emitter predates the field. A field genuinely absent -- on any of the
    three boxes, in either shape -- must read as "not reported", never as
    "zero strays found"; see _stray_config_backup_findings' docstring for
    how both shapes are normalised into the same decision.

    `systemd_hardening` is PAT-1237: deploy/patched-maintenance-facts.sh
    scores every patched-owned systemd unit (name starts with "patched-",
    FragmentPath under /etc/systemd/system) against patched.im/docs/systemd-
    hardening-floor.md's per-class `systemd-analyze security` ceiling. A
    unit over its ceiling degrades the row and names the unit/score/ceiling;
    a unit systemd-analyze scored but that isn't in the class mapping
    degrades the row too, worded "unclassified" rather than "over ceiling"
    -- a brand-new unit landing unclassified is the case this guard exists
    to catch, and it must never read as passing. `available: false` (the
    box's systemd-analyze is missing or broken) reads as "not available",
    distinct from both "not reported" (the field/box predates this ticket)
    and a clean scan. Same PAT-1440 shape split as stray_config_backups
    above: prod-01/api-01 hand over the full per-unit array with names and
    scores; portal-01's /healthz hands over `systemd_hardening_available`
    plus three pre-summed counts, with no unit names or scores, because
    that detail is a target list on a public unauthenticated response. See
    _systemd_hardening_findings' docstring for the full three-bucket
    breakdown (over ceiling / unclassified / could not be judged) and how
    both shapes reach the same decision.

    Like _run_deploy_drift_check_tick, this function's return value drives
    the shared tick_maintenance_drift_check heartbeat via _run_tick: None
    keeps the tick ok (also true when every box reads unconfigured — a
    standing configuration/staleness gap is not itself a tick failure, same
    convention as health_alert_delivery/portal_auth/deploy_drift above); a
    non-empty string (the degraded boxes' reasons, joined) makes the tick
    heartbeat degraded too, so tick_maintenance_drift_check can never read ok
    while one of the three named checks reads degraded — the PAT-1045 shape
    every check in this file must not reproduce.

    PAT-1427: the actual per-source work now lives in
    _check_one_maintenance_source below, factored out so fast_check_loop can
    recompute the prod-01 source alone, on a fast cadence, without this
    function's api-01/portal-01 HTTP calls coming along for the ride. This
    function's own behaviour — all three sources, every hour — is unchanged.
    """
    sources = [
        ("maintenance_prod01", "local", MAINTENANCE_FACTS_FILE),
        ("maintenance_api01", "url", f"{PATCHED_API_INTERNAL}/admin/ops/maintenance"),
        ("maintenance_portal01", "url_portal", "https://app.patched.im/healthz"),
    ]

    degraded_reasons: list[str] = []

    for check_name, kind, location in sources:
        reason = _check_one_maintenance_source(check_name, kind, location, now)
        if reason:
            degraded_reasons.append(f"{check_name}: {reason}")

    if degraded_reasons:
        return _truncate_check_reason("; ".join(degraded_reasons))
    return None


def _check_one_maintenance_source(
    check_name: str, kind: str, location: str, now: datetime
) -> str | None:
    """One source's worth of _run_maintenance_drift_check_tick's per-source
    logic (fetch, parse, staleness, degraded-reason classification, and the
    _record_check_status write), factored out under PAT-1427 so it can be
    called on its own — specifically, so fast_check_loop can recompute
    "maintenance_prod01" (kind="local", a bare file read) every
    _FAST_CHECK_INTERVAL without also re-fetching api-01/portal-01 over HTTP
    on that same short cadence. Behaviour for every kind is unchanged from
    the inline loop body this replaces; _run_maintenance_drift_check_tick
    still calls this once per source, in the same order, every hour.

    Returns the degraded reason string (unprefixed by check_name — the
    caller adds that) if this source is degraded, else None (covers both
    "ok" and "unconfigured" — same convention _run_deploy_drift_check_tick
    uses: only a real, positively-confirmed problem returns non-None."""
    if kind == "local":
        facts, err = _maintenance_facts_from_local_file(location)
    elif kind == "url":
        # api-01's internal Tailscale admin endpoint — self-signed cert,
        # same _VERIFY_INTERNAL every other PATCHED_API_INTERNAL call uses.
        facts, err = _maintenance_facts_from_url(location, verify=_VERIFY_INTERNAL)
    else:
        # portal-01's public /healthz — real CF Origin Cert, full
        # verification (the function's default). Do not pass
        # _VERIFY_INTERNAL here.
        facts, err = _maintenance_facts_from_url(location)
        if err is None and kind == "url_portal":
            # portal-01's /healthz nests the reduced facts under
            # "maintenance"; a healthz body without that key is itself an
            # unparseable-shape error, not a healthy-but-empty result.
            maint = facts.get("maintenance") if isinstance(facts, dict) else None
            if not isinstance(maint, dict):
                facts, err = None, f"{location} response has no 'maintenance' object"
            else:
                facts = maint

    if err is not None:
        _record_check_status(check_name, "unconfigured", _truncate_check_reason(err), now)
        return None

    generated_at_raw = facts.get("generated_at") if isinstance(facts, dict) else None
    generated_at = None
    if isinstance(generated_at_raw, str):
        try:
            generated_at = datetime.fromisoformat(generated_at_raw.replace("Z", "+00:00"))
        except ValueError:
            generated_at = None

    if generated_at is None:
        reason = f"{location}: facts have no parseable generated_at timestamp"
        _record_check_status(check_name, "unconfigured", reason, now)
        return None

    age = now - generated_at
    if age > _MAINTENANCE_STALE_AFTER:
        reason = (
            f"{location}: facts are stale — generated_at "
            f"{generated_at.isoformat()} is {age} old (limit "
            f"{_MAINTENANCE_STALE_AFTER}); the facts timer may have stopped running"
        )
        _record_check_status(check_name, "unconfigured", _truncate_check_reason(reason), now)
        return None

    # The collector's Pro result is tri-state. An absent, null, or otherwise
    # malformed value is not evidence that Pro is detached; it is an
    # unavailable observation and must not make the scheduler heartbeat fail.
    if not isinstance(facts.get("pro_attached"), bool):
        reason = f"{location}: Pro attachment status unavailable"
        _record_check_status(check_name, "unconfigured", reason, now)
        return None

    reasons = _maintenance_facts_degraded_reasons(facts)
    # Computed once per source (PAT-1408 non-author review: a second
    # call site classifying the same raw facts a second time is a
    # divergence risk) and used for each finding function's pair of return
    # values: the degraded reasons are merged into `reasons` here, and each
    # info_note is appended to the final reason string on BOTH branches
    # below so a 0600-root stray, an unclassified unit, an unjudged
    # artefact, or the "this box doesn't report the field yet" case, stays
    # visible even when nothing else pushed the row to degraded.
    stray_degraded, stray_info_note = _stray_config_backup_findings(facts)
    hardening_degraded, hardening_info_note = _systemd_hardening_findings(facts)
    artefact_degraded, artefact_info_note = _artefact_drift_findings(facts)
    reasons = reasons + stray_degraded + hardening_degraded + artefact_degraded
    info_notes = [n for n in (stray_info_note, hardening_info_note, artefact_info_note) if n]
    if reasons:
        reason = "; ".join(reasons)
        if info_notes:
            reason = f"{reason}; " + "; ".join(info_notes)
        _record_check_status(check_name, "degraded", _truncate_check_reason(reason), now)
        return reason
    else:
        reason = f"confirmed healthy as of {generated_at.isoformat()}"
        if info_notes:
            reason = f"{reason}; " + "; ".join(info_notes)
        _record_check_status(check_name, "ok", _truncate_check_reason(reason), now)
        return None


def _run_tick(label: str, fn, now: datetime) -> None:
    """Run one scheduler tick with a heartbeat (PAT-981).

    Every tick in scheduler_loop is routed through here so that, in addition
    to whatever a tick already records about itself (or doesn't), we always
    persist a `tick_<label>` entry in check_statuses. That turns "this tick
    silently stopped running" into a visible degraded state instead of
    invisible silence — including for _run_automation_digest_tick itself,
    which previously had no way to notice its own death.

    Preserves current behaviour exactly: `fn` is called, any exception is
    caught and logged with the same `[scheduler/<label>] Error: ...` text
    every tick already prints today, and the exception never propagates —
    one failing tick must never stop the loop.

    PAT-1018: `fn` may optionally return a reason string, in addition to the
    two ways it already had of reporting itself here (raise, or say
    nothing). `None` or an empty string keeps today's meaning, ok — every
    tick written before this ticket returns None implicitly (a bare
    `return` or falling off the end) and keeps behaving exactly as before.
    A non-empty string means the tick ran to completion without raising but
    something inside it did not do its job, and is recorded degraded with
    that string as the reason (truncated the same way an exception's text
    already is, via _truncate_check_reason). This is deliberately a return
    value rather than a raise: these are partial failures — a Slack post
    that did not confirm, say — where the tick genuinely should keep
    running rather than abort, unlike a real exception, which still means
    degraded with the exception text exactly as before.
    """
    check_name = f"tick_{label.replace('-', '_')}"
    try:
        reason = fn()
    except Exception as exc:
        print(f"[scheduler/{label}] Error: {exc}")
        try:
            _record_check_status(check_name, "degraded", _truncate_check_reason(str(exc)), now)
        except Exception as record_exc:
            print(f"[scheduler/{label}] failed to record tick status: {record_exc}")
        return
    try:
        if reason:
            _record_check_status(check_name, "degraded", _truncate_check_reason(reason), now)
        else:
            _record_check_status(check_name, "ok", "", now)
    except Exception as record_exc:
        print(f"[scheduler/{label}] failed to record tick status: {record_exc}")


def scheduler_loop():
    """Background thread: check every hour for due digests/alerts/reports."""
    print("[scheduler] Started")
    while True:
        try:
            now = datetime.now(timezone.utc)

            # 30-day retention cleanup for public uploads. Kept on its own
            # thread (unchanged): must not block the hourly loop. PAT-1215:
            # routed through _run_tick, same as report-schedules below, so a
            # dead/erroring thread heartbeats into check_statuses instead of
            # being invisible.
            if now.hour == 4:  # 04:00 UTC
                threading.Thread(
                    target=lambda: _run_tick("public-uploads-cleanup", _cleanup_old_public_uploads, now),
                    daemon=True,
                ).start()

            # PAT-218: cert digest emails
            _run_tick("cert-digest", lambda: _run_cert_digest_tick(now), now)

            # PAT-444: stale-endpoint weekly digest (weekly gate enforced per-tenant)
            _run_tick("stale-digest", lambda: _run_stale_digest_tick(now), now)

            # PAT-539: scheduled report PDFs (per-tenant catalog subscriptions)
            _run_tick("report-tick", lambda: _run_report_tick(now), now)

            # PAT-643: automation failure + staleness Slack alerts
            _run_tick("automation-alerts", lambda: _run_automation_alerts_tick(now), now)

            # PAT-1716: nightly uninstall E2E verification heartbeat -- catches
            # a job that stopped reporting even with no new result to react to.
            _run_tick("nightly-uninstall-checks", lambda: _run_nightly_uninstall_checks_tick(now), now)

            # PAT-979: owner/consultant separation state; runs before the digest
            # so the current value is included in the same tick.
            _run_tick("rbac-operators", lambda: _run_rbac_operators_check_tick(now), now)

            # PAT-1010: outbound email dry-run/unconfigured visibility; runs
            # before the digest so the current value is included in the same tick.
            _run_tick("email-delivery-check", lambda: _run_email_delivery_check_tick(now), now)

            # PAT-992: does the running checkout match what the last deploy
            # confirmed as deployed — surfaces "merged but never deployed"
            # drift instead of it being discovered weeks later.
            _run_tick("deploy-drift-check", lambda: _run_deploy_drift_check_tick(now), now)

            # PAT-989: patch/reboot/timer drift across all three boxes (prod-01,
            # api-01, portal-01) — surfaces pending security updates, unattached
            # Pro, failed/unexpectedly-disabled timers, and stale facts snapshots
            # instead of someone having to SSH in and look.
            _run_tick("maintenance-drift-check", lambda: _run_maintenance_drift_check_tick(now), now)

            # Daily automation health digest (positive confirmation, 09:00 UTC)
            _run_tick("automation-digest", lambda: _run_automation_digest_tick(now), now)

            # PAT-678: at-risk health transition alerts
            _run_tick("health-alerts", lambda: _run_health_alerts_tick(now), now)

            # PAT-837: portal Cloudflare Access AUD-drift monitor
            _run_tick("portal-auth-check", lambda: _run_portal_auth_healthcheck_tick(now), now)

            # PAT-435: Calendly lead follow-up email sequence
            _run_tick("calendly-followup", lambda: _run_calendly_followups_tick(now), now)

            # PAT-1103: monthly band-drift history for every tenant with an
            # active contract — advisory-only, feeds the renewal
            # conversation; per-tenant-per-month idempotent (safe hourly).
            _run_tick("band-drift-check", lambda: _run_band_drift_check_tick(now), now)

            # PAT-370: daily report schedule email send loop — runs at 07:00 UTC.
            # Kept on its own thread (unchanged): check_report_schedules walks
            # every tenant and can take a while, and must not block the hourly
            # loop. The heartbeat is recorded from inside that thread once the
            # run (or its failure) completes.
            if now.hour == 7:
                try:
                    threading.Thread(
                        target=lambda: _run_tick("report-schedules", check_report_schedules, now),
                        daemon=True,
                    ).start()
                except Exception as rse:
                    print(f"[scheduler/report-schedules] Error: {rse}")

            # PAT-670: trial expiry upgrade emails — runs at 08:00 UTC. Kept
            # on its own thread (unchanged): walks every tenant and must not
            # block the hourly loop. PAT-1215: routed through _run_tick,
            # same as report-schedules above, so a dead/erroring thread
            # heartbeats into check_statuses instead of being invisible.
            if now.hour == 8:
                try:
                    threading.Thread(
                        target=lambda: _run_tick("trial-expiry", check_trial_expiry_emails, now),
                        daemon=True,
                    ).start()
                except Exception as tee:
                    print(f"[scheduler/trial-expiry] Error: {tee}")

            # Write heartbeat so smoke tests can assert the loop is alive
            now_iso = now.isoformat()
            with get_db() as db:
                db.execute(
                    "INSERT INTO kv(key, value, updated_at) VALUES('scheduler_heartbeat', ?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                    (now_iso, now_iso),
                )

        except Exception as e:
            print(f"[scheduler] Error: {e}")

        time.sleep(3600)  # Check every hour


def fast_check_loop():
    """Background thread (PAT-1427): recompute deploy_drift and
    maintenance_prod01 every _FAST_CHECK_INTERVAL, independent of
    scheduler_loop's hourly cadence.

    scheduler_loop above is right for digests/reports/alerts — this
    function does NOT replace it, or restructure it, and every OTHER
    check_statuses row (including maintenance_api01/maintenance_portal01)
    stays exactly where it was: recomputed only once an hour, by
    scheduler_loop, as before.

    Only two checks qualify for this fast path, and both are cheap, local,
    and already bounded/fail-closed:
      - deploy_drift (_run_deploy_drift_check_tick): a local file read
        (DEPLOYED_SHA_FILE) plus a 5s-timeout local `git status`/
        `git rev-parse`. Never touches the network.
      - maintenance_prod01 (_check_one_maintenance_source, kind="local"):
        a local file read (MAINTENANCE_FACTS_FILE). Factored out of
        _run_maintenance_drift_check_tick specifically so this loop can
        recompute prod-01 alone, without also re-fetching api-01/portal-01.

    maintenance_api01 and maintenance_portal01 deliberately stay off this
    loop: both fetch over HTTP from another box, and a network call does
    not belong on a fast timer just to make a row look fresh — a slow or
    hung remote box would turn a 2-minute local loop into a thread
    pile-up. Nor should anything that hits the DB or another network
    dependency ever be added here; if a future check needs that, it
    belongs on scheduler_loop's hourly cadence, not this one.

    Uses its own tick_ heartbeat labels (deploy-drift-fast,
    maintenance-prod01-fast) rather than reusing scheduler_loop's
    (tick_deploy_drift_check, tick_maintenance_drift_check) — this loop's
    liveness is then visible on its own, without silently redefining what
    those two hourly heartbeats mean.
    """
    print("[fast-check] Started")
    while True:
        try:
            now = datetime.now(timezone.utc)
            # Concurrent writer note (PAT-1427, raised in non-author review):
            # this loop and the hourly scheduler_loop both call
            # _record_check_status for deploy_drift/maintenance_prod01, from
            # two different threads, on overlapping schedules. Two things
            # make that safe, and they are complementary, not alternatives:
            #   1. SQLite-level: get_db() (shared.py's _open_db_connection)
            #      sets `PRAGMA journal_mode=WAL` and `PRAGMA
            #      busy_timeout=10000` on every connection, so a write from
            #      one thread never blocks a reader, and a second concurrent
            #      writer just waits (up to 10s) rather than failing; this
            #      process already had multiple writer threads
            #      (report-schedules, trial-expiry) before this ticket.
            #   2. Correctness-level: _record_check_status itself guards its
            #      UPSERT so a write only replaces a row whose evaluated_at
            #      it is >= — see that function's own docstring. Without
            #      that guard, scheduler_loop captures `now` once at the top
            #      of its iteration and runs many other ticks before
            #      reaching these two, so its write can commit to SQLite
            #      several minutes after being "evaluated" — late enough to
            #      silently overwrite a fresher fast-path result with a
            #      stale one, undoing the entire point of this loop. The
            #      guard makes the newest evaluation win on wall-clock time
            #      instead of commit order.
            # Do not add a per-check mutex/lock here on top of these two: it
            # would protect against a hazard they already close, and is the
            # kind of thing a future reader deletes because it looks
            # unnecessary.
            _run_tick("deploy-drift-fast", lambda: _run_deploy_drift_check_tick(now), now)
            _run_tick(
                "maintenance-prod01-fast",
                lambda: _check_one_maintenance_source(
                    "maintenance_prod01", "local", MAINTENANCE_FACTS_FILE, now
                ),
                now,
            )
        except Exception as e:
            print(f"[fast-check] Error: {e}")
        time.sleep(_FAST_CHECK_INTERVAL.total_seconds())


# ══════════════════════════════════════════════════════════════
# APP
# ══════════════════════════════════════════════════════════════
# _send_email, templates, get_db — all imported from shared.py


def _docs_urls(env: str, flag: str) -> dict:
    """PAT-2408: /docs, /redoc and /openapi.json carry no staff identity, so
    they are off unless BOTH DASHBOARD_ENV is dev/local AND
    DASHBOARD_ENABLE_API_DOCS=1. Production needs no variable set. `app.openapi()`
    still works in-process with the URLs disabled."""
    if (env or "").strip().lower() in ("dev", "local") and (flag or "").strip() == "1":
        return {"docs_url": "/docs", "redoc_url": "/redoc", "openapi_url": "/openapi.json"}
    return {"docs_url": None, "redoc_url": None, "openapi_url": None}


def _tenant_id_param_ok(request: Request) -> bool:
    """False when the request's matched route has a `tenant_id` path parameter
    that is not a canonical UUID. Used by the auth middleware, which runs
    before routing has put `path_params` on the request."""
    for route in request.app.router.routes:
        match, child_scope = route.matches(request.scope)
        if match == Match.FULL:
            tenant_id = child_scope.get("path_params", {}).get("tenant_id")
            return tenant_id is None or _is_canonical_uuid(tenant_id)
    return True


def _require_canonical_tenant_id(request: Request) -> None:
    """PAT-2408: one shared edge check for every route that takes a tenant id.
    Attached app-wide (see `FastAPI(dependencies=...)`), so a new route with a
    `{tenant_id}` path parameter cannot forget it; tests/test_pat2408_console_boundary.py
    enumerates the routes and fails if one lacks it. Only canonical lowercase
    hyphenated UUIDs pass (upper case, braces, urn: and un-hyphenated forms are
    refused, not normalised), before any handler or upstream call runs."""
    tenant_id = request.path_params.get("tenant_id")
    if tenant_id is not None and not _is_canonical_uuid(tenant_id):
        raise UnsafePathSegment("invalid tenant identifier")


app = FastAPI(
    title="Patched.im Dashboard",
    dependencies=[Depends(_require_canonical_tenant_id)],
    **_docs_urls(DASHBOARD_ENV, os.getenv("DASHBOARD_ENABLE_API_DOCS", "")),
)


@app.exception_handler(UnsafePathSegment)
async def _unsafe_path_segment_handler(request: Request, exc: UnsafePathSegment):
    message = (
        "Invalid tenant identifier."
        if "tenant" in str(exc)
        else "Invalid identifier."
    )
    return JSONResponse({"error": message}, status_code=400)


app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")


# ══════════════════════════════════════════════════════════════
# AUTH MIDDLEWARE — defence-in-depth behind Cloudflare Access
# ══════════════════════════════════════════════════════════════
# CF Access guards browser traffic at the edge. This middleware adds
# app-level auth to /api/* AND /admin/* so those endpoints don't fall
# open if CF Access is bypassed (misconfigured Access app, leaked origin
# IP, direct localhost access from a future tenant on the VPS, etc.).
#
# The /admin/* guard is PAT-456 hardening: /admin/* carries all-tenant
# reads AND writes (POST /admin/tenants, allowlist, tenant rules, report
# email). It was inadvertently dropped when PAT-484's de-monolith was
# reverted (2a76ffa); this restores it (regression test: tests/test_pat456.py).
#
# Browser requests pick up the token from a server-rendered value and a
# fetch() monkey-patch in the page script (console.html adminFetch()).
#
# Navigation routes cannot attach custom headers. Downloads enforce their
# own signed-session check in the handler. Impersonation navigation uses the
# same middleware authentication/RBAC as other admin paths, also accepting
# a verified dashboard Access JWT for a person arriving without a session.
_ADMIN_NAV_EXEMPT_SUFFIXES = ("/impersonation/start", "/impersonation/end")


# ── Middleware registration order — read this before touching either function ──
# Starlette/FastAPI applies @app.middleware("http") decorators in REVERSE
# registration order: the LAST one registered becomes the OUTERMOST layer, so
# it runs first on the way in and last on the way out. `impersonation_write_guard`
# is registered here, FIRST, so it ends up as the INNER layer; `api_bearer_auth`
# (registered second, below) wraps around it as the OUTER layer.
#
# PAT-833: this is load-bearing, not incidental. api_bearer_auth writes the
# destructive-write audit row before dispatch and updates it with the real
# outcome after — including a response the guard below returns directly
# without calling call_next (its 403 when blocking a write during read-only
# impersonation). Being the outer layer means that 403 still flows back
# through api_bearer_auth's post-dispatch update, landing as a
# "rejected_403" audit row instead of vanishing. If `impersonation_write_guard`
# were ever registered AFTER (i.e. below) `api_bearer_auth`, it would become
# the outer layer instead and its 403 would short-circuit the inner audit
# middleware entirely — silently dropping the audit trail for destructive
# writes attempted mid-impersonation. Keep this one registered first.
@app.middleware("http")
async def impersonation_write_guard(request: Request, call_next):
    """Block mutating requests during a read-only impersonation session.
    Exempt: impersonation management endpoints and support-access toggle.

    Registered BEFORE api_bearer_auth (see the comment block above) so it is
    the inner layer and a 403 here still passes back through that middleware's
    audit-log update.
    """
    path   = request.url.path
    method = request.method
    if method in ("PUT", "POST", "DELETE", "PATCH") and path.startswith("/admin/"):
        imp = _imp_get(request)
        if imp and not imp.get("write_mode"):
            # Allow the write-mode enable endpoint and support-access toggle
            exempt_suffixes = ("/impersonation/write-mode", "/support-access")
            if not any(path.endswith(s) for s in exempt_suffixes):
                return JSONResponse(
                    {"error": "Not available in impersonation mode — enable write mode first"},
                    status_code=403,
                )
    return await call_next(request)


@app.middleware("http")
async def api_bearer_auth(request: Request, call_next):
    # PAT-695: accept EITHER a valid `patched_session` cookie (browser, minted on
    # /console from the CF-Access identity) OR the shared Bearer token (scripts/ops,
    # and the instant rollback path). Then apply owner/consultant RBAC, server-side
    # echo-back confirmation on destructive routes, and a destructive-write audit log.
    path   = request.url.path
    method = request.method
    is_get_download = method == "GET" and path.endswith("/download")
    guarded = (path.startswith("/api/") or path.startswith("/admin/")) and not is_get_download
    if not guarded:
        return await call_next(request)

    # Navigation links cannot carry a Bearer header: accept a signed session
    # or verified dashboard Access identity, before any handler side effects.
    is_auth_navigation = method == "GET" and any(
        path.endswith(s) for s in _ADMIN_NAV_EXEMPT_SUFFIXES
    )

    if not DASHBOARD_API_KEY:
        # Fail closed if the server isn't configured — better to 500 than to
        # silently allow unauthed traffic.
        return JSONResponse({"error": "Server auth not configured"}, 500)

    # ── Authenticate: Bearer token OR session cookie ──
    auth = request.headers.get("authorization", "")
    if auth == f"Bearer {DASHBOARD_API_KEY}":
        # Bearer auth carries no email → owner (back-compat + rollback path).
        role, actor = "owner", "bearer-token"
    else:
        email = _session_decode(request.cookies.get(SESSION_COOKIE, ""))
        if not email and is_auth_navigation:
            email = _cf_email(request)
            if not email and _DEV_ENV:
                email = "dev@local"
        if not email:
            return JSONResponse({"error": "Unauthorized"}, 401)
        role, actor = _role_for_email(email), email

    # PAT-1990: publish the authenticated identity this middleware already
    # resolved so a route handler writing its own audit row records the same
    # actor the central admin_audit_log row does. Re-deriving it in the
    # handler cannot see Bearer auth (it carries no email) and silently
    # degrades to "unknown" — two trails naming different actors for one
    # action is worse than either trail alone. Additive only: nothing reads
    # this unless it asks for it.
    request.state.actor_email = actor
    request.state.actor_role = role

    destructive = _is_destructive(method, path)
    quarantined = _is_legacy_execution_quarantined(method, path)
    # Every quarantined attempt is material evidence, even if the legacy
    # route was not previously classified as destructive. It must therefore
    # have exactly one terminal audit row for owner, consultant and
    # impersonation paths alike.
    audit_required = destructive or quarantined
    # PAT-799: resource_name defaults to a generic tenant-path lookup; a matched
    # X-Confirm-Resource echo (below) overrides it with the value the operator
    # actually typed, which is already server-validated and more authoritative.
    resource_name = _tenant_name_from_path(path) if destructive else None
    reason = (request.headers.get("X-Audit-Reason") or "").strip() or None if destructive else None

    # ── RBAC: a small set of GETs are owner-only regardless of the
    # consultant-gets-every-GET default (see _OWNER_ONLY_GET) — checked before
    # the write-allow-list below since this can also apply to a GET.
    if role == "consultant" and method == "GET" and _is_owner_only_get(method, path):
        # Audited, unlike an ordinary consultant GET denial: the routes behind
        # this gate are the audit trail itself (admin actions, impersonation
        # sessions, alert history). An unauthorised attempt to READ the audit
        # log is at least as worth recording as a denied write — and if it is
        # not recorded here, it leaves no trace anywhere.
        _audit_write(actor, role, method, path, "denied_rbac")
        return JSONResponse(
            {"error": "Forbidden — this view requires the owner role."},
            status_code=403,
        )

    # ── RBAC: consultants get GETs + an explicit write allow-list; else 403 ──
    if role == "consultant" and method in ("POST", "PUT", "DELETE", "PATCH"):
        if not _consultant_write_allowed(method, path):
            if audit_required:
                _audit_write(actor, role, method, path, "denied_rbac",
                             resource_name=resource_name, reason=reason)
            return JSONResponse(
                {"error": "Forbidden — this action requires the owner role. Ask an operator to perform it."},
                status_code=403,
            )

    # PAT-1481: quarantine only after authentication and RBAC. This prevents a
    # consultant learning that a normally owner-only legacy operation exists;
    # authenticated owners receive the stable non-retryable 410 before a
    # handler can contact an execution-capable upstream or make a local write.
    if quarantined:
        imp = _imp_get(request)
        if imp and not imp.get("write_mode"):
            exempt_suffixes = ("/impersonation/write-mode", "/support-access")
            if not any(path.endswith(s) for s in exempt_suffixes):
                _audit_write(actor, role, method, path, "rejected_403",
                             resource_name=resource_name, reason=reason)
                return JSONResponse(
                    {"error": "Not available in impersonation mode — enable write mode first"},
                    status_code=403,
                )
        _audit_write(actor, role, method, path, "rejected_410",
                     resource_name=resource_name, reason=reason)
        return JSONResponse(_LEGACY_EXECUTION_QUARANTINE_BODY, status_code=410)

    # PAT-2408: refuse a non-canonical tenant id here too, after authentication, RBAC and the
    # legacy quarantine (so those answers do not change).
    # The shared route dependency (`_require_canonical_tenant_id`) is the
    # per-route control, but it runs after this middleware, and the
    # confirmation resolver below issues upstream reads built from the path
    # before any route dependency has run. Same validator, same answer.
    if not _tenant_id_param_ok(request):
        return JSONResponse({"error": "Invalid tenant identifier."}, status_code=400)

    # ── Server-side echo-back confirmation on destructive proxies ──
    confirm = _confirm_rule(method, path)
    if confirm is not None:
        kind, ident = confirm
        provided = (request.headers.get("X-Confirm-Resource") or "").strip()
        if not provided:
            if destructive:
                _audit_write(actor, role, method, path, "confirm_missing",
                             resource_name=resource_name, reason=reason)
            return JSONResponse(
                {"error": f"Confirmation required — resend with header X-Confirm-Resource set to the {kind} name/identifier."},
                status_code=428,
            )
        acceptable = _resolve_confirm_resource(kind, ident, path)
        if provided.lower() not in acceptable:
            if destructive:
                _audit_write(actor, role, method, path, "confirm_mismatch",
                             resource_name=resource_name, reason=reason)
            return JSONResponse(
                {"error": f"Confirmation mismatch — X-Confirm-Resource did not match the {kind} on record."},
                status_code=409,
            )
        resource_name = provided

    if not destructive:
        return await call_next(request)

    # PAT-799: a route handler may stash a richer before/after snapshot on
    # request.state (e.g. billing rates, ring config, App Control lists) —
    # populate defaults from request headers first (X-Audit-Before/-After let a
    # thin proxy route log a diff the server never otherwise computes, e.g. a
    # ring override's old/new value the client already holds) so a handler that
    # sets request.state.audit_before/after itself always wins, since it runs
    # inside call_next, after these defaults are assigned.
    request.state.audit_resource_name = resource_name
    request.state.audit_reason = reason
    request.state.audit_before = (request.headers.get("X-Audit-Before") or None)
    request.state.audit_after = (request.headers.get("X-Audit-After") or None)

    # Write the row BEFORE dispatch (matches the pre-PAT-799 guarantee: a
    # destructive request always leaves a trail even if the handler hangs,
    # crashes, or the request is cancelled mid-flight) — then enrich/correct
    # the SAME row after the handler runs, rather than a second insert.
    audit_id = _audit_write(actor, role, method, path, "in_progress",
                            resource_name=resource_name, reason=reason,
                            before=request.state.audit_before, after=request.state.audit_after)
    try:
        response = await call_next(request)
    except BaseException:
        # BaseException (not just Exception) so an asyncio.CancelledError from
        # a client disconnect/timeout still gets recorded as "error" instead of
        # leaving the row stuck at "in_progress" forever.
        _audit_update(audit_id, "error",
                      resource_name=getattr(request.state, "audit_resource_name", None),
                      reason=getattr(request.state, "audit_reason", None),
                      before=getattr(request.state, "audit_before", None),
                      after=getattr(request.state, "audit_after", None))
        raise
    # A route can return a 4xx/5xx JSONResponse without raising (e.g. a
    # validation failure) — that's not "allowed", the write didn't happen.
    outcome = "allowed" if response.status_code < 400 else f"rejected_{response.status_code}"
    _audit_update(audit_id, outcome,
                  resource_name=getattr(request.state, "audit_resource_name", None),
                  reason=getattr(request.state, "audit_reason", None),
                  before=getattr(request.state, "audit_before", None),
                  after=getattr(request.state, "audit_after", None))
    return response


@app.on_event("startup")
def startup():
    init_db()
    # PAT-917: skip spawning the background daemon threads under pytest. Each
    # `with TestClient(app) as c:` across the suite fires this startup event,
    # and none of these threads are ever joined/stopped — they accumulate for
    # the life of the pytest process. scheduler_loop/check_report_schedules/
    # check_trial_expiry_emails each make a one-shot `http.get` call as soon
    # as their thread is scheduled, which can land during a *different*
    # test's `monkeypatch.setattr(dashboard.http, "get", ...)` window and
    # race-corrupt that test's captured call state (observed intermittently
    # in tests/test_pat852.py). Production (uvicorn, no pytest import) is
    # unaffected.
    if "pytest" in sys.modules:
        return
    # Start scheduler in background
    threading.Thread(target=scheduler_loop, daemon=True).start()
    # PAT-1427: fast path for deploy_drift/maintenance_prod01 — see
    # fast_check_loop's own docstring for why only these two qualify.
    threading.Thread(target=fast_check_loop, daemon=True).start()
    # Public CVE-scan retention sweep
    threading.Thread(target=_public_retention_loop, daemon=True).start()
    # PAT-370: run report schedule check once at startup (catches missed sends
    # on restart) and then daily at 07:00 UTC via scheduler_loop().
    threading.Thread(target=check_report_schedules, daemon=True).start()
    # PAT-670: run trial expiry check once at startup (catches missed sends
    # on restart) and then daily at 08:00 UTC via scheduler_loop().
    threading.Thread(target=check_trial_expiry_emails, daemon=True).start()


# ── Pages ──
@app.get("/")
async def root_redirect():
    return RedirectResponse(url=f"/console/{CONSOLE_BUILD_ID}", status_code=302)


@app.get("/console", response_class=HTMLResponse)
async def console_ui(request: Request):
    return RedirectResponse(url=f"/console/{CONSOLE_BUILD_ID}", status_code=302)


@app.get("/console/{rev}", response_class=HTMLResponse)
async def console_ui_rev(request: Request, rev: str):
    if rev != CONSOLE_BUILD_ID:
        return RedirectResponse(url=f"/console/{CONSOLE_BUILD_ID}", status_code=302)

    imp = _imp_get(request)
    # If we have an expired cookie (couldn't be decoded as valid), check the raw cookie
    # for an expired session so we can log it and show a flash.
    expired_flash = request.query_params.get("imp_expired") == "1"

    # Hydrate tenant_name into the imp dict from the clients table
    if imp:
        with get_db() as db:
            row = db.execute(
                "SELECT company FROM clients WHERE tenant_id=?", (imp["tenant_id"],)
            ).fetchone()
        if row:
            imp["tenant_name"] = row["company"]

    # PAT-696: real environment banner + role indicator context.
    #  - env: the systemd DASHBOARD_ENV ({dev,local}); defaults to "production".
    #  - api_backend: the hostname of the internal API a destructive action hits.
    #  - actor_email / role: the SAME identity minted into the session cookie below
    #    (CF-Access email, or dev@local in a dev/local env), so the sidebar chip
    #    matches the api_bearer_auth middleware's role decision exactly.
    env = DASHBOARD_ENV or "production"
    api_backend = urlparse(PATCHED_API_INTERNAL).hostname or PATCHED_API_INTERNAL
    actor_email = _cf_email(request)
    if not actor_email and _DEV_ENV:
        actor_email = "dev@local"
    role = _role_for_email(actor_email)

    response = templates.TemplateResponse(
        request=request, name="console.html",
        context={
            "impersonation":  imp,
            "imp_expired":    expired_flash,
            "env":            env,
            "api_backend":    api_backend,
            "actor_email":    actor_email,
            "role":           role,
            # PAT-697: single freshness vocabulary, injected so _dhFreshnessBucket
            # reads the same thresholds the server digest uses (no drift possible).
            "device_freshness": DEVICE_FRESHNESS,
            # PAT-967: the console.css / theme.js cache-bust queries are rendered
            # from this so they can never drift from CONSOLE_BUILD_ID. A stale
            # theme.js query previously caused an infinite mobile redirect loop
            # (PAT-966); templating it removes the manual-bump footgun entirely.
            "console_build_id": CONSOLE_BUILD_ID,
        },
    )
    # PAT-695: mint a session cookie from the CF-Access identity. In production, if
    # a verified JWT is absent we do NOT mint (page still loads; API calls 401). In a
    # dev/local env we mint as dev@local so local development works.
    session_email = _cf_email(request)
    if not session_email and _DEV_ENV:
        session_email = "dev@local"
    if session_email:
        expiry = int(time.time()) + SESSION_MAX_AGE
        response.set_cookie(
            SESSION_COOKIE,
            _session_encode(session_email, expiry),
            max_age=SESSION_MAX_AGE,
            httponly=True,
            samesite="lax",
            secure=True,
            path="/",
        )
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"]        = "no-cache"
    return response


# ── PAT-137: Impersonation session management ────────────────────────────────

@app.get("/admin/tenants/{tenant_id}/impersonation/start")
async def imp_start(tenant_id: str, request: Request):
    """Start an impersonation session for the given tenant. Redirect to /console."""
    # Check opt-out
    with get_db() as db:
        row = db.execute(
            "SELECT billing_tier, support_access_opt_out, company FROM clients WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
    if not row:
        return JSONResponse({"error": "Tenant not found"}, status_code=404)
    if row["support_access_opt_out"] and row["billing_tier"] == "full":
        return JSONResponse(
            {"error": "This tenant has disabled support access"},
            status_code=403,
        )

    # PAT-695: no silent support@patched.im fallback — reject if we can't identify
    # the actor (dev/local env mints as dev@local so local dev still works).
    actor_email = _mirror_actor_email(request)
    if not actor_email:
        return JSONResponse(
            {"error": "Unauthorized — no authenticated identity for impersonation"},
            status_code=401,
        )
    session_id = str(uuid.uuid4())
    now        = datetime.now(timezone.utc)
    expires_at = (now + timedelta(seconds=IMP_MAX_AGE)).isoformat()

    payload = {
        "session_id":  session_id,
        "tenant_id":   tenant_id,
        "actor_email": actor_email,
        "started_at":  now.isoformat(),
        "expires_at":  expires_at,
        "write_mode":  False,
    }
    _imp_log(session_id, tenant_id, actor_email, "started", now.isoformat())

    cookie_val = _imp_encode(payload)
    response   = RedirectResponse(url="/console", status_code=302)
    response.set_cookie(
        IMP_COOKIE,
        cookie_val,
        max_age=IMP_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=True,
    )
    return response


@app.get("/admin/impersonation/end")
async def imp_end(request: Request):
    """End the current impersonation session. Redirect to /console."""
    imp = _imp_get(request)
    if imp:
        now = datetime.now(timezone.utc)
        started = datetime.fromisoformat(imp["started_at"])
        dur = int((now - started).total_seconds())
        _imp_log(
            imp["session_id"], imp["tenant_id"], imp["actor_email"],
            "ended", imp["started_at"], now.isoformat(), dur,
        )
    response = RedirectResponse(url="/console", status_code=302)
    response.delete_cookie(IMP_COOKIE, samesite="lax", secure=True)
    return response


@app.post("/admin/impersonation/write-mode")
async def imp_write_mode(request: Request):
    """Enable write mode for the current impersonation session."""
    imp = _imp_get(request)
    if not imp:
        return JSONResponse({"error": "No active impersonation session"}, status_code=400)

    imp["write_mode"] = True
    _imp_log(imp["session_id"], imp["tenant_id"], imp["actor_email"],
             "write_enabled", imp["started_at"])

    cookie_val = _imp_encode(imp)
    response   = JSONResponse({"ok": True})
    # Recalculate remaining max_age from expires_at
    remaining = max(0, int(
        (datetime.fromisoformat(imp["expires_at"]) - datetime.now(timezone.utc)).total_seconds()
    ))
    response.set_cookie(
        IMP_COOKIE, cookie_val, max_age=remaining,
        httponly=True, samesite="lax", secure=True,
    )
    return response


@app.get("/admin/tenants/{tenant_id}/impersonation-log")
def imp_log_get(tenant_id: str):
    """Return the impersonation audit log for a tenant (most recent 50 events)."""
    with get_db() as db:
        rows = db.execute(
            "SELECT id, session_id, actor_email, action, started_at, ended_at, "
            "duration_seconds, created_at "
            "FROM impersonation_audit_log WHERE tenant_id=? "
            "ORDER BY created_at DESC LIMIT 50",
            (tenant_id,),
        ).fetchall()
    return JSONResponse({"entries": [dict(r) for r in rows]})


@app.get("/admin/tenants/{tenant_id}/support-access")
def support_access_get(tenant_id: str):
    """Return support access opt-out setting for a tenant."""
    with get_db() as db:
        row = db.execute(
            "SELECT billing_tier, support_access_opt_out FROM clients WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
    if not row:
        return JSONResponse({"error": "Tenant not found"}, status_code=404)
    return JSONResponse({
        "billing_tier":           row["billing_tier"],
        "support_access_opt_out": bool(row["support_access_opt_out"]),
        "can_opt_out":            row["billing_tier"] == "full",
    })


@app.put("/admin/tenants/{tenant_id}/support-access")
async def support_access_put(tenant_id: str, request: Request):
    """Update support access opt-out for a Tier 3 (full) tenant."""
    data = await request.json()
    opt_out = bool(data.get("opt_out", False))

    with get_db() as db:
        row = db.execute(
            "SELECT billing_tier FROM clients WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        if not row:
            return JSONResponse({"error": "Tenant not found"}, status_code=404)
        if row["billing_tier"] != "full":
            return JSONResponse(
                {"error": "Support access opt-out is only available for Tier 3 (Full) tenants"},
                status_code=400,
            )
        db.execute(
            "UPDATE clients SET support_access_opt_out=? WHERE tenant_id=?",
            (1 if opt_out else 0, tenant_id),
        )
    return JSONResponse({"ok": True, "support_access_opt_out": opt_out})


# ── Admin API proxy — forwards to patched-api-01 internal port over Tailscale ──
# The admin UI HTML uses relative paths (/admin/*); these handlers proxy them
# to the Go service. Auth is CF Access at the edge + Tailscale network restriction
# on the Go side — no additional app-layer token needed here.

@app.get("/admin/tenants")
def proxy_tenants():
    r = http.get(f"{PATCHED_API_INTERNAL}/admin/tenants", timeout=10, verify=_VERIFY_INTERNAL)
    return _proxy_json(r)


@app.post("/admin/tenants")
async def proxy_create_tenant(request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/tenant-rules/{tenant_id}")
def proxy_rules_get(tenant_id: str, request: Request):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenant-rules/{_seg(tenant_id)}",
        params=dict(request.query_params),
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.put("/admin/tenant-rules/{tenant_id}/{rule_id}")
async def proxy_rules_put(tenant_id: str, rule_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.put,
        f"{PATCHED_API_INTERNAL}/admin/tenant-rules/{_seg(tenant_id)}/{_seg(rule_id)}",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.delete("/admin/tenant-rules/{tenant_id}/{rule_id}")
def proxy_rules_delete(tenant_id: str, rule_id: str):
    r = http.delete(
        f"{PATCHED_API_INTERNAL}/admin/tenant-rules/{_seg(tenant_id)}/{_seg(rule_id)}",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return Response(status_code=r.status_code)


@app.get("/admin/tenant-platforms/{tenant_id}")
def proxy_platforms_get(tenant_id: str):
    r = http.get(f"{PATCHED_API_INTERNAL}/admin/tenant-platforms/{_seg(tenant_id)}", timeout=10, verify=_VERIFY_INTERNAL)
    return _proxy_json(r)


@app.put("/admin/tenant-platforms/{tenant_id}")
async def proxy_platforms_put(tenant_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.put,
        f"{PATCHED_API_INTERNAL}/admin/tenant-platforms/{_seg(tenant_id)}",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/metrics/proxy")
def proxy_metrics_prom(request: Request):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/metrics/proxy",
        params=dict(request.query_params),
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-340 console proxy routes (overview, devices, device-detail, findings) ──
# Declare /admin/tenants/overview before /admin/tenants/{tenant_id}/devices
# so the literal segment is never captured by the path parameter.

@app.get("/admin/tenants/overview")
def proxy_tenants_overview():
    r = http.get(f"{PATCHED_API_INTERNAL}/admin/tenants/overview", timeout=10, verify=_VERIFY_INTERNAL)
    if not r.content:
        return JSONResponse({}, status_code=r.status_code)
    try:
        data = r.json()
    except Exception:
        return JSONResponse({"error": "upstream returned non-JSON", "status": r.status_code}, status_code=r.status_code)
    # Merge billing_tier from local SQLite so the Customers page and nav badge
    # reflect the value the admin sets on the Account tab.
    tenants = data.get("tenants") or []
    if tenants:
        conn = _open_db_connection(DB_PATH)
        try:
            ids = [t["id"] for t in tenants]
            rows = conn.execute(
                "SELECT tenant_id, billing_tier FROM clients WHERE tenant_id IN ({})".format(
                    ",".join("?" * len(ids))
                ),
                ids,
            ).fetchall()
        finally:
            conn.close()
        billing = {row["tenant_id"]: row["billing_tier"] for row in rows}
        for t in tenants:
            t["billing_tier"] = billing.get(t["id"], "report")
    return JSONResponse(data, status_code=r.status_code)


@app.get("/admin/tenants/{tenant_id}/devices")
def proxy_tenant_devices(tenant_id: str, request: Request):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/devices",
        params=dict(request.query_params),
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.delete("/admin/tenants/{tenant_id}/devices/{device_id}")
def proxy_device_delete(tenant_id: str, device_id: str):
    """PAT-646: Hard-delete a device from the tenant's estate."""
    r = http.delete(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/devices/{_seg(device_id)}",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/devices/{device_id}")
def proxy_device_detail(device_id: str):
    r = http.get(f"{PATCHED_API_INTERNAL}/admin/devices/{_seg(device_id)}", timeout=10, verify=_VERIFY_INTERNAL)
    return _proxy_json(r)


# ── PAT-462 / PAT-585: Per-device apps + removal proxy routes ─────────────────
# These routes were present in production (PAT-462 PR #69) but dropped during
# PAT-542 re-skin (PR #81). Restored by PAT-585.
# IMPORTANT: declare these before /admin/devices/{device_id} would catch them —
# FastAPI matches literal path segments before greedy captures, but sub-path
# routes require explicit declarations because {device_id} doesn't match '/'.

@app.get("/admin/devices/{device_id}/apps")
def proxy_device_apps(device_id: str):
    r = http.get(f"{PATCHED_API_INTERNAL}/admin/devices/{_seg(device_id)}/apps", timeout=10, verify=_VERIFY_INTERNAL)
    return _proxy_json(r)


@app.get("/admin/devices/{device_id}/removals")
def proxy_device_removals_list(device_id: str):
    r = http.get(f"{PATCHED_API_INTERNAL}/admin/devices/{_seg(device_id)}/removals", timeout=10, verify=_VERIFY_INTERNAL)
    return _proxy_json(r)


@app.post("/admin/devices/{device_id}/removals")
async def proxy_device_removals_create(device_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/devices/{_seg(device_id)}/removals",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.delete("/admin/devices/{device_id}/removals/{task_id}")
def proxy_device_removals_cancel(device_id: str, task_id: str):
    r = http.delete(
        f"{PATCHED_API_INTERNAL}/admin/devices/{_seg(device_id)}/removals/{_seg(task_id)}",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    if not r.content:
        return JSONResponse({}, status_code=r.status_code)
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/findings")
def proxy_tenant_findings(tenant_id: str, request: Request):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/findings",
        params=dict(request.query_params),
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-402: CVE findings proxy (restored PAT-760; dropped by 2a76ffa revert) ─

@app.get("/admin/tenants/{tenant_id}/cve-findings")
def proxy_tenant_cve_findings(tenant_id: str, request: Request):
    try:
        r = http.get(
            f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/cve-findings",
            params=dict(request.query_params),
            timeout=15,
            verify=_VERIFY_INTERNAL,
        )
        return Response(content=r.content, status_code=r.status_code,
                        media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=503)


@app.get("/admin/tenants/{tenant_id}/cve-findings/{cve_id}/devices")
def proxy_tenant_cve_finding_devices(tenant_id: str, cve_id: str, request: Request):
    try:
        r = http.get(
            f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/cve-findings/{_seg(cve_id)}/devices",
            params=dict(request.query_params),
            timeout=15,
            verify=_VERIFY_INTERNAL,
        )
        return Response(content=r.content, status_code=r.status_code,
                        media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=503)


# ── PAT-1607: remediation artefacts + device-lifecycle proxy routes ──────────
# PAT-1549 (go-service, now live): a generated per-device, per-rule
# remediation artefact for an advisory CIS/config finding (a .mobileconfig
# for macOS, an Intune settings-catalogue JSON payload for Windows). CVE
# findings have no rule_id and cannot reach this path (see the Go handler's
# own doc comment) -- the Findings screen only offers "Generate" on CIS rows.
# Owner-only by default: not added to _CONSULTANT_WRITE_ALLOW, matching the
# "owner-only for writes when unsure" default above.
@app.post("/admin/tenants/{tenant_id}/remediation-artefacts")
async def proxy_remediation_artefact_generate(tenant_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/remediation-artefacts",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/remediation-artefacts")
def proxy_remediation_artefacts_list(tenant_id: str, request: Request):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/remediation-artefacts",
        params=dict(request.query_params),
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/remediation-artefacts/{artefact_id}")
def proxy_remediation_artefact_get(tenant_id: str, artefact_id: str):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/remediation-artefacts/{_seg(artefact_id)}",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# PAT-1595 (go-service, now live): per-device lifecycle reconciliation
# (bucket + six-state classification). The Findings footer uses this to
# count devices excluded from every finding count above because they could
# not be inspected in the current window -- never counted as passing.
@app.get("/admin/tenants/{tenant_id}/device-lifecycle")
def proxy_device_lifecycle(tenant_id: str):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/device-lifecycle",
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-1609: device disposition proxy routes ────────────────────────────────
# PAT-1825 (go-service, now live): device_dispositions -- the append-only-
# with-supersede record of what a named customer contact said about a device
# the agent has gone quiet on (root AGENTS.md "absence requires authority":
# an inventory gap alone never closes anything; a disposition is evidence
# someone said something, not a platform-derived fact). See go-service's
# internal/handlers/device_dispositions.go for the request/response shapes.
#
# reported_by / reported_by_role are deliberately NEVER server-stamped, unlike
# created_by/computed_by/cancelled_by on the removal-campaign proxies above --
# they name the CUSTOMER's contact who told the operator what happened, which
# only the operator typing it into the form can know. This mirrors
# removal-campaign's authorized_by rule exactly (see that proxy family's
# module comment). Writes are owner-only by default -- not added to
# _CONSULTANT_WRITE_ALLOW, matching the "owner-only for writes when unsure"
# posture used by every other proxy family above.
@app.get("/admin/tenants/{tenant_id}/device-dispositions")
def proxy_device_dispositions_list(tenant_id: str, request: Request):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/device-dispositions",
        params=dict(request.query_params),
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/device-dispositions")
async def proxy_device_dispositions_create(tenant_id: str, request: Request):
    body, err = await _read_capped_json(request)
    if err:
        return err
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/device-dispositions",
        json=body,
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-1861: finding disposition proxy routes ──────────────────────────────
# PAT-1829's append-only-with-supersede finding disposition contract has two
# exact identity shapes: CIS is device_id + rule_key, while CVE is a tenant
# aggregate cve_id. The platform validates those shapes and all permitted
# statuses. Dashboard only caps/parses the request as an object and forwards it
# unchanged so upstream validation responses retain their actual semantics.
# Writes stay owner-only by default, like device dispositions above.
@app.get("/admin/tenants/{tenant_id}/finding-dispositions")
def proxy_finding_dispositions_list(tenant_id: str, request: Request):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/finding-dispositions",
        params=dict(request.query_params),
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/finding-dispositions")
async def proxy_finding_dispositions_create(tenant_id: str, request: Request):
    body, err = await _read_capped_json(request)
    if err:
        return err
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/finding-dispositions",
        json=body,
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/needs-attention")
def proxy_tenant_needs_attention(tenant_id: str, request: Request):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/needs-attention",
        params=dict(request.query_params),
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-1820: protected software console proxy routes ────────────────────────
# PAT-1823 (go-service, now live): protected_software baseline rows
# (tenant_id IS NULL) merged with per-tenant additions,
# protected_software_overrides (audited per-tenant baseline opt-out) and
# protected_software_changes (changelog). See go-service's
# internal/handlers/protected_software.go for the request/response shapes.
# Writes (add / override-remove) are owner-only by default -- not added to
# _CONSULTANT_WRITE_ALLOW, matching the "owner-only for writes when unsure"
# posture used by the other proxy families above. added_by / removed_by are
# always the server-resolved actor identity, never anything the client sent,
# same as body["actor"] on the catalogue proxies below.
@app.get("/admin/tenants/{tenant_id}/protected-software")
def proxy_protected_software_list(tenant_id: str):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/protected-software",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/protected-software/changes")
def proxy_protected_software_changes(tenant_id: str):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/protected-software/changes",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/protected-software")
async def proxy_protected_software_add(tenant_id: str, request: Request):
    body, err = await _read_capped_json(request)
    if err:
        return err
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)
    # Actor is the audit identity -- always the server-resolved value, never
    # anything the client sent. Assign unconditionally so a client-supplied
    # "added_by" in the body is dropped entirely (not merely defaulted).
    body["added_by"] = _mirror_actor_email(request)
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/protected-software",
        json=body,
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/protected-software/{baseline_id}/override-remove")
async def proxy_protected_software_override_remove(tenant_id: str, baseline_id: str, request: Request):
    body, err = await _read_capped_json(request)
    if err:
        return err
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)
    # Same server-resolved-actor rule as the add route above -- "removed_by"
    # is never taken from the client.
    body["removed_by"] = _mirror_actor_email(request)
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/protected-software/{_seg(baseline_id)}/override-remove",
        json=body,
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-1612: removal campaign console proxy routes ──────────────────────────
# PAT-1598 (go-service, now live): removal_campaigns / removal_campaign_dry_runs
# / removal_campaign_authorizations. See go-service's
# internal/handlers/removal_campaigns.go for the request/response shapes and
# the state machine (draft -> dry_run -> authorized, cancel reachable from
# draft/dry_run only). No agent-facing delivery path exists yet -- this is a
# governance record, not an actuation queue (evidence before actuation, root
# AGENTS.md).
#
# created_by / computed_by are always the server-resolved actor identity
# (the Patched operator working the campaign), same rule as protected-software's
# added_by/removed_by above -- never anything the client sent. authorized_by is
# the one exception: it names the CUSTOMER's authorising contact under their
# own MSA clause, which only the operator typing it into the form can know, so
# it is taken from the request body as free text and forwarded unchanged.
# cancelled_by is server-resolved like created_by; the cancellation reason
# itself is free text from the client (the platform requires it non-blank).
@app.get("/admin/tenants/{tenant_id}/removal-campaigns")
def proxy_removal_campaigns_list(tenant_id: str):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/removal-campaigns",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/removal-campaigns/{campaign_id}")
def proxy_removal_campaign_get(tenant_id: str, campaign_id: str):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/removal-campaigns/{_seg(campaign_id)}",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/removal-campaigns")
async def proxy_removal_campaign_create(tenant_id: str, request: Request):
    body, err = await _read_capped_json(request)
    if err:
        return err
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)
    body["created_by"] = _mirror_actor_email(request)
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/removal-campaigns",
        json=body,
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/removal-campaigns/{campaign_id}/dry-run")
async def proxy_removal_campaign_dry_run(tenant_id: str, campaign_id: str, request: Request):
    body, err = await _read_capped_json(request)
    if err:
        return err
    if not isinstance(body, dict):
        body = {}
    body["computed_by"] = _mirror_actor_email(request)
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/removal-campaigns/{_seg(campaign_id)}/dry-run",
        json=body,
        timeout=20,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/removal-campaigns/{campaign_id}/authorize")
async def proxy_removal_campaign_authorize(tenant_id: str, campaign_id: str, request: Request):
    body, err = await _read_capped_json(request)
    if err:
        return err
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)
    # authorized_by is deliberately NOT overwritten here -- see the module
    # docstring above. Client-side, the confirm modal blocks submission until
    # both authorized_by and authorization_clause are non-empty; the platform
    # enforces the same rule server-side regardless.
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/removal-campaigns/{_seg(campaign_id)}/authorize",
        json=body,
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/removal-campaigns/{campaign_id}/cancel")
async def proxy_removal_campaign_cancel(tenant_id: str, campaign_id: str, request: Request):
    body, err = await _read_capped_json(request)
    if err:
        return err
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)
    body["cancelled_by"] = _mirror_actor_email(request)
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/removal-campaigns/{_seg(campaign_id)}/cancel",
        json=body,
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-561: Browser extensions proxy route ──────────────────────────────────

@app.get("/admin/tenants/{tenant_id}/browser-extensions")
def proxy_browser_extensions(tenant_id: str):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/browser-extensions",
        headers={"Accept": "application/json"},
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-1067: Agent-health proxy route ───────────────────────────────────────
# Surfaces agent_health.degraded (PAT-1065 macOS, PAT-1066 Windows), ingested
# and exposed server-side by PAT-1064. Grouped per device deliberately — the
# operator question is "which of this tenant's devices are silently failing" —
# with a tenant-level `total` alongside. kind/subject/reason are free-form,
# documented-not-enforced vocabulary; this route passes the payload through
# unmodified rather than validating against a fixed list.
@app.get("/admin/tenants/{tenant_id}/agent-health")
def proxy_agent_health(tenant_id: str):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/agent-health",
        headers={"Accept": "application/json"},
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-826: Browser-extension policy store (approve / unapprove) ─────────────
# Pure policy plane — GET/POST/PUT only; no DELETE proxy (the console has no
# removal action, per the ticket). Writes are owner-only via the default RBAC
# posture, matching the app-policy proxies above.

@app.get("/admin/tenants/{tenant_id}/extension-policies/scan")
def proxy_tenant_extension_policies_scan(tenant_id: str):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/extension-policies/scan",
        headers={"Accept": "application/json"},
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/extension-policies")
def proxy_tenant_extension_policies_list(tenant_id: str):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/extension-policies",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/extension-policies")
async def proxy_tenant_extension_policies_create(tenant_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/extension-policies",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.put("/admin/tenants/{tenant_id}/extension-policies/{entry_id}")
async def proxy_tenant_extension_policies_update(tenant_id: str, entry_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.put,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/extension-policies/{_seg(entry_id)}",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-832: Browser-extension REMOVAL request queue ─────────────────────────
# The destructive escalation the policy plane above deliberately excludes: a
# removal has the agent (PAT-829) delete the extension's files on the endpoint.
# Owner-only via the default RBAC posture (not in the consultant write allow-list).
# requested_by is stamped from the authenticated identity server-side and never
# trusted from the client, matching the mirror-approvals audit pattern.

@app.get("/admin/tenants/{tenant_id}/extension-removals")
def proxy_tenant_extension_removals_list(tenant_id: str, request: Request):
    params = {}
    if request.query_params.get("include_history", "").lower() == "true":
        params["include_history"] = "true"
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/extension-removals",
        headers={"Accept": "application/json"},
        params=params,
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/extension-removals")
async def proxy_tenant_extension_removals_create(tenant_id: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON body required"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)
    actor = _mirror_actor_email(request)
    if actor:
        body["requested_by"] = actor
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/extension-removals",
        json=body,
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.delete("/admin/tenants/{tenant_id}/extension-removals/{request_id}")
def proxy_tenant_extension_removals_cancel(tenant_id: str, request_id: str):
    r = http.delete(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/extension-removals/{_seg(request_id)}",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-128: Customer portal access management ───────────────────────────────
# UI on top of the already-existing go-service admin CRUD for `portal_users`
# (PAT-693) — the email -> tenant mapping that actually gates portal access
# (see internal/portalauth/middleware.go). This adds NO new authentication —
# Cloudflare Access still verifies identity.
#
# PAT-2007: `portal_users.role` is `admin` or `viewer` and gates the customer
# portal's own write surface (software approvals). The role lives entirely
# upstream — this dashboard proxy only allowlists the value on the way out
# (exactly `admin`/`viewer`, `400` on anything else, before the upstream call
# is ever made) and passes through whatever the upstream list returns. Older
# upstream rows or an unmigrated go-service may return no `role` at all; the
# console renders that as "—" rather than guessing a value.
#
# Cross-tenant safety: every route below is scoped strictly to the {tenant_id}
# in its own URL path.
#   - The create/invite body always sends that path tenant_id upstream, never
#     a client-supplied one (there isn't one to trust in the first place — we
#     don't even read tenant_id out of the request body). The upstream create
#     endpoint is an upsert-by-email that MOVES an already-mapped email to the
#     given tenant, so _portal_user_current_tenant() below warns (via 409) if
#     the email is currently held by a DIFFERENT tenant, rather than silently
#     reassigning it — the operator must resend with `force: true` to proceed.
#   - The upstream disable endpoint (DELETE /admin/portal-users/{email}) is
#     email-only, not tenant-scoped, so without an extra check an operator on
#     tenant A's tab could disable a tenant B user just by typing/guessing
#     their email in tenant A's Customer Access tab. _portal_user_membership()
#     closes that gap by confirming membership first.
#
# Known limitation (accepted, not fixed here): the membership check + the
# subsequent create/delete are two separate upstream calls, not one atomic
# transaction, so a concurrent write between them could in theory still move
# or re-map the row. Closing that fully requires a tenant-scoped upstream
# endpoint in the go-service (out of scope for this dashboard-only PR) — the
# race window requires two conflicting admin actions on the same email at
# the same moment, which is an acceptable risk for a small internal-operator
# tool relative to the cost of a cross-repo change here.

@app.get("/admin/tenants/{tenant_id}/portal-users")
def proxy_portal_users_list(tenant_id: str):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/portal-users",
        params={"tenant_id": tenant_id},
        headers={"Accept": "application/json"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


def _portal_user_current_tenant(email: str) -> str | None:
    """Best-effort GLOBAL lookup (no tenant filter — the upstream list
    endpoint returns every tenant's rows when tenant_id is omitted): which
    tenant_id (if any) currently holds this email. Used to warn an operator
    before a grant silently moves someone else's tenant's portal access (the
    upstream create endpoint is an upsert-by-email that reassigns tenant_id).
    Returns None on any upstream error OR if the email isn't mapped anywhere
    yet — both cases mean "nothing to warn about", so the caller proceeds."""
    try:
        r = http.get(
            f"{PATCHED_API_INTERNAL}/admin/portal-users",
            timeout=10,
            verify=_VERIFY_INTERNAL,
        )
        if r.status_code != 200:
            return None
        data = r.json()
        target = email.strip().lower()
        for u in (data.get("users") or []):
            if str(u.get("email", "")).strip().lower() == target:
                return u.get("tenant_id")
    except Exception:
        return None
    return None


# PAT-2007: the only two values the upstream role column accepts. Allowlisted
# here (not just left to the upstream 400) so an invalid value is refused
# before any upstream call is made at all, per the same "refuse before you
# proxy" shape the rest of this file uses for body validation.
_PORTAL_USER_ROLES = frozenset({"admin", "viewer"})


@app.post("/admin/tenants/{tenant_id}/portal-users")
async def proxy_portal_users_create(tenant_id: str, request: Request):
    """Grants (or re-enables) portal access for an email under THIS tenant.
    "Invite" here means authorising an email that already has — or will
    separately/manually be given — a Cloudflare Access identity in Patched's
    Entra directory; this call never sends any email itself. Re-POSTing an
    already-mapped email re-enables it and moves it to this tenant (the
    upstream API's documented upsert behaviour) — see the module-level
    comment above for how the 409/`force` conflict flow guards against doing
    that silently.

    PAT-2007: an optional `role` (`admin`/`viewer`) is forwarded to the
    upstream upsert. Omitted, the upstream default applies (a new row is
    `viewer`; an existing row on the same tenant keeps its current role).
    Anything other than exactly `admin` or `viewer` is a 400 here, before the
    upstream is ever called."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON body required"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)
    email = str(body.get("email") or "").strip()
    if not email:
        return JSONResponse({"error": "email is required"}, status_code=400)
    role = body.get("role")
    if role is not None and (not isinstance(role, str) or role not in _PORTAL_USER_ROLES):
        return JSONResponse({"error": "role must be admin or viewer"}, status_code=400)
    force = bool(body.get("force"))
    if not force:
        current_tenant = _portal_user_current_tenant(email)
        if current_tenant and current_tenant != tenant_id:
            return JSONResponse(
                {
                    "error": "already_mapped_elsewhere",
                    "current_tenant_id": current_tenant,
                    "message": "This email already has portal access under a different tenant. "
                               "Granting access here will move it to this tenant, removing it from "
                               "the other one. Resend with force=true to proceed.",
                },
                status_code=409,
            )
    # tenant_id is always the path segment — the client never gets a say.
    upstream_body = {"email": email, "tenant_id": tenant_id}
    if role is not None:
        upstream_body["role"] = role
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/portal-users",
        json=upstream_body,
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


def _portal_user_membership(tenant_id: str, email: str) -> bool | None:
    """Tri-state membership check: True (has a portal_users row under this
    tenant), False (upstream responded fine but the email isn't there), or
    None (the upstream call itself failed — distinct from False so the
    revoke route can tell "not this tenant's user" apart from "couldn't
    check" instead of collapsing both into the same 404)."""
    try:
        r = http.get(
            f"{PATCHED_API_INTERNAL}/admin/portal-users",
            params={"tenant_id": tenant_id},
            timeout=10,
            verify=_VERIFY_INTERNAL,
        )
        if r.status_code != 200:
            return None
        data = r.json()
        users = data.get("users") or []
        target = email.strip().lower()
        return any(str(u.get("email", "")).strip().lower() == target for u in users)
    except Exception:
        return None


@app.delete("/admin/tenants/{tenant_id}/portal-users/{email}")
def proxy_portal_users_revoke(tenant_id: str, email: str):
    membership = _portal_user_membership(tenant_id, email)
    if membership is None:
        return JSONResponse({"error": "could not verify tenant membership upstream"}, status_code=502)
    if membership is False:
        return JSONResponse({"error": "portal user not found for this tenant"}, status_code=404)
    r = http.delete(
        # quote(): the upstream call is a single email-shaped path segment —
        # unescaped '?'/'#'/'&' in an (RFC 5322-legal, if unusual) local-part
        # would otherwise be read as the start of a query string/fragment and
        # silently truncate the path, targeting the wrong (or no) row.
        f"{PATCHED_API_INTERNAL}/admin/portal-users/{_seg(email)}",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-1990: verified portal welcome email ──────────────────────────────────
# Until app-layer auth lands (PAT-1883), a design partner reaches the portal
# through two manual steps: a Customer Access membership above, and their email
# added by hand to the app.patched.im Cloudflare Access Allow policy. Nothing
# told them they were in. This sends that message, but only once the second
# step is independently confirmed against Cloudflare's own API.
#
# Why the Cloudflare precondition is a hard gate and not a warning: One-time
# PIN is the only login method enabled on that Access application, so identity
# IS the exact email string in the policy. If the address is not in an Include
# rule, the person cannot sign in at all, and a welcome email telling them to
# go and sign in is a message that only produces a support conversation. There
# is deliberately no override and no bypass — an operator who believes the
# check is wrong fixes Cloudflare, not this route.
#
# The check fails closed in every direction. A missing credential, an
# unreachable API, a non-200, an unparseable body and a policy list with no
# Allow policy at all are each a refusal, never an assumed pass: an incomplete
# read of the policy is not authority to claim the address is present.

# Role/shared mailboxes. Portal access is personal (the PIN goes to whoever
# holds the mailbox), so a shared address means an unknown and unbounded set
# of people can read a customer's estate posture.
_PORTAL_WELCOME_ROLE_LOCAL_PARTS = frozenset({
    "it", "admin", "support", "info", "helpdesk",
    "security", "office", "accounts", "team", "all",
})

PORTAL_WELCOME_REPLY_TO = "andy@patched.im"
PORTAL_WELCOME_SUBJECT = "Your Patched portal access"

# The address Cloudflare's One-time PIN mail actually arrives from. It is NOT
# guessable and NOT derivable from the API: reading it needs a real test
# sign-in against app.patched.im and a look at the received message, which is
# the manual pre-flight step on PAT-1990 that only Andy can do. Until it is
# set, _render_portal_welcome_email() renders the literal placeholder below
# and the send route refuses — see the guard in api_portal_user_welcome_send.
# Set it in the service env file on patched-prod-01 and restart; no code change.
PORTAL_WELCOME_CLOUDFLARE_SENDER = os.getenv("PORTAL_WELCOME_CLOUDFLARE_SENDER", "").strip()
_PORTAL_WELCOME_SENDER_PLACEHOLDER = "{cloudflare_sender}"

# Copy is approved as drafted on the ticket. Keep the wording here; do not
# paraphrase it at a call site.
_PORTAL_WELCOME_BODY = """Hi {first_name},

Your Patched portal for {tenant_name} is ready. It's where you'll see what's on your estate, what has changed, what's vulnerable and whether your controls are working.

Signing in

1. Go to https://app.patched.im
2. Enter {email}. It has to be exactly this address, because your access is tied to it.
3. You'll be emailed a one-time code. Enter it and you're in.

The code comes from Cloudflare, who secure the portal, not from Patched, so it will arrive from {cloudflare_sender}. If it hasn't turned up within a minute, check your junk or quarantine folder. If your IT team holds external mail, ask them to allow that address.

Codes only last a few minutes, and when your session ends you'll be asked for a new one. That's deliberate.

Your first look

If your devices haven't reported in yet, the portal will look fairly empty. The Install page in the portal has the agent and instructions, and devices appear shortly after they're installed.

Getting help

Questions about the portal or your findings? Reply to this email or write to support@patched.im.

Access is personal to you. Each colleague who needs the portal gets their own named access. Reply with their name and email and it will be set up.

Andy Bridson
Patched"""


def _portal_welcome_role_address(email: str) -> str | None:
    """The denylisted role local-part this address resolves to, or None if it
    is a named individual. Plus-addressing (`support+acme@`) is compared on the
    pre-`+` segment as well as the whole local part, because it reaches the
    same shared mailbox — that only ever adds refusals, never allows one."""
    local = email.split("@", 1)[0].strip().lower()
    candidates = {local}
    if "+" in local:
        candidates.add(local.split("+", 1)[0])
    hits = sorted(candidates & _PORTAL_WELCOME_ROLE_LOCAL_PARTS)
    return hits[0] if hits else None


def _portal_welcome_audit_write(actor_email: str, tenant_id: str, tenant_name: str,
                                 recipient: str, outcome: str, detail: str = "") -> None:
    """Append one row to portal_welcome_audit_log for every welcome attempt —
    refused, dry-run, failed or sent alike. Best-effort: an audit failure must
    never be the reason a legitimate send is lost, so this never raises. It is
    the route-local half of the pair; the central admin_audit_log row is
    written by the destructive-write middleware from _DESTRUCTIVE_RULES."""
    now = datetime.now(timezone.utc).isoformat()
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO portal_welcome_audit_log "
                "(id, ts, actor_email, tenant_id, tenant_name, recipient, outcome, detail) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), now, actor_email or "unknown", tenant_id,
                 tenant_name or "", recipient, outcome, detail or ""),
            )
    except Exception:
        pass


def _portal_welcome_state(tenant_id: str, email: str) -> dict | None:
    """The recorded welcome for this tenant+email, or None if never sent."""
    try:
        with get_db() as db:
            row = db.execute(
                "SELECT welcomed_at, welcomed_by FROM portal_user_welcomes "
                "WHERE tenant_id=? AND email=?",
                (tenant_id, email.strip().lower()),
            ).fetchone()
    except Exception:
        return None
    if not row:
        return None
    return {"welcomed_at": row["welcomed_at"], "welcomed_by": row["welcomed_by"]}


def _portal_user_row(tenant_id: str, email: str) -> tuple[str, dict | None]:
    """Tri-state lookup of a portal_users row under THIS tenant, returning
    ("ok", row) / ("missing", None) / ("error", None). Same reasoning as
    _portal_user_membership above — "the upstream call failed" must stay
    distinguishable from "this tenant has no such user", because only the
    second is a statement about the customer's access."""
    try:
        r = http.get(
            f"{PATCHED_API_INTERNAL}/admin/portal-users",
            params={"tenant_id": tenant_id},
            timeout=10,
            verify=_VERIFY_INTERNAL,
        )
        if r.status_code != 200:
            return "error", None
        data = r.json()
    except Exception:
        return "error", None
    target = email.strip().lower()
    for u in (data.get("users") or []):
        if isinstance(u, dict) and str(u.get("email", "")).strip().lower() == target:
            return "ok", u
    return "missing", None


def _cf_access_email_authorised(email: str) -> tuple[bool | None, str]:
    """Is this exact address (case-insensitively) in an Include rule of an
    Allow policy on the app.patched.im Cloudflare Access application?

    Returns (True, detail) / (False, detail) / (None, detail) where None means
    the check could not be completed. The caller treats None as a refusal —
    an unverified precondition is not a satisfied one.

    Only `email` Include entries count. An `email_domain`, `email_list`,
    `everyone` or any other rule type is deliberately NOT accepted as evidence
    for a specific person: "somebody at this domain may sign in" is not the
    same claim as "this named individual is authorised", and the whole point
    of this gate is the named individual. An exact match in the same policy's
    `exclude` block overrides the include, because Cloudflare evaluates it
    that way and the person would be turned away at the PIN prompt.

    Reuses the PAT-1712/PAT-837 Cloudflare read credential
    (CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_ACCESS_APP_ID)
    that the portal_auth AUD monitor already uses. No new credential.
    """
    required = {
        "CLOUDFLARE_API_TOKEN": CLOUDFLARE_API_TOKEN,
        "CLOUDFLARE_ACCOUNT_ID": CLOUDFLARE_ACCOUNT_ID,
        "CLOUDFLARE_ACCESS_APP_ID": CLOUDFLARE_ACCESS_APP_ID,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        return None, (
            "Cloudflare Access cannot be checked: " + ", ".join(missing) +
            " not set on this host, so the policy membership is unverified."
        )
    try:
        r = http.get(
            f"https://api.cloudflare.com/client/v4/accounts/{CLOUDFLARE_ACCOUNT_ID}"
            f"/access/apps/{CLOUDFLARE_ACCESS_APP_ID}/policies",
            headers={"Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}"},
            timeout=15,
        )
    except Exception as exc:
        return None, f"Cloudflare Access policy lookup failed: {exc}"
    if r.status_code != 200:
        return None, f"Cloudflare Access policy lookup returned {r.status_code}"
    try:
        policies = r.json().get("result")
    except Exception as exc:
        return None, f"Cloudflare Access policy response unparseable: {exc}"
    if not isinstance(policies, list):
        return None, "Cloudflare Access policy response contained no policy list"

    allow_policies = [p for p in policies
                      if isinstance(p, dict) and str(p.get("decision", "")).lower() == "allow"]
    if not allow_policies:
        # Not "the email is absent" — we never got to look at an Allow policy
        # at all, which is a broken read, not a negative result.
        return None, "The app.patched.im Access application has no Allow policy to check"

    target = email.strip().lower()

    def _emails_in(rules) -> set[str]:
        found: set[str] = set()
        for rule in (rules or []):
            if not isinstance(rule, dict):
                continue
            entry = rule.get("email")
            if isinstance(entry, dict) and entry.get("email"):
                found.add(str(entry["email"]).strip().lower())
        return found

    for policy in allow_policies:
        if target not in _emails_in(policy.get("include")):
            continue
        if target in _emails_in(policy.get("exclude")):
            return False, (
                f"{email} appears in an Include rule but is also explicitly excluded "
                f"from the same Allow policy, so Cloudflare will refuse the sign-in."
            )
        name = str(policy.get("name") or policy.get("id") or "").strip()
        detail = f"Exact match in an Include rule of Allow policy {name!r}." if name else \
                 "Exact match in an Include rule of an Allow policy."
        if policy.get("require"):
            # Say what was actually verified rather than implying more. The
            # include match is real; a require block is an extra condition
            # this check did not evaluate.
            detail += (" That policy also carries a Require block, which this check "
                       "does not evaluate.")
        return True, detail

    return False, (
        f"{email} is not in any Include rule of the app.patched.im Access Allow policy. "
        f"Add the exact address in Cloudflare first, then send the welcome. Note that a "
        f"domain-wide or group rule does not count here: One-time PIN ties access to the "
        f"exact address."
    )


def _portal_welcome_html_from_text(text: str) -> str:
    """Render the approved plain-text body as simple HTML.

    Derived from the text rather than maintained as a second copy on purpose:
    the wording is approved once, on the ticket, and two hand-written bodies
    would drift the moment either is edited."""
    parts = []
    for block in text.split("\n\n"):
        escaped = _html.escape(block).replace("\n", "<br>")
        escaped = escaped.replace(
            "https://app.patched.im",
            '<a href="https://app.patched.im">https://app.patched.im</a>',
        )
        parts.append(f"<p>{escaped}</p>")
    return "".join(parts)


def _render_portal_welcome_email(first_name: str, tenant_name: str,
                                  email: str) -> tuple[str, str, str]:
    """(subject, html, text) for the welcome email. Renders the literal
    {cloudflare_sender} placeholder when PORTAL_WELCOME_CLOUDFLARE_SENDER is
    unset — the send route refuses in that state, so an unfilled placeholder
    can never reach a customer."""
    text = _PORTAL_WELCOME_BODY.format(
        first_name=first_name,
        tenant_name=tenant_name,
        email=email,
        cloudflare_sender=PORTAL_WELCOME_CLOUDFLARE_SENDER or _PORTAL_WELCOME_SENDER_PLACEHOLDER,
    )
    return PORTAL_WELCOME_SUBJECT, _portal_welcome_html_from_text(text), text


def _portal_welcome_actor(request: Request) -> str:
    """Who is sending. Prefers the identity api_bearer_auth already
    authenticated (which is the only thing that can name a Bearer caller at
    all) and falls back to the session cookie / verified Access identity the way the
    other route-local audit writers in this file do."""
    return (
        getattr(request.state, "actor_email", "")
        or _session_decode(request.cookies.get(SESSION_COOKIE, ""))
        or _cf_email(request)
        or "unknown"
    )


@app.get("/admin/tenants/{tenant_id}/portal-welcomes")
def api_portal_welcomes_list(tenant_id: str):
    """Local welcome state for every portal user of this tenant, so the
    Customer Access table can show "Welcomed" alongside the upstream
    Active/Disabled status. Kept separate from the portal-users proxy because
    that route is a straight pass-through to the go-service and this state is
    the dashboard's own."""
    try:
        with get_db() as db:
            rows = db.execute(
                "SELECT email, welcomed_at, welcomed_by FROM portal_user_welcomes "
                "WHERE tenant_id=?", (tenant_id,),
            ).fetchall()
    except Exception:
        return JSONResponse({"error": "could not read welcome state"}, status_code=500)
    return JSONResponse({"welcomes": [dict(r) for r in rows]})


@app.get("/admin/tenants/{tenant_id}/portal-users/{email}/welcome-context")
def api_portal_user_welcome_context(tenant_id: str, email: str):
    """Read-only preflight for the confirmation step: everything the operator
    needs to see BEFORE confirming, including the Cloudflare policy verdict.
    Runs the same checks the send route runs, so the modal cannot promise a
    send the send route will then refuse. Changes no state and sends nothing."""
    email = (email or "").strip()
    tenant_name = _tenant_name_from_db(tenant_id)
    context = {
        "tenant_id": tenant_id,
        "tenant_name": tenant_name,
        "recipient": email,
        "reply_to": PORTAL_WELCOME_REPLY_TO,
        "sender": MAIL_SENDER,
        "subject": PORTAL_WELCOME_SUBJECT,
        "welcome": _portal_welcome_state(tenant_id, email),
        "email_delivery": email_delivery_status(),
    }
    if not email or not _EMAIL_RE.match(email):
        context.update(can_send=False, reason="A valid recipient email address is required.")
        return JSONResponse(context)

    role_part = _portal_welcome_role_address(email)
    if role_part:
        context.update(can_send=False, role_address=role_part,
                       reason=f"Named individuals only. {email!r} is a role or shared "
                              f"address ({role_part}@), and portal access is personal.")
        return JSONResponse(context)

    membership, row = _portal_user_row(tenant_id, email)
    if membership == "error":
        context.update(can_send=False, reason="Could not verify this tenant's Customer Access "
                                              "list upstream, so nothing was sent.")
        return JSONResponse(context)
    if membership == "missing":
        context.update(can_send=False, reason="This email has no Customer Access membership "
                                              "under this tenant.")
        return JSONResponse(context)
    if row and row.get("disabled_at"):
        context.update(can_send=False, reason="This portal user is disabled. Re-enable their "
                                              "access before sending a welcome.")
        return JSONResponse(context)

    authorised, detail = _cf_access_email_authorised(email)
    context["cloudflare_detail"] = detail
    context["cloudflare_verified"] = bool(authorised)
    if authorised is not True:
        context.update(can_send=False, reason=detail)
        return JSONResponse(context)

    if not PORTAL_WELCOME_CLOUDFLARE_SENDER:
        context.update(can_send=False, cloudflare_sender_missing=True,
                       reason="The Cloudflare One-time PIN sender address has not been "
                              "recorded yet, so the email would go out with an unfilled "
                              "placeholder. Set PORTAL_WELCOME_CLOUDFLARE_SENDER on "
                              "patched-prod-01 and restart.")
        return JSONResponse(context)

    if context["email_delivery"] == "dry_run":
        context.update(can_send=False, dry_run=True,
                       reason="EMAIL_DRY_RUN is set, so no message would be sent.")
        return JSONResponse(context)

    context["can_send"] = True
    return JSONResponse(context)


@app.post("/admin/tenants/{tenant_id}/portal-users/{email}/welcome")
async def api_portal_user_welcome_send(tenant_id: str, email: str, request: Request):
    """Send (or resend) the portal welcome email. Resend takes this identical
    path: the same Cloudflare check, the same X-Confirm-Resource echo, the same
    audit row. A person's Cloudflare membership can be removed between the
    first send and the second, so a resend that skipped the check would be
    asserting something that was last true days ago.

    PAT-815's lesson is the shape of the tail of this function: welcomed_at /
    welcomed_by are written ONLY after _send_email() has returned True with
    delivery actually live. A refusal, a dry run and a provider failure all
    leave state exactly as it was and return the real reason.
    """
    email = (email or "").strip()
    actor = _portal_welcome_actor(request)
    tenant_name = _tenant_name_from_db(tenant_id)

    def _audit(outcome: str, detail: str = "") -> None:
        _portal_welcome_audit_write(actor, tenant_id, tenant_name, email, outcome, detail)

    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    first_name = str(body.get("first_name") or "").strip()

    if not email or not _EMAIL_RE.match(email):
        _audit("refused", "invalid recipient email address")
        return JSONResponse({"error": "A valid recipient email address is required."},
                            status_code=400)
    if not first_name:
        _audit("refused", "no first name supplied for the greeting")
        return JSONResponse(
            {"error": "The recipient's first name is required. The email opens with it."},
            status_code=400)

    # Named individuals only. Checked first: it is local, definitive and
    # permanent, so there is no reason to spend an upstream call before it.
    role_part = _portal_welcome_role_address(email)
    if role_part:
        reason = (f"Named individuals only. {email} is a role or shared address "
                  f"({role_part}@). Portal access is personal to one person, because the "
                  f"one-time PIN goes to whoever holds the mailbox.")
        _audit("refused", reason)
        return JSONResponse({"error": reason, "role_address": role_part}, status_code=422)

    # Must actually be a Customer Access member of THIS tenant, and enabled.
    membership, row = _portal_user_row(tenant_id, email)
    if membership == "error":
        reason = "Could not verify this tenant's Customer Access list upstream."
        _audit("failed", reason)
        return JSONResponse({"error": reason}, status_code=502)
    if membership == "missing":
        reason = "This email has no Customer Access membership under this tenant."
        _audit("refused", reason)
        return JSONResponse({"error": reason}, status_code=404)
    if row and row.get("disabled_at"):
        reason = ("This portal user is disabled. Re-enable their access before sending "
                  "a welcome.")
        _audit("refused", reason)
        return JSONResponse({"error": reason}, status_code=409)

    # The Cloudflare precondition. No override, no bypass.
    authorised, cf_detail = _cf_access_email_authorised(email)
    if authorised is None:
        _audit("failed", cf_detail)
        return JSONResponse({"error": cf_detail, "cloudflare_verified": False}, status_code=502)
    if authorised is False:
        _audit("refused", cf_detail)
        return JSONResponse({"error": cf_detail, "cloudflare_verified": False}, status_code=412)

    if not PORTAL_WELCOME_CLOUDFLARE_SENDER:
        reason = ("The Cloudflare One-time PIN sender address has not been recorded yet, so "
                  "this email would tell the customer to expect a code from "
                  "'{cloudflare_sender}'. Set PORTAL_WELCOME_CLOUDFLARE_SENDER on "
                  "patched-prod-01 and restart, then send.")
        _audit("refused", reason)
        return JSONResponse({"error": reason, "cloudflare_sender_missing": True},
                            status_code=503)

    # EMAIL_DRY_RUN: refuse rather than pretend. _send_email() returns True
    # under dry run (PAT-1010), so recording welcomed_at off that return would
    # mark a customer welcomed who was never written to.
    if email_delivery_status() == "dry_run":
        reason = "EMAIL_DRY_RUN is set, so no message was sent and nothing was recorded."
        _audit("dry_run", reason)
        return JSONResponse({"error": reason, "dry_run": True}, status_code=503)

    subject, html, text = _render_portal_welcome_email(first_name, tenant_name, email)
    try:
        # Direct call, matching proxy_report_email's shape for the other
        # operator-initiated send in this file.
        ok = _send_email(email, subject, html, text, reply_to=PORTAL_WELCOME_REPLY_TO)
    except Exception as exc:
        _audit("failed", f"mail provider raised: {exc}")
        return JSONResponse({"error": f"Email delivery failed: {exc}"}, status_code=502)

    if not ok:
        reason = ("Email delivery failed at the mail provider. Nothing was recorded, so the "
                  "user is still unwelcomed. Check the Graph mail configuration and retry.")
        _audit("failed", reason)
        return JSONResponse({"error": reason}, status_code=502)

    # Only now — a real send, confirmed ok — does any state change.
    now = datetime.now(timezone.utc).isoformat()
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO portal_user_welcomes (tenant_id, email, welcomed_at, welcomed_by) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(tenant_id, email) DO UPDATE SET welcomed_at=excluded.welcomed_at, "
                "welcomed_by=excluded.welcomed_by",
                (tenant_id, email.strip().lower(), now, actor),
            )
    except Exception as exc:
        # The email really did go out, so this is not a failed send and must
        # not be reported as one. Record the bookkeeping failure loudly
        # instead of silently returning ok.
        _audit("sent_unrecorded", f"email sent but welcome state could not be recorded: {exc}")
        return JSONResponse(
            {"ok": True, "state_recorded": False,
             "warning": "The welcome email was sent, but the Welcomed status could not be "
                        "recorded. Do not resend without checking with the recipient."},
            status_code=200)

    _audit("sent", cf_detail)
    return JSONResponse({"ok": True, "state_recorded": True,
                         "welcomed_at": now, "welcomed_by": actor})


# ── Authoritative software-metering proxy routes ─────────────────────────────

@app.get("/admin/tenants/{tenant_id}/metering")
def proxy_metering_fleet(tenant_id: str, request: Request):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/metering",
        headers={"Accept": "application/json"},
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/metering/{app_name}")
def proxy_metering_breakdown(tenant_id: str, app_name: str):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/metering/{_seg(app_name)}",
        headers={"Accept": "application/json"},
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── Console proxy routes (tenant lifecycle, account, apps, billing, reports) ──
# NOTE: declare all literal-path routes (/revoked, /overview already above)
# before parameterised {tenant_id} routes in the same HTTP method to avoid
# FastAPI matching literals against the path-parameter capture.

@app.post("/admin/tenants/{tenant_id}/enrollment-tokens")
async def proxy_enrollment_tokens(tenant_id: str, request: Request):
    params = dict(request.query_params)
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/v1/admin/tenants/{_seg(tenant_id)}/enrollment-tokens",
        params=params,
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


def _proxy_json(r):
    """Return a JSONResponse from a requests.Response, safe against non-JSON or empty upstream bodies."""
    if not r.content:
        return JSONResponse({}, status_code=r.status_code)
    try:
        data = r.json()
        return JSONResponse(data, status_code=r.status_code)
    except Exception:
        body = r.text if hasattr(r, "text") else r.content.decode("utf-8", errors="replace")
        return JSONResponse(
            {"error": "upstream returned non-JSON", "status": r.status_code, "body": body},
            status_code=r.status_code,
        )


@app.get("/admin/tenants/revoked")
def proxy_tenants_revoked():
    r = http.get(f"{PATCHED_API_INTERNAL}/admin/tenants/revoked", timeout=10, verify=_VERIFY_INTERNAL)
    return _proxy_json(r)


@app.get("/admin/tenants/trials")
def proxy_tenants_trials(request: Request):
    """PAT-670: proxy trial list to the platform internal API."""
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/trials",
        params=dict(request.query_params),
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/trial-notify")
def proxy_trial_notify(tenant_id: str):
    """PAT-670: mark upgrade email sent for a trial tenant."""
    r = http.post(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/trial-notify",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/service-exceptions/proxy")
def proxy_service_exceptions():
    """Fixed read under existing admin session/Bearer RBAC. No request selectors."""
    import service_exceptions
    from shared import readonly_db_connections

    headers = {"Cache-Control": "no-store"}
    try:
        # Do not follow redirects or forward caller query parameters/credentials.
        with http.get(f"{PATCHED_API_INTERNAL}/admin/service-exceptions", timeout=5,
                      verify=_VERIFY_INTERNAL, allow_redirects=False, stream=True) as response:
            if response.status_code != 200:
                raise service_exceptions.InvalidEvidence("Source unavailable")
            payload = bytearray()
            deadline = time.monotonic() + 6
            for chunk in response.iter_content(chunk_size=16384):
                payload.extend(chunk)
                if len(payload) > 524288 or time.monotonic() > deadline:
                    raise service_exceptions.InvalidEvidence("Source response exceeded bounds")
            data, invalid = service_exceptions.project(json.loads(payload), datetime.now(timezone.utc))
    except (requests.RequestException, ValueError, TypeError):
        return JSONResponse({"error": "Service exception source unavailable or invalid", "degraded": True},
                            status_code=502, headers=headers)
    with readonly_db_connections():
        data = service_exceptions.join_local(data, invalid, lambda: _open_db_connection(DB_PATH),
                                             _check_status_freshness, datetime.now(timezone.utc))
    return JSONResponse(data, headers=headers)


@app.get("/admin/health/proxy")
def proxy_health():
    r = http.get(f"{PATCHED_API_INTERNAL}/admin/health", timeout=15, verify=_VERIFY_INTERNAL)
    if not r.content:
        return JSONResponse({}, status_code=r.status_code)
    try:
        data = r.json()
    except Exception:
        return JSONResponse({"error": "upstream returned non-JSON", "status": r.status_code}, status_code=r.status_code)
    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free  = st.f_bfree  * st.f_frsize
        avail = st.f_bavail * st.f_frsize
        used  = total - free
        to_gb = lambda b: round(b / 1e9, 1)
        used_pct = round(used / total * 100, 1) if total else 0.0
        prod_disk = {"host": "prod-01", "path": "/", "total_gb": to_gb(total), "used_gb": to_gb(used), "free_gb": to_gb(avail), "used_pct": used_pct}
        sh = data.get("service_health", {})
        for d in sh.get("disk_usage", []):
            d["host"] = "api-01"
        sh.setdefault("disk_usage", []).insert(0, prod_disk)
        data["service_health"] = sh
    except Exception:
        pass
    try:
        ar = http.get(f"{PATCHED_API_INTERNAL}/admin/automations", timeout=10, verify=_VERIFY_INTERNAL)
        jobs = ar.json().get("jobs", []) if ar.content else []
        from datetime import datetime, timezone, timedelta
        alerts = []
        for j in jobs:
            # Persisted legacy execution records remain available as history,
            # but must not make the live service-health surface claim that a
            # retired/quarantined job is failing or lagging.
            if j.get("job_name") in _QUARANTINED_AUTOMATIONS:
                continue
            status = j.get("last_status")
            last_run = j.get("last_run")
            # PAT-697: this is job/ingest lag, NOT device staleness — a job whose
            # last run is >26h old is "lagging", not "stale". Reserve "stale" for
            # device freshness only.
            lagging = False
            if last_run:
                age_h = (datetime.now(timezone.utc) - datetime.fromisoformat(last_run.replace("Z", "+00:00"))).total_seconds() / 3600
                lagging = age_h > 26
            if status and status != "success":
                alerts.append({"job_name": j.get("job_name"), "last_status": status, "last_run": last_run, "reason": "failed"})
            elif lagging or not last_run:
                alerts.append({"job_name": j.get("job_name"), "last_status": status, "last_run": last_run, "reason": "lagging"})
        data.setdefault("service_health", {})["automation_alerts"] = alerts
    except Exception:
        pass
    # PAT-1369: forward a genuine upstream failure (including the synthetic
    # "unreachable" response _ApiSession returns on ConnectionError/Timeout)
    # as a real error status instead of always answering 200, since a merged
    # 200 here would be indistinguishable from a healthy check.
    return JSONResponse(data, status_code=r.status_code if r.status_code >= 500 else 200)


_BILLING_TIERS = {"report", "patch", "full"}

# PAT-1100: v3 banded retainer pricing (2026-08-02 commercial re-ruling).
# "report" is deliberately NOT one of these — it's a legitimate operational
# state (a tenant can be run in report-only mode) but has no price-list entry
# any more, so it is intentionally absent from `bands`/`tail_rate_per_endpoint`
# rather than being priced at zero explicitly. _compute_monthly() below
# returns 0.0 for any tier not present here, which covers "report" without a
# special case.
_BILLING_BAND_TIERS = {"patch", "full"}

# Each tier's bands must stay sorted ascending by max_endpoints (enforced by
# _validate_billing_bands()). A band covers every endpoint count up to and
# including its max_endpoints, with the previous band's max_endpoints (or 0)
# as the exclusive lower bound — i.e. band N covers (bands[N-1].max, band.max].
_BILLING_BAND_DEFAULTS = {
    "patch": [
        {"max_endpoints": 25,  "monthly": 500.0,  "advisory_hours": 2},
        {"max_endpoints": 60,  "monthly": 750.0,  "advisory_hours": 3},
        {"max_endpoints": 120, "monthly": 1200.0, "advisory_hours": 4},
        {"max_endpoints": 250, "monthly": 2000.0, "advisory_hours": 6},
    ],
    "full": [
        {"max_endpoints": 60,  "monthly": 1500.0, "advisory_hours": 4},
        {"max_endpoints": 120, "monthly": 2600.0, "advisory_hours": 6},
        {"max_endpoints": 250, "monthly": 4200.0, "advisory_hours": 10},
    ],
}
# Endpoints beyond the top band (>250) are billed at a flat per-endpoint tail
# rate applied to the FULL endpoint count (not just the excess over 250) —
# the simplest, least-surprising convention consistent with "tail rate
# £N/endpoint" as written in the ticket. Advisory hours have no defined
# convention above the last band, so the balance endpoint treats tail-territory
# allowance as 0 rather than inventing a number.
_BILLING_TAIL_RATE_DEFAULTS = {"patch": 8.0, "full": 16.0}
_BILLING_ANNUAL_DISCOUNT_DEFAULT = 0.92  # annual prepay = monthly * this (BELOW monthly, not above)
_BILLING_RATES_KEY = "billing_rates"


def _default_billing_rates() -> dict:
    """A fresh (unaliased) copy of the v3 rate defaults."""
    return {
        "bands": {tier: [dict(b) for b in bands] for tier, bands in _BILLING_BAND_DEFAULTS.items()},
        "tail_rate_per_endpoint": dict(_BILLING_TAIL_RATE_DEFAULTS),
        "annual_discount": _BILLING_ANNUAL_DISCOUNT_DEFAULT,
    }


def _validate_billing_bands(raw) -> tuple[list | None, str | None]:
    """Validate + normalise a tier's band list. Bands must have strictly
    increasing positive-integer max_endpoints and non-negative monthly/
    advisory_hours. Returns (normalized_bands, None) or (None, error_message)."""
    if not isinstance(raw, list) or not raw:
        return None, "bands must be a non-empty list"
    out = []
    prev_max = 0
    for b in raw:
        if not isinstance(b, dict):
            return None, "each band must be an object"
        try:
            max_ep = int(b["max_endpoints"])
            monthly = float(b["monthly"])
            advisory_hours = float(b.get("advisory_hours", 0))
        except (KeyError, TypeError, ValueError):
            return None, "each band requires numeric max_endpoints, monthly, advisory_hours"
        if max_ep <= prev_max:
            return None, "band max_endpoints must be positive and strictly increasing"
        if monthly < 0 or advisory_hours < 0:
            return None, "band monthly and advisory_hours must be >= 0"
        out.append({"max_endpoints": max_ep, "monthly": monthly, "advisory_hours": advisory_hours})
        prev_max = max_ep
    return out, None


def _billing_rates() -> dict:
    """Load the v3 banded rate card from `kv`, falling back to defaults on any
    parse/shape failure and merging in whatever validates field-by-field
    (same resilience contract the old flat-rate loader had).

    PAT-1100: a `kv` row stored under the OLD v2 flat shape (top-level
    `report`/`patch`/`full`/`app_control`/`floor`/`monthly_uplift` scalars) is
    structurally incompatible with the new nested-bands shape — there is no
    sane numeric translation from a flat per-device rate to a banded model, so
    that case falls back cleanly to the v3 defaults rather than attempting to
    auto-convert the old numbers. Detected by the presence of the old `floor`
    key or the absence of the new `bands` key.
    """
    rates = _default_billing_rates()
    with get_db() as db:
        row = db.execute("SELECT value FROM kv WHERE key=?", (_BILLING_RATES_KEY,)).fetchone()
    if not row:
        return rates
    try:
        stored = json.loads(row["value"])
    except Exception as e:
        print(f"[billing] failed to parse stored rates: {e}")
        return rates
    if not isinstance(stored, dict) or "floor" in stored or "bands" not in stored:
        print("[billing] stored rates are pre-v3 (flat) shape or invalid; using v3 defaults")
        return rates

    bands = stored.get("bands")
    if isinstance(bands, dict):
        for tier in _BILLING_BAND_TIERS:
            if tier in bands:
                validated, err = _validate_billing_bands(bands[tier])
                if not err:
                    rates["bands"][tier] = validated

    tail = stored.get("tail_rate_per_endpoint")
    if isinstance(tail, dict):
        for tier in _BILLING_BAND_TIERS:
            if tier in tail:
                try:
                    v = float(tail[tier])
                    if v >= 0:
                        rates["tail_rate_per_endpoint"][tier] = v
                except (TypeError, ValueError):
                    pass

    if "annual_discount" in stored:
        try:
            v = float(stored["annual_discount"])
            # Defense in depth alongside the PATCH-time bound: never load a
            # stored value that would make annual prepay MORE expensive than
            # monthly (the v2 monthly_uplift defect this ticket fixes).
            if 0 < v <= 1:
                rates["annual_discount"] = v
        except (TypeError, ValueError):
            pass

    return rates


def _billing_band_for(endpoints: int, bands: list) -> dict | None:
    """The first band (ascending by max_endpoints) that covers `endpoints`,
    or None if `endpoints` exceeds every banded tier (tail territory)."""
    for band in bands:
        if endpoints <= band["max_endpoints"]:
            return band
    return None


def _compute_monthly(endpoints: int, billing_tier: str, frequency: str, rates: dict) -> float:
    """v3 banded retainer calc. `billing_tier` values with no price-list entry
    (today: only "report") return 0.0 rather than erroring — report-only is a
    legitimate operational state, just not a sellable recurring tier."""
    bands_by_tier = rates.get("bands", {})
    if billing_tier not in bands_by_tier:
        headline = 0.0
    else:
        band = _billing_band_for(endpoints, bands_by_tier[billing_tier])
        if band is not None:
            headline = float(band["monthly"])
        else:
            tail_rate = float(rates.get("tail_rate_per_endpoint", {}).get(billing_tier, 0.0))
            headline = endpoints * tail_rate
    # Annual prepay is 8% BELOW the monthly headline (annual_discount < 1),
    # not an uplift above it — the old `monthly_uplift` direction was the
    # defect this ticket exists to fix. The stored/computed "monthly" figure
    # IS the headline; only the annual path multiplies by annual_discount.
    if frequency == "annual":
        headline = headline * float(rates.get("annual_discount", 1.0))
    return round(headline, 2)


def _billing_band_ordinal(endpoints: int, bands: list) -> int:
    """0-based position of `endpoints` in the ascending `bands` list — the
    same band _billing_band_for() would return, expressed as a comparable
    integer instead of a dict. `len(bands)` means tail territory (beyond the
    top band). Two ordinals from the SAME bands list can be compared
    directly to tell whether one endpoint count sits in a strictly higher or
    lower band than another — this is what _tenant_band_drift() uses to
    classify drift direction without duplicating the band-walk logic."""
    for i, band in enumerate(bands):
        if endpoints <= band["max_endpoints"]:
            return i
    return len(bands)


def _billing_band_edges(bands: list, ordinal: int) -> tuple[int, int | None]:
    """(lower, upper) endpoint edges of the band at `ordinal` in `bands`.
    `lower` is the previous band's max_endpoints (0 if `ordinal` is the
    first band) — the band covers (lower, upper]. `upper` is None for tail
    territory (ordinal == len(bands)), meaning no ceiling exists."""
    lower = bands[ordinal - 1]["max_endpoints"] if ordinal > 0 else 0
    upper = bands[ordinal]["max_endpoints"] if ordinal < len(bands) else None
    return lower, upper


def _tenant_band_drift(tenant_id: str, current_endpoints: int, contract: dict, rates: dict) -> dict:
    """Live band-drift computation for one tenant with an active contract.
    Advisory only — nothing here writes to billing_contracts or any other
    billed figure; see the PAT-1103 ruling recorded on billing_drift_checks'
    migration comment. Shared by GET /admin/billing/drift, GET
    /admin/billing/renewals, and the monthly scheduler tick
    (_run_band_drift_check_tick) so there is exactly one implementation of
    the drift-classification math, not one per caller.

    `current_endpoints` must come from the same source api_billing_summary/
    api_billing_renewals already use (_billing_tenant_overview() or
    _tenant_device_count()) — this function does not fetch endpoints itself,
    so it can't accidentally introduce a second counting path.

    Both the contract's signature endpoint count and the tenant's current
    endpoint count are re-evaluated against bands ordinal positions in the
    SAME (current) band table for `contract["tier_at_signature"]` — a
    contract only stores the endpoint count and monthly figure at signature,
    not which literal band edge it fell under, so "which band was this
    signed at" has to be re-derived every time, using whatever the band
    table looks like today (PAT-1101's band-table-changed-mid-term case
    applies here too).

    direction:
      'above' — current_endpoints now falls in a strictly HIGHER band than
                the one the contract was signed at (i.e. exceeds that band's
                own max_endpoints).
      'below' — current_endpoints now falls in a strictly LOWER band.
      'none'  — current_endpoints is still within the signed-at band.

    headroom_to_next_edge — endpoints of room before the tenant crosses
    another band boundary, semantics depending on `direction`:
      'above' — room left to grow before crossing UP out of the CURRENT
                band (None if already in tail territory — no ceiling).
      'below' — room left to shrink before crossing DOWN out of the current
                band into a still-lower one.
      'none'  — not currently drifting, so there's no single "direction of
                drift" to measure against; report the nearest edge (the
                smaller of the room-to-grow and room-to-shrink) as a general
                "how much slack is left" figure. This is a judgment call —
                there's no ticket-specified semantic for the non-drifting
                case, and "nearest edge" is the most useful single number to
                show next to a badge that isn't otherwise alarming anyone.

    band_would_produce — what _compute_monthly() would return right now for
    this tenant's live endpoints, at the contract's own tier/frequency (the
    same value api_billing_renewals's current_band_monthly/current_monthly
    already computed before this ticket — reused, not duplicated).
    """
    tier = contract["tier_at_signature"]
    frequency = contract["billing_frequency"]
    bands = rates.get("bands", {}).get(tier) or []

    signature_endpoints = contract["band_endpoints_at_signature"]
    contracted_band = _billing_band_for(signature_endpoints, bands)
    current_band = _billing_band_for(current_endpoints, bands)

    contracted_ordinal = _billing_band_ordinal(signature_endpoints, bands)
    current_ordinal = _billing_band_ordinal(current_endpoints, bands)

    if current_ordinal > contracted_ordinal:
        direction = "above"
    elif current_ordinal < contracted_ordinal:
        direction = "below"
    else:
        direction = "none"

    lower, upper = _billing_band_edges(bands, current_ordinal)
    if direction == "above":
        headroom = (upper - current_endpoints) if upper is not None else None
    elif direction == "below":
        headroom = current_endpoints - lower
    else:
        up_room = (upper - current_endpoints) if upper is not None else None
        down_room = current_endpoints - lower
        headroom = down_room if up_room is None else min(up_room, down_room)

    band_would_produce = _compute_monthly(current_endpoints, tier, frequency, rates)

    return {
        "tenant_id": tenant_id,
        "contracted_band_max": contracted_band["max_endpoints"] if contracted_band else None,
        "current_endpoints": current_endpoints,
        "current_band": current_band,
        "direction": direction,
        "headroom_to_next_edge": headroom,
        "band_would_produce": band_would_produce,
    }


def _consecutive_drift_months(tenant_id: str, live_direction: str) -> int:
    """How many of the most recently RECORDED months in billing_drift_checks
    match `live_direction`, counting backward from the most recent row and
    stopping at the first mismatch (or empty history).

    Deliberately keyed off `live_direction` (computed fresh by
    _tenant_band_drift right now) rather than trusting the table's own most
    recent row to already reflect today: the current calendar month's row
    may not exist yet if the scheduler tick hasn't run this hour. A tenant
    recorded 'above' for 3 consecutive prior months whose LIVE direction has
    now genuinely changed to 'none' must show a streak that reflects today
    (0, since the most recent recorded row is 'above' and doesn't match
    'none'), never the historical 3-month 'above' streak — that historical
    max is a different, not-yet-built metric."""
    with get_db() as db:
        rows = db.execute(
            "SELECT direction FROM billing_drift_checks WHERE tenant_id=? ORDER BY checked_month DESC",
            (tenant_id,),
        ).fetchall()
    streak = 0
    for row in rows:
        if row["direction"] != live_direction:
            break
        streak += 1
    return streak


def _log_report_delivery(tenant_id: str, report_type: str, tenant_name: str = "",
                          recipient: str = None, status: str = "generated",
                          subject_scope: str = "tenant", subject_id: str | None = None) -> str:
    if subject_scope not in {"tenant", "device"}:
        raise ValueError("report delivery subject_scope must be tenant or device")
    if not subject_id:
        subject_id = tenant_id
    if not subject_id:
        raise ValueError("report delivery subject_id is required")
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    row_id  = str(uuid.uuid4())
    with get_db() as db:
        db.execute(
            "INSERT INTO report_deliveries "
            "(id, tenant_id, tenant_name, report_type, subject_scope, subject_id, recipient, generated_at, sent_at, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (row_id, tenant_id, tenant_name, report_type, subject_scope, subject_id, recipient,
             now_iso, now_iso if recipient else None,
             "sent" if recipient else "generated"),
        )
    return row_id


def _tenant_name_from_db(tenant_id: str) -> str:
    with get_db() as db:
        row = db.execute("SELECT company FROM clients WHERE tenant_id=?", (tenant_id,)).fetchone()
    return row["company"] if row else tenant_id


@app.get("/admin/reports")
def admin_reports_list():
    with get_db() as db:
        rows = db.execute(
            "SELECT id, tenant_id, tenant_name, report_type, subject_scope, subject_id, recipient, "
            "generated_at, sent_at, status "
            "FROM report_deliveries ORDER BY generated_at DESC LIMIT 200"
        ).fetchall()
    return JSONResponse([dict(r) for r in rows])


@app.get("/admin/billing/rates")
def api_billing_rates_get():
    return JSONResponse(_billing_rates())


def _billing_tenant_overview() -> tuple[dict, dict]:
    """Live device counts + display names for every tenant, via one call to
    the platform's tenant overview. Shared by api_billing_summary (PAT-1100)
    and api_billing_renewals (PAT-1101) — the established pattern for
    getting a device count is this call or `_tenant_device_count()`; don't
    invent a third way."""
    device_counts = {}
    tenant_names = {}
    try:
        r = http.get(f"{PATCHED_API_INTERNAL}/admin/tenants/overview", timeout=15, verify=_VERIFY_INTERNAL)
        if r.status_code == 200:
            for t in (r.json().get("tenants") or []):
                if t.get("id"):
                    tenant_id = t["id"]
                    device_counts[tenant_id] = int(t.get("device_count") or 0)
                    display_name = (
                        t.get("name")
                        or t.get("company")
                        or t.get("display_name")
                        or t.get("tenant_name")
                    )
                    if display_name:
                        tenant_names[tenant_id] = display_name
    except Exception as e:
        print(f"[billing] overview fetch failed: {e}")
    return device_counts, tenant_names


@app.get("/admin/billing/summary")
def api_billing_summary():
    rates = _billing_rates()
    device_counts, tenant_names = _billing_tenant_overview()
    with get_db() as db:
        clients = db.execute(
            "SELECT tenant_id, company, billing_tier, app_control_enabled, billing_frequency, onboarding_state "
            "FROM clients"
        ).fetchall()
        tenant_ids = [dict(c)["tenant_id"] for c in clients]
        active_contracts = {}
        if tenant_ids:
            placeholders = ",".join("?" for _ in tenant_ids)
            contract_rows = db.execute(
                f"SELECT * FROM billing_contracts WHERE status='active' AND tenant_id IN ({placeholders})",
                tenant_ids,
            ).fetchall()
            active_contracts = {cr["tenant_id"]: dict(cr) for cr in contract_rows}
    rows = []
    total = 0.0
    for c in clients:
        c = dict(c)
        tid = c["tenant_id"]
        if tid not in device_counts:
            continue
        endpoints = device_counts[tid]
        billing_tier = c.get("billing_tier") or "report"
        # PAT-1100: Application Control is now included in Full Endpoint
        # Management (PAT-1038) rather than billed separately, so this is no
        # longer passed into _compute_monthly(). Still surfaced on the row as
        # an informational flag — it just isn't a charge any more.
        app_control = bool(c.get("app_control_enabled"))
        frequency = c.get("billing_frequency") or "annual"
        contract = active_contracts.get(tid)
        if contract is not None:
            # PAT-1101: a signed contract is the source of truth for what a
            # tenant is billed. monthly_at_signature was frozen at signature
            # time from whatever the band table produced THEN — it must
            # never be recomputed from the CURRENT band table on every read,
            # which is exactly the live-recalculation defect this ticket
            # closes. Use the frequency/discount as recorded on the
            # contract too, not re-derived from the current rate config.
            # Only a tenant with NO active contract (pre-sale/quoting) falls
            # back to the live _compute_monthly() band lookup below.
            monthly = contract["monthly_at_signature"]
            frequency = contract["billing_frequency"]
        else:
            monthly = _compute_monthly(endpoints, billing_tier, frequency, rates)
        total += monthly
        rows.append({
            "tenant_id": tid, "company": tenant_names.get(tid) or c.get("company") or tid,
            "billing_tier": billing_tier, "endpoints": endpoints,
            "app_control_enabled": app_control, "frequency": frequency, "monthly": monthly,
            "has_contract": contract is not None,
        })
    rows.sort(key=lambda x: x["monthly"], reverse=True)
    return JSONResponse({"rates": rates, "rows": rows, "total": round(total, 2)})


@app.get("/admin/reports/{report_reference}/{subject_id}")
def proxy_report_generic(report_reference: str, subject_id: str):
    """Proxy a registry-defined PDF by report type or legacy path reference.

    Existing browser links used the first path segment (for example `cve`),
    while the reports workspace now passes the stable platform report type.
    Both forms resolve from the live registry. Device report definitions get a
    device substitution; tenant definitions get a tenant substitution.
    """
    try:
        definition = _report_definition_for_reference(report_reference)
    except ReportCatalogueUnavailable as exc:
        return JSONResponse({"error": f"report catalogue unavailable: {exc}", "degraded": True}, status_code=503)
    if not definition:
        return JSONResponse({"error": f"unknown report type: {report_reference!r}"}, status_code=404)
    if definition["subject_scope"] == "tenant":
        # PAT-2408: a tenant subject is a tenant id, so same canonical-UUID rule
        # as every `{tenant_id}` route (the parameter here is `subject_id`).
        if not _is_canonical_uuid(subject_id):
            return JSONResponse({"error": "Invalid tenant identifier."}, status_code=400)
        platform_path = _report_platform_path(definition, tenant_id=subject_id)
    else:
        platform_path = _report_platform_path(definition, device_id=subject_id)
    try:
        r = http.get(
            f"{PATCHED_API_INTERNAL}{platform_path}",
            timeout=30, verify=_VERIFY_INTERNAL,
        )
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=502)
    if r.status_code != 200:
        return Response(content=r.content, status_code=r.status_code)
    if definition["subject_scope"] == "tenant":
        _log_report_delivery(
            subject_id, definition["type"], tenant_name=_tenant_name_from_db(subject_id),
            subject_scope="tenant", subject_id=subject_id,
        )
    else:
        # The dashboard has no trustworthy tenant join for a generic device
        # report. Keep the legacy tenant grouping blank rather than inventing
        # one, and audit the actual device subject explicitly.
        _log_report_delivery(
            "", definition["type"], subject_scope="device", subject_id=subject_id,
        )
    return Response(
        content=r.content, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{definition["type"]}-{subject_id}.pdf"'},
    )


@app.get("/admin/tenants/{tenant_id}/account")
def admin_account_get(tenant_id: str):
    with get_db() as db:
        row = db.execute(
            "SELECT company, company_phone, "
            "primary_contact_name, primary_contact_email, "
            "technical_contact_name, technical_contact_email, "
            "billing_contact_name, billing_contact_email, "
            "onboarding_state, contract_renewal_date, contract_notes, account_notes, "
            "agent_config_tier, billing_tier, app_control_enabled, billing_frequency "
            "FROM clients WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
    if not row:
        return JSONResponse({"error": "tenant not found in clients"}, status_code=404)
    d = dict(row)
    d["app_control_enabled"] = bool(d.get("app_control_enabled"))
    # Derive subscription_tier from billing_tier as fallback (no per-tenant GET route in go-service).
    # billing_tier keeps its own report/patch/full pricing vocabulary (PAT-1599
    # didn't touch it — see _SUB_TIER_TO_BILLING); "patch" maps to "managed"
    # here because the patch billing band already implies actuation, which is
    # what separates "managed" from read-only "assurance" under PAT-1599.
    _bt_to_sub = {"report": "assurance", "patch": "managed", "full": "managed"}
    d["subscription_tier"] = _bt_to_sub.get(d.get("billing_tier") or "report", "assurance")
    return JSONResponse(d)


@app.get("/admin/tenants/{tenant_id}/stale-digest-config")
def api_stale_digest_config_get(tenant_id: str):
    with get_db() as db:
        row = db.execute(
            "SELECT stale_digest_enabled, stale_digest_threshold_days, "
            "stale_digest_recipient, last_stale_digest_sent_at, "
            "stale_digest_day_of_week, stale_digest_hour FROM clients WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
    if not row:
        return JSONResponse({"error": "tenant not found in clients"}, status_code=404)
    d = dict(row)
    d["default_threshold_days"] = STALE_THRESHOLD_DEFAULT_DAYS
    return JSONResponse(d)


@app.get("/admin/tenants/{tenant_id}/apps")
def proxy_tenant_apps(tenant_id: str, request: Request):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/apps",
        params=dict(request.query_params),
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/app-control")
def proxy_tenant_app_control_get(tenant_id: str):
    r = http.get(f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/app-control", timeout=10, verify=_VERIFY_INTERNAL)
    return _proxy_json(r)


def _app_control_snapshot(tenant_id: str) -> str | None:
    """PAT-799: best-effort before-state for the App Control admins/allowlist
    audit rows. Never raises — a failed lookup just means before=None."""
    try:
        r = http.get(f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/app-control", timeout=10, verify=_VERIFY_INTERNAL)
        if r.status_code == 200:
            return json.dumps(r.json())
    except Exception:
        pass
    return None


@app.put("/admin/tenants/{tenant_id}/app-control/admins")
async def proxy_tenant_app_control_admins_put(tenant_id: str, request: Request):
    before = _app_control_snapshot(tenant_id)
    body = await request.json()
    r = await run_in_threadpool(http.put, f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/app-control/admins", json=body, timeout=10, verify=_VERIFY_INTERNAL)
    request.state.audit_before = before
    request.state.audit_after = json.dumps(body)
    return _proxy_json(r)


@app.put("/admin/tenants/{tenant_id}/app-control/allowlist")
async def proxy_tenant_app_control_allowlist_put(tenant_id: str, request: Request):
    before = _app_control_snapshot(tenant_id)
    body = await request.json()
    r = await run_in_threadpool(http.put, f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/app-control/allowlist", json=body, timeout=10, verify=_VERIFY_INTERNAL)
    request.state.audit_before = before
    request.state.audit_after = json.dumps(body)
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/ce-status")
def proxy_tenant_ce_status(tenant_id: str):
    r = http.get(f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/ce-status", timeout=10, verify=_VERIFY_INTERNAL)
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/enforcement-audit")
def proxy_tenant_enforcement_audit(tenant_id: str, request: Request):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/enforcement-audit",
        params=dict(request.query_params),
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/allowlist/scan")
def proxy_tenant_allowlist_scan(tenant_id: str):
    r = http.get(f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/allowlist/scan", timeout=15, verify=_VERIFY_INTERNAL)
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/allowlist")
async def proxy_tenant_allowlist_create(tenant_id: str, request: Request):
    try:
        body, requests_uninstall = await _read_strict_allowlist_body(request, 8192)
    except _StrictJSONBodyError as exc:
        return JSONResponse({"error": str(exc)}, status_code=exc.status_code)
    request.state.audit_after = body.decode("utf-8")
    if requests_uninstall:
        return JSONResponse(_LEGACY_EXECUTION_QUARANTINE_BODY, status_code=410)
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/allowlist",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.put("/admin/tenants/{tenant_id}/allowlist/{entry_id}")
async def proxy_tenant_allowlist_update(tenant_id: str, entry_id: str, request: Request):
    try:
        body, requests_uninstall = await _read_strict_allowlist_body(request, 4096)
    except _StrictJSONBodyError as exc:
        return JSONResponse({"error": str(exc)}, status_code=exc.status_code)
    request.state.audit_after = body.decode("utf-8")
    if requests_uninstall:
        return JSONResponse(_LEGACY_EXECUTION_QUARANTINE_BODY, status_code=410)
    r = await run_in_threadpool(http.put,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/allowlist/{_seg(entry_id)}",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.delete("/admin/tenants/{tenant_id}/allowlist/{entry_id}")
def proxy_tenant_allowlist_delete(tenant_id: str, entry_id: str):
    r = http.delete(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/allowlist/{_seg(entry_id)}",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-470/474/479/563: P6 app-policy store + drift (mandatory / approved / unapproved) ──

@app.get("/admin/tenants/{tenant_id}/app-policies")
def proxy_tenant_app_policies_list(tenant_id: str):
    r = http.get(f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/app-policies", timeout=10, verify=_VERIFY_INTERNAL)
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/app-policies")
async def proxy_tenant_app_policies_create(tenant_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/app-policies",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.put("/admin/tenants/{tenant_id}/app-policies")
async def proxy_tenant_app_policies_put(tenant_id: str, request: Request):
    """Upsert an app-policy entry by identity (P6 store, ON CONFLICT upsert — PAT-563)."""
    try:
        body, payload = await _read_strict_app_policy_body(request)
    except _StrictJSONBodyError as exc:
        return JSONResponse({"error": str(exc)}, status_code=exc.status_code)
    context = _app_policy_audit_context(tenant_id, payload)
    request.state.audit_before = await _app_policy_before_snapshot(tenant_id, payload)
    request.state.audit_after = json.dumps({**context, "write_state": "attempted"}, sort_keys=True)
    try:
        r = await run_in_threadpool(
            http.put, f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/app-policies",
            data=body, headers={"Content-Type": "application/json"}, timeout=10, verify=_VERIFY_INTERNAL,
        )
    except Exception:
        request.state.audit_after = json.dumps({**context, "write_state": "unavailable"}, sort_keys=True)
        return JSONResponse({"error": "Platform app-policy write unavailable"}, status_code=502)
    request.state.audit_after = json.dumps({**context, "write_state": "applied" if r.status_code < 400 else "rejected",
                                            "upstream_status": r.status_code}, sort_keys=True)
    return _proxy_json(r)


@app.put("/admin/tenants/{tenant_id}/app-policies/{policy_id}")
async def proxy_tenant_app_policies_update(tenant_id: str, policy_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.put,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/app-policies/{_seg(policy_id)}",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.delete("/admin/tenants/{tenant_id}/app-policies/{policy_id}")
def proxy_tenant_app_policies_delete(tenant_id: str, policy_id: str):
    r = http.delete(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/app-policies/{_seg(policy_id)}",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/app-policy-drift")
def proxy_tenant_app_policy_drift(tenant_id: str):
    """Aggregate app-policy drift (mandatory missing + unapproved present) for a tenant (PAT-479)."""
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/app-policy-drift",
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/new-apps")
async def proxy_tenant_new_apps_list(tenant_id: str, status: str = "pending"):
    """PAT-167: List new-app entries awaiting a decision for a tenant."""
    r = await run_in_threadpool(http.get,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/new-apps",
        params={"status": status},
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.put("/admin/tenants/{tenant_id}/new-apps/{entry_id}")
async def proxy_tenant_new_apps_put(tenant_id: str, entry_id: str, request: Request):
    """PAT-1481: record a non-actuating tenant governance decision."""
    try:
        body, decision = await _read_strict_new_app_decision_body(request)
    except _StrictJSONBodyError as exc:
        return JSONResponse({"error": str(exc)}, status_code=exc.status_code)
    request.state.audit_after = body.decode("utf-8")
    # Upstream's historical "remove" value records an unapproved policy decision.
    # Direct endpoint removal is a separate, quarantined /removals route.
    if decision not in {"approve", "remove", "defer"}:
        return JSONResponse(_LEGACY_EXECUTION_QUARANTINE_BODY, status_code=410)
    r = await run_in_threadpool(http.put,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/new-apps/{_seg(entry_id)}",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    # PAT-799: before is always "pending" for this route (decisions are one-shot);
    # after is the decision body itself.
    request.state.audit_before = "pending"
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/restore")
def proxy_tenant_restore(tenant_id: str):
    r = http.post(f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/restore", timeout=10, verify=_VERIFY_INTERNAL)
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/decommission")
def proxy_tenant_decommission_get(tenant_id: str):
    """PAT-1111: current audited platform agent-decommission directive."""
    quoted_tenant_id = _seg(tenant_id)
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{quoted_tenant_id}/decommission",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/decommission/devices")
def proxy_tenant_decommission_devices_get(tenant_id: str):
    """PAT-1111: persistent per-device acknowledgement/removal state."""
    quoted_tenant_id = _seg(tenant_id)
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{quoted_tenant_id}/decommission/devices",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.put("/admin/tenants/{tenant_id}/decommission")
async def proxy_tenant_decommission_put(tenant_id: str, request: Request):
    """PAT-1111: guarded thin proxy to PAT-1108's audited write contract.

    The authenticated dashboard identity always replaces any client-supplied
    actor. Immediate removal also requires a server-validated tenant-name echo;
    the UI gate is not the security boundary for the irreversible action.
    """
    quoted_tenant_id = _seg(tenant_id)
    try:
        incoming = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON body required"}, status_code=400)
    if not isinstance(incoming, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)

    mode = incoming.get("mode")
    if mode not in {"none", "expiry", "immediate"}:
        return JSONResponse({"error": "mode must be one of none, expiry, immediate"}, status_code=400)

    expires_at = incoming.get("expires_at") if mode == "expiry" else None
    if mode == "expiry":
        if not isinstance(expires_at, str) or not expires_at.strip():
            return JSONResponse(
                {"error": "expires_at is required for expiry mode and must be RFC3339"},
                status_code=400,
            )
        expires_at = expires_at.strip()
        if not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
            expires_at,
        ):
            return JSONResponse({"error": "expires_at must be RFC3339"}, status_code=400)
        try:
            parsed_expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if parsed_expiry.utcoffset() is None:
                raise ValueError("timezone required")
        except ValueError:
            return JSONResponse({"error": "expires_at must be RFC3339"}, status_code=400)
        if parsed_expiry.astimezone(timezone.utc) <= datetime.now(timezone.utc):
            return JSONResponse(
                {"error": "expires_at must be in the future; use immediate mode for immediate removal"},
                status_code=400,
            )

    reason = incoming.get("reason")
    if reason is not None and not isinstance(reason, str):
        return JSONResponse({"error": "reason must be a string or null"}, status_code=400)
    if isinstance(reason, str) and len(reason) > 500:
        return JSONResponse({"error": "reason must be 500 characters or fewer"}, status_code=400)

    if mode == "immediate":
        provided = (request.headers.get("X-Confirm-Resource") or "").strip()
        if not provided:
            return JSONResponse(
                {"error": "Confirmation required: type the tenant name before immediate agent removal."},
                status_code=428,
            )
        acceptable, resolution = await run_in_threadpool(
            _resolve_decommission_tenant, tenant_id
        )
        if resolution == "not_found":
            return JSONResponse(
                {"error": "Unable to confirm agent removal because this tenant was not found."},
                status_code=404,
            )
        if resolution == "unavailable":
            return JSONResponse(
                {"error": "Unable to resolve the tenant identity for agent removal."},
                status_code=502,
            )
        if provided.lower() not in acceptable:
            return JSONResponse(
                {"error": "Confirmation mismatch: the typed tenant name does not match this tenant."},
                status_code=409,
            )
        request.state.audit_resource_name = provided

    payload = {
        "mode": mode,
        "expires_at": expires_at,
        "purge": incoming.get("purge") is True,
        "reason": reason,
        "actor": _mirror_actor_email(request),
    }

    before = json.dumps({"read_error": "unavailable"}, sort_keys=True)
    try:
        current = await run_in_threadpool(
            http.get,
            f"{PATCHED_API_INTERNAL}/admin/tenants/{quoted_tenant_id}/decommission",
            timeout=10,
            verify=_VERIFY_INTERNAL,
        )
        before = _decommission_audit_snapshot(current, tenant_id)
    except Exception:
        # Best-effort local before snapshot. The platform write remains the
        # authoritative audited transaction and must not depend on this read.
        pass

    request.state.audit_before = before
    attempted = {
        "mode": payload["mode"],
        "expires_at": payload["expires_at"],
        "purge": payload["purge"],
        "reason": payload["reason"],
    }
    request.state.audit_after = json.dumps({
        "write_state": "attempted",
        "attempted": attempted,
    }, sort_keys=True)
    try:
        r = await run_in_threadpool(
            http.put,
            f"{PATCHED_API_INTERNAL}/admin/tenants/{quoted_tenant_id}/decommission",
            json=payload,
            timeout=10,
            verify=_VERIFY_INTERNAL,
        )
    except Exception:
        return JSONResponse(
            {"error": "Platform decommission write unavailable"}, status_code=502
        )
    if r.status_code < 400:
        request.state.audit_after = _decommission_audit_snapshot(r, tenant_id, after=True)
    else:
        request.state.audit_after = json.dumps({
            "write_error": "upstream_write_failed",
            "status_code": r.status_code,
            "attempted": attempted,
        }, sort_keys=True)
    return _proxy_json(r)


def _delete_service_engagement_for_purged_tenant(tenant_id: str):
    """Delete the local snapshot after an authoritative platform purge.

    Reads and deletes inside a single BEGIN IMMEDIATE transaction, guarding
    the DELETE on the exact updated_at just read — the same version-qualified
    predicate orphan repair uses (see admin_service_engagement_orphan_repair).
    A concurrent PUT racing this purge therefore can't have its write
    silently discarded: if the row changed between the read and the delete,
    this raises instead of deleting state that was never actually observed.
    The caller's except-and-preserve path (see
    _cleanup_service_engagement_after_tenant_delete) already treats any
    exception here as "cleanup failed, snapshot preserved" — the same
    owner-only orphan-repair endpoint can independently re-verify platform
    absence and reconcile it afterwards.
    """
    with get_db() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT * FROM service_engagements WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        before = _service_engagement_row(row)
        if row is not None:
            if _SERVICE_ENGAGEMENT_PURGE_CLEANUP_HOOK:
                _SERVICE_ENGAGEMENT_PURGE_CLEANUP_HOOK(db, tenant_id)
            expected_updated_at = row["updated_at"]
            deleted = db.execute(
                "DELETE FROM service_engagements WHERE tenant_id=? "
                "AND (updated_at = ? OR (updated_at IS NULL AND ? IS NULL))",
                (tenant_id, expected_updated_at, expected_updated_at),
            )
            if deleted.rowcount != 1:
                raise RuntimeError(
                    "service_engagements row for tenant_id="
                    f"{tenant_id!r} changed concurrently during purge cleanup"
                )
    return before


def _cleanup_service_engagement_after_tenant_delete(tenant_id: str):
    try:
        before = _delete_service_engagement_for_purged_tenant(tenant_id)
        return {}, before, True
    except Exception as exc:
        safe_tenant_id = str(tenant_id).replace("\r", r"\r").replace("\n", r"\n")
        print(
            f"[CRITICAL tenant-delete] local service snapshot cleanup failed "
            f"tenant_id={safe_tenant_id}: {exc}",
            file=sys.stderr,
        )
        return {"X-Patched-Local-Cleanup": "service-engagement-failed"}, None, False


@app.delete("/admin/tenants/{tenant_id}/purge")
def proxy_tenant_purge(tenant_id: str, request: Request):
    r = http.delete(f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/purge", timeout=15, verify=_VERIFY_INTERNAL)
    headers = {}
    if r.status_code == 200:
        # The platform owns tenant lifecycle, but this consultancy snapshot is
        # dashboard-local. Delete it only after authoritative purge succeeds.
        headers, before, cleaned = _cleanup_service_engagement_after_tenant_delete(tenant_id)
        request.state.audit_before = json.dumps(before, sort_keys=True) if before else None
        request.state.audit_after = (
            json.dumps(None) if cleaned
            else json.dumps({"local_cleanup": "failed", "snapshot_preserved": True}, sort_keys=True)
        )
        return JSONResponse(
            {"purged": True, "tenant_id": tenant_id},
            status_code=200,
            headers=headers,
        )
    return Response(status_code=r.status_code, headers=headers)


@app.delete("/admin/tenants/{tenant_id}")
def proxy_tenant_offboard(tenant_id: str):
    r = http.delete(f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}", timeout=10, verify=_VERIFY_INTERNAL)
    # Offboard is reversible: the tenant remains in the revoked index and can
    # be restored. Its consultancy history must survive that lifecycle change.
    # Only the authoritative purge route above destroys the local snapshot.
    return Response(status_code=r.status_code)


@app.patch("/admin/billing/rates")
async def api_billing_rates_patch(request: Request):
    before = _billing_rates()  # PAT-799: global rate card — snapshot before mutating.
    data = await request.json()
    if not isinstance(data, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)
    rates = _default_billing_rates()
    rates["bands"] = {tier: [dict(b) for b in bands] for tier, bands in before["bands"].items()}
    rates["tail_rate_per_endpoint"] = dict(before["tail_rate_per_endpoint"])
    rates["annual_discount"] = before["annual_discount"]

    if "bands" in data:
        if not isinstance(data["bands"], dict):
            return JSONResponse({"error": "bands must be an object keyed by tier"}, status_code=400)
        for tier, band_list in data["bands"].items():
            if tier not in _BILLING_BAND_TIERS:
                return JSONResponse({"error": f"unknown billing tier for bands: {tier!r}"}, status_code=400)
            validated, err = _validate_billing_bands(band_list)
            if err:
                return JSONResponse({"error": f"{tier} bands: {err}"}, status_code=400)
            rates["bands"][tier] = validated

    if "tail_rate_per_endpoint" in data:
        if not isinstance(data["tail_rate_per_endpoint"], dict):
            return JSONResponse({"error": "tail_rate_per_endpoint must be an object keyed by tier"}, status_code=400)
        for tier, v in data["tail_rate_per_endpoint"].items():
            if tier not in _BILLING_BAND_TIERS:
                return JSONResponse({"error": f"unknown billing tier for tail_rate_per_endpoint: {tier!r}"}, status_code=400)
            try:
                v = float(v)
            except (TypeError, ValueError):
                return JSONResponse({"error": f"tail_rate_per_endpoint.{tier} must be a number"}, status_code=400)
            if v < 0:
                return JSONResponse({"error": f"tail_rate_per_endpoint.{tier} must be >= 0"}, status_code=400)
            rates["tail_rate_per_endpoint"][tier] = v

    if "annual_discount" in data:
        try:
            v = float(data["annual_discount"])
        except (TypeError, ValueError):
            return JSONResponse({"error": "annual_discount must be a number"}, status_code=400)
        # PAT-1100: annual prepay must be a discount BELOW the monthly headline,
        # never an uplift above it — that was the exact defect (monthly_uplift:
        # 1.22) this ticket exists to repair. Bound to (0, 1] so a value like
        # 1.22 can't be stored and silently re-invert the fix.
        if v <= 0 or v > 1:
            return JSONResponse({"error": "annual_discount must be > 0 and <= 1"}, status_code=400)
        rates["annual_discount"] = v

    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO kv(key, value, updated_at) VALUES(?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (_BILLING_RATES_KEY, json.dumps(rates), now_iso),
        )
    # PAT-799: this is the global commercial rate card — every tenant invoice is
    # computed from it. Record the full before/after so a bad edit is diffable.
    request.state.audit_before = json.dumps(before)
    request.state.audit_after = json.dumps(rates)
    return JSONResponse(rates)


# ── PAT-1100: time ledger ────────────────────────────────────────────────────
# Advisory-hours consumption + service_integrity work, tracked per tenant.
# `class` is a hard 400-on-anything-else distinction (not just a label) —
# without it, hours-based advisory support gives customers a reason not to
# report a broken agent, since fixing it would eat their advisory allowance.
# service_integrity entries are logged here for visibility but must NEVER be
# summed into the advisory balance below.
_TIME_LEDGER_CLASSES = {"advisory", "service_integrity"}


def _tenant_device_count(tenant_id: str) -> int:
    """Best-effort live endpoint count for one tenant, via the same platform
    overview call /admin/billing/summary uses. Returns 0 on any failure —
    this only affects the advisory-allowance calc, not billing itself."""
    try:
        r = http.get(f"{PATCHED_API_INTERNAL}/admin/tenants/overview", timeout=15, verify=_VERIFY_INTERNAL)
        if r.status_code == 200:
            for t in (r.json().get("tenants") or []):
                if t.get("id") == tenant_id:
                    return int(t.get("device_count") or 0)
    except Exception as e:
        print(f"[time-ledger] tenant device count fetch failed: {e}")
    return 0


@app.post("/admin/tenants/{tenant_id}/time-ledger")
async def api_time_ledger_create(tenant_id: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON body required"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)

    entry_date = (body.get("entry_date") or "").strip()
    if not entry_date:
        return JSONResponse({"error": "entry_date is required"}, status_code=400)
    # Non-author review finding: the balance endpoint matches entries via
    # `entry_date LIKE '<YYYY-MM>%'`, so a non-ISO OR non-zero-padded date
    # (e.g. "2026-8-11", which datetime.strptime happily accepts) would
    # silently never be counted toward any month's balance rather than
    # erroring loudly — require the strict zero-padded shape the LIKE prefix
    # match depends on, not just "parseable as a date".
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", entry_date):
        return JSONResponse({"error": "entry_date must be YYYY-MM-DD"}, status_code=400)
    try:
        datetime.strptime(entry_date, "%Y-%m-%d")
    except ValueError:
        return JSONResponse({"error": "entry_date must be YYYY-MM-DD"}, status_code=400)

    entry_class = body.get("class")
    if entry_class not in _TIME_LEDGER_CLASSES:
        return JSONResponse(
            {"error": f"class must be one of {sorted(_TIME_LEDGER_CLASSES)}"}, status_code=400
        )

    try:
        duration_minutes = int(body.get("duration_minutes"))
    except (TypeError, ValueError):
        return JSONResponse({"error": "duration_minutes must be an integer"}, status_code=400)
    # PAT-1100: coarse granularity is deliberate, not a nice-to-have — reject
    # anything that isn't a positive multiple of 15.
    if duration_minutes <= 0 or duration_minutes % 15 != 0:
        return JSONResponse(
            {"error": "duration_minutes must be a positive multiple of 15"}, status_code=400
        )

    entry_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    created_by = _mirror_actor_email(request) or None
    with get_db() as db:
        db.execute(
            "INSERT INTO time_ledger (id, tenant_id, entry_date, duration_minutes, note, class, created_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (entry_id, tenant_id, entry_date, duration_minutes, body.get("note"), entry_class, created_by, now_iso),
        )
    return JSONResponse({"id": entry_id, "ok": True})


@app.get("/admin/tenants/{tenant_id}/time-ledger")
def api_time_ledger_list(tenant_id: str):
    with get_db() as db:
        rows = db.execute(
            "SELECT id, tenant_id, entry_date, duration_minutes, note, class, created_by, created_at "
            "FROM time_ledger WHERE tenant_id=? ORDER BY entry_date DESC, created_at DESC LIMIT 200",
            (tenant_id,),
        ).fetchall()
    return JSONResponse({"entries": [dict(r) for r in rows]})


@app.get("/admin/tenants/{tenant_id}/time-ledger/balance")
def api_time_ledger_balance(tenant_id: str):
    """Minimal, tenant-scoped, read-only balance shape — intentionally just
    {consumed_minutes, allowance_minutes, remaining_minutes, over_80_percent}
    and nothing else. PAT-1100 built this so PAT-1104 (customer-portal balance
    panel, separate ticket, not implemented here) has something safe to wire
    up later: no band table, no tail rate, no other tenant's data reachable
    from this response.
    """
    now = datetime.now(timezone.utc)
    month_prefix = now.strftime("%Y-%m")
    with get_db() as db:
        row = db.execute(
            "SELECT COALESCE(SUM(duration_minutes), 0) AS total FROM time_ledger "
            "WHERE tenant_id=? AND class='advisory' AND entry_date LIKE ?",
            (tenant_id, f"{month_prefix}%"),
        ).fetchone()
        consumed_minutes = int(row["total"] or 0)
        client_row = db.execute(
            "SELECT billing_tier FROM clients WHERE tenant_id=?", (tenant_id,)
        ).fetchone()

    billing_tier = (client_row["billing_tier"] if client_row else None) or "report"
    rates = _billing_rates()
    allowance_hours = 0.0
    bands = rates.get("bands", {}).get(billing_tier)
    if bands:
        endpoints = _tenant_device_count(tenant_id)
        band = _billing_band_for(endpoints, bands)
        # Tail territory (>250 endpoints) has no defined advisory-hours
        # convention — allowance stays 0 rather than inventing a number.
        if band is not None:
            allowance_hours = float(band.get("advisory_hours") or 0)

    allowance_minutes = int(round(allowance_hours * 60))
    remaining_minutes = allowance_minutes - consumed_minutes
    over_80_percent = allowance_minutes > 0 and consumed_minutes >= 0.8 * allowance_minutes

    return JSONResponse({
        "consumed_minutes": consumed_minutes,
        "allowance_minutes": allowance_minutes,
        "remaining_minutes": remaining_minutes,
        "over_80_percent": over_80_percent,
    })


# ── PAT-1101: contracts — the source of truth for what a signed tenant is
# billed ──────────────────────────────────────────────────────────────────
# A contract's monthly_at_signature/advisory_hours_at_signature are frozen
# facts, derived ONCE (via _compute_monthly/_billing_band_for against the
# CURRENT band table) at the moment the contract is created, then never
# recomputed. Every write here happens through this explicit POST, triggered
# by a human action — never a scheduled job (that's PAT-1103's band-drift
# watcher, out of scope here: "never auto-apply a new band to a live
# contract").
_CONTRACT_TIERS = _BILLING_BAND_TIERS  # patch | full — a contract implies a
                                        # priced tier; 'report' has no band
                                        # table and can't be contracted.
_CONTRACT_FREQUENCIES = {"monthly", "annual"}


def _add_months(date_str: str, months: int) -> str:
    """Add `months` calendar months to an ISO (YYYY-MM-DD) date string,
    clamping the day to the target month's last day if it overflows (e.g.
     2027-01-31 + 1 month -> 2027-02-28). No dateutil dependency in
    requirements.txt — plain date arithmetic is the established pattern in
    this file, so this stays stdlib-only rather than adding one."""
    d = datetime.strptime(date_str, "%Y-%m-%d").date()
    month_index = d.month - 1 + months
    year = d.year + month_index // 12
    month = month_index % 12 + 1
    day = min(d.day, calendar.monthrange(year, month)[1])
    return date(year, month, day).isoformat()


def _iso_date_or_400(value: str, field: str) -> tuple[str | None, JSONResponse | None]:
    value = (value or "").strip()
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", value):
        return None, JSONResponse({"error": f"{field} must be YYYY-MM-DD"}, status_code=400)
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return None, JSONResponse({"error": f"{field} must be YYYY-MM-DD"}, status_code=400)
    return value, None


@app.post("/admin/tenants/{tenant_id}/contracts")
async def api_contract_create(tenant_id: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON body required"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)

    # Non-author review finding: derive frozen figures only for a tenant that
    # actually exists — otherwise a typo'd tenant_id would still succeed and
    # freeze phantom figures onto a contract row for nothing.
    with get_db() as db:
        if not db.execute("SELECT 1 FROM clients WHERE tenant_id=?", (tenant_id,)).fetchone():
            return JSONResponse({"error": f"tenant not found: {tenant_id!r}"}, status_code=404)

    tier = body.get("tier_at_signature")
    if tier not in _CONTRACT_TIERS:
        return JSONResponse(
            {"error": f"tier_at_signature must be one of {sorted(_CONTRACT_TIERS)}"}, status_code=400
        )

    frequency = body.get("billing_frequency")
    if frequency not in _CONTRACT_FREQUENCIES:
        return JSONResponse(
            {"error": f"billing_frequency must be one of {sorted(_CONTRACT_FREQUENCIES)}"}, status_code=400
        )

    # `or 12` would silently turn an explicit 0 into 12 (0 is falsy) — only a
    # genuinely absent/None value should fall back to the default, so an
    # explicit 0 still hits the >0 rejection below.
    term_length_months_raw = body.get("term_length_months")
    if term_length_months_raw is None:
        term_length_months_raw = 12
    try:
        term_length_months = int(term_length_months_raw)
    except (TypeError, ValueError):
        return JSONResponse({"error": "term_length_months must be an integer"}, status_code=400)
    if term_length_months <= 0:
        return JSONResponse({"error": "term_length_months must be positive"}, status_code=400)

    term_start_raw = body.get("term_start") or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    term_start, err = _iso_date_or_400(term_start_raw, "term_start")
    if err:
        return err

    assessment_credit_applies = bool(body.get("assessment_credit_applies"))
    assessment_credit_value = body.get("assessment_credit_value")
    if assessment_credit_value is not None:
        try:
            assessment_credit_value = float(assessment_credit_value)
        except (TypeError, ValueError):
            return JSONResponse({"error": "assessment_credit_value must be a number"}, status_code=400)

    assessment_credit_expires_at = body.get("assessment_credit_expires_at")
    if assessment_credit_expires_at:
        assessment_credit_expires_at, err = _iso_date_or_400(
            assessment_credit_expires_at, "assessment_credit_expires_at"
        )
        if err:
            return err
    else:
        assessment_credit_expires_at = None

    supersede = (request.query_params.get("supersede") or "").strip().lower() == "true"

    # Frozen facts derived from CURRENT state — computed here, at signature
    # time, and never again. _tenant_device_count()/_billing_rates() are the
    # same helpers PAT-1100's live quoting path and the time-ledger balance
    # endpoint already use; no third way to get a device count.
    rates = _billing_rates()
    endpoints = _tenant_device_count(tenant_id)
    monthly = _compute_monthly(endpoints, tier, frequency, rates)
    bands = rates.get("bands", {}).get(tier) or []
    band = _billing_band_for(endpoints, bands)
    # Tail territory (>250 endpoints) has no defined advisory-hours
    # convention — same convention the balance endpoint (PAT-1100) uses:
    # allowance stays 0 rather than inventing a number.
    advisory_hours = float(band.get("advisory_hours") or 0) if band is not None else 0.0
    annual_discount = float(rates.get("annual_discount")) if frequency == "annual" else None
    renewal_date = _add_months(term_start, term_length_months)

    contract_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    created_by = _mirror_actor_email(request) or None

    with get_db() as db:
        existing = db.execute(
            "SELECT id FROM billing_contracts WHERE tenant_id=? AND status='active'", (tenant_id,)
        ).fetchone()
        if existing and not supersede:
            return JSONResponse(
                {"error": "tenant already has an active contract — supersede it first"},
                status_code=400,
            )
        if existing and supersede:
            db.execute("UPDATE billing_contracts SET status='superseded' WHERE id=?", (existing["id"],))

        db.execute(
            "INSERT INTO billing_contracts (id, tenant_id, tier_at_signature, band_endpoints_at_signature, "
            "monthly_at_signature, billing_frequency, annual_discount_at_signature, term_start, "
            "term_length_months, renewal_date, advisory_hours_at_signature, named_specialist, "
            "named_customer_contact, assessment_credit_applies, assessment_credit_value, "
            "assessment_credit_expires_at, note, status, created_at, created_by) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                contract_id, tenant_id, tier, endpoints, monthly, frequency, annual_discount, term_start,
                term_length_months, renewal_date, advisory_hours,
                body.get("named_specialist"), body.get("named_customer_contact"),
                1 if assessment_credit_applies else 0, assessment_credit_value,
                assessment_credit_expires_at, body.get("note"), "active", now_iso, created_by,
            ),
        )
        row = db.execute("SELECT * FROM billing_contracts WHERE id=?", (contract_id,)).fetchone()

    return JSONResponse(dict(row))


@app.get("/admin/tenants/{tenant_id}/contracts")
def api_contracts_list(tenant_id: str):
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM billing_contracts WHERE tenant_id=? ORDER BY created_at DESC", (tenant_id,)
        ).fetchall()
    return JSONResponse({"contracts": [dict(r) for r in rows]})


@app.get("/admin/tenants/{tenant_id}/contracts/active")
def api_contract_active(tenant_id: str):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM billing_contracts WHERE tenant_id=? AND status='active' LIMIT 1", (tenant_id,)
        ).fetchone()
    if not row:
        return JSONResponse({"error": "no active contract"}, status_code=404)
    return JSONResponse(dict(row))


@app.get("/admin/billing/renewals")
def api_billing_renewals():
    """Tenants whose active contract's renewal_date falls within the next 60
    days OR is already past (overdue is even more visible-without-searching
    than upcoming — never filtered out). For each: the contracted figure vs
    what the CURRENT band table would produce for their CURRENT live
    endpoint count (the delta IS the renewal conversation), plus mean/peak/
    over-allowance advisory-class time_ledger consumption across the
    contract term so far.

    The "current-band figure" intentionally reuses the contract's own
    tier_at_signature/billing_frequency — only endpoints and the rate card
    are swapped for their CURRENT values — so the delta isolates exactly
    the two things that can drift a contracted figure (band-table edits,
    endpoint-count drift), not an unrelated tier change.
    """
    rates = _billing_rates()
    device_counts, tenant_names = _billing_tenant_overview()
    now = datetime.now(timezone.utc)
    today_str = now.strftime("%Y-%m-%d")
    window_end = (now + timedelta(days=60)).strftime("%Y-%m-%d")

    with get_db() as db:
        # Non-author review finding: a contract whose term_start is still in
        # the future (renewal not yet even begun) could otherwise appear here
        # if its renewal_date happened to fall inside the 60-day window (a
        # short term_length_months). Renewals-visibility should only ever
        # cover terms that have actually started.
        contracts = [
            dict(r) for r in db.execute(
                "SELECT * FROM billing_contracts WHERE status='active' AND renewal_date <= ? "
                "AND term_start <= ? ORDER BY renewal_date ASC",
                (window_end, today_str),
            ).fetchall()
        ]
        tenant_ids = [c["tenant_id"] for c in contracts]
        ledger_by_tenant: dict = {}
        if tenant_ids:
            placeholders = ",".join("?" for _ in tenant_ids)
            ledger_rows = db.execute(
                f"SELECT tenant_id, entry_date, duration_minutes FROM time_ledger "
                f"WHERE class='advisory' AND tenant_id IN ({placeholders})",
                tenant_ids,
            ).fetchall()
            for lr in ledger_rows:
                ledger_by_tenant.setdefault(lr["tenant_id"], []).append(lr)

    rows = []
    for c in contracts:
        tid = c["tenant_id"]
        endpoints = device_counts.get(tid, 0)
        # PAT-1103: current_monthly/delta reuse the shared band-drift helper
        # rather than recomputing _compute_monthly() a second time here —
        # band_would_produce IS current_monthly, same value, one
        # implementation. Existing delta values (asserted by
        # TestRenewalsDeltaAndConsumption) are unchanged by this refactor.
        drift = _tenant_band_drift(tid, endpoints, c, rates)
        current_monthly = drift["band_would_produce"]
        contracted_monthly = c["monthly_at_signature"]
        delta = round(current_monthly - contracted_monthly, 2)
        consecutive_months_drifted = _consecutive_drift_months(tid, drift["direction"])

        # Group this tenant's advisory-class entries within [term_start, now]
        # by calendar month (YYYY-MM), summing duration_minutes per month —
        # service_integrity entries were already excluded by the SQL filter
        # above, never entering this calculation.
        term_start = c["term_start"]
        month_totals: dict = {}
        for lr in ledger_by_tenant.get(tid, []):
            entry_date = lr["entry_date"]
            if term_start <= entry_date <= today_str:
                month_key = entry_date[:7]
                month_totals[month_key] = month_totals.get(month_key, 0) + int(lr["duration_minutes"] or 0)
        month_values = list(month_totals.values())
        allowance_minutes = int(round((c["advisory_hours_at_signature"] or 0) * 60))
        consumption_mean_minutes = round(sum(month_values) / len(month_values), 1) if month_values else 0.0
        consumption_peak_minutes = max(month_values) if month_values else 0
        consumption_months_over_allowance = sum(1 for v in month_values if v > allowance_minutes)

        renewal_date_obj = datetime.strptime(c["renewal_date"], "%Y-%m-%d").date()
        days_until_renewal = (renewal_date_obj - now.date()).days

        rows.append({
            "tenant_id": tid,
            "company": tenant_names.get(tid) or tid,
            "tier_at_signature": c["tier_at_signature"],
            "billing_frequency": c["billing_frequency"],
            "endpoints": endpoints,
            "contracted_monthly": contracted_monthly,
            "current_band_monthly": current_monthly,
            "delta": delta,
            "contracted_advisory_hours": c["advisory_hours_at_signature"],
            "consumption_mean_minutes": consumption_mean_minutes,
            "consumption_peak_minutes": consumption_peak_minutes,
            "consumption_months_over_allowance": consumption_months_over_allowance,
            "consumption_months_counted": len(month_values),
            "term_start": term_start,
            "renewal_date": c["renewal_date"],
            "days_until_renewal": days_until_renewal,
            # PAT-1103: band-drift fields, additive to the PAT-1101 response
            # shape above — every field above this comment already existed
            # and keeps its exact prior value/meaning.
            "drift_direction": drift["direction"],
            "drift_headroom_to_next_edge": drift["headroom_to_next_edge"],
            "drift_contracted_band_max": drift["contracted_band_max"],
            "drift_consecutive_months": consecutive_months_drifted,
        })

    rows.sort(key=lambda x: x["days_until_renewal"])
    return JSONResponse({"rows": rows, "window_days": 60})


@app.get("/admin/billing/drift")
def api_billing_drift():
    """Band-drift visibility for EVERY tenant with an active contract — not
    just those inside api_billing_renewals' 60-day renewal window. PAT-1103:
    "visible per tenant without going looking for it" is a broader
    acceptance criterion than the renewal view, so this is the standalone
    surface for it. Purely advisory (see the ruling recorded on
    billing_drift_checks' migration comment in init_db()) — nothing here
    ever writes anything; the only writer of billing_drift_checks is the
    monthly scheduler tick.
    """
    rates = _billing_rates()
    device_counts, tenant_names = _billing_tenant_overview()

    with get_db() as db:
        contracts = [
            dict(r) for r in db.execute(
                "SELECT * FROM billing_contracts WHERE status='active' ORDER BY tenant_id"
            ).fetchall()
        ]

    rows = []
    for c in contracts:
        tid = c["tenant_id"]
        endpoints = device_counts.get(tid, 0)
        drift = _tenant_band_drift(tid, endpoints, c, rates)
        consecutive_months_drifted = _consecutive_drift_months(tid, drift["direction"])
        rows.append({
            "tenant_id": tid,
            "company": tenant_names.get(tid) or tid,
            "tier_at_signature": c["tier_at_signature"],
            "endpoints": endpoints,
            "contracted_monthly": c["monthly_at_signature"],
            "band_would_produce": drift["band_would_produce"],
            "contracted_band_max": drift["contracted_band_max"],
            "direction": drift["direction"],
            "headroom_to_next_edge": drift["headroom_to_next_edge"],
            "consecutive_months_drifted": consecutive_months_drifted,
        })

    # Judgment call: tenants actively drifting (direction != 'none') surface
    # first, longest current streak first, so the conversation-worthy rows
    # are at the top without hiding the non-drifting ones lower down — PAT-
    # 1103 is explicit that direction='none' tenants must still appear, just
    # de-emphasised, not filtered out.
    rows.sort(key=lambda x: (x["direction"] == "none", -x["consecutive_months_drifted"]))
    return JSONResponse({"rows": rows})


# ── PAT-1102: one-off charges + assessment-credit tracking ──────────────────
#
# The pricing model is recurring (bands/contracts, above) AND non-recurring —
# one-off charges (assessment, onboarding, audit pack, advisory overflow).
# All of these are manual Xero invoices today and stay that way (no Xero
# integration here — PAT-654, unbuilt, out of scope). This block just gives
# the dashboard something that KNOWS these charges exist, their status, and
# the assessment-credit rule: see api_charge_apply_credit below for the
# "explicit human action with an audit trail" mechanics.

_CHARGE_TYPES = {"assessment", "onboarding", "audit_pack", "advisory_overflow"}
_CHARGE_STATUSES = {"draft", "invoiced", "paid", "credited", "written_off"}

_ASSESSMENT_CREDIT_WINDOW_DAYS = 90


def _charge_credits_total(db, charge_id: str) -> float:
    row = db.execute(
        "SELECT SUM(amount) as total FROM billing_charge_credits WHERE charge_id=?", (charge_id,)
    ).fetchone()
    return float(row["total"] or 0) if row else 0.0


def _charge_with_totals(row: sqlite3.Row, credits: float) -> dict:
    """Every read of a charge exposes gross, credit and net — never just the
    raw `amount` — so a discounted figure is always reconstructable later
    rather than a mystery number nobody can explain in a year."""
    d = dict(row)
    d["gross"] = d["amount"]
    d["credits"] = round(credits, 2)
    d["net"] = round(d["amount"] - credits, 2)
    return d


@app.post("/admin/tenants/{tenant_id}/charges")
async def api_charge_create(tenant_id: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON body required"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)

    # Same tenant-existence check PAT-1101's hotfix added to contract
    # creation — otherwise a typo'd tenant_id would still succeed and create
    # a charge for nothing.
    with get_db() as db:
        if not db.execute("SELECT 1 FROM clients WHERE tenant_id=?", (tenant_id,)).fetchone():
            return JSONResponse({"error": f"tenant not found: {tenant_id!r}"}, status_code=404)

    charge_type = body.get("charge_type")
    if charge_type not in _CHARGE_TYPES:
        return JSONResponse(
            {"error": f"charge_type must be one of {sorted(_CHARGE_TYPES)}"}, status_code=400
        )

    amount_raw = body.get("amount")
    try:
        amount = float(amount_raw)
    except (TypeError, ValueError):
        return JSONResponse({"error": "amount must be a number"}, status_code=400)
    if amount <= 0:
        return JSONResponse({"error": "amount must be positive"}, status_code=400)

    date_raised_raw = body.get("date_raised") or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    date_raised, err = _iso_date_or_400(date_raised_raw, "date_raised")
    if err:
        return err

    # credit_expires_at is computed here, server-side, from date_raised — the
    # client cannot supply or influence it (body.get("credit_expires_at") is
    # deliberately never read). Meaningless for non-assessment charge types,
    # so it stays null/0 there.
    if charge_type == "assessment":
        credit_expires_at = (
            datetime.strptime(date_raised, "%Y-%m-%d").date()
            + timedelta(days=_ASSESSMENT_CREDIT_WINDOW_DAYS)
        ).isoformat()
    else:
        credit_expires_at = None

    charge_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    created_by = _mirror_actor_email(request) or None

    with get_db() as db:
        db.execute(
            "INSERT INTO billing_charges (id, tenant_id, charge_type, amount, date_raised, status, "
            "xero_invoice_reference, note, credit_expires_at, credit_consumed, created_at, created_by) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                charge_id, tenant_id, charge_type, amount, date_raised, "draft",
                (body.get("xero_invoice_reference") or None), (body.get("note") or None),
                credit_expires_at, 0, now_iso, created_by,
            ),
        )
        row = db.execute("SELECT * FROM billing_charges WHERE id=?", (charge_id,)).fetchone()

    return JSONResponse(_charge_with_totals(row, 0.0))


@app.get("/admin/tenants/{tenant_id}/charges")
def api_charges_list(tenant_id: str):
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM billing_charges WHERE tenant_id=? ORDER BY date_raised DESC, created_at DESC",
            (tenant_id,),
        ).fetchall()
        charges = [_charge_with_totals(r, _charge_credits_total(db, r["id"])) for r in rows]
    return JSONResponse({"charges": charges})


@app.patch("/admin/tenants/{tenant_id}/charges/{charge_id}")
async def api_charge_update(tenant_id: str, charge_id: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON body required"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)

    updates = {}
    if "status" in body:
        status = body.get("status")
        if status not in _CHARGE_STATUSES:
            return JSONResponse(
                {"error": f"status must be one of {sorted(_CHARGE_STATUSES)}"}, status_code=400
            )
        updates["status"] = status
    if "xero_invoice_reference" in body:
        updates["xero_invoice_reference"] = (body.get("xero_invoice_reference") or None)
    if "note" in body:
        updates["note"] = (body.get("note") or None)
    if not updates:
        return JSONResponse({"error": "no updatable fields supplied (status, xero_invoice_reference, note)"},
                             status_code=400)

    with get_db() as db:
        # Tenant-scoped: a charge_id that exists but belongs to a different
        # tenant_id must 404, same as it not existing at all — never leak or
        # allow cross-tenant writes via a guessed id.
        existing = db.execute(
            "SELECT id FROM billing_charges WHERE id=? AND tenant_id=?", (charge_id, tenant_id)
        ).fetchone()
        if not existing:
            return JSONResponse({"error": "charge not found"}, status_code=404)

        set_clause = ", ".join(f"{k}=?" for k in updates)
        db.execute(f"UPDATE billing_charges SET {set_clause} WHERE id=?", (*updates.values(), charge_id))
        row = db.execute("SELECT * FROM billing_charges WHERE id=?", (charge_id,)).fetchone()
        credits = _charge_credits_total(db, charge_id)

    return JSONResponse(_charge_with_totals(row, credits))


@app.get("/admin/tenants/{tenant_id}/available-assessment-credit")
def api_available_assessment_credit(tenant_id: str):
    """The sharp endpoint. Returns the tenant's most recent assessment-type
    charge with credit_consumed=0, WHETHER OR NOT it has expired — an expired
    credit is visibly expired, never silently omitted, so the conversation
    can still be had deliberately. Distinguishes three states:
      - no assessment charge exists at all
      - one exists but credit_expires_at has passed (expired)
      - one exists, unexpired, unconsumed (available)
    """
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with get_db() as db:
        # Non-author review finding: exclude 'written_off' — an operator who
        # has explicitly declared an assessment charge written off must not
        # have it resurface as an applicable credit just because
        # credit_consumed is independently still 0. status and
        # credit_consumed are separate dimensions; a written-off assessment
        # is never a valid credit source regardless of consumption state.
        row = db.execute(
            "SELECT * FROM billing_charges WHERE tenant_id=? AND charge_type='assessment' "
            "AND credit_consumed=0 AND status != 'written_off' "
            "ORDER BY date_raised DESC, created_at DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()

    if not row:
        return JSONResponse({
            "available": False, "expired": False,
            "charge_id": None, "amount": None, "credit_expires_at": None,
        })

    # Non-author review finding: credit_expires_at is always set by
    # api_charge_create for charge_type='assessment', but treat an
    # unexpectedly-null value as NOT available rather than "never expires" —
    # bool(None) is False, so the naive `expired` check below would silently
    # present a never-expiring credit if this invariant were ever broken by
    # a future code path.
    if not row["credit_expires_at"]:
        return JSONResponse({
            "available": False, "expired": False,
            "charge_id": row["id"], "amount": row["amount"], "credit_expires_at": None,
        })

    expired = row["credit_expires_at"] < today_str
    return JSONResponse({
        "available": not expired,
        "expired": expired,
        "charge_id": row["id"],
        "amount": row["amount"],
        "credit_expires_at": row["credit_expires_at"],
    })


@app.post("/admin/tenants/{tenant_id}/charges/{target_charge_id}/apply-credit")
async def api_charge_apply_credit(tenant_id: str, target_charge_id: str, request: Request):
    """The explicit human action that actually moves an assessment credit
    onto another charge (usually an onboarding charge). Single get_db()
    transaction: the billing_charge_credits insert and the source charge's
    credit_consumed=1 flip either both happen or neither does — that pairing
    IS the audit-trail integrity property ("a credit can only be applied
    once")."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON body required"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)

    source_charge_id = body.get("source_charge_id")
    if not source_charge_id:
        return JSONResponse({"error": "source_charge_id is required"}, status_code=400)

    override_expired = (request.query_params.get("override_expired") or "").strip().lower() == "true"

    with get_db() as db:
        target = db.execute(
            "SELECT * FROM billing_charges WHERE id=? AND tenant_id=?", (target_charge_id, tenant_id)
        ).fetchone()
        if not target:
            return JSONResponse({"error": "target charge not found"}, status_code=404)

        source = db.execute(
            "SELECT * FROM billing_charges WHERE id=? AND tenant_id=? AND charge_type='assessment'",
            (source_charge_id, tenant_id),
        ).fetchone()
        if not source:
            return JSONResponse(
                {"error": "source_charge_id must be a tenant-scoped assessment charge"}, status_code=400
            )

        # A credit can only ever be applied once — this is the audit-trail
        # integrity property the ticket calls out explicitly.
        if source["credit_consumed"]:
            return JSONResponse({"error": "credit already consumed"}, status_code=400)

        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        is_expired = bool(source["credit_expires_at"]) and source["credit_expires_at"] < today_str
        # WARN but do not silently refuse an expired credit — surface it and
        # require the explicit ?override_expired=true flag so a human can
        # still choose to honour it deliberately. Never auto-apply either way.
        if is_expired and not override_expired:
            return JSONResponse(
                {
                    "error": "assessment credit has expired; retry with ?override_expired=true "
                             "to apply it deliberately",
                    "expired": True,
                    "credit_expires_at": source["credit_expires_at"],
                },
                status_code=400,
            )

        # "Credited in full" is the default POLICY, not a hard-coded rule this
        # endpoint enforces blindly — an operator can override the amount.
        amount_raw = body.get("amount")
        amount = source["amount"] if amount_raw is None else amount_raw
        try:
            amount = float(amount)
        except (TypeError, ValueError):
            return JSONResponse({"error": "amount must be a number"}, status_code=400)
        if amount <= 0:
            return JSONResponse({"error": "amount must be positive"}, status_code=400)

        credit_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()
        applied_by = _mirror_actor_email(request) or None
        db.execute(
            "INSERT INTO billing_charge_credits (id, charge_id, source_charge_id, amount, reason, "
            "applied_at, applied_by) VALUES (?,?,?,?,?,?,?)",
            (credit_id, target_charge_id, source_charge_id, amount, body.get("reason"), now_iso, applied_by),
        )
        db.execute("UPDATE billing_charges SET credit_consumed=1 WHERE id=?", (source_charge_id,))

        target_row = db.execute("SELECT * FROM billing_charges WHERE id=?", (target_charge_id,)).fetchone()
        credits_total = _charge_credits_total(db, target_charge_id)

    result = _charge_with_totals(target_row, credits_total)
    result["credit_applied"] = {
        "id": credit_id,
        "source_charge_id": source_charge_id,
        "amount": amount,
        "applied_despite_expired": bool(is_expired and override_expired),
    }
    return JSONResponse(result)


@app.post("/admin/conversion-events")
async def api_conversion_events(request: Request):
    data = await request.json()
    tenant_id = data.get("tenant_id")
    event_name = data.get("event_name")
    if not tenant_id or not event_name:
        return JSONResponse({"error": "tenant_id and event_name are required"}, status_code=400)

    event_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT OR IGNORE INTO conversion_events (id, tenant_id, event_name, category, severity, recorded_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (event_id, tenant_id, event_name, data.get("category"), data.get("severity"), now_iso),
        )
    return JSONResponse({"id": event_id})


_SERVICE_NAMES = {
    "Endpoint Assurance",
    "Managed Patching",
    "Full Endpoint Management",
}
_POSTURE_REVIEW_STATUSES = {"not_started", "scheduled", "in_review", "current", "overdue"}
_PLAN_STATUSES = {"not_started", "active", "complete"}

# Narrow test seams for deterministic lost-update coverage. Production leaves
# both unset; hooks run inside the same request at the documented race boundary.
_SERVICE_ENGAGEMENT_BEFORE_WRITE_HOOK = None
_SERVICE_ENGAGEMENT_ORPHAN_AFTER_PROOF_HOOK = None
_SERVICE_ENGAGEMENT_ORPHAN_BEFORE_DELETE_HOOK = None
_SERVICE_ENGAGEMENT_PURGE_CLEANUP_HOOK = None


def _service_engagement_date(value, field: str):
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{field} must be a string or null")
    value = (value or "").strip() or None
    if value:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            raise ValueError(f"{field} must be YYYY-MM-DD")
        try:
            date.fromisoformat(value)
        except ValueError:
            raise ValueError(f"{field} must be YYYY-MM-DD")
    return value


def _service_engagement_text(value, field: str, limit: int = 2000):
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{field} must be a string or null")
    value = (value or "").strip() or None
    if value and len(value) > limit:
        raise ValueError(f"{field} must be at most {limit} characters")
    return value


def _service_engagement_lines(value, field: str):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 50:
        raise ValueError(f"{field} must be an array of at most 50 strings")
    result = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{field} must contain strings")
        text = item.strip()
        if "\r" in item or "\n" in item:
            raise ValueError(f"{field} entries must not contain line breaks")
        if len(text) > 500:
            raise ValueError(f"{field} entries must be at most 500 characters")
        if text:
            result.append(text)
    return result


def _service_engagement_links(value, field: str):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 25:
        raise ValueError(f"{field} must be an array of at most 25 links")
    result = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError(f"{field} must contain link objects")
        raw_url = item.get("url")
        if isinstance(raw_url, str) and ("\r" in raw_url or "\n" in raw_url):
            raise ValueError(f"{field} URLs must not contain line breaks")
        label = _service_engagement_text(item.get("label"), f"{field}.label", 200)
        url = _service_engagement_text(raw_url, f"{field}.url", 1000)
        if "\r" in (label or "") or "\n" in (label or ""):
            raise ValueError(f"{field} labels must not contain line breaks")
        if "|" in (label or "") or "|" in (url or ""):
            raise ValueError(f"{field} labels and URLs must not contain |")
        if not url or urlparse(url).scheme not in {"http", "https"} or not urlparse(url).netloc:
            raise ValueError(f"{field} links must use an absolute http or https URL")
        result.append({"label": label or url, "url": url})
    return result


def _service_engagement_row(row):
    if not row:
        return None
    result = dict(row)
    for field in ("decisions", "owners", "exceptions", "project_links", "escalation_links"):
        raw = result.pop(f"{field}_json", "[]")
        try:
            result[field] = json.loads(raw or "[]")
        except (TypeError, json.JSONDecodeError) as exc:
            # Every write path (admin_service_engagement_put) only ever
            # writes json.dumps() of a validated list, so a decode failure
            # here means on-disk corruption or out-of-band tampering, not a
            # normal user input error. Fail soft (still return a usable row
            # rather than 500ing every read for this tenant) but don't fail
            # silent — this is worth an operator noticing.
            safe_tenant_id = str(result.get("tenant_id")).replace("\r", r"\r").replace("\n", r"\n")
            print(
                f"[WARN service-engagement] {field}_json for tenant_id={safe_tenant_id} "
                f"failed to decode, returning []: {exc}",
                file=sys.stderr,
            )
            result[field] = []
    return result


def _service_engagement_scope_error(request: Request, tenant_id: str, require_write: bool = False):
    """Keep a support-impersonation session inside its selected customer.

    Normal owner/consultant staff sessions are already authenticated and RBAC
    checked by api_bearer_auth. Impersonation adds a narrower tenant scope that
    generic `/admin/tenants/*` reads do not otherwise enforce server-side.
    """
    impersonation = _imp_get(request)
    if impersonation and impersonation.get("tenant_id") != tenant_id:
        return JSONResponse(
            {"error": "Forbidden — impersonation is scoped to another tenant."},
            status_code=403,
        )
    if impersonation and require_write and impersonation.get("write_mode") is not True:
        return JSONResponse(
            {"error": "Forbidden — impersonation write mode is disabled."},
            status_code=403,
        )
    return None


@app.get("/admin/tenants/{tenant_id}/service-engagement")
def admin_service_engagement_get(tenant_id: str, request: Request):
    scope_error = _service_engagement_scope_error(request, tenant_id)
    if scope_error:
        return scope_error
    with get_db() as db:
        tenant = db.execute("SELECT 1 FROM clients WHERE tenant_id=?", (tenant_id,)).fetchone()
        row = db.execute("SELECT * FROM service_engagements WHERE tenant_id=?", (tenant_id,)).fetchone()
    if not tenant:
        return JSONResponse({"error": "tenant not found in clients"}, status_code=404)
    return JSONResponse({"engagement": _service_engagement_row(row)})


@app.put("/admin/tenants/{tenant_id}/service-engagement")
async def admin_service_engagement_put(tenant_id: str, request: Request):
    scope_error = _service_engagement_scope_error(request, tenant_id, require_write=True)
    if scope_error:
        return scope_error
    try:
        data = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JSONResponse({"error": "request body must be valid JSON"}, status_code=400)
    if not isinstance(data, dict):
        return JSONResponse({"error": "request body must be a JSON object"}, status_code=400)
    expected_updated_at = data.get("expected_updated_at")
    if expected_updated_at is not None and not isinstance(expected_updated_at, str):
        return JSONResponse({"error": "expected_updated_at must be a string or null"}, status_code=400)
    service_name_value = data.get("service_name")
    if not isinstance(service_name_value, str):
        return JSONResponse({"error": "service_name must be a string"}, status_code=400)
    service_name = service_name_value.strip()
    if service_name not in _SERVICE_NAMES:
        return JSONResponse({"error": "service_name must be Endpoint Assurance, Managed Patching, or Full Endpoint Management"}, status_code=400)
    review_status_value = data.get("posture_review_status", "not_started")
    plan_status_value = data.get("plan_status", "not_started")
    if not isinstance(review_status_value, str):
        return JSONResponse({"error": "posture_review_status must be a string"}, status_code=400)
    if not isinstance(plan_status_value, str):
        return JSONResponse({"error": "plan_status must be a string"}, status_code=400)
    review_status = review_status_value.strip()
    plan_status = plan_status_value.strip()
    if review_status not in _POSTURE_REVIEW_STATUSES:
        return JSONResponse({"error": "invalid posture_review_status"}, status_code=400)
    if plan_status not in _PLAN_STATUSES:
        return JSONResponse({"error": "invalid plan_status"}, status_code=400)
    try:
        named_specialist = _service_engagement_text(data.get("named_specialist"), "named_specialist", 200)
        service_cadence = _service_engagement_text(data.get("service_cadence"), "service_cadence", 500)
        next_review_date = _service_engagement_date(data.get("next_review_date"), "next_review_date")
        plan_start_date = _service_engagement_date(data.get("plan_start_date"), "plan_start_date")
        plan_summary = _service_engagement_text(data.get("plan_summary"), "plan_summary", 4000)
        decisions = _service_engagement_lines(data.get("decisions"), "decisions")
        owners = _service_engagement_lines(data.get("owners"), "owners")
        exceptions = _service_engagement_lines(data.get("exceptions"), "exceptions")
        project_links = _service_engagement_links(data.get("project_links"), "project_links")
        escalation_links = _service_engagement_links(data.get("escalation_links"), "escalation_links")
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    now_iso = datetime.now(timezone.utc).isoformat()
    actor = _mirror_actor_email(request) or None
    with get_db() as db:
        tenant = db.execute("SELECT 1 FROM clients WHERE tenant_id=?", (tenant_id,)).fetchone()
        if not tenant:
            return JSONResponse({"error": "tenant not found in clients"}, status_code=404)
        current_row = db.execute(
            "SELECT * FROM service_engagements WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        before = _service_engagement_row(current_row)
        current_updated_at = current_row["updated_at"] if current_row else None
        if expected_updated_at != current_updated_at:
            return JSONResponse(
                {
                    "error": "service engagement changed since it was loaded",
                    "engagement": before,
                },
                status_code=409,
            )
        if _SERVICE_ENGAGEMENT_BEFORE_WRITE_HOOK:
            _SERVICE_ENGAGEMENT_BEFORE_WRITE_HOOK(db, tenant_id)
        write = db.execute("""
            INSERT INTO service_engagements (
                tenant_id, service_name, named_specialist, service_cadence,
                posture_review_status, next_review_date, plan_status,
                plan_start_date, plan_summary, decisions_json, owners_json,
                exceptions_json, project_links_json, escalation_links_json,
                updated_at, updated_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id) DO UPDATE SET
                service_name=excluded.service_name,
                named_specialist=excluded.named_specialist,
                service_cadence=excluded.service_cadence,
                posture_review_status=excluded.posture_review_status,
                next_review_date=excluded.next_review_date,
                plan_status=excluded.plan_status,
                plan_start_date=excluded.plan_start_date,
                plan_summary=excluded.plan_summary,
                decisions_json=excluded.decisions_json,
                owners_json=excluded.owners_json,
                exceptions_json=excluded.exceptions_json,
                project_links_json=excluded.project_links_json,
                escalation_links_json=excluded.escalation_links_json,
                updated_at=excluded.updated_at,
                updated_by=excluded.updated_by
            WHERE service_engagements.updated_at = ?
        """, (
            tenant_id, service_name, named_specialist, service_cadence,
            review_status, next_review_date, plan_status, plan_start_date,
            plan_summary, json.dumps(decisions), json.dumps(owners),
            json.dumps(exceptions), json.dumps(project_links),
            json.dumps(escalation_links), now_iso, actor, expected_updated_at,
        ))
        if write.rowcount != 1:
            current = db.execute(
                "SELECT * FROM service_engagements WHERE tenant_id=?", (tenant_id,)
            ).fetchone()
            return JSONResponse(
                {
                    "error": "service engagement changed since it was loaded",
                    "engagement": _service_engagement_row(current),
                },
                status_code=409,
            )
        row = db.execute("SELECT * FROM service_engagements WHERE tenant_id=?", (tenant_id,)).fetchone()
    after = _service_engagement_row(row)
    request.state.audit_before = json.dumps(before, sort_keys=True) if before else None
    request.state.audit_after = json.dumps(after, sort_keys=True)
    return JSONResponse({"engagement": after})


@app.delete("/admin/tenants/{tenant_id}/service-engagement")
def admin_service_engagement_delete(tenant_id: str, request: Request):
    scope_error = _service_engagement_scope_error(request, tenant_id, require_write=True)
    if scope_error:
        return scope_error
    with get_db() as db:
        tenant = db.execute("SELECT 1 FROM clients WHERE tenant_id=?", (tenant_id,)).fetchone()
        if not tenant:
            return JSONResponse({"error": "tenant not found in clients"}, status_code=404)
        row = db.execute("SELECT * FROM service_engagements WHERE tenant_id=?", (tenant_id,)).fetchone()
        if not row:
            return JSONResponse({"error": "service engagement not found"}, status_code=404)
        before = _service_engagement_row(row)
        db.execute("DELETE FROM service_engagements WHERE tenant_id=?", (tenant_id,))
    request.state.audit_before = json.dumps(before, sort_keys=True)
    request.state.audit_after = json.dumps(None)
    return JSONResponse({"deleted": True, "tenant_id": tenant_id})


def _platform_confirms_tenant_absent(tenant_id: str):
    """Use a tier-gated tenant-specific lookup as existence proof.

    Its subscription-tier middleware resolves the tenant row first and has a
    documented JSON 404 contract. The exact media type and body are required,
    so an edge/router/proxy 404 cannot authorize a local delete.
    """
    try:
        response = http.get(
            f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/allowlist",
            timeout=5,
            verify=_VERIFY_INTERNAL,
        )
    except Exception:
        return None
    if response.status_code == 404:
        content_type = str(response.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            return None
        try:
            payload = response.json()
        except Exception:
            return None
        return True if payload == {"error": "tenant not found"} else None
    if response.status_code in {200, 403}:
        return False
    return None


@app.get("/admin/tenants/{tenant_id}/service-engagement/orphan")
def admin_service_engagement_orphan_preview(tenant_id: str, request: Request):
    """Owner-only, audited read-before-repair for a platform-absent snapshot."""
    if _imp_get(request):
        return JSONResponse(
            {"error": "Orphan preview is unavailable during impersonation."}, status_code=403
        )
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM service_engagements WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
    if not row:
        return JSONResponse({"error": "orphaned service engagement not found"}, status_code=404)
    absent = _platform_confirms_tenant_absent(tenant_id)
    if absent is None:
        return JSONResponse(
            {"error": "Unable to prove the tenant is absent from the platform."}, status_code=503
        )
    if not absent:
        return JSONResponse(
            {"error": "Tenant still exists on the platform; snapshot is not an orphan."},
            status_code=409,
        )
    engagement = _service_engagement_row(row)
    request.state.audit_before = json.dumps(engagement, sort_keys=True)
    request.state.audit_after = json.dumps({"read_only": True}, sort_keys=True)
    # This is a full consultancy-engagement snapshot surfaced ahead of an
    # operator confirming repair — deny any intermediary caching of it.
    return JSONResponse(
        {"engagement": engagement, "platform_absent": True, "repair_available": True},
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
        },
    )


@app.delete("/admin/tenants/{tenant_id}/service-engagement/orphan")
def admin_service_engagement_orphan_repair(tenant_id: str, request: Request):
    """Retry local cleanup after an authoritative upstream purge succeeded.

    The normal service-engagement DELETE keeps its existing tenant/client 404
    boundary. This owner-only, confirmation-gated repair path additionally
    proves the tenant is absent from both platform indexes before deleting the
    orphan, so it cannot become an alternate delete route for a live tenant.
    """
    if _imp_get(request):
        return JSONResponse(
            {"error": "Orphan repair is unavailable during impersonation."},
            status_code=403,
        )
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM service_engagements WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
    if not row:
        return JSONResponse({"error": "orphaned service engagement not found"}, status_code=404)
    absent = _platform_confirms_tenant_absent(tenant_id)
    if absent is None:
        return JSONResponse(
            {"error": "Unable to prove the tenant is absent from the platform."},
            status_code=503,
        )
    if not absent:
        return JSONResponse(
            {"error": "Tenant still exists on the platform; orphan repair refused."},
            status_code=409,
        )
    if _SERVICE_ENGAGEMENT_ORPHAN_AFTER_PROOF_HOOK:
        _SERVICE_ENGAGEMENT_ORPHAN_AFTER_PROOF_HOOK(tenant_id)
    before_io = _service_engagement_row(row)
    with get_db() as db:
        db.execute("BEGIN IMMEDIATE")
        current_row = db.execute(
            "SELECT * FROM service_engagements WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        current_before = _service_engagement_row(current_row)
        if current_before != before_io:
            return JSONResponse(
                {
                    "error": "Service engagement changed while platform absence was checked; repair refused.",
                    "engagement": current_before,
                },
                status_code=409,
            )
        if _SERVICE_ENGAGEMENT_ORPHAN_BEFORE_DELETE_HOOK:
            _SERVICE_ENGAGEMENT_ORPHAN_BEFORE_DELETE_HOOK(db, tenant_id)
        expected_updated_at = current_row["updated_at"]
        deleted = db.execute(
            "DELETE FROM service_engagements WHERE tenant_id=? "
            "AND (updated_at = ? OR (updated_at IS NULL AND ? IS NULL))",
            (tenant_id, expected_updated_at, expected_updated_at),
        )
        if deleted.rowcount != 1:
            return JSONResponse(
                {"error": "Service engagement changed before repair deletion; repair refused."},
                status_code=409,
            )
    request.state.audit_before = json.dumps(current_before, sort_keys=True)
    request.state.audit_after = json.dumps(None)
    return JSONResponse({"deleted": True, "tenant_id": tenant_id, "repair": "orphan"})


_ONBOARDING_STATES = {"prospect", "onboarding", "active", "offboarded"}

_SUBSCRIPTION_TIERS = {"assurance", "managed"}
# Maps subscription_tier values to the SQLite billing_tier enum used for pricing.
# billing_tier itself stays the pre-existing report/patch/full pricing-band
# vocabulary (PAT-1599 collapsed subscription_tier, not the local billing/rates
# schema — that's a separate, larger migration; see PAT-1599 report-back).
# "managed" absorbs the old "patch" billing band since patch deployment is
# itself actuation under authorisation, i.e. "managed" per the PAT-1599
# definitions, not the read-only "assurance" band.
_SUB_TIER_TO_BILLING = {"assurance": "report", "managed": "full"}


@app.put("/admin/tenants/{tenant_id}/subscription-tier")
async def admin_subscription_tier_put(tenant_id: str, request: Request):
    """PAT-724: unified tier control — proxy to go-service and mirror SQLite."""
    data = await request.json()
    tier = (data.get("subscription_tier") or "").strip()
    if tier not in _SUBSCRIPTION_TIERS:
        return JSONResponse({"error": "subscription_tier must be assurance or managed"}, status_code=400)
    # PAT-799: entitlement/agent-config change — record before/after tier.
    # `after` is just `tier` (the subscription_tier enum: assurance/managed).
    # For `before`, the only locally-stored value is
    # `clients.billing_tier`, which is a DIFFERENT, coarser enum (report/
    # patch/full via _SUB_TIER_TO_BILLING) — comparing the two side by side
    # in the audit log would show a spurious "change" on a no-op save. The
    # console UI already knows the tenant's current subscription_tier (it's
    # what populated the dropdown) and sends it as X-Audit-Before, which the
    # auth middleware picks up automatically; only fall back to the mismatched
    # local column for non-UI (Bearer/script) callers that don't send it.
    if request.state.audit_before is None:
        with get_db() as db:
            before_row = db.execute("SELECT billing_tier FROM clients WHERE tenant_id=?", (tenant_id,)).fetchone()
        request.state.audit_before = before_row["billing_tier"] if before_row else None
    request.state.audit_after = tier
    r = await run_in_threadpool(http.put,
        f"{PATCHED_API_INTERNAL}/admin/tenant-tier/{_seg(tenant_id)}",
        json={"subscription_tier": tier, "updated_by": "dashboard"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    if r.status_code != 200:
        return _proxy_json(r)
    resp = r.json()
    billing_tier = _SUB_TIER_TO_BILLING.get(tier, "report")
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with get_db() as db:
        db.execute(
            "UPDATE clients SET agent_config_tier=?, agent_config_version=?, "
            "agent_config_issued_at=?, app_control_enabled=?, billing_tier=? "
            "WHERE tenant_id=?",
            (
                resp.get("agent_config_tier"),
                resp.get("agent_config_version"),
                now_iso,
                int(bool(resp.get("app_control_enabled"))),
                billing_tier,
                tenant_id,
            ),
        )
    return JSONResponse(resp)


@app.post("/admin/tenants/{tenant_id}/account")
async def admin_account_post(tenant_id: str, request: Request):
    data = await request.json()
    primary_name   = (data.get("primary_contact_name") or "").strip() or None
    primary_email  = (data.get("primary_contact_email") or "").strip() or None
    tech_name      = (data.get("technical_contact_name") or "").strip() or None
    tech_email     = (data.get("technical_contact_email") or "").strip() or None
    billing_name   = (data.get("billing_contact_name") or "").strip() or None
    billing_email  = (data.get("billing_contact_email") or "").strip() or None
    company_phone  = (data.get("company_phone") or "").strip() or None
    renewal_date   = (data.get("contract_renewal_date") or "").strip() or None
    state = (data.get("onboarding_state") or "").strip() or None
    if state and state not in _ONBOARDING_STATES:
        return JSONResponse({"error": f"invalid onboarding_state: {state!r}"}, status_code=400)
    notes_contract = data.get("contract_notes") or None
    notes_account  = data.get("account_notes") or None
    new_tier       = data.get("agent_config_tier") or None
    billing_tier = data.get("billing_tier")
    if billing_tier is not None and billing_tier not in _BILLING_TIERS:
        return JSONResponse({"error": f"invalid billing_tier: {billing_tier!r}"}, status_code=400)
    billing_freq = data.get("billing_frequency")
    if billing_freq is not None and billing_freq not in {"annual", "monthly"}:
        return JSONResponse({"error": f"invalid billing_frequency: {billing_freq!r}"}, status_code=400)
    app_control_enabled = data.get("app_control_enabled")
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with get_db() as db:
        existing = db.execute("SELECT tenant_id FROM clients WHERE tenant_id=?", (tenant_id,)).fetchone()
        if not existing:
            db.execute(
                "INSERT OR IGNORE INTO clients "
                "(id, company, tenant_id, created_at, "
                "primary_contact_name, primary_contact_email, "
                "technical_contact_name, technical_contact_email, "
                "billing_contact_name, billing_contact_email, "
                "company_phone, onboarding_state, contract_renewal_date, "
                "contract_notes, account_notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), tenant_id, tenant_id, now_iso,
                 primary_name, primary_email, tech_name, tech_email,
                 billing_name, billing_email, company_phone, state, renewal_date,
                 notes_contract, notes_account),
            )
        else:
            db.execute(
                "UPDATE clients SET "
                "primary_contact_name=?, primary_contact_email=?, "
                "technical_contact_name=?, technical_contact_email=?, "
                "billing_contact_name=?, billing_contact_email=?, "
                "company_phone=?, onboarding_state=?, contract_renewal_date=?, "
                "contract_notes=?, account_notes=? "
                "WHERE tenant_id=?",
                (primary_name, primary_email, tech_name, tech_email,
                 billing_name, billing_email, company_phone, state, renewal_date,
                 notes_contract, notes_account, tenant_id),
            )
        if billing_tier is not None:
            db.execute("UPDATE clients SET billing_tier=? WHERE tenant_id=?", (billing_tier, tenant_id))
        if billing_freq is not None:
            db.execute("UPDATE clients SET billing_frequency=? WHERE tenant_id=?", (billing_freq, tenant_id))
        if app_control_enabled is not None:
            db.execute("UPDATE clients SET app_control_enabled=? WHERE tenant_id=?", (int(bool(app_control_enabled)), tenant_id))
    if new_tier and new_tier in {"report_deploy", "patch"}:
        with get_db() as db:
            cfg_row = db.execute(
                "SELECT agent_config_tier, agent_proxy_mode, agent_proxy_type, "
                "agent_proxy_host, agent_proxy_port, agent_proxy_pac_url, "
                "agent_proxy_auth_ref, agent_proxy_bypass_when_off_corp "
                "FROM clients WHERE tenant_id=?", (tenant_id,),
            ).fetchone()
        cfg = dict(cfg_row) if cfg_row else {}
        try:
            r = await run_in_threadpool(http.put,
                f"{PATCHED_API_INTERNAL}/admin/agent-config/{_seg(tenant_id)}",
                json={"tier": new_tier, "proxy": {
                    "mode": cfg.get("agent_proxy_mode") or "system",
                    "type": cfg.get("agent_proxy_type"),
                    "host": cfg.get("agent_proxy_host"),
                    "port": cfg.get("agent_proxy_port"),
                    "pac_url": cfg.get("agent_proxy_pac_url"),
                    "auth_ref": cfg.get("agent_proxy_auth_ref"),
                    "bypass_when_off_corp": bool(cfg.get("agent_proxy_bypass_when_off_corp", False)),
                }, "updated_by": "dashboard"},
                timeout=10, verify=_VERIFY_INTERNAL,
            )
        except Exception as exc:
            print(f"[admin-account] agent-config push failed for {tenant_id}: {exc}")
            return JSONResponse(
                {"error": f"agent-config push failed: {exc}"}, status_code=502,
            )
        if r.status_code != 200:
            print(f"[admin-account] agent-config push for {tenant_id} returned {r.status_code}: {r.text[:200]}")
            return JSONResponse(
                {"error": f"agent-config push failed: upstream returned {r.status_code}"},
                status_code=502,
            )
        try:
            pr = r.json()
            with get_db() as db:
                db.execute(
                    "UPDATE clients SET agent_config_tier=?, agent_config_version=?, agent_config_issued_at=? "
                    "WHERE tenant_id=?",
                    (new_tier, pr.get("config_version"), now_iso, tenant_id),
                )
        except Exception as exc:
            # Upstream returned 200 but the body was unparseable, or the local
            # write failed — still surface this explicitly rather than lying
            # with {"ok": True} while the local tier stays stale.
            print(f"[admin-account] agent-config push for {tenant_id} succeeded upstream "
                  f"but local persist failed: {exc}")
            return JSONResponse(
                {"error": f"agent-config local persist failed: {exc}"}, status_code=502,
            )
    return JSONResponse({"ok": True})


@app.patch("/admin/tenants/{tenant_id}/stale-digest-config")
async def api_stale_digest_config_patch(tenant_id: str, request: Request):
    data = await request.json()
    enabled   = int(bool(data.get("stale_digest_enabled", True)))
    recipient = (data.get("stale_digest_recipient") or "").strip() or None
    threshold_raw = data.get("stale_digest_threshold_days")
    if threshold_raw in (None, "", 0, "0"):
        threshold = None
    else:
        try:
            threshold = int(threshold_raw)
        except (TypeError, ValueError):
            return JSONResponse({"error": "threshold_days must be an integer"}, status_code=400)
        if not (1 <= threshold <= 365):
            return JSONResponse({"error": "threshold_days must be 1-365"}, status_code=400)

    # PAT-575: optional fixed schedule. Empty/None clears it (back to legacy weekly).
    def _opt_int(raw, lo, hi, label):
        if raw in (None, ""):
            return None, None
        try:
            v = int(raw)
        except (TypeError, ValueError):
            return None, f"{label} must be an integer"
        if not (lo <= v <= hi):
            return None, f"{label} must be {lo}-{hi}"
        return v, None

    dow, err = _opt_int(data.get("stale_digest_day_of_week"), 0, 6, "day_of_week")
    if err:
        return JSONResponse({"error": err}, status_code=400)
    hour, err = _opt_int(data.get("stale_digest_hour"), 0, 23, "hour")
    if err:
        return JSONResponse({"error": err}, status_code=400)

    with get_db() as db:
        result = db.execute(
            "UPDATE clients SET stale_digest_enabled=?, stale_digest_threshold_days=?, "
            "stale_digest_recipient=?, stale_digest_day_of_week=?, stale_digest_hour=? "
            "WHERE tenant_id=?",
            (enabled, threshold, recipient, dow, hour, tenant_id),
        )
        if result.rowcount == 0:
            return JSONResponse({"error": "tenant not found in clients"}, status_code=404)
    return JSONResponse({"ok": True})


@app.put("/admin/tenants/{tenant_id}/allowlist-policy")
async def proxy_tenant_allowlist_policy(tenant_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.put,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/allowlist-policy",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.put("/admin/tenant-attestations/{tenant_id}/{control_id}")
async def proxy_tenant_attestation(tenant_id: str, control_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.put,
        f"{PATCHED_API_INTERNAL}/admin/tenant-attestations/{_seg(tenant_id)}/{_seg(control_id)}",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-218: Cert endpoints ──────────────────────────────────────────────────

@app.get("/api/tenant/{tenant_id}/certs")
def api_tenant_certs(tenant_id: str, request: Request):
    """Fetch certs from go-service, classify dashboard-side, apply ?type= filter."""
    params = {}
    if request.query_params.get("expiring_within_days"):
        params["expiring_within_days"] = request.query_params["expiring_within_days"]
    if request.query_params.get("device_id"):
        params["device_id"] = request.query_params["device_id"]

    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenant/{_seg(tenant_id)}/certs",
        params=params,
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    if r.status_code != 200:
        return JSONResponse(r.json() if r.content else {"error": "upstream error"}, status_code=r.status_code)

    raw = r.json()
    if not isinstance(raw, list):
        return JSONResponse(raw, status_code=r.status_code)

    enriched = _enrich_certificates(raw)

    type_filter = request.query_params.get("type", "")
    if type_filter:
        allowed = {t.strip() for t in type_filter.split(",") if t.strip()}
        enriched = [c for c in enriched if c["type"] in allowed]

    return JSONResponse(enriched)


@app.get("/api/tenant/{tenant_id}/cert-digest-config")
def api_cert_digest_config_get(tenant_id: str):
    with get_db() as db:
        row = db.execute(
            "SELECT cert_digest_enabled, cert_digest_recipient, cert_digest_severity, "
            "cert_digest_frequency, last_cert_digest_sent_at FROM clients WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
    if not row:
        return JSONResponse({"error": "tenant not found in clients"}, status_code=404)
    return JSONResponse(dict(row))


@app.patch("/api/tenant/{tenant_id}/cert-digest-config")
async def api_cert_digest_config_patch(tenant_id: str, request: Request):
    data = await request.json()
    enabled   = int(bool(data.get("cert_digest_enabled", True)))
    recipient = data.get("cert_digest_recipient") or None
    severity  = data.get("cert_digest_severity", "expired_plus_critical")
    frequency = data.get("cert_digest_frequency", "daily")

    valid_severities = {"expired_only", "expired_plus_critical", "expired_plus_warning", "all_categorised"}
    valid_frequencies = {"daily", "weekly", "monthly"}
    if severity not in valid_severities:
        return JSONResponse({"error": f"invalid severity: {severity}"}, status_code=400)
    if frequency not in valid_frequencies:
        return JSONResponse({"error": f"invalid frequency: {frequency}"}, status_code=400)

    with get_db() as db:
        result = db.execute(
            "UPDATE clients SET cert_digest_enabled=?, cert_digest_recipient=?, "
            "cert_digest_severity=?, cert_digest_frequency=? WHERE tenant_id=?",
            (enabled, recipient, severity, frequency, tenant_id),
        )
        if result.rowcount == 0:
            return JSONResponse({"error": "tenant not found in clients"}, status_code=404)
    return JSONResponse({"ok": True})


# ── PAT-539: Per-tenant report subscriptions (catalog + schedule config) ─────

@app.get("/admin/tenants/{tenant_id}/reports-config")
def api_reports_config_get(tenant_id: str):
    """Return the full catalog merged with this tenant's subscription state."""
    try:
        definitions = tuple(
            entry for entry in _report_catalogue() if entry["subject_scope"] == "tenant"
        )
    except ReportCatalogueUnavailable as exc:
        return JSONResponse(
            {"error": f"report catalogue unavailable: {exc}", "degraded": True}, status_code=503,
        )
    with get_db() as db:
        client = db.execute(
            "SELECT primary_contact_email, app_control_enabled, "
            "cert_digest_enabled, cert_digest_frequency, cert_digest_recipient, last_cert_digest_sent_at, "
            "stale_digest_enabled, stale_digest_recipient, last_stale_digest_sent_at "
            "FROM clients WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
        if not client:
            return JSONResponse({"error": "tenant not found"}, status_code=404)
        client = dict(client)

        subs_rows = db.execute(
            "SELECT report_type, enabled, frequency, recipient, last_sent_at "
            "FROM report_subscriptions WHERE tenant_id=?",
            (tenant_id,),
        ).fetchall()
    subs = {r["report_type"]: dict(r) for r in subs_rows}

    result = []
    for entry in definitions:
        rt = entry["type"]
        if rt == _REPORT_BRIDGE_CERT:
            row = {
                "type":              rt,
                "label":             entry["label"],
                "description":       entry["description"],
                "default_frequency": entry["default_frequency"],
                "enabled":           bool(client.get("cert_digest_enabled", 1)),
                "frequency":         client.get("cert_digest_frequency") or entry["default_frequency"],
                "recipient":         client.get("cert_digest_recipient"),
                "last_sent_at":      client.get("last_cert_digest_sent_at"),
                "bridge":            "cert",
            }
        elif rt == _REPORT_BRIDGE_STALE:
            row = {
                "type":              rt,
                "label":             entry["label"],
                "description":       entry["description"],
                "default_frequency": entry["default_frequency"],
                "enabled":           bool(client.get("stale_digest_enabled", 1)),
                "frequency":         "weekly",  # stale digest is fixed weekly
                "recipient":         client.get("stale_digest_recipient"),
                "last_sent_at":      client.get("last_stale_digest_sent_at"),
                "bridge":            "stale",
            }
        else:
            sub = subs.get(rt, {})
            # local-admin defaults to enabled for PAM tenants if no explicit row exists.
            default_enabled = (
                bool(client.get("app_control_enabled"))
                if rt == "local-admin" and rt not in subs
                else False
            )
            row = {
                "type":              rt,
                "label":             entry["label"],
                "description":       entry["description"],
                "default_frequency": entry["default_frequency"],
                "enabled":           bool(sub.get("enabled", default_enabled)),
                "frequency":         sub.get("frequency") or entry["default_frequency"],
                "recipient":         sub.get("recipient"),
                "last_sent_at":      sub.get("last_sent_at"),
            }
        row["primary_contact_email"] = client.get("primary_contact_email")
        result.append(row)

    return JSONResponse(result)


@app.patch("/admin/tenants/{tenant_id}/reports-config")
async def api_reports_config_patch(tenant_id: str, request: Request):
    """Enable/disable one report type and set its frequency + optional recipient."""
    data = await request.json()
    report_type = data.get("report_type")
    try:
        definition = _report_definition(report_type, subject_scope="tenant")
    except ReportCatalogueUnavailable as exc:
        return JSONResponse(
            {"error": f"report catalogue unavailable: {exc}", "degraded": True}, status_code=503,
        )
    if not definition:
        return JSONResponse({"error": f"unknown report_type: {report_type!r}"}, status_code=400)

    frequency = data.get("frequency", "monthly")
    if frequency not in _CERT_FREQ_HOURS:
        return JSONResponse({"error": f"invalid frequency: {frequency!r} (daily/weekly/monthly)"}, status_code=400)

    enabled   = bool(data.get("enabled", False))
    recipient = (data.get("recipient") or "").strip() or None
    if recipient and not _EMAIL_RE.match(recipient):
        return JSONResponse({"error": "invalid recipient email"}, status_code=400)

    with get_db() as db:
        if not db.execute("SELECT 1 FROM clients WHERE tenant_id=?", (tenant_id,)).fetchone():
            return JSONResponse({"error": "tenant not found"}, status_code=404)

        if report_type == _REPORT_BRIDGE_CERT:
            db.execute(
                "UPDATE clients SET cert_digest_enabled=?, cert_digest_frequency=?, "
                "cert_digest_recipient=? WHERE tenant_id=?",
                (int(enabled), frequency, recipient, tenant_id),
            )
        elif report_type == _REPORT_BRIDGE_STALE:
            db.execute(
                "UPDATE clients SET stale_digest_enabled=?, stale_digest_recipient=? "
                "WHERE tenant_id=?",
                (int(enabled), recipient, tenant_id),
            )
        else:
            db.execute(
                "INSERT INTO report_subscriptions "
                "(tenant_id, report_type, enabled, frequency, recipient) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(tenant_id, report_type) DO UPDATE SET "
                "enabled=excluded.enabled, frequency=excluded.frequency, "
                "recipient=excluded.recipient",
                (tenant_id, report_type, int(enabled), frequency, recipient),
            )
    return JSONResponse({"ok": True})


@app.get("/admin/tenants/{tenant_id}/reports/deliveries")
def api_tenant_report_deliveries(tenant_id: str):
    """Delivery history for a single tenant (most recent 50)."""
    with get_db() as db:
        rows = db.execute(
            "SELECT id, report_type, recipient, generated_at, sent_at, status "
            "FROM report_deliveries WHERE tenant_id=? ORDER BY generated_at DESC LIMIT 50",
            (tenant_id,),
        ).fetchall()
    return JSONResponse([dict(r) for r in rows])


# ── PAT-549: Enrolled device revocation ─────────────────────────────────────

@app.get("/admin/tenants/{tenant_id}/enrolled-devices")
def proxy_tenant_enrolled_devices(tenant_id: str):
    """List enrolled devices for a tenant — proxied to go-service."""
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/enrolled-devices",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/removal-summary")
def proxy_tenant_removal_summary(tenant_id: str):
    """Aggregate removal-execution states across all enrolled devices for a tenant."""
    _STATE_PRIORITY = {"failed": 5, "residual": 4, "manual": 3, "in-progress": 2, "queued": 1, "removed": 0}

    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/enrolled-devices",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    # PAT-1369: a non-200 here (including the synthetic "unreachable" response
    # on a ConnectionError/Timeout) must not collapse into the same
    # {"apps": {}} shape a tenant with genuinely zero removals returns, which
    # would report degraded as silently as PAT-912/PAT-837/PAT-960 did.
    if r.status_code != 200:
        return JSONResponse(
            {"apps": {}, "degraded": True, "error": f"enrolled-devices fetch returned {r.status_code}"},
            status_code=r.status_code,
        )
    if not r.content:
        return JSONResponse({"apps": {}})
    try:
        devices = r.json().get("devices") or []
    except Exception:
        return JSONResponse({"apps": {}})

    def _fetch_removals(device_id: str):
        try:
            dr = http.get(
                f"{PATCHED_API_INTERNAL}/admin/devices/{_seg(device_id)}/removals",
                timeout=8,
                verify=_VERIFY_INTERNAL,
            )
            if dr.status_code == 200 and dr.content:
                return dr.json().get("tasks") or []
        except Exception:
            pass
        return []

    apps: dict = {}
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_fetch_removals, d["id"]): d["id"] for d in devices if d.get("id")}
        for fut in as_completed(futures):
            for task in fut.result():
                name  = task.get("app_name") or task.get("name") or ""
                state = task.get("state") or ""
                if not name or not state:
                    continue
                if name not in apps:
                    apps[name] = {"state": state, "count": 1}
                else:
                    apps[name]["count"] += 1
                    if _STATE_PRIORITY.get(state, -1) > _STATE_PRIORITY.get(apps[name]["state"], -1):
                        apps[name]["state"] = state

    return JSONResponse({"apps": apps})


@app.post("/admin/devices/{device_id}/revoke")
def proxy_device_revoke(device_id: str):
    """Revoke a device — proxied to go-service (pull-based, no push to device)."""
    r = http.post(
        f"{PATCHED_API_INTERNAL}/admin/devices/{_seg(device_id)}/revoke",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-117: Patching rings endpoints ────────────────────────────────────────

@app.get("/admin/tenants/{tenant_id}/ring-config")
def proxy_ring_config_get(tenant_id: str):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/ring-config",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.put("/admin/tenants/{tenant_id}/ring-config")
async def proxy_ring_config_put(tenant_id: str, request: Request):
    before = None
    try:
        br = await run_in_threadpool(http.get, f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/ring-config", timeout=10, verify=_VERIFY_INTERNAL)
        if br.status_code == 200:
            before = json.dumps(br.json())
    except Exception:
        pass
    body = await request.body()
    r = await run_in_threadpool(http.put,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/ring-config",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    # PAT-799: rollout percentages/soak-gap/failure-threshold for the whole
    # tenant estate — record before/after for audit.
    request.state.audit_before = before
    request.state.audit_after = body.decode("utf-8", "replace")
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/ring-devices")
def proxy_ring_devices_get(tenant_id: str, request: Request):
    params = {}
    if request.query_params.get("cursor"):
        params["cursor"] = request.query_params["cursor"]
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/ring-devices",
        params=params,
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.put("/admin/tenants/{tenant_id}/ring-devices/{device_id}")
async def proxy_ring_device_override_put(tenant_id: str, device_id: str, request: Request):
    # PAT-799: unlike its siblings (ring-config, webhooks, App Control), this
    # route deliberately does NOT fetch a before-snapshot server-side. The
    # ring-devices list is paginated per-tenant and can run to thousands of
    # devices on a large estate — scanning it to find one device's current
    # override would trade a cheap single-device write for an unbounded GET.
    # The before/after audit context here comes entirely from the client's
    # X-Audit-Before/-After headers (the console UI already has the select's
    # old/new value; see _pdrSetOverride in console.html) — a non-UI/Bearer
    # caller that skips those headers gets a row with before=after=None, same
    # as any other optional audit context (e.g. reason) from a non-UI caller.
    body = await request.body()
    r = await run_in_threadpool(http.put,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/ring-devices/{_seg(device_id)}",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/ring-rollouts")
def proxy_ring_rollouts_get(tenant_id: str):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/ring-rollouts",
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# PAT-2299: the quarantined rollout-create proxy (PAT-1398) was removed. The
# console's "Start rollout" path went in PAT-2249 and the platform's create
# route in PAT-2246. Listing, pause, resume, skip and emergency stay for the
# retained rollout evidence view; a POST to the collection path is now a 405.


@app.post("/admin/tenants/{tenant_id}/ring-rollouts/{rollout_id}/pause")
async def proxy_ring_rollout_pause(tenant_id: str, rollout_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/ring-rollouts/{_seg(rollout_id)}/pause",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/ring-rollouts/{rollout_id}/resume")
async def proxy_ring_rollout_resume(tenant_id: str, rollout_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/ring-rollouts/{_seg(rollout_id)}/resume",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/ring-rollouts/{rollout_id}/skip")
async def proxy_ring_rollout_skip(tenant_id: str, rollout_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/ring-rollouts/{_seg(rollout_id)}/skip",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/ring-rollouts/{rollout_id}/emergency")
async def proxy_ring_rollout_emergency(tenant_id: str, rollout_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/ring-rollouts/{_seg(rollout_id)}/emergency",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-595: Automations ─────────────────────────────────────────────────────

@app.get("/admin/check-status")
def get_check_status():
    """Latest durable availability state for locally scheduled checks."""
    return JSONResponse({"checks": _get_check_statuses()})


# ── PAT-1303: operational truth page ─────────────────────────────────────────

@app.get("/admin/truth")
def get_truth_page():
    """The joined view: every entry in truth_manifest.yaml, evaluated against
    whatever evidence this box could actually collect for it. Absence of
    evidence is amber, never green, and never a dropped row -- see truth.py's
    module docstring. Goes through the existing /admin/* session-or-Bearer +
    RBAC middleware; no new auth path."""
    try:
        return JSONResponse(_build_truth_page())
    except truth.ManifestError as e:
        # Loud, visible failure -- a malformed manifest is a bug to fix, not
        # a page to silently blank out.
        return JSONResponse({"error": "truth_manifest.yaml is invalid", "detail": str(e)}, status_code=500)


@app.post("/admin/truth/report")
async def post_truth_report(request: Request):
    """Receives observations pushed by deploy/truth-report.sh, running on a
    box this app cannot read locally (api-01, portal-01 -- see that script's
    header comment). Guarded by the existing session-or-Bearer middleware,
    same as every other /admin/* route -- no new auth path, no new secret.

    Body shape: {"scope": "api-01", "observations": [
      {"entry_id": "...", "success": true|false|null, "detail": "...", "observed_at": "<iso8601>"},
      ...
    ]}
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON body required"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)

    scope = body.get("scope")
    observations = body.get("observations")
    if not isinstance(scope, str) or not scope:
        return JSONResponse({"error": "'scope' (string) required"}, status_code=400)
    if not isinstance(observations, list):
        return JSONResponse({"error": "'observations' (list) required"}, status_code=400)

    stored = 0
    errors = []
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        for i, obs in enumerate(observations):
            if not isinstance(obs, dict) or not obs.get("entry_id"):
                errors.append(f"observation #{i}: missing entry_id")
                continue
            success = obs.get("success")
            if success is not None and not isinstance(success, bool):
                errors.append(f"observation #{i} ({obs.get('entry_id')}): 'success' must be true/false/null")
                continue
            db.execute(
                "INSERT INTO truth_reports (scope, entry_id, success, detail, observed_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(scope, entry_id) DO UPDATE SET "
                "success=excluded.success, detail=excluded.detail, observed_at=excluded.observed_at",
                (scope, obs["entry_id"], success, str(obs.get("detail", ""))[:2000], obs.get("observed_at") or now_iso),
            )
            stored += 1

    return JSONResponse({"stored": stored, "errors": errors})


@app.post("/admin/nightly-checks/report")
async def post_nightly_check_report(request: Request):
    """PAT-1716: one result from a registered nightly uninstall E2E job --
    macOS (PAT-1714), Windows (PAT-1715), a future level-2 canary. See
    NIGHTLY_UNINSTALL_JOBS for the registered job list; an unregistered
    `job` is rejected rather than silently accepted, so a typo'd or
    not-yet-onboarded job name cannot masquerade as a passing check.

    Guarded by the existing session-or-Bearer middleware, same as every
    other /admin/* route -- no new auth path, no new secret. The reporting
    workflow runs on GitHub Actions and this box is not internet-exposed
    (Cloudflare Access sits in front of the public hostname), so it reaches
    this route the same way updater's daily-vendor-verify.yml already
    reaches this app's internal API today: join the tailnet with the
    existing TS_OAUTH_CLIENT_ID/TS_OAUTH_SECRET org secrets, SSH to
    patched-prod-01 with the existing DEPLOY_SSH_KEY org secret, and curl
    this route on the box's own loopback with the DASHBOARD_API_KEY already
    in /etc/patched-dashboard/dashboard.env. No new credential anywhere.

    Body: {"job": "nightly-uninstall-e2e-macos", "platform": "macos",
           "level": 1, "run_url": "https://...", "status": "pass"|"fail",
           "finished_at": "<iso8601>"}

    Report on success AND failure (if: always() on the workflow step) --
    only a report that arrives at all can move this check off unconfigured.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON body required"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)

    job = body.get("job")
    if not isinstance(job, str) or job not in _NIGHTLY_UNINSTALL_JOBS_BY_NAME:
        return JSONResponse(
            {"error": f"unknown job {job!r} -- not in NIGHTLY_UNINSTALL_JOBS"},
            status_code=400,
        )
    registered = _NIGHTLY_UNINSTALL_JOBS_BY_NAME[job]

    status = body.get("status")
    if status not in ("pass", "fail"):
        return JSONResponse({"error": "'status' must be 'pass' or 'fail'"}, status_code=400)

    now = datetime.now(timezone.utc)

    finished_at = body.get("finished_at")
    parsed_finished_at = truth._parse_iso(finished_at) if isinstance(finished_at, str) else None
    if parsed_finished_at is None:
        return JSONResponse({"error": "'finished_at' must be a parseable ISO 8601 timestamp"}, status_code=400)
    skew_seconds = (parsed_finished_at - now).total_seconds()
    if skew_seconds > _NIGHTLY_FUTURE_SKEW_TOLERANCE_SECONDS:
        return JSONResponse(
            {"error": f"'finished_at' is {truth._human_seconds(skew_seconds)} ahead of server time -- rejecting a future timestamp"},
            status_code=400,
        )

    # PAT-1716 follow-up: the job name is registered, but the body's own
    # platform/level are still caller-supplied -- a report for the macOS job
    # claiming platform "windows" (or the wrong level) must not be accepted
    # and rendered as if it described the registered job's own identity.
    # Still required in the body (not silently filled from the registry) so
    # a misconfigured workflow fails loudly instead of reporting under a
    # platform/level it never actually ran.
    platform = body.get("platform")
    if not isinstance(platform, str) or not platform:
        return JSONResponse({"error": "'platform' (string) required"}, status_code=400)
    if platform != registered["platform"]:
        return JSONResponse(
            {"error": f"'platform' {platform!r} does not match the registered platform "
                      f"{registered['platform']!r} for job {job!r}"},
            status_code=400,
        )

    level = body.get("level")
    if not isinstance(level, int) or isinstance(level, bool):
        return JSONResponse({"error": "'level' (integer) required"}, status_code=400)
    if level != registered["level"]:
        return JSONResponse(
            {"error": f"'level' {level!r} does not match the registered level "
                      f"{registered['level']!r} for job {job!r}"},
            status_code=400,
        )

    run_url = body.get("run_url")
    if not isinstance(run_url, str):
        run_url = ""

    _record_nightly_job_result(job, platform, level, run_url, status, finished_at, now)
    return JSONResponse({"ok": True, "job": job})


@app.get("/admin/automations")
def proxy_automations_list():
    r = http.get(f"{PATCHED_API_INTERNAL}/admin/automations", timeout=10, verify=_VERIFY_INTERNAL)
    return _proxy_json(r)


@app.get("/admin/automations/{job_name}/runs")
def proxy_automation_runs(job_name: str):
    r = http.get(f"{PATCHED_API_INTERNAL}/admin/automations/{_seg(job_name)}/runs", timeout=10, verify=_VERIFY_INTERNAL)
    return _proxy_json(r)


@app.post("/admin/automations/{job_name}/trigger")
async def proxy_automation_trigger(job_name: str, request: Request):
    # The API service currently performs real work only for this key. Do not
    # proxy arbitrary names: a recorded upstream no-op must not look like a
    # successful manual operation in the Console.
    if job_name != "installomator_sync":
        return JSONResponse({"error": "This automation is evidence-only and cannot be triggered from Dashboard."}, status_code=404)
    body = await request.body()
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/automations/{_seg(job_name)}/trigger",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=60,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-283: Agent config endpoints ─────────────────────────────────────────

@app.get("/api/tenant/{tenant_id}/agent-config")
def api_agent_config_get(tenant_id: str):
    with get_db() as db:
        row = db.execute(
            "SELECT agent_config_tier, agent_proxy_mode, agent_proxy_type, "
            "agent_proxy_host, agent_proxy_port, agent_proxy_pac_url, "
            "agent_proxy_auth_ref, agent_proxy_bypass_when_off_corp, "
            "agent_config_version, agent_config_issued_at, "
            "agent_update_channel, agent_pinned_version "
            "FROM clients WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
    if not row:
        return JSONResponse({"error": "tenant not found in clients"}, status_code=404)
    d = dict(row)
    d["agent_proxy_bypass_when_off_corp"] = bool(d["agent_proxy_bypass_when_off_corp"])
    return JSONResponse(d)


@app.patch("/api/tenant/{tenant_id}/agent-config")
async def api_agent_config_patch(tenant_id: str, request: Request):
    with get_db() as db:
        if not db.execute("SELECT 1 FROM clients WHERE tenant_id=?", (tenant_id,)).fetchone():
            return JSONResponse({"error": "tenant not found in clients"}, status_code=404)

    data = await request.json()

    tier = data.get("agent_config_tier", "report_deploy")
    if tier not in {"report_deploy", "patch"}:
        return JSONResponse({"error": f"invalid tier: {tier!r}"}, status_code=400)

    proxy_mode = data.get("agent_proxy_mode", "system")
    if proxy_mode not in {"system", "manual", "off"}:
        return JSONResponse({"error": f"invalid proxy mode: {proxy_mode!r}"}, status_code=400)

    proxy_type = data.get("agent_proxy_type") or None
    if proxy_type is not None and proxy_type not in {"http", "https", "socks5"}:
        return JSONResponse({"error": f"invalid proxy type: {proxy_type!r}"}, status_code=400)

    proxy_host   = data.get("agent_proxy_host") or None
    proxy_port_v = data.get("agent_proxy_port")
    proxy_port   = int(proxy_port_v) if proxy_port_v else None
    if proxy_port is not None and not (1 <= proxy_port <= 65535):
        return JSONResponse({"error": "proxy port must be 1–65535"}, status_code=400)
    proxy_pac_url  = data.get("agent_proxy_pac_url") or None
    proxy_auth_ref = data.get("agent_proxy_auth_ref") or None
    bypass         = int(bool(data.get("agent_proxy_bypass_when_off_corp", False)))

    # PAT-108: bootstrap loader channel + pinned version
    update_channel = data.get("update_channel", "stable")
    if update_channel not in {"stable", "beta"}:
        return JSONResponse({"error": f"invalid update_channel: {update_channel!r}"}, status_code=400)
    pinned_version = data.get("pinned_version") or None

    platform_body = {
        "tier": tier,
        "proxy": {
            "mode":                 proxy_mode,
            "type":                 proxy_type,
            "host":                 proxy_host,
            "port":                 proxy_port,
            "pac_url":              proxy_pac_url,
            "auth_ref":             proxy_auth_ref,
            "bypass_when_off_corp": bool(bypass),
        },
        "update_channel":  update_channel,
        "pinned_version":  pinned_version,
        "updated_by": "dashboard",
    }
    try:
        r = await run_in_threadpool(http.put,
            f"{PATCHED_API_INTERNAL}/admin/agent-config/{_seg(tenant_id)}",
            json=platform_body,
            timeout=10,
            verify=_VERIFY_INTERNAL,
        )
    except Exception as exc:
        return JSONResponse({"error": f"platform unreachable: {exc}"}, status_code=502)

    if r.status_code == 404:
        return JSONResponse({"error": "tenant not found on platform"}, status_code=404)
    if r.status_code != 200:
        return JSONResponse({"error": f"platform error {r.status_code}"}, status_code=502)

    pr             = r.json()
    config_version = pr.get("config_version")
    issued_at      = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with get_db() as db:
        result = db.execute(
            "UPDATE clients SET "
            "agent_config_tier=?, agent_proxy_mode=?, agent_proxy_type=?, "
            "agent_proxy_host=?, agent_proxy_port=?, agent_proxy_pac_url=?, "
            "agent_proxy_auth_ref=?, agent_proxy_bypass_when_off_corp=?, "
            "agent_config_version=?, agent_config_issued_at=?, "
            "agent_update_channel=?, agent_pinned_version=? "
            "WHERE tenant_id=?",
            (tier, proxy_mode, proxy_type, proxy_host, proxy_port, proxy_pac_url,
             proxy_auth_ref, bypass, config_version, issued_at,
             update_channel, pinned_version, tenant_id),
        )
        if result.rowcount == 0:
            return JSONResponse({"error": "tenant not found in clients"}, status_code=404)

    return JSONResponse({"ok": True, "config_version": config_version, "issued_at": issued_at})


@app.get("/certs", response_class=HTMLResponse)
def certs_view(request: Request):
    unauthorized = _require_dashboard_session(request)
    if unauthorized:
        return unauthorized
    tenant_id = request.query_params.get("tenant_id", "")
    certs, error, status_code = [], None, 200
    # PAT-2408: this query value is placed in an upstream path, so it must be a
    # canonical UUID like every other tenant id at the edge.
    if not _is_canonical_uuid(tenant_id):
        error, status_code = "Select an estate from the console to view its certificates.", 400
    else:
        try:
            response = http.get(
                f"{PATCHED_API_INTERNAL}/admin/tenant/{_seg(tenant_id)}/certs",
                timeout=15, verify=_VERIFY_INTERNAL,
            )
            raw = response.json() if response.status_code == 200 else None
            if not isinstance(raw, list):
                error, status_code = "Certificate inventory is unavailable. Try again shortly.", 503
            else:
                certs = _enrich_certificates(raw)
        except Exception:
            # Do not expose upstream bodies, internal addresses or credentials.
            error, status_code = "Certificate inventory is unavailable. Try again shortly.", 503
    return templates.TemplateResponse(
        request=request,
        name="certs.html",
        context={"certs": certs, "tenant_id": tenant_id, "error": error,
                 "console_build_id": CONSOLE_BUILD_ID},
        status_code=status_code,
        headers={"Cache-Control": "no-store"},
    )


# ── API: Freshness config (PAT-697) ──
# GET-only (consultant-safe): the single source of truth for device-freshness
# thresholds. The console injects DEVICE_FRESHNESS into the template context, but
# this endpoint lets any other tooling read the same numbers so nothing hard-codes
# its own bucket boundaries.
@app.get("/api/config/freshness")
async def get_freshness_config():
    return JSONResponse({
        "active_max_days": DEVICE_FRESHNESS["active_max_days"],
        "silent_min_days": DEVICE_FRESHNESS["silent_min_days"],
        "stale_digest_default_days": STALE_THRESHOLD_DEFAULT_DAYS,
    })


# ── PAT-698: cross-tenant triage queue ───────────────────────────────────────
# The Home page leads with a single, severity-ranked "needs attention" queue that
# folds signals from across every tenant into one actionable list. Aggregation is
# done dashboard-side (here) by fanning out over the EXISTING per-tenant proxies —
# no new upstream contract is invented. build_triage_queue() is a *pure* function
# (all inputs are already-fetched dicts) so it is unit-testable without touching
# the platform API; the endpoint below is the thin I/O shell around it.

# Severity ordering for the queue (lower sorts first).
_TRIAGE_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}

# Cap the (comparatively expensive) needs-attention fan-out: we rank tenants by
# the cheap signals already present in the overview payload and only pull the
# per-tenant join for the worst offenders.
TRIAGE_NA_FANOUT_CAP = 20


# ── PAT-673/674/678: health-bucket heuristic ─────────────────────────────────
# Used until PAT-147 health scoring is live on the platform API.
# Maps compliance_pct → (bucket, score) using the same thresholds as the tickets:
#   healthy ≥ 75 | watch 50–74 | at_risk < 50
# When health_score/health_bucket are eventually exposed by /admin/tenants/overview,
# swap these in here and remove the heuristic (the callers just read .bucket/.score).
GRAFANA_URL = os.getenv("GRAFANA_URL", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")


def _health_bucket_heuristic(compliance_pct) -> tuple:
    """Return (bucket, score) from compliance_pct. Heuristic until PAT-147 is live."""
    if compliance_pct is None:
        return ("watch", 50)
    score = int(round(float(compliance_pct)))
    if score >= 75:
        return ("healthy", score)
    elif score >= 50:
        return ("watch", score)
    else:
        return ("at_risk", score)


def _triage_tenant_signal_score(t: dict) -> int:
    """Cheap urgency proxy from a tenants/overview row — used only to decide which
    tenants are worth a needs-attention fan-out, never shown to the user."""
    s = 0
    s += (t.get("crit_high_fail_count") or 0) * 10
    s += (t.get("new_apps_awaiting_decision") or 0) * 3
    dc, a7 = t.get("device_count"), t.get("active_last_7d")
    if isinstance(dc, int) and isinstance(a7, int):
        s += max(0, dc - a7) * 2
    cp = t.get("compliance_pct")
    if isinstance(cp, (int, float)) and cp < 80:
        s += int(80 - cp)
    return s


def build_triage_queue(tenants, health, na_by_tenant=None, freshness=None):
    """Fold cross-tenant signals into one severity-ranked action queue.

    Inputs (all already fetched — no I/O here):
      tenants       list of tenants/overview rows
      health        the /admin/health payload (service_health.{cert_expiry,
                    ingestion_freshness})
      na_by_tenant  {tenant_id: needs-attention payload} for the fanned-out tenants
      freshness     DEVICE_FRESHNESS thresholds

    Returns a list of items sorted critical→info:
      {severity, kind, tenant_id, tenant_name, tab, title, detail, sort_weight}

    Stub upstream metrics (reports_generated, catalogue_job) are deliberately NOT
    consumed here — they are hard-coded/stub upstream and must never be surfaced
    as real signal.
    """
    tenants = tenants or []
    health = health or {}
    na_by_tenant = na_by_tenant or {}

    name_by_id = {t.get("id"): (t.get("name") or t.get("id")) for t in tenants}
    items = []

    def add(severity, kind, tenant_id, tab, title, detail, weight):
        items.append({
            "severity": severity, "kind": kind,
            "tenant_id": tenant_id,
            "tenant_name": name_by_id.get(tenant_id, tenant_id),
            "tab": tab, "title": title, "detail": detail,
            "sort_weight": weight,
        })

    # 1. Silent / stale devices per tenant (Phase-2 buckets, cheap overview data).
    for t in tenants:
        dc, a7 = t.get("device_count"), t.get("active_last_7d")
        if isinstance(dc, int) and isinstance(a7, int):
            silent = max(0, dc - a7)
            if silent > 0:
                sev = "critical" if silent >= 10 else ("high" if silent >= 3 else "medium")
                add(sev, "silent_devices", t.get("id"), "device-health",
                    "%d device%s not seen recently" % (silent, "" if silent == 1 else "s"),
                    "Enrolled but inactive in the last 7 days", silent)

    # 2. Blocked / failed patches (provenance failure_reason via needs-attention).
    #    Upstream shape (verified in the per-tenant Needs Attention tab): payload
    #    has .items[] with category in {vulnerable,out_of_date,blocked} and, for
    #    blocked rows, a .failure_reason; and a .summary.blocked count.
    for tid, na in na_by_tenant.items():
        if not isinstance(na, dict):
            continue
        blocked = [it for it in (na.get("items") or [])
                   if isinstance(it, dict) and it.get("category") == "blocked"]
        for it in blocked:
            reason = it.get("failure_reason") or "unknown"
            app = it.get("app_name") or "app"
            # PAT-1006: the needs-attention item shape is {device_id, hostname, ...}
            # (see go-service/internal/handlers/needs_attention.go) — there is no
            # "device_name" field. Reading it.get("device_name") always returned
            # None, so this line silently dropped the device from every blocked-
            # patch title. Same class of bug as the PAT-1004 device-detail
            # patch-outcome field mismatch — verified against the actual Go
            # struct before fixing, not assumed from the client's prior (wrong)
            # usage.
            dev = it.get("hostname") or ""
            add("critical", "blocked_patch", tid, "needs-attention",
                "Patch blocked: %s" % app,
                (dev + " — " if dev else "") + "reason: " + reason, 1000)
        if not blocked:
            summ = na.get("summary") or {}
            n = summ.get("blocked") or 0
            if n > 0:
                add("high", "blocked_patch", tid, "needs-attention",
                    "%d blocked patch%s" % (n, "" if n == 1 else "es"),
                    "Verification-blocked updates awaiting review", 500 + n)

    # 3. Expiring credentials / certs (reuse the health cert_expiry surface).
    sh = health.get("service_health") if isinstance(health.get("service_health"), dict) else health
    for c in (sh.get("cert_expiry") or [] if isinstance(sh, dict) else []):
        if not isinstance(c, dict):
            continue
        days = c.get("days_left")
        if not isinstance(days, (int, float)) or days > 30:
            continue
        sev = "critical" if days <= 7 else "high"
        label = c.get("name") or c.get("subject") or c.get("cn") or "certificate"
        add(sev, "cert_expiry", c.get("tenant_id"), "account",
            "Certificate expiring in %dd" % int(days), str(label), 2000 - int(days))

    # 4. Per-tenant ingestion lag (/admin/health ingestion_freshness.stalest_tenant).
    fresh = sh.get("ingestion_freshness") if isinstance(sh, dict) else None
    if isinstance(fresh, dict):
        stalest = fresh.get("stalest_tenant")
        if isinstance(stalest, dict) and stalest.get("tenant_name"):
            hrs = stalest.get("hours_stale") or 0
            if hrs > 12:
                sev = "critical" if hrs > 48 else "high"
                add(sev, "ingestion_lag", stalest.get("tenant_id"), "device-health",
                    "Ingestion lagging %dh" % int(hrs),
                    "No fresh telemetry received from this tenant", int(hrs))

    # 5. Critical/High CIS findings per tenant (cheap overview data).
    for t in tenants:
        crit = t.get("crit_high_fail_count")
        if isinstance(crit, int) and crit > 0:
            sev = "high" if crit >= 5 else "medium"
            add(sev, "cis_findings", t.get("id"), "needs-attention",
                "%d critical/high CIS failure%s" % (crit, "" if crit == 1 else "s"),
                "Endpoints failing critical or high controls", crit)

    # 6. Apps awaiting a policy decision (info-level backlog).
    for t in tenants:
        n = t.get("new_apps_awaiting_decision")
        if isinstance(n, int) and n > 0:
            add("info", "apps_review", t.get("id"), "software-catalogue",
                "%d app%s awaiting review" % (n, "" if n == 1 else "s"),
                "New software pending an approve/deny decision", n)

    items.sort(key=lambda x: (_TRIAGE_SEVERITY_ORDER.get(x["severity"], 9), -x["sort_weight"]))
    return items


# PAT-1006/1020: Home leads with patching posture, not CIS compliance, and is a
# tenant view, not a device queue (PAT-1020 removed the earlier per-device
# card — devices are reached by opening a tenant, not from Home directly). The
# helpers below turn the same already-fetched inputs (tenants overview +
# needs-attention fan-out) into estate-wide AND per-tenant patch counters —
# nothing here is approximated or invented.
#
# Sourcing, verified against the actual Go response shape (go-service/internal/
# handlers/needs_attention.go) before writing this — not assumed from the
# client's prior (buggy) field usage:
#   needsAttentionResp.ByDevice[] = {device_id, hostname, total, vulnerable,
#   out_of_date, blocked} — a genuine per-device rollup the platform already
#   computes, scoped to the one tenant the needs-attention call was made for.
#   That is the ONLY place an individual device's patch state lives;
#   tenantOverviewEntry (the /admin/tenants/overview row) has no device-level
#   or estate-wide "pending updates" field at all. There is also no estate- or
#   tenant-wide count of ATTEMPTED-AND-FAILED patch installs anywhere upstream
#   — that only exists per-device, in deviceDetailPatch.Outcome (go-service
#   internal/handlers/admin_overview.go), which would mean one HTTP call per
#   device to source from Home. "blocked" here means verification-blocked
#   (lp.state = 'verification_failed'), never "attempted and failed" — see
#   PAT-1019.
#
# Coverage caveat (real, not hidden): both are scoped to na_by_tenant, i.e. only
# the top TRIAGE_NA_FANOUT_CAP tenants ranked by _triage_tenant_signal_score —
# the same pre-existing fan-out cap every other per-tenant signal in
# build_triage_queue() already lives with. tenants_reviewed/tenants_total below
# let the UI say so plainly instead of implying full-estate coverage.
# devices_not_checked_in is the one exception: device_count/active_last_7d are
# on every tenants/overview row, so that counter genuinely covers the whole
# estate with no fan-out cap.


# PAT-1006 review: the upstream Go struct types these as ints, but this
# dashboard proxies an internal service over the network and must not trust the
# shape it gets back. An un-coerced value reached the client and was
# concatenated straight into innerHTML, and a non-numeric `total` raised
# TypeError on comparison — turning malformed upstream JSON into a 500 on Home
# and an XSS sink. Coerce here, at the boundary, so neither is reachable.
# PAT-1019 review: device_id is upstream-supplied and lands in a set. A list or
# dict there raised TypeError and 500'd /api/home/triage — the endpoint whose
# whole contract is that it degrades rather than errors. Coerce to a hashable
# string, or skip the row.
def _device_key(value):
    if value is None:
        return None
    if isinstance(value, (str, int)):
        key = str(value).strip()
        return key or None
    return None


def _count0(value):
    """Non-negative int, or 0 for anything that isn't one. Never raises."""
    if isinstance(value, bool):
        return 0
    try:
        n = int(value)
    except (TypeError, ValueError):
        return 0
    return n if n > 0 else 0


def _na_device_rows(na):
    """The by_device rows of a needs-attention payload, or [] if it is absent
    or not the expected shape. A dict/str/int here is malformed, not empty —
    see _na_has_device_data for how that distinction reaches the UI."""
    rows = na.get("by_device")
    if not isinstance(rows, list):
        return []
    return [d for d in rows if isinstance(d, dict)]


def _na_has_device_data(na):
    """True when this payload genuinely carried a by_device list. A response
    missing it, or carrying the wrong type, is UNAVAILABLE rather than clear —
    collapsing those two renders a confident all-clear over unknown data."""
    return isinstance(na, dict) and isinstance(na.get("by_device"), list)


def build_tenant_patch_stats(na_by_tenant):
    """Per-tenant device counts with pending updates / blocked patches (PAT-1020),
    grouped from the SAME already-fanned-out needs-attention payloads that feed
    build_estate_patch_stats() — just partitioned per tenant instead of summed
    estate-wide. No extra join is needed: na_by_tenant[tid] is already the
    needs-attention response scoped to that one tenant, so its by_device rows
    ARE that tenant's per-device rollup.

    Returns {tenant_id: {"devices_pending_update": n, "devices_blocked": n}} —
    only for tenants with a genuine by_device list. A tenant_id absent from the
    returned dict was NOT reviewed this run (outside the TRIAGE_NA_FANOUT_CAP
    fan-out, or its needs-attention call failed) — callers must not treat a
    missing key as "0 issues", only as "unknown this run".
    """
    na_by_tenant = na_by_tenant or {}
    out = {}
    for tid, na in na_by_tenant.items():
        if not _na_has_device_data(na):
            continue
        pending = set()
        blocked = set()
        for d in _na_device_rows(na):
            device_id = _device_key(d.get("device_id"))
            if device_id is None:
                continue
            if _count0(d.get("out_of_date")) > 0:
                pending.add(device_id)
            if _count0(d.get("blocked")) > 0:
                blocked.add(device_id)
        out[tid] = {
            "devices_pending_update": len(pending),
            "devices_blocked": len(blocked),
        }
    return out


# PAT-1067: agent-health mirrors the needs-attention fan-out shape above —
# one call per (fan-out-capped) tenant, grouped per tenant instead of per
# device, same "absent key means unreviewed, not clean" contract as
# build_tenant_patch_stats. Kept separate from that function (rather than
# merged) because the source payload shape is unrelated — devices[].degraded,
# not by_device[].out_of_date/blocked — and PAT-1029's four questions (what/
# why/since/how many) live entirely client-side per entry; the server-side
# rollup only needs "how many devices have at least one degraded entry".
def _ah_device_rows(ah):
    """The devices[] rows of an agent-health payload, or [] if absent or not
    the expected shape. Mirrors _na_device_rows."""
    rows = ah.get("devices") if isinstance(ah, dict) else None
    if not isinstance(rows, list):
        return []
    return [d for d in rows if isinstance(d, dict)]


def _ah_has_device_data(ah):
    """True when this payload genuinely carried a devices list — mirrors
    _na_has_device_data. A response missing it, or carrying the wrong type,
    is UNAVAILABLE rather than clear."""
    return isinstance(ah, dict) and isinstance(ah.get("devices"), list)


def build_tenant_agent_health_stats(ah_by_tenant):
    """Per-tenant count of devices with at least one degraded agent-health
    signal (PAT-1067), from /admin/tenants/{id}/agent-health, one call per
    tenant, same fan-out cap as needs-attention.

    Returns {tenant_id: {"devices_degraded": n}} — only for tenants with a
    genuine devices list. A tenant_id absent from the returned dict was NOT
    reviewed this run, exactly the same "absent means unknown, not clean"
    contract as build_tenant_patch_stats — callers must not treat a missing
    key as "0 degraded".
    """
    ah_by_tenant = ah_by_tenant or {}
    out = {}
    for tid, ah in ah_by_tenant.items():
        if not _ah_has_device_data(ah):
            continue
        degraded_devices = set()
        for d in _ah_device_rows(ah):
            device_id = _device_key(d.get("device_id"))
            if device_id is None:
                continue
            deg = d.get("degraded")
            if isinstance(deg, list) and len(deg) > 0:
                degraded_devices.add(device_id)
        out[tid] = {"devices_degraded": len(degraded_devices)}
    return out


def build_estate_patch_stats(tenants, na_by_tenant):
    """Estate-wide patch counters for the Home headline. See the module note
    above for exactly which parts are full-estate vs fan-out-scoped."""
    tenants = tenants or []
    na_by_tenant = na_by_tenant or {}

    not_checked_in = 0
    for t in tenants:
        dc, a7 = t.get("device_count"), t.get("active_last_7d")
        if isinstance(dc, int) and isinstance(a7, int):
            not_checked_in += max(0, dc - a7)

    pending_update_devices = set()
    blocked_devices = set()
    for na in na_by_tenant.values():
        if not isinstance(na, dict):
            continue
        for d in _na_device_rows(na):
            if not d.get("device_id"):
                continue
            did = _device_key(d.get("device_id"))
            if did is None:
                continue
            if _count0(d.get("out_of_date")) > 0:
                pending_update_devices.add(did)
            if _count0(d.get("blocked")) > 0:
                blocked_devices.add(did)

    return {
        "devices_pending_update": len(pending_update_devices),
        "devices_blocked": len(blocked_devices),
        "devices_not_checked_in": not_checked_in,
        # Coverage is the number of tenants that genuinely returned device
        # data, NOT the number we called. A tenant that answered without a
        # by_device list has not been reviewed, and counting it as such would
        # overstate how much of the estate these numbers cover.
        "tenants_reviewed": sum(1 for na in na_by_tenant.values() if _na_has_device_data(na)),
        "tenants_total": len(tenants),
        # The fan-out cap is the hard ceiling on coverage regardless of how
        # many tenants exist, so the UI can say "these numbers cover N of M".
        "fanout_cap": TRIAGE_NA_FANOUT_CAP,
    }


@app.get("/api/home/triage")
def home_triage(request: Request):
    """PAT-698: cross-tenant triage queue. Fans out over EXISTING per-tenant
    endpoints dashboard-side (capped) and returns a severity-ranked action list.

    Degrades gracefully: any upstream that is absent/unreachable simply
    contributes nothing — the panel shows a neutral state, never an error. The
    `sources` map lets the UI tell "nothing needs attention" (all sources ok, no
    items) apart from "not yet available" (no source reachable)."""
    sources = {"tenants": False, "health": False, "needs_attention": False, "agent_health": False}

    tenants = []
    try:
        r = http.get(f"{PATCHED_API_INTERNAL}/admin/tenants/overview", timeout=10, verify=_VERIFY_INTERNAL)
        if r.ok and r.content:
            tenants = (r.json() or {}).get("tenants") or []
            sources["tenants"] = True
    except Exception:
        pass

    health = {}
    try:
        r = http.get(f"{PATCHED_API_INTERNAL}/admin/health", timeout=15, verify=_VERIFY_INTERNAL)
        if r.ok and r.content:
            health = r.json() or {}
            sources["health"] = True
    except Exception:
        pass

    # Fan out needs-attention only for the worst-ranked tenants, with bounded
    # concurrency so a large estate can't stall the Home load.
    na_by_tenant = {}
    ranked = sorted(tenants, key=_triage_tenant_signal_score, reverse=True)[:TRIAGE_NA_FANOUT_CAP]

    def _fetch_na(tid):
        try:
            r = http.get(f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tid)}/needs-attention",
                         timeout=10, verify=_VERIFY_INTERNAL)
            if r.ok and r.content:
                return tid, r.json()
        except Exception:
            pass
        return tid, None

    ids = [t.get("id") for t in ranked if t.get("id")]
    if ids:
        with ThreadPoolExecutor(max_workers=min(6, len(ids))) as ex:
            for tid, payload in ex.map(_fetch_na, ids):
                if payload is not None:
                    na_by_tenant[tid] = payload
                    # Only claim this source is AVAILABLE when a response
                    # actually carried a structurally valid by_device list. A
                    # bare {} decodes fine and would otherwise mark the source
                    # up, rendering green zeros for pending/blocked instead of
                    # "not yet available" — a confident all-clear over data we
                    # never received.
                    if _na_has_device_data(payload):
                        sources["needs_attention"] = True

    # PAT-1067: same fan-out shape as needs-attention above, over the same
    # ranked/capped tenant set, for the degraded-agent signal PAT-1064 exposes.
    # A separate fan-out (rather than folding into _fetch_na) because it's an
    # independent upstream call with its own independent failure mode — one
    # going down must not take the other's sources flag with it.
    ah_by_tenant = {}

    def _fetch_ah(tid):
        try:
            r = http.get(f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tid)}/agent-health",
                         timeout=10, verify=_VERIFY_INTERNAL)
            if r.ok and r.content:
                return tid, r.json()
        except Exception:
            pass
        return tid, None

    if ids:
        with ThreadPoolExecutor(max_workers=min(6, len(ids))) as ex:
            for tid, payload in ex.map(_fetch_ah, ids):
                if payload is not None:
                    ah_by_tenant[tid] = payload
                    # Same "only claim available on a genuine devices list"
                    # discipline as needs_attention above.
                    if _ah_has_device_data(payload):
                        sources["agent_health"] = True

    items = build_triage_queue(tenants, health, na_by_tenant, DEVICE_FRESHNESS)
    patch_stats = build_estate_patch_stats(tenants, na_by_tenant)
    # PAT-1020: per-tenant breakdown (same source, grouped instead of summed)
    # feeds the "Tenants needing attention" row chips — Home is a tenant view,
    # not a per-device queue, so there is no separate device_queue key any more.
    tenant_patch_stats = build_tenant_patch_stats(na_by_tenant)
    # PAT-1067: per-tenant degraded-device count, feeding _homeTenantScore so a
    # tenant whose agents are quietly broken isn't filtered out of "Tenants
    # needing attention" (see the PAT-1019 comment on _homeTenantScore for why
    # a signal that doesn't contribute to the score is worse than not having it).
    tenant_agent_health_stats = build_tenant_agent_health_stats(ah_by_tenant)
    return JSONResponse({
        "items": items,
        "sources": sources,
        "patch_stats": patch_stats,
        "tenant_patch_stats": tenant_patch_stats,
        "tenant_agent_health_stats": tenant_agent_health_stats,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    })


# ── API: Metrics ──
@app.get("/api/metrics")
async def get_metrics():
    with get_db() as db:
        total_scans = db.execute("SELECT COUNT(*) FROM scans WHERE status='complete'").fetchone()[0]
        total_cves = db.execute("SELECT COALESCE(SUM(total_cves),0) FROM scans WHERE status='complete'").fetchone()[0]
        total_devices = db.execute("SELECT COALESCE(SUM(total_devices),0) FROM scans WHERE status='complete'").fetchone()[0]
        last_scan = db.execute("SELECT completed_at, company FROM scans WHERE status='complete' ORDER BY completed_at DESC LIMIT 1").fetchone()
        recent = db.execute(
            "SELECT id, company, completed_at, total_devices, total_cves, status, triggered_by "
            "FROM scans ORDER BY started_at DESC LIMIT 10"
        ).fetchall()

    return {
        "total_scans": total_scans,
        "total_cves": total_cves,
        "total_devices": total_devices,
        "last_scan_date": last_scan["completed_at"] if last_scan else None,
        "last_scan_company": last_scan["company"] if last_scan else None,
        "recent_scans": [dict(r) for r in recent],
    }


# ─────────────────────────────────────────────────────────────
# Endpoint Intelligence news feed  (PAT-542)
# Fetches a curated set of RSS feeds and returns the N most
# recent items. Cache TTL = 4 h; stale cache served on error.
# ─────────────────────────────────────────────────────────────

_NEWS_FEEDS = [
    {"id": "SANS ISC",       "url": "https://isc.sans.edu/rssfeed.xml",                                                           "type": "rss"},
    {"id": "MSRC",           "url": "https://msrc-blog.microsoft.com/feed/",                                                      "type": "rss"},
    {"id": "Malwarebytes",   "url": "https://www.malwarebytes.com/blog/feed/index.xml",                                           "type": "rss"},
    {"id": "BleepingComputer","url": "https://www.bleepingcomputer.com/feed/",                                                     "type": "rss"},
    {"id": "CISA KEV",       "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",        "type": "cisa_kev"},
]
_NEWS_ITEM_LIMIT = 8
_NEWS_CACHE: dict = {"items": [], "fetched_at": 0.0}
_NEWS_TTL = 4 * 3600


def _parse_rss_feed(source_id: str, xml_text: str) -> list:
    items = []
    try:
        root = _ET.fromstring(xml_text)
        channel = root.find("channel") or root
        for item in channel.findall("item")[:6]:
            title = (item.findtext("title") or "").strip()
            link  = (item.findtext("link") or "").strip()
            pub   = (item.findtext("pubDate") or "").strip()
            if not title or not link:
                continue
            try:
                from email.utils import parsedate_to_datetime
                dt = parsedate_to_datetime(pub).astimezone(timezone.utc).isoformat()
            except Exception:
                dt = None
            items.append({"source": source_id, "title": title, "url": link, "published_at": dt})
    except Exception:
        pass
    return items


def _parse_cisa_kev(source_id: str, json_text: str) -> list:
    items = []
    try:
        data = json.loads(json_text)
        vulns = sorted(data.get("vulnerabilities", []), key=lambda v: v.get("dateAdded", ""), reverse=True)
        for v in vulns[:6]:
            cve_id  = v.get("cveID", "")
            product = v.get("product", "")
            vendor  = v.get("vendorProject", "")
            title   = f"{cve_id} — {vendor} {product}".strip(" —")
            date    = v.get("dateAdded")
            dt      = f"{date}T00:00:00+00:00" if date else None
            items.append({"source": source_id, "title": title, "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "published_at": dt})
    except Exception:
        pass
    return items


def _report_send_audit_write(actor_email: str, tenant_id: str, tenant_name: str,
                              report_type: str, recipient: str, recipient_category: str,
                              outcome: str, detail: str = "") -> None:
    """Append one row to report_send_audit_log for every send attempt (success
    or failure). Best-effort — never breaks the request."""
    now = datetime.now(timezone.utc).isoformat()
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO report_send_audit_log "
                "(id, ts, actor_email, tenant_id, tenant_name, report_type, "
                "recipient, recipient_category, outcome, detail) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), now, actor_email or "unknown", tenant_id,
                 tenant_name or "", report_type, recipient, recipient_category or "",
                 outcome, detail or ""),
            )
    except Exception:
        pass


def _recipient_category(tenant_id: str, recipient: str) -> tuple[str, str]:
    """Classify a report recipient for the send-confirmation UI and audit log:
    primary contact, delivery contact, or external/ad-hoc. This dashboard has no
    local concept of a tenant portal user (that lives in the customer-facing
    portal app, PAT-711), so that category can never be resolved here — the
    ticket's "if known" carve-out covers this gap."""
    rlow = recipient.strip().lower()
    with get_db() as db:
        row = db.execute(
            "SELECT primary_contact_email FROM clients WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
    if row and row["primary_contact_email"] and row["primary_contact_email"].strip().lower() == rlow:
        return "primary", "Primary contact"
    try:
        r = http.get(
            f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/delivery-contacts",
            timeout=10, verify=_VERIFY_INTERNAL,
        )
        if r.status_code == 200:
            for c in (r.json() or []):
                if isinstance(c, dict) and (c.get("email") or "").strip().lower() == rlow:
                    label = c.get("label")
                    return "delivery", (f"Delivery contact — {label}" if label else "Delivery contact")
    except Exception:
        pass
    return "external", "External / ad-hoc"


@app.get("/admin/tenants/{tenant_id}/reports/recipient-category")
def api_report_recipient_category(tenant_id: str, recipient: str = ""):
    """Classify a prospective report recipient so the send-confirmation modal in
    console.html can call out primary/delivery contacts vs. external/ad-hoc."""
    recipient = (recipient or "").strip()
    if not recipient or not _EMAIL_RE.match(recipient):
        return JSONResponse({"error": "valid recipient email required"}, status_code=400)
    category, label = _recipient_category(tenant_id, recipient)
    return JSONResponse({"category": category, "label": label})


@app.post("/admin/tenants/{tenant_id}/reports/email")
async def proxy_report_email(tenant_id: str, request: Request):
    """Send any catalog report type as a PDF email attachment to the given
    recipient. Every attempt is written to report_send_audit_log — the
    confirmation step itself lives client-side (console.html); this route is
    the audited execution path it calls once the user has confirmed."""
    data = await request.json()
    report_type = data.get("report_type", "executive-summary")
    recipient   = (data.get("recipient") or "").strip()

    actor = (
        _session_decode(request.cookies.get(SESSION_COOKIE, ""))
        or _cf_email(request)
        or "unknown"
    )
    tname = _tenant_name_from_db(tenant_id)

    def _audit(outcome: str, detail: str = "", category: str = "") -> None:
        _report_send_audit_write(actor, tenant_id, tname, report_type, recipient, category, outcome, detail)

    if not recipient or not _EMAIL_RE.match(recipient):
        _audit("rejected", "invalid recipient email")
        return JSONResponse({"error": "valid recipient email required"}, status_code=400)
    if email_delivery_status() == "dry_run":
        # Refuse before consulting the catalogue too: an operator-initiated
        # email cannot be permitted to depend on an upstream response when the
        # configured delivery mode itself guarantees that no email is sent.
        _audit("dry_run", "EMAIL_DRY_RUN is set, no message was sent")
        return JSONResponse(
            {"error": "EMAIL_DRY_RUN is set, so no message was sent"},
            status_code=503,
        )
    try:
        definition = _report_definition(report_type, subject_scope="tenant")
    except ReportCatalogueUnavailable as exc:
        _audit("failed", f"report catalogue unavailable: {exc}")
        return JSONResponse(
            {"error": f"report catalogue unavailable: {exc}", "degraded": True}, status_code=503,
        )
    if not definition:
        _audit("rejected", f"unknown report_type: {report_type!r}")
        return JSONResponse({"error": f"unknown report_type: {report_type!r}"}, status_code=400)

    platform_path = _report_platform_path(definition, tenant_id=tenant_id)

    category, _category_label = _recipient_category(tenant_id, recipient)

    try:
        r = await run_in_threadpool(http.get,
            f"{PATCHED_API_INTERNAL}{platform_path}",
            timeout=30, verify=_VERIFY_INTERNAL,
        )
    except Exception as exc:
        _audit("failed", f"platform unreachable: {exc}", category)
        return JSONResponse({"error": f"platform unreachable: {exc}"}, status_code=502)
    if r.status_code != 200:
        _audit("failed", f"platform returned {r.status_code}", category)
        return JSONResponse({"error": f"platform returned {r.status_code}"}, status_code=r.status_code)

    label = definition["label"]
    subject, html_body, text_body = render_report_email(
        "report_attachment_email", estate_name=tname, report_label=label,
        period=datetime.now(timezone.utc).date().isoformat(),
    )
    display_name = email_display_label(tname)
    fname = f"{report_type}-{display_name.lower().replace(' ', '-')}.pdf"

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp.write(r.content)
        tmp_path = tmp.name

    try:
        ok = _send_email(recipient, subject, html_body, text_body,
                         attachment_path=tmp_path, attachment_name=fname)
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass

    if not ok:
        _audit("failed", "email delivery failed (mail provider)", category)
        return JSONResponse(
            {"error": "Email delivery failed — check the mail provider configuration and try again."},
            status_code=502,
        )

    _audit("sent", "", category)
    _log_report_delivery(tenant_id, report_type, tenant_name=tname, recipient=recipient)
    return JSONResponse({"ok": True})


def _fetch_news_items() -> list:
    all_items = []
    for feed in _NEWS_FEEDS:
        try:
            resp = http.get(feed["url"], timeout=8, headers={"User-Agent": "Patched-Dashboard/1.0"})
            resp.raise_for_status()
            if feed["type"] == "rss":
                all_items.extend(_parse_rss_feed(feed["id"], resp.text))
            elif feed["type"] == "cisa_kev":
                all_items.extend(_parse_cisa_kev(feed["id"], resp.text))
        except Exception:
            pass
    all_items.sort(key=lambda x: x.get("published_at") or "", reverse=True)
    return all_items[:_NEWS_ITEM_LIMIT]


@app.get("/api/news")
def api_news():
    """Endpoint intelligence feed — cached RSS + CISA KEV items, 4h TTL."""
    now = time.time()
    if now - _NEWS_CACHE["fetched_at"] < _NEWS_TTL and _NEWS_CACHE["items"]:
        return JSONResponse(_NEWS_CACHE["items"])
    items = _fetch_news_items()
    if items:
        _NEWS_CACHE["items"] = items
        _NEWS_CACHE["fetched_at"] = now
    return JSONResponse(_NEWS_CACHE["items"])


@app.get("/api/smoke/health")
async def smoke_health():
    """Liveness probe for the smoke test suite. Returns scheduler heartbeat and
    email delivery state.

    PAT-1346: email_dry_run is the raw flag and is kept for compatibility, but
    email_delivery is what the smoke gate asserts on. "not dry-run" is not the
    same as deliverable — with the flag off and no provider configured,
    _send_email() would fail on every send while this probe still looked fine.
    email_delivery_status() collapses both conditions into one tri-state.

    Protected by the standard Bearer middleware — no extra auth needed."""
    with get_db() as db:
        row = db.execute("SELECT value FROM kv WHERE key='scheduler_heartbeat'").fetchone()
    return JSONResponse({
        "scheduler_last_tick": row["value"] if row else None,
        "email_dry_run": EMAIL_DRY_RUN,
        "email_delivery": email_delivery_status(),
    })


# ── API: Upload-based Scan ──
# Zero-friction prospect path: no Graph app registration needed. The user
# uploads an Intune All-devices CSV (required) and optionally a detected-apps
# JSON. No client row is written — these are one-shot scans, not retainer
# clients with credentials we'd track.
@app.post("/api/scan/upload")
async def start_upload_scan(
    company: str = Form(...),
    devices_file: UploadFile = File(...),
    apps_file: UploadFile | None = File(None),
):
    company = (company or "").strip() or "Unnamed"

    tmp_dir = Path(tempfile.mkdtemp(prefix="patched_upload_"))

    # PAT-456 / C1: never build the on-disk path from the client filename —
    # UploadFile.filename is attacker-controlled and unsanitised. Sanitise to a
    # basename, then defence-in-depth resolve/relative_to check against tmp_dir.
    def _resolve_within(dirp, filename, default):
        p = dirp / _safe_filename(filename, default)
        try:
            p.resolve().relative_to(dirp.resolve())
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid upload filename.")
        return p

    dev_path = _resolve_within(tmp_dir, devices_file.filename, "devices.csv")
    dev_path.write_bytes(await devices_file.read())

    apps_path = None
    if apps_file is not None and apps_file.filename:
        apps_path = _resolve_within(tmp_dir, apps_file.filename, "apps.json")
        apps_path.write_bytes(await apps_file.read())

    job_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        db.execute(
            "INSERT INTO scans (id, company, tenant_id, started_at, status, triggered_by) "
            "VALUES (?, ?, '', ?, 'running', 'upload')",
            (job_id, company, now)
        )

    JOBS[job_id] = {"status": "running", "progress": 0, "messages": [], "error": None}

    def background():
        try:
            logo = str(BASE / "static" / "logo.png")
            ts = datetime.now().strftime("%Y%m%d_%H%M")
            safe = re.sub(r'[^\w\-]', '_', company)
            out = str(REPORTS_DIR / f"Patched_CVE_{safe}_{ts}.docx")
            scan_stats = {"devices": 0, "total_cves": 0}

            def on_progress(pct, msg):
                JOBS[job_id]["progress"] = pct
                JOBS[job_id]["messages"].append(msg)
                if "valid device" in msg.lower():
                    try:
                        n = int(re.search(r'(\d+)\s+valid', msg).group(1))
                        scan_stats["devices"] = n
                    except: pass

            run_scan_from_upload(
                devices_csv_path=str(dev_path),
                apps_file_path=str(apps_path) if apps_path else None,
                nvd_api_key=NVD_API_KEY, company_name=company,
                logo_path=logo, output_path=out, on_progress=on_progress,
            )

            for msg in JOBS[job_id]["messages"]:
                if "CVE(s)" in msg and "→" in msg:
                    try:
                        n = int(re.search(r'→\s*(\d+)\s+CVE', msg).group(1))
                        scan_stats["total_cves"] += n
                    except: pass

            JOBS[job_id]["status"] = "complete"
            JOBS[job_id]["progress"] = 100

            with get_db() as db:
                db.execute("""
                    UPDATE scans SET status='complete', completed_at=?,
                    total_devices=?, total_cves=?, report_path=? WHERE id=?
                """, (datetime.now(timezone.utc).isoformat(),
                      scan_stats["devices"], scan_stats["total_cves"], out, job_id))

        except Exception as e:
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["error"] = str(e)
            JOBS[job_id]["messages"].append(f"❌ {e}")
            with get_db() as db:
                db.execute("UPDATE scans SET status='error', error=? WHERE id=?", (str(e), job_id))
        finally:
            try:
                for p in tmp_dir.iterdir(): p.unlink(missing_ok=True)
                tmp_dir.rmdir()
            except: pass

    threading.Thread(target=background, daemon=True).start()
    return {"job_id": job_id}


# ── API: Scan Status ──
@app.get("/api/scan/{job_id}/status")
async def scan_status(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return JSONResponse({"error": "Job not found"}, 404)
    return {
        "status": job["status"],
        "progress": job["progress"],
        "messages": job["messages"][-30:],
        "error": job["error"],
    }


# ── PAT-1217: explicit in-app auth for download routes ──────────────────────
# The `/download`-suffix exemption in api_bearer_auth (above) exists so plain
# <a href> navigations work without an Authorization header — it was never
# meant to leave a route with NO credential of its own. `/reports/download/
# {token}` is the one deliberate exception (the token IS the credential); the
# two routes below had no credential at all and were silently relying on the
# now-removed Cloudflare Access edge bypass for /api/*.
#
# Session-cookie ONLY, deliberately — AGENTS.md: "CF Access (cookie-based)
# still authenticates these... don't re-enable bearer auth on the /download
# path." Bearer can't help a real <a href> navigation anyway (browsers don't
# attach it), and no caller of either route below is known to send one — this
# just makes the app enforce, itself, the same patched_session cookie CF
# Access already mints, instead of trusting the edge alone. That trust is what
# broke: an edge bypass rule silently covered /api/* for a period, which is
# exactly the failure mode this closes without touching the header the docs
# warn against.
def _require_dashboard_session(request: Request) -> JSONResponse | None:
    """Return a 401 JSONResponse if there's no valid `patched_session` cookie;
    otherwise return None (caller may proceed)."""
    email = _session_decode(request.cookies.get(SESSION_COOKIE, ""))
    if not email:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return None


# ── API: Download Report ──
@app.get("/api/scan/{job_id}/download")
async def download_report(job_id: str, request: Request):
    unauthorized = _require_dashboard_session(request)
    if unauthorized:
        return unauthorized
    with get_db() as db:
        row = db.execute("SELECT report_path FROM scans WHERE id=?", (job_id,)).fetchone()
    if not row or not row["report_path"] or not os.path.exists(row["report_path"]):
        return JSONResponse({"error": "Report not found"}, 404)
    return FileResponse(row["report_path"], filename=os.path.basename(row["report_path"]),
                        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")


# ── PAT-215: Credential expiry tracker ──────────────────────────────────────

@app.get("/api/credentials")
async def api_get_credentials():
    with get_db() as db:
        rows = db.execute("""
            SELECT id, name, service, description, expires_at, auto_refresh_source, notes, created_at, updated_at
            FROM credentials WHERE deleted_at IS NULL ORDER BY service, name
        """).fetchall()
    return JSONResponse([dict(r) for r in rows])


@app.post("/api/credentials")
async def api_create_credential(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON body required"}, status_code=400)
    name = (body.get("name") or "").strip()
    service = (body.get("service") or "").strip()
    if not name or not service:
        return JSONResponse({"error": "name and service are required"}, status_code=400)
    cred_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute("""
            INSERT INTO credentials (id, name, service, description, expires_at, auto_refresh_source, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (cred_id, name, service,
              body.get("description"), body.get("expires_at"),
              body.get("auto_refresh_source"), body.get("notes"),
              now, now))
    return JSONResponse({"id": cred_id, "ok": True})


@app.put("/api/credentials/{cred_id}")
async def api_update_credential(cred_id: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON body required"}, status_code=400)
    name = (body.get("name") or "").strip()
    service = (body.get("service") or "").strip()
    if not name or not service:
        return JSONResponse({"error": "name and service are required"}, status_code=400)
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute("SELECT id FROM credentials WHERE id=? AND deleted_at IS NULL", (cred_id,)).fetchone()
        if not row:
            return JSONResponse({"error": "not found"}, status_code=404)
        db.execute("""
            UPDATE credentials SET name=?, service=?, description=?, expires_at=?,
                auto_refresh_source=?, notes=?, updated_at=?
            WHERE id=?
        """, (name, service, body.get("description"), body.get("expires_at"),
              body.get("auto_refresh_source"), body.get("notes"), now, cred_id))
    return JSONResponse({"ok": True})


@app.delete("/api/credentials/{cred_id}")
async def api_delete_credential(cred_id: str):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            "UPDATE credentials SET deleted_at=? WHERE id=? AND deleted_at IS NULL",
            (now, cred_id)
        )
    return JSONResponse({"ok": True})


# ── PAT-558: App deploy-ring assignments (local, dashboard-only) ──────────────
# Stores pilot|general|deferred ring per (identifier, tenant). Enforcement is
# future work; this ticket covers the data model and UI only.

@app.get("/admin/tenants/{tenant_id}/app-rings")
def api_app_rings_get(tenant_id: str):
    with get_db() as db:
        rows = db.execute(
            "SELECT identifier, ring, updated_at FROM app_deploy_rings WHERE tenant_id=?",
            (tenant_id,),
        ).fetchall()
    return JSONResponse({"rings": [{"identifier": r[0], "ring": r[1], "updated_at": r[2]} for r in rows]})


@app.patch("/admin/tenants/{tenant_id}/app-rings/{identifier:path}")
async def api_app_rings_patch(tenant_id: str, identifier: str, request: Request):
    body = await request.json()
    ring = body.get("ring", "")
    if ring not in ("pilot", "general", "deferred"):
        return JSONResponse({"error": "ring must be pilot, general, or deferred"}, status_code=400)
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            """INSERT INTO app_deploy_rings (identifier, tenant_id, ring, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT (identifier, tenant_id) DO UPDATE
               SET ring=excluded.ring, updated_at=excluded.updated_at""",
            (identifier, tenant_id, ring, now),
        )
    return JSONResponse({"ok": True, "identifier": identifier, "ring": ring})


# ── PAT-779: per-tenant operator runbook / notes (local, dashboard-only) ─────
# Internal-operator-only per the ticket — never proxied to the customer portal.
# Soft-deleted (deleted_at) so history survives an accidental delete.
_RUNBOOK_CATEGORIES = {"onboarding", "support", "deployment", "reporting", "billing", "technical", "other"}


def _runbook_actor(request: Request) -> str:
    return (
        _session_decode(request.cookies.get(SESSION_COOKIE, ""))
        or _cf_email(request)
        or "unknown"
    )


@app.get("/admin/tenants/{tenant_id}/runbook-notes")
def api_runbook_notes_list(tenant_id: str):
    with get_db() as db:
        rows = db.execute("""
            SELECT id, tenant_id, title, body, category, pinned, created_by, updated_by, created_at, updated_at
            FROM tenant_runbook_notes
            WHERE tenant_id=? AND deleted_at IS NULL
            ORDER BY pinned DESC, updated_at DESC
        """, (tenant_id,)).fetchall()
    return JSONResponse({"notes": [dict(r) for r in rows]})


@app.post("/admin/tenants/{tenant_id}/runbook-notes")
async def api_runbook_notes_create(tenant_id: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON body required"}, status_code=400)
    title = (body.get("title") or "").strip()
    if not title:
        return JSONResponse({"error": "title is required"}, status_code=400)
    category = body.get("category") or "other"
    if category not in _RUNBOOK_CATEGORIES:
        return JSONResponse({"error": f"invalid category: {category!r}"}, status_code=400)
    note_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    actor = _runbook_actor(request)
    with get_db() as db:
        db.execute("""
            INSERT INTO tenant_runbook_notes
                (id, tenant_id, title, body, category, pinned, created_by, updated_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (note_id, tenant_id, title, body.get("body") or "", category,
              1 if body.get("pinned") else 0, actor, actor, now, now))
    return JSONResponse({"id": note_id, "ok": True})


@app.put("/admin/tenants/{tenant_id}/runbook-notes/{note_id}")
async def api_runbook_notes_update(tenant_id: str, note_id: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON body required"}, status_code=400)
    title = (body.get("title") or "").strip()
    if not title:
        return JSONResponse({"error": "title is required"}, status_code=400)
    category = body.get("category") or "other"
    if category not in _RUNBOOK_CATEGORIES:
        return JSONResponse({"error": f"invalid category: {category!r}"}, status_code=400)
    now = datetime.now(timezone.utc).isoformat()
    actor = _runbook_actor(request)
    with get_db() as db:
        row = db.execute(
            "SELECT id FROM tenant_runbook_notes WHERE id=? AND tenant_id=? AND deleted_at IS NULL",
            (note_id, tenant_id),
        ).fetchone()
        if not row:
            return JSONResponse({"error": "not found"}, status_code=404)
        db.execute("""
            UPDATE tenant_runbook_notes
            SET title=?, body=?, category=?, pinned=?, updated_by=?, updated_at=?
            WHERE id=? AND tenant_id=?
        """, (title, body.get("body") or "", category, 1 if body.get("pinned") else 0,
              actor, now, note_id, tenant_id))
    return JSONResponse({"ok": True})


@app.delete("/admin/tenants/{tenant_id}/runbook-notes/{note_id}")
async def api_runbook_notes_delete(tenant_id: str, note_id: str, request: Request):
    now = datetime.now(timezone.utc).isoformat()
    actor = _runbook_actor(request)
    with get_db() as db:
        db.execute("""
            UPDATE tenant_runbook_notes SET deleted_at=?, updated_by=?, updated_at=?
            WHERE id=? AND tenant_id=? AND deleted_at IS NULL
        """, (now, actor, now, note_id, tenant_id))
    return JSONResponse({"ok": True})


# ── PAT-370: Report delivery infrastructure proxy routes ──────────────────────
# These proxy through to the Go service admin API; the dashboard never handles
# schedule/contact/record state itself — Postgres on patched-api-01 is the source
# of truth.  Download endpoints end with /download so they're exempt from Bearer
# auth per the existing middleware carve-out (browsers can't send custom headers
# on <a href> navigations).

@app.get("/admin/tenants/{tenant_id}/delivery-contacts")
def proxy_delivery_contacts_list(tenant_id: str):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/delivery-contacts",
        timeout=10, verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/delivery-contacts")
async def proxy_delivery_contact_create(tenant_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/delivery-contacts",
        data=body, headers={"Content-Type": "application/json"},
        timeout=10, verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.put("/admin/tenants/{tenant_id}/delivery-contacts/{contact_id}")
async def proxy_delivery_contact_update(tenant_id: str, contact_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.put,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/delivery-contacts/{_seg(contact_id)}",
        data=body, headers={"Content-Type": "application/json"},
        timeout=10, verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.delete("/admin/tenants/{tenant_id}/delivery-contacts/{contact_id}")
def proxy_delivery_contact_delete(tenant_id: str, contact_id: str):
    r = http.delete(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/delivery-contacts/{_seg(contact_id)}",
        timeout=10, verify=_VERIFY_INTERNAL,
    )
    if r.status_code == 204:
        return JSONResponse({}, status_code=204)
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/report-schedules")
def proxy_report_schedules_list(tenant_id: str):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/report-schedules",
        timeout=10, verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/report-schedules")
async def proxy_report_schedule_create(tenant_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/report-schedules",
        data=body, headers={"Content-Type": "application/json"},
        timeout=10, verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.put("/admin/tenants/{tenant_id}/report-schedules/{schedule_id}")
async def proxy_report_schedule_update(tenant_id: str, schedule_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.put,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/report-schedules/{_seg(schedule_id)}",
        data=body, headers={"Content-Type": "application/json"},
        timeout=10, verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.delete("/admin/tenants/{tenant_id}/report-schedules/{schedule_id}")
def proxy_report_schedule_delete(tenant_id: str, schedule_id: str):
    r = http.delete(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/report-schedules/{_seg(schedule_id)}",
        timeout=10, verify=_VERIFY_INTERNAL,
    )
    if r.status_code == 204:
        return JSONResponse({}, status_code=204)
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/report-records")
def proxy_report_records_list(tenant_id: str, request: Request):
    params = dict(request.query_params)
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/report-records",
        params=params, timeout=15, verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/report-records/generate")
async def proxy_report_records_generate(tenant_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/report-records/generate",
        data=body, headers={"Content-Type": "application/json"},
        timeout=120, verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/report-records/{record_id}/download")
def proxy_report_record_download(tenant_id: str, record_id: str, request: Request):
    """Proxy the file download from Go service — streams PDF or XLSX back to the browser.
    Ends with /download so it is exempt from the Bearer middleware (browser downloads
    can't attach Authorization headers via <a href>). PAT-1217: relying on the CF Access
    cookie alone was fragile — it depended on /admin/* never having an edge bypass rule,
    which is accidental rather than a designed control. Hardened with the same explicit
    session-cookie check as /api/scan/{job_id}/download (see the comment there — no
    Bearer, per AGENTS.md), for defense in depth.
    """
    unauthorized = _require_dashboard_session(request)
    if unauthorized:
        return unauthorized
    fmt = request.query_params.get("format", "pdf")
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/report-records/{_seg(record_id)}/download",
        params={"format": fmt}, timeout=30, verify=_VERIFY_INTERNAL,
    )
    if r.status_code != 200:
        return _proxy_json(r)
    ct = r.headers.get("Content-Type", "application/octet-stream")
    cd = r.headers.get("Content-Disposition", "attachment")
    from starlette.responses import Response
    return Response(content=r.content, media_type=ct, headers={"Content-Disposition": cd})


# ── PAT-1405: Authored Endpoint Assurance artifact workflow ────────────────
# The dashboard authenticates the individual staff member. The platform owns
# the immutable metadata and bytes; neither route accepts a filesystem path.
#
# Size-limit source of truth: the Go platform enforces a hard per-document
# ceiling of 25 MiB on approve (go-service/internal/handlers/
# assessment_artifacts.go: `maxAssessmentArtifactBytes = 25 << 20`; the
# document itself is read with `io.LimitReader(file, maxAssessmentArtifactBytes+1)`
# and rejected with 400 if it's longer), independent of whatever the
# dashboard's own pre-flight check allows through — so no document over
# 25 MiB can ever actually be approved/stored regardless of this constant.
# Both of the dashboard's own checks (the approve pre-flight body-size gate
# and the download post-fetch content-size gate) are pinned to the same
# constant here so the two numbers are self-evidently consistent rather
# than two independently-chosen literals that happen to agree today and
# silently drift apart later (PAT-1405 security review finding).
_ASSESSMENT_DOCUMENT_MAX_BYTES = 25 << 20
# Multipart/form overhead allowance on the approve route mirrors the
# platform's own `http.MaxBytesReader(w, r.Body, maxAssessmentArtifactBytes+(1<<20))`.
_ASSESSMENT_APPROVE_BODY_MAX_BYTES = _ASSESSMENT_DOCUMENT_MAX_BYTES + (1 << 20)

# Fixed allowlist for the download-token-issue response: project the upstream
# platform payload onto exactly these fields (see IssueAssessmentDownloadTokenHandler's
# response contract: token/expires_at/recipient/artifact_id) rather than
# relaying it verbatim, so "the dashboard never forwards a filesystem path"
# is structurally enforced instead of merely true-today because the platform
# happens not to emit one (PAT-1405 security review finding).
_ASSESSMENT_TOKEN_RESPONSE_FIELDS = ("expires_at", "recipient", "artifact_id")


async def _read_capped_body(request: Request, max_bytes: int, too_large_message: str = "request body too large"):
    """Read a raw request body, rejecting an oversized payload before it is
    fully buffered into memory. Same Content-Length-precheck + streaming-
    running-cap idiom as `_read_capped_json` below (used by the catalogue
    routes), generalized for a non-JSON (e.g. multipart) body that must be
    forwarded upstream byte-for-byte rather than parsed.
    Returns (data, None) on success or (None, JSONResponse) on error."""
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > max_bytes:
                return None, JSONResponse({"error": too_large_message}, status_code=413)
        except ValueError:
            return None, JSONResponse({"error": "invalid Content-Length"}, status_code=400)
    chunks = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_bytes:
            return None, JSONResponse({"error": too_large_message}, status_code=413)
        chunks.append(chunk)
    return b"".join(chunks), None


@app.post("/admin/tenants/{tenant_id}/assessment-artifacts/approve")
async def proxy_assessment_artifact_approve(tenant_id: str, request: Request):
    try:
        tenant_id = str(uuid.UUID(tenant_id))
    except (ValueError, AttributeError):
        return JSONResponse({"error": "Invalid tenant identifier."}, status_code=400)
    actor = _mirror_actor_email(request)
    if not actor or actor == "bearer-token":
        return JSONResponse(
            {"error": "An authenticated named staff session is required for approval."},
            status_code=403,
        )
    # PAT-1405 security review: check Content-Type before touching the body
    # at all (cheap, no read required), and match on the media type only —
    # split off any `; boundary=...` parameter rather than a literal
    # `.startswith("multipart/form-data;")`, which incorrectly rejected a
    # legitimate (if unusual) boundary-less `Content-Type: multipart/form-data`
    # header with a generic 400 instead of letting real type-checking run.
    # This inbound check (this repo has no app-wide CSRF-token mechanism —
    # SameSite=Lax on `patched_session`, shared by every /admin/* write
    # route, is the primary cross-site control; see the comment on the
    # download-tokens route below) also closes off a cross-site
    # `enctype="text/plain"` body-smuggling attempt as defense-in-depth,
    # independent of SameSite enforcement.
    content_type = request.headers.get("content-type", "")
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type != "multipart/form-data":
        return JSONResponse({"error": "multipart/form-data is required."}, status_code=400)
    # Stream with a running cap instead of `await request.body()`, so an
    # oversized upload is rejected before it is fully buffered into memory
    # rather than after (PAT-1405 security review finding).
    body, err = await _read_capped_body(
        request, _ASSESSMENT_APPROVE_BODY_MAX_BYTES, "Assessment document is too large."
    )
    if err:
        return err
    try:
        r = await run_in_threadpool(
            http.post,
            f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/assessment-artifacts/approve",
            data=body,
            headers={"Content-Type": content_type, "X-Patched-Actor-Email": actor},
            timeout=60,
            verify=_VERIFY_INTERNAL,
        )
    except Exception as exc:
        print(f"[assessment-approve] platform request failed: {exc}")
        return JSONResponse({"error": "platform unreachable"}, status_code=502)
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/assessment-artifacts/{artifact_id}/download-tokens")
async def proxy_assessment_download_token_issue(tenant_id: str, artifact_id: str, request: Request):
    try:
        tenant_id = str(uuid.UUID(tenant_id))
        artifact_id = str(uuid.UUID(artifact_id))
    except (ValueError, AttributeError):
        return JSONResponse({"error": "Invalid tenant or artifact identifier."}, status_code=400)
    actor = _mirror_actor_email(request)
    if not actor or actor == "bearer-token":
        return JSONResponse(
            {"error": "An authenticated named staff session is required to issue a recipient link."},
            status_code=403,
        )
    # PAT-1405 security review: this repo has no app-wide CSRF-token
    # mechanism (grepped — none exists). The primary cross-site control for
    # every /admin/* write route, this one included, is SameSite=Lax on the
    # `patched_session` cookie (set in the login response handler), which
    # modern browsers do not attach to a cross-site POST/PUT/DELETE/PATCH at
    # all — including a classic cross-site <form enctype="text/plain"> POST,
    # since POST is not a "safe" method eligible for Lax's top-level-
    # navigation exemption. That protection is shared automatically by every
    # write route via the session-cookie config, not something to reinvent
    # per-route. What IS route-specific and was genuinely missing: an
    # inbound Content-Type check. Without one, a request whose body merely
    # *parses* as JSON got relayed to the platform as `Content-Type:
    # application/json` regardless of what the client actually sent —
    # closing that (independent of whether SameSite holds in some future
    # browser/proxy edge case) is the defense-in-depth fix here.
    content_type = request.headers.get("content-type", "")
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        return JSONResponse({"error": "application/json is required."}, status_code=400)
    body, err = await _read_capped_body(request, 1 << 14, "Request body is too large.")
    if err:
        return err
    try:
        r = await run_in_threadpool(
            http.post,
            f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/assessment-artifacts/"
            f"{_seg(artifact_id)}/download-tokens",
            data=body,
            headers={"Content-Type": "application/json", "X-Patched-Actor-Email": actor},
            timeout=15,
            verify=_VERIFY_INTERNAL,
        )
    except Exception as exc:
        print(f"[assessment-token] platform request failed: {exc}")
        return JSONResponse({"error": "platform unreachable"}, status_code=502)
    if r.status_code == 200:
        try:
            payload = r.json()
        except Exception:
            return JSONResponse({"error": "platform returned an invalid token contract"}, status_code=502)
        if not isinstance(payload, dict):
            return JSONResponse({"error": "platform returned an invalid token contract"}, status_code=502)
        token = payload.get("token")
        try:
            token = str(uuid.UUID(token))
        except (ValueError, AttributeError, TypeError):
            return JSONResponse({"error": "platform returned an invalid token contract"}, status_code=502)
        projected = {"token": token, "download_url": f"{PUBLIC_BASE_URL}/reports/download/{token}"}
        for field in _ASSESSMENT_TOKEN_RESPONSE_FIELDS:
            if field in payload:
                projected[field] = payload[field]
        return JSONResponse(projected, status_code=200)
    return _proxy_json(r)


# ── PAT-370: Public single-use report download ────────────────────────────────
# Token is the only auth — Cloudflare Access must bypass /reports/download/*
# so external recipients (customers, brokers, auditors) can reach this without
# a Patched.im CF Access account.  The token is validated and single-use.

@app.get("/reports/download/{token}")
def public_report_download(token: str):
    """Redeem a single-use external download token and stream the approved artifact.

    Auth: token UUID only — no session, no CF Access required (bypass must be
    configured in the Cloudflare Access policy for /reports/download/*).
    """
    # PAT-1405 security review: PAT-370's local `report_ext_tokens.token` has
    # always been minted as a canonical `str(uuid.uuid4())` — unchanged since
    # PAT-370's original commit (verified against git history: the only
    # INSERT site for this table has only ever used `str(uuid.uuid4())`) — so
    # a strict UUID-format gate ahead of the local lookup cannot break any
    # legitimate outstanding local token today. Even so, don't make the
    # local lookup itself depend on that historical fact holding forever:
    # look up the token AS SUPPLIED first, and treat "doesn't parse as a
    # UUID" only as a signal to skip the platform redeem call (which is
    # reachable with zero authentication — see the P3 rate-limiting note
    # below — so it's worth not spending it on obvious garbage), never as a
    # reason to 404 ahead of the local table.
    try:
        normalized_token = str(uuid.UUID(token))
    except (ValueError, AttributeError):
        normalized_token = None

    now_iso = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        row = db.execute(
            "SELECT tenant_id, record_id, email, expires_at, redeemed_at "
            "FROM report_ext_tokens WHERE token=?",
            (token,),
        ).fetchone()

    from starlette.responses import Response as _Resp

    if not row:
        if normalized_token is None:
            # Not a locally-known token and not UUID-shaped, so it can never
            # match a PAT-1405 platform token either — those are always
            # minted as UUIDs (IssueAssessmentDownloadTokenHandler). No rate
            # limiter exists anywhere in this app (grepped — none found);
            # this early-out at least keeps non-UUID garbage from reaching
            # the unauthenticated platform-redeem call below. A well-formed-
            # but-unknown UUID still reaches it — that residual unbounded/
            # unrate-limited redemption-attempt surface is a real follow-up
            # that needs infra-level rate limiting, not something fixable
            # from this route alone.
            return Response("Download link not found.", status_code=404, media_type="text/plain")
        token = normalized_token
        # PAT-1405: assessment tokens are canonical on patched-api-01. Keeping
        # the recipient URL here preserves the established Access-bypass path;
        # the dashboard has no artifact path or bytes of its own.
        #
        # Token-burn note (PAT-1405 security review): the platform's redeem
        # handler (assessment_artifacts.go: RedeemAssessmentDownloadTokenHandler)
        # marks the token `used_at=NOW()` in the SAME DB transaction that
        # hash-verifies the stored artifact and reads its bytes, and commits
        # that transaction BEFORE writing any response back to us. So by the
        # time this call returns at all — success, malformed response, or
        # otherwise — the token is already durably consumed server-side.
        # There is no reissue/un-redeem endpoint on the platform, so this
        # dashboard genuinely cannot un-burn a token once this POST has been
        # made: this is an accepted platform-level limitation, not something
        # a dashboard-only change can fully close (a real fix needs a
        # platform-side un-redeem/reissue endpoint, out of scope for this
        # worktree — PAT-1405's Go half). What IS fixed here: the checks
        # below are pinned to exactly what the platform guarantees on
        # success — `_ASSESSMENT_DOCUMENT_MAX_BYTES` is the same 25 MiB
        # ceiling the platform enforces at approval time, and the filename
        # regex's character class matches `sanitiseFilename()`'s output
        # alphabet exactly — so a genuine platform 200 should never
        # legitimately fail dashboard-side validation; the residual
        # burn-then-502 window is limited to transport corruption or a
        # dashboard bug, not normal operation. See
        # test_platform_redeem_call_is_a_single_irreversible_post in
        # tests/test_pat1405_assessment_delivery.py, which proves (and
        # documents) the current one-shot, no-compensating-action behavior.
        try:
            upstream = http.post(
                f"{PATCHED_API_INTERNAL}/admin/assessment-download-tokens/{_seg(token)}/redeem",
                timeout=30,
                verify=_VERIFY_INTERNAL,
            )
        except Exception as exc:
            # TODO(PAT-1405 follow-up): round 3 review extends the token-burn
            # note above to this specific failure mode. The platform commits
            # its redeem transaction (marking the token used) BEFORE writing
            # any response at all, so a transport-level exception here (timeout,
            # connection reset, TLS failure, etc.) gives no signal either way —
            # the token may already be durably consumed server-side even though
            # we never received a response to confirm it. Unlike the "platform
            # responded but the response failed our own validation" path above,
            # there isn't even an audit row or alert on THIS repo's side for
            # this outcome today — we only `print()` it. Not fixable from this
            # worktree alone: needs a platform-side ("PAT-1405's Go half")
            # reissue/un-redeem endpoint plus audit logging of "redeemed but
            # delivery failed" outcomes specifically. Worth a dedicated
            # follow-up ticket.
            print(f"[assessment-download] platform fetch failed for {token[:8]}…: {exc}")
            return _Resp("Report temporarily unavailable. Please try again later.",
                         status_code=502, media_type="text/plain")
        if upstream.status_code != 200:
            safe_status = upstream.status_code if upstream.status_code in (400, 404, 409, 410) else 502
            # P3 (round 3 review): "integrity check failure" is more specific than
            # a fully generic message, but it's returned to a caller who holds
            # nothing but a valid single-use token for this exact artifact — i.e.
            # the intended recipient (or whoever else possesses that unguessable
            # UUID, the same threat model every other message on this route
            # already trusts: 410 already tells them "expired or already used",
            # 404 tells them "not found"). It reveals a server-side data-integrity
            # fact about an artifact this caller is already authorized to receive,
            # not information about any OTHER tenant, artifact, or internal path/
            # implementation detail. Genericizing it further would also break the
            # established pattern here of a differentiated-but-safe message per
            # failure class (400/404/410 are equally specific). Left as-is
            # deliberately, not an oversight.
            safe_message = {
                400: "Download link is invalid.",
                404: "Download link not found.",
                409: "Report unavailable due to an integrity check failure.",
                410: "This download link has expired or has already been used.",
            }.get(safe_status, "Report temporarily unavailable. Please try again later.")
            return _Resp(safe_message, status_code=safe_status, media_type="text/plain")
        content_type = (upstream.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        allowed_types = {
            "application/pdf",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        }
        disposition = upstream.headers.get("Content-Disposition", "")
        if (not upstream.content or len(upstream.content) > _ASSESSMENT_DOCUMENT_MAX_BYTES
                or content_type not in allowed_types or not re.fullmatch(
                    r'attachment; filename="[A-Za-z0-9._-]+\.(?:pdf|docx)"', disposition
                )):
            print(f"[assessment-download] unsafe upstream response for {token[:8]}…")
            return _Resp("Report unavailable due to an invalid delivery response.",
                         status_code=502, media_type="text/plain")
        return _Resp(content=upstream.content, media_type=content_type, headers={
            "Content-Disposition": disposition,
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
        })

    if row["redeemed_at"]:
        return _Resp(
            "This download link has already been used.\n"
            "Each link is single-use. Contact your Patched.im account manager "
            "if you need a new link.",
            status_code=410, media_type="text/plain",
        )

    if now_iso > row["expires_at"]:
        return _Resp(
            "This download link has expired (links are valid for 30 days).\n"
            "Contact your Patched.im account manager if you need a new link.",
            status_code=410, media_type="text/plain",
        )

    # Atomically CLAIM the token before fetching: the conditional UPDATE means
    # two concurrent requests race on `redeemed_at IS NULL` and only one wins
    # (single-use preserved). If the upstream fetch then fails we RELEASE the
    # claim below, so a transient Go-service error doesn't burn the token and
    # leave the customer with a dead link (mirror of the Go R-report fix).
    with get_db() as db:
        cur = db.execute(
            "UPDATE report_ext_tokens SET redeemed_at=? "
            "WHERE token=? AND redeemed_at IS NULL",
            (now_iso, token),
        )
        claimed = cur.rowcount == 1
    if not claimed:
        return _Resp(
            "This download link has already been used.\n"
            "Each link is single-use. Contact your Patched.im account manager "
            "if you need a new link.",
            status_code=410, media_type="text/plain",
        )

    def _release_token():
        with get_db() as db:
            db.execute(
                "UPDATE report_ext_tokens SET redeemed_at=NULL WHERE token=?",
                (token,),
            )

    tenant_id = row["tenant_id"]
    record_id = row["record_id"]

    try:
        r = http.get(
            f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}"
            f"/report-records/{_seg(record_id)}/download",
            params={"format": "xlsx"},
            timeout=30,
            verify=_VERIFY_INTERNAL,
        )
    except Exception as exc:
        print(f"[report-download] Go service fetch failed for token {token[:8]}…: {exc}")
        _release_token()
        return _Resp("Report temporarily unavailable. Please try again later.",
                     status_code=502, media_type="text/plain")

    if r.status_code != 200:
        print(f"[report-download] Go service {r.status_code} for token {token[:8]}…")
        _release_token()
        return _Resp(f"Report unavailable ({r.status_code}).",
                     status_code=502, media_type="text/plain")

    print(f"[report-download] token {token[:8]}… redeemed by {row['email']} "
          f"— {len(r.content)} bytes")

    return _Resp(
        content=r.content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f'attachment; filename="patched-report-{record_id[:8]}.xlsx"',
        },
    )


# ── PAT-631: Shadow IT detection proxy routes ─────────────────────────────────

@app.get("/admin/shadow-it/catalogue")
def proxy_shadow_it_catalogue():
    r = http.get(f"{PATCHED_API_INTERNAL}/admin/shadow-it/catalogue", timeout=10, verify=_VERIFY_INTERNAL)
    return _proxy_json(r)


@app.get("/admin/shadow-it/findings/{tenant_id}")
def proxy_shadow_it_findings(tenant_id: str):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/shadow-it/findings",
        timeout=15, verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.put("/admin/shadow-it/{tenant_id}/{label}")
async def proxy_shadow_it_policy(tenant_id: str, label: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.put,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/shadow-it/{_seg(label)}",
        data=body, headers={"Content-Type": "application/json"},
        timeout=10, verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-134: Outbound webhooks ───────────────────────────────────────────────

@app.get("/admin/tenants/{tenant_id}/webhooks")
def proxy_webhooks_list(tenant_id: str):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/webhooks",
        timeout=10, verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/webhooks")
async def proxy_webhooks_create(tenant_id: str, request: Request):
    body = await request.body()
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/webhooks",
        data=body, headers={"Content-Type": "application/json"},
        timeout=10, verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.put("/admin/tenants/{tenant_id}/webhooks/{webhook_id}")
async def proxy_webhooks_update(tenant_id: str, webhook_id: str, request: Request):
    # PAT-799: find this webhook's current state (enabled flag, url) in the
    # tenant's list before applying the update, for the audit before/after.
    before = None
    try:
        lr = await run_in_threadpool(http.get, f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/webhooks", timeout=10, verify=_VERIFY_INTERNAL)
        if lr.status_code == 200:
            items = lr.json()
            items = items if isinstance(items, list) else (items.get("webhooks") or items.get("items") or [])
            for wh in items:
                if isinstance(wh, dict) and str(wh.get("id")) == webhook_id:
                    before = json.dumps(wh)
                    break
    except Exception:
        pass
    body = await request.body()
    r = await run_in_threadpool(http.put,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/webhooks/{_seg(webhook_id)}",
        data=body, headers={"Content-Type": "application/json"},
        timeout=10, verify=_VERIFY_INTERNAL,
    )
    request.state.audit_before = before
    request.state.audit_after = body.decode("utf-8", "replace")
    return _proxy_json(r)


@app.delete("/admin/tenants/{tenant_id}/webhooks/{webhook_id}")
def proxy_webhooks_delete(tenant_id: str, webhook_id: str):
    r = http.delete(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/webhooks/{_seg(webhook_id)}",
        timeout=10, verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.get("/admin/tenants/{tenant_id}/webhooks/{webhook_id}/deliveries")
def proxy_webhooks_deliveries(tenant_id: str, webhook_id: str):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/webhooks/{_seg(webhook_id)}/deliveries",
        timeout=10, verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/webhooks/{webhook_id}/test")
def proxy_webhooks_test(tenant_id: str, webhook_id: str):
    r = http.post(
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/webhooks/{_seg(webhook_id)}/test",
        timeout=15, verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── Actor resolution for server-side audit fields ────────────────────────────
# Originally introduced for the PAT-794 mirror-EULA-approval proxies against
# patched.im's `/admin/mirror/*` routes — those dashboard-side proxies were
# dead code (the console stopped calling them at PAT-852) and were removed
# under PAT-847 (see docs/API_REFERENCE.md). This actor-resolution helper
# outlived them, and the catalogue review proxies (PAT-852) that followed
# (retired in PAT-2249): the extension-removal queue (PAT-832, above) and the
# Homebrew review proxies (PAT-2046, below) rely on it to stamp the
# authenticated actor server-side rather than trust a client-supplied value.

def _mirror_actor_email(request: Request) -> str:
    """Authenticated actor for the approved_by audit field — never client-supplied."""
    actor = getattr(request.state, "actor_email", "")
    if actor:
        return actor
    if DASHBOARD_API_KEY and request.headers.get("authorization", "") == f"Bearer {DASHBOARD_API_KEY}":
        return "bearer-token"
    email = _session_decode(request.cookies.get(SESSION_COOKIE, ""))
    if email:
        return email
    cf = _cf_email(request)
    if cf:
        return cf
    return "dev@local" if _DEV_ENV else ""


# ── Capped JSON body reader for write proxies ──────────────────────────────
# PAT-852 / PAT-66 introduced this for the catalogue review proxies; PAT-2249
# retired those, and the extension-removal and Homebrew review proxies keep
# using it. It caps the request-body size BEFORE fully buffering it, so an
# oversized or abusive payload is rejected up front rather than read into
# memory and forwarded upstream.
ADMIN_JSON_MAX_BODY_BYTES = 1 << 20  # 1 MiB


async def _read_capped_json(request: Request, max_bytes: int = ADMIN_JSON_MAX_BODY_BYTES):
    """Read + parse a JSON request body, rejecting oversized bodies before they
    are fully buffered. Checks Content-Length up front, then streams with a hard
    running cap (so a chunked/absent-length body can't sneak past). Returns
    (data, None) on success or (None, JSONResponse) on error — callers do
    `body, err = await _read_capped_json(request); if err: return err`."""
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > max_bytes:
                return None, JSONResponse({"error": "request body too large"}, status_code=413)
        except ValueError:
            return None, JSONResponse({"error": "invalid Content-Length"}, status_code=400)
    chunks = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_bytes:
            return None, JSONResponse({"error": "request body too large"}, status_code=413)
        chunks.append(chunk)
    raw = b"".join(chunks)
    if not raw:
        return None, JSONResponse({"error": "JSON body required"}, status_code=400)
    try:
        return json.loads(raw), None
    except (ValueError, TypeError):
        return None, JSONResponse({"error": "JSON body required"}, status_code=400)


# ── PAT-2046: Homebrew CVE mapping review queue — /admin/homebrew/review/* ──
# Global, tenant-free backlog (go-service's homebrew_cpe_review_queue) of
# official-tap Homebrew formulae/casks reported with no curated CPE mapping.
# Thin authenticated-proxy + actor-injection shape (see _read_capped_json
# above); the platform-owned model and lifecycle are
# in go-service/docs/API.md ("Homebrew CPE review queue"). The response never
# carries a tenant or device identifier, only aggregate prevalence counts —
# nothing here needs to change that.

@app.get("/admin/homebrew/review")
def proxy_homebrew_review_list(request: Request):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/homebrew/review",
        params=dict(request.query_params),
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/homebrew/review/{review_id}/map")
async def proxy_homebrew_review_map(review_id: str, request: Request):
    body, err = await _read_capped_json(request)
    if err:
        return err
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)
    # Actor is the audit identity -- always the server-resolved value, never
    # anything the client sent. The platform stores this as claimed_actor
    # and never treats it as authoritative either way (the authoritative
    # actor there is always admin_shared_token), but every other proxy in
    # this file holds the same discipline and this one keeps it too.
    body["actor"] = _mirror_actor_email(request)
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/homebrew/review/{_seg(review_id)}/map",
        json=body,
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/homebrew/review/{review_id}/accept-suggestion")
async def proxy_homebrew_review_accept_suggestion(review_id: str, request: Request):
    body, err = await _read_capped_json(request)
    if err:
        return err
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)
    body["actor"] = _mirror_actor_email(request)
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/homebrew/review/{_seg(review_id)}/accept-suggestion",
        json=body,
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/homebrew/review/{review_id}/dismiss")
async def proxy_homebrew_review_dismiss(review_id: str, request: Request):
    body, err = await _read_capped_json(request)
    if err:
        return err
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)
    body["actor"] = _mirror_actor_email(request)
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/homebrew/review/{_seg(review_id)}/dismiss",
        json=body,
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-2404: Software identities — /admin/software-catalogue/* ─────────────
# The platform's curated software identity catalogue: staff review identities
# that devices have reported (candidates), name them, and can withdraw one
# (retire an alias). This console stores nothing: every call is a proxy to
# patched-api-01. It is an identity catalogue, not a package catalogue, so
# no installer, label, deployment or update field exists anywhere here.
# The platform enforces the evidence bar and takes the identity from what
# devices reported; the four identity fields in a review body only name which
# candidate is meant, so they are forwarded verbatim and never edited here.

_SWC_PLATFORMS = ("macos", "windows")
_SWC_REVIEW_FIELDS = (
    "platform", "identity_kind", "identity_value_normalized",
    "companion_value_normalized", "canonical_name", "vendor_name", "reason",
)
_SWC_RETIRE_FIELDS = ("reason",)
_SWC_UPSTREAM_DOWN = "The software identity service is unavailable. Try again shortly."


def _swc_proxy_json(r):
    """Relay a platform answer. 2xx passes through; a 4xx keeps only its
    {"error"} message so the operator sees why a write was refused; anything
    else (5xx, a degraded-upstream stand-in, a redirect) is replaced with a
    fixed message so no platform body is ever reflected."""
    status = r.status_code
    try:
        data = r.json() if r.content else {}
    except Exception:
        data = None
    if 200 <= status < 300:
        if data is None:
            return JSONResponse({"error": _SWC_UPSTREAM_DOWN}, status_code=502)
        return JSONResponse(data, status_code=status)
    if 400 <= status < 500:
        msg = data.get("error") if isinstance(data, dict) else None
        if not isinstance(msg, str) or not msg.strip():
            msg = "The platform refused this request."
        return JSONResponse({"error": msg.strip()[:500]}, status_code=status)
    return JSONResponse({"error": _SWC_UPSTREAM_DOWN}, status_code=502)


def _swc_valid_alias_id(alias_id: str) -> bool:
    try:
        return str(uuid.UUID(alias_id)) == alias_id.lower()
    except (ValueError, AttributeError, TypeError):
        return False


@app.get("/admin/software-catalogue/candidates")
def proxy_software_catalogue_candidates(request: Request):
    platform = request.query_params.get("platform", "")
    if platform not in _SWC_PLATFORMS:
        return JSONResponse({"error": "platform must be macos or windows"}, status_code=400)
    params = {"platform": platform}
    query = request.query_params.get("query")
    if query:
        params["query"] = query
    limit = request.query_params.get("limit")
    if limit:
        if not limit.isdigit():
            return JSONResponse({"error": "limit must be a whole number"}, status_code=400)
        params["limit"] = limit
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/software-catalogue/candidates",
        params=params,
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _swc_proxy_json(r)


@app.get("/admin/software-catalogue/aliases")
def proxy_software_catalogue_aliases():
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/software-catalogue/aliases",
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _swc_proxy_json(r)


@app.post("/admin/software-catalogue/reviews")
async def proxy_software_catalogue_review(request: Request):
    body, err = await _read_capped_json(request)
    if err:
        return err
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)
    # Only the fields the platform accepts go upstream; the actor is always
    # the server-resolved staff identity, whatever the client sent.
    out = {k: body[k] for k in _SWC_REVIEW_FIELDS if k in body}
    out["actor"] = _mirror_actor_email(request)
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/software-catalogue/reviews",
        json=out,
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _swc_proxy_json(r)


@app.post("/admin/software-catalogue/aliases/{alias_id}/retire")
async def proxy_software_catalogue_alias_retire(alias_id: str, request: Request):
    if not _swc_valid_alias_id(alias_id):
        return JSONResponse({"error": "alias id must be a UUID"}, status_code=400)
    body, err = await _read_capped_json(request)
    if err:
        return err
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)
    out = {k: body[k] for k in _SWC_RETIRE_FIELDS if k in body}
    out["actor"] = _mirror_actor_email(request)
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/software-catalogue/aliases/{_seg(alias_id.lower())}/retire",
        json=out,
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _swc_proxy_json(r)


# ── PAT-2097: Unapproved software alert lifecycle — operator cross-tenant
# queue, /admin/software-alerts and
# /admin/tenants/{tenant_id}/software-alerts/{id}/acknowledge ──────────────
# The platform's operator queue (go-service internal/handlers/software_alerts.go,
# internal/softwaregov/alert_views.go) lists open/acknowledged Unapproved
# software alerts across every active tenant, oldest first by open_since
# (raised, or last re-opened). Acknowledging records that staff have seen the
# alert -- it changes nothing on a device and resolves nothing; resolution is
# evidence-only (see go-service/docs/API.md, "Unapproved software alert
# lifecycle"). Same thin authenticated-proxy shape as the homebrew review
# proxies above. The actor recorded is the platform's own fixed "operator"
# kind (softwaregov.ActorOperator) -- there is no client-supplied actor field
# to strip or inject here, unlike the homebrew review proxies.

@app.get("/admin/software-alerts")
def proxy_software_alerts_list(request: Request):
    r = http.get(
        f"{PATCHED_API_INTERNAL}/admin/software-alerts",
        params=dict(request.query_params),
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


@app.post("/admin/tenants/{tenant_id}/software-alerts/{alert_id}/acknowledge")
async def proxy_software_alert_acknowledge(tenant_id: str, alert_id: str, request: Request):
    body, err = await _read_capped_json(request)
    if err:
        return err
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object required"}, status_code=400)
    r = await run_in_threadpool(http.post,
        f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/software-alerts/{_seg(alert_id)}/acknowledge",
        json=body,
        timeout=15,
        verify=_VERIFY_INTERNAL,
    )
    return _proxy_json(r)


# ── PAT-676: dashboard-login signal ──────────────────────────────────────────
# Fires once per session per tenant when the operator opens a tenant workspace.
# Proxies to PUT /admin/tenant/{tenantID}/signal on the platform internal admin
# API, which records last_dashboard_login_at and increments
# dashboard_logins_last_30d for that tenant. Fail-soft: errors are logged but
# never propagated to the caller.

@app.post("/api/tenant/{tenant_id}/signal")
async def api_tenant_signal(tenant_id: str):
    """Record a dashboard login signal for the given tenant (PAT-676)."""
    try:
        r = await run_in_threadpool(http.put,
            f"{PATCHED_API_INTERNAL}/admin/tenant/{_seg(tenant_id)}/signal",
            json={},
            timeout=5,
            verify=_VERIFY_INTERNAL,
        )
        if r.status_code not in (200, 201):
            print(f"[signal] platform {r.status_code} for tenant {tenant_id}: {r.text[:200]}")
    except Exception as exc:
        print(f"[signal] error for tenant {tenant_id}: {exc}")
    return JSONResponse({"status": "ok"})


# ── PAT-288: on-demand agent log retrieval ────────────────────────────────────

@app.post("/api/tenant/{tenant_id}/device/{device_id}/request-logs")
async def api_request_device_logs(tenant_id: str, device_id: str, request: Request):
    """Issue a log_request directive for a specific device via the agent-config write path."""
    with get_db() as db:
        row = db.execute(
            "SELECT agent_config_tier, agent_proxy_mode, agent_proxy_type, "
            "agent_proxy_host, agent_proxy_port, agent_proxy_pac_url, "
            "agent_proxy_auth_ref, agent_proxy_bypass_when_off_corp, "
            "agent_update_channel, agent_pinned_version "
            "FROM clients WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
    if not row:
        return JSONResponse({"error": "tenant not found"}, status_code=404)

    body = await request.json()
    request_id = str(uuid.uuid4())
    device_name = body.get("device_name", "")

    platform_body = {
        "tier":           row["agent_config_tier"] or "report_deploy",
        "proxy": {
            "mode":                 row["agent_proxy_mode"] or "system",
            "type":                 row["agent_proxy_type"],
            "host":                 row["agent_proxy_host"],
            "port":                 row["agent_proxy_port"],
            "pac_url":              row["agent_proxy_pac_url"],
            "auth_ref":             row["agent_proxy_auth_ref"],
            "bypass_when_off_corp": bool(row["agent_proxy_bypass_when_off_corp"]),
        },
        "update_channel": row["agent_update_channel"] or "stable",
        "pinned_version": row["agent_pinned_version"],
        "log_request": {
            "components": body.get("components") or [],
            "device_id":  device_id,
            "max_bytes":  10 * 1024 * 1024,
            "request_id": request_id,
            "since":      body.get("since") or "",
            "until":      body.get("until") or "",
        },
        "updated_by": "dashboard",
    }
    try:
        r = await run_in_threadpool(http.put,
            f"{PATCHED_API_INTERNAL}/admin/agent-config/{_seg(tenant_id)}",
            json=platform_body,
            timeout=10,
            verify=_VERIFY_INTERNAL,
        )
    except Exception as exc:
        return JSONResponse({"error": f"platform unreachable: {exc}"}, status_code=502)

    if r.status_code not in (200, 201):
        return JSONResponse({"error": f"platform error {r.status_code}"}, status_code=502)

    with get_db() as db:
        db.execute(
            "INSERT OR IGNORE INTO device_log_requests (request_id, tenant_id, device_id, device_name) "
            "VALUES (?, ?, ?, ?)",
            (request_id, tenant_id, device_id, device_name),
        )
    return JSONResponse({"request_id": request_id, "config_version": r.json().get("config_version")})


@app.get("/api/tenant/{tenant_id}/device/{device_id}/logs")
def api_list_device_logs(tenant_id: str, device_id: str):
    """Merge locally-tracked requests with bundles present on the platform.

    Returns a list ordered most-recent first. Status:
      requested — directive issued, no bundle yet
      uploaded  — bundle present on platform
      expired   — bundle present but older than 30 days
    """
    with get_db() as db:
        local = db.execute(
            "SELECT request_id, device_name, requested_at FROM device_log_requests "
            "WHERE tenant_id=? AND device_id=? ORDER BY requested_at DESC",
            (tenant_id, device_id),
        ).fetchall()

    try:
        r = http.get(
            f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/agent-logs",
            timeout=10,
            verify=_VERIFY_INTERNAL,
        )
        bundles = {b["request_id"]: b for b in (r.json().get("logs") or [])} if r.ok else {}
    except Exception:
        bundles = {}

    now = datetime.now(timezone.utc)
    results = []
    seen = set()
    for req in local:
        rid = req["request_id"]
        seen.add(rid)
        bundle = bundles.get(rid)
        if bundle:
            received = datetime.fromisoformat(bundle["received_at"].replace("Z", "+00:00"))
            age_days = (now - received).days
            status = "expired" if age_days >= 30 else "uploaded"
            results.append({
                "request_id":       rid,
                "device_id":        device_id,
                "device_name":      req["device_name"],
                "requested_at":     req["requested_at"],
                "received_at":      bundle["received_at"],
                "bundle_size_bytes": bundle["bundle_size_bytes"],
                "status":           status,
            })
        else:
            results.append({
                "request_id":   rid,
                "device_id":    device_id,
                "device_name":  req["device_name"],
                "requested_at": req["requested_at"],
                "received_at":  None,
                "bundle_size_bytes": None,
                "status":       "requested",
            })

    # Also surface any bundles that exist on the platform but weren't locally tracked
    # (e.g. from a prior session or different browser).
    for rid, bundle in bundles.items():
        if bundle.get("device_id") != device_id:
            continue
        if rid in seen:
            continue
        received = datetime.fromisoformat(bundle["received_at"].replace("Z", "+00:00"))
        age_days = (now - received).days
        results.append({
            "request_id":       rid,
            "device_id":        device_id,
            "device_name":      "",
            "requested_at":     bundle["received_at"],
            "received_at":      bundle["received_at"],
            "bundle_size_bytes": bundle["bundle_size_bytes"],
            "status":           "expired" if age_days >= 30 else "uploaded",
        })

    results.sort(key=lambda x: x["requested_at"] or "", reverse=True)
    return JSONResponse({"logs": results, "total": len(results)})


@app.get("/api/tenant/{tenant_id}/device/{device_id}/logs/{request_id}/bundle")
def api_fetch_device_log_bundle(tenant_id: str, device_id: str, request_id: str):
    """Proxy + decompress a log bundle from the platform. Returns a JSON array of log lines."""
    try:
        r = http.get(
            f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tenant_id)}/agent-logs/{_seg(device_id)}/{_seg(request_id)}",
            timeout=30,
            verify=_VERIFY_INTERNAL,
        )
    except Exception as exc:
        return JSONResponse({"error": f"platform unreachable: {exc}"}, status_code=502)

    if r.status_code == 404:
        return JSONResponse({"error": "bundle not found"}, status_code=404)
    if r.status_code != 200:
        return JSONResponse({"error": f"platform error {r.status_code}"}, status_code=502)

    try:
        raw = gzip.decompress(r.content)
    except Exception as exc:
        return JSONResponse({"error": f"decompress failed: {exc}"}, status_code=502)

    lines = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            lines.append(json.loads(line))
        except json.JSONDecodeError:
            lines.append({"raw": line})

    return JSONResponse({"lines": lines, "total": len(lines)})


# ══════════════════════════════════════════════════════════════
# PAT-435: Calendly webhook + Leads API
# CF Access must bypass /webhooks/calendly (Calendly calls it directly).
# Configure the bypass in CF Access: Applications → Dashboard → Policies →
# add a "Bypass" policy for path /webhooks/calendly (same pattern as
# /reports/download/* for PAT-370 / PAT-625).
# ══════════════════════════════════════════════════════════════

# Max age for a Calendly webhook signature before we treat it as a replay.
CALENDLY_WEBHOOK_MAX_AGE_S = 300


def _verify_calendly_signature(raw_body: bytes, header: str) -> bool:
    """Verify Calendly HMAC-SHA256 webhook signature.

    Header format: t=TIMESTAMP,v1=HEXSIG
    Signed payload: f"{TIMESTAMP}.{raw_body_str}"
    """
    if not CALENDLY_WEBHOOK_SECRET:
        # Fail CLOSED: if the secret isn't configured we cannot authenticate the
        # caller, so reject rather than accept unverified webhooks in prod. Set
        # CALENDLY_WEBHOOK_SECRET in the environment for the endpoint to work.
        print("[calendly] CALENDLY_WEBHOOK_SECRET not set — rejecting webhook (fail closed)")
        return False
    try:
        parts = {p.split("=", 1)[0]: p.split("=", 1)[1] for p in header.split(",")}
        ts = parts["t"]
        sig = parts["v1"]
    except (KeyError, ValueError):
        return False
    # Replay protection: reject signatures whose timestamp is too old (or too
    # far in the future). Calendly sends `t` as Unix epoch seconds.
    try:
        ts_val = float(ts)
    except ValueError:
        return False
    if abs(time.time() - ts_val) > CALENDLY_WEBHOOK_MAX_AGE_S:
        print("[calendly] webhook timestamp outside allowed window — rejecting (replay guard)")
        return False
    expected = hmac.new(
        CALENDLY_WEBHOOK_SECRET.encode(),
        f"{ts}.{raw_body.decode('utf-8', errors='replace')}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, sig)


@app.post("/webhooks/calendly")
async def webhooks_calendly(request: Request):
    """Receive Calendly invitee.created events and kick off the lead flow.

    Auth: HMAC-SHA256 (Calendly-Webhook-Signature header) — no CF Access.
    """
    raw_body = await request.body()
    sig_header = request.headers.get("Calendly-Webhook-Signature", "")
    if not _verify_calendly_signature(raw_body, sig_header):
        return JSONResponse({"error": "invalid signature"}, status_code=401)

    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)

    event_type = payload.get("event", "")
    if event_type != "invitee.created":
        return JSONResponse({"ok": True, "skipped": event_type})

    p = payload.get("payload", {})
    invitee = p.get("invitee", {})
    scheduled_event = p.get("scheduled_event", {}) or p.get("event", {})
    event_type_obj = p.get("event_type", {})

    email_addr = invitee.get("email", "").strip().lower()
    name = invitee.get("name", "").strip()
    meeting_at = scheduled_event.get("start_time", "")
    event_uri = scheduled_event.get("uri", "") or event_type_obj.get("uri", "")
    event_label = event_type_obj.get("name", "")

    if not email_addr:
        return JSONResponse({"error": "no email in payload"}, status_code=400)

    lead_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        # Upsert: if the same invitee books multiple times, update meeting_at.
        existing = db.execute(
            "SELECT id FROM calendly_leads WHERE email=?", (email_addr,)
        ).fetchone()
        if existing:
            lead_id = existing["id"]
            db.execute(
                "UPDATE calendly_leads SET meeting_at=?, event_type=?, event_uri=? WHERE id=?",
                (meeting_at, event_label, event_uri, lead_id),
            )
        else:
            db.execute(
                "INSERT INTO calendly_leads "
                "(id, email, name, event_type, event_uri, booked_at, meeting_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (lead_id, email_addr, name, event_label, event_uri, now_iso, meeting_at),
            )

    # Send initial confirmation email
    first = name.split()[0] if name else "there"
    subject = "Your Patched.im consultation is confirmed"
    html = (
        f"<p>Hi {first},</p>"
        f"<p>Thanks for booking a Patched.im consultation — we're looking forward to "
        f"the conversation.</p>"
        f"<p>In the meantime, if you'd like to see what we can surface for your estate, "
        f"you can run a free CVE scan at "
        f"<a href='https://patched.im'>patched.im</a>. "
        f"It only takes a couple of minutes.</p>"
        f"<p>See you soon,<br>Andy @ Patched.im</p>"
    )
    text = (
        f"Hi {first},\n\nThanks for booking a Patched.im consultation — we're looking "
        f"forward to the conversation.\n\nIn the meantime, you can run a free CVE scan "
        f"at https://patched.im.\n\nSee you soon,\nAndy @ Patched.im"
    )
    ok = _send_email(email_addr, subject, html, text)
    # PAT-1010: initial_email_sent_at drives the Leads tab's "confirmed"
    # checkmark (templates/console.html), an operator-visible claim that
    # this lead got a real confirmation email. _send_email() returns True
    # under EMAIL_DRY_RUN even though nothing was sent, so only record it
    # when delivery is not suppressed.
    if ok and email_delivery_status() != "dry_run":
        with get_db() as db:
            db.execute(
                "UPDATE calendly_leads SET initial_email_sent_at=? WHERE id=?",
                (now_iso, lead_id),
            )
    print(f"[calendly] {'✅' if ok else '❌'} initial email to {email_addr} (lead {lead_id})")
    return JSONResponse({"ok": True, "lead_id": lead_id})


@app.get("/api/leads")
def api_leads():
    """Return all Calendly leads with scan and follow-up status."""
    with get_db() as db:
        leads = db.execute(
            "SELECT id, email, name, event_type, booked_at, meeting_at, "
            "       initial_email_sent_at, converted_at "
            "FROM calendly_leads ORDER BY booked_at DESC"
        ).fetchall()

        sends = db.execute(
            "SELECT lead_id, day_number, sent_at FROM calendly_followup_sends"
        ).fetchall()

        # Group follow-up sends by lead
        followups: dict[str, list] = {}
        for s in sends:
            followups.setdefault(s["lead_id"], []).append(
                {"day": s["day_number"], "sent_at": s["sent_at"]}
            )

        # Left-join public_scans on email (latest completed scan per email)
        scans = db.execute(
            "SELECT email, id AS scan_id, status, report_path, completed_at, download_token "
            "FROM public_scans "
            "WHERE status='complete' OR status='error' "
            "ORDER BY created_at DESC"
        ).fetchall()
        scan_by_email: dict[str, dict] = {}
        for sc in scans:
            em = sc["email"].lower()
            if em not in scan_by_email:
                scan_by_email[em] = dict(sc)

    result = []
    for lead in leads:
        lid = lead["id"]
        em = lead["email"].lower()
        scan = scan_by_email.get(em)
        result.append({
            "id": lid,
            "email": lead["email"],
            "name": lead["name"],
            "event_type": lead["event_type"],
            "booked_at": lead["booked_at"],
            "meeting_at": lead["meeting_at"],
            "initial_email_sent_at": lead["initial_email_sent_at"],
            "converted_at": lead["converted_at"],
            "followups": followups.get(lid, []),
            "scan": {
                "scan_id": scan["scan_id"],
                "status": scan["status"],
                "completed_at": scan["completed_at"],
                "has_report": bool(scan["report_path"]),
                "download_token": scan["download_token"],
            } if scan else None,
        })
    return JSONResponse(result)


@app.post("/api/leads/{lead_id}/convert")
def api_lead_convert(lead_id: str):
    """Mark a lead as converted (used by the 'Convert to Tenant' button).

    This just stamps converted_at — the operator still creates the tenant
    via the normal /admin route.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute("SELECT id FROM calendly_leads WHERE id=?", (lead_id,)).fetchone()
        if not row:
            return JSONResponse({"error": "not found"}, status_code=404)
        db.execute(
            "UPDATE calendly_leads SET converted_at=? WHERE id=?",
            (now_iso, lead_id),
        )
    return JSONResponse({"ok": True})


# ── PAT-673/674/675/678: Fleet overview API ──────────────────────────────────
def _resolve_health_bucket(t: dict) -> tuple:
    """Return (bucket, score) for a tenants/overview row.

    Uses the real health_score/health_bucket from the platform (PAT-708) when
    available. Falls back to the heuristic only when health_score is null (tenant
    hasn't had its first nightly recompute yet).
    """
    real_score = t.get("health_score")
    real_bucket = t.get("health_bucket")
    if real_score is not None and real_bucket is not None:
        return (real_bucket, int(real_score))
    # Graceful fallback for tenants whose score hasn't been computed yet.
    return _health_bucket_heuristic(t.get("compliance_pct"))


def _score_trend_html(t: dict):
    """Return an HTML string for the 30-day compliance score trend.

    Uses compliance_score_current and compliance_score_30d_ago from the platform
    (PAT-708 / PAT-676). Returns None when either value is absent (pre-recompute).
    """
    cur = t.get("compliance_score_current")
    ago = t.get("compliance_score_30d_ago")
    if cur is None or ago is None:
        return None
    delta = int(cur) - int(ago)
    if delta > 0:
        return f'<span style="color:#16a34a;font-family:var(--font-mono);font-weight:600;">&#9650;&nbsp;+{delta}%</span>'
    elif delta < 0:
        return f'<span style="color:#dc2626;font-family:var(--font-mono);font-weight:600;">&#9660;&nbsp;{delta}%</span>'
    else:
        return '<span style="color:var(--muted);font-family:var(--font-mono);">&#8212;</span>'


@app.get("/api/admin/fleet-summary")
def api_fleet_summary():
    """PAT-673/708: estate-wide aggregate stats for the Estate Overview top row."""
    try:
        r = http.get(f"{PATCHED_API_INTERNAL}/admin/tenants/overview", timeout=15, verify=_VERIFY_INTERNAL)
        tenants = r.json().get("tenants", []) if r.status_code == 200 and r.content else []
    except Exception as e:
        print(f"[fleet-summary] overview fetch failed: {e}")
        tenants = []

    # Fetch health data for ingest freshness
    ingest_at = None
    tenants_stale_24h = 0
    try:
        hr = http.get(f"{PATCHED_API_INTERNAL}/admin/health", timeout=10, verify=_VERIFY_INTERNAL)
        if hr.status_code == 200 and hr.content:
            hd = hr.json()
            freshn = hd.get("service_health", {}).get("ingestion_freshness", {})
            ingest_at = freshn.get("most_recent_ingest_at")
            stalest = freshn.get("stalest_tenant", {})
            if stalest.get("hours_stale", 0) > 24:
                tenants_stale_24h = 1  # minimal: track if stalest is >24h
    except Exception:
        pass

    buckets = {"healthy": 0, "watch": 0, "at_risk": 0}
    total_devices = 0
    compliance_sum = 0.0
    compliance_count = 0

    for t in tenants:
        bucket, _ = _resolve_health_bucket(t)
        buckets[bucket] = buckets.get(bucket, 0) + 1
        total_devices += t.get("device_count") or 0
        cp = t.get("compliance_pct")
        if cp is not None:
            compliance_sum += float(cp)
            compliance_count += 1

    avg_compliance = round(compliance_sum / compliance_count, 1) if compliance_count else None

    return JSONResponse({
        "tenant_count": len(tenants),
        "total_endpoints": total_devices,
        "tenants_healthy": buckets["healthy"],
        "tenants_watch": buckets["watch"],
        "tenants_at_risk": buckets["at_risk"],
        "tenants_alerting": buckets["at_risk"],
        "tenants_with_zero_ingest_24h": tenants_stale_24h,
        "avg_compliance_score": avg_compliance,
        "last_ingest_across_fleet": ingest_at,
    })


@app.get("/api/admin/fleet-tenants")
def api_fleet_tenants():
    """PAT-674/708: per-tenant health rows for the Estate Overview table. Sorted by bucket (worst first)."""
    try:
        r = http.get(f"{PATCHED_API_INTERNAL}/admin/tenants/overview", timeout=15, verify=_VERIFY_INTERNAL)
        tenants = r.json().get("tenants", []) if r.status_code == 200 and r.content else []
    except Exception as e:
        print(f"[fleet-tenants] overview fetch failed: {e}")
        return JSONResponse({"error": "upstream unavailable"}, status_code=502)

    # Merge billing_tier from local SQLite (same pattern as proxy_tenants_overview)
    if tenants:
        try:
            conn = _open_db_connection(DB_PATH)
            ids = [t["id"] for t in tenants]
            rows = conn.execute(
                "SELECT tenant_id, billing_tier FROM clients WHERE tenant_id IN ({})".format(
                    ",".join("?" * len(ids))
                ),
                ids,
            ).fetchall()
            conn.close()
            billing = {row["tenant_id"]: row["billing_tier"] for row in rows}
        except Exception:
            billing = {}
    else:
        billing = {}

    _BUCKET_SORT = {"at_risk": 0, "watch": 1, "healthy": 2}

    result = []
    for t in tenants:
        bucket, score = _resolve_health_bucket(t)
        tid = t.get("id", "")
        result.append({
            "id": tid,
            "name": t.get("name", ""),
            "tier": t.get("tier", ""),
            "billing_tier": billing.get(tid, t.get("billing_tier", "report")),
            "device_count": t.get("device_count"),
            "active_last_7d": t.get("active_last_7d"),
            "compliance_pct": t.get("compliance_pct"),
            "health_score": score,
            "health_bucket": bucket,
            # 30-day trend: rendered as an HTML snippet (arrow + delta) from
            # compliance_score_current vs compliance_score_30d_ago (PAT-708).
            # None when either value is absent (pre-first nightly recompute).
            "score_trend": _score_trend_html(t),
            "crit_high_fail_count": t.get("crit_high_fail_count"),
            "new_apps_awaiting_decision": t.get("new_apps_awaiting_decision"),
            "macos_enabled": t.get("macos_enabled"),
            "windows_enabled": t.get("windows_enabled"),
        })

    result.sort(key=lambda t: (_BUCKET_SORT.get(t["health_bucket"], 9), -(t["health_score"] or 0)))
    return JSONResponse({"tenants": result})


@app.get("/api/admin/service-health")
def api_service_health():
    """PAT-675: service health panel for the Estate Overview page."""
    out: dict = {
        "dashboard": {"ok": True, "note": "serving this response"},
        "api": None,
        "ingest": None,
        "backups": [],
        "disks": [],
        "worker": None,
        "automation_alerts": [],
        "grafana_url": GRAFANA_URL or None,
    }

    try:
        hr = http.get(f"{PATCHED_API_INTERNAL}/admin/health", timeout=10, verify=_VERIFY_INTERNAL)
        if hr.status_code == 200 and hr.content:
            hd = hr.json()
            sh = hd.get("service_health", {})

            # API health
            out["api"] = {
                "ok": sh.get("db_reachable", False),
                "detail": "db reachable" if sh.get("db_reachable") else "db unreachable",
            }

            # Ingest pipeline
            freshn = sh.get("ingestion_freshness", {})
            stalest = freshn.get("stalest_tenant", {})
            last_ingest = freshn.get("most_recent_ingest_at")
            hours_stale = stalest.get("hours_stale", 0)
            out["ingest"] = {
                "ok": hours_stale < 2,
                "last_ingest_at": last_ingest,
                "stalest_tenant": stalest.get("tenant_name"),
                "stalest_hours": round(hours_stale, 1) if hours_stale else None,
                "detail": f"last batch {round(hours_stale, 1)}h ago" if hours_stale else "no data",
            }

            # Backup jobs (prod-r2, db-r2 — from DR work)
            out["backups"] = sh.get("backup_jobs", [])

            # Disk usage (prod-01 added by proxy_health; api-01 from platform)
            out["disks"] = sh.get("disk_usage", [])

            # Automation alerts (from platform)
            out["automation_alerts"] = sh.get("automation_alerts", [])

            # Worker: not yet available (awaits PAT-144 executor stage 3)
            out["worker"] = {"ok": None, "note": "awaiting PAT-144 worker metrics"}

    except Exception as e:
        print(f"[service-health] platform health fetch failed: {e}")
        out["api"] = {"ok": None, "detail": f"platform unreachable: {e}"}

    # Add prod-01 disk directly (same as proxy_health does)
    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        used = total - free
        used_pct = round(used / total * 100, 1) if total else 0.0
        to_gb = lambda b: round(b / 1e9, 1)
        if not any(d.get("host") == "prod-01" for d in out["disks"]):
            out["disks"].insert(0, {
                "host": "prod-01", "path": "/",
                "total_gb": to_gb(total), "used_gb": to_gb(used),
                "free_gb": to_gb(free), "used_pct": used_pct,
            })
    except Exception:
        pass

    return JSONResponse(out)


# ─────────────────────────────────────────────────────────────────────────────
# PAT-710: Ops panel — data aggregation + guarded firewall-apply trigger
# ─────────────────────────────────────────────────────────────────────────────

def _ops_get_systemctl_prop(unit: str, *props: str) -> dict:
    """Read one or more properties from a systemd unit via systemctl show.
    Returns a dict {prop: value}. Any failure returns empty strings."""
    import subprocess
    try:
        result = subprocess.run(
            ["systemctl", "show", unit] + ["--property=" + p for p in props],
            capture_output=True, text=True, timeout=5
        )
        out: dict = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                if k in props:
                    out[k] = v
        return out
    except Exception:
        return {}


def _ops_cert_expiry(hostname: str, port: int = 443) -> dict | None:
    """Return TLS cert expiry info for a hostname.  None on any error.

    Uses CERT_NONE + binary_form=True so the cert is fetched without
    chain validation (Cloudflare Origin Certs aren't browser-trusted).
    Parsed with the cryptography library which is available in the venv.
    """
    import ssl, socket
    from datetime import datetime, timezone
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(socket.create_connection((hostname, port), timeout=8),
                             server_hostname=hostname) as s:
            der = s.getpeercert(binary_form=True)
        if not der:
            return {"hostname": hostname, "error": "no certificate returned"}
        from cryptography import x509 as cx509
        c = cx509.load_der_x509_certificate(der)
        # not_valid_after_utc is tz-aware (Python 3.12+); fall back to naive utc.
        try:
            not_after = c.not_valid_after_utc
        except AttributeError:
            not_after = c.not_valid_after.replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
        return {
            "hostname": hostname,
            "not_after": not_after.isoformat(),
            "days_left": days_left,
            "warn": days_left < 30,
        }
    except Exception as e:
        return {"hostname": hostname, "error": str(e)}


def _ops_dashboard_version() -> dict:
    """Return checkout version plus the deploy script's recorded provenance.

    This stays a read-only view of the canonical on-box checkout and
    DEPLOYED_SHA file. An unreadable or malformed record is explicit unknown,
    never a guessed match.
    """
    import subprocess
    import re
    result = {
        "sha": "unknown", "committed_at": "unknown",
        "deployed_sha": None, "deployed_at": None,
        "deployment_match": "unknown",
    }
    try:
        full_sha = subprocess.check_output(
            ["git", "-C", DASHBOARD_REPO_DIR, "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL, timeout=5, text=True
        ).strip()
        sha = subprocess.check_output(
            ["git", "-C", DASHBOARD_REPO_DIR, "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL, timeout=5, text=True
        ).strip()
        ts = subprocess.check_output(
            ["git", "-C", DASHBOARD_REPO_DIR, "log", "-1", "--format=%ci"],
            stderr=subprocess.DEVNULL, timeout=5, text=True
        ).strip()
        result.update({"sha": sha, "committed_at": ts})
    except Exception:
        result["provenance_error"] = "checkout version unavailable"
        return result

    try:
        with open(DEPLOYED_SHA_FILE, "r") as f:
            lines = f.read().splitlines()
    except (OSError, UnicodeError):
        result["provenance_error"] = "deployment provenance unavailable"
        return result

    record = {}
    for line in lines:
        if line.startswith("DEPLOYED_SHA="):
            record["sha"] = line[len("DEPLOYED_SHA="):].strip()
        elif line.startswith("DEPLOYED_AT="):
            record["at"] = line[len("DEPLOYED_AT="):].strip()
    deployed_sha = record.get("sha", "")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", deployed_sha):
        result["provenance_error"] = "deployment provenance has no usable SHA"
        return result
    result["deployed_sha"] = deployed_sha
    result["deployed_at"] = record.get("at") or None
    current = full_sha.lower()
    recorded = deployed_sha.lower()
    result["deployment_match"] = "match" if current == recorded else "mismatch"
    return result


@app.get("/api/ops/data")
def api_ops_data():
    """PAT-710: aggregate data for the Ops panel tiles.

    Pulls from:
      - /admin/health (platform) — health, backups, disk, ingest
      - /admin/ops/version (platform) — binary SHA, build time, schema version
      - /admin/ops/partitions (platform) — raw_payloads partition horizon
      - Local systemctl — firewall timer last-apply timestamps
      - Local git + openssl — dashboard version + TLS cert expiry
      - Local check_statuses (PAT-990) — maintenance_prod01/api01/portal01,
        recorded by the PAT-989 scheduler tick; not re-fetched live here
      - Local check_statuses (PAT-1171) — every non-ok row (degraded or
        unconfigured), generic across all check names, not just maintenance
    """
    out: dict = {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "firewall": {},
        "backups": [],
        "health": {},
        "versions": {},
        "certs": [],
        "partitions": {},
        "maintenance": [],
        "checks_attention": [],
    }

    # ── Platform health (backups, disk, DB, ingest) ──────────────────────────
    try:
        hr = http.get(f"{PATCHED_API_INTERNAL}/admin/health", timeout=12, verify=_VERIFY_INTERNAL)
        if hr.ok and hr.content:
            hd = hr.json()
            sh = hd.get("service_health", {})
            # Tag disk entries with host label
            for d in sh.get("disk_usage", []):
                d.setdefault("host", "api-01")
            out["backups"] = sh.get("backup_jobs", [])
            out["health"]["db_reachable"] = sh.get("db_reachable", False)
            out["health"]["ingest_freshness"] = sh.get("ingestion_freshness", {})
            out["health"]["disk_usage"] = sh.get("disk_usage", [])
    except Exception as e:
        out["health"]["error"] = str(e)

    # Add prod-01 disk
    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free  = st.f_bavail * st.f_frsize
        used  = total - free
        to_gb = lambda b: round(b / 1e9, 1)
        disk_list = out["health"].get("disk_usage", [])
        if not any(d.get("host") == "prod-01" for d in disk_list):
            disk_list.insert(0, {
                "host": "prod-01", "path": "/",
                "total_gb": to_gb(total), "used_gb": to_gb(used),
                "free_gb": to_gb(free),
                "used_pct": round(used / total * 100, 1) if total else 0.0,
            })
        out["health"]["disk_usage"] = disk_list
    except Exception:
        pass

    # Service states on prod-01 (dashboard, nginx)
    for svc in ("patched-dashboard", "nginx"):
        props = _ops_get_systemctl_prop(f"{svc}.service", "ActiveState", "SubState")
        out["health"].setdefault("services", {})[svc] = {
            "active": props.get("ActiveState", "unknown"),
            "sub": props.get("SubState", "unknown"),
        }

    # ── Platform: version + partitions ────────────────────────────────────────
    try:
        vr = http.get(f"{PATCHED_API_INTERNAL}/admin/ops/version", timeout=8, verify=_VERIFY_INTERNAL)
        if vr.ok and vr.content:
            vd = vr.json()
            out["versions"]["api"] = {
                "sha": vd.get("binary_sha"),
                "build_time": vd.get("binary_build_time"),
                "schema_mig_version": vd.get("schema_mig_version"),
            }
    except Exception as e:
        out["versions"]["api"] = {"error": str(e)}

    # Dashboard version from git
    out["versions"]["dashboard"] = _ops_dashboard_version()

    try:
        pr = http.get(f"{PATCHED_API_INTERNAL}/admin/ops/partitions", timeout=8, verify=_VERIFY_INTERNAL)
        if pr.ok and pr.content:
            out["partitions"] = pr.json()
    except Exception as e:
        out["partitions"]["error"] = str(e)

    # ── Firewall timers (prod-01 local systemctl) ─────────────────────────────
    for edge, unit in [
        ("prod-01-edge", "hetzner-firewall-apply.service"),
        ("api-01-edge",  "hetzner-firewall-apply-api.service"),
    ]:
        props = _ops_get_systemctl_prop(
            unit,
            "ActiveState", "ExecMainStartTimestamp", "ExecMainExitTimestamp", "ExecMainStatus",
        )
        # Timer next-elapse
        timer_props = _ops_get_systemctl_prop(
            unit.replace(".service", ".timer"),
            "ActiveState", "NextElapseUSecRealtime",
        )
        out["firewall"][edge] = {
            "unit": unit,
            "last_active_state": props.get("ActiveState", "unknown"),
            # ExecMainStartTimestamp is set even for failed oneshots; ActiveExitTimestamp is not.
            "last_apply_timestamp": props.get("ExecMainStartTimestamp") or props.get("ExecMainExitTimestamp") or None,
            "last_exit_code": props.get("ExecMainStatus") or None,
            "timer_active": timer_props.get("ActiveState") == "active",
        }

    # ── TLS cert expiry ───────────────────────────────────────────────────────
    for host in ("api.patched.im", "dashboard.patched.im", "app.patched.im"):
        cert = _ops_cert_expiry(host)
        if cert:
            out["certs"].append(cert)

    # ── PAT-990: patch/reboot/timer drift (Patching tile) ────────────────────
    # This is a local, cheap read of the three check_statuses rows the
    # PAT-989 scheduler tick (_run_maintenance_drift_check_tick) already
    # records every tick — same convention as versions.dashboard reporting
    # _ops_dashboard_version() rather than re-deriving it here. Never fetch
    # the boxes' facts live from this endpoint; that work belongs to the tick.
    _MAINT_BOXES = (
        ("prod-01", "maintenance_prod01"),
        ("api-01", "maintenance_api01"),
        ("portal-01", "maintenance_portal01"),
    )
    _maint_rows = {
        row["name"]: row for row in _get_check_statuses()
        if row["name"].startswith("maintenance_")
    }
    for box, check_name in _MAINT_BOXES:
        row = _maint_rows.get(check_name)
        if row:
            out["maintenance"].append({
                "box": box,
                "state": row["state"],
                "reason": row["reason"],
                "evaluated_at": row["evaluated_at"],
            })
        else:
            # A row can be legitimately absent (scheduler tick hasn't run
            # since deploy) -- report it as its own unconfigured entry rather
            # than silently omitting the box, same "no data must not look
            # like nothing wrong" discipline as the rest of this file.
            out["maintenance"].append({
                "box": box,
                "state": "unconfigured",
                "reason": f"no {check_name} row recorded yet -- the maintenance-drift-check scheduler tick has not run since this was deployed",
                "evaluated_at": None,
            })

    # ── PAT-1171: any check_statuses row currently degraded or unconfigured
    # ────────────────────────────────────────────────────────────────────
    # Generic across every check name written via _record_check_status --
    # this is the staff-visible surface that closes the gap PAT-1132 found:
    # portal_auth (and, separately, deploy_drift) sat degraded in SQLite for
    # ~10 days with nobody looking. Deliberately not filtered to exclude the
    # maintenance_* rows already summarised above; a check going degraded
    # should show up here regardless of whether another tile also renders
    # it, so nothing added to check_statuses in the future can silently
    # fall outside every tile's coverage.
    out["checks_attention"] = _get_check_statuses(("degraded", "unconfigured"))

    return JSONResponse(out)


@app.post("/api/ops/firewall-apply")
async def api_ops_firewall_apply(request: Request):
    """PAT-710: guarded firewall-apply trigger.

    Owner-only, audit-logged. Body: {"edge": "prod-01-edge"|"api-01-edge"}.
    Runs `systemctl start hetzner-firewall-apply.service` (or -api variant) —
    no sudo (PAT-931). www-data is authorized for exactly these two units'
    start verb via a polkit rule (deploy/49-patched-ops-fw.rules) that talks
    to systemd over D-Bus directly; there's no setuid transition here at all,
    which is what let PAT-887 turn NoNewPrivileges=true on for this service.
    Returns the unit's journal tail after start.
    """
    import subprocess

    body = await request.json()
    edge = (body.get("edge") or "").strip()
    if edge not in ("prod-01-edge", "api-01-edge"):
        return JSONResponse({"error": "edge must be 'prod-01-edge' or 'api-01-edge'"}, 400)

    unit = "hetzner-firewall-apply-api.service" if edge == "api-01-edge" else "hetzner-firewall-apply.service"

    # PAT-799: this route already sat in _DESTRUCTIVE_RULES, so the middleware
    # logs actor/outcome for every call; attach the edge + result here instead
    # of a second bespoke _audit_write (the old code double-logged one row from
    # here and one from the middleware for the same request).
    request.state.audit_resource_name = edge
    actor = (
        _session_decode(request.cookies.get(SESSION_COOKIE, ""))
        or _cf_email(request)
        or "unknown"
    )
    slog = f"[ops-fw] actor={actor} edge={edge} unit={unit}"
    print(slog, flush=True)

    try:
        result = subprocess.run(
            ["systemctl", "start", unit],
            capture_output=True, text=True, timeout=120,
        )
        exit_code = result.returncode

        # Fetch journal tail for the unit (last 20 lines).
        journal = subprocess.run(
            ["journalctl", "-u", unit, "-n", "20", "--no-pager", "--output=short-iso"],
            capture_output=True, text=True, timeout=10,
        )
        journal_lines = journal.stdout.strip() if journal.returncode == 0 else "(journal unavailable)"

        request.state.audit_after = f"exit_code={exit_code} unit={unit}"
        return JSONResponse({
            "ok": exit_code == 0,
            "exit_code": exit_code,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "journal": journal_lines,
            "unit": unit,
            "edge": edge,
        })
    except subprocess.TimeoutExpired:
        request.state.audit_after = f"timeout unit={unit}"
        return JSONResponse({"error": "timeout waiting for firewall apply (>120s)"}, 504)
    except Exception as e:
        request.state.audit_after = f"exception unit={unit} err={e}"
        return JSONResponse({"error": str(e)}, 500)


# ── PAT-780: global Docs section (GitHub-backed, read-only) ─────────────────
# Internal-only, like every /api/* route — never proxied to the customer portal.
_DOCS_MD_EXTENSIONS = ["fenced_code", "tables", "sane_lists"]


def _docs_humanize(filename: str) -> str:
    stem = filename.rsplit(".", 1)[0]
    return stem.replace("_", " ").replace("-", " ").strip().title()


def _docs_title(text: str, fallback: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("# "):
            return line[2:].strip()
    return fallback


def _docs_category(rel: Path) -> str:
    parts = rel.parts
    return parts[0] if len(parts) > 1 else "General"


def _docs_resolve(rel_path: str) -> Path:
    """Resolve a doc-relative path under _DOCS_ROOT, rejecting traversal outside it."""
    candidate = (_DOCS_ROOT / rel_path).resolve()
    if candidate != _DOCS_ROOT and not str(candidate).startswith(str(_DOCS_ROOT) + os.sep):
        raise ValueError("path escapes docs root")
    if candidate.suffix.lower() != ".md":
        raise ValueError("not a markdown file")
    return candidate


def _docs_iter_files():
    if not _DOCS_ROOT.is_dir():
        return
    for p in sorted(_DOCS_ROOT.rglob("*.md")):
        if p.is_file():
            yield p


# PAT-902: python-markdown passes raw HTML embedded in doc source straight
# through unescaped (that's the vulnerability: a docs/*.md file containing
# `<script>` or an `onerror=` handler renders live in the staff console,
# which then does `... + d.html + ...` into innerHTML with no client-side
# escaping). Sanitise server-side before the HTML ever leaves this endpoint.
#
# Deliberately stdlib-only (html.parser.HTMLParser), not a third-party
# sanitiser (bleach was evaluated and rejected, see PR description). The
# allowlist below is the exact tag/attribute surface _DOCS_MD_EXTENSIONS
# (fenced_code, tables, sane_lists) plus stock python-markdown legitimately
# emit, confirmed by rendering sample docs, plus <details>/<summary>: raw
# HTML actually used today in docs/architecture.md for collapsible previous-
# snapshot sections (checked every docs/*.md file for real raw-HTML usage
# before finalising this list; that was the only hit besides plain markdown
# constructs). Anything not allowlisted is dropped: a disallowed tag is
# unwrapped (its text content is kept, escaped, but the tag itself is not)
# while its children still go through the same allowlist. script/style are
# dropped tag-and-content, since neither is ever legitimate rendered doc
# content. No <img>: no docs/*.md file uses one today; add it (with a
# relative/https-only src, mirroring the href scheme check) if that changes.
_DOCS_HTML_ALLOWED_TAGS = {
    "h1", "h2", "h3", "h4", "h5", "h6",
    "p", "ul", "ol", "li",
    "table", "thead", "tbody", "tr", "th", "td",
    "pre", "code",
    "a", "em", "strong", "blockquote", "hr", "br",
    "details", "summary",
}
# Tags whose content (not just the tag) must be dropped entirely.
_DOCS_HTML_DROP_CONTENT_TAGS = {"script", "style"}
# Void tags: no children, never need a closing tag re-emitted.
_DOCS_HTML_VOID_TAGS = {"br", "hr"}
_DOCS_HTML_ALLOWED_ATTRS = {
    "a": {"href", "title"},
    "code": {"class"},  # fenced_code emits class="language-xxx" on <code>
    "th": {"style"},    # tables extension emits style="text-align: ...;" for :---: columns
    "td": {"style"},
    "details": {"open"},
}
_DOCS_HTML_URL_SCHEMES = {"http", "https", "mailto"}
# Matches exactly what python-markdown's tables extension emits for column
# alignment. Nothing else is a legitimate value here, so reject anything
# that doesn't match rather than trying to sanitise arbitrary CSS.
_DOCS_HTML_STYLE_RE = re.compile(r"^text-align:\s*(left|right|center);?$")


_DOCS_HTML_HREF_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):")


def _docs_safe_href(value):
    if value is None:
        return None
    # Browsers strip TAB/LF/CR from anywhere in a URL before parsing the
    # scheme, which is the classic "java\tscript:" filter-bypass trick, so
    # strip them here first so the scheme check sees what the browser sees.
    cleaned = value.strip().translate({0x09: None, 0x0A: None, 0x0D: None})
    if any(ord(ch) < 0x20 for ch in cleaned):
        return None  # other control characters: never legitimate, reject outright
    # Reject scheme-relative links ("//evil.example/x") and their backslash-
    # normalised variants ("\\evil.example", "/\evil.example") -- browsers
    # treat backslash as a path separator in URLs, so all of these resolve to
    # an absolute link to an ARBITRARY HOST under the current scheme even
    # though there's no "scheme:" prefix for the check below to catch. A
    # single leading slash (a same-origin absolute path, e.g. "/docs/x.md")
    # is fine; two or more is a different host.
    normalized = cleaned.replace("\\", "/")
    if len(normalized) - len(normalized.lstrip("/")) >= 2:
        return None
    m = _DOCS_HTML_HREF_SCHEME_RE.match(cleaned)
    if not m:
        return cleaned  # no scheme: relative link or #fragment, e.g. "SCHEMA.md", "../x.md"
    if m.group(1).lower() not in _DOCS_HTML_URL_SCHEMES:
        return None
    return cleaned


class _DocsHtmlSanitizer(_HTMLParser):
    """Rebuild markdown-rendered doc HTML through the allowlist above."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = []
        self._drop_content_depth = 0

    def _emit_open(self, tag, attrs_list):
        kept_attrs = []
        allowed = _DOCS_HTML_ALLOWED_ATTRS.get(tag, set())
        for name, value in attrs_list:
            name = (name or "").lower()
            if name not in allowed:
                continue
            if tag == "a" and name == "href":
                safe = _docs_safe_href(value)
                if safe is None:
                    continue
                kept_attrs.append(f'href="{_html.escape(safe, quote=True)}"')
            elif tag in ("th", "td") and name == "style":
                if not value or not _DOCS_HTML_STYLE_RE.match(value.strip()):
                    continue
                kept_attrs.append(f'style="{_html.escape(value.strip(), quote=True)}"')
            else:
                kept_attrs.append(f'{name}="{_html.escape(value or "", quote=True)}"')
        attr_str = (" " + " ".join(kept_attrs)) if kept_attrs else ""
        self.out.append(f"<{tag}{attr_str}>")

    def handle_starttag(self, tag, attrs):
        if tag in _DOCS_HTML_DROP_CONTENT_TAGS:
            self._drop_content_depth += 1
            return
        if self._drop_content_depth:
            return
        if tag in _DOCS_HTML_ALLOWED_TAGS:
            self._emit_open(tag, attrs)

    def handle_startendtag(self, tag, attrs):
        if tag in _DOCS_HTML_DROP_CONTENT_TAGS:
            # HTMLParser still emits a later handle_endtag() for a self-closed
            # <script/>/<style/> (the "/" is meaningless on a non-void HTML
            # element; a real browser keeps the element open and treats
            # everything up to the next literal </script> as raw content).
            # Enter drop mode here too, or that raw content leaks through
            # handle_data as visible escaped text instead of being dropped.
            self._drop_content_depth += 1
            return
        if self._drop_content_depth:
            return
        if tag in _DOCS_HTML_ALLOWED_TAGS:
            self._emit_open(tag, attrs)
            if tag not in _DOCS_HTML_VOID_TAGS:
                self.out.append(f"</{tag}>")

    def handle_endtag(self, tag):
        if tag in _DOCS_HTML_DROP_CONTENT_TAGS:
            if self._drop_content_depth:
                self._drop_content_depth -= 1
            return
        if self._drop_content_depth:
            return
        if tag in _DOCS_HTML_ALLOWED_TAGS and tag not in _DOCS_HTML_VOID_TAGS:
            self.out.append(f"</{tag}>")

    def handle_data(self, data):
        if self._drop_content_depth:
            return
        self.out.append(_html.escape(data, quote=False))

    def handle_entityref(self, name):
        if self._drop_content_depth:
            return
        self.out.append(f"&{name};")

    def handle_charref(self, name):
        if self._drop_content_depth:
            return
        self.out.append(f"&#{name};")

    def get_html(self):
        return "".join(self.out)


def _docs_sanitize_html(raw_html: str) -> str:
    sanitizer = _DocsHtmlSanitizer()
    sanitizer.feed(raw_html)
    sanitizer.close()
    return sanitizer.get_html()


@app.get("/api/docs/tree")
def api_docs_tree():
    """List every docs/*.md file grouped by top-level folder (category)."""
    grouped: dict[str, list] = {}
    count = 0
    for p in _docs_iter_files():
        rel = p.relative_to(_DOCS_ROOT)
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        title = _docs_title(text, _docs_humanize(p.name))
        # No last-edited timestamp here on purpose: the box's deploy model does
        # `git reset --hard` on every push, which resets every file's mtime to
        # deploy time regardless of which docs actually changed — a filesystem
        # mtime would misrepresent itself as a real "last updated" date.
        grouped.setdefault(_docs_category(rel), []).append({
            "path": rel.as_posix(),
            "title": title,
        })
        count += 1
    categories = [
        {"category": cat, "docs": sorted(items, key=lambda d: d["title"].lower())}
        for cat, items in sorted(grouped.items(), key=lambda kv: kv[0].lower())
    ]
    return JSONResponse({"categories": categories, "count": count})


@app.get("/api/docs/content")
def api_docs_content(path: str):
    try:
        fp = _docs_resolve(path)
    except ValueError:
        return JSONResponse({"error": "invalid path"}, status_code=400)
    if not fp.is_file():
        return JSONResponse({"error": "not found"}, status_code=404)
    text = fp.read_text(encoding="utf-8", errors="replace")
    title = _docs_title(text, _docs_humanize(fp.name))
    raw_html = _markdown.markdown(text, extensions=_DOCS_MD_EXTENSIONS)
    safe_html = _docs_sanitize_html(raw_html)
    github_url = f"https://github.com/{DOCS_GITHUB_REPO}/blob/{DOCS_GITHUB_BRANCH}/{DOCS_ROOT_DIR}/{path}"
    return JSONResponse({"path": path, "title": title, "html": safe_html, "github_url": github_url})


@app.get("/api/docs/search")
def api_docs_search(q: str = ""):
    q = (q or "").strip()
    if not q:
        return JSONResponse({"results": []})
    ql = q.lower()
    results = []
    for p in _docs_iter_files():
        rel = p.relative_to(_DOCS_ROOT)
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        title = _docs_title(text, _docs_humanize(p.name))
        hay = text.lower()
        idx = hay.find(ql)
        if ql not in title.lower() and idx < 0:
            continue
        snippet = ""
        if idx >= 0:
            start = max(0, idx - 60)
            end = min(len(text), idx + len(q) + 60)
            snippet = text[start:end].replace("\n", " ").strip()
        results.append({
            "path": rel.as_posix(),
            "title": title,
            "category": _docs_category(rel),
            "snippet": snippet,
        })
    results.sort(key=lambda r: r["title"].lower())
    return JSONResponse({"results": results[:50]})


# ══════════════════════════════════════════════════════════════════════════════
# Admin Tools ▸ Logs — a unified, interrogable feed over every log source the
# dashboard already writes, plus remote automation-run history.
# ══════════════════════════════════════════════════════════════════════════════
# Owner-only (see _OWNER_ONLY_GET + the RBAC check in api_bearer_auth) —
# impersonation session records live in this feed, which is as sensitive as
# anything a consultant could otherwise see.
#
# Normalised entry shape (one dict per row, newest-first):
#   id           str   "<source>:<source-native id>" — stable, globally unique
#   ts           str   ISO8601 UTC — the column each source already stamps
#   source       str   one of _LOG_SOURCES's keys
#   source_label str   human label for the UI (mirrors _LOG_SOURCES[source])
#   actor        str   email/"system"/"—" — whichever the source actually records
#   action       str   short machine-ish label (e.g. "DELETE /admin/tenants/t-1")
#   summary      str   one human-readable line for the collapsed table row
#   outcome      str   normalised bucket: success | info | warning | error | denied
#                       (doubles as "severity" — see the docstring on admin_logs)
#   outcome_raw  str   the source's own outcome/status string, unmodified
#   detail       dict  every raw column from the source row — the expanded-row payload
#
# Sources included (see _LOG_SOURCES for the full list + labels):
#   admin_audit        admin_audit_log — every privileged /admin/* action. Written
#                       since PAT-695 but never had a reader until this ticket.
#   impersonation      impersonation_audit_log — tenant impersonation sessions.
#   report_send        report_send_audit_log — report delivery attempts.
#   alert_sent         Outbound Slack alert history, merged from FOUR separate
#                       idempotency-ledger tables that are all really the same
#                       thing ("what did we tell Slack, and when"):
#                       automation_alerts_sent (run failures), automation_stale_
#                       alerts_sent (jobs that stopped running), health_alerts_sent
#                       (tenant → at_risk transitions), automation_digest_sent
#                       (daily all-clear confirmation). detail.kind (see each
#                       _fetch_* below) tells the four apart on the expanded row.
#   automation_run     Remote — GET {PATCHED_API_INTERNAL}/admin/automations'
#                       recent_runs, flattened to one entry per run. Degrades
#                       gracefully: sources["automation_run"].available=false
#                       with an .error string if api-01 is unreachable, rather
#                       than failing the whole request.
#   conversion_event   conversion_events (Needs Attention CTA clicks) — included;
#                       no actor is recorded at write time (client-side event,
#                       not an operator action), so actor is always "—".
#   device_log_request device_log_requests (on-demand agent log bundle asks) —
#                       included for the same reason/caveat as conversion_event.
#
# Filtering is server-side and pushed into SQL for every local source (time
# range, free-text LIKE across the source's own text columns, and an
# outcome-bucket predicate translated back into that source's raw column) so
# a growing table never has to be pulled client-side to be filtered. See
# _log_fetch's docstring for why a per-source LIMIT of `cap` rows, taken
# independently from each source and then merged, is sufficient to assemble a
# correct global top-N — no unbounded read ever happens.

_LOG_SOURCES = {
    "admin_audit":        "Admin audit",
    "impersonation":      "Impersonation",
    "report_send":        "Report sends",
    "alert_sent":         "Outbound alerts",
    "automation_run":     "Automation runs",
    "conversion_event":   "Conversion events",
    "device_log_request": "Device log requests",
}

# Outcome buckets double as "severity" for filtering/colouring in the UI.
# Not every source models every bucket — a source that doesn't model a given
# bucket simply contributes zero rows when that bucket is requested (see
# _bucket_where's "1=0" fallback below), rather than ignoring the filter.
_LOG_OUTCOMES = ("success", "info", "warning", "error", "denied")

_LOG_DEFAULT_LIMIT = 200
_LOG_MAX_LIMIT = 1000


def _log_entry(source: str, raw_id, ts: str, actor: str | None, action: str,
                summary: str, outcome: str, outcome_raw: str, detail: dict) -> dict:
    return {
        "id": f"{source}:{raw_id}",
        "ts": ts or "",
        "source": source,
        "source_label": _LOG_SOURCES.get(source, source),
        "actor": actor or "—",
        "action": action,
        "summary": summary,
        "outcome": outcome,
        "outcome_raw": outcome_raw,
        "detail": detail,
    }


def _bucket_where(bucket_sql: dict, buckets: set) -> str | None:
    """SQL predicate (no leading AND) for the requested outcome buckets,
    translated via this source's own bucket_sql map of {bucket: raw-column
    predicate}. None means "no outcome filter requested" (buckets falsy). If
    buckets is non-empty but none of them are modelled by this source, returns
    "1=0" so the source contributes zero rows for that filter rather than
    silently ignoring it (e.g. filtering to outcome=denied should show no
    conversion_event rows, not every conversion_event row)."""
    if not buckets:
        return None
    parts = [bucket_sql[b] for b in buckets if b in bucket_sql]
    return "(" + " OR ".join(parts) + ")" if parts else "1=0"


def _log_fetch(db, table: str, ts_col: str, since: str, until: str, q: str,
                q_cols: tuple, bucket_sql: dict, buckets: set, cap: int) -> list:
    """Fetch up to `cap` rows from one local log table, newest-first, with
    time range + free-text + outcome-bucket filters all applied in SQL.

    table/ts_col/q_cols are always internal constants (never request input) —
    only VALUES are parameterised, so the f-string identifier interpolation
    below is not a SQL-injection surface.

    Why a per-source cap of `cap` rows is enough for a correct global top-N:
    any row that belongs in the true global top-N (by ts, across all sources)
    can have at most N-1 rows anywhere — including within its own source —
    with a larger ts. So it is necessarily within its own source's top-N too.
    Taking each source's own top-`cap` candidates, merging, and re-sorting
    therefore reproduces the correct global top-`cap` exactly."""
    where, params = [], []
    if since:
        where.append(f"{ts_col} >= ?"); params.append(since)
    if until:
        where.append(f"{ts_col} <= ?"); params.append(until)
    if q:
        if q_cols:
            where.append("(" + " OR ".join(f"{c} LIKE ?" for c in q_cols) + ")")
            params.extend([f"%{q}%"] * len(q_cols))
        else:
            where.append("1=0")  # nothing to search in this source
    bw = _bucket_where(bucket_sql, buckets)
    if bw is not None:
        where.append(bw)
    sql = f"SELECT * FROM {table}"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += f" ORDER BY {ts_col} DESC LIMIT ?"
    params.append(cap)
    return db.execute(sql, params).fetchall()


def _log_count(db, table: str, ts_col: str, since: str, until: str, q: str,
                q_cols: tuple, bucket_sql: dict, buckets: set) -> int:
    """Same filters as _log_fetch, but a COUNT(*) — lets the UI show
    "showing N of TOTAL" per source without pulling TOTAL rows over the wire."""
    where, params = [], []
    if since:
        where.append(f"{ts_col} >= ?"); params.append(since)
    if until:
        where.append(f"{ts_col} <= ?"); params.append(until)
    if q:
        if q_cols:
            where.append("(" + " OR ".join(f"{c} LIKE ?" for c in q_cols) + ")")
            params.extend([f"%{q}%"] * len(q_cols))
        else:
            where.append("1=0")
    bw = _bucket_where(bucket_sql, buckets)
    if bw is not None:
        where.append(bw)
    sql = f"SELECT COUNT(*) AS n FROM {table}"
    if where:
        sql += " WHERE " + " AND ".join(where)
    row = db.execute(sql, params).fetchone()
    return row["n"] if row else 0


def _bucket_admin_audit(outcome: str) -> str:
    if outcome == "allowed":
        return "success"
    if outcome in ("denied_rbac", "confirm_missing", "confirm_mismatch"):
        return "denied"
    if outcome == "in_progress":
        return "info"
    # "error" and every "rejected_<status>" outcome (a 4xx/5xx the handler
    # returned without raising) both mean the write did not happen — error.
    return "error"


_ADMIN_AUDIT_BUCKET_SQL = {
    "success": "outcome = 'allowed'",
    "denied":  "outcome IN ('denied_rbac','confirm_missing','confirm_mismatch')",
    "info":    "outcome = 'in_progress'",
    "error":   "(outcome = 'error' OR outcome LIKE 'rejected\\_%' ESCAPE '\\')",
}


def _bucket_impersonation(action: str) -> str:
    return "warning" if action == "write_enabled" else "info"


_IMPERSONATION_BUCKET_SQL = {
    "info":    "action IN ('started','ended')",
    "warning": "action = 'write_enabled'",
}


def _bucket_report_send(outcome: str) -> str:
    if outcome == "sent":
        return "success"
    if outcome == "rejected":
        return "warning"
    return "error"  # "failed"


_REPORT_SEND_BUCKET_SQL = {
    "success": "outcome = 'sent'",
    "warning": "outcome = 'rejected'",
    "error":   "outcome = 'failed'",
}

# conversion_events / device_log_requests: same story — routine, no
# success/failure axis worth modelling — always "info".
_ALWAYS_INFO_BUCKET_SQL = {"info": "1=1"}


def _log_local_source(entries: list, sources_meta: dict, db, key: str, table: str,
                       ts_col: str, q_cols: tuple, bucket_sql: dict,
                       since: str, until: str, q: str, buckets: set, cap: int,
                       row_to_entry) -> None:
    """Fetch + count one local table, map its rows to normalised entries via
    row_to_entry(row), and record availability in sources_meta. A query
    failure degrades just that one source rather than the whole request."""
    try:
        for row in _log_fetch(db, table, ts_col, since, until, q, q_cols, bucket_sql, buckets, cap):
            entries.append(row_to_entry(row))
        matched = _log_count(db, table, ts_col, since, until, q, q_cols, bucket_sql, buckets)
        sources_meta[key] = {"label": _LOG_SOURCES[key], "available": True, "matched": matched}
    except Exception as exc:
        sources_meta[key] = {"label": _LOG_SOURCES[key], "available": False, "matched": 0, "error": str(exc)}


def _log_alert_sent_source(entries: list, sources_meta: dict, db,
                            since: str, until: str, q: str, buckets: set, cap: int) -> None:
    """The four outbound-alert idempotency ledgers, merged into one logical
    "alert_sent" source (see the module docstring above for why)."""
    try:
        merged = []
        for row in _log_fetch(db, "automation_alerts_sent", "alerted_at", since, until, q,
                               ("job_name",), {"error": "1=1"}, buckets, cap):
            merged.append(_log_entry(
                "alert_sent", f"job-failure:{row['job_name']}:{row['run_id']}", row["alerted_at"],
                "system", "automation_failure_alert",
                f'Slack alert sent — automation "{row["job_name"]}" run #{row["run_id"]} failed',
                "error", "job_failure_alert",
                {"kind": "job_failure_alert", **dict(row)}))
        for row in _log_fetch(db, "automation_stale_alerts_sent", "alerted_at", since, until, q,
                               ("job_name",), {"warning": "1=1"}, buckets, cap):
            merged.append(_log_entry(
                "alert_sent", f"stale:{row['job_name']}:{row['alert_date']}", row["alerted_at"],
                "system", "automation_stale_alert",
                f'Slack alert sent — automation "{row["job_name"]}" has gone stale (no new run)',
                "warning", "stale_alert",
                {"kind": "stale_alert", **dict(row)}))
        for row in _log_fetch(db, "automation_digest_sent", "sent_at", since, until, q,
                               ("digest_date",), {"success": "1=1"}, buckets, cap):
            merged.append(_log_entry(
                "alert_sent", f"digest:{row['digest_date']}", row["sent_at"],
                "system", "automation_health_digest",
                f'Slack daily automation health digest posted for {row["digest_date"]}',
                "success", "daily_digest",
                {"kind": "daily_digest", **dict(row)}))
        # PAT-1011 considered making this feed reflect alert_delivered
        # per-row (sent vs failed), but health_alerts_sent is a
        # current-STATE table upserted every tick for every tenant
        # (including tenants who were never at_risk and tenants who
        # recovered), not an event log of alert attempts -- alert_delivered
        # only means "nothing currently owed", not "an alert was attempted
        # this tick". Labelling every row by that column would make a
        # healthy tenant's routine state row read as "Slack alert sent",
        # and a RECOVERED tenant could read as a fresh "Slack alert send
        # FAILED" forever, inheriting whatever alert_delivered value its
        # last at-risk episode happened to end on. That is worse than the
        # existing imprecision this feed already had, not better, so left
        # as it was pre-PAT-1011. The underlying data-model issue (this
        # table conflates state-tracking with event-logging, so every
        # tenant shows up here every tick regardless of whether anything
        # happened) is real and pre-existing -- tracked separately, not a
        # PAT-1011 regression to fix under this ticket's scope.
        for row in _log_fetch(db, "health_alerts_sent", "alerted_at", since, until, q,
                               ("tenant_id", "bucket"), {"warning": "1=1"}, buckets, cap):
            merged.append(_log_entry(
                "alert_sent", f"health:{row['tenant_id']}:{row['bucket']}", row["alerted_at"],
                "system", "health_at_risk_alert",
                f'Slack alert sent — tenant {row["tenant_id"]} transitioned to "{row["bucket"]}"',
                "warning", "health_transition_alert",
                {"kind": "health_transition_alert", **dict(row)}))
        merged.sort(key=lambda e: e["ts"], reverse=True)
        entries.extend(merged[:cap])

        matched = sum([
            _log_count(db, "automation_alerts_sent", "alerted_at", since, until, q,
                       ("job_name",), {"error": "1=1"}, buckets),
            _log_count(db, "automation_stale_alerts_sent", "alerted_at", since, until, q,
                       ("job_name",), {"warning": "1=1"}, buckets),
            _log_count(db, "automation_digest_sent", "sent_at", since, until, q,
                       ("digest_date",), {"success": "1=1"}, buckets),
            _log_count(db, "health_alerts_sent", "alerted_at", since, until, q,
                       ("tenant_id", "bucket"), {"warning": "1=1"}, buckets),
        ])
        sources_meta["alert_sent"] = {"label": _LOG_SOURCES["alert_sent"], "available": True, "matched": matched}
    except Exception as exc:
        sources_meta["alert_sent"] = {"label": _LOG_SOURCES["alert_sent"], "available": False, "matched": 0, "error": str(exc)}


def _automation_run_bucket(status: str) -> str:
    if status == "success":
        return "success"
    if status == "failed":
        return "error"
    return "info"  # e.g. "running", or an unrecognised future status


def _log_automation_run_entries(jobs: list, since: str, until: str, q: str, buckets: set) -> list:
    """Flatten {"jobs":[{job_name, schedule, recent_runs:[...]}]} into log
    entries, filtered in Python — this list is already small/bounded (a
    handful of recent runs per registered job), so there's no growing-table
    concern that would otherwise demand pushing the filter into a query."""
    ql = q.lower() if q else ""
    out = []
    for job in jobs or []:
        job_name = job.get("job_name", "")
        schedule = job.get("schedule", "")
        for run in job.get("recent_runs") or []:
            ts = run.get("started_at") or run.get("finished_at") or ""
            if since and ts < since:
                continue
            if until and ts > until:
                continue
            status = run.get("status", "")
            bucket = _automation_run_bucket(status)
            if buckets and bucket not in buckets:
                continue
            output = run.get("output") or ""
            error_msg = run.get("error_msg") or ""
            if ql and ql not in " ".join([job_name, schedule, status, output, error_msg]).lower():
                continue
            summary = f'Automation "{job_name}" run {status}'
            if error_msg:
                summary += f' — {error_msg[:200]}'
            out.append(_log_entry(
                "automation_run", f'{job_name}:{run.get("id")}', ts, "system",
                f"automation_run:{job_name}", summary, bucket, status,
                {"job_name": job_name, "schedule": schedule, **run}))
    out.sort(key=lambda e: e["ts"], reverse=True)
    return out


@app.get("/admin/logs")
def admin_logs(request: Request, q: str = "", since: str = "", until: str = "",
                limit: int = _LOG_DEFAULT_LIMIT, offset: int = 0):
    """Unified, interrogable admin log feed — see the module docstring above
    this section for the entry shape and the full source list. Owner-only;
    enforced by _OWNER_ONLY_GET in the api_bearer_auth middleware, not here.

    Query params:
      source   repeatable and/or comma-separated (?source=admin_audit&source=
               impersonation, or ?source=admin_audit,impersonation) — which of
               _LOG_SOURCES to include. Omit/empty = every source.
      outcome  same repeatable/comma-separated shape, over _LOG_OUTCOMES.
               Omit/empty = no outcome filter.
      q        free-text, matched against each source's own text columns.
      since/until  ISO8601 UTC bounds (inclusive), matched against each
               source's own timestamp column.
      limit    default 200, clamped to [1, 1000].
      offset   default 0, clamped to >= 0. offset+limit is also clamped to
               1000 — the per-source candidate window never exceeds that, so
               this endpoint never does an unbounded read.
    """
    q = (q or "").strip()
    since = (since or "").strip()
    until = (until or "").strip()
    limit = max(1, min(limit or _LOG_DEFAULT_LIMIT, _LOG_MAX_LIMIT))
    offset = max(0, offset or 0)
    cap = min(offset + limit, _LOG_MAX_LIMIT)

    requested_sources = set()
    for raw in request.query_params.getlist("source"):
        requested_sources.update(s.strip() for s in raw.split(",") if s.strip())
    sources = (requested_sources & set(_LOG_SOURCES)) if requested_sources else set(_LOG_SOURCES)

    requested_buckets = set()
    for raw in request.query_params.getlist("outcome"):
        requested_buckets.update(b.strip() for b in raw.split(",") if b.strip())
    buckets = requested_buckets & set(_LOG_OUTCOMES)

    entries: list = []
    sources_meta: dict = {}

    with get_db() as db:
        if "admin_audit" in sources:
            _log_local_source(
                entries, sources_meta, db, "admin_audit", "admin_audit_log", "ts",
                ("actor_email", "method", "path", "resource", "resource_name", "reason", "outcome"),
                _ADMIN_AUDIT_BUCKET_SQL, since, until, q, buckets, cap,
                lambda r: _log_entry(
                    "admin_audit", r["id"], r["ts"], r["actor_email"],
                    f'{r["method"]} {r["path"]}', r["resource_name"] or r["resource"] or r["path"],
                    _bucket_admin_audit(r["outcome"] or ""), r["outcome"] or "", dict(r)))

        if "impersonation" in sources:
            _log_local_source(
                entries, sources_meta, db, "impersonation", "impersonation_audit_log", "created_at",
                ("session_id", "tenant_id", "actor_email", "action"),
                _IMPERSONATION_BUCKET_SQL, since, until, q, buckets, cap,
                lambda r: _log_entry(
                    "impersonation", r["id"], r["created_at"], r["actor_email"],
                    f'impersonation_{r["action"]}',
                    f'{r["actor_email"]} {r["action"]} impersonation of tenant {r["tenant_id"]}',
                    _bucket_impersonation(r["action"]), r["action"], dict(r)))

        if "report_send" in sources:
            _log_local_source(
                entries, sources_meta, db, "report_send", "report_send_audit_log", "ts",
                ("actor_email", "tenant_id", "tenant_name", "report_type", "recipient",
                 "recipient_category", "outcome", "detail"),
                _REPORT_SEND_BUCKET_SQL, since, until, q, buckets, cap,
                lambda r: _log_entry(
                    "report_send", r["id"], r["ts"], r["actor_email"],
                    f'report_send:{r["report_type"]}',
                    f'{r["report_type"]} report to {r["recipient"]} ({r["tenant_name"] or r["tenant_id"]}) — {r["outcome"]}',
                    _bucket_report_send(r["outcome"] or ""), r["outcome"] or "", dict(r)))

        if "alert_sent" in sources:
            _log_alert_sent_source(entries, sources_meta, db, since, until, q, buckets, cap)

        if "conversion_event" in sources:
            _log_local_source(
                entries, sources_meta, db, "conversion_event", "conversion_events", "recorded_at",
                ("tenant_id", "event_name", "category", "severity"),
                _ALWAYS_INFO_BUCKET_SQL, since, until, q, buckets, cap,
                lambda r: _log_entry(
                    "conversion_event", r["id"], r["recorded_at"], None,
                    f'conversion:{r["event_name"]}',
                    f'{r["event_name"]} — tenant {r["tenant_id"]}' + (f' ({r["category"]})' if r["category"] else ""),
                    "info", r["event_name"], dict(r)))

        if "device_log_request" in sources:
            _log_local_source(
                entries, sources_meta, db, "device_log_request", "device_log_requests", "requested_at",
                ("tenant_id", "device_id", "device_name"),
                _ALWAYS_INFO_BUCKET_SQL, since, until, q, buckets, cap,
                lambda r: _log_entry(
                    "device_log_request", r["request_id"], r["requested_at"], None,
                    "device_log_requested",
                    f'Log bundle requested — {r["device_name"] or r["device_id"]} (tenant {r["tenant_id"]})',
                    "info", "requested", dict(r)))

    if "automation_run" in sources:
        try:
            r = http.get(f"{PATCHED_API_INTERNAL}/admin/automations", timeout=10, verify=_VERIFY_INTERNAL)
            r.raise_for_status()
            jobs = (r.json() or {}).get("jobs", [])
            run_entries = _log_automation_run_entries(jobs, since, until, q, buckets)
            entries.extend(run_entries[:cap])
            sources_meta["automation_run"] = {
                "label": _LOG_SOURCES["automation_run"], "available": True, "matched": len(run_entries),
            }
        except Exception as exc:
            # PAT: must never 500 the whole Logs page just because api-01 is
            # unreachable — every other source above has already been fetched.
            sources_meta["automation_run"] = {
                "label": _LOG_SOURCES["automation_run"], "available": False, "matched": 0,
                "error": f"automation runs unavailable: {exc}",
            }

    entries.sort(key=lambda e: e["ts"], reverse=True)
    page = entries[offset:offset + limit]

    return JSONResponse({
        "entries": page,
        "count": len(page),
        "total_matched": sum(m.get("matched", 0) for m in sources_meta.values()),
        "limit": limit,
        "offset": offset,
        "sources": sources_meta,
    })


if __name__ == "__main__":
    import uvicorn
    print("\n  Patched.im Dashboard")
    print("  http://localhost:8000\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
