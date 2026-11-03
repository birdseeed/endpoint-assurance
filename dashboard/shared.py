"""
shared.py — Resources shared by main.py: database, templates, mail, and a
couple of leftover public-upload-retention helpers (see below).

Originally also shared with public_router.py (the anonymous public CVE-scan
/ Intune-upload funnel, PAT-233); that funnel was removed under PAT-866 and
now lives at scan.patched.im (portal repo).
"""

import base64
import os
import re
import sqlite3
import sys
import time
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone, timedelta
from pathlib import Path

import jinja2 as _jinja2
import requests as http
from fastapi.templating import Jinja2Templates

from intune_upload import (
    neutralise_formula,
)

# ── Config ──
NVD_API_KEY         = os.getenv("NVD_API_KEY", "")
DASHBOARD_API_KEY   = os.getenv("DASHBOARD_API_KEY", "")

# PAT-228 added this so smoke-tested deploys could exercise the email-compose
# path without transmitting, and it stayed set on prod-01 from ~2026-07-17.
# PAT-1346 (2026-09-03) switched real sending ON and unset it in production.
# The deploy gate was inverted in the same commit: scripts/smoke/
# email_delivery.py now FAILS THE DEPLOY unless /api/smoke/health reports
# email_delivery == "live". Setting this again in production without
# inverting that module back will therefore auto-rollback the next deploy --
# the dependency runs in both directions, deliberately, so the flag and the
# gate can never disagree silently. Full writeup: truth_manifest.yaml's
# prod01-email-delivery entry / PAT-1346.
def _parse_email_dry_run(raw: str) -> bool:
    """Parse EMAIL_DRY_RUN explicitly rather than by truthiness.

    PAT-1346: this was `bool(os.getenv("EMAIL_DRY_RUN", ""))`, which is True
    for ANY non-empty string -- including "0", "false" and "no". That was
    harmless while the operational rule was "must be set to 1", but the rule
    is now "must be absent", so the obvious way to disable suppression by
    hand (EMAIL_DRY_RUN=0) would have silently switched it back ON and
    stopped all outbound mail.

    An unrecognised value resolves to ON, the conservative direction for
    accidental sends, and says so on stderr rather than deciding quietly.
    That is safe to do now only because a suppressed state is no longer
    invisible: scripts/smoke/email_delivery.py fails the deploy unless
    delivery is live, and the hourly email_delivery check_statuses row
    reports degraded.
    """
    value = raw.strip().lower()
    if value in ("", "0", "false", "no", "off"):
        return False
    if value in ("1", "true", "yes", "on"):
        return True
    print(
        f"[email] EMAIL_DRY_RUN={raw!r} is not a recognised boolean; "
        "treating outbound email as SUPPRESSED. Use 1 or 0, or unset it.",
        file=sys.stderr,
        flush=True,
    )
    return True


EMAIL_DRY_RUN = _parse_email_dry_run(os.getenv("EMAIL_DRY_RUN", ""))

_EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

# ── PAT-109: Microsoft Graph sendMail (scheduled report delivery) ──
# Patched.im Mailer app (app-only Mail.Send, scoped to MAIL_SENDER via an
# Exchange ApplicationAccessPolicy). This is the sole outbound-email provider.
GRAPH_MAIL_TENANT_ID     = os.getenv("GRAPH_MAIL_TENANT_ID", "")
GRAPH_MAIL_CLIENT_ID     = os.getenv("GRAPH_MAIL_CLIENT_ID", "")
GRAPH_MAIL_CLIENT_SECRET = os.getenv("GRAPH_MAIL_CLIENT_SECRET", "")
MAIL_SENDER              = os.getenv("MAIL_SENDER", "noreply@patched.im")
PUBLIC_BASE_URL     = os.getenv("PUBLIC_BASE_URL", "https://dashboard.patched.im").rstrip("/")
# PAT-866: PUBLIC_RETENTION_DAYS still gates _cleanup_old_public_uploads()/
# _public_retention_sweep() below, which keep sweeping the now-frozen
# public_uploads/public_scans tables (no new rows land there any more, but
# old ones past retention still get purged on the existing schedule).
PUBLIC_RETENTION_DAYS = int(os.getenv("PUBLIC_RETENTION_DAYS", "30"))

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

# ── Paths ──
BASE = Path(__file__).parent
# DASHBOARD_DB_PATH lets an out-of-process test harness (e.g. the Playwright
# E2E suite under e2e/, which drives a real `uvicorn main:app` subprocess and
# so can't use the tests/ monkeypatch-DB_PATH trick) point the app at a
# throwaway sqlite file instead of the real on-disk dashboard.db. Unset in
# production, so the default path below is unchanged.
_DB_PATH_OVERRIDE = os.getenv("DASHBOARD_DB_PATH", "").strip()
DB_PATH = Path(_DB_PATH_OVERRIDE) if _DB_PATH_OVERRIDE else BASE / "dashboard.db"
# PAT-2307: everything else the app writes at runtime lives in
# DASHBOARD_STATE_DIR, never in the code tree. On patched-prod-01 the unit
# sets it to /var/lib/patched-dashboard (its StateDirectory=, which systemd
# creates before the service starts) and the code tree is root-owned and
# read-only to the service. Unset, as in local development and the tests,
# it is the checkout, as before. DB_PATH above is deliberately unchanged:
# production sets DASHBOARD_DB_PATH explicitly (PAT-994).
_STATE_DIR_OVERRIDE = os.getenv("DASHBOARD_STATE_DIR", "").strip()
STATE_DIR = Path(_STATE_DIR_OVERRIDE) if _STATE_DIR_OVERRIDE else BASE
REPORTS_DIR = STATE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# Email Jinja2 env — used by the scheduler outside request context
_email_env = _jinja2.Environment(
    loader=_jinja2.FileSystemLoader(str(BASE / "templates")),
    autoescape=_jinja2.select_autoescape(["html"]),
)

# ── Templates ──
templates = Jinja2Templates(directory=str(BASE / "templates"))
# Register neutralise_formula as a Jinja2 filter so templates can use {{ val | nf }}
templates.env.filters["nf"] = neutralise_formula


# ══════════════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════════════
# PAT-901: every dashboard.db connection goes through this helper so WAL mode
# and a busy_timeout are applied consistently. Without these, concurrent
# writers (hourly scheduler_loop tick functions, per-request audit rows,
# scan/retention threads) past SQLite's default 5s lock wait raise
# "database is locked". busy_timeout is a per-connection setting so it must
# be set on every open; journal_mode=WAL is persisted in the database file
# once set, but re-issuing the PRAGMA on each open is cheap and keeps the
# behaviour explicit and self-documenting at every call site.
_READONLY_CONNECTIONS = ContextVar("dashboard_readonly_connections", default=False)


@contextmanager
def readonly_db_connections():
    """Scope a read projection without changing writers or the configured path."""
    token = _READONLY_CONNECTIONS.set(True)
    try:
        yield
    finally:
        _READONLY_CONNECTIONS.reset(token)


def _open_db_connection(db_path):
    if _READONLY_CONNECTIONS.get():
        # mode=ro refuses missing databases and never changes journal mode.
        conn = sqlite3.connect(Path(db_path).resolve().as_uri() + "?mode=ro", uri=True, timeout=1)
        conn.row_factory = sqlite3.Row
        return conn
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


@contextmanager
def get_db():
    conn = _open_db_connection(DB_PATH)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ══════════════════════════════════════════════════════════════
# EMAIL — Microsoft Graph sendMail
# ══════════════════════════════════════════════════════════════
_graph_mail_token_cache = {"token": "", "exp": 0.0}


def _graph_mail_token() -> str | None:
    """Client-credentials access token for the Patched.im Mailer app.
    Cached in-process until ~60s before expiry. Returns None if unconfigured
    or on failure (caller falls back / logs)."""
    if not (GRAPH_MAIL_TENANT_ID and GRAPH_MAIL_CLIENT_ID and GRAPH_MAIL_CLIENT_SECRET):
        return None
    now = time.time()
    if _graph_mail_token_cache["token"] and now < _graph_mail_token_cache["exp"]:
        return _graph_mail_token_cache["token"]
    try:
        r = http.post(
            f"https://login.microsoftonline.com/{GRAPH_MAIL_TENANT_ID}/oauth2/v2.0/token",
            data={"client_id": GRAPH_MAIL_CLIENT_ID,
                  "client_secret": GRAPH_MAIL_CLIENT_SECRET,
                  "scope": "https://graph.microsoft.com/.default",
                  "grant_type": "client_credentials"},
            timeout=15,
        )
        if r.status_code != 200:
            print(f"[email:graph] token {r.status_code}: {r.text[:200]}")
            return None
        body = r.json()
        _graph_mail_token_cache["token"] = body["access_token"]
        _graph_mail_token_cache["exp"] = now + int(body.get("expires_in", 3600)) - 60
        return _graph_mail_token_cache["token"]
    except Exception as e:
        print(f"[email:graph] token error: {e}")
        return None


def _graph_send_mail(to_email: str, subject: str, html: str, text: str,
                     attachment_path: str | None = None,
                     attachment_name: str | None = None,
                     reply_to: str | None = None) -> bool:
    """Send a single email as MAIL_SENDER via Microsoft Graph sendMail.
    Returns True on success. Logs but does not raise.

    PAT-1990: reply_to sets the message's Reply-To header. MAIL_SENDER is an
    unmonitored noreply mailbox, so any message that invites a reply (the
    portal welcome email asks the recipient to reply for help) has to name a
    mailbox a human actually reads. Optional and defaulted to None, so every
    pre-existing caller keeps sending exactly the message it sent before."""
    token = _graph_mail_token()
    if not token:
        print(f"[email:graph] no token — would have sent to {to_email}: {subject}")
        return False
    message = {
        "subject": subject,
        "body": {"contentType": "HTML", "content": html or text},
        "toRecipients": [{"emailAddress": {"address": to_email}}],
    }
    if reply_to:
        message["replyTo"] = [{"emailAddress": {"address": reply_to}}]
    if attachment_path and os.path.exists(attachment_path):
        with open(attachment_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        fname = attachment_name or os.path.basename(attachment_path)
        ctype = ("application/pdf" if fname.lower().endswith(".pdf")
                 else "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        message["attachments"] = [{
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": fname,
            "contentType": ctype,
            "contentBytes": b64,
        }]
    try:
        r = http.post(
            f"https://graph.microsoft.com/v1.0/users/{MAIL_SENDER}/sendMail",
            json={"message": message, "saveToSentItems": False},
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json"},
            timeout=30,
        )
        if r.status_code >= 300:
            print(f"[email:graph] sendMail {r.status_code}: {r.text[:300]}")
            return False
        return True
    except Exception as e:
        print(f"[email:graph] sendMail error: {e}")
        return False


def _send_email(to_email: str, subject: str, html: str, text: str,
                attachment_path: str | None = None,
                attachment_name: str | None = None,
                reply_to: str | None = None) -> bool:
    """Send via Microsoft Graph only. Returns True on success; callers surface failures.

    PAT-1990: reply_to is optional and forwarded to _graph_send_mail(). It does
    NOT change this function's dry-run contract — under EMAIL_DRY_RUN this still
    returns True without sending, so a caller that needs to know whether delivery
    is actually live must consult email_delivery_status() (see PAT-1010 below).
    """
    if EMAIL_DRY_RUN:
        print(f"[email:dry-run] Would send to {to_email!r}: {subject!r}")
        return True
    # Graph is the sole sender. Missing or invalid Graph configuration fails closed.
    return _graph_send_mail(to_email, subject, html, text, attachment_path,
                            attachment_name, reply_to)


def email_delivery_status() -> str:
    """Whether _send_email() can currently deliver a real message, based on
    configuration presence only (no network calls, cheap enough to call from
    a request handler).

    PAT-1010: _send_email()'s own bool return means "did the caller's send
    attempt succeed", and is deliberately True under EMAIL_DRY_RUN so the
    ~dozen ordinary feature-email callers (digests, trial nudges, lead
    confirmations) keep working without actually mailing anyone. That is
    correct for them, but a caller that specifically needs to know whether
    delivery is actually live right now (a health check, a deliverability
    probe) must not infer that from a bare True. Call this instead.

    Returns "dry_run" while EMAIL_DRY_RUN is set (delivery is deliberately
    suppressed), "unconfigured" if Graph is not set up, else "live". Mirrors the tri-state vocabulary already used
    by check_statuses (ok/degraded/unconfigured) rather than inventing a new
    one; see main.py's _record_check_status.

    "live" here means only "a provider is configured", not "verified
    working": invalid or expired credentials read identically to good ones.
    For an actual credential-validity check use email_delivery_check()
    below, which is heavier (it can make a real network call) and is meant
    for the hourly scheduler tick, not a per-request check.
    """
    if EMAIL_DRY_RUN:
        return "dry_run"
    if GRAPH_MAIL_TENANT_ID and GRAPH_MAIL_CLIENT_ID and GRAPH_MAIL_CLIENT_SECRET:
        return "live"
    return "unconfigured"


def email_delivery_check() -> "tuple[str, str]":
    """Fuller delivery-capability check for the scheduler's hourly
    email_delivery check_statuses row (PAT-1010). Returns (state, reason) in
    check_statuses' own vocabulary (ok/degraded/unconfigured).

    email_delivery_status() above only looks at whether a provider is
    *configured*; "an API key is present" is not the same claim as "this
    actually works": invalid, expired, or wrong-scope credentials would
    read identically to a healthy path there, which is exactly the
    false-green failure shape PAT-837/912/960 hit before (config read but
    never validated). This function validates where a cheap check already
    exists in this codebase rather than adding a new outbound probe:

    * Graph is _send_email()'s sole path, and
      _graph_mail_token() already performs (and caches) a real OAuth
      client-credentials request. Reusing it here means a broken Graph
      credential shows up as "degraded", not a false "ok", and since the
      token is cached for close to its full lifetime, this does not add a
      network call on every scheduler tick beyond what the cache would
      already need to do roughly once an hour, matching the cadence other
      scheduler ticks in this codebase already use for their own live
      validation calls (e.g. the PAT-837 portal_auth Cloudflare AUD check).
      A successful token fetch only proves the app credentials authenticate
      though, not that Mail.Send permission or MAIL_SENDER access is granted
      -- an actual sendMail call can still 403 on a missing permission grant
      or Application Access Policy restriction that this check does not
      probe (a real send-capability probe or a Graph permission-grant query
      is a deeper project than this ticket takes on). The "ok" reason text
      says exactly that rather than implying full deliverability was
      verified.
    """
    if EMAIL_DRY_RUN:
        return "degraded", (
            "EMAIL_DRY_RUN is set, so outbound email is suppressed estate-wide; "
            "_send_email() logs and returns True without sending anything"
        )
    if GRAPH_MAIL_TENANT_ID and GRAPH_MAIL_CLIENT_ID and GRAPH_MAIL_CLIENT_SECRET:
        if _graph_mail_token():
            return "ok", (
                "OAuth token acquired successfully; this confirms the app credentials "
                "authenticate, not that Mail.Send permission or MAIL_SENDER access is "
                "granted (a token request can succeed while the actual sendMail call "
                "still 403s on a missing permission grant or Application Access Policy "
                "restriction, which this check does not probe)"
            )
        return "degraded", (
            "GRAPH_MAIL_TENANT_ID/GRAPH_MAIL_CLIENT_ID/GRAPH_MAIL_CLIENT_SECRET are "
            "configured but the OAuth token request failed, so Graph sendMail is not "
            "actually deliverable right now (see [email:graph] token logs for the reason)"
        )
    return "unconfigured", (
        "Microsoft Graph mail is not configured (GRAPH_MAIL_TENANT_ID/"
        "GRAPH_MAIL_CLIENT_ID/GRAPH_MAIL_CLIENT_SECRET all unset)"
    )


# ══════════════════════════════════════════════════════════════
# PUBLIC UPLOAD HELPERS (PAT-233 / intune upload funnel)
# ══════════════════════════════════════════════════════════════
# PAT-866 removed the funnel that used to call these (now scan.patched.im,
# portal repo) along with _verify_turnstile/_get_client_ip/
# _check_public_rate_limit, which had no remaining caller. This one stays —
# main.py's scheduler startup still runs it to sweep the now-frozen
# public_uploads table per the existing PUBLIC_RETENTION_DAYS policy.
def _cleanup_old_public_uploads():
    """Delete public upload records and report files older than PUBLIC_RETENTION_DAYS."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=PUBLIC_RETENTION_DAYS)).isoformat()
    with get_db() as db:
        old = db.execute(
            "SELECT report_path FROM public_uploads WHERE created_at < ?", (cutoff,)
        ).fetchall()
    for row in old:
        path = row["report_path"]
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass
    with get_db() as db:
        db.execute("DELETE FROM public_uploads WHERE created_at < ?", (cutoff,))
    print(f"[cleanup] Removed {len(old)} old public upload record(s)")


# ══════════════════════════════════════════════════════════════
# PUBLIC CVE-SCAN HELPERS (patched.im/cve-scan)
# ══════════════════════════════════════════════════════════════
# PAT-866 removed _client_ip/_check_rate_limits/_mask_email — the funnel
# that called them (now scan.patched.im, portal repo) is gone. main.py
# also had its own local _mask_email, for the GET /admin/monitoring/
# public-scans staff route (removed under PAT-1196 — see main.py), so
# the one here was unreachable even before that ticket.
def _safe_filename(name: str, default: str) -> str:
    """Return a path-safe basename for an uploaded file. NEVER trust the client
    filename: UploadFile.filename is attacker-controlled and unsanitised, so a
    value like '../../etc/x' would escape the target dir on write (PAT-456)."""
    base = os.path.basename((name or "").replace("\\", "/").strip()).lstrip(". ").strip()
    if not base or base in (".", ".."):
        return default
    return base[:128]


def _public_retention_sweep():
    """Delete files + rows older than PUBLIC_RETENTION_DAYS. Run daily."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=PUBLIC_RETENTION_DAYS)).isoformat()
    with get_db() as db:
        rows = db.execute(
            "SELECT id, devices_path, apps_path, report_path FROM public_scans "
            "WHERE created_at < ? AND (deleted_at IS NULL OR deleted_at = '')",
            (cutoff,),
        ).fetchall()
    for r in rows:
        for p in (r["devices_path"], r["apps_path"], r["report_path"]):
            if p and os.path.exists(p):
                try: os.unlink(p)
                except Exception as e: print(f"[retention] unlink {p}: {e}")
        with get_db() as db:
            db.execute(
                "UPDATE public_scans SET status='deleted', deleted_at=?, "
                "devices_path=NULL, apps_path=NULL, report_path=NULL WHERE id=?",
                (datetime.now(timezone.utc).isoformat(), r["id"]),
            )
    if rows:
        print(f"[retention] purged {len(rows)} public scan(s) older than {PUBLIC_RETENTION_DAYS}d")


def _public_retention_loop():
    """Daily retention sweep, started from startup hook."""
    while True:
        try: _public_retention_sweep()
        except Exception as e: print(f"[retention] error: {e}")
        time.sleep(24 * 3600)
