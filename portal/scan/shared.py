"""shared.py — Resources shared between the scan app and its router.

This is the public-scan subset of the dashboard's shared.py (PAT-457), lifted
into the standalone scan.patched.im service. It carries ONLY what the public
CVE-scan / Intune-upload funnel needs: config, the SQLite handle, email
(Microsoft Graph primary + SendGrid fallback), Turnstile verification, the
rate-limit and retention helpers, and the background scan worker.

Deliberately absent (unlike the dashboard original): the dashboard API key,
tenant credentials, and any Graph tenant-scan path. This service holds no
platform secrets beyond mail + Turnstile.

State (scan.db, uploads/, reports/, nvd.db) lives under a writable state dir
(systemd StateDirectory=/var/lib/patched-scan); the app code dir is read-only.
"""

import base64
import functools
import fcntl
import hashlib
import hmac
import multiprocessing
from multiprocessing import reduction as _mp_reduction
import os
import queue as _queue
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from html import escape as _html_escape
from pathlib import Path

import jinja2 as _jinja2
import requests as http
from fastapi.templating import Jinja2Templates
from intune_upload import neutralise_formula
from scanner import LEGAL_LINE, LEGAL_NAME, run_scan_from_upload

# ── Config ──
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# ── Public upload config (PAT-233) ──
TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY", "")
TURNSTILE_SITE_KEY = os.getenv("TURNSTILE_SITE_KEY", "")
EMAIL_DRY_RUN = bool(os.getenv("EMAIL_DRY_RUN", ""))
PUBLIC_RATE_EMAIL_MAX = int(os.getenv("PUBLIC_RATE_EMAIL_MAX", "3"))
PUBLIC_RATE_IP_MAX = int(os.getenv("PUBLIC_RATE_IP_MAX", "10"))

# ── Pricing / design-partner enquiry form (PAT-1978) ──
# Receiving end of the website's (patched.im/pricing) enquiry form. Own
# rate-limit counters so a burst of enquiries never shares a budget with the
# CVE-scan funnel, and vice versa.
PRICING_RATE_EMAIL_MAX = int(os.getenv("PRICING_RATE_EMAIL_MAX", "3"))
PRICING_RATE_IP_MAX = int(os.getenv("PRICING_RATE_IP_MAX", "10"))
PRICING_ENQUIRY_TO = os.getenv("PRICING_ENQUIRY_TO", "hello@patched.im")

# ── Mac app waitlist (PAT-2560) ──
# Receiving end of the patched.im homepage form. Own counters, same defaults
# as the enquiry form. Each new sign up is announced to WAITLIST_NOTIFY_TO,
# which defaults to wherever enquiries already go.
WAITLIST_RATE_EMAIL_MAX = int(os.getenv("WAITLIST_RATE_EMAIL_MAX", "3"))
WAITLIST_RATE_IP_MAX = int(os.getenv("WAITLIST_RATE_IP_MAX", "10"))
WAITLIST_NOTIFY_TO = os.getenv("WAITLIST_NOTIFY_TO", "") or PRICING_ENQUIRY_TO

_EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

# ── Public scan flow (scan.patched.im/public/scan) ──
# PAT-2564: explicit opt-in only; missing or malformed values fail closed.
PUBLIC_SCAN_ENABLED = os.getenv("PUBLIC_SCAN_ENABLED", "").strip().lower() == "true"
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY", "")
SCAN_FROM_EMAIL = os.getenv("SCAN_FROM_EMAIL", "scans@patched.im")
SCAN_FROM_NAME = os.getenv("SCAN_FROM_NAME", "Patched.im")

# ── PAT-109: Microsoft Graph sendMail (report delivery, primary) ──
# Patched.im Mailer app (app-only Mail.Send, scoped to MAIL_SENDER via an
# Exchange ApplicationAccessPolicy). When these are set, _send_email prefers
# Graph over the legacy SendGrid path.
GRAPH_MAIL_TENANT_ID = os.getenv("GRAPH_MAIL_TENANT_ID", "")
GRAPH_MAIL_CLIENT_ID = os.getenv("GRAPH_MAIL_CLIENT_ID", "")
GRAPH_MAIL_CLIENT_SECRET = os.getenv("GRAPH_MAIL_CLIENT_SECRET", "")
MAIL_SENDER = os.getenv("MAIL_SENDER", "noreply@patched.im")
# PAT-1184: ops copy of every scan REPORT email (not OTP/verification mail).
# Unset/empty = no BCC = today's behaviour.
SCAN_REPORT_BCC = os.getenv("SCAN_REPORT_BCC", "").strip()
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "https://scan.patched.im").rstrip("/")
TURNSTILE_SECRET = os.getenv("TURNSTILE_SECRET", "")
# PAT-893: explicit, deliberate opt-out for local dev only. Forgetting to set
# TURNSTILE_SECRET in production must refuse traffic, not silently disable
# bot protection.
TURNSTILE_DEV_BYPASS = os.getenv("TURNSTILE_DEV_BYPASS", "") == "1"
PUBLIC_RETENTION_DAYS = int(os.getenv("PUBLIC_RETENTION_DAYS", "30"))
PUBLIC_RL_PER_EMAIL_24H = PUBLIC_RATE_EMAIL_MAX
PUBLIC_RL_PER_IP_24H = PUBLIC_RATE_IP_MAX
OTP_EXPIRY_MIN = 15
OTP_MAX_ATTEMPTS = 5

# Hard wall-clock bound for the public CVE-scan job's report-generation step
# (PAT-1177 -- this path previously had no timeout at all: _run_public_scan
# ran on a bare daemon thread with no join/timeout of any kind, so a
# hung/grinding scan sat in status='scanning' forever with nothing to notice
# or recover it). Mirrors UPLOAD_JOB_TIMEOUT_SECONDS in router.py.
PUBLIC_SCAN_JOB_TIMEOUT_SECONDS = int(os.getenv("PUBLIC_SCAN_JOB_TIMEOUT_SECONDS", "300"))

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
PUBLIC_MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB hard cap per file

# ── Paths ──
# BASE = the (read-only) app code dir: templates + static + logo live here.
BASE = Path(__file__).parent
# STATE_DIR = the writable state dir (systemd StateDirectory=/var/lib/patched-scan).
# $STATE_DIRECTORY is exported by systemd; SCAN_STATE_DIR is an explicit override
# used by tests and local runs. Falls back to ./state next to the code for a bare
# local invocation.
STATE_DIR = Path(
    os.getenv("SCAN_STATE_DIR")
    or os.getenv("STATE_DIRECTORY")
    or str(BASE / "state")
)
STATE_DIR.mkdir(parents=True, exist_ok=True)
# PAT-994: scan.db lives in its own sub-directory containing nothing else, so
# the backup unit's ReadWritePaths grant can be narrowed to exactly that —
# STATE_DIR itself still holds uploads/ and reports/ (and nvd.db alongside
# it), which the backup job has no business writing to. SCAN_DB_DIR is an
# explicit override, same pattern as SCAN_STATE_DIR above, for tests/local
# runs that want the DB somewhere else without moving the whole state tree.
DB_DIR = Path(os.getenv("SCAN_DB_DIR") or str(STATE_DIR / "db"))
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DB_DIR / "scan.db"
# Uploaded CSV/JSON, one sub-dir per scan_id. Purged after the report is built.
PUBLIC_DIR = STATE_DIR / "uploads"
PUBLIC_DIR.mkdir(exist_ok=True)
# Generated .docx reports (both the CVE scan and the Intune-upload funnel).
PUBLIC_REPORTS_DIR = STATE_DIR / "reports"
PUBLIC_REPORTS_DIR.mkdir(exist_ok=True)

# Email Jinja2 env — used outside request context.
_email_env = _jinja2.Environment(
    loader=_jinja2.FileSystemLoader(str(BASE / "templates")),
    autoescape=_jinja2.select_autoescape(["html"]),
)

# ── Templates (shared so the router can render pages) ──
templates = Jinja2Templates(directory=str(BASE / "templates"))
templates.env.filters["nf"] = neutralise_formula
# PAT-2520: the legal entity, defined once in scanner.py (re-exported here for
# the router and tests). Templates read `legal_name` / `legal_line`; none
# spells the name out.
templates.env.globals["legal_name"] = LEGAL_NAME
templates.env.globals["legal_line"] = LEGAL_LINE

# PAT-2237: scan's own static dir - scan.patched.im is a separate FastAPI
# app on its own StaticFiles mount (scan/app.py), so it needs its own
# static_url() rather than sharing the portal's.
SCAN_STATIC_DIR = (BASE / "static").resolve()


@functools.cache
def static_url(path: str) -> str:
    """Return a cache-busted /static/ URL for scan-owned static files:
    /static/{path}?v={sha256(bytes)[:12]}. See main.py's static_url() for
    the full rationale (PAT-2237) - this is the same pattern applied to
    scan's own static dir, since scan-owned assets (site.css, favicon.svg)
    carried the identical hand-bumped-?v= problem.
    """
    target = (SCAN_STATIC_DIR / path).resolve()
    if target != SCAN_STATIC_DIR and SCAN_STATIC_DIR not in target.parents:
        raise ValueError(f"static_url: {path!r} resolves outside the static directory")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()[:12]
    return f"/static/{path}?v={digest}"


templates.env.globals["static_url"] = static_url


# ══════════════════════════════════════════════════════════════
# BOUNDED CONCURRENCY (PAT-1177)
# ══════════════════════════════════════════════════════════════
# A small fail-closed cap on how many report-generation jobs (Intune upload
# + public CVE scan) may run at once. Acquired with blocking=False at the
# request handler, before anything is marked processing/verified: a
# saturated cap must refuse the request outright rather than queue it
# silently, so a burst of traffic (or an attacker) cannot pile up unbounded
# background subprocesses on the box. Released in a try/finally around the
# job -- including on the hard-kill timeout path below -- so a slot is never
# leaked.
MAX_CONCURRENT_SCAN_JOBS = int(os.getenv("MAX_CONCURRENT_SCAN_JOBS", "4"))
_SCAN_JOB_SEMAPHORE = threading.BoundedSemaphore(MAX_CONCURRENT_SCAN_JOBS)


def try_acquire_scan_slot() -> bool:
    """Non-blocking acquire of one of MAX_CONCURRENT_SCAN_JOBS slots.
    Returns False immediately when saturated. Callers MUST NOT start a job
    or record anything as processing when this returns False (fail
    closed) -- return a friendly "try again later" response instead."""
    return _SCAN_JOB_SEMAPHORE.acquire(blocking=False)


def release_scan_slot() -> None:
    """Release a slot acquired via try_acquire_scan_slot(). Callers MUST
    call this in a try/finally that wraps the whole job -- success,
    hard-kill timeout, or error -- so a slot is never leaked."""
    _SCAN_JOB_SEMAPHORE.release()


# ══════════════════════════════════════════════════════════════
# KILLABLE REPORT-GENERATION SUBPROCESS (PAT-1177)
# ══════════════════════════════════════════════════════════════
# Report generation (generate_devices_report / generate_apps_cve_report /
# the scan-and-generate step in scanner.run_scan_from_upload) is the CPU-
# heavy part of each job. Python threads cannot be killed, so the PAT-1173
# thread-based timeout could only bound how long a job was WAITED on, never
# actually stop a hung/grinding worker -- it kept running forever after the
# supervisor gave up. Running just that step in a multiprocessing.Process
# lets the parent genuinely terminate it.
#
# Everything else -- DB writes, the guarded status='processing' claim, and
# the email send -- stays on the caller's own thread, unchanged from
# PAT-1173: the child here never touches the DB and never sends email, so
# there is no SQLite-from-subprocess contention and the terminal-state logic
# is untouched.
#
# Always spawn, never inherit the platform default (fork on Linux). uvicorn
# runs sync handlers in a threadpool, so other threads exist in this process
# and may hold locks (logging's, the allocator's, ...) at the instant we
# fork; the child inherits memory as-is, including any lock held mid-release,
# and can deadlock on it forever with no thread left alive to release it.
# spawn starts a clean interpreter instead, sidestepping that class of bug
# entirely. A private context object (not multiprocessing.set_start_method,
# which is process-global and can only be set once) so this can't fight the
# app or the test runner over the global default.
_MP_CONTEXT = multiprocessing.get_context("spawn")


def _detach_report_job_guard(descriptor):
    return descriptor.detach()


class _ReportJobGuard:
    """Transfer the held open-file description during spawn serialization.

    Calling DupFd inside __reduce__ uses multiprocessing's spawn pass-fd
    mechanism, rather than a later resource-sharing server handshake. The
    child therefore inherits the held lock before it can execute any work;
    death before transfer cannot leave an unguarded writer running.
    """

    def __init__(self, fd):
        self.fd = fd

    def __reduce__(self):
        return (_detach_report_job_guard, (_mp_reduction.DupFd(self.fd),))


def _report_job_child(target, args, result_queue, guard_fd=None) -> None:
    """Runs inside the child process. Deliberately module-level (not a
    closure/lambda) so it is picklable/importable by the freshly spawned
    interpreter, which re-imports this module from scratch. `target` and
    every element of `args` must themselves be picklable -- module-level
    functions and plain rows/paths/strings, never a live DB connection or
    anything holding one. The `stats` value put on the queue must stay
    small: a large object can block this put() until the parent drains the
    queue, and the parent only reads after join() returns -- a big-enough
    payload would hang both sides."""
    try:
        stats = target(*args)
        result_queue.put({"ok": True, "stats": stats})
    except Exception as exc:
        result_queue.put({"ok": False, "error": str(exc)[:500]})
    # Deliberately keep guard_fd open for this process's full lifetime,
    # including queue flushing and interpreter cleanup. The OS closes it on
    # exit; LOCK_UN here would also unlock the parent's open-file description.
    # This function is only the spawned process entry point.


@dataclass
class ReportJobOutcome:
    status: str  # "done" | "timeout" | "error"
    stats: "dict | None" = None
    error: "str | None" = None


def _discard_partial_report(path: "str | None") -> None:
    """Best-effort removal of a report file a killed or crashed child may
    have left half-written at `path`. A terminated process can be stopped
    mid doc.save() -- that file isn't just unrecorded, it may be a
    truncated/corrupt .docx -- so remove it unconditionally rather than
    leaving it for a caller's superseded-job cleanup to maybe find."""
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except OSError as exc:
        print(f"[report-job] could not remove partial report {path}: {exc}")


def run_report_job(target, args: tuple, timeout_seconds: float,
                   output_path: "str | None", *, guard_fd: "int | None" = None) -> ReportJobOutcome:
    """Run `target(*args)` -- the report-generation call only -- in a
    subprocess hard-bounded to `timeout_seconds` wall-clock. Genuinely stops
    a hung/grinding job (unlike a thread-join bound, which can only stop
    waiting, never stop the thread): on timeout the child is terminated
    (SIGTERM via proc.terminate()), given 5s to exit, then killed (SIGKILL
    via proc.kill()) if it still hasn't. Either way the parent always joins
    after terminate/kill so the child is never left a zombie. Any partial
    file at `output_path` is removed on the timeout path -- a killed
    process can leave a truncated .docx mid doc.save().

    Returns a ReportJobOutcome:
      - status="done", stats=<whatever `target` returned>
      - status="timeout" (child ran past timeout_seconds and was killed)
      - status="error", error=<str> (child raised, or exited abnormally
        with nothing on the result queue)

    `target` MUST be a module-level function (not a closure/lambda) and
    every element of `args` MUST be picklable (parsed rows/lists, output
    path, logo path, NVD key -- never a DB handle). Always runs under the
    spawn start method (see _MP_CONTEXT above), regardless of the platform
    default. Optional guard_fd must refer to the caller's held scan lock;
    only this public-scan path supplies it. The child retains the same lock
    until its target can no longer write, even if its supervisor is killed.
    Other report jobs keep their existing unguarded API and outcomes.
    """
    result_queue = _MP_CONTEXT.Queue()
    guard = _ReportJobGuard(guard_fd) if guard_fd is not None else None
    proc = _MP_CONTEXT.Process(
        target=_report_job_child, args=(target, args, result_queue, guard), daemon=True,
    )
    proc.start()
    proc.join(timeout_seconds)

    if proc.is_alive():
        print(f"[report-job] hard-killing report generation after {timeout_seconds}s")
        proc.terminate()
        proc.join(5)
        if proc.is_alive():
            proc.kill()
            proc.join()
        _discard_partial_report(output_path)
        return ReportJobOutcome(status="timeout")

    # The child has already exited by this point (join() above returned
    # without a timeout), so a bounded get() here is just waiting out any
    # last sliver of pipe-flush latency, never the job itself. Queue.empty()
    # is documented as unreliable -- it can race with the child's put() even
    # after the process has exited -- so don't branch on it.
    try:
        result = result_queue.get(timeout=5)
    except _queue.Empty:
        result = None

    if result is None:
        # The process exited without ever putting anything on the queue --
        # an unhandled crash (segfault, OOM-killed, etc.) rather than a
        # Python exception _report_job_child could catch and report.
        _discard_partial_report(output_path)
        return ReportJobOutcome(
            status="error",
            error=f"report generation process exited abnormally (exit code {proc.exitcode})",
        )

    if result.get("ok"):
        return ReportJobOutcome(status="done", stats=result.get("stats"))
    _discard_partial_report(output_path)
    return ReportJobOutcome(
        status="error", error=result.get("error") or "report generation failed",
    )


# ══════════════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════════════
@contextmanager
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ══════════════════════════════════════════════════════════════
# EMAIL — Microsoft Graph sendMail (primary) + SendGrid (legacy)
# ══════════════════════════════════════════════════════════════
_graph_mail_token_cache = {"token": "", "exp": 0.0}


def _graph_mail_token() -> "str | None":
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
                     attachment_path: "str | None" = None,
                     attachment_name: "str | None" = None,
                     bcc: "str | None" = None) -> bool:
    """Send a single email as MAIL_SENDER via Microsoft Graph sendMail.
    Returns True on success. Logs but does not raise."""
    token = _graph_mail_token()
    if not token:
        print(f"[email:graph] no token — would have sent to {to_email}: {subject}")
        return False
    message = {
        "subject": subject,
        "body": {"contentType": "HTML", "content": html or text},
        "toRecipients": [{"emailAddress": {"address": to_email}}],
    }
    if bcc:
        message["bccRecipients"] = [{"emailAddress": {"address": bcc}}]
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
                attachment_path: "str | None" = None,
                attachment_name: "str | None" = None,
                bcc: "str | None" = None) -> bool:
    """Send an email. Prefers Microsoft Graph sendMail (PAT-109) when the
    Mailer app is configured, else falls back to the legacy SendGrid path.
    Returns True on success. Logs but does not raise — caller decides how to
    surface failures.

    `bcc` (PAT-1184) is an internal ops copy — callers pass it only for
    report-delivery emails, never for OTP/verification mail. Never logged."""
    if EMAIL_DRY_RUN:
        print(f"[email:dry-run] Would send to {to_email!r}: {subject!r}")
        return True
    # PAT-109: prefer Microsoft Graph sendMail when the Mailer app is configured.
    if GRAPH_MAIL_TENANT_ID and GRAPH_MAIL_CLIENT_ID and GRAPH_MAIL_CLIENT_SECRET:
        return _graph_send_mail(to_email, subject, html, text,
                                attachment_path, attachment_name, bcc)
    if not SENDGRID_API_KEY:
        print(f"[email] SENDGRID_API_KEY missing — would have sent to {to_email}: {subject}")
        return False
    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": SCAN_FROM_EMAIL, "name": SCAN_FROM_NAME},
        "subject": subject,
        "content": [
            {"type": "text/plain", "value": text},
            {"type": "text/html", "value": html},
        ],
    }
    if bcc:
        payload["personalizations"][0]["bcc"] = [{"email": bcc}]
    if attachment_path and os.path.exists(attachment_path):
        with open(attachment_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        payload["attachments"] = [{
            "content": b64,
            "filename": attachment_name or os.path.basename(attachment_path),
            "type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "disposition": "attachment",
        }]
    try:
        r = http.post(
            "https://api.sendgrid.com/v3/mail/send",
            json=payload,
            headers={"Authorization": f"Bearer {SENDGRID_API_KEY}",
                     "Content-Type": "application/json"},
            timeout=30,
        )
        if r.status_code >= 300:
            print(f"[email] SendGrid {r.status_code}: {r.text[:300]}")
            return False
        return True
    except Exception as e:
        print(f"[email] SendGrid error: {e}")
        return False


# ══════════════════════════════════════════════════════════════
# TURNSTILE
# ══════════════════════════════════════════════════════════════
def _verify_turnstile(token: str, remote_ip: str) -> bool:
    """Cloudflare Turnstile server-side verification. Fails CLOSED when
    TURNSTILE_SECRET is unset (PAT-893) — an operator who forgets to fill in
    the secret during install must get a refused-traffic service, not bot
    protection silently disabled. Set TURNSTILE_DEV_BYPASS=1 for local dev."""
    if not TURNSTILE_SECRET:
        if TURNSTILE_DEV_BYPASS:
            return True
        print("[turnstile] TURNSTILE_SECRET not set and TURNSTILE_DEV_BYPASS "
              "not set — refusing (fail closed)")
        return False
    try:
        r = http.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={"secret": TURNSTILE_SECRET, "response": token, "remoteip": remote_ip},
            timeout=10,
        )
        return r.status_code == 200 and r.json().get("success") is True
    except Exception as e:
        print(f"[turnstile] verify failed: {e}")
        return False


# ══════════════════════════════════════════════════════════════
# PUBLIC UPLOAD HELPERS (PAT-233 / intune upload funnel)
# ══════════════════════════════════════════════════════════════
def _get_client_ip(request) -> str:
    """Extract real client IP, preferring the CF-Connecting-IP header (set by Cloudflare)."""
    return (
        request.headers.get("cf-connecting-ip")
        or request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )


def _check_public_rate_limit(email: str, ip: str, db) -> "tuple[bool, str]":
    """Returns (allowed, reason). Checks per-email and per-IP upload counts in the last 24 h."""
    since = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
    email_count = db.execute(
        "SELECT COUNT(*) FROM public_uploads WHERE email=? AND created_at > ?",
        (email, since),
    ).fetchone()[0]
    if email_count >= PUBLIC_RATE_EMAIL_MAX:
        return False, (f"Too many uploads from this email address. "
                       f"Limit: {PUBLIC_RATE_EMAIL_MAX} per 24 hours.")
    ip_count = db.execute(
        "SELECT COUNT(*) FROM public_uploads WHERE ip=? AND created_at > ?",
        (ip, since),
    ).fetchone()[0]
    if ip_count >= PUBLIC_RATE_IP_MAX:
        return False, (f"Too many uploads from this IP address. "
                       f"Limit: {PUBLIC_RATE_IP_MAX} per 24 hours.")
    return True, ""


def _cleanup_old_public_uploads():
    """Delete public upload records and report files older than PUBLIC_RETENTION_DAYS."""
    cutoff = (datetime.now(UTC) - timedelta(days=PUBLIC_RETENTION_DAYS)).isoformat()
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
# PUBLIC CVE-SCAN HELPERS (scan.patched.im/public/scan)
# ══════════════════════════════════════════════════════════════
def _client_ip(request) -> str:
    """Honour CF-Connecting-IP (Cloudflare) then X-Forwarded-For, else peer."""
    cf = request.headers.get("cf-connecting-ip")
    if cf:
        return cf.strip()
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


def _scan_quota_mac(key: bytes, field: str, value: str) -> bytes:
    """Separate email and IP namespaces even if their strings coincide."""
    return hmac.digest(key, b"public-scan-quota\0" + field.encode() + b"\0" + value.encode(), "sha256")


def _purge_scan_erasure_limits(db, cutoff: str):
    db.execute("DELETE FROM public_scan_erasure_limits WHERE created_at<=?", (cutoff,))


def _check_rate_limits(email: str, ip: str) -> "str | None":
    """Returns an error string if rate-limited, else None."""
    cutoff = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
    with get_db() as db:
        _purge_scan_erasure_limits(db, cutoff)
        by_email = db.execute(
            "SELECT COUNT(*) FROM public_scans WHERE email=? AND created_at>?",
            (email, cutoff),
        ).fetchone()[0]
        by_ip = db.execute(
            "SELECT COUNT(*) FROM public_scans WHERE ip=? AND created_at>?",
            (ip, cutoff),
        ).fetchone()[0]
        for row in db.execute("SELECT mac_key, email_mac, ip_mac FROM public_scan_erasure_limits WHERE created_at>?", (cutoff,)):
            if row["email_mac"] is not None:
                by_email += hmac.compare_digest(row["email_mac"], _scan_quota_mac(row["mac_key"], "email", email))
            if row["ip_mac"] is not None:
                by_ip += hmac.compare_digest(row["ip_mac"], _scan_quota_mac(row["mac_key"], "ip", ip))
    if by_email >= PUBLIC_RL_PER_EMAIL_24H:
        return f"Too many scans from this email in the last 24h (limit {PUBLIC_RL_PER_EMAIL_24H})."
    if by_ip >= PUBLIC_RL_PER_IP_24H:
        return f"Too many scans from this network in the last 24h (limit {PUBLIC_RL_PER_IP_24H})."
    return None


def _check_pricing_rate_limit(email: str, ip: str) -> "str | None":
    """Returns an error string if rate-limited, else None. Same shape as
    _check_rate_limits above (PAT-1978), but against its own
    public_pricing_enquiries table so pricing-enquiry volume never shares
    counters with the CVE-scan funnel."""
    cutoff = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
    with get_db() as db:
        by_email = db.execute(
            "SELECT COUNT(*) FROM public_pricing_enquiries WHERE email=? AND created_at>?",
            (email, cutoff),
        ).fetchone()[0]
        by_ip = db.execute(
            "SELECT COUNT(*) FROM public_pricing_enquiries WHERE ip=? AND created_at>?",
            (ip, cutoff),
        ).fetchone()[0]
    if by_email >= PRICING_RATE_EMAIL_MAX:
        return (f"Too many enquiries from this email in the last 24h "
                f"(limit {PRICING_RATE_EMAIL_MAX}).")
    if by_ip >= PRICING_RATE_IP_MAX:
        return (f"Too many enquiries from this network in the last 24h "
                f"(limit {PRICING_RATE_IP_MAX}).")
    return None


def _check_waitlist_rate_limit(email: str, ip: str) -> "str | None":
    """Returns an error string if rate-limited, else None (PAT-2560). Counts
    waitlist_attempts, never waitlist_signups: a person already on the list
    and a stranger are limited identically, so the answer says nothing about
    who is on it."""
    cutoff = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
    with get_db() as db:
        by_email = db.execute(
            "SELECT COUNT(*) FROM waitlist_attempts WHERE email=? AND created_at>?",
            (email, cutoff),
        ).fetchone()[0]
        by_ip = db.execute(
            "SELECT COUNT(*) FROM waitlist_attempts WHERE ip=? AND created_at>?",
            (ip, cutoff),
        ).fetchone()[0]
    if by_email >= WAITLIST_RATE_EMAIL_MAX:
        return (f"That is too many tries from this email address in the last 24 hours "
                f"(limit {WAITLIST_RATE_EMAIL_MAX}).")
    if by_ip >= WAITLIST_RATE_IP_MAX:
        return (f"That is too many tries from this network in the last 24 hours "
                f"(limit {WAITLIST_RATE_IP_MAX}).")
    return None


def waitlist_unnotified_count() -> int:
    """Sign ups whose "new sign up" email was not accepted for delivery
    (PAT-2560). Zero in normal running. /healthz reports it so a mailer that
    has died does not look the same as a quiet week. Returns -1 when the
    table cannot be read."""
    try:
        with get_db() as db:
            return db.execute(
                "SELECT COUNT(*) FROM waitlist_signups WHERE notified_at IS NULL"
            ).fetchone()[0]
    except sqlite3.Error as exc:
        # /healthz must still answer. -1 is "could not be read", which is not
        # the same thing as 0 and must not be reported as it.
        print(f"[waitlist] could not count unnotified sign ups: {exc}")
        return -1


def _mask_email(email: str) -> str:
    try:
        local, domain = email.split("@", 1)
        if len(local) <= 2:
            return f"{local[0]}***@{domain}"
        return f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}@{domain}"
    except Exception:
        return "***"


def _safe_filename(name: str, default: str) -> str:
    """Return a path-safe basename for an uploaded file. NEVER trust the client
    filename: UploadFile.filename is attacker-controlled and unsanitised, so a
    value like '../../etc/x' would escape the target dir on write (PAT-456)."""
    base = os.path.basename((name or "").replace("\\", "/").strip()).lstrip(". ").strip()
    if not base or base in (".", ".."):
        return default
    return base[:128]


@contextmanager
def _public_scan_lock(scan_id: str, *, blocking: bool = True):
    """Coordinate erasure with workers, including across service processes.

    Fixed anonymous lock slots avoid a persistent scan-ID ledger. Collisions
    can delay erasure with an honest retry response, never bypass the lock.
    OS locks are released on process exit, so stale statuses cannot prevent
    retention indefinitely. Do not unlink lock files (that breaks exclusion).
    """
    lock_dir = STATE_DIR / "scan-locks"
    lock_dir.mkdir(exist_ok=True)
    slot = int(hashlib.sha256(scan_id.encode()).hexdigest(), 16) % 64
    with (lock_dir / str(slot)).open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError:
            yield False
            return
        # Release by closing, never explicit LOCK_UN: a report child may
        # still own a duplicate after abrupt supervisor death or exceptions.
        # The lock lasts until the last holder closes, including that child.
        yield handle


def _erase_public_scan(scan_id: str) -> str:
    """Erase one scan, or retain only the information needed to retry files.

    Returns missing/busy/pending/deleted. No arbitrary request-supplied paths
    are accepted. Personal fields and bearer capabilities are revoked before
    file IO; a failed unlink must not be reported as complete erasure.
    """
    with _public_scan_lock(scan_id, blocking=False) as acquired:
        if not acquired:
            return "busy"
        with get_db() as db:
            row = db.execute("SELECT * FROM public_scans WHERE id=?", (scan_id,)).fetchone()
            if not row:
                return "missing"
            now = datetime.now(UTC)
            quota_cutoff = (now - timedelta(hours=24)).isoformat()
            _purge_scan_erasure_limits(db, quota_cutoff)
            # Transfer quota accounting in the same transaction as identifier
            # removal. Retries neither double-count nor extend the old window.
            # Already-erased legacy identities cannot be reconstructed.
            if row["created_at"] > quota_cutoff and (row["email"] or row["ip"]):
                key = os.urandom(32)
                db.execute(
                    "INSERT OR IGNORE INTO public_scan_erasure_limits "
                    "(scan_hash, created_at, mac_key, email_mac, ip_mac) VALUES (?,?,?,?,?)",
                    (hashlib.sha256(scan_id.encode()).hexdigest(), row["created_at"], key,
                     _scan_quota_mac(key, "email", row["email"]) if row["email"] else None,
                     _scan_quota_mac(key, "ip", row["ip"]) if row["ip"] else None),
                )
            db.execute(
                "UPDATE public_scans SET email='', company='', ip=NULL, "
                "status='deletion_pending', deleted_at=?, otp_code=NULL, "
                "otp_expires_at=NULL, otp_attempts=0, download_token=NULL, "
                "job_id=NULL, error=NULL, verified_at=NULL, completed_at=NULL, "
                "report_emailed_at=NULL WHERE id=?",
                (now.isoformat(), scan_id),
            )
        pending = {}
        for field in ("devices_path", "apps_path", "report_path"):
            path = row[field]
            if not path:
                continue
            try:
                target = Path(path)
                resolved = target.resolve()
                if field == "report_path":
                    owned = (resolved.parent == PUBLIC_REPORTS_DIR.resolve()
                             and resolved.name.endswith(f"_{scan_id}.docx"))
                else:
                    root = PUBLIC_DIR.resolve() / scan_id
                    owned = (root.parent == PUBLIC_DIR.resolve()
                             and root in resolved.parents)
                if not owned:
                    raise ValueError("path outside scan ownership")
                target.unlink(missing_ok=True)
            except (OSError, ValueError):
                # Keep the path for retry, without leaking paths/PII to logs.
                pending[field] = path
        with get_db() as db:
            if pending:
                db.execute(
                    "UPDATE public_scans SET devices_path=?, apps_path=?, report_path=? WHERE id=?",
                    (pending.get("devices_path"), pending.get("apps_path"),
                     pending.get("report_path"), scan_id),
                )
                return "pending"
            db.execute("DELETE FROM public_scans WHERE id=?", (scan_id,))
        return "deleted"


def _public_retention_sweep():
    """Erase expired scans and retry incomplete or historical deletions.

    Historical tombstones are reconciled only when this function is run;
    changing source does not run it against any historical database.
    """
    cutoff = (datetime.now(UTC) - timedelta(days=PUBLIC_RETENTION_DAYS)).isoformat()
    with get_db() as db:
        _purge_scan_erasure_limits(db, (datetime.now(UTC) - timedelta(hours=24)).isoformat())
        rows = db.execute(
            "SELECT id FROM public_scans WHERE created_at < ? "
            "OR status IN ('deleted', 'deletion_pending') OR deleted_at IS NOT NULL AND deleted_at != ''",
            (cutoff,),
        ).fetchall()
    purged = sum(_erase_public_scan(r["id"]) == "deleted" for r in rows)
    # The Intune-upload funnel has its own retention sweep over public_uploads.
    _cleanup_old_public_uploads()
    # PAT-1978: the pricing-enquiry ledger holds no submitted field content,
    # only email/ip/timestamps for rate-limiting -- but a rate-limit table
    # with no expiry is still an unbounded PII log by accident. Purge it on
    # the same schedule as everything else here.
    with get_db() as db:
        db.execute("DELETE FROM public_pricing_enquiries WHERE created_at < ?", (cutoff,))
    # PAT-2560: the waitlist's rate-limit ledger goes the same way. The list
    # itself (waitlist_signups) is deliberately NOT swept here: it is kept
    # until the app has launched or the person asks to leave, as the privacy
    # notice says. Do not add it to this function.
    with get_db() as db:
        db.execute("DELETE FROM waitlist_attempts WHERE created_at < ?", (cutoff,))
    if purged:
        print(f"[retention] erased {purged} public scan(s)")


def _public_retention_loop():
    """Daily retention sweep, started from the startup hook."""
    while True:
        try:
            _public_retention_sweep()
        except Exception as e:
            print(f"[retention] error: {e}")
        time.sleep(24 * 3600)


def _send_scan_failure_email(email: str, company: str, reason: str) -> None:
    """Best-effort 'your scan could not be completed' email. Shared by the
    timeout and generic-error paths in _run_public_scan so the backup email
    promised on the scan page (PAT-1218) is sent on every terminal failure,
    not just uncaught exceptions."""
    _send_email(
        email,
        "Patched.im: your CVE scan could not be completed",
        f"<p>Your scan for <b>{_html_escape(company or '')}</b> could not be completed.</p>"
        f"<p>Error: {_html_escape(reason[:300])}</p>"
        f"<p>Reply to this email if you'd like a hand investigating.</p>",
        f"Your scan for {company} could not be completed.\nError: {reason[:300]}\n",
    )


def _run_public_scan(scan_id: str):
    # Hold through generation, email and cleanup. Erasure returns a retry
    # response while this bounded worker owns the lock, rather than claiming
    # success while the subprocess could still create a report or send mail.
    with _public_scan_lock(scan_id) as guard:
        _run_public_scan_locked(scan_id, guard.fileno())


def _run_public_scan_locked(scan_id: str, guard_fd: int):
    """Background worker: runs the upload pipeline, emails the report,
    updates the public_scans row. Cleans up uploads after success/failure."""
    with get_db() as db:
        row = db.execute("SELECT * FROM public_scans WHERE id=?", (scan_id,)).fetchone()
    if not row or row["deleted_at"] or row["status"] in ("deleted", "deletion_pending"):
        print(f"[public_scan] {scan_id} not available")
        return

    company = row["company"]
    email = row["email"]
    devices_path = row["devices_path"]
    apps_path = row["apps_path"]

    try:
        logo = str(BASE / "static" / "patched-report-logo.png")
        ts = datetime.now().strftime("%Y%m%d_%H%M")
        safe = re.sub(r"[^\w\-]", "_", company)
        out = str(PUBLIC_REPORTS_DIR / f"Patched_CVE_{safe}_{ts}_{scan_id}.docx")

        with get_db() as db:
            # Record the output before the subprocess can create it, so a
            # failed partial-report unlink remains discoverable for erasure.
            db.execute("UPDATE public_scans SET status='scanning', report_path=? WHERE id=?",
                       (out, scan_id))

        # PAT-1177: parsing + NVD matching + doc generation is the CPU/IO-heavy
        # unit for this path (scanner.py has no separate "generate only" step
        # the way intune_upload.py does), so the whole call runs in a killable
        # subprocess via run_report_job -- genuinely bounded, unlike the old
        # bare thread with no timeout at all. Every arg is picklable (plain
        # paths/strings); the child never touches the DB or sends email.
        outcome = run_report_job(
            run_scan_from_upload,
            (devices_path, apps_path, NVD_API_KEY, company, logo, out),
            PUBLIC_SCAN_JOB_TIMEOUT_SECONDS,
            out,
            guard_fd=guard_fd,
        )

        if outcome.status == "timeout":
            reason = f"Report generation exceeded the {PUBLIC_SCAN_JOB_TIMEOUT_SECONDS}s limit."
            print(f"[public_scan] {scan_id} hard-killed after "
                  f"{PUBLIC_SCAN_JOB_TIMEOUT_SECONDS}s")
            with get_db() as db:
                db.execute(
                    "UPDATE public_scans SET status='timeout', error=? "
                    "WHERE id=? AND status='scanning'",
                    (reason, scan_id),
                )
            _send_scan_failure_email(email, company, reason)
            return
        if outcome.status == "error":
            raise RuntimeError(outcome.error or "report generation failed")

        with get_db() as db:
            db.execute(
                "UPDATE public_scans SET status='complete', completed_at=?, "
                "report_path=? WHERE id=? AND status='scanning'",
                (datetime.now(UTC).isoformat(), out, scan_id),
            )

        # Email the report
        download_url = f"{PUBLIC_BASE_URL}/public/scan/r/{row['download_token']}"
        delete_url = f"{PUBLIC_BASE_URL}/public/scan/d/{row['delete_token']}"
        subject = f"Your Patched.im CVE assessment for {company}"
        text = (
            f"Hi,\n\nYour CVE assessment for {company} is ready.\n\n"
            f"Download the report (Word .docx, attached and at the link below):\n{download_url}\n\n"
            f"Delete the report and uploaded data now: {delete_url}\n\n"
            f"All data is automatically deleted after {PUBLIC_RETENTION_DAYS} days.\n\n"
            f"- Patched.im\n"
        )
        logo_url = f"{PUBLIC_BASE_URL}/static/patched-report-logo.png"
        html = (
            f"<img src=\"{logo_url}\" width=\"150\" height=\"42\" alt=\"Patched.im\" "
            f"style=\"display:block;width:150px;height:42px;border:0;outline:none;\">"
            f"<p>Hi,</p>"
            f"<p>Your CVE assessment for <b>{_html_escape(company or '')}</b> is ready.</p>"
            f"<p><a href=\"{download_url}\">Download the report (Word .docx)</a>, "
            f"also attached to this email.</p>"
            f"<p style=\"color:#666;font-size:13px;\">"
            f"All uploaded data and the report are automatically deleted after "
            f"{PUBLIC_RETENTION_DAYS} days. "
            f"<a href=\"{delete_url}\">Delete now</a>.</p>"
            f"<p>- Patched.im</p>"
        )
        attachment_name = f"Patched_CVE_{safe}.docx"
        ok = _send_email(email, subject, html, text, out, attachment_name,
                         bcc=SCAN_REPORT_BCC or None)
        if ok:
            with get_db() as db:
                db.execute(
                    "UPDATE public_scans SET report_emailed_at=? WHERE id=?",
                    (datetime.now(UTC).isoformat(), scan_id),
                )
        else:
            print(f"[public_scan] {scan_id} report generated but email send failed")

    except Exception as e:
        print(f"[public_scan] {scan_id} failed: {e}")
        with get_db() as db:
            db.execute(
                "UPDATE public_scans SET status='error', error=? WHERE id=?",
                (str(e)[:500], scan_id),
            )
        # Tell the user it failed
        _send_scan_failure_email(email, company, str(e))

    finally:
        # Uploads (CSV/JSON) are no longer needed once the report is generated.
        # Report stays until retention sweep or delete-now link.
        remaining = []
        for p in (devices_path, apps_path):
            try:
                if p:
                    Path(p).unlink(missing_ok=True)
                remaining.append(None)
            except OSError:
                remaining.append(p)
        with get_db() as db:
            db.execute(
                "UPDATE public_scans SET devices_path=?, apps_path=? WHERE id=?",
                (*remaining, scan_id),
            )
