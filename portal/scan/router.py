"""
router.py — Unauthenticated public CVE scan / Intune upload funnel.

Ported verbatim from the dashboard's public_router (PAT-457). The route paths
are UNCHANGED so existing email links and muscle memory survive the move; only
the public hostname changes (scan.patched.im instead of dashboard.patched.im).

Routes:
    GET  /public/intune-instructions
    GET  /public/intune-upload
    POST /public/intune-upload
    GET  /public/scan
    GET  /public/privacy
    POST /public/scan
    GET  /public/scan/verify/{scan_id}
    POST /public/scan/verify/{scan_id}
    GET  /public/scan/done/{scan_id}
    GET  /public/scan/status/{scan_id}
    GET  /public/scan/r/{token}
    GET  /public/scan/d/{token}
    POST /public/scan/d/{token}
    POST /public/pricing-enquiry
    GET  /public/waitlist
    POST /public/waitlist

None of these routes are authenticated — this whole service is public by
design. Security is: Turnstile + per-email/per-IP rate limits + OTP email
verification + file size caps.
"""

import html
import os
import re
import secrets
import threading
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from intune_upload import (
    MAX_UPLOAD_BYTES,
    detect_csv_type,
    generate_apps_cve_report,
    generate_devices_report,
    parse_apps_rows,
    parse_csv_safe,
    parse_devices_rows,
)
from scanner import nvd_available
from shared import (
    _EMAIL_RE,
    BASE,
    EMAIL_RE,
    NVD_API_KEY,
    OTP_EXPIRY_MIN,
    OTP_MAX_ATTEMPTS,
    PRICING_ENQUIRY_TO,
    PUBLIC_BASE_URL,
    PUBLIC_DIR,
    PUBLIC_MAX_UPLOAD_BYTES,
    PUBLIC_REPORTS_DIR,
    PUBLIC_RETENTION_DAYS,
    SCAN_REPORT_BCC,
    SENDGRID_API_KEY,
    TURNSTILE_SITE_KEY,
    WAITLIST_NOTIFY_TO,
    _check_pricing_rate_limit,
    _check_public_rate_limit,
    _check_rate_limits,
    _check_waitlist_rate_limit,
    _client_ip,
    _erase_public_scan,
    _get_client_ip,
    _graph_send_mail,
    _mask_email,
    _run_public_scan,
    _safe_filename,
    _send_email,
    _verify_turnstile,
    get_db,
    release_scan_slot,
    run_report_job,
    templates,
    try_acquire_scan_slot,
)

router = APIRouter(tags=["public"])

# Human-facing message when the NVD dataset has not been seeded on the box.
_NVD_UNAVAILABLE_MSG = (
    "Scanning is temporarily unavailable while we refresh our vulnerability "
    "dataset. Please try again shortly."
)

# Hard wall-clock bound for one Intune-upload job's report-generation step.
# Report generation is also capped per app (CVE_REPORT_MAX_PER_APP in
# intune_upload.py) so a normal job finishes well under this; this bound is
# a fail-safe so a job that still hangs or grinds lands in status='timeout'
# with a reason instead of sitting in 'processing' forever with no report,
# no email, and no error (PAT-1173).
#
# PAT-1177: generation now runs in a killable multiprocessing.Process (see
# shared.run_report_job) instead of a plain thread. Python cannot kill a
# running thread, so the original PAT-1173 model could only bound how long
# the request-handling thread WAITED — a timed-out job's worker kept running
# forever, invisible, and needed a guarded completion UPDATE to stop it
# mailing the user or leaving an unrecorded report once superseded. The
# subprocess is genuinely terminated (SIGTERM, then SIGKILL) once this bound
# elapses, so that race is now structurally impossible; the guarded
# `WHERE status='processing'` claim below is kept anyway as defence in depth
# and because it costs nothing.
#
# Each job still gets its own dedicated background thread (never a shared
# pool) to run this synchronously without blocking the request handler —
# with generation itself now hard-bounded, that thread can no longer hang
# indefinitely either.
UPLOAD_JOB_TIMEOUT_SECONDS = 300


def _discard_orphaned_report(path: str) -> None:
    """Best-effort delete of a report a superseded upload job already wrote
    to disk. Retention (scan/shared.py _cleanup_old_public_uploads) is
    DB-driven — it only ever deletes files it can find via a row's
    report_path — so a report that never gets recorded because its job was
    superseded by a timeout would otherwise sit on disk past the 30-day
    retention window forever. These reports contain a customer's CVE or
    device data, so remove the file here instead of waiting on retention."""
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except OSError as exc:
        print(f"[upload] could not remove superseded report {path}: {exc}")


# ══════════════════════════════════════════════════════════════
# INTUNE UPLOAD FUNNEL (PAT-233)
# These routes are NOT behind the app-level Bearer middleware.
# Cloudflare Access does NOT protect them (public funnel).
# Security is: Turnstile + per-email/per-IP rate limits + 10 MB cap + CSV sniff.
# ══════════════════════════════════════════════════════════════

@router.get("/public/intune-instructions", response_class=HTMLResponse)
async def public_instructions(request: Request):
    return templates.TemplateResponse(request=request, name="public_instructions.html", context={})


@router.get("/public/intune-upload", response_class=HTMLResponse)
async def public_upload_get(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="public_upload.html",
        context={"turnstile_site_key": TURNSTILE_SITE_KEY, "retention_days": PUBLIC_RETENTION_DAYS},
    )


@router.post("/public/intune-upload", response_class=HTMLResponse)
async def public_upload_post(request: Request):
    client_ip = _get_client_ip(request)

    def _err(msg: str, status: int = 400):
        return templates.TemplateResponse(
            request=request,
            name="public_upload.html",
            context={"turnstile_site_key": TURNSTILE_SITE_KEY, "error": msg, "retention_days": PUBLIC_RETENTION_DAYS},
            status_code=status,
        )

    # ── Parse multipart form ──
    form = await request.form()
    email_raw = str(form.get("email", "")).strip()
    turnstile_token = str(form.get("cf-turnstile-response", ""))
    file_field = form.get("file")

    # ── Validate email ──
    if not email_raw or not _EMAIL_RE.match(email_raw) or len(email_raw) > 254:
        return _err("Please enter a valid email address.")

    # ── Validate file field ──
    if file_field is None or not hasattr(file_field, "read"):
        return _err("Please choose a CSV file to upload.")

    # ── Content-type hint check (not authoritative — we also sniff) ──
    ct = getattr(file_field, "content_type", "") or ""
    if ct and not any(k in ct for k in ("csv", "text", "octet-stream")):
        return _err("Please upload a CSV file (.csv).")

    # ── Read with hard size cap ──
    content = await file_field.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        return _err("File too large. Maximum upload size is 10 MB.")

    # ── Verify Turnstile ──
    if not _verify_turnstile(turnstile_token, client_ip):
        return _err("Bot-protection check failed. Please try again.")

    # ── Rate limits ──
    with get_db() as db:
        allowed, reason = _check_public_rate_limit(email_raw, client_ip, db)
    if not allowed:
        return _err(reason, status=429)

    # ── Parse CSV (synchronous — needed for type detection) ──
    try:
        headers, rows = parse_csv_safe(content)
    except ValueError as exc:
        return _err(str(exc))

    # ── Type detection ──
    csv_type = detect_csv_type(headers)
    if csv_type is None:
        return _err(
            "We couldn't identify this CSV. We support two exports: "
            "the Intune Devices export and the Intune Discovered Apps export. "
            "See the export instructions for help.",
        )

    # PAT-457: the Discovered Apps report needs the NVD dataset; the Devices
    # report is a static patch-currency check and does not. Refuse the apps
    # path cleanly if the dataset is not seeded on the box.
    if csv_type != "devices" and not nvd_available():
        return _err(_NVD_UNAVAILABLE_MSG, status=503)

    # ── Bounded concurrency (PAT-1177, fail closed) ──
    # Acquired BEFORE the DB record is created: a saturated cap must refuse
    # the request outright, with nothing recorded as processing, rather than
    # accept it and queue it silently.
    if not try_acquire_scan_slot():
        return _err(
            "We're processing a lot of scans right now, please try again in a few minutes.",
            status=503,
        )

    # ── Create DB record ──
    job_id = str(uuid.uuid4())[:12]
    now_iso = datetime.now(UTC).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO public_uploads (id, email, ip, upload_type, status, created_at) VALUES (?,?,?,?,?,?)",
            (job_id, email_raw, client_ip, csv_type, "processing", now_iso),
        )

    # ── Start background processing ──
    # _do_upload_job owns its own terminal DB writes (done / error) and is
    # the only thing that ever sends the delivery email.
    def _do_upload_job(job_id=job_id, email=email_raw, csv_type=csv_type, rows=rows):
        try:
            _run_upload_job(job_id, email, csv_type, rows)
        except Exception as exc:
            print(f"[upload] ❌ job {job_id} failed: {exc}")
            with get_db() as db:
                db.execute(
                    "UPDATE public_uploads SET status='error', error=? "
                    "WHERE id=? AND status='processing'",
                    (str(exc)[:500], job_id),
                )

    def _run_upload_job(job_id, email, csv_type, rows):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        logo = str(BASE / "static" / "patched-report-logo.png")
        logo_url = f"{PUBLIC_BASE_URL}/static/patched-report-logo.png"
        logo_header = (
            f"<img src=\"{logo_url}\" width=\"150\" height=\"42\" alt=\"Patched.im\" "
            f"style=\"display:block;width:150px;height:42px;border:0;outline:none;\">"
        )

        # PAT-1177: report generation (the CPU-heavy step) runs in a killable
        # subprocess via shared.run_report_job instead of inline on this
        # thread — see that function's docstring and the UPLOAD_JOB_TIMEOUT_SECONDS
        # comment above for why. `generate_devices_report` / `generate_apps_cve_report`
        # are module-level functions in intune_upload.py and every arg below
        # is picklable (parsed rows/apps lists, plain path strings, the NVD
        # key), so this works identically under fork and spawn.
        if csv_type == "devices":
            devices = parse_devices_rows(rows)
            out = str(PUBLIC_REPORTS_DIR / f"Patched_Intune_Devices_{ts}_{job_id}.docx")
            outcome = run_report_job(
                generate_devices_report, (devices, out, logo), UPLOAD_JOB_TIMEOUT_SECONDS, out,
            )
        else:
            apps = parse_apps_rows(rows)
            out = str(PUBLIC_REPORTS_DIR / f"Patched_Intune_Apps_CVE_{ts}_{job_id}.docx")
            outcome = run_report_job(
                generate_apps_cve_report, (apps, NVD_API_KEY, out, logo),
                UPLOAD_JOB_TIMEOUT_SECONDS, out,
            )

        if outcome.status == "timeout":
            reason = f"Report generation exceeded the {UPLOAD_JOB_TIMEOUT_SECONDS}s limit."
            print(f"[upload] ⏱️ job {job_id} hard-killed after {UPLOAD_JOB_TIMEOUT_SECONDS}s")
            with get_db() as db:
                db.execute(
                    "UPDATE public_uploads SET status='timeout', error=? "
                    "WHERE id=? AND status='processing'",
                    (reason, job_id),
                )
            return
        if outcome.status == "error":
            print(f"[upload] ❌ job {job_id} report generation failed: {outcome.error}")
            with get_db() as db:
                db.execute(
                    "UPDATE public_uploads SET status='error', error=? "
                    "WHERE id=? AND status='processing'",
                    ((outcome.error or "report generation failed")[:500], job_id),
                )
            return

        stats = outcome.stats
        if csv_type == "devices":
            subject = "Your Intune Device Estate Report | Patched.im"
            text = (
                f"Hi,\n\nYour Intune device estate report is attached. "
                f"It covers {stats['total']} device(s).\n\n"
                f"Your uploaded data and this report will be deleted after 30 days.\n\n"
                f"- Patched.im\n"
            )
            body = (
                logo_header +
                f"<p>Hi,</p>"
                f"<p>Your Intune device estate report is attached. "
                f"It covers <strong>{stats['total']}</strong> device(s).</p>"
                f"<ul>"
                f"<li>Compliant: {stats['compliant']}</li>"
                f"<li>Non-compliant: {stats['non_compliant']}</li>"
                f"<li>Out-of-date OS: {stats['out_of_date']}</li>"
                f"<li>Stale check-in (&gt;14 d): {stats['stale']}</li>"
                f"</ul>"
                f"<p>OS currency is assessed against a static reference and may not reflect the very latest releases.</p>"
                f"<p>Your uploaded data and this report will be deleted after 30 days.</p>"
                f"<p>- Patched.im</p>"
            )
        else:
            subject = "Your Intune Application CVE Report | Patched.im"
            text = (
                f"Hi,\n\nYour application CVE report is attached. "
                f"We scanned {stats['total_apps']} application(s).\n\n"
                f"Your uploaded data and this report will be deleted after 30 days.\n\n"
                f"- Patched.im\n"
            )
            body = (
                logo_header +
                f"<p>Hi,</p>"
                f"<p>Your application CVE report is attached. "
                f"We scanned <strong>{stats['total_apps']}</strong> application(s).</p>"
                f"<ul>"
                f"<li>Apps with known CVEs: {stats['apps_with_cves']}</li>"
                f"<li>Unique CVEs found: {stats['total_cves']}</li>"
                f"</ul>"
                f"<p>Your uploaded data and this report will be deleted after 30 days.</p>"
                f"<p>- Patched.im</p>"
            )

        # Claim completion BEFORE sending email or touching anything else
        # observable, guarded by status='processing'. This guard predates
        # PAT-1177's hard-kill subprocess (which makes the race it guards
        # against structurally impossible — a killed child is verified dead
        # before run_report_job returns) but is kept anyway as defence in
        # depth: it closes two PAT-1173 gaps in one guard: a superseded job
        # can no longer (a) email the user a report whose status already
        # says 'timeout', or (b) leave its .docx unrecorded and therefore
        # invisible to the retention sweep (scan/shared.py
        # _cleanup_old_public_uploads only deletes files it can find via
        # report_path), which would otherwise let a confidential report sit
        # on disk past the 30-day retention window forever.
        with get_db() as db:
            cur = db.execute(
                "UPDATE public_uploads SET status='done', report_path=? "
                "WHERE id=? AND status='processing'",
                (out, job_id),
            )
            claimed = cur.rowcount == 1

        if not claimed:
            print(
                f"[upload] job {job_id} finished after being superseded "
                f"(already timed out or errored). Discarding report, no email sent."
            )
            _discard_orphaned_report(out)
            return

        # Ported-bug fix (was `_send_email(email, subject, body, out)` in the
        # dashboard): the report path landed in the `text` parameter, so the
        # "report is attached" email shipped with NO attachment — and this
        # funnel has no download route, so the user never got their report.
        # Pass a plain-text body and the attachment path explicitly.
        sent = _send_email(email, subject, body, text, out,
                          bcc=SCAN_REPORT_BCC or None)
        if not sent:
            # _send_email never raises on delivery failure, it returns False —
            # so this branch is the only place that finds out. Leaving the row
            # 'done' here would be the same silent failure PAT-1173 was about:
            # the user gets no report (this funnel has no download route) and
            # nothing else records that delivery failed. Flip the row we just
            # claimed to a terminal error state and discard the undelivered
            # report rather than leaving it on disk unreferenced.
            print(f"[upload] ❌ job {job_id} report generated but email delivery failed")
            with get_db() as db:
                db.execute(
                    "UPDATE public_uploads SET status='error', error='email delivery failed', "
                    "report_path=NULL WHERE id=? AND status='done'",
                    (job_id,),
                )
            _discard_orphaned_report(out)
            return

        print(f"[upload] ✅ {csv_type} report sent to {email} (job {job_id})")

    def _supervise_upload_job(job_id=job_id):
        """Run _do_upload_job on its own dedicated background thread (never a
        shared pool, so one job can never head-of-line-block another) and
        always release the concurrency slot acquired above, whatever the
        outcome — normal completion, the run_report_job hard-kill timeout
        path, or an unexpected exception."""
        try:
            _do_upload_job()
        finally:
            release_scan_slot()

    threading.Thread(target=_supervise_upload_job, daemon=True).start()

    # ── Return confirmation page immediately (report goes to email) ──
    return templates.TemplateResponse(
        request=request,
        name="public_upload.html",
        context={
            "turnstile_site_key": TURNSTILE_SITE_KEY,
            "uploaded": True,
            "submitted_email": email_raw,
            "retention_days": PUBLIC_RETENTION_DAYS,
        },
    )


# ══════════════════════════════════════════════════════════════
# PUBLIC CVE-SCAN FUNNEL (patched.im/cve-scan)
# ══════════════════════════════════════════════════════════════

@router.get("/public/scan", response_class=HTMLResponse)
async def public_scan_form(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="public_scan.html",
        context={"turnstile_site_key": TURNSTILE_SITE_KEY,
                 "retention_days": PUBLIC_RETENTION_DAYS},
    )


@router.get("/public/privacy", response_class=HTMLResponse)
async def public_privacy(request: Request):
    return templates.TemplateResponse(request=request, name="public_privacy.html")


@router.post("/public/scan")
async def public_scan_submit(
    request: Request,
    company: str = Form(...),
    email: str = Form(...),
    authorised: str = Form(""),
    devices_file: UploadFile = File(...),
    apps_file: UploadFile | None = File(None),
):
    company = (company or "").strip()
    email = (email or "").strip().lower()
    ip = _client_ip(request)

    # PAT-457: refuse cleanly when the NVD dataset is not seeded, rather than
    # accepting the upload and failing deep in the background worker (or, worse,
    # attempting a blocking download mid-request on a box with no internet).
    if not nvd_available():
        return HTMLResponse(_NVD_UNAVAILABLE_MSG, 503)

    if not company:
        return HTMLResponse("Company name is required.", 400)
    if not EMAIL_RE.match(email):
        return HTMLResponse("Please provide a valid email address.", 400)
    if authorised != "yes":
        return HTMLResponse(
            "You must confirm you're authorised to share this device inventory.", 400,
        )

    # Turnstile (Cloudflare captcha)
    form = await request.form()
    turnstile_token = (form.get("cf-turnstile-response") or "").strip()
    if not _verify_turnstile(turnstile_token, ip):
        return HTMLResponse("Captcha verification failed. Please try again.", 400)

    # Rate limits
    err = _check_rate_limits(email, ip)
    if err:
        return HTMLResponse(err, 429)

    # Read upload(s) with size cap
    dev_bytes = await devices_file.read(PUBLIC_MAX_UPLOAD_BYTES + 1)
    if len(dev_bytes) > PUBLIC_MAX_UPLOAD_BYTES:
        return HTMLResponse(f"Devices file exceeds {PUBLIC_MAX_UPLOAD_BYTES // (1024*1024)} MB.", 413)

    apps_bytes = None
    apps_filename = None
    if apps_file is not None and apps_file.filename:
        apps_bytes = await apps_file.read(PUBLIC_MAX_UPLOAD_BYTES + 1)
        if len(apps_bytes) > PUBLIC_MAX_UPLOAD_BYTES:
            return HTMLResponse(f"Apps file exceeds {PUBLIC_MAX_UPLOAD_BYTES // (1024*1024)} MB.", 413)
        apps_filename = apps_file.filename

    scan_id = uuid.uuid4().hex
    scan_dir = PUBLIC_DIR / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    # PAT-456 / C1: NEVER build the on-disk path from the client filename —
    # UploadFile.filename is attacker-controlled and unsanitised, so a value
    # like "../../main.py" would escape scan_dir on write (arbitrary file
    # write as the dashboard user, pre-OTP). Sanitise to a basename, then
    # defence-in-depth: resolve and assert the path stays inside scan_dir.
    def _resolve_within(dirp, filename, default):
        p = dirp / _safe_filename(filename, default)
        try:
            p.resolve().relative_to(dirp.resolve())
        except ValueError as exc:
            raise ValueError("resolved upload path escapes scan directory") from exc
        return p

    try:
        dev_path = _resolve_within(scan_dir, devices_file.filename, "devices.csv")
        apps_path = None
        if apps_bytes is not None:
            apps_path = _resolve_within(scan_dir, apps_filename, "apps.json")
    except ValueError:
        return HTMLResponse("Invalid upload filename.", 400)

    dev_path.write_bytes(dev_bytes)
    if apps_bytes is not None:
        apps_path.write_bytes(apps_bytes)

    # OTP — six digits, 15 min validity
    otp = f"{secrets.randbelow(1_000_000):06d}"
    otp_expires = (datetime.now(UTC) + timedelta(minutes=OTP_EXPIRY_MIN)).isoformat()

    download_token = secrets.token_urlsafe(32)
    delete_token = secrets.token_urlsafe(32)
    now = datetime.now(UTC).isoformat()

    with get_db() as db:
        db.execute("""
            INSERT INTO public_scans
            (id, email, company, ip, status, otp_code, otp_expires_at,
             devices_path, apps_path, download_token, delete_token, created_at)
            VALUES (?, ?, ?, ?, 'pending_verify', ?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, email, company, ip, otp, otp_expires,
              str(dev_path), str(apps_path) if apps_path else None,
              download_token, delete_token, now))

    # Send OTP
    subject = "Your Patched.im verification code"
    text = (f"Your Patched.im verification code is: {otp}\n\n"
            f"It expires in {OTP_EXPIRY_MIN} minutes.\n\n"
            f"If you didn't request a CVE scan, ignore this email.\n")
    html = (f"<p>Your Patched.im verification code is:</p>"
            f"<p style=\"font-size:24px;font-weight:bold;letter-spacing:2px;\">{otp}</p>"
            f"<p>It expires in {OTP_EXPIRY_MIN} minutes.</p>"
            f"<p style=\"color:#666;font-size:13px;\">If you didn't request a CVE scan, ignore this email.</p>")
    sent = _send_email(email, subject, html, text)
    if not sent and SENDGRID_API_KEY:
        # Real send failure (key present, send failed). With no key, _send_email
        # logged the OTP to stdout — let dev/local proceed.
        return HTMLResponse("Could not send verification email. Please try again later.", 502)

    # Redirect to OTP form
    return RedirectResponse(url=f"/public/scan/verify/{scan_id}", status_code=303)


@router.get("/public/scan/verify/{scan_id}", response_class=HTMLResponse)
async def public_scan_verify_form(request: Request, scan_id: str):
    with get_db() as db:
        row = db.execute("SELECT email, status FROM public_scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return HTMLResponse("Scan request not found.", 404)
    if row["status"] != "pending_verify":
        return HTMLResponse("This verification link is no longer valid.", 410)
    return templates.TemplateResponse(
        request=request,
        name="public_verify.html",
        context={"scan_id": scan_id,
                 "email_masked": _mask_email(row["email"])},
    )


@router.post("/public/scan/verify/{scan_id}")
async def public_scan_verify_submit(scan_id: str, otp: str = Form(...)):
    otp = (otp or "").strip()
    now = datetime.now(UTC)

    with get_db() as db:
        row = db.execute(
            "SELECT otp_code, otp_expires_at, status FROM public_scans WHERE id=?",
            (scan_id,),
        ).fetchone()
        if not row:
            return HTMLResponse("Scan request not found.", 404)
        if row["status"] != "pending_verify":
            return HTMLResponse("This verification link is no longer valid.", 410)
        try:
            expires = datetime.fromisoformat(row["otp_expires_at"])
        except Exception:
            expires = now - timedelta(seconds=1)
        if now > expires:
            return HTMLResponse("Verification code expired. Start a new scan request.", 410)

        # Atomically reserve one attempt slot before testing the guess. The
        # check-then-increment used to be two separate statements (a SELECT
        # of otp_attempts, then a later UPDATE), which raced across the
        # independent connections get_db() hands out per request: N
        # concurrent submissions could all read otp_attempts < OTP_MAX_ATTEMPTS
        # before any of their increments committed, so all N got to test a
        # guess. Folding the check and the increment into one UPDATE ...
        # RETURNING makes the reservation atomic at the SQLite engine level
        # (a single statement is one transaction) - no row returned means the
        # cap was already reached by this request or a concurrent one, and no
        # guess is compared.
        reserved = db.execute(
            "UPDATE public_scans SET otp_attempts = otp_attempts + 1 "
            "WHERE id = ? AND otp_attempts < ? "
            "RETURNING otp_attempts",
            (scan_id, OTP_MAX_ATTEMPTS),
        ).fetchone()
        if reserved is None:
            db.execute(
                "UPDATE public_scans SET status='error', error='OTP attempts exceeded' WHERE id=?",
                (scan_id,),
            )
            return HTMLResponse("Too many incorrect codes. Start a new scan request.", 429)

        # constant-time compare
        if not secrets.compare_digest(otp, row["otp_code"] or ""):
            return HTMLResponse("Incorrect code. Try again.", 400)

        # ── Bounded concurrency (PAT-1177, fail closed) ──
        # The code is correct, but if the scan job cannot be started right
        # now, don't commit to 'verified' (which would consume the OTP and
        # record nothing that ever actually runs). Leave the row
        # 'pending_verify' with the OTP still live so the user can retry the
        # same code once a slot frees up, and refuse the request outright.
        if not try_acquire_scan_slot():
            return HTMLResponse(
                "We're processing a lot of scans right now, please try again in a few minutes.",
                503,
            )

        db.execute(
            "UPDATE public_scans SET status='verified', verified_at=?, otp_code=NULL WHERE id=?",
            (now.isoformat(), scan_id),
        )

    def _supervise_public_scan(scan_id=scan_id):
        """Run _run_public_scan and always release the concurrency slot
        acquired above, whatever the outcome — normal completion, the
        run_report_job hard-kill timeout path, or an unexpected exception."""
        try:
            _run_public_scan(scan_id)
        finally:
            release_scan_slot()

    threading.Thread(target=_supervise_public_scan, daemon=True).start()
    return RedirectResponse(url=f"/public/scan/done/{scan_id}", status_code=303)


@router.get("/public/scan/done/{scan_id}", response_class=HTMLResponse)
async def public_scan_done(request: Request, scan_id: str):
    with get_db() as db:
        row = db.execute(
            "SELECT email, company, status FROM public_scans WHERE id=?", (scan_id,),
        ).fetchone()
    if not row:
        return HTMLResponse("Scan request not found.", 404)
    return templates.TemplateResponse(
        request=request,
        name="public_done.html",
        context={"email_masked": _mask_email(row["email"]),
                 "company": row["company"],
                 "scan_id": scan_id},
    )


@router.get("/public/scan/status/{scan_id}")
async def public_scan_status(scan_id: str):
    with get_db() as db:
        row = db.execute(
            "SELECT status, download_token FROM public_scans WHERE id=?", (scan_id,),
        ).fetchone()
    if not row:
        return JSONResponse({"status": "not_found"}, status_code=404)
    payload: dict = {"status": row["status"]}
    if row["status"] == "complete" and row["download_token"]:
        payload["download_url"] = f"/public/scan/r/{row['download_token']}"
    return JSONResponse(payload)


@router.get("/public/scan/r/{token}")
async def public_scan_download(token: str):
    with get_db() as db:
        row = db.execute(
            "SELECT report_path, company, deleted_at FROM public_scans WHERE download_token=?",
            (token,),
        ).fetchone()
    if not row or row["deleted_at"]:
        return HTMLResponse("Report not found or has been deleted.", 404)
    if not row["report_path"] or not os.path.exists(row["report_path"]):
        return HTMLResponse("Report not ready yet. Check back shortly.", 404)
    safe = re.sub(r"[^\w\-]", "_", row["company"] or "Report")
    return FileResponse(
        row["report_path"],
        filename=f"Patched_CVE_{safe}.docx",
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )


@router.get("/public/scan/d/{token}", response_class=HTMLResponse)
async def public_scan_delete_form(request: Request, token: str):
    with get_db() as db:
        row = db.execute(
            "SELECT id, company, deleted_at, status FROM public_scans WHERE delete_token=?", (token,),
        ).fetchone()
    if not row:
        return HTMLResponse("Not found.", 404)
    if row["deleted_at"] or row["status"] in ("deleted", "deletion_pending"):
        return HTMLResponse(
            f'<p>File deletion is incomplete. Please retry.</p>'
            f'<form method="post" action="/public/scan/d/{html.escape(token, quote=True)}">'
            '<button type="submit">Retry deletion</button></form>', 200,
        )
    return HTMLResponse(
        f"<html><body style=\"font-family:sans-serif;max-width:480px;margin:60px auto;\">"
        f"<h2>Delete report for {html.escape(row['company'] or '')}?</h2>"
        f"<p>This permanently deletes the report and any remaining data.</p>"
        f"<form method=\"post\" action=\"/public/scan/d/{token}\">"
        f"<button type=\"submit\" style=\"background:#C0392B;color:#fff;padding:10px 18px;"
        f"border:0;border-radius:6px;font-size:14px;cursor:pointer;\">Delete now</button>"
        f"</form></body></html>"
    )


@router.post("/public/scan/d/{token}")
async def public_scan_delete_exec(token: str):
    with get_db() as db:
        row = db.execute(
            "SELECT id, devices_path, apps_path, report_path FROM public_scans WHERE delete_token=?",
            (token,),
        ).fetchone()
        if not row:
            return HTMLResponse("Not found.", 404)
    outcome = _erase_public_scan(row["id"])
    if outcome == "missing":
        return HTMLResponse("Not found.", 404)
    if outcome == "busy":
        return HTMLResponse("A scan is still running. Please retry deletion shortly.", 409)
    if outcome == "pending":
        return HTMLResponse(
            "File deletion is incomplete. Report access has been revoked. Please retry shortly.", 503,
        )
    return HTMLResponse(
        "<html><body style=\"font-family:sans-serif;max-width:480px;margin:60px auto;\">"
        "<h2>Deleted.</h2><p>The report and any remaining data have been removed.</p>"
        "</body></html>"
    )


# ══════════════════════════════════════════════════════════════
# PRICING / DESIGN-PARTNER ENQUIRY (PAT-1978)
#
# Receiving end of the website's (patched.im/pricing) enquiry form. That
# form is a plain HTML `<form method="post" action="https://scan.patched.im
# /public/pricing-enquiry">` -- a full-page navigation, not a fetch() call
# -- so this route needs no CORS configuration even though the website is a
# different origin. It fails visibly by construction: the browser navigates
# to whatever this route returns, success or error, with no JS in the
# middle that could swallow a network failure silently.
#
# Security is a honeypot field plus per-email/per-IP rate limiting, not
# Turnstile: this form gets a handful of submissions, never a file upload
# or a paid job, so the cost of a spam hit is low and rate-limiting has
# almost no legitimate-user collision risk at that volume. Turnstile would
# also mean wiring a Cloudflare widget + site key into the website repo
# for a form that does not need the heavier defence the scan/upload
# funnels carry (those process uploaded files and trigger real background
# jobs). If spam becomes a real problem here, add Turnstile the same way
# public_scan_form does -- not a redesign, just wiring the existing
# _verify_turnstile helper into this route too.
# ══════════════════════════════════════════════════════════════

# Hidden field name the website form must add. A genuine visitor never
# fills it in; a bot form-filler often does. A non-empty value here is
# treated as spam and gets an apparent-success response with nothing
# delivered and nothing counted against the rate limit, so the filler gets
# no signal that it was filtered. The website side must hide it with CSS
# (off-screen positioning -- e.g. `position:absolute;left:-9999px`), NOT
# `type="hidden"`, since some scrapers skip genuinely hidden inputs but
# still fill in visible-but-off-screen ones.
PRICING_HONEYPOT_FIELD = "website"


@router.post("/public/pricing-enquiry", response_class=HTMLResponse)
async def public_pricing_enquiry(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    organisation: str = Form(...),
    devices: str = Form(""),
    mix: str = Form(""),
    tool: str = Form(""),
    partner: str = Form(""),
    # honeypot -- Python identifier differs from the wire field name so the
    # constant is the single source of truth for what the form must call it.
    honeypot: str = Form("", alias=PRICING_HONEYPOT_FIELD),
):
    ip = _client_ip(request)
    name = (name or "").strip()
    email = (email or "").strip().lower()
    organisation = (organisation or "").strip()
    devices = (devices or "").strip()
    mix = (mix or "").strip()
    tool = (tool or "").strip()
    is_partner = bool((partner or "").strip())

    def _page(success: bool, reason: str = "", status_code: int = 200):
        return templates.TemplateResponse(
            request=request,
            name="public_pricing_enquiry.html",
            context={"success": success, "reason": reason, "name": name},
            status_code=status_code,
        )

    # Honeypot: accept silently, deliver nothing, don't touch the rate
    # limiter or the DB at all -- a filtered submission must look identical
    # to a real one to whatever filled the field in.
    if honeypot.strip():
        return _page(success=True)

    if not name or not organisation:
        return _page(success=False, status_code=400,
                     reason="Name and organisation are required.")
    if not email or not EMAIL_RE.match(email):
        return _page(success=False, status_code=400,
                     reason="Please provide a valid work email address.")

    err = _check_pricing_rate_limit(email, ip)
    if err:
        return _page(success=False, status_code=429, reason=err)

    enquiry_id = uuid.uuid4().hex
    now = datetime.now(UTC).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO public_pricing_enquiries (id, email, ip, created_at) VALUES (?,?,?,?)",
            (enquiry_id, email, ip, now),
        )

    subject = (f"Design partner enquiry: {organisation}" if is_partner
               else f"Pricing enquiry: {organisation}")
    text = (
        f"Name: {name}\n"
        f"Email: {email}\n"
        f"Organisation: {organisation}\n"
        f"Devices (rough): {devices or '-'}\n"
        f"Windows/Mac mix: {mix or '-'}\n"
        f"Current management tool: {tool or '-'}\n"
        f"Design partner interest: {'yes' if is_partner else 'no'}\n"
        f"Submitted from IP: {ip}\n"
    )
    body_html = (
        f"<p><b>Name:</b> {html.escape(name)}<br>"
        f"<b>Email:</b> {html.escape(email)}<br>"
        f"<b>Organisation:</b> {html.escape(organisation)}<br>"
        f"<b>Devices (rough):</b> {html.escape(devices or '-')}<br>"
        f"<b>Windows/Mac mix:</b> {html.escape(mix or '-')}<br>"
        f"<b>Current management tool:</b> {html.escape(tool or '-')}<br>"
        f"<b>Design partner interest:</b> {'yes' if is_partner else 'no'}<br>"
        f"<b>Submitted from IP:</b> {html.escape(ip)}</p>"
    )

    sent = _graph_send_mail(PRICING_ENQUIRY_TO, subject, body_html, text)
    if not sent:
        # _graph_send_mail never raises on delivery failure, it returns
        # False -- this is the only place that finds out. The whole point
        # of this endpoint is that a lead never silently vanishes, so say
        # so plainly rather than returning a generic thanks page.
        return _page(
            success=False, status_code=502,
            reason=("We could not send that just now. Please try again, or "
                     "email hello@patched.im directly."),
        )

    with get_db() as db:
        db.execute(
            "UPDATE public_pricing_enquiries SET delivered_at=? WHERE id=?",
            (datetime.now(UTC).isoformat(), enquiry_id),
        )

    return _page(success=True)


# ══════════════════════════════════════════════════════════════
# MAC APP WAITLIST (PAT-2560)
#
# Receiving end of the patched.im homepage form: a plain cross-origin HTML
# form post, a full-page navigation, exactly like the enquiry form above, so
# it needs no CORS and cannot fail silently in a script.
#
# Unlike the enquiry form, this one keeps what it is sent. The waitlist count
# decides whether the app is built at all (300 sign ups in two weeks), so the
# list has to be a list, not a mailbox:
#
#   * waitlist_signups holds one row per email address. A second submission
#     from the same address stores nothing new and gets the identical page,
#     so the count is people and the response never says who is on it.
#   * waitlist_attempts is the rate-limit ledger (email, ip, time), purged
#     after PUBLIC_RETENTION_DAYS like the other ledgers. The list itself is
#     never purged by the sweep and holds no IP address.
#   * Each new sign up is announced to WAITLIST_NOTIFY_TO with the running
#     total in the subject. The row is the record; the email is a courtesy.
#     If the email cannot be sent the visitor is still on the list and is told
#     so, the row keeps notified_at NULL, and /healthz counts it.
#
# Security is the same honeypot plus per-email and per-IP limits as the
# enquiry form, for the same reasons given above it.
# ══════════════════════════════════════════════════════════════

# Same wire name as the enquiry form's honeypot, so the homepage form needs
# no change to its off-screen field when its action moves to this route.
WAITLIST_HONEYPOT_FIELD = "website"

# Where a GET (a refresh after the form post, a pasted link) is sent.
WAITLIST_FORM_URL = "https://patched.im/#waitlist"

# Stored fields are bounded. A name or address beyond these is refused with a
# reason; the two optional answers are cut to length, because losing the tail
# of "what do you use now" is better than losing the sign up.
WAITLIST_NAME_MAX = 100
WAITLIST_EMAIL_MAX = 254
WAITLIST_ANSWER_MAX = 200

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")


def _one_line(value: str) -> str:
    """Collapse control characters (newlines included) to single spaces."""
    return _CONTROL_CHARS.sub(" ", value or "").strip()


@router.get("/public/waitlist")
def public_waitlist_form_redirect():
    return RedirectResponse(WAITLIST_FORM_URL, status_code=303)


@router.post("/public/waitlist", response_class=HTMLResponse)
async def public_waitlist(
    request: Request,
    name: str = Form(""),
    email: str = Form(""),
    devices: str = Form(""),
    tool: str = Form(""),
    honeypot: str = Form("", alias=WAITLIST_HONEYPOT_FIELD),
):
    ip = _client_ip(request)
    name = _one_line(name)
    email = _one_line(email).lower()
    devices = _one_line(devices)[:WAITLIST_ANSWER_MAX]
    tool = _one_line(tool)[:WAITLIST_ANSWER_MAX]

    def _page(success: bool, reason: str = "", status_code: int = 200):
        return templates.TemplateResponse(
            request=request,
            name="public_waitlist.html",
            context={"success": success, "reason": reason, "name": name,
                     "form_url": WAITLIST_FORM_URL},
            status_code=status_code,
        )

    # Honeypot: looks exactly like a real sign up, stores nothing, sends
    # nothing and does not touch the rate limiter.
    if honeypot.strip():
        return _page(success=True)

    if not name:
        return _page(success=False, status_code=400,
                     reason="Please give a first name.")
    if len(name) > WAITLIST_NAME_MAX:
        return _page(success=False, status_code=400,
                     reason="That name is too long. A first name is all that is needed.")
    if not email or len(email) > WAITLIST_EMAIL_MAX or not EMAIL_RE.match(email):
        return _page(success=False, status_code=400,
                     reason="Please give a valid email address.")

    err = _check_waitlist_rate_limit(email, ip)
    if err:
        return _page(success=False, status_code=429, reason=err)

    now = datetime.now(UTC).isoformat()
    signup_id = uuid.uuid4().hex
    with get_db() as db:
        db.execute(
            "INSERT INTO waitlist_attempts (id, email, ip, created_at) VALUES (?,?,?,?)",
            (uuid.uuid4().hex, email, ip, now),
        )
        cur = db.execute(
            "INSERT OR IGNORE INTO waitlist_signups (id, email, name, devices, tool, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (signup_id, email, name, devices, tool, now),
        )
        is_new = cur.rowcount == 1
        total = db.execute("SELECT COUNT(*) FROM waitlist_signups").fetchone()[0]

    # Already on the list: nothing new to store, nothing to announce, and the
    # same page as a first sign up.
    if not is_new:
        return _page(success=True)

    subject = f"Waitlist sign up {total}: {name}"
    text = (
        f"Sign up number {total} on the Patched waitlist.\n\n"
        f"Name: {name}\n"
        f"Email: {email}\n"
        f"Macs: {devices or '-'}\n"
        f"Uses now: {tool or '-'}\n"
    )
    body_html = (
        f"<p>Sign up number <b>{total}</b> on the Patched waitlist.</p>"
        f"<p><b>Name:</b> {html.escape(name)}<br>"
        f"<b>Email:</b> {html.escape(email)}<br>"
        f"<b>Macs:</b> {html.escape(devices or '-')}<br>"
        f"<b>Uses now:</b> {html.escape(tool or '-')}</p>"
    )
    # _send_email, not the enquiry form's direct _graph_send_mail: it is the
    # path the scan funnel's own OTP and report mail takes (Graph when the
    # Mailer app is configured, SendGrid otherwise), so this works under
    # either mail setup the box may have. It honours EMAIL_DRY_RUN, which
    # logs the message and reports success; that setting is for staging and
    # must be blank in production (deploy/env-scan.template).
    if _send_email(WAITLIST_NOTIFY_TO, subject, body_html, text):
        with get_db() as db:
            db.execute(
                "UPDATE waitlist_signups SET notified_at=? WHERE id=?",
                (datetime.now(UTC).isoformat(), signup_id),
            )
    else:
        # The person IS on the list, so they are told so. What failed is the
        # owner's copy: say it where it will be seen (the service log, and
        # waitlist_unnotified on /healthz), never to the visitor.
        print(f"[waitlist] sign up {total} stored but its notification email "
              f"was not sent ({_mask_email(email)})")

    return _page(success=True)
