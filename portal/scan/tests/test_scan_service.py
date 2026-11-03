"""End-to-end tests for the standalone public scan service (PAT-457/PAT-121).

No network: Turnstile is skipped, email is dry-run, NVD is the fixture DB.
Covers healthz, rate limiting, the OTP state machine (happy path, max attempts,
expiry), upload size/type rejection, the full upload -> verify -> scan -> report
-> download -> delete flow, and the NVD-missing 503 gate.
"""

import sqlite3
import threading
import time
from datetime import UTC, datetime, timedelta

import shared


# ── helpers ──────────────────────────────────────────────────────────────────
def _submit_scan(client, devices_csv, email="scan@test.example", company="Acme"):
    """POST /public/scan; returns (response, scan_id or None)."""
    resp = client.post(
        "/public/scan",
        data={"company": company, "email": email, "authorised": "yes",
              "cf-turnstile-response": "x"},
        files={"devices_file": ("devices.csv", devices_csv, "text/csv")},
        follow_redirects=False,
    )
    scan_id = None
    if resp.status_code == 303:
        scan_id = resp.headers["location"].rsplit("/", 1)[-1]
    return resp, scan_id


def _otp_for(scan_id):
    conn = sqlite3.connect(str(shared.DB_PATH))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT otp_code FROM public_scans WHERE id=?", (scan_id,)).fetchone()
    conn.close()
    return row["otp_code"] if row else None


def _wait_status(client, scan_id, want="complete", timeout=20.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = client.get(f"/public/scan/status/{scan_id}").json()
        if last.get("status") in (want, "error"):
            return last
        time.sleep(0.1)
    return last


# ── healthz ──────────────────────────────────────────────────────────────────
def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["nvd"] is True  # fixture NVD DB is present
    # PAT-1210: fixture nvd.db is built fresh at test-session start, so it
    # must never report stale, and its last-refreshed timestamp must be present.
    assert "nvd_last_refreshed" in body
    assert body["nvd_last_refreshed"] is not None
    assert "nvd_stale" in body
    assert body["nvd_stale"] is False
    # PAT-893: conftest sets TURNSTILE_DEV_BYPASS=1 for the whole suite, so
    # the secret is genuinely unconfigured but the bypass is active.
    assert body["turnstile_configured"] is False
    assert body["turnstile_dev_bypass"] is True
    # PAT-1176: no DEPLOYED_SHA file in the test state dir, so both fields
    # report null rather than erroring - a legitimate pre-first-deploy state.
    assert body["deployed_sha"] is None
    assert body["deployed_at"] is None


def test_healthz_reports_stale_dataset(client, monkeypatch):
    """PAT-1210: /healthz must distinguish 'present but abandoned' from
    genuinely current. scanner.nvd_stale() looks up nvd_last_refreshed()
    unqualified within scanner.py's own module globals at call time, so
    patching the scanner module attribute (rather than app.py's separately
    bound import of the same function) is the seam that actually flows
    through nvd_stale() regardless of who calls it."""
    import scanner

    ten_days_ago = time.time() - 60 * 60 * 24 * 10
    monkeypatch.setattr(scanner, "nvd_last_refreshed", lambda: ten_days_ago)
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["nvd_stale"] is True


def test_healthz_reports_deployed_sha_once_recorded(client, tmp_path, monkeypatch):
    """PAT-1176: deploy/deploy-portal-01.sh writes DEPLOYED_SHA as the last
    step of a deploy; scan's /healthz must surface it the same way main.py's
    does for the portal service, without adding a new route."""
    import app as scan_app

    sha_file = tmp_path / "DEPLOYED_SHA"
    sha_file.write_text("DEPLOYED_SHA=abc1234def5678\nDEPLOYED_AT=2026-08-05T12:00:00Z\n")
    monkeypatch.setattr(scan_app, "DEPLOYED_SHA_FILE", sha_file)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["deployed_sha"] == "abc1234def5678"
    assert body["deployed_at"] == "2026-08-05T12:00:00Z"


def test_healthz_deployed_sha_missing_key_line_is_null_not_error(client, tmp_path, monkeypatch):
    import app as scan_app

    sha_file = tmp_path / "DEPLOYED_SHA"
    sha_file.write_text("some unrelated content\n")
    monkeypatch.setattr(scan_app, "DEPLOYED_SHA_FILE", sha_file)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["deployed_sha"] is None
    assert body["deployed_at"] is None


# ── Turnstile fail-closed (PAT-893) ─────────────────────────────────────────
def test_verify_turnstile_fails_closed_when_unconfigured(monkeypatch):
    import shared
    monkeypatch.setattr(shared, "TURNSTILE_SECRET", "")
    monkeypatch.setattr(shared, "TURNSTILE_DEV_BYPASS", False)
    assert shared._verify_turnstile("any-token", "1.2.3.4") is False


def test_verify_turnstile_bypass_still_works_for_dev(monkeypatch):
    import shared
    monkeypatch.setattr(shared, "TURNSTILE_SECRET", "")
    monkeypatch.setattr(shared, "TURNSTILE_DEV_BYPASS", True)
    assert shared._verify_turnstile("any-token", "1.2.3.4") is True


def test_submit_refused_when_turnstile_misconfigured(client, devices_csv, monkeypatch):
    """With the secret unset and the dev bypass OFF, /public/scan must refuse
    the submission rather than silently letting it through (the PAT-893 bug:
    an operator who forgets TURNSTILE_SECRET during install got bot
    protection silently disabled instead of a refused service)."""
    import shared
    monkeypatch.setattr(shared, "TURNSTILE_SECRET", "")
    monkeypatch.setattr(shared, "TURNSTILE_DEV_BYPASS", False)
    resp, sid = _submit_scan(client, devices_csv)
    assert resp.status_code == 400
    assert sid is None


# ── rate limiting ────────────────────────────────────────────────────────────
def test_scan_rate_limit_per_email(client, devices_csv):
    email = "rl@test.example"
    for _ in range(3):
        resp, sid = _submit_scan(client, devices_csv, email=email)
        assert resp.status_code == 303, resp.text
    # 4th submission from the same email in 24h is refused.
    resp, _ = _submit_scan(client, devices_csv, email=email)
    assert resp.status_code == 429
    assert "Too many scans" in resp.text


# ── OTP state machine ────────────────────────────────────────────────────────
def test_otp_happy_path_download_and_delete(client, devices_csv):
    resp, scan_id = _submit_scan(client, devices_csv)
    assert scan_id, resp.text

    otp = _otp_for(scan_id)
    assert otp and len(otp) == 6

    verify = client.post(f"/public/scan/verify/{scan_id}", data={"otp": otp},
                         follow_redirects=False)
    assert verify.status_code == 303
    assert verify.headers["location"].endswith(f"/public/scan/done/{scan_id}")

    status = _wait_status(client, scan_id, want="complete")
    assert status and status["status"] == "complete", status
    assert "download_url" in status

    # Download the report.
    dl = client.get(status["download_url"])
    assert dl.status_code == 200
    assert dl.headers["content-type"].startswith(
        "application/vnd.openxmlformats-officedocument"
    )
    assert dl.content[:2] == b"PK"  # .docx is a zip container
    assert len(dl.content) > 1000

    # Delete flow: fetch delete token from DB, GET the confirm page, POST it.
    conn = sqlite3.connect(str(shared.DB_PATH))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT delete_token FROM public_scans WHERE id=?",
                       (scan_id,)).fetchone()
    conn.close()
    token = row["delete_token"]

    assert client.get(f"/public/scan/d/{token}").status_code == 200
    dele = client.post(f"/public/scan/d/{token}")
    assert dele.status_code == 200
    assert "Deleted" in dele.text

    # After erasure, the download link and removed scan both return 404.
    assert client.get(status["download_url"]).status_code == 404
    assert client.get(f"/public/scan/status/{scan_id}").status_code == 404


def test_otp_max_attempts_locks_out(client, devices_csv):
    resp, scan_id = _submit_scan(client, devices_csv, email="lock@test.example")
    assert scan_id
    # 5 wrong codes are rejected 400; the 6th trips the lockout (429).
    for _ in range(5):
        bad = client.post(f"/public/scan/verify/{scan_id}", data={"otp": "000000"})
        assert bad.status_code == 400, bad.text
    locked = client.post(f"/public/scan/verify/{scan_id}", data={"otp": "000000"})
    assert locked.status_code == 429
    # Even the correct code no longer works once locked / errored.
    otp = _otp_for(scan_id)
    # otp_code may have been left intact (status flipped to error); the link is dead.
    after = client.post(f"/public/scan/verify/{scan_id}", data={"otp": otp or "000000"})
    assert after.status_code in (410, 429)


def test_otp_concurrent_attempts_never_exceed_cap(client, devices_csv):
    """N concurrent wrong-code submissions against one scan_id (PAT-890).

    The lockout used to be a read-then-write race: each request read
    otp_attempts, then wrote otp_attempts+1 as a separate statement over its
    own get_db() connection, so concurrent requests could all read the count
    before any increment committed and all get to test a guess. Firing many
    threads at once and counting how many actually reached the comparison
    step (400 = compared and rejected, 429 = turned away by the lockout
    before comparing) proves the cap holds under real concurrency, not just
    sequentially.
    """
    resp, scan_id = _submit_scan(client, devices_csv, email="race@test.example")
    assert scan_id

    concurrency = 20
    results: list[int] = []
    lock = threading.Lock()

    def _guess():
        r = client.post(f"/public/scan/verify/{scan_id}", data={"otp": "000000"})
        with lock:
            results.append(r.status_code)

    threads = [threading.Thread(target=_guess) for _ in range(concurrency)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == concurrency
    compared = results.count(400)  # reached secrets.compare_digest
    # 429 = this request's own reservation lost the race against the cap.
    # 410 = the request read status='error' on its initial lookup because a
    # different thread's reservation had already tripped the lockout and
    # flipped status before this one even got that far. Both mean "never
    # reached the comparison step".
    turned_away = results.count(429) + results.count(410)
    assert compared + turned_away == concurrency, results
    assert compared <= shared.OTP_MAX_ATTEMPTS, (
        f"{compared} guesses reached the comparison step, cap is "
        f"{shared.OTP_MAX_ATTEMPTS}: {results}"
    )

    conn = sqlite3.connect(str(shared.DB_PATH))
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT otp_attempts, status FROM public_scans WHERE id=?", (scan_id,)
    ).fetchone()
    conn.close()
    assert row["otp_attempts"] == shared.OTP_MAX_ATTEMPTS
    assert row["status"] == "error"


def test_otp_expired(client, devices_csv):
    resp, scan_id = _submit_scan(client, devices_csv, email="exp@test.example")
    assert scan_id
    otp = _otp_for(scan_id)
    # Force expiry into the past.
    past = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    conn = sqlite3.connect(str(shared.DB_PATH))
    conn.execute("UPDATE public_scans SET otp_expires_at=? WHERE id=?", (past, scan_id))
    conn.commit()
    conn.close()
    r = client.post(f"/public/scan/verify/{scan_id}", data={"otp": otp})
    assert r.status_code == 410
    assert "expired" in r.text.lower()


# ── upload funnel: size + type rejection ─────────────────────────────────────
def test_upload_rejects_oversize(client):
    big = b"a" * (10 * 1024 * 1024 + 1)  # > 10 MB cap
    r = client.post(
        "/public/intune-upload",
        data={"email": "big@test.example", "cf-turnstile-response": "x"},
        files={"file": ("big.csv", big, "text/csv")},
    )
    assert r.status_code == 400
    assert "too large" in r.text.lower()


def test_upload_rejects_unknown_csv(client):
    junk = b"colA,colB\n1,2\n3,4\n"
    r = client.post(
        "/public/intune-upload",
        data={"email": "junk@test.example", "cf-turnstile-response": "x"},
        files={"file": ("junk.csv", junk, "text/csv")},
    )
    assert r.status_code == 400
    # (apostrophe is HTML-escaped by Jinja autoescape, so match on plain words)
    assert "identify this CSV" in r.text


def test_upload_devices_report_emailed_with_attachment(client, monkeypatch):
    """Regression for a bug ported from the dashboard: the upload funnel's email
    call passed the report path into the `text` parameter instead of
    `attachment_path`, so the 'report is attached' email had no attachment (and
    this funnel has no download route). Assert the attachment path is passed and
    a real .docx exists there."""
    import os
    import threading

    import router

    calls = []
    done = threading.Event()

    def _record(to_email, subject, html, text, attachment_path=None,
                attachment_name=None, bcc=None):
        calls.append({"to": to_email, "subject": subject, "html": html,
                      "text": text, "attachment_path": attachment_path,
                      "bcc": bcc})
        done.set()
        return True

    monkeypatch.setattr(router, "_send_email", _record)

    csv_bytes = (
        b"Device name,OS,OS version,Compliance,Last check-in\n"
        b"UP-PC-01,Windows,10.0.19045.0,Compliant,2026-07-01T09:00:00Z\n"
    )
    r = client.post(
        "/public/intune-upload",
        data={"email": "attach@test.example", "cf-turnstile-response": "x"},
        files={"file": ("devices.csv", csv_bytes, "text/csv")},
    )
    assert r.status_code == 200

    assert done.wait(timeout=15), "background upload job did not send email"
    call = calls[0]
    assert call["attachment_path"], "report was not passed as an attachment"
    assert call["attachment_path"].endswith(".docx")
    assert os.path.exists(call["attachment_path"])
    with open(call["attachment_path"], "rb") as f:
        assert f.read(2) == b"PK"  # a real .docx sits at the attached path
    # And the body params are actually HTML + plain text, not a file path.
    # (the body opens with the brand logo header, then the copy paragraphs)
    assert call["html"].startswith("<img ")
    assert "<p>Hi,</p>" in call["html"]
    assert "attached" in call["text"]
    assert not call["text"].rstrip().endswith(".docx")
    # PAT-1184: SCAN_REPORT_BCC is unset in the test environment, so the
    # default behaviour (no bcc key materialising into a real address) holds.
    assert call["bcc"] is None


# ── PAT-1184: SCAN_REPORT_BCC ────────────────────────────────────────────────
# Payload-building unit tests: EMAIL_DRY_RUN is forced off and the transport
# (shared.http.post) is stubbed so no real network call is made, but the
# actual Graph/SendGrid message dict that _send_email builds is inspected
# directly for the bcc field.
def test_send_email_graph_adds_bcc_when_set(monkeypatch):
    import shared

    monkeypatch.setattr(shared, "EMAIL_DRY_RUN", False)
    monkeypatch.setattr(shared, "GRAPH_MAIL_TENANT_ID", "tid")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_ID", "cid")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_SECRET", "secret")
    monkeypatch.setattr(shared, "_graph_mail_token", lambda: "fake-token")

    captured = {}

    class _Resp:
        status_code = 200
        text = ""

    def _fake_post(url, json=None, headers=None, timeout=None, **kw):
        captured["json"] = json
        return _Resp()

    monkeypatch.setattr(shared.http, "post", _fake_post)

    ok = shared._send_email("user@example.com", "Subject", "<p>hi</p>", "hi",
                            bcc="ops@patched.im")
    assert ok is True
    message = captured["json"]["message"]
    assert message["bccRecipients"] == [{"emailAddress": {"address": "ops@patched.im"}}]


def test_send_email_graph_no_bcc_key_when_unset(monkeypatch):
    import shared

    monkeypatch.setattr(shared, "EMAIL_DRY_RUN", False)
    monkeypatch.setattr(shared, "GRAPH_MAIL_TENANT_ID", "tid")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_ID", "cid")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_SECRET", "secret")
    monkeypatch.setattr(shared, "_graph_mail_token", lambda: "fake-token")

    captured = {}

    class _Resp:
        status_code = 200
        text = ""

    def _fake_post(url, json=None, headers=None, timeout=None, **kw):
        captured["json"] = json
        return _Resp()

    monkeypatch.setattr(shared.http, "post", _fake_post)

    ok = shared._send_email("user@example.com", "Subject", "<p>hi</p>", "hi")
    assert ok is True
    assert "bccRecipients" not in captured["json"]["message"]


def test_send_email_sendgrid_adds_bcc_when_set(monkeypatch):
    import shared

    monkeypatch.setattr(shared, "EMAIL_DRY_RUN", False)
    monkeypatch.setattr(shared, "GRAPH_MAIL_TENANT_ID", "")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_ID", "")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_SECRET", "")
    monkeypatch.setattr(shared, "SENDGRID_API_KEY", "sg-key")

    captured = {}

    class _Resp:
        status_code = 202
        text = ""

    def _fake_post(url, json=None, headers=None, timeout=None, **kw):
        captured["json"] = json
        return _Resp()

    monkeypatch.setattr(shared.http, "post", _fake_post)

    ok = shared._send_email("user@example.com", "Subject", "<p>hi</p>", "hi",
                            bcc="ops@patched.im")
    assert ok is True
    assert captured["json"]["personalizations"][0]["bcc"] == [{"email": "ops@patched.im"}]


def test_send_email_sendgrid_no_bcc_key_when_unset(monkeypatch):
    import shared

    monkeypatch.setattr(shared, "EMAIL_DRY_RUN", False)
    monkeypatch.setattr(shared, "GRAPH_MAIL_TENANT_ID", "")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_ID", "")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_SECRET", "")
    monkeypatch.setattr(shared, "SENDGRID_API_KEY", "sg-key")

    captured = {}

    class _Resp:
        status_code = 202
        text = ""

    def _fake_post(url, json=None, headers=None, timeout=None, **kw):
        captured["json"] = json
        return _Resp()

    monkeypatch.setattr(shared.http, "post", _fake_post)

    ok = shared._send_email("user@example.com", "Subject", "<p>hi</p>", "hi")
    assert ok is True
    assert "bcc" not in captured["json"]["personalizations"][0]


def test_upload_report_email_includes_configured_bcc(client, monkeypatch):
    """The intune-upload REPORT send (_run_upload_job) must pass bcc=SCAN_REPORT_BCC."""
    import router

    monkeypatch.setattr(router, "SCAN_REPORT_BCC", "ops@patched.im")

    calls = []
    done = threading.Event()

    def _record(*args, **kwargs):
        calls.append(kwargs)
        done.set()
        return True

    monkeypatch.setattr(router, "_send_email", _record)

    csv_bytes = (
        b"Device name,OS,OS version,Compliance,Last check-in\n"
        b"UP-PC-01,Windows,10.0.19045.0,Compliant,2026-07-01T09:00:00Z\n"
    )
    r = client.post(
        "/public/intune-upload",
        data={"email": "bcc-on@test.example", "cf-turnstile-response": "x"},
        files={"file": ("devices.csv", csv_bytes, "text/csv")},
    )
    assert r.status_code == 200
    assert done.wait(timeout=15), "background upload job did not send email"
    assert calls[0].get("bcc") == "ops@patched.im"


def test_upload_report_email_no_bcc_when_unset(client, monkeypatch):
    import router

    monkeypatch.setattr(router, "SCAN_REPORT_BCC", "")

    calls = []
    done = threading.Event()

    def _record(*args, **kwargs):
        calls.append(kwargs)
        done.set()
        return True

    monkeypatch.setattr(router, "_send_email", _record)

    csv_bytes = (
        b"Device name,OS,OS version,Compliance,Last check-in\n"
        b"UP-PC-01,Windows,10.0.19045.0,Compliant,2026-07-01T09:00:00Z\n"
    )
    r = client.post(
        "/public/intune-upload",
        data={"email": "bcc-off@test.example", "cf-turnstile-response": "x"},
        files={"file": ("devices.csv", csv_bytes, "text/csv")},
    )
    assert r.status_code == 200
    assert done.wait(timeout=15), "background upload job did not send email"
    assert calls[0].get("bcc") is None


def test_public_scan_report_email_gets_bcc_but_otp_never_does(client, devices_csv, monkeypatch):
    """PAT-1184: the CVE-scan REPORT email (shared._run_public_scan) carries
    the configured BCC; the OTP/verification email (router.py) must NEVER
    carry one, even with SCAN_REPORT_BCC set — Andy does not want OTP codes."""
    import router
    import shared

    monkeypatch.setattr(shared, "SCAN_REPORT_BCC", "ops@patched.im")

    calls = []

    def _record(to_email, subject, html, text, attachment_path=None,
                attachment_name=None, bcc=None):
        calls.append({"subject": subject, "bcc": bcc})
        return True

    # OTP send goes through router's own imported _send_email binding; the
    # report send (inside _run_public_scan) goes through shared's.
    monkeypatch.setattr(router, "_send_email", _record)
    monkeypatch.setattr(shared, "_send_email", _record)

    resp, scan_id = _submit_scan(client, devices_csv, email="bcc-flow@test.example")
    assert scan_id, resp.text

    otp = _otp_for(scan_id)
    assert otp

    verify = client.post(f"/public/scan/verify/{scan_id}", data={"otp": otp},
                         follow_redirects=False)
    assert verify.status_code == 303

    status = _wait_status(client, scan_id, want="complete")
    assert status and status["status"] == "complete", status

    assert len(calls) == 2, calls
    otp_call, report_call = calls
    assert "verification code" in otp_call["subject"].lower()
    assert otp_call["bcc"] is None, "OTP email must never carry the ops BCC"
    assert "CVE assessment" in report_call["subject"]
    assert report_call["bcc"] == "ops@patched.im"


# ── NVD-missing gate ─────────────────────────────────────────────────────────
def test_scan_refused_when_nvd_missing(client, devices_csv, monkeypatch):
    import router
    monkeypatch.setattr(router, "nvd_available", lambda: False)
    resp, scan_id = _submit_scan(client, devices_csv, email="no-nvd@test.example")
    assert resp.status_code == 503
    assert scan_id is None
    assert "temporarily unavailable" in resp.text.lower()


def test_pages_render(client):
    for path in ("/public/scan", "/public/intune-upload", "/public/privacy",
                 "/public/intune-instructions"):
        r = client.get(path)
        assert r.status_code == 200, path
        assert "Patched" in r.text


def test_nvd_sync_parses_fkie_top_level_shape(tmp_path):
    """Regression: fkie-cad per-CVE JSON has id/descriptions/metrics/published at
    the TOP level (not nested under "cve"). The original dashboard-ported parser
    read the nested shape only, so every row collapsed to cve_id="?" and the
    PRIMARY KEY squashed the whole dataset to one row per prefix."""
    import json
    import sqlite3
    import zipfile

    import scanner

    cve = {
        "id": "CVE-2099-0001",
        "published": "2099-01-02T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "Test flaw in Windows 10."}],
        "metrics": {
            "cvssMetricV31": [
                {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
            ]
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "criteria": "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*"
                            }
                        ]
                    }
                ]
            }
        ],
    }
    feed = tmp_path / "feed.zip"
    with zipfile.ZipFile(feed, "w") as zf:
        zf.writestr("nvd-json-data-feeds-main/CVE-2099-0001.json", json.dumps(cve))
        # A no-configurations file must be skipped, not crash.
        zf.writestr(
            "nvd-json-data-feeds-main/CVE-2099-0002.json",
            json.dumps({"id": "CVE-2099-0002"}),
        )

    out_db = tmp_path / "nvd-sync.db"
    scanner.sync_nvd_local_dataset(db_path=str(out_db), feed_zip=str(feed))

    row = sqlite3.connect(out_db).execute(
        "SELECT cve_id, cpe_prefix, description, base_score, severity, published FROM nvd_cves"
    ).fetchall()
    assert row == [
        (
            "CVE-2099-0001",
            "cpe:2.3:o:microsoft:windows_10",
            "Test flaw in Windows 10.",
            9.8,
            "CRITICAL",
            "2099-01-02",
        )
    ]


def test_nvd_sync_creates_cpe_prefix_index(tmp_path):
    """PAT-1218: `_scan`'s `WHERE cpe_prefix = ?` lookup cannot be served by
    the nvd_cves PRIMARY KEY (cve_id, cpe_prefix) alone — confirmed on
    production via EXPLAIN QUERY PLAN showing a full table scan over a 132MB
    dataset. Every (re)build via sync_nvd_local_dataset must create the
    supporting index so future dataset refreshes get it automatically."""
    import json
    import zipfile

    import scanner

    cve = {
        "id": "CVE-2099-9999",
        "published": "2099-01-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "Index coverage test."}],
        "metrics": {
            "cvssMetricV31": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}]
        },
        "configurations": [
            {"nodes": [{"cpeMatch": [
                {"criteria": "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*"}
            ]}]}
        ],
    }
    feed = tmp_path / "feed.zip"
    with zipfile.ZipFile(feed, "w") as zf:
        zf.writestr("nvd-json-data-feeds-main/CVE-2099-9999.json", json.dumps(cve))

    out_db = tmp_path / "nvd-index.db"
    scanner.sync_nvd_local_dataset(db_path=str(out_db), feed_zip=str(feed))

    idx = sqlite3.connect(str(out_db)).execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_nvd_cves_cpe_prefix'"
    ).fetchone()
    assert idx is not None, "sync_nvd_local_dataset must create idx_nvd_cves_cpe_prefix"


# ── PAT-864: formula/CSV injection into the delivered .docx report ──────────
def test_gen_report_neutralises_formula_device_name(tmp_path):
    """Regression for PAT-864: an uploaded Intune CSV device name starting with
    a formula-injection prefix (=, +, -, @) must never land raw in a docx cell
    of the report delivered off the unauthenticated public scan funnel — it must
    come out prefixed with a leading apostrophe per neutralise_formula()'s
    convention. Exercises the real pipeline (run_scan_from_upload -> _gen_report)
    with a malicious device name, then reads the generated .docx back to check
    the cell text actually written, not just the helper in isolation."""
    import scanner
    from docx import Document

    malicious_name = "=cmd|'/c calc'!A1"
    devices_csv = (
        "Device name,OS,OS version,Compliance,Last check-in\n"
        f"{malicious_name},Windows,10.0.19045.0,Compliant,2026-07-01T09:00:00Z\n"
    ).encode()
    csv_path = tmp_path / "devices.csv"
    csv_path.write_bytes(devices_csv)
    out_path = tmp_path / "report.docx"

    scanner.run_scan_from_upload(
        devices_csv_path=str(csv_path),
        apps_file_path=None,
        nvd_api_key="",
        company_name="Acme",
        logo_path=None,
        output_path=str(out_path),
    )

    doc = Document(str(out_path))
    # Collect every cell across every table — the device name must never
    # appear anywhere as a live, un-neutralised formula.
    all_cell_texts = [c.text for t in doc.tables for row in t.rows for c in row.cells]

    assert malicious_name not in all_cell_texts, (
        "device name reached a docx cell as a live formula, unneutralised"
    )
    neutralised = "'" + malicious_name
    assert neutralised in all_cell_texts, (
        "neutralised device name not found in any table cell — "
        "expected it prefixed with a leading apostrophe"
    )

    # Specifically the Device Security Posture table (scanner.py:398,401-402 —
    # the root cause cited in PAT-864): device name is column 0 of the first
    # data row.
    posture_table = doc.tables[2]
    assert posture_table.cell(1, 0).text == neutralised

    # And the Windows Devices summary table, which carries the same field.
    windows_table = doc.tables[3]
    assert windows_table.cell(1, 0).text == neutralised


# ── PAT-1173: unbounded per-app CVE enumeration + jobs stuck in 'processing' ─
def test_apps_cve_report_caps_cves_per_app_and_notes_truncation(tmp_path, monkeypatch):
    """Regression for PAT-1173: uploading a handful of high-CVE apps (Chrome,
    Firefox, OpenSSL — each with thousands of matching NVD CVEs) made
    generate_apps_cve_report enumerate every matching CVE per app with no cap,
    producing an enormous .docx and a job that ground for 17+ minutes. Feed a
    single synthetic app with 400 fake CVEs (scanner._scan is monkeypatched so
    this never touches the real NVD dataset) and assert: the rendered CVE
    table is capped to CVE_REPORT_MAX_PER_APP rows, the report still reports
    the true uncapped total, a 'top N of M' truncation note is present in the
    report text, and generation completes quickly rather than grinding."""
    import time as time_mod

    import intune_upload
    from docx import Document

    many_cves = [
        {
            "id": f"CVE-2099-{i:05d}",
            "description": "Synthetic test CVE for cap coverage.",
            "score": round(10.0 - i * 0.001, 3),
            "severity": "CRITICAL" if i < 10 else ("HIGH" if i < 100 else "MEDIUM"),
            "published": "2099-01-01",
        }
        for i in range(400)
    ]

    def _fake_scan(app_cpe, key, cache):
        return many_cves

    monkeypatch.setattr(intune_upload, "_scan", _fake_scan)

    apps = [{"name": "Google Chrome", "version": "120.0.6099.129", "platform": "Windows"}]
    out_path = tmp_path / "apps_cve_report.docx"

    start = time_mod.monotonic()
    stats = intune_upload.generate_apps_cve_report(apps, "", str(out_path), None)
    elapsed = time_mod.monotonic() - start

    assert elapsed < 5.0, f"report generation took {elapsed:.2f}s for a single high-CVE app"
    # Counts/summary stats still reflect the true, uncapped total.
    assert stats["total_cves"] == 400
    assert stats["apps_with_cves"] == 1

    doc = Document(str(out_path))
    # Both the "Vulnerable Applications" and "CVE Inventory" tables have 5
    # columns; the CVE inventory table is built later in the document, so it's
    # the last 5-column table.
    five_col_tables = [t for t in doc.tables if len(t.columns) == 5]
    assert len(five_col_tables) == 2, "expected the vulnerable-apps and CVE inventory tables"
    cve_table = five_col_tables[-1]
    rendered_cve_rows = len(cve_table.rows) - 1  # minus header row
    assert rendered_cve_rows == intune_upload.CVE_REPORT_MAX_PER_APP

    all_text = "\n".join(p.text for p in doc.paragraphs)
    assert f"top {intune_upload.CVE_REPORT_MAX_PER_APP} of 400" in all_text, (
        "truncation note ('top N of M CVEs by CVSS score') not found in report text"
    )


# ── PAT-1218: scan-funnel timeout cap ────────────────────────────────────────
def test_cve_inventory_appendix_caps_rows_and_notes_truncation(tmp_path, monkeypatch):
    """Regression for PAT-1218: scanner.py's own "CVE Inventory" appendix
    table (built in _gen_report, distinct from intune_upload's per-app CVE
    table already covered by test_apps_cve_report_caps_cves_per_app_and_notes_truncation
    above) was the only unbounded per-report render left in scan/scanner.py —
    a realistic estate can produce 10,000+ unique CVE rows here. Monkeypatch
    scanner._scan (not intune_upload._scan) so a single device's fake CVEs
    flow through run_scan_from_upload into _gen_report's CVE Inventory table,
    then assert: the table is capped to CVE_APPENDIX_MAX_ROWS rows, generation
    completes quickly, and the 'Showing top N of M' note is present."""
    import time as time_mod

    import scanner
    from docx import Document

    many_cves = [
        {
            "id": f"CVE-2099-{i:05d}",
            "description": "Synthetic test CVE for appendix cap coverage.",
            "score": round(10.0 - i * 0.001, 3),
            "severity": "CRITICAL" if i < 10 else ("HIGH" if i < 100 else "MEDIUM"),
            "published": "2099-01-01",
        }
        for i in range(400)
    ]

    def _fake_scan(app_cpe, key, cache):
        # run_scan_from_upload reads results back out of `cache` (populated
        # by _scan as a side effect in the real implementation) rather than
        # this return value directly, so the fake must mirror that contract.
        cache[app_cpe] = many_cves
        return many_cves

    monkeypatch.setattr(scanner, "_scan", _fake_scan)

    devices_csv = (
        b"Device name,OS,OS version,Compliance,Last check-in\n"
        b"APPENDIX-PC-01,Windows,10.0.19045.0,Compliant,2026-07-01T09:00:00Z\n"
    )
    csv_path = tmp_path / "devices.csv"
    csv_path.write_bytes(devices_csv)
    out_path = tmp_path / "report.docx"

    start = time_mod.monotonic()
    scanner.run_scan_from_upload(
        devices_csv_path=str(csv_path),
        apps_file_path=None,
        nvd_api_key="",
        company_name="Acme",
        logo_path=None,
        output_path=str(out_path),
    )
    elapsed = time_mod.monotonic() - start
    assert elapsed < 5.0, f"report generation took {elapsed:.2f}s for a single high-CVE device"

    doc = Document(str(out_path))
    five_col_tables = [t for t in doc.tables if len(t.columns) == 5]
    cve_table = None
    for t in five_col_tables:
        if t.cell(0, 0).text == "CVE ID":
            cve_table = t
            break
    assert cve_table is not None, "CVE Inventory table (header row 'CVE ID', ...) not found"
    rendered_cve_rows = len(cve_table.rows) - 1  # minus header row
    assert rendered_cve_rows == scanner.CVE_APPENDIX_MAX_ROWS

    all_text = "\n".join(p.text for p in doc.paragraphs)
    assert f"top {scanner.CVE_APPENDIX_MAX_ROWS} of 400" in all_text, (
        "truncation note ('Showing top N of M unique CVEs...') not found in report text"
    )


def test_scan_reuses_prefix_fetch_across_versions_of_same_base_cpe(tmp_path, monkeypatch):
    """PAT-1218: two versions of the same product (eg. Chrome 120 vs 124)
    share a base_cpe. The DB fetch + json.loads of every matching row's
    `configurations` blob is the expensive part and depends only on
    base_cpe, not the specific version, so it must happen once per report
    (per shared `cache` dict) regardless of how many versions of that
    product the estate has. Seed a tiny real NVD db with one CVE whose
    versionStartIncluding excludes the older version and includes the newer
    one, count actual sqlite3.connect calls across two scanner._scan() calls
    sharing one cache dict, and confirm both calls still return correct
    (different) results."""
    import json

    import scanner

    configs = [{"nodes": [{"cpeMatch": [
        {
            "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "124.0.0",
        }
    ]}]}]
    db_path = tmp_path / "nvd-versions.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE nvd_cves (cve_id TEXT, cpe_prefix TEXT, description TEXT, "
        "base_score REAL, severity TEXT, published TEXT, configurations TEXT, "
        "PRIMARY KEY(cve_id, cpe_prefix))"
    )
    conn.execute(
        "INSERT INTO nvd_cves VALUES (?,?,?,?,?,?,?)",
        ("CVE-2099-CHROME", "cpe:2.3:a:google:chrome", "Chrome flaw only in 124+.",
         8.8, "HIGH", "2099-01-01", json.dumps(configs)),
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr(scanner, "NVD_DB_PATH", str(db_path))

    connect_calls = []
    real_connect = scanner.sqlite3.connect

    def _counting_connect(*a, **kw):
        connect_calls.append((a, kw))
        return real_connect(*a, **kw)

    monkeypatch.setattr(scanner.sqlite3, "connect", _counting_connect)

    cache = {}
    old_cpe = "cpe:2.3:a:google:chrome:120.0.6099.129:*:*:*:*:*:*:*"
    new_cpe = "cpe:2.3:a:google:chrome:124.0.6367.0:*:*:*:*:*:*:*"

    old_result = scanner._scan(old_cpe, "", cache)
    new_result = scanner._scan(new_cpe, "", cache)

    assert len(connect_calls) == 1, (
        f"expected exactly one sqlite3.connect for the shared base_cpe prefix "
        f"across both versions, got {len(connect_calls)}"
    )
    assert old_result == [], "version 120 must not match a versionStartIncluding=124.0.0 CVE"
    assert len(new_result) == 1 and new_result[0]["id"] == "CVE-2099-CHROME", new_result


def test_public_done_page_recognises_timeout_and_not_found_status(client, devices_csv):
    """PAT-1218: the poll loop's JS previously recognised only complete/error/
    deleted as terminal — 'timeout' (introduced by PAT-1177) and 'not_found'
    (the shape of a 404 body from /public/scan/status, see router.py's
    public_scan_status) both fell through to 'keep polling' and, once
    maxPolls was exhausted, silently stopped with the spinner still showing.
    There's no JS test harness in this repo, so this is a lightweight
    string-presence regression proving the branches exist in the rendered
    page, not a full JS execution test."""
    resp, scan_id = _submit_scan(client, devices_csv, email="done-page@test.example")
    assert resp.status_code == 303
    r = client.get(f"/public/scan/done/{scan_id}")
    assert r.status_code == 200
    assert "'timeout'" in r.text
    assert "'not_found'" in r.text


def test_run_public_scan_timeout_sends_failure_email(client, devices_csv, monkeypatch):
    """PAT-1218: the scan page promises a backup email ('We'll also email a
    copy... as a backup'), but a timed-out job previously updated the DB row
    and returned without ever sending it — only the except-block's
    generic-error path sent one. Force run_report_job to report a timeout
    outcome directly (avoids waiting out a real subprocess timeout) and
    confirm _send_scan_failure_email actually fires for the timeout branch
    too, by patching shared._send_email (the transport) to capture the call —
    patching the transport directly rather than relying on EMAIL_DRY_RUN's
    logging keeps this a positive assertion that a send was attempted, not
    just that no exception was raised."""
    import shared

    resp, scan_id = _submit_scan(client, devices_csv, email="scan-timeout@test.example")
    assert resp.status_code == 303
    otp = _otp_for(scan_id)
    assert otp

    monkeypatch.setattr(
        shared, "run_report_job",
        lambda *a, **kw: shared.ReportJobOutcome(status="timeout"),
    )
    email_calls = []
    monkeypatch.setattr(
        shared, "_send_email",
        lambda *a, **kw: email_calls.append((a, kw)) or True,
    )

    r = client.post(f"/public/scan/verify/{scan_id}", data={"otp": otp}, follow_redirects=False)
    assert r.status_code == 303

    status = _wait_status(client, scan_id, want="timeout")
    assert status and status["status"] == "timeout", status

    assert len(email_calls) == 1, "timeout path must send the backup failure email"
    args, kwargs = email_calls[0]
    assert args[0] == "scan-timeout@test.example"
    assert "could not be completed" in args[1]


def test_upload_job_hard_kills_report_generation_past_timeout(client, monkeypatch, db_conn):
    """PAT-1177: report generation now runs in a genuinely killable
    multiprocessing.Process (shared.run_report_job), not an unkillable
    thread. The old PAT-1173 model could only bound how long the request
    handler WAITED on a stuck worker — the worker itself kept running
    forever in the background. Prove the new model actually stops it:

    1. the job lands 'timeout' quickly — close to UPLOAD_JOB_TIMEOUT_SECONDS
       (plus process spawn/kill overhead), nowhere near the full sleep the
       generator was told to do. That proves the supervising thread isn't
       just waiting the whole thing out.
    2. the child process was genuinely terminated, not abandoned: this test
       waits well past when an un-killed child would have woken up on its
       own and confirms it never wrote its post-sleep sentinel file. An
       orphaned/merely-abandoned worker (the old model) would eventually
       write it; a hard-killed one never does.
    3. no email is sent for the timed-out job and no report is left on disk.

    Uses _hardkill_targets.sleep_then_touch_sentinel — a real module-level
    function with a real time.sleep(), because run_report_job's target
    crosses a process boundary (spawn on this macOS test runner) and cannot
    be a closure/Event-based fake the way an in-thread test could use.
    """
    import router
    from _hardkill_targets import sleep_then_touch_sentinel

    timeout_seconds = 0.4
    sleep_seconds = 3.0
    monkeypatch.setattr(router, "UPLOAD_JOB_TIMEOUT_SECONDS", timeout_seconds)
    monkeypatch.setattr(router, "generate_devices_report", sleep_then_touch_sentinel)

    email_calls = []
    monkeypatch.setattr(
        router, "_send_email",
        lambda *a, **kw: email_calls.append((a, kw)) or True,
    )

    email = "hardkill@test.example"
    csv_bytes = (
        b"Device name,OS,OS version,Compliance,Last check-in\n"
        b"UP-PC-01,Windows,10.0.19045.0,Compliant,2026-07-01T09:00:00Z\n"
    )

    start = time.monotonic()
    r = client.post(
        "/public/intune-upload",
        data={"email": email, "cf-turnstile-response": "x"},
        files={"file": ("devices.csv", csv_bytes, "text/csv")},
    )
    assert r.status_code == 200

    row = _wait_upload_row(db_conn, email, {"timeout"}, timeout=10.0)
    elapsed = time.monotonic() - start

    assert row is not None, "upload job never reached a terminal state"
    assert row["status"] == "timeout"
    assert row["error"], "timed-out job must record a human-readable reason"
    assert str(timeout_seconds) in row["error"] or "limit" in row["error"].lower()
    assert row["report_path"] is None

    # (1) proves the supervisor did not sit through the full sleep.
    assert elapsed < sleep_seconds, (
        f"elapsed {elapsed:.2f}s should be well under the {sleep_seconds}s "
        f"sleep the child was told to do — reaching 'timeout' this late "
        f"suggests the job was waited out rather than hard-killed"
    )

    # (2) proves the child was genuinely killed, not merely abandoned: wait
    # past when an un-killed child would have woken up and written its
    # sentinel, then confirm it never did.
    remaining = sleep_seconds - elapsed
    if remaining > 0:
        time.sleep(remaining)
    time.sleep(1.0)  # margin for process teardown / filesystem visibility

    import shared

    sentinels = list(shared.PUBLIC_REPORTS_DIR.glob(f"*_{row['id']}.docx.sentinel"))
    assert sentinels == [], (
        "the report-generation child wrote its post-sleep sentinel file, "
        "meaning it kept running after the timeout instead of being "
        "hard-killed"
    )

    assert email_calls == [], "a timed-out job must never send the delivery email"


def test_upload_job_hard_kill_is_not_timing_flaky(client, monkeypatch, db_conn):
    """Brief-mandated repeat run of the hard-kill timing assertion (not just
    a single lucky pass): three independent uploads, each bound to a tight
    timeout while the generator sleeps far longer, must all land 'timeout'
    well before their sleep would have elapsed."""
    import router
    from _hardkill_targets import sleep_then_touch_sentinel

    timeout_seconds = 0.3
    sleep_seconds = 2.0
    monkeypatch.setattr(router, "UPLOAD_JOB_TIMEOUT_SECONDS", timeout_seconds)
    monkeypatch.setattr(router, "generate_devices_report", sleep_then_touch_sentinel)
    monkeypatch.setattr(router, "_send_email", lambda *a, **kw: True)

    csv_bytes = (
        b"Device name,OS,OS version,Compliance,Last check-in\n"
        b"UP-PC-01,Windows,10.0.19045.0,Compliant,2026-07-01T09:00:00Z\n"
    )

    for i in range(3):
        email = f"hardkill-repeat-{i}@test.example"
        start = time.monotonic()
        r = client.post(
            "/public/intune-upload",
            data={"email": email, "cf-turnstile-response": "x"},
            files={"file": ("devices.csv", csv_bytes, "text/csv")},
        )
        assert r.status_code == 200
        row = _wait_upload_row(db_conn, email, {"timeout"}, timeout=10.0)
        elapsed = time.monotonic() - start
        assert row is not None and row["status"] == "timeout", f"run {i} did not time out"
        assert elapsed < sleep_seconds, (
            f"run {i}: elapsed {elapsed:.2f}s too close to sleep_seconds"
        )


def test_upload_refused_when_concurrency_saturated(client, monkeypatch, db_conn):
    """PAT-1177: MAX_CONCURRENT_SCAN_JOBS is a fail-closed cap enforced via a
    BoundedSemaphore acquired (non-blocking) at the request handler, BEFORE
    any DB row is created. With the cap exhausted, a new upload must be
    refused immediately with a friendly message and must create no
    public_uploads row at all — not 'processing', not anything."""
    import threading as threading_mod

    import shared

    monkeypatch.setattr(shared, "_SCAN_JOB_SEMAPHORE", threading_mod.BoundedSemaphore(1))
    assert shared.try_acquire_scan_slot() is True  # consume the only slot

    email = "saturated@test.example"
    csv_bytes = (
        b"Device name,OS,OS version,Compliance,Last check-in\n"
        b"UP-PC-01,Windows,10.0.19045.0,Compliant,2026-07-01T09:00:00Z\n"
    )
    r = client.post(
        "/public/intune-upload",
        data={"email": email, "cf-turnstile-response": "x"},
        files={"file": ("devices.csv", csv_bytes, "text/csv")},
    )
    assert r.status_code == 503
    assert "try again" in r.text.lower()

    row = db_conn.execute(
        "SELECT * FROM public_uploads WHERE email=?", (email,),
    ).fetchone()
    assert row is None, "a saturated request must not create any DB row"

    shared.release_scan_slot()


def test_public_scan_refused_when_concurrency_saturated(client, devices_csv, monkeypatch, db_conn):
    """Same fail-closed cap, applied to the public CVE-scan job start (which
    happens at OTP verification, not at /public/scan submission — the scan
    row already exists as 'pending_verify' by then). With the cap
    exhausted, verifying a correct OTP must NOT flip the row to 'verified'
    or start the job; the OTP stays live so the user can retry once a slot
    is free."""
    import threading as threading_mod

    import shared

    resp, scan_id = _submit_scan(client, devices_csv, email="scan-saturated@test.example")
    assert resp.status_code == 303
    otp = _otp_for(scan_id)
    assert otp

    monkeypatch.setattr(shared, "_SCAN_JOB_SEMAPHORE", threading_mod.BoundedSemaphore(1))
    assert shared.try_acquire_scan_slot() is True  # consume the only slot

    r = client.post(f"/public/scan/verify/{scan_id}", data={"otp": otp}, follow_redirects=False)
    assert r.status_code == 503
    assert "try again" in r.text.lower()

    row = db_conn.execute(
        "SELECT status FROM public_scans WHERE id=?", (scan_id,),
    ).fetchone()
    assert row["status"] == "pending_verify", (
        "a saturated verify must not advance the row to 'verified' / start the job"
    )

    shared.release_scan_slot()


def test_upload_job_that_raises_lands_in_status_error_not_processing(client, monkeypatch, db_conn):
    """Regression for PAT-1173: any exception in the background upload worker
    must land the row in status='error' with the reason recorded, never leave
    it 'processing'. Updated for PAT-1177: the exception is now raised
    INSIDE the report-generation subprocess and comes back to the parent as
    a ReportJobOutcome(status="error", ...) rather than propagating directly
    — this pins that the reason still makes it into the DB row."""
    import router
    from _hardkill_targets import raise_synthetic_failure

    monkeypatch.setattr(router, "generate_devices_report", raise_synthetic_failure)

    email = "job-error@test.example"
    csv_bytes = (
        b"Device name,OS,OS version,Compliance,Last check-in\n"
        b"UP-PC-01,Windows,10.0.19045.0,Compliant,2026-07-01T09:00:00Z\n"
    )
    r = client.post(
        "/public/intune-upload",
        data={"email": email, "cf-turnstile-response": "x"},
        files={"file": ("devices.csv", csv_bytes, "text/csv")},
    )
    assert r.status_code == 200

    row = _wait_upload_row(db_conn, email, {"error"}, timeout=5.0)
    assert row is not None, "upload job never reached a terminal state"
    assert row["status"] == "error"
    assert "synthetic failure" in row["error"]
    assert row["report_path"] is None


def test_upload_job_with_failed_email_delivery_lands_in_status_error(client, monkeypatch, db_conn):
    """Regression: _send_email never raises, it returns False on delivery
    failure. Before this fix that return value was ignored, so a failed send
    left the row 'done' with a report_path the user never actually received
    (this funnel has no download route) — a silent failure indistinguishable
    from success anywhere in Linear or the DB. A failed send must flip the
    already-claimed row to 'error', clear report_path, and remove the
    undelivered .docx from disk rather than leaving it unreferenced."""
    import os

    import router

    monkeypatch.setattr(router, "_send_email", lambda *a, **kw: False)

    discarded = []
    real_discard_orphaned_report = router._discard_orphaned_report

    def _tracking_discard(path):
        discarded.append(path)
        real_discard_orphaned_report(path)

    monkeypatch.setattr(router, "_discard_orphaned_report", _tracking_discard)

    email = "delivery-fail@test.example"
    csv_bytes = (
        b"Device name,OS,OS version,Compliance,Last check-in\n"
        b"UP-PC-01,Windows,10.0.19045.0,Compliant,2026-07-01T09:00:00Z\n"
    )
    r = client.post(
        "/public/intune-upload",
        data={"email": email, "cf-turnstile-response": "x"},
        files={"file": ("devices.csv", csv_bytes, "text/csv")},
    )
    assert r.status_code == 200

    row = _wait_upload_row(db_conn, email, {"error"}, timeout=5.0)
    assert row is not None, "upload job never reached a terminal state"
    assert row["status"] == "error"
    assert row["error"] == "email delivery failed"
    assert row["report_path"] is None, (
        "report_path must be cleared once delivery is known to have failed, "
        "not left pointing at a report the user never received"
    )

    assert len(discarded) == 1, "the undelivered report must be discarded exactly once"
    assert not os.path.exists(discarded[0]), (
        "the undelivered report must actually be removed from disk"
    )


def _wait_upload_row(db_conn, email, want_statuses, timeout=5.0):
    """Poll public_uploads for the row for `email` until its status is one of
    `want_statuses`, or the timeout elapses. Returns the last row seen (which
    may still be 'processing' if the wait timed out)."""
    deadline = time.time() + timeout
    row = None
    while time.time() < deadline:
        row = db_conn.execute(
            "SELECT * FROM public_uploads WHERE email=? ORDER BY created_at DESC LIMIT 1",
            (email,),
        ).fetchone()
        if row is not None and row["status"] in want_statuses:
            return row
        time.sleep(0.02)
    return row


# ── pricing / design-partner enquiry form (PAT-1978) ─────────────────────────
def _submit_pricing_enquiry(client, **overrides):
    data = {
        "name": "Jo Bloggs",
        "email": "jo@acme.example",
        "organisation": "Acme Ltd",
        "devices": "120",
        "mix": "Mostly Windows",
        "tool": "Intune",
        "partner": "on",
        "website": "",  # honeypot, empty for a genuine submission
    }
    data.update(overrides)
    return client.post("/public/pricing-enquiry", data=data)


def test_pricing_enquiry_valid_submission_delivers_and_succeeds(client, monkeypatch):
    import router

    calls = []

    def _record(to_email, subject, html, text, attachment_path=None,
                attachment_name=None, bcc=None):
        calls.append({"to": to_email, "subject": subject, "text": text})
        return True

    monkeypatch.setattr(router, "_graph_send_mail", _record)

    resp = _submit_pricing_enquiry(client)
    assert resp.status_code == 200
    assert "could not" not in resp.text.lower()
    assert "thanks" in resp.text.lower()

    assert len(calls) == 1
    assert calls[0]["to"] == "hello@patched.im"
    assert "Acme Ltd" in calls[0]["subject"]
    assert "Design partner enquiry" in calls[0]["subject"]  # partner="on" above
    assert "jo@acme.example" in calls[0]["text"]
    assert "120" in calls[0]["text"]


def test_pricing_enquiry_missing_required_field_rejected(client, monkeypatch):
    import router

    monkeypatch.setattr(router, "_graph_send_mail", lambda *a, **kw: True)

    # organisation omitted entirely -> FastAPI 422s it before our handler runs.
    resp = client.post(
        "/public/pricing-enquiry",
        data={"name": "Jo Bloggs", "email": "jo@acme.example"},
    )
    assert resp.status_code == 422

    # email present but not a valid address -> our own validation rejects it
    # with a plain response, not a generic success page.
    resp2 = _submit_pricing_enquiry(client, email="not-an-email")
    assert resp2.status_code == 400
    assert "thanks" not in resp2.text.lower()
    assert "valid work email" in resp2.text.lower()


def test_pricing_enquiry_honeypot_is_invisible_to_the_bot(client, monkeypatch):
    """A filled honeypot must look like an ordinary success to the sender,
    but must never actually deliver, and must never count against the rate
    limiter (checked via a second, genuine submission from the same email
    succeeding right after)."""
    import router
    import shared

    calls = []
    monkeypatch.setattr(router, "_graph_send_mail",
                        lambda *a, **kw: calls.append(1) or True)

    resp = _submit_pricing_enquiry(
        client, email="honeypot@test.example", website="https://spam.example",
    )
    assert resp.status_code == 200
    assert "could not" not in resp.text.lower()  # apparent success
    assert calls == [], "a honeypot hit must never actually deliver"

    with shared.get_db() as db:
        row = db.execute(
            "SELECT COUNT(*) FROM public_pricing_enquiries WHERE email=?",
            ("honeypot@test.example",),
        ).fetchone()
    assert row[0] == 0, "a honeypot hit must not consume rate-limit budget"


def test_pricing_enquiry_rate_limit_is_visible_not_silent(client, monkeypatch):
    import router

    monkeypatch.setattr(router, "_graph_send_mail", lambda *a, **kw: True)

    email = "rl-pricing@test.example"
    for _ in range(3):  # PRICING_RATE_EMAIL_MAX default
        resp = _submit_pricing_enquiry(client, email=email)
        assert resp.status_code == 200, resp.text

    resp = _submit_pricing_enquiry(client, email=email)
    assert resp.status_code == 429
    assert "too many enquiries" in resp.text.lower()


def test_pricing_enquiry_delivery_failure_is_visible_not_silent_success(client, monkeypatch):
    """The ticket's named acceptance criterion: a failed _graph_send_mail
    must produce a response that plainly tells the sender delivery failed,
    never a generic success page."""
    import router

    monkeypatch.setattr(router, "_graph_send_mail", lambda *a, **kw: False)

    resp = _submit_pricing_enquiry(client, email="delivery-fail@test.example")
    assert resp.status_code == 502
    assert "thanks" not in resp.text.lower()
    assert "could not send" in resp.text.lower()

    with shared.get_db() as db:
        row = db.execute(
            "SELECT delivered_at FROM public_pricing_enquiries WHERE email=?",
            ("delivery-fail@test.example",),
        ).fetchone()
    assert row is not None, "the attempt must still be recorded for rate-limiting"
    assert row["delivered_at"] is None, "a failed send must not be marked delivered"
