"""
Tests for PAT-572: CVE-upload-only scan path, end-to-end.

Context: PAT-572 removed the Microsoft Graph tenant-scan pipeline, leaving
scanner.py / POST /api/scan/upload as the only CVE scan path. Confirmed via
grep before writing this file — no existing test imported `scanner` or hit
`/api/scan/upload`; this path had zero coverage.

Drives the real flow: POST /api/scan/upload with an Intune devices CSV
(reusing the existing tests/fixtures/devices_valid.csv, which already
matches scanner.py's `_parse_devices_csv` header aliases) -> poll
GET /api/scan/{job_id}/status to completion -> assert the scan matched a
CVE and a .docx report was written under REPORTS_DIR.

scanner._scan()'s local NVD dataset lives at a path hardcoded relative to
scanner.py's own file location (`os.path.join(os.path.dirname(__file__),
"nvd.db")`) rather than an injectable parameter, so this file seeds a tiny
synthetic nvd.db there for the duration of the test and restores whatever
was there before (nvd.db is gitignored and not expected to exist in a
fresh checkout, but a dev machine's real dataset is not something a test
should ever clobber).
"""
import json
import os
import sqlite3
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard
import scanner
from fastapi.testclient import TestClient

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
BEARER = {"Authorization": "Bearer test-key"}


def _session_cookie(email="owner@patched.im", ttl=3600):
    """Build a Cookie header for a freshly-minted session. PAT-1217:
    /api/scan/{job_id}/download checks patched_session, not Bearer — see
    main.py's _require_dashboard_session and AGENTS.md's "don't re-enable
    bearer auth on the /download path"."""
    tok = dashboard._session_encode(email, int(time.time()) + ttl)
    return {"Cookie": f"{dashboard.SESSION_COOKIE}={tok}"}

# LAPTOP-ALICE in devices_valid.csv is Windows build 10.0.26100.2161, which
# scanner._os_cpe() maps to cpe:2.3:o:microsoft:windows_11:24H2:... . The
# base CPE prefix scanner._scan() looks up in nvd_cves is the first 5
# colon-separated fields.
WIN11_CPE_PREFIX = "cpe:2.3:o:microsoft:windows_11"


@pytest.fixture
def nvd_fixture_db():
    """Seed a tiny nvd.db (one synthetic CVE, matched via a wildcard-version
    CPE criteria so it hits every Windows 11 device regardless of build)
    at scanner.py's hardcoded db path. Backs up / restores any real nvd.db
    that happens to exist on the machine running the test."""
    db_path = os.path.join(os.path.dirname(scanner.__file__), "nvd.db")
    backup_path = db_path + ".pat572-test-backup"
    had_existing = os.path.exists(db_path)
    if had_existing:
        os.rename(db_path, backup_path)

    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE nvd_cves (cve_id TEXT, cpe_prefix TEXT, description TEXT, "
        "base_score REAL, severity TEXT, published TEXT, configurations TEXT, "
        "PRIMARY KEY(cve_id, cpe_prefix))"
    )
    configurations = json.dumps([
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {
                            # version "*" — version_match() treats this as an
                            # unconditional match once vendor/product agree.
                            "criteria": f"{WIN11_CPE_PREFIX}:*:*:*:*:*:*:*:*",
                            "vulnerable": True,
                        }
                    ]
                }
            ]
        }
    ])
    conn.execute(
        "INSERT INTO nvd_cves VALUES (?,?,?,?,?,?,?)",
        (
            "CVE-2026-99999",
            WIN11_CPE_PREFIX,
            "Synthetic test CVE seeded for PAT-572 upload-scan coverage.",
            9.8,
            "CRITICAL",
            "2026-07-01",
            configurations,
        ),
    )
    conn.commit()
    conn.close()

    yield db_path

    os.remove(db_path)
    if had_existing:
        os.rename(backup_path, db_path)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    monkeypatch.setattr(dashboard, "REPORTS_DIR", reports_dir)
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


def _poll_until_not_running(get_status, description, max_wait=5.0, interval=0.05):
    """Poll `get_status()` (a zero-arg callable returning a status string)
    until it reports something other than 'running', bounded so a genuine
    hang fails loudly instead of sleeping-and-hoping or hanging CI.

    Shared by every poller below PAT-1343: the upload-scan background job
    (main.py's `start_upload_scan`) writes its completion in two separate
    places that are NOT updated atomically — the in-memory `JOBS[job_id]`
    dict (read by GET /api/scan/{job_id}/status) is flipped to 'complete'
    first, and only afterwards does the same background thread UPDATE the
    `scans` row in the database. Polling one of those stores until it
    leaves 'running' says nothing about the other one's state at that
    instant. Each assertion in this file that depends on a background-job
    result must poll *the specific store it is about to read*, not a
    different one presumed to be in sync.
    """
    deadline = time.monotonic() + max_wait
    last_status = None
    while time.monotonic() < deadline:
        last_status = get_status()
        if last_status != "running":
            return last_status
        time.sleep(interval)
    pytest.fail(
        f"{description} stuck on status={last_status!r} for over "
        f"{max_wait:.1f}s (never left 'running')"
    )


def _poll_until_complete(client, job_id, max_wait=5.0, interval=0.05):
    """Poll GET /api/scan/{job_id}/status (the JOBS-dict-backed view) until
    status leaves 'running'. Returns the final status body."""
    body = {}

    def _get():
        nonlocal body
        r = client.get(f"/api/scan/{job_id}/status", headers=BEARER)
        assert r.status_code == 200
        body = r.json()
        return body["status"]

    _poll_until_not_running(
        _get, f"scan job {job_id} API status (/status endpoint)", max_wait, interval
    )
    return body


def _poll_db_row_complete(dashboard_module, job_id, max_wait=5.0, interval=0.05):
    """Poll the `scans` table row (the actual source of truth for
    report_path/total_devices/total_cves) until its own status column
    leaves 'running'. This is deliberately a SEPARATE poll from
    `_poll_until_complete` above — see that function's docstring for why
    polling the API status first does not prove the DB row is done too."""
    row = {}

    def _get():
        nonlocal row
        with dashboard_module.get_db() as db:
            row = db.execute(
                "SELECT status, total_devices, total_cves, report_path "
                "FROM scans WHERE id=?",
                (job_id,),
            ).fetchone()
        return row["status"]

    _poll_until_not_running(
        _get, f"scan job {job_id} DB row status (scans table)", max_wait, interval
    )
    return row


class TestUploadScanEndToEnd:
    def test_upload_scan_matches_cve_and_produces_docx_report(self, client, nvd_fixture_db):
        with open(os.path.join(FIXTURES, "devices_valid.csv"), "rb") as devices_f:
            resp = client.post(
                "/api/scan/upload",
                headers=BEARER,
                data={"company": "Acme Test Co"},
                files={"devices_file": ("devices.csv", devices_f, "text/csv")},
            )
        assert resp.status_code == 200, resp.text
        job_id = resp.json()["job_id"]
        assert job_id

        status = _poll_until_complete(client, job_id)
        assert status["status"] == "complete", (
            f"expected scan to complete, got {status['status']!r}: {status['error']}"
        )
        assert status["progress"] == 100

        # ── The scan actually matched the seeded CVE, not just "ran" ──
        # PAT-1343: poll the DB row itself rather than trusting that the
        # /status poll above proves this row is done too — see
        # _poll_until_not_running's docstring. This is the exact race that
        # made PR #394 (docs-only, main green) fail on 2026-08-13: the
        # /status poll saw 'complete' from JOBS before the background
        # thread's `UPDATE scans SET status='complete', ...` had committed.
        row = _poll_db_row_complete(dashboard, job_id)
        assert row is not None
        assert row["status"] == "complete"
        assert row["total_devices"] > 0
        assert row["total_cves"] > 0, "expected the seeded CVE-2026-99999 to be matched"

        report_path = row["report_path"]
        assert report_path, "scans.report_path should be set on completion"
        assert os.path.exists(report_path), f"report file missing on disk: {report_path}"
        assert report_path.endswith(".docx")
        assert os.path.getsize(report_path) > 0

        # ── Download route serves the same file ──
        # PAT-1217: this route checks patched_session, not Bearer (AGENTS.md:
        # "don't re-enable bearer auth on the /download path") — a session
        # cookie is required even though the rest of this test authenticates
        # with BEARER for the /api/scan/upload and /status calls.
        dl = client.get(f"/api/scan/{job_id}/download", headers=_session_cookie())
        assert dl.status_code == 200
        assert dl.headers["content-type"] == (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        assert len(dl.content) > 0

        # Bearer alone must NOT work here (PAT-1217) — regression coverage for
        # the exact mistake this ticket fixed: a download route silently
        # trusting a credential it never validated.
        dl_bearer_only = client.get(f"/api/scan/{job_id}/download", headers=BEARER)
        assert dl_bearer_only.status_code == 401

        # No credential at all must also 401 — the original hole.
        dl_no_auth = client.get(f"/api/scan/{job_id}/download")
        assert dl_no_auth.status_code == 401

        # A CF-Access-authenticated caller with no patched_session cookie must
        # ALSO 401 — deliberate, documented in AGENTS.md's /download section.
        # This is the known tradeoff of the fix (a fresh/bookmarked download
        # link requires visiting /console/{rev} once first) — asserted here so
        # a future change can't silently start trusting
        # CF-Access-Authenticated-User-Email as a standalone credential
        # without that being a conscious decision: that header is used
        # elsewhere in this file only as an actor label on routes the
        # Bearer/session middleware already gated, never as the sole gate.
        dl_cf_header_only = client.get(
            f"/api/scan/{job_id}/download",
            headers={"CF-Access-Authenticated-User-Email": "owner@patched.im"},
        )
        assert dl_cf_header_only.status_code == 401

    def test_upload_scan_requires_bearer_auth(self, client):
        with open(os.path.join(FIXTURES, "devices_valid.csv"), "rb") as devices_f:
            resp = client.post(
                "/api/scan/upload",
                data={"company": "No Auth Co"},
                files={"devices_file": ("devices.csv", devices_f, "text/csv")},
            )
        assert resp.status_code == 401

    def test_upload_scan_requires_devices_file(self, client):
        resp = client.post(
            "/api/scan/upload",
            headers=BEARER,
            data={"company": "Missing File Co"},
        )
        # FastAPI 422s on a missing required File(...) param before the
        # handler body ever runs.
        assert resp.status_code == 422
