"""Test fixtures for the standalone scan service.

No network: Turnstile verification is skipped (TURNSTILE_SECRET unset +
TURNSTILE_DEV_BYPASS=1, PAT-893's explicit opt-out for local/test use — an
unset secret alone now fails closed), email is dry-run (EMAIL_DRY_RUN=1), and
the NVD dataset is a tiny hand-built SQLite with one known Windows-10 CVE row
so a scan produces a deterministic finding.

Environment is set at import time, BEFORE the app modules are imported, because
shared.py / scanner.py read their paths from the environment at import.
"""

import json
import os
import sqlite3
import socket
import sys
import tempfile
from pathlib import Path

import pytest

# ── Isolated state + NVD dataset, wired up before importing the app ──────────
_STATE_DIR = Path(tempfile.mkdtemp(prefix="scan-test-state-"))
_NVD_DB = _STATE_DIR / "nvd.db"

os.environ["SCAN_STATE_DIR"] = str(_STATE_DIR)
os.environ["SCAN_DB_DIR"] = str(_STATE_DIR / "db")
os.environ["NVD_DB_PATH"] = str(_NVD_DB)
os.environ["EMAIL_DRY_RUN"] = "1"
# Legacy funnel tests explicitly opt in; retirement tests cover default-off.
os.environ["PUBLIC_SCAN_ENABLED"] = "true"
os.environ["PUBLIC_BASE_URL"] = "https://scan.test"
os.environ.pop("TURNSTILE_SECRET", None)
os.environ["TURNSTILE_DEV_BYPASS"] = "1"  # PAT-893: explicit opt-out, skip captcha in tests
os.environ.pop("SENDGRID_API_KEY", None)
os.environ.pop("GRAPH_MAIL_TENANT_ID", None)

# The scan app is a flat module dir (deployed to /opt/patched-scan); put it on
# the path exactly as the systemd WorkingDirectory would.
SCAN_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCAN_DIR))

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _build_nvd_db(path: Path):
    """Minimal NVD dataset: one Windows-10 OS CVE that matches any windows_10
    version, so the fixture devices.csv (which has a Windows 10 22H2 device)
    yields exactly one deterministic OS finding."""
    configs = [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"}
    ]}]}]
    conn = sqlite3.connect(str(path))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS nvd_cves ("
        "cve_id TEXT, cpe_prefix TEXT, description TEXT, base_score REAL, "
        "severity TEXT, published TEXT, configurations TEXT, "
        "PRIMARY KEY(cve_id, cpe_prefix))"
    )
    conn.execute(
        "INSERT OR REPLACE INTO nvd_cves VALUES (?,?,?,?,?,?,?)",
        ("CVE-2099-0001", "cpe:2.3:o:microsoft:windows_10",
         "Test Windows 10 remote code execution.", 9.8, "CRITICAL",
         "2099-01-01", json.dumps(configs)),
    )
    conn.commit()
    conn.close()


_build_nvd_db(_NVD_DB)


@pytest.fixture(autouse=True)
def _block_outbound_sockets(monkeypatch):
    """Fail unexpected outbound traffic; in-process ASGI needs no TCP socket."""
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def guarded(original):
        def connect(sock, *args, **kwargs):
            if sock.family in (socket.AF_INET, socket.AF_INET6):
                raise AssertionError("Outbound network is forbidden in scan tests")
            return original(sock, *args, **kwargs)
        return connect

    monkeypatch.setattr(socket.socket, "connect", guarded(original_connect))
    monkeypatch.setattr(socket.socket, "connect_ex", guarded(original_connect_ex))


@pytest.fixture(autouse=True)
def _isolate_db():
    """Fresh, empty tables before every test so per-email/per-IP counters and
    prior rows never leak across tests (the state dir is session-scoped)."""
    import db as scan_db
    import shared

    scan_db.init_db()
    conn = sqlite3.connect(str(shared.DB_PATH))
    conn.execute("DELETE FROM public_scans")
    conn.execute("DELETE FROM public_scan_erasure_limits")
    conn.execute("DELETE FROM public_uploads")
    conn.execute("DELETE FROM public_pricing_enquiries")
    conn.execute("DELETE FROM waitlist_signups")
    conn.execute("DELETE FROM waitlist_attempts")
    conn.commit()
    conn.close()
    yield


@pytest.fixture
def client():
    """TestClient over the scan app, with the DB schema initialised.

    Imports are lazy so the environment above is applied before shared.py /
    scanner.py read their paths at import time."""
    import app as scan_app  # the FastAPI instance is scan_app.app
    import db as scan_db
    from fastapi.testclient import TestClient

    scan_db.init_db()
    return TestClient(scan_app.app, raise_server_exceptions=False)


@pytest.fixture
def devices_csv() -> bytes:
    return (FIXTURES / "devices.csv").read_bytes()


@pytest.fixture
def db_conn():
    """Direct connection to the scan DB for reading OTP codes etc."""
    import shared

    conn = sqlite3.connect(str(shared.DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()
