"""PAT-2564: retire both public creation funnels before request processing.

Startup configuration must explicitly enable the legacy funnel. Existing token
links are a separate contract and continue to work while new work is disabled.
"""

import importlib
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, Mock

import pytest
import shared
from fastapi.testclient import TestClient
from starlette.datastructures import UploadFile
from starlette.requests import Request

DISABLED_VALUES = [None, "false", "", "garbage", "truthy", "2"]
CREATION_ROUTES = [
    ("GET", "/public/scan", None),
    ("POST", "/public/scan", "devices_file"),
    ("POST", "/public/scan", "devices_file_with_apps"),
    ("GET", "/public/scan/verify/pending", None),
    ("POST", "/public/scan/verify/pending", None),
    ("GET", "/public/intune-instructions", None),
    ("GET", "/public/intune-upload", None),
    ("POST", "/public/intune-upload", "devices"),
    ("POST", "/public/intune-upload", "apps"),
]


@pytest.fixture(autouse=True)
def _restore_startup_config(monkeypatch):
    yield
    # Restore env and patched functions before refreshing startup bindings.
    # Other scan tests opt in through conftest and must see that setting again.
    monkeypatch.undo()
    import app
    import router

    importlib.reload(shared)
    importlib.reload(router)
    importlib.reload(app)


def _configured_client(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("PUBLIC_SCAN_ENABLED", raising=False)
    else:
        monkeypatch.setenv("PUBLIC_SCAN_ENABLED", value)
    # Config is read at process startup, just like the existing service config.
    # Reload dependants so imported config bindings cannot mask the env change.
    import app
    import router

    importlib.reload(shared)
    importlib.reload(router)
    importlib.reload(app)
    body_reads = []

    async def observed_app(scope, receive, send):
        async def observed_receive():
            message = await receive()
            if message["type"] == "http.request":
                body_reads.append(message)
            return message

        await app.app(scope, observed_receive, send)

    client = TestClient(observed_app, raise_server_exceptions=False)
    client.input_body_reads = body_reads
    return client


def _seed_scan(db_conn, *, status="pending_verify", report_path=None):
    now = datetime.now(UTC)
    db_conn.execute(
        "INSERT INTO public_scans "
        "(id,email,company,status,otp_code,otp_expires_at,download_token,"
        "delete_token,report_path,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("pending", "existing@test.example", "Existing estate", status,
         "111111", (now + timedelta(minutes=15)).isoformat(),
         "existing-report", "existing-delete", report_path, now.isoformat()),
    )
    db_conn.commit()


def _snapshot(db_conn):
    return {
        table: [tuple(row) for row in db_conn.execute(f"SELECT * FROM {table}")]
        for table in ("public_scans", "public_uploads")
    }


def _submission(kind, devices_csv):
    data = {"company": "Example", "email": "new@test.example",
            "authorised": "yes", "cf-turnstile-response": "x", "otp": "111111"}
    if kind in ("devices_file", "devices_file_with_apps"):
        files = {"devices_file": ("devices.csv", devices_csv, "text/csv")}
        if kind.endswith("with_apps"):
            files["apps_file"] = ("apps.json", b"[]", "application/json")
    elif kind == "devices":
        files = {"file": ("devices.csv", devices_csv, "text/csv")}
    elif kind == "apps":
        content = b"Application name,Application version,Device count\nExample,1,1\n"
        files = {"file": ("apps.csv", content, "text/csv")}
    else:
        files = None
    return data, files


@pytest.mark.parametrize("value", DISABLED_VALUES)
@pytest.mark.parametrize("path_variant", ["canonical", "trailing_slash", "encoded_slash"])
@pytest.mark.parametrize("method,path,kind", CREATION_ROUTES)
def test_disabled_creation_is_refused_before_body_or_side_effects(
    monkeypatch, db_conn, devices_csv, value, method, path, kind, path_variant,
):
    client = _configured_client(monkeypatch, value)
    _seed_scan(db_conn)
    before = _snapshot(db_conn)
    files_before = sorted(str(p) for p in shared.STATE_DIR.rglob("*"))
    import router

    traps = []
    for owner, name in ((Request, "form"), (Request, "body"),
                        (Request, "stream"), (UploadFile, "read")):
        trap = AsyncMock(side_effect=AssertionError(f"disabled request reached {name}"))
        monkeypatch.setattr(owner, name, trap)
        traps.append(trap)
    for name in ("get_db", "parse_csv_safe", "detect_csv_type",
                 "parse_devices_rows", "parse_apps_rows", "run_report_job",
                 "_run_public_scan", "_send_email", "_graph_send_mail",
                 "_verify_turnstile", "try_acquire_scan_slot"):
        if hasattr(router, name):
            trap = Mock(side_effect=AssertionError(f"disabled request reached {name}"))
            monkeypatch.setattr(router, name, trap)
            traps.append(trap)
    if path_variant == "trailing_slash":
        path += "/"
    elif path_variant == "encoded_slash":
        path = path.replace("/public/", "/public%2F", 1)
    data, files = _submission(kind, devices_csv)
    response = client.request(method, path, data=data if method == "POST" else None,
                              files=files, follow_redirects=False)
    assert all(trap.call_count == 0 for trap in traps), "disabled route processed input or work"
    assert client.input_body_reads == [], "disabled route consumed the ASGI request body"
    assert response.status_code == 503, response.text
    assert response.headers.get("cache-control") == "no-store"
    assert "not currently offered" in response.text.lower()
    assert "https://patched.im" in response.text
    assert "<form" not in response.text.lower()
    assert _snapshot(db_conn) == before
    assert sorted(str(p) for p in shared.STATE_DIR.rglob("*")) == files_before


@pytest.mark.parametrize("value", DISABLED_VALUES)
def test_existing_report_status_done_and_delete_links_survive_disabled_funnel(
    monkeypatch, db_conn, tmp_path, value,
):
    client = _configured_client(monkeypatch, value)
    report = shared.PUBLIC_REPORTS_DIR / "Patched_CVE_existing_pending.docx"
    report.write_bytes(b"existing report")
    _seed_scan(db_conn, status="complete", report_path=str(report))
    assert client.get("/public/scan/done/pending").status_code == 200
    status = client.get("/public/scan/status/pending")
    assert status.status_code == 200
    assert status.json()["download_url"] == "/public/scan/r/existing-report"
    download = client.get("/public/scan/r/existing-report")
    assert download.status_code == 200
    assert download.content == b"existing report"
    assert client.get("/public/scan/d/existing-delete").status_code == 200
    deleted = client.post("/public/scan/d/existing-delete")
    assert deleted.status_code == 200
    assert not report.exists()
    assert client.get("/public/scan/r/existing-report").status_code == 404
    assert client.get("/public/scan/status/pending").status_code == 404


@pytest.mark.parametrize("kind", ["devices_file", "devices_file_with_apps"])
def test_explicit_true_preserves_scan_submission_and_otp(monkeypatch, db_conn, devices_csv, kind):
    client = _configured_client(monkeypatch, "true")
    import router

    thread = Mock()
    monkeypatch.setattr(router.threading, "Thread", thread)
    assert client.get("/public/scan").status_code == 200
    data, files = _submission(kind, devices_csv)
    response = client.post("/public/scan", data=data, files=files, follow_redirects=False)
    assert response.status_code == 303, response.text
    verify_path = response.headers["location"]
    assert client.get(verify_path).status_code == 200
    row = db_conn.execute("SELECT * FROM public_scans").fetchone()
    verified = client.post(verify_path, data={"otp": row["otp_code"]}, follow_redirects=False)
    assert verified.status_code == 303
    assert db_conn.execute("SELECT status FROM public_scans").fetchone()[0] == "verified"
    thread.return_value.start.assert_called_once()
    router.release_scan_slot()


@pytest.mark.parametrize("kind", ["devices", "apps"])
def test_explicit_true_preserves_intune_creation(monkeypatch, db_conn, devices_csv, kind):
    client = _configured_client(monkeypatch, "true")
    import router

    thread = Mock()
    monkeypatch.setattr(router.threading, "Thread", thread)
    assert client.get("/public/intune-instructions").status_code == 200
    assert client.get("/public/intune-upload").status_code == 200
    data, files = _submission(kind, devices_csv)
    response = client.post("/public/intune-upload", data=data, files=files)
    assert response.status_code == 200, response.text
    assert db_conn.execute("SELECT status FROM public_uploads").fetchone()[0] == "processing"
    thread.return_value.start.assert_called_once()
    router.release_scan_slot()
