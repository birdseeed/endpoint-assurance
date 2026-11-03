"""Owned, offline PAT-1966 fixtures; no collectors, startup or production DB."""
import copy
import importlib
import json
import os
import shutil
import sqlite3
import sys
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROXY = "/admin/service-exceptions/proxy"
CATEGORIES = [
    ("outgoing_email", "Outgoing email"),
    ("scheduled_jobs", "Scheduled jobs"),
    ("customer_access", "Customer access setup"),
    ("device_reports", "Device reports"),
    ("assurance_processing", "Assurance processing"),
    ("vulnerability_data", "Vulnerability data updates"),
    ("reports", "Report generation and delivery"),
    ("backups", "Backups and restore tests"),
    ("server_health", "Server health"),
    ("version_checks", "Software version checks"),
    ("billing", "Billing connection"),
]


def assert_owner():
    # This only guards isolated test fixtures, never queue or source-write authority.
    owner_path = os.environ.get("QUEUE_RUN_TEST_OWNER_PATH")
    nonce = os.environ.get("QUEUE_RUN_TEST_OWNER_NONCE")
    if owner_path is None and nonce is None:
        return
    assert owner_path and nonce, "Both test owner environment values must be nonempty"
    try:
        actual_nonce = json.loads(Path(owner_path).read_text())["owner_nonce"]
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise AssertionError("Test owner record is unreadable or malformed") from exc
    assert actual_nonce == nonce, "Test owner nonce mismatch"


def stamp(hours=0):
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def feed(with_exceptions=True):
    now = stamp()
    body = {"observed_at": now, "coverage": "partial", "checks": [], "exceptions": []}
    for key, name in CATEGORIES:
        body["checks"].append({
            "id": key, "name": name, "explanation": "Purpose: " + name,
            "source": "Recorded " + key + " evidence", "scope": "patched-api-01 / " + name,
            "availability": "unavailable", "result": "unavailable", "checked_at": None,
            "last_success_at": None, "next_expected_at": None,
            "reason": "This source is not connected; no health conclusion is supported.",
            "next_action": "Inspect " + name + " evidence; do not start a job.",
        })
    for key in ("scheduled_jobs", "device_reports"):
        check = next(c for c in body["checks"] if c["id"] == key)
        check.update(availability="degraded", result="unknown", checked_at=now,
                     reason="Partial recorded evidence; wider coverage is unknown.")
    jobs = body["checks"][1]
    jobs["observations"] = [
        {"id": "health_signals_recompute", "scope": "health_signals_recompute",
         "result": "failed", "evidence_at": stamp(1), "last_success_at": stamp(25)},
        {"id": "api01_backup", "scope": "api01_backup", "result": "ok",
         "evidence_at": stamp(2), "last_success_at": stamp(2)},
    ]
    if with_exceptions:
        jobs["result"] = "failed"
        body["checks"][3]["result"] = "stale"
        body["exceptions"] = [
            {"id": "scheduled_jobs:health_signals_recompute", "check_id": "scheduled_jobs",
             "tenant_id": None, "scope": "health_signals_recompute", "since": None,
             "evidence_at": jobs["observations"][0]["evidence_at"],
             "reason": "Latest recorded job failed. The onset time is unknown.",
             "deep_link": "/console#automations"},
            {"id": "device_reports:tenant-alder", "check_id": "device_reports",
             "tenant_id": "tenant-alder", "scope": "Customer receipt / Alder fixture",
             "since": None, "evidence_at": stamp(40),
             "reason": "Customer receipt is stale. Expected population and onset are unknown.",
             "deep_link": "/console#ops"},
        ]
    else:
        jobs["observations"] = []
    return body


@contextmanager
def upstream(body=None, status=200, raw=None):
    state = {"body": copy.deepcopy(body if body is not None else feed()),
             "status": status, "raw": raw, "requests": []}
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["requests"].append((self.command, self.path))
            payload = state["raw"] if state["raw"] is not None else json.dumps(state["body"]).encode()
            self.send_response(state["status"])
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port), state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


@contextmanager
def isolated_app(tmp_path, monkeypatch, upstream_url):
    # Copy tracked Python only. Import-time mkdir writes into this owned copy.
    assert_owner()
    runtime = tmp_path / "app"
    runtime.mkdir()
    names = [p.stem for p in ROOT.glob("*.py")]
    for source in ROOT.glob("*.py"):
        assert_owner()
        shutil.copyfile(source, runtime / source.name)
    for directory in ("templates", "static"):
        assert_owner()
        (runtime / directory).symlink_to(ROOT / directory, target_is_directory=True)
    assert_owner()
    (runtime / "truth_manifest.yaml").symlink_to(ROOT / "truth_manifest.yaml")
    previous = {name: sys.modules.pop(name) for name in names if name in sys.modules}
    monkeypatch.syspath_prepend(str(runtime))
    monkeypatch.setenv("DASHBOARD_DB_PATH", str(tmp_path / "owned.db"))
    monkeypatch.delenv("DASHBOARD_STATE_DIR", raising=False)
    monkeypatch.setenv("PATCHED_API_INTERNAL", upstream_url)
    monkeypatch.setenv("DASHBOARD_API_KEY", "test-key")
    monkeypatch.setenv("ADMIN_API_TOKEN", "test-upstream-key")
    monkeypatch.setenv("EMAIL_DRY_RUN", "1")
    db_path = tmp_path / "owned.db"
    assert_owner()
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE check_statuses(name TEXT PRIMARY KEY,state TEXT,reason TEXT,evaluated_at TEXT)")
        db.execute("CREATE TABLE report_send_audit_log(id TEXT PRIMARY KEY,ts TEXT,actor_email TEXT,tenant_id TEXT,tenant_name TEXT,report_type TEXT,recipient TEXT,recipient_category TEXT,outcome TEXT,detail TEXT)")
    dashboard = importlib.import_module("main")
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@example.test"}))
    reads, forbidden = [], []
    def readonly_connection(path):
        assert Path(path).resolve() == db_path.resolve(), "non-owned DB access"
        conn = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        conn.set_trace_callback(reads.append)
        def authorise(action, arg1, arg2, db, trigger):
            if action in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE,
                          sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_DROP_TABLE, sqlite3.SQLITE_ALTER_TABLE):
                forbidden.append((action, arg1))
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        conn.set_authorizer(authorise)
        return conn
    monkeypatch.setattr(dashboard, "_open_db_connection", readonly_connection)
    def no_action(*args, **kwargs):
        forbidden.append("collector/provider/send/trigger")
        raise AssertionError("Read projection called an active collector/provider/send/trigger")
    for name in ("_send_email", "email_delivery_check", "check_report_schedules",
                 "check_trial_expiry_emails", "_run_email_delivery_check_tick", "scheduler_loop",
                 "fast_check_loop", "_cf_access_email_authorised"):
        monkeypatch.setattr(dashboard, name, no_action)
    try:
        yield dashboard, db_path, reads
    finally:
        for name in names:
            sys.modules.pop(name, None)
        sys.modules.update(previous)
        assert not forbidden, forbidden
