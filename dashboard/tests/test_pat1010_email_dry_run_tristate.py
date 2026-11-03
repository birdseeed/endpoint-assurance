"""
PAT-1010: EMAIL_DRY_RUN tri-state visibility.

Covers:
  * shared.email_delivery_status() distinguishes "dry_run" (EMAIL_DRY_RUN
    set), "unconfigured" (no mail provider set up), and "live" (a provider
    is configured and dry-run is off) from configuration alone (no network
    calls) -- the cheap signal a per-request caller can check instead of
    trusting _send_email()'s bare bool.
  * shared.email_delivery_check() goes further for the scheduler tick: when
    Graph is the active path it actually validates the credential via
    _graph_mail_token() (a real, cached OAuth request), so an
    invalid/expired credential is "degraded", not a false "ok".
  * _run_email_delivery_check_tick() records that into check_statuses as
    "email_delivery", and is wired into scheduler_loop().
  * Ordinary feature-email callers (e.g. the cert-digest tick, exercised via
    its real caller path, not just _send_email() directly) are unaffected:
    _send_email() still returns True under dry-run and normal bookkeeping
    still runs.
  * The retired SendGrid routes and configuration are absent; Graph is the
    only production sender.
  * Every durable-state write found to be gated on a bare _send_email() True
    that would otherwise be wrong under dry-run: trial-expiry (calls the
    platform's trial-notify API believing the customer was told), the
    scheduled + on-demand report-delivery log
    (rendered directly in the console's Reports > Delivery Log tab), the
    monthly/weekly report_schedule_sends period gate (marking it under
    dry-run would permanently skip that whole cadence period, not just
    delay it), and the Calendly initial-confirmation / follow-up checkmarks
    (rendered in the Leads tab).

  PAT-2249 removed the catalogue-hosting vendor outreach flow (PAT-960), so
  its dry-run coverage went with it.

  PAT-866 removed the public, unauthenticated /public/scan OTP funnel
  (public_router.py) from this repo -- it now lives at scan.patched.im
  (portal repo). The coverage that used to sit here for that funnel went
  with it.

Run with: pytest tests/test_pat1010_email_dry_run_tristate.py -v
"""

import inspect
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


BEARER = {"Authorization": "Bearer test-key"}


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()


class _FakeResp:
    def __init__(self, payload=None, status_code=200, text="", content=b"x"):
        self._payload = payload if payload is not None else {}
        self.status_code = status_code
        self.text = text
        self.content = content

    def json(self):
        return self._payload


def _status(name):
    with dashboard.get_db() as conn:
        return conn.execute(
            "SELECT name, state, reason, evaluated_at FROM check_statuses WHERE name=?",
            (name,),
        ).fetchone()


def _clear_delivery_config(monkeypatch):
    """Reset every shared.py var email_delivery_status()/email_delivery_check()
    read so each test starts from a known baseline instead of whatever
    happens to be set in the environment the suite runs under."""
    monkeypatch.setattr(shared, "EMAIL_DRY_RUN", False)
    monkeypatch.setattr(shared, "GRAPH_MAIL_TENANT_ID", "")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_ID", "")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_SECRET", "")


# ── shared.email_delivery_status(): cheap, config-presence-only ─────────────

def test_email_delivery_status_dry_run_wins_even_if_graph_is_configured(monkeypatch):
    _clear_delivery_config(monkeypatch)
    monkeypatch.setattr(shared, "EMAIL_DRY_RUN", True)
    monkeypatch.setattr(shared, "GRAPH_MAIL_TENANT_ID", "tenant")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_ID", "client")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_SECRET", "secret")

    assert shared.email_delivery_status() == "dry_run"


def test_email_delivery_status_unconfigured_when_no_provider_and_not_dry_run(monkeypatch):
    _clear_delivery_config(monkeypatch)

    assert shared.email_delivery_status() == "unconfigured"


def test_email_delivery_status_live_with_graph(monkeypatch):
    _clear_delivery_config(monkeypatch)
    monkeypatch.setattr(shared, "GRAPH_MAIL_TENANT_ID", "tenant")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_ID", "client")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_SECRET", "secret")

    assert shared.email_delivery_status() == "live"


# ── shared.email_delivery_check(): validates what it cheaply can ────────────

def test_email_delivery_check_dry_run(monkeypatch):
    _clear_delivery_config(monkeypatch)
    monkeypatch.setattr(shared, "EMAIL_DRY_RUN", True)

    state, reason = shared.email_delivery_check()

    assert state == "degraded"
    assert "EMAIL_DRY_RUN" in reason


def test_email_delivery_check_unconfigured(monkeypatch):
    _clear_delivery_config(monkeypatch)

    state, reason = shared.email_delivery_check()

    assert state == "unconfigured"
    assert "Microsoft Graph" in reason


def test_email_delivery_check_graph_configured_but_token_fails_is_degraded_not_ok(monkeypatch):
    """The P1 this guards: a Graph credential that is present but invalid
    (expired, wrong scope, revoked) must not read as "ok" just because the
    env vars are non-empty."""
    _clear_delivery_config(monkeypatch)
    monkeypatch.setattr(shared, "GRAPH_MAIL_TENANT_ID", "tenant")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_ID", "client")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_SECRET", "secret")
    monkeypatch.setattr(shared, "_graph_mail_token", lambda: None)

    state, reason = shared.email_delivery_check()

    assert state == "degraded"
    assert "GRAPH_MAIL" in reason


def test_email_delivery_check_graph_configured_and_token_succeeds_is_ok_but_says_unverified(monkeypatch):
    """P1 (softened per review): a successful OAuth token fetch proves the
    app credentials authenticate, not that Mail.Send permission or
    MAIL_SENDER access is granted -- the actual sendMail call can still 403
    on a missing permission grant. "ok" must say that honestly rather than
    implying full deliverability was verified."""
    _clear_delivery_config(monkeypatch)
    monkeypatch.setattr(shared, "GRAPH_MAIL_TENANT_ID", "tenant")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_ID", "client")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_SECRET", "secret")
    monkeypatch.setattr(shared, "_graph_mail_token", lambda: "real-token")

    state, reason = shared.email_delivery_check()

    assert state == "ok"
    assert "Mail.Send" in reason
    assert "not that" in reason or "does not" in reason


# ── _run_email_delivery_check_tick() / check_statuses ───────────────────

def test_email_delivery_check_tick_records_degraded_while_dry_run(db, monkeypatch):
    _clear_delivery_config(monkeypatch)
    monkeypatch.setattr(shared, "EMAIL_DRY_RUN", True)
    now = datetime.now(timezone.utc)

    dashboard._run_email_delivery_check_tick(now)

    row = _status("email_delivery")
    assert row["state"] == "degraded"
    assert "EMAIL_DRY_RUN" in row["reason"]
    assert row["evaluated_at"] == now.isoformat()


def test_email_delivery_check_tick_records_unconfigured_when_no_provider(db, monkeypatch):
    _clear_delivery_config(monkeypatch)
    now = datetime.now(timezone.utc)

    dashboard._run_email_delivery_check_tick(now)

    row = _status("email_delivery")
    assert row["state"] == "unconfigured"
    assert "Microsoft Graph" in row["reason"]


def test_email_delivery_check_tick_records_degraded_for_broken_graph_credential(db, monkeypatch):
    _clear_delivery_config(monkeypatch)
    monkeypatch.setattr(shared, "GRAPH_MAIL_TENANT_ID", "tenant")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_ID", "client")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_SECRET", "secret")
    monkeypatch.setattr(shared, "_graph_mail_token", lambda: None)
    now = datetime.now(timezone.utc)

    dashboard._run_email_delivery_check_tick(now)

    row = _status("email_delivery")
    assert row["state"] == "degraded"


def test_email_delivery_check_visible_via_admin_check_status_endpoint(db, monkeypatch):
    _clear_delivery_config(monkeypatch)
    monkeypatch.setattr(shared, "EMAIL_DRY_RUN", True)
    now = datetime.now(timezone.utc)

    dashboard._run_email_delivery_check_tick(now)

    with TestClient(dashboard.app) as client:
        response = client.get("/admin/check-status", headers=BEARER)

    assert response.status_code == 200
    checks = {c["name"]: c for c in response.json()["checks"]}
    assert checks["email_delivery"]["state"] == "degraded"


def test_email_delivery_check_tick_wired_into_scheduler_loop():
    """P2: prove the tick is actually registered in scheduler_loop(), not
    just defined and unused. scheduler_loop() itself is not exercised
    end-to-end here (most of its other ticks make live external calls with
    no existing precedent for running the whole loop in a test), so this
    checks the wiring directly via source inspection instead."""
    src = inspect.getsource(dashboard.scheduler_loop)
    assert "_run_email_delivery_check_tick" in src
    assert "email-delivery-check" in src
    # And _run_tick is the wrapper every other tick uses, so this one gets
    # the same tick_email_delivery_check heartbeat-on-exception behaviour.
    assert '_run_tick("email-delivery-check"' in src


# ── Ordinary feature-email callers are unaffected by dry-run ────────────

def test_send_email_still_returns_true_under_dry_run(monkeypatch):
    """_send_email()'s bool return is unchanged by this ticket: ordinary
    feature callers must keep getting True under dry-run so their normal
    'did this work' bookkeeping still runs, exactly as before PAT-1010."""
    monkeypatch.setattr(shared, "EMAIL_DRY_RUN", True)

    sent = shared._send_email(
        "ops@example.com", "subject", "<p>html</p>", "text",
    )

    assert sent is True


def _seed_cert_client(tenant_id="t-cert", recipient="ops@acme.test"):
    with dashboard.get_db() as conn:
        conn.execute(
            "INSERT INTO clients (id, company, tenant_id, "
            "created_at, cert_digest_enabled, cert_digest_recipient, cert_digest_severity, "
            "cert_digest_frequency, last_cert_digest_sent_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            ("id-cert", "Acme", tenant_id,
             datetime.now(timezone.utc).isoformat(), 1, recipient,
             "expired_plus_critical", "daily", None),
        )


def test_cert_digest_tick_real_caller_path_does_not_mark_sent_under_dry_run(db, monkeypatch):
    """Round 4: cert_digest_frequency can be weekly/monthly, so marking
    last_cert_digest_sent_at under dry-run doesn't just delay the real send
    to "next tick" -- it skips it until the next scheduled occurrence of
    that cadence, the same shape of defect fixed on report_schedule_sends.
    Exercises the real caller (_run_cert_digest_tick), not just
    _send_email() in isolation."""
    monkeypatch.setattr(shared, "EMAIL_DRY_RUN", True)
    _seed_cert_client()
    now = datetime.now(timezone.utc)
    expired_cert = {
        "device_id": "d1", "subject_cn": "x", "issuer_cn": "",
        "not_after": (now - timedelta(days=2)).isoformat(),
        "ext_key_usage": [], "basic_constraints_ca": False, "is_self_signed": False,
    }

    def fake_get(url, *a, **k):
        if url.endswith("/certs"):
            return _FakeResp([expired_cert])
        return _FakeResp({})

    monkeypatch.setattr(dashboard.http, "get", fake_get)

    dashboard._run_cert_digest_tick(now)

    with dashboard.get_db() as conn:
        row = conn.execute(
            "SELECT last_cert_digest_sent_at FROM clients WHERE tenant_id='t-cert'"
        ).fetchone()
    assert row["last_cert_digest_sent_at"] is None


def test_cert_digest_tick_real_caller_path_marks_sent_when_live(db, monkeypatch):
    monkeypatch.setattr(shared, "EMAIL_DRY_RUN", False)
    monkeypatch.setattr(shared, "GRAPH_MAIL_TENANT_ID", "tenant")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_ID", "client")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_SECRET", "secret")
    monkeypatch.setattr(shared, "_graph_send_mail", lambda *a, **k: True)
    _seed_cert_client()
    now = datetime.now(timezone.utc)
    expired_cert = {
        "device_id": "d1", "subject_cn": "x", "issuer_cn": "",
        "not_after": (now - timedelta(days=2)).isoformat(),
        "ext_key_usage": [], "basic_constraints_ca": False, "is_self_signed": False,
    }

    def fake_get(url, *a, **k):
        if url.endswith("/certs"):
            return _FakeResp([expired_cert])
        return _FakeResp({})

    monkeypatch.setattr(dashboard.http, "get", fake_get)

    dashboard._run_cert_digest_tick(now)

    with dashboard.get_db() as conn:
        row = conn.execute(
            "SELECT last_cert_digest_sent_at FROM clients WHERE tenant_id='t-cert'"
        ).fetchone()
    assert row["last_cert_digest_sent_at"] is not None


def _seed_stale_client(tenant_id="t-stale", recipient="ops@acme.test"):
    with dashboard.get_db() as conn:
        conn.execute(
            "INSERT INTO clients (id, company, tenant_id, created_at, "
            "stale_digest_recipient, last_stale_digest_sent_at) "
            "VALUES (?,?,?,?,?,?)",
            ("id-stale", "Acme", tenant_id,
             datetime.now(timezone.utc).isoformat(), recipient, None),
        )


def test_stale_digest_tick_real_caller_path_does_not_mark_sent_under_dry_run(db, monkeypatch):
    """Round 4: stale digest is fixed weekly, so marking
    last_stale_digest_sent_at under dry-run would skip it for a full week."""
    monkeypatch.setattr(shared, "EMAIL_DRY_RUN", True)
    _seed_stale_client()
    now = datetime.now(timezone.utc)

    def fake_get(url, *a, **k):
        if url.endswith("/admin/tenants/overview"):
            return _FakeResp({"tenants": [{"id": "t-stale"}]})
        if url.endswith("/devices"):
            return _FakeResp({"devices": [{
                "hostname": "OLD-01",
                "last_seen": (now - timedelta(days=30)).isoformat(),
            }]})
        return _FakeResp({})

    monkeypatch.setattr(dashboard.http, "get", fake_get)

    dashboard._run_stale_digest_tick(now)

    with dashboard.get_db() as conn:
        row = conn.execute(
            "SELECT last_stale_digest_sent_at FROM clients WHERE tenant_id='t-stale'"
        ).fetchone()
    assert row["last_stale_digest_sent_at"] is None


def test_graph_is_the_only_mail_sender_and_legacy_routes_are_absent(db, monkeypatch):
    _clear_delivery_config(monkeypatch)
    monkeypatch.setattr(shared, "GRAPH_MAIL_TENANT_ID", "tenant")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_ID", "client")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_SECRET", "secret")
    calls = []
    monkeypatch.setattr(shared, "_graph_send_mail", lambda *a, **k: calls.append(a) or True)

    assert shared._send_email("ops@example.com", "subject", "<p>body</p>", "body") is True
    assert len(calls) == 1
    assert not hasattr(shared, "_sendgrid_send_mail")
    assert not hasattr(shared, "SENDGRID_API_KEY")

    with TestClient(dashboard.app) as client:
        assert client.get("/admin/monitoring/sendgrid-bounces", headers=BEARER).status_code == 404
        assert client.post("/admin/monitoring/sendgrid-test", headers=BEARER).status_code == 404


def test_init_db_soft_deletes_existing_sendgrid_credential_idempotently(db):
    now = datetime.now(timezone.utc).isoformat()
    with dashboard.get_db() as conn:
        conn.execute(
            """INSERT INTO credentials
               (id, name, service, created_at, updated_at, deleted_at)
               VALUES (?, ?, ?, ?, ?, NULL)""",
            ("cred-sendgrid", "Legacy mail credential", "Legacy vendor", now, now),
        )

    dashboard.init_db()
    with dashboard.get_db() as conn:
        retired = conn.execute(
            "SELECT deleted_at, updated_at FROM credentials WHERE id='cred-sendgrid'"
        ).fetchone()
    assert retired["deleted_at"] is not None

    dashboard.init_db()
    with dashboard.get_db() as conn:
        rerun = conn.execute(
            "SELECT deleted_at, updated_at FROM credentials WHERE id='cred-sendgrid'"
        ).fetchone()
    assert dict(rerun) == dict(retired)

    with TestClient(dashboard.app) as client:
        visible = client.get("/api/credentials", headers=BEARER).json()
    assert all(row["id"] != "cred-sendgrid" for row in visible)


# ── Trial-expiry: don't cross-notify the platform under dry-run ─────────

def _make_trial(**kwargs):
    base = {
        "tenant_id": "tenant-uuid-001",
        "name": "Acme Corp",
        "trial_email": "admin@acme.example",
        "trial_expires_at": "2099-01-01T00:00:00Z",
        "upgrade_email_sent_at": None,
        "device_count": 3,
        "failing_eval_count": 7,
        "state": "expiring_soon",
    }
    base.update(kwargs)
    return base


def test_trial_notify_not_called_under_email_dry_run(db, monkeypatch):
    """Even though _send_email() returns True under dry-run, the local
    ledger insert and the platform trial-notify POST (which tells another
    system the customer was told) must not fire -- no email actually went
    out."""
    trial = _make_trial()
    r_trials = _FakeResp({"trials": [trial]}, 200, content=b"...")

    with patch.object(dashboard, "http") as mock_http, \
         patch.object(dashboard, "_send_email", return_value=True), \
         patch.object(dashboard, "email_delivery_status", return_value="dry_run"):
        mock_http.get.return_value = r_trials
        dashboard.check_trial_expiry_emails()
        mock_http.post.assert_not_called()

    with dashboard.get_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM trial_expiry_notifications WHERE tenant_id=?",
            (trial["tenant_id"],),
        ).fetchone()
    assert row is None, "dry-run must not write the local notified ledger either"


# ── Scheduled + on-demand report delivery: don't log "sent" under dry-run ──

def _seed_report_sub(tenant_id="t-rep"):
    with dashboard.get_db() as conn:
        conn.execute(
            "INSERT INTO clients (id, company, tenant_id, "
            "created_at, primary_contact_email) VALUES (?,?,?,?,?)",
            ("id-rep", "Acme", tenant_id,
             datetime.now(timezone.utc).isoformat(), "primary@acme.test"),
        )
        conn.execute(
            "INSERT INTO report_subscriptions (tenant_id, report_type, enabled, frequency, "
            "recipient, last_sent_at) VALUES (?,?,?,?,?,?)",
            (tenant_id, "executive-summary", 1, "monthly", None, None),
        )


def test_report_tick_does_not_mark_delivered_under_dry_run(db, monkeypatch):
    _seed_report_sub()
    now = datetime.now(timezone.utc)

    def fake_get(url, *a, **k):
        return _FakeResp(content=b"%PDF-fake")

    monkeypatch.setattr(dashboard.http, "get", fake_get)
    monkeypatch.setattr(dashboard, "_send_email", lambda *a, **k: True)
    monkeypatch.setattr(dashboard, "email_delivery_status", lambda: "dry_run")

    dashboard._run_report_tick(now)

    with dashboard.get_db() as conn:
        sub_row = conn.execute(
            "SELECT last_sent_at FROM report_subscriptions "
            "WHERE tenant_id='t-rep' AND report_type='executive-summary'"
        ).fetchone()
        delivery_rows = conn.execute(
            "SELECT 1 FROM report_deliveries WHERE tenant_id='t-rep'"
        ).fetchall()
    assert sub_row["last_sent_at"] is None, \
        "dry-run must not mark the period sent, or the real report is skipped next period"
    assert delivery_rows == [], \
        "dry-run must not write a 'sent' row into the Delivery Log the console UI renders"


def test_on_demand_report_email_refuses_under_dry_run(db, monkeypatch):
    with dashboard.get_db() as conn:
        conn.execute(
            "INSERT INTO clients (id, company, tenant_id, created_at, primary_contact_email) "
            "VALUES (?,?,?,?,?)",
            ("id-1", "Acme", "0a4c2c91-7412-575c-b544-dea3a596dd31", datetime.now(timezone.utc).isoformat(), "primary@acme.test"),
        )
    monkeypatch.setattr(dashboard, "email_delivery_status", lambda: "dry_run")
    send_calls = []
    monkeypatch.setattr(dashboard, "_send_email", lambda *a, **k: send_calls.append(1) or True)
    get_calls = []
    monkeypatch.setattr(dashboard.http, "get",
                         lambda *a, **k: get_calls.append(1) or _FakeResp({}, 200))

    with TestClient(dashboard.app) as client:
        tok = dashboard._session_encode("owner@patched.im", int(time.time()) + 3600)
        response = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/reports/email",
            headers={"Cookie": f"{dashboard.SESSION_COOKIE}={tok}"},
            json={"report_type": "executive-summary", "recipient": "primary@acme.test"},
        )

    assert response.status_code == 503
    assert "EMAIL_DRY_RUN" in response.json()["error"]
    assert send_calls == [], "must not even attempt the send under dry-run"

    with dashboard.get_db() as conn:
        audit_rows = conn.execute(
            "SELECT outcome FROM report_send_audit_log WHERE tenant_id='0a4c2c91-7412-575c-b544-dea3a596dd31'"
        ).fetchall()
        delivery_rows = conn.execute(
            "SELECT 1 FROM report_deliveries WHERE tenant_id='0a4c2c91-7412-575c-b544-dea3a596dd31'"
        ).fetchall()
    assert [r["outcome"] for r in audit_rows] == ["dry_run"]
    assert delivery_rows == [], \
        "must not write a 'sent' row into the Delivery Log the console UI renders"


# ── Calendly: don't render a confirmed/followed-up checkmark under dry-run ──

def test_calendly_initial_confirmation_not_marked_sent_under_dry_run(db, monkeypatch):
    monkeypatch.setattr(dashboard, "_verify_calendly_signature", lambda body, header: True)
    monkeypatch.setattr(dashboard, "_send_email", lambda *a, **k: True)
    monkeypatch.setattr(dashboard, "email_delivery_status", lambda: "dry_run")

    payload = {
        "event": "invitee.created",
        "payload": {
            "invitee": {"email": "lead@example.com", "name": "Lead Person"},
            "scheduled_event": {"start_time": "2026-08-01T10:00:00Z"},
            "event_type": {"name": "Consult"},
        },
    }

    with TestClient(dashboard.app) as client:
        response = client.post(
            "/webhooks/calendly",
            json=payload,
            headers={"Calendly-Webhook-Signature": "t=1,v1=fake"},
        )

    assert response.status_code == 200
    with dashboard.get_db() as conn:
        row = conn.execute(
            "SELECT initial_email_sent_at FROM calendly_leads WHERE email='lead@example.com'"
        ).fetchone()
    assert row["initial_email_sent_at"] is None, \
        "Leads tab 'confirmed' checkmark must not show for a dry-run no-op"


def test_calendly_followup_tick_not_marked_sent_under_dry_run(db, monkeypatch):
    booked_at = (datetime.now(timezone.utc) - timedelta(days=4)).isoformat()
    with dashboard.get_db() as conn:
        conn.execute(
            "INSERT INTO calendly_leads (id, email, name, event_type, event_uri, booked_at, meeting_at) "
            "VALUES (?,?,?,?,?,?,?)",
            ("lead-1", "lead@example.com", "Lead Person", "Consult", "uri-1", booked_at, ""),
        )
    monkeypatch.setattr(dashboard, "_send_email", lambda *a, **k: True)
    monkeypatch.setattr(dashboard, "email_delivery_status", lambda: "dry_run")

    dashboard._run_calendly_followups_tick(datetime.now(timezone.utc))

    with dashboard.get_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM calendly_followup_sends WHERE lead_id='lead-1'"
        ).fetchone()
    assert row is None, \
        "Leads tab 'D+day' checkmark must not show, and the real follow-up must still be due"


def _seed_calendly_lead(lead_id="lead-1", days_since_booked=4, email="lead@example.com"):
    booked_at = (datetime.now(timezone.utc) - timedelta(days=days_since_booked)).isoformat()
    with dashboard.get_db() as conn:
        conn.execute(
            "INSERT INTO calendly_leads (id, email, name, event_type, event_uri, booked_at, meeting_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (lead_id, email, "Lead Person", "Consult", "uri-1", booked_at, ""),
        )


def test_calendly_followup_tick_sends_only_latest_step_when_both_overdue(db, monkeypatch):
    """Round 6: a dry-run gap can leave D+3 unsent while D+7 also becomes
    due before dry-run is turned off. Sending every overdue-and-unsent step
    in one catch-up tick would mail stale pre-meeting D+3 copy alongside
    post-meeting D+7 copy -- wrong content, not just late. Only the latest
    (D+7) step must be attempted; D+3 must never be sent at all."""
    _seed_calendly_lead(days_since_booked=8)  # both D+3 and D+7 are overdue
    sent_subjects = []
    monkeypatch.setattr(dashboard, "_send_email",
                         lambda to, subject, html, text: sent_subjects.append(subject) or True)
    monkeypatch.setattr(dashboard, "email_delivery_status", lambda: "live")

    dashboard._run_calendly_followups_tick(datetime.now(timezone.utc))

    assert sent_subjects == [dict(dashboard._FOLLOWUP_STEPS)[7]], \
        "only the D+7 (latest applicable) step should have been sent"
    with dashboard.get_db() as conn:
        rows = {r["day_number"] for r in conn.execute(
            "SELECT day_number FROM calendly_followup_sends WHERE lead_id='lead-1'"
        ).fetchall()}
    assert rows == {7}, "D+3 must never get a sent row once D+7 is also due"


def test_calendly_followup_tick_does_not_send_superseded_step_on_a_later_tick(db, monkeypatch):
    """Round 6: the skip must be re-derived from due-ness every tick, not
    just "was a later step already sent this exact tick" -- otherwise a
    catch-up spanning two ticks (e.g. D+7's send throws on tick 1, retries
    and succeeds on tick 2) would let D+3 sneak out on some later tick once
    D+7 already has a sent row and is no longer "due and unsent"."""
    _seed_calendly_lead(days_since_booked=8)
    # Simulate D+7 already sent on an earlier tick.
    with dashboard.get_db() as conn:
        conn.execute(
            "INSERT INTO calendly_followup_sends (lead_id, day_number, sent_at) VALUES (?,?,?)",
            ("lead-1", 7, datetime.now(timezone.utc).isoformat()),
        )
    sent_subjects = []
    monkeypatch.setattr(dashboard, "_send_email",
                         lambda to, subject, html, text: sent_subjects.append(subject) or True)
    monkeypatch.setattr(dashboard, "email_delivery_status", lambda: "live")

    dashboard._run_calendly_followups_tick(datetime.now(timezone.utc))

    assert sent_subjects == [], "D+3 must stay permanently superseded, not sent on a later tick"
    with dashboard.get_db() as conn:
        rows = {r["day_number"] for r in conn.execute(
            "SELECT day_number FROM calendly_followup_sends WHERE lead_id='lead-1'"
        ).fetchall()}
    assert rows == {7}


def test_calendly_followup_tick_sends_earlier_step_alone_when_later_not_yet_due(db, monkeypatch):
    """Sanity check the fix doesn't over-suppress: when only D+3 is due
    (D+7 isn't yet), it must still send normally."""
    _seed_calendly_lead(days_since_booked=4)  # D+3 due, D+7 not yet
    sent_subjects = []
    monkeypatch.setattr(dashboard, "_send_email",
                         lambda to, subject, html, text: sent_subjects.append(subject) or True)
    monkeypatch.setattr(dashboard, "email_delivery_status", lambda: "live")

    dashboard._run_calendly_followups_tick(datetime.now(timezone.utc))

    assert sent_subjects == [dict(dashboard._FOLLOWUP_STEPS)[3]]
    with dashboard.get_db() as conn:
        rows = {r["day_number"] for r in conn.execute(
            "SELECT day_number FROM calendly_followup_sends WHERE lead_id='lead-1'"
        ).fetchall()}
    assert rows == {3}


# ── report_schedule_sends: don't permanently skip a whole cadence period ────

def test_report_schedule_does_not_mark_period_sent_under_dry_run(db, monkeypatch):
    sched = {
        "id": "sched-1", "cadence": "daily", "cadence_config": {},
        "name": "Monthly Report", "content_type": "full",
        "recipient_ids": [], "ad_hoc_emails": ["ops@acme.test"],
    }

    def fake_get(url, *a, **k):
        if url.endswith("/report-schedules"):
            return _FakeResp([sched])
        return _FakeResp({})

    def fake_post(url, *a, **k):
        if url.endswith("/generate"):
            return _FakeResp({"id": "record-1"}, status_code=201)
        return _FakeResp({})

    monkeypatch.setattr(dashboard.http, "get", fake_get)
    monkeypatch.setattr(dashboard.http, "post", fake_post)
    monkeypatch.setattr(dashboard, "_send_email", lambda *a, **k: True)
    monkeypatch.setattr(dashboard, "email_delivery_status", lambda: "dry_run")

    today = datetime.now(timezone.utc).date()
    dashboard._check_tenant_report_schedules("t-sched", "Acme", today)

    with dashboard.get_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM report_schedule_sends WHERE tenant_id='t-sched' "
            "AND schedule_id='sched-1'"
        ).fetchone()
    assert row is None, \
        "dry-run must not mark this cadence period sent -- this tick runs " \
        "once a day, so marking it would skip the whole period once dry-run is off"


def test_report_schedule_marks_period_sent_when_live(db, monkeypatch):
    sched = {
        "id": "sched-1", "cadence": "daily", "cadence_config": {},
        "name": "Monthly Report", "content_type": "full",
        "recipient_ids": [], "ad_hoc_emails": ["ops@acme.test"],
    }

    def fake_get(url, *a, **k):
        if url.endswith("/report-schedules"):
            return _FakeResp([sched])
        return _FakeResp({})

    def fake_post(url, *a, **k):
        if url.endswith("/generate"):
            return _FakeResp({"id": "record-1"}, status_code=201)
        return _FakeResp({})

    monkeypatch.setattr(dashboard.http, "get", fake_get)
    monkeypatch.setattr(dashboard.http, "post", fake_post)
    monkeypatch.setattr(dashboard, "_send_email", lambda *a, **k: True)
    monkeypatch.setattr(dashboard, "email_delivery_status", lambda: "live")

    today = datetime.now(timezone.utc).date()
    dashboard._check_tenant_report_schedules("t-sched", "Acme", today)

    with dashboard.get_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM report_schedule_sends WHERE tenant_id='t-sched' "
            "AND schedule_id='sched-1'"
        ).fetchone()
    assert row is not None
