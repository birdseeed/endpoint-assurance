"""PAT-2354 customer email acceptance through existing sender seams.

No provider calls: disposable SQLite, strict HTTP stubs and captured _send_email.
UUIDs remain in tenant-scoped hrefs but must never become visible estate labels.
"""
import asyncio
import os
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from unittest.mock import Mock
from pathlib import Path

import pytest
from starlette.requests import Request

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")
import main as dashboard
import shared

TENANT = "12345678-1234-4234-8234-123456789abc"
NOW = datetime(2026, 10, 3, 12, tzinfo=timezone.utc)
PDF = b"%PDF-1.4 disposable acceptance report"
DEFINITION = {"type": "executive-summary", "label": "Executive Summary",
              "subject_scope": "tenant",
              "admin_pdf_path": "/admin/tenants/{tenantID}/reports/executive-summary/pdf"}


class VisibleHTML(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.parts = []
        self.hidden = 0
        self.hrefs = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        if tag in ("style", "script"):
            self.hidden += 1
        if tag == "a":
            self.hrefs.extend(v for k, v in attrs if k == "href")

    def handle_endtag(self, tag):
        if tag in ("style", "script"):
            self.hidden -= 1

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


@pytest.fixture
def harness(tmp_path, monkeypatch):
    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW if tz is not None else NOW.replace(tzinfo=None)
    monkeypatch.setattr(dashboard, "datetime", FixedDatetime)
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "emails.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "emails.db")
    dashboard.init_db()
    attachments = []
    def fake_send(*args, **kwargs):
        if kwargs.get("attachment_path"):
            attachments.append(Path(kwargs["attachment_path"]).read_bytes())
        return True
    sender = Mock(side_effect=fake_send)
    sender.attachments = attachments
    monkeypatch.setattr(dashboard, "_send_email", sender)
    monkeypatch.setattr(dashboard, "email_delivery_status", lambda: "live")
    monkeypatch.setattr(dashboard, "_report_catalogue", lambda: (DEFINITION,))
    monkeypatch.setattr(dashboard, "_recipient_category", lambda *a: ("primary", "Primary"))
    monkeypatch.setattr(dashboard, "compute_days_until_expiry", lambda cert: -3)
    urls = []
    schedule = {"id": "schedule-test", "name": "Security Report", "cadence": "daily",
                "content_type": "full", "ad_hoc_emails": '["recipient@example.test"]'}

    def fake_get(url, **kwargs):
        urls.append(url)
        if url.endswith("/admin/tenants/overview"):
            payload = {"tenants": [{"id": TENANT}]}
        elif url.endswith(f"/admin/tenants/{TENANT}/devices"):
            payload = {"devices": [{"id": "device-test", "hostname": "Mac Test",
                                   "last_seen": "2026-09-01T12:00:00+00:00"}]}
        elif url.endswith(f"/admin/tenant/{TENANT}/certs"):
            payload = [{"device_id": "device-test", "subject_cn": "cert.example.test",
                        "issuer_cn": "Test issuer", "not_after": "2026-09-30T12:00:00Z"}]
        elif url.endswith(f"/admin/tenants/{TENANT}/report-schedules"):
            payload = [schedule]
        elif url.endswith(f"/admin/tenants/{TENANT}/reports/executive-summary/pdf"):
            payload = {}
        else:
            raise AssertionError(f"Unexpected API read: {url}")
        return Mock(status_code=200, content=PDF, json=lambda: payload)

    def fake_post(url, **kwargs):
        assert url.endswith(f"/admin/tenants/{TENANT}/report-records/generate")
        assert kwargs["json"]["period_start"] == "2026-10-03"
        assert kwargs["json"]["period_end"] == "2026-10-03"
        return Mock(status_code=201, json=lambda: {"id": "record-test"})

    monkeypatch.setattr(dashboard.http, "get", fake_get)
    monkeypatch.setattr(dashboard.http, "post", fake_post)
    return sender, urls


def capture(harness, company, variant):
    sender, urls = harness
    with dashboard.get_db() as db:
        db.execute("INSERT INTO clients (id, company, tenant_id, created_at, primary_contact_email, "
                   "stale_digest_enabled, cert_digest_enabled, cert_digest_recipient, cert_digest_severity) "
                   "VALUES (?,?,?,?,?,1,1,?,?)",
                   ("client-test", company, TENANT, NOW.isoformat(), "recipient@example.test",
                    "recipient@example.test", "all_categorised"))
        db.execute("INSERT INTO report_subscriptions "
                   "(tenant_id, report_type, enabled, frequency) VALUES (?,?,1,'monthly')",
                   (TENANT, "executive-summary"))
    if variant == "stale":
        dashboard._run_stale_digest_tick(NOW)
    elif variant == "cert":
        dashboard._run_cert_digest_tick(NOW)
    elif variant == "pdf-tick":
        dashboard._run_report_tick(NOW)
    elif variant == "xlsx-schedule":
        dashboard._check_tenant_report_schedules(TENANT, company, NOW.date())
    else:
        import json
        body = json.dumps({"report_type": "executive-summary", "recipient": "recipient@example.test"}).encode()
        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}
        request = Request({"type": "http", "method": "POST", "path": "/", "headers": []}, receive)
        response = asyncio.run(dashboard.proxy_report_email(TENANT, request))
        assert response.status_code == 200
    sender.assert_called_once()
    return sender.call_args


VARIANTS = ("stale", "cert", "pdf-tick", "pdf-on-demand", "xlsx-schedule")


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("company", ("Acme Estate", "", "   ", TENANT))
def test_customer_subject_and_visible_content_use_safe_estate_name(harness, variant, company):
    call = capture(harness, company, variant)
    recipient, subject, html, text = call.args[:4]
    assert recipient == "recipient@example.test"
    assert TENANT not in subject
    assert TENANT not in "".join(VisibleHTML(html).parts)
    # Link targets retain internal tenant IDs; they are not customer display copy.
    visible_text = re.sub(r"https?://\S+", "", text)
    assert TENANT not in visible_text
    if company == "Acme Estate":
        assert company in subject
    else:
        assert "estate" in subject.lower(), "Missing or UUID estate names need a readable estate fallback"
    assert any(term in subject.lower() for term in ("digest", "summary", "report"))
    assert any(date in subject for date in ("2026-10-03", "3 October 2026", "03 October 2026", "October 2026"))


@pytest.mark.parametrize("variant", VARIANTS)
def test_customer_emails_use_email_safe_current_brand_surfaces(harness, variant):
    call = capture(harness, "Acme Estate", variant)
    html = call.args[2].lower()
    assert "#f5f5f3" in html, "Current Brand v3 paper surface absent"
    assert "#0f1115" in html, "Current Brand v3 slate ink absent"
    assert "#f5530a" in html, "Current Brand v3 signal accent absent"
    assert re.search(r'<img\b[^>]*alt=[\"\'][^\"\']*patched', html), "Email-safe Patched brand asset absent"
    assert 'style=' in html, "Core styling must survive mail clients that strip style blocks"


@pytest.mark.parametrize("variant", VARIANTS)
def test_existing_customer_report_payload_and_scoped_links_are_preserved(harness, variant):
    call = capture(harness, "Acme Estate", variant)
    html, text = call.args[2:4]
    if variant == "stale":
        assert "Mac Test" in html and "Mac Test" in text
        assert f"{dashboard.PUBLIC_BASE_URL}/console#tenant/{TENANT}/device-health" in VisibleHTML(html).hrefs
    elif variant == "cert":
        assert "cert.example.test" in html and "cert.example.test" in text
        assert f"{dashboard.PUBLIC_BASE_URL}/certs?tenant_id={TENANT}" in VisibleHTML(html).hrefs
    elif variant.startswith("pdf"):
        assert "Executive Summary" in html and "Executive Summary" in text
        assert call.kwargs["attachment_name"].endswith(".pdf")
        assert harness[0].attachments == [PDF]
        assert any(TENANT in url for url in harness[1])
    else:
        links = VisibleHTML(html).hrefs
        assert len(links) == 1 and "/reports/download/" in links[0]
        token = links[0].rsplit("/", 1)[-1]
        with dashboard.get_db() as db:
            row = db.execute("SELECT tenant_id, record_id, email FROM report_ext_tokens WHERE token=?", (token,)).fetchone()
        assert tuple(row) == (TENANT, "record-test", "recipient@example.test")
        assert "2026-10-03" in html and "2026-10-03" in text
