"""Supplemental caller-level escaping, periods and asset contract coverage."""
from datetime import datetime, timezone
from markupsafe import escape
from unittest.mock import Mock

import pytest

from report_email import REPORT_EMAIL_LOGO_URL, email_display_label, render_report_email
from tests.test_pat2354_email_branding import (
    DEFINITION, NOW, TENANT, VARIANTS, VisibleHTML, capture, dashboard, harness as harness,
)


@pytest.mark.parametrize("value", (None, "", "  ", TENANT, "{" + TENANT + "}", TENANT.replace("-", "")))
def test_display_name_fallback(value):
    assert email_display_label(value) == "Your estate"


@pytest.mark.parametrize("value, expected", (
    ("urn:uuid:" + TENANT, "Your estate"),
    ("URN:UUID:" + TENANT.upper(), "Your estate"),
    ("Acme urn:uuid:" + TENANT + " Estate", "Acme Estate"),
    ("Acme {urn:uuid:" + TENANT + "} Estate", "Acme Estate"),
    ("Acme {" + TENANT + "} Estate", "Acme Estate"),
    ("Acme [" + TENANT + "] Estate", "Acme Estate"),
    ("Acme (" + TENANT.replace("-", "").upper() + ") Estate", "Acme Estate"),
    ("Acme (urn:uuid:" + TENANT + ") Estate", "Acme Estate"),
    ("Acme ()\r\nEstate", "Acme () Estate"),
))
def test_display_labels_remove_uuid_wrappers(value, expected):
    assert email_display_label(value) == expected


def test_display_labels_remove_embedded_uuid_and_header_controls():
    assert email_display_label("Acme (" + TENANT + ")\r\nEstate") == "Acme Estate"
    subject, _, _ = render_report_email(
        "report_attachment_email", estate_name="Acme\r\nBcc: other@example.test",
        report_label="Summary\nInjected", period="2026-10-03",
    )
    assert "\r" not in subject and "\n" not in subject


@pytest.mark.parametrize("variant", VARIANTS)
def test_all_sender_paths_escape_customer_estate_copy(harness, variant):
    company = '<img src=x onerror="alert(1)"> & Estate'
    call = capture(harness, company, variant)
    html, plain = call.args[2:4]
    assert company not in html
    assert escape(company) in html
    assert company in plain  # plain text is not HTML-entity encoded
    assert html.count("<img ") == 1  # only the approved logo
    assert call.args[0] == "recipient@example.test"


@pytest.mark.parametrize("variant", ("pdf-tick", "pdf-on-demand"))
def test_pdf_label_is_escaped_and_attachment_fallback_contains_no_uuid(harness, monkeypatch, variant):
    label = '<script>alert("label")</script> & Summary'
    monkeypatch.setattr(dashboard, "_report_catalogue", lambda: ({**DEFINITION, "label": label},))
    call = capture(harness, TENANT, variant)
    assert "<script>" not in call.args[2]
    assert escape(label) in call.args[2]
    assert label in call.args[3]
    assert TENANT not in call.kwargs["attachment_name"]
    assert "your-estate" in call.kwargs["attachment_name"]


@pytest.mark.parametrize("variant", ("stale", "cert"))
def test_digest_data_is_escaped_without_changing_links(harness, monkeypatch, variant):
    fake_get = dashboard.http.get
    value = '<script>alert("device")</script>&'

    def with_data(url, **kwargs):
        response = fake_get(url, **kwargs)
        data = response.json()
        if url.endswith("/devices"):
            data["devices"][0]["hostname"] = value
        elif url.endswith("/certs"):
            data[0]["subject_cn"] = value
            data[0]["issuer_cn"] = value
        return response

    monkeypatch.setattr(dashboard.http, "get", with_data)
    call = capture(harness, "Acme Estate", variant)
    assert "<script>" not in call.args[2]
    assert escape(value) in call.args[2]
    assert value in call.args[3]
    assert TENANT in VisibleHTML(call.args[2]).hrefs[0]


@pytest.mark.parametrize("cadence, start, end", (
    ("daily", "2026-10-03", "2026-10-03"),
    ("weekly", "2026-09-28", "2026-10-04"),
    ("monthly", "2026-10-01", "2026-10-31"),
    ("quarterly", "2026-10-01", "2026-12-31"),
))
def test_schedule_copy_retains_actual_period_and_token_recipient(harness, monkeypatch, cadence, start, end):
    fake_get = dashboard.http.get
    label = '<img src=x> Security Review'

    def with_schedule(url, **kwargs):
        response = fake_get(url, **kwargs)
        if url.endswith("/report-schedules"):
            response.json()[0].update(cadence=cadence, name=label)
        return response

    def generate(url, **kwargs):
        assert url.endswith(f"/admin/tenants/{TENANT}/report-records/generate")
        assert kwargs["json"]["period_start"] == start
        assert kwargs["json"]["period_end"] == end
        return Mock(status_code=201, json=lambda: {"id": "record-test"})

    monkeypatch.setattr(dashboard.http, "get", with_schedule)
    monkeypatch.setattr(dashboard.http, "post", generate)
    monkeypatch.setattr(dashboard, "_is_schedule_due", lambda *args: True)
    call = capture(harness, "Acme Estate", "xlsx-schedule")
    assert start in call.args[1] and end in call.args[1]
    assert escape(label) in call.args[2] and label in call.args[3]
    assert label not in call.args[2]
    url, = VisibleHTML(call.args[2]).hrefs
    with dashboard.get_db() as db:
        row = db.execute("SELECT tenant_id, record_id, email FROM report_ext_tokens WHERE token=?",
                         (url.rsplit("/", 1)[-1],)).fetchone()
    assert tuple(row) == (TENANT, "record-test", "recipient@example.test")


def test_on_demand_subject_uses_utc_send_date(harness, monkeypatch):
    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            assert tz == timezone.utc
            return NOW
    monkeypatch.setattr(dashboard, "datetime", FixedDatetime)
    call = capture(harness, "Acme Estate", "pdf-on-demand")
    assert call.args[1] == "Patched | Acme Estate | Executive Summary | 2026-10-03"


def test_raster_logo_has_visible_fallback_and_no_extra_link():
    _, html, _ = render_report_email(
        "report_attachment_email", estate_name="Acme Estate",
        report_label="Executive Summary", period="2026-10-03",
    )
    assert REPORT_EMAIL_LOGO_URL == "https://patched.im/apple-touch-icon.png?v=2026-09-26-brand-v3"
    assert f'src="{REPORT_EMAIL_LOGO_URL}"' in html
    assert 'alt="Patched"' in html and ">Patched<span" in html
    assert not VisibleHTML(html).hrefs  # logo never adds an unrelated navigation
    assert "<script" not in html and "<link" not in html and "<style" not in html
