"""PAT-2097 in a real browser: the Alerts page renders, an admin can
acknowledge an open alert (a plain form POST + redirect, no AJAX - unlike
PAT-2008's approval writes, this page does not intercept the submit), and a
viewer sees no Acknowledge control. Smoke coverage only; the guard, filter
and 409/404 behaviour are covered in full by tests/test_pat2097_alerts.py
against the same stub.
"""

from e2e.conftest import HARNESS_VALID_TOKEN
from tests.conftest import STUB_STATE


def _context(browser, harness_url):
    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def test_alerts_page_lists_rows_and_acknowledge_updates_the_page(browser, harness_url):
    context = _context(browser, harness_url)
    page = context.new_page()
    page.goto("/software/alerts?status=all", wait_until="networkidle")
    assert "Tor Browser" in page.content()
    assert "ShadyCoupons" in page.content()

    # PAT-2155: the Acknowledge control only renders on the Open tab now
    # (an alert can only ever be acknowledged while open).
    page.goto("/software/alerts?status=open", wait_until="networkidle")
    row = page.locator("tr", has_text="Tor Browser")
    row.get_by_placeholder("Note (optional)").fill("Raised with the service desk")
    row.get_by_role("button", name="Acknowledge").click()
    page.wait_for_selector("#alert-result")
    assert "Alert acknowledged." in page.locator("#alert-result").inner_text()
    post = STUB_STATE["alert_acknowledge_posts"][-1]
    assert post["alert_id"] == "1"
    assert post["body"] == {"note": "Raised with the service desk"}
    context.close()


def test_viewer_sees_no_acknowledge_control(browser, harness_url):
    STUB_STATE["portal_role"] = "viewer"
    context = _context(browser, harness_url)
    page = context.new_page()
    # PAT-2155: the Open tab is where an admin's Acknowledge control would
    # render - the one tab where a viewer's absence of it is a real check,
    # not a given (every other tab never shows it, to anyone).
    page.goto("/software/alerts?status=open", wait_until="networkidle")
    assert "Tor Browser" in page.content()
    assert page.locator('button:has-text("Acknowledge")').count() == 0
    context.close()


def test_overview_links_to_alerts_page(browser, harness_url):
    STUB_STATE["overview_data"] = {
        "tenant_name": "Acme Trust Ltd", "generated_at": "2026-09-24T10:00:00Z",
        "devices_total": 3, "devices_reporting_24h": 3,
        "findings_open": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "patch_status": {"up_to_date": 3, "pending": 0, "failed": 0},
        "unapproved_alerts_open": 2, "unapproved_alerts_acknowledged": 1,
    }
    context = _context(browser, harness_url)
    page = context.new_page()
    page.goto("/", wait_until="networkidle")
    link = page.locator('a[href="/software/alerts"]').first
    assert link.count() >= 1
    link.click()
    page.wait_for_url("**/software/alerts")
    context.close()
