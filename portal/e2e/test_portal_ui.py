"""Browser-driven E2E suite for the customer portal (PAT-1021).

Drives a real headless Chromium against e2e/_harness.py (the real portal
app with Cloudflare Access verification stubbed) sitting in front of the
stub platform backend from tests/conftest.py. Covers the class of bug pytest
route tests cannot: a page that returns 200 but renders blank, or a form
whose button does nothing.

Run with `pytest e2e/ -v` (excluded from the default `pytest` run - see
e2e/conftest.py's module docstring).
"""

import re

import pytest
from playwright.sync_api import expect

from e2e.conftest import HARNESS_VALID_TOKEN
from tests.conftest import STUB_STATE

# The 11 authenticated HTML GET routes (PAT-1021 brief, reduced from 9 to 8
# by PAT-1643's /unapproved-apps + /extensions -> /software merge, then back
# to 11 by PAT-1999's Homebrew tab, PAT-1785's Exceptions page and PAT-2070
# closing the gap where those two had never been added here; PAT-2164 then
# split /devices/{id} into six tab routes, each checked below), each paired
# with a
# piece of fixture-specific text that only appears if the page actually
# rendered real content - not just a 200 with an empty body.
PAGE_CHECKS = [
    ("/", "Acme Trust Ltd"),
    # PAT-1843: all reporting groups share one server-bucketed roster and a
    # client-side segmented view. Static page copy proves the shell rendered;
    # the focused interaction test below proves the rows switch correctly.
    ("/devices", "Your estate roster"),
    # PAT-2164: the device page split into six tabs - one check per tab,
    # each on a piece of fixture text that only renders on that tab.
    ("/devices/dev-mac-001", "C02XL0GTJGH5"),
    ("/devices/dev-mac-001/hardware", "Apple M2"),
    ("/devices/dev-mac-001/software", "Example App"),
    ("/devices/dev-mac-001/vulnerabilities", "ExampleBrowser"),
    ("/devices/dev-mac-001/compliance", "Firewall enabled"),
    ("/devices/dev-mac-001/evidence", "Hardware health: battery"),
    ("/findings", "CVE-2026-0001"),
    # PAT-1643: /unapproved-apps and /extensions merged into one /software
    # page (301 redirects cover the old paths, checked in tests/test_pages.py).
    ("/software", "TorrentBox"),
    ("/homebrew", "openssl@3"),
    ("/homebrew/devices/hb-mac-01", "firefox"),
    ("/exceptions", "LegacyLedger"),
    ("/reports", "Executive Estate Summary"),
    ("/install", "Generate a one-off install token"),
    ("/support", "hello@patched.im"),
]


@pytest.fixture(scope="session")
def run_errors():
    """Collected across the WHOLE run by every page created below. This is
    the highest-value assertion in this suite (PAT-1021 brief): it catches
    the "renders blank" / "dead JS" bug class directly, on every page, not
    just the ones a text assertion happens to cover."""
    state = {"js": [], "network": []}
    yield state
    assert state["js"] == [], f"uncaught JS errors during the run: {state['js']}"
    assert state["network"] == [], f"failed network requests during the run: {state['network']}"


def _stub_out_google_fonts(route):
    """The portal loads Google Fonts client-side on every page (AGENTS.md).
    Fulfilling those requests locally - rather than letting them hit the
    real network or aborting them - keeps this suite hermetic and keeps the
    requestfailed collector honest about the app's own behaviour instead of
    an external font CDN's reachability from CI."""
    route.fulfill(status=200, content_type="text/css", body="")


def _new_authed_page(browser, harness_url, run_errors, token):
    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": token, "url": harness_url,
    }])
    context.route("https://fonts.googleapis.com/**", _stub_out_google_fonts)
    context.route("https://fonts.gstatic.com/**", _stub_out_google_fonts)
    page = context.new_page()
    page.on("pageerror", lambda exc: run_errors["js"].append(str(exc)))
    page.on("requestfailed", lambda req: run_errors["network"].append(
        f"{req.method} {req.url} -> {req.failure}"))
    return context, page


@pytest.fixture
def authed_page(browser, harness_url, run_errors):
    context, page = _new_authed_page(browser, harness_url, run_errors, HARNESS_VALID_TOKEN)
    yield page
    context.close()


@pytest.mark.parametrize("path,expected_text", PAGE_CHECKS)
def test_page_renders_real_content(authed_page, harness_url, path, expected_text):
    authed_page.goto(f"{harness_url}{path}")
    expect(authed_page.get_by_text(expected_text, exact=False).first).to_be_visible()


def test_sign_out_link_points_at_cf_access_team_domain(authed_page, harness_url):
    """PAT-1585: not clicked - the harness's team domain isn't a real,
    reachable Cloudflare Access tenant, so this only asserts the link is
    present and correctly formed, not that Cloudflare's own logout flow
    works (that needs a live session, see the ticket's verification note)."""
    authed_page.goto(f"{harness_url}/")
    link = authed_page.get_by_role("link", name="Sign out")
    expect(link).to_be_visible()
    assert link.get_attribute("href") == "https://e2e-harness.cloudflareaccess.com/cdn-cgi/access/logout"


def test_device_reporting_tabs_switch_rows_update_url_and_compose_with_search(
    authed_page, harness_url,
):
    """PAT-1843: one page switches authoritative reporting buckets without
    reloading, bookmarks the selected view and keeps search independent."""
    authed_page.goto(f"{harness_url}/devices")
    normal_rows = authed_page.locator('tr[data-filter-view="normal"]')
    quiet_rows = authed_page.locator('tr[data-filter-view="quiet"]')

    authed_page.get_by_role("link", name="Reporting normally", exact=False).click()
    expect(authed_page).to_have_url(f"{harness_url}/devices?view=normal")
    expect(normal_rows.first).to_be_visible()
    if quiet_rows.count():
        expect(quiet_rows.first).to_be_hidden()

    search = authed_page.get_by_role("searchbox", name="Search devices")
    search.fill("definitely-not-a-device")
    expect(normal_rows.first).to_be_hidden()
    empty = authed_page.get_by_text("No devices match this reporting state and search.")
    expect(empty).to_be_visible()
    search.fill("")
    expect(normal_rows.first).to_be_visible()


def test_overview_reporting_loss_cta_shows_the_exact_24_hour_roster(
    authed_page, harness_url,
):
    """The overview alert must not send a 24-hour reporting gap to the
    broader silent default, which would omit recently-lost reporting."""
    authed_page.goto(f"{harness_url}/")
    assert authed_page.locator(".attention-summary__item").first.evaluate(
        "el => getComputedStyle(el).display"
    ) == "grid"
    authed_page.get_by_role(
        "link", name="View affected devices and last seen times"
    ).click()
    expect(authed_page).to_have_url(
        f"{harness_url}/devices?view=not_reporting_24h"
    )
    row = authed_page.locator("#device-table tbody tr").filter(
        has_text="acme-win-accounts"
    )
    expect(row).to_be_visible()
    expect(row.locator(".last-seen")).to_have_text(
        re.compile(r"\d{2} \w{3} \d{4} \d{2}:\d{2} UTC")
    )


def test_generate_report_submits_real_form(authed_page, harness_url):
    """Drives the real /reports 'Generate report' button in the browser,
    then confirms the stub platform actually received the POST - not just
    that the portal rendered a 'success' page."""
    before = STUB_STATE["generate_calls"]
    authed_page.goto(f"{harness_url}/reports")
    authed_page.locator(
        "form[action='/reports/generate']:has("
        "input[name='report_type'][value='executive-summary'])"
    ).get_by_role("button", name="Generate report").click()
    expect(authed_page).to_have_url(f"{harness_url}/reports?generated=1")
    expect(authed_page.get_by_text("Report generation requested")).to_be_visible()
    assert STUB_STATE["generate_calls"] == before + 1
    assert STUB_STATE["generate_posts"][-1] == {"report_type": "executive-summary"}


def test_save_schedule_submits_real_form(authed_page, harness_url):
    """Fills and submits the real schedule form, then confirms the stub
    platform received the PUT with the values chosen in the browser."""
    before = len(STUB_STATE["typed_schedule_puts"])
    authed_page.goto(f"{harness_url}/reports")
    authed_page.select_option("#sched-cadence", "weekly")
    authed_page.select_option("select[name='weekday']", "1")
    authed_page.select_option("select[name='hour_utc']", "9")
    enabled = authed_page.locator("input[name='enabled']")
    if not enabled.is_checked():
        enabled.check()
    authed_page.get_by_role("button", name="Save schedule").click()
    expect(authed_page).to_have_url(
        f"{harness_url}/reports?schedule_saved=1&schedule_type=executive-summary"
    )
    expect(authed_page.get_by_text("Schedule saved")).to_be_visible()

    assert len(STUB_STATE["typed_schedule_puts"]) == before + 1
    report_type, sent = STUB_STATE["typed_schedule_puts"][-1]
    assert report_type == "executive-summary"
    assert sent["cadence"] == "weekly"
    assert sent["weekday"] == 1
    assert sent["hour_utc"] == 9
    assert sent["enabled"] is True


def test_generate_enrolment_token_submits_real_form(authed_page, harness_url):
    """Clicks the real /install 'Generate a one-off install token' button,
    then confirms the stub platform received the expected POST body and
    that the minted token is actually rendered back into the page."""
    before = STUB_STATE["enrolment_calls"]
    authed_page.goto(f"{harness_url}/install")
    authed_page.get_by_role("button", name="Generate a one-off install token").click()
    # The token also appears embedded inside the macOS/Windows artifacts
    # below it, so target the dedicated token element rather than matching
    # its text anywhere on the page.
    expect(authed_page.locator("#enrolment-token")).to_have_text("enr-tok-abc123xyz789")

    assert STUB_STATE["enrolment_calls"] == before + 1
    assert STUB_STATE["enrolment_posts"][-1] == {"delivery_path": "mdm"}


def test_invalid_token_does_not_render_estate_content(browser, harness_url, run_errors):
    """Negative control (PAT-1021 brief). The harness stub still rejects any
    token that is not its own sentinel, so a bad token here must still hit
    the real fail-closed 401 path - proving the harness has not quietly
    disabled auth everywhere, only accepted the one token the tests above
    present on purpose."""
    context, page = _new_authed_page(browser, harness_url, run_errors, "not-the-harness-token")
    try:
        response = page.goto(f"{harness_url}/devices")
        assert response.status == 401
        expect(page.get_by_role("heading", name="Your session has expired")).to_be_visible()
        expect(page.get_by_text("acme-mbp-frontdesk")).not_to_be_visible()
    finally:
        context.close()
