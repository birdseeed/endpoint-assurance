"""PAT-2254 in a real browser: software review lives in /software, so the
Overview's New software card is read only and everything on it opens
/software. It also carries the PAT-2139 clause that survives the move: the
products still waiting on a decision stay findable on /software.

Also the layout of the one card whose headline gained a label (Reporting and
agent health: "3" now reads "3 with collection issues"), checked for clipping
at desktop and phone widths in both themes.

Fast, template-level coverage (counts identical in Top 3, the glance line and
the card, no controls in the markup, the link parameters) lives in
tests/test_pat2254_overview_truthful.py.
"""

import copy
import re

from e2e.conftest import HARNESS_VALID_TOKEN
from tests.conftest import OVERVIEW, OVERVIEW_CARDS, STUB_STATE

PRODUCTS = (
    ("UpdateST", "com.example.updatest", "critical"),
    ("WiFiman", "com.example.wifiman", "not_assessed"),
    ("notchi", "com.example.notchi", "not_assessed"),
)


def _new_software_product(name, identifier, urgency):
    return {
        "name": name, "platform": "macos", "identifier": identifier,
        "team_id": "ABCDE12345", "product_key": f"application:macos:{identifier}",
        "approval_state": "unreviewed", "first_seen_at": "2026-09-24T20:51:00Z",
        "device_count": 1, "urgency": urgency,
        "reasons": [{"code": "signing_unknown", "level": urgency,
                    "detail": f"{name} has not been assessed yet"}],
    }


def _new_software_block():
    counts = {"critical": 0, "high": 0, "not_assessed": 0, "medium": 0, "low": 0}
    for _, _, urgency in PRODUCTS:
        counts[urgency] += 1
    return {
        "since": "2026-09-10T12:00:00Z", "since_basis": "default_window",
        "until": "2026-09-25T12:00:00Z", "window_days": 14, "last_review_at": None,
        "total": len(PRODUCTS), "counts": counts,
        "excluded": {"approved": 0, "ignored": 0, "patched_agent": 0},
        "truncated": False, "limit": 50,
        "products": [_new_software_product(name, identifier, urgency)
                     for name, identifier, urgency in PRODUCTS],
    }


def _application_row(name, identifier):
    return {
        "type": "application", "name": name, "identifier": identifier,
        "platform": "macos", "policy_state": "undecided", "enforcement_tier": "",
        "device_count": 1, "evidence_basis": "identifier_match",
        "identifier_matched_devices": 1, "name_matched_devices": 0,
        "removal_state": "not_available", "decided_by": None, "decided_at": None,
        "justification": None, "version_count": 1, "team_id": "ABCDE12345",
        "signed_by": None, "notarized": None,
    }


def _applications_data():
    return {
        "total": len(PRODUCTS), "truncated": False, "estate_too_large": False,
        "applications": [_application_row(name, identifier) for name, identifier, _ in PRODUCTS],
    }


def _context(browser, harness_url, color_scheme="light"):
    context = browser.new_context(base_url=harness_url, color_scheme=color_scheme)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def test_overview_has_no_review_controls_and_a_product_opens_in_software(browser, harness_url):
    STUB_STATE["portal_role"] = "admin"
    STUB_STATE["overview_data"] = {**OVERVIEW, "new_software": _new_software_block()}
    STUB_STATE["applications_data"] = _applications_data()
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.goto("/", wait_until="networkidle")
        for name, _, _ in PRODUCTS:
            link = page.locator(".new-software-table").get_by_role("link", name=name, exact=True)
            assert link.count() == 1, name

        # Read only: an administrator sees no state selector, Apply button or
        # approval form anywhere on the page.
        assert page.locator("select[data-approval-row-state]").count() == 0
        assert page.locator("form[action='/software/approvals']").count() == 0
        assert page.get_by_role("button", name="Apply").count() == 0
        assert page.locator("th", has_text="Approval").count() == 0

        # A product opens in /software, where it can be reviewed.
        page.locator(".new-software-table").get_by_role(
            "link", name="UpdateST", exact=True).click()
        page.wait_for_url(re.compile(r"/software\?search=UpdateST"))
        row = page.locator('tr[data-approval-row]', has_text="UpdateST")
        assert row.count() == 1
        assert row.locator("select[data-approval-row-state]").count() == 1

        # PAT-2139's surviving clause: the other undecided products are
        # findable on /software.
        page.goto("/software", wait_until="networkidle")
        waiting = page.locator('tr[data-approval-row][data-filter-decision="waiting"]')
        for name in ("UpdateST", "WiFiman", "notchi"):
            assert waiting.filter(has_text=name).count() == 1, name
    finally:
        context.close()


def test_urgency_counts_and_waiting_links_open_software_with_their_filters(browser, harness_url):
    STUB_STATE["overview_data"] = {**OVERVIEW, "new_software": _new_software_block()}
    STUB_STATE["applications_data"] = _applications_data()
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.goto("/", wait_until="networkidle")
        page.locator(".new-software a.kpi__item", has_text="Critical").click()
        page.wait_for_url(re.compile(r"/software\?new_days=14&urgency=critical$"))

        page.goto("/", wait_until="networkidle")
        page.locator(".welcome-block").get_by_role(
            "link", name=re.compile(r"Decide on \d+ products? waiting")).click()
        page.wait_for_url(re.compile(r"/software\?approval=waiting$"))
        # The approval filter is one /software genuinely reads today.
        assert page.locator("input[name='approval'][value='waiting']").is_checked()
    finally:
        context.close()


def _agent_health_cards(degraded):
    data = copy.deepcopy(OVERVIEW_CARDS)
    card = data["cards"]["agent_health"]
    card["state"] = "value"
    card["completeness"] = {"complete": True, "reason": None}
    card["values"] = {
        "devices_degraded": degraded, "devices_reporting": 4, "devices_not_reporting": 0,
        "oldest_successful_ingest": "2026-12-15T09:00:00Z",
    }
    return data


CLIPPED_JS = """
() => {
  const unit = document.querySelector('[data-card="agent_health"] .ov-card__unit');
  const headline = document.querySelector('[data-card="agent_health"] .ov-card__headline');
  const card = document.querySelector('[data-card="agent_health"]');
  return {
    unitClipped: unit.scrollWidth > unit.clientWidth + 1,
    headlineClipped: headline.scrollWidth > headline.clientWidth + 1,
    unitText: unit.textContent.trim(),
    unitInsideCard: unit.getBoundingClientRect().right <= card.getBoundingClientRect().right + 1,
    docOverflow: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
  };
}
"""


def test_agent_health_label_reads_in_full_at_desktop_and_phone_widths(browser, harness_url):
    STUB_STATE["overview_data"] = {**OVERVIEW, "devices_degraded": 3}
    STUB_STATE["overview_cards_data"] = _agent_health_cards(3)
    for scheme in ("light", "dark"):
        context = _context(browser, harness_url, color_scheme=scheme)
        page = context.new_page()
        try:
            for width in (1440, 1280, 390):
                page.set_viewport_size({"width": width, "height": 1200})
                page.goto("/", wait_until="networkidle")
                result = page.evaluate(CLIPPED_JS)
                where = f"{scheme} {width}px"
                assert result["unitText"] == "with collection issues", where
                assert not result["unitClipped"], where
                assert not result["headlineClipped"], where
                assert result["unitInsideCard"], where
                assert not result["docOverflow"], where
        finally:
            context.close()
