"""PAT-2160 in a real browser: the "Top 3 actions" + "Your estate at a
glance" welcome block, above the "Needs attention" pill card (PAT-2159).

Andy's ruling (2026-09-25, "Actions only, trim duplicates"): actions are
the headline (first/left, stronger visual weight); the glance list is
trimmed to facts Needs attention does not already carry.

Full state-matrix coverage (unit level) lives in
tests/test_pat2160_estate_glance.py; this file is layout + link smoke
against a real rendered page, the same split PAT-2159's own e2e file uses.
"""

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.test_table_overflow import MEASURE_JS, WIDE_FALLBACK_FONT_CSS
from tests.conftest import OVERVIEW, OVERVIEW_CARDS_ZERO, STUB_STATE

FINDINGS_WITH_FIX = [
    {
        "cve_id": "CVE-2026-1234", "severity": "high", "cvss": 8.1,
        "app": "ExampleBrowser", "version": "124.0.1", "devices_affected": 4,
        "first_seen": "2026-12-20T08:00:00Z",
        "summary": "Use-after-free in the rendering engine.",
        "match_confidence": "version_confirmed", "fixed_version": "125.0.0",
    },
    {
        "cve_id": "CVE-2026-1235", "severity": "critical", "cvss": 9.1,
        "app": "ExampleBrowser", "version": "124.0.1", "devices_affected": 3,
        "first_seen": "2026-12-21T08:00:00Z",
        "summary": "Heap overflow parsing a crafted page.",
        "match_confidence": "version_confirmed", "fixed_version": "125.0.0",
    },
]

BUSY_OVERVIEW = {
    **OVERVIEW,
    "devices_total": 12,
    "devices_reporting_24h": 10,
    "findings_open": {"critical": 1, "high": 6, "medium": 5, "low": 2},
    "cve_attention": {"available": True, "critical": 1, "high": 1},
    "unapproved_alerts_open": 2,
    "unapproved_alerts_acknowledged": 0,
}


def _context(browser, harness_url):
    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def _assert_no_document_overflow(page):
    doc = page.evaluate(MEASURE_JS)
    assert doc["scrollWidth"] <= doc["clientWidth"] + 1, (
        f"document scrollWidth={doc['scrollWidth']} > clientWidth={doc['clientWidth']}"
    )


def test_welcome_block_renders_glance_and_actions_at_1280(browser, harness_url):
    STUB_STATE["overview_data"] = BUSY_OVERVIEW
    STUB_STATE["findings_data"] = FINDINGS_WITH_FIX
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/", wait_until="networkidle")

        assert page.locator(".welcome-block").count() == 1
        assert "Your estate at a glance" in page.content()
        assert "Top 3 actions" in page.content()

        actions = page.locator(".welcome-list--actions li")
        assert actions.count() >= 1
        first_action_text = actions.first.inner_text()
        assert "stopped reporting" in first_action_text

        # Trimmed glance content: device count only (no reporting-loss
        # clause), no confirmed-CVE-count line, no Unapproved-alert line -
        # each of those stays on Needs attention below.
        glance = page.locator(".welcome-col--glance")
        glance_text = glance.inner_text()
        assert "12 devices." in glance_text
        assert "not reporting" not in glance_text
        assert "confirmed" not in glance_text.lower()
        assert "unapproved" not in glance_text.lower()
    finally:
        context.close()


def test_actions_render_first_and_with_stronger_visual_weight(browser, harness_url):
    STUB_STATE["overview_data"] = BUSY_OVERVIEW
    STUB_STATE["findings_data"] = FINDINGS_WITH_FIX
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/", wait_until="networkidle")

        actions_box = page.locator(".welcome-col--actions").bounding_box()
        glance_box = page.locator(".welcome-col--glance").bounding_box()
        assert actions_box is not None and glance_box is not None
        # Actions sits to the left of glance at this width (the headline).
        assert actions_box["x"] < glance_box["x"]

        def heading_font_size(selector):
            return page.locator(selector).evaluate(
                "el => parseFloat(getComputedStyle(el).fontSize)"
            )

        actions_heading_size = heading_font_size(".welcome-col--actions h2")
        glance_heading_size = heading_font_size(".welcome-col--glance h2")
        assert actions_heading_size > glance_heading_size
    finally:
        context.close()


def test_welcome_block_links_resolve(browser, harness_url):
    STUB_STATE["overview_data"] = BUSY_OVERVIEW
    STUB_STATE["findings_data"] = FINDINGS_WITH_FIX
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/", wait_until="networkidle")

        block = page.locator(".welcome-block")
        links = block.locator("a")
        count = links.count()
        assert count >= 2
        seen = set()
        for i in range(count):
            href = links.nth(i).get_attribute("href")
            assert href and href.startswith("/")
            seen.add(href)
        # A representative sample of the real destinations this block
        # should be able to route to, each returning a real page.
        for href in seen:
            resp = page.request.get(href)
            assert resp.status < 400, f"{href} -> {resp.status}"
    finally:
        context.close()


def test_needs_attention_card_top_within_viewport_at_1280x800(browser, harness_url):
    STUB_STATE["overview_data"] = BUSY_OVERVIEW
    STUB_STATE["findings_data"] = FINDINGS_WITH_FIX
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.set_viewport_size({"width": 1280, "height": 800})
        page.goto("/", wait_until="networkidle")

        box = page.locator(".attention-summary").first.bounding_box()
        assert box is not None
        assert 0 <= box["y"] < 800, (
            f"Needs attention card top at y={box['y']} is below the 800px fold"
        )
    finally:
        context.close()


def test_no_overflow_at_390px(browser, harness_url):
    STUB_STATE["overview_data"] = BUSY_OVERVIEW
    STUB_STATE["findings_data"] = FINDINGS_WITH_FIX
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.add_style_tag(content=WIDE_FALLBACK_FONT_CSS)
        page.set_viewport_size({"width": 390, "height": 900})
        page.goto("/", wait_until="networkidle")
        _assert_no_document_overflow(page)
        assert page.locator(".welcome-block").count() == 1
    finally:
        context.close()


def test_nothing_needs_action_state_renders_cleanly(browser, harness_url):
    STUB_STATE["overview_data"] = {
        **OVERVIEW,
        "devices_total": 5,
        "devices_reporting_24h": 5,
        "findings_open": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "cve_attention": {"available": True, "critical": 0, "high": 0},
        "unapproved_alerts_open": 0,
        "unapproved_alerts_acknowledged": 0,
    }
    STUB_STATE["findings_data"] = []
    # Zero out "software waiting on a decision" too (rule 5), so every one
    # of rank_top_actions's six sources is genuinely clean, not just the
    # ones BUSY_OVERVIEW above happens to touch: no undecided applications,
    # and the one default-fixture undecided extension (MysteryHelper)
    # resolved via the same approval-overrides overlay POST /software/
    # approvals writes use, rather than editing the shared EXTENSIONS
    # fixture itself.
    STUB_STATE["applications_data"] = {
        "total": 0, "truncated": False, "estate_too_large": False, "applications": [],
    }
    # PAT-2254: Top 3 actions reads the platform's Software awaiting approval
    # card for this figure, so a clean estate says so there as well.
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_ZERO
    STUB_STATE["approval_overrides"] = {("browser_extension", "firefox", "mysteryhelper-ext-id"):
                                         "approved"}
    # Rule 6 (CVE assessment coverage below 50%) must also stay quiet - the
    # shared default CVE_ASSESSMENT_TENANT fixture is 30% covered, which
    # would fire it on its own.
    STUB_STATE["cve_assessment_data"] = {
        "last_feed_sync_at": "2026-09-22T01:04:12Z",
        "last_full_match_at": "2026-09-22T01:09:40Z",
        "queued_observations": 0,
        "assessed_products": 10, "pending_products": 0, "not_assessed_products": 0,
    }
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/", wait_until="networkidle")
        assert "Nothing needs action right now." in page.content()
        _assert_no_document_overflow(page)
    finally:
        context.close()
