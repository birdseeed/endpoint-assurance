"""PAT-2157 in a real browser: the "What's new" nav-rail link and its
unread dot, plus no-overflow at 390px on the /whats-new page itself.

Full validation/route-drift coverage lives in tests/test_pat2157_whats_new.py;
this file is the browser-only behaviour that pytest's TestClient cannot see:
real localStorage in a fresh context, the dot's visibility toggling on real
computed styles, and real layout at phone width.

Red-proofed against origin/main (39704dd): every test below fails there,
since neither the #rail-whats-new link, its data-whats-new-newest attribute,
the unread-dot script, nor /whats-new itself exist yet.
"""

import re
from datetime import date, timedelta

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN


def _context(browser, harness_url):
    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def test_whats_new_link_pinned_at_bottom_of_rail_above_support(browser, harness_url):
    """Desktop width so the rail renders without needing the burger. The
    link sits after the alphabetical nav list and above the Support
    contact block - checked by real bounding-box position, not just DOM
    order, since that is what "pinned at the bottom, above Support" means
    on screen."""
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})
        page.goto(f"{harness_url}/", wait_until="networkidle")

        link = page.locator("#rail-whats-new")
        support = page.locator(".rail__specialist")
        assert link.count() == 1
        assert support.count() == 1
        assert link.get_attribute("href") == "/whats-new"
        assert link.is_visible()

        link_box = link.bounding_box()
        support_box = support.bounding_box()
        assert link_box is not None and support_box is not None
        assert link_box["y"] < support_box["y"], (
            "the What's new link must sit above the Support contact block"
        )

        # Not one of the alphabetical rail__nav items - it must live outside
        # that list entirely (N1: Findings/Devices/Software/Exceptions/
        # Reports keep their stable position; nothing here should perturb
        # that list's contents).
        nav_items = page.locator(".rail__nav .rail__item").all_inner_texts()
        assert "What's new" not in nav_items
    finally:
        context.close()


def test_unread_dot_visible_fresh_context_then_clears_after_visit(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})

        page.goto(f"{harness_url}/", wait_until="networkidle")
        dot = page.locator("[data-whats-new-dot]")
        assert dot.is_visible(), "a fresh browser (no localStorage) must show the dot"

        page.goto(f"{harness_url}/whats-new", wait_until="networkidle")
        # Confirm the page actually rendered changelog content, so the
        # assertions below aren't vacuously true against an empty/broken
        # page.
        assert page.locator(".changelog-entry").count() > 0

        page.goto(f"{harness_url}/", wait_until="networkidle")
        dot_after = page.locator("[data-whats-new-dot]")
        assert not dot_after.is_visible(), (
            "visiting /whats-new must mark it seen and clear the dot on return"
        )
    finally:
        context.close()


def test_dot_has_accessible_label_not_colour_alone(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})
        page.goto(f"{harness_url}/", wait_until="networkidle")
        dot = page.locator("[data-whats-new-dot]")
        assert dot.is_visible()
        # The accessible name comes from visually-hidden text inside the
        # dot, not from colour alone.
        assert dot.inner_text().strip() != ""
    finally:
        context.close()


def test_no_overflow_at_390(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 390, "height": 900})
        page.goto(f"{harness_url}/whats-new", wait_until="networkidle")

        doc_metrics = page.evaluate(
            "() => ({scrollWidth: document.documentElement.scrollWidth, "
            "clientWidth: document.documentElement.clientWidth})"
        )
        assert doc_metrics["scrollWidth"] <= doc_metrics["clientWidth"], (
            f"/whats-new overflows the document at 390px: {doc_metrics}"
        )

        # Open the rail (off-canvas below 900px) and check it too - the
        # pinned What's new link/dot must not push it wider than the
        # viewport either.
        page.locator("#rail-burger").click()
        rail = page.locator("#rail")
        rail.wait_for(state="visible")
        link = page.locator("#rail-whats-new")
        assert link.is_visible()
        rail_metrics = page.evaluate(
            "(el) => ({scrollWidth: el.scrollWidth, clientWidth: window.innerWidth})",
            rail.element_handle(),
        )
        assert rail_metrics["scrollWidth"] <= rail_metrics["clientWidth"], (
            f"open rail overflows the viewport at 390px: {rail_metrics}"
        )
    finally:
        context.close()


@pytest.mark.parametrize("days_before, unread", [(1, True), (0, False)])
def test_weekly_seen_marker_returns_to_date_semantics(browser, harness_url, days_before, unread):
    """A deployed weekly marker must not suppress all future daily updates."""
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})
        page.goto(f"{harness_url}/", wait_until="networkidle")
        newest = page.locator("#rail-whats-new").get_attribute("data-whats-new-newest")
        seen = (date.fromisoformat(newest) - timedelta(days=days_before)).isoformat()
        page.evaluate(
            "value => localStorage.setItem('patched.whatsNewSeen', value)", f"week:{seen}"
        )
        page.reload(wait_until="networkidle")
        assert page.locator("[data-whats-new-dot]").is_visible() is unread
        assert page.evaluate("localStorage.getItem('patched.whatsNewSeen')") == seen

        page.goto(f"{harness_url}/whats-new", wait_until="networkidle")
        assert page.locator(".changelog-entry").count() > 0
        assert page.evaluate("localStorage.getItem('patched.whatsNewSeen')") == newest
        assert not page.locator("[data-whats-new-dot]").is_visible()
    finally:
        context.close()


def test_dot_clears_when_going_back_from_whats_new(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})
        page.goto(f"{harness_url}/", wait_until="networkidle")
        assert page.locator("[data-whats-new-dot]").is_visible()
        page.locator("#rail-whats-new").click()
        page.wait_for_url("**/whats-new")
        page.go_back(wait_until="networkidle")
        assert page.url.rstrip("/") == harness_url.rstrip("/")
        assert not page.locator("[data-whats-new-dot]").is_visible()
    finally:
        context.close()


def test_cached_page_repaints_unread_dot_on_pageshow(browser, harness_url):
    """Chromium disables bfcache in Playwright. Dispatch its persisted restore
    event on an already drawn page after a real visit has marked entries seen.
    A fresh navigation alone would rerun scripts and miss this regression.
    """
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})
        page.goto(f"{harness_url}/", wait_until="networkidle")
        dot = page.locator("[data-whats-new-dot]")
        assert dot.is_visible()
        visit = context.new_page()
        visit.goto(f"{harness_url}/whats-new", wait_until="networkidle")
        assert visit.locator(".changelog-entry").count() > 0
        visit.close()
        assert dot.is_visible(), "the cached page retains its original painted dot"
        page.evaluate(
            "window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true}))"
        )
        assert not dot.is_visible()
    finally:
        context.close()


@pytest.mark.parametrize("path", ["/", "/whats-new"])
def test_empty_changelog_has_no_unread_dot_or_seen_write(browser, harness_url, path):
    context = _context(browser, harness_url)
    try:
        def empty_newest(route):
            response = route.fetch()
            body, replaced = re.subn(
                r'data-whats-new-newest="[^"]*"', 'data-whats-new-newest=""',
                response.text(), count=1,
            )
            assert replaced == 1
            route.fulfill(response=response, body=body)

        # Exercise the browser contract for an empty changelog without changing
        # the shared harness's source file or history for another test.
        context.route(f"{harness_url}{path}", empty_newest)
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})
        page.goto(f"{harness_url}{path}", wait_until="networkidle")
        assert not page.locator("[data-whats-new-dot]").is_visible()
        assert page.evaluate("localStorage.getItem('patched.whatsNewSeen')") is None
    finally:
        context.close()
