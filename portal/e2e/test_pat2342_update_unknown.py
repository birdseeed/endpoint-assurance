"""Update currency's four buckets remain visible across layouts and themes."""

import copy
import os
from pathlib import Path

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.walk.walk import THEME_STORAGE_KEY
from tests.conftest import OVERVIEW, STUB_STATE


@pytest.mark.parametrize("width", [1440, 1280, 390])
@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("layout", ["compact-current", "full-current", "full-stale"])
@pytest.mark.parametrize("state", ["mixed", "all-unknown", "invalid"])
def test_update_buckets_remain_visible(
    browser, harness_url, monkeypatch, width, theme, layout, state,
):
    data = copy.deepcopy(OVERVIEW)
    data["devices_reporting_24h"] = 0 if layout == "full-stale" else 11
    data["findings_open"] = {
        "critical": 0, "high": int(layout == "full-current"), "medium": 5, "low": 2,
    }
    patch = ({"up_to_date": 0, "pending": 0, "failed": 0, "unknown": 12}
             if state == "all-unknown"
             else {"up_to_date": 4, "pending": 2, "failed": 1,
                   "unknown": True if state == "invalid" else 5})
    data["patch_status"] = patch
    monkeypatch.setitem(STUB_STATE, "overview_data", data)
    context = browser.new_context(viewport={"width": width, "height": 900})
    context.add_cookies([{"name": "CF_Authorization", "value": HARNESS_VALID_TOKEN,
                         "url": harness_url}])
    context.add_init_script(f"localStorage.setItem('{THEME_STORAGE_KEY}', '{theme}')")
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/", wait_until="networkidle")
        assert page.locator("html").get_attribute("data-theme") == theme
        assert page.locator(".cis-compact").count() == int(layout == "compact-current")
        band = page.locator("section.card").filter(
            has=page.get_by_role("heading", name="Update currency", exact=True))
        assert band.count() == 1
        expected = [str(patch[k]) for k in ("up_to_date", "pending", "failed")]
        expected.append("Not reported" if state == "invalid" else str(patch["unknown"]))
        assert band.locator(".stat-name").all_text_contents() == [
            "Up to date", "Pending", "Failed", "Unknown"]
        assert band.locator(".stat-num").all_text_contents() == expected
        assert band.locator(".posture-caveat").count() == int(layout == "full-stale")
        band.scroll_into_view_if_needed()
        for stat in band.locator(".stat").all():
            assert stat.is_visible()
            assert stat.evaluate("el => el.scrollWidth <= el.clientWidth + 1"), (
                f"bucket overflows at {width}/{theme}/{layout}/{state}: {stat.inner_text()}"
            )
        assert page.evaluate(
            "document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1")
        evidence = os.environ.get("PAT2342_EVIDENCE_DIR")
        if evidence:
            Path(evidence).mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(Path(evidence) / f"{width}-{theme}-{layout}-{state}.png"),
                            full_page=True)
    finally:
        context.close()
