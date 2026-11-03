"""Report history download links at phone and desktop width (PAT-2405).

The stub history is mixed: one report with a PDF and a CSV, one with PDF only
(plus the short note), and one from an older platform with no `formats` field.
The page must not scroll sideways, no cell may run into the next, and the
download buttons must not wrap their labels mid-word.
"""

import os
from pathlib import Path

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.walk.walk import check_cells, check_overflow

SHOT_DIR = os.environ.get("PAT2405_SHOT_DIR")


@pytest.mark.parametrize("width", [390, 1280])
def test_report_history_downloads_fit(browser, harness_url, width):
    context = browser.new_context(
        base_url=harness_url, viewport={"width": width, "height": 900})
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/reports", wait_until="networkidle")
        history = page.locator(".card-table")
        rows = history.locator("tbody tr")
        assert rows.count() == 3
        assert history.get_by_role("link", name="Download PDF").count() == 3
        assert history.get_by_role("link", name="Download CSV").count() == 1
        assert history.get_by_text("CSV is available for newly generated reports.").count() == 1
        # Button labels stay on one line: a single line box is as tall as the button's text.
        for label in ("Download PDF", "Download CSV"):
            for link in history.get_by_role("link", name=label).all():
                box = link.bounding_box()
                assert box and box["height"] < 44, f"{label} wrapped at {width}px: {box}"
        scroll = page.evaluate(
            "document.documentElement.scrollWidth - document.documentElement.clientWidth")
        assert scroll <= 0, f"page scrolls sideways by {scroll}px at {width}px"
        findings = check_overflow(page, "/reports", width, "light")
        findings += check_cells(page, "/reports", width, "light")
        assert not findings, "\n".join(f.detail for f in findings)
        if SHOT_DIR:
            Path(SHOT_DIR).mkdir(parents=True, exist_ok=True)
            page.locator(".card-table").screenshot(path=f"{SHOT_DIR}/reports-history-{width}.png")
    finally:
        context.close()
