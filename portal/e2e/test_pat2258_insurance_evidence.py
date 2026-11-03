"""PAT-2258 in a real browser: /reports/insurance-evidence at 1280px and
390px, light and dark. Every question renders (both groups, the "Not
evidenced by Patched" group included), nothing overflows the page or a
question block, the PDF and CSV buttons download the platform's files, and
an answer's source link reaches the portal view it names.

Rendering, copy and proxy coverage against the stub lives in
tests/test_pat2258_insurance_evidence.py; fixture data is tests/conftest.py's
INSURANCE_EVIDENCE, the platform's real JSON for a seeded estate.
"""

import os

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.test_table_overflow import MEASURE_JS
from tests.conftest import INSURANCE_EVIDENCE, INSURANCE_EVIDENCE_PDF

PAGE = "/reports/insurance-evidence"
SHOT_DIR = os.environ.get("PAT2258_SHOT_DIR")

BLOCK_OVERFLOW_JS = """
() => Array.from(document.querySelectorAll('.insurance-item, .kpi, .card')).filter(
  (el) => el.scrollWidth > el.clientWidth + 1
).map((el) => ({
  cls: el.className, id: el.id, scrollWidth: el.scrollWidth, clientWidth: el.clientWidth,
}))
"""


def _context(browser, harness_url, color_scheme):
    context = browser.new_context(base_url=harness_url, color_scheme=color_scheme,
                                  accept_downloads=True)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("width", [1280, 390])
def test_every_question_renders_without_overflow(browser, harness_url, width, theme):
    context = _context(browser, harness_url, theme)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": width, "height": 1000})
        resp = page.goto(PAGE, wait_until="networkidle")
        assert resp.status == 200
        assert page.evaluate("document.documentElement.getAttribute('data-theme')") == theme

        for q in INSURANCE_EVIDENCE["questions"]:
            heading = page.locator(f"#q-{q['id']}-title")
            assert heading.count() == 1, q["id"]
            assert heading.inner_text().strip() == q["title"]
        not_evidenced = page.locator(
            "section[aria-labelledby='ie-not-evidenced-heading'] .insurance-item")
        assert not_evidenced.count() == 5

        doc = page.evaluate(MEASURE_JS)
        assert doc["scrollWidth"] <= doc["clientWidth"] + 1, doc
        overflowing = page.evaluate(BLOCK_OVERFLOW_JS)
        assert not overflowing, overflowing

        for label in ("Download PDF", "Download CSV"):
            btn = page.get_by_role("link", name=label)
            assert btn.is_visible()
            box = btn.bounding_box()
            assert box and box["x"] >= 0 and box["x"] + box["width"] <= width + 1, (label, box)

        if SHOT_DIR:
            page.screenshot(
                path=os.path.join(SHOT_DIR, f"insurance-{width}-{theme}.png"), full_page=True)
    finally:
        context.close()


def test_pdf_and_csv_buttons_download_the_platform_files(browser, harness_url):
    context = _context(browser, harness_url, "light")
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto(PAGE, wait_until="networkidle")
        with page.expect_download() as info:
            page.get_by_role("link", name="Download PDF").click()
        pdf = info.value
        assert pdf.suggested_filename.endswith(".pdf")
        with open(pdf.path(), "rb") as fh:
            assert fh.read() == INSURANCE_EVIDENCE_PDF
        with page.expect_download() as info:
            page.get_by_role("link", name="Download CSV").click()
        csv_dl = info.value
        assert csv_dl.suggested_filename.endswith(".csv")
        with open(csv_dl.path(), encoding="utf-8") as fh:
            assert fh.readline().startswith("question_id,group,title,question,status")
    finally:
        context.close()


def test_source_link_reaches_the_named_view(browser, harness_url):
    context = _context(browser, harness_url, "light")
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto(PAGE, wait_until="networkidle")
        page.locator("#q-edr_coverage a[href='/ce-readiness']").click()
        page.wait_for_url("**/ce-readiness")
        assert page.locator("h1").inner_text().strip() == "Cyber Essentials readiness"
    finally:
        context.close()
