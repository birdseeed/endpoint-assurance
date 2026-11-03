"""Declared software pages hold their layout at phone and laptop widths.

Runs against the stub platform only. Set PAT2393_SHOT_DIR to also save a
screenshot of each page.
"""
import os
from pathlib import Path

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.walk.walk import check_overflow
from tests.conftest import DECLARATION_FIXTURE, seed_declaration

PAGES = {
    "software": "/software",
    "add-empty": "/software/add",
    "add-search": "/software/add?query=Synthetic&platform=macos",
    "detail": f"/software/declarations/{DECLARATION_FIXTURE['id']}?query=Synthetic",
}


@pytest.fixture(autouse=True)
def seeded():
    seed_declaration()


@pytest.mark.parametrize("width", [1280, 390])
@pytest.mark.parametrize("name", list(PAGES))
def test_declaration_pages_do_not_overflow(browser, harness_url, name, width):
    context = browser.new_context(base_url=harness_url, viewport={"width": width, "height": 900})
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url}])
    try:
        page = context.new_page()
        page.goto(PAGES[name], wait_until="networkidle")
        if name == "software":
            row = page.locator("tr.declared-row")
            assert row.count() == 1
            text = row.inner_text()
            for expected in ("Declared", "Not observed", "Identity not yet matched"):
                assert expected in text
        if name == "add-search":
            assert page.locator("text=Synthetic known editor").count() >= 1
        if name == "detail":
            assert page.locator("form[action$='/resolve']").count() == 1
        shot_dir = os.environ.get("PAT2393_SHOT_DIR")
        if shot_dir:
            Path(shot_dir).mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(Path(shot_dir) / f"{name}-{width}.png"), full_page=True,
                            clip={"x": 0, "y": 0, "width": width,
                                  "height": min(1500, page.evaluate(
                                      "document.documentElement.scrollHeight"))})
        assert page.evaluate(
            "document.documentElement.scrollWidth <= document.documentElement.clientWidth"), (
            f"{name} scrolls horizontally at {width}px")
        assert check_overflow(page, PAGES[name], width, "light") == []
    finally:
        context.close()


EMPTY_PAGES = {
    "add-nothing-to-offer": "/software/add?query=Synthetic&platform=macos",
    "detail-nothing-to-offer": f"/software/declarations/{DECLARATION_FIXTURE['id']}",
}


@pytest.mark.parametrize("width", [1280, 390])
@pytest.mark.parametrize("name", list(EMPTY_PAGES))
def test_pages_hold_their_layout_with_nothing_to_offer(
        browser, harness_url, monkeypatch, name, width):
    """PAT-2404: no known products, so no lookup card and a plain statement."""
    from tests import conftest
    monkeypatch.setattr(conftest, "DECLARATION_PRODUCTS", [])
    context = browser.new_context(base_url=harness_url, viewport={"width": width, "height": 900})
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url}])
    try:
        page = context.new_page()
        page.goto(EMPTY_PAGES[name], wait_until="networkidle")
        assert page.locator("input[name='query']").count() == 0
        if name.startswith("add"):
            assert page.locator("text=Look up a known product").count() == 0
            assert page.locator("text=Approval details").count() == 1
        else:
            assert page.locator("text=Not yet matched to a known product").count() == 1
            assert page.locator("form[action$='/resolve']").count() == 0
        shot_dir = os.environ.get("PAT2393_SHOT_DIR")
        if shot_dir:
            Path(shot_dir).mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(Path(shot_dir) / f"{name}-{width}.png"), full_page=True)
        assert page.evaluate(
            "document.documentElement.scrollWidth <= document.documentElement.clientWidth")
        assert check_overflow(page, EMPTY_PAGES[name], width, "light") == []
    finally:
        context.close()
