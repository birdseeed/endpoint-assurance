"""PAT-2329 browser coverage: the dense-page note under 768px.

Andy's ruling of 2026-09-30: phones are a supported quick-look tier. The pages
in `main.PHONE_SUPPORTED_ROUTES` are built for a 390px screen; every other
signed-in page says "This page is best viewed on a larger screen." once, under
its heading, below 768px. It is drawn by portal.css (`.page--dense >
.page-head::after`), so this reads the pseudo-element's computed style: it must
be a block under 768px, absent from 768px up, absent from a phone-supported
page at any width, and it must take its space inside the heading block, below
the heading's own text, rather than overlay it. The server side (which
responses carry `.page--dense`) is `tests/test_pat2329_phone_tier.py`.

"""

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from tests.conftest import STUB_STATE

NOTE = "This page is best viewed on a larger screen."

DENSE = [
    "/software/alerts/1",
    "/software", "/findings", "/devices", "/devices/dev-mac-001/compliance",
    "/devices/dev-mac-001/software", "/reports", "/install", "/homebrew", "/ai-tooling",
    "/ce-readiness",
]
PHONE = ["/", "/software/alerts", "/devices/dev-mac-001", "/requests",
         "/feedback"]

# Every `.page-head` directly under <main> whose ::after is drawn as a block
# carrying the note.
VISIBLE_NOTES_JS = """
(note) => Array.from(document.querySelectorAll('main.page > .page-head')).filter((head) => {
  const after = getComputedStyle(head, '::after');
  return after.display === 'block' && after.content.includes(note);
}).length
"""

# The first heading block's height, with and without the note drawn.
HEAD_HEIGHT_JS = (
    "() => document.querySelector('main.page > .page-head').getBoundingClientRect().height")


@pytest.fixture
def open_page(browser, harness_url):
    STUB_STATE["feedback_enabled"] = True
    contexts = []

    def _open(path, width):
        context = browser.new_context(base_url=harness_url)
        contexts.append(context)
        context.add_cookies([{
            "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
        }])
        page = context.new_page()
        page.set_viewport_size({"width": width, "height": 900})
        response = page.goto(path, wait_until="networkidle")
        assert response is not None and response.status == 200, (path, response and response.status)
        return page

    yield _open
    for context in contexts:
        context.close()


def notes(page) -> int:
    return page.evaluate(VISIBLE_NOTES_JS, NOTE)


@pytest.mark.parametrize("path", DENSE)
@pytest.mark.parametrize("width", [390, 600, 767])
def test_a_dense_page_says_so_below_768px(open_page, path, width):
    assert notes(open_page(path, width)) == 1, (path, width)


@pytest.mark.parametrize("path", DENSE)
@pytest.mark.parametrize("width", [768, 1024, 1440])
def test_a_dense_page_is_silent_from_768px_up(open_page, path, width):
    assert notes(open_page(path, width)) == 0, (path, width)


@pytest.mark.parametrize("path", PHONE)
@pytest.mark.parametrize("width", [390, 767, 768, 1440])
def test_a_phone_supported_page_never_says_so(open_page, path, width):
    assert notes(open_page(path, width)) == 0, (path, width)


def test_a_page_with_three_headings_says_it_once(open_page):
    """install.html has three `.page-head` blocks."""
    page = open_page("/install", 390)
    assert page.locator("main.page > .page-head").count() == 3
    assert notes(page) == 1


def test_the_note_sits_inside_the_heading_block_below_its_text(open_page):
    """It takes its own line of space in the heading block (the page-head grows by
    the note's line plus margin), so it is below the heading's text, not over it."""
    page = open_page("/software", 390)
    with_note = page.evaluate(HEAD_HEIGHT_JS)
    page.add_style_tag(content="main.page > .page-head::after { display: none !important; }")
    without_note = page.evaluate(HEAD_HEIGHT_JS)
    assert 20 <= with_note - without_note <= 60, (with_note, without_note)


def test_the_note_is_muted_small_and_has_no_control(open_page):
    page = open_page("/software", 390)
    style = page.evaluate("""() => {
      const head = document.querySelector('main.page > .page-head');
      const after = getComputedStyle(head, '::after');
      const probe = document.createElement('span');
      probe.style.color = 'var(--mute)';
      document.body.appendChild(probe);
      const mute = getComputedStyle(probe).color;
      probe.remove();
      return {color: after.color, mute, size: after.fontSize};
    }""")
    assert style["color"] == style["mute"], style
    assert float(style["size"].removesuffix("px")) <= 14, style
    # Nothing to dismiss: no button or link is drawn for it, and nothing in the
    # page-head carries a dismiss hook.
    assert page.locator("main.page > .page-head button, main.page > .page-head [data-dismiss]"
                        ).count() == 0


def test_the_dense_page_still_shows_its_content_at_390px(open_page):
    """Nothing is blocked or hidden besides the note appearing."""
    page = open_page("/findings", 390)
    assert page.get_by_role("heading", name="Findings", level=1).is_visible()
    assert page.locator("main.page table, main.page .card").first.is_visible()
