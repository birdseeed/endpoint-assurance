"""PAT-2325: every table in the portal carries the shared table styling.

`/requests` (My requests) shipped with a bare `<table>`. The portal's table
alignment, cell padding and phone stacking all hang off `.data-table` (and
`.table-stack` with per-cell `data-label`), so the bare table rendered
centred headers over left-aligned, unpadded cells, ran two dates together and
put the Status pills off-column. Nothing failed, because no test looked at
the markup and the stub walk redirects `/requests` away when feedback is off.

This reads every template under `templates/` as text, so it also covers
templates that only render for a customer state the stub platform does not
reach. A `<table` whose class attribute has no `data-table` token fails, and
the message names the template file and line.
"""

import re
from html.parser import HTMLParser
from pathlib import Path

from tests.conftest import STUB_STATE

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"

# Template comments can mention `<table` without rendering one. Blanked, not
# removed, so line numbers still match the file on disk.
_COMMENT_RE = re.compile(r"\{#.*?#\}|<!--.*?-->", re.DOTALL)

# One Jinja construct: a tag, an expression or a comment. `>` inside one (for
# example `{% if devices|length > 1 %}`) must not end the `<table ...>` tag.
_JINJA = r"\{%.*?%\}|\{\{.*?\}\}|\{#.*?#\}"
_TABLE_TAG_RE = re.compile(rf"<table\b(?:{_JINJA}|[^>])*>", re.DOTALL | re.IGNORECASE)
_CLASS_ATTR_RE = re.compile(r"""\bclass\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.IGNORECASE)
_DATA_TABLE_TOKEN_RE = re.compile(r"(?<![\w-])data-table(?![\w-])")


def _blank(match: re.Match) -> str:
    return re.sub(r"[^\n]", " ", match.group(0))


def unstyled_tables(source: str) -> list[tuple[int, str]]:
    """Line number and tag text of every `<table` without a `data-table` class."""
    visible = _COMMENT_RE.sub(_blank, source)
    found = []
    for tag in _TABLE_TAG_RE.finditer(visible):
        text = tag.group(0)
        class_attr = _CLASS_ATTR_RE.search(text)
        value = (class_attr.group(1) or class_attr.group(2)) if class_attr else ""
        if not _DATA_TABLE_TOKEN_RE.search(value):
            found.append((visible.count("\n", 0, tag.start()) + 1, " ".join(text.split())))
    return found


def _template_tables() -> int:
    total = 0
    for path in sorted(TEMPLATES.rglob("*.html")):
        source = _COMMENT_RE.sub(_blank, path.read_text(encoding="utf-8"))
        total += len(_TABLE_TAG_RE.findall(source))
    return total


def test_every_template_table_carries_the_data_table_class():
    failures = []
    for path in sorted(TEMPLATES.rglob("*.html")):
        for line, tag in unstyled_tables(path.read_text(encoding="utf-8")):
            failures.append(f"{path.relative_to(TEMPLATES.parent)}:{line}: {tag}")
    assert not failures, (
        "A table without class=\"data-table\" renders unaligned and unpadded "
        "(PAT-2325). Add class=\"data-table table-stack\" and a data-label on "
        "each cell:\n  " + "\n  ".join(failures)
    )


def test_the_scan_reaches_the_portal_tables():
    # A path or glob mistake would make the guard above pass vacuously.
    assert (TEMPLATES / "feedback_requests.html").is_file()
    assert _template_tables() >= 40


def test_checker_flags_a_bare_table_with_its_line():
    source = "<div>\n  <table>\n    <tr></tr>\n  </table>\n</div>\n"
    assert unstyled_tables(source) == [(2, "<table>")]


def test_checker_flags_a_class_that_lacks_the_token():
    source = '<table class="table-stack device-table" id="x">\n</table>\n'
    assert [line for line, _ in unstyled_tables(source)] == [1]


def test_checker_does_not_accept_a_lookalike_class():
    source = '<table class="data-table-lite">\n</table>\n<table class="my-data-table">\n</table>\n'
    assert [line for line, _ in unstyled_tables(source)] == [1, 3]


def test_checker_accepts_a_styled_table_in_any_form():
    source = (
        '<table class="data-table table-stack">\n</table>\n'
        "<table class='table-stack data-table'>\n</table>\n"
        '<TABLE\n  id="x"\n  class="data-table {% if a > b %}wide{% endif %}">\n</TABLE>\n'
    )
    assert unstyled_tables(source) == []


def test_checker_ignores_a_table_named_only_in_a_comment():
    source = "{# a <table> here is prose #}\n<!-- <table> -->\n"
    assert unstyled_tables(source) == []


class _Cells(HTMLParser):
    """The rendered table's class, and each body cell's data-label."""

    def __init__(self):
        super().__init__()
        self.table_classes = []
        self.labels = []
        self._in_body = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "table":
            self.table_classes.append(attrs.get("class") or "")
        elif tag == "tbody":
            self._in_body = True
        elif tag == "td" and self._in_body:
            self.labels.append(attrs.get("data-label"))

    def handle_endtag(self, tag):
        if tag == "tbody":
            self._in_body = False


def test_requests_page_renders_a_stacked_labelled_table(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["feedback_enabled"] = True
    STUB_STATE["feedback_rows"] = [{
        "reference": "FB-1", "type": "feature", "title": "A title", "status": "received",
        "created_at": "2026-09-28T16:26:00Z", "last_status_change": "2026-09-28T18:16:00Z",
    }]
    response = client.get("/requests", headers={"Cf-Access-Jwt-Assertion": token})
    assert response.status_code == 200
    cells = _Cells()
    cells.feed(response.text)
    assert len(cells.table_classes) == 1
    assert {"data-table", "table-stack"} <= set(cells.table_classes[0].split())
    assert cells.labels == ["Reference", "Type", "Title", "Status", "Received", "Last update"]
    # Each date is kept whole, so two of them can never run together.
    assert response.text.count('<span class="nowrap">28 Sep 2026</span>') == 2
