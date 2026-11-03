"""PAT-2509: the Version sprawl "Latest released" cell shows plain wording.

The platform now sends each product's latest-released source as
`{"name": <machine name>, "label": <plain wording>, "url": ..., "checked_at": ...}`.
The portal renders the label and the date it was last checked, never the
machine name (`curated_catalogue` read as internal wording on the page), and
it must cope with an older platform that sends no label. A product with no
known latest release reads "Not known".
"""

import copy
import html as html_lib
import re
from pathlib import Path

import pytest

from tests.conftest import STUB_STATE, VERSION_SPRAWL_SUMMARY

ROOT = Path(__file__).resolve().parent.parent
MACHINE_NAME = "curated_catalogue"
ROUTE = "/reports/software/version-sprawl"


def _get(client, token, path=ROUTE):
    STUB_STATE["expected_jwt"] = token
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _latest_cell(body, name):
    """(inner HTML, visible text) of the Latest released cell of the product
    called `name`. The first occurrence of the name is in that row's own
    Product cell, so the next Latest released cell is the row's."""
    start = body.index(name)
    cell_start = body.index('<td data-label="Latest released">', start)
    inner = body[cell_start:body.index("</td>", cell_start)]
    text = html_lib.unescape(re.sub(r"<[^>]+>", "", inner))
    return inner, " ".join(text.split())


def _product(name, latest, source, platform="macos"):
    row = copy.deepcopy(next(p for p in VERSION_SPRAWL_SUMMARY["products"]
                             if p["name"] == "SingleVersionApp"))
    row.update({"name": name, "platform": platform, "latest_released": latest,
                "latest_released_source": source})
    return row


def _serve_products(*rows):
    STUB_STATE["version_sprawl_data"] = {
        **VERSION_SPRAWL_SUMMARY, "products": list(rows), "total": len(rows)}


# ── the four cases ───────────────────────────────────────────────────────────

def test_label_date_and_https_url_render_a_linked_label_and_the_checked_date(client, make_token):
    body = _get(client, make_token()).text
    inner, text = _latest_cell(body, "ManyVersionApp")
    assert text == "10.4.0 endoflife.date, checked 05 Oct 2026"
    assert ('<a href="https://endoflife.date/manyversionapp" target="_blank" '
            'rel="noopener noreferrer">endoflife.date</a>') in inner
    assert '<span class="mono">10.4.0</span>' in inner


def test_label_and_date_without_a_url_render_plain_text(client, make_token):
    body = _get(client, make_token()).text
    inner, text = _latest_cell(body, "SingleVersionApp")
    assert text == "2.1.0 Patched reference list, checked 05 Oct 2026"
    assert "<a " not in inner


def test_a_value_with_a_source_that_has_no_label_shows_the_version_and_no_source(
        client, make_token):
    """An older platform sends the machine name and no label. The portal shows
    the version alone: no source line, and never the machine name."""
    body = _get(client, make_token()).text
    inner, text = _latest_cell(body, "OlderPlatformApp")
    assert text == "3.2.1"
    assert "cell-subtle" not in inner
    assert "<a " not in inner


def test_no_value_reads_not_known(client, make_token):
    body = _get(client, make_token()).text
    inner, text = _latest_cell(body, "UnknownLatestApp")
    assert text == "Not known"
    assert "Unknown" not in inner


def test_a_label_with_no_checked_date_shows_the_label_alone(client, make_token):
    body = _get(client, make_token()).text
    inner, text = _latest_cell(body, "NotAssessedApp")
    assert text == "5.0 endoflife.date"
    assert "checked" not in inner
    assert 'href="https://endoflife.date/notassessedapp"' in inner


# ── the machine name never reaches a customer ───────────────────────────────

def test_the_machine_name_is_absent_from_the_page_for_every_fixture_row(client, make_token):
    products = VERSION_SPRAWL_SUMMARY["products"]
    names = {(p["latest_released_source"] or {}).get("name") for p in products}
    assert MACHINE_NAME in names, "the fixture must still carry a curated_catalogue row"
    assert any(p["latest_released_source"] and not p["latest_released_source"].get("label")
               for p in products), "the fixture must carry a source with no label"
    body = _get(client, make_token()).text
    assert MACHINE_NAME not in body
    assert MACHINE_NAME not in body.lower()


CHECKED = "2026-10-05T01:02:00Z"


@pytest.mark.parametrize("source,expected", [
    ({"name": MACHINE_NAME, "url": "", "label": "Patched reference list", "checked_at": CHECKED},
     "1.2.3 Patched reference list, checked 05 Oct 2026"),
    ({"name": MACHINE_NAME, "url": "", "label": "Patched reference list", "checked_at": None},
     "1.2.3 Patched reference list"),
    # No usable label: no source line at all, so no date or link on its own either.
    ({"name": MACHINE_NAME, "url": "", "checked_at": CHECKED}, "1.2.3"),
    ({"name": MACHINE_NAME, "url": "", "label": "", "checked_at": CHECKED}, "1.2.3"),
    ({"name": MACHINE_NAME, "url": "", "label": "   ", "checked_at": CHECKED}, "1.2.3"),
    ({"name": MACHINE_NAME, "url": "", "label": None, "checked_at": CHECKED}, "1.2.3"),
    ({"name": MACHINE_NAME, "url": "", "label": 7, "checked_at": CHECKED}, "1.2.3"),
    ({"name": MACHINE_NAME, "url": "https://example.test/ref", "checked_at": CHECKED}, "1.2.3"),
], ids=["label-date", "label-no-date", "no-label-key", "empty-label", "blank-label",
        "null-label", "non-string-label", "no-label-with-url"])
def test_the_machine_name_is_never_rendered_whatever_the_source_shape(
        client, make_token, source, expected):
    _serve_products(_product("ShapeApp", "1.2.3", source))
    body = _get(client, make_token()).text
    _, text = _latest_cell(body, "ShapeApp")
    assert text == expected
    assert MACHINE_NAME not in body


# ── the source link ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "http://example.test/insecure",
    "javascript:alert(1)",
    "//example.test/protocol-relative",
    "ftp://example.test/file",
    "example.test/no-scheme",
    "HTTP://example.test/upper",
    "",
    None,
    42,
], ids=["http", "javascript", "protocol-relative", "ftp", "no-scheme", "upper-http",
        "empty", "null", "non-string"])
def test_a_source_url_that_is_not_https_is_not_rendered_as_a_link(client, make_token, url):
    _serve_products(_product("LinkApp", "1.2.3", {
        "name": "endoflife.date", "slug": "x", "url": url, "label": "endoflife.date",
        "checked_at": "2026-10-05T01:02:00Z"}))
    inner, text = _latest_cell(_get(client, make_token()).text, "LinkApp")
    assert "<a " not in inner
    assert "href" not in inner
    assert text == "1.2.3 endoflife.date, checked 05 Oct 2026"


def test_an_https_source_url_is_a_link_that_opens_safely(client, make_token):
    _serve_products(_product("LinkApp", "1.2.3", {
        "name": "endoflife.date", "slug": "x", "url": "https://endoflife.date/x",
        "label": "endoflife.date", "checked_at": "2026-10-05T01:02:00Z"}))
    inner, _ = _latest_cell(_get(client, make_token()).text, "LinkApp")
    assert 'href="https://endoflife.date/x"' in inner
    assert 'target="_blank"' in inner and 'rel="noopener noreferrer"' in inner


def test_a_label_is_escaped(client, make_token):
    _serve_products(_product("EscApp", "1.2.3", {
        "name": "endoflife.date", "url": "https://example.test/a",
        "label": "<script>alert(1)</script>", "checked_at": None}))
    body = _get(client, make_token()).text
    inner, _ = _latest_cell(body, "EscApp")
    assert "<script>alert(1)</script>" not in inner
    assert "&lt;script&gt;" in inner


# ── the checked date ─────────────────────────────────────────────────────────

def test_an_unparseable_checked_at_is_dropped_not_shown_raw(client, make_token):
    _serve_products(_product("DateApp", "1.2.3", {
        "name": "endoflife.date", "label": "endoflife.date", "checked_at": "last Tuesday"}))
    _, text = _latest_cell(_get(client, make_token()).text, "DateApp")
    assert text == "1.2.3 endoflife.date"


def test_the_checked_date_is_the_utc_date(client, make_token):
    """00:30 on 6 Oct at +01:00 is 23:30 on 5 Oct UTC; the filter every other
    date on the page uses says 5 Oct."""
    _serve_products(_product("DateApp", "1.2.3", {
        "name": "endoflife.date", "label": "endoflife.date",
        "checked_at": "2026-10-06T00:30:00+01:00"}))
    _, text = _latest_cell(_get(client, make_token()).text, "DateApp")
    assert text == "1.2.3 endoflife.date, checked 05 Oct 2026"


def test_the_checked_date_is_not_split_across_lines(client, make_token):
    inner, _ = _latest_cell(_get(client, make_token()).text, "ManyVersionApp")
    assert '<span class="nowrap">05 Oct 2026</span>' in inner


# ── row builder ──────────────────────────────────────────────────────────────

def test_the_row_builder_passes_the_label_url_and_date_and_not_the_name():
    from main import _version_sprawl_product_row
    raw = next(p for p in VERSION_SPRAWL_SUMMARY["products"] if p["name"] == "ManyVersionApp")
    row = _version_sprawl_product_row(raw)
    assert row["latest_released_source_label"] == "endoflife.date"
    assert row["latest_released_source_url"] == "https://endoflife.date/manyversionapp"
    assert row["latest_released_checked_at"].strftime("%Y-%m-%d") == "2026-10-05"
    assert not any(MACHINE_NAME in str(v) for v in row.values())


def test_the_row_builder_has_no_source_for_a_null_source():
    from main import _version_sprawl_product_row
    raw = next(p for p in VERSION_SPRAWL_SUMMARY["products"] if p["name"] == "UnknownLatestApp")
    row = _version_sprawl_product_row(raw)
    assert row["latest_released"] is None
    assert row["latest_released_source_label"] is None
    assert row["latest_released_source_url"] is None
    assert row["latest_released_checked_at"] is None


# ── no template names the machine source ────────────────────────────────────

def test_no_template_contains_the_machine_name():
    offenders = sorted(
        str(path.relative_to(ROOT)) for path in (ROOT / "templates").rglob("*")
        if path.is_file() and MACHINE_NAME in path.read_text(encoding="utf-8", errors="ignore"))
    assert offenders == []


# ── exports: the platform's label and the appended column pass straight through ──

def test_the_csv_carries_the_label_and_the_appended_checked_column(client, make_token):
    resp = _get(client, make_token(), ROUTE + ".csv")
    assert resp.status_code == 200
    header, first, second = resp.text.splitlines()[:3]
    columns = header.split(",")
    assert columns[-1] == "latest_released_checked_at"
    assert columns[-2] == "generated_at"
    assert first.split(",")[columns.index("latest_released_source")] == "endoflife.date"
    assert second.split(",")[columns.index("latest_released_source")] == "Patched reference list"
    assert MACHINE_NAME not in resp.text


def test_the_pdf_is_built_from_the_csv_header_so_it_gains_the_column_too(client, make_token):
    resp = _get(client, make_token(), ROUTE + ".pdf")
    assert resp.status_code == 200
    body = STUB_STATE["table_pdf_posts"][-1]["body"]
    assert body["columns"][-1] == "latest_released_checked_at"
    assert "Patched reference list" in {row[body["columns"].index("latest_released_source")]
                                         for row in body["rows"]}
    assert MACHINE_NAME not in repr(body)
