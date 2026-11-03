"""Regression coverage for PAT-1326 Software Catalogue table density."""

from pathlib import Path

import main as dashboard


ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "static/css/console.css").read_text()
HTML = (ROOT / "templates/console.html").read_text()


def test_catalogue_table_uses_compact_header_and_body_padding():
    # PAT-1615: the compact 6px/8px row density now comes from the shared
    # .rdx-table--compact modifier (PAT-1601's table opted into by
    # #as-table's markup) instead of a dedicated #as-table th/td rule.
    assert 'id="as-table" class="rdx-table rdx-table--compact"' in HTML
    assert ".rdx-table--compact th, .rdx-table--compact td { padding: 6px 8px; }" in CSS


def test_catalogue_identity_and_details_share_the_second_line():
    assert "#as-table .as-app-id {\n  display: inline;" in CSS
    assert "#as-table .sc-details-btn { margin: 0 0 0 6px;" in CSS
    assert "'<div class=\"as-app-id\">'" in HTML
    assert 'class="sc-details-btn"' in HTML


def test_catalogue_badges_and_actions_are_compact_but_table_scoped():
    assert "#as-table .as-badge {" in CSS
    assert "#as-table .sc-manage-btn {" in CSS
    assert "font-size: var(--fs-xs);" in CSS
    assert "line-height: 1.35;" in CSS


def test_console_build_id_advances_for_catalogue_css_release():
    assert dashboard.CONSOLE_BUILD_ID == "2026-10-04-pat2404"
