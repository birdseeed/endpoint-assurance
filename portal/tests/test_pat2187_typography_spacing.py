"""PAT-2187: Brand v3 interface type and compact Overview attention rows."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSS = (ROOT / "static/css/portal.css").read_text()


def _rule(selector: str) -> str:
    match = re.search(rf"^{re.escape(selector)}\s*\{{.*?^\s*\}}", CSS, re.MULTILINE | re.DOTALL)
    assert match, f"missing CSS rule for {selector}"
    return match.group(0)


def test_attention_metadata_has_no_fixed_desktop_indent():
    """A short CVE message must stay with its row at every viewport width."""
    assert "padding-left: 186px" not in CSS
    assert "attention-row__meta { padding-left" not in CSS
    assert "flex: 0 0 170px" not in CSS


def test_structural_ui_uses_brand_v3_sans_not_legacy_mono_labels():
    for selector in (
        "h2", ".rail__group-label", ".data-table th", ".pill", ".field-label",
        ".attention-row__label", ".kpi__label", ".hardware-block h3, .device-card__subhead",
    ):
        rule = _rule(selector)
        assert "font-family: var(--sans)" in rule
        assert "font-family: var(--mono)" not in rule
        assert "text-transform: none" in rule


def test_attention_card_uses_modern_stacked_rows_and_rounded_semantic_chips():
    row = _rule(".attention-row")
    chips = _rule(".attention-pills .pill")
    heading = _rule(".attention-summary__head h2")

    assert "border-radius: var(--radius)" in row
    assert "background: var(--surface-sunken)" in row
    assert "border-radius: var(--radius-pill)" in chips
    assert "color-mix(in srgb, currentColor 24%, transparent)" in chips
    assert "font-family: var(--sans)" in heading


def test_technical_identifiers_remain_explicitly_monospace():
    text = (ROOT / "templates/device_software.html").read_text()
    assert 'class="cell-subtle mono cell-truncate"' in text
    # PAT-2255: /software's list no longer shows raw identifiers; they live
    # in the product detail's Identifiers section, still monospace.
    detail = (ROOT / "templates/_software_history.html").read_text()
    assert '<dd class="mono cell-anywrap">' in detail
