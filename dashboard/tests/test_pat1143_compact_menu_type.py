"""PAT-1143: one compact type scale across global and customer menus."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
THEME = (ROOT / "static" / "css" / "theme.css").read_text(encoding="utf-8")


def _rule(source, selector):
    start = source.index(selector + " {")
    end = source.index("\n}", start) + 2
    return source[start:end]


def test_global_and_customer_primary_menus_share_the_compact_type_token():
    global_label = _rule(THEME, ".grail-label")
    customer_primary = _rule(THEME, ".cwf-group-btn")
    customer_subnav = _rule(THEME, ".cwf-subnav .tnav-link")

    assert "font-family: var(--font-body);" in global_label
    assert "font-family: var(--font-body);" in customer_primary
    assert "font-family: var(--font-body);" in customer_subnav
    assert "font-size: var(--fs-sm);" in global_label
    assert "font-size: var(--fs-sm);" in customer_primary
    assert "font-size: var(--fs-sm);" in customer_subnav


def test_customer_identity_hierarchy_is_unchanged_by_menu_compaction():
    customer_name = _rule(THEME, ".ctxnav-cust-name")
    customer_coverage = _rule(THEME, ".ctxnav-cust-coverage")

    assert "font-size: var(--fs-md);" in customer_name
    assert "font-weight: 600;" in customer_name
    assert "font-size: var(--fs-sm);" in customer_coverage
