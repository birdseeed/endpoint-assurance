"""PAT-1139: readable shared shell navigation at desktop and drawer widths."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text(encoding="utf-8")
THEME = (ROOT / "static" / "css" / "theme.css").read_text(encoding="utf-8")
CONSOLE = (ROOT / "static" / "css" / "console.css").read_text(encoding="utf-8")


def _rule(source, selector):
    start = source.index(selector + " {")
    end = source.index("\n}", start) + 2
    return source[start:end]


def test_global_rail_fits_every_primary_destination_in_readable_body_type():
    rail = _rule(THEME, ".global-rail")
    label = _rule(THEME, ".grail-label")

    assert "width: 144px;" in rail
    assert "padding: 8px 6px;" in rail
    assert "font-family: var(--font-body);" in label
    assert "font-size: var(--fs-sm);" in label
    assert "white-space: nowrap;" in label
    for label_text in ("Service overview", "Tenants", "Operations", "Intelligence"):
        assert ">" + label_text + "</span>" in HTML


def test_customer_context_metadata_uses_native_body_type_without_losing_hierarchy():
    tier = _rule(CONSOLE, "#ctxnav-cust-tier.ctx-badge")
    evidence = _rule(CONSOLE, "#ctxnav-cust-evidence.freshness-stamp")

    assert "font-family: var(--font-body);" in tier
    assert "font-size: var(--fs-sm);" in tier
    assert "letter-spacing: normal;" in tier
    assert "text-transform: none;" in tier
    assert "white-space: normal;" in tier
    assert "font-family: var(--font-body);" in evidence
    assert "font-size: var(--fs-sm);" in evidence
    assert "white-space: normal;" in evidence


def test_mobile_drawers_remain_within_the_viewport_and_keep_labels_visible():
    narrow = THEME[THEME.index("@media (max-width: 900px)"):THEME.index("@media (max-width: 480px)")]

    assert ".global-rail, .context-nav {" in narrow
    assert "html:has(body.nav-open),\n  body.nav-open { overflow-x: hidden; }" in narrow
    assert ".context-nav {\n    left: 144px;" in narrow
    assert "width: calc(100vw - 144px);" in narrow
    assert "max-width: 260px;" in narrow
    assert "min-width: 0;" in narrow
    assert "transform: translateX(calc(-100% - 144px));" in narrow
    assert "body.nav-open .global-rail, body.nav-open .context-nav { transform: translateX(0); }" in narrow
