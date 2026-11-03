"""PAT-1142: compact, contemporary global navigation rail."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text(encoding="utf-8")
THEME = (ROOT / "static" / "css" / "theme.css").read_text(encoding="utf-8")


def _rule(source, selector):
    start = source.index(selector + " {")
    end = source.index("\n}", start) + 2
    return source[start:end]


def test_global_rail_is_a_compact_horizontal_labelled_control_set():
    rail = _rule(THEME, ".global-rail")
    item = _rule(THEME, ".grail-item")
    label = _rule(THEME, ".grail-label")

    assert "width: 144px;" in rail
    assert "padding: 8px 6px;" in rail
    assert "flex-direction: row;" in item
    assert "min-height: 40px;" in item
    assert "padding: 7px 5px;" in item
    assert "font-size: var(--fs-sm);" in label
    assert "white-space: nowrap;" in label


def test_global_destinations_use_one_nav_specific_18px_icon_family():
    rail_start = HTML.index('<nav class="global-rail" id="global-rail"')
    rail = HTML[rail_start:HTML.index("</nav>", rail_start)]

    for name in ("work", "customers", "operations", "administration"):
        assert f'data-icon="nav-{name}" data-icon-size="18"' in rail
        assert f"'nav-{name}':" in HTML

    assert rail.count('data-icon-size="18"') == 4
    assert 'aria-hidden="true" focusable="false"' in HTML


def test_compact_mobile_drawers_use_the_same_rail_width_without_overflow():
    narrow = THEME[THEME.index("@media (max-width: 900px)"):THEME.index("@media (max-width: 480px)")]

    assert "left: 144px;" in narrow
    assert "width: calc(100vw - 144px);" in narrow
    assert "transform: translateX(calc(-100% - 144px));" in narrow
    assert "min-width: 0;" in narrow
    assert "overflow-x: hidden;" in narrow
