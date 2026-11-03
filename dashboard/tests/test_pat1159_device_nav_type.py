"""PAT-1159 device workspace navigation typography contracts."""

import re
from pathlib import Path


THEME_CSS = (Path(__file__).resolve().parents[1] / "static/css/theme.css").read_text()


def _rule(selector: str) -> str:
    match = re.search(re.escape(selector) + r"\s*\{([^}]+)\}", THEME_CSS)
    assert match, f"missing CSS rule for {selector}"
    return match.group(1)


def test_device_workspace_nav_uses_compact_menu_type_and_spacing():
    nav_button = _rule(".ddw-nav button")

    assert "font-size: var(--fs-sm);" in nav_button
    assert "padding: 7px 10px;" in nav_button
    assert "font-size: var(--fs-base);" not in nav_button
    assert "padding: 9px 10px;" not in nav_button


def test_device_section_content_typography_is_not_overridden():
    panels = _rule(".ddw-panels")

    assert "flex: 1 1 auto;" in panels
    assert "min-width: 0;" in panels
    assert "font-size" not in panels
