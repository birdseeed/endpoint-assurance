"""PAT-1323: semantic labels use one compact rectangular radius."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
THEME = (ROOT / "static/css/theme.css").read_text()
CONSOLE = (ROOT / "static/css/console.css").read_text()
TEMPLATE = (ROOT / "templates/console.html").read_text()


def test_shared_badge_radius_is_compact_and_used_by_catalogue_labels():
    assert "--badge-radius: 4px;" in THEME
    assert ".as-badge {" in CONSOLE
    assert "border-radius: var(--badge-radius);" in CONSOLE
    assert "border-radius: 12px;" not in CONSOLE.split(".as-badge {", 1)[1].split("}", 1)[0]


def test_semantic_badges_use_shared_radius_across_console_surfaces():
    selectors = (
        ".dd-hardware-state {",
        ".dd-signal-state {",
        ".sev-badge {",
        ".findings-chip {",
        ".patch-chip {",
        ".rdx-class-tag {",
        ".pd-update-chip {",
        ".dh-fresh-chip  {",
        ".bx-risk-chip   {",
        ".bx-pol-chip       {",
        ".bx-job-state {",
        ".dc-state, .dc-never-ack {",
        ".rep-status        {",
        ".bill-renewal-badge {",
        ".bill-renewal-delta {",
        ".bill-drift-badge {",
        ".dra-state       {",
        ".pdr-state-badge {",
        ".auto-badge {",
    )
    for selector in selectors:
        rule = CONSOLE.split(selector, 1)[1].split("}", 1)[0]
        assert re.search(r"border-radius:\s*var\(--badge-radius\)", rule), selector

    assert "border-radius:var(--badge-radius)" in TEMPLATE


def test_shape_dependent_controls_remain_round():
    assert ".sc-view-count" in CONSOLE
    assert "border-radius: 999px;" in CONSOLE.split(".sc-view-count", 1)[1].split("}", 1)[0]
    assert ".bx-removals-badge" in CONSOLE
    assert "border-radius:9px" in CONSOLE.split(".bx-removals-badge", 1)[1].split("}", 1)[0]
    assert ".toggle-slider" in THEME
    assert "border-radius: 999px;" in THEME.split(".toggle-slider {", 1)[1].split("}", 1)[0]
    assert ".prog-bar-track" in THEME
    assert "border-radius: 999px;" in THEME.split(".prog-bar-track {", 1)[1].split("}", 1)[0]
