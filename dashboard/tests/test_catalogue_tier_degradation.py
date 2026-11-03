"""PAT-722: the merged Software Catalogue tab must degrade gracefully when the
tier-gated installed-inventory scan is denied (report-tier tenants), instead of
hard-failing the whole tab. These are structural guards on templates/console.html.
"""
import os

_HTML = None


def _console_html():
    global _HTML
    if _HTML is None:
        path = os.path.join(os.path.dirname(__file__), "..", "templates", "console.html")
        with open(path, encoding="utf-8") as f:
            _HTML = f.read()
    return _HTML


def test_tier_notice_element_present():
    # A dedicated, non-error notice element the degraded path reveals.
    assert 'id="sc-tier-notice"' in _console_html()


def test_scload_has_tier_denied_branch():
    html = _console_html()
    # The scan .catch must special-case a tier/403 denial rather than always
    # showing the red "Failed to load software inventory" error wall.
    assert "tierDenied" in html
    assert "err.status === 403" in html
    assert "subscription tier" in html


def test_tier_denied_seeds_empty_scan_and_renders_catalogue():
    html = _console_html()
    # Degraded path seeds an empty scan so _scRenderTable renders catalogue-only
    # rows, and it re-renders + refreshes the save bar.
    assert "tier_denied: true" in html
    # The scan-derived summary bar is hidden and given an id to target.
    assert 'id="as-policy-bar"' in html


def test_load_resets_prior_tier_degraded_state():
    # Switching from a report-tier tenant to a patch-tier one must restore the
    # summary bar and hide the notice.
    html = _console_html()
    assert "pbarReset" in html and "noticeReset" in html
