"""PAT-776: Deploy Agent generated artifacts must stay readable in both themes."""

import os


_CONSOLE_HTML = None
_CONSOLE_CSS = None


def _console_html():
    global _CONSOLE_HTML
    if _CONSOLE_HTML is None:
        path = os.path.join(os.path.dirname(__file__), "..", "templates", "console.html")
        with open(path, encoding="utf-8") as f:
            _CONSOLE_HTML = f.read()
    return _CONSOLE_HTML


def _console_css():
    global _CONSOLE_CSS
    if _CONSOLE_CSS is None:
        path = os.path.join(os.path.dirname(__file__), "..", "static", "css", "console.css")
        with open(path, encoding="utf-8") as f:
            _CONSOLE_CSS = f.read()
    return _CONSOLE_CSS


def test_deploy_agent_artifact_elements_and_controls_present():
    html = _console_html()
    assert 'id="tab-deploy-agent"' in html
    assert 'id="da-macos-script" class="da-artifact-box"' in html
    assert 'id="da-windows-cmd" class="da-artifact-box"' in html
    assert "_daCopy('da-macos-script', this)" in html
    assert "_daDownload('da-macos-script', 'patched-enroll-macos.sh')" in html
    assert "_daCopy('da-windows-cmd', this)" in html


def test_deploy_agent_css_cache_version_includes_pat_776_fix():
    # PAT-967: the cache-buster is now rendered from CONSOLE_BUILD_ID (a dated
    # string) via Jinja, so the raw template carries the placeholder rather than a
    # literal. The rendered dated value is asserted in tests/test_pat951.py
    # (test_console_css_cache_bust_is_current).
    assert "console.css?v={{ console_build_id }}" in _console_html()


def test_deploy_agent_artifact_css_sets_readable_light_and_dark_colors():
    # PAT-1615: the hand-picked light-mode hex palette plus a separate
    # hardcoded :root[data-theme="dark"] override block is gone. Theme
    # tokens (var(--surface-sunken)/var(--text)) already resolve to a
    # readable pair in both themes (theme.css's own light/dark blocks),
    # so there is no second override to maintain here any more.
    css = _console_css()
    rule = css.split(".da-artifact-box {", 1)[1].split("}", 1)[0]
    assert "background: var(--surface-sunken);" in rule
    assert "color: var(--text);" in rule
    assert "caret-color: var(--text);" in rule
    assert "#f8fafc" not in rule
    assert "#0f172a" not in rule
    assert ':root[data-theme="dark"] .da-artifact-box' not in css
    assert ".da-artifact-box::selection" in css
