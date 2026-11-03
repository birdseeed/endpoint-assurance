"""PAT-810: the duplicate global Estate page is removed from the IA."""

import os


_HTML = None


def _console_html():
    global _HTML
    if _HTML is None:
        path = os.path.join(os.path.dirname(__file__), "..", "templates", "console.html")
        with open(path, encoding="utf-8") as f:
            _HTML = f.read()
    return _HTML


def test_duplicate_global_estate_page_is_not_in_nav_or_sections():
    html = _console_html()
    assert 'id="nav-fleet"' not in html
    assert "consoleNav('fleet')" not in html
    assert 'id="section-fleet"' not in html
    assert "'fleet':            'nav-fleet'" not in html
    assert "if (section === 'fleet')" not in html
    assert "_loadFleet(" not in html
    assert "> Estate</a>" not in html
    assert '> Fleet</a>' not in html
    assert '<h1>Estate</h1>' not in html
    assert '<h1>Fleet</h1>' not in html


def test_home_still_owns_estate_wide_summary_surface():
    html = _console_html()
    assert 'id="section-home"' in html
    # PAT-1966: staff work is service evidence; posture remains inert.
    assert 'id="home-service-exceptions"' in html
    assert 'data-retired-surface="estate-posture"' in html
    assert 'id="home-stat-strip"' not in html
    assert "Service exceptions" in html
    assert "consoleNav('customers-list')" in html
    assert "adminFetch('/api/admin/fleet-tenants').then(function(r) { return r.json(); })" not in html
