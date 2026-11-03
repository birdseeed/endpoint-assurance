"""PAT-1047 v2: workflow-first dashboard rewrite — regression coverage.

Covers the parts of the v2 rewrite not already pinned by more specific test
files (test_pat955_expanded_sidebar.py for global-rail/context-nav
structure, test_pat956_home_redesign.py / test_pat1006_home_patching_first.py
for Work, test_pat854_xss_onclick_escaping.py for the inline-handler
invariant, test_console_build_id.py for the cache contract): the new global
shell, persistent navigation, the device diagnostic workspace, the canonical
Brand v3 lockup, the imported light/dark semantic colour contract, and the
absence of both the pre-PAT-1047 shell markup and the PAT-1047 v1
rejected-branch defects (invented device posture score, duplicate hidden
identity, horizontal workload tabs).
"""

import hashlib
import re as _re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def html():
    return (ROOT / "templates" / "console.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def theme_css():
    return (ROOT / "static" / "css" / "theme.css").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def console_css():
    return (ROOT / "static" / "css" / "console.css").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def brand_tokens():
    return (ROOT / "static" / "vendor" / "brand" / "tokens.css").read_text(encoding="utf-8")


def _resolved_tokens(brand, theme, mode):
    values = {}
    for css in (brand, theme):
        for block in _re.findall(r"(?m)^:root\s*\{([^}]+)\}", css):
            values.update(_re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", block))
        selector = r'(?m)^\[data-theme="' + mode + r'"\][^{]*\{([^}]+)\}'
        for block in _re.findall(selector, css):
            values.update(_re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", block))

    def resolve(name, trail=()):
        assert name not in trail, "token alias cycle: " + repr(trail + (name,))
        assert name in values, "missing semantic token: " + name
        value = values[name].strip()
        return _re.sub(r"var\((--[\w-]+)\)", lambda m: resolve(m[1], trail + (name,)), value)

    return {name: resolve(name) for name in values}


# ── New global shell + exact primary navigation ──────────────────────────────

def test_shell_has_topbar_global_rail_context_nav_main_structure(html):
    assert '<div class="app-shell">' in html
    assert '<header class="topbar">' in html
    assert '<div class="app-body">' in html
    assert '<nav class="global-rail" id="global-rail"' in html
    assert '<nav class="context-nav" id="context-nav"' in html
    assert '<main class="main" id="console-main" tabindex="-1">' in html
    assert 'href="#console-main"' in html
    assert "</main>" in html


def test_primary_nav_matches_required_global_surfaces(html):
    # Service overview, Tenants, Operations, Intelligence on the global rail;
    # Service Health (Infrastructure, Automations, Operational Truth) and
    # Admin Tools (Credentials, Docs, Homebrew review, Software alerts, Logs,
    # Reports) grouped in the
    # context navigator — exactly the brief's global surface list.
    rail_start = html.index('<nav class="global-rail" id="global-rail"')
    rail_end = html.index("</nav>", rail_start)
    rail = html[rail_start:rail_end]
    for grail_id in ("grail-work", "grail-customers", "grail-operations", "grail-intelligence"):
        assert 'id="%s"' % grail_id in rail

    assert rail.count('class="grail-item') == 4
    for label in ("Service overview", "Tenants", "Operations", "Intelligence"):
        assert '>' + label + '</span>' in rail
    for route in ('home', 'customers-list', 'ops', 'homebrew-review'):
        assert "consoleNav('" + route + "')" in rail

    ctx_start = html.index('<nav class="context-nav" id="context-nav"')
    ctx_end = html.index("</nav>", html.rindex('id="nav-section-customer"'))
    ctx = html[ctx_start:ctx_end]
    assert 'id="nav-home"' not in ctx  # Work is on the global rail, not here
    assert '<div class="nav-section-label"><span class="icon" data-icon="settings"></span> Service Health</div>' in ctx
    assert 'id="nav-automations"' in ctx
    assert 'id="nav-ops"' in ctx
    assert '<div class="nav-section-label"><span class="icon" data-icon="lock"></span> Admin Tools</div>' in ctx
    for nav_id in ("nav-credentials", "nav-docs", "nav-homebrew-review", "nav-software-alerts", "nav-logs", "nav-reports"):
        assert 'id="%s"' % nav_id in ctx


def test_topbar_has_customer_selector_and_operator_identity(html):
    assert '<div class="topbar-customer" id="topbar-customer">' in html
    assert 'id="tw-switcher"' in html
    assert '<div class="topbar-identity" id="topbar-identity">' in html
    assert 'id="identity-btn"' in html
    assert 'id="identity-menu"' in html


def test_sticky_environment_and_application_chrome_do_not_overlap(html, theme_css, console_css):
    assert '<body class="env-{{ env }}' in html
    assert "--env-chrome-height: 34px" in theme_css
    assert "top: calc(var(--env-chrome-height) + var(--impersonation-chrome-height));" in theme_css
    assert "height:34px" in console_css


# ── Persistent global navigation in tenant and device contexts ──────────────

def test_global_nav_never_hidden_for_tenant_or_device_context(html):
    # The pre-PAT-1047 design swapped the rail for a separate tenant sidebar.
    # v2 keeps exactly one global rail + context navigator, always visible
    # (the context navigator collapses to zero width via CSS, it is never
    # display:none'd from JS).
    assert "global-rail').style.display" not in html
    assert "context-nav').style.display" not in html


def test_tenant_and_device_screens_do_not_redeclare_global_nav(html):
    tenant_start = html.index('<div id="section-tenant-workspace"')
    device_start = html.index('<div id="section-device-detail"')
    reports_marker = html.index("<!-- ═══ SECTION: REPORTS")
    tenant_and_device = html[tenant_start:reports_marker]
    assert 'id="global-rail"' not in tenant_and_device
    assert 'id="context-nav"' not in tenant_and_device
    assert device_start > tenant_start


def test_devices_workload_exposes_inventory_only(html):
    # PAT-1609 added Disposition Queue as a second devices-scoped destination
    # (deciding what happened to a device the agent has gone quiet on) --
    # still device inventory/lifecycle, not software or customer setup, so
    # it stays in this workload rather than widening the group's remit.
    assert "'devices':        ['device-health', 'disposition-queue', 'device-lifecycle']" in html
    assert 'id="subtabbar-devices"' in html


# ── Device diagnostic workspace ──────────────────────────────────────────────

def test_device_workspace_has_vertical_nav_with_seven_approved_destinations(html):
    bar_start = html.index('<nav class="ddw-nav" id="dd-subtab-nav"')
    bar_end = html.index("</nav>", bar_start)
    bar = html[bar_start:bar_end]

    for ddtab, label in (
        ("overview", ">Summary<"),   # data-ddtab value unchanged; label now "Summary"
        ("inventory", ">Hardware<"),
        ("hardware", ">Security<"),
        ("software", ">Software<"),
        ("patching", ">Patching<"),
        ("compliance", ">Compliance<"),
        ("activity", ">Activity<"),
    ):
        assert 'data-ddtab="%s"' % ddtab in bar
        assert "onclick=\"_ddTab('%s');return false;\"" % ddtab in bar
        assert label in bar

    for panel_id in (
        "ddtab-overview", "ddtab-inventory", "ddtab-hardware", "ddtab-software",
        "ddtab-patching", "ddtab-compliance", "ddtab-activity",
    ):
        assert 'id="%s"' % panel_id in html


def test_device_workspace_is_a_two_column_diagnostic_frame(html, theme_css, console_css):
    assert 'id="device-detail-content" class="device-workspace"' in html
    assert '<div class="ddw-panels">' in html
    assert ".device-workspace { display: flex" in theme_css
    assert ".device-workspace { flex-direction: column; }" in console_css


def test_device_workspace_js_tab_list_matches_markup(html):
    assert "var _DD_TABS = ['overview', 'inventory', 'hardware', 'software', 'patching', 'compliance', 'activity'];" in html
    assert "var _ddActiveTab = 'overview';" in html
    assert "inventory: true" in html
    assert "hardware: true" in html
    assert 'id="dd-hardware-empty"' in html


def test_device_posture_score_is_deleted_not_just_renamed(html):
    # REDESIGN_V2.md rejected-branch defect: _ddRenderOverviewPosture()
    # synthesised a 0-100 "Posture" score from arbitrary point deductions.
    # It must be gone, not merely renamed — the replacement renders only the
    # four real, already-sourced signals without a synthetic score.
    assert "_ddRenderOverviewPosture" not in html
    fn_start = html.index("function _ddRenderSummaryTiles(")
    fn_end = html.index("\n}", fn_start)
    fn = html[fn_start:fn_end]
    assert "'Posture'" not in fn
    assert "score -= Math.min" not in fn
    assert "signal('Patching'" in fn
    assert "signal('Compliance'" in fn
    assert "signal('Agent'" in fn
    assert "signal('Check-in'" in fn


def test_console_uses_system_fonts_without_external_font_fetches(html, theme_css):
    assert "fonts.googleapis.com" not in html
    assert "fonts.gstatic.com" not in html
    assert "--font-brand-display: var(--font-body)" in theme_css
    assert "--font-brand-mono:    var(--font-mono)" in theme_css


def test_extensions_folded_into_software_not_a_standalone_tab(html):
    assert 'data-ddtab="extensions"' not in html
    assert 'id="ddtab-extensions"' not in html
    # The browser-extensions loader/wrap survive, just relocated.
    software_start = html.index('id="ddtab-software"')
    software_end = html.index("<!-- ddtab: Activity", software_start)
    assert 'id="dd-ext-wrap"' in html[software_start:software_end]


# ── Canonical ring-mark lockup ───────────────────────────────────────────────

RING_MARK_PATH = 'd="M 30.72 2.304 H 47.36 A 16.64 16.64 0 0 1 61.696 16.64" stroke="var(--signal, #f5530a)" stroke-width="4.608" stroke-linecap="round"'
RING_MARK_OUTER = 'rect x="2.304" y="2.304" width="59.392" height="59.392" rx="16.64" stroke="currentColor" stroke-width="4.608"'


def test_v3_lockup_is_canonical_and_present_once(html):
    assert html.count('class="brand-lockup"') == 1
    assert '<a href="#" class="brand-lockup" aria-label="Home" onclick="consoleNav(\'home\'); return false;">' in html
    assert html.count('class="operator-logo logo-light"') == 1
    assert html.count('class="operator-logo logo-dark"') == 1
    assert 'class="ring-mark"' not in html
    assert RING_MARK_PATH not in html
    assert RING_MARK_OUTER not in html


def test_v3_lockup_uses_pinned_canonical_light_and_dark_assets(html):
    start = html.index('<a href="#" class="brand-lockup"')
    end = html.index("</a>", start)
    lockup = html[start:end]
    for name, digest in (
        ("patched-lockup-horizontal.svg", "6c8ba5d548fb07747fc79a9cea68499b9bbc747f9bcc2d61c345e6d33072b37d"),
        ("patched-lockup-horizontal-white.svg", "7ef04361b5021820b11a75dc66f3c11eb1a208a8672cb19ef2202fbc20ca58db"),
    ):
        assert '/static/vendor/brand/logo/' + name + '?v={{ console_build_id }}' in lockup
        assert hashlib.sha256((ROOT / 'static/vendor/brand/logo' / name).read_bytes()).hexdigest() == digest
    assert lockup.count('alt="Patched"') == 2


# ── Light-first system-font and semantic-token contract ─────────────────────

REQUIRED_SEMANTIC_TOKENS = [
    "--canvas", "--rail", "--surface", "--surface-sunken", "--border",
    "--text", "--muted", "--focus", "--accent", "--success", "--warning", "--danger",
]


def test_theme_resolves_imported_light_semantic_tokens(html, theme_css, brand_tokens):
    assert html.index('/static/vendor/brand/tokens.css') < html.index('/static/css/theme.css')
    values = _resolved_tokens(brand_tokens, theme_css, "light")
    for token in REQUIRED_SEMANTIC_TOKENS:
        assert values[token] and 'var(' not in values[token]
    assert values['--canvas'] == '#F8FAFC'
    assert values['--surface'] == '#FFFFFF'
    assert values['--text'] == '#0F172A'
    assert values['--accent'] == values['--focus'] == '#2563EB'
    assert values['--success'] == '#15803D'
    assert values['--warning'] == '#A15C07'
    assert values['--danger'] == '#B91C1C'
    assert values['--unknown'] == '#6D4FC2'
    assert values['--not-assessed'] == '#64748B'


def test_theme_resolves_coherent_imported_dark_mapping(theme_css, brand_tokens):
    values = _resolved_tokens(brand_tokens, theme_css, "dark")
    for token in REQUIRED_SEMANTIC_TOKENS:
        assert values[token] and 'var(' not in values[token]
    assert values['--canvas'] == '#1E293B'
    assert values['--surface'] == '#0F172A'
    assert values['--text'] == '#F8FAFC'
    assert values['--accent'] == values['--focus'] == '#60A5FA'
    assert values['--success'] == '#4ADE80'
    assert values['--warning'] == '#FBBF24'
    assert values['--danger'] == '#F87171'
    assert values['--unknown'] == '#B4A2F5'
    assert values['--not-assessed'] == '#94A3B8'


def test_operator_ui_uses_system_font_stack(theme_css):
    assert "-apple-system, BlinkMacSystemFont, 'Segoe UI'" in theme_css
    assert "--font-body:" in theme_css
    assert "--font-display:" in theme_css


def test_console_uses_pinned_v3_palette_and_normal_text_contrast(theme_css, brand_tokens):
    assert hashlib.sha256(brand_tokens.encode()).hexdigest() == "6c3d97c61a462b1bf65022550bc2e4a90c5ea4fab25ff338c072c28f64d0fba6"
    # Canonical colours stay in the kit; the console supplies aliases/native fonts.
    for token in ("--primary", "--nav-active", "--focus-ring", "--success", "--warning", "--danger", "--unknown"):
        assert not _re.search(_re.escape(token) + r"\s*:", theme_css)

    def luminance(colour):
        channels = [int(colour[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4 for v in channels]
        return sum(v * w for v, w in zip(linear, (0.2126, 0.7152, 0.0722)))

    for mode in ("light", "dark"):
        values = _resolved_tokens(brand_tokens, theme_css, mode)
        assert values['--accent-solid'] == values['--primary']
        assert values['--on-accent'] == values['--on-primary']
        assert values['--nav-active'] == values['--link'] == values['--primary']
        assert "-apple-system" in values['--font-body']
        for fg, bg in (("--on-primary", "--primary"), ("--link", "--surface"), ("--unknown", "--surface"), ("--unknown", "--canvas")):
            first, second = luminance(values[fg]), luminance(values[bg])
            assert (max(first, second) + 0.05) / (min(first, second) + 0.05) >= 4.5, (mode, fg, bg)


def test_portal_orange_controls_and_links_meet_normal_text_contrast():
    def luminance(hex_colour):
        channels = [int(hex_colour[i : i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [
            value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4
            for value in channels
        ]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    def contrast(first, second):
        first_luminance = luminance(first)
        second_luminance = luminance(second)
        return (max(first_luminance, second_luminance) + 0.05) / (
            min(first_luminance, second_luminance) + 0.05
        )

    assert contrast("#ffffff", "#c93f04") >= 4.5  # light solid control
    assert contrast("#c93f04", "#ffffff") >= 4.5  # light link
    assert contrast("#0f1115", "#ff7840") >= 4.5  # dark solid control
    assert contrast("#ff7840", "#15181e") >= 4.5  # dark link


def test_decorative_grid_backdrop_is_retired(theme_css):
    assert "body::before" not in theme_css
    assert "--grid-line: transparent" in theme_css


# ── Absence of retired old-shell anchors (pre-PAT-1047 AND v1) ──────────────

RETIRED_ANCHORS = [
    'class="shell"',
    'class="sidebar">',
    '<nav id="sidebar-tenant-nav"',
    "mobile-topbar",
    "mobile-nav-toggle",
    "mtb-mark",
    "mtb-title",
    'class="tnav-crumb"',
    'class="tnav-switch"',
    'class="tnav-foot"',
    "tnav-theme-btn",
    "_tnavTheme(",
    "_updateTnavThemeSeg(",
    "tnav-group-manage",
    "tnav-group-monitor",
    # PAT-1047 v1 rejected-branch anchors, retired by v2:
    'id="sidebar-app-nav"',
    'id="workload-tabbar"',
    'id="tenant-workload-nav"',
    'id="sidebar-identity"',
    "_ddRenderOverviewPosture",
    'class="home-dashboard-grid"',
]


@pytest.mark.parametrize("anchor", RETIRED_ANCHORS)
def test_retired_old_shell_anchor_is_gone(html, anchor):
    assert anchor not in html


def test_retired_mobile_drawer_css_is_gone(console_css):
    assert ".mobile-topbar" not in console_css
    assert ".mtb-mark" not in console_css
    assert "#sidebar-tenant-nav" not in console_css


def test_hidden_duplicate_identity_markup_is_gone(html):
    # REDESIGN_V2.md rejected-branch defect: a hidden sidebar-identity block
    # existed only to satisfy stale tests. Removed outright, not re-hidden —
    # the topbar identity button is the only place role/email render.
    assert "si-role-chip si-role-{{ role }}" in html  # still rendered, just once
    assert html.count("si-role-chip si-role-{{ role }}") == 1


# ── Copy rules: "estate" not "fleet", no em dashes in visible copy ──────────

def test_no_fleet_in_new_shell_visible_copy():
    # Scoped to rendered TEXT NODES only — ids, data-*, JS variable names and
    # code comments (e.g. ctx-client-fleet, tenantFleet) are internal and
    # predate this ticket; the brief's "estate, never fleet" rule is about
    # what an operator reads on screen, not internal identifiers.
    html_text = (ROOT / "templates" / "console.html").read_text(encoding="utf-8")
    home_start = html_text.index('<div id="section-home"')
    home_end = html_text.index("<!-- ═══ SECTION: REPORTS")
    tenant_start = html_text.index('<div id="section-tenant-workspace"')
    tenant_head_end = html_text.index("<!-- Tab panels -->")
    device_start = html_text.index('<div id="section-device-detail"')
    device_end = html_text.index('id="ddtab-hardware"')
    for label, chunk in (
        ("home", html_text[home_start:home_end]),
        ("tenant head/nav", html_text[tenant_start:tenant_head_end]),
        ("device head/nav", html_text[device_start:device_end]),
    ):
        text_nodes = _re.findall(r">([^<{}]+)<", chunk)
        visible = " ".join(text_nodes).lower()
        assert "fleet" not in visible, "%s region renders 'fleet' in visible text" % label
