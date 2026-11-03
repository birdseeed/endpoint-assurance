"""PAT-1957: /devices defaults to Reporting normally; tabs carry alert tones."""

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.conftest import STUB_STATE
from tests.test_devices_groups import GROUPED_DEVICES

ROOT = Path(__file__).resolve().parent.parent


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _device(n, days):
    seen = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "device_id": f"dev-{n}", "hostname": f"acme-host-{n}", "platform": "macOS",
        "os_version": "15.5", "last_seen": seen, "cis_score": 80,
        "findings_open": 0, "encryption_ok": True, "patch_pending": False,
    }


def _roster(silent, quiet, normal):
    devices = []
    for _ in range(silent):
        devices.append(_device(len(devices), 20))
    for _ in range(quiet):
        devices.append(_device(len(devices), 7))
    for _ in range(normal):
        devices.append(_device(len(devices), 0.5))
    return {"devices": devices}


def _page(client, make_token, roster, path="/devices"):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["devices_data"] = roster
    resp = _get(client, token, path)
    assert resp.status_code == 200
    return resp.text


def _tabs(html):
    """Map tab key to its full opening <a ...> tag and inner HTML."""
    found = {}
    pattern = r'<a href="[^"]*" data-filter-tab="(\w+)"([^>]*)>(.*?)</a>'
    for match in re.finditer(pattern, html, re.S):
        found[match.group(1)] = {"attrs": match.group(2), "inner": match.group(3)}
    return found


def _selected(html):
    return re.search(r'data-row-filter="view"[^>]*data-initial="(\w*)"', html).group(1)


# ── (a) default landing view ──────────────────────────────────────────────
@pytest.mark.parametrize(
    "counts",
    [(0, 0, 1), (2, 1, 3), (0, 2, 1), (3, 0, 0), (0, 0, 0)],
)
def test_no_view_param_lands_on_normal_whatever_the_counts(client, make_token, counts):
    html = _page(client, make_token, _roster(*counts))
    assert _selected(html) == "normal"
    assert 'data-filter-tab="normal" class="tab-active" aria-current="true"' in html
    assert 'data-filter-tab="silent" class="tab-active"' not in html


def test_a_tenant_with_silent_devices_still_lands_on_normal(client, make_token):
    html = _page(client, make_token, GROUPED_DEVICES)
    assert _selected(html) == "normal"
    # All rows are still served, so switching is client side.
    assert html.count('data-filter-view="silent"') == 2


def test_unrecognised_view_falls_back_to_normal(client, make_token):
    html = _page(client, make_token, GROUPED_DEVICES, "/devices?view=bogus")
    assert _selected(html) == "normal"


# ── (b) explicit views are honoured, including empty groups ──────────────
@pytest.mark.parametrize("view", ["silent", "quiet", "normal"])
@pytest.mark.parametrize("counts", [(0, 0, 1), (2, 1, 3)])
def test_explicit_view_is_honoured(client, make_token, view, counts):
    html = _page(client, make_token, _roster(*counts), f"/devices?view={view}")
    assert _selected(html) == view
    assert f'data-filter-tab="{view}" class="tab-active" aria-current="true"' in html


def test_explicit_empty_silent_view_is_still_silent(client, make_token):
    html = _page(client, make_token, _roster(0, 0, 1), "/devices?view=silent")
    assert _selected(html) == "silent"
    assert "Silent over 14 days (0)" in html


def test_stale_and_reporting_gap_views_are_unchanged(client, make_token):
    stale = _page(client, make_token, GROUPED_DEVICES, "/devices?view=stale&stale_days=7")
    assert 'data-row-filter="view"' not in stale
    gap = _page(client, make_token, GROUPED_DEVICES, "/devices?view=not_reporting_24h")
    assert 'data-row-filter="view"' not in gap


# ── (c) tones follow the counts, reporting state only ────────────────────
@pytest.mark.parametrize(
    ("counts", "silent_tone", "quiet_tone"),
    [
        ((0, 0, 1), None, None),
        ((2, 1, 3), "bad", "warn"),
        ((0, 2, 1), None, "warn"),
        ((3, 0, 1), "bad", None),
    ],
)
def test_tab_tones_follow_counts(client, make_token, counts, silent_tone, quiet_tone):
    tabs = _tabs(_page(client, make_token, _roster(*counts)))
    for key, expected in (("silent", silent_tone), ("quiet", quiet_tone)):
        attrs = tabs[key]["attrs"]
        if expected is None:
            assert "data-tone" not in attrs
        else:
            assert f'data-tone="{expected}"' in attrs
    # Normal is never an alert, whatever its count and whichever tab is selected.
    assert "data-tone" not in tabs["normal"]["attrs"]


@pytest.mark.parametrize("view", ["silent", "quiet", "normal"])
def test_tones_are_independent_of_the_selected_tab(client, make_token, view):
    tabs = _tabs(_page(client, make_token, _roster(2, 1, 3), f"/devices?view={view}"))
    assert 'data-tone="bad"' in tabs["silent"]["attrs"]
    assert 'data-tone="warn"' in tabs["quiet"]["attrs"]
    assert "data-tone" not in tabs["normal"]["attrs"]


def test_kpi_keeps_its_bad_text_prominence_only_when_silent_devices_exist(client, make_token):
    with_silent = _page(client, make_token, _roster(2, 0, 1))
    assert re.search(r'kpi__value bad-text">2<', with_silent)
    without = _page(client, make_token, _roster(0, 0, 1))
    assert not re.search(r'kpi__value bad-text', without)


# ── (d) accessible name carries the count and the state ──────────────────
def test_toned_tabs_expose_count_and_state_without_changing_the_visible_label(
    client, make_token,
):
    tabs = _tabs(_page(client, make_token, _roster(2, 1, 3)))
    silent = tabs["silent"]["inner"]
    quiet = tabs["quiet"]["inner"]
    assert silent.startswith("Silent over 14 days (2)")
    assert '<span class="visually-hidden">, alert</span>' in silent
    assert quiet.startswith("Quiet 3–14 days (1)")
    assert '<span class="visually-hidden">, warning</span>' in quiet
    # Neutral tabs add nothing: label and count only.
    assert "visually-hidden" not in tabs["normal"]["inner"]
    assert tabs["normal"]["inner"].strip() == "Reporting normally (3)"


def test_zero_count_tabs_have_no_state_text(client, make_token):
    tabs = _tabs(_page(client, make_token, _roster(0, 0, 1)))
    for key in ("silent", "quiet"):
        assert "visually-hidden" not in tabs[key]["inner"]
        assert "data-tone" not in tabs[key]["attrs"]
    assert tabs["silent"]["inner"].strip() == "Silent over 14 days (0)"


# ── (e) other segmented_control callers are unchanged ────────────────────
def test_software_filter_bar_carries_no_alert_or_warning_tone(client, make_token):
    """PAT-2120 added a second segmented control on /software (the
    decision-state filter, replacing the five decision group cards),
    covered by this same no-tone rule. PAT-2163 replaced both of
    /software's segmented controls (Type, decision) with the Type
    <select> and Approval <details> filter bar (templates/_macros.html's
    filter_bar) - neither is a devices.html-style toned tab, and this test
    now guards that no tone/alert/warning markup leaks into that bar."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?type=application")
    assert resp.status_code == 200
    assert "data-tone" not in resp.text
    assert ", alert</span>" not in resp.text
    assert ", warning</span>" not in resp.text


def test_only_devices_passes_a_tone_to_segmented_control():
    callers = {}
    for template in (ROOT / "templates").glob("*.html"):
        source = template.read_text()
        if template.name != "_macros.html" and "segmented_control(" in source:
            callers[template.name] = source
    # PAT-2163: software.html no longer calls segmented_control at all - its
    # Type/decision filters are the filter_bar macro (Type <select> +
    # Approval <details>) instead. PAT-2215: local_admins.html's By
    # account/By device toggle is deliberately a plain navigation link
    # pair, not a segmented_control call - the two views are different
    # tables entirely (unlike devices.html/homebrew.html's tabs, which
    # switch between subsets of one table), so it is not a caller here.
    # PAT-2263: findings.html's All/Blocklist-not-enforced driver-findings
    # tab is the same row-filter-over-one-table shape as devices.html/
    # homebrew.html, so it is a legitimate third caller - but, like
    # homebrew.html, it carries no tone (severity is the pill-critical
    # badge in the table instead), so it joins the no-tone assertion below
    # rather than the devices.html-only tone allowance.
    # PAT-2255: homebrew.html now uses the shared filter_bar macro, the same
    # as software.html, so it is no longer a caller either.
    assert set(callers) == {"devices.html", "findings.html"}
    assert "'bad' if" not in callers["findings.html"]
    assert "'warn' if" not in callers["findings.html"]


# ── (f) CSS contracts: both tones, active and inactive, existing tokens ──
def _rule(css, selector):
    match = re.search(re.escape(selector) + r" \{([^}]*)\}", css)
    assert match, f"missing rule {selector}"
    return match.group(1)


def test_tab_tone_css_uses_existing_tokens_for_inactive_and_active_states():
    css = (ROOT / "static" / "css" / "portal.css").read_text()
    inactive_bad = _rule(css, '.view-tabs a[data-tone="bad"]')
    assert "background: var(--bad-wash)" in inactive_bad and "color: var(--bad)" in inactive_bad
    inactive_warn = _rule(css, '.view-tabs a[data-tone="warn"]')
    assert "background: var(--warn-wash)" in inactive_warn and "color: var(--warn)" in inactive_warn
    active_bad = _rule(css, '.view-tabs a[data-tone="bad"].tab-active')
    assert "background: var(--bad)" in active_bad and "color: var(--snow)" in active_bad
    active_warn = _rule(css, '.view-tabs a[data-tone="warn"].tab-active')
    assert "background: var(--warn)" in active_warn and "color: var(--snow)" in active_warn
    # An active toned tab differs from an inactive one in background and text.
    assert active_bad != inactive_bad and active_warn != inactive_warn
    # The neutral active tab is untouched.
    assert "background: var(--slate)" in _rule(css, ".view-tabs a.tab-active")


def test_tab_tone_css_introduces_no_hardcoded_colours():
    css = (ROOT / "static" / "css" / "portal.css").read_text()
    block = css[css.index("PAT-1957: reporting-state tones"):css.index(".threshold-picker")]
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(|hsla?\(", block)


def test_visually_hidden_utility_exists():
    css = (ROOT / "static" / "css" / "portal.css").read_text()
    rule = _rule(css, ".visually-hidden")
    assert "position: absolute" in rule and "overflow: hidden" in rule


def test_portal_css_version_is_bumped_for_pat_1957():
    """PAT-2237: the cache-buster is now the file's own content hash
    (static_url()), not a hand-bumped literal per ticket."""
    base = (ROOT / "templates" / "base.html").read_text()
    assert "{{ static_url('css/portal.css') }}" in base
    assert "pat-1954-2" not in base


def test_tab_bar_wraps_on_phones_so_the_default_normal_tab_is_never_offscreen():
    css = (ROOT / "static" / "css" / "portal.css").read_text()
    narrow = css[css.index("@media (max-width: 680px)"):]
    assert re.search(r"\.view-tabs \{[^}]*flex-wrap: wrap", narrow)
    assert re.search(r"\.devices-toolbar \.view-tabs \{ flex: 1 1 100%; \}", narrow)
