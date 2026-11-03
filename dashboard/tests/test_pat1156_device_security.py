"""Regression coverage for PAT-1156's actionable Device Security surface."""

import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text()
CSS = (ROOT / "static" / "css" / "console.css").read_text()


def _function(name: str) -> str:
    start = HTML.index(f"function {name}(")
    brace = HTML.index("{", start)
    depth = 0
    for index in range(brace, len(HTML)):
        if HTML[index] == "{":
            depth += 1
        elif HTML[index] == "}":
            depth -= 1
            if depth == 0:
                return HTML[start:index + 1]
    raise AssertionError(f"unbalanced function {name}")


def _node_json(functions: list[str], expression: str):
    source = "\n".join(_function(name) for name in functions)
    script = f"{source}\nconsole.log(JSON.stringify({expression}));"
    result = subprocess.run(
        ["node", "-e", script], check=True, capture_output=True, text=True
    )
    return json.loads(result.stdout)


def _security_panel() -> str:
    start = HTML.index('id="ddtab-hardware"')
    end = HTML.index('<!-- /#ddtab-hardware -->', start)
    return HTML[start:end]


def test_visible_destination_is_security_with_internal_hardware_compatibility():
    nav_start = HTML.index('<nav class="ddw-nav" id="dd-subtab-nav"')
    nav_end = HTML.index("</nav>", nav_start)
    nav = HTML[nav_start:nav_end]
    assert 'data-ddtab="hardware"' in nav
    assert "_ddTab('hardware')" in nav
    assert 'aria-label="Security"' in nav
    assert ">Security<" in nav
    assert 'data-ddtab="inventory"' in nav
    assert ">Hardware</button>" in nav
    panel = _security_panel()
    assert 'aria-label="Security"' in panel
    assert "Security overview" in panel
    assert "No security evidence has been reported" in panel


def test_signal_classifier_is_key_aware_and_conservative():
    fixtures = [
        {"key": "remote_desktop_enabled", "value": "disabled"},
        {"key": "autoplay_disabled", "value": "No"},
        {"key": "firewall", "value": "unknown"},
        {"key": "new_vendor_posture", "value": "sparkly"},
        {"key": "new_vendor_posture", "value": "pass"},
        {"key": "new_vendor_posture", "value": "fail"},
        {"key": "auto_security_updates", "value": "disabled"},
        {"key": "auto_security_updates", "value": "enabled"},
        {"key": "auto_os_updates", "value": "off"},
        {"key": "auto_os_updates", "value": "yes"},
    ]
    result = _node_json(
        ["_ddSignalState"], f"{json.dumps(fixtures)}.map(_ddSignalState)"
    )
    assert result == [
        "healthy", "risk", "unknown", "info", "healthy", "risk",
        "risk", "healthy", "risk", "healthy",
    ]


def test_overview_aggregates_all_applicable_evidence_and_never_greens_unknown():
    signals = [
        {"key": "windows_firewall_domain", "value": "enabled", "observed_at": "2026-08-04T09:00:00Z"},
        {"key": "windows_firewall_private", "value": "disabled", "observed_at": "2026-08-04T10:00:00Z"},
        {"key": "windows_firewall_public", "value": "disabled", "observed_at": "2026-08-04T08:00:00Z"},
        {"key": "auto_updates_enabled", "value": "Unknown", "observed_at": "2026-08-04T11:00:00Z"},
        {"key": "secure_boot_enabled", "value": "Unknown"},
    ]
    result = _node_json(
        ["_ddSignalState", "_ddOverviewState", "_ddLatestSignalObserved", "_ddSecurityOverview"],
        f"_ddSecurityOverview({json.dumps(signals)}, {{}}, {{}})",
    )
    cards = {card["label"]: card for card in result}
    assert list(cards) == ["AV / EDR", "Firewall", "Encryption", "Secure Boot", "SIP / UAC", "Automatic Updates"]
    assert cards["Firewall"]["state"] == "risk"
    assert cards["Firewall"]["evidence_count"] == 3
    assert cards["Firewall"]["observed_at"] == "2026-08-04T10:00:00Z"
    assert cards["Automatic Updates"]["evidence_count"] == 1
    assert cards["Automatic Updates"]["state"] == "unknown"
    assert cards["Secure Boot"]["state"] == "unknown"


def test_overview_mixed_positive_and_unconfirmed_evidence_stays_unknown():
    signals = [
        {"key": "windows_firewall_domain", "value": "enabled"},
        {"key": "windows_firewall_private", "value": "Unknown"},
        {"key": "defender_realtime", "value": "Unknown"},
    ]
    result = _node_json(
        ["_ddSignalState", "_ddOverviewState", "_ddLatestSignalObserved", "_ddSecurityOverview"],
        f"_ddSecurityOverview({json.dumps(signals)}, "
        "{security_tools:[{name:'Microsoft Defender'}]}, {last_seen:'2026-08-04T11:00:00Z'})",
    )
    cards = {card["label"]: card for card in result}
    assert cards["Firewall"]["state"] == "unknown"
    assert cards["AV / EDR"]["state"] == "unknown"
    assert cards["AV / EDR"]["evidence_count"] == 2


def test_automatic_update_controls_drive_card_badge_and_default_risk_view():
    signals = [
        {"key": "auto_security_updates", "value": "disabled"},
        {"key": "auto_os_updates", "value": "enabled"},
    ]
    result = _node_json(
        ["_ddSignalState", "_ddIsBadSig", "_ddSignalsForView", "_ddOverviewState", "_ddLatestSignalObserved", "_ddSecurityOverview"],
        "(() => { const signals = " + json.dumps(signals) + "; return {"
        "card:_ddSecurityOverview(signals, {}, {}).find(c => c.label === 'Automatic Updates').state,"
        "badge:signals.filter(_ddIsBadSig).length,"
        "defaultKeys:_ddSignalsForView(signals, 'risk').map(s => s.key)"
        "}; })()",
    )
    assert result == {
        "card": "risk",
        "badge": 1,
        "defaultKeys": ["auto_security_updates"],
    }


def test_security_badge_counts_confirmed_risks_only():
    load = _function("_loadDeviceDetail")
    assert "rawSigs.filter(_ddIsBadSig).length" in load
    assert "function _ddIsBadSig(s) { return _ddSignalState(s) === 'risk'; }" in HTML
    classifier = _function("_ddSignalState")
    assert "return 'unknown'" in classifier
    assert "return 'info'" in classifier


def test_default_views_counts_and_search_reconcile_without_mutating_counts():
    panel = _security_panel()
    assert 'data-dd-signal-view="risk"' in panel
    assert 'data-dd-signal-view="unknown"' in panel
    assert 'data-dd-signal-view="all"' in panel
    assert 'id="dd-signals-search"' in panel
    render = _function("_ddRenderSignals")
    assert "var counts = { risk:0, unknown:0, healthy:0, info:0 }" in render
    assert "_ddSignalsForView(_ddSigsAll, _ddSigView)" in render
    assert "if (_ddSigSearch)" in render
    assert "dd-signal-count-all" in render and "_ddSigsAll.length" in render
    assert "sorted.length + ' shown'" in render


def test_signal_rows_lead_with_human_label_and_retain_raw_key():
    labels = _node_json(
        ["_ddSignalLabel"],
        "['av_enabled','windows_firewall_private','uac_enabled','llmnr_disabled'].map(_ddSignalLabel)",
    )
    assert labels == ["AV Enabled", "Windows Firewall Private", "UAC Enabled", "LLMNR Disabled"]
    panel = _security_panel()
    assert "<th>State</th><th>Value</th><th>Observed</th>" in panel
    render = _function("_ddRenderSignals")
    assert 'class="dd-signal-label"' in render
    assert 'class="dd-signal-key"' in render
    assert "_ddSignalStateBadge(state)" in render
    assert "_ddRelDate(s.observed_at)" in render


def test_complete_evidence_and_supporting_sections_are_retained_without_old_toggle():
    panel = _security_panel()
    assert "Endpoint Protection" in panel
    assert "System Extensions" in panel
    assert "Background Items" in panel
    assert "dd-signal-count-all" in panel
    assert "dd-signals-toggle" not in panel
    assert "Show all signals" not in HTML
    assert "Show alerts only" not in HTML
    assert "function _ddToggleSignals" not in HTML


def test_security_surface_is_compact_and_contains_overflow_at_732_and_narrower():
    for selector in (
        ".dd-security-cards", ".dd-security-table-wrap", ".dd-signal-controls",
        ".dd-signal-label", ".dd-signal-key",
    ):
        assert selector in CSS
    assert "max-height: 480px; overflow: auto" in CSS
    assert "@media (max-width: 732px)" in CSS
    assert "@media (max-width: 430px)" in CSS
    assert ".dd-security-cards { grid-template-columns: 1fr; }" in CSS


def test_prior_summary_verdict_and_other_destinations_are_unchanged():
    assert "function _ddSetDeviceVerdict(" in HTML
    assert "function _ddRenderMachineInformation(" in HTML
    summary_start = HTML.index('id="ddtab-overview"')
    summary_end = HTML.index('<!-- /#ddtab-overview -->', summary_start)
    summary = HTML[summary_start:summary_end]
    assert summary.index(">Machine information<") < summary.index(">Device status<")
    for tab in ("overview", "software", "patching", "compliance", "activity"):
        assert f'data-ddtab="{tab}"' in HTML
    assert 'id="dd-delete-btn"' in HTML and 'id="dd-revoke-btn"' in HTML
