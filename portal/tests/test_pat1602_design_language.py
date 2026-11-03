"""PAT-1602: customer portal adopts the console redesign's design language.

Covers the two pieces of real behaviour change this ticket makes:
  - Overview: coverage as the hero, stated as a fraction with a stacked bar,
    never a bare percentage, with a standing "not counted as compliant"
    statement (2026-09-13 ruling).
  - Findings: CVE and CIS compliance findings render as distinct sections,
    never interleaved as rows in one list (same ruling).
The token/component pass itself (fonts, colours, corner language) has no
new logic to assert beyond "no brand-face fallback left in markup", covered
below.
"""

from pathlib import Path

import pytest

import main
from tests.conftest import OVERVIEW, STUB_STATE

ROOT = Path(__file__).resolve().parent.parent


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


# ── Token pass: no brand faces in the portal's own markup ─────────────────
def test_base_html_has_no_archivo_inter_jetbrains_reference():
    """The portal (app.patched.im) loads no web fonts and must not name a
    brand face even as an inert SVG fallback - root AGENTS.md: platform
    system font throughout, no Archivo/Inter/JetBrains Mono. (scan/, the
    separate public funnel service, is out of scope for this ticket.)"""
    html = (ROOT / "templates" / "base.html").read_text()
    assert "Archivo" not in html
    assert "Inter" not in html
    assert "JetBrains" not in html
    assert "fonts.googleapis.com" not in html


# ── coverage_geometry() ─────────────────────────────────────────────────
def test_coverage_geometry_states_fraction_and_percent():
    cov = main.coverage_geometry(248, 222)
    assert cov == {
        "total": 248, "reporting": 222, "retired": 0, "missing": 26,
        "pct": 89.5, "reporting_pct": 89.52, "retired_pct": 0.0, "missing_pct": 10.48,
    }


def test_coverage_geometry_carves_retired_out_of_missing():
    """PAT-2135: a retired device is the customer's own decision, not a
    coverage gap - it is counted in total but subtracted from missing, and
    gets its own segment/percentage."""
    cov = main.coverage_geometry(248, 200, 26)
    assert cov["missing"] == 22
    assert cov["retired"] == 26
    total_pct = cov["reporting_pct"] + cov["retired_pct"] + cov["missing_pct"]
    assert total_pct == pytest.approx(100, abs=0.1)


def test_coverage_geometry_clamps_retired_so_missing_never_goes_negative():
    """A retired count that (transiently) exceeds total - reporting must
    not produce a negative "missing" segment."""
    cov = main.coverage_geometry(10, 8, 100)
    assert cov["retired"] == 2
    assert cov["missing"] == 0


def test_coverage_geometry_zero_total_has_no_percent():
    """No denominator, no percent claim - a bare 0/0 must not render 0%."""
    cov = main.coverage_geometry(0, 0)
    assert cov["pct"] is None
    assert cov["total"] == 0 and cov["reporting"] == 0 and cov["missing"] == 0


def test_coverage_geometry_clamps_reporting_to_total():
    """A reporting count that (transiently) exceeds the total must not
    produce a negative "missing" segment or a >100% bar."""
    cov = main.coverage_geometry(10, 15)
    assert cov["reporting"] == 10
    assert cov["missing"] == 0


def test_coverage_geometry_rejects_non_numeric_input():
    cov = main.coverage_geometry(None, "not-a-number", "also-not-a-number")
    assert cov == {
        "total": 0, "reporting": 0, "retired": 0, "missing": 0,
        "pct": None, "reporting_pct": 0, "retired_pct": 0, "missing_pct": 0,
    }


# ── Overview: coverage as the hero ─────────────────────────────────────
def test_overview_coverage_hero_states_fraction_with_denominator(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    # OVERVIEW fixture: devices_total=12, devices_reporting_24h=11.
    assert "What we can see of your estate" in resp.text
    assert (
        '<span class="coverage-hero__count">11<span class="coverage-hero__of">'
        ' of 12</span></span>' in resp.text
    )
    assert "91.7%" in resp.text
    assert 'class="bar-stack__seg bar-stack__seg--ok" style="width:91.67%"' in resp.text
    assert 'class="bar-stack__seg bar-stack__seg--bad" style="width:8.33%"' in resp.text


def test_overview_coverage_hero_always_states_the_unseen_rule(client, make_token, monkeypatch):
    """The "not counted as compliant" statement is a standing product fact,
    not an alarm - unlike the degraded-devices line (PAT-1588), it must
    render even when every known device is currently reporting."""
    monkeypatch.setitem(STUB_STATE, "overview_data", {
        **OVERVIEW, "devices_total": 12, "devices_reporting_24h": 12, "devices_degraded": 0,
    })
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    assert "not counted as compliant" in resp.text
    assert "reporting a collection issue" not in resp.text  # PAT-1588 unchanged


def test_overview_coverage_hero_zero_devices_has_no_bare_percent(client, make_token, monkeypatch):
    monkeypatch.setitem(STUB_STATE, "overview_data", {
        **OVERVIEW, "devices_total": 0, "devices_reporting_24h": 0,
    })
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    assert (
        '<span class="coverage-hero__count">0<span class="coverage-hero__of">'
        ' of 0</span></span>' in resp.text
    )
    assert "coverage-hero__pct" not in resp.text


# ── Findings: CVE and CIS as distinct sections ─────────────────────────
def test_findings_renders_cve_and_cis_as_distinct_sections(client, make_token):
    """Ruling 2026-09-13: CVE and CIS compliance findings render as distinct
    sections, never interleaved as rows in one list."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    assert "<h2>CVE findings</h2>" in resp.text
    assert "<h2>CIS compliance findings</h2>" in resp.text
    # CVE content stays entirely inside the CVE section (before the CIS
    # heading); CIS severity counts stay entirely after it.
    cve_head = resp.text.index("<h2>CVE findings</h2>")
    cis_head = resp.text.index("<h2>CIS compliance findings</h2>")
    assert cve_head < cis_head
    assert resp.text.index("CVE-2026-0001") < cis_head
    # OVERVIEW fixture findings_open: critical=1, high=3, medium=5, low=2.
    cis_section = resp.text[cis_head:]
    assert '<span class="sev-count">1</span><span class="sev-name">Critical</span>' in cis_section
    assert '<span class="sev-count">3</span><span class="sev-name">High</span>' in cis_section


def test_findings_cis_section_degrades_soft_on_overview_outage(client, make_token, monkeypatch):
    """The CIS summary is secondary content (like the reports schedule
    fetch) - an outage on /v1/portal/overview must not take the CVE table
    down with it."""
    monkeypatch.setitem(STUB_STATE, "mode", "overview500")
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    assert "CVE-2026-0001" in resp.text  # CVE table unaffected
    assert "temporarily unavailable" in resp.text
    assert '<span class="sev-name">Critical</span>' not in resp.text


def test_findings_cis_section_states_no_failures_when_clean(client, make_token, monkeypatch):
    monkeypatch.setitem(STUB_STATE, "overview_data", {
        **OVERVIEW, "findings_open": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    })
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    assert "No open CIS Level 1 failures across your estate." in resp.text


# ── Nav hierarchy (ruled 2026-09-13) ───────────────────────────────────
def test_nav_keeps_estate_destinations_prominent(client, make_token):
    """PAT-2185 groups the rail while retaining Overview, Devices, Findings
    and Software as the primary estate destinations."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    text = resp.text
    assert 'id="rail-estate">Your estate<' in text
    assert text.index('href="/"') < text.index('href="/devices"') < text.index('href="/findings"')
