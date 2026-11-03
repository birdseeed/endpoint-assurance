"""
PAT-1741 — four console defects: tier badge (out of scope, see below),
More menus, device counts, snapshot shape. This ticket fixes defects 2, 3
and 4 only; defect 1 (retired tier badge) is explicitly deferred to
PAT-1599 and untouched here.

Console.html ships one hash-routed SPA with no JS test runner inside pytest
(see AGENTS.md), so — same convention as test_pat1554_coverage_gap.py and
test_pat1613_evidence_workspace.py — the client-side wiring is asserted
structurally (markup + function-source presence) here, and the actual
guard/format logic is unit-tested for real in tests/js/console-reports.test.js
and tests/js/console-evidence.test.js (node --test, `npm run test:console`).

Run with: pytest tests/test_pat1741_console_defects.py -v
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text(encoding="utf-8")
CONSOLE_REPORTS_JS = (ROOT / "static" / "js" / "console-reports.js").read_text(encoding="utf-8")
CONSOLE_EVIDENCE_JS = (ROOT / "static" / "js" / "console-evidence.js").read_text(encoding="utf-8")


def _extract_fn(text, name):
    start = text.index("function " + name + "(")
    i = text.index("{", start)
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[start:j + 1]
    raise AssertionError("unbalanced braces for " + name)


# ── Defect 2: stacked report-type More menus ────────────────────────────

def test_rpt_more_details_share_a_native_grouping_name():
    assert '<details class="rpt-more" name="rpt-more-group">' in HTML


def test_outside_click_closes_open_rpt_more_menus():
    assert "PatchedConsoleReports.closeMenusOutsideClick" in HTML
    assert "document.addEventListener('click'" in HTML
    assert ".rpt-more[open]" in HTML


def test_close_menus_outside_click_exported_from_console_reports_js():
    assert "closeMenusOutsideClick" in CONSOLE_REPORTS_JS
    assert "closeMenusOutsideClick: closeMenusOutsideClick" in CONSOLE_REPORTS_JS


# ── Defect 3: device count mismatch (tenant header / sidebar / hero) ────

def test_ov2_render_hero_mirrors_live_total_devices_onto_tenant_header_and_sidebar():
    fn = _extract_fn(HTML, "_ov2RenderHero")
    # Both destinations are updated from the same live totalDevices figure
    # _ov2Load computed, the same value rendered as the hero's "Devices" stat
    # a few lines above — not re-derived from the cached tenant-list row.
    assert "getElementById('ctx-client-fleet')" in fn
    assert "getElementById('ctxnav-cust-coverage')" in fn
    assert "_consoleState.tenantFleet = totalDevices" in fn
    assert fn.count("totalDevices + ' device'") >= 1


# ── Defect 4: coverage_snapshot shape drift — documented, not unified ───

def test_coverage_snapshot_shapes_documented_above_the_read_functions():
    # Both write-side shapes named explicitly, by source value and field
    # names, so a future reader doesn't have to rediscover this from the two
    # write paths in the patched.im Go repo.
    assert '"portal_overview"' in CONSOLE_EVIDENCE_JS
    assert "devices_reporting_24h" in CONSOLE_EVIDENCE_JS
    assert '"executive_summary"' in CONSOLE_EVIDENCE_JS
    assert "devices_active_7d" in CONSOLE_EVIDENCE_JS
    assert "findings_by_severity" in CONSOLE_EVIDENCE_JS
    # The comment sits directly above coverageFromSnapshot, per the brief.
    comment_idx = CONSOLE_EVIDENCE_JS.index("PAT-1741 (defect 4)")
    fn_idx = CONSOLE_EVIDENCE_JS.index("function coverageFromSnapshot(")
    assert comment_idx < fn_idx
