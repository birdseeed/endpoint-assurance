"""PAT-1372 compact Operational Truth workspace regression contracts."""
import os

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard


def _console():
    return open("templates/console.html", encoding="utf-8").read()


def test_truth_workspace_has_semantic_summary_filters_and_accessible_table():
    page = _console()
    assert '<span>Action required</span>' in page
    assert '<span>Evidence missing</span>' in page
    assert '<span>Verified</span>' in page
    assert 'id="truth-search" type="search"' in page
    assert 'id="truth-state-filter"' in page
    assert 'id="truth-scope-filter"' in page
    assert '<caption>Declared operational checks and their observed evidence</caption>' in page
    assert 'aria-live="polite"' in page
    assert 'This does not indicate a healthy estate.' in page


def test_truth_workspace_uses_tested_helper_and_prevents_stale_refresh_overwrite():
    page = _console()
    assert '/static/js/console-truth.js?v={{ console_build_id }}' in page
    assert 'PatchedConsoleTruth.prepare' in page
    assert 'PatchedConsoleTruth.filter' in page
    assert 'var _truthRequest = 0' in page
    assert 'if (requestId !== _truthRequest) return;' in page
    assert 'PatchedConsoleTruth.concise(c.reason, 150)' in page


def test_truth_long_proof_and_notes_are_explicit_expandable_detail():
    page = _console()
    assert 'aria-controls="truth-detail-' in page
    assert 'function _truthToggleDetail' in page
    assert 'What this proves' in page
    assert 'Manifest note' in page
    assert 'class="truth-detail-grid"' in page


def test_truth_workspace_replaces_raw_six_column_wall_and_bumps_cache_build():
    page = _console()
    # Scoped to the Operational Truth section itself (PAT-1820 added an
    # unrelated Protected Software tab with its own legitimate <th>Reason</th>
    # column -- protected_software.reason -- elsewhere on the same page; the
    # regression this guards against is the old six-column truth table, not
    # every "Reason" header on the console).
    start = page.index('id="section-truth"')
    end = page.index('id="section-credentials"')
    truth_section = page[start:end]
    assert '<th>Proves</th>' not in truth_section
    assert '<th>Reason</th>' not in truth_section
    assert 'class="truth-table"' in page
    assert dashboard.CONSOLE_BUILD_ID == "2026-10-04-pat2404"
