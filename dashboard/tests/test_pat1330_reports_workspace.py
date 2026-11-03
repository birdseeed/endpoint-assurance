"""PAT-1330 Reports workspace structure and release regression coverage."""

from pathlib import Path

import main as dashboard


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates/console.html").read_text()
CSS = (ROOT / "static/css/console.css").read_text()


def _reports_markup() -> str:
    start = HTML.index('id="tab-reports"')
    end = HTML.index('id="tab-evidence-issued"', start)
    return HTML[start:end]


def test_reports_workspace_has_three_explicit_views_and_summary():
    reports = _reports_markup()
    assert 'class="rpt-summary"' in reports
    assert 'id="rpt-view-types"' in reports
    assert 'id="rpt-view-delivery"' in reports
    assert 'id="rpt-view-history"' in reports
    assert 'role="tablist" aria-label="Reports workspace"' in reports
    assert "function _rptSetView" in HTML


def test_reports_removes_misplaced_and_duplicate_legacy_sections():
    reports = _reports_markup()
    assert "Blocked Software" not in reports
    assert "Scheduled Reports" not in reports
    assert "Delivery History" not in reports
    assert "Past Reports" not in reports
    assert "Generate XLSX now" not in reports
    assert "_blkLoad" not in HTML


def test_report_rows_are_compact_until_configuration_is_opened():
    assert 'class="rpt-types-table"' in HTML
    assert 'class="rpt-more"' in HTML
    assert ">Configure</button>" in HTML
    assert ">Send now</button>" in HTML
    assert ">Generate</button>" in HTML
    assert "_rptEditingType === type" in HTML
    assert ".rpt-types-table td," in CSS
    assert "padding: 7px 8px;" in CSS


def test_history_separates_artifact_and_delivery_state():
    reports = _reports_markup()
    assert "<th>Artifact</th><th>Delivery</th>" in reports
    assert "PatchedConsoleReports.combineHistory" in HTML
    assert "console-reports.js?v={{ console_build_id }}" in HTML
    assert "delivery_status || '—'" not in reports


def test_report_send_confirmation_safeguards_remain():
    assert "/reports/recipient-category?recipient=" in HTML
    assert "External / ad-hoc (unverified)" in HTML
    assert "Confirm report send" in HTML
    assert "Recipient and report are correct" in HTML


def test_console_build_id_advances_for_reports_release():
    assert dashboard.CONSOLE_BUILD_ID == "2026-10-04-pat2404"
