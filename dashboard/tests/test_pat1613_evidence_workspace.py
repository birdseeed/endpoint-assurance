"""
PAT-1613 — Evidence, issued reports and the assessor pack (dashboard UI half).

Backend (already shipped and deployed, patched.im repo commit d3423da):
  report_records gained pdf_sha256/xlsx_sha256/issued_at/coverage_snapshot and
  the self-referential supersedes_report_id/superseded_by_report_id pair
  (migration 0126_report_records_issuance_integrity.sql). GenerateReportHandler
  freezes coverage_snapshot (devices_total, devices_active_24h/7d,
  devices_macos/windows, compliance_overall_pct) onto the row the moment it
  issues a report; migration 0126's trigger then rejects any further UPDATE
  except a single one-time write of superseded_by_report_id.

This ticket wires the console's existing report-records/report-schedules/
delivery-contacts proxies (main.py — unchanged by this ticket, already
present) into a new "Issued Reports" tab against
docs/design/console-redesign/07-evidence.html.

Both gaps originally flagged here are now closed (PAT-1685, patched.im PR
#481, deployed) and covered below rather than worked around:
  - coverage_snapshot now carries findings_total/findings_by_severity when
    the findings query succeeded at issue time; "Findings then" renders that
    frozen figure and only falls back to "not captured" when the keys are
    genuinely absent (legacy row, or the query failed at issue time).
  - POST .../report-records/generate now accepts an optional
    supersedes_report_id. The console offers "Issue a correction" on any
    issued, non-superseded row, running through the same generate endpoint
    and the same pre-issue coverage guard as an ordinary issue.

Console.html ships one hash-routed SPA with no JS test runner inside pytest
(see AGENTS.md), so — same convention as test_pat1554_coverage_gap.py — the
client-side wiring is asserted structurally (markup + function-source
presence), and the actual guard/format logic is unit-tested for real in
tests/js/console-evidence.test.js (node --test, `npm run test:console`).

Run with: pytest tests/test_pat1613_evidence_workspace.py -v
"""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates/console.html").read_text()
CSS = (ROOT / "static/css/console.css").read_text()
JS = (ROOT / "static/js/console-evidence.js").read_text()


def _evidence_markup() -> str:
    start = HTML.index('id="tab-evidence-issued"')
    end = HTML.index('<template data-retired-surface="runbook">', start)
    return HTML[start:end]


def test_evidence_tab_is_registered_in_the_nav_and_the_workload_router():
    assert 'data-tab="evidence-issued"' in HTML
    assert "'evidence-issued'" in HTML  # in _TENANT_TABS
    assert "_WORKLOAD_TABS = {" in HTML
    workload_block = HTML[HTML.index("_WORKLOAD_TABS = {"):HTML.index("};", HTML.index("_WORKLOAD_TABS = {"))]
    assert "'reports', 'evidence-issued'" in workload_block
    assert "if (tab === 'evidence-issued')    _evdActivate();" in HTML


def test_evidence_panel_has_issued_table_schedule_card_and_assessor_pack():
    panel = _evidence_markup()
    assert 'id="evd-issued-tbody"' in panel
    for header in ("Report", "Period", "Coverage then", "Findings then", "Sent to", "State"):
        assert ">" + header + "<" in panel
    assert 'id="evd-schedule-list"' in panel
    assert "THEIR CONTROL" in panel
    assert 'id="evd-assessor-pack"' in panel
    assert 'id="evd-assessor-list"' in panel
    assert "CYBER ESSENTIALS" in panel
    assert "ISO 27001 A" in panel
    assert "ART 32" in panel
    assert 'id="evd-coverage-statement"' in panel
    assert "This paragraph is the product." in panel
    assert "does not change" in panel


def test_issue_button_present_and_correction_action_wired():
    panel = _evidence_markup()
    assert "Issue a report" in panel
    assert "_evdIssueReport()" in panel
    # The correction action (PAT-1685) is rendered per-row, not as a static
    # button in the tab header — it isn't present in the static panel markup
    # at all, only inside _evdRenderIssued's row template (see the next test).
    assert "_evdIssueCorrection" in HTML


def test_correction_action_only_offered_on_issued_non_superseded_rows():
    row_start = HTML.index("function _evdRenderIssued")
    row_end = HTML.index("function _evdRecordsPrev")
    row_template = HTML[row_start:row_end]
    assert "r.id && r.issued_at && !r.superseded_by_report_id" in row_template
    assert "Issue a correction" in row_template
    assert "_evdIssueCorrection(this.closest(" in row_template
    assert "dataset.recordId" in row_template
    assert "data-record-id=" in row_template


def test_issued_rows_render_from_frozen_fields_not_a_live_recompute():
    assert "PatchedConsoleEvidence.formatHash(r.pdf_sha256)" in HTML
    assert "PatchedConsoleEvidence.coverageFromSnapshot(r.coverage_snapshot)" in HTML
    assert "PatchedConsoleEvidence.findingsFromSnapshot(r.coverage_snapshot)" in HTML
    assert "PatchedConsoleEvidence.supersessionInfo(r)" in HTML
    # Must not derive the displayed coverage % from today's compliance figure.
    assert "cov.pct.toFixed" in HTML
    assert "r.compliance_overall_pct" not in HTML


def test_supersession_relationship_is_shown_and_issued_rows_have_no_edit_affordance():
    panel = _evidence_markup()
    assert "superInfo.supersedes" in HTML
    assert "superInfo.supersededBy" in HTML
    assert "evd-super-tag" in panel or "evd-super-tag" in HTML
    # An issued row offers download links and the correction action only —
    # no edit/save action anywhere in the issued table's row template. The
    # correction button is not an edit: it opens the same generate flow
    # pre-targeted at this record's id, never mutates the row in place.
    row_template_start = HTML.index("function _evdRenderIssued")
    row_template_end = HTML.index("function _evdRecordsPrev")
    row_template = HTML[row_template_start:row_template_end]
    assert ">Edit<" not in row_template
    assert ">Save<" not in row_template


def test_findings_render_frozen_figure_when_present_not_captured_when_absent():
    fn_start = HTML.index("function _evdRenderIssued")
    fn_end = HTML.index("function _evdRecordsPrev")
    fn = HTML[fn_start:fn_end]
    assert "findings.available" in fn
    assert "findings.bySeverity" in fn
    assert "findings.total" in fn
    assert "not captured" in fn


def test_correction_guard_blocks_before_any_network_call():
    fn_start = HTML.index("function _evdIssueCorrection")
    fn_end = HTML.index("function ", fn_start + 20)
    fn = HTML[fn_start:fn_end]
    guard_pos = fn.index("PatchedConsoleEvidence.canIssueReport")
    fetch_pos = fn.index("adminFetch(")
    assert guard_pos < fetch_pos, "coverage guard must run before the correction generate call"
    assert "if (!guard.allowed)" in fn
    assert "return;" in fn.split("if (!guard.allowed)")[1].split("}")[0] + "}"
    assert "supersedes_report_id: recordId" in fn


def test_correction_includes_target_record_period_when_present_omits_when_absent():
    # go-service/internal/handlers/report_delivery.go's GenerateReportHandler
    # accepts optional period_start/period_end — a correction must carry the
    # superseded record's own period (same reporting period, fixed content),
    # and must never send an empty string for a record with no period.
    fn_start = HTML.index("function _evdIssueCorrection")
    fn_end = HTML.index("function ", fn_start + 20)
    fn = HTML[fn_start:fn_end]
    assert "if (record.period_start) payload.period_start = record.period_start;" in fn
    assert "if (record.period_end)   payload.period_end   = record.period_end;" in fn
    # Never unconditionally set on the payload literal itself.
    assert "period_start: record.period_start" not in fn
    assert "period_end: record.period_end" not in fn


def test_correction_errors_mapped_to_plain_language():
    fn_start = HTML.index("function _evdIssueCorrection")
    fn_end = HTML.index("function ", fn_start + 20)
    fn = HTML[fn_start:fn_end]
    assert "PatchedConsoleEvidence.correctionErrorMessage(err.status, err.body)" in fn
    assert "correctionErrorMessage(status, rawBody)" in JS
    assert "This report has already been corrected." in JS


def test_issue_guard_blocks_before_any_network_call():
    fn_start = HTML.index("function _evdIssueReport")
    fn_end = HTML.index("function ", fn_start + 20)
    fn = HTML[fn_start:fn_end]
    guard_pos = fn.index("PatchedConsoleEvidence.canIssueReport")
    fetch_pos = fn.index("adminFetch(")
    assert guard_pos < fetch_pos, "coverage guard must run before the generate call"
    assert "if (!guard.allowed)" in fn
    assert "return;" in fn.split("if (!guard.allowed)")[1].split("}")[0] + "}"


def test_coverage_guard_uses_live_estate_fetch_not_the_issued_records_list():
    assert "/enrolled-devices'" in HTML.split("function _evdLoadAll")[1].split("function _evdComputeCoverage")[0]
    assert "/devices?limit=500'" in HTML.split("function _evdLoadAll")[1].split("function _evdComputeCoverage")[0]
    assert "_evdComputeCoverage(res[2], res[3])" in HTML


def test_assessor_pack_never_fakes_unavailable_items():
    assert "Not yet available" in HTML
    assert "item.available" in HTML
    # The pure module is the single source of truth for which items are real.
    assert "not yet linked to CIS controls" in JS
    assert "no disposition record exists" in JS
    assert "no customer-facing action log" in JS


def test_evidence_js_module_is_loaded_and_console_build_id_advances():
    assert 'console-evidence.js?v={{ console_build_id }}' in HTML
    assert dashboard.CONSOLE_BUILD_ID == "2026-10-04-pat2404"


def test_evidence_css_uses_theme_tokens_not_hardcoded_colors():
    start = CSS.index("PAT-1613: Issued Reports")
    end = CSS.index("PAT-696: Danger zone block")
    block = CSS[start:end]
    assert "var(--" in block
    # No literal hex colors introduced by this ticket's CSS block.
    import re as _re
    assert not _re.search(r"#[0-9a-fA-F]{3,6}\b", block)


# ── PAT-1685: the generate proxy forwards supersedes_report_id unchanged ──────
# main.py's proxy_report_records_generate is unchanged by this ticket — it
# already forwards the raw request body verbatim (see the comment above the
# route). This test proves that holds for the new field specifically, rather
# than trusting the "no proxy change needed" assumption in the ticket brief.

@pytest.fixture
def _client(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


def test_generate_proxy_forwards_supersedes_report_id_unchanged(_client):
    upstream_body = json.dumps({"id": "new-id", "supersedes_report_id": "old-id"}).encode()
    mock = MagicMock(status_code=200, content=upstream_body)
    mock.json.return_value = {"id": "new-id", "supersedes_report_id": "old-id"}

    with patch.object(dashboard.http, "post", return_value=mock) as mocked_post:
        r = _client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/report-records/generate",
            json={"name": "Q1 corrected", "content_type": "full", "supersedes_report_id": "old-id"},
            headers={"Authorization": "Bearer test-key"},
        )

    assert r.status_code == 200
    assert r.json()["supersedes_report_id"] == "old-id"
    _, kwargs = mocked_post.call_args
    forwarded = json.loads(kwargs["data"])
    assert forwarded == {"name": "Q1 corrected", "content_type": "full", "supersedes_report_id": "old-id"}


def test_generate_proxy_omits_supersedes_report_id_when_not_sent(_client):
    upstream_body = json.dumps({"id": "new-id"}).encode()
    mock = MagicMock(status_code=200, content=upstream_body)
    mock.json.return_value = {"id": "new-id"}

    with patch.object(dashboard.http, "post", return_value=mock) as mocked_post:
        r = _client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/report-records/generate",
            json={"name": "Ad-hoc", "content_type": "full"},
            headers={"Authorization": "Bearer test-key"},
        )

    assert r.status_code == 200
    _, kwargs = mocked_post.call_args
    forwarded = json.loads(kwargs["data"])
    assert "supersedes_report_id" not in forwarded
