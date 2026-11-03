"""PAT-1358 regression guards for the compact Infrastructure workspace."""

import os
from pathlib import Path
import subprocess

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard


ROOT = Path(__file__).resolve().parents[1]
CONSOLE = (ROOT / "templates" / "console.html").read_text()
CONSOLE_CSS = (ROOT / "static" / "css" / "console.css").read_text()


def _function(name: str) -> str:
    start = CONSOLE.index("function " + name + "(")
    brace = CONSOLE.index("{", start)
    depth = 0
    for index in range(brace, len(CONSOLE)):
        if CONSOLE[index] == "{":
            depth += 1
        elif CONSOLE[index] == "}":
            depth -= 1
            if depth == 0:
                return CONSOLE[start:index + 1]
    raise AssertionError(f"unbalanced {name}")


def test_supporting_details_render_every_legacy_ops_field():
    render = _function("_opsRender")
    for field in (
        "health.db_reachable",
        "freshness.most_recent_ingest_at",
        "serviceRows['patched-dashboard']",
        "serviceRows.nginx",
        "api.build_time",
        "dashboard.committed_at",
        "item.not_after",
        "partitionList.length",
        "latestPartition.month",
        "detail.maintenanceAssessments[index].age.label",
    ):
        assert field in render


def test_infrastructure_tenant_link_is_explicitly_read_only():
    enter = _function("enterTenant")
    ops_open = _function("_opsOpenTenant")
    assert "PatchedConsoleInfrastructure.shouldSignalTenantEntry(options)" in enter
    assert "enterTenant(tenant, tab || 'device-health', { readOnly: true })" in ops_open


def test_guarded_infrastructure_actions_use_the_consultant_owner_gate():
    assert '<section class="infra-guarded owner-only"' in CONSOLE
    assert ".role-consultant .owner-only { display:none !important; }" in (ROOT / "static" / "css" / "console.css").read_text()


def test_firewall_attention_actions_are_owner_only_too():
    render = _function("_opsRender")
    assert "action.kind === 'firewall' ? ' owner-only'" in render
    assert 'class="' + "' + actionClass + '" in render


def test_infrastructure_details_shrink_and_wrap_unbroken_proof_values():
    assert ".infra-details {" in CONSOLE_CSS
    assert ".infra-details details { min-width: 0; }" in CONSOLE_CSS
    assert ".infra-detail-grid > * { min-width: 0; }" in CONSOLE_CSS
    assert ".infra-detail-grid li, .infra-check-list li { overflow-wrap: anywhere; }" in CONSOLE_CSS


def test_dashboard_provenance_reports_match_mismatch_and_missing_record(tmp_path, monkeypatch):
    full_sha = "a" * 40
    calls = []

    def fake_check_output(command, **_kwargs):
        calls.append(command)
        if "--short" in command:
            return full_sha[:12] + "\n"
        if command[-1] == "HEAD":
            return full_sha + "\n"
        return "2026-08-14 12:00:00 +0000\n"

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)
    record = tmp_path / "DEPLOYED_SHA"
    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(tmp_path))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(record))

    record.write_text(f"DEPLOYED_SHA={full_sha}\nDEPLOYED_AT=2026-08-14T12:00:00+00:00\n")
    assert dashboard._ops_dashboard_version()["deployment_match"] == "match"

    record.write_text("DEPLOYED_SHA=" + "b" * 40 + "\n")
    assert dashboard._ops_dashboard_version()["deployment_match"] == "mismatch"

    record.unlink()
    missing = dashboard._ops_dashboard_version()
    assert missing["deployment_match"] == "unknown"
    assert missing["deployed_sha"] is None
    assert all(command[2] == str(tmp_path) for command in calls)


def test_dashboard_provenance_rejects_short_long_and_non_utf8_records(tmp_path, monkeypatch):
    full_sha = "c" * 40
    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(tmp_path))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(tmp_path / "DEPLOYED_SHA"))
    monkeypatch.setattr(subprocess, "check_output", lambda command, **_kwargs: full_sha[:12] + "\n" if "--short" in command else (full_sha + "\n" if command[-1] == "HEAD" else "2026-08-14 12:00:00 +0000\n"))

    record = tmp_path / "DEPLOYED_SHA"
    for invalid in ("d" * 39, "d" * 41, "not-a-sha"):
        record.write_text(f"DEPLOYED_SHA={invalid}\n")
        assert dashboard._ops_dashboard_version()["deployment_match"] == "unknown"

    record.write_bytes(b"DEPLOYED_SHA=" + full_sha.encode() + b"\xff\n")
    assert dashboard._ops_dashboard_version()["deployment_match"] == "unknown"
