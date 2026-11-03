"""Regression coverage for PAT-1153's machine-first Device Summary."""

from pathlib import Path


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


def _summary() -> str:
    start = HTML.index('id="ddtab-overview"')
    end = HTML.index('<!-- /#ddtab-overview -->', start)
    return HTML[start:end]


def test_summary_hierarchy_is_machine_then_status_then_supporting_work():
    summary = _summary()
    machine = summary.index(">Machine information<")
    status = summary.index(">Device status<")
    review = summary.index(">Needs review<")
    activity = summary.index(">Recent activity<")
    assert machine < status < review
    assert machine < status < activity
    assert 'class="panel dd-machine-card"' in summary
    assert 'class="dd-machine-grid" id="dd-identity-grid"' in summary


def test_machine_information_has_exact_fixed_fact_set_in_stable_order():
    render = _function("_ddRenderMachineInformation")
    fields = [
        "Hostname", "Model", "Serial", "OS", "CPU", "RAM", "Disk",
        "Primary user", "Agent version", "Last check-in", "Last login",
        "Backup", "MDM",
    ]
    assert render.count("_ddMachineField(") == len(fields)
    positions = [render.index(f"_ddMachineField('{field}'") for field in fields]
    assert positions == sorted(positions)
    assert "Not reported" in render
    assert "_ddReported" in render


def test_os_disk_and_dates_use_complete_honest_formatting():
    render = _function("_ddRenderMachineInformation")
    assert "dev.os, dev.os_version" in render
    assert "dev.os_build" in render
    assert "hardware.disk_total_gb" in render
    assert "hardware.disk_free_gb" in render
    assert "free space not reported" in render
    assert "_fmtTsHtml(dev.last_seen)" in render
    assert "_fmtTsHtml(dev.primary_user_last_seen_at)" in render
    assert "dev.last_seen ?" in render and ": 'Not reported'" in render


def test_mdm_always_resolves_to_one_of_three_explicit_states():
    mdm = _function("_ddMdmState")
    assert "return 'Not reported'" in mdm
    assert "? 'Enrolled' : 'Not enrolled'" in mdm
    assert "mdm|dep" in mdm
    render = _function("_ddRenderMachineInformation")
    assert "_ddMdmState(signalMap.patched_mdm_enrollment)" in render


def test_backup_prefers_matching_cached_inventory_device():
    load = _function("_ddLoadMachineBackup")
    assert "_dhLastTenantId === tenantId" in load
    assert "cacheIsCurrent && Array.isArray(_dhDevices) ? _dhDevices : []" in load
    assert "_ddInventoryDeviceMatch(row, deviceId, detailDevice)" in load
    cached_branch = load[load.index("if (cached)"):load.index("if (!tenantId)")]
    assert "_ddRenderMachineBackup(deviceId, cached)" in cached_branch
    assert "return;" in cached_branch


def test_previous_tenant_cache_is_skipped_even_for_reused_id_or_serial():
    load = _function("_ddLoadMachineBackup")
    tenant_pos = load.index("var tenantId = _consoleState.tenantId")
    guard_pos = load.index("var cacheIsCurrent = !!tenantId && _dhLastTenantId === tenantId")
    cache_pos = load.index("cacheIsCurrent && Array.isArray(_dhDevices)")
    fallback_pos = load.index("fetchTenantDevices(tenantId, { limit: 500 })")
    assert tenant_pos < guard_pos < cache_pos < fallback_pos
    # ID/serial matching is unreachable for stale-tenant rows because the
    # cache source becomes [] before .find invokes this predicate.
    assert "_ddInventoryDeviceMatch(row, deviceId, detailDevice)" in load[cache_pos:fallback_pos]
    assert "if (cached)" in load[cache_pos:fallback_pos]
    assert "return;" in load[cache_pos:fallback_pos]
    # When cacheIsCurrent is false, execution therefore continues to the
    # current-tenant fallback instead of accepting the reused identity.
    assert "fetchTenantDevices(tenantId, { limit: 500 })" in load[fallback_pos:]


def test_backup_fallback_is_supplementary_and_stale_guarded():
    load = _function("_ddLoadMachineBackup")
    assert "fetchTenantDevices(tenantId, { limit: 500 })" in load
    then_branch = load[load.index(".then(function(data)"):]
    assert "if (_ddStale(deviceId)) return" in then_branch
    assert "data && Array.isArray(data.devices)" in then_branch
    assert "_ddRenderMachineBackup(deviceId, match || null)" in then_branch
    assert "Not reported" in load

    device_load = _function("_loadDeviceDetail")
    render_pos = device_load.index("_ddRenderMachineInformation(dev, hw0, _earlySigMap)")
    backup_pos = device_load.index("_ddLoadMachineBackup(deviceId, dev)")
    assert render_pos < backup_pos
    assert "await _ddLoadMachineBackup" not in device_load


def test_backup_uses_canonical_bucket_and_tooltip_semantics():
    value = _function("_ddBackupValueHtml")
    assert "_DH_BACKUP_BUCKET_META[backup.bucket]" in value
    assert "_dhBackupTooltipText(backup)" in value
    assert "meta.cls" in value and "meta.label" in value
    assert "Not reported" in value


def test_status_is_compact_secondary_and_issues_are_separate():
    summary = _summary()
    status_start = summary.index('class="panel dd-status-card"')
    status_end = summary.index("</div>\n\n          <div class=\"dd-summary-supporting\"", status_start)
    status = summary[status_start:status_end]
    assert 'id="dd-status-verdict"' in status
    assert 'id="dd-posture-stats"' in status
    assert 'id="dd-issues-banner"' not in status
    assert 'class="panel dd-summary-review"' in summary
    assert 'id="dd-issues-banner"' in summary[status_end:]


def test_machine_information_has_no_disclosure_or_extra_click():
    summary = _summary()
    machine_start = summary.index('class="panel dd-machine-card"')
    machine_end = summary.index('class="panel dd-status-card"')
    machine = summary[machine_start:machine_end]
    for disclosure in ("<details", "<summary", "aria-expanded", "accordion", "toggle"):
        assert disclosure not in machine.lower()
    assert "<button" not in machine


def test_machine_grid_is_responsive_without_fixed_width_overflow():
    assert "grid-template-columns: repeat(4, minmax(0, 1fr))" in CSS
    assert "@media (max-width: 700px)" in CSS
    assert "grid-template-columns: repeat(2, minmax(0, 1fr))" in CSS
    assert "@media (max-width: 430px)" in CSS
    assert ".dd-machine-grid { grid-template-columns: 1fr; }" in CSS
    assert ".dd-machine-field { min-width: 0" in CSS
    assert "overflow-wrap: anywhere" in CSS


def test_pat1152_truth_contract_is_unchanged():
    issues = _function("_ddRenderIssues")
    assert "if (hardIssues.length > 0)" in issues
    hard = issues[issues.index("if (hardIssues.length > 0)"):]
    assert "_ddSetDeviceVerdict('action')" in hard
    assert "agentHealthState === 'verified'" in issues
    assert "_ddSetDeviceVerdict('healthy')" in issues
    assert "_ddSetDeviceVerdict('attention')" in issues

    agent = _function("_loadDeviceAgentHealth")
    assert "_ddApplyDegraded([], 'unavailable')" in agent
    assert "_ddApplyDegraded(match.degraded, 'verified')" in agent
