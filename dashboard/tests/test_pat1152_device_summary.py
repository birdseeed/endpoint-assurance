"""Regression coverage for PAT-1152's truthful Device Summary verdict."""

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


def _summary_panel() -> str:
    start = HTML.index('id="ddtab-overview"')
    end = HTML.index('<!-- /#ddtab-overview -->', start)
    return HTML[start:end]


def test_summary_has_device_status_not_issue_tiles():
    summary = _summary_panel()
    assert ">Device status<" in summary
    assert "Issue tiles" not in summary
    assert 'id="dd-status-verdict"' in summary
    assert summary.index(">Machine information<") < summary.index(">Device status<")


def test_four_status_signals_are_semantic_buttons_with_direct_navigation():
    summary = _summary_panel()
    assert 'id="dd-posture-stats"' in summary
    render = _function("_ddRenderSummaryTiles")
    for label, destination in (
        ("Patching", "patching"),
        ("Compliance", "compliance"),
        ("Agent", "activity"),
        ("Check-in", "activity"),
    ):
        assert f"signal('{label}'" in render
        assert f"'{destination}'" in render
    assert "<button type=\"button\" class=\"dd-status-signal" in render
    assert "onclick=\"_ddTab(this.dataset.ddtab)\"" in render


def test_compliance_findings_are_ranked_and_force_action_required():
    issues = _function("_ddRenderIssues")
    assert "function _ddRenderIssues(dev, pending, failedPatches, failEvals, degraded, agentHealthState)" in issues
    assert "if (failEvals && failEvals.length)" in issues
    assert "compliance finding" in issues
    assert "tab: 'compliance'" in issues
    hard_branch = issues[issues.index("if (hardIssues.length > 0)"):]
    assert "_ddSetDeviceVerdict('action')" in hard_branch


def test_degraded_only_is_attention_needed_not_healthy():
    verdict = _function("_ddSetDeviceVerdict")
    assert "statusBadge.textContent = 'Attention needed'" in verdict
    assert "statusBadge.className = 'badge badge-warning'" in verdict

    issues = _function("_ddRenderIssues")
    degraded_branch = issues[issues.index("// Agent-health attention only"):]
    assert "_ddSetDeviceVerdict('attention')" in degraded_branch
    assert "_ddSetDeviceVerdict('healthy')" not in degraded_branch


def test_all_clear_is_the_only_healthy_path():
    issues = _function("_ddRenderIssues")
    clear_start = issues.index("hardIssues.length === 0 && attentionIssues.length === 0 && agentHealthState === 'verified'")
    clear_end = issues.index("function issueRowHtml", clear_start)
    clear_branch = issues[clear_start:clear_end]
    assert "_ddSetDeviceVerdict('healthy')" in clear_branch
    assert "No issues need review" in clear_branch


def test_ranked_rows_link_to_matching_device_page():
    issues = _function("_ddRenderIssues")
    assert "tab: 'patching'" in issues
    assert "tab: 'compliance'" in issues
    assert "tab: 'activity'" in issues
    assert 'class="dd-issue-review"' in issues
    assert 'data-ddtab="' in issues
    assert "_ddTab(this.dataset.ddtab)" in issues


def test_async_degraded_refresh_preserves_compliance_context():
    apply_degraded = _function("_ddApplyDegraded")
    assert "var data = _ddLastData" in apply_degraded
    assert "data.evaluations || []" in apply_degraded
    assert "ev.status === 'fail' || ev.status === 'error'" in apply_degraded
    assert "_ddRenderIssues(dev, pending, failedPatches, failEvals, degraded, agentHealthState)" in apply_degraded
    assert "_ddRenderSummaryTiles(dev, comp, pending, failedPatches, failEvals, degraded, agentHealthState)" in apply_degraded


def test_initial_agent_health_is_pending_and_cannot_render_normal():
    load = _function("_loadDeviceDetail")
    assert "_ddRenderIssues(dev, pending, failedPatches, failEvals, [], 'pending')" in load
    assert "_ddRenderSummaryTiles(dev, comp, pending, failedPatches, failEvals, [], 'pending')" in load

    signals = _function("_ddRenderSummaryTiles")
    assert "agentValue = 'Checking'" in signals
    assert "Waiting for agent-health verification" in signals
    assert "agentHealthState === 'verified'" in signals


def test_failed_or_unavailable_agent_health_stays_attention_needed():
    loader = _function("_loadDeviceAgentHealth")
    assert "_ddApplyDegraded([], 'unavailable')" in loader
    assert "!match || !Array.isArray(match.degraded)" in loader

    signals = _function("_ddRenderSummaryTiles")
    assert "agentHealthState === 'unavailable'" in signals
    assert "agentValue = 'Unavailable'" in signals
    assert "Unable to verify agent health" in signals

    issues = _function("_ddRenderIssues")
    assert "Agent health unavailable" in issues
    assert "_ddSetDeviceVerdict('attention')" in issues


def test_successful_explicit_empty_agent_health_is_only_normal_state():
    loader = _function("_loadDeviceAgentHealth")
    assert "Array.isArray(match.degraded)" in loader
    assert "_ddApplyDegraded(match.degraded, 'verified')" in loader

    signals = _function("_ddRenderSummaryTiles")
    verified_clear = signals[signals.index("} else if (agentHealthState === 'verified')"):]
    assert "agentValue = 'Reporting normally'" in verified_clear
    assert "agentDetail = 'No degraded signals'" in verified_clear

    issues = _function("_ddRenderIssues")
    assert "attentionIssues.length === 0 && agentHealthState === 'verified'" in issues


def test_verified_degraded_list_remains_attention_needed():
    signals = _function("_ddRenderSummaryTiles")
    degraded_branch = signals[signals.index("agentHealthState === 'verified' && degraded.length"):]
    assert "agentValue = degraded.length + ' degraded'" in degraded_branch
    assert "agentTone = 'success'" not in degraded_branch.split("} else if (agentHealthState === 'verified')")[0]

    issues = _function("_ddRenderIssues")
    assert "attention: true" in issues
    assert "degraded: true" in issues
    assert "_ddSetDeviceVerdict('attention')" in issues


def test_secondary_content_and_responsive_contract_remain_compact():
    summary = _summary_panel()
    assert summary.index(">Needs review<") > summary.index(">Device status<")
    assert summary.index(">Recent activity<") > summary.index(">Device status<")
    assert ".dd-summary-supporting { display: grid" in CSS
    assert "grid-template-columns: repeat(4, minmax(0, 1fr))" in CSS
    assert "@media (max-width: 900px)" in CSS
    assert "@media (max-width: 520px)" in CSS
