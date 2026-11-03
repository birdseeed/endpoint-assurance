"""PAT-1398 rendered rollout workflow contract.

PAT-2299 removed the quarantined rollout-create proxy that the rest of this
file used to cover; test_pat2249_catalogue_pipeline_retired.py now proves the
route and its rules are gone. What remains here is the retained rollout
evidence view and the separate emergency path.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text()


def test_rendered_workflow_keeps_evidence_and_emergency_but_not_rollout_create():
    assert 'console-rollouts.js?v={{ console_build_id }}' in HTML
    # PAT-2249: the rollout-create prompt matched updates against the retired
    # catalogue review model (GET /admin/catalogue/products) and posted to a
    # create route PAT-2246 had already removed from the platform. The
    # read-only rollout evidence view and the separate emergency path remain.
    assert "_pdRolloutPromptFromButton" not in HTML
    assert "PatchedConsoleRollouts.eligibility" not in HTML
    assert "PatchedConsoleRollouts.rolloutBody" not in HTML
    assert "PatchedConsoleRollouts.waveEvidence" in HTML
    assert "PatchedConsoleRollouts.provenanceForRollout" in HTML
    assert "_consoleState.tenantId !== tid" in HTML
    assert "Per-device endpoint evidence unavailable. Outcomes are unknown." in HTML
    assert "No matching endpoint evidence. Device outcomes are unknown." in HTML
    assert "function _pdrEmergencyDeployPrompt" in HTML
    assert "Confirm emergency deploy" in HTML
