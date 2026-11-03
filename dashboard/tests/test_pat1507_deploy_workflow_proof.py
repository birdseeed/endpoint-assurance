"""Regression coverage for GitHub Actions reporting a rolled-back deploy as green."""

from __future__ import annotations

from pathlib import Path

import yaml


REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / "ci-archive" / "workflows" / "deploy.yml"


def _deploy_steps() -> list[dict]:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return workflow["jobs"]["deploy"]["steps"]


def _step_index(name_fragment: str) -> int:
    for index, step in enumerate(_deploy_steps()):
        if name_fragment.lower() in step.get("name", "").lower():
            return index
    raise AssertionError(f"no deploy workflow step contains {name_fragment!r}")


def test_workflow_fails_when_the_requested_revision_is_not_operating():
    verify_index = _step_index("verify deployed revision")
    script = _deploy_steps()[verify_index]["with"]["script"]

    assert _step_index("bare mirror") < verify_index
    assert _step_index("reconcile box-side config") < verify_index
    assert "expected_sha='${{ github.sha }}'" in script
    assert "git -C /opt/patched-dashboard rev-parse HEAD" in script
    assert "DEPLOYED_SHA" in script
    assert "systemctl is-active --quiet patched-dashboard" in script
    assert '"$actual_sha" != "$expected_sha"' in script
    assert '"$deployed_sha" != "$expected_sha"' in script
    assert "exit 1" in script
