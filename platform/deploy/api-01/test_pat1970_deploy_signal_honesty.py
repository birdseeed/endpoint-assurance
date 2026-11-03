"""PAT-1970: a green `deploy-api-01` run must mean something was deployed.

`deploy-api-01.yml` used to carry two jobs and a push trigger: `build-test`
ran on every push to `main`, while `deploy` was gated on `workflow_dispatch`
plus `inputs.deploy`. A merge therefore built, tested, skipped the deploy and
reported the whole run `success` under a workflow named as a promise to
deploy. On 2026-09-21 one of those runs was nearly recorded as a completed
production deploy of a security fix while the binary on the box was untouched.

The gate was never the bug and is unchanged. The fix was to split the eager
build into its own honestly named workflow, `api-build.yml`, so the run list
reads `api-build` for a merge and `deploy-api-01` only when a deploy was
actually asked for.

That fix is a property of two `on:` blocks and a job condition, which is
exactly the kind of thing that gets undone by a later edit that looks
reasonable in isolation: adding a push trigger back to deploy-api-01.yml to
"validate merges" would silently restore the original defect in full. This
module is the regression check. It reads the real workflow files from this
checkout, in the same text-assertion style as the other workflow guards in
this directory (no YAML parser, so it has no dependency the runner might not
carry).
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
DEPLOY_WORKFLOW = WORKFLOWS / "deploy-api-01.yml"
BUILD_WORKFLOW = WORKFLOWS / "api-build.yml"


def trigger_block(workflow: str) -> str:
    """Return the `on:` block only, so a comment elsewhere cannot satisfy it."""
    match = re.search(r"(?ms)^on:\n(.*?)(?=^[a-z][a-z-]*:|\Z)", workflow)
    assert match, "workflow has no top-level `on:` block"
    return match.group(1)


def without_comments(text: str) -> str:
    """Drop comment lines so prose about the box is not read as wiring."""
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


class DeploySignalHonestyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.deploy = DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        cls.build = BUILD_WORKFLOW.read_text(encoding="utf-8")

    def test_deploy_workflow_never_runs_on_push(self) -> None:
        triggers = trigger_block(self.deploy)
        self.assertNotIn(
            "push:",
            triggers,
            "deploy-api-01.yml must not run on push: a push run cannot deploy, so it "
            "would put a green run named `deploy-api-01` in the run list having "
            "shipped nothing. That is the PAT-1970 defect. Put build-only work in "
            "api-build.yml instead.",
        )
        self.assertIn("workflow_dispatch:", triggers)

    def test_deploy_job_gate_is_unchanged(self) -> None:
        self.assertIn(
            "if: github.event_name == 'workflow_dispatch' && inputs.deploy "
            "&& github.ref == 'refs/heads/main'",
            self.deploy,
        )

    def test_run_name_distinguishes_shipping_from_not(self) -> None:
        # The run list shows run-name, not the workflow name, so this string is
        # the whole point: it is what someone glancing at the Actions tab reads.
        self.assertIn("run-name:", self.deploy)
        run_name = re.search(r"(?ms)^run-name:.*?(?=^\S)", self.deploy)
        self.assertIsNotNone(run_name)
        rendered = run_name.group(0)
        self.assertIn("SHIPPING to patched-api-01", rendered)
        self.assertIn("BUILD ONLY, nothing shipped", rendered)
        # Both arms must key off the same two facts the deploy job's `if` tests,
        # or the title can claim a deploy the run did not perform.
        self.assertIn("inputs.deploy", rendered)
        self.assertIn("github.ref == 'refs/heads/main'", rendered)

    def test_skipped_deploy_announces_itself_on_the_run_page(self) -> None:
        # A skipped job is easy to miss; a warning annotation is not. This
        # covers the one green-but-shipped-nothing path that survives the
        # split: an artifact-only dispatch (deploy=false, or a non-main ref).
        self.assertIn("no-deploy-notice:", self.deploy)
        self.assertIn(
            "if: ${{ !(inputs.deploy && github.ref == 'refs/heads/main') }}",
            self.deploy,
        )
        self.assertIn("::warning::NOTHING WAS DEPLOYED.", self.deploy)

    def test_build_workflow_runs_on_push_and_is_callable(self) -> None:
        triggers = trigger_block(self.build)
        self.assertIn("push:", triggers)
        self.assertIn("branches: [main]", triggers)
        self.assertIn("workflow_call:", triggers)
        self.assertIn("uses: ./.github/workflows/api-build.yml", self.deploy)

    def test_build_workflow_cannot_reach_the_box(self) -> None:
        # The structural half of the guarantee. api-build.yml runs
        # automatically on every merge, so it must hold no credential and name
        # no host: even if someone later adds a step to it by mistake, there is
        # nothing there for that step to deploy with. Comments are stripped
        # first, because this file explains the box at length in prose.
        #
        # The forbidden list is the means of reaching the box, not the word
        # "patched-api-01" itself: the step summary this workflow prints names
        # the host in order to say it did NOT ship to it, and a guard that
        # tripped on that would be pushing people to write vaguer output.
        wiring = without_comments(self.build)
        for forbidden in (
            "root@patched-api-01",
            "ssh -i",
            "secrets.",
            "tailscale",
            "rsync",
            "DEPLOY_SSH_KEY",
            "environment: production",
        ):
            self.assertNotIn(
                forbidden.lower(),
                wiring.lower(),
                f"api-build.yml must not reference {forbidden!r}: it runs on every "
                "push to main and must have no way to change production.",
            )

    def test_the_two_workflows_keep_distinct_names(self) -> None:
        self.assertIn("name: api-build\n", self.build)
        self.assertIn("name: deploy-api-01\n", self.deploy)


if __name__ == "__main__":
    unittest.main()
