"""PAT-1436: workflow-level assertions that api-vps-artefacts/
patched-maintenance-facts.sh -- the emitter api-01 runs hourly via
patched-maintenance-facts.timer -- actually has a deploy path.

Before this ticket, `grep -rn "patched-maintenance-facts.sh"
.github/workflows/` returned zero matches: nothing shipped this file to
/opt/patched-api/bin/patched-maintenance-facts.sh, ever. It only reached the
box when a person copied it by hand. Confirmed live after a successful
deploy run: portal-01's copy of this script (shipped whole via portal's own
deploy/ directory) reports stray_config_backups and the prometheus_rules_*
fields; api-01's never has, because the script simply was not there to run.
This is a regression check for that gap staying closed -- same technique as
test_prometheus_rules_deploy_wiring.py (this directory): read the real
.github/workflows/deploy-api-01.yml from this checkout and assert the
emitter is actually staged to its final path, rather than adding a YAML
parser or a second CI job.

Also pins the PAT-1423 staging-lifecycle trap so it does not bite a third
time: deploy.sh deletes /opt/patched-deploy-staging/ as its very last
action (its "Cleaning up staging directory" block, guarded by
PATCHED_DEPLOY_KEEP_STAGING). PAT-1423 originally rode that same rsync and
failed on its first real run with exit 127, "No such file or directory" --
the script had been deleted by the deploy it was sequenced after. This
emitter avoids that trap a different way than PAT-1423 did: rather than a
second staging directory plus a separate install script, it ships straight
to its final destination in one rsync step, because (unlike the Prometheus
rules) it needs no promtool-equivalent gate, backup, or reload before going
live -- the next hourly timer firing just picks up whatever is on disk.
"""

from __future__ import annotations

import importlib.util
import os
import stat
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "deploy-api-01.yml"
SCRIPT_PATH = REPO_ROOT / "api-vps-artefacts" / "patched-maintenance-facts.sh"

_CHECK_MODULE_PATH = Path(__file__).with_name("check_binary_inventory.py")
_SPEC = importlib.util.spec_from_file_location("check_binary_inventory", _CHECK_MODULE_PATH)
assert _SPEC and _SPEC.loader
_CHECK_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_CHECK_MODULE)
workflow_step = _CHECK_MODULE.workflow_step


class MaintenanceFactsDeployWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    # ── the workflow actually ships the emitter to its final path ─────────

    def test_a_step_ships_the_emitter_to_its_final_path(self):
        deploy_step = workflow_step(self.workflow, "Deploy maintenance facts emitter on api-01")
        self.assertIn("api-vps-artefacts/patched-maintenance-facts.sh", deploy_step)
        self.assertIn("root@patched-api-01", deploy_step)
        # Final path, not a staging path -- ExecStart= in
        # patched-maintenance-facts.service invokes this exact path directly.
        self.assertIn("/opt/patched-api/bin/patched-maintenance-facts.sh", deploy_step)

    def test_emitter_is_not_staged_where_deploy_sh_deletes_it(self):
        # The bug this asserts against already shipped once, for a different
        # file (PAT-1423's Prometheus rules), and failed on its first real
        # run with exit 127 "No such file or directory". deploy.sh removes
        # /opt/patched-deploy-staging/ entirely as its last action (its
        # "Cleaning up staging directory" block, guarded by
        # PATCHED_DEPLOY_KEEP_STAGING) -- anything riding the same rsync as
        # the Go binaries into that directory is gone by the time any later
        # step tries to use it.
        deploy_step = workflow_step(self.workflow, "Deploy maintenance facts emitter on api-01")
        # Check the actual rsync destination, not the step's prose -- the
        # step's own comments legitimately name /opt/patched-deploy-staging/
        # to explain why it was avoided, so a bare substring check over the
        # whole step (comments included) would trip on its own explanation.
        code_lines = [
            line for line in deploy_step.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        self.assertNotIn("/opt/patched-deploy-staging/", "\n".join(code_lines))

        binaries_step = workflow_step(
            self.workflow, "Stage binaries, migrations and deploy script on api-01"
        )
        self.assertNotIn("patched-maintenance-facts.sh", binaries_step)

        prometheus_step = workflow_step(self.workflow, "Stage Prometheus rules on api-01")
        self.assertNotIn("patched-maintenance-facts.sh", prometheus_step)

    def test_deploy_step_runs_after_deploy_sh_and_before_the_always_readback(self):
        # The provenance readback step's `if: always()` must still fire even
        # if this new step fails, so it must stay positioned before it.
        deploy_idx = self.workflow.index("- name: Run deploy.sh on api-01")
        emitter_idx = self.workflow.index("- name: Deploy maintenance facts emitter on api-01")
        readback_idx = self.workflow.index(
            "- name: Read back three-binary provenance and timer state"
        )
        self.assertLess(deploy_idx, emitter_idx)
        self.assertLess(emitter_idx, readback_idx)

    # ── the executable bit, which this file genuinely needs ───────────────

    def test_script_is_executable_in_the_checkout(self):
        # patched-maintenance-facts.timer's unit runs this script via
        # `ExecStart=/opt/patched-api/bin/patched-maintenance-facts.sh`
        # directly (systemd, not `bash <path>`), so it genuinely needs +x --
        # unlike deploy-prometheus-rules.sh, which is invoked as
        # `bash <path>` and works fine without it. actions/checkout@v4
        # preserves git's tracked file mode, and this step ships straight
        # from that checkout (never through actions/upload-artifact +
        # actions/download-artifact, which is what strips the +x bit off
        # the Go binaries and is why the binaries step needs an explicit
        # `chmod +x`). If this file's mode ever regresses to non-executable
        # in git, the hourly timer will fail with a permission error on the
        # box even though this deploy step "succeeds".
        mode = os.stat(SCRIPT_PATH).st_mode
        self.assertTrue(
            mode & stat.S_IXUSR,
            f"{SCRIPT_PATH} is not executable ({oct(mode)}); "
            "patched-maintenance-facts.timer invokes it via ExecStart= directly "
            "and will fail once deployed",
        )

    def test_no_chmod_needed_because_the_bit_already_survives_the_checkout(self):
        # Documents *why* the deploy step doesn't chmod +x itself (unlike the
        # binaries rsync step, which restores +x after upload/download-
        # artifact drops it): rsync -a preserves the source file's mode, and
        # the source here is the actions/checkout working tree, not an
        # artifact round-trip. If a chmod is ever added to this specific
        # step, that's a sign the file stopped being executable in git and
        # this test above would have already failed.
        deploy_step = workflow_step(self.workflow, "Deploy maintenance facts emitter on api-01")
        self.assertNotIn("chmod +x", deploy_step)

    # ── the file is verified executable on the box, not just assumed ──────

    def test_a_step_verifies_the_file_landed_executable_on_the_box(self):
        # Non-author review (PAT-1436): the rsync step relies on git mode +
        # `rsync -a` preserving +x, but this whole ticket exists because a
        # file this box needed was silently not there. Shipping this one and
        # only ASSUMING it arrived correctly would repeat that shape one
        # level down -- so the workflow must check for real, over SSH,
        # against the box, not just trust the transfer.
        verify_step = workflow_step(
            self.workflow, "Verify the maintenance facts emitter landed executable"
        )
        self.assertIn("root@patched-api-01", verify_step)
        # Assert the behaviour, not one spelling of it: the step must test
        # executability of that exact path on the box. `test -x`, `[ -x ]`
        # and a case/if over them are all acceptable shapes.
        self.assertIn("-x /opt/patched-api/bin/patched-maintenance-facts.sh", verify_step)

    def test_error_annotations_go_to_stdout_not_stderr(self):
        # `::error::` is a GitHub Actions workflow command and is parsed ONLY
        # from stdout. Redirecting it to stderr puts it in the raw log but
        # NOT in the Actions UI as an annotation -- which would make the
        # step quieter than the failure it exists to shout about. This
        # shipped that way once and a non-author review caught it.
        verify_step = workflow_step(
            self.workflow, "Verify the maintenance facts emitter landed executable"
        )
        for line in verify_step.splitlines():
            if "::error::" in line:
                self.assertNotIn(
                    ">&2",
                    line,
                    "::error:: must go to stdout or Actions will not render it as an "
                    f"annotation; offending line: {line.strip()}",
                )

    def test_an_unreachable_box_is_not_reported_as_a_lost_executable_bit(self):
        # A bare `test -x` over ssh cannot tell "not executable" from "ssh
        # never got there" -- both are non-zero. Reporting a network or auth
        # failure as a chmod problem sends the reader to debug the wrong
        # thing, so the step must distinguish them.
        verify_step = workflow_step(
            self.workflow, "Verify the maintenance facts emitter landed executable"
        )
        self.assertIn("SSH/network failure", verify_step)
        self.assertIn("missing", verify_step)

    def test_verification_failure_is_loud_and_explains_the_broken_timer(self):
        # A quiet failure here is the exact familiar shape this ticket is
        # about: patched-maintenance-facts.timer invokes this file via
        # ExecStart= directly, so a lost +x bit means the timer fails on
        # EVERY hourly firing while this deploy step would otherwise report
        # success. The step must actually fail the job (not just log and
        # continue) and must say, in its own failure message, what a lost
        # +x bit means -- so whoever hits it does not have to re-derive that
        # the timer is now broken.
        verify_step = workflow_step(
            self.workflow, "Verify the maintenance facts emitter landed executable"
        )
        self.assertIn("exit 1", verify_step)
        self.assertIn("ExecStart", verify_step)
        self.assertIn("timer", verify_step.lower())

    def test_verification_step_runs_after_the_transfer_and_before_the_always_readback(self):
        # Must run after the file is actually shipped (nothing to verify
        # before that), and -- like every other step in this sequence --
        # before the provenance readback's `if: always()`, so a failure here
        # still lets that step run and surface the box's real state.
        emitter_idx = self.workflow.index("- name: Deploy maintenance facts emitter on api-01")
        verify_idx = self.workflow.index(
            "- name: Verify the maintenance facts emitter landed executable"
        )
        readback_idx = self.workflow.index(
            "- name: Read back three-binary provenance and timer state"
        )
        self.assertLess(emitter_idx, verify_idx)
        self.assertLess(verify_idx, readback_idx)


if __name__ == "__main__":
    unittest.main()
