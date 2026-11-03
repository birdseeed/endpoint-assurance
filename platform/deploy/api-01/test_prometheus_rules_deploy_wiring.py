"""PAT-1423: workflow-level assertions that api-vps-artefacts/alerting/
prometheus-rules-patched.yml actually has a deploy path.

Before this ticket `grep -rn "prometheus-rules-patched\\|prometheus/rules"
.github/workflows/ deploy/` returned zero matches -- nothing shipped this
file anywhere, ever, and PAT-1377's fix sat unshipped on main for days as a
direct result. This is a regression check for that gap staying closed: it
reads the real .github/workflows/deploy-api-01.yml and the real deploy/
api-01/deploy-prometheus-rules.sh from this checkout (not a synthetic
fixture) and asserts the three things item 2 of the ticket names explicitly
-- the promtool gate, the install step, and the `systemctl reload
prometheus` call -- are actually wired in, plus that the workflow actually
stages and invokes the script over SSH.

Deliberately extends this repo's existing workflow-assertion technique
rather than inventing a second one: check_binary_inventory.py (this
directory) already parses deploy-api-01.yml's named steps with a regex-based
`workflow_step` helper and is already wired into CI (`python3 deploy/api-01/
check_binary_inventory.py`, the "Verify migration and command deployment
contracts" step in deploy-api-01.yml) and its own test module loads it via
importlib (test_binary_inventory.py, same directory) -- this file does the
same thing rather than adding a YAML parser or a second CI job. It's a
separate module instead of new assertions inside check_binary_inventory.py's
`check()` because that function's contract (production-binaries.tsv, one row
per Go main command, MANAGED/SEPARATE classification) is specifically about
the three Go binaries and doesn't have a slot for "one static config file
with its own script" without stretching an already-dense, already-tested
contract to cover an unrelated concern.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "deploy-api-01.yml"
# PAT-1970 split the api-01 pipeline in two. Everything that reaches the box
# stayed in deploy-api-01.yml; the build and lint gates moved to api-build.yml,
# which runs on push and is also called by the deploy workflow.
BUILD_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "api-build.yml"
SCRIPT_PATH = REPO_ROOT / "deploy" / "api-01" / "deploy-prometheus-rules.sh"

_CHECK_MODULE_PATH = Path(__file__).with_name("check_binary_inventory.py")
_SPEC = importlib.util.spec_from_file_location("check_binary_inventory", _CHECK_MODULE_PATH)
assert _SPEC and _SPEC.loader
_CHECK_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_CHECK_MODULE)
workflow_step = _CHECK_MODULE.workflow_step


class PrometheusRulesWorkflowWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.build_workflow = BUILD_WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.script = SCRIPT_PATH.read_text(encoding="utf-8")

    # ── the workflow actually ships the file and runs the script ──────────

    def test_rsync_step_stages_the_rules_file_and_deploy_script(self):
        rsync_step = workflow_step(self.workflow, "Stage Prometheus rules on api-01")
        self.assertIn("api-vps-artefacts/alerting/prometheus-rules-patched.yml", rsync_step)
        self.assertIn("api-vps-artefacts/alerting/prometheus-rules-patched.test.yml", rsync_step)
        self.assertIn("deploy/api-01/deploy-prometheus-rules.sh", rsync_step)
        self.assertIn("/opt/patched-prometheus-staging/", rsync_step)

    def test_ci_installs_promtool_and_evaluates_the_real_fixture(self):
        ci = (REPO_ROOT / ".github" / "workflows" / "go-test.yml").read_text(encoding="utf-8")
        self.assertIn("apt-get install -y -qq prometheus", ci)
        self.assertIn("promtool --version | grep -F '2.45.3'", ci)
        self.assertIn("promtool test rules api-vps-artefacts/alerting/prometheus-rules-patched.test.yml", ci)
        self.assertIn("promtool check rules api-vps-artefacts/alerting/prometheus-rules-patched.yml", ci)

    def test_ci_runs_selector_liveness_module(self):
        ci = (REPO_ROOT / ".github" / "workflows" / "go-test.yml").read_text(encoding="utf-8")
        self.assertIn("api-vps-artefacts/alerting/selector-liveness/**", ci)
        self.assertIn("working-directory: api-vps-artefacts/alerting/selector-liveness", ci)
        self.assertIn("run: go test ./...", ci)

    def test_rules_payload_is_not_staged_where_deploy_sh_deletes_it(self):
        # The bug this asserts against actually shipped and failed on its first
        # real run with exit 127 "No such file or directory". The rules script
        # and yml rode the SAME rsync as the Go binaries, into
        # /opt/patched-deploy-staging/ -- and deploy.sh removes that entire
        # directory as its last action (its "Cleaning up staging directory"
        # block, guarded by PATCHED_DEPLOY_KEEP_STAGING). So by the time the
        # rules step ran, the script it wanted to execute had been deleted by
        # the deploy it was deliberately sequenced after.
        #
        # The ordering cannot simply be swapped: the rules reference metrics
        # the new binaries emit, so the binaries must land first. The rules
        # payload therefore has to live somewhere that outlives deploy.sh.
        binaries_step = workflow_step(
            self.workflow, "Stage binaries, migrations and deploy script on api-01"
        )
        self.assertNotIn("prometheus-rules-patched.yml", binaries_step)
        self.assertNotIn("deploy-prometheus-rules.sh", binaries_step)

    def test_a_deploy_step_invokes_the_script_over_ssh(self):
        self.assertIn("deploy-prometheus-rules.sh", self.workflow)
        # Must be invoked via ssh against api-01, the same pattern deploy.sh
        # itself uses in the step immediately above -- not just staged.
        invoke_step = workflow_step(self.workflow, "Deploy Prometheus alerting rules on api-01")
        self.assertIn("root@patched-api-01", invoke_step)
        self.assertIn("/opt/patched-prometheus-staging/deploy-prometheus-rules.sh", invoke_step)
        # And must NOT reach into the directory deploy.sh deletes.
        self.assertNotIn("/opt/patched-deploy-staging/deploy-prometheus-rules.sh", invoke_step)

    def test_deploy_step_runs_after_deploy_sh_and_before_the_always_readback(self):
        # Ordering matters for two reasons: the rules file must ride the
        # same staged checkout as the binaries (no separate stage step), and
        # the provenance readback step's `if: always()` must still fire even
        # if this new step fails, so it stays positioned before it.
        deploy_idx = self.workflow.index("- name: Run deploy.sh on api-01")
        rules_idx = self.workflow.index("- name: Deploy Prometheus alerting rules on api-01")
        readback_idx = self.workflow.index(
            "- name: Read back three-binary provenance and timer state"
        )
        self.assertLess(deploy_idx, rules_idx)
        self.assertLess(rules_idx, readback_idx)

    def test_deploy_script_is_shellchecked(self):
        lint_step = workflow_step(self.build_workflow, "Lint the box-side deploy script")
        self.assertIn("deploy/api-01/deploy-prometheus-rules.sh", lint_step)

    # ── item 2's three named requirements, in the script itself ──────────

    def test_script_contains_the_promtool_gate(self):
        self.assertIn('"$PROMTOOL" test rules "$STAGED_RULE_TESTS"', self.script)
        self.assertIn('"$PROMTOOL" check rules "$STAGED_RULES"', self.script)
        # The gate must run, and its failure (promtool's own non-zero exit,
        # caught by `set -e`) must happen BEFORE any install step below.
        test_gate_idx = self.script.index('"$PROMTOOL" test rules')
        check_gate_idx = self.script.index('"$PROMTOOL" check rules')
        install_idx = self.script.index('mv -f "${RULES_DEST}.new" "$RULES_DEST"')
        self.assertLess(test_gate_idx, install_idx)
        self.assertLess(check_gate_idx, install_idx)

    def test_script_contains_an_install_step(self):
        self.assertIn('cp "$STAGED_RULES" "${RULES_DEST}.new"', self.script)
        self.assertIn('mv -f "${RULES_DEST}.new" "$RULES_DEST"', self.script)

    def test_script_reloads_via_systemctl_not_the_disabled_http_endpoint(self):
        self.assertIn('"$SYSTEMCTL" reload prometheus', self.script)
        # The whole point of item 2's callout: the HTTP endpoint is disabled
        # (403, no --web.enable-lifecycle) -- the script must not actually
        # call it, and must not add the flag that would re-enable it either.
        # Both strings are expected to appear in the header comment
        # explaining this constraint, so check executable lines only.
        code_lines = [
            line for line in self.script.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        code = "\n".join(code_lines)
        self.assertNotIn("/-/reload", code)
        self.assertNotIn("web.enable-lifecycle", code)

    def test_script_backs_up_the_previous_file_before_overwriting(self):
        self.assertIn('cp -a "$RULES_DEST" "$BACKUP"', self.script)
        backup_idx = self.script.index('cp -a "$RULES_DEST" "$BACKUP"')
        install_idx = self.script.index('mv -f "${RULES_DEST}.new" "$RULES_DEST"')
        self.assertLess(backup_idx, install_idx)

    def test_script_verifies_reload_success_before_declaring_victory(self):
        self.assertIn("prometheus_config_last_reload_successful", self.script)
        self.assertIn("prometheus_config_last_reload_success_timestamp_seconds", self.script)

    def test_script_writes_a_sidecar_hash_for_drift_detection(self):
        self.assertIn("INSTALLED_SHA256=", self.script)
        self.assertIn('mv -f "${SIDECAR}.new" "$SIDECAR"', self.script)


if __name__ == "__main__":
    unittest.main()
