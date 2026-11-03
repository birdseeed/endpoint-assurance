#!/usr/bin/env python3
"""
test_windows_artifact_upload_workflow.py — PAT-1260 regression coverage for
windows-agent-release.yml's move from an anonymous GitHub Releases download
URL to the API's authenticated artifact-download route.

Patched-LTD/updater is a private repo, so the GitHub Releases URL this
workflow used to sign into the artifact metadata (and register with the
dashboard) 404'd for every unauthenticated device request — confirmed live
on WIN-STAGING, 2026-08-11 (bootstrap-updater: "update available 0.13.18 →
0.13.19" followed by a 404 on the download). The fix moves both RELEASE_URL
sites to the API's own authenticated download route and adds an "Upload MSI
to the API" step that must run, and must succeed, before the version is ever
registered — a device must never be told about a version whose bytes are
not yet stored there.

PAT-1257 lesson: a test that only asserts the workflow *contains* a string
proves someone wrote something that looks right, not that the shell does
what it claims. Where the step body has no genuine external dependency (the
RELEASE_URL string interpolation, and the pure-bash guard clauses in the
upload step before it ever touches the network), this file extracts and
actually EXECUTES that shell against fixtures rather than grepping the YAML.
The tailscale/ssh portion is stubbed out with fake binaries on PATH so the
test still never contacts a real host or credential, mirroring
ci/test_dashboard_registration_pattern.py's existing "never contacts
Tailscale, prod-01, or the dashboard API" contract.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/windows-agent-release.yml"

EXPECTED_URL_TEMPLATE = (
    "https://api.patched.im/v1/agent/artifact/download?platform=windows&channel=beta&version={}"
)

BASH = ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail"]


class WindowsArtifactUploadWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text()
        cls.workflow = yaml.safe_load(cls.text)
        cls.build_steps = {s.get("name"): s for s in cls.workflow["jobs"]["build"]["steps"] if s.get("name")}
        cls.publish_steps = {s.get("name"): s for s in cls.workflow["jobs"]["publish"]["steps"] if s.get("name")}
        cls.publish_step_names = [s.get("name") for s in cls.workflow["jobs"]["publish"]["steps"]]

    # -------------------------------------------------------------------
    # RELEASE_URL: both sites. EXECUTED with a fixture version rather than
    # grepped, so a future refactor of the surrounding quoting/escaping
    # cannot silently change the value this test never actually renders.
    # -------------------------------------------------------------------

    @staticmethod
    def _release_url_line(run: str) -> str:
        for line in run.splitlines():
            if line.strip().startswith("RELEASE_URL="):
                return line.strip()
        raise AssertionError("no RELEASE_URL= assignment found in step body")

    def _execute_release_url(self, run: str, version: str) -> str:
        line = self._release_url_line(run)
        script = f'V="{version}"\n{line}\nprintf %s "$RELEASE_URL"\n'
        proc = subprocess.run(BASH, input=script, capture_output=True, text=True)
        self.assertEqual(0, proc.returncode, proc.stderr)
        return proc.stdout

    def test_sign_metadata_release_url_is_the_api_download_route(self):
        run = self.build_steps["Sign artifact metadata (Ed25519)"]["run"]
        self.assertEqual(
            EXPECTED_URL_TEMPLATE.format("0.13.19"),
            self._execute_release_url(run, "0.13.19"),
        )

    def test_register_release_url_is_the_api_download_route(self):
        run = self.publish_steps["Register artifact with dashboard"]["run"]
        self.assertEqual(
            EXPECTED_URL_TEMPLATE.format("0.13.19"),
            self._execute_release_url(run, "0.13.19"),
        )

    def test_neither_release_url_site_still_points_at_github_releases(self):
        sites = {
            "build: Sign artifact metadata (Ed25519)": self.build_steps["Sign artifact metadata (Ed25519)"]["run"],
            "publish: Register artifact with dashboard": self.publish_steps["Register artifact with dashboard"]["run"],
        }
        for name, run in sites.items():
            with self.subTest(step=name):
                self.assertNotIn("github.com/${{ github.repository }}/releases/download", run)

    # -------------------------------------------------------------------
    # Upload step: exists, and is ordered correctly.
    # -------------------------------------------------------------------

    def test_upload_step_exists(self):
        self.assertIn("Upload MSI to the API", self.publish_steps)

    def test_upload_step_ordered_before_registration(self):
        self.assertLess(
            self.publish_step_names.index("Upload MSI to the API"),
            self.publish_step_names.index("Register artifact with dashboard"),
            "the artifact upload must run, and succeed, before the version is registered "
            "so a device can never be told about a version whose bytes are not yet stored",
        )

    def test_upload_step_ordered_after_its_prerequisites(self):
        # It needs the published MSI on disk, and a live tailnet + SSH key
        # to reach the box — all three must already exist by the time it runs.
        for prerequisite in ("Publish release", "Setup Tailscale", "Configure SSH key"):
            with self.subTest(prerequisite=prerequisite):
                self.assertLess(
                    self.publish_step_names.index(prerequisite),
                    self.publish_step_names.index("Upload MSI to the API"),
                )

    def test_upload_step_is_never_skippable(self):
        # No `if:` condition and no continue-on-error - a failed upload must
        # stop the job, not be silently bypassed or swallowed.
        step = self.publish_steps["Upload MSI to the API"]
        self.assertNotIn("if", step)
        self.assertNotIn("continue-on-error", step)

    def test_upload_step_reuses_admin_api_url_and_introduces_no_new_secret(self):
        step = self.publish_steps["Upload MSI to the API"]
        env = step.get("env", {})
        self.assertEqual(env.get("ADMIN_API_URL"), "${{ vars.ADMIN_API_URL }}")
        # The admin/publisher credential itself (ADMIN_API_TOKEN) is read
        # live from prod-01's dashboard.env inside the remote script, exactly
        # like "Register artifact with dashboard" below - this step's own
        # env block must not introduce a distinct new secret.
        self.assertNotIn("secrets.", str(env))

    # -------------------------------------------------------------------
    # Upload step: EXECUTE the pure-bash guard clauses and the ssh
    # invocation shape against fixtures (PAT-1257 lesson) rather than
    # grepping for "exit 1". tailscale/ssh are stubbed on PATH so this
    # never touches a real network, host, or credential.
    # -------------------------------------------------------------------

    def _upload_run_body(self) -> str:
        return self.publish_steps["Upload MSI to the API"]["run"]

    def _run_upload_script(
        self,
        *,
        admin_api_url="https://patched-api-01.example-tailnet.ts.net:8443",
        msi_contents: bytes | None = b"fake msi bytes",
        ssh_exit_code: int = 0,
    ):
        """Executes the step's real `run:` body (after substituting the same
        ${{ }} expressions GitHub Actions would) inside a sandbox: a fake
        sudo/tailscale/ssh on PATH stand in for the real ones so no network
        call, SSH key, or credential is ever touched. Returns
        (CompletedProcess, captured-ssh-stdin-bytes-or-None, captured-ssh-argv-text-or-None).
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir = root / "bin"
            bin_dir.mkdir()

            msi_name = "PatchedAgent-0.13.19.msi"
            if msi_contents is not None:
                (root / msi_name).write_bytes(msi_contents)

            ssh_stdin_capture = root / "ssh-stdin.bin"
            ssh_argv_capture = root / "ssh-argv.txt"

            # The real script calls `sudo "$(command -v tailscale)" ...`
            # (PAT-1579: resolved through PATH rather than a hardcoded
            # absolute path, since tailscale/github-action 4.1.3 moved where
            # it installs the binary and broke the old hardcoded
            # /usr/bin/tailscale call). This fake sudo checks the EXACT
            # absolute path the workflow is expected to invoke - not just
            # "some command that basenames to tailscale" - and only then
            # re-dispatches through PATH to the tailscale stub below so it
            # gets control. Pinning the exact resolved path here (rather than
            # a lenient basename match) is deliberate: the same class of gap
            # PAT-1257 was raised over - a lenient stub would keep passing
            # even if the workflow silently changed which binary it invokes.
            # Purely a sandboxing device for this test - never installed
            # anywhere real.
            expected_tailscale_path = bin_dir / "tailscale"
            (bin_dir / "sudo").write_text(
                "#!/bin/sh\n"
                f'if [ "$1" != "{expected_tailscale_path}" ]; then\n'
                f'  echo "fake sudo: expected {expected_tailscale_path}, got: $1" >&2\n'
                "  exit 99\n"
                "fi\n"
                "shift\n"
                'exec tailscale "$@"\n'
            )
            (bin_dir / "tailscale").write_text("#!/bin/sh\necho '100.64.0.1'\n")
            (bin_dir / "ssh").write_text(
                "#!/bin/sh\n"
                f'cat > "{ssh_stdin_capture}"\n'
                f'printf "%s\\n" "$@" > "{ssh_argv_capture}"\n'
                f"exit {ssh_exit_code}\n"
            )
            for name in ("sudo", "tailscale", "ssh"):
                path = bin_dir / name
                os.chmod(path, 0o755)

            run = self._upload_run_body()
            # GitHub Actions substitutes these ${{ }} expressions before the
            # shell ever sees the script; do the same substitution here so
            # what actually executes matches what would run in CI.
            run = run.replace("${{ needs.build.outputs.version }}", "0.13.19")
            run = run.replace("${{ needs.build.outputs.msi }}", msi_name)

            env = {
                **os.environ,
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
                "ADMIN_API_URL": admin_api_url,
                "RUNNER_TEMP": str(root),
                "HOME": str(root),
            }
            proc = subprocess.run(BASH, input=run, cwd=root, env=env, capture_output=True, text=True)
            # Read captures into memory now - the sandbox directory (and
            # everything in it) is gone as soon as this `with` block exits.
            stdin_bytes = ssh_stdin_capture.read_bytes() if ssh_stdin_capture.exists() else None
            argv = ssh_argv_capture.read_text() if ssh_argv_capture.exists() else None
            return proc, stdin_bytes, argv

    def test_upload_script_fails_closed_when_admin_api_url_unset(self):
        proc, stdin, _ = self._run_upload_script(admin_api_url="")
        self.assertNotEqual(0, proc.returncode)
        self.assertIn("ADMIN_API_URL is not set", proc.stdout + proc.stderr)
        self.assertIsNone(stdin, "must never reach ssh when ADMIN_API_URL is unset")

    def test_upload_script_fails_closed_when_msi_missing(self):
        proc, stdin, _ = self._run_upload_script(msi_contents=None)
        self.assertNotEqual(0, proc.returncode)
        self.assertIn("missing or empty", proc.stdout + proc.stderr)
        self.assertIsNone(stdin, "must never reach ssh when the MSI file is missing")

    def test_upload_script_pipes_the_exact_msi_bytes_into_ssh_stdin(self):
        contents = b"totally real msi bytes \x00\x01\x02\xff"
        proc, stdin_bytes, _ = self._run_upload_script(msi_contents=contents)
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertIsNotNone(stdin_bytes, "ssh was never invoked")
        self.assertEqual(contents, stdin_bytes)

    def test_upload_script_substitutes_admin_api_url_and_version_into_remote_script(self):
        proc, _, argv = self._run_upload_script(admin_api_url="https://patched-api-01.example-tailnet.ts.net:8443")
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertIn(
            "https://patched-api-01.example-tailnet.ts.net:8443/admin/agent-versions/windows/beta/0.13.19/artifact",
            argv,
        )
        self.assertIn('request = "PUT"', argv)
        self.assertIn('header = "Content-Type: application/octet-stream"', argv)
        # The placeholder tokens must never survive substitution.
        self.assertNotIn("__ADMIN_API_URL__", argv)
        self.assertNotIn("__VERSION__", argv)

    def test_upload_script_propagates_ssh_failure(self):
        # Simulates the remote curl returning a non-2xx (the remote script's
        # own HTTP_CODE gate exits 1 in that case) - the outer script must
        # propagate that failure so the step, and therefore the job, fails
        # before "Register artifact with dashboard" ever runs.
        proc, _, _ = self._run_upload_script(ssh_exit_code=1)
        self.assertNotEqual(0, proc.returncode)


if __name__ == "__main__":
    unittest.main()
