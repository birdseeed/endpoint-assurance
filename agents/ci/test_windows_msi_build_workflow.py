#!/usr/bin/env python3
"""
test_windows_msi_build_workflow.py - PAT-1777 regressions for the shared
Windows agent MSI build.

The MSI build steps (Setup .NET, Publish Service, Python setup, the
credential guard, Build MSI and the File table assertion) live in one
composite action, .github/actions/windows-agent-msi, called in two phases by
windows-agent-release.yml. The release workflow keeps every supply-chain
control where it was: the artifact trust key gate before the build, and HMAC
and Ed25519 signing with their "Assert ... was signed when expected" gates
after it. (PAT-2304, 2026-09-30: the legacy allowlist signature check that
used to run between the two build phases is retired with the allowlist.)
windows-msi-build.yml runs the same two phases on pull requests, build only,
so a WiX error such as WIX0012 fails the pull request instead of the release.

These tests lock that shape. They never run a workflow and never contact a
network; where a step body has no external dependency (the action's input
validation) it is executed against fixtures rather than grepped.
"""

import os
import json
import re
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / ".github/workflows/windows-agent-release.yml"
PR_CHECK = ROOT / ".github/workflows/windows-msi-build.yml"
ACTION = ROOT / ".github/actions/windows-agent-msi/action.yml"
RESOLVER = ROOT / "windows/installer/resolve-release-version.sh"
ACTION_REF = "./.github/actions/windows-agent-msi"
SHA = "0123456789abcdef0123456789abcdef01234567"

BASH = ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail"]

# The release build job, in order. Changing this list means changing where a
# supply-chain control runs relative to the build: review it as such.
RELEASE_BUILD_STEPS = [
    None,  # actions/checkout@v7
    "Resolve version",
    "Assert self-update artifact trust key is provisioned",
    "Build headless Service",
    "Build and verify MSI",
    "Report build mode in job summary",
    "Locate MSI and compute checksum",
    "Sign artifact with HMAC-SHA256",
    "Assert artifact was signed when expected",
    "Sign artifact metadata (Ed25519)",
    "Assert artifact metadata was signed when expected",
    "Upload release artifact",
]

PREPARE_STEPS = [
    "Setup .NET (8 + 10)",
    "Publish Service",
    "Setup Python",
    "Install Python dependencies",
]
PACKAGE_STEPS = [
    "Guard MSI credential properties stay out of install logs",
    "Guard MSI sets an explicit install-directory ACL",
    "Test headless payload guard",
    "Build MSI",
    "Assert headless assurance MSI payload",
    "Assert install-directory ACL in the built MSI",
]

SECRET_OR_PUBLISH_MARKERS = (
    "secrets.",
    "ARTIFACT_SIGNING_KEY",
    "ARTIFACT_METADATA_SIGNING_KEY",
    "UPDATER_",
    "DEPLOY_SSH_KEY",
    "TS_OAUTH",
    "upload-artifact",
    "gh release",
    "git push",
    "git tag",
    "ssh ",
    "tailscale",
    "curl ",
    "api.patched.im",
)


def load(path: Path) -> dict:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict), f"{path}: expected a mapping"
    return document


def without_comments(text: str) -> str:
    """Drop full-line YAML comments, which explain what the file must not do."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def resolve(version: str) -> dict:
    proc = subprocess.run(
        ["bash", str(RESOLVER), version, SHA], capture_output=True, text=True, check=True
    )
    return dict(line.split("=", 1) for line in proc.stdout.splitlines())


class SharedActionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = without_comments(ACTION.read_text(encoding="utf-8"))
        cls.action = load(ACTION)
        cls.steps = cls.action["runs"]["steps"]

    def test_is_a_composite_action_with_the_resolver_inputs(self):
        self.assertEqual("composite", self.action["runs"]["using"])
        self.assertEqual(
            {"phase", "version", "file_version", "informational_version", "msi_product_version"},
            set(self.action["inputs"]),
        )
        for name, spec in self.action["inputs"].items():
            with self.subTest(input=name):
                self.assertIs(True, spec.get("required"))

    def test_phases_contain_exactly_the_shared_build_steps_in_order(self):
        self.assertEqual("Validate windows-agent-msi inputs", self.steps[0]["name"])
        self.assertNotIn("if", self.steps[0], "input validation must run for every phase")
        by_phase = {"prepare": [], "package": []}
        for step in self.steps[1:]:
            condition = step.get("if", "")
            phases = [p for p in by_phase if condition == f"success() && inputs.phase == '{p}'"]
            self.assertEqual(1, len(phases), f"{step.get('name')}: unexpected if: {condition!r}")
            by_phase[phases[0]].append(step["name"])
        self.assertEqual(PREPARE_STEPS, by_phase["prepare"])
        self.assertEqual(PACKAGE_STEPS, by_phase["package"])

    def test_build_msi_compiles_the_checked_out_wix_project(self):
        # PAT-1777 acceptance: this is the step WIX0012 fails, and it builds
        # whatever windows/installer/Product.wxs the caller checked out.
        step = next(s for s in self.steps if s["name"] == "Build MSI")
        self.assertEqual(
            "dotnet build windows/installer/Patched.wixproj -c Release "
            "-p:ProductVersion=${{ inputs.msi_product_version }} --nologo",
            step["run"],
        )
        self.assertNotIn("continue-on-error", step)

    def test_no_step_can_fail_open(self):
        for step in self.steps:
            with self.subTest(step=step.get("name")):
                self.assertNotIn("continue-on-error", step)

    def test_action_references_no_secret_and_publishes_nothing(self):
        for marker in SECRET_OR_PUBLISH_MARKERS:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, self.text)

    def test_third_party_actions_match_the_release_pins(self):
        uses = {s["uses"] for s in self.steps if "uses" in s}
        self.assertEqual({"actions/setup-dotnet@v6", "actions/setup-python@v5"}, uses)

    # Executed, not grepped: the validation guards the ${{ inputs.* }}
    # interpolation into the dotnet command lines.

    def _validate(self, phase, values):
        run = self.steps[0]["run"]
        env = {
            **os.environ,
            "PHASE": phase,
            "VERSION": values["version"],
            "FILE_VERSION": values["file_version"],
            "INFORMATIONAL_VERSION": values["informational_version"],
            "MSI_PRODUCT_VERSION": values["msi_product_version"],
        }
        return subprocess.run(BASH, input=run, env=env, capture_output=True, text=True)

    def test_validation_accepts_every_resolver_output(self):
        for version in (
            "0.0.0", "0.13.19", "253.255.655",
            "0.15.1-beta.1", "0.15.1.1", "253.255.654-beta.99",
        ):
            for phase in ("prepare", "package"):
                with self.subTest(version=version, phase=phase):
                    proc = self._validate(phase, resolve(version))
                    self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)

    def test_validation_rejects_malformed_beta_identities(self):
        good = resolve("0.15.1-beta.1")
        for version in (
            "", "0.15", "0.15.1-beta.1", "0.15.1.0", "0.15.1.00",
            "0.15.1.01", "0.15.1.100", "0.15.1.-1", "0.15.1.x",
            "0.15.1.1.1", "0.15.1.1\n", "0.15.1.1 ",
        ):
            for phase in ("prepare", "package"):
                with self.subTest(version=version, phase=phase):
                    proc = self._validate(phase, {
                        **good, "version": version, "informational_version": version + "+" + SHA,
                    })
                    self.assertNotEqual(0, proc.returncode)
                    self.assertIn("invalid version", proc.stdout)

    def test_informational_version_must_match_the_installable_identity(self):
        for version, other in (("1.2.3", "1.2.4"), ("0.15.1-beta.1", "0.15.1.2")):
            for phase in ("prepare", "package"):
                with self.subTest(version=version, phase=phase):
                    proc = self._validate(phase, {
                        **resolve(version), "informational_version": other + "+" + SHA,
                    })
                    self.assertNotEqual(0, proc.returncode)
                    self.assertIn("invalid informational_version", proc.stdout)

    def test_validation_rejects_an_unknown_phase(self):
        for phase in ("", "Prepare", "publish", "prepare package"):
            with self.subTest(phase=phase):
                proc = self._validate(phase, resolve("0.0.0"))
                self.assertNotEqual(0, proc.returncode)
                self.assertIn("unknown phase", proc.stdout)

    def test_validation_rejects_values_that_could_alter_the_command_line(self):
        good = resolve("1.2.3")
        for field, bad in (
            ("version", "1.2.3 -p:Foo=bar"),
            ("version", "1.2.3;calc"),
            ("msi_product_version", "3.2.3\n"),
            ("file_version", "3.2.3.1"),
            ("informational_version", "1.2.3+" + "g" * 40),
            ("informational_version", "1.2.3+" + SHA + " --x"),
        ):
            with self.subTest(field=field, value=bad):
                proc = self._validate("prepare", {**good, field: bad})
                self.assertNotEqual(0, proc.returncode)
                self.assertIn(f"invalid {field}", proc.stdout)

    def test_beta_inputs_cannot_inject_shell_syntax(self):
        good = resolve("0.15.1-beta.1")
        for field in ("version", "informational_version", "file_version", "msi_product_version"):
            for suffix in (";exit 0", "$(exit 0)", "`exit 0`", "\nexit 0", '"', " -p:Foo=bar"):
                for phase in ("prepare", "package"):
                    with self.subTest(field=field, suffix=suffix, phase=phase):
                        proc = self._validate(phase, {**good, field: good[field] + suffix})
                        self.assertNotEqual(0, proc.returncode)
                        self.assertIn(f"invalid {field}", proc.stdout)

    def test_beta_does_not_relax_msi_file_or_provenance_formats(self):
        good = resolve("0.15.1-beta.1")
        for field, bad in (
            ("msi_product_version", "2.15.101.1"),
            ("msi_product_version", "2.15.beta"),
            ("file_version", "2.15.101"),
            ("file_version", "2.15.101.1"),
            ("informational_version", "0.15.1.1+" + "g" * 40),
            ("informational_version", "0.15.1.1+" + SHA[:-1]),
            ("informational_version", "0.15.1.1+" + SHA + "0"),
            ("informational_version", "0.15.1.1+" + SHA + "+extra"),
        ):
            for phase in ("prepare", "package"):
                with self.subTest(field=field, value=bad, phase=phase):
                    proc = self._validate(phase, {**good, field: bad})
                    self.assertNotEqual(0, proc.returncode)
                    self.assertIn(f"invalid {field}", proc.stdout)


class ReleaseWorkflowUsesSharedBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = load(RELEASE)
        cls.build = cls.workflow["jobs"]["build"]
        cls.steps = cls.build["steps"]

    def test_release_build_job_step_order_is_locked(self):
        self.assertEqual(RELEASE_BUILD_STEPS, [s.get("name") for s in self.steps])
        self.assertEqual("actions/checkout@v7", self.steps[0]["uses"])

    def test_no_release_build_step_is_conditional_or_fail_open(self):
        for step in self.steps:
            with self.subTest(step=step.get("name")):
                self.assertNotIn("if", step)
                self.assertNotIn("continue-on-error", step)

    def test_shared_build_is_called_in_both_phases_with_resolved_versions(self):
        calls = [s for s in self.steps if s.get("uses") == ACTION_REF]
        self.assertEqual(["prepare", "package"], [s["with"]["phase"] for s in calls])
        for call in calls:
            with self.subTest(phase=call["with"]["phase"]):
                self.assertEqual(
                    {
                        "phase": call["with"]["phase"],
                        "version": "${{ steps.ver.outputs.version }}",
                        "file_version": "${{ steps.ver.outputs.file_version }}",
                        "informational_version": "${{ steps.ver.outputs.informational_version }}",
                        "msi_product_version": "${{ steps.ver.outputs.msi_product_version }}",
                    },
                    call["with"],
                )

    def test_retired_allowlist_signature_check_does_not_return(self):
        # PAT-2304: the allowlist, its .sig and the verifier script are
        # deleted, so this step could only ever fail or verify nothing. The
        # two build phases now run back to back.
        names = [s.get("name") for s in self.steps]
        self.assertNotIn("Verify Windows allowlist signature (refuse to ship otherwise)", names)
        prepare = names.index("Build headless Service")
        self.assertEqual("Build and verify MSI", names[prepare + 1])
        text = without_comments(RELEASE.read_text(encoding="utf-8"))
        for retired in ("verify-allowlist-signature.py", "windows-allowlist.json"):
            with self.subTest(retired=retired):
                self.assertNotIn(retired, text)

    def test_signing_steps_still_hold_their_secrets_in_the_release_workflow(self):
        by_name = {s.get("name"): s for s in self.steps}
        self.assertEqual(
            "${{ secrets.ARTIFACT_SIGNING_KEY }}",
            by_name["Sign artifact with HMAC-SHA256"]["env"]["ARTIFACT_SIGNING_KEY"],
        )
        self.assertEqual(
            "${{ secrets.ARTIFACT_METADATA_SIGNING_KEY }}",
            by_name["Sign artifact metadata (Ed25519)"]["env"]["ARTIFACT_METADATA_SIGNING_KEY"],
        )
        for name in ("Build headless Service", "Build and verify MSI"):
            with self.subTest(step=name):
                self.assertNotIn("secrets.", str(by_name[name]))

    def test_moved_steps_are_not_duplicated_in_the_release_workflow(self):
        names = {s.get("name") for s in self.steps}
        for moved in PREPARE_STEPS + PACKAGE_STEPS:
            with self.subTest(step=moved):
                self.assertNotIn(moved, names)


class PullRequestMsiCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = without_comments(PR_CHECK.read_text(encoding="utf-8"))
        cls.workflow = load(PR_CHECK)
        # PyYAML reads the bare key `on` as boolean True.
        cls.triggers = cls.workflow[True]
        cls.jobs = cls.workflow["jobs"]

    def test_runs_on_pull_request_and_main_only(self):
        self.assertEqual({"pull_request", "push"}, set(self.triggers))
        self.assertEqual(["main"], self.triggers["push"]["branches"])
        self.assertNotIn("pull_request_target", self.text)
        self.assertNotIn("workflow_run", self.text)

    def test_path_filters_cover_every_input_to_the_msi(self):
        required = {
            "windows/installer/**",
            "windows/src/**",
            "windows/*.props",
            "windows/*.targets",
            "windows/*.sln",
            "requirements.txt",
            ".github/actions/windows-agent-msi/**",
            ".github/workflows/windows-msi-build.yml",
            ".github/workflows/windows-agent-release.yml",
        }
        for event in ("pull_request", "push"):
            with self.subTest(event=event):
                paths = set(self.triggers[event]["paths"])
                self.assertEqual(set(), required - paths)
        self.assertEqual(
            set(self.triggers["pull_request"]["paths"]), set(self.triggers["push"]["paths"])
        )

    def test_read_only_token_and_no_secrets(self):
        self.assertEqual({"contents": "read"}, self.workflow["permissions"])
        for name, job in self.jobs.items():
            with self.subTest(job=name):
                self.assertNotIn("permissions", job)
                self.assertNotIn("environment", job)
                self.assertNotIn("secrets", job)
        for marker in SECRET_OR_PUBLISH_MARKERS:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, self.text)

    def test_builds_through_the_same_phases_and_wiring_as_the_release(self):
        self.assertEqual({"msi-build"}, set(self.jobs))
        job = self.jobs["msi-build"]
        release_build = load(RELEASE)["jobs"]["build"]
        self.assertEqual(release_build["runs-on"], job["runs-on"])

        steps = job["steps"]
        self.assertEqual("actions/checkout@v7", steps[0]["uses"])
        self.assertIs(False, steps[0]["with"]["persist-credentials"])

        pr_calls = [s["with"] for s in steps if s.get("uses") == ACTION_REF]
        release_calls = [s["with"] for s in release_build["steps"] if s.get("uses") == ACTION_REF]
        self.assertEqual(release_calls, pr_calls)
        self.assertEqual(["prepare", "package"], [c["phase"] for c in pr_calls])
        for step in steps:
            with self.subTest(step=step.get("name")):
                self.assertNotIn("if", step)
                self.assertNotIn("continue-on-error", step)

    def test_build_only_version_resolves_through_the_release_resolver(self):
        job = self.jobs["msi-build"]
        versions = job["strategy"]["matrix"]["version"]
        self.assertEqual(["0.0.0", "0.15.1-beta.1"], versions)
        self.assertIs(False, job["strategy"]["fail-fast"])
        steps = job["steps"]
        step = next(s for s in steps if s.get("id") == "ver")
        self.assertEqual({"BUILD_VERSION": "${{ matrix.version }}"}, step["env"])
        run = step["run"]
        self.assertIn('windows/installer/resolve-release-version.sh "$BUILD_VERSION" "$GITHUB_SHA"', run)
        # The resolver is committed as mode 100644. Git Bash on windows-latest
        # runs it by shebang regardless (the release job has always invoked it
        # the same way); a POSIX runner needs the interpreter named.
        posix_run = run.replace(
            "windows/installer/resolve-release-version.sh", "bash windows/installer/resolve-release-version.sh"
        )
        action_steps = load(ACTION)["runs"]["steps"]
        for version in versions:
            with self.subTest(version=version), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / "github_output"
                output.touch()
                proc = subprocess.run(
                    BASH,
                    input=posix_run,
                    cwd=ROOT,
                    env={
                        **os.environ, "BUILD_VERSION": version,
                        "GITHUB_SHA": SHA, "GITHUB_OUTPUT": str(output),
                    },
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(0, proc.returncode, proc.stderr)
                values = dict(line.split("=", 1) for line in output.read_text().splitlines())
                self.assertEqual(resolve(version), values)
                expected_msi = "2.0.0" if version == "0.0.0" else "2.15.101"
                self.assertEqual(expected_msi, values["msi_product_version"])
                # Both action phases accept each version the PR matrix resolves.
                for phase in ("prepare", "package"):
                    with self.subTest(phase=phase):
                        proc = subprocess.run(
                            BASH,
                            input=action_steps[0]["run"],
                            env={
                                **os.environ,
                                "PHASE": phase,
                                "VERSION": values["version"],
                                "FILE_VERSION": values["file_version"],
                                "INFORMATIONAL_VERSION": values["informational_version"],
                                "MSI_PRODUCT_VERSION": values["msi_product_version"],
                            },
                            capture_output=True,
                            text=True,
                        )
                        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)


class HeadlessPayloadTests(unittest.TestCase):
    """PAT-2352: inspect the installer and execute its actual payload guard.

    The PowerShell fixtures replace only the COM File-table read, unavailable
    outside Windows. The allow/reject logic runs verbatim from the shared action.
    A real built-MSI check and an installed upgrade remain separate requirements.
    """

    def test_msi_ships_only_the_service_executable(self):
        wix = ET.parse(ROOT / "windows/installer/Product.wxs").getroot()
        ns = {"w": "http://wixtoolset.org/schemas/v4/wxs"}
        files = [f.get("Name", "") for f in wix.findall(".//w:File", ns)]
        self.assertEqual(["Patched.Service.exe"], files)

    def test_msi_does_not_create_a_user_run_entry(self):
        wix = ET.parse(ROOT / "windows/installer/Product.wxs").getroot()
        ns = {"w": "http://wixtoolset.org/schemas/v4/wxs"}
        run_values = [
            value.attrib
            for value in wix.findall(".//w:RegistryValue", ns)
            if value.get("Key", "").lower().endswith("\\currentversion\\run")
        ]
        self.assertEqual([], run_values, "the headless MSI must not add logon UI")

    def test_shared_release_build_publishes_only_service(self):
        runs = "\n".join(s.get("run", "") for s in load(ACTION)["runs"]["steps"])
        projects = re.findall(r"dotnet\s+publish\s+(\S+\.csproj)", runs)
        self.assertEqual(["windows/src/Service/Service.csproj"], projects)

    def _run_payload_guard(self, file_names):
        if not shutil.which("pwsh"):
            self.skipTest("PowerShell is required to execute the release payload guard")
        guards = [
            step["run"] for step in load(ACTION)["runs"]["steps"]
            if "SELECT `FileName` FROM `File`" in step.get("run", "")
        ]
        self.assertEqual(1, len(guards), "expected the shared MSI File-table guard")
        # Keep the production comparison and failure behaviour intact. Do not
        # reimplement the guard in Python: that could pass while CI accepts a tray.
        guard = guards[0]
        start = guard.index("$expected =")
        fixture = json.dumps(file_names)
        script = "$ErrorActionPreference = 'Stop'\n"
        script += f"$fileNames = @('{fixture}' | ConvertFrom-Json)\n"
        script += guard[start:]
        return subprocess.run(
            ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, check=False,
        )

    def test_release_payload_guard_accepts_service_only(self):
        proc = self._run_payload_guard(["Patched.Service.exe"])
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)

    def test_release_payload_guard_rejects_the_retired_tray(self):
        proc = self._run_payload_guard(["Patched.Service.exe", "PatchedTray.exe"])
        self.assertNotEqual(0, proc.returncode, proc.stdout + proc.stderr)

    def test_release_payload_guard_rejects_every_unexpected_file(self):
        for name in ("Patched.Tray.exe", "Patched.SelfService.exe", "windows-allowlist.json",
                     "windows-allowlist.json.sig", "unrecognised.dll"):
            with self.subTest(file=name):
                proc = self._run_payload_guard(["Patched.Service.exe", name])
                self.assertNotEqual(0, proc.returncode, proc.stdout + proc.stderr)

    def test_release_payload_guard_still_requires_service(self):
        proc = self._run_payload_guard([])
        self.assertNotEqual(0, proc.returncode, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
