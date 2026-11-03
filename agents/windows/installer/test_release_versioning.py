#!/usr/bin/env python3
"""Regression tests for the Windows release-version pipeline (PAT-1095)."""

from __future__ import annotations

import os
import hashlib
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


INSTALLER = Path(__file__).resolve().parent
REPO = INSTALLER.parent.parent
RESOLVER = INSTALLER / "resolve-release-version.sh"
SHA256SUMS_WRITER = INSTALLER / "write-sha256sums.ps1"
WORKFLOW = REPO / ".github" / "workflows" / "windows-agent-release.yml"
WINDOWS_BUILD_WORKFLOW = REPO / ".github" / "workflows" / "windows-build.yml"
# PAT-1777: the MSI build steps live in one composite action shared by the
# release workflow and the pull request MSI check.
MSI_BUILD_ACTION = REPO / ".github" / "actions" / "windows-agent-msi" / "action.yml"
MSI_BUILD_ACTION_USE = "uses: ./.github/actions/windows-agent-msi"
RELEASE_TO_ACTION_INPUTS = (
    "version: ${{ steps.ver.outputs.version }}",
    "file_version: ${{ steps.ver.outputs.file_version }}",
    "informational_version: ${{ steps.ver.outputs.informational_version }}",
    "msi_product_version: ${{ steps.ver.outputs.msi_product_version }}",
)
PRODUCT_WXS = INSTALLER / "Product.wxs"
WIXPROJ = INSTALLER / "Patched.wixproj"
TRAY_PROJECT = REPO / "windows" / "src" / "Tray" / "Tray.csproj"
SHA = "0123456789abcdef0123456789abcdef01234567"
WIX = "{http://wixtoolset.org/schemas/v4/wxs}"
BASH = os.environ.get("PATCHED_RELEASE_TEST_BASH", "bash")
PWSH = os.environ.get("PATCHED_RELEASE_TEST_PWSH", "pwsh")


def resolve(version: str, sha: str = SHA) -> dict[str, str]:
    result = subprocess.run(
        [BASH, RESOLVER.as_posix(), version, sha],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        detail = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
        raise RuntimeError(detail or f"resolver exited {result.returncode} without output")
    return dict(line.split("=", 1) for line in result.stdout.splitlines())


def msi_order(version: str) -> tuple[int, int, int]:
    """MSI compares ProductVersion's three numeric fields lexicographically."""
    return tuple(int(field) for field in version.split("."))  # type: ignore[return-value]


def file_order(version: str) -> tuple[int, int, int, int]:
    """Windows Installer compares the executable version resource numerically."""
    return tuple(int(field) for field in version.split("."))  # type: ignore[return-value]


class ReleaseVersionResolverTests(unittest.TestCase):
    def test_maps_release_to_msi_file_and_informational_versions(self) -> None:
        version = resolve("12.34.56")
        self.assertEqual(version["version"], "12.34.56")
        self.assertEqual(version["channel"], "stable")
        self.assertEqual(version["msi_product_version"], "14.34.5600")
        self.assertEqual(version["file_version"], "14.34.5600.0")
        self.assertEqual(version["informational_version"], f"12.34.56+{SHA}")

    def test_beta_identity_is_numeric_and_msi_revisions_are_monotonic(self) -> None:
        first = resolve("12.34.56-beta.1")
        second = resolve("12.34.56-beta.2")
        last = resolve("12.34.56-beta.99")
        next_patch = resolve("12.34.57")
        self.assertEqual(first["version"], "12.34.56.1")
        self.assertEqual(first["channel"], "beta")
        self.assertEqual(first["tag_version"], "12.34.56-beta.1")
        self.assertEqual(first["msi_product_version"], "14.34.5601")
        self.assertLess(msi_order(first["msi_product_version"]), msi_order(second["msi_product_version"]))
        self.assertLess(msi_order(last["msi_product_version"]), msi_order(next_patch["msi_product_version"]))
        self.assertEqual(resolve("12.34.56.2")["version"], second["version"])

    def test_accepts_encoded_msi_boundaries_and_rejects_overflow(self) -> None:
        version = resolve("253.255.654-beta.99")
        self.assertEqual(version["msi_product_version"], "255.255.65499")
        self.assertEqual(version["file_version"], "255.255.65499.0")
        self.assertEqual(resolve("253.255.655")["msi_product_version"], "255.255.65500")
        self.assertLess(msi_order(version["msi_product_version"]), msi_order(resolve("253.255.655")["msi_product_version"]))
        for invalid in ("0.0.656", "0.0.655-beta.1", "0.0.654-beta.100", "0.0.654-beta.0"):
            with self.subTest(version=invalid):
                result = subprocess.run(["bash", str(RESOLVER), invalid, SHA], check=False, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)

    def test_rejects_malformed_prerelease_and_overflow_versions(self) -> None:
        for invalid in (
            "",
            "1.2",
            "1.2.3.4.5",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2.3-rc.1",
            "1.2.3+build.1",
            "254.0.0",
            "255.0.0",
            "0.256.0",
            "0.0.65536",
        ):
            with self.subTest(version=invalid):
                result = subprocess.run(
                    ["bash", str(RESOLVER), invalid, SHA],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)

    def test_rejects_abbreviated_or_non_hex_commit_provenance(self) -> None:
        for invalid in ("abc123", "g" * 40, "a" * 39):
            with self.subTest(sha=invalid):
                result = subprocess.run(
                    ["bash", str(RESOLVER), "1.2.3", invalid],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)

    def test_current_semantic_release_upgrades_legacy_msi_and_replaces_its_binaries(self) -> None:
        legacy_msi = "1.0.0"
        legacy_file_version = "1.0.0.0"
        current = resolve("0.13.2")
        self.assertEqual(current["msi_product_version"], "2.13.200")
        self.assertGreater(msi_order(current["msi_product_version"]), msi_order(legacy_msi))
        self.assertEqual(current["file_version"], "2.13.200.0")
        self.assertGreater(file_order(current["file_version"]), file_order(legacy_file_version))
        self.assertEqual(current["informational_version"], f"0.13.2+{SHA}")

    def test_msi_epoch_mapping_is_monotonic_for_future_semantic_releases(self) -> None:
        semantic_versions = ("0.0.0", "0.13.0", "0.13.1", "0.14.0", "1.0.0", "2.0.0")
        msi_versions = [resolve(version)["msi_product_version"] for version in semantic_versions]
        self.assertEqual(msi_versions[0], "2.0.0")
        self.assertTrue(
            all(
                msi_order(later) > msi_order(earlier)
                for earlier, later in zip(msi_versions, msi_versions[1:])
            )
        )

    def test_epoched_file_versions_are_monotonic_for_future_releases(self) -> None:
        semantic_versions = ("0.13.1", "0.13.2", "0.14.0", "1.0.0")
        file_versions = [resolve(version)["file_version"] for version in semantic_versions]
        self.assertTrue(
            all(
                file_order(later) > file_order(earlier)
                for earlier, later in zip(file_versions, file_versions[1:])
            )
        )


class PackagingWiringTests(unittest.TestCase):
    def test_sha256sums_writer_emits_lf_only_shasum_record(self) -> None:
        """The released manifest must work with macOS `shasum -a 256 -c`."""
        artifact_name = "PatchedAgent-0.2.10.msi"
        artifact_bytes = b"PAT-1225 checksum fixture\x00"
        digest = hashlib.sha256(artifact_bytes).hexdigest()

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "SHA256SUMS"
            (Path(directory) / artifact_name).write_bytes(artifact_bytes)
            result = subprocess.run(
                [
                    PWSH,
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    str(SHA256SUMS_WRITER),
                    "-Sha256",
                    digest.upper(),
                    "-Artifact",
                    artifact_name,
                    "-OutputPath",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            manifest = output.read_bytes()
            expected = f"{digest}  {artifact_name}\n".encode("utf-8")
            self.assertEqual(manifest, expected)
            self.assertNotIn(b"\r", manifest)
            self.assertFalse(manifest.startswith(b"\xef\xbb\xbf"))

            # This is the POSIX shasum record form: lowercase SHA-256, two
            # spaces, filename, LF. Validate its digest semantics separately
            # so a newline-safe but malformed manifest cannot pass.
            checksum, separator, filename = manifest.decode("utf-8").rstrip("\n").partition("  ")
            self.assertEqual(separator, "  ")
            self.assertEqual(filename, artifact_name)
            self.assertEqual(checksum, hashlib.sha256((Path(directory) / filename).read_bytes()).hexdigest())

            # Exercise the documented macOS command when it is available.
            # GitHub's Windows image does not promise shasum, so the byte and
            # grammar assertions above remain the cross-platform regression.
            if os.name != "nt" and (shasum := shutil.which("shasum")):
                verified = subprocess.run(
                    [shasum, "-a", "256", "-c", output.name],
                    cwd=directory,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_wix_consumes_build_product_version_and_preserves_upgrade_identity(self) -> None:
        product = PRODUCT_WXS.read_text(encoding="utf-8")
        self.assertNotIn('<?define ProductVersion = "1.0.0" ?>', product)
        root = ET.fromstring(product)
        package = root.find(f"{WIX}Package")
        self.assertIsNotNone(package)
        self.assertEqual(package.get("Version"), "$(var.ProductVersion)")
        self.assertEqual(package.get("UpgradeCode"), "$(UpgradeCode)")
        self.assertIn(
            '<?define UpgradeCode    = "{A1B2C3D4-E5F6-7890-ABCD-000000000311}" ?>',
            product,
        )

        major_upgrade = package.find(f"{WIX}MajorUpgrade")
        self.assertIsNotNone(major_upgrade)
        self.assertEqual(major_upgrade.get("Schedule"), "afterInstallInitialize")

    def test_wix_project_exports_product_version_as_preprocessor_constant(self) -> None:
        project = ET.fromstring(WIXPROJ.read_text(encoding="utf-8"))
        constants = [element.text or "" for element in project.findall(".//DefineConstants")]
        self.assertTrue(any("ProductVersion=$(ProductVersion)" in value for value in constants))

    def test_release_workflow_passes_one_mapping_to_every_packaged_output(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        action = MSI_BUILD_ACTION.read_text(encoding="utf-8")
        self.assertIn("RELEASE_INPUT_VERSION: ${{ github.event.inputs.version }}", workflow)
        self.assertIn('case "${{ github.event_name }}" in', workflow)
        self.assertIn("workflow_dispatch)", workflow)
        self.assertIn('V="$RELEASE_INPUT_VERSION"', workflow)
        self.assertIn("push)", workflow)
        self.assertIn('V="${GITHUB_REF_NAME#windows-agent-v}"', workflow)
        self.assertIn("unsupported release event: ${{ github.event_name }}", workflow)
        self.assertIn('resolve-release-version.sh "$V" "$GITHUB_SHA"', workflow)
        self.assertIn("./windows/installer/write-sha256sums.ps1 -Sha256 $hash -Artifact $dest", workflow)
        self.assertNotIn("Out-File SHA256SUMS", workflow)

        # Both phases of the shared build receive every resolved value, unchanged.
        for phase in ("prepare", "package"):
            with self.subTest(phase=phase):
                marker = f"phase: {phase}"
                self.assertEqual(workflow.count(marker), 1)
                call = workflow.split(marker, 1)[1].split("\n      - ", 1)[0]
                self.assertIn(MSI_BUILD_ACTION_USE, workflow.split(marker, 1)[0].rsplit("- name:", 1)[1])
                for wiring in RELEASE_TO_ACTION_INPUTS:
                    self.assertIn(wiring, call)

        self.assertIn("-p:ProductVersion=${{ inputs.msi_product_version }}", action)
        self.assertNotIn("dotnet publish", workflow)
        self.assertNotIn("dotnet build", workflow)

        for project in (
            "windows/src/Service/Service.csproj",
        ):
            with self.subTest(project=project):
                publish_line = next(
                    line for line in action.splitlines()
                    if line.strip().startswith("run: dotnet publish") and project in line
                )
                self.assertIn("-r win-x64", publish_line)
                self.assertIn("--self-contained true", publish_line)
                self.assertIn("-p:PublishSingleFile=true", publish_line)
                self.assertIn("-p:Version=${{ inputs.version }}", publish_line)
                self.assertIn("-p:AssemblyVersion=${{ inputs.file_version }}", publish_line)
                self.assertIn("-p:FileVersion=${{ inputs.file_version }}", publish_line)
                self.assertIn(
                    "-p:InformationalVersion=${{ inputs.informational_version }}",
                    publish_line,
                )
                self.assertIn(
                    "-p:IncludeSourceRevisionInInformationalVersion=false",
                    publish_line,
                )

    def test_wix_excludes_self_service_from_the_assurance_installer(self) -> None:
        product = PRODUCT_WXS.read_text(encoding="utf-8")
        root = ET.fromstring(product)
        feature = root.find(f"{WIX}Package/{WIX}Feature")
        self.assertIsNotNone(feature)
        feature_groups = {
            ref.get("Id") for ref in feature.findall(f"{WIX}ComponentGroupRef")
        }
        self.assertNotIn("SelfServiceBinary", feature_groups)

        self.assertIsNone(root.find(f".//{WIX}ComponentGroup[@Id='SelfServiceBinary']"))
        self.assertNotIn("SelfServicePublishDir", product)
        for path in (WORKFLOW, MSI_BUILD_ACTION):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("Publish Self Service", text)
                self.assertNotIn("windows/src/SelfService/SelfService.csproj", text)

    def test_wpf_single_file_outputs_bundle_native_runtime_libraries(self) -> None:
        for project_path in (TRAY_PROJECT,):
            with self.subTest(project=project_path.relative_to(REPO).as_posix()):
                project = ET.fromstring(project_path.read_text(encoding="utf-8"))
                values = [
                    element.text
                    for element in project.findall(".//IncludeNativeLibrariesForSelfExtract")
                ]
                self.assertEqual(values, ["true"])

    def test_release_workflow_fails_closed_when_msi_file_table_lacks_an_executable(self) -> None:
        # PAT-1777: the assertion lives in the shared action; the release
        # workflow must still run that action's package phase.
        self.assertIn(MSI_BUILD_ACTION_USE, WORKFLOW.read_text(encoding="utf-8"))
        workflow = MSI_BUILD_ACTION.read_text(encoding="utf-8")
        self.assertIn("- name: Assert headless assurance MSI payload", workflow)
        self.assertIn("New-Object -ComObject WindowsInstaller.Installer", workflow)
        self.assertIn("OpenView('SELECT `FileName` FROM `File`')", workflow)
        self.assertIn("$record.StringData(1).Split('|')[-1]", workflow)
        self.assertIn("MSI File table is missing required endpoint executable(s)", workflow)
        self.assertIn('$expected = @("Patched.Service.exe")', workflow)
        self.assertIn('$fileNames | Where-Object { $_ -notin $expected }', workflow)
        self.assertIn("Assurance MSI File table contains unexpected payload(s)", workflow)

    def test_windows_build_runs_the_release_version_pipeline_on_workflow_changes(self) -> None:
        workflow = WINDOWS_BUILD_WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(workflow.count("- '.github/workflows/windows-build.yml'"), 2)
        self.assertEqual(workflow.count("- '.github/workflows/windows-agent-release.yml'"), 2)
        self.assertEqual(workflow.count("- '.github/actions/windows-agent-msi/**'"), 2)
        self.assertIn("uses: actions/setup-python@v7", workflow)
        self.assertIn("python-version: '3.12'", workflow)

        step = workflow.split("- name: Test Windows release version pipeline", 1)[1]
        step = step.split("\n      - name:", 1)[0]
        self.assertIn("shell: bash", step)
        self.assertIn("PATCHED_RELEASE_TEST_BASH: 'C:\\Program Files\\Git\\bin\\bash.exe'", step)
        self.assertIn("run: python windows/installer/test_release_versioning.py", step)

    def test_manual_build_example_uses_epoched_product_and_binary_versions(self) -> None:
        readme = (INSTALLER / "README-install.md").read_text(encoding="utf-8")
        self.assertIn("-p:ProductVersion=2.3.1", readme)
        self.assertIn("-p:AssemblyVersion=2.3.1.0", readme)
        self.assertIn("-p:FileVersion=2.3.1.0", readme)
        self.assertEqual(
            readme.count("-p:IncludeSourceRevisionInInformationalVersion=false"),
            1,
        )
        self.assertIn("Do not pass raw semantic `X.Y.Z` to `-p:ProductVersion`", readme)


if __name__ == "__main__":
    unittest.main()
