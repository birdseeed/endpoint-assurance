#!/usr/bin/env python3
"""
test_windows_artifact_metadata_signing_workflow.py — static regressions for
PAT-1248's Ed25519 artifact-metadata signing in windows-agent-release.yml.

BootstrapUpdater.cs (Windows self-update) now verifies a signed
artifact-metadata envelope with the pinned ArtifactTrust public key instead
of recomputing the old, never-provisioned ARTIFACT_SIGNING_KEY HMAC. This
test never runs the workflow (no GitHub Actions, no network); it asserts the
checked-in YAML shape so a future edit cannot regress to publishing a release
that BootstrapUpdater can never verify, or to silently skipping the signing
step's hard-fail gate.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/windows-agent-release.yml"
SCRIPT = ROOT / "verifier" / "sign-artifact-metadata.py"
ARTIFACT_TRUST = ROOT / "windows/src/Shared/Verification/ArtifactTrust.cs"
PLACEHOLDER_MARKER = "UNPROVISIONED-PAT-1248-ARTIFACT-KEY-REPLACE-BEFORE-SHIP"


class WindowsArtifactMetadataSigningWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text()
        cls.workflow = yaml.safe_load(cls.text)
        cls.build_steps = {s.get("name"): s for s in cls.workflow["jobs"]["build"]["steps"] if s.get("name")}
        cls.publish_steps = {s.get("name"): s for s in cls.workflow["jobs"]["publish"]["steps"] if s.get("name")}

    def test_sign_artifact_metadata_script_exists(self):
        self.assertTrue(SCRIPT.exists(), "verifier/sign-artifact-metadata.py must exist")

    def test_sign_step_uses_dedicated_secret_and_script(self):
        step = self.build_steps["Sign artifact metadata (Ed25519)"]
        run = step["run"]
        env = step.get("env", {})
        self.assertIn("ARTIFACT_METADATA_SIGNING_KEY", env)
        # Must not reuse the old symmetric HMAC secret for the new asymmetric
        # path (env dict membership is exact-key, so this only trips if the
        # literal old secret name is reintroduced here).
        self.assertNotIn("ARTIFACT_SIGNING_KEY", env)
        self.assertIn("verifier/sign-artifact-metadata.py", run)
        self.assertIn("--key-id", run)

    def test_metadata_document_carries_minimum_required_fields(self):
        run = self.build_steps["Sign artifact metadata (Ed25519)"]["run"]
        for field in ("version", "platform", "channel", "artifact_url", "artifact_sha256"):
            self.assertIn(f"'{field}'", run, f"artifact metadata build is missing field '{field}'")
        self.assertIn("'windows'", run)

    def test_sign_step_has_no_unindented_multiline_python_block(self):
        # PAT-1248 footgun (same class as the pre-existing NOTES= comment in
        # the publish job): an unindented multi-line python heredoc inside a
        # `run: |` block scalar silently truncates the YAML block. Every
        # `python3 -c "..."` invocation in this workflow must stay on one
        # physical line.
        for name in ("Sign artifact metadata (Ed25519)",):
            run = self.build_steps[name]["run"]
            for match in re.finditer(r'python3 -c "', run):
                start = match.end()
                end = run.index('"', start)
                snippet = run[start:end]
                self.assertNotIn("\n", snippet, f"{name}: python3 -c body must be a single line")

    def test_assert_signed_gate_hard_fails_on_canonical_repo(self):
        step = self.build_steps["Assert artifact metadata was signed when expected"]
        run = step["run"]
        env = step.get("env", {})
        self.assertEqual(env.get("SIGNING_EXPECTED"), "${{ github.repository == 'Patched-LTD/updater' }}")
        self.assertIn("METADATA_SIGNED", env)
        self.assertIn("exit 1", run)
        self.assertIn('if [ "$SIGNING_EXPECTED" = "true" ] && [ "$METADATA_SIGNED" != "true" ]; then', run)

    def test_assert_signed_gate_runs_after_sign_step(self):
        names = [s.get("name") for s in self.workflow["jobs"]["build"]["steps"]]
        self.assertLess(
            names.index("Sign artifact metadata (Ed25519)"),
            names.index("Assert artifact metadata was signed when expected"),
            "the assert-signed gate must run after the sign step",
        )

    def test_metadata_envelope_uploaded_and_downstream_referenced(self):
        upload = self.build_steps["Upload release artifact"]
        self.assertIn("steps.sign_metadata.outputs.metadata_file", upload["with"]["path"])
        self.assertEqual(upload["with"].get("if-no-files-found"), "warn")

        publish_run = self.publish_steps["Publish release"]["run"]
        self.assertIn("needs.build.outputs.artifact_metadata_file", publish_run)

        register_run = self.publish_steps["Register artifact with dashboard"]["run"]
        self.assertIn("needs.build.outputs.artifact_metadata_file", register_run)
        self.assertIn("artifact_metadata_signature", register_run)

    def test_build_job_exposes_metadata_outputs(self):
        outputs = self.workflow["jobs"]["build"]["outputs"]
        self.assertIn("artifact_metadata_signed", outputs)
        self.assertIn("artifact_metadata_file", outputs)

    # -------------------------------------------------------------------------
    # PAT-1248 review correction: ArtifactTrustTests.Production_KeyMaterialIsProvisioned
    # used to be a unit test that was *expected* to fail until Andy provisions the
    # real key - unfixable-by-design red is worse than the gap it guarded (a PR
    # cannot open on red, and a permanently-red suite trains everyone to ignore
    # red). The enforcement point moved here: the release workflow hard-fails on
    # the canonical repo if ArtifactTrust.cs still carries the placeholder.
    # -------------------------------------------------------------------------

    def test_artifact_trust_file_exists(self):
        self.assertTrue(ARTIFACT_TRUST.exists(), "windows/src/Shared/Verification/ArtifactTrust.cs must exist")

    def test_placeholder_marker_in_workflow_matches_the_literal_in_artifact_trust_cs(self):
        # The whole point of "trivially greppable" is that these two strings can
        # never silently drift apart. If ArtifactTrust.cs's sentinel is ever
        # renamed without updating the workflow's grep target (or vice versa),
        # this fails loudly instead of the gate silently stopping matching.
        trust_source = ARTIFACT_TRUST.read_text()
        self.assertIn(
            PLACEHOLDER_MARKER, trust_source,
            "ArtifactTrust.cs no longer contains the exact placeholder marker "
            "this test (and the release workflow's grep) expect - update both "
            "together, never just one.",
        )
        gate_run = self.build_steps["Assert self-update artifact trust key is provisioned"]["run"]
        self.assertIn(PLACEHOLDER_MARKER, gate_run)

    def test_trust_key_gate_hard_fails_on_canonical_repo(self):
        step = self.build_steps["Assert self-update artifact trust key is provisioned"]
        run = step["run"]
        env = step.get("env", {})
        self.assertEqual(env.get("SIGNING_EXPECTED"), "${{ github.repository == 'Patched-LTD/updater' }}")
        self.assertIn("grep", run)
        self.assertIn("exit 1", run)
        self.assertIn('if [ "$SIGNING_EXPECTED" = "true" ] && [ "$IS_PLACEHOLDER" = "true" ]; then', run)

    def test_trust_key_gate_runs_before_the_expensive_publish_steps(self):
        # Fail fast: this should not burn build minutes publishing Service before discovering the release can never be trusted.
        # PAT-1777: Setup .NET and the Service publish step now run inside
        # the shared windows-agent-msi action's prepare phase.
        names = [s.get("name") for s in self.workflow["jobs"]["build"]["steps"]]
        self.assertEqual(
            "./.github/actions/windows-agent-msi",
            self.build_steps["Build headless Service"]["uses"],
        )
        self.assertEqual("prepare", self.build_steps["Build headless Service"]["with"]["phase"])
        self.assertLess(
            names.index("Assert self-update artifact trust key is provisioned"),
            names.index("Build headless Service"),
            "the artifact-trust-key gate should run before the expensive publish steps",
        )

    def test_trust_key_gate_has_no_unindented_multiline_python_block(self):
        run = self.build_steps["Assert self-update artifact trust key is provisioned"]["run"]
        self.assertNotIn("python3 -c", run)  # pure bash/grep - no python footgun to check, but confirm it stays that way


if __name__ == "__main__":
    unittest.main()


class TestArtifactTrustGateMatchesAssignments(unittest.TestCase):
    """PAT-1257: the gate must key off the ASSIGNMENT, not the bare marker.

    The original gate grepped ArtifactTrust.cs for the placeholder marker
    anywhere in the file. That was wrong: the marker legitimately stays in the
    file forever as the UnprovisionedPlaceholderKeyId declaration that
    IsProvisioned and the unit tests compare against. So the gate fired on the
    first genuinely-provisioned release (0.13.16) and would have blocked every
    release after it. It failed closed, which is the right direction, but it
    was still a false positive.
    """

    def setUp(self):
        self.workflow = WORKFLOW.read_text()
        self.trust = ARTIFACT_TRUST.read_text()

    def test_gate_matches_assignment_not_bare_marker(self):
        # The assignment-shaped patterns are what the gate looks for. Spaces
        # around '=' are stripped before matching, so the patterns are written
        # unspaced.
        self.assertIn("ProductionKeyId=UnprovisionedPlaceholderKeyId", self.workflow)
        self.assertIn(
            "ProductionPublicKeyBase64=UnprovisionedPlaceholderPublicKeyBase64",
            self.workflow,
        )

    def test_gate_also_matches_literal_placeholder_values(self):
        # Assignment by literal value, not just by constant name — someone could
        # inline the placeholder rather than reference it (review finding).
        self.assertIn(r'ProductionKeyId=\"$PLACEHOLDER_KEY_ID\"', self.workflow)
        self.assertIn(r'ProductionPublicKeyBase64=\"$PLACEHOLDER_PUBKEY\"', self.workflow)
        self.assertIn(PLACEHOLDER_MARKER, self.workflow)

    def test_gate_normalises_whitespace_before_matching(self):
        # Without this the gate only catches the spaced form and a reformat
        # defeats it silently.
        self.assertIn("tr -s '[:space:]' ' '", self.workflow)
        self.assertIn("sed 's/ *= */=/g'", self.workflow)

    def test_placeholder_declarations_still_exist_in_source(self):
        # If these ever go away the gate silently stops being able to match
        # anything, so the guard would pass vacuously on an unprovisioned build.
        self.assertIn("UnprovisionedPlaceholderKeyId =", self.trust)
        self.assertIn("UnprovisionedPlaceholderPublicKeyBase64 =", self.trust)

    def test_current_source_is_provisioned(self):
        # The committed state must be provisioned: neither Production constant
        # may be assigned a placeholder, by name or by literal value.
        flat = " ".join(self.trust.split())
        for pattern in (
            "ProductionKeyId = UnprovisionedPlaceholderKeyId",
            "ProductionPublicKeyBase64 = UnprovisionedPlaceholderPublicKeyBase64",
        ):
            self.assertNotIn(pattern, flat, f"ArtifactTrust.cs is unprovisioned: {pattern}")


class TestArtifactTrustGateExecutes(unittest.TestCase):
    """PAT-1257: actually RUN the gate, do not just grep the workflow for it.

    A test that asserts the workflow contains the right strings proves the
    author wrote something that looks right. It does not prove the shell does
    what it claims. This gate is the only thing standing between an
    unprovisioned build and the estate, so it gets executed against fixtures
    covering every way the constants can be left unprovisioned.
    """

    @staticmethod
    def _gate_script():
        """Extract the gate's `run:` body from the workflow, dedented."""
        text = WORKFLOW.read_text()
        start = text.index("          # PAT-1257: assert the PRODUCTION constants")
        end = text.index("\n      - name:", start)
        body = text[start:end]
        return "\n".join(
            line[10:] if line.startswith(" " * 10) else line for line in body.split("\n")
        )

    def _run_gate(self, trust_source: str) -> int:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "windows/src/Shared/Verification"
            target.mkdir(parents=True)
            (target / "ArtifactTrust.cs").write_text(trust_source)
            script = root / "gate.sh"
            script.write_text(self._gate_script())
            proc = subprocess.run(
                ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", str(script)],
                cwd=root,
                env={**os.environ, "SIGNING_EXPECTED": "true"},
                capture_output=True,
                text=True,
            )
            return proc.returncode

    def test_real_provisioned_source_passes(self):
        # The committed file itself must pass, or every release is blocked.
        self.assertEqual(0, self._run_gate(ARTIFACT_TRUST.read_text()))

    def test_placeholder_by_constant_name_is_rejected(self):
        src = (
            'const string ProductionKeyId = UnprovisionedPlaceholderKeyId;\n'
            'const string ProductionPublicKeyBase64 = UnprovisionedPlaceholderPublicKeyBase64;\n'
        )
        self.assertEqual(1, self._run_gate(src))

    def test_placeholder_without_spaces_is_rejected(self):
        # The gap a review round caught: a reformat that removes spaces around
        # '=' must not defeat the gate.
        src = 'const string ProductionKeyId=UnprovisionedPlaceholderKeyId;\n'
        self.assertEqual(1, self._run_gate(src))

    def test_placeholder_by_literal_value_is_rejected(self):
        # Inlining the placeholder rather than referencing the constant.
        src = f'const string ProductionKeyId = "{PLACEHOLDER_MARKER}";\n'
        self.assertEqual(1, self._run_gate(src))

    def test_placeholder_split_across_lines_is_rejected(self):
        # The public key constant is already wrapped in the real file.
        src = (
            'const string ProductionPublicKeyBase64 =\n'
            '    UnprovisionedPlaceholderPublicKeyBase64;\n'
        )
        self.assertEqual(1, self._run_gate(src))

    def test_marker_present_only_as_a_declaration_does_not_trip_the_gate(self):
        # The exact false positive that broke the 0.13.16 release: the marker
        # legitimately lives in the file forever as its own declaration.
        src = (
            f'internal const string UnprovisionedPlaceholderKeyId = "{PLACEHOLDER_MARKER}";\n'
            'public const string ProductionKeyId = "1c6ffd04c60dd94d";\n'
            'public const string ProductionPublicKeyBase64 =\n'
            '    "yYFmWA8rvRsalWAMP2B/JnIEQ5FX1cql+MK7LS+SOd0=";\n'
        )
        self.assertEqual(0, self._run_gate(src))
