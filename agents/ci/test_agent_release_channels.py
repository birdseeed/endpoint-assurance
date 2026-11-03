#!/usr/bin/env python3
"""Static contract tests for PAT-2003 beta publication and stable promotion."""

import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
MAC = (REPO / ".github/workflows/macos-agent-release.yml").read_text()
WIN = (REPO / ".github/workflows/windows-agent-release.yml").read_text()
PROMOTE = (REPO / ".github/workflows/agent-release-promote.yml").read_text()


class AgentReleaseChannelTests(unittest.TestCase):
    def test_both_build_workflows_publish_beta_only_and_keep_tag_identity(self):
        for name, text in (("macOS", MAC), ("Windows", WIN)):
            with self.subTest(platform=name):
                self.assertIn("-beta.*", text)
                self.assertIn("channel=beta", text)
                self.assertIn("--prerelease", text)
                self.assertIn("**Channel:** beta", text)
                self.assertIn("**Installable version:**", text)
                self.assertIn("tag_version", text)
                self.assertIn("expected X.Y.Z-beta.N", text)
                self.assertNotIn("channel=stable&version=${V}", text)

    def test_windows_beta_artifact_is_uploaded_before_beta_registration(self):
        self.assertLess(WIN.index("name: Upload MSI to the API"), WIN.index("name: Register artifact with dashboard"))
        self.assertIn("/agent-versions/windows/beta/__VERSION__/artifact", WIN)
        self.assertIn("'channel': 'beta'", WIN)
        self.assertIn("'channel': 'beta'", WIN)

    def test_windows_manual_dispatch_rejects_non_beta_identity_before_resolution(self):
        beta_guard = 'if ! [[ "$V" =~ ^(0|[1-9][0-9]*)\\.'
        self.assertIn(beta_guard, WIN)
        self.assertLess(WIN.index(beta_guard), WIN.index('windows/installer/resolve-release-version.sh "$V"'))

    def test_manual_promoter_reuses_exact_asset_and_fails_closed(self):
        for contract in (
            "workflow_dispatch:",
            "expected_sha256",
            "gh release download",
            "tools/verify-agent-release.py",
            "sign-artifact-metadata.py",
            "--key-env ARTIFACT_METADATA_SIGNING_KEY",
            "admin/agent-releases/promote",
            "HTTP $CODE",
            "same bytes",
            "stable",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, PROMOTE)
        self.assertNotIn("windows-agent-msi", PROMOTE)
        self.assertNotIn("build-bundle.sh", PROMOTE)
        self.assertIn("/admin/agent-versions/__PLATFORM__/stable/__VERSION__/artifact", PROMOTE)
        self.assertIn("PAT-2004 promotion refused", PROMOTE)
        self.assertIn("253.255.654.99", PROMOTE)
        self.assertIn("--draft", PROMOTE)
        self.assertIn("isDraft", PROMOTE)
        self.assertIn("existing stable release is public", PROMOTE)
        self.assertIn("sha256sum -c SHA256SUMS", PROMOTE)
        self.assertIn("cmp -s", PROMOTE)
        self.assertLess(PROMOTE.index("name: Stage same bytes in a draft stable release"), PROMOTE.index("name: Call PAT-2004 promotion gate"))
        self.assertLess(PROMOTE.index("name: Call PAT-2004 promotion gate"), PROMOTE.index("name: Publish the gated stable release"))
        self.assertLess(PROMOTE.index('REVISION="${BASH_REMATCH[4]}"'), PROMOTE.index('[[ "$EXPECTED_SHA256" =~'))

    def test_macos_uses_authenticated_artifact_store_for_beta_and_stable_delivery(self):
        bootstrap = (REPO / "macos/patched-bootstrap.sh").read_text()
        self.assertIn("/admin/agent-versions/macos/beta/__VERSION__/artifact", MAC)
        self.assertIn("platform=macos&channel=beta&version=${V}", MAC)
        self.assertIn("platform=${PLATFORM}&channel=stable&version=${VERSION}", PROMOTE)
        self.assertIn('"agent_artifact_download"', bootstrap)
        self.assertIn("is_expected_artifact_download_url", bootstrap)
        self.assertIn('q == {"platform": ["macos"], "channel": [channel], "version": [version]}', bootstrap)
        self.assertIn('bootstrap_curl_bearer "$BEARER_TOKEN" -sf', bootstrap)

    def test_metadata_signer_reads_seed_from_environment_not_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "metadata.json"
            output = root / "signed.json"
            source.write_text(json.dumps({
                "version": "1.2.3.4",
                "platform": "windows",
                "channel": "stable",
                "artifact_url": "https://example.invalid/artifact",
                "artifact_sha256": "a" * 64,
            }))
            seed = base64.b64encode(b"\x01" * 32).decode()
            env = dict(os.environ, TEST_ARTIFACT_KEY=seed)
            result = subprocess.run([
                sys.executable,
                str(REPO / "verifier/sign-artifact-metadata.py"),
                "--input", str(source), "--key-env", "TEST_ARTIFACT_KEY",
                "--key-id", "0123456789abcdef", "--output", str(output),
            ], env=env, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            envelope = json.loads(output.read_text())
            self.assertEqual(envelope["key_id"], "0123456789abcdef")
            self.assertIn("signed_payload", envelope)


if __name__ == "__main__":
    unittest.main()
