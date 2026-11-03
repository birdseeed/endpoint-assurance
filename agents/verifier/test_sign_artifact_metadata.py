#!/usr/bin/env python3
"""
test_sign_artifact_metadata.py — unit tests for sign-artifact-metadata.py
(PAT-1248).

Stdlib + cryptography only. Covers:
  - A well-formed metadata document signs successfully and round-trips: the
    resulting envelope verifies with the matching public key, and the exact
    input bytes are recovered from signed_payload.
  - The script rejects the agent-config key id (PAT-516 key separation).
  - The script rejects the catalogue key id (PAT-516 key separation,
    extended to the third key purpose).
  - Missing required fields (version/platform/channel/artifact_url/
    artifact_sha256) are rejected fail-closed.
  - A non-https artifact_url is rejected.
  - A malformed (non-64-hex) artifact_sha256 is rejected.
  - Invalid JSON input is rejected.
"""

import base64
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "verifier" / "sign-artifact-metadata.py"

_spec = importlib.util.spec_from_file_location("sign_artifact_metadata", SCRIPT)
sign_artifact_metadata = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sign_artifact_metadata)  # type: ignore[union-attr]

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature  # noqa: E402

AGENT_CONFIG_KEY_ID = "ecd47f2c5b3d5705"
CATALOGUE_KEY_ID = "734eba29d9f804a0"
ARTIFACT_KEY_ID = "aa11bb22cc33dd44"  # distinct dev/test key id, not a real production value


def _run(args, cwd=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, cwd=cwd,
    )


def _valid_metadata(**overrides):
    doc = {
        "version": "0.13.16",
        "platform": "windows",
        "channel": "stable",
        "artifact_url": "https://api.patched.im/v1/agent/artifact-download/0.13.16",
        "artifact_sha256": "a" * 64,
    }
    doc.update(overrides)
    return doc


class SignArtifactMetadataTests(unittest.TestCase):
    def setUp(self):
        self.private_key = Ed25519PrivateKey.generate()
        seed = self.private_key.private_bytes_raw()
        self.seed_b64 = base64.b64encode(seed).decode()
        self.public_key = self.private_key.public_key()

    def _sign(self, tmp_path, metadata, key_id=ARTIFACT_KEY_ID, key_b64=None):
        input_path = tmp_path / "artifact-metadata.json"
        output_path = tmp_path / "artifact-metadata.signed.json"
        input_path.write_text(json.dumps(metadata))
        result = _run([
            "--input", str(input_path),
            "--output", str(output_path),
            "--key", key_b64 or self.seed_b64,
            "--key-id", key_id,
        ])
        return result, input_path, output_path

    def test_valid_metadata_signs_and_round_trips(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            metadata = _valid_metadata()
            result, input_path, output_path = self._sign(tmp_path, metadata)

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            envelope = json.loads(output_path.read_text())
            self.assertEqual(set(envelope.keys()), {"signed_payload", "signature", "key_id"})
            self.assertEqual(envelope["key_id"], ARTIFACT_KEY_ID)

            signed_payload = base64.b64decode(envelope["signed_payload"])
            signature = base64.b64decode(envelope["signature"])

            # Exact input bytes are recovered — the script signs byte-for-byte
            # what it read, never a re-serialized copy.
            self.assertEqual(signed_payload, input_path.read_bytes())
            self.assertEqual(json.loads(signed_payload), metadata)

            # The signature verifies against the matching public key and
            # rejects a tampered payload or the wrong key — this is the same
            # verification shape ArtifactTrust.Verify() performs in C#.
            self.public_key.verify(signature, signed_payload)
            with self.assertRaises(InvalidSignature):
                self.public_key.verify(signature, signed_payload + b"tamper")
            other_key = Ed25519PrivateKey.generate().public_key()
            with self.assertRaises(InvalidSignature):
                other_key.verify(signature, signed_payload)

    def test_rejects_agent_config_key_id(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            result, _, output_path = self._sign(
                Path(td), _valid_metadata(), key_id=AGENT_CONFIG_KEY_ID)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("agent-config", result.stderr.lower())
            self.assertFalse(output_path.exists())

    def test_rejects_catalogue_key_id(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            result, _, output_path = self._sign(
                Path(td), _valid_metadata(), key_id=CATALOGUE_KEY_ID)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("catalogue", result.stderr.lower())
            self.assertFalse(output_path.exists())

    def test_rejects_missing_required_fields(self):
        import tempfile
        for field in ("version", "platform", "channel", "artifact_url", "artifact_sha256"):
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory() as td:
                    metadata = _valid_metadata()
                    del metadata[field]
                    result, _, output_path = self._sign(Path(td), metadata)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(field, result.stderr)
                    self.assertFalse(output_path.exists())

    def test_rejects_empty_required_field(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            result, _, output_path = self._sign(Path(td), _valid_metadata(channel=""))
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output_path.exists())

    def test_rejects_non_https_artifact_url(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            result, _, output_path = self._sign(
                Path(td), _valid_metadata(artifact_url="http://api.patched.im/x.msi"))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("https://", result.stderr)
            self.assertFalse(output_path.exists())

    def test_rejects_malformed_sha256(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            for bad in ("not-hex" * 8, "a" * 63, "a" * 65, ""):
                with self.subTest(bad=bad):
                    result, _, output_path = self._sign(
                        Path(td), _valid_metadata(artifact_sha256=bad))
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output_path.exists())

    def test_rejects_invalid_json_input(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            input_path = tmp_path / "bad.json"
            output_path = tmp_path / "out.json"
            input_path.write_text("{not-json")
            result = _run([
                "--input", str(input_path),
                "--output", str(output_path),
                "--key", self.seed_b64,
                "--key-id", ARTIFACT_KEY_ID,
            ])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not valid JSON", result.stderr)
            self.assertFalse(output_path.exists())

    def test_requires_key_or_kms_resource(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            input_path = tmp_path / "artifact-metadata.json"
            output_path = tmp_path / "out.json"
            input_path.write_text(json.dumps(_valid_metadata()))
            result = _run([
                "--input", str(input_path),
                "--output", str(output_path),
                "--key-id", ARTIFACT_KEY_ID,
            ])
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
