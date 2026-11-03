#!/usr/bin/env python3
"""Pure policy, real Ed25519, durable restart and real bash request-builder tests."""
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


policy = load("policy", ROOT / "endpoint/agent_update_channel.py")
signer = load("config_test_signer", ROOT / "endpoint/test-verify-agent-config.py")
policy._VERIFY._PINNED_KEY_ID = signer._TEST_KEY_ID
policy._VERIFY._PINNED_PUBKEY_B64 = signer._TEST_PUBKEY_B64
OWN = "00000000-0000-0000-0000-000000002005"
OTHER = "00000000-0000-0000-0000-000000002006"


def envelope(**extra):
    payload = dict(tenant_id="tenant", config_version=4, update_channel="stable", pinned_version="1.2.3")
    payload.update(extra)
    return signer._make_response(json.dumps(payload, separators=(",", ":")).encode())


class ChannelTests(unittest.TestCase):
    def test_own_override_and_pin(self):
        result, _ = policy.select(envelope(device_channel_overrides={OWN: "beta"}), None, "tenant", OWN, 0)
        self.assertEqual(result, dict(effective_channel="beta", source="device_override", pinned_version="1.2.3", config_version=4))

    def test_absent_foreign_malformed_override(self):
        for overrides in (None, [], 42, {}, {OTHER: "beta"}, {OWN: "stable"}, {OWN: {}}, {OWN: "preview"}):
            result, _ = policy.select(envelope(update_channel="beta", device_channel_overrides=overrides), None, "tenant", OWN, 0)
            self.assertEqual((result["effective_channel"], result["source"]), ("beta", "tenant"))

    def test_unverified_wrong_scope_and_rollback(self):
        for value in ({"update_channel": "beta", "device_channel_overrides": {OWN: "beta"}}, envelope(tenant_id="other"), envelope(config_version=3)):
            result, state = policy.select(value, None, "tenant", OWN, 4)
            self.assertEqual(result, policy.DEFAULT)
            self.assertIsNone(state)
        corrupt = envelope(device_channel_overrides={OWN: "beta"})
        corrupt["signature"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(policy.select(corrupt, None, "tenant", OWN, 0)[0], policy.DEFAULT)

    def test_unknown_identity_not_hardware_match(self):
        cfg = policy.decode_verified(envelope(device_channel_overrides={OTHER: "beta"}))
        self.assertEqual(policy.resolve(cfg, "tenant", None, verified=True)["source"], "tenant")
        self.assertEqual(policy.resolve(cfg, "tenant", OWN, verified=False), policy.DEFAULT)

    def test_device_scoped_source_and_p0(self):
        result, _ = policy.select(envelope(device_id=OWN, update_channel_source="tenant", device_channel_overrides={OWN: "beta"}), None, "tenant", OWN, 0)
        self.assertEqual(result["effective_channel"], "stable")
        self.assertEqual(result["source"], "tenant")
        for source in (None, "unknown"):
            result, _ = policy.select(envelope(device_id=OWN, update_channel="beta", update_channel_source=source), None, "tenant", OWN, 0)
            self.assertIsNone(result["source"])
        self.assertEqual(policy.select(envelope(device_id=OTHER, update_channel="beta"), None, "tenant", OWN, 0)[0], policy.DEFAULT)

    def test_restart_reverifies_signature_floor_and_identity(self):
        good = envelope(device_channel_overrides={OWN: "beta"})
        _, state = policy.select(good, None, "tenant", OWN, 0)
        with tempfile.TemporaryDirectory() as directory:
            cache = str(Path(directory) / "state.json")
            policy.atomic_json(cache, state)
            cached = policy.read_json(cache)
            self.assertEqual(policy.policy_from_state(cached, "tenant", OWN, 4)[1]["source"], "device_override")
            with self.assertRaises(ValueError):
                policy.policy_from_state(cached, "tenant", OTHER, 4)
            self.assertEqual(policy.select(None, cached, "tenant", OWN, 4)[0]["effective_channel"], "beta")
            self.assertEqual(policy.select(envelope(config_version=3), cached, "tenant", OWN, 0)[0]["config_version"], 4)
            self.assertEqual(policy.select(None, cached, "tenant", OTHER, 4)[0]["source"], "tenant")
            self.assertEqual(policy.select(None, cached, "other", OWN, 0)[0], policy.DEFAULT)
            cached["envelope"]["signed_payload"] = base64.b64encode(b"{}").decode()
            with self.assertRaises(ValueError):
                policy.select(good, cached, "tenant", OWN, 0)

    def test_real_bash_artifact_query_uses_decision_and_preserves_pin(self):
        source = (ROOT / "macos/patched-bootstrap.sh").read_text()
        encoder = source[source.index("url_encode() {"):source.index("# HMAC-SHA256 a file")]
        builder = source[source.index('_encoded_channel=$(url_encode "$UPDATE_CHANNEL")'):source.index('_encoded_channel=$(url_encode "$UPDATE_CHANNEL")') + source[source.index('_encoded_channel=$(url_encode "$UPDATE_CHANNEL")'):].index("\nfi") + 3]
        for override, expected in (("beta", "beta"), (None, "stable")):
            overrides = {OWN: override} if override else {}
            result, _ = policy.select(envelope(device_channel_overrides=overrides), None, "tenant", OWN, 0)
            script = encoder + '\nAPI_URL="https://api.example.test"\nUPDATE_CHANNEL="' + result["effective_channel"] + '"\nPINNED_VERSION="' + result["pinned_version"] + '"\n' + builder + '\nprintf "%s" "$ARTIFACT_ENDPOINT"'
            output = subprocess.check_output(["bash", "-c", script], text=True)
            self.assertEqual(output, "https://api.example.test/v1/agent/artifact?platform=macos&channel=" + expected + "&version=1.2.3")

    def test_healthy_selection_merges_without_degraded_fault(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / "inventory.json", root / "output.json"
            source.write_text('{"schema_version":3}')
            # Test only helper output seam; production helper always reverifies.
            (root / "agent_update_channel.py").write_text('print(\'{"effective_channel":"beta","source":"device_override","config_version":4,"observed_at":"2026-09-27T00:00:00Z"}\')')
            command = 'PYTHON3=/usr/bin/python3; PATCHED_BUNDLE_DIR="$1"; PATCHED_AGENT_HEALTH_STORE="$1/absent.json"; source "$2"; patched_agent_health_merge_into_payload "$3" "$4"'
            subprocess.check_call(["zsh", "-c", command, "test", str(root), str(ROOT / "macos/lib/agent_health.sh"), str(source), str(target)])
            health = json.loads(target.read_text())["agent_health"]
            self.assertEqual(health["degraded"], [])
            self.assertEqual(health["update_channel"]["source"], "device_override")
            (root / "agent_update_channel.py").write_text('raise SystemExit(1)')
            subprocess.check_call(["zsh", "-c", command, "test", str(root), str(ROOT / "macos/lib/agent_health.sh"), str(source), str(target)])
            self.assertNotIn("update_channel", json.loads(target.read_text())["agent_health"])

    def test_state_rejects_symlink_and_world_writable_file(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "cache.json"
            cache.write_text('{}')
            cache.chmod(0o666)
            with self.assertRaises(ValueError):
                policy.check_state_file(cache)
            link = Path(directory) / "link"
            link.symlink_to(cache)
            with self.assertRaises(ValueError):
                policy.check_state_file(link)


if __name__ == "__main__":
    unittest.main()
