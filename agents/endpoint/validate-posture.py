#!/usr/bin/env python3
"""
validate-posture.py — structural validation only (stdlib, no jsonschema).

Fail-closed: exits 1 on any structural problem. Checks required-field presence
and primitive types. Does NOT verify the authenticity of the posture payload.

Authenticity is now handled by verify-posture.py (PAT-910): the fetch path
(patched-fetch-posture.sh) verifies the Ed25519 signature, tenant binding, and
anti-rollback at parity with verify-agent-config.py before caching, and refuses
to cache any unverified posture. The earlier "authenticity is TLS-only" gap is
therefore closed. This script runs in the fetch path AFTER verify-posture.py
and BEFORE the atomic cache commit, so a signed-but-malformed payload can never
reach the cache that root-privileged readers (patched-uninstall.sh) consume.
It is not the authenticity verifier and must never be treated as one.

TODO(PAT-480-priv): audit BUNDLE_DIR ownership and sudoers pinning for this
script (privilege model review, PAT-66 follow-up).
"""
import sys
import json
import argparse

_TOP_REQUIRED = {
    "schema_version", "tenant_id", "issued_at", "generated_at", "device",
    "tier", "app_count", "compliance", "evidence",
}
_DEVICE_REQUIRED   = {"id", "os"}
_COMP_REQUIRED     = {"platform", "benchmarks"}
_EVIDENCE_REQUIRED = {"coverage_window_days", "scans_logged", "recent_scan_times"}


def _err(msg):
    print(f"Posture verification failed: {msg}", file=sys.stderr)


def verify_posture(response_file):
    try:
        with open(response_file) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        _err(e)
        return False

    if not isinstance(data, dict):
        _err("root is not an object")
        return False

    missing = _TOP_REQUIRED - data.keys()
    if missing:
        _err(f"missing required top-level fields: {sorted(missing)}")
        return False

    if data["schema_version"] != 1:
        _err(f"unsupported schema_version: {data['schema_version']!r}")
        return False

    if not isinstance(data["tenant_id"], str) or not data["tenant_id"]:
        _err("tenant_id must be a non-empty string")
        return False

    if not isinstance(data["issued_at"], str) or not data["issued_at"]:
        _err("issued_at must be a non-empty string")
        return False

    if not isinstance(data["generated_at"], str):
        _err("generated_at must be a string")
        return False

    if not isinstance(data["tier"], str):
        _err("tier must be a string")
        return False

    if not isinstance(data["app_count"], int):
        _err("app_count must be an integer")
        return False

    device = data["device"]
    if not isinstance(device, dict):
        _err("device must be an object")
        return False
    missing = _DEVICE_REQUIRED - device.keys()
    if missing:
        _err(f"device missing required fields: {sorted(missing)}")
        return False

    compliance = data["compliance"]
    if not isinstance(compliance, dict):
        _err("compliance must be an object")
        return False
    missing = _COMP_REQUIRED - compliance.keys()
    if missing:
        _err(f"compliance missing required fields: {sorted(missing)}")
        return False
    if not isinstance(compliance["benchmarks"], list):
        _err("compliance.benchmarks must be an array")
        return False

    evidence = data["evidence"]
    if not isinstance(evidence, dict):
        _err("evidence must be an object")
        return False
    missing = _EVIDENCE_REQUIRED - evidence.keys()
    if missing:
        _err(f"evidence missing required fields: {sorted(missing)}")
        return False
    if not isinstance(evidence["recent_scan_times"], list):
        _err("evidence.recent_scan_times must be an array")
        return False

    # app_policy shape (PAT-910): root-privileged removal gating reads
    # app_policy.apps[].user_removable, so if the field is present it must be
    # well-formed — an object whose "apps" is a list of objects with string
    # app_name and boolean user_removable. Absent app_policy is allowed here
    # (the uninstall gate independently refuses when it cannot resolve policy).
    if "app_policy" in data:
        ap = data["app_policy"]
        if not isinstance(ap, dict):
            _err("app_policy must be an object")
            return False
        apps = ap.get("apps")
        if not isinstance(apps, list):
            _err("app_policy.apps must be an array")
            return False
        for i, entry in enumerate(apps):
            if not isinstance(entry, dict):
                _err(f"app_policy.apps[{i}] must be an object")
                return False
            if not isinstance(entry.get("app_name"), str):
                _err(f"app_policy.apps[{i}].app_name must be a string")
                return False
            if not isinstance(entry.get("user_removable"), bool):
                _err(f"app_policy.apps[{i}].user_removable must be a boolean")
                return False
        if "drift" in ap and not isinstance(ap["drift"], list):
            _err("app_policy.drift must be an array")
            return False

    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--response-file", required=True)
    args = parser.parse_args()

    if not verify_posture(args.response_file):
        sys.exit(1)
    sys.exit(0)
