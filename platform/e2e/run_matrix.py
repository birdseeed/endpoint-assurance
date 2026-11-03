#!/usr/bin/env python3
"""
e2e/run_matrix.py — Layer A matrix runner (PAT-739 T4).

Reads e2e/data/matrix.json, groups 662 cases into ~10 synthetic devices,
enables all T2 rules, posts each device payload, polls for evaluations,
reads verdicts through the dashboard, and asserts expected_status against
the observed status.

Writes artifacts to e2e/artifacts/layer-a-run1/.
"""

import base64
import hashlib
import hmac as _hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).parent
STATE_DIR = SCRIPT_DIR / ".state"
MATRIX_FILE = SCRIPT_DIR / "data" / "matrix.json"
RUN_ID = os.environ.get("E2E_RUN_ID", "layer-a-run1")
ARTIFACT_DIR = SCRIPT_DIR / "artifacts" / RUN_ID

# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------

API_PUBLIC_URL = "http://127.0.0.1:18080"
API_INTERNAL_URL = "http://127.0.0.1:18081"
DASHBOARD_URL = "http://127.0.0.1:18000"

# ---------------------------------------------------------------------------
# State loading
# ---------------------------------------------------------------------------


def state_get(key):
    p = STATE_DIR / key
    if p.exists():
        return p.read_text().strip()
    return ""


def load_state():
    keys = ["ADMIN_API_TOKEN", "DASHBOARD_API_KEY", "TENANT_ID", "BEARER_TOKEN", "HMAC_SECRET_B64"]
    state = {}
    for k in keys:
        v = state_get(k)
        if not v:
            print(f"ERROR: state file '{k}' missing or empty. Run e2e/stack.sh up first.")
            sys.exit(1)
        state[k] = v
    return state


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only)
# ---------------------------------------------------------------------------


def _do_request(req, retries=2):
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except Exception as e:
            if attempt < retries:
                time.sleep(1)
                continue
            print(f"  HTTP error: {e}")
            return 0, b""
    return 0, b""


def http_get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    return _do_request(req)


def http_post(url, body, headers=None):
    req = urllib.request.Request(url, data=body, headers=headers or {}, method="POST")
    return _do_request(req)


def http_put(url, body, headers=None):
    req = urllib.request.Request(url, data=body, headers=headers or {}, method="PUT")
    return _do_request(req)


# ---------------------------------------------------------------------------
# HMAC signing
# ---------------------------------------------------------------------------


def sign_payload(body, hmac_secret_b64):
    """Return (signature_hex, timestamp_str, nonce_str)."""
    secret = base64.b64decode(hmac_secret_b64)
    sig = _hmac.new(secret, body, hashlib.sha256).hexdigest()
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())
    return sig, timestamp, nonce


# ---------------------------------------------------------------------------
# Deterministic device UUID (uuid5 from serial)
# ---------------------------------------------------------------------------

# Fixed namespace — same value every run.
_UUID_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # uuid.NAMESPACE_DNS


def device_uuid5(serial):
    return str(uuid.uuid5(_UUID_NS, serial)).upper()


# ---------------------------------------------------------------------------
# Pre-step: enable all T2 rules for the tenant
# ---------------------------------------------------------------------------


def enable_all_t2_rules(state):
    """Enable all T2 rules for the tenant. Returns count of PUT calls succeeded."""
    admin_token = state["ADMIN_API_TOKEN"]
    tenant_id = state["TENANT_ID"]

    code, body = http_get(
        f"{API_INTERNAL_URL}/admin/tenant-rules/{tenant_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    if code != 200:
        print(f"ERROR: GET tenant-rules returned {code}: {body.decode(errors='replace')[:200]}")
        sys.exit(1)

    data = json.loads(body)
    t2_rules = [r for r in data["rules"] if r["collection_tier"] == "T2"]
    print(f"  Found {len(t2_rules)} T2 rules across all platforms; enabling all...")

    enabled_count = 0
    errors = 0
    for r in t2_rules:
        rule_id = r["rule_id"]
        put_body = json.dumps({"enabled": True, "override_severity": None}).encode()
        code, resp = http_put(
            f"{API_INTERNAL_URL}/admin/tenant-rules/{tenant_id}/{rule_id}",
            body=put_body,
            headers={
                "Authorization": f"Bearer {admin_token}",
                "Content-Type": "application/json",
            },
        )
        if code in (200, 201, 204):
            enabled_count += 1
        else:
            errors += 1
            print(f"  WARNING: PUT rule {r['rule_key']} returned {code}: {resp.decode(errors='replace')[:80]}")

    if errors:
        print(f"  Enabled {enabled_count} T2 rules ({errors} errors).")
    else:
        print(f"  Enabled {enabled_count} T2 rules (all OK).")

    # Verify: re-read and count enabled T2 rules.
    code, body = http_get(
        f"{API_INTERNAL_URL}/admin/tenant-rules/{tenant_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    if code == 200:
        data = json.loads(body)
        still_disabled = [r for r in data["rules"] if r["collection_tier"] == "T2" and not r.get("enabled")]
        if still_disabled:
            print(f"  WARNING: {len(still_disabled)} T2 rules still show enabled=false after pre-step.")
            for r in still_disabled[:5]:
                print(f"    {r['rule_key']} ({r['platform']})")
        else:
            print(f"  Verified: all T2 rules now enabled.")
    return enabled_count


# ---------------------------------------------------------------------------
# Payload construction
# ---------------------------------------------------------------------------


def build_compliance_map(cases):
    """Build {signal_key: inject_value} from group cases (omitting omit_signal=True)."""
    compliance = {}
    for c in cases:
        if not c.get("omit_signal") and c.get("inject") is not None:
            key = c["signal_key"]
            if key in compliance and compliance[key] != c["inject"]:
                # Two rules sharing a signal_key with conflicting inject values:
                # silent last-writer-wins would corrupt both assertions.
                raise SystemExit(
                    f"signal_key collision in group: {key} "
                    f"({compliance[key]!r} vs {c['inject']!r}) — split the group"
                )
            compliance[key] = c["inject"]
    return compliance


def build_macos_payload(serial, hw_uuid, arch, tenant_id, compliance):
    """Build schema_version=2 macOS payload."""
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {
        "schema_version": 2,
        "agent": "patched-e2e",
        "agent_version": "0.0.0-e2e",
        "tenant_id": tenant_id,
        "collected_at": now_iso,
        "device": {
            "serial": serial,
            "hw_uuid": hw_uuid,
            "hostname": f"{serial}.local",
            "computer_name": serial,
            "hw_model": "Mac14,2",
            "arch": arch,
            "last_boot": now_iso,
        },
        "hardware": {
            "cpu_model": "Apple M2" if arch == "arm64" else "Intel Core i7",
            "cpu_cores": 8,
            "ram_gb": 16,
            "disk_total_gb": 500.0,
            "disk_free_gb": 300.0,
        },
        "os": {
            "name": "macOS",
            "version": "15.4.1",
            "build": "24E263",
        },
        "compliance": compliance,
        "security_tools": [],
        "system_extensions": [],
        "background_items": [],
        "icloud": {"signed_in": "No"},
        "apps": [],
    }


def build_windows_payload(serial, hw_uuid, arch, tenant_id, compliance):
    """Build schema_version=3 Windows payload.

    hardware is required by ValidatePayload (top-level required for all schema versions).
    platform is required when schema_version == 3.
    security_tools and apps are top-level required arrays.
    system_extensions/background_items/icloud are NOT required for schema_version 3.
    """
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {
        "schema_version": 3,
        "platform": "windows",
        "agent": "patched-e2e",
        "agent_version": "0.0.0-e2e",
        "tenant_id": tenant_id,
        "collected_at": now_iso,
        "device": {
            "serial": serial,
            "hw_uuid": hw_uuid,
            "hostname": serial,
            "computer_name": serial,
            "hw_model": "Virtual Machine",
            "arch": arch,
            "last_boot": now_iso,
        },
        "hardware": {
            "cpu_model": "Intel Core i7-10700",
            "cpu_cores": 8,
            "ram_gb": 16,
            "disk_total_gb": 256.0,
            "disk_free_gb": 128.0,
        },
        "os": {
            "name": "Windows",
            "version": "10.0.19045",
            "build": "19045",
        },
        "compliance": compliance,
        "security_tools": [],
        "apps": [],
    }


def build_payload(platform, arch, serial, hw_uuid, tenant_id, group_cases):
    compliance = build_compliance_map(group_cases)
    if platform == "macos":
        return build_macos_payload(serial, hw_uuid, arch, tenant_id, compliance)
    else:
        return build_windows_payload(serial, hw_uuid, arch, tenant_id, compliance)


# ---------------------------------------------------------------------------
# API / dashboard interaction
# ---------------------------------------------------------------------------


def post_device(payload_dict, state, artifacts_dir, serial):
    """POST payload. Returns raw_payload_id or None on error."""
    body = json.dumps(payload_dict).encode()
    sig, timestamp, nonce = sign_payload(body, state["HMAC_SECRET_B64"])

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {state['BEARER_TOKEN']}",
        "X-Patched-Signature": sig,
        "X-Patched-Timestamp": timestamp,
        "X-Patched-Nonce": nonce,
    }
    code, resp_body = http_post(f"{API_PUBLIC_URL}/v1/inventory", body, headers)

    # Save payload evidence regardless of outcome.
    dev_dir = artifacts_dir / "devices"
    dev_dir.mkdir(parents=True, exist_ok=True)
    (dev_dir / f"{serial}.payload.json").write_text(json.dumps(payload_dict, indent=2))

    if code != 200:
        print(f"  ERROR: POST /v1/inventory returned {code}: {resp_body.decode(errors='replace')[:200]}")
        return None

    # Response is {"raw_payload_id": <int>, "request_id": "...", "status": "ok"}
    # raw_payload_id is at the top level (not nested under "data").
    data = json.loads(resp_body)
    raw_id = data.get("raw_payload_id")
    return raw_id if raw_id is not None else "ok"


def find_device_id(tenant_id, serial, admin_token, timeout_s=90):
    """Poll until device appears by serial. Returns device_id or None."""
    deadline = time.time() + timeout_s
    attempt = 0
    while time.time() < deadline:
        code, body = http_get(
            f"{API_INTERNAL_URL}/admin/tenants/{tenant_id}/devices",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        if code == 200:
            data = json.loads(body)
            for d in data.get("devices", []):
                if d.get("serial") == serial:
                    return d["id"]
        attempt += 1
        if attempt % 15 == 1 and attempt > 1:
            print(f"    Still waiting for device ({attempt}s)...")
        time.sleep(1)
    return None


def wait_for_evaluations(device_id, dashboard_key, artifacts_dir, serial, timeout_s=120):
    """Poll dashboard until evaluations appear. Returns evaluations list."""
    deadline = time.time() + timeout_s
    attempt = 0
    while time.time() < deadline:
        code, body = http_get(
            f"{DASHBOARD_URL}/admin/devices/{device_id}",
            headers={"Authorization": f"Bearer {dashboard_key}"},
        )
        if code == 200:
            data = json.loads(body)
            evals = data.get("evaluations", [])
            if evals:
                # Save full device response as evidence.
                dev_dir = artifacts_dir / "devices"
                dev_dir.mkdir(parents=True, exist_ok=True)
                (dev_dir / f"{serial}.evaluations.json").write_text(json.dumps(data, indent=2))
                return evals
        attempt += 1
        if attempt % 20 == 1 and attempt > 1:
            print(f"    Still waiting for evaluations ({attempt}s)...")
        time.sleep(1)
    return []


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    print(f"=== Patched E2E Layer A Matrix Runner (run_id={RUN_ID}) ===")
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    (ARTIFACT_DIR / "devices").mkdir(parents=True, exist_ok=True)

    # Load state.
    state = load_state()
    tenant_id = state["TENANT_ID"]
    admin_token = state["ADMIN_API_TOKEN"]
    dashboard_key = state["DASHBOARD_API_KEY"]
    print(f"Tenant: {tenant_id}")

    # Load matrix.
    with open(MATRIX_FILE) as f:
        matrix = json.load(f)
    cases = matrix["cases"]
    print(f"Matrix: {len(cases)} cases")

    # Pre-step: enable all T2 rules.
    print("\n=== Pre-step: Enable T2 rules ===")
    t2_enabled_count = enable_all_t2_rules(state)

    # Group cases by (platform, state, device_arch).
    print("\n=== Grouping cases ===")
    groups = defaultdict(list)
    for c in cases:
        key = (c["platform"], c["state"], c.get("device_arch", "arm64"))
        groups[key].append(c)

    print(f"Groups ({len(groups)} total):")
    for k in sorted(groups.keys()):
        print(f"  {k}: {len(groups[k])} cases")

    # Process each group.
    ledger = []

    print("\n=== Processing device groups ===")
    for group_key in sorted(groups.keys()):
        platform, state_name, arch = group_key
        group_cases = groups[group_key]

        # Deterministic serial. Include arch suffix only for non-default (x86_64).
        if arch != "arm64":
            serial = f"e2e-a-{platform}-{state_name}-{arch}"
        else:
            serial = f"e2e-a-{platform}-{state_name}"
        hw_uuid = device_uuid5(serial)

        n = len(group_cases)
        print(f"\n[{serial}] platform={platform} state={state_name} arch={arch} cases={n}")

        # Build payload.
        payload_dict = build_payload(platform, arch, serial, hw_uuid, tenant_id, group_cases)
        compliance_size = len(payload_dict.get("compliance", {}))
        print(f"  Compliance map: {compliance_size} signals set")

        # POST payload.
        raw_id = post_device(payload_dict, state, ARTIFACT_DIR, serial)
        if raw_id is None:
            print(f"  FAILED to POST payload.")
            for c in group_cases:
                ledger.append(_mk_ledger_row(c, serial, None, None, "MISSING_EVAL"))
            continue
        print(f"  Posted OK (raw_payload_id={raw_id})")

        # Find device_id (extractor must create the device row).
        print(f"  Finding device_id for serial={serial}...")
        device_id = find_device_id(tenant_id, serial, admin_token, timeout_s=90)
        if device_id is None:
            print(f"  ERROR: Device did not appear within 90s.")
            for c in group_cases:
                ledger.append(_mk_ledger_row(c, serial, None, None, "MISSING_EVAL"))
            continue
        print(f"  Device found: {device_id}")

        # Poll dashboard for evaluations.
        print(f"  Waiting for evaluations from dashboard...")
        evals = wait_for_evaluations(device_id, dashboard_key, ARTIFACT_DIR, serial, timeout_s=120)
        if not evals:
            print(f"  ERROR: No evaluations appeared within 120s.")
            for c in group_cases:
                ledger.append(_mk_ledger_row(c, serial, device_id, None, "MISSING_EVAL"))
            continue
        print(f"  Evaluations received: {len(evals)} rule(s)")

        # Build eval map: rule_key -> status (dashboard returns latest per rule).
        eval_map = {e["rule_key"]: e["status"] for e in evals}

        # Assert each case.
        g_pass = g_fail = g_missing = 0
        for c in group_cases:
            rk = c["rule_key"]
            expected = c["expected_status"]
            if rk not in eval_map:
                result = "MISSING_EVAL"
                observed = None
                g_missing += 1
            else:
                observed = eval_map[rk]
                if observed == expected:
                    result = "PASS"
                    g_pass += 1
                else:
                    result = "FAIL"
                    g_fail += 1
            ledger.append(_mk_ledger_row(c, serial, device_id, observed, result))

        print(f"  {g_pass} PASS, {g_fail} FAIL, {g_missing} MISSING_EVAL")

    # Write ledger.
    ledger_path = ARTIFACT_DIR / "ledger.jsonl"
    with open(ledger_path, "w") as f:
        for row in ledger:
            f.write(json.dumps(row) + "\n")
    print(f"\nLedger: {ledger_path} ({len(ledger)} rows)")

    # Aggregate.
    total_pass = sum(1 for r in ledger if r["result"] == "PASS")
    total_fail = sum(1 for r in ledger if r["result"] == "FAIL")
    total_missing = sum(1 for r in ledger if r["result"] == "MISSING_EVAL")
    mismatches = [r for r in ledger if r["result"] != "PASS"]

    summary = {
        "run_id": RUN_ID,
        "total_cases": len(ledger),
        "pass": total_pass,
        "fail": total_fail,
        "missing_eval": total_missing,
        "t2_rules_enabled": t2_enabled_count,
        "mismatches": mismatches,
    }
    summary_path = ARTIFACT_DIR / "summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Summary: {summary_path}")

    # Print results.
    print(f"\n=== FINAL RESULTS ===")
    print(f"Total cases : {len(ledger)}")
    print(f"PASS        : {total_pass}")
    print(f"FAIL        : {total_fail}")
    print(f"MISSING_EVAL: {total_missing}")
    print(f"T2 rules enabled: {t2_enabled_count}")

    if mismatches:
        print(f"\n--- Mismatches ({len(mismatches)}) ---")
        # Group by root cause pattern for cleaner output.
        for m in mismatches:
            note = f" [{m['notes']}]" if m.get("notes") else ""
            print(
                f"  {m['result']:12s} | {m['rule_key']:<55} | state={m['state']:<22} "
                f"| expected={m['expected']:<14} observed={m['observed']}{note}"
            )
    else:
        print("\nAll cases PASS.")

    return 0 if (total_fail == 0 and total_missing == 0) else 1


def _mk_ledger_row(case, serial, device_id, observed, result):
    return {
        "rule_key": case["rule_key"],
        "platform": case["platform"],
        "state": case["state"],
        "tier": case.get("tier"),
        "signal_key": case.get("signal_key"),
        "inject": case.get("inject"),
        "omit_signal": case.get("omit_signal"),
        "expected": case["expected_status"],
        "observed": observed,
        "result": result,
        "device_id": device_id,
        "serial": serial,
        "notes": case.get("notes"),
    }


if __name__ == "__main__":
    sys.exit(main())
