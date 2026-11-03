#!/usr/bin/env python3
"""
Patched E2E Settings-Behaviour Suite (T5 / PAT-739)

Verifies that every tenant-level compliance SETTING changes evaluation
behaviour end-to-end through the local stack.

Usage:
    python3 run_settings.py

Reads credentials from:
    e2e/.state/ (relative to this file)

Writes evidence to:
    ./artifacts/

Writes results to:
    ./RESULTS.md
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib import request as urllib_request, error as urllib_error

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

STATE_DIR   = Path(__file__).resolve().parent / ".state"
ARTIFACTS   = Path(__file__).parent / "artifacts"
RESULTS_MD  = Path(__file__).parent / "RESULTS.md"

API_PUBLIC    = "http://127.0.0.1:18080"
API_INTERNAL  = "http://127.0.0.1:18081"
DASHBOARD     = "http://127.0.0.1:18000"

PG_DSN        = "postgres://patched_e2e:patched_e2e@127.0.0.1:55432/patched_e2e"

# T2 rule under test
T2_RULE_KEY    = "cis_macos_5_2_2_min_length"
T2_SIGNAL_KEY  = "pwpolicy_min_length"
T2_SIGNAL_FAIL = 8   # < 15 → FAIL

# Validate hardcoded rule keys against the canonical rule data at startup
import csv as _csv
_RULES_CSV = Path(__file__).resolve().parent / "data" / "rules.csv"
_KNOWN_RULE_KEYS = {r["rule_key"] for r in _csv.DictReader(open(_RULES_CSV))}
T2_SIGNAL_PASS = 16  # ≥ 15 → PASS

# T1 rule for global-kill-switch test
T1_KILL_KEY = "cis_macos_2_5_3_sip"

for _rk in (T2_RULE_KEY, T1_KILL_KEY):
    if _rk not in _KNOWN_RULE_KEYS:
        raise SystemExit(
            f"Rule key {_rk!r} not in data/rules.csv — constant is stale, "
            "regenerate rules.csv or update the constant"
        )

EXTRACTOR_MAX_WAIT = 60  # seconds

# ---------------------------------------------------------------------------
# State helpers
# ---------------------------------------------------------------------------

def state(key: str) -> str:
    p = STATE_DIR / key
    if not p.exists():
        raise RuntimeError(f"State file missing: {p}  (Run stack.sh up first)")
    return p.read_text().strip()


def save_artifact(name: str, data) -> Path:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    p = ARTIFACTS / name
    if isinstance(data, (dict, list)):
        p.write_text(json.dumps(data, indent=2, default=str))
    else:
        p.write_text(str(data))
    return p


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def http(method: str, url: str, *, headers: dict = None, body=None, timeout=15) -> dict:
    """Return (status_code, parsed_json_or_text)."""
    headers = headers or {}
    data = None
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        elif isinstance(body, bytes):
            data = body
        else:
            data = body.encode()
    req = urllib_request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib_request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            try:
                return resp.status, json.loads(raw)
            except Exception:
                return resp.status, raw.decode()
    except urllib_error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw.decode()


def admin(method: str, path: str, *, body=None) -> tuple:
    token = state("ADMIN_API_TOKEN")
    return http(method, API_INTERNAL + path,
                headers={"Authorization": f"Bearer {token}"},
                body=body)


def dashboard_get(path: str) -> tuple:
    key = state("DASHBOARD_API_KEY")
    return http("GET", DASHBOARD + path,
                headers={"Authorization": f"Bearer {key}"})


# ---------------------------------------------------------------------------
# HMAC / ingestion helpers
# ---------------------------------------------------------------------------

def compute_sig(body_bytes: bytes, hmac_secret_b64: str) -> str:
    secret = base64.b64decode(hmac_secret_b64)
    return hmac.new(secret, body_bytes, hashlib.sha256).hexdigest()


def ingest(tenant_id: str, bearer_token: str, hmac_secret_b64: str, serial: str, extra_compliance: dict = None) -> dict:
    """POST a schema_version-2 macOS payload for the given tenant+serial.
    Returns the parsed JSON response.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    hw_uuid = f"E2ESETT-{serial[-4:].upper()}-AAAA-BBBB-CCCC-{uuid.uuid4().hex[:12].upper()}"

    compliance = {
        "filevault": "On",
        "sip": "enabled",
        "gatekeeper": "enabled",
        "firewall": "enabled",
        "screen_lock": "enabled",
        "screen_lock_timeout": 300,
        "pending_updates_count": 0,
        "remote_login": "disabled",
        "automatic_updates": "enabled",
        "automatic_security_updates": "enabled",
        "os_up_to_date": True,
        "password_hint": "",
    }
    if extra_compliance:
        compliance.update(extra_compliance)

    payload = {
        "schema_version": 2,
        "agent": "e2e-settings",
        "agent_version": "0.0.1",
        "tenant_id": tenant_id,
        "collected_at": now,
        "device": {
            "serial": serial,
            "hw_uuid": hw_uuid,
            "hostname": f"settings-{serial.lower()}",
            "computer_name": f"Settings {serial}",
            "hw_model": "Mac14,2",
            "arch": "arm64",
            "last_boot": now,
        },
        "hardware": {"cpu_model": "Apple M2", "cpu_cores": 8,
                     "ram_gb": 16, "disk_total_gb": 500.0, "disk_free_gb": 300.0},
        "os": {"name": "macOS", "version": "15.4.1", "build": "24E263"},
        "compliance": compliance,
        "security_tools": [],
        "system_extensions": [],
        "background_items": [],
        "icloud": {"signed_in": "No"},
        "apps": [],
    }

    body_bytes = json.dumps(payload).encode()
    sig       = compute_sig(body_bytes, hmac_secret_b64)
    ts        = str(int(time.time()))
    nonce     = str(uuid.uuid4())

    status, resp = http("POST", API_PUBLIC + "/v1/inventory",
                        headers={
                            "Authorization":      f"Bearer {bearer_token}",
                            "X-Patched-Signature": sig,
                            "X-Patched-Timestamp": ts,
                            "X-Patched-Nonce":     nonce,
                        },
                        body=body_bytes)
    if status != 200:
        raise RuntimeError(f"Ingest returned {status}: {resp}")
    return resp


# ---------------------------------------------------------------------------
# Extractor polling
# ---------------------------------------------------------------------------

def wait_for_device(tenant_id: str, serial: str, max_wait: int = EXTRACTOR_MAX_WAIT) -> str:
    """Poll until device appears; return device_id."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        status, resp = admin("GET", f"/admin/tenants/{tenant_id}/devices")
        if status == 200:
            for d in resp.get("devices", []):
                if d.get("serial") == serial:
                    return d["id"]
        time.sleep(2)
    raise RuntimeError(f"Device {serial} did not appear within {max_wait}s")


def wait_for_evaluations(device_id: str, max_wait: int = EXTRACTOR_MAX_WAIT) -> list:
    """Poll until evaluations appear; return evaluation list."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        status, resp = admin("GET", f"/admin/devices/{device_id}")
        if status == 200:
            evals = resp.get("evaluations", [])
            if evals:
                return evals
        time.sleep(2)
    return []  # return empty rather than raise; caller asserts


def wait_for_t1_no_t2(device_id: str, t2_rule_key: str, max_wait: int = EXTRACTOR_MAX_WAIT) -> tuple:
    """Wait until T1 evaluations appear (extractor ran), then return all evals.
    Returns (evals, t1_appeared) where t1_appeared=True means the extractor ran.
    Use this for suppression/platform scenarios where T1 should appear but T2 should not.
    """
    deadline = time.time() + max_wait
    while time.time() < deadline:
        status, resp = admin("GET", f"/admin/devices/{device_id}")
        if status == 200:
            evals = resp.get("evaluations", [])
            # Consider extractor ran if any T1 evals are present
            t1_evals = [e for e in evals if e.get("rule_key") != t2_rule_key]
            if t1_evals:
                return evals, True
        time.sleep(2)
    # Extractor may not have run — return whatever we have
    status, resp = admin("GET", f"/admin/devices/{device_id}")
    if status == 200:
        return resp.get("evaluations", []), False
    return [], False


def wait_for_no_evaluations(device_id: str, settle_wait: int = 15) -> list:
    """Wait settle_wait seconds then return evaluations (expected to be empty)."""
    time.sleep(settle_wait)
    status, resp = admin("GET", f"/admin/devices/{device_id}")
    if status == 200:
        return resp.get("evaluations", [])
    return []


# ---------------------------------------------------------------------------
# Rule ID lookup
# ---------------------------------------------------------------------------

def get_rule_id(tenant_id: str, rule_key: str) -> str:
    status, resp = admin("GET", f"/admin/tenant-rules/{tenant_id}?platform=macos")
    if status != 200:
        raise RuntimeError(f"tenant-rules list failed: {status}")
    for r in resp.get("rules", []):
        if r["rule_key"] == rule_key:
            return r["rule_id"]
    raise RuntimeError(f"Rule not found: {rule_key}")


# ---------------------------------------------------------------------------
# psql helper (for scenario 7)
# ---------------------------------------------------------------------------

def psql_exec(sql: str) -> str:
    import subprocess
    result = subprocess.run(
        ["psql", PG_DSN, "-t", "-c", sql],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"psql failed: {result.stderr}")
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------

results = []

def record(scenario: str, passed: bool, observed: str, notes: str = ""):
    marker = "PASS" if passed else "FAIL"
    results.append((scenario, marker, observed, notes))
    print(f"  [{marker}] {scenario}")
    if notes:
        print(f"         note: {notes}")
    print(f"         obs: {observed[:200]}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("Patched E2E Settings Suite (T5)")
    print("=" * 60)

    ARTIFACTS.mkdir(parents=True, exist_ok=True)

    # ── Create our own tenant ──────────────────────────────────────────────
    print("\n[setup] Creating tenant e2e-settings...")
    st, resp = admin("POST", "/admin/tenants", body={"name": "e2e-settings"})
    if st not in (200, 201):
        raise RuntimeError(f"Tenant creation failed {st}: {resp}")

    TENANT_ID      = resp["tenant_id"]
    BEARER_TOKEN   = resp["bearer_token"]
    HMAC_SECRET    = resp["hmac_secret_b64"]

    save_artifact("00_tenant_created.json", resp)
    print(f"         tenant_id={TENANT_ID}")

    # Lookup T2 rule ID
    T2_RULE_ID = get_rule_id(TENANT_ID, T2_RULE_KEY)
    print(f"         t2_rule_id={T2_RULE_ID}  ({T2_RULE_KEY})")

    # ── Scenario 1: T2 default-off ─────────────────────────────────────────
    print("\n[s1] T2 default-off")
    serial1 = "e2e-s1"
    extra1  = {T2_SIGNAL_KEY: T2_SIGNAL_FAIL}
    ingest_resp1 = ingest(TENANT_ID, BEARER_TOKEN, HMAC_SECRET, serial1, extra1)
    save_artifact("s1_ingest.json", ingest_resp1)

    device1 = wait_for_device(TENANT_ID, serial1)
    evals1  = wait_for_evaluations(device1)
    save_artifact("s1_evals.json", evals1)

    t2_in_evals1 = any(e.get("rule_key") == T2_RULE_KEY for e in evals1)
    t1_in_evals1 = any(e.get("rule_key") == "cis_macos_2_5_1_1_filevault" for e in evals1)

    # Also check dashboard
    _, dash1 = dashboard_get(f"/admin/devices/{device1}")
    save_artifact("s1_dash.json", dash1)
    dash_t2 = any(e.get("rule_key") == T2_RULE_KEY for e in dash1.get("evaluations", []))
    dash_t1 = len(dash1.get("evaluations", [])) > 0

    passed1 = (not t2_in_evals1) and t1_in_evals1 and (not dash_t2) and dash_t1
    record(
        "S1: T2 default-off",
        passed1,
        f"T2 in evals={t2_in_evals1} (want False), T1 present={t1_in_evals1} (want True), "
        f"dashboard T2={dash_t2} (want False), dashboard T1={dash_t1} (want True)",
    )

    # ── Scenario 2: T2 enable ──────────────────────────────────────────────
    print("\n[s2] T2 enable")
    st2, enable_resp = admin("PUT", f"/admin/tenant-rules/{TENANT_ID}/{T2_RULE_ID}",
                             body={"enabled": True})
    save_artifact("s2_put_rule.json", {"status": st2, "resp": enable_resp})

    serial2 = "e2e-s2"
    extra2  = {T2_SIGNAL_KEY: T2_SIGNAL_FAIL}
    ingest_resp2 = ingest(TENANT_ID, BEARER_TOKEN, HMAC_SECRET, serial2, extra2)
    save_artifact("s2_ingest.json", ingest_resp2)

    device2 = wait_for_device(TENANT_ID, serial2)
    evals2  = wait_for_evaluations(device2)
    save_artifact("s2_evals.json", evals2)

    t2_eval2 = next((e for e in evals2 if e.get("rule_key") == T2_RULE_KEY), None)
    # Assert the verdict DIRECTION too: the injected value violates the gte-15
    # rule, so presence alone would let an always-pass evaluator slip through.
    passed2 = (
        (st2 == 200)
        and (t2_eval2 is not None)
        and (t2_eval2.get("status") == "fail")
    )
    record(
        "S2: T2 enable",
        passed2,
        f"PUT status={st2}, T2 eval={t2_eval2!r}",
    )

    # ── Scenario 3: T2 disable ─────────────────────────────────────────────
    print("\n[s3] T2 disable")
    st3, delete_resp = admin("DELETE", f"/admin/tenant-rules/{TENANT_ID}/{T2_RULE_ID}")
    save_artifact("s3_delete_rule.json", {"status": st3, "resp": delete_resp})

    serial3 = "e2e-s3"
    extra3  = {T2_SIGNAL_KEY: T2_SIGNAL_FAIL}
    ingest_resp3 = ingest(TENANT_ID, BEARER_TOKEN, HMAC_SECRET, serial3, extra3)
    save_artifact("s3_ingest.json", ingest_resp3)

    device3 = wait_for_device(TENANT_ID, serial3)
    evals3  = wait_for_evaluations(device3)
    save_artifact("s3_evals.json", evals3)

    t2_in_evals3 = any(e.get("rule_key") == T2_RULE_KEY for e in evals3)
    passed3 = (st3 == 200) and (not t2_in_evals3)
    record(
        "S3: T2 disable (DELETE)",
        passed3,
        f"DELETE status={st3}, T2 in evals={t2_in_evals3} (want False)",
    )

    # ── Scenario 4: Suppression ────────────────────────────────────────────
    print("\n[s4] Suppression")
    # First re-enable the rule, then add suppression.
    future = (datetime.now(timezone.utc) + timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    st4, supp_resp = admin("PUT", f"/admin/tenant-rules/{TENANT_ID}/{T2_RULE_ID}",
                           body={"enabled": True,
                                 "suppression_reason": "e2e",
                                 "suppressed_until": future})
    save_artifact("s4_put_suppressed.json", {"status": st4, "resp": supp_resp})

    serial4 = "e2e-s4"
    extra4  = {T2_SIGNAL_KEY: T2_SIGNAL_FAIL}
    ingest_resp4 = ingest(TENANT_ID, BEARER_TOKEN, HMAC_SECRET, serial4, extra4)
    save_artifact("s4_ingest.json", ingest_resp4)

    device4 = wait_for_device(TENANT_ID, serial4)
    # Wait for T1 evaluations to appear (extractor ran), then check T2 is absent
    evals4, t1_ran4 = wait_for_t1_no_t2(device4, T2_RULE_KEY)
    save_artifact("s4_evals.json", evals4)

    # Code says: suppressed_until < now() must be TRUE for the rule to load.
    # If suppressed_until is in the future, condition is FALSE → rule excluded from JOIN.
    # So: enabled=true + suppressed_until=future → NOT evaluated.
    t2_in_evals4 = any(e.get("rule_key") == T2_RULE_KEY for e in evals4)
    passed4 = (st4 == 200) and t1_ran4 and (not t2_in_evals4)
    record(
        "S4: Suppression (enabled=true + suppressed_until=future)",
        passed4,
        f"PUT status={st4}, extractor_ran={t1_ran4}, T2 in evals={t2_in_evals4} (want False), "
        f"total evals (T1 rules present)={len(evals4)}. "
        f"Semantics: suppressed_until < now() must be TRUE to include; future suppressed_until excludes rule.",
        notes=f"suppressed_until={future}",
    )

    # ── Scenario 5: Severity override ─────────────────────────────────────
    print("\n[s5] Severity override")
    # Clear suppression + set override_severity=critical (enabled=true, no suppression)
    st5a, over_resp = admin("PUT", f"/admin/tenant-rules/{TENANT_ID}/{T2_RULE_ID}",
                            body={"enabled": True, "override_severity": "critical"})
    save_artifact("s5_put_override.json", {"status": st5a, "resp": over_resp})

    # Verify GET shows override
    st5b, list_resp5 = admin("GET", f"/admin/tenant-rules/{TENANT_ID}?platform=macos")
    t2_rule_entry5 = next((r for r in list_resp5.get("rules", []) if r["rule_key"] == T2_RULE_KEY), None)
    save_artifact("s5_list_rules.json", list_resp5)

    serial5 = "e2e-s5"
    extra5  = {T2_SIGNAL_KEY: T2_SIGNAL_FAIL}
    ingest_resp5 = ingest(TENANT_ID, BEARER_TOKEN, HMAC_SECRET, serial5, extra5)
    save_artifact("s5_ingest.json", ingest_resp5)

    device5 = wait_for_device(TENANT_ID, serial5)
    evals5  = wait_for_evaluations(device5)
    save_artifact("s5_evals.json", evals5)

    t2_eval5 = next((e for e in evals5 if e.get("rule_key") == T2_RULE_KEY), None)

    # Check findings endpoint for severity
    _, findings5 = dashboard_get(f"/admin/tenants/{TENANT_ID}/findings")
    save_artifact("s5_findings.json", findings5)
    t2_finding5 = next(
        (f for f in findings5.get("findings", []) if f.get("rule_key") == T2_RULE_KEY and
         f.get("device_id") == device5),
        None
    )

    override_in_list = t2_rule_entry5 and t2_rule_entry5.get("override_severity") == "critical"
    # Device-detail (admin/devices/{id}) reads r.severity from compliance_rules (GLOBAL severity)
    # NOT from compliance_evaluations.severity (the stored/effective value).
    # So eval_severity here is the global severity, not the override.
    eval_severity_from_detail  = t2_eval5.get("severity") if t2_eval5 else None
    finding_severity = t2_finding5.get("severity") if t2_finding5 else None

    # Key assertion: findings endpoint reads compliance_evaluations.severity = stored at eval time
    # using COALESCE(tr.override_severity, cr.severity), so it IS the effective overridden severity.
    # device detail reads cr.severity (global) — different source.
    passed5 = (override_in_list and finding_severity == "critical")
    record(
        "S5: Severity override",
        passed5,
        f"GET /tenant-rules shows override={override_in_list}. "
        f"device_detail.severity={eval_severity_from_detail!r} (reads compliance_rules.severity = GLOBAL). "
        f"findings.severity={finding_severity!r} (reads compliance_evaluations.severity = EFFECTIVE/overridden). "
        f"DEVIATION: device detail returns global severity, not effective; "
        f"two endpoints disagree when an override is active.",
    )

    # ── Scenario 6: Per-OS master switch ───────────────────────────────────
    print("\n[s6] Per-OS master switch: disable macos")
    st6a, sw_resp = admin("PUT", f"/admin/tenant-platforms/{TENANT_ID}",
                          body={"platform": "macos", "enabled": False})
    save_artifact("s6_platform_disable.json", {"status": st6a, "resp": sw_resp})

    serial6a = "e2e-s6a"
    extra6   = {T2_SIGNAL_KEY: T2_SIGNAL_FAIL}
    ingest_resp6a = ingest(TENANT_ID, BEARER_TOKEN, HMAC_SECRET, serial6a, extra6)
    save_artifact("s6a_ingest.json", ingest_resp6a)

    # When platform is disabled, FetchTenantDevices filters out macOS devices via enabledOSFilter,
    # so wait_for_device (which polls the API list) will timeout. Use psql to wait for
    # device extraction and get the device_id directly.
    device6a = None
    deadline6a = time.time() + EXTRACTOR_MAX_WAIT
    while time.time() < deadline6a:
        row6a = psql_exec(
            f"SELECT id::text FROM devices WHERE serial='{serial6a}' AND tenant_id='{TENANT_ID}'"
        ).strip()
        if row6a:
            device6a = row6a
            break
        time.sleep(2)
    if not device6a:
        raise RuntimeError(f"Device {serial6a} did not appear in DB within {EXTRACTOR_MAX_WAIT}s")

    # Check evaluations via admin/devices endpoint (device is in DB but filtered from list)
    _, raw6a = admin("GET", f"/admin/devices/{device6a}")
    evals6a = raw6a.get("evaluations", [])
    save_artifact("s6a_evals.json", evals6a)

    # IMPORTANT: FetchTenantDevices uses enabledOSFilter: when macos_enabled=false,
    # the SQL filter is "d.os NOT IN ('macOS')" → macOS devices are EXCLUDED from the list.
    # The extractor DOES upsert the device and its data (device/apps/signals), but
    # the admin API hides it. This is a DEVIATION from the spec "device appears in /admin/tenants/{id}/devices".
    _, devices_resp6 = admin("GET", f"/admin/tenants/{TENANT_ID}/devices")
    device6_in_api_list = any(d["id"] == device6a for d in devices_resp6.get("devices", []))
    device6_in_db = bool(device6a)
    save_artifact("s6a_devices.json", {"api_list": devices_resp6, "device_in_db": device6_in_db, "device_in_api_list": device6_in_api_list})

    no_evals6a = len(evals6a) == 0

    # Re-enable macos
    st6b, re_resp = admin("PUT", f"/admin/tenant-platforms/{TENANT_ID}",
                          body={"platform": "macos", "enabled": True})
    save_artifact("s6_platform_enable.json", {"status": st6b, "resp": re_resp})

    serial6b = "e2e-s6b"
    ingest_resp6b = ingest(TENANT_ID, BEARER_TOKEN, HMAC_SECRET, serial6b, extra6)
    save_artifact("s6b_ingest.json", ingest_resp6b)

    # Platform re-enabled → API list now includes macOS devices again
    device6b = wait_for_device(TENANT_ID, serial6b)
    evals6b  = wait_for_evaluations(device6b)
    save_artifact("s6b_evals.json", evals6b)

    has_evals6b = len(evals6b) > 0

    # Device is in DB (extractor ran and upserted) but NOT in API list (filtered by enabledOSFilter).
    # Spec says "device appears in /admin/tenants/{id}/devices" — this is a DEVIATION.
    # Behaviour: extractor upserts device, API hides it via OS filter.
    passed6 = (st6a == 200 and no_evals6a and device6_in_db and
               st6b == 200 and has_evals6b)
    record(
        "S6: Per-OS master switch (macos off → no evals; on → evals)",
        passed6,
        f"disable status={st6a}, no_evals_when_off={no_evals6a}, "
        f"device_in_db={device6_in_db}, device_in_API_list={device6_in_api_list} "
        f"(DEVIATION: spec says device appears in API list, but FetchTenantDevices "
        f"filters macOS devices via enabledOSFilter when macos_enabled=false), "
        f"re-enable status={st6b}, evals_when_on={has_evals6b} ({len(evals6b)} rules)",
    )

    # ── Scenario 7: Global rule kill-switch ───────────────────────────────
    print("\n[s7] Global rule kill-switch")
    sip_rule_id = get_rule_id(TENANT_ID, T1_KILL_KEY)

    # Disable the rule
    psql_exec(f"UPDATE compliance_rules SET enabled=false WHERE rule_key='{T1_KILL_KEY}'")

    serial7 = "e2e-s7"
    extra7  = {T2_SIGNAL_KEY: T2_SIGNAL_FAIL}
    ingest_resp7 = ingest(TENANT_ID, BEARER_TOKEN, HMAC_SECRET, serial7, extra7)
    save_artifact("s7_ingest.json", ingest_resp7)

    device7 = wait_for_device(TENANT_ID, serial7)
    evals7  = wait_for_evaluations(device7)
    save_artifact("s7_evals.json", evals7)

    sip_in_evals7 = any(e.get("rule_key") == T1_KILL_KEY for e in evals7)

    # Restore
    psql_exec(f"UPDATE compliance_rules SET enabled=true WHERE rule_key='{T1_KILL_KEY}'")

    # Verify restored
    verify_row = psql_exec(f"SELECT enabled FROM compliance_rules WHERE rule_key='{T1_KILL_KEY}'")
    restored = verify_row.strip() in ("t", "true", "True", "1")

    passed7 = (not sip_in_evals7) and restored
    record(
        "S7: Global rule kill-switch",
        passed7,
        f"sip in evals (want False)={sip_in_evals7}, restored={restored}, "
        f"restore verify row='{verify_row}'",
    )

    # ── Scenario 8: Audit trails ───────────────────────────────────────────
    print("\n[s8] Audit trails")
    # Query tenant_rule_changes for our T2 rule
    rule_changes_raw = psql_exec(
        f"SELECT change_type, old_enabled, new_enabled FROM tenant_rule_changes "
        f"WHERE tenant_id='{TENANT_ID}' AND rule_id='{T2_RULE_ID}' ORDER BY changed_at"
    )
    save_artifact("s8_rule_changes.txt", rule_changes_raw)

    # Query tenant_platform_changes
    platform_changes_raw = psql_exec(
        f"SELECT platform, old_enabled, new_enabled FROM tenant_platform_changes "
        f"WHERE tenant_id='{TENANT_ID}' ORDER BY changed_at"
    )
    save_artifact("s8_platform_changes.txt", platform_changes_raw)

    # Parse change_types
    change_types = []
    for line in rule_changes_raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if parts:
            change_types.append(parts[0])

    platform_changes = []
    for line in platform_changes_raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if parts and len(parts) >= 3:
            platform_changes.append(tuple(parts[:3]))

    # Expected rule change_types from scenarios 2-5:
    # S2: PUT enabled=True (new row) → "enabled"
    # S3: DELETE → "disabled"
    # S4: PUT enabled=True + suppressed_until=future → "enabled" + "suppressed"
    # S5: PUT enabled=True + override_severity=critical (no suppression change because still suppressed?)
    #     Actually S5: enabled=True, override_severity=critical, no suppression → "unsuppressed" + "severity_overridden"
    expected_types = {"enabled", "disabled", "suppressed", "unsuppressed", "severity_overridden"}
    observed_set   = set(change_types)

    # Platform changes: disable (False) + enable (True) from S6
    platform_has_disable = any(p[2] == "f" or p[2] == "false" for p in platform_changes)
    platform_has_enable  = any((p[2] == "t" or p[2] == "true") for p in platform_changes)

    passed8 = (expected_types.issubset(observed_set) and
               platform_has_disable and platform_has_enable)
    record(
        "S8: Audit trails",
        passed8,
        f"rule change_types observed={sorted(observed_set)}, expected_subset={sorted(expected_types)}, "
        f"platform_disable={platform_has_disable}, platform_enable={platform_has_enable}",
        notes=f"Raw platform_changes: {platform_changes[:5]}",
    )

    # ── Write RESULTS.md ───────────────────────────────────────────────────
    write_results()

    # Summary
    total  = len(results)
    passed = sum(1 for _, m, _, _ in results if m == "PASS")
    failed = total - passed

    print()
    print("=" * 60)
    print(f"DONE: {passed}/{total} PASS  |  {failed} FAIL")
    print(f"Results written to {RESULTS_MD}")
    print("=" * 60)
    return 0 if failed == 0 else 1


def write_results():
    lines = [
        "# T5 Settings-Behaviour Suite Results",
        "",
        f"Run: {datetime.now(timezone.utc).isoformat()}",
        "",
        "| Scenario | Result | Observed Behaviour |",
        "|---|---|---|",
    ]
    for scenario, marker, observed, notes in results:
        obs_short = observed.replace("|", "/").replace("\n", " ")[:300]
        lines.append(f"| {scenario} | **{marker}** | {obs_short} |")

    lines += [
        "",
        "## Key Observations",
        "",
        "### Suppression semantics (S4)",
        "The SQL in `LoadRulesForTenant` includes:",
        "```sql",
        "AND (tr.suppressed_until IS NULL OR tr.suppressed_until < now())",
        "```",
        "This means: a rule is included ONLY when `suppressed_until` is NULL OR already past.",
        "A future `suppressed_until` excludes the rule from the JOIN → rule not evaluated.",
        "So `enabled=true` + `suppressed_until=<future>` → **not evaluated** (suppressed).",
        "",
        "### Severity override surfacing (S5)",
        "The `LoadRulesForTenant` query uses `COALESCE(tr.override_severity, cr.severity)` as",
        "the severity, which is what gets stored in `compliance_evaluations.severity` at ingest",
        "time by the extractor. The findings endpoint (`GET /admin/tenants/{id}/findings`) reads",
        "`compliance_evaluations.severity` — so it returns the **effective (overridden) severity**,",
        "not the global rule severity.",
        "",
        "### Platform-switch behaviour (S6)",
        "When `macos_enabled=false`, `isPlatformEnabled` returns false → extractor skips evaluation",
        "entirely (no `compliance_evaluations` rows written), but still runs `upsertDevice`,",
        "`upsertApps`, `insertComplianceSignals` etc. Device IS in the `devices` DB table.",
        "DEVIATION: `FetchTenantDevices` uses `enabledOSFilter` → SQL adds `d.os NOT IN ('macOS')`",
        "→ macOS devices are EXCLUDED from `GET /admin/tenants/{id}/devices` when macos_enabled=false.",
        "The spec says 'device appears in /admin/tenants/{id}/devices' — this is NOT the actual behaviour.",
        "",
        "### Audit trail change_type values (S8)",
        "Observed `tenant_rule_changes.change_type` values:",
    ]
    for scenario, marker, observed, notes in results:
        if "S8" in scenario:
            lines.append(f"- {observed}")
    lines += [
        "",
        "## Deviations / Findings",
        "",
        "1. **S6: Platform-switch hides macOS devices from API list when disabled**: The spec says",
        "   'device appears in /admin/tenants/{id}/devices'. In reality, `FetchTenantDevices` uses",
        "   `enabledOSFilter` which generates `d.os NOT IN ('macOS')` when `macos_enabled=false`.",
        "   macOS devices are excluded from the API listing while the platform is off.",
        "   The device IS in the `devices` table (extractor ran `upsertDevice`), just hidden from the API.",
        "",
        "2. **S5: device detail returns global severity, not effective (overridden) severity**:",
        "   `GET /admin/devices/{id}` uses `report.Fetch` which joins `compliance_rules.severity`",
        "   (global), ignoring any `override_severity` in `tenant_rules`.",
        "   `GET /admin/tenants/{id}/findings` reads `compliance_evaluations.severity` which IS",
        "   the effective/overridden severity stored at evaluation time.",
        "   Two endpoints disagree when an override is active.",
        "",
    ]

    RESULTS_MD.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    sys.exit(main())
