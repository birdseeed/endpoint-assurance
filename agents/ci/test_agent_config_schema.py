#!/usr/bin/env python3
"""Regression coverage for the signed agent-config inner-payload schema."""

from copy import deepcopy
import json
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "contracts/agent-config.schema.json").read_text())
jsonschema.Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = jsonschema.Draft202012Validator(
    SCHEMA,
    format_checker=jsonschema.FormatChecker(),
)


# This is the inner document after the agent has verified the signed envelope.
# Keep retained assurance, self-update/ring and decommission fields here so the
# gate cannot narrow the production contract while containing app execution.
PRODUCTION_SIGNED_PAYLOAD = {
    "tenant_id": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
    "config_version": 1481,
    "issued_at": "2026-09-08T12:00:00Z",
    "tier": "assurance",
    "scan_cadence": "daily",
    "catalog_scope": "all",
    "ring": 3,
    "ring_promotions": None,
    "ring_promotions_scoped": {"macos": None, "windows": None},
    "legacy_app_execution_enabled": False,
    "app_control_authority": "report",
    "pinned_version": "2.4.1",
    "update_channel": "stable",
    "app_control": {
        "app_allowlist": [],
        "approved_admins": [],
        "enabled": False,
    },
    "os_update_policy": {
        "target_os": None,
        "minimum_age_days": 7,
        "grace_days": 14,
        "deferral_budget": 5,
        "blocking_window_days": 3,
        "exploited_overrides_age": True,
        "deadline": None,
    },
    "per_app_patch": None,
    "decommission": {
        "mode": "none",
        "expires_at": None,
        "purge": False,
        "reason": None,
    },
}


def rejected(document: dict, name: str) -> None:
    errors = list(VALIDATOR.iter_errors(document))
    assert errors, f"{name}: invalid agent config was accepted"


VALIDATOR.validate(PRODUCTION_SIGNED_PAYLOAD)

for source in ("tenant", "device_override", None):
    selection = deepcopy(PRODUCTION_SIGNED_PAYLOAD)
    selection["update_channel_source"] = source
    selection["device_channel_overrides"] = {"00000000-0000-0000-0000-000000002005": "beta"}
    VALIDATOR.validate(selection)
for value in ("stable", "preview", False):
    selection = deepcopy(PRODUCTION_SIGNED_PAYLOAD)
    selection["device_channel_overrides"] = {"00000000-0000-0000-0000-000000002005": value}
    rejected(selection, "override must be beta only")
selection = deepcopy(PRODUCTION_SIGNED_PAYLOAD)
selection["update_channel_source"] = "guessed"
rejected(selection, "unknown channel source")

# The field deliberately remains optional for backward-compatible signed
# payloads. Its schema default is false, and each executor treats absence as
# deny. Null is deliberately schema-valid as an explicit revocation: accepting
# it means a signed config can clear a previously true grant, while each agent
# still maps it to false. Only exact true enables; non-boolean values reject.
absent_gate = deepcopy(PRODUCTION_SIGNED_PAYLOAD)
del absent_gate["legacy_app_execution_enabled"]
VALIDATOR.validate(absent_gate)

for value in (None, False, True):
    boolean_gate = deepcopy(PRODUCTION_SIGNED_PAYLOAD)
    boolean_gate["legacy_app_execution_enabled"] = value
    VALIDATOR.validate(boolean_gate)

for value in ("false", 0, {}, []):
    malformed_gate = deepcopy(PRODUCTION_SIGNED_PAYLOAD)
    malformed_gate["legacy_app_execution_enabled"] = value
    rejected(malformed_gate, f"legacy_app_execution_enabled={value!r}")

# App Control authority is deliberately separate from the projected package
# tier. The schema carries the canonical signed vocabulary; consumers map an
# absent/null/malformed/unknown value to report before any actuation.
for value in ("report", "block", "enforce", None):
    authority = deepcopy(PRODUCTION_SIGNED_PAYLOAD)
    authority["app_control_authority"] = value
    VALIDATOR.validate(authority)

for value in ("REPORT", "unknown", False, 1, {}, []):
    authority = deepcopy(PRODUCTION_SIGNED_PAYLOAD)
    authority["app_control_authority"] = value
    rejected(authority, f"app_control_authority={value!r}")

for scoped_policy in (
    {"linux": None},
    {"macos": {"Patched": {"approval": "nobody"}}},
    {"windows": {"Patched": {"approval": "up_to_ring", "approved_ring": 4, "version": "1.2.3"}}},
):
    malformed_scoped = deepcopy(PRODUCTION_SIGNED_PAYLOAD)
    malformed_scoped["ring_promotions_scoped"] = scoped_policy
    rejected(malformed_scoped, f"ring_promotions_scoped={scoped_policy!r}")

print(
    "agent-config schema: optional/default-false legacy gate accepts null or booleans; "
    "only exact true enables and malformed gates/scoped policies reject"
)
