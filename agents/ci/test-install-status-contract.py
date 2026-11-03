#!/usr/bin/env python3
"""Validate the platform-neutral Self Service install outcome contract."""

import json
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "contracts/install-status.schema.json").read_text())


def status(outcome: str, **extra: str) -> dict:
    row = {
        "package_id": "example",
        "package_source": "vendor",
        "display_name": "Example",
        "outcome": outcome,
        "recorded_at": "2026-08-15T12:00:01Z",
        **extra,
    }
    return {
        "schema_version": 1,
        "generated_at": "2026-08-15T12:00:02Z",
        "last_run": {
            "started_at": "2026-08-15T12:00:00Z",
            "finished_at": "2026-08-15T12:00:02Z",
        },
        "installs": [row],
    }


def rejected(document: dict) -> None:
    try:
        jsonschema.validate(document, SCHEMA, format_checker=jsonschema.FormatChecker())
    except jsonschema.ValidationError:
        return
    raise AssertionError(f"invalid install status was accepted: {document}")


for valid in (
    status("success"),
    status("already_installed"),
    status("failed", failure_kind="install_failed", error_message="installer exited 1"),
    status("failed", failure_kind="verification_blocked", error_message="signature mismatch"),
    status(
        "authority_refused",
        failure_kind="execution_authority_refused",
        error_message="signed execution authority refused",
    ),
):
    jsonschema.validate(valid, SCHEMA, format_checker=jsonschema.FormatChecker())

missing_kind = status("failed", error_message="failed")
rejected(missing_kind)
success_with_error = status("success", error_message="must not leak into success")
rejected(success_with_error)
invented_kind = status("failed", failure_kind="network", error_message="failed")
rejected(invented_kind)
refusal_without_kind = status("authority_refused", error_message="refused")
rejected(refusal_without_kind)
refusal_with_retry_kind = status(
    "authority_refused", failure_kind="install_failed", error_message="refused"
)
rejected(refusal_with_retry_kind)

mac_source = (ROOT / "endpoint/patched-install.sh").read_text()
windows_contract = (ROOT / "windows/src/Shared/Installation/InstallContracts.cs").read_text()
for token in ("row['failure_kind'] = g('PATCHED_R_FAILURE_KIND')", "'recorded_at':    g('PATCHED_R_TS')"):
    assert token in mac_source, f"macOS producer no longer writes {token}"
for token in ('JsonPropertyName("failure_kind")', 'JsonPropertyName("recorded_at")'):
    assert token in windows_contract, f"Windows producer contract no longer writes {token}"

assert 'outcome="authority_refused"' in mac_source
assert 'failure_kind="execution_authority_refused"' in mac_source

assert "ExecutionAuthorityRefused" in windows_contract

# PAT-1621: the Windows Self Service UI (the only Windows reader/writer of this
# contract's "not currently authorised" presentation and the pending-install
# invention it must not do) was retired. PAT-1618 subsequently deleted
# menubar/PatchedUpdater/InstallStatus.swift, the macOS Self Service catalogue's
# presentation of this same contract -- it was never adopted by the surviving
# PatchedUpdater agent UI, which has no install-status presentation surface of
# its own. The platform-neutral contract above is still validated; there is no
# remaining platform presentation layer to check here on either side.

print("install-status contract: valid outcomes accepted; invalid/drift cases rejected")
