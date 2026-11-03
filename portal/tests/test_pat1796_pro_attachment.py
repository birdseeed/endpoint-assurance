"""PAT-1796: bounded, tri-state Ubuntu Pro attachment facts.

The maintenance emitter is driven through PATH shims so these tests exercise
its real shell and embedded JSON parsing without querying the development
machine's package, systemd, or Ubuntu Pro state.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "patched-maintenance-facts.sh"


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _run_emitter(
    tmp_path: Path, *, pro_output: str = "", timeout_exit: int = 0
) -> tuple[dict, str]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_executable(
        fake_bin / "id",
        "#!/bin/bash\n"
        'if [ "$1" = "-u" ]; then echo 0; else exec /usr/bin/id "$@"; fi\n',
    )
    _write_executable(
        fake_bin / "timeout",
        "#!/bin/bash\n"
        'printf "%s" "$*" > "$FAKE_TIMEOUT_ARGS_FILE"\n'
        'if [ "${FAKE_TIMEOUT_EXIT:-0}" -ne 0 ]; then exit "$FAKE_TIMEOUT_EXIT"; fi\n'
        'shift\n'
        'exec "$@"\n',
    )
    _write_executable(
        fake_bin / "pro",
        "#!/bin/bash\n"
        'printf "%s" "$FAKE_PRO_OUTPUT"\n',
    )

    out_file = tmp_path / "maintenance.json"
    timeout_args = tmp_path / "timeout-args"
    config_root = tmp_path / "etc"
    config_root.mkdir()
    env = dict(os.environ)
    env.update(
        {
            "PATH": f"{fake_bin}:{env['PATH']}",
            "OUT_FILE": str(out_file),
            "CONFIG_BACKUP_ROOT": str(config_root),
            "FAKE_TIMEOUT_ARGS_FILE": str(timeout_args),
            "FAKE_TIMEOUT_EXIT": str(timeout_exit),
            "FAKE_PRO_OUTPUT": pro_output,
        }
    )
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    return (
        json.loads(out_file.read_text(encoding="utf-8")),
        timeout_args.read_text(encoding="utf-8"),
    )


def _response(
    *, attached: object, contract_valid: object, result: str = "success", errors: object = ()
) -> str:
    return json.dumps(
        {
            "result": result,
            "errors": list(errors) if isinstance(errors, tuple) else errors,
            "data": {
                "attributes": {
                    "is_attached": attached,
                    "is_attached_and_contract_valid": contract_valid,
                }
            },
        }
    )


def test_emitter_uses_bounded_purpose_specific_pro_api_for_attached_contract(tmp_path):
    facts, timeout_args = _run_emitter(
        tmp_path,
        pro_output=_response(attached=True, contract_valid=True),
    )

    assert facts["pro_attached"] is True
    assert facts["esm_updates"] is not None
    assert timeout_args == "10s pro api u.pro.status.is_attached.v1"


def test_emitter_reports_genuinely_detached_only_after_well_formed_success(tmp_path):
    facts, _ = _run_emitter(
        tmp_path,
        pro_output=_response(attached=False, contract_valid=False),
    )

    assert facts["pro_attached"] is False
    assert facts["esm_updates"] is None


@pytest.mark.parametrize("timeout_exit", [1, 124], ids=["non-zero", "timeout"])
def test_emitter_preserves_unknown_for_pro_command_failure(tmp_path, timeout_exit):
    facts, _ = _run_emitter(tmp_path, timeout_exit=timeout_exit)

    assert facts["pro_attached"] is None
    assert facts["esm_updates"] is None


def test_emitter_preserves_unknown_for_malformed_pro_json(tmp_path):
    facts, _ = _run_emitter(tmp_path, pro_output="not-json")

    assert facts["pro_attached"] is None
    assert facts["esm_updates"] is None


def test_emitter_preserves_unknown_for_pro_api_errors(tmp_path):
    facts, _ = _run_emitter(
        tmp_path,
        pro_output=_response(
            attached=False, contract_valid=False, result="failure", errors=("bad",)
        ),
    )

    assert facts["pro_attached"] is None
    assert facts["esm_updates"] is None


@pytest.mark.parametrize(
    "attached, contract_valid",
    [(True, False), (True, "true"), ("false", False)],
    ids=["invalid-contract", "invalid-contract-type", "invalid-attached-type"],
)
def test_emitter_preserves_unknown_for_invalid_attachment_or_contract(
    tmp_path, attached, contract_valid
):
    facts, _ = _run_emitter(
        tmp_path,
        pro_output=_response(attached=attached, contract_valid=contract_valid),
    )

    assert facts["pro_attached"] is None
    assert facts["esm_updates"] is None


def test_emitter_no_longer_uses_unbounded_full_pro_status():
    text = SCRIPT.read_text(encoding="utf-8")

    assert "timeout 10s pro api u.pro.status.is_attached.v1" in text
    assert "pro status --format=json" not in text
