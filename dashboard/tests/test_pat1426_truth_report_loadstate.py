"""PAT-1426 — port the LoadState "unit definition is gone" guard from
truth.py (PAT-1411) to deploy/truth-report.sh.

Requires a bash 4+ interpreter (the script's `declare -A ENTRY_UNITS`, added
under PAT-1303, needs associative-array support). Production hosts run
Ubuntu 24.04's bash 5.x. macOS ships bash 3.2 at /bin/bash by default, which
does not support `declare -A` at all, so this module resolves a bash 4+
binary at import time (preferring Homebrew's, since that's what's readily
installable on a Mac dev box) rather than hardcoding a path.

The bug (PAT-1411's root cause, reproduced live during PAT-1304's
injected-failure proof): when a `.timer` outlives its paired `.service`,
`systemctl show <service>` keeps reporting ActiveState=inactive and
Result=success/ExecMainStatus=0 carried forward from the last real run
before the unit definition vanished. The old guard in this script only
checked `[ -z "$active_state" ]`, which does NOT catch this — a `not-found`
(or masked/bad-setting/error) unit still has a non-empty ActiveState, so the
script would emit a fresh-looking success observation for a unit whose
definition is gone. PAT-1411 fixed the Python half
(truth.collect_systemd_observation); this file proves the bash half
(deploy/truth-report.sh) got the identical fix, and that the two halves
cannot silently drift apart again (the "drift" test at the bottom).

`bats` is not installed in this environment, so the script is driven
end-to-end as a real subprocess, with `systemctl`/`curl`/`hostname` replaced
by tiny shims placed first on PATH. bash itself IS assumed present (the
script's own shebang).

macOS note: this dev machine's `bash`/`date`/`stat` are the BSD/Darwin
builds, not the GNU builds the script's production host (Ubuntu) has.
`date -u -d '<systemd timestamp>' +FMT` (GNU-only) is therefore also
shimmed here purely so the test suite can run locally; the script's own
`date` invocation is untouched. `stat -c` is avoided entirely by exporting
DASHBOARD_API_KEY directly into the subprocess environment rather than via
the env-file path, which is the one place the script shells out to GNU
`stat -c`.
"""
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import truth  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "truth-report.sh"

VALID_EXIT_TS = "Thu 2026-08-13 23:30:34 UTC"


def _find_bash4() -> str:
    for candidate in ("/opt/homebrew/bin/bash", "/usr/local/bin/bash", "bash"):
        path = candidate if os.path.isabs(candidate) else None
        if path and not os.path.exists(path):
            continue
        try:
            out = subprocess.run(
                [candidate, "-c", 'echo "${BASH_VERSINFO[0]}"'],
                capture_output=True, text=True, timeout=5,
            ).stdout.strip()
            if out and int(out) >= 4:
                return candidate
        except Exception:
            continue
    pytest.skip(
        "no bash 4+ available — deploy/truth-report.sh needs `declare -A` support",
        allow_module_level=True,
    )


BASH4 = _find_bash4()

# The two units api-01's mapping declares (see ENTRY_UNITS in the script).
# Tests use patched-api-01 as the scoped host and only ever configure
# patched-cve-sync.service; patched-backup.service/patched-partitions.service/
# patched-alert-metrics.service are left unconfigured (the fake systemctl
# reports them as not present at all), which the script's pre-existing
# blank-ActiveState guard already skips harmlessly.
TARGET_ENTRY_ID = "api01-cve-sync"
TARGET_UNIT = "patched-cve-sync.service"


def _fake_bin(tmp_path) -> Path:
    """Build a directory of shim executables and return it. Callers prepend
    this to PATH so the shims are found ahead of any real systemctl/curl/
    hostname/date on the machine running the test."""
    bindir = tmp_path / "fakebin"
    bindir.mkdir()

    (bindir / "hostname").write_text(
        "#!/bin/bash\n"
        'echo "${FAKE_HOSTNAME:-patched-api-01}"\n'
    )

    # Real systemctl prints one PROP=VALUE line per requested --property,
    # blank for a property the unit doesn't have. This shim's per-unit
    # output is supplied by the test via an env var named
    # FAKE_UNIT_PROPS_<unit with non-alnum chars -> _>; a unit with no such
    # var produces empty output, matching real systemctl on an unknown unit.
    (bindir / "systemctl").write_text(
        "#!/bin/bash\n"
        'if [ "$1" = "show" ]; then\n'
        '    unit="$2"\n'
        '    var_name="FAKE_UNIT_PROPS_$(printf "%s" "$unit" | tr -c "A-Za-z0-9" "_")"\n'
        '    props="${!var_name:-}"\n'
        '    if [ -n "$props" ]; then\n'
        '        printf "%s\\n" "$props"\n'
        '    fi\n'
        '    exit 0\n'
        "fi\n"
        'exit 1\n'
    )

    # Never hit the real network. Writes a canned JSON body to the -o file
    # and prints the http_code word (200) to stdout, mirroring
    # curl -w '%{http_code}'.
    (bindir / "curl").write_text(
        "#!/bin/bash\n"
        'out_file=""\n'
        'args=("$@")\n'
        'for ((i=0; i<${#args[@]}; i++)); do\n'
        '    if [ "${args[$i]}" = "-o" ]; then\n'
        '        out_file="${args[$((i+1))]}"\n'
        '    fi\n'
        "done\n"
        'if [ -n "$out_file" ]; then\n'
        '    echo \'{"status":"ok"}\' > "$out_file"\n'
        "fi\n"
        'printf "200"\n'
        'exit 0\n'
    )

    # GNU-date shim, test-environment-only — see module docstring.
    (bindir / "date").write_text(
        "#!/bin/bash\n"
        'exec python3 -c "\n'
        "import re, sys\n"
        "args = sys.argv[1:]\n"
        "value = fmt = None\n"
        "for i, a in enumerate(args):\n"
        "    if a == \\\"-d\\\":\n"
        "        value = args[i + 1]\n"
        "    elif a.startswith(\\\"+\\\"):\n"
        "        fmt = a[1:]\n"
        "if value is None or fmt is None:\n"
        "    sys.exit(1)\n"
        "m = re.match(r\\\"^\\\\w{3} (\\\\d{4}-\\\\d{2}-\\\\d{2}) (\\\\d{2}:\\\\d{2}:\\\\d{2}) UTC\\$\\\", value.strip())\n"
        "if not m or fmt != \\\"%Y-%m-%dT%H:%M:%SZ\\\":\n"
        "    sys.exit(1)\n"
        "print(f\\\"{m.group(1)}T{m.group(2)}Z\\\")\n"
        '" "$@"\n'
    )

    for f in bindir.iterdir():
        f.chmod(f.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return bindir


def _run_script(tmp_path, unit_props: str | None, extra_env: dict | None = None):
    bindir = _fake_bin(tmp_path)
    env = dict(os.environ)
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["DASHBOARD_API_KEY"] = "test-bearer-token"
    # Point at a nonexistent env file so the script's source-the-env-file
    # branch (which shells out to GNU `stat -c`) is skipped entirely;
    # DASHBOARD_API_KEY above is picked up directly from the environment.
    env["TRUTH_REPORT_ENV_FILE"] = str(tmp_path / "does-not-exist.env")
    env["TRUTH_REPORT_URL"] = "https://example.invalid/admin/truth/report"
    env["FAKE_HOSTNAME"] = "patched-api-01"
    if unit_props is not None:
        env["FAKE_UNIT_PROPS_patched_cve_sync_service"] = unit_props
    if extra_env:
        env.update(extra_env)

    return subprocess.run(
        [BASH4, str(SCRIPT)],
        env=env, cwd=str(REPO),
        capture_output=True, text=True, timeout=15,
    )


# ─────────────────────────────────────────────────────────────────────────
# Negative case: LoadState says the unit definition is gone -> no observation
# ─────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("load_state", sorted(truth._UNIT_DEFINITION_GONE_LOAD_STATES))
def test_gone_load_state_emits_no_observation(tmp_path, load_state):
    """The exact PAT-1411/PAT-1304 stale-green shape: ActiveState=inactive
    and Result=success carried forward from the unit's last real run, but
    LoadState says the definition is gone. Must NOT be reported."""
    props = (
        f"ActiveState=inactive\n"
        f"LoadState={load_state}\n"
        f"Result=success\n"
        f"ExecMainStatus=0\n"
        f"ExecMainStartTimestamp=Thu 2026-08-13 23:20:00 UTC\n"
        f"ExecMainExitTimestamp={VALID_EXIT_TS}\n"
    )
    result = _run_script(tmp_path, props)

    # No REPORTED-observation line (the "entry (unit): success=..." shape
    # that would go into the JSON payload) for the target unit — only its
    # skip line, asserted separately below, may mention it.
    assert f"{TARGET_ENTRY_ID} ({TARGET_UNIT}): success=" not in result.stdout, result.stdout
    assert "success=true" not in result.stdout
    assert f"LoadState={load_state}" in result.stdout
    assert "unit definition is gone" in result.stdout
    assert "absence renders amber, which is the honest state" in result.stdout
    # No units configured -> nothing to report -> clean exit, no network hit.
    assert result.returncode == 0, result.stderr
    assert "Nothing to report" in result.stdout


# ─────────────────────────────────────────────────────────────────────────
# Positive control: without this, a script that emits nothing for every
# input would pass the negative tests above for the wrong reason.
# ─────────────────────────────────────────────────────────────────────────

def test_loaded_unit_with_completed_run_still_reports(tmp_path):
    props = (
        f"ActiveState=inactive\n"
        f"LoadState=loaded\n"
        f"Result=success\n"
        f"ExecMainStatus=0\n"
        f"ExecMainStartTimestamp=Thu 2026-08-13 23:20:00 UTC\n"
        f"ExecMainExitTimestamp={VALID_EXIT_TS}\n"
    )
    result = _run_script(tmp_path, props)

    assert result.returncode == 0, result.stderr
    assert f"{TARGET_ENTRY_ID} ({TARGET_UNIT}): success=true" in result.stdout, result.stdout
    assert "Reporting 1 observation(s)" in result.stdout
    assert "Reported." in result.stdout


# ─────────────────────────────────────────────────────────────────────────
# Drift test: the ticket's real requirement. This must fail if someone edits
# truth.py's frozenset or the script's case-statement list without updating
# the other.
# ─────────────────────────────────────────────────────────────────────────

def test_script_load_state_list_matches_truth_py_frozenset():
    text = SCRIPT.read_text()
    m = re.search(r'case "\$load_state" in\s*\n\s*([A-Za-z0-9_|-]+)\)', text)
    assert m, "could not find the `case \"$load_state\" in ...)` guard in deploy/truth-report.sh"
    script_states = frozenset(m.group(1).split("|"))

    assert script_states == truth._UNIT_DEFINITION_GONE_LOAD_STATES, (
        "deploy/truth-report.sh's LoadState skip-list has drifted from "
        "truth._UNIT_DEFINITION_GONE_LOAD_STATES — PAT-1411 and PAT-1426 "
        "must name the same set on both sides of this feature."
    )
