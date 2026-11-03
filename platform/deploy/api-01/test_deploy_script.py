from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import textwrap
import time
import unittest
from datetime import datetime, timezone

from deploy_test_support import PARK_HELPER
import schema_drift as sd
import test_schema_drift_check as drift_tests


DEPLOY_SCRIPT = Path(__file__).with_name("deploy.sh")
BUILD_SHA = "a" * 40
SCHEMA_DRIFT_ARTEFACTS = (
    "SCHEMA_FINGERPRINT_JOURNAL", "schema_drift.py", "schema_fingerprint.sql",
    "schema-drift-check.sh", "schema-drift-allowlist.txt",
)
# PAT-2062: a stand-in for schema-drift-check.sh, staged and manifest-bound like
# the real one, so deploy.sh's wiring is tested for every exit the check has.
# FAKE_DRIFT_HANG makes it hang, to exercise deploy.sh's wall-clock timeout.
# It records that it ran, the URL it was handed, its arguments and PGOPTIONS.
SCHEMA_DRIFT_STUB = """#!/usr/bin/env bash
set -euo pipefail
printf '%s' "${DATABASE_URL:-}" > "$FAKE_DRIFT_SEEN_URL"
printf '%s\\n' "$*" "${PGOPTIONS:-}" > "$FAKE_DRIFT_ARGS"
if [[ "${FAKE_DRIFT_HANG:-0}" == "1" ]]; then
  exec sleep 60
fi
if [[ "${FAKE_DRIFT_LEAK:-0}" == "1" ]]; then
  echo "psql: error: connection to $DATABASE_URL failed"
fi
printf '%s\\n' "${FAKE_DRIFT_OUTPUT:-OK: live schema matches the migrations}"
exit "${FAKE_DRIFT_RC:-0}"
"""
FAKE_TIMEOUT = """#!/usr/bin/env python3
import os, signal, subprocess, sys
args = sys.argv[1:]
if args and args[0].startswith("--kill-after="):
    args = args[1:]
seconds, cmd = float(args[0]), args[1:]
proc = subprocess.Popen(cmd, start_new_session=True)
try:
    sys.exit(proc.wait(timeout=seconds))
except subprocess.TimeoutExpired:
    os.killpg(proc.pid, signal.SIGKILL)
    proc.wait()
    sys.exit(124)
"""


class DeployScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.staging = self.root / "staging"
        self.staging.mkdir()
        (self.staging / "migrations").mkdir()
        (self.staging / "migrations/0105_test_migration.sql").write_text("SELECT 1;\n", encoding="utf-8")
        self.api = self.root / "live/patched-api"
        self.extractor = self.root / "live/patched-extractor"
        self.cve_sync = self.root / "live/patched-cve-sync"
        self.receipt = self.root / "live/DEPLOYED_BINARIES"
        self.api.parent.mkdir()
        for path, content in (
            (self.api, b"old-api"),
            (self.extractor, b"old-extractor"),
            (self.cve_sync, b"old-cve-sync"),
        ):
            path.write_bytes(content)
        self.receipt.write_text("DEPLOYED_SHA=old\n", encoding="utf-8")
        for name, content in (
            ("patched-api", b"new-api"),
            ("patched-extractor", b"new-extractor"),
            ("patched-cve-sync", b"new-cve-sync"),
        ):
            (self.staging / name).write_bytes(content)
        hardening_guard = self.staging / "verify-systemd-hardening-floor.sh"
        hardening_guard.write_text(
            "#!/usr/bin/env bash\nexit \"${FAKE_HARDENING_GUARD_RC:-0}\"\n",
            encoding="utf-8",
        )
        hardening_guard.chmod(0o755)
        for name in SCHEMA_DRIFT_ARTEFACTS:
            (self.staging / name).write_text(f"stub {name}\n", encoding="utf-8")
        (self.staging / "schema-drift-check.sh").write_text(SCHEMA_DRIFT_STUB, encoding="utf-8")
        self.drift_seen_url = self.root / "drift-seen-url"
        self.drift_args = self.root / "drift-args"
        self._write_manifest()
        self.env_file = self.root / "api.env"
        self.env_file.write_text("DATABASE_URL=postgres://test\n", encoding="utf-8")
        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()
        self.systemctl_log = self.root / "systemctl.log"
        self.psql_log = self.root / "psql.log"
        (self.root / "psql-exists.count").write_text("0\n", encoding="utf-8")
        self.timer_state = self.root / "timer.state"
        self.timer_state.write_text("running\n", encoding="utf-8")
        self.show_count = self.root / "show.count"
        self.show_count.write_text("0\n", encoding="utf-8")
        self._write_fake("chown", "exit 0")
        self._write_fake(
            "install",
            """
            destination="${!#}"
            mkdir -p "$destination"
            chmod 0700 "$destination"
            """,
        )
        self._write_fake(
            "stat",
            """
            target="${!#}"
            if [[ "$target" == *rollback-sources ]]; then printf 'root:root 700\\n'
            elif [[ "$target" == *rollback-sources/* ]]; then printf 'root:root 600\\n'
            else printf '%s\\n' "${FAKE_STAT_OUTPUT:-root:root 755}"
            fi
            """,
        )
        self._write_fake(
            "cp",
            """
            source="${@: -2:1}"
            destination="${!#}"
            if [[ "$source" == *.bak-* && ( "$destination" == "$FAKE_API_BIN" || "$destination" == "$FAKE_EXTRACTOR_BIN" || "$destination" == "$FAKE_CVE_SYNC_BIN" ) ]]; then
              echo 'simulated ETXTBSY: direct overwrite of running executable' >&2
              exit 1
            fi
            exec /bin/cp "$@"
            """,
        )
        self._write_fake(
            "mv",
            """
            source="${@: -2:1}"
            destination="${!#}"
            if [[ "${FAKE_MV_FAIL_CVE:-0}" == "1" && "$source" == *.new && "$destination" == "$FAKE_CVE_SYNC_BIN" ]]; then
              exit 1
            fi
            if [[ "${FAKE_MV_FAIL_ROLLBACK:-0}" == "1" && "$source" == *.rollback-new && "$destination" == "$FAKE_API_BIN" ]]; then
              exit 1
            fi
            exec /bin/mv "$@"
            """,
        )
        self._write_fake(
            "psql",
            """
            # PAT-2062: the real drift check's psql calls (schema_drift.py always
            # passes -X first) go to a real scratch database when one is given.
            if [[ -n "${FAKE_PSQL_REAL_BIN:-}" && "${1:-}" == "-X" ]]; then
              exec "$FAKE_PSQL_REAL_BIN" "$@"
            fi
            [[ "${FAKE_PSQL_SLEEP:-0}" == "1" ]] && park_arm
            printf '%s\\n' "$*" >> "$FAKE_PSQL_LOG"
            printf '%s\\n' "${PGDATABASE:-}" >> "$FAKE_PSQL_DATABASE_LOG"
            [[ "${FAKE_PSQL_SLEEP:-0}" == "1" ]] && park_block 30
            if [[ "$*" == *" -f "* && "${FAKE_MIGRATION_FAIL:-0}" == "1" ]]; then
              echo 'simulated migration failure' >&2
              exit 1
            fi
            if [[ "$*" == *"SELECT EXISTS"* ]]; then
              exists_count="$(cat "$FAKE_PSQL_EXISTS_COUNT")"
              exists_count=$((exists_count + 1))
              printf '%s\n' "$exists_count" > "$FAKE_PSQL_EXISTS_COUNT"
              if [[ "${FAKE_POSTINSTALL_PSQL_FAIL:-0}" == "1" && "$exists_count" -ge 2 ]]; then
                echo 'simulated post-install psql failure' >&2
                exit 1
              fi
            fi
            case "$*" in
              *"SELECT version FROM schema_migrations"*)
                if [[ "${FAKE_MIGRATION_APPLIED:-1}" == "1" ]]; then echo 0105_test_migration; fi
                ;;
              *"SELECT EXISTS"*) echo "${FAKE_MIGRATION_HEAD_PRESENT:-t}" ;;
              *to_regclass*) printf 'device_agent_health\\n' ;;
              *) printf '' ;;
            esac
            """,
        )
        self._write_fake(
            "curl",
            """
            if [[ "${FAKE_CORRUPT_BACKUP:-0}" == "1" && "${FAKE_CURL_STATUS:-200}" != "200" ]]; then
              backup="$(find "$FAKE_BACKUP_DIR" -name 'patched-api.bak-*' -print -quit)"
              [[ -z "$backup" ]] || echo -n tamper >> "$backup"
            fi
            printf '%s' "${FAKE_CURL_STATUS:-200}"
            """,
        )
        self._write_fake(
            "systemctl",
            """
            printf '%s\\n' "$*" >> "$FAKE_SYSTEMCTL_LOG"
            command="$1"
            unit="${!#}"
            case "$command" in
              is-enabled)
                [[ "$unit" == "patched-cve-sync.timer" && "${FAKE_TIMER_ENABLED:-1}" != "1" ]] && exit 1
                exit 0
                ;;
              is-active)
                if [[ "$unit" == "patched-cve-sync.timer" ]]; then
                  [[ "${FAKE_TIMER_ACTIVE:-1}" == "1" && "$(cat "$FAKE_TIMER_STATE")" == "running" ]]
                  exit
                fi
                exit 0
                ;;
              show)
                case "$*" in
                  *User*WorkingDirectory*ProtectSystem*)
                    unit="$2"
                    working="/opt/patched-api"
                    [[ "$unit" == "patched-extractor.service" ]] && working="/opt/patched-extractor"
                    user=patched; protect=strict; writes="/var/log/patched"
                    [[ "${FAKE_UNIT_CONTRACT:-valid}" == "user" ]] && user=root
                    [[ "${FAKE_UNIT_CONTRACT:-valid}" == "working" ]] && working=/opt/wrong
                    [[ "${FAKE_UNIT_CONTRACT:-valid}" == "write" ]] && writes=/opt/patched-api
                    if [[ "$unit" == "patched-cve-sync.service" ]]; then
                      [[ "${FAKE_CVE_UNIT_CONTRACT:-valid}" == "user" ]] && user=root
                      [[ "${FAKE_CVE_UNIT_CONTRACT:-valid}" == "working" ]] && working=/opt/wrong
                      [[ "${FAKE_CVE_UNIT_CONTRACT:-valid}" == "write" ]] && writes=/opt/patched-api
                    fi
                    printf 'User=%s\\nWorkingDirectory=%s\\nProtectSystem=%s\\nReadWritePaths=%s\\nReadWriteDirectories=\\n' "$user" "$working" "$protect" "$writes"
                    ;;
                  *ActiveState*SubState*)
                    state="${FAKE_SERVICE_STATE:-inactive/dead}"
                    if [[ -n "${FAKE_SERVICE_STATE_AFTER_STOP:-}" && "$(cat "$FAKE_TIMER_STATE")" == "stopped" ]]; then
                      state="$FAKE_SERVICE_STATE_AFTER_STOP"
                    fi
                    printf 'ActiveState=%s\\nSubState=%s\\n' "${state%/*}" "${state#*/}"
                    ;;
                  *LoadState*) printf '%s\\n' "${FAKE_LOAD_STATE:-loaded}" ;;
                  *NextElapseUSecRealtime*) printf '%s\\n' "$FAKE_NEXT_TRIGGER_OUTPUT" ;;
                  *ExecStart*)
                    if [[ -n "${FAKE_EXEC_START_RAW:-}" ]]; then
                      printf '%s\\n' "$FAKE_EXEC_START_RAW"
                    else
                      printf '{ path=%s ; argv[]=%s ; }\\n' "${FAKE_EXEC_START:-$FAKE_CVE_SYNC_BIN}" "${FAKE_EXEC_START:-$FAKE_CVE_SYNC_BIN}"
                    fi
                    ;;
                  *InvocationID*)
                    count="$(cat "$FAKE_SHOW_COUNT")"
                    count=$((count + 1))
                    printf '%s\\n' "$count" > "$FAKE_SHOW_COUNT"
                    if [[ "${FAKE_INVOCATION_EMPTY:-0}" == "1" && "${FAKE_INVOCATION_CHANGE:-0}" == "1" && "$count" -gt 1 ]]; then
                      printf 'deploy-started-invocation-id\\n'
                    elif [[ "${FAKE_INVOCATION_EMPTY:-0}" == "1" ]]; then
                      printf ''
                    elif [[ "${FAKE_INVOCATION_AFTER_EMPTY:-0}" == "1" && "$count" -gt 1 ]]; then
                      printf ''
                    elif [[ "${FAKE_INVOCATION_CHANGE:-0}" == "1" && "$count" -gt 1 ]]; then
                      printf 'changed-invocation-id\\n'
                    else
                      printf 'stable-invocation-id\\n'
                    fi
                    ;;
                esac
                ;;
              stop)
                [[ "$unit" == "patched-cve-sync.timer" ]] && printf 'stopped\\n' > "$FAKE_TIMER_STATE"
                ;;
              start)
                if [[ "$unit" == "patched-cve-sync.timer" && "${FAKE_TIMER_RESTORE_SLEEP:-0}" == "1" && ! -f "$FAKE_TIMER_RESTORE_MARKER" ]]; then
                  park_arm
                  : > "$FAKE_TIMER_RESTORE_MARKER"
                  park_block 2
                fi
                [[ "$unit" == "patched-cve-sync.timer" ]] && printf 'running\\n' > "$FAKE_TIMER_STATE"
                ;;
              restart)
                if [[ "${FAKE_RESTART_SLEEP:-0}" == "1" && "$*" == *patched-api.service* && ! -f "$FAKE_RESTART_MARKER" ]]; then
                  park_arm
                  : > "$FAKE_RESTART_MARKER"
                  park_block 30
                fi
                exit 0
                ;;
              list-timers)
                [[ "${FAKE_REPORTING_FAIL:-0}" == "1" ]] && exit 1
                printf 'NEXT LEFT LAST PASSED UNIT ACTIVATES\\n'
                ;;
              *) exit 0 ;;
            esac
            """,
        )
        self._write_fake("busctl", "printf '%s\\n' \"$FAKE_NEXT_TRIGGER_RAW\"")
        if shutil.which("timeout") is None:
            # macOS has no coreutils timeout; CI and the box use the real one.
            # Same contract: [--kill-after=N] SECONDS CMD..., group kill, 124.
            fake_timeout = self.fake_bin / "timeout"
            fake_timeout.write_text(FAKE_TIMEOUT, encoding="utf-8")
            fake_timeout.chmod(0o755)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_manifest(self, *, api_content: bytes = b"new-api", schema_drift: bool = True) -> None:
        entries = (
            ("patched-api", api_content),
            ("patched-extractor", b"new-extractor"),
            ("patched-cve-sync", b"new-cve-sync"),
        )
        lines = [f"GITHUB_SHA={BUILD_SHA}", "MIGRATION_HEAD=0105_test_migration"]
        lines.extend(f"{hashlib.sha256(content).hexdigest()}  {name}" for name, content in entries)
        migration = self.staging / "migrations/0105_test_migration.sql"
        lines.append(f"{hashlib.sha256(migration.read_bytes()).hexdigest()}  migration:{migration.name}")
        if schema_drift:
            lines.extend(
                f"{hashlib.sha256((self.staging / name).read_bytes()).hexdigest()}  schema-drift:{name}"
                for name in SCHEMA_DRIFT_ARTEFACTS
            )
        (self.staging / "BINARY_MANIFEST").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Every fake gets the park helper. The helper and the measurements behind
    # each of its three properties live in deploy_test_support, shared with
    # test_emergency_api_only.py so the two harnesses cannot drift on how they
    # park a fake.
    def _write_fake(self, name: str, body: str) -> None:
        path = self.fake_bin / name
        path.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n" + PARK_HELPER + textwrap.dedent(body),
            encoding="utf-8",
        )
        path.chmod(0o755)

    def _run(
        self,
        *,
        curl_status: str = "200",
        mv_fail_cve: bool = False,
        mv_fail_rollback: bool = False,
        timer_enabled: bool = True,
        timer_active: bool = True,
        service_state: str = "inactive/dead",
        service_state_after_stop: str | None = None,
        invocation_change: bool = False,
        invocation_empty: bool = False,
        invocation_after_empty: bool = False,
        load_state: str = "loaded",
        exec_start: str | None = None,
        exec_start_raw: str | None = None,
        migration_fail: bool = False,
        next_trigger_seconds: int = 3600,
        next_trigger_output: str | None = None,
        stat_output: str = "root:root 755",
        reporting_fail: bool = False,
        signal_number: int | None = None,
        signal_after_swap: bool = False,
        unit_contract: str = "valid",
        cve_unit_contract: str = "valid",
        migration_applied: bool = True,
        migration_head_present: bool = True,
        corrupt_backup: bool = False,
        postinstall_psql_fail: bool = False,
        signal_during_timer_restore: bool = False,
        staging_dir: Path | None = None,
        hardening_guard_rc: int = 0,
        script: Path | None = None,
        schema_drift_enforce: str | None = None,
        drift_rc: int = 0,
        drift_output: str | None = None,
        drift_leak: bool = False,
        drift_hang: bool = False,
        drift_timeout_seconds: int | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        trigger_output = next_trigger_output or f"t {int(datetime.now(timezone.utc).timestamp() + next_trigger_seconds) * 1_000_000}"
        env.update(
            {
                "PATH": f"{self.fake_bin}:{env['PATH']}",
                "PATCHED_DEPLOY_TEST_MODE": "1",
                "PATCHED_DEPLOY_STAGING_DIR": str(staging_dir or self.staging),
                "PATCHED_API_BIN": str(self.api),
                "PATCHED_EXTRACTOR_BIN": str(self.extractor),
                "PATCHED_CVE_SYNC_BIN": str(self.cve_sync),
                "PATCHED_DEPLOY_RECEIPT": str(self.receipt),
                "PATCHED_API_ENV_FILE": str(self.env_file),
                "PATCHED_DEPLOY_SMOKE_DELAY_SECONDS": "0",
                "PATCHED_DEPLOY_KEEP_STAGING": "1",
                "PATCHED_BUSCTL_BIN": str(self.fake_bin / "busctl"),
                "FAKE_CURL_STATUS": curl_status,
                "FAKE_HARDENING_GUARD_RC": str(hardening_guard_rc),
                "FAKE_MV_FAIL_CVE": "1" if mv_fail_cve else "0",
                "FAKE_MV_FAIL_ROLLBACK": "1" if mv_fail_rollback else "0",
                "FAKE_TIMER_ENABLED": "1" if timer_enabled else "0",
                "FAKE_TIMER_ACTIVE": "1" if timer_active else "0",
                "FAKE_SERVICE_STATE": service_state,
                "FAKE_SERVICE_STATE_AFTER_STOP": service_state_after_stop or "",
                "FAKE_INVOCATION_CHANGE": "1" if invocation_change else "0",
                "FAKE_INVOCATION_EMPTY": "1" if invocation_empty else "0",
                "FAKE_INVOCATION_AFTER_EMPTY": "1" if invocation_after_empty else "0",
                "FAKE_LOAD_STATE": load_state,
                "FAKE_EXEC_START": exec_start or str(self.cve_sync),
                "FAKE_EXEC_START_RAW": exec_start_raw or "",
                "FAKE_NEXT_TRIGGER_RAW": trigger_output,
                "FAKE_STAT_OUTPUT": stat_output,
                "FAKE_REPORTING_FAIL": "1" if reporting_fail else "0",
                "FAKE_PSQL_SLEEP": "1" if signal_number is not None and not signal_after_swap and not signal_during_timer_restore else "0",
                "FAKE_MIGRATION_FAIL": "1" if migration_fail else "0",
                "FAKE_MIGRATION_APPLIED": "1" if migration_applied else "0",
                "FAKE_MIGRATION_HEAD_PRESENT": "t" if migration_head_present else "f",
                "FAKE_PSQL_LOG": str(self.psql_log),
                "FAKE_PSQL_DATABASE_LOG": str(self.root / "psql-database.log"),
                # Only one fake may park the script per run. Parking the api
                # restart as well would stop deploy.sh ever reaching the timer
                # restore the signal_during_timer_restore case exists to cover.
                "FAKE_RESTART_SLEEP": "1" if signal_after_swap and not signal_during_timer_restore else "0",
                "FAKE_RESTART_MARKER": str(self.root / "restart.marker"),
                "FAKE_UNIT_CONTRACT": unit_contract,
                "FAKE_CVE_UNIT_CONTRACT": cve_unit_contract,
                "FAKE_CORRUPT_BACKUP": "1" if corrupt_backup else "0",
                "FAKE_POSTINSTALL_PSQL_FAIL": "1" if postinstall_psql_fail else "0",
                "FAKE_PSQL_EXISTS_COUNT": str(self.root / "psql-exists.count"),
                "FAKE_BACKUP_DIR": str(self.receipt) + ".rollback-sources",
                "FAKE_TIMER_RESTORE_SLEEP": "1" if signal_during_timer_restore else "0",
                "FAKE_TIMER_RESTORE_MARKER": str(self.root / "timer-restore.marker"),
                "FAKE_API_BIN": str(self.api),
                "FAKE_EXTRACTOR_BIN": str(self.extractor),
                "FAKE_CVE_SYNC_BIN": str(self.cve_sync),
                "FAKE_SYSTEMCTL_LOG": str(self.systemctl_log),
                "FAKE_TIMER_STATE": str(self.timer_state),
                "FAKE_SHOW_COUNT": str(self.show_count),
                "FAKE_DRIFT_SEEN_URL": str(self.drift_seen_url),
                "FAKE_DRIFT_ARGS": str(self.drift_args),
                "FAKE_DRIFT_RC": str(drift_rc),
                "FAKE_DRIFT_LEAK": "1" if drift_leak else "0",
                "FAKE_DRIFT_HANG": "1" if drift_hang else "0",
            }
        )
        if drift_timeout_seconds is not None:
            env["PATCHED_SCHEMA_DRIFT_TIMEOUT_SECONDS"] = str(drift_timeout_seconds)
        env.pop("PATCHED_SCHEMA_DRIFT_ENFORCE", None)
        if schema_drift_enforce is not None:
            env["PATCHED_SCHEMA_DRIFT_ENFORCE"] = schema_drift_enforce
        if drift_output is not None:
            env["FAKE_DRIFT_OUTPUT"] = drift_output
        env.update(extra_env or {})
        args = ["bash", str(script or DEPLOY_SCRIPT)]
        if signal_number is None:
            return subprocess.run(
                args, env=env, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, check=False,
            )
        psql_log_size_before = self.psql_log.stat().st_size if self.psql_log.exists() else 0
        process = subprocess.Popen(
            args, env=env, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, start_new_session=True,
        )
        # PAT-1938: synchronise on a point deploy.sh publishes, never on a side
        # effect part-way through one. Each marker below is written by a fake
        # that has already armed its park, so the signal arrives while Bash is
        # blocked in `wait` on a foreground child, the one place in a shell
        # script where trap dispatch is unambiguous.
        #
        # The old readiness check for signal_after_swap read the swapped binary
        # back instead, and then touched restart.marker itself, which cancelled
        # the park it was meant to be waiting for. The test won that race every
        # time measured, so the signal landed at an arbitrary instruction in the
        # post-swap block, nine `$(stat ...)` and three `$(sha256_file ...)`
        # command substitutions deep, and the instruction varied run to run. On
        # the CI bash that produced `trap: line 2: unexpected EOF while looking
        # for matching ')'` and exit 2 instead of the expected signal code.
        #
        # The deadline below is a diagnostic ceiling, not a synchronisation
        # mechanism. Signalling anyway once it expires is what the old five
        # second version did, and it reproduces the very defect this fixes, so
        # a missed marker fails loudly here instead.
        deadline = time.monotonic() + 60
        ready = False
        while time.monotonic() < deadline:
            if signal_during_timer_restore:
                ready = (self.root / "timer-restore.marker").exists()
            elif signal_after_swap:
                # Reached only after all three binaries are swapped and their
                # hash and ownership invariants have passed.
                ready = (self.root / "restart.marker").exists()
            else:
                ready = self.psql_log.exists() and self.psql_log.stat().st_size > psql_log_size_before
            if ready:
                break
            if process.poll() is not None:
                break
            time.sleep(0.02)
        if not ready:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, _ = process.communicate(timeout=30)
            self.fail(
                "deploy.sh never reached its signal synchronisation point "
                f"(exit={process.returncode}):\n{stdout}"
            )
        os.killpg(process.pid, signal_number)
        output, _ = process.communicate(timeout=30)
        return subprocess.CompletedProcess(args, process.returncode, output)

    # PAT-1985. The failure this covers is the interpreter dying, not a command
    # failing, so it cannot be provoked by any fake: a fake is a separate
    # process and its exit status routes through ERR like every other command.
    # PAT-1938's own note records the real-world shape — a trap string that did
    # not parse, giving `unexpected EOF while looking for matching ')'` and exit
    # 2 — and records that reproducing it by racing a signal was exactly the
    # non-determinism that had to be engineered out of these tests.
    #
    # So the death is injected instead of raced: a byte-identical copy of
    # deploy.sh with one unparseable line spliced in at a named anchor. Nothing
    # test-only is added to the production script, the injected line is a parse
    # error of the same class rather than a command that exits non-zero, and the
    # trap wiring under test is the real file's. The anchor is asserted so this
    # fails loudly if the swap block is ever restructured.
    PARSE_ERROR_ANCHOR = 'mv -f "${CVE_SYNC_BIN}.new" "$CVE_SYNC_BIN"'
    PARSE_ERROR_LINE = 'echo "$( PATCHED_TEST_INJECTED_PARSE_ERROR\n'

    def _script_with_parse_error_after_swap(self) -> Path:
        source = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(
            source.count(self.PARSE_ERROR_ANCHOR), 1,
            "swap anchor for the injected parse error is no longer unique in deploy.sh",
        )
        lines = source.splitlines(keepends=True)
        index = next(i for i, line in enumerate(lines) if line.strip() == self.PARSE_ERROR_ANCHOR)
        lines.insert(index + 1, self.PARSE_ERROR_LINE)
        mutated = self.root / "deploy-parse-error.sh"
        mutated.write_text("".join(lines), encoding="utf-8")
        return mutated

    def assert_old_install(self) -> None:
        self.assertEqual(self.api.read_bytes(), b"old-api")
        self.assertEqual(self.extractor.read_bytes(), b"old-extractor")
        self.assertEqual(self.cve_sync.read_bytes(), b"old-cve-sync")
        self.assertEqual(self.receipt.read_text(encoding="utf-8"), "DEPLOYED_SHA=old\n")

    def assert_no_swap_temps(self) -> None:
        self.assertEqual(list(self.api.parent.glob("*.new")), [])
        self.assertEqual(list(self.api.parent.glob("*.rollback-new")), [])

    def test_success_installs_and_hash_proves_all_three_without_starting_oneshot(self) -> None:
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.api.read_bytes(), b"new-api")
        self.assertEqual(self.extractor.read_bytes(), b"new-extractor")
        self.assertEqual(self.cve_sync.read_bytes(), b"new-cve-sync")
        receipt = self.receipt.read_text(encoding="utf-8")
        self.assertIn(f"DEPLOYED_SHA={BUILD_SHA}", receipt)
        for name, content in (("patched-api", b"new-api"), ("patched-extractor", b"new-extractor"), ("patched-cve-sync", b"new-cve-sync")):
            self.assertIn(f"{name}={hashlib.sha256(content).hexdigest()}", receipt)
        calls = self.systemctl_log.read_text(encoding="utf-8")
        self.assertIn("stop patched-cve-sync.timer", calls)
        self.assertIn("start patched-cve-sync.timer", calls)
        self.assertIn("restart patched-api.service patched-extractor.service", calls)
        self.assertNotIn("restart patched-cve-sync.service", calls)
        self.assertNotIn("start patched-cve-sync.service", calls)

    def test_hardening_guard_failure_rolls_back_installed_binaries(self) -> None:
        result = self._run(hardening_guard_rc=7)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rolling back binaries", result.stdout)
        self.assert_old_install()

    def test_failed_smoke_atomically_restores_running_binaries_and_receipt(self) -> None:
        result = self._run(curl_status="500")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assert_old_install()
        self.assert_no_swap_temps()
        self.assertNotIn("simulated ETXTBSY", result.stdout)
        self.assertEqual(self.timer_state.read_text(encoding="utf-8"), "running\n")

    def test_failed_install_restores_all_and_cleans_partial_swap_files(self) -> None:
        result = self._run(mv_fail_cve=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assert_old_install()
        self.assert_no_swap_temps()

    def test_disabled_or_inactive_timer_fails_before_install(self) -> None:
        for kwargs, expected in (({"timer_enabled": False}, "not enabled"), ({"timer_active": False}, "not active")):
            with self.subTest(kwargs=kwargs):
                result = self._run(**kwargs)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(expected, result.stdout)
                self.assert_old_install()

    def test_active_sync_is_never_interrupted(self) -> None:
        result = self._run(service_state="active/running")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("ActiveState=active SubState=running", result.stdout)
        self.assertNotIn("stop patched-cve-sync.service", self.systemctl_log.read_text(encoding="utf-8"))
        self.assert_old_install()

    def test_timer_firing_during_quiesce_rolls_back_and_restores_timer(self) -> None:
        result = self._run(service_state_after_stop="activating/start")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("started while quiescing", result.stdout)
        self.assert_old_install()
        self.assertEqual(self.timer_state.read_text(encoding="utf-8"), "running\n")
        self.assertNotIn("stop patched-cve-sync.service", self.systemctl_log.read_text(encoding="utf-8"))

    def test_invocation_change_fails_and_rolls_back(self) -> None:
        result = self._run(invocation_change=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("invocation changed", result.stdout)
        self.assert_old_install()

    def test_never_run_oneshot_empty_invocation_id_stays_empty_and_deploy_succeeds(self) -> None:
        # PAT-1748: after a reboot the timer-owned oneshot has no InvocationID
        # until its next scheduled run. A loaded, inactive/dead unit with an
        # empty ID that is still empty after the smoke test must not block.
        result = self._run(invocation_empty=True)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("has not run since boot", result.stdout)
        self.assertEqual(self.api.read_bytes(), b"new-api")
        self.assertEqual(self.extractor.read_bytes(), b"new-extractor")
        self.assertEqual(self.cve_sync.read_bytes(), b"new-cve-sync")
        receipt = self.receipt.read_text(encoding="utf-8")
        self.assertIn(f"DEPLOYED_SHA={BUILD_SHA}", receipt)
        for name, content in (("patched-api", b"new-api"), ("patched-extractor", b"new-extractor"), ("patched-cve-sync", b"new-cve-sync")):
            self.assertIn(f"{name}={hashlib.sha256(content).hexdigest()}", receipt)
        calls = self.systemctl_log.read_text(encoding="utf-8")
        self.assertIn("show patched-cve-sync.service --property=LoadState --value", calls)
        self.assertIn("stop patched-cve-sync.timer", calls)
        self.assertIn("start patched-cve-sync.timer", calls)
        self.assertIn("restart patched-api.service patched-extractor.service", calls)
        self.assertNotIn("restart patched-cve-sync.service", calls)
        self.assertNotIn("start patched-cve-sync.service", calls)
        self.assertEqual(self.timer_state.read_text(encoding="utf-8"), "running\n")

    def test_empty_invocation_id_that_becomes_set_fails_and_rolls_back(self) -> None:
        result = self._run(invocation_empty=True, invocation_change=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("invocation changed while timer was quiesced", result.stdout)
        self.assertIn("after='deploy-started-invocation-id'", result.stdout)
        self.assert_old_install()
        self.assertEqual(self.timer_state.read_text(encoding="utf-8"), "running\n")

    def test_empty_invocation_id_with_unloaded_unit_fails_before_migrations_and_restores_timer(self) -> None:
        for load_state in ("not-found", "masked", "error"):
            with self.subTest(load_state=load_state):
                self.timer_state.write_text("running\n", encoding="utf-8")
                self.psql_log.unlink(missing_ok=True)
                result = self._run(invocation_empty=True, load_state=load_state)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("InvocationID is empty", result.stdout)
                self.assertIn(f"LoadState={load_state} ActiveState=inactive SubState=dead", result.stdout)
                self.assertFalse(self.psql_log.exists(), "no psql call may run before the invocation guard passes")
                self.assert_old_install()
                self.assertEqual(self.timer_state.read_text(encoding="utf-8"), "running\n")

    def test_empty_invocation_id_outside_inactive_dead_fails_closed(self) -> None:
        for service_state in ("failed/failed", "active/exited"):
            with self.subTest(service_state=service_state):
                self.timer_state.write_text("running\n", encoding="utf-8")
                self.psql_log.unlink(missing_ok=True)
                result = self._run(invocation_empty=True, service_state=service_state)
                active, sub = service_state.split("/")
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("InvocationID is empty", result.stdout)
                self.assertIn(f"LoadState=loaded ActiveState={active} SubState={sub}", result.stdout)
                self.assertFalse(self.psql_log.exists(), "no psql call may run before the invocation guard passes")
                self.assert_old_install()
                self.assertEqual(self.timer_state.read_text(encoding="utf-8"), "running\n")

    def test_set_invocation_id_that_becomes_empty_fails_and_rolls_back(self) -> None:
        result = self._run(invocation_after_empty=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("invocation changed while timer was quiesced", result.stdout)
        self.assertIn("after=''", result.stdout)
        self.assert_old_install()

    def test_execstart_must_resolve_to_exact_sync_binary(self) -> None:
        result = self._run(exec_start="/wrong/patched-cve-sync")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("exactly one ExecStart", result.stdout)
        self.assert_old_install()
        self.assertEqual(self.timer_state.read_text(encoding="utf-8"), "running\n")

    def test_execstart_parser_rejects_prefixed_path_fragment(self) -> None:
        raw = f"attacker-prefix {{ path={self.cve_sync} ; argv[]={self.cve_sync} ; }}"
        result = self._run(exec_start_raw=raw)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("exactly one ExecStart", result.stdout)
        self.assert_old_install()
        self.assertEqual(self.timer_state.read_text(encoding="utf-8"), "running\n")

    def test_live_execstart_parser_rejects_multiple_entries(self) -> None:
        raw = (
            f"{{ path={self.cve_sync} ; argv[]={self.cve_sync} ; }} "
            f"{{ path={self.cve_sync} ; argv[]={self.cve_sync} --again ; }}"
        )
        result = self._run(exec_start_raw=raw)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("count=2", result.stdout)
        self.assert_old_install()
        self.assertEqual(self.timer_state.read_text(encoding="utf-8"), "running\n")

    def test_pending_migration_succeeds_before_install(self) -> None:
        migration = self.staging / "migrations/0105_test_migration.sql"
        migration.write_text("SELECT 1;\n", encoding="utf-8")
        result = self._run(migration_applied=False)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("applying migration: 0105_test_migration", result.stdout)
        self.assertIn(f"-f {migration}", self.psql_log.read_text(encoding="utf-8"))
        self.assertEqual(self.api.read_bytes(), b"new-api")
        self.assertFalse((self.staging / "RECOVERY_REQUIRED").exists())

    def test_every_migration_psql_call_passes_database_url_via_dbname_flag(self) -> None:
        # Regression test for PAT-1414: every migration-related psql invocation must
        # pass DATABASE_URL as the -d/--dbname argument, not via the PGDATABASE env
        # var. libpq's connection-string-as-dbname parsing is not applied to
        # PGDATABASE on all psql builds (confirmed against the real production psql
        # 16.14), so a PGDATABASE-only invocation silently falls back to a local
        # socket connection instead of failing loudly. Asserting the fake psql's
        # env-var log stays empty while its argv log carries "-d postgres://test"
        # is what would have caught the regression before it reached production.
        migration = self.staging / "migrations/0105_test_migration.sql"
        migration.write_text("SELECT 1;\n", encoding="utf-8")
        result = self._run(migration_applied=False)
        self.assertEqual(result.returncode, 0, result.stdout)
        psql_calls = self.psql_log.read_text(encoding="utf-8").splitlines()
        self.assertTrue(psql_calls, "expected at least one psql invocation")
        for call in psql_calls:
            self.assertIn("-d postgres://test", call, f"psql call missing -d flag: {call!r}")
        database_env_log = (self.root / "psql-database.log").read_text(encoding="utf-8")
        for line in database_env_log.splitlines():
            self.assertEqual(line, "", "PGDATABASE must not be relied on to carry the connection URI")

    def test_pending_migration_failure_restores_timer_before_install(self) -> None:
        migration = self.staging / "migrations/0105_test_migration.sql"
        migration.write_text("SELECT 1;\n", encoding="utf-8")
        result = self._run(migration_fail=True, migration_applied=False)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("simulated migration failure", result.stdout)
        self.assert_old_install()
        self.assertEqual(self.timer_state.read_text(encoding="utf-8"), "running\n")

    def test_migration_content_must_match_ci_manifest_before_execution(self) -> None:
        migration = self.staging / "migrations/0105_test_migration.sql"
        migration.write_text("SELECT untrusted_branch_change;\n", encoding="utf-8")
        result = self._run(migration_applied=False)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("staged migration does not match BINARY_MANIFEST", result.stdout)
        self.assertNotIn(f"-f {migration}", self.psql_log.read_text(encoding="utf-8") if self.psql_log.exists() else "")
        self.assert_old_install()
        source = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        self.assertLess(source.index("migration content changed after manifest verification"), source.index('psql -d "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$file"'))
        # The manifest step moved to api-build.yml under PAT-1970 when the
        # push-triggered build was split out of the deploy workflow; the
        # manifest contract this asserts is otherwise unchanged.
        workflow = (DEPLOY_SCRIPT.parents[2] / ".github/workflows/api-build.yml").read_text(encoding="utf-8")
        self.assertIn('sha256sum "$migration"', workflow)
        self.assertIn('migration:#', workflow)
        self.assertIn("^[0-9]{4}_[a-z0-9_]+\\.sql$", workflow)
        self.assertIn("invalid forward migration filename", workflow)

    def test_later_rollback_leaves_persistent_timer_disabled_with_truthful_recovery_evidence(self) -> None:
        migration = self.staging / "migrations/0105_test_migration.sql"
        migration.write_text("SELECT 1;\n", encoding="utf-8")
        result = self._run(curl_status="500", migration_applied=False)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("RECOVERY REQUIRED: 1 forward migration(s) remain applied", result.stdout)
        self.assert_old_install()
        self.assertEqual(self.timer_state.read_text(encoding="utf-8"), "stopped\n")
        evidence = (self.staging / "RECOVERY_REQUIRED").read_text(encoding="utf-8")
        self.assertIn("RECOVERY_REQUIRED=true", evidence)
        self.assertIn("MIGRATIONS_APPLIED_THIS_RUN=1", evidence)
        self.assertIn("CVE_TIMER=disabled", evidence)
        self.assertIn("CURRENT_CVE_SYNC_SHA256=" + hashlib.sha256(b"old-cve-sync").hexdigest(), evidence)

    def test_head_check_failure_after_migration_keeps_timer_disabled_before_binary_swap(self) -> None:
        result = self._run(migration_applied=False, migration_head_present=False)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("RECOVERY REQUIRED", result.stdout)
        self.assert_old_install()
        self.assertEqual(self.timer_state.read_text(encoding="utf-8"), "stopped\n")
        evidence = (self.staging / "RECOVERY_REQUIRED").read_text(encoding="utf-8")
        self.assertIn("deploy exited after forward migration before commit", evidence)

    def test_deploy_refuses_near_timer_window_without_stopping_timer(self) -> None:
        result = self._run(next_trigger_seconds=899)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("due within 15 minutes", result.stdout)
        calls = self.systemctl_log.read_text(encoding="utf-8")
        self.assertNotIn("stop patched-cve-sync.timer", calls)
        self.assert_old_install()

    def test_activating_sync_is_blocked_and_active_exited_is_safe(self) -> None:
        blocked = self._run(service_state="activating/start")
        self.assertNotEqual(blocked.returncode, 0, blocked.stdout)
        self.assertIn("ActiveState=activating SubState=start", blocked.stdout)
        safe = self._run(service_state="active/exited")
        self.assertEqual(safe.returncode, 0, safe.stdout)

    def test_failed_failed_is_non_running_safe_after_timer_quiesce(self) -> None:
        result = self._run(service_state="failed/failed")
        self.assertEqual(result.returncode, 0, result.stdout)
        calls = self.systemctl_log.read_text(encoding="utf-8")
        self.assertIn("stop patched-cve-sync.timer", calls)

    def test_machine_timer_timestamp_and_invalid_forms(self) -> None:
        future = f"t {int(datetime.now(timezone.utc).timestamp() + 3600) * 1_000_000}"
        success = self._run(next_trigger_output=future)
        self.assertEqual(success.returncode, 0, success.stdout)
        for invalid in ("n/a", "Sun 2026-08-16 01:03:30 BST", "t nope"):
            with self.subTest(invalid=invalid):
                failed = self._run(next_trigger_output=invalid)
                self.assertNotEqual(failed.returncode, 0, failed.stdout)
                self.assertIn("invalid machine next-elapse", failed.stdout)

        self.systemctl_log.write_text("", encoding="utf-8")
        infinity = self._run(next_trigger_output="t 18446744073709551615")
        self.assertNotEqual(infinity.returncode, 0, infinity.stdout)
        self.assertIn("no finite next elapse (USEC_INFINITY)", infinity.stdout)
        self.assertNotIn("stop patched-cve-sync.timer", self.systemctl_log.read_text(encoding="utf-8"))

    def test_wrong_owner_or_mode_rolls_back(self) -> None:
        for stat_output in ("patched:patched 755", "root:root 775"):
            with self.subTest(stat_output=stat_output):
                result = self._run(stat_output=stat_output)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("invariant failed", result.stdout)
                self.assert_old_install()

    def test_effective_unit_contract_drift_fails_before_timer_or_filesystem_mutation(self) -> None:
        for drift in ("user", "working", "write"):
            with self.subTest(drift=drift):
                result = self._run(unit_contract=drift)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertTrue("write contract drifted" in result.stdout or "writes under /opt" in result.stdout, result.stdout)
                calls = self.systemctl_log.read_text(encoding="utf-8")
                self.assertNotIn("stop patched-cve-sync.timer", calls)
                self.assert_old_install()

    def test_effective_cve_unit_contract_is_checked_before_timer_or_filesystem_mutation(self) -> None:
        for drift in ("user", "working", "write"):
            with self.subTest(drift=drift):
                result = self._run(cve_unit_contract=drift)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertTrue("write contract drifted" in result.stdout or "writes under /opt" in result.stdout, result.stdout)
                calls = self.systemctl_log.read_text(encoding="utf-8")
                self.assertIn("show patched-cve-sync.service", calls)
                self.assertNotIn("stop patched-cve-sync.timer", calls)
                self.assert_old_install()

    def test_database_env_is_parsed_without_shell_evaluation(self) -> None:
        marker = self.root / "source-executed"
        self.env_file.write_text(f"DATABASE_URL=$(touch${{IFS}}{marker})\n", encoding="utf-8")
        result = self._run()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("shell expansion markers", result.stdout)
        self.assertFalse(marker.exists())
        source = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn('source "$API_ENV_FILE"', source)

    def test_database_url_requires_absolute_postgres_dsn_and_cannot_inject_psql_options(self) -> None:
        for value in ("--host=attacker", "dbname=patched", "file:/tmp/socket"):
            with self.subTest(value=value):
                self.env_file.write_text(f"DATABASE_URL={value}\n", encoding="utf-8")
                result = self._run()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("absolute postgres:// or postgresql://", result.stdout)
                self.assert_old_install()
        self.env_file.write_text("DATABASE_URL=postgresql://test\n", encoding="utf-8")
        accepted = self._run()
        self.assertEqual(accepted.returncode, 0, accepted.stdout)
        # DATABASE_URL is passed as a single quoted argv element to -d, so even a
        # value crafted to look like a flag (e.g. starting with "-") is taken as
        # the literal dbname/conninfo value, never re-parsed as a new psql option
        # -- read_database_url() additionally requires the value to start with
        # postgres:// or postgresql://, which cannot start with "-" anyway.
        self.assertIn("-d postgresql://test", self.psql_log.read_text(encoding="utf-8"))
        source = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn('PGDATABASE="$DATABASE_URL"', source)
        self.assertIn('psql -d "$DATABASE_URL"', source)

    def test_postinstall_psql_function_failure_uses_errtrace_and_rolls_back(self) -> None:
        result = self._run(postinstall_psql_fail=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("simulated post-install psql failure", result.stdout)
        self.assertIn("rolling back binaries", result.stdout)
        self.assert_old_install()
        self.assertIn("set -Eeuo pipefail", DEPLOY_SCRIPT.read_text(encoding="utf-8"))

    def test_unconventioned_forward_sql_is_rejected_cleanly(self) -> None:
        unexpected = self.staging / "migrations/0106_bad-name.sql"
        unexpected.write_text("SELECT 1;\n", encoding="utf-8")
        result = self._run()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("unexpected staged SQL filename refused: 0106_bad-name.sql", result.stdout)
        self.assertNotIn("invalid integer", result.stdout)
        self.assert_old_install()

    def test_manifest_hash_mismatch_fails_before_timer_or_install(self) -> None:
        self._write_manifest(api_content=b"not-the-staged-api")
        result = self._run()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("does not match BINARY_MANIFEST", result.stdout)
        self.assert_old_install()
        calls = self.systemctl_log.read_text(encoding="utf-8") if self.systemctl_log.exists() else ""
        self.assertNotIn("stop patched-cve-sync.timer", calls)

    def test_manifest_head_requires_staged_sql_and_database_record(self) -> None:
        migration = self.staging / "migrations/0105_test_migration.sql"
        migration.unlink()
        missing = self._run()
        self.assertNotEqual(missing.returncode, 0, missing.stdout)
        self.assertIn("not present in staged migrations", missing.stdout)
        self.assert_old_install()
        migration.write_text("SELECT 1;\n", encoding="utf-8")
        absent_from_database = self._run(migration_head_present=False)
        self.assertNotEqual(absent_from_database.returncode, 0, absent_from_database.stdout)
        self.assertIn("not recorded in schema_migrations", absent_from_database.stdout)
        self.assert_old_install()

    def test_corrupted_rollback_source_is_refused_and_success_receipt_removed(self) -> None:
        result = self._run(curl_status="500", corrupt_backup=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("untrusted or corrupted rollback source", result.stdout)
        self.assertIn("ROLLBACK FAILED", result.stdout)
        self.assertFalse(self.receipt.exists())

    def test_rollback_sources_are_root_controlled_and_have_recorded_digests(self) -> None:
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout)
        backup_dir = Path(str(self.receipt) + ".rollback-sources")
        digest_files = list(backup_dir.glob("ROLLBACK_SHA256-*"))
        self.assertEqual(len(digest_files), 1)
        digest_text = digest_files[0].read_text(encoding="utf-8")
        self.assertIn(hashlib.sha256(b"old-api").hexdigest(), digest_text)
        self.assertEqual(backup_dir.stat().st_mode & 0o777, 0o700)

    def test_unsafe_staging_cleanup_targets_are_rejected_before_mutation(self) -> None:
        result = self._run(staging_dir=Path("/"))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("unsafe staging directory refused", result.stdout)
        self.assert_old_install()

    def test_incomplete_rollback_fails_loudly_and_removes_success_receipt(self) -> None:
        result = self._run(curl_status="500", mv_fail_rollback=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("ROLLBACK FAILED", result.stdout)
        self.assertFalse(self.receipt.exists())
        self.assert_no_swap_temps()

    def test_non_root_requires_explicit_test_mode(self) -> None:
        env = os.environ.copy()
        env.pop("PATCHED_DEPLOY_TEST_MODE", None)
        result = subprocess.run(
            ["bash", str(DEPLOY_SCRIPT)], env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must run as root", result.stdout)

    def test_root_branch_rejects_test_mode_and_override_variables(self) -> None:
        source = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        self.assertRegex(source, r'if \[\[ "\$EUID" -eq 0 \]\]')
        self.assertIn("PATCHED_DEPLOY_TEST_MODE is forbidden for root production invocation", source)
        for name in ("PATCHED_API_BIN", "PATCHED_CVE_SYNC_BIN", "PATCHED_SYSTEMCTL_BIN", "PATCHED_DEPLOY_KEEP_STAGING"):
            self.assertIn(name, source)

    def test_exit_and_signal_traps_share_timer_restoration(self) -> None:
        source = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("trap restore_timer_on_exit EXIT", source)
        self.assertIn("trap 'dispatch_signal 129' HUP", source)
        self.assertIn("trap 'dispatch_signal 130' INT", source)
        self.assertIn("trap 'dispatch_signal 143' TERM", source)
        self.assertIn('if [[ "$TIMER_STOPPED" -eq 1 ]]', source)
        self.assertIn('if [[ "$TIMER_TRANSITION" -eq 1 ]]', source)

    def test_hup_int_and_term_restore_timer_during_migrations(self) -> None:
        for signal_number, expected_code in (
            (signal.SIGHUP, 129), (signal.SIGINT, 130), (signal.SIGTERM, 143),
        ):
            with self.subTest(signal_number=signal_number):
                self.timer_state.write_text("running\n", encoding="utf-8")
                self.systemctl_log.write_text("", encoding="utf-8")
                result = self._run(signal_number=signal_number)
                self.assertEqual(result.returncode, expected_code, result.stdout)
                self.assertEqual(self.timer_state.read_text(encoding="utf-8"), "running\n")
                self.assert_old_install()
                # PAT-1986. Everything above is also true of a run signalled
                # before quiesce_timer_for_deploy ever stopped the timer: it
                # reads "running" because it was never stopped, the binaries
                # are the old ones because nothing had been swapped, and the
                # exit code only shows that some trap ran. Demonstrated, not
                # assumed -- an earlier step spliced into deploy.sh that wrote
                # to the psql log this test synchronises on, with the timer
                # quiesce and the migrations never reached, left the test green
                # in 0.7s. Two discriminators pin the signal to the migration
                # phase, which is the only phase in which this test's claim is
                # about anything:
                #   - that phase had begun and the next one had not, so the
                #     signal landed inside it;
                #   - the timer was stopped exactly once and started exactly
                #     once, so the restoration this test is named for is what
                #     put it back, rather than it never having been stopped.
                self.assertIn("== Applying pending migrations ==", result.stdout)
                self.assertNotIn("== Backing up current binaries ==", result.stdout)
                calls = self.systemctl_log.read_text(encoding="utf-8")
                self.assertEqual(calls.count("stop patched-cve-sync.timer"), 1, calls)
                self.assertEqual(calls.count("start patched-cve-sync.timer"), 1, calls)

    def test_hup_int_and_term_after_swap_roll_back_everything(self) -> None:
        for signal_number, expected_code in (
            (signal.SIGHUP, 129), (signal.SIGINT, 130), (signal.SIGTERM, 143),
        ):
            with self.subTest(signal_number=signal_number):
                self.timer_state.write_text("running\n", encoding="utf-8")
                (self.root / "restart.marker").unlink(missing_ok=True)
                result = self._run(signal_number=signal_number, signal_after_swap=True)
                self.assertEqual(result.returncode, expected_code, result.stdout)
                self.assertEqual(self.timer_state.read_text(encoding="utf-8"), "running\n")
                self.assert_old_install()
                self.assertIn("rolling back binaries", result.stdout)

    def test_signal_during_timer_restore_is_deferred_then_rolls_back(self) -> None:
        marker = self.root / "timer-restore.marker"
        marker.unlink(missing_ok=True)
        result = self._run(
            signal_number=signal.SIGTERM,
            signal_after_swap=True,
            signal_during_timer_restore=True,
        )
        self.assertEqual(result.returncode, 143, result.stdout)
        self.assertTrue(marker.exists())
        # The marker alone is vacuous: rollback starts the timer too, so it
        # appears even when the signal landed long before restore_timer_after_deploy
        # and the deferral this test is named for never ran. Two independent
        # discriminators, both of which failed before PAT-1938:
        #   - the smoke test must have begun, so the signal cannot have been
        #     handled during the earlier service restart;
        #   - the timer must have been started twice, once by the interrupted
        #     restore_timer_after_deploy (the transition the signal was queued
        #     across) and once by the rollback that the queued signal triggered.
        self.assertIn("== Smoke test ==", result.stdout)
        calls = self.systemctl_log.read_text(encoding="utf-8")
        self.assertEqual(calls.count("start patched-cve-sync.timer"), 2, calls)
        self.assert_old_install()
        self.assertEqual(self.timer_state.read_text(encoding="utf-8"), "running\n")

    def test_fatal_parse_error_after_swap_rolls_back_from_the_exit_trap(self) -> None:
        # PAT-1985. The ERR trap cannot fire here — the interpreter is the thing
        # failing — so before this fix the EXIT trap restored the timer, recorded
        # migration recovery evidence and left the new binaries installed. The
        # exit path looked tidy while the box was running unverified bytes under
        # a receipt describing the previous release.
        binary_evidence = self.staging / "BINARY_ROLLBACK_REQUIRED"
        result = self._run(script=self._script_with_parse_error_after_swap())
        # Exit 2 is what a fatal parse error gives on every Bash this ships
        # against: 5.2 on the Ubuntu box and in CI, 5.3 on a dev Mac. Measured
        # aside, in case this ever reads 0 instead: Bash 3.2, which is still
        # /bin/bash on macOS, exits 0 on the same parse error. It fires the EXIT
        # trap and rolls back identically, so the fix holds there too, but a run
        # against 3.2 would report a fatal deploy failure as success. If this
        # assertion fails with 0, check which bash is on PATH before touching
        # the trap logic.
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("unexpected EOF while looking for matching", result.stdout)
        self.assertIn("without running the ERR trap", result.stdout)
        # rollback() names its caller. "exit-trap" rather than a $LINENO number
        # is the proof this run came from EXIT and not from ERR, which is the
        # whole point: an ERR-driven rollback here would mean the test was
        # provoking a command failure rather than an interpreter death.
        self.assertIn("DEPLOY FAILED at line exit-trap", result.stdout)
        self.assertNotRegex(result.stdout, r"DEPLOY FAILED at line \d+")
        self.assert_old_install()
        self.assert_no_swap_temps()
        self.assertEqual(self.timer_state.read_text(encoding="utf-8"), "running\n")
        # The rollback completed, so the evidence it writes on failure must not
        # be left behind claiming otherwise.
        self.assertFalse(binary_evidence.exists(), binary_evidence)

    def test_fatal_parse_error_with_failing_rollback_leaves_unambiguous_evidence(self) -> None:
        # PAT-1985, the other half: when the EXIT-trap rollback cannot restore
        # the binaries, the box must say so in its own right rather than letting
        # a restored timer and migration evidence imply a clean exit.
        binary_evidence = self.staging / "BINARY_ROLLBACK_REQUIRED"
        migration_evidence = self.staging / "RECOVERY_REQUIRED"
        # migration_applied=False makes this run apply a forward migration too,
        # so both recovery conditions are live at once and the test can show
        # they are recorded separately rather than one masking the other.
        result = self._run(
            script=self._script_with_parse_error_after_swap(),
            mv_fail_rollback=True,
            migration_applied=False,
        )
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("ROLLBACK FAILED", result.stdout)
        self.assertTrue(binary_evidence.exists(), result.stdout)
        evidence = binary_evidence.read_text(encoding="utf-8")
        self.assertIn("BINARY_ROLLBACK_REQUIRED=true", evidence)
        self.assertIn("BINARIES_ROLLED_BACK=false", evidence)
        self.assertIn("DEPLOY_PHASE=installing", evidence)
        self.assertIn(str(self.api), evidence)
        # Distinguishable in file and in content from the uncommitted-migration
        # case, which is a different and less urgent problem.
        self.assertNotEqual(binary_evidence, migration_evidence)
        self.assertTrue(migration_evidence.exists(), result.stdout)
        migration_text = migration_evidence.read_text(encoding="utf-8")
        self.assertIn("RECOVERY_REQUIRED=true", migration_text)
        self.assertNotIn("BINARY_ROLLBACK_REQUIRED", migration_text)
        self.assertNotIn("RECOVERY_REQUIRED=true", evidence)
        self.assertEqual(self.api.read_bytes(), b"new-api")

    def test_clean_exit_leaves_no_binary_rollback_evidence(self) -> None:
        # PAT-1985 case (i). If a successful deploy produced the marker it would
        # stop meaning anything.
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.staging / "BINARY_ROLLBACK_REQUIRED").exists())

    def test_err_trap_rollback_leaves_no_binary_rollback_evidence(self) -> None:
        # PAT-1985. A command failure still routes through ERR, rollback still
        # completes, and the EXIT trap must not then claim otherwise.
        result = self._run(curl_status="500")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("DEPLOY FAILED at line", result.stdout)
        self.assert_old_install()
        self.assertFalse((self.staging / "BINARY_ROLLBACK_REQUIRED").exists(), result.stdout)

    def test_success_prunes_each_backup_family_to_five(self) -> None:
        backup_dir = Path(str(self.receipt) + ".rollback-sources")
        backup_dir.mkdir()
        for destination in (self.api, self.extractor, self.cve_sync, self.receipt):
            for index in range(7):
                (backup_dir / f"{destination.name}.bak-2026010{index}T000000Z").write_text(
                    "old\n", encoding="utf-8"
                )
        for index in range(7):
            (backup_dir / f"ROLLBACK_SHA256-2026010{index}T000000Z").write_text(
                "digest\n", encoding="utf-8"
            )
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout)
        for destination in (self.api, self.extractor, self.cve_sync, self.receipt):
            self.assertEqual(len(list(backup_dir.glob(f"{destination.name}.bak-*"))), 5)
        self.assertEqual(len(list(backup_dir.glob("ROLLBACK_SHA256-*"))), 5)

    def test_root_environment_and_staging_contract_are_mutation_sensitive(self) -> None:
        source = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("PATH=/usr/sbin:/usr/bin:/sbin:/bin", source)
        self.assertIn("unset BASH_ENV ENV CDPATH", source)
        self.assertLess(source.index("PATH=/usr/sbin:/usr/bin:/sbin:/bin"), source.index('SCRIPT_DIR="$(cd'))
        self.assertIn('staging_state="$(stat -c \'%U:%G %a\' "$target")"', source)
        self.assertIn('"root:root 755"', source)
        # PAT-1970 split the pipeline: deploy-api-01.yml keeps everything that
        # reaches the box, api-build.yml keeps the containerised root harness.
        # Each positive assertion below is asked of the file that now owns it;
        # both negatives are asked of both files, because a negative that only
        # looks at one half of a split stops being a guard.
        workflows = DEPLOY_SCRIPT.parents[2] / ".github/workflows"
        deploy_workflow = (workflows / "deploy-api-01.yml").read_text(encoding="utf-8")
        build_workflow = (workflows / "api-build.yml").read_text(encoding="utf-8")
        self.assertIn("/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/bash --noprofile --norc", deploy_workflow)
        self.assertIn("docker run --rm --network none", build_workflow)
        self.assertIn("--cap-drop ALL", build_workflow)
        self.assertIn("PATCHED_ROOT_HARNESS_CONTAINER=1", build_workflow)
        for name, workflow in (("deploy-api-01.yml", deploy_workflow), ("api-build.yml", build_workflow)):
            self.assertNotIn("sudo bash deploy/api-01/test_root_production_integration.sh", workflow, name)
            self.assertNotIn("--cap-add", workflow, name)

    def test_post_receipt_reporting_failure_does_not_rollback_or_mask_success(self) -> None:
        result = self._run(reporting_fail=True)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("WARNING: could not print CVE timer", result.stdout)
        self.assertEqual(self.api.read_bytes(), b"new-api")
        self.assertEqual(self.extractor.read_bytes(), b"new-extractor")
        self.assertEqual(self.cve_sync.read_bytes(), b"new-cve-sync")
        self.assertIn(f"DEPLOYED_SHA={BUILD_SHA}", self.receipt.read_text(encoding="utf-8"))


    # -- PAT-2062: schema drift check wiring --------------------------------

    DRIFT_DIFF = (
        "schema drift check against the migrations at 0105_test_migration\n"
        "DRIFT: the live schema differs from what the migrations produce.\n"
        "+ column|devices|pat2062_planted|integer|null|"
    )

    def _psql_file_calls(self) -> list[str]:
        if not self.psql_log.exists():
            return []
        return [c for c in self.psql_log.read_text(encoding="utf-8").splitlines() if " -f " in c]

    def _systemctl_calls(self) -> str:
        return self.systemctl_log.read_text(encoding="utf-8") if self.systemctl_log.exists() else ""

    def assert_stopped_before_anything_changed(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("::error::SCHEMA DRIFT CHECK FAILED", result.stdout)
        self.assertIn("nothing has been changed", result.stdout)
        self.assertNotIn("Applying pending migrations", result.stdout)
        self.assertEqual(self._psql_file_calls(), [])
        self.assertNotIn("stop patched-cve-sync.timer", self._systemctl_calls())
        self.assertEqual(self.timer_state.read_text(encoding="utf-8"), "running\n")
        self.assert_old_install()

    def test_schema_drift_enforces_by_default(self) -> None:
        source = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        # PAT-2062: flipped to enforce after the first deploy logged "schema drift check: OK"
        # (run 35907459408, 2026-09-23). SCHEMA_DRIFT.md says how a fixing commit gets past it.
        self.assertRegex(source, r"(?m)^SCHEMA_DRIFT_ENFORCE_DEFAULT=1$")
        self.assertRegex(source, r'(?m)^  SCHEMA_DRIFT_ENFORCE="\$SCHEMA_DRIFT_ENFORCE_DEFAULT"$')
        result = self._run(drift_rc=1, drift_output=self.DRIFT_DIFF)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("Schema drift check (read-only, enforcing)", result.stdout)
        self.assertIn("::error::SCHEMA DRIFT CHECK FAILED", result.stdout)

    def test_schema_drift_warn_mode_prints_the_diff_and_continues_to_migrations(self) -> None:
        result = self._run(schema_drift_enforce="0", drift_rc=1, drift_output=self.DRIFT_DIFF,
                           migration_applied=False)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("  | + column|devices|pat2062_planted|integer|null|", result.stdout)
        self.assertIn("  | DRIFT: the live schema differs", result.stdout)
        self.assertIn("the live schema differs from what the migrations produce at its recorded head", result.stdout)
        self.assertLess(result.stdout.index("::warning::SCHEMA DRIFT"), result.stdout.index("applying migration: 0105_test_migration"))
        self.assertEqual(len(self._psql_file_calls()), 1)
        self.assertEqual(self.api.read_bytes(), b"new-api")
        self.assertIn("production binary deploy completed successfully", result.stdout)

    def test_schema_drift_warn_mode_continues_on_refusal(self) -> None:
        result = self._run(schema_drift_enforce="0", drift_rc=2,
                           drift_output="REFUSED: schema drift check could not run: gap")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("  | REFUSED: schema drift check could not run: gap", result.stdout)
        self.assertIn("refused or failed (exit 2)", result.stdout)
        self.assertIn("::warning::", result.stdout)

    def test_schema_drift_enforce_stops_on_drift_before_timer_or_any_migration(self) -> None:
        result = self._run(schema_drift_enforce="1", drift_rc=1, drift_output=self.DRIFT_DIFF,
                           migration_applied=False)
        self.assert_stopped_before_anything_changed(result)
        self.assertIn("Schema drift check (read-only, enforcing)", result.stdout)
        self.assertIn("  | + column|devices|pat2062_planted|integer|null|", result.stdout)
        self.assertTrue(self.drift_seen_url.exists(), "the check itself must have run")

    def test_schema_drift_enforce_stops_on_refusal(self) -> None:
        for rc in (2, 127):
            with self.subTest(rc=rc):
                result = self._run(schema_drift_enforce="1", drift_rc=rc, migration_applied=False,
                                   drift_output="REFUSED: schema drift check could not run: unknown head")
                self.assert_stopped_before_anything_changed(result)
                self.assertIn(f"refused or failed (exit {rc})", result.stdout)

    def test_schema_drift_missing_or_tampered_artefact_is_caught_by_the_manifest(self) -> None:
        journal = self.staging / "SCHEMA_FINGERPRINT_JOURNAL"
        check = self.staging / "schema-drift-check.sh"

        def tamper_journal() -> None:
            journal.write_text("stub SCHEMA_FINGERPRINT_JOURNAL\n+ tampered\n", encoding="utf-8")

        def delete_journal() -> None:
            journal.unlink()

        def tamper_check() -> None:
            check.write_text(SCHEMA_DRIFT_STUB.replace('exit "${FAKE_DRIFT_RC:-0}"', "exit 0"), encoding="utf-8")

        def symlink_journal() -> None:
            real = self.root / "journal-elsewhere"
            real.write_bytes(journal.read_bytes())
            journal.unlink()
            journal.symlink_to(real)

        def no_manifest_entries() -> None:
            self._write_manifest(schema_drift=False)

        cases = {
            "tampered journal": (tamper_journal, "does not match BINARY_MANIFEST: SCHEMA_FINGERPRINT_JOURNAL"),
            "missing journal": (delete_journal, "missing or not a regular file: SCHEMA_FINGERPRINT_JOURNAL"),
            "symlinked journal": (symlink_journal, "missing or not a regular file: SCHEMA_FINGERPRINT_JOURNAL"),
            "tampered check script": (tamper_check, "does not match BINARY_MANIFEST: schema-drift-check.sh"),
            "manifest without entries": (no_manifest_entries, "lacks exactly one schema-drift entry for SCHEMA_FINGERPRINT_JOURNAL"),
        }
        original = {name: (self.staging / name).read_bytes() for name in SCHEMA_DRIFT_ARTEFACTS}
        for label, (mutate, reason) in cases.items():
            for mode in ("1", "0"):
                with self.subTest(case=label, mode=mode):
                    for name, content in original.items():
                        path = self.staging / name
                        if path.is_symlink() or path.exists():
                            path.unlink()
                        path.write_bytes(content)
                    self._write_manifest()
                    self.drift_seen_url.unlink(missing_ok=True)
                    self.api.write_bytes(b"old-api")
                    self.extractor.write_bytes(b"old-extractor")
                    self.cve_sync.write_bytes(b"old-cve-sync")
                    self.receipt.write_text("DEPLOYED_SHA=old\n", encoding="utf-8")
                    self.systemctl_log.unlink(missing_ok=True)
                    self.psql_log.unlink(missing_ok=True)
                    mutate()
                    result = self._run(schema_drift_enforce=mode, migration_applied=False)
                    self.assertRegex(result.stdout, rf"(?m)^  \| .*{re.escape(reason)}$")
                    self.assertIn("failed verification against BINARY_MANIFEST", result.stdout)
                    self.assertFalse(self.drift_seen_url.exists(), "an unverified check must never run")
                    if mode == "1":
                        self.assert_stopped_before_anything_changed(result)
                    else:
                        self.assertEqual(result.returncode, 0, result.stdout)
                        self.assertIn("::warning::SCHEMA DRIFT CHECK FAILED", result.stdout)
                        self.assertEqual(self.api.read_bytes(), b"new-api")

    def test_schema_drift_unknown_manifest_entry_is_still_rejected(self) -> None:
        manifest = self.staging / "BINARY_MANIFEST"
        manifest.write_text(manifest.read_text(encoding="utf-8") + f"{'0' * 64}  schema-drift:evil.sh\n", encoding="utf-8")
        result = self._run()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("invalid migration hash entry", result.stdout)
        self.assert_old_install()

    def test_schema_drift_clean_target_passes_in_both_modes(self) -> None:
        for mode in ("0", "1"):
            with self.subTest(mode=mode):
                self.api.write_bytes(b"old-api")
                result = self._run(schema_drift_enforce=mode)
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertIn("  | OK: live schema matches the migrations", result.stdout)
                self.assertIn("schema drift check: OK", result.stdout)
                self.assertNotIn("::warning::", result.stdout)
                self.assertNotIn("::error::", result.stdout)
                self.assertEqual(self.api.read_bytes(), b"new-api")
                args = self.drift_args.read_text(encoding="utf-8")
                self.assertIn(f"--journal {self.staging}/SCHEMA_FINGERPRINT_JOURNAL", args)
                self.assertIn(f"--allowlist {self.staging}/schema-drift-allowlist.txt", args)
                self.assertIn("statement_timeout", args)

    def test_schema_drift_output_never_contains_the_database_url(self) -> None:
        secret = "placeholderpw"
        url = f"postgres://patched:{secret}@db.invalid:5432/patched"
        self.env_file.write_text(f"DATABASE_URL={url}\n", encoding="utf-8")
        for mode in ("0", "1"):
            with self.subTest(mode=mode):
                result = self._run(schema_drift_enforce=mode, drift_rc=2, drift_leak=True,
                                   drift_output=f"REFUSED: psql failed: password {secret} rejected")
                self.assertEqual(self.drift_seen_url.read_text(encoding="utf-8"), url,
                                 "the check must receive DATABASE_URL from deploy.sh")
                self.assertNotIn(url, result.stdout)
                self.assertNotIn(secret, result.stdout)
                self.assertIn("[DATABASE_URL redacted]", result.stdout)
                self.assertIn("password [redacted] rejected", result.stdout)

    def test_schema_drift_hanging_check_is_a_refusal_in_both_modes(self) -> None:
        for mode in ("1", "0"):
            with self.subTest(mode=mode):
                self.systemctl_log.unlink(missing_ok=True)
                self.psql_log.unlink(missing_ok=True)
                started = time.monotonic()
                result = self._run(schema_drift_enforce=mode, drift_hang=True, drift_timeout_seconds=1,
                                   migration_applied=False)
                self.assertLess(time.monotonic() - started, 30, "the timeout did not bound the check")
                self.assertIn("did not finish within 1 seconds", result.stdout)
                if mode == "1":
                    self.assert_stopped_before_anything_changed(result)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout)
                    self.assertIn("::warning::SCHEMA DRIFT CHECK FAILED", result.stdout)
                    self.assertEqual(self.api.read_bytes(), b"new-api")
        source = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        self.assertRegex(source, r"(?m)^  SCHEMA_DRIFT_TIMEOUT_SECONDS=600$")
        self.assertIn('timeout --kill-after=10 "$SCHEMA_DRIFT_TIMEOUT_SECONDS"', source)

    def test_schema_drift_mode_is_validated_and_root_cannot_override_it(self) -> None:
        result = self._run(schema_drift_enforce="yes")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("SCHEMA_DRIFT_ENFORCE must be 0 (warn) or 1 (enforce)", result.stdout)
        self.assert_old_install()
        source = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        overrides = source[source.index("UNSAFE_OVERRIDE_NAMES=("):source.index(")", source.index("UNSAFE_OVERRIDE_NAMES=("))]
        self.assertIn("PATCHED_SCHEMA_DRIFT_ENFORCE", overrides)
        self.assertIn("PATCHED_SCHEMA_DRIFT_TIMEOUT_SECONDS", overrides)

    def test_schema_drift_artefacts_are_built_bound_and_staged_by_ci(self) -> None:
        workflows = DEPLOY_SCRIPT.parents[2] / ".github/workflows"
        build = (workflows / "api-build.yml").read_text(encoding="utf-8")
        deploy = (workflows / "deploy-api-01.yml").read_text(encoding="utf-8")
        self.assertIn("image: postgres:16", build)
        self.assertIn("schema_drift.py build-journal", build)
        self.assertIn("--migrations go-service/migrations --out go-service/dist/SCHEMA_FINGERPRINT_JOURNAL", build)
        self.assertIn("sed 's#  #  schema-drift:#'", build)
        self.assertLess(build.index("Build the schema drift journal"), build.index("Create commit-bound binary manifest"))
        for name in SCHEMA_DRIFT_ARTEFACTS:
            with self.subTest(name=name):
                self.assertRegex(build, rf"(?m)^\s+go-service/dist/{name}$")
                self.assertRegex(deploy, rf"(?m)^\s+go-service/dist/{name} \\$")
                self.assertRegex(build, rf"(?m)^\s+{name}(?: \\|\))")

    # -- PAT-2062: the real check against a scratch database ------------------

    def _scratch_db(self) -> str:
        name = f"patched_test_deploy_drift_{os.urandom(5).hex()}"
        subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", drift_tests.TEST_DSN,
                        "-c", f'CREATE DATABASE "{name}"'], check=True, capture_output=True)
        self.addCleanup(subprocess.run, ["psql", "-X", "-q", "-d", drift_tests.TEST_DSN, "-c",
                                         f'DROP DATABASE IF EXISTS "{name}"'], capture_output=True, check=False)
        return drift_tests._db_url(drift_tests.TEST_DSN, name)

    def _stage_real_schema_drift(self) -> tuple[str, dict[str, str]]:
        """Stage the real check, a journal built from a small migration set and
        a target built from the same set. Returns the target URL and the env
        that routes the check's psql to the real server."""
        if not drift_tests.TEST_DSN:
            raise AssertionError("SCHEMA_DRIFT_DB_TESTS_REQUIRED=1 but SCHEMA_DRIFT_TEST_DSN is unset")
        real_psql = shutil.which("psql")
        self.assertIsNotNone(real_psql)
        migrations = self.root / "drift-migrations"
        migrations.mkdir()
        for name, body in drift_tests.MIGRATIONS.items():
            (migrations / name).write_text(body, encoding="utf-8")
        journal = sd.build_journal(self._scratch_db(), migrations)
        (self.staging / "SCHEMA_FINGERPRINT_JOURNAL").write_text(journal.dump(), encoding="utf-8")
        for name in SCHEMA_DRIFT_ARTEFACTS[1:]:
            shutil.copyfile(Path(__file__).with_name(name), self.staging / name)
        target = self._scratch_db()
        for f in sorted(migrations.iterdir()):
            if not f.name.endswith("_rollback.sql"):
                sd._psql(target, "-f", str(f))
        self.env_file.write_text(f"DATABASE_URL={target}\n", encoding="utf-8")
        self._write_manifest()
        return target, {"FAKE_PSQL_REAL_BIN": str(real_psql)}

    @unittest.skipUnless(drift_tests.TEST_DSN or drift_tests.DB_REQUIRED, "SCHEMA_DRIFT_TEST_DSN not set")
    def test_real_schema_drift_check_clean_target_passes_in_both_modes(self) -> None:
        target, env = self._stage_real_schema_drift()
        for mode in ("0", "1"):
            with self.subTest(mode=mode):
                self.api.write_bytes(b"old-api")
                result = self._run(schema_drift_enforce=mode, extra_env=env)
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertIn("  | OK: live schema matches the migrations", result.stdout)
                self.assertIn("schema drift check: OK", result.stdout)
                self.assertNotIn(target, result.stdout)
                self.assertEqual(self.api.read_bytes(), b"new-api")

    @unittest.skipUnless(drift_tests.TEST_DSN or drift_tests.DB_REQUIRED, "SCHEMA_DRIFT_TEST_DSN not set")
    def test_real_schema_drift_is_warned_or_enforced_before_any_migration(self) -> None:
        target, env = self._stage_real_schema_drift()
        sd._psql(target, "-c", "ALTER TABLE widgets ADD COLUMN pat2062_planted integer")
        planted = "  | + column|widgets|pat2062_planted|integer|null|"

        enforced = self._run(schema_drift_enforce="1", extra_env=env, migration_applied=False)
        self.assert_stopped_before_anything_changed(enforced)
        self.assertIn(planted, enforced.stdout)
        self.assertNotIn(target, enforced.stdout)

        warned = self._run(schema_drift_enforce="0", extra_env=env, migration_applied=False)
        self.assertEqual(warned.returncode, 0, warned.stdout)
        self.assertIn(planted, warned.stdout)
        self.assertIn("::warning::SCHEMA DRIFT CHECK FAILED", warned.stdout)
        self.assertEqual(len(self._psql_file_calls()), 1)
        self.assertNotIn(target, warned.stdout)
        # The check itself wrote nothing: the planted column is all that differs.
        self.assertIn("pat2062_planted", "\n".join(sd.fingerprint(target)))

    @unittest.skipUnless(drift_tests.TEST_DSN or drift_tests.DB_REQUIRED, "SCHEMA_DRIFT_TEST_DSN not set")
    def test_real_schema_drift_refusal_on_unknown_head_is_enforced(self) -> None:
        target, env = self._stage_real_schema_drift()
        sd._psql(target, "-c", "INSERT INTO schema_migrations (version) VALUES ('0999_not_in_journal')")
        result = self._run(schema_drift_enforce="1", extra_env=env, migration_applied=False)
        self.assert_stopped_before_anything_changed(result)
        self.assertIn("  | REFUSED: schema drift check could not run", result.stdout)
        self.assertIn("refused or failed (exit 2)", result.stdout)


if __name__ == "__main__":
    unittest.main()
