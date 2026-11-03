from __future__ import annotations

import hashlib
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import textwrap
import time
import unittest

from deploy_test_support import PARK_HELPER


SCRIPT = Path(__file__).with_name("emergency-api-only.sh")
BUILD_SHA = "b" * 40


class EmergencyApiOnlyExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.staging = self.root / "staging"
        self.staging.mkdir()
        self.live = self.root / "live"
        self.live.mkdir()
        self.api = self.live / "patched-api"
        self.extractor = self.live / "patched-extractor"
        self.cve = self.live / "patched-cve-sync"
        self.receipt = self.live / "DEPLOYED_BINARIES"
        self.api.write_bytes(b"old-api")
        self.extractor.write_bytes(b"current-extractor")
        self.cve.write_bytes(b"current-cve")
        self.receipt.write_text("DEPLOYED_SHA=old\n", encoding="utf-8")
        self.env_file = self.root / "api.env"
        self.env_file.write_text("DATABASE_URL=postgres://test\n", encoding="utf-8")
        (self.staging / "patched-api").write_bytes(b"new-api")
        api_hash = hashlib.sha256(b"new-api").hexdigest()
        (self.staging / "BINARY_MANIFEST").write_text(
            f"GITHUB_SHA={BUILD_SHA}\nMIGRATION_HEAD=0105_test_migration\n{api_hash}  patched-api\n"
            f"{'1' * 64}  patched-extractor\n{'2' * 64}  patched-cve-sync\n",
            encoding="utf-8",
        )
        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()
        self.restart_marker = self.root / "restart.marker"
        self.systemctl_log = self.root / "systemctl.log"
        self.mv_log = self.root / "mv.log"
        self._fake("chown", "exit 0")
        self._fake("install", 'destination="${!#}"; mkdir -p "$destination"; chmod 0700 "$destination"')
        self._fake(
            "stat",
            """
            target="${!#}"
            [[ "$target" == *rollback-sources ]] && { echo 'root:root 700'; exit 0; }
            [[ "$target" == *rollback-sources/* ]] && { echo 'root:root 600'; exit 0; }
            [[ "${FAKE_BAD_STAGING:-0}" == "1" && "$target" == "$PATCHED_EMERGENCY_STAGING_DIR" ]] && { printf 'patched:patched 775\\n'; exit 0; }
            [[ "$target" == */BINARY_MANIFEST ]] && { printf 'root:root 644\\n'; exit 0; }
            printf 'root:root 755\\n'
            """,
        )
        self._fake(
            "cp",
            """
            source="${@: -2:1}"; destination="${!#}"
            if [[ "$source" == *.emergency-bak-* && "$destination" == "$PATCHED_EMERGENCY_API_BIN" ]]; then
              echo 'direct executable overwrite forbidden' >&2; exit 1
            fi
            exec /bin/cp "$@"
            """,
        )
        self._fake(
            "mv",
            """
            source="${@: -2:1}"; destination="${!#}"
            printf '%s -> %s\\n' "$source" "$destination" >> "$FAKE_MV_LOG"
            [[ "${FAKE_MV_FAIL_INSTALL:-0}" == "1" && "$source" == *.new && "$destination" == "$PATCHED_EMERGENCY_API_BIN" ]] && exit 1
            exec /bin/mv "$@"
            """,
        )
        self._fake(
            "systemctl",
            """
            printf '%s\\n' "$*" >> "$FAKE_SYSTEMCTL_LOG"
            if [[ "$1" == "show" ]]; then
              user=patched; working=/opt/patched-api; protect=strict; writes=/var/log/patched-api
              [[ "${FAKE_UNIT_CONTRACT:-valid}" == "user" ]] && user=root
              [[ "${FAKE_UNIT_CONTRACT:-valid}" == "working" ]] && working=/opt/wrong
              [[ "${FAKE_UNIT_CONTRACT:-valid}" == "write" ]] && writes=/opt/patched-api
              printf 'User=%s\\nWorkingDirectory=%s\\nProtectSystem=%s\\nReadWritePaths=%s\\nReadWriteDirectories=\\n' "$user" "$working" "$protect" "$writes"
            elif [[ "$1" == "restart" && "${FAKE_RESTART_SLEEP:-0}" == "1" && ! -f "$FAKE_RESTART_MARKER" ]]; then
              # PAT-1986. Was `touch ...; sleep 30`, which had both hazards
              # PAT-1938 measured: the readiness marker was published by a fork
              # (touch), and the block was a child forked after it, so killpg
              # could miss the sleep entirely and emergency-api-only.sh would
              # then defer its trap for the sleep's full 30 seconds. That is the
              # intermittent communicate() timeout this module was seen to throw.
              park_arm
              : > "$FAKE_RESTART_MARKER"
              park_block 30
            fi
            exit 0
            """,
        )
        self._fake("curl", "printf '%s' \"${FAKE_CURL_STATUS:-200}\"")
        self._fake(
            "psql",
            "case \" $* \" in *' -d postgres://'*|*' -d postgresql://'*) ;; *) exit 88 ;; esac; "
            "printf '%s\\n' \"${FAKE_MIGRATION_PRESENT:-t}\"",
        )
        self._fake(
            "cat",
            """
            [[ "${FAKE_REPORT_FAIL:-0}" == "1" ]] && exit 1
            exec /bin/cat "$@"
            """,
        )
        self._fake(
            "find",
            """
            [[ "${FAKE_PRUNE_FAIL:-0}" == "1" ]] && exit 1
            exec /usr/bin/find "$@"
            """,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # Every fake gets the park helper. The helper and the measurements behind
    # each of its three properties live in deploy_test_support, shared with
    # test_deploy_script.py so the two harnesses cannot drift on how they park
    # a fake.
    def _fake(self, name: str, body: str) -> None:
        path = self.fake_bin / name
        path.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n" + PARK_HELPER + textwrap.dedent(body),
            encoding="utf-8",
        )
        path.chmod(0o755)

    def _run(self, *, sha: str = BUILD_SHA, curl: str = "200", bad_staging: bool = False,
             mv_fail: bool = False, report_fail: bool = False, prune_fail: bool = False,
             unit_contract: str = "valid", migration_ack: str = "migrations-applied=0105_test_migration",
             migration_present: str = "t", signal_number: int | None = None,
             script: Path = SCRIPT) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update({
            "PATH": f"{self.fake_bin}:{env['PATH']}",
            "PATCHED_EMERGENCY_TEST_MODE": "1",
            "PATCHED_EMERGENCY_STAGING_DIR": str(self.staging),
            "PATCHED_EMERGENCY_API_BIN": str(self.api),
            "PATCHED_EMERGENCY_EXTRACTOR_BIN": str(self.extractor),
            "PATCHED_EMERGENCY_CVE_SYNC_BIN": str(self.cve),
            "PATCHED_EMERGENCY_RECEIPT": str(self.receipt),
            "PATCHED_EMERGENCY_API_ENV_FILE": str(self.env_file),
            "FAKE_CURL_STATUS": curl,
            "FAKE_BAD_STAGING": "1" if bad_staging else "0",
            "FAKE_MV_FAIL_INSTALL": "1" if mv_fail else "0",
            "FAKE_REPORT_FAIL": "1" if report_fail else "0",
            "FAKE_PRUNE_FAIL": "1" if prune_fail else "0",
            "FAKE_UNIT_CONTRACT": unit_contract,
            "FAKE_MIGRATION_PRESENT": migration_present,
            "FAKE_RESTART_SLEEP": "1" if signal_number is not None else "0",
            "FAKE_RESTART_MARKER": str(self.restart_marker),
            "FAKE_SYSTEMCTL_LOG": str(self.systemctl_log),
            "FAKE_MV_LOG": str(self.mv_log),
        })
        args = ["bash", str(script), sha, "PAT-1396 test emergency", migration_ack]
        if signal_number is None:
            return subprocess.run(
                args, env=env, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, check=False,
            )
        process = subprocess.Popen(
            args, env=env, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, start_new_session=True,
        )
        # PAT-1986, following PAT-1938. The marker is written by a fake that has
        # already armed its park, so the signal arrives while Bash is blocked in
        # `wait` on a foreground child -- the one place in a shell script where
        # trap dispatch is unambiguous -- and it arrives at the post-swap
        # restart rather than at an arbitrary earlier instruction.
        #
        # The deadline is a diagnostic ceiling, not a synchronisation mechanism.
        # Signalling anyway once it expires is what the old five second version
        # did, and a signal delivered blind lands before the swap, where every
        # assertion in the signal test is satisfied by the untouched pre-deploy
        # state. A missed marker fails loudly here instead.
        deadline = time.monotonic() + 60
        ready = False
        while time.monotonic() < deadline:
            ready = self.restart_marker.exists()
            if ready or process.poll() is not None:
                break
            time.sleep(0.02)
        if not ready:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, _ = process.communicate(timeout=30)
            self.fail(
                "emergency-api-only.sh never reached its signal synchronisation "
                f"point (exit={process.returncode}):\n{stdout}"
            )
        os.killpg(process.pid, signal_number)
        output, _ = process.communicate(timeout=30)
        return subprocess.CompletedProcess(args, process.returncode, output)

    def test_success_atomically_installs_api_and_makes_primary_receipt_truthful(self) -> None:
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.api.read_bytes(), b"new-api")
        receipt = self.receipt.read_text(encoding="utf-8")
        self.assertIn("REDUCED_SCOPE=true", receipt)
        self.assertIn(f"DEPLOYED_SHA={BUILD_SHA}", receipt)
        self.assertIn(f"patched-api={hashlib.sha256(b'new-api').hexdigest()}", receipt)
        self.assertIn(f"patched-extractor={hashlib.sha256(b'current-extractor').hexdigest()}", receipt)
        self.assertIn(f"patched-cve-sync={hashlib.sha256(b'current-cve').hexdigest()}", receipt)
        pointer = next(line.split("=", 1)[1] for line in receipt.splitlines() if line.startswith("previous_receipt="))
        self.assertTrue(Path(pointer).is_file())
        self.assertEqual(Path(pointer).read_text(encoding="utf-8"), "DEPLOYED_SHA=old\n")

    def test_manifest_expected_sha_and_staging_invariants_fail_before_install(self) -> None:
        for kwargs, message in (({"sha": "c" * 40}, "does not match"), ({"bad_staging": True}, "staging must")):
            with self.subTest(kwargs=kwargs):
                result = self._run(**kwargs)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(message, result.stdout)
                self.assertEqual(self.api.read_bytes(), b"old-api")

    def test_effective_api_unit_drift_fails_before_backup_or_parent_mutation(self) -> None:
        for drift in ("user", "working", "write"):
            with self.subTest(drift=drift):
                result = self._run(unit_contract=drift)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertTrue("write contract drifted" in result.stdout or "writes under /opt" in result.stdout, result.stdout)
                self.assertEqual(self.api.read_bytes(), b"old-api")
                self.assertEqual(list(self.live.glob("*.emergency-bak-*")), [])

    def test_migration_ack_and_database_head_are_required(self) -> None:
        for kwargs, message in (
            ({"migration_ack": ""}, "acknowledgement is required"),
            ({"migration_present": "f"}, "is not applied"),
        ):
            with self.subTest(kwargs=kwargs):
                result = self._run(**kwargs)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(message, result.stdout)
                self.assertEqual(self.api.read_bytes(), b"old-api")

    def test_smoke_or_install_failure_atomically_restores_api_and_receipt(self) -> None:
        for kwargs in ({"curl": "500"}, {"mv_fail": True}):
            with self.subTest(kwargs=kwargs):
                result = self._run(**kwargs)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(self.api.read_bytes(), b"old-api")
                self.assertEqual(self.receipt.read_text(encoding="utf-8"), "DEPLOYED_SHA=old\n")
                self.assertNotIn("direct executable overwrite forbidden", result.stdout)

    def test_hup_int_and_term_after_swap_restore_binary_receipt_and_owners(self) -> None:
        for signal_number, expected_code in (
            (signal.SIGHUP, 129), (signal.SIGINT, 130), (signal.SIGTERM, 143),
        ):
            with self.subTest(signal_number=signal_number):
                self.api.write_bytes(b"old-api")
                self.receipt.write_text("DEPLOYED_SHA=old\n", encoding="utf-8")
                self.restart_marker.unlink(missing_ok=True)
                self.systemctl_log.write_text("", encoding="utf-8")
                self.mv_log.write_text("", encoding="utf-8")
                result = self._run(signal_number=signal_number)
                self.assertEqual(result.returncode, expected_code, result.stdout)
                self.assertEqual(self.api.read_bytes(), b"old-api")
                self.assertEqual(self.receipt.read_text(encoding="utf-8"), "DEPLOYED_SHA=old\n")
                self.assertIn("EMERGENCY API DEPLOY FAILED", result.stdout)
                self.assertEqual(self.api.stat().st_mode & 0o777, 0o755)
                self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o644)
                # PAT-1986. Everything above is also true of a run interrupted
                # before the swap ever happened. DEPLOY_PHASE is "installing"
                # from well before the swap, so a signal landing anywhere after
                # that still runs rollback and still prints EMERGENCY API DEPLOY
                # FAILED, while the binary and receipt read as the old ones
                # because they were never replaced. Demonstrated, not assumed:
                # deleting the swap outright and publishing the restart marker
                # from an earlier step left this test green in 1.0s. Two
                # independent discriminators pin the signal to the post-swap
                # restart, which is the only place this test's name is about:
                #   - the new bytes were moved into place and the backup was
                #     then moved back over them, so a swap happened and was
                #     undone rather than never happening;
                #   - patched-api.service was restarted twice, once by the
                #     interrupted post-swap restart and once by the rollback,
                #     so the signal landed at that restart and not earlier.
                moves = self.mv_log.read_text(encoding="utf-8")
                self.assertIn(f"{self.api}.new -> {self.api}", moves)
                self.assertIn(f"{self.api}.emergency-rollback-new -> {self.api}", moves)
                restarts = self.systemctl_log.read_text(encoding="utf-8")
                self.assertEqual(restarts.count("restart patched-api.service"), 2, restarts)

    # PAT-1993 checked this script for the gap PAT-1985 fixed in deploy.sh: a
    # fatal Bash-level failure (a parse error, not a command failing) that
    # kills the interpreter mid-swap before any rollback-triggering trap runs.
    # deploy.sh had that gap because its ERR trap was the only thing that
    # called rollback(), and its EXIT trap independently restored the timer
    # without checking DEPLOY_PHASE, so an ERR trap that never fired (the
    # interpreter died instead of a command failing) left new, unverified
    # binaries installed under an EXIT trap that looked clean.
    #
    # emergency-api-only.sh never had that split. It has no ERR trap at all --
    # emergency_exit(), its only EXIT trap, has always performed the
    # DEPLOY_PHASE-based rollback check directly and unconditionally, so it
    # never assumed some other trap had already handled an installing-phase
    # failure. This test proves that holds for the fatal-interpreter-death
    # case specifically, using the same injection technique as PAT-1985's
    # deploy.sh test (see test_deploy_script.py): a fatal parse error cannot be
    # provoked by any fake, since a fake is a separate process whose exit
    # status routes through the normal set -e path like any other command, so
    # the death is spliced into a copy of the real script instead.
    PARSE_ERROR_ANCHOR = 'mv -f "${API_BIN}.new" "$API_BIN"'
    PARSE_ERROR_LINE = 'echo "$( PATCHED_TEST_INJECTED_PARSE_ERROR\n'

    def _script_with_parse_error_after_swap(self) -> Path:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(
            source.count(self.PARSE_ERROR_ANCHOR), 1,
            "swap anchor for the injected parse error is no longer unique in emergency-api-only.sh",
        )
        lines = source.splitlines(keepends=True)
        index = next(i for i, line in enumerate(lines) if line.strip() == self.PARSE_ERROR_ANCHOR)
        lines.insert(index + 1, self.PARSE_ERROR_LINE)
        mutated = self.root / "emergency-parse-error.sh"
        mutated.write_text("".join(lines), encoding="utf-8")
        return mutated

    def test_fatal_parse_error_after_swap_rolls_back_from_the_exit_trap(self) -> None:
        result = self._run(script=self._script_with_parse_error_after_swap())
        # Exit 2 is what a fatal parse error gives on every Bash this ships
        # against: 5.2 on the Ubuntu box and in CI, 5.3 on a dev Mac. Bash 3.2
        # (still /bin/bash on macOS) exits 0 on the same parse error instead --
        # it fires the EXIT trap and rolls back identically, so the assertion
        # below on stdout and the restored binary hold there too, but the
        # returncode check would need loosening if this ever ran against 3.2.
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("unexpected EOF while looking for matching", result.stdout)
        self.assertIn("EMERGENCY API DEPLOY FAILED", result.stdout)
        self.assertEqual(self.api.read_bytes(), b"old-api")
        self.assertEqual(self.receipt.read_text(encoding="utf-8"), "DEPLOYED_SHA=old\n")
        self.assertEqual(list(self.live.glob("*.new")), [])
        self.assertEqual(list(self.live.glob("*.emergency-rollback-new")), [])

    def test_emergency_database_env_is_never_shell_evaluated(self) -> None:
        marker = self.root / "source-executed"
        self.env_file.write_text(f"DATABASE_URL=$(touch${{IFS}}{marker})\n", encoding="utf-8")
        result = self._run()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("shell expansion markers", result.stdout)
        self.assertFalse(marker.exists())
        self.assertNotIn('source "$API_ENV_FILE"', SCRIPT.read_text(encoding="utf-8"))

    def test_emergency_database_url_rejects_psql_option_injection(self) -> None:
        for value in ("--host=attacker", "dbname=patched", "file:/tmp/socket"):
            with self.subTest(value=value):
                self.env_file.write_text(f"DATABASE_URL={value}\n", encoding="utf-8")
                result = self._run()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("absolute postgres:// or postgresql://", result.stdout)
                self.assertEqual(self.api.read_bytes(), b"old-api")
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn('PGDATABASE="$DATABASE_URL"', source)
        self.assertIn('psql -d "$DATABASE_URL"', source)

    def test_success_prunes_history_to_five(self) -> None:
        backup_dir = Path(str(self.receipt) + ".rollback-sources")
        backup_dir.mkdir()
        for index in range(7):
            (backup_dir / f"patched-api.emergency-bak-2026010{index}").write_text("x", encoding="utf-8")
            (backup_dir / f"DEPLOYED_BINARIES.emergency-bak-2026010{index}").write_text("x", encoding="utf-8")
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(len(list(backup_dir.glob("patched-api.emergency-bak-*"))), 5)
        self.assertEqual(len(list(backup_dir.glob("DEPLOYED_BINARIES.emergency-bak-*"))), 5)

    def test_missing_extractor_and_cve_are_recorded_honestly(self) -> None:
        self.extractor.unlink()
        self.cve.unlink()
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout)
        receipt = self.receipt.read_text(encoding="utf-8")
        self.assertIn("patched-extractor=MISSING", receipt)
        self.assertIn("patched-cve-sync=MISSING", receipt)

    def test_postcommit_report_and_prune_failures_are_warnings(self) -> None:
        result = self._run(report_fail=True, prune_fail=True)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("WARNING: could not print", result.stdout)
        self.assertIn("WARNING: could not prune", result.stdout)
        self.assertEqual(self.api.read_bytes(), b"new-api")
        self.assertIn("REDUCED_SCOPE=true", self.receipt.read_text(encoding="utf-8"))

    def test_repo_units_prove_opt_working_directories_are_read_only(self) -> None:
        root = SCRIPT.parents[2]
        contracts = (
            ("patched-api.service", "/opt/patched-api"),
            ("patched-extractor.service", "/opt/patched-extractor"),
            ("patched-cve-sync.service", "/opt/patched-api"),
        )
        for unit_name, working_directory in contracts:
            unit = (root / "api-vps-artefacts" / unit_name).read_text(encoding="utf-8")
            self.assertIn(f"WorkingDirectory={working_directory}", unit)
            self.assertIn("ProtectSystem=strict", unit)
            read_write_lines = [line for line in unit.splitlines() if line.startswith("ReadWritePaths=")]
            for line in read_write_lines:
                self.assertNotIn(working_directory, line.split("=", 1)[1].split())

    def test_sha_helper_has_linux_and_macos_implementations(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("command -v sha256sum", source)
        self.assertIn("shasum -a 256", source)

    def test_workflow_retains_artifacts_and_has_build_only_dispatch(self) -> None:
        workflows = SCRIPT.parents[2] / ".github/workflows"
        workflow = (workflows / "deploy-api-01.yml").read_text(encoding="utf-8")
        # The artifact upload moved to api-build.yml under PAT-1970 along with
        # the rest of the build; the 14-day retention this break-glass path
        # depends on is unchanged, just in the other file now.
        build_workflow = (workflows / "api-build.yml").read_text(encoding="utf-8")
        self.assertIn("retention-days: 14", build_workflow)
        self.assertIn("deploy:\n        description: Deploy after building", workflow)
        self.assertIn("required: false", workflow)
        self.assertIn("inputs.deploy && github.ref == 'refs/heads/main'", workflow)

    def test_emergency_rollback_restores_prior_directory_state(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('EMERGENCY_DIRS=("$API_PARENT" "$API_BIN_DIR" "$RECEIPT_DIR")', source)
        self.assertIn("PRE_DIR_OWNERS=()", source)
        self.assertIn("PRE_DIR_MODES=()", source)
        self.assertIn('chown "${PRE_DIR_OWNERS[$i]}" "${EMERGENCY_DIRS[$i]}"', source)
        self.assertIn('chmod "${PRE_DIR_MODES[$i]}" "${EMERGENCY_DIRS[$i]}"', source)

    def test_root_integration_uses_disposable_capability_free_container(self) -> None:
        source = (SCRIPT.parent / "test_root_production_integration.sh").read_text(encoding="utf-8")
        self.assertNotIn("chroot", source)
        self.assertNotIn("mknod", source)
        self.assertNotIn("mount --bind", source)
        self.assertNotIn("umount", source)
        self.assertIn("PATCHED_ROOT_HARNESS_CONTAINER", source)
        self.assertIn("[[ -c /dev/null", source)
        for production_script in (SCRIPT, SCRIPT.parent / "deploy.sh"):
            self.assertNotIn("< <(", production_script.read_text(encoding="utf-8"))

    def test_bootstrap_uses_fixed_root_staging_and_commit_bound_manifest(self) -> None:
        source = (SCRIPT.parent / "bootstrap-cve-sync.sh").read_text(encoding="utf-8")
        self.assertIn("STAGING_DIR=/opt/patched-bootstrap-cve-sync", source)
        self.assertNotIn("/tmp/patched-cve-sync", source)
        self.assertIn('MANIFEST_SHA="$(sed -n', source)
        self.assertIn('[[ "$MANIFEST_SHA" == "$EXPECTED_GITHUB_SHA" ]]', source)
        self.assertIn('[[ "$(sha256_file "$STAGED_BIN")" == "$EXPECTED_BIN_SHA" ]]', source)
        self.assertIn("exec_start_count=", source)
        self.assertIn('[[ "$exec_start_value" == "$TARGET_BIN --mode=scheduled" ]] || exec_start_valid=0', source)
        self.assertIn("exact scheduled CVE pipeline command", source)
        self.assertIn('systemctl enable --now patched-cve-sync.timer', source)
        self.assertNotIn('systemctl start patched-cve-sync.service', source)
        self.assertIn("rollback_bootstrap_on_exit", source)
        self.assertLess(source.index("PATH=/usr/sbin:/usr/bin:/sbin:/bin"), source.index('EXPECTED_GITHUB_SHA='))

    def test_root_harness_executes_bootstrap_full_and_emergency_paths(self) -> None:
        source = (SCRIPT.parent / "test_root_production_integration.sh").read_text(encoding="utf-8")
        self.assertIn("bootstrap_failure_status", source)
        self.assertIn("removed partial binary, units and timer enablement", source)
        self.assertIn("bootstrap_refusal_status", source)
        self.assertIn("already bootstrapped", source)
        self.assertIn("production binary deploy completed successfully", source)
        self.assertIn("emergency_invariant_status", source)
        self.assertIn("forbidden for root emergency invocation", source)
        self.assertIn("REDUCED_SCOPE=true", source)


if __name__ == "__main__":
    unittest.main()
