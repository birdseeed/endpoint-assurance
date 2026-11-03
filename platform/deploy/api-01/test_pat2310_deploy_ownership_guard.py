"""PAT-2310: nothing root runs, installs or reads on patched-api-01 may be
owned by a non-root or unknown uid, or be writable by group or other.

Three rsyncs in .github/workflows/deploy-api-01.yml ran `rsync -a` without
--chown, so the files they placed kept the GitHub-hosted runner's uid, 1001,
which has no passwd entry on the box:

  /opt/patched-api/bin/patched-maintenance-facts.sh   root runs it hourly
  /opt/patched-prometheus-staging/*                   root runs and installs it
  /etc/apt/apt.conf.d/52-automatic-reboot.conf        apt reads it as root

The next account created on api-01 would have been given uid 1001 and could
have rewritten any of them. This module covers the two halves of the fix:

  * the guard itself (deploy/api-01/deploy-ownership-guard.sh), run for real
    against a temporary tree through its test-only path prefix. The tests run
    as an ordinary user, who cannot create a file owned by another uid, so a
    file owned by the current user stands in for "non-root": without the
    trusted-uid override the guard must treat it exactly as it would the
    runner's uid on the box. The no-passwd-entry rule is proven against the
    live box instead (PAT-2310's read-only dry run); an orphan uid is also
    non-root, so rule 4 fails such a file even if rule 2 were broken.
  * the workflow wiring, read as text the same way the other deploy-wiring
    tests in this directory do: every rsync to the box sets root ownership,
    the check is piped from the runner's copy at the right two points, and
    CI shellchecks it.

PAT-2312 gave the guard a second path set, `check --box prod-01`, for
.github/workflows/deploy-prod01-backup.yml. That workflow's rsync had the same
missing --chown, so /opt/patched-backup-setup and every file in it were uid
1001 on patched-prod-01, where 1001 is the `patched` account, and root then ran
install.sh from there. The Prod01* classes below cover the prod-01 path set
and that workflow's wiring the same way.

Run with: python3 -m unittest deploy.api-01.test_pat2310_deploy_ownership_guard -v
(or via `python3 -m unittest discover -s deploy/api-01 -p 'test_*.py'`)
"""

from __future__ import annotations

import importlib.util
import json
import os
import pwd
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
GUARD_PATH = REPO_ROOT / "deploy" / "api-01" / "deploy-ownership-guard.sh"
GUARD_REL = "deploy/api-01/deploy-ownership-guard.sh"
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "deploy-api-01.yml"
PROD01_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "deploy-prod01-backup.yml"
PROD01_ARTEFACTS = REPO_ROOT / "api-vps-artefacts" / "prod-01-backup"
GO_TEST_PATH = REPO_ROOT / ".github" / "workflows" / "go-test.yml"
BUILD_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "api-build.yml"
PARTITIONS_UNIT = REPO_ROOT / "api-vps-artefacts" / "patched-partitions.service"
ARTEFACT_MANIFEST = REPO_ROOT / "api-vps-artefacts" / "artefact-manifest.json"

_CHECK_MODULE_PATH = Path(__file__).with_name("check_binary_inventory.py")
_SPEC = importlib.util.spec_from_file_location("check_binary_inventory", _CHECK_MODULE_PATH)
assert _SPEC and _SPEC.loader
_CHECK_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_CHECK_MODULE)
workflow_step = _CHECK_MODULE.workflow_step

ME = pwd.getpwuid(os.getuid()).pw_name

EARLY_CHECK = "Check root-run paths on api-01 are root-owned before anything runs"
LATE_CHECK = "Re-check root-run paths on api-01 after every file is placed"
RECLAIM = "Reclaim files earlier deploys left runner-owned on api-01"

PROD01_COPY = "Copy artefacts to prod-01"
PROD01_CHECK = "Check root-run paths on prod-01 are root-owned before install.sh runs"
PROD01_INSTALL = "Run install.sh on prod-01"

# A clean copy of what the guard checks on api-01, as (kind, mode). Parent
# directories not listed here (etc/, etc/apt/) are outside the checked set.
CLEAN_TREE = {
    "opt/patched-api": ("d", 0o755),
    "opt/patched-api/bin": ("d", 0o755),
    "opt/patched-api/bin/patched-api": ("f", 0o755),
    "opt/patched-api/bin/patched-cve-sync": ("f", 0o755),
    "opt/patched-api/bin/backup.sh": ("f", 0o750),
    "opt/patched-api/bin/create-partitions.sh": ("f", 0o755),
    "opt/patched-api/bin/patched-maintenance-facts.sh": ("f", 0o755),
    "opt/patched-api/DEPLOYED_BINARIES": ("f", 0o644),
    "opt/patched-extractor": ("d", 0o755),
    "opt/patched-extractor/bin": ("d", 0o755),
    "opt/patched-extractor/bin/patched-extractor": ("f", 0o755),
    "opt/patched-extractor/bin/patched-extractor.bak-<timestamp>T081329Z": ("f", 0o755),
    "opt/patched-prometheus-staging": ("d", 0o755),
    "opt/patched-prometheus-staging/deploy-prometheus-rules.sh": ("f", 0o644),
    "opt/patched-prometheus-staging/prometheus-rules-patched.yml": ("f", 0o644),
    "opt/patched-prometheus-staging/prometheus-rules-patched.test.yml": ("f", 0o644),
    "opt/patched-systemd-staging": ("d", 0o700),
    "opt/patched-systemd-staging/patched-maintenance-facts.service": ("f", 0o644),
    "opt/patched-cve-systemd-staging": ("d", 0o700),
    "opt/patched-cve-systemd-staging/patched-cve-sync.service": ("f", 0o644),
    "etc/apt/apt.conf.d/52-automatic-reboot.conf": ("f", 0o644),
}

# A clean copy of what the guard checks on prod-01 with `--box prod-01`: the
# setup directory exactly as the workflow's `rsync --delete` leaves it (one
# file per artefact in the repo, with git's 0644, as on the box), and the
# libexec directory install.sh provisions root:root 0750.
PROD01_CLEAN_TREE = {
    "opt/patched-backup-setup": ("d", 0o755),
    **{
        f"opt/patched-backup-setup/{path.name}": ("f", 0o644)
        for path in sorted(PROD01_ARTEFACTS.iterdir())
        if path.is_file()
    },
    "usr/local/libexec/patched-prod-backup": ("d", 0o750),
    "usr/local/libexec/patched-prod-backup/prod-backup.sh": ("f", 0o750),
    "usr/local/libexec/patched-prod-backup/restore-test.sh": ("f", 0o750),
}


def code_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


_RSYNC_COMMAND = re.compile(r"^rsync\s|(?:&&|\|\||;|\||\$\()\s*rsync\s")


def rsync_commands(workflow: str) -> tuple[list[str], list[str]]:
    """Return (commands, unparsed) for every rsync in the workflow's shell.

    Continuation lines are joined. Whole-line comments are skipped, because
    many comments in the deploy workflow explain rsync behaviour. A line that
    invokes `rsync -<option>` in a shape this parser does not recognise (say
    `timeout 60 rsync -a`) is returned in `unparsed`, so the caller fails
    rather than silently not checking it.
    """
    commands: list[str] = []
    unparsed: list[str] = []
    lines = workflow.splitlines()
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if stripped.startswith("#"):
            index += 1
            continue
        if _RSYNC_COMMAND.search(stripped):
            parts = [stripped]
            while parts[-1].endswith("\\") and index + 1 < len(lines):
                index += 1
                parts.append(lines[index].strip())
            commands.append(" ".join(part.rstrip("\\").strip() for part in parts))
        elif re.search(r"\brsync\s+-", stripped):
            unparsed.append(stripped)
        index += 1
    return commands, unparsed


def rsync_findings(workflow: str, host: str = "patched-api-01") -> list[str]:
    """Every rsync to `host` that does not set root ownership."""
    commands, unparsed = rsync_commands(workflow)
    findings = [f"rsync in a shape this check cannot parse: {line}" for line in unparsed]
    for command in commands:
        tokens = command.split()
        if not any(token.startswith(f"root@{host}:") for token in tokens):
            continue
        if "--chown=root:root" not in tokens:
            findings.append(f"rsync to {host} without --chown=root:root: {command}")
    return findings


class _GuardHarness(unittest.TestCase):
    """Runs the real guard against a temporary copy of one box's path set.

    No test methods of its own; TREE is the clean tree to build and BOX_ARGS
    the arguments after `check` that select the path set.
    """

    TREE: dict[str, tuple[str, int]] = CLEAN_TREE
    BOX_ARGS: tuple[str, ...] = ()

    def setUp(self) -> None:
        if os.geteuid() == 0:
            self.skipTest(
                "the guard refuses its test-only overrides as root; CI runs this "
                "suite as the unprivileged runner user"
            )
        self.prefix = os.path.realpath(tempfile.mkdtemp(prefix="pat2310-"))
        self.addCleanup(self._remove_prefix)
        self.build_tree(self.TREE)

    def build_tree(self, tree: dict[str, tuple[str, int]]) -> None:
        for rel, (kind, _mode) in sorted(tree.items()):
            path = Path(self.prefix, rel)
            if kind == "d":
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"# {rel}\n", encoding="utf-8")
        # Deepest first, so a 0700 directory is set after its contents.
        for rel, (_kind, mode) in sorted(tree.items(), key=lambda item: -item[0].count("/")):
            os.chmod(Path(self.prefix, rel), mode)

    def _remove_prefix(self) -> None:
        for root, dirs, _files in os.walk(self.prefix):
            for name in dirs:
                path = os.path.join(root, name)
                if not os.path.islink(path):
                    os.chmod(path, 0o755)
        shutil.rmtree(self.prefix, ignore_errors=True)

    def path(self, rel: str) -> str:
        return os.path.join(self.prefix, rel)

    def add_file(self, rel: str, mode: int = 0o755) -> str:
        path = self.path(rel)
        Path(path).write_text("#!/bin/sh\n", encoding="utf-8")
        os.chmod(path, mode)
        return path

    def run_guard(
        self,
        *args: str,
        trusted: bool = True,
        service_user: str = ME,
        piped: bool = False,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PATCHED_OWNERSHIP_GUARD_PREFIX": self.prefix,
            "PATCHED_OWNERSHIP_GUARD_SERVICE_USER": service_user,
        }
        if trusted:
            env["PATCHED_OWNERSHIP_GUARD_TRUSTED_UID"] = str(os.getuid())
        env.update(extra_env or {})
        argv = list(args) if args else ["check", *self.BOX_ARGS]
        if piped:
            # Exactly how the workflow runs it: the script arrives on stdin.
            with GUARD_PATH.open("rb") as script:
                result = subprocess.run(
                    ["bash", "-s", "--", *argv], stdin=script, env=env,
                    capture_output=True, timeout=60,
                )
            return subprocess.CompletedProcess(
                result.args, result.returncode,
                result.stdout.decode("utf-8"), result.stderr.decode("utf-8"),
            )
        return subprocess.run(
            ["bash", str(GUARD_PATH), *argv], env=env, capture_output=True,
            text=True, timeout=60, stdin=subprocess.DEVNULL,
        )

    @staticmethod
    def errors(result: subprocess.CompletedProcess[str]) -> list[str]:
        return [line for line in result.stdout.splitlines() if line.startswith("::error::")]

    def named(self, result: subprocess.CompletedProcess[str], rel: str, reason: str = "") -> bool:
        # "<path> is ..." -- the trailing space keeps .../patched-extractor
        # from matching .../patched-extractor.bak-...
        needle = f"{self.path(rel)} "
        return any(needle in line and reason in line for line in self.errors(result))


class GuardBehaviourTests(_GuardHarness):
    """The real guard, run against a temporary copy of the api-01 paths."""

    # -- the clean case ------------------------------------------------------

    def test_clean_tree_passes(self):
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.errors(result), [])
        self.assertIn("deploy-ownership-guard: ok:", result.stdout)

    def test_clean_tree_passes_when_piped_the_way_the_workflow_runs_it(self):
        result = self.run_guard(piped=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("deploy-ownership-guard: ok:", result.stdout)

    def test_check_alone_is_the_api01_set_and_names_it(self):
        # PAT-2312 must not change what deploy-api-01.yml's bare `check` does.
        default = self.run_guard()
        explicit = self.run_guard("check", "--box", "api-01")
        for result in (default, explicit):
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("deploy-ownership-guard: box: api-01", result.stdout)
        def checked(result: subprocess.CompletedProcess[str]) -> str:
            return next(line for line in result.stdout.splitlines() if "checked:" in line)

        self.assertEqual(checked(default), checked(explicit))
        self.assertIn(self.path("opt/patched-api"), checked(default))
        self.assertNotIn("patched-backup-setup", default.stdout)
        self.assertNotIn("patched-prod-backup", default.stdout)

    # -- rule 4: an owner other than root --------------------------------------

    def test_a_file_owned_by_a_non_root_user_fails_and_is_named(self):
        # No trusted uid: every file here is owned by this ordinary user,
        # which is what the runner's uid 1001 looked like on the box.
        result = self.run_guard(trusted=False)
        self.assertEqual(result.returncode, 1, result.stdout)
        for rel in (
            "opt/patched-api/bin/patched-maintenance-facts.sh",
            "opt/patched-prometheus-staging/deploy-prometheus-rules.sh",
            "opt/patched-prometheus-staging/prometheus-rules-patched.yml",
            "etc/apt/apt.conf.d/52-automatic-reboot.conf",
            "opt/patched-api/bin",
        ):
            self.assertTrue(
                self.named(result, rel, f"owned by {ME} (uid {os.getuid()}), not root"),
                f"{rel} was not named as non-root:\n{result.stdout}",
            )

    def test_error_annotations_go_to_stdout(self):
        result = self.run_guard(trusted=False)
        self.assertEqual(result.returncode, 1)
        self.assertTrue(self.errors(result))
        self.assertNotIn("::error::", result.stderr)

    # -- rule 3: group or other write ------------------------------------------

    def test_a_group_writable_file_fails_and_only_it_is_named(self):
        rel = "opt/patched-prometheus-staging/prometheus-rules-patched.yml"
        os.chmod(self.path(rel), 0o664)
        result = self.run_guard()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertTrue(self.named(result, rel, "writable by group or other"), result.stdout)
        per_path = [line for line in self.errors(result) if self.prefix in line]
        self.assertEqual(len(per_path), 1, result.stdout)

    def test_an_other_writable_directory_fails(self):
        os.chmod(self.path("opt/patched-api/bin"), 0o757)
        result = self.run_guard()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertTrue(self.named(result, "opt/patched-api/bin", "writable by group or other"))

    # -- rule 1: symlinks --------------------------------------------------------

    def test_a_symlink_fails(self):
        target = self.add_file("opt/patched-api/DEPLOYED_BINARIES.real", 0o644)
        os.symlink(target, self.path("opt/patched-prometheus-staging/deploy-prometheus-rules.sh.link"))
        result = self.run_guard()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertTrue(
            self.named(result, "opt/patched-prometheus-staging/deploy-prometheus-rules.sh.link", "is a symlink"),
            result.stdout,
        )

    # -- the allowlist ------------------------------------------------------------

    def test_the_allowlist_is_one_exact_path_not_a_name(self):
        self.add_file("opt/patched-extractor/bin/create-partitions.sh")
        self.add_file("opt/patched-api/bin/create-partitions.sh.new")
        result = self.run_guard(trusted=False)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertFalse(self.named(result, "opt/patched-api/bin/create-partitions.sh"), result.stdout)
        self.assertIn("allowlisted", result.stdout)
        self.assertTrue(self.named(result, "opt/patched-extractor/bin/create-partitions.sh", "not root"))
        self.assertTrue(self.named(result, "opt/patched-api/bin/create-partitions.sh.new", "not root"))
        # Same owner, same directory, not on the allowlist.
        self.assertTrue(self.named(result, "opt/patched-api/bin/patched-maintenance-facts.sh", "not root"))

    def test_the_allowlisted_path_needs_its_named_owner(self):
        result = self.run_guard(trusted=False, service_user="nobody")
        self.assertTrue(self.named(result, "opt/patched-api/bin/create-partitions.sh", "not root"), result.stdout)

    def test_the_allowlisted_path_still_fails_when_writable(self):
        os.chmod(self.path("opt/patched-api/bin/create-partitions.sh"), 0o775)
        result = self.run_guard(trusted=False)
        self.assertTrue(
            self.named(result, "opt/patched-api/bin/create-partitions.sh", "writable by group or other"),
            result.stdout,
        )

    # -- the legacy extractor backups ------------------------------------------------

    def test_the_legacy_backup_exception_is_narrow(self):
        self.add_file("opt/patched-extractor/bin/patched-extractor.bak-manual")
        self.add_file("opt/patched-extractor/bin/patched-extractor.bak-<timestamp>T081329Z.sh")
        self.add_file("opt/patched-api/bin/patched-api.bak-<timestamp>T081329Z")
        self.add_file("opt/patched-api/bin/patched-extractor.bak-<timestamp>T081329Z")
        result = self.run_guard(trusted=False)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertFalse(
            self.named(result, "opt/patched-extractor/bin/patched-extractor.bak-<timestamp>T081329Z"),
            result.stdout,
        )
        self.assertIn("tolerated: 1 legacy", result.stdout)
        for rel in (
            "opt/patched-extractor/bin/patched-extractor.bak-manual",
            "opt/patched-extractor/bin/patched-extractor.bak-<timestamp>T081329Z.sh",
            "opt/patched-api/bin/patched-api.bak-<timestamp>T081329Z",
            "opt/patched-api/bin/patched-extractor.bak-<timestamp>T081329Z",
        ):
            self.assertTrue(self.named(result, rel, "not root"), f"{rel}:\n{result.stdout}")

    def test_a_legacy_backup_needs_the_service_user_as_owner(self):
        result = self.run_guard(trusted=False, service_user="nobody")
        self.assertTrue(
            self.named(result, "opt/patched-extractor/bin/patched-extractor.bak-<timestamp>T081329Z", "not root"),
            result.stdout,
        )

    def test_a_legacy_backup_still_fails_when_writable(self):
        rel = "opt/patched-extractor/bin/patched-extractor.bak-<timestamp>T081329Z"
        os.chmod(self.path(rel), 0o775)
        result = self.run_guard(trusted=False)
        self.assertTrue(self.named(result, rel, "writable by group or other"), result.stdout)

    # -- coverage, absence and read failures -----------------------------------------

    def test_a_missing_service_tree_fails(self):
        shutil.rmtree(self.path("opt/patched-extractor"))
        result = self.run_guard()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertTrue(any("patched-extractor is missing" in line for line in self.errors(result)), result.stdout)

    def test_absent_staging_paths_are_reported_not_failed(self):
        shutil.rmtree(self.path("opt/patched-systemd-staging"))
        os.remove(self.path("etc/apt/apt.conf.d/52-automatic-reboot.conf"))
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stdout)
        absent = next(line for line in result.stdout.splitlines() if "absent" in line)
        self.assertIn(self.path("opt/patched-systemd-staging"), absent)
        self.assertIn(self.path("etc/apt/apt.conf.d/52-automatic-reboot.conf"), absent)
        self.assertIn(self.path("opt/patched-deploy-staging"), absent)

    def test_a_tree_that_cannot_be_read_fails_closed(self):
        os.chmod(self.path("opt/patched-cve-systemd-staging"), 0o000)
        result = self.run_guard()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertTrue(any("could not read all of" in line for line in self.errors(result)), result.stdout)

    def test_usage_errors_exit_2(self):
        for argv in ((), ("check", "extra"), ("lock",)):
            with self.subTest(argv=argv):
                env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
                result = subprocess.run(
                    ["bash", str(GUARD_PATH), *argv], env=env, capture_output=True,
                    text=True, timeout=60, stdin=subprocess.DEVNULL,
                )
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_bad_override_values_fail_closed(self):
        for extra in (
            {"PATCHED_OWNERSHIP_GUARD_PREFIX": "relative/path"},
            {"PATCHED_OWNERSHIP_GUARD_TRUSTED_UID": "0 -o -true"},
        ):
            with self.subTest(extra=extra):
                result = self.run_guard(extra_env=extra)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("Nothing was checked", result.stdout)


class WorkflowWiringTests(unittest.TestCase):
    """deploy-api-01.yml, go-test.yml and api-build.yml, read as text."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.guard = GUARD_PATH.read_text(encoding="utf-8")

    def step_index(self, name: str) -> int:
        marker = f"- name: {name}\n"
        self.assertIn(marker, self.workflow, f"step {name!r} is missing")
        return self.workflow.index(marker)

    # -- every rsync to the box sets root ownership -----------------------------

    def test_every_rsync_to_the_box_sets_root_ownership(self):
        commands, _unparsed = rsync_commands(self.workflow)
        to_box = [c for c in commands if "root@patched-api-01:" in c]
        # Six today. Fewer means the parser lost its input, not that the
        # workflow got safer.
        self.assertGreaterEqual(len(to_box), 6, commands)
        self.assertEqual(rsync_findings(self.workflow), [])

    def test_the_rsync_check_fails_on_a_missing_chown(self):
        # A guard that cannot fail is not a guard: the exact shape PAT-2310
        # fixed must be reported, and so must an rsync the parser cannot read.
        bad = (
            "      - name: Ship something\n"
            "        run: |\n"
            "          # rsync -av --chown=root:root in a comment does not count\n"
            "          rsync -av \\\n"
            '            -e "ssh -i /tmp/api01_key" \\\n'
            "            api-vps-artefacts/thing.sh \\\n"
            "            root@patched-api-01:/opt/patched-api/bin/thing.sh\n"
            "          timeout 60 rsync -av --chown=root:root x root@patched-api-01:/opt/x\n"
        )
        findings = rsync_findings(bad)
        self.assertEqual(len(findings), 2, findings)
        self.assertTrue(any("without --chown=root:root" in f and "thing.sh" in f for f in findings), findings)
        self.assertTrue(any("cannot parse" in f and "timeout 60" in f for f in findings), findings)

    def test_the_three_runner_owned_placements_now_set_root_ownership(self):
        for step in (
            "Stage Prometheus rules on api-01",
            "Deploy maintenance facts emitter on api-01",
            "Deploy automatic reboot policy on api-01",
        ):
            with self.subTest(step=step):
                commands, _ = rsync_commands(workflow_step(self.workflow, step))
                self.assertEqual(len(commands), 1, step)
                self.assertIn("--chown=root:root", commands[0].split())

    # -- the check runs from the runner, at the right two points ------------------

    def test_both_checks_pipe_the_runners_copy(self):
        for step in (EARLY_CHECK, LATE_CHECK):
            with self.subTest(step=step):
                body = "\n".join(code_lines(workflow_step(self.workflow, step)))
                self.assertIn("root@patched-api-01", body)
                self.assertIn("/bin/bash --noprofile --norc -s -- check", body)
                self.assertIn(f"< {GUARD_REL}", body)
                self.assertIn("/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin", body)

    def test_no_step_runs_a_copy_of_the_check_from_the_box(self):
        references = [
            line.strip() for line in code_lines(self.workflow) if "deploy-ownership-guard" in line
        ]
        self.assertEqual(len(references), 2, references)
        for line in references:
            self.assertEqual(line, f"< {GUARD_REL} || rc=$?")

    def test_the_check_runs_before_root_runs_anything_and_again_after_the_last_placement(self):
        stage_prometheus = self.step_index("Stage Prometheus rules on api-01")
        reclaim = self.step_index(RECLAIM)
        early = self.step_index(EARLY_CHECK)
        preflight = self.step_index("Preflight current systemd hardening floor on api-01")
        deploy_sh = self.step_index("Run deploy.sh on api-01")
        rules = self.step_index("Deploy Prometheus alerting rules on api-01")
        reboot_verify = self.step_index("Verify the automatic reboot policy landed on api-01")
        late = self.step_index(LATE_CHECK)
        readback = self.step_index("Read back three-binary provenance and timer state")
        self.assertLess(stage_prometheus, reclaim)
        self.assertLess(reclaim, early)
        self.assertLess(early, preflight)
        self.assertLess(preflight, deploy_sh)
        self.assertLess(deploy_sh, rules)
        self.assertLess(reboot_verify, late)
        self.assertLess(late, readback)
        # Every rsync to the box happens before the late check.
        last_rsync = max(m.start() for m in re.finditer(r"(?m)^\s+rsync\s", self.workflow))
        self.assertLess(last_rsync, late)

    def test_an_unreachable_box_is_not_reported_as_an_ownership_finding(self):
        for step in (EARLY_CHECK, LATE_CHECK):
            with self.subTest(step=step):
                body = workflow_step(self.workflow, step)
                self.assertIn('"$rc" -eq 255', body)
                self.assertIn("SSH/network failure", body)
                self.assertIn('exit "$rc"', body)
                for line in body.splitlines():
                    if "::error::" in line:
                        self.assertNotIn(">&2", line)

    def test_the_reclaim_step_touches_exactly_the_two_late_placed_paths(self):
        body = "\n".join(code_lines(workflow_step(self.workflow, RECLAIM)))
        self.assertIn(
            "for f in /opt/patched-api/bin/patched-maintenance-facts.sh "
            "/etc/apt/apt.conf.d/52-automatic-reboot.conf; do",
            body,
        )
        self.assertIn('chown -h root:root "$f"', body)
        self.assertIn('[ -L "$f" ]', body)
        self.assertNotIn("*", body)
        # One chown invocation, never recursive (the other "chown" is the
        # text of its failure message).
        self.assertEqual(len(re.findall(r"\bchown\s+-", body)), 1, body)
        self.assertNotRegex(body, r"\bchown\s+-\w*R")

    # -- CI and packaging ------------------------------------------------------------

    def test_ci_shellchecks_the_guard(self):
        go_test = GO_TEST_PATH.read_text(encoding="utf-8")
        build = BUILD_WORKFLOW_PATH.read_text(encoding="utf-8")
        contract = workflow_step(go_test, "API deployment contract")
        lint = workflow_step(build, "Lint the box-side deploy script")
        for body in (contract, lint):
            shellcheck = next(line for line in body.splitlines() if line.strip().startswith("shellcheck "))
            self.assertIn(GUARD_REL, shellcheck.split())

    def test_the_guard_is_not_a_hand_copied_artefact(self):
        manifest = json.loads(ARTEFACT_MANIFEST.read_text(encoding="utf-8"))
        self.assertNotIn("deploy-ownership-guard", json.dumps(manifest))
        self.assertFalse((REPO_ROOT / "api-vps-artefacts" / "deploy-ownership-guard.sh").exists())

    # -- the allowlist's premise --------------------------------------------------------

    def test_the_allowlist_has_one_exact_entry_and_its_premise_holds(self):
        body = self.guard[self.guard.index("allowlisted_owner() {"):]
        body = body[: body.index("\n}\n")]
        arms = re.findall(r'^\s+("[^"\n]*")\)', body, re.MULTILINE)
        self.assertEqual(arms, ['"$PREFIX/opt/patched-api/bin/create-partitions.sh"'])
        # The entry is only safe while root never runs the file.
        unit = PARTITIONS_UNIT.read_text(encoding="utf-8")
        self.assertRegex(unit, r"(?m)^User=patched$")
        self.assertRegex(unit, r"(?m)^ExecStart=/opt/patched-api/bin/create-partitions\.sh$")
        self.assertNotRegex(unit, r"(?m)^Exec\w*=[-@:+!]*[+!]")


class Prod01GuardBehaviourTests(_GuardHarness):
    """PAT-2312: the real guard with `check --box prod-01`."""

    TREE = PROD01_CLEAN_TREE
    BOX_ARGS = ("--box", "prod-01")

    SETUP = "opt/patched-backup-setup"
    LIBEXEC = "usr/local/libexec/patched-prod-backup"

    def test_the_clean_tree_mirrors_the_artefact_directory(self):
        # A guard over a hand-kept list could miss a file the rsync ships.
        shipped = {p.name for p in PROD01_ARTEFACTS.iterdir() if p.is_file()}
        self.assertIn("install.sh", shipped)
        self.assertEqual(
            {Path(rel).name for rel in self.TREE if rel.startswith(f"{self.SETUP}/")}, shipped,
        )

    def test_clean_tree_passes(self):
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.errors(result), [])
        self.assertIn("deploy-ownership-guard: box: prod-01", result.stdout)
        checked = next(line for line in result.stdout.splitlines() if "checked:" in line)
        self.assertIn(self.path(self.SETUP), checked)
        self.assertIn(self.path(self.LIBEXEC), checked)
        self.assertIn("deploy-ownership-guard: ok:", result.stdout)

    def test_clean_tree_passes_when_piped_the_way_the_workflow_runs_it(self):
        result = self.run_guard(piped=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("deploy-ownership-guard: ok:", result.stdout)

    def test_the_prod01_set_checks_no_api01_path(self):
        self.build_tree(CLEAN_TREE)
        result = self.run_guard(trusted=False)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertNotIn(self.path("opt/patched-api"), result.stdout)
        self.assertNotIn(self.path("opt/patched-extractor"), result.stdout)
        self.assertNotIn(self.path("etc/apt"), result.stdout)

    # -- red: the live PAT-2312 shape ------------------------------------------

    def test_a_setup_tree_left_runner_owned_fails_and_every_path_is_named(self):
        # No trusted uid: every path is owned by this ordinary user, which is
        # what uid 1001 (`patched`) looked like on prod-01 before --chown.
        result = self.run_guard(trusted=False)
        self.assertEqual(result.returncode, 1, result.stdout)
        for rel in self.TREE:
            with self.subTest(rel=rel):
                self.assertTrue(
                    self.named(result, rel, f"owned by {ME} (uid {os.getuid()}), not root"),
                    f"{rel} was not named as non-root:\n{result.stdout}",
                )
        self.assertIn("on prod-01", result.stdout)

    def test_the_api01_exceptions_do_not_apply_to_prod01(self):
        # The allowlist and the legacy-backup tolerance are api-01 paths.
        # Under --box prod-01 a file owned by the service user is a finding
        # like any other, and nothing is reported as allowlisted or tolerated.
        result = self.run_guard(trusted=False)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertNotIn("allowlisted", result.stdout)
        self.assertNotIn("tolerated", result.stdout)

    # -- rules 1 and 3 ------------------------------------------------------------

    def test_a_group_writable_install_sh_fails_and_only_it_is_named(self):
        rel = f"{self.SETUP}/install.sh"
        os.chmod(self.path(rel), 0o664)
        result = self.run_guard()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertTrue(self.named(result, rel, "writable by group or other"), result.stdout)
        per_path = [line for line in self.errors(result) if self.prefix in line]
        self.assertEqual(len(per_path), 1, result.stdout)

    def test_an_other_writable_libexec_directory_fails(self):
        os.chmod(self.path(self.LIBEXEC), 0o757)
        result = self.run_guard()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertTrue(self.named(result, self.LIBEXEC, "writable by group or other"), result.stdout)

    def test_a_symlink_in_the_setup_directory_fails(self):
        target = self.add_file(f"{self.LIBEXEC}/elsewhere.sh", 0o750)
        os.remove(self.path(f"{self.SETUP}/prod-backup.sh"))
        os.symlink(target, self.path(f"{self.SETUP}/prod-backup.sh"))
        result = self.run_guard()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertTrue(self.named(result, f"{self.SETUP}/prod-backup.sh", "is a symlink"), result.stdout)

    def test_a_symlinked_setup_directory_fails(self):
        shutil.rmtree(self.path(self.SETUP))
        os.symlink(self.path(self.LIBEXEC), self.path(self.SETUP))
        result = self.run_guard()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertTrue(any("patched-backup-setup is missing" in line for line in self.errors(result)), result.stdout)

    # -- coverage and absence -------------------------------------------------------

    def test_a_missing_setup_directory_fails(self):
        shutil.rmtree(self.path(self.SETUP))
        result = self.run_guard()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertTrue(any("patched-backup-setup is missing" in line for line in self.errors(result)), result.stdout)

    def test_libexec_absent_before_the_first_install_is_reported_not_failed(self):
        shutil.rmtree(self.path(self.LIBEXEC))
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stdout)
        absent = next(line for line in result.stdout.splitlines() if "absent" in line)
        self.assertIn(self.path(self.LIBEXEC), absent)

    def test_box_usage_errors_exit_2(self):
        for argv in (
            ("check", "--box"),
            ("check", "--box", "prod-02"),
            ("check", "--box", "PROD-01"),
            ("check", "--box", "prod-01", "extra"),
            ("check", "--box=prod-01"),
            ("check", "prod-01"),
            ("--box", "prod-01", "check"),
        ):
            with self.subTest(argv=argv):
                result = self.run_guard(*argv)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertNotIn("deploy-ownership-guard: ok", result.stdout)


class Prod01WorkflowWiringTests(unittest.TestCase):
    """PAT-2312: deploy-prod01-backup.yml, read as text."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = PROD01_WORKFLOW_PATH.read_text(encoding="utf-8")

    def step_index(self, name: str) -> int:
        marker = f"- name: {name}\n"
        self.assertIn(marker, self.workflow, f"step {name!r} is missing")
        return self.workflow.index(marker)

    def test_the_rsync_to_prod01_sets_root_ownership(self):
        commands, unparsed = rsync_commands(self.workflow)
        self.assertEqual(unparsed, [])
        to_box = [c for c in commands if "root@patched-prod-01:" in c]
        self.assertEqual(len(to_box), 1, commands)
        self.assertIn("--chown=root:root", to_box[0].split())
        self.assertIn("root@patched-prod-01:/opt/patched-backup-setup/", to_box[0].split())
        self.assertEqual(rsync_findings(self.workflow, "patched-prod-01"), [])

    def test_the_rsync_check_fails_on_the_pre_pat2312_workflow(self):
        # Red: the real workflow with --chown removed is exactly what shipped
        # before PAT-2312, and the check must report it.
        self.assertIn("--chown=root:root", self.workflow)
        before = self.workflow.replace(" --chown=root:root", "")
        findings = rsync_findings(before, "patched-prod-01")
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("patched-prod-01 without --chown=root:root", findings[0])

    def test_the_check_pipes_the_runners_copy_with_the_prod01_set(self):
        body = "\n".join(code_lines(workflow_step(self.workflow, PROD01_CHECK)))
        self.assertIn("root@patched-prod-01", body)
        self.assertIn("/bin/bash --noprofile --norc -s -- check --box prod-01", body)
        self.assertIn(f"< {GUARD_REL}", body)
        self.assertIn("/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin", body)
        self.assertIn("BatchMode=yes", body)

    def test_no_step_runs_a_copy_of_the_check_from_the_box(self):
        references = [
            line.strip() for line in code_lines(self.workflow) if "deploy-ownership-guard" in line
        ]
        self.assertEqual(references, [f"< {GUARD_REL} || rc=$?"])
        self.assertFalse((PROD01_ARTEFACTS / "deploy-ownership-guard.sh").exists())

    def test_the_check_runs_after_the_rsync_and_before_install_sh(self):
        copy = self.step_index(PROD01_COPY)
        check = self.step_index(PROD01_CHECK)
        install = self.step_index(PROD01_INSTALL)
        self.assertLess(copy, check)
        self.assertLess(check, install)
        # install.sh is run in exactly one place, and that is after the check.
        runs = [m.start() for m in re.finditer(r"bash /opt/patched-backup-setup/install\.sh", self.workflow)]
        self.assertEqual(len(runs), 1, runs)
        self.assertLess(check, runs[0])
        # The check step itself neither continues on error nor is conditional.
        step = workflow_step(self.workflow, PROD01_CHECK)
        self.assertNotIn("continue-on-error", step)
        self.assertNotRegex(step, r"(?m)^\s+if:")

    def test_an_unreachable_box_is_not_reported_as_an_ownership_finding(self):
        body = workflow_step(self.workflow, PROD01_CHECK)
        self.assertIn('"$rc" -eq 255', body)
        self.assertIn("SSH/network failure", body)
        self.assertIn('exit "$rc"', body)
        for line in body.splitlines():
            if "::error::" in line:
                self.assertNotIn(">&2", line)

    def test_no_reclaim_step_is_needed_or_present(self):
        # The rsync's --chown re-owns the tree before the check, so nothing in
        # this workflow chowns anything by hand.
        for line in code_lines(self.workflow):
            self.assertNotRegex(line, r"(?:^|[\s;&|'\"])chown\s", line)

    def test_the_workflow_runs_these_tests_before_it_touches_the_box(self):
        verify = workflow_step(self.workflow, "Verify root-owned operational script path")
        self.assertIn("python3 -m unittest deploy.api-01.test_pat2310_deploy_ownership_guard -v", verify)
        self.assertLess(
            self.step_index("Verify root-owned operational script path"),
            self.step_index("Connect to Tailscale"),
        )


if __name__ == "__main__":
    unittest.main()
