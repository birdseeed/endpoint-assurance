"""PAT-2312: `patched` on patched-api-01 is a service account, not a login.

`patched` (uid 1000) is the User= of every Patched service on api-01. It was
also an admin login: /etc/sudoers.d/patched granted NOPASSWD ALL, it was in
`sudo`, its shell was /bin/bash and ~/.ssh/authorized_keys held a key. Its home
held leftovers from ad-hoc sessions. deploy/api-01/service-account-hygiene.sh
removes all of that (`apply`) and fails the deploy while any of it is back
(`check`).

The script is run for real against a fake root prefix. The account tools it
calls (getent, id, gpasswd, usermod, visudo, sudo) are PATH shims that keep
the fake account's state in files and record every call, so no test touches
the real account database or sudoers. Commands the script must never run
(systemctl and friends) are shims that record the call and fail.

The script refuses its test-only prefix when running as root. Tests here run
as an ordinary user, so that refusal is proven in CI by
test_root_production_integration.sh, which runs as root in a disposable
container, and here too when the suite happens to run as root or can use
`unshare -r`.

Run with: python3 -m unittest deploy.api-01.test_pat2312_service_account_hygiene -v
(or via `python3 -m unittest discover -s deploy/api-01 -p 'test_*.py'`)
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "deploy" / "api-01" / "service-account-hygiene.sh"
SCRIPT_REL = "deploy/api-01/service-account-hygiene.sh"
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "deploy-api-01.yml"
GO_TEST_PATH = REPO_ROOT / ".github" / "workflows" / "go-test.yml"
BUILD_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "api-build.yml"
ROOT_HARNESS = REPO_ROOT / "deploy" / "api-01" / "test_root_production_integration.sh"
ARTEFACTS = REPO_ROOT / "api-vps-artefacts"
ARTEFACT_MANIFEST = ARTEFACTS / "artefact-manifest.json"
GO_SERVICE = REPO_ROOT / "go-service"

_CHECK_MODULE_PATH = Path(__file__).with_name("check_binary_inventory.py")
_SPEC = importlib.util.spec_from_file_location("check_binary_inventory", _CHECK_MODULE_PATH)
assert _SPEC and _SPEC.loader
_CHECK_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_CHECK_MODULE)
workflow_step = _CHECK_MODULE.workflow_step

OVERRIDE = "PATCHED_SERVICE_ACCOUNT_HYGIENE_PREFIX"

HYGIENE_STEP = "Keep the patched service account without login or sudo on api-01"
LATE_CHECK = "Re-check root-run paths on api-01 after every file is placed"
READBACK = "Read back three-binary provenance and timer state"

# The account as it was on api-01 on 2026-09-30.
LIVE_PASSWD = "patched:x:1000:1000:,,,:/home/patched:/bin/bash"
LIVE_GROUPS = "patched sudo users"
NOLOGIN = "/usr/sbin/nologin"

# Ubuntu 24.04's /etc/sudoers, as on the box.
SUDOERS = """#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults\tenv_reset
Defaults\tmail_badpass
Defaults\tsecure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
Defaults\tuse_pty

# User privilege specification
root\tALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo\tALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "@include" directives:

@includedir /etc/sudoers.d
"""
SUDOERS_README = """#
# The default /etc/sudoers file created on installation of the
# sudo  package now includes the directive:
#
# \t@includedir /etc/sudoers.d
#
# This will cause sudo to read and parse any files in the /etc/sudoers.d
# directory that do not end in '~' or contain a '.' character.
#
"""
CLOUD_INIT_USERS = "# Created by cloud-init on instance boot automatically, do not edit.\n#\n\n# User rules for root\nroot ALL=(ALL) NOPASSWD:ALL\n"
DROPIN = "patched ALL=(ALL) NOPASSWD: ALL\n"

# The home directory on the box: what stays, and what apply removes.
HOME_KEEP = {
    ".bashrc": "f",
    ".profile": "f",
    ".bash_logout": "f",
    ".cloud-locale-test.skip": "f",
    ".cache": "d",
    ".cache/motd.legal-displayed": "f",
    ".ssh": "d",
}
HOME_REMOVE = {
    ".ssh/authorized_keys": "f",
    ".ssh/known_hosts": "f",
    "patched-api-new": "f",
    "patched-rules-new.yml": "f",
    "rules-dedupe.yml": "f",
    ".cursor": "d",
    ".cursor/argv.json": "f",
    ".cursor/extensions": "d",
    ".cursor/extensions/extensions.json": "f",
    ".cursor-server": "d",
    ".cursor-server/bin": "d",
    ".cursor-server/bin/node": "f",
    ".bash_history": "f",
    ".psql_history": "f",
    ".lesshst": "f",
    ".sudo_as_admin_successful": "f",
}
# The top-level paths apply removes, each logged once.
REMOVED_TOP = [rel for rel in HOME_REMOVE if rel.count("/") == 0 or rel.startswith(".ssh/")]

# The exact LEFTOVERS allowlist in the script.
EXPECTED_LEFTOVERS = [
    ("f", ".ssh/authorized_keys"),
    ("f", ".ssh/authorized_keys2"),
    ("f", ".ssh/known_hosts"),
    ("f", "patched-api-new"),
    ("f", "patched-rules-new.yml"),
    ("f", "rules-dedupe.yml"),
    ("d", ".cursor"),
    ("d", ".cursor-server"),
    ("f", ".bash_history"),
    ("f", ".psql_history"),
    ("f", ".lesshst"),
    ("f", ".sudo_as_admin_successful"),
]

SHIMS = {
    "getent": r"""#!/bin/sh
printf 'getent %s\n' "$*" >> "$PAT2312_FAKE_STATE/calls.log"
if [ "$#" -eq 2 ] && [ "$1" = passwd ] && [ "$2" = patched ] && [ -f "$PAT2312_FAKE_STATE/passwd" ]; then
  cat "$PAT2312_FAKE_STATE/passwd"
  exit 0
fi
exit 2
""",
    "id": r"""#!/bin/sh
printf 'id %s\n' "$*" >> "$PAT2312_FAKE_STATE/calls.log"
if [ "$*" = "-nG patched" ] && [ -f "$PAT2312_FAKE_STATE/passwd" ]; then
  cat "$PAT2312_FAKE_STATE/groups"
  exit 0
fi
echo "id: 'patched': no such user" >&2
exit 1
""",
    "gpasswd": r"""#!/bin/sh
S="$PAT2312_FAKE_STATE"
printf 'gpasswd %s\n' "$*" >> "$S/calls.log"
if [ "$#" -ne 3 ] || [ "$1" != -d ] || [ "$2" != patched ]; then
  echo "gpasswd shim: unexpected arguments: $*" >&2
  exit 2
fi
if [ -f "$S/gpasswd_fail" ]; then
  echo "gpasswd: cannot lock /etc/group; try again later." >&2
  exit 1
fi
kept=""
found=0
for g in $(cat "$S/groups"); do
  if [ "$g" = "$3" ]; then found=1; else kept="$kept${kept:+ }$g"; fi
done
if [ "$found" -ne 1 ]; then
  echo "gpasswd: user 'patched' is not a member of '$3'" >&2
  exit 3
fi
printf '%s\n' "$kept" > "$S/groups"
echo "Removing user patched from group $3"
""",
    "usermod": r"""#!/bin/sh
S="$PAT2312_FAKE_STATE"
printf 'usermod %s\n' "$*" >> "$S/calls.log"
if [ "$#" -ne 3 ] || [ "$1" != -s ] || [ "$3" != patched ]; then
  echo "usermod shim: only 'usermod -s SHELL patched' is expected, got: $*" >&2
  exit 2
fi
if [ -f "$S/usermod_fail" ]; then
  echo "usermod: cannot lock /etc/passwd; try again later." >&2
  exit 1
fi
line="$(cat "$S/passwd")"
printf '%s:%s\n' "${line%:*}" "$2" > "$S/passwd"
""",
    "visudo": r"""#!/bin/sh
S="$PAT2312_FAKE_STATE"
printf 'visudo %s\n' "$*" >> "$S/calls.log"
[ "$*" = "-c" ] || { echo "visudo shim: unexpected arguments: $*" >&2; exit 2; }
if [ -f "$S/visudo_fail" ]; then
  echo "/etc/sudoers.d/broken:1:9: syntax error" >&2
  exit 1
fi
echo "/etc/sudoers: parsed OK"
""",
    # Grants when patched is in sudo or admin, or a sudoers line starts with
    # its name, unless the test supplies sudo's answer outright.
    "sudo": r"""#!/bin/sh
S="$PAT2312_FAKE_STATE"
R="$PAT2312_FAKE_ROOT"
printf 'sudo %s\n' "$*" >> "$S/calls.log"
[ "$*" = "-n -l -U patched" ] || { echo "sudo shim: unexpected arguments: $*" >&2; exit 2; }
if [ -f "$S/sudo_output" ]; then
  cat "$S/sudo_output"
  exit "$(cat "$S/sudo_rc" 2>/dev/null || echo 0)"
fi
grants=0
for g in $(cat "$S/groups"); do
  case "$g" in sudo|admin) grants=1 ;; esac
done
if grep -qs '^patched[[:space:]]' "$R/etc/sudoers" "$R"/etc/sudoers.d/*; then
  grants=1
fi
if [ "$grants" -eq 1 ]; then
  printf 'Matching Defaults entries for patched on fakehost:\n    env_reset, use_pty\n\n'
  printf 'User patched may run the following commands on fakehost:\n    (ALL : ALL) ALL\n'
else
  echo "User patched is not allowed to run sudo on fakehost."
fi
""",
}
# Commands the script must never run: each records the call and fails.
FORBIDDEN = ("systemctl", "service", "passwd", "chage", "chsh", "userdel", "pkill", "killall", "loginctl")


def code_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


class _FakeBox(unittest.TestCase):
    """A fake api-01: a root prefix with sudoers and the home directory, and
    shims standing in for the account database."""

    def setUp(self) -> None:
        if os.geteuid() == 0:
            self.skipTest(
                "the script refuses its test-only prefix as root; CI runs this suite "
                "as the unprivileged runner user and proves the refusal in the root harness"
            )
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="pat2312-"))
        self.addCleanup(self._cleanup)
        self.root = os.path.join(self.tmp, "root")
        self.state = os.path.join(self.tmp, "state")
        self.shims = os.path.join(self.tmp, "shims")
        self.outside = os.path.join(self.tmp, "outside")
        for path in (self.root, self.state, self.shims, self.outside):
            os.mkdir(path)
        for name, body in SHIMS.items():
            self._write_shim(name, body)
        for name in FORBIDDEN:
            self._write_shim(
                name,
                f"#!/bin/sh\nprintf '{name} %s\\n' \"$*\" >> \"$PAT2312_FAKE_STATE/calls.log\"\nexit 99\n",
            )
        self.build_dirty_box()

    def _write_shim(self, name: str, body: str) -> None:
        path = os.path.join(self.shims, name)
        Path(path).write_text(body, encoding="utf-8")
        os.chmod(path, 0o755)

    def _cleanup(self) -> None:
        for root, dirs, _files in os.walk(self.tmp):
            for name in dirs:
                path = os.path.join(root, name)
                if not os.path.islink(path):
                    os.chmod(path, 0o755)
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- building the box ------------------------------------------------------

    def write(self, rel: str, text: str, mode: int = 0o644) -> str:
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.lexists(path):
            os.remove(path)
        Path(path).write_text(text, encoding="utf-8")
        os.chmod(path, mode)
        return path

    def home(self, rel: str = "") -> str:
        return os.path.join(self.root, "home/patched", rel) if rel else os.path.join(self.root, "home/patched")

    def build_home(self, base: str) -> None:
        for rel, kind in sorted({**HOME_KEEP, **HOME_REMOVE}.items()):
            path = os.path.join(base, rel)
            if kind == "d":
                os.makedirs(path, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                Path(path).write_text(f"{rel}\n", encoding="utf-8")
        os.chmod(os.path.join(base, ".ssh"), 0o700)
        os.chmod(base, 0o750)

    def build_dirty_box(self) -> None:
        self.write("etc/sudoers", SUDOERS, 0o440)
        self.write("etc/sudoers.d/README", SUDOERS_README, 0o440)
        self.write("etc/sudoers.d/90-cloud-init-users", CLOUD_INIT_USERS, 0o440)
        self.write("etc/sudoers.d/patched", DROPIN, 0o440)
        os.chmod(os.path.join(self.root, "etc/sudoers.d"), 0o750)
        self.build_home(self.home())
        self.set_account(LIVE_PASSWD, LIVE_GROUPS)

    def make_clean(self) -> None:
        """The state apply leaves: no drop-in, no privileged group, nologin,
        no key files or leftovers."""
        os.remove(os.path.join(self.root, "etc/sudoers.d/patched"))
        for rel in sorted(HOME_REMOVE, reverse=True):
            path = self.home(rel)
            if os.path.isdir(path):
                os.rmdir(path)
            else:
                os.remove(path)
        self.set_account(LIVE_PASSWD.rsplit(":", 1)[0] + ":" + NOLOGIN, "patched users")

    def set_account(self, passwd: str | None, groups: str | None = None) -> None:
        passwd_path = os.path.join(self.state, "passwd")
        if passwd is None:
            if os.path.exists(passwd_path):
                os.remove(passwd_path)
        else:
            Path(passwd_path).write_text(passwd + "\n", encoding="utf-8")
        if groups is not None:
            Path(self.state, "groups").write_text(groups + "\n", encoding="utf-8")

    def set_shell(self, shell: str) -> None:
        self.set_account(LIVE_PASSWD.rsplit(":", 1)[0] + ":" + shell)

    def fail_tool(self, name: str) -> None:
        Path(self.state, f"{name}_fail").write_text("", encoding="utf-8")

    def sudo_answers(self, output: str, rc: int = 0) -> None:
        Path(self.state, "sudo_output").write_text(output, encoding="utf-8")
        Path(self.state, "sudo_rc").write_text(f"{rc}\n", encoding="utf-8")

    # -- running the script --------------------------------------------------

    def env(self, **extra: str) -> dict[str, str]:
        env = {
            "PATH": f"{self.shims}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            OVERRIDE: self.root,
            "PAT2312_FAKE_STATE": self.state,
            "PAT2312_FAKE_ROOT": self.root,
        }
        env.update(extra)
        return env

    def run_script(
        self, *argv: str, piped: bool = False, env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = self.env() if env is None else env
        if piped:
            # Exactly how the workflow runs it: the script arrives on stdin.
            with SCRIPT_PATH.open("rb") as script:
                result = subprocess.run(
                    ["bash", "-s", "--", *argv], stdin=script, env=env,
                    capture_output=True, timeout=60,
                )
            return subprocess.CompletedProcess(
                result.args, result.returncode,
                result.stdout.decode("utf-8"), result.stderr.decode("utf-8"),
            )
        return subprocess.run(
            ["bash", str(SCRIPT_PATH), *argv], env=env, capture_output=True,
            text=True, timeout=60, stdin=subprocess.DEVNULL,
        )

    def calls(self) -> list[str]:
        path = Path(self.state, "calls.log")
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    def clear_calls(self) -> None:
        Path(self.state, "calls.log").unlink(missing_ok=True)

    def account(self) -> tuple[str, str]:
        passwd_path = Path(self.state, "passwd")
        passwd = passwd_path.read_text(encoding="utf-8").strip() if passwd_path.exists() else "<none>"
        groups = Path(self.state, "groups").read_text(encoding="utf-8").strip()
        return passwd, groups

    def snapshot(self) -> dict[str, str]:
        """Every path under the tmp root and outside, with its kind and content."""
        seen: dict[str, str] = {}
        for base in (self.root, self.outside):
            for root, dirs, files in os.walk(base):
                for name in dirs + files:
                    path = os.path.join(root, name)
                    rel = os.path.relpath(path, self.tmp)
                    if os.path.islink(path):
                        seen[rel] = "l:" + os.readlink(path)
                    elif os.path.isdir(path):
                        seen[rel] = "d"
                    elif stat.S_ISFIFO(os.lstat(path).st_mode):
                        seen[rel] = "p"
                    else:
                        seen[rel] = "f:" + Path(path).read_text(encoding="utf-8")
        seen["state/passwd"], seen["state/groups"] = self.account()
        return seen

    @staticmethod
    def errors(result: subprocess.CompletedProcess[str]) -> list[str]:
        return [line for line in result.stdout.splitlines() if line.startswith("::error::")]

    def assert_error(self, result: subprocess.CompletedProcess[str], *needles: str) -> None:
        for needle in needles:
            self.assertTrue(
                any(needle in line for line in self.errors(result)),
                f"no ::error:: line contains {needle!r}:\n{result.stdout}{result.stderr}",
            )

    def assert_no_forbidden_calls(self) -> None:
        for call in self.calls():
            self.assertNotIn(call.split()[0], FORBIDDEN, self.calls())


class ApplyTests(_FakeBox):
    """`apply` on a fake box in the shape api-01 was in on 2026-09-30."""

    def test_check_fails_on_the_live_shape_naming_every_finding(self):
        result = self.run_script("check")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assert_error(
            result,
            f"{self.root}/etc/sudoers.d/patched exists",
            f"{self.root}/etc/sudoers.d/patched:1 names patched: patched ALL=(ALL) NOPASSWD: ALL",
            "patched is in group sudo",
            "the shell of patched is '/bin/bash'",
            f"{self.home('.ssh/authorized_keys')} exists",
            "sudo -l -U patched lists commands it may run: (ALL : ALL) ALL",
            "6 finding(s)",
        )
        self.assertNotIn("ok:", result.stdout)

    def test_apply_on_the_live_shape_then_check_passes(self):
        result = self.run_script("apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.errors(result), [])

        self.assertFalse(os.path.lexists(os.path.join(self.root, "etc/sudoers.d/patched")))
        for rel in ("etc/sudoers", "etc/sudoers.d/README", "etc/sudoers.d/90-cloud-init-users"):
            self.assertTrue(os.path.isfile(os.path.join(self.root, rel)), rel)
        passwd, groups = self.account()
        self.assertEqual(passwd, "patched:x:1000:1000:,,,:/home/patched:/usr/sbin/nologin")
        self.assertEqual(groups.split(), ["patched", "users"])
        for rel in HOME_REMOVE:
            self.assertFalse(os.path.lexists(self.home(rel)), rel)
        for rel, kind in HOME_KEEP.items():
            self.assertTrue(os.path.isdir(self.home(rel)) if kind == "d" else os.path.isfile(self.home(rel)), rel)
        self.assertTrue(os.path.isdir(self.home()))

        calls = self.calls()
        self.assertIn("visudo -c", calls)
        self.assertEqual([c for c in calls if c.startswith("gpasswd")], ["gpasswd -d patched sudo"])
        self.assertEqual([c for c in calls if c.startswith("usermod")], ["usermod -s /usr/sbin/nologin patched"])
        self.assert_no_forbidden_calls()

        check = self.run_script("check")
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
        self.assertEqual(self.errors(check), [])
        self.assertIn("service-account-hygiene: ok:", check.stdout)

    def test_apply_logs_each_change(self):
        result = self.run_script("apply")
        self.assertEqual(result.returncode, 0, result.stdout)
        changes = [line for line in result.stdout.splitlines() if "changed:" in line]
        self.assertIn(f"removed {self.root}/etc/sudoers.d/patched, the NOPASSWD sudo rule for patched.", result.stdout)
        self.assertIn("removed patched from group sudo.", result.stdout)
        self.assertIn("set the shell of patched from '/bin/bash' to /usr/sbin/nologin.", result.stdout)
        self.assertIn("visudo -c: the sudoers configuration parses.", result.stdout)
        for rel in REMOVED_TOP:
            with self.subTest(rel=rel):
                self.assertTrue(any(f"removed {self.home(rel)}" in line for line in changes), result.stdout)
        # One drop-in, one group, one shell, and each top-level leftover once.
        self.assertEqual(len(changes), 3 + len(REMOVED_TOP), result.stdout)
        self.assertIn(f"apply: {len(changes)} change(s) made.", result.stdout)

    def test_apply_is_idempotent(self):
        first = self.run_script("apply")
        self.assertEqual(first.returncode, 0, first.stdout)
        after_first = self.snapshot()
        self.clear_calls()

        second = self.run_script("apply")
        self.assertEqual(second.returncode, 0, second.stdout)
        self.assertEqual(self.errors(second), [])
        self.assertNotIn("changed:", second.stdout)
        self.assertIn("apply: nothing to change.", second.stdout)
        self.assertEqual(self.snapshot(), after_first)
        # Only reads and the sudoers parse check the second time round.
        self.assertEqual(
            sorted({c.split()[0] for c in self.calls()}), ["getent", "id", "visudo"], self.calls(),
        )
        self.assertEqual(self.run_script("check").returncode, 0)

    def test_apply_and_check_piped_the_way_the_workflow_runs_them(self):
        applied = self.run_script("apply", piped=True)
        self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
        self.assertIn("apply: 14 change(s) made.", applied.stdout)
        checked = self.run_script("check", piped=True)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        self.assertIn("service-account-hygiene: ok:", checked.stdout)

    def test_apply_removes_admin_and_wheel_as_well_as_sudo(self):
        self.set_account(LIVE_PASSWD, "patched wheel sudo users admin")
        result = self.run_script("apply")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(
            [c for c in self.calls() if c.startswith("gpasswd")],
            ["gpasswd -d patched sudo", "gpasswd -d patched admin", "gpasswd -d patched wheel"],
        )
        self.assertEqual(self.account()[1].split(), ["patched", "users"])
        self.assertEqual(self.run_script("check").returncode, 0)

    def test_apply_leaves_a_shell_that_already_cannot_log_in(self):
        for shell in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"):
            with self.subTest(shell=shell):
                self.set_shell(shell)
                self.clear_calls()
                result = self.run_script("apply")
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertEqual([c for c in self.calls() if c.startswith("usermod")], [])
                self.assertTrue(self.account()[0].endswith(":" + shell))

    def test_apply_replaces_an_empty_shell_field_which_means_bin_sh(self):
        self.set_shell("")
        result = self.run_script("apply")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("usermod -s /usr/sbin/nologin patched", self.calls())
        self.assertTrue(self.account()[0].endswith(":/usr/sbin/nologin"))

    def test_apply_never_touches_a_service_or_locks_the_account(self):
        self.run_script("apply")
        self.assert_no_forbidden_calls()
        for call in self.calls():
            if call.startswith("usermod"):
                self.assertEqual(call, "usermod -s /usr/sbin/nologin patched")
        # Commands, not the words in messages: drop quoted strings first.
        code = "\n".join(code_lines(SCRIPT_PATH.read_text(encoding="utf-8")))
        code = re.sub(r'"(?:[^"\\]|\\.)*"|\'[^\']*\'', '""', code)
        for pattern in (
            r"\bsystemctl\b", r"\bservice\s", r"\bkill\b", r"\bpkill\b", r"\bchage\b",
            r"\bpasswd\s+-", r"usermod\s+-[a-zA-Z]*[LUe]", r"\buserdel\b", r"\bloginctl\b",
        ):
            self.assertNotRegex(code, pattern)

    # -- failures are loud, and do not stop the other steps ----------------------

    def test_a_failing_visudo_fails_apply_loudly(self):
        self.fail_tool("visudo")
        result = self.run_script("apply")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assert_error(result, "visudo -c failed", "syntax error", "problem(s) above")
        # The other steps are independent and still ran.
        self.assertFalse(os.path.lexists(os.path.join(self.root, "etc/sudoers.d/patched")))
        self.assertEqual(self.account()[1].split(), ["patched", "users"])
        self.assertFalse(os.path.lexists(self.home(".ssh/authorized_keys")))

    def test_a_failing_gpasswd_fails_apply_loudly(self):
        self.fail_tool("gpasswd")
        result = self.run_script("apply")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assert_error(result, "gpasswd -d patched sudo failed", "patched is still in group sudo")
        self.assertEqual(self.run_script("check").returncode, 1)

    def test_a_failing_usermod_fails_apply_loudly(self):
        self.fail_tool("usermod")
        result = self.run_script("apply")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assert_error(result, "usermod -s /usr/sbin/nologin patched failed; its shell is still '/bin/bash'")

    def test_no_passwd_entry_changes_nothing(self):
        self.set_account(None)
        before = self.snapshot()
        for command in ("apply", "check"):
            with self.subTest(command=command):
                result = self.run_script(command)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assert_error(result, "patched has no passwd entry")
        self.assertEqual(self.snapshot(), before)
        self.assertEqual([c for c in self.calls() if not c.startswith("getent")], [])

    def test_a_home_directory_other_than_the_expected_one_is_refused(self):
        self.set_account("patched:x:1000:1000:,,,:/srv/patched:/bin/bash")
        result = self.run_script("apply")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assert_error(result, "home directory of patched is '/srv/patched', not /home/patched")
        for rel in HOME_REMOVE:
            self.assertTrue(os.path.lexists(self.home(rel)), rel)
        check = self.run_script("check")
        self.assertEqual(check.returncode, 1, check.stdout)
        self.assert_error(check, "so its SSH key files were not checked")


class SymlinkAndKindTests(_FakeBox):
    """A root rm in a directory another user owns must never follow a link."""

    def outside_file(self, rel: str, text: str = "precious\n") -> str:
        path = os.path.join(self.outside, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        Path(path).write_text(text, encoding="utf-8")
        return path

    def replace_with_link(self, rel: str, target: str) -> None:
        path = self.home(rel)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        elif os.path.lexists(path):
            os.remove(path)
        os.symlink(target, path)

    def test_a_symlinked_leftover_file_is_unlinked_not_followed(self):
        target = self.outside_file("usr/local/bin/important")
        self.replace_with_link("patched-api-new", target)
        result = self.run_script("apply")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertFalse(os.path.lexists(self.home("patched-api-new")))
        self.assertEqual(Path(target).read_text(encoding="utf-8"), "precious\n")
        self.assertIn(f"unlinked {self.home('patched-api-new')}, a symlink to {target}.", result.stdout)

    def test_a_symlinked_leftover_directory_is_unlinked_not_followed(self):
        target_dir = os.path.join(self.outside, "srv/data")
        kept = self.outside_file("srv/data/keep.db")
        self.replace_with_link(".cursor-server", target_dir)
        result = self.run_script("apply")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertFalse(os.path.lexists(self.home(".cursor-server")))
        self.assertEqual(Path(kept).read_text(encoding="utf-8"), "precious\n")

    def test_a_symlink_inside_a_leftover_directory_is_not_followed(self):
        kept = self.outside_file("srv/data/keep.db")
        os.symlink(os.path.join(self.outside, "srv/data"), self.home(".cursor/linked-data"))
        os.symlink(kept, self.home(".cursor/linked-file"))
        result = self.run_script("apply")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertFalse(os.path.lexists(self.home(".cursor")))
        self.assertEqual(Path(kept).read_text(encoding="utf-8"), "precious\n")

    def test_a_symlinked_authorized_keys_is_unlinked_not_followed(self):
        # The shape that matters most: a link to root's own key file.
        root_keys = self.outside_file("root/.ssh/authorized_keys", "deploy key placeholder\n")
        self.replace_with_link(".ssh/authorized_keys", root_keys)
        result = self.run_script("apply")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertFalse(os.path.lexists(self.home(".ssh/authorized_keys")))
        self.assertEqual(Path(root_keys).read_text(encoding="utf-8"), "deploy key placeholder\n")

    def test_a_symlinked_ssh_directory_is_refused_and_nothing_through_it_removed(self):
        root_keys = self.outside_file("root/.ssh/authorized_keys", "deploy key placeholder\n")
        root_hosts = self.outside_file("root/.ssh/known_hosts", "hosts\n")
        self.replace_with_link(".ssh", os.path.join(self.outside, "root/.ssh"))
        result = self.run_script("apply")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assert_error(result, f"{self.home('.ssh')} is a symlink to", "Nothing under it was removed")
        # Said once, not once per key file under it.
        self.assertEqual(sum(f"{self.home('.ssh')} is a symlink" in line for line in self.errors(result)), 1)
        self.assertEqual(Path(root_keys).read_text(encoding="utf-8"), "deploy key placeholder\n")
        self.assertEqual(Path(root_hosts).read_text(encoding="utf-8"), "hosts\n")
        self.assertTrue(os.path.islink(self.home(".ssh")))
        # Everything not under the link was still dealt with.
        self.assertFalse(os.path.lexists(self.home("patched-api-new")))
        self.assertFalse(os.path.lexists(os.path.join(self.root, "etc/sudoers.d/patched")))
        # check sees the key file sshd would read through the link.
        check = self.run_script("check")
        self.assertEqual(check.returncode, 1, check.stdout)
        self.assert_error(check, f"{self.home('.ssh/authorized_keys')} exists")

    def test_a_symlinked_home_directory_is_refused(self):
        elsewhere = os.path.join(self.outside, "elsewhere")
        self.build_home(elsewhere)
        before = {rel: os.path.lexists(os.path.join(elsewhere, rel)) for rel in HOME_REMOVE}
        shutil.rmtree(self.home())
        os.symlink(elsewhere, self.home())
        result = self.run_script("apply")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assert_error(result, f"{self.home()} is a symlink to")
        self.assertEqual({rel: os.path.lexists(os.path.join(elsewhere, rel)) for rel in HOME_REMOVE}, before)
        self.assertTrue(all(before.values()))

    def test_a_leftover_of_an_unexpected_kind_is_refused_and_left_alone(self):
        os.remove(self.home("patched-api-new"))
        os.mkdir(self.home("patched-api-new"))
        Path(self.home("patched-api-new/inside")).write_text("x\n", encoding="utf-8")
        shutil.rmtree(self.home(".cursor"))
        Path(self.home(".cursor")).write_text("not a directory\n", encoding="utf-8")
        os.remove(self.home(".lesshst"))
        os.mkfifo(self.home(".lesshst"))
        result = self.run_script("apply")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assert_error(
            result,
            f"{self.home('patched-api-new')} is a directory, not a regular file as expected. Left alone",
            f"{self.home('.cursor')} is a regular file, not a directory as expected. Left alone",
            f"{self.home('.lesshst')} is a named pipe, not a regular file as expected. Left alone",
        )
        self.assertTrue(os.path.isfile(self.home("patched-api-new/inside")))
        self.assertTrue(os.path.isfile(self.home(".cursor")))
        self.assertTrue(stat.S_ISFIFO(os.lstat(self.home(".lesshst")).st_mode))
        self.assertFalse(os.path.lexists(self.home("rules-dedupe.yml")))
        self.assertFalse(os.path.lexists(self.home(".cursor-server")))


class CheckTests(_FakeBox):
    """`check` on a box apply has already cleaned, with one thing put back."""

    def setUp(self) -> None:
        super().setUp()
        self.make_clean()

    def assert_only(self, result: subprocess.CompletedProcess[str], *needles: str) -> None:
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assert_error(result, *needles)
        per_item = [line for line in self.errors(result) if "finding(s):" not in line]
        self.assertEqual(len(per_item), len(needles), result.stdout)
        self.assertIn(f"{len(needles)} finding(s)", result.stdout)

    def test_a_clean_box_passes(self):
        result = self.run_script("check")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.errors(result), [])
        self.assertIn("service-account-hygiene: ok:", result.stdout)

    def test_check_changes_nothing(self):
        self.build_dirty_box()
        before = self.snapshot()
        result = self.run_script("check")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(
            sorted({c.split()[0] for c in self.calls()}), ["getent", "id", "sudo"], self.calls(),
        )

    # -- sudoers -------------------------------------------------------------------

    def test_the_drop_in_fails_even_when_empty(self):
        self.write("etc/sudoers.d/patched", "", 0o440)
        self.assert_only(self.run_script("check"), f"{self.root}/etc/sudoers.d/patched exists")

    def test_a_rule_naming_patched_in_another_drop_in_fails(self):
        self.write("etc/sudoers.d/50-ops", "patched ALL=(ALL) ALL\n", 0o440)
        self.assert_only(
            self.run_script("check"),
            f"{self.root}/etc/sudoers.d/50-ops:1 names patched",
            "sudo -l -U patched lists commands it may run",
        )

    def test_a_rule_for_another_host_fails_although_sudo_l_does_not_list_it(self):
        # sudo -l -U reports only this host's rules; the file read catches it.
        self.write("etc/sudoers.d/50-ops", "# ops\npatched otherhost = (ALL) ALL\n", 0o440)
        self.sudo_answers("User patched is not allowed to run sudo on fakehost.\n")
        self.assert_only(self.run_script("check"), f"{self.root}/etc/sudoers.d/50-ops:2 names patched")

    def test_uid_gid_alias_and_group_forms_fail(self):
        self.sudo_answers("User patched is not allowed to run sudo on fakehost.\n")
        for line in (
            "#1000 ALL=(ALL) ALL",
            "%#1000 ALL=(ALL) ALL",
            "%:#1000 ALL=(ALL) ALL",
            "%patched ALL=(ALL) ALL",
            "User_Alias OPS = alice, patched",
            "alice, patched ALL = (root) /usr/bin/true",
            "Defaults:patched !requiretty",
        ):
            with self.subTest(line=line):
                self.write("etc/sudoers", SUDOERS + line + "\n", 0o440)
                result = self.run_script("check")
                self.assert_only(result, f"{self.root}/etc/sudoers:{SUDOERS.count(chr(10)) + 1} names patched: {line}")

    def test_comments_and_other_names_are_not_findings(self):
        self.write(
            "etc/sudoers.d/60-notes",
            "# patched is a service account and gets no rule here\n"
            "#includedir /etc/sudoers.d/patched-extra\n"
            "root ALL=/usr/bin/systemctl restart patched-api # restart patched\n"
            "Defaults:alice env_keep += PATCHED_HOME\n"
            "alice ALL=(patched-ro) /usr/bin/true\n"
            "#10000 ALL=(ALL) ALL\n"
            "#\n",
            0o440,
        )
        result = self.run_script("check")
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_an_unreadable_sudoers_d_fails_closed(self):
        os.chmod(os.path.join(self.root, "etc/sudoers.d"), 0o000)
        result = self.run_script("check")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assert_error(result, "could not list", "could not be read")

    def test_an_unreadable_sudoers_file_fails_closed(self):
        os.chmod(os.path.join(self.root, "etc/sudoers.d/90-cloud-init-users"), 0o000)
        result = self.run_script("check")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assert_error(result, "could not read", "90-cloud-init-users")

    def test_a_missing_sudoers_fails_closed(self):
        os.remove(os.path.join(self.root, "etc/sudoers"))
        result = self.run_script("check")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assert_error(result, "etc/sudoers is missing")

    # -- groups, shell, keys -------------------------------------------------------

    def test_each_privileged_group_fails(self):
        self.sudo_answers("User patched is not allowed to run sudo on fakehost.\n")
        for group in ("sudo", "admin", "wheel"):
            with self.subTest(group=group):
                self.set_account(LIVE_PASSWD.rsplit(":", 1)[0] + ":" + NOLOGIN, f"patched {group} users")
                self.assert_only(self.run_script("check"), f"patched is in group {group}, which sudoers grants")

    def test_a_group_whose_name_merely_contains_sudo_passes(self):
        self.set_account(LIVE_PASSWD.rsplit(":", 1)[0] + ":" + NOLOGIN, "patched sudoers-audit nowheel users")
        self.assertEqual(self.run_script("check").returncode, 0)

    def test_every_login_shell_fails_and_every_nologin_shell_passes(self):
        for shell, label in (
            ("/bin/bash", "/bin/bash"),
            ("/bin/sh", "/bin/sh"),
            ("/usr/bin/zsh", "/usr/bin/zsh"),
            ("", "(empty, so /bin/sh)"),
            ("/usr/sbin/nologin.bak", "/usr/sbin/nologin.bak"),
        ):
            with self.subTest(shell=shell):
                self.set_shell(shell)
                self.assert_only(self.run_script("check"), f"the shell of patched is '{label}', a login shell")
        for shell in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"):
            with self.subTest(shell=shell):
                self.set_shell(shell)
                self.assertEqual(self.run_script("check").returncode, 0)

    def test_each_authorized_keys_file_fails(self):
        for name in ("authorized_keys", "authorized_keys2"):
            with self.subTest(name=name):
                path = self.home(f".ssh/{name}")
                Path(path).write_text("ssh-ed25519 PLACEHOLDER test\n", encoding="utf-8")
                self.assert_only(self.run_script("check"), f"{path} exists")
                os.remove(path)

    def test_a_dangling_authorized_keys_symlink_fails(self):
        os.symlink(os.path.join(self.outside, "missing"), self.home(".ssh/authorized_keys"))
        self.assert_only(self.run_script("check"), f"{self.home('.ssh/authorized_keys')} exists")

    def test_a_missing_home_directory_is_not_a_finding(self):
        shutil.rmtree(self.home())
        self.assertEqual(self.run_script("check").returncode, 0)

    def test_known_hosts_and_leftovers_alone_are_not_findings(self):
        # check is about login and sudo; the leftovers are apply's to tidy.
        Path(self.home(".ssh/known_hosts")).write_text("host\n", encoding="utf-8")
        Path(self.home(".bash_history")).write_text("ls\n", encoding="utf-8")
        self.assertEqual(self.run_script("check").returncode, 0)

    # -- sudo -l ----------------------------------------------------------------------

    def test_sudo_l_listing_commands_fails_even_when_nothing_else_does(self):
        # A rule no other check sees, such as `ALL ALL=(ALL) ALL`.
        self.sudo_answers(
            "Matching Defaults entries for patched on fakehost:\n    env_reset\n\n"
            "User patched may run the following commands on fakehost:\n"
            "    (ALL) ALL\n    (root) NOPASSWD: /usr/bin/true\n"
        )
        self.assert_only(
            self.run_script("check"),
            "sudo -l -U patched lists commands it may run: (ALL) ALL; (root) NOPASSWD: /usr/bin/true",
        )

    def test_an_answer_sudo_l_does_not_recognise_fails_closed(self):
        for output, rc in (
            ("sudo: unknown user patched\n", 1),
            ("User patched is not allowed to run sudo on fakehost.\n", 1),
            ("", 0),
            ("sudo: /etc/sudoers.d/broken:1:9: syntax error\n", 1),
        ):
            with self.subTest(output=output, rc=rc):
                self.sudo_answers(output, rc)
                result = self.run_script("check")
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assert_error(result, "could not tell from sudo -l -U patched whether it has sudo rights")
                self.assertNotIn("ok:", result.stdout)


class InvocationTests(_FakeBox):
    """Arguments, the test-only prefix, and where the output goes."""

    def test_usage_errors_exit_2(self):
        for argv in ((), ("check", "extra"), ("lock",), ("--apply",), ("Apply",)):
            with self.subTest(argv=argv):
                result = self.run_script(*argv)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(self.calls(), [])

    def test_non_root_without_the_prefix_is_refused_and_changes_nothing(self):
        before = self.snapshot()
        env = self.env()
        del env[OVERRIDE]
        for command in ("apply", "check"):
            with self.subTest(command=command):
                result = self.run_script(command, env=env)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assert_error(result, "must run as root on patched-api-01")
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.snapshot(), before)

    def test_bad_prefix_values_are_refused_and_change_nothing(self):
        before = self.snapshot()
        for value in ("relative/path", "/", os.path.join(self.tmp, "missing")):
            with self.subTest(value=value):
                result = self.run_script("apply", env=self.env(**{OVERRIDE: value}))
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("Nothing was changed.", result.stdout)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.snapshot(), before)

    def test_error_annotations_go_to_stdout(self):
        result = self.run_script("check")
        self.assertEqual(result.returncode, 1)
        self.assertTrue(self.errors(result))
        self.assertNotIn("::error::", result.stderr)


def _as_root_prefix() -> list[str] | None:
    """A command prefix that runs as uid 0, or None when there is none."""
    if os.geteuid() == 0:
        return []
    unshare = shutil.which("unshare")
    if unshare:
        probe = subprocess.run([unshare, "-r", "true"], capture_output=True, timeout=30)
        if probe.returncode == 0:
            return [unshare, "-r"]
    return None


class RootRefusalTests(unittest.TestCase):
    """As root the test-only prefix is refused before anything is read."""

    def test_overrides_are_refused_as_root(self):
        runner = _as_root_prefix()
        if runner is None:
            self.skipTest(
                "no way to run as uid 0 here; test_root_production_integration.sh "
                "proves this as real root in CI"
            )
        tmp = os.path.realpath(tempfile.mkdtemp(prefix="pat2312-root-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        dropin = Path(tmp, "etc/sudoers.d/patched")
        dropin.parent.mkdir(parents=True)
        dropin.write_text(DROPIN, encoding="utf-8")
        for value in (tmp, ""):
            for command in ("apply", "check"):
                with self.subTest(value=value, command=command):
                    with SCRIPT_PATH.open("rb") as script:
                        result = subprocess.run(
                            [*runner, "bash", "-s", "--", command], stdin=script,
                            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), OVERRIDE: value},
                            capture_output=True, timeout=60,
                        )
                    out = result.stdout.decode("utf-8")
                    self.assertEqual(result.returncode, 1, out)
                    self.assertIn(f"{OVERRIDE} is a test-only override and is refused when running as root", out)
        self.assertEqual(dropin.read_text(encoding="utf-8"), DROPIN)

    def test_the_root_branch_refuses_the_override_before_anything_else(self):
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        configure = source[source.index("configure() {"):]
        configure = configure[: configure.index("\n}\n")]
        root_branch = configure[configure.index('if [ "$EUID" -eq 0 ]; then'):configure.index("return 0")]
        self.assertIn("PATH=/usr/sbin:/usr/bin:/sbin:/bin", root_branch)
        self.assertIn("unset BASH_ENV ENV CDPATH", root_branch)
        self.assertIn('printenv "$name"', root_branch)
        self.assertEqual(re.search(r'^OVERRIDE_NAMES="([^"]*)"$', source, re.M).group(1), OVERRIDE)
        # Both commands configure before they load the account or read a file.
        for command in ("cmd_apply", "cmd_check"):
            body = source[source.index(f"{command}() {{"):]
            body = body[: body.index("\n}\n")]
            self.assertLess(body.index("configure"), body.index("load_account"))

    def test_the_root_harness_proves_the_refusal_as_real_root(self):
        harness = ROOT_HARNESS.read_text(encoding="utf-8")
        self.assertIn('< "$REPO_ROOT/deploy/api-01/service-account-hygiene.sh"', harness)
        self.assertIn(f"{OVERRIDE}=\"$hygiene_value\"", harness)
        self.assertIn('for hygiene_value in "$hygiene_prefix" ""; do', harness)
        self.assertIn("for hygiene_command in apply check; do", harness)
        self.assertIn(f"{OVERRIDE} is a test-only override and is refused when running as root", harness)
        self.assertLess(harness.index("hygiene_prefix"), harness.index('echo "root production integration passed"'))


class ScriptContractTests(unittest.TestCase):
    """What the script may remove, and the premise that `patched` needs no
    login and no sudo."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT_PATH.read_text(encoding="utf-8")

    def test_the_leftovers_are_an_exact_allowlist(self):
        block = self.source[self.source.index("LEFTOVERS=("):]
        block = block[: block.index("\n)\n")]
        entries = re.findall(r'^\s+"([fd]) ([^"\s]+)"$', block, re.M)
        self.assertEqual(entries, EXPECTED_LEFTOVERS)
        self.assertEqual(len(code_lines(block)) - 1, len(EXPECTED_LEFTOVERS), block)
        for _kind, rel in entries:
            self.assertNotRegex(rel, r"[*?\[\]{}~$]|\.\.")
            self.assertFalse(rel.startswith("/"))
        for keep in (".bashrc", ".profile", ".bash_logout", ".cache", ".ssh", ""):
            self.assertNotIn(keep, [rel for _kind, rel in entries])

    def test_the_fixed_paths_are_the_expected_ones(self):
        for line in (
            "SERVICE_USER=patched",
            "EXPECTED_HOME=/home/patched",
            "NOLOGIN=/usr/sbin/nologin",
            "SUDOERS_DROPIN=/etc/sudoers.d/patched",
            'PRIVILEGED_GROUPS="sudo admin wheel"',
            'KEY_FILES=".ssh/authorized_keys .ssh/authorized_keys2"',
        ):
            self.assertIn(f"\n{line}\n", self.source)

    def test_no_recursive_remove_without_the_symlink_checks(self):
        code = "\n".join(code_lines(self.source))
        recursive = re.findall(r"\brm\s+-\w*[rR]\w*[^\n]*", code)
        self.assertEqual(recursive, ['rm -rf "$RM_ONE_FS" -- "$name" 2>/dev/null && [ ! -e "$name" ] && [ ! -L "$name" ]; then'])
        body = self.source[self.source.index("remove_leftover() {"):]
        body = body[: body.index("\n}\n")]
        self.assertLess(body.index("enter_real_dir"), body.index("rm -rf"))
        self.assertLess(body.index('if [ -L "$name" ]; then'), body.index("rm -rf"))
        # Relative to a directory entered and verified, never a path with a
        # trailing slash, which would make rm follow a link.
        self.assertNotRegex(code, r'rm [^\n]*"\$name/"')

    def test_every_unit_running_as_patched_needs_no_login_or_sudo(self):
        units = sorted(p for p in ARTEFACTS.glob("*.service") if re.search(r"(?m)^User=patched$", p.read_text(encoding="utf-8")))
        self.assertEqual(
            [p.name for p in units],
            [
                "patched-api.service",
                "patched-cve-sync.service",
                "patched-extractor.service",
                "patched-partitions.service",
                "patched-tooling-cve-refresh.service",
            ],
        )
        for unit in units:
            with self.subTest(unit=unit.name):
                text = unit.read_text(encoding="utf-8")
                self.assertRegex(text, r"(?m)^NoNewPrivileges=(true|yes)$")
                self.assertRegex(text, r"(?m)^ProtectHome=(true|yes|read-only|tmpfs)$")
                self.assertNotRegex(text, r"(?m)^PAMName=")
                for exec_line in re.findall(r"(?m)^Exec\w*=(.*)$", text):
                    self.assertNotRegex(exec_line, r"\b(sudo|su|runuser|login)\b|\bbash\s+-l|\bsh\s+-l")

    def test_the_go_services_never_run_sudo_su_or_runuser(self):
        offenders = []
        for path in GO_SERVICE.rglob("*.go"):
            if path.name.endswith("_test.go"):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if re.search(r'"(?:/usr)?/s?bin/(?:sudo|su|runuser)"|"(?:sudo|runuser)"', text):
                offenders.append(str(path.relative_to(REPO_ROOT)))
        self.assertEqual(offenders, [])

    def test_the_script_is_not_a_hand_copied_artefact(self):
        manifest = json.loads(ARTEFACT_MANIFEST.read_text(encoding="utf-8"))
        self.assertNotIn("service-account-hygiene", json.dumps(manifest))
        self.assertFalse((ARTEFACTS / "service-account-hygiene.sh").exists())


class WorkflowWiringTests(unittest.TestCase):
    """deploy-api-01.yml, go-test.yml and api-build.yml, read as text."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.step = workflow_step(cls.workflow, HYGIENE_STEP)

    def step_index(self, name: str) -> int:
        marker = f"- name: {name}\n"
        self.assertIn(marker, self.workflow, f"step {name!r} is missing")
        return self.workflow.index(marker)

    def test_the_step_runs_after_the_ownership_re_check_and_before_the_readback(self):
        late = self.step_index(LATE_CHECK)
        hygiene = self.step_index(HYGIENE_STEP)
        readback = self.step_index(READBACK)
        self.assertLess(late, hygiene)
        self.assertLess(hygiene, readback)
        # Nothing between them: the deploy is complete before this runs.
        between = self.workflow[late:readback]
        self.assertEqual(len(re.findall(r"(?m)^\s*- name: ", between)), 2, between)
        for name in (
            "Run deploy.sh on api-01",
            "Preflight and activate serial CVE pipeline units",
            "Deploy Prometheus alerting rules on api-01",
            "Verify the automatic reboot policy landed on api-01",
        ):
            self.assertLess(self.step_index(name), hygiene)
        last_rsync = max(m.start() for m in re.finditer(r"(?m)^\s+rsync\s", self.workflow))
        self.assertLess(last_rsync, hygiene)
        # The readback still runs whatever happens here.
        self.assertRegex(workflow_step(self.workflow, READBACK), r"(?m)^        if: always\(\)$")

    def test_the_step_is_unconditional_and_cannot_be_skipped_on_error(self):
        self.assertTrue(self.step)
        self.assertNotIn("continue-on-error", self.step)
        self.assertNotRegex(self.step, r"(?m)^        if:")

    def test_it_pipes_the_runners_copy_apply_then_check(self):
        body = "\n".join(code_lines(self.step))
        prefix = "'/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/bash --noprofile --norc -s -- "
        apply_at = body.index(prefix + "apply'")
        check_at = body.index(prefix + "check'")
        self.assertLess(apply_at, check_at)
        self.assertEqual(body.count(f"< {SCRIPT_REL} || "), 2)
        self.assertEqual(body.count("root@patched-api-01"), 2)
        self.assertEqual(body.count("-o BatchMode=yes"), 2)

    def test_no_step_runs_a_copy_from_the_box(self):
        references = [line.strip() for line in code_lines(self.workflow) if "service-account-hygiene" in line]
        self.assertEqual(
            [line for line in references if line.startswith("<")],
            [f"< {SCRIPT_REL} || apply_rc=$?", f"< {SCRIPT_REL} || check_rc=$?"],
        )
        self.assertNotRegex(self.workflow, r"/opt/[^\s'\"]*service-account-hygiene")
        self.assertNotRegex(self.workflow, r"rsync[^\n]*service-account-hygiene")

    def test_failures_are_named_and_not_swallowed(self):
        body = self.step
        self.assertIn('"$apply_rc" -eq 255', body)
        self.assertIn('"$check_rc" -eq 255', body)
        self.assertIn("SSH/network failure", body)
        self.assertIn('exit "$apply_rc"', body)
        self.assertIn('exit "$check_rc"', body)
        # check runs even when apply failed, and apply's failure still fails the step.
        code = "\n".join(code_lines(body))
        self.assertLess(code.index("-s -- check'"), code.index('if [ "$apply_rc" -ne 0 ]; then'))
        for line in body.splitlines():
            if "::error::" in line:
                self.assertNotIn(">&2", line)

    def test_ci_shellchecks_the_script(self):
        go_test = GO_TEST_PATH.read_text(encoding="utf-8")
        build = BUILD_WORKFLOW_PATH.read_text(encoding="utf-8")
        contract = workflow_step(go_test, "API deployment contract")
        lint = workflow_step(build, "Lint the box-side deploy script")
        for body in (contract, lint):
            shellcheck = next(line for line in body.splitlines() if line.strip().startswith("shellcheck "))
            self.assertIn(SCRIPT_REL, shellcheck.split())


if __name__ == "__main__":
    unittest.main()
