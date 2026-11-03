#!/usr/bin/env python3
"""PAT-2395 (PAT-2368 M2) synthetic installer and entrypoint-ancestry checks.

Run with python3 ci/test_privileged_entrypoint_ancestry.py (unprivileged, bash
and python3 only; pytest collects it through test-suite.yml as well).

A root-owned script inside a directory another user owns is replaceable by that
user, so file ownership alone protects nothing. The retained collector jobs must
run from a dedicated tree whose whole ancestry the installer verified.

Nothing here touches the real system. macos/install.sh and macos/uninstall.sh
are copied into an owned scratch directory with every system path rebased onto a
scratch filesystem root; id, uname, launchctl, chown, chmod, install and rm
are recording stubs. The copy is refused if any system path is left un-rebased.
Tests cannot chown to root, so the ownership probe is replaced: a scratch path
owned by the invoking user reads as uid 0 unless the test marks it user-owned.
Mode bits and symlinks are always read from the real scratch filesystem.

SEAM the implementation must provide (see Contract below):
  macos/install.sh and macos/uninstall.sh, one literal line each:
      AGENT_DIR="/absolute/dedicated/tree"      (same value in both)
      LEGACY_BIN_DIR="/usr/local/bin"
  macos/install.sh, one literal line:
      ANCESTRY_ANCHOR="/"
  macos/install.sh, a self-contained block of bash function definitions between
      # >>> PATCHED_ANCESTRY_HELPERS_START
      # <<< PATCHED_ANCESTRY_HELPERS_END
  defining
      patched_ancestry_probe <path>
          prints "<uid> <octal-permission-bits> <kind>" from lstat, kind one of
          dir | symlink | other | missing ("- - missing" when absent)
      patched_verify_ancestry <dir> <anchor>
          returns 0 only when every existing component from <anchor> to <dir>
          inclusive is a real directory, uid 0 and not group/other-writable.
          Components that do not exist yet are allowed (fresh install). A
          relative path, a ".." component or a <dir> outside <anchor> fails.
          It names the rejected component on stderr and obtains ownership only
          through patched_ancestry_probe.
  The installer calls patched_verify_ancestry "$AGENT_DIR" "$ANCESTRY_ANCHOR"
  before its first write. No environment variable may relax the check.

Passing is portable source evidence, not installed privilege-boundary proof.
"""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MACOS = ROOT / "macos"
SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
LEGACY_BIN = "/usr/local/bin"
MARK_START = "# >>> PATCHED_ANCESTRY_HELPERS_START"
MARK_END = "# <<< PATCHED_ANCESTRY_HELPERS_END"
# Every system location the installer or uninstaller may name. Each occurrence
# in a scratch copy is rebased under the scratch root before anything runs.
SENSITIVE = ("/usr/local", "/Library", "/etc/patched", "/var/db/patched",
             "/var/lib/patched", "/var/log")
# /var, /etc and /tmp are symlinks on macOS; the rest are user-controlled.
FORBIDDEN_TREE_PREFIXES = ("/usr/local", "/opt", "/Users", "/home", "/tmp",
                           "/var", "/etc", "/private/tmp")
MACOS_PLISTS = {
    "com.patched.collect.plist": "patched-collect.sh",
    "com.patched.upload.plist": "patched-upload.sh",
    "com.patched.bootstrap.plist": "patched-bootstrap.sh",
}
INSTALLED_JOBS = ("com.patched.collect", "com.patched.upload")
ENDPOINT_PLISTS = ("com.patched.update.plist", "com.patched.config-poll.plist",
                   "com.patched.posture-poll.plist")
ENTRYPOINTS = ("patched-collect.sh", "patched-upload.sh")
CREDENTIALS = {"tenant-id": "11111111-1111-1111-1111-111111111111",
               "bearer-token": "test-bearer",
               "hmac-secret": "dGVzdC1zZWNyZXQtMTIzNDU2Nzg="}

STUB = r'''#!{python}
import json, os, sys
TOOL = {tool!r}
REAL = {real!r}
argv = sys.argv[1:]
entry = os.environ.get("PAT2395_ENTRY_DIR", "")
record = {{"tool": TOOL, "argv": argv,
           "entrypoints_present": bool(entry) and all(
               os.path.isfile(os.path.join(entry, name)) for name in {entrypoints!r})}}
with open(os.environ["PAT2395_LOG"], "a") as log:
    log.write(json.dumps(record) + "\n")
if TOOL == "id":
    print("root" if any("n" in item for item in argv if item.startswith("-")) else "0")
elif TOOL == "uname":
    print("Darwin")
elif TOOL == "install":
    kept, skip = [], False
    for item in argv:
        if skip:
            skip = False
        elif item in ("-o", "-g"):
            skip = True
        elif not (item.startswith(("-o", "-g")) and len(item) > 2 and not item.startswith("--")):
            kept.append(item)
    os.execv(REAL, [REAL] + kept)
elif TOOL in ("chmod", "rm"):
    os.execv(REAL, [REAL] + argv)
'''

# PAT-2398: the verifier also reads each component's ACL through
# patched_ancestry_acl_listing (/bin/ls -lden). On macOS the real one runs
# against the scratch tree. Anywhere else there is no macOS ACL to read and ls
# has no -e, so the listing is replaced by a header-only one (no entries); the
# parser behind it still runs. ACL refusal itself is covered by
# ci/test_privileged_installer_trust.py.
ACL_LISTING_OVERRIDE = "" if sys.platform == "darwin" else (
    "\npatched_ancestry_acl_listing() { echo 'drwxr-xr-x  2 0  0  64 Jan  1 00:00 scratch'; }")

FAKE_PROBE = r'''import os, stat, sys
target = sys.argv[1]
with open(sys.argv[2]) as handle:
    user_owned = set(line for line in handle.read().split("\n") if line)
try:
    info = os.lstat(target)
except OSError:
    print("- - missing")
    sys.exit(0)
kind = ("symlink" if stat.S_ISLNK(info.st_mode)
        else "dir" if stat.S_ISDIR(info.st_mode) else "other")
uid = info.st_uid
if uid == os.geteuid():
    uid = 501 if os.path.normpath(target) in user_owned else 0
print("%d %o %s" % (uid, stat.S_IMODE(info.st_mode), kind))
'''


def constants(text, name):
    return re.findall(r'^' + re.escape(name) + r'="([^"]*)"$', text, re.M)


class Contract:
    """What the product source declares today; None means not declared."""

    def __init__(self):
        self.install = (MACOS / "install.sh").read_text()
        self.uninstall = (MACOS / "uninstall.sh").read_text()
        declared = constants(self.install, "AGENT_DIR")
        self.agent_dir = declared[0] if len(declared) == 1 else None

    @property
    def entry_dir(self):
        """Where the collector entrypoints are destined (legacy until fixed)."""
        return self.agent_dir or LEGACY_BIN

    def helper_block(self):
        match = re.search(re.escape(MARK_START) + r"[^\n]*\n(.*?)^" + re.escape(MARK_END),
                          self.install, re.M | re.S)
        return match[1] if match else None


def snapshot(root):
    """Every path under root: kind, permission bits and content or link target."""
    state = {}
    for directory, names, files in os.walk(root, followlinks=False):
        for name in names + files:
            path = os.path.join(directory, name)
            info = os.lstat(path)
            relative = os.path.relpath(path, root)
            if stat.S_ISLNK(info.st_mode):
                state[relative] = ("symlink", os.readlink(path))
            elif stat.S_ISDIR(info.st_mode):
                state[relative] = ("dir", stat.S_IMODE(info.st_mode))
            else:
                with open(path, "rb") as handle:
                    digest = hashlib.sha256(handle.read()).hexdigest()
                state[relative] = ("file", stat.S_IMODE(info.st_mode), digest)
    return state


class Scratch:
    """An owned scratch filesystem root plus a staged, rebased release tarball."""

    def __init__(self, case, contract):
        if os.geteuid() == 0:
            raise RuntimeError("run this fixture without privilege")
        self.contract = contract
        self.base = Path(os.path.realpath(tempfile.mkdtemp(prefix="pat2395-")))
        case.addCleanup(shutil.rmtree, str(self.base), True)
        self.root, self.stage, self.stubs = (self.base / n for n in ("root", "stage", "stubs"))
        self.tmp, self.log = self.base / "tmp", self.base / "calls.jsonl"
        self.owned_list = self.base / "user-owned.txt"
        for directory in (self.root, self.stage, self.stubs, self.tmp):
            directory.mkdir(mode=0o755)
        self.log.write_text("")
        self.owned_list.write_text("")
        self.probe = self.base / "fake_probe.py"
        self.probe.write_text(FAKE_PROBE)
        for tool in ("id", "uname", "launchctl", "chown", "chmod", "install", "rm"):
            passthrough = tool in ("chmod", "install", "rm")
            real = shutil.which(tool, path=SYSTEM_PATH) if passthrough else ""
            if passthrough and not real:
                raise RuntimeError("system " + tool + " not found")
            stub = self.stubs / tool
            stub.write_text(STUB.format(python=sys.executable, tool=tool, real=real,
                                        entrypoints=ENTRYPOINTS))
            stub.chmod(0o700)
        for relative in ("usr/local/bin", "Library/LaunchDaemons", "etc", "var/db",
                         "var/log", "var/lib"):
            (self.root / relative).mkdir(parents=True, mode=0o755)
        if contract.agent_dir:
            self.path("/" + contract.agent_dir.strip("/").split("/")[0]).mkdir(exist_ok=True)
        # The retained read-only metadata in PAT-2368: a Homebrew-owned, user
        # writable /usr/local/bin holding other people's tools.
        self.homebrew = self.path(LEGACY_BIN)
        self.homebrew.chmod(0o775)
        self.user_owned(self.homebrew)
        (self.homebrew / "brew-tool").write_text("#!/bin/sh\n# not ours\n")
        (self.homebrew / "brew-tool").chmod(0o755)
        self.build_stage()

    # -- paths -------------------------------------------------------------
    def path(self, system_path):
        return self.root / system_path.lstrip("/")

    @property
    def entry_dir(self):
        return self.path(self.contract.entry_dir)

    @property
    def daemons(self):
        return self.path("/Library/LaunchDaemons")

    def user_owned(self, path):
        with self.owned_list.open("a") as handle:
            handle.write(os.path.normpath(str(path)) + "\n")

    # -- staging -----------------------------------------------------------
    def rebase(self, text):
        prefixes = set(SENSITIVE)
        if self.contract.agent_dir:
            prefixes.add(self.contract.agent_dir)
        names = "|".join(re.escape(item) for item in sorted(prefixes, key=len, reverse=True))
        text = re.sub(r'(?<![\w.$}/])(' + names + r')(?=[/"\'\s<:;)}]|$)',
                      lambda match: str(self.root) + match[1], text, flags=re.M)
        text = re.sub(r'^ANCESTRY_ANCHOR="/"$', 'ANCESTRY_ANCHOR="' + str(self.root) + '"',
                      text, flags=re.M)
        for match in re.finditer(names, text):
            before = text[:match.start()]
            if not before.endswith(str(self.root)) and not re.search(r'[\w$}]$', before):
                raise RuntimeError("un-rebased system path in scratch copy: " +
                                   text[max(0, match.start() - 40):match.end() + 40])
        return text

    def script(self, name):
        text = self.rebase((MACOS / name).read_text())
        # Privileged scripts may call tools by absolute path or reset PATH; the
        # scratch copy must still reach the recording stubs, never the system.
        text = re.sub(r'(?<![\w.$}/-])/(?:usr/)?s?bin/(id|uname|launchctl|chown|chmod|install|rm)\b',
                      r'\1', text)
        text = re.sub(r'^\s*(?:export\s+)?PATH=.*$',
                      'export PATH=' + shlex.quote(str(self.stubs) + ":" + SYSTEM_PATH),
                      text, flags=re.M)
        override = ('patched_ancestry_probe() { ' + shlex.quote(sys.executable) + ' ' +
                    shlex.quote(str(self.probe)) + ' "$1" ' +
                    shlex.quote(str(self.owned_list)) + '; }' + ACL_LISTING_OVERRIDE)
        text = re.sub(r'^' + re.escape(MARK_END) + r'.*$',
                      lambda match: match[0] + "\n" + override, text, flags=re.M)
        return text

    def build_stage(self):
        for name in ("install.sh", "uninstall.sh"):
            (self.stage / name).write_text(self.script(name))
        for name in ENTRYPOINTS:
            (self.stage / name).write_text("#!/bin/sh\n# NEW " + name + "\nexit 0\n")
        for name in ("com.patched.collect.plist", "com.patched.upload.plist"):
            (self.stage / name).write_text(self.rebase((MACOS / name).read_text()))
        for name in ("endpoint-install.sh", "endpoint-uninstall.sh"):
            (self.stage / name).write_text(
                "#!/bin/bash\nprintf '%s\\n' " + shlex.quote(name) + " >> " +
                shlex.quote(str(self.base / "endpoint-calls.log")) + "\nexit 0\n")

    # -- fixtures ----------------------------------------------------------
    def plant_legacy_install(self):
        for name in ENTRYPOINTS:
            target = self.homebrew / name
            target.write_text("#!/bin/sh\n# OLD " + name + "\nexit 0\n")
            target.chmod(0o755)
        for label, name in zip(INSTALLED_JOBS, ENTRYPOINTS):
            with (self.daemons / (label + ".plist")).open("wb") as handle:
                plistlib.dump({"Label": label,
                               "ProgramArguments": [str(self.homebrew / name)]}, handle)
        self.plant_data()

    def plant_data(self):
        creds = self.path("/etc/patched")
        creds.mkdir(mode=0o700)
        for name, value in dict(CREDENTIALS, **{"artifact-key": "placeholder-artifact-key"}).items():
            (creds / name).write_text(value + "\n")
            (creds / name).chmod(0o600)
        queue = self.path("/var/db/patched/queue")
        queue.mkdir(parents=True, mode=0o700)
        (queue / "queued-item.json").write_text('{"queued": true}\n')

    def poison(self, variant):
        """Make the ancestry of the entrypoint tree untrusted; return the bad path."""
        tree, parent = self.entry_dir, self.entry_dir.parent
        parent.mkdir(parents=True, exist_ok=True)
        attacker = self.root / "Users" / "mallory"
        attacker.mkdir(parents=True)
        self.user_owned(attacker)
        if variant == "user-owned parent":
            self.user_owned(parent)
            return parent
        if variant == "group-writable parent":
            parent.chmod(0o775)
            return parent
        if variant == "symlink parent":
            moved = attacker / "moved-parent"
            parent.rename(moved)
            self.user_owned(moved)
            parent.symlink_to(moved)
            return parent
        if variant == "pre-existing user-owned tree":
            tree.mkdir(exist_ok=True)
            self.user_owned(tree)
            return tree
        if variant == "pre-existing symlink tree":
            if tree.exists():
                tree.rename(attacker / "moved-tree")
            else:
                (attacker / "moved-tree").mkdir()
            tree.symlink_to(attacker / "moved-tree")
            return tree
        raise ValueError(variant)

    # -- execution ---------------------------------------------------------
    def run(self, name, *arguments):
        environment = {"PATH": str(self.stubs) + ":" + SYSTEM_PATH, "TMPDIR": str(self.tmp),
                       "HOME": str(self.tmp), "PAT2395_LOG": str(self.log),
                       "PAT2395_ENTRY_DIR": str(self.entry_dir)}
        return subprocess.run(["/bin/bash", str(self.stage / name), *arguments],
                              env=environment, cwd=str(self.stage), capture_output=True,
                              text=True, timeout=60, stdin=subprocess.DEVNULL)

    def install(self):
        arguments = []
        for name, value in CREDENTIALS.items():
            arguments += ["--" + name, value]
        return self.run("install.sh", *arguments)

    def calls(self, *tools):
        records = [json.loads(line) for line in self.log.read_text().splitlines()]
        return [record for record in records if record["tool"] in tools]

    def endpoint_calls(self):
        log = self.base / "endpoint-calls.log"
        return log.read_text().split() if log.exists() else []

    def installed_entrypoint(self, label):
        with (self.daemons / (label + ".plist")).open("rb") as handle:
            return Path(plistlib.load(handle)["ProgramArguments"][0])

    def homebrew_takeover(self):
        """Ownership or mode operations aimed at /usr/local or /usr/local/bin."""
        protected = {os.path.normpath(str(self.homebrew)),
                     os.path.normpath(str(self.homebrew.parent))}
        found = []
        for record in self.calls("chown", "chmod", "install"):
            operands = [os.path.normpath(item) for item in record["argv"] if item.startswith("/")]
            recursive = any(re.fullmatch(r"-[A-Za-z]*R[A-Za-z]*", item) for item in record["argv"])
            direct = [item for item in operands if item in protected]
            above = [item for item in operands
                     if recursive and any(path.startswith(item.rstrip("/") + "/") for path in protected)]
            if record["tool"] == "install" and "-d" not in record["argv"]:
                continue
            if direct or above:
                found.append(record["tool"] + " " + " ".join(record["argv"]))
        return found


class ControlTests(unittest.TestCase):
    """Pass before and after the fix. A failure here means the harness broke."""

    def setUp(self):
        os.umask(0o022)
        self.contract = Contract()

    def test_control_fresh_install_on_trusted_ancestry_succeeds(self):
        scratch = Scratch(self, self.contract)
        result = scratch.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for label, name in zip(INSTALLED_JOBS, ENTRYPOINTS):
            entry = scratch.installed_entrypoint(label)
            self.assertEqual(entry.name, name)
            self.assertTrue(entry.is_file() and os.access(entry, os.X_OK),
                            "installed job targets a missing entrypoint: " + str(entry))
            self.assertIn("NEW " + name, entry.read_text())
            self.assertTrue(str(entry).startswith(str(scratch.root) + "/"))
        creds = scratch.path("/etc/patched")
        self.assertEqual((creds / "tenant-id").read_text().strip(), CREDENTIALS["tenant-id"])
        self.assertEqual(scratch.endpoint_calls(), ["endpoint-install.sh"])
        self.assertTrue(any("bootstrap" in call["argv"] or "load" in call["argv"]
                            for call in scratch.calls("launchctl")))
        self.assertTrue((scratch.homebrew / "brew-tool").is_file())

    def test_control_scratch_copies_reference_no_real_system_path(self):
        scratch = Scratch(self, self.contract)
        for name in ("install.sh", "uninstall.sh"):
            text = (scratch.stage / name).read_text()
            for line in text.splitlines():
                for prefix in SENSITIVE:
                    for match in re.finditer(re.escape(prefix), line):
                        before = line[:match.start()]
                        self.assertTrue(before.endswith(str(scratch.root)) or
                                        re.search(r'[\w$}]$', before), name + ": " + line)

    def test_control_fake_probe_reads_real_modes_and_symlinks(self):
        scratch = Scratch(self, self.contract)
        directory = scratch.root / "probe"
        directory.mkdir(mode=0o750)
        (scratch.root / "link").symlink_to(directory)
        scratch.user_owned(scratch.homebrew)

        def probe(path):
            return subprocess.run([sys.executable, str(scratch.probe), str(path),
                                   str(scratch.owned_list)], capture_output=True,
                                  text=True, timeout=10).stdout.strip()
        self.assertEqual(probe(directory), "0 750 dir")
        self.assertEqual(probe(scratch.root / "link").split()[2], "symlink")
        self.assertEqual(probe(scratch.homebrew), "501 775 dir")
        self.assertEqual(probe(scratch.root / "absent"), "- - missing")

    def test_control_endpoint_jobs_do_not_execute_from_usr_local_bin(self):
        for name in ENDPOINT_PLISTS:
            with self.subTest(plist=name), (ROOT / "endpoint" / name).open("rb") as handle:
                entry = plistlib.load(handle)["ProgramArguments"][0]
                self.assertFalse(entry.startswith(LEGACY_BIN + "/"), entry)

    def test_control_uninstall_without_purge_keeps_credentials_and_queue(self):
        scratch = Scratch(self, self.contract)
        scratch.plant_legacy_install()
        result = scratch.run("uninstall.sh")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((scratch.path("/etc/patched") / "bearer-token").is_file())
        self.assertTrue((scratch.path("/var/db/patched/queue") / "queued-item.json").is_file())
        self.assertTrue((scratch.homebrew / "brew-tool").is_file())


class EntrypointAncestryTests(unittest.TestCase):
    """Red until PAT-2395 is implemented."""

    VARIANTS = ("user-owned parent", "symlink parent", "group-writable parent",
                "pre-existing user-owned tree", "pre-existing symlink tree")

    def setUp(self):
        os.umask(0o022)
        self.contract = Contract()

    def require_tree(self):
        self.assertIsNotNone(
            self.contract.agent_dir,
            'macos/install.sh declares no dedicated root-owned tree (AGENT_DIR="..."); '
            'privileged entrypoints still install to ' + LEGACY_BIN)
        return self.contract.agent_dir

    # (a) ------------------------------------------------------------------
    def test_a_every_retained_plist_targets_the_dedicated_root_owned_tree(self):
        for name, script in MACOS_PLISTS.items():
            with self.subTest(plist=name), (MACOS / name).open("rb") as handle:
                entry = plistlib.load(handle)["ProgramArguments"][0]
                self.assertEqual(Path(entry).name, script)
                self.assertFalse(entry.startswith("/usr/local/"),
                                 "privileged job executes from a Homebrew-writable "
                                 "directory: " + entry)
        tree = self.require_tree()
        self.assertEqual(tree, os.path.normpath(tree))
        self.assertTrue(tree.startswith("/") and tree != "/")
        for prefix in FORBIDDEN_TREE_PREFIXES:
            self.assertFalse(tree == prefix or tree.startswith(prefix + "/"),
                             "tree sits under a user-controlled or symlinked location: " + tree)
        self.assertEqual(constants(self.contract.uninstall, "AGENT_DIR"), [tree],
                         "uninstall.sh must name the same tree as install.sh")
        for name in MACOS_PLISTS:
            with self.subTest(plist=name, tree=tree), (MACOS / name).open("rb") as handle:
                entry = plistlib.load(handle)["ProgramArguments"][0]
                self.assertEqual(str(Path(entry).parent), tree)

    # (b) function seam ----------------------------------------------------
    def verify(self, scratch, target, anchor):
        block = self.contract.helper_block()
        self.assertIsNotNone(block, "macos/install.sh has no " + MARK_START +
                             " block: the installer verifies no ancestry before writing")
        helpers = scratch.base / "helpers.sh"
        helpers.write_text(block)
        body = ('set -euo pipefail\nsource ' + shlex.quote(str(helpers)) + '\n'
                'patched_ancestry_probe() { ' + shlex.quote(sys.executable) + ' ' +
                shlex.quote(str(scratch.probe)) + ' "$1" ' +
                shlex.quote(str(scratch.owned_list)) + '; }' + ACL_LISTING_OVERRIDE + '\n'
                'patched_verify_ancestry "$1" "$2"\n')
        return subprocess.run(["/bin/bash", "-c", body, "verify", str(target), str(anchor)],
                              env={"PATH": SYSTEM_PATH}, capture_output=True, text=True,
                              timeout=20, cwd=str(scratch.base))

    def chain(self):
        scratch = Scratch(self, self.contract)
        tree = scratch.root / "a" / "b" / "c"
        tree.mkdir(parents=True, mode=0o755)
        return scratch, tree

    def test_b_verifier_accepts_root_owned_real_directories(self):
        scratch, tree = self.chain()
        result = self.verify(scratch, tree, scratch.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.verify(scratch, tree / "not" / "created-yet", scratch.root)
        self.assertEqual(result.returncode, 0, "a fresh install has no tree yet: " + result.stderr)
        (scratch.root / "a" / "b").chmod(0o1755)
        result = self.verify(scratch, tree, scratch.root)
        self.assertEqual(result.returncode, 0, "sticky but not writable is safe: " + result.stderr)

    def test_b_verifier_rejects_untrusted_components(self):
        cases = {
            "user-owned parent": lambda s, t: s.user_owned(t.parent),
            "user-owned anchor": lambda s, t: s.user_owned(s.root),
            "user-owned tree": lambda s, t: s.user_owned(t),
            "group-writable parent": lambda s, t: t.parent.chmod(0o775),
            "other-writable parent": lambda s, t: t.parent.chmod(0o757),
            "symlink parent": lambda s, t: (t.parent.rename(s.root / "real-b"),
                                            t.parent.symlink_to(s.root / "real-b")),
            "symlink tree": lambda s, t: (t.rename(s.root / "real-c"),
                                          t.symlink_to(s.root / "real-c")),
            "regular file as parent": lambda s, t: (shutil.rmtree(str(t.parent)),
                                                    t.parent.write_text("x")),
        }
        for name, mutate in cases.items():
            with self.subTest(case=name):
                scratch, tree = self.chain()
                mutate(scratch, tree)
                result = self.verify(scratch, tree, scratch.root)
                self.assertNotEqual(result.returncode, 0, name + " was accepted")
                self.assertTrue(result.stderr.strip(), "a refusal must say what it rejected")
        scratch, tree = self.chain()
        for target in (scratch.root / "a" / ".." / "a" / "b" / "c", "a/b/c", scratch.base / "tmp"):
            with self.subTest(target=str(target)):
                result = self.verify(scratch, target, scratch.root)
                self.assertNotEqual(result.returncode, 0, str(target) + " was accepted")

    @unittest.skipUnless(sys.platform == "darwin", "the production probe uses macOS stat")
    def test_b_production_probe_reports_owner_mode_and_kind(self):
        block = self.contract.helper_block()
        self.assertIsNotNone(block, "macos/install.sh has no " + MARK_START + " block")
        scratch = Scratch(self, self.contract)
        directory = scratch.root / "probe"
        directory.mkdir(mode=0o750)
        (scratch.root / "link").symlink_to(directory)
        (scratch.base / "helpers.sh").write_text(block)
        expected = {directory: "%d 750 dir" % os.geteuid(),
                    scratch.root / "absent": "- - missing"}
        for path in (directory, scratch.root / "link", scratch.root / "absent"):
            result = subprocess.run(
                ["/bin/bash", "-c", 'set -euo pipefail\nsource "$1"\npatched_ancestry_probe "$2"',
                 "probe", str(scratch.base / "helpers.sh"), str(path)],
                env={"PATH": SYSTEM_PATH}, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            if path in expected:
                self.assertEqual(result.stdout.strip(), expected[path])
            else:
                self.assertEqual(result.stdout.split()[2], "symlink")

    # (b) installer --------------------------------------------------------
    def assert_refused_before_any_write(self, scratch, variant):
        bad = scratch.poison(variant)
        before = snapshot(scratch.root)
        result = scratch.install()
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0,
                            "installer accepted " + variant + " (" + str(bad) + ")")
        self.assertEqual(snapshot(scratch.root), before, "installer wrote before refusing")
        self.assertEqual(scratch.calls("launchctl", "chown", "chmod", "install", "rm"), [],
                         "installer acted before refusing")
        self.assertEqual(scratch.endpoint_calls(), [])
        self.assertRegex(output, r"(?i)(own|symlink|writable|ancestry|untrusted)")

    def test_b_installer_refuses_untrusted_ancestry_before_writing(self):
        for variant in self.VARIANTS:
            with self.subTest(variant=variant):
                self.assert_refused_before_any_write(Scratch(self, self.contract), variant)

    # (c) ------------------------------------------------------------------
    def test_c_install_preserves_homebrew_owned_directories(self):
        scratch = Scratch(self, self.contract)
        before = snapshot(scratch.path("/usr/local"))
        result = scratch.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(scratch.homebrew_takeover(), [],
                         "installer changed ownership or mode of a Homebrew directory")
        self.assertEqual(snapshot(scratch.path("/usr/local")), before,
                         "installer wrote under /usr/local")
        self.assertEqual(stat.S_IMODE(scratch.homebrew.stat().st_mode), 0o775)

    # (d) ------------------------------------------------------------------
    def test_d_upgrade_moves_entrypoints_and_preserves_scoped_data(self):
        scratch = Scratch(self, self.contract)
        scratch.plant_legacy_install()
        result = scratch.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for name in ENTRYPOINTS:
            legacy = scratch.homebrew / name
            self.assertFalse(legacy.exists() and os.access(legacy, os.X_OK),
                             "legacy entrypoint left executable in a user-owned "
                             "directory: " + LEGACY_BIN + "/" + name)
        tree = scratch.path(self.require_tree())
        for label, name in zip(INSTALLED_JOBS, ENTRYPOINTS):
            entry = scratch.installed_entrypoint(label)
            self.assertEqual(entry, tree / name)
            self.assertIn("NEW " + name, entry.read_text())
        loads = [call for call in scratch.calls("launchctl")
                 if call["argv"] and call["argv"][0] in ("bootstrap", "load", "kickstart")]
        self.assertTrue(loads, "upgraded jobs were never reloaded onto the new tree")
        self.assertTrue(all(call["entrypoints_present"] for call in loads),
                        "a job was loaded before its new entrypoint was installed")
        early = [call["argv"] for call in scratch.calls("rm")
                 if not call["entrypoints_present"] and
                 any(item == str(scratch.homebrew / name) for item in call["argv"]
                     for name in ENTRYPOINTS)]
        self.assertEqual(early, [], "legacy entrypoint removed before the new tree was installed")
        creds = scratch.path("/etc/patched")
        for name, value in CREDENTIALS.items():
            self.assertEqual((creds / name).read_text().strip(), value)
        self.assertTrue((creds / "artifact-key").is_file(), "scoped credential lost on upgrade")
        self.assertTrue((scratch.path("/var/db/patched/queue") / "queued-item.json").is_file(),
                        "queued payload lost on upgrade")
        self.assertTrue((scratch.homebrew / "brew-tool").is_file())
        self.assertEqual(scratch.homebrew_takeover(), [])
        self.assertEqual(stat.S_IMODE(scratch.homebrew.stat().st_mode), 0o775)

    def test_d_failed_verification_leaves_the_legacy_install_intact(self):
        for variant in self.VARIANTS:
            with self.subTest(variant=variant):
                scratch = Scratch(self, self.contract)
                scratch.plant_legacy_install()
                self.assert_refused_before_any_write(scratch, variant)
                for label in INSTALLED_JOBS:
                    self.assertTrue((scratch.daemons / (label + ".plist")).is_file())

    # (e) ------------------------------------------------------------------
    def test_e_uninstall_removes_tree_and_legacy_entrypoints_and_nothing_else(self):
        tree_path = self.require_tree()
        self.assertEqual(constants(self.contract.uninstall, "AGENT_DIR"), [tree_path],
                         "uninstall.sh does not know the dedicated tree")
        scratch = Scratch(self, self.contract)
        scratch.plant_legacy_install()
        tree = scratch.path(tree_path)
        (tree / "lib").mkdir(parents=True)
        for name in ENTRYPOINTS:
            (tree / name).write_text("#!/bin/sh\n# NEW " + name + "\n")
            (tree / name).chmod(0o755)
        (tree / "lib" / "common.sh").write_text("# module\n")
        first = scratch.path("/" + tree_path.strip("/").split("/")[0])
        (first / "OtherVendor").mkdir()
        (first / "OtherVendor" / "keep").write_text("not ours\n")
        before = snapshot(scratch.root)
        result = scratch.run("uninstall.sh")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        after = snapshot(scratch.root)
        relative = os.path.relpath(tree, scratch.root)
        required = {path for path in before if path == relative or path.startswith(relative + "/")}
        required |= {os.path.relpath(scratch.homebrew / name, scratch.root) for name in ENTRYPOINTS}
        required |= {os.path.relpath(scratch.daemons / (label + ".plist"), scratch.root)
                     for label in INSTALLED_JOBS}
        optional, parent = set(), Path(relative).parent
        while len(parent.parts) > 1:
            optional.add(str(parent))
            parent = parent.parent
        removed = set(before) - set(after)
        self.assertEqual(required - removed, set(), "uninstall left privileged files behind")
        self.assertEqual(removed - required - optional, set(), "uninstall removed unrelated paths")
        self.assertEqual(set(after) - set(before), set(), "uninstall created files")
        self.assertEqual({path for path in after if after[path] != before[path]}, set(),
                         "uninstall modified surviving paths")
        self.assertEqual(scratch.homebrew_takeover(), [])

    # (f) ------------------------------------------------------------------
    def test_f_sibling_consumers_name_the_same_tree(self):
        tree = self.require_tree()
        trigger = (MACOS / "patched-collect-trigger.sh").read_text()
        self.assertEqual(constants(trigger, "COLLECT_BIN_DIR"), [tree],
                         "the sudo collect trigger must execute the entrypoints from the tree")
        decommission = (ROOT / "endpoint" / "patched-decommission.sh").read_text()
        self.assertIn(":-" + tree + "}", decommission,
                      "decommission removal verification must check the tree, or a failed "
                      "uninstall reads as a removed agent")


if __name__ == "__main__":
    unittest.main(verbosity=2)
