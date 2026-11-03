#!/usr/bin/env python3
"""PAT-2398 synthetic checks: ancestry ACLs, installer command resolution, stat kinds.

Run with python3 ci/test_privileged_installer_trust.py (unprivileged; pytest
collects it through test-suite.yml as well). Three gaps PAT-2395 left open in
macos/install.sh and macos/uninstall.sh, which run as root on customer Macs:

  ACLs   patched_verify_ancestry read uid and permission bits only, so an ACL
         entry granting someone else write on /Library/Patched or a parent
         passed. It must reject any allow entry that gives a principal other
         than root a permission outside a fixed read-only set, and fail closed
         on a listing it cannot parse.
  PATH   both scripts resolved install, id, launchctl, rm and others through
         the caller's PATH. Every command word must be a shell builtin, a
         function the script defines, or an allowlisted absolute system path.
  stat   the probe matched the human strings "Directory" / "Symbolic Link"
         from stat %HT. It must read the numeric file type instead.

Nothing here touches the real system or needs privilege. ACLs are applied with
chmod +a to directories in an owned scratch tree; ownership is faked exactly as
in ci/test_privileged_entrypoint_ancestry.py, whose harness this reuses. Tests
that need a real macOS ACL or the macOS stat are skipped elsewhere; the parser
is exercised on every platform by injecting listings.

SEAM the implementation must provide, inside the PATCHED_ANCESTRY_HELPERS block:
  patched_ancestry_acl_listing <path>
      prints the output of a numeric long listing with ACL entries
      (/bin/ls -lden): one header line, then one line per entry of the form
      " <index>: <principal uuid> [inherited] allow|deny <perm>[,<perm>...]".
      Returns non-zero if the listing cannot be read.
  patched_verify_ancestry obtains ACLs only through that function.

PAT-2420 extends the PATH guard to four more scripts: endpoint/install.sh and
endpoint/uninstall.sh (root; they inherit a reset PATH from the macOS installer
but had none of their own when run directly) and the two user-initiated zsh
triggers, macos/patched-collect-trigger.sh and macos/patched-uninstall-trigger.sh.

Passing is portable source evidence, not installed privilege-boundary proof.
"""
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import privileged_command_words as command_words  # noqa: E402
import test_privileged_entrypoint_ancestry as ancestry  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
MACOS = ROOT / "macos"
DARWIN = sys.platform == "darwin"
SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
PATH_LINE = 'export PATH="' + SYSTEM_PATH + '"'
SCRIPTS = ("install.sh", "uninstall.sh")
ENDPOINT = ROOT / "endpoint"
# PAT-2420. Every script the PATH guard covers, with the only programs it may
# hand to sudo. The triggers exist to start three root entrypoints through
# sudo; nothing else may reach sudo, and no other script may use it at all.
GUARDED = {
    "macos/install.sh": (),
    "macos/uninstall.sh": (),
    "endpoint/install.sh": (),
    "endpoint/uninstall.sh": (),
    "tools/pkg-scripts/postinstall": (),
    "macos/patched-collect-trigger.sh": ('"$COLLECT_BIN_DIR/patched-collect.sh"',
                                         '"$COLLECT_BIN_DIR/patched-upload.sh"',
                                         '"$BUNDLE_DIR/patched-fetch-posture.sh"'),
    "macos/patched-uninstall-trigger.sh": ('"$BUNDLE_DIR/patched-uninstall.sh"',
                                           '"$BUNDLE_DIR/patched-fetch-posture.sh"'),
}

# ---------------------------------------------------------------------------
# ACL fixtures
# ---------------------------------------------------------------------------
# The membership UUID macOS derives for uid 0. It is the only principal an
# allow entry may name; a name such as "user:root" is never trusted, because a
# name is resolved through the directory service and a UUID is not.
ROOT_UUID = "FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000"
DAEMON_UUID = "FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000001"
ADMIN_GROUP_UUID = "ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000050"
WHEEL_GROUP_UUID = "ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000"
HEADER = "drwxr-xr-x  2 0  0  64 Jan  1 00:00 scratch"
# Every write-type permission the ticket names. On a directory chmod stores
# write as add_file and append as add_subdirectory.
WRITE_PERMISSIONS = ("write", "append", "delete", "delete_child", "add_file",
                     "add_subdirectory", "writeattr", "writeextattr", "writesecurity", "chown")
NON_ROOT_PRINCIPALS = ("user:daemon", "group:admin", "group:wheel", "everyone")
READ_ONLY = "list,search,readattr,readextattr,readsecurity"


def helper_block(case):
    block = ancestry.Contract().helper_block()
    case.assertIsNotNone(block, "macos/install.sh has no " + ancestry.MARK_START + " block")
    return block


def chain(case):
    """A scratch root with a root-owned (faked) a/b/c directory chain."""
    os.umask(0o022)
    scratch = ancestry.Scratch(case, ancestry.Contract())
    tree = scratch.root / "a" / "b" / "c"
    tree.mkdir(parents=True, mode=0o755)
    # ACLs must not survive into the harness's own cleanup.
    case.addCleanup(subprocess.run, ["/bin/chmod", "-R", "-N", str(scratch.base)],
                    capture_output=True)
    return scratch, tree


def add_acl(case, path, entry):
    result = subprocess.run(["/bin/chmod", "+a", entry, str(path)], capture_output=True, text=True)
    case.assertEqual(result.returncode, 0, "could not apply test ACL: " + result.stderr)


def verify(case, scratch, target, anchor, listing=None, listing_fails=False):
    """Run the real patched_verify_ancestry with faked ownership.

    listing: text the ACL listing seam returns for every component, replacing
    the real /bin/ls call. Off macOS a clean header-only listing is the default,
    because there is no macOS ACL to read.
    """
    helpers = scratch.base / "helpers.sh"
    helpers.write_text(helper_block(case))
    body = ('set -euo pipefail\nsource ' + shlex.quote(str(helpers)) + '\n'
            'patched_ancestry_probe() { ' + shlex.quote(sys.executable) + ' ' +
            shlex.quote(str(scratch.probe)) + ' "$1" ' +
            shlex.quote(str(scratch.owned_list)) + '; }\n')
    if listing is None and not listing_fails and not DARWIN:
        listing = HEADER + "\n"
    if listing_fails:
        body += 'patched_ancestry_acl_listing() { return 1; }\n'
    elif listing is not None:
        injected = scratch.base / "listing.txt"
        injected.write_text(listing)
        body += ('patched_ancestry_acl_listing() { /bin/cat ' +
                 shlex.quote(str(injected)) + '; }\n')
    body += 'patched_verify_ancestry "$1" "$2"\n'
    return subprocess.run(["/bin/bash", "-c", body, "verify", str(target), str(anchor)],
                          env={"PATH": SYSTEM_PATH}, capture_output=True, text=True,
                          timeout=20, cwd=str(scratch.base))


class AncestryAclTests(unittest.TestCase):
    """Red until patched_verify_ancestry reads ACLs."""

    # -- controls: real ACLs that must pass --------------------------------
    def test_control_no_acl_passes(self):
        scratch, tree = chain(self)
        result = verify(self, scratch, tree, scratch.root)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(DARWIN, "needs a real macOS ACL")
    def test_control_deny_only_acl_passes(self):
        for principal in ("user:daemon", "group:wheel"):
            with self.subTest(principal=principal):
                scratch, tree = chain(self)
                add_acl(self, tree.parent, principal + " deny add_file,delete_child,delete")
                result = verify(self, scratch, tree, scratch.root)
                self.assertEqual(result.returncode, 0, "a deny entry grants nothing: " + result.stderr)

    @unittest.skipUnless(DARWIN, "needs a real macOS ACL")
    def test_control_read_only_allow_acl_passes(self):
        for entry in ("user:daemon allow " + READ_ONLY,
                      "everyone allow list,search",
                      "group:admin allow " + READ_ONLY + ",file_inherit,directory_inherit"):
            with self.subTest(entry=entry):
                scratch, tree = chain(self)
                add_acl(self, tree.parent, entry)
                result = verify(self, scratch, tree, scratch.root)
                self.assertEqual(result.returncode, 0, "read-only grant refused: " + result.stderr)

    @unittest.skipUnless(DARWIN, "needs a real macOS ACL")
    def test_control_root_user_write_allow_passes(self):
        scratch, tree = chain(self)
        add_acl(self, tree.parent, "user:root allow add_file,delete_child")
        result = verify(self, scratch, tree, scratch.root)
        self.assertEqual(result.returncode, 0,
                         "an entry for uid 0 grants nothing root lacks: " + result.stderr)

    # -- real ACLs that must be rejected -------------------------------------
    def assert_rejected(self, result, component, what):
        self.assertNotEqual(result.returncode, 0, what + " was accepted")
        self.assertIn(str(component), result.stderr, "a refusal must name the component")
        self.assertRegex(result.stderr, r"(?i)\bACL\b", "a refusal must say an ACL caused it")

    @unittest.skipUnless(DARWIN, "needs a real macOS ACL")
    def test_write_granting_acl_for_a_non_root_principal_is_rejected(self):
        for permission in WRITE_PERMISSIONS:
            with self.subTest(permission=permission):
                scratch, tree = chain(self)
                add_acl(self, tree.parent, "user:daemon allow " + permission)
                self.assert_rejected(verify(self, scratch, tree, scratch.root), tree.parent,
                                     "user:daemon allow " + permission)
        for principal in NON_ROOT_PRINCIPALS:
            with self.subTest(principal=principal):
                scratch, tree = chain(self)
                add_acl(self, tree.parent, principal + " allow add_file")
                self.assert_rejected(verify(self, scratch, tree, scratch.root), tree.parent,
                                     principal + " allow add_file")

    @unittest.skipUnless(DARWIN, "needs a real macOS ACL")
    def test_write_granting_acl_is_rejected_on_every_component(self):
        for position in ("anchor", "grandparent", "parent", "tree"):
            with self.subTest(position=position):
                scratch, tree = chain(self)
                component = {"anchor": scratch.root, "grandparent": tree.parent.parent,
                             "parent": tree.parent, "tree": tree}[position]
                add_acl(self, component, "group:admin allow add_subdirectory")
                self.assert_rejected(verify(self, scratch, tree, scratch.root), component,
                                     "write ACL on the " + position)

    @unittest.skipUnless(DARWIN, "needs a real macOS ACL")
    def test_write_grant_hidden_among_other_entries_is_rejected(self):
        cases = {
            "mixed with read permissions": ["user:daemon allow list,search,add_file,readattr"],
            "behind a read-only entry": ["user:daemon allow add_file", "everyone allow list,search"],
            "behind an entry for root": ["user:daemon allow delete_child", "user:root allow add_file"],
            # ACL evaluation order is deliberately not modelled: a write allow
            # is refused even where a deny entry would currently mask it.
            "masked by a deny entry": ["user:daemon allow add_file", "everyone deny add_file"],
        }
        for name, entries in cases.items():
            with self.subTest(case=name):
                scratch, tree = chain(self)
                for entry in entries:
                    add_acl(self, tree.parent, entry)
                self.assert_rejected(verify(self, scratch, tree, scratch.root), tree.parent, name)

    @unittest.skipUnless(DARWIN, "needs a real macOS ACL")
    def test_inherited_write_grant_is_rejected(self):
        scratch, tree = chain(self)
        add_acl(self, tree.parent.parent,
                "user:daemon allow add_file,file_inherit,directory_inherit,only_inherit")
        inheriting = tree.parent.parent / "created-after"
        inheriting.mkdir()
        listing = subprocess.run(["/bin/ls", "-lden", str(inheriting)], capture_output=True,
                                 text=True).stdout
        self.assertIn(" inherited allow ", listing, "fixture did not inherit an entry: " + listing)
        # Anchored at the inheriting directory itself: its parent carries the
        # inheritable entry and would be refused first.
        self.assert_rejected(verify(self, scratch, inheriting, inheriting), inheriting,
                             "inherited write ACL")

    @unittest.skipUnless(DARWIN, "the production listing uses macOS ls")
    def test_production_listing_is_numeric_and_fails_on_a_missing_path(self):
        scratch, tree = chain(self)
        add_acl(self, tree, "user:root allow add_file")
        helpers = scratch.base / "helpers.sh"
        helpers.write_text(helper_block(self))

        def listing(path):
            return subprocess.run(
                ["/bin/bash", "-c", 'set -euo pipefail\nsource "$1"\npatched_ancestry_acl_listing "$2"',
                 "listing", str(helpers), str(path)],
                env={"PATH": SYSTEM_PATH, "LANG": "fr_FR.UTF-8", "LC_ALL": "fr_FR.UTF-8"},
                capture_output=True, text=True, timeout=20)
        result = listing(tree)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"(?m)^ 0: " + ROOT_UUID + r" allow add_file$")
        self.assertNotIn("user:root", result.stdout, "principals must not be resolved to names")
        self.assertNotEqual(listing(scratch.root / "absent").returncode, 0)

    # -- parser, every platform ----------------------------------------------
    def test_injected_listing_controls_pass(self):
        cases = {
            "header only": "",
            "deny": " 0: " + DAEMON_UUID + " deny add_file,delete_child\n",
            "deny then read-only allow": (" 0: " + ADMIN_GROUP_UUID + " deny delete\n"
                                          " 1: " + DAEMON_UUID + " allow list,search\n"),
            "read-only with inheritance flags": (
                " 0: " + ADMIN_GROUP_UUID + " allow " + READ_ONLY +
                ",file_inherit,directory_inherit,limit_inherit,only_inherit\n"),
            "inherited read-only": " 0: " + DAEMON_UUID + " inherited allow list,search\n",
            "root uuid write": " 0: " + ROOT_UUID + " allow add_file,delete_child,writesecurity\n",
        }
        for name, entries in cases.items():
            with self.subTest(case=name):
                scratch, tree = chain(self)
                result = verify(self, scratch, tree, scratch.root, listing=HEADER + "\n" + entries)
                self.assertEqual(result.returncode, 0, name + ": " + result.stderr)

    def test_injected_write_grants_are_rejected(self):
        cases = {
            "non-root user": " 0: " + DAEMON_UUID + " allow add_file\n",
            "admin group": " 0: " + ADMIN_GROUP_UUID + " allow add_subdirectory\n",
            "wheel group": " 0: " + WHEEL_GROUP_UUID + " allow delete_child\n",
            "inherited": " 0: " + DAEMON_UUID + " inherited allow add_file\n",
            "after a root entry": (" 0: " + ROOT_UUID + " allow add_file\n"
                                   " 1: " + DAEMON_UUID + " allow chown\n"),
            # Only the uid 0 UUID is trusted. A resolved name is not, whoever
            # it claims to be: names come from the directory service.
            "root by name": " 0: user:root allow add_file\n",
            "wheel by name": " 0: group:wheel allow add_file\n",
            "name with a space": " 0: group:DOMAIN\\Domain Users allow add_file\n",
        }
        cases.update({"permission " + permission: " 0: " + DAEMON_UUID + " allow list," + permission + "\n"
                      for permission in WRITE_PERMISSIONS})
        for name, entries in cases.items():
            with self.subTest(case=name):
                scratch, tree = chain(self)
                result = verify(self, scratch, tree, scratch.root, listing=HEADER + "\n" + entries)
                self.assertNotEqual(result.returncode, 0, name + " was accepted")
                self.assertRegex(result.stderr, r"(?i)\bACL\b")

    def test_unparseable_listing_fails_closed(self):
        cases = {
            "empty listing": "",
            "blank header": "\n",
            "free text": HEADER + "\nsomething unexpected\n",
            "missing index": HEADER + "\n " + DAEMON_UUID + " deny delete\n",
            "non-numeric index": HEADER + "\n x: " + DAEMON_UUID + " deny delete\n",
            "no leading space": HEADER + "\n0: " + DAEMON_UUID + " deny delete\n",
            "tab indented": HEADER + "\n\t0: " + DAEMON_UUID + " deny delete\n",
            "unknown verb": HEADER + "\n 0: " + DAEMON_UUID + " permit list\n",
            "no verb": HEADER + "\n 0: " + DAEMON_UUID + " list\n",
            "no permissions": HEADER + "\n 0: " + DAEMON_UUID + " allow\n",
            "empty permission": HEADER + "\n 0: " + DAEMON_UUID + " allow list,,search\n",
            "trailing comma": HEADER + "\n 0: " + DAEMON_UUID + " allow list,\n",
            "unknown permission": HEADER + "\n 0: " + DAEMON_UUID + " allow list,frobnicate\n",
            "upper-case permission": HEADER + "\n 0: " + DAEMON_UUID + " allow LIST\n",
            "blank line among entries": HEADER + "\n\n 0: " + DAEMON_UUID + " deny delete\n",
            "garbage after a valid entry": (HEADER + "\n 0: " + DAEMON_UUID + " deny delete\n"
                                            "total 0\n"),
        }
        for name, listing in cases.items():
            with self.subTest(case=name):
                scratch, tree = chain(self)
                result = verify(self, scratch, tree, scratch.root, listing=listing)
                self.assertNotEqual(result.returncode, 0, name + " was accepted")
                self.assertTrue(result.stderr.strip(), "a refusal must say what it rejected")
        scratch, tree = chain(self)
        result = verify(self, scratch, tree, scratch.root, listing_fails=True)
        self.assertNotEqual(result.returncode, 0, "an unreadable ACL was accepted")
        self.assertRegex(result.stderr, r"(?i)\bACL\b")

    # -- installer -----------------------------------------------------------
    @unittest.skipUnless(DARWIN, "needs a real macOS ACL")
    def test_installer_refuses_an_acl_poisoned_ancestry_before_writing(self):
        contract = ancestry.Contract()
        for position in ("parent", "pre-existing tree"):
            with self.subTest(position=position):
                os.umask(0o022)
                scratch = ancestry.Scratch(self, contract)
                self.addCleanup(subprocess.run, ["/bin/chmod", "-R", "-N", str(scratch.base)],
                                capture_output=True)
                scratch.plant_legacy_install()
                target = scratch.entry_dir.parent
                if position == "pre-existing tree":
                    target = scratch.entry_dir
                    target.mkdir()
                add_acl(self, target, "group:admin allow add_file,add_subdirectory,delete_child")
                before = ancestry.snapshot(scratch.root)
                result = scratch.install()
                self.assertNotEqual(result.returncode, 0, "installer accepted an ACL on " + str(target))
                self.assertEqual(ancestry.snapshot(scratch.root), before,
                                 "installer wrote before refusing")
                self.assertEqual(scratch.calls("launchctl", "chown", "chmod", "install", "rm"), [],
                                 "installer acted before refusing")
                self.assertEqual(scratch.endpoint_calls(), [])
                self.assertRegex(result.stdout + result.stderr, r"(?i)\bACL\b")
                self.assertIn(str(target), result.stderr)

    @unittest.skipUnless(DARWIN, "needs a real macOS ACL")
    def test_control_installer_accepts_deny_and_read_only_acls(self):
        os.umask(0o022)
        scratch = ancestry.Scratch(self, ancestry.Contract())
        self.addCleanup(subprocess.run, ["/bin/chmod", "-R", "-N", str(scratch.base)],
                        capture_output=True)
        add_acl(self, scratch.entry_dir.parent, "user:daemon deny delete")
        add_acl(self, scratch.entry_dir.parent, "group:admin allow list,search")
        result = scratch.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


# ---------------------------------------------------------------------------
# stat kind
# ---------------------------------------------------------------------------
class ProbeKindTests(unittest.TestCase):
    def test_probe_does_not_match_human_readable_kind_strings(self):
        block = helper_block(self)
        self.assertNotIn("%HT", block, "stat %HT prints a human-readable kind string")
        for label in ("Directory", "Symbolic Link", "Regular File"):
            self.assertNotIn('"' + label + '"', block, "probe matches the string " + label)

    @unittest.skipUnless(DARWIN, "the production probe uses macOS stat")
    def test_production_probe_kind_is_numeric_and_locale_independent(self):
        scratch, tree = chain(self)
        (scratch.root / "to-dir").symlink_to(tree)
        (scratch.root / "dangling").symlink_to(scratch.root / "nowhere")
        (scratch.root / "file").write_text("x")
        os.mkfifo(str(scratch.root / "fifo"))
        helpers = scratch.base / "helpers.sh"
        helpers.write_text(helper_block(self))
        expected = {tree: "dir", scratch.root / "to-dir": "symlink",
                    scratch.root / "dangling": "symlink", scratch.root / "file": "other",
                    scratch.root / "fifo": "other", scratch.root / "absent": "missing"}
        for locale in ("C", "fr_FR.UTF-8", "ja_JP.UTF-8"):
            for path, kind in expected.items():
                with self.subTest(locale=locale, path=path.name):
                    result = subprocess.run(
                        ["/bin/bash", "-c",
                         'set -euo pipefail\nsource "$1"\npatched_ancestry_probe "$2"',
                         "probe", str(helpers), str(path)],
                        env={"PATH": SYSTEM_PATH, "LANG": locale, "LC_ALL": locale},
                        capture_output=True, text=True, timeout=20)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.split()[2], kind, result.stdout)


# ---------------------------------------------------------------------------
# Command resolution
# ---------------------------------------------------------------------------
# An allowlist, not a blocklist: anything not named here is a violation, so a
# new tool has to be added on purpose. None of these runs another program named
# by its arguments (no env, xargs, sudo, find, sh -c).
ALLOWED_TOOLS = {
    "/bin/bash", "/bin/cat", "/bin/chmod", "/bin/launchctl", "/bin/ls", "/bin/rm", "/bin/rmdir",
    "/usr/bin/base64", "/usr/bin/dirname", "/usr/bin/head", "/usr/bin/id", "/usr/bin/install",
    "/usr/bin/python3", "/usr/bin/stat", "/usr/bin/tr", "/usr/bin/uname", "/usr/bin/wc",
    "/usr/sbin/chown", "/usr/libexec/PlistBuddy",
    # PAT-2420: the endpoint installer pair and the triggers.
    "/bin/cp", "/bin/date", "/bin/mv", "/usr/bin/awk", "/usr/bin/shasum",
}
# awk can start programs (system(), pipes), so it is held to the one literal
# program the endpoint installer uses to take the digest out of shasum's output.
AWK_PROGRAMS = {"'{print $1}'"}
SUDO = "/usr/bin/sudo"
# bash 3.2 builtins the scripts use. Deliberately excludes eval, exec, command,
# builtin, source, ".", trap and time, each of which runs a further command.
BUILTINS = {"[", ":", "true", "echo", "printf", "read", "cd", "pwd", "set", "shift", "local",
            "export", "umask", "exit", "return", "kill", "continue", "break", "shopt"}
# Command words that are a variable-rooted absolute path. AGENT_DIR is a
# literal absolute constant whose ancestry the installer has verified.
ALLOWED_VARIABLE_COMMANDS = {'"$AGENT_DIR/patched-collect.sh"'}
# The only scripts /bin/bash may be handed: siblings shipped in the tarball.
ALLOWED_BASH_SCRIPTS = {'"$ENDPOINT_INSTALL_SRC"', '"$SCRIPT_DIR/endpoint-uninstall.sh"'}
PYTHON_SPAWNS = re.compile(r"\b(subprocess|popen|system|spawn\w*|exec\w*|pty|shutil|ctypes|"
                           r"__import__|importlib|eval|compile)\b")


def violations(text, sudo_targets=()):
    """Every reason a script's command words are not safe to run as root.

    sudo_targets: the exact command words sudo may be given as its first
    argument. Empty for every script but the triggers, so sudo is refused.
    """
    try:
        commands, functions = command_words.scan(text)
    except command_words.ShellScanError as error:
        return ["unreadable shell, cannot vouch for it: " + str(error)]
    found = []
    for command in commands:
        word, where = command.word, "line %d: " % command.line
        for heredoc in command.heredocs:
            if word != "/bin/cat":
                found.append(where + "here-document fed to " + word)
            elif not heredoc.literal and re.search(r"\$\(|`", heredoc.body):
                found.append(where + "command substitution inside a here-document")
        if word in BUILTINS:
            for argument in command.arguments:
                if word in ("export", "local") and re.match(r"PATH\+?=", argument) and \
                        word + " " + argument != PATH_LINE:
                    found.append(where + "PATH set to something other than " + SYSTEM_PATH)
        elif word in functions or word in ALLOWED_VARIABLE_COMMANDS:
            pass
        elif word == "/bin/bash":
            if not command.arguments or command.arguments[0] not in ALLOWED_BASH_SCRIPTS:
                found.append(where + "/bin/bash given an unlisted script or option: " +
                             " ".join(command.arguments[:1]))
        elif word == "/usr/bin/python3":
            if len(command.arguments) < 2 or command.arguments[0] != "-c":
                found.append(where + "/usr/bin/python3 must be given inline code with -c")
            elif PYTHON_SPAWNS.search(command.arguments[1]):
                found.append(where + "inline python may start another program")
        elif word == "/usr/bin/awk":
            if not command.arguments or command.arguments[0] not in AWK_PROGRAMS:
                found.append(where + "/usr/bin/awk given an unlisted program")
        elif word == SUDO and sudo_targets:
            if not command.arguments or command.arguments[0] not in sudo_targets:
                found.append(where + "/usr/bin/sudo given an unlisted command or option: " +
                             " ".join(command.arguments[:1]))
        elif word in ALLOWED_TOOLS:
            pass
        elif word.startswith("/"):
            found.append(where + "absolute path not on the allowlist: " + word)
        else:
            found.append(where + "command resolved through PATH: " + word)
    return found


class GuardSelfCheckTests(unittest.TestCase):
    """Pass before and after the fix: prove the guard can fail."""

    BARE = {
        "top level": "rm -f /tmp/x\n",
        "function body": "cleanup() {\n    rm -f /tmp/x\n}\n",
        "pipeline": "/usr/bin/head -1 /tmp/x | tr -d ' '\n",
        "after &&": "[ -n \"$A\" ] && launchctl bootout system/x\n",
        "after ||": "/bin/launchctl bootout system/x || rm -f /tmp/x\n",
        "after a continuation": "/bin/launchctl kickstart x 2>/dev/null || \\\n    rm -f /tmp/x\n",
        "command substitution": "A=\"$(id -u)\"\n",
        "nested substitution": "A=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\n",
        "substitution in an argument": "[ \"$(uname -s)\" = Darwin ] || exit 1\n",
        "substitution in arithmetic": "A=$(( 1 + $(wc -l < /tmp/x) ))\n",
        "substitution in a parameter default": "A=\"${B:-$(id -un)}\"\n",
        "substitution in a here-string": "read -r A <<< \"$(cat /tmp/x)\"\n",
        "substitution in an array after a comment": "A=(\n    # note\n    $(id -u)\n)\n",
        "if condition": "if ! launchctl bootstrap system x; then exit 1; fi\n",
        "while condition": "while sleep 1; do :; done\n",
        "for body": "for f in a b; do rm -f \"$f\"; done\n",
        "case arm": "case \"$1\" in\n    a|b) rm -f /tmp/x ;;\n    *) : ;;\nesac\n",
        "last case arm without ;;": "case \"$1\" in\n    a) : ;;\n    *) chmod 600 /tmp/x\nesac\n",
        "subshell": "( cd /tmp && rm -f x )\n",
        "brace group": "[ -e /tmp/x ] || { echo no >&2; rm -f /tmp/y; }\n",
        "after an assignment prefix": "LC_ALL=C ls -l /tmp\n",
        "background": "sleep 1 &\n",
        "quoted command word": "\"rm\" -f /tmp/x\n",
        "variable command word": "\"$TOOL\" -f /tmp/x\n",
        "relative path": "./helper.sh\n",
        "here-document command": "cat <<EOF\nhello\nEOF\n",
        "after a here-document": "/bin/cat <<'EOF'\nrm stays text\nEOF\nrm -f /tmp/x\n",
    }
    WRAPPED = {
        "eval": "eval \"$A\"\n",
        "exec": "exec /bin/rm -f /tmp/x\n",
        "command builtin": "command rm -f /tmp/x\n",
        "source": "source /tmp/x\n",
        "dot": ". /tmp/x\n",
        "trap": "trap 'rm -f /tmp/x' EXIT\n",
        "env": "/usr/bin/env rm -f /tmp/x\n",
        "xargs": "/bin/cat /tmp/x | /usr/bin/xargs rm\n",
        "sudo": "/usr/bin/sudo -u nobody id\n",
        "homebrew path": "/usr/local/bin/jq . /tmp/x\n",
        "awk running a program": "/usr/bin/awk 'BEGIN { system(\"id\") }'\n",
        "awk program from a variable": "/usr/bin/awk \"$PROGRAM\" /tmp/x\n",
        "bash -c": "/bin/bash -c 'rm -f /tmp/x'\n",
        "bash unlisted script": "/bin/bash \"$OTHER\"\n",
        "python script file": "/usr/bin/python3 /tmp/x.py\n",
        "python spawning": "/usr/bin/python3 -c \"import subprocess; subprocess.run(['id'])\"\n",
        "python os.system": "/usr/bin/python3 -c \"import os; os.system('id')\"\n",
        "here-document to an interpreter": "/usr/bin/python3 - <<'EOF'\nprint(1)\nEOF\n",
        "substitution in a here-document": "/bin/cat <<EOF\n$(id -u)\nEOF\n",
        "PATH widened": "export PATH=\"/usr/local/bin:$PATH\"\n",
        "backticks": "A=`id -u`\n",
        "process substitution": "/bin/cat <(id -u)\n",
        "function keyword": "function f { rm -f /tmp/x; }\n",
        "unterminated quote": "echo \"unterminated\n",
    }
    CLEAN = (
        'set -euo pipefail\n' + PATH_LINE + '\n'
        'die() { echo "ERROR: $*" >&2; exit 1; }\n'
        'DIR="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd)"\n'
        'LIST=(\n    one.sh\n    # a comment (with brackets; rm) between elements\n    two.sh\n)\n'
        '[ "$(/usr/bin/id -u)" -eq 0 ] || die "must run as root"\n'
        'case "$1" in\n    --x|-x) shift 2 ;;\n    [0-9]*) : ;;\n    *) die "unknown: $1" ;;\nesac\n'
        'for name in "${LIST[@]}"; do\n    /bin/rm -f "$DIR/$name"  # rm in a comment\ndone\n'
        'N="$(printf \'%s\' "$2" | /usr/bin/wc -c | /usr/bin/tr -d \' \' || true)"\n'
        'if [ $(( 0$N & 022 )) -ne 0 ] && [ $# -gt 0 ]; then echo "rm is only text"; fi\n'
        'while IFS= read -r line; do :; done <<< "$N"\n'
        '/bin/launchctl kickstart -k "system/x" 2>/dev/null || \\\n'
        '    "$AGENT_DIR/patched-collect.sh" || echo "WARN" >&2\n'
        '/bin/bash "$ENDPOINT_INSTALL_SRC" ${ARGS[@]+"${ARGS[@]}"} || die "failed"\n'
        'T=$(/usr/bin/python3 -c "\nimport json, sys\nprint(json.load(open(sys.argv[1])))\n" "$DIR/e.json")\n'
        '/bin/cat <<EOF\nrun: sudo launchctl list | grep com.patched in $DIR\nEOF\n'
    )

    def test_guard_flags_a_bare_command_in_every_position(self):
        for name, text in self.BARE.items():
            with self.subTest(position=name):
                found = violations(text)
                self.assertTrue(found, "guard missed a PATH-resolved command: " + text)
                self.assertTrue(any("PATH" in item for item in found), found)

    def test_guard_flags_wrappers_unlisted_paths_and_unreadable_shell(self):
        for name, text in self.WRAPPED.items():
            with self.subTest(construct=name):
                self.assertTrue(violations(text), "guard accepted: " + text)

    def test_guard_accepts_a_script_using_only_allowed_forms(self):
        self.assertEqual(violations(self.CLEAN), [])

    def test_guard_holds_sudo_to_the_listed_targets(self):
        allowed = ('"$BUNDLE_DIR/patched-fetch-posture.sh"',)
        script = '/usr/bin/sudo "$BUNDLE_DIR/patched-fetch-posture.sh"\n'
        self.assertTrue(violations(script), "sudo must be refused where no target is listed")
        self.assertEqual(violations(script, allowed), [])
        for name, text in {
                "bare sudo": 'sudo "$BUNDLE_DIR/patched-fetch-posture.sh"\n',
                "unlisted target": '/usr/bin/sudo "$BUNDLE_DIR/other.sh"\n',
                "option before the target": '/usr/bin/sudo -E "$BUNDLE_DIR/patched-fetch-posture.sh"\n',
                "target named by a variable": '/usr/bin/sudo "$TARGET"\n',
                "no target": "/usr/bin/sudo\n"}.items():
            with self.subTest(case=name):
                self.assertTrue(violations(text, allowed), "guard accepted: " + text)

    def test_guard_reports_one_violation_per_bare_command_site(self):
        found = violations("a() { rm x; }\nrm y | tr -d z\nA=$(id -u)\n")
        self.assertEqual(len(found), 4, found)
        self.assertEqual(sorted(re.sub(r".*: ", "", item) for item in found),
                         ["id", "rm", "rm", "tr"])


class InstallerCommandResolutionTests(unittest.TestCase):
    """Red until every guarded script stops resolving tools through PATH."""

    maxDiff = None

    def test_no_command_in_the_installer_scripts_resolves_through_path(self):
        for relative, sudo_targets in GUARDED.items():
            with self.subTest(script=relative):
                found = violations((ROOT / relative).read_text(), sudo_targets)
                self.assertEqual(found, [], relative + ":\n  " + "\n  ".join(found))

    def test_scanner_sees_the_known_command_sites(self):
        """The guard is only as good as its reach: name sites it must have read."""
        expected = {
            "macos/install.sh": {"/usr/bin/stat": 1, "/bin/ls": 1, "/usr/bin/python3": 1,
                           "/usr/bin/id": 1, "/usr/bin/uname": 1, "/usr/bin/dirname": 1,
                           "/usr/bin/head": 3, "/usr/bin/tr": 4, "/usr/bin/base64": 1,
                           "/usr/bin/wc": 1, "/usr/bin/install": 9, "/bin/chmod": 2,
                           "/usr/sbin/chown": 2, "/usr/libexec/PlistBuddy": 3,
                           "/bin/launchctl": 6, "/bin/rm": 2, "/bin/rmdir": 1, "/bin/bash": 1,
                           "/bin/cat": 2, '"$AGENT_DIR/patched-collect.sh"': 1},
            "macos/uninstall.sh": {"/usr/bin/id": 1, "/usr/bin/dirname": 1, "/bin/launchctl": 2,
                                   "/bin/rm": 7, "/bin/rmdir": 1, "/bin/cat": 2, "/bin/bash": 1,
                                   "/usr/bin/stat": 1, "/bin/ls": 1, "kill": 1},
            "tools/pkg-scripts/postinstall": {"/bin/launchctl": 3, "/bin/rm": 5,
                                              "/usr/bin/install": 1},
            "endpoint/install.sh": {"/usr/bin/dirname": 1, "/usr/bin/python3": 1, "/usr/bin/id": 1,
                                    "/usr/bin/shasum": 3, "/usr/bin/awk": 3, "/usr/bin/install": 4,
                                    "/bin/cp": 4, "/bin/chmod": 7, "/usr/sbin/chown": 6,
                                    "/bin/launchctl": 3, "/bin/rm": 5, "/bin/mv": 1},
            "endpoint/uninstall.sh": {"/usr/bin/id": 1, "/bin/launchctl": 2, "/bin/rm": 8,
                                      "/bin/cat": 1, "kill": 1},
            "macos/patched-collect-trigger.sh": {"/bin/date": 1, SUDO: 3},
            "macos/patched-uninstall-trigger.sh": {"/bin/date": 1, SUDO: 2},
        }
        self.assertEqual(set(expected), set(GUARDED))
        for name, sites in expected.items():
            commands, _ = command_words.scan((ROOT / name).read_text())
            counts = {}
            for command in commands:
                counts[command.word] = counts.get(command.word, 0) + 1
            for word, count in sites.items():
                with self.subTest(script=name, word=word):
                    self.assertEqual(counts.get(word, 0), count)
            external = {word for word in counts if word.startswith(("/", '"'))}
            self.assertEqual(external - set(sites), set(),
                             name + " runs a tool this test does not account for")

    def test_path_is_reset_before_the_first_external_command(self):
        for name in GUARDED:
            with self.subTest(script=name):
                text = (ROOT / name).read_text()
                declared = re.findall(r"^[ \t]*(?:export[ \t]+)?PATH\+?=.*$", text, re.M)
                self.assertEqual(declared, [PATH_LINE],
                                 "expected exactly one literal system-only PATH line")
                line = text[:text.index(PATH_LINE)].count("\n") + 1
                commands, _ = command_words.scan(text)
                early = [command for command in commands if command.line < line]
                self.assertEqual([command.word for command in early if command.word != "set"], [],
                                 "a command runs before PATH is reset")

    def test_agent_dir_command_root_is_a_literal_absolute_constant(self):
        declared = ancestry.constants((MACOS / "install.sh").read_text(), "AGENT_DIR")
        self.assertEqual(len(declared), 1)
        self.assertTrue(declared[0].startswith("/") and "$" not in declared[0], declared)
        self.assertNotRegex((MACOS / "install.sh").read_text(), r"(?m)^\s*AGENT_DIR\+?=(?!\"/)")

    @unittest.skipUnless(DARWIN, "the allowlisted paths are macOS system paths")
    def test_allowlisted_tools_are_root_owned_system_files(self):
        for tool in sorted(ALLOWED_TOOLS):
            with self.subTest(tool=tool):
                info = os.stat(tool)
                self.assertTrue(os.access(tool, os.X_OK), tool + " is not executable")
                self.assertEqual(info.st_uid, 0, tool + " is not root-owned")
                self.assertEqual(info.st_mode & 0o022, 0, tool + " is group- or other-writable")
                self.assertTrue(tool.startswith(("/bin/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/")))


# Tools the harness must replace to run unprivileged. In a shadow copy each
# absolute path is rebased onto an absolute stub path, so nothing in the copy
# depends on PATH; the PATH the script runs with is then filled with decoys.
STUBBED = {"/usr/bin/id": "id", "/usr/bin/uname": "uname", "/bin/launchctl": "launchctl",
           "/usr/sbin/chown": "chown", "/bin/chmod": "chmod", "/usr/bin/install": "install",
           "/bin/rm": "rm"}
DECOYS = sorted({Path(tool).name for tool in ALLOWED_TOOLS} | {
    "sh", "zsh", "env", "sudo", "mkdir", "cp", "mv", "ln", "touch", "sed", "awk", "grep", "cut",
    "sort", "tee", "date", "sleep", "find", "xargs", "curl", "tar", "shasum", "mktemp", "plutil",
    "defaults", "dscl", "pkill", "killall", "basename", "readlink", "realpath", "true", "false",
    "test", "[", "echo", "printf", "kill", "pwd", "python", "perl", "ruby", "osascript"})


class ShadowScratch(ancestry.Scratch):
    """A scratch install whose command search path holds only recording decoys."""

    def __init__(self, case, contract, poison_script_path):
        self.poison_script_path = poison_script_path
        super().__init__(case, contract)
        case.addCleanup(subprocess.run, ["/bin/chmod", "-R", "-N", str(self.base)],
                        capture_output=True)
        self.marker = self.base / "decoy-selected"
        for decoy in DECOYS:
            target = self.shadow / decoy
            target.write_text("#!/bin/sh\nprintf '%s\\n' " + shlex.quote(decoy) + " >> " +
                              shlex.quote(str(self.marker)) + "\nexit 0\n")
            target.chmod(0o700)

    @property
    def shadow(self):
        directory = self.base / "shadow"
        directory.mkdir(mode=0o755, exist_ok=True)
        return directory

    def script(self, name):
        return self.shadow_text((MACOS / name).read_text())

    def shadow_text(self, source, stubbed=None):
        stubbed = STUBBED if stubbed is None else stubbed
        text = self.rebase(source)
        pattern = "|".join(re.escape(tool) for tool in sorted(stubbed, key=len, reverse=True))
        text = re.sub(r'(?<![\w.$}/-])(' + pattern + r')(?![\w/.-])',
                      lambda match: shlex.quote(str(self.stubs / stubbed[match[1]])), text)
        if self.poison_script_path:
            # As if the PATH reset were missing: absolute paths must hold alone.
            text = re.sub(r'^\s*(?:export\s+)?PATH=.*$',
                          'export PATH=' + shlex.quote(str(self.shadow) + ":" + SYSTEM_PATH),
                          text, flags=re.M)
        override = ('patched_ancestry_probe() { ' + shlex.quote(sys.executable) + ' ' +
                    shlex.quote(str(self.probe)) + ' "$1" ' +
                    shlex.quote(str(self.owned_list)) + '; }')
        if not DARWIN:
            override += "\npatched_ancestry_acl_listing() { echo " + shlex.quote(HEADER) + "; }"
        return re.sub(r'^' + re.escape(ancestry.MARK_END) + r'.*$',
                      lambda match: match[0] + "\n" + override, text, flags=re.M)

    def run(self, name, *arguments):
        environment = {"PATH": str(self.shadow) + ":" + SYSTEM_PATH, "TMPDIR": str(self.tmp),
                       "HOME": str(self.tmp), "PAT2395_LOG": str(self.log),
                       "PAT2395_ENTRY_DIR": str(self.entry_dir)}
        return subprocess.run(["/bin/bash", str(self.stage / name), *arguments],
                              env=environment, cwd=str(self.stage), capture_output=True,
                              text=True, timeout=60, stdin=subprocess.DEVNULL)

    def selected(self):
        return self.marker.read_text().split() if self.marker.exists() else []


class CallerPathShadowTests(unittest.TestCase):
    """Run the real scripts with every tool name shadowed on the command search path.

    Two layers are checked separately: the caller's PATH poisoned with the
    script's own PATH line intact, and the script's PATH line itself poisoned,
    which absolute command words must survive on their own.
    """

    def scratch(self, poison_script_path):
        os.umask(0o022)
        return ShadowScratch(self, ancestry.Contract(), poison_script_path)

    def assert_clean(self, scratch, result, what):
        self.assertEqual(scratch.selected(), [],
                         what + " ran a tool chosen by PATH: " + " ".join(scratch.selected()))
        self.assertEqual(result.returncode, 0, what + ":\n" + result.stdout + result.stderr)

    def layers(self):
        for poison_script_path in (False, True):
            yield poison_script_path, ("script PATH poisoned" if poison_script_path
                                       else "caller PATH poisoned")

    def test_fresh_install_and_uninstall_select_no_tool_from_path(self):
        for poison, layer in self.layers():
            with self.subTest(layer=layer):
                scratch = self.scratch(poison)
                self.assert_clean(scratch, scratch.install(), "install")
                for label, name in zip(ancestry.INSTALLED_JOBS, ancestry.ENTRYPOINTS):
                    self.assertIn("NEW " + name, scratch.installed_entrypoint(label).read_text())
                self.assertEqual((scratch.path("/etc/patched") / "tenant-id").read_text().strip(),
                                 ancestry.CREDENTIALS["tenant-id"])
                self.assertEqual(scratch.endpoint_calls(), ["endpoint-install.sh"])
                state = scratch.path("/Library/Application Support/Patched")
                (state / ".agent-health.lock").mkdir(parents=True)
                finished = subprocess.Popen(["/bin/sh", "-c", "exit 0"])
                finished.wait()
                (state / ".agent-health.lock" / "pid").write_text("%d|0\n" % finished.pid)
                (state / ".agent-health.json").write_text("{}\n")
                self.assert_clean(scratch, scratch.run("uninstall.sh", "--purge"), "uninstall")
                self.assertFalse(scratch.entry_dir.exists(), "uninstall left the tree")
                self.assertFalse(scratch.path("/etc/patched").exists(), "--purge kept credentials")
                self.assertFalse((state / ".agent-health.lock").exists())
                self.assertEqual(scratch.endpoint_calls(),
                                 ["endpoint-install.sh", "endpoint-uninstall.sh"])

    def test_upgrade_without_start_selects_no_tool_from_path(self):
        for poison, layer in self.layers():
            with self.subTest(layer=layer):
                scratch = self.scratch(poison)
                scratch.plant_legacy_install()
                legacy_lib = scratch.homebrew / "lib"
                legacy_lib.mkdir()
                (legacy_lib / "common.sh").write_text("# ours\n")
                (scratch.stage / "lib").mkdir()
                (scratch.stage / "lib" / "common.sh").write_text("# module\n")
                staged = scratch.base / "creds"
                staged.mkdir()
                for name, value in ancestry.CREDENTIALS.items():
                    (staged / name).write_text("  " + value + " \nsecond line\n")
                result = scratch.run("install.sh", "--creds-dir", str(staged), "--no-start")
                self.assert_clean(scratch, result, "upgrade")
                for name in ancestry.ENTRYPOINTS:
                    self.assertFalse((scratch.homebrew / name).exists())
                    self.assertTrue((scratch.entry_dir / name).is_file())
                self.assertFalse(legacy_lib.exists(), "emptied legacy lib directory left behind")
                self.assertTrue((scratch.entry_dir / "lib" / "common.sh").is_file())
                self.assertEqual((scratch.path("/etc/patched") / "bearer-token").read_text().strip(),
                                 ancestry.CREDENTIALS["bearer-token"])
                self.assertTrue((scratch.homebrew / "brew-tool").is_file())
                self.assert_clean(scratch, scratch.run("uninstall.sh"), "uninstall")
                self.assertTrue((scratch.path("/etc/patched") / "bearer-token").is_file())

    def test_help_and_enrollment_file_select_no_tool_from_path(self):
        for poison, layer in self.layers():
            with self.subTest(layer=layer):
                scratch = self.scratch(poison)
                result = scratch.run("install.sh", "--help")
                self.assert_clean(scratch, result, "--help")
                self.assertIn("--enrollment-token", result.stdout)
                (scratch.stage / "enrollment.json").write_text('{"enrollment_token": "TESTTOKEN-ABC"}\n')
                self.assert_clean(scratch, scratch.run("install.sh"), "enrollment install")
                self.assertEqual((scratch.path("/etc/patched") / "enrollment-token").read_text().strip(),
                                 "TESTTOKEN-ABC")

    @unittest.skipUnless(DARWIN, "PlistBuddy is macOS-only")
    def test_custom_api_url_selects_no_tool_from_path(self):
        for poison, layer in self.layers():
            with self.subTest(layer=layer):
                scratch = self.scratch(poison)
                arguments = ["--api-url", "https://api.example.invalid"]
                for name, value in ancestry.CREDENTIALS.items():
                    arguments += ["--" + name, value]
                self.assert_clean(scratch, scratch.run("install.sh", *arguments), "install")
                plist = (scratch.daemons / "com.patched.upload.plist").read_text()
                self.assertIn("https://api.example.invalid", plist)


# ---------------------------------------------------------------------------
# PAT-2420: the endpoint installer pair and the trigger scripts
# ---------------------------------------------------------------------------
ENDPOINT_DAEMONS = ("com.patched.update.plist", "com.patched.config-poll.plist",
                    "com.patched.posture-poll.plist")
TRIGGER_STUBS = {"/usr/bin/sudo": "sudo", "/bin/date": "date"}


def execute(scratch, script, *arguments, interpreter="/bin/bash"):
    environment = {"PATH": str(scratch.shadow) + ":" + SYSTEM_PATH, "TMPDIR": str(scratch.tmp),
                   "HOME": str(scratch.tmp), "PAT2395_LOG": str(scratch.log),
                   "PAT2395_ENTRY_DIR": str(scratch.entry_dir)}
    return subprocess.run([interpreter, str(script), *arguments], env=environment,
                          cwd=str(script.parent), capture_output=True, text=True, timeout=60,
                          stdin=subprocess.DEVNULL)


class EndpointAndTriggerShadowTests(unittest.TestCase):
    """Run the four PAT-2420 scripts with every tool name shadowed on PATH."""

    scratch = CallerPathShadowTests.scratch
    assert_clean = CallerPathShadowTests.assert_clean
    layers = CallerPathShadowTests.layers

    def endpoint_stage(self, scratch):
        """A release directory: both scripts beside a minimal hash-pinned bundle."""
        stage = scratch.base / "endpoint-stage"
        bundle = stage / "patched-updater"
        bundle.mkdir(parents=True)
        files = dict({name: "<plist/>\n" for name in ENDPOINT_DAEMONS},
                     **{"patched-fetch-config.sh": "#!/bin/zsh\n", "verify-agent-config.py": "# py\n"})
        manifest = ""
        for name, content in sorted(files.items()):
            (bundle / name).write_text(content)
            manifest += hashlib.sha256(content.encode()).hexdigest() + " " + name + "\n"
        (bundle / "manifest.sha256").write_text(manifest)
        daemon = "#!/bin/zsh\n# daemon\n"
        (bundle / "patched-update.sh").write_text(daemon)
        install = (ENDPOINT / "install.sh").read_text()
        self.assertEqual(install.count("__MANIFEST_HASH__"), 1)
        self.assertEqual(install.count("__DAEMON_HASH__"), 1)
        install = install.replace("__MANIFEST_HASH__", hashlib.sha256(manifest.encode()).hexdigest())
        install = install.replace("__DAEMON_HASH__", hashlib.sha256(daemon.encode()).hexdigest())
        (stage / "install.sh").write_text(scratch.shadow_text(install))
        (stage / "uninstall.sh").write_text(
            scratch.shadow_text((ENDPOINT / "uninstall.sh").read_text()))
        return stage

    def test_endpoint_install_and_uninstall_select_no_tool_from_path(self):
        for poison, layer in self.layers():
            with self.subTest(layer=layer):
                scratch = self.scratch(poison)
                stage = self.endpoint_stage(scratch)
                bundle = scratch.path("/usr/local/patched-updater")
                state = scratch.path("/Library/Application Support/Patched")
                creds = scratch.path("/etc/patched")
                # What an older release left behind, so the purge block runs.
                bundle.mkdir()
                (bundle / "Installomator.sh").write_text("# legacy\n")
                (scratch.daemons / "com.patched.catalogue-poll.plist").write_text("<plist/>\n")
                (state / ".patched-catalogue-fetch.lock").mkdir(parents=True)
                (state / "catalogue.json").write_text("{}\n")
                result = execute(scratch, stage / "install.sh", "--enrollment-token", "TESTTOKEN-ABC")
                self.assert_clean(scratch, result, "endpoint install")
                for name in ENDPOINT_DAEMONS:
                    self.assertTrue((scratch.daemons / name).is_file(), name)
                    self.assertTrue((bundle / name).is_file(), name)
                self.assertTrue((bundle / "patched-update.sh").is_file())
                self.assertEqual((creds / "enrollment-token").read_text().strip(), "TESTTOKEN-ABC")
                self.assertFalse((bundle / "Installomator.sh").exists())
                self.assertFalse((scratch.daemons / "com.patched.catalogue-poll.plist").exists())
                self.assertFalse((state / "catalogue.json").exists())
                self.assertFalse((state / ".patched-catalogue-fetch.lock").exists())
                loaded = [call["argv"] for call in scratch.calls("launchctl")
                          if call["argv"][:1] == ["bootstrap"]]
                self.assertEqual(len(loaded), len(ENDPOINT_DAEMONS), loaded)

                (state / "posture.json").write_text("{}\n")
                (state / "blocking-deferrals-zoom.json").write_text("{}\n")
                (state / ".agent-health.lock").mkdir()
                result = execute(scratch, stage / "uninstall.sh")
                self.assert_clean(scratch, result, "endpoint uninstall")
                self.assertFalse(bundle.exists(), "uninstall left the bundle")
                for name in ENDPOINT_DAEMONS:
                    self.assertFalse((scratch.daemons / name).exists(), name)
                for name in ("posture.json", "blocking-deferrals-zoom.json", ".agent-health.lock",
                             "triggers"):
                    self.assertFalse((state / name).exists(), name)
                self.assertTrue((creds / "enrollment-token").is_file(),
                                "endpoint uninstall must leave the shared credentials")

    def test_endpoint_install_without_start_selects_no_tool_from_path(self):
        for poison, layer in self.layers():
            with self.subTest(layer=layer):
                scratch = self.scratch(poison)
                stage = self.endpoint_stage(scratch)
                (stage / "enrollment.json").write_text('{"enrollment_token": "FROM-FILE"}\n')
                result = execute(scratch, stage / "install.sh", "--no-start")
                self.assert_clean(scratch, result, "endpoint install --no-start")
                self.assertEqual(
                    (scratch.path("/etc/patched") / "enrollment-token").read_text().strip(),
                    "FROM-FILE")
                self.assertEqual([call["argv"] for call in scratch.calls("launchctl")
                                  if call["argv"][:1] == ["bootstrap"]], [])

    def test_pkg_postinstall_selects_no_tool_from_path(self):
        for poison, layer in self.layers():
            with self.subTest(layer=layer):
                scratch = self.scratch(poison)
                bundle = scratch.path("/usr/local/patched-updater")
                bundle.mkdir()
                for name in ENDPOINT_DAEMONS[:2] + ("Installomator.sh",):
                    (bundle / name).write_text("<plist/>\n")
                (scratch.daemons / "com.patched.catalogue-poll.plist").write_text("<plist/>\n")
                script = scratch.base / "postinstall"
                script.write_text(scratch.shadow_text(
                    (ROOT / "tools" / "pkg-scripts" / "postinstall").read_text()))
                self.assert_clean(scratch, execute(scratch, script), "postinstall")
                for name in ENDPOINT_DAEMONS[:2]:
                    self.assertTrue((scratch.daemons / name).is_file(), name)
                self.assertFalse((bundle / "Installomator.sh").exists())
                self.assertFalse((scratch.daemons / "com.patched.catalogue-poll.plist").exists())
                self.assertEqual(len([call for call in scratch.calls("launchctl")
                                      if call["argv"][:1] == ["bootstrap"]]), 2)

    def trigger(self, scratch, name, *arguments):
        """Run a trigger with sudo and date replaced by recording stubs."""
        zsh = shutil.which("zsh")
        self.assertIsNotNone(zsh, "zsh is required; bash/sh is not a valid substitute")
        record = scratch.base / "trigger-calls.log"
        for tool in TRIGGER_STUBS.values():
            stub = scratch.stubs / tool
            stub.write_text("#!/bin/sh\nprintf '%s\\n' " + shlex.quote(tool) + "\" $*\" >> " +
                            shlex.quote(str(record)) + "\nexit 0\n")
            stub.chmod(0o700)
        script = scratch.base / name
        script.write_text(scratch.shadow_text((MACOS / name).read_text(), TRIGGER_STUBS))
        result = execute(scratch, script, *arguments, interpreter=zsh)
        calls = record.read_text().splitlines() if record.exists() else []
        return result, [call for call in calls if call.startswith("sudo ")]

    def test_triggers_select_no_tool_from_path(self):
        for poison, layer in self.layers():
            with self.subTest(layer=layer, trigger="collect"):
                scratch = self.scratch(poison)
                result, started = self.trigger(scratch, "patched-collect-trigger.sh")
                self.assert_clean(scratch, result, "collect trigger")
                tree = scratch.path(ancestry.Contract().agent_dir)
                bundle = scratch.path("/usr/local/patched-updater")
                self.assertEqual(started, ["sudo " + str(tree / "patched-collect.sh"),
                                           "sudo " + str(tree / "patched-upload.sh"),
                                           "sudo " + str(bundle / "patched-fetch-posture.sh")])
            with self.subTest(layer=layer, trigger="uninstall"):
                scratch = self.scratch(poison)
                result, started = self.trigger(scratch, "patched-uninstall-trigger.sh", "Acme App")
                self.assert_clean(scratch, result, "uninstall trigger")
                bundle = scratch.path("/usr/local/patched-updater")
                self.assertEqual(started,
                                 ["sudo " + str(bundle / "patched-uninstall.sh") + " --app-id Acme App",
                                  "sudo " + str(bundle / "patched-fetch-posture.sh")])


# ---------------------------------------------------------------------------
# PAT-2420: the uninstaller verifies the tree's ancestry before deleting it
# ---------------------------------------------------------------------------
def uninstall_block():
    text = (MACOS / "uninstall.sh").read_text()
    match = re.search(re.escape(ancestry.MARK_START) + r"[^\n]*\n(.*?)^" +
                      re.escape(ancestry.MARK_END), text, re.M | re.S)
    return match[1] if match else None


class UninstallAncestryTests(unittest.TestCase):
    """Red until macos/uninstall.sh refuses to delete through an untrusted path.

    uninstall.sh ships alone (as macos-uninstall.sh in the endpoint bundle), so
    it cannot source the helpers from install.sh and carries its own copy.
    """

    def setUp(self):
        os.umask(0o022)

    def installed(self):
        scratch = ancestry.Scratch(self, ancestry.Contract())
        self.addCleanup(subprocess.run, ["/bin/chmod", "-R", "-N", str(scratch.base)],
                        capture_output=True)
        result = scratch.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        scratch.log.write_text("")
        return scratch

    def test_helper_block_is_byte_identical_to_the_installer(self):
        block = uninstall_block()
        self.assertIsNotNone(block, "macos/uninstall.sh has no " + ancestry.MARK_START + " block")
        self.assertEqual(block, helper_block(self),
                         "the ancestry helpers in macos/uninstall.sh have drifted from macos/install.sh")
        text = (MACOS / "uninstall.sh").read_text()
        self.assertEqual(ancestry.constants(text, "ANCESTRY_ANCHOR"), ["/"])
        self.assertEqual(text.count(ancestry.MARK_START), 1)

    def test_ancestry_is_verified_before_the_first_delete(self):
        commands, _ = command_words.scan((MACOS / "uninstall.sh").read_text())
        verifies = [c for c in commands if c.word == "patched_verify_ancestry"]
        self.assertEqual([c.arguments[:2] for c in verifies], [['"$AGENT_DIR"', '"$ANCESTRY_ANCHOR"']],
                         "exactly one verification, of the tree against the anchor")
        # That one call is the body of agent_dir_may_be_deleted; the script asks it twice.
        checks = [c.line for c in commands if c.word == "agent_dir_may_be_deleted"]
        self.assertEqual(len(checks), 2, "expected a check up front and one at the delete")
        self.assertLess(verifies[0].line, checks[0])
        deletes = [c.line for c in commands if c.word in ("/bin/rm", "/bin/rmdir")]
        self.assertLess(checks[0], min(deletes), "a delete runs before the ancestry check")
        recursive = [c.line for c in commands if c.word == "/bin/rm" and '"$AGENT_DIR"' in c.arguments]
        self.assertEqual(len(recursive), 1)
        self.assertEqual(checks[1], recursive[0] - 1,
                         "the tree must be verified again on the line that guards its delete")

    def assert_refused(self, scratch, result, bad, purge):
        output = result.stdout + result.stderr
        tree = scratch.entry_dir
        self.assertNotEqual(result.returncode, 0, "uninstall reported success:\n" + output)
        for name in ancestry.ENTRYPOINTS:
            self.assertTrue(os.path.lexists(str(tree / name)) or tree.is_symlink(),
                            "uninstall deleted through an untrusted path: " + name)
        deleted = [call["argv"] for call in scratch.calls("rm")
                   if any(os.path.normpath(item) == str(tree) or
                          item.startswith(str(tree) + "/") for item in call["argv"])]
        self.assertEqual(deleted, [], "rm was aimed at the untrusted tree")
        self.assertIn(str(bad), result.stderr, "the refusal must name the rejected component")
        self.assertRegex(result.stderr, r"(?i)not removed")
        self.assertIn(str(tree), result.stderr)
        # Everything that is not under the untrusted path is still cleaned up.
        for label in ancestry.INSTALLED_JOBS:
            self.assertFalse((scratch.daemons / (label + ".plist")).exists(), label)
            self.assertTrue(any(call["argv"] == ["bootout", "system/" + label]
                                for call in scratch.calls("launchctl")), label + " not booted out")
        self.assertEqual(scratch.endpoint_calls()[-1:], ["endpoint-uninstall.sh"])
        creds = scratch.path("/etc/patched")
        queue = scratch.path("/var/db/patched")
        self.assertEqual(creds.exists(), not purge, "--purge must still be honoured")
        self.assertEqual(queue.exists(), not purge, "--purge must still be honoured")

    def test_owner_cases_refuse_the_recursive_delete(self):
        for variant in ("user-owned parent", "group-writable parent",
                        "pre-existing user-owned tree", "pre-existing symlink tree"):
            for purge in (False, True):
                with self.subTest(variant=variant, purge=purge):
                    scratch = self.installed()
                    bad = scratch.poison(variant)
                    result = scratch.run("uninstall.sh", *(["--purge"] if purge else []))
                    self.assert_refused(scratch, result, bad, purge)
                    if variant == "pre-existing symlink tree":
                        moved = scratch.root / "Users" / "mallory" / "moved-tree"
                        self.assertTrue((moved / ancestry.ENTRYPOINTS[0]).is_file(),
                                        "uninstall deleted behind a symlink")
                        self.assertTrue(scratch.entry_dir.is_symlink(), "the symlink was removed")

    @unittest.skipUnless(DARWIN, "needs a real macOS ACL")
    def test_acl_cases_refuse_the_recursive_delete(self):
        for position in ("parent", "tree"):
            with self.subTest(position=position):
                scratch = self.installed()
                bad = scratch.entry_dir.parent if position == "parent" else scratch.entry_dir
                add_acl(self, bad, "group:admin allow add_file,add_subdirectory,delete_child")
                result = scratch.run("uninstall.sh", "--purge")
                self.assert_refused(scratch, result, bad, True)
                self.assertRegex(result.stderr, r"(?i)\bACL\b")

    def test_trusted_ancestry_is_deleted_and_exits_zero(self):
        scratch = self.installed()
        if DARWIN:   # grants that give nothing away must not block an uninstall
            add_acl(self, scratch.entry_dir.parent, "user:daemon deny delete")
            add_acl(self, scratch.entry_dir, "group:admin allow list,search")
        result = scratch.run("uninstall.sh")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(scratch.entry_dir.exists(), "uninstall left the tree")
        self.assertNotRegex(result.stderr, r"(?i)not removed")

    def test_nothing_to_delete_under_an_untrusted_parent_is_not_a_failure(self):
        """A legacy-only machine: no tree, so no delete to refuse."""
        scratch = ancestry.Scratch(self, ancestry.Contract())
        scratch.plant_legacy_install()
        scratch.poison("group-writable parent")
        self.assertFalse(os.path.lexists(str(scratch.entry_dir)))
        result = scratch.run("uninstall.sh")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for name in ancestry.ENTRYPOINTS:
            self.assertFalse((scratch.homebrew / name).exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
