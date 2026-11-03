"""PAT-2307: the deploy refuses to run anything a non-root user could have changed.

On patched-prod-01 root runs scripts/deploy.sh, pip, the smoke suite and two
timer scripts out of /opt/patched-dashboard, installs systemd units, polkit
rules and the nginx site config from it, and runs the post-receive hook in
/opt/git/dashboard.git. Until this ticket both trees belonged to www-data (or
to a uid with no passwd entry), so the app could plant code that root ran on
the next deploy.

deploy/code-tree-guard.sh is the check and the fix. These tests drive the real
script against scratch trees. They cannot chown to root without privilege, so
the tree's owner is configured as the invoking user (CODE_TREE_OWNER), exactly
as the deploy harness does; the owner test runs the other way round, with the
owner set to root and the files owned by the test user, standing in for
www-data.
"""

from __future__ import annotations

import grp
import os
import pwd
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
GUARD = REPO / "deploy" / "code-tree-guard.sh"

SHA_A = "a" * 40
SHA_B = "b" * 40


def _me() -> tuple[str, str]:
    return pwd.getpwuid(os.getuid()).pw_name, grp.getgrgid(os.getgid()).gr_name


def _write(path: Path, content: str, mode: int) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    os.chmod(path, mode)
    return path


class Box:
    """A scratch stand-in for patched-prod-01's code tree, mirror and state dir."""

    def __init__(self, base: Path):
        self.base = base
        self.tree = base / "opt" / "patched-dashboard"
        self.mirror = base / "opt" / "git" / "dashboard.git"
        self.state = base / "var" / "lib" / "patched-dashboard"
        self.outside = base / "usr" / "bin"
        _write(self.tree / "scripts" / "deploy.sh", "#!/bin/bash\n", 0o755)
        _write(self.tree / "scripts" / "smoke" / "run_all.py", "print('ok')\n", 0o755)
        _write(self.tree / "deploy" / "nginx-dashboard.conf", "server {}\n", 0o644)
        _write(self.tree / "deploy" / "patched-dashboard.service", "[Service]\n", 0o644)
        _write(self.tree / "main.py", "app = None\n", 0o644)
        _write(self.mirror / "hooks" / "post-receive", "#!/bin/bash\n", 0o755)
        _write(self.mirror / "config", "[core]\n\tbare = true\n", 0o644)
        _write(self.outside / "python3", "#!/bin/sh\n", 0o755)
        (self.tree / "venv" / "bin").mkdir(parents=True)
        (self.tree / "venv" / "bin" / "python3").symlink_to(self.outside / "python3")
        (self.tree / "venv" / "lib").mkdir()
        (self.tree / "venv" / "lib64").symlink_to("lib")
        for directory in (self.base, *self.base.rglob("*")):
            if directory.is_dir() and not directory.is_symlink():
                os.chmod(directory, 0o755)

    def env(self, **overrides: str) -> dict[str, str]:
        user, group = _me()
        env = dict(
            os.environ,
            CODE_TREE_DIR=str(self.tree),
            CODE_TREE_MIRROR_DIR=str(self.mirror),
            CODE_TREE_OWNER=user,
            CODE_TREE_GROUP=group,
            CODE_TREE_STATE_DIR=str(self.state),
            CODE_TREE_SERVICE_USER=user,
            CODE_TREE_SERVICE_GROUP=group,
            CODE_TREE_RUN_AS_SELF="1",
        )
        env.update(overrides)
        return env

    def run(self, *args: str, **overrides: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(GUARD), *args],
            text=True, capture_output=True, env=self.env(**overrides), timeout=60,
        )


@pytest.fixture
def box(tmp_path: Path) -> Box:
    return Box(tmp_path / "box")


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


# ── check: the guard itself ────────────────────────────────────────────────


def test_a_locked_tree_passes(box: Box):
    result = box.run("check")
    assert result.returncode == 0, result.stderr
    assert "code-tree-guard: ok" in result.stdout
    assert "::error::" not in result.stderr


def test_a_group_writable_deploy_script_fails_the_deploy(box: Box):
    """The exact escalation: the service user rewrites what root runs next."""
    os.chmod(box.tree / "scripts" / "deploy.sh", 0o775)
    result = box.run("check")
    assert result.returncode == 1
    assert "::error::code-tree-guard: owned or writable by a non-root user:" in result.stderr
    assert "scripts/deploy.sh" in result.stderr
    assert "adopt_code_tree=true" in result.stderr


def test_a_world_writable_nginx_config_fails_the_deploy(box: Box):
    os.chmod(box.tree / "deploy" / "nginx-dashboard.conf", 0o646)
    result = box.run("check")
    assert result.returncode == 1
    assert "deploy/nginx-dashboard.conf" in result.stderr


def test_a_writable_directory_fails_even_when_every_file_in_it_is_locked(box: Box):
    """Directory write lets the holder rename a root-owned file away and put
    its own in its place, so a writable deploy/ is as bad as a writable file."""
    os.chmod(box.tree / "deploy", 0o775)
    result = box.run("check")
    assert result.returncode == 1
    assert f"non-root user: {box.tree.resolve() / 'deploy'}\n" in result.stderr


def test_the_mirror_hook_directory_is_held_to_the_same_standard(box: Box):
    os.chmod(box.mirror / "hooks", 0o777)
    result = box.run("check")
    assert result.returncode == 1
    assert "dashboard.git/hooks" in result.stderr


@pytest.mark.skipif(os.geteuid() == 0, reason="needs a non-root test user to stand in for www-data")
def test_files_owned_by_a_non_root_user_fail_even_without_write_bits(box: Box):
    """Ownership alone is enough: the owner can chmod its own file back to writable."""
    result = box.run("check", CODE_TREE_OWNER="root", CODE_TREE_GROUP="root")
    assert result.returncode == 1
    assert "scripts/deploy.sh" in result.stderr or "more." in result.stderr


def test_a_symlink_to_a_writable_file_outside_the_tree_fails(box: Box):
    os.chmod(box.outside / "python3", 0o777)
    result = box.run("check")
    assert result.returncode == 1
    assert "venv/bin/python3 ->" in result.stderr


def test_a_symlink_into_a_writable_directory_outside_the_tree_fails(box: Box):
    os.chmod(box.outside, 0o777)
    result = box.run("check")
    assert result.returncode == 1
    assert "venv/bin/python3 ->" in result.stderr


def test_a_dangling_symlink_fails_closed(box: Box):
    (box.tree / "scripts" / "later.sh").symlink_to(box.base / "nowhere" / "later.sh")
    result = box.run("check")
    assert result.returncode == 1
    assert "dangling symlink" in result.stderr


def test_a_writable_directory_above_the_tree_fails(box: Box):
    os.chmod(box.base / "opt", 0o777)
    result = box.run("check")
    assert result.returncode == 1
    assert str((box.base / "opt").resolve()) in result.stderr


def test_a_sticky_world_writable_directory_above_the_tree_is_allowed(box: Box):
    """/tmp-style: the sticky bit stops other users renaming entries they do
    not own, and the component below is itself checked."""
    os.chmod(box.base / "opt", 0o1777)
    result = box.run("check")
    assert result.returncode == 0, result.stderr


def test_a_missing_mirror_fails_rather_than_checking_half_the_box(box: Box):
    result = box.run("check", CODE_TREE_MIRROR_DIR=str(box.base / "absent.git"))
    assert result.returncode == 1
    assert "nothing was checked" in result.stderr


def test_the_guard_runs_when_piped_in_over_stdin_as_the_workflow_does(box: Box):
    """deploy.yml runs `ssh root@box 'bash -s -- check' < deploy/code-tree-guard.sh`.
    Nothing in the script may read stdin, or it would eat its own source."""
    with GUARD.open("rb") as source:
        ok = subprocess.run(
            ["bash", "-s", "--", "check"], stdin=source,
            capture_output=True, env=box.env(), timeout=60,
        )
    assert ok.returncode == 0, ok.stderr.decode()
    os.chmod(box.tree / "scripts" / "deploy.sh", 0o777)
    with GUARD.open("rb") as source:
        bad = subprocess.run(
            ["bash", "-s", "--", "check"], stdin=source,
            capture_output=True, env=box.env(), timeout=60,
        )
    assert bad.returncode == 1
    assert b"scripts/deploy.sh" in bad.stderr


# ── lock ───────────────────────────────────────────────────────────────────


def test_lock_removes_group_and_other_write_and_keeps_deployed_sha_readable(box: Box):
    os.chmod(box.tree / "scripts" / "deploy.sh", 0o777)
    os.chmod(box.tree / "deploy", 0o777)
    os.chmod(box.mirror / "hooks" / "post-receive", 0o775)
    sha = _write(box.tree / "DEPLOYED_SHA", f"DEPLOYED_SHA={SHA_A}\n", 0o600)
    assert box.run("check").returncode == 1

    locked = box.run("lock")
    assert locked.returncode == 0, locked.stderr
    assert box.run("check").returncode == 0
    assert _mode(box.tree / "scripts" / "deploy.sh") == 0o755
    assert _mode(sha) == 0o644, "the app reads DEPLOYED_SHA (deploy_drift); root owns it"


def test_lock_never_follows_a_symlink_out_of_the_tree(box: Box):
    """A link planted in the tree must not turn root's chmod/chown onto the
    file it points at; the check then still refuses the link."""
    os.chmod(box.outside / "python3", 0o777)
    assert box.run("lock").returncode == 0
    assert _mode(box.outside / "python3") == 0o777
    assert box.run("check").returncode == 1


# ── prepare-state: moving the app's runtime data out of the tree ─────────


def test_prepare_state_copies_verifies_and_leaves_the_originals(box: Box):
    nvd = _write(box.tree / "nvd.db", "SQLite format 3\x00cache", 0o644)
    report = _write(box.tree / "reports" / "Patched_CVE_Acme.docx", "docx-bytes", 0o644)
    os.utime(report, (1_700_000_000, 1_700_000_000))
    box.state.mkdir(parents=True)

    result = box.run("prepare-state")
    assert result.returncode == 0, result.stderr

    moved_nvd = box.state / "nvd.db"
    moved_report = box.state / "reports" / "Patched_CVE_Acme.docx"
    assert moved_nvd.read_bytes() == nvd.read_bytes()
    assert moved_report.read_bytes() == report.read_bytes()
    assert int(moved_report.stat().st_mtime) == 1_700_000_000, (
        "prune-reports.sh ages reports out by mtime; the copy must keep it"
    )
    assert nvd.exists() and report.exists(), "originals are never deleted in the same deploy"
    assert "verified byte for byte" in result.stdout
    assert not list(box.state.rglob("*.migrate.*")), "no temporary copies left behind"


def test_prepare_state_never_overwrites_what_the_app_already_wrote(box: Box):
    _write(box.tree / "nvd.db", "old cache", 0o644)
    newer = _write(box.state / "nvd.db", "newer cache the app built", 0o644)

    result = box.run("prepare-state")
    assert result.returncode == 0, result.stderr
    assert newer.read_text() == "newer cache the app built"
    assert "left as it is" in result.stdout


def test_prepare_state_is_idempotent(box: Box):
    _write(box.tree / "nvd.db", "cache", 0o644)
    box.state.mkdir(parents=True)
    assert box.run("prepare-state").returncode == 0
    again = box.run("prepare-state")
    assert again.returncode == 0, again.stderr
    assert "already matches" in again.stdout


def test_prepare_state_does_not_copy_through_symlinks_or_a_hot_journal(box: Box):
    secret = _write(box.base / "etc" / "shadow", "root:hash", 0o600)
    (box.tree / "reports").mkdir(parents=True)
    (box.tree / "reports" / "planted.docx").symlink_to(secret)
    _write(box.tree / "nvd.db", "cache", 0o644)
    _write(box.tree / "nvd.db-journal", "hot", 0o644)
    box.state.mkdir(parents=True)

    result = box.run("prepare-state")
    assert result.returncode == 0, result.stderr
    assert not (box.state / "reports" / "planted.docx").exists()
    assert not (box.state / "nvd.db").exists()


def test_prepare_state_creates_a_missing_state_directory(box: Box):
    _write(box.tree / "nvd.db", "cache", 0o644)
    result = box.run("prepare-state")
    assert result.returncode == 0, result.stderr
    assert _mode(box.state) == 0o750
    assert (box.state / "nvd.db").read_text() == "cache"


def test_prepare_state_refuses_a_symlinked_state_directory(box: Box):
    real = box.base / "elsewhere"
    real.mkdir()
    box.state.parent.mkdir(parents=True)
    box.state.symlink_to(real)
    result = box.run("prepare-state")
    assert result.returncode == 1
    assert "symlink" in result.stderr


# ── adopt and adopt-finish: the one-time move, driven by the workflow ────


def test_adopt_moves_the_data_out_then_locks_and_checks(box: Box):
    _write(box.tree / "nvd.db", "cache", 0o644)
    os.chmod(box.tree / "scripts" / "deploy.sh", 0o777)
    result = box.run("adopt")
    assert result.returncode == 0, result.stderr
    assert (box.state / "nvd.db").read_text() == "cache"
    assert _mode(box.tree / "scripts" / "deploy.sh") == 0o755
    assert "code-tree-guard: ok" in result.stdout


def test_adopt_finish_does_not_lock_when_the_deploy_did_not_land(box: Box):
    """A deploy that rolled back leaves the old code running; it keeps the
    tree it expects, and the step fails loudly instead."""
    _write(box.tree / "DEPLOYED_SHA", f"DEPLOYED_SHA={SHA_B}\nDEPLOYED_AT=x\n", 0o600)
    os.chmod(box.tree / "scripts" / "deploy.sh", 0o777)
    result = box.run("adopt-finish", SHA_A)
    assert result.returncode == 1
    assert "did not land" in result.stderr
    assert _mode(box.tree / "scripts" / "deploy.sh") == 0o777


def test_adopt_finish_locks_once_the_new_commit_is_confirmed_running(box: Box):
    _write(box.tree / "DEPLOYED_SHA", f"DEPLOYED_SHA={SHA_A}\nDEPLOYED_AT=x\n", 0o600)
    os.chmod(box.tree / "scripts" / "deploy.sh", 0o777)
    result = box.run("adopt-finish", SHA_A)
    assert result.returncode == 0, result.stderr
    assert _mode(box.tree / "scripts" / "deploy.sh") == 0o755
    assert _mode(box.tree / "DEPLOYED_SHA") == 0o644


@pytest.mark.parametrize(
    "args",
    [(), ("nope",), ("check", "extra"), ("adopt-finish",), ("adopt-finish", "not-a-sha"), ("adopt-finish", "a" * 39)],
)
def test_usage_errors_exit_2(box: Box, args):
    assert box.run(*args).returncode == 2


# ── what root's git would run ──────────────────────────────────────────────


def _init_checkout_git(box: Box, config: str) -> Path:
    git_dir = box.tree / ".git"
    _write(git_dir / "config", config, 0o644)
    _write(git_dir / "hooks" / "pre-commit.sample", "#!/bin/sh\n", 0o755)
    os.chmod(git_dir, 0o755)
    os.chmod(git_dir / "hooks", 0o755)
    return git_dir


STANDARD_CHECKOUT_CONFIG = (
    "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
    "\tlogallrefupdates = true\n[remote \"origin\"]\n\turl = /opt/git/dashboard.git\n"
    "\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n"
)


def test_a_standard_clone_config_and_sample_hooks_pass(box: Box):
    _init_checkout_git(box, STANDARD_CHECKOUT_CONFIG)
    result = box.run("check")
    assert result.returncode == 0, result.stderr


def test_a_planted_fsmonitor_in_the_checkout_config_fails(box: Box):
    """core.fsmonitor runs a command on index refresh, which root's
    `git reset --hard` does on every deploy. Ownership cannot catch a value
    the service user wrote before the tree was adopted."""
    _init_checkout_git(box, STANDARD_CHECKOUT_CONFIG + "[core]\n\tfsmonitor = /tmp/x\n")
    result = box.run("check")
    assert result.returncode == 1
    assert "root's git would act on this:" in result.stderr
    assert "key 'core.fsmonitor' is not on the allowlist" in result.stderr


def test_an_include_is_reported_rather_than_followed(box: Box):
    _init_checkout_git(box, STANDARD_CHECKOUT_CONFIG + "[include]\n\tpath = /var/www/evil.gitconfig\n")
    result = box.run("check")
    assert result.returncode == 1
    assert "include.path" in result.stderr


def test_a_reference_transaction_hook_in_the_checkout_fails(box: Box):
    """reset --hard moves a ref, so git runs this hook as root."""
    git_dir = _init_checkout_git(box, STANDARD_CHECKOUT_CONFIG)
    _write(git_dir / "hooks" / "reference-transaction", "#!/bin/sh\n", 0o755)
    result = box.run("check")
    assert result.returncode == 1
    assert "hooks/reference-transaction: git runs this as a hook" in result.stderr


def test_the_mirror_may_carry_its_post_receive_and_nothing_else(box: Box):
    _write(box.mirror / "hooks" / "post-receive.pre-pat909.bak", "#!/bin/bash\n", 0o755)
    assert box.run("check").returncode == 0, "post-receive and non-hook names are fine"
    _write(box.mirror / "hooks" / "pre-receive", "#!/bin/bash\n", 0o755)
    result = box.run("check")
    assert result.returncode == 1
    assert "dashboard.git/hooks/pre-receive: git runs this as a hook" in result.stderr
