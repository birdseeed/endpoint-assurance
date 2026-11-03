"""PAT-2312: stale privileges and root-only files on patched-prod-01.

- deploy/removed-artifacts.txt removes three sudoers grants and a crontab
  for accounts that no longer exist (jarvis, openclaw), and the shim one of
  the grants ran. Whoever was next created with either name would have
  inherited them.
- sync_box_config makes /usr/local/bin/hcloud root:root 0755 (root runs it
  from the firewall-apply units; it was owned by a login account) and the
  Cloudflare Origin private key root:root 0600 (it was readable by every
  local user, www-data included).
- The manifest also removes /etc/sudoers.d/patched, the passwordless grant
  for the `patched` login account, which Andy retired on 2026-09-30, and
  sync_box_config then removes the account itself. The removal and its
  guards are tested in tests/test_pat2312_retired_account.py; here, only its
  place in the sync.

All of it is driven through the real sync_box_config against scratch paths.
"""

from __future__ import annotations

import grp
import os
import pwd
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.retired_account_box import TMP_FILE, RetiredAccountBox, absent_account_assignments

REPO = Path(__file__).resolve().parent.parent
DEPLOY_SH = REPO / "scripts" / "deploy.sh"
MANIFEST = REPO / "deploy" / "removed-artifacts.txt"
ROLLBACK_TEST = REPO / "scripts" / "test-post-receive-rollback.sh"
MANAGED_UNITS = (
    "patched-dashboard.service", "patched-dashboard-prune-reports.service",
    "patched-maintenance-facts.service", "patched-maintenance-facts.timer",
)
STALE_SUDOERS = (
    "/etc/sudoers.d/90-jarvis", "/etc/sudoers.d/jarvis-claude", "/etc/sudoers.d/patched-deploy",
)
JARVIS_SHIM = "/usr/local/bin/jarvis-claude"
STALE_CRONTAB = "/var/spool/cron/crontabs/openclaw"
STALE_LINGER = "/var/lib/systemd/linger/openclaw"
# The retired `patched` account's passwordless grant (Andy, 2026-09-30).
RETIRED_ACCOUNT_SUDOERS = "/etc/sudoers.d/patched"
# The provider's grant. It must never be in the manifest.
CLOUD_INIT_SUDOERS = "/etc/sudoers.d/90-cloud-init-users"
# What patched-prod-01 holds beside the stale entries (read-only,
# 2026-09-30). None of these may be touched.
LIVE_SUDOERS = (CLOUD_INIT_SUDOERS, "/etc/sudoers.d/README")
LIVE_CRONTABS = ("/var/spool/cron/crontabs/root",)
# Every sudoers file and crontab the manifest may remove. Allowlists, so a
# new entry under either has to be added here on purpose, with its review.
REMOVABLE_SUDOERS = {"/etc/sudoers.d/patched-ops-fw", *STALE_SUDOERS, RETIRED_ACCOUNT_SUDOERS}
REMOVABLE_CRONTABS = {STALE_CRONTAB}
STALE = (*STALE_SUDOERS, RETIRED_ACCOUNT_SUDOERS, JARVIS_SHIM, STALE_CRONTAB, STALE_LINGER)
LIVE = (*LIVE_SUDOERS, *LIVE_CRONTABS)

# The files sync_box_config holds to CONFIG_OWNER:CONFIG_GROUP and a mode:
# (log label, scratch path under tmp_path, mode, a drifted mode to fix).
TARGETS = {
    "hcloud": ("hcloud", ("usr", "local", "bin", "hcloud"), 0o755, 0o775),
    "origin_key": ("origin TLS key", ("etc", "ssl", "dashboard.patched.im.key"), 0o600, 0o644),
}


def _manifest_paths() -> list[str]:
    return [
        line.strip() for line in MANIFEST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _sync_box_config_function() -> str:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    start = text.index("\nsync_box_config() (\n") + 1
    return text[start:text.index("\n# rollback REASON", start)]


def _target_path(tmp_path: Path, name: str) -> Path:
    return tmp_path.joinpath(*TARGETS[name][1])


def _run_sync(
    tmp_path: Path, *, manifest: str = "", chown_rc: int | None = None,
    retired: RetiredAccountBox | None = None,
) -> tuple[subprocess.CompletedProcess[str], str, list[str]]:
    """Drive the real sync_box_config against scratch directories.

    The hcloud and origin key it checks are the TARGETS paths under
    tmp_path, which the caller sets up (or not) first. chown is a shim that
    records its arguments and runs the real chown, or exits chown_rc
    without running it. The retired-account step sees the scratch box
    `retired`, or a scratch account that does not exist.
    """
    repo = tmp_path / "repo"
    deploy_dir = repo / "deploy"
    systemd_dir = tmp_path / "systemd"
    fakebin = tmp_path / "bin"
    for directory in (deploy_dir, systemd_dir, tmp_path / "polkit", fakebin):
        directory.mkdir(parents=True, exist_ok=True)
    for unit in MANAGED_UNITS:
        (deploy_dir / unit).write_text(f"{unit}\n")
        (systemd_dir / unit).write_text(f"{unit}\n")
    (deploy_dir / "removed-artifacts.txt").write_text(manifest)
    (fakebin / "systemctl").write_text(
        "#!/usr/bin/env bash\n[ \"$1\" = show ] && echo loaded\nexit 0\n"
    )
    real_chown = shutil.which("chown", path="/usr/sbin:/usr/bin:/bin:/sbin")
    assert real_chown, "no chown on this machine"
    chown_events = tmp_path / "chown-calls"
    (fakebin / "chown").write_text(
        "#!/usr/bin/env bash\n"
        f"echo \"$*\" >> {shlex.quote(str(chown_events))}\n"
        + (f"exit {chown_rc}\n" if chown_rc is not None else f"exec {shlex.quote(real_chown)} \"$@\"\n")
    )
    guard = deploy_dir / "verify-systemd-hardening-floor.sh"
    guard.write_text("#!/usr/bin/env bash\nexit 0\n")
    for executable in (fakebin / "systemctl", fakebin / "chown", guard):
        executable.chmod(0o755)
    log = tmp_path / "deploy.log"
    harness = tmp_path / "harness.sh"
    harness.write_text(
        "#!/usr/bin/env bash\nset -eu\n"
        f"REPO_DIR={shlex.quote(str(repo))}\nSYSTEMD_DIR={shlex.quote(str(systemd_dir))}\n"
        f"POLKIT_RULES_DIR={shlex.quote(str(tmp_path / 'polkit'))}\nLOG={shlex.quote(str(log))}\n"
        "CONFIG_OWNER=$(id -un)\nCONFIG_GROUP=$(id -gn)\n"
        f"REMOVED_ARTIFACTS_MANIFEST={shlex.quote(str(deploy_dir / 'removed-artifacts.txt'))}\n"
        f"HCLOUD_BIN={shlex.quote(str(_target_path(tmp_path, 'hcloud')))}\n"
        f"ORIGIN_KEY={shlex.quote(str(_target_path(tmp_path, 'origin_key')))}\n"
        + (retired.assignments() if retired else absent_account_assignments(tmp_path, fakebin))
        + "log() { echo \"$*\" >> \"$LOG\"; }\n" + _sync_box_config_function() + "\nsync_box_config\n"
    )
    path = f"{fakebin}:/usr/bin:/bin" if retired is None else f"{retired.bin}:{fakebin}:/usr/bin:/bin"
    env = dict(os.environ, PATH=path, TMPDIR=str(tmp_path))
    result = subprocess.run(["bash", str(harness)], text=True, capture_output=True, env=env, timeout=30)
    calls = chown_events.read_text().splitlines() if chown_events.exists() else []
    return result, log.read_text() if log.exists() else "", calls


# ── the stale grants, shim and crontab ─────────────────────────────────────


def test_the_stale_sudoers_grants_and_the_shim_are_in_the_manifest():
    paths = _manifest_paths()
    for path in (*STALE_SUDOERS, JARVIS_SHIM):
        assert path in paths, path


def test_the_orphan_openclaw_crontab_is_in_the_manifest():
    assert STALE_CRONTAB in _manifest_paths()
    assert STALE_LINGER in _manifest_paths()


def test_the_retired_accounts_grant_is_in_the_manifest():
    """Andy's decision of 2026-09-30: the `patched` account goes, and its
    passwordless grant goes first, so no later account created as `patched`
    can inherit it."""
    assert RETIRED_ACCOUNT_SUDOERS in _manifest_paths()


def test_the_cloud_init_grant_is_never_in_the_manifest():
    assert CLOUD_INIT_SUDOERS not in _manifest_paths()
    assert CLOUD_INIT_SUDOERS not in REMOVABLE_SUDOERS


def test_the_manifest_removes_only_allowlisted_sudoers_files_and_crontabs():
    """A live grant or crontab in the manifest would be deleted as root on
    every deploy. 90-cloud-init-users is the provider's, and root's crontab
    is root's."""
    for path in _manifest_paths():
        assert path not in ("/etc/sudoers", "/etc/sudoers.d", "/etc/crontab"), path
        if path.startswith("/etc/sudoers"):
            assert path in REMOVABLE_SUDOERS, f"{path} is not on the reviewed sudoers allowlist"
        if path.startswith(("/var/spool/cron", "/etc/cron")):
            assert path in REMOVABLE_CRONTABS, f"{path} is not on the reviewed crontab allowlist"
    for path in LIVE:
        assert path not in _manifest_paths(), path


def _deploy_machinery() -> list[Path]:
    files = [DEPLOY_SH, REPO / "deploy" / "post-receive"]
    files += sorted((REPO / "deploy").glob("*.sh"))
    files += sorted((REPO / ".github" / "workflows").glob("*.yml"))
    return files


def test_nothing_in_the_deploy_machinery_writes_sudoers_content():
    """sudo refuses to run at all if any file in /etc/sudoers.d fails to
    parse. The manifest deletes whole files, which cannot cause that; an
    edit could. Comments are allowed to mention sudoers."""
    for path in _deploy_machinery():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            assert "sudoers" not in line and "visudo" not in line, f"{path.name}:{number}: {line.strip()}"


def _fake_root_manifest(root: Path) -> str:
    """The real manifest with every entry moved under root."""
    return "".join(
        line + "\n" if not line.strip() or line.lstrip().startswith("#") else f"{root}{line.strip()}\n"
        for line in MANIFEST.read_text(encoding="utf-8").splitlines()
    )


def _fake_mode(path: str) -> int:
    if path.startswith("/etc/sudoers.d/"):
        return 0o440
    if path.startswith("/var/spool/cron/"):
        return 0o600
    return 0o755


def test_the_manifest_removes_the_stale_entries_in_a_fake_root_and_nothing_else(tmp_path):
    root = tmp_path / "root"
    # The stale files are laid down whether or not the manifest lists them,
    # so dropping an entry fails here on the file that survives.
    removed = sorted({*_manifest_paths(), *STALE})
    for path in (*removed, *LIVE):
        target = root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"content of {path}\n")
        target.chmod(_fake_mode(path))
    manifest = _fake_root_manifest(root)

    result, log, _ = _run_sync(tmp_path, manifest=manifest)
    assert result.returncode == 0, log
    for path in removed:
        assert not (root / path.lstrip("/")).exists(), path
    for path in STALE:
        assert f"Removed stale artefact: {root}{path}" in log
    # The live grants and root's crontab are byte for byte and mode for mode
    # what they were, and nothing new (a backup, a temp file) appeared beside
    # them: sudo would parse any file without a dot in its name, and cron
    # would load any file in its spool.
    for path in LIVE:
        target = root / path.lstrip("/")
        assert target.read_text() == f"content of {path}\n", path
        assert target.stat().st_mode & 0o7777 == _fake_mode(path), path
    for directory, live in (("etc/sudoers.d", LIVE_SUDOERS), ("var/spool/cron/crontabs", LIVE_CRONTABS)):
        assert sorted(p.name for p in (root / directory).iterdir()) == sorted(Path(p).name for p in live)

    # Every deploy runs it again: already absent is a clean no-op.
    result, log, _ = _run_sync(tmp_path, manifest=manifest)
    assert result.returncode == 0, log
    for path in STALE:
        assert f"Stale artefact already absent, skipping: {root}{path}" in log


# ── hcloud and the origin TLS key ──────────────────────────────────────────


def _make_file(path: Path, mode: int) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("fixture\n")
    os.chown(path, -1, os.getgid())
    path.chmod(mode)
    return path


def _user() -> str:
    return pwd.getpwuid(os.getuid()).pw_name


def _group_name(gid: int | None = None) -> str:
    return grp.getgrgid(os.getgid() if gid is None else gid).gr_name


def _want(mode: int) -> str:
    return f"{_user()}:{_group_name()} {mode:o}"


def _move_to_a_secondary_group(path: Path) -> int | None:
    """Give path a group other than the invoking user's primary one, the
    nearest a test without root gets to a file someone else owns."""
    for gid in os.getgroups():
        if gid == os.getgid():
            continue
        try:
            os.chown(path, -1, gid)
        except PermissionError:
            continue
        return gid
    return None


each_target = pytest.mark.parametrize("name", sorted(TARGETS))


@each_target
def test_a_file_in_the_wrong_group_is_chowned_back(tmp_path, name):
    label, _, mode, _ = TARGETS[name]
    path = _make_file(_target_path(tmp_path, name), mode)
    other = _move_to_a_secondary_group(path)
    if other is None:
        pytest.skip("the invoking user has no secondary group to move the file into")

    result, log, calls = _run_sync(tmp_path)
    assert result.returncode == 0, log
    assert path.stat().st_gid == os.getgid()
    assert calls == [f"-h {_user()}:{_group_name()} {path}"]
    assert (
        f"Enforced {label} ownership: {path} was {_user()}:{_group_name(other)} {mode:o}, now {_want(mode)}"
        in log
    )


@each_target
def test_a_file_with_the_wrong_mode_is_chowned_and_chmodded(tmp_path, name):
    """For the origin key, 0644 is what patched-prod-01 had: readable by
    every local user."""
    label, _, mode, drifted = TARGETS[name]
    path = _make_file(_target_path(tmp_path, name), drifted)

    result, log, calls = _run_sync(tmp_path)
    assert result.returncode == 0, log
    assert path.stat().st_mode & 0o7777 == mode
    assert calls == [f"-h {_user()}:{_group_name()} {path}"]
    assert f"Enforced {label} ownership: {path} was {_want(drifted)}, now {_want(mode)}" in log


@each_target
def test_a_correct_file_is_left_alone(tmp_path, name):
    label, _, mode, _ = TARGETS[name]
    path = _make_file(_target_path(tmp_path, name), mode)

    result, log, calls = _run_sync(tmp_path)
    assert result.returncode == 0, log
    assert calls == []
    assert f"{label} ownership unchanged ({path} is {_want(mode)})" in log


@each_target
def test_a_symlink_is_refused_and_its_target_left_alone(tmp_path, name):
    """chown -h would fix the link and not the file that is used, and chmod
    follows links, so neither may be pointed at one."""
    target = _make_file(tmp_path / "elsewhere" / name, 0o640)
    other = _move_to_a_secondary_group(target)
    path = _target_path(tmp_path, name)
    path.parent.mkdir(parents=True)
    path.symlink_to(target)

    result, log, calls = _run_sync(tmp_path)
    assert result.returncode != 0
    assert f"ERROR: {path} is a symlink; refusing to change ownership through it" in log
    assert calls == []
    assert path.is_symlink()
    assert target.stat().st_mode & 0o7777 == 0o640
    assert target.stat().st_gid == (other if other is not None else os.getgid())


@each_target
def test_a_missing_file_is_not_an_error(tmp_path, name):
    label = TARGETS[name][0]
    result, log, calls = _run_sync(tmp_path)
    assert result.returncode == 0, log
    assert calls == []
    assert f"{label} not installed at {_target_path(tmp_path, name)}; no ownership to enforce" in log


@each_target
def test_a_directory_at_the_path_is_refused(tmp_path, name):
    path = _target_path(tmp_path, name)
    path.mkdir(parents=True)
    result, log, calls = _run_sync(tmp_path)
    assert result.returncode != 0
    assert f"ERROR: {path} is not a regular file; refusing to change it" in log
    assert calls == []


@each_target
def test_a_failed_chown_fails_the_sync(tmp_path, name):
    _, _, mode, drifted = TARGETS[name]
    path = _make_file(_target_path(tmp_path, name), drifted)
    result, log, _ = _run_sync(tmp_path, chown_rc=1)
    assert result.returncode != 0
    assert f"ERROR: failed to set {path} to {_want(mode)}" in log
    assert f"ERROR: {path} is {_want(drifted)} after box-config sync, not {_want(mode)}" in log
    assert path.stat().st_mode & 0o7777 == drifted, "chmod must not run after a failed chown"


def test_each_file_is_enforced_independently(tmp_path):
    """A refused hcloud must not stop the key being fixed, or the reverse."""
    hcloud = _target_path(tmp_path, "hcloud")
    hcloud.parent.mkdir(parents=True)
    hcloud.symlink_to(_make_file(tmp_path / "elsewhere" / "hcloud", 0o755))
    key = _make_file(_target_path(tmp_path, "origin_key"), 0o644)

    result, log, _ = _run_sync(tmp_path)
    assert result.returncode != 0
    assert key.stat().st_mode & 0o7777 == 0o600
    assert f"Enforced origin TLS key ownership: {key} was {_want(0o644)}, now {_want(0o600)}" in log


def test_the_defaults_are_the_files_on_the_box():
    text = DEPLOY_SH.read_text(encoding="utf-8")
    assert 'HCLOUD_BIN="${DEPLOY_HCLOUD_BIN:-/usr/local/bin/hcloud}"' in text
    assert 'ORIGIN_KEY="${DEPLOY_ORIGIN_KEY:-/etc/ssl/dashboard.patched.im.key}"' in text
    assert 'enforce_root_file hcloud "$HCLOUD_BIN" 0755 || rc=1' in text
    assert 'enforce_root_file "origin TLS key" "$ORIGIN_KEY" 0600 || rc=1' in text


def test_the_nginx_config_names_the_key_the_deploy_locks_down():
    """If the site config ever points somewhere else, the step above would
    be locking down a file nobody uses."""
    conf = (REPO / "deploy" / "nginx-dashboard.conf").read_text(encoding="utf-8")
    assert "ssl_certificate_key /etc/ssl/dashboard.patched.im.key;" in conf


def test_the_rollback_dry_run_never_reaches_a_real_hcloud_or_key():
    """The dry run runs the whole deploy on a developer machine or a CI
    runner, either of which may have its own /usr/local/bin/hcloud or
    /etc/ssl."""
    text = ROLLBACK_TEST.read_text(encoding="utf-8")
    assert 'export DEPLOY_HCLOUD_BIN="$WORKDIR/usr/local/bin/hcloud"' in text
    assert 'export DEPLOY_ORIGIN_KEY="$WORKDIR/etc/ssl/dashboard.patched.im.key"' in text


# ── the retired `patched` account ──────────────────────────────────────────


def test_the_sync_removes_the_retired_account(tmp_path):
    """Wired into the real sync_box_config, after the manifest."""
    box = RetiredAccountBox(tmp_path / "retired")
    box.add_account()
    result, log, _ = _run_sync(tmp_path, retired=box)
    assert result.returncode == 0, log
    assert box.name not in box.passwd()
    assert not box.home.exists()
    assert not (box.tmp / TMP_FILE).exists()
    assert f"Retired account {box.name} removed" in log


def test_a_retired_account_guard_fails_the_sync(tmp_path):
    box = RetiredAccountBox(tmp_path / "retired")
    box.add_account()
    box.run_process()
    result, log, _ = _run_sync(tmp_path, retired=box)
    assert result.returncode != 0
    assert f"ERROR: refusing to remove {box.name}: process 4242 runs as uid {box.uid}" in log
    assert f"{box.name}:x:" in box.passwd()
    assert box.home.exists()


def test_an_absent_retired_account_leaves_the_sync_green(tmp_path):
    result, log, _ = _run_sync(tmp_path)
    assert result.returncode == 0, log
    assert "Retired account pat2312-no-such-account already absent; nothing to remove" in log


def test_the_rollback_dry_run_never_reaches_a_real_account():
    """The dry run runs the whole deploy on a developer machine or a CI
    runner, which may have accounts of their own. Every setting points at
    scratch, and getent, pgrep, userdel and groupdel are shims."""
    text = ROLLBACK_TEST.read_text(encoding="utf-8")
    for setting in (
        "DEPLOY_RETIRED_ACCOUNT", "DEPLOY_RETIRED_ACCOUNT_UID", "DEPLOY_RETIRED_ACCOUNT_HOME",
        "DEPLOY_RETIRED_ACCOUNT_TMP_DIRS", "DEPLOY_RETIRED_ACCOUNT_SCAN_ROOT", "DEPLOY_RETIRED_ACCOUNT_TUNNEL_DIR",
    ):
        assert f"export {setting}=" in text, setting
    assert 'export DEPLOY_RETIRED_ACCOUNT="pat2312-dryrun"' in text
    for command in ("getent", "pgrep", "userdel", "groupdel"):
        assert f'cat > "$FAKE_BIN/{command}"' in text, command
