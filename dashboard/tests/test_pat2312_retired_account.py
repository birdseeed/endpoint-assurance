"""PAT-2312: the deploy removes the retired `patched` account on patched-prod-01.

Andy decided on 2026-09-30 to remove the local account `patched` (uid 1001)
entirely. deploy/removed-artifacts.txt deletes its passwordless sudoers
grant; scripts/deploy.sh's remove_retired_account removes the account, its
home and its tmp files, but only when every guard holds.

These tests run the real function from scripts/deploy.sh against a scratch
box (tests/retired_account_box.py) whose getent, pgrep, userdel and groupdel
are shims. The wiring into sync_box_config and the full deploy is covered in
tests/test_pat2312_box_privileges.py and scripts/test-post-receive-rollback.sh.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path

import pytest

from tests.retired_account_box import (
    TMP_FILE,
    TUNNEL_JSON,
    TUNNEL_JSON_BODY,
    RetiredAccountBox,
)

REPO = Path(__file__).resolve().parent.parent
DEPLOY_SH = REPO / "scripts" / "deploy.sh"


def _function() -> str:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    start = text.index("\nremove_retired_account() (\n") + 1
    return text[start:text.index("\n)\n", start) + 3]


def _run(box: RetiredAccountBox, **env: str) -> tuple[subprocess.CompletedProcess[str], str]:
    harness = box.base / "harness.sh"
    harness.write_text(
        "#!/usr/bin/env bash\nset -u\n"
        f"LOG={shlex.quote(str(box.log))}\n"
        "log() { echo \"$*\" >> \"$LOG\"; }\n"
        + box.assignments() + _function()
        + f"\nremove_retired_account {shlex.quote(box.name)} {box.uid}\n"
    )
    full_env = dict(os.environ, PATH=f"{box.bin}:/usr/bin:/bin", **env)
    result = subprocess.run(["bash", str(harness)], text=True, capture_output=True, env=full_env, timeout=60)
    return result, box.log_text()


@pytest.fixture
def box(tmp_path: Path) -> RetiredAccountBox:
    return RetiredAccountBox(tmp_path / "box")


def _assert_untouched(box: RetiredAccountBox) -> None:
    """A refusal changes nothing: the account, its group, its home and its
    tmp file are all still there, and neither userdel nor groupdel ran."""
    assert f"{box.name}:x:" in box.passwd()
    assert f"\n{box.name}:x:" in f"\n{box.group()}"
    assert (box.home / ".cloudflared" / TUNNEL_JSON).exists()
    assert (box.tmp / TMP_FILE).exists()
    assert not [c for c in box.calls() if c.startswith(("userdel", "groupdel"))]


# ── absent ─────────────────────────────────────────────────────────────────


def test_an_absent_account_is_a_logged_no_op(box):
    (box.tmp / "not-scanned").write_text("left alone\n")
    result, log = _run(box)
    assert result.returncode == 0, log
    assert f"Retired account {box.name} already absent; nothing to remove" in log
    assert (box.tmp / "not-scanned").exists()
    assert not [c for c in box.calls() if not c.startswith("getent")]


# ── removal ────────────────────────────────────────────────────────────────


def test_a_present_account_is_removed_with_its_home_and_tmp_files(box):
    box.add_account()
    (box.var_tmp / "scratch-dir").mkdir()
    (box.var_tmp / "scratch-dir" / "file").write_text("scratch\n")

    result, log = _run(box)
    assert result.returncode == 0, log
    # The passwd entry, its group and both memberships are gone; the other
    # account is not touched.
    assert box.name not in box.passwd()
    assert box.name not in box.group()
    assert "sudo:x:27:\n" in box.group()
    assert "users:x:100:someone\n" in box.group()
    assert "someone:x:1000:1000::/home/someone:/bin/bash" in box.passwd()
    # The home went with userdel -r, cert.pem included; the tmp files went
    # before it. The credential the tunnel uses is untouched.
    assert not box.home.exists()
    assert not (box.tmp / TMP_FILE).exists()
    assert not (box.var_tmp / "scratch-dir").exists()
    assert box.tmp.is_dir() and box.var_tmp.is_dir()
    assert (box.tunnel / TUNNEL_JSON).read_text() == TUNNEL_JSON_BODY
    assert [c for c in box.calls() if c.startswith(("userdel", "groupdel"))] == [f"userdel -r {box.name}"]
    # Before and after are both on the record.
    assert (
        f"Retired account {box.name} is present: {box.name}:x:{box.uid}:4242:,,,:{box.home}:/bin/bash"
        f" (member of sudo users)"
    ) in log
    assert f"Tunnel credential {box.home}/.cloudflared/{TUNNEL_JSON} matches {box.tunnel}/{TUNNEL_JSON} byte for byte" in log
    assert f"  deleting: {box.tmp}/{TMP_FILE}" in log
    assert f"Retired account {box.name} removed: no passwd entry, no group, in no group's member list" in log


def test_a_second_run_is_a_no_op(box):
    box.add_account()
    first, log = _run(box)
    assert first.returncode == 0, log
    box.log.unlink()

    second, log = _run(box)
    assert second.returncode == 0, log
    assert f"Retired account {box.name} already absent; nothing to remove" in log
    assert [c for c in box.calls() if c.startswith("userdel")] == [f"userdel -r {box.name}"]


def test_tmp_symlinks_are_deleted_not_followed(box):
    """A link the account left in /tmp goes; what it points at does not."""
    box.add_account()
    target = box.base / "outside" / "target"
    target.parent.mkdir()
    target.write_text("not the account's to lose\n")
    (box.tmp / "link").symlink_to(target)

    result, log = _run(box)
    assert result.returncode == 0, log
    assert not (box.tmp / "link").is_symlink()
    assert target.read_text() == "not the account's to lose\n"


def test_a_group_userdel_leaves_is_removed(box):
    box.add_account()
    result, log = _run(box, USERDEL_KEEPS_GROUP="1")
    assert result.returncode == 0, log
    assert f"groupdel {box.name}" in box.calls()
    assert box.name not in box.group()
    assert f"Removed group {box.name}, which userdel left behind" in log


def test_a_leftover_group_with_another_gid_is_not_removed(box):
    box.add_account(group_gid=5555)
    result, log = _run(box, USERDEL_KEEPS_GROUP="1")
    assert result.returncode != 0
    assert f"ERROR: group {box.name} has gid 5555, not {box.name}'s primary gid 4242" in log
    assert not [c for c in box.calls() if c.startswith("groupdel")]
    assert f"still there: group {box.name}:x:5555:" in log


def test_a_failed_userdel_fails_loudly(box):
    box.add_account()
    result, log = _run(box, USERDEL_RC="8")
    assert result.returncode != 0
    assert f"ERROR: userdel -r {box.name} exited 8" in log
    assert f"still there: passwd entry {box.name}:x:" in log
    assert not [c for c in box.calls() if c.startswith("groupdel")]


def test_a_removal_that_did_not_finish_fails_every_later_run(box):
    """userdel exits 12 when it removed the entry but not the home. That
    must not turn into a quiet "already absent" on the next deploy."""
    box.add_account()
    result, log = _run(box, USERDEL_LEAVES_HOME="1")
    assert result.returncode != 0
    assert f"still there: home {box.home}" in log

    box.log.unlink()
    again, log = _run(box)
    assert again.returncode != 0
    assert f"ERROR: the retired account {box.name} is gone but its home {box.home} survived" in log


def test_a_surviving_membership_fails_the_absent_path(box):
    box.write_db(passwd=["someone:x:1000:1000::/home/someone:/bin/bash"], group=[f"sudo:x:27:{box.name}"])
    result, log = _run(box)
    assert result.returncode != 0
    assert f"ERROR: the retired account {box.name} is gone but its membership of sudo survived" in log


@pytest.mark.skipif(os.geteuid() == 0, reason="root can delete from a read-only directory")
def test_a_tmp_file_that_cannot_be_deleted_stops_it_before_userdel(box):
    box.add_account()
    locked = box.tmp / "locked"
    locked.mkdir()
    (locked / "file").write_text("scratch\n")
    locked.chmod(0o555)
    try:
        result, log = _run(box)
    finally:
        locked.chmod(0o755)
    assert result.returncode != 0
    assert f"ERROR: could not delete everything {box.name} owns under {box.tmp}" in log
    assert f"  still owned by {box.name}: {locked}/file" in log
    assert f"{box.name}:x:" in box.passwd()
    assert not [c for c in box.calls() if c.startswith("userdel")]


# ── guards: each refuses, names the reason and changes nothing ─────────────


def test_a_process_running_as_the_account_is_refused(box):
    box.add_account()
    box.run_process("-u", 4242)
    result, log = _run(box)
    assert result.returncode != 0
    assert f"ERROR: refusing to remove {box.name}: process 4242 runs as uid {box.uid} (pgrep -u)" in log
    assert f"Retired account {box.name} left in place" in log
    _assert_untouched(box)


def test_a_process_with_the_accounts_real_uid_is_refused(box):
    box.add_account()
    box.run_process("-U", 4343)
    result, log = _run(box)
    assert result.returncode != 0
    assert f"process 4343 runs as uid {box.uid} (pgrep -U)" in log
    _assert_untouched(box)


def test_a_pgrep_that_fails_is_a_refusal_not_a_pass(box):
    box.add_account()
    result, log = _run(box, PGREP_RC="3")
    assert result.returncode != 0
    assert f"ERROR: pgrep -u {box.uid} exited 3; cannot prove that no process runs as {box.name}" in log
    _assert_untouched(box)


def test_a_file_owned_outside_the_home_and_tmp_is_refused(box):
    box.add_account()
    stray = box.root / "usr-local-bin-tool"
    stray.write_text("owned by the account\n")
    result, log = _run(box)
    assert result.returncode != 0
    assert f"ERROR: refusing to remove {box.name}: it owns files outside {box.home}" in log
    assert f"  owned by {box.name}: {stray}" in log
    assert stray.exists()
    _assert_untouched(box)


def test_a_tunnel_credential_with_no_copy_in_etc_is_refused(box):
    box.add_account()
    (box.tunnel / TUNNEL_JSON).unlink()
    result, log = _run(box)
    assert result.returncode != 0
    assert (
        f"ERROR: refusing to remove {box.name}: {box.home}/.cloudflared/{TUNNEL_JSON} has no regular-file copy"
        f" at {box.tunnel}/{TUNNEL_JSON}"
    ) in log
    _assert_untouched(box)


def test_a_tunnel_credential_that_differs_from_etc_is_refused(box):
    box.add_account()
    (box.tunnel / TUNNEL_JSON).write_text('{"TunnelID":"another-placeholder"}\n')
    result, log = _run(box)
    assert result.returncode != 0
    assert f"{box.home}/.cloudflared/{TUNNEL_JSON} differs from {box.tunnel}/{TUNNEL_JSON}" in log
    _assert_untouched(box)


def test_an_etc_copy_that_is_a_link_back_into_the_home_is_refused(box):
    """The case that loses the credential: /etc/cloudflared's "copy" is a
    link to the home's file, so the two compare identical and deleting the
    home deletes the only real one."""
    box.add_account()
    (box.tunnel / TUNNEL_JSON).unlink()
    (box.tunnel / TUNNEL_JSON).symlink_to(box.home / ".cloudflared" / TUNNEL_JSON)
    result, log = _run(box)
    assert result.returncode != 0
    assert f"has no regular-file copy at {box.tunnel}/{TUNNEL_JSON}" in log
    _assert_untouched(box)


def test_a_tunnel_credential_in_the_home_that_is_a_link_is_refused(box):
    box.add_account()
    link = box.home / ".cloudflared" / "linked.json"
    link.symlink_to(box.tunnel / TUNNEL_JSON)
    result, log = _run(box)
    assert result.returncode != 0
    assert f"ERROR: refusing to remove {box.name}: {link} is not a regular file" in log
    _assert_untouched(box)


def test_a_hidden_or_nested_tunnel_credential_is_checked_too(box):
    box.add_account()
    nested = box.home / ".cloudflared" / "old" / ".spare.json"
    nested.parent.mkdir()
    nested.write_text('{"TunnelID":"spare-placeholder"}\n')
    result, log = _run(box)
    assert result.returncode != 0
    assert f"{nested} has no regular-file copy at {box.tunnel}/.spare.json" in log
    _assert_untouched(box)


def test_a_symlinked_cloudflared_directory_is_refused(box):
    box.add_account()
    real = box.base / "cloudflared-elsewhere"
    (box.home / ".cloudflared").rename(real)
    (box.home / ".cloudflared").symlink_to(real)
    result, log = _run(box)
    assert result.returncode != 0
    assert f"ERROR: refusing to remove {box.name}: {box.home}/.cloudflared is a symlink" in log
    assert (real / TUNNEL_JSON).exists()


def test_an_account_with_another_uid_is_refused(box):
    """Whoever is next created as the account name is not the account PAT-2312
    retired, and is left alone."""
    box.add_account(uid=box.uid + 1)
    result, log = _run(box)
    assert result.returncode != 0
    assert (
        f"ERROR: refusing to remove {box.name}: its uid is {box.uid + 1}, not {box.uid}, so it is not the"
        " account PAT-2312 retired"
    ) in log
    _assert_untouched(box)
    assert not [c for c in box.calls() if c.startswith("pgrep")]


def test_an_account_whose_home_is_elsewhere_is_refused(box):
    """userdel -r deletes whatever the passwd entry names as the home."""
    elsewhere = box.base / "somewhere-else"
    elsewhere.mkdir()
    box.add_account(home=elsewhere)
    result, log = _run(box)
    assert result.returncode != 0
    assert f"ERROR: refusing to remove {box.name}: its home is {elsewhere}, not {box.home}" in log
    assert elsewhere.exists()
    _assert_untouched(box)


def test_a_symlinked_home_is_refused(box):
    box.add_account()
    real = box.base / "home-elsewhere"
    box.home.rename(real)
    box.home.symlink_to(real)
    result, log = _run(box)
    assert result.returncode != 0
    assert f"ERROR: refusing to remove {box.name}: {box.home} is not a directory (or is a symlink)" in log
    assert (real / ".cloudflared" / TUNNEL_JSON).exists()
    assert not [c for c in box.calls() if c.startswith("userdel")]


def test_a_getent_that_fails_is_a_refusal_not_absence(box):
    box.add_account()
    result, log = _run(box, GETENT_RC="1")
    assert result.returncode != 0
    assert f"ERROR: getent passwd {box.name} exited 1; cannot tell whether the retired account" in log
    _assert_untouched(box)


def test_every_failing_guard_is_reported_in_one_run(box):
    box.add_account()
    box.run_process("-u", 4242)
    (box.tunnel / TUNNEL_JSON).unlink()
    result, log = _run(box)
    assert result.returncode != 0
    assert "(pgrep -u)" in log
    assert "has no regular-file copy" in log
    _assert_untouched(box)


def test_a_missing_setting_refuses_to_run(box):
    box.add_account()
    harness = box.base / "harness.sh"
    harness.write_text(
        "#!/usr/bin/env bash\n"
        f"LOG={shlex.quote(str(box.log))}\n"
        "log() { echo \"$*\" >> \"$LOG\"; }\n"
        + box.assignments() + "RETIRED_ACCOUNT_HOME=\n" + _function()
        + f"\nremove_retired_account {shlex.quote(box.name)} {box.uid}\n"
    )
    env = dict(os.environ, PATH=f"{box.bin}:/usr/bin:/bin")
    result = subprocess.run(["bash", str(harness)], text=True, capture_output=True, env=env, timeout=60)
    assert result.returncode != 0
    assert "ERROR: the retired-account step is missing its account name" in box.log_text()
    _assert_untouched(box)


# ── the production values and the override rules ──────────────────────────


def _settings_block() -> str:
    """Everything from the box values to the umask that follows them, so a
    line moved out of the dry-run branch is still run here."""
    text = DEPLOY_SH.read_text(encoding="utf-8")
    start = text.index("\nRETIRED_ACCOUNT=patched\n") + 1
    return text[start:text.index("\numask 022\n", start)]


def _settings(env: dict[str, str]) -> dict[str, str]:
    script = _settings_block() + "\n" + "".join(
        f'printf "%s=%s\\n" {name} "${name}"\n'
        for name in (
            "RETIRED_ACCOUNT", "RETIRED_ACCOUNT_UID", "RETIRED_ACCOUNT_HOME", "RETIRED_ACCOUNT_TMP_DIRS",
            "RETIRED_ACCOUNT_SCAN_ROOT", "RETIRED_ACCOUNT_TUNNEL_DIR", "RETIRED_ACCOUNT_PATH",
        )
    )
    base = {k: v for k, v in os.environ.items() if not k.startswith("DEPLOY_")}
    result = subprocess.run(
        ["bash", "-c", script], text=True, capture_output=True, env={**base, **env}, timeout=10, check=True,
    )
    return dict(line.split("=", 1) for line in result.stdout.splitlines())


OVERRIDES = {
    "DEPLOY_RETIRED_ACCOUNT": "scratch", "DEPLOY_RETIRED_ACCOUNT_UID": "4321",
    "DEPLOY_RETIRED_ACCOUNT_HOME": "/scratch/home", "DEPLOY_RETIRED_ACCOUNT_TMP_DIRS": "/scratch/tmp",
    "DEPLOY_RETIRED_ACCOUNT_SCAN_ROOT": "/scratch", "DEPLOY_RETIRED_ACCOUNT_TUNNEL_DIR": "/scratch/cf",
}
BOX_VALUES = {
    "RETIRED_ACCOUNT": "patched", "RETIRED_ACCOUNT_UID": "1001", "RETIRED_ACCOUNT_HOME": "/home/patched",
    "RETIRED_ACCOUNT_TMP_DIRS": "/tmp /var/tmp", "RETIRED_ACCOUNT_SCAN_ROOT": "/",
    "RETIRED_ACCOUNT_TUNNEL_DIR": "/etc/cloudflared", "RETIRED_ACCOUNT_PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
}


def test_a_real_deploy_uses_the_box_values_and_a_fixed_path():
    """Without DEPLOY_ALLOW_NONROOT the overrides and the caller's PATH are
    never read, whatever is set."""
    assert _settings({"PATH": "/scratch/bin:/usr/bin:/bin", **OVERRIDES}) == BOX_VALUES
    assert _settings({"PATH": "/usr/bin:/bin"}) == BOX_VALUES
    # Set in exactly two places: the box value, and the dry-run branch.
    text = DEPLOY_SH.read_text(encoding="utf-8")
    assert text.count("RETIRED_ACCOUNT_PATH=") == 2
    assert "\nRETIRED_ACCOUNT_PATH=/usr/sbin:/usr/bin:/sbin:/bin\n" in text
    assert '\n    RETIRED_ACCOUNT_PATH="$PATH"\nfi\n' in text


def test_the_dry_run_takes_the_overrides_and_its_own_path():
    got = _settings({"PATH": "/scratch/bin:/usr/bin:/bin", "DEPLOY_ALLOW_NONROOT": "1", **OVERRIDES})
    assert got == {
        "RETIRED_ACCOUNT": "scratch", "RETIRED_ACCOUNT_UID": "4321", "RETIRED_ACCOUNT_HOME": "/scratch/home",
        "RETIRED_ACCOUNT_TMP_DIRS": "/scratch/tmp", "RETIRED_ACCOUNT_SCAN_ROOT": "/scratch",
        "RETIRED_ACCOUNT_TUNNEL_DIR": "/scratch/cf", "RETIRED_ACCOUNT_PATH": "/scratch/bin:/usr/bin:/bin",
    }


@pytest.mark.parametrize("name", sorted(OVERRIDES))
def test_a_real_deploy_that_sets_an_override_is_refused_before_anything_runs(tmp_path, name):
    """Even set to an empty string: setting one at all is a mistake."""
    log = tmp_path / "deploy.log"
    env = {k: v for k, v in os.environ.items() if not k.startswith("DEPLOY_")}
    env.update({name: "", "DEPLOY_REPO_DIR": str(tmp_path / "no-checkout"), "DEPLOY_LOG": str(log)})
    result = subprocess.run(["bash", str(DEPLOY_SH)], text=True, capture_output=True, env=env, timeout=30)
    assert result.returncode == 1
    assert f"ERROR: {name} set without DEPLOY_ALLOW_NONROOT" in result.stderr
    assert "Nothing was deployed." in result.stderr
    assert not log.exists()


def test_the_account_is_removed_after_the_manifest_in_sync_box_config():
    """The manifest deletes the account's sudoers grant first, so there is
    never a moment with the grant but no account to hold it."""
    text = DEPLOY_SH.read_text(encoding="utf-8")
    sync = text[text.index("\nsync_box_config() (\n"):text.index("\nremove_retired_account() (\n")]
    call = '    remove_retired_account "$RETIRED_ACCOUNT" "$RETIRED_ACCOUNT_UID" || rc=1\n'
    assert sync.count(call) == 1
    assert sync.index('done < "$REMOVED_ARTIFACTS_MANIFEST"') < sync.index(call) < sync.index('    return "$rc"\n)')
