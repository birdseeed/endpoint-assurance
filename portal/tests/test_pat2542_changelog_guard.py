"""The per-change guard judges only changes introduced by the PR branch."""

import os
import subprocess
import textwrap
from pathlib import Path

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/changelog-guard.yml'


def _git(repo, *args):
    return subprocess.check_output(
        ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', *args],
        cwd=repo, text=True, stderr=subprocess.STDOUT,
    ).strip()


def _commit(repo, path, text):
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    _git(repo, 'add', path)
    _git(repo, 'commit', '-m', 'guard fixture')
    return _git(repo, 'rev-parse', 'HEAD')


@pytest.mark.parametrize('target_path, feature_path, label, expected', [
    ('data/changelog.json', 'templates/example.html', 'false', 1),
    ('templates/example.html', 'README.md', 'false', 0),
    ('README.md', 'templates/example.html', 'true', 0),
    ('README.md', 'data/changelog.json', 'false', 0),
])
def test_guard_uses_only_feature_branch_changes(
    tmp_path, target_path, feature_path, label, expected,
):
    """Run the workflow's actual shell against divergent disposable branches.

    Target-only changelog work cannot satisfy a visible PR, and target-only
    visible work cannot make a documentation PR require a changelog entry.
    Commits here are local fixtures in pytest's temporary repository only.
    """
    _git(tmp_path, 'init', '-b', 'main')
    _git(tmp_path, 'config', 'user.name', 'Guard fixture')
    _git(tmp_path, 'config', 'user.email', 'guard@example.invalid')
    _commit(tmp_path, 'main.py', '# base\n')
    _git(tmp_path, 'switch', '-c', 'feature')
    head = _commit(tmp_path, feature_path, 'feature change\n')
    if feature_path == 'data/changelog.json':
        head = _commit(tmp_path, 'templates/example.html', 'visible feature change\n')
    _git(tmp_path, 'switch', 'main')
    base = _commit(tmp_path, target_path, 'target change\n')

    script = textwrap.dedent(WORKFLOW.read_text().split('        run: |\n', 1)[1])
    result = subprocess.run(
        ['bash', '-c', script], cwd=tmp_path,
        env={**os.environ, 'BASE': base, 'HEAD': head, 'NO_CHANGELOG': label},
        text=True, capture_output=True, check=False,
    )
    assert result.returncode == expected, result.stdout + result.stderr
