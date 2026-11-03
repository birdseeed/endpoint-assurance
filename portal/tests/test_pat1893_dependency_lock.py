"""PAT-1893: deploys and rollbacks must install a fully pinned, hash-locked
dependency set, not whatever is newest on PyPI at deploy time.

Checks two things:

1. Every runtime lock file (`requirements.lock`, `scan/requirements.lock`) pins
   each top-level requirement to an exact version (`==`) and carries at least
   one `--hash=sha256:...` entry. A lock file that regresses to an unpinned or
   unhashed line stops being an immutable artefact -- a rollback to an older
   commit would then re-resolve that one dependency against whatever is
   current on PyPI, silently reopening the gap this ticket closes.
2. The box installers (`deploy/install.sh`, `deploy/install-scan.sh`) install
   from the `.lock` file with `pip install --require-hashes`, not from the
   floating `requirements.txt`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
LOCK_FILES = (REPO / "requirements.lock", REPO / "scan" / "requirements.lock")

_HASH_RE = re.compile(r"--hash=sha256:[0-9a-f]{64}")


def _requirement_blocks(lock_text: str) -> list[str]:
    """Split a pip-compile lock file into per-requirement blocks.

    A block starts at a line that isn't blank, isn't a comment, and doesn't
    start with whitespace (a top-level requirement), and continues through
    any following indented/backslash-continued lines (its hashes and its
    `# via` annotation).
    """
    blocks: list[str] = []
    current: list[str] = []
    for line in lock_text.splitlines():
        if line and not line[0].isspace() and not line.startswith("#"):
            if current:
                blocks.append("\n".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    return blocks


@pytest.mark.parametrize("lock_path", LOCK_FILES, ids=lambda p: str(p.relative_to(REPO)))
def test_lock_file_pins_every_requirement_with_a_hash(lock_path: Path):
    blocks = _requirement_blocks(lock_path.read_text())
    assert blocks, f"{lock_path} produced no requirement blocks -- parser or file is broken"

    unpinned: list[str] = []
    unhashed: list[str] = []
    for block in blocks:
        first_line = block.splitlines()[0]
        name = first_line.split("==", 1)[0].strip().rstrip("\\").strip()
        if "==" not in first_line:
            unpinned.append(name)
            continue
        if not _HASH_RE.search(block):
            unhashed.append(name)

    assert not unpinned, (
        f"{lock_path.relative_to(REPO)} has unpinned requirement(s) (no ==): {unpinned}"
    )
    assert not unhashed, (
        f"{lock_path.relative_to(REPO)} has requirement(s) with no --hash entry: {unhashed}"
    )


@pytest.mark.parametrize(
    "installer,lock_name",
    [
        (REPO / "deploy" / "install.sh", "requirements.lock"),
        (REPO / "deploy" / "install-scan.sh", "requirements.lock"),
    ],
    ids=["install.sh", "install-scan.sh"],
)
def test_installer_uses_require_hashes_against_the_lock_file(installer: Path, lock_name: str):
    text = installer.read_text()
    assert f"pip\" install --quiet --require-hashes -r \"$APP_DIR/{lock_name}\"" in text, (
        f"{installer.name} must install from {lock_name} with --require-hashes so a "
        "rollback restores the exact pinned dependency set instead of re-resolving "
        "against whatever is newest on PyPI at deploy time"
    )
    # Guard against a regression back to installing the floating requirements.txt.
    assert 'pip" install --quiet -r "$APP_DIR/requirements.txt"' not in text
