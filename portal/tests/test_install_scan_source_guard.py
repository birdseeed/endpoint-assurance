"""PAT-1212: the scan installer must fail closed before rsync --delete."""

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "deploy" / "install-scan.sh"


def check_source(source: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(INSTALLER), "--check-source", str(source)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_install_scan_accepts_complete_repository_source():
    result = check_source(REPO_ROOT)

    assert result.returncode == 0, result.stderr
    assert "Complete scan deployment source" in result.stdout


def test_install_scan_rejects_missing_runtime_file_before_rsync(tmp_path: Path):
    result = check_source(tmp_path)

    assert result.returncode == 1
    assert "Incomplete scan deployment source" in result.stderr
    assert "Refusing to rsync --delete" in result.stderr


def test_install_scan_rejects_empty_requirements_before_rsync(tmp_path: Path):
    source = tmp_path / "source"
    shutil.copytree(REPO_ROOT, source, ignore=shutil.ignore_patterns(".git"))
    (source / "scan" / "requirements.txt").write_text("")

    result = check_source(source)

    assert result.returncode == 1
    assert "scan/requirements.txt is empty" in result.stderr
    assert "Refusing to rsync --delete" in result.stderr


def test_install_scan_rejects_symlinked_runtime_file_before_rsync(tmp_path: Path):
    source = tmp_path / "source"
    shutil.copytree(REPO_ROOT, source, ignore=shutil.ignore_patterns(".git"))
    app = source / "scan" / "app.py"
    app.unlink()
    app.symlink_to("router.py")

    result = check_source(source)

    assert result.returncode == 1
    assert "missing or non-regular scan/app.py" in result.stderr
    assert "Refusing to rsync --delete" in result.stderr


@pytest.mark.parametrize(
    "runtime_asset",
    (
        "scan/static/brand/patched-mark-primary.svg",
        "scan/static/favicon.svg",
        "scan/static/patched-lockup-onslate.svg",
        "scan/templates/public_scan_unavailable.html",
    ),
)
def test_install_scan_rejects_missing_footer_runtime_asset_before_rsync(
    tmp_path: Path, runtime_asset: str
):
    source = tmp_path / "source"
    shutil.copytree(REPO_ROOT, source, ignore=shutil.ignore_patterns(".git"))
    (source / runtime_asset).unlink()

    result = check_source(source)

    assert result.returncode == 1
    assert f"missing or non-regular {runtime_asset}" in result.stderr
    assert "Refusing to rsync --delete" in result.stderr


def _manifest() -> set[str]:
    """The installer's REQUIRED_SOURCE_FILES entries, read from the script."""
    text = INSTALLER.read_text()
    block = text[text.index("readonly REQUIRED_SOURCE_FILES=("):]
    block = block[: block.index("\n)\n")]
    return {line.strip().strip('"') for line in block.splitlines()[1:] if line.strip()}


def test_install_scan_manifest_names_every_runtime_file():
    """PAT-2560: the manifest is hand-kept, and a runtime file left off it is
    exactly the file a staged-source omission would delete from the live
    service without the installer noticing. public_pricing_enquiry.html had
    been missing from it since PAT-1978. Every template, module, operator
    script and static asset the scan service ships must be listed."""
    scan = REPO_ROOT / "scan"
    runtime = [
        *scan.glob("*.py"),
        *scan.glob("bin/*.py"),
        *scan.glob("templates/*.html"),
        *(p for p in scan.glob("static/**/*") if p.is_file()),
    ]
    shipped = {p.relative_to(REPO_ROOT).as_posix() for p in runtime}
    assert len(shipped) > 20, shipped
    assert sorted(shipped - _manifest()) == []
