"""PAT-1237: cross-repo drift check for the systemd_hardening unit-class/
ceiling policy shared by all three patched-maintenance-facts.sh emitters
(dashboard/deploy, patched.im/api-vps-artefacts, portal/deploy).

See dashboard/tests/test_pat1237_systemd_hardening_parity.py's module
docstring for the full rationale (itself modeled on
test_pat1433_stray_config_backups_parity.py) -- this is the same test,
ported to this repo. Short version:

  * A bounded, marker-delimited region (_systemd_hardening_class_for_unit,
    the unit-name -> class mapping, and _systemd_hardening_ceiling_for_class,
    the class -> ceiling table) is kept byte-identical across all three
    copies, delimited by:

        # PARITY-BLOCK-BEGIN: systemd-hardening-ceilings-policy (PAT-1237)
        ...
        # PARITY-BLOCK-END

  * NOT the whole section -- each script enumerates candidate units and
    assembles JSON in its own house style (this repo round-trips the scan
    through \\t-delimited env vars into an embedded python3 heredoc;
    dashboard/api-01 assemble via `jq` directly in bash). Forcing
    byte-identical JSON-assembly code across those architectures is the
    bigger "shared library / build-time generation" work PAT-1433 already
    deferred for the sibling stray_config_backups block, and the same
    deferral applies here.
  * There is no CI location that sees all three repos -- each repo's
    pipeline checks out only itself. This only runs meaningfully on a local
    machine where the sibling repos are checked out alongside this one (the
    permanent `~/development/Patched.im/<repo>` layout, or ticket worktrees
    pointed at via the env vars below). It is a local drift nudge, not a
    CI-enforced gate.
  * Resolution: `PAT1237_DASHBOARD_REPO` / `PAT1237_PATCHED_IM_REPO` env
    vars override the sibling repo path (point them at ticket worktrees,
    e.g. `dashboard-pat-1237`, `patched.im-pat-1237`, to verify a
    coordinated in-flight change); otherwise this looks for conventional
    sibling dirs `<this repo's parent>/dashboard` and `.../patched.im`. A
    sibling that can't be found, or hasn't merged its own PAT-1237 markers
    yet, is skipped with a warning rather than failing the whole test --
    three independent PRs must each be able to merge without waiting on the
    other two. If neither sibling can be found at all, the test is skipped
    outright.

Run with: pytest tests/test_pat1237_systemd_hardening_parity.py -v
"""

import os
import warnings
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SELF_SCRIPT = REPO / "deploy" / "patched-maintenance-facts.sh"

BEGIN_MARKER = "# PARITY-BLOCK-BEGIN: systemd-hardening-ceilings-policy (PAT-1237)"
END_MARKER = "# PARITY-BLOCK-END"
GUARD_BEGIN = "# PARITY-BLOCK-BEGIN: deploy-hardening-ceilings-policy (PAT-1237)"
GUARD_END = "# PARITY-BLOCK-END: deploy-hardening-ceilings-policy (PAT-1237)"
SELF_GUARD = REPO / "deploy" / "verify-systemd-hardening-floor.sh"

# name -> (env var override, conventional sibling dirname, script path relative to repo root)
SIBLINGS = {
    "dashboard": ("PAT1237_DASHBOARD_REPO", "dashboard", "deploy/patched-maintenance-facts.sh"),
    "patched.im": (
        "PAT1237_PATCHED_IM_REPO",
        "patched.im",
        "api-vps-artefacts/patched-maintenance-facts.sh",
    ),
}


def _extract_block(text: str, source: str) -> str:
    start = text.find(BEGIN_MARKER)
    end = text.find(END_MARKER, start if start != -1 else 0)
    assert start != -1 and end != -1 and end > start, (
        f"{source}: parity markers not found or out of order -- expected "
        f"a {BEGIN_MARKER!r} ... {END_MARKER!r} region"
    )
    return text[start : end + len(END_MARKER)]


def _extract_guard(text: str, source: str) -> str:
    start = text.find(GUARD_BEGIN)
    end = text.find(GUARD_END, start if start != -1 else 0)
    assert start != -1 and end > start, f"{source}: deploy hardening parity markers missing"
    return text[start : end + len(GUARD_END)]


def _resolve_sibling_script(env_var: str, dirname: str, rel_path: str) -> Path | None:
    override = os.environ.get(env_var)
    if override:
        candidate = Path(override) / rel_path
        return candidate if candidate.is_file() else None
    candidate = REPO.parent / dirname / rel_path
    return candidate if candidate.is_file() else None


def test_systemd_hardening_parity_block_matches_siblings():
    own_text = _extract_block(SELF_SCRIPT.read_text(), str(SELF_SCRIPT))

    checked = []
    for name, (env_var, dirname, rel_path) in SIBLINGS.items():
        sibling_script = _resolve_sibling_script(env_var, dirname, rel_path)
        if sibling_script is None:
            warnings.warn(
                f"PAT-1237 parity check: could not locate the {name} repo "
                f"(set {env_var} to point at a checkout, or ensure "
                f"{REPO.parent / dirname} exists) -- skipping comparison "
                f"against it this run.",
                stacklevel=2,
            )
            continue

        sibling_text = sibling_script.read_text()
        if BEGIN_MARKER not in sibling_text:
            warnings.warn(
                f"PAT-1237 parity check: {sibling_script} has no parity "
                f"markers yet (its PAT-1237 change may not have merged) -- "
                f"skipping comparison against it this run.",
                stacklevel=2,
            )
            continue

        sibling_block = _extract_block(sibling_text, str(sibling_script))
        assert sibling_block == own_text, (
            f"systemd_hardening parity block drifted between "
            f"{SELF_SCRIPT} and {sibling_script}. Edit both copies "
            f"identically (see this block's own header comment in either "
            f"file)."
        )
        checked.append(name)

    if not checked:
        pytest.skip(
            "PAT-1237 parity check: neither sibling repo (dashboard, "
            "patched.im) could be located from this checkout. This is a "
            "local drift nudge, not a CI gate -- see this file's module "
            "docstring for how to point it at specific worktrees."
        )


def test_deploy_guard_policy_matches_canonical_siblings():
    own = _extract_guard(SELF_GUARD.read_text(), str(SELF_GUARD))
    guard_paths = {
        "dashboard": (
            "PAT1237_DASHBOARD_REPO",
            "dashboard",
            "deploy/verify-systemd-hardening-floor.sh",
        ),
        "patched.im": (
            "PAT1237_PATCHED_IM_REPO",
            "patched.im",
            "deploy/api-01/verify-systemd-hardening-floor.sh",
        ),
    }
    checked = []
    for name, (env_var, dirname, rel_path) in guard_paths.items():
        sibling = _resolve_sibling_script(env_var, dirname, rel_path)
        if sibling is None or GUARD_BEGIN not in sibling.read_text():
            continue
        assert _extract_guard(sibling.read_text(), str(sibling)) == own
        checked.append(name)
    if not checked:
        pytest.skip("PAT-1237 deploy guard parity found no current canonical sibling")
