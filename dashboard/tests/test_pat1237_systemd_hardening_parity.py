"""PAT-1237: cross-repo drift check for the systemd_hardening unit-class/
ceiling policy shared by all three patched-maintenance-facts.sh emitters
(dashboard/deploy, patched.im/api-vps-artefacts, portal/deploy).

Modeled directly on test_pat1433_stray_config_backups_parity.py (same
directory) -- read that file's docstring first, it explains the pattern this
file reuses wholesale, just against a different marker and a different pair
of functions. The short version: a bounded, marker-delimited region in each
copy -- _systemd_hardening_class_for_unit (the unit-name -> class mapping)
and _systemd_hardening_ceiling_for_class (the class -> ceiling table) -- kept
byte-identical across all three, delimited by the literal comment lines:

    # PARITY-BLOCK-BEGIN: systemd-hardening-ceilings-policy (PAT-1237)
    ...
    # PARITY-BLOCK-END

Deliberately NOT the whole systemd_hardening section: each script enumerates
candidate units and assembles JSON in its own house style (dashboard
accumulates via `jq` inline; patched.im/api-01 builds a bash array of
`jq -n` objects then `jq -s`s it; portal exports \\t-delimited records to an
embedded python3 heredoc) -- exactly the same per-repo architecture split
PAT-1433's block already lives with. The parity block covers the part that
matters most (which unit belongs to which class, and each class's ceiling)
and is architecture-independent pure bash, so it CAN be made byte-identical
without touching how each script assembles JSON.

Where this can actually run: nowhere in CI, for the same reason
test_pat1433_stray_config_backups_parity.py's own docstring gives -- no
single CI pipeline checks out all three repos together. The resolution
strategy (sibling-directory default, env var override, skip-not-fail when a
sibling can't be found) is identical to that file; see its docstring for the
full reasoning, not repeated here.

Run with: pytest tests/test_pat1237_systemd_hardening_parity.py -v
"""

import os
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
    "patched.im": ("PAT1237_PATCHED_IM_REPO", "patched.im", "api-vps-artefacts/patched-maintenance-facts.sh"),
    "portal": ("PAT1237_PORTAL_REPO", "portal", "deploy/patched-maintenance-facts.sh"),
}


def _extract_block(text: str, source: str) -> str:
    start = text.find(BEGIN_MARKER)
    end = text.find(END_MARKER, start if start != -1 else 0)
    assert start != -1 and end != -1 and end > start, (
        f"{source}: parity markers not found or out of order -- expected "
        f"a {BEGIN_MARKER!r} ... {END_MARKER!r} region"
    )
    return text[start : end + len(END_MARKER)]


def _extract_guard_policy(text: str, source: str) -> str:
    start = text.find(GUARD_BEGIN)
    end = text.find(GUARD_END, start if start != -1 else 0)
    assert start != -1 and end > start, f"{source}: deploy hardening parity markers missing"
    return text[start : end + len(GUARD_END)]


def _resolve_sibling_script(env_var: str, dirname: str, rel_path: str) -> Path | None:
    override = os.environ.get(env_var)
    if override:
        candidate = Path(override) / rel_path
        return candidate if candidate.is_file() else None
    for sibling_dir in (dirname, f"{dirname}-pat-1237"):
        candidate = REPO.parent / sibling_dir / rel_path
        if candidate.is_file():
            return candidate
    return None


def test_systemd_hardening_parity_block_matches_siblings():
    own_text = _extract_block(SELF_SCRIPT.read_text(), str(SELF_SCRIPT))

    checked = []
    unavailable = []
    for name, (env_var, dirname, rel_path) in SIBLINGS.items():
        sibling_script = _resolve_sibling_script(env_var, dirname, rel_path)
        if sibling_script is None:
            unavailable.append(f"{name} (set {env_var})")
            continue

        sibling_text = sibling_script.read_text()
        if BEGIN_MARKER not in sibling_text:
            unavailable.append(f"{name} (checkout predates parity block)")
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
        pytest.skip("PAT-1237 parity check found no locatable current siblings: " + ", ".join(unavailable))
    assert checked


def test_deploy_guard_policy_matches_locatable_siblings():
    own = _extract_guard_policy(SELF_GUARD.read_text(), str(SELF_GUARD))
    guard_paths = {
        "patched.im": ("PAT1237_PATCHED_IM_REPO", "patched.im", "deploy/api-01/verify-systemd-hardening-floor.sh"),
        "portal": ("PAT1237_PORTAL_REPO", "portal", "deploy/verify-systemd-hardening-floor.sh"),
    }
    checked = []
    for name, (env_var, dirname, rel_path) in guard_paths.items():
        sibling = _resolve_sibling_script(env_var, dirname, rel_path)
        if sibling is None:
            continue
        assert _extract_guard_policy(sibling.read_text(), str(sibling)) == own
        checked.append(name)
    if not checked:
        pytest.skip("PAT-1237 deploy guard parity check found no locatable siblings")
