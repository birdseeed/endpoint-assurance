"""PAT-1433: cross-repo drift check for the stray_config_backups naming
policy shared by all three patched-maintenance-facts.sh emitters
(dashboard/deploy, patched.im/api-vps-artefacts, portal/deploy).

See dashboard/tests/test_pat1433_stray_config_backups_parity.py's module
docstring for the full rationale -- this is the same test, ported to this
repo's unittest convention (matching test_pat1431_stray_config_backups.py in
this directory). Short version:

  * A bounded, marker-delimited region (CONFIG_BACKUP_ROOT/CONFIG_BACKUP_DIRS
    glob + its -backup exclusion, KNOWN_LIVE_CONFIG_BASENAMES, and
    _stray_name_matches) is kept byte-identical across all three copies,
    delimited by:

        # PARITY-BLOCK-BEGIN: stray-config-backups-policy (PAT-1433)
        ...
        # PARITY-BLOCK-END

  * NOT the whole section -- each script assembles its JSON differently
    (this one builds a bash array of `jq -n` objects then `jq -s`s it;
    dashboard accumulates via `jq` inline; portal round-trips through an
    embedded python3 heredoc). Forcing byte-identical JSON-assembly code
    across those three architectures is the bigger "shared library /
    build-time generation" work PAT-1433 explicitly defers.
  * There is no CI location that sees all three repos -- each repo's
    pipeline checks out only itself. This only runs meaningfully on a local
    machine where the sibling repos are checked out alongside this one (the
    permanent `~/development/Patched.im/<repo>` layout, or ticket worktrees
    pointed at via the env vars below). It is a local drift nudge, not a
    CI-enforced gate.
  * Resolution: `PAT1433_DASHBOARD_REPO` / `PAT1433_PORTAL_REPO` env vars
    override the sibling repo path (point them at ticket worktrees, e.g.
    `dashboard-pat-1433`, `portal-pat-1433`, to verify a coordinated
    in-flight change); otherwise this looks for conventional sibling dirs
    `<this repo's parent>/dashboard` and `.../portal`. A sibling that can't
    be found, or hasn't merged its own PAT-1433 markers yet, is skipped with
    a warning rather than failing the whole test -- three independent PRs
    must each be able to merge without waiting on the other two. If neither
    sibling can be found at all, the test is skipped outright.

Run with: python3 -m unittest deploy.api-01.test_pat1433_stray_config_backups_parity -v
"""

from __future__ import annotations

import os
import unittest
import warnings
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SELF_SCRIPT = REPO_ROOT / "api-vps-artefacts" / "patched-maintenance-facts.sh"

BEGIN_MARKER = "# PARITY-BLOCK-BEGIN: stray-config-backups-policy (PAT-1433)"
END_MARKER = "# PARITY-BLOCK-END"

# name -> (env var override, conventional sibling dirname, script path relative to repo root)
SIBLINGS = {
    "dashboard": ("PAT1433_DASHBOARD_REPO", "dashboard", "deploy/patched-maintenance-facts.sh"),
    "portal": ("PAT1433_PORTAL_REPO", "portal", "deploy/patched-maintenance-facts.sh"),
}


def _extract_block(text: str, source: str) -> str:
    start = text.find(BEGIN_MARKER)
    end = text.find(END_MARKER)
    assert start != -1 and end != -1 and end > start, (
        f"{source}: parity markers not found or out of order -- expected "
        f"a {BEGIN_MARKER!r} ... {END_MARKER!r} region"
    )
    return text[start : end + len(END_MARKER)]


def _resolve_sibling_script(env_var: str, dirname: str, rel_path: str) -> Path | None:
    override = os.environ.get(env_var)
    if override:
        candidate = Path(override) / rel_path
        return candidate if candidate.is_file() else None
    candidate = REPO_ROOT.parent / dirname / rel_path
    return candidate if candidate.is_file() else None


class StrayConfigBackupsParityTests(unittest.TestCase):
    def test_parity_block_matches_siblings(self):
        own_text = _extract_block(SELF_SCRIPT.read_text(), str(SELF_SCRIPT))

        checked = []
        for name, (env_var, dirname, rel_path) in SIBLINGS.items():
            sibling_script = _resolve_sibling_script(env_var, dirname, rel_path)
            if sibling_script is None:
                warnings.warn(
                    f"PAT-1433 parity check: could not locate the {name} "
                    f"repo (set {env_var} to point at a checkout, or "
                    f"ensure {REPO_ROOT.parent / dirname} exists) -- "
                    f"skipping comparison against it this run."
                )
                continue

            sibling_text = sibling_script.read_text()
            if BEGIN_MARKER not in sibling_text:
                warnings.warn(
                    f"PAT-1433 parity check: {sibling_script} has no "
                    f"parity markers yet (its PAT-1433 change may not "
                    f"have merged) -- skipping comparison against it this "
                    f"run."
                )
                continue

            sibling_block = _extract_block(sibling_text, str(sibling_script))
            self.assertEqual(
                sibling_block, own_text,
                f"stray_config_backups parity block drifted between "
                f"{SELF_SCRIPT} and {sibling_script}. Edit both copies "
                f"identically (see this block's own header comment in "
                f"either file).",
            )
            checked.append(name)

        if not checked:
            self.skipTest(
                "PAT-1433 parity check: neither sibling repo (dashboard, "
                "portal) could be located from this checkout. This is a "
                "local drift nudge, not a CI gate -- see this file's "
                "module docstring for how to point it at specific "
                "worktrees."
            )


if __name__ == "__main__":
    unittest.main()
