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

Run with: python3 -m unittest deploy.api-01.test_pat1237_systemd_hardening_parity -v
(or via `python3 -m unittest discover -s deploy/api-01 -p 'test_*.py'`)
"""

from __future__ import annotations

import os
import unittest
import warnings
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SELF_SCRIPT = REPO / "api-vps-artefacts" / "patched-maintenance-facts.sh"

BEGIN_MARKER = "# PARITY-BLOCK-BEGIN: systemd-hardening-ceilings-policy (PAT-1237)"
END_MARKER = "# PARITY-BLOCK-END"

# name -> (env var override, conventional sibling dirname, script path relative to repo root)
SIBLINGS = {
    "dashboard": ("PAT1237_DASHBOARD_REPO", "dashboard", "deploy/patched-maintenance-facts.sh"),
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


def _resolve_sibling_script(env_var: str, dirname: str, rel_path: str) -> Path | None:
    override = os.environ.get(env_var)
    if override:
        candidate = Path(override) / rel_path
        return candidate if candidate.is_file() else None
    candidate = REPO.parent / dirname / rel_path
    return candidate if candidate.is_file() else None


class SystemdHardeningParityTests(unittest.TestCase):
    def test_systemd_hardening_parity_block_matches_siblings(self):
        own_text = _extract_block(SELF_SCRIPT.read_text(), str(SELF_SCRIPT))

        checked = []
        for name, (env_var, dirname, rel_path) in SIBLINGS.items():
            sibling_script = _resolve_sibling_script(env_var, dirname, rel_path)
            if sibling_script is None:
                warnings.warn(
                    f"PAT-1237 parity check: could not locate the {name} repo "
                    f"(set {env_var} to point at a checkout, or ensure "
                    f"{REPO.parent / dirname} exists) -- skipping comparison "
                    f"against it this run."
                )
                continue

            sibling_text = sibling_script.read_text()
            if BEGIN_MARKER not in sibling_text:
                warnings.warn(
                    f"PAT-1237 parity check: {sibling_script} has no parity "
                    f"markers yet (its PAT-1237 change may not have merged) -- "
                    f"skipping comparison against it this run."
                )
                continue

            sibling_block = _extract_block(sibling_text, str(sibling_script))
            self.assertEqual(
                sibling_block, own_text,
                f"systemd_hardening parity block drifted between "
                f"{SELF_SCRIPT} and {sibling_script}. Edit both copies "
                f"identically (see this block's own header comment in either "
                f"file).",
            )
            checked.append(name)

        if not checked:
            self.skipTest(
                "PAT-1237 parity check: neither sibling repo (dashboard, "
                "portal) could be located from this checkout. This is a local "
                "drift nudge, not a CI gate -- see this file's module "
                "docstring for how to point it at specific worktrees."
            )


if __name__ == "__main__":
    unittest.main()
