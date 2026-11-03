"""PAT-1433: cross-repo drift check for the stray_config_backups naming
policy shared by all three patched-maintenance-facts.sh emitters
(dashboard/deploy, patched.im/api-vps-artefacts, portal/deploy).

Why this exists: PAT-1408 built the check for dashboard, PAT-1431 hand-ported
it to patched.im and portal -- three hand-maintained copies against one
shared JSON schema, propagated by hand every time. This test is the cheap
mitigation named in PAT-1433: a bounded, marker-delimited region in each
copy -- CONFIG_BACKUP_ROOT/CONFIG_BACKUP_DIRS (the /etc/patched-* glob and
its -backup exclusion), KNOWN_LIVE_CONFIG_BASENAMES, and _stray_name_matches
(the naming-match regex) -- kept byte-identical across all three, delimited
by the literal comment lines:

    # PARITY-BLOCK-BEGIN: stray-config-backups-policy (PAT-1433)
    ...
    # PARITY-BLOCK-END

Deliberately NOT the whole stray_config_backups section: each script
assembles its JSON differently (dashboard accumulates via `jq` inside the
loop; patched.im/api-01 builds a bash array of `jq -n` objects then
`jq -s`s it; portal exports the loop's values as \\x1f-delimited env vars to
an embedded python3 heredoc, its own house style predating this ticket).
Forcing those three architectures to emit byte-identical code would mean
rewriting one or two scripts' overall structure -- exactly the "shared
library / build-time generation" work PAT-1433 calls a real architectural
change and says to leave for a follow-up, not fold into this cheap mitigation.
The parity block covers the part that both matters most (the naming/scope
policy that decides what gets flagged) and is architecture-independent pure
bash, so it CAN be made byte-identical without touching how each script
assembles JSON.

Where this can actually run: nowhere in CI. Each of the three repos' CI
checks out only itself -- there is no single place all three are checked out
together in any of their pipelines, and inventing one (a submodule, a
fetch-the-other-two-repos CI step with its own auth) is exactly the fragile
cross-repo mechanism PAT-1433 says not to build. The one place all three
copies are routinely visible together is this local dev machine, where
`~/development/Patched.im/<repo>` are permanent sibling checkouts (see the
workspace CLAUDE.md) and `bin/worktree-start.sh` creates ticket worktrees as
further siblings alongside them. So:

  * By default, this test looks for the two sibling repos at
    `<this repo's parent dir>/patched.im` and `.../portal` -- the permanent
    main checkouts every session on this machine already has. If one isn't
    there (or has this file's markers but not both, or is missing
    entirely), that sibling is skipped with a warning rather than failing
    the whole test -- during the window where PAT-1433's three PRs merge on
    different schedules, a sibling repo legitimately may not have the
    marked block yet, and that must not block any of the three PRs on the
    other two.
  * `PAT1433_DASHBOARD_REPO` / `PAT1433_PATCHED_IM_REPO` /
    `PAT1433_PORTAL_REPO` env vars override the resolved path for any repo
    (including this one) -- set them to point at specific ticket worktrees
    (e.g. `patched.im-pat-1433`, `portal-pat-1433`) when verifying a
    coordinated in-flight change like this one, rather than against
    whatever's merged to each repo's `main`.
  * If neither sibling can be found at all, the test is skipped outright
    (not silently passed) with a clear reason -- this is a local drift
    nudge, not a CI-enforced gate; there is no clean way to make it one
    given the repos are independent (see PAT-1433's own instructions).

Run with: pytest tests/test_pat1433_stray_config_backups_parity.py -v
"""

import os
import warnings
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SELF_SCRIPT = REPO / "deploy" / "patched-maintenance-facts.sh"

BEGIN_MARKER = "# PARITY-BLOCK-BEGIN: stray-config-backups-policy (PAT-1433)"
END_MARKER = "# PARITY-BLOCK-END"

# name -> (env var override, conventional sibling dirname, script path relative to repo root)
SIBLINGS = {
    "patched.im": ("PAT1433_PATCHED_IM_REPO", "patched.im", "api-vps-artefacts/patched-maintenance-facts.sh"),
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
    candidate = REPO.parent / dirname / rel_path
    return candidate if candidate.is_file() else None


def test_stray_config_backups_parity_block_matches_siblings():
    own_text = _extract_block(SELF_SCRIPT.read_text(), str(SELF_SCRIPT))

    checked = []
    for name, (env_var, dirname, rel_path) in SIBLINGS.items():
        sibling_script = _resolve_sibling_script(env_var, dirname, rel_path)
        if sibling_script is None:
            warnings.warn(
                f"PAT-1433 parity check: could not locate the {name} repo "
                f"(set {env_var} to point at a checkout, or ensure "
                f"{REPO.parent / dirname} exists) -- skipping comparison "
                f"against it this run."
            )
            continue

        sibling_text = sibling_script.read_text()
        if BEGIN_MARKER not in sibling_text:
            warnings.warn(
                f"PAT-1433 parity check: {sibling_script} has no parity "
                f"markers yet (its PAT-1433 change may not have merged) -- "
                f"skipping comparison against it this run."
            )
            continue

        sibling_block = _extract_block(sibling_text, str(sibling_script))
        assert sibling_block == own_text, (
            f"stray_config_backups parity block drifted between "
            f"{SELF_SCRIPT} and {sibling_script}. Edit both copies "
            f"identically (see this block's own header comment in either "
            f"file)."
        )
        checked.append(name)

    if not checked:
        pytest.skip(
            "PAT-1433 parity check: neither sibling repo (patched.im, "
            "portal) could be located from this checkout. This is a local "
            "drift nudge, not a CI gate -- see this file's module "
            "docstring for how to point it at specific worktrees."
        )
