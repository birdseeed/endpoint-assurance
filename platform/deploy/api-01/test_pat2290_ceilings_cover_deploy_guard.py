"""PAT-2290: every unit the deploy guard scores must also be classified by
the patched-maintenance-facts.sh ceilings block.

Two policy blocks list which patched-owned units belong to which
systemd-analyze security ceiling class:

  * `deploy-hardening-ceilings-policy` in
    deploy/api-01/verify-systemd-hardening-floor.sh, which fails a deploy
    when a unit is unclassified or over its ceiling.
  * `systemd-hardening-ceilings-policy` in
    api-vps-artefacts/patched-maintenance-facts.sh, which scores every
    installed patched-*.service on the box each hour and degrades the row
    for any unit it cannot classify (class, ceiling and over_ceiling all
    come back JSON null).

The existing PAT-1237 parity tests keep each block byte-identical across
patched.im, portal and dashboard. They compare copies of one block with each
other, so they cannot notice a unit that one block names and the other does
not: all three copies of the maintenance-facts block can agree and still
omit it. PAT-2109 added patched-tooling-cve-refresh.service to the deploy
guard only, so the unit deployed and passed the guard while the hourly
scorer reported it unclassified.

This test evaluates both mapping functions in bash (not a substring search,
because the maintenance-facts block carries long comments that name units
and would satisfy a text match without classifying anything) and requires,
for every unit that is named in the deploy guard and shipped here as
api-vps-artefacts/*.service, that the maintenance-facts block returns the
same non-empty class.

Run with: python3 -m unittest deploy.api-01.test_pat2290_ceilings_cover_deploy_guard -v
(or via `python3 -m unittest discover -s deploy/api-01 -p 'test_*.py'`)
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GUARD_SCRIPT = REPO / "deploy" / "api-01" / "verify-systemd-hardening-floor.sh"
FACTS_SCRIPT = REPO / "api-vps-artefacts" / "patched-maintenance-facts.sh"
SHIPPED_UNITS_DIR = REPO / "api-vps-artefacts"

GUARD_BEGIN = "# PARITY-BLOCK-BEGIN: deploy-hardening-ceilings-policy (PAT-1237)"
GUARD_END = "# PARITY-BLOCK-END: deploy-hardening-ceilings-policy (PAT-1237)"
FACTS_BEGIN = "# PARITY-BLOCK-BEGIN: systemd-hardening-ceilings-policy (PAT-1237)"
FACTS_END = "# PARITY-BLOCK-END"

UNIT_NAME = re.compile(r"patched-[a-z0-9-]+\.service")


def _extract(text: str, begin: str, end: str, source: str) -> str:
    start = text.find(begin)
    stop = text.find(end, start if start != -1 else 0)
    assert start != -1 and stop > start, (
        f"{source}: expected a {begin!r} ... {end!r} region"
    )
    return text[start : stop + len(end)]


def _class_from_block(block: str, function: str, unit: str) -> str:
    """Evaluate one mapping function from a policy block in bash.

    Both blocks are only comments and function definitions, so sourcing them
    has no side effects. An unknown unit yields an empty string (the facts
    block prints nothing, the guard returns non-zero), never an error.
    """
    result = subprocess.run(
        ["bash", "-c", f'{block}\n{function} "$1" || true', "bash", unit],
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


class CeilingsCoverDeployGuardTests(unittest.TestCase):
    def test_every_shipped_unit_in_the_deploy_guard_is_classified_by_the_scorer(self):
        guard_block = _extract(
            GUARD_SCRIPT.read_text(encoding="utf-8"), GUARD_BEGIN, GUARD_END, str(GUARD_SCRIPT)
        )
        facts_block = _extract(
            FACTS_SCRIPT.read_text(encoding="utf-8"), FACTS_BEGIN, FACTS_END, str(FACTS_SCRIPT)
        )

        shipped = {path.name for path in SHIPPED_UNITS_DIR.glob("patched-*.service")}
        guarded = set(UNIT_NAME.findall(guard_block))
        to_check = sorted(shipped & guarded)

        # A guard that silently checks nothing is not a guard: if the block
        # is reshaped so the unit names stop matching, fail here rather than
        # passing over an empty set.
        self.assertTrue(
            to_check,
            f"no unit is both shipped in {SHIPPED_UNITS_DIR} and named in the "
            f"deploy guard block of {GUARD_SCRIPT}; the test has lost its input",
        )

        missing = []
        mismatched = []
        for unit in to_check:
            guard_class = _class_from_block(guard_block, "unit_class", unit)
            scorer_class = _class_from_block(
                facts_block, "_systemd_hardening_class_for_unit", unit
            )
            if not scorer_class:
                missing.append(unit)
            elif scorer_class != guard_class:
                mismatched.append(f"{unit} (guard: {guard_class}, scorer: {scorer_class})")

        self.assertFalse(
            missing,
            "unit(s) named in the deploy guard in "
            f"{GUARD_SCRIPT.relative_to(REPO)} and shipped as api-vps-artefacts/*.service "
            "are missing from _systemd_hardening_class_for_unit in "
            f"{FACTS_SCRIPT.relative_to(REPO)}, so the hourly scorer would report them "
            "unclassified: " + ", ".join(missing) + ". Add them to the same "
            "case arm in all three patched-maintenance-facts.sh copies "
            "(patched.im, portal, dashboard).",
        )
        self.assertFalse(
            mismatched,
            "deploy guard and hourly scorer disagree on the class of: " + "; ".join(mismatched),
        )


if __name__ == "__main__":
    unittest.main()
