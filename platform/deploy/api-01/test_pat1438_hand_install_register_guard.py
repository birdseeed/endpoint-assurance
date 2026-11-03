"""PAT-1438: standing guard that api-vps-artefacts/ cannot grow a third
undocumented artefact the way patched-maintenance-facts.service/.timer
(fixed under PAT-1439) and 52-automatic-reboot.conf (fixed by this ticket)
did -- a file that reaches patched-api-01 (or, for
nginx-main-tailscale.conf, patched-prod-01) with neither a CI deploy path
nor a documented reason for staying manual.

api-vps-artefacts/ has around 95 entries. Most of them are NOT box-installed
artefacts at all: `.md` handover notes and rollout write-ups, `.template`
placeholder files, and whole subdirectories that belong to other boxes or
are already covered by their own deploy-wiring tests (`pat-backup-01/`,
`prod-01-backup/`, `portal-01-backup/`, `api-01-backup/`, `alerting/`). A
naive "every file must be deployed or documented" check would light up
dozens of false positives on that material and would get abandoned rather
than maintained -- so the in-scope rule below is deliberately narrow and
explicit:

  A top-level entry of api-vps-artefacts/ is IN SCOPE for this guard if
  it is a FILE (not a directory) whose name does not end in `.md` or
  `.template`. Top-level directories are only allowed to exist if they are
  named in EXCLUDED_DIRECTORIES below, each with its own reason -- an
  unrecognised new directory fails the guard just as loudly as an
  unrecognised new file, rather than being silently skipped by virtue of
  being a directory.

Same technique as test_maintenance_facts_deploy_wiring.py and
test_pat1439_maintenance_facts_units_deploy_wiring.py (this directory):
read the real files from this checkout as text and assert on them, rather
than adding a YAML parser or a second CI job.

An in-scope artefact satisfies the guard one of two ways:

  (a) It is shipped by a deploy workflow -- found as the literal text
      "api-vps-artefacts/<filename>" on a non-comment line somewhere in a
      .github/workflows/*.yml file, the same idiom the existing wiring
      tests assert on for individual files. A line whose first
      non-whitespace character is `#` does not count: a file merely
      mentioned in a comment (an explanatory note, a disabled step) is not
      a file anything actually deploys.
  (b) It is named in the hand-install register in
      api-vps-artefacts/provisioning-checklist.md, section
      "## 12. Hand-install register", as a "- `<filename>`: <reason>" line,
      with a non-empty reason.

Neither: the guard fails with a message naming the exact file and telling
the reader to do one of those two things -- that failure is the feature
this ticket exists to add.

Run with: python3 -m unittest deploy.api-01.test_pat1438_hand_install_register_guard -v
(or via `python3 -m unittest discover -s deploy/api-01 -p 'test_*.py'`)
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ARTEFACTS_DIR = REPO_ROOT / "api-vps-artefacts"
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
CHECKLIST_PATH = ARTEFACTS_DIR / "provisioning-checklist.md"

REGISTER_HEADING = "## 12. Hand-install register"
REGISTER_END_MARKER = "Files not listed above are either excluded by the rule"

EXCLUDED_SUFFIXES = (".md", ".template")

# Each of these is a whole subdirectory that belongs to a different box, or
# (alerting/) is a mixed multi-box directory already covered by its own
# dedicated wiring tests (test_prometheus_rules_deploy_wiring.py,
# test_maintenance_facts_prometheus_rules.py,
# test_selector_liveness_weekly_wiring.py, test_promtool_check_rules.py) --
# folding it into this flat top-level guard would either duplicate that
# coverage or fight it. A NEW top-level directory that isn't one of these is
# NOT silently skipped: see test_no_unrecognised_top_level_directories.
EXCLUDED_DIRECTORIES = {
    "pat-backup-01": "belongs to patched's pat-backup-01 box, not api-01",
    "prod-01-backup": "belongs to patched-prod-01, not api-01",
    "portal-01-backup": "belongs to the portal box, not api-01",
    "api-01-backup": "api-01's own backup *transport* config, already reasoned about "
        "via its own install.sh/sshd config pair; not a service artefact this guard "
        "meaningfully classifies as a single file",
    "alerting": "mixed multi-box alerting config with its own dedicated deploy-wiring "
        "tests (see module docstring); already covered, not by this guard",
}


def discover_in_scope_files() -> list[str]:
    files = []
    for entry in ARTEFACTS_DIR.iterdir():
        if entry.is_dir():
            continue
        if entry.name.endswith(EXCLUDED_SUFFIXES):
            continue
        files.append(entry.name)
    return sorted(files)


def discover_top_level_directories() -> list[str]:
    return sorted(entry.name for entry in ARTEFACTS_DIR.iterdir() if entry.is_dir())


def load_workflow_texts() -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(WORKFLOWS_DIR.glob("*.yml"))}


def is_ci_deployed(filename: str, workflow_texts: dict[str, str]) -> str | None:
    """Return the workflow filename that ships this artefact, or None.

    A whole-line comment (first non-whitespace character `#`) never counts.
    Non-author review, PAT-1438: a bare substring search over the whole
    workflow text would count a file as "shipped" just because its name is
    mentioned in a comment -- an explanatory note, a step disabled by
    commenting it out, prose referencing a sibling step above it. That is
    the exact correct-by-luck shape this guard exists to catch, one level
    down: the guard would certify as CI-deployed something nothing actually
    deploys. Only a line that is not purely a comment can satisfy (a).
    """
    needle = f"api-vps-artefacts/{filename}"
    for workflow_name, text in workflow_texts.items():
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            if needle in line:
                return workflow_name
    return None


_ENTRY_RE = re.compile(r"(?m)^- `([^`]+)`: ")


def parse_register(checklist_text: str) -> dict[str, str]:
    """Parse the '- `<filename>`: <reason>' lines under REGISTER_HEADING.

    Reasons may wrap across indented continuation lines, so this collects
    everything between one entry marker and the next (or the section's
    closing paragraph) rather than assuming a single line per entry.
    """
    start = checklist_text.index(REGISTER_HEADING)
    end = checklist_text.index(REGISTER_END_MARKER, start)
    section = checklist_text[start:end]

    matches = list(_ENTRY_RE.finditer(section))
    register: dict[str, str] = {}
    for index, match in enumerate(matches):
        filename = match.group(1)
        reason_start = match.end()
        reason_end = matches[index + 1].start() if index + 1 < len(matches) else len(section)
        reason = " ".join(section[reason_start:reason_end].split())
        register[filename] = reason
    return register


class HandInstallRegisterGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.checklist_text = CHECKLIST_PATH.read_text(encoding="utf-8")
        cls.register = parse_register(cls.checklist_text)
        cls.workflow_texts = load_workflow_texts()

    # ── sanity: the parser actually found the register, not an empty dict ──

    def test_register_heading_exists(self):
        self.assertIn(
            REGISTER_HEADING,
            self.checklist_text,
            f"expected a {REGISTER_HEADING!r} section in {CHECKLIST_PATH}",
        )

    def test_register_parses_a_non_empty_set_of_entries(self):
        self.assertTrue(
            self.register,
            "parsed zero entries from the hand-install register -- either the "
            "section is empty or the '- `filename`: reason' format has drifted "
            "from what parse_register() expects",
        )

    def test_register_reasons_are_never_empty(self):
        blank = [name for name, reason in self.register.items() if not reason]
        self.assertFalse(
            blank,
            f"register entries with no reason text at all: {blank}. A blank "
            "reason is indistinguishable from a copy-paste slip -- write "
            "'reason not recorded' explicitly if that is genuinely the case.",
        )

    def test_register_entries_correspond_to_real_files(self):
        stale = [name for name in self.register if not (ARTEFACTS_DIR / name).is_file()]
        self.assertFalse(
            stale,
            f"register lists {stale} but no such file exists in {ARTEFACTS_DIR} -- "
            "the entry is stale and should be removed, or the file was renamed "
            "and the register needs to follow it",
        )

    # ── no new directory can hide from classification just by being one ────

    def test_no_unrecognised_top_level_directories(self):
        unexpected = [
            d for d in discover_top_level_directories() if d not in EXCLUDED_DIRECTORIES
        ]
        self.assertFalse(
            unexpected,
            f"new top-level directory(ies) {unexpected} appeared in {ARTEFACTS_DIR} "
            "and are not in this guard's EXCLUDED_DIRECTORIES allowlist. Classify "
            "them: add an entry to EXCLUDED_DIRECTORIES in "
            "deploy/api-01/test_pat1438_hand_install_register_guard.py with the "
            "real reason they are out of scope (belongs to another box, already "
            "covered by other tests, etc), or fold their in-scope contents into "
            "this guard's discovery logic.",
        )

    # ── comment-only mentions must not count as a real deploy reference ────

    def test_comment_only_reference_is_not_treated_as_a_deploy(self):
        # Non-author review, PAT-1438: a bare substring search over the
        # whole workflow text would count a file as CI-deployed just
        # because its name is mentioned in a comment -- an explanatory
        # note, or a step disabled by commenting it out. That is exactly
        # the correct-by-luck state this guard exists to catch, one level
        # down: it would certify as deployed something nothing deploys.
        workflow_texts = {
            "fake-deploy.yml": "\n".join(
                [
                    "jobs:",
                    "  deploy:",
                    "    steps:",
                    "      # api-vps-artefacts/never-shipped.conf used to ship here,",
                    "      # removed 2026-08-19; left as a note, not a live step.",
                    "      - run: echo noop",
                ]
            ),
        }
        self.assertIsNone(
            is_ci_deployed("never-shipped.conf", workflow_texts),
            "a filename mentioned only on a comment line must not be "
            "treated as CI-deployed",
        )

    def test_indented_comment_reference_also_does_not_count(self):
        # The `#` need not be in column 0 -- a comment inside a multi-line
        # `run: |` block is indented, and must be excluded the same way.
        workflow_texts = {
            "fake-deploy.yml": "\n".join(
                [
                    "jobs:",
                    "  deploy:",
                    "    steps:",
                    "      - run: |",
                    "          # api-vps-artefacts/indented-comment.conf noted here only",
                    "          echo noop",
                ]
            ),
        }
        self.assertIsNone(
            is_ci_deployed("indented-comment.conf", workflow_texts),
            "an indented comment line must not be treated as CI-deployed either",
        )

    def test_a_real_non_comment_reference_still_counts(self):
        # Bounds the fix from the other direction: tightening comment
        # handling must not make the detector blind to a genuine deploy
        # step referencing the file on a real code line.
        workflow_texts = {
            "fake-deploy.yml": "\n".join(
                [
                    "jobs:",
                    "  deploy:",
                    "    steps:",
                    "      - run: |",
                    "          rsync api-vps-artefacts/really-shipped.conf root@host:/etc/",
                ]
            ),
        }
        self.assertEqual(
            is_ci_deployed("really-shipped.conf", workflow_texts),
            "fake-deploy.yml",
        )

    # ── the actual guard: every in-scope file is deployed or registered ────

    def test_every_in_scope_artefact_is_deployed_or_registered(self):
        unaccounted = []
        for filename in discover_in_scope_files():
            deployed_by = is_ci_deployed(filename, self.workflow_texts)
            if deployed_by is not None:
                continue
            if filename in self.register:
                continue
            unaccounted.append(filename)

        self.assertFalse(
            unaccounted,
            "the following api-vps-artefacts/ file(s) are neither shipped by a "
            "CI deploy workflow nor named in the hand-install register: "
            f"{unaccounted}. This is exactly the gap PAT-1438 closed for "
            "52-automatic-reboot.conf and PAT-1439 closed for "
            "patched-maintenance-facts.service/.timer -- a file installed on the "
            "box (or expected to be) that nothing tracks. Fix it one of two "
            "ways: (1) give it a real CI deploy step in "
            ".github/workflows/deploy-api-01.yml referencing it as "
            f"'api-vps-artefacts/<filename>', or (2) add a "
            "'- `<filename>`: <reason>' line for it under "
            f"'{REGISTER_HEADING}' in {CHECKLIST_PATH.relative_to(REPO_ROOT)} "
            "with the real, documented reason it stays manual -- write "
            "'reason not recorded' rather than inventing one if you cannot "
            "find it stated anywhere.",
        )

    # ── spot-checks that the two halves of the classification are sane ─────

    def test_fixed_artefacts_are_deployed_not_registered(self):
        # Regression pin: these three used to have no deploy path at all
        # (PAT-1436/PAT-1439) and 52-automatic-reboot.conf used to have
        # neither a deploy path nor a documented reason (PAT-1438, this
        # ticket). All four must now be satisfied via (a), the CI path --
        # not via (b), a register entry -- or the fix has regressed into a
        # weaker guarantee than what actually shipped.
        for filename in (
            "patched-maintenance-facts.sh",
            "patched-maintenance-facts.service",
            "patched-maintenance-facts.timer",
            "52-automatic-reboot.conf",
        ):
            with self.subTest(filename=filename):
                self.assertIsNotNone(
                    is_ci_deployed(filename, self.workflow_texts),
                    f"{filename} is expected to have a real CI deploy path in "
                    "deploy-api-01.yml; it no longer does",
                )
                self.assertNotIn(
                    filename,
                    self.register,
                    f"{filename} is CI-deployed and should not also carry a "
                    "hand-install register entry -- that would say two "
                    "contradictory things about the same file",
                )

    def test_a_known_hand_installed_file_is_registered_with_a_reason(self):
        self.assertIn("Caddyfile.api", self.register)
        self.assertTrue(self.register["Caddyfile.api"])


if __name__ == "__main__":
    unittest.main()
