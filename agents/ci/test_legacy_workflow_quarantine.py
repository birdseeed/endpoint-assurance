#!/usr/bin/env python3
"""Regression checks for the PAT-1474 legacy-workflow quarantine, for the
PAT-2247 and PAT-2299 catalogue retirements, and for the PAT-2304 Windows
allowlist and PAT-2308 smoke and behavioral probe retirements staying
retired."""

import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
ACTIONS = ROOT / ".github" / "actions"


def triggers(filename: str) -> dict:
    document = load_workflow(filename)
    value = document.get("on", {})
    assert isinstance(value, dict), f"{filename}: expected a trigger mapping"
    return value


def load_workflow(filename: str) -> dict:
    document = yaml.load(
        (WORKFLOWS / filename).read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    assert isinstance(document, dict), f"{filename}: expected a workflow mapping"
    return document


def check_legacy_workflows() -> None:
    # smoke-test.yml and behavioral-analysis.yml were held manual-only and
    # publication-free here (PAT-1474, PAT-1510, PAT-1517) until PAT-2308
    # deleted them; RETIRED_PROBE_WORKFLOWS below keeps them deleted.
    manual_only = ("upstream-label-diff.yml",)
    for filename in manual_only:
        configured = triggers(filename)
        assert set(configured) == {"workflow_dispatch"}, (
            f"{filename}: quarantined legacy workflow must remain manual-only; "
            f"found {sorted(configured)}"
        )

    assert not (WORKFLOWS / "installomator-upstream-review.yml").exists(), (
        "installomator-upstream-review.yml: the retired broad-maintenance model "
        "must not regain a scheduled or manually-dispatched issue-creation path"
    )

    # PAT-2247: no patching, ever (ADR-0011 dead) -- the signed-catalogue
    # sign/publish pipeline and the native package mirrors it fed are
    # deleted outright rather than quarantined further. PAT-2245 already
    # established catalogue-pin-guard.yml must not exist; the rest of this
    # list is PAT-2247's own deletions.
    for filename in (
        "daily-vendor-verify.yml",
        "mirror-pipeline.yml",
        "mirror-pipeline-windows.yml",
        "test-catalogue-publish-workflow.yml",
        "catalogue-pin-guard.yml",
    ):
        assert not (WORKFLOWS / filename).exists(), (
            f"{filename}: retired by PAT-2247 (no patching) -- must not reappear"
        )

    for filename in (
        "codeql-csharp.yml",
        "dep-audit.yml",
        "done-audit.yml",
        "semgrep-swift.yml",
    ):
        assert "schedule" in triggers(filename), (
            f"{filename}: retained agent/security/operational schedule disappeared"
        )

    upstream = load_workflow("upstream-label-diff.yml")
    assert upstream["jobs"]["diff"]["permissions"] == {"contents": "read"}, (
        "upstream-label-diff.yml: manual diagnostics need no repository or issue write token"
    )
    upstream_steps = {
        step.get("name"): step for step in upstream["jobs"]["diff"]["steps"]
    }
    for name in (
        "Commit updated diff report",
        "Open GitHub issue for divergences",
        "Record run in automations API",
    ):
        condition = upstream_steps[name].get("if", "")
        assert "github.event_name == 'schedule'" in condition, (
            f"upstream-label-diff.yml: {name} must stay unreachable from manual runs"
        )


# PAT-2299 (2026-09-30): scripts that served only the retired catalogue
# discovery pipeline. Their one runner was daily-vendor-verify.yml's
# discovery-report job (deleted by PAT-2247), and discovery reported to the
# /admin/discovery/* platform routes PAT-2249 removed. The publisher audit was
# a manual, report-only tool that nothing ran or read. None of them may come
# back, and no workflow may start calling them again.
#
# ci/mirror_pipeline.py, ci/mirror_pipeline_windows.py and verifier/verify.py
# were kept here because validate-labels.yml still reached them. PAT-2304
# retired that last caller; they are listed in RETIRED_ALLOWLIST_CHAIN below.
RETIRED_SCRIPTS = (
    "ci/discovery_common.py",
    "ci/discovery_macos.py",
    "ci/discovery_windows.py",
    "ci/test_discovery_common.py",
    "ci/test_discovery_macos.py",
    "ci/test_discovery_windows.py",
    "ci/audit_windows_publishers.py",
    "ci/windows-publisher-audit-report.json",
)


def check_retired_scripts() -> None:
    for rel in RETIRED_SCRIPTS:
        assert not (ROOT / rel).exists(), (
            f"{rel}: retired by PAT-2299 (no patching) -- must not reappear"
        )

    names = tuple(Path(rel).stem for rel in RETIRED_SCRIPTS)
    for workflow in sorted(WORKFLOWS.glob("*.y*ml")):
        text = workflow.read_text(encoding="utf-8")
        for name in names:
            assert name not in text, (
                f"{workflow.name}: references {name!r}, retired by PAT-2299 -- "
                "no workflow may run the discovery or publisher-audit scripts"
            )


# PAT-2304 (2026-09-30): the Windows allowlist mapped labels to winget
# installers for the Windows install path, which is patching (retired, Andy
# 2026-09-28). The allowlist, its signature, its signing workflow and scripts,
# its validator and schema, and the mirror and vendor-verifier chain that the
# validator was the last live caller of, are all deleted. None may come back,
# and no workflow or composite action may run or reference them again.
RETIRED_ALLOWLIST_WORKFLOWS = ("sign-windows-allowlist.yml",)

RETIRED_ALLOWLIST_CHAIN = (
    "windows/windows-allowlist.json",
    "windows/windows-allowlist.json.sig",
    "contracts/windows-allowlist.schema.json",
    "windows/sign-allowlist.py",
    "windows/verify-allowlist-signature.py",
    "ci/validate-windows-allowlist.py",
    "ci/test_validate_windows_allowlist.py",
    "ci/mirror_pipeline.py",
    "ci/mirror_pipeline_windows.py",
    "ci/test_mirror_pipeline.py",
    "ci/test_mirror_pipeline_windows.py",
    "verifier/verify.py",
    "verifier/test_verify.py",
    "verifier/testdata/bbedit-sparkle-plist-feed-trimmed.plist",
    "verifier/testdata/jre8-sparkle-appcast-real.xml",
)

# Tokens that no longer have a legitimate use anywhere in CI: the module name
# the mirror scripts were imported by, and the secret that held a copy of the
# agent-config private key for signing the allowlist.
RETIRED_ALLOWLIST_TOKENS = ("mirror_pipeline", "ALLOWLIST_SIGNING_KEY")

# PAT-2352: the MSI File-table guard now allows only the Service executable,
# rejecting every other file (including the retired allowlist). Executable
# fixtures in test_windows_msi_build_workflow exercise that fail-closed guard.
MSI_ACTION = ACTIONS / "windows-agent-msi" / "action.yml"


def _ci_files() -> list:
    return sorted(WORKFLOWS.glob("*.y*ml")) + sorted(ACTIONS.rglob("*.y*ml"))


def _executable_lines(path: Path) -> list:
    """Lines that can run or configure something, i.e. not full-line comments.

    Dated retirement notes live in comments and may name what was retired.
    """
    return [
        (number, line)
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if not line.lstrip().startswith("#")
    ]


def _file_reference(name: str) -> "re.Pattern":
    # Matches the name as a path component, so "verify.py" catches
    # "verifier/verify.py" and "python3 verify.py" but not "test_verify.py"
    # or "sign-artifact-metadata.py".
    return re.compile(r"(?<![\w.-])" + re.escape(name) + r"(?![\w-])")


def check_retired_allowlist_chain() -> None:
    for filename in RETIRED_ALLOWLIST_WORKFLOWS:
        assert not (WORKFLOWS / filename).exists(), (
            f"{filename}: retired by PAT-2304 (no patching) -- must not reappear"
        )
    for rel in RETIRED_ALLOWLIST_CHAIN:
        assert not (ROOT / rel).exists(), (
            f"{rel}: retired by PAT-2304 (no patching) -- must not reappear"
        )

    names = {Path(rel).name for rel in RETIRED_ALLOWLIST_CHAIN}
    names.update(RETIRED_ALLOWLIST_WORKFLOWS)
    patterns = {name: _file_reference(name) for name in sorted(names)}
    for path in _ci_files():
        shown = path.relative_to(ROOT)
        for number, line in _executable_lines(path):
            for name, pattern in patterns.items():
                assert not pattern.search(line), (
                    f"{shown}:{number}: references {name!r}, retired by PAT-2304 -- "
                    "no workflow or action may run or read it again"
                )
            for token in RETIRED_ALLOWLIST_TOKENS:
                assert token not in line, (
                    f"{shown}:{number}: references {token!r}, retired by PAT-2304"
                )

    action = MSI_ACTION.read_text(encoding="utf-8")
    assert '$expected = @("Patched.Service.exe")' in action, (
        "The MSI payload must allow only the headless Service"
    )
    assert '$fileNames | Where-Object { $_ -notin $expected }' in action, (
        "The MSI payload guard must reject every unexpected file, including the retired allowlist"
    )

    product = (ROOT / "windows" / "installer" / "Product.wxs").read_text(encoding="utf-8")
    assert "windows-allowlist" not in product, (
        "windows/installer/Product.wxs: references the retired Windows allowlist"
    )


# PAT-2308 (2026-09-30): the PAT-504 smoke test and PAT-505 behavioral probe
# installed catalogue apps on hosted runners (winget on Windows, the
# Installomator engine on macOS) to gate catalogue promotion and record
# baselines on the verifier-state branch. That is the patching path retired on
# 2026-09-28, and the catalogue they fed is gone (PAT-2245, PAT-2247). Both
# workflows, every script they ran, the contract test and workflow that pinned
# them, and the verifier files nothing called after PAT-2304 are deleted.
RETIRED_PROBE_WORKFLOWS = (
    "smoke-test.yml",
    "behavioral-analysis.yml",
    "test-live-probe-contract.yml",
)

RETIRED_PROBE_FILES = (
    "ci/smoke-test-macos.zsh",
    "ci/smoke-test-windows.ps1",
    "ci/behavioral-probe-macos.zsh",
    "ci/behavioral-probe-windows.ps1",
    "ci/lib/windows-behavioral-probe.psm1",
    "ci/merge-smoke-results.py",
    "ci/test_merge_smoke_results.py",
    "ci/merge-behavior-results.py",
    "ci/test_merge_behavior_results.py",
    "ci/select-behavioral-labels.py",
    "ci/test_select_behavioral_labels.py",
    "ci/test_live_probe_contract.py",
    "verifier/analyze-behavior.py",
    "verifier/test_analyze_behavior.py",
    "verifier/alerting.py",
    "verifier/test_alerting.py",
    "verifier/windows_evidence_attestation.py",
    "verifier/windows-evidence-public-key.json",
    "verifier/catalogue-coverage-baseline.json",
    "verifier/catalogue-label-presence-baseline.json",
    "verifier/resolver-retirements.json",
    "verifier/acknowledged-findings.json",
    "verifier/state/verification-state.json",
)

# Install steps that only the retired Windows probe jobs ran. Matching them as
# well as the file names means the same winget install path cannot come back
# under a new script or workflow name.
RETIRED_PROBE_TOKENS = ("Repair-WinGetPackageManager", "Microsoft.WinGet.Client")
RETIRED_PROBE_INSTALLS = (
    re.compile(r"\bwinget(?:\.exe)?\s+install\b", re.IGNORECASE),
    re.compile(r"\bsudo\b.*Installomator\.sh"),
)


def check_retired_probe_chain() -> None:
    for filename in RETIRED_PROBE_WORKFLOWS:
        assert not (WORKFLOWS / filename).exists(), (
            f"{filename}: retired by PAT-2308 (no patching) -- must not reappear"
        )
    for rel in RETIRED_PROBE_FILES:
        assert not (ROOT / rel).exists(), (
            f"{rel}: retired by PAT-2308 (no patching) -- must not reappear"
        )

    names = {Path(rel).name for rel in RETIRED_PROBE_FILES}
    names.update(RETIRED_PROBE_WORKFLOWS)
    patterns = {name: _file_reference(name) for name in sorted(names)}
    for path in _ci_files():
        shown = path.relative_to(ROOT)
        for number, line in _executable_lines(path):
            for name, pattern in patterns.items():
                assert not pattern.search(line), (
                    f"{shown}:{number}: references {name!r}, retired by PAT-2308 -- "
                    "no workflow or action may run or read it again"
                )
            for token in RETIRED_PROBE_TOKENS:
                assert token not in line, (
                    f"{shown}:{number}: references {token!r}, the WinGet client "
                    "setup only the retired PAT-2308 probe jobs used"
                )
            for install in RETIRED_PROBE_INSTALLS:
                assert not install.search(line), (
                    f"{shown}:{number}: installs third-party software on a runner, "
                    "the probe path retired by PAT-2308 (no patching)"
                )


# Pytest entry points. Without them pytest collects nothing from this file,
# and since PAT-2247 deleted test-catalogue-publish-workflow.yml (the only
# workflow that ran it as a script) these assertions ran nowhere. test-suite.yml
# runs `python3 -m pytest -q`, so these are what make the guard fire in CI.
def test_legacy_package_automation_stays_quarantined() -> None:
    check_legacy_workflows()


def test_retired_catalogue_scripts_stay_deleted() -> None:
    check_retired_scripts()


def test_retired_windows_allowlist_chain_stays_deleted() -> None:
    check_retired_allowlist_chain()


def test_retired_smoke_and_behavioral_probes_stay_deleted() -> None:
    check_retired_probe_chain()


def main() -> None:
    check_legacy_workflows()
    check_retired_scripts()
    check_retired_allowlist_chain()
    check_retired_probe_chain()
    print("OK: legacy package automation is quarantined behind manual dispatch.")


if __name__ == "__main__":
    main()
