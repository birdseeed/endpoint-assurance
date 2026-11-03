#!/usr/bin/env python3
"""Static contract tests for PAT-1531's Windows assurance-only artifact seam."""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def project_items(path: Path, element: str, attribute: str) -> set[str]:
    root = ET.parse(path).getroot()
    return {
        item.attrib[attribute].replace("\\", "/")
        for item in root.findall(f".//{element}")
        if attribute in item.attrib
    }


RETIRED_PAIR = re.compile(r'^\s*\("([a-z0-9_]+)",\s*"([a-z0-9_]+)"\),\s*$', re.MULTILINE)
HEALTH_RECORD_CALL = re.compile(r"\.Record(?:Failure|Success)\(")


def retired_pair_recorders(
    sources: dict[str, str], pairs: list[tuple[str, str]]
) -> list[str]:
    """Shipped sources that still record a retired agent-health pair (PAT-2422).

    A source is flagged when it makes a RecordFailure or RecordSuccess call and
    names both halves of a retired pair as string literals. Matching the two
    literals anywhere in the file, not only as call arguments, also catches a
    recorder that passes them through constants.
    """
    hits = []
    for name, text in sorted(sources.items()):
        if not HEALTH_RECORD_CALL.search(text):
            continue
        for kind, subject in pairs:
            if f'"{kind}"' in text and f'"{subject}"' in text:
                hits.append(f"{name} records retired pair {kind}/{subject}")
    return hits


def check_retired_health_reasons(excluded: set[str]) -> None:
    service_dir = ROOT / "windows/src/Service"
    retired_file = service_dir / "RetiredHealthReasons.cs"
    pairs = RETIRED_PAIR.findall(retired_file.read_text(encoding="utf-8"))
    if ("sync_never_succeeded", "catalogue") not in pairs:
        fail("could not read the retired agent-health pairs from RetiredHealthReasons.cs")

    # The detector must be able to fail before its clean result means anything.
    literal = {"A.cs": 'h.RecordFailure("capability_missing", "package_engine", "x");'}
    constants = {
        "B.cs": 'const string K = "sync_never_succeeded"; const string S = "catalogue";\n'
        "_agentHealth.RecordSuccess(K, S);"
    }
    unrelated = {"C.cs": '_agentHealth.RecordFailure("sync_never_succeeded", "posture", "x");'}
    if (
        len(retired_pair_recorders(literal, pairs)) != 1
        or len(retired_pair_recorders(constants, pairs)) != 1
        or retired_pair_recorders(unrelated, pairs)
    ):
        fail("retired agent-health guard self-check failed: the detector is not working")

    shipped = {
        path.relative_to(service_dir).as_posix(): path.read_text(encoding="utf-8")
        for path in service_dir.rglob("*.cs")
        if {"bin", "obj"}.isdisjoint(path.relative_to(service_dir).parts)
        and path != retired_file
        and path.relative_to(service_dir).as_posix() not in excluded
    }
    if "AssuranceCapabilityHealth.cs" not in shipped or "InstallRunner.cs" in shipped:
        fail("retired agent-health guard is not scanning the shipped Service sources")
    hits = retired_pair_recorders(shipped, pairs)
    if hits:
        fail(
            "a reason listed in RetiredHealthReasons.cs is still recorded by the shipped "
            "service, so the store would silently drop a live signal: " + "; ".join(hits)
        )


def main() -> None:
    service_project = ROOT / "windows/src/Service/Service.csproj"
    references = project_items(service_project, "ProjectReference", "Include")
    if "../Engine/Engine.csproj" in references:
        fail("Service.csproj still references the legacy Engine project")

    excluded = project_items(service_project, "Compile", "Remove")
    required_exclusions = {
        "DeviceRemovalTasksClient.cs",
        "InstallRunner.cs",
        "InventoryCollector.cs",
        "PendingInstallsFetcher.cs",
        "PendingRemovalsFetcher.cs",
        "RegistryUninstallLookup.cs",
        "RemovalRunner.cs",
        "UninstallExecutor.cs",
        "DeviceRemovalRunner.cs",
    }
    missing_exclusions = required_exclusions - excluded
    if missing_exclusions:
        fail(f"Service.csproj still compiles legacy runner source: {sorted(missing_exclusions)}")

    check_retired_health_reasons(excluded)

    program = (ROOT / "windows/src/Service/Program.cs").read_text(encoding="utf-8")
    worker = (ROOT / "windows/src/Service/Worker.cs").read_text(encoding="utf-8")
    for forbidden in (
        "using Patched.Engine;",
        "AddSingleton<InstallRunner>",
        "AddSingleton<RemovalRunner>",
        "AddSingleton<UninstallExecutor>",
        "AddSingleton<DeviceRemovalRunner>",
    ):
        if forbidden in program:
            fail(f"Program.cs still wires legacy actuation: {forbidden}")
    for forbidden in ("_installs.RunAsync", "_removals.RunAsync", "_deviceRemovals.RunAsync"):
        if forbidden in worker:
            fail(f"Worker.cs still invokes legacy actuation: {forbidden}")
    # PAT-2245: the signed app catalogue is retired. The service must not host its
    # sync again, and must remove the cache an older release left behind at startup.
    for forbidden in ("CatalogueFetcher", "CatalogueSyncService"):
        if forbidden in program:
            fail(f"Program.cs still wires the retired catalogue sync: {forbidden}")
    if "RetiredCatalogueCleanup.RunProduction(" not in program:
        fail("Program.cs does not remove the retired catalogue cache at startup")
    if program.index("RetiredCatalogueCleanup.RunProduction(") > program.index("host.Run();"):
        fail("Program.cs removes the retired catalogue cache after the host starts")
    if "AddSingleton<AssuranceCapabilityHealth>" not in program:
        fail("Program.cs does not register assurance-only capability health")
    health_call = "_assuranceCapabilityHealth.Record();"
    inventory_upload = "await _inventoryPoster.PostAsync"
    if health_call not in worker:
        fail("Worker.cs does not record assurance-only capability health before inventory upload")
    if worker.index(health_call) > worker.index(inventory_upload):
        fail("Worker.cs records assurance-only capability health after inventory upload")

    quarantined_tests = project_items(
        ROOT / "windows/tests/Service.Tests/Service.Tests.csproj", "Compile", "Remove"
    )
    required_quarantined_tests = {
        "DeviceRemovalRunnerTests.cs",
        "InventoryCollectorTests.cs",
    }
    missing_quarantined_tests = required_quarantined_tests - quarantined_tests
    if missing_quarantined_tests:
        fail(f"legacy actuation tests are not explicitly quarantined: {sorted(missing_quarantined_tests)}")

    quarantine_target = ROOT / "windows/tests/QuarantinedRunners.Tests/QuarantinedRunners.Tests.csproj"
    if not quarantine_target.is_file():
        fail("non-shipping QuarantinedRunners.Tests compile/test target is missing")
    quarantine_source = quarantine_target.read_text(encoding="utf-8")
    for runner in (
        "DeviceRemovalRunner.cs",
        "InstallRunner.cs",
        "InventoryCollector.cs",
        "RemovalRunner.cs",
    ):
        if runner not in quarantine_source:
            fail(f"non-shipping quarantine target does not compile {runner}")

    solution = (ROOT / "windows/PatchedAgent.sln").read_text(encoding="utf-8")
    if "QuarantinedRunners.Tests" in solution:
        fail("QuarantinedRunners.Tests was added to the shipping solution")

    wix = ET.parse(ROOT / "windows/installer/Product.wxs").getroot()
    namespace = {"wix": "http://wixtoolset.org/schemas/v4/wxs"}
    feature = wix.find(".//wix:Feature[@Id='ProductFeature']", namespace)
    if feature is None:
        fail("Product.wxs has no ProductFeature")
    feature_groups = {ref.attrib["Id"] for ref in feature.findall("wix:ComponentGroupRef", namespace)}
    prohibited_groups = {"SelfServiceBinary", "AllowlistFiles"}
    present_groups = prohibited_groups & feature_groups
    if present_groups:
        fail(f"ProductFeature still packages legacy group(s): {sorted(present_groups)}")
    if wix.find(".//wix:ComponentGroup[@Id='SelfServiceBinary']", namespace) is not None:
        fail("Product.wxs still defines the unshipped SelfServiceBinary component group")
    # PAT-2304 (2026-09-30): the legacy allowlist and its .sig are deleted, so
    # the deprecated Fragment that sourced them must not come back either.
    if wix.find(".//wix:ComponentGroup[@Id='AllowlistFiles']", namespace) is not None:
        fail("Product.wxs still defines the retired AllowlistFiles component group")
    retired_sources = [
        element.attrib["Source"]
        for element in wix.iter("{http://wixtoolset.org/schemas/v4/wxs}File")
        if "allowlist" in element.attrib.get("Source", "").lower()
    ]
    if retired_sources:
        fail(f"Product.wxs still sources retired allowlist file(s): {retired_sources}")
    if "SelfServicePublishDir" in (ROOT / "windows/installer/Product.wxs").read_text(encoding="utf-8"):
        fail("Product.wxs still defines the unused SelfServicePublishDir variable")

    wix_references = project_items(ROOT / "windows/installer/Patched.wixproj", "ProjectReference", "Include")
    if "../src/SelfService/SelfService.csproj" in wix_references:
        fail("Patched.wixproj still builds the legacy Self Service project")

    # PAT-1777: the MSI build steps, including the File table assertion, live
    # in one composite action that the release workflow and the pull request
    # MSI check both call.
    workflow = (ROOT / ".github/workflows/windows-agent-release.yml").read_text(encoding="utf-8")
    action = (ROOT / ".github/actions/windows-agent-msi/action.yml").read_text(encoding="utf-8")
    if "uses: ./.github/actions/windows-agent-msi" not in workflow:
        fail("release workflow no longer builds through the shared windows-agent-msi action")
    for name, text in (("release workflow", workflow), ("windows-agent-msi action", action)):
        if "Publish Self Service" in text:
            fail(f"{name} still publishes Self Service")
        if "QuarantinedRunners" in text:
            fail(f"{name} references the non-shipping quarantined-runner target")
    for required in (
        '$expected = @("Patched.Service.exe")',
        '$fileNames | Where-Object { $_ -notin $expected }',
    ):
        if required not in action:
            fail(f"windows-agent-msi action assertion is missing expected artifact contract: {required}")
    if "../src/Tray/Tray.csproj" in wix_references:
        fail("Patched.wixproj still builds the retired tray")
    if {"TrayBinary", "TrayAutoStart"} & feature_groups:
        fail("ProductFeature still packages the retired tray or its logon startup")

    print("PASS: Windows assurance-only build and MSI payload seam is intact")


if __name__ == "__main__":
    main()
