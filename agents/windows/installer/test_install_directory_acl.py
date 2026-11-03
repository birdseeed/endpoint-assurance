#!/usr/bin/env python3
"""Regression guard: the MSI sets an explicit, protected ACL on its install directory (PAT-2399).

Until this ticket %ProgramFiles%\\Patched carried no ACL of its own: every entry was
inherited from Program Files, so the boundary around a LocalSystem service's executable was a
default the agent never set. Product.wxs now sets it with Windows Installer's own
MsiLockPermissionsEx (the core PermissionEx element with Sddl=), on the directory and on the
service executable. util:PermissionEx is refused here: it merges entries into the inherited
DACL and cannot protect it.

This guard parses Product.wxs and fails when either element is missing, conditional,
unprotected, or grants anyone but SYSTEM and Administrators (full control) and Users (read
and execute). It cannot prove what Windows Installer does with the table at install time;
that needs an installed device (README-install.md, "Install directory ACL").
"""

from __future__ import annotations

import re
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

INSTALLER = Path(__file__).resolve().parent
PRODUCT_WXS = INSTALLER / "Product.wxs"
GATE_TESTS = INSTALLER.parent / "tests" / "Service.Tests" / "InstallIntegrityGateTests.cs"
WIX = "{http://wixtoolset.org/schemas/v4/wxs}"
UTIL = "{http://wixtoolset.org/schemas/v4/wxs/util}"

SERVICE_FILE_ID = "PatchedServiceExe"
INSTALL_DIRECTORY_ID = "INSTALLFOLDER"
FULL = "FA"
READ_EXECUTE = "0x1200a9"
# Trustee -> the only rights it may hold. An allowlist: any other trustee or right fails.
EXPECTED_RIGHTS = {"SY": FULL, "BA": FULL, "BU": READ_EXECUTE}
ACE = re.compile(r"\(([^()]*)\)")


def load() -> ET.Element:
    return ET.parse(PRODUCT_WXS).getroot()


def sddl_problems(sddl: str | None, flags: str) -> list[str]:
    """flags: the inheritance flags every ACE must carry (OICI on the directory, none on a file)."""
    if not sddl:
        return ["no Sddl"]
    problems = []
    if not re.match(r"^D:P(AI)?\(", sddl):
        problems.append(f"DACL is not protected (must start D:P or D:PAI, or Program Files' entries are inherited): {sddl}")
    if "S:" in sddl or "O:" in sddl or "G:" in sddl:
        problems.append(f"only a DACL is expected in {sddl}")
    seen = {}
    for ace in ACE.findall(sddl):
        fields = ace.split(";")
        if len(fields) != 6 or fields[0] != "A" or fields[3] or fields[4]:
            problems.append(f"unexpected ACE ({ace})")
            continue
        _, ace_flags, rights, _, _, trustee = fields
        if trustee not in EXPECTED_RIGHTS:
            problems.append(f"ACE grants {trustee}; only SYSTEM, Administrators and Users are expected")
        elif rights.lower() != EXPECTED_RIGHTS[trustee].lower():
            problems.append(f"{trustee} holds {rights}, expected {EXPECTED_RIGHTS[trustee]}")
        if ace_flags != flags:
            problems.append(f"ACE ({ace}) has inheritance flags '{ace_flags}', expected '{flags}'")
        seen[trustee] = seen.get(trustee, 0) + 1
    for trustee in EXPECTED_RIGHTS:
        if seen.get(trustee, 0) != 1:
            problems.append(f"expected exactly one ACE for {trustee}, found {seen.get(trustee, 0)}")
    return problems


def permission_problems(name: str, element: ET.Element | None, flags: str) -> list[str]:
    if element is None:
        return [f"{name}: element not found"]
    problems = []
    if list(element.iter(f"{UTIL}PermissionEx")):
        problems.append(f"{name}: util:PermissionEx merges into the inherited DACL; use PermissionEx Sddl")
    perms = [p for p in element if p.tag == f"{WIX}PermissionEx"]
    if len(perms) != 1:
        return problems + [f"{name}: expected one PermissionEx Sddl child, found {len(perms)}"]
    if perms[0].get("Condition") is not None:
        problems.append(f"{name}: PermissionEx must be unconditional")
    return problems + [f"{name}: {p}" for p in sddl_problems(perms[0].get("Sddl"), flags)]


def install_directory_problems(root: ET.Element) -> list[str]:
    problems = []
    folder = next((d for d in root.iter(f"{WIX}Directory") if d.get("Id") == INSTALL_DIRECTORY_ID), None)
    parent = next((s for s in root.iter(f"{WIX}StandardDirectory") if folder is not None and folder in list(s)), None)
    if folder is None or parent is None or parent.get("Id") != "ProgramFiles64Folder":
        problems.append(f"{INSTALL_DIRECTORY_ID} must be declared directly under ProgramFiles64Folder")

    # The component that installs the service executable, and the directory it resolves to.
    component = file = None
    for group in root.iter(f"{WIX}ComponentGroup"):
        for candidate in group.iter(f"{WIX}Component"):
            found = next((f for f in candidate.iter(f"{WIX}File") if f.get("Id") == SERVICE_FILE_ID), None)
            if found is not None:
                component, file = candidate, found
                if (candidate.get("Directory") or group.get("Directory")) != INSTALL_DIRECTORY_ID:
                    problems.append(f"{SERVICE_FILE_ID} is not installed into {INSTALL_DIRECTORY_ID}")
    if component is None:
        return problems + [f"File {SERVICE_FILE_ID} not found in any component"]

    # In the same component as the executable, so the ACL is applied whenever the binary is
    # installed (fresh install and major upgrade) and never left behind by a feature change.
    folders = [c for c in component if c.tag == f"{WIX}CreateFolder" and c.get("Directory") in (None, INSTALL_DIRECTORY_ID)]
    problems += permission_problems("install directory CreateFolder", folders[0] if len(folders) == 1 else None, "OICI")
    problems += permission_problems(f"File {SERVICE_FILE_ID}", file, "")
    return problems


class ProductWxsTests(unittest.TestCase):
    def test_install_directory_and_executable_carry_the_explicit_protected_acl(self) -> None:
        self.assertEqual(install_directory_problems(load()), [])

    def test_windows_tests_apply_the_same_directory_sddl(self) -> None:
        # InstallIntegrityGateTests applies this SDDL to a real directory on Windows and
        # proves the service's own check accepts it. It must be the SDDL the MSI ships.
        directory = next(e for e in load().iter(f"{WIX}CreateFolder")
                         if any(p.tag == f"{WIX}PermissionEx" for p in e))
        sddl = next(p for p in directory if p.tag == f"{WIX}PermissionEx").get("Sddl")
        self.assertIn(f'"{sddl}"', GATE_TESTS.read_text(encoding="utf-8"))


class GuardDetectsRegressionsInTheRealFileTests(unittest.TestCase):
    """Write each defect back into the real Product.wxs tree and prove the guard is red."""

    def assert_red(self, transform, fragment: str) -> None:
        root = load()
        transform(root)
        problems = install_directory_problems(root)
        self.assertTrue(any(fragment in p for p in problems), problems)

    @staticmethod
    def permission(root: ET.Element, parent_tag: str) -> tuple[ET.Element, ET.Element]:
        for parent in root.iter(f"{WIX}{parent_tag}"):
            for child in parent:
                if child.tag == f"{WIX}PermissionEx" and (parent_tag != "File" or parent.get("Id") == SERVICE_FILE_ID):
                    return parent, child
        raise AssertionError(f"no PermissionEx under {parent_tag}")

    def set_sddl(self, parent_tag: str, sddl: str):
        return lambda root: self.permission(root, parent_tag)[1].set("Sddl", sddl)

    def test_removing_the_directory_permission_fails(self) -> None:
        def remove(root: ET.Element) -> None:
            parent, child = self.permission(root, "CreateFolder")
            parent.remove(child)
        self.assert_red(remove, "install directory CreateFolder: expected one PermissionEx")

    def test_removing_the_directory_createfolder_fails(self) -> None:
        def remove(root: ET.Element) -> None:
            folder, _ = self.permission(root, "CreateFolder")
            next(c for c in root.iter(f"{WIX}Component") if folder in list(c)).remove(folder)
        self.assert_red(remove, "install directory CreateFolder: element not found")

    def test_removing_the_executable_permission_fails(self) -> None:
        def remove(root: ET.Element) -> None:
            parent, child = self.permission(root, "File")
            parent.remove(child)
        self.assert_red(remove, f"File {SERVICE_FILE_ID}: expected one PermissionEx")

    def test_util_permission_instead_fails(self) -> None:
        def swap(root: ET.Element) -> None:
            parent, child = self.permission(root, "CreateFolder")
            parent.remove(child)
            ET.SubElement(parent, f"{UTIL}PermissionEx", {"User": "SYSTEM", "GenericAll": "yes"})
        self.assert_red(swap, "util:PermissionEx merges")

    def test_unprotected_dacl_fails(self) -> None:
        self.assert_red(self.set_sddl("CreateFolder", "D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"),
                        "not protected")

    def test_users_write_fails(self) -> None:
        self.assert_red(self.set_sddl("CreateFolder", "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)"),
                        "BU holds 0x1301bf")
        self.assert_red(self.set_sddl("File", "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)"), "BU holds FA")

    def test_extra_trustee_fails(self) -> None:
        self.assert_red(self.set_sddl("CreateFolder",
                        "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;FA;;;WD)"), "ACE grants WD")

    def test_missing_administrators_fails(self) -> None:
        self.assert_red(self.set_sddl("CreateFolder", "D:PAI(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)"),
                        "exactly one ACE for BA")

    def test_non_inheriting_directory_ace_fails(self) -> None:
        # Without OICI a file created in the directory would get no entries from it at all.
        self.assert_red(self.set_sddl("CreateFolder", "D:PAI(A;;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"),
                        "inheritance flags ''")

    def test_conditional_permission_fails(self) -> None:
        self.assert_red(lambda root: self.permission(root, "CreateFolder")[1].set("Condition", "NOT Installed"),
                        "must be unconditional")

    def test_executable_moved_out_of_the_install_directory_fails(self) -> None:
        def move(root: ET.Element) -> None:
            next(g for g in root.iter(f"{WIX}ComponentGroup") if g.get("Id") == "ServiceBinaries").set("Directory", "STATEROOT")
        self.assert_red(move, f"not installed into {INSTALL_DIRECTORY_ID}")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False, verbosity=1).result.wasSuccessful() else 1)
