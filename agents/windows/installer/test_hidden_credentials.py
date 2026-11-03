#!/usr/bin/env python3
"""Regression guard: the MSI accepts one credential and never logs it (PAT-1755).

Andy's ruling, 2026-09-15: an installer accepts an enrolment token and nothing else,
and the token is written from a deferred custom action with HideTarget="yes" rather
than from a WiX RegistryValue, so it never reaches a verbose install log.

Two separate masking mechanisms, easy to confuse:

  * Property/@Hidden="yes" lists a property in MsiHiddenProperties. Windows Installer
    then masks its value as ********** on the "Command Line:" entry, on every
    "PROPERTY CHANGE" entry and in the closing "Property(S)" dump. Secure="yes" masks
    nothing: it only lets the value cross from the client to the elevated server
    process.
  * CustomAction/@HideTarget="yes" (msidbCustomActionTypeHideTarget) masks a custom
    action's target, which for a deferred EXE action is its command line. It is the
    only mechanism that suppresses an execute-script op's own data. Hidden does not:
    a verbose log of a bare upgrade contained
      Executing op: RegAddValue(Name=EnrollmentToken,Value=<token>,)
    even with ENROLLMENT_TOKEN Hidden (WIN-STAGING, 2026-09-15), which is why the
    registry write was replaced by the custom action this file guards.

This guard parses Product.wxs and fails when:
  * ENROLLMENT_TOKEN is not declared Secure="yes" Hidden="yes";
  * a raw-credential property (TENANT_ID, BEARER_TOKEN, HMAC_SECRET) is declared,
    referenced or conditioned on anywhere, which is how the removed install path
    would come back;
  * a SetProperty or a property-setting CustomAction builds a value (typically
    deferred CustomActionData) from the token without the receiving property also
    being declared Hidden="yes";
  * a CustomAction passes the token through its Target/ExeCommand without
    HideTarget="yes";
  * any other authored attribute or element text references the token, which now has
    no reviewed exceptions at all: a RegistryValue, File or IniFile write would be
    logged by the op that performs it.

It guards the provisioning custom action itself (PAT-1755) and fails when:
  * WriteEnrollmentToken stops being a single deferred, non-impersonated,
    HideTarget="yes", Return="check" EXE action on the installed service binary
    running the --write-enrollment-token flag the service parses with the token as
    its argument;
  * it stops being scheduled exactly once, After="InstallFiles" (before
    InstallServices and StartServices, with the binary already on disk);
  * its condition loses ENROLLMENT_TOKEN (a bare install or self-update would run it)
    or NOT Installed (a repair would rewrite the token), or gains any other term.

It guards the uninstall credential purge (PAT-1764) and fails when:
  * the PurgeAgentCredentials custom action stops being a deferred, non-impersonated,
    Return="ignore" EXE action on the installed service binary with the
    --purge-credentials flag the service parses;
  * its InstallExecuteSequence condition loses REMOVE~="ALL", NOT UPGRADINGPRODUCTCODE
    (a self-update would wipe the device identity) or NOT PATCHED_RETAIN_CREDENTIALS
    (a purge=false decommission would lose credentials), or gains any other term.

It guards the registry provisioning key (PAT-1764) and fails when:
  * this package authors any write under HKLM\\SOFTWARE\\Patched\\Enrollment. Nothing
    should: the token goes to the credential file store. Anything re-added there must
    still carry a protected PermissionEx Sddl granting only SYSTEM and Administrators,
    so that check stays live and is exercised against fixtures.

And it guards the unconsumed-token carry-over across a major upgrade (PAT-1766),
which now needs no AppSearch machinery because the token file belongs to no
component, failing when:
  * any AppSearch machinery (a Property carrying a RegistrySearch, or a SetProperty
    onto ENROLLMENT_TOKEN) comes back, which would mean the token is component-owned
    again;
  * CompCredsDir stops being a bare CreateFolder component, or gains a RemoveFile or
    RemoveFolder that would let the old product's removal sweep the token file;
  * the MajorUpgrade stops removing the old product before this one installs.
"""

from __future__ import annotations

import re
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


INSTALLER = Path(__file__).resolve().parent
PRODUCT_WXS = INSTALLER / "Product.wxs"
WIX = "{http://wixtoolset.org/schemas/v4/wxs}"
UTIL = "{http://wixtoolset.org/schemas/v4/wxs/util}"

TOKEN_PROPERTY = "ENROLLMENT_TOKEN"

# PAT-1755: the only credential the installer accepts. Every other secret property was
# removed rather than hidden.
SECRET_PROPERTIES = (TOKEN_PROPERTY,)

# The removed raw-credential install path. These must not come back in any form: a
# Property declaration, a [NAME] reference, or a condition that gates something on one.
RAW_CREDENTIAL_PROPERTIES = ("TENANT_ID", "BEARER_TOKEN", "HMAC_SECRET")

# Formatted-string references such as [ENROLLMENT_TOKEN]. Condition text uses the
# bare name, which never logs a value, so conditions are deliberately ignored here and
# checked separately for the raw-credential names.
SECRET_REFERENCE = re.compile(r"\[(" + "|".join(SECRET_PROPERTIES) + r")\]")
RAW_CREDENTIAL_REFERENCE = re.compile(r"\[(" + "|".join(RAW_CREDENTIAL_PROPERTIES) + r")\]")
RAW_CREDENTIAL_WORD = re.compile(r"\b(" + "|".join(RAW_CREDENTIAL_PROPERTIES) + r")\b")

# Attributes that only evaluate a condition; they never carry a value into a log.
CONDITION_ATTRIBUTES = {"Condition"}

# PAT-1755: deliberately empty. Every previous exception was a registry write whose
# RegAddValue op logged the token, which is exactly what this ticket removed. A new
# entry here would be a new clear-text exposure and needs its own review.
ALLOWED_REGISTRY_REFERENCES: dict[tuple[str, str], str] = {}


def load(path: Path = PRODUCT_WXS) -> ET.Element:
    return ET.parse(path).getroot()


def is_yes(value: str | None) -> bool:
    return (value or "").strip().lower() == "yes"


def hidden_properties(root: ET.Element) -> set[str]:
    return {
        prop.get("Id", "")
        for prop in root.iter(f"{WIX}Property")
        if is_yes(prop.get("Hidden"))
    }


def references_secret(value: str | None) -> bool:
    return bool(value and SECRET_REFERENCE.search(value))


def violations(root: ET.Element) -> list[str]:
    problems: list[str] = []
    hidden = hidden_properties(root)
    declared = {prop.get("Id", ""): prop for prop in root.iter(f"{WIX}Property")}

    for name in SECRET_PROPERTIES:
        prop = declared.get(name)
        if prop is None:
            problems.append(f"Property {name} is not declared in Product.wxs")
            continue
        if name not in hidden:
            problems.append(
                f'Property {name} is not Hidden="yes": its value will be written to verbose MSI logs'
            )
        if not is_yes(prop.get("Secure")):
            problems.append(
                f'Property {name} is not Secure="yes": the value cannot reach the elevated execute '
                "sequence, so the deferred provisioning action would receive nothing"
            )

    # The removed raw-credential install path must not reappear.
    for name in RAW_CREDENTIAL_PROPERTIES:
        if name in declared:
            problems.append(
                f"Property {name} is declared: the raw-credential install path was removed in "
                "PAT-1755 and the installer accepts only ENROLLMENT_TOKEN"
            )
    for element in root.iter():
        for attribute, value in element.attrib.items():
            pattern = RAW_CREDENTIAL_WORD if attribute in CONDITION_ATTRIBUTES else RAW_CREDENTIAL_REFERENCE
            match = pattern.search(value or "")
            if match:
                tag = element.tag.replace(WIX, "").replace(UTIL, "util:")
                problems.append(
                    f"{tag} attribute {attribute} references the removed raw credential {match.group(1)}"
                )

    # SetProperty Id="X" Value="...[SECRET]..." sets property X, which for a
    # deferred custom action named X becomes its CustomActionData.
    for setter in root.iter(f"{WIX}SetProperty"):
        target = setter.get("Id", "")
        if references_secret(setter.get("Value")) and target not in hidden:
            problems.append(
                f'SetProperty {target} carries a secret; declare <Property Id="{target}" Hidden="yes" />'
            )

    for action in root.iter(f"{WIX}CustomAction"):
        action_id = action.get("Id", "")
        # Type 51: CustomAction Property="X" Value="...[SECRET]...".
        target = action.get("Property")
        if target and references_secret(action.get("Value")) and target not in hidden:
            problems.append(
                f'CustomAction {action_id} sets {target} from a secret; declare <Property Id="{target}" Hidden="yes" />'
            )
        for attribute in ("Target", "ExeCommand", "JScriptCall", "VBScriptCall", "DllEntry"):
            if references_secret(action.get(attribute)) and not is_yes(action.get("HideTarget")):
                problems.append(
                    f'CustomAction {action_id} passes a secret in {attribute} without HideTarget="yes"'
                )

    # Anything else that formats a secret into authored data is new exposure and
    # needs a deliberate review, so it fails until it is added above.
    handled = {f"{WIX}SetProperty", f"{WIX}CustomAction", f"{WIX}Property"}
    for element in root.iter():
        if element.tag in handled:
            continue
        for attribute, value in element.attrib.items():
            if attribute in CONDITION_ATTRIBUTES or not references_secret(value):
                continue
            if element.tag == f"{WIX}RegistryValue":
                key = (element.get("Key", ""), element.get("Name", ""))
                if ALLOWED_REGISTRY_REFERENCES.get(key) == value and attribute == "Value":
                    continue
            tag = element.tag.replace(WIX, "").replace(UTIL, "util:")
            problems.append(f"{tag} attribute {attribute} references a secret outside the reviewed set: {value}")
        if element.text and references_secret(element.text):
            tag = element.tag.replace(WIX, "").replace(UTIL, "util:")
            problems.append(f"{tag} element text references a secret outside the reviewed set")

    return problems


# ── Shared helpers for the custom-action guards ─────────────────────────────

WINDOWS = INSTALLER.parent
SERVICE_ENTRY_POINT = WINDOWS / "src" / "Service" / "ServiceEntryPoint.cs"
DECOMMISSION_SCRIPT = WINDOWS / "src" / "Service" / "DecommissionHandoffScript.cs"

SERVICE_EXE_FILE_ID = "PatchedServiceExe"
SCRIPT_ATTRIBUTES = ("DllEntry", "BinaryRef", "JScriptCall", "VBScriptCall", "Script")


def csharp_const(path: Path, name: str) -> str:
    match = re.search(rf'const\s+string\s+{name}\s*=\s*"([^"]+)"', path.read_text(encoding="utf-8"))
    if not match:
        raise AssertionError(f"{name} not found in {path.name}")
    return match.group(1)


def single_action(root: ET.Element, action_id: str) -> tuple[ET.Element | None, list[str]]:
    actions = [a for a in root.iter(f"{WIX}CustomAction") if a.get("Id") == action_id]
    if len(actions) != 1:
        return None, [f"expected exactly one CustomAction {action_id}, found {len(actions)}"]
    return actions[0], []


def action_attribute_problems(action: ET.Element, action_id: str, expected: dict[str, str]) -> list[str]:
    problems = [
        f'CustomAction {action_id} {attribute} must be "{value}", got {action.get(attribute)!r}'
        for attribute, value in expected.items()
        if (action.get(attribute) or "").strip() != value
    ]
    problems += [
        f"CustomAction {action_id} must not use {attribute} (no DLL or script custom actions, PAT-599)"
        for attribute in SCRIPT_ATTRIBUTES
        if action.get(attribute) is not None
    ]
    return problems


def scheduled_custom(root: ET.Element, action_id: str) -> tuple[ET.Element | None, list[str]]:
    scheduled = [
        c for seq in root.iter(f"{WIX}InstallExecuteSequence")
        for c in seq.iter(f"{WIX}Custom") if c.get("Action") == action_id
    ]
    if len(scheduled) != 1:
        return None, [f"expected {action_id} scheduled once in InstallExecuteSequence, found {len(scheduled)}"]
    return scheduled[0], []


def and_condition_problems(action_id: str, condition: str, required: list[str]) -> list[str]:
    """The condition must be a plain AND of exactly the required terms, nothing else."""
    problems: list[str] = []
    condition = " ".join(condition.split())
    if re.search(r"\bOR\b|\bXOR\b|\bEQV\b|\bIMP\b|[()]", condition, re.IGNORECASE):
        problems.append(f"{action_id} condition must be a plain AND of required terms: {condition!r}")
    terms = [t.strip() for t in re.split(r"\bAND\b", condition, flags=re.IGNORECASE)]
    for term in required:
        if term not in terms:
            problems.append(f"{action_id} condition is missing {term}: {condition!r}")
    for term in terms:
        if term not in required:
            problems.append(f"{action_id} condition has an unreviewed term {term!r}")
    return problems


# ── PAT-1755: enrolment-token provisioning custom action ────────────────────

PROVISION_ACTION_ID = "WriteEnrollmentToken"
REQUIRED_PROVISION_TERMS = [TOKEN_PROPERTY, "NOT Installed"]
# InstallFiles is before InstallServices and StartServices, and puts the service binary
# the action runs on disk first.
PROVISION_AFTER = "InstallFiles"


def provision_problems(root: ET.Element, provision_flag: str | None = None) -> list[str]:
    provision_flag = provision_flag or csharp_const(SERVICE_ENTRY_POINT, "WriteEnrollmentTokenFlag")
    action, problems = single_action(root, PROVISION_ACTION_ID)
    if action is None:
        return problems

    problems += action_attribute_problems(action, PROVISION_ACTION_ID, {
        "FileRef": SERVICE_EXE_FILE_ID,
        # The token is the argument after the flag, quoted so a value with a space could
        # never split into two arguments.
        "ExeCommand": f'{provision_flag} "[{TOKEN_PROPERTY}]"',
        "Execute": "deferred",
        "Impersonate": "no",
        "HideTarget": "yes",
        # Return="check" and not "ignore": an install handed a token that could not be
        # provisioned must fail rather than leave a device that can never enrol.
        "Return": "check",
    })

    custom, scheduling = scheduled_custom(root, PROVISION_ACTION_ID)
    problems += scheduling
    if custom is None:
        return problems

    if custom.get("After") != PROVISION_AFTER:
        problems.append(
            f'{PROVISION_ACTION_ID} must be scheduled After="{PROVISION_AFTER}", so the service binary '
            f"exists and the token is written before StartServices, got {custom.get('After')!r}"
        )
    if custom.get("Before") is not None:
        problems.append(f"{PROVISION_ACTION_ID} must not also set Before")
    problems += and_condition_problems(
        PROVISION_ACTION_ID, custom.get("Condition") or "", REQUIRED_PROVISION_TERMS)
    return problems


# ── PAT-1764: uninstall credential purge ────────────────────────────────────

PURGE_ACTION_ID = "PurgeAgentCredentials"
ENROLLMENT_KEY = "SOFTWARE\\Patched\\Enrollment"
REQUIRED_PURGE_TERMS = ('REMOVE~="ALL"', "NOT UPGRADINGPRODUCTCODE")
# Only SYSTEM (SY) and BUILTIN\Administrators (BA) may hold an ACE on the key.
ALLOWED_ACL_TRUSTEES = {"SY", "BA"}
ACE = re.compile(r"\(([^)]*)\)")


def purge_problems(
    root: ET.Element,
    purge_flag: str | None = None,
    retain_property: str | None = None,
) -> list[str]:
    purge_flag = purge_flag or csharp_const(SERVICE_ENTRY_POINT, "PurgeCredentialsFlag")
    retain_property = retain_property or csharp_const(DECOMMISSION_SCRIPT, "RetainCredentialsMsiProperty")

    action, problems = single_action(root, PURGE_ACTION_ID)
    if action is None:
        return problems

    problems += action_attribute_problems(action, PURGE_ACTION_ID, {
        "FileRef": SERVICE_EXE_FILE_ID,
        "ExeCommand": purge_flag,
        "Execute": "deferred",
        "Impersonate": "no",
        "Return": "ignore",
    })

    custom, scheduling = scheduled_custom(root, PURGE_ACTION_ID)
    problems += scheduling
    if custom is None:
        return problems

    if custom.get("Before") != "RemoveFiles":
        problems.append(f'{PURGE_ACTION_ID} must be scheduled Before="RemoveFiles" while the binary still exists')
    problems += and_condition_problems(
        PURGE_ACTION_ID, custom.get("Condition") or "",
        list(REQUIRED_PURGE_TERMS) + [f"NOT {retain_property}"])

    declared = {p.get("Id"): p for p in root.iter(f"{WIX}Property")}
    retain = declared.get(retain_property)
    if retain is None or not is_yes(retain.get("Secure")):
        problems.append(f'Property {retain_property} must be declared Secure="yes"')
    return problems


def sddl_problems(sddl: str | None) -> list[str]:
    if not sddl:
        return ["no Sddl"]
    problems: list[str] = []
    if not sddl.startswith("D:P"):
        problems.append(f"DACL is not protected (must start D:P, so HKLM\\SOFTWARE's Users read is not inherited): {sddl}")
    if "S:" in sddl:
        problems.append(f"unexpected SACL in {sddl}")
    aces = ACE.findall(sddl)
    if not aces:
        problems.append(f"no ACEs in {sddl}")
    trustees = set()
    for ace in aces:
        fields = ace.split(";")
        if len(fields) != 6 or fields[0] != "A":
            problems.append(f"unexpected ACE ({ace}) in {sddl}")
            continue
        trustees.add(fields[5])
        if fields[5] not in ALLOWED_ACL_TRUSTEES:
            problems.append(f"ACE grants {fields[5]}; only SYSTEM and Administrators may access the key: {sddl}")
    for trustee in ALLOWED_ACL_TRUSTEES - trustees:
        problems.append(f"no ACE for {trustee} in {sddl}")
    return problems


def enrollment_registry_elements(root: ET.Element) -> list[ET.Element]:
    return [
        e for tag in ("RegistryValue", "RegistryKey") for e in root.iter(f"{WIX}{tag}")
        if e.get("Root") == "HKLM" and (e.get("Key") or "").rstrip("\\").lower() == ENROLLMENT_KEY.lower()
    ]


def registry_provisioning_problems(root: ET.Element) -> list[str]:
    """PAT-1755: this package writes nothing under the Enrollment key. If something is
    ever re-added there it must still carry the protected PermissionEx Sddl, so both
    rules are checked rather than the presence check replacing the ACL check."""
    problems: list[str] = []
    for element in enrollment_registry_elements(root):
        name = element.get("Name") or element.get("Key")
        problems.append(
            f"{name}: this package must not write under HKLM\\{ENROLLMENT_KEY}; the enrolment token goes "
            "to the credential file store from a HideTarget custom action, because a registry op logs its value"
        )
        if list(element.iter(f"{UTIL}PermissionEx")):
            problems.append(
                f"{name}: util:PermissionEx merges into the inherited DACL (Users keep read); use PermissionEx Sddl"
            )
        perms = [p for p in element if p.tag == f"{WIX}PermissionEx"]
        if len(perms) != 1:
            problems.append(f"{name}: expected one PermissionEx Sddl child, found {len(perms)}")
            continue
        problems.extend(f"{name}: {p}" for p in sddl_problems(perms[0].get("Sddl")))
    return problems


# ── PAT-1766: an unconsumed token survives a major upgrade ──────────────────
#
# It survives because nothing in this package owns the token file: RemoveFiles only
# removes rows in the File table and RemoveFolders leaves a non-empty directory. So the
# guard is the absence of component ownership and of the AppSearch machinery that only
# existed because the token used to be a component-owned registry value.

CREDS_COMPONENT_ID = "CompCredsDir"
CREDS_DIRECTORY_ID = "CREDSDIR"


def upgrade_token_problems(root: ET.Element) -> list[str]:
    problems: list[str] = []

    for prop in root.iter(f"{WIX}Property"):
        if list(prop.iter(f"{WIX}RegistrySearch")):
            problems.append(
                f"Property {prop.get('Id')} carries a RegistrySearch: the AppSearch carry-over was removed "
                "in PAT-1755 because the token file is no longer component-owned, and AppSearch on a "
                "credential is exposure with nothing to preserve"
            )
    for setter in root.iter(f"{WIX}SetProperty"):
        if setter.get("Id") == TOKEN_PROPERTY:
            problems.append(
                f"SetProperty onto {TOKEN_PROPERTY} ({setter.get('Action')}) copies a token between "
                "properties; nothing needs to since the token file survives RemoveExistingProducts"
            )

    components = [c for c in root.iter(f"{WIX}Component") if c.get("Id") == CREDS_COMPONENT_ID]
    if len(components) != 1:
        problems.append(f"expected exactly one Component {CREDS_COMPONENT_ID}, found {len(components)}")
    else:
        component = components[0]
        if component.get("Directory") != CREDS_DIRECTORY_ID:
            problems.append(
                f'{CREDS_COMPONENT_ID} must stay in Directory="{CREDS_DIRECTORY_ID}", '
                f"got {component.get('Directory')!r}"
            )
        children = {child.tag.replace(WIX, "") for child in component}
        if children != {"CreateFolder"}:
            problems.append(
                f"{CREDS_COMPONENT_ID} must declare only CreateFolder so no file under creds is "
                f"component-owned, found {sorted(children)}"
            )
        for tag in ("RemoveFile", "RemoveFolder"):
            if list(component.iter(f"{WIX}{tag}")):
                problems.append(
                    f"{CREDS_COMPONENT_ID} must not carry {tag}: the old product's removal during a major "
                    "upgrade would sweep an unconsumed enrolment token (PAT-1766)"
                )

    upgrades = list(root.iter(f"{WIX}MajorUpgrade"))
    if len(upgrades) != 1:
        problems.append(f"expected exactly one MajorUpgrade, found {len(upgrades)}")
    elif upgrades[0].get("Schedule") != "afterInstallInitialize":
        problems.append(
            'MajorUpgrade must stay Schedule="afterInstallInitialize"; the token carry-over is reasoned '
            "about as remove-then-install"
        )
    return problems


# ── Tests against the real Product.wxs ─────────────────────────────────────


class ProductWxsTests(unittest.TestCase):
    def test_only_the_enrolment_token_is_accepted_and_it_is_hidden(self) -> None:
        self.assertEqual(violations(load()), [])

    def test_provisioning_action_hides_the_token_and_fails_closed(self) -> None:
        self.assertEqual(provision_problems(load()), [])

    def test_purge_action_is_full_uninstall_only(self) -> None:
        self.assertEqual(purge_problems(load()), [])

    def test_nothing_is_written_under_the_enrollment_registry_key(self) -> None:
        self.assertEqual(registry_provisioning_problems(load()), [])

    def test_unconsumed_token_is_not_component_owned(self) -> None:
        self.assertEqual(upgrade_token_problems(load()), [])

    def test_raw_credential_properties_are_not_secrets_to_hide_but_absentees(self) -> None:
        # The previous guard hid BEARER_TOKEN and HMAC_SECRET. PAT-1755 removed them, so
        # they must not be in the set of properties this file expects to exist.
        for name in RAW_CREDENTIAL_PROPERTIES:
            self.assertNotIn(name, SECRET_PROPERTIES)

    def test_guard_is_reading_the_real_file(self) -> None:
        # A parse that silently produced an empty tree would make every assertion above
        # pass vacuously.
        root = load()
        self.assertEqual(TOKEN_PROPERTY, next(
            p.get("Id") for p in root.iter(f"{WIX}Property") if p.get("Id") == TOKEN_PROPERTY))
        self.assertIsNotNone(single_action(root, PROVISION_ACTION_ID)[0])
        self.assertIsNotNone(single_action(root, PURGE_ACTION_ID)[0])


# ── Regression detection: write each defect back and prove the guard is red ──


def mutated(transform) -> ET.Element:
    root = load()
    transform(root)
    return root


def all_problems(root: ET.Element) -> list[str]:
    return (violations(root) + provision_problems(root) + purge_problems(root)
            + registry_provisioning_problems(root) + upgrade_token_problems(root))


def action(root: ET.Element, action_id: str) -> ET.Element:
    return next(a for a in root.iter(f"{WIX}CustomAction") if a.get("Id") == action_id)


def custom(root: ET.Element, action_id: str) -> ET.Element:
    return next(c for c in root.iter(f"{WIX}Custom") if c.get("Action") == action_id)


def package(root: ET.Element) -> ET.Element:
    return next(root.iter(f"{WIX}Package"))


class GuardDetectsRegressionsInTheRealFileTests(unittest.TestCase):
    def assert_red(self, root: ET.Element, fragment: str) -> None:
        problems = all_problems(root)
        self.assertTrue(any(fragment in p for p in problems), problems)

    # ── the token property itself ──
    def test_token_losing_hidden_fails(self) -> None:
        def unhide(r: ET.Element) -> None:
            next(p for p in r.iter(f"{WIX}Property") if p.get("Id") == TOKEN_PROPERTY).set("Hidden", "no")
        self.assert_red(mutated(unhide), 'not Hidden="yes"')

    def test_token_losing_secure_fails(self) -> None:
        def insecure(r: ET.Element) -> None:
            del next(p for p in r.iter(f"{WIX}Property") if p.get("Id") == TOKEN_PROPERTY).attrib["Secure"]
        self.assert_red(mutated(insecure), 'not Secure="yes"')

    # ── the removed raw-credential path coming back ──
    def test_raw_credential_property_returning_fails(self) -> None:
        def readd(r: ET.Element) -> None:
            ET.SubElement(package(r), f"{WIX}Property", {"Id": "BEARER_TOKEN", "Secure": "yes", "Hidden": "yes"})
        self.assert_red(mutated(readd), "Property BEARER_TOKEN is declared")

    def test_raw_credential_reference_returning_fails(self) -> None:
        def readd(r: ET.Element) -> None:
            component = ET.SubElement(package(r), f"{WIX}Component")
            ET.SubElement(component, f"{WIX}RegistryValue", {
                "Root": "HKLM", "Key": ENROLLMENT_KEY, "Name": "HmacSecret",
                "Value": "[HMAC_SECRET]", "Type": "string"})
        self.assert_red(mutated(readd), "removed raw credential HMAC_SECRET")

    def test_raw_credential_condition_returning_fails(self) -> None:
        def readd(r: ET.Element) -> None:
            ET.SubElement(package(r), f"{WIX}Component", {"Condition": "TENANT_ID AND NOT Installed"})
        self.assert_red(mutated(readd), "removed raw credential TENANT_ID")

    # ── the provisioning action ──
    def test_provision_losing_hide_target_fails(self) -> None:
        self.assert_red(mutated(lambda r: action(r, PROVISION_ACTION_ID).set("HideTarget", "no")), "HideTarget")

    def test_provision_dropping_hide_target_attribute_fails(self) -> None:
        def drop(r: ET.Element) -> None:
            del action(r, PROVISION_ACTION_ID).attrib["HideTarget"]
        # Both the shape guard and the secret guard must catch it.
        self.assert_red(mutated(drop), "HideTarget")
        self.assertTrue(any("passes a secret in ExeCommand" in p for p in violations(mutated(drop))))

    def test_provision_ignoring_failures_fails(self) -> None:
        self.assert_red(mutated(lambda r: action(r, PROVISION_ACTION_ID).set("Return", "ignore")), "Return")

    def test_provision_impersonating_fails(self) -> None:
        self.assert_red(mutated(lambda r: action(r, PROVISION_ACTION_ID).set("Impersonate", "yes")), "Impersonate")

    def test_provision_immediate_fails(self) -> None:
        self.assert_red(mutated(lambda r: action(r, PROVISION_ACTION_ID).set("Execute", "immediate")), "Execute")

    def test_provision_dll_action_fails(self) -> None:
        self.assert_red(
            mutated(lambda r: action(r, PROVISION_ACTION_ID).set("DllEntry", "WriteCredentials")), "DllEntry")

    def test_provision_wrong_flag_fails(self) -> None:
        self.assert_red(
            mutated(lambda r: action(r, PROVISION_ACTION_ID).set("ExeCommand", '--provision "[ENROLLMENT_TOKEN]"')),
            "ExeCommand")

    def test_provision_scheduled_after_start_services_fails(self) -> None:
        self.assert_red(mutated(lambda r: custom(r, PROVISION_ACTION_ID).set("After", "StartServices")), "After")

    def test_provision_running_on_a_repair_fails(self) -> None:
        self.assert_red(
            mutated(lambda r: custom(r, PROVISION_ACTION_ID).set("Condition", "ENROLLMENT_TOKEN")),
            "missing NOT Installed")

    def test_provision_running_without_a_token_fails(self) -> None:
        self.assert_red(
            mutated(lambda r: custom(r, PROVISION_ACTION_ID).set("Condition", "NOT Installed")),
            "missing ENROLLMENT_TOKEN")

    def test_provision_or_bypass_fails(self) -> None:
        self.assert_red(
            mutated(lambda r: custom(r, PROVISION_ACTION_ID).set(
                "Condition", "ENROLLMENT_TOKEN AND NOT Installed OR Privileged")),
            "plain AND")

    def test_provision_extra_term_fails(self) -> None:
        self.assert_red(
            mutated(lambda r: custom(r, PROVISION_ACTION_ID).set(
                "Condition", "ENROLLMENT_TOKEN AND NOT Installed AND Privileged")),
            "unreviewed term")

    # ── the purge action ──
    def test_purge_missing_upgrade_guard_fails(self) -> None:
        self.assert_red(
            mutated(lambda r: custom(r, PURGE_ACTION_ID).set(
                "Condition", 'REMOVE~="ALL" AND NOT PATCHED_RETAIN_CREDENTIALS')),
            "NOT UPGRADINGPRODUCTCODE")

    def test_purge_missing_full_uninstall_guard_fails(self) -> None:
        self.assert_red(
            mutated(lambda r: custom(r, PURGE_ACTION_ID).set(
                "Condition", "NOT UPGRADINGPRODUCTCODE AND NOT PATCHED_RETAIN_CREDENTIALS")),
            'REMOVE~="ALL"')

    def test_purge_missing_retain_guard_fails(self) -> None:
        self.assert_red(
            mutated(lambda r: custom(r, PURGE_ACTION_ID).set(
                "Condition", 'REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE')),
            "NOT PATCHED_RETAIN_CREDENTIALS")

    def test_purge_or_bypass_fails(self) -> None:
        self.assert_red(
            mutated(lambda r: custom(r, PURGE_ACTION_ID).set(
                "Condition",
                'REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE AND NOT PATCHED_RETAIN_CREDENTIALS OR Installed')),
            "plain AND")

    def test_purge_impersonated_action_fails(self) -> None:
        self.assert_red(mutated(lambda r: action(r, PURGE_ACTION_ID).set("Impersonate", "yes")), "Impersonate")

    def test_purge_blocking_return_fails(self) -> None:
        self.assert_red(mutated(lambda r: action(r, PURGE_ACTION_ID).set("Return", "check")), "Return")

    # ── registry provisioning coming back ──
    def test_token_registry_write_returning_fails(self) -> None:
        def readd(r: ET.Element) -> None:
            component = ET.SubElement(package(r), f"{WIX}Component")
            value = ET.SubElement(component, f"{WIX}RegistryValue", {
                "Root": "HKLM", "Key": ENROLLMENT_KEY, "Name": "EnrollmentToken",
                "Value": f"[{TOKEN_PROPERTY}]", "Type": "string"})
            ET.SubElement(value, f"{WIX}PermissionEx", {"Sddl": "D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)"})
        root = mutated(readd)
        # Both halves must fire: the registry surface is gone, and even a correctly
        # ACL'd write would leak the token through its RegAddValue op.
        self.assert_red(root, "must not write under HKLM")
        self.assertTrue(any("references a secret outside the reviewed set" in p for p in violations(root)))

    def test_unprotected_dacl_on_a_readded_write_fails(self) -> None:
        def readd(r: ET.Element) -> None:
            component = ET.SubElement(package(r), f"{WIX}Component")
            value = ET.SubElement(component, f"{WIX}RegistryValue", {
                "Root": "HKLM", "Key": ENROLLMENT_KEY, "Name": "Marker", "Value": "1", "Type": "string"})
            ET.SubElement(value, f"{WIX}PermissionEx", {"Sddl": "D:(A;CI;KA;;;SY)(A;CI;KA;;;BA)"})
        self.assert_red(mutated(readd), "not protected")

    def test_users_read_ace_on_a_readded_write_fails(self) -> None:
        def readd(r: ET.Element) -> None:
            component = ET.SubElement(package(r), f"{WIX}Component")
            value = ET.SubElement(component, f"{WIX}RegistryValue", {
                "Root": "HKLM", "Key": ENROLLMENT_KEY, "Name": "Marker", "Value": "1", "Type": "string"})
            ET.SubElement(value, f"{WIX}PermissionEx", {
                "Sddl": "D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)"})
        self.assert_red(mutated(readd), "grants BU")

    def test_missing_permission_on_a_readded_write_fails(self) -> None:
        def readd(r: ET.Element) -> None:
            component = ET.SubElement(package(r), f"{WIX}Component")
            ET.SubElement(component, f"{WIX}RegistryValue", {
                "Root": "HKLM", "Key": ENROLLMENT_KEY, "Name": "Marker", "Value": "1", "Type": "string"})
        self.assert_red(mutated(readd), "Marker: expected one PermissionEx")

    def test_util_permission_on_a_readded_write_fails(self) -> None:
        def readd(r: ET.Element) -> None:
            component = ET.SubElement(package(r), f"{WIX}Component")
            value = ET.SubElement(component, f"{WIX}RegistryValue", {
                "Root": "HKLM", "Key": ENROLLMENT_KEY, "Name": "Marker", "Value": "1", "Type": "string"})
            ET.SubElement(value, f"{UTIL}PermissionEx", {"User": "SYSTEM", "GenericAll": "yes"})
        self.assert_red(mutated(readd), "merges into the inherited DACL")

    # ── the upgrade carry-over ──
    def test_appsearch_machinery_returning_fails(self) -> None:
        def readd(r: ET.Element) -> None:
            prop = ET.SubElement(package(r), f"{WIX}Property", {"Id": "PATCHEDEXISTINGTOKEN", "Hidden": "yes"})
            ET.SubElement(prop, f"{WIX}RegistrySearch", {
                "Id": "S", "Root": "HKLM", "Key": ENROLLMENT_KEY, "Name": "EnrollmentToken",
                "Type": "raw", "Bitness": "always64"})
        self.assert_red(mutated(readd), "carries a RegistrySearch")

    def test_set_property_onto_the_token_returning_fails(self) -> None:
        def readd(r: ET.Element) -> None:
            ET.SubElement(package(r), f"{WIX}SetProperty", {
                "Id": TOKEN_PROPERTY, "Action": "Preserve", "Value": "[SOMETHING]",
                "After": "AppSearch", "Sequence": "both"})
        self.assert_red(mutated(readd), f"SetProperty onto {TOKEN_PROPERTY}")

    def test_component_owned_file_under_creds_fails(self) -> None:
        def own(r: ET.Element) -> None:
            component = next(c for c in r.iter(f"{WIX}Component") if c.get("Id") == CREDS_COMPONENT_ID)
            ET.SubElement(component, f"{WIX}RemoveFile", {"Id": "Sweep", "Name": "enrollment-token", "On": "uninstall"})
        self.assert_red(mutated(own), "must not carry RemoveFile")

    def test_creds_component_gaining_another_child_fails(self) -> None:
        def own(r: ET.Element) -> None:
            component = next(c for c in r.iter(f"{WIX}Component") if c.get("Id") == CREDS_COMPONENT_ID)
            ET.SubElement(component, f"{WIX}File", {"Id": "Token", "Name": "enrollment-token", "Source": "x"})
        self.assert_red(mutated(own), "must declare only CreateFolder")

    def test_major_upgrade_schedule_change_fails(self) -> None:
        self.assert_red(
            mutated(lambda r: next(r.iter(f"{WIX}MajorUpgrade")).set("Schedule", "afterInstallFinalize")),
            "afterInstallInitialize")


# ── Regression detection against minimal fixtures ──────────────────────────


def wxs(body: str) -> ET.Element:
    return ET.fromstring(
        '<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"><Package>'
        f'<Property Id="{TOKEN_PROPERTY}" Secure="yes" Hidden="yes" />'
        f"{body}</Package></Wix>"
    )


class SecretGuardFixtureTests(unittest.TestCase):
    """Prove the guard goes red on each shape of the defect, not only on today's file."""

    def test_clean_fixture_passes(self) -> None:
        self.assertEqual(violations(wxs("")), [])

    def test_missing_hidden_fails(self) -> None:
        root = wxs("")
        for prop in root.iter(f"{WIX}Property"):
            if prop.get("Id") == TOKEN_PROPERTY:
                del prop.attrib["Hidden"]
        self.assertTrue(any(TOKEN_PROPERTY in p for p in violations(root)))

    def test_missing_property_fails(self) -> None:
        root = ET.fromstring('<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"><Package /></Wix>')
        self.assertTrue(any("is not declared" in p for p in violations(root)))

    def test_unhidden_custom_action_data_fails(self) -> None:
        root = wxs(
            f'<SetProperty Id="WriteToken" Value="Token=[{TOKEN_PROPERTY}]" Before="WriteToken" Sequence="execute" />')
        self.assertTrue(any("SetProperty WriteToken" in p for p in violations(root)))

    def test_hidden_custom_action_data_passes(self) -> None:
        root = wxs(
            '<Property Id="WriteToken" Hidden="yes" />'
            f'<SetProperty Id="WriteToken" Value="Token=[{TOKEN_PROPERTY}]" Before="WriteToken" Sequence="execute" />')
        self.assertEqual(violations(root), [])

    def test_type51_custom_action_fails_until_target_hidden(self) -> None:
        body = f'<CustomAction Id="SetCreds" Property="WriteToken" Value="Token=[{TOKEN_PROPERTY}]" />'
        self.assertTrue(any("CustomAction SetCreds" in p for p in violations(wxs(body))))
        self.assertEqual(violations(wxs('<Property Id="WriteToken" Hidden="yes" />' + body)), [])

    def test_exe_command_without_hide_target_fails(self) -> None:
        body = (f'<CustomAction Id="RunEnrol" Directory="INSTALLFOLDER" ExeCommand="enrol.exe [{TOKEN_PROPERTY}]" '
                'Execute="deferred" />')
        self.assertTrue(any("HideTarget" in p for p in violations(wxs(body))))
        hidden = body.replace('Execute="deferred"', 'Execute="deferred" HideTarget="yes"')
        self.assertEqual(violations(wxs(hidden)), [])

    def test_any_registry_write_of_the_token_fails(self) -> None:
        body = ('<Component><RegistryValue Root="HKLM" Key="SOFTWARE\\Patched\\Enrollment" Name="EnrollmentToken" '
                f'Value="[{TOKEN_PROPERTY}]" Type="string" /></Component>')
        self.assertTrue(any("RegistryValue" in p for p in violations(wxs(body))))

    def test_file_write_of_the_token_fails(self) -> None:
        body = f'<Component><IniFile Id="I" Name="p.ini" Section="s" Key="k" Value="[{TOKEN_PROPERTY}]" /></Component>'
        self.assertTrue(any("IniFile" in p for p in violations(wxs(body))))

    def test_conditions_on_the_token_name_are_allowed(self) -> None:
        body = f'<Component Condition="{TOKEN_PROPERTY} AND NOT Installed" />'
        self.assertEqual(violations(wxs(body)), [])

    def test_element_text_carrying_the_token_fails(self) -> None:
        body = f"<Property Id=\"Leak\">[{TOKEN_PROPERTY}]</Property><Component>[{TOKEN_PROPERTY}]</Component>"
        self.assertTrue(any("element text references a secret" in p for p in violations(wxs(body))))


class SddlFixtureTests(unittest.TestCase):
    """The protected-ACL check stays tested even though nothing in the package uses it."""

    def test_protected_system_and_admins_passes(self) -> None:
        self.assertEqual(sddl_problems("D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)"), [])

    def test_missing_sddl_fails(self) -> None:
        self.assertEqual(sddl_problems(None), ["no Sddl"])

    def test_unprotected_fails(self) -> None:
        self.assertTrue(any("not protected" in p for p in sddl_problems("D:(A;CI;KA;;;SY)(A;CI;KA;;;BA)")))

    def test_extra_trustee_fails(self) -> None:
        self.assertTrue(any("grants AU" in p for p in sddl_problems(
            "D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;AU)")))

    def test_deny_ace_fails(self) -> None:
        self.assertTrue(any("unexpected ACE" in p for p in sddl_problems(
            "D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(D;CI;KA;;;BU)")))

    def test_missing_admins_fails(self) -> None:
        self.assertTrue(any("no ACE for BA" in p for p in sddl_problems("D:P(A;CI;KA;;;SY)")))

    def test_sacl_fails(self) -> None:
        self.assertTrue(any("unexpected SACL" in p for p in sddl_problems(
            "D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)S:(AU;SA;KA;;;WD)")))


class ConditionHelperTests(unittest.TestCase):
    def test_plain_and_of_required_terms_passes(self) -> None:
        self.assertEqual(and_condition_problems("A", "X AND NOT Y", ["X", "NOT Y"]), [])

    def test_parenthesised_condition_fails(self) -> None:
        self.assertTrue(any("plain AND" in p for p in and_condition_problems("A", "(X OR Z) AND NOT Y", ["X", "NOT Y"])))

    def test_whitespace_is_normalised(self) -> None:
        self.assertEqual(and_condition_problems("A", "X\n   AND   NOT Y", ["X", "NOT Y"]), [])


class FlagsMatchTheServiceTests(unittest.TestCase):
    def test_flags_come_from_the_service_source(self) -> None:
        self.assertEqual("--purge-credentials", csharp_const(SERVICE_ENTRY_POINT, "PurgeCredentialsFlag"))
        self.assertEqual("--write-enrollment-token", csharp_const(SERVICE_ENTRY_POINT, "WriteEnrollmentTokenFlag"))

    def test_the_action_runs_the_flag_the_service_parses(self) -> None:
        # A flag renamed in one place only would leave the install silently not
        # provisioning (the service would treat it as a host start).
        exe_command = action(load(), PROVISION_ACTION_ID).get("ExeCommand") or ""
        self.assertTrue(exe_command.startswith(csharp_const(SERVICE_ENTRY_POINT, "WriteEnrollmentTokenFlag") + " "))


if __name__ == "__main__":
    result = unittest.main(exit=False, verbosity=2).result
    sys.exit(0 if result.wasSuccessful() else 1)
