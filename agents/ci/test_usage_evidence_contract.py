"""PAT-2328: validate metering fragments against the unmodified platform schema."""
import copy
from datetime import datetime
import json
import os
from pathlib import Path
import re
import unittest

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
MIRROR = ROOT / "contracts/inventory-payload.schema.json"
CANONICAL = json.loads(MIRROR.read_text())
FIELDS = ("apps", "metering_status", "metering_user_hive_count", "metering_record_count")
# Fragments omit unrelated required device inventory, but preserve the complete
# canonical app schema, including its evidence/value consistency conditions.
FRAGMENT = {"$schema": CANONICAL["$schema"], "type": "object",
            "properties": {key: CANONICAL["properties"][key] for key in FIELDS}}
FORMATS = jsonschema.FormatChecker()


@FORMATS.checks("date-time", raises=ValueError)
def emitted_datetime(value):
    # jsonschema silently skips date-time when its optional format dependency
    # is missing. The agents emit this RFC3339 subset; validate calendar dates too.
    if not isinstance(value, str):
        return True
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})", value):
        return False
    return datetime.fromisoformat(value.upper().replace("Z", "+00:00")).tzinfo is not None


VALIDATOR = jsonschema.validators.validator_for(FRAGMENT)(
    FRAGMENT, format_checker=FORMATS)
FIXTURES = json.loads((ROOT / "contracts/inventory-usage-evidence.fixtures.json").read_text())


class UsageEvidenceContractTests(unittest.TestCase):
    def test_every_state_and_partial_read_fixture_is_valid(self):
        for case in FIXTURES:
            with self.subTest(case=case["name"]):
                VALIDATOR.validate(case["payload"])

    def test_invalid_evidence_cannot_masquerade_as_non_use(self):
        baseline = {"apps": [{"name": "Fixture", "version": "1.0"}]}
        for fields in (
            {"usage_evidence": "never_used"},
            {"usage_evidence": "recorded"},
            {"usage_evidence": "recorded", "last_used_at": "not-a-date"},
            {"usage_evidence": "no_record", "launch_count": 1},
            {"usage_evidence": "unmapped", "last_used_at": "2026-09-30T12:00:00Z"},
            {"usage_evidence": "unavailable", "launch_count": -1},
        ):
            with self.subTest(fields=fields):
                payload = copy.deepcopy(baseline)
                payload["apps"][0].update(fields)
                self.assertTrue(list(VALIDATOR.iter_errors(payload)))

    def test_count_diagnostics_are_nonnegative_bounded_integers(self):
        for key in FIELDS[2:]:
            for value in (-1, 2147483648, "1", True):
                with self.subTest(key=key, value=value):
                    self.assertTrue(list(VALIDATOR.iter_errors({key: value})))

    def test_mirror_is_byte_identical_when_source_supplied(self):
        source = os.environ.get("PATCHED_PLATFORM_SCHEMA")
        if not source:
            self.skipTest("PATCHED_PLATFORM_SCHEMA not supplied")
        self.assertEqual(Path(source).read_bytes(), MIRROR.read_bytes())

    def test_actual_mac_payload_fragments_when_supplied(self):
        folder = os.environ.get("PATCHED_USAGE_DUMP")
        if not folder:
            self.skipTest("PATCHED_USAGE_DUMP not supplied")
        files = sorted(Path(folder).glob("macos-*.json"))
        self.assertTrue(files, "No generated Mac payload fragments found")
        for payload in files:
            with self.subTest(payload=payload.name):
                VALIDATOR.validate(json.loads(payload.read_text()))


if __name__ == "__main__":
    unittest.main()
