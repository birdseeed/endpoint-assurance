#!/usr/bin/env python3
"""
Deterministic compliance test-matrix generator.
Reads rules.csv and expands each rule into test cases per the specification recipe.
"""

import csv
import json
import sys
from pathlib import Path


def parse_json_list(s):
    """Parse JSON array string like "[\"On\"]" into Python list."""
    if not s or not s.strip():
        return []
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return []


def parse_applicable_arch(s):
    """Parse applicable_arch which can be empty, plain string, or JSON array."""
    if not s or not s.strip():
        return []
    # Try JSON first
    try:
        result = json.loads(s)
        if isinstance(result, list):
            return result
    except json.JSONDecodeError:
        pass
    # If not JSON, treat as plain string (single architecture)
    s = s.strip()
    if s:
        return [s]
    return []


def is_numeric(s):
    """Check if a string is numeric (int or float)."""
    try:
        int(s)
        return True
    except ValueError:
        try:
            float(s)
            return True
        except ValueError:
            return False


def get_numeric_value(s):
    """Parse string as int if possible, else float."""
    if '.' in s:
        return float(s)
    return int(s)


def get_opposite_value(original, expected_values):
    """Get the conventional opposite of a value for noncompliant case."""
    opposites = {
        "On": "Off",
        "Off": "On",
        "Yes": "No",
        "No": "Yes",
        "enabled": "disabled",
        "disabled": "enabled",
    }

    if original in opposites:
        opposite = opposites[original]
        if opposite not in expected_values:
            return opposite

    if is_numeric(original):
        try:
            num = get_numeric_value(original)
            new_val = int(num) + 1 if isinstance(num, int) else str(int(num) + 1)
            if str(new_val) not in expected_values:
                return str(new_val)
        except:
            pass

    # Fallback
    if "__violation__" not in expected_values:
        return "__violation__"
    return "__other__"


def generate_cases(rule):
    """Generate all test cases for a single rule."""
    rule_key = rule["rule_key"]
    platform = rule["platform"]
    tier = rule["collection_tier"]
    signal_key = rule["signal_key"]
    comparator = rule["comparator"]
    expected_values = parse_json_list(rule["expected_values"])
    applicable_arch = parse_applicable_arch(rule["applicable_arch"])
    treat_unknown_as = rule["treat_unknown_as"]

    cases = []

    # Determine if this is a findings rule
    is_findings_rule = (
        (rule_key.startswith("patched_macos_") or rule_key.startswith("patched_win_"))
        and treat_unknown_as == "pass"
    )

    if not expected_values:
        return cases

    # 1. Compliant case
    if is_findings_rule:
        # Findings rules: compliant = missing semantics
        case = {
            "rule_key": rule_key,
            "platform": platform,
            "tier": tier,
            "signal_key": signal_key,
            "state": "missing",
            "inject": None,
            "omit_signal": True,
            "expected_status": "pass",
            "device_arch": "arm64",
            "notes": "findings rule: agent emits key only on violation"
        }
        cases.append(case)
    else:
        # Normal compliant case
        if comparator in ("eq", "in"):
            value = expected_values[0]
        elif comparator == "neq":
            # neq passes only when the observed value is NOT in expected_values
            value = "None" if "None" not in expected_values else "__other__"
        elif comparator == "contains":
            value = expected_values[0]
        elif comparator == "gte":
            value = expected_values[0]
        elif comparator == "lte":
            value = expected_values[0]
        else:
            value = expected_values[0]

        case = {
            "rule_key": rule_key,
            "platform": platform,
            "tier": tier,
            "signal_key": signal_key,
            "state": "compliant",
            "inject": value,
            "omit_signal": False,
            "expected_status": "pass",
            "device_arch": "arm64",
        }
        cases.append(case)

    # Also emit literal eq cases for findings rules
    if is_findings_rule:
        case = {
            "rule_key": rule_key,
            "platform": platform,
            "tier": tier,
            "signal_key": signal_key,
            "state": "compliant",
            "inject": expected_values[0],
            "omit_signal": False,
            "expected_status": "pass",
            "device_arch": "arm64",
            "notes": "findings rule: literal case"
        }
        cases.append(case)

    # 2. Noncompliant case
    if comparator in ("eq", "in"):
        opposite = get_opposite_value(expected_values[0], expected_values)
        noncompliant_value = opposite
    elif comparator == "neq":
        noncompliant_value = expected_values[0]
    elif comparator == "contains":
        noncompliant_value = "no-match-here"
    elif comparator == "gte":
        if is_numeric(expected_values[0]):
            num = get_numeric_value(expected_values[0])
            if isinstance(num, int):
                noncompliant_value = str(num - 1)
            else:
                noncompliant_value = str(num - 1.0)
        else:
            noncompliant_value = "__violation__"
    elif comparator == "lte":
        if is_numeric(expected_values[0]):
            num = get_numeric_value(expected_values[0])
            if isinstance(num, int):
                noncompliant_value = str(num + 1)
            else:
                noncompliant_value = str(num + 1.0)
        else:
            noncompliant_value = "__violation__"
    else:
        noncompliant_value = "__violation__"

    case = {
        "rule_key": rule_key,
        "platform": platform,
        "tier": tier,
        "signal_key": signal_key,
        "state": "noncompliant",
        "inject": noncompliant_value,
        "omit_signal": False,
        "expected_status": "fail",
        "device_arch": "arm64",
    }
    cases.append(case)

    # 3. Missing case (skip for findings rules - already covered by compliant-as-missing)
    if not is_findings_rule:
        if treat_unknown_as == "fail":
            expected_status = "fail"
        else:
            expected_status = "pass"

        case = {
            "rule_key": rule_key,
            "platform": platform,
            "tier": tier,
            "signal_key": signal_key,
            "state": "missing",
            "inject": None,
            "omit_signal": True,
            "expected_status": expected_status,
            "device_arch": "arm64",
        }
        cases.append(case)

    # 4. Collector error case
    # For gte/lte with numeric values, "Unknown" is non-numeric => "error"
    if comparator in ("gte", "lte"):
        expected_status = "error"
    else:
        # For eq/in/neq/contains, compute honestly
        if comparator == "eq" or comparator == "in":
            expected_status = "fail" if "Unknown" not in expected_values else "pass"
        elif comparator == "neq":
            expected_status = "pass" if "Unknown" not in expected_values else "fail"
        elif comparator == "contains":
            # evaluator checks observed ("Unknown") CONTAINS expected_values[0]
            expected_status = "pass" if expected_values[0] in "Unknown" else "fail"
        else:
            expected_status = "fail"

    note = None
    if comparator not in ("gte", "lte"):
        note = "error state structurally unreachable for this comparator"

    case = {
        "rule_key": rule_key,
        "platform": platform,
        "tier": tier,
        "signal_key": signal_key,
        "state": "collector_error",
        "inject": "Unknown",
        "omit_signal": False,
        "expected_status": expected_status,
        "device_arch": "arm64",
    }
    if note:
        case["notes"] = note
    cases.append(case)

    # 5. Not applicable case (only if applicable_arch is non-empty)
    if applicable_arch:
        # Determine the mismatching architecture
        if "arm64" in applicable_arch:
            mismatch_arch = "x86_64"
        else:
            mismatch_arch = "arm64"

        # Not applicable case: omit_signal=false, inject compliant value
        if comparator in ("eq", "in"):
            compliant_value = expected_values[0]
        elif comparator == "neq":
            compliant_value = expected_values[0]
        elif comparator == "contains":
            compliant_value = expected_values[0]
        elif comparator in ("gte", "lte"):
            compliant_value = expected_values[0]
        else:
            compliant_value = expected_values[0]

        case = {
            "rule_key": rule_key,
            "platform": platform,
            "tier": tier,
            "signal_key": signal_key,
            "state": "not_applicable",
            "inject": compliant_value,
            "omit_signal": False,
            "expected_status": "not_applicable",
            "device_arch": mismatch_arch,
        }
        cases.append(case)

        # Companion arch_match_compliant case
        case = {
            "rule_key": rule_key,
            "platform": platform,
            "tier": tier,
            "signal_key": signal_key,
            "state": "arch_match_compliant",
            "inject": compliant_value,
            "omit_signal": False,
            "expected_status": "pass",
            "device_arch": applicable_arch[0],
        }
        cases.append(case)

    return cases


def main():
    if len(sys.argv) < 3:
        print("Usage: gen_matrix.py <input_csv> <output_json>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    # Read CSV
    rules = []
    with open(input_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rules.append(row)

    # Generate all cases
    all_cases = []
    state_counts = {}
    platform_counts = {}
    rules_with_applicable_arch = []

    for rule in rules:
        cases = generate_cases(rule)
        all_cases.extend(cases)

        if parse_applicable_arch(rule["applicable_arch"]):
            rules_with_applicable_arch.append(rule["rule_key"])

        for case in cases:
            state = case["state"]
            state_counts[state] = state_counts.get(state, 0) + 1

            platform = case["platform"]
            if platform not in platform_counts:
                platform_counts[platform] = 0
            platform_counts[platform] += 1

    # Build output
    output = {
        "generated_from": "rules.csv",
        "recipe_version": 1,
        "counts": {
            "total_cases": len(all_cases),
            "per_state": state_counts,
            "per_platform": platform_counts,
            "rules_with_applicable_arch": len(rules_with_applicable_arch),
            "applicable_arch_rule_keys": sorted(rules_with_applicable_arch),
        },
        "cases": all_cases,
    }

    # Write JSON
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
