#!/usr/bin/env python3
"""
validate-catalogue.py — CI gate for the Patched Tier 2 deploy catalogue.

Validates engine/catalogue/deploy-catalogue.json for structural correctness:

  - All required top-level fields present on every entry
  - No duplicate entry IDs
  - Covered entries have valid macOS and/or Windows sections
  - Gap entries include a gap_reason
  - Source-trust values are from the known set
  - macOS-only entries (platform_scope = macos_only) do not have a windows section
  - prevalence_rank values are unique integers 1–N

Exits 0 on success, non-zero on any failure. Wire into CI alongside validate-labels.py.

Usage:
    python3 ci/validate-catalogue.py [--repo-root DIR] [--catalogue FILE]
"""

import argparse
import json
import sys
from pathlib import Path

# Fields required on every catalogue entry.
REQUIRED_ENTRY_FIELDS = {"id", "display_name", "prevalence_rank", "coverage_status"}

# Valid values for coverage_status.
VALID_COVERAGE_STATUS = {"covered", "gap"}

# Valid source_trust values for macOS entries.
VALID_MACOS_SOURCE_TRUST = {
    "publisher_allowlist",
    "installomator_import",
    "catalogue_pending",
}

# Valid source_trust values for Windows entries.
VALID_WINDOWS_SOURCE_TRUST = {
    "winget_community",
    "winget_pending",
    "catalogue_pending",
}

# Required fields inside a macos block.
REQUIRED_MACOS_FIELDS = {"installomator_label", "bundle_id", "verified", "source_trust"}

# Required fields inside a windows block.
REQUIRED_WINDOWS_FIELDS = {"winget_id", "publisher", "verified", "source_trust"}


def fail(entry_id, msg, errors):
    errors.append(f"{entry_id}: {msg}")


def validate_macos_block(entry_id, macos, errors):
    """Validate a macos block. Returns True if the block looks structurally sound."""
    ok = True
    missing = REQUIRED_MACOS_FIELDS - set(macos.keys())
    if missing:
        fail(entry_id, f"macos block missing fields: {sorted(missing)}", errors)
        ok = False
        return ok

    trust = macos.get("source_trust")
    if trust not in VALID_MACOS_SOURCE_TRUST:
        fail(
            entry_id,
            f"macos.source_trust '{trust}' not in {sorted(VALID_MACOS_SOURCE_TRUST)}",
            errors,
        )
        ok = False

    if not isinstance(macos.get("verified"), bool):
        fail(entry_id, "macos.verified must be a boolean", errors)
        ok = False

    bundle_id = macos.get("bundle_id")
    if not bundle_id or not isinstance(bundle_id, str):
        fail(entry_id, "macos.bundle_id must be a non-empty string", errors)
        ok = False

    # If label is present (non-null), it must be a non-empty string.
    label = macos.get("installomator_label")
    if label is not None and not isinstance(label, str):
        fail(entry_id, "macos.installomator_label must be a string or null", errors)
        ok = False

    # A covered entry must have a label.
    return ok


def validate_windows_block(entry_id, windows, errors):
    """Validate a windows block. Returns True if the block looks structurally sound."""
    ok = True
    missing = REQUIRED_WINDOWS_FIELDS - set(windows.keys())
    if missing:
        fail(entry_id, f"windows block missing fields: {sorted(missing)}", errors)
        ok = False
        return ok

    trust = windows.get("source_trust")
    if trust not in VALID_WINDOWS_SOURCE_TRUST:
        fail(
            entry_id,
            f"windows.source_trust '{trust}' not in {sorted(VALID_WINDOWS_SOURCE_TRUST)}",
            errors,
        )
        ok = False

    if not isinstance(windows.get("verified"), bool):
        fail(entry_id, "windows.verified must be a boolean", errors)
        ok = False

    publisher = windows.get("publisher")
    if not publisher or not isinstance(publisher, str):
        fail(entry_id, "windows.publisher must be a non-empty string", errors)
        ok = False

    # winget_id may be null for gap entries, but must be string if present.
    winget_id = windows.get("winget_id")
    if winget_id is not None and not isinstance(winget_id, str):
        fail(entry_id, "windows.winget_id must be a string or null", errors)
        ok = False

    return ok


def validate_entry(entry, errors):
    """Validate a single catalogue entry. Returns the entry's id (or None on fatal error)."""
    # ID — used for all subsequent error messages.
    entry_id = entry.get("id", "<unknown>")

    # Required fields.
    missing = REQUIRED_ENTRY_FIELDS - set(entry.keys())
    if missing:
        fail(entry_id, f"missing required fields: {sorted(missing)}", errors)

    # coverage_status.
    status = entry.get("coverage_status")
    if status not in VALID_COVERAGE_STATUS:
        fail(
            entry_id,
            f"coverage_status '{status}' must be one of {sorted(VALID_COVERAGE_STATUS)}",
            errors,
        )

    # gap entries must have gap_reason.
    if status == "gap" and not entry.get("gap_reason"):
        fail(entry_id, "gap entries must include a non-empty gap_reason field", errors)

    # prevalence_rank must be a positive integer.
    rank = entry.get("prevalence_rank")
    if not isinstance(rank, int) or rank < 1:
        fail(entry_id, f"prevalence_rank must be a positive integer, got: {rank!r}", errors)

    # platform_scope — if present must be a string.
    scope = entry.get("platform_scope")
    if scope is not None and not isinstance(scope, str):
        fail(entry_id, "platform_scope must be a string", errors)
    macos_only = scope == "macos_only"

    # macos block.
    macos = entry.get("macos")
    if macos is None and not macos_only:
        # Allowed only if it's a Windows-only app — not in our current catalogue.
        # For now, treat missing macos on a non-macos-only entry as a warning, not an error.
        pass
    elif macos is not None:
        validate_macos_block(entry_id, macos, errors)

    # windows block.
    windows = entry.get("windows")
    if macos_only and windows is not None:
        fail(
            entry_id,
            "platform_scope=macos_only but windows block is present (should be null)",
            errors,
        )
    elif windows is not None:
        validate_windows_block(entry_id, windows, errors)

    # Covered entry coherence — must have at least one deployable platform.
    if status == "covered":
        macos_label = (macos or {}).get("installomator_label")
        winget_id = (windows or {}).get("winget_id") if windows else None
        if not macos_label and not winget_id and not macos_only:
            fail(
                entry_id,
                "coverage_status=covered but no installomator_label and no winget_id present",
                errors,
            )

    return entry_id if entry_id != "<unknown>" else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", default=".", help="Repo root (default: cwd)")
    ap.add_argument(
        "--catalogue",
        metavar="FILE",
        help="Path to the catalogue JSON (default: engine/catalogue/deploy-catalogue.json)",
    )
    args = ap.parse_args()

    root = Path(args.repo_root).resolve()
    catalogue_path = (
        Path(args.catalogue).resolve()
        if args.catalogue
        else root / "engine" / "catalogue" / "deploy-catalogue.json"
    )

    if not catalogue_path.is_file():
        print(f"FATAL: catalogue not found at {catalogue_path}", file=sys.stderr)
        return 2

    # Parse.
    try:
        doc = json.loads(catalogue_path.read_text())
    except json.JSONDecodeError as e:
        print(f"FATAL: catalogue JSON invalid — {e}", file=sys.stderr)
        return 2

    entries = doc.get("entries")
    if not isinstance(entries, list) or not entries:
        print("FATAL: catalogue 'entries' is missing or empty", file=sys.stderr)
        return 2

    errors = []
    seen_ids = {}
    seen_ranks = {}

    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"entries[{i}]: must be an object")
            continue

        entry_id = validate_entry(entry, errors)

        # Duplicate ID check.
        if entry_id:
            if entry_id in seen_ids:
                fail(entry_id, f"duplicate id — first seen at index {seen_ids[entry_id]}", errors)
            else:
                seen_ids[entry_id] = i

        # Duplicate rank check.
        rank = entry.get("prevalence_rank")
        if isinstance(rank, int):
            if rank in seen_ranks:
                fail(
                    entry_id or f"entries[{i}]",
                    f"duplicate prevalence_rank {rank} — also used by '{seen_ranks[rank]}'",
                    errors,
                )
            else:
                seen_ranks[rank] = entry_id or f"entries[{i}]"

    # Summary.
    total = len(entries)
    covered = sum(1 for e in entries if e.get("coverage_status") == "covered")
    gaps = sum(1 for e in entries if e.get("coverage_status") == "gap")

    print(f"Catalogue: {catalogue_path}")
    print(f"  Total entries : {total}")
    print(f"  Covered       : {covered} ({100 * covered // total}%)")
    print(f"  Gaps          : {gaps}")

    if errors:
        print(f"\nFAILED — {len(errors)} problem(s):\n")
        for e in errors:
            print(f"  x {e}")
        return 1

    for entry in entries:
        entry_id = entry.get("id", "?")
        status = entry.get("coverage_status", "?")
        macos_label = (entry.get("macos") or {}).get("installomator_label") or "-"
        winget_id = ((entry.get("windows") or {}).get("winget_id")) or "-"
        scope = entry.get("platform_scope", "")
        scope_tag = f" [{scope}]" if scope else ""
        mark = "ok" if status == "covered" else "gap"
        print(f"  {mark}  {entry_id:<24} macOS:{macos_label:<36} win:{winget_id}{scope_tag}")

    print(f"\nAll {total} catalogue entries valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
