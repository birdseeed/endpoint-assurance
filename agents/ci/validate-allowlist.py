#!/usr/bin/env python3
"""
validate-allowlist.py — CI enforcement gate for the endpoint label allowlist.

Reads endpoint/labels-allowlist.txt, looks up each label's manifest record, and
fails non-zero if any allowlisted label violates the invariants that close threat
T4 (see docs/installomator-security-review.md):

  - manifest record must exist for every label in the allowlist
  - expected_team_id must be present and a valid 10-char Apple Team ID
  - every download URL must be https://
  - url-resolution method (download.method) must be non-empty

This check is intentionally narrow: it targets only the six allowlisted labels,
not the full ~1120-record manifest. validate-labels.py covers the full manifest.
Do not merge or weaken that script.

Usage:
    python3 ci/validate-allowlist.py [--repo-root DIR]
"""

import argparse
import json
import re
import sys
from pathlib import Path

TEAM_ID_RE = re.compile(r"^[A-Z0-9]{10}$")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", default=".", help="Repo root (default: cwd)")
    args = ap.parse_args()

    root = Path(args.repo_root).resolve()
    allowlist_path = root / "endpoint" / "labels-allowlist.txt"
    labels_dir = root / "engine" / "labels"

    if not allowlist_path.is_file():
        print(f"FATAL: allowlist not found at {allowlist_path}", file=sys.stderr)
        return 2
    if not labels_dir.is_dir():
        print(f"FATAL: labels directory not found at {labels_dir}", file=sys.stderr)
        return 2

    # Parse the allowlist — skip comment lines, extract label names (column 0).
    allowlisted = []
    for line in allowlist_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        label = line.split("\t")[0]
        if label:
            allowlisted.append(label)

    if not allowlisted:
        print("FATAL: allowlist is empty — expected at least one label.", file=sys.stderr)
        return 2

    errors = []

    for label in allowlisted:
        record_path = labels_dir / f"{label}.json"

        # 1. Manifest record must exist.
        if not record_path.is_file():
            errors.append(f"{label}: no manifest record at {record_path}")
            continue

        try:
            rec = json.loads(record_path.read_text())
        except json.JSONDecodeError as e:
            errors.append(f"{label}: invalid JSON in manifest record — {e}")
            continue

        # 2. expected_team_id must be present and a valid 10-char Apple Team ID.
        tid = rec.get("expected_team_id", "")
        if not tid:
            errors.append(f"{label}: expected_team_id is missing or empty (closes T4 — must be set)")
        elif not TEAM_ID_RE.match(tid):
            errors.append(f"{label}: expected_team_id '{tid}' is not a 10-char alphanumeric Apple Team ID")

        # 3. Download URL must be https://.
        dl = rec.get("download", {})
        method = dl.get("method", "")
        if method == "static":
            url = dl.get("url", "")
            if not url.startswith("https://"):
                errors.append(f"{label}: download.url is not https:// — '{url}'")
        elif method == "resolved":
            source = dl.get("source", "")
            if not source.startswith("https://"):
                errors.append(f"{label}: download.source is not https:// — '{source}'")
        # method == "" is caught below

        # 4. url-resolution method (download.method) must be non-empty.
        if not method:
            errors.append(f"{label}: download.method (url-resolution method) is missing or empty")

    if errors:
        print(f"FAILED — {len(errors)} allowlist invariant(s) violated:\n")
        for e in errors:
            print(f"  ✗ {e}")
        print(f"\nFix the manifest record(s) above before merging.")
        return 1

    print(f"Checked {len(allowlisted)} allowlisted label(s) — all invariants satisfied.")
    for label in allowlisted:
        rec = json.loads((labels_dir / f"{label}.json").read_text())
        tid = rec["expected_team_id"]
        method = rec["download"]["method"]
        print(f"  ✓ {label:<16} {method:<9} {tid}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
