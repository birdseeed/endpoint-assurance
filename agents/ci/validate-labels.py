#!/usr/bin/env python3
"""
validate-labels.py — CI gate for the Patched Updater label manifest.

Validates every label record in engine/labels/ against contracts/label.schema.json
and enforces the security-critical invariants from the security review:

  - expected_team_id present and a 10-char Apple Team ID   (closes threat T4)
  - every URL is https://                                  (review §4.2)
  - every URL is a well-formed absolute URL, not a regex/shell fragment
                                                            (PAT-882)
  - the file name matches the record's `label` field
  - no two records share a `label`
  - the record validates against the JSON Schema

Exits non-zero on any failure — wire it into CI so it runs on every PR,
including every PR the verification agent opens.

Usage:
    python3 ci/validate-labels.py [--repo-root DIR] [--emit-allowlist FILE]

--emit-allowlist writes the derived endpoint allowlist (the subset of records
with patched.allowlisted = true) as the tab-separated labels-allowlist.txt
format, so the allowlist is generated from the manifest and cannot drift.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from installomator_pkg_contract import (  # noqa: E402
    is_endpoint_allowlisted,
    pkgindmg_contract_errors,
    safe_relative_pkg_pattern_error,
    team_id_contract_errors,
)
from installomator_execution_contract import managed_execution_contract_errors  # noqa: E402

TEAM_ID_RE = re.compile(r"^[A-Z0-9]{10}$")

# PAT-882: characters that never appear in a real, well-formed URL but do
# appear in a leaked grep/regex pattern or shell fragment (the bug class that
# produced "https://[^\"" as a download.source — a fragment of the shell
# expression `grep -oE 'https://[^"]*\.dmg'` captured verbatim instead of the
# page it was meant to scrape). `{` and `}` are deliberately NOT included:
# several legitimate static URLs in the manifest use `${var}` shell-style
# template placeholders (e.g. amazoncorretto*jdk.json, jetbrains*.json) that
# the engine substitutes at run time.
URL_REGEX_FRAGMENT_RE = re.compile(r"[\[\]\^`<>\\|]")
# A raw, unescaped space is never valid inside a URL either.
URL_WHITESPACE_RE = re.compile(r"\s")


def url_sanity_error(url):
    """
    Return a human-readable error string if `url` is not a well-formed,
    non-regex-fragment absolute HTTPS URL. Return None if it looks fine.

    This exists because the schema's `^https://` pattern check alone lets a
    regex/shell fragment through as long as it happens to start with
    "https://" — exactly the PAT-882 defect class. This check is deliberately
    conservative: it flags characters that are never legitimate in a URL
    (even a templated one) rather than trying to fully validate URL syntax.
    """
    if URL_REGEX_FRAGMENT_RE.search(url):
        return (f"'{url}' contains a character ([, ], ^, `, <, >, \\, or |) that "
                f"never appears in a real URL — looks like a regex/grep fragment "
                f"or shell snippet leaked into the field")
    if URL_WHITESPACE_RE.search(url):
        return f"'{url}' contains raw whitespace — not a valid URL"
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return f"'{url}' does not have an https:// scheme"
    if not parsed.netloc or "." not in parsed.netloc.split("@")[-1].split(":")[0]:
        return f"'{url}' has no resolvable host — not a well-formed absolute URL"
    return None


def fail(label, msg, errors):
    errors.append(f"{label}: {msg}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", default=".", help="Repo root (default: cwd)")
    ap.add_argument("--emit-allowlist", metavar="FILE",
                    help="Write the derived endpoint allowlist to FILE")
    args = ap.parse_args()

    root = Path(args.repo_root).resolve()
    schema_path = root / "contracts" / "label.schema.json"
    labels_dir = root / "engine" / "labels"
    engine_path = root / "engine" / "Installomator.sh"

    if not schema_path.is_file():
        print(f"FATAL: schema not found at {schema_path}", file=sys.stderr)
        return 2
    if not labels_dir.is_dir():
        print(f"FATAL: labels directory not found at {labels_dir}", file=sys.stderr)
        return 2
    if not engine_path.is_file():
        print(f"FATAL: endpoint engine not found at {engine_path}", file=sys.stderr)
        return 2

    try:
        import jsonschema
    except ImportError:
        print("FATAL: jsonschema not installed (pip install jsonschema)", file=sys.stderr)
        return 2

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)

    errors = []
    seen_labels = {}
    records = []

    label_files = sorted(labels_dir.glob("*.json"))
    if not label_files:
        print(f"FATAL: no label records in {labels_dir}", file=sys.stderr)
        return 2

    for path in label_files:
        name = path.name

        # 1. Parse.
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            errors.append(f"{name}: invalid JSON — {e}")
            continue

        # 2. Schema.
        schema_errs = sorted(validator.iter_errors(rec), key=str)
        for e in schema_errs:
            loc = "/".join(str(p) for p in e.absolute_path) or "(root)"
            fail(name, f"schema: {loc}: {e.message}", errors)
        if schema_errs:
            # Don't run the field checks below on a record that failed the
            # schema — the fields may be missing entirely.
            continue

        label = rec["label"]

        # 3. File name matches the label.
        if name != f"{label}.json":
            fail(name, f"file name must be '{label}.json' to match the label field", errors)

        # 4. Duplicate label.
        if label in seen_labels:
            fail(name, f"duplicate label — also defined in {seen_labels[label]}", errors)
        else:
            seen_labels[label] = name

        # 5. Team ID — belt-and-braces over the schema pattern (closes T4).
        tid = rec["expected_team_id"]
        if not TEAM_ID_RE.match(tid):
            fail(label, f"expected_team_id '{tid}' is not a 10-char Apple Team ID", errors)

        # 6. Every URL is https, and a well-formed URL rather than a regex/shell
        #    fragment (PAT-882) — the https-prefix check alone does not catch a
        #    value like "https://[^\"" leaked from a grep pattern.
        dl = rec["download"]
        urls = []
        if dl["method"] == "static":
            urls.append(("download.url", dl["url"]))
        elif dl["method"] == "resolved":
            urls.append(("download.source", dl["source"]))
        notice = rec.get("redistribution_notice")
        if notice:
            urls.append(("redistribution_notice.url", notice["url"]))
        for field, url in urls:
            if not url.startswith("https://"):
                fail(label, f"{field} is not https:// — {url}", errors)
                continue
            sanity_err = url_sanity_error(url)
            if sanity_err:
                fail(label, f"{field}: {sanity_err}", errors)

        # 7. PAT-500 mirror consistency checks.
        #    mirror=true requires mirror_eula_approved=true (EULA gate).
        #    pinned_sha256 (top-level) must be a 64-char hex string or null.
        p = rec.get("patched", {})
        if p.get("mirror") and not p.get("mirror_eula_approved"):
            fail(label,
                 "patched.mirror=true but patched.mirror_eula_approved is not set to true — "
                 "confirm redistribution licensing before enabling the mirror",
                 errors)

        # vendor_only=true requires a human-readable vendor_only_reason (schema
        # §patched.vendor_only_reason says "required when vendor_only=true", but
        # that conditional requirement isn't expressible in JSON Schema as
        # written here, so it's enforced as a custom check instead).
        if p.get("vendor_only") and not p.get("vendor_only_reason"):
            fail(label,
                 "patched.vendor_only=true but patched.vendor_only_reason is missing or empty",
                 errors)

        # mirror_sha256 was a temporary field used in an earlier draft of PAT-49;
        # it was superseded by the top-level pinned_sha256 field (schema §4.4).
        # Reject any label that still carries it so stale fields don't accumulate.
        if "mirror_sha256" in rec:
            fail(label,
                 "mirror_sha256 is no longer a valid field — "
                 "use pinned_sha256 (written by the mirror pipeline)",
                 errors)

        # PAT-1385: pkgindmg payload locators are data, never shell. The JSON
        # Schema owns the typed root-vs-explicit shape; this custom check owns
        # the path safety properties that are clearer and more auditable in
        # code than in a large negative-lookahead regex.
        pkg_locator = rec.get("pkg_in_dmg")
        if pkg_locator and pkg_locator.get("mode") in {
                "relative-path-glob", "relative-path-glob-by-arch"}:
            patterns = pkg_locator.get("patterns", [])
            if pkg_locator.get("mode") == "relative-path-glob-by-arch":
                patterns = list(pkg_locator.get("patterns_by_arch", {}).values())
            for pattern in patterns:
                locator_err = safe_relative_pkg_pattern_error(pattern)
                if locator_err:
                    fail(label, f"pkg_in_dmg pattern {pattern!r}: {locator_err}", errors)
        elif pkg_locator and pkg_locator.get("mode") == "relative-path-version-component":
            template = pkg_locator.get("template", "")
            rendered = template.replace("{version_component}", "0")
            locator_err = safe_relative_pkg_pattern_error(rendered)
            if template.count("{version_component}") != 1 or locator_err:
                fail(label, f"pkg_in_dmg template {template!r}: "
                     f"{locator_err or 'requires exactly one version component'}", errors)
        elif pkg_locator and pkg_locator.get("mode") == "relative-path-version-digits":
            template = pkg_locator.get("template", "")
            rendered = template.replace("{version_digits}", "0")
            locator_err = safe_relative_pkg_pattern_error(rendered)
            if template.count("{version_digits}") != 1 or locator_err:
                fail(label, f"pkg_in_dmg template {template!r}: "
                     f"{locator_err or 'requires exactly one version-digits component'}", errors)

        records.append(rec)

    # PAT-1385: the endpoint executes this exact shell engine, not the JSON
    # records. Cross-check every pkgindmg record that has a runtime stanza and
    # refuse any allowlisted record with no stanza. This closes the narrow
    # payload-selection drift.
    errors.extend(pkgindmg_contract_errors(
        records, engine_path.read_text(encoding="utf-8")))
    # PAT-1429: the endpoint enforces expected_team_id via the shell's own
    # expectedTeamID= assignment, not the manifest -- and nothing compared
    # the two before this check. Three separate, independently-reviewed
    # manifest corrections (PAT-1282 veracrypt, PAT-1283 veracrypt-fuse-t,
    # PAT-1272 logseq) each fixed engine/labels/*.json's expected_team_id
    # and each silently missed the matching engine/Installomator.sh
    # expectedTeamID= update -- a systemic pattern, not three coincidences,
    # and the single best justification for why this check exists: a
    # manifest fix that is reviewed and correct still fails closed on every
    # real install, silently, when only one of its two enforcement halves
    # gets updated. Same shape as the pkgindmg check above: parse the shell
    # as data, compare, fail closed on drift.
    errors.extend(team_id_contract_errors(
        records, engine_path.read_text(encoding="utf-8")))
    # PAT-1403: records that can reach endpoints must agree with the exact
    # committed shell engine that the release bundle copies and executes, on
    # every execution-affecting field (type/downloadURL/expectedTeamID/
    # blockingProcesses/versionKey) -- the broader reconciliation PAT-1385's
    # narrower pkgindmg-payload check above doesn't cover.
    errors.extend(managed_execution_contract_errors(records, engine_path.read_text(encoding="utf-8")))

    # Report.
    print(f"Checked {len(label_files)} label record(s) in {labels_dir}")
    if errors:
        print(f"\nFAILED — {len(errors)} problem(s):\n")
        for e in errors:
            print(f"  ✗ {e}")
        return 1

    for rec in records:
        flags = []
        if is_endpoint_allowlisted(rec):
            flags.append("allowlisted")
        if rec["patched"]["mirror"] is True:
            flags.append("mirror")
        if rec["patched"].get("mirror_eula_approved") is False:
            flags.append("eula_pending")
        elif rec["patched"].get("mirror_eula_approved"):
            flags.append("eula_approved")
        print(f"  ✓ {rec['label']:<16} {rec['download']['method']:<9} "
              f"{rec['expected_team_id']}  {', '.join(flags)}")
    print("\nAll label records valid.")

    # Emit the derived allowlist.
    if args.emit_allowlist:
        out = Path(args.emit_allowlist)
        lines = [
            "# labels-allowlist.txt — GENERATED from the label manifest by",
            "# ci/validate-labels.py --emit-allowlist. Do not edit by hand.",
            "# Format: label <TAB> name <TAB> expected_team_id <TAB> app_path <TAB> download_method <TAB> mirror_url <TAB> pinned_sha256",
        ]
        # PAT-1403 (round 2, Finding 5): round 1 added an 8th trailing
        # installed_version_key column here on the strength of "an
        # endpoint-side consumer" — but the actual, only consumer,
        # endpoint/patched-update.sh's `while IFS=$'\t' read -r label name
        # expected_tid app_path url_method allowlist_mirror_url
        # allowlist_pinned_sha256; do`, only ever names SEVEN variables. zsh
        # `read` assigns any EXTRA fields (with their delimiters) onto the
        # LAST named variable, so an 8-field row would have silently
        # corrupted allowlist_pinned_sha256 with a literal embedded tab plus
        # the version-key value appended — breaking pinned-hash verification
        # for every mirrored label (currently ghostty) in production. No
        # consumer of the 8th field exists yet. Reverted to the 7-field
        # format the real consumer actually parses; installed_version_key
        # stays a manifest field and is still reconciled against the shell's
        # versionKey by ci/installomator_execution_contract.py — it is only
        # the DERIVED allowlist emission that is reverted here.
        for rec in sorted(records, key=lambda r: r["label"]):
            if not is_endpoint_allowlisted(rec):
                continue
            lines.append("\t".join([
                rec["label"], rec["name"], rec["expected_team_id"],
                rec["app_path"], rec["download"]["method"],
                rec.get("patched", {}).get("mirror_url") or "",
                rec.get("pinned_sha256") or "",
            ]))
        out.write_text("\n".join(lines) + "\n")
        n = sum(1 for r in records if is_endpoint_allowlisted(r))
        print(f"\nWrote derived allowlist ({n} label(s)) to {out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
