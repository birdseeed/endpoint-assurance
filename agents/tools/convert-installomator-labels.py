#!/usr/bin/env python3
"""
tools/convert-installomator-labels.py

Converts Installomator's fragment label files (engine/fragments/labels/*.sh)
into the Patched structured label manifest (engine/labels/<label>.json).

Schema: contracts/label.schema.json
Format: docs/label-manifest-format.md
Tracks: PAT-41

Usage:
    python3 tools/convert-installomator-labels.py [--repo-root DIR] [--dry-run] [--no-skip-existing]

Options:
    --repo-root DIR     Repo root directory (default: cwd)
    --dry-run           Parse and report without writing files
    --no-skip-existing  Overwrite existing records (default: preserve existing records)
"""

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path

TEAM_ID_RE = re.compile(r"^[A-Z0-9]{10}$")

# Installomator uses mixed-case type names; normalise to schema's lowercase.
TYPE_MAP = {
    "dmg": "dmg",
    "pkg": "pkg",
    "zip": "zip",
    "tbz": "tbz",
    "appindmg": "appindmg",
    "appindmginzip": "appindmginzip",
    "appinzip": "appinzip",
    "pkgindmg": "pkgindmg",
    "pkginzip": "pkginzip",
}
# Installomator uses camelCase variants; add them:
TYPE_MAP.update({
    "pkgindmg": "pkgindmg",
    "pkginzip": "pkginzip",
    "appindmg": "appindmg",
    "appinzip": "appinzip",
    "appindmginzip": "appindmginzip",
})
# Handle the actual mixed-case strings from the fragments
_TYPE_ALIASES = {
    "pkgindmg": "pkgindmg",
    "pkginzip": "pkginzip",
    "appindmg": "appindmg",
    "appinzip": "appinzip",
    "appindmginzip": "appindmginzip",
    "pkgindmginzip": "pkginzip",   # edge case normalisation
}
VALID_TYPES = set(TYPE_MAP.values())


def normalise_type(raw: str) -> str | None:
    """Lowercase and normalise Installomator type string to schema type."""
    lc = raw.lower().replace("-", "").replace("_", "")
    if lc in TYPE_MAP:
        return TYPE_MAP[lc]
    if lc in _TYPE_ALIASES:
        return _TYPE_ALIASES[lc]
    return None


def _normalise_label(stem: str) -> str:
    """Convert a fragment filename stem to a schema-valid label (lowercase kebab-case)."""
    return stem.lower().replace("_", "-")


def parse_fragment(path: Path) -> dict:
    """Extract fields from a single fragment .sh file."""
    text = path.read_text(errors="replace")

    def first_match(pattern, flags=0):
        m = re.search(pattern, text, flags)
        return m.group(1).strip() if m else None

    # Normalise the label: schema requires ^[a-z0-9][a-z0-9-]*$ (lowercase, hyphens only)
    f: dict = {
        "label": _normalise_label(path.stem),
        "_original_stem": path.stem,
    }

    f["name"] = first_match(r'\bname\s*=\s*"([^"]*)"')
    f["type_raw"] = first_match(r'\btype\s*=\s*"([^"]*)"')
    f["expected_team_id"] = first_match(r'\bexpectedTeamID\s*=\s*"([^"]*)"')
    f["app_path_explicit"] = first_match(r'\bappPath\s*=\s*"([^"]*)"')
    f["has_update_tool"] = bool(re.search(r'\bupdateTool\s*=', text))
    f["_fragment_text"] = text  # kept for fallback source-URL extraction

    # MAUSource (Microsoft AutoUpdate XML feeds) — a common source-URL variable
    m = re.search(r'\bMAUSource\s*=\s*"(https://[^"]+)"', text)
    f["mau_source"] = m.group(1) if m else ""

    # downloadURL — capture the rest of the line after the assignment
    m = re.search(r"\bdownloadURL\s*=\s*(.+?)(?:\n|$)", text)
    f["download_url_raw"] = m.group(1).strip() if m else ""

    # appNewVersion — for version-source classification and resolved-source extraction
    m = re.search(r"\bappNewVersion\s*=\s*(.+?)(?:\n|$)", text)
    f["version_raw"] = m.group(1).strip() if m else ""

    # blockingProcesses — quoted names inside ( ... )
    m = re.search(r"\bblockingProcesses\s*=\s*\(([^)]*)\)", text, re.DOTALL)
    if m:
        procs = re.findall(r'"([^"]+)"', m.group(1))
        if not procs:
            # Unquoted single-word entries
            procs = [
                p.strip()
                for p in m.group(1).split()
                if p.strip() and not p.strip().startswith("#")
            ]
        f["blocking_processes"] = procs
    else:
        f["blocking_processes"] = []

    return f


def _extract_https_urls(text: str) -> list[str]:
    """
    Return https:// URLs found in text, excluding those with shell variable references.
    Also returns partial URLs truncated just before the first ${...} variable, so that
    labels with version-interpolated paths still yield a usable base URL.
    """
    results = []
    for m in re.finditer(r"https://[^\s\"'\\|>{}\n]+", text):
        raw_url = m.group(0).rstrip(".,;)")
        if "$" not in raw_url:
            results.append(raw_url)
        else:
            # Truncate at first shell variable reference to get the base URL/domain
            truncated = re.split(r"\$", raw_url)[0].rstrip("/?")
            if len(truncated) > len("https://") + 3:  # must have more than just domain
                results.append(truncated)
    return results


_DOWNLOAD_URL_FROM_GIT_RE = re.compile(
    r"""downloadURLFromGit\s+["']?([A-Za-z0-9_.-]+)["']?\s+["']?([A-Za-z0-9_.-]+)["']?""",
    re.IGNORECASE,
)


def _github_api_url(owner: str, repo: str) -> str:
    return f"https://api.github.com/repos/{owner}/{repo}/releases/latest"


def classify_download(raw: str, version_raw: str, fragment_text: str = "", mau_source: str = "") -> tuple:
    """
    Returns (method, url, strategy, source, error).

    method  : 'static' | 'resolved' | None
    url     : static URL string, or None
    strategy: resolved strategy string, or None
    source  : resolved source URL string, or None
    error   : failure description string, or None
    """
    if not raw:
        return None, None, None, None, "empty downloadURL"

    # --- downloadURLFromGit helper (GitHub releases) ---
    m = _DOWNLOAD_URL_FROM_GIT_RE.search(raw)
    if m:
        owner, repo = m.group(1), m.group(2)
        source = _github_api_url(owner, repo)
        return "resolved", None, "github-release", source, None

    # Resolved: command substitution OR references $appNewVersion / ${appNewVersion}
    # or any other shell variable substitution in the URL itself
    uses_cmd_sub = "$(" in raw
    uses_version_var = bool(re.search(r"\$\{?app(?:New|Full)Version|\$\{?pkgNew|\$\{?[a-zA-Z]+Version", raw))
    is_resolved = uses_cmd_sub or uses_version_var

    # --- STATIC ---
    if not is_resolved:
        url = raw.strip("\"'").strip()
        if not url.startswith("https://"):
            found = _extract_https_urls(raw)
            if found:
                url = found[0]
            else:
                return None, None, None, None, f"no https:// URL: {raw[:80]}"
        url = re.split(r"[\s\"'#]", url)[0].rstrip(".,;)")
        return "static", url, None, None, None

    # --- RESOLVED ---
    # Source URL priority:
    # 1. https:// URL inside the $() command substitution of downloadURL
    # 2. https:// URL from the appNewVersion/$appFullVersion command
    # 3. https:// URL from any variable command in the fragment
    source_candidates: list[str] = []

    if uses_cmd_sub:
        m2 = re.search(r"\$\((.+?)\)", raw, re.DOTALL)
        if m2:
            source_candidates = _extract_https_urls(m2.group(1))

    if not source_candidates and version_raw:
        # appNewVersion may be the source (e.g., warp, synologydriveclient)
        m2 = re.search(r"\$\((.+?)\)", version_raw, re.DOTALL)
        if m2:
            source_candidates = _extract_https_urls(m2.group(1))
        if not source_candidates:
            source_candidates = _extract_https_urls(version_raw)

    if not source_candidates and fragment_text:
        # Scan the whole fragment for the first command that fetches a URL —
        # used for labels with intermediate variables (warp, synologydriveclient, etc.)
        for cmd_m in re.finditer(r"\$\((.+?)\)", fragment_text, re.DOTALL):
            candidates = _extract_https_urls(cmd_m.group(1))
            if candidates:
                source_candidates = candidates
                break

    if not source_candidates and fragment_text:
        # Last resort: scan for variable definitions that hold https URLs
        # (e.g. baseURL="https://...", downloadPage="https://...", feedURL="https://...")
        var_defs = re.findall(r'\b\w+\s*=\s*"(https://[^"${}\s]+)"', fragment_text)
        if var_defs:
            source_candidates = [var_defs[0]]

    if not source_candidates:
        source_candidates = _extract_https_urls(raw)

    # MAUSource fallback (Microsoft AutoUpdate XML feeds)
    if not source_candidates and mau_source:
        source_candidates = [mau_source]

    if not source_candidates:
        return None, None, None, None, f"no source URL found: {raw[:80]}"

    source = source_candidates[0]
    strategy = _infer_strategy(raw, version_raw)
    return "resolved", None, strategy, source, None


def _infer_strategy(download_raw: str, version_raw: str) -> str:
    combined = download_raw + " " + version_raw
    if "api.github.com" in combined:
        return "github-release"
    if any(
        kw in combined.lower()
        for kw in ["appcast", "sparkle", "releaseNotes", "releases.xml", "/rss", "feed.xml", ".xml"]
    ) and "curl" in combined:
        # .xml check could be noisy; require curl too
        return "sparkle-appcast"
    if re.search(r"curl\s+-[a-zA-Z]*I[a-zA-Z]*L", combined):
        return "http-redirect"
    return "vendor-api"


def classify_version(version_raw: str, download_method: str) -> str:
    """Map appNewVersion logic to schema version.source enum."""
    if not version_raw:
        return "none"
    # Parsed from the redirect filename / Location header path segments
    if re.search(r"grep.*location|curl.*-[a-zA-Z]*I[a-zA-Z]*L.*location", version_raw, re.IGNORECASE):
        return "http-headers"
    # Parsed by stripping the URL (echo $downloadURL | sed …)
    if re.search(r"echo.*\$\{?downloadURL|\$\{?downloadURL.*sed", version_raw):
        return "download-filename"
    # Any other appNewVersion = there's an external fetch
    return "resolved-source"


def convert_fragment(
    path: Path,
    today: str,
    skip_existing: bool,
    out_dir: Path,
) -> tuple:
    """
    Returns (label, status, record_or_reason).

    status: 'ok' | 'skipped-existing' | 'failed'
    """
    f = parse_fragment(path)
    label = f["label"]

    # The output filename uses the normalised label; also check the original-stem name
    # so that re-runs over already-converted uppercase/underscore labels are idempotent.
    out_path = out_dir / f"{label}.json"
    original_stem = f.get("_original_stem", label)
    original_path = out_dir / f"{original_stem}.json"

    # Preserve already-written records (curated starters and earlier runs)
    if skip_existing and (out_path.exists() or original_path.exists()):
        # If the file only exists under the old (un-normalised) name, rename it now.
        if not out_path.exists() and original_path.exists():
            original_path.rename(out_path)
        return label, "skipped-existing", None

    # --- Validate required fields ---
    name = f.get("name")
    if not name:
        return label, "failed", "missing name"

    type_raw = f.get("type_raw") or ""
    ltype = normalise_type(type_raw)
    if not ltype:
        return label, "failed", f"unknown type: {type_raw!r}"

    team_id = f.get("expected_team_id") or ""
    if not TEAM_ID_RE.match(team_id):
        return label, "failed", f"invalid expectedTeamID: {team_id!r}"

    # --- app_path ---
    app_path = f.get("app_path_explicit")
    if not app_path:
        # Derive from name; keep the exact display name including spaces
        app_path = f"/Applications/{name}.app"
    if not re.match(r"^/Applications/.+\.app$", app_path):
        app_path = f"/Applications/{name}.app"

    # --- download ---
    method, static_url, strategy, source, dl_err = classify_download(
        f.get("download_url_raw", ""),
        f.get("version_raw", ""),
        f.get("_fragment_text", ""),
        f.get("mau_source", ""),
    )
    if dl_err or not method:
        return label, "failed", dl_err or "could not classify download"

    if method == "static":
        download: dict = {"method": "static", "url": static_url}
    else:
        download = {"method": "resolved", "strategy": strategy, "source": source}

    # --- version ---
    vsource = classify_version(f.get("version_raw", ""), method)
    version_obj: dict = {"source": vsource}

    # --- assemble record ---
    record: dict = {
        "label": label,
        "name": name,
        "type": ltype,
        "app_path": app_path,
        "expected_team_id": team_id,
        "download": download,
        "version": version_obj,
        "blocking_processes": f.get("blocking_processes", []),
        "pinned_sha256": None,
        "patched": {
            "allowlisted": False,
            "mirror": False,
            "reviewed_by": "installomator-import",
            "reviewed_at": today,
            "notes": (
                "Auto-converted from Installomator fragment. "
                "Team ID and URL require human review before setting allowlisted=true."
            ),
        },
    }

    return label, "ok", record


def main() -> int:
    ap = argparse.ArgumentParser(description="Convert Installomator fragments to the Patched label manifest.")
    ap.add_argument("--repo-root", default=".", help="Repo root (default: cwd)")
    ap.add_argument("--dry-run", action="store_true", help="Parse only; do not write files")
    ap.add_argument(
        "--no-skip-existing",
        action="store_true",
        help="Overwrite existing records (default: preserve them)",
    )
    args = ap.parse_args()

    root = Path(args.repo_root).resolve()
    fragments_dir = root / "engine" / "fragments" / "labels"
    out_dir = root / "engine" / "labels"
    today = date.today().isoformat()
    skip_existing = not args.no_skip_existing

    if not fragments_dir.is_dir():
        print(f"FATAL: fragments dir not found: {fragments_dir}", file=sys.stderr)
        return 2

    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    fragment_files = sorted(fragments_dir.glob("*.sh"))
    print(f"Input: {len(fragment_files)} fragment files in {fragments_dir}")
    if skip_existing:
        existing = list(out_dir.glob("*.json")) if out_dir.exists() else []
        print(f"       {len(existing)} existing record(s) will be preserved")

    ok_labels: list[str] = []
    skipped: list[str] = []
    failed: list[tuple[str, str]] = []

    for path in fragment_files:
        label, status, result = convert_fragment(path, today, skip_existing, out_dir)
        if status == "ok":
            if not args.dry_run:
                (out_dir / f"{label}.json").write_text(
                    json.dumps(result, indent=2, ensure_ascii=False) + "\n"
                )
            ok_labels.append(label)
        elif status == "skipped-existing":
            skipped.append(label)
        else:
            failed.append((label, result))

    total_in = len(fragment_files)
    total_out = len(ok_labels) + len(skipped)
    print(f"\nConversion summary:")
    print(f"  Fragment files in:   {total_in}")
    print(f"  Records written:     {len(ok_labels)}")
    print(f"  Preserved existing:  {len(skipped)}")
    print(f"  Failed (skipped):    {len(failed)}")
    print(f"  Total in engine/labels/: {total_out}")

    if failed:
        print(f"\nFailed labels ({len(failed)}):")
        for lbl, reason in sorted(failed):
            print(f"  ✗ {lbl}: {reason}")

    if args.dry_run:
        print("\n(dry-run: no files written)")
    else:
        print(f"\nRecords written to {out_dir}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
