#!/usr/bin/env python3
"""
upstream-diff.py — Daily upstream Installomator label-set diff (PAT-53).

Fetches the public Installomator label fragments from GitHub, diffs them against
the Patched label manifest, and writes a structured proposal report for human
review. This is one input signal among others — changes are NEVER auto-applied.

The upstream labels live at:
  https://github.com/Installomator/Installomator/tree/main/fragments/labels/
Each *.sh file is a bash case-statement fragment that declares:
  name, type, downloadURL, expectedTeamID, blockingProcesses, ...

The diff surfaces:
  - Labels present upstream but absent from the Patched manifest (potential additions)
  - Labels in both, where expectedTeamID diverges (upstream may have updated theirs)
  - Labels in both, where the primary download URL pattern diverges
  - Labels only in Patched (informational; not a problem)

Output: verifier/upstream-diff/YYYY-MM-DD.json + .md

IMPORTANT: These reports are proposals for human review — never auto-applied.

Requires: Python 3.6+ stdlib only (runs on Apple stock /usr/bin/python3 and
          GitHub Actions ubuntu-latest with no pip install step).

Usage:
    python3 verifier/upstream-diff.py [--labels-dir DIR] [--report-dir DIR]
                                       [--ref REF] [--dry-run] [--selftest]
"""

import argparse
import datetime
import json
import os
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path

UA = "PatchedUpdater-UpstreamDiff/0.1"
GITHUB_API = "https://api.github.com"
UPSTREAM_OWNER = "Installomator"
UPSTREAM_REPO = "Installomator"
UPSTREAM_LABELS_PATH = "fragments/labels"


def utcnow():
    """Return current UTC time as an ISO-8601 string."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# GitHub API helpers — pure stdlib, no pip deps
# --------------------------------------------------------------------------

def _gh_request(url):
    """Fetch a URL with a GitHub-friendly User-Agent. Returns raw bytes.

    REST API calls send GITHUB_TOKEN as a bearer token when set — in
    Actions the unauthenticated API rate limit (60/hr, shared across the
    runner IP pool) 403s the run (PAT-925). raw.githubusercontent.com
    fetches stay unauthenticated: they are not under the API limit.
    """
    headers = {"User-Agent": UA}
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith(GITHUB_API):
        headers["Authorization"] = "Bearer {}".format(token)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError("HTTP {} fetching {}: {}".format(e.code, url, e.reason)) from e
    except Exception as e:
        raise RuntimeError("Error fetching {}: {}".format(url, e)) from e


def _gh_api_json(path):
    """Call the GitHub REST API and return parsed JSON."""
    url = "{}{}".format(GITHUB_API, path)
    data = _gh_request(url)
    return json.loads(data)


def _gh_raw(owner, repo, ref, path):
    """Fetch raw file content from GitHub."""
    url = "https://raw.githubusercontent.com/{}/{}/{}/{}".format(owner, repo, ref, path)
    return _gh_request(url).decode("utf-8", errors="replace")


# --------------------------------------------------------------------------
# Fetch upstream labels
# --------------------------------------------------------------------------

# Regex to extract key fields from a .sh case-statement fragment.
# Each fragment looks like:
#   labelname)
#       name="App Name"
#       type="dmg"
#       downloadURL="https://..."
#       expectedTeamID="XXXXXXXXXX"
#       ;;
#
# Some fields may be absent (e.g. expectedTeamID omitted for open-source apps).
# We extract from the raw text using simple line-oriented regexes — robust
# enough for the structured fragment format.

_RE_NAME = re.compile(r'^\s*name="([^"]*)"', re.MULTILINE)
_RE_TYPE = re.compile(r'^\s*type="([^"]*)"', re.MULTILINE)
_RE_TEAM_ID = re.compile(r'^\s*expectedTeamID="([^"]*)"', re.MULTILINE)
# downloadURL may be a simple assignment or a multi-line conditional; capture
# the first static https:// value if present.
_RE_DOWNLOAD_URL = re.compile(r'^\s*downloadURL="(https://[^"]*)"', re.MULTILINE)


def _parse_fragment(label_name, content):
    """Parse one upstream .sh fragment into a structured dict."""
    def _first(pattern):
        m = pattern.search(content)
        return m.group(1).strip() if m else None

    return {
        "label": label_name,
        "name": _first(_RE_NAME),
        "type": _first(_RE_TYPE),
        "expected_team_id": _first(_RE_TEAM_ID),
        "download_url": _first(_RE_DOWNLOAD_URL),
    }


def _list_upstream_label_names(ref):
    """Return all label names from the upstream fragments/labels/ directory.

    Uses the Git Trees API, not the contents API: the contents API IGNORES
    per_page/page for directory listings (paginating loops forever on the
    same full listing until the rate limit 403s) AND caps the listing at
    1000 entries — upstream passed 1000 labels in 2026, so a contents
    listing is silently truncated (PAT-925). A tree fetch has no such cap;
    walk the path segments from the root tree to the labels tree.
    """
    tree_sha = ref  # the trees API accepts a branch/tag name for the root
    for segment in UPSTREAM_LABELS_PATH.split("/"):
        tree = _gh_api_json(
            "/repos/{}/{}/git/trees/{}".format(
                UPSTREAM_OWNER, UPSTREAM_REPO, tree_sha
            )
        )
        entry = next(
            (
                e for e in tree.get("tree", [])
                if e.get("path") == segment and e.get("type") == "tree"
            ),
            None,
        )
        if entry is None:
            raise RuntimeError(
                "Path segment {!r} of {} not found in upstream tree {}".format(
                    segment, UPSTREAM_LABELS_PATH, tree_sha
                )
            )
        tree_sha = entry["sha"]

    labels_tree = _gh_api_json(
        "/repos/{}/{}/git/trees/{}".format(UPSTREAM_OWNER, UPSTREAM_REPO, tree_sha)
    )
    if labels_tree.get("truncated"):
        raise RuntimeError(
            "Upstream {} tree listing is truncated (>100k entries?)".format(
                UPSTREAM_LABELS_PATH
            )
        )
    names = []
    for entry in labels_tree.get("tree", []):
        fname = entry.get("path", "")
        if entry.get("type") == "blob" and fname.endswith(".sh"):
            names.append(fname[:-3])  # strip .sh suffix → label name
    return names


def fetch_upstream_labels(ref="main"):
    """Fetch all upstream label fragments and return {label_name: parsed_dict}.

    Fetches the directory listing first, then retrieves each .sh file
    individually. This is network-intensive but correct — the monolithic
    Installomator.sh is ~600 KB and harder to parse reliably.
    """
    print("Fetching upstream label list (ref={})...".format(ref), file=sys.stderr)
    names = _list_upstream_label_names(ref)
    print("  Found {} upstream label fragments".format(len(names)), file=sys.stderr)

    upstream = {}
    errors = []
    for i, label_name in enumerate(names, 1):
        if i % 50 == 0 or i == len(names):
            print("  Fetching fragment {}/{}...".format(i, len(names)), file=sys.stderr)
        try:
            content = _gh_raw(
                UPSTREAM_OWNER, UPSTREAM_REPO, ref,
                "{}/{}.sh".format(UPSTREAM_LABELS_PATH, label_name)
            )
            upstream[label_name] = _parse_fragment(label_name, content)
        except Exception as e:
            errors.append("{}: {}".format(label_name, e))

    if errors:
        print("WARNING: failed to fetch {} fragments:".format(len(errors)), file=sys.stderr)
        for err in errors[:10]:
            print("  {}".format(err), file=sys.stderr)
        if len(errors) > 10:
            print("  ... and {} more".format(len(errors) - 10), file=sys.stderr)

    return upstream


# --------------------------------------------------------------------------
# Load Patched labels
# --------------------------------------------------------------------------

def load_patched_labels(labels_dir):
    """Load all Patched label JSON records. Returns {label_name: record}.
    Mirrors the load_labels() approach of verify.py (retired 2026-09-30,
    PAT-2304)."""
    files = sorted(labels_dir.glob("*.json"))
    if not files:
        sys.exit("FATAL: no label records in {}".format(labels_dir))
    labels = {}
    for f in files:
        try:
            rec = json.loads(f.read_text())
            name = rec.get("label")
            if name:
                labels[name] = rec
        except Exception as e:
            print("WARNING: could not parse {}: {}".format(f, e), file=sys.stderr)
    return labels


# --------------------------------------------------------------------------
# Diff logic
# --------------------------------------------------------------------------

def _patched_download_url(rec):
    """Extract the primary download URL from a Patched label record."""
    dl = rec.get("download", {})
    if dl.get("method") == "static":
        return dl.get("url")
    # For resolved labels, return the source hint if present
    return dl.get("source")


def diff_labels(upstream, patched):
    """Produce a structured diff between upstream and Patched label sets.

    Returns a dict with four categories:
      upstream_only    — in upstream, not in Patched (potential additions)
      team_id_diverged — both have it, expectedTeamID differs
      url_diverged     — both have it, primary download URL pattern differs
      patched_only     — in Patched, not in upstream (informational)
    """
    upstream_names = set(upstream)
    patched_names = set(patched)

    upstream_only = []
    for name in sorted(upstream_names - patched_names):
        u = upstream[name]
        upstream_only.append({
            "label": name,
            "upstream_name": u.get("name"),
            "upstream_type": u.get("type"),
            "upstream_team_id": u.get("expected_team_id"),
            "upstream_url": u.get("download_url"),
        })

    patched_only = []
    for name in sorted(patched_names - upstream_names):
        p = patched[name]
        patched_only.append({
            "label": name,
            "patched_name": p.get("name"),
            "patched_team_id": p.get("expected_team_id"),
        })

    team_id_diverged = []
    url_diverged = []
    for name in sorted(upstream_names & patched_names):
        u = upstream[name]
        p = patched[name]

        u_tid = u.get("expected_team_id") or ""
        p_tid = p.get("expected_team_id") or ""
        # Only flag if both sides have a Team ID and they differ
        if u_tid and p_tid and u_tid != p_tid:
            team_id_diverged.append({
                "label": name,
                "upstream_team_id": u_tid,
                "patched_team_id": p_tid,
                "upstream_name": u.get("name"),
                "patched_name": p.get("name"),
                "recommendation": (
                    "Upstream changed Team ID — verify which is correct before "
                    "updating Patched record."
                ),
            })

        u_url = u.get("download_url") or ""
        p_url = _patched_download_url(p) or ""
        # Compare URL patterns; ignore if either is empty (resolved labels may
        # have no static URL on the upstream side)
        if u_url and p_url and u_url != p_url:
            url_diverged.append({
                "label": name,
                "upstream_url": u_url,
                "patched_url": p_url,
                "upstream_name": u.get("name"),
                "patched_name": p.get("name"),
                "recommendation": (
                    "Download URL diverged — check if upstream moved the source; "
                    "verify before updating Patched record."
                ),
            })

    return {
        "upstream_only": upstream_only,
        "team_id_diverged": team_id_diverged,
        "url_diverged": url_diverged,
        "patched_only": patched_only,
    }


# --------------------------------------------------------------------------
# Write report
# --------------------------------------------------------------------------

def write_report(diff, report_dir, upstream_ref, upstream_count, patched_count):
    """Write YYYY-MM-DD.json + .md to report_dir. Returns (json_path, md_path)."""
    report_dir.mkdir(parents=True, exist_ok=True)
    day = datetime.date.today().isoformat()

    # ---- JSON ----
    doc = {
        "generated_at": utcnow(),
        "date": day,
        "upstream_ref": upstream_ref,
        "upstream_label_count": upstream_count,
        "patched_label_count": patched_count,
        "summary": {
            "upstream_only": len(diff["upstream_only"]),
            "team_id_diverged": len(diff["team_id_diverged"]),
            "url_diverged": len(diff["url_diverged"]),
            "patched_only": len(diff["patched_only"]),
        },
        "diff": diff,
        "note": (
            "These are proposals for human review — never auto-applied. "
            "A human must evaluate each divergence and decide what (if anything) "
            "to update in the Patched label manifest."
        ),
    }
    json_path = report_dir / "{}.json".format(day)
    json_path.write_text(json.dumps(doc, indent=2) + "\n")

    # ---- Markdown ----
    lines = [
        "# Upstream label diff — {}".format(day),
        "",
        "> **These are proposals for human review — never auto-applied.**",
        "> A human must evaluate each divergence and decide what (if anything)",
        "> to update in the Patched label manifest.",
        "",
        "Generated: {}".format(doc["generated_at"]),
        "Upstream ref: `{}` ({} labels)".format(upstream_ref, upstream_count),
        "Patched manifest: {} labels".format(patched_count),
        "",
        "## Summary",
        "",
        "| Category | Count |",
        "|---|---|",
        "| Upstream only (potential new additions) | {} |".format(len(diff["upstream_only"])),
        "| Team ID diverged | {} |".format(len(diff["team_id_diverged"])),
        "| Download URL diverged | {} |".format(len(diff["url_diverged"])),
        "| Patched only (informational) | {} |".format(len(diff["patched_only"])),
        "",
    ]

    # Team ID divergences — highest priority
    if diff["team_id_diverged"]:
        lines += [
            "## Team ID divergences (action required — verify before updating)",
            "",
            "| Label | Upstream Team ID | Patched Team ID | Recommendation |",
            "|---|---|---|---|",
        ]
        for item in diff["team_id_diverged"]:
            lines.append(
                "| `{}` | `{}` | `{}` | {} |".format(
                    item["label"], item["upstream_team_id"],
                    item["patched_team_id"], item["recommendation"]
                )
            )
        lines.append("")

    # URL divergences
    if diff["url_diverged"]:
        lines += [
            "## Download URL divergences (review — upstream may have moved source)",
            "",
            "| Label | Upstream URL | Patched URL | Recommendation |",
            "|---|---|---|---|",
        ]
        for item in diff["url_diverged"]:
            lines.append(
                "| `{}` | `{}` | `{}` | {} |".format(
                    item["label"], item["upstream_url"],
                    item["patched_url"], item["recommendation"]
                )
            )
        lines.append("")

    # Upstream-only labels
    if diff["upstream_only"]:
        lines += [
            "## Upstream-only labels (not in Patched manifest)",
            "",
            "These labels exist upstream but are not in the Patched manifest. "
            "Consider adding if relevant.",
            "",
            "| Label | Name | Type | Team ID | Download URL |",
            "|---|---|---|---|---|",
        ]
        for item in diff["upstream_only"]:
            lines.append(
                "| `{}` | {} | {} | `{}` | {} |".format(
                    item["label"],
                    item["upstream_name"] or "—",
                    item["upstream_type"] or "—",
                    item["upstream_team_id"] or "—",
                    item["upstream_url"] or "—",
                )
            )
        lines.append("")

    # Patched-only labels
    if diff["patched_only"]:
        lines += [
            "## Patched-only labels (informational)",
            "",
            "These labels exist in the Patched manifest but not in the upstream. "
            "No action required.",
            "",
            "| Label | Name | Team ID |",
            "|---|---|---|",
        ]
        for item in diff["patched_only"]:
            lines.append(
                "| `{}` | {} | `{}` |".format(
                    item["label"],
                    item["patched_name"] or "—",
                    item["patched_team_id"] or "—",
                )
            )
        lines.append("")

    if not any([diff["upstream_only"], diff["team_id_diverged"],
                diff["url_diverged"], diff["patched_only"]]):
        lines += [
            "## No divergences found",
            "",
            "Upstream and Patched label sets are in sync.",
            "",
        ]

    md_path = report_dir / "{}.md".format(day)
    md_path.write_text("\n".join(lines) + "\n")
    return json_path, md_path


# --------------------------------------------------------------------------
# Self-test — exercises diff logic with no network
# --------------------------------------------------------------------------

def selftest():
    all_pass = True

    # --- _parse_fragment ---
    print("  _parse_fragment:")
    sample_fragment = (
        'googlechrome)\n'
        '    name="Google Chrome"\n'
        '    type="dmg"\n'
        '    downloadURL="https://dl.google.com/chrome/mac/universal/stable/GGRO/googlechrome.dmg"\n'
        '    expectedTeamID="EQHXZ8M8AV"\n'
        '    ;;\n'
    )
    parsed = _parse_fragment("googlechrome", sample_fragment)
    parse_cases = [
        ("label", parsed["label"], "googlechrome"),
        ("name", parsed["name"], "Google Chrome"),
        ("type", parsed["type"], "dmg"),
        ("expected_team_id", parsed["expected_team_id"], "EQHXZ8M8AV"),
        ("download_url", parsed["download_url"],
         "https://dl.google.com/chrome/mac/universal/stable/GGRO/googlechrome.dmg"),
    ]
    for field, got, expected in parse_cases:
        ok = got == expected
        if not ok:
            all_pass = False
        print("    [{}] {}: expected {!r}, got {!r}".format(
            "PASS" if ok else "FAIL", field, expected, got))

    # Fragment with no expectedTeamID (open-source label pattern)
    oss_fragment = (
        'anki)\n'
        '    name="Anki"\n'
        '    type="dmg"\n'
        '    downloadURL="https://github.com/ankitects/anki/releases/download/24.06/anki-24.06-mac-apple-qt6.dmg"\n'
        '    ;;\n'
    )
    oss_parsed = _parse_fragment("anki", oss_fragment)
    ok = oss_parsed["expected_team_id"] is None
    if not ok:
        all_pass = False
    print("    [{}] missing team_id -> None: got {!r}".format(
        "PASS" if ok else "FAIL", oss_parsed["expected_team_id"]))

    # Fragment with conditional downloadURL — should capture first https:// value
    resolved_fragment = (
        '8x8)\n'
        '    name="8x8 Work"\n'
        '    type="dmg"\n'
        '    expectedTeamID="FC967L3QRG"\n'
        '    if [[ "$arch" == "arm64" ]]; then\n'
        '        downloadURL="https://example.com/arm64/8x8.dmg"\n'
        '    fi\n'
        '    ;;\n'
    )
    resolved_parsed = _parse_fragment("8x8", resolved_fragment)
    ok = resolved_parsed["download_url"] == "https://example.com/arm64/8x8.dmg"
    if not ok:
        all_pass = False
    print("    [{}] conditional url: got {!r}".format(
        "PASS" if ok else "FAIL", resolved_parsed["download_url"]))

    # --- diff_labels ---
    print("  diff_labels:")

    upstream_mock = {
        "chrome": {
            "label": "chrome", "name": "Google Chrome", "type": "dmg",
            "expected_team_id": "EQHXZ8M8AV",
            "download_url": "https://dl.google.com/chrome.dmg",
        },
        "slack": {
            "label": "slack", "name": "Slack", "type": "dmg",
            "expected_team_id": "BQR82RBBHL",
            "download_url": "https://files.slack.com/desktop-releases/mac/Slack.dmg",
        },
        "newapp": {
            "label": "newapp", "name": "New App", "type": "pkg",
            "expected_team_id": "NEWTEAMID01",
            "download_url": "https://example.com/newapp.pkg",
        },
        "teamidchanged": {
            "label": "teamidchanged", "name": "Changed App", "type": "dmg",
            "expected_team_id": "NEWTEAMIDXX",
            "download_url": "https://example.com/app.dmg",
        },
        "urlchanged": {
            "label": "urlchanged", "name": "URL Changed App", "type": "dmg",
            "expected_team_id": "URLTEAMID01",
            "download_url": "https://new-cdn.example.com/app.dmg",
        },
    }

    patched_mock = {
        "chrome": {
            "label": "chrome", "name": "Google Chrome",
            "expected_team_id": "EQHXZ8M8AV",
            "download": {"method": "static",
                         "url": "https://dl.google.com/chrome.dmg"},
        },
        "slack": {
            "label": "slack", "name": "Slack",
            "expected_team_id": "BQR82RBBHL",
            "download": {"method": "static",
                         "url": "https://files.slack.com/desktop-releases/mac/Slack.dmg"},
        },
        "patchedonly": {
            "label": "patchedonly", "name": "Patched Only App",
            "expected_team_id": "PATCHEDONLY1",
            "download": {"method": "static", "url": "https://example.com/p.dmg"},
        },
        "teamidchanged": {
            "label": "teamidchanged", "name": "Changed App",
            "expected_team_id": "OLDTEAMIDXX",
            "download": {"method": "static",
                         "url": "https://example.com/app.dmg"},
        },
        "urlchanged": {
            "label": "urlchanged", "name": "URL Changed App",
            "expected_team_id": "URLTEAMID01",
            "download": {"method": "static",
                         "url": "https://old-cdn.example.com/app.dmg"},
        },
    }

    diff = diff_labels(upstream_mock, patched_mock)

    # upstream_only: newapp
    got_uo = [x["label"] for x in diff["upstream_only"]]
    ok = got_uo == ["newapp"]
    if not ok:
        all_pass = False
    print("    [{}] upstream_only labels: expected ['newapp'], got {}".format(
        "PASS" if ok else "FAIL", got_uo))

    # patched_only: patchedonly
    got_po = [x["label"] for x in diff["patched_only"]]
    ok = got_po == ["patchedonly"]
    if not ok:
        all_pass = False
    print("    [{}] patched_only labels: expected ['patchedonly'], got {}".format(
        "PASS" if ok else "FAIL", got_po))

    # team_id_diverged: teamidchanged
    got_tid = [x["label"] for x in diff["team_id_diverged"]]
    ok = got_tid == ["teamidchanged"]
    if not ok:
        all_pass = False
    print("    [{}] team_id_diverged labels: expected ['teamidchanged'], got {}".format(
        "PASS" if ok else "FAIL", got_tid))

    # url_diverged: urlchanged
    got_ud = [x["label"] for x in diff["url_diverged"]]
    ok = got_ud == ["urlchanged"]
    if not ok:
        all_pass = False
    print("    [{}] url_diverged labels: expected ['urlchanged'], got {}".format(
        "PASS" if ok else "FAIL", got_ud))

    # matching labels (chrome, slack) not in any divergence list
    all_diverged = (
        set(x["label"] for x in diff["team_id_diverged"]) |
        set(x["label"] for x in diff["url_diverged"]) |
        set(x["label"] for x in diff["upstream_only"]) |
        set(x["label"] for x in diff["patched_only"])
    )
    ok = "chrome" not in all_diverged and "slack" not in all_diverged
    if not ok:
        all_pass = False
    print("    [{}] matching labels not flagged: chrome/slack absent from divergences".format(
        "PASS" if ok else "FAIL"))

    # team_id_diverged values
    if diff["team_id_diverged"]:
        item = diff["team_id_diverged"][0]
        ok = (item["upstream_team_id"] == "NEWTEAMIDXX" and
              item["patched_team_id"] == "OLDTEAMIDXX")
        if not ok:
            all_pass = False
        print("    [{}] team_id_diverged values: upstream={!r} patched={!r}".format(
            "PASS" if ok else "FAIL", item["upstream_team_id"], item["patched_team_id"]))

    # url_diverged values
    if diff["url_diverged"]:
        item = diff["url_diverged"][0]
        ok = ("new-cdn" in (item["upstream_url"] or "") and
              "old-cdn" in (item["patched_url"] or ""))
        if not ok:
            all_pass = False
        print("    [{}] url_diverged values: upstream={!r} patched={!r}".format(
            "PASS" if ok else "FAIL", item["upstream_url"], item["patched_url"]))

    # --- _patched_download_url ---
    print("  _patched_download_url:")
    url_cases = [
        ({"download": {"method": "static", "url": "https://a.example.com/app.pkg"}},
         "https://a.example.com/app.pkg"),
        ({"download": {"method": "resolved", "source": "https://vendor.example.com/page"}},
         "https://vendor.example.com/page"),
        ({"download": {}}, None),
    ]
    for rec, expected in url_cases:
        got = _patched_download_url(rec)
        ok = got == expected
        if not ok:
            all_pass = False
        print("    [{}] {}: expected {!r}, got {!r}".format(
            "PASS" if ok else "FAIL", rec["download"].get("method", "?"), expected, got))

    print("selftest: ALL PASS" if all_pass else "selftest: FAILURES")
    return 0 if all_pass else 1


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Patched Updater — upstream Installomator label-set diff (PAT-53)"
    )
    ap.add_argument("--labels-dir", default="engine/labels",
                    help="Path to Patched label manifest directory (default: engine/labels)")
    ap.add_argument("--report-dir", default="verifier/upstream-diff",
                    help="Directory to write dated reports (default: verifier/upstream-diff)")
    ap.add_argument("--ref", default="main",
                    help="Upstream git ref to diff against (default: main)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Fetch and diff but do not write report files")
    ap.add_argument("--selftest", action="store_true",
                    help="Run offline unit tests and exit")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    labels_dir = Path(args.labels_dir)
    report_dir = Path(args.report_dir)

    print("Loading Patched labels...", file=sys.stderr)
    patched = load_patched_labels(labels_dir)
    print("  Loaded {} Patched labels".format(len(patched)), file=sys.stderr)

    upstream = fetch_upstream_labels(ref=args.ref)

    print("Diffing label sets...", file=sys.stderr)
    diff = diff_labels(upstream, patched)

    summary = {
        "upstream_only": len(diff["upstream_only"]),
        "team_id_diverged": len(diff["team_id_diverged"]),
        "url_diverged": len(diff["url_diverged"]),
        "patched_only": len(diff["patched_only"]),
    }
    print(
        "  upstream_only={}  team_id_diverged={}  url_diverged={}  patched_only={}".format(
            summary["upstream_only"], summary["team_id_diverged"],
            summary["url_diverged"], summary["patched_only"]
        ),
        file=sys.stderr,
    )

    has_divergences = (
        summary["team_id_diverged"] > 0 or
        summary["url_diverged"] > 0 or
        summary["upstream_only"] > 0
    )

    if args.dry_run:
        print("--dry-run: skipping report write", file=sys.stderr)
        print(json.dumps({"summary": summary, "diff": diff}, indent=2))
        return 0

    json_path, md_path = write_report(
        diff, report_dir, args.ref, len(upstream), len(patched)
    )
    print("Report written: {}".format(json_path), file=sys.stderr)
    print("Report written: {}".format(md_path), file=sys.stderr)

    # Exit 2 when actionable divergences found (Team ID or URL changes or
    # upstream-only labels), so the workflow can distinguish "divergences found"
    # from a script error (exit 1).
    if has_divergences:
        print(
            "Divergences found — see report for proposals (human review required).",
            file=sys.stderr,
        )
        return 2

    print("No actionable divergences.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
