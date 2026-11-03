#!/usr/bin/env python3
"""
done_audit.py — done-without-evidence detector (PAT-985).

Why this exists: this estate's rule is "Done means operating, not merged"
(root CLAUDE.md). Linear's GitHub integration flips an issue to Done the
moment its linked PR merges — branch names carry the issue identifier (e.g.
andy/pat-954-slug), so the automation fires with total reliability. That
setting has proven hard to locate, and it would not help retroactively or
for a manual close either. So this tool does not try to prevent the false
Done; it detects it after the fact, which also catches manual closes and
pre-existing rot that a settings change never would.

Once a day (via .github/workflows/done-audit.yml) it pulls every issue on
team PAT completed within a lookback window, flags the ones that look
runtime-affecting (something that must actually run somewhere to have any
effect) but carry no comment evidence that anyone ever confirmed it running,
and posts the list as a comment on PAT-985 itself — this ticket, so the
detector's own findings live where the work is tracked.

This is a heuristic over titles/descriptions/comment text, not a proof. An
earlier automated sweep in this estate had roughly 4 of its top 6 findings
wrong when it relied on PR titles and comment text as a proxy for reality —
expect a similar false-positive rate here. Every flagged issue is reported
as "worth checking", never "broken", and carries the cheapest concrete check
that would settle it. Findings are sorted with protective work (backups,
monitoring, alerting, security gates, credential handling, DR) first, since
a false Done there is far more dangerous than on a UI tweak.

Detection logic
----------------
Runtime-affecting: a `repo:*` label, OR title/description mentioning one of
a fixed keyword list (deploy, monitor, alert, backup, timer, cron, systemd,
migration, endpoint, agent, certificate, credential, env var, scheduled).
Pure documentation / test-only / no-behaviour-change signals are explicitly
excluded UNLESS a `repo:*` label is also present (the label is a stronger,
explicit signal that overrides a text-based exclusion guess).

Evidence: scanning each comment (not the concatenation of all comments, so a
commit SHA has to appear *alongside* deploy language in the same comment,
not just somewhere in the thread) for: a 7-40 hex commit SHA plus deploy
language; "deployed" / "verified" / "confirmed on"; a Patched hostname
(patched-api-01 / patched-prod-01 / patched-portal-01, or a numbered
sibling); systemctl / HTTP 200 / snapshot / exit 0; or a fenced code block
(the cheapest available proxy for "a log line quoted from a real run" — the
weakest of these signals and the most likely to over-forgive; see the module
docstring note in _comment_evidence()). "merged" or "PR #123" alone matches
none of these and is correctly not evidence.

Flag = runtime-affecting AND no evidence.

State / noise control
----------------------
No git-committed state file: the "did the flagged set change since last
run" check reads the previous run's own marker back out of PAT-985's most
recent audit comment (an HTML-comment fingerprint of the sorted flagged
identifier set, same idea as verifier/alerting.py's finding markers). If the
current run's fingerprint matches, execute() does not post — a daily
comment repeating yesterday's list is noise that trains people to ignore it.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

DEFAULT_TEAM = "PAT"
DEFAULT_TICKET = "PAT-985"
DEFAULT_LOOKBACK_DAYS = 30

_MARKER_PREFIX = "patched-done-audit"
_MARKER_RE = re.compile(re.escape(_MARKER_PREFIX) + r":([0-9a-f]{16})")

_IDENTIFIER_RE = re.compile(r"^([A-Za-z]+)-(\d+)$")

# --------------------------------------------------------------------------
# Runtime-affecting classification
# --------------------------------------------------------------------------

# Leading-boundary only (not \bword\b) so "deploy" also catches "deployed" /
# "deployment", "monitor" also catches "monitoring", etc.
_RUNTIME_KEYWORDS = [
    "deploy", "monitor", "alert", "backup", "timer", "cron", "systemd",
    "migrat", "endpoint", "agent", "certificat", "credential",
    "env var", "environment variable", "schedul",
    # Verification and integrity controls. Added after validating the
    # classifier against known ground truth: PAT-495 ("SHA-256 content hash
    # pinning via signed catalogue") went unflagged despite being the most
    # consequential false Done found — a security control inert for five
    # weeks because the endpoint it depends on returned 404. It carried no
    # repo: label and used none of the deployment vocabulary above.
    # Controls of this kind describe what they protect, not where they run,
    # so they need their own stems or the detector misses exactly the class
    # of work where a false Done is most dangerous.
    # Kept deliberately narrow. An earlier attempt used bare stems like
    # "sign", "gate", "verif", "hash" and "rotat"; against the real corpus
    # that classified 372 of 402 completed issues as runtime-affecting,
    # because "sign" matches "signal", "gate" matches "gateway", and the
    # rest are simply common words here. A classifier that flags everything
    # discriminates nothing. These are multi-word or distinctive enough to
    # mean what they say.
    "signed catalogue", "signing key", "sign the", "signature",
    "hash pinning", "pinned sha", "pinned_sha", "content hash",
    "allowlist", "tamper", "sandboxing", "code signing",
]
_RUNTIME_KEYWORD_RE = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in _RUNTIME_KEYWORDS) + r")")

_DOC_TEST_PREFIX_RE = re.compile(
    r"^\s*(docs?|documentation|tests?|typo)(\([^)]*\))?\s*:", re.IGNORECASE)

_EXCLUDE_PHRASES = [
    "no runtime effect",
    "no behaviour change",
    "no behavior change",
    "documentation only",
    "test-only",
    "tests only",
]


def _issue_text(issue: dict) -> str:
    return f"{issue.get('title', '')}\n{issue.get('description', '') or ''}"


def is_runtime_affecting(issue: dict) -> tuple[bool, list[str]]:
    """Return (runtime_affecting, reasons). Pure — no network."""
    labels = [(lbl or "").lower() for lbl in issue.get("labels", [])]
    repo_label = next((lbl for lbl in labels if lbl.startswith("repo:")), None)

    text = _issue_text(issue)
    text_lower = text.lower()

    doc_test_prefix = bool(_DOC_TEST_PREFIX_RE.match(issue.get("title", "") or ""))
    explicit_exclude = any(p in text_lower for p in _EXCLUDE_PHRASES)

    if (doc_test_prefix or explicit_exclude) and not repo_label:
        return False, []

    reasons = []
    if repo_label:
        reasons.append(f"label '{repo_label}'")

    matched = sorted({m.group(1) for m in _RUNTIME_KEYWORD_RE.finditer(text_lower)})
    if matched:
        reasons.append("keyword(s): " + ", ".join(matched))

    return bool(reasons), reasons


# --------------------------------------------------------------------------
# Evidence scanning
# --------------------------------------------------------------------------

_SHA_RE = re.compile(r"\b[0-9a-f]{7,40}\b", re.IGNORECASE)
_DEPLOY_WORDS = ["deploy", "shipped", "rolled out", "running on", "live on", "pushed to"]
_STRONG_PHRASES = ["deployed", "verified", "confirmed on"]
_HOSTNAME_RE = re.compile(r"\bpatched-(?:api|prod|portal)-\d+\b", re.IGNORECASE)
_EXEC_MARKERS = ["systemctl", "http 200", "snapshot", "exit 0"]
_CODE_FENCE_RE = re.compile(r"```")


def _comment_evidence(comment: str) -> str | None:
    """Return a short human-readable reason string if `comment` carries an
    evidence marker, else None. A comment saying only "merged" or "PR #123"
    matches nothing here — that is deliberate; see module docstring."""
    lower = comment.lower()

    sha_match = _SHA_RE.search(comment)
    if sha_match and any(w in lower for w in _DEPLOY_WORDS):
        return f"commit SHA `{sha_match.group(0)}` alongside deploy language"

    for phrase in _STRONG_PHRASES:
        if phrase in lower:
            return f"phrase '{phrase}'"

    host_match = _HOSTNAME_RE.search(comment)
    if host_match:
        return f"hostname `{host_match.group(0)}`"

    for marker in _EXEC_MARKERS:
        if marker in lower:
            return f"execution marker '{marker}'"

    # Weakest signal: a fenced code block is the cheapest available proxy
    # for "a log line quoted from a real run", but a code block can just as
    # easily be a *proposed* command that was never run. Kept because
    # omitting it would silently under-detect the "pasted terminal output"
    # case the ticket explicitly asks for; flagged here as the most likely
    # source of false negatives (i.e. things that should be flagged but
    # aren't, because someone pasted a plan rather than a result).
    if _CODE_FENCE_RE.search(comment):
        return "quoted code block (possible log output)"

    return None


def find_evidence(comments: list[str]) -> tuple[bool, list[str]]:
    """Return (has_evidence, reasons) — reasons is one entry per comment
    that matched, in comment order."""
    reasons = []
    for c in comments:
        r = _comment_evidence(c or "")
        if r:
            reasons.append(r)
    return bool(reasons), reasons


# --------------------------------------------------------------------------
# Consequence tiering + suggested check
# --------------------------------------------------------------------------

_PROTECTIVE_KEYWORDS = [
    "backup", "monitor", "alert", "security", "credential",
    "disaster recovery", "encrypt", "tls", "certificat", "secret", "gate",
]


def is_protective(issue: dict) -> bool:
    text = _issue_text(issue).lower()
    return any(k in text for k in _PROTECTIVE_KEYWORDS)


# Checked in order; first match wins. Ordered so protective categories
# (backup/credential/monitor/alert/certificate) resolve before generic
# infra ones, matching the "protective work first" sort.
_CHECK_SUGGESTIONS = [
    ("backup", "confirm a backup has actually run and produced a snapshot/output on the target host"),
    ("credential", "ssh the host and confirm the credential/secret is actually present in the target environment, not just read by the code"),
    ("env var", "ssh the host and confirm the env var is set in the target environment, not just read by the code"),
    ("environment variable", "ssh the host and confirm the env var is set in the target environment, not just read by the code"),
    ("monitor", "confirm the monitor has executed at least once and produced a real signal (a log line or delivered alert)"),
    ("alert", "confirm the alert has actually fired at least once (a log line or delivered message), not just that it would fire"),
    ("certificat", "confirm the certificate is installed/renewed on the target host and has not expired"),
    ("systemd", "ssh the host and confirm the unit file carries the expected directives and has actually run (systemctl status)"),
    ("timer", "ssh the host and confirm the timer unit is enabled and has fired (systemctl list-timers)"),
    ("cron", "ssh the host and confirm the cron job is installed and has run"),
    ("migrat", "confirm the migration ran against the target database, not just that it merged"),
    ("endpoint", "curl the live endpoint and confirm it returns the expected response"),
    ("agent", "confirm the agent build is actually live on a real endpoint, not just merged"),
    ("deploy", "confirm the deployed SHA is actually running on the target host, not just that CI went green"),
]


def suggest_check(issue: dict) -> str:
    text = _issue_text(issue).lower()
    for key, message in _CHECK_SUGGESTIONS:
        if key in text:
            return message
    return "confirm on the target host/environment that this change is actually in effect"


# --------------------------------------------------------------------------
# Per-issue classification + full-run audit
# --------------------------------------------------------------------------

def classify_issue(issue: dict) -> dict:
    """Pure classification of one issue dict (as returned by
    LinearClient.get_completed_issues()). No network."""
    runtime_affecting, runtime_reasons = is_runtime_affecting(issue)

    has_evidence, evidence_reasons = (False, [])
    if runtime_affecting:
        has_evidence, evidence_reasons = find_evidence(issue.get("comments", []))

    flagged = runtime_affecting and not has_evidence

    return {
        "identifier": issue["identifier"],
        "title": issue.get("title", ""),
        "url": issue.get("url", ""),
        "completedAt": issue.get("completedAt"),
        "runtime_affecting": runtime_affecting,
        "runtime_reasons": runtime_reasons,
        "has_evidence": has_evidence,
        "evidence_reasons": evidence_reasons,
        "flagged": flagged,
        "protective": is_protective(issue),
        "suggested_check": suggest_check(issue) if flagged else None,
    }


def _sort_key(c: dict):
    tier = 0 if c["protective"] else 1
    try:
        ts = datetime.fromisoformat((c["completedAt"] or "").replace("Z", "+00:00")).timestamp()
    except ValueError:
        ts = 0.0
    return (tier, -ts)


def run_audit(issues: list[dict]) -> dict:
    """Classify every issue and return {counts, flagged}. `flagged` is
    sorted protective-first, most-recently-completed-first within tier."""
    classified = [classify_issue(i) for i in issues]
    runtime_affecting = [c for c in classified if c["runtime_affecting"]]
    flagged = sorted((c for c in classified if c["flagged"]), key=_sort_key)
    counts = {
        "examined": len(classified),
        "runtime_affecting": len(runtime_affecting),
        "flagged": len(flagged),
    }
    return {"counts": counts, "flagged": flagged}


# --------------------------------------------------------------------------
# State hash / marker (no git-committed state — see module docstring)
# --------------------------------------------------------------------------

def compute_state_hash(flagged: list[dict]) -> str:
    identifiers = sorted(c["identifier"] for c in flagged)
    payload = json.dumps(identifiers, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _marker(state_hash: str) -> str:
    return f"<!-- {_MARKER_PREFIX}:{state_hash} -->"


def extract_previous_hash(comments: list[dict]) -> str | None:
    """comments: list of {'body', 'createdAt'}. Return the state hash from
    the most recent comment (by createdAt) that carries our marker, or None
    if no prior audit comment exists."""
    candidates = []
    for c in comments:
        m = _MARKER_RE.search(c.get("body") or "")
        if m:
            candidates.append((c.get("createdAt") or "", m.group(1)))
    if not candidates:
        return None
    candidates.sort()
    return candidates[-1][1]


# --------------------------------------------------------------------------
# Report body
# --------------------------------------------------------------------------

def build_comment_body(flagged: list[dict], counts: dict, run_url: str,
                        lookback_days: int, state_hash: str) -> str:
    lines = [
        _marker(state_hash),
        "",
        f"**Done-without-evidence sweep** (lookback {lookback_days} days)",
        "",
        f"Examined **{counts['examined']}** completed issues · "
        f"**{counts['runtime_affecting']}** look runtime-affecting · "
        f"**{counts['flagged']}** worth checking.",
        "",
    ]
    if not flagged:
        lines.append("Nothing flagged this run.")
    else:
        lines.append(
            "Sorted by consequence (protective work — backups, monitoring, "
            "alerting, security gates, credential handling, DR — first). "
            "These are **worth checking**, not confirmed broken.")
        lines.append("")
        _REPORT_CAP = 15
        shown = flagged[:_REPORT_CAP]
        if len(flagged) > _REPORT_CAP:
            lines.append(
                f"Showing the top **{_REPORT_CAP}** by consequence. "
                f"{len(flagged) - _REPORT_CAP} more are below the cut — a list "
                f"nobody reads is the same as no list, so the tail is counted "
                f"rather than printed."
            )
            lines.append("")
        for c in shown:
            tag = "protective" if c["protective"] else "other"
            lines.append(f"- **[{c['identifier']}]({c['url']})** ({tag}) — {c['title']}")
            lines.append(f"  - Why it looks runtime-affecting: {'; '.join(c['runtime_reasons'])}")
            lines.append(f"  - Cheapest check: {c['suggested_check']}")
    lines += [
        "",
        "_Heuristic over titles/descriptions/comments, not proof — false "
        "positives expected. See verifier/done_audit.py's module docstring._",
        f"_Workflow run: {run_url}_",
    ]
    return "\n".join(lines)


def _workflow_run_url() -> str:
    server, repo, run_id = (os.environ.get("GITHUB_SERVER_URL"),
                             os.environ.get("GITHUB_REPOSITORY"),
                             os.environ.get("GITHUB_RUN_ID"))
    if server and repo and run_id:
        return f"{server}/{repo}/actions/runs/{run_id}"
    return "(no workflow run URL — not running in GitHub Actions)"


def _parse_identifier(identifier: str) -> tuple[str, int]:
    m = _IDENTIFIER_RE.match(identifier.strip())
    if not m:
        raise ValueError(f"not a valid issue identifier: {identifier!r}")
    return m.group(1).upper(), int(m.group(2))


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def execute(client, team: str, ticket: str, lookback_days: int,
            dry_run: bool = False, now: datetime | None = None) -> dict:
    """Run one audit pass against `client` (a LinearClient, or a test stub
    exposing the same get_completed_issues / get_issue_by_number /
    create_comment surface) and return a summary dict:
    {counts, flagged, state_hash, previous_hash, posted}.

    Posts a new comment on `ticket` iff the flagged set's fingerprint
    differs from the most recent marker found in that issue's own comments,
    and dry_run is False. Raises LookupError if `ticket` cannot be found —
    that is a hard failure, not a thing to silently skip.
    """
    now = now or datetime.now(timezone.utc)
    completed_after = (now - timedelta(days=lookback_days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    issues = list(client.get_completed_issues(team, completed_after))
    audit = run_audit(issues)
    counts, flagged = audit["counts"], audit["flagged"]
    state_hash = compute_state_hash(flagged)

    team_key, number = _parse_identifier(ticket)
    ticket_issue = client.get_issue_by_number(team_key, number)
    if not ticket_issue:
        raise LookupError(f"could not find {ticket} to post the report on")

    previous_hash = extract_previous_hash(ticket_issue.get("comments", []))
    posted = False
    if previous_hash != state_hash and not dry_run:
        body = build_comment_body(flagged, counts, _workflow_run_url(),
                                   lookback_days, state_hash)
        client.create_comment(ticket_issue["id"], body)
        posted = True

    return {
        "counts": counts,
        "flagged": flagged,
        "state_hash": state_hash,
        "previous_hash": previous_hash,
        "posted": posted,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Detect Linear issues completed without recorded "
                     "operating evidence (PAT-985)")
    ap.add_argument("--team", default=DEFAULT_TEAM)
    ap.add_argument("--ticket", default=DEFAULT_TICKET,
                     help="issue identifier to post the report on")
    ap.add_argument("--lookback-days", type=int, default=DEFAULT_LOOKBACK_DAYS)
    ap.add_argument("--dry-run", action="store_true",
                     help="print the report instead of posting to Linear")
    args = ap.parse_args()

    token = os.environ.get("LINEAR_API_TOKEN", "")
    if not token:
        # Unlike verify.py's run_alerting() (verify.py retired 2026-09-30,
        # PAT-2304; there Linear alerting was a
        # bonus on top of a Linear-independent primary job and so degraded
        # gracefully), this tool's entire job IS querying and posting to
        # Linear. A missing token here has no useful degraded mode — it is
        # total silent failure, exactly the "fails safe and is invisible
        # when it fails" bug class this tool exists to catch (root
        # CLAUDE.md). Refuse to run quietly; the workflow's own "Assert
        # Linear API token present" step is the second, independent guard
        # on the canonical scheduled run.
        print("ERROR: LINEAR_API_TOKEN is not set. This tool's entire job "
              "is querying and posting to Linear — there is no degraded "
              "mode. Refusing to run silently.", file=sys.stderr)
        return 1

    from linear_client import LinearClient
    client = LinearClient(token)

    try:
        result = execute(client, args.team, args.ticket, args.lookback_days,
                          dry_run=args.dry_run)
    except LookupError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    counts = result["counts"]
    print(f"{counts['examined']} examined / {counts['runtime_affecting']} "
          f"runtime-affecting / {counts['flagged']} flagged")

    if result["posted"]:
        print(f"Posted updated report to {args.ticket} "
              f"(state {result['previous_hash']} -> {result['state_hash']}).")
    elif args.dry_run:
        print(f"Dry run: state would be {result['state_hash']} "
              f"(previous {result['previous_hash']}) — not posting.")
    else:
        print(f"No change since last run (state {result['state_hash']}) — "
              f"exiting quietly, nothing posted.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
