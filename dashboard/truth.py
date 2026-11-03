"""
truth.py — PAT-1303 operational truth page: manifest loading + evaluation.

The problem this closes: fourteen times in a hundred days, something shipped
and was silently inert for days or weeks — an alerter with no credential, a
monitor that had never run once, a job 503ing for weeks, a check that
computes a degraded state then records itself healthy. The shape is always
the same: things that fail safe are invisible when they fail, so a dead job
looks exactly like a healthy one.

Architecture (do not violate this while extending the file):

  The page is driven by a DECLARED INVENTORY (truth_manifest.yaml), joined
  against OBSERVED EVIDENCE collected separately. It is never driven by
  what happens to report in — a checked entry with no evidence renders
  amber, never green, and is NEVER silently dropped from the output. If you
  add a new evidence kind, make sure "nobody has wired a collector for this
  yet" produces an amber row with a clear reason, not an absent one.

  state rules:
    green   — evidence exists, is fresher than the entry's stale_after_seconds,
              and reports success.
    red     — evidence exists and reports failure.
    amber   — everything else: no evidence, stale evidence, or evidence that
              explicitly can't determine a state (e.g. a check_statuses row of
              'unconfigured').
    retired — the entry carries a top-level `retired: {at, reason}` block.
              PAT-1342: a job that's gone for good (e.g. its endpoint was
              removed and the cron/timer that called it deleted from the box)
              is never just deleted from this manifest — deleting the row
              would make it indistinguishable from a job that was never
              declared at all, the exact failure this page exists to catch.
              Retired entries are excluded from evidence collection (there is
              nothing left to observe) unless they declare a
              `requires_github_commit` release prerequisite. A conditional
              retirement stays amber/red until that immutable commit is
              verified on the declared branch, then evaluates as retired.

    quarantined — the entry carries a top-level `quarantined: {at, reason}`
              block. Its workflow may remain available for manual compatibility
              and report history, but it is unscheduled and non-triggerable from
              Patched. Like retired history, it is not active evidence work.

Everything in the "pure" section below takes plain data in and returns plain
data out — no I/O, no subprocess, no network, no DB handle. That's what
makes it unit-testable without a box, a token, or a database. The
"collection" section at the bottom does the actual I/O and is kept thin and
injectable (subprocess runner, HTTP getter, DB rows) so it can be exercised
with fakes in tests too.

check_statuses vocabulary mapping (see main.py's `check_statuses` table and
`_record_check_status`): that table already has a three-state vocabulary —
'ok' / 'degraded' / 'unconfigured' — with generic Slack alerting on
transition. This module reuses it rather than inventing a parallel one:

    check_statuses state   ->   Observation.success   ->   truth state
    'ok'                         True                       green
    'degraded'                   False                      red
    'unconfigured'               None                        amber

'degraded' rows in this codebase are evaluated failures or configuration
problems (e.g. rbac_operators degraded means no session owners are configured;
session users remain consultants), so they map to red. 'unconfigured' rows mean the check itself lacks what it needs to
run (missing config, in a startup grace window, etc.) — an indeterminate
state, so they map to amber rather than red, distinct from a hard failure.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone

import yaml

# ─────────────────────────────────────────────────────────────────────────
# Manifest schema
# ─────────────────────────────────────────────────────────────────────────

VALID_EVIDENCE_KINDS = {
    "systemd",
    "file_mtime",
    "log_tail",
    "github_workflow",
    "check_status",
    "agent_health",
    "absent",
}

VALID_SCOPE_PREFIXES = ("prod-01", "api-01", "portal-01", "tenant-zero", "github:", "agent:")

_REQUIRED_TOP_FIELDS = ("id", "scope", "name", "proves", "cadence_seconds", "stale_after_seconds", "evidence")


class ManifestError(ValueError):
    """Raised on any malformed manifest entry. A malformed entry is a loud
    error at load time — never a silently skipped row. Collects every
    problem found (not just the first) so a single load attempt tells you
    everything wrong with the file."""


def load_manifest(path: str | os.PathLike) -> list[dict]:
    """Load and validate truth_manifest.yaml. Returns the list of entry
    dicts, unmodified, in file order. Raises ManifestError listing every
    validation problem found across the whole file."""
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise ManifestError(f"{path}: manifest must be a YAML list of entries, got {type(raw).__name__}")

    errors: list[str] = []
    seen_ids: set[str] = set()

    for i, entry in enumerate(raw):
        prefix = f"entry #{i}"
        if not isinstance(entry, dict):
            errors.append(f"{prefix}: not a mapping ({type(entry).__name__})")
            continue

        entry_id = entry.get("id")
        if entry_id:
            prefix = f"entry {entry_id!r}"

        for field in _REQUIRED_TOP_FIELDS:
            if field not in entry or entry[field] in (None, ""):
                errors.append(f"{prefix}: missing required field {field!r}")

        if not isinstance(entry_id, str) or not entry_id:
            errors.append(f"{prefix}: 'id' must be a non-empty string")
        elif entry_id in seen_ids:
            errors.append(f"{prefix}: duplicate id {entry_id!r}")
        else:
            seen_ids.add(entry_id)

        scope = entry.get("scope")
        if not isinstance(scope, str) or not scope.startswith(VALID_SCOPE_PREFIXES):
            errors.append(
                f"{prefix}: 'scope' {scope!r} must start with one of {VALID_SCOPE_PREFIXES}"
            )

        proves = entry.get("proves")
        if proves is not None and (not isinstance(proves, str) or not proves.strip()):
            errors.append(f"{prefix}: 'proves' must be a non-empty string")

        cadence = entry.get("cadence_seconds")
        stale = entry.get("stale_after_seconds")
        if cadence is not None:
            if not isinstance(cadence, (int, float)) or cadence <= 0:
                errors.append(f"{prefix}: 'cadence_seconds' must be a positive number")
        if stale is not None:
            if not isinstance(stale, (int, float)) or stale <= 0:
                errors.append(f"{prefix}: 'stale_after_seconds' must be a positive number")
        if isinstance(cadence, (int, float)) and isinstance(stale, (int, float)):
            if stale < cadence:
                errors.append(
                    f"{prefix}: 'stale_after_seconds' ({stale}) is smaller than "
                    f"'cadence_seconds' ({cadence}) — normal jitter would read as amber"
                )

        evidence = entry.get("evidence")
        if not isinstance(evidence, dict):
            errors.append(f"{prefix}: 'evidence' must be a mapping")
        else:
            kind = evidence.get("kind")
            if kind not in VALID_EVIDENCE_KINDS:
                errors.append(f"{prefix}: evidence.kind {kind!r} not in {sorted(VALID_EVIDENCE_KINDS)}")
            if kind == "absent":
                if not evidence.get("reason"):
                    errors.append(f"{prefix}: evidence.kind 'absent' requires evidence.reason")
            elif kind is not None and not evidence.get("locator"):
                errors.append(f"{prefix}: evidence.kind {kind!r} requires evidence.locator")

        retired = entry.get("retired")
        if retired is not None:
            if not isinstance(retired, dict):
                errors.append(f"{prefix}: 'retired' must be a mapping with 'at' and 'reason'")
            else:
                if not isinstance(retired.get("at"), str) or not retired.get("at", "").strip():
                    errors.append(f"{prefix}: 'retired.at' must be a non-empty string")
                if not isinstance(retired.get("reason"), str) or not retired.get("reason", "").strip():
                    errors.append(f"{prefix}: 'retired.reason' must be a non-empty string")
                prerequisite = retired.get("requires_github_commit")
                if prerequisite is not None:
                    if not isinstance(prerequisite, dict):
                        errors.append(f"{prefix}: 'retired.requires_github_commit' must be a mapping")
                    else:
                        repo = prerequisite.get("repo")
                        sha = prerequisite.get("sha")
                        branch = prerequisite.get("branch")
                        if not isinstance(repo, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
                            errors.append(f"{prefix}: retirement prerequisite repo must be an owner/repository name")
                        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
                            errors.append(f"{prefix}: retirement prerequisite sha must be a full 40-character commit SHA")
                        if not isinstance(branch, str) or not re.fullmatch(r"[A-Za-z0-9._/-]+", branch):
                            errors.append(f"{prefix}: retirement prerequisite branch must be a non-empty Git ref name")

        quarantined = entry.get("quarantined")
        if quarantined is not None:
            if not isinstance(quarantined, dict):
                errors.append(f"{prefix}: 'quarantined' must be a mapping with 'at' and 'reason'")
            else:
                if not isinstance(quarantined.get("at"), str) or not quarantined.get("at", "").strip():
                    errors.append(f"{prefix}: 'quarantined.at' must be a non-empty string")
                if not isinstance(quarantined.get("reason"), str) or not quarantined.get("reason", "").strip():
                    errors.append(f"{prefix}: 'quarantined.reason' must be a non-empty string")
        if retired is not None and quarantined is not None:
            errors.append(f"{prefix}: an entry cannot be both retired and quarantined")

    if errors:
        raise ManifestError(f"{path}: {len(errors)} manifest validation error(s):\n" + "\n".join(errors))

    return raw


# ─────────────────────────────────────────────────────────────────────────
# Observation + pure evaluation
# ─────────────────────────────────────────────────────────────────────────

@dataclass
class Observation:
    """One piece of collected evidence for one manifest entry.

    observed_at: when the evidence was produced. None means "evidence
      collection ran and has a definite reason it found nothing" (see
      `detail`) — distinct from the Python value `None` used in place of an
      Observation entirely, which means "no collector attempted this at
      all". Both render amber; the difference is only in how specific the
      reason can be.
    success: True (evidence reports success), False (evidence reports
      failure), or None (evidence exists but cannot determine a state —
      e.g. a check_statuses 'unconfigured' row).
    detail: short human sentence — what the evidence actually says.
    """
    observed_at: datetime | None
    success: bool | None
    detail: str = ""


def _human_seconds(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 120:
        return f"{seconds}s"
    minutes = seconds / 60
    if minutes < 120:
        return f"{minutes:.0f}m"
    hours = minutes / 60
    if hours < 48:
        return f"{hours:.1f}h"
    return f"{hours / 24:.1f}d"


def evaluate_entry(entry: dict, observation: Observation | None, now: datetime) -> tuple[str, str]:
    """Given one manifest entry and its observation (or None), return
    (state, reason). state is 'green' | 'amber' | 'red' | 'quarantined' | 'retired'.

    This is the one function every other rule in this module exists to
    protect: a None observation MUST return amber, never green, and the
    reason MUST name what's missing.
    """
    name = entry.get("name", entry.get("id", "this entry"))

    retired = entry.get("retired")
    if retired:
        prerequisite = retired.get("requires_github_commit")
        if prerequisite:
            if observation is None:
                return (
                    "amber",
                    f"retirement pending: no evidence that {prerequisite['sha'][:8]} is on "
                    f"{prerequisite['repo']}:{prerequisite['branch']}",
                )
            if observation.observed_at is None or observation.success is None:
                return ("amber", observation.detail or "retirement prerequisite could not be verified")
            if observation.success is False:
                return ("red", observation.detail or "retirement prerequisite is not on the required branch")
        return ("retired", f"retired {retired['at']}: {retired['reason']}")

    quarantined = entry.get("quarantined")
    if quarantined:
        return ("quarantined", f"quarantined {quarantined['at']}: {quarantined['reason']}")

    if observation is None:
        return (
            "amber",
            f"no observation collected for {name} — no collector has reported evidence for this entry yet",
        )

    if observation.observed_at is None:
        # The collector ran and has a specific, known reason there's no
        # timestamped evidence (e.g. "no GitHub token configured", "tenant-zero
        # not reachable"). Always amber; the detail carries the specific reason.
        return ("amber", observation.detail or f"no evidence available for {name}")

    age_seconds = (now - observation.observed_at).total_seconds()
    stale_after = entry["stale_after_seconds"]
    if age_seconds > stale_after:
        return (
            "amber",
            f"last evidence is {_human_seconds(age_seconds)} old, older than the "
            f"{_human_seconds(stale_after)} staleness threshold for {name} "
            f"(evidence: {observation.detail or 'no detail recorded'})",
        )

    if observation.success is None:
        return ("amber", observation.detail or f"evidence for {name} could not determine a state")

    if observation.success is False:
        return ("red", observation.detail or f"{name} reported failure")

    return ("green", observation.detail or f"{name} ran and reported success")


def evaluate_all(manifest: list[dict], observations: dict[str, Observation | None], now: datetime) -> list[dict]:
    """Evaluate every manifest entry against its observation. Returns a list
    of result dicts in manifest order — the caller is responsible for any
    display sort (e.g. worst-first). Every entry in the manifest produces
    exactly one result, whether or not it has an observation."""
    results = []
    for entry in manifest:
        obs = observations.get(entry["id"])
        state, reason = evaluate_entry(entry, obs, now)
        results.append({
            "id": entry["id"],
            "scope": entry["scope"],
            "name": entry["name"],
            "proves": entry["proves"],
            "notes": entry.get("notes"),
            "state": state,
            "reason": reason,
            "last_signal_at": obs.observed_at.isoformat() if (obs and obs.observed_at) else None,
        })
    return results


_SORT_ORDER = {"red": 0, "amber": 1, "green": 2, "quarantined": 3, "retired": 4}


def sort_worst_first(results: list[dict]) -> list[dict]:
    """Red, amber, green, quarantined, then retired; stable within each state."""
    return sorted(results, key=lambda r: _SORT_ORDER.get(r["state"], 99))


def aggregate(results: list[dict]) -> dict:
    """Whole-page summary counts."""
    summary = {"green": 0, "amber": 0, "red": 0, "quarantined": 0, "retired": 0, "total": len(results)}
    for r in results:
        summary[r["state"]] = summary.get(r["state"], 0) + 1
    return summary


# ─────────────────────────────────────────────────────────────────────────
# Collection — the only section in this file that does real I/O. Every
# function here is a thin, injectable wrapper: pass in a fake to test the
# logic without a box, a token, or a database.
# ─────────────────────────────────────────────────────────────────────────

_CHECK_STATUS_SUCCESS = {"ok": True, "degraded": False, "unconfigured": None}


def collect_check_status_observation(locator: str, check_statuses_by_name: dict) -> Observation | None:
    """kind: check_status. Reads this app's own `check_statuses` table
    (already collected by the scheduler; see main.py's _record_check_status).
    `check_statuses_by_name` is {name: {"state":..., "reason":..., "evaluated_at": iso str}}."""
    row = check_statuses_by_name.get(locator)
    if not row:
        return None
    success = _CHECK_STATUS_SUCCESS.get(row["state"])
    observed_at = _parse_iso(row.get("evaluated_at"))
    if observed_at is None:
        return None
    detail = row.get("reason") or f"{locator}: {row['state']}"
    return Observation(observed_at=observed_at, success=success, detail=detail)


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _systemctl_show(unit: str, props: list[str], runner=subprocess.run) -> dict:
    """Query systemd unit properties via `systemctl show`. Forces TZ=UTC on
    the subprocess so any timestamp property comes back in a fixed,
    parseable format ("Thu 2026-08-13 23:30:34 UTC") rather than whatever
    the box's local timezone happens to be."""
    env = dict(os.environ)
    env["TZ"] = "UTC"
    try:
        result = runner(
            ["systemctl", "show", unit] + [f"--property={p}" for p in props],
            capture_output=True, text=True, timeout=5, env=env,
        )
    except Exception:
        return {}
    out: dict = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            if k in props:
                out[k] = v
    return out


# PAT-1411: LoadState values that mean "no live unit definition", regardless
# of what ActiveState/Result/ExecMainStatus say. Found live on patched-prod-01
# during PAT-1304's injected-failure proof: removing
# /etc/systemd/system/patched-dashboard-prune-reports.service and running
# `systemctl daemon-reload` did NOT turn the truth page amber, because the
# paired .timer kept systemd's runtime object for the service alive.
# `systemctl show` on the removed service kept reporting ActiveState=inactive
# (not blank, so the old guard below never fired) and Result=success /
# ExecMainStatus=0 carried forward from the last real run before removal --
# a stale last-good result reported as if it were current. That's exactly the
# failure this page exists to catch (PAT-1303): a check that ran once, then
# its unit vanished, with nothing signalling the change.
#
# "loaded" is the only LoadState that means systemd actually has a current,
# valid unit definition on disk. Everything else means there is no live
# definition to trust ActiveState/Result against:
#   not-found    unit file is gone (the exact PAT-1304 case above)
#   masked       unit is symlinked to /dev/null -- no real definition backs it
#   bad-setting  unit file present but systemd rejected a setting in it
#   error        systemd could not load the unit for an internal reason
# "stub" (referenced but never loaded) and "merged" (an alias name pointing
# at another loaded unit) are deliberately left out: a merged alias's target
# is genuinely loaded, and a stub is covered by the blank-ActiveState check
# below anyway.
#
# _UNIT_DEFINITION_GONE_LOAD_STATES: PAT-1411 established this policy here;
# PAT-1426 ported the identical guard to deploy/truth-report.sh (the bash
# half of this same feature, used by api-01/portal-01 to push their own
# systemd evidence to this page — see that script's header). That script's
# `case "$load_state" in ...)` list must stay byte-for-byte in sync with this
# frozenset, and tests/test_pat1426_truth_report_loadstate.py asserts exactly
# that so the two can't silently drift apart again.
_UNIT_DEFINITION_GONE_LOAD_STATES = frozenset({"not-found", "masked", "bad-setting", "error"})

_SYSTEMD_TS_RE = re.compile(r"^\w{3} (\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) UTC$")


def _parse_systemd_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    m = _SYSTEMD_TS_RE.match(value.strip())
    if not m:
        return None
    try:
        return datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def collect_systemd_observation(locator: str, now: datetime, runner=subprocess.run) -> Observation | None:
    """kind: systemd, collected locally (prod-01 only — this app runs there).

    locator ending in '.timer' checks the TIMER's own schedule state (used
    for the one case in this manifest where the interesting fact is "will
    this ever fire again", not "did the underlying job succeed" — see
    prod01-edge-firewall-timer). Any other locator is treated as a .service
    unit and reports on its last completed run.

    Both branches check LoadState before anything else (PAT-1411): systemd
    can keep a runtime object alive, and ActiveState/Result reporting on it,
    even after the corresponding unit file has been removed from disk, if a
    paired unit (e.g. a .timer whose .service was deleted) is still around.
    See _UNIT_DEFINITION_GONE_LOAD_STATES above.
    """
    if locator.endswith(".timer"):
        props = _systemctl_show(locator, ["ActiveState", "LoadState", "UnitFileState", "LastTriggerUSec"], runner=runner)
        # PAT-1411: check LoadState before trusting ActiveState. A removed
        # .timer whose runtime object is kept alive by something else (e.g. a
        # paired .service systemd hasn't fully forgotten) is the same shape
        # of bug as the .service case above -- fix both branches, not one.
        if props.get("LoadState", "") in _UNIT_DEFINITION_GONE_LOAD_STATES:
            return None  # no evidence: unit definition is gone, not "no evidence yet"
        active_state = props.get("ActiveState", "")
        if not active_state:
            return None  # unit doesn't exist on this box
        enabled = props.get("UnitFileState", "")
        if enabled == "disabled":
            return Observation(
                observed_at=now, success=False,
                detail=f"{locator} is disabled — it will never fire",
            )
        return Observation(
            observed_at=now, success=True,
            detail=f"{locator} is {enabled or 'enabled'} and {active_state}",
        )

    props = _systemctl_show(
        locator,
        ["ActiveState", "LoadState", "Result", "ExecMainStatus", "ExecMainStartTimestamp", "ExecMainExitTimestamp"],
        runner=runner,
    )
    # PAT-1411: see _UNIT_DEFINITION_GONE_LOAD_STATES above. ActiveState and
    # Result/ExecMainStatus can all still report the last real run even after
    # the unit file itself was removed, if something else (e.g. a paired
    # .timer) keeps systemd's runtime object alive -- this is the exact
    # live shape found during PAT-1304's injected-failure proof. Check
    # LoadState first so a stale last-good result is never reported as
    # current evidence.
    if props.get("LoadState", "") in _UNIT_DEFINITION_GONE_LOAD_STATES:
        return None  # no evidence: unit definition is gone, not "no evidence yet"
    active_state = props.get("ActiveState", "")
    if not active_state:
        return None  # unit doesn't exist on this box

    observed_at = (
        _parse_systemd_timestamp(props.get("ExecMainExitTimestamp"))
        or _parse_systemd_timestamp(props.get("ExecMainStartTimestamp"))
    )
    if observed_at is None:
        # A unit that exists but has never run (e.g. a monthly timer whose
        # first fire hasn't happened yet) has no evidence, not failed evidence.
        return None

    result = props.get("Result", "")
    success = result == "success"
    exit_status = props.get("ExecMainStatus", "")
    detail = f"{locator}: Result={result or 'unknown'}" + (f", ExecMainStatus={exit_status}" if exit_status else "")
    return Observation(observed_at=observed_at, success=success, detail=detail)


def collect_file_mtime_observation(path: str, now: datetime) -> Observation | None:
    """kind: file_mtime. Existence + mtime only — this kind has no inherent
    success/failure signal beyond "the file is there and this recent"."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    observed_at = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
    return Observation(observed_at=observed_at, success=True, detail=f"{path} last modified {observed_at.isoformat()}")


def collect_log_tail_observation(
    path: str, now: datetime, success_pattern: str | None = None, failure_pattern: str | None = None,
) -> Observation | None:
    """kind: log_tail. Reads the last non-empty line of a log file and
    classifies it via two regexes: failure_pattern is checked first (a line
    can plausibly contain both if it's a diagnostic dump), then
    success_pattern. Neither matching is treated as indeterminate (amber via
    success=None), not silently green."""
    try:
        st = os.stat(path)
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
    except OSError:
        return None
    if not lines:
        return None
    last = lines[-1]
    observed_at = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
    if failure_pattern and re.search(failure_pattern, last):
        return Observation(observed_at=observed_at, success=False, detail=f"last line: {last[:200]}")
    if success_pattern and re.search(success_pattern, last):
        return Observation(observed_at=observed_at, success=True, detail=f"last line: {last[:200]}")
    return Observation(observed_at=observed_at, success=None, detail=f"last line did not match a known pattern: {last[:200]}")


def collect_github_workflow_observation(
    locator: str, token: str | None, now: datetime, repo: str = "", http_get=None,
) -> Observation | None:
    """kind: github_workflow. Requires a GitHub token already configured in
    this app's environment (GITHUB_TOKEN). If none is configured, returns an
    explicit "known missing" Observation (observed_at=None) rather than a
    bare None, so the amber reason on the page says exactly why — this app
    does not add a new secret to make this kind collectible."""
    if not token:
        return Observation(observed_at=None, success=None, detail="no GitHub token configured")
    if http_get is None:
        import requests as http_get_module
        http_get = http_get_module.get
    try:
        r = http_get(
            f"https://api.github.com/repos/{repo}/actions/workflows/{locator}/runs",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            params={"event": "schedule", "per_page": 1},
            timeout=10,
        )
        if r.status_code != 200:
            return Observation(observed_at=None, success=None, detail=f"GitHub API returned HTTP {r.status_code}")
        data = r.json()
        runs = data.get("workflow_runs") or []
        if not runs:
            return None
        run = runs[0]
        observed_at = _parse_iso((run.get("run_started_at") or "").replace("Z", "+00:00"))
        if observed_at is None:
            return None
        conclusion = run.get("conclusion")
        success = conclusion == "success"
        return Observation(observed_at=observed_at, success=success, detail=f"latest scheduled run: {conclusion or run.get('status')}")
    except Exception as e:
        return Observation(observed_at=None, success=None, detail=f"GitHub API request failed: {e}")


def collect_github_commit_ancestor_observation(
    repo: str, sha: str, branch: str, token: str | None, now: datetime, http_get=None,
) -> Observation:
    """Verify an immutable release prerequisite through GitHub's compare API.

    A successful comparison is evidence that ``sha`` is already an ancestor of
    ``branch`` (compare status ``ahead`` or ``identical``). Missing credentials
    and API failures are indeterminate, never interpreted as retirement.
    """
    if not token:
        return Observation(
            observed_at=None,
            success=None,
            detail=f"retirement pending: no GitHub token configured to verify {repo}:{branch}",
        )
    if http_get is None:
        import requests as http_get_module
        http_get = http_get_module.get
    try:
        response = http_get(
            f"https://api.github.com/repos/{repo}/compare/{sha}...{branch}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            timeout=10,
        )
        if response.status_code != 200:
            return Observation(
                observed_at=None,
                success=None,
                detail=f"retirement pending: GitHub compare API returned HTTP {response.status_code}",
            )
        status = (response.json().get("status") or "").lower()
        if status in {"ahead", "identical"}:
            return Observation(
                observed_at=now,
                success=True,
                detail=f"verified {sha[:8]} is on {repo}:{branch} (compare status {status})",
            )
        if status in {"behind", "diverged"}:
            return Observation(
                observed_at=now,
                success=False,
                detail=f"retirement blocked: {sha[:8]} is not on {repo}:{branch} (compare status {status})",
            )
        return Observation(
            observed_at=None,
            success=None,
            detail=f"retirement pending: GitHub compare returned unknown status {status or 'missing'}",
        )
    except Exception as exc:
        return Observation(
            observed_at=None,
            success=None,
            detail=f"retirement pending: GitHub compare request failed: {exc}",
        )


@dataclass
class CollectionContext:
    """Bundles every dependency collect_observation needs, so it stays pure
    dependency-injection and testable with fakes."""
    now: datetime
    is_local_prod01: bool = False
    check_statuses_by_name: dict | None = None
    github_token: str | None = None
    github_http_get: object = None
    systemctl_runner: object = subprocess.run
    reported_observations: dict | None = None  # {(scope, entry_id): Observation}


def collect_observation(entry: dict, ctx: CollectionContext) -> Observation | None:
    """Top-level dispatcher: given one manifest entry, decide how to collect
    its evidence based on evidence.kind and scope. This is the only place
    that needs to know "prod-01 is local, api-01/portal-01 need a report"."""
    evidence = entry["evidence"]
    kind = evidence["kind"]
    locator = evidence.get("locator")
    scope = entry["scope"]

    if kind == "absent":
        return Observation(observed_at=None, success=None, detail=evidence.get("reason", "no collector exists for this check"))

    if kind == "check_status":
        return collect_check_status_observation(locator, ctx.check_statuses_by_name or {})

    if kind == "github_workflow":
        repo = scope.split(":", 1)[1] if ":" in scope else ""
        return collect_github_workflow_observation(
            locator, ctx.github_token, ctx.now, repo=f"Patched-LTD/{repo}", http_get=ctx.github_http_get,
        )

    if kind == "agent_health":
        # Deliberately not wired up in this milestone — agent_health is
        # push-based from the endpoint (folded into /v1/inventory) and there
        # is no server-side puller for it yet. Amber, honestly, until there is.
        return None

    if kind == "log_tail":
        if scope == "prod-01" and ctx.is_local_prod01:
            return collect_log_tail_observation(
                locator, ctx.now,
                success_pattern=evidence.get("success_pattern"),
                failure_pattern=evidence.get("failure_pattern"),
            )
        return (ctx.reported_observations or {}).get((scope, entry["id"]))

    if kind in ("systemd", "file_mtime"):
        if scope == "prod-01" and ctx.is_local_prod01:
            if kind == "systemd":
                return collect_systemd_observation(locator, ctx.now, runner=ctx.systemctl_runner)
            return collect_file_mtime_observation(locator, ctx.now)
        # api-01 / portal-01 (or prod-01 evaluated from off-box, e.g. tests):
        # evidence comes only from the push-reporter's stored reports.
        return (ctx.reported_observations or {}).get((scope, entry["id"]))

    return None


def collect_all_observations(manifest: list[dict], ctx: CollectionContext) -> dict[str, Observation | None]:
    # Static retired and quarantined entries short-circuit in evaluate_entry.
    # Conditional retirement is the exception: verify its cross-repo release
    # prerequisite before allowing the historical state to take effect.
    observations: dict[str, Observation | None] = {}
    for entry in manifest:
        prerequisite = (entry.get("retired") or {}).get("requires_github_commit")
        if prerequisite:
            observations[entry["id"]] = collect_github_commit_ancestor_observation(
                prerequisite["repo"],
                prerequisite["sha"],
                prerequisite["branch"],
                ctx.github_token,
                ctx.now,
                http_get=ctx.github_http_get,
            )
        elif entry.get("retired") or entry.get("quarantined"):
            observations[entry["id"]] = None
        else:
            observations[entry["id"]] = collect_observation(entry, ctx)
    return observations


def build_truth_page(manifest: list[dict], ctx: CollectionContext) -> dict:
    """End-to-end: collect, evaluate, sort worst-first, aggregate. This is
    what main.py's /admin/truth route calls."""
    observations = collect_all_observations(manifest, ctx)
    results = evaluate_all(manifest, observations, ctx.now)
    results = sort_worst_first(results)
    return {
        "generated_at": ctx.now.isoformat(),
        "summary": aggregate(results),
        "checks": results,
    }
