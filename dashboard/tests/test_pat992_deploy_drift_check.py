"""
PAT-992: DEPLOYED_SHA is a file nothing wrote — hand-created once on
patched-prod-01, asserting a wrong answer (a stale SHA) ever since, with no
code anywhere that updates it. "The box, not Linear, is the check" was
unusable because the box itself couldn't be trusted.

This covers the dashboard half:
  * _run_deploy_drift_check_tick() compares scripts/deploy.sh's recorded
    DEPLOYED_SHA_FILE against this checkout's own `git rev-parse HEAD`,
    never against origin/main (the box cannot reach GitHub, PAT-617), and
    refuses health when tracked files differ from HEAD. Untracked runtime
    files are deliberately ignored.
  * Every branch that cannot positively confirm a match records
    unconfigured or degraded with a specific reason, never ok.
  * The PAT-1045 shape this ticket must not reproduce: several existing
    ticks compute a degraded state, record it under their own check name,
    then implicitly return None, so tick_<label> reads ok while the named
    check reads degraded (confirmed live on prod-01: email_delivery
    degraded, tick_email_delivery_check ok, same timestamp). Every degraded
    branch here must return its reason so _run_tick's wrapper heartbeat
    (tick_deploy_drift_check) agrees with the named check (deploy_drift).
  * Unconfigured (no deploy has ever recorded a SHA under this tooling) is,
    by the convention already established for health_alert_delivery /
    portal_auth (see test_check_status.py's
    test_health_alerts_tick_unconfigured_channel_does_not_degrade_tick),
    NOT treated as a tick failure — the tick heartbeat stays ok while the
    named check reads unconfigured. That is a standing configuration gap,
    not the tick silently dying.
  * FIX 2 from independent review: DEPLOYED_SHA_FILE is written LAST, after
    the restart and smoke suite -- deliberately, and that ordering does not
    change. But that means every successful deploy has a real window where
    this process is already running new code and the record hasn't caught
    up yet. Reporting that window as degraded is safe-direction but still a
    false alarm that can land in the 09:00 UTC digest. A mismatch where the
    recorded timestamp predates this process's own start (_PROCESS_STARTED_
    AT), within a bounded grace window (_DEPLOY_INFLIGHT_GRACE), is reported
    unconfigured instead -- check_statuses' state column only allows ok/
    degraded/unconfigured (see the CHECK constraint in init_db), so
    "indeterminate, ask again next tick" reuses unconfigured, following the
    same "not a tick failure" convention as the missing-file case. Past the
    grace window a mismatch reports degraded as before -- a genuinely stuck
    deploy must not be able to hide in the maybe-in-flight state forever.

Run with: pytest tests/test_pat992_deploy_drift_check.py -v
"""

import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()


def _status(name):
    with dashboard.get_db() as conn:
        return conn.execute(
            "SELECT name, state, reason, evaluated_at FROM check_statuses WHERE name=?",
            (name,),
        ).fetchone()


def _init_repo(path, commits=1):
    """Real git checkout in a scratch dir — exercises the actual `git
    rev-parse HEAD` subprocess call rather than mocking it away."""
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "t@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "PAT-992 test"], check=True)
    sha = None
    for i in range(commits):
        (path / "f.txt").write_text(f"commit {i}\n")
        subprocess.run(["git", "-C", str(path), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(path), "commit", "-q", "-m", f"commit {i}"], check=True)
        sha = subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
        ).strip()
    return sha


def _write_sha_file(path, sha, deployed_at="2026-07-29T00:00:00Z"):
    path.write_text(f"DEPLOYED_SHA={sha}\nDEPLOYED_AT={deployed_at}\n")


def _settle_process_start(monkeypatch, before=None):
    """Model this process as having been running for a long time -- well
    before any DEPLOYED_AT used in a fixture -- so the FIX 2 in-flight
    grace window never applies. Every test that wants a genuine, immediate
    'degraded' out of a SHA mismatch (not 'maybe still deploying') must
    call this, since a bare `datetime.now(...)` process start would
    otherwise almost always postdate a fixture's fixed-past DEPLOYED_AT and
    be mistaken for a fresh restart racing the write."""
    monkeypatch.setattr(
        dashboard, "_PROCESS_STARTED_AT",
        before or datetime(2020, 1, 1, tzinfo=timezone.utc),
    )


# ── unconfigured: no DEPLOYED_SHA_FILE yet ──────────────────────────────────


def test_missing_deployed_sha_file_is_unconfigured_not_ok(db, tmp_path, monkeypatch):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _init_repo(repo_dir)
    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(repo_dir))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(repo_dir / "DEPLOYED_SHA"))
    now = datetime.now(timezone.utc)

    reason = dashboard._run_deploy_drift_check_tick(now)

    row = _status("deploy_drift")
    assert row["state"] == "unconfigured"
    assert "does not exist" in row["reason"]
    assert reason is None  # unconfigured must not degrade the tick's own heartbeat


def test_missing_deployed_sha_file_tick_heartbeat_stays_ok(db, tmp_path, monkeypatch):
    """Matches the established convention (health_alert_delivery,
    portal_auth): unconfigured is a standing config gap, not a tick
    failure, so tick_deploy_drift_check must read ok even though
    deploy_drift itself reads unconfigured."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _init_repo(repo_dir)
    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(repo_dir))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(repo_dir / "DEPLOYED_SHA"))
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "deploy-drift-check", lambda: dashboard._run_deploy_drift_check_tick(now), now
    )

    assert _status("deploy_drift")["state"] == "unconfigured"
    assert _status("tick_deploy_drift_check")["state"] == "ok"


# ── ok: recorded SHA matches the local checkout's HEAD ──────────────────────


def test_matching_sha_is_ok(db, tmp_path, monkeypatch):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    sha = _init_repo(repo_dir)
    sha_file = repo_dir / "DEPLOYED_SHA"
    _write_sha_file(sha_file, sha)
    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(repo_dir))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(sha_file))
    now = datetime.now(timezone.utc)

    reason = dashboard._run_deploy_drift_check_tick(now)

    row = _status("deploy_drift")
    assert row["state"] == "ok"
    assert sha[:12] in row["reason"]
    assert reason is None


def test_matching_sha_ok_through_run_tick_both_read_ok(db, tmp_path, monkeypatch):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    sha = _init_repo(repo_dir)
    sha_file = repo_dir / "DEPLOYED_SHA"
    _write_sha_file(sha_file, sha)
    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(repo_dir))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(sha_file))
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "deploy-drift-check", lambda: dashboard._run_deploy_drift_check_tick(now), now
    )

    assert _status("deploy_drift")["state"] == "ok"
    assert _status("tick_deploy_drift_check")["state"] == "ok"


def test_matching_sha_with_tracked_hotfix_degrades_then_clears(
    db, tmp_path, monkeypatch
):
    """PAT-1378: an scp hotfix changes served content without moving HEAD or
    DEPLOYED_SHA. That must fail loud, then clear once the file is reconciled."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    sha = _init_repo(repo_dir)
    sha_file = repo_dir / "DEPLOYED_SHA"
    _write_sha_file(sha_file, sha)
    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(repo_dir))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(sha_file))
    now = datetime.now(timezone.utc)

    (repo_dir / "f.txt").write_text("scp hotfix\n")
    dashboard._run_tick(
        "deploy-drift-check", lambda: dashboard._run_deploy_drift_check_tick(now), now
    )

    check_row = _status("deploy_drift")
    assert check_row["state"] == "degraded"
    assert "1 tracked-file change(s)" in check_row["reason"]
    assert "scp/manual hotfix" in check_row["reason"]
    assert _status("tick_deploy_drift_check")["state"] == "degraded"

    (repo_dir / "f.txt").write_text("commit 0\n")
    later = now + timedelta(minutes=1)
    dashboard._run_tick(
        "deploy-drift-check", lambda: dashboard._run_deploy_drift_check_tick(later), later
    )

    assert _status("deploy_drift")["state"] == "ok"
    assert _status("tick_deploy_drift_check")["state"] == "ok"


def test_matching_sha_ignores_untracked_runtime_files(db, tmp_path, monkeypatch):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    sha = _init_repo(repo_dir)
    sha_file = repo_dir / "DEPLOYED_SHA"
    _write_sha_file(sha_file, sha)
    (repo_dir / "runtime-output.tmp").write_text("not deployed content\n")
    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(repo_dir))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(sha_file))

    dashboard._run_deploy_drift_check_tick(datetime.now(timezone.utc))

    assert _status("deploy_drift")["state"] == "ok"


@pytest.mark.parametrize("failure", ["error", "timeout"])
def test_tracked_status_failure_degrades_instead_of_assuming_clean(
    db, tmp_path, monkeypatch, failure
):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    sha = _init_repo(repo_dir)
    sha_file = repo_dir / "DEPLOYED_SHA"
    _write_sha_file(sha_file, sha)
    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(repo_dir))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(sha_file))
    real_check_output = subprocess.check_output

    def fail_status(command, **kwargs):
        if "status" not in command:
            return real_check_output(command, **kwargs)
        assert kwargs["timeout"] == 5
        assert "--untracked-files=no" in command
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        raise subprocess.CalledProcessError(128, command)

    monkeypatch.setattr(subprocess, "check_output", fail_status)
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "deploy-drift-check", lambda: dashboard._run_deploy_drift_check_tick(now), now
    )

    check_row = _status("deploy_drift")
    assert check_row["state"] == "degraded"
    assert _status("tick_deploy_drift_check")["state"] == "degraded"
    if failure == "timeout":
        assert "timed out after 5 seconds" in check_row["reason"]
    else:
        assert "could not inspect tracked-file state" in check_row["reason"]


# ── degraded: recorded SHA does not match HEAD ──────────────────────────────


def test_mismatched_sha_is_degraded_with_no_github_claim(db, tmp_path, monkeypatch):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    sha = _init_repo(repo_dir)
    sha_file = repo_dir / "DEPLOYED_SHA"
    _write_sha_file(sha_file, "0" * 40)  # deliberately wrong/stale
    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(repo_dir))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(sha_file))
    _settle_process_start(monkeypatch)  # rule out the FIX 2 in-flight grace window
    now = datetime.now(timezone.utc)

    reason = dashboard._run_deploy_drift_check_tick(now)

    row = _status("deploy_drift")
    assert row["state"] == "degraded"
    assert sha[:12] in row["reason"]
    assert "0" * 12 in row["reason"]
    # Must state plainly that it cannot reach GitHub/origin main, never
    # imply it made that comparison.
    assert "cannot reach origin/main" in row["reason"]
    assert "GitHub" in row["reason"]
    assert reason == row["reason"]


def test_mismatched_sha_via_run_tick_both_read_degraded_with_same_reason(
    db, tmp_path, monkeypatch
):
    """The specific PAT-1045-shape regression this ticket cares about most:
    a check that reads degraded must never sit behind a tick heartbeat that
    reads ok. If _run_deploy_drift_check_tick regressed to the
    record-then-implicit-None shape (the same bug as
    _run_email_delivery_check_tick), this assertion on
    tick_deploy_drift_check would fail while deploy_drift stayed degraded —
    exactly the live prod-01 contradiction this ticket exists to prevent."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _init_repo(repo_dir)
    sha_file = repo_dir / "DEPLOYED_SHA"
    _write_sha_file(sha_file, "f" * 40)
    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(repo_dir))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(sha_file))
    _settle_process_start(monkeypatch)  # rule out the FIX 2 in-flight grace window
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "deploy-drift-check", lambda: dashboard._run_deploy_drift_check_tick(now), now
    )

    check_row = _status("deploy_drift")
    tick_row = _status("tick_deploy_drift_check")
    assert check_row["state"] == "degraded"
    assert tick_row["state"] == "degraded", (
        "tick_deploy_drift_check read 'ok' while deploy_drift read 'degraded' "
        "-- this is the PAT-1045 shape, not agreement"
    )
    assert tick_row["reason"] == check_row["reason"]


# ── FIX 2 (independent review): a mismatch just after a restart is ─────────
# reported as indeterminate ("unconfigured"), not a false "degraded", while
# a deploy may still be finishing -- bounded so a genuinely stuck deploy
# can't hide there forever.


def test_mismatch_within_inflight_grace_is_unconfigured_not_degraded(
    db, tmp_path, monkeypatch
):
    """The concrete bug this fixes: right after a restart, DEPLOYED_SHA_FILE
    still names the PREVIOUS commit (the write is deliberately last, after
    the smoke suite) while this process is already running the new one.
    That mismatch must not be reported as a real problem while it's still
    plausibly just the deploy finishing."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _init_repo(repo_dir)
    sha_file = repo_dir / "DEPLOYED_SHA"
    now = datetime.now(timezone.utc)
    process_started_at = now - timedelta(seconds=30)
    # Recorded provenance predates this process's own start -- exactly the
    # signature of "we restarted onto new code and the write hasn't landed
    # yet".
    _write_sha_file(
        sha_file, "e" * 40,
        deployed_at=(process_started_at - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(repo_dir))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(sha_file))
    monkeypatch.setattr(dashboard, "_PROCESS_STARTED_AT", process_started_at)

    dashboard._run_tick(
        "deploy-drift-check", lambda: dashboard._run_deploy_drift_check_tick(now), now
    )

    check_row = _status("deploy_drift")
    assert check_row["state"] == "unconfigured", (
        f"expected unconfigured (deploy plausibly still in flight), got "
        f"{check_row['state']!r} -- {check_row['reason']!r}"
    )
    assert "may still be finishing" in check_row["reason"]
    # Same convention as the missing-file case: this is not a tick failure.
    assert _status("tick_deploy_drift_check")["state"] == "ok"


def test_mismatch_past_inflight_grace_bound_is_degraded(db, tmp_path, monkeypatch):
    """A genuinely stuck/crashed deploy (smoke hung forever, or crashed
    before ever reaching write_deployed_sha) must not be able to hide in
    the 'maybe still deploying' state indefinitely -- past
    _DEPLOY_INFLIGHT_GRACE the same mismatch is a real problem again."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _init_repo(repo_dir)
    sha_file = repo_dir / "DEPLOYED_SHA"
    now = datetime.now(timezone.utc)
    process_started_at = now - dashboard._DEPLOY_INFLIGHT_GRACE - timedelta(seconds=1)
    _write_sha_file(
        sha_file, "e" * 40,
        deployed_at=(process_started_at - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(repo_dir))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(sha_file))
    monkeypatch.setattr(dashboard, "_PROCESS_STARTED_AT", process_started_at)

    dashboard._run_tick(
        "deploy-drift-check", lambda: dashboard._run_deploy_drift_check_tick(now), now
    )

    check_row = _status("deploy_drift")
    assert check_row["state"] == "degraded", (
        f"the in-flight grace window must be bounded -- expected degraded "
        f"once past it, got {check_row['state']!r}"
    )
    assert _status("tick_deploy_drift_check")["state"] == "degraded"


def test_mismatch_when_record_postdates_process_start_is_degraded_immediately(
    db, tmp_path, monkeypatch
):
    """If DEPLOYED_AT is NEWER than (or equal to) this process's own start,
    there is no ambiguity to give the benefit of the doubt to -- the
    record was written after this process came up, so a mismatch means a
    real, already-settled problem, not a deploy in progress. Must not wait
    out the grace window unnecessarily."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _init_repo(repo_dir)
    sha_file = repo_dir / "DEPLOYED_SHA"
    now = datetime.now(timezone.utc)
    process_started_at = now - timedelta(minutes=5)
    _write_sha_file(
        sha_file, "e" * 40,
        deployed_at=(process_started_at + timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(repo_dir))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(sha_file))
    monkeypatch.setattr(dashboard, "_PROCESS_STARTED_AT", process_started_at)

    dashboard._run_tick(
        "deploy-drift-check", lambda: dashboard._run_deploy_drift_check_tick(now), now
    )

    assert _status("deploy_drift")["state"] == "degraded"
    assert _status("tick_deploy_drift_check")["state"] == "degraded"


# ── degraded: the recorded file is unreadable or unparseable ───────────────


def test_deployed_sha_file_missing_key_line_is_degraded_not_unconfigured(
    db, tmp_path, monkeypatch
):
    """The file EXISTS but is corrupt/malformed -- a real break, not a
    standing config gap, so (unlike the missing-file case) this must
    degrade the tick too."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _init_repo(repo_dir)
    sha_file = repo_dir / "DEPLOYED_SHA"
    sha_file.write_text("not the expected format at all\n")
    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(repo_dir))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(sha_file))
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "deploy-drift-check", lambda: dashboard._run_deploy_drift_check_tick(now), now
    )

    check_row = _status("deploy_drift")
    assert check_row["state"] == "degraded"
    assert "DEPLOYED_SHA=" in check_row["reason"]
    assert _status("tick_deploy_drift_check")["state"] == "degraded"


def test_deployed_sha_file_unreadable_is_degraded(db, tmp_path, monkeypatch):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _init_repo(repo_dir)
    sha_file = repo_dir / "DEPLOYED_SHA"
    _write_sha_file(sha_file, "a" * 40)
    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(repo_dir))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(sha_file))

    def _boom(*a, **k):
        raise OSError("simulated permission denied")

    monkeypatch.setattr("builtins.open", lambda *a, **k: _boom())
    now = datetime.now(timezone.utc)

    reason = dashboard._run_deploy_drift_check_tick(now)

    row = _status("deploy_drift")
    assert row["state"] == "degraded"
    assert "could not be read" in row["reason"]
    assert reason == row["reason"]


# ── degraded: the local checkout's own HEAD can't be read ──────────────────


def test_local_head_unreadable_is_degraded_not_unconfigured(db, tmp_path, monkeypatch):
    """DASHBOARD_REPO_DIR points somewhere that isn't a git checkout at all
    (e.g. deploy.sh's own preflight would refuse to run) -- a real break on
    this box, must degrade both the check and the tick."""
    not_a_repo = tmp_path / "not-a-repo"
    not_a_repo.mkdir()
    sha_file = not_a_repo / "DEPLOYED_SHA"
    _write_sha_file(sha_file, "b" * 40)
    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(not_a_repo))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(sha_file))
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "deploy-drift-check", lambda: dashboard._run_deploy_drift_check_tick(now), now
    )

    check_row = _status("deploy_drift")
    assert check_row["state"] == "degraded"
    assert "could not read local checkout HEAD" in check_row["reason"]
    assert _status("tick_deploy_drift_check")["state"] == "degraded"


# ── never ok on partial information ─────────────────────────────────────────


@pytest.mark.parametrize(
    "setup",
    ["missing_file", "corrupt_file", "not_a_repo"],
)
def test_never_reports_ok_without_a_positive_match(db, tmp_path, monkeypatch, setup):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    sha_file = repo_dir / "DEPLOYED_SHA"

    if setup == "missing_file":
        _init_repo(repo_dir)
        # sha_file deliberately not created
    elif setup == "corrupt_file":
        _init_repo(repo_dir)
        sha_file.write_text("garbage\n")
    elif setup == "not_a_repo":
        _write_sha_file(sha_file, "c" * 40)
        # repo_dir deliberately has no .git

    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(repo_dir))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(sha_file))
    now = datetime.now(timezone.utc)

    dashboard._run_deploy_drift_check_tick(now)

    assert _status("deploy_drift")["state"] in ("unconfigured", "degraded")
    assert _status("deploy_drift")["state"] != "ok"
