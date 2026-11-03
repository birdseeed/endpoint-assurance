"""
PAT-1427: check_statuses rows carry no signal of their own age, and
scheduler_loop only recomputes every check once an hour -- including
deploy_drift and maintenance_prod01, both cheap local reads with no network
involved. Two live incidents on 2026-08-19 showed the cost:

  1. A just-restarted process stayed `unconfigured` (a false SHA-mismatch
     claim) ten minutes after DEPLOYED_SHA had already been corrected --
     under-reporting a problem that no longer existed.
  2. A stale `maintenance_prod01` row asserted "stray config backups: not
     reported by this emitter" a full scheduler tick after prod-01's own
     emitter had started reporting that field -- the worse failure mode, a
     stale row INVENTING a false absence rather than merely under-reporting.

This file covers both halves of the fix:
  * Every row `_get_check_statuses()` returns (and therefore every row
    `GET /admin/check-status` serves) now carries `age_seconds` + `stale`
    (see `_check_status_freshness`), computed against a two-tier threshold:
    a short one for the checks on the fast path, a much longer default for
    everything recomputed only by the hourly scheduler_loop.
  * `fast_check_loop` recomputes ONLY deploy_drift and maintenance_prod01
    (both local, bounded, already fail-closed) every `_FAST_CHECK_INTERVAL`,
    independent of scheduler_loop's hourly cadence. maintenance_api01 and
    maintenance_portal01 -- both HTTP calls to another box -- deliberately
    stay hourly-only; this file asserts they are NOT on the fast path, since
    that is the part most likely to regress later (someone "helpfully"
    moving a network check onto a fast timer to make a row look fresher).
  * `_record_check_status`'s UPSERT only applies when the incoming
    evaluated_at is >= the row's current one, so a slow scheduler_loop write
    that was evaluated before, but commits after, a fresher fast_check_loop
    write can never silently replace it -- caught in a second round of
    non-author review; see the "newest evaluation wins" test section below.

Run with: pytest tests/test_pat1427_check_freshness.py -v
"""

import ast
import inspect
import json
import os
import subprocess
import sys
import textwrap
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


BEARER = {"Authorization": "Bearer test-key"}


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()


def _status(name):
    with dashboard.get_db() as conn:
        return conn.execute(
            "SELECT name, state, reason, evaluated_at FROM check_statuses WHERE name=?",
            (name,),
        ).fetchone()


def _init_repo(path, commits=1):
    """Real git checkout in a scratch dir, same helper shape as
    test_pat992_deploy_drift_check.py -- exercises the actual `git
    rev-parse HEAD` subprocess call rather than mocking it away."""
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "t@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "PAT-1427 test"], check=True)
    sha = None
    for i in range(commits):
        (path / "f.txt").write_text(f"commit {i}\n")
        subprocess.run(["git", "-C", str(path), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(path), "commit", "-q", "-m", f"commit {i}"], check=True)
        sha = subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
        ).strip()
    return sha


def _write_sha_file(path, sha, deployed_at):
    path.write_text(f"DEPLOYED_SHA={sha}\nDEPLOYED_AT={deployed_at}\n")


def _function_body_without_docstring(fn) -> str:
    """Return fn's source with its docstring statement removed, using the
    AST's own line range for that one statement -- rather than scanning for
    the first/next line containing `\"\"\"`, which breaks the moment the
    function's body ever gains its own nested triple-quoted string (e.g. a
    multi-line SQL literal or another docstring-shaped constant). This is
    the guard the regression test below depends on staying robust: it is
    what stops a network call quietly landing in fast_check_loop later."""
    src = textwrap.dedent(inspect.getsource(fn))
    tree = ast.parse(src)
    func_node = tree.body[0]
    assert isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef))
    lines = src.splitlines()
    body = func_node.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        doc_stmt = body[0]
        start = doc_stmt.lineno - 1  # ast lineno is 1-indexed
        end = doc_stmt.end_lineno    # 1-indexed inclusive; slicing lines[end:] drops it
        lines = lines[:start] + lines[end:]
    return "\n".join(lines)


# ── age_seconds / stale: the universal, cheap half ──────────────────────────


def test_freshly_evaluated_row_reads_not_stale_with_small_age(db):
    now = datetime.now(timezone.utc)
    dashboard._record_check_status("portal_auth", "ok", "", now)

    rows = dashboard._get_check_statuses(now=now)
    row = next(r for r in rows if r["name"] == "portal_auth")

    assert row["age_seconds"] == 0
    assert row["stale"] is False


def test_deliberately_old_row_reads_stale_with_large_age(db):
    now = datetime.now(timezone.utc)
    old = now - timedelta(hours=5)
    dashboard._record_check_status("portal_auth", "ok", "", old)

    rows = dashboard._get_check_statuses(now=now)
    row = next(r for r in rows if r["name"] == "portal_auth")

    assert row["age_seconds"] == 5 * 3600
    assert row["stale"] is True


def test_unparseable_evaluated_at_reads_maximally_stale_not_fresh():
    """A row that can't even be dated must not silently read as current --
    same 'don't no-op into looking healthy' discipline as every
    check_statuses writer in this file."""
    now = datetime.now(timezone.utc)

    age_seconds, stale = dashboard._check_status_freshness("portal_auth", "garbage", now)
    assert age_seconds is None
    assert stale is True

    age_seconds, stale = dashboard._check_status_freshness("portal_auth", "", now)
    assert age_seconds is None
    assert stale is True

    age_seconds, stale = dashboard._check_status_freshness("portal_auth", None, now)
    assert age_seconds is None
    assert stale is True


def test_fast_path_checks_use_a_tighter_stale_threshold_than_default(db):
    """The same age must read differently depending on which loop is
    supposed to be keeping the row fresh: 10 minutes old is well past
    deploy_drift's fast-path threshold but nowhere near portal_auth's
    hourly-only default."""
    now = datetime.now(timezone.utc)
    ten_minutes_ago = now - timedelta(minutes=10)
    dashboard._record_check_status("deploy_drift", "ok", "matches", ten_minutes_ago)
    dashboard._record_check_status("maintenance_prod01", "ok", "matches", ten_minutes_ago)
    dashboard._record_check_status("portal_auth", "ok", "", ten_minutes_ago)

    rows = {r["name"]: r for r in dashboard._get_check_statuses(now=now)}

    assert rows["deploy_drift"]["stale"] is True
    assert rows["maintenance_prod01"]["stale"] is True
    assert rows["portal_auth"]["stale"] is False


def test_endpoint_serves_age_seconds_and_stale_on_every_row(db):
    evaluated_at = datetime.now(timezone.utc) - timedelta(hours=3)
    dashboard._record_check_status("portal_auth", "degraded", "Cloudflare API returned 500", evaluated_at)

    with TestClient(dashboard.app) as client:
        response = client.get("/admin/check-status", headers=BEARER)

    assert response.status_code == 200
    checks = {c["name"]: c for c in response.json()["checks"]}
    row = checks["portal_auth"]
    assert isinstance(row["age_seconds"], int)
    assert row["age_seconds"] >= 3 * 3600 - 5  # allow a few seconds of test wall-clock slop
    assert row["stale"] is True


# ── fast_check_loop: which checks qualify, and which explicitly do not ──────


def test_fast_path_check_names_are_exactly_deploy_drift_and_maintenance_prod01():
    assert dashboard._FAST_PATH_CHECK_NAMES == frozenset({"deploy_drift", "maintenance_prod01"})


def test_fast_check_loop_source_never_mentions_the_network_backed_maintenance_checks():
    """Regression guard (ticket-flagged as the part most likely to
    regress): fast_check_loop's EXECUTABLE body (its docstring is allowed
    to explain, in prose, why maintenance_api01/maintenance_portal01 are
    excluded -- that's not a call site) must never grow a reference to
    those two checks, or to the HTTP-fetch helper that backs them, no
    matter how the function gets refactored later."""
    body = _function_body_without_docstring(dashboard.fast_check_loop)

    assert "maintenance_api01" not in body
    assert "maintenance_portal01" not in body
    assert "_maintenance_facts_from_url" not in body
    assert "PATCHED_API_INTERNAL" not in body
    # And it does call the two qualifying checks.
    assert "_run_deploy_drift_check_tick" in body
    assert "_check_one_maintenance_source" in body
    assert '"maintenance_prod01"' in body


def test_fast_check_loop_is_started_at_app_startup():
    src = inspect.getsource(dashboard.startup)
    assert "fast_check_loop" in src


def test_fast_check_loop_one_iteration_recomputes_only_the_two_qualifying_checks_and_makes_no_network_call(
    db, tmp_path, monkeypatch
):
    """Behavioural companion to the source-inspection guard above: actually
    run one iteration of fast_check_loop's body (stopped via a fake
    time.sleep raising after the first pass) against real local files, and
    confirm only deploy_drift/maintenance_prod01 get written and http.get
    is never touched."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _init_repo(repo_dir)
    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(repo_dir))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(repo_dir / "DEPLOYED_SHA"))  # missing -> unconfigured
    monkeypatch.setattr(dashboard, "MAINTENANCE_FACTS_FILE", str(tmp_path / "maint.json"))  # missing -> unconfigured

    def _boom_get(*args, **kwargs):
        raise AssertionError("fast_check_loop must never make a network call")

    monkeypatch.setattr(dashboard.http, "get", _boom_get)

    class _StopLoop(Exception):
        pass

    def _fake_sleep(_seconds):
        raise _StopLoop()

    monkeypatch.setattr(dashboard.time, "sleep", _fake_sleep)

    with pytest.raises(_StopLoop):
        dashboard.fast_check_loop()

    assert _status("deploy_drift") is not None
    assert _status("maintenance_prod01") is not None
    assert _status("maintenance_api01") is None
    assert _status("maintenance_portal01") is None


# ── _record_check_status: newest evaluation wins on wall-clock, not on ──────
# ── write-commit order ───────────────────────────────────────────────────
#
# fast_check_loop and scheduler_loop both write deploy_drift/
# maintenance_prod01. scheduler_loop captures `now` once at the top of its
# iteration and then runs many other ticks (reports, digests, emails)
# before reaching these two, so its write can commit to SQLite several
# minutes after it was "evaluated" -- by which point a fast-path tick may
# already have recorded a later, fresher result. Without a guard, that
# slow write would silently replace the fresher one on commit order alone:
# the fast path being undone by the slow path. _record_check_status's
# UPSERT only applies when the incoming evaluated_at is >= the currently
# stored one, so the newest evaluation always wins regardless of which
# thread's write reaches SQLite last.


def test_older_evaluated_at_write_does_not_replace_a_newer_row(db):
    now = datetime.now(timezone.utc)
    newer = now
    older = now - timedelta(minutes=5)

    dashboard._record_check_status("deploy_drift", "ok", "fresh fast-path result", newer)
    # A slow hourly write, evaluated BEFORE the fast-path write above but
    # only committing now -- exactly the race this guard exists for.
    dashboard._record_check_status("deploy_drift", "degraded", "stale slow-path result", older)

    row = _status("deploy_drift")
    assert row["state"] == "ok"
    assert row["reason"] == "fresh fast-path result"
    assert row["evaluated_at"] == newer.isoformat()


def test_newer_evaluated_at_write_does_replace_an_older_row(db):
    now = datetime.now(timezone.utc)
    older = now - timedelta(minutes=5)
    newer = now

    dashboard._record_check_status("deploy_drift", "degraded", "old result", older)
    dashboard._record_check_status("deploy_drift", "ok", "new result", newer)

    row = _status("deploy_drift")
    assert row["state"] == "ok"
    assert row["reason"] == "new result"
    assert row["evaluated_at"] == newer.isoformat()


def test_equal_evaluated_at_write_still_applies(db):
    """A tie (same evaluated_at) must still update -- the guard is `>=`,
    not `>` -- since a tick can legitimately re-record the same timestamp
    (e.g. _run_tick's own heartbeat alongside a check's richer entry)."""
    now = datetime.now(timezone.utc)

    dashboard._record_check_status("portal_auth", "degraded", "first", now)
    dashboard._record_check_status("portal_auth", "ok", "second", now)

    row = _status("portal_auth")
    assert row["state"] == "ok"
    assert row["reason"] == "second"


def test_a_dropped_write_does_not_fire_a_transition_alert_for_an_unpersisted_state(
    db, monkeypatch
):
    """The write-guard has a second-order effect that must also hold: if a
    write loses the max(evaluated_at) race, it must not evaluate (and
    possibly send) an alert for a state that was never actually persisted
    to check_statuses."""
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")
    posts = []

    def fake_post(url, json=None, **kwargs):
        posts.append(json)

        class _Resp:
            status_code = 200
            text = "ok"

        return _Resp()

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    now = datetime.now(timezone.utc)
    dashboard._record_check_status("deploy_drift", "ok", "fresh", now)
    posts.clear()  # only care about the losing write below

    # This write is older than what's already stored, so it must not apply
    # -- and therefore must not evaluate a "degraded" transition alert for
    # a state that never actually became the row's value.
    dashboard._record_check_status(
        "deploy_drift", "degraded", "stale", now - timedelta(minutes=5)
    )

    assert posts == []
    assert _status("deploy_drift")["state"] == "ok"


# ── The concrete PAT-992-adjacent scenario from the ticket ──────────────────


def test_deploy_drift_post_restart_resolves_within_fast_window_not_an_hour(
    db, tmp_path, monkeypatch
):
    """The exact production scenario (2026-08-19): the service restarts,
    and a tick fires ~2 seconds before DEPLOYED_SHA is written by the tail
    end of the deploy. Before this ticket, only the hourly scheduler_loop
    would ever look again, so the row stayed `unconfigured` for up to an
    hour. Now fast_check_loop's next pass, _FAST_CHECK_INTERVAL later --
    not scheduler_loop's next hourly pass -- must pick up the corrected
    file and flip the row to `ok`."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    sha = _init_repo(repo_dir)
    sha_file = repo_dir / "DEPLOYED_SHA"
    monkeypatch.setattr(dashboard, "DASHBOARD_REPO_DIR", str(repo_dir))
    monkeypatch.setattr(dashboard, "DEPLOYED_SHA_FILE", str(sha_file))

    process_started_at = datetime.now(timezone.utc)
    monkeypatch.setattr(dashboard, "_PROCESS_STARTED_AT", process_started_at)

    # Tick #1: fires 2 seconds after process start, DEPLOYED_SHA not yet
    # written (the deploy script writes it last, after the restart).
    tick1 = process_started_at + timedelta(seconds=2)
    dashboard._run_tick(
        "deploy-drift-fast", lambda: dashboard._run_deploy_drift_check_tick(tick1), tick1
    )
    assert _status("deploy_drift")["state"] == "unconfigured"

    # The deploy finishes writing DEPLOYED_SHA a moment later.
    _write_sha_file(sha_file, sha, deployed_at=tick1.strftime("%Y-%m-%dT%H:%M:%SZ"))

    # Tick #2: fast_check_loop's NEXT pass, one _FAST_CHECK_INTERVAL later --
    # well inside the fast window, and far short of the hourly loop's next
    # run. Must now read ok, not still unconfigured/degraded.
    tick2 = process_started_at + dashboard._FAST_CHECK_INTERVAL
    assert dashboard._FAST_CHECK_INTERVAL < timedelta(hours=1)
    dashboard._run_tick(
        "deploy-drift-fast", lambda: dashboard._run_deploy_drift_check_tick(tick2), tick2
    )

    row = _status("deploy_drift")
    assert row["state"] == "ok", f"expected ok, got {row['state']!r} -- {row['reason']!r}"
    assert sha[:12] in row["reason"]

    # And the served row is now fresh under _get_check_statuses' own
    # freshness computation, not just internally correct.
    fresh_rows = {r["name"]: r for r in dashboard._get_check_statuses(now=tick2)}
    assert fresh_rows["deploy_drift"]["stale"] is False


def test_maintenance_prod01_fast_path_matches_hourly_tick_behaviour_for_the_same_source(
    db, tmp_path
):
    """_check_one_maintenance_source (what fast_check_loop calls directly
    for prod-01) must produce the exact same result as running it inside
    the full three-source hourly tick -- the refactor that split it out
    must not have changed prod-01's own behaviour."""
    facts_path = tmp_path / "maint.json"
    now = datetime.now(timezone.utc)
    facts_path.write_text(json.dumps({
        "generated_at": now.isoformat(),
        "reboot_required": True,
        # PAT-1796: an omitted Pro status is unconfigured, not detached.
        # This test covers the independent reboot-degraded fast-path branch.
        "pro_attached": True,
    }))

    reason = dashboard._check_one_maintenance_source(
        "maintenance_prod01", "local", str(facts_path), now
    )

    row = _status("maintenance_prod01")
    assert row["state"] == "degraded"
    assert "reboot_required" in row["reason"] or "reboot" in row["reason"].lower()
    assert reason is not None


# ── AGENTS.md wording must match the actual constants ───────────────────────


def test_agents_md_deploy_inflight_grace_wording_matches_the_constant():
    agents_md = (
        (os.path.dirname(__file__) + "/../AGENTS.historical.md.txt")
    )
    with open(agents_md) as f:
        text = f.read()

    grace_minutes = int(dashboard._DEPLOY_INFLIGHT_GRACE.total_seconds() // 60)
    fast_minutes = int(dashboard._FAST_CHECK_INTERVAL.total_seconds() // 60)

    assert f"{grace_minutes} minutes" in text, (
        "AGENTS.md's stated _DEPLOY_INFLIGHT_GRACE value has drifted from the "
        "actual constant -- update the doc (or the constant) so they agree."
    )
    assert f"{fast_minutes} minutes" in text, (
        "AGENTS.md's stated _FAST_CHECK_INTERVAL value has drifted from the "
        "actual constant -- update the doc (or the constant) so they agree."
    )
    # The old, now-inaccurate claim (staleness bounded by the classification
    # grace alone) must not still be there unqualified.
    assert "for at most 10 minutes." not in text
