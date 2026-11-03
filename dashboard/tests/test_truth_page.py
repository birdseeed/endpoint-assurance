"""PAT-1303 — operational truth page.

The problem this page exists to solve: things that fail safe are invisible
when they fail (a job with no credential, a monitor that never ran, a check
that degrades then reports itself healthy). The architecture that prevents
that: a declared manifest joined against observed evidence, where absence of
evidence renders amber, never green, and is never silently dropped from the
output.

These tests cover truth.py's pure evaluation core (load_manifest,
evaluate_entry, evaluate_all/aggregate) plus the collection layer's
dependency-injected functions (systemd/log_tail/check_status/github), and
the /admin/truth route wiring in main.py.
"""
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import truth  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)

BASE_ENTRY = {
    "id": "test-entry",
    "scope": "prod-01",
    "name": "test job",
    "proves": "the test job ran and exited zero",
    "cadence_seconds": 600,
    "stale_after_seconds": 1800,
    "evidence": {"kind": "systemd", "locator": "test.service"},
}


def _entry(**overrides):
    e = {**BASE_ENTRY, "evidence": dict(BASE_ENTRY["evidence"])}
    for k, v in overrides.items():
        if k == "evidence":
            e["evidence"].update(v)
        else:
            e[k] = v
    return e


# ─────────────────────────────────────────────────────────────────────────
# evaluate_entry — the core contract
# ─────────────────────────────────────────────────────────────────────────

def test_none_observation_is_amber_and_names_what_is_missing():
    """The single most load-bearing rule in this file: an entry nobody has
    wired a collector for must render amber, and must say so, not disappear
    and not pass."""
    state, reason = truth.evaluate_entry(_entry(), None, NOW)
    assert state == "amber"
    assert "no observation" in reason.lower() or "no collector" in reason.lower()
    assert "test job" in reason


def test_known_missing_observation_uses_its_own_detail_as_reason():
    """An Observation with observed_at=None (collector ran, actively knows
    why there's no evidence — e.g. no GitHub token) is still amber, but the
    reason is the specific one the collector determined, not the generic
    fallback."""
    obs = truth.Observation(observed_at=None, success=None, detail="no GitHub token configured")
    state, reason = truth.evaluate_entry(_entry(), obs, NOW)
    assert state == "amber"
    assert reason == "no GitHub token configured"


def test_stale_observation_is_amber_not_green():
    obs = truth.Observation(
        observed_at=NOW - timedelta(seconds=BASE_ENTRY["stale_after_seconds"] + 1),
        success=True,
        detail="ran fine",
    )
    state, reason = truth.evaluate_entry(_entry(), obs, NOW)
    assert state == "amber"
    assert "stale" in reason.lower() or "old" in reason.lower()


def test_fresh_successful_observation_is_green():
    obs = truth.Observation(observed_at=NOW - timedelta(seconds=60), success=True, detail="exit 0")
    state, reason = truth.evaluate_entry(_entry(), obs, NOW)
    assert state == "green"
    assert reason == "exit 0"


def test_failing_observation_is_red():
    obs = truth.Observation(observed_at=NOW - timedelta(seconds=60), success=False, detail="exit 1")
    state, reason = truth.evaluate_entry(_entry(), obs, NOW)
    assert state == "red"
    assert reason == "exit 1"


def test_fresh_but_indeterminate_observation_is_amber():
    """success=None (e.g. a check_statuses 'unconfigured' row) is fresh
    evidence that still cannot determine a state — amber, not a guess."""
    obs = truth.Observation(observed_at=NOW - timedelta(seconds=60), success=None, detail="cannot determine")
    state, reason = truth.evaluate_entry(_entry(), obs, NOW)
    assert state == "amber"
    assert reason == "cannot determine"


def test_retired_entry_short_circuits_to_retired_state():
    """PAT-1342: a decommissioned job carries a top-level `retired` block and
    must render as its own state, never amber (that would misread as an
    unresolved evidence gap) and never dropped. This must win even when
    there is genuinely no observation to collect."""
    entry = _entry(retired={"at": "2026-08-16", "reason": "endpoint removed by PAT-852"})
    state, reason = truth.evaluate_entry(entry, None, NOW)
    assert state == "retired"
    assert "2026-08-16" in reason
    assert "endpoint removed by PAT-852" in reason


def test_retired_entry_ignores_any_observation_present():
    """Even a fresh, failing observation must not override retirement --
    retired is a declared fact about the job, not a read of stale evidence."""
    entry = _entry(retired={"at": "2026-08-16", "reason": "endpoint removed"})
    obs = truth.Observation(observed_at=NOW, success=False, detail="stale evidence still on disk")
    state, reason = truth.evaluate_entry(entry, obs, NOW)
    assert state == "retired"


def test_conditional_retirement_requires_verified_release_commit():
    entry = _entry(retired={
        "at": "2026-09-08",
        "reason": "upstream workflow deleted",
        "requires_github_commit": {
            "repo": "Patched-LTD/updater",
            "sha": "e" * 40,
            "branch": "main",
        },
    })

    state, reason = truth.evaluate_entry(entry, None, NOW)
    assert state == "amber"
    assert "retirement pending" in reason

    state, reason = truth.evaluate_entry(
        entry,
        truth.Observation(NOW, False, "commit is not on updater main"),
        NOW,
    )
    assert state == "red"
    assert reason == "commit is not on updater main"

    state, reason = truth.evaluate_entry(
        entry,
        truth.Observation(NOW, True, "commit is on updater main"),
        NOW,
    )
    assert state == "retired"
    assert "upstream workflow deleted" in reason


def test_evidence_source_that_does_not_exist_is_amber_never_dropped():
    """PAT-1086 case: a manifest entry whose evidence source (e.g. a systemd
    unit) does not exist at all on the box must still appear in the output,
    as amber — never silently dropped. collect_systemd_observation returns
    None when the unit doesn't exist; evaluate_all must still produce a row
    for it."""
    manifest = [_entry(id="ghost-unit", name="ghost unit that was never installed")]
    observations = {"ghost-unit": None}  # simulates "unit doesn't exist" collection result
    results = truth.evaluate_all(manifest, observations, NOW)
    assert len(results) == 1
    assert results[0]["id"] == "ghost-unit"
    assert results[0]["state"] == "amber"
    assert "ghost unit" in results[0]["reason"]


# ─────────────────────────────────────────────────────────────────────────
# load_manifest — loud errors at load, not silently skipped rows
# ─────────────────────────────────────────────────────────────────────────

def test_load_manifest_rejects_entry_missing_proves(tmp_path):
    bad = [{**_entry(), "proves": None}]
    del bad[0]["proves"]
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump(bad))
    with pytest.raises(truth.ManifestError, match="proves"):
        truth.load_manifest(p)


def test_load_manifest_rejects_entry_missing_stale_after_seconds(tmp_path):
    bad = [{**_entry()}]
    del bad[0]["stale_after_seconds"]
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump(bad))
    with pytest.raises(truth.ManifestError, match="stale_after_seconds"):
        truth.load_manifest(p)


def test_load_manifest_rejects_duplicate_ids(tmp_path):
    p = tmp_path / "dup.yaml"
    p.write_text(yaml.safe_dump([_entry(), _entry()]))
    with pytest.raises(truth.ManifestError, match="duplicate"):
        truth.load_manifest(p)


def test_load_manifest_rejects_unknown_evidence_kind(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump([_entry(evidence={"kind": "carrier_pigeon", "locator": "x"})]))
    with pytest.raises(truth.ManifestError, match="evidence.kind"):
        truth.load_manifest(p)


def test_load_manifest_rejects_stale_smaller_than_cadence(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump([_entry(cadence_seconds=1000, stale_after_seconds=500)]))
    with pytest.raises(truth.ManifestError, match="stale_after_seconds"):
        truth.load_manifest(p)


def test_load_manifest_rejects_absent_kind_missing_reason(tmp_path):
    p = tmp_path / "bad.yaml"
    entry = _entry(evidence={"kind": "absent"})
    del entry["evidence"]["locator"]
    p.write_text(yaml.safe_dump([entry]))
    with pytest.raises(truth.ManifestError, match="reason"):
        truth.load_manifest(p)


def test_load_manifest_accepts_absent_kind_with_reason_and_no_locator(tmp_path):
    p = tmp_path / "ok.yaml"
    entry = _entry(evidence={"kind": "absent", "reason": "not reachable"})
    del entry["evidence"]["locator"]
    p.write_text(yaml.safe_dump([entry]))
    loaded = truth.load_manifest(p)
    assert len(loaded) == 1


def test_load_manifest_rejects_retired_missing_reason(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump([_entry(retired={"at": "2026-08-16"})]))
    with pytest.raises(truth.ManifestError, match="retired.reason"):
        truth.load_manifest(p)


def test_load_manifest_rejects_retired_missing_at(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump([_entry(retired={"reason": "endpoint removed"})]))
    with pytest.raises(truth.ManifestError, match="retired.at"):
        truth.load_manifest(p)


def test_load_manifest_accepts_retired_with_at_and_reason(tmp_path):
    p = tmp_path / "ok.yaml"
    entry = _entry(retired={"at": "2026-08-16", "reason": "endpoint removed"})
    p.write_text(yaml.safe_dump([entry]))
    loaded = truth.load_manifest(p)
    assert len(loaded) == 1
    assert loaded[0]["retired"]["reason"] == "endpoint removed"


@pytest.mark.parametrize(
    ("prerequisite", "message"),
    [
        ({"repo": "updater", "sha": "e" * 40, "branch": "main"}, "owner/repository"),
        ({"repo": "Patched-LTD/updater", "sha": "short", "branch": "main"}, "40-character"),
        ({"repo": "Patched-LTD/updater", "sha": "e" * 40, "branch": ""}, "Git ref"),
    ],
)
def test_load_manifest_rejects_invalid_retirement_prerequisite(tmp_path, prerequisite, message):
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump([_entry(retired={
        "at": "2026-09-08",
        "reason": "workflow removed",
        "requires_github_commit": prerequisite,
    })]))

    with pytest.raises(truth.ManifestError, match=message):
        truth.load_manifest(path)


def test_the_real_manifest_loads_cleanly():
    """The actual checked-in truth_manifest.yaml must load without error —
    this is what would catch a hand-editing mistake before it ships."""
    manifest = truth.load_manifest(REPO / "truth_manifest.yaml")
    assert len(manifest) > 20
    ids = [e["id"] for e in manifest]
    assert len(ids) == len(set(ids))
    for entry in manifest:
        assert entry["proves"].strip()


def test_real_manifest_carries_the_retired_catalogue_sync_entry():
    """PAT-1342: the dead catalogue-suggestions-sync cron was removed from
    the box, but its manifest row must stay -- retired, not deleted -- so it
    never reads as a job that was simply never declared."""
    manifest = truth.load_manifest(REPO / "truth_manifest.yaml")
    by_id = {e["id"]: e for e in manifest}
    entry = by_id["prod01-catalogue-suggestions-sync"]
    assert entry["retired"]["at"] == "2026-08-16"
    assert entry["retired"]["reason"].strip()
    state, reason = truth.evaluate_entry(entry, None, NOW)
    assert state == "retired"


# ─────────────────────────────────────────────────────────────────────────
# aggregate / sort_worst_first
# ─────────────────────────────────────────────────────────────────────────

def test_aggregate_counts_each_state():
    manifest = [_entry(id=f"e{i}") for i in range(3)]
    observations = {
        "e0": truth.Observation(NOW, True, "ok"),
        "e1": truth.Observation(NOW, False, "bad"),
        "e2": None,
    }
    results = truth.evaluate_all(manifest, observations, NOW)
    summary = truth.aggregate(results)
    assert summary == {
        "green": 1,
        "red": 1,
        "amber": 1,
        "retired": 0,
        "quarantined": 0,
        "total": 3,
    }


def test_sort_worst_first_orders_red_amber_green():
    manifest = [_entry(id="g"), _entry(id="a"), _entry(id="r")]
    observations = {
        "g": truth.Observation(NOW, True, "ok"),
        "a": None,
        "r": truth.Observation(NOW, False, "bad"),
    }
    results = truth.evaluate_all(manifest, observations, NOW)
    sorted_results = truth.sort_worst_first(results)
    assert [r["id"] for r in sorted_results] == ["r", "a", "g"]


# ─────────────────────────────────────────────────────────────────────────
# collection layer — dependency-injected, no real box/network/DB
# ─────────────────────────────────────────────────────────────────────────

def _fake_run(stdout: str):
    def runner(*args, **kwargs):
        return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")
    return runner


def test_collect_systemd_observation_missing_unit_returns_none():
    runner = _fake_run("")  # systemctl show on a nonexistent unit prints empty properties
    obs = truth.collect_systemd_observation("ghost.service", NOW, runner=runner)
    assert obs is None


def test_collect_systemd_observation_success():
    """A genuinely healthy, currently-loaded service still returns its normal
    successful Observation -- PAT-1411's LoadState guard must not turn every
    entry amber, only ones whose unit definition is actually gone."""
    stdout = (
        "ActiveState=inactive\n"
        "LoadState=loaded\n"
        "Result=success\n"
        "ExecMainStatus=0\n"
        "ExecMainStartTimestamp=Thu 2026-08-13 23:30:33 UTC\n"
        "ExecMainExitTimestamp=Thu 2026-08-13 23:30:34 UTC\n"
    )
    obs = truth.collect_systemd_observation("ok.service", NOW, runner=_fake_run(stdout))
    assert obs is not None
    assert obs.success is True
    assert obs.observed_at == datetime(2026, 8, 13, 23, 30, 34, tzinfo=timezone.utc)


def test_collect_systemd_observation_failure():
    stdout = (
        "ActiveState=failed\n"
        "LoadState=loaded\n"
        "Result=exit-code\n"
        "ExecMainStatus=1\n"
        "ExecMainStartTimestamp=Thu 2026-08-13 01:37:11 UTC\n"
        "ExecMainExitTimestamp=Thu 2026-08-13 01:37:41 UTC\n"
    )
    obs = truth.collect_systemd_observation("bad.service", NOW, runner=_fake_run(stdout))
    assert obs is not None
    assert obs.success is False


def test_collect_systemd_observation_disabled_timer_is_failure():
    """A genuinely present-but-disabled timer (LoadState=loaded, just not
    enabled) still returns the existing "will never fire" failure
    Observation -- PAT-1411's LoadState guard is additional, not a
    replacement for this check."""
    stdout = "ActiveState=inactive\nLoadState=loaded\nUnitFileState=disabled\nLastTriggerUSec=\n"
    obs = truth.collect_systemd_observation("dead.timer", NOW, runner=_fake_run(stdout))
    assert obs is not None
    assert obs.success is False
    assert "disabled" in obs.detail


# ─────────────────────────────────────────────────────────────────────────
# PAT-1411 -- LoadState guard against a removed unit whose runtime object is
# kept alive by a paired unit (found live on patched-prod-01 during PAT-1304's
# injected-failure proof: removing patched-dashboard-prune-reports.service
# and running `systemctl daemon-reload` did NOT turn the truth page amber,
# because the paired .timer kept the service's runtime object alive, and
# `systemctl show` on the removed service kept reporting the LAST REAL RUN's
# ActiveState=inactive / Result=success / ExecMainStatus=0 forever).
# ─────────────────────────────────────────────────────────────────────────

def test_collect_systemd_observation_removed_service_with_surviving_timer_is_no_evidence():
    """The exact live shape found on patched-prod-01: LoadState=not-found,
    but ActiveState/Result/ExecMainStatus still carry the last real run
    forward because the paired .timer kept the runtime object alive. Must be
    no-evidence (None), NOT a stale green Observation."""
    stdout = (
        "ActiveState=inactive\n"
        "LoadState=not-found\n"
        "Result=success\n"
        "ExecMainStatus=0\n"
        "ExecMainStartTimestamp=Thu 2026-08-13 23:30:33 UTC\n"
        "ExecMainExitTimestamp=Thu 2026-08-13 23:30:34 UTC\n"
    )
    obs = truth.collect_systemd_observation(
        "patched-dashboard-prune-reports.service", NOW, runner=_fake_run(stdout),
    )
    assert obs is None


def test_collect_systemd_observation_removed_timer_with_surviving_runtime_object_is_no_evidence():
    """Same shape, .timer branch: a removed .timer file whose runtime object
    is still kept alive reports LoadState=not-found. Must be no-evidence,
    not a stale "enabled and active" Observation."""
    stdout = "ActiveState=active\nLoadState=not-found\nUnitFileState=enabled\nLastTriggerUSec=12345\n"
    obs = truth.collect_systemd_observation("dead.timer", NOW, runner=_fake_run(stdout))
    assert obs is None


def test_collect_systemd_observation_masked_service_is_no_evidence():
    stdout = (
        "ActiveState=inactive\n"
        "LoadState=masked\n"
        "Result=success\n"
        "ExecMainStatus=0\n"
        "ExecMainStartTimestamp=Thu 2026-08-13 23:30:33 UTC\n"
        "ExecMainExitTimestamp=Thu 2026-08-13 23:30:34 UTC\n"
    )
    obs = truth.collect_systemd_observation("masked.service", NOW, runner=_fake_run(stdout))
    assert obs is None


def test_collect_check_status_observation_maps_ok_to_success_true():
    rows = {"deploy_drift": {"state": "ok", "reason": "", "evaluated_at": NOW.isoformat()}}
    obs = truth.collect_check_status_observation("deploy_drift", rows)
    assert obs.success is True


def test_collect_check_status_observation_maps_degraded_to_success_false():
    rows = {"rbac_operators": {"state": "degraded", "reason": "unset", "evaluated_at": NOW.isoformat()}}
    obs = truth.collect_check_status_observation("rbac_operators", rows)
    assert obs.success is False


def test_collect_check_status_observation_maps_unconfigured_to_indeterminate():
    rows = {"x": {"state": "unconfigured", "reason": "grace window", "evaluated_at": NOW.isoformat()}}
    obs = truth.collect_check_status_observation("x", rows)
    assert obs.success is None


def test_collect_check_status_observation_missing_row_returns_none():
    assert truth.collect_check_status_observation("nope", {}) is None


def test_collect_log_tail_observation_success_pattern(tmp_path):
    p = tmp_path / "sync.log"
    p.write_text('{"ok":true,"synced":50}\n')
    obs = truth.collect_log_tail_observation(str(p), NOW, success_pattern=r'"ok":true', failure_pattern=r'"error"')
    assert obs.success is True


def test_collect_log_tail_observation_failure_pattern(tmp_path):
    p = tmp_path / "sync.log"
    p.write_text('{"error":"Unauthorized"}\n')
    obs = truth.collect_log_tail_observation(str(p), NOW, success_pattern=r'"ok":true', failure_pattern=r'"error"')
    assert obs.success is False


def test_collect_log_tail_observation_missing_file_returns_none(tmp_path):
    obs = truth.collect_log_tail_observation(str(tmp_path / "nope.log"), NOW)
    assert obs is None


def test_collect_github_workflow_observation_no_token_is_known_missing():
    obs = truth.collect_github_workflow_observation("x.yml", None, NOW)
    assert obs is not None
    assert obs.observed_at is None
    assert obs.detail == "no GitHub token configured"
    # And evaluate_entry turns that into the exact amber reason:
    state, reason = truth.evaluate_entry(_entry(), obs, NOW)
    assert state == "amber"
    assert reason == "no GitHub token configured"


def test_collect_github_workflow_observation_with_token_parses_run():
    class _FakeResp:
        status_code = 200
        def json(self):
            return {
                "workflow_runs": [{
                    "run_started_at": "2026-08-13T03:00:10Z",
                    "conclusion": "failure",
                    "status": "completed",
                }]
            }
    obs = truth.collect_github_workflow_observation(
        "daily-vendor-verify.yml", "tok", NOW, repo="Patched-LTD/updater",
        http_get=lambda *a, **k: _FakeResp(),
    )
    assert obs.success is False
    assert obs.observed_at == datetime(2026, 8, 13, 3, 0, 10, tzinfo=timezone.utc)


def test_collect_github_commit_ancestor_without_token_is_known_missing():
    obs = truth.collect_github_commit_ancestor_observation(
        "Patched-LTD/updater", "e" * 40, "main", None, NOW,
    )

    assert obs.observed_at is None
    assert obs.success is None
    assert "no GitHub token" in obs.detail


@pytest.mark.parametrize(
    ("compare_status", "expected"),
    [("ahead", True), ("identical", True), ("behind", False), ("diverged", False)],
)
def test_collect_github_commit_ancestor_classifies_compare_status(compare_status, expected):
    class _FakeResp:
        status_code = 200

        def json(self):
            return {"status": compare_status}

    seen = {}

    def _get(url, **kwargs):
        seen.update(url=url, kwargs=kwargs)
        return _FakeResp()

    obs = truth.collect_github_commit_ancestor_observation(
        "Patched-LTD/updater", "e" * 40, "main", "tok", NOW, http_get=_get,
    )

    assert obs.observed_at == NOW
    assert obs.success is expected
    assert seen["url"].endswith("/repos/Patched-LTD/updater/compare/" + "e" * 40 + "...main")
    assert seen["kwargs"]["timeout"] == 10


# ─────────────────────────────────────────────────────────────────────────
# collect_observation dispatcher — scope-aware routing
# ─────────────────────────────────────────────────────────────────────────

def test_dispatcher_absent_kind_always_amber_with_configured_reason():
    entry = _entry(evidence={"kind": "absent", "reason": "tenant-zero unreachable"})
    del entry["evidence"]["locator"]
    ctx = truth.CollectionContext(now=NOW)
    obs = truth.collect_observation(entry, ctx)
    assert obs.detail == "tenant-zero unreachable"
    state, reason = truth.evaluate_entry(entry, obs, NOW)
    assert state == "amber"
    assert reason == "tenant-zero unreachable"


def test_dispatcher_remote_scope_without_report_is_none():
    """api-01/portal-01 systemd entries with no reporter installed yet must
    come back as no-observation (amber) — never fabricated from a local
    systemctl call this box can't make of a remote box."""
    entry = _entry(scope="api-01", evidence={"kind": "systemd", "locator": "patched-cve-sync.service"})
    ctx = truth.CollectionContext(now=NOW, is_local_prod01=True, reported_observations={})
    obs = truth.collect_observation(entry, ctx)
    assert obs is None


def test_dispatcher_remote_scope_uses_reported_observation_when_present():
    entry = _entry(scope="api-01", id="api01-x", evidence={"kind": "systemd", "locator": "x.service"})
    reported = truth.Observation(observed_at=NOW, success=True, detail="reported by api-01")
    ctx = truth.CollectionContext(now=NOW, reported_observations={("api-01", "api01-x"): reported})
    obs = truth.collect_observation(entry, ctx)
    assert obs is reported


def test_dispatcher_agent_health_kind_is_none_not_wired_up():
    entry = _entry(scope="agent:macos", evidence={"kind": "agent_health", "locator": "sync_never_succeeded:catalogue"})
    ctx = truth.CollectionContext(now=NOW)
    assert truth.collect_observation(entry, ctx) is None


def test_dispatcher_check_status_kind_ignores_scope_locality():
    """check_status entries are readable regardless of is_local_prod01 —
    they come from this app's own DB, which it always has local access to,
    even for entries whose scope names a different box (e.g.
    maintenance_api01, pulled centrally by the existing drift-check tick)."""
    entry = _entry(scope="api-01", evidence={"kind": "check_status", "locator": "maintenance_api01"})
    rows = {"maintenance_api01": {"state": "degraded", "reason": "1 timer failed", "evaluated_at": NOW.isoformat()}}
    ctx = truth.CollectionContext(now=NOW, is_local_prod01=False, check_statuses_by_name=rows)
    obs = truth.collect_observation(entry, ctx)
    assert obs.success is False


# ─────────────────────────────────────────────────────────────────────────
# build_truth_page — end to end with fakes
# ─────────────────────────────────────────────────────────────────────────

def test_collect_all_observations_skips_retired_entries_entirely():
    """PAT-1342: retirement is decided before any collection is attempted --
    a retired entry must not touch its (possibly now-deleted) evidence
    source at all. A systemd runner that would raise proves collection was
    never invoked for it."""
    def _boom(*args, **kwargs):
        raise AssertionError("collector invoked for a retired entry")

    manifest = [
        _entry(id="retired-one", evidence={"kind": "systemd", "locator": "gone.service"},
               retired={"at": "2026-08-16", "reason": "job decommissioned"}),
    ]
    ctx = truth.CollectionContext(now=NOW, is_local_prod01=True, systemctl_runner=_boom)
    observations = truth.collect_all_observations(manifest, ctx)
    assert observations == {"retired-one": None}


def test_collect_all_observations_verifies_conditional_retirement():
    class _FakeResp:
        status_code = 200

        def json(self):
            return {"status": "ahead"}

    manifest = [
        _entry(
            id="release-ordered-retirement",
            retired={
                "at": "2026-09-08",
                "reason": "workflow removed",
                "requires_github_commit": {
                    "repo": "Patched-LTD/updater",
                    "sha": "e" * 40,
                    "branch": "main",
                },
            },
        ),
    ]
    ctx = truth.CollectionContext(
        now=NOW,
        github_token="tok",
        github_http_get=lambda *_args, **_kwargs: _FakeResp(),
    )

    observations = truth.collect_all_observations(manifest, ctx)

    assert observations["release-ordered-retirement"].success is True


def test_build_truth_page_end_to_end():
    manifest = [
        _entry(id="green-one", evidence={"kind": "check_status", "locator": "ok-check"}),
        _entry(id="red-one", evidence={"kind": "check_status", "locator": "bad-check"}),
        _entry(id="amber-one", evidence={"kind": "systemd", "locator": "ghost.service"}),
    ]
    ctx = truth.CollectionContext(
        now=NOW,
        is_local_prod01=True,
        check_statuses_by_name={
            "ok-check": {"state": "ok", "reason": "fine", "evaluated_at": NOW.isoformat()},
            "bad-check": {"state": "degraded", "reason": "broken", "evaluated_at": NOW.isoformat()},
        },
        systemctl_runner=_fake_run(""),
    )
    page = truth.build_truth_page(manifest, ctx)
    assert page["summary"] == {
        "green": 1,
        "amber": 1,
        "red": 1,
        "retired": 0,
        "quarantined": 0,
        "total": 3,
    }
    assert [c["id"] for c in page["checks"]] == ["red-one", "amber-one", "green-one"]
