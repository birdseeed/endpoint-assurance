"""
Tests for PAT-841/PAT-956 — automation status on the ops console Home.

Coverage:
  - The Home section renders a compact all-automation summary and a link out to
    the full Automations view.
  - The summary fetches from the SAME /admin/automations data source
    the Automations tab (PAT-595) and the automation-alerts Slack tick
    (PAT-643) already use — no new endpoint invented.
  - The render logic distinguishes success / failed / no-run states and sorts
    failed or warning jobs to the top.
  - GET /admin/automations (the existing PAT-595 proxy the card reuses)
    continues to proxy through untouched, including when the upstream jobs
    list only contains mirror_pipeline and omits mirror_pipeline_windows
    entirely — the scenario the card must render gracefully.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

BEARER = {"Authorization": "Bearer test-key"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


def _extract_fn(text, name):
    # Pull a single top-level `function <name>(...) { ... }` body by brace
    # match — same technique as tests/test_pat697.py.
    start = text.index("function " + name + "(")
    i = text.index("{", start)
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[start:j + 1]
    raise AssertionError("unbalanced braces for " + name)


# ── Card scaffold present on Home ─────────────────────────────────────────────

class TestCardScaffold:
    def test_home_has_automation_summary_containers(self, client):
        r = client.get("/console")
        assert r.status_code == 200
        assert 'id="home-service-exceptions" aria-busy="true"' in r.text
        assert '/static/js/console-service-exceptions.js?v=' in r.text
        assert '>Service exceptions</h2>' in r.text

    def test_card_links_out_to_automations(self, client):
        r = client.get("/console")
        # Same nav mechanism the rest of Home's "View all X →" links use.
        assert "consoleNav('automations')" in r.text

    def test_loader_wired_into_home_refresh(self, client):
        r = client.get("/console")
        fn = _extract_fn(r.text, "_loadHomeData")
        assert "PatchedServiceExceptions.load(adminFetch, !!force)" in fn
        assert "_loadHomeAutomations(" not in fn
        assert "_loadHomeAttention(" not in fn
        assert "_loadHomePatchQueue(" not in fn


# ── Reuses the existing /admin/automations data source, no new endpoint ──────

class TestDataSource:
    def test_render_fn_reads_recent_runs_shape(self, client):
        r = client.get("/console")
        fn = _extract_fn(r.text, "_renderHomeAutomations")
        # Same JobSummary fields the Automations tab (_autoRender) and the
        # PAT-643 alert tick already key off: job_name, recent_runs and
        # recent_runs[].started_at.
        assert "recent_runs" in fn
        assert "assessment.state" in fn
        assert ".started_at" in fn

    def test_loader_hits_admin_automations(self, client):
        r = client.get("/console")
        fn = _extract_fn(r.text, "_loadHomeAutomations")
        assert "/admin/automations" in fn

    def test_summary_is_not_limited_to_known_mirror_jobs(self, client):
        r = client.get("/console")
        fn = _extract_fn(r.text, "_renderHomeAutomations")
        assert "active.slice()" in fn
        assert "_MIRROR_JOBS" not in r.text


# ── Graceful when a job is absent entirely (mirror_pipeline_windows today) ───

class TestWindowsAbsentGraceful:
    def test_render_fn_has_no_run_history_fallback(self, client):
        r = client.get("/console")
        fn = _extract_fn(r.text, "_renderHomeAutomations")
        assert "No run history" in fn
        assert "_autoStateLabel(assessment.state)" in fn

    def test_admin_automations_proxy_tolerates_windows_job_absent(self, client, monkeypatch):
        # The upstream go-service simply won't list mirror_pipeline_windows
        # until its automation is registered (separate in-flight PR) — the
        # proxy this card reuses must pass that straight through, not error.
        class _FakeResp:
            status_code = 200
            content = b"x"

            def json(self):
                return {
                    "jobs": [
                        {
                            "job_name": "mirror_pipeline",
                            "schedule": "Daily (06:00 UTC)",
                            "description": "Download, scan, verify and publish app binaries to Cloudflare R2 mirror",
                            "last_status": "success",
                            "last_run": "2026-07-13T06:00:00Z",
                            "recent_runs": [
                                {
                                    "id": 42,
                                    "started_at": "2026-07-13T06:00:00Z",
                                    "finished_at": "2026-07-13T06:04:00Z",
                                    "status": "success",
                                    "duration_s": 240.0,
                                    "output": "published 12 apps",
                                }
                            ],
                        }
                        # mirror_pipeline_windows deliberately absent.
                    ]
                }

        monkeypatch.setattr(dashboard.http, "get", lambda *a, **k: _FakeResp())

        r = client.get("/admin/automations", headers=BEARER)
        assert r.status_code == 200
        body = r.json()
        names = [j["job_name"] for j in body["jobs"]]
        assert names == ["mirror_pipeline"]
        assert "mirror_pipeline_windows" not in names

    def test_admin_automations_proxy_handles_both_present(self, client, monkeypatch):
        class _FakeResp:
            status_code = 200
            content = b"x"

            def json(self):
                return {
                    "jobs": [
                        {
                            "job_name": "mirror_pipeline",
                            "recent_runs": [{"status": "success", "started_at": "2026-07-13T06:00:00Z"}],
                        },
                        {
                            "job_name": "mirror_pipeline_windows",
                            "recent_runs": [{"status": "failed", "started_at": "2026-07-13T06:05:00Z"}],
                        },
                    ]
                }

        monkeypatch.setattr(dashboard.http, "get", lambda *a, **k: _FakeResp())

        r = client.get("/admin/automations", headers=BEARER)
        assert r.status_code == 200
        names = {j["job_name"] for j in r.json()["jobs"]}
        assert names == {"mirror_pipeline", "mirror_pipeline_windows"}
