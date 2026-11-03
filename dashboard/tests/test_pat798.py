"""
Tests for PAT-798 — unify stale/silent freshness wording and thresholds.

PAT-697 established the single server-owned freshness vocabulary
(DEVICE_FRESHNESS / STALE_THRESHOLD_DEFAULT_DAYS, active 7d / silent 30d) and
wired the Device Health tab + digest tick to it. This ticket audits the
remaining consumers that PAT-697 didn't touch and were still saying
"default 14 days" or hard-coding the 7/30 boundaries instead of reading the
shared config:

  - The platform-owned report catalogue's "stale-endpoints" description — was
    previously duplicated by the dashboard as "default 14 days". The dashboard
    now renders platform metadata rather than retaining its own report list.
  - The Reports Hub card copy in templates/console.html — same fix, via the
    device_freshness template context PAT-697 already injects.
  - The Tenant Overview tab's platform-mix stat row (_ovLoadDevices) — was
    hard-coding `days >= 30` / `days >= 7` and the "Stale (7-30d)" /
    "Silent (30d+)" labels instead of reusing the shared _freshnessCfg() /
    _dhFreshnessBucket() helpers the Device Health tab already uses.
  - The stale-endpoint alert config form's placeholder fallback
    (_stalePopulate) — was falling back to a bare 14 if the server response
    ever omitted default_threshold_days; now falls back to the shared
    _freshnessCfg().active_max_days.
"""

import os
import re
import sys
from datetime import datetime, timezone

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
    # Pull a single top-level `function <name>(...) { ... }` body by brace match
    # (same approach as tests/test_pat697.py's TestTemplateInjection._extract_fn).
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


def _seed_client(db_mod, tenant_id="9dcf8143-f7c5-5dba-9a2b-2feb5c6c6c12", recipient="ops@acme.test"):
    with db_mod.get_db() as db:
        db.execute(
            "INSERT INTO clients (id, company, tenant_id, "
            "created_at, primary_contact_email, stale_digest_enabled) "
            "VALUES (?,?,?,?,?,?)",
            ("id-798", "Acme", tenant_id,
             datetime.now(timezone.utc).isoformat(), recipient, 1),
        )


# ── Platform report catalogue has no dashboard fallback ───────────────────────

def _platform_catalogue(stale_description):
    return {"reports": [{
        "type": "stale-endpoints",
        "label": "Stale / Inactive Endpoints",
        "description": stale_description,
        "default_frequency": "weekly",
        "customer_facing": True,
        "subject_scope": "tenant",
        "admin_pdf_path": "/admin/reports/stale-endpoints/{tenantID}.pdf",
    }]}


class _Response:
    status_code = 200

    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


def _use_catalogue(monkeypatch, payload):
    dashboard._REPORT_CATALOGUE_CACHE.update(
        entries=None, fetched_at=0.0, failure_reason=None, failure_at=0.0,
    )
    monkeypatch.setattr(dashboard.http, "get", lambda *args, **kwargs: _Response(payload))


class TestPlatformReportCatalogue:
    def test_dashboard_has_no_local_report_catalogue(self):
        assert not hasattr(dashboard, "REPORT_CATALOG")
        assert not hasattr(dashboard, "_REPORT_PDF_PATHS")
        assert not hasattr(dashboard, "_REPORT_URL_PATHS")

    def test_catalogue_description_is_passed_through_from_platform(self, monkeypatch):
        description = "Devices that have not reported within the configured freshness threshold."
        _use_catalogue(monkeypatch, _platform_catalogue(description))
        entry = dashboard._report_catalogue()[0]
        assert entry["description"] == description

    def test_reports_config_endpoint_serves_platform_description(self, client, monkeypatch):
        _seed_client(dashboard)
        description = "Devices that have not reported within the configured freshness threshold."
        _use_catalogue(monkeypatch, _platform_catalogue(description))
        r = client.get("/admin/tenants/9dcf8143-f7c5-5dba-9a2b-2feb5c6c6c12/reports-config", headers=BEARER)
        assert r.status_code == 200
        entries = r.json()
        stale_entry = next(e for e in entries if e["type"] == "stale-endpoints")
        assert stale_entry["description"] == description


# ── Reports page (console.html) matches the same default ─────────────────────
#
# PAT-786 removed the global cross-tenant Reports Hub card grid — the only
# place `{{ device_freshness.active_max_days }}` was rendered directly into
# the /console HTML — in favour of the per-tenant Reports tab, which sources
# the same description from REPORT_CATALOG via the reports-config API
# (covered by TestReportCatalogDescription above). What's left to check here
# is that the raw /console page still carries the shared freshness config
# for the JS that consumes it, and never regresses to a hardcoded "14 days".

class TestReportsPageFreshnessCopy:
    def test_console_page_has_no_hardcoded_14(self, client):
        r = client.get("/console")
        assert r.status_code == 200
        assert "14 days" not in r.text

    def test_console_page_injects_shared_freshness_config(self, client):
        r = client.get("/console")
        assert f'"active_max_days": {dashboard.STALE_THRESHOLD_DEFAULT_DAYS}' in r.text


# ── Tenant Overview tab sources thresholds from the shared config ────────────

class TestTenantOverviewFreshness:
    def test_overview_freshness_uses_shared_helpers_not_hardcoded_days(self, client):
        # PAT-961/968: the Overview freshness logic moved from _ovLoadDevices to
        # _ov2Load; the PAT-798 guarantee (thresholds from shared config, not
        # hardcoded day literals) is unchanged and now lives there.
        r = client.get("/console")
        fn = _extract_fn(r.text, "_ov2Load")
        assert "_freshnessCfg()" in fn or "_dhFreshnessBucket(" in fn
        # No "days >= 30" / "days >= 7" literals duplicating the server config.
        assert not re.search(r"days\s*>=\s*30", fn)
        assert not re.search(r"days\s*>=\s*7\b", fn)

    def test_overview_freshness_labels_source_cfg_not_literal_boundaries(self, client):
        r = client.get("/console")
        fn = _extract_fn(r.text, "_ov2Load")
        # Labels must be built from cfg.active_max_days / cfg.silent_min_days,
        # not literal '7–30d' / '30d+' strings baked into the label text.
        assert "cfg.active_max_days" in fn
        assert "cfg.silent_min_days" in fn
        assert "'Stale (7" not in fn
        assert "'Silent (30d+)'" not in fn


# ── Stale-endpoint alert form falls back to the shared default, not 14 ───────

class TestStaleAlertFormFallback:
    def test_stale_populate_does_not_fall_back_to_14(self, client):
        r = client.get("/console")
        fn = _extract_fn(r.text, "_stalePopulate")
        assert not re.search(r"\|\|\s*14\b", fn)
        assert "_freshnessCfg()" in fn

    def test_stale_digest_config_endpoint_always_sends_default_threshold_days(self, client):
        # Belt-and-suspenders: confirm the server-side field the form reads from
        # actually reflects the shared default (7), so the fallback path is only
        # ever exercised on a malformed/legacy response.
        _seed_client(dashboard)
        r = client.get("/admin/tenants/9dcf8143-f7c5-5dba-9a2b-2feb5c6c6c12/stale-digest-config", headers=BEARER)
        assert r.status_code == 200
        assert r.json()["default_threshold_days"] == dashboard.STALE_THRESHOLD_DEFAULT_DAYS == 7
