"""
Regression tests for PAT-790 — tenant Overview mixed cached and live metrics,
producing internally inconsistent cards (top-row dashes contradicted by a
populated platform-breakdown row below).

Confirmed root cause (not just the ticket's hypothesis): `_ovActivate()` in
templates/console.html refreshed `_consoleState.tenantData` from the *bare*
`/admin/tenants` list endpoint, not `/admin/tenants/overview`. The bare endpoint
is used elsewhere in the app (e.g. `_shadowITLoad`) purely as a lightweight
`{id, name, ...}` tenant listing for CRUD / shadow-IT lookups — its upstream
Go-service response does not carry `device_count` / `active_last_7d` /
`compliance_pct` / `crit_high_fail_count`, the `TenantsOverviewItem` fields
documented at the `fetchTenantsOverview()` stub and populated into
`_consoleState.tenantData` by `enterTenant()`. main.py proxies each endpoint
verbatim (`/admin/tenants` at proxy_tenants, `/admin/tenants/overview` at
proxy_tenants_overview) — it does not normalise or backfill fields between them,
so whichever shape the upstream returns for a given path is exactly what the
frontend gets. Refreshing from the bare endpoint therefore silently wiped the
metric fields, producing dashes in the top row (Total Devices, Active (7d),
Compliance, Crit/High Fails) while `_ovLoadDevices()` — a separate, live call to
`/admin/tenants/{id}/devices` — proved devices existed in the platform-breakdown
row underneath.

Fix:
  1. `_ovActivate()` now refreshes from `/admin/tenants/overview` (the same
     endpoint that seeds `tenantData` in the first place).
  2. `_ovLoadDevices()` now also feeds a live macOS+Windows device total
     (`_ovLiveTotalDevices`) into `_ovRenderMetrics()`, which prefers it over the
     cached `device_count`. This guarantees Total Devices can never show a dash
     (or a stale/mismatched figure) once the live devices call has already
     proven devices exist — covering the case where the overview payload is
     missing or incomplete even after point 1's endpoint fix (e.g. a lagging
     cache), per acceptance criterion "missing metric fields do not cause
     misleading dashes when live data proves devices exist."
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

BEARER = {"Authorization": "Bearer test-key"}


class _FakeResp:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.content = b"x"

    def json(self):
        return self._payload


def _extract_fn(text, name):
    """Pull a single top-level `function <name>(...) { ... }` body by brace match."""
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


def _console_html():
    path = os.path.join(os.path.dirname(__file__), "..", "templates", "console.html")
    with open(path, encoding="utf-8") as f:
        return f.read()


# ── JS source: the refresh call must hit the endpoint that actually carries the
#    metric fields _ovRenderMetrics() reads ─────────────────────────────────────

class TestOvActivateRefreshEndpoint:
    def test_activate_refreshes_from_tenants_overview_not_bare_tenants(self):
        fn = _extract_fn(_console_html(), "_ovActivate")
        assert "adminFetch('/admin/tenants/overview')" in fn, (
            "_ovActivate must refresh tenantData from /admin/tenants/overview — "
            "the same endpoint that seeds it via enterTenant()/fetchTenantsOverview()"
        )
        # The historical bug: refreshing from the bare list endpoint, which does
        # not reliably carry device_count/active_last_7d/compliance_pct/
        # crit_high_fail_count.
        assert "adminFetch('/admin/tenants')" not in fn, (
            "_ovActivate must not refresh from the bare /admin/tenants endpoint — "
            "it lacks the overview metric fields and silently blanks the top-row cards"
        )

    def test_activate_guards_overview_refresh_against_mid_flight_tenant_switch(self):
        # A slow /admin/tenants/overview response for tenant A resolving after
        # the user has already switched to tenant B must not clobber B's
        # _consoleState.tenantData with A's cached figures — that would
        # reintroduce the same "inconsistent cards" symptom across tenants
        # instead of across endpoints.
        fn = _extract_fn(_console_html(), "_ovActivate")
        assert "if (_consoleState.tenantId !== tid) return;" in fn


# ── JS source: Total Devices must prefer the live devices-endpoint total so it
#    can never contradict the platform breakdown row ────────────────────────────

class TestOverviewDeviceTotalPrefersLiveData:
    def test_ov2load_derives_total_from_live_devices_with_cached_fallback(self):
        # PAT-961 replaced the old _ovLoadDevices/_ovRenderMetrics pair with
        # _ov2Load; PAT-968 deleted the now-dead originals. The PAT-790 guarantee
        # is unchanged and now lives here: the estate hero's device total is the
        # live macOS+Windows count from /devices, falling back to the cached
        # device_count only when there are no live devices — so it can never
        # contradict the live platform data or show a stale/dashed figure.
        fn = _extract_fn(_console_html(), "_ov2Load")
        # PAT-1554 appended "+ neverReported" to this line (coverage-gap
        # devices enrolled but never reporting inventory) — the PAT-790
        # guarantee itself is unchanged: live mac+win still takes priority
        # over the cached device_count, which is still only a fallback.
        assert "var totalDevices = ((mac + win) || t.device_count || 0) + neverReported;" in fn
        assert "if (os.indexOf('mac') !== -1 || os.indexOf('darwin') !== -1) mac++;" in fn
        assert "else if (os.indexOf('win') !== -1) win++;" in fn


# ── Behavioural mirror of the fixed algorithm: tenant-overview data missing,
#    devices endpoint populated (the exact PAT-790 bug scenario) ────────────────

def _render_total_devices(tenant_data, live_mac_count, live_win_count, devices_loaded):
    """Pure-Python mirror of the fixed _ovRenderMetrics()/_ovLoadDevices() logic
    for the Total Devices card, used to pin down the intended numeric behaviour
    (a JS-execution engine isn't part of this repo's test toolchain — the JS
    source assertions above guard the real implementation against drift from
    this mirror).
    """
    live_total = (live_mac_count + live_win_count) if devices_loaded else None
    device_count = tenant_data.get("device_count")
    if live_total is not None:
        return live_total
    if device_count is not None:
        return device_count
    return None


class TestOverviewRenderingWithMissingOverviewData:
    def test_total_devices_derives_from_live_devices_when_overview_missing(self):
        # Ticket's observed scenario: tenant overview payload has no device_count
        # (cached list stale/incomplete) but the live devices endpoint returned
        # 2 macOS + 1 Windows device.
        tenant_data = {"device_count": None, "active_last_7d": None,
                       "compliance_pct": None, "crit_high_fail_count": None}
        total = _render_total_devices(tenant_data, live_mac_count=2, live_win_count=1,
                                       devices_loaded=True)
        assert total == 3, "Total Devices must equal macOS + Windows once devices load"

    def test_total_devices_matches_platform_row_sum(self):
        tenant_data = {"device_count": None}
        mac, win = 5, 7
        total = _render_total_devices(tenant_data, mac, win, devices_loaded=True)
        assert total == mac + win

    def test_total_devices_falls_back_to_cached_value_before_devices_load(self):
        # Before the live devices call resolves there's nothing live to prefer —
        # cached overview data (if present) is shown, not a premature zero/dash.
        tenant_data = {"device_count": 8}
        total = _render_total_devices(tenant_data, live_mac_count=0, live_win_count=0,
                                       devices_loaded=False)
        assert total == 8

    def test_total_devices_unavailable_only_when_neither_source_has_data(self):
        tenant_data = {"device_count": None}
        total = _render_total_devices(tenant_data, live_mac_count=0, live_win_count=0,
                                       devices_loaded=False)
        assert total is None


# ── Backend proxy: confirm (don't assume) the two endpoints really do carry
#    different shapes — main.py passes each upstream response through verbatim
#    (plus a billing_tier merge on /overview), so whichever endpoint the
#    frontend calls determines whether the metric fields are present at all ────

class TestProxyEndpointShapesDiffer:
    def _client(self, tmp_path, monkeypatch):
        monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
        monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
        dashboard.init_db()
        return TestClient(dashboard.app)

    def test_overview_endpoint_passes_through_metric_fields(self, tmp_path, monkeypatch):
        upstream_overview = {"tenants": [{
            "id": "t-1", "name": "Acme",
            "device_count": 3, "active_last_7d": 2,
            "compliance_pct": 91.5, "crit_high_fail_count": 0,
        }]}

        def fake_get(url, *a, **k):
            if url.endswith("/admin/tenants/overview"):
                return _FakeResp(upstream_overview)
            return _FakeResp({"tenants": []})

        monkeypatch.setattr(dashboard.http, "get", fake_get)
        client = self._client(tmp_path, monkeypatch)
        with client:
            r = client.get("/admin/tenants/overview", headers=BEARER)
        assert r.status_code == 200
        tenant = r.json()["tenants"][0]
        assert tenant["device_count"] == 3
        assert tenant["active_last_7d"] == 2
        assert tenant["compliance_pct"] == 91.5
        assert tenant["crit_high_fail_count"] == 0

    def test_bare_tenants_endpoint_does_not_fabricate_missing_metric_fields(
        self, tmp_path, monkeypatch
    ):
        # The bare list endpoint's upstream response, as used for CRUD/shadow-IT
        # lookups, has no metric fields — main.py proxies it verbatim and does
        # not backfill them. This is exactly why the frontend must not treat
        # the two endpoints as interchangeable.
        upstream_bare = {"tenants": [{"id": "t-1", "name": "Acme"}]}

        def fake_get(url, *a, **k):
            if url.endswith("/admin/tenants"):
                return _FakeResp(upstream_bare)
            return _FakeResp({"tenants": []})

        monkeypatch.setattr(dashboard.http, "get", fake_get)
        client = self._client(tmp_path, monkeypatch)
        with client:
            r = client.get("/admin/tenants", headers=BEARER)
        assert r.status_code == 200
        tenant = r.json()["tenants"][0]
        assert "device_count" not in tenant
        assert "active_last_7d" not in tenant
        assert "compliance_pct" not in tenant
        assert "crit_high_fail_count" not in tenant
