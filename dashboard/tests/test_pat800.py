"""
Tests for PAT-800 — Device Health tab: search, filters, CSV export, and
first-class agent health states.

Covers:
  * Filter row markup: search input (hostname/serial/user/OS/device ID),
    health-state / OS / agent-version selects, CSV export button.
  * Sortable column headers wired to _dhSortBy.
  * _dhHealthState() derives active/stale/silent/missing from last_seen and
    recognises an explicit status field for suspended/revoked/errored
    ("where data exists" — no such field exists in the API today, so this
    only asserts the graceful-degradation branches are present, not live data).
  * _dhApplyFilters() searches hostname/serial/device id/os/primary user and
    respects the health-state/OS/agent-version selects.
  * _dhRender() buckets "never seen" separately from "silent" for the stat row
    and distinguishes the two empty states (no devices vs. no matches).

Run with: pytest tests/test_pat800.py -v
"""

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


@pytest.fixture
def console_html(client):
    r = client.get("/console")
    assert r.status_code == 200
    return r.text


def _extract_fn(text, name):
    # Pull a single top-level `function <name>(...) { ... }` body by brace match
    # (same approach as tests/test_pat798.py's _extract_fn).
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


# ── Filter row markup ─────────────────────────────────────────────────────────

class TestFilterRowMarkup:
    def test_search_input_present_with_useful_placeholder(self, console_html):
        assert 'id="dh-filter-search"' in console_html
        idx = console_html.index('id="dh-filter-search"')
        tag = console_html[idx:console_html.index(">", idx)]
        for term in ("hostname", "serial", "OS", "device ID"):
            assert term in tag

    def test_health_state_filter_present(self, console_html):
        assert 'id="dh-filter-state"' in console_html

    def test_os_filter_present(self, console_html):
        assert 'id="dh-filter-os"' in console_html

    def test_dedicated_version_filter_removed_in_favour_of_os_column(self, console_html):
        # PAT-1008: the standalone agent-version dropdown was already
        # permanently inert — agent_version was never present in the real
        # TenantDevicesResponse contract (confirmed against
        # go-service/internal/handlers/admin_overview.go's tenantDeviceEntry,
        # which has no AgentVersion field on this endpoint) — so it never
        # actually filtered anything in production. It's dropped along with
        # the floating dh-filter-row dropdowns. OS *and* OS version (which
        # IS real — os_version is a genuine column, see FetchTenantDevices)
        # are now both filterable from the single OS column-header select,
        # grouped by OS via <optgroup>.
        assert 'id="dh-filter-version-wrap"' not in console_html
        assert 'id="dh-filter-version"' not in console_html
        fn = _extract_fn(console_html, "_dhPopulateFilterOptions")
        assert "optgroup" in fn
        assert "osver:" in fn

    def test_csv_export_button_present(self, console_html):
        assert "_dhExportCSV()" in console_html
        assert "CSV" in console_html


# ── Sortable columns ───────────────────────────────────────────────────────────

class TestSortableColumns:
    def test_column_headers_wired_to_sort(self, console_html):
        # PAT-961 triage redesign: the Device column header now sorts by severity
        # (was hostname), and the standalone OS column was folded into the "Why
        # it's flagged" reason cell — so hostname/os are no longer sortable table
        # headers (hostname stays searchable, OS stays filterable).
        for col in ("severity", "primary_user", "last_seen", "compliance"):
            assert "_dhSortBy('" + col + "')" in console_html
            assert 'id="dh-sort-' + col + '"' in console_html

    def test_dh_sort_by_toggles_direction_on_repeat_click(self, console_html):
        fn = _extract_fn(console_html, "_dhSortBy")
        assert "_dhSortDir *= -1" in fn
        assert "_dhRender()" in fn

    def test_dh_sort_devices_covers_all_sortable_columns(self, console_html):
        fn = _extract_fn(console_html, "_dhSortDevices")
        for col in ("severity", "hostname", "os", "primary_user", "compliance", "last_seen"):
            assert "'" + col + "'" in fn


# ── _dhHealthState: explicit states + last_seen-derived buckets ───────────────

class TestHealthStateDerivation:
    def test_recognises_explicit_backend_states(self, console_html):
        fn = _extract_fn(console_html, "_dhHealthState")
        assert "'suspended'" in fn
        assert "'revoked'" in fn
        assert "'errored'" in fn

    def test_never_seen_is_distinct_from_silent(self, console_html):
        fn = _extract_fn(console_html, "_dhHealthState")
        assert "return 'missing'" in fn
        # Falls back to the shared freshness bucket only once last_seen exists.
        assert "_dhFreshnessBucket(d.last_seen)" in fn

    def test_health_state_meta_covers_all_seven_states(self, console_html):
        idx = console_html.index("_DH_HEALTH_STATE_META = {")
        end = console_html.index("};", idx)
        meta = console_html[idx:end]
        for state in ("active", "stale", "silent", "missing", "suspended", "revoked", "errored"):
            assert re.search(r"\b" + state + r":", meta), state


# ── _dhApplyFilters: search + filter semantics ─────────────────────────────────

class TestApplyFilters:
    def test_search_matches_hostname_serial_id_os_and_user(self, console_html):
        fn = _extract_fn(console_html, "_dhApplyFilters")
        for field in ("d.hostname", "d.serial", "d.id", "d.os", "d.os_version",
                      "d.primary_user_display", "d.primary_user_account"):
            assert field in fn

    def test_filters_respect_health_state_and_os_version_selects(self, console_html):
        # PAT-1008: the version filter is now OS-version (d.os_version), via
        # the OS column's combined 'osver:<os>|<version>' select value — not
        # the old (permanently-inert) d.agent_version.
        fn = _extract_fn(console_html, "_dhApplyFilters")
        assert "_dhHealthState(d) !== stateFilter" in fn
        assert "d.os || ''" in fn
        assert "d.os_version || ''" in fn


# ── _dhRender: stat buckets + dual empty states ────────────────────────────────

class TestRenderBucketsAndEmptyStates:
    def test_never_seen_counted_separately_from_silent(self, console_html):
        fn = _extract_fn(console_html, "_dhRender")
        assert "missing" in fn
        assert "Never seen" in fn
        # Distinct counters, not folded together.
        assert re.search(r"missing\+\+|missing\s*\+\+", fn)

    def test_stale_and_silent_stat_cards_still_present(self, console_html):
        fn = _extract_fn(console_html, "_dhRender")
        assert "'Stale ('" in fn
        assert "'Silent ('" in fn

    def test_distinguishes_no_devices_from_no_matches(self, console_html):
        fn = _extract_fn(console_html, "_dhRender")
        assert "No devices enrolled for this tenant." in fn
        assert "No devices match the current search or filters." in fn

    def test_filter_row_hidden_when_tenant_has_zero_devices(self, console_html):
        fn = _extract_fn(console_html, "_dhRender")
        idx = fn.index("total === 0")
        block = fn[idx:idx + 400]
        assert "dh-filter-row" in block


# ── Reset on tenant switch ──────────────────────────────────────────────────────

class TestFilterResetOnTenantSwitch:
    def test_dh_activate_resets_filters_before_fetch(self, console_html):
        fn = _extract_fn(console_html, "_dhActivate")
        assert "_dhResetFilters()" in fn

    def test_reset_filters_clears_search_and_all_selects(self, console_html):
        fn = _extract_fn(console_html, "_dhResetFilters")
        for sel_id in ("dh-filter-state", "dh-filter-os"):
            assert sel_id in fn
        assert "dh-filter-search" in fn


# ── CSV export ───────────────────────────────────────────────────────────────

class TestCsvExport:
    def test_export_uses_filtered_and_sorted_devices(self, console_html):
        fn = _extract_fn(console_html, "_dhExportCSV")
        assert "_dhApplyFilters(_dhDevices)" in fn
        assert "_dhSortDevices(" in fn

    def test_export_includes_health_state_column(self, console_html):
        fn = _extract_fn(console_html, "_dhExportCSV")
        assert "'health_state'" in fn
        assert "_dhHealthState(d)" in fn

    def test_export_produces_a_csv_blob_download(self, console_html):
        fn = _extract_fn(console_html, "_dhExportCSV")
        assert "text/csv" in fn
        assert ".download" in fn
