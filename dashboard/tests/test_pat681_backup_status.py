"""
Tests for PAT-681 — Backup status: device-list Backup column, per-device
tooltip, and the estate-wide "No backup" / "Backup stale" counts on the Home
verdict hero.

Backend note: the backup fields this ticket surfaces (device.backup.bucket,
tenant.backup_status_counts) are already returned end to end by the Go API
(go-service/internal/handlers/admin_overview.go, deviceBackupSummary /
tenantBackupStatusCounts) and passed through unmodified by this dashboard's
existing /admin/tenants/{id}/devices and /admin/tenants/overview proxies
(main.py) — confirmed by reading admin_overview.go directly, not assumed.
This ticket is therefore frontend-only (templates/console.html); no proxy
route needed a change to carry the new fields.

Covers:
  * Backup column header: sort trigger + filter select (fixed 5-value enum,
    unlike the OS select's per-fleet dynamic options).
  * _dhBackupBadgeHtml() / _dhBackupTooltipText() / _dhBackupTypeLabel() /
    _dhBackupRank(): dash for "never reported", correct bucket -> CSS class
    mapping, human-readable tooltip text, and the exact sync-only
    risk-communication framing the ticket mandates verbatim.
  * _dhApplyFilters() / _dhSortDevices() / _dhResetFilters() wire the new
    column into the existing PAT-800/PAT-1008 filter+sort+reset machinery.
  * CSV export carries the new fields.
  * _renderHomeVerdict() sums backup_status_counts across tenants (not
    recomputed from the device list) into "No backup" / "Backup stale" tiles.
  * PAT-951 regression: no traffic-light circle-emoji glyphs reintroduced.

Run with: pytest tests/test_pat681_backup_status.py -v
"""

import os
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
    # Pull a single top-level `function <name>(...) { ... }` body by brace
    # match (same approach as tests/test_pat800.py's _extract_fn).
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


# ── Column header markup ─────────────────────────────────────────────────────

class TestBackupColumnMarkup:
    def test_backup_filter_select_present_with_fixed_options(self, console_html):
        assert 'id="dh-filter-backup"' in console_html
        idx = console_html.index('id="dh-filter-backup"')
        end = console_html.index("</select>", idx)
        select_html = console_html[idx:end]
        for value in ("ok", "stale", "none", "sync_only", "unreported"):
            assert 'value="' + value + '"' in select_html

    def test_backup_column_sortable(self, console_html):
        assert "_dhSortBy('backup')" in console_html
        assert 'id="dh-sort-backup"' in console_html

    def test_backup_th_precedes_user_th(self, console_html):
        # Column order: Device, OS, Backup, User, ... — mirrors the OS column
        # PAT-1008 added, grouped with the other device-attribute columns.
        backup_idx = console_html.index('class="col-backup"')
        user_idx = console_html.index('class="col-user meter-sort-hdr"')
        assert backup_idx < user_idx


# ── _dhSortDevices / _dhApplyFilters / _dhResetFilters wiring ───────────────

class TestBackupSortAndFilterWiring:
    def test_dh_sort_devices_covers_backup(self, console_html):
        fn = _extract_fn(console_html, "_dhSortDevices")
        assert "'backup'" in fn
        assert "_dhBackupRank" in fn

    def test_dh_sort_by_defaults_backup_ascending_worst_first(self, console_html):
        # Matches severity: ascending rank = most-urgent-first.
        fn = _extract_fn(console_html, "_dhSortBy")
        assert "col === 'backup'" in fn

    def test_apply_filters_respects_backup_select(self, console_html):
        fn = _extract_fn(console_html, "_dhApplyFilters")
        assert "dh-filter-backup" in fn
        assert "'unreported'" in fn
        assert "d.backup && d.backup.bucket" in fn

    def test_reset_filters_clears_backup_select(self, console_html):
        fn = _extract_fn(console_html, "_dhResetFilters")
        assert "dh-filter-backup" in fn


# ── _dhBackupBadgeHtml / _dhBackupRank ───────────────────────────────────────

class TestBackupBadge:
    def test_never_reported_renders_a_dash_not_a_fifth_state(self, console_html):
        fn = _extract_fn(console_html, "_dhBackupBadgeHtml")
        assert "if (!b) return" in fn
        assert "&mdash;" in fn

    def test_bucket_meta_covers_all_four_buckets(self, console_html):
        idx = console_html.index("_DH_BACKUP_BUCKET_META = {")
        end = console_html.index("};", idx)
        meta = console_html[idx:end]
        for bucket, cls in (
            ("ok", "dh-fresh-ok"),
            ("stale", "dh-fresh-warn"),
            ("none", "dh-fresh-stale"),
            ("sync_only", "dh-fresh-muted"),
        ):
            assert bucket + ":" in meta
            assert cls in meta

    def test_badge_title_is_escaped(self, console_html):
        fn = _extract_fn(console_html, "_dhBackupBadgeHtml")
        assert "_escHtml(title)" in fn

    def test_backup_rank_orders_worst_first_unreported_last(self, console_html):
        fn = _extract_fn(console_html, "_dhBackupRank")
        # none (worst) must rank lower than ok (best); unreported (default)
        # must rank higher than every real bucket.
        none_pos = fn.index("case 'none':")
        ok_pos = fn.index("case 'ok':")
        default_pos = fn.index("default:")
        assert none_pos < ok_pos < default_pos


# ── _dhBackupTooltipText: human-readable + exact sync-only framing ──────────

class TestBackupTooltip:
    def test_sync_only_carries_exact_risk_framing(self, console_html):
        fn = _extract_fn(console_html, "_dhBackupTooltipText")
        assert "not a backup, no ransomware recovery protection" in fn

    def test_includes_days_ago_and_type(self, console_html):
        fn = _extract_fn(console_html, "_dhBackupTooltipText")
        assert "last_backup_days_ago" in fn
        assert "_dhBackupTypeLabel(b.backup_type)" in fn

    def test_none_bucket_notes_no_backup_configured(self, console_html):
        fn = _extract_fn(console_html, "_dhBackupTooltipText")
        assert "no backup configured" in fn

    def test_notes_field_included_and_untrusted(self, console_html):
        # b.notes is agent-reported; it must flow into the tooltip text (which
        # the caller then escapes), not be dropped.
        fn = _extract_fn(console_html, "_dhBackupTooltipText")
        assert "b.notes" in fn

    def test_absolute_timestamp_rides_alongside_relative_age(self, console_html):
        # Review finding: last_backup_at was on the wire and unused. Both the
        # relative age and the absolute timestamp must appear, not one or the
        # other — _fmtTs is the repo's existing local-timestamp formatter.
        fn = _extract_fn(console_html, "_dhBackupTooltipText")
        assert "b.last_backup_at" in fn
        assert "_fmtTs(b.last_backup_at)" in fn
        # Still present alongside the timestamp, not replaced by it.
        assert "b.last_backup_days_ago" in fn


# ── _dhBackupTypeLabel: known map + safe fallback humanization ──────────────

class TestBackupTypeLabel:
    def test_known_wire_tokens_are_humanized(self, console_html):
        idx = console_html.index("_DH_BACKUP_TYPE_LABELS = {")
        end = console_html.index("};", idx)
        labels = console_html[idx:end]
        assert "time_machine" in labels and "Time Machine" in labels
        assert "file_history" in labels and "File History" in labels
        assert "onedrive_sync" in labels
        assert "icloud_sync" in labels

    def test_lookup_guards_against_proto_pollution_style_keys(self, console_html):
        # backup_type is agent-reported. A plain `map[t]` read for
        # t == "__proto__" returns Object.prototype (truthy, wrong display)
        # rather than undefined — same class of bug PAT-1008's review found
        # for the OS filter map (there, a write; here, a misleading read).
        fn = _extract_fn(console_html, "_dhBackupTypeLabel")
        assert "hasOwnProperty" in fn

    def test_unknown_type_falls_back_to_humanized_snake_case(self, console_html):
        fn = _extract_fn(console_html, "_dhBackupTypeLabel")
        assert "replace(/_/g" in fn


# ── CSV export ───────────────────────────────────────────────────────────────

class TestCsvExportCarriesBackupFields:
    def test_export_headers_include_backup_columns(self, console_html):
        fn = _extract_fn(console_html, "_dhExportCSV")
        for col in ("'backup_bucket'", "'backup_type'", "'last_backup_days_ago'"):
            assert col in fn

    def test_export_unreported_devices_marked_explicitly(self, console_html):
        fn = _extract_fn(console_html, "_dhExportCSV")
        assert "'unreported'" in fn


# ── Home verdict hero: estate-wide backup risk counts ────────────────────────

class TestHomeVerdictBackupStats:
    def test_sums_backup_status_counts_across_tenants_not_recomputed(self, console_html):
        fn = _extract_fn(console_html, "_renderHomeVerdict")
        assert "t.backup_status_counts" in fn
        assert "backupStale" in fn
        assert "backupNone" in fn

    def test_renders_no_backup_and_backup_stale_stat_tiles(self, console_html):
        fn = _extract_fn(console_html, "_renderHomeVerdict")
        assert "'No backup'" in fn
        assert "'Backup stale'" in fn
        # Both new tiles precede the CIS-posture secondary tile (PAT-1006
        # ordering: patch/risk signals lead, CIS posture trails).
        no_backup_pos = fn.index("'No backup'")
        cis_pos = fn.index("'CIS posture'")
        assert no_backup_pos < cis_pos

    def test_derives_unreported_as_device_count_minus_four_buckets(self, console_html):
        # tenantBackupStatusCounts (go-service/internal/handlers/admin_overview.go
        # ~L64-68) has no fifth "unreported" field — confirmed by reading the Go
        # struct, not assumed. Must be derived client-side from device_count.
        fn = _extract_fn(console_html, "_renderHomeVerdict")
        assert "backupUnreported" in fn
        assert "bc.ok || 0" in fn or "(bc.ok || 0)" in fn
        assert "dc - reported" in fn

    def test_significant_unreported_coverage_is_not_rendered_green(self, console_html):
        # Review finding: a tenant whose devices have never reported backup
        # status contributes 0 to both counters, and 0 rendered green reads as
        # "checked, confirmed fine" — indistinguishable from a genuinely
        # healthy estate. Same fail-open-looks-healthy shape as
        # PAT-837/912/960/1010 elsewhere this session.
        fn = _extract_fn(console_html, "_renderHomeVerdict")
        assert "backupCoverageThin" in fn
        assert "0.10" in fn  # the 10%-of-estate threshold, explained inline
        assert "backupNoneCol" in fn and "backupStaleCol" in fn
        # Both colour variables must fall back to muted (not green) when thin,
        # and to red/orange (not muted) whenever the count is actually > 0.
        none_col_line = [l for l in fn.splitlines() if "backupNoneCol =" in l][0]
        assert "var(--red)" in none_col_line
        assert "var(--muted)" in none_col_line
        assert "var(--green)" in none_col_line
        stale_col_line = [l for l in fn.splitlines() if "backupStaleCol =" in l][0]
        assert "var(--orange)" in stale_col_line
        assert "var(--muted)" in stale_col_line
        assert "var(--green)" in stale_col_line

    def test_thin_coverage_note_states_the_actual_unreported_count(self, console_html):
        fn = _extract_fn(console_html, "_renderHomeVerdict")
        assert "backupCoverageNote" in fn
        assert "have never reported backup status" in fn
        # The note (not a silent colour swap) is what carries the caveat —
        # wired into both tiles' title, same tooltip mechanism as the
        # existing patch-counter coverageNote.
        assert "stat(backupNone, 'No backup', backupNoneCol, {title: backupCoverageNote})" in fn
        assert "stat(backupStale, 'Backup stale', backupStaleCol, {title: backupCoverageNote})" in fn

    def test_sync_only_summed_and_rendered_as_its_own_tile(self, console_html):
        # Review round 3: sync_only was missing from the fleet-level rollup
        # entirely — an estate that's 100% OneDrive/iCloud sync (zero true
        # backups anywhere) previously showed "No backup: 0" in green, since
        # sync_only devices are never counted in the "none" bucket
        # (report.BackupBucket checks sync_only first). Must be summed and
        # given its own tile, not folded into "No backup".
        fn = _extract_fn(console_html, "_renderHomeVerdict")
        assert "backupSyncOnly" in fn
        assert "bc.sync_only || 0" in fn
        assert "'Sync only'" in fn
        assert "stat(backupSyncOnly, 'Sync only'" in fn

    def test_sync_only_tile_carries_the_risk_framing(self, console_html):
        # Same substantive point as the device-badge tooltip
        # (_dhBackupTooltipText's "not a backup, no ransomware recovery
        # protection"), in a compact form appropriate for a tile tooltip.
        fn = _extract_fn(console_html, "_renderHomeVerdict")
        assert "backupSyncOnlyNote" in fn
        assert "is not a backup" in fn
        assert "no ransomware recovery protection" in fn
        assert "stat(backupSyncOnly, 'Sync only', backupSyncOnlyCol, {title: backupSyncOnlyNote})" in fn

    def test_sync_only_tile_also_respects_thin_coverage_caveat(self, console_html):
        # A 0 sync-only count under thin coverage is just as unreliable as a
        # 0 in the other two tiles — most of the estate may simply not have
        # reported yet, so the same caveat must fold in here.
        fn = _extract_fn(console_html, "_renderHomeVerdict")
        note_line_idx = fn.index("var backupSyncOnlyNote")
        note_block = fn[note_line_idx:fn.index(";", note_line_idx)]
        assert "backupCoverageThin" in note_block
        assert "backupCoverageNote" in note_block
        col_line = [l for l in fn.splitlines() if "backupSyncOnlyCol =" in l][0]
        assert "var(--orange)" in col_line
        assert "var(--muted)" in col_line
        assert "var(--green)" in col_line

    def test_sync_only_tile_precedes_cis_posture(self, console_html):
        fn = _extract_fn(console_html, "_renderHomeVerdict")
        sync_only_pos = fn.index("'Sync only'")
        cis_pos = fn.index("'CIS posture'")
        assert sync_only_pos < cis_pos


# ── PAT-951 regression: no traffic-light emoji glyphs reintroduced ──────────

class TestNoTrafficLightEmojiReintroduced:
    def test_backup_badge_meta_carries_no_circle_emoji_entities(self, console_html):
        idx = console_html.index("_DH_BACKUP_BUCKET_META = {")
        end = console_html.index("};", idx)
        meta = console_html[idx:end]
        for forbidden in ("&#128994;", "&#128993;", "&#128308;", "\U0001F7E2", "\U0001F7E1", "\U0001F534"):
            assert forbidden not in meta
