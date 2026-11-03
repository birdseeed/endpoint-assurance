"""PAT-701: stale-device view, CSV export and CVE links.

Stale maths are unit-tested with a pinned clock (boundary at exactly N days);
the view and CSV export are exercised end-to-end against the stubbed platform,
whose roster carries one device 10 days silent.
"""

import csv
import io
from datetime import UTC, datetime, timedelta

import main
from tests.conftest import STALE_DEVICE_DAYS, STUB_STATE

NOW = datetime(2026, 7, 3, 12, 0, 0, tzinfo=UTC)


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Stale maths: boundary at exactly N days ───────────────────────────────
def test_exactly_n_days_is_stale():
    assert main.days_since(_iso(NOW - timedelta(days=7)), NOW) == 7
    roster = [{"last_seen": _iso(NOW - timedelta(days=7))}]
    assert main.annotate_staleness(roster, 7, NOW) == 1
    assert roster[0]["is_stale"] is True and roster[0]["days_stale"] == 7


def test_just_under_n_days_is_not_stale():
    last_seen = _iso(NOW - timedelta(days=7) + timedelta(seconds=1))
    assert main.days_since(last_seen, NOW) == 6
    roster = [{"last_seen": last_seen}]
    assert main.annotate_staleness(roster, 7, NOW) == 0
    assert roster[0]["is_stale"] is False


def test_never_reported_counts_as_stale():
    roster = [{"last_seen": None}, {"last_seen": "not-a-date"}, {}]
    assert main.annotate_staleness(roster, 7, NOW) == 3
    assert all(d["days_stale"] is None and d["is_stale"] for d in roster)


def test_threshold_normalised_to_offered_choices():
    assert main.normalise_stale_days("14") == 14
    assert main.normalise_stale_days("30") == 30
    for bad in ("", "0", "-3", "9", "banana", None):
        assert main.normalise_stale_days(bad) == 7


# ── Stale view on /devices ────────────────────────────────────────────────
def test_stale_view_shows_only_stale_devices(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices?view=stale&stale_days=7")
    assert resp.status_code == 200
    assert "acme-mbp-storeroom" in resp.text
    assert "acme-mbp-frontdesk" not in resp.text
    assert "acme-win-accounts" not in resp.text
    # PAT-1843 keeps Last seen to one relative value; stale qualification is
    # carried by the page heading and the evidence badges, not a third label.
    assert "days ago</span>" in resp.text
    assert "Encryption evidence stale" in resp.text
    assert ">Stale</span>" not in resp.text


def test_default_view_is_one_server_bucketed_roster(client, make_token):
    """PAT-1843: all reporting groups share one rendered table. The default
    client view is normal (PAT-1957, was silent), and retaining all
    server-classified rows in the response is what allows same-page switching
    without another API call."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices")
    assert resp.status_code == 200
    for hostname in ("acme-mbp-frontdesk", "acme-win-accounts", "acme-mbp-storeroom"):
        assert hostname in resp.text
    assert resp.text.count('<table class="data-table device-table table-stack"') == 1
    assert 'data-row-filter="view" data-query-param="view" data-initial="normal"' in resp.text
    assert 'href="/devices.csv"' in resp.text


def test_stale_view_respects_higher_threshold(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    assert STALE_DEVICE_DAYS < 14
    resp = _get(client, token, "/devices?view=stale&stale_days=14")
    assert resp.status_code == 200
    assert "acme-mbp-storeroom" not in resp.text
    # PAT-2135: this legacy stale-threshold browse mode is independent of
    # the silent/quiet/normal grouping's retired-device carve-out -
    # conftest.DEVICES' retired-40-days-silent fixture still qualifies as
    # stale here, so the page is not empty at this threshold.
    assert "acme-mbp-retired" in resp.text
    assert "No stale devices" not in resp.text


# ── CSV export ────────────────────────────────────────────────────────────
def test_csv_full_roster(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert resp.headers["content-disposition"] == (
        'attachment; filename="patched-devices.csv"'
    )
    rows = list(csv.reader(io.StringIO(resp.text)))
    assert rows[0] == list(main.CSV_COLUMNS)
    # header + 6 devices (PAT-2135 added two retired ones, PAT-2324 a server)
    assert len(rows) == 7
    by_host = {r[0]: r for r in rows[1:]}
    assert set(by_host) == {
        "acme-mbp-frontdesk", "acme-win-accounts", "acme-mbp-storeroom",
        "acme-mbp-retired", "acme-mbp-zombie", "acme-win-dc1",
    }
    stale_row = by_host["acme-mbp-storeroom"]
    assert stale_row[1:3] == ["macOS", "14.7"]
    assert stale_row[4] == str(STALE_DEVICE_DAYS)  # days_stale
    # PAT-1864: a historical pass/fail is not current assurance evidence in
    # an export. Both fields retain the explicit stale qualification.
    assert stale_row[5] == "74" and stale_row[6] == "stale" and stale_row[7] == "stale"
    assert by_host["acme-win-accounts"][6] == "no"  # encryption_ok
    # PAT-2256: the platform returns null for every Windows device's update
    # state, and the export says so rather than guessing.
    assert by_host["acme-win-accounts"][7] == "unknown"  # patch_pending
    # PAT-1597: cis_score is rounded, never the raw float the platform sends.
    assert by_host["acme-win-accounts"][5] == "31"


def test_csv_stale_only(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices.csv?stale_days=7")
    assert resp.status_code == 200
    assert resp.headers["content-disposition"] == (
        'attachment; filename="patched-devices-stale-7d.csv"'
    )
    rows = list(csv.reader(io.StringIO(resp.text)))
    assert rows[0] == list(main.CSV_COLUMNS)
    # PAT-2135: acme-mbp-retired (40 days silent) also clears the 7-day
    # threshold here - this CSV export is unaffected by the retired-device
    # carve-out that applies to /devices' own silent/quiet/normal grouping.
    assert len(rows) == 3
    assert {r[0] for r in rows[1:]} == {"acme-mbp-storeroom", "acme-mbp-retired"}


def test_csv_requires_auth(client, make_token):
    assert client.get("/devices.csv").status_code == 401
    resp = _get(client, make_token(exp_delta=-120), "/devices.csv?stale_days=7")
    assert resp.status_code == 401


# ── CVE links (scope addition folded into PAT-701) ────────────────────────
def test_findings_cve_ids_link_to_nvd(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    # PAT-2092: class="cve-id" added so the findings table's own nowrap CVE
    # id rule (.data-table td a.cve-id) applies here too - previously this
    # link had no class at all, so the blanket .data-table td
    # {overflow-wrap: anywhere} could break it mid-word ("CVE-2026-/0001").
    assert (
        '<a class="cve-id" href="https://nvd.nist.gov/vuln/detail/CVE-2026-1234" '
        'target="_blank" rel="noopener noreferrer">CVE-2026-1234</a>'
    ) in resp.text


def test_device_detail_cve_ids_link_to_nvd(client, make_token):
    # PAT-2164: Applications with open findings moved to the Vulnerabilities tab.
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices/dev-mac-001/vulnerabilities")
    assert resp.status_code == 200
    assert 'href="https://nvd.nist.gov/vuln/detail/CVE-2026-5678"' in resp.text
    assert 'rel="noopener noreferrer"' in resp.text
