"""PAT-2454: the Overview's top CVE action counts what it says it counts.

Live defect: "Review 242 CVEs in Mozilla Firefox (x64 en-US)" while that
product had 266 critical or high CVEs (and the device page showed 340 across
every severity). Four causes, all in main.py:

1. overview() read only the first OVERVIEW_CVE_ROWS_LIMIT rows of
   GET /v1/portal/findings, so a large estate's critical and high rows were
   cut off part way through.
2. The guard that was meant to catch that truncation compared rows with
   cve_attention's total, which counts distinct CVE ids. Different units, so
   a truncated read passed.
3. group_cve_fixes counted rows, so a product present in two versions
   counted each shared CVE twice.
4. The text did not say it counted critical and high only.

Every integration case runs through GET / against the stub platform, whose
/v1/portal/findings serves real pages (limit, offset, total), so the answer
is only right when the portal pages through the rows.
"""

import pytest

import main
from tests.conftest import OVERVIEW, STUB_STATE

SEVERITY_CVSS = {"critical": 9.8, "high": 8.1, "medium": 5.5, "low": 2.1}


def _get(client, token, path="/"):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _row(cve_id, app, version, severity, fixed="", devices=1):
    return {
        "cve_id": cve_id, "severity": severity, "cvss": SEVERITY_CVSS[severity],
        "app": app, "version": version, "devices_affected": devices,
        "first_seen": "2026-09-01T08:00:00Z", "summary": "A test finding.",
        "match_confidence": "version_confirmed", "fixed_version": fixed,
    }


def _section(body, start, end):
    return body.split(start, 1)[1].split(end, 1)[0]


def _top_actions(body):
    return _section(body, "Top 3 actions", "Your estate at a glance")


def _seed(monkeypatch, rows, critical, high):
    monkeypatch.setitem(STUB_STATE, "overview_data", {
        **OVERVIEW,
        "cve_attention": {"available": True, "critical": critical, "high": high},
    })
    monkeypatch.setitem(STUB_STATE, "findings_data", rows)


def _watch_findings(monkeypatch, fail_from_offset=None):
    """Wrap upstream.get_json: record every /v1/portal/findings request and,
    when asked, fail the ones at or past an offset."""
    real = main.upstream.get_json
    calls = []

    def wrapper(path, jwt_token, params=None):
        if path == "/v1/portal/findings":
            calls.append(dict(params or {}))
            if fail_from_offset is not None and (params or {}).get("offset", 0) >= fail_from_offset:
                raise main.upstream.UpstreamError("error", "boom")
        return real(path, jwt_token, params=params)

    monkeypatch.setattr(main.upstream, "get_json", wrapper)
    return calls


def _large_estate_rows():
    """820 rows, 800 of them critical or high, so one page of 500 cuts the
    list off inside Alpha Browser.

    Beta Suite: 130 distinct critical CVEs on two versions, 260 rows, first
    in the platform's order (highest severity first).
    Alpha Browser: 180 distinct high CVEs on three versions with three
    different fixed versions, 540 rows. This is the right answer.
    Gamma Tool: 20 medium rows that end the critical and high rows.

    On the first 500 rows alone Beta Suite has 130 distinct CVEs and Alpha
    Browser 80, so a truncated read names the wrong product; on all rows
    Alpha Browser has 180 and Beta Suite 130.
    """
    rows = []
    for i in range(130):
        for version in ("1.0", "1.1"):
            rows.append(_row(f"CVE-2026-{1000 + i}", "Beta Suite", version, "critical", "9.9"))
    for i in range(180):
        for version, fixed in (("10.0", "10.9"), ("11.0", "11.9"), ("12.0", "12.9")):
            rows.append(_row(f"CVE-2026-{2000 + i}", "Alpha Browser", version, "high", fixed))
    for i in range(20):
        rows.append(_row(f"CVE-2026-{3000 + i}", "Gamma Tool", "1.0", "medium", "1.1"))
    return rows


# ── 1. Truncation: the right answer is only reachable by paging ────────────

def test_top_cve_action_pages_through_every_critical_and_high_row(
    client, make_token, monkeypatch,
):
    _seed(monkeypatch, _large_estate_rows(), critical=130, high=180)
    calls = _watch_findings(monkeypatch)
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert response.status_code == 200
    actions = _top_actions(response.text)
    assert "Review 180 critical or high CVEs in Alpha Browser" in actions
    assert "Beta Suite" not in actions
    assert [c["offset"] for c in calls] == [0, 500]
    assert all(c["limit"] == 500 for c in calls)


# ── 2. The ticket's acceptance case ────────────────────────────────────────

def test_top_cve_action_reads_a_high_row_without_cvss_after_a_medium_page(
    client, make_token, monkeypatch,
):
    # The platform orders by CVSS DESC NULLS LAST, not by severity. A high
    # finding with no numeric score follows a whole page of medium findings.
    rows = [_row(f"CVE-2026-{8000 + i}", "Medium App", "1.0", "medium")
            for i in range(500)]
    late_high = _row("CVE-2026-9999", "Late High App", "1.0", "high")
    late_high["cvss"] = None
    rows.append(late_high)
    _seed(monkeypatch, rows, critical=0, high=1)
    calls = _watch_findings(monkeypatch)
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert response.status_code == 200
    assert "Review 1 critical or high CVE in Late High App" in _top_actions(response.text)
    assert [c["offset"] for c in calls] == [0, 500]


def test_one_product_across_two_fixed_versions_counts_its_distinct_cves(
    client, make_token, monkeypatch,
):
    firefox = "Mozilla Firefox (x64 en-US)"
    rows = []
    for i in range(12):  # shared by both versions
        severity = "critical" if i < 4 else "high"
        rows.append(_row(f"CVE-2026-{4000 + i}", firefox, "140.0.1", severity, "141.0", 5))
        rows.append(_row(f"CVE-2026-{4000 + i}", firefox, "139.0.2", severity, "140.0", 3))
    for i in range(5):  # only on the newer version
        rows.append(_row(f"CVE-2026-{4100 + i}", firefox, "140.0.1", "high", "141.0", 5))
    for i in range(3):  # only on the older version
        rows.append(_row(f"CVE-2026-{4200 + i}", firefox, "139.0.2", "high", "140.0", 3))
    for i in range(7):  # lower severities are not part of the count
        rows.append(_row(f"CVE-2026-{4300 + i}", firefox, "140.0.1", "medium", "141.0", 5))
    for i in range(6):
        rows.append(_row(f"CVE-2026-{4400 + i}", "7-Zip", "23.1", "high", "24.0", 2))
    # Distinct critical or high CVEs: Firefox 20 (12 + 5 + 3), 7-Zip 6.
    _seed(monkeypatch, rows, critical=4, high=22)
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    actions = _top_actions(response.text)
    assert "Review 20 critical or high CVEs in Mozilla Firefox (x64 en-US)" in actions
    assert "to fix" not in actions
    # Not the 32 rows, and not the 27 that includes the medium ones.
    assert "Review 32" not in actions
    assert "Review 27" not in actions


# ── 3. Units: distinct CVE ids, not rows ───────────────────────────────────

def test_the_same_cves_on_many_versions_count_once_each(client, make_token, monkeypatch):
    rows = [
        _row(f"CVE-2026-{5000 + i}", "Zip Tool", f"1.{v}", "high", "2.0", devices=5 - v % 3)
        for i in range(4) for v in range(10)
    ]
    assert len(rows) == 40
    _seed(monkeypatch, rows, critical=0, high=4)
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    actions = _top_actions(response.text)
    assert "Update Zip Tool to 2.0 on at least 5 devices to fix 4 critical or high CVEs" in actions
    assert "40" not in actions


# ── 4. An incomplete read never names a product ────────────────────────────

def test_a_failed_later_page_falls_back_to_the_unnamed_action(
    client, make_token, monkeypatch,
):
    _seed(monkeypatch, _large_estate_rows(), critical=130, high=180)
    calls = _watch_findings(monkeypatch, fail_from_offset=500)
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert response.status_code == 200
    actions = _top_actions(response.text)
    assert "Review 310 critical or high CVEs" in actions
    assert "Alpha Browser" not in actions
    assert "Beta Suite" not in actions
    assert [c["offset"] for c in calls] == [0, 500]


def test_hitting_the_page_cap_falls_back_to_the_unnamed_action(
    client, make_token, monkeypatch,
):
    _seed(monkeypatch, _large_estate_rows(), critical=130, high=180)
    monkeypatch.setattr(main, "OVERVIEW_CVE_MAX_PAGES", 1)
    calls = _watch_findings(monkeypatch)
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert response.status_code == 200
    actions = _top_actions(response.text)
    assert "Review 310 critical or high CVEs" in actions
    assert "Alpha Browser" not in actions
    assert "Beta Suite" not in actions
    assert [c["offset"] for c in calls] == [0]


# ── 5. A medium page does not prove later rows are below high ───────────────

def test_reads_the_rest_even_when_the_first_page_ends_below_high(
    client, make_token, monkeypatch,
):
    rows = [_row(f"CVE-2026-{6000 + i}", "Delta App", "1.0", "high", "1.1") for i in range(10)]
    rows += [_row(f"CVE-2026-{7000 + i}", "Epsilon App", "1.0", "medium", "1.1")
             for i in range(590)]
    assert len(rows) == 600  # a second page exists, but nothing on it is high
    _seed(monkeypatch, rows, critical=0, high=10)
    calls = _watch_findings(monkeypatch)
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert response.status_code == 200
    assert "Update Delta App to 1.1 on at least 1 device to fix 10 critical or high CVEs" in (
        _top_actions(response.text)
    )
    assert [c["offset"] for c in calls] == [0, 500]


# ── 6a. The paging helper ──────────────────────────────────────────────────

def _page(rows, total, offset=0):
    return {"total": total, "limit": 500, "offset": offset, "findings": rows}


def _rows(n, severity, prefix="CVE-2026-9", app="App"):
    return [_row(f"{prefix}{i:05d}", app, "1.0", severity) for i in range(n)]


def _serve(monkeypatch, pages_by_offset):
    """Replace upstream.get_json with a scripted platform; returns the log of
    (path, params) requests."""
    calls = []

    def fake(path, jwt_token, params=None):
        calls.append((path, jwt_token, dict(params or {})))
        result = pages_by_offset(params["offset"]) if callable(pages_by_offset) \
            else pages_by_offset[params["offset"]]
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(main.upstream, "get_json", fake)
    return calls


def test_helper_a_page_that_reaches_the_end_is_complete_with_no_further_request(monkeypatch):
    calls = _serve(monkeypatch, {})
    first = _page(_rows(3, "critical"), total=3)
    rows, complete = main._read_critical_high_findings("tok", first)
    assert complete is True
    assert rows == first["findings"]
    assert calls == []


def test_helper_reads_past_a_page_that_ends_below_high(monkeypatch):
    later = _rows(400, "high", prefix="CVE-2026-7")
    calls = _serve(monkeypatch, {500: _page(later, total=900, offset=500)})
    rows_in = _rows(499, "high") + _rows(1, "medium", prefix="CVE-2026-8")
    rows, complete = main._read_critical_high_findings("tok", _page(rows_in, total=900))
    assert complete is True
    assert rows == rows_in + later
    assert len(calls) == 1


def test_helper_a_low_row_does_not_end_the_read(monkeypatch):
    calls = _serve(monkeypatch, {11: main.upstream.UpstreamError("timeout", "slow")})
    rows_in = _rows(10, "critical") + _rows(1, "low", prefix="CVE-2026-8")
    _, complete = main._read_critical_high_findings("tok", _page(rows_in, total=900))
    assert complete is False
    assert calls == [("/v1/portal/findings", "tok", {"limit": 500, "offset": 11})]


def test_helper_pages_with_a_cumulative_offset_and_joins_the_rows(monkeypatch):
    page1 = _rows(500, "high", prefix="CVE-2026-1")
    page2 = _rows(150, "high", prefix="CVE-2026-2") + _rows(50, "medium", prefix="CVE-2026-3")
    calls = _serve(monkeypatch, {500: _page(page2, total=700, offset=500)})

    rows, complete = main._read_critical_high_findings("tok", _page(page1, total=700))

    assert complete is True
    assert rows == page1 + page2
    assert calls == [("/v1/portal/findings", "tok", {"limit": 500, "offset": 500})]


def test_helper_a_second_page_that_reaches_the_end_on_a_high_row_is_complete(monkeypatch):
    page1 = _rows(500, "critical", prefix="CVE-2026-1")
    page2 = _rows(100, "high", prefix="CVE-2026-2")
    calls = _serve(monkeypatch, {500: _page(page2, total=600, offset=500)})
    rows, complete = main._read_critical_high_findings("tok", _page(page1, total=600))
    assert complete is True
    assert len(rows) == 600
    assert len(calls) == 1


def test_helper_a_failed_later_page_is_incomplete(monkeypatch):
    page1 = _rows(500, "high")
    _serve(monkeypatch, {500: main.upstream.UpstreamError("timeout", "slow")})
    _, complete = main._read_critical_high_findings("tok", _page(page1, total=900))
    assert complete is False


@pytest.mark.parametrize("severity", ["critical", "medium", "low"])
def test_helper_hitting_the_page_cap_is_incomplete(monkeypatch, severity):
    assert main.OVERVIEW_CVE_MAX_PAGES == 10
    calls = _serve(
        monkeypatch,
        lambda offset: _page(_rows(500, severity, prefix=f"CVE-2026-{offset}"),
                             total=100000, offset=offset),
    )
    rows, complete = main._read_critical_high_findings(
        "tok", _page(_rows(500, severity, prefix="CVE-2026-0"), total=100000),
    )
    assert complete is False
    # Ten pages in all: the one handed in plus nine more.
    assert [c[2]["offset"] for c in calls] == [500 * n for n in range(1, 10)]
    assert len(rows) == 5000


def test_helper_the_last_page_the_cap_allows_can_still_finish_the_read(monkeypatch):
    def pages(offset):
        last = offset == 4500
        rows = (_rows(499, "high", prefix=f"CVE-2026-{offset}")
                + (_rows(1, "medium", prefix="CVE-2026-m") if last
                   else _rows(1, "high", prefix="CVE-2026-h")))
        return _page(rows, total=5000, offset=offset)

    calls = _serve(monkeypatch, pages)
    _, complete = main._read_critical_high_findings(
        "tok", _page(_rows(500, "high", prefix="CVE-2026-0"), total=5000),
    )
    assert complete is True
    assert len(calls) == 9


@pytest.mark.parametrize("first_page", [
    None,
    [],
    "findings",
    {"findings": []},
    {"total": "3", "findings": []},
    {"total": True, "findings": []},
    {"total": 3.0, "findings": []},
    {"total": 3},
    {"total": 3, "findings": None},
    {"total": 3, "findings": {"a": 1}},
])
def test_helper_a_malformed_first_page_is_incomplete(monkeypatch, first_page):
    calls = _serve(monkeypatch, {})
    _, complete = main._read_critical_high_findings("tok", first_page)
    assert complete is False
    assert calls == []


@pytest.mark.parametrize("second_page", [
    [],
    "findings",
    {"findings": _rows(1, "high")},
    {"total": "900", "findings": _rows(1, "high")},
    {"total": 900, "findings": "nope"},
    {"total": 900},
])
def test_helper_a_malformed_later_page_is_incomplete(monkeypatch, second_page):
    _serve(monkeypatch, {500: second_page})
    _, complete = main._read_critical_high_findings("tok", _page(_rows(500, "high"), total=900))
    assert complete is False


def test_helper_an_empty_later_page_with_rows_still_owed_is_incomplete(monkeypatch):
    calls = _serve(monkeypatch, {500: _page([], total=900, offset=500)})
    _, complete = main._read_critical_high_findings("tok", _page(_rows(500, "high"), total=900))
    assert complete is False
    assert len(calls) == 1  # no loop


def test_helper_an_empty_first_page_is_complete_only_when_the_total_is_zero(monkeypatch):
    _serve(monkeypatch, {})
    assert main._read_critical_high_findings("tok", _page([], total=0)) == ([], True)
    _, complete = main._read_critical_high_findings("tok", _page([], total=3))
    assert complete is False


@pytest.mark.parametrize("last_row", [
    {"cve_id": "CVE-2026-1", "app": "App"},
    {"cve_id": "CVE-2026-1", "app": "App", "severity": "unknown"},
    {"cve_id": "CVE-2026-1", "app": "App", "severity": None},
    "not a row",
])
def test_helper_a_last_row_with_no_known_severity_does_not_end_the_read(monkeypatch, last_row):
    # Every owed page is read regardless of its final row's severity.
    calls = _serve(monkeypatch, {500: _page(_rows(5, "medium"), total=505, offset=500)})
    rows_in = _rows(499, "high") + [last_row]
    _, complete = main._read_critical_high_findings("tok", _page(rows_in, total=505))
    assert complete is True
    assert len(calls) == 1


def test_helper_a_last_row_with_no_known_severity_and_a_failed_owed_page_is_incomplete(
    monkeypatch,
):
    _serve(monkeypatch, {500: main.upstream.UpstreamError("error", "boom")})
    rows_in = _rows(499, "high") + [{"cve_id": "CVE-2026-1", "app": "App"}]
    _, complete = main._read_critical_high_findings("tok", _page(rows_in, total=505))
    assert complete is False


def test_helper_a_last_row_with_no_known_severity_and_nothing_owed_is_complete(monkeypatch):
    calls = _serve(monkeypatch, {})
    rows_in = _rows(2, "high") + [{"cve_id": "CVE-2026-1", "app": "App"}]
    _, complete = main._read_critical_high_findings("tok", _page(rows_in, total=3))
    assert complete is True
    assert calls == []


# ── 6b. group_cve_fixes counts distinct CVE ids ────────────────────────────

def _g(cve_id, app, fixed="1.0", devices=1):
    return {"cve_id": cve_id, "app": app, "fixed_version": fixed, "devices_affected": devices}


def test_group_counts_a_cve_once_however_many_versions_carry_it():
    rows = [_g("CVE-1", "Foo"), _g("CVE-1", "Foo"), _g("CVE-2", "Foo"), _g("CVE-2", "Foo")]
    assert main.group_cve_fixes(rows)["cve_count"] == 2


def test_group_rows_without_a_usable_cve_id_each_count_once():
    rows = [
        _g("CVE-1", "Foo"), _g("CVE-1", "Foo"),
        {"app": "Foo", "fixed_version": "1.0", "devices_affected": 1},
        {"app": "Foo", "fixed_version": "1.0", "devices_affected": 1, "cve_id": None},
        {"app": "Foo", "fixed_version": "1.0", "devices_affected": 1, "cve_id": 7},
        {"app": "Foo", "fixed_version": "1.0", "devices_affected": 1, "cve_id": ""},
        {"app": "Foo", "fixed_version": "1.0", "devices_affected": 1, "cve_id": "  "},
    ]
    assert main.group_cve_fixes(rows)["cve_count"] == 1 + 5


def test_group_ranks_by_distinct_cves_not_rows():
    rows = (
        [_g("CVE-1", "Many Rows")] * 5
        + [_g("CVE-2", "Two Cves"), _g("CVE-3", "Two Cves")]
    )
    group = main.group_cve_fixes(rows)
    assert group["app"] == "Two Cves"
    assert group["cve_count"] == 2


def test_group_distinct_ties_still_break_on_product_name_and_keep_the_device_floor():
    rows = [
        _g("CVE-1", "Zeta", devices=2), _g("CVE-1", "Zeta", devices=9),
        _g("CVE-2", "Alpha", devices=1), _g("CVE-2", "Alpha", devices=1),
    ]
    group = main.group_cve_fixes(rows)
    assert group["app"] == "Alpha"
    assert group["cve_count"] == 1
    zeta = main.group_cve_fixes([r for r in rows if r["app"] == "Zeta"])
    assert zeta["devices"] == 9  # the largest single value, as before


# ── 6c. _cve_action_source trusts a read only when it is complete ──────────

def test_action_source_does_not_group_an_incomplete_read_even_with_plenty_of_rows():
    rows = [_row(f"CVE-2026-{i}", "Foo", "1.0", "high", "1.1") for i in range(500)]
    src = main._cve_action_source({"available": True, "critical": 0, "high": 3}, True, False, rows)
    assert src["candidate"] == {
        "kind": "review", "app": None, "fixed_version": None, "devices": None, "cve_count": 3,
    }


def test_action_source_does_not_compare_rows_with_distinct_totals():
    # Two distinct CVEs on one product, but cve_attention counts 40: the two
    # figures are in different units, so a complete read is trusted as read.
    rows = [_row("CVE-2026-1", "Foo", "1.0", "high", "1.1"),
            _row("CVE-2026-2", "Foo", "1.0", "critical", "1.1")]
    src = main._cve_action_source({"available": True, "critical": 10, "high": 30}, True, True, rows)
    assert src["candidate"]["app"] == "Foo"
    assert src["candidate"]["cve_count"] == 2
