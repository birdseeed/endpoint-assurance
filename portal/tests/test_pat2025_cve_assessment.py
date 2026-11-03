"""PAT-2025: portal shows CVE assessment state (no known CVEs, pending, not
yet assessed) and when it was last checked.

Consumes the additive `cve_assessment` fields PAT-2024 puts on
GET /v1/portal/devices, GET /v1/portal/devices/{id} and GET /v1/portal/findings
(contracts/portal-api.md "CVE assessment state (PAT-2024)"). The platform half
is not merged yet at the time this ticket is implemented, so every scenario
here also proves the graceful-degradation path: a response entirely lacking
the field (older platform) must render the same honest "not yet assessed"
reading as an explicit not_assessed state, never "No known CVEs", never a
crash (root AGENTS.md: absence requires authority, CVE claims require
evidence).
"""

import csv
import io

import requests

import main
import upstream
from tests.conftest import (
    CVE_ASSESSMENT_TENANT,
    DEVICE_DETAIL,
    DEVICE_DETAIL_ALL_NOT_ASSESSED,
    DEVICES,
    STUB_STATE,
)


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


# ── Device detail: all four states on one page ────────────────────────────
def test_device_detail_renders_all_four_cve_assessment_states(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices/dev-mac-001/vulnerabilities")

    assert response.status_code == 200
    text = response.text
    # ExampleBrowser: assessed, 2 matches, severity joined from
    # apps_with_findings (max_severity "high") rather than a generic pill.
    assert "2 CVEs (High)" in text
    # CleanApp: assessed, zero matches - a genuine clean read.
    assert "No known CVEs" in text
    # QueuedApp: mapped, not matched yet.
    assert "Checking" in text
    # In-House Tool: no mapping at all - distinct from clean, with its
    # one-line explanation shown.
    assert "Not yet assessed" in text
    # Jinja autoescapes the apostrophe in this copy to &#39; in rendered HTML.
    assert (
        "Patched has not yet identified this product&#39;s vulnerability source"
        in text
    )
    # Device-level summary: assessed (sum of finding_count over assessed
    # products), last matched, and the three product counts.
    assert "2 CVEs" in text
    assert "2 / 1 / 1" in text


def test_device_detail_all_not_assessed_never_reads_as_clean(client, make_token, monkeypatch):
    monkeypatch.setitem(STUB_STATE, "device_detail_data", DEVICE_DETAIL_ALL_NOT_ASSESSED)
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices/dev-mac-001/vulnerabilities")

    assert response.status_code == 200
    text = response.text
    assert text.count("Not yet assessed") >= 3  # device summary + 2 products
    assert "No known CVEs" not in text


def test_device_detail_missing_cve_assessment_field_degrades_honestly(
    client, make_token, monkeypatch
):
    # Simulates a platform deployment that predates PAT-2024: the whole key
    # is absent from the response, not merely zero-valued.
    older_platform_device = {
        k: v for k, v in DEVICE_DETAIL.items() if k != "cve_assessment"
    }
    assert "cve_assessment" not in older_platform_device
    monkeypatch.setitem(STUB_STATE, "device_detail_data", older_platform_device)
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices/dev-mac-001/vulnerabilities")

    assert response.status_code == 200
    text = response.text
    assert "Not yet assessed" in text
    assert "No CVE assessment data is available for this device yet." in text
    assert "No known CVEs" not in text


# ── Devices roster / CSV ───────────────────────────────────────────────────
def test_devices_csv_gains_an_assessment_state_column(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices.csv")

    assert response.status_code == 200
    rows = list(csv.reader(io.StringIO(response.text)))
    header = rows[0]
    # PAT-2324 added a trailing `type` column after it, so read it by name.
    assert header[-2:] == ["cve_assessment_state", "type"]
    state = header.index("cve_assessment_state")
    by_hostname = {row[0]: row for row in rows[1:]}
    assert by_hostname["acme-mbp-frontdesk"][state] == "assessed"
    assert by_hostname["acme-win-accounts"][state] == "pending"
    # Every product on this device is unmapped - never counted as clean.
    assert by_hostname["acme-mbp-storeroom"][state] == "not_assessed"


def test_devices_csv_missing_cve_assessment_degrades_to_not_assessed(
    client, make_token, monkeypatch
):
    older_platform_devices = {
        "devices": [
            {k: v for k, v in d.items() if k != "cve_assessment"}
            for d in DEVICES["devices"]
        ]
    }
    assert all("cve_assessment" not in d for d in older_platform_devices["devices"])
    monkeypatch.setitem(STUB_STATE, "devices_data", older_platform_devices)
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices.csv")

    assert response.status_code == 200
    rows = list(csv.reader(io.StringIO(response.text)))
    state = rows[0].index("cve_assessment_state")
    for row in rows[1:]:
        assert row[state] == "not_assessed"


def _without_nowrap_spans(html):
    """The date in these sentences sits in a nowrap span (PAT-2298); the copy
    assertions below are about the words, so read them with the span removed."""
    return html.replace('<span class="nowrap">', "").replace("</span>", "")


# ── Findings page: timestamps + estate-wide counts ────────────────────────
def test_findings_page_shows_last_checked_and_feed_updated_timestamps(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/findings")

    assert response.status_code == 200
    text = _without_nowrap_spans(response.text)
    assert "CVE data last checked 22 Sep 2026 01:09 UTC" in text
    assert "vulnerability feed last updated 22 Sep 2026 01:04 UTC" in text
    assert "180 products assessed, 3 checking, 412 not yet assessed" in text


def test_findings_page_missing_cve_assessment_degrades_to_zero_without_crash(
    client, make_token, monkeypatch
):
    monkeypatch.setitem(STUB_STATE, "mode", "findings_omit_cve_assessment")
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/findings")

    assert response.status_code == 200
    text = response.text
    assert "CVE data last checked not yet recorded" in text
    assert "vulnerability feed last updated not yet recorded" in text
    assert "0 products assessed, 0 checking, 0 not yet assessed" in text


# ── Overview: coverage figure + timestamps, fed by a lightweight probe ────
def test_overview_shows_cve_data_checked_and_coverage_figure(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/")

    assert response.status_code == 200
    text = _without_nowrap_spans(response.text)
    assert "CVE data last checked 22 Sep 2026 01:09 UTC" in text
    assert "vulnerability feed last updated 22 Sep 2026 01:04 UTC" in text
    # 180 assessed of 595 total (180 + 3 + 412) = 30% (rounded).
    assert "180 of 595 installed products assessed for CVEs (30%)" in text
    # PAT-2160 moved the figure into "Your estate at a glance", which keeps
    # the never-counted-as-clean rule in its own wording.
    assert "the rest are not yet assessed, not clean" in text
    assert text.count("180 of 595 installed products assessed for CVEs") == 1


def test_overview_cve_assessment_unavailable_is_honest_not_a_false_zero(
    client, make_token, monkeypatch
):
    monkeypatch.setitem(STUB_STATE, "mode", "findings500")
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/")

    assert response.status_code == 200
    text = response.text
    assert "CVE assessment coverage is temporarily unavailable." in text
    assert "CVE data last checked" not in text
    assert "0 of 0 installed products" not in text


def test_overview_missing_cve_assessment_field_reads_as_zero_not_clean(
    client, make_token, monkeypatch
):
    monkeypatch.setitem(STUB_STATE, "mode", "findings_omit_cve_assessment")
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/")

    assert response.status_code == 200
    text = response.text
    assert "No installed products have been assessed for CVEs yet." in text
    assert "installed products assessed for CVEs (100%)" not in text


# ── Summary counts must exclude not_assessed from "clean" ─────────────────
def test_not_assessed_products_never_counted_towards_assessed_coverage(
    client, make_token, monkeypatch
):
    monkeypatch.setitem(STUB_STATE, "cve_assessment_data", {
        **CVE_ASSESSMENT_TENANT,
        "assessed_products": 10, "pending_products": 0, "not_assessed_products": 90,
    })
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/")

    assert response.status_code == 200
    text = response.text
    # 10 of 100 assessed - not 10 of 10, and not counted as if the 90
    # unmapped products were simply absent from the denominator.
    assert "10 of 100 installed products assessed for CVEs (10%)" in text


# ── Review round 1 (nemotron-3-ultra) fixes ────────────────────────────────
# P1: state == "assessed" with an unusable finding_count must never degrade
# to a clean "No known CVEs" pill - that is the exact false-clean this
# ticket exists to prevent (root AGENTS.md: CVE claims require evidence).
def test_cve_assessment_view_assessed_with_malformed_finding_count_never_reads_as_clean():
    view = main._cve_assessment_view({
        "state": "assessed", "finding_count": "not-a-number",
        "last_matched_at": "2026-09-22T01:00:00Z",
    })
    assert view["display_label"] != "No known CVEs"
    assert view["pill_class"] != "pill-ok"


def test_cve_assessment_view_assessed_with_missing_finding_count_never_reads_as_clean():
    view = main._cve_assessment_view({
        "state": "assessed", "last_matched_at": "2026-09-22T01:00:00Z",
        # finding_count omitted entirely - contract says assessed always
        # carries one; a response that doesn't is a contract violation,
        # not a genuine zero.
    })
    assert view["display_label"] != "No known CVEs"
    assert view["pill_class"] != "pill-ok"


def test_cve_assessment_product_view_assessed_with_malformed_finding_count_never_reads_as_clean():
    view = main._cve_assessment_product_view({
        "app": "Weird App", "versions": ["1.0"], "state": "assessed",
        "last_matched_at": "2026-09-22T01:00:00Z", "finding_count": -1,
    })
    assert view["display_label"] != "No known CVEs"
    assert view["pill_class"] != "pill-ok"


def test_device_detail_page_with_assessed_malformed_finding_count_does_not_render_clean(
    client, make_token, monkeypatch
):
    broken_detail = {
        **{k: v for k, v in DEVICE_DETAIL.items() if k != "cve_assessment"},
        "apps_with_findings": [],
        "cve_assessment": {
            "state": "assessed", "finding_count": None,
            "last_matched_at": "2026-09-22T01:00:00Z",
            "assessed_products": 1, "pending_products": 0, "not_assessed_products": 0,
            "products": [
                {"app": "Weird App", "versions": ["1.0"], "state": "assessed",
                 "last_matched_at": "2026-09-22T01:00:00Z", "finding_count": None},
            ],
        },
    }
    monkeypatch.setitem(STUB_STATE, "device_detail_data", broken_detail)
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices/dev-mac-001/vulnerabilities")

    assert response.status_code == 200
    assert "No known CVEs" not in response.text


# P2: cve_assessment.products missing entirely, or present but empty, both
# render the same honest "no data yet" message - never a crash.
def test_device_detail_cve_assessment_products_key_missing_renders_empty_state(
    client, make_token, monkeypatch
):
    detail = {
        **{k: v for k, v in DEVICE_DETAIL.items() if k != "cve_assessment"},
        "cve_assessment": {
            "state": "not_assessed", "finding_count": None, "last_matched_at": None,
            "assessed_products": 0, "pending_products": 0, "not_assessed_products": 0,
            # no "products" key at all
        },
    }
    monkeypatch.setitem(STUB_STATE, "device_detail_data", detail)
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices/dev-mac-001/vulnerabilities")

    assert response.status_code == 200
    assert "No CVE assessment data is available for this device yet." in response.text


def test_device_detail_cve_assessment_products_empty_list_renders_empty_state(
    client, make_token, monkeypatch
):
    detail = {
        **{k: v for k, v in DEVICE_DETAIL.items() if k != "cve_assessment"},
        "cve_assessment": {
            "state": "not_assessed", "finding_count": None, "last_matched_at": None,
            "assessed_products": 0, "pending_products": 0, "not_assessed_products": 0,
            "products": [],
        },
    }
    monkeypatch.setitem(STUB_STATE, "device_detail_data", detail)
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices/dev-mac-001/vulnerabilities")

    assert response.status_code == 200
    assert "No CVE assessment data is available for this device yet." in response.text


# P2: the overview page's extra /v1/portal/findings probe must degrade to
# the "temporarily unavailable" state on a real connection failure, not
# just an HTTP error status - upstream.py uses `requests`, not httpx, but
# the same wrapping (RequestException -> UpstreamError) must hold for a
# genuine refused connection/timeout, not only for a stub 500.
def test_overview_findings_probe_connection_error_reads_as_unavailable(
    client, make_token, monkeypatch
):
    real_request = upstream._session.request

    def flaky_request(method, url, **kwargs):
        if "/v1/portal/findings" in url:
            raise requests.exceptions.ConnectionError("connection refused (test)")
        return real_request(method, url, **kwargs)

    monkeypatch.setattr(upstream._session, "request", flaky_request)
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/")

    assert response.status_code == 200
    assert "CVE assessment coverage is temporarily unavailable." in response.text
