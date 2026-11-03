"""PAT-2263: the device Compliance tab's "Known vulnerable drivers" section
and the Findings page's estate driver-findings section, both reading the
platform's additive `kernel_drivers` device block and the
`GET /v1/portal/driver-findings` estate endpoint (contracts/portal-api.md
"kernel_drivers (PAT-2263)" and "GET /v1/portal/driver-findings (PAT-2263)").

Every render state per the ticket's own Done-when list: not_reported
(macOS and older-agent wording), unavailable, a match loaded and not
loaded, blocklist enforced/not enforced/unknown, a stale list, no matches,
the platform's "unknown" (no hash, or no list fetched yet) states, and a
banned-words check that the section never claims "safe", "exploited" or
"compromised". Plus the Findings page's estate section and its
"blocklist not enforced" filter.
"""

from copy import deepcopy

import main
from tests.conftest import DEVICE_DETAIL, DRIVER_FINDINGS, DRIVER_LISTS, STUB_STATE

NOT_REPORTED_MACOS_TEXT = "Driver checks apply to Windows devices."
NOT_REPORTED_AGENT_TEXT = "This device's agent doesn't report drivers yet."
UNAVAILABLE_TEXT = "The agent could not read this device's drivers."
BANNED_WORDS = ("safe", "exploited", "compromised", "none found")


def _get_compliance(client, token, device_id="dev-mac-001"):
    return client.get(
        f"/devices/{device_id}/compliance", headers={"Cf-Access-Jwt-Assertion": token})


def _assert_no_banned_words(body: str):
    lowered = body.lower()
    for word in BANNED_WORDS:
        assert word not in lowered, f"banned claim word {word!r} found in rendered driver section"


def _windows_detail(**kernel_drivers_block):
    detail = deepcopy(DEVICE_DETAIL)
    detail["platform"] = "Windows"
    detail["kernel_drivers"] = kernel_drivers_block
    return detail


BASE_ENFORCEMENT = {
    "vulnerable_driver_blocklist": "enabled", "hvci": "on",
    "smart_app_control": "off", "code_integrity_policy": "on",
    "blocklist_enforced": "yes",
}

MATCH = {
    "source": "loldrivers", "source_url": "https://www.loldrivers.io/api/drivers.json",
    "category": "vulnerable", "entry_id": "e-1", "entry_name": "gdrv.sys",
    "hash_kind": "sha256", "hash": "b" * 64, "list_version": "sha256:4be1...",
    "list_fetched_at": "2026-09-26T01:00:00Z", "list_stale": False,
}


def _driver_row(loaded, match_status="listed", matches=None, unknown_reason=None):
    hash_status = "hashed" if match_status != "unknown" else "unhashed"
    default_matches = [MATCH] if match_status == "listed" else []
    return {
        "path": "C:\\Windows\\Temp\\helper.sys", "service_name": "helper",
        "service_type": "kernel", "start_type": "demand", "loaded": loaded,
        "sources": ["service"], "hash_status": hash_status,
        "unhashed_reason": unknown_reason, "version": "1.0.0.1", "sha256": "b" * 64,
        "authenticode_sha256": None, "reported_at": "2026-09-29T09:00:00Z",
        "first_seen_at": "2026-09-27T09:00:00Z", "match_status": match_status,
        "unknown_reason": unknown_reason,
        "matches": matches if matches is not None else default_matches,
    }


# ── not_reported: key missing entirely (older platform) ───────────────────
def test_missing_kernel_drivers_key_on_macos_shows_macos_wording(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    assert "kernel_drivers" not in DEVICE_DETAIL

    response = _get_compliance(client, token)

    assert response.status_code == 200
    body = response.text
    assert NOT_REPORTED_MACOS_TEXT in body
    assert NOT_REPORTED_AGENT_TEXT not in body
    _assert_no_banned_words(body)


def test_missing_kernel_drivers_key_on_windows_shows_agent_wording(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    detail["platform"] = "Windows"
    assert "kernel_drivers" not in detail
    STUB_STATE["device_detail_data"] = detail

    response = _get_compliance(client, token)

    assert response.status_code == 200
    body = response.text
    assert NOT_REPORTED_AGENT_TEXT in body
    assert NOT_REPORTED_MACOS_TEXT not in body
    _assert_no_banned_words(body)


def test_explicit_not_reported_status(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _windows_detail(
        status="not_reported", enforcement=None, lists=[], summary={},
        drivers=[], drivers_truncated=False, errors=[],
        reported_at=None, observed_at=None,
    )

    response = _get_compliance(client, token)

    assert response.status_code == 200
    body = response.text
    assert NOT_REPORTED_AGENT_TEXT in body
    assert "Vulnerable driver blocklist" not in body
    _assert_no_banned_words(body)


# ── unavailable: enforcement still reported, drivers not ───────────────────
def test_unavailable_shows_line_and_still_shows_enforcement(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _windows_detail(
        status="unavailable", enforcement=BASE_ENFORCEMENT, lists=DRIVER_LISTS,
        summary={"drivers": 0, "hashed": 0, "unhashed": 0, "listed": 0,
                  "listed_malicious": 0, "unknown": 0},
        drivers=[], drivers_truncated=False,
        errors=["driver_list_read_failed"],
        reported_at="2026-09-29T09:00:00Z", observed_at="2026-09-29T08:59:40Z",
    )

    response = _get_compliance(client, token)

    assert response.status_code == 200
    body = response.text
    assert UNAVAILABLE_TEXT in body
    # contract: "unavailable (the agent could not read its driver list;
    # `enforcement` is still reported)" - the blocklist line must still show.
    assert "Vulnerable driver blocklist" in body
    assert "enforced" in body
    _assert_no_banned_words(body)


# ── matches: loaded / not loaded, evidence-only phrasing ───────────────────
def test_match_loaded_shows_present_and_not_blocked(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _windows_detail(
        status="complete", enforcement={**BASE_ENFORCEMENT, "blocklist_enforced": "no"},
        lists=DRIVER_LISTS,
        summary={"drivers": 1, "hashed": 1, "unhashed": 0, "listed": 1,
                  "listed_malicious": 0, "unknown": 0},
        drivers=[_driver_row(loaded=True)], drivers_truncated=False, errors=[],
        reported_at="2026-09-29T09:00:00Z", observed_at="2026-09-29T08:59:40Z",
    )

    response = _get_compliance(client, token)

    assert response.status_code == 200
    body = response.text
    assert "Present and not blocked by Windows" in body
    assert "Present, blocked by Windows" not in body
    assert "not enforced" in body
    assert "helper.sys" in body or "Temp" in body
    _assert_no_banned_words(body)


def test_match_not_loaded_shows_present_blocked(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _windows_detail(
        status="complete", enforcement=BASE_ENFORCEMENT, lists=DRIVER_LISTS,
        summary={"drivers": 1, "hashed": 1, "unhashed": 0, "listed": 1,
                  "listed_malicious": 0, "unknown": 0},
        drivers=[_driver_row(loaded=False)], drivers_truncated=False, errors=[],
        reported_at="2026-09-29T09:00:00Z", observed_at="2026-09-29T08:59:40Z",
    )

    response = _get_compliance(client, token)

    assert response.status_code == 200
    body = response.text
    assert "Present, blocked by Windows" in body
    assert "Present and not blocked by Windows" not in body
    _assert_no_banned_words(body)


def test_malicious_match_shows_malicious_pill(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    malicious_match = {**MATCH, "source": "loldrivers", "category": "malicious"}
    STUB_STATE["device_detail_data"] = _windows_detail(
        status="complete", enforcement=BASE_ENFORCEMENT, lists=DRIVER_LISTS,
        summary={"drivers": 1, "hashed": 1, "unhashed": 0, "listed": 1,
                  "listed_malicious": 1, "unknown": 0},
        drivers=[_driver_row(loaded=True, matches=[malicious_match])],
        drivers_truncated=False, errors=[],
        reported_at="2026-09-29T09:00:00Z", observed_at="2026-09-29T08:59:40Z",
    )

    response = _get_compliance(client, token)

    assert response.status_code == 200
    assert "Malicious" in response.text


# ── blocklist enforcement labels ────────────────────────────────────────────
def test_blocklist_enforced_unknown_never_defaults_either_way(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _windows_detail(
        status="complete",
        enforcement={**BASE_ENFORCEMENT, "blocklist_enforced": "not-a-real-value"},
        lists=DRIVER_LISTS,
        summary={"drivers": 0, "hashed": 0, "unhashed": 0, "listed": 0,
                  "listed_malicious": 0, "unknown": 0},
        drivers=[], drivers_truncated=False, errors=[],
        reported_at="2026-09-29T09:00:00Z", observed_at="2026-09-29T08:59:40Z",
    )

    response = _get_compliance(client, token)

    assert response.status_code == 200
    assert "Vulnerable driver blocklist: <strong>unknown</strong>" in response.text


# ── stale list state, shown plainly ────────────────────────────────────────
def test_stale_list_shows_stale_pill(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _windows_detail(
        status="complete", enforcement=BASE_ENFORCEMENT, lists=DRIVER_LISTS,
        summary={"drivers": 0, "hashed": 0, "unhashed": 0, "listed": 0,
                  "listed_malicious": 0, "unknown": 0},
        drivers=[], drivers_truncated=False, errors=[],
        reported_at="2026-09-29T09:00:00Z", observed_at="2026-09-29T08:59:40Z",
    )
    # DRIVER_LISTS' second entry (loldrivers) is already stale=True.

    response = _get_compliance(client, token)

    assert response.status_code == 200
    body = response.text
    assert "loldrivers.io" in body
    assert "Stale" in body


# ── no matches: clean, dated, never "safe" ─────────────────────────────────
def test_no_matches_shows_dated_wording_never_safe(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _windows_detail(
        status="complete", enforcement=BASE_ENFORCEMENT,
        lists=[
            {"source": "microsoft_driver_blocklist",
             "source_url": "https://aka.ms/VulnerableDriverBlockList", "status": "succeeded",
             "fetched_at": "2026-09-29T01:00:00Z", "attempted_at": "2026-09-29T01:00:00Z",
             "list_version": "10.0.29545.0", "entry_count": 1124, "stale": False},
        ],
        summary={"drivers": 5, "hashed": 5, "unhashed": 0, "listed": 0,
                  "listed_malicious": 0, "unknown": 0},
        drivers=[_driver_row(loaded=False, match_status="unknown", unknown_reason=None)],
        drivers_truncated=False, errors=[],
        reported_at="2026-09-29T09:00:00Z", observed_at="2026-09-29T08:59:40Z",
    )

    response = _get_compliance(client, token)

    assert response.status_code == 200
    body = response.text
    assert "No drivers on this device match the vulnerable driver lists checked on" in body
    _assert_no_banned_words(body)


# ── unknown: no list ever fetched ────────────────────────────────────────────
def test_no_list_ever_fetched_reads_as_unknown_not_clean(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _windows_detail(
        status="complete", enforcement=BASE_ENFORCEMENT,
        lists=[
            {"source": "microsoft_driver_blocklist",
             "source_url": "https://aka.ms/VulnerableDriverBlockList", "status": "never_fetched",
             "fetched_at": None, "attempted_at": "2026-09-29T01:00:00Z",
             "list_version": None, "entry_count": None, "stale": True},
            {"source": "loldrivers", "source_url": "https://www.loldrivers.io/api/drivers.json",
             "status": "never_fetched", "fetched_at": None, "attempted_at": "2026-09-29T01:00:00Z",
             "list_version": None, "entry_count": None, "stale": True},
        ],
        summary={"drivers": 5, "hashed": 5, "unhashed": 0, "listed": 0,
                  "listed_malicious": 0, "unknown": 5},
        drivers=[_driver_row(
            loaded=False, match_status="unknown", unknown_reason="lists_unavailable")],
        drivers_truncated=False, errors=[],
        reported_at="2026-09-29T09:00:00Z", observed_at="2026-09-29T08:59:40Z",
    )

    response = _get_compliance(client, token)

    assert response.status_code == 200
    body = response.text
    assert "no driver list has been fetched yet" in body
    assert "No drivers on this device match the vulnerable driver lists checked on" not in body
    _assert_no_banned_words(body)


# ── unknown: no drivers could be hashed ─────────────────────────────────────
def test_no_drivers_hashed_reads_as_unknown_not_clean(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _windows_detail(
        status="complete", enforcement=BASE_ENFORCEMENT, lists=DRIVER_LISTS,
        summary={"drivers": 3, "hashed": 0, "unhashed": 3, "listed": 0,
                  "listed_malicious": 0, "unknown": 3},
        drivers=[_driver_row(loaded=False, match_status="unknown", unknown_reason="not_hashed")],
        drivers_truncated=False, errors=[],
        reported_at="2026-09-29T09:00:00Z", observed_at="2026-09-29T08:59:40Z",
    )

    response = _get_compliance(client, token)

    assert response.status_code == 200
    body = response.text
    assert "none of this device's drivers could be hashed" in body
    assert "No drivers on this device match the vulnerable driver lists checked on" not in body
    _assert_no_banned_words(body)


# ── malformed input never 500s ─────────────────────────────────────────────
def test_kernel_drivers_missing_and_malformed_never_500(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    for override in (None, "not-a-dict", 42, [], {}):
        detail = deepcopy(DEVICE_DETAIL)
        detail["platform"] = "Windows"
        if override is None:
            detail.pop("kernel_drivers", None)
        else:
            detail["kernel_drivers"] = override
        STUB_STATE["device_detail_data"] = detail

        response = _get_compliance(client, token)
        assert response.status_code == 200
        _assert_no_banned_words(response.text)


# ── unit-level: normalise_kernel_drivers fails soft on garbage ─────────────
def test_normalise_kernel_drivers_treats_absence_and_garbage_as_not_reported():
    for raw in (None, "not-a-dict", 42, [], {}):
        view = main.normalise_kernel_drivers(raw, "macOS")
        assert view["status"] == "not_reported"
        assert view["enforcement"] is None
        assert view["matches"] == []
        assert view["is_macos"] is True


def test_normalise_kernel_drivers_checked_state_boundaries():
    # No list ever fetched -> unknown_no_list, even with hashed drivers.
    raw = {
        "status": "complete", "enforcement": BASE_ENFORCEMENT,
        "lists": [{"source": "microsoft_driver_blocklist", "status": "never_fetched",
                    "fetched_at": None, "attempted_at": None, "list_version": None,
                    "entry_count": None, "stale": True}],
        "summary": {"drivers": 2, "hashed": 2, "unhashed": 0, "listed": 0,
                     "listed_malicious": 0, "unknown": 2},
        "drivers": [], "drivers_truncated": False, "errors": [],
    }
    assert main.normalise_kernel_drivers(raw)["checked_state"] == "unknown_no_list"

    # A list has fetched, but every driver is unhashed -> unknown_unhashed.
    raw["lists"][0].update({"status": "succeeded", "fetched_at": "2026-09-29T01:00:00Z"})
    raw["summary"] = {"drivers": 2, "hashed": 0, "unhashed": 2, "listed": 0,
                       "listed_malicious": 0, "unknown": 2}
    assert main.normalise_kernel_drivers(raw)["checked_state"] == "unknown_unhashed"

    # Fetched and hashed, none listed -> clean.
    raw["summary"] = {"drivers": 2, "hashed": 2, "unhashed": 0, "listed": 0,
                       "listed_malicious": 0, "unknown": 0}
    assert main.normalise_kernel_drivers(raw)["checked_state"] == "clean"


# ── Findings page: estate driver-findings section ──────────────────────────
def test_findings_page_shows_driver_findings_section(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = client.get("/findings", headers={"Cf-Access-Jwt-Assertion": token})

    assert response.status_code == 200
    body = response.text
    assert "Known vulnerable drivers" in body
    assert "acme-win-accounts" in body
    assert "Not enforced" in body
    assert "Blocklist not enforced" in body
    _assert_no_banned_words(body)


def test_findings_page_driver_filter_marks_critical_rows(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = client.get("/findings", headers={"Cf-Access-Jwt-Assertion": token})

    assert response.status_code == 200
    # DRIVER_FINDINGS' one row has blocklist_enforced "no" -> critical.
    assert 'data-filter-blocklist="not_enforced"' in response.text


def test_findings_page_driver_findings_unavailable_fails_soft(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["driver_findings_status"] = 500

    response = client.get("/findings", headers={"Cf-Access-Jwt-Assertion": token})

    assert response.status_code == 200
    body = response.text
    assert "Driver findings are temporarily unavailable" in body
    # The CVE table above must be entirely unaffected by this outage.
    assert "CVE-2026-1234" in body or "CVE-2026-0001" in body


def test_findings_page_no_driver_findings_never_says_safe(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["driver_findings_data"] = {"findings": [], "lists": DRIVER_LISTS, "summary": {}}

    response = client.get("/findings", headers={"Cf-Access-Jwt-Assertion": token})

    assert response.status_code == 200
    body = response.text
    assert "No drivers on your estate match the vulnerable driver lists checked so far." in body
    _assert_no_banned_words(body)


def test_driver_findings_row_marks_not_enforced_as_critical():
    row = main._driver_finding_row_view(DRIVER_FINDINGS[0])
    assert row["critical"] is True
    assert row["blocklist_enforced_label"] == "not enforced"

    enforced = {**DRIVER_FINDINGS[0], "blocklist_enforced": "yes"}
    assert main._driver_finding_row_view(enforced)["critical"] is False
