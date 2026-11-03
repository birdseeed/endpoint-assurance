"""PAT-1879: render the PAT-1969 finding-verification-lifecycle contract on
device_detail.html (finding_kind="cis", scoped to one device) and
findings.html (finding_kind="cve", tenant-wide). Fixtures live in
tests/conftest.py: LIFECYCLE_CIS_CURRENT/HISTORY cover a finding that
reaches an authoritative verified_fixed close (cis-1.1) and one that fails,
is fixed, then recurs (cis-2.6); LIFECYCLE_CVE_CURRENT/HISTORY cover a
pending_verification finding (CVE-2026-1234) and a verified_fixed finding
whose evidence is deliberately non-authoritative (CVE-2026-0001).
"""

import copy

import main
from tests.conftest import DEVICE_DETAIL, STUB_STATE


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


# ── Every lifecycle state renders with dates and responsible authority ────
def test_device_detail_renders_dates_and_actor_for_each_event(client, make_token):
    # PAT-2164: the CIS lifecycle only renders on the Compliance tab now.
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices/dev-mac-001/compliance")
    assert resp.status_code == 200
    # Operator-action events carry a real actor - it must render, not just
    # the source_type label.
    assert "alex@patched.im" in resp.text
    assert "jane@tenant-a.example" in resp.text
    # humandate renders '04 Dec 2026' for the verified_fixed
    # observation - proves a real date reached the page, not a placeholder.
    assert "04 Dec 2026" in resp.text


def test_findings_renders_dates_and_actor_for_cve_lifecycle(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    assert "alex@patched.im" in resp.text
    assert "25 Dec 2026" in resp.text


# ── Pending verification is distinct from verified fixed ──────────────────
def test_pending_verification_is_not_rendered_as_verified_fixed(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    assert '<span class="pill pill-warn">Pending verification</span>' in resp.text
    # The pending-verification CVE's own status pill is never pill-ok - the
    # only place "Verified fixed" pill-ok can legitimately appear on this
    # page is the *other* CVE's row.
    pending_idx = resp.text.index("CVE-2026-1234")
    next_row_idx = resp.text.index("CVE-2026-0001")
    pending_row = resp.text[pending_idx:next_row_idx]
    assert "pill-ok" not in pending_row
    assert "Verified fixed" not in pending_row


# ── Verified fixed links to the fresh observation that closed it ──────────
def test_verified_fixed_shows_the_closing_observation(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices/dev-mac-001/compliance")
    assert resp.status_code == 200
    assert '<span class="pill pill-ok">Verified fixed</span>' in resp.text
    # Closed-by note names the endpoint observation that proved it, with the
    # date of that specific observation (not just the current-row summary).
    assert "Closed by" in resp.text
    assert "Endpoint observation" in resp.text
    assert "04 Dec 2026" in resp.text


# ── Still failing / recurred retain earlier history ────────────────────────
def test_recurred_finding_keeps_full_event_history(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices/dev-mac-001/compliance")
    assert resp.status_code == 200
    assert '<span class="pill pill-bad">Recurred</span>' in resp.text
    # The current status is "recurred", but the timeline must still carry
    # the finding's full prior life - including the verified_fixed event
    # that recurrence overtook, not just the latest two events.
    assert "5 lifecycle events" in resp.text
    assert "recurred 1 time" in resp.text
    for label in ("First observed", "Guidance issued", "Still failing"):
        assert label in resp.text


# ── Stale/partial evidence cannot display a successful verification ───────
def test_nonauthoritative_verified_fixed_is_not_a_clean_pass(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    # CVE-2026-0001 is verified_fixed but status_authoritative=False in the
    # fixture - it must render pill-warn, never pill-ok, and the closure
    # note must say so explicitly.
    closing_idx = resp.text.index("CVE-2026-0001")
    trailing = resp.text[closing_idx:closing_idx + 2000]
    assert 'pill pill-warn" title="This verification could not be confirmed' in trailing
    assert '<span class="pill pill-ok">Verified fixed</span>' not in trailing
    assert "Not confirmed as authoritative evidence." in trailing


def test_authoritative_verified_fixed_still_reads_clean(client, make_token):
    """Pin the positive case next to the negative one above: an authoritative
    verified_fixed (cis-1.1) keeps the plain pill-ok with no caveat text."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices/dev-mac-001/compliance")
    assert resp.status_code == 200
    assert "Not confirmed as authoritative evidence." not in resp.text


# ── No lifecycle evidence yet is a distinct, honest state ──────────────────
def test_finding_with_no_lifecycle_row_shows_explicit_absence(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = copy.deepcopy(DEVICE_DETAIL)
    detail["compliance_signals"].append({
        "rule_id": "cis-9.9", "title": "New rule with no lifecycle evidence yet",
        "severity": "low", "status": "fail", "advisory": "",
    })
    STUB_STATE["device_detail_data"] = detail
    resp = _get(client, token, "/devices/dev-mac-001/compliance")
    assert resp.status_code == 200
    assert "No lifecycle evidence yet" in resp.text


# ── Management-platform neutrality ─────────────────────────────────────────
def test_lifecycle_copy_names_no_management_platform(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    for path in ("/devices/dev-mac-001/compliance", "/findings"):
        resp = _get(client, token, path)
        assert resp.status_code == 200
        lowered = resp.text.lower()
        for banned in ("jamf", "intune", "patch my pc", "robopack"):
            assert banned not in lowered


# ── Upstream error handling reuses _error_page, same as every other call ──
def test_device_detail_lifecycle_failure_uses_error_page(client, make_token):
    # PAT-2164: the CIS lifecycle fetch only happens on the Compliance tab
    # now - no other tab route calls it at all.
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["lifecycle_status_override"] = 503
    resp = _get(client, token, "/devices/dev-mac-001/compliance")
    # 503 from the platform classifies as "not_enabled" (upstream.py's
    # _classify) and renders not_enabled.html, exactly like every other
    # portal read that hits a 503 - main.py adds no bespoke handling for
    # these two calls.
    assert resp.status_code == 503
    assert "portal not yet enabled" in resp.text.lower()
    # Proves the failure is real: request reached the stub before failing.
    assert len(STUB_STATE["lifecycle_requests"]) >= 1


def test_findings_lifecycle_failure_uses_error_page(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["lifecycle_status_override"] = 401
    resp = _get(client, token, "/findings")
    assert resp.status_code == 401
    assert "session has expired" in resp.text.lower()


def test_device_detail_lifecycle_forbidden_uses_not_linked_page(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["lifecycle_status_override"] = 403
    resp = _get(client, token, "/devices/dev-mac-001/compliance")
    assert resp.status_code == 403
    assert "not linked" in resp.text.lower()


# ── Index-building helpers, unit level ─────────────────────────────────────
def test_lifecycle_pill_class_downgrades_nonauthoritative_verified_fixed():
    assert main._lifecycle_pill_class("verified_fixed", True) == "pill-ok"
    assert main._lifecycle_pill_class("verified_fixed", False) == "pill-warn"
    assert main._lifecycle_pill_class("pending_verification", False) == "pill-warn"
    assert main._lifecycle_pill_class("still_failing", True) == "pill-bad"
    assert main._lifecycle_pill_class("unknown_future_status", True) == "pill-muted"


def test_lifecycle_index_groups_events_by_finding_key_and_finds_closing_event():
    current = [{
        "finding_key": "cis-1.1", "status": "verified_fixed",
        "status_authoritative": True,
    }]
    history = [
        {"id": 1, "finding_key": "cis-1.1", "event_type": "first_observed",
         "source_type": "endpoint_observation", "actor": "", "authoritative": True,
         "observed_at": "2026-12-01T08:00:00Z", "recorded_at": "2026-12-01T08:00:05Z"},
        {"id": 2, "finding_key": "cis-1.1", "event_type": "verified_fixed",
         "source_type": "endpoint_observation", "actor": "", "authoritative": True,
         "observed_at": "2026-12-04T09:00:00Z", "recorded_at": "2026-12-04T09:00:05Z"},
    ]
    index = main._lifecycle_index(current, history)
    entry = index["cis-1.1"]
    assert entry["closing_event"]["id"] == 2
    assert [e["id"] for e in entry["events"]] == [2, 1]  # newest first


def test_withdrawn_reads_as_a_matcher_correction_never_a_fix():
    # PAT-2107: a finding the corrected matcher stopped producing is withdrawn
    # (source "matcher", never authoritative). It must never borrow the
    # verified_fixed treatment: no pill-ok, no closing observation.
    current = {"finding_key": "CVE-2018-0592", "status": "withdrawn", "status_authoritative": False}
    events = [
        {"id": 1, "finding_key": "CVE-2018-0592", "event_type": "first_observed",
         "source_type": "endpoint_observation", "authoritative": True},
        {"id": 2, "finding_key": "CVE-2018-0592", "event_type": "withdrawn",
         "source_type": "matcher", "authoritative": False},
    ]
    entry = main._lifecycle_index([current], events)["CVE-2018-0592"]
    assert entry["status_label"] == "Withdrawn: matcher correction, not a fix"
    assert entry["pill_class"] == "pill-muted"
    assert entry["closing_event"] is None
    withdrawn_event = entry["events"][0]
    assert withdrawn_event["event_type"] == "withdrawn"
    assert withdrawn_event["actor_label"] == "CVE matcher correction"
    assert withdrawn_event["pill_class"] != "pill-ok"
