"""PAT-1927: Cyber Essentials v3.3 readiness page.

Consumes GET /v1/portal/ce-readiness verbatim (contracts/portal-api.md), a
read-only per-device proxy that carries no verdict of its own - the portal
must not say, or imply, that a device or the estate passes, is compliant,
is certified or is ready. See that contract's "What this does not claim"
section, mirrored in main.py's route docstring.
"""

import re

from tests.conftest import CE_READINESS_CSV, CE_READINESS_REPORT_EMPTY, STUB_STATE

# Word-bounded so "readiness"/"already" etc never false-positive, but a
# banned word inside a longer real sentence still matches.
_BANNED_CLAIM_RE = re.compile(
    r"\b(passes|compliant|certified)\b|\bis ready\b", re.IGNORECASE
)


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


# ── Renders counts and devices ─────────────────────────────────────────────

def test_ce_readiness_renders_estate_counts_and_devices(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/ce-readiness")
    assert resp.status_code == 200
    body = resp.text
    assert "Cyber Essentials readiness" in body
    # Estate counts (contract field names: devices_total, not_passing,
    # unknown, no_outstanding_items_evidenced, retired_excluded).
    assert "mac-01" in body
    assert "win-02" in body
    assert "mac-03" in body
    assert "CVE-2026-1234" in body
    assert "generated_at" not in body  # raw key name never leaks into copy


def test_ce_readiness_renders_empty_estate(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["ce_readiness_data"] = CE_READINESS_REPORT_EMPTY
    resp = _get(client, token, "/ce-readiness")
    assert resp.status_code == 200
    assert "temporarily unavailable" not in resp.text.lower()
    assert "could not be read" not in resp.text.lower()


# ── No-verdict copy scan ────────────────────────────────────────────────────

def test_ce_readiness_never_claims_a_verdict(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/ce-readiness")
    assert resp.status_code == 200
    match = _BANNED_CLAIM_RE.search(resp.text)
    assert not match, f"banned verdict word found: {match.group(0)!r}"


def test_ce_readiness_empty_estate_never_claims_a_verdict(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["ce_readiness_data"] = CE_READINESS_REPORT_EMPTY
    resp = _get(client, token, "/ce-readiness")
    assert resp.status_code == 200
    match = _BANNED_CLAIM_RE.search(resp.text)
    assert not match, f"banned verdict word found: {match.group(0)!r}"


# ── Unknown state renders as not passing (in plain English), with reason ──

def test_ce_readiness_unknown_device_state_and_reason(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/ce-readiness")
    assert resp.status_code == 200
    body = resp.text
    # win-02 is the "unknown" device (cve_match_pending). Its row must show
    # the "Unknown" state (never a bare "unknown" claim of health) and a
    # plain-English reason, not the raw reason code.
    win02_idx = body.index("win-02")
    window = body[win02_idx:win02_idx + 4000]
    assert "Unknown" in window
    assert "cve_match_pending" not in window
    assert "queued" in window.lower() or "pending" in window.lower()


# ── not_evidenced controls never render as ok ──────────────────────────────

def test_ce_readiness_not_evidenced_controls_never_pill_ok(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/ce-readiness")
    assert resp.status_code == 200
    body = resp.text
    assert "Not evidenced by Patched" in body
    # No not_evidenced control row may carry the ok pill class.
    for line in body.splitlines():
        if "Not evidenced by Patched" in line:
            assert "pill-ok" not in line


def test_ce_readiness_evidenced_ok_control_is_never_labelled_pass(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/ce-readiness")
    assert resp.status_code == 200
    assert "Evidenced OK" in resp.text
    assert not _BANNED_CLAIM_RE.search(resp.text)


# ── Due-basis caveat ────────────────────────────────────────────────────────

def test_ce_readiness_due_basis_caveat_present_with_items(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/ce-readiness")
    assert resp.status_code == 200
    body = resp.text.lower()
    assert "published" in body
    assert "vendor shipped the fix" in body or "shipped the fix" in body


# ── CSV proxy ───────────────────────────────────────────────────────────────

def test_ce_readiness_csv_proxies_verbatim(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/ce-readiness.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert resp.text == CE_READINESS_CSV
    # The platform's own formula-injection escaping must survive untouched.
    assert "'=Example App" in resp.text


def test_ce_readiness_csv_requests_format_csv_and_no_tenant_param(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/ce-readiness.csv")
    assert resp.status_code == 200
    assert len(STUB_STATE["ce_readiness_requests"]) == 1
    query = STUB_STATE["ce_readiness_requests"][0]["query"]
    assert query.get("format") == "csv"
    assert "tenant" not in query


# ── Error state ──────────────────────────────────────────────────────────

def test_ce_readiness_error_state_is_not_rendered_as_empty(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["ce_readiness_status"] = 500
    resp = _get(client, token, "/ce-readiness")
    assert resp.status_code == 502
    body = resp.text.lower()
    assert "could not" in body or "temporarily unavailable" in body
    assert "no_outstanding_items_evidenced" not in body


def test_ce_readiness_csv_error_state_is_honest(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["ce_readiness_status"] = 500
    resp = _get(client, token, "/ce-readiness.csv")
    assert resp.status_code == 502
    assert "text/csv" not in resp.headers.get("content-type", "")


# ── JWT forwarded, no tenant param sent ─────────────────────────────────

def test_ce_readiness_forwards_jwt_and_sends_no_tenant_param(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/ce-readiness")
    assert resp.status_code == 200
    assert len(STUB_STATE["ce_readiness_requests"]) == 1
    request = STUB_STATE["ce_readiness_requests"][0]
    assert request["jwt"] == token
    assert "tenant" not in request["query"]


def test_ce_readiness_rejects_when_jwt_not_forwarded(client, make_token):
    token = make_token()
    other = make_token(email="bob@tenant-b.example")
    STUB_STATE["expected_jwt"] = other
    resp = _get(client, token, "/ce-readiness")
    # The stub 401s any call whose forwarded JWT doesn't match - proving the
    # portal cannot silently drop or substitute the caller's JWT.
    assert resp.status_code in (401, 502)


# ── Nav link ─────────────────────────────────────────────────────────────

def test_ce_readiness_nav_link_exists(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    assert 'href="/ce-readiness"' in resp.text


def test_overview_links_to_ce_readiness(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    assert 'href="/ce-readiness"' in resp.text
    assert "Cyber Essentials" in resp.text


# ── Control summary counts only what is evidenced ──────────────────────────

def test_ce_readiness_summary_never_counts_not_evidenced_controls_as_evidenced(
        client, make_token):
    # win-02 has one evidenced_ok control and one not_evidenced control. The
    # summary must not say "2 controls evidenced" - that overstates coverage.
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    body = _get(client, token, "/ce-readiness").text
    assert "0 items, 1 of 2 controls evidenced" in body
    # Any "N control(s) evidenced" must be the "X of N" form.
    assert not re.search(r"(?<!of )\b\d+ controls? evidenced", body)


def test_ce_control_labels_keep_acronyms():
    import main

    def label(control):
        return main._ce_control_view(
            {"control": control, "state": "not_evidenced"})["control_label"]

    assert label("edr_coverage") == "EDR coverage"
    assert label("defender_realtime_protection") == "Defender realtime protection"
