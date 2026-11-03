"""PAT-1953: overview surfaces CVE attention as its own platform read model,

kept in its own row of the merged "Needs attention" card (PAT-2159), never
blended into the CIS row or its count, and never rendered as a false clean
read when the platform genuinely doesn't know yet (including before the
platform PR that introduces cve_attention has been deployed, when the key
is entirely absent from /v1/portal/overview)."""

from tests.conftest import OVERVIEW, STUB_STATE


def _get(client, token, path="/"):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def test_cve_attention_unavailable_renders_honest_unknown_state(
    client, make_token, monkeypatch
):
    monkeypatch.setitem(STUB_STATE, "overview_data", {
        **OVERVIEW,
        "cve_attention": {"available": False, "critical": 0, "high": 0},
    })
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert response.status_code == 200
    assert "CVE attention is not yet available for this estate." in response.text
    assert "0 critical, 0 high" not in response.text
    assert "0 critical and 0 high" not in response.text
    assert (
        "No critical or high confirmed CVE findings are currently shown."
        not in response.text
    )


def test_cve_attention_key_entirely_absent_renders_same_unknown_state(
    client, make_token
):
    # OVERVIEW (the shared default stub) carries no cve_attention key at all -
    # this simulates the real state of the platform today, before PR #569
    # ships. The handler must not crash and must render the same honest
    # "not yet available" state as an explicit available: false.
    assert "cve_attention" not in OVERVIEW
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert response.status_code == 200
    assert "CVE attention is not yet available for this estate." in response.text
    assert "0 critical, 0 high" not in response.text
    assert (
        "No critical or high confirmed CVE findings are currently shown."
        not in response.text
    )


def test_cve_attention_singular_count_and_findings_link(client, make_token, monkeypatch):
    monkeypatch.setitem(STUB_STATE, "overview_data", {
        **OVERVIEW,
        "cve_attention": {"available": True, "critical": 1, "high": 0},
    })
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert response.status_code == 200
    assert "Confirmed CVEs" in response.text
    assert 'class="pill pill-critical">1 critical' in response.text
    assert 'class="pill pill-muted">0 high' in response.text
    assert 'href="/findings#cve-findings"' in response.text


def test_cve_attention_plural_count_and_findings_link(client, make_token, monkeypatch):
    monkeypatch.setitem(STUB_STATE, "overview_data", {
        **OVERVIEW,
        "cve_attention": {"available": True, "critical": 2, "high": 5},
    })
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert response.status_code == 200
    assert 'class="pill pill-critical">2 critical' in response.text
    assert 'class="pill pill-high">5 high' in response.text
    assert 'href="/findings#cve-findings"' in response.text


def test_cve_attention_available_and_zero_is_a_genuine_all_clear(
    client, make_token, monkeypatch
):
    """CVE attention on its own reads as a clean, muted zero - but with the
    default OVERVIEW fixture's non-zero CIS findings still in play, the
    overall card must not claim a global all-clear off one clean source
    (D4: the two counts stay separate, never mixed)."""
    monkeypatch.setitem(STUB_STATE, "overview_data", {
        **OVERVIEW,
        "cve_attention": {"available": True, "critical": 0, "high": 0},
    })
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert response.status_code == 200
    assert "CVE attention is not yet available for this estate." not in response.text
    assert 'class="pill pill-muted">0 critical' in response.text
    assert 'class="pill pill-muted">0 high' in response.text
    # The default OVERVIEW fixture's CIS findings (critical=1, high=3) stay
    # visible and unaffected by the CVE row being clean.
    assert 'class="pill pill-critical">1 critical' in response.text
    assert 'class="pill pill-high">3 high' in response.text
    assert "Nothing needs attention." not in response.text


def test_findings_page_cve_section_has_its_own_anchor_and_cis_anchor_is_unchanged(
    client, make_token
):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/findings")

    assert response.status_code == 200
    assert 'id="cve-findings"' in response.text
    assert 'id="cis-compliance-findings"' in response.text
    assert response.text.count('id="cve-findings"') == 1
    assert response.text.count('id="cis-compliance-findings"') == 1
