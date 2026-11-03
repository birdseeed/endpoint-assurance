"""PAT-1785: /exceptions renders the per-tenant software exception register
against the proposed (not yet built - see main.py's `exceptions()`
docstring) GET /v1/portal/exceptions contract. This is a portal-side-only
ticket: the platform endpoint does not exist today, so these tests exercise
the portal's rendering, grouping and error handling against a stub that
mimics the proposed shape.

Default fixture (tests/conftest.py EXCEPTIONS, 4 rows, total=4, not
truncated):
  LegacyLedger  unaccepted                              -> needs attention
  ShadyCoupons  accepted, review_overdue=True            -> needs attention
  CorpVPN       accepted, review not due                 -> accepted
  MysteryTool   status="withdrawn" (unrecognised)        -> unrecognised
"""

from tests.conftest import EXCEPTIONS, STUB_STATE


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def test_exceptions_requires_auth(client):
    resp = client.get("/exceptions")
    assert resp.status_code == 401


def test_exceptions_nav_link_present(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    assert ">Exceptions<" in resp.text


def test_exceptions_never_removes_a_finding(client, make_token):
    """Root rule (PAT-1785): an exception never removes a finding from any
    report. The register page must never claim to suppress or hide
    anything - it only ever adds status on top."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/exceptions")
    assert resp.status_code == 200
    assert "never removes a finding" in resp.text


def test_exceptions_unaccepted_is_first_class_status(client, make_token):
    """Unaccepted renders as its own explicit status, not a blank or an
    absence, and lands in the needs-attention group, ahead of the
    Accepted group's heading."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/exceptions")
    assert resp.status_code == 200
    accepted_heading_start = resp.text.index("<h2>Accepted</h2>")
    assert "LegacyLedger" in resp.text[:accepted_heading_start]
    assert "Unaccepted" in resp.text[:accepted_heading_start]


def test_exceptions_accepted_shows_named_acceptor_and_date(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/exceptions")
    assert resp.status_code == 200
    assert "CorpVPN" in resp.text
    assert "Priya Shah" in resp.text


def test_exceptions_review_overdue_needs_attention_even_when_accepted(client, make_token):
    """PAT-1785 rule: a review date passing raises a finding independently
    of acceptance - an accepted exception with a lapsed review date must
    still land in Needs attention, not Accepted."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/exceptions")
    assert resp.status_code == 200
    needs_attention_start = resp.text.index("<h2>Needs attention</h2>")
    accepted_heading_start = resp.text.index("<h2>Accepted</h2>")
    shady_pos = resp.text.index("ShadyCoupons")
    assert needs_attention_start < shady_pos < accepted_heading_start
    assert "Overdue" in resp.text


def test_exceptions_accepted_not_overdue_lands_in_accepted_group(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/exceptions")
    assert resp.status_code == 200
    accepted_heading_start = resp.text.index("<h2>Accepted</h2>")
    needs_attention_heading_start = resp.text.index("<h2>Needs attention</h2>")
    corpvpn_pos = resp.text.index("CorpVPN")
    assert accepted_heading_start < corpvpn_pos
    # CorpVPN is not in the needs-attention table at all.
    needs_attention_block = resp.text[needs_attention_heading_start:accepted_heading_start]
    assert "CorpVPN" not in needs_attention_block


def test_exceptions_unrecognised_status_not_silently_dropped(client, make_token):
    """Absence requires authority (root AGENTS.md): a status this page
    doesn't recognise must render distinctly, never as accepted or
    unaccepted, and never disappear from the page entirely."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/exceptions")
    assert resp.status_code == 200
    assert "MysteryTool" in resp.text
    assert "Status not recognised" in resp.text


def test_exceptions_shows_depends_on_and_devices(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/exceptions")
    assert resp.status_code == 200
    assert "Finance close process depends on the 4.1 report format" in resp.text
    assert "acme-mbp-frontdesk" in resp.text


def test_exceptions_shows_decision_history(client, make_token):
    """Full decision history is kept, including a change of acceptor."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/exceptions")
    assert resp.status_code == 200
    assert "Acceptor_changed" in resp.text or "Acceptor changed" in resp.text
    assert "Alex left the account team" in resp.text


def test_exceptions_request_affordances_are_mailto_not_a_write(client, make_token):
    """PAT-1785: request/record model, not self-service - the portal must
    never write a disposition itself. Every action on this page is a
    mailto link, same as PAT-1642/PAT-1643."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/exceptions")
    assert resp.status_code == 200
    assert "Ask us to decide" in resp.text
    assert "Ask us to review" in resp.text
    assert "Request a new exception" in resp.text
    assert 'href="mailto:hello@patched.im?subject=' in resp.text
    assert "/exceptions/accept" not in resp.text
    assert "/exceptions/new" not in resp.text


def test_exceptions_no_action_link_for_already_decided_row(client, make_token):
    """CorpVPN is accepted with a review date not yet due - it needs no
    "ask us to decide" or "ask us to review" affordance."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/exceptions")
    assert resp.status_code == 200
    accepted_heading_start = resp.text.index("<h2>Accepted</h2>")
    unrecognised_title = "<h2>Status not recognised</h2>"
    unrecognised_idx = resp.text.find(unrecognised_title)
    end = unrecognised_idx if unrecognised_idx != -1 else len(resp.text)
    accepted_block = resp.text[accepted_heading_start:end]
    assert "Ask us to decide" not in accepted_block
    assert "Ask us to review" not in accepted_block


def test_exceptions_empty_tenant_renders_clean(client, make_token, monkeypatch):
    STUB_STATE["exceptions_data"] = {
        "generated_at": "2026-09-17T12:00:00Z", "total": 0,
        "truncated": False, "exceptions": [],
    }
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/exceptions")
    assert resp.status_code == 200
    assert "0 software exceptions on file" in resp.text
    assert "Nothing needs attention" in resp.text


def test_exceptions_truncated_shows_partial_notice(client, make_token):
    data = dict(EXCEPTIONS)
    data["total"] = 400
    data["truncated"] = True
    STUB_STATE["exceptions_data"] = data
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/exceptions")
    assert resp.status_code == 200
    assert "This list is partial" in resp.text
    assert "Showing the first 4 of 400 exceptions" in resp.text


def test_exceptions_uses_shared_layout_and_single_page_search(client, make_token):
    """PAT-1846 keeps both decision groups searchable and structurally
    consistent without adding page-specific JavaScript."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/exceptions")
    assert resp.status_code == 200
    # PAT-2092: the "Accepted" table carries an extra exception-table--accepted
    # class so its Product column (a different trailing-column count than
    # "Needs attention") can get its own per-reveal-tier width - see
    # exception-col-product-accepted's comment in portal.css. Both tables
    # still match the shared ".exception-table" selector for search/CSS.
    assert resp.text.count('class="data-table exception-table"') == 1
    assert 'class="data-table exception-table exception-table--accepted"' in resp.text
    assert 'data-table-search=".exception-table"' in resp.text
    assert resp.text.count('class="table-scroll"') >= 2
    assert '<h2>Needs attention</h2>' in resp.text
    assert '<h2>Accepted</h2>' in resp.text


def test_exceptions_decision_evidence_is_stacked_and_summary_spans_columns(client, make_token):
    """Named decisions, dates and summary rows remain legible when a row
    includes both its decision and supporting history."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/exceptions")
    assert resp.status_code == 200
    assert 'class="cell-stack"><span class="pill pill-ok">Accepted</span>' in resp.text
    assert "By Alex Patched on" in resp.text
    assert 'class="exception-review" data-value="2026-08-01"' in resp.text
    assert 'data-value="2026-11-05T09:00:00Z"' in resp.text
    assert 'colspan="8"' in resp.text


def test_exceptions_unexpected_shape_renders_error_not_empty(client, make_token):
    """Same contract-drift protection as /findings and /software (PAT-888):
    a response matching neither documented shape must not render as an
    innocuous empty register."""
    token = make_token()
    STUB_STATE["mode"] = "malformed"
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/exceptions")
    assert resp.status_code != 200
    assert "0 software exceptions on file" not in resp.text


def test_exceptions_upstream_401_shows_reauth(client, make_token):
    token = make_token()
    STUB_STATE["mode"] = "auth401"
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/exceptions")
    assert resp.status_code == 401
    assert "session has expired" in resp.text.lower() or "sign in" in resp.text.lower()


def test_exceptions_upstream_503_shows_not_enabled(client, make_token):
    token = make_token()
    STUB_STATE["mode"] = "down503"
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/exceptions")
    assert resp.status_code == 503
