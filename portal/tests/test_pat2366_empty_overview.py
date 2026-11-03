"""PAT-2366: a verified empty new-software read must render the whole Overview."""

from tests.conftest import OVERVIEW, STUB_STATE
from tests.test_pat2093_new_software import _get, _new_software


def test_overview_renders_verified_empty_software_risk(client, make_token):
    STUB_STATE["overview_data"] = {**OVERVIEW, "new_software": _new_software()}

    response = _get(client, make_token())

    assert response.status_code == 200
    body = response.text
    card = body[body.index('id="high-risk-heading"'):body.index('id="extension-risk-heading"')]
    assert "Newly found in the last 14 days" in card
    assert '<span class="risk-card__count">0</span>' in card
    assert "Nothing newly found in this window is rated critical or high." in card
    assert "risk-card__badges" not in card
    assert "not counted as low risk" not in card
    assert "Software risk could not be read" not in card
    assert 'href="/software?approval=waiting"' in card
