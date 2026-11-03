"""PAT-1844: the software page consumes the shared portal layout primitives.

PAT-2120 rebuilt /software around one merged product table (see
test_software.py's module docstring for the merge behaviour); the five
separate decision-group cards this file used to guard are gone, replaced
by a single data-table plus the decision-state segmented control, so these
tests are rewritten against that shape rather than the old group cards."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _get(client, token, path="/software"):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def test_software_uses_one_table_with_a_decision_state_filter(client, make_token):
    source = (ROOT / "templates" / "software.html").read_text()

    assert 'class="card group-card gap-card"' in source
    # PAT-2120 Done-when: one table, no separate group cards per state.
    assert source.count('<table class="data-table software-table table-stack">') == 1
    assert 'id="group-waiting"' not in source
    assert 'id="group-not-wanted"' not in source
    assert 'id="group-approved"' not in source
    assert 'id="group-ignored"' not in source
    assert 'id="group-unrecognised"' not in source
    # PAT-2163: the five decision-state labels are now the Approval
    # dropdown's checkbox options (main.py's SOFTWARE_APPROVAL_FILTER_OPTIONS),
    # not literal text in the template source - check the rendered page.
    resp = _get(client, make_token())
    # PAT-2255: one approval vocabulary, the four states a row shows.
    for label in (
        "Unreviewed",
        "Approved",
        "Unapproved",
        "Ignored",
        "State not recognised",
    ):
        assert label in resp.text


def test_software_table_columns_share_the_established_contract():
    source = (ROOT / "templates" / "software.html").read_text()
    macros = (ROOT / "templates" / "_macros.html").read_text()
    css = (ROOT / "static" / "css" / "portal.css").read_text()

    # PAT-2163: the search box moved into the filter_bar macro - software.html
    # passes '.software-table' as the macro's search_selector argument, and
    # the macro itself wires that into data-table-search.
    assert "'.software-table'" in source
    assert 'data-table-search="{{ search_selector }}"' in macros
    assert source.count('<col class="software-col-product">') == 1
    # PAT-2070: Type/Platform are .col-secondary (hidden below 1440px, shown
    # above it); Evidence is .col-tertiary (hidden below 1680px) - the same
    # staged-reveal pattern the old inventory table used.
    assert source.count('<col class="software-col-type col-secondary">') == 1
    assert source.count('<col class="software-col-platform col-secondary">') == 1
    assert source.count('<col class="software-col-installs">') == 1
    assert source.count('<col class="software-col-evidence col-tertiary">') == 1
    assert source.count('<col class="software-col-cve">') == 1
    assert source.count('<col class="software-col-signing">') == 1
    assert source.count('<col class="software-col-actions">') == 1
    # PAT-2255: the one-line review cell shared with /homebrew.
    assert source.count("{{ review_cell(") == 1
    assert ".software-table { min-width: 900px; table-layout: fixed; }" in css


def test_software_filters_and_bulk_bar_sit_directly_above_the_table(client, make_token):
    """PAT-2120 Done-when: filters + bulk bar sit directly above the one
    table, not between two tables."""
    resp = _get(client, make_token())
    html = resp.text
    assert resp.status_code == 200
    tools_start = html.index('<section class="approval-tools"')
    table_start = html.index('<table class="data-table software-table table-stack">')
    bulk_start = html.index('id="approval-form"')
    assert tools_start < bulk_start < table_start


def test_software_explains_protected_limits_without_claiming_unprotection(client, make_token):
    response = _get(client, make_token())

    assert response.status_code == 200
    assert "not known to be protected" in response.text
    assert "never confirmed unprotected" in response.text
    assert "Extensions are never checked for protection" in response.text
