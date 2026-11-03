"""PAT-2300: a `--routes` filter that walks nothing must never read as clean.

`--routes /devices/dev-mac-001/compliance` used to be matched against route
TEMPLATES (`/devices/{device_id}/compliance`), matched nothing, walked zero
pages and printed "0 finding(s)" with exit 0: the same output as a clean page.
These tests hold the three fixes without a browser, the stub servers or the
network:

  * a filter that matches no route fails with its own exit code and names it;
  * a concrete path is matched to its template, segment by segment, and is
    walked with the values it names;
  * the summary line says how many page loads it covers.

The walk itself (a real Chromium against the stub portal) is exercised by
running `python e2e/walk/walk.py --routes ...` by hand; the CLI here runs with
`run_walk` and the stub servers replaced.
"""

from __future__ import annotations

import contextlib

import pytest

from e2e.walk import walk

CONCRETE = "/devices/dev-mac-001/compliance"
TEMPLATE = "/devices/{device_id}/compliance"
# The exit codes the walker already uses: clean, findings, bad arguments or
# missing credentials, a stopped prod walk, an interrupted one.
CODES_ALREADY_IN_USE = {0, 1, 2, 3, 130}
# Placeholders for the fake prod credentials; never real values.
FAKE_ID = "local-id-placeholder"
FAKE_SECRET = "local-secret-placeholder"


@pytest.fixture(scope="module")
def portal_app():
    import main as portal_main

    return portal_main.app


@pytest.fixture
def stub_walk_calls(monkeypatch):
    """The stub walk's CLI without its servers or its browser. The list
    records what `run_walk` was asked to walk; a test that expects the walk
    to be refused asserts it stays empty."""

    @contextlib.contextmanager
    def fake_stub():
        yield "http://stub.invalid"

    @contextlib.contextmanager
    def fake_harness(stub_url):
        yield "http://harness.invalid"

    calls: list[list[str] | None] = []

    def fake_run_walk(harness_url, app, routes_filter=None, out_dir=walk.OUT_DIR):
        calls.append(routes_filter)
        return []

    monkeypatch.setattr(walk, "stub_platform_server", fake_stub)
    monkeypatch.setattr(walk, "harness_process", fake_harness)
    monkeypatch.setattr(walk, "run_walk", fake_run_walk)
    return calls


@pytest.fixture
def prod_walk_calls(monkeypatch):
    """The same for `--prod`: no credentials needed from the environment, no
    browser. Records the routes `run_prod_walk` was asked to walk."""
    monkeypatch.setenv(walk.PROD_CLIENT_ID_ENV, FAKE_ID)
    monkeypatch.setenv(walk.PROD_CLIENT_SECRET_ENV, FAKE_SECRET)
    calls: list[list[str]] = []

    def fake_run_prod_walk(base_url, creds, routes, **kwargs):
        calls.append(list(routes))
        return []

    monkeypatch.setattr(walk, "run_prod_walk", fake_run_prod_walk)
    return calls


# (a) A filter that matches nothing fails, and says which one


def test_a_filter_matching_nothing_exits_non_zero_and_names_it(
        capsys, tmp_path, stub_walk_calls):
    code = walk.main(["--routes", "/nonexistent", "--out-dir", str(tmp_path)])
    output = capsys.readouterr()
    assert code not in (0, 1), "a walk of nothing must not read as clean or as findings"
    assert code not in CODES_ALREADY_IN_USE
    assert "/nonexistent" in output.err
    assert "0 finding(s)" not in output.out
    assert stub_walk_calls == [], "nothing may be walked for a filter that matched nothing"


def test_one_bad_filter_among_good_ones_fails_and_names_only_the_bad_one(
        capsys, tmp_path, stub_walk_calls):
    code = walk.main(["--routes", f"/,{CONCRETE},/devcies,/nope", "--out-dir", str(tmp_path)])
    output = capsys.readouterr()
    assert code not in CODES_ALREADY_IN_USE
    assert "/devcies" in output.err and "/nope" in output.err
    assert CONCRETE not in output.err
    assert stub_walk_calls == [], "a typo must not quietly shrink the walk"


def test_the_error_says_what_a_filter_may_be(capsys, tmp_path, stub_walk_calls):
    walk.main(["--routes", "/devices?view=quiet", "--out-dir", str(tmp_path)])
    err = capsys.readouterr().err
    assert "/devices?view=quiet" in err
    assert "concrete path" in err and "query" in err


def test_a_walk_of_zero_pages_never_confirms_a_fingerprint_fixed(
        monkeypatch, capsys, tmp_path, stub_walk_calls):
    """`--fingerprint` exits 0 when the finding does not reproduce. A walk that
    visited nothing must not be able to say that (here: a template with no
    fixture id, so it matches a route but has no page to load)."""
    monkeypatch.setattr(walk, "FIXTURE_PARAMS", {})
    code = walk.main(["--routes", TEMPLATE, "--fingerprint", "wk-break-x-1440-light",
                      "--out-dir", str(tmp_path)])
    assert code not in (0, 1)
    assert code not in CODES_ALREADY_IN_USE
    assert "no page" in capsys.readouterr().err.lower()


# (b) A concrete path is matched to its template and walked as given


def test_a_concrete_path_resolves_to_its_template(portal_app):
    plan = walk.plan_stub_walk(portal_app, [CONCRETE])
    assert plan.unmatched == []
    assert [(p.template, p.route) for p in plan.pages] == [(TEMPLATE, CONCRETE)]
    assert plan.findings == []


def test_a_concrete_path_is_walked_with_its_own_ids_so_a_404_is_a_finding(portal_app):
    """An id the stub does not serve is still walked, not swapped for the
    fixture id and not skipped: the page's 404 is then a real `status` finding."""
    plan = walk.plan_stub_walk(portal_app, ["/devices/no-such-device/compliance"])
    assert plan.unmatched == []
    assert [p.route for p in plan.pages] == ["/devices/no-such-device/compliance"]


def test_a_template_filter_still_takes_its_fixture_id(portal_app):
    plan = walk.plan_stub_walk(portal_app, [TEMPLATE])
    assert [(p.template, p.route) for p in plan.pages] == [(TEMPLATE, CONCRETE)]


def test_a_param_with_a_suffix_matches_by_segment(portal_app):
    plan = walk.plan_stub_walk(portal_app, ["/ai-tooling/devices/dev-mac-001.csv"])
    assert plan.unmatched == []
    assert [(p.template, p.route) for p in plan.pages] == [
        ("/ai-tooling/devices/{device_id}.csv", "/ai-tooling/devices/dev-mac-001.csv")]


def test_a_literal_route_wins_over_a_param_route_that_would_also_match(portal_app):
    """`/devices/jamf` fits `/devices/{device_id}` too; the server routes it to
    the Jamf page, so that is the page the walk visits."""
    templates = walk.discover_routes(portal_app)
    assert "/devices/jamf" in templates and "/devices/{device_id}" in templates
    plan = walk.plan_stub_walk(portal_app, ["/devices/jamf"])
    assert [(p.template, p.route) for p in plan.pages] == [("/devices/jamf", "/devices/jamf")]


@pytest.mark.parametrize("wanted", [
    "/devices/dev-mac-001/compliance/extra",   # too many segments
    "/devices//compliance",                    # an empty segment is not a value
    "devices/dev-mac-001/compliance",          # no leading slash
    "/devices/dev-mac-001/compliance/",        # trailing slash is a different path
    "/devices/dev-mac-001/nonsense",           # right shape, wrong literal
    "/devices/dev-mac-001?view=quiet",         # query strings are not matched
    "/devices/{id}/compliance",                # a misspelt template is not an id
])
def test_segments_must_line_up_exactly(portal_app, wanted):
    plan = walk.plan_stub_walk(portal_app, [wanted])
    assert plan.unmatched == [wanted]
    assert plan.pages == []


def test_a_shorter_concrete_path_matches_the_shorter_template(portal_app):
    plan = walk.plan_stub_walk(portal_app, ["/devices/dev-mac-001"])
    assert [(p.template, p.route) for p in plan.pages] == [
        ("/devices/{device_id}", "/devices/dev-mac-001")]


def test_two_filters_for_one_page_walk_it_once(portal_app):
    plan = walk.plan_stub_walk(portal_app, [CONCRETE, TEMPLATE])
    assert [p.route for p in plan.pages] == [CONCRETE]


def test_no_filter_walks_every_route_as_before(portal_app):
    plan = walk.plan_stub_walk(portal_app, None)
    assert plan.unmatched == []
    templates = walk.discover_routes(portal_app)
    walked = {p.template for p in plan.pages}
    reported = {f.route for f in plan.findings}
    assert walked | reported == set(templates)


def test_run_walk_refuses_an_unmatched_filter_rather_than_walking_less(portal_app):
    with pytest.raises(walk.RouteFilterError) as exc:
        walk.run_walk("http://harness.invalid", portal_app, routes_filter=["/nonexistent"])
    assert "/nonexistent" in str(exc.value)


# (c) The summary states how many page loads it covers


def test_the_summary_line_states_the_page_count():
    assert walk._summarise([], 24).splitlines()[0] == "0 finding(s) across 24 page loads"
    assert walk._summarise([], 0).splitlines()[0] == "0 finding(s) across 0 page loads"


def test_the_stub_walk_prints_the_page_count(capsys, tmp_path, stub_walk_calls):
    code = walk.main(["--routes", CONCRETE, "--out-dir", str(tmp_path)])
    out = capsys.readouterr().out
    # A device's Compliance tab is a dense page: no 390px width (PAT-2329).
    pages = len(walk.THEMES) * len(walk.DENSE_WIDTHS)
    assert code == 0
    assert f"0 finding(s) across {pages} page loads" in out
    assert stub_walk_calls == [[CONCRETE]]


# The prod walk keeps its concrete paths, gains the page count, and cannot walk nothing


def test_the_prod_walk_takes_concrete_paths_as_given_and_prints_the_page_count(
        capsys, tmp_path, prod_walk_calls):
    code = walk.main(["--prod", "--routes", "/devices/real-id-1/compliance",
                      "--out-dir", str(tmp_path)])
    out = capsys.readouterr().out
    # A dense page again (PAT-2329): 1440 and 1280, no 390px.
    pages = len(walk.THEMES) * len(walk.PROD_DENSE_WIDTHS)
    assert code == 0
    assert prod_walk_calls == [["/devices/real-id-1/compliance"]]
    assert f"0 finding(s) across {pages} page loads" in out


def test_a_prod_walk_left_with_no_route_to_visit_fails(capsys, tmp_path, prod_walk_calls):
    code = walk.main(["--prod", "--routes", "/cdn-cgi/access/logout", "--out-dir", str(tmp_path)])
    output = capsys.readouterr()
    assert code not in CODES_ALREADY_IN_USE
    assert prod_walk_calls == []
    assert "0 finding(s)" not in output.out
    assert "no page" in output.err.lower()
