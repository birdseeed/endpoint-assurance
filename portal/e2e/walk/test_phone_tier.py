"""PAT-2329: the walker walks 390px only on phone-supported routes.

Andy's ruling of 2026-09-30: phones are a supported quick-look tier. The
routes in `main.PHONE_SUPPORTED_ROUTES` get the full width matrix (1440 and
390 in the stub walk, 1440, 1280 and 390 in `--prod`); every other page is
dense and is walked at 1440 and 1280px. These tests cover the selection itself
(concrete path to route template, the device page against its sub-tabs), the
plan and the summary the stub walk prints, and the `--prod` progress and
summary, with no browser and no network: `run_walk` and `run_prod_walk` are
replaced where a test drives the CLI.

"""

import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from e2e.walk import walk

PHONE_ROUTES = frozenset({"/", "/devices/{device_id}", "/requests"})


@pytest.fixture(scope="module")
def portal_app():
    import main as portal_main

    return portal_main.app


@pytest.fixture(scope="module")
def templates(portal_app):
    return tuple(walk.discover_routes(portal_app))


# The one list, and where the walker reads it


def test_the_walker_reads_the_portals_own_list():
    import main as portal_main

    assert walk.phone_supported_routes() is portal_main.PHONE_SUPPORTED_ROUTES


def test_every_phone_supported_route_is_a_route_the_walk_discovers(templates):
    """A renamed route must not leave the list naming a page that is gone."""
    assert walk.phone_supported_routes() <= set(templates)


# Concrete path to route template


@pytest.mark.parametrize("path, template", [
    ("/", "/"),
    ("/devices/abc-123", "/devices/{device_id}"),
    ("/devices/abc-123?tab=x", "/devices/{device_id}"),
    ("/devices/abc/compliance", "/devices/{device_id}/compliance"),
    ("/devices/abc/software", "/devices/{device_id}/software"),
    ("/software/alerts/12", "/software/alerts/{alert_id}"),
    ("/software/alerts", "/software/alerts"),
    ("/software", "/software"),
    # The literal Jamf page wins over device "jamf", as the server routes it.
    ("/devices/jamf", "/devices/jamf"),
    # The server routes the decoded path, so an encoded slash is a boundary.
    ("/devices/abc%2Fcompliance", "/devices/{device_id}/compliance"),
    ("/ai-tooling/devices/dev-mac-001.csv", "/ai-tooling/devices/{device_id}.csv"),
])
def test_a_concrete_path_is_matched_to_its_template(templates, path, template):
    assert walk.route_template(path, templates) == template


@pytest.mark.parametrize("path", [
    "/devices/",                     # a trailing slash is a different path
    "/devices/abc/nonsense",         # right shape, wrong literal
    "/devices/abc/compliance/more",  # too many segments
    "/nope",
])
def test_a_path_that_is_no_route_matches_no_template(templates, path):
    assert walk.route_template(path, templates) is None


# The widths a route is walked at


def test_the_device_page_is_phone_supported_and_its_sub_tabs_are_not(templates):
    for prod, full in ((False, walk.WIDTHS), (True, walk.PROD_WIDTHS)):
        device = walk.route_template("/devices/abc-123", templates)
        compliance = walk.route_template("/devices/abc-123/compliance", templates)
        assert walk.widths_for_template(device, prod=prod, phone_routes=PHONE_ROUTES) == full
        dense = walk.widths_for_template(compliance, prod=prod, phone_routes=PHONE_ROUTES)
        assert dense == (1440, 1280)
        assert 390 in full and 390 not in dense


def test_a_dense_route_is_walked_without_390px():
    assert walk.widths_for_template("/software", prod=False, phone_routes=PHONE_ROUTES) == (
        1440, 1280)
    assert walk.widths_for_template("/software", prod=True, phone_routes=PHONE_ROUTES) == (
        1440, 1280)
    assert walk.widths_for_template("/requests", prod=False, phone_routes=PHONE_ROUTES) == (
        1440, 390)
    assert walk.widths_for_template("/requests", prod=True, phone_routes=PHONE_ROUTES) == (
        1440, 1280, 390)


def test_a_path_that_matches_no_route_is_dense_not_phone():
    assert walk.widths_for_template(None, prod=True, phone_routes=PHONE_ROUTES) == (1440, 1280)


@pytest.mark.parametrize("path, widths", [
    ("/", (1440, 1280, 390)),
    ("/devices/real-id-1", (1440, 1280, 390)),
    ("/devices/real-id-1?x=y", (1440, 1280, 390)),
    ("/devices/real-id-1/compliance", (1440, 1280)),
    ("/devices/jamf", (1440, 1280)),
    ("/software?type=application", (1440, 1280)),
    ("/software/alerts/9", (1440, 1280)),
    ("/not-a-route", (1440, 1280)),
])
def test_prod_widths_for_a_concrete_path(path, widths):
    assert walk.prod_widths_for_path(path) == widths


# The stub walk's plan and summary


def test_the_stub_plan_gives_each_page_its_widths(portal_app):
    plan = walk.plan_stub_walk(portal_app, ["/", "/software", "/devices/{device_id}",
                                             "/devices/{device_id}/compliance"])
    assert plan.unmatched == []
    assert plan.widths_by_route == {
        "/": (1440, 390),
        "/software": (1440, 1280),
        "/devices/dev-mac-001": (1440, 390),
        "/devices/dev-mac-001/compliance": (1440, 1280),
    }
    assert plan.page_loads == len(walk.THEMES) * (2 + 2 + 2 + 2)


def test_the_stub_plan_counts_a_concrete_device_path_like_its_template(portal_app):
    plan = walk.plan_stub_walk(portal_app, ["/devices/no-such-device",
                                             "/devices/no-such-device/compliance"])
    assert plan.widths_by_route == {
        "/devices/no-such-device": (1440, 390),
        "/devices/no-such-device/compliance": (1440, 1280),
    }


def test_the_stub_plan_follows_the_list_it_is_given(portal_app):
    plan = walk.plan_stub_walk(
        portal_app, ["/", "/software"], phone_routes=frozenset({"/software"}))
    assert plan.widths_by_route == {"/": (1440, 1280), "/software": (1440, 390)}


def test_the_whole_stub_walk_is_390px_on_the_phone_routes_and_nowhere_else(portal_app):
    plan = walk.plan_stub_walk(portal_app, None)
    phone = {p.template for p in plan.pages if 390 in p.widths}
    assert phone == walk.phone_supported_routes() & {p.template for p in plan.pages}
    assert phone, "the phone-supported routes must be walked at 390px"
    assert all(p.widths == walk.DENSE_WIDTHS for p in plan.pages if p.template not in phone)


@pytest.fixture
def stub_walk(monkeypatch):
    @contextlib.contextmanager
    def fake_stub():
        yield "http://stub.invalid"

    @contextlib.contextmanager
    def fake_harness(stub_url):
        yield "http://harness.invalid"

    monkeypatch.setattr(walk, "stub_platform_server", fake_stub)
    monkeypatch.setattr(walk, "harness_process", fake_harness)
    monkeypatch.setattr(walk, "run_walk", lambda *a, **k: [])


def test_the_stub_summary_states_each_routes_widths(capsys, tmp_path, stub_walk):
    code = walk.main(["--routes", "/,/software,/devices/dev-mac-001/compliance",
                      "--out-dir", str(tmp_path)])
    out = capsys.readouterr().out.splitlines()
    assert code == 0
    # 2 themes x (2 + 2 + 2) widths.
    assert out[0] == "0 finding(s) across 12 page loads"
    assert "widths 1440, 390: /" in out
    assert "widths 1440, 1280: /devices/dev-mac-001/compliance, /software" in out


# The prod walk's progress and summary


@pytest.fixture
def prod_walk(monkeypatch):
    monkeypatch.setenv(walk.PROD_CLIENT_ID_ENV, "local-id-placeholder")
    monkeypatch.setenv(walk.PROD_CLIENT_SECRET_ENV, "local-secret-placeholder")
    calls = []

    def fake_run_prod_walk(base_url, creds, routes, **kwargs):
        calls.append({"routes": list(routes), **kwargs})
        return []

    monkeypatch.setattr(walk, "run_prod_walk", fake_run_prod_walk)
    return calls


def test_the_prod_summary_states_each_routes_widths_and_walks_those(
        capsys, tmp_path, prod_walk):
    routes = ["/requests", "/software", "/devices/real-id-1/compliance", "/devices/real-id-1"]
    code = walk.main(["--prod", "--routes", ",".join(routes), "--out-dir", str(tmp_path)])
    out = capsys.readouterr().out.splitlines()
    assert code == 0
    # 2 themes x (3 + 2 + 2 + 3) widths.
    assert out[0] == "0 finding(s) across 20 page loads"
    assert "widths 1440, 1280, 390: /requests, /devices/real-id-1" in out
    assert "widths 1440, 1280: /software, /devices/real-id-1/compliance" in out
    # The walk is handed the very mapping the summary printed.
    assert prod_walk[0]["widths"] == {
        "/requests": (1440, 1280, 390),
        "/software": (1440, 1280),
        "/devices/real-id-1/compliance": (1440, 1280),
        "/devices/real-id-1": (1440, 1280, 390),
    }


@pytest.fixture
def portal():
    """A local 'portal' that answers 200 to anything (no network)."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html><body><p>Overview</p></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


def test_the_prod_route_loop_walks_and_names_the_widths_of_each_route(
        monkeypatch, browser, portal, tmp_path):
    """The real route loop, with the page load itself replaced, records which
    widths it walks and what its progress lines say."""
    seen = []

    def record(context, base_url, url, route, theme, width, *args, **kwargs):
        seen.append((route, width))
        return []

    monkeypatch.setattr(walk, "_walk_one", record)
    messages = []
    walk.walk_prod_routes(
        browser, portal, walk.ProdCredentials("id-placeholder", "secret-placeholder"),
        ["/requests", "/software"], tmp_path, pacing=walk.Pacing(),
        progress=messages.append)
    assert sorted(set(seen)) == [
        ("/requests", 390), ("/requests", 1280), ("/requests", 1440),
        ("/software", 1280), ("/software", 1440)]
    assert any("/requests" in m and "widths 1440, 1280, 390" in m for m in messages), messages
    assert any("/software" in m and "widths 1440, 1280," in m and "390" not in m
               for m in messages), messages


def test_the_stub_plan_classifies_decoded_paths_but_loads_the_path_as_given(portal_app):
    path = "/devices/dev-mac-001%2Fcompliance"
    plan = walk.plan_stub_walk(portal_app, [path])
    assert plan.unmatched == []
    assert [(page.template, page.route, page.widths) for page in plan.pages] == [
        ("/devices/{device_id}/compliance", path, (1440, 1280))]
