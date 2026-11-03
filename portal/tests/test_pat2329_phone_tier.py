"""PAT-2329: phones are a supported quick-look tier, not a full-parity one.

Andy's ruling of 2026-09-30. The pages in `main.PHONE_SUPPORTED_ROUTES` are
built for a 390px screen. Every other signed-in page is dense, and says so
once below 768px ("This page is best viewed on a larger screen."). The note
is drawn by portal.css from a `.page--dense` class on `<main>`, under the first
`.page-head`, so this suite pins the three things the CSS depends on: which
responses carry the class (dense pages only, never a phone-supported, signed-out
or error page), that every dense page has a direct-child `.page-head` for the
note to hang off, and that the stylesheet still shows the note under 768px and
hides it at 768px and above. The browser side is `e2e/test_pat2329_dense_note.py`.

"""

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.responses import HTMLResponse

import main
from tests.conftest import STUB_STATE

CSS = Path(__file__).resolve().parent.parent / "static" / "css" / "portal.css"
NOTE = "This page is best viewed on a larger screen."

# Andy's ruling of 2026-09-30, and the examples he named as dense. Changing the
# list is a decision to record on PAT-2329, not a test to make pass.
RULED_PHONE_ROUTES = {
    "/",
    "/software/alerts",
    "/devices/{device_id}",
    "/requests",
    "/feedback",
}
NAMED_DENSE_ROUTES = [
    "/software", "/findings", "/devices", "/devices/{device_id}/compliance",
    "/devices/{device_id}/software", "/homebrew", "/ai-tooling", "/reports", "/ce-readiness",
]

PHONE_PAGES = [
    "/", "/software/alerts", "/devices/dev-mac-001", "/requests",
    "/feedback",
]
DENSE_PAGES = [
    "/software/alerts/1",
    "/software", "/findings", "/devices", "/devices/jamf", "/devices/dev-mac-001/compliance",
    "/devices/dev-mac-001/software", "/devices/dev-mac-001/hardware", "/homebrew",
    "/ai-tooling", "/reports", "/ce-readiness", "/exceptions", "/install", "/support",
    "/whats-new", "/local-admins", "/reports/software/publishers",
]

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source",
        "track", "wbr"}


class MainChildren(HTMLParser):
    """`<main>`'s class list and its direct children, as (tag, classes) pairs."""

    def __init__(self):
        super().__init__()
        self.stack: list[str] = []
        self.main_classes: list[str] | None = None
        self.children: list[tuple[str, list[str]]] = []

    def handle_starttag(self, tag, attrs):
        classes = (dict(attrs).get("class") or "").split()
        if tag == "main" and self.main_classes is None:
            self.main_classes = classes
        elif self.main_classes is not None and self.stack and self.stack[-1] == "main":
            self.children.append((tag, classes))
        if tag not in VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        # Tolerate an omitted end tag: close back to the last matching open tag.
        if tag in self.stack:
            while self.stack.pop() != tag:
                pass


def parse_main(body: str) -> MainChildren:
    parser = MainChildren()
    parser.feed(body)
    return parser


def _get(client, path, token):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


@pytest.fixture
def token(make_token):
    value = make_token()
    STUB_STATE["expected_jwt"] = value
    STUB_STATE["feedback_enabled"] = True
    return value


def is_dense(response) -> bool:
    parsed = parse_main(response.text)
    assert parsed.main_classes is not None, "the response has no <main>"
    return "page--dense" in parsed.main_classes


# The one list


def test_the_phone_supported_list_is_the_ruled_one():
    assert main.PHONE_SUPPORTED_ROUTES == RULED_PHONE_ROUTES


def test_every_phone_supported_route_is_a_get_route_of_the_app():
    """A renamed route must not leave the list naming a page that is gone."""
    get_routes = {r.path for r in main.app.routes if "GET" in (getattr(r, "methods", None) or ())}
    assert main.PHONE_SUPPORTED_ROUTES <= get_routes


def test_the_named_dense_pages_are_not_phone_supported():
    """The device page is on the list; its tabs are not."""
    assert "/devices/{device_id}" in main.PHONE_SUPPORTED_ROUTES
    for route in NAMED_DENSE_ROUTES:
        assert route not in main.PHONE_SUPPORTED_ROUTES, route


# Which responses carry the class


@pytest.mark.parametrize("path", DENSE_PAGES)
def test_a_dense_page_is_marked_dense(client, token, path):
    response = _get(client, path, token)
    assert response.status_code == 200, path
    assert is_dense(response), path


@pytest.mark.parametrize("path", PHONE_PAGES)
def test_a_phone_supported_page_is_not_marked_dense(client, token, path):
    response = _get(client, path, token)
    assert response.status_code == 200, path
    assert not is_dense(response), path


def test_the_device_page_is_phone_supported_and_its_tabs_are_not(client, token):
    device = "/devices/dev-mac-001"
    assert not is_dense(_get(client, device, token))
    for tab in ("compliance", "software", "hardware", "vulnerabilities", "evidence"):
        assert is_dense(_get(client, f"{device}/{tab}", token)), tab


def test_the_literal_jamf_page_is_dense_although_it_fits_the_device_template(client, token):
    assert is_dense(_get(client, "/devices/jamf", token))


def test_a_signed_out_page_is_not_marked_dense(client):
    response = client.get("/software")
    assert response.status_code == 401
    assert "page--dense" not in response.text


def test_a_session_expired_page_is_not_marked_dense(client, make_token):
    STUB_STATE["mode"] = "auth401"
    response = _get(client, "/software", make_token())
    assert response.status_code == 401
    assert "page--dense" not in response.text


@pytest.mark.parametrize("mode, status", [("forbidden403", 403), ("down503", 503)])
def test_the_not_linked_and_not_enabled_pages_are_not_marked_dense(
        client, make_token, mode, status):
    STUB_STATE["mode"] = mode
    response = _get(client, "/software", make_token())
    assert response.status_code == status
    assert "page--dense" not in response.text


def test_an_error_page_on_a_dense_route_is_not_marked_dense(client, token):
    """/findings with a malformed platform payload renders error.html with the
    nav kept (PAT-888), on a route that is otherwise dense."""
    STUB_STATE["mode"] = "malformed"
    response = _get(client, "/findings", token)
    assert response.status_code != 200
    assert "Portal" in response.text  # the rail is still there, so this is a signed-in page
    assert "page--dense" not in response.text


def test_a_bad_request_error_page_on_a_dense_route_is_not_marked_dense(client, token):
    """/software/history without an item is a 400 error page, not the history page."""
    response = _get(client, "/software/history", token)
    assert response.status_code == 400
    assert "page--dense" not in response.text


# Every dense page has a heading for the note to hang off


def _path_for(route_path: str) -> str | None:
    params = re.findall(r"\{(\w+)\}", route_path)
    if not params:
        return route_path
    if route_path.startswith("/homebrew/devices/"):
        return route_path.replace("{device_id}", "hb-mac-01")
    if params == ["device_id"]:
        return route_path.replace("{device_id}", "dev-mac-001")
    if params == ["alert_id"]:
        return route_path.replace("{alert_id}", "1")
    return None


def _html_get_routes():
    for route in main.app.routes:
        if "GET" in (getattr(route, "methods", None) or ()) and getattr(
                route, "response_class", None) is HTMLResponse:
            yield route.path


def test_every_dense_html_page_has_a_direct_child_page_head_and_every_other_is_phone_supported(
        client, token):
    """The note is the first direct-child `.page-head`'s ::after. A page whose
    heading moved inside a wrapper would silently lose it; a 200 page that is
    neither dense nor on the list would silently lose the note the other way."""
    checked_dense = 0
    for route_path in sorted(set(_html_get_routes())):
        path = _path_for(route_path)
        if path is None:
            continue
        response = _get(client, path, token)
        if response.status_code != 200 or "text/html" not in response.headers["content-type"]:
            continue
        parsed = parse_main(response.text)
        if parsed.main_classes is None:
            continue
        dense = "page--dense" in parsed.main_classes
        assert dense == (route_path not in main.PHONE_SUPPORTED_ROUTES), (
            f"{route_path}: dense={dense} but phone-supported="
            f"{route_path in main.PHONE_SUPPORTED_ROUTES}")
        if dense:
            checked_dense += 1
            heads = [c for tag, c in parsed.children if "page-head" in c]
            assert heads, f"{route_path} has no direct-child .page-head for the note"
    assert checked_dense >= 25, "the sweep found too few dense pages to mean anything"


# The stylesheet


def _css_rules():
    text = re.sub(r"/\*.*?\*/", "", CSS.read_text(), flags=re.S)
    return text


def test_the_note_is_shown_under_768px_and_hidden_from_768px_up():
    css = _css_rules()
    base = re.search(
        r"\.page--dense > \.page-head::after\s*\{([^}]*)\}", css)
    assert base, "the dense-page note rule is missing from portal.css"
    assert f'content: "{NOTE}"' in base.group(1)
    assert re.search(r"display:\s*none", base.group(1)), "hidden unless the media query shows it"
    shown = re.search(
        r"@media\s*\(max-width:\s*767\.98px\)\s*\{\s*\.page--dense > \.page-head::after\s*"
        r"\{\s*display:\s*block;\s*\}\s*\}", css)
    assert shown, "the note must be shown by a max-width: 767.98px media query"


def test_only_the_first_page_head_carries_the_note():
    """install.html has three `.page-head` blocks; one note is enough."""
    css = _css_rules()
    assert re.search(
        r"\.page--dense > \.page-head ~ \.page-head::after\s*\{\s*content:\s*none;\s*\}", css)


def test_the_note_copy_is_written_once_and_has_no_em_dash():
    assert chr(0x2014) not in NOTE
    base_html = (CSS.parent.parent.parent / "templates" / "base.html").read_text()
    assert "page--dense" in base_html
    assert NOTE not in base_html, "the copy lives in portal.css only, so it is written once"
