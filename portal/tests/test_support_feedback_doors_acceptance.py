"""Support/Feedback door acceptance through real middleware, routes and templates.

Only the loopback platform stub changes: it implements the deployed door list
contract and records traffic. No portal handler or availability helper is mocked.
Device context uses the existing tenant-scoped device read and route wire field;
the platform intake has no device_id, kind or support_category field.
"""

import html
from email.parser import BytesParser
from email.policy import default
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

import main
from tests.conftest import STUB_STATE, StubPlatformHandler
from tests.test_pat2257_service_identity import make_service_token, service_on  # noqa: F401


class Page(HTMLParser):
    """Collect actual rendered controls and links without template assumptions."""

    def __init__(self, markup):
        super().__init__()
        self.forms = []
        self.links = []
        self.options = []
        self.selected = {}
        self.form = None
        self.select = None
        self.feed(markup)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.form = {"attrs": attrs, "controls": []}
            self.forms.append(self.form)
        elif tag in {"input", "textarea", "select"} and self.form is not None:
            self.form["controls"].append(attrs)
        if tag == "select":
            self.select = attrs.get("name")
        elif tag == "option":
            self.options.append((self.select, attrs.get("value")))
            if "selected" in attrs:
                self.selected[self.select] = attrs.get("value")
        elif tag == "a":
            self.links.append(attrs)

    def handle_endtag(self, tag):
        if tag == "form":
            self.form = None
        elif tag == "select":
            self.select = None

    def post_form(self, action):
        forms = [f for f in self.forms if f["attrs"].get("action") == action
                 and f["attrs"].get("method", "get").lower() == "post"]
        assert len(forms) == 1, f"Expected one usable POST form for {action}"
        return forms[0]

    def values(self, name):
        return {value for field, value in self.options if field == name}


@pytest.fixture
def intake(client, make_token, monkeypatch, stub_platform):
    """Capture real HTTP, filter lists just as the already deployed API does."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["feedback_enabled"] = True
    seen = []
    original_get = StubPlatformHandler.do_GET
    original_send = requests.sessions.Session.send

    def local_send(session, request, **kwargs):
        assert urlsplit(request.url).netloc == urlsplit(stub_platform).netloc
        seen.append((request.method, request.url, dict(request.headers)))
        return original_send(session, request, **kwargs)

    def get(handler):
        parsed = urlsplit(handler.path)
        door = parse_qs(parsed.query).get("door", [""])[0]
        if parsed.path != "/v1/portal/feedback" or not door:
            return original_get(handler)
        if handler._fail_if_wrong_jwt():
            return
        if not STUB_STATE["feedback_enabled"] or STUB_STATE["feedback_status"]:
            return original_get(handler)
        if door not in {"support", "feedback"}:
            return handler._send(400, {"error": "invalid_feedback"})
        types = {"support", "bug", "question"} if door == "support" else {"feature", "design"}
        rows = [row for row in STUB_STATE["feedback_rows"] if row["type"] in types]
        STUB_STATE["feedback_gets"] += 1
        handler._send(200, rows)

    monkeypatch.setattr(requests.sessions.Session, "send", local_send)
    monkeypatch.setattr(StubPlatformHandler, "do_GET", get)
    return token, seen


def headers(token, *, json=False):
    return {"Cf-Access-Jwt-Assertion": token, "Origin": "https://testserver",
            "Accept": "application/json" if json else "text/html"}


def form(token, door, **changes):
    data = {"csrf_token": main._csrf_token(token), "description": "Please help <b>with this</b>.",
            "route": "/devices"}
    if door == "support":
        data.update(type="support", category="not_working")
    else:
        data.update(type="feature", title="An easier export filter")
    data.update(changes)
    return {key: value for key, value in data.items() if value is not None}


def parts():
    post = STUB_STATE["feedback_posts"][-1]
    raw = b"Content-Type: " + post["content_type"].encode() + b"\r\n\r\n" + post["body"]
    message = BytesParser(policy=default).parsebytes(raw)
    return {part.get_param("name", header="content-disposition"): part
            for part in message.iter_parts()}


def text_part(fields, name):
    return fields[name].get_payload(decode=True).decode()


def test_support_slim_form_email_fallback_and_response_aim(client, intake):
    token, _ = intake
    response = client.get("/support", headers=headers(token))
    assert response.status_code == 200
    page = Page(response.text)
    support = page.post_form("/support")
    controls = {c.get("name"): c for c in support["controls"]}
    assert {"csrf_token", "category", "description", "screenshot"} <= controls.keys()
    assert page.values("category") == {"not_working", "findings_or_reports", "account_billing"}
    assert "title" not in controls or "required" not in controls["title"]
    assert controls["screenshot"]["accept"] == "image/png,image/jpeg"
    assert "required" not in controls["screenshot"]
    assert any(a.get("href", "").startswith("mailto:") for a in page.links)
    assert "one business day" in response.text
    assert "5 MiB" in response.text
    assert "team that runs your service" not in response.text
    assert "not a ticket queue" not in response.text


@pytest.mark.parametrize("path", ["/devices", "/feedback"])
def test_modal_and_no_script_feedback_offer_only_feature_and_design(client, intake, path):
    token, _ = intake
    response = client.get(path, headers=headers(token))
    assert response.status_code == 200
    page = Page(response.text)
    feedback = page.post_form("/feedback")
    assert page.values("type") == {"feature", "design"}
    assert not any(c.get("name") in {"severity", "category"} for c in feedback["controls"])
    if path == "/devices":
        assert 'id="feedback-dialog"' in response.text
        assert any("data-feedback-open" in a and a.get("href", "").startswith("/feedback")
                   for a in page.links)
    else:
        assert 'id="feedback-dialog"' not in response.text


def test_navigation_has_one_feedback_list_and_retains_certificates(client, intake):
    token, _ = intake
    page = client.get("/devices", headers=headers(token)).text
    assert "My requests" not in page
    links = Page(page).links
    rail = [a for a in links if "rail__item" in a.get("class", "")]
    assert any(a.get("href") == "/requests" for a in rail)
    assert any(a.get("href") == "/certificates" for a in rail)
    assert not any(a.get("href") == "/requests" for a in links if a not in rail)


@pytest.mark.parametrize("door,path,types", [
    ("support", "/support", {"support", "bug", "question"}),
    ("feedback", "/requests", {"feature", "design"}),
])
def test_each_list_requests_exact_door_and_displays_open_and_closed_rows(
        client, intake, door, path, types):
    token, seen = intake
    STUB_STATE["feedback_rows"] = [
        {"reference": f"FB-{i}", "type": kind, "title": f"Owned {kind} {state}",
         "status": state, "created_at": "2026-09-30T12:00:00Z"}
        for i, (kind, state) in enumerate((kind, state)
        for kind in ["support", "bug", "question", "feature", "design"]
        for state in ["received", "closed_merged"])
    ]
    response = client.get(path, headers=headers(token))
    assert response.status_code == 200
    queries = [parse_qs(urlsplit(url).query) for method, url, _ in seen
               if method == "GET" and urlsplit(url).path == "/v1/portal/feedback"]
    assert {"door": [door]} in queries, "The business list must request its canonical API door"
    for row in STUB_STATE["feedback_rows"]:
        assert (row["title"] in response.text) == (row["type"] in types)
    assert "Received" in response.text and "Closed" in response.text


@pytest.mark.parametrize("category", ["not_working", "findings_or_reports", "account_billing"])
def test_support_description_only_posts_canonical_intake_and_lands_on_support(
        client, intake, category):
    token, seen = intake
    response = client.post("/support", data=form(token, "support", category=category),
                           headers=headers(token), follow_redirects=False)
    assert response.status_code == 303, response.text[:250]
    assert urlsplit(response.headers["location"]).path == "/support"
    fields = parts()
    assert text_part(fields, "type") == "support"
    assert text_part(fields, "category") == category
    assert text_part(fields, "description") == form(token, "support")["description"]
    assert 5 <= len(text_part(fields, "title")) <= 120
    assert set(fields) <= {"type", "category", "title", "description", "route", "screenshot"}
    posts = [(url, h) for method, url, h in seen if method == "POST"]
    assert len(posts) == 1 and urlsplit(posts[0][0]).path == "/v1/portal/feedback"
    assert posts[0][1]["Cf-Access-Jwt-Assertion"] == token


@pytest.mark.parametrize("kind", ["feature", "design"])
@pytest.mark.parametrize("severity", [None, "cosmetic"])
def test_feedback_types_succeed_without_forwarding_stale_bug_severity(
        client, intake, kind, severity):
    token, seen = intake
    response = client.post(
        "/feedback", data=form(token, "feedback", type=kind, severity=severity),
                           headers=headers(token), follow_redirects=False)
    assert response.status_code == 303, response.text[:250]
    assert urlsplit(response.headers["location"]).path == "/requests"
    fields = parts()
    assert text_part(fields, "type") == kind
    assert not {"severity", "category", "tenant_id", "actor", "kind"} & fields.keys()
    assert any(method == "POST" and h["Cf-Access-Jwt-Assertion"] == token
               for method, _, h in seen)


@pytest.mark.parametrize("path,changes", [
    ("/feedback", {"type": "bug", "severity": "cosmetic"}),
    ("/feedback", {"type": "question"}),
    ("/feedback", {"type": "support", "category": "not_working"}),
    ("/feedback", {"type": "feature", "category": "not_working"}),
    ("/feedback", {"type": "unknown"}),
    ("/support", {"type": "feature"}),
    ("/support", {"category": "unknown"}),
    ("/support", {"category": ""}),
])
def test_invalid_door_type_category_refused_before_intake(client, intake, path, changes):
    token, _ = intake
    data = form(token, "support" if path == "/support" else "feedback", **changes)
    response = client.post(path, data=data, headers=headers(token, json=True))
    assert response.status_code in {400, 422}, response.text[:250]
    assert STUB_STATE["feedback_posts"] == []


@pytest.mark.parametrize("door,path,kind", [("support", "/support", "support"),
                                          ("feedback", "/feedback", "feature"),
                                          ("feedback", "/feedback", "design")])
@pytest.mark.parametrize("failure", ["expired", "unavailable", "disabled"])
def test_failures_preserve_escaped_draft_and_expired_csrf_can_retry(
        client, intake, door, path, kind, failure):
    token, _ = intake
    data = form(token, door, type=kind)
    if failure == "expired":
        data["csrf_token"] = "0" * 64
    else:
        STUB_STATE["feedback_post_status"] = 503 if failure == "unavailable" else 404
    response = client.post(path, data=data, headers=headers(token), follow_redirects=False)
    assert response.status_code == (403 if failure == "expired" else 502), response.text[:250]
    assert html.escape(data["description"]) in response.text
    assert "<b>with this</b>" not in response.text
    draft_page = Page(response.text)
    draft = draft_page.post_form(path)
    if door == "feedback":
        assert draft_page.selected["type"] == kind
        assert html.escape(data["title"]) in response.text
    else:
        assert draft_page.selected["category"] == data["category"]
    controls = {c.get("name"): c for c in draft["controls"]}
    assert controls["csrf_token"]["value"] == main._csrf_token(token)
    if failure == "expired":
        assert STUB_STATE["feedback_posts"] == []
        data["csrf_token"] = controls["csrf_token"]["value"]
        retry = client.post(path, data=data, headers=headers(token), follow_redirects=False)
        assert retry.status_code == 303
    else:
        assert any(word in response.text.lower() for word in ["unavailable", "could not", "cannot"])


@pytest.mark.parametrize("path", ["/support", "/feedback"])
@pytest.mark.parametrize("bad", ["origin", "csrf", "file_type", "file_size"])
def test_private_bounded_upload_guards_refuse_before_upstream(client, intake, path, bad):
    token, _ = intake
    data = form(token, "support" if path == "/support" else "feedback")
    h = headers(token, json=True)
    files = None
    if bad == "origin":
        h["Origin"] = "https://evil.example"
    elif bad == "csrf":
        data["csrf_token"] = ""
    elif bad == "file_type":
        files = {"screenshot": ("private.txt", b"private", "text/plain")}
    else:
        files = {"screenshot": ("large.png", b"x" * (5 * 1024 * 1024 + 1), "image/png")}
    response = client.post(path, data=data, files=files, headers=h)
    expected = 403 if bad in {"origin", "csrf"} else 422 if bad == "file_type" else 413
    assert response.status_code == expected, response.text[:250]
    assert STUB_STATE["feedback_posts"] == []


@pytest.mark.parametrize("mime,filename,raw", [
    ("image/png", "small.png", b"\x89PNG\r\n\x1a\n"),
    ("image/jpeg", "small.jpg", b"\xff\xd8\xff\xd9"),
])
def test_support_optional_screenshot_uses_existing_multipart_boundary(
        client, intake, mime, filename, raw):
    # The backend, not the portal, decodes/re-encodes image bytes. These are
    # transport controls, not proof that the API accepts an invalid image.
    token, _ = intake
    response = client.post("/support", data=form(token, "support"),
                           files={"screenshot": (filename, raw, mime)},
                           headers=headers(token), follow_redirects=False)
    assert response.status_code == 303, response.text[:250]
    shot = parts()["screenshot"]
    assert shot.get_content_type() == mime
    assert shot.get_payload(decode=True) == raw


def test_support_device_context_is_read_from_tenant_scoped_existing_view(client, intake):
    token, seen = intake
    path = "/devices/dev-mac-001"
    response = client.get("/support", params={"route": path}, headers=headers(token))
    assert response.status_code == 200
    fields = Page(response.text).post_form("/support")["controls"]
    assert any(c.get("name") == "route" and c.get("value") == path for c in fields)
    assert any(method == "GET" and urlsplit(url).path == "/v1/portal/devices/dev-mac-001"
               for method, url, _ in seen), "Device provenance requires the existing scoped read"
    assert "acme-mbp-frontdesk" in response.text


@pytest.mark.parametrize("route", ["https://evil.example/", "//evil.example/", "/invented"])
def test_support_never_presents_unvalidated_route_as_context(client, intake, route):
    token, _ = intake
    response = client.get("/support", params={"route": route}, headers=headers(token))
    assert response.status_code in {200, 400, 422}
    if response.status_code == 200:
        controls = Page(response.text).post_form("/support")["controls"]
        assert not any(c.get("name") == "route" and c.get("value") == route for c in controls)


@pytest.mark.parametrize("path", ["/support", "/feedback"])
def test_service_readonly_denies_door_writes_before_any_intake(
        client, intake, service_on, make_service_token, path):  # noqa: F811
    token = make_service_token()
    response = client.post(path, data=form(token, "support" if path == "/support" else "feedback"),
                           headers=headers(token))
    assert response.status_code == 403
    assert "read-only" in response.text
    assert STUB_STATE["feedback_posts"] == []


@pytest.mark.parametrize("path", ["/support", "/feedback"])
@pytest.mark.parametrize("description", ["", "x" * 5001], ids=["empty", "too_long"])
def test_description_is_required_and_bounded(client, intake, path, description):
    token, _ = intake
    response = client.post(path,
                           data=form(token, "support" if path == "/support" else "feedback",
                                     description=description),
                           headers=headers(token, json=True))
    assert response.status_code == 422
    assert STUB_STATE["feedback_posts"] == []


def test_client_identity_fields_cannot_reach_canonical_feedback_intake(client, intake):
    token, _ = intake
    data = form(token, "feedback", tenant_id="untrusted-tenant", actor="untrusted-actor")
    response = client.post("/feedback", data=data, headers=headers(token, json=True))
    assert response.status_code == 201, response.text[:250]
    fields = parts()
    assert not {"tenant_id", "actor", "reporter_email", "jwt"} & fields.keys()
    assert text_part(fields, "type") == "feature"


def test_support_entry_from_device_page_keeps_context_without_javascript(client, intake):
    token, _ = intake
    path = "/devices/dev-mac-001"
    device = client.get(path, headers=headers(token))
    assert device.status_code == 200
    links = [a["href"] for a in Page(device.text).links
             if urlsplit(a.get("href", "")).path == "/support"
             and parse_qs(urlsplit(a["href"]).query).get("route") == [path]]
    assert links, "Opening Support from a device must retain its validated route context"
    support = client.get(links[0], headers=headers(token))
    assert support.status_code == 200
    controls = Page(support.text).post_form("/support")["controls"]
    assert any(c.get("name") == "route" and c.get("value") == path for c in controls)
    assert "acme-mbp-frontdesk" in support.text
