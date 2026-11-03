"""PAT-2185: grouped, icon-led rail retained after PAT-2022 went live."""

import re


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def test_ai_tooling_requires_auth(client):
    assert client.get("/ai-tooling").status_code == 401


def test_ai_tooling_is_truthful_and_active(client, make_token):
    response = _get(client, make_token(), "/ai-tooling")
    assert response.status_code == 200
    body = response.text
    assert "In development" not in body
    assert "presence, version and configuration shape only" in body
    for excluded in ("prompts", "chat history", "model output", "file contents",
                     "keys", "MCP arguments", "environment values"):
        assert excluded in body
    assert "coming soon" not in body.lower()
    active_ai = (
        'href="/ai-tooling" '
        'class="rail__item rail__item--primary active"'
    )
    assert active_ai in body


def test_rail_links_every_destination_with_hidden_outline_icon(client, make_token):
    body = _get(client, make_token(), "/").text
    nav = re.search(r'<nav class="rail__nav"[^>]*>(.*?)</nav>', body, re.DOTALL).group(1)
    links = re.findall(r'(<a href="[^"]+" class="rail__item[^"]*">.*?</a>)', nav, re.DOTALL)
    assert len(links) == 14
    for link in links:
        assert '<svg class="rail__icon" aria-hidden="true" focusable="false"' in link
        assert "<span>" in link


def test_rail_sections_are_labelled_and_primary_items_are_distinct(client, make_token):
    body = _get(client, make_token(), "/").text
    nav = re.search(r'<nav class="rail__nav"[^>]*>(.*?)</nav>', body, re.DOTALL).group(1)
    for label in ("Your estate", "Governance", "Operations"):
        assert f'>{label}</h2>' in nav
    for path in ("/", "/software/alerts", "/devices", "/findings", "/software",
                 "/ai-tooling"):
        assert re.search(rf'href="{re.escape(path)}" class="rail__item rail__item--primary', nav)
    assert "<span>AI Tooling</span></a>" in nav
    assert "rail__status" not in re.search(
        r'<a href="/ai-tooling".*?</a>', nav, re.DOTALL).group(0)
