"""Andy's 24 Sept 2026 portal review: rail order, footer, and no
"specialist" wording anywhere a customer can read it (Patched is a
self-service assurance product since the 19 Sept reset)."""

import re

from tests.conftest import STUB_STATE

PAGES = ["/", "/devices", "/devices/dev-mac-001", "/findings", "/software",
         "/software/alerts", "/homebrew", "/exceptions", "/reports", "/install",
         "/ai-tooling", "/support"]


def _get(client, token, path):
    STUB_STATE["expected_jwt"] = token
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def test_rail_groups_destinations_without_orphaning_routes(client, make_token):
    body = _get(client, make_token(), "/").text
    nav = re.search(r'<nav class="rail__nav"[^>]*>(.*?)</nav>', body, re.DOTALL).group(1)
    assert all(label in nav for label in ("Your estate", "Governance", "Operations"))
    paths = re.findall(r'href="([^"]+)"', nav)
    assert paths == ["/", "/software/alerts", "/devices", "/findings", "/software",
                     "/ai-tooling", "/ce-readiness", "/exceptions", "/homebrew",
                     "/local-admins", "/certificates", "/reports", "/install", "/support?route=/"]


def test_no_customer_facing_page_mentions_a_specialist(client, make_token):
    token = make_token()
    for path in PAGES:
        resp = _get(client, token, path)
        assert resp.status_code == 200, path
        visible = re.sub(r'class="[^"]*"', "", resp.text)
        assert "specialist" not in visible.lower(), path


def test_portal_footer_has_no_marketing_links_or_read_only_note(client, make_token):
    body = _get(client, make_token(), "/").text
    footer = re.search(r"<footer.*?</footer>", body, re.DOTALL).group(0)
    assert "patched.im/blog" not in footer
    assert "Read-only view of your estate" not in footer
