"""PAT-2130: the 19 Sept 2026 reset made Patched a one-plan self-service
product (24 Sept revision comment on PAT-1602) - no Assurance/Managed tier
shown to customers, no Patched "specialist" acting for the customer, no
specialist-time drawdown. This test renders every page the test harness can
render and fails if any of that retired vocabulary leaks into the visible
page text.

Only one theme render is needed: the light/dark toggle (templates/base.html)
is applied entirely client-side (an inline script sets [data-theme] from
localStorage/prefers-color-scheme before paint, and portal.css keys off that
attribute) - the server always renders identical HTML and CSS custom
properties regardless of theme, so there is no separate server-rendered
theme variant to check.
"""

from html.parser import HTMLParser

from tests.conftest import OVERVIEW, STUB_STATE
from tests.test_portal_review_2026_09_24 import PAGES

# Case-sensitive for the two retired proper-noun tier names (a lowercase
# "assurance" is the product word - "Endpoint Assurance", "assurance
# evidence", assurance_csv_value - and must not trip this). Case-insensitive
# for specialist/drawdown, which have no legitimate lowercase product sense
# in this portal.
CASE_SENSITIVE_TERMS = ("Assurance", "Managed")
CASE_INSENSITIVE_TERMS = ("specialist", "drawdown")

# Content never shown to a customer (script/style bodies, and anything
# under an explicit data-walker-ignore marker) is excluded from the text
# walk below.
_SKIP_TAGS = {"script", "style"}


class _VisibleTextWalker(HTMLParser):
    """Collects rendered text, dropping <script>/<style> bodies and any
    subtree rooted at an element carrying data-walker-ignore."""

    def __init__(self):
        super().__init__()
        self.chunks = []
        self._skip_depth = 0
        self._skip_tag_stack = []

    def handle_starttag(self, tag, attrs):
        attr_names = {name for name, _ in attrs}
        ignored = "data-walker-ignore" in attr_names
        if self._skip_depth or ignored or tag in _SKIP_TAGS:
            self._skip_depth += 1
        self._skip_tag_stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        pass  # self-closing tags (e.g. <br/>) carry no text either way

    def handle_endtag(self, tag):
        if self._skip_tag_stack and self._skip_tag_stack[-1] == tag:
            self._skip_tag_stack.pop()
        if self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data):
        if not self._skip_depth:
            self.chunks.append(data)

    def visible_text(self):
        return "".join(self.chunks)


def _visible_text(html):
    walker = _VisibleTextWalker()
    walker.feed(html)
    return walker.visible_text()


def _get(client, token, path):
    STUB_STATE["expected_jwt"] = token
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _assert_clean(path, visible):
    for term in CASE_SENSITIVE_TERMS:
        assert term not in visible, f"{path}: found retired tier name {term!r}"
    lowered = visible.lower()
    for term in CASE_INSENSITIVE_TERMS:
        assert term not in lowered, f"{path}: found retired term {term!r}"


def test_no_tier_or_specialist_copy(client, make_token):
    token = make_token()

    # Force the historical tier-bearing overview shape (the platform used
    # to send `tier` before the 19 Sept reset) so a lingering tier chip -
    # or any other latent tier rendering - has something to leak, rather
    # than testing only the case where the field is already absent.
    STUB_STATE["overview_data"] = {**OVERVIEW, "tier": "Managed"}

    for path in PAGES:
        resp = _get(client, token, path)
        assert resp.status_code == 200, path
        visible = _visible_text(resp.text)
        _assert_clean(path, visible)
