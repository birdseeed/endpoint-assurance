"""PAT-2303: no ticket wording or "--" in customer copy on two pages.

/reports/software/duplicate-tools renders the platform's standing caveat
verbatim (`basis.statement`). The platform's wording is fixed at its source, so
the page must carry neither "ticket" nor "--" in anything a customer reads.

/support no longer carries the retired managed-service sentence or an
exception to the customer-copy walker.
"""

from html.parser import HTMLParser

from tests.conftest import STUB_STATE


class _VisibleText(HTMLParser):
    """Text nodes a reader meets: no <script>/<style>, no comments. Each is
    kept with whether it sits inside a `data-walker-ignore` element."""

    SKIP = {"script", "style", "noscript", "template"}
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
            "source", "track", "wbr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, bool]] = []
        self.nodes: list[tuple[str, bool]] = []

    def handle_starttag(self, tag, attrs):
        if tag in self.VOID:
            return
        ignored = any(name == "data-walker-ignore" for name, _ in attrs)
        self.stack.append((tag, ignored))

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                return

    def handle_data(self, data):
        if not data.strip():
            return
        if any(tag in self.SKIP for tag, _ in self.stack):
            return
        self.nodes.append((data.strip(), any(ignored for _, ignored in self.stack)))


def _text_nodes(html: str) -> list[tuple[str, bool]]:
    parser = _VisibleText()
    parser.feed(html)
    return parser.nodes


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


# ── duplicate tools ─────────────────────────────────────────────────────────

def test_duplicate_tools_has_no_ticket_wording_and_no_double_hyphen(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/duplicate-tools")
    assert resp.status_code == 200
    shown = [text for text, _ in _text_nodes(resp.text)]
    assert shown, "the parser found no text on the page"
    for text in shown:
        assert "ticket" not in text.lower(), text
        assert "--" not in text, text


# ── /support ────────────────────────────────────────────────────────────────

def test_support_has_no_retired_service_or_ticket_wording(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/support")
    assert resp.status_code == 200
    nodes = _text_nodes(resp.text)
    with_ticket = [(text, ignored) for text, ignored in nodes if "ticket" in text.lower()]
    assert with_ticket == [], with_ticket
    assert "not a ticket queue" not in resp.text
    assert "the team that runs your service" not in resp.text
    assert "data-walker-ignore" not in resp.text
