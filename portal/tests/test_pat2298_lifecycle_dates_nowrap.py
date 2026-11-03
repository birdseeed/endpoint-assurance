"""PAT-2298: a date in the portal's cells and evidence lists sits in a nowrap
span, so a narrow column breaks the sentence around a date and never through it.

The stub walker reported `break` findings for "04 Dec 2026" split over two
lines in the Verification (lifecycle) cell of the device Compliance tab, and
for "29 Sep 2026" in the Known vulnerable drivers list on /findings. The same
defect then turned up in cells and evidence lists across the portal. Event
reason text is prose the platform supplies, so it stays free to wrap (and
escaped).
"""

import copy
import re
from html.parser import HTMLParser

from jinja2 import Environment

import main
from tests.conftest import LIFECYCLE_CIS_HISTORY, STUB_STATE
from tests.test_pat2263_kernel_drivers import (
    BASE_ENFORCEMENT,
    DRIVER_LISTS,
    _driver_row,
    _windows_detail,
)

DATE = re.compile(r"\b\d{1,2}\s+[A-Z][a-z]{2}\s+\d{4}\b")


class _Dates(HTMLParser):
    """Collects the text inside every element matching `is_root` as
    (text, in_nowrap) pieces, so a test can ask whether a date is inside a
    nowrap span (or inside an element that itself carries the class)."""

    def __init__(self, is_root):
        super().__init__()
        self.is_root = is_root
        self.stack = []  # (tag, is_root, is_nowrap)
        self.pieces = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        classes = (attrs.get("class") or "").split()
        self.stack.append((tag, self.is_root(attrs, classes), "nowrap" in classes))

    def handle_endtag(self, tag):
        while self.stack:
            if self.stack.pop()[0] == tag:
                break

    def handle_data(self, data):
        if any(entry[1] for entry in self.stack) and data.strip():
            self.pieces.append((data, any(entry[2] for entry in self.stack)))


def _pieces(html, is_root):
    parser = _Dates(is_root)
    parser.feed(html)
    return parser.pieces


def _lifecycle(attrs, classes):
    return "lifecycle" in classes


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _dates_outside_nowrap(pieces):
    return [
        (match.group(0), text)
        for text, in_nowrap in pieces
        if not in_nowrap
        for match in DATE.finditer(text)
    ]


def _dates_inside_nowrap(pieces):
    return [text for text, in_nowrap in pieces if in_nowrap and DATE.search(text)]


def test_compliance_lifecycle_dates_are_nowrap(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices/dev-mac-001/compliance")
    assert resp.status_code == 200
    pieces = _pieces(resp.text, _lifecycle)

    # The closure sentence plus the timeline's recorded and observed dates.
    assert len(_dates_inside_nowrap(pieces)) >= 10
    assert _dates_outside_nowrap(pieces) == []
    # Only the date is held together; the time may wrap onto its own line.
    assert 'observed <span class="nowrap">04 Dec 2026</span> 09:00 (UTC).' in resp.text


def test_findings_lifecycle_dates_are_nowrap(client, make_token):
    # The same macro renders the CVE lifecycle column on /findings.
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    pieces = _pieces(resp.text, _lifecycle)

    assert _dates_inside_nowrap(pieces)
    assert _dates_outside_nowrap(pieces) == []


def test_findings_driver_section_dates_are_nowrap(client, make_token):
    # The walker's finding: "29 Sep 2026" in the source-list line, plus the
    # Fetched and First seen cells of the estate driver table.
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    pieces = _pieces(resp.text, lambda attrs, classes: attrs.get("id") == "driver-findings")

    inside = _dates_inside_nowrap(pieces)
    assert "29 Sep 2026" in inside  # the source list, DRIVER_LISTS[0], and the Fetched cell
    assert "27 Sep 2026" in inside  # First seen cell of the matched driver
    assert _dates_outside_nowrap(pieces) == []
    assert (
        '<span class="mono">v10.0.29545.0, fetched '
        '<span class="nowrap">29 Sep 2026</span> 01:00 (UTC)</span>'
    ) in resp.text


def test_compliance_driver_section_dates_are_nowrap(client, make_token):
    # The same list line and Fetched cell on a Windows device's Compliance tab.
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _windows_detail(
        status="complete", enforcement=BASE_ENFORCEMENT, lists=DRIVER_LISTS,
        summary={"drivers": 1, "hashed": 1, "unhashed": 0, "listed": 1,
                  "listed_malicious": 0, "unknown": 0},
        drivers=[_driver_row(loaded=True)], drivers_truncated=False, errors=[],
        reported_at="2026-09-29T09:00:00Z", observed_at="2026-09-29T08:59:40Z",
    )
    resp = _get(client, token, "/devices/dev-mac-001/compliance")
    assert resp.status_code == 200
    pieces = _pieces(resp.text, lambda attrs, classes: attrs.get("id") == "kernel-drivers")

    inside = _dates_inside_nowrap(pieces)
    assert "29 Sep 2026" in inside  # the source list
    assert "26 Sep 2026" in inside  # the match's Fetched cell
    assert _dates_outside_nowrap(pieces) == []


def test_event_reason_prose_is_not_nowrap_and_stays_escaped(client, make_token):
    events = copy.deepcopy(LIFECYCLE_CIS_HISTORY)
    for ev in events:
        if ev["id"] == 2:
            ev["reason"] = "Update to 14.7.1 before 30 Dec 2026 <b>today</b> and re-check"
    STUB_STATE["lifecycle_history_overrides"] = {"cis": events}
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices/dev-mac-001/compliance")
    assert resp.status_code == 200

    # Escaped, never rendered as markup.
    assert "&lt;b&gt;today&lt;/b&gt;" in resp.text
    assert "<b>today</b>" not in resp.text
    # Prose is left free to wrap: the reason is one text run outside any
    # nowrap span, and only the real dates the macro formats are inside one.
    reasons = [
        (text, in_nowrap)
        for text, in_nowrap in _pieces(resp.text, _lifecycle)
        if "Update to 14.7.1" in text
    ]
    assert reasons and all(not in_nowrap for _, in_nowrap in reasons)


# ── humandate_nowrap: the date is held together, the time is left to wrap ──
def _render(template, **context):
    env = Environment(autoescape=True)
    env.filters["humandate_nowrap"] = main.humandate_nowrap
    return env.from_string(template).render(**context)


def test_humandate_nowrap_holds_the_date_and_leaves_the_time_free():
    assert _render("{{ v | humandate_nowrap(true) }}", v="2026-12-04T09:00:05Z") == (
        '<span class="nowrap">04 Dec 2026</span> 09:00'
    )
    assert _render("{{ v | humandate_nowrap }}", v="2026-12-04T09:00:05Z") == (
        '<span class="nowrap">04 Dec 2026</span>'
    )


def test_humandate_nowrap_converts_to_utc_like_humandate():
    value = "2026-09-21T00:30:00+01:00"
    assert _render("{{ v | humandate_nowrap(true) }}", v=value) == (
        '<span class="nowrap">20 Sep 2026</span> 23:30'
    )
    assert main.humandate(value, True) == "20 Sep 2026 23:30"


def test_humandate_nowrap_fallbacks_are_plain_escaped_text_never_markup():
    # Empty: humandate's own dash. Unparseable: the value unchanged, escaped by
    # the template like any other string, and never wrapped in a span.
    assert _render("{{ v | humandate_nowrap(true) }}", v=None) == "-"
    assert _render("{{ v | humandate_nowrap(true) }}", v="") == "-"
    hostile = "<script>alert(1)</script> 04 Dec 2026"
    out = _render("{{ v | humandate_nowrap(true) }}", v=hostile)
    assert out == "&lt;script&gt;alert(1)&lt;/script&gt; 04 Dec 2026"
    assert "<" not in out and "nowrap" not in out


def test_humandate_nowrap_output_is_the_only_markup_it_adds():
    # A datetime with markup-free digits: the span is the sole tag in the output.
    out = str(main.humandate_nowrap("2026-12-04T09:00:05Z", True))
    assert re.fullmatch(r'<span class="nowrap">\d{2} [A-Z][a-z]{2} \d{4}</span> \d{2}:\d{2}', out)
