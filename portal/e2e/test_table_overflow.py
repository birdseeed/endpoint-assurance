"""Guards PAT-2070 - two distinct overflow bugs the owner hit at desktop
width on the live portal, and one the audit found besides:

1. `test_no_authenticated_page_scrolls_the_whole_document_horizontally` -
   the whole page shifting sideways, exercised with deliberately long
   identifiers (long Windows install paths, SIDs, bundle ids, a long
   hostname or tenant name, a finding with a dozen CVEs on one row) at
   390px and 1280px. A table genuinely wider than the viewport is expected
   to scroll inside its own `.table-scroll` wrapper (PAT-1954) - that is
   not what this test polices; it asserts
   `document.documentElement.scrollWidth <= clientWidth`.

2. `test_no_table_scroll_overflows_at_1280_with_typical_data` - what the
   owner actually reported: ordinary, unremarkable data ("MacBook-Pro-Andy",
   "Microsoft Visual Studio Code") making a table scroll sideways inside its
   own `.table-scroll` container at a completely ordinary desktop width. The
   pre-PAT-2070 CSS forced several tables' `min-width` past what a card ever
   has available (`--maxw: 1200px` caps `.page` at every viewport from
   1440px up), so this was happening on every load, not just with unusually
   long values - this test polices exactly that class of bug, which test 1
   above cannot catch (a table scrolling inside its own container never
   overflows the document).

Deliberately feeds every fixture through STUB_STATE's override keys (see
tests/conftest.py) rather than editing the DEVICES/DEVICE_DETAIL/... module
constants in place, so neither variant used here can ever leak into any
other test's baseline fixtures - restored to None in each fixture's
teardown whatever the test outcome.
"""
import copy

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from tests.conftest import (
    DEVICE_DETAIL,
    DEVICES,
    EXCEPTIONS,
    FINDINGS,
    HOMEBREW_DEVICE_DETAIL,
    HOMEBREW_DEVICES,
    OVERVIEW,
    SOFTWARE_INVENTORY,
    STUB_STATE,
)

# Realistic long values named in the PAT-2070 brief: a deep Windows install
# path, a SID, a long bundle id, a long product name, a long hostname/tenant
# name and a finding with a dozen CVEs on one row.
LONG_WIN_PATH = (
    r"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7"
    r"\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\Extensions"
    r"\Microsoft.TeamFoundation.Client.dll"
)
LONG_SID = "S-1-5-21-3623811015-3361044348-30300820-1013"
LONG_BUNDLE_ID = (
    "com.microsoft.VisualStudioForMac.RoslynLanguageServices.CSharp."
    "ExtensionHostHelper." + ("Q" * 120)
)
LONG_PRODUCT_NAME = (
    "Really Quite A Long Third-Party Enterprise Application Name For "
    "Accounting And Payroll Reconciliation Suite Professional Edition"
)
LONG_HOSTNAME = (
    "acme-finance-workstation-accounting-payroll-reconciliation-03"
    ".internal.acmecorp.example.com"
)
LONG_TENANT_NAME = "Acme International Holdings And Subsidiaries (Isle of Man) Trust Ltd"
LONG_EMAIL = "jane.alexandra.middleton-worthington@finance.accounting.acmecorp.example.com"
MANY_CVES = [f"CVE-2026-{n:05d}" for n in range(1, 13)]

# The 11 authenticated HTML GET routes (main.py), each needing its own
# fixture id/path where the route takes one.
PAGES = [
    "/",
    "/devices",
    "/devices/dev-mac-001",
    "/devices/dev-mac-001/hardware",
    "/devices/dev-mac-001/software",
    "/devices/dev-mac-001/vulnerabilities",
    "/devices/dev-mac-001/compliance",
    "/devices/dev-mac-001/evidence",
    "/findings",
    "/software",
    "/homebrew",
    "/homebrew/devices/hb-mac-01",
    "/exceptions",
    "/reports",
    "/install",
    "/support",
]

WIDTHS = [1280, 390, 1920]

MEASURE_JS = """
() => {
  const docEl = document.documentElement;
  return {scrollWidth: docEl.scrollWidth, clientWidth: docEl.clientWidth};
}
"""

# Per-table secondary/tertiary column headers that must be VISIBLE once the
# viewport is wide enough to reveal them (1920px, well past both the 1440px
# .col-secondary and 1680px .col-tertiary reveal tiers) - see portal.css's
# .col-secondary comment for the tier assignment and how each breakpoint was
# measured. This is the guard against a future reveal breakpoint being set
# so high (like the 2200px this ticket started with) that it never fires in
# practice - a column "revealed" at a width nothing ever renders at is
# silently hidden data, exactly the defect the coordinator flagged.
REVEALED_COLUMNS_BY_PAGE = {
    "/": ["Version", "Not applicable", "Out of scope", "CIS mapped", "CIS unmapped", "Non-CIS"],
    "/devices": ["OS version"],
    "/findings": ["First seen", "CVSS"],
    # PAT-2120: Signing is no longer its own column - protected_badge()/
    # signing_badge() render inline in the Product cell instead (the
    # ticket's Data decision, "unless that breaks something - say which
    # you chose"), so it has nothing to reveal at this breakpoint any more.
    "/software": ["Platform", "Evidence", "Type"],
    "/exceptions": ["Type", "Requested by"],
}

HEADER_VISIBILITY_JS = """
() => {
  const headers = [];
  document.querySelectorAll('table thead th').forEach((th) => {
    headers.push({
      text: th.textContent.trim(),
      visible: getComputedStyle(th).display !== 'none',
    });
  });
  return headers;
}
"""

# Ordinary, unremarkable values - the shape of data the owner actually saw
# when this bug was reported, not a stress case.
TYPICAL_HOSTNAME = "MacBook-Pro-Andy"
TYPICAL_PRODUCT_NAME = "Microsoft Visual Studio Code"
TYPICAL_BUNDLE_ID = "com.microsoft.VSCode"

# PAT-2070 (CI failure on the Linux e2e job): Linux Chromium's system-ui
# fallback chain resolves to a wider font (DejaVu Sans / Liberation Sans)
# than macOS's San Francisco, so any nowrap element sized exactly to its
# text is a few px wider there than in local development - enough to tip a
# borderline layout into overflow that never reproduces on a macOS runner.
# Forcing this font locally reproduces the same class of defect regardless
# of which OS pytest happens to run on.
WIDE_FALLBACK_FONT_CSS = '* { font-family: "Verdana", "DejaVu Sans", sans-serif !important; }'


def _force_wide_fallback_font(page):
    page.add_style_tag(content=WIDE_FALLBACK_FONT_CSS)


TABLE_SCROLL_MEASURE_JS = """
() => {
  const out = [];
  document.querySelectorAll('.table-scroll').forEach((container) => {
    const overflow = container.scrollWidth - container.clientWidth;
    if (overflow > 1) {
      const table = container.querySelector('table');
      out.push({
        tableCls: table ? table.className : null,
        scrollWidth: container.scrollWidth, clientWidth: container.clientWidth,
      });
    }
  });
  return out;
}
"""


@pytest.fixture
def long_data_stub():
    """Overrides every STUB_STATE fixture key touched by the 11 pages with a
    deep-copied, deliberately long-valued variant, then restores every key to
    None on teardown - see the module docstring for why this uses the
    override keys rather than mutating the shared module constants."""
    touched = [
        "devices_data", "device_detail_data", "software_inventory_data",
        "exceptions_data", "homebrew_devices_data",
        "homebrew_device_detail_data", "findings_data", "overview_data",
    ]

    devices = copy.deepcopy(DEVICES)
    devices["devices"][0]["hostname"] = LONG_HOSTNAME
    STUB_STATE["devices_data"] = devices

    device_detail = copy.deepcopy(DEVICE_DETAIL)
    device_detail["hostname"] = LONG_HOSTNAME
    device_detail["apps_with_findings"][0]["app"] = LONG_PRODUCT_NAME
    device_detail["apps_with_findings"][0]["cve_ids"] = MANY_CVES
    device_detail["apps_with_findings"][0]["fixed_version"] = (
        "125.0.0-really-long-build-tag-2026.09.23+abcdef1234567890"
    )
    # PAT-2099: the Collection issues table's generic fallback line echoes
    # the raw `subject` value verbatim in parentheses - stress that with an
    # unusually long, unrecognised subject alongside a real approved-copy
    # row, rather than only the short documented subjects the default
    # fixture already covers.
    device_detail["agent_health_degraded"] = [
        {
            "kind": "tcc_denied", "subject": "browser_extensions",
            "reason": "full_disk_access_missing",
            "first_seen": "2026-09-20T09:00:00Z", "last_seen": "2026-09-24T09:00:00Z",
            "count": 5,
        },
        {
            "kind": "future_unmapped_kind",
            "subject": "a_deliberately_long_future_inventory_subject_name_for_overflow_testing",
            "reason": "future_unmapped_reason",
            "first_seen": "2026-09-20T09:00:00Z", "last_seen": "2026-09-24T09:00:00Z",
            "count": 1,
        },
    ]
    STUB_STATE["device_detail_data"] = device_detail

    software = copy.deepcopy(SOFTWARE_INVENTORY)
    software["products"][0]["name"] = LONG_PRODUCT_NAME
    software["products"][0]["identifier"] = LONG_BUNDLE_ID
    software["products"][0]["canonical_name"] = LONG_PRODUCT_NAME + " (Reviewed)"
    # PAT-2119: product 0's identifier is the 120+ character LONG_BUNDLE_ID
    # above, which main.py's _inventory_approval locks as
    # IDENTIFIER_TOO_LONG_LOCK regardless of product_key/team_id - correct
    # for that row, but it means this fixture otherwise never renders a
    # real (unlocked) Approval select/Apply/checkbox/History control, so
    # the PAT-2119 clipping regression on those controls was invisible to
    # this sweep. Product 1 (MeteringGap, Windows - no team_id required)
    # gets the fields _inventory_approval needs to leave it unlocked
    # instead: a non-empty product_key and a platform in APPROVAL_PLATFORMS
    # with a short identifier (already true - "com.acme.gap") are enough.
    software["products"][1]["product_key"] = "pk-meteringgap"
    STUB_STATE["software_inventory_data"] = software

    exceptions = copy.deepcopy(EXCEPTIONS)
    exceptions["exceptions"][0]["product"] = LONG_PRODUCT_NAME
    exceptions["exceptions"][0]["depends_on"] = (
        "Finance close process depends on the 4.1 report format. " * 3
    )
    exceptions["exceptions"][0]["requested_by"] = LONG_EMAIL
    STUB_STATE["exceptions_data"] = exceptions

    homebrew_devices = copy.deepcopy(HOMEBREW_DEVICES)
    homebrew_devices["devices"][0]["prefixes"] = [
        {"path": r"/opt/homebrew/Cellar/some-really-long-formula-name-that-keeps-going/3.5.2_1",
         "owner": "alice", "owner_uid": 501, "collection_status": "complete",
         "formulae": 2, "casks": 1, "taps": 1},
        {"path": r"/usr/local/some/other/deeply/nested/homebrew/prefix/path/for/testing/overflow",
         "owner": "bob", "owner_uid": 502, "collection_status": "complete",
         "formulae": 1, "casks": 0, "taps": 0},
    ]
    STUB_STATE["homebrew_devices_data"] = homebrew_devices

    homebrew_device_detail = copy.deepcopy(HOMEBREW_DEVICE_DETAIL)
    homebrew_device_detail["state"] = homebrew_devices["devices"][0]
    STUB_STATE["homebrew_device_detail_data"] = homebrew_device_detail

    findings = copy.deepcopy(FINDINGS)
    findings[0]["app"] = LONG_PRODUCT_NAME
    findings[0]["summary"] = LONG_SID + " " + LONG_WIN_PATH
    STUB_STATE["findings_data"] = findings

    overview = copy.deepcopy(OVERVIEW)
    overview["tenant_name"] = LONG_TENANT_NAME
    STUB_STATE["overview_data"] = overview

    yield

    for key in touched:
        STUB_STATE[key] = None


@pytest.fixture
def typical_data_stub():
    """Overrides the same STUB_STATE keys as long_data_stub above, but with
    ordinary values a real estate would actually show - no unusually long
    identifier anywhere. Every other page's default fixture data (findings,
    exceptions, homebrew) is already this ordinary, so only the three pages
    the coordinator named as needing it are overridden here."""
    touched = ["devices_data", "device_detail_data", "software_inventory_data"]

    devices = copy.deepcopy(DEVICES)
    devices["devices"][0]["hostname"] = TYPICAL_HOSTNAME
    STUB_STATE["devices_data"] = devices

    device_detail = copy.deepcopy(DEVICE_DETAIL)
    device_detail["hostname"] = TYPICAL_HOSTNAME
    device_detail["apps_with_findings"][0]["app"] = TYPICAL_PRODUCT_NAME
    # PAT-2099: an ordinary Collection issues row - the shape a real macOS
    # estate without Full Disk Access granted actually shows.
    device_detail["agent_health_degraded"] = [
        {
            "kind": "tcc_denied", "subject": "browser_extensions",
            "reason": "full_disk_access_missing",
            "first_seen": "2026-09-20T09:00:00Z", "last_seen": "2026-09-24T09:00:00Z",
            "count": 5,
        },
    ]
    STUB_STATE["device_detail_data"] = device_detail

    software = copy.deepcopy(SOFTWARE_INVENTORY)
    software["products"][0]["name"] = TYPICAL_PRODUCT_NAME
    software["products"][0]["identifier"] = TYPICAL_BUNDLE_ID
    # PAT-2119: give this (macOS) row what main.py's _inventory_approval
    # needs to leave it unlocked - a product_key and a valid 10-character
    # team_id - so the page actually renders a real Approval select, Apply
    # button, bulk checkbox, state pill and History link rather than the
    # locked/no-controls state every default fixture row was in. Without
    # this, the sweep below never exercised the controls the PAT-2119
    # clipping bug was in.
    software["products"][0]["product_key"] = "pk-vscode"
    software["products"][0]["team_id"] = "EQHXZ8M8AV"
    STUB_STATE["software_inventory_data"] = software

    yield

    for key in touched:
        STUB_STATE[key] = None


def test_no_table_scroll_overflows_at_1280_and_1920_with_typical_data(
    browser, harness_url, typical_data_stub,
):
    """The bug the owner actually reported: at an ordinary desktop width,
    with ordinary data, several tables' .table-scroll container had to be
    scrolled sideways to read the rest of the row - see the module
    docstring for why test 1 above cannot catch this class of bug. Checked
    at both 1280px (below every reveal tier, so every table is at its
    narrowest/primary-only column set) and 1920px (past every reveal tier,
    so every table is at its widest/full column set - the coordinator's
    "no-overflow check at 1920" from the second round of feedback)."""
    context = browser.new_context(base_url=harness_url)
    try:
        context.add_cookies([{
            "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN,
            "url": harness_url,
        }])
        context.route(
            "https://fonts.googleapis.com/**",
            lambda route: route.fulfill(status=200, content_type="text/css", body=""),
        )
        context.route(
            "https://fonts.gstatic.com/**",
            lambda route: route.fulfill(status=200, content_type="text/css", body=""),
        )
        page = context.new_page()
        failures = []
        for path in PAGES:
            for width in (1280, 1920):
                page.set_viewport_size({"width": width, "height": 900})
                page.goto(f"{harness_url}{path}", wait_until="networkidle")
                for r in page.evaluate(TABLE_SCROLL_MEASURE_JS):
                    failures.append(
                        f"{path} at {width}px: table {r['tableCls']!r} "
                        f"scrollWidth={r['scrollWidth']} > clientWidth={r['clientWidth']}"
                    )
    finally:
        context.close()

    assert not failures, "tables scrolling inside .table-scroll:\n" + "\n".join(failures)


def test_secondary_columns_are_visible_at_1920_not_silently_hidden(
    browser, harness_url, typical_data_stub,
):
    """PAT-2070 round 2 shipped a .col-secondary reveal breakpoint
    (2200px) above every width this ticket - or a real customer's own
    monitor - ever renders at, which the coordinator caught: that silently
    removes real evidence (including Devices affected, a key CVE
    prioritisation column on Findings) from every customer permanently, not
    just below some responsive breakpoint. This guards the fix by asserting
    each table's demoted columns are genuinely visible again at 1920px, not
    just present-but-hidden in the DOM - the failure mode a bare "does this
    text exist in the HTML" test would miss entirely."""
    context = browser.new_context(base_url=harness_url)
    try:
        context.add_cookies([{
            "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN,
            "url": harness_url,
        }])
        context.route(
            "https://fonts.googleapis.com/**",
            lambda route: route.fulfill(status=200, content_type="text/css", body=""),
        )
        context.route(
            "https://fonts.gstatic.com/**",
            lambda route: route.fulfill(status=200, content_type="text/css", body=""),
        )
        page = context.new_page()
        failures = []
        for path, expected in REVEALED_COLUMNS_BY_PAGE.items():
            page.set_viewport_size({"width": 1920, "height": 900})
            page.goto(f"{harness_url}{path}", wait_until="networkidle")
            headers = page.evaluate(HEADER_VISIBILITY_JS)
            visible_texts = {h["text"] for h in headers if h["visible"]}
            for column in expected:
                if column not in visible_texts:
                    failures.append(f"{path} at 1920px: {column!r} is not visible")
    finally:
        context.close()

    assert not failures, "columns still hidden at 1920px:\n" + "\n".join(failures)


def test_devices_affected_is_always_primary_on_findings(browser, harness_url, typical_data_stub):
    """Devices (labelled "Devices affected" until PAT-2092 shortened the
    header text to fit its column - see findings-table's own portal.css
    comment) is a key CVE prioritisation column (coordinator's instruction
    #3) and must never be demoted - checked at 1280px, below every reveal
    tier, where every genuinely secondary/tertiary column on every other
    table in REVEALED_COLUMNS_BY_PAGE is hidden."""
    context = browser.new_context(base_url=harness_url)
    try:
        context.add_cookies([{
            "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN,
            "url": harness_url,
        }])
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})
        page.goto(f"{harness_url}/findings", wait_until="networkidle")
        headers = page.evaluate(HEADER_VISIBILITY_JS)
        visible_texts = {h["text"] for h in headers if h["visible"]}
    finally:
        context.close()

    assert "Devices" in visible_texts


def test_no_authenticated_page_scrolls_the_whole_document_horizontally(
    browser, harness_url, long_data_stub,
):
    context = browser.new_context(base_url=harness_url)
    try:
        context.add_cookies([{
            "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN,
            "url": harness_url,
        }])
        context.route(
            "https://fonts.googleapis.com/**",
            lambda route: route.fulfill(status=200, content_type="text/css", body=""),
        )
        context.route(
            "https://fonts.gstatic.com/**",
            lambda route: route.fulfill(status=200, content_type="text/css", body=""),
        )
        page = context.new_page()
        failures = []
        for path in PAGES:
            for width in WIDTHS:
                page.set_viewport_size({"width": width, "height": 900})
                page.goto(f"{harness_url}{path}", wait_until="networkidle")
                m = page.evaluate(MEASURE_JS)
                if m["scrollWidth"] > m["clientWidth"]:
                    failures.append(
                        f"{path} at {width}px: scrollWidth={m['scrollWidth']} "
                        f"> clientWidth={m['clientWidth']}"
                    )
    finally:
        context.close()

    assert not failures, "pages with horizontal document overflow:\n" + "\n".join(failures)


def test_no_document_overflow_with_a_wider_fallback_font(
    browser, harness_url, long_data_stub,
):
    """Reproduces the Linux-CI-only failure locally (see WIDE_FALLBACK_FONT_CSS's
    comment): with every element forced onto a wider fallback font, the same
    document-overflow check as the test above, at the same two widths
    (390px and 1280px) the CI failure named. Caught .attention-summary__item's
    CTA link on the overview forcing the card past the viewport at 390px -
    a CSS Grid item's automatic minimum size defaults to its content's
    min-content, which for `white-space: nowrap` text is its full unwrapped
    width, wider still under this font - fixed with `min-width: 0` on the
    grid's items plus letting the link wrap once the grid collapses to one
    column below 820px, not by special-casing the 6px this showed up as on
    the CI runner's exact font metrics."""
    context = browser.new_context(base_url=harness_url)
    try:
        context.add_cookies([{
            "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN,
            "url": harness_url,
        }])
        context.route(
            "https://fonts.googleapis.com/**",
            lambda route: route.fulfill(status=200, content_type="text/css", body=""),
        )
        context.route(
            "https://fonts.gstatic.com/**",
            lambda route: route.fulfill(status=200, content_type="text/css", body=""),
        )
        page = context.new_page()
        failures = []
        for path in PAGES:
            for width in (390, 1280):
                page.set_viewport_size({"width": width, "height": 900})
                page.goto(f"{harness_url}{path}", wait_until="networkidle")
                _force_wide_fallback_font(page)
                m = page.evaluate(MEASURE_JS)
                if m["scrollWidth"] > m["clientWidth"]:
                    failures.append(
                        f"{path} at {width}px (wide fallback font): "
                        f"scrollWidth={m['scrollWidth']} > clientWidth={m['clientWidth']}"
                    )
    finally:
        context.close()

    assert not failures, (
        "pages with horizontal document overflow under a wider fallback font:\n"
        + "\n".join(failures)
    )


def test_no_table_scroll_overflows_at_1280_with_a_wider_fallback_font(
    browser, harness_url, typical_data_stub,
):
    """Same font-forcing as the test above, applied to the table-scroll
    check instead of the document check - the coordinator's third
    instruction ("the table check at 1280"), so a wider Linux fallback font
    pushing a table's own content past its column (not just the page's
    prose past the viewport) is caught locally too."""
    context = browser.new_context(base_url=harness_url)
    try:
        context.add_cookies([{
            "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN,
            "url": harness_url,
        }])
        context.route(
            "https://fonts.googleapis.com/**",
            lambda route: route.fulfill(status=200, content_type="text/css", body=""),
        )
        context.route(
            "https://fonts.gstatic.com/**",
            lambda route: route.fulfill(status=200, content_type="text/css", body=""),
        )
        page = context.new_page()
        failures = []
        for path in PAGES:
            page.set_viewport_size({"width": 1280, "height": 900})
            page.goto(f"{harness_url}{path}", wait_until="networkidle")
            _force_wide_fallback_font(page)
            for r in page.evaluate(TABLE_SCROLL_MEASURE_JS):
                failures.append(
                    f"{path} at 1280px (wide fallback font): table {r['tableCls']!r} "
                    f"scrollWidth={r['scrollWidth']} > clientWidth={r['clientWidth']}"
                )
    finally:
        context.close()

    assert not failures, (
        "tables scrolling inside .table-scroll under a wider fallback font:\n"
        + "\n".join(failures)
    )
