"""Guards the device detail page layout after Andy's 24 Sept 2026 review.

1. `test_compliance_signals_fit_their_card` - with real CIS signals (long
   snake_case rule ids, three-line advisories, the nowrap "No lifecycle
   evidence yet" pill) the Compliance signals table was auto-layout, so it
   sized to its content and pushed the Verification column past the card
   edge at ordinary desktop widths. The stub's two short signals never
   triggered it, which is why test_table_overflow.py stayed green.

2. `test_device_card_leads_the_page` - the device's identity and what its
   evidence is and how fresh it is are read before anything that relies on
   that evidence, so they sit directly under the page head. PAT-2141
   follow-up (Andy's live feedback, 25 Sept 2026) merged the Identification
   and Evidence collection cards into one "Device" card and moved it to
   lead the page (previously Evidence collection alone led); this test
   updates with that structure rather than pinning the pre-follow-up shape.
"""

import copy

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.test_table_overflow import (  # noqa: F401 - fixtures used by name
    PAGES,
    TABLE_SCROLL_MEASURE_JS,
    long_data_stub,
    typical_data_stub,
)
from tests.conftest import DEVICE_DETAIL, STUB_STATE

# The eight signals from the live screenshot, verbatim in shape: the longest
# rule ids and advisories a real macOS device reports today.
REAL_SIGNALS = [
    (
        'cis_macos_2_5_1_1_filevault',
        'Enable FileVault',
        'critical',
        'pass',
        (
            'Disk encryption protects data at rest. Required for any device that '
            'may store customer or business data.'
        ),
    ),
    (
        'patched_macos_disk_encryption_off',
        'Full-disk encryption enabled (macOS)',
        'critical',
        'pass',
        (
            'Disk encryption protects data at rest. Finding reported by the agent '
            'when FileVault is disabled or not fully encrypted. [PAT-2059/0174 '
            'backfill]'
        ),
    ),
    (
        'cis-2.6',
        'Enable the Application Layer Firewall',
        'high',
        'fail',
        (
            'Restricts inbound connections to allow-listed applications. Reduces '
            'lateral-movement surface on shared networks.'
        ),
    ),
    (
        'cis_macos_2_6_8_system_prefs_admin_lock',
        'Require Admin Password to Change System-Wide Preferences',
        'high',
        'fail',
        (
            'CIS §2.6.8. Eight authorisation database rights (system.preferences.*)'
            ' must have shared=false (absent or explicit <false/>) so that admin '
            'credentials are required to modify system-wide settings. Collector '
            'checks all 8 rights via security authorizationdb read and emits Yes '
            'only if all pass.'
        ),
    ),
    (
        'cis_macos_1_4_auto_security_updates',
        'Auto-install macOS security updates',
        'high',
        'pass',
        (
            'Critical CVE patches reach the endpoint without operator action. Drift'
            ' here is the single largest contributor to known-vulnerable estates in'
            ' SME environments.'
        ),
    ),
    (
        'cis_macos_2_4_4_remote_login',
        'Disable Remote Login (SSH)',
        'high',
        'pass',
        (
            'Inbound SSH is an attack surface that has no business case on managed '
            'endpoints.'
        ),
    ),
    (
        'cis_macos_2_5_2_1_gatekeeper',
        'Enable Gatekeeper',
        'high',
        'pass',
        (
            'Blocks execution of unsigned or improperly notarised binaries from the'
            ' internet.'
        ),
    ),
    (
        'cis_macos_2_5_3_sip',
        'Enable System Integrity Protection (SIP)',
        'high',
        'pass',
        (
            'Kernel-level protection against tampering with system files. Disabling'
            ' SIP is a known attacker prerequisite for persistence.'
        ),
    ),
]

WIDTHS = [1280, 1366, 1440, 1512, 1680, 1920]

WIDE_FALLBACK_FONT_CSS = '* { font-family: "Verdana", "DejaVu Sans", sans-serif !important; }'

CARD_FIT_JS = """
() => {
  const out = [];
  document.querySelectorAll('.card').forEach((card) => {
    const cr = card.getBoundingClientRect();
    card.querySelectorAll('.table-scroll').forEach((sc) => {
      if (sc.scrollWidth - sc.clientWidth > 1) {
        out.push({heading: (card.querySelector('h2') || {}).textContent,
                  why: 'table-scroll overflows', sw: sc.scrollWidth, cw: sc.clientWidth});
      }
    });
    card.querySelectorAll('.pill').forEach((p) => {
      const r = p.getBoundingClientRect();
      if (r.width && r.right > cr.right + 1) {
        out.push({heading: (card.querySelector('h2') || {}).textContent,
                  why: 'pill past card edge', text: p.textContent.trim()});
      }
    });
  });
  return out;
}
"""


@pytest.fixture
def real_signals_stub():
    detail = copy.deepcopy(DEVICE_DETAIL)
    detail["compliance_signals"] = [
        {"rule_id": r, "title": t, "severity": s, "status": st, "advisory": a}
        for (r, t, s, st, a) in REAL_SIGNALS
    ]
    STUB_STATE["device_detail_data"] = detail
    yield
    STUB_STATE["device_detail_data"] = None


def _page(browser, harness_url):
    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    for pattern in ("https://fonts.googleapis.com/**", "https://fonts.gstatic.com/**"):
        context.route(
            pattern,
            lambda route: route.fulfill(status=200, content_type="text/css", body=""),
        )
    return context, context.new_page()


@pytest.mark.parametrize("wide_font", [False, True])
def test_compliance_signals_fit_their_card(browser, harness_url, real_signals_stub, wide_font):
    # PAT-2164: Compliance signals moved to their own tab.
    context, page = _page(browser, harness_url)
    failures = []
    try:
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            page.goto(f"{harness_url}/devices/dev-mac-001/compliance", wait_until="networkidle")
            if wide_font:
                page.add_style_tag(content=WIDE_FALLBACK_FONT_CSS)
            assert page.get_by_text("No lifecycle evidence yet").count() >= 1
            assert "&lt;wbr" not in page.content()
            # The break points must actually be there, not just unescaped.
            assert "system_<wbr>prefs_<wbr>admin_<wbr>lock" in page.content()
            for f in page.evaluate(CARD_FIT_JS):
                failures.append(f"{width}px: {f}")
    finally:
        context.close()
    assert not failures, "\n".join(failures)


def test_device_card_leads_the_page(browser, harness_url, real_signals_stub):
    context, page = _page(browser, harness_url)
    try:
        page.set_viewport_size({"width": 1440, "height": 900})
        page.goto(f"{harness_url}/devices/dev-mac-001", wait_until="networkidle")
        headings = page.evaluate(
            "() => Array.from(document.querySelectorAll('.card h2'))"
            ".map((h) => h.textContent.trim())"
        )
    finally:
        context.close()
    assert headings[0] == "Device", headings


# ── Every width, not just the three the column widths were measured at ──
# PAT-2070/2092 guarded 1280, 1440 and 1920 only, and the exceptions tables
# were sized to exactly those, so they scrolled sideways at every width in
# between. This sweeps the whole desktop range.

SWEEP_WIDTHS = list(range(1280, 1921, 40)) + [1366, 1512]

# PAT-2119: no default fixture row was ever addressable by
# main.py's _inventory_approval (none carried a product_key, or a
# team_id on a macOS row), so /software never rendered a real Approval
# select/Apply/checkbox/pill/History control anywhere this sweep looked -
# the clipping bug those controls had at desktop widths was invisible to
# it. typical_data_stub and long_data_stub (e2e/test_table_overflow.py)
# now each carry one addressable row for exactly this reason - see their
# own PAT-2119 comments for which row and why.
CELL_APPROVAL_CLIP_JS = """
() => {
  const out = [];
  document.querySelectorAll('td.cell-approval').forEach((cell) => {
    const container = cell.closest('.card') || cell.closest('.table-scroll');
    if (!container) return;
    const cr = container.getBoundingClientRect();
    const controls = cell.querySelectorAll(
      '.approval-row-form__state, .approval__btn, .approval-select, ' +
      '.approval-row-meta .pill, .approval__history'
    );
    controls.forEach((el) => {
      const r = el.getBoundingClientRect();
      if (r.width === 0 && r.height === 0) return;  // not rendered this row
      if (r.left < cr.left - 1 || r.right > cr.right + 1 ||
          r.top < cr.top - 1 || r.bottom > cr.bottom + 1) {
        out.push({
          why: 'control outside its card/table container', cls: el.className,
          left: r.left, right: r.right, containerLeft: cr.left, containerRight: cr.right,
        });
      }
      if (el.scrollWidth - el.clientWidth > 1) {
        out.push({
          why: 'control text truncated', cls: el.className,
          scrollWidth: el.scrollWidth, clientWidth: el.clientWidth,
        });
      }
    });
  });
  return out;
}
"""

# PAT-2119: the Evidence cell (the evidence date, plus a "Used: <date>"
# subtitle) is meant to read as exactly two lines - see software.html's
# cell-evidence comment. This measures the two inner spans
# (.cell-evidence__main and .cell-subtle) rather than the enclosing td:
# every td in a table row is stretched to the row's tallest cell (a normal
# HTML table behaviour, not a bug), and this table's Product column
# deliberately wraps a long product name across several lines - that
# stretches every other td in the same row, including a perfectly healthy
# two-line Evidence cell, to match. Measuring the td itself would flag
# that healthy cell as broken. Each span's own height is not affected by
# its row's height (vertical-align: top leaves any extra space below it),
# so 1.6 line-heights per span (comfortable single-line headroom, not 1.0
# flat) is what actually catches a genuine extra wrap - the PAT-2119 bug -
# without tripping on the row-stretch case above.
EVIDENCE_HEIGHT_JS = """
() => {
  const out = [];
  document.querySelectorAll('td.cell-evidence').forEach((cell) => {
    const main = cell.querySelector('.cell-evidence__main');
    const sub = cell.querySelector('.cell-subtle');
    if (!main || !sub) return;
    const mainRect = main.getBoundingClientRect();
    if (mainRect.height === 0) return;  // hidden (col-tertiary below 1680px)
    const check = (el, label) => {
      const cs = getComputedStyle(el);
      const lineHeight = parseFloat(cs.lineHeight) || 20;
      const height = el.getBoundingClientRect().height;
      const maxHeight = lineHeight * 1.6;
      if (height > maxHeight) {
        out.push({label, height, maxHeight, text: el.textContent.trim()});
      }
    };
    check(main, 'main');
    check(sub, 'sub');
  });
  return out;
}
"""


@pytest.mark.parametrize("fixture_name", ["typical_data_stub", "long_data_stub"])
def test_no_table_scrolls_sideways_at_any_desktop_width(
    browser, harness_url, request, fixture_name
):
    request.getfixturevalue(fixture_name)
    context, page = _page(browser, harness_url)
    failures = []
    try:
        for path in PAGES:
            for width in SWEEP_WIDTHS:
                page.set_viewport_size({"width": width, "height": 900})
                page.goto(f"{harness_url}{path}", wait_until="networkidle")
                for r in page.evaluate(TABLE_SCROLL_MEASURE_JS):
                    failures.append(f"{path} at {width}px: {r}")
                if path == "/software":
                    for r in page.evaluate(CELL_APPROVAL_CLIP_JS):
                        failures.append(f"{path} at {width}px: {r}")
                    for r in page.evaluate(EVIDENCE_HEIGHT_JS):
                        failures.append(f"{path} at {width}px: {r}")
    finally:
        context.close()
    assert not failures, "\n".join(failures)
