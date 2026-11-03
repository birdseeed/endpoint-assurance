"""Acceptance tests for e2e/walk/walk.py's check FUNCTIONS (PAT-2126).

Serves a tiny fixture page from this test module (never added to the
product's own templates/static) containing four deliberate cases:

  1. a wide table clipped by an `overflow: hidden` wrapper (should be
     caught by check_overflow)
  2. a `console.error()` fired on load (should be caught by check_console)
  3. an em dash in an `<h1>` heading (should be caught by check_copy)
  4. an em dash inside a `<td>` (must NOT be caught - `<td>` is one of
     check_copy's explicit ignore tags, PAT-2126 brief)

This module points walk.py's check functions at that fixture page directly
- it never touches the real portal app, the stub platform, or the e2e
harness subprocess (so it doesn't need the `harness_url`/`stub_platform_url`
fixtures from e2e/conftest.py, only the session-scoped `browser` fixture,
which this module inherits automatically since e2e/conftest.py applies to
its whole directory tree).

Collected by `pytest e2e/` (as intended - a plain `pytest` still never
touches e2e/ at all, since pyproject.toml's testpaths is ["tests",
"scan/tests"]) but this module never invokes walk.py's CLI/`run_walk`
against the real app, so nothing here depends on findings existing or not -
the walk itself staying a CLI-only concern that can never fail this suite.

Red-proof (verified by hand for PAT-2126, not kept as a permanent test):
with check_copy's body temporarily replaced by `return []`,
test_copy_check_reports_the_heading_em_dash_and_not_the_td goes red; with
check_overflow's body replaced by `return []`,
test_overflow_check_reports_the_clipped_table goes red. Both pass again
once the real bodies are restored.

A second, separate fixture page (TRUNCATION_FIXTURE_HTML below) covers
PAT-2128: text-overflow:ellipsis truncation is intentional, not a defect,
*only* when the element's full value is still readable via a `title` or
`aria-label`. Kept as its own page/server rather than added to the
PAT-2126 fixture above so none of the existing findings-count assertions
there have to change. Red-proof (verified by hand for PAT-2128, not kept as
a permanent test): re-running check_overflow's old body - CLIPPING limited
to {hidden, clip} with no textOverflow/hasFullText facts gathered, every
clipped element unconditionally reported as `overflow` - against this same
fixture reports THREE `overflow` findings (both ellipsis spans plus the
table), which is exactly what
test_ellipsis_with_title_is_not_reported and
test_ellipsis_without_title_gives_truncation_no_full_text exist to catch:
the old body reports the titled span (should be silent) and reports the
untitled span as `overflow` instead of `truncation-no-full-text`. The real
body restores all three tests to green.
"""

import http.server
import socket
import threading
import time

import pytest

import e2e.walk.walk as walk_module
from e2e.walk.walk import check_console, check_copy, check_l12, check_l13, check_overflow

FIXTURE_HTML = """<!doctype html>
<html>
<head><meta charset="utf-8"><title>Walker fixture</title></head>
<body>
<h1>Coverage overview — quarterly</h1>
<div class="clip-wrap" style="width: 120px; overflow: hidden;">
  <table style="width: 900px; border-collapse: collapse;">
    <tr><td>Wide row that will not fit — deliberately overflows its
    wrapper so the walker's overflow check has something to catch</td></tr>
  </table>
</div>
<script>console.error("fixture console error - PAT-2126 red-proof");</script>
</body>
</html>"""


class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = FIXTURE_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # keep pytest -q output quiet - no per-request access log


@pytest.fixture(scope="module")
def fixture_url():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()


def _load_fixture(browser, fixture_url):
    """Returns (context, page, js_errors). Caller closes the context."""
    context = browser.new_context()
    js_errors = []
    page = context.new_page()
    # Must be attached before goto() - a console.error fired during initial
    # page load would otherwise be missed.
    page.on("console", lambda msg: js_errors.append(msg.text) if msg.type == "error" else None)
    page.goto(fixture_url)
    return context, page, js_errors


@pytest.fixture
def fixture_page(browser, fixture_url):
    context, page, js_errors = _load_fixture(browser, fixture_url)
    yield page, js_errors
    context.close()


def test_overflow_check_reports_the_clipped_table(fixture_page):
    page, _ = fixture_page
    findings = check_overflow(page, "/fixture", 1440, "light")
    assert len(findings) == 1, findings
    finding = findings[0]
    assert finding.check == "overflow"
    assert finding.route == "/fixture"
    assert finding.width == 1440
    assert finding.theme == "light"
    assert finding.severity == "medium"
    assert "div" in finding.detail
    assert "scrollWidth 900" in finding.detail
    assert "clientWidth 120" in finding.detail


def test_console_check_reports_the_console_error(fixture_page):
    page, js_errors = fixture_page
    assert js_errors, "the fixture page's console.error was not captured by the page listener"
    findings = check_console(js_errors, [], "/fixture", 1440, "light")
    assert len(findings) == 1, findings
    finding = findings[0]
    assert finding.check == "console"
    assert finding.severity == "medium"
    assert "fixture console error" in finding.detail


def test_copy_check_reports_the_heading_em_dash_and_not_the_td(fixture_page):
    page, _ = fixture_page
    findings = check_copy(page, "/fixture", 1440, "light")
    assert len(findings) == 1, findings
    finding = findings[0]
    assert finding.check == "copy"
    assert finding.severity == "low"
    selector = finding.detail.split(":", 1)[0]
    assert "h1" in selector, finding.detail
    assert "td" not in selector, finding.detail


def test_no_console_errors_and_no_failed_requests_means_no_console_findings(fixture_page):
    findings = check_console([], [], "/fixture", 1440, "light")
    assert findings == []


# ── PAT-2128: text-overflow: ellipsis truncation is not a layout defect ────
#
# A separate fixture page/server on purpose - see the module docstring's
# "second, separate fixture page" note. Three deliberate cases:
#
#   1. an ellipsis-truncated span WITH a `title` carrying its full value
#      (must not be reported at all - intentional truncation, readable
#      another way)
#   2. an ellipsis-truncated span with NO title/aria-label (must be
#      reported, but as `truncation-no-full-text`, not `overflow` - the
#      layout is fine, the accessibility affordance is what's missing)
#   3. a wide table clipped by `overflow: hidden` with no `text-overflow`
#      set at all (must still be reported as a plain `overflow` finding,
#      exactly as before PAT-2128)

TRUNCATION_FIXTURE_HTML = """<!doctype html>
<html>
<head><meta charset="utf-8"><title>Walker truncation fixture</title>
<style>
.trunc { display: inline-block; width: 80px; overflow: hidden;
         white-space: nowrap; text-overflow: ellipsis; }
</style>
</head>
<body>
<span id="ellipsis-with-title"
      class="trunc"
      title="Full product name that would not otherwise fit on screen"
      >Full product name that would not otherwise fit on screen</span>
<span id="ellipsis-no-title"
      class="trunc">Another full value with no way to read the rest of it</span>
<div id="clip-wrap-no-ellipsis" style="width: 120px; overflow: hidden;">
  <table style="width: 900px; border-collapse: collapse;">
    <tr><td>Wide row clipped with no text-overflow: ellipsis set,
      a real overflow defect (PAT-2128)</td></tr>
  </table>
</div>
</body>
</html>"""


class _TruncationFixtureHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = TRUNCATION_FIXTURE_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # keep pytest -q output quiet - no per-request access log


@pytest.fixture(scope="module")
def truncation_fixture_url():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TruncationFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()


@pytest.fixture
def truncation_fixture_page(browser, truncation_fixture_url):
    context = browser.new_context()
    page = context.new_page()
    page.goto(truncation_fixture_url)
    yield page
    context.close()


def test_ellipsis_with_title_is_not_reported(truncation_fixture_page):
    findings = check_overflow(truncation_fixture_page, "/truncation-fixture", 1440, "light")
    assert not any("ellipsis-with-title" in f.detail for f in findings), findings


def test_ellipsis_without_title_gives_truncation_no_full_text(truncation_fixture_page):
    findings = check_overflow(truncation_fixture_page, "/truncation-fixture", 1440, "light")
    matches = [f for f in findings if "ellipsis-no-title" in f.detail]
    assert len(matches) == 1, findings
    finding = matches[0]
    assert finding.check == "truncation-no-full-text"
    assert finding.severity == "low"
    assert "no title/aria-label" in finding.detail
    assert finding.fingerprint.startswith("wk-truncation-no-full-text-")


def test_clipped_table_without_ellipsis_is_still_reported_as_overflow(truncation_fixture_page):
    findings = check_overflow(truncation_fixture_page, "/truncation-fixture", 1440, "light")
    matches = [f for f in findings if "clip-wrap-no-ellipsis" in f.detail]
    assert len(matches) == 1, findings
    finding = matches[0]
    assert finding.check == "overflow"
    assert finding.severity == "medium"


def test_truncation_fixture_produces_exactly_the_expected_findings(truncation_fixture_page):
    # Belt-and-suspenders on the three cases together: exactly one
    # `overflow` and one `truncation-no-full-text`, nothing else - the
    # titled ellipsis span must never surface a finding of any kind.
    findings = check_overflow(truncation_fixture_page, "/truncation-fixture", 1440, "light")
    assert sorted(f.check for f in findings) == ["overflow", "truncation-no-full-text"]


# ── PAT-2128 follow-up: `.visually-hidden`-style screen-reader-only
# elements are not overflow defects ──────────────────────────────────────
#
# The first real portal-main walk (2026-09-25) reported 32 `overflow`
# findings that were every one a `.visually-hidden` label/span
# (portal.css ~line 849: a 1px box, `overflow: hidden`, `clip:
# rect(0, 0, 0, 0)`) - the correct accessible-hiding idiom, not a layout
# defect. check_overflow now excludes these, matched generically on
# computed geometry/style (a ~0px box, or a `clip`/`clip-path` that hides
# the element) rather than keyed to the `.visually-hidden` class name.
#
# Three deliberate cases:
#
#   1. an element using the exact `.visually-hidden` recipe (1px box +
#      `clip: rect(0,0,0,0)`) - must not be reported at all
#   2. an element NOT using that class or a 1px box, hidden instead via
#      `clip-path: inset(50%)` on a normally-sized box - proves the match
#      is generic, not keyed to the class name or the tiny box alone
#   3. a wide table clipped by a plain `overflow: hidden` wrapper with no
#      clip/clip-path at all - a real layout defect, must still be
#      reported as `overflow` exactly as before
#
# Red-proof (verified by hand for this ticket, not kept as a permanent
# test): with the visually-hidden exclusion removed from _OVERFLOW_JS (the
# `isVisuallyHidden` check deleted so every clipped candidate is reported
# unconditionally, as check_overflow's body was before this change), running
# against this fixture reports THREE `overflow` findings instead of one -
# both screen-reader-only labels plus the real table - which is exactly what
# test_visually_hidden_label_is_not_reported and
# test_clip_path_hidden_label_is_not_reported below exist to catch. Restoring
# the real body brings it back to exactly one.

VISUALLY_HIDDEN_FIXTURE_HTML = """<!doctype html>
<html>
<head><meta charset="utf-8"><title>Walker visually-hidden fixture</title>
<style>
.visually-hidden {
  position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0;
  overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
}
.clip-path-hidden {
  display: inline-block; width: 60px; height: 20px; overflow: hidden;
  clip-path: inset(50%); white-space: nowrap;
}
</style>
</head>
<body>
<span id="sr-only-label" class="visually-hidden">Screen-reader-only label
  text, much wider than the one-pixel box that hides it visually</span>
<span id="clip-path-label" class="clip-path-hidden">Another screen-reader
  label, hidden via clip-path on a normally-sized box instead</span>
<div id="clip-wrap-real-defect" style="width: 120px; overflow: hidden;">
  <table style="width: 900px; border-collapse: collapse;">
    <tr><td>Wide row clipped for real, not a visually-hidden idiom
      (PAT-2128 follow-up)</td></tr>
  </table>
</div>
</body>
</html>"""


class _VisuallyHiddenFixtureHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = VISUALLY_HIDDEN_FIXTURE_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # keep pytest -q output quiet - no per-request access log


@pytest.fixture(scope="module")
def visually_hidden_fixture_url():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _VisuallyHiddenFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()


@pytest.fixture
def visually_hidden_fixture_page(browser, visually_hidden_fixture_url):
    context = browser.new_context()
    page = context.new_page()
    page.goto(visually_hidden_fixture_url)
    yield page
    context.close()


def test_visually_hidden_label_is_not_reported(visually_hidden_fixture_page):
    findings = check_overflow(visually_hidden_fixture_page, "/visually-hidden-fixture", 1440,
                               "light")
    assert not any("sr-only-label" in f.detail for f in findings), findings


def test_clip_path_hidden_label_is_not_reported(visually_hidden_fixture_page):
    findings = check_overflow(visually_hidden_fixture_page, "/visually-hidden-fixture", 1440,
                               "light")
    assert not any("clip-path-label" in f.detail for f in findings), findings


def test_real_clipped_table_still_reported_as_overflow(visually_hidden_fixture_page):
    findings = check_overflow(visually_hidden_fixture_page, "/visually-hidden-fixture", 1440,
                               "light")
    matches = [f for f in findings if "clip-wrap-real-defect" in f.detail]
    assert len(matches) == 1, findings
    finding = matches[0]
    assert finding.check == "overflow"
    assert finding.severity == "medium"


def test_visually_hidden_fixture_produces_exactly_the_expected_finding(
        visually_hidden_fixture_page):
    # Belt-and-suspenders: exactly the real table's `overflow` finding,
    # nothing else - neither screen-reader-only label surfaces anything.
    findings = check_overflow(visually_hidden_fixture_page, "/visually-hidden-fixture", 1440,
                               "light")
    assert [f.check for f in findings] == ["overflow"]


def test_fingerprints_identical_across_two_independent_runs(browser, fixture_url):
    def _run():
        context, page, js_errors = _load_fixture(browser, fixture_url)
        try:
            findings = (
                check_overflow(page, "/fixture", 1440, "light")
                + check_console(js_errors, [], "/fixture", 1440, "light")
                + check_copy(page, "/fixture", 1440, "light")
            )
        finally:
            context.close()
        return sorted(f.fingerprint for f in findings)

    first = _run()
    second = _run()
    assert first, "expected at least one finding to compare"
    assert first == second


# ── L12 (portal-rubric.md, Andy ruling 2026-09-25, PAT-2128) ───────────────
#
# 390px-only rubric check: no table cell breaks a word mid-letter or renders
# one character per line, and no table forces the page to scroll sideways
# instead of stacking (.table-stack) or scrolling inside its own card. Five
# deliberate cases in one fixture page, each in its own `.card`:
#
#   1. a fixed-layout table narrowed to 12px so its one cell (two-letter
#      text, too short for the word-break regex below to ever match it)
#      renders about one character per line - must be reported
#   2. a hyphenated CVE id ("CVE-2026-0001") in a cell wide enough to wrap
#      naturally at the hyphens (a real CSS/UAX14 soft-wrap opportunity,
#      not a mid-word break, per PAT-2092's WORD_BREAK_JS rationale) - must
#      NOT be reported
#   3. a table wider than its card, inside an `overflow-x: auto` wrapper
#      within that card - reachable by scrolling, must NOT be reported
#   4. the same over-wide table with no scroll wrapper at all - forces the
#      card (and, at the page level, potentially the whole page) to scroll
#      sideways - must be reported
#   5. the same over-wide table, `.table-stack` in stacked mode (its own
#      CSS switches it to `display: block`, the same recipe
#      static/css/portal.css's real `.table-stack` media-query rule uses at
#      phone width) - must NOT be reported
#
# Red-proof (verified by hand for this ticket, not kept as a permanent
# test): with check_l12's three `page.evaluate(...)` result lists each
# force-emptied (a stand-in for "the rule disabled"), every assertion below
# that expects a finding goes red - test_onechar_per_line_cell_is_reported
# and test_wide_table_without_scroll_wrapper_is_reported both fail because
# `findings` comes back empty. Restoring the real bodies (this diff) brings
# them back to green.

L12_FIXTURE_HTML = """<!doctype html>
<html>
<head><meta charset="utf-8"><title>Walker L12 fixture</title>
<style>
.card { width: 200px; border: 1px solid #ccc; padding: 8px; margin-bottom: 16px; }
.l12-onechar-table { table-layout: fixed; width: 12px; border-collapse: collapse; }
.l12-onechar-table td { overflow-wrap: anywhere; }
.l12-cve-table td { width: 60px; }
.l12-wide-scroll-wrap { overflow-x: auto; width: 100%; }
.l12-wide-table { width: 500px; border-collapse: collapse; }
/* Same stacked-mode recipe as static/css/portal.css's real .table-stack
   phone-width rule (PAT-2136/PAT-2137), applied unconditionally here
   rather than behind a max-width media query so this fixture page (served
   standalone, with no other portal CSS loaded) exercises it at any
   viewport the test sets. */
.table-stack, .table-stack tbody, .table-stack tr { display: block; width: 100%; }
.table-stack td { display: block; }
</style>
</head>
<body>

<div class="card">
  <table class="l12-onechar-table"><tbody><tr><td>OK</td></tr></tbody></table>
</div>

<div class="card">
  <table class="l12-cve-table"><tbody><tr><td>CVE-2026-0001</td></tr></tbody></table>
</div>

<div class="card">
  <div class="l12-wide-scroll-wrap">
    <table class="l12-wide-table"><tbody><tr><td>Wide content that needs horizontal
      scroll to read fully, well past its card</td></tr></tbody></table>
  </div>
</div>

<div class="card">
  <table class="l12-wide-table"><tbody><tr><td>Wide content with no scroll wrapper
    at all, well past its card</td></tr></tbody></table>
</div>

<div class="card">
  <table class="table-stack l12-wide-table"><tbody><tr><td data-label="Value">Stacked
    row value that would otherwise overflow its card</td></tr></tbody></table>
</div>

</body>
</html>"""


class _L12FixtureHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = L12_FIXTURE_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # keep pytest -q output quiet - no per-request access log


@pytest.fixture(scope="module")
def l12_fixture_url():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _L12FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()


@pytest.fixture
def l12_fixture_page(browser, l12_fixture_url):
    context = browser.new_context()
    page = context.new_page()
    # 390px, matching the walker's own phone-width pass - L12 is a
    # 390px-only rule, so the fixture is set to that width rather than the
    # 1440px the other fixtures above use.
    page.set_viewport_size({"width": 390, "height": 900})
    page.goto(l12_fixture_url)
    yield page
    context.close()


def test_onechar_per_line_cell_is_reported(l12_fixture_page):
    findings = check_l12(l12_fixture_page, "/l12-fixture", 390, "light")
    matches = [f for f in findings if "one character per line" in f.detail]
    assert len(matches) == 1, findings
    finding = matches[0]
    assert finding.check == "L12"
    assert finding.severity == "medium"
    assert "'OK'" in finding.detail
    assert "12.0px" in finding.detail
    assert finding.fingerprint.startswith("wk-L12-l12-fixture-390-light-")


def test_hyphenated_cve_id_wrapping_at_hyphen_is_not_reported(l12_fixture_page):
    findings = check_l12(l12_fixture_page, "/l12-fixture", 390, "light")
    assert not any("CVE-2026-0001" in f.detail or "cve" in f.detail.lower()
                   for f in findings), findings


def test_wide_table_in_scrollable_wrapper_is_not_reported(l12_fixture_page):
    findings = check_l12(l12_fixture_page, "/l12-fixture", 390, "light")
    # Card 3's table is the one over-wide table exempted by the scrollable
    # wrapper; only card 4's un-wrapped table (a distinct selector path,
    # `div:nth-of-type(4) > ...`) may still be reported for a wide table.
    assert not any("div:nth-of-type(3)" in f.detail for f in findings), findings


def test_wide_table_without_scroll_wrapper_is_reported(l12_fixture_page):
    findings = check_l12(l12_fixture_page, "/l12-fixture", 390, "light")
    matches = [f for f in findings if f.check == "L12" and "scrollWidth 500" in f.detail]
    assert len(matches) == 1, findings
    finding = matches[0]
    assert "neither a stacked .table-stack table" in finding.detail
    assert finding.severity == "medium"


def test_stacked_table_is_not_reported(l12_fixture_page):
    findings = check_l12(l12_fixture_page, "/l12-fixture", 390, "light")
    assert not any("Stacked row value" in f.detail for f in findings), findings
    assert not any("div:nth-of-type(5)" in f.detail for f in findings), findings


def test_l12_fixture_produces_exactly_the_expected_findings(l12_fixture_page):
    # Belt-and-suspenders on all five cases together: exactly the
    # one-char-per-line cell (card 1) and the un-wrapped wide table
    # (card 4), nothing else - cards 2 (hyphenated CVE), 3 (scrollable
    # wrapper) and 5 (stacked table) each surface nothing.
    findings = check_l12(l12_fixture_page, "/l12-fixture", 390, "light")
    assert len(findings) == 2, findings
    assert sum(1 for f in findings if "div:nth-of-type(1)" in f.detail) == 1, findings
    assert sum(1 for f in findings if "div:nth-of-type(4)" in f.detail) == 1, findings
    assert not any("div:nth-of-type(2)" in f.detail or "div:nth-of-type(3)" in f.detail
                   or "div:nth-of-type(5)" in f.detail for f in findings), findings


# ── L13 (portal-rubric.md, Andy ruling 2026-09-25, PAT-2155) ───────────────
#
# 1440px-only rubric check, generalising L11: no date-shaped run of text in
# any table cell renders across three or more lines. Two deliberate cases,
# each in its own `.card`:
#
#   1. a single unsplit "25 Sep 2026 11:42"-shaped text node in a table
#      column far too narrow for it (PAT-2155's own live defect: "Raised
#      wraps over four lines") - must be reported
#   2. the PAT-2140/PAT-2155 fix - the same date and time split into two
#      separate text nodes (cell-evidence__main/cell-subtle), each one
#      comfortably within a column wide enough to hold it on one line -
#      must NOT be reported
#
# Red-proof (verified by hand for this ticket, not kept as a permanent
# test): with check_l13's `page.evaluate(...)` result force-emptied (a
# stand-in for "the rule disabled"), test_narrow_unsplit_date_wrapping_
# over_two_lines_is_reported goes red - `findings` comes back empty.
# Restoring the real body (this diff) brings it back to green.

L13_FIXTURE_HTML = """<!doctype html>
<html>
<head><meta charset="utf-8"><title>Walker L13 fixture</title>
<style>
.card { width: 200px; border: 1px solid #ccc; padding: 8px; margin-bottom: 16px; }
.l13-narrow-table { table-layout: fixed; width: 20px; border-collapse: collapse; }
.l13-narrow-table td { overflow-wrap: break-word; }
.l13-split-table { table-layout: fixed; width: 120px; border-collapse: collapse; }
.cell-evidence__main { display: block; }
.cell-subtle { display: block; }
</style>
</head>
<body>

<div class="card">
  <table class="l13-narrow-table"><tbody><tr>
    <td>25 Sep 2026 11:42</td>
  </tr></tbody></table>
</div>

<div class="card">
  <table class="l13-split-table"><tbody><tr>
    <td><span class="cell-evidence__main">25 Sep 2026</span>
      <span class="cell-subtle">11:42 UTC</span></td>
  </tr></tbody></table>
</div>

</body>
</html>"""


class _L13FixtureHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = L13_FIXTURE_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # keep pytest -q output quiet - no per-request access log


@pytest.fixture(scope="module")
def l13_fixture_url():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _L13FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()


@pytest.fixture
def l13_fixture_page(browser, l13_fixture_url):
    context = browser.new_context()
    page = context.new_page()
    # L13 is a 1440px-only rule (unlike L12's 390px), matching the walker's
    # own desktop pass.
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(l13_fixture_url)
    yield page
    context.close()


def test_narrow_unsplit_date_wrapping_over_two_lines_is_reported(l13_fixture_page):
    findings = check_l13(l13_fixture_page, "/l13-fixture", 1440, "light")
    assert len(findings) == 1, findings
    finding = findings[0]
    assert finding.check == "L13"
    assert finding.severity == "medium"
    assert "25 Sep 2026 11:42" in finding.detail
    assert finding.fingerprint.startswith("wk-L13-l13-fixture-1440-light-")


def test_split_date_time_cell_is_not_reported(l13_fixture_page):
    findings = check_l13(l13_fixture_page, "/l13-fixture", 1440, "light")
    # Belt-and-suspenders: the only finding at all is the unsplit table's -
    # the split date/time cell (card 2) surfaces nothing.
    assert len(findings) == 1, findings
    assert not any("11:42 UTC" in f.detail for f in findings), findings


# ── L13 at its binding 1280px width (PAT-2162) ──────────────────────────────
#
# The fixtures above prove check_l13 itself works at 1440px. They don't
# prove the walker ever RUNS it at 1280px - before PAT-2162, walk.py's
# _walk_one gated check_l13 to width == 1440 only, and 1440px was never
# actually the rubric's binding width (docs/portal-rubric.md: "... at
# 1280px width"). This fixture's table column is narrower at <=1350px
# viewports than above it (a max-width media query, standing in for the
# real portal's rail-adjusted content width shrinking with the viewport),
# so its date cell wraps to 3 lines at 1280px but sits on one line at
# 1440px - a defect check_l13 can only ever catch if something actually
# calls it at 1280px.
#
# Red-proof (verified by hand for PAT-2162, run for real below): against
# unmodified main, walk.py has no _walk_l13 function and no L13_WIDTH
# constant, so test_walker_1280_pass_reports_a_date_cell_that_only_wraps_
# at_1280px fails with AttributeError - not because the fixture is wrong,
# but because nothing in the walker checks L13 at 1280px at all.

L13_AT_1280_FIXTURE_HTML = """<!doctype html>
<html>
<head><meta charset="utf-8"><title>Walker L13-at-1280 fixture</title>
<style>
body { margin: 0; font-family: monospace; font-size: 14px; }
.card { width: 220px; border: 1px solid #ccc; padding: 8px; }
.l13-1280-table { table-layout: fixed; width: 100%; border-collapse: collapse; }
.l13-1280-table td { overflow-wrap: break-word; }
/* Narrower column at <=1350px (covers the walker's 1280px pass), wider
   above it (covers 1440px) - the same viewport-narrows-the-column shape
   the real portal's rail-adjusted layout produces, without depending on
   any real route or fixture data. */
@media (max-width: 1350px) {
  .l13-1280-table { width: 70px; }
}
@media (min-width: 1351px) {
  .l13-1280-table { width: 200px; }
}
</style>
</head>
<body>

<div class="card">
  <table class="l13-1280-table"><tbody><tr>
    <td>24 Sep 2026 10:00 UTC</td>
  </tr></tbody></table>
</div>

</body>
</html>"""


class _L13At1280FixtureHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = L13_AT_1280_FIXTURE_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # keep pytest -q output quiet - no per-request access log


@pytest.fixture(scope="module")
def l13_at_1280_fixture_url():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _L13At1280FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()


def test_walker_1280_pass_reports_a_date_cell_that_only_wraps_at_1280px(
        browser, l13_at_1280_fixture_url):
    """Exercises the walker's own 1280px L13 pass (_walk_l13), not
    check_l13 directly at a hand-set viewport - check_l13 doesn't care what
    width it's told it's running at, so calling it directly would pass
    trivially even on unmodified main. The point is whether the walker's
    OWN gating logic ever runs the check at 1280px at all; on unmodified
    main it does not (see red-proof note above)."""
    context = browser.new_context()
    try:
        findings = walk_module._walk_l13(
            context, l13_at_1280_fixture_url, "/l13-at-1280-fixture")
    finally:
        context.close()
    assert len(findings) == 1, findings
    finding = findings[0]
    assert finding.check == "L13"
    assert finding.width == walk_module.L13_WIDTH == 1280
    assert finding.theme == "light"
    assert "24 Sep 2026 10:00" in finding.detail
    assert "1280px" in finding.detail


def test_same_fixture_produces_no_l13_finding_at_1440px(browser, l13_at_1280_fixture_url):
    context = browser.new_context()
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1440, "height": 900})
        page.goto(l13_at_1280_fixture_url)
        findings = check_l13(page, "/l13-at-1280-fixture", 1440, "light")
    finally:
        context.close()
    assert findings == [], findings


# ── PAT-2257: checks (a)-(e) and the authenticated --prod walk ───────────
#
# One fixture server serves a page per check, each carrying both the defect
# and a near-identical control that must stay silent, so every test pins
# the exact finding count: a check that goes quiet (returns nothing) fails
# the "defect is reported" half, and a check that over-reports fails the
# count.
#
# Red-proof (verified by hand for PAT-2257, not kept as a permanent test):
# with each check's body replaced by `return []` in turn - check_cells,
# check_break, check_leak, check_theme_toggle, check_counts - exactly that
# check's `..._is_reported` tests go red (5 separate runs); with the prod
# guard's abort branch replaced by `route.continue_()`,
# test_prod_guard_aborts_every_write_and_scopes_the_credential goes red on
# the server having received a POST; with `_page_shows_secret` returning
# False, test_walk_one_never_screenshots_a_page_showing_the_secret goes red.
# Each goes green again once the real body is restored.

import io  # noqa: E402
import json as _json  # noqa: E402
from contextlib import redirect_stderr  # noqa: E402

from e2e.walk.walk import (  # noqa: E402
    COPY_BANNED_PATTERNS,
    LEAK_PATTERNS,
    ProdConfigError,
    ProdCredentials,
    check_break,
    check_cells,
    check_counts,
    check_leak,
    check_theme_toggle,
    install_prod_guard,
    prod_credentials_from_env,
    prod_request_headers,
    redact,
    validate_prod_base_url,
    write_report,
)

# Low-entropy placeholders; never a real credential.
FAKE_ID = "walker-id-placeholder.access"
FAKE_SECRET = "walker-secret-placeholder"

CELLS_HTML = """<!doctype html><html><head><meta charset="utf-8"></head><body>
<table style="table-layout: fixed; width: 300px; border-collapse: collapse; font: 14px sans-serif">
  <tr><td style="width: 100px; white-space: nowrap">22631.3880-a-long-unbroken-build-label</td>
      <td style="width: 200px">spilled into</td></tr>
  <tr><td style="width: 100px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis"
          title="22631.3880-a-long-unbroken-build-label">22631.3880-a-long-unbroken-build-label</td>
      <td style="width: 200px">clipped, fine</td></tr>
  <tr><td style="width: 100px"><span style="display: block; overflow: hidden;
          white-space: nowrap">22631.3880-a-long-unbroken-build-label</span></td>
      <td style="width: 200px">clipped by a span, fine</td></tr>
  <tr><td style="width: 100px">short</td><td style="width: 200px">wraps normally</td></tr>
</table>
</body></html>"""

BREAK_HTML = """<!doctype html><html><head><meta charset="utf-8"></head><body
 style="font: 16px monospace">
<p id="v" style="width: 50px; word-break: break-all">22631.3880</p>
<p id="d" style="width: 60px">25 Sep 2026</p>
<p id="vok" style="width: 50px; white-space: nowrap">0.19.24</p>
<p id="dok" style="width: 120px"><span>25 Sep 2026</span><br><span>10:00</span></p>
<p id="wide">Build 22631.3880 released on 2026-09-25 with agent 0.19.24</p>
</body></html>"""

LEAK_HTML = """<!doctype html><html><head><meta charset="utf-8"></head><body>
<p id="ref">Tracked in PAT-1234 for now.</p>
<p id="word">Raise a ticket with support.</p>
<table><tr><td id="guid">ab23bec8-563f-4c07-a878-c48ab3d79c90</td></tr></table>
<p id="dash">Estate -- overview</p>
<span id="attr" title="See PAT-99">i</span>
<p data-walker-ignore>PAT-1 is allowed here</p>
<pre><code>patched-agent --enrol</code></pre>
<p style="display: none">PAT-2 hidden from customers</p>
<p>Ticketing tools such as Jira can receive findings.</p>
<p>Estate - overview, with a plain hyphen</p>
</body></html>"""


# PAT-2509: a source's machine name (`curated_catalogue`) read as internal
# wording in the Version sprawl "Latest released" cell. The cell is a <td>,
# which check_copy skips, so check_leak (every text node and the title,
# aria-label, alt and placeholder attributes) is what catches it there.
MACHINE_NAME_HTML = """<!doctype html><html><head><meta charset="utf-8"></head><body>
<h2 id="heading">Source: curated_catalogue</h2>
<table><tr><td id="cell">2.1.0 <span>curated_catalogue</span></td></tr></table>
<span id="attr" title="from curated_catalogue">i</span>
<p data-walker-ignore>curated_catalogue is allowed here</p>
</body></html>"""

MACHINE_NAME_OK_HTML = """<!doctype html><html><head><meta charset="utf-8"></head><body>
<h2>Source: Patched reference list</h2>
<table><tr><td>2.1.0 <span>Patched reference list, checked 05 Oct 2026</span></td></tr></table>
</body></html>"""


def _toggle_page(data_theme, active_choice, same_paint=False, missing=False):
    if missing:
        return "<!doctype html><html><body><p>no toggle</p></body></html>"
    buttons = []
    for choice in ("light", "dark"):
        active = choice == active_choice
        style = "" if not active or same_paint else "background: rgb(0, 0, 0); color: white"
        buttons.append(
            f'<button class="theme-toggle__btn{" is-active" if active else ""}" '
            f'data-theme-choice="{choice}" aria-pressed="{"true" if active else "false"}" '
            f'style="{style}">{choice}</button>')
    return (f'<!doctype html><html data-theme="{data_theme}"><body>'
            f'<div class="theme-toggle" role="group">{"".join(buttons)}</div></body></html>')


COUNTS_HTML = """<!doctype html><html><head><meta charset="utf-8"></head><body><main>
<div class="card"><p>96 awaiting approval</p></div>
<section class="strip"><h3>Awaiting approval</h3><span>95</span></section>
<div><p>12 extensions waiting on a decision</p><p>96 products waiting on a decision</p></div>
<div><p>3 not reporting</p></div>
<div class="tab">Not reporting (3)</div>
<p data-walker-ignore>7 awaiting approval</p>
</main></body></html>"""

# PAT-2255: a list cell that truncates an MSI product code still leaks it,
# and the Overview's two phrasings of the awaiting-decision figure are
# compared as one count. Each page pairs the defect with controls.
LEAK_LIST_HTML = """<!doctype html><html><head><meta charset="utf-8"></head><body>
<table>
  <tr><td id="msi"><span style="display: block; width: 120px; overflow: hidden;
      text-overflow: ellipsis; white-space: nowrap">{AC76BA86-1033-FF00-7760-BC1501</span></td></tr>
  <tr><td id="version">10.0.19045.4894</td></tr>
  <tr><td id="date">2026-09-25</td></tr>
  <tr><td id="hash">deadbeef</td></tr>
</table>
</body></html>"""

COUNTS_AWAITING_BAD_HTML = """<!doctype html><html><head><meta charset="utf-8"></head><body><main>
<div class="top3"><p>Decide on 128 products waiting for an approval decision</p></div>
<div class="glance"><p>140 products waiting on an approval decision.</p></div>
</main></body></html>"""

COUNTS_AWAITING_OK_HTML = """<!doctype html><html><head><meta charset="utf-8"></head><body><main>
<div class="top3"><p>Decide on 140 products waiting for an approval decision</p></div>
<div class="glance"><p>140 products waiting on an approval decision.</p></div>
<div class="ext"><p>12 extensions waiting on a decision</p></div>
</main></body></html>"""

SECRET_HTML = (f"<!doctype html><html><body><p>debug: {FAKE_SECRET}</p>"
               "</body></html>")

PAT2257_PAGES = {
    "/cells": CELLS_HTML,
    "/break": BREAK_HTML,
    "/leak": LEAK_HTML,
    "/toggle-ok": _toggle_page("dark", "dark"),
    "/toggle-none": _toggle_page("dark", None),
    "/toggle-wrong": _toggle_page("dark", "light"),
    "/toggle-same-paint": _toggle_page("dark", "dark", same_paint=True),
    "/toggle-missing": _toggle_page("dark", "dark", missing=True),
    "/counts": COUNTS_HTML,
    "/leak-list": LEAK_LIST_HTML,
    "/machine-name": MACHINE_NAME_HTML,
    "/machine-name-ok": MACHINE_NAME_OK_HTML,
    "/counts-awaiting-bad": COUNTS_AWAITING_BAD_HTML,
    "/counts-awaiting-ok": COUNTS_AWAITING_OK_HTML,
    "/secret": SECRET_HTML,
    "/writer": """<!doctype html><html><body>
<form id="f" method="post" action="/approve"><input name="state" value="approved">
<button type="submit" id="go">Approve</button></form>
<img src="/pixel.gif" alt="">
<script>
  fetch('/approve', {method: 'POST', body: 'state=approved'}).catch(() => {});
  fetch(window.OTHER_ORIGIN + '/ping', {mode: 'no-cors'}).catch(() => {});
  document.getElementById('f').submit();
  document.getElementById('go').click();
</script></body></html>""",
}


def _recording_handler(pages, log):
    class _Handler(http.server.BaseHTTPRequestHandler):
        def _serve(self):
            log.append({"method": self.command, "path": self.path,
                        "headers": {k.lower(): v for k, v in self.headers.items()}})
            body = pages.get(self.path.split("?", 1)[0], "").encode("utf-8")
            if self.command == "POST":
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
            self.send_response(200 if body or self.command != "GET" else 404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_HEAD = _serve

        def log_message(self, format, *args):
            pass

    return _Handler


def _serve(pages, log):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _recording_handler(pages, log))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


@pytest.fixture(scope="module")
def pat2257_server():
    log = []
    server, url = _serve(PAT2257_PAGES, log)
    try:
        yield url, log
    finally:
        server.shutdown()


@pytest.fixture
def open_page(browser, pat2257_server):
    base, _ = pat2257_server
    contexts = []

    def _open(path, width=1440):
        context = browser.new_context()
        contexts.append(context)
        page = context.new_page()
        page.set_viewport_size({"width": width, "height": 900})
        page.goto(base + path)
        return page

    yield _open
    for context in contexts:
        context.close()


# (a) cells

def test_cell_spilling_into_its_neighbour_is_reported(open_page):
    findings = check_cells(open_page("/cells"), "/cells", 1440, "light")
    assert len(findings) == 1, findings
    assert findings[0].check == "cells"
    assert "tr:nth-of-type(1)" in findings[0].detail
    assert "spilled into" in findings[0].detail


# (b) break

def test_version_and_date_breaking_mid_string_are_reported(open_page):
    findings = check_break(open_page("/break"), "/break", 390, "light")
    got = sorted((f.detail.split(": ", 1)[1].split(" breaks")[0]) for f in findings)
    assert got == ["date '25 Sep 2026'", "version '22631.3880'"], findings
    assert all(f.check == "break" for f in findings)


# (c) leak

def test_internal_references_in_customer_text_are_reported(open_page):
    findings = check_leak(open_page("/leak"), "/leak", 1440, "light")
    names = sorted(f.detail.split(": ", 1)[1].split(" ", 1)[0] for f in findings)
    assert names == ["double-hyphen", "guid", "ticket-ref", "ticket-ref", "ticket-word"], findings
    details = " ".join(f.detail for f in findings)
    assert "#ref" in details or "p:nth-of-type(1)" in details
    assert "[title]" in details
    assert "--enrol" not in details          # code is exempt from `--`
    assert "PAT-1 " not in details and "PAT-2" not in details  # ignored / hidden


# (d) theme toggle

def test_theme_toggle_with_correct_active_state_is_clean(open_page):
    assert check_theme_toggle(open_page("/toggle-ok"), "/t", 1440, "dark") == []


@pytest.mark.parametrize("path,needle", [
    ("/toggle-none", "0 theme buttons"),
    ("/toggle-wrong", "shown active but the page is in 'dark'"),
    ("/toggle-same-paint", "looks identical"),
    ("/toggle-missing", "no theme toggle"),
])
def test_theme_toggle_without_a_true_active_state_is_reported(open_page, path, needle):
    findings = check_theme_toggle(open_page(path), path, 1440, "dark")
    assert len(findings) == 1, findings
    assert findings[0].check == "theme-toggle"
    assert needle in findings[0].detail


# (e) counts

def test_the_same_named_count_disagreeing_is_reported(open_page):
    findings = check_counts(open_page("/counts"), "/counts", 1440, "light")
    assert len(findings) == 1, findings
    assert findings[0].check == "count-mismatch"
    assert findings[0].severity == "high"
    assert "'awaiting approval'" in findings[0].detail
    assert "95" in findings[0].detail and "96" in findings[0].detail


def test_a_truncated_guid_in_a_list_cell_is_reported(open_page):
    """PAT-2255 defect 3: the live /software list showed MSI product codes
    cut short by an ellipsis ("{AC76BA86-1033-FF00-7760-BC1501..."), which
    the whole-GUID pattern missed. Versions, dates and bare hex are not
    GUIDs and stay silent."""
    findings = check_leak(open_page("/leak-list"), "/leak-list", 1440, "light")
    assert len(findings) == 1, findings
    assert findings[0].check == "leak"
    assert "guid 'AC76BA86-1033-FF00-7760-BC1501'" in findings[0].detail
    assert "#msi" in findings[0].detail or "td" in findings[0].detail


# PAT-2509: the machine name of a latest-released source.

def test_both_banned_lists_reject_the_machine_name():
    """The pattern lists themselves, with no browser: a page containing the
    string is rejected by the copy list and by the leak list."""
    assert any(p.search("Source: curated_catalogue") for _, p in COPY_BANNED_PATTERNS)
    assert any(p.search("Source: Curated_Catalogue") for _, p in COPY_BANNED_PATTERNS)
    assert any(p.search("Source: curated_catalogue") for _, p in LEAK_PATTERNS)
    for _, pattern in (*COPY_BANNED_PATTERNS, *LEAK_PATTERNS):
        assert not pattern.search("Patched reference list, checked 05 Oct 2026")


def test_the_machine_name_in_text_outside_a_cell_is_a_copy_finding(open_page):
    findings = check_copy(open_page("/machine-name"), "/machine-name", 1440, "light")
    assert len(findings) == 1, findings
    assert findings[0].check == "copy"
    assert "'curated_catalogue'" in findings[0].detail
    assert "h2" in findings[0].detail


def test_the_machine_name_in_a_table_cell_is_a_leak_finding(open_page):
    """check_copy skips <td>, which is where the Latest released cell lives,
    so the copy list alone could never have failed on the real defect."""
    page = open_page("/machine-name")
    assert not [f for f in check_copy(page, "/machine-name", 1440, "light")
                if "td" in f.detail.split(":", 1)[0]]
    findings = check_leak(page, "/machine-name", 1440, "light")
    assert sorted(f.detail.split(": ", 1)[1].split(" ", 1)[0] for f in findings) == [
        "machine-name", "machine-name", "machine-name"], findings
    selectors = " ".join(f.detail.split(":", 1)[0] for f in findings)
    assert "td" in selectors and "[title]" in selectors
    assert all(f.check == "leak" for f in findings)
    assert "allowed here" not in " ".join(f.detail for f in findings)


def test_plain_source_wording_is_clean(open_page):
    page = open_page("/machine-name-ok")
    assert check_copy(page, "/machine-name-ok", 1440, "light") == []
    assert check_leak(page, "/machine-name-ok", 1440, "light") == []


def test_the_overview_awaiting_decision_phrasings_are_one_count(open_page):
    """PAT-2255: Top 3 ("Decide on 128 products waiting for an approval
    decision") and the at-a-glance line ("140 products waiting on an
    approval decision") are the same figure; the walker now keys both on
    "products waiting" and reports them disagreeing."""
    findings = check_counts(open_page("/counts-awaiting-bad"), "/c", 1440, "light")
    assert len(findings) == 1, findings
    assert findings[0].check == "count-mismatch"
    assert "'products waiting'" in findings[0].detail
    assert "128" in findings[0].detail and "140" in findings[0].detail


def test_agreeing_awaiting_decision_phrasings_are_clean(open_page):
    assert check_counts(open_page("/counts-awaiting-ok"), "/c", 1440, "light") == []


def test_pat2257_checks_are_wired_into_every_walked_page():
    """_walk_one runs the five checks through check_pat2257 at every width."""
    import inspect
    src = inspect.getsource(walk_module._walk_one)
    # PAT-2285 adds `secrets=` so the leak check redacts before it truncates.
    assert "check_pat2257(page, route, width, theme, secrets=secrets)" in src
    body = inspect.getsource(walk_module.check_pat2257)
    for name in ("check_cells", "check_break", "check_leak", "check_theme_toggle",
                 "check_counts"):
        assert name in body


# ── --prod ────────────────────────────────────────────────────────────────

def test_prod_requires_both_env_vars_and_never_echoes_values():
    with pytest.raises(ProdConfigError) as exc:
        prod_credentials_from_env({"PORTAL_WALKER_CLIENT_ID": FAKE_ID})
    assert "PORTAL_WALKER_CLIENT_SECRET" in str(exc.value)
    assert FAKE_ID not in str(exc.value)
    creds = prod_credentials_from_env({"PORTAL_WALKER_CLIENT_ID": FAKE_ID,
                                       "PORTAL_WALKER_CLIENT_SECRET": FAKE_SECRET})
    assert FAKE_ID not in repr(creds) and FAKE_SECRET not in repr(creds)
    assert FAKE_SECRET not in str(creds)


def test_prod_cli_exits_2_without_credentials(monkeypatch):
    monkeypatch.delenv("PORTAL_WALKER_CLIENT_ID", raising=False)
    monkeypatch.setenv("PORTAL_WALKER_CLIENT_SECRET", FAKE_SECRET)
    err = io.StringIO()
    with redirect_stderr(err):
        code = walk_module.main(["--prod", "--routes", "/"])
    assert code == 2
    assert "PORTAL_WALKER_CLIENT_ID" in err.getvalue()
    assert FAKE_SECRET not in err.getvalue()


@pytest.mark.parametrize("url,ok", [
    ("https://app.patched.im", True),
    ("https://app.patched.im/", True),
    ("http://127.0.0.1:8123", True),
    ("http://app.patched.im", False),
    ("https://app.patched.im/devices", False),
    ("ftp://app.patched.im", False),
])
def test_prod_base_url_must_be_an_https_origin(url, ok):
    if ok:
        assert validate_prod_base_url(url).startswith(("https://", "http://127.0.0.1"))
    else:
        with pytest.raises(ProdConfigError):
            validate_prod_base_url(url)


def test_credential_headers_go_to_the_portal_origin_only():
    creds = ProdCredentials(FAKE_ID, FAKE_SECRET)
    base = "https://app.patched.im"
    assert prod_request_headers("https://app.patched.im/devices?x=1", base, creds) == {
        "CF-Access-Client-Id": FAKE_ID, "CF-Access-Client-Secret": FAKE_SECRET}
    for other in ("https://fonts.googleapis.com/css", "https://example-team.cloudflareaccess.com/x",
                  "http://app.patched.im/", "https://app.patched.im.evil.example/",
                  "https://app.patched.im:8443/"):
        assert prod_request_headers(other, base, creds) == {}, other


def test_report_and_summary_are_redacted(tmp_path):
    finding = walk_module.Finding(
        fingerprint="wk-console-root-1440-light-x", check="console", route="/", width=1440,
        theme="light", severity="medium", detail=f"failed request carrying {FAKE_SECRET}")
    path = write_report([finding], tmp_path, secrets=(FAKE_ID, FAKE_SECRET))
    text = path.read_text()
    assert FAKE_SECRET not in text and "[redacted]" in text
    assert _json.loads(text)[0]["check"] == "console"
    assert redact(f"x {FAKE_ID} y", (FAKE_ID,)) == "x [redacted] y"


def test_prod_guard_aborts_every_write_and_scopes_the_credential(browser):
    log, other_log = [], []
    server, base = _serve(PAT2257_PAGES, log)
    other, other_url = _serve({"/ping": "pong"}, other_log)
    blocked = []
    context = browser.new_context()
    try:
        install_prod_guard(context, base, ProdCredentials(FAKE_ID, FAKE_SECRET), blocked)
        context.add_init_script(f"window.OTHER_ORIGIN = {_json.dumps(other_url)};")
        page = context.new_page()
        page.goto(base + "/writer")
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(300)
    finally:
        context.close()
        server.shutdown()
        other.shutdown()
    methods = [e["method"] for e in log]
    assert "POST" not in methods, log
    assert any(b.startswith("POST ") and b.endswith("/approve") for b in blocked), blocked
    gets = [e for e in log if e["method"] == "GET"]
    assert gets and all(e["headers"].get("cf-access-client-id") == FAKE_ID for e in gets)
    assert all(e["headers"].get("cf-access-client-secret") == FAKE_SECRET for e in gets)
    # The other origin was reached without the credential.
    assert other_log, "cross-origin request never made - fixture broken"
    assert all("cf-access-client-id" not in e["headers"] for e in other_log)
    assert all("cf-access-client-secret" not in e["headers"] for e in other_log)


def test_walk_one_never_screenshots_a_page_showing_the_secret(
        browser, pat2257_server, tmp_path):
    base, _ = pat2257_server
    context = browser.new_context()
    try:
        findings = walk_module._walk_one(
            context, base, base + "/secret", "/secret", "light", 1280, tmp_path, {},
            secrets=(FAKE_ID, FAKE_SECRET), blocked=[])
    finally:
        context.close()
    exposure = [f for f in findings if f.check == "secret-exposure"]
    assert len(exposure) == 1, findings
    assert FAKE_SECRET not in exposure[0].detail
    assert list(tmp_path.glob("*.png")) == []
    assert all(f.screenshot is None for f in findings if f.width == 1280)


def test_prod_walk_matrix_covers_three_widths_and_both_themes():
    assert walk_module.PROD_WIDTHS == (1440, 1280, 390)
    assert walk_module.THEMES == ("light", "dark")
    assert walk_module.PROD_BASE_URL == "https://app.patched.im"
    for width in walk_module.PROD_WIDTHS:
        assert width in walk_module.VIEWPORT_HEIGHT_BY_WIDTH


# ── PAT-2285: pacing, the analytics beacon, and admin-only pages ─────────
#
# The first authenticated prod walk (PAT-2257) reported 163 findings, 146 of
# them walker noise: portal 429s from the walker's own request rate, the
# Cloudflare analytics beacon failing in headless Chromium, and admin-only
# pages answering 403 to the read-only service identity. Each class below has
# a defect case and a control that must stay a real finding, run through the
# real `_walk_one` / link check against a fixture server that plays the
# portal (a 429 the first time, a 429 forever, a 403, a 500).
#
# Red-proof (recorded on the PAT-2285 ticket): the tests below were written
# and run first against the unmodified walker. The behavioural ones (429,
# beacon, 403 through `_walk_one` and `check_console`) failed by reporting
# the noise this ticket removes; the ones that name new API (`Pacing`,
# `retry_after_seconds`, the `service_identity` and `pacing` keywords) failed
# on the missing name.

PAT2285_OK_PAGE = _toggle_page("light", "light").replace(
    "<html", '<html lang="en"', 1).replace(
    "<body>", '<head><meta charset="utf-8"><link rel="icon" href="data:,"></head><body>'
              '<p>Overview</p>', 1)
PAT2285_BEACON = "https://static.cloudflareinsights.com/beacon.min.js"
PAT2285_OTHER_HOST = "https://tracker.example.test/collect.js"


def _pat2285_page(script_src=None):
    extra = f'<script src="{script_src}" defer></script>' if script_src else ""
    return PAT2285_OK_PAGE.replace("</body>", extra + "</body>")


class _PaceServer:
    """A fixture 'portal'. `rules[path](n, nav)` returns (status, headers, body),
    where `n` counts this path's earlier requests of the same kind (`nav` is
    True for a browser navigation, False for the walker's API fetches)."""

    def __init__(self):
        self.log = []
        self._counts = {}
        outer = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                path = self.path.split("?", 1)[0]
                nav = self.headers.get("Sec-Fetch-Dest") == "document"
                key = (path, nav)
                outer._counts[key] = outer._counts.get(key, 0) + 1
                outer.log.append({"path": path, "nav": nav})
                rule = outer.rules.get(path)
                if rule is None:
                    status, headers, body = 404, {}, "not found"
                else:
                    status, headers, body = rule(outer._counts[key], nav)
                if status == "stall":
                    # Headers and a few bytes, then silence.
                    self.send_response(200)
                    self.send_header("Content-Length", "100")
                    self.end_headers()
                    self.wfile.write(b"x" * 10)
                    self.wfile.flush()
                    time.sleep(3)
                    return
                if status == "slow":
                    time.sleep(0.4)
                    status = 200
                if status == "reset":
                    # Promise 100 bytes, send 10, hang up: a transport error.
                    self.send_response(200)
                    self.send_header("Content-Length", "100")
                    self.end_headers()
                    self.wfile.write(b"x" * 10)
                    self.wfile.flush()
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                payload = body.encode("utf-8")
                self.send_response(status)
                ctype = "application/javascript" if path.endswith(".js") else "text/html"
                self.send_header("Content-Type", f"{ctype}; charset=utf-8")
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format, *args):
                pass

        limited = (429, {"Retry-After": "0"}, "<html><body>Slow down</body></html>")
        page = (200, {}, PAT2285_OK_PAGE)
        self.rules = {
            "/ok": lambda n, nav: page,
            # Only the very first request is throttled: the probe's retry succeeds.
            "/flaky": lambda n, nav: limited if self.seen("/flaky") == 1 else page,
            # The probe is fine; the first browser navigation is throttled.
            "/flaky-nav": lambda n, nav: limited if nav and n == 1 else page,
            "/limited": lambda n, nav: limited,
            "/limited-nav": lambda n, nav: limited if nav else page,
            "/limited-sub": lambda n, nav: (200, {}, _pat2285_page("/limited.js")),
            "/limited.js": lambda n, nav: limited,
            "/admin-only": lambda n, nav: (403, {}, "<html><body>Admins only</body></html>"),
            "/boom": lambda n, nav: (500, {}, "<html><body>boom</body></html>"),
            "/beacon-only": lambda n, nav: (200, {}, _pat2285_page(PAT2285_BEACON)),
            "/other-host-only": lambda n, nav: (200, {}, _pat2285_page(PAT2285_OTHER_HOST)),
            "/flaky-link": lambda n, nav: limited if n == 1 else page,
            "/stall": lambda n, nav: ("stall", {}, ""),
            "/slow": lambda n, nav: ("slow", {}, PAT2285_OK_PAGE),
            "/reset": lambda n, nav: ("reset", {}, ""),
            "/reset-once": lambda n, nav: ("reset", {}, "") if n == 1 else page,
        }
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"

    def seen(self, path):
        """How many requests `path` has had so far, this one included."""
        return len(self.requests(path))

    def requests(self, path):
        return [e for e in self.log if e["path"] == path]

    def close(self):
        self._server.shutdown()


@pytest.fixture
def pace_server():
    server = _PaceServer()
    try:
        yield server
    finally:
        server.close()


@pytest.fixture
def pace_context(browser):
    context = browser.new_context()
    # The two third-party hosts are refused, as they are in headless Chromium
    # against the live portal (connection refused), so the walker sees real
    # console errors and failed requests without any network access.
    for host in ("static.cloudflareinsights.com", "tracker.example.test"):
        context.route(f"https://{host}/**", lambda route: route.abort("connectionrefused"))
    yield context
    context.close()


def _walk_pace_route(context, server, path, tmp_path, **kwargs):
    return walk_module._walk_one(
        context, server.url, server.url + path, path, "light", 1280, tmp_path, {}, **kwargs)


# 1. Rate limiting: retry once, then a distinct class

def test_a_429_that_clears_on_retry_produces_no_finding(pace_server, pace_context, tmp_path):
    findings = _walk_pace_route(pace_context, pace_server, "/flaky", tmp_path)
    assert findings == [], findings
    assert len(pace_server.requests("/flaky")) >= 3  # 429, the retried 200, then the page load


def test_a_429_on_the_page_load_that_clears_on_retry_produces_no_finding(
        pace_server, pace_context, tmp_path):
    findings = _walk_pace_route(pace_context, pace_server, "/flaky-nav", tmp_path)
    assert findings == [], findings
    assert len([e for e in pace_server.requests("/flaky-nav") if e["nav"]]) == 2


def test_a_persistent_429_is_rate_limited_not_a_status_failure(
        pace_server, pace_context, tmp_path):
    findings = _walk_pace_route(pace_context, pace_server, "/limited", tmp_path)
    assert [f.check for f in findings] == ["rate-limited"], findings
    assert "429" in findings[0].detail and "/limited" in findings[0].detail
    assert findings[0].severity == "low"
    assert len(pace_server.requests("/limited")) == 2  # retried once, not hammered


def test_a_persistent_429_on_the_page_load_is_rate_limited_and_the_page_is_not_checked(
        pace_server, pace_context, tmp_path):
    findings = _walk_pace_route(pace_context, pace_server, "/limited-nav", tmp_path)
    assert {f.check for f in findings} == {"rate-limited"}, findings
    assert list(tmp_path.glob("*.png")) == []  # a throttled page is not a page to judge


def test_a_persistent_429_on_a_subresource_is_rate_limited_not_a_console_error(
        pace_server, pace_context, tmp_path):
    findings = _walk_pace_route(pace_context, pace_server, "/limited-sub", tmp_path)
    assert {f.check for f in findings} == {"rate-limited"}, findings
    assert "/limited.js" in findings[0].detail


@pytest.mark.parametrize("path,code", [("/boom", "500"), ("/missing", "404")])
def test_other_failing_statuses_are_still_status_findings(
        pace_server, pace_context, tmp_path, path, code):
    findings = _walk_pace_route(pace_context, pace_server, path, tmp_path)
    assert [f.check for f in findings] == ["status"], findings
    assert code in findings[0].detail


def test_check_status_classifies_429_apart_from_every_other_failure():
    limited = walk_module.check_status(429, "/devices", 1440, "light")
    assert [f.check for f in limited] == ["rate-limited"]
    assert limited[0].fingerprint.startswith("wk-rate-limited-devices-1440-light")
    assert [f.check for f in walk_module.check_status(500, "/devices", 1440, "light")] == ["status"]
    assert walk_module.check_status(200, "/devices", 1440, "light") == []


def test_the_walker_honours_retry_after_and_retries_once(pace_server, pace_context, tmp_path):
    pace_server.rules["/flaky"] = lambda n, nav: (
        (429, {"Retry-After": "7"}, "slow") if n == 1 and not nav
        else (200, {}, PAT2285_OK_PAGE))
    sleeps = []
    pacing = walk_module.Pacing(sleep=sleeps.append)
    findings = _walk_pace_route(pace_context, pace_server, "/flaky", tmp_path, pacing=pacing)
    assert findings == [], findings
    assert sleeps == [7.0]


@pytest.mark.parametrize("header,expected", [
    ({"retry-after": "3"}, 3.0),
    ({"retry-after": "0"}, 0.0),
    ({}, 12.0),                             # no header: the walker's own default
    ({"retry-after": "soon"}, 12.0),        # unparseable: the default, never a crash
    ({"retry-after": "-4"}, 0.0),
    ({"retry-after": "9999"}, 60.0),        # capped, so a bad header cannot stall a walk
])
def test_retry_after_seconds(header, expected):
    assert walk_module.retry_after_seconds(header, default=12.0, cap=60.0) == expected


def test_pacing_spaces_authenticated_requests_and_the_stub_default_does_not():
    now = [100.0]
    sleeps = []

    def _sleep(seconds):
        sleeps.append(seconds)
        now[0] += seconds

    pacing = walk_module.Pacing(interval=2.0, sleep=_sleep, clock=lambda: now[0])
    pacing.wait()                       # first request: nothing to wait for
    assert sleeps == []
    now[0] += 0.5
    pacing.wait()                       # 0.5s since the last one: wait out the rest
    assert sleeps == [1.5]
    now[0] += 5.0
    pacing.wait()                       # already slower than the interval
    assert sleeps == [1.5]

    stub = walk_module.Pacing(sleep=sleeps.append)
    for _ in range(5):
        stub.wait()
    assert sleeps == [1.5], "the default (stub walk) must never pace"


def test_the_prod_walk_paces_every_authenticated_request(browser, pace_server, tmp_path):
    """Run the real prod route walk (`run_prod_walk` minus the browser launch)
    against the fixture 'portal' with a recording sleep and a frozen clock:
    every authenticated request after the first is preceded by one full
    interval."""
    sleeps = []
    pacing = walk_module.Pacing(interval=2.5, sleep=sleeps.append, clock=lambda: 0.0)
    creds = ProdCredentials(FAKE_ID, FAKE_SECRET)
    messages, checkpoints = [], []
    findings = walk_module.walk_prod_routes(
        browser, walk_module.validate_prod_base_url(pace_server.url), creds, ["/ok"],
        out_dir=tmp_path, pacing=pacing, progress=messages.append,
        checkpoint=lambda so_far: checkpoints.append(list(so_far)))
    assert [f for f in findings if f.check not in ("auth",)] == [], findings
    # A long walk reports where it is, and saves what it has before the link phase.
    assert any("/ok" in m for m in messages), messages
    assert len(checkpoints) == 1, checkpoints
    # /ok is not a phone-supported route, so it is walked at 1440 and 1280 only
    # (PAT-2329): 2 themes x 2 widths = 4 page loads, each a probe plus a navigation.
    page_loads = len(walk_module.THEMES) * len(walk_module.prod_widths_for_path("/ok"))
    assert page_loads == 4
    assert len(sleeps) >= 2 * page_loads - 1, sleeps
    assert set(sleeps) == {2.5}
    assert walk_module.PROD_PACE_SECONDS > 0


def test_pace_flag_rejects_a_negative_interval(capsys):
    with pytest.raises(SystemExit) as exit_info:
        walk_module.main(["--prod", "--pace", "-1"])
    assert exit_info.value.code == 2
    assert "--pace must not be negative" in capsys.readouterr().err


# 2. Cloudflare's analytics beacon

def test_check_console_ignores_the_beacon_host_and_only_that_host():
    beacon_failure = f"GET {PAT2285_BEACON} -> net::ERR_CONNECTION_REFUSED"
    beacon_console = f"Refused to load the script '{PAT2285_BEACON}' (analytics)"
    assert walk_module.check_console([beacon_console], [beacon_failure], "/", 1440, "light") == []

    other_failure = f"GET {PAT2285_OTHER_HOST} -> net::ERR_CONNECTION_REFUSED"
    found = walk_module.check_console([], [other_failure], "/", 1440, "light")
    assert [f.check for f in found] == ["console"]
    assert walk_module.check_console(["boom at app.js:1"], [], "/", 1440, "light")

    # Exact host only: neither a lookalike nor a message that also names another host.
    for lookalike in ("https://static.cloudflareinsights.com.evil.test/beacon.min.js",
                      "https://evilstatic.cloudflareinsights.com/beacon.min.js",
                      "https://cloudflareinsights.com/beacon.min.js"):
        failed = [f"GET {lookalike} -> x"]
        assert walk_module.check_console([], failed, "/", 1440, "light"), lookalike
    mixed = f"Refused to connect to '{PAT2285_OTHER_HOST}?next={PAT2285_BEACON}'"
    assert walk_module.check_console([mixed], [], "/", 1440, "light")


def test_the_beacon_failing_in_the_browser_produces_no_finding(
        pace_server, pace_context, tmp_path):
    findings = _walk_pace_route(pace_context, pace_server, "/beacon-only", tmp_path)
    assert findings == [], findings


def test_another_host_failing_in_the_browser_is_still_a_console_finding(
        pace_server, pace_context, tmp_path):
    findings = _walk_pace_route(pace_context, pace_server, "/other-host-only", tmp_path)
    assert findings, "a non-beacon third-party failure must still be reported"
    assert {f.check for f in findings} == {"console"}, findings
    assert any("tracker.example.test" in f.detail or "ERR_CONNECTION_REFUSED" in f.detail
               for f in findings)


# 3. Admin-only pages are not visible to the read-only service identity

def test_a_403_to_the_service_identity_is_not_visible_not_a_broken_page():
    found = walk_module.check_status(403, "/local-admins", 1440, "light", service_identity=True)
    assert [f.check for f in found] == ["not-visible"]
    assert "service identity" in found[0].detail and "403" in found[0].detail
    assert found[0].severity == "low"
    # Outside the prod service-identity walk a 403 keeps its meaning.
    assert [f.check for f in walk_module.check_status(403, "/local-admins", 1440, "light")] == [
        "status"]
    for status in (401, 404, 500, 502):
        got = walk_module.check_status(status, "/x", 1440, "light", service_identity=True)
        assert [f.check for f in got] == ["status"], status


def test_the_service_identity_403_on_a_walked_page_is_not_visible(
        pace_server, pace_context, tmp_path):
    findings = _walk_pace_route(
        pace_context, pace_server, "/admin-only", tmp_path, service_identity=True)
    assert [f.check for f in findings] == ["not-visible"], findings
    # The stub walk has no such identity: same page, same 403, still a status failure.
    stub = _walk_pace_route(pace_context, pace_server, "/admin-only", tmp_path)
    assert [f.check for f in stub] == ["status"], stub


def test_a_500_is_still_a_status_failure_for_the_service_identity(
        pace_server, pace_context, tmp_path):
    findings = _walk_pace_route(
        pace_context, pace_server, "/boom", tmp_path, service_identity=True)
    assert [f.check for f in findings] == ["status"], findings


# 4. The link check gets the same three treatments

def _link_owner(server, *paths):
    return {f"{server.url}{p}": ("/", 1440, "light") for p in paths}


def test_link_check_retries_a_429_and_reports_a_persistent_one_apart(
        pace_server, pace_context, tmp_path):
    flaky = walk_module.check_internal_links(
        pace_context, _link_owner(pace_server, "/flaky-link"), pacing=walk_module.Pacing())
    assert flaky == [], flaky
    persistent = walk_module.check_internal_links(
        pace_context, _link_owner(pace_server, "/limited"), pacing=walk_module.Pacing())
    assert [f.check for f in persistent] == ["rate-limited"], persistent
    assert len(pace_server.requests("/limited")) == 2


def test_link_check_403_is_not_visible_only_for_the_service_identity(
        pace_server, pace_context):
    owner = _link_owner(pace_server, "/admin-only")
    got = walk_module.check_internal_links(
        pace_context, owner, pacing=walk_module.Pacing(), service_identity=True)
    assert [f.check for f in got] == ["not-visible"], got
    stub = walk_module.check_internal_links(pace_context, owner, pacing=walk_module.Pacing())
    assert [f.check for f in stub] == ["link"], stub


@pytest.mark.parametrize("path", ["/boom", "/missing"])
def test_link_check_404_and_500_are_still_link_findings(pace_server, pace_context, path):
    got = walk_module.check_internal_links(
        pace_context, _link_owner(pace_server, path), pacing=walk_module.Pacing(),
        service_identity=True)
    assert [f.check for f in got] == ["link"], got


# 5. A dropped connection must neither crash the walk nor print the credential
#
# The first live run of this ticket lost a ten minute walk at its last step:
# one link fetch failed in transit, Playwright raised, and the traceback it
# printed carried the request headers, credential included. A failed fetch is
# now retried once and then a finding; nothing that escapes is printed raw.

def _quick_pacing():
    return walk_module.Pacing(error_backoff=0.0)


def test_a_dropped_link_fetch_is_retried_once_and_then_a_finding_not_a_crash(
        pace_server, pace_context):
    flaky = walk_module.check_internal_links(
        pace_context, _link_owner(pace_server, "/reset-once"), pacing=_quick_pacing())
    assert flaky == [], flaky
    dropped = walk_module.check_internal_links(
        pace_context, _link_owner(pace_server, "/reset"), pacing=_quick_pacing())
    assert [f.check for f in dropped] == ["link"], dropped
    assert "could not be fetched" in dropped[0].detail
    assert len(pace_server.requests("/reset")) == 2


def test_a_dropped_probe_is_a_status_finding_not_a_crash(pace_server, pace_context, tmp_path):
    findings = _walk_pace_route(
        pace_context, pace_server, "/reset", tmp_path, pacing=_quick_pacing())
    assert [f.check for f in findings] == ["status"], findings
    assert "could not be fetched" in findings[0].detail


def test_a_fetch_failure_finding_never_carries_request_headers(pace_server, pace_context):
    creds = ProdCredentials(FAKE_ID, FAKE_SECRET)
    # Credentialed link checks go through fetch_portal (PAT-2293), so they
    # need the portal origin as well as the headers.
    found = walk_module.check_internal_links(
        pace_context, _link_owner(pace_server, "/reset"), pacing=_quick_pacing(),
        base_url=pace_server.url, headers=creds.headers())
    text = " ".join(f.detail for f in found)
    assert found and FAKE_SECRET not in text and FAKE_ID not in text
    assert "Call log" not in text
    assert "could not be fetched" in text
    assert len(pace_server.requests("/reset")) == 2  # retried once, inside the guard


def test_an_unexpected_prod_walk_error_is_printed_redacted_and_without_a_traceback(
        monkeypatch, capsys):
    monkeypatch.setenv("PORTAL_WALKER_CLIENT_ID", FAKE_ID)
    monkeypatch.setenv("PORTAL_WALKER_CLIENT_SECRET", FAKE_SECRET)

    def _boom(*args, **kwargs):
        raise RuntimeError(
            "APIRequestContext.get: aborted\nCall log:\n"
            f"  - CF-Access-Client-Id: {FAKE_ID}\n  - CF-Access-Client-Secret: {FAKE_SECRET}")

    monkeypatch.setattr(walk_module, "run_prod_walk", _boom)
    code = walk_module.main(["--prod", "--routes", "/"])
    captured = capsys.readouterr()
    assert code == 3
    output = captured.out + captured.err
    assert "aborted" in output
    assert FAKE_SECRET not in output and FAKE_ID not in output
    assert "Call log" not in output and "Traceback" not in output


# 6. The pace adapts: a 429 means this page costs the platform more than the
# interval allows for, so the walk slows down for the rest of the run.

def test_a_429_slows_the_pace_up_to_a_ceiling_and_the_unpaced_stub_stays_unpaced():
    pacing = walk_module.Pacing(interval=1.0, slow_step=1.0, max_interval=3.0)
    seen = []
    for _ in range(4):
        pacing.slow_down()
        seen.append(pacing.interval)
    assert seen == [2.0, 3.0, 3.0, 3.0]
    stub = walk_module.Pacing()
    stub.slow_down()
    assert stub.interval == 0.0


def test_fetching_a_429_slows_the_pace_and_a_clean_fetch_does_not(
        pace_server, pace_context):
    pacing = walk_module.Pacing(interval=1.0, sleep=lambda s: None, clock=lambda: 0.0)
    walk_module.check_internal_links(
        pace_context, _link_owner(pace_server, "/ok"), pacing=pacing)
    assert pacing.interval == 1.0
    walk_module.check_internal_links(
        pace_context, _link_owner(pace_server, "/flaky-link"), pacing=pacing)
    assert pacing.interval == 2.0


def test_a_429_on_the_page_load_slows_the_pace(pace_server, pace_context, tmp_path):
    pacing = walk_module.Pacing(interval=1.0, sleep=lambda s: None, clock=lambda: 0.0)
    _walk_pace_route(pace_context, pace_server, "/flaky-nav", tmp_path, pacing=pacing)
    assert pacing.interval == 2.0


# 7. A stalled link is bounded, not retried, and named while the walk runs

def test_a_stalled_link_times_out_once_and_is_a_finding(
        pace_server, pace_context, monkeypatch):
    monkeypatch.setattr(walk_module, "FETCH_TIMEOUT_MS", 500)
    started = time.monotonic()
    found = walk_module.check_internal_links(
        pace_context, _link_owner(pace_server, "/stall"), pacing=_quick_pacing())
    assert [f.check for f in found] == ["link"], found
    assert "could not be fetched" in found[0].detail
    assert any(message in found[0].detail for message in (
        "timed out", "Timeout 500ms exceeded.",
    )), found[0].detail
    assert len(pace_server.requests("/stall")) == 1, "a timeout is not retried"
    assert time.monotonic() - started < 2.5


def test_a_slow_link_and_a_failed_link_are_named_in_the_progress_output(
        pace_server, pace_context, monkeypatch):
    monkeypatch.setattr(walk_module, "SLOW_LINK_SECONDS", 0.1)
    messages = []
    walk_module.check_internal_links(
        pace_context, _link_owner(pace_server, "/slow", "/reset"), pacing=_quick_pacing(),
        progress=messages.append)
    assert any(m.startswith("slow link") and "/slow" in m for m in messages), messages
    assert any(m.startswith("link failed") and "/reset" in m for m in messages), messages


def test_probe_error_redacts_before_truncating_the_first_line(monkeypatch, tmp_path):
    # A secret straddling the 200-character cutoff cannot be scrubbed later
    # by write_report: the truncated prefix no longer matches the full value.
    def fail(*args, **kwargs):
        raise walk_module.PlaywrightError("x" * 190 + FAKE_SECRET + "\nCall log: headers")

    monkeypatch.setattr(walk_module, "fetch_paced", fail)
    findings = walk_module._walk_one(
        None, "https://portal.example.test", "https://portal.example.test/devices",
        "/devices", "light", 1280, tmp_path, {}, secrets=(FAKE_ID, FAKE_SECRET))
    report = write_report(findings, tmp_path, secrets=(FAKE_ID, FAKE_SECRET)).read_text()
    assert "walker-sec" not in report
    assert "[redacted]" in report


def test_link_error_redacts_findings_and_progress_before_truncating(
        monkeypatch, browser, pace_server, tmp_path):
    def collect_link(context, base_url, url, route, theme, width, screenshots, owner, **kwargs):
        owner[base_url + "/ok"] = (route, width, theme)
        return []

    def fail(*args, **kwargs):
        raise walk_module.PlaywrightError("x" * 190 + FAKE_SECRET + "\nCall log: headers")

    monkeypatch.setattr(walk_module, "_walk_one", collect_link)
    # The prod link phase fetches through fetch_portal, never fetch_paced.
    monkeypatch.setattr(walk_module, "fetch_portal", fail)
    monkeypatch.setattr(walk_module, "fetch_paced",
                        lambda *a, **k: pytest.fail("a prod link was fetched outside the guard"))
    messages = []
    findings = walk_module.walk_prod_routes(
        browser, pace_server.url, ProdCredentials(FAKE_ID, FAKE_SECRET), ["/ok"],
        tmp_path, pacing=_quick_pacing(), progress=messages.append)
    report = write_report(findings, tmp_path, secrets=(FAKE_ID, FAKE_SECRET)).read_text()
    assert "walker-sec" not in report + " ".join(messages)
    assert "[redacted]" in report and any("[redacted]" in m for m in messages)


def test_prod_walk_interrupt_does_not_escape_with_a_credential_traceback(monkeypatch, capsys):
    monkeypatch.setenv("PORTAL_WALKER_CLIENT_ID", FAKE_ID)
    monkeypatch.setenv("PORTAL_WALKER_CLIENT_SECRET", FAKE_SECRET)

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt(f"interrupted {FAKE_SECRET}\nCall log: {FAKE_ID}")

    monkeypatch.setattr(walk_module, "run_prod_walk", interrupt)
    try:
        result = walk_module.main(["--prod", "--routes", "/"])
    except KeyboardInterrupt:
        pytest.fail("the interruption escaped the production error boundary")
    assert result == 130
    output = capsys.readouterr()
    assert FAKE_SECRET not in output.err and FAKE_ID not in output.err
    assert "Traceback" not in output.err and "Call log" not in output.err


# PAT-2322: containment's own redirect cancellation is an informational note.
def test_same_origin_redirect_records_destination_without_console_finding(
        browser, pace_server, tmp_path):
    pace_server.rules['/redirect'] = lambda n, nav: (307, {'Location': '/ok'}, '')
    context = browser.new_context()
    creds = ProdCredentials(FAKE_ID, FAKE_SECRET)
    install_prod_guard(context, pace_server.url, creds, [])
    try:
        findings = _walk_pace_route(context, pace_server, '/redirect', tmp_path,
                                    probe_headers=creds.headers(), secrets=creds.secrets())
        assert not [f for f in findings if f.check == 'console'], findings
        notes = [f for f in findings if f.check == 'redirect']
        assert len(notes) == 1, findings
        assert notes[0].severity == 'info'
        assert notes[0].detail == 'redirect -> /ok'
        report = _json.loads(write_report(findings, tmp_path).read_text())
        assert any(f['check'] == 'redirect' and f['detail'] == 'redirect -> /ok'
                   for f in report)
        assert walk_module._summarise(findings, 1).startswith('0 finding(s) across 1 page loads')
    finally:
        context.close()


def test_non_redirect_aborted_request_remains_console_finding(browser, pace_server, tmp_path):
    pace_server.rules['/abort-page'] = lambda n, nav: (200, {}, _pat2285_page('/aborted.js'))
    context = browser.new_context()
    creds = ProdCredentials(FAKE_ID, FAKE_SECRET)
    install_prod_guard(context, pace_server.url, creds, [])
    context.route('**/aborted.js', lambda route: route.abort('aborted'))
    try:
        findings = _walk_pace_route(context, pace_server, '/abort-page', tmp_path,
                                    probe_headers=creds.headers(), secrets=creds.secrets())
        assert any(f.check == 'console' and 'net::ERR_ABORTED' in f.detail for f in findings)
        assert not any(f.check == 'redirect' for f in findings)
    finally:
        context.close()


@pytest.mark.parametrize("browser_only", [False, True])
def test_cross_origin_redirect_is_refused_and_reported(
        browser, pace_server, tmp_path, browser_only):
    other = _PaceServer()
    pace_server.rules['/unsafe'] = lambda n, nav: (
        (307, {'Location': other.url + '/ok'}, '')
        if not browser_only or pace_server.seen('/unsafe') > 1
        else (200, {}, PAT2285_OK_PAGE))
    context = browser.new_context()
    creds = ProdCredentials(FAKE_ID, FAKE_SECRET)
    install_prod_guard(context, pace_server.url, creds, [])
    try:
        findings = _walk_pace_route(context, pace_server, '/unsafe', tmp_path,
                                    probe_headers=creds.headers(), secrets=creds.secrets())
        assert any(f.check in {'status', 'console'} for f in findings), findings
        assert not any(f.check == 'redirect' for f in findings)
        assert other.log == []
    finally:
        context.close()
        other.close()


@pytest.mark.parametrize('failure,marked,expected', [
    ('net::ERR_ABORTED', True, False),
    ('net::ERR_ABORTED', False, True),
    ('net::ERR_CONNECTION_RESET', True, True),
])
def test_redirect_suppression_requires_exact_request_and_abort(failure, marked, expected):
    class Request:
        url = 'https://portal.example/redirect'
        method = 'GET'

    known, failed = Request(), Request()
    failed.failure = failure
    signals = walk_module.PageSignals(None)
    signals.redirect_requests[failed if marked else known] = 'https://portal.example/ok'
    signals._on_request_failed(failed)
    assert bool(signals.failed_requests) is expected


@pytest.mark.parametrize('extra_check,expected', [(None, 0), ('status', 1), ('readonly', 1)])
def test_redirect_note_keeps_cli_clean_but_never_hides_findings(
        monkeypatch, tmp_path, extra_check, expected):
    from types import SimpleNamespace

    note = walk_module.Finding('redirect-note', 'redirect', '/redirect', 1280,
                               'light', 'info', 'redirect -> /ok')
    results = [note]
    if extra_check:
        # Even a separate info entry is still a finding: the exception is exact.
        results.append(walk_module.Finding('real', extra_check, '/redirect', 1280,
                                          'light', 'info', 'real failure'))
    monkeypatch.setenv(walk_module.PROD_CLIENT_ID_ENV, FAKE_ID)
    monkeypatch.setenv(walk_module.PROD_CLIENT_SECRET_ENV, FAKE_SECRET)
    monkeypatch.setattr(walk_module, 'prod_routes', lambda *args: (['/redirect'], []))
    monkeypatch.setattr(walk_module, 'run_prod_walk', lambda *args, **kwargs: results)
    args = SimpleNamespace(base_url='https://portal.example', fingerprint=None)
    assert walk_module._main_prod(args, ['/redirect'], tmp_path) == expected
