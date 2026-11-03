#!/usr/bin/env python
"""Deterministic Playwright crawl of the customer portal (PAT-2126).

Walks every authenticated GET route the FastAPI app itself exposes (route
discovery is read off `main.app.routes` at runtime - see `discover_routes`
below - not a hand-maintained list, so a new page is walked automatically)
across a light x dark x 1440px matrix, plus 390px on the phone-supported
routes only and 1280px on dense routes (PAT-2329, see `widths_for_template`),
against the same e2e stub platform, harness subprocess and fixture data `e2e/` already
uses (see `e2e/conftest.py`'s `stub_platform_server` / `harness_process`
context managers, factored out for this reuse). One extra, lightweight pass
runs on phone-supported routes at 1280px, light theme only, running nothing
but rubric rule L13 (see `_walk_l13` / `L13_WIDTH` below) - rule L13
is binding at 1280px (PAT-2162), not 1440px, and checking only that one
rule at that one extra width keeps the added walk time to one page load per
route instead of doubling the whole matrix.

This is a CLI, not a pytest test - `pyproject.toml`'s `testpaths` never
collects it, and `pytest e2e/` does not run it either (see e2e/walk/
test_walk.py's docstring for why: it only exercises this module's check
FUNCTIONS, against a tiny fixture page it serves itself, never the real
walk against the stub portal). Run it explicitly:

    python e2e/walk/walk.py
    python e2e/walk/walk.py --routes /,/devices
    python e2e/walk/walk.py --routes /devices/dev-mac-001/compliance
    python e2e/walk/walk.py --fingerprint wk-overflow-devices-390-dark-abcd1234
    PORTAL_WALKER_CLIENT_ID=... PORTAL_WALKER_CLIENT_SECRET=... \
        python e2e/walk/walk.py --prod --routes /,/devices

`--routes` takes route templates (`/devices/{device_id}`, walked with its
FIXTURE_PARAMS id) or concrete paths (`/devices/dev-mac-001`, matched to its
template by segment and walked exactly as given). A walk that loads no page
never exits 0 (PAT-2300): a filter that matches no route stops the walk with
exit 4 and names it, and the summary line says how many page loads it covers.

`--prod` (PAT-2257) walks the live portal at https://app.patched.im as the
read-only service identity, authenticating with a Cloudflare Access service
token read from the two environment variables above. It is strictly
read-only: GET navigation only, every non-GET/HEAD request the page tries to
make is aborted (and reported), form submission is disabled in the page, and
the walker never clicks anything. The credentials are sent only to the
portal's own origin, never logged, and scrubbed from the report; a page that
renders either value is not screenshotted. See `run_prod_walk`.

An unexpected error stops the prod walk with exit 3 and one redacted line on
stderr, never a traceback (Playwright's would carry the request headers, and so
the service token); a fetch that fails in transit is retried once and then
reported as a finding.

Because the portal limits each identity's request rate, the prod walk spaces
its authenticated requests (`--pace SECONDS` sets the starting gap, default
PROD_PACE_SECONDS; every 429 widens it) and retries a 429 once after
Retry-After; a 429 that persists is reported as `rate-limited`, not as a broken
page. The pacing and the retry run inside the PAT-2293 redirect containment,
one hop at a time (`fetch_portal`, `navigate_portal`). It prints progress to
stderr and saves the page results to walk-report.json before the link phase,
because fetching every link takes a while on a real estate. A 403 to the
service identity (an admin-only page) is reported as `not-visible`.
Cloudflare's analytics beacon host is ignored in the console and
failed-request checks (PAT-2285).

Findings are never auto-fixed. Per PAT-2126's own instruction: the walker
reports what it finds, and portal findings it surfaces are explicitly out of
scope for this ticket to fix.

Out of scope for CI to gate on: the CI job that runs this (see
.github/workflows/ci.yml's `walk` job) is `continue-on-error: true` and
uploads e2e/walk/out/ as an artefact - it can never block a merge.
"""

from __future__ import annotations

import argparse
import contextlib
import functools
import hashlib
import json
import math
import re
import sys
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlencode, urljoin, urlsplit

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from playwright.sync_api import Error as PlaywrightError  # noqa: E402
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

from e2e.conftest import (  # noqa: E402
    HARNESS_VALID_TOKEN,
    harness_process,
    stub_platform_server,
)
from tests.conftest import STUB_STATE, reset_approval_stub, seed_declaration  # noqa: E402

OUT_DIR = Path(__file__).resolve().parent / "out"
SCREENSHOT_SUBDIR = "screenshots"

THEME_STORAGE_KEY = "patched-portal-theme"
THEMES = ("light", "dark")
WIDTHS = (1440, 390)
VIEWPORT_HEIGHT_BY_WIDTH = {1440: 900, 1280: 800, 390: 844}

# PAT-2257: the authenticated production walk. 1280 is in the matrix here
# (not a separate L13-only pass) because the prod walk is the one that has
# to prove every width a customer sees, with screenshots, before a ticket
# closes.
PROD_BASE_URL = "https://app.patched.im"
PROD_WIDTHS = (1440, 1280, 390)

# PAT-2329 (Andy, 2026-09-30): phones are a supported quick-look tier, so 390px
# is walked only on the routes in main.py's PHONE_SUPPORTED_ROUTES. WIDTHS and
# PROD_WIDTHS above are the full matrix a phone-supported route gets; every other
# route is dense and is walked at both desktop widths, in either mode.
PHONE_WIDTH = 390
DENSE_WIDTHS = (1440, 1280)
PROD_DENSE_WIDTHS = tuple(w for w in PROD_WIDTHS if w != PHONE_WIDTH)
PROD_CLIENT_ID_ENV = "PORTAL_WALKER_CLIENT_ID"
PROD_CLIENT_SECRET_ENV = "PORTAL_WALKER_CLIENT_SECRET"
# Cloudflare Access's own paths on the portal origin (login, logout,
# identity). Never walked or link-checked: /cdn-cgi/access/logout would end
# the walker's session.
PROD_SKIP_PREFIXES = ("/cdn-cgi/",)
READ_ONLY_METHODS = ("GET", "HEAD")

# A walk that loaded no page says nothing about the portal, so it must never
# exit 0 (PAT-2300): a --routes filter that matches no route, or nothing left to
# load. Its own code, beside 0 clean, 1 findings, 2 bad arguments or missing
# credentials, 3 a prod walk stopped by an error and 130 interrupted.
EXIT_NO_PAGES = 4
NO_PAGE_MESSAGE = "no page was walked, so this result says nothing about the portal"

# PAT-2285: pacing and rate limits. The platform limits each verified identity
# to PORTAL_RATE_LIMIT_RPM requests a minute (default 120, burst 30), and one
# portal page render costs several platform calls, so an unpaced walk of a
# handful of routes spends the whole budget and gets 429s that say nothing
# about the portal. The prod walk therefore starts each authenticated request
# at least PROD_PACE_SECONDS after the previous one (`--pace` overrides it), and
# any 429 is retried once after the server's Retry-After (or a default when it
# sends none, as the portal's own error page does), capped so a bad header
# cannot stall a walk. A 429 that persists is reported as `rate-limited`, never
# as a page failure. The stub walk is not paced: its stub platform has no limit.
#
# What a request costs the platform varies by page, and a live estate has
# hundreds of internal links (one history link per software product), so a
# fixed pace is either too fast for the dear pages or an hour for the cheap
# ones. The pace therefore starts low and every 429 slows it by
# PROD_PACE_STEP_SECONDS, up to PROD_PACE_MAX_SECONDS, for the rest of the run.
PROD_PACE_SECONDS = 1.0
PROD_PACE_STEP_SECONDS = 1.0
PROD_PACE_MAX_SECONDS = 6.0
# Per-request timeout for the walker's own fetches (Playwright's default is 30s
# and a stalled request is retried once, so this bounds the worst case).
FETCH_TIMEOUT_MS = 20_000
# A link fetch slower than this is named on stderr as it happens (path only).
SLOW_LINK_SECONDS = 10.0
RATE_LIMIT_DEFAULT_BACKOFF_SECONDS = 10.0
RATE_LIMIT_MAX_BACKOFF_SECONDS = 60.0
# A fetch that fails in transit (a dropped connection) is retried once after
# this long, then reported, so one bad request cannot end a ten minute walk.
TRANSPORT_RETRY_SECONDS = 2.0

# PAT-2285: Cloudflare's own analytics beacon, injected at the edge, fails with
# a refused connection in headless Chromium on every page. It is not portal
# code. Exactly this host is ignored in the console and failed-request checks;
# every other third-party failure is still a finding.
IGNORED_HOSTS = ("static.cloudflareinsights.com",)

# Rubric rule L13 (docs/portal-rubric.md) is binding at 1280px, not 1440px
# (PAT-2162 - it went unreported at 1280px for a run of the full width x
# theme matrix above, which never included 1280px at all). Checked in a
# separate, deliberately lightweight pass (`_walk_l13`) rather than by
# adding 1280 to WIDTHS, so it doesn't double the cost of every other check
# in the matrix (status/console/overflow/copy/L12/screenshots) for a width
# only L13 cares about. PAT-2329 dense pages include 1280 in their full
# matrix, so this extra pass now applies only to phone-supported pages.
# Theme doesn't affect text wrapping, so light only.
L13_WIDTH = 1280
L13_VIEWPORT_HEIGHT = 800

# Path-param routes need a concrete id to walk - taken from the same
# tests/conftest.py fixtures the rest of e2e/ already renders against (see
# module docstrings there for where each id comes from: DEVICES,
# HOMEBREW_DEVICES, ALERTS, the stub's /v1/portal/reports/rep-0001 handler).
# A route added later with a path param NOT listed here is not silently
# skipped - see `resolve_route` - it is reported as a finding instead.
FIXTURE_PARAMS: dict[str, dict[str, str]] = {
    "/devices/{device_id}": {"device_id": "dev-mac-001"},
    "/devices/{device_id}/hardware": {"device_id": "dev-mac-001"},
    "/devices/{device_id}/software": {"device_id": "dev-mac-001"},
    "/devices/{device_id}/vulnerabilities": {"device_id": "dev-mac-001"},
    "/devices/{device_id}/compliance": {"device_id": "dev-mac-001"},
    "/devices/{device_id}/evidence": {"device_id": "dev-mac-001"},
    "/homebrew/devices/{device_id}": {"device_id": "hb-mac-01"},
    "/ai-tooling/devices/{device_id}": {"device_id": "dev-mac-001"},
    "/ai-tooling/devices/{device_id}.csv": {"device_id": "dev-mac-001"},
    "/ai-tooling/devices/{device_id}.pdf": {"device_id": "dev-mac-001"},
    "/software/alerts/{alert_id}": {"alert_id": "1"},
    # PAT-2393: the id seed_declaration() puts in the stub.
    "/software/declarations/{declaration_id}": {
        "declaration_id": "00000000-0000-4000-8000-000000000001"},
    "/reports/{report_id}/download": {"report_id": "rep-0001"},
}
_PARAM_RE = re.compile(r"\{([^}/]+)\}")

# Routes with no path params that still cannot be exercised meaningfully
# without specific query parameters - PAT-2128 follow-up. `/software/history`
# 400s bare (it needs `item`, the JSON-encoded product reference the
# approval-history drawer link always carries - see main.py's
# `_approval_view`/`history_url`). The value here is the same shape
# `tests/test_pat2008_software_approvals.py`'s `_item()` helper builds and
# the stub platform's `/v1/portal/software-approvals/history` handler
# accepts (`tests/conftest.py`): a real, schema-valid item, not a made-up
# string. A route added here with no entry is reported as skipped rather
# than walked bare - see `resolve_route_query`.
FIXTURE_QUERY_PARAMS: dict[str, dict[str, str] | None] = {
    "/software/history": {
        "item": json.dumps(
            {"type": "application", "platform": "macos",
             "identifier": "com.example.mysteryapp", "name": "MysteryApp"},
            separators=(",", ":"),
        ),
    },
}

SEVERITY_BY_CHECK = {
    "status": "high",
    "auth": "high",
    "console": "medium",
    "overflow": "medium",
    "link": "medium",
    "copy": "low",
    # A clipped element with `text-overflow: ellipsis` and no title/aria-label
    # (see check_overflow) is not the same defect as an `overflow` finding -
    # the layout is fine, but there is no way to read the truncated value.
    "truncation-no-full-text": "low",
    # A GET route the walker knows needs query parameters to render
    # anything but its own 400 refusal, with no fixture value configured
    # for it (see FIXTURE_QUERY_PARAMS) - explicitly not walked rather than
    # silently producing a `status` 400 finding that looks like a real bug.
    "skipped": "low",
    # Rubric rule L12 (portal-rubric.md, Andy ruling 2026-09-25, PAT-2128):
    # phone-width (390px only) table text breakage or an over-wide table
    # with no stack/scroll affordance. Same severity band as `overflow` -
    # a genuine layout defect at a specific, real viewport.
    "L12": "medium",
    # Rubric rule L13 (portal-rubric.md, Andy ruling 2026-09-25, PAT-2155):
    # generalises L11 (the Evidence date column) to every date/time cell in
    # every portal table - a check for a date-shaped run of text rendering
    # across three or more lines, at the rubric's binding 1280px width
    # (L13_WIDTH; PAT-2162 - previously wrongly checked at 1440px only, see
    # _walk_l13). Same severity band as L12/overflow.
    "L13": "medium",
    # PAT-2257 checks. See each check_* function below.
    "cells": "medium",            # adjacent table cells intersect
    "break": "medium",            # a version- or date-shaped string breaks mid-string
    "leak": "medium",             # internal reference in customer-visible text
    "theme-toggle": "medium",     # the theme toggle shows no (or the wrong) active state
    "count-mismatch": "high",     # the same named count disagrees with itself on one page
    "readonly": "high",           # prod walk: the page tried a non-GET request (aborted)
    "secret-exposure": "high",    # prod walk: a page rendered the walker's credential
    # PAT-2285. Neither is a defect in the portal, so neither is medium or
    # high. `rate-limited`: a 429 that survived a retry, so the page or link
    # could not be checked (a coverage gap, not a failure). `not-visible`:
    # a 403 to the read-only service identity, expected for an admin-only page
    # (informational). Both stay in the report so nothing is silently dropped.
    "rate-limited": "low",
    "not-visible": "low",
}

# (c) Internal references that must never reach customer-visible text.
# `--` is exempt inside pre/code/kbd/samp, where a command-line flag is
# legitimate copy (the install page's deploy commands); everything else
# applies everywhere except [data-walker-ignore].
LEAK_PATTERNS = (
    ("ticket-ref", re.compile(r"\bPAT-\d+\b")),
    ("ticket-word", re.compile(r"\btickets?\b", re.IGNORECASE)),
    # PAT-2255: a GUID is a leak whole or cut short - a list cell that
    # truncates an MSI product code ("{AC76BA86-1033-FF00-7760-BC1501...")
    # still shows its first three groups, so the pattern needs only those.
    ("guid", re.compile(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}(?:-[0-9a-f]{1,4}(?:-[0-9a-f]{1,12})?)?",
        re.IGNORECASE)),
    ("double-hyphen", re.compile(r"--")),
    # PAT-2509: a source's machine name ("curated_catalogue") is a key for the
    # platform, never wording for a customer. It leaked into a table cell.
    ("machine-name", re.compile(r"curated_catalogue", re.IGNORECASE)),
)
LEAK_CODE_EXEMPT = ("double-hyphen",)

# (e) Named counts that must agree wherever they appear on one page. A count
# is keyed by its phrase plus up to two qualifying words before it ("12
# extensions waiting on a decision" and "96 products waiting on a decision"
# are different counts), so only genuinely the same count is compared.
NAMED_COUNTS = (
    "awaiting approval",
    "waiting on a decision",
    # PAT-2255: the Overview's own phrasings of the one awaiting-decision
    # figure (Top 3 actions, the at-a-glance line) and /software's
    # headline, so 128 in one place and 140 in another is caught.
    "waiting for an approval decision",
    "waiting on an approval decision",
    "products waiting",
    "not reporting",
    "open findings",
)

COPY_BANNED_PATTERNS = (
    ("specialist", re.compile(r"specialist", re.IGNORECASE)),
    ("fleet", re.compile(r"fleet", re.IGNORECASE)),
    ("coming soon", re.compile(r"coming soon", re.IGNORECASE)),
    ("em-dash", re.compile("—")),
    # PAT-2509: a latest-released source's machine name read as internal
    # wording. check_copy skips <td> text, so the same string is also in
    # LEAK_PATTERNS, which does look in table cells.
    ("curated_catalogue", re.compile(r"curated_catalogue", re.IGNORECASE)),
)

# Shared with e2e/test_portal_ui.py's _stub_out_google_fonts - the portal
# loads Google Fonts client-side on every page; fulfilling those requests
# locally keeps the walk hermetic and keeps the requestfailed collector
# honest about the app's own behaviour rather than a font CDN's reachability
# from CI.
def _stub_out_google_fonts(route):
    route.fulfill(status=200, content_type="text/css", body="")


# ── Finding + fingerprint ──────────────────────────────────────────────────


@dataclass
class Finding:
    fingerprint: str
    check: str
    route: str
    width: int | None
    theme: str | None
    severity: str
    detail: str
    screenshot: str | None = None

    def sort_key(self):
        return (
            self.route,
            self.width if self.width is not None else -1,
            self.theme or "",
            self.check,
            self.fingerprint,
        )

    def to_dict(self) -> dict:
        return asdict(self)


def _slug(route: str) -> str:
    """Deterministic, filesystem/fingerprint-safe slug for a route path
    (concrete or templated: `{param}` braces collapse to plain text)."""
    s = route.strip("/").replace("{", "").replace("}", "")
    s = re.sub(r"[^a-zA-Z0-9]+", "-", s).strip("-").lower()
    return s or "root"


def _short_hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:8]


def fingerprint(check: str, route: str, width: int | None, theme: str | None,
                 salt: str | None = None) -> str:
    """`wk-<check>-<route-slug>-<width>-<theme>[-<short hash>]` (PAT-2126
    brief). Deterministic across runs: `salt` (a selector or matched text)
    is hashed with sha1 and truncated, never included verbatim, so the
    fingerprint format itself never changes shape between runs even when
    the underlying text does."""
    parts = [f"wk-{check}", _slug(route), str(width) if width is not None else "na",
              theme or "na"]
    fp = "-".join(parts)
    if salt:
        fp += f"-{_short_hash(salt)}"
    return fp


# ── Check functions (pure enough to be pointed at any Page/base URL) ──────
# These are what e2e/walk/test_walk.py exercises directly against a fixture
# page it serves itself - kept free of any route-discovery/stub-platform
# knowledge so that works.

# A page.evaluate() call takes exactly one function/expression, so the
# selector-path helper is declared INSIDE each arrow function body below,
# not as a separate top-level statement before it (two top-level statements
# is a syntax error Playwright rejects at evaluate() time).
_CSS_PATH_JS = """
  function __wkCssPath(el) {
    if (!el || el.nodeType !== 1) return '';
    const parts = [];
    while (el && el.nodeType === 1 && el !== document.body) {
      let sel = el.tagName.toLowerCase();
      if (el.id) { parts.unshift(sel + '#' + el.id); break; }
      let i = 1, sib = el;
      while ((sib = sib.previousElementSibling)) { if (sib.tagName === el.tagName) i++; }
      sel += ':nth-of-type(' + i + ')';
      parts.unshift(sel);
      el = el.parentElement;
    }
    return parts.length ? parts.join(' > ') : 'body';
  }
"""

_OVERFLOW_JS = """
() => {
""" + _CSS_PATH_JS + """
  const docEl = document.documentElement;
  const result = {
    docOverflow: docEl.scrollWidth > docEl.clientWidth,
    docScrollWidth: docEl.scrollWidth, docClientWidth: docEl.clientWidth,
    elements: [],
  };
  // hidden/clip genuinely hide overflow content - no affordance gets it
  // back on screen, so any such element wider than its box is always a
  // candidate. overflow:auto is different: it grows a scrollbar, so a
  // plain auto-scrollable area is not a defect (the content IS reachable,
  // by scrolling) and must NOT be inspected on its own. The one case an
  // auto element still matters is the same single-line truncation pattern
  // hidden/clip commonly use - text-overflow:ellipsis + white-space:nowrap
  // - just implemented with overflow:auto instead; that still clips its
  // text just as effectively; PAT-2128. So: auto only becomes a candidate
  // when text-overflow is already ellipsis, decided inline below rather
  // than by widening CLIP_ONLY itself (which would flag ordinary scroll
  // regions with no ellipsis at all as false "overflow" findings). Whether
  // a candidate is then reported as `overflow`, excluded as intentional
  // truncation, or reported as the separate `truncation-no-full-text`
  // finding is check_overflow's call, in Python, using the
  // textOverflow/hasFullText facts gathered here.
  // A screen-reader-only element (the `.visually-hidden` idiom: an
  // overflow:hidden/clip box collapsed to ~0px with its content pulled out
  // of the flow via `clip`/`clip-path`, portal.css ~line 849) is a
  // correct accessible-hiding pattern, not a layout defect - PAT-2128
  // follow-up. Matched generically on computed geometry/style so any
  // element using the same recipe is excluded the same way, not keyed to
  // the class name.
  function __wkClipRectIsZero(clip) {
    const m = /^rect\\(([^)]*)\\)$/.exec((clip || '').trim());
    if (!m) return false;
    const parts = m[1].split(/[,\\s]+/).filter(Boolean);
    return parts.length === 4 && parts.every((p) => parseFloat(p) === 0);
  }
  function __wkClipPathHides(clipPath) {
    const v = (clipPath || '').trim();
    if (!v || v === 'none') return false;
    // inset(50%[ ...]) and circle(0) are the common non-`clip`-property
    // variants of the same visually-hidden recipe.
    return /^inset\\(\\s*50%(\\s+50%){0,3}\\s*\\)$/i.test(v)
      || /^circle\\(\\s*0(px|%)?\\s*\\)$/i.test(v);
  }
  const CLIP_ONLY = new Set(['hidden', 'clip']);
  document.querySelectorAll('body *').forEach((el) => {
    const cs = getComputedStyle(el);
    const isClip = CLIP_ONLY.has(cs.overflow) || CLIP_ONLY.has(cs.overflowX);
    const isAuto = cs.overflow === 'auto' || cs.overflowX === 'auto';
    if (!isClip && !isAuto) return;
    if (el.scrollWidth > el.clientWidth + 2) {
      if (isClip) {
        const rect = el.getBoundingClientRect();
        const isVisuallyHidden = rect.width <= 1 || rect.height <= 1
          || __wkClipRectIsZero(cs.clip) || __wkClipPathHides(cs.clipPath);
        if (isVisuallyHidden) return;
      }
      const isEllipsis = cs.textOverflow === 'ellipsis';
      if (isAuto && !isClip && !isEllipsis) return;  // plain scroll area, not a defect
      const title = (el.getAttribute('title') || '').trim();
      const ariaLabel = (el.getAttribute('aria-label') || '').trim();
      result.elements.push({
        selector: __wkCssPath(el),
        scrollWidth: el.scrollWidth, clientWidth: el.clientWidth,
        textOverflow: cs.textOverflow,
        hasFullText: Boolean(title || ariaLabel),
      });
    }
  });
  return result;
}
"""

_COPY_JS = """
() => {
""" + _CSS_PATH_JS + """
  const IGNORE_SELECTOR = 'td, pre, code, [data-walker-ignore]';
  const results = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null);
  let node;
  while ((node = walker.nextNode())) {
    const text = node.textContent;
    if (!text || !text.trim()) continue;
    const parentEl = node.parentElement;
    if (!parentEl || parentEl.closest(IGNORE_SELECTOR)) continue;
    results.push({selector: __wkCssPath(parentEl), text: text.trim().slice(0, 200)});
  }
  return results;
}
"""

_LINKS_JS = """
() => Array.from(document.querySelectorAll('a[href]')).map((a) => a.getAttribute('href'))
"""

# ── L12 (portal-rubric.md, Andy ruling 2026-09-25, PAT-2128) ───────────────
# 390px-only: no table cell breaks a word mid-letter or renders one
# character per line, and no table forces the page to scroll sideways
# instead of stacking (.table-stack) or scrolling inside its own card.

# Mid-word break detection: verbatim approach from
# e2e/test_pat2136_device_detail_phone.py's WORD_BREAK_JS, itself reusing
# e2e/test_pat2092_layout.py's WORD_BREAK_JS - alphanumeric runs only, a
# hyphen/"@"/"." is a real CSS/UAX14 soft-wrap opportunity (compound
# hostnames, emails, CVE ids like "CVE-2026-0001"), not a word fragmenting
# mid-letter, so splitting on them keeps a legitimate break at a hyphen from
# being flagged as the same defect as a word broken inside its own letters.
_L12_WORD_BREAK_JS = """
() => {
""" + _CSS_PATH_JS + """
  const failures = [];
  document.querySelectorAll('table').forEach((table) => {
    table.querySelectorAll('th, td').forEach((cell) => {
      if (getComputedStyle(cell).display === 'none') return;
      const walker = document.createTreeWalker(cell, NodeFilter.SHOW_TEXT);
      let node;
      while ((node = walker.nextNode())) {
        const text = node.textContent;
        const re = /[A-Za-z0-9]+/g;
        let m;
        while ((m = re.exec(text))) {
          const word = m[0];
          if (word.length < 3) continue;
          const range = document.createRange();
          range.setStart(node, m.index);
          range.setEnd(node, m.index + word.length);
          const seen = new Set();
          Array.from(range.getClientRects()).forEach((r) => {
            seen.add(Math.round(r.top) + ':' + Math.round(r.left));
          });
          if (seen.size > 1) {
            failures.push({
              selector: __wkCssPath(cell),
              word: word,
              text: cell.textContent.trim().slice(0, 60),
            });
          }
        }
      }
    });
  });
  return failures;
}
"""

# One-character-per-line detection: verbatim approach from
# e2e/test_pat2136_device_detail_phone.py's ONE_CHAR_PER_LINE_JS - catches
# the stricter, narrower net a word-break check alone misses (a cell whose
# own box renders narrower than a single average character at this app's
# table font-size, even holding text too short - under 3 alphanumeric
# characters - for the word-break regex above to ever match it).
_L12_ONE_CHAR_PER_LINE_JS = """
() => {
""" + _CSS_PATH_JS + """
  const failures = [];
  document.querySelectorAll('table').forEach((table) => {
    table.querySelectorAll('td').forEach((cell) => {
      if (getComputedStyle(cell).display === 'none') return;
      const text = cell.textContent.trim();
      if (!text) return;
      const r = cell.getBoundingClientRect();
      if (r.width > 0 && r.width < 14) {
        failures.push({selector: __wkCssPath(cell), width: r.width, text: text.slice(0, 30)});
      }
    });
  });
  return failures;
}
"""

# Over-wide-table detection: a table whose scrollWidth exceeds its card's
# clientWidth must either be a `.table-stack` table that has actually
# switched into its stacked (label/value) layout at this width - checked by
# computed display, not the class name alone, the same way the walker's own
# overflow check verifies geometry rather than trusting a class (see
# _OVERFLOW_JS's isVisuallyHidden) - or sit inside a horizontally
# scrollable ancestor within its own card (overflow-x auto/scroll), so the
# width is reachable by scrolling rather than forcing the page itself to
# scroll sideways. Page-level horizontal overflow is already covered by
# check_overflow's docOverflow finding - not duplicated here.
_L12_TABLE_WIDTH_JS = """
() => {
""" + _CSS_PATH_JS + """
  const failures = [];
  document.querySelectorAll('table').forEach((table) => {
    const card = table.closest('.card');
    if (!card) return;
    if (table.scrollWidth <= card.clientWidth + 2) return;
    if (table.classList.contains('table-stack')
        && getComputedStyle(table).display === 'block') {
      return;
    }
    let scrollable = false;
    let el = table.parentElement;
    while (el && el !== card.parentElement) {
      const cs = getComputedStyle(el);
      if (cs.overflowX === 'auto' || cs.overflowX === 'scroll') { scrollable = true; break; }
      el = el.parentElement;
    }
    if (scrollable) return;
    failures.push({
      selector: __wkCssPath(table),
      scrollWidth: table.scrollWidth,
      cardClientWidth: card.clientWidth,
    });
  });
  return failures;
}
"""


# ── Pacing, rate limits and ignored hosts (PAT-2285) ──────────────────────


def retry_after_seconds(headers: Mapping[str, str] | None, *,
                        default: float = RATE_LIMIT_DEFAULT_BACKOFF_SECONDS,
                        cap: float = RATE_LIMIT_MAX_BACKOFF_SECONDS) -> float:
    """How long to wait before retrying a 429: the `Retry-After` header in
    seconds when it is a usable number, clamped to [0, cap]; `default` when it
    is missing or not a number (the HTTP-date form is not honoured). The
    portal's own 429 page sends no header, so the default is the common case."""
    raw = next((v for k, v in (headers or {}).items() if k.lower() == "retry-after"), None)
    try:
        seconds = float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    if not math.isfinite(seconds):
        return default
    return max(0.0, min(seconds, cap))


@dataclass
class Pacing:
    """Spacing between authenticated requests and the back-off after a 429.

    `interval` is the minimum time between the starts of two consecutive
    requests (0 = no pacing, the stub walk's setting). `sleep` and `clock` are
    injectable so tests never really wait."""
    interval: float = 0.0
    slow_step: float = PROD_PACE_STEP_SECONDS
    max_interval: float = PROD_PACE_MAX_SECONDS
    default_backoff: float = RATE_LIMIT_DEFAULT_BACKOFF_SECONDS
    max_backoff: float = RATE_LIMIT_MAX_BACKOFF_SECONDS
    error_backoff: float = TRANSPORT_RETRY_SECONDS
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    _last: float | None = field(default=None, init=False, repr=False)

    def wait(self) -> None:
        """Call immediately before every request that counts against the
        portal's rate limit."""
        if self.interval > 0 and self._last is not None:
            remaining = self.interval - (self.clock() - self._last)
            if remaining > 0:
                self.sleep(remaining)
        self._last = self.clock()

    def slow_down(self) -> None:
        """Called on every 429: the requests are dearer than the interval
        allows for, so widen it (never for an unpaced walk)."""
        if self.interval > 0:
            self.interval = min(self.interval + self.slow_step, self.max_interval)

    def backoff(self, headers: Mapping[str, str] | None) -> float:
        return retry_after_seconds(headers, default=self.default_backoff, cap=self.max_backoff)


def _send_with_retry(send: Callable[[], object], pacing: Pacing):
    """One paced request, `send()`, repeated at most once: after a 429 (wait
    out `Retry-After`) or a transport error (wait `pacing.error_backoff`).
    Whatever the second attempt returns is the answer, and a second transport
    error propagates. A timeout (FETCH_TIMEOUT_MS) is not retried, and nor is
    a ProdRequestError, which is a refusal, not a transient failure.

    `send` is called afresh for each attempt and must repeat exactly the same
    request. A 429's own headers are read only for Retry-After: its Location,
    if it has one, is never followed."""
    for attempt in (1, 2):
        pacing.wait()
        try:
            resp = send()
        except ProdRequestError:
            raise
        except PlaywrightError as exc:
            # A timeout is not transient the way a dropped connection is, and
            # retrying it doubles the cost of a page that is simply slow.
            if attempt == 2 or _is_timeout(exc):
                raise
            pacing.sleep(pacing.error_backoff)
            continue
        if resp.status == 429:
            pacing.slow_down()
        if resp.status != 429 or attempt == 2:
            return resp
        delay = pacing.backoff(resp.headers)
        resp.dispose()
        pacing.sleep(delay)


def fetch_paced(context, url: str, *, pacing: Pacing):
    """A paced, unauthenticated GET through the context's request API (the
    stub walk's probe and link check), retried as `_send_with_retry` says.

    It takes no headers on purpose: a request that carries the prod service
    token must go through `fetch_portal`, which paces and retries each
    redirect hop itself and never lets a redirect leave the portal's origin
    (PAT-2293). For the same reason it refuses a context that carries the
    prod guard: that context's cookie jar holds the portal's session."""
    if getattr(context, "_portal_redirects", None) is not None:
        raise ProdRequestError("unguarded fetch refused on the production context")
    return _send_with_retry(
        lambda: context.request.get(url, fail_on_status_code=False, timeout=FETCH_TIMEOUT_MS),
        pacing)


def _is_timeout(exc: BaseException) -> bool:
    """Playwright 1.47 raises a plain Error ("Request timed out after ...")
    for an API request timeout, not TimeoutError, so the message is checked too."""
    first = (str(exc).splitlines() or [""])[0].lower()
    return isinstance(exc, PlaywrightTimeoutError) or "timed out" in first


def _short_error(exc: BaseException, secrets: tuple[str, ...] = ()) -> str:
    """One redacted line describing an exception. Playwright appends the
    request's headers, credential included, after the first line ("Call
    log:"), so only the first line is ever kept."""
    first = (str(exc).splitlines() or [type(exc).__name__])[0]
    return _clip(first, 200, secrets)


def _fetch_error_finding(check: str, target: str, route: str, width: int | None,
                         theme: str | None, exc: BaseException,
                         secrets: tuple[str, ...] = ()) -> Finding:
    return Finding(
        fingerprint=fingerprint(check, route, width, theme, salt=f"fetch-error:{target}"),
        check=check, route=route, width=width, theme=theme,
        severity=SEVERITY_BY_CHECK[check],
        detail=f"{redact(target, secrets)} could not be fetched: {_short_error(exc, secrets)}",
    )


def is_ignored_url(url: str) -> bool:
    """True for a URL on exactly one of IGNORED_HOSTS (not a subdomain, not a
    lookalike that merely contains the name)."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return False
    return host in IGNORED_HOSTS


_URL_IN_TEXT_RE = re.compile(r"https?://[^\s'\"<>()\[\]]+", re.IGNORECASE)


def _mentions_only_ignored_hosts(text: str) -> bool:
    """A console or failed-request message that names at least one URL, every
    one of them on an ignored host."""
    urls = _URL_IN_TEXT_RE.findall(text)
    return bool(urls) and all(is_ignored_url(u) for u in urls)


def _rate_limited_finding(target: str, route: str, width: int | None, theme: str | None,
                          *, salt: str | None = None) -> Finding:
    return Finding(
        fingerprint=fingerprint("rate-limited", route, width, theme, salt=salt),
        check="rate-limited", route=route, width=width, theme=theme,
        severity=SEVERITY_BY_CHECK["rate-limited"],
        detail=(f"{target} was rate limited (HTTP 429) on both attempts, so it was not "
                "checked. This is the walker's request rate against the portal, not a "
                "defect in the page."),
    )


def _not_visible_finding(target: str, route: str, width: int | None, theme: str | None,
                         *, salt: str | None = None) -> Finding:
    return Finding(
        fingerprint=fingerprint("not-visible", route, width, theme, salt=salt),
        check="not-visible", route=route, width=width, theme=theme,
        severity=SEVERITY_BY_CHECK["not-visible"],
        detail=(f"{target} returned 403 to the read-only service identity, so it was not "
                "checked. Expected for an admin-only page; if this one is not admin-only, "
                "check the service token and the estate it maps to."),
    )


def check_status(status: int, route: str, width: int | None, theme: str | None,
                 *, service_identity: bool = False) -> list[Finding]:
    """Non-2xx is a `status` finding, except a 429 (`rate-limited`) and, for
    the prod service-identity walk only, a 403 (`not-visible`)."""
    if 200 <= status < 300:
        return []
    if status == 429:
        return [_rate_limited_finding(route, route, width, theme)]
    if status == 403 and service_identity:
        return [_not_visible_finding(route, route, width, theme, salt=str(status))]
    detail = f"{route} returned status {status} (expected 2xx)"
    return [Finding(
        fingerprint=fingerprint("status", route, width, theme, salt=str(status)),
        check="status", route=route, width=width, theme=theme,
        severity=SEVERITY_BY_CHECK["status"], detail=detail,
    )]


def check_console(js_errors: list[str], failed_requests: list[str],
                   route: str, width: int | None, theme: str | None,
                   *, secrets: tuple[str, ...] = ()) -> list[Finding]:
    findings: list[Finding] = []
    # Cloudflare's analytics beacon (IGNORED_HOSTS) is not portal code.
    js_errors = [m for m in js_errors if not _mentions_only_ignored_hosts(m)]
    failed_requests = [m for m in failed_requests if not _mentions_only_ignored_hosts(m)]
    # Dedupe within this one page load - the same console error or failed
    # request commonly fires more than once per render.
    for message in dict.fromkeys(js_errors):
        findings.append(Finding(
            fingerprint=fingerprint("console", route, width, theme, salt=f"js:{message}"),
            check="console", route=route, width=width, theme=theme,
            severity=SEVERITY_BY_CHECK["console"],
            detail=f"console error: {_clip(message, 300, secrets)}",
        ))
    for message in dict.fromkeys(failed_requests):
        findings.append(Finding(
            fingerprint=fingerprint("console", route, width, theme, salt=f"net:{message}"),
            check="console", route=route, width=width, theme=theme,
            severity=SEVERITY_BY_CHECK["console"],
            detail=f"failed request: {_clip(message, 300, secrets)}",
        ))
    return findings


def check_overflow(page, route: str, width: int | None, theme: str | None) -> list[Finding]:
    """An element with `text-overflow: ellipsis` (its `overflow` one of
    hidden/clip/auto - see _OVERFLOW_JS's isClip/isAuto split) is deliberate
    truncation, not a layout defect - PAT-2126's first real run found
    roughly 148 of these reported as plain `overflow` findings, almost all
    noise. Such an element is only excluded outright when its full value is
    still readable some other way - a `title` or `aria-label` attribute
    (the two ways of surfacing it this check can verify without a broader
    accessibility-tree walk). Ellipsis-truncated with NEITHER attribute is
    still a real defect - just a different one (nothing links this text to
    a way to read the rest of it), reported separately as
    `truncation-no-full-text` so it doesn't reopen the same noise problem
    under the `overflow` check's name. Anything clipped WITHOUT ellipsis
    (a hard cut mid-character, a control that's simply too narrow) is
    unaffected and keeps reporting as `overflow`, exactly as before -
    `data['elements']` never even contains a plain `overflow: auto`
    scrollable area with no ellipsis (_OVERFLOW_JS drops it - it's
    reachable by scrolling, not a defect), so this function doesn't have to
    special-case it here.

    PAT-2128 follow-up: _OVERFLOW_JS also drops any `overflow: hidden`/`clip`
    element rendered at ~0px (or otherwise hidden via `clip`/`clip-path`) -
    the `.visually-hidden` screen-reader-only idiom, matched on computed
    geometry/style rather than the class name. The first real portal-main
    walk (2026-09-25) found 32 of these reported as `overflow`, all
    accessible labels using that exact recipe."""
    data = page.evaluate(_OVERFLOW_JS)
    findings: list[Finding] = []
    if data.get("docOverflow"):
        findings.append(Finding(
            fingerprint=fingerprint("overflow", route, width, theme, salt="document"),
            check="overflow", route=route, width=width, theme=theme,
            severity=SEVERITY_BY_CHECK["overflow"],
            detail=(f"document scrollWidth {data['docScrollWidth']} > "
                    f"clientWidth {data['docClientWidth']}"),
        ))
    for el in data.get("elements", []):
        if el.get("textOverflow") == "ellipsis":
            if el.get("hasFullText"):
                # Intentional truncation with the full value in title or
                # aria-label: not a defect.
                continue
            findings.append(Finding(
                fingerprint=fingerprint("truncation-no-full-text", route, width, theme,
                                         salt=el["selector"]),
                check="truncation-no-full-text", route=route, width=width, theme=theme,
                severity=SEVERITY_BY_CHECK["truncation-no-full-text"],
                detail=(f"{el['selector']}: text-overflow: ellipsis truncates content "
                        f"(scrollWidth {el['scrollWidth']} > clientWidth {el['clientWidth']}) "
                        "with no title/aria-label to read the full value"),
            ))
            continue
        findings.append(Finding(
            fingerprint=fingerprint("overflow", route, width, theme, salt=el["selector"]),
            check="overflow", route=route, width=width, theme=theme,
            severity=SEVERITY_BY_CHECK["overflow"],
            detail=(f"{el['selector']}: clipped element scrollWidth {el['scrollWidth']} > "
                    f"clientWidth {el['clientWidth']}"),
        ))
    return findings


def check_copy(page, route: str, width: int | None, theme: str | None,
               *, secrets: tuple[str, ...] = ()) -> list[Finding]:
    nodes = page.evaluate(_COPY_JS)
    findings: list[Finding] = []
    for node in nodes:
        text = node["text"]
        for name, pattern in COPY_BANNED_PATTERNS:
            if pattern.search(text):
                findings.append(Finding(
                    fingerprint=fingerprint(
                        "copy", route, width, theme, salt=f"{node['selector']}:{name}"),
                    check="copy", route=route, width=width, theme=theme,
                    severity=SEVERITY_BY_CHECK["copy"],
                    detail=f"{node['selector']}: {name!r} in {_clip(text, 120, secrets)!r}",
                ))
    return findings


# ── L13 (portal-rubric.md, Andy ruling 2026-09-25, PAT-2155) ───────────────
# Generalises L11 (which only covered /software's Evidence date column):
# no date/time cell in any portal table wraps beyond two lines, at the
# rubric's binding width of 1280px (docs/portal-rubric.md line ~141).
# PAT-2155's own live report ("Raised wraps over four lines") is this
# rule's origin case.
#
# PAT-2162: the walker originally ran this check only at 1440px (see
# `_walk_one` below, and this module's now-superseded git history) because
# that was one of the two widths the rest of the matrix already walked at -
# not because 1440px is the rule. A date cell that wrapped over two lines
# only at 1280px (a real portal table, narrower rail-adjusted content width
# at that viewport) went unreported. 1280px is the binding width, checked by the
# dedicated `_walk_l13` pass. L13 still also runs at 1440px in the WIDTHS
# matrix: .col-secondary columns (PAT-2070) are hidden below 1440px, so at
# 1440px a table has more columns and a date column can be narrower than at
# 1280px. Neither width implies the other.

# Matched per date-shaped TEXT NODE inside a cell, not the whole cell's
# text. The PAT-2140/PAT-2155 date/time split (cell-evidence/cell-evidence
# __main/cell-subtle) deliberately renders a date and its time as two
# separate text nodes on two separate lines - a cell-level line count would
# immediately re-trigger this very check on the fix it exists to require.
# It would also misfire on a cell that legitimately carries a third line of
# unrelated detail next to its date (who acknowledged an alert, why it was
# resolved): that third line's own wrapping is not a date-cell defect.
# Matching the date-shaped run of text on its own, the way L12's word-break
# check already matches individual words rather than a whole cell, gives
# the same real-defect coverage without either false positive: a lone
# unsplit "25 Sep 2026 11:42"-shaped text node that wraps across 3+ lines
# still matches and still reports; a short date-only or time-only node
# next to it does not.
_L13_DATE_WRAP_JS = """
() => {
""" + _CSS_PATH_JS + """
  const DATE_RE = /\\d{1,2}\\s+[A-Z][a-z]{2}\\s+\\d{4}(?:\\s+\\d{1,2}:\\d{2})?/;
  const failures = [];
  document.querySelectorAll('table').forEach((table) => {
    table.querySelectorAll('th, td').forEach((cell) => {
      if (getComputedStyle(cell).display === 'none') return;
      const walker = document.createTreeWalker(cell, NodeFilter.SHOW_TEXT);
      let node;
      while ((node = walker.nextNode())) {
        const text = node.textContent;
        const m = DATE_RE.exec(text);
        if (!m) continue;
        const range = document.createRange();
        range.setStart(node, m.index);
        range.setEnd(node, m.index + m[0].length);
        const seen = new Set();
        Array.from(range.getClientRects()).forEach((r) => {
          if (r.width === 0 && r.height === 0) return;
          seen.add(Math.round(r.top));
        });
        const lines = seen.size;
        if (lines >= 3) {
          failures.push({selector: __wkCssPath(cell), lines: lines, text: m[0].slice(0, 60)});
        }
      }
    });
  });
  return failures;
}
"""


def check_l13(page, route: str, width: int | None, theme: str | None) -> list[Finding]:
    """Rubric rule L13 (portal-rubric.md, Andy ruling 2026-09-25, PAT-2155):
    no date-shaped run of text in any table cell renders across three or
    more lines, at the rubric's binding width of 1280px (PAT-2162;
    L13_WIDTH). Callers gate this to width == L13_WIDTH only (see
    _walk_l13); this function does not re-check width itself - it just
    reports whatever `page` is currently sized to via `width`/`theme` in
    the finding, so the unit tests below can call it directly against a
    fixture already sized to whichever width they're exercising. See
    _L13_DATE_WRAP_JS's own comment for why matching is per date-shaped
    text node, not per whole cell."""
    findings: list[Finding] = []
    for item in page.evaluate(_L13_DATE_WRAP_JS):
        findings.append(Finding(
            fingerprint=fingerprint("L13", route, width, theme, salt=item["selector"]),
            check="L13", route=route, width=width, theme=theme,
            severity=SEVERITY_BY_CHECK["L13"],
            detail=(f"{item['selector']}: date {item['text']!r} renders across "
                    f"{item['lines']} lines at {width}px (rule L13)"),
        ))
    return findings


def check_l12(page, route: str, width: int | None, theme: str | None) -> list[Finding]:
    """Rubric rule L12 (portal-rubric.md, Andy ruling 2026-09-25, PAT-2128):
    at 390px, no table text breaks mid-word or renders one character per
    line, and a table wider than its card either stacks (.table-stack in
    stacked mode) or scrolls inside its card - never the page itself.
    Callers gate this to width == 390 only (see _walk_one); this function
    does not re-check width itself so the unit tests below can call it
    directly against a fixture already sized to 390px."""
    findings: list[Finding] = []

    for item in page.evaluate(_L12_WORD_BREAK_JS):
        findings.append(Finding(
            fingerprint=fingerprint(
                "L12", route, width, theme,
                salt=f"wordbreak:{item['selector']}:{item['word']}"),
            check="L12", route=route, width=width, theme=theme,
            severity=SEVERITY_BY_CHECK["L12"],
            detail=(f"{item['selector']}: {item['word']!r} breaks across lines in "
                    f"{item['text']!r} (rule L12)"),
        ))

    for item in page.evaluate(_L12_ONE_CHAR_PER_LINE_JS):
        findings.append(Finding(
            fingerprint=fingerprint("L12", route, width, theme,
                                     salt=f"onechar:{item['selector']}"),
            check="L12", route=route, width=width, theme=theme,
            severity=SEVERITY_BY_CHECK["L12"],
            detail=(f"{item['selector']} is {item['width']:.1f}px wide, rendering "
                    f"{item['text']!r} roughly one character per line (rule L12)"),
        ))

    for item in page.evaluate(_L12_TABLE_WIDTH_JS):
        findings.append(Finding(
            fingerprint=fingerprint("L12", route, width, theme,
                                     salt=f"tablewidth:{item['selector']}"),
            check="L12", route=route, width=width, theme=theme,
            severity=SEVERITY_BY_CHECK["L12"],
            detail=(f"{item['selector']}: table scrollWidth {item['scrollWidth']} exceeds "
                    f"its card clientWidth {item['cardClientWidth']}, and is neither a "
                    "stacked .table-stack table nor inside a horizontally scrollable "
                    "ancestor (rule L12)"),
        ))

    return findings


# ── PAT-2257 checks (a)-(e) ─────────────────────────────────────────────
# Each runs at every width and theme of the matrix, in the stub walk and the
# prod walk alike. Like the checks above they measure computed geometry or
# rendered text, never a class name alone.

# (a) Adjacent table cells must not intersect. Table layout never overlaps
# two cells' own boxes, so the real defect is a cell's CONTENT spilling into
# its neighbour (a nowrap version string wider than a fixed column, an
# absolutely positioned badge). Each cell's visual extent is its own box
# united with its text's line boxes, each clipped to the nearest ancestor
# (within the cell) that clips overflow, so deliberate ellipsis truncation
# never counts as spill. A 1px tolerance absorbs sub-pixel borders.
_CELLS_JS = """
() => {
""" + _CSS_PATH_JS + """
  const T = 1;
  function box(r) { return {l: r.left, t: r.top, r: r.right, b: r.bottom}; }
  function visible(el) {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  }
  function clipper(node, cell) {
    let el = node.nodeType === 1 ? node : node.parentElement;
    while (el) {
      const cs = getComputedStyle(el);
      if (cs.overflowX !== 'visible' || cs.overflowY !== 'visible') return el;
      if (el === cell) return null;
      el = el.parentElement;
    }
    return null;
  }
  function extent(cell) {
    const e = box(cell.getBoundingClientRect());
    const walker = document.createTreeWalker(cell, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
      if (!node.textContent.trim()) continue;
      const range = document.createRange();
      range.selectNodeContents(node);
      const clip = clipper(node, cell);
      const c = clip ? box(clip.getBoundingClientRect()) : null;
      for (const cr of range.getClientRects()) {
        if (cr.width === 0 && cr.height === 0) continue;
        let r = box(cr);
        if (c) {
          r = {l: Math.max(r.l, c.l), t: Math.max(r.t, c.t),
               r: Math.min(r.r, c.r), b: Math.min(r.b, c.b)};
          if (r.r <= r.l || r.b <= r.t) continue;
        }
        e.l = Math.min(e.l, r.l); e.t = Math.min(e.t, r.t);
        e.r = Math.max(e.r, r.r); e.b = Math.max(e.b, r.b);
      }
    }
    return e;
  }
  function intersects(a, b) {
    return a.l < b.r - T && b.l < a.r - T && a.t < b.b - T && b.t < a.b - T;
  }
  const out = [];
  document.querySelectorAll('tr').forEach((tr) => {
    const cells = Array.from(tr.children).filter(
      (c) => (c.tagName === 'TD' || c.tagName === 'TH') && visible(c));
    for (let i = 0; i + 1 < cells.length; i++) {
      const a = cells[i], b = cells[i + 1];
      const ba = box(a.getBoundingClientRect()), bb = box(b.getBoundingClientRect());
      if (intersects(extent(a), bb) || intersects(extent(b), ba)) {
        out.push({selector: __wkCssPath(a), next: __wkCssPath(b),
                  text: (a.textContent.trim() + ' | ' + b.textContent.trim()).slice(0, 80)});
      }
    }
  });
  return out;
}
"""

# (b) A version-shaped (22631.3880, 0.19.24, 15.5) or date-shaped (25 Sep
# 2026, 2026-09-25, 25/09/2026) string never breaks across lines anywhere on
# the page. Measured per match with a Range: its line boxes sitting on more
# than one line (tops more than 3px apart) is a break. A date with its time
# on a second line is not this defect: only the date part is matched.
_BREAK_JS = """
() => {
""" + _CSS_PATH_JS + """
  const PATTERNS = [
    ['version', /\\b\\d+(?:\\.\\d+){1,3}\\b/g],
    ['date', /\\b\\d{1,2}\\s+[A-Z][a-z]{2}\\s+\\d{4}\\b/g],
    ['date', /\\b\\d{4}-\\d{2}-\\d{2}\\b/g],
    ['date', /\\b\\d{1,2}\\/\\d{1,2}\\/\\d{2,4}\\b/g],
  ];
  const SKIP = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'TEXTAREA']);
  const out = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let node;
  while ((node = walker.nextNode())) {
    const parent = node.parentElement;
    if (!parent || SKIP.has(parent.tagName)) continue;
    const text = node.textContent;
    for (const [kind, re] of PATTERNS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text))) {
        if (m[0].length < 3) continue;
        const range = document.createRange();
        range.setStart(node, m.index);
        range.setEnd(node, m.index + m[0].length);
        const tops = [];
        for (const r of range.getClientRects()) {
          if (r.width === 0 && r.height === 0) continue;
          if (!tops.some((t) => Math.abs(t - r.top) <= 3)) tops.push(r.top);
        }
        if (tops.length > 1) {
          out.push({selector: __wkCssPath(parent), kind: kind, text: m[0], lines: tops.length});
        }
      }
    }
  }
  return out;
}
"""

# (c) Customer-visible text: every rendered text node plus the title,
# aria-label, alt and placeholder attributes a customer (or their screen
# reader) meets. Only [data-walker-ignore] opts out. Text inside a
# display:none subtree is not customer-visible and is skipped; a
# screen-reader-only label is visible to its reader and is kept.
_LEAK_JS = """
() => {
""" + _CSS_PATH_JS + """
  const SKIP = 'script, style, noscript, template, [data-walker-ignore]';
  const CODE = 'pre, code, kbd, samp';
  const out = [];
  function shown(el) { return el.getClientRects().length > 0; }
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let node;
  while ((node = walker.nextNode())) {
    const text = node.textContent;
    if (!text || !text.trim()) continue;
    const el = node.parentElement;
    if (!el || el.closest(SKIP) || !shown(el)) continue;
    out.push({selector: __wkCssPath(el), text: text.trim().slice(0, 2000),
              inCode: Boolean(el.closest(CODE))});
  }
  document.querySelectorAll('[title], [aria-label], [alt], [placeholder]').forEach((el) => {
    if (el.closest(SKIP)) return;
    ['title', 'aria-label', 'alt', 'placeholder'].forEach((attr) => {
      const v = (el.getAttribute(attr) || '').trim();
      if (v) out.push({selector: __wkCssPath(el) + '[' + attr + ']', text: v.slice(0, 2000),
                       inCode: false});
    });
  });
  return out;
}
"""

# (d) The header theme toggle (templates/base.html) on this page: which
# button claims to be active (is-active class AND aria-pressed="true"), the
# theme actually applied (<html data-theme>), and each button's painted
# colours, so an "active" state that looks identical to the inactive one
# still fails.
_THEME_TOGGLE_JS = """
() => {
  const group = document.querySelector('.theme-toggle');
  if (!group) return {present: false};
  const current = document.documentElement.getAttribute('data-theme') || '';
  const buttons = Array.from(group.querySelectorAll('[data-theme-choice]')).map((b) => {
    const cs = getComputedStyle(b);
    return {
      choice: b.getAttribute('data-theme-choice'),
      classActive: b.classList.contains('is-active'),
      pressed: b.getAttribute('aria-pressed') === 'true',
      paint: cs.backgroundColor + '|' + cs.color,
    };
  });
  return {present: true, current: current, buttons: buttons};
}
"""

# (e) Named counts (NAMED_COUNTS). For each phrase, the deepest rendered
# elements whose text contains it; from each, up to three ancestors (short
# text only) are searched for a number either before the phrase ("96
# awaiting approval", "12 extensions waiting on a decision") or after it as
# a label ("Awaiting approval 96", "Not reporting (3)").
_COUNTS_JS = """
(phrases) => {
""" + _CSS_PATH_JS + """
  const norm = (s) => (s || '').replace(/\\s+/g, ' ').trim().toLowerCase();
  const SKIP = 'script, style, noscript, template, [data-walker-ignore]';
  const all = Array.from(document.body.querySelectorAll('*')).filter(
    (el) => !el.closest(SKIP) && el.getClientRects().length > 0);
  const out = [];
  phrases.forEach((phrase) => {
    const esc = phrase.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&');
    const before = new RegExp('(\\\\d[\\\\d,]*)\\\\s+((?:[a-z]+\\\\s+){0,2}?)' + esc + '\\\\b');
    const after = new RegExp('\\\\b' + esc + '\\\\s*[:(]?\\\\s*(\\\\d[\\\\d,]*)\\\\b');
    const holders = all.filter((el) => norm(el.innerText).includes(phrase));
    const deepest = holders.filter((el) => !holders.some((o) => o !== el && el.contains(o)));
    const used = new Set();
    deepest.forEach((el) => {
      let a = el;
      for (let i = 0; i < 4 && a && a !== document.body; i++, a = a.parentElement) {
        const t = norm(a.innerText);
        if (t.length > 200) break;
        let key = null, value = null;
        let m = before.exec(t);
        if (m) { key = (m[2] + phrase).trim(); value = m[1]; }
        else {
          m = after.exec(t);
          if (m) { key = phrase; value = m[1]; }
        }
        if (key !== null) {
          if (!used.has(a)) {
            used.add(a);
            out.push({key: key, value: value.replace(/,/g, ''), selector: __wkCssPath(a)});
          }
          break;
        }
      }
    });
  });
  return out;
}
"""


def check_cells(page, route: str, width: int | None, theme: str | None) -> list[Finding]:
    """(a) Adjacent table cells' visual extents must not intersect."""
    findings: list[Finding] = []
    for item in page.evaluate(_CELLS_JS):
        findings.append(Finding(
            fingerprint=fingerprint("cells", route, width, theme, salt=item["selector"]),
            check="cells", route=route, width=width, theme=theme,
            severity=SEVERITY_BY_CHECK["cells"],
            detail=(f"{item['selector']} intersects its neighbour {item['next']} "
                    f"({item['text']!r})"),
        ))
    return findings


def check_break(page, route: str, width: int | None, theme: str | None) -> list[Finding]:
    """(b) Version- and date-shaped strings never break mid-string."""
    findings: list[Finding] = []
    for item in page.evaluate(_BREAK_JS):
        findings.append(Finding(
            fingerprint=fingerprint("break", route, width, theme,
                                     salt=f"{item['selector']}:{item['text']}"),
            check="break", route=route, width=width, theme=theme,
            severity=SEVERITY_BY_CHECK["break"],
            detail=(f"{item['selector']}: {item['kind']} {item['text']!r} breaks across "
                    f"{item['lines']} lines"),
        ))
    return findings


def check_leak(page, route: str, width: int | None, theme: str | None,
               *, secrets: tuple[str, ...] = ()) -> list[Finding]:
    """(c) No ticket reference, the word "ticket", a GUID or `--` in
    customer-visible text (LEAK_PATTERNS; `--` allowed in code)."""
    findings: list[Finding] = []
    for node in page.evaluate(_LEAK_JS):
        text = node["text"]
        for name, pattern in LEAK_PATTERNS:
            if node.get("inCode") and name in LEAK_CODE_EXEMPT:
                continue
            match = pattern.search(text)
            if not match:
                continue
            findings.append(Finding(
                fingerprint=fingerprint("leak", route, width, theme,
                                         salt=f"{node['selector']}:{name}"),
                check="leak", route=route, width=width, theme=theme,
                severity=SEVERITY_BY_CHECK["leak"],
                detail=(f"{node['selector']}: {name} {redact(match.group(0), secrets)!r} "
                        f"in {_clip(text, 120, secrets)!r}"),
            ))
    return findings


def check_theme_toggle(page, route: str, width: int | None, theme: str | None) -> list[Finding]:
    """(d) The theme toggle is on the page and shows exactly one active
    button: the one for the theme actually applied, painted differently
    from the inactive one."""
    data = page.evaluate(_THEME_TOGGLE_JS)
    problem = None
    if not data.get("present"):
        problem = "no theme toggle on the page"
    else:
        buttons = data.get("buttons") or []
        active = [b for b in buttons if b["classActive"] and b["pressed"]]
        inactive = [b for b in buttons if not (b["classActive"] or b["pressed"])]
        if len(active) != 1:
            problem = f"{len(active)} theme buttons show an active state (expected exactly 1)"
        elif active[0]["choice"] != data.get("current"):
            problem = (f"the {active[0]['choice']!r} button is shown active but the page is "
                       f"in {data.get('current')!r}")
        elif any(b["paint"] == active[0]["paint"] for b in inactive):
            problem = "the active theme button looks identical to the inactive one"
    if problem is None:
        return []
    return [Finding(
        fingerprint=fingerprint("theme-toggle", route, width, theme, salt=problem),
        check="theme-toggle", route=route, width=width, theme=theme,
        severity=SEVERITY_BY_CHECK["theme-toggle"], detail=problem,
    )]


def check_counts(page, route: str, width: int | None, theme: str | None) -> list[Finding]:
    """(e) The same named count (NAMED_COUNTS) shows one value everywhere
    it appears on the page."""
    by_key: dict[str, dict[str, list[str]]] = {}
    for item in page.evaluate(_COUNTS_JS, list(NAMED_COUNTS)):
        by_key.setdefault(item["key"], {}).setdefault(item["value"], []).append(item["selector"])
    findings: list[Finding] = []
    for key, values in sorted(by_key.items()):
        if len(values) < 2:
            continue
        shown = ", ".join(f"{v} at {sels[0]}" for v, sels in sorted(values.items()))
        findings.append(Finding(
            fingerprint=fingerprint("count-mismatch", route, width, theme, salt=key),
            check="count-mismatch", route=route, width=width, theme=theme,
            severity=SEVERITY_BY_CHECK["count-mismatch"],
            detail=f"{key!r} shows {len(values)} different values on one page: {shown}",
        ))
    return findings


def check_pat2257(page, route: str, width: int | None, theme: str | None,
                  *, secrets: tuple[str, ...] = ()) -> list[Finding]:
    """All five PAT-2257 checks, in a fixed order."""
    return (check_cells(page, route, width, theme)
            + check_break(page, route, width, theme)
            + check_leak(page, route, width, theme, secrets=secrets)
            + check_theme_toggle(page, route, width, theme)
            + check_counts(page, route, width, theme))


def check_link(url: str, status: int, route: str, width: int | None,
                theme: str | None, *, service_identity: bool = False) -> list[Finding]:
    if 200 <= status < 300:
        return []
    if status == 429:
        return [_rate_limited_finding(f"internal link {url}", route, width, theme, salt=url)]
    if status == 403 and service_identity:
        return [_not_visible_finding(f"internal link {url}", route, width, theme, salt=url)]
    return [Finding(
        fingerprint=fingerprint("link", route, width, theme, salt=url),
        check="link", route=route, width=width, theme=theme,
        severity=SEVERITY_BY_CHECK["link"],
        detail=f"internal link {url} returned status {status}",
    )]


def check_auth(status: int, route: str) -> list[Finding]:
    """Unauthenticated request. Passes if the route 401s/403s directly, or
    the (unfollowed) response is a redirect - a live deployment's redirect
    target is Cloudflare Access's own sign-in page, which never reaches this
    app, so a redirect status here is the closest this app-level check can
    get to confirming "redirects to sign-in" for a real edge."""
    if status in (401, 403) or 300 <= status < 400:
        return []
    return [Finding(
        fingerprint=fingerprint("auth", route, None, None, salt=str(status)),
        check="auth", route=route, width=None, theme=None,
        severity=SEVERITY_BY_CHECK["auth"],
        detail=(f"{route} returned status {status} to an unauthenticated request "
                "(expected 401/403 or a sign-in redirect)"),
    )]


def check_missing_fixture(route_template: str) -> list[Finding]:
    return [Finding(
        fingerprint=fingerprint("status", route_template, None, None, salt="missing-fixture"),
        check="status", route=route_template, width=None, theme=None,
        severity=SEVERITY_BY_CHECK["status"],
        detail=(f"{route_template} has a path param with no fixture id configured in "
                "e2e/walk/walk.py's FIXTURE_PARAMS - not walked"),
    )]


def check_skipped_query(route_template: str) -> list[Finding]:
    return [Finding(
        fingerprint=fingerprint("skipped", route_template, None, None,
                                 salt="missing-query-fixture"),
        check="skipped", route=route_template, width=None, theme=None,
        severity=SEVERITY_BY_CHECK["skipped"],
        detail=(f"{route_template} needs query parameters to render anything but a 400 and "
                "has no fixture value configured in e2e/walk/walk.py's FIXTURE_QUERY_PARAMS - "
                "not walked"),
    )]


# ── Route discovery ─────────────────────────────────────────────────────


def discover_routes(app) -> list[str]:
    """Reads the route table straight off the running FastAPI app (not a
    hard-coded list), so a new page is walked automatically. Skips
    /healthz, /static/* and any route that doesn't answer GET."""
    seen: set[str] = set()
    routes: list[str] = []
    for r in app.routes:
        path = getattr(r, "path", None)
        methods = getattr(r, "methods", None)
        if path is None or not methods or "GET" not in methods:
            continue
        if path == "/healthz" or path.startswith("/static"):
            continue
        if path in seen:
            continue
        seen.add(path)
        routes.append(path)
    return sorted(routes)


@dataclass(frozen=True)
class StubPage:
    """One page the stub walk loads, at every theme and width."""

    template: str  # the route template it belongs to
    route: str  # the concrete path that is loaded, and what its findings name
    query: str = ""  # "?..." from FIXTURE_QUERY_PARAMS, or ""
    # The widths it is loaded at (PAT-2329): the full matrix for a
    # phone-supported route, both desktop widths for a dense one.
    widths: tuple[int, ...] = WIDTHS


@dataclass
class StubPlan:
    """What the stub walk will load for a `--routes` filter, worked out before
    any browser starts (PAT-2300)."""

    pages: list[StubPage] = field(default_factory=list)
    # Routes that match but cannot be loaded (no fixture id, no query value).
    findings: list[Finding] = field(default_factory=list)
    # Filters that matched no route. Any of these fails the walk.
    unmatched: list[str] = field(default_factory=list)

    @property
    def page_loads(self) -> int:
        """Sum the actual width matrix selected for each route (PAT-2329)."""
        return sum(len(THEMES) * len(page.widths) for page in self.pages)

    @property
    def widths_by_route(self) -> dict[str, tuple[int, ...]]:
        return {page.route: page.widths for page in self.pages}


class RouteFilterError(ValueError):
    """`--routes` named something that is not a route. Raised rather than
    walking less, so a typo can never read as a clean walk (PAT-2300)."""

    def __init__(self, unmatched: list[str]):
        self.unmatched = list(unmatched)
        super().__init__(unmatched_message(unmatched))


def unmatched_message(unmatched: list[str]) -> str:
    return (
        f"--routes matched no route: {', '.join(repr(name) for name in unmatched)}\n"
        "a filter is a route template (/devices/{device_id}) or a concrete path "
        "(/devices/dev-mac-001); a query string is not matched (the stub walk's query "
        "values come from FIXTURE_QUERY_PARAMS). Nothing was walked.")


def _template_pattern(template: str) -> re.Pattern[str]:
    """A route template as a pattern over one concrete path: each `{param}` is
    any non-empty run inside a single path segment (so never a `?query` or a
    `#fragment`), everything else literal."""
    pattern, pos = "", 0
    for match in _PARAM_RE.finditer(template):
        pattern += re.escape(template[pos:match.start()]) + "([^/?#]+)"
        pos = match.end()
    return re.compile(pattern + re.escape(template[pos:]))


def _specificity(template: str) -> tuple[int, int, str]:
    """Sort key for templates that fit the same path: fewest params first,
    then the most literal characters. It is the route the server picks for
    this app (`/devices/jamf` over `/devices/{device_id}`, and the `.csv`
    route over the plain one for `/ai-tooling/devices/x.csv`)."""
    return (len(_PARAM_RE.findall(template)), -len(_PARAM_RE.sub("", template)), template)


def phone_supported_routes() -> frozenset[str]:
    """The portal's own list of phone-supported route templates
    (`main.PHONE_SUPPORTED_ROUTES`, PAT-2329): the one source of truth, read
    here rather than copied, so the walker and the dense-page note in the
    templates can never disagree about which pages are phone-supported."""
    import main as portal_main  # local import: needs REPO_ROOT on sys.path first

    return portal_main.PHONE_SUPPORTED_ROUTES


@functools.cache
def _portal_route_templates() -> tuple[str, ...]:
    import main as portal_main  # local import: needs REPO_ROOT on sys.path first

    return tuple(discover_routes(portal_main.app))


def route_template(path: str, templates: Iterable[str]) -> str | None:
    """The route template the server serves a concrete `path` with, or None.

    Matched segment by segment, so `/devices/abc-123` is `/devices/{device_id}`
    and `/devices/abc/compliance` is not (its own template is), and the most
    specific template wins as it does for the server (`/devices/jamf` is the
    Jamf page, not device "jamf"). The query string is not part of the path, and
    the path is percent-decoded first because the server routes the decoded
    path (an encoded `/` in an id is a segment boundary to it)."""
    path = unquote(urlsplit(path).path)
    hits = [t for t in templates if _template_pattern(t).fullmatch(path)]
    return min(hits, key=_specificity) if hits else None


def widths_for_template(template: str | None, *, prod: bool,
                        phone_routes: frozenset[str] | None = None) -> tuple[int, ...]:
    """The widths a route is walked at (PAT-2329). A phone-supported route gets
    the full matrix (WIDTHS, or PROD_WIDTHS in the prod walk); every other
    route, and a path that matches no route, gets both desktop widths."""
    phone = phone_supported_routes() if phone_routes is None else phone_routes
    if template is not None and template in phone:
        return PROD_WIDTHS if prod else WIDTHS
    return PROD_DENSE_WIDTHS if prod else DENSE_WIDTHS


def prod_widths_for_path(path: str, *, templates: Iterable[str] | None = None,
                         phone_routes: frozenset[str] | None = None) -> tuple[int, ...]:
    """`widths_for_template` for a concrete production path, which can carry a
    real id and a query string."""
    known = _portal_route_templates() if templates is None else templates
    return widths_for_template(route_template(path, known), prod=True,
                               phone_routes=phone_routes)


def plan_stub_walk(app, routes_filter: list[str] | None,
                   phone_routes: frozenset[str] | None = None) -> StubPlan:
    """Which pages the stub walk loads for `routes_filter` (all of them when
    it is empty).

    A filter is a route template, which is loaded with its FIXTURE_PARAMS ids,
    or a concrete path, matched to its template segment by segment (`{param}`
    stands for any one segment) and loaded exactly as given: its ids are not
    swapped for the fixture's, so an id the stub does not serve shows up as a
    real `status` finding instead of being skipped or quietly replaced. Two
    filters for the same page load it once. A filter that fits no route is
    returned in `unmatched`; the caller must not walk in that case."""
    templates = discover_routes(app)
    known = set(templates)
    plan = StubPlan()
    picks: list[tuple[str, str | None]] = []
    if not routes_filter:
        picks = [(template, None) for template in templates]
    else:
        for name in routes_filter:
            if name in known:
                picks.append((name, None))
                continue
            # A `{...}` that is not a template of this app is a typo, not an id.
            # Match the decoded path, as the server does, but load it as given.
            hits = ([] if "{" in name or "}" in name else
                    [t for t in templates if _template_pattern(t).fullmatch(unquote(name))])
            if not hits:
                plan.unmatched.append(name)
                continue
            picks.append((min(hits, key=_specificity), name))

    seen: set[str] = set()
    for template, given in sorted(set(picks), key=lambda pick: (pick[0], pick[1] or "")):
        if given is None:
            route, ok = resolve_route(template)
            if not ok:
                plan.findings.extend(check_missing_fixture(template))
                continue
        else:
            route = given
        query, query_ok = resolve_route_query(route)
        if not query_ok:
            plan.findings.extend(check_skipped_query(route))
            continue
        if route in seen:
            continue
        seen.add(route)
        plan.pages.append(StubPage(
            template, route, query,
            widths_for_template(template, prod=False, phone_routes=phone_routes)))
    return plan


def resolve_route(template: str) -> tuple[str, bool]:
    """Returns (concrete_path, ok). ok is False when the template has a
    path param this module has no fixture id for - the caller must report
    that (check_missing_fixture), never silently skip it."""
    params = _PARAM_RE.findall(template)
    if not params:
        return template, True
    fixture = FIXTURE_PARAMS.get(template)
    if fixture is None:
        return template, False
    concrete = template
    for name in params:
        if name not in fixture:
            return template, False
        concrete = concrete.replace("{" + name + "}", str(fixture[name]))
    return concrete, True


def resolve_route_query(concrete_route: str) -> tuple[str, bool]:
    """Returns (query_string, ok) - query_string already includes a leading
    `?` when non-empty. A route not in FIXTURE_QUERY_PARAMS needs no query
    params to walk (ok=True, empty string). A route present with a `None`
    value is one the walker knows needs params but has no fixture wired up
    for - ok=False, and the caller must report that explicitly
    (check_skipped_query) rather than walking it bare."""
    if concrete_route not in FIXTURE_QUERY_PARAMS:
        return "", True
    params = FIXTURE_QUERY_PARAMS[concrete_route]
    if params is None:
        return "", False
    return "?" + urlencode(params), True


# ── Orchestration ──────────────────────────────────────────────────────


def _scroll_through(page) -> None:
    """Some pages may reveal content on scroll (IntersectionObserver-style
    reveal). Scroll to the bottom in viewport-sized steps before a full-page
    screenshot, so nothing below the fold is captured blank."""
    with contextlib.suppress(Exception):
        viewport = page.viewport_size["height"] if page.viewport_size else 900
        y = 0
        height = page.evaluate("document.body.scrollHeight")
        while y < height:
            page.evaluate(f"window.scrollTo(0, {y})")
            page.wait_for_timeout(40)
            y += viewport
            height = page.evaluate("document.body.scrollHeight")
        page.evaluate("window.scrollTo(0, 0)")
        page.wait_for_timeout(40)


def _internal_links(page, harness_url: str) -> set[str]:
    origin = urlsplit(harness_url)
    hrefs = page.evaluate(_LINKS_JS)
    out: set[str] = set()
    for href in hrefs:
        if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        absolute = urljoin(page.url, href)
        parts = urlsplit(absolute)
        if parts.scheme not in ("http", "https"):
            continue
        if (parts.scheme, parts.netloc) != (origin.scheme, origin.netloc):
            continue
        out.add(absolute.split("#", 1)[0])
    return out


class PageSignals:
    """What one page load reported: console errors, failed requests, and the
    same-origin responses that were 429 (with their headers, for Retry-After).
    Requests to an ignored host (Cloudflare's beacon) are never recorded."""

    def __init__(self, origin: tuple[str, str, int] | None):
        self.origin = origin
        self.js_errors: list[str] = []
        self.failed_requests: list[str] = []
        self.rate_limited: list[str] = []
        self.rate_limit_headers: list[Mapping[str, str]] = []
        self.redirect_requests: dict[object, str] = {}

    def attach(self, page) -> None:
        # The guard records validated, controlled hops by exact Request identity.
        page._portal_redirect_requests = self.redirect_requests
        page.on("pageerror", lambda exc: self.js_errors.append(str(exc)))
        page.on("console", self._on_console)
        page.on("requestfailed", self._on_request_failed)
        page.on("response", self._on_response)

    def reset(self) -> None:
        self.js_errors.clear()
        self.failed_requests.clear()
        self.rate_limited.clear()
        self.rate_limit_headers.clear()
        self.redirect_requests.clear()

    def _on_console(self, msg) -> None:
        if msg.type != "error":
            return
        if is_ignored_url((msg.location or {}).get("url") or ""):
            return
        self.js_errors.append(msg.text)

    def _on_request_failed(self, req) -> None:
        if is_ignored_url(req.url):
            return
        if req.failure == "net::ERR_ABORTED" and req in self.redirect_requests:
            return  # Only the guard's own validated navigation cancellation.
        self.failed_requests.append(f"{req.method} {req.url} -> {req.failure}")

    def _on_response(self, resp) -> None:
        if (resp.status == 429 and self.origin is not None
                and _origin(resp.url) == self.origin):
            self.rate_limited.append(resp.url)
            self.rate_limit_headers.append(resp.headers)


def _load_page(page, url: str, signals: PageSignals, pacing: Pacing, *,
               guarded: bool = False) -> None:
    """Navigate and let the page settle. If the portal answered any of it with
    a 429, wait out Retry-After and load it once more from a clean slate; what
    the second load reported is what is left in `signals`.

    `guarded` is the prod walk's: every attempt, the retry included, is a
    fresh `navigate_portal` from the original URL, which paces each redirect
    hop and goes through the context's origin guard exactly as the first did.
    A 429 is never a redirect, so its Location (if any) is never followed."""
    for attempt in (1, 2):
        signals.reset()
        if guarded:
            navigate_portal(page, url, pacing=pacing)
        else:
            pacing.wait()
            page.goto(url, wait_until="load")
        page.wait_for_load_state("networkidle")
        if signals.rate_limited:
            pacing.slow_down()
        if not signals.rate_limited or attempt == 2:
            return
        pacing.sleep(max(pacing.backoff(h) for h in signals.rate_limit_headers))


def check_internal_links(context, link_owner: dict[str, tuple[str, int | None, str | None]],
                         *, pacing: Pacing,
                         base_url: str | None = None,
                         headers: dict[str, str] | None = None,
                         skip_prefixes: tuple[str, ...] = (),
                         service_identity: bool = False,
                         secrets: tuple[str, ...] = (),
                         progress: Callable[[str], None] | None = None) -> list[Finding]:
    """Fetch each collected internal href exactly once (paced, a 429 retried
    once), against the page that first linked to it.

    `headers` are the prod walk's service-token headers: with them, every
    link goes through `fetch_portal` against `base_url` (PAT-2293), which
    refuses an href or redirect hop off that origin before anything is sent.
    Without them each link is a plain unauthenticated fetch (the stub walk)."""
    if headers and not base_url:
        raise ValueError("authenticated link checks need the portal origin (base_url)")
    findings: list[Finding] = []
    items = sorted(link_owner.items())
    for done, (href, (owner_route, owner_width, owner_theme)) in enumerate(items, start=1):
        if progress and (done == 1 or done % 25 == 0 or done == len(items)):
            progress(f"link {done} of {len(items)}, {len(findings)} finding(s) so far, "
                     f"pace {pacing.interval:g}s")
        if skip_prefixes and urlsplit(href).path.startswith(skip_prefixes):
            continue
        started = pacing.clock()
        try:
            resp = (fetch_portal(context, href, base_url, headers, pacing=pacing) if headers
                    else fetch_paced(context, href, pacing=pacing))
        except PlaywrightError as exc:
            findings.append(_fetch_error_finding(
                "link", f"internal link {href}", owner_route, owner_width, owner_theme,
                exc, secrets))
            if progress:
                progress(f"link failed: {redact(urlsplit(href).path, secrets)}: "
                         f"{_short_error(exc, secrets)}")
            continue
        elapsed = pacing.clock() - started
        if progress and elapsed >= SLOW_LINK_SECONDS:
            progress(f"slow link ({elapsed:.0f}s): {urlsplit(href).path}")
        findings.extend(check_link(href, resp.status, owner_route, owner_width, owner_theme,
                                   service_identity=service_identity))
    return findings


def run_walk(harness_url: str, app, routes_filter: list[str] | None = None,
             out_dir: Path = OUT_DIR) -> list[Finding]:
    plan = plan_stub_walk(app, routes_filter)
    if plan.unmatched:
        raise RouteFilterError(plan.unmatched)

    findings: list[Finding] = list(plan.findings)
    screenshots_dir = out_dir / SCREENSHOT_SUBDIR
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    # first-seen (route, width, theme) per internal href, so each is fetched
    # exactly once at the end regardless of how many pages link to it.
    link_owner: dict[str, tuple[str, int | None, str | None]] = {}

    with sync_playwright() as playwright:
        chromium = playwright.chromium.launch()
        authed = chromium.new_context(base_url=harness_url)
        authed.add_cookies([{
            "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
        }])
        authed.route("https://fonts.googleapis.com/**", _stub_out_google_fonts)
        authed.route("https://fonts.gstatic.com/**", _stub_out_google_fonts)
        unauthed = chromium.new_context(base_url=harness_url)
        unauthed.route("https://fonts.googleapis.com/**", _stub_out_google_fonts)
        unauthed.route("https://fonts.gstatic.com/**", _stub_out_google_fonts)

        try:
            for stub_page in plan.pages:
                concrete = stub_page.route
                url = f"{harness_url}{concrete}{stub_page.query}"

                # Auth check: once per route, unauthenticated, no navigation
                # needed - a raw fetch with redirects unfollowed is enough
                # to read the real status this app returns.
                auth_resp = unauthed.request.get(url, max_redirects=0,
                                                  fail_on_status_code=False)
                findings.extend(check_auth(auth_resp.status, concrete))

                for theme in THEMES:
                    for width in stub_page.widths:
                        findings.extend(_walk_one(
                            authed, harness_url, url, concrete, theme, width,
                            screenshots_dir, link_owner))

                # Phone-supported stub pages retain the lightweight L13 pass.
                # Dense pages already check it in their full 1280px matrix.
                if L13_WIDTH not in stub_page.widths:
                    findings.extend(_walk_l13(authed, url, concrete))
        finally:
            authed.close()
            unauthed.close()

        # Link check: fetch each internal href exactly once, authenticated
        # (most pages require it), against its first-seen owning page.
        with contextlib.suppress(Exception):
            linkctx = chromium.new_context(base_url=harness_url)
            linkctx.add_cookies([{
                "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
            }])
            try:
                findings.extend(check_internal_links(linkctx, link_owner, pacing=Pacing()))
            finally:
                linkctx.close()

        chromium.close()

    findings.sort(key=lambda f: f.sort_key())
    return findings


def _walk_one(authed_context, harness_url: str, url: str, route: str, theme: str, width: int,
              screenshots_dir: Path,
              link_owner: dict[str, tuple[str, int | None, str | None]],
              *, probe_headers: dict[str, str] | None = None,
              secrets: tuple[str, ...] = (),
              blocked: list[str] | None = None,
              pacing: Pacing | None = None,
              service_identity: bool = False) -> list[Finding]:
    """One route at one theme and width. `probe_headers`, `secrets` and
    `blocked` are the prod walk's (PAT-2257): credentials for the plain
    fetch probe (the page itself gets them from the context's route guard,
    see install_prod_guard), values that must never reach a screenshot, and
    the guard's shared list of aborted non-GET requests.

    PAT-2285: `pacing` spaces the probe and the page load (none by default,
    as in the stub walk), and a 429 on either is retried once; one that
    persists is a `rate-limited` finding and the page is not checked, because
    a page that half loaded says nothing about the portal. `service_identity`
    is the prod walk's: a 403 is then `not-visible`, not a `status` failure."""
    findings: list[Finding] = []
    pacing = pacing or Pacing()

    # Probe status + content type first via a plain fetch - a page.goto()
    # against a download-disposition route (the CSV exports, the report PDF
    # download) triggers Chromium's download machinery instead of rendering,
    # which page.goto() surfaces as a navigation error. A fetch never has
    # that problem and tells us up front whether there is even a document to
    # render.
    # With the prod credentials the probe goes through fetch_portal, which
    # paces and retries each redirect hop inside its origin check (PAT-2293);
    # nothing carrying the service token is fetched any other way.
    try:
        probe = (fetch_portal(authed_context, url, harness_url, probe_headers, pacing=pacing)
                 if probe_headers else
                 fetch_paced(authed_context, url, pacing=pacing))
    except PlaywrightError as exc:
        # ProdRequestError included: its text is fixed and credential-free,
        # and anything else is redacted before it is shortened.
        findings.append(_fetch_error_finding("status", route, route, width, theme, exc, secrets))
        return findings
    findings.extend(check_status(probe.status, route, width, theme,
                                 service_identity=service_identity))
    if not (200 <= probe.status < 300):
        return findings
    content_type = probe.headers.get("content-type", "")
    if "text/html" not in content_type:
        return findings  # e.g. CSV/PDF download route - no DOM to check

    signals = PageSignals(_origin(url))
    page = authed_context.new_page()
    page.add_init_script(
        f"try {{ localStorage.setItem('{THEME_STORAGE_KEY}', '{theme}'); }} catch (e) {{}}"
    )
    signals.attach(page)
    blocked_before = len(blocked) if blocked is not None else 0
    try:
        page.set_viewport_size({"width": width, "height": VIEWPORT_HEIGHT_BY_WIDTH[width]})
        # Prod: navigate_portal, paced per hop, the 429 retry included.
        _load_page(page, url, signals, pacing, guarded=bool(probe_headers))
        _scroll_through(page)

        for request, target in signals.redirect_requests.items():
            destination = urlsplit(target)
            detail = "redirect -> " + destination.path
            if destination.query:
                detail += "?" + destination.query
            if destination.fragment:
                detail += "#" + destination.fragment
            findings.append(Finding(
                fingerprint=fingerprint("redirect", route, width, theme,
                                        salt=request.url + " -> " + target),
                check="redirect", route=route, width=width, theme=theme,
                severity="info", detail=redact(detail, secrets),
            ))

        if blocked is not None:
            # Requests the prod guard aborted are reported as `readonly`,
            # not as ordinary failed requests.
            aborted = set(blocked[blocked_before:])
            signals.failed_requests[:] = [r for r in signals.failed_requests
                                          if not any(r.startswith(b) for b in aborted)]
            findings.extend(check_readonly(blocked[blocked_before:], route, width, theme,
                                           secrets=secrets))
        if signals.rate_limited:
            for limited_url in dict.fromkeys(signals.rate_limited):
                findings.append(_rate_limited_finding(
                    limited_url, route, width, theme, salt=limited_url))
            return findings
        findings.extend(check_console(
            signals.js_errors, signals.failed_requests, route, width, theme, secrets=secrets))
        findings.extend(check_overflow(page, route, width, theme))
        findings.extend(check_copy(page, route, width, theme, secrets=secrets))
        if width == 390:
            findings.extend(check_l12(page, route, width, theme))
        # L13 also runs here at 1440px, on top of _walk_l13's binding 1280px
        # pass: .col-secondary columns (PAT-2070) only appear at 1440px and
        # up, so a date column can be narrower at 1440px than at 1280px.
        # The prod walk has 1280 in its matrix, so L13 runs there too.
        if width in (1440, L13_WIDTH):
            findings.extend(check_l13(page, route, width, theme))
        findings.extend(check_pat2257(page, route, width, theme, secrets=secrets))

        for href in _internal_links(page, harness_url):
            link_owner.setdefault(href, (route, width, theme))

        slug = _slug(route)
        screenshot_rel = f"{SCREENSHOT_SUBDIR}/{slug}-{width}-{theme}.png"
        if secrets and _page_shows_secret(page, secrets):
            # Never write a credential into a screenshot. The finding says
            # so without repeating the value.
            findings.append(Finding(
                fingerprint=fingerprint("secret-exposure", route, width, theme),
                check="secret-exposure", route=route, width=width, theme=theme,
                severity=SEVERITY_BY_CHECK["secret-exposure"],
                detail="the page rendered the walker's credential; no screenshot was taken",
            ))
            screenshot_rel = None
        else:
            page.screenshot(path=str(screenshots_dir / f"{slug}-{width}-{theme}.png"),
                             full_page=True)
        # Attach the screenshot path to every finding produced for this
        # exact page/theme/width combination.
        for f in findings:
            if f.route == route and f.width == width and f.theme == theme and f.screenshot is None:
                f.screenshot = screenshot_rel
    except PlaywrightError:
        if not secrets:
            raise
        findings.append(_prod_request_finding(
            route, width, theme, "browser request failed or was refused by the origin guard"))
    finally:
        page.close()

    return findings


def _walk_l13(authed_context, url: str, route: str) -> list[Finding]:
    """The dedicated 1280px, light-theme-only pass that checks rubric rule
    L13 (PAT-2162) at its actual binding width - see L13_WIDTH's own
    comment above for why this isn't just another entry in WIDTHS. Runs
    once per phone-supported stub route, deliberately light: no console/overflow/copy/L12
    checks and no screenshot, just enough of a page load for check_l13's
    layout measurement to be real (the probe fetch below still catches a
    non-HTML/non-2xx route, e.g. a CSV/PDF download, without navigating to
    it - same reasoning as _walk_one's own probe)."""
    probe = authed_context.request.get(url, fail_on_status_code=False)
    if not (200 <= probe.status < 300):
        return []
    if "text/html" not in probe.headers.get("content-type", ""):
        return []

    page = authed_context.new_page()
    page.add_init_script(
        f"try {{ localStorage.setItem('{THEME_STORAGE_KEY}', 'light'); }} catch (e) {{}}"
    )
    try:
        page.set_viewport_size({"width": L13_WIDTH, "height": L13_VIEWPORT_HEIGHT})
        page.goto(url, wait_until="load")
        page.wait_for_load_state("networkidle")
        return check_l13(page, route, L13_WIDTH, "light")
    finally:
        page.close()


# ── Authenticated production walk (PAT-2257) ────────────────────────────


@dataclass(frozen=True)
class ProdCredentials:
    """The Cloudflare Access service token. repr is redacted so the values
    can never reach a log line or traceback by accident.

    `session_values` holds the CF_Authorization cookie values Cloudflare
    Access issued this identity during the walk (see learn_session_cookies).
    They are scrubbed like the token itself, and are not part of its identity
    (compare=False), so learning one does not make different credentials."""
    client_id: str
    client_secret: str
    session_values: set[str] = field(default_factory=set, compare=False)

    def __repr__(self) -> str:
        return "ProdCredentials(<redacted>)"

    __str__ = __repr__

    def headers(self) -> dict[str, str]:
        return {"CF-Access-Client-Id": self.client_id,
                "CF-Access-Client-Secret": self.client_secret}

    def secrets(self) -> tuple[str, ...]:
        """Everything to scrub, as of now: call it again after the walk has
        seen more cookies rather than keeping an old tuple."""
        return (self.client_id, self.client_secret, *sorted(self.session_values))


SESSION_COOKIE = "cf_authorization"


def learn_session_cookies(context, creds: ProdCredentials) -> None:
    """Add every CF_Authorization cookie value in `context` to what
    `creds.secrets()` scrubs. The JWT pattern in `redact` already catches a
    well-formed one; this also catches one that is not JWT-shaped.

    Best effort by design: a context that cannot be read (closed, say) adds
    nothing, and the JWT pattern still applies."""
    try:
        cookies = context.cookies()
    except Exception:
        return
    for cookie in cookies:
        if (cookie.get("name") or "").lower() == SESSION_COOKIE and cookie.get("value"):
            creds.session_values.add(cookie["value"])


class ProdConfigError(Exception):
    """Raised before any request is made. Its message never contains a
    credential value, only variable names."""


def prod_credentials_from_env(env: dict[str, str]) -> ProdCredentials:
    client_id = (env.get(PROD_CLIENT_ID_ENV) or "").strip()
    client_secret = (env.get(PROD_CLIENT_SECRET_ENV) or "").strip()
    missing = [name for name, value in ((PROD_CLIENT_ID_ENV, client_id),
                                        (PROD_CLIENT_SECRET_ENV, client_secret)) if not value]
    if missing:
        raise ProdConfigError(
            "--prod needs the Cloudflare Access service token in the environment: "
            + ", ".join(missing) + " not set")
    return ProdCredentials(client_id, client_secret)


def _origin(url: str) -> tuple[str, str, int] | None:
    """Compare scheme, host and effective port; reject ambiguous URL syntax."""
    if "\\" in url or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        return None
    try:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return None
        if parts.username is not None or parts.password is not None:
            return None
        port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
        return parts.scheme, parts.hostname.lower(), port
    except ValueError:
        return None


def validate_prod_base_url(base_url: str) -> str:
    """https only, no path. A plain-http base is allowed only for a local
    host (the walker's own tests); the credential is never sent in clear
    text to anything else."""
    parts = urlsplit(base_url.rstrip("/"))
    host = (parts.hostname or "").lower()
    if parts.path or parts.query or parts.fragment or not host or _origin(base_url) is None:
        raise ProdConfigError("--base-url must be an origin only, without user information")
    if parts.scheme != "https" and not (parts.scheme == "http"
                                         and host in ("localhost", "127.0.0.1")):
        raise ProdConfigError("--base-url must be https")
    return f"{parts.scheme}://{parts.netloc}"


def prod_request_headers(url: str, base_url: str, creds: ProdCredentials) -> dict[str, str]:
    """The service-token headers for a request to the portal's own origin,
    and nothing for any other origin (a font CDN, Cloudflare's team domain):
    the credential goes to app.patched.im and nowhere else."""
    if _origin(url) is None or _origin(url) != _origin(base_url):
        return {}
    return creds.headers()


MAX_PROD_REDIRECTS = 10
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_AUTH_HEADERS = {"cf-access-client-id", "cf-access-client-secret", "cookie", "authorization",
                 "proxy-authorization", "cf-access-jwt-assertion"}


class ProdRequestError(PlaywrightError):
    """A credential-safe failure: never copy Playwright's header-bearing call log."""


def _redirect_target(response, url: str, allowed_origin: str) -> str | None:
    location = response.headers.get("location")
    if response.status not in _REDIRECT_STATUSES or location is None:
        return None
    try:
        target = urljoin(url, location)
    except ValueError:
        raise ProdRequestError("invalid redirect refused") from None
    if _origin(target) is None or _origin(target) != _origin(allowed_origin):
        raise ProdRequestError("cross-origin or invalid redirect refused")
    return target


def fetch_portal(context, url: str, base_url: str, headers: dict[str, str], *,
                 pacing: Pacing | None = None):
    """Authenticated API GET: inspect every hop before any credentials leave.

    PAT-2285: each hop is paced and retried on its own (`_send_with_retry`: a
    429 once after Retry-After, a dropped connection once). A retry repeats
    that hop's URL and checks its origin again before sending, exactly as the
    first attempt did, and never reads a 429's Location: only a 3xx is a
    redirect, and its target is checked by `_redirect_target` like any other."""
    pacing = pacing if pacing is not None else Pacing()
    for hop in range(MAX_PROD_REDIRECTS + 1):
        response = _fetch_portal_hop(context, url, base_url, headers, pacing)
        try:
            target = _redirect_target(response, url, base_url)
        except ProdRequestError:
            response.dispose()
            raise
        if target is None:
            return response
        response.dispose()
        if hop == MAX_PROD_REDIRECTS:
            raise ProdRequestError("portal redirect limit exceeded")
        url = target


def _fetch_portal_hop(context, url: str, base_url: str, headers: dict[str, str],
                      pacing: Pacing):
    """One hop of fetch_portal: the credentialed GET, never following a
    redirect, paced and retried by `_send_with_retry`."""

    def send():
        # Before every attempt, the retry included.
        if _origin(url) is None or _origin(url) != _origin(base_url):
            raise ProdRequestError("cross-origin or invalid request refused")
        return context.request.get(url, headers=headers, max_redirects=0,
                                   fail_on_status_code=False, timeout=FETCH_TIMEOUT_MS)

    try:
        return _send_with_retry(send, pacing)
    except ProdRequestError:
        raise
    except PlaywrightError as exc:
        failure = "portal request timed out" if _is_timeout(exc) else "portal request failed"
    # Raised outside the handler so Playwright's error, whose call log carries
    # the request headers, is neither chained nor kept as context.
    raise ProdRequestError(failure) from None


def _prod_request_finding(route: str, width: int | None, theme: str | None,
                          message: str) -> Finding:
    return Finding(fingerprint=fingerprint("status", route, width, theme, salt=message),
                   check="status", route=route, width=width, theme=theme,
                   severity=SEVERITY_BY_CHECK["status"], detail=message)


# Disables form submission in the page before any of its own script runs:
# a submit event is cancelled and form.submit()/requestSubmit() do nothing.
# The network guard below would abort the resulting POST anyway; this stops
# the walker from ever starting one.
_NO_SUBMIT_INIT_JS = """
(() => {
  document.addEventListener('submit', (e) => {
    e.preventDefault();
    e.stopImmediatePropagation();
  }, true);
  try {
    HTMLFormElement.prototype.submit = function () {};
    HTMLFormElement.prototype.requestSubmit = function () {};
  } catch (e) {}
})();
"""


def install_prod_guard(context, base_url: str, creds: ProdCredentials,
                       blocked: list[str]) -> None:
    """Fetch one hop only; never return a redirect to Chromium.

    Playwright does not re-route a browser's redirect hops. Top-level walker
    navigations follow validated redirects through navigate_portal instead.
    Other redirects fail visibly rather than escaping this boundary.
    """
    context._portal_redirects = {}

    def _handle(route):
        request = route.request
        if request.method.upper() not in READ_ONLY_METHODS:
            blocked.append(f"{request.method} {redact(request.url, creds.secrets())}")
            route.abort("blockedbyclient")
            return
        response = None
        try:
            if _origin(request.url) is None:
                raise ProdRequestError("invalid request refused")
            headers = {k: v for k, v in request.all_headers().items()
                       if k.lower() not in _AUTH_HEADERS}
            extra = prod_request_headers(request.url, base_url, creds)
            if extra:
                headers.update(extra)
                # Let the API context supply the portal's own cookies.
            else:
                # route.continue_ cannot override Cookie. route.fetch can;
                # an empty header also suppresses the API context's cookie jar.
                headers["cookie"] = ""
            response = route.fetch(headers=headers, max_redirects=0)
            target = _redirect_target(response, request.url, base_url)
            if target is not None:
                # Only the helper's current top-level navigation may follow.
                if (request.is_navigation_request() and request.frame.parent_frame is None
                        and request.frame.page in context._portal_redirects):
                    context._portal_redirects[request.frame.page] = target
                    notes = getattr(request.frame.page, "_portal_redirect_requests", None)
                    if notes is not None:
                        notes[request] = target
                    # A 204 cancels navigation without starting Chromium's
                    # asynchronous error page, which could race the next hop.
                    route.fulfill(status=204, body="")
                else:
                    route.abort("blockedbyclient")
                return
            route.fulfill(response=response)
        except PlaywrightError:
            # Never propagate a fetch exception with its header-bearing call log.
            route.abort("blockedbyclient")
        finally:
            if response is not None:
                response.dispose()

    context.route("**/*", _handle)
    context.add_init_script(_NO_SUBMIT_INIT_JS)


def navigate_portal(page, url: str, *, pacing: Pacing | None = None):
    """Follow safe top-level redirects using fresh, independently guarded GETs.

    With `pacing` (PAT-2285), every hop waits its turn like any other
    authenticated request."""
    redirects = page.context._portal_redirects
    for hop in range(MAX_PROD_REDIRECTS + 1):
        if pacing is not None:
            pacing.wait()
        redirects[page] = None
        try:
            response = page.goto(url, wait_until="load")
        except PlaywrightError:
            # The guard's 204 usually surfaces as an aborted navigation.
            target = redirects[page]
            if target is None:
                raise ProdRequestError(
                    "browser request failed or unsafe redirect refused") from None
        else:
            # Another Chromium may treat the 204 as a completed navigation.
            # A recorded target still means the page is a blank intermediate
            # hop, so follow it rather than checking that page.
            target = redirects[page]
            if target is None:
                return response
        finally:
            redirects.pop(page, None)
        if hop == MAX_PROD_REDIRECTS:
            raise ProdRequestError("portal redirect limit exceeded") from None
        url = target


def check_readonly(blocked: list[str], route: str, width: int | None,
                   theme: str | None, *, secrets: tuple[str, ...] = ()) -> list[Finding]:
    findings: list[Finding] = []
    for entry in dict.fromkeys(blocked):
        findings.append(Finding(
            fingerprint=fingerprint("readonly", route, width, theme, salt=entry),
            check="readonly", route=route, width=width, theme=theme,
            severity=SEVERITY_BY_CHECK["readonly"],
            detail=("the page tried a write request, aborted by the read-only guard: "
                    f"{_clip(entry, 300, secrets)}"),
        ))
    return findings


def _page_shows_secret(page, secrets: tuple[str, ...]) -> bool:
    try:
        html = page.content()
    except Exception:
        return True  # cannot prove it is clean: do not screenshot it
    return any(s and s in html for s in secrets)


def prod_routes(app, routes_filter: list[str] | None) -> tuple[list[str], list[Finding]]:
    """The concrete paths to walk in prod. Given --routes, exactly those
    (concrete paths, query strings allowed; fixture ids mean nothing in
    prod). Otherwise every discovered GET route that needs no path or query
    fixture, with the rest reported as `skipped` rather than walked."""
    if routes_filter:
        return [r for r in routes_filter if not r.startswith(PROD_SKIP_PREFIXES)], []
    walk: list[str] = []
    skipped: list[Finding] = []
    for template in discover_routes(app):
        if _PARAM_RE.search(template) or template in FIXTURE_QUERY_PARAMS:
            skipped.append(Finding(
                fingerprint=fingerprint("skipped", template, None, None, salt="prod-needs-id"),
                check="skipped", route=template, width=None, theme=None,
                severity=SEVERITY_BY_CHECK["skipped"],
                detail=(f"{template} needs a real id or query value in prod; pass it with "
                        "--routes to walk it"),
            ))
            continue
        walk.append(template)
    return walk, skipped


def run_prod_walk(base_url: str, creds: ProdCredentials, routes: list[str],
                  out_dir: Path = OUT_DIR, pacing: Pacing | None = None,
                  progress: Callable[[str], None] | None = None,
                  checkpoint: Callable[[list[Finding]], None] | None = None,
                  widths: Mapping[str, tuple[int, ...]] | None = None) -> list[Finding]:
    """Walk `routes` on the live portal as the read-only service identity,
    at PROD_WIDTHS x THEMES (a dense route without 390px, PAT-2329), with the
    same checks as the stub walk plus the read-only and secret guards. GET
    navigation only; nothing is clicked.

    PAT-2285: every authenticated request is paced (`pacing`, default one
    request per PROD_PACE_SECONDS), a 429 is retried once and otherwise
    reported as `rate-limited`, and a 403 is `not-visible` (admin-only pages
    are 403 to this identity) rather than a broken page or link."""
    base_url = validate_prod_base_url(base_url)
    with sync_playwright() as playwright:
        chromium = playwright.chromium.launch()
        try:
            return walk_prod_routes(chromium, base_url, creds, routes, out_dir, pacing,
                                    progress=progress, checkpoint=checkpoint, widths=widths)
        finally:
            chromium.close()


def walk_prod_routes(chromium, base_url: str, creds: ProdCredentials, routes: list[str],
                     out_dir: Path = OUT_DIR, pacing: Pacing | None = None,
                     progress: Callable[[str], None] | None = None,
                     checkpoint: Callable[[list[Finding]], None] | None = None,
                     widths: Mapping[str, tuple[int, ...]] | None = None) -> list[Finding]:
    """`run_prod_walk` on an already-launched browser (the tests share one:
    Playwright's sync API allows a single instance per thread). `base_url`
    is validated again here (it is idempotent), so no caller can point the
    service token at anything `validate_prod_base_url` would refuse.

    A live walk takes tens of minutes (every link is fetched, paced), so
    `progress` gets a line per route and every few links, and `checkpoint`
    gets the findings so far once the pages are done, before the link phase,
    so a walk that dies late still leaves its page results behind.

    `widths` is each route's widths (PAT-2329: 390px only on a phone-supported
    route). A caller that reports them passes the same mapping it reports, so
    what is printed is what is walked; a route missing from it, or no mapping at
    all, is worked out from the portal's own route table."""
    base_url = validate_prod_base_url(base_url)
    pacing = pacing or Pacing(interval=PROD_PACE_SECONDS)
    findings: list[Finding] = []
    screenshots_dir = out_dir / SCREENSHOT_SUBDIR
    screenshots_dir.mkdir(parents=True, exist_ok=True)
    link_owner: dict[str, tuple[str, int | None, str | None]] = {}
    blocked: list[str] = []

    # Service workers are blocked: they could fetch outside the route guard.
    authed = chromium.new_context(base_url=base_url, service_workers="block")
    install_prod_guard(authed, base_url, creds, blocked)
    unauthed = chromium.new_context(base_url=base_url)
    try:
        for index, route in enumerate(routes, start=1):
            route_widths = (widths or {}).get(route) or prod_widths_for_path(route)
            if progress:
                progress(f"route {index} of {len(routes)}: {route}, "
                         f"widths {', '.join(str(w) for w in route_widths)}, "
                         f"pace {pacing.interval:g}s")
            url = urljoin(base_url + "/", route.lstrip("/"))
            path = urlsplit(url).path or "/"
            auth_resp = unauthed.request.get(url, max_redirects=0, fail_on_status_code=False)
            findings.extend(check_auth(auth_resp.status, path))
            for theme in THEMES:
                for width in route_widths:
                    findings.extend(_walk_one(
                        authed, base_url, url, route, theme, width, screenshots_dir,
                        link_owner, probe_headers=creds.headers(), secrets=creds.secrets(),
                        blocked=blocked, pacing=pacing, service_identity=True))
                    # Cloudflare Access sets CF_Authorization on the first
                    # authenticated response; scrub it from then on.
                    learn_session_cookies(authed, creds)
        if checkpoint:
            checkpoint(findings)
        # Every link goes through fetch_portal with the service token.
        findings.extend(check_internal_links(
            authed, link_owner, pacing=pacing, base_url=base_url, headers=creds.headers(),
            skip_prefixes=PROD_SKIP_PREFIXES, service_identity=True, secrets=creds.secrets(),
            progress=progress))
    finally:
        # Last look before the jar goes: a walk that dies here still has its
        # session cookie scrubbed from the CLI line that reports it.
        learn_session_cookies(authed, creds)
        authed.close()
        unauthed.close()

    findings.sort(key=lambda f: f.sort_key())
    return findings


# A JSON Web Token: three base64url segments, the first a JSON header (`{"`
# encodes as `eyJ`). The signature may be empty (an unsigned token). The
# CF_Authorization cookie is one; so is Cf-Access-Jwt-Assertion.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def redact(text: str, secrets: tuple[str, ...]) -> str:
    """Replace every occurrence of each secret, and every JWT-shaped string,
    with a fixed marker. The longest secret goes first, so one that contains
    another is not left half-replaced.

    Anything that shortens text must call this first: a value cut at the
    boundary no longer matches, and its prefix would survive (PAT-2285)."""
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    return _JWT_RE.sub("[redacted]", text)


def _clip(text: str, limit: int, secrets: tuple[str, ...] = ()) -> str:
    """Redact, then shorten: never the other way round."""
    return redact(text, secrets)[:limit]


def write_report(findings: list[Finding], out_dir: Path,
                 secrets: tuple[str, ...] = ()) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "walk-report.json"
    body = json.dumps([f.to_dict() for f in findings], indent=2, sort_keys=False) + "\n"
    report_path.write_text(redact(body, secrets))
    return report_path


def _widths_lines(widths_by_route: Mapping[str, tuple[int, ...]]) -> list[str]:
    """One line per distinct width set, naming its routes, so the summary
    states which pages were walked at 390px and which were not (PAT-2329)."""
    groups: dict[tuple[int, ...], list[str]] = {}
    for route, widths in widths_by_route.items():
        groups.setdefault(tuple(widths), []).append(route)
    return [f"widths {', '.join(str(w) for w in widths)}: {', '.join(routes)}"
            for widths, routes in sorted(groups.items(), key=lambda kv: (-len(kv[0]), kv[0]))]


def _summarise(findings: list[Finding], page_loads: int,
               widths_by_route: Mapping[str, tuple[int, ...]] | None = None) -> str:
    """`page_loads` is route x theme x width, so "0 finding(s) across 0 page
    loads" cannot pass for a clean walk (PAT-2300). `widths_by_route` adds the
    widths each route was walked at."""
    notes = [f for f in findings if _is_redirect_note(f)]
    findings = [f for f in findings if not _is_redirect_note(f)]
    by_check: dict[str, int] = {}
    by_route: dict[str, int] = {}
    for f in findings:
        by_check[f.check] = by_check.get(f.check, 0) + 1
        by_route[f.route] = by_route.get(f.route, 0) + 1
    lines = [f"{len(findings)} finding(s) across {page_loads} page loads"]
    if findings:
        lines.append("by check: " + ", ".join(f"{k}={v}" for k, v in sorted(by_check.items())))
        top_routes = sorted(by_route.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
        lines.append("top routes: " + ", ".join(f"{k}={v}" for k, v in top_routes))
    if notes:
        lines.append(f"{len(notes)} redirect note(s)")
    if widths_by_route:
        lines.extend(_widths_lines(widths_by_route))
    return "\n".join(lines)


def _is_redirect_note(finding: Finding) -> bool:
    return finding.check == "redirect" and finding.severity == "info"


def _prefixed(message: str) -> str:
    return "\n".join(f"walk: {line}" for line in message.splitlines())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--routes", default=None,
        help=("Comma-separated list to restrict the walk to: route templates "
              "(/devices/{device_id}) or concrete paths (/devices/dev-mac-001). A filter that "
              f"matches no route stops the walk with exit {EXIT_NO_PAGES}. With --prod, "
              "concrete paths only, walked as given."))
    parser.add_argument(
        "--fingerprint", default=None,
        help="Exit non-zero only if this exact fingerprint reproduces; exit 0 otherwise")
    parser.add_argument("--out-dir", default=str(OUT_DIR))
    parser.add_argument(
        "--prod", action="store_true",
        help=(f"Walk the live portal as the read-only service identity (needs "
              f"{PROD_CLIENT_ID_ENV} and {PROD_CLIENT_SECRET_ENV} in the environment). "
              "GET navigation only."))
    parser.add_argument(
        "--base-url", default=PROD_BASE_URL,
        help="Origin for --prod (default %(default)s)")
    parser.add_argument(
        "--pace", type=float, default=None, metavar="SECONDS",
        help=("With --prod: starting minimum seconds between authenticated requests, to stay "
              "under the portal's per-identity rate limit; each 429 widens it, up to "
              f"{PROD_PACE_MAX_SECONDS:g}s (default {PROD_PACE_SECONDS:g}). "
              "The stub walk is not paced."))
    args = parser.parse_args(argv)
    if args.pace is not None and args.pace < 0:
        parser.error("--pace must not be negative")
    if args.pace is not None and not args.prod:
        parser.error("--pace only applies with --prod")

    routes_filter = [r.strip() for r in args.routes.split(",")] if args.routes else None
    out_dir = Path(args.out_dir)

    if args.prod:
        return _main_prod(args, routes_filter, out_dir)

    reset_approval_stub()
    seed_declaration()
    STUB_STATE["mode"] = "ok"

    import main as portal_main  # local import: needs REPO_ROOT on sys.path first

    # Decided before any server or browser starts: a filter that names no route
    # must fail, not walk fewer pages and report a clean result (PAT-2300).
    plan = plan_stub_walk(portal_main.app, routes_filter)
    if plan.unmatched:
        print(_prefixed(unmatched_message(plan.unmatched)), file=sys.stderr)
        return EXIT_NO_PAGES

    with stub_platform_server() as stub_url, harness_process(stub_url) as harness_url:
        findings = run_walk(harness_url, portal_main.app, routes_filter=routes_filter,
                             out_dir=out_dir)

    report_path = write_report(findings, out_dir)
    print(redact(_summarise(findings, plan.page_loads, plan.widths_by_route), ()))
    print(f"report: {report_path}")

    if plan.page_loads == 0:
        # Ahead of --fingerprint, whose exit 0 means "did not reproduce".
        print(_prefixed(NO_PAGE_MESSAGE), file=sys.stderr)
        return EXIT_NO_PAGES
    if args.fingerprint:
        matched = any(f.fingerprint == args.fingerprint for f in findings)
        return 1 if matched else 0
    return 1 if any(not _is_redirect_note(f) for f in findings) else 0


def _main_prod(args, routes_filter: list[str] | None, out_dir: Path) -> int:
    import os

    try:
        creds = prod_credentials_from_env(dict(os.environ))
        base_url = validate_prod_base_url(args.base_url)
    except ProdConfigError as exc:
        print(f"walk: {exc}", file=sys.stderr)
        return 2

    import main as portal_main  # local import: needs REPO_ROOT on sys.path first

    routes, skipped = prod_routes(portal_main.app, routes_filter)
    if not routes:
        print(_prefixed(f"{NO_PAGE_MESSAGE} (paths under {', '.join(PROD_SKIP_PREFIXES)} are "
                        "never walked)"), file=sys.stderr)
        return EXIT_NO_PAGES
    # `pace` is absent when a caller builds args by hand; the default applies.
    pace = getattr(args, "pace", None)
    pacing = Pacing(interval=pace if pace is not None else PROD_PACE_SECONDS)
    # creds.secrets() is called at each use, never kept: it grows as the walk
    # learns the session cookie (learn_session_cookies).

    def _progress(message: str) -> None:
        print(f"walk: {redact(message, creds.secrets())}", file=sys.stderr, flush=True)

    def _checkpoint(so_far: list[Finding]) -> None:
        # The page phase is done; save it before the (long) link phase.
        write_report(sorted(skipped + so_far, key=lambda f: f.sort_key()), out_dir,
                     secrets=creds.secrets())

    # Decided once, here, so the summary states the widths the walk used.
    widths = {route: prod_widths_for_path(route) for route in routes}

    try:
        walked = run_prod_walk(base_url, creds, routes, out_dir=out_dir, pacing=pacing,
                               progress=_progress, checkpoint=_checkpoint, widths=widths)
    except (Exception, KeyboardInterrupt) as exc:
        # Playwright errors may include headers and cookies in their call logs.
        # The CLI must never print an unhandled credential-bearing traceback:
        # one line, the error's first line only (never the call log after it),
        # redacted before it is shortened.
        print(f"walk: the prod walk stopped ({type(exc).__name__}): "
              f"{_short_error(exc, creds.secrets())}", file=sys.stderr)
        return 130 if isinstance(exc, KeyboardInterrupt) else 3
    findings = sorted(skipped + walked, key=lambda f: f.sort_key())
    report_path = write_report(findings, out_dir, secrets=creds.secrets())
    page_loads = sum(len(THEMES) * len(widths[route]) for route in routes)
    print(redact(_summarise(findings, page_loads, widths), creds.secrets()))
    print(f"report: {report_path}")
    if args.fingerprint:
        return 1 if any(f.fingerprint == args.fingerprint for f in findings) else 0
    return 1 if any(not _is_redirect_note(f) for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
