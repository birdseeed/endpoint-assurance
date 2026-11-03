"""Patched customer portal - app.patched.im (PAT-331).

Read-only, customer-scoped view of a tenant's own estate: live CIS L1
posture, open CVE findings, device roster and audit-ready report downloads.

Trust model (PAT-330, locked):
  - Every request must carry a valid CF Access JWT; verified server-side in
    auth.py. Fail closed.
  - No database, no estate state. Every read goes to the platform's
    customer-scoped endpoints with the caller's JWT forwarded verbatim;
    the platform derives the tenant from the verified identity.
  - Read-only, no customer-visible state. The only customer "writes" are
    the mailto: support link (PAT-454), two bounded proxied calls the
    platform owns and validates (report generation POST, report schedule
    PUT - PAT-703), and MDM enrolment-token generation (POST, PAT-453) -
    the token is minted upstream, returned once in the POST response and
    rendered into the install artifacts; the portal never stores it.
  - PAT-2008: POST /software/approvals is the one governance write (admin
    only, Origin + session-bound CSRF + role checked in the portal before
    the platform is called). See the section comment above that route.
"""

import base64
import csv
import decimal
import functools
import hashlib
import hmac
import io
import json
import logging
import os
import re
import threading
import time
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import NamedTuple
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup
from python_multipart import MultipartParser
from python_multipart.multipart import parse_options_header
from starlette.datastructures import UploadFile

import auth
import certificates
import upstream

SUPPORT_EMAIL = "hello@patched.im"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# PAT-2037: this is intentionally a portal asset revision, rather than a
# platform feature switch. The platform endpoint is the source of truth for
# whether feedback exists for a signed-in customer.
PORTAL_BUILD = "2026-10-04-support-feedback"
FEEDBACK_TYPES = ("feature", "design")
SUPPORT_CATEGORIES = {
    "not_working": "Something is not working",
    "findings_or_reports": "Question about my findings or reports",
    "account_billing": "Account and billing",
}
FEEDBACK_TYPE_LABELS = {
    "feature": "Feature request", "design": "Design or usability",
    "support": "Support", "bug": "Problem", "question": "Question",
}
FEEDBACK_STATUS_LABELS = {
    "received": "Received",
    "planned": "Planned",
    "on_the_roadmap": "On the roadmap",
    "in_progress": "In progress",
    "shipped": "Shipped",
    "closed_not_planned": "Closed",
    "closed_merged": "Closed",
}
FEEDBACK_TITLE_MIN_CHARS = 5
FEEDBACK_TITLE_MAX_CHARS = 120
FEEDBACK_DESCRIPTION_MAX_CHARS = 5000
FEEDBACK_SCREENSHOT_MAX_BYTES = 5 * 1024 * 1024
FEEDBACK_UPLOAD_MAX_BYTES = FEEDBACK_SCREENSHOT_MAX_BYTES + 64 * 1024
FEEDBACK_ALLOWED_SCREENSHOT_TYPES = {"image/png", "image/jpeg"}

# PAT-2093: the overview's new_software block ranks urgency in this order
# (contracts/portal-api.md "New software by urgency") - not_assessed sits
# between high and medium, never merged into low. "Not assessed" is never
# "no CVEs" (same rule PAT-2025's cve_assessment already follows), so it
# keeps its own level, label and pill class throughout.
NEW_SOFTWARE_URGENCY_LEVELS = ("critical", "high", "not_assessed", "medium", "low")
NEW_SOFTWARE_URGENCY_LABELS = {
    "critical": "Critical", "high": "High", "not_assessed": "Not assessed",
    "medium": "Medium", "low": "Low",
}
# Reuses the severity pill classes already defined in portal.css for CVE and
# CIS findings (pill-critical/high/medium/low). PAT-2140: not_assessed used
# to reuse pill-muted, the same neutral pill-low also renders with (pill-low
# and pill-muted share the same --hair background) - on screen the two were
# barely distinguishable, and Andy's live review flagged the whole card as
# uncoloured. not_assessed now gets pill-info (portal.css: --hair background,
# --graphite foreground, the same secondary-text token already used for
# other neutral-but-legible reads elsewhere on the page), so it reads as its
# own distinct neutral rather than a second "muted".
NEW_SOFTWARE_URGENCY_PILL_CLASS = {
    "critical": "pill-critical", "high": "pill-high", "not_assessed": "pill-info",
    "medium": "pill-medium", "low": "pill-low",
}
NEW_SOFTWARE_URGENCY_RANK = {level: i for i, level in enumerate(NEW_SOFTWARE_URGENCY_LEVELS)}

# PAT-2254: software review lives in /software (Andy, 28 September 2026), so
# every software count and row on the Overview links into /software
# pre-filtered. `type`, `approval` and `search` are the params the PAT-2163
# filter bar and the inventory search already read. `new_days` (first seen
# within N days, the New software window) and `urgency` (a comma list of
# NEW_SOFTWARE_URGENCY_LEVELS, the same comma convention `approval` uses)
# are applied by /software since PAT-2255 (see _software_filter_state), and
# are named here once rather than spelled out in each template.
SOFTWARE_NEW_DAYS_PARAM = "new_days"
SOFTWARE_URGENCY_PARAM = "urgency"


def _software_filter_url(
    *, type_=None, approval=None, new_days=None, urgency=None, search=None,
) -> str:
    """A /software link carrying only filters the page knows. Unknown
    urgency levels and a non-positive or non-integer window are dropped
    rather than reflected into a link; the search term is percent-encoded
    (spaces as %20). Parameter order is fixed: type, approval, new_days,
    urgency, search."""
    params: list[tuple[str, str]] = []
    if type_ in ("application", "extension"):
        params.append(("type", type_))
    if isinstance(approval, str) and approval:
        params.append(("approval", approval))
    if type(new_days) is int and new_days > 0:
        params.append((SOFTWARE_NEW_DAYS_PARAM, str(new_days)))
    levels = [
        level for level in (urgency or "").split(",") if level in NEW_SOFTWARE_URGENCY_LEVELS
    ]
    if levels:
        params.append((SOFTWARE_URGENCY_PARAM, ",".join(levels)))
    if isinstance(search, str) and search:
        params.append(("search", search))
    query = urlencode(params, safe=",", quote_via=quote)
    return "/software" + (f"?{query}" if query else "")


# The one place "waiting on a decision" is linked from the Overview.
SOFTWARE_WAITING_URL = _software_filter_url(approval="waiting")

# PAT-2254: internal identifiers that must never reach a customer. The
# Overview's tenant name is platform data, and a delivery runbook once named
# a tenant "Endpoint Assurance cycle 2026-09-03 (PAT-1301)".
_TICKET_GROUP_RE = re.compile(r"\s*[(\[][^()\[\]]*\bPAT-\d+\b[^()\[\]]*[)\]]", re.IGNORECASE)
_TICKET_REF_RE = re.compile(r"\s*\bPAT-\d+\b", re.IGNORECASE)
_CYCLE_LABEL_RE = re.compile(r"\s*\bcycle\s+\d{4}-\d{2}-\d{2}\b", re.IGNORECASE)
_GUID_RE = re.compile(
    r"\s*\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)
TENANT_NAME_FALLBACK = "Your estate"


def _customer_facing_tenant_name(raw) -> str:
    """The tenant name as a customer may see it: ticket references (bare or
    inside a bracketed group), date-stamped cycle labels and GUIDs removed,
    leftover separators and whitespace tidied, and "Your estate" when
    nothing is left or the value is not a string. A name that carries none
    of these comes back unchanged. Render-time defence only: the name
    itself is platform data."""
    if not isinstance(raw, str):
        return TENANT_NAME_FALLBACK
    name = raw
    for pattern in (_TICKET_GROUP_RE, _TICKET_REF_RE, _CYCLE_LABEL_RE, _GUID_RE):
        name = pattern.sub("", name)
    if name != raw:
        name = re.sub(r"\s+", " ", name).strip(" \t-\u2013\u2014:;,|/")
    return name.strip() or TENANT_NAME_FALLBACK


BASE_DIR = Path(__file__).resolve().parent

logger = logging.getLogger("portal.auth")

# PAT-1151: deploy/deploy-portal-01.sh writes this file, atomically, as the
# last step of a successful deploy (same DEPLOYED_SHA=<sha> / DEPLOYED_AT=
# <UTC ISO8601> convention the dashboard's scripts/deploy.sh uses, PAT-992).
# Overridable so tests never touch the real repo checkout.
DEPLOYED_SHA_FILE = Path(os.getenv("DEPLOYED_SHA_FILE", str(BASE_DIR / "DEPLOYED_SHA")))

# PAT-989: deploy/patched-maintenance-facts.sh writes this file, atomically,
# on an hourly systemd timer. Absolute production path (not repo-relative
# like DEPLOYED_SHA_FILE above) since the facts file lives in box state, not
# the app checkout; overridable so tests never touch the real box path.
MAINTENANCE_FACTS_FILE = Path(
    os.getenv("MAINTENANCE_FACTS_FILE", "/var/lib/patched/maintenance.json")
)
# The emitter runs hourly; three timer periods of silence is a generous
# margin before treating the data as stale rather than a false positive on
# ordinary scheduling jitter.
MAINTENANCE_STALE_AFTER = timedelta(hours=3)

# The catalogue is tenant-entitlement context, not global application data.
# Cache it very briefly by a digest of the exact verified CF Access assertion,
# rather than email or a tenant value the portal must never infer.  The
# platform remains the final authorizer for every generation/schedule write.
REPORT_CATALOGUE_CACHE_TTL_SECONDS = 15
REPORT_CATALOGUE_CACHE_MAX_ENTRIES = 64
_report_catalogue_cache: OrderedDict[str, tuple[float, tuple[dict, ...]]] = OrderedDict()
_report_catalogue_cache_lock = threading.Lock()

# PAT-2037: whether feedback is available is platform-owned, but checking it
# for every portal render would add an avoidable upstream call. Keep only a
# short-lived SHA-256 digest of the verified assertion, never the assertion
# itself, so a tenant's state cannot leak to another tenant and a platform
# enablement change becomes visible without a process restart. A confirmed
# feature costs an upstream call only once a minute; absent or temporarily
# unreachable feedback is retried after 15 seconds so a newly enabled feature
# is discovered promptly. Each worker has its own cache, so workers converge
# on a platform change at the relevant TTL.
FEEDBACK_AVAILABLE_CACHE_TTL_SECONDS = 60
FEEDBACK_UNAVAILABLE_CACHE_TTL_SECONDS = 15
FEEDBACK_AVAILABILITY_CACHE_MAX_ENTRIES = 64
_feedback_availability_cache: OrderedDict[str, tuple[float, bool]] = OrderedDict()
_feedback_availability_cache_lock = threading.Lock()

app = FastAPI(title="Patched portal", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# PAT-2237: STATIC_DIR is the resolved root static_url() must not escape.
STATIC_DIR = (BASE_DIR / "static").resolve()


@functools.cache
def static_url(path: str) -> str:
    """Return a cache-busted /static/ URL: /static/{path}?v={sha256(bytes)[:12]}.

    The version is the first 12 hex characters of the file's own content
    hash, so a changed asset always gets a changed URL - nothing has to
    remember to hand-bump a version string on every PR that touches
    portal.css/portal.js/etc (PAT-2237: three same-day PRs changed
    portal.css without bumping its old hand-set ?v=, so browsers that had
    already visited kept serving the stale, cached stylesheet).

    Hashed once per distinct path and cached for the life of the process
    (functools.cache) - a deploy restarts the process, so a cached entry
    can never outlive the file it was computed from. A missing file
    raises FileNotFoundError at render time, so a typo'd path fails a test
    or a walk rather than silently 404ing in a customer's browser.
    """
    target = (STATIC_DIR / path).resolve()
    if target != STATIC_DIR and STATIC_DIR not in target.parents:
        raise ValueError(f"static_url: {path!r} resolves outside the static directory")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()[:12]
    return f"/static/{path}?v={digest}"


# ── Template helpers ──────────────────────────────────────────────────────
def humandate(value, with_time: bool = False):
    """Render a timestamp as '12 Dec 2026' (or '12 Dec 2026 09:05') in UTC.

    Templates label these values "(UTC)", so the value is always converted to
    UTC before formatting, in both modes: the platform API serialises
    timestamptz in its own local zone (+01:00 in British Summer Time), and
    printing those wall-clock digits under a UTC label is an hour out. That
    includes the date-only form, where 2026-09-21T00:30:00+01:00 is 20 Sep in
    UTC. A naive datetime (or naive ISO string) is taken to be UTC already.
    Empty values render "-" and unparseable strings come back unchanged."""
    parsed = _parse_utc(value)
    if parsed is None:
        return "-" if not value else str(value)
    fmt = "%d %b %Y %H:%M" if with_time else "%d %b %Y"
    return parsed.strftime(fmt)


def _parse_utc(value) -> datetime | None:
    """Shared parse used by humandate/humantime: a timestamp (datetime or
    ISO string) converted to UTC, or None for empty/unparseable input. See
    humandate's own docstring for why everything is normalised to UTC before
    formatting."""
    if not value:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    try:
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    except OverflowError:
        return None


def humantime(value):
    """PAT-2140: just the 'HH:MM' half of humandate(value, True), so a
    narrow column can put the date and the time on their own lines instead
    of wrapping one long string word by word. Empty/unparseable input
    renders '-' (unparseable strings render unchanged, same as humandate),
    matching humandate's own fallbacks so the two never disagree on what
    counts as a failure."""
    if not value:
        return "-"
    parsed = _parse_utc(value)
    if parsed is None:
        return str(value)
    return parsed.strftime("%H:%M")


def humandate_nowrap(value, with_time: bool = False):
    """PAT-2298: humandate, with the date part in a nowrap span so a narrow
    cell breaks around '29 Sep 2026' and never through it. The time stays
    outside the span and may wrap onto its own line (the walker's `break`
    check and rubric L13 both accept a date-then-time break), which keeps a
    cell's minimum width to the date instead of the whole timestamp.

    Returns Markup built with Markup.format, which escapes every argument,
    so the only markup in the result is the span this function writes. A
    value that is empty or does not parse takes humandate's own fallback
    ('-' or the value unchanged) as a plain string, which Jinja escapes as
    usual and which is never wrapped."""
    parsed = _parse_utc(value)
    if parsed is None:
        return humandate(value, with_time)
    date = Markup('<span class="nowrap">{}</span>').format(parsed.strftime("%d %b %Y"))
    if not with_time:
        return date
    return Markup("{} {}").format(date, parsed.strftime("%H:%M"))


# PAT-2119: the platform sends the raw internal platform key ("macos",
# "windows", "linux") in every payload that carries one - GET /v1/portal/
# software's inventory rows, /v1/portal/devices, /v1/portal/applications,
# and the device-detail views. Templates want the customer-facing spelling.
# Anything not in this map (an older platform's "unknown", or a future
# platform key nobody has taught this list yet) passes through unchanged
# rather than guessing - absence requires authority (root AGENTS.md), and
# that applies to display labels as much as to inventory conclusions.
PLATFORM_DISPLAY_LABELS = {"macos": "macOS", "windows": "Windows", "linux": "Linux"}


def platform_display(value):
    if not isinstance(value, str):
        return value
    return PLATFORM_DISPLAY_LABELS.get(value, value)


# PAT-2324 (Andy, 30 September 2026: "Servers need to be differentiated from
# Desktops"): the platform now sends `device_class` ("server", "workstation"
# or "unknown"; a Mac is always "workstation") and `os_caption` (for example
# "Microsoft Windows Server 2022 Standard") on the devices roster and on the
# device response. Both are additive, and the portal deploys on either side of
# the platform's rollout: with either field absent, or a value this file does
# not recognise, every device renders exactly as it did before. Absence
# requires authority (root AGENTS.md), so "unknown" and anything unrecognised
# is not a class at all, never guessed into "workstation".
DEVICE_CLASS_LABELS = {"server": "Server", "workstation": "Workstation"}

# The edition words a Windows caption may end with. A caption is turned into a
# short name only when everything after the release is one of these, so
# "Microsoft Windows Server 2022 Datacenter: Azure Edition" or a Windows IoT
# caption keeps the bare build number rather than getting a partial name.
_WINDOWS_EDITIONS = (
    r"(?:Standard|Datacenter|Enterprise|Pro|Professional|Education|Home|Essentials|"
    r"Foundation|Evaluation|LTSC|LTSB|N|KN|Single Language|for Workstations)"
)
_WINDOWS_CAPTION = re.compile(
    r"^(?:Microsoft\s+)?Windows\s+"
    r"(?:Server\s+(?P<server>20\d\d)(?:\s+(?P<r2>R2))?|(?P<client>7|8\.1|8|1\d))"
    rf"(?:\s+{_WINDOWS_EDITIONS})*\s*$",
    re.IGNORECASE,
)


def windows_short_name(caption):
    """A short OS name from a Windows `os_caption`, or None.

    "Microsoft Windows Server 2022 Standard" is "Server 2022", "Microsoft
    Windows 11 Enterprise" is "Windows 11". The whole caption must parse:
    an unrecognised release, an edition word not listed above, or anything
    that is not a string returns None, and the caller shows the build number
    on its own. It never returns a wrong or partly stripped name.
    """
    if not isinstance(caption, str) or len(caption) > 120:
        return None
    match = _WINDOWS_CAPTION.match(caption.strip())
    if not match:
        return None
    if match.group("server"):
        return f"Server {match.group('server')}" + (" R2" if match.group("r2") else "")
    return f"Windows {match.group('client')}"


def device_type_view(device):
    """How one device row (roster row or device response) is told apart.

    kind         "server", "workstation" or None (absent, "unknown" or
                 unrecognised).
    label        "Server" / "Workstation", or None with kind.
    is_server    kind == "server".
    platform_label
                 "Windows Server" for a Windows device the platform calls a
                 server, otherwise None, and the caller shows the platform
                 as it always did.
    os_name      the short Windows name from `os_caption`, or None; only ever
                 read for a Windows device.
    """
    device = device if isinstance(device, dict) else {}
    kind = device.get("device_class")
    if not (isinstance(kind, str) and kind in DEVICE_CLASS_LABELS):
        kind = None
    platform = device.get("platform")
    is_windows = isinstance(platform, str) and platform.strip().lower() == "windows"
    return {
        "kind": kind,
        "label": DEVICE_CLASS_LABELS.get(kind),
        "is_server": kind == "server",
        "platform_label": "Windows Server" if kind == "server" and is_windows else None,
        "os_name": windows_short_name(device.get("os_caption")) if is_windows else None,
    }


# PAT-2163 (orchestrator follow-up, Andy's live desktop screenshot): a
# browser extension row has no OS platform at all (GET /v1/portal/
# extensions carries a `browser`, not a `platform` - see APPROVAL_BROWSERS
# below), so the /software table's Platform column was reading the
# genuinely-missing platform as "No platform" for every extension, which
# reads as a data gap rather than what it actually is: an extension, shown
# by its browser instead. "any" (an extension policy that applies across
# every browser, not a specific one) and any value this page does not
# otherwise recognise both read as the honest fallback, never guessed at a
# specific browser name.
BROWSER_DISPLAY_LABELS = {
    "chrome": "Chrome", "edge": "Edge", "firefox": "Firefox", "safari": "Safari",
}


def _browser_display(value) -> str:
    return BROWSER_DISPLAY_LABELS.get(value, "Browser extension") if isinstance(value, str) else \
        "Browser extension"


# PAT-2141: the hardware block reports disk/volume sizes in raw bytes
# (contracts/portal-api.md "GET /v1/portal/devices/{deviceID}"). Humanised
# to decimal GB (the vendor-label convention: a "500 GB" drive reports
# 500,000,000,000-ish bytes, not 465 GiB), one decimal place under 100 GB
# for readability, whole GB above it. None/non-numeric input renders
# nothing here - the caller decides the explicit "Unknown"/"Not collected"
# fallback text, this filter never silently prints "0 GB" for absent data.
def humanbytes(value):
    """Decimal units, matching how macOS and Windows report disk sizes.
    Under 1 GB reads in MB (a 0.5 GB volume showed as "0.0 GB" used, which
    reads as empty); under 1 MB reads "<1 MB" rather than a misleading 0."""
    if type(value) not in (int, float):
        return None
    if value >= 1_000_000_000:
        gb = value / 1_000_000_000
        return f"{gb:.0f} GB" if gb >= 100 else f"{gb:.1f} GB"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.0f} MB"
    return "0 MB" if value <= 0 else "<1 MB"


templates.env.filters["humandate"] = humandate
templates.env.filters["humantime"] = humantime
templates.env.filters["humandate_nowrap"] = humandate_nowrap
templates.env.filters["platform_display"] = platform_display
templates.env.filters["device_type"] = device_type_view
templates.env.filters["humanbytes"] = humanbytes
templates.env.globals["support_email"] = SUPPORT_EMAIL
templates.env.globals["portal_build"] = PORTAL_BUILD
templates.env.globals["static_url"] = static_url

# PAT-2520: the legal entity, defined once. The company is Patched LTD (Isle of
# Man, company number 139269C); "Patched" the product and "patched.im" the
# domain are different things and stay as they are. Templates read these as
# `legal_name` and `legal_line` and never spell the name out. The scan service
# keeps its own copy in scan/scanner.py (the two are separate processes with
# separate trust boundaries and import nothing from each other); the two MUST
# be equal, and tests/test_pat2520_legal_name.py fails if they are not.
LEGAL_NAME = "Patched LTD"
LEGAL_COMPANY_NUMBER = "139269C"
LEGAL_LINE = f"{LEGAL_NAME} · Isle of Man · Company No. {LEGAL_COMPANY_NUMBER}"
templates.env.globals["legal_name"] = LEGAL_NAME
templates.env.globals["legal_line"] = LEGAL_LINE


def exception_action_mailto(product: str, version: str, action: str) -> str:
    """PAT-1785: same request/record pattern as PAT-1642's device actions
    and PAT-1643's software actions - the portal writes no disposition, a
    named Patched specialist records the actual acceptance, acceptor or
    review-date renewal by hand after reading the email (12 Sept portal
    decision: "a customer asks, a specialist records"). `action` is one of
    'new' (request a not-yet-registered exception), 'accept' (ask for a
    decision on an unaccepted exception) or 'review' (ask for a review-date
    renewal on one that has fallen due)."""
    subjects = {
        "new": f"Please record a software exception for {product}",
        "accept": f"Please record a decision for the {product} exception",
        "review": f"Please review the {product} exception - review date has passed",
    }
    subject = quote(subjects.get(action, f"About the {product} exception"))
    body_text = f"Product: {product}\n"
    if version:
        body_text += f"Version: {version}\n"
    body_text += "\n"
    body = quote(body_text)
    return f"mailto:{SUPPORT_EMAIL}?subject={subject}&body={body}"


templates.env.globals["exception_action_mailto"] = exception_action_mailto


def _feedback_availability_cache_key(jwt_token: str) -> str:
    return hashlib.sha256(jwt_token.encode("utf-8")).hexdigest()


def _clear_feedback_availability_cache() -> None:
    """Test helper: clear the process-local availability optimisation."""
    with _feedback_availability_cache_lock:
        _feedback_availability_cache.clear()


def _remember_feedback_availability(jwt_token: str, available: bool) -> None:
    key = _feedback_availability_cache_key(jwt_token)
    with _feedback_availability_cache_lock:
        _feedback_availability_cache[key] = (time.monotonic(), available)
        _feedback_availability_cache.move_to_end(key)
        while len(_feedback_availability_cache) > FEEDBACK_AVAILABILITY_CACHE_MAX_ENTRIES:
            _feedback_availability_cache.popitem(last=False)


def _feedback_availability_cache_ttl(available: bool) -> int:
    return (
        FEEDBACK_AVAILABLE_CACHE_TTL_SECONDS
        if available
        else FEEDBACK_UNAVAILABLE_CACHE_TTL_SECONDS
    )


def _feedback_is_available(jwt_token: str) -> bool:
    """Ask the platform, not a portal flag, whether feedback is enabled.

    A feature-disabled platform deliberately answers 404.  That is a normal
    compatibility response, not a customer-facing error and not a reason to
    make every other portal page fail. Other failures hide this optional UI
    too, so the rest of a customer's estate remains usable.
    """
    key = _feedback_availability_cache_key(jwt_token)
    now = time.monotonic()
    with _feedback_availability_cache_lock:
        cached = _feedback_availability_cache.get(key)
        if (
            cached is not None
            and now - cached[0] < _feedback_availability_cache_ttl(cached[1])
        ):
            _feedback_availability_cache.move_to_end(key)
            return cached[1]
        if cached is not None:
            del _feedback_availability_cache[key]
    try:
        upstream.get_json("/v1/portal/feedback", jwt_token)
    except upstream.UpstreamError as exc:
        if exc.kind in ("auth", "forbidden"):
            raise
        available = False
    else:
        available = True
    _remember_feedback_availability(jwt_token, available)
    return available


# PAT-2329 (Andy, 2026-09-30): phones are a supported quick-look tier, not a
# full-parity one. These route templates (the `path` of the matched route, so
# `/devices/{device_id}` is the device page and not its `/compliance` or
# `/software` tabs) are built and walked for a 390px screen; every other
# signed-in page is dense. A dense page says so once below 768px (see
# `_is_dense_page`, `.page--dense` in portal.css). This is the one list: the
# walker (`e2e/walk/walk.py`) reads it to decide which routes get a 390px pass,
# and `tests/test_pat2329_phone_tier.py` fails if an entry is not a real GET
# route, so a rename cannot leave it quietly stale.
PHONE_SUPPORTED_ROUTES: frozenset[str] = frozenset({
    "/",
    "/software/alerts",
    "/devices/{device_id}",
    "/requests",
    "/feedback",
})

# Templates that are not portal pages: an error, a sign-in state or the
# "not linked / not enabled" dead ends. They never carry the dense-page note.
NON_PAGE_TEMPLATES: frozenset[str] = frozenset({
    "error.html", "session_expired.html", "signed_out.html", "not_linked.html",
    "not_enabled.html",
})


def _is_dense_page(request: Request, template_name: str, show_nav: bool) -> bool:
    """True when this response is a signed-in portal page outside
    PHONE_SUPPORTED_ROUTES (PAT-2329), which base.html marks `.page--dense`.

    Off unless the request positively matched a route: a page rendered from
    middleware or an exception handler has no matched route, and an error,
    sign-in or rail-less page never counts. The route is the one the server
    picked (`/devices/jamf`, not `/devices/{device_id}`), whatever the method,
    so a form re-rendered by a POST follows the page it belongs to."""
    if not show_nav or template_name in NON_PAGE_TEMPLATES:
        return False
    route_path = getattr(request.scope.get("route"), "path", None)
    return route_path is not None and route_path not in PHONE_SUPPORTED_ROUTES


def _render(request: Request, name: str, context: dict, status_code: int = 200) -> HTMLResponse:
    identity = getattr(request.state, "identity", None)
    # The logout endpoint lives on the CF Access team domain, not this origin
    # (auth.issuer() == "https://<team>.cloudflareaccess.com"). Only computed
    # when signed in: auth.team_domain() would otherwise raise ConfigError,
    # and an unauthenticated page has no session to end anyway.
    sign_out_url = f"{auth.issuer()}/cdn-cgi/access/logout" if identity else None
    feedback_available = context.get(
        "feedback_available", getattr(request.state, "feedback_available", False)
    )
    merged = {
        "request": request, "identity": identity, "show_nav": identity is not None,
        "sign_out_url": sign_out_url, "feedback_available": bool(feedback_available), **context,
    }
    merged.setdefault("dense_page", _is_dense_page(request, name, bool(merged["show_nav"])))
    # PAT-2105: every signed-in page gets the session-bound CSRF token so any
    # form posting to a guarded route (see _guarded_form) can carry it. A
    # route may still override it (e.g. /software blanks it for viewers).
    jwt_token = getattr(request.state, "jwt", "") if identity else ""
    if jwt_token and "csrf_token" not in merged:
        merged["csrf_token"] = _csrf_token(jwt_token)
    return templates.TemplateResponse(request, name, merged, status_code=status_code)


def safe_return_to(raw: str) -> str | None:
    """Validate a same-origin relative path (optionally with a query string)
    for the post-reauth return-to redirect (PAT-777). Only ever used to echo
    back where the user already was, but the incoming `?return_to=` on `/`
    is attacker-influenceable (a crafted link), so this must reject anything
    that could act as an open redirect: absolute URLs, protocol-relative
    URLs (`//evil.com`), and backslash tricks browsers sometimes treat as
    slashes. Returns None if `raw` is missing or unsafe.
    """
    if not raw or len(raw) > 2048:
        return None
    if not raw.startswith("/") or raw.startswith("//"):
        return None
    if "\\" in raw:
        return None
    parsed = urlsplit(raw)
    if parsed.scheme or parsed.netloc:
        return None
    return raw


def _request_return_to(request: Request) -> str | None:
    """Best-effort same-origin path+query of the request that just failed
    auth, so 'Sign in again' can return the user to where they were instead
    of always dropping them at '/'. Derived from the ASGI-routed path (always
    origin-relative by construction), so this is not itself attacker input -
    still run through safe_return_to for defence in depth and consistency
    with the query-param path below."""
    path = request.url.path
    if path in ("", "/"):
        return None
    query = request.url.query
    raw = f"{path}?{query}" if query else path
    return safe_return_to(raw)


def _sign_in_url(request: Request) -> str:
    return_to = _request_return_to(request)
    return f"/?return_to={quote(return_to, safe='')}" if return_to else "/"


def _session_expired_response(request: Request, reason: str) -> HTMLResponse:
    """Session-expired page (PAT-777): preserves a validated return-to path
    and clears the stale CF_Authorization cookie. Clearing it matters because
    Cloudflare Access's own edge session is carried entirely in that cookie -
    if we don't clear it, a fresh 'Sign in again' click just resends the same
    already-rejected token and the origin rejects it again, an infinite loop
    invisible to Cloudflare. Deleting our copy (host-scoped, path=/, matching
    how Access sets it for this single-app trust domain per PAT-330) forces
    the browser to drop it, so the next request to Access has no cookie to
    validate and Access is forced to run a real login handshake."""
    resp = _render(
        request, "session_expired.html",
        {"title": "Session expired", "reason": reason, "sign_in_url": _sign_in_url(request)},
        status_code=401,
    )
    resp.delete_cookie("CF_Authorization", path="/")
    return resp


def _signed_out_response(request: Request) -> HTMLResponse:
    """Signed-out page: no Access token was presented at all (a visitor who
    has never signed in), distinct from session_expired.html (a token that
    was presented and rejected). Unlike _session_expired_response, there is
    no stale CF_Authorization cookie to clear."""
    return _render(
        request, "signed_out.html",
        {"title": "Sign in", "sign_in_url": _sign_in_url(request)},
        status_code=401,
    )


def _error_page(request: Request, exc: upstream.UpstreamError) -> HTMLResponse:
    if exc.kind == "auth":
        return _session_expired_response(request, "upstream")
    if exc.kind == "forbidden":
        # Verified identity, but no estate is linked to it yet (PAT-699).
        # A re-auth CTA would loop forever, so this page offers none.
        return _render(
            request, "not_linked.html",
            {"title": "Account not linked", "show_nav": False}, status_code=403,
        )
    if exc.kind == "not_enabled":
        return _render(request, "not_enabled.html",
                       {"title": "Portal not yet enabled", "show_nav": False},
                       status_code=503)
    if exc.kind == "not_found":
        return _render(request, "error.html",
                       {"title": "Not found",
                        "message": "That item could not be found in your estate."},
                       status_code=404)
    if exc.kind == "rate_limited":
        return _render(request, "error.html",
                       {"title": "Slow down a moment",
                        "message": "You've generated several tokens recently - please "
                                   "wait a few minutes before trying again."},
                       status_code=429)
    return _render(request, "error.html",
                   {"title": "Temporarily unavailable",
                    "message": "We could not reach the Patched platform just now. "
                               "Please try again in a minute. If this persists, contact "
                               f"{SUPPORT_EMAIL}."},
                   status_code=502)


# ── Auth middleware: fail closed on every request ─────────────────────────
# Entries ending in "/" match by prefix (a directory of assets); anything
# else matches by exact equality. This is the single source of truth for
# which paths skip the JWT check - the middleware below must not hardcode
# its own copy of this list.
EXEMPT_PATHS = ("/static/", "/healthz")
# PAT-2257: the only methods the read-only service identity may use.
SERVICE_IDENTITY_METHODS = ("GET", "HEAD")


def _is_exempt(path: str) -> bool:
    return any(path.startswith(p) if p.endswith("/") else path == p for p in EXEMPT_PATHS)


@app.middleware("http")
async def require_cf_access_jwt(request: Request, call_next):
    path = request.url.path
    if _is_exempt(path):
        return await call_next(request)

    token = request.headers.get("Cf-Access-Jwt-Assertion") or request.cookies.get(
        "CF_Authorization", ""
    )
    try:
        # PAT-2118: verify_token can do a blocking JWKS fetch to Cloudflare
        # (stale cache or an unknown kid on key rotation). Called straight
        # from this async middleware that fetch would run on the event
        # loop and stall every other request on the worker while it waits
        # - the same shape PAT-2105 fixed for platform calls.
        claims = await run_in_threadpool(auth.verify_token, token)
    except auth.ConfigError:
        # Misconfigured box must not serve data. Distinct message so it is
        # obvious in ops that this is config, not a customer session issue.
        return templates.TemplateResponse(
            request, "error.html",
            {"request": request, "identity": None, "show_nav": False,
             "title": "Portal unavailable",
             "message": "The portal is not fully configured yet. "
                        f"Please contact {SUPPORT_EMAIL}."},
            status_code=503,
        )
    except auth.MissingTokenError:
        # A visitor who has never signed in, not a session that lapsed -
        # normal traffic, not a fault, so this is .info not .warning and we
        # don't log the exception message the way the AuthError branch below
        # does (that branch's PAT-1221 comment about diagnosing AUD drift
        # doesn't apply here - there is no token to have drifted).
        logger.info("No Access token presented for %s", path)
        return _signed_out_response(request)
    except auth.AuthError as exc:
        # PAT-1221: the exception message is declared safe to log (see
        # auth.AuthError's docstring) and is the only way to tell an AUD/
        # issuer mismatch apart from an ordinary expiry from the access log
        # alone, which only ever shows the resulting 401.
        logger.warning("CF Access JWT rejected for %s: %s", path, exc)
        return _session_expired_response(request, "verify")
    service_cn = auth.service_common_name(claims)
    if service_cn is not None:
        # PAT-2257: the read-only service identity (a Cloudflare Access
        # service token, allowlisted by common name). It is never shown as
        # a person, and the page never renders its common name (the token's
        # client id); logs name it by common name only.
        request.state.identity = {"email": auth.SERVICE_IDENTITY_LABEL,
                                  "service": True, "claims": claims}
        request.state.jwt = token
        if request.method not in SERVICE_IDENTITY_METHODS:
            # The one central write guard for this identity: refused here,
            # before any route (and so any platform write) can run. Covers
            # every current and future non-GET route without each route
            # having to remember it; tests/test_pat2257_service_identity.py
            # enumerates app.routes to prove it.
            logger.warning(
                "portal.service_identity.write_refused common_name=%s method=%s path=%s",
                service_cn, request.method, path)
            return _render(request, "error.html", {
                "title": "Change not made",
                "message": "This account is read-only, so nothing was changed.",
                "show_nav": False,
            }, status_code=403)
        logger.info("portal.service_identity.read common_name=%s method=%s path=%s",
                    service_cn, request.method, path)
    else:
        request.state.identity = {"email": claims["email"], "claims": claims}
        request.state.jwt = token
    # Feedback is optional. Probe it off the event loop through a bounded,
    # digest-keyed cache. The two intake doors make the canonical call
    # themselves and update this cache from that result instead.
    if path not in ("/requests", "/feedback", "/support"):
        try:
            request.state.feedback_available = await run_in_threadpool(
                _feedback_is_available, token
            )
        except upstream.UpstreamError as exc:
            return _error_page(request, exc)
    else:
        request.state.feedback_available = False
    # Post-reauth landing: Cloudflare Access preserves the full URL it
    # intercepted (query string included) across its login redirect, so a
    # '?return_to=' appended to the 'Sign in again' link (see _sign_in_url)
    # comes back here once the user has a fresh, valid JWT. Send them on to
    # the page they were actually on instead of leaving them at '/' (PAT-777).
    if path == "/":
        target = safe_return_to(request.query_params.get("return_to", ""))
        if target and target != "/":
            return RedirectResponse(url=target, status_code=303)
    return await call_next(request)


def _deployed_sha_info() -> dict:
    """PAT-1151: read the DEPLOYED_SHA record written by deploy/deploy-
    portal-01.sh. This rides on /healthz rather than a new route because
    /healthz and /static/* are this app's only unauthenticated paths (see
    AGENTS.md) - that invariant does not bend for this ticket. A missing or
    unparsable file is reported as null fields, never an error: before the
    first automated deploy runs, or immediately after a fresh install, no
    SHA has been recorded yet - a legitimate state, not a bug."""
    sha = None
    deployed_at = None
    try:
        content = DEPLOYED_SHA_FILE.read_text()
    except OSError:
        return {"deployed_sha": None, "deployed_at": None}
    for line in content.splitlines():
        if line.startswith("DEPLOYED_SHA="):
            sha = line[len("DEPLOYED_SHA="):].strip() or None
        elif line.startswith("DEPLOYED_AT="):
            deployed_at = line[len("DEPLOYED_AT="):].strip() or None
    return {"deployed_sha": sha, "deployed_at": deployed_at}


# PAT-1440: the recorded /healthz-projection decision for every top-level
# field deploy/patched-maintenance-facts.sh's `facts` dict produces (the
# emitter's json.dumps(facts, ...) call at the bottom of that script - see
# tests/test_pat1440_healthz_projection_parity.py, which parses that dict
# literal and asserts every key it finds has an entry here). Three decisions:
#
#   "carried"  - forwarded through _maintenance_info() unchanged (or with a
#                straightforward type-safe wrap, e.g. bool()).
#   "reduced"  - never forwarded raw; replaced by an aggregate count/bool per
#                _stray_config_backups_counts()/_systemd_hardening_counts()'s
#                (or the pre-existing third_party_pending/timers) convention.
#   "withheld: <reason>" - deliberately dropped, reason stated inline.
#
# This exists because stray_config_backups and systemd_hardening reached
# prod-01/api-01's dashboard rows the day they were added, but silently never
# reached portal-01's - _maintenance_info() built an explicit allowlist dict
# and anything not named in it was dropped with no signal anyone had to look
# at (PAT-1440). A new field added to the emitter with no decision recorded
# here now fails a test instead of silently vanishing the same way.
#
# Deliberately a plain dict, not reflection over _maintenance_info's source -
# the whole point is a decision a person made and can be reviewed as a
# one-line diff, not something inferred from code shape.
MAINTENANCE_HEALTHZ_PROJECTION: dict[str, str] = {
    "generated_at": "carried",
    "hostname": "withheld: internal box hostname has no operational value to a public caller",
    "pending_updates": (
        "withheld: a broader pending-updates count adds no signal beyond "
        "security_updates/esm_updates, which are already carried"
    ),
    "security_updates": "carried",
    "esm_updates": "carried",
    "pro_attached": "carried",
    "reboot_required": "carried",
    "running_kernel": "withheld: an exact kernel version is a vulnerable-software fingerprint",
    "newest_kernel": "withheld: an exact kernel version is a vulnerable-software fingerprint",
    "automatic_reboot_configured": "carried",
    "third_party_pending": "reduced",
    "timers": "reduced",
    "stray_config_backups": "reduced",
    "systemd_hardening": "reduced",
}


def _maintenance_info() -> dict | None:
    """PAT-989: read the box-local snapshot deploy/patched-maintenance-
    facts.sh writes hourly to MAINTENANCE_FACTS_FILE, and reduce it to a
    bounded, aggregate-only view safe for /healthz's public, unauthenticated
    response.

    /healthz is internet-reachable with no auth (see AGENTS.md - that
    invariant does not bend for this ticket), so this deliberately never
    forwards the full facts file: no unit names, no package names, no exact
    versions - only counts and booleans. Per-timer unit names and precise
    pending-update counts are exactly the kind of thing that hands an
    attacker a free vulnerable-software inventory; deployed_sha already sets
    the low-disclosure-risk precedent this follows (a commit hash, not a
    version-fingerprint list).

    Missing, stale (generated_at older than MAINTENANCE_STALE_AFTER - the
    emitter's timer has gone quiet), or unparseable data returns None so the
    "maintenance" key is omitted from the response entirely, rather than a
    fabricated healthy-looking default - the same "never invent zeros"
    discipline _deployed_sha_info() already applies to a missing
    DEPLOYED_SHA_FILE. A consumer that can't tell "no data yet" from
    "confirmed healthy" is worse off than one that admits it doesn't know.

    PAT-1440: `stray_config_backups` (PAT-1431/1433) and `systemd_hardening`
    (PAT-1237) extend this same reduction, factored into
    _stray_config_backups_counts()/_systemd_hardening_counts() below - paths,
    filenames, owners, modes and unit names never leave this function; only
    counts and one availability boolean do. See the "recorded decision" map
    MAINTENANCE_HEALTHZ_PROJECTION further down this file (and
    tests/test_pat1440_healthz_projection_parity.py) for the drift guard
    that keeps every future field the emitter adds from silently vanishing
    at this boundary the way these two just did."""
    try:
        raw = MAINTENANCE_FACTS_FILE.read_text()
    except OSError:
        return None
    try:
        facts = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(facts, dict):
        return None

    generated_at = facts.get("generated_at")
    try:
        generated = datetime.fromisoformat(str(generated_at).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if generated.tzinfo is None:
        generated = generated.replace(tzinfo=UTC)
    if datetime.now(UTC) - generated > MAINTENANCE_STALE_AFTER:
        return None

    timers = facts.get("timers")
    timers = timers if isinstance(timers, list) else []
    timers_failed_count = sum(
        1 for t in timers if isinstance(t, dict) and t.get("last_result") == "failed"
    )
    timers_disabled_count = sum(
        1 for t in timers if isinstance(t, dict) and t.get("enabled") == "disabled"
    )

    third_party_pending = facts.get("third_party_pending")
    third_party_pending = third_party_pending if isinstance(third_party_pending, list) else []

    # PAT-1796: Pro attachment is tri-state. The emitter uses null for an
    # unavailable, timed-out, malformed or otherwise untrustworthy Pro API
    # response. Carry that uncertainty to public /healthz rather than
    # bool-casting it into a misleading "detached" false.
    pro_attached = facts.get("pro_attached")
    if not isinstance(pro_attached, bool):
        pro_attached = None

    result = {
        "generated_at": generated_at,
        "reboot_required": bool(facts.get("reboot_required")),
        "security_updates": facts.get("security_updates"),
        "esm_updates": facts.get("esm_updates"),
        "pro_attached": pro_attached,
        "automatic_reboot_configured": bool(facts.get("automatic_reboot_configured")),
        "third_party_pending_count": len(third_party_pending),
        "timers_failed_count": timers_failed_count,
        "timers_disabled_count": timers_disabled_count,
    }
    result.update(_stray_config_backups_counts(facts))
    result.update(_systemd_hardening_counts(facts))
    return result


def _stray_config_backups_counts(facts: dict) -> dict:
    """PAT-1440: reduce `stray_config_backups` (PAT-1431/1433 - the emitter's
    scan of /etc/patched-{dashboard,api,portal} for ad-hoc *.bak*/*.pre-*
    copies) to the counts-only shape this box's public /healthz is allowed
    to carry. See _maintenance_info's docstring for why: the full array
    holds absolute paths, owners, groups and modes of files on a production
    box, which is exactly the disclosure /healthz's "counts and booleans
    only" discipline exists to block.

    Mirrors the dashboard's _stray_config_backup_findings() classification
    (readable-beyond-owner vs unknown-mode vs root-only-safe) so the two
    sides agree on what "readable" and "unknown" mean, without either side
    importing the other's code across the repo boundary - see that
    function's own docstring for the fail-closed reasoning this repeats:
    mode_unknown, or either boolean coming back JSON null, escalates to
    "unknown", never to "confirmed safe".

    Returns an EMPTY dict, not zeroed keys, whenever `stray_config_backups`
    is absent or not a list - i.e. this emitter predates the field, or wrote
    something unparseable. _maintenance_info merges this into its result
    with dict.update(), so an empty dict here means the three
    `stray_config_backups_*` keys are missing from the /healthz response
    entirely, not present-and-zero. That distinction is the whole point
    (PAT-1440): a dashboard consumer that can't tell "this box has never
    reported this field" from "this box scanned and found nothing" would
    have portal-01's row read as permanently clean the moment an old
    emitter silently stopped writing the field - the exact "unknown reads
    as clean" shape PAT-912/837/960 already caught this estate doing
    elsewhere. See _maintenance_facts_degraded_reasons in the dashboard repo
    for the consumer side of this contract.
    """
    raw = facts.get("stray_config_backups")
    if not isinstance(raw, list):
        return {}

    readable = 0
    unknown = 0
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        group_readable = entry.get("group_readable")
        world_readable = entry.get("world_readable")
        if entry.get("mode_unknown") or group_readable is None or world_readable is None:
            unknown += 1
        elif group_readable or world_readable:
            readable += 1

    return {
        "stray_config_backups_count": len(raw),
        "stray_config_backups_readable_count": readable,
        "stray_config_backups_unknown_count": unknown,
    }


def _systemd_hardening_counts(facts: dict) -> dict:
    """PAT-1440: reduce `systemd_hardening` (PAT-1237 - every patched-owned
    systemd unit scored against patched.im/docs/systemd-hardening-floor.md's
    per-class ceiling) to the counts-only shape /healthz is allowed to
    carry. The full shape names every unit and its live exposure score -
    published unauthenticated, that is a target list handed to anyone on
    the internet naming exactly which service is unhardened. See
    _maintenance_info's docstring.

    Three states, kept distinguishable exactly like
    _stray_config_backups_counts above:

      - field absent/malformed -> return {} -> every systemd_hardening_*
        key missing from /healthz -> "not reported by this emitter".
      - present with `available` not True (systemd-analyze missing or
        broken on this box, or a malformed value) -> return only
        `systemd_hardening_available: False`, no count keys -> "not
        available", distinct from a clean scan. Fabricating 0s here would
        claim a scan happened when it didn't.
      - present with `available: True` -> full counts, `available: True`.
        An empty (or all-classified-and-passing) `units` list is a real
        clean scan and correctly reports 0s - it arrives with
        `available: True` alongside it, so it is never confused with the
        two absent/unavailable cases above.

    Classification mirrors the dashboard's _systemd_hardening_findings():
    unclassified (class is null) is checked before unjudged (over_ceiling
    is null) for the same reason that function documents - a brand-new
    unit landing unclassified must never fall through and read as merely
    "could not be judged" against a ceiling it was never assigned.
    """
    raw = facts.get("systemd_hardening")
    if not isinstance(raw, dict):
        return {}

    available = raw.get("available") is True
    if not available:
        return {"systemd_hardening_available": False}

    units = raw.get("units")
    units = units if isinstance(units, list) else []

    over_ceiling = 0
    unclassified = 0
    unjudged = 0
    for entry in units:
        if not isinstance(entry, dict):
            continue
        unit_class = entry.get("class")
        over = entry.get("over_ceiling")
        if unit_class is None:
            unclassified += 1
        elif over is None:
            unjudged += 1
        elif over is True:
            over_ceiling += 1

    return {
        "systemd_hardening_available": True,
        "systemd_hardening_over_ceiling_count": over_ceiling,
        "systemd_hardening_unclassified_count": unclassified,
        "systemd_hardening_unjudged_count": unjudged,
    }


@app.get("/healthz")
def healthz():
    payload = {"status": "ok", **_deployed_sha_info()}
    maintenance = _maintenance_info()
    if maintenance is not None:
        payload["maintenance"] = maintenance
    return JSONResponse(payload)


# ── Chart geometry (dependency-free inline SVG) ───────────────────────────
DIAL_RADIUS = 52
DIAL_CIRCUMFERENCE = 2 * 3.14159265 * DIAL_RADIUS


def dial_geometry(score) -> dict:
    try:
        pct = max(0.0, min(100.0, float(score)))
    except (TypeError, ValueError):
        pct = 0.0
    return {
        "radius": DIAL_RADIUS,
        "circumference": round(DIAL_CIRCUMFERENCE, 2),
        "dash": round(DIAL_CIRCUMFERENCE * pct / 100.0, 2),
        "value": round(pct),
    }


def coverage_geometry(total, reporting, retired=0) -> dict:
    """Stacked-bar geometry for the overview coverage hero (PAT-1602
    ruling: coverage is prominent on the landing screen, stated as a
    fraction, never a bare percentage).

    Deliberately built only from devices_total/devices_reporting_24h/
    devices_retired, the platform's own overview aggregate - not a second
    upstream call against the device roster. PAT-2135: a retired device is
    the customer's own decision, not a coverage gap, so it is carved out of
    `missing` (and gets its own bar segment/legend line) rather than
    reading as "not seen in 24h" - devices_reporting_24h itself is
    unchanged by the platform (it still counts every device that reported,
    retired or not), so this is the one place that split has to be applied.
    """
    try:
        total = int(total)
    except (TypeError, ValueError):
        total = 0
    try:
        reporting = int(reporting)
    except (TypeError, ValueError):
        reporting = 0
    try:
        retired = int(retired)
    except (TypeError, ValueError):
        retired = 0
    total = max(total, 0)
    reporting = max(0, min(reporting, total))
    retired = max(0, min(retired, total - reporting))
    missing = total - reporting - retired
    return {
        "total": total,
        "reporting": reporting,
        "retired": retired,
        "missing": missing,
        "pct": round(reporting / total * 100, 1) if total else None,
        "reporting_pct": round(reporting / total * 100, 2) if total else 0,
        "retired_pct": round(retired / total * 100, 2) if total else 0,
        "missing_pct": round(missing / total * 100, 2) if total else 0,
    }


CONTROL_COVERAGE_COUNT_FIELDS = {
    "controls": ("total", "evaluated", "out_of_scope", "undetermined_evaluations"),
    "measurements": ("pass", "fail", "undetermined", "not_applicable"),
    "identifiers": ("cis_mapped", "cis_unmapped", "non_cis"),
}


def is_control_coverage_response(data) -> bool:
    """Accept only the complete aggregate contract PAT-1859 can render.

    This is a shape guard, not portal-side coverage calculation. A missing or
    malformed aggregate must degrade to the card's honest unavailable state,
    rather than allowing an undefined template value to read as zero, blank,
    or a broken Overview page.
    """
    if not isinstance(data, dict):
        return False
    if not isinstance(data.get("generated_at"), str):
        return False
    if not isinstance(data.get("platforms"), list) or not all(
        isinstance(platform, str) for platform in data["platforms"]
    ):
        return False
    if type(data.get("total_zero")) is not bool:
        return False
    for group, fields in CONTROL_COVERAGE_COUNT_FIELDS.items():
        values = data.get(group)
        if not isinstance(values, dict) or any(
            type(values.get(field)) is not int for field in fields
        ):
            return False
    benchmarks = data.get("benchmarks")
    if not isinstance(benchmarks, list):
        return False
    for benchmark in benchmarks:
        if not isinstance(benchmark, dict):
            return False
        if not isinstance(benchmark.get("benchmark"), str) or not isinstance(
            benchmark.get("benchmark_version"), str
        ):
            return False
        for group, fields in CONTROL_COVERAGE_COUNT_FIELDS.items():
            values = benchmark.get(group)
            if not isinstance(values, dict) or any(
                type(values.get(field)) is not int for field in fields
            ):
                return False
    return True


def trend_geometry(trend: list, width: int = 560, height: int = 150, pad: int = 10) -> dict:
    """Turn cis_trend [{date, score}] into SVG polyline points."""
    points = []
    for entry in trend or []:
        try:
            score = float(entry.get("score"))
        except (TypeError, ValueError, AttributeError):
            continue
        points.append({"date": entry.get("date", ""), "score": score})
    if not points:
        return {"points": "", "labels": [], "width": width, "height": height}
    lo = min(p["score"] for p in points)
    hi = max(p["score"] for p in points)
    span = (hi - lo) or 1.0
    n = len(points)
    coords = []
    for i, p in enumerate(points):
        x = pad + (i * (width - 2 * pad) / max(n - 1, 1))
        y = pad + (height - 2 * pad) * (1 - (p["score"] - lo) / span)
        coords.append(f"{round(x, 1)},{round(y, 1)}")
    last = points[-1]
    return {
        "points": " ".join(coords),
        "labels": [points[0]["date"], last["date"]],
        "lo": round(lo), "hi": round(hi),
        "last_x": coords[-1].split(",")[0], "last_y": coords[-1].split(",")[1],
        "width": width, "height": height,
    }


# ── Stale-device maths (PAT-701) ──────────────────────────────────────────
STALE_CHOICES = (7, 14, 30)
DEFAULT_STALE_DAYS = 7
# PAT-2324: `type` (server, workstation or empty) is the newest trailing
# column, after cve_assessment_state, so a reader that takes columns by
# position keeps working.
CSV_COLUMNS = ("hostname", "platform", "os_version", "last_seen", "days_stale",
               "cis_score", "encryption_ok", "patch_pending", "cve_assessment_state",
               "type")
NULLABLE_ASSURANCE_FIELDS = ("encryption_ok", "patch_pending")
EVIDENCE_COLLECTION_STATES = {"complete", "partial", "unavailable"}
EVIDENCE_AUTHORITIES = {
    "section_scoped", "presence_only", "unavailable", "unknown", "stale",
}
EVIDENCE_FRESHNESS = {"fresh", "stale", "unknown"}
RFC3339_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
EVIDENCE_SECTION_NAMES = (
    ("certificates", "Certificates"),
    ("battery", "Hardware health: battery"),
    ("storage", "Hardware health: storage"),
    ("disks", "Hardware health: disks"),
)

# PAT-2141: each Evidence collection chip links to the card that actually
# shows that named collection's data, when one exists on this page.
# certificates has no card here (compliance signals do not distinguish by
# certificate evidence specifically), so it stays a plain, unlinked chip -
# "where one exists" per the ticket, not a link to nowhere.
# PAT-2164: the target moved from an in-page anchor to its own tab - the
# value here is the tab's own URL segment (also its section id, e.g.
# "hardware"), and normalise_device_evidence below turns it into a full
# cross-tab "/devices/{id}/hardware#hardware" deep link.
EVIDENCE_SECTION_ANCHORS = {
    "certificates": None,
    "battery": "hardware",
    "storage": "hardware",
    "disks": "hardware",
}

# PAT-2141: shared status vocabulary for the identity/hardware blocks
# (contracts/portal-api.md "identity and hardware (PAT-2141)"), one step
# wider than the evidence envelope's three states - "not_collected" covers
# a block with no stored data and no explicit collection status at all.
# Absence requires authority (root AGENTS.md): an unrecognised or missing
# status is never silently treated as complete, and never rendered blank.
HARDWARE_BLOCK_STATES = {"complete", "partial", "unavailable", "not_collected"}


def _block_status(value) -> str:
    return value if value in HARDWARE_BLOCK_STATES else "unknown"


def _block_status_label(status: str) -> str:
    return {
        "complete": "Complete", "partial": "Partial", "unavailable": "Unavailable",
        "not_collected": "Not collected",
    }.get(status, "Unknown")


def _num(value):
    """Only a genuine int/float is numeric evidence - bool is an int subclass
    in Python, so `type(value) in (int, float)` (not isinstance) keeps a
    stray JSON `true`/`false` from being read as 1/0 cores or GB."""
    return value if type(value) in (int, float) else None


def _text(raw: dict, key: str):
    value = raw.get(key)
    return value if isinstance(value, str) and value else None


def _evidence_timing_view(raw) -> dict:
    """The identity/hardware blocks' own evidence timing - the same
    observed_at/received_at/freshness reading as normalise_device_evidence,
    reduced to just that timing (no sections/authority, which stay
    device-wide on the main Evidence collection card)."""
    raw = raw if isinstance(raw, dict) else {}
    freshness = raw.get("freshness")
    return {
        "observed_at": normalise_evidence_timestamp(raw.get("observed_at")),
        "received_at": normalise_evidence_timestamp(raw.get("received_at")),
        "freshness": (
            freshness if isinstance(freshness, str) and freshness in EVIDENCE_FRESHNESS
            else "unknown"
        ),
    }


def normalise_identity(raw) -> dict:
    """Presentation-safe view of the additive `identity` block (PAT-2141).

    `present` distinguishes a block genuinely absent from the response (an
    older platform build that predates this ticket - the page must fail
    soft, never crash, never show a zero) from one that is present but
    `not_collected` (a device row that exists but has never delivered a
    payload). Per the contract there is no partial state for this block:
    it is validated together at ingest, so `complete` is the only state
    that renders individual field values - anything else states its status
    explicitly rather than guessing at partial data.
    """
    present = isinstance(raw, dict)
    raw = raw if present else {}
    status = _block_status(raw.get("status")) if present else "not_collected"
    os_name = _text(raw, "os_name")
    os_version = _text(raw, "os_version")
    os_build = _text(raw, "os_build")
    os_line = " ".join(p for p in (os_name, os_version) if p) or None
    if os_build:
        os_line = f"{os_line} ({os_build})" if os_line else f"Build {os_build}"
    return {
        "present": present,
        "status": status,
        "status_label": _block_status_label(status),
        "complete": status == "complete",
        "serial": _text(raw, "serial"),
        "hardware_model": _text(raw, "hardware_model"),
        "computer_name": _text(raw, "computer_name"),
        "architecture": _text(raw, "architecture"),
        "os_line": os_line,
        "agent_version": _text(raw, "agent_version"),
        "first_seen": _text(raw, "first_seen"),
        "last_seen": _text(raw, "last_seen"),
        "evidence": _evidence_timing_view(raw.get("evidence")),
    }


def _hardware_disk_view(item) -> dict:
    item = item if isinstance(item, dict) else {}
    smart_status = _text(item, "smart_status")
    # "Not Supported" is a genuine, unalarming answer (many external/virtual
    # disks never report SMART data) - only an actual non-Verified reading
    # (Failing, or any other value the collector sends) gets the warning
    # treatment, per this ticket's own rule.
    warn = smart_status is not None and smart_status not in ("Verified", "Not Supported")
    internal = item.get("internal") if type(item.get("internal")) is bool else None
    solid_state = item.get("solid_state") if type(item.get("solid_state")) is bool else None
    return {
        "device": _text(item, "device"),
        "smart_status": smart_status,
        "smart_warn": warn,
        "internal": internal,
        "solid_state": solid_state,
    }


def _hardware_volume_view(item) -> dict:
    item = item if isinstance(item, dict) else {}
    total_bytes = _num(item.get("total_bytes"))
    free_bytes = _num(item.get("free_bytes"))
    used_pct = _num(item.get("used_pct"))
    used_bytes = (
        total_bytes - free_bytes if total_bytes is not None and free_bytes is not None else None
    )
    return {
        "mount": _text(item, "mount"),
        "used_bytes": used_bytes,
        "free_bytes": free_bytes,
        "used_pct": used_pct,
        # D-honesty: 90%+ used is the documented warning threshold; a
        # missing used_pct never defaults to "not full" or "full".
        "warn": used_pct is not None and used_pct >= 90,
    }


MACOS_SYSTEM_VOLUME_PREFIX = "/System/Volumes/"


def _split_system_volumes(block: dict) -> dict:
    """macOS mounts every APFS system sub-volume (/System/Volumes/Data,
    Preboot, VM, Update...) alongside "/"; they share one container, so on a
    real Mac seven near-identical rows buried the volumes a customer cares
    about (Andy, 25 Sept 2026: "poor layout"). They move to system_rows,
    shown collapsed; rows keeps "/" and every other mount. Nothing is
    dropped."""
    rows = block.get("rows") or []
    block["system_rows"] = [
        r for r in rows if (r.get("mount") or "").startswith(MACOS_SYSTEM_VOLUME_PREFIX)]
    block["rows"] = [
        r for r in rows if not (r.get("mount") or "").startswith(MACOS_SYSTEM_VOLUME_PREFIX)]
    return block


def _hardware_sub_block(raw, item_view_fn=None) -> dict:
    raw = raw if isinstance(raw, dict) else {}
    status = _block_status(raw.get("status"))
    items = raw.get("items")
    view = {
        "status": status, "status_label": _block_status_label(status),
        "complete": status == "complete",
    }
    if item_view_fn is not None:
        # "rows", never "items" - a dict's own bound `.items()` method
        # shadows a same-named key under Jinja's dot-attribute resolution
        # (`hardware.disks.items` silently resolves to the dict method, not
        # the list, and the for-loop below raises TypeError: not iterable).
        view["rows"] = [item_view_fn(i) for i in items] if isinstance(items, list) else []
    return view


def normalise_hardware(raw) -> dict:
    """Presentation-safe view of the additive `hardware` block (PAT-2141) -
    see normalise_identity's docstring for the absent-vs-not_collected
    distinction, which applies the same way here. Unlike identity, hardware
    is a rollup of five independent sub-blocks (cpu, memory, disks, volumes,
    battery) that can each be complete/partial/unavailable/not_collected on
    their own - the top-level status is a glance-level summary only, so the
    template always reads each sub-block's own status for the real claim.
    """
    present = isinstance(raw, dict)
    raw = raw if present else {}
    status = _block_status(raw.get("status")) if present else "not_collected"

    cpu_raw = raw.get("cpu") if isinstance(raw.get("cpu"), dict) else {}
    cpu_status = _block_status(cpu_raw.get("status"))
    memory_raw = raw.get("memory") if isinstance(raw.get("memory"), dict) else {}
    memory_status = _block_status(memory_raw.get("status"))

    battery_raw = raw.get("battery") if isinstance(raw.get("battery"), dict) else {}
    battery_status = _block_status(battery_raw.get("status"))
    battery_condition = _text(battery_raw, "condition")
    battery_present = (
        battery_raw.get("present") if type(battery_raw.get("present")) is bool else None
    )

    return {
        "present": present,
        "status": status,
        "status_label": _block_status_label(status),
        "evidence": _evidence_timing_view(raw.get("evidence")),
        "cpu": {
            "status": cpu_status, "status_label": _block_status_label(cpu_status),
            "complete": cpu_status == "complete",
            "model": _text(cpu_raw, "model"), "cores": _num(cpu_raw.get("cores")),
        },
        "memory": {
            "status": memory_status, "status_label": _block_status_label(memory_status),
            "complete": memory_status == "complete",
            "total_gb": _num(memory_raw.get("total_gb")),
        },
        "disks": _hardware_sub_block(raw.get("disks"), _hardware_disk_view),
        "volumes": _split_system_volumes(
            _hardware_sub_block(raw.get("volumes"), _hardware_volume_view)),
        "battery": {
            "status": battery_status, "status_label": _block_status_label(battery_status),
            "complete": battery_status == "complete",
            "present": battery_present,
            "cycle_count": _num(battery_raw.get("cycle_count")),
            "condition": battery_condition,
            "condition_warn": battery_condition is not None and battery_condition != "Normal",
            "max_capacity_pct": _num(battery_raw.get("max_capacity_pct")),
        },
    }


# PAT-2262: the firmware block's own top-level status vocabulary
# (contracts/portal-api.md "firmware (PAT-2262)") - narrower than
# HARDWARE_BLOCK_STATES above: firmware has no "not_collected" state of its
# own, and reads "not_reported" (an agent older than this ticket, or macOS,
# which does not collect it yet) as the honest fallback for anything this
# page does not recognise, including the block being absent entirely from
# an older platform response.
FIRMWARE_STATUSES = {"not_reported", "unavailable", "partial", "complete"}
# A bios/system/baseboard sub-block's own status, once it has been read at
# least once (contracts/portal-api.md: "each carries its own status
# (complete or partial ...)"). A sub-block that has never been read is
# `None` here, not a fabricated third value.
FIRMWARE_SECTION_STATUSES = {"complete", "partial"}


def _firmware_status(value) -> str:
    return value if value in FIRMWARE_STATUSES else "not_reported"


def _firmware_section(raw) -> dict:
    """Shared shape for bios/system/baseboard: `present` distinguishes a
    section that has never been read (null on the wire) from one that has
    been read at least once, however partially - the field-level values
    still default to "Not read" in the template regardless, since a read
    section can carry explicit nulls for individual fields too (contracts/
    portal-api.md: "Values are explicit nulls when not populated or not
    read.")."""
    present = isinstance(raw, dict)
    raw = raw if present else {}
    status = raw.get("status") if raw.get("status") in FIRMWARE_SECTION_STATUSES else None
    return {"present": present, "status": status, "reported_at": _text(raw, "reported_at")}


MONTHS_LONG = (
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
)


def _firmware_release_view(release_date, release_date_raw) -> tuple:
    """('March 2021', '4 years old') from a bios.release_date (YYYY-MM-DD,
    contracts/portal-api.md PAT-2262). Age is whole years from release_date
    to today, under one year reads as "less than a year old" - copy states
    age only, never a verdict ("outdated"/"vulnerable"/"old BIOS" - this
    ticket's own Done-when criteria bans those words from this section,
    tested in tests/test_pat2262_firmware.py). A release_date the agent
    could not parse falls back to release_date_raw verbatim with no
    computed age, rather than guessing at a date; both absent renders
    neither."""
    if isinstance(release_date, str):
        try:
            year, month, day = (int(p) for p in release_date.split("-"))
            release = datetime(year, month, day, tzinfo=UTC).date()
        except (ValueError, TypeError):
            release = None
    else:
        release = None
    if release is not None:
        today = datetime.now(UTC).date()
        years = today.year - release.year - (
            (today.month, today.day) < (release.month, release.day))
        if years < 1:
            age_label = "less than a year old"
        elif years == 1:
            age_label = "1 year old"
        else:
            age_label = f"{years} years old"
        return f"{MONTHS_LONG[release.month - 1]} {release.year}", age_label
    if isinstance(release_date_raw, str) and release_date_raw:
        return release_date_raw, None
    return None, None


def _firmware_bios_view(raw) -> dict:
    section = _firmware_section(raw)
    body = raw if isinstance(raw, dict) else {}
    release_label, age_label = _firmware_release_view(
        body.get("release_date"), body.get("release_date_raw"))
    section.update({
        "manufacturer": _text(body, "manufacturer"),
        "version": _text(body, "version"),
        "smbios_version": _text(body, "smbios_version"),
        "release_label": release_label,
        "age_label": age_label,
    })
    return section


def _firmware_system_view(raw) -> dict:
    section = _firmware_section(raw)
    body = raw if isinstance(raw, dict) else {}
    section.update({
        "manufacturer": _text(body, "manufacturer"),
        "model": _text(body, "model"),
    })
    return section


def _firmware_baseboard_view(raw) -> dict:
    section = _firmware_section(raw)
    body = raw if isinstance(raw, dict) else {}
    section.update({
        "manufacturer": _text(body, "manufacturer"),
        "product": _text(body, "product"),
    })
    return section


def normalise_firmware(raw) -> dict:
    """Presentation-safe view of the additive `firmware` block (PAT-2262,
    contracts/portal-api.md "firmware (PAT-2262)"). `present` distinguishes
    the block being genuinely absent from the response (an older platform
    build that predates this ticket) from one that is present but
    `status="not_reported"` (this exact device's agent has never sent the
    block: an agent older than PAT-2262, or macOS, which does not collect
    firmware yet) - both read identically to the template, "not_reported",
    since there is no way to tell "never asked" from "too old to ask" from
    here, and absence requires authority (root AGENTS.md): never a
    fabricated status either way."""
    present = isinstance(raw, dict)
    raw = raw if present else {}
    status = _firmware_status(raw.get("status")) if present else "not_reported"
    errors = raw.get("errors")
    bios = _firmware_bios_view(raw.get("bios"))
    system = _firmware_system_view(raw.get("system"))
    baseboard = _firmware_baseboard_view(raw.get("baseboard"))
    return {
        "present": present,
        "status": status,
        "reported_at": _text(raw, "reported_at"),
        "observed_at": _text(raw, "observed_at"),
        "errors": [e for e in errors if isinstance(e, str)] if isinstance(errors, list) else [],
        "bios": bios,
        "system": system,
        "baseboard": baseboard,
        "any_section_present": bios["present"] or system["present"] or baseboard["present"],
    }


# ── PAT-2263: kernel drivers matched against Microsoft's recommended driver
# block rules and loldrivers.io (contracts/portal-api.md "kernel_drivers
# (PAT-2263)" and "GET /v1/portal/driver-findings (PAT-2263)"). ─────────────
KERNEL_DRIVER_STATUSES = {"not_reported", "unavailable", "partial", "complete"}
DRIVER_LIST_SOURCE_LABEL = {
    "microsoft_driver_blocklist": "Microsoft's list", "loldrivers": "loldrivers.io",
}
DRIVER_LIST_STATUS_LABEL = {
    "succeeded": "Succeeded", "failed": "Failed", "never_fetched": "Never fetched",
}
# "yes"/"no" read as "enforced"/"not enforced" in customer copy; anything
# else (including a genuinely absent value) is unknown - never defaulted to
# either enforced or not enforced (root AGENTS.md: absence requires
# authority).
BLOCKLIST_ENFORCED_LABEL = {"yes": "enforced", "no": "not enforced"}


def _driver_source_label(source) -> str:
    fallback = source if isinstance(source, str) else "Unknown source"
    return DRIVER_LIST_SOURCE_LABEL.get(source, fallback)


def _truncate_hash(value) -> dict:
    """A hash is evidence, not prose: show enough to eyeball a match (12
    hex chars) with the full value available to copy, never the whole
    64-character SHA-256 inline in a table cell (L1/L11-shaped clipping
    risk) and never silently swapped for a different, shorter identifier."""
    if not isinstance(value, str) or not value:
        return {"full": None, "truncated": None}
    return {"full": value, "truncated": (value[:12] + "…") if len(value) > 12 else value}


def _driver_list_view(raw) -> dict:
    raw = raw if isinstance(raw, dict) else {}
    source = raw.get("source")
    status = raw.get("status")
    fetched_at = _text(raw, "fetched_at")
    return {
        "source": source,
        "source_label": _driver_source_label(source),
        "status": status,
        "status_label": DRIVER_LIST_STATUS_LABEL.get(status, "Unknown"),
        "fetched_at": fetched_at,
        "attempted_at": _text(raw, "attempted_at"),
        "list_version": _text(raw, "list_version"),
        "entry_count": _num(raw.get("entry_count")),
        "stale": raw.get("stale") is True,
        "ever_fetched": fetched_at is not None,
    }


def _driver_match_view(raw) -> dict:
    raw = raw if isinstance(raw, dict) else {}
    hash_view = _truncate_hash(raw.get("hash"))
    category = raw.get("category") if raw.get("category") in ("vulnerable", "malicious") else None
    return {
        "source": raw.get("source"),
        "source_label": _driver_source_label(raw.get("source")),
        "category": category,
        "entry_name": _text(raw, "entry_name"),
        "hash_kind": _text(raw, "hash_kind"),
        "hash_full": hash_view["full"],
        "hash_truncated": hash_view["truncated"],
        "list_version": _text(raw, "list_version"),
        "list_fetched_at": _text(raw, "list_fetched_at"),
        "list_stale": raw.get("list_stale") is True,
    }


def _driver_row_view(raw) -> dict:
    """One row of the additive `kernel_drivers.drivers` array. `loaded_label`
    is the ticket's exact evidence-only phrasing for whether the file is
    currently loaded - never "safe"/"blocked" verdict language, just what
    was observed (contracts/portal-api.md: the portal must not render a
    driver with no match as safe; this ticket's own copy ruling: "Present
    and not blocked by Windows" / "Present, blocked by Windows")."""
    raw = raw if isinstance(raw, dict) else {}
    loaded = raw.get("loaded")
    matches_raw = raw.get("matches")
    matches = [
        _driver_match_view(m) for m in matches_raw if isinstance(m, dict)
    ] if isinstance(matches_raw, list) else []
    return {
        "path": _text(raw, "path"),
        "service_name": _text(raw, "service_name"),
        "start_type": _text(raw, "start_type"),
        "loaded": loaded if isinstance(loaded, bool) else None,
        "loaded_label": (
            "Present and not blocked by Windows" if loaded is True
            else "Present, blocked by Windows" if loaded is False
            else "Unknown"
        ),
        "version": _text(raw, "version"),
        "reported_at": _text(raw, "reported_at"),
        "first_seen_at": _text(raw, "first_seen_at"),
        "match_status": raw.get("match_status"),
        "unknown_reason": raw.get("unknown_reason"),
        "matches": matches,
    }


def normalise_kernel_drivers(raw, platform=None) -> dict:
    """Presentation-safe view of the additive `kernel_drivers` block
    (PAT-2263, contracts/portal-api.md "kernel_drivers (PAT-2263)"). Absent
    entirely (older platform build) reads identically to `not_reported`
    exactly like normalise_firmware does - there is no way to tell "never
    asked" from "too old to ask" from here, and both must fail soft, never
    crash and never invent a status.

    `matches` flattens every listed (never unknown) driver row's own
    `matches` array into one list of rows for the device page's "Known
    vulnerable drivers" section - one row per (driver, match), matching the
    ticket's own listing shape (driver path/name, source, list version and
    fetched date, hash, loaded state). Unknown-match rows are never
    included here: the platform's own rule is that a driver with no match
    must never be rendered as safe, so this portal only ever asserts a
    match it was actually given, never a clean verdict about an unmatched
    row.

    `checked_state` resolves the three ways the "no matches" section can
    read, all fail-soft and none inventing a verdict the platform did not
    supply:
      - "unknown_no_list": no list has ever completed a fetch (every
        `lists[].fetched_at` is null) - nothing has actually been checked
        against, so "no matches" would overclaim a check that never
        happened.
      - "unknown_unhashed": at least one driver exists and none could be
        hashed (`summary.hashed == 0`) - matching never ran on this
        device's drivers at all.
      - "clean": lists have been fetched and drivers were hashed, and
        `summary.listed == 0` - a genuine "checked, none matched" state,
        dated by the newest list fetch actually used to check it.
    Both platform rules ("a driver with no match must never be shown as
    safe... a list can be stale" and "Unknown (no hash, or no list fetched
    yet) is shown as unknown") collapse to this one field.
    """
    present = isinstance(raw, dict)
    raw = raw if present else {}
    status = raw.get("status") if raw.get("status") in KERNEL_DRIVER_STATUSES else "not_reported"
    if not present:
        status = "not_reported"
    enforcement_raw = raw.get("enforcement") if isinstance(raw.get("enforcement"), dict) else None
    enforcement = None
    if enforcement_raw is not None:
        blocklist_enforced = enforcement_raw.get("blocklist_enforced")
        enforcement = {
            "blocklist_enforced": blocklist_enforced,
            "blocklist_enforced_label": BLOCKLIST_ENFORCED_LABEL.get(blocklist_enforced, "unknown"),
            "vulnerable_driver_blocklist": _text(enforcement_raw, "vulnerable_driver_blocklist"),
            "hvci": _text(enforcement_raw, "hvci"),
            "smart_app_control": _text(enforcement_raw, "smart_app_control"),
            "code_integrity_policy": _text(enforcement_raw, "code_integrity_policy"),
        }
    lists_raw = raw.get("lists")
    lists = (
        [_driver_list_view(row) for row in lists_raw if isinstance(row, dict)]
        if isinstance(lists_raw, list) else []
    )
    lists_ever_fetched = any(row["ever_fetched"] for row in lists)
    checked_at = max((row["fetched_at"] for row in lists if row["fetched_at"]), default=None)
    any_list_stale = any(row["stale"] for row in lists)

    summary_raw = raw.get("summary") if isinstance(raw.get("summary"), dict) else {}
    summary = {
        k: _num(summary_raw.get(k)) or 0
        for k in ("drivers", "hashed", "unhashed", "listed", "listed_malicious", "unknown")
    }

    drivers_raw = raw.get("drivers")
    drivers = (
        [_driver_row_view(row) for row in drivers_raw if isinstance(row, dict)]
        if isinstance(drivers_raw, list) else []
    )
    matches = []
    for driver in drivers:
        if driver["match_status"] != "listed":
            continue
        for match in driver["matches"]:
            row = dict(match)
            row.update({
                "driver_path": driver["path"], "service_name": driver["service_name"],
                "loaded": driver["loaded"], "loaded_label": driver["loaded_label"],
            })
            matches.append(row)

    if not lists_ever_fetched:
        checked_state = "unknown_no_list"
    elif summary["drivers"] > 0 and summary["hashed"] == 0:
        checked_state = "unknown_unhashed"
    else:
        checked_state = "clean"

    errors = raw.get("errors")
    return {
        "present": present,
        "status": status,
        "reported_at": _text(raw, "reported_at"),
        "observed_at": _text(raw, "observed_at"),
        "errors": [e for e in errors if isinstance(e, str)] if isinstance(errors, list) else [],
        "enforcement": enforcement,
        "lists": lists,
        "lists_ever_fetched": lists_ever_fetched,
        "any_list_stale": any_list_stale,
        "checked_at": checked_at,
        "summary": summary,
        "matches": matches,
        "checked_state": checked_state,
        "drivers_truncated": raw.get("drivers_truncated") is True,
        "is_macos": isinstance(platform, str) and platform.lower() == "macos",
    }


# The platform's portal roster contract is bounded at 500 rows per request.
# Keep a second, explicit ceiling over the total aggregation: a broken or
# drifting upstream envelope must fail the request rather than let a customer
# wait indefinitely for a CSV that may be incomplete.
DEVICES_PAGE_SIZE = 500
DEVICES_MAX_PAGES = 50
DEVICES_MAX_ROWS = DEVICES_PAGE_SIZE * DEVICES_MAX_PAGES


def normalise_assurance_boolean(value):
    """Keep only actual boolean evidence; absent or malformed values are unknown.

    The platform deliberately distinguishes a checked pass/fail from a control
    that was not evaluated.  Python truthiness would collapse ``None`` (and a
    malformed upstream value) into a false claim, so portal rendering only
    accepts the JSON booleans themselves as evidence.
    """
    return value if type(value) is bool else None


def normalise_nullable_assurance(device: dict) -> None:
    """Normalise nullable assurance fields before any roster or detail render."""
    for field in NULLABLE_ASSURANCE_FIELDS:
        device[field] = normalise_assurance_boolean(device.get(field))


def normalise_evidence_timestamp(value):
    """Keep only RFC 3339 timestamps; missing or malformed values are unknown."""
    if not isinstance(value, str) or not RFC3339_TIMESTAMP.fullmatch(value):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if parsed.tzinfo is not None else None


def normalise_device_evidence(raw, device_id: str = "") -> dict:
    """Make the additive evidence contract safe for a customer-facing detail view.

    The portal deliberately accepts only the documented enum values and
    RFC 3339 timestamps. Older platform responses and any malformed additive
    field stay visible as Unknown, never as an asserted absence or a complete
    collection. This is presentation-only: the authenticated upstream detail
    response remains the sole source of the device's data.

    PAT-2164: `device_id` turns each chip's EVIDENCE_SECTION_ANCHORS tab key
    into a real cross-tab deep link ("/devices/{id}/hardware#hardware") now
    that Hardware is its own tab rather than an in-page anchor on this same
    page. An empty device_id (the unit-level call in
    test_pat1868_device_evidence.py) degrades every chip to unlinked, same as
    a section with no anchor at all - never a broken "#hardware" href on a
    page that no longer has that id.
    """
    raw = raw if isinstance(raw, dict) else {}
    sections = raw.get("sections")
    sections = sections if isinstance(sections, dict) else {}
    hardware = sections.get("hardware_health")
    hardware = hardware if isinstance(hardware, dict) else {}

    collection_values = {
        "certificates": sections.get("certificates"),
        "battery": hardware.get("battery"),
        "storage": hardware.get("storage"),
        "disks": hardware.get("disks"),
    }
    collection_statuses = []
    for key, name in EVIDENCE_SECTION_NAMES:
        value = collection_values[key]
        status = (
            value if isinstance(value, str) and value in EVIDENCE_COLLECTION_STATES
            else "unknown"
        )
        tab = EVIDENCE_SECTION_ANCHORS.get(key)
        anchor = f"/devices/{quote(device_id, safe='')}/{tab}#{tab}" if tab and device_id else None
        collection_statuses.append({"name": name, "status": status, "anchor": anchor})

    authority = raw.get("authority")
    freshness = raw.get("freshness")
    return {
        "observed_at": normalise_evidence_timestamp(raw.get("observed_at")),
        "received_at": normalise_evidence_timestamp(raw.get("received_at")),
        "authority": (
            authority if isinstance(authority, str) and authority in EVIDENCE_AUTHORITIES
            else "unknown"
        ),
        "freshness": (
            freshness if isinstance(freshness, str) and freshness in EVIDENCE_FRESHNESS
            else "unknown"
        ),
        "sections": collection_statuses,
    }


def assurance_csv_value(value, is_stale: bool) -> str:
    """Render assurance evidence without treating stale or unknown as current."""
    if is_stale:
        return "stale"
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def days_since(last_seen, now=None):
    """Whole days elapsed since an ISO-8601 timestamp; None if missing/unparseable."""
    if not last_seen or not isinstance(last_seen, str):
        return None
    try:
        parsed = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    now = now or datetime.now(UTC)
    return max(0, int((now - parsed).total_seconds() // 86400))


def normalise_stale_days(value) -> int:
    """Clamp the threshold to the offered choices; anything else gets the default."""
    try:
        days = int(value)
    except (TypeError, ValueError):
        return DEFAULT_STALE_DAYS
    return days if days in STALE_CHOICES else DEFAULT_STALE_DAYS


def annotate_staleness(roster: list, stale_days: int, now=None) -> int:
    """Mark each device with days_stale / is_stale in place; return the stale count.

    A device is stale when it has not reported for stale_days or more whole
    days, or has never reported at all (no parseable last_seen).
    """
    now = now or datetime.now(UTC)
    stale_count = 0
    for d in roster:
        annotate_device_staleness(d, stale_days, now)
        stale_count += 1 if d["is_stale"] else 0
    return stale_count


def annotate_device_staleness(device: dict, stale_days: int, now=None) -> None:
    """Apply roster-equivalent evidence normalisation and staleness to one device."""
    normalise_nullable_assurance(device)
    days = days_since(device.get("last_seen"), now or datetime.now(UTC))
    device["days_stale"] = days
    device["is_stale"] = days is None or days >= stale_days


def _pagination_integer(data: dict, field: str) -> int:
    """Return a non-negative pagination field or fail the upstream contract.

    ``bool`` is deliberately not accepted despite being an ``int`` subclass:
    a JSON ``true`` for an offset is a malformed platform response, not page 1.
    """
    value = data.get(field)
    if type(value) is not int or value < 0:
        raise upstream.UpstreamError("error", f"invalid devices pagination field: {field}")
    return value


# The platform permits up to 500 rows. PAT-2139: the default used to be a
# more "readable" 100, but a product with no matching governance row (an
# inventory-only row - see the /software merge below) only ever reaches the
# "Waiting on a decision" table when it falls inside the page actually
# fetched; on a ~150-product estate that silently dropped some undecided
# products off page 1 with no visible sign anything was cut (the "vanished"
# report on PAT-2139). The default now matches the platform's own max, so
# any estate at or under 500 total inventory products always sees every
# inventory-only row on the first load; the pagination controls by the table
# (and the honest "showing N of M" notice) remain for the estates still
# above that. These values are query handling only, never tenant scope.
SOFTWARE_INVENTORY_DEFAULT_LIMIT = 500
SOFTWARE_INVENTORY_MAX_LIMIT = 500
SOFTWARE_INVENTORY_MAX_SEARCH_LENGTH = 256


def _bounded_query_int(value: str | None, default: int, minimum: int, maximum: int) -> int:
    """Parse a customer-controlled integer without forwarding malformed input."""
    try:
        parsed = int(value) if value is not None else default
    except ValueError:
        return default
    return min(max(parsed, minimum), maximum)


def _software_inventory_query(request: Request) -> tuple[int, int, str]:
    """Return bounded inventory query values matching the platform contract."""
    limit = _bounded_query_int(
        request.query_params.get("limit"), SOFTWARE_INVENTORY_DEFAULT_LIMIT,
        1, SOFTWARE_INVENTORY_MAX_LIMIT,
    )
    offset = _bounded_query_int(request.query_params.get("offset"), 0, 0, 2**31 - 1)
    search = request.query_params.get("search", "").strip()[:SOFTWARE_INVENTORY_MAX_SEARCH_LENGTH]
    return limit, offset, search


def _software_inventory_envelope(data) -> tuple[list[dict], int, int, int, dict, str]:
    """Validate the minimal contract needed to truthfully render inventory.

    A malformed inventory response is deliberately an unavailable enhancement,
    not an empty estate. The established policy view below remains available.
    """
    if not isinstance(data, dict):
        raise upstream.UpstreamError("error", "invalid software inventory envelope")
    products = upstream.unwrap_list(data, "products")
    for product in products:
        if not isinstance(product, dict):
            raise upstream.UpstreamError("error", "invalid software inventory product")
        required = (
            "name", "identifier", "platform", "device_count", "installation_count",
            "metered_installation_count", "unmetered_installation_count",
            "stale_installation_count", "unused_installation_count", "usage_state",
            "removal_candidate", "evidence_at",
        )
        if any(field not in product for field in required):
            raise upstream.UpstreamError("error", "incomplete software inventory product")
        # no_evidence_installation_count (PAT-2327) is additive: an older
        # platform omits it and it reads as 0, but a value that is present
        # must be a real count.
        count_fields = (
            "device_count", "installation_count", "metered_installation_count",
            "unmetered_installation_count", "stale_installation_count",
            "unused_installation_count", "unknown_version_installation_count",
            "no_evidence_installation_count",
        )
        if any(type(product.get(field, 0)) is not int or product.get(field, 0) < 0
               for field in count_fields):
            raise upstream.UpstreamError("error", "invalid software inventory counts")
        if (
            not isinstance(product["name"], str)
            or not isinstance(product["identifier"], str)
            or not isinstance(product["platform"], str)
            or not isinstance(product["evidence_at"], str)
            or not isinstance(product.get("versions", []), list)
            or type(product["removal_candidate"]) is not bool
            or any(not isinstance(version, str) for version in product.get("versions", []))
            or (
                product.get("last_used_at") is not None
                and not isinstance(product.get("last_used_at"), str)
            )
        ):
            raise upstream.UpstreamError("error", "invalid software inventory product fields")
    total = _pagination_integer(data, "total")
    limit = _pagination_integer(data, "limit")
    offset = _pagination_integer(data, "offset")
    coverage = data.get("coverage")
    if not isinstance(coverage, dict):
        raise upstream.UpstreamError("error", "invalid software inventory coverage")
    coverage_counts = (
        "installation_count", "metered_installation_count", "unmetered_installation_count",
        "stale_installation_count", "unused_installation_count",
    )
    if any(
        type(coverage.get(field)) is not int or coverage[field] < 0
        for field in coverage_counts
    ):
        raise upstream.UpstreamError("error", "invalid software inventory coverage counts")
    generated_at = data.get("generated_at")
    if not isinstance(generated_at, str) or not generated_at:
        raise upstream.UpstreamError("error", "invalid software inventory timestamp")
    return products, total, limit, offset, coverage, generated_at


SOFTWARE_USAGE_STATE_LABELS = {
    "used": "Used",
    "unused": "Unused",
    "unmetered": "Unmetered",
    "mixed": "Mixed evidence",
    "stale": "Stale evidence",
    "unknown": "Unknown evidence",
}


# PAT-2326: the tone each platform usage verdict reads in (the pill classes
# ok, warn and muted). Shared by the inventory row and the /software usage
# line so the two cannot disagree.
SOFTWARE_USAGE_STATE_TONES = {
    "used": "ok", "unused": "warn", "unmetered": "muted",
    "mixed": "muted", "stale": "warn", "unknown": "muted",
}


def _no_evidence_count(product: dict) -> int:
    """PAT-2327: `no_evidence_installation_count`, installations on metered
    devices with no recorded last use (never unused: nothing shows they were
    left alone). An absent, malformed or negative value reads as 0, which is
    exactly the behaviour before the platform sent it."""
    count = product.get("no_evidence_installation_count")
    return count if type(count) is int and count > 0 else 0


def _software_inventory_row(product: dict) -> dict:
    """Present the platform's usage verdict without reconstructing one here.

    PAT-2028: each row additionally carries the estate-wide `cve_assessment`
    object GET /v1/portal/software now returns per product (contracts/
    portal-api.md "CVE assessment state (PAT-2024, extended by PAT-2028)").
    Reused verbatim via _cve_assessment_product_view (PAT-2025) - its shape
    is a superset (it also carries app/versions for the device-detail table,
    unused here and simply ignored), so it degrades an older platform's
    missing field, and a malformed finding_count on an assessed row, exactly
    as PAT-2025 already does: never "No known CVEs" for not_assessed, never
    a crash (root AGENTS.md: absence requires authority, CVE claims require
    evidence)."""
    state = product.get("usage_state")
    if state not in SOFTWARE_USAGE_STATE_LABELS:
        raise upstream.UpstreamError("error", "invalid software usage state")
    candidate = product.get("removal_candidate") is True
    # A candidate is an explicit platform assertion only. A contract-breaking
    # combination must not turn partial evidence into a customer-facing hint.
    if candidate and (
        state != "unused"
        or product["metered_installation_count"] != product["installation_count"]
        or product["unmetered_installation_count"] != 0
        or product["stale_installation_count"] != 0
        or product["unused_installation_count"] != product["installation_count"]
    ):
        raise upstream.UpstreamError("error", "invalid software removal candidate")
    return {
        **product,
        "usage_label": SOFTWARE_USAGE_STATE_LABELS.get(state, "Evidence state not recognised"),
        "usage_class": SOFTWARE_USAGE_STATE_TONES.get(state, "muted"),
        "no_evidence_installation_count": _no_evidence_count(product),
        "candidate": candidate,
        "cve_assessment": _cve_assessment_product_view(product.get("cve_assessment")),
    }


# ── CVE assessment state (PAT-2024/PAT-2025) ──────────────────────────────
# contracts/portal-api.md "CVE assessment state (PAT-2024)": per product or
# device, `state` is one of assessed (a CPE mapping matched current
# versions), pending (mapped, not matched yet) or not_assessed (no mapping
# exists, so no CVE statement can be made at all). An older platform
# deployment simply omits the whole cve_assessment object; that must
# degrade to the same honest not_assessed reading, never a crash and never
# "No known CVEs" - CVE claims require evidence, and absence requires
# authority (root AGENTS.md).
CVE_ASSESSMENT_STATES = ("assessed", "pending", "not_assessed")

CVE_ASSESSMENT_STATE_LABELS = {
    "assessed": "Assessed",
    "pending": "Checking",
    "not_assessed": "Not yet assessed",
}

CVE_NOT_ASSESSED_EXPLANATION = (
    "Patched has not yet identified this product's vulnerability source, "
    "so no CVE result can be shown for it."
)


def _cve_state_display(state: str, finding_count) -> tuple[str, str]:
    """(label, pill class) for one already-normalised state + finding count.

    Not yet assessed is deliberately never pill-ok and never worded the
    same as a genuine zero-finding clean read (PAT-2025 - the two states
    must stay visually distinct and neither counts as clean in a summary
    figure)."""
    if state == "assessed":
        if not finding_count:
            return "No known CVEs", "pill-ok"
        return f"{finding_count} CVE{'' if finding_count == 1 else 's'}", "pill-bad"
    if state == "pending":
        return "Checking", "pill-muted"
    return "Not yet assessed", "pill-warn"


def _cve_assessment_counts(raw) -> dict:
    """assessed_products/pending_products/not_assessed_products, each
    clamped to a non-negative int. A missing or malformed count reads as 0,
    never a guess, so absent data can never inflate the assessed bucket."""

    def _count(field):
        value = raw.get(field) if isinstance(raw, dict) else None
        return value if isinstance(value, int) and value >= 0 else 0

    return {
        "assessed_products": _count("assessed_products"),
        "pending_products": _count("pending_products"),
        "not_assessed_products": _count("not_assessed_products"),
    }


def _cve_assessment_view(raw) -> dict:
    """Normalise a device-level cve_assessment envelope (GET
    /v1/portal/devices and GET /v1/portal/devices/{id}, ignoring its
    `products` list). Missing entirely (older platform not yet carrying
    PAT-2024) and malformed both degrade to state=not_assessed with zeroed
    counts, never a crash and never a false clean read."""
    if not isinstance(raw, dict):
        raw = {}
    state = raw.get("state")
    if state not in CVE_ASSESSMENT_STATES:
        state = "not_assessed"
    finding_count = raw.get("finding_count")
    finding_count_valid = isinstance(finding_count, int) and finding_count >= 0
    if state == "assessed" and not finding_count_valid:
        # Contract: assessed always carries a valid finding_count. A
        # response that violates that is a contract fault, not a genuine
        # zero - it must never be presented as a clean "No known CVEs"
        # (PAT-2025 review round 1, P1: this was rendering clean).
        state = "not_assessed"
    if state != "assessed":
        finding_count = None
    last_matched_at = raw.get("last_matched_at")
    if state != "assessed" or not isinstance(last_matched_at, str):
        last_matched_at = None
    display_label, pill_class = _cve_state_display(state, finding_count)
    view = {
        "state": state,
        "state_label": CVE_ASSESSMENT_STATE_LABELS[state],
        "finding_count": finding_count,
        "last_matched_at": last_matched_at,
        "display_label": display_label,
        "pill_class": pill_class,
        "explanation": CVE_NOT_ASSESSED_EXPLANATION if state == "not_assessed" else None,
    }
    view.update(_cve_assessment_counts(raw))
    return view


def _cve_assessment_product_view(raw) -> dict:
    """Normalise one entry of cve_assessment.products (device detail only -
    app, versions, state, last_matched_at, finding_count; no per-product
    assessed/pending/not_assessed counts, unlike the device-level shape)."""
    if not isinstance(raw, dict):
        raw = {}
    state = raw.get("state")
    if state not in CVE_ASSESSMENT_STATES:
        state = "not_assessed"
    finding_count = raw.get("finding_count")
    finding_count_valid = isinstance(finding_count, int) and finding_count >= 0
    if state == "assessed" and not finding_count_valid:
        # See _cve_assessment_view - assessed with an unusable count must
        # never read as clean.
        state = "not_assessed"
    if state != "assessed":
        finding_count = None
    last_matched_at = raw.get("last_matched_at")
    if state != "assessed" or not isinstance(last_matched_at, str):
        last_matched_at = None
    app = raw.get("app") if isinstance(raw.get("app"), str) else ""
    versions = raw.get("versions")
    versions = [v for v in versions if isinstance(v, str)] if isinstance(versions, list) else []
    display_label, pill_class = _cve_state_display(state, finding_count)
    return {
        "app": app,
        "versions": versions,
        "state": state,
        "state_label": CVE_ASSESSMENT_STATE_LABELS[state],
        "finding_count": finding_count,
        "last_matched_at": last_matched_at,
        "display_label": display_label,
        "pill_class": pill_class,
        "explanation": CVE_NOT_ASSESSED_EXPLANATION if state == "not_assessed" else None,
    }


# PAT-2099: contracts/portal-api.md "agent_health_degraded (PAT-2099)" -
# tenant-scoped rows from the agent_health.degraded channel (PAT-1064). The
# macOS agent only ever sends the tcc_denied / full_disk_access_missing pair
# today, for these four subjects; the customer copy below is Andy-approved
# and must be used verbatim, never composed from the raw subject string.
AGENT_HEALTH_SUBJECT_LABELS = {
    "browser_extensions": "Browser extensions",
    "mcp_servers": "MCP servers",
    "ide_extensions": "IDE extensions",
    "package_managers": "Package managers",
}
FULL_DISK_ACCESS_GUIDE_URL = "https://docs.patched.im/getting-started"


def _agent_health_degraded_view(raw) -> list:
    """Normalise device.agent_health_degraded into rows the template can
    render. Only the documented tcc_denied / full_disk_access_missing triple
    for a known subject gets the approved sentence and the install-guide
    link; any other kind/reason/subject - including a future vocabulary this
    portal doesn't know about yet - degrades to a neutral generic line with
    no link, never a guess at new copy. Missing, not a list, or empty
    renders no rows at all (older platform, or a genuinely healthy device)."""
    rows = []
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, dict):
            continue
        subject = entry.get("subject")
        if not isinstance(subject, str) or not subject:
            continue
        label = AGENT_HEALTH_SUBJECT_LABELS.get(subject)
        if label and entry.get("kind") == "tcc_denied" \
                and entry.get("reason") == "full_disk_access_missing":
            message = (
                f"{label} could not be read because macOS Full Disk Access "
                "is not granted to Patched."
            )
            guide_url = FULL_DISK_ACCESS_GUIDE_URL
        else:
            message = f"Part of this device's inventory could not be collected ({subject})."
            guide_url = None
        first_seen = entry.get("first_seen")
        last_seen = entry.get("last_seen")
        rows.append({
            "message": message,
            "guide_url": guide_url,
            "first_seen": first_seen if isinstance(first_seen, str) else None,
            "last_seen": last_seen if isinstance(last_seen, str) else None,
        })
    return rows


def _tenant_cve_assessment_view(raw) -> dict:
    """Normalise the tenant-level cve_assessment object carried on GET
    /v1/portal/findings (contracts/portal-api.md). Missing/malformed
    degrades to a zero-valued object with null timestamps - the same
    degradation the platform itself documents for a database predating
    migration 0161."""
    if not isinstance(raw, dict):
        raw = {}
    last_feed_sync_at = raw.get("last_feed_sync_at")
    if not isinstance(last_feed_sync_at, str):
        last_feed_sync_at = None
    last_full_match_at = raw.get("last_full_match_at")
    if not isinstance(last_full_match_at, str):
        last_full_match_at = None
    counts = _cve_assessment_counts(raw)
    total = sum(counts.values())
    return {
        "last_feed_sync_at": last_feed_sync_at,
        "last_full_match_at": last_full_match_at,
        **counts,
        "total_products": total,
        "coverage_pct": round(counts["assessed_products"] * 100 / total) if total else None,
    }


def _retirement_view(retirement) -> dict:
    """Normalise a device's `retirement` block (contracts/portal-api.md
    "GET /v1/portal/devices"/"GET /v1/portal/devices/{deviceID}", PAT-2135)
    for both the roster and the device page: `null` (never retired) reads
    as retired: False, and nothing else is trusted from a malformed value -
    a device is never shown as retired on a hunch."""
    if not isinstance(retirement, dict):
        return {"retired": False}
    retired_at = retirement.get("retired_at")
    return {
        "retired": True,
        "retired_at": retired_at if isinstance(retired_at, str) else None,
        "retired_by": retirement.get("retired_by") or "",
        "reason": retirement.get("reason") or "",
        "reported_after_retirement": retirement.get("reported_after_retirement") is True,
    }


RETIREMENT_HISTORY_LIMIT = 20


def _retirement_history_view(jwt_token: str, device_id: str) -> list | None:
    """GET /v1/portal/devices/{id}/retirement/history (every role, PAT-2135).
    Fail-soft: this is a supplementary disclosure on the device Overview
    tab, not primary content, so a failure here must not take the rest of
    the tab down with it - None (not []) means "could not be read", shown
    as such rather than a false "no history"."""
    try:
        data = upstream.get_json(
            f"/v1/portal/devices/{quote(device_id, safe='')}/retirement/history", jwt_token,
            params={"limit": RETIREMENT_HISTORY_LIMIT},
        )
    except upstream.UpstreamError as exc:
        logger.warning("portal.device_retirement_history.fail_soft kind=%s", exc.kind)
        return None
    decisions = data.get("decisions") if isinstance(data, dict) else None
    if not isinstance(decisions, list):
        return None
    history = []
    for entry in decisions:
        if not isinstance(entry, dict):
            continue
        decided_at = entry.get("decided_at")
        history.append({
            "action": entry.get("action") if entry.get("action") in ("retire", "unretire") else "",
            "reason": entry.get("reason") or "",
            "actor_email": entry.get("actor_email") or "",
            "decided_at": decided_at if isinstance(decided_at, str) else None,
        })
    return history


def get_device_roster(jwt_token: str) -> list:
    """Read the complete tenant roster from the paginated platform contract.

    This deliberately aggregates before the caller starts a CSV response. A
    failure on any later page can therefore still become the portal's normal
    error page, rather than a successful-looking partial download.
    """
    roster = []
    seen_device_ids = set()
    expected_total = None
    offset = 0

    for _ in range(DEVICES_MAX_PAGES):
        data = upstream.get_json(
            "/v1/portal/devices", jwt_token,
            params={"limit": DEVICES_PAGE_SIZE, "offset": offset},
        )
        if not isinstance(data, dict):
            raise upstream.UpstreamError("error", "invalid devices pagination envelope")

        page_rows = upstream.unwrap_list(data, "devices")
        total = _pagination_integer(data, "total")
        page_limit = _pagination_integer(data, "limit")
        page_offset = _pagination_integer(data, "offset")
        if page_limit != DEVICES_PAGE_SIZE or page_offset != offset:
            raise upstream.UpstreamError("error", "non-advancing devices pagination metadata")
        if total > DEVICES_MAX_ROWS:
            raise upstream.UpstreamError("error", "devices roster exceeds pagination safety limit")
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            raise upstream.UpstreamError("error", "devices pagination total changed during read")
        if len(page_rows) > page_limit or len(roster) + len(page_rows) > total:
            raise upstream.UpstreamError("error", "devices page exceeds reported total")

        for device in page_rows:
            if not isinstance(device, dict):
                raise upstream.UpstreamError("error", "invalid device row in paginated roster")
            device_id = device.get("device_id")
            if not isinstance(device_id, str) or not device_id or device_id in seen_device_ids:
                raise upstream.UpstreamError(
                    "error", "duplicate or invalid device ID in paginated roster"
                )
            seen_device_ids.add(device_id)
            # PAT-2025: normalise once here so both /devices and /devices.csv
            # see the same graceful-degradation behaviour (see
            # _cve_assessment_view - missing or malformed input reads as
            # not_assessed, never as a clean device).
            device["cve_assessment"] = _cve_assessment_view(device.get("cve_assessment"))
            # PAT-2135: same normalise-once shape for the roster's own
            # retirement block (contracts/portal-api.md "GET
            # /v1/portal/devices") - costs nothing extra, it already rides
            # on this same response.
            device["retirement_view"] = _retirement_view(device.get("retirement"))
        roster.extend(page_rows)

        if len(roster) == total:
            return roster
        if not page_rows:
            raise upstream.UpstreamError("error", "devices pagination ended before reported total")
        offset += len(page_rows)

    raise upstream.UpstreamError("error", "devices pagination safety limit reached")


# ── /devices decision-ordered groups (PAT-1642) ───────────────────────────
# Fixed group boundaries for the default /devices page - independent of the
# user-adjustable stale_days threshold above, which remains only the
# ?view=stale browse mode's own knob (PAT-701, unchanged). These two numbers
# are the ticket's own group definitions, not a second staleness algorithm:
# grouping reads the days_stale value annotate_staleness already computed
# from the single, unmodified days_since() - it is never recomputed here.
GROUP_QUIET_DAYS = 3
GROUP_SILENT_DAYS = 14
REPORTING_GAP_HOURS = 24


def bucket_group(days_stale) -> str:
    """Classify an already-computed days_stale value into one of the three
    groups /devices orders real (agent-reported) devices into:

      silent  - more than GROUP_SILENT_DAYS days silent, OR no parseable
                last_seen at all. A device this endpoint has never heard
                from is treated as maximally silent, never as healthy -
                "absence requires authority" (root AGENTS.md) - so it is
                never folded into "reporting normally" by omission.
      quiet   - between GROUP_QUIET_DAYS and GROUP_SILENT_DAYS days.
      normal  - fewer than GROUP_QUIET_DAYS days.

    Groups 4/5 (reconciled against a customer-supplied device list) are not
    computed here or anywhere - the platform has no such list yet (PAT-1595,
    unbuilt); see the gap card in templates/devices.html.
    """
    if days_stale is None or days_stale > GROUP_SILENT_DAYS:
        return "silent"
    if days_stale >= GROUP_QUIET_DAYS:
        return "quiet"
    return "normal"


def is_reporting_gap(last_seen, now=None) -> bool:
    """Return whether a device has not reported for the last 24 hours.

    This is deliberately timestamp-precise rather than based on the roster's
    whole-day reporting groups. A reporting-loss link must not omit a device
    that was last seen 25 hours ago merely because it was seen "yesterday".
    """
    if not isinstance(last_seen, str):
        return True
    try:
        seen = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
    except ValueError:
        return True
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=UTC)
    return (now or datetime.now(UTC)) - seen >= timedelta(hours=REPORTING_GAP_HOURS)


def _attention_view(coverage, findings, cve_attention, cve_assessment_unavailable,
                     alert_counts) -> dict:
    """View model for the merged "Needs attention" card (PAT-2159, folding
    the old separate "Needs attention"/"CVE attention" cards into one card
    with one row per source). CIS and CVE severity counts render as pills
    sharing the portal's existing pill-critical/pill-high tones; a zero
    count gets pill-muted rather than the alert tone - colour is never the
    only signal, so the label and count render either way.

    Evidence freshness is judged per source, independently: CIS evidence is
    fresh only once at least one device has reported in the last 24 hours
    (coverage.reporting); CVE evidence is fresh only once cve_attention
    itself is available and the tenant's own CVE-assessment freshness read
    did not fail (cve_assessment_unavailable). "Nothing needs attention"
    (all_clear) renders only when every source is both zero and fresh - a
    zero count read from stale or unavailable evidence must never look
    like a clean pass (root AGENTS.md - absence requires authority, the
    same rule PAT-1953's cve_attention and PAT-2093's new_software already
    follow elsewhere on this page).
    """
    cis_known = bool(coverage.get("total"))
    cis_fresh = cis_known and bool(coverage.get("reporting"))
    cve_known = bool(cve_attention.get("available"))
    cve_fresh = cve_known and not cve_assessment_unavailable
    cis_zero = not findings.get("critical") and not findings.get("high")
    cve_zero = not cve_attention.get("critical") and not cve_attention.get("high")
    no_reporting_loss = not coverage.get("missing")
    no_alerts = not (alert_counts.get("available") and alert_counts.get("open"))
    all_zero = cis_zero and cve_zero and no_reporting_loss and no_alerts
    all_fresh = cis_known and cis_fresh and cve_known and cve_fresh
    return {
        "cis_pill_critical": "pill-critical" if findings.get("critical") else "pill-muted",
        "cis_pill_high": "pill-high" if findings.get("high") else "pill-muted",
        "cve_pill_critical": "pill-critical" if cve_attention.get("critical") else "pill-muted",
        "cve_pill_high": "pill-high" if cve_attention.get("high") else "pill-muted",
        "cis_stale": cis_known and not cis_fresh,
        "all_clear": all_zero and all_fresh,
    }


# ── PAT-2160: "Your estate at a glance" + "Top 3 actions" welcome block ────
# Sits above the "Needs attention" pill card (PAT-2159) and is deliberately
# built only from data the overview() route already fetches, or from
# existing portal API calls made elsewhere in this file (/v1/portal/
# applications, /v1/portal/extensions - see _software_waiting_view below) -
# never a new platform field. Andy's ruling on this ticket: rules-based now,
# an LLM phrasing layer is a later, separate, opt-in ticket - every line
# below is computed, not generated.

# Raised from the pre-PAT-2160 limit of 1 (a lightweight probe that only
# ever read the tenant-level cve_assessment object riding on this response)
# so the same call also returns real finding rows for group_cve_fixes to
# rank (PAT-2160 ranking rule 2), without adding a second upstream call for
# it. 500 matches the platform's own clamp (see tests/conftest.py's stub)
# and the bounded-fetch precedent LIFECYCLE_FETCH_LIMIT already sets in this
# file - large enough for any real SME estate, but still a hard cap, not an
# unbounded fetch.
OVERVIEW_CVE_ROWS_LIMIT = 500

# PAT-2454: the first page above is rarely the whole story on a large estate
# (one live estate had 543 critical or high rows, one per CVE per product and
# version), so the Overview reads the whole findings list, at most this many
# pages (page one included, 5,000 rows) in all. The platform orders by CVSS
# DESC NULLS LAST, so a high finding without a score can follow medium or low
# rows. Hitting the cap is not a failure of the page: the read is
# reported incomplete and the action stays unnamed (_cve_action_source).
OVERVIEW_CVE_MAX_PAGES = 10


def _read_critical_high_findings(jwt_token: str, first_page) -> tuple[list, bool]:
    """Read the critical and high rows of GET /v1/portal/findings that the
    Overview's Top 3 CVE action ranks, and say whether it read all of them
    (PAT-2454). Returns (rows read, complete).

    `first_page` is the response overview() already fetched at offset 0 (it
    also supplies cve_assessment), so this makes no request for it. Rows come
    back ordered by CVSS DESC NULLS LAST, not by severity: high findings with
    no score can follow medium or low rows. While rows are still owed
    (offset + rows read < total), the next page of OVERVIEW_CVE_ROWS_LIMIT is
    fetched, up to OVERVIEW_CVE_MAX_PAGES pages in all.

    complete is True only when the list ended. It is False when the cap was
    reached with rows still owed, a later page failed
    (upstream.UpstreamError), or any page was malformed (not a dict, `total`
    not an int, `findings` not a list, an empty page while rows are still
    owed). No row's severity proves that later rows are below high (absence
    requires authority). An incomplete read is never a partial answer: the
    caller must not name a product from it.

    The rows returned are every row read, whatever its severity; the caller
    keeps the critical and high ones.
    """
    rows: list = []
    page = first_page
    offset = 0
    pages_read = 0
    while True:
        pages_read += 1
        if not isinstance(page, dict):
            return rows, False
        total = page.get("total")
        page_rows = page.get("findings")
        if type(total) is not int or not isinstance(page_rows, list):
            return rows, False
        if not page_rows:
            # Only an empty first page of an empty list is a finished read. An
            # empty page that follows rows still owed (the platform answers an
            # offset past the end with total 0) means the list moved under us.
            return rows, pages_read == 1 and total == 0
        rows.extend(r for r in page_rows if isinstance(r, dict))
        offset += len(page_rows)
        if offset >= total:
            return rows, True
        if pages_read >= OVERVIEW_CVE_MAX_PAGES:
            return rows, False
        try:
            page = upstream.get_json(
                "/v1/portal/findings", jwt_token,
                params={"limit": OVERVIEW_CVE_ROWS_LIMIT, "offset": offset},
            )
        except upstream.UpstreamError:
            return rows, False


# PAT-2190: the ten Overview information cards, read from the platform's
# GET /v1/portal/overview/cards (PAT-2207, contracts/portal-api.md
# "overview/cards"). Order, label and link are fixed here so the template
# never re-derives them. A card links to the closest existing filtered
# view - never a route that doesn't exist (AGENTS.md's Routes list) - and
# os_updates/high_risk_software/agent_health/recent_activity fall back to
# the nearest real page rather than inventing a new filtered view.
OVERVIEW_CARD_ORDER = (
    "devices", "os_updates", "vulnerabilities", "cis_posture",
    "browser_extensions", "high_risk_software", "software_awaiting_approval",
    "exceptions_review", "agent_health", "recent_activity",
)

OVERVIEW_CARD_LABELS = {
    "devices": "Devices",
    "os_updates": "OS update status",
    "vulnerabilities": "Vulnerabilities",
    "cis_posture": "CIS posture",
    "browser_extensions": "Browser extensions",
    "high_risk_software": "High-risk software",
    "software_awaiting_approval": "Software awaiting approval",
    "exceptions_review": "Exceptions nearing review",
    "agent_health": "Reporting and agent health",
    "recent_activity": "Recent activity",
}

# PAT-2190 rework (Andy review): every query param below is verified
# against the consuming route/template, not assumed real. `approval=waiting`
# is genuinely read by `_software_approval_filter` (main.py) and seeds the
# Approval dropdown's `data-initial`, which static/js/portal.js's
# `initApprovals` applies as the active client-side row filter on load -
# the same mechanism `type=extension` already uses for the Type filter.
# `view=not_reporting_24h` routes to the dedicated devices_reporting_gap.html
# template (see the `if view == "not_reporting_24h"` branch below). The
# `#cve-findings`/`#cis-compliance-findings` anchors are real ids in
# templates/findings.html. `recent_activity` has no href at all: the
# contract makes it permanently `unavailable` (not_yet_supported) until
# PAT-2197, and /whats-new is the product changelog, not estate activity -
# a card with nothing real to link to is rendered as a non-interactive,
# non-focusable block instead of a link that goes nowhere useful.
OVERVIEW_CARD_LINKS = {
    "devices": "/devices",
    "os_updates": "/devices",
    "vulnerabilities": "/findings#cve-findings",
    "cis_posture": "/findings#cis-compliance-findings",
    "browser_extensions": "/software?type=extension",
    # PAT-2254: high_risk_software is built per render in
    # _overview_card_render (its window length comes from the card itself).
    "software_awaiting_approval": SOFTWARE_WAITING_URL,
    "exceptions_review": "/exceptions",
    "agent_health": "/devices?view=not_reporting_24h",
    # "recent_activity": deliberately absent - see comment above.
}

# Neutral headline-slot words for unknown/unavailable (Andy review: never a
# multi-clause sentence in the headline, never a digit for these two
# states - root AGENTS.md, absence requires authority).
OVERVIEW_CARD_STATE_WORDS = {
    "unknown": "Not yet known",
    "unavailable": "Not available",
}

# Bounded reason codes (contracts/portal-api.md) rendered in plain English,
# one clause, in the card's single supporting line - a raw snake_case code
# must never reach a customer. An unfamiliar code (the contract says new
# ones may be added) is still treated as incomplete, never as complete.
OVERVIEW_CARD_REASON_TEXT = {
    "query_failed": "could not be read right now",
    "source_not_migrated": "not available for your estate yet",
    "not_yet_supported": "not supported yet",
    "not_modelled": "not tracked yet",
    "no_update_evidence": "no update evidence has been collected yet",
    "version_evidence_pending": "only partial version evidence has been collected so far",
    "no_completed_match_run": "a full vulnerability check has not completed yet",
    "no_evaluations": "no compliance checks have been recorded yet",
    "estate_too_large": "Your estate is too large to assess here",
    "truncated": "showing a partial list, so the real number may be higher",
    "coverage_incomplete": "coverage of your estate is incomplete",
    "devices_not_reporting": "some devices have not reported, so this may be incomplete",
    "no_devices": "no devices are currently known",
}
OVERVIEW_CARD_REASON_TEXT_DEFAULT = "this is incomplete and the reason is not recognised yet"


def _overview_card_reason_text(reason) -> str:
    if not reason:
        return OVERVIEW_CARD_REASON_TEXT_DEFAULT
    return OVERVIEW_CARD_REASON_TEXT.get(reason, OVERVIEW_CARD_REASON_TEXT_DEFAULT)


# PAT-2230: the CIS score arrives as a raw platform float (0-100, e.g.
# 37.096774193548384) - rendered verbatim it overflowed the card and put a
# horizontal scrollbar on the whole Overview page at 1162px (production,
# real tenant data, 2026-09-28). One decimal place, rounded half-up (never
# Python's default round-half-to-even/"banker's rounding" - decimal with an
# explicit ROUND_HALF_UP context does that), trailing ".0" trimmed so a
# clean score reads "84" rather than "84.0".
def _format_cis_score(score) -> str:
    quantized = decimal.Decimal(str(score)).quantize(
        decimal.Decimal("0.1"), rounding=decimal.ROUND_HALF_UP,
    )
    text = str(quantized)
    if text.endswith(".0"):
        text = text[:-2]
    return text


# PAT-2230: the six "risk" cards where a genuine zero is worth calling out
# green - every other combination (a positive count, or a card that isn't a
# risk count at all) must not paint ok. See _overview_card_tone.
OVERVIEW_CARD_OK_ELIGIBLE = frozenset({
    "vulnerabilities", "browser_extensions", "high_risk_software",
    "software_awaiting_approval", "exceptions_review", "agent_health",
})


def _overview_card_tone(key: str, state, values) -> str:
    """PAT-2230: a content tone independent of the contract `state` - the
    production defect this fixes is every `value`/`zero` card painting a
    green left accent purely because the card was *complete*, so "146
    vulnerabilities", "14 elevated extensions" and "96 awaiting approval"
    all read as healthy. `state` alone must never imply green again.

    `ok` is reserved for the six risk cards in OVERVIEW_CARD_OK_ELIGIBLE,
    and only when their own relevant count is genuinely zero in a complete
    (`value`/`zero`) state - a `partial` card reading zero is still
    incomplete, so it reads neutral, not ok. `unknown`/`unavailable` carry
    no values at all and always read neutral. cis_posture, os_updates and
    recent_activity never imply a pass/fail from their own figure, so they
    are always neutral."""
    if state in ("unknown", "unavailable"):
        return "neutral"
    v = values or {}

    if key == "vulnerabilities":
        count = v.get("critical", 0) + v.get("high", 0)
        tone = "bad" if count > 0 else "ok"
    elif key == "browser_extensions":
        tone = "warn" if v.get("elevated", 0) > 0 else "ok"
    elif key == "high_risk_software":
        count = v.get("critical", 0) + v.get("high", 0)
        tone = "warn" if count > 0 else "ok"
    elif key == "software_awaiting_approval":
        tone = "warn" if v.get("products", 0) > 0 else "ok"
    elif key == "exceptions_review":
        if v.get("review_overdue", 0) > 0:
            tone = "bad"
        elif v.get("review_due_soon", 0) > 0:
            tone = "warn"
        else:
            tone = "ok"
    elif key == "agent_health":
        tone = "warn" if v.get("devices_degraded", 0) > 0 else "ok"
    elif key == "devices":
        count = v.get("silent", 0) + v.get("unknown", 0)
        return "warn" if count > 0 else "neutral"
    else:  # cis_posture, os_updates, recent_activity - no pass/fail implied
        return "neutral"

    if tone == "ok" and state not in ("value", "zero"):
        return "neutral"
    return tone


def _overview_card_headline(key: str, values: dict) -> str:
    """The one primary figure for `value`/`zero`/`partial` states - always a
    single number, matching the exact figure each card's own `zero` rule in
    the platform (go-service/internal/report/portal_overview_cards.go) is
    keyed on, so the headline reads zero exactly when the card's state is
    zero. Never multi-clause (Andy review) - the breakdown lives in the one
    supporting line below, built by _overview_card_support."""
    v = values or {}
    if key == "devices":
        return str(v.get("total", 0))
    if key == "os_updates":
        return str(v.get("pending", 0))
    if key == "vulnerabilities":
        return str(v.get("critical", 0) + v.get("high", 0))
    if key == "cis_posture":
        return _format_cis_score(v.get("score", 0))
    if key == "browser_extensions":
        return str(v.get("elevated", 0))
    if key == "high_risk_software":
        return str(v.get("critical", 0) + v.get("high", 0))
    if key == "software_awaiting_approval":
        return str(v.get("products", 0))
    if key == "exceptions_review":
        return str(v.get("review_overdue", 0) + v.get("review_due_soon", 0))
    if key == "agent_health":
        return str(v.get("devices_degraded", 0))
    return "0"


def _overview_card_support(key: str, values: dict) -> str:
    """The one supporting line for a complete (`value`/`zero`) card - a
    short stat breakdown, "." separated (never " - ", Andy review), never a
    second sentence. `partial`/`unknown`/`unavailable` cards use the reason
    text in this slot instead (see _overview_card_render) - the reason is
    the one thing worth a customer's single supporting line when the figure
    itself is incomplete."""
    v = values or {}
    if key == "devices":
        return (
            f"{v.get('active', 0)} active · {v.get('stale', 0)} stale · "
            f"{v.get('silent', 0)} silent · {v.get('unknown', 0)} not seen · "
            f"{v.get('retired', 0)} retired"
        )
    if key == "vulnerabilities":
        return f"{v.get('critical', 0)} critical · {v.get('high', 0)} high"
    if key == "cis_posture":
        return f"{v.get('evaluations', 0)} evaluations"
    if key == "browser_extensions":
        return f"{v.get('total', 0)} total extensions"
    if key == "high_risk_software":
        return f"{v.get('classified', 0)} classified"
    if key == "software_awaiting_approval":
        return f"{v.get('devices', 0)} devices"
    if key == "exceptions_review":
        return f"{v.get('review_overdue', 0)} overdue · {v.get('review_due_soon', 0)} due soon"
    if key == "agent_health":
        return (
            f"{v.get('devices_reporting', 0)} reporting · "
            f"{v.get('devices_not_reporting', 0)} not reporting"
        )
    return ""


def _overview_card_unit(key: str, state, values) -> str:
    """PAT-2254: the small label beside a card's headline figure, for the
    one card whose bare number was unreadable ("3" over "4 reporting . 0 not
    reporting"). It names what the figure counts and matches the coverage
    panel's own "N devices reporting a collection issue" line. Only a state
    that shows a figure gets one; unknown/unavailable show a state word, so
    a unit beside it would label nothing."""
    if key != "agent_health" or state not in ("value", "zero", "partial"):
        return ""
    degraded = (values or {}).get("devices_degraded", 0)
    return "with a collection issue" if degraded == 1 else "with collection issues"


def _overview_card_render(key: str, card) -> dict:
    """One card's full render context. `card` is the contract's own dict for
    this key (state/source/scope/window/freshness/completeness/values/
    unavailable_signals) - rendered as supplied, never re-derived or
    inferred (root AGENTS.md - absence requires authority).

    Andy review: headline is always one figure or one short neutral state
    word, never prose; support is at most one short line - a stat breakdown
    when the card is complete, or the plain-English reason when it is not."""
    label = OVERVIEW_CARD_LABELS[key]
    href = OVERVIEW_CARD_LINKS.get(key)
    if key == "high_risk_software":
        window = card.get("window")
        days = window.get("days") if isinstance(window, dict) else None
        href = _software_filter_url(new_days=days, urgency="critical,high")
    state = card.get("state")
    values = card.get("values")
    reason = (card.get("completeness") or {}).get("reason")

    if state in ("value", "zero"):
        headline = _overview_card_headline(key, values)
        support = _overview_card_support(key, values)
    elif state == "partial":
        if key == "os_updates":
            # PAT-2230: a partial os_updates card showed its pending count
            # (often 0, the floor) as the headline - reading as "nothing
            # behind" when the real picture is incomplete. The headline
            # becomes the state word instead, and the known pending floor
            # moves into the support line alongside the reason.
            headline = "Partial"
            pending = (values or {}).get("pending", 0)
            support = f"{pending} pending known · {_overview_card_reason_text(reason)}"
        else:
            headline = _overview_card_headline(key, values)
            support = _overview_card_reason_text(reason)
    else:  # unknown / unavailable - values is always null, never a number
        headline = OVERVIEW_CARD_STATE_WORDS.get(state, "Not available")
        support = _overview_card_reason_text(reason)

    return {
        "key": key, "label": label, "href": href, "state": state,
        "tone": _overview_card_tone(key, state, values),
        "headline": headline, "support": support,
        "unit": _overview_card_unit(key, state, values),
        "freshness": card.get("freshness") or {},
    }


def _overview_cards_view(jwt_token: str) -> dict:
    """GET /v1/portal/overview/cards (PAT-2207), rendered as ten cards or a
    single honest "unavailable" state. Never lets this call take the rest
    of the Overview page down with it: a 5xx, 404 (platform not deployed
    yet) or timeout all reach here as upstream.UpstreamError and degrade to
    `{"available": False}`, the same fail-soft shape control-coverage
    already uses on this page. No params are ever sent - the tenant comes
    only from the forwarded JWT (Trust model 2)."""
    try:
        data = upstream.get_json("/v1/portal/overview/cards", jwt_token)
    except upstream.UpstreamError:
        return {"available": False}
    if not isinstance(data, dict) or not isinstance(data.get("cards"), dict):
        return {"available": False}
    cards_raw = data["cards"]
    cards = []
    for key in OVERVIEW_CARD_ORDER:
        card = cards_raw.get(key)
        if not isinstance(card, dict) or not card.get("state"):
            return {"available": False}
        try:
            cards.append(_overview_card_render(key, card))
        except (TypeError, AttributeError, ValueError):
            # A value outside the contract (a null count, a non-object
            # completeness) degrades the summary, never 500s the Overview.
            logger.warning("overview card %s outside contract; summary unavailable", key)
            return {"available": False}
    return {
        "available": True, "cards": cards,
        "awaiting_decision": _card_awaiting_decision(cards_raw["software_awaiting_approval"]),
    }


def _card_awaiting_decision(card) -> dict | None:
    """The Software awaiting approval card's own figure as a
    _software_waiting_view-shaped dict, when the card shows one (`value`,
    `zero` or `partial`; unknown/unavailable show a state word and carry
    none), read from the same `values.products` the card's headline
    renders. None when the card has no usable number.

    A `partial` card's figure is a floor, so it can back an action ("Decide
    on 5 products") but never a claim of absence: a partial zero is reported
    unavailable, which drops the glance line and marks Top 3 incomplete
    rather than saying nothing is waiting (root AGENTS.md - absence requires
    authority)."""
    state = card.get("state")
    if state not in ("value", "zero", "partial"):
        return None
    products = (card.get("values") or {}).get("products", 0)
    if type(products) is not int or products < 0:
        return None
    return {"available": state != "partial" or products > 0, "count": products}


def _awaiting_decision(overview_cards: dict, portal_count: dict) -> dict:
    """PAT-2254: the one "products waiting on a decision" figure Top 3
    actions and the at-a-glance line read, so they can never disagree with
    the Software awaiting approval card (live: 128 in Top 3, 140 on the
    card). The platform's card value is the complete one: it covers the
    inventory-only products that the portal's own applications + extensions
    read (`portal_count`, see _software_waiting_view) cannot see, so that
    count is only ever a floor. It is used only when the card shows no
    figure at all, in which case there is no second number on the page to
    disagree with."""
    if overview_cards.get("available"):
        from_card = overview_cards.get("awaiting_decision")
        if from_card is not None:
            return from_card
    return portal_count


def _plural(n: int, word: str) -> str:
    return word if n == 1 else word + "s"


def group_cve_fixes(findings: list) -> dict | None:
    """Find the single product update - or, failing that, the single
    product review - that covers the most critical/high CVE findings at
    once (PAT-2160 ranking rule 2).

    `findings` must already be filtered by the caller to open CVE findings
    whose severity is "critical" or "high" (see _cve_action_source below) -
    this function does no severity filtering itself, so it stays a plain,
    independently testable grouping/ranking step. Each row is expected to
    carry `app`, `fixed_version` and `devices_affected`, the same fields
    GET /v1/portal/findings already returns (see FINDINGS_CSV_COLUMNS).

    Findings are grouped by `app`. A group becomes a "fix" candidate,
    naming one recommended version, only when every row in the group
    shares the exact same non-empty fixed_version string - if the group's
    fixed_version is missing, blank, or disagrees between rows, this
    portal has no single version it can honestly recommend, so the group
    becomes a "review" candidate instead (root AGENTS.md - absence
    requires authority - no update instruction is invented from a value
    the portal was not given).

    A fix candidate's device count is the largest single devices_affected
    value seen in its group, not a sum - summing would double-count a
    device hit by more than one of the group's CVEs, and the portal has no
    per-device union of affected devices to compute the true figure (see
    the PAT-2160 implementation report for this as a candidate platform
    field).

    A group's `cve_count` is the number of distinct `cve_id` values in it
    (PAT-2454). The platform sends one row per CVE per product and version,
    so a product installed in two versions carries each shared CVE twice, and
    counting rows told the customer there were more CVEs than the product has.
    A row with a missing, blank or non-string `cve_id` cannot be matched to
    any other row, so each such row counts once.

    Every group (fix or review alike) is ranked by how many CVEs it
    covers, most first, ties broken by product name so the result is
    deterministic. Returns the single best group, or None if `findings` is
    empty or every row is missing a usable `app` name.
    """
    groups: dict[str, dict] = {}
    for f in findings:
        app = f.get("app")
        if not isinstance(app, str) or not app:
            continue
        g = groups.setdefault(
            app, {"app": app, "versions": set(), "devices": 0, "cve_ids": set(), "unnamed": 0},
        )
        fixed = f.get("fixed_version")
        g["versions"].add(fixed if isinstance(fixed, str) and fixed else None)
        devices = f.get("devices_affected")
        if isinstance(devices, int) and not isinstance(devices, bool) and devices > g["devices"]:
            g["devices"] = devices
        cve_id = f.get("cve_id")
        if isinstance(cve_id, str) and cve_id.strip():
            g["cve_ids"].add(cve_id.strip())
        else:
            g["unnamed"] += 1

    if not groups:
        return None

    candidates = []
    for g in groups.values():
        versions = g["versions"]
        only_version = next(iter(versions)) if len(versions) == 1 else None
        candidates.append({
            "kind": "fix" if only_version else "review",
            "app": g["app"],
            "fixed_version": only_version,
            "devices": g["devices"],
            "cve_count": len(g["cve_ids"]) + g["unnamed"],
        })

    candidates.sort(key=lambda c: (-c["cve_count"], c["app"].casefold()))
    return candidates[0]


def _cve_action_source(cve_attention, cve_fresh, findings_rows_complete, findings_rows) -> dict:
    """Resolve rank_top_actions's rule-2 source dict from data overview()
    already has: cve_attention's own trusted critical/high counts, and the
    finding rows _read_critical_high_findings read (see OVERVIEW_CVE_ROWS_LIMIT
    and OVERVIEW_CVE_MAX_PAGES above).

    available mirrors cve_fresh's own definition (cve_attention.available
    and the tenant CVE-assessment read did not fail) - the same freshness
    _attention_view already applies to the CVE pill row - so a stale or
    unavailable CVE read never produces an action here either.

    The grouped candidate from group_cve_fixes is only trusted when
    `findings_rows_complete` is True, meaning every critical and high row was
    read. A partial read could recommend "the update that fixes the most" for
    the wrong product entirely (PAT-2454: a live estate's first 500 of 777
    rows named a product with 242 CVEs when it had 266). Rows are not compared
    with cve_attention's total: that total counts distinct CVE ids and the rows
    are one per CVE per product and version, so the two are in different units.
    When the read is incomplete, or failed outright, this falls back to an
    ungrouped "review N critical/high CVEs" candidate with no product named,
    built only from cve_attention's own trusted counts - still honest, just
    less specific.
    """
    if not cve_attention.get("available") or not cve_fresh:
        return {"available": False, "candidate": None}
    total = (cve_attention.get("critical") or 0) + (cve_attention.get("high") or 0)
    if not total:
        return {"available": True, "candidate": None}

    if findings_rows_complete:
        critical_high = [f for f in findings_rows if f.get("severity") in ("critical", "high")]
        group = group_cve_fixes(critical_high)
        if group is not None:
            return {"available": True, "candidate": group}

    return {"available": True, "candidate": {
        "kind": "review", "app": None, "fixed_version": None,
        "devices": None, "cve_count": total,
    }}


def _software_waiting_view(jwt_token: str) -> dict:
    """Count of products waiting on a governance decision (PAT-2160's
    "software waiting on a decision" fact and ranking rule 5), reusing the
    exact same two upstream reads and the exact same
    APP_POLICY_GROUP/EXT_APPROVAL_GROUP bucket rules (via _app_group/
    _ext_group) software() already uses for its own "waiting" group - not
    a second definition of "waiting" that could drift out of sync with
    that page.

    Deliberately does not also read GET /v1/portal/software, the
    inventory-only merge PAT-2120 layers on top in software() - that merge
    only ever ADDS products into the waiting bucket on top of applications
    and extensions (main.py's _inventory_group default), so this count can
    only ever be a floor on software()'s own figure, never an
    overstatement (root AGENTS.md - absence requires authority). Pulling
    in that merge here would mean replicating software()'s heavier
    pagination/search-aware fetch and row-matching logic for one count;
    see the PAT-2160 implementation report for this noted as a follow-up
    rather than duplicated here.

    available is False, and count is not trustworthy, only when either
    upstream read fails - the same fail-soft posture this page's other
    additive facts already use.
    """
    waiting, _extensions = _software_waiting_and_extensions(jwt_token)
    return waiting


def _software_waiting_and_extensions(jwt_token: str) -> tuple[dict, list | None]:
    """_software_waiting_view's two reads, also handing back the extension
    rows (None when the reads failed) so the Overview's PAT-2177 Browser
    extensions card reuses them instead of fetching /v1/portal/extensions a
    second time. The waiting dict keeps _software_waiting_view's contract."""
    try:
        apps_data = upstream.get_json("/v1/portal/applications", jwt_token)
        applications = upstream.unwrap_list(apps_data, "applications")
        ext_data = upstream.get_json("/v1/portal/extensions", jwt_token)
        extensions = upstream.unwrap_list(ext_data, "extensions")
    except upstream.UpstreamError:
        return {"available": False, "count": 0}, None
    return _governance_waiting(applications, extensions), extensions


def _governance_waiting(applications: list, extensions: list) -> dict:
    """PAT-2255: the portal's own waiting-on-a-decision floor, computed from
    the applications and extensions reads alone. One function so the
    Overview (above) and /software fall back to the identical number when
    the platform card has none (see _awaiting_decision)."""
    count = sum(1 for a in applications if _app_group(a.get("policy_state")) == "waiting")
    count += sum(1 for e in extensions if _ext_group(e.get("approval_state")) == "waiting")
    return {"available": True, "count": count}


OVERVIEW_RISK_TOP_N = 3
HIGH_RISK_URGENCIES = ("critical", "high")
EXT_DECISION_LABELS = {"waiting": "Waiting on a decision", "approved": "Approved",
                       "not_wanted": "Not wanted", "ignored": "Ignored"}
# PAT-2231: both ongoing-review cards render exactly one primary action in
# their card-foot, styled identically (the .btn/.btn-small idiom already
# used for the rest of the app rather than a plain text link), so the pair
# reads as a consistent design rather than two independently-styled cards.
# High-risk software's action is not count-dependent - it always points at
# the one place a customer can act on newly found software - so this is a
# fixed dict shared by every status branch below. Browser extensions'
# equivalent varies with the live waiting count (_extension_risk_view).
HIGH_RISK_PRIMARY_ACTION = {
    "text": "Review software waiting on a decision",
    "href": SOFTWARE_WAITING_URL,
}


def _high_risk_software_view(new_software: dict) -> dict:
    """PAT-2177 "High-risk software" card, built only from the PAT-2093
    new_software read model the Overview already renders: urgency and its
    human-readable reasons come from the platform's trust + CVE evidence,
    never recomputed here. Scope is honest about its window - the platform
    exposes urgency for newly found software only (new_software.window_days),
    not a whole-estate risk score, so the card says "newly found in the last
    N days" and never implies it has assessed everything installed.

    - "unavailable": the new_software read could not be trusted. Never a
      clean read (root AGENTS.md - absence requires authority).
    - "clear": a trustworthy read with nothing rated critical or high in the
      window. not_assessed is still surfaced, because not assessed is not
      low risk.
    - "data": at least one critical/high product.
    """
    status = new_software.get("status")
    if status == "unavailable":
        return {"status": "unavailable", "primary_action": HIGH_RISK_PRIMARY_ACTION}
    window_days = new_software.get("window_days")
    if status == "empty":
        # PAT-2366: use the complete clear-state model, including counts
        # read by the template, for a verified empty window too.
        new_software = {"window_days": window_days}
    counts = new_software.get("counts") or {}
    count = sum(counts.get(level, 0) for level in HIGH_RISK_URGENCIES)
    risky = [p for p in new_software.get("products") or []
             if p.get("urgency") in HIGH_RISK_URGENCIES]
    top = risky[:OVERVIEW_RISK_TOP_N]
    more = max(count - len(top), 0)
    # PAT-2254: the count, its urgency pills and the "more" action all open
    # /software filtered to the same window and levels, not the Overview's
    # own table (which no longer carries review controls).
    count_href = _software_filter_url(new_days=window_days, urgency="critical,high")
    # PAT-2231 review: the standalone "And N more in the newly found list
    # below" paragraph is folded into the one primary action instead of
    # sitting as a second line - "View N more high-risk products" covers
    # exactly what that paragraph named (PAT-2254: it now opens the same
    # critical and high products in /software). Only when there is nothing
    # left to view does the card fall back to the fixed action every other
    # status already uses.
    if more:
        primary_action = {
            "text": f"View {more} more high-risk {_plural(more, 'product')}",
            "href": count_href,
        }
    else:
        primary_action = HIGH_RISK_PRIMARY_ACTION
    return {
        "status": "data" if count else "clear",
        "window_days": window_days,
        "count": count,
        "counts": {level: counts.get(level, 0) for level in HIGH_RISK_URGENCIES},
        "not_assessed": counts.get("not_assessed", 0),
        "products": top,
        "more": more,
        # Device total across the products the platform returned. When the
        # block is truncated (or only some are shown) this is a floor.
        "devices": sum(p.get("device_count", 0) for p in risky),
        "devices_is_floor": bool(new_software.get("truncated")) or len(risky) < count,
        "count_href": count_href,
        "level_hrefs": {
            level: _software_filter_url(new_days=window_days, urgency=level)
            for level in ("critical", "high", "not_assessed")
        },
        "primary_action": primary_action,
    }


def _extension_risk_view(extensions) -> dict:
    """PAT-2177 "Browser extensions" card from the GET /v1/portal/extensions
    rows _software_waiting_and_extensions already read (None when that read
    failed). Uses the platform's own
    risk_level (normal/elevated, the corrected PAT-125 evidence model) and
    approval_state - no portal-side rule such as "wildcard permission means
    high risk". A row whose risk_level is missing or unrecognised counts as
    "risk not assessed", never as normal."""
    if not isinstance(extensions, list):
        return {"status": "unavailable"}
    rows = [e for e in extensions if isinstance(e, dict)]
    if not rows:
        return {"status": "empty"}

    def devices(e):
        n = e.get("device_count")
        return n if isinstance(n, int) and not isinstance(n, bool) else 0

    elevated = [e for e in rows if e.get("risk_level") == "elevated"]
    unassessed = [e for e in rows if e.get("risk_level") not in ("normal", "elevated")]
    waiting = [e for e in rows if _ext_group(e.get("approval_state")) == "waiting"]
    not_wanted = [e for e in rows if _ext_group(e.get("approval_state")) == "not_wanted"]
    elevated.sort(key=lambda e: (-devices(e), str(e.get("name") or "")))
    top = []
    for e in elevated[:OVERVIEW_RISK_TOP_N]:
        group = _ext_group(e.get("approval_state"))
        top.append({
            "name": e.get("name") or "Unnamed extension",
            "href": _software_filter_url(
                type_="extension", search=e["name"] if isinstance(e.get("name"), str) else None),
            "browser": e.get("browser") if isinstance(e.get("browser"), str) else "",
            "device_count": devices(e),
            "decision": EXT_DECISION_LABELS.get(group, "State not recognised"),
        })
    waiting_n = len(waiting)
    total_n = len(rows)
    # PAT-2231: one primary action, its text and target driven by the live
    # waiting count rather than a fixed link - "Review N decisions" only
    # when there is something to decide on. Mirrors High-risk software's
    # single card-foot action, folding what used to be a separate "and N
    # more" line into the action itself: "View all N extensions" already
    # says there is more than the top-N preview shown above it, the same
    # shape High-risk's own "View N more" does, so neither card carries an
    # extra paragraph after its preview list.
    if waiting_n:
        primary_action = {
            "text": f"Review {waiting_n} {_plural(waiting_n, 'decision')}",
            "href": _software_filter_url(type_="extension", approval="waiting"),
        }
    else:
        primary_action = {
            "text": f"View all {total_n} {_plural(total_n, 'extension')}",
            "href": _software_filter_url(type_="extension"),
        }
    return {
        "status": "data" if (elevated or waiting or unassessed) else "clear",
        "total": len(rows),
        "elevated": len(elevated),
        "elevated_devices": sum(devices(e) for e in elevated),
        "waiting": waiting_n,
        "waiting_href": _software_filter_url(type_="extension", approval="waiting"),
        "not_wanted": len(not_wanted),
        "unassessed": len(unassessed),
        "top": top,
        # How many more elevated-risk extensions exist beyond the top-N
        # preview shown here (never a bare 0 - "more" is truthy only when
        # there really is more to see, same shape as high_risk's own).
        "more": max(len(elevated) - len(top), 0),
        "primary_action": primary_action,
    }


def _cis_healthy(cis_fresh: bool, findings_view: dict) -> bool:
    """PAT-2177: CIS compresses to a compact posture card only when the
    evidence is current and no critical or high CIS check is failing. Stale
    or missing evidence is never "healthy" - the full CIS layout stays."""
    return bool(cis_fresh) and not findings_view.get("critical") and not findings_view.get("high")


def _estate_glance_view(coverage, cve_assessment, cve_assessment_unavailable,
                         software_waiting) -> list:
    """Up to 3 short factual lines for "Your estate at a glance" (PAT-2160).

    Andy's ruling (2026-09-25): trim this list to facts the "Needs
    attention" card below it does not already carry. Reporting loss,
    confirmed CVE counts and open Unapproved alerts are dropped entirely -
    each already has its own row, with its own stale/unavailable handling,
    on that card, so repeating them here would just be the same fact
    worded twice. Only the device count (a bare total, not the reporting-
    loss clause - that clause is Needs attention's job now), CVE
    assessment coverage, and software waiting on a decision remain.

    A line is included only when its own source read succeeded and is
    current (root AGENTS.md - absence requires authority: never a
    fabricated zero).
    """
    lines = []

    if coverage.get("total"):
        total = coverage["total"]
        lines.append({
            "text": f"{total} {_plural(total, 'device')}.",
            "link": "/devices", "link_label": "View devices",
        })

    if not cve_assessment_unavailable:
        if cve_assessment.get("coverage_pct") is not None:
            assessed = cve_assessment["assessed_products"]
            total_products = cve_assessment["total_products"]
            text = (
                f"{assessed} of {total_products} installed "
                f"{_plural(total_products, 'product')} assessed for CVEs "
                f"({cve_assessment['coverage_pct']}%); the rest are not yet assessed, not clean."
            )
        else:
            text = "No installed products have been assessed for CVEs yet."
        lines.append({
            "text": text, "link": "/findings#cve-findings", "link_label": "View CVE findings",
        })

    if software_waiting.get("available"):
        n = software_waiting["count"]
        text = (
            f"{n} {_plural(n, 'product')} waiting on an approval decision."
            if n else "No products are waiting on an approval decision."
        )
        lines.append({"text": text, "link": SOFTWARE_WAITING_URL, "link_label": "View software"})

    return lines[:3]


def rank_top_actions(*, reporting_loss, cve_action, cis_high, unapproved_alerts,
                      software_waiting, cve_coverage) -> dict:
    """Deterministic "Top 3 actions" ranking (PAT-2160). Each parameter is a
    small dict already resolved by the caller (overview()) from one
    Overview data source: {"available": bool, ...count/candidate fields}.
    "available" must be True only when that source's read succeeded and is
    current - this function makes no upstream calls and applies no
    freshness judgement of its own; it only ranks and caps what it is
    given.

    Fixed priority order, independent of magnitude (a large count in a
    lower-priority rule never outranks a smaller one above it):

      1. reporting loss (devices not reporting in the last 24 hours)
      2. critical/high CVEs: the single update fixing the most, or a
         "review" fallback when no single fixed version is known (see
         _cve_action_source/group_cve_fixes)
      3. failing high CIS checks
      4. open Unapproved software alerts
      5. software waiting on an approval decision
      6. CVE assessment coverage below 50%

    A source with available == False, or with a zero/None count/candidate,
    never produces an action - no action is invented from absent or clean
    data (root AGENTS.md - absence requires authority). At most 3 actions
    are returned, taken from the top of this list downward.

    Returns {"actions": [...], "all_fresh": bool}. all_fresh is True only
    when every one of the six sources above reports available - the
    caller uses it to choose between "Nothing needs action right now"
    (every source fresh, nothing to act on) and an explicit stale/
    unavailable line (some source could not be read, so this list may be
    incomplete) - the same distinction _attention_view's all_clear already
    draws for the pill card above.
    """
    actions = []

    if reporting_loss.get("available") and reporting_loss.get("count"):
        n = reporting_loss["count"]
        actions.append({
            "text": f"Check why {n} {_plural(n, 'device')} stopped reporting",
            "link": "/devices?view=not_reporting_24h",
        })

    candidate = cve_action.get("candidate") if cve_action.get("available") else None
    if candidate is not None:
        n = candidate["cve_count"]
        if candidate["kind"] == "fix":
            # PAT-2160, Andy's ruling: the device count is the largest
            # single devices_affected value in the group, not a true
            # per-device union (see group_cve_fixes's docstring) - "at
            # least N" words it honestly as a floor, never a claimed exact
            # figure.
            dev = candidate["devices"]
            actions.append({
                "text": (
                    f"Update {candidate['app']} to {candidate['fixed_version']} on at least "
                    f"{dev} {_plural(dev, 'device')} to fix {n} critical or high "
                    f"{_plural(n, 'CVE')}"
                ),
                "link": "/findings#cve-findings",
            })
        elif candidate["app"]:
            actions.append({
                "text": f"Review {n} critical or high {_plural(n, 'CVE')} in {candidate['app']}",
                "link": "/findings#cve-findings",
            })
        else:
            actions.append({
                "text": f"Review {n} critical or high {_plural(n, 'CVE')}",
                "link": "/findings#cve-findings",
            })

    if cis_high.get("available") and cis_high.get("count"):
        n = cis_high["count"]
        actions.append({
            "text": f"Review {n} failing high CIS {_plural(n, 'check')}",
            "link": "/findings#cis-compliance-findings",
        })

    if unapproved_alerts.get("available") and unapproved_alerts.get("count"):
        n = unapproved_alerts["count"]
        actions.append({
            "text": f"Decide on {n} open Unapproved software {_plural(n, 'alert')}",
            "link": "/software/alerts",
        })

    if software_waiting.get("available") and software_waiting.get("count"):
        n = software_waiting["count"]
        actions.append({
            "text": f"Decide on {n} {_plural(n, 'product')} waiting for an approval decision",
            "link": SOFTWARE_WAITING_URL,
        })

    if (
        cve_coverage.get("available")
        and cve_coverage.get("pct") is not None
        and cve_coverage["pct"] < 50
    ):
        actions.append({
            "text": f"Review CVE assessment coverage ({cve_coverage['pct']}%)",
            "link": "/findings#cve-findings",
        })

    sources = (
        reporting_loss, cve_action, cis_high, unapproved_alerts, software_waiting, cve_coverage,
    )
    return {"actions": actions[:3], "all_fresh": all(s.get("available") for s in sources)}


# ── Pages ─────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def overview(request: Request):
    try:
        data = upstream.get_json("/v1/portal/overview", request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)

    # PAT-2190: the ten Overview information cards are a separate platform
    # read model (PAT-2207, GET /v1/portal/overview/cards) from the
    # /v1/portal/overview call above - its own failure (5xx, 404 because
    # the platform isn't deployed yet, or a timeout) must not take the rest
    # of this already-successful page down with it, so it is fetched and
    # degraded independently, exactly like control-coverage below.
    overview_cards = _overview_cards_view(request.state.jwt)

    # PAT-1859: control coverage is a supplementary explanation of the
    # established CIS score, not another score calculation in the portal.
    # It is one aggregate platform read model, deliberately not a device or
    # rule fan-out. If it is unavailable, preserve the overview rather than
    # turning a secondary explanatory card into an outage for the landing
    # page.
    control_coverage, control_coverage_unavailable = None, False
    try:
        control_coverage = upstream.get_json(
            "/v1/portal/control-coverage", request.state.jwt
        )
    except upstream.UpstreamError:
        control_coverage_unavailable = True
    else:
        if not is_control_coverage_response(control_coverage):
            control_coverage, control_coverage_unavailable = None, True

    findings = data.get("findings_open") or {}
    patch = data.get("patch_status") or {}
    # PAT-2342: unavailable unknown counts are not an authoritative zero.
    patch_unknown = patch.get("unknown")
    if type(patch_unknown) is not int or patch_unknown < 0:
        patch_unknown = None
    # PAT-1953: cve_attention is a separate platform read model from
    # findings_open (CIS). It may be entirely absent from the response
    # until the platform PR that introduces it is deployed - that must
    # render the same honest "not yet available" state as an explicit
    # available: false, never a false "0 critical, 0 high" clean read
    # (root AGENTS.md - absence requires authority).
    cve_attention_raw = data.get("cve_attention") or {}
    cve_attention = {
        "available": bool(cve_attention_raw.get("available")),
        "critical": cve_attention_raw.get("critical", 0) or 0,
        "high": cve_attention_raw.get("high", 0) or 0,
    }

    # PAT-2025: the tenant-level cve_assessment object (last checked/feed
    # updated timestamps, assessed-product coverage) rides only on GET
    # /v1/portal/findings, not on this overview read model - a probe reads
    # it without a second /findings page load. Like control-coverage above,
    # its own failure must not take the rest of the overview down with it.
    # PAT-2160: the limit was raised from 1 to OVERVIEW_CVE_ROWS_LIMIT so
    # this same call also returns real finding rows for the "Top 3 actions"
    # CVE ranking rule (_cve_action_source/group_cve_fixes) - see that
    # constant's own comment for why 500 rather than unbounded.
    # PAT-2454: that one page is not the whole list on a large estate, so the
    # rows are read on until every critical and high one is in hand, or the
    # read says it could not (_read_critical_high_findings).
    cve_assessment, cve_assessment_unavailable = _tenant_cve_assessment_view(None), False
    findings_rows, findings_rows_complete = [], False
    try:
        findings_probe = upstream.get_json(
            "/v1/portal/findings", request.state.jwt,
            params={"limit": OVERVIEW_CVE_ROWS_LIMIT, "offset": 0},
        )
    except upstream.UpstreamError:
        cve_assessment_unavailable = True
    else:
        if isinstance(findings_probe, dict):
            cve_assessment = _tenant_cve_assessment_view(findings_probe.get("cve_assessment"))
            # A first page with no findings list is a contract break and
            # raises here, as it always has.
            upstream.unwrap_list(findings_probe, "findings")
            findings_rows, findings_rows_complete = _read_critical_high_findings(
                request.state.jwt, findings_probe,
            )
        else:
            cve_assessment_unavailable = True

    # PAT-2097: unapproved-software alert counts, additive to this overview
    # response. null (or the key entirely absent, before the platform ships
    # it) means the count could not be read - rendered as genuinely
    # unavailable, never a false "0 open" clean read (root AGENTS.md -
    # absence requires authority, same rule as cve_attention above).
    alerts_open_raw = data.get("unapproved_alerts_open")
    alerts_ack_raw = data.get("unapproved_alerts_acknowledged")
    alert_counts = {
        "available": type(alerts_open_raw) is int and type(alerts_ack_raw) is int,
        "open": alerts_open_raw if type(alerts_open_raw) is int else 0,
        "acknowledged": alerts_ack_raw if type(alerts_ack_raw) is int else 0,
    }

    # PAT-2093: new software by urgency, additive to this overview response
    # like cve_attention and alert_counts above. PAT-2159: _new_software_view
    # now always returns a dict with a status - "unavailable" (the read
    # failed or could not be trusted) still renders the card with an
    # explicit unavailable line rather than disappearing it, "empty" (a
    # successful read, every count genuinely zero) hides the card, and
    # "data" renders it as before. PAT-2254: the card is read only. Software
    # review (Set state / Apply) lives in /software, so there is no role
    # read here and every count and row links into a filtered /software.
    new_software = _new_software_view(data.get("new_software"))

    findings_view = {k: findings.get(k, 0) for k in ("critical", "high", "medium", "low")}
    coverage = coverage_geometry(
        data.get("devices_total"), data.get("devices_reporting_24h"), data.get("devices_retired"))

    # PAT-2160: freshness definitions duplicated from _attention_view's own
    # one-line formulas (not imported from its return dict, which is
    # PAT-2159's own established contract) - cis_fresh/cve_fresh gate both
    # the welcome block's facts/actions below and the pill card's own
    # cis_stale/all_clear reasoning, so both must apply the identical rule.
    cis_known = bool(coverage.get("total"))
    cis_fresh = cis_known and bool(coverage.get("reporting"))
    cve_known = bool(cve_attention.get("available"))
    cve_fresh = cve_known and not cve_assessment_unavailable

    portal_waiting, extensions = _software_waiting_and_extensions(request.state.jwt)
    # PAT-2254: Top 3 actions, the at-a-glance line and the Software awaiting
    # approval card read one value (see _awaiting_decision).
    software_waiting = _awaiting_decision(overview_cards, portal_waiting)
    glance_lines = _estate_glance_view(
        coverage, cve_assessment, cve_assessment_unavailable, software_waiting,
    )
    top_actions = rank_top_actions(
        reporting_loss={"available": cis_known, "count": coverage.get("missing", 0)},
        cve_action=_cve_action_source(
            cve_attention, cve_fresh, findings_rows_complete, findings_rows,
        ),
        cis_high={"available": cis_known and cis_fresh, "count": findings_view.get("high", 0)},
        unapproved_alerts={"available": alert_counts["available"], "count": alert_counts["open"]},
        software_waiting=software_waiting,
        cve_coverage={
            "available": not cve_assessment_unavailable,
            "pct": cve_assessment.get("coverage_pct"),
        },
    )

    high_risk = _high_risk_software_view(new_software)
    extension_risk = _extension_risk_view(extensions)
    cis_healthy = _cis_healthy(cis_fresh, findings_view)

    return _render(request, "overview.html", {
        "title": "Overview",
        "nav": "overview",
        # PAT-2254: the page title is "Overview"; the tenant name is the
        # subline, cleaned of any internal identifier the platform's name
        # for the tenant carries.
        "tenant_name": _customer_facing_tenant_name(data.get("tenant_name")),
        "overview_cards": overview_cards,
        "high_risk": high_risk,
        "extension_risk": extension_risk,
        "cis_healthy": cis_healthy,
        "data": data,
        "coverage": coverage,
        "dial": dial_geometry(data.get("cis_score_current")),
        "trend": trend_geometry(data.get("cis_trend") or []),
        "findings": findings_view,
        "findings_total": sum(findings.get(k, 0) or 0
                              for k in ("critical", "high", "medium", "low")),
        "cve_attention": cve_attention,
        "alert_counts": alert_counts,
        "glance_lines": glance_lines,
        "top_actions": top_actions,
        "attention": _attention_view(
            coverage, findings_view, cve_attention, cve_assessment_unavailable, alert_counts,
        ),
        "patch": {
            **{k: patch.get(k, 0) for k in ("up_to_date", "pending", "failed")},
            "unknown": patch_unknown,
        },
        "control_coverage": control_coverage,
        "control_coverage_unavailable": control_coverage_unavailable,
        "cve_assessment": cve_assessment,
        "cve_assessment_unavailable": cve_assessment_unavailable,
        "new_software": new_software,
    })


DEVICE_VIEWS = ("silent", "quiet", "normal", "retired")

# PAT-2212: the device-list reconciliation card's own count-tile filter
# (?list_group=), independent of the roster-wide reporting-state ?view=
# above - one card can be showing "not on your list" while the main table
# is filtered to Silent, and vice versa. never_seen defaults first because
# it is the group most likely to need the customer's action (a device they
# expect but Patched has never seen).
DEVICE_LIST_GROUPS = ("never_seen", "not_on_list", "matched")


@app.get("/devices", response_class=HTMLResponse)
def devices(request: Request, view: str = "all", stale_days: str = "", list_group: str = "",
            type: str = "all"):
    try:
        roster = get_device_roster(request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    threshold = normalise_stale_days(stale_days)
    annotate_staleness(roster, threshold)
    selected_type = type if type in ("all", "workstation", "server", "unknown") else "all"
    typed_roster = [d for d in roster if selected_type == "all"
                    or (device_type_view(d)["kind"] or "unknown") == selected_type]
    stale_count = sum(d["is_stale"] for d in typed_roster)

    if view == "stale":
        shown = [d for d in typed_roster if d["is_stale"]]
        return _render(request, "devices_stale.html", {
            "title": "Devices", "nav": "devices", "devices": shown,
            "total": len(roster), "stale_count": stale_count,
            "stale_days": threshold, "stale_choices": STALE_CHOICES,
        })

    can_edit, role_unavailable = False, False
    try:
        can_edit = _portal_role(request.state.jwt) == "admin"
    except upstream.UpstreamError as exc:
        logger.warning("portal.devices.role_fail_soft kind=%s", exc.kind)
        role_unavailable = True
    device_result = _device_flash_view(_read_flash(
        request.state.jwt, request.query_params.get(DEVICE_RESULT_PARAM, "")))

    if view == "not_reporting_24h":
        # PAT-2135: a retired device is the customer's own decision, not a
        # coverage gap - it never appears in "not reporting" here, the same
        # exclusion the Overview's coverage hero and Needs attention card
        # apply via coverage_geometry's own retired argument.
        missing = [d for d in typed_roster
                   if not d["retirement_view"]["retired"] and is_reporting_gap(d.get("last_seen"))]
        annotate_staleness(missing, REPORTING_GAP_HOURS // 24)
        return _render(request, "devices_reporting_gap.html", {
            "title": "Devices", "nav": "devices", "devices": missing,
            "total": len(roster), "missing": len(missing),
            "can_edit": can_edit, "return_to": "/devices?view=not_reporting_24h",
            "device_result": device_result,
        })

    # PAT-1642/PAT-1843: the platform-derived bucket remains authoritative,
    # while all three reporting states share one page and one table.  The
    # selected state seeds the server-hidden rows and the client-side view;
    # it never changes which server rows were fetched or classified. PAT-2135: a retired device is
    # excluded from silent/quiet/normal (it is the customer's own decision,
    # never "missing") and gets its own group/tab instead.
    for d in roster:
        d["group"] = "retired" if d["retirement_view"]["retired"] else bucket_group(d["days_stale"])
    silent = [d for d in roster if d["group"] == "silent"]
    quiet = [d for d in roster if d["group"] == "quiet"]
    normal = [d for d in roster if d["group"] == "normal"]
    retired = [d for d in roster if d["group"] == "retired"]
    # PAT-1957: with no (or an unrecognised) ?view= the page lands on
    # "normal" whatever the counts, so a healthy tenant is not greeted by an
    # empty Silent tab; an explicit silent|quiet|normal|retired is honoured
    # as sent.
    selected_view = view if view in DEVICE_VIEWS else "normal"
    # PAT-2212: same "unrecognised falls back to a stable default" shape as
    # selected_view above, for the device-list card's own tile filter.
    selected_list_group = list_group if list_group in DEVICE_LIST_GROUPS else "never_seen"
    device_list = _device_list_view(request.state.jwt)

    def filter_url(**changes):
        params = {"view": selected_view}
        if selected_type != "all":
            params["type"] = selected_type
        if stale_days:
            params["stale_days"] = str(threshold)
        if list_group:
            params["list_group"] = selected_list_group
        params.update(changes)
        if params.get("type") == "all":
            params.pop("type")
        return "/devices?" + urlencode(params)

    view_options = []
    for group, label in (("silent", f"Silent over {GROUP_SILENT_DAYS} days"),
                         ("quiet", "Quiet 3–14 days"), ("normal", "Reporting normally"),
                         ("retired", "Retired")):
        count = sum(d["group"] == group for d in typed_roster)
        tone = {"silent": "bad", "quiet": "warn"}.get(group) if count else None
        view_options.append((group, label, count, filter_url(view=group), tone))
    type_options = []
    has_unknown = any(device_type_view(d)["kind"] is None for d in roster)
    view_roster = [d for d in roster if d["group"] == selected_view]
    for kind, label in (("all", "All types"), ("workstation", "Workstations"),
                        ("server", "Servers"), ("unknown", "Unknown type")):
        count = sum(kind == "all" or (device_type_view(d)["kind"] or "unknown") == kind
                    for d in view_roster)
        if (count or selected_type == kind) and (kind != "unknown" or has_unknown):
            type_options.append((kind, label, count, filter_url(type=kind)))
    type_plural = {"all": "devices", "workstation": "workstations", "server": "servers",
                   "unknown": "devices of unknown type"}[selected_type]
    return _render(request, "devices.html", {
        "title": "Devices", "nav": "devices",
        "total": len(roster), "devices": typed_roster, "device_view": selected_view,
        "device_type": selected_type, "view_options": view_options, "type_options": type_options,
        "empty_type_text": f"No {type_plural} in this reporting state.",
        "has_visible_devices": any(d["group"] == selected_view for d in typed_roster),
        "list_urls": {group: filter_url(list_group=group) for group in DEVICE_LIST_GROUPS},
        "silent": silent, "quiet": quiet, "normal": normal, "retired": retired,
        "list_group": selected_list_group,
        "quiet_days": GROUP_QUIET_DAYS, "silent_days": GROUP_SILENT_DAYS,
        "can_edit": can_edit, "role_unavailable": role_unavailable,
        "device_list": device_list, "return_to": "/devices",
        "device_result": device_result,
    })


# ── PAT-2405: every list export is also a PDF ──────────────────────────────
# One function per export produces the header and the rows for a request;
# the CSV route writes them as CSV and the PDF route posts the very same rows
# to the platform's table renderer (POST /v1/portal/exports/table-pdf, the
# portal has no PDF renderer of its own). The PDF therefore shows exactly the
# rows the CSV holds for the same query and role, and never re-fetches or
# re-filters differently. Rows hold the real values: any spreadsheet
# formula-neutralising prefix is applied only when the CSV is written, so the
# PDF reads as the data does.
PDF_EXPORT_PATH = "/v1/portal/exports/table-pdf"
PDF_EXPORT_MAX_ROWS = 10000
PDF_EXPORT_MAX_COLUMNS = 40
PDF_EXPORT_MAX_FILTERS = 20
# The platform refuses a body of 16 MiB or more; stay clear of the edge.
PDF_EXPORT_MAX_BODY_BYTES = 15 * 1024 * 1024
# The most of a platform-produced CSV the portal will hold to re-render it.
PDF_EXPORT_MAX_SOURCE_BYTES = 64 * 1024 * 1024
_PDF_FILENAME_SAFE = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
PLATFORM_FILTER_LABELS = {"macos": "macOS", "windows": "Windows"}


class _ExportTable(NamedTuple):
    export: str          # the platform's key for this export
    csv_filename: str    # the CSV twin's filename; the PDF mirrors it
    columns: list
    rows: list           # lists of str, real values (never neutralised)
    filters: list        # (label, value) pairs for the selection actually set


def _cell(value) -> str:
    return "" if value is None else str(value)


def _csv_formula_guard(value) -> str:
    """The one spreadsheet formula guard for every CSV the portal writes
    itself (PAT-2411). A cell that starts with tab, CR or LF, or whose
    left-stripped form starts with =, +, - or @, gets a leading single quote
    so a spreadsheet reads it as text. Stricter than the platform's CSVSafe
    (which checks only the first byte and not LF); a plain `-5` is prefixed
    too, as there."""
    text = "" if value is None else str(value)
    return "'" + text if (text.startswith(("\t", "\r", "\n"))
                           or text.lstrip().startswith(("=", "+", "-", "@"))) else text


def _csv_line(values) -> str:
    buf = io.StringIO()
    csv.writer(buf).writerow([_csv_formula_guard(v) for v in values])
    return buf.getvalue()


def _table_csv_response(table: _ExportTable) -> StreamingResponse:
    """The CSV twin of `_table_pdf_response`: the same table, written as CSV
    with every cell, the header included, through `_csv_formula_guard`. There
    is deliberately no way to write a cell unguarded."""
    def body():
        yield _csv_line(table.columns)
        for row in table.rows:
            yield _csv_line(row)

    return StreamingResponse(body(), media_type="text/csv", headers={
        "Content-Disposition": f'attachment; filename="{table.csv_filename}"',
    })


def _pdf_twin(csv_url: str) -> str:
    """A page's CSV link with its extension swapped, query string kept."""
    path, sep, query = csv_url.partition("?")
    return (path[:-4] + ".pdf" if path.endswith(".csv") else path) + sep + query


def _pdf_filename(csv_filename: str) -> str:
    stem = csv_filename[:-4] if csv_filename.lower().endswith(".csv") else csv_filename
    name = f"{stem}.pdf"
    return name if _PDF_FILENAME_SAFE.match(name) else "patched-export.pdf"


def _table_pdf_payload(table: _ExportTable) -> dict:
    """The platform's table-pdf body. More than PDF_EXPORT_MAX_ROWS rows (or
    a body past the size limit) sends the leading rows and the real count in
    total_rows, so the PDF can say it is a partial listing."""
    columns, rows = list(table.columns), table.rows
    if not 1 <= len(columns) <= PDF_EXPORT_MAX_COLUMNS or any(len(r) != len(columns) for r in rows):
        raise upstream.UpstreamError("error", "export table is not renderable as a PDF")

    def body(count: int) -> dict:
        payload = {
            "export": table.export,
            "filters": [{"label": a, "value": b}
                        for a, b in table.filters[:PDF_EXPORT_MAX_FILTERS]],
            "columns": columns, "rows": rows[:count],
        }
        if count < len(rows):
            payload["total_rows"] = len(rows)
        return payload

    count = min(len(rows), PDF_EXPORT_MAX_ROWS)

    def fits(n: int) -> bool:
        return len(json.dumps(body(n), ensure_ascii=False).encode()) <= PDF_EXPORT_MAX_BODY_BYTES

    if not fits(count):
        low, high = 0, count  # largest n that fits; n=0 always does
        while low < high:
            mid = (low + high + 1) // 2
            low, high = (mid, high) if fits(mid) else (low, mid - 1)
        count = low
    return body(count)


def _table_pdf_response(request: Request, table: _ExportTable, on_forbidden=None):
    """POST the table to the platform's renderer and return its PDF as a
    download. A platform refusal or fault is the portal's normal error page
    (never the platform's body); `on_forbidden` lets an admin-only export
    answer a 403 exactly as its CSV twin does."""
    try:
        pdf = upstream.post_bytes(
            PDF_EXPORT_PATH, request.state.jwt, _table_pdf_payload(table))
    except upstream.UpstreamError as exc:
        if exc.kind == "forbidden" and on_forbidden is not None:
            return on_forbidden()
        return _error_page(request, exc)
    return Response(content=pdf, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="{_pdf_filename(table.csv_filename)}"',
        "Cache-Control": "private, no-store",
    })


class _ProxiedCsv(NamedTuple):
    """An export whose CSV is the platform's own (streamed verbatim). The one
    shared description of the request: the CSV route streams the answer, the
    PDF route parses the very same answer into a table."""
    export: str
    path: str
    params: dict
    default_filename: str
    filters: list


def _proxied_csv_response(request: Request, spec: _ProxiedCsv):
    try:
        resp = upstream.stream(
            spec.path, request.state.jwt, params={**spec.params, "format": "csv"})
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    return _sam_csv_response(resp, default_filename=spec.default_filename)


def _unneutralise(cell: str) -> str:
    """Undo the platform's spreadsheet guard (one leading apostrophe in front
    of a formula trigger) so the PDF shows the real value."""
    if cell.startswith("'"):
        rest = cell[1:]
        if rest.startswith(("\t", "\r", "\n")) or rest.lstrip().startswith(("=", "+", "-", "@")):
            return rest
    return cell


def _proxied_csv_table(resp, spec: _ProxiedCsv) -> _ExportTable:
    """Read the platform's CSV answer (bounded) into a table. A ragged or
    headerless file is a platform fault, never guessed at."""
    try:
        chunks: list[bytes] = []
        size = 0
        for chunk in upstream.iter_stream(resp):
            size += len(chunk)
            if size > PDF_EXPORT_MAX_SOURCE_BYTES:
                raise upstream.UpstreamError("unavailable", "export too large to render")
            chunks.append(chunk)
    except upstream.UpstreamStreamError as exc:
        raise upstream.UpstreamError("unavailable", str(exc)) from exc
    finally:
        resp.close()
    try:
        text = b"".join(chunks).decode("utf-8-sig")
        records = [r for r in csv.reader(io.StringIO(text, newline=""), strict=True) if r]
    except (UnicodeDecodeError, csv.Error) as exc:
        raise upstream.UpstreamError("error", "unreadable CSV export") from exc
    if not records or any(len(r) != len(records[0]) for r in records):
        raise upstream.UpstreamError("error", "malformed CSV export")
    disposition = re.search(r'filename="([^"]+)"', resp.headers.get("Content-Disposition", ""))
    filename = disposition.group(1) if disposition else spec.default_filename
    return _ExportTable(
        spec.export, filename if filename.lower().endswith(".csv") else spec.default_filename,
        records[0], [[_unneutralise(c) for c in r] for r in records[1:]], spec.filters)


def _proxied_csv_pdf_response(request: Request, spec: _ProxiedCsv):
    try:
        resp = upstream.stream(
            spec.path, request.state.jwt, params={**spec.params, "format": "csv"})
        table = _proxied_csv_table(resp, spec)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    return _table_pdf_response(request, table)


def _filter_pairs(params: dict, specs: dict) -> list:
    """(label, value) pairs, in `specs` order, for the filters actually set.
    `specs` maps a param to (label, value-labels or None for the raw value)."""
    pairs = []
    for key, (label, names) in specs.items():
        if params.get(key):
            pairs.append((label, names.get(params[key], params[key]) if names else params[key]))
    return pairs


def _title_label(value: str) -> str:
    return value.replace("_", " ").capitalize()


def _devices_export_table(request: Request, stale_days: str) -> _ExportTable:
    """Every device (PAT-701/PAT-1865), or with ?stale_days=N only the stale
    ones. Raises UpstreamError; fetching completes before anything is sent,
    so a later page failure cannot send a partial file."""
    roster = get_device_roster(request.state.jwt)
    threshold = normalise_stale_days(stale_days)
    annotate_staleness(roster, threshold)
    if stale_days:
        shown = [d for d in roster if d["is_stale"]]
        export, filename = "devices-stale", f"patched-devices-stale-{threshold}d.csv"
        filters = [("Stale for at least", f"{threshold} days")]
    else:
        shown = roster
        export, filename, filters = "devices", "patched-devices.csv", []
    rows = []
    for d in shown:
        kind = device_type_view(d)["kind"]
        rows.append([_cell(v) for v in (
            d.get("hostname", ""),
            d.get("platform", ""),
            d.get("os_version", ""),
            d.get("last_seen", ""),
            "" if d["days_stale"] is None else d["days_stale"],
            # PAT-2324: a server has no CIS score (no server benchmark
            # yet), and the pages say so, so the export leaves it empty.
            "" if d.get("cis_score") is None or kind == "server"
            else round(d.get("cis_score")),
            assurance_csv_value(d["encryption_ok"], d["is_stale"]),
            assurance_csv_value(d["patch_pending"], d["is_stale"]),
            d.get("cve_assessment", {}).get("state", "not_assessed"),
            kind or "",
        )])
    return _ExportTable(export, filename, list(CSV_COLUMNS), rows, filters)


@app.get("/devices.csv")
def devices_csv(request: Request, stale_days: str = ""):
    """CSV export of every device (PAT-701/PAT-1865), generated statelessly.

    ?stale_days=N restricts the complete aggregated roster to stale devices.
    Fetching completes before StreamingResponse is constructed, so a later
    page failure cannot send a partial CSV body to the customer.
    """
    try:
        table = _devices_export_table(request, stale_days)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    return _table_csv_response(table)


@app.get("/devices.pdf")
def devices_pdf(request: Request, stale_days: str = ""):
    """PAT-2405: the same table as /devices.csv, as a PDF."""
    try:
        table = _devices_export_table(request, stale_days)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    return _table_pdf_response(request, table)


# ── Jamf Pro coverage (PAT-2145) ────────────────────────────────────────────
# Which Macs the customer's Jamf Pro manages that Patched has never seen, and
# which Macs Patched sees that Jamf hasn't reported - built only from
# webhooks the customer's own Jamf Pro pushes and the agent's own MDM
# evidence (contracts/portal-api.md "Jamf Pro coverage (PAT-2145)"). Patched
# never holds a Jamf API credential. Every portal role reads this and the
# setup page below; only the four writes further down (setup PUT, token
# create/rotate, token revoke, device purge) are admin only.
JAMF_PAGE_SIZE = 25
JAMF_RESULT_PARAM = "jamf_result"
JAMF_SETUP_MAX_BODY_BYTES = 2 * 1024

# connector.status -> (label, pill class). Five platform states, shown as
# five distinct reads rather than collapsed to green/amber/grey - "revoked"
# and "amber" both carry connector.amber=true upstream but are not the same
# thing to an admin (one needs a new token, the other just needs Jamf Pro
# checked).
JAMF_CONNECTOR_STATUS = {
    "not_configured": ("Not connected", "pill-muted"),
    "awaiting_first_event": ("Awaiting first event", "pill-muted"),
    "ok": ("Connected", "pill-ok"),
    "amber": ("Delayed", "pill-warn"),
    "revoked": ("Token revoked", "pill-bad"),
}

# jamf_state (the "gap" bucket's own field) -> human label.
JAMF_STATE_LABELS = {
    "enrolled": "Enrolled",
    "dep_assigned_only": "Assigned in Apple Business Manager",
}

# mdm_state (the "not_reported_by_jamf" bucket's per-row field) -> a short
# table pill. "unmanaged" is used here, and only here, because the platform
# itself restricts that exact value to the agent's own evidence of no MDM
# enrolment (root AGENTS.md: absence requires authority - Jamf's silence is
# never treated as proof of "unmanaged", see basis.no_backfill/
# no_delete_event below). The row's own `note` field, rendered verbatim in
# the table, carries the full sentence (including any named vendor); this
# is only the compact pill.
JAMF_MDM_STATE_LABELS = {
    "other_mdm": ("Another MDM", "pill-muted"),
    "jamf_no_event_yet": ("Jamf, no event yet", "pill-warn"),
    "enrolled_mdm_unidentified": ("MDM enrolled, unidentified", "pill-muted"),
    "unmanaged": ("No MDM enrolment reported", "pill-muted"),
    "unknown": ("Unknown", "pill-muted"),
}


def _jamf_offset(raw: str) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return 0
    return min(value, 2_147_483_647) if value >= 0 else 0


def _jamf_bucket_page(jwt_token: str, bucket: str, offset: int) -> dict:
    data = upstream.get_json(
        "/v1/portal/mdm/jamf/coverage", jwt_token,
        params={"bucket": bucket, "limit": JAMF_PAGE_SIZE, "offset": offset},
    )
    return data if isinstance(data, dict) else {}


def _jamf_page_url(bucket_param: str, current_offsets: dict, offset: int) -> str | None:
    """A Previous/Next link for one bucket's own offset query param,
    carrying the other two buckets' current offsets unchanged so paging one
    table never resets the others."""
    if offset < 0:
        return None
    params = dict(current_offsets)
    params[bucket_param] = str(offset)
    return "/devices/jamf?" + urlencode(params)


def _jamf_bucket_view(data: dict, bucket_key: str, offset: int, bucket_param: str,
                      current_offsets: dict) -> dict:
    section = data.get(bucket_key) if isinstance(data.get(bucket_key), dict) else {}
    rows = section.get("rows") if isinstance(section.get("rows"), list) else []
    total = section.get("total") if type(section.get("total")) is int else len(rows)
    return {
        "rows": rows, "total": total, "offset": offset,
        "shown_from": offset + 1 if rows else 0, "shown_to": offset + len(rows),
        "prev_url": (_jamf_page_url(bucket_param, current_offsets, offset - JAMF_PAGE_SIZE)
                    if offset > 0 else None),
        "next_url": (_jamf_page_url(bucket_param, current_offsets, offset + JAMF_PAGE_SIZE)
                    if offset + len(rows) < total else None),
    }


def _jamf_connector_view(connector: dict) -> dict:
    status = connector.get("status") if isinstance(connector, dict) else None
    label, pill_class = JAMF_CONNECTOR_STATUS.get(status or "", ("Unknown", "pill-muted"))
    return {
        "status": status or "not_configured", "label": label, "pill_class": pill_class,
        "amber": bool(connector.get("amber")) if isinstance(connector, dict) else False,
        "message": (connector.get("message") or "") if isinstance(connector, dict) else "",
        "first_event_at": connector.get("first_event_at") if isinstance(connector, dict) else None,
        "last_event_at": connector.get("last_event_at") if isinstance(connector, dict) else None,
        "hours_since_last_event": (
            connector.get("hours_since_last_event") if isinstance(connector, dict) else None),
        "check_in_enabled": bool(connector.get("check_in_enabled"))
                            if isinstance(connector, dict) else False,
        "jamf_instance": connector.get("jamf_instance") if isinstance(connector, dict) else None,
    }


def _jamf_mdm_state_view(state) -> dict:
    label, pill_class = JAMF_MDM_STATE_LABELS.get(state or "", ("Unknown", "pill-muted"))
    return {"state": state, "label": label, "pill_class": pill_class}


def _jamf_flash_view(data: dict | None) -> dict | None:
    if not data:
        return None

    def text(key, limit=600):
        value = data.get(key)
        return value[:limit] if isinstance(value, str) else ""

    return {"error": text("error"), "notice": text("notice")}


def _jamf_redirect(
        request: Request, payload: dict, return_to: str = "/devices/jamf") -> RedirectResponse:
    token = _sign_flash(request.state.jwt, payload)
    separator = "&" if "?" in return_to else "?"
    url = f"{return_to}{separator}{JAMF_RESULT_PARAM}={quote(token, safe='')}#jamf-result"
    return RedirectResponse(url=url, status_code=303)


JAMF_ERROR_MESSAGES = {
    "not_configured": "Jamf is not connected yet. Create a webhook token first.",
}


def _jamf_error_payload(exc: upstream.UpstreamError, action: str) -> dict:
    if exc.kind == "unavailable":
        return {"error": (
            "The Patched platform could not be reached, so this change may not have been "
            "saved. Refresh the page to check before trying again."
        )}
    if exc.status == 409:
        return {"error": JAMF_ERROR_MESSAGES["not_configured"]}
    try:
        body = json.loads(exc.body) if exc.body else {}
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    code = body.get("error") if isinstance(body.get("error"), str) else ""
    message = body.get("message") if isinstance(body.get("message"), str) else ""
    if code == "admin_role_required":
        return {"error": (
            f"Only an administrator on your account can {action}. Nothing was changed."
        )}
    return {"error": (
        (message[:300] + " Nothing was changed.") if message
        else "The Patched platform refused this change. Nothing was changed."
    )}


@app.get("/devices/jamf", response_class=HTMLResponse)
def devices_jamf(request: Request, gap_offset: str = "0", not_reported_offset: str = "0",
                 covered_offset: str = "0"):
    """PAT-2145: connector health, the "from Jamf webhooks since <date>"
    basis statement, and the three coverage buckets (gap, not reported by
    Jamf, covered), each independently paged. Every portal role reads this
    page; the linked setup page's writes are admin only."""
    offsets = {
        "gap_offset": str(_jamf_offset(gap_offset)),
        "not_reported_offset": str(_jamf_offset(not_reported_offset)),
        "covered_offset": str(_jamf_offset(covered_offset)),
    }
    try:
        gap_data = _jamf_bucket_page(request.state.jwt, "gap", int(offsets["gap_offset"]))
        nr_data = _jamf_bucket_page(
            request.state.jwt, "not_reported_by_jamf", int(offsets["not_reported_offset"]))
        cov_data = _jamf_bucket_page(request.state.jwt, "covered", int(offsets["covered_offset"]))
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)

    connector = _jamf_connector_view(gap_data.get("connector") or {})
    basis = gap_data.get("basis") or {}
    counts = gap_data.get("counts") or {}

    gap_view = _jamf_bucket_view(
        gap_data, "gap", int(offsets["gap_offset"]), "gap_offset", offsets)
    for row in gap_view["rows"]:
        row["jamf_state_label"] = JAMF_STATE_LABELS.get(row.get("jamf_state"), "Enrolled")
    nr_view = _jamf_bucket_view(
        nr_data, "not_reported_by_jamf", int(offsets["not_reported_offset"]),
        "not_reported_offset", offsets)
    for row in nr_view["rows"]:
        row["mdm"] = _jamf_mdm_state_view(row.get("mdm_state"))
    cov_view = _jamf_bucket_view(
        cov_data, "covered", int(offsets["covered_offset"]), "covered_offset", offsets)

    can_edit, role_unavailable = False, False
    try:
        can_edit = _portal_role(request.state.jwt) == "admin"
    except upstream.UpstreamError as exc:
        logger.warning("portal.devices_jamf.role_fail_soft kind=%s", exc.kind)
        role_unavailable = True

    return _render(request, "devices_jamf.html", {
        "title": "Jamf coverage", "nav": "devices",
        "connector": connector, "basis": basis, "counts": counts,
        "not_reported_by_mdm_state": counts.get("not_reported_by_jamf_by_mdm_state") or {},
        "gap": gap_view, "not_reported": nr_view, "covered": cov_view,
        "can_edit": can_edit, "role_unavailable": role_unavailable,
        "jamf_result": _jamf_flash_view(_read_flash(
            request.state.jwt, request.query_params.get(JAMF_RESULT_PARAM, ""))),
    })


@app.get("/devices/jamf/setup", response_class=HTMLResponse)
def devices_jamf_setup(request: Request):
    """PAT-2145: the webhook URL, whether a token exists and when it was
    last rotated, the exact events to tick in Jamf Pro, how to configure
    auth, the check-in toggle and the destructive actions (revoke, purge,
    reset pinned instance). Every portal role reads; the write forms below
    render only for can_edit, checked again server-side on every write."""
    try:
        setup = upstream.get_json("/v1/portal/mdm/jamf/setup", request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    connector, connector_unavailable = None, False
    try:
        coverage = _jamf_bucket_page(request.state.jwt, "gap", 0)
        connector = _jamf_connector_view(coverage.get("connector") or {})
    except upstream.UpstreamError as exc:
        logger.warning("portal.devices_jamf_setup.connector_fail_soft kind=%s", exc.kind)
        connector_unavailable = True
    can_edit, role_unavailable = False, False
    try:
        can_edit = _portal_role(request.state.jwt) == "admin"
    except upstream.UpstreamError as exc:
        logger.warning("portal.devices_jamf_setup.role_fail_soft kind=%s", exc.kind)
        role_unavailable = True
    return _render(request, "devices_jamf_setup.html", {
        "title": "Jamf setup", "nav": "devices",
        "setup": setup if isinstance(setup, dict) else {}, "token_reveal": None,
        "connector": connector, "connector_unavailable": connector_unavailable,
        "can_edit": can_edit, "role_unavailable": role_unavailable,
        "jamf_result": _jamf_flash_view(_read_flash(
            request.state.jwt, request.query_params.get(JAMF_RESULT_PARAM, ""))),
    })


JAMF_COVERAGE_BUCKET_LABELS = {
    "gap": "Managed by Jamf, not seen by Patched",
    "not_reported_by_jamf": "Seen by Patched, not reported by Jamf",
    "covered": "Both",
}


def _jamf_coverage_csv_spec(request: Request) -> _ProxiedCsv:
    bucket = request.query_params.get("bucket", "")
    params: dict[str, str] = {}
    if bucket in JAMF_COVERAGE_BUCKET_LABELS:
        params["bucket"] = bucket
    return _ProxiedCsv(
        "jamf-coverage", "/v1/portal/mdm/jamf/coverage", params,
        "patched-jamf-coverage.csv",
        _filter_pairs(params, {"bucket": ("Show", JAMF_COVERAGE_BUCKET_LABELS)}))


@app.get("/devices/jamf/coverage.csv")
def devices_jamf_coverage_csv(request: Request):
    """Proxies the platform's own unpaged CSV (contracts/portal-api.md:
    every row, formula-injection-safe cells already applied upstream, the
    basis statement on every row) rather than re-serialising it portal-side.
    ?bucket= restricts it exactly like the page's own per-table CSV links."""
    return _proxied_csv_response(request, _jamf_coverage_csv_spec(request))


@app.get("/devices/jamf/coverage.pdf")
def devices_jamf_coverage_pdf(request: Request):
    """PAT-2405: the same rows as the CSV above, as a PDF."""
    return _proxied_csv_pdf_response(request, _jamf_coverage_csv_spec(request))


# ── Finding verification lifecycle (PAT-1879, reading PAT-1969's contract) ─
# GET /v1/portal/finding-lifecycle[/history] are tenant-scoped current-state
# and immutable-event-history reads over the same finding identity as
# compliance signals (finding_kind="cis") and CVE findings
# (finding_kind="cve"). Bounded to LIFECYCLE_FETCH_LIMIT rows per call - an
# open-finding count for one kind is small relative to that, matching the
# bounded-fetch convention other secondary reads on these pages already use
# (protected-software, the CIS summary rollup on /findings).
LIFECYCLE_FETCH_LIMIT = 500

# event_type / status -> (label, pill class). Every value the platform's
# finding_lifecycle_events.event_type CHECK constraint allows (migration
# 0156, widened by 0191 for `withdrawn`) must have an entry here so no
# lifecycle state falls through to a
# generic default. first_observed/currently_observed/still_failing/recurred
# read as active problems (pill-bad); acknowledged/risk_accepted/
# verification_unknown are neutral operator or non-authoritative states
# (pill-muted); guidance_issued/customer_applied/pending_verification are
# in-progress but explicitly not a pass yet (pill-warn, so pending
# verification never reads the same as a verified fix); verified_fixed is
# the only pill-ok status, and only when the current row is authoritative -
# see _lifecycle_pill_class below for the non-authoritative downgrade.
LIFECYCLE_STATUS_META = {
    "first_observed": ("First observed", "pill-bad"),
    "currently_observed": ("Currently observed", "pill-bad"),
    "acknowledged": ("Acknowledged", "pill-muted"),
    "risk_accepted": ("Risk accepted", "pill-muted"),
    "guidance_issued": ("Guidance issued", "pill-warn"),
    "customer_applied": ("Customer applied a fix", "pill-warn"),
    "pending_verification": ("Pending verification", "pill-warn"),
    "verification_unknown": ("Verification unknown", "pill-muted"),
    "verified_fixed": ("Verified fixed", "pill-ok"),
    "still_failing": ("Still failing", "pill-bad"),
    "recurred": ("Recurred", "pill-bad"),
    # PAT-2107: the matcher stopped producing this finding while the device
    # still reports the same software at the same version. A correction on
    # Patched's side, never a fix, so it must not read like verified_fixed.
    "withdrawn": ("Withdrawn: matcher correction, not a fix", "pill-muted"),
}

LIFECYCLE_SOURCE_LABEL = {
    "endpoint_observation": "Endpoint observation",
    "operator_action": "Operator action",
    "migration": "Migrated record",
    "matcher": "CVE matcher correction",
}


def _lifecycle_status_label(status: str) -> str:
    meta = LIFECYCLE_STATUS_META.get(status)
    if meta:
        return meta[0]
    return status.replace("_", " ").capitalize() if status else "Unknown"


def _lifecycle_pill_class(status: str, authoritative: bool) -> str:
    meta = LIFECYCLE_STATUS_META.get(status)
    if meta is None:
        return "pill-muted"
    # PAT-1879: stale or partial evidence must never present as a clean
    # verification. The wire contract's status_authoritative/authoritative
    # fields are the gate - render off the value the platform sent, not off
    # an assumption about which combinations are reachable today, so this
    # stays correct if the platform's evidence model ever admits a
    # non-authoritative verified_fixed row.
    if status == "verified_fixed" and not authoritative:
        return "pill-warn"
    return meta[1]


def _lifecycle_event_view(event: dict) -> dict:
    status = event.get("event_type", "")
    actor = (event.get("actor") or "").strip()
    source_type = event.get("source_type", "")
    view = dict(event)
    view["status_label"] = _lifecycle_status_label(status)
    view["pill_class"] = _lifecycle_pill_class(status, bool(event.get("authoritative")))
    view["actor_label"] = actor or LIFECYCLE_SOURCE_LABEL.get(source_type, "Unknown source")
    return view


def _lifecycle_entry(current_row: dict, events: list) -> dict:
    """Combine one finding-lifecycle current row with its full event history
    into what the templates render. Events are newest-first so the most
    recent state reads at the top of the expandable timeline; the immutable
    history itself (oldest to newest, as the platform returns it) is never
    discarded - still_failing and recurred rows carry every earlier event
    exactly as guidance_issued or acknowledged rows do."""
    status = current_row.get("status", "")
    authoritative = bool(current_row.get("status_authoritative"))
    event_views = [
        _lifecycle_event_view(e)
        for e in sorted(events, key=lambda e: e.get("id", 0), reverse=True)
    ]
    closing_event = None
    if status == "verified_fixed":
        closing_event = next(
            (e for e in event_views if e.get("event_type") == "verified_fixed"), None
        )
    entry = dict(current_row)
    entry["status_label"] = _lifecycle_status_label(status)
    entry["pill_class"] = _lifecycle_pill_class(status, authoritative)
    entry["pill_title"] = (
        "This verification could not be confirmed as authoritative evidence."
        if status == "verified_fixed" and not authoritative else None
    )
    entry["events"] = event_views
    entry["closing_event"] = closing_event
    return entry


def _lifecycle_index(current_rows: list, history_rows: list) -> dict:
    events_by_key: dict[str, list] = {}
    for event in history_rows:
        events_by_key.setdefault(event.get("finding_key"), []).append(event)
    return {
        row.get("finding_key"): _lifecycle_entry(row, events_by_key.get(row.get("finding_key"), []))
        for row in current_rows
    }


def _fetch_lifecycle_index(
    jwt_token: str, *, finding_kind: str, device_id: str | None = None
) -> dict:
    """Fetch both PAT-1969 finding-lifecycle endpoints for one finding_kind
    and return finding_key -> render-ready lifecycle dict. Raises
    upstream.UpstreamError exactly like every other portal read - callers
    fold it into their existing try/except UpstreamError -> _error_page
    block rather than failing soft, because the lifecycle state is why the
    caller is fetching this data, not an optional enhancement to it."""
    params = {"finding_kind": finding_kind, "limit": LIFECYCLE_FETCH_LIMIT}
    if device_id:
        params["device_id"] = device_id
    current_data = upstream.get_json("/v1/portal/finding-lifecycle", jwt_token, params=params)
    current_rows = upstream.unwrap_list(current_data, "findings")
    history_data = upstream.get_json(
        "/v1/portal/finding-lifecycle/history", jwt_token, params=params
    )
    history_rows = upstream.unwrap_list(history_data, "events")
    return _lifecycle_index(current_rows, history_rows)


# PAT-2141 follow-up (Andy's live feedback, 25 Sept 2026): "Top of the page
# should show how many CVEs and Issues there are on the machine and when
# clicked, move down to the CVE / CIS section." Both tiles reuse data the
# page already fetches and renders elsewhere - neither is a second,
# independently computed count - and absence stays explicit per root
# AGENTS.md ("absence requires authority"): pending/not-yet-assessed CVE
# state and missing/stale compliance evidence read as words, never a
# fabricated 0.
COUNT_STRIP_TONE_MUTE = "mute-text"
COUNT_STRIP_TONE_WARN = "warn-text"
COUNT_STRIP_TONE_BAD = "bad-text"
COUNT_STRIP_TONE_GRAPHITE = "graphite-text"


def _worst_severity_rank(items: list, severity_key: str):
    """The lowest (worst) SEVERITY_ORDER rank across a list of dicts, or
    None if none of them carry a recognised severity. Shared by both count
    strip tiles below so their tone logic stays identical in shape."""
    worst_rank = None
    for item in items:
        sev = item.get(severity_key)
        sev = sev.lower() if isinstance(sev, str) else None
        rank = SEVERITY_ORDER.get(sev)
        if rank is not None and (worst_rank is None or rank < worst_rank):
            worst_rank = rank
    return worst_rank


def _severity_rank_tone(worst_rank) -> str:
    """critical/high -> bad-text, medium -> warn-text, low -> mute-text; no
    recognised severity at all on a nonzero count is a contract gap, not an
    empty result, so it stays bad-text rather than downplaying an
    unexplained finding to muted."""
    if worst_rank in (SEVERITY_ORDER["critical"], SEVERITY_ORDER["high"]):
        return COUNT_STRIP_TONE_BAD
    if worst_rank == SEVERITY_ORDER["medium"]:
        return COUNT_STRIP_TONE_WARN
    if worst_rank == SEVERITY_ORDER["low"]:
        return COUNT_STRIP_TONE_MUTE
    return COUNT_STRIP_TONE_BAD


def _device_cve_tile_view(cve_assessment: dict, apps: list, device_is_stale) -> dict:
    """CVE count strip tile. Reuses the exact `cve_assessment` state/
    finding_count the CVE assessment card already renders (_cve_assessment_view
    above) - not a second count. `state` "pending"/"not_assessed" read as
    words, matching the CVE assessment card's own "Checking"/"Not yet
    assessed" pills, never a 0 that would misread as a clean device.

    The tone (severity colour) comes from apps_with_findings' own per-app
    `max_severity` - the same figure the "Applications with open findings"
    table already shows for each row - since no per-CVE severity exists
    anywhere in this data.

    `stale` (Andy's follow-up ruling, 25 Sept 2026: hiding a known count
    under a stale-evidence word is worse than showing it with a caveat) is
    the same device-wide `is_stale` the Summary assurance pills already key
    off. It never replaces a real count - the CVE assessment figure is
    already dated (`last_matched_at`) and stays authoritative even when the
    device itself hasn't reported recently - it only adds a caveat sub-line
    the template renders under the number. It is never set on the
    "Checking"/"Not assessed" words, which already carry their own
    uncertainty.
    """
    state = cve_assessment.get("state")
    if state == "pending":
        return {"value": "Checking", "tone": COUNT_STRIP_TONE_MUTE,
                "is_count": False, "stale": False}
    if state != "assessed":
        return {"value": "Not assessed", "tone": COUNT_STRIP_TONE_GRAPHITE,
                "is_count": False, "stale": False}
    count = cve_assessment.get("finding_count") or 0
    stale = bool(device_is_stale)
    if count == 0:
        return {"value": 0, "tone": COUNT_STRIP_TONE_MUTE, "is_count": True, "stale": stale}
    worst_rank = _worst_severity_rank(apps, "max_severity")
    tone = _severity_rank_tone(worst_rank)
    return {"value": count, "tone": tone, "is_count": True, "stale": stale}


# PAT-2256: the one definition of a "failing check" for the device page. The
# platform's roster counts a device's fail and error results as findings_open
# (contracts/portal-api.md), so the device page must too: a not_applicable
# result is a control that does not apply to this device, not a failure. The
# page counted every result that was not a pass (58 on a Mac whose list row
# said 35). Anything else outside the platform's four-value vocabulary still
# counts as open, so an unrecognised status can never hide a problem.
#
# PAT-2294: this is now only the fallback. The platform returns findings_open
# on the device response too, computed by the same code as the roster row, and
# the tile prefers it (_platform_findings_open); counting the signals here
# remains for an older platform or a stub that does not send it. The one
# thing the signals cannot see is the platform's exclusion of a failing
# result with no observed value (unreadable evidence), which is why the
# signal count could exceed the list's figure by that many.
CIS_NOT_FAILING_STATUSES = ("pass", "compliant", "ok", "not_applicable")


def _signal_undetermined(signal) -> bool:
    """True only when the platform sent `undetermined` as a JSON true on this
    rule result: its `status` is `fail` only because the value could not be
    read, so nothing was observed to fail. The Compliance tab shows such a row
    as "Not assessed" (templates/device_compliance.html tests the same JSON
    true), matching the Devices roster and the device page for that device,
    and no failing count includes it. A missing field (an older platform), a
    string, a number or null is not a true, so that row keeps its plain
    status."""
    return isinstance(signal, dict) and signal.get("undetermined") is True


def _platform_findings_open(device) -> int | None:
    """`findings_open` from the device response when the platform sent a real
    count, otherwise None. Only a non-negative integer counts: a bool is an
    int subclass in Python, so `type(...) is int` keeps a stray JSON
    true/false from reading as 1/0, and a string, float, list or object (an
    older or malformed build) is not a count at all and falls back to the
    signals."""
    value = device.get("findings_open") if isinstance(device, dict) else None
    return value if type(value) is int and value >= 0 else None


def _device_issues_tile_view(signals: list, device_is_stale,
                             platform_findings_open: int | None = None) -> dict:
    """Failing checks count strip tile - failing/recurred CIS controls.

    PAT-2294: the number is the platform's own `findings_open` for the device
    (`platform_findings_open`, see _platform_findings_open) whenever the
    response carries one, so this tile, the Compliance tab count and the
    Devices list read one figure computed by one piece of code. When the
    platform did not send it, the number is counted from the exact `signals`
    list the Compliance signals table below renders (CIS_NOT_FAILING_STATUSES
    above is the one rule for what is not open, shared with that table's pill
    colouring). Either way the tone comes from the open signals' own
    `severity` field, the same per-row severity pill the Compliance signals
    table already shows, mirroring the CVE tile's own severity-tiered tone:
    the platform sends a count, not a severity, so the signals still decide
    the colour. A rule the platform marks `undetermined` (_signal_undetermined)
    is not open in either respect: the table reads "Not assessed" for it, so
    it is left out of the fallback count and out of the tone. A platform
    count with no open signal to explain it stays in the contract-gap tone
    rather than muted (_severity_rank_tone), and a platform zero is a muted
    zero.

    Andy's follow-up ruling, 25 Sept 2026: showing "Stale" in place of the
    count hid a real, currently-visible failure (cis-2.6 FAIL/recurred)
    behind a word, while the CVE tile beside it kept its number for the
    same stale device - inconsistent, and it hides a known failure. A stale
    device now still shows its real failing-control count; staleness is
    only a caveat sub-line the template renders under the number (`stale`),
    never a replacement for it. No signals recorded at all is a genuinely
    different case (nothing to count, not evidence gone stale) and still
    reads "Not available", never a bare 0.
    """
    # PAT-2496: a rule whose value could not be read is "Not assessed", not a
    # failing check, so it is neither counted nor allowed to set the tone.
    open_signals = [
        s for s in signals
        if str(s.get("status") or "").lower() not in CIS_NOT_FAILING_STATUSES
        and not _signal_undetermined(s)
    ]
    count = len(open_signals) if platform_findings_open is None else platform_findings_open
    if not signals and count == 0:
        # Nothing evaluated is not a clean device, whichever side counted it.
        return {"value": "Not available", "tone": COUNT_STRIP_TONE_MUTE,
                "is_count": False, "stale": False}
    stale = bool(device_is_stale)
    if count == 0:
        return {"value": 0, "tone": COUNT_STRIP_TONE_MUTE, "is_count": True, "stale": stale}
    worst_rank = _worst_severity_rank(open_signals, "severity")
    tone = _severity_rank_tone(worst_rank)
    return {"value": count, "tone": tone, "is_count": True, "stale": stale}


# ── PAT-2164: device page tabs (Overview/Hardware/Software/Vulnerabilities/
# Compliance/Evidence) ─────────────────────────────────────────────────────
# Supersedes the single long scroll PAT-2141 built. Every tab route below
# shares one upstream fetch (_device_base_context) and one page head
# (templates/_macros.html's device_page_head, the count strip + tab bar),
# so the head can never diverge between tabs; each route then only computes
# the extra, section-specific piece its own tab needs on top of that shared
# fetch (Compliance's CIS lifecycle index, Vulnerabilities' cve_products) -
# "only render what a tab needs, where the code allows cheaply" per the
# ticket - rather than every route paying for every section's own cost.
DEVICE_TAB_ROUTE = {
    "overview": "",
    "hardware": "/hardware",
    "software": "/software",
    "vulnerabilities": "/vulnerabilities",
    "compliance": "/compliance",
    "evidence": "/evidence",
}


def _device_base_context(request: Request, device_id: str, stale_days: str = "") -> dict:
    """The one upstream call (`GET /v1/portal/devices/{id}`) every device tab
    route shares, plus every transform that costs nothing extra to compute
    from it (no further HTTP call): device/evidence/identity/hardware,
    sorted compliance signals, apps with findings, the cve_assessment view,
    collection issues, and the two count-strip tiles. Raises
    upstream.UpstreamError on failure - every caller catches it itself,
    since the Software tab's not-found page reads differently from every
    other tab's (see _device_software_not_found) and must stay that way.
    """
    data = upstream.get_json(f"/v1/portal/devices/{quote(device_id, safe='')}",
                             request.state.jwt)
    signals = upstream.unwrap_list(data, "compliance_signals")
    apps = upstream.unwrap_list(data, "apps_with_findings")
    source_device = data.get("device") if isinstance(data.get("device"), dict) else data
    device = dict(source_device) if isinstance(source_device, dict) else {}
    # Detail shares the selected roster boundary when it was opened from a
    # stale view. A historical pass or fail must not become current merely
    # because the caller opened the device directly.
    annotate_device_staleness(device, normalise_stale_days(stale_days))
    evidence = normalise_device_evidence(device.get("evidence"), device_id)
    # PAT-2141: identity/hardware are additive, top-level siblings of
    # `device` on this response (contracts/portal-api.md), and may be
    # absent entirely from an older platform build - normalise_identity/
    # normalise_hardware both fail soft on that, never raising and never
    # rendering a zero or blank in the block's place.
    device_identity = normalise_identity(data.get("identity"))
    hardware = normalise_hardware(data.get("hardware"))
    # PAT-2262: additive, same top-level response - see normalise_firmware's
    # docstring for the absent-vs-not_reported distinction, which fails soft
    # on an older platform build exactly like identity/hardware above do.
    firmware = normalise_firmware(data.get("firmware"))
    # PAT-2263: additive, same top-level response - see
    # normalise_kernel_drivers's docstring for the absent-vs-not_reported
    # fail-soft, matching identity/hardware/firmware above.
    kernel_drivers = normalise_kernel_drivers(data.get("kernel_drivers"), device.get("platform"))
    # PAT-2135: additive, rides on this same response - see _retirement_view.
    device["retirement_view"] = _retirement_view(device.get("retirement"))
    signals = sorted(signals, key=lambda s: SEVERITY_ORDER.get(
        str(s.get("severity", "")).lower(), 9))
    raw_cve_assessment = (
        data.get("cve_assessment") if isinstance(data.get("cve_assessment"), dict) else {}
    )
    cve_assessment = _cve_assessment_view(raw_cve_assessment)
    degraded_health = _agent_health_degraded_view(data.get("agent_health_degraded"))
    cve_tile = _device_cve_tile_view(cve_assessment, apps, device.get("is_stale"))
    # PAT-2294: findings_open / encryption_ok / patch_pending are device-level
    # fields the platform computes with the roster's own code; the tile takes
    # findings_open from it, Summary reads the other two off `device`.
    issues_tile = _device_issues_tile_view(
        signals, device.get("is_stale"), _platform_findings_open(device))
    return {
        "device": device, "signals": signals, "apps": apps, "evidence": evidence,
        "device_identity": device_identity, "hardware": hardware, "firmware": firmware,
        "kernel_drivers": kernel_drivers,
        "raw_cve_assessment": raw_cve_assessment, "cve_assessment": cve_assessment,
        "degraded_health": degraded_health, "cve_tile": cve_tile, "issues_tile": issues_tile,
    }


def _device_cve_products(apps: list, raw_cve_assessment: dict) -> list:
    """Vulnerabilities-tab-only: joins each assessed product with a finding
    to the severity `apps_with_findings` already carries for it, exactly as
    the pre-PAT-2164 single page did - no extra HTTP call, just the same
    Python join, now only run for the one tab that renders it."""
    severity_by_app = {}
    for a in apps:
        name = a.get("app")
        if isinstance(name, str) and name and isinstance(a.get("max_severity"), str):
            severity_by_app.setdefault(name, a["max_severity"].lower())
    raw_products = raw_cve_assessment.get("products")
    cve_products = []
    for raw_product in raw_products if isinstance(raw_products, list) else []:
        product_view = _cve_assessment_product_view(raw_product)
        if product_view["finding_count"]:
            severity = severity_by_app.get(product_view["app"])
            if severity in SEVERITY_ORDER:
                plural = "" if product_view["finding_count"] == 1 else "s"
                product_view["pill_class"] = f"pill-{severity}"
                product_view["display_label"] = (
                    f"{product_view['finding_count']} CVE{plural} ({severity.capitalize()})"
                )
        cve_products.append(product_view)
    return cve_products


def _device_software_tile_totals(request: Request, device_id: str) -> tuple[int | None, int | None]:
    """Cheap, fail-soft (apps_total, ext_total) pair for the page head's
    Software N tile on every tab EXCEPT Software itself (which already has
    both totals from its own full fetch - see device_software below, which
    passes them straight to _device_tab_definitions instead of calling this
    again). The applications call passes limit=1 (the total rides on the
    envelope regardless of how many rows are returned); extensions has no
    pagination on the platform at all (contracts/portal-api.md, PAT-1799
    note), so there is no cheaper form of that one. Each fails independently
    and soft - an outage here must never fail a tab whose own section does
    not touch software data at all - and absence requires authority (root
    AGENTS.md): a total that could not be read stays None (no number shown),
    never a 0.
    """
    apps_total = None
    try:
        apps_data = upstream.get_json(
            "/v1/portal/software", request.state.jwt,
            params={"device_id": device_id, "limit": 1, "offset": 0, "search": ""},
        )
        _products, apps_total, _limit, _offset, _coverage, _generated = (
            _software_inventory_envelope(apps_data)
        )
    except upstream.UpstreamError as exc:
        logger.warning("portal.device_tabs.software_total_fail_soft kind=%s", exc.kind)

    ext_total = None
    try:
        ext_data = upstream.get_json(
            "/v1/portal/extensions", request.state.jwt, params={"device_id": device_id})
        ext_rows = upstream.unwrap_list(ext_data, "extensions")
        ext_total = max(_pagination_integer(ext_data, "total"), len(ext_rows))
    except upstream.UpstreamError as exc:
        logger.warning("portal.device_tabs.extensions_total_fail_soft kind=%s", exc.kind)

    return apps_total, ext_total


def _device_tab_definitions(
    device_id: str, active_tab: str, cve_tile: dict, issues_tile: dict,
    software_totals: tuple,
) -> list[dict]:
    """The six device tabs, in order, each carrying its own URL and - where
    meaningful - a count. An unknown count (a tile that isn't currently a
    real number, e.g. "Checking"/"Not assessed"/"Not available", or a
    software total that could not be read) shows no number at all, never a
    0 (root AGENTS.md: absence requires authority)."""
    encoded_id = quote(device_id, safe="")
    base = f"/devices/{encoded_id}"
    apps_total, ext_total = software_totals
    software_total = (
        apps_total + ext_total if apps_total is not None and ext_total is not None else None
    )
    vuln_count = str(cve_tile["value"]) if cve_tile.get("is_count") else None
    compliance_count = f"{issues_tile['value']} failing" if issues_tile.get("is_count") else None
    definitions = (
        ("overview", "Overview", None),
        ("hardware", "Hardware", None),
        ("software", "Software", str(software_total) if software_total is not None else None),
        ("vulnerabilities", "Vulnerabilities", vuln_count),
        ("compliance", "Compliance", compliance_count),
        ("evidence", "Evidence", None),
    )
    return [
        {
            "key": key, "label": label, "url": base + DEVICE_TAB_ROUTE[key],
            "count_display": count_display, "current": key == active_tab,
        }
        for key, label, count_display in definitions
    ]


@app.get("/devices/{device_id}", response_class=HTMLResponse)
def device_detail(request: Request, device_id: str, stale_days: str = ""):
    """Overview tab: the device's identity, the Summary assurance card and
    Collection issues (PAT-2164). Hardware, Software, Vulnerabilities,
    Compliance and Evidence all moved to their own tab routes below -
    nothing here needs the CIS lifecycle fetch or the CVE product join,
    since neither Compliance signals nor the CVE assessment card render on
    this tab any more."""
    try:
        base = _device_base_context(request, device_id, stale_days)
        software_totals = _device_software_tile_totals(request, device_id)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    tabs = _device_tab_definitions(
        device_id, "overview", base["cve_tile"], base["issues_tile"], software_totals)

    # PAT-2135: retire/unretire lives on this tab only (the Device card),
    # not repeated across every tab route - can_edit and the history read
    # are both extra calls only this route pays for.
    can_edit, role_unavailable = False, False
    try:
        can_edit = _portal_role(request.state.jwt) == "admin"
    except upstream.UpstreamError as exc:
        logger.warning("portal.device_detail.role_fail_soft kind=%s", exc.kind)
        role_unavailable = True
    retirement_history = _retirement_history_view(request.state.jwt, device_id)

    return _render(request, "device_detail.html", {
        "title": base["device"].get("hostname") or "Device",
        "nav": "devices",
        "device": base["device"], "device_identity": base["device_identity"],
        "degraded_health": base["degraded_health"],
        "cve_tile": base["cve_tile"], "issues_tile": base["issues_tile"], "tabs": tabs,
        "can_edit": can_edit, "role_unavailable": role_unavailable,
        "retirement_history": retirement_history,
        "return_to": f"/devices/{quote(device_id, safe='')}",
        "device_result": _device_flash_view(_read_flash(
            request.state.jwt, request.query_params.get(DEVICE_RESULT_PARAM, ""))),
    })


@app.get("/devices/{device_id}/hardware", response_class=HTMLResponse)
def device_hardware(request: Request, device_id: str, stale_days: str = ""):
    """Hardware tab: the Hardware card as-is, including the macOS
    system-volumes disclosure (PAT-2164)."""
    try:
        base = _device_base_context(request, device_id, stale_days)
        software_totals = _device_software_tile_totals(request, device_id)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    tabs = _device_tab_definitions(
        device_id, "hardware", base["cve_tile"], base["issues_tile"], software_totals)

    return _render(request, "device_hardware.html", {
        "title": base["device"].get("hostname") or "Device",
        "nav": "devices",
        "device": base["device"], "hardware": base["hardware"], "firmware": base["firmware"],
        "cve_tile": base["cve_tile"], "issues_tile": base["issues_tile"], "tabs": tabs,
    })


@app.get("/devices/{device_id}/vulnerabilities", response_class=HTMLResponse)
def device_vulnerabilities(request: Request, device_id: str, stale_days: str = ""):
    """Vulnerabilities tab: Applications with open findings, then CVE
    assessment (PAT-2164) - the same cve_products join the pre-tab page
    always did, just computed only for this one tab now."""
    try:
        base = _device_base_context(request, device_id, stale_days)
        software_totals = _device_software_tile_totals(request, device_id)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    cve_products = _device_cve_products(base["apps"], base["raw_cve_assessment"])
    tabs = _device_tab_definitions(
        device_id, "vulnerabilities", base["cve_tile"], base["issues_tile"], software_totals)

    return _render(request, "device_vulnerabilities.html", {
        "title": base["device"].get("hostname") or "Device",
        "nav": "devices",
        "device": base["device"], "apps": base["apps"],
        "cve_assessment": base["cve_assessment"], "cve_products": cve_products,
        "cve_tile": base["cve_tile"], "issues_tile": base["issues_tile"], "tabs": tabs,
    })


@app.get("/devices/{device_id}/compliance", response_class=HTMLResponse)
def device_compliance(request: Request, device_id: str, stale_days: str = ""):
    """Compliance tab: Compliance signals (PAT-2164), with the CIS
    finding-verification lifecycle (PAT-1879) joined in - fetched only for
    this tab, since no other tab renders a signal's lifecycle cell."""
    try:
        base = _device_base_context(request, device_id, stale_days)
        software_totals = _device_software_tile_totals(request, device_id)
        lifecycle = _fetch_lifecycle_index(
            request.state.jwt, finding_kind="cis", device_id=device_id,
        )
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    signals = base["signals"]
    for s in signals:
        s["lifecycle"] = lifecycle.get(s.get("rule_id"))
    tabs = _device_tab_definitions(
        device_id, "compliance", base["cve_tile"], base["issues_tile"], software_totals)

    return _render(request, "device_compliance.html", {
        "title": base["device"].get("hostname") or "Device",
        "nav": "devices",
        "device": base["device"], "signals": signals,
        "kernel_drivers": base["kernel_drivers"],
        "cve_tile": base["cve_tile"], "issues_tile": base["issues_tile"], "tabs": tabs,
    })


@app.get("/devices/{device_id}/evidence", response_class=HTMLResponse)
def device_evidence(request: Request, device_id: str, stale_days: str = ""):
    """Evidence tab: evidence collection facts and chips, plus the
    collection-issues detail (PAT-2164) - the same degraded_health table the
    Overview tab shows, since it is as relevant to "what evidence do we
    have" here as it is to the device's landing tab."""
    try:
        base = _device_base_context(request, device_id, stale_days)
        software_totals = _device_software_tile_totals(request, device_id)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    tabs = _device_tab_definitions(
        device_id, "evidence", base["cve_tile"], base["issues_tile"], software_totals)

    return _render(request, "device_evidence.html", {
        "title": base["device"].get("hostname") or "Device",
        "nav": "devices",
        "device": base["device"], "evidence": base["evidence"],
        "degraded_health": base["degraded_health"],
        "cve_tile": base["cve_tile"], "issues_tile": base["issues_tile"], "tabs": tabs,
    })


FINDINGS_PAGE_SIZE = 50
# The platform caps /v1/portal/driver-findings at 500 rows per request.
DRIVER_FINDINGS_LIMIT = 500

# PAT-2043: source and install-reason display for Homebrew CVE findings
# (contracts/portal-api.md "source, confidence_tier, install_reasons
# (PAT-2023)"). Only `homebrew_formula` and `homebrew_cask` are documented -
# an unrecognised value degrades to no label rather than a guess.
HOMEBREW_SOURCE_LABEL = {
    "homebrew_formula": "Homebrew formula",
    "homebrew_cask": "Homebrew cask",
}
HOMEBREW_INSTALL_REASON_LABEL = {
    "on_request": "installed on request",
    "dependency": "installed as a dependency",
}


def _homebrew_finding_view(f: dict) -> None:
    """Annotate one /v1/portal/findings row with Homebrew display fields, in
    place. Degrades to nothing when the platform is older than PAT-2023 and
    never sends `source` - no crash, just no Homebrew labels.

    Confidence for a Homebrew row is `confidence_tier` (high/low), a
    separate field from the CVE-match `match_confidence` other software
    uses (contracts/portal-api.md line ~627) - reusing match_confidence for
    a Homebrew row would show a value that was never computed for it. Reuse
    the existing PAT-1586/PAT-1842 confidence badge wording rather than
    inventing new copy: high maps to the same "Confirmed" presentation as
    version_confirmed, low to the same "Possible" presentation as
    version_unverified - a low tier is a live "version not verifiable"
    signal, never presented as a confirmed vulnerability.
    """
    source = f.get("source")
    f["homebrew_source_label"] = HOMEBREW_SOURCE_LABEL.get(source)
    if f["homebrew_source_label"] is None:
        f["confidence_key"] = f.get("match_confidence")
        f["homebrew_install_reason_label"] = None
        return

    tier = f.get("confidence_tier")
    f["confidence_key"] = {
        "high": "version_confirmed",
        "low": "version_unverified",
    }.get(tier)

    reasons = f.get("install_reasons") or []
    labels = [
        HOMEBREW_INSTALL_REASON_LABEL[r] for r in ("on_request", "dependency") if r in reasons
    ]
    f["homebrew_install_reason_label"] = " / ".join(labels) or None


def _parse_page(raw) -> int:
    """Clamp an arbitrary `?page=` value to a sane 1-based page number.
    Never trusted as an offset directly - non-numeric or <1 quietly falls
    back to page 1 instead of erroring."""
    try:
        page = int(raw)
    except (TypeError, ValueError):
        return 1
    return page if page >= 1 else 1


def _driver_finding_row_view(raw) -> dict:
    """One row of GET /v1/portal/driver-findings (PAT-2263) - an estate-wide
    match, one per (device, driver), always a listed match (the endpoint
    itself only ever returns matched drivers - "no reported hash is on
    either list as fetched", never an unmatched row), so unlike the device
    page's own matches list there is no unknown/clean state to resolve
    here."""
    raw = raw if isinstance(raw, dict) else {}
    loaded = raw.get("loaded")
    blocklist_enforced = raw.get("blocklist_enforced")
    hash_view = _truncate_hash(raw.get("sha256"))
    # A finding can carry more than one match (the same hash listed on both
    # Microsoft's list and loldrivers.io); the estate table renders one row
    # per finding, not per match, so templates/findings.html reads only the
    # first match's list provenance (version/fetched/stale) for its List
    # version/Fetched columns - category and blocklist_enforced are already
    # top-level fields on the finding itself (contracts/portal-api.md), not
    # per-match, so they lose nothing by that simplification.
    matches_raw = raw.get("matches")
    matches = [
        _driver_match_view(m) for m in matches_raw if isinstance(m, dict)
    ] if isinstance(matches_raw, list) else []
    category = raw.get("category") if raw.get("category") in ("vulnerable", "malicious") else None
    return {
        "device_id": _text(raw, "device_id"),
        "hostname": _text(raw, "hostname") or "Unknown device",
        "path": _text(raw, "path"),
        "service_name": _text(raw, "service_name"),
        "start_type": _text(raw, "start_type"),
        "loaded": loaded if isinstance(loaded, bool) else None,
        "loaded_label": (
            "Present and not blocked by Windows" if loaded is True
            else "Present, blocked by Windows" if loaded is False
            else "Unknown"
        ),
        "version": _text(raw, "version"),
        "hash_full": hash_view["full"], "hash_truncated": hash_view["truncated"],
        "reported_at": _text(raw, "reported_at"),
        "first_seen_at": _text(raw, "first_seen_at"),
        "category": category,
        "blocklist_enforced": blocklist_enforced,
        "blocklist_enforced_label": BLOCKLIST_ENFORCED_LABEL.get(blocklist_enforced, "unknown"),
        # Ticket ruling (PAT-2263): a match on a device where the blocklist
        # is not enforced is shown as critical - a known-vulnerable or
        # malicious driver with nothing stopping it loading.
        "critical": blocklist_enforced == "no",
        "matches": matches,
    }


def _driver_findings_view(data) -> dict:
    """Presentation-safe view of GET /v1/portal/driver-findings (PAT-2263,
    contracts/portal-api.md). Fetched fail-soft by the Findings page (see
    findings() below) exactly like the CIS summary rollup already is -
    this is secondary, additive content and an outage here must never take
    down the CVE findings table this page already serves reliably."""
    data = data if isinstance(data, dict) else {}
    rows_raw = upstream.unwrap_list(data, "findings")
    rows = [_driver_finding_row_view(r) for r in rows_raw if isinstance(r, dict)]
    lists_raw = data.get("lists")
    lists = (
        [_driver_list_view(row) for row in lists_raw if isinstance(row, dict)]
        if isinstance(lists_raw, list) else []
    )
    summary_raw = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    enforced_raw = (
        summary_raw.get("blocklist_enforced")
        if isinstance(summary_raw.get("blocklist_enforced"), dict) else {}
    )
    summary = {
        k: _num(summary_raw.get(k)) or 0
        for k in ("devices_reporting", "devices_unavailable", "devices_with_listed_drivers",
                   "devices_with_unhashed_drivers", "listed_drivers", "listed_malicious_drivers")
    }
    summary["blocklist_enforced"] = {
        k: _num(enforced_raw.get(k)) or 0 for k in ("yes", "no", "unknown")
    }
    total = _num(data.get("total"))
    return {
        "generated_at": _text(data, "generated_at"),
        "total": total if total is not None else len(rows),
        "rows": rows, "lists": lists, "summary": summary,
        "any_list_stale": any(row["stale"] for row in lists),
        "critical_count": sum(1 for r in rows if r["critical"]),
    }


@app.get("/findings", response_class=HTMLResponse)
def findings(request: Request, page: str = "1", driver_view: str = "all"):
    page_num = _parse_page(page)
    offset = (page_num - 1) * FINDINGS_PAGE_SIZE
    try:
        data = upstream.get_json(
            "/v1/portal/findings", request.state.jwt,
            params={"limit": FINDINGS_PAGE_SIZE, "offset": offset},
        )
        rows = upstream.unwrap_list(data, "findings")
        cve_lifecycle = _fetch_lifecycle_index(request.state.jwt, finding_kind="cve")
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    for f in rows:
        f["lifecycle"] = cve_lifecycle.get(f.get("cve_id"))
        _homebrew_finding_view(f)

    # PAT-2025: the tenant-level cve_assessment object rides on this same
    # response (contracts/portal-api.md "CVE assessment state (PAT-2024)"),
    # estate-wide rather than per-page, so any page of this call carries it.
    cve_assessment = _tenant_cve_assessment_view(
        data.get("cve_assessment") if isinstance(data, dict) else None
    )

    # PAT-1201: an offset past the last row returns findings=[] with a
    # bogus total=0 (the platform's count only rides along on the returned
    # rows - see the /v1/portal/findings contract) so it must never be read
    # as "empty tenant" when a non-zero offset was requested. Page 1
    # (offset 0) is the one case where an empty result is trustworthy, so
    # bounce anything else back there rather than rendering a nonsense
    # "page N of 0" - a stale bookmark, hand-edited URL, or a page whose
    # rows shrank under it are the only ways to reach this.
    if not rows and offset > 0:
        return RedirectResponse(url="/findings", status_code=302)

    # Ordering (cvss desc, then cve_id/app as stable tie-breakers) is the
    # platform's job now (contract, PAT-1201) so pages don't reorder
    # against each other - the portal must not re-sort what it's handed.
    total = data.get("total", len(rows)) if isinstance(data, dict) else len(rows)
    limit = data.get("limit", FINDINGS_PAGE_SIZE) if isinstance(data, dict) else FINDINGS_PAGE_SIZE
    total_pages = max(1, -(-total // limit)) if limit else 1

    # Ruling 2026-09-13 (Andy): CVE and CIS compliance findings render as
    # distinct sections on this page, never interleaved as rows in one
    # list. There is no tenant-wide CIS/compliance findings list endpoint
    # today - only /v1/portal/overview's severity rollup and each device's
    # own compliance_signals (see the PAT-1602 report for that gap) - so
    # the CIS section is that rollup, not a fabricated row list. Secondary
    # content: fails soft like the reports schedule fetch does, so a CIS
    # summary outage never takes down the CVE table this page already
    # serves reliably.
    cis_summary, cis_summary_unavailable = None, False
    try:
        overview_data = upstream.get_json("/v1/portal/overview", request.state.jwt)
        findings_open = overview_data.get("findings_open") or {}
        cis_summary = {
            k: findings_open.get(k, 0) or 0 for k in ("critical", "high", "medium", "low")
        }
        cis_summary["total"] = sum(cis_summary.values())
    except upstream.UpstreamError:
        cis_summary_unavailable = True

    # PAT-2263: estate driver findings - additive, secondary content on
    # this page exactly like the CIS rollup above, so a driver-findings
    # outage never takes down the CVE table. One page (limit 500, the same
    # ceiling /v1/portal/findings itself defaults to) - there is no
    # server-side driver search/filter either, matching the CVE table's own
    # documented client-side-only search scope.
    driver_findings, driver_findings_unavailable = None, False
    try:
        driver_findings_data = upstream.get_json(
            "/v1/portal/driver-findings", request.state.jwt,
            params={"limit": DRIVER_FINDINGS_LIMIT, "offset": 0},
        )
        driver_findings = _driver_findings_view(driver_findings_data)
    except upstream.UpstreamError:
        driver_findings_unavailable = True

    return _render(request, "findings.html", {
        "title": "Findings", "nav": "findings", "findings": rows,
        "page": page_num, "total_pages": total_pages, "total": total,
        "cis_summary": cis_summary, "cis_summary_unavailable": cis_summary_unavailable,
        "cve_assessment": cve_assessment,
        "driver_findings": driver_findings,
        "driver_findings_unavailable": driver_findings_unavailable,
        "driver_view": driver_view if driver_view in ("all", "not_enforced") else "all",
    })


FINDINGS_CSV_COLUMNS = ("cve_id", "severity", "cvss", "app", "version", "match_confidence",
                        "fixed_version", "devices_affected", "first_seen", "summary")

# Hard backstop on the pagination loop below: 50 pages * 500 rows/page =
# 25,000 findings. A platform contract bug (total that never converges with
# the actual row count) must never turn a CSV export into an infinite
# request loop - this is a best-effort export, not a page users can retry.
FINDINGS_CSV_MAX_PAGES = 50


def _findings_export_table(request: Request) -> _ExportTable:
    """Every open CVE finding (PAT-1587), across all pages.

    /v1/portal/findings is paginated (PAT-1201) unlike /v1/portal/devices,
    so a full export must walk every page or a tenant with more than one
    page of findings (this has happened - one tenant hit 709 rows) silently
    gets a truncated export with no indication anything was cut off.
    Raises UpstreamError.
    """
    found = []
    offset = 0
    for _ in range(FINDINGS_CSV_MAX_PAGES):
        data = upstream.get_json(
            "/v1/portal/findings", request.state.jwt,
            params={"limit": 500, "offset": offset},
        )
        page_rows = upstream.unwrap_list(data, "findings")
        found.extend(page_rows)
        # A short page (fewer rows than requested) means we've reached
        # the end - this doesn't depend on a "total" field, so it holds
        # even if the response were ever a bare array instead of the
        # documented {total, findings} wrapper.
        if len(page_rows) < 500:
            break
        offset += 500
    rows = [[_cell(v) for v in (
        f.get("cve_id", ""),
        f.get("severity", ""),
        "" if f.get("cvss") is None else f.get("cvss"),
        f.get("app", ""),
        f.get("version", ""),
        f.get("match_confidence", ""),
        f.get("fixed_version", ""),
        "" if f.get("devices_affected") is None else f.get("devices_affected"),
        f.get("first_seen", ""),
        f.get("summary", ""),
    )] for f in found]
    return _ExportTable("findings", "patched-findings.csv", list(FINDINGS_CSV_COLUMNS), rows, [])


@app.get("/findings.csv")
def findings_csv(request: Request):
    """CSV export of every open CVE finding (PAT-1587), across all pages."""
    try:
        table = _findings_export_table(request)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    return _table_csv_response(table)


@app.get("/findings.pdf")
def findings_pdf(request: Request):
    """PAT-2405: the same table as /findings.csv, as a PDF."""
    try:
        table = _findings_export_table(request)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    return _table_pdf_response(request, table)


EVIDENCE_BASIS_LABELS = {
    "identifier_match": "Identifier match",
    "name_match_only": "Name match only",
    "unknown": "No match evidence",
}

REMOVAL_STATE_LABELS = {
    # Applications have no removal data model at all (PAT-1598, not built) -
    # "not_available" must never read the same as an extension that simply
    # hasn't been asked for yet.
    "not_available": "No removal pathway",
    "not_requested": "Not requested",
    "requested": "Removal requested",
    "in_progress": "Removal in progress",
    "removal_completed": "Removal completed for its request scope",
}

# PAT-1821: matches dashboard/static/js/console-protected-software.js's
# CATEGORY_LABELS exactly, so a category reads the same word to the customer
# on the portal as it does to a specialist in the console.
PROTECTED_CATEGORY_LABELS = {
    "edr": "EDR",
    "mdm": "MDM",
    "backup": "Backup",
    "security": "Security",
    "patched_agent": "Patched Agent",
    "customer_defined": "Customer defined",
}


def _protected_category_label(category: str) -> str:
    # Absence requires authority: an unrecognised category must say so, not
    # silently borrow another category's label or disappear.
    return PROTECTED_CATEGORY_LABELS.get(category, category or "Protected")


def _normalize_software_name(name: str) -> str:
    """Casefold + collapse whitespace for a strict identity comparison.
    Used only for exact-string equality - see _protected_software_index for
    why this must never become a substring or fuzzy match."""
    return " ".join((name or "").strip().casefold().split())


def _protected_software_index(products: list) -> dict:
    """PAT-1821: GET /v1/portal/protected-software has no shared product id
    with GET /v1/portal/applications. It returns vendor + product_name;
    applications returns a single OS-observed `name` - raw device_apps.name
    (go-service/internal/report/portal_applications.go), which some
    platforms report vendor-prefixed ("CrowdStrike Falcon Sensor") and some
    don't ("Falcon Sensor"). This indexes every protected entry under both
    normalized forms - product_name alone, and "vendor product_name" - so
    an application row matches on an exact, case/whitespace-insensitive
    comparison against either.

    Deliberately NOT a substring match. A substring match would say
    "Defender" is a match inside "ZoneAlarm Extreme Defender", or "Agent"
    is a match inside some unrelated "XYZ Agent Helper" - a false positive
    that badges a product the platform never actually protected. This is a
    customer-facing identity claim (root AGENTS.md, "identity is not
    packaging": a display-name string is not proof of product identity),
    so a name that doesn't exactly match one of the two forms above is left
    unbadged rather than guessed at. That trades away some real matches (an
    OS report using a third naming convention neither form anticipates)
    for zero false positives - the right side of that trade for a
    disposition badge whose entire point is to be trustworthy.
    """
    index: dict = {}
    for p in products or []:
        if not isinstance(p, dict):
            continue
        vendor = (p.get("vendor") or "").strip()
        product_name = (p.get("product_name") or "").strip()
        if not product_name:
            continue
        candidates = {product_name}
        if vendor:
            candidates.add(f"{vendor} {product_name}")
        for candidate in candidates:
            key = _normalize_software_name(candidate)
            if key:
                index.setdefault(key, p)
    return index


def _protected_match(name: str, index: dict) -> dict | None:
    return index.get(_normalize_software_name(name))

APP_POLICY_GROUP = {
    "undecided": "waiting",
    "unapproved": "not_wanted",
    "approved": "approved",
    # PAT-1742 (Andy): a mandatory policy is a stronger form of approved,
    # not a distinct customer-facing state - there is no separate
    # "mandatory" group on this page.
    "mandatory": "approved",
    # PAT-2008: PAT-2007 stores a customer's Ignore on an application as
    # tenant_app_policies policy 'unmanaged' and reads it back as `ignored`
    # (contracts/portal-api.md, "Portal roles and software approval writes").
    # It is the same customer-facing state as an ignored extension, so it
    # joins that group instead of reading as an unrecognised value.
    "unmanaged": "ignored",
}

EXT_APPROVAL_GROUP = {
    "unreviewed": "waiting",
    "unapproved": "not_wanted",
    "approved": "approved",
    "ignored": "ignored",
}


def _evidence_basis_label(basis: str) -> str:
    # Absence requires authority: a basis value this page doesn't recognise
    # must say so, not silently read as either documented value.
    return EVIDENCE_BASIS_LABELS.get(basis, "Evidence basis not recognised")


def _removal_state_label(state: str) -> str:
    return REMOVAL_STATE_LABELS.get(state, "Removal status not recognised")


def _app_group(policy_state) -> str:
    return APP_POLICY_GROUP.get(policy_state, "unrecognised")


def _ext_group(approval_state) -> str:
    return EXT_APPROVAL_GROUP.get(approval_state, "unrecognised")


# PAT-1832: version_count is an exact, always-confident distinct-version
# count across the devices behind installs (device_count) - 0 only when
# installs is 0, never null. "on M versions" is only worth saying once
# there is more than one version; "on 1 version" reads as noise, so the
# suffix is dropped when version_count <= 1.
def _installs_label(installs: int, version_count: int) -> str:
    device_word = "device" if installs == 1 else "devices"
    if version_count and version_count > 1:
        return f"{installs} {device_word} on {version_count} versions"
    return f"{installs} {device_word}"


# PAT-1832: macOS codesign signing state (PAT-1799), applications only -
# extensions never carry team_id/signed_by/notarized at all, not even as
# null, so signing_state is only ever computed for kind == "application".
# signed_by is null means genuinely unknown (this is also the permanent
# shape of every Windows row today, PAT-1828 - a real, documented gap, not
# something to paper over here) and must never render as "Unsigned".
#
# notarized is a real platform tri-state (notarizedTriState, app_policy_
# drift.go), not a boolean-or-null shorthand for "yes/no evidence": True
# means at least one matched device confirmed notarized, False means at
# least one matched device explicitly reported notarized=false with none
# confirming true (genuine negative evidence), and null means no matched
# device carried a notarized signal at all (no evidence either way). A
# review flagged that collapsing False and null into one label ("Signed,
# not notarized") claims positive knowledge the platform doesn't have for
# the null case - fixed by giving null its own distinct, honest label.
SIGNING_STATE_LABELS = {
    "notarized": "Signed & notarized",
    "not_notarized": "Signed, not notarized",
    "notarization_unknown": "Signed, notarization unknown",
    "unknown": "Unknown",
}
SIGNING_STATE_PILL_CLASS = {
    # Deliberately distinct class names from pill-ok/pill-warn/pill-muted
    # (visually identical, see portal.css) - the protected-software badge
    # (PAT-1821) already renders literal "pill-ok" in the same row and is
    # asserted absent by name in tests/test_software.py; reusing that exact
    # class here would make a signed-and-notarized application row read as
    # a false positive for "this row is protected".
    "notarized": "pill-signed-ok",
    "not_notarized": "pill-signed-warn",
    "notarization_unknown": "pill-signed-unknown",
    "unknown": "pill-signed-unknown",
}


def _signing_state(kind: str, signed_by: str | None, notarized: bool | None) -> str | None:
    if kind != "application":
        return None
    if not signed_by:
        return "unknown"
    if notarized is True:
        return "notarized"
    if notarized is False:
        return "not_notarized"
    return "notarization_unknown"


def _software_row(
    name: str, kind: str, installs: int, evidence_basis: str, removal_state: str,
    protected_category: str | None = None,
    decided_by: str | None = None, decided_at: str | None = None,
    justification: str | None = None,
    version_count: int = 0,
    team_id: str | None = None, signed_by: str | None = None,
    notarized: bool | None = None,
    approval: dict | None = None,
    platform: str | None = None, identifier: str | None = None,
    browser: str | None = None,
) -> dict:
    signing_state = _signing_state(kind, signed_by, notarized)
    # PAT-2163 (orchestrator follow-up): an extension's Platform column
    # shows its browser instead of an OS platform it never had - see
    # _browser_display's own comment. Applications are unaffected (browser
    # is always None there, so this is exactly platform_display(platform)
    # or the pre-existing "No platform" fallback, same as before).
    platform_label = _browser_display(browser) if kind == "extension" else (
        platform_display(platform) if platform else "No platform"
    )
    return {
        # PAT-2008: approval write fields (item, state, lock reason, history
        # link). Absent for callers that only need the display shape.
        **(approval or _approval_view(name, None, None, None)),
        "publisher": _publisher(signed_by),
        "name": name, "kind": kind, "installs": installs,
        "version_count": version_count,
        "installs_label": _installs_label(installs, version_count),
        "team_id": team_id,
        "signed_by": signed_by,
        "notarized": notarized,
        "signing_state": signing_state,
        "signing_label": SIGNING_STATE_LABELS.get(signing_state) if signing_state else None,
        "signing_pill_class": (
            SIGNING_STATE_PILL_CLASS.get(signing_state) if signing_state else None
        ),
        "evidence_basis": evidence_basis,
        "evidence_label": _evidence_basis_label(evidence_basis),
        # PAT-2120: platform/identifier, and the GET /v1/portal/software
        # evidence a matching identity carries (versions, dated evidence,
        # CVE assessment) - see software()'s merge comment for the join
        # rule. Every row gets an honest default here (never assessed,
        # never a fabricated date) so a row with no inventory match still
        # renders truthfully rather than a blank cell.
        "platform": platform,
        "platform_label": platform_label,
        "identifier": identifier,
        "versions": [],
        "unknown_version_installation_count": 0,
        "installation_count": None,
        "evidence_at": None,
        "last_used_at": None,
        # PAT-2326: the platform's usage verdict, only ever copied from a
        # matching inventory product (_merge_inventory_evidence). None means
        # the platform said nothing about this row, which is never "unused".
        "usage_state": None,
        "no_evidence_installation_count": 0,
        "canonical_name": None,
        "cve_assessment": _cve_assessment_product_view(None),
        # Filled in by software() once the row is placed in its bucket
        # (waiting/not_wanted/approved/ignored/unrecognised) - drives the
        # decision-state filter's data-filter-decision attribute.
        "group": None,
        # Only an identifier match is confirmed identity. A name match, an
        # "unknown" basis, or a missing or unrecognised value can never be
        # marked (absence requires authority).
        "confirm_needed": evidence_basis != "identifier_match",
        "removal_state": removal_state,
        "removal_label": _removal_state_label(removal_state),
        # PAT-1821: a disposition badge only - never affects grouping,
        # evidence, removal state or the actions above. protected_category
        # is None whenever GET /v1/portal/protected-software found no exact
        # name match (or wasn't available at all), which reads as "not
        # known to be protected", never as "confirmed unprotected".
        "protected": protected_category is not None,
        "protected_category": protected_category,
        "protected_label": (
            _protected_category_label(protected_category) if protected_category else None
        ),
        # PAT-1839: decision provenance from GET /v1/portal/applications and
        # /v1/portal/extensions (PAT-1800). decided_at is what tells us a
        # decision record exists at all - an application policy row's
        # decided_by is permanently null (tenant_app_policies has no actor
        # column). PAT-2008: that reads "not recorded", never a guessed name;
        # the per-product history drawer carries who made each portal change.
        # decided_at itself stays raw here and is formatted with the existing
        # `humandate` filter in the template, same as exceptions.html already
        # does for accepted_at/requested_at.
        "decided_by": decided_by,
        "decided_by_label": decided_by or "Not recorded",
        "decided_at": decided_at,
        "has_decision": bool(decided_at),
        "justification": justification,
    }


# ── Software approval writes (PAT-2008, platform contract PAT-2007) ───────
# The portal's first customer write that changes estate governance state.
# Four independent guards stand in front of PUT /v1/portal/software-approvals,
# all in the portal, before the platform (which re-checks role and identity
# on its own) is ever asked to write:
#
#   1. Origin: a state-changing request must carry this portal's own Origin
#      (or, with no Origin header at all, a same-origin Referer). Cross-site
#      and opaque ("null") origins are refused.
#   2. CSRF token: a synchronizer token bound to the caller's verified CF
#      Access assertion (see _csrf_token). The portal is stateless, so the
#      token is derived rather than stored; an attacker page can neither read
#      the HttpOnly CF_Authorization cookie nor compute the token without it.
#   3. Role: GET /v1/portal/me must say `admin`. A viewer, or any role value
#      this code does not recognise, is refused 403 without a write call.
#   4. Input: only approved / unapproved / ignored (or, PAT-2058, unreviewed
#      - so far only reachable from the Homebrew tab's Reset to unreviewed
#      action), at most 500 distinct products, a reason of at most 1000
#      characters, and item shapes that match the platform's strict request
#      schema exactly - application, browser_extension, (PAT-2058)
#      homebrew_formula/homebrew_cask, or (PAT-2031) observation.
#
# The tenant and the actor are never taken from the request body: the JWT
# is forwarded verbatim and the platform derives both from it, exactly as it
# does for every read.
APPROVAL_WRITE_STATES = ("approved", "unapproved", "ignored")
# PAT-2058: the Homebrew tab offers a fourth action, Reset to unreviewed,
# that /software does not expose today - the platform's write contract has
# always accepted "unreviewed" as a target state (contracts/portal-api.md
# "PUT /v1/portal/software-approvals"), so this is additive to the shared
# write route (APPROVAL_ALL_WRITE_STATES below), not a new endpoint. Kept
# separate from APPROVAL_WRITE_STATES, which still governs /software's own
# three-action set, so this ticket cannot silently change what /software
# renders.
APPROVAL_HOMEBREW_WRITE_STATES = APPROVAL_WRITE_STATES + ("unreviewed",)
APPROVAL_ALL_WRITE_STATES = APPROVAL_HOMEBREW_WRITE_STATES
APPROVAL_STATE_LABELS = {
    "approved": "Approved",
    "unapproved": "Unapproved",
    "ignored": "Ignored",
    "unreviewed": "Unreviewed",
    "mandatory": "Mandatory",
}
APPROVAL_ACTION_LABELS = {
    "approved": "Approve", "unapproved": "Unapprove", "ignored": "Ignore",
    "unreviewed": "Reset to unreviewed",
}
# Mirrors ApprovalMaxItems / ApprovalMaxReasonChars in the platform's
# portal_software_approvals.go. The portal refuses above these itself rather
# than relying on the platform to.
APPROVAL_MAX_ITEMS = 500
APPROVAL_MAX_REASON_CHARS = 1000
APPROVAL_MAX_BODY_BYTES = 512 * 1024
APPROVAL_MAX_FORM_FIELDS = APPROVAL_MAX_ITEMS + 16
APPROVAL_MAX_IDENTIFIER_CHARS = 512
# PAT-2008 review fix: the platform truncates a stored identifier at 128
# characters (the same limit GET /v1/portal/applications documents for its
# own undecided-row output above). A write built from an identifier at or
# past that length would silently save a truncated value that no longer
# matches the real product, so the row is locked instead.
APPROVAL_IDENTIFIER_PLATFORM_LIMIT = 128
APPROVAL_MAX_NAME_CHARS = 256
APPROVAL_HISTORY_LIMIT = 100
APPROVAL_BROWSERS = ("chrome", "edge", "firefox", "safari", "any")
APPROVAL_PLATFORMS = ("macos", "windows")
APPROVAL_OBSERVATION_KINDS = (
    "ide_extension", "npm_package", "pip_package", "local_model",
    "local_model_runtime", "mcp_server",
)
_TEAM_ID_RE = re.compile(r"^[A-Z0-9]{10}$")
_EXTENSION_ID_RE = re.compile(r"^[A-Za-z0-9@._{}\-]{1,255}$")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
CSRF_FIELD = "csrf_token"
APPROVAL_RESULT_PARAM = "approval_result"
APPROVAL_FLASH_MAX_CHARS = 8192
PORTAL_ROLES = ("admin", "viewer")
# PAT-2257: the service identity's role - below viewer for writes (it can
# make none at all), a viewer for reads.
SERVICE_READONLY_ROLE = "service_readonly"

NAME_ONLY_LOCK = (
    "Known by its name only, so it has no confirmed identity and cannot be marked."
)
NO_EVIDENCE_LOCK = (
    "No device evidence confirms this product's identity, so it cannot be marked."
)
MANDATORY_LOCK = "Set as mandatory in your Patched policy, so it cannot be changed here."
NO_IDENTIFIER_LOCK = (
    "This decision is held in your Patched policy without a product identifier "
    "the portal can send, so it cannot be changed here yet."
)
UNKNOWN_PLATFORM_LOCK = "Its platform is not known, so it cannot be marked."
IDENTIFIER_TOO_LONG_LOCK = (
    "Its identifier is too long for Patched to store, so it cannot be changed here."
)
NO_TEAM_ID_LOCK = "Its macOS signing Team ID is not known, so it cannot be changed here."
# PAT-2058: a formula/cask's (name, tap) is always a confirmed identity per
# the contract ("approval_state/product_key are never null... always a
# confirmed identity, unlike an application's display-name case") - this
# only fires for a malformed or very old platform response with no name at
# all, never for an ordinary row.
HOMEBREW_NO_NAME_LOCK = "This package's identity could not be read, so it cannot be marked."


def _csrf_token(jwt_token: str) -> str:
    """Stateless synchronizer token, bound to the caller's session.

    HMAC-SHA256 keyed by the verified CF Access assertion over a fixed,
    purpose-specific label. The assertion is a high-entropy secret that only
    this browser (HttpOnly cookie) and this origin hold, so the token cannot
    be computed by a cross-site page, and the digest reveals nothing usable
    about the assertion. It rotates with the Access session. No box secret
    and no server-side store are needed, which keeps the portal stateless."""
    return hmac.new(
        jwt_token.encode("utf-8"), b"patched-portal-csrf-v1", hashlib.sha256,
    ).hexdigest()


def _csrf_valid(request: Request, submitted: str) -> bool:
    jwt_token = getattr(request.state, "jwt", "") or ""
    if not jwt_token or not submitted:
        return False
    return hmac.compare_digest(_csrf_token(jwt_token), submitted)


def _is_local_dev_host(host: str) -> bool:
    """True only for a genuinely local host - localhost or 127.0.0.1, with
    or without a port. This repo has no dev/test-mode flag (no ENV/DEBUG/
    TESTING setting anywhere in main.py, auth.py or upstream.py), so this is
    the single explicit, host-scoped allowance for a plain http Origin:
    e2e/_harness.py's own harness (and any local `uvicorn main:app` run)
    really does serve http with nothing in front of it. Nothing else -
    including the FastAPI TestClient's default "testserver" host used by
    tests/ - gets this exemption, because in production nginx terminates
    TLS in front of the portal (deploy/RUNBOOK.md) and forwards plain http,
    so request.url.scheme reads "http" there too; trusting that value (the
    previous behaviour) let an attacker-supplied Origin: http://app.patched.im
    pass the check it exists to fail."""
    return host.split(":", 1)[0] in ("localhost", "127.0.0.1")


def _same_origin(request: Request) -> bool:
    """Strict Origin check for a state-changing request.

    Origin is compared with the host the request was addressed to, and must
    be https, except on a genuinely local host (see _is_local_dev_host) -
    request.url.scheme is not a trustworthy signal here, since nginx
    terminates TLS in front of the portal and forwards plain http. No
    Origin at all falls back to a same-origin Referer; neither present, or
    Origin "null", is refused."""
    host = (request.headers.get("host") or "").lower()
    if not host:
        return False
    origin = request.headers.get("origin")
    if origin is None:
        referer = request.headers.get("referer") or ""
        if not referer:
            return False
        origin = referer
    parts = urlsplit(origin.strip())
    if parts.netloc.lower() != host:
        return False
    if _is_local_dev_host(host):
        return parts.scheme in ("https", "http")
    return parts.scheme == "https"


# PAT-2105: every state-changing route (each @app.post/put/delete/patch in
# this file) goes through _guarded_form before it does anything else, so
# the size cap, Origin and CSRF checks run in one place and in one order:
# size cap, then Origin, then CSRF token. Role checks and input validation
# stay with each route, after this guard. tests/test_pat2105_csrf.py
# enumerates app.routes and fails if any unsafe-method route answers
# without this guard refusing it.
STATE_CHANGE_MAX_BODY_BYTES = 16 * 1024
STATE_CHANGE_MAX_FORM_FIELDS = 64
_STATE_CHANGE_ORIGIN_REFUSAL = (
    "This change was refused because it did not come from the portal page itself. "
    "Reload the page and try again.")
_STATE_CHANGE_CSRF_REFUSAL = "This page has expired. Reload it and make the change again."


async def _guarded_form(
    request: Request, event: str, *,
    max_bytes: int = STATE_CHANGE_MAX_BODY_BYTES,
    max_fields: int = STATE_CHANGE_MAX_FORM_FIELDS,
    too_large_message: str = "That request was too large.",
) -> tuple[dict[str, list[str]] | None, HTMLResponse | None]:
    """Read and guard a state-changing form post. Returns (form, None) with
    every field as a list of values, or (None, refusal) where the refusal
    is the same "Change not made" error page PAT-2008 uses. `event` names
    the route in the refusal log line; nothing from the body is logged."""
    raw = await request.body()
    if len(raw) > max_bytes:
        return None, _approval_refusal(request, 413, too_large_message)
    if not _same_origin(request):
        logger.warning("portal.%s.refused reason=origin", event)
        return None, _approval_refusal(request, 403, _STATE_CHANGE_ORIGIN_REFUSAL)
    try:
        form = parse_qs(raw.decode("utf-8"), keep_blank_values=True,
                        max_num_fields=max_fields)
    except (UnicodeDecodeError, ValueError):
        return None, _approval_refusal(request, 400, "That request could not be read.")
    csrf_values = form.get(CSRF_FIELD, [])
    if len(csrf_values) != 1 or not _csrf_valid(request, csrf_values[0]):
        logger.warning("portal.%s.refused reason=csrf", event)
        return None, _approval_refusal(request, 403, _STATE_CHANGE_CSRF_REFUSAL)
    return form, None


def _portal_role(jwt_token: str) -> str:
    """The caller's portal role from GET /v1/portal/me. Anything other than
    an exact `admin` is treated as read-only (fail closed). Raises
    UpstreamError when the platform cannot answer."""
    if _is_service_jwt(jwt_token):
        # PAT-2257: never admin, whatever the platform says. This can only
        # ever lower a role, never raise one.
        return SERVICE_READONLY_ROLE
    data = upstream.get_json("/v1/portal/me", jwt_token)
    role = data.get("role") if isinstance(data, dict) else None
    return role if role in PORTAL_ROLES else "viewer"


def _is_service_jwt(jwt_token: str) -> bool:
    """True when this request's (already middleware-verified) assertion is
    the read-only service identity's. Reads the claims without re-verifying:
    it is the same string auth.verify_token accepted for this request, and a
    True answer can only take privilege away."""
    if not jwt_token:
        return False
    try:
        claims = auth.pyjwt.decode(jwt_token, options={"verify_signature": False})
    except Exception:
        return False
    return auth.service_common_name(claims) is not None


def _publisher(signed_by: str | None) -> str:
    """A filter label from the macOS signing identity, when there is one.
    "Developer ID Application: Example Inc (ABCDE12345)" reads "Example Inc".
    This only groups rows for filtering; it is never identity (identity is
    not packaging)."""
    if not isinstance(signed_by, str) or not signed_by.strip():
        return ""
    value = signed_by.strip()
    prefix = "Developer ID Application:"
    if value.startswith(prefix):
        value = value[len(prefix):].strip()
    value = re.sub(r"\s*\([A-Z0-9]{10}\)$", "", value)
    return value[:120]


def _approval_view(name: str, item: dict | None, state: str | None,
                   lock: str | None, protected: bool = False,
                   write_states: tuple = APPROVAL_WRITE_STATES) -> dict:
    """Everything a template needs to render one product's approval cell.

    `write_states` is the set of target states this row's own actions list
    (and the per-row Set state select, _macros.html's approval_form_cell)
    offers - APPROVAL_WRITE_STATES for every existing caller (applications,
    extensions, inventory rows), APPROVAL_HOMEBREW_WRITE_STATES (PAT-2058)
    for a Homebrew formula/cask row, which also offers Reset to
    unreviewed."""
    view = {
        "approval_item": item,
        "approval_state": state,
        "approval_state_label": APPROVAL_STATE_LABELS.get(state or ""),
        "approval_lock": lock,
        "approval_item_json": None,
        "approval_actions": [],
        "history_url": None,
    }
    if item:
        payload = {**item, "name": (name or "")[:APPROVAL_MAX_NAME_CHARS]}
        view["approval_item_json"] = json.dumps(payload, separators=(",", ":"))
        view["approval_actions"] = [
            {
                "state": target,
                "label": APPROVAL_ACTION_LABELS[target],
                "value": json.dumps({"state": target, "item": payload}, separators=(",", ":")),
                "protected": protected and target == "unapproved",
            }
            for target in write_states if target != state
        ]
        view["history_url"] = "/software/history?" + urlencode(
            {"item": view["approval_item_json"]})
    return view


def _app_approval_state(policy_state) -> str | None:
    return {
        "undecided": "unreviewed", "unmanaged": "ignored", "approved": "approved",
        "unapproved": "unapproved", "mandatory": "mandatory",
    }.get(policy_state)


def _app_approval(a: dict, protected: bool) -> dict:
    """Write item for one GET /v1/portal/applications row, or the reason it
    cannot be marked.

    PAT-2104: a decided (policy) row now carries its own `identifier` and
    `policy_team_id`, populated only when the platform can round-trip this
    exact row through PUT /v1/portal/software-approvals - so a non-empty
    `identifier` there is addressed straight from those two fields, not
    from `evidence_basis`/`team_id` (device signing evidence, which can
    disagree with the policy's own stored identity). Before this, decided
    rows always carried `identifier: ""` and were always locked, so a
    customer could never unapprove something they had approved.

    A row without a usable `identifier` - every undecided row (identity
    only ever comes from `evidence_basis`/`identifier`/`team_id` there),
    and a decided row an older platform build sent with none - falls back
    to today's behaviour: only a row the platform itself grouped by a real
    identifier on a known platform is addressable."""
    name = a.get("name", "") or ""
    state = _app_approval_state(a.get("policy_state"))
    basis = a.get("evidence_basis")
    if basis == "name_match_only":
        return _approval_view(name, None, state, NAME_ONLY_LOCK)

    decided = a.get("policy_state") not in (None, "undecided")
    raw_identifier = a.get("identifier")
    policy_identifier = raw_identifier.strip() if isinstance(raw_identifier, str) else ""

    if decided and policy_identifier:
        if a.get("policy_state") == "mandatory":
            return _approval_view(name, None, state, MANDATORY_LOCK)
        platform = a.get("platform")
        if platform not in APPROVAL_PLATFORMS:
            return _approval_view(name, None, state, UNKNOWN_PLATFORM_LOCK)
        if len(policy_identifier) >= APPROVAL_IDENTIFIER_PLATFORM_LIMIT:
            return _approval_view(name, None, state, IDENTIFIER_TOO_LONG_LOCK)
        item = {"type": "application", "platform": platform, "identifier": policy_identifier}
        if platform == "macos":
            team = a.get("policy_team_id")
            team_valid = isinstance(team, str) and bool(_TEAM_ID_RE.match(team.strip().upper()))
            if not team_valid:
                return _approval_view(name, None, state, NO_TEAM_ID_LOCK)
            item["team_id"] = team.strip().upper()
        return _approval_view(name, item, state, None, protected)

    if basis != "identifier_match":
        return _approval_view(name, None, state, NO_EVIDENCE_LOCK)
    if a.get("policy_state") == "mandatory":
        return _approval_view(name, None, state, MANDATORY_LOCK)
    platform = a.get("platform")
    identifier = (a.get("identifier") or "").strip() if isinstance(a.get("identifier"), str) else ""
    if platform not in APPROVAL_PLATFORMS or not identifier:
        return _approval_view(name, None, state, NO_IDENTIFIER_LOCK)
    if len(identifier) >= APPROVAL_IDENTIFIER_PLATFORM_LIMIT:
        return _approval_view(name, None, state, IDENTIFIER_TOO_LONG_LOCK)
    item = {"type": "application", "platform": platform, "identifier": identifier}
    team = a.get("team_id")
    if platform == "macos" and isinstance(team, str) and _TEAM_ID_RE.match(team.strip().upper()):
        item["team_id"] = team.strip().upper()
    return _approval_view(name, item, state, None, protected)


def _ext_approval(e: dict) -> dict:
    name = e.get("name", "") or ""
    state = e.get("approval_state") if e.get("approval_state") in APPROVAL_STATE_LABELS else None
    browser = e.get("browser")
    ext_id = e.get("extension_id")
    if (
        browser not in APPROVAL_BROWSERS or not isinstance(ext_id, str)
        or not _EXTENSION_ID_RE.match(ext_id.strip())
    ):
        return _approval_view(name, None, state, NO_IDENTIFIER_LOCK)
    item = {"type": "browser_extension", "browser": browser, "extension_id": ext_id.strip()}
    return _approval_view(name, item, state, None)


def _inventory_approval(
    product: dict, protected_index: dict, protected: bool | None = None,
) -> dict:
    """Write item for one GET /v1/portal/software inventory row.

    PAT-2104: that read now carries its own `policy_state`, `team_id` and
    `product_key`, matching PUT /v1/portal/software-approvals exactly, so
    this reads them directly instead of borrowing state from a matching
    GET /v1/portal/applications row.

    PAT-2008 review fix (P2), now folded in here rather than solved by
    borrowing: a product that is already decided (or mandatory) still gets
    its own state pill and, unless it is genuinely addressable, still locks
    rather than being posted with no team_id and refused by the platform
    with 422 unconfirmed_identity or 409 operator_managed. A row an older
    platform build sent with no `product_key` - or one the write schema
    cannot address, which the platform already reflects as a missing
    `product_key` - falls back to locked, same as every row was before
    PAT-2104.

    PAT-2120 review fix (P2): `protected` may be supplied by the caller
    when it already holds the one protected-software decision for this
    row (see _merge_inventory_evidence - a merged row must not let this
    function silently recompute its own answer from the inventory
    product's name while protected_category/protected_label stay decided
    from the governance row's name, which can disagree). Left as None
    (every other caller), this computes it the original way, from this
    product's own name."""
    name = product.get("name", "") or ""
    platform = product.get("platform")
    if protected is None:
        protected = _protected_match(name, protected_index) is not None

    def view(item, state, lock):
        return {**_approval_view(name, item, state, lock, protected), "protected": protected}

    raw_state = product.get("policy_state")
    state = raw_state if raw_state in APPROVAL_STATE_LABELS else "unreviewed"

    if platform not in APPROVAL_PLATFORMS:
        return view(None, state, UNKNOWN_PLATFORM_LOCK)
    raw_identifier = product.get("identifier")
    identifier = raw_identifier.strip() if isinstance(raw_identifier, str) else ""
    if not identifier:
        return view(None, state, NAME_ONLY_LOCK)
    product_key = product.get("product_key")
    if not isinstance(product_key, str) or not product_key:
        return view(None, state, NO_EVIDENCE_LOCK)
    if raw_state == "mandatory":
        return view(None, state, MANDATORY_LOCK)
    if len(identifier) >= APPROVAL_IDENTIFIER_PLATFORM_LIMIT:
        return view(None, state, IDENTIFIER_TOO_LONG_LOCK)
    team = product.get("team_id")
    team_valid = isinstance(team, str) and bool(_TEAM_ID_RE.match(team.strip().upper()))
    if platform == "macos" and not team_valid:
        return view(None, state, NO_TEAM_ID_LOCK)
    item = {"type": "application", "platform": platform, "identifier": identifier}
    if team_valid:
        item["team_id"] = team.strip().upper()
    return view(item, state, None)


# ── PAT-2120: merging the inventory and governance read models ────────────
# GET /v1/portal/software (inventory: dated evidence, versions, CVE
# assessment) and GET /v1/portal/applications + /v1/portal/extensions
# (governance: decision state, evidence basis, removal state) describe
# overlapping populations with no shared primary key today. PAT-2104 is
# adding `product_key` to both, but as of this ticket the platform-side
# change is still In Review and the applications fixture/contract carries
# no product_key yet - so the only identity both sides reliably share is
# (platform, identifier), the same fields PUT /v1/portal/software-approvals
# addresses a row by. This mirrors the exact-equality discipline
# _protected_software_index already established for a different
# no-shared-key join (PAT-1821): strict, case/whitespace-insensitive
# equality only, never a substring or name-only guess, so a genuine
# duplicate is merged but two different products are never folded into
# one. The cost of that strictness is real: an application row without a
# confirmed identifier (most undecided rows - see APPLICATIONS fixture)
# cannot be matched even when the same product is sitting in the inventory
# list, so it renders as two honestly-separate rows rather than a risky
# guessed merge. That is intentional, not a gap to silently paper over.
INVENTORY_POLICY_GROUP = {
    "unreviewed": "waiting",
    "unapproved": "not_wanted",
    "approved": "approved",
    "mandatory": "approved",
    "ignored": "ignored",
}


def _inventory_group(policy_state) -> str:
    # Mirrors _inventory_approval's own state normalisation exactly (a
    # missing or foreign policy_state there reads as "unreviewed", never a
    # 6th pill state) - the group a row lands in and the state pill it
    # shows must never disagree.
    return INVENTORY_POLICY_GROUP.get(policy_state, "waiting")


def _software_identity_key(platform, identifier) -> tuple | None:
    if not isinstance(platform, str) or not platform:
        return None
    if not isinstance(identifier, str):
        return None
    normalized = _normalize_software_name(identifier)
    return (platform, normalized) if normalized else None


def _merge_inventory_evidence(row: dict, product: dict, protected_index: dict) -> None:
    """Enrich an existing governance row in place with the matching
    inventory product's evidence (versions, dated evidence, CVE
    assessment), and prefer the inventory endpoint's own approval
    addressing (PAT-2104's product_key/team_id/policy_state) over the
    governance endpoint's - it is the richer, more reliable path
    _inventory_approval exists for.

    PAT-2120 review fix (P2): protected/protected_category/protected_label
    must come from exactly ONE source for a merged row. Before this fix,
    _inventory_approval (called via row.update() below) independently
    recomputed `protected` from the inventory product's own name, while
    protected_category/protected_label stayed whatever the governance row
    (applications/extensions) had already matched under its own name -
    two separate lookups that can disagree, rendering "Protected by your
    None" when only the inventory name matched, or silently dropping an
    otherwise-correct badge when only the governance name matched. The
    governance row's own match wins when it found one (row["protected"]
    is already set from it by the time this runs); only when the
    governance side found no match do we fall back to the inventory
    product's own name, and then set all three fields from that single
    decision together."""
    row["versions"] = [v for v in (product.get("versions") or []) if isinstance(v, str)]
    row["unknown_version_installation_count"] = (
        product.get("unknown_version_installation_count") or 0
    )
    row["installation_count"] = product.get("installation_count")
    row["evidence_at"] = product.get("evidence_at")
    row["last_used_at"] = product.get("last_used_at")
    usage_state = product.get("usage_state")
    row["usage_state"] = usage_state if usage_state in SOFTWARE_USAGE_STATE_LABELS else None
    row["no_evidence_installation_count"] = _no_evidence_count(product)
    row["canonical_name"] = product.get("canonical_name")
    row["cve_assessment"] = _cve_assessment_product_view(product.get("cve_assessment"))
    if not row["protected"]:
        match = _protected_match(product.get("name", "") or "", protected_index)
        row["protected"] = match is not None
        row["protected_category"] = match.get("category") if match else None
        row["protected_label"] = (
            _protected_category_label(row["protected_category"])
            if row["protected_category"] else None
        )
    row.update(_inventory_approval(product, protected_index, protected=row["protected"]))


def _inventory_only_row(product: dict, protected_index: dict) -> dict:
    """A row for an inventory product with no matching governance row (see
    _software_identity_key) - the inventory endpoint is application-only
    (PAT-2104), so this is always kind="application". evidence_basis reads
    identifier_match when the product carries a real identifier (which
    every inventory row does whenever identity is confirmed) and unknown
    otherwise; removal_state is always not_available, the same honest
    reading applications already give (no removal data model exists for
    an application either way, root AGENTS.md - absence requires
    authority)."""
    name = product.get("name", "") or ""
    identifier = product.get("identifier")
    evidence_basis = "identifier_match" if isinstance(identifier, str) and identifier else "unknown"
    match = _protected_match(name, protected_index)
    row = _software_row(
        name, "application", product.get("device_count") or 0,
        evidence_basis, "not_available",
        protected_category=(match.get("category") if match else None),
        version_count=len([v for v in (product.get("versions") or []) if isinstance(v, str)]),
        platform=product.get("platform"), identifier=identifier,
    )
    _merge_inventory_evidence(row, product, protected_index)
    return row


# ── PAT-2156: one device's Software installed view ────────────────────────
# /devices/{device_id}/software (contracts/portal-api.md "device_id
# (PAT-2156)" on both GET /v1/portal/software and GET /v1/portal/extensions).
# The device-scoped software endpoint already returns the same PAT-2104
# merged shape (team_id/product_key/policy_state) an ordinary inventory row
# carries - it is not a second, independent read model the way applications/
# extensions were for the estate-wide /software page - so a row here is
# built straight from _software_inventory_row + _inventory_approval, the
# exact two helpers /software's own inventory rows already trust, plus the
# two fields only this endpoint carries: a device-scoped cve_assessment
# (already handled by _software_inventory_row) and first_seen_on_device.
def _device_software_row(product: dict, protected_index: dict) -> dict:
    row = _software_inventory_row(product)
    match = _protected_match(product.get("name", "") or "", protected_index)
    row["protected"] = match is not None
    row["protected_category"] = match.get("category") if match else None
    row["protected_label"] = (
        _protected_category_label(row["protected_category"]) if row["protected_category"] else None
    )
    row.update(_inventory_approval(product, protected_index, protected=row["protected"]))
    first_seen = product.get("first_seen_on_device")
    row["first_seen_on_device"] = first_seen if isinstance(first_seen, str) else None
    return row


def _device_extension_row(e: dict) -> dict:
    """One row of GET /v1/portal/extensions?device_id=... - the same fields
    the unfiltered endpoint already carries, filtered to one device. Built
    with _software_row/_ext_approval exactly as /software builds an
    extension row, so the approval pill, lock reasons and history link can
    never drift from that page's own behaviour."""
    row = _software_row(
        e.get("name", ""), "extension", e.get("device_count") or 0,
        e.get("evidence_basis", ""), e.get("removal_state", ""),
        decided_by=e.get("decided_by"), decided_at=e.get("decided_at"),
        justification=e.get("justification"),
        version_count=e.get("version_count") or 0,
        approval=_ext_approval(e),
    )
    row["versions"] = [v for v in (e.get("versions") or []) if isinstance(v, str)]
    row["browser"] = e.get("browser") if isinstance(e.get("browser"), str) else None
    risk_level = e.get("risk_level")
    row["risk_level"] = risk_level if risk_level in ("normal", "elevated") else None
    row["group"] = _ext_group(e.get("approval_state"))
    return row


def _new_software_approval(product: dict) -> dict:
    """Approval write view for one new_software product (PAT-2093,
    contracts/portal-api.md "new_software"; since PAT-2254 only the
    /reports/new-software rows use it, the Overview card being read only).
    Its identity fields (name,
    platform, identifier, team_id, product_key) are the same PAT-2104 shape
    GET /v1/portal/software's inventory rows carry and PUT
    /v1/portal/software-approvals takes, per the contract's own "Identity"
    section - the one difference is the field name for state
    (approval_state here, policy_state there), so this maps that one field
    and delegates to _inventory_approval rather than re-implementing the
    same identity/lock rules a second time. A row with no product_key (no
    usable identity) locks exactly as it would on /software - see
    _inventory_approval's own NO_EVIDENCE_LOCK/NAME_ONLY_LOCK/etc paths."""
    mapped = {**product, "policy_state": product.get("approval_state")}
    return _inventory_approval(mapped, {})


def _new_software_reason_view(reason) -> dict | None:
    if not isinstance(reason, dict):
        return None
    code, level, detail = reason.get("code"), reason.get("level"), reason.get("detail")
    if not isinstance(code, str) or not code or not isinstance(detail, str) or not detail:
        return None
    return {
        "code": code,
        "level": level if level in NEW_SOFTWARE_URGENCY_LABELS else None,
        "level_label": NEW_SOFTWARE_URGENCY_LABELS.get(level, ""),
        "detail": detail,
    }


def _new_software_product_view(product) -> dict | None:
    """One new_software.products row, or None if it cannot be trusted -
    see _new_software_view for why that fails the whole block rather than
    silently dropping the row."""
    if not isinstance(product, dict):
        return None
    name = product.get("name")
    urgency = product.get("urgency")
    if not isinstance(name, str) or not name or urgency not in NEW_SOFTWARE_URGENCY_LABELS:
        return None
    reasons_raw = product.get("reasons")
    reasons = [
        view for view in (
            _new_software_reason_view(r)
            for r in (reasons_raw if isinstance(reasons_raw, list) else [])
        ) if view
    ]
    device_count = product.get("device_count")
    return {
        "name": name,
        # PAT-2254: the row opens the product in /software, where the review
        # controls live. The Overview shows it read only.
        "href": _software_filter_url(search=name),
        "platform": product.get("platform") or "",
        "device_count": device_count if isinstance(device_count, int) else 0,
        "first_seen_at": product.get("first_seen_at"),
        "urgency": urgency,
        "urgency_label": NEW_SOFTWARE_URGENCY_LABELS[urgency],
        "urgency_pill_class": NEW_SOFTWARE_URGENCY_PILL_CLASS[urgency],
        "urgency_rank": NEW_SOFTWARE_URGENCY_RANK[urgency],
        "reasons": reasons,
    }


def _new_software_view(raw) -> dict:
    """View for the overview's additive new_software block (PAT-2093,
    contracts/portal-api.md "new_software"). Always returns a dict with a
    `status` so the template never special-cases None:

    - "unavailable": the shape cannot be trusted - the platform's own null
      for "could not be computed", a missing key (an older platform build),
      or a malformed block (including one unparseable product entry, which
      takes the whole block unavailable rather than silently dropping a
      row, the same posture _software_inventory_envelope already takes for
      the software page). The card still renders, with an explicit
      unavailable line (PAT-2159) - an error must never look identical to
      a confirmed "nothing new" read (root AGENTS.md - absence requires
      authority, the same rule PAT-1953's cve_attention and PAT-2097's
      alert_counts already follow elsewhere on this page).
    - "empty": a trustworthy read reporting zero new products in the
      window (total == 0, the platform's own aggregate count - the same
      field the pre-PAT-2159 empty state already keyed off). This is the
      one case PAT-2159 hides the card entirely - it is only ever reached
      from a well-formed read, never from a value the portal could not
      parse.
    - "data": a trustworthy read with at least one new product; renders
      the full card as before.
    """
    if not isinstance(raw, dict):
        return {"status": "unavailable"}
    window_days = raw.get("window_days")
    total = raw.get("total")
    products_raw = raw.get("products")
    if (
        not isinstance(window_days, int) or isinstance(window_days, bool)
        or not isinstance(total, int) or isinstance(total, bool)
        or not isinstance(products_raw, list)
    ):
        return {"status": "unavailable"}
    counts_raw = raw.get("counts") if isinstance(raw.get("counts"), dict) else {}
    counts = {
        level: counts_raw.get(level) if type(counts_raw.get(level)) is int else 0
        for level in NEW_SOFTWARE_URGENCY_LEVELS
    }
    products = []
    for raw_product in products_raw:
        view = _new_software_product_view(raw_product)
        if view is None:
            return {"status": "unavailable"}
        products.append(view)
    # Stable sort: urgency first (contract order above), newest-first order
    # from the platform preserved within a level.
    products.sort(key=lambda p: p["urgency_rank"])
    if total == 0:
        return {"status": "empty", "window_days": window_days}
    return {
        "status": "data",
        "window_days": window_days,
        "total": total,
        "truncated": bool(raw.get("truncated")),
        "counts": counts,
        "products": products,
        # PAT-2254: every figure on the card opens /software pre-filtered to
        # the same window (and level), so a count and the list it opens
        # cannot disagree.
        "all_href": _software_filter_url(new_days=window_days),
        "level_hrefs": {
            level: _software_filter_url(new_days=window_days, urgency=level)
            for level in NEW_SOFTWARE_URGENCY_LEVELS
        },
    }


def _parse_approval_item(obj) -> tuple[dict, str] | None:
    """Validate one posted product reference against the platform's strict
    item schema. Returns (item to send, display name) or None. `name` is a
    display-only field the portal adds for its own messages; it is never
    sent upstream."""
    if not isinstance(obj, dict):
        return None
    name = obj.get("name", "")
    if not isinstance(name, str) or len(name) > APPROVAL_MAX_NAME_CHARS:
        return None
    kind = obj.get("type")
    if kind == "application":
        if set(obj) - {"type", "platform", "identifier", "team_id", "name"}:
            return None
        platform = obj.get("platform")
        identifier = obj.get("identifier")
        if platform not in APPROVAL_PLATFORMS or not isinstance(identifier, str):
            return None
        identifier = identifier.strip()
        if (
            not identifier or len(identifier) > APPROVAL_MAX_IDENTIFIER_CHARS
            or _CONTROL_CHARS_RE.search(identifier)
        ):
            return None
        item = {"type": "application", "platform": platform, "identifier": identifier}
        if "team_id" in obj:
            team = obj["team_id"]
            if platform != "macos" or not isinstance(team, str) or not _TEAM_ID_RE.match(team):
                return None
            item["team_id"] = team
        return item, name
    if kind == "browser_extension":
        if set(obj) - {"type", "browser", "extension_id", "name"}:
            return None
        browser = obj.get("browser")
        ext_id = obj.get("extension_id")
        if (
            browser not in APPROVAL_BROWSERS or not isinstance(ext_id, str)
            or not _EXTENSION_ID_RE.match(ext_id)
        ):
            return None
        return {"type": "browser_extension", "browser": browser, "extension_id": ext_id}, name
    if kind in ("homebrew_formula", "homebrew_cask"):
        # PAT-2058: contracts/portal-api.md "PUT /v1/portal/software-
        # approvals" - name is required (the formula name or cask token,
        # exactly as GET /v1/portal/homebrew/formulae|casks identity.name/
        # token show it), tap is optional, and no platform/identifier/
        # team_id/browser/extension_id belongs on this item shape. The
        # item's own identity field is called "name", the same key the
        # outer payload already uses for its display name - both are always
        # the same string for Homebrew (there is no separate display name
        # the way an application has one), so the two never disagree.
        if set(obj) - {"type", "name", "tap"}:
            return None
        if not name or _CONTROL_CHARS_RE.search(name):
            return None
        item = {"type": kind, "name": name}
        if "tap" in obj:
            tap = obj["tap"]
            if (
                not isinstance(tap, str) or len(tap) > APPROVAL_MAX_IDENTIFIER_CHARS
                or _CONTROL_CHARS_RE.search(tap)
            ):
                return None
            item["tap"] = tap
        return item, name
    if kind == "observation":
        # PAT-2031: exact tenant-local tooling identity. The source is
        # optional in the platform contract, but when present remains part
        # of identity and must survive the portal unchanged. As with every
        # other item shape, tenant and actor are deliberately absent.
        if set(obj) - {"type", "identity_kind", "name", "source"}:
            return None
        identity_kind = obj.get("identity_kind")
        clean_name = name.strip()
        if identity_kind not in APPROVAL_OBSERVATION_KINDS or not clean_name:
            return None
        if _CONTROL_CHARS_RE.search(clean_name):
            return None
        item = {"type": "observation", "identity_kind": identity_kind, "name": clean_name}
        if "source" in obj:
            source = obj["source"]
            if (
                not isinstance(source, str) or len(source) > APPROVAL_MAX_IDENTIFIER_CHARS
                or _CONTROL_CHARS_RE.search(source)
            ):
                return None
            item["source"] = source
        return item, name
    return None


def _approval_item_key(item: dict) -> tuple:
    if item["type"] == "application":
        return ("application", item["platform"], item["identifier"].casefold(),
                item.get("team_id", ""))
    if item["type"] == "browser_extension":
        return ("browser_extension", item["browser"], item["extension_id"])
    if item["type"] == "observation":
        return ("observation", item["identity_kind"], item["name"].casefold(),
                item.get("source", "").casefold())
    # homebrew_formula / homebrew_cask (PAT-2058): identity is (kind, name,
    # tap), case-insensitive on name to match the platform's own resolver.
    return (item["type"], item["name"].casefold(), item.get("tap", ""))


def _flash_signature(jwt_token: str, raw: str) -> str:
    return hmac.new(
        jwt_token.encode("utf-8"), b"patched-portal-flash-v1:" + raw.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()[:32]


def _sign_flash(jwt_token: str, payload: dict) -> str:
    """The post-write result travels in the redirect URL, signed with the
    session so a crafted link cannot put arbitrary text in a portal notice."""
    raw = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")
    return f"{raw}.{_flash_signature(jwt_token, raw)}"


def _read_flash(jwt_token: str, value: str) -> dict | None:
    if not value or not jwt_token or len(value) > APPROVAL_FLASH_MAX_CHARS or "." not in value:
        return None
    raw, _, signature = value.rpartition(".")
    try:
        expected = _flash_signature(jwt_token, raw)
    except UnicodeEncodeError:
        return None
    if not hmac.compare_digest(expected, signature):
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _approval_flash_view(data: dict | None) -> dict | None:
    """Normalise a verified flash payload into what the notice renders."""
    if not data:
        return None

    def text(key, limit=400):
        value = data.get(key)
        return value[:limit] if isinstance(value, str) else ""

    def lines(key):
        values = data.get(key)
        if not isinstance(values, list):
            return []
        return [v[:400] for v in values[:20] if isinstance(v, str)]

    def count(key):
        value = data.get(key)
        return value if type(value) is int and value >= 0 else None

    state = data.get("state")
    return {
        "error": text("error"),
        "notice": text("notice"),
        "error_lines": lines("error_lines"),
        "state": state if state in APPROVAL_ALL_WRITE_STATES else None,
        "state_label": APPROVAL_STATE_LABELS.get(state or "", ""),
        "requested": count("requested"),
        "changed": count("changed"),
        "protected": lines("protected"),
        "resolved_alerts": count("resolved_alerts"),
    }


APPROVAL_RETURN_PATHS = ("/software", "/homebrew", "/ai-tooling", "/reports/new-software")

# PAT-2156: the device Software view's own return path. A strict UUID only,
# nothing else - no path traversal (`/devices/../x`), no non-UUID id, no
# extra segment, and (being a full-string match) no way to smuggle an
# external URL in behind a valid-looking prefix. safe_return_to above
# already rejects an absolute/protocol-relative target before this ever
# runs; this regex is the second, independent gate that decides which
# *path* on this origin the write is allowed to bounce back to.
DEVICE_SOFTWARE_RETURN_RE = re.compile(
    r"^/devices/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/software"
)
AI_TOOLING_DEVICE_RETURN_RE = re.compile(r"^/ai-tooling/devices/[A-Za-z0-9._-]{1,128}$")


def _approval_return_to(raw: str) -> str:
    """Where to send the browser after a write: back to /software with its
    tab, search and filters, or back to the device Software view (PAT-2156)
    with its own tab/search/offset - never anywhere else. PAT-2254: the
    Overview is no longer a return path. Its New software card used to post
    approvals (PAT-2139 sent them back to "/"); software review now lives
    in /software and the Overview is read only, so a stale form that still
    posts return_to="/" falls back to /software like any unlisted path.
    PAT-2163: this already covers the filter bar's `type`/`approval`
    params with no change needed - the query loop below keeps every param
    it doesn't itself recognise (only APPROVAL_RESULT_PARAM is stripped),
    so a write from a filtered /software view already lands back on that
    same filtered view. Still strictly path-restricted to
    APPROVAL_RETURN_PATHS - see tests/test_pat2008_software_approvals.py's
    test_return_to_cannot_leave_the_software_page and
    tests/test_pat2163_software_filter_bar.py's return-path tests."""
    target = safe_return_to(raw) or "/software"
    parts = urlsplit(target)
    path = parts.path if (
        parts.path in APPROVAL_RETURN_PATHS or DEVICE_SOFTWARE_RETURN_RE.fullmatch(parts.path)
        or AI_TOOLING_DEVICE_RETURN_RE.fullmatch(parts.path)
    ) else "/software"
    query = [(k, v) for k, v in parse_qs(parts.query, keep_blank_values=True).items()
             if k != APPROVAL_RESULT_PARAM]
    flat = [(k, item) for k, values in query for item in values]
    return path + ("?" + urlencode(flat) if flat else "")


def _approval_redirect(request: Request, return_to: str, payload: dict,
                       anchor: str | None = None) -> RedirectResponse:
    """PAT-2255: `anchor` is the row the customer should land on after the
    write (the next product in their filtered view), so a no-JS browser
    returns to the same filtered URL with the next item in view. Only an
    exact row-id shape is honoured (SOFTWARE_ROW_ANCHOR_RE); anything else
    falls back to the result notice, never reflected into the URL."""
    token = _sign_flash(request.state.jwt, payload)
    separator = "&" if "?" in return_to else "?"
    fragment = anchor if anchor and SOFTWARE_ROW_ANCHOR_RE.fullmatch(anchor) else "approval-result"
    url = f"{return_to}{separator}{APPROVAL_RESULT_PARAM}={quote(token, safe='')}#{fragment}"
    return RedirectResponse(url=url, status_code=303)


def _approval_refusal(request: Request, status_code: int, message: str) -> HTMLResponse:
    return _render(request, "error.html", {
        "title": "Change not made", "message": message,
    }, status_code=status_code)


APPROVAL_ERROR_MESSAGES = {
    "admin_role_required": (
        "Only an administrator on your account can change approval state. Nothing was changed."
    ),
    "name_only": (
        "Some products are known by name only, so they cannot be marked. Nothing was changed."
    ),
    "unconfirmed_identity": (
        "Some products do not have a confirmed identity yet, so they cannot be marked. "
        "Nothing was changed."
    ),
    "operator_managed": (
        "Some products are set as mandatory in your Patched policy, so they cannot be "
        "changed here. Nothing was changed."
    ),
}


def _approval_error_payload(exc: upstream.UpstreamError, names: list[str]) -> dict:
    """Turn a platform refusal into customer-facing text: the platform's own
    per-item reasons, named by product, under a headline for the code."""
    if exc.kind == "unavailable":
        return {"error": (
            "The Patched platform could not be reached, so this change may not have been "
            "saved. Refresh the page to check before trying again."
        )}
    try:
        body = json.loads(exc.body) if exc.body else {}
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    code = body.get("error") if isinstance(body.get("error"), str) else ""
    message = body.get("message") if isinstance(body.get("message"), str) else ""
    headline = APPROVAL_ERROR_MESSAGES.get(code) or (
        (message[:300] + " Nothing was changed.") if message
        else "The Patched platform refused this change. Nothing was changed."
    )
    error_lines = []
    items = body.get("items") if isinstance(body.get("items"), list) else []
    for entry in items[:20]:
        if not isinstance(entry, dict):
            continue
        index = entry.get("index")
        reason = entry.get("message") if isinstance(entry.get("message"), str) else ""
        label = (
            names[index] if type(index) is int and 0 <= index < len(names) and names[index]
            else "A selected product"
        )
        if reason:
            error_lines.append(f"{label}: {reason[:300]}")
    return {"error": headline, "error_lines": error_lines}


def _resolved_alert_count(results) -> int | None:
    """PAT-2097 (not deployed everywhere yet) adds `resolved_alerts` per
    result. Tolerate its absence, and either a count or a list per item."""
    if not isinstance(results, list):
        return None
    total, seen = 0, False
    for result in results:
        if not isinstance(result, dict) or "resolved_alerts" not in result:
            continue
        value = result["resolved_alerts"]
        if type(value) is int and value >= 0:
            total, seen = total + value, True
        elif isinstance(value, list):
            total, seen = total + len(value), True
    return total if seen else None


@app.post("/software/approvals")
async def software_approvals(request: Request):
    """PAT-2008: set approval state for one product (an inline row control)
    or many (the bulk bar), then redirect back to the page it was posted
    from - /software, /homebrew (PAT-2058) or the Overview's New software
    card - with a signed result notice. See the section comment above for
    the guard order."""
    form, refusal = await _guarded_form(
        request, "software_approvals",
        max_bytes=APPROVAL_MAX_BODY_BYTES, max_fields=APPROVAL_MAX_FORM_FIELDS,
        too_large_message=f"That request was too large. Select at most {APPROVAL_MAX_ITEMS} "
        "products at a time.")
    if refusal is not None:
        return refusal
    try:
        role = await run_in_threadpool(_portal_role, request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if role != "admin":
        return _approval_refusal(
            request, 403, "Only an administrator on your account can change approval state. "
            "Your account can view decisions and their history.")

    return_to = _approval_return_to((form.get("return_to") or [""])[0])
    # PAT-2255: the next row in the customer's filtered view, validated by
    # _approval_redirect. Used only for a successful write; a refusal lands
    # on the notice that explains it.
    anchors = form.get("return_anchor", [])
    return_anchor = anchors[0] if len(anchors) == 1 else None

    row_actions = form.get("row_action", [])
    if row_actions:
        if len(row_actions) != 1:
            return _approval_refusal(request, 400, "That request could not be read.")
        try:
            action = json.loads(row_actions[0])
        except ValueError:
            return _approval_refusal(request, 400, "That request could not be read.")
        if not isinstance(action, dict) or set(action) != {"state", "item"}:
            return _approval_refusal(request, 400, "That request could not be read.")
        state = action["state"]
        raw_items = [action["item"]]
    else:
        states = form.get("state", [])
        state = states[0] if len(states) == 1 else None
        raw_items = []
        for value in form.get("item", []):
            try:
                raw_items.append(json.loads(value))
            except ValueError:
                return _approval_refusal(request, 400, "That request could not be read.")

    if state not in APPROVAL_ALL_WRITE_STATES:
        return _approval_refusal(
            request, 400, "Choose Approve, Unapprove, Ignore or Reset to unreviewed.")

    reasons = form.get("reason", [""])
    if len(reasons) > 1:
        return _approval_refusal(request, 400, "That request could not be read.")
    reason = reasons[0].strip()
    if "\x00" in reason:
        return _approval_refusal(request, 400, "That request could not be read.")
    if len(reason) > APPROVAL_MAX_REASON_CHARS:
        return _approval_redirect(request, return_to, {
            "error": f"The reason can be at most {APPROVAL_MAX_REASON_CHARS} characters. "
                     "Nothing was changed."})

    if not raw_items:
        return _approval_redirect(request, return_to, {
            "error": "Select at least one product first. Nothing was changed."})
    if len(raw_items) > APPROVAL_MAX_ITEMS:
        return _approval_redirect(request, return_to, {
            "error": f"Select at most {APPROVAL_MAX_ITEMS} products at a time. "
                     "Nothing was changed."})

    items, names, seen = [], [], set()
    for raw_item in raw_items:
        parsed = _parse_approval_item(raw_item)
        if parsed is None:
            return _approval_refusal(request, 400, "That request could not be read.")
        item, name = parsed
        key = _approval_item_key(item)
        if key in seen:
            continue
        seen.add(key)
        items.append(item)
        names.append(name)

    payload: dict = {"state": state, "items": items}
    if reason:
        payload["reason"] = reason
    try:
        result = await run_in_threadpool(
            upstream.put_json, "/v1/portal/software-approvals", request.state.jwt, payload)
    except upstream.UpstreamError as exc:
        # Only the classification is logged: never the JWT, the body or the
        # customer's reason text.
        logger.warning("portal.software_approvals.upstream_refused kind=%s status=%s",
                       exc.kind, exc.status)
        if exc.kind == "auth":
            return _session_expired_response(request, "upstream")
        if exc.kind == "not_enabled":
            return _error_page(request, exc)
        return _approval_redirect(request, return_to, _approval_error_payload(exc, names))

    results = result.get("results") if isinstance(result, dict) else None
    protected = []
    for entry in results if isinstance(results, list) else []:
        if not isinstance(entry, dict) or entry.get("protected_warning") is not True:
            continue
        index = entry.get("index")
        match = entry.get("protected") if isinstance(entry.get("protected"), dict) else {}
        label = (
            names[index] if type(index) is int and 0 <= index < len(names) and names[index]
            else " ".join(str(match.get(k) or "") for k in ("vendor", "product_name")).strip()
            or "A selected product"
        )
        category = match.get("category")
        if isinstance(category, str) and category:
            label = f"{label} ({_protected_category_label(category)})"
        protected.append(label)
    changed = result.get("changed_count") if isinstance(result, dict) else None
    return _approval_redirect(request, return_to, {
        "state": state,
        "requested": len(items),
        "changed": changed if type(changed) is int else None,
        "protected": protected[:20],
        "resolved_alerts": _resolved_alert_count(results),
        # A protected-product warning must be read, so it wins over the
        # next-row anchor.
    }, anchor=None if protected else return_anchor)


# ── Device retirement and the customer device list (PAT-2135) ─────────────
# Self-service replacements for the old "Tell us it's gone"/"Ask us to
# check" mailto links (PAT-1642) and the "send us a device list" placeholder
# card: the customer records the decision directly - nobody at Patched acts
# on their behalf (rubric C1). Guarded exactly like the software approval
# write above: Origin + session-bound CSRF via _guarded_form, then admin
# role, checked here before the platform is asked (which enforces the same
# thing server-side: 403 admin_role_required). See contracts/portal-api.md
# "Device retirement and the customer device list (PAT-2135)". Neither
# write route takes a {device_id} path parameter - device_id travels as a
# plain form field instead, so both stay static paths that
# tests/test_pat2105_csrf.py's app.routes enumeration can exercise directly.
RETIREMENT_MAX_REASON_CHARS = 500
DEVICE_RESULT_PARAM = "device_result"
DEVICE_LIST_MAX_BODY_BYTES = 2 * 1024 * 1024  # platform's own 2 MiB cap
DEVICE_LIST_UPLOAD_MAX_BYTES = DEVICE_LIST_MAX_BODY_BYTES + 8 * 1024  # multipart framing overhead
DEVICE_LIST_MAX_ROWS = 10000
DEVICE_LIST_MAX_FIELD_CHARS = 255
DEVICE_LIST_HOSTNAME_HEADERS = {"hostname", "host name", "device name", "computer name", "name"}
DEVICE_LIST_SERIAL_HEADERS = {"serial", "serial number", "serialnumber"}
DEVICE_RETURN_RE = re.compile(r"^/devices/[^/?#]+$")


def _device_return_to(raw: str, device_id: str) -> str:
    """Where to send the browser after a retirement write: back to
    /devices, or back to the one device's own page - never anywhere else.
    Mirrors _approval_return_to's shape (safe_return_to first, then a
    strict path allowlist, then carry the rest of the query string minus
    our own result param)."""
    fallback = f"/devices/{quote(device_id, safe='')}"
    target = safe_return_to(raw) or fallback
    parts = urlsplit(target)
    path = parts.path if (
        parts.path == "/devices" or DEVICE_RETURN_RE.fullmatch(parts.path)
    ) else fallback
    query = [(k, v) for k, v in parse_qs(parts.query, keep_blank_values=True).items()
             if k != DEVICE_RESULT_PARAM]
    flat = [(k, item) for k, values in query for item in values]
    return path + ("?" + urlencode(flat) if flat else "")


def _device_redirect(request: Request, return_to: str, payload: dict) -> RedirectResponse:
    token = _sign_flash(request.state.jwt, payload)
    separator = "&" if "?" in return_to else "?"
    url = f"{return_to}{separator}{DEVICE_RESULT_PARAM}={quote(token, safe='')}#device-result"
    return RedirectResponse(url=url, status_code=303)


def _device_flash_view(data: dict | None) -> dict | None:
    if not data:
        return None

    def text(key, limit=400):
        value = data.get(key)
        return value[:limit] if isinstance(value, str) else ""

    return {"error": text("error"), "notice": text("notice")}


DEVICE_ERROR_MESSAGES = {
    "admin_role_required": (
        "Only an administrator on your account can retire or reactivate a device. "
        "Nothing was changed."
    ),
}


def _device_error_payload(exc: upstream.UpstreamError) -> dict:
    if exc.kind == "unavailable":
        return {"error": (
            "The Patched platform could not be reached, so this change may not have been "
            "saved. Refresh the page to check before trying again."
        )}
    try:
        body = json.loads(exc.body) if exc.body else {}
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    code = body.get("error") if isinstance(body.get("error"), str) else ""
    message = body.get("message") if isinstance(body.get("message"), str) else ""
    headline = DEVICE_ERROR_MESSAGES.get(code) or (
        (message[:300] + " Nothing was changed.") if message
        else "The Patched platform refused this change. Nothing was changed."
    )
    return {"error": headline}


@app.post("/devices/jamf/setup")
async def devices_jamf_setup_put(request: Request):
    """PAT-2145: turn the optional ComputerCheckIn webhook event on or off,
    and/or forget the pinned Jamf Pro instance after a planned move. Admin
    only, guarded like every other write here (_guarded_form: size cap,
    then Origin, then CSRF)."""
    form, refusal = await _guarded_form(
        request, "devices_jamf_setup_put", max_bytes=JAMF_SETUP_MAX_BODY_BYTES)
    if refusal is not None:
        return refusal
    try:
        role = await run_in_threadpool(_portal_role, request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if role != "admin":
        return _approval_refusal(
            request, 403,
            "Only an administrator on your account can change the Jamf webhook settings.")

    check_in_values = form.get("check_in_enabled", [])
    reset_values = form.get("reset_jamf_instance", [])
    if len(check_in_values) > 1 or len(reset_values) > 1:
        return _approval_refusal(request, 400, "That request could not be read.")
    payload: dict = {}
    if check_in_values:
        if check_in_values[0] not in ("true", "false"):
            return _approval_refusal(request, 400, "That request could not be read.")
        payload["check_in_enabled"] = check_in_values[0] == "true"
    if reset_values:
        if reset_values[0] != "true":
            return _approval_refusal(request, 400, "That request could not be read.")
        payload["reset_jamf_instance"] = True
    if not payload:
        return _approval_refusal(request, 400, "That request could not be read.")

    try:
        result = await run_in_threadpool(
            upstream.put_json, "/v1/portal/mdm/jamf/setup", request.state.jwt, payload)
    except upstream.UpstreamError as exc:
        logger.warning("portal.devices_jamf_setup_put.upstream_refused kind=%s status=%s",
                       exc.kind, exc.status)
        if exc.kind == "auth":
            return _session_expired_response(request, "upstream")
        if exc.kind == "not_enabled":
            return _error_page(request, exc)
        return _jamf_redirect(
            request, _jamf_error_payload(exc, "change the Jamf webhook settings"),
            "/devices/jamf/setup")

    changed = result.get("changed") if isinstance(result, dict) else None
    notice = "Jamf settings updated." if changed else "Nothing changed."
    return _jamf_redirect(request, {"notice": notice}, "/devices/jamf/setup")


@app.post("/devices/jamf/token")
async def devices_jamf_token_create(request: Request):
    """PAT-2145: create the tenant's Jamf webhook connector and its first
    token, or rotate the existing one. Security-critical: the plaintext
    token is returned to the browser exactly once, directly in this
    response's own body - never via a redirect, a flash, a query string or
    the session (main.py never persists it; upstream stores only its
    SHA-256), and it is never logged (the warning below logs only kind/
    status on failure, never the response body). Cache-Control: no-store
    plus Pragma: no-cache for older HTTP/1.0 caches, so no proxy, browser
    cache or history snapshot can retain it either."""
    form, refusal = await _guarded_form(request, "devices_jamf_token_create")
    if refusal is not None:
        return refusal
    try:
        role = await run_in_threadpool(_portal_role, request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if role != "admin":
        return _approval_refusal(
            request, 403,
            "Only an administrator on your account can create or rotate the Jamf webhook token.")

    try:
        result = await run_in_threadpool(
            upstream.post_json, "/v1/portal/mdm/jamf/token", request.state.jwt, None)
    except upstream.UpstreamError as exc:
        logger.warning("portal.devices_jamf_token_create.upstream_refused kind=%s status=%s",
                       exc.kind, exc.status)
        if exc.kind == "auth":
            return _session_expired_response(request, "upstream")
        if exc.kind == "not_enabled":
            return _error_page(request, exc)
        return _jamf_redirect(
            request, _jamf_error_payload(exc, "create or rotate the Jamf webhook token"),
            "/devices/jamf/setup")

    token_ok = isinstance(result, dict) and isinstance(result.get("token"), str) and result["token"]
    if not token_ok:
        return _approval_refusal(
            request, 502, "The Patched platform did not return a token. Try again.")

    setup = result.get("setup") if isinstance(result.get("setup"), dict) else {}
    resp = _render(request, "devices_jamf_setup.html", {
        "title": "Jamf setup", "nav": "devices",
        "setup": setup, "can_edit": True, "role_unavailable": False,
        # Do not put the one-time token at risk by making a follow-up coverage
        # request before returning it. The normal GET shows authoritative
        # connector health after the admin has copied the token into Jamf Pro.
        "connector": None, "connector_unavailable": False,
        "jamf_result": None,
        "token_reveal": {
            "action": result.get("action") or "token_created",
            "token": result["token"],
            "webhook_url": result.get("webhook_url") or "",
            "note": result.get("note") or "",
        },
    })
    # PAT-2145: belt-and-braces on top of the platform's own no-store header
    # (portal_jamf_coverage.go) - this response must never be cached by any
    # intermediary. The template also clears the reveal on history navigation.
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.post("/devices/jamf/token/revoke")
async def devices_jamf_token_revoke(request: Request):
    """PAT-2145: revoke the Jamf webhook token. This also deletes the Jamf
    device records first seen under it (anything a leaked token could have
    fabricated) - the confirm panel in the template warns of this plainly
    before the form can be submitted."""
    form, refusal = await _guarded_form(request, "devices_jamf_token_revoke")
    if refusal is not None:
        return refusal
    try:
        role = await run_in_threadpool(_portal_role, request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if role != "admin":
        return _approval_refusal(
            request, 403,
            "Only an administrator on your account can revoke the Jamf webhook token.")

    try:
        result = await run_in_threadpool(
            upstream.delete_json, "/v1/portal/mdm/jamf/token", request.state.jwt)
    except upstream.UpstreamError as exc:
        logger.warning("portal.devices_jamf_token_revoke.upstream_refused kind=%s status=%s",
                       exc.kind, exc.status)
        if exc.kind == "auth":
            return _session_expired_response(request, "upstream")
        if exc.kind == "not_enabled":
            return _error_page(request, exc)
        return _jamf_redirect(
            request, _jamf_error_payload(exc, "revoke the Jamf webhook token"),
            "/devices/jamf/setup")

    note = (result.get("note") if isinstance(result, dict) and isinstance(result.get("note"), str)
           else None)
    return _jamf_redirect(request, {"notice": note or "Token revoked."}, "/devices/jamf/setup")


@app.post("/devices/jamf/devices/purge")
async def devices_jamf_devices_purge(request: Request):
    """PAT-2145: delete every Mac Jamf has reported for the tenant. The
    connector, token and webhook URL are kept; the lists refill from
    Jamf's next events."""
    form, refusal = await _guarded_form(request, "devices_jamf_devices_purge")
    if refusal is not None:
        return refusal
    try:
        role = await run_in_threadpool(_portal_role, request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if role != "admin":
        return _approval_refusal(
            request, 403,
            "Only an administrator on your account can delete the Jamf device records.")

    try:
        result = await run_in_threadpool(
            upstream.delete_json, "/v1/portal/mdm/jamf/devices", request.state.jwt)
    except upstream.UpstreamError as exc:
        logger.warning("portal.devices_jamf_devices_purge.upstream_refused kind=%s status=%s",
                       exc.kind, exc.status)
        if exc.kind == "auth":
            return _session_expired_response(request, "upstream")
        if exc.kind == "not_enabled":
            return _error_page(request, exc)
        return _jamf_redirect(
            request, _jamf_error_payload(exc, "delete the Jamf device records"),
            "/devices/jamf/setup")

    n = result.get("devices_deleted") if isinstance(result, dict) else None
    notice = (f"Deleted {n} Jamf device record{'' if n == 1 else 's'}."
             if type(n) is int else "Jamf device records deleted.")
    return _jamf_redirect(request, {"notice": notice}, "/devices/jamf/setup")


@app.post("/devices/retirement")
async def device_retirement(request: Request):
    """PAT-2135: customer self-service retire/unretire, replacing the old
    "Tell us it's gone"/"Ask us to check" mailto links (PAT-1642). Same
    guard order as /software/approvals: size cap, Origin, CSRF
    (_guarded_form), then role, admin only."""
    form, refusal = await _guarded_form(request, "device_retirement")
    if refusal is not None:
        return refusal

    device_ids = form.get("device_id", [])
    if len(device_ids) != 1 or not device_ids[0]:
        return _approval_refusal(request, 400, "That request could not be read.")
    device_id = device_ids[0]
    return_to = _device_return_to((form.get("return_to") or [""])[0], device_id)

    try:
        role = await run_in_threadpool(_portal_role, request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if role != "admin":
        return _approval_refusal(
            request, 403, "Only an administrator on your account can retire or reactivate a "
            "device. Your account can view its retirement history.")

    retired_values = form.get("retired", [])
    if len(retired_values) != 1 or retired_values[0] not in ("true", "false"):
        return _approval_refusal(request, 400, "That request could not be read.")
    retired = retired_values[0] == "true"

    reasons = form.get("reason", [""])
    if len(reasons) > 1:
        return _approval_refusal(request, 400, "That request could not be read.")
    reason = reasons[0].strip()
    if "\x00" in reason:
        return _approval_refusal(request, 400, "That request could not be read.")
    if len(reason) > RETIREMENT_MAX_REASON_CHARS:
        return _device_redirect(request, return_to, {
            "error": f"The reason can be at most {RETIREMENT_MAX_REASON_CHARS} characters. "
                     "Nothing was changed."})

    payload: dict = {"retired": retired}
    if reason:
        payload["reason"] = reason
    try:
        result = await run_in_threadpool(
            upstream.put_json,
            f"/v1/portal/devices/{quote(device_id, safe='')}/retirement",
            request.state.jwt, payload,
        )
    except upstream.UpstreamError as exc:
        logger.warning("portal.device_retirement.upstream_refused kind=%s status=%s",
                       exc.kind, exc.status)
        if exc.kind == "auth":
            return _session_expired_response(request, "upstream")
        if exc.kind == "not_enabled":
            return _error_page(request, exc)
        if exc.kind == "not_found":
            return _approval_refusal(request, 404, "That device could not be found.")
        return _device_redirect(request, return_to, _device_error_payload(exc))

    changed = result.get("changed") if isinstance(result, dict) else None
    if changed is False:
        notice = "That device is already " + ("retired." if retired else "active.")
    elif retired:
        notice = "Device retired. It stays on your roster and in every report, marked retired."
    else:
        notice = "Device returned to active."
    return _device_redirect(request, return_to, {"notice": notice})


def _device_list_decode(raw: bytes) -> str:
    """Decode an uploaded CSV: UTF-8 (tolerating a leading BOM) first,
    falling back to cp1252 - the common "Excel CSV" export encoding -
    rather than failing outright on an ordinary spreadsheet export."""
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("cp1252")


def _device_list_header_index(header: list) -> tuple:
    """Case-insensitive header match for a hostname-like column and an
    optional serial column. Returns (hostname_idx, serial_idx, error) -
    error is set (both indexes None) only when neither is recognisable."""
    normalised = [str(c).strip().lower() for c in header]
    hostname_idx = next(
        (i for i, c in enumerate(normalised) if c in DEVICE_LIST_HOSTNAME_HEADERS), None)
    serial_idx = next(
        (i for i, c in enumerate(normalised) if c in DEVICE_LIST_SERIAL_HEADERS), None)
    if hostname_idx is None and serial_idx is None:
        return None, None, (
            "That file has no column named Hostname (or Device name/Computer name) or "
            "Serial, so nothing could be read. Add a header row with one of those names."
        )
    return hostname_idx, serial_idx, None


def parse_device_list_csv(raw: bytes) -> tuple:
    """Parse an uploaded device-list CSV in the portal (PAT-2135), using
    Python's csv module: cap the file size before parsing, accept a header
    row naming a hostname-like column and/or a serial column
    (case-insensitive), decode UTF-8 with BOM first and fall back to
    cp1252, and skip blank rows. Returns (entries, entry_lines, error) -
    error is set (entries/entry_lines []) on any problem. entry_lines is
    the same length and order as entries: entry_lines[i] is the 1-based
    line in the original file entries[i] came from (via csv.reader's own
    line_num, so it stays correct across a skipped blank row and an
    embedded newline inside a quoted field) - used to map a platform
    invalid_entry row index back to a line the customer can actually find,
    rather than assuming no row was ever skipped."""
    if len(raw) > DEVICE_LIST_MAX_BODY_BYTES:
        return [], [], "That file is larger than 2 MiB. Export a smaller list and try again."
    try:
        text = _device_list_decode(raw)
    except UnicodeDecodeError:
        return [], [], (
            "That file could not be read as text. Save it as CSV (UTF-8) and try again."
        )
    reader = csv.reader(io.StringIO(text))
    try:
        header = next(reader)
    except StopIteration:
        return [], [], "That file is empty."
    hostname_idx, serial_idx, error = _device_list_header_index(header)
    if error:
        return [], [], error
    entries = []
    entry_lines = []
    for row in reader:
        if not any(str(cell).strip() for cell in row):
            continue  # blank row
        hostname = (
            row[hostname_idx].strip() if hostname_idx is not None and hostname_idx < len(row)
            else ""
        )
        serial = (
            row[serial_idx].strip() if serial_idx is not None and serial_idx < len(row) else ""
        )
        if not hostname and not serial:
            continue
        entry = {}
        if hostname:
            entry["hostname"] = hostname[:DEVICE_LIST_MAX_FIELD_CHARS]
        if serial:
            entry["serial"] = serial[:DEVICE_LIST_MAX_FIELD_CHARS]
        entries.append(entry)
        entry_lines.append(reader.line_num)
        if len(entries) > DEVICE_LIST_MAX_ROWS:
            return [], [], (
                f"That file has more than {DEVICE_LIST_MAX_ROWS:,} rows. Split it and upload "
                "in parts."
            )
    if not entries:
        return [], [], "That file has no rows to upload."
    return entries, entry_lines, None


async def _guarded_multipart_form(request: Request, event: str):
    """Like _guarded_form (PAT-2105: size cap, then Origin, then CSRF) but
    for the one multipart/form-data POST on this surface, the device-list
    CSV upload - _guarded_form's parse_qs cannot read a file field.
    Content-Length is checked before Starlette reads anything off the
    wire. A real browser form upload always sends one; without it,
    Starlette's request.form() would spool an unbounded body to disk
    before any size cap of ours ever ran, so a missing Content-Length is
    refused outright here (411) rather than treated as "no limit given" -
    the uploaded file's own bytes are still capped again by the caller for
    defence in depth, but that check must never be the only one."""
    declared_length = request.headers.get("content-length")
    too_large_message = "That upload was too large. CSV files up to 2 MiB are accepted."
    no_length_message = "That upload could not be read. Try again from the Devices page."
    if declared_length is None:
        return None, _approval_refusal(request, 411, no_length_message)
    try:
        if int(declared_length) > DEVICE_LIST_UPLOAD_MAX_BYTES:
            return None, _approval_refusal(request, 413, too_large_message)
    except ValueError:
        return None, _approval_refusal(request, 400, "That request could not be read.")
    if not _same_origin(request):
        logger.warning("portal.%s.refused reason=origin", event)
        return None, _approval_refusal(request, 403, _STATE_CHANGE_ORIGIN_REFUSAL)
    try:
        form = await request.form(max_files=2, max_fields=8)
    except Exception:
        return None, _approval_refusal(request, 400, "That request could not be read.")
    csrf_value = form.get(CSRF_FIELD)
    if not isinstance(csrf_value, str) or not _csrf_valid(request, csrf_value):
        logger.warning("portal.%s.refused reason=csrf", event)
        return None, _approval_refusal(request, 403, _STATE_CHANGE_CSRF_REFUSAL)
    return form, None


# PAT-2216: the CSRF token is bound to the Cloudflare Access assertion, so a
# Feedback form left open while Access renews the session carries a token
# that no longer matches. That refusal must never cost the customer what
# they typed: the modal gets a fresh token back and retries once, and the
# no-JavaScript form is re-rendered with the draft and a fresh token. The
# fresh token is only ever returned after the Origin check has passed, to a
# request that already carries a verified session - the same token any GET
# of any portal page renders into its forms.
_FEEDBACK_EXPIRED_REFUSAL = (
    "This page has expired, so your feedback has not been sent yet. Your details are "
    "still here: check them and press Send feedback again."
)


class _FeedbackRefusal(NamedTuple):
    status: int
    message: str
    expired: bool = False


async def _guarded_feedback_form(request: Request):
    """Apply the portal's write guards before parsing a feedback upload.

    The 5 MiB screenshot allowance includes a small fixed multipart margin.
    Rejecting a missing Content-Length prevents Starlette from spooling an
    unbounded upload before the route can enforce its own limit. Returns
    (form, refusal). An expired token is the one refusal that still returns
    the parsed form, so the route can hand the customer's draft back.
    """
    declared_length = request.headers.get("content-length")
    if declared_length is None:
        return None, _FeedbackRefusal(
            411, "That feedback could not be read. Reload the page and try again."
        )
    try:
        if int(declared_length) > FEEDBACK_UPLOAD_MAX_BYTES:
            return None, _FeedbackRefusal(413, "Screenshots up to 5 MiB are accepted.")
    except ValueError:
        return None, _FeedbackRefusal(400, "That feedback could not be read.")
    if not _same_origin(request):
        logger.warning("portal.feedback.refused reason=origin")
        return None, _FeedbackRefusal(403, _STATE_CHANGE_ORIGIN_REFUSAL)
    try:
        form = await request.form(max_files=1, max_fields=8)
    except Exception:
        return None, _FeedbackRefusal(400, "That feedback could not be read.")
    csrf_value = form.get(CSRF_FIELD)
    if not isinstance(csrf_value, str) or not _csrf_valid(request, csrf_value):
        logger.warning("portal.feedback.refused reason=csrf")
        return form, _FeedbackRefusal(403, _FEEDBACK_EXPIRED_REFUSAL, expired=True)
    return form, None


DEVICE_LIST_ERROR_MESSAGES = {
    "admin_role_required": (
        "Only an administrator on your account can change the device list. Nothing was changed."
    ),
    "empty_list": "That file has no rows. To clear your list, use Clear list instead.",
    "too_many_entries": (
        f"That file has more than {DEVICE_LIST_MAX_ROWS:,} rows. Split it and upload in parts."
    ),
    "invalid_filename": "That file name could not be used. Rename the file and try again.",
    "body_too_large": "That file is larger than 2 MiB. Export a smaller list and try again.",
}


def _device_list_error_payload(
    exc: upstream.UpstreamError, entry_lines: list | None = None,
) -> dict:
    """entry_lines maps the entries the portal actually sent (in the same
    order) back to their real 1-based line in the uploaded file (see
    parse_device_list_csv) - used to turn the platform's own 0-based
    `items[].index` into a line the customer can actually find, correct
    even when a blank row was skipped ahead of it. None (the device-list
    clear route shares this function but never uploads entries) falls
    back to the old header-plus-index guess."""
    if exc.kind == "unavailable":
        return {"error": (
            "The Patched platform could not be reached, so this upload may not have been "
            "saved. Refresh the page to check before trying again."
        )}
    try:
        body = json.loads(exc.body) if exc.body else {}
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    code = body.get("error") if isinstance(body.get("error"), str) else ""
    message = body.get("message") if isinstance(body.get("message"), str) else ""
    if code == "invalid_entry":
        items = body.get("items") if isinstance(body.get("items"), list) else []
        first = items[0] if items and isinstance(items[0], dict) else {}
        index = first.get("index")
        reason = first.get("message") if isinstance(first.get("message"), str) else message
        if type(index) is int and entry_lines is not None and 0 <= index < len(entry_lines):
            row = f"row {entry_lines[index]} of your file"
        elif type(index) is int:
            row = f"row {index + 2} of your file"
        else:
            row = "a row in your file"
        return {"error": (
            f"There is a problem with {row}: {reason[:200] if reason else 'invalid entry'}. "
            "Nothing was uploaded."
        )}
    headline = DEVICE_LIST_ERROR_MESSAGES.get(code) or (
        (message[:300] + " Nothing was changed.") if message
        else "The Patched platform refused this upload. Nothing was changed."
    )
    return {"error": headline}


@app.post("/devices/device-list")
async def device_list_upload(request: Request):
    """PAT-2135: customer self-service device-list upload, replacing the
    old "send us a device list" placeholder. The portal parses the CSV
    (parse_device_list_csv, Python's csv module) and sends structured JSON
    upstream - the platform validates, stores it and does the
    reconciliation. Admin only, guarded like every other write here."""
    form, refusal = await _guarded_multipart_form(request, "device_list_upload")
    if refusal is not None:
        return refusal
    try:
        role = await run_in_threadpool(_portal_role, request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if role != "admin":
        return _approval_refusal(
            request, 403, "Only an administrator on your account can upload a device list. "
            "Nothing was changed.")

    upload = form.get("device_list_file")
    if upload is None or not getattr(upload, "filename", ""):
        return _device_redirect(request, "/devices", {
            "error": "Choose a CSV file first. Nothing was uploaded."})
    raw = await upload.read(DEVICE_LIST_MAX_BODY_BYTES + 1)
    if len(raw) > DEVICE_LIST_MAX_BODY_BYTES:
        return _device_redirect(request, "/devices", {
            "error": "That file is larger than 2 MiB. Export a smaller list and try again."})
    entries, entry_lines, error = parse_device_list_csv(raw)
    if error:
        return _device_redirect(request, "/devices", {"error": error})

    filename = Path(upload.filename).name[:DEVICE_LIST_MAX_FIELD_CHARS]
    payload = {"filename": filename, "entries": entries}
    try:
        result = await run_in_threadpool(
            upstream.put_json, "/v1/portal/device-list", request.state.jwt, payload)
    except upstream.UpstreamError as exc:
        logger.warning("portal.device_list_upload.upstream_refused kind=%s status=%s",
                       exc.kind, exc.status)
        if exc.kind == "auth":
            return _session_expired_response(request, "upstream")
        if exc.kind == "not_enabled":
            return _error_page(request, exc)
        return _device_redirect(
            request, "/devices", _device_list_error_payload(exc, entry_lines))

    stored_list = result.get("list") if isinstance(result, dict) else None
    count = stored_list.get("entry_count") if isinstance(stored_list, dict) else None
    notice = (
        f"Device list uploaded: {count} device{'' if count == 1 else 's'}."
        if type(count) is int else "Device list uploaded."
    )
    return _device_redirect(request, "/devices", {"notice": notice})


@app.post("/devices/device-list/clear")
async def device_list_clear(request: Request):
    """PAT-2135: clears the uploaded device list. Recorded upstream, not
    erased (contracts/portal-api.md); admin only, same guard as every
    other write here."""
    form, refusal = await _guarded_form(request, "device_list_clear")
    if refusal is not None:
        return refusal
    try:
        role = await run_in_threadpool(_portal_role, request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if role != "admin":
        return _approval_refusal(
            request, 403, "Only an administrator on your account can clear the device list. "
            "Nothing was changed.")
    try:
        await run_in_threadpool(
            upstream.delete_json, "/v1/portal/device-list", request.state.jwt)
    except upstream.UpstreamError as exc:
        logger.warning("portal.device_list_clear.upstream_refused kind=%s status=%s",
                       exc.kind, exc.status)
        if exc.kind == "auth":
            return _session_expired_response(request, "upstream")
        if exc.kind == "not_enabled":
            return _error_page(request, exc)
        return _device_redirect(request, "/devices", _device_list_error_payload(exc))
    return _device_redirect(request, "/devices", {"notice": "Device list cleared."})


@app.post("/devices/device-list/entries/{entry_id}")
async def device_list_entry_remove(request: Request, entry_id: str):
    """PAT-2271: customer self-service removal of a single device-list entry
    (a stale or wrong row on the customer's own uploaded list), proxying
    DELETE /v1/portal/device-list/entries/{entryID} - same guard, role and
    error shape as the bulk clear above. The platform's 404 covers an
    unknown id, a cross-tenant id and an id from a superseded upload alike
    (all indistinguishable from "never existed"), which reads to the
    customer as "already removed" rather than an error. entry_id is typed
    str, not int (matching /software/alerts/{alert_id}/acknowledge's own
    precedent), so tests/test_pat2105_csrf.py's generic route enumeration -
    which strips the {braces} from every unsafe route's path template and
    posts to the literal result - reaches this route's own guard instead of
    a framework-level 422 on a non-numeric placeholder."""
    form, refusal = await _guarded_form(request, "device_list_entry_remove")
    if refusal is not None:
        return refusal
    if not entry_id.isdigit():
        return _approval_refusal(request, 400, "That request could not be read.")
    try:
        role = await run_in_threadpool(_portal_role, request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if role != "admin":
        return _approval_refusal(
            request, 403, "Only an administrator on your account can change the device list. "
            "Nothing was changed.")
    try:
        await run_in_threadpool(
            upstream.delete_json, f"/v1/portal/device-list/entries/{entry_id}",
            request.state.jwt,
        )
    except upstream.UpstreamError as exc:
        logger.warning("portal.device_list_entry_remove.upstream_refused kind=%s status=%s",
                       exc.kind, exc.status)
        if exc.kind == "auth":
            return _session_expired_response(request, "upstream")
        if exc.kind == "not_enabled":
            return _error_page(request, exc)
        if exc.kind == "not_found":
            return _device_redirect(request, "/devices", {
                "notice": "That entry has already been removed from your list."})
        return _device_redirect(request, "/devices", _device_list_error_payload(exc))
    return _device_redirect(request, "/devices", {"notice": "Entry removed from your list."})


def _device_list_view(jwt_token: str) -> dict:
    """GET /v1/portal/device-list (every role, PAT-2135) - the upload's
    mirror read: current list meta, the two reconciliation groups (capped
    at 500 rows each per the platform contract), the matched counts and
    the truncated/cleared flags. Fails soft (available: False) rather than
    taking /devices down with it - this card is additive, not primary
    roster data."""
    try:
        data = upstream.get_json("/v1/portal/device-list", jwt_token)
    except upstream.UpstreamError as exc:
        logger.warning("portal.device_list.fail_soft kind=%s", exc.kind)
        return {"available": False, "has_list": False}
    if not isinstance(data, dict):
        return {"available": False, "has_list": False}
    lst = data.get("list") if isinstance(data.get("list"), dict) else None
    cleared = data.get("cleared") if isinstance(data.get("cleared"), dict) else None
    never_seen = (
        data.get("on_list_never_seen") if isinstance(data.get("on_list_never_seen"), list)
        else []
    )
    not_on_list = (
        data.get("seen_not_on_list") if isinstance(data.get("seen_not_on_list"), list) else []
    )
    # PAT-2271: the itemised match list is additive - an upstream still on
    # the old contract simply omits the key, which is distinct from the key
    # being present as an empty list (a real, itemised "nothing matched"
    # state). matched_itemised tells the template which case it is looking
    # at, so a not-yet-upgraded platform still renders the honest
    # count-only fallback rather than a false-empty itemised group.
    matched_raw = data.get("matched")
    if isinstance(matched_raw, list):
        matched = [
            row for row in matched_raw
            if isinstance(row, dict) and isinstance(row.get("device"), dict)
        ]
        matched_itemised = True
    else:
        matched = []
        matched_itemised = False

    def count(key, fallback):
        value = data.get(key)
        return value if type(value) is int else fallback

    return {
        "available": True,
        "has_list": lst is not None,
        "list": lst,
        "cleared": cleared,
        "matched_count": data.get("matched_count") if type(data.get("matched_count")) is int
        else None,
        "matched_retired_count": (
            data.get("matched_retired_count")
            if type(data.get("matched_retired_count")) is int else None
        ),
        "matched": matched,
        "matched_itemised": matched_itemised,
        "never_seen": never_seen[:500],
        "never_seen_total": count("on_list_never_seen_total", len(never_seen)),
        "not_on_list": not_on_list[:500],
        "not_on_list_total": count("seen_not_on_list_total", len(not_on_list)),
        "truncated": bool(data.get("truncated")),
    }


def _history_decision_view(entry: dict) -> dict:
    def state_label(value):
        return APPROVAL_STATE_LABELS.get(value, "State not recognised")

    reason = entry.get("reason")
    actor = entry.get("actor_email")
    return {
        "decided_at": entry.get("decided_at") if isinstance(entry.get("decided_at"), str) else None,
        "actor": actor if isinstance(actor, str) and actor else "Not recorded",
        "previous_label": state_label(entry.get("previous_state")),
        "new_label": state_label(entry.get("new_state")),
        "reason": reason if isinstance(reason, str) and reason else None,
        "protected_warning": entry.get("protected_warning") is True,
    }


PRODUCT_TYPE_LABELS = {
    "application": "Application",
    "browser_extension": "Browser extension",
    "homebrew_formula": "Homebrew formula",
    "homebrew_cask": "Homebrew cask",
    "observation": "AI tool",
}


def _product_identifiers_view(item: dict) -> list[tuple[str, str]]:
    """PAT-2255 defects 3 and 4: the raw identifiers the /software list no
    longer shows (an MSI product code, a bundle id, a Team ID, an extension
    id), labelled, for the product detail's "Identifiers" section. Built
    only from the already-validated approval item, so nothing here is new
    data; it is where the list's identity detail now lives."""
    rows: list[tuple[str, str]] = [
        ("Type", PRODUCT_TYPE_LABELS.get(item.get("type"), "Not recognised")),
    ]
    if item.get("platform"):
        rows.append(("Platform", platform_display(item["platform"])))
    if item.get("identifier"):
        rows.append(("Identifier", item["identifier"]))
    if item.get("team_id"):
        rows.append(("macOS Team ID", item["team_id"]))
    if item.get("browser"):
        rows.append(("Browser", _browser_display(item["browser"])))
    if item.get("extension_id"):
        rows.append(("Extension ID", item["extension_id"]))
    if item.get("type") in ("homebrew_formula", "homebrew_cask"):
        rows.append(("Package", item.get("name") or ""))
        if item.get("tap"):
            rows.append(("Tap", item["tap"]))
    if item.get("identity_kind"):
        rows.append(("Kind", item["identity_kind"].replace("_", " ")))
    if item.get("source"):
        rows.append(("Source", item["source"]))
    return rows


@app.get("/software/history", response_class=HTMLResponse)
def software_history(request: Request, item: str = "", partial: str = ""):
    """PAT-2008: one product's approval history from
    GET /v1/portal/software-approvals/history (PAT-2007): who, when, before,
    after and why. Every portal role may read it. `partial=1` returns only
    the drawer body for the in-page drawer; without it this is a full page,
    which is also the no-JavaScript fallback for the drawer link."""
    template = "_software_history.html" if partial == "1" else "software_history.html"
    try:
        parsed = _parse_approval_item(json.loads(item)) if item and len(item) < 4096 else None
    except ValueError:
        parsed = None
    if parsed is None:
        if partial == "1":
            return HTMLResponse(
                '<p class="empty">That product reference could not be read.</p>',
                status_code=400)
        return _render(request, "error.html", {
            "title": "History not available",
            "message": "That product reference could not be read.",
        }, status_code=400)
    product, name = parsed
    params = {k: v for k, v in product.items()}
    params["limit"] = APPROVAL_HISTORY_LIMIT
    context = {
        "title": f"History for {name}" if name else "Approval history",
        "nav": "software", "product_name": name or "This product",
        "decisions": [], "total": 0, "history_error": False,
        "identifiers": _product_identifiers_view(product),
    }
    try:
        data = upstream.get_json("/v1/portal/software-approvals/history",
                                 request.state.jwt, params=params)
        decisions = upstream.unwrap_list(data, "decisions")
        total = data.get("total") if isinstance(data, dict) else None
        context["decisions"] = [
            _history_decision_view(entry) for entry in decisions if isinstance(entry, dict)
        ]
        context["total"] = total if type(total) is int else len(context["decisions"])
    except upstream.UpstreamError as exc:
        if partial != "1" and exc.kind in ("auth", "forbidden", "not_enabled"):
            return _error_page(request, exc)
        logger.warning("portal.software_history.fail_soft kind=%s", exc.kind)
        context["history_error"] = True
    return _render(request, template, context)


# ── Approved software declared before any endpoint reports it ─────────────
# An admin records that a product is approved before it is installed anywhere.
# The platform owns the declaration, its tenant, its actor and its identity
# state; the portal proxies bounded writes and renders what the platform says.
# Approval is a decision, never proof of installation, trust or compliance,
# and it does not suppress a vulnerability finding. Every write goes through
# _guarded_form (size cap, Origin, CSRF), then a fresh exact-admin role read,
# then an allowlist of form fields: tenant, actor and trust fields a client
# submits are refused, never forwarded. A platform refusal is turned into a
# fixed customer sentence here; its body is never put in the page.
DECLARATION_PLATFORMS = (("macos", "macOS"), ("windows", "Windows"))
DECLARATION_CREATE_FIELDS = frozenset({
    CSRF_FIELD, "name", "publisher", "platform", "justification", "alias_id",
    "min_version", "review_date"})
DECLARATION_RESOLVE_FIELDS = frozenset({CSRF_FIELD, "alias_id", "justification"})
DECLARATION_API = "/v1/portal/software-declarations"
DECLARATION_NAME_MAX_CHARS = 200
DECLARATION_VERSION_MAX_CHARS = 64
DECLARATION_JUSTIFICATION_MAX_CHARS = 1000
DECLARATION_LIST_MAX_ROWS = 200
DECLARATION_HISTORY_MAX_ROWS = 100
DECLARATION_SEARCH_MAX_CHARS = 100
DECLARATION_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
DECLARATION_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
DECLARATION_ACTION_LABELS = {"created": "Added", "resolved": "Matched to a known product"}
DECLARATION_IDENTITY_LABELS = {
    "matched": "Identity matched", "unmatched": "Identity not yet matched"}
DECLARATION_OBSERVATION_LABELS = {"observed": "Observed", "not_observed": "Not observed"}
DECLARATION_MEANING = (
    "Approval records your decision. It does not show that the software is installed, "
    "trusted or compliant, and it does not hide any vulnerability finding.")
DECLARATION_ADDED_NOTICE = (
    "Approved software added. It shows as not observed until an endpoint reports it.")
DECLARATION_RESOLVED_NOTICE = "The approval was matched to the known product you chose."


def _declaration_not_found(request: Request) -> HTMLResponse:
    """An unknown id, another tenant's id (the platform answers 404 or 403)
    and a malformed id all read the same page, so the id is never an
    existence oracle for another tenant's declaration."""
    return _render(request, "error.html", {
        "title": "Not found",
        "message": "That approved software could not be found in your estate.",
    }, status_code=404)


def _declaration_admin_refusal(request: Request) -> HTMLResponse:
    return _approval_refusal(
        request, 403, "Only an administrator on your account can add approved software. "
        "Your account can view approved software and its history.")


def _declaration_text(value, limit: int = DECLARATION_NAME_MAX_CHARS) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def _declaration_view(entry: dict) -> dict | None:
    """One platform declaration as the pages need it. A row with no valid
    id is dropped, since nothing could link to or act on it."""
    declaration_id = entry.get("id") or entry.get("declaration_id")
    if not isinstance(declaration_id, str) or not DECLARATION_UUID_RE.match(declaration_id):
        return None
    identity = entry.get("identity_state")
    observation = entry.get("observation_state")
    count = entry.get("observed_installation_count")
    platform = entry.get("platform")
    return {
        "id": declaration_id,
        "url": f"/software/declarations/{declaration_id}",
        "name": _declaration_text(entry.get("name")) or "Unnamed software",
        "publisher": _declaration_text(entry.get("publisher")),
        "platform": platform if isinstance(platform, str) else "",
        "platform_label": platform_display(platform) if isinstance(platform, str) else "",
        "identity_state": identity if identity in DECLARATION_IDENTITY_LABELS else "",
        "identity_label": DECLARATION_IDENTITY_LABELS.get(identity, "Identity not reported"),
        "observation_state": observation if observation in DECLARATION_OBSERVATION_LABELS else "",
        "observation_label": DECLARATION_OBSERVATION_LABELS.get(
            observation, "Observation not reported"),
        "observed_count": count if type(count) is int and count >= 0 else 0,
        "min_version": _declaration_text(entry.get("min_version"), DECLARATION_VERSION_MAX_CHARS),
        "review_date": _declaration_text(entry.get("review_date"), 10),
        "justification": _declaration_text(
            entry.get("justification"), DECLARATION_JUSTIFICATION_MAX_CHARS),
        "approved_by": _declaration_text(entry.get("approved_by")),
        "approved_at": entry.get("approved_at") if isinstance(
            entry.get("approved_at"), str) else None,
    }


def _declared_not_observed(jwt_token: str) -> tuple[list[dict], int, bool]:
    """The declarations no endpoint has reported yet, for the Software view:
    (rows, total not observed, load failed). Fail-soft: a platform that has
    not rolled the endpoint out yet (404) shows nothing, any other failure
    is reported to the page so it never reads as "nothing declared"."""
    try:
        data = upstream.get_json(DECLARATION_API, jwt_token)
    except upstream.UpstreamError as exc:
        if exc.kind == "not_found":
            return [], 0, False
        logger.warning("portal.software_declarations.fail_soft kind=%s", exc.kind)
        return [], 0, True
    views = [_declaration_view(e) for e in upstream.unwrap_list(data, "declarations")
             if isinstance(e, dict)]
    rows = [v for v in views if v and v["observation_state"] == "not_observed"]
    return rows[:DECLARATION_LIST_MAX_ROWS], len(rows), False


def _known_product_search(jwt_token: str, query: str, platform: str) -> list[dict] | None:
    """The platform's curated product lookup. None means it could not be
    read (shown as such, never as "no matches")."""
    # The platform requires `platform` on every lookup, so "Any" is one
    # lookup per platform, merged. One failing makes the whole answer
    # unreadable rather than a partial list that reads as complete.
    platforms = [platform] if platform else [value for value, _label in DECLARATION_PLATFORMS]
    entries = []
    try:
        for one in platforms:
            data = upstream.get_json("/v1/portal/software-products", jwt_token,
                                     params={"query": query, "platform": one})
            entries.extend(upstream.unwrap_list(data, "products")[:25])
    except upstream.UpstreamError as exc:
        logger.warning("portal.software_products.fail_soft kind=%s", exc.kind)
        return None
    found = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        alias_id = entry.get("alias_id")
        if not isinstance(alias_id, str) or not DECLARATION_UUID_RE.match(alias_id):
            continue
        entry_platform = entry.get("platform")
        found.append({
            "alias_id": alias_id,
            "name": _declaration_text(entry.get("canonical_name")) or "Unnamed product",
            "publisher": _declaration_text(entry.get("vendor_name")),
            "platform": entry_platform if isinstance(entry_platform, str) else "",
            "platform_label": platform_display(entry_platform)
            if isinstance(entry_platform, str) else "",
        })
    return found


def _known_products_offered(jwt_token: str) -> bool:
    """Whether the platform has any known product a declaration could be
    matched to. An empty catalogue and an unreadable one both mean there is
    nothing to offer, so the portal does not show a search that cannot
    succeed."""
    return bool(_known_product_search(jwt_token, "", ""))


def _declaration_platform(raw) -> str:
    return raw if raw in {value for value, _label in DECLARATION_PLATFORMS} else ""


def _single_form_values(form: dict, allowed: frozenset) -> dict | None:
    """One value per field, and nothing outside `allowed`. None refuses the
    request: a client-supplied tenant, actor, key or identity field is never
    ignored quietly or forwarded."""
    if set(form) - allowed or any(len(values) != 1 for values in form.values()):
        return None
    return {key: values[0] for key, values in form.items()}


def _declaration_form_context(*, values: dict, error: str = "", query: str = "",
                              platform: str = "", products: list | None = None,
                              chosen: dict | None = None,
                              lookup_offered: bool = True) -> dict:
    return {
        "lookup_offered": lookup_offered,
        "title": "Add approved software", "nav": "software",
        "platforms": DECLARATION_PLATFORMS, "values": values, "error": error,
        "query": query, "search_platform": platform, "products": products,
        "searched": bool(query), "chosen": chosen, "meaning": DECLARATION_MEANING,
        "name_max": DECLARATION_NAME_MAX_CHARS,
        "version_max": DECLARATION_VERSION_MAX_CHARS,
        "justification_max": DECLARATION_JUSTIFICATION_MAX_CHARS,
    }


@app.get("/software/add", response_class=HTMLResponse)
async def software_add_form(request: Request):
    try:
        role = await run_in_threadpool(_portal_role, request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if role != "admin":
        return _declaration_admin_refusal(request)
    offered = await run_in_threadpool(_known_products_offered, request.state.jwt)
    # With no known product to offer the lookup card is not shown, so any
    # search or preselection in the URL is ignored.
    query = _declaration_text(request.query_params.get("query"),
                              DECLARATION_SEARCH_MAX_CHARS) if offered else ""
    platform = _declaration_platform(
        request.query_params.get("platform", "")) if offered else ""
    products = None
    chosen = None
    if query:
        products = await run_in_threadpool(
            _known_product_search, request.state.jwt, query, platform)
        wanted = request.query_params.get("alias_id", "")
        # A known product is only ever taken from the platform's own answer
        # to this search, never from the URL.
        chosen = next((p for p in products or [] if p["alias_id"] == wanted), None)
    values = {"name": "", "publisher": "", "platform": platform, "justification": "",
              "min_version": "", "review_date": ""}
    if chosen:
        values.update(name=chosen["name"], publisher=chosen["publisher"],
                      platform=chosen["platform"] or platform)
    return _render(request, "software_add.html", _declaration_form_context(
        values=values, query=query, platform=platform, products=products, chosen=chosen,
        lookup_offered=offered))


def _declaration_payload(fields: dict) -> tuple[dict | None, str]:
    """Validate a create submission. Returns (payload, "") or (None, reason)."""
    name = fields.get("name", "").strip()
    publisher = fields.get("publisher", "").strip()
    justification = fields.get("justification", "").strip()
    platform = fields.get("platform", "")
    alias_id = fields.get("alias_id", "").strip()
    min_version = fields.get("min_version", "").strip()
    review_date = fields.get("review_date", "").strip()
    if not name or len(name) > DECLARATION_NAME_MAX_CHARS:
        return None, f"Enter the software name, up to {DECLARATION_NAME_MAX_CHARS} characters."
    if not publisher or len(publisher) > DECLARATION_NAME_MAX_CHARS:
        return None, f"Enter the publisher, up to {DECLARATION_NAME_MAX_CHARS} characters."
    if not _declaration_platform(platform):
        return None, "Choose macOS or Windows."
    if not justification or len(justification) > DECLARATION_JUSTIFICATION_MAX_CHARS:
        return None, ("Give a reason for approving it, up to "
                      f"{DECLARATION_JUSTIFICATION_MAX_CHARS} characters.")
    if "\x00" in name + publisher + justification + min_version:
        return None, "That text contains characters that cannot be saved."
    if len(min_version) > DECLARATION_VERSION_MAX_CHARS:
        return None, "The minimum version is too long."
    if alias_id and not DECLARATION_UUID_RE.match(alias_id):
        return None, "Choose the known product again."
    if review_date:
        try:
            datetime.strptime(review_date, "%Y-%m-%d")
            valid_date = bool(DECLARATION_DATE_RE.match(review_date))
        except ValueError:
            valid_date = False
        if not valid_date:
            return None, "Enter the review date as year-month-day, for example 2027-03-31."
    payload = {"name": name, "publisher": publisher, "platform": platform,
               "justification": justification}
    if alias_id:
        payload["alias_id"] = alias_id
    if min_version:
        payload["min_version"] = min_version
    if review_date:
        payload["review_date"] = review_date
    return payload, ""


@app.post("/software/add")
async def software_add(request: Request):
    form, refusal = await _guarded_form(request, "software_add")
    if refusal is not None:
        return refusal
    try:
        role = await run_in_threadpool(_portal_role, request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if role != "admin":
        return _declaration_admin_refusal(request)
    fields = _single_form_values(form, DECLARATION_CREATE_FIELDS)
    if fields is None:
        return _approval_refusal(request, 400, "That request could not be read.")
    payload, problem = _declaration_payload(fields)
    drafts = {key: fields.get(key, "") for key in (
        "name", "publisher", "platform", "justification", "min_version", "review_date")}

    def again(message: str, status_code: int) -> HTMLResponse:
        # No lookup card on the error re-render: it would need another
        # upstream check, and the drafts are what the admin needs back.
        return _render(request, "software_add.html", _declaration_form_context(
            values=drafts, error=message, lookup_offered=False), status_code=status_code)

    if payload is None:
        return again(problem, 400)
    try:
        await run_in_threadpool(
            upstream.post_json, DECLARATION_API, request.state.jwt, payload)
    except upstream.UpstreamError as exc:
        logger.warning("portal.software_add.upstream_refused kind=%s status=%s",
                       exc.kind, exc.status)
        if exc.kind == "auth":
            return _session_expired_response(request, "upstream")
        if exc.kind == "not_enabled":
            return _error_page(request, exc)
        if exc.kind == "forbidden":
            return _declaration_admin_refusal(request)
        if exc.status == 409:
            return again("This software is already approved for your estate. "
                         "Nothing was changed.", 409)
        if exc.status == 422:
            return again("The known product you chose could not be used for this approval. "
                         "Search again, or add the software by name. Nothing was changed.", 422)
        if exc.kind == "invalid":
            return again("Patched could not accept those details. Check them and try again. "
                         "Nothing was changed.", 400)
        return again("The Patched platform could not be reached, so this may not have been "
                     "saved. Check the Software page before trying again.", 502)
    return _approval_redirect(request, "/software", {"notice": DECLARATION_ADDED_NOTICE})


def _declaration_detail_context(request: Request, declaration_id: str,
                                can_edit: bool, flash: dict | None) -> dict | HTMLResponse:
    """Everything the detail page needs, or the not-found / error page."""
    jwt_token = request.state.jwt
    try:
        data = upstream.get_json(f"{DECLARATION_API}/{declaration_id}", jwt_token)
    except upstream.UpstreamError as exc:
        if exc.kind in ("not_found", "forbidden", "invalid"):
            return _declaration_not_found(request)
        return _error_page(request, exc)
    declaration = _declaration_view(data) if isinstance(data, dict) else None
    if declaration is None:
        return _declaration_not_found(request)
    history, history_error = [], False
    try:
        raw = upstream.get_json(f"{DECLARATION_API}/{declaration_id}/history", jwt_token)
        for entry in upstream.unwrap_list(raw, "decisions")[:DECLARATION_HISTORY_MAX_ROWS]:
            if not isinstance(entry, dict):
                continue
            actor = entry.get("actor_email")
            reason = entry.get("justification")
            history.append({
                "action": DECLARATION_ACTION_LABELS.get(entry.get("action"), "Changed"),
                "actor": actor if isinstance(actor, str) and actor else "Not recorded",
                "decided_at": entry.get("decided_at") if isinstance(
                    entry.get("decided_at"), str) else None,
                "reason": reason if isinstance(reason, str) and reason else None,
            })
    except upstream.UpstreamError as exc:
        logger.warning("portal.software_declaration_history.fail_soft kind=%s", exc.kind)
        history_error = True
    products = None
    query = _declaration_text(request.query_params.get("query"), DECLARATION_SEARCH_MAX_CHARS)
    query = query or declaration["name"][:DECLARATION_SEARCH_MAX_CHARS]
    # None: no match card (not an admin, or already matched). True: the card
    # with its search. False: nothing to match to yet, so a plain statement.
    match_offered = None
    if can_edit and declaration["identity_state"] == "unmatched":
        match_offered = _known_products_offered(jwt_token)
        if match_offered:
            products = _known_product_search(
                jwt_token, query, _declaration_platform(declaration["platform"]))
    return {
        "match_offered": match_offered,
        "query": query,
        "title": "Approved software", "nav": "software",
        "declaration": declaration, "history": history, "history_error": history_error,
        "can_edit": can_edit, "products": products, "meaning": DECLARATION_MEANING,
        "justification_max": DECLARATION_JUSTIFICATION_MAX_CHARS,
        "flash": _approval_flash_view(flash),
    }


@app.get("/software/declarations/{declaration_id}", response_class=HTMLResponse)
async def software_declaration_detail(request: Request, declaration_id: str):
    if not DECLARATION_UUID_RE.match(declaration_id):
        return _declaration_not_found(request)
    try:
        role = await run_in_threadpool(_portal_role, request.state.jwt)
    except upstream.UpstreamError as exc:
        logger.warning("portal.software_declaration.role_fail_soft kind=%s", exc.kind)
        role = "viewer"
    flash = _read_flash(request.state.jwt, request.query_params.get(APPROVAL_RESULT_PARAM, ""))
    context = await run_in_threadpool(
        _declaration_detail_context, request, declaration_id, role == "admin", flash)
    if isinstance(context, HTMLResponse):
        return context
    return _render(request, "software_declaration.html", context)


@app.post("/software/declarations/{declaration_id}/resolve")
async def software_declaration_resolve(request: Request, declaration_id: str):
    form, refusal = await _guarded_form(request, "software_declaration_resolve")
    if refusal is not None:
        return refusal
    try:
        role = await run_in_threadpool(_portal_role, request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if role != "admin":
        return _declaration_admin_refusal(request)
    if not DECLARATION_UUID_RE.match(declaration_id):
        return _declaration_not_found(request)
    fields = _single_form_values(form, DECLARATION_RESOLVE_FIELDS)
    if fields is None:
        return _approval_refusal(request, 400, "That request could not be read.")
    detail_url = f"/software/declarations/{declaration_id}"
    alias_id = fields.get("alias_id", "").strip()
    justification = fields.get("justification", "").strip()
    if not DECLARATION_UUID_RE.match(alias_id):
        return _approval_redirect(request, detail_url, {
            "error": "Choose the known product this software matches. Nothing was changed."})
    if (not justification or len(justification) > DECLARATION_JUSTIFICATION_MAX_CHARS
            or "\x00" in justification):
        return _approval_redirect(request, detail_url, {
            "error": "Give a reason, up to "
                     f"{DECLARATION_JUSTIFICATION_MAX_CHARS} characters. Nothing was changed."})
    try:
        await run_in_threadpool(
            upstream.post_json, f"{DECLARATION_API}/{declaration_id}/resolve",
            request.state.jwt, {"alias_id": alias_id, "justification": justification})
    except upstream.UpstreamError as exc:
        logger.warning("portal.software_declaration_resolve.upstream_refused kind=%s status=%s",
                       exc.kind, exc.status)
        if exc.kind == "auth":
            return _session_expired_response(request, "upstream")
        if exc.kind == "not_enabled":
            return _error_page(request, exc)
        if exc.kind in ("not_found", "forbidden"):
            return _declaration_not_found(request)
        if exc.status == 409:
            message = "This software has already been matched. Nothing was changed."
        elif exc.status == 422:
            message = ("That known product could not be confirmed as the same software yet. "
                       "Nothing was changed.")
        elif exc.kind == "unavailable":
            message = ("The Patched platform could not be reached, so this may not have been "
                       "saved. Refresh the page to check before trying again.")
        else:
            message = "Patched could not accept that match. Nothing was changed."
        return _approval_redirect(request, detail_url, {"error": message})
    return _approval_redirect(request, detail_url, {"notice": DECLARATION_RESOLVED_NOTICE})


# ── Unapproved software alerts (PAT-2097) ─────────────────────────────────
# A separate top-level nav page, not a Software tab: unlike the Software
# governance catalogue (a snapshot of current policy state), this is a
# lifecycle of discrete, timestamped events - raised, acknowledged, resolved,
# re-opened - each with its own filters and paging against the platform's
# own /v1/portal/software-alerts contract. Software.html is already large;
# folding a second server-paginated list with its own filter set into it
# would make both harder to read. GET /v1/portal/software-alerts and
# GET /v1/portal/software-alerts/{id} are open to every portal role;
# POST /v1/portal/software-alerts/{id}/acknowledge is portal admin only,
# behind the same _guarded_form (Origin + CSRF) as PAT-2008/PAT-2105.
ALERT_STATUS_FILTERS = ("open", "acknowledged", "resolved", "all")
ALERT_STATUS_LABELS = {
    "open": "Open", "acknowledged": "Acknowledged", "resolved": "Resolved",
}
ALERT_TRIGGER_LABELS = {
    "marked": "Marked by review",
    "observed": "Observed automatically",
    "baseline": "Present before alert tracking began",
}
ALERT_ACTOR_KIND_LABELS = {"operator": "Patched operator", "system": "System"}
ALERT_NOTE_MAX_CHARS = 1000
ALERT_PAGE_SIZE = 50
ALERT_RESULT_PARAM = "alert_result"
# Bounds for the free-text product/device filter fields - generous enough
# for a real product_key or device UUID, never large enough to matter for
# the request-size guard.
ALERT_FILTER_PRODUCT_MAX_CHARS = 512
ALERT_FILTER_DEVICE_MAX_CHARS = 128


def _alert_product_view(product: dict) -> dict:
    """One alert's product, as the table and detail page need it. `kind`
    feeds the existing software_type_tag() macro (PAT-1643) so an alert row
    carries the identical application/extension tag as every other
    software table, rather than a second label vocabulary."""
    ptype = product.get("type")
    name = None
    for key in ("name", "identifier", "extension_id"):
        value = product.get(key)
        if isinstance(value, str) and value.strip():
            name = value.strip()
            break
    platform = product.get("platform") if ptype == "application" else product.get("browser")
    product_key = product.get("product_key")
    return {
        "kind": "extension" if ptype == "browser_extension" else "application",
        "name": name or "Unknown product",
        "platform": platform if isinstance(platform, str) else "",
        "product_key": product_key if isinstance(product_key, str) else "",
    }


def _alert_device_view(device: dict) -> dict:
    device_id = device.get("device_id")
    hostname = device.get("hostname")
    return {
        "device_id": device_id if isinstance(device_id, str) and device_id else "",
        "hostname": hostname if isinstance(hostname, str) and hostname else "Unknown device",
        "last_seen": device.get("last_seen"),
    }


def _alert_row(raw: dict) -> dict:
    """One GET /v1/portal/software-alerts row (or the detail read's own
    top-level fields), everything the list table and the detail page need.
    can_acknowledge is display-only - the write route re-checks role and
    status on its own, exactly like PAT-2008's approval controls."""
    status = raw.get("status")
    alert_id = raw.get("id")
    product = raw.get("product") if isinstance(raw.get("product"), dict) else {}
    device = raw.get("device") if isinstance(raw.get("device"), dict) else {}
    reopened_count = raw.get("reopened_count")

    def nonempty_str(value):
        return value if isinstance(value, str) and value else None

    return {
        "id": alert_id if type(alert_id) is int else None,
        "status": status,
        "status_label": ALERT_STATUS_LABELS.get(status, "Status not recognised"),
        "trigger_label": ALERT_TRIGGER_LABELS.get(raw.get("trigger"), "Not recorded"),
        "product": _alert_product_view(product),
        "device": _alert_device_view(device),
        "raised_at": raw.get("raised_at"),
        # PAT-2155: the All tab shows one compact "Last updated" column
        # instead of near-empty Raised/Acknowledged/Resolved columns -
        # status_changed_at (contracts/portal-api.md: "most recently
        # changed first within each" status group) is the one timestamp
        # that means something across every status, open included (where
        # it equals raised_at).
        "status_changed_at": raw.get("status_changed_at"),
        "acknowledged_at": raw.get("acknowledged_at"),
        "acknowledged_by": nonempty_str(raw.get("acknowledged_by")),
        "resolved_at": raw.get("resolved_at"),
        "resolved_reason": nonempty_str(raw.get("resolved_reason")),
        "reopened_count": reopened_count if type(reopened_count) is int else 0,
        "last_reopened_at": raw.get("last_reopened_at"),
        "can_acknowledge": status == "open",
    }


def _alert_transition_view(entry: dict) -> dict:
    """One row of GET /v1/portal/software-alerts/{id}'s history: who, when,
    from what, to what, and the free-text note - every value autoescaped by
    Jinja like every other customer-supplied text on this portal."""
    actor_kind = entry.get("actor_kind")
    actor = entry.get("actor")
    if actor_kind == "portal_user" and isinstance(actor, str) and actor:
        actor_label = actor
    else:
        actor_label = ALERT_ACTOR_KIND_LABELS.get(actor_kind, "Not recorded")
    from_status = entry.get("from")
    reason = entry.get("reason")
    note = entry.get("note")
    from_label = (
        ALERT_STATUS_LABELS.get(from_status, "Status not recognised") if from_status else "Raised"
    )
    return {
        "from_label": from_label,
        "to_label": ALERT_STATUS_LABELS.get(entry.get("to"), "Status not recognised"),
        "actor_label": actor_label,
        "reason": reason if isinstance(reason, str) and reason else None,
        "note": note if isinstance(note, str) and note else None,
        "at": entry.get("at"),
    }


def _alert_filter_url(status: str, product: str, device: str, page: int = 1) -> str:
    """A real, bookmarkable link for a status tab, a pager step or the
    filter form's own action - never a client-side-only state change (the
    segmented_control macro's tabs are client-side row filters over a
    single already-fetched page, which this list is not: each status/
    product/device/page combination is its own platform read)."""
    params: dict[str, str] = {"status": status}
    if product:
        params["product"] = product
    if device:
        params["device"] = device
    if page > 1:
        params["page"] = str(page)
    return "/software/alerts?" + urlencode(params)


def _alert_return_to(raw: str) -> str:
    """Where to send the browser after an acknowledge write: back to
    /software/alerts (list or detail) with its filters and paging, never
    anywhere else."""
    target = safe_return_to(raw) or "/software/alerts"
    parts = urlsplit(target)
    if parts.path != "/software/alerts" and not parts.path.startswith("/software/alerts/"):
        return "/software/alerts"
    query = [(k, v) for k, v in parse_qs(parts.query, keep_blank_values=True).items()
             if k != ALERT_RESULT_PARAM]
    flat = [(k, item) for k, values in query for item in values]
    return parts.path + ("?" + urlencode(flat) if flat else "")


def _alert_redirect(request: Request, return_to: str, payload: dict) -> RedirectResponse:
    token = _sign_flash(request.state.jwt, payload)
    separator = "&" if "?" in return_to else "?"
    url = f"{return_to}{separator}{ALERT_RESULT_PARAM}={quote(token, safe='')}#alert-result"
    return RedirectResponse(url=url, status_code=303)


def _alert_flash_view(data: dict | None) -> dict | None:
    if not data:
        return None

    def text(key, limit=400):
        value = data.get(key)
        return value[:limit] if isinstance(value, str) else ""

    return {
        "error": text("error"),
        "changed": data.get("changed") is True,
        "already_acknowledged": data.get("already_acknowledged") is True,
    }


def _alert_device_options(jwt_token: str) -> list[dict]:
    """PAT-2155: the alerts filter's device picker, built from the same
    tenant device roster GET /v1/portal/devices that /devices itself reads
    (get_device_roster) - not a second, alert-specific endpoint. The
    contract's own `device_id` filter (contracts/portal-api.md
    "GET /v1/portal/software-alerts") already takes an exact device_id, so
    this only has to map a picked hostname back to the id it was rendered
    from; the raw id is never shown, only carried as each <option>'s value.
    Fails soft to an empty list (never blocks the page) - a customer role
    that can read alerts but not the device roster still sees every alert,
    just without a device filter, the same fail-soft shape _alert_role
    already uses for the Acknowledge control."""
    try:
        roster = get_device_roster(jwt_token)
    except upstream.UpstreamError as exc:
        logger.warning("portal.software_alerts.device_picker_fail_soft kind=%s", exc.kind)
        return []
    if not isinstance(roster, list):
        logger.warning("portal.software_alerts.device_picker_fail_soft kind=malformed")
        return []
    options = [
        {"device_id": d["device_id"], "hostname": str(d.get("hostname") or "Unknown device")}
        for d in roster
        if isinstance(d, dict) and isinstance(d.get("device_id"), str) and d["device_id"]
    ]
    options.sort(key=lambda o: o["hostname"].lower())
    return options


def _alert_role(request: Request) -> tuple[str, bool]:
    """Fail-soft role read for display, same shape as /software's own -
    hiding the Acknowledge control is never the control; the write route
    re-reads the role itself and refuses on its own."""
    try:
        return _portal_role(request.state.jwt), False
    except upstream.UpstreamError as exc:
        logger.warning("portal.software_alerts.role_fail_soft kind=%s", exc.kind)
        return "viewer", True


@app.get("/alerts")
def alerts_shortcut(request: Request):
    """PAT-2256: the alerts page lives at /software/alerts, but "/alerts" is
    what people type and share, and it answered Not found. A fixed target
    (never taken from the request) with the query string carried over, so
    /alerts?status=acknowledged lands on the same tab. Authenticated like
    every other route: the middleware refuses a request with no session
    before this handler runs."""
    target = "/software/alerts"
    if request.url.query:
        target = f"{target}?{request.url.query}"
    return RedirectResponse(url=target, status_code=307)


@app.get("/software/alerts", response_class=HTMLResponse)
def software_alerts(request: Request):
    """PAT-2097: the tenant's unapproved-software alert lifecycle (open,
    acknowledged, resolved, re-opened), one row per (episode, device) pair.
    Every portal role may read it; only admin sees the Acknowledge control.
    Server-paginated and server-filtered (status/product_key/device_id) -
    see contracts/portal-api.md's "GET /v1/portal/software-alerts"."""
    status_filter = request.query_params.get("status", "open")
    if status_filter not in ALERT_STATUS_FILTERS:
        status_filter = "open"
    product_filter = request.query_params.get("product", "")[:ALERT_FILTER_PRODUCT_MAX_CHARS]
    device_filter = request.query_params.get("device", "")[:ALERT_FILTER_DEVICE_MAX_CHARS]
    page_num = _parse_page(request.query_params.get("page", "1"))
    offset = (page_num - 1) * ALERT_PAGE_SIZE

    role, role_unavailable = _alert_role(request)
    can_edit = role == "admin"

    params: dict = {"limit": ALERT_PAGE_SIZE, "offset": offset}
    if status_filter != "all":
        params["status"] = status_filter
    if product_filter:
        params["product_key"] = product_filter
    if device_filter:
        params["device_id"] = device_filter
    try:
        data = upstream.get_json("/v1/portal/software-alerts", request.state.jwt, params=params)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)

    alerts_raw = upstream.unwrap_list(data, "alerts")
    rows = [_alert_row(a) for a in alerts_raw if isinstance(a, dict)]
    raw_counts = data.get("counts") if isinstance(data, dict) else None
    counts_raw = raw_counts if isinstance(raw_counts, dict) else {}
    counts = {k: counts_raw.get(k) if type(counts_raw.get(k)) is int else 0
              for k in ("open", "acknowledged", "resolved")}
    counts["all"] = counts["open"] + counts["acknowledged"] + counts["resolved"]
    total = data.get("total", len(rows)) if isinstance(data, dict) else len(rows)
    limit = data.get("limit", ALERT_PAGE_SIZE) if isinstance(data, dict) else ALERT_PAGE_SIZE
    total_pages = max(1, -(-total // limit)) if limit else 1

    # Same PAT-1201 shape as /findings: an offset past the last row comes
    # back with alerts=[] and a bogus total, never trustworthy as "no
    # alerts" except on the first page.
    if not rows and offset > 0:
        return RedirectResponse(
            url=_alert_filter_url(status_filter, product_filter, device_filter), status_code=302)

    status_tabs = [
        ("open", "Open", counts["open"], "bad" if counts["open"] else None),
        ("acknowledged", "Acknowledged", counts["acknowledged"], None),
        ("resolved", "Resolved", counts["resolved"], None),
        ("all", "All", counts["all"], None),
    ]
    tab_urls = {value: _alert_filter_url(value, product_filter, device_filter)
                for value, _, _, _ in status_tabs}
    # PAT-2155: the old "Clear filters" link reused tab_urls[status_filter],
    # which is this exact page's own URL (filters included) - a no-op that
    # looked like a working control. A real clear drops product/device but
    # keeps the tab.
    clear_url = _alert_filter_url(status_filter, "", "")
    return_to = request.url.path + ("?" + request.url.query if request.url.query else "")

    return _render(request, "software_alerts.html", {
        "title": "Alerts", "nav": "alerts",
        "alerts": rows, "counts": counts, "total": total,
        "page": page_num, "total_pages": total_pages,
        "status_filter": status_filter, "status_tabs": status_tabs, "tab_urls": tab_urls,
        "product_filter": product_filter, "device_filter": device_filter,
        "device_options": _alert_device_options(request.state.jwt),
        "clear_url": clear_url,
        "prev_url": _alert_filter_url(status_filter, product_filter, device_filter, page_num - 1),
        "next_url": _alert_filter_url(status_filter, product_filter, device_filter, page_num + 1),
        "can_edit": can_edit, "role_unavailable": role_unavailable,
        "csrf_token": _csrf_token(request.state.jwt) if can_edit else "",
        "return_to": return_to,
        "alert_result": _alert_flash_view(_read_flash(
            request.state.jwt, request.query_params.get(ALERT_RESULT_PARAM, ""))),
    })


@app.get("/software/alerts/{alert_id}", response_class=HTMLResponse)
def software_alert_detail(request: Request, alert_id: str):
    """PAT-2097: one alert with its full, append-only history. Every portal
    role may read it; only admin sees the Acknowledge control."""
    if not alert_id.isdigit():
        return _render(request, "error.html", {
            "title": "Alert not found",
            "message": "That alert reference could not be read.",
        }, status_code=404)

    role, role_unavailable = _alert_role(request)
    can_edit = role == "admin"

    try:
        data = upstream.get_json(f"/v1/portal/software-alerts/{alert_id}", request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if not isinstance(data, dict):
        return _render(request, "error.html", {
            "title": "Temporarily unavailable",
            "message": "That alert could not be read just now. Please try again in a minute.",
        }, status_code=502)

    alert = _alert_row(data)
    history_raw = data.get("history") if isinstance(data.get("history"), list) else []
    history = [_alert_transition_view(h) for h in history_raw if isinstance(h, dict)]
    return_to = _alert_return_to(request.query_params.get("return_to", ""))

    return _render(request, "software_alert_detail.html", {
        "title": f"Alert: {alert['product']['name']}", "nav": "alerts",
        "alert": alert, "history": history,
        "can_edit": can_edit, "role_unavailable": role_unavailable,
        "csrf_token": _csrf_token(request.state.jwt) if can_edit else "",
        "return_to": return_to,
        "alert_result": _alert_flash_view(_read_flash(
            request.state.jwt, request.query_params.get(ALERT_RESULT_PARAM, ""))),
    })


@app.post("/software/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(request: Request, alert_id: str):
    """PAT-2097: POST /v1/portal/software-alerts/{id}/acknowledge, portal
    admin only, optional note up to 1000 characters, idempotent on the
    platform. Same guard order as PAT-2008/PAT-2105: size cap, then Origin,
    then CSRF token (_guarded_form), then role, then input - and the same
    run_in_threadpool discipline as every other async route's platform call.
    `alert_id` is deliberately `str`, not `int`: FastAPI would 422 a
    non-numeric id while resolving the path parameter, before the guard
    ever runs, which would let a cross-origin or tokenless request against
    this route skip the guard's refusal page - see tests/test_pat2105_csrf.py's
    route walk, which this route must also pass."""
    form, refusal = await _guarded_form(request, "software_alert_acknowledge")
    if refusal is not None:
        return refusal

    try:
        role = await run_in_threadpool(_portal_role, request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if role != "admin":
        return _approval_refusal(
            request, 403, "Only an administrator on your account can acknowledge alerts. "
            "Your account can view alerts and their history.")

    return_to = _alert_return_to((form.get("return_to") or [""])[0])

    if not alert_id.isdigit():
        return _approval_refusal(request, 400, "That alert reference could not be read.")

    notes = form.get("note", [""])
    if len(notes) > 1:
        return _approval_refusal(request, 400, "That request could not be read.")
    note = notes[0].strip()
    if "\x00" in note:
        return _approval_refusal(request, 400, "That request could not be read.")
    if len(note) > ALERT_NOTE_MAX_CHARS:
        return _alert_redirect(request, return_to, {
            "error": f"The note can be at most {ALERT_NOTE_MAX_CHARS} characters. "
                     "Nothing was changed."})

    payload = {"note": note} if note else None
    try:
        result = await run_in_threadpool(
            upstream.post_json, f"/v1/portal/software-alerts/{alert_id}/acknowledge",
            request.state.jwt, payload)
    except upstream.UpstreamError as exc:
        # Only the classification is logged: never the JWT, the body or the
        # customer's note text.
        logger.warning("portal.software_alert_acknowledge.upstream_refused kind=%s status=%s",
                       exc.kind, exc.status)
        if exc.kind == "auth":
            return _session_expired_response(request, "upstream")
        if exc.kind == "not_enabled":
            return _error_page(request, exc)
        if exc.status == 409:
            return _alert_redirect(request, return_to, {
                "error": "This alert has already been resolved, so it cannot be acknowledged."})
        if exc.kind == "not_found":
            return _alert_redirect(request, return_to, {
                "error": "That alert could not be found."})
        if exc.kind == "forbidden":
            return _alert_redirect(request, return_to, {
                "error": "Only an administrator on your account can acknowledge alerts."})
        return _alert_redirect(request, return_to, {
            "error": "The Patched platform refused this change. Nothing was changed."})

    changed = result.get("changed") if isinstance(result, dict) else None
    return _alert_redirect(request, return_to, {
        "changed": changed is True,
        "already_acknowledged": changed is False,
    })


# ── PAT-2163/PAT-2255: the /software filter bar and review workspace ──────
# PAT-2163 replaced the two rows of segmented-tab boxes with one compact bar:
# a Type <select> and an Approval checkbox <details> popover, both native
# form controls so they work with no JS (see templates/_macros.html's
# filter_bar docstring and static/js/portal.js's filter-bar layer).
#
# PAT-2255 (Andy's ruling of 28 September 2026: software review is done
# here, and PAT-2254 links every Overview software count into this page)
# makes the URL the whole filter state. Every filter below is read from the
# query string, applied to the rows server-side (a row that does not match
# renders with row-hide-filter / row-hide-search, so the first paint, a
# no-JS browser and a bookmarked link all show the filtered list) and seeds
# the controls, which static/js/portal.js then keeps in step:
#
#   type=application|extension   approval=<comma list of group keys>
#   publisher=<label>|__unknown__  min_devices=N   search=<text>
#   new_days=N    first seen within N days (GET /v1/portal/software/new
#                 ?since=now-N days), the PAT-2254 New software window
#   urgency=<comma list of NEW_SOFTWARE_URGENCY_LEVELS>, matched against the
#                 Overview's new_software block (the only urgency source)
#   new_since=<RFC 3339>|all  the review queue: new since the last review,
#                 pinned to the window the banner showed, so approving one
#                 product (which moves "last review" to now) does not empty
#                 the queue mid-review
#
# The approval group keys (waiting/approved/not_wanted/ignored/unrecognised)
# are unchanged, so PAT-2254's `approval=waiting` links and old bookmarks
# keep working; only their labels now use the one approval vocabulary a row
# shows (Unreviewed, Approved, Unapproved, Ignored). The old
# `?decision=<single value>` param still maps into `approval`.
SOFTWARE_APPROVAL_FILTER_OPTIONS = (
    ("waiting", "Unreviewed"),
    ("approved", "Approved"),
    ("not_wanted", "Unapproved"),
    ("ignored", "Ignored"),
    ("unrecognised", "State not recognised"),
)
SOFTWARE_APPROVAL_FILTER_LABELS = dict(SOFTWARE_APPROVAL_FILTER_OPTIONS)
SOFTWARE_APPROVAL_FILTER_KEYS = frozenset(SOFTWARE_APPROVAL_FILTER_LABELS)
# PAT-2255: the state words a person would type map onto the group keys, so
# `approval=unreviewed` or `approval=unapproved` means what it says on both
# review surfaces. Links the portal builds always use the group keys.
SOFTWARE_APPROVAL_ALIASES = {"unreviewed": "waiting", "unapproved": "not_wanted"}

# PAT-2255: the one approval state a row shows, in the Approval column only,
# keyed by the same group the row is filtered on so the pill and the filter
# can never disagree. Mandatory reads Approved (PAT-1742: a stronger form of
# approved, not a separate customer-facing state); its lock line says why it
# cannot be changed here.
SOFTWARE_STATE_PILL = {
    "waiting": ("Unreviewed", "pill-state--unreviewed"),
    "approved": ("Approved", "pill-state--approved"),
    "not_wanted": ("Unapproved", "pill-state--unapproved"),
    "ignored": ("Ignored", "pill-state--ignored"),
    "unrecognised": ("State not recognised", "pill-state--unknown"),
}

# PAT-2255: signing is its own column, never a second approval-looking pill.
# Short words for the cell; the full PAT-1832 label (and signer/Team ID when
# known) stays in the title.
SIGNING_SHORT_LABELS = {
    "notarized": "Notarized",
    "not_notarized": "Not notarized",
    "notarization_unknown": "Signed",
    "unknown": "Unknown",
}

SOFTWARE_NEW_SINCE_PARAM = "new_since"
SOFTWARE_NEW_SINCE_ALL = "all"
# GET /v1/portal/software/new takes RFC 3339 or YYYY-MM-DD; "since the
# beginning" (a tenant that has never recorded a review) is sent as the
# epoch rather than omitted, because an omitted `since` means "since the
# last review", which moves the moment the first product is decided.
SOFTWARE_NEW_SINCE_EPOCH = "1970-01-01T00:00:00Z"
SOFTWARE_NEW_DAYS_MAX = 365
SOFTWARE_SEARCH_PARAM = "search"
# PAT-2326: the usage filter. The values are the platform's own `usage_state`
# words a person can act on (mixed, stale and unknown evidence are readings of
# collection coverage, not usage verdicts, so they are not filters), and the
# filter compares that field and nothing else. Labels are what the row reads.
SOFTWARE_USAGE_PARAM = "usage"
SOFTWARE_USAGE_FILTER_OPTIONS = (
    ("unused", "Unused"),
    ("used", "Used"),
    # The platform's "unmetered" covers devices that do not meter and, since
    # PAT-2327, products whose installations have no recorded last use, so
    # the option says both.
    ("unmetered", "Not metered or no evidence"),
)
SOFTWARE_USAGE_FILTER_LABELS = dict(SOFTWARE_USAGE_FILTER_OPTIONS)
SOFTWARE_ROW_ANCHOR_RE = re.compile(r"^sw-[0-9a-f]{12}$")
SOFTWARE_URGENCY_RANKED_LIMIT = 50


def _software_approval_filter(request: Request) -> list[str]:
    """Parses `?approval=` (one or more, each optionally itself a comma
    list - the JS layer always writes one comma-joined param, but a plain
    HTML form with several same-named checkboxes posts one per checked box,
    and this must read both the same way) plus the legacy single-value
    `?decision=` (PAT-1798's segmented control) when `approval` is absent.
    Returns an ordered, deduplicated list of only the recognised group
    keys - an unknown value (a stale bookmark, a hand-edited URL) is
    silently dropped, never reflected back into the page and never used to
    filter. Order is the order the values were given in (a repeat is
    dropped on its second occurrence, not moved) - the order the chips
    render in; the Approval dropdown's own checkboxes always render in
    SOFTWARE_APPROVAL_FILTER_OPTIONS's fixed display order."""
    # An empty `approval=` (e.g. a form submitted with nothing ticked) is
    # treated as absent, so a legacy `decision=` alongside it still applies.
    raw_values = [v for v in request.query_params.getlist("approval") if v.strip()]
    if not raw_values:
        legacy = request.query_params.get("decision", "")
        if legacy and legacy != "all":
            raw_values = [legacy]
    selected: list[str] = []
    for raw in raw_values:
        for part in raw.split(","):
            part = SOFTWARE_APPROVAL_ALIASES.get(part.strip(), part.strip())
            if part in SOFTWARE_APPROVAL_FILTER_KEYS and part not in selected:
                selected.append(part)
    # PAT-2163 (orchestrator follow-up): the old "Unreviewed only" checkbox
    # (?unreviewed=1) is exactly the "waiting" group, so it is a like-for-
    # like alias that only applies when nothing more specific was given.
    if not selected and request.query_params.get("unreviewed") == "1":
        selected = ["waiting"]
    return selected


def _software_new_days(request: Request) -> int | None:
    """`new_days=N`, 1 to SOFTWARE_NEW_DAYS_MAX. Anything else is dropped,
    never reflected and never used to filter."""
    raw = request.query_params.get(SOFTWARE_NEW_DAYS_PARAM, "").strip()
    if not re.fullmatch(r"[0-9]{1,4}", raw):
        return None
    value = int(raw)
    return value if 1 <= value <= SOFTWARE_NEW_DAYS_MAX else None


def _software_urgency_filter(request: Request) -> list[str]:
    """`urgency=` as an ordered, deduplicated list of known levels, read the
    same way as `approval` (comma list or repeated params)."""
    selected: list[str] = []
    for raw in request.query_params.getlist(SOFTWARE_URGENCY_PARAM):
        for part in raw.split(","):
            part = part.strip()
            if part in NEW_SOFTWARE_URGENCY_LEVELS and part not in selected:
                selected.append(part)
    return selected


def _software_usage_filter(request: Request) -> list[str]:
    """PAT-2326: `usage=` as an ordered, deduplicated list of known usage
    words, read like `approval` (a comma list or repeated params). An
    unknown word is dropped, never reflected and never used to filter, and
    there is no alias that could widen a word: `unused` means the platform's
    `usage_state == "unused"` and nothing else."""
    selected: list[str] = []
    for raw in request.query_params.getlist(SOFTWARE_USAGE_PARAM):
        for part in raw.split(","):
            part = part.strip()
            if part in SOFTWARE_USAGE_FILTER_LABELS and part not in selected:
                selected.append(part)
    return selected


def _software_new_since(request: Request) -> str | None:
    """`new_since=` as a canonical UTC RFC 3339 timestamp, or "all" for a
    tenant that has never recorded a review. Anything unparseable is
    dropped."""
    raw = request.query_params.get(SOFTWARE_NEW_SINCE_PARAM, "").strip()
    if raw == SOFTWARE_NEW_SINCE_ALL:
        return raw
    if not raw or len(raw) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _software_filter_state(request: Request) -> dict:
    """Every /software filter, read once from the URL."""
    type_filter = request.query_params.get("type")
    if type_filter not in ("application", "extension"):
        type_filter = None
    _limit, _offset, search = _software_inventory_query(request)
    return {
        "type": type_filter,
        "approval": _software_approval_filter(request),
        "usage": _software_usage_filter(request),
        "publisher": request.query_params.get("publisher", "")[:120],
        "min_devices": _bounded_query_int(
            request.query_params.get("min_devices"), 0, 0, 1_000_000),
        "search": search,
        "new_days": _software_new_days(request),
        "urgency": _software_urgency_filter(request),
        "new_since": _software_new_since(request),
    }


def _software_query(state: dict, **overrides) -> list[tuple[str, str]]:
    """The query params for a /software URL carrying `state` (with
    `overrides` applied), in one fixed order. The one builder every chip,
    Clear all, pagination and review-queue link on the page uses."""
    s = {**state, **overrides}
    params: list[tuple[str, str]] = []
    if s.get("type"):
        params.append(("type", s["type"]))
    if s.get("approval"):
        params.append(("approval", ",".join(s["approval"])))
    if s.get("usage"):
        params.append((SOFTWARE_USAGE_PARAM, ",".join(s["usage"])))
    if s.get("publisher"):
        params.append(("publisher", s["publisher"]))
    if s.get("min_devices"):
        params.append(("min_devices", str(s["min_devices"])))
    if s.get("new_since"):
        params.append((SOFTWARE_NEW_SINCE_PARAM, s["new_since"]))
    if s.get("new_days"):
        params.append((SOFTWARE_NEW_DAYS_PARAM, str(s["new_days"])))
    if s.get("urgency"):
        params.append((SOFTWARE_URGENCY_PARAM, ",".join(s["urgency"])))
    if s.get("search"):
        params.append((SOFTWARE_SEARCH_PARAM, s["search"]))
    return params


def _software_url(state: dict, extra: list[tuple[str, str]] | None = None, **overrides) -> str:
    params = _software_query(state, **overrides) + list(extra or [])
    query = urlencode(params, safe=",", quote_via=quote)
    return "/software" + (f"?{query}" if query else "")


def _software_active_filters(state: dict, applied: dict) -> list[str]:
    """Names of the filters actually in force. `applied` says whether the
    filters that depend on a second read (new_days, urgency, new_since, and
    PAT-2326's usage, which needs the inventory read) could be read; one
    whose source failed is not in force, and the page says so."""
    active = []
    for key in ("type", "approval", "publisher", "min_devices", "search"):
        if state.get(key):
            active.append(key)
    for key in ("new_days", "urgency", "new_since", "usage"):
        if state.get(key) and applied.get(key):
            active.append(key)
    return active


def _software_filter_bar_view(
    request: Request, state: dict, applied: dict,
    total_products: int, app_count: int, ext_count: int,
    approval_counts: dict[str, int], publishers: list[str],
    usage_counts: dict[str, int] | None = None,
) -> dict:
    """The /software filter bar's view: the Type/Publisher/Approval option
    lists (a zero-count Type or Approval option is left out unless it is
    the one currently selected, so an active filter never vanishes from its
    own dropdown), the chips and Clear all, and the hidden row filters that
    carry new_days/urgency/new_since to static/js/portal.js. Paging params
    ride through untouched.

    PAT-2255: every count here is the number of rows the list holds, stated
    plainly. The old "at least N" came from mixing the platform's governance
    total with shown rows that included inventory-only products (defect 8);
    where the list itself is partial, the page says why in one muted line
    instead."""
    kept = [
        (k, v) for k, v in request.query_params.multi_items()
        if k in ("limit", "offset")
    ]
    type_filter = state["type"]
    selected_approvals = state["approval"]
    filter_publisher = state["publisher"]

    type_options = [
        {"value": "", "label": "All types", "count": total_products,
         "selected": type_filter is None, "hide": False},
        {"value": "application", "label": "Applications", "count": app_count,
         "selected": type_filter == "application",
         "hide": app_count == 0 and type_filter != "application"},
        {"value": "extension", "label": "Extensions", "count": ext_count,
         "selected": type_filter == "extension",
         "hide": ext_count == 0 and type_filter != "extension"},
    ]
    approval_options = [
        {"value": key, "label": label, "count": approval_counts.get(key, 0),
         "selected": key in selected_approvals,
         "hide": approval_counts.get(key, 0) == 0 and key not in selected_approvals}
        for key, label in SOFTWARE_APPROVAL_FILTER_OPTIONS
    ]
    # PAT-2326: the usage options sit in the More filters panel. Selected only
    # while the filter is in force (the inventory read it needs succeeded), so a
    # checked box never claims a filter the page did not apply. A zero-count
    # option is left out unless it is selected, the same rule as Approval.
    usage_counts = usage_counts or {}
    usage_selected = state["usage"] if applied.get("usage") else []
    usage_options = [
        {"value": key, "label": label, "count": usage_counts.get(key, 0),
         "selected": key in usage_selected,
         "hide": usage_counts.get(key, 0) == 0 and key not in usage_selected}
        for key, label in SOFTWARE_USAGE_FILTER_OPTIONS
    ]
    publisher_options = [
        {"value": "", "label": "All publishers", "selected": filter_publisher == ""},
    ]
    publisher_options += [
        {"value": p, "label": p, "selected": filter_publisher == p} for p in publishers
    ]
    publisher_options.append({
        "value": "__unknown__", "label": "Publisher not known",
        "selected": filter_publisher == "__unknown__",
    })

    def url(**overrides) -> str:
        return _software_url(state, kept, **overrides)

    # PAT-2163: no "Type:"/"Approval:" prefix on the primary chips (they sit
    # directly under the control that owns them, and the phone height
    # budget needs them short); Publisher and minimum devices keep a prefix.
    # PAT-2255: the membership filters (review queue, first seen, urgency)
    # have no dropdown of their own - their chip is the control, marked
    # static so the JS chip rebuild keeps it.
    chips = []
    if type_filter:
        chips.append({
            "label": "Applications" if type_filter == "application" else "Extensions",
            "remove_url": url(type=None),
        })
    for value in selected_approvals:
        chips.append({
            "label": SOFTWARE_APPROVAL_FILTER_LABELS[value],
            "remove_url": url(approval=[v for v in selected_approvals if v != value]),
        })
    for value in usage_selected:
        chips.append({
            "label": SOFTWARE_USAGE_FILTER_LABELS[value],
            "remove_url": url(usage=[v for v in usage_selected if v != value]),
        })
    if filter_publisher:
        publisher_label = (
            "Publisher not known" if filter_publisher == "__unknown__" else filter_publisher
        )
        chips.append({
            "label": f"Publisher: {publisher_label}",
            "remove_url": url(publisher=""),
        })
    if state["min_devices"]:
        n = state["min_devices"]
        chips.append({
            "label": f"At least {n} {'device' if n == 1 else 'devices'}",
            "remove_url": url(min_devices=0),
        })
    if state["new_since"] and applied.get("new_since"):
        chips.append({"label": "New since your last review", "static": True,
                      "param": SOFTWARE_NEW_SINCE_PARAM, "value": "",
                      "remove_url": url(new_since=None)})
    if state["new_days"] and applied.get("new_days"):
        n = state["new_days"]
        chips.append({"label": f"First seen in the last {n} {'day' if n == 1 else 'days'}",
                      "static": True, "param": SOFTWARE_NEW_DAYS_PARAM, "value": "",
                      "remove_url": url(new_days=None)})
    if state["urgency"] and applied.get("urgency"):
        for level in state["urgency"]:
            chips.append({
                "label": f"Urgency: {NEW_SOFTWARE_URGENCY_LABELS[level]}", "static": True,
                "param": SOFTWARE_URGENCY_PARAM, "value": level,
                "remove_url": url(urgency=[v for v in state["urgency"] if v != level]),
            })

    hidden_row_filters = []
    if state["new_since"] and applied.get("new_since"):
        hidden_row_filters.append({"name": SOFTWARE_NEW_SINCE_PARAM,
                                   "value": state["new_since"], "row_filter": "queue",
                                   "initial": "1"})
    if state["new_days"] and applied.get("new_days"):
        hidden_row_filters.append({"name": SOFTWARE_NEW_DAYS_PARAM,
                                   "value": str(state["new_days"]), "row_filter": "new",
                                   "initial": "1"})
    if state["urgency"] and applied.get("urgency"):
        joined = ",".join(state["urgency"])
        hidden_row_filters.append({"name": SOFTWARE_URGENCY_PARAM, "value": joined,
                                   "row_filter": "urgency", "initial": joined})
    # A no-JS Apply submits the bar's own form; the search box carries no
    # name (Enter must not submit it), so the current search rides along
    # here instead of being dropped.
    hidden_fields = [{"name": SOFTWARE_SEARCH_PARAM, "value": state["search"]}] if (
        state["search"]) else []

    active = _software_active_filters(state, applied)
    return {
        "type_options": type_options,
        "approval_options": approval_options,
        "usage_options": usage_options,
        "publisher_options": publisher_options,
        "chips": chips,
        "clear_url": _software_url({}, kept) if active else None,
        "hidden_row_filters": hidden_row_filters,
        "hidden_fields": hidden_fields,
        "active_filters": active,
        "search": state["search"],
    }


def _new_software_identities(products) -> tuple[set, list[dict]]:
    """(identity keys, product dicts) for a GET /v1/portal/software/new or
    Overview new_software product list, keyed exactly the way the /software
    merge keys a row (_software_identity_key: platform plus the normalised
    identifier). A name-only product (no identifier) has no key and can
    never match a row; the caller counts it as unmatched rather than
    guessing (identity is not packaging)."""
    keys: set = set()
    rows: list[dict] = []
    for product in products if isinstance(products, list) else []:
        if not isinstance(product, dict):
            continue
        rows.append(product)
        key = _software_identity_key(product.get("platform"), product.get("identifier"))
        if key is not None:
            keys.add(key)
    return keys, rows


def _fetch_software_new(jwt_token: str, since: str | None) -> dict | None:
    """GET /v1/portal/software/new, with `since` when given. None when the
    read fails or its shape cannot be trusted - a membership filter built on
    it is then not applied, and the page says so (absence requires
    authority: an unreadable window never becomes "nothing new")."""
    try:
        data = upstream.get_json(
            "/v1/portal/software/new", jwt_token,
            params={"since": since} if since else None)
    except upstream.UpstreamError as exc:
        logger.warning("portal.software.new_software_fail_soft kind=%s", exc.kind)
        return None
    if not isinstance(data, dict) or not isinstance(data.get("products"), list):
        return None
    return data


def _fetch_software_urgency(jwt_token: str) -> dict | None:
    """The Overview's new_software block (GET /v1/portal/overview), the only
    place the platform rates urgency (contracts/portal-api.md "New software
    by urgency"). Returns {identity key: urgency} plus the block's own
    counts and truncation, or None when the block cannot be trusted."""
    try:
        data = upstream.get_json("/v1/portal/overview", jwt_token)
    except upstream.UpstreamError as exc:
        logger.warning("portal.software.urgency_fail_soft kind=%s", exc.kind)
        return None
    block = data.get("new_software") if isinstance(data, dict) else None
    if _new_software_view(block).get("status") == "unavailable":
        return None
    index: dict = {}
    products = []
    for product in block.get("products") or []:
        urgency = product.get("urgency")
        if urgency not in NEW_SOFTWARE_URGENCY_LEVELS:
            continue
        products.append(product)
        key = _software_identity_key(product.get("platform"), product.get("identifier"))
        if key is not None:
            index.setdefault(key, urgency)
    counts = block.get("counts") if isinstance(block.get("counts"), dict) else {}
    return {
        "index": index, "products": products,
        "counts": {level: counts.get(level) if type(counts.get(level)) is int else 0
                   for level in NEW_SOFTWARE_URGENCY_LEVELS},
        "truncated": block.get("truncated") is True,
    }


def _software_row_key(row: dict) -> tuple | None:
    if row.get("kind") != "application":
        return None
    return _software_identity_key(row.get("platform"), row.get("identifier"))


def _software_detail_url(row: dict) -> str | None:
    """The product detail (history drawer, with its Identifiers section).
    A markable row already has one; a locked row that still carries a real
    application identifier (mandatory, identifier too long to store, no
    Team ID) gets one built from that identity, so its identifiers are not
    shown nowhere. The item is display-only: the history route re-validates
    it against the approval item schema and only reads."""
    if row.get("history_url"):
        return row["history_url"]
    if row.get("kind") != "application" or row.get("platform") not in APPROVAL_PLATFORMS:
        return None
    identifier = row.get("identifier")
    identifier = identifier.strip() if isinstance(identifier, str) else ""
    if (
        not identifier or len(identifier) > APPROVAL_MAX_IDENTIFIER_CHARS
        or _CONTROL_CHARS_RE.search(identifier)
    ):
        return None
    item = {"type": "application", "platform": row["platform"], "identifier": identifier,
            "name": (row.get("name") or "")[:APPROVAL_MAX_NAME_CHARS]}
    return "/software/history?" + urlencode({"item": json.dumps(item, separators=(",", ":"))})


def _software_state_title(row: dict) -> str:
    """The approval pill's tooltip: who decided and why (PAT-1839
    provenance, moved off the list so a row is one line)."""
    parts = []
    if row.get("has_decision"):
        when = humandate(row.get("decided_at"))
        who = row.get("decided_by")
        parts.append(f"Decided {when} by {who}" if who
                     else f"Decided {when}. Who decided was not recorded")
    elif row.get("group") == "waiting":
        parts.append("No decision recorded yet")
    if row.get("justification"):
        parts.append(f"Justification: {row['justification']}")
    if row.get("approval_state") == "mandatory":
        parts.append("Set as mandatory in your Patched policy")
    # A product's own removal state (PAT-1726) is kept only where it says
    # something happened; an application's permanent not_available and an
    # extension's not_requested are no news, and never read as a request.
    if row.get("group") == "not_wanted" and row.get("removal_state") not in (
            None, "", "not_available", "not_requested"):
        parts.append(row.get("removal_label") or "")
    return ". ".join(p for p in parts if p) + ("." if parts else "")


def _software_usage_view(row: dict) -> dict:
    """PAT-2326: what a /software row says about usage, read straight from
    the platform's `usage_state` and never reconstructed here. `key` is what
    the usage filter compares (the state, or "none" when the platform sent no
    verdict for this row, which is never "unused"). `prefix` is the text
    before the date, `date` the last use when there is one to show, `text`
    the whole line in plain text (for tooltips and tests) and `tone` the
    pill class (ok, warn, muted). Unused reads "Unused · last used <date>"
    (or "no use recorded" when the platform has no launch timestamp), Used
    "Used · <date>", unmetered "Not metered" (or "No usage evidence" when the
    platform counts installations with no recorded last use, PAT-2327), and
    any other state the platform's own label."""
    state = row.get("usage_state")
    if state not in SOFTWARE_USAGE_STATE_LABELS:
        return {"key": "none", "prefix": "", "date": None, "text": "", "tone": "muted"}
    last_used = row.get("last_used_at")
    when = last_used if _parse_utc(last_used) is not None else None
    if state == "unused":
        prefix = "Unused · last used " if when else "Unused · no use recorded"
    elif state == "used":
        prefix = "Used · " if when else "Used"
    elif state == "unmetered":
        # PAT-2327: an unmetered product whose installations are on metered
        # devices with no recorded last use has no usage evidence; a device
        # that does not meter at all is not metered. Both are unmetered to
        # the platform and neither is ever unused.
        prefix = ("No usage evidence" if row.get("no_evidence_installation_count")
                  else "Not metered")
        when = None
    else:
        prefix, when = SOFTWARE_USAGE_STATE_LABELS[state], None
    return {
        "key": state, "prefix": prefix, "date": when,
        "text": prefix + (humandate(when) if when else ""),
        "tone": SOFTWARE_USAGE_STATE_TONES.get(state, "muted"),
    }


def _software_row_view(row: dict) -> None:
    """PAT-2255: everything a compact /software row renders, set
    once here so the template carries no logic: the one approval state, the
    signing column, the installs and installed versions, the product detail link and
    the lower-cased text search matches against (static/js/portal.js reads
    the same data-search attribute, so server and browser filter alike)."""
    label, pill_class = SOFTWARE_STATE_PILL.get(
        row.get("group") or "unrecognised", SOFTWARE_STATE_PILL["unrecognised"])
    row["state_label"] = label
    row["state_class"] = pill_class
    row["state_title"] = _software_state_title(row)
    signing = row.get("signing_state")
    row["signing_short"] = SIGNING_SHORT_LABELS.get(signing) if signing else None
    if signing:
        title = row.get("signing_label") or ""
        if row.get("signed_by"):
            title += f" ({row['signed_by']}"
            title += f", Team ID {row['team_id']})" if row.get("team_id") else ")"
        row["signing_title"] = title
    else:
        row["signing_title"] = "Signing applies to applications only"
    installs = row.get("installs") or 0
    device_word = "device" if installs == 1 else "devices"
    if row.get("installation_count") is not None:
        row["installs_text"] = f"{row['installation_count']} on {installs} {device_word}"
    else:
        row["installs_text"] = row.get("installs_label") or f"{installs} {device_word}"
    versions = [v for v in (row.get("versions") or []) if isinstance(v, str)]
    row["versions_text"] = ", ".join(versions)
    title = row["installs_text"]
    if versions:
        title += f". Versions: {row['versions_text']}"
    unknown = row.get("unknown_version_installation_count") or 0
    row["installed_versions_title"] = (
        "Installed versions: " + (row["versions_text"] or "Not reported"))
    if unknown:
        row["installed_versions_title"] += (
            f". {unknown} installation{'' if unknown == 1 else 's'} without a version")
    if unknown:
        title += (f". {unknown} installation{'' if unknown == 1 else 's'}"
                  " without a version")
    # PAT-2326: the Evidence column, where the usage line lives, is hidden
    # below 1680px, so the Installs tooltip carries it too.
    usage = _software_usage_view(row)
    row["usage_key"] = usage["key"]
    row["usage_prefix"] = usage["prefix"]
    row["usage_date"] = usage["date"]
    row["usage_text"] = usage["text"]
    row["usage_tone"] = usage["tone"]
    if usage["text"]:
        title += f". Usage: {usage['text']}"
    row["installs_title"] = title
    row["detail_url"] = _software_detail_url(row)
    name_title = row.get("name") or ""
    if row.get("canonical_name") and row["canonical_name"] != row.get("name"):
        name_title += f" (reviewed identity: {row['canonical_name']})"
    row["name_title"] = name_title
    search_parts = (
        row.get("name"), row.get("canonical_name"), row.get("publisher"),
        row.get("identifier"), row.get("platform_label"),
        "extension" if row.get("kind") == "extension" else "application",
    )
    row["search_text"] = " ".join(p for p in search_parts if isinstance(p, str) and p).lower()


def _software_row_id(row: dict, taken: set) -> str:
    """A stable anchor per row (the redirect after an approval lands on the
    next row by it). Hashes the approval item when there is one, else the
    row's own identity fields; a collision is salted, never reused."""
    basis = row.get("approval_item_json") or json.dumps(
        [row.get("kind"), row.get("platform"), row.get("identifier"), row.get("name"),
         row.get("browser")], separators=(",", ":"))
    salt = 0
    while True:
        seed = basis if not salt else f"{basis}#{salt}"
        row_id = "sw-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
        if row_id not in taken:
            taken.add(row_id)
            return row_id
        salt += 1


def _software_row_hidden(row: dict, state: dict, applied: dict) -> bool:
    """Server-side mirror of static/js/portal.js's applyFilters() plus
    approvalFilterExcludes(): a row the filters exclude. Kept to exactly the
    same rules so the first paint and the browser agree."""
    if state["type"] and row["kind"] != state["type"]:
        return True
    if state["approval"] and row["group"] not in state["approval"]:
        return True
    # PAT-2326: the platform's own usage verdict and nothing else. A row with
    # no verdict (no matching inventory product), or one the platform calls
    # mixed, stale or unknown, is never in "unused", "used" or "not metered".
    if (state["usage"] and applied.get("usage")
            and row.get("usage_state") not in state["usage"]):
        return True
    publisher = state["publisher"]
    if publisher == "__unknown__" and row.get("publisher"):
        return True
    if publisher and publisher != "__unknown__" and row.get("publisher") != publisher:
        return True
    if state["min_devices"] and (row.get("installs") or 0) < state["min_devices"]:
        return True
    if state["new_since"] and applied.get("new_since") and row.get("filter_queue") != "1":
        return True
    if state["new_days"] and applied.get("new_days") and row.get("filter_new") != "1":
        return True
    if (state["urgency"] and applied.get("urgency")
            and row.get("filter_urgency") not in state["urgency"]):
        return True
    return False


def _software_display_sort_key(row: dict) -> tuple:
    """Name first (case-insensitive), then identity, so two loads of the
    same data always render the same order whatever order the platform
    returned rows in."""
    return (
        (row.get("name") or "").casefold(), row.get("kind") or "",
        row.get("platform") or "", (row.get("identifier") or "").casefold(),
        row.get("browser") or "", row.get("name") or "",
    )


def _software_headline(overview_cards: dict, floor: dict) -> dict:
    """PAT-2255 defect 1: the headline figure is _awaiting_decision, the one
    value the Overview's Top 3, at-a-glance line and Software awaiting
    approval card read (PAT-2254). `note` is the one muted line that says
    why a figure is partial or where it came from; never "at least"."""
    figure = _awaiting_decision(overview_cards, floor)
    from_card = bool(overview_cards.get("available")) and (
        overview_cards.get("awaiting_decision") is not None)
    card = next((c for c in overview_cards.get("cards") or []
                 if c.get("key") == "software_awaiting_approval"), None)
    note = None
    if not from_card:
        note = ("Counted from the applications and browser extensions below, because the "
                "estate-wide figure is not available right now.")
    elif card and card.get("state") == "partial":
        # The card's only partial reason is coverage_incomplete (a device
        # stale or without inventory, contracts/portal-api.md
        # "overview/cards"): a floor that can only rise.
        note = ("Some devices have not reported recently, so this figure may rise when "
                "they do.")
    return {
        "available": bool(figure.get("available")),
        "count": figure.get("count", 0),
        "from_card": from_card,
        "note": note,
    }


def _new_unreviewed(products: list[dict]) -> list[dict]:
    """The new products still waiting on a decision, as the platform itself
    reports each one's state (approval_state, the same resolver every
    governance surface uses)."""
    return [p for p in products if p.get("approval_state") == "unreviewed"]


def _software_review_queue(state, applied, rows, new_data) -> dict | None:
    """The review queue (defect 5): products first seen since the pinned
    window that are still waiting on a decision. `count` is the platform's
    own figure for that (the banner that opened the queue shows the same
    one), `unmatched` those of them that match no row here (a name-only
    product, or one the applications read did not return), named on the
    page rather than silently dropped."""
    if not (state["new_since"] and applied.get("new_since") and new_data is not None):
        return None
    waiting = _new_unreviewed(new_data["products"])
    matched_keys = {_software_row_key(r) for r in rows if r.get("filter_queue") == "1"}
    unmatched = sum(
        1 for p in waiting
        if _software_identity_key(p.get("platform"), p.get("identifier")) not in matched_keys)
    since = None if state["new_since"] == SOFTWARE_NEW_SINCE_ALL else state["new_since"]
    return {
        "count": len(waiting),
        "unmatched": unmatched,
        "since": since,
        "truncated": new_data["data"].get("truncated") is True,
        "leave_url": _software_url(state, new_since=None, approval=[]),
    }


@app.get("/software", response_class=HTMLResponse)
def software(request: Request):
    """The merged software review workspace (PAT-1643, PAT-1742, PAT-2120,
    PAT-2255): GET /v1/portal/applications and /v1/portal/extensions
    (governance: decision state, evidence basis) with GET /v1/portal/software
    (inventory: versions, dated evidence, CVE assessment) folded in by
    (platform, identifier), one row per product, one approval state per
    row.

    Grouping (APP_POLICY_GROUP / EXT_APPROVAL_GROUP):
      - undecided / unreviewed -> waiting (Unreviewed)
      - unapproved -> not_wanted (Unapproved)
      - approved, and mandatory (PAT-1742) -> approved
      - ignored (and an application's stored "unmanaged") -> ignored
      - anything else -> unrecognised, rendered visibly, never guessed into
        one of the above (absence requires authority, root AGENTS.md)

    Every row is always rendered (PAT-1798's client-side filtering stays);
    the URL's filters mark the rows they exclude hidden server-side, so the
    first paint already shows the filtered list (PAT-2255 defect 7). See the
    section comment above for the parameters.

    PAT-1821: protected-software badges the application rows it matches with
    strict-exact identity; its failure degrades the badge away, never the
    page."""
    state = _software_filter_state(request)

    # PAT-1870: inventory is an evidence view alongside the governance read
    # models, intentionally fail-soft: an endpoint rollout or contract fault
    # cannot make established policy decisions disappear from this page.
    inventory = None
    inventory_error = False
    inventory_limit, inventory_offset, inventory_search = _software_inventory_query(request)
    try:
        inventory_data = upstream.get_json(
            "/v1/portal/software", request.state.jwt,
            params={
                "limit": inventory_limit,
                "offset": inventory_offset,
                "search": inventory_search,
            },
        )
        products, inventory_total, returned_limit, returned_offset, coverage, generated_at = (
            _software_inventory_envelope(inventory_data)
        )
        if (
            returned_limit != inventory_limit or returned_offset != inventory_offset
            or len(products) > returned_limit
            or (returned_offset >= inventory_total and products)
            or (
                returned_offset < inventory_total
                and (
                    not products
                    or returned_offset + len(products) > inventory_total
                )
            )
        ):
            raise upstream.UpstreamError("error", "inconsistent software inventory pagination")

        def inventory_url(offset: int) -> str:
            return _software_url(state, [("limit", str(returned_limit)),
                                         ("offset", str(offset))])

        inventory = {
            "products": [_software_inventory_row(product) for product in products],
            "total": inventory_total,
            "limit": returned_limit,
            "offset": returned_offset,
            "coverage": coverage,
            "generated_at": generated_at,
            "previous_url": (
                inventory_url(max(0, returned_offset - returned_limit))
                if returned_offset else None
            ),
            "next_url": (
                inventory_url(returned_offset + returned_limit)
                if returned_offset + len(products) < inventory_total else None
            ),
        }
    except upstream.UpstreamError as exc:
        # Only the safe, stable upstream classification: request headers,
        # the JWT, tenant identity and response bodies never reach the logs.
        logger.warning("portal.software_inventory.fail_soft kind=%s", exc.kind)
        inventory_error = True

    try:
        apps_data = upstream.get_json("/v1/portal/applications", request.state.jwt)
        applications = upstream.unwrap_list(apps_data, "applications")
        ext_data = upstream.get_json("/v1/portal/extensions", request.state.jwt)
        extensions = upstream.unwrap_list(ext_data, "extensions")
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)

    try:
        protected_data = upstream.get_json("/v1/portal/protected-software", request.state.jwt)
        protected_products = upstream.unwrap_list(protected_data, "products")
    except upstream.UpstreamError:
        protected_products = []
    protected_index = _protected_software_index(protected_products)

    groups: dict[str, list] = {
        "waiting": [], "not_wanted": [], "approved": [], "ignored": [], "unrecognised": [],
    }

    # enforcement_tier is deliberately not carried into the row shape: its
    # values are the retired buyer-facing tier vocabulary (PAT-1566).
    # PAT-2008: write controls only for the customer admin role. The role
    # read is fail-soft for display (no controls, never a broken page); the
    # write route re-reads it and refuses on its own, and so does the
    # platform. Hiding a control is never the control.
    try:
        role = _portal_role(request.state.jwt)
        role_unavailable = False
    except upstream.UpstreamError as exc:
        logger.warning("portal.software.role_fail_soft kind=%s", exc.kind)
        role, role_unavailable = "viewer", True
    can_edit = role == "admin"

    for a in applications:
        app_name = a.get("name", "")
        match = _protected_match(app_name, protected_index)
        row = _software_row(
            app_name, "application", a.get("device_count") or 0,
            a.get("evidence_basis", ""), a.get("removal_state", ""),
            protected_category=(match.get("category") if match else None),
            decided_by=a.get("decided_by"), decided_at=a.get("decided_at"),
            justification=a.get("justification"),
            version_count=a.get("version_count") or 0,
            team_id=a.get("team_id"), signed_by=a.get("signed_by"),
            notarized=a.get("notarized"),
            approval=_app_approval(a, protected=match is not None),
            platform=a.get("platform"), identifier=a.get("identifier"),
        )
        bucket = _app_group(a.get("policy_state"))
        row["group"] = bucket
        groups[bucket].append(row)

    # PAT-1821: protected-software is application-only on the platform, so
    # extension rows are never matched or badged.
    for e in extensions:
        row = _software_row(
            e.get("name", ""), "extension", e.get("device_count") or 0,
            e.get("evidence_basis", ""), e.get("removal_state", ""),
            decided_by=e.get("decided_by"), decided_at=e.get("decided_at"),
            justification=e.get("justification"),
            version_count=e.get("version_count") or 0,
            approval=_ext_approval(e),
            browser=e.get("browser"),
        )
        row["browser"] = e.get("browser") if isinstance(e.get("browser"), str) else None
        bucket = _ext_group(e.get("approval_state"))
        row["group"] = bucket
        groups[bucket].append(row)

    # PAT-2120: fold the inventory evidence into the one table. A product
    # whose (platform, identifier) matches a governance row enriches it in
    # place (see _software_identity_key for why that, not name, is the join
    # key); anything left over is its own row, grouped by its policy_state.
    identifier_index: dict[tuple, dict] = {}
    for rows in groups.values():
        for row in sorted(rows, key=_software_display_sort_key):
            if row["kind"] != "application":
                continue
            key = _software_identity_key(row.get("platform"), row.get("identifier"))
            if key is not None:
                identifier_index.setdefault(key, row)

    if inventory is not None:
        for product in inventory["products"]:
            key = _software_identity_key(product.get("platform"), product.get("identifier"))
            match = identifier_index.get(key) if key is not None else None
            if match is not None:
                _merge_inventory_evidence(match, product, protected_index)
                # The inventory side's policy_state is the richer PAT-2104
                # source _inventory_approval already prefers for the state;
                # a genuine value moves the row so its bucket and its state
                # never disagree.
                raw_state = product.get("policy_state")
                if raw_state in INVENTORY_POLICY_GROUP:
                    new_bucket = INVENTORY_POLICY_GROUP[raw_state]
                    if new_bucket != match["group"]:
                        groups[match["group"]].remove(match)
                        match["group"] = new_bucket
                        groups[new_bucket].append(match)
            else:
                row = _inventory_only_row(product, protected_index)
                bucket = _inventory_group(product.get("policy_state"))
                row["group"] = bucket
                groups[bucket].append(row)

    for rows in groups.values():
        rows.sort(key=_software_display_sort_key)
    all_rows = [r for rows in groups.values() for r in rows]
    for row in all_rows:
        _software_row_view(row)

    # PAT-2255 defect 7: the three membership filters. Each is read only
    # when its param is present; a source that cannot be read leaves that
    # filter out of force and the page says so, never a silently
    # unfiltered list presented as filtered.
    applied = {"new_since": False, "new_days": False, "urgency": False, "usage": False}
    filter_notices: list[str] = []
    queue_data = None
    # PAT-2326: usage is the platform's per-product verdict from the inventory
    # read, so the filter is in force only when that read succeeded. When it
    # did not, the list is not limited by usage and says so: an unreadable
    # inventory is never "no unused software", and no row is ever treated as
    # unused because its verdict is missing.
    usage_note = None
    if state["usage"]:
        if inventory is None:
            filter_notices.append(
                "Usage could not be read right now, so this list is not limited by usage.")
        else:
            applied["usage"] = True
            if inventory["total"] > len(inventory["products"]):
                usage_note = (
                    "Usage comes from the software evidence, and this page of it holds "
                    f"products {inventory['offset'] + 1} to "
                    f"{inventory['offset'] + len(inventory['products'])} of "
                    f"{inventory['total']}. Use Next or Previous below to check the others.")
    if state["new_since"]:
        since = (SOFTWARE_NEW_SINCE_EPOCH if state["new_since"] == SOFTWARE_NEW_SINCE_ALL
                 else state["new_since"])
        data = _fetch_software_new(request.state.jwt, since)
        if data is None:
            filter_notices.append(
                "New products could not be read right now, so this list is not limited to "
                "products new since your last review.")
        else:
            keys, products = _new_software_identities(data["products"])
            queue_data = {"data": data, "products": products}
            applied["new_since"] = True
            for row in all_rows:
                row["filter_queue"] = "1" if _software_row_key(row) in keys else "0"
    if state["new_days"]:
        since = (datetime.now(UTC) - timedelta(days=state["new_days"])).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        data = _fetch_software_new(request.state.jwt, since)
        if data is None:
            filter_notices.append(
                "First-seen dates could not be read right now, so this list is not limited "
                "by when products were first seen.")
        else:
            keys, _products = _new_software_identities(data["products"])
            applied["new_days"] = True
            for row in all_rows:
                row["filter_new"] = "1" if _software_row_key(row) in keys else "0"
            if data.get("truncated") is True:
                filter_notices.append(
                    "More products were first seen in this window than one read can hold, "
                    "so this list shows the newest of them.")
    urgency_note = None
    if state["urgency"]:
        urgency = _fetch_software_urgency(request.state.jwt)
        if urgency is None:
            filter_notices.append(
                "Urgency could not be read right now, so this list is not filtered by "
                "urgency.")
        else:
            applied["urgency"] = True
            for row in all_rows:
                row["filter_urgency"] = urgency["index"].get(_software_row_key(row), "none")
            matched = {_software_row_key(r) for r in all_rows
                       if r.get("filter_urgency") in state["urgency"]}
            listed = [p for p in urgency["products"] if p.get("urgency") in state["urgency"]]
            unmatched = sum(
                1 for p in listed
                if _software_identity_key(p.get("platform"), p.get("identifier")) not in matched)
            unlisted = max(0, sum(urgency["counts"][lvl] for lvl in state["urgency"])
                           - len(listed))
            missing = unmatched + unlisted
            if missing:
                urgency_note = (
                    f"{missing} more new {'product' if missing == 1 else 'products'} at "
                    f"{'this urgency is' if len(state['urgency']) == 1 else 'these urgencies are'}"
                    " not in this list: the Overview ranks the "
                    f"{SOFTWARE_URGENCY_RANKED_LIMIT} most urgent, and a product known by "
                    "name only cannot be matched to a row.")

    for row in all_rows:
        row["hidden_filter"] = _software_row_hidden(row, state, applied)
        row["hidden_search"] = bool(state["search"]) and (
            state["search"].lower() not in row["search_text"])

    # Stable anchors, and for each row the next row still in view: an
    # approval write from that row lands on it (review flow).
    taken: set = set()
    for row in all_rows:
        row["row_id"] = _software_row_id(row, taken)
    visible_ids = [r["row_id"] for r in all_rows
                   if not r["hidden_filter"] and not r["hidden_search"]]
    for row in all_rows:
        if row["row_id"] in visible_ids:
            i = visible_ids.index(row["row_id"])
            row["next_row_id"] = (visible_ids[i + 1] if i + 1 < len(visible_ids)
                                  else (visible_ids[i - 1] if i else ""))
        else:
            row["next_row_id"] = visible_ids[0] if visible_ids else ""

    app_rows_shown = sum(1 for r in all_rows if r["kind"] == "application")
    ext_rows_shown = sum(1 for r in all_rows if r["kind"] == "extension")

    def _platform_total(raw_total, shown):
        # A platform total is quoted only when it is a real count at least
        # as large as the rows it returned; otherwise the notice below says
        # the total could not be read rather than guessing one.
        return raw_total if isinstance(raw_total, int) and raw_total >= shown else None

    app_governance_shown = len(applications)
    raw_app_total = apps_data.get("total") if isinstance(apps_data, dict) else None
    raw_ext_total = ext_data.get("total") if isinstance(ext_data, dict) else None
    app_total = _platform_total(raw_app_total, app_governance_shown)
    ext_total = _platform_total(raw_ext_total, len(extensions))

    app_truncated = bool(apps_data.get("truncated")) if isinstance(apps_data, dict) else False
    app_estate_too_large = (
        bool(apps_data.get("estate_too_large")) if isinstance(apps_data, dict) else False
    )
    ext_truncated = bool(ext_data.get("truncated")) if isinstance(ext_data, dict) else False
    ext_estate_too_large = (
        bool(ext_data.get("estate_too_large")) if isinstance(ext_data, dict) else False
    )

    approval_counts = {key: len(groups[key]) for key in SOFTWARE_APPROVAL_FILTER_KEYS}
    usage_counts = {
        key: sum(1 for r in all_rows if r["usage_key"] == key)
        for key, _label in SOFTWARE_USAGE_FILTER_OPTIONS
    }
    publishers = sorted({r["publisher"] for r in all_rows if r["publisher"]}, key=str.casefold)
    filter_bar = _software_filter_bar_view(
        request, state, applied, len(all_rows), app_rows_shown, ext_rows_shown,
        approval_counts, publishers, usage_counts,
    )

    # PAT-2255 defect 1: one count, the Overview's own source.
    headline = _software_headline(
        _overview_cards_view(request.state.jwt), _governance_waiting(applications, extensions))

    # PAT-2010/PAT-2255 defect 5: the "N new since your last review" banner
    # is the entry to the review queue. Its count is the queue's own: the
    # products GET /v1/portal/software/new lists for the window that are
    # still Unreviewed, the figure the queue heading repeats. Its link pins
    # the window it was counted over. Fail-soft and supplementary: a failed
    # read shows nothing, never a fabricated zero. In queue mode the queue
    # heading replaces it.
    review_queue = _software_review_queue(state, applied, all_rows, queue_data)
    new_review = None
    if not state["new_since"]:
        data = _fetch_software_new(request.state.jwt, None)
        if data is not None:
            _keys, products = _new_software_identities(data["products"])
            count = len(_new_unreviewed(products))
            since_raw = data.get("since")
            pinned = SOFTWARE_NEW_SINCE_ALL
            if isinstance(since_raw, str) and since_raw:
                try:
                    parsed = datetime.fromisoformat(since_raw.replace("Z", "+00:00"))
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=UTC)
                    pinned = parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")
                except ValueError:
                    pinned = None
            if count and pinned:
                new_review = {
                    "count": count,
                    "no_review": pinned == SOFTWARE_NEW_SINCE_ALL,
                    "href": _software_url({}, new_since=pinned, approval=["waiting"]),
                }

    visible_count = len(visible_ids)
    declared_rows, declared_total, declared_error = _declared_not_observed(request.state.jwt)
    return _render(request, "software.html", {
        "declared_rows": declared_rows, "declared_total": declared_total,
        "declared_error": declared_error, "declaration_meaning": DECLARATION_MEANING,
        "title": "Software", "nav": "software",
        "headline": headline,
        "new_review": new_review,
        "review_queue": review_queue,
        "filter_notices": filter_notices,
        "urgency_note": urgency_note,
        "usage_note": usage_note,
        "all_rows": all_rows,
        "visible_count": visible_count,
        "type_filter": state["type"],
        "selected_approvals": state["approval"],
        # PAT-2163: named software_filter_bar, not filter_bar - the template
        # imports a Jinja macro of that exact name (_macros.html), and a
        # context variable with the same name would shadow it.
        "software_filter_bar": filter_bar,
        "total_products": len(all_rows),
        "truncated": app_truncated or ext_truncated,
        "estate_too_large": app_estate_too_large or ext_estate_too_large,
        "app_truncated": app_truncated, "app_estate_too_large": app_estate_too_large,
        "ext_truncated": ext_truncated, "ext_estate_too_large": ext_estate_too_large,
        "ext_shown": len(extensions), "ext_total": ext_total,
        "app_shown": app_governance_shown, "app_total": app_total,
        "inventory": inventory, "inventory_error": inventory_error,
        "inventory_search": inventory_search,
        "can_edit": can_edit, "role_unavailable": role_unavailable,
        "csrf_token": _csrf_token(request.state.jwt) if can_edit else "",
        "return_to": _approval_return_to(
            request.url.path + ("?" + request.url.query if request.url.query else "")),
        "approval_result": _approval_flash_view(_read_flash(
            request.state.jwt, request.query_params.get(APPROVAL_RESULT_PARAM, ""))),
        "filter_publisher": state["publisher"],
        "filter_min_devices": state["min_devices"],
    })


# ── PAT-2156: one device's Software installed view ────────────────────────
DEVICE_SOFTWARE_TABS = ("application", "extension")


def _device_software_not_found(request: Request) -> HTMLResponse:
    """A malformed device_id (platform 400) and an unknown or other-tenant
    device_id (platform 404) render the identical not-found page - the
    platform deliberately gives them the same response so device_id can
    never be used as a cross-tenant existence oracle (contracts/portal-api.md
    "device_id (PAT-2156)"), and this route must not tell the two apart
    either."""
    return _render(request, "error.html", {
        "title": "Not found",
        "message": "That device could not be found in your estate.",
    }, status_code=404)


@app.get("/devices/{device_id}/software", response_class=HTMLResponse)
def device_software(request: Request, device_id: str, stale_days: str = ""):
    """PAT-2156: one device's installed applications and browser extensions -
    the same evidence and approval model /software already gives the whole
    estate (contracts/portal-api.md "device_id (PAT-2156)" on both
    GET /v1/portal/software and GET /v1/portal/extensions), scoped to this
    device. Applications are searched and paginated server-side (the same
    inventory query /software's own table uses); extensions have no
    pagination on the platform (contracts/portal-api.md, PAT-1799 note) and
    are searched client-side, the same data-table-search approach /software
    already uses for its one merged table.

    PAT-2164: this is now one of six device tabs, so it shares the same
    device fetch (_device_base_context) every other tab uses for the page
    head (device name, count strip, tab bar) - the not-found check below
    runs against THAT call, ahead of the software-specific one, so an
    unknown/other-tenant device_id reads the same device-specific not-found
    page here it always has, on the very first call this route makes rather
    than the second."""
    tab = request.query_params.get("tab")
    if tab not in DEVICE_SOFTWARE_TABS:
        tab = "application"
    limit, offset, search = _software_inventory_query(request)

    try:
        base = _device_base_context(request, device_id, stale_days)
    except upstream.UpstreamError as exc:
        if exc.kind in ("invalid", "not_found"):
            return _device_software_not_found(request)
        return _error_page(request, exc)

    try:
        apps_data = upstream.get_json(
            "/v1/portal/software", request.state.jwt,
            params={"device_id": device_id, "limit": limit, "offset": offset, "search": search},
        )
    except upstream.UpstreamError as exc:
        if exc.kind in ("invalid", "not_found"):
            return _device_software_not_found(request)
        return _error_page(request, exc)
    try:
        products, apps_total, returned_limit, returned_offset, _coverage, _generated_at = (
            _software_inventory_envelope(apps_data)
        )
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)

    # PAT-1821: protected-software is a disposition badge only, same
    # fail-soft contract as /software - its own failure never fails this
    # page, it only narrows which rows get badged.
    try:
        protected_data = upstream.get_json("/v1/portal/protected-software", request.state.jwt)
        protected_products = upstream.unwrap_list(protected_data, "products")
    except upstream.UpstreamError:
        protected_products = []
    protected_index = _protected_software_index(protected_products)

    # PAT-2008: write controls only for the customer admin role, fail-soft
    # for display exactly as /software already is - the write route and the
    # platform both re-check role on their own; hiding a control is never
    # the control.
    try:
        role = _portal_role(request.state.jwt)
        role_unavailable = False
    except upstream.UpstreamError as exc:
        logger.warning("portal.device_software.role_fail_soft kind=%s", exc.kind)
        role, role_unavailable = "viewer", True
    can_edit = role == "admin"

    def apps_url(offset_value: int) -> str:
        query = {"tab": "application"}
        if search:
            query["search"] = search
        if offset_value:
            query["offset"] = offset_value
        return f"/devices/{quote(device_id, safe='')}/software?" + urlencode(query)

    apps = {
        "products": [_device_software_row(p, protected_index) for p in products],
        "total": apps_total, "limit": returned_limit, "offset": returned_offset,
        "previous_url": (
            apps_url(max(0, returned_offset - returned_limit)) if returned_offset else None
        ),
        "next_url": (
            apps_url(returned_offset + returned_limit)
            if returned_offset + len(products) < apps_total else None
        ),
    }

    extensions: list = []
    extensions_error = False
    ext_total = 0
    try:
        ext_data = upstream.get_json(
            "/v1/portal/extensions", request.state.jwt, params={"device_id": device_id})
        ext_rows = upstream.unwrap_list(ext_data, "extensions")
        extensions = [_device_extension_row(e) for e in ext_rows]
        ext_total = max(_pagination_integer(ext_data, "total"), len(extensions))
    except upstream.UpstreamError as exc:
        # The device's own existence was already confirmed by the software
        # call above; a failure here is this endpoint being unavailable,
        # not a second 404 to race against the first - fail soft, same
        # posture /software takes for its own supplementary reads.
        logger.warning("portal.device_software.extensions_fail_soft kind=%s", exc.kind)
        extensions_error = True

    # PAT-2164: the Software tab already has both real totals from the two
    # calls above - reuse them for the head's Software N tile and this
    # tab's own count instead of _device_software_tile_totals' separate
    # limit=1 fetch every other tab needs (which would just repeat the
    # apps_total this route already has in full).
    hostname = base["device"].get("hostname") or "Device"
    tabs = _device_tab_definitions(
        device_id, "software", base["cve_tile"], base["issues_tile"],
        (apps_total, ext_total),
    )

    return _render(request, "device_software.html", {
        "title": f"{hostname} - Software installed", "nav": "devices",
        "device": base["device"], "device_id": device_id, "hostname": hostname,
        "cve_tile": base["cve_tile"], "issues_tile": base["issues_tile"], "tabs": tabs,
        "tab": tab, "search": search,
        "apps": apps, "extensions": extensions, "extensions_error": extensions_error,
        "ext_total": ext_total,
        "can_edit": can_edit, "role_unavailable": role_unavailable,
        "csrf_token": _csrf_token(request.state.jwt) if can_edit else "",
        "return_to": _approval_return_to(
            request.url.path + ("?" + request.url.query if request.url.query else "")),
        "approval_result": _approval_flash_view(_read_flash(
            request.state.jwt, request.query_params.get(APPROVAL_RESULT_PARAM, ""))),
    })


# ── Homebrew tab (PAT-1999, reading the PAT-2013 contract) ────────────────
# macOS-only evidence view over GET /v1/portal/homebrew/* (contracts/
# portal-api.md "Homebrew (PAT-2013)"). PAT-2058: formulae and casks now
# join the same approval model as applications and browser extensions - the
# same resolver, the same software_approval_decisions audit table and the
# same PUT /v1/portal/software-approvals write endpoint, no parallel
# approval store. Taps are never approvable (PAT-2013's homebrew_tap
# identity is package-namespace evidence, not a product), so the taps and
# devices sections below stay read-only. Marking a Homebrew package
# Unapproved raises no alert or notification (the contract is explicit:
# software_unapproved_episodes.policy_kind only admits application/
# browser_extension) - this tab must not offer or imply one, so its copy
# never mentions an alert, unlike /software's own toolbar-hint.
#
# "What current means" (contract): a not_present report is authoritative
# absence ("no Homebrew on this Mac"); not_reported is a coverage gap, never
# presented as absence. The contract has no separate signal for "the agent
# is too old to collect Homebrew" - that reads identically to not_reported
# today, which is a real gap, flagged in the ticket report rather than
# guessed at here.
HOMEBREW_DEVICE_STATUS_LABELS = {
    "complete": "Read completely",
    "partial": "Partially read",
    "not_present": "No Homebrew found",
    "failed": "Could not be read",
    "not_reported": "Not yet reported",
}


def _homebrew_summary_view(raw: dict) -> dict:
    status_raw = raw.get("device_status") if isinstance(raw.get("device_status"), dict) else {}
    status = {k: int(status_raw.get(k) or 0)
              for k in ("complete", "partial", "not_present", "failed", "not_reported")}
    return {
        "macos_device_count": int(raw.get("macos_device_count") or 0),
        "devices_with_homebrew": int(raw.get("devices_with_homebrew") or 0),
        "status": status,
        "formula_count": int(raw.get("formula_count") or 0),
        "cask_count": int(raw.get("cask_count") or 0),
        "tap_count": int(raw.get("tap_count") or 0),
        "third_party_tap_count": int(raw.get("third_party_tap_count") or 0),
        "estate_software_installation_count": raw.get("estate_software_installation_count"),
        # PAT-2058: distinct current formulae and casks together (never
        # installations, never taps) resolved to those two approval states
        # (contracts/portal-api.md "GET /v1/portal/homebrew/summary").
        "unreviewed_count": int(raw.get("unreviewed_count") or 0),
        "unapproved_count": int(raw.get("unapproved_count") or 0),
        "generated_at": raw.get("generated_at"),
        # No Mac has ever reported a homebrew block, or reported one that
        # found nothing, and none is currently unread - a genuine, positive
        # "no Homebrew here" reading, not a rendering default.
        "no_homebrew_found": (
            int(raw.get("macos_device_count") or 0) > 0
            and int(raw.get("devices_with_homebrew") or 0) == 0
            and status["failed"] == 0 and status["not_reported"] == 0
        ),
    }


# ── PAT-2043 (second half): per-package CVE counts on the Homebrew tab ────
# Neither GET /v1/portal/homebrew/formulae nor .../casks carries a CVE
# count (contracts/portal-api.md "Homebrew (PAT-2013)" has no such field),
# and GET /v1/portal/findings has no source/package filter ("There is no
# search/filter query param" - same contract, "GET /v1/portal/findings").
# So the only route to a per-package count is to walk the tenant's findings
# once and aggregate the Homebrew-sourced rows in Python, the same way
# findings_csv already walks the same endpoint for its export. This is a
# page load, not an export, so the ceiling below is smaller: it only ever
# feeds one optional column, so stopping early on a runaway tenant degrades
# that column, never the tab itself.
HOMEBREW_CVE_INDEX_PAGE_SIZE = 500
HOMEBREW_CVE_INDEX_MAX_PAGES = 20

HOMEBREW_FINDING_APP_SUFFIX = {
    "homebrew_formula": " (Homebrew formula)",
    "homebrew_cask": " (Homebrew cask)",
}


def _homebrew_finding_package_name(f: dict) -> str | None:
    """The Homebrew package name is not its own field on a findings row -
    only encoded in `app` as "<name> (Homebrew formula)" or "<token>
    (Homebrew cask)" (contracts/portal-api.md, PAT-2023). Anything that
    doesn't match that exact shape is left unmatched rather than guessed
    at."""
    suffix = HOMEBREW_FINDING_APP_SUFFIX.get(f.get("source"))
    app = f.get("app")
    if not suffix or not isinstance(app, str) or not app.endswith(suffix):
        return None
    return app[: -len(suffix)]


def _homebrew_worse_severity(a: str | None, b: str | None) -> str | None:
    """Worse of two severities, ranked by SEVERITY_ORDER. An unranked value
    (missing or unrecognised) only wins when there is nothing else to
    compare it against - it never displaces a known severity."""
    if a is None:
        return b
    if b is None:
        return a
    rank_a = SEVERITY_ORDER.get(a, len(SEVERITY_ORDER))
    rank_b = SEVERITY_ORDER.get(b, len(SEVERITY_ORDER))
    return a if rank_a <= rank_b else b


def _fetch_homebrew_cve_index(jwt_token: str) -> dict | None:
    """Aggregate /v1/portal/findings by (source, package name). Only
    confidence_tier == "high" findings count toward a confirmed count and
    severity - a "low" tier row is a live "version not verifiable" signal,
    counted separately and never presented as confirmed (same rule
    _homebrew_finding_view already applies to the findings list). Returns
    None on any upstream failure so the caller can degrade the CVE column
    to nothing without failing the tab (root AGENTS.md: evidence before
    actuation extends to evidence before a claim - no evidence, no count)."""
    index: dict[tuple, dict] = {}
    offset = 0
    try:
        for _ in range(HOMEBREW_CVE_INDEX_MAX_PAGES):
            data = upstream.get_json(
                "/v1/portal/findings", jwt_token,
                params={"limit": HOMEBREW_CVE_INDEX_PAGE_SIZE, "offset": offset},
            )
            rows = upstream.unwrap_list(data, "findings")
            for f in rows:
                name = _homebrew_finding_package_name(f)
                if name is None:
                    continue
                key = (f.get("source"), name)
                entry = index.setdefault(
                    key, {"confirmed_count": 0, "confirmed_severity": None, "possible_count": 0},
                )
                tier = f.get("confidence_tier")
                if tier == "high":
                    entry["confirmed_count"] += 1
                    entry["confirmed_severity"] = _homebrew_worse_severity(
                        entry["confirmed_severity"], f.get("severity") or None,
                    )
                elif tier == "low":
                    entry["possible_count"] += 1
            if len(rows) < HOMEBREW_CVE_INDEX_PAGE_SIZE:
                break
            offset += HOMEBREW_CVE_INDEX_PAGE_SIZE
    except upstream.UpstreamError:
        return None
    return index


HOMEBREW_CVE_NOT_ASSESSED_TITLE = (
    "No CVE finding has been matched to this package, and the platform does not "
    "report whether Homebrew packages have been assessed, so this is not a clean result."
)


def _homebrew_apply_cve_fields(row: dict, cve_index: dict | None, source: str, name: str,
                               assessment=None) -> None:
    """Attach CVE-count display fields to a formula/cask row, in place.

    cve_index is None when the findings fetch failed outright - every row
    reads "Unavailable" and the tab carries one shared note. A name with no
    entry in an index that *did* fetch successfully means no matched
    findings, not "assessed clean".

    PAT-2255 defect 10: that cell used to be empty, which reads as clean.
    Neither GET /v1/portal/homebrew/formulae nor .../casks carries an
    assessment state (contracts/portal-api.md "Homebrew (PAT-2013)"), so a
    package with no matched finding reads "Not yet assessed". "None found"
    renders only when the row itself carries a platform cve_assessment in
    state `assessed` (the PAT-2024 shape, not sent for Homebrew today), so
    the cell starts saying so the day the platform does, and never before
    (root AGENTS.md: absence requires authority).
    """
    row["cve_confirmed_count"] = None
    row["cve_display_label"] = None
    row["cve_pill_class"] = None
    row["cve_possible_label"] = None
    row["cve_filter"] = "none"
    row["cve_state"] = "unavailable"
    row["cve_state_title"] = "CVE counts could not be read from the platform right now."
    if cve_index is None:
        return
    entry = cve_index.get((source, name))
    if entry is None:
        row["cve_confirmed_count"] = 0
        view = _cve_assessment_product_view(assessment) if isinstance(assessment, dict) else None
        if view is not None and view["state"] == "assessed" and not view["finding_count"]:
            row["cve_state"] = "none_found"
            row["cve_state_title"] = (
                "Assessed: no known CVE matches the installed versions"
                + (f", last matched {humandate(view['last_matched_at'], True)} UTC."
                   if view["last_matched_at"] else "."))
        else:
            row["cve_state"] = "not_assessed"
            row["cve_state_title"] = HOMEBREW_CVE_NOT_ASSESSED_TITLE
        return
    row["cve_state"] = "findings"
    row["cve_state_title"] = ""
    confirmed = entry["confirmed_count"]
    possible = entry["possible_count"]
    row["cve_confirmed_count"] = confirmed
    if confirmed:
        severity = entry["confirmed_severity"]
        plural = "" if confirmed == 1 else "s"
        if severity in SEVERITY_ORDER:
            row["cve_display_label"] = f"{confirmed} CVE{plural} ({severity.capitalize()})"
            row["cve_pill_class"] = f"pill-{severity}"
        else:
            row["cve_display_label"] = f"{confirmed} CVE{plural}"
            row["cve_pill_class"] = "pill-muted"
    if possible:
        plural = "" if possible == 1 else "s"
        row["cve_possible_label"] = f"{possible} possible"
    row["cve_filter"] = "has" if (confirmed or possible) else "none"


def _homebrew_approval(name: str, tap: str, kind: str, raw_state) -> dict:
    """Write item and approval-cell view for one Homebrew formula or cask
    row (PAT-2058, contracts/portal-api.md "PUT /v1/portal/software-
    approvals" Homebrew item shape). Unlike an application, a formula/cask's
    own (name, tap) is always a confirmed identity - GET /v1/portal/homebrew/
    formulae|casks documents approval_state/product_key as "never null" -
    so the only lock path here is a malformed row with no name at all,
    never name-only or no-evidence. `tap` omitted, "" or the package's own
    default tap all address the same identity (softwaregov.
    NormalizeHomebrewTap); this sends whatever the platform reported, which
    the platform normalises on its side regardless."""
    state = raw_state if raw_state in APPROVAL_STATE_LABELS else "unreviewed"
    clean_name = (name or "").strip()
    if not clean_name:
        return _approval_view("", None, state, HOMEBREW_NO_NAME_LOCK)
    item = {"type": kind, "name": clean_name}
    clean_tap = (tap or "").strip()
    if clean_tap:
        item["tap"] = clean_tap
    return _approval_view(
        clean_name, item, state, None, write_states=APPROVAL_HOMEBREW_WRITE_STATES)


def _homebrew_formula_row(f: dict, cve_index: dict | None = None) -> dict:
    on_request = int(f.get("on_request_device_count") or 0)
    name = f.get("name", "")
    row = {
        "name": name, "tap": f.get("tap") or "",
        "third_party_tap": bool(f.get("third_party_tap")),
        "versions": f.get("versions") or [],
        "device_count": int(f.get("device_count") or 0),
        "installation_count": int(f.get("installation_count") or 0),
        "on_request_device_count": on_request,
        "dependency_device_count": int(f.get("dependency_device_count") or 0),
        # Default view is on-request packages; a formula only ever seen as a
        # dependency is hidden until the toggle reveals it (client-side, same
        # data-row-filter idiom the /software kind tabs already use).
        "filter_dep": "on_request" if on_request else "dependency",
        "first_seen_at": f.get("first_seen_at"), "evidence_at": f.get("evidence_at"),
    }
    _homebrew_apply_cve_fields(row, cve_index, "homebrew_formula", name,
                               f.get("cve_assessment"))
    row.update(_homebrew_approval(name, f.get("tap"), "homebrew_formula", f.get("approval_state")))
    return row


def _homebrew_cask_row(c: dict, cve_index: dict | None = None) -> dict:
    linked = int(c.get("linked_app_device_count") or 0)
    app_names = c.get("app_names") or []
    # The Software inventory holds the bundle's display name, not its
    # filename - "Firefox", never "Firefox.app" - so the cross-reference
    # search strips the bundle suffix rather than searching for a name the
    # inventory would never actually match.
    linked_app_name = None
    if linked and app_names and isinstance(app_names[0], str):
        linked_app_name = app_names[0][:-4] if app_names[0].endswith(".app") else app_names[0]
    name = c.get("token") or c.get("name") or ""
    row = {
        "name": name,
        "tap": c.get("tap") or "", "third_party_tap": bool(c.get("third_party_tap")),
        "versions": c.get("versions") or [],
        "device_count": int(c.get("device_count") or 0),
        "installation_count": int(c.get("installation_count") or 0),
        "linked_app_device_count": linked,
        # Linked to an app already in inventory - point at it there instead
        # of this row inventing its own second count of the same install.
        "linked_app_name": linked_app_name,
        "first_seen_at": c.get("first_seen_at"), "evidence_at": c.get("evidence_at"),
    }
    _homebrew_apply_cve_fields(row, cve_index, "homebrew_cask", name,
                               c.get("cve_assessment"))
    row.update(_homebrew_approval(name, c.get("tap"), "homebrew_cask", c.get("approval_state")))
    return row


def _homebrew_tap_row(t: dict) -> dict:
    return {
        "name": t.get("name", ""), "third_party": bool(t.get("third_party")),
        "remote_urls": t.get("remote_urls") or [],
        "device_count": int(t.get("device_count") or 0),
        "first_seen_at": t.get("first_seen_at"), "evidence_at": t.get("evidence_at"),
    }


def _homebrew_device_row(d: dict) -> dict:
    status = d.get("collection_status") or "not_reported"
    prefixes = d.get("prefixes") or []
    return {
        "device_id": d.get("device_id", ""), "hostname": d.get("hostname") or "(unknown)",
        "collection_status": status,
        "collection_status_label": HOMEBREW_DEVICE_STATUS_LABELS.get(
            status, "Status not recognised"),
        "reported_at": d.get("reported_at"),
        "prefixes": prefixes,
        "owners": sorted({p.get("owner") for p in prefixes if p.get("owner")}),
        "formula_count": int(d.get("formula_count") or 0),
        "cask_count": int(d.get("cask_count") or 0),
        "tap_count": int(d.get("tap_count") or 0),
    }


def _homebrew_entry_row(e: dict) -> dict:
    return {
        "kind": e.get("kind", ""), "prefix": e.get("prefix") or "",
        "name": e.get("name") or "", "version": e.get("version"),
        "tap": e.get("tap") or "", "third_party_tap": bool(e.get("third_party_tap")),
        "installed_on_request": e.get("installed_on_request"),
        "installed_as_dependency": e.get("installed_as_dependency"),
        "installed_at": e.get("installed_at"),
        "apps": e.get("apps") or [], "linked_apps": e.get("linked_apps") or [],
        "remote_url": e.get("remote_url"),
        "first_seen_at": e.get("first_seen_at"), "evidence_at": e.get("evidence_at"),
    }


# PAT-2255 defect 9: /homebrew adopts the /software filter bar (the same
# filter_bar macro, the same approval vocabulary and URL keys) in place of
# its three rows of segmented tabs, so the two review surfaces behave the
# same. Every filter is read from the URL and applied server-side, exactly
# as on /software:
#   kind=cask|formula   approval=<comma list of /software group keys>
#   deps=all            include formulae installed only as a dependency
#                       (the default shows packages installed on request)
#   findings=has        only packages with a matched CVE finding
#   search=<text>
HOMEBREW_APPROVAL_GROUP = {
    "unreviewed": "waiting", "approved": "approved", "unapproved": "not_wanted",
    "ignored": "ignored",
}
HOMEBREW_DEPS_DEFAULT = "on_request"


def _homebrew_filter_state(request: Request) -> dict:
    kind = request.query_params.get("kind")
    deps = request.query_params.get("deps")
    findings = request.query_params.get("findings")
    return {
        "kind": kind if kind in ("cask", "formula") else None,
        "approval": _software_approval_filter(request),
        "deps": "all" if deps == "all" else HOMEBREW_DEPS_DEFAULT,
        "findings": "has" if findings == "has" else None,
        "search": request.query_params.get("search", "").strip()[
            :SOFTWARE_INVENTORY_MAX_SEARCH_LENGTH],
    }


def _homebrew_url(state: dict, **overrides) -> str:
    s = {**state, **overrides}
    params: list[tuple[str, str]] = []
    if s.get("kind"):
        params.append(("kind", s["kind"]))
    if s.get("approval"):
        params.append(("approval", ",".join(s["approval"])))
    if s.get("deps") == "all":
        params.append(("deps", "all"))
    if s.get("findings"):
        params.append(("findings", s["findings"]))
    if s.get("search"):
        params.append(("search", s["search"]))
    query = urlencode(params, safe=",", quote_via=quote)
    return "/homebrew" + (f"?{query}" if query else "")


def _homebrew_row_view(row: dict, kind: str) -> None:
    """One formula/cask row's review-surface fields: its kind, its one
    approval state (the same pill vocabulary /software uses), the text
    search matches against, and the CVE cell's word when there is no
    finding (never blank, defect 10)."""
    row["kind"] = kind
    row["group"] = HOMEBREW_APPROVAL_GROUP.get(row.get("approval_state"), "unrecognised")
    label, pill_class = SOFTWARE_STATE_PILL[row["group"]]
    row["state_label"] = label
    row["state_class"] = pill_class
    row["state_title"] = ""
    row["cve_cell_label"] = {
        "not_assessed": "Not yet assessed", "none_found": "None found",
        "unavailable": "Unavailable",
    }.get(row.get("cve_state"))
    row["cve_cell_class"] = {
        "not_assessed": "pill-warn", "none_found": "pill-ok", "unavailable": "pill-muted",
    }.get(row.get("cve_state"))
    parts = (row.get("name"), row.get("tap"), "cask" if kind == "cask" else "formula",
             row.get("linked_app_name"))
    row["search_text"] = " ".join(p for p in parts if isinstance(p, str) and p).lower()


def _homebrew_row_hidden(row: dict, state: dict) -> bool:
    """Server-side mirror of static/js/portal.js's applyFilters() for the
    Homebrew rows (same rules, so first paint and browser agree)."""
    if state["kind"] and row["kind"] != state["kind"]:
        return True
    if state["approval"] and row["group"] not in state["approval"]:
        return True
    if state["deps"] != "all" and row.get("filter_dep") == "dependency":
        return True
    if state["findings"] == "has" and row.get("cve_filter") != "has":
        return True
    return False


def _homebrew_filter_bar_view(state: dict, casks: list, formulae: list) -> dict:
    rows = casks + formulae
    approval_counts = {key: sum(1 for r in rows if r["group"] == key)
                       for key in SOFTWARE_APPROVAL_FILTER_KEYS}
    kind = state["kind"]
    type_options = [
        {"value": "", "label": "All packages", "count": len(rows),
         "selected": kind is None, "hide": False},
        {"value": "cask", "label": "Casks", "count": len(casks),
         "selected": kind == "cask", "hide": not casks and kind != "cask"},
        {"value": "formula", "label": "Formulae", "count": len(formulae),
         "selected": kind == "formula", "hide": not formulae and kind != "formula"},
    ]
    approval_options = [
        {"value": key, "label": label, "count": approval_counts.get(key, 0),
         "selected": key in state["approval"],
         "hide": approval_counts.get(key, 0) == 0 and key not in state["approval"]}
        for key, label in SOFTWARE_APPROVAL_FILTER_OPTIONS
    ]
    chips = []
    if kind:
        chips.append({"label": "Casks" if kind == "cask" else "Formulae",
                      "remove_url": _homebrew_url(state, kind=None)})
    for value in state["approval"]:
        chips.append({"label": SOFTWARE_APPROVAL_FILTER_LABELS[value],
                      "remove_url": _homebrew_url(
                          state, approval=[v for v in state["approval"] if v != value])})
    if state["deps"] == "all":
        chips.append({"label": "Including dependencies",
                      "remove_url": _homebrew_url(state, deps=HOMEBREW_DEPS_DEFAULT)})
    if state["findings"]:
        chips.append({"label": "With CVE findings",
                      "remove_url": _homebrew_url(state, findings=None)})
    active = [name for name in ("kind", "approval", "findings", "search") if state.get(name)]
    if state["deps"] == "all":
        active.insert(2, "deps")
    return {
        "type_options": type_options,
        "approval_options": approval_options,
        "chips": chips,
        "clear_url": "/homebrew" if active else None,
        "hidden_fields": ([{"name": "search", "value": state["search"]}]
                          if state["search"] else []),
        "active_filters": active,
        "search": state["search"],
        "deps": state["deps"],
        "findings": state["findings"] or "",
        "dependency_count": sum(1 for f in formulae if f.get("filter_dep") == "dependency"),
        "with_findings_count": sum(1 for r in rows if r.get("cve_filter") == "has"),
    }


@app.get("/homebrew", response_class=HTMLResponse)
def homebrew(request: Request):
    """Every section below the summary strip is fetched and rendered
    independently: an older platform missing one of the four list
    endpoints, or the summary itself, must degrade that section rather than
    take down the whole page (same fail-soft convention as /software's
    protected-software badge and inventory view)."""
    try:
        summary_raw = upstream.get_json("/v1/portal/homebrew/summary", request.state.jwt)
    except upstream.UpstreamError as exc:
        if exc.kind == "not_found":
            return _render(request, "homebrew.html", {
                "title": "Homebrew", "nav": "homebrew", "available": False,
            })
        return _error_page(request, exc)
    summary = _homebrew_summary_view(summary_raw if isinstance(summary_raw, dict) else {})
    state = _homebrew_filter_state(request)

    def _fetch(path: str, key: str, params: dict, row_fn):
        try:
            data = upstream.get_json(path, request.state.jwt, params=params)
            rows = [row_fn(item) for item in upstream.unwrap_list(data, key)]
        except upstream.UpstreamError:
            return None, True, 0
        raw_total = data.get("total") if isinstance(data, dict) else None
        total = raw_total if isinstance(raw_total, int) else len(rows)
        return rows, False, total

    # PAT-2043: fetched once, ahead of the formula/cask rows themselves, so
    # both row builders can attach a per-package CVE count from the same
    # aggregation rather than each re-walking /v1/portal/findings.
    cve_index = _fetch_homebrew_cve_index(request.state.jwt)
    cve_index_unavailable = cve_index is None

    formulae, formulae_error, formulae_total = _fetch(
        "/v1/portal/homebrew/formulae", "formulae",
        {"include_dependencies": "true", "limit": 500},
        lambda item: _homebrew_formula_row(item, cve_index),
    )
    casks, casks_error, casks_total = _fetch(
        "/v1/portal/homebrew/casks", "casks", {"limit": 500},
        lambda item: _homebrew_cask_row(item, cve_index),
    )
    taps, taps_error, taps_total = _fetch(
        "/v1/portal/homebrew/taps", "taps", {"limit": 500}, _homebrew_tap_row,
    )
    devices, devices_error, devices_total = _fetch(
        "/v1/portal/homebrew/devices", "devices", {"limit": 500}, _homebrew_device_row,
    )

    if formulae is not None:
        formulae.sort(key=lambda r: (-r["device_count"], r["name"].casefold(), r["tap"]))
    if casks is not None:
        casks.sort(key=lambda r: (-r["device_count"], r["name"].casefold()))
    if taps is not None:
        taps.sort(key=lambda r: (not r["third_party"], r["name"].casefold()))
    if devices is not None:
        devices.sort(key=lambda r: r["hostname"].casefold())

    # PAT-2255: one review surface across both tables - rows carry their
    # kind, state and search text, the URL's filters hide what they exclude
    # server-side, and each markable row names the next visible row for the
    # post-write redirect, the same as /software.
    for row in casks or []:
        _homebrew_row_view(row, "cask")
    for row in formulae or []:
        _homebrew_row_view(row, "formula")
    package_rows = (casks or []) + (formulae or [])
    needle = state["search"].lower()
    for row in package_rows:
        row["hidden_filter"] = _homebrew_row_hidden(row, state)
        row["hidden_search"] = bool(needle) and needle not in row["search_text"]
    taken: set = set()
    for row in package_rows:
        row["row_id"] = _software_row_id(row, taken)
    visible_ids = [r["row_id"] for r in package_rows
                   if not r["hidden_filter"] and not r["hidden_search"]]
    for row in package_rows:
        if row["row_id"] in visible_ids:
            i = visible_ids.index(row["row_id"])
            row["next_row_id"] = (visible_ids[i + 1] if i + 1 < len(visible_ids)
                                  else (visible_ids[i - 1] if i else ""))
        else:
            row["next_row_id"] = visible_ids[0] if visible_ids else ""
    filter_bar = _homebrew_filter_bar_view(state, casks or [], formulae or [])

    # PAT-2058: write controls only for the customer admin role, same
    # fail-soft role read as /software - hiding a control is never the
    # control, the write route and the platform both re-check it.
    try:
        role = _portal_role(request.state.jwt)
        role_unavailable = False
    except upstream.UpstreamError as exc:
        logger.warning("portal.homebrew.role_fail_soft kind=%s", exc.kind)
        role, role_unavailable = "viewer", True
    can_edit = role == "admin"

    return _render(request, "homebrew.html", {
        "title": "Homebrew", "nav": "homebrew", "available": True, "summary": summary,
        "formulae": formulae, "formulae_error": formulae_error, "formulae_total": formulae_total,
        "casks": casks, "casks_error": casks_error, "casks_total": casks_total,
        "casks_visible": sum(1 for r in casks or []
                             if not r["hidden_filter"] and not r["hidden_search"]),
        "formulae_visible": sum(1 for r in formulae or []
                                if not r["hidden_filter"] and not r["hidden_search"]),
        "homebrew_filter_bar": filter_bar,
        "taps": taps, "taps_error": taps_error, "taps_total": taps_total,
        "devices": devices, "devices_error": devices_error, "devices_total": devices_total,
        "cve_index_unavailable": cve_index_unavailable,
        "can_edit": can_edit, "role_unavailable": role_unavailable,
        "csrf_token": _csrf_token(request.state.jwt) if can_edit else "",
        "return_to": _approval_return_to(
            request.url.path + ("?" + request.url.query if request.url.query else "")),
        "approval_result": _approval_flash_view(_read_flash(
            request.state.jwt, request.query_params.get(APPROVAL_RESULT_PARAM, ""))),
    })


@app.get("/homebrew/devices/{device_id}", response_class=HTMLResponse)
def homebrew_device_detail(request: Request, device_id: str, kind: str = ""):
    kind_filter = kind if kind in ("formula", "cask", "tap") else None
    params = {"limit": 500}
    if kind_filter:
        params["kind"] = kind_filter
    try:
        data = upstream.get_json(
            f"/v1/portal/homebrew/devices/{quote(device_id, safe='')}",
            request.state.jwt, params=params,
        )
        entries = [_homebrew_entry_row(e) for e in upstream.unwrap_list(data, "entries")]
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    state = data.get("state") if isinstance(data.get("state"), dict) else {}
    return _render(request, "homebrew_device.html", {
        "title": (state.get("hostname") or "Homebrew device") + " - Homebrew",
        "nav": "homebrew",
        "device": _homebrew_device_row(state), "entries": entries, "kind_filter": kind_filter,
    })


# The CSV export claims to hold the full estate, so it has to actually
# fetch the full estate rather than one 500-row page. HOMEBREW_CSV_MAX_PAGES
# gives a ceiling far above anything a real estate produces today, matching
# get_device_roster's own DEVICES_MAX_PAGES magnitude, so the loop below
# cannot run forever against a drifting or hostile total.
HOMEBREW_CSV_PAGE_SIZE = 500
HOMEBREW_CSV_MAX_PAGES = 50


def _homebrew_paginate_list(
    path: str, jwt_token: str, key: str, params: dict | None = None,
) -> tuple[list, bool, int]:
    """Page a /v1/portal/homebrew/* list endpoint to completion for the CSV
    export, aggregating fully before the caller starts streaming (same
    convention as get_device_roster: a later page's failure must still
    become the portal's normal error page, not a partial download that
    looks complete).

    A non-advancing offset, a limit the platform did not honour, or a total
    that changes mid-read are contract violations and raise, exactly like
    get_device_roster. Hitting the page-count ceiling is different: a
    genuinely huge estate is not a contract violation, so that case returns
    what was read plus truncated=True instead of raising, letting the CSV
    itself say it stopped early rather than either looping forever or
    failing an export that is merely large.
    """
    rows: list = []
    offset = 0
    expected_total = None
    for _ in range(HOMEBREW_CSV_MAX_PAGES):
        page_params = dict(params or {})
        page_params["limit"] = HOMEBREW_CSV_PAGE_SIZE
        page_params["offset"] = offset
        data = upstream.get_json(path, jwt_token, params=page_params)
        if not isinstance(data, dict):
            raise upstream.UpstreamError("error", f"invalid {key} pagination envelope")
        page_rows = upstream.unwrap_list(data, key)
        total = _pagination_integer(data, "total")
        page_limit = _pagination_integer(data, "limit")
        page_offset = _pagination_integer(data, "offset")
        if page_limit != HOMEBREW_CSV_PAGE_SIZE or page_offset != offset:
            raise upstream.UpstreamError("error", f"non-advancing {key} pagination metadata")
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            raise upstream.UpstreamError("error", f"{key} pagination total changed during read")
        if len(page_rows) > page_limit or len(rows) + len(page_rows) > total:
            raise upstream.UpstreamError("error", f"{key} page exceeds reported total")
        rows.extend(page_rows)
        if len(rows) == total:
            return rows, False, total
        if not page_rows:
            raise upstream.UpstreamError("error", f"{key} pagination ended before reported total")
        offset += len(page_rows)
    return rows, True, expected_total if expected_total is not None else len(rows)


HOMEBREW_CSV_COLUMNS = (
    "kind", "name", "tap", "third_party_tap", "versions", "device_count",
    "installation_count", "on_request_device_count", "dependency_device_count",
    "first_seen_at", "evidence_at",
)


def _homebrew_export_table(request: Request) -> _ExportTable:
    """Every formula (on request or dependency) and every cask, one row
    each, paginated to completion before anything is sent so a later failure
    can never send a partial body. Raises UpstreamError."""
    formulae, formulae_truncated, formulae_total = _homebrew_paginate_list(
        "/v1/portal/homebrew/formulae", request.state.jwt, "formulae",
        {"include_dependencies": "true"},
    )
    casks, casks_truncated, casks_total = _homebrew_paginate_list(
        "/v1/portal/homebrew/casks", request.state.jwt, "casks",
    )
    rows = []
    for f in formulae:
        rows.append([
            "formula", f.get("name", ""), f.get("tap", ""), f.get("third_party_tap", False),
            ";".join(f.get("versions") or []), f.get("device_count", 0),
            f.get("installation_count", 0), f.get("on_request_device_count", 0),
            f.get("dependency_device_count", 0),
            f.get("first_seen_at", ""), f.get("evidence_at", ""),
        ])
    for c in casks:
        rows.append([
            "cask", c.get("token") or c.get("name", ""), c.get("tap", ""),
            c.get("third_party_tap", False), ";".join(c.get("versions") or []),
            c.get("device_count", 0), c.get("installation_count", 0), "", "",
            c.get("first_seen_at", ""), c.get("evidence_at", ""),
        ])
    # Only ever reached if a single kind's row count clears the safety
    # ceiling above (25,000 rows). The export never stops silently.
    if formulae_truncated:
        rows.append([
            "notice", f"Formulae export stopped at {len(formulae)} of "
            f"{formulae_total} rows, the most one export can hold.",
            "", "", "", "", "", "", "", "", "",
        ])
    if casks_truncated:
        rows.append([
            "notice", f"Casks export stopped at {len(casks)} of "
            f"{casks_total} rows, the most one export can hold.",
            "", "", "", "", "", "", "", "", "",
        ])
    return _ExportTable("homebrew", "patched-homebrew.csv", list(HOMEBREW_CSV_COLUMNS),
                        [[_cell(v) for v in r] for r in rows], [])


@app.get("/homebrew.csv")
def homebrew_csv(request: Request):
    """CSV export of the full estate Homebrew inventory: every formula (on
    request or dependency) and every cask, one row each."""
    try:
        table = _homebrew_export_table(request)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    return _table_csv_response(table)


@app.get("/homebrew.pdf")
def homebrew_pdf(request: Request):
    """PAT-2405: the same table as /homebrew.csv, as a PDF."""
    try:
        table = _homebrew_export_table(request)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    return _table_pdf_response(request, table)


@app.get("/unapproved-apps")
def unapproved_apps_redirect():
    """PAT-1643: merged into /software. Kept as a 301 (not just removed) so
    existing bookmarks and any report deep links keep working."""
    return RedirectResponse(url="/software", status_code=301)


@app.get("/extensions")
def extensions_redirect():
    """PAT-1643: merged into /software. Kept as a 301 (not just removed) so
    existing bookmarks and any report deep links keep working."""
    return RedirectResponse(url="/software", status_code=301)


EXCEPTION_STATUS_LABELS = {
    "accepted": "Accepted",
    "unaccepted": "Unaccepted",
}


def _exception_status_label(status: str) -> str:
    # Absence requires authority: a status value this page doesn't
    # recognise must say so, never silently read as accepted OR unaccepted.
    return EXCEPTION_STATUS_LABELS.get(status, "Status not recognised")


def _exception_row(item: dict) -> dict:
    status = item.get("status", "")
    return {
        "id": item.get("id", ""),
        "product": item.get("product", ""),
        "version": item.get("version", ""),
        "kind": item.get("type", ""),
        "device_count": item.get("device_count") or 0,
        "devices": item.get("devices") or [],
        "devices_truncated": bool(item.get("devices_truncated")),
        "requested_by": item.get("requested_by", ""),
        "requested_at": item.get("requested_at", ""),
        "depends_on": item.get("depends_on", ""),
        "acceptor": item.get("acceptor") or None,
        "accepted_at": item.get("accepted_at") or None,
        "status": status,
        "status_label": _exception_status_label(status),
        # review_overdue is taken as reported, never recomputed from
        # review_date client-side - "today" belongs to the platform, not a
        # browser or this server's own clock, and it must stay true for an
        # accepted exception exactly as for an unaccepted one (a review
        # date lapsing never depends on acceptance status).
        "review_date": item.get("review_date") or None,
        "review_overdue": bool(item.get("review_overdue")),
        "history": item.get("history") or [],
    }


def _exception_group(row: dict) -> str:
    if row["status"] not in EXCEPTION_STATUS_LABELS:
        return "unrecognised"
    # Rules (PAT-1785): unaccepted is a first-class status and a review
    # date raising a finding when it passes is independent of acceptance -
    # either one alone is enough to need attention, so an accepted
    # exception with a lapsed review date still sorts here, not into the
    # clear "accepted" group.
    if row["status"] == "unaccepted" or row["review_overdue"]:
        return "needs_attention"
    return "accepted"


@app.get("/exceptions", response_class=HTMLResponse)
def exceptions(request: Request):
    """PAT-1785: per-tenant software exception register - pinned versions
    and accepted risk, with a named acceptor or a first-class "unaccepted"
    status. An exception never removes a finding from any report (root
    AGENTS.md: absence requires authority); this page exists alongside
    /findings and /software, not instead of either.

    Relationship to the app policy model (mandatory/approved/unapproved,
    /software): deliberately orthogonal, not merged. An exception records
    accepted risk for a specific pinned version with an acceptor, a review
    date and a dependency reason - fields no policy row carries - and a
    product can be policy-unapproved while carrying an accepted exception
    at the same time. Conflating the two would let an exception's identity
    (product + version) stand in for a policy decision it never made
    (root AGENTS.md: identity is not packaging).

    A pinned version never suppresses a CVE for that product/version -
    only the platform-side "update available" noise it may also quiet, per
    the same never-remove-a-finding rule. That suppression, like the data
    model and admin/API surface below, is platform-side work; see PAT-1785
    follow-up.

    Read-only, matching every other governance surface here (PAT-1642
    devices, PAT-1643/PAT-1742 software): the portal never records a
    disposition itself. A customer asks (mailto, specialist-routed); a
    named Patched specialist records the acceptance, the acceptor, or a
    review-date renewal on the admin side (12 Sept portal decision).

    The shipped platform contract is PAT-1824's
    `go-service/internal/handlers/software_exceptions.go`,
    `PortalExceptionsHandler`. This route only forwards the verified JWT to
    that tenant-scoped endpoint and consumes its returned exception list plus
    `total`/`truncated` fields. The platform owns row caps, ordering,
    review-overdue calculation and the append-only decision history; do not
    duplicate a speculative contract here.
    """
    try:
        data = upstream.get_json("/v1/portal/exceptions", request.state.jwt)
        items = upstream.unwrap_list(data, "exceptions")
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)

    rows = [_exception_row(i) for i in items]
    groups: dict[str, list] = {"needs_attention": [], "accepted": [], "unrecognised": []}
    for row in rows:
        groups[_exception_group(row)].append(row)
    for group_rows in groups.values():
        group_rows.sort(key=lambda r: r["product"].casefold())

    total = data.get("total", len(rows)) if isinstance(data, dict) else len(rows)
    truncated = bool(data.get("truncated")) if isinstance(data, dict) else False

    return _render(request, "exceptions.html", {
        "title": "Exceptions", "nav": "exceptions",
        "needs_attention": groups["needs_attention"],
        "accepted": groups["accepted"],
        "unrecognised": groups["unrecognised"],
        "total": total, "shown": len(rows), "truncated": truncated,
    })


# ── Local admins (PAT-2215) ─────────────────────────────────────────────────
# Standing local-administrator roster: PAT-1974's account names (previously
# only a bare count on the device Compliance tab and a report under
# Reports), PAT-1988/1992's built-in-Administrator account_state. One
# platform call (GET /v1/portal/local-admins, contracts/portal-api.md)
# carries the whole page - unlike /homebrew this page needs no additional
# per-section fetch.
#
# Account names are personal data, so the whole page - not just a write
# control - is admin role only. The platform's own GET already 403s a
# viewer with {"error":"admin_role_required"}; this route reads that same
# body shape (main.py already parses it for the write routes' refusal
# banners) to show a plain notice instead of the roster, and never renders
# a name for a role the platform itself would refuse to serve.
LOCAL_ADMIN_PLATFORM_LABELS = {"macos": "macOS", "windows": "Windows"}
LOCAL_ADMIN_PRINCIPAL_TYPE_LABELS = {
    "user": "User", "group": "Group", "unresolved": "Unresolved",
}
LOCAL_ADMIN_OVER_LIMIT_LABELS = {"yes": "Over the limit", "no": "Within the limit"}
LOCAL_ADMIN_UNKNOWN_LABELS = {"yes": "Could not be read", "no": "Read"}


class _LocalAdminsForbidden(Exception):
    """Internal marker: the caller is signed in but not a portal admin.
    Never a customer-facing message on its own - the route that catches it
    decides how to say so."""


def _fetch_local_admins(jwt_token: str) -> dict:
    """GET /v1/portal/local-admins, raising _LocalAdminsForbidden for the
    admin-role refusal specifically (never confused with PAT-699's "account
    not linked to an estate" 403, which _error_page already maps to
    not_linked.html and would be the wrong page here - the caller here is
    fully linked, just not an admin)."""
    try:
        data = upstream.get_json("/v1/portal/local-admins", jwt_token)
    except upstream.UpstreamError as exc:
        if exc.kind == "forbidden":
            try:
                body = json.loads(exc.body) if exc.body else {}
            except ValueError:
                body = {}
            if isinstance(body, dict) and body.get("error") == "admin_role_required":
                raise _LocalAdminsForbidden() from None
        raise
    if not isinstance(data, dict) or not isinstance(data.get("devices"), list):
        raise upstream.UpstreamError("error", "invalid local admins response")
    # The platform contract is an unpaged full-estate response. Refuse a
    # future paged/truncated envelope rather than silently exporting a slice.
    total = data.get("total", len(data["devices"]))
    if (data.get("truncated") or data.get("has_more") or data.get("next_cursor")
            or data.get("next") or data.get("offset", 0) != 0
            or type(total) is not int or total != len(data["devices"])
            or any(not isinstance(d, dict) for d in data["devices"])):
        raise upstream.UpstreamError("error", "incomplete local admins response")
    for device in data["devices"]:
        principals = device.get("principals")
        if principals is not None and (
            not isinstance(principals, list)
            or any(not isinstance(principal, dict) for principal in principals)
        ):
            raise upstream.UpstreamError("error", "invalid local admins principals")
    return data


def _local_admins_admin_only_page(request: Request) -> HTMLResponse:
    return _render(request, "local_admins.html", {
        "title": "Local admins", "nav": "local-admins", "admin_only": True,
    }, status_code=403)


def _local_admins_principal_note(p: dict) -> str:
    """Plain-language caveat next to one principal, per PAT-1974's own
    principal rules: a directory group is labelled as a group, not a
    person, and its own membership stays opaque to the device; an
    unresolved SID states so rather than being guessed at; a built-in
    Administrator states its own account_state plainly (PAT-1992), or
    that it is included when the platform has not established a state -
    never silently omitted (root AGENTS.md: absence requires authority)."""
    if p.get("builtin"):
        state = p.get("account_state")
        if state == "disabled":
            return "Built-in Administrator, disabled"
        if state == "enabled":
            return "Built-in Administrator, enabled"
        if state == "unknown":
            return "Built-in Administrator, enabled state not established"
        return "Built-in Administrator, included"
    if p.get("principal_type") == "group":
        return "Directory group, not a person"
    if p.get("principal_type") == "unresolved":
        return "Unresolved - could not be matched to a name"
    return ""


def _local_admins_principal_view(p: dict) -> dict:
    raw_type = p.get("principal_type") if isinstance(p.get("principal_type"), str) else ""
    return {
        "name": p.get("name") or "",
        "principal_type": raw_type,
        "type_label": LOCAL_ADMIN_PRINCIPAL_TYPE_LABELS.get(raw_type, "Not recognised"),
        "builtin": bool(p.get("builtin")),
        "account_state": p.get("account_state"),
        "note": _local_admins_principal_note(p),
    }


def _local_admins_device_row(d: dict) -> dict:
    principals = [
        _local_admins_principal_view(p) for p in (d.get("principals") or [])
        if isinstance(p, dict)
    ]
    passed = d.get("pass")
    membership_readable = bool(d.get("membership_readable"))
    # Membership is multi-valued: a device with an unresolved SID can also
    # have users and groups. No priority summary may hide those memberships.
    types_present = {p["principal_type"] for p in principals}
    return {
        "device_id": d.get("device_id") or "",
        "hostname": d.get("hostname") or "Unknown device",
        "platform": d.get("platform") or "",
        "reported_admin_count": d.get("reported_admin_count"),
        "assessed_admin_count": d.get("assessed_admin_count"),
        "pass": passed,
        "membership_readable": membership_readable,
        "collection_status": d.get("collection_status") or "",
        "builtin_admin_note": d.get("builtin_admin_note") or "",
        "principals": principals,
        "principal_count": len(principals),
        "filter_platform": d.get("platform") or "",
        "filter_principal_type": ",".join(sorted(types_present)),
        "filter_over_limit": "yes" if passed is False else "no" if passed is True else "",
        "filter_unknown": "no" if membership_readable else "yes",
    }


def _local_admins_account_rows(devices: list[dict]) -> list[dict]:
    """Groups every principal across devices by (principal_type, name) -
    the same key the platform's own distinct_accounts figure uses
    (contracts/portal-api.md) - so a directory group or user standing admin
    on several devices counts once here too, with every device it holds
    that on. over_limit is "yes" the moment any linked device is itself
    over the limit; a device this page could not assess (pass is unknown)
    never on its own makes an account "over the limit" - a real fail on
    another linked device is still the deciding fact, never invented from
    an unknown one."""
    accounts: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []
    for d in devices:
        for p in d["principals"]:
            key = (p["principal_type"], p["name"])
            if key not in accounts:
                accounts[key] = {
                    "name": p["name"], "principal_type": p["principal_type"],
                    "type_label": p["type_label"], "builtin": p["builtin"],
                    "note": p["note"], "devices": [], "platforms": set(),
                    "over_limit": "no",
                }
                order.append(key)
            row = accounts[key]
            row["devices"].append({
                "device_id": d["device_id"], "hostname": d["hostname"],
                "platform": d["platform"], "pass": d["pass"],
                "membership_readable": d["membership_readable"],
                "collection_status": d["collection_status"],
                "builtin": p["builtin"], "account_state": p["account_state"],
                "note": p["note"],
            })
            if d["platform"]:
                row["platforms"].add(d["platform"])
            if d["filter_over_limit"] == "yes":
                row["over_limit"] = "yes"
    rows = []
    for key in order:
        row = accounts[key]
        row["device_count"] = len(row["devices"])
        row["platform"] = ",".join(sorted(row["platforms"]))
        row["filter_platform"] = row["platform"]
        row["filter_principal_type"] = row["principal_type"]
        # Match any linked device's evidence, including an unknown verdict.
        row["filter_over_limit"] = ",".join(sorted({
            "yes" if d["pass"] is False else "no" if d["pass"] is True else ""
            for d in row["devices"]
        }))
        row["filter_unknown"] = ",".join(sorted({
            "no" if d["membership_readable"] else "yes" for d in row["devices"]
        }))
        notes = sorted({d["note"] for d in row["devices"] if d["note"]})
        row["note"] = "; ".join(notes)
        rows.append(row)
    rows.sort(key=lambda r: r["name"].casefold())
    return rows


LOCAL_ADMIN_FILTERS = {
    "platform": LOCAL_ADMIN_PLATFORM_LABELS,
    "principal_type": LOCAL_ADMIN_PRINCIPAL_TYPE_LABELS,
    "over_limit": LOCAL_ADMIN_OVER_LIMIT_LABELS,
    "unknown": LOCAL_ADMIN_UNKNOWN_LABELS,
}
LOCAL_ADMIN_SORTS = {
    "account": {"name": "Account", "type": "Type", "device_count": "Devices",
                "device_list": "Device list"},
    "device": {"hostname": "Device", "platform": "Platform", "count": "Count",
               "limit": "Against the limit", "membership": "Membership"},
}


def _local_admins_state(request: Request) -> dict:
    view = "device" if request.query_params.get("view") == "device" else "account"
    sorts = LOCAL_ADMIN_SORTS[view]
    sort = request.query_params.get("sort")
    return {
        "view": view,
        "sort": sort if sort in sorts else next(iter(sorts)),
        "direction": "desc" if request.query_params.get("direction") == "desc" else "asc",
        "search": request.query_params.get("search", "").strip(),
        **{key: _ai_tooling_multiselect(request, key, labels)
           for key, labels in LOCAL_ADMIN_FILTERS.items()},
    }


def _local_admins_url(state: dict, path="/local-admins", **changes) -> str:
    state = {**state, **changes}
    params = [(key, ",".join(value) if isinstance(value, list) else value)
              for key, value in state.items() if value]
    return path + ("?" + urlencode(params) if params else "")


def _local_admins_rows(data: dict, state: dict) -> tuple[list, list, list]:
    """The single membership, search and order pipeline for HTML and CSV.

    Filters are AND across fields, OR within a field, matching any exact
    comma-separated row token. Search covers the same explicit row text on
    first paint and export. Unknown sortable evidence stays last in both
    directions; stable identity tie breaks make repeated downloads predictable.
    """
    devices = [_local_admins_device_row(d) for d in data["devices"]]
    devices.sort(key=lambda d: (d["hostname"].casefold(), d["device_id"]))
    accounts = _local_admins_account_rows(devices)
    rows = accounts if state["view"] == "account" else devices
    for row in rows:
        if state["view"] == "account":
            row["sort_values"] = {
                "name": row["name"].casefold(), "type": row["type_label"].casefold(),
                "device_count": row["device_count"],
                "device_list": ", ".join(d["hostname"] for d in row["devices"]).casefold(),
            }
            search = [row["name"], row["type_label"], row["note"], row["platform"],
                      str(row["device_count"]), row["sort_values"]["device_list"]]
            row["identity"] = (row["name"].casefold(), row["principal_type"], row["name"])
        else:
            limit = ("Within limit" if row["pass"] is True else
                     "Over limit" if row["pass"] is False else "Unknown")
            membership = ("Read (partial)" if row["collection_status"] == "partial"
                          else "Read") if row["membership_readable"] else "Could not be read"
            row["sort_values"] = {
                "hostname": row["hostname"].casefold(), "platform": row["platform"].casefold(),
                "count": row["assessed_admin_count"],
                "limit": limit.casefold() if row["pass"] is not None else None,
                "membership": membership.casefold(),
            }
            search = [row["hostname"], row["platform"], limit, membership,
                      str(row["assessed_admin_count"]) if row["assessed_admin_count"] is not None
                      else "Unknown", row["builtin_admin_note"]]
            search += [p["name"] + " " + p["type_label"] + " " + p["note"]
                       for p in row["principals"]]
            row["identity"] = (row["hostname"].casefold(), row["device_id"])
        row["search_text"] = " ".join(search).lower()
        row["hidden"] = (
            any(state[key] and not set(state[key]).intersection(row["filter_" + key].split(","))
                for key in LOCAL_ADMIN_FILTERS)
            or state["search"].lower() not in row["search_text"]
        )
    rows.sort(key=lambda r: r["identity"])
    known = [r for r in rows if r["sort_values"][state["sort"]] is not None]
    unknown = [r for r in rows if r["sort_values"][state["sort"]] is None]
    known.sort(key=lambda r: r["sort_values"][state["sort"]], reverse=state["direction"] == "desc")
    rows[:] = known + unknown
    return devices, accounts, [r for r in rows if not r["hidden"]]


def _local_admins_filter_bar_view(state: dict, rows: list) -> dict:
    result = {"chips": []}
    option_keys = {"platform": "platform", "principal_type": "principal",
                   "over_limit": "over_limit", "unknown": "unknown"}
    for key, labels in LOCAL_ADMIN_FILTERS.items():
        options = []
        for value, label in labels.items():
            count = sum(value in row["filter_" + key].split(",") for row in rows)
            options.append({"value": value, "label": label, "count": count,
                            "selected": value in state[key], "muted": count == 0})
            if value in state[key]:
                result["chips"].append({
                    "label": ("Membership: " if key == "unknown" else "") + label,
                    "remove_url": _local_admins_url(
                        state, **{key: [v for v in state[key] if v != value]}),
                })
        result[option_keys[key] + "_options"] = options
    if state["search"]:
        result["chips"].append({"label": "Search: " + state["search"],
                                "remove_url": _local_admins_url(state, search="")})
    result["clear_url"] = _local_admins_url(
        state, search="", **{key: [] for key in LOCAL_ADMIN_FILTERS})
    for view in ("account", "device"):
        sort = state["sort"] if view == state["view"] else next(iter(LOCAL_ADMIN_SORTS[view]))
        result[view + "_view_url"] = _local_admins_url(state, view=view, sort=sort)
    result["sorts"] = [{
        "key": key, "label": label, "active": key == state["sort"],
        "url": _local_admins_url(state, sort=key,
                                 direction=("desc" if key == state["sort"]
                                            and state["direction"] == "asc" else "asc")),
    } for key, label in LOCAL_ADMIN_SORTS[state["view"]].items()]
    return result


def _local_admins_summary_tiles(over_limit, distinct_accounts, unreadable) -> list[dict]:
    """The three estate tiles (PAT-2215): devices over the admin limit,
    distinct accounts holding standing admin, and devices where membership
    could not be read. Same .ai-summary-grid/.ov-card idiom as AI Tooling's
    own summary strip (PAT-2213) rather than a new tile style. Every figure
    comes straight from the platform's own /v1/portal/local-admins response
    (over_limit_devices/distinct_accounts/unreadable_devices) - none is
    recomputed here. A figure the platform could not establish renders
    "Unknown", never a fabricated 0 (root AGENTS.md: absence requires
    authority) - unreadable itself is always a real count from the
    platform today, but this stays defensive rather than assuming so."""
    def tile(label, value, href, warn=False):
        available = isinstance(value, int)
        headline = str(value) if available else "Unknown"
        zero = available and value == 0
        return {
            "label": label, "headline": headline, "zero": zero,
            "warn": bool(available and value and warn), "href": href,
        }
    return [
        tile("Over the limit", over_limit,
             "/local-admins?over_limit=yes#local-admins-table", warn=True),
        tile("Distinct accounts", distinct_accounts, "#local-admins-table"),
        tile("Membership could not be read", unreadable,
             "/local-admins?view=device&unknown=yes#local-admins-table", warn=True),
    ]


@app.get("/local-admins", response_class=HTMLResponse)
def local_admins(request: Request):
    """Governance -> Local admins (PAT-2215): the standing local-
    administrator roster behind the existing "local-admin" report and the
    device Compliance tab's single pass/fail rule (cis_macos_5_8_
    local_admin_count / cis_win_5_8_local_admin_count), shown by account
    (default) and by device. Read-only, matching every other governance
    surface in this repo; nothing here suggests Patched removes admin
    rights (rubric C1) - it states who holds standing admin and whether the
    device is within the rule's threshold, nothing more.

    Account names are personal data, so the whole page - not just a write
    control - is admin role only; a viewer sees a plain notice instead of
    the roster. The platform re-checks the role on its own GET (see
    _fetch_local_admins); this route's own check is display only.
    """
    try:
        data = _fetch_local_admins(request.state.jwt)
    except _LocalAdminsForbidden:
        return _local_admins_admin_only_page(request)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)

    state = _local_admins_state(request)
    devices, accounts, visible = _local_admins_rows(data, state)
    view = state["view"]
    filter_bar = _local_admins_filter_bar_view(state, accounts if view == "account" else devices)

    threshold = data.get("threshold")
    summary_tiles = _local_admins_summary_tiles(
        data.get("over_limit_devices"), data.get("distinct_accounts"),
        data.get("unreadable_devices"),
    )

    return _render(request, "local_admins.html", {
        "title": "Local admins", "nav": "local-admins", "admin_only": False,
        "threshold": threshold if isinstance(threshold, int) else 2,
        "summary_tiles": summary_tiles,
        "devices": devices, "accounts": accounts,
        "devices_total": len(devices), "accounts_total": len(accounts),
        "view": view, "filter_bar": filter_bar, "state": state,
        "visible_count": len(visible),
        "export_view_url": _local_admins_url(state, "/local-admins.csv", scope="view"),
        "export_view_pdf_url": _local_admins_url(state, "/local-admins.pdf", scope="view"),
    })


def _local_admins_export_table(request: Request) -> _ExportTable:
    """The selected entity rows with scope=view, or the original all-estate
    device/principal pairs at the bare URL. Both retain unreadable devices,
    unknown counts and per-device principal evidence. Raises
    _LocalAdminsForbidden for a caller who is not an admin, and UpstreamError."""
    data = _fetch_local_admins(request.state.jwt)
    state = _local_admins_state(request)
    devices, _accounts, visible = _local_admins_rows(data, state)
    export_view = request.query_params.get("scope") == "view"
    rows: list[list] = []
    filters: list[tuple[str, str]] = []
    if export_view:
        filters.append(("View", "By account" if state["view"] == "account" else "By device"))
        if state["search"]:
            filters.append(("Search", state["search"]))
        for key, label in (("platform", "Platform"), ("principal_type", "Principal type"),
                           ("over_limit", "Admin count"), ("unknown", "Membership")):
            if state[key]:
                names = LOCAL_ADMIN_FILTERS[key]
                filters.append((label, ", ".join(names[v] for v in state[key])))
        if state["view"] == "account":
            columns = ["account", "principal_type", "device_count", "device_list",
                       "notes", "devices_json"]
            for row in visible:
                rows.append([row["name"], row["principal_type"], row["device_count"],
                             "; ".join(d["hostname"] for d in row["devices"]), row["note"],
                             json.dumps(row["devices"], ensure_ascii=False)])
        else:
            columns = ["device_id", "hostname", "platform", "reported_admin_count",
                       "assessed_admin_count", "pass", "membership_readable",
                       "collection_status", "builtin_admin_note",
                       "principal_names", "principals_json"]
            for row in visible:
                rows.append([row["device_id"], row["hostname"], row["platform"],
                             row["reported_admin_count"], row["assessed_admin_count"],
                             row["pass"],
                             row["membership_readable"], row["collection_status"],
                             row["builtin_admin_note"],
                             "; ".join(p["name"] for p in row["principals"]),
                             json.dumps(row["principals"], ensure_ascii=False)])
    else:
        # The original all-estate format stays available at the bare URL.
        devices.sort(key=lambda d: (d["hostname"].casefold(), d["device_id"]))
        columns = [
            "device_id", "hostname", "platform", "reported_admin_count",
            "assessed_admin_count", "pass", "membership_readable", "collection_status",
            "principal_name", "principal_type", "builtin", "account_state", "note",
        ]
        for d in devices:
            base = [
                d["device_id"], d["hostname"], d["platform"] or "",
                d["reported_admin_count"] if d["reported_admin_count"] is not None else "",
                d["assessed_admin_count"] if d["assessed_admin_count"] is not None else "",
                "" if d["pass"] is None else d["pass"],
                d["membership_readable"], d["collection_status"],
            ]
            if not d["principals"]:
                rows.append(base + ["", "", "", "", ""])
                continue
            for p in d["principals"]:
                rows.append(base + [
                    p["name"], p["principal_type"], p["builtin"],
                    p["account_state"] or "", p["note"],
                ])
    filename = (f"patched-local-admins-by-{state['view']}.csv" if export_view
                else "patched-local-admins.csv")
    return _ExportTable("local-admins", filename, columns,
                        [[_cell(v) for v in r] for r in rows], filters)


def _local_admins_refusal() -> Response:
    return Response(
        content="Local admins export is available to portal admins only.\n",
        media_type="text/plain", status_code=403,
    )


@app.get("/local-admins.csv")
def local_admins_csv(request: Request):
    """Export the selected entity rows with scope=view, or the original
    all-estate device/principal pairs at the bare URL. Both retain unreadable
    devices, unknown counts and per-device principal evidence."""
    try:
        table = _local_admins_export_table(request)
    except _LocalAdminsForbidden:
        return _local_admins_refusal()
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    return _table_csv_response(table)


@app.get("/local-admins.pdf")
def local_admins_pdf(request: Request):
    """PAT-2405: the same table as /local-admins.csv, as a PDF. Admin only,
    refused exactly as the CSV is, before any PDF call: account names are
    personal data."""
    try:
        table = _local_admins_export_table(request)
    except _LocalAdminsForbidden:
        return _local_admins_refusal()
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    return _table_pdf_response(request, table, on_forbidden=_local_admins_refusal)


WEEKDAY_NAMES = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday",
                 "Friday", "Saturday"]  # index = platform weekday (0=Sunday)


def _schedule_summary(schedule: dict) -> str:
    """One-line description of a configured schedule, e.g.
    'Weekly on Monday at 07:00 UTC'."""
    hour = schedule.get("hour_utc")
    at = f"at {hour:02d}:00 UTC" if isinstance(hour, int) else ""
    cadence = schedule.get("cadence")
    if cadence == "daily":
        return f"Daily {at}"
    if cadence == "weekly":
        wd = schedule.get("weekday")
        name = WEEKDAY_NAMES[wd] if isinstance(wd, int) and 0 <= wd <= 6 else "?"
        return f"Weekly on {name} {at}"
    if cadence == "monthly":
        return f"Monthly on day {schedule.get('month_day')} {at}"
    return ""


def _clear_report_catalogue_cache():
    """Test hook: no request state survives a fixture boundary."""
    with _report_catalogue_cache_lock:
        _report_catalogue_cache.clear()


def _catalogue_cache_key(jwt: str) -> str:
    """Never retain the bearer assertion itself in process memory."""
    return hashlib.sha256(jwt.encode("utf-8")).hexdigest()


def _validate_report_catalogue(catalogue: list) -> tuple[dict, ...]:
    """Refuse a malformed catalogue rather than render or authorise guesses."""
    required_fields = ("type", "label", "description", "default_frequency", "subject_scope")
    types = set()
    for item in catalogue:
        if not isinstance(item, dict):
            raise upstream.UpstreamError("error", "invalid report catalogue entry")
        if any(
            not isinstance(item.get(field), str) or not item[field]
            for field in required_fields
        ):
            raise upstream.UpstreamError("error", "invalid report catalogue entry")
        if item["type"] in types:
            raise upstream.UpstreamError("error", "duplicate report catalogue type")
        types.add(item["type"])
    return tuple(catalogue)


def _customer_report_catalogue(jwt: str) -> tuple[dict, ...]:
    """Read the caller's bounded, short-lived customer report catalogue.

    A cache hit only skips the duplicate read between rendering a form and
    submitting it. The following platform write still rejects a type revoked
    or no longer entitled after that read, so it cannot grant stale authority.
    """
    key = _catalogue_cache_key(jwt)
    now = time.monotonic()
    with _report_catalogue_cache_lock:
        cached = _report_catalogue_cache.get(key)
        if cached and cached[0] > now:
            _report_catalogue_cache.move_to_end(key)
            return cached[1]
        if cached:
            del _report_catalogue_cache[key]

    catalogue = _validate_report_catalogue(upstream.unwrap_list(
        upstream.get_json("/v1/portal/reports/catalogue", jwt), "reports"))
    with _report_catalogue_cache_lock:
        # Clearing expired entries on each write keeps the cache bounded even
        # when users arrive only once per assertion.
        for stale_key, (expires_at, _) in list(_report_catalogue_cache.items()):
            if expires_at <= now:
                del _report_catalogue_cache[stale_key]
        _report_catalogue_cache[key] = (
            now + REPORT_CATALOGUE_CACHE_TTL_SECONDS, catalogue)
        _report_catalogue_cache.move_to_end(key)
        while len(_report_catalogue_cache) > REPORT_CATALOGUE_CACHE_MAX_ENTRIES:
            _report_catalogue_cache.popitem(last=False)
    return catalogue


def _report_type_is_currently_available(jwt: str, report_type: str) -> bool:
    """Validate a typed write against the exact caller's report catalogue."""
    return any(item["type"] == report_type for item in _customer_report_catalogue(jwt))


# ── PAT-2010 (consuming PAT-2009): New Software and Unapproved & Unreviewed
# Software (drift) reports ─────────────────────────────────────────────────
# contracts/portal-api.md "Software governance reporting (PAT-2009)". Both
# reads share one `coverage` block; _report_coverage_view normalises it once
# rather than twice, and defaults `complete` False on anything malformed so
# an incomplete estate can never silently read as fully assessed (root
# AGENTS.md - absence requires authority).
def _report_coverage_view(raw) -> dict:
    coverage = raw if isinstance(raw, dict) else {}

    def int_or_none(key):
        value = coverage.get(key)
        return value if type(value) is int else None

    return {
        "devices_total": int_or_none("devices_total"),
        "devices_reporting": int_or_none("devices_reporting"),
        "devices_stale": int_or_none("devices_stale"),
        "devices_retired": int_or_none("devices_retired"),
        "devices_without_inventory": int_or_none("devices_without_inventory"),
        "oldest_device_last_seen": coverage.get("oldest_device_last_seen"),
        "stale_after_days": int_or_none("stale_after_days"),
        "complete": coverage.get("complete") is True,
    }


def _new_software_report_row(raw: dict) -> dict | None:
    """One GET /v1/portal/software/new product row: quick approve/unapprove
    reuses _new_software_approval (the Overview New software card's own
    helper, PAT-2093) unchanged - the two endpoints document the identical
    identity fields (name/platform/identifier/team_id/product_key), so this
    is the same write shape, not a lookalike needing its own dispatcher. A
    name_only row (identity_basis == "name_only", product_key null) locks
    the same way _inventory_approval already locks any no-identifier row."""
    name = raw.get("name")
    if not isinstance(name, str) or not name:
        return None
    first_device_raw = raw.get("first_device")
    first_device = None
    if isinstance(first_device_raw, dict):
        hostname = first_device_raw.get("hostname")
        first_device = {
            "hostname": hostname if isinstance(hostname, str) and hostname else None,
            "first_seen_at": first_device_raw.get("first_seen_at"),
            "still_installed": first_device_raw.get("still_installed") is True,
        }
    device_count = raw.get("device_count")
    return {
        **_new_software_approval(raw),
        "name": name,
        "platform": raw.get("platform") or "",
        "identifier": raw.get("identifier"),
        "identity_basis": raw.get("identity_basis"),
        "approval_state": raw.get("approval_state"),
        "approval_state_label": APPROVAL_STATE_LABELS.get(raw.get("approval_state"), ""),
        "device_count": device_count if type(device_count) is int else 0,
        "first_seen_at": raw.get("first_seen_at"),
        "first_device": first_device,
    }


@app.get("/reports/new-software", response_class=HTMLResponse)
def reports_new_software(request: Request):
    """PAT-2010: table of products first seen since the tenant's last
    review, with a quick Approve/Unapprove control per row through the
    existing PAT-2008 write, and the admin-only new-software notification
    toggle (reusing /ai-tooling's own POST route, never a second copy)."""
    try:
        data = upstream.get_json("/v1/portal/software/new", request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if not isinstance(data, dict):
        return _error_page(
            request, upstream.UpstreamError("error", "invalid new-software report"))

    raw_products = data.get("products")
    products = [
        row for row in (
            _new_software_report_row(p) for p in raw_products if isinstance(p, dict)
        ) if row is not None
    ] if isinstance(raw_products, list) else []
    total = data.get("total") if type(data.get("total")) is int else len(products)

    try:
        role = _portal_role(request.state.jwt)
        role_unavailable = False
    except upstream.UpstreamError as exc:
        logger.warning("portal.reports_new_software.role_fail_soft kind=%s", exc.kind)
        role, role_unavailable = "viewer", True
    can_edit = role == "admin"

    notifications, notifications_error = None, False
    try:
        notifications = _ai_notification_view(upstream.get_json(
            "/v1/portal/software-notifications", request.state.jwt))
        if notifications is None:
            raise upstream.UpstreamError("error", "invalid software notification settings")
    except upstream.UpstreamError as exc:
        logger.warning("portal.reports_new_software.notifications_fail_soft kind=%s", exc.kind)
        notifications_error = True

    return_to = _approval_return_to(request.url.path)
    return _render(request, "software_report_new.html", {
        "title": "New software", "nav": "reports",
        "generated_at": data.get("generated_at"),
        "since": data.get("since"), "since_basis": data.get("since_basis"),
        "last_review_at": data.get("last_review_at"),
        "coverage": _report_coverage_view(data.get("coverage")),
        "total": total, "truncated": data.get("truncated") is True,
        "products": products,
        "can_edit": can_edit, "role_unavailable": role_unavailable,
        "csrf_token": _csrf_token(request.state.jwt),
        "return_to": return_to,
        "approval_result": _approval_flash_view(_read_flash(
            request.state.jwt, request.query_params.get(APPROVAL_RESULT_PARAM, ""))),
        "notifications": notifications, "notifications_error": notifications_error,
        "notification_saved": _ai_notification_flash_view(_read_flash(
            request.state.jwt, request.query_params.get(AI_NOTIFICATION_RESULT_PARAM, ""))),
        "csv_url": "/reports/new-software.csv",
    })


@app.get("/reports/new-software.csv")
def reports_new_software_csv(request: Request):
    try:
        resp = upstream.stream(
            "/v1/portal/software/new", request.state.jwt, params={"format": "csv"})
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    return _sam_csv_response(resp, "patched-new-software.csv")


def _drift_product_row(raw: dict) -> dict | None:
    name = raw.get("name")
    if not isinstance(name, str) or not name:
        return None
    device_count, stale_count = raw.get("device_count"), raw.get("stale_device_count")
    return {
        "type": raw.get("type"), "name": name,
        "platform": raw.get("platform") or "",
        "identifier": raw.get("identifier"), "team_id": raw.get("team_id"),
        "product_key": raw.get("product_key"),
        "approval_state": raw.get("approval_state"),
        "approval_state_label": APPROVAL_STATE_LABELS.get(raw.get("approval_state"), ""),
        "device_count": device_count if type(device_count) is int else 0,
        "stale_device_count": stale_count if type(stale_count) is int else 0,
        "observed_since": raw.get("observed_since"),
    }


def _drift_top_device_row(raw: dict) -> dict | None:
    hostname = raw.get("hostname")
    if not isinstance(hostname, str) or not hostname:
        return None
    names = raw.get("unapproved_products")
    count = raw.get("unapproved_product_count")
    return {
        "device_id": raw.get("device_id"), "hostname": hostname,
        "platform": raw.get("platform") or "",
        "unapproved_product_count": count if type(count) is int else 0,
        "unapproved_products": [n for n in names if isinstance(n, str)]
        if isinstance(names, list) else [],
        "last_seen": raw.get("last_seen"), "stale": raw.get("stale") is True,
    }


def _drift_trend_geometry(raw_trend, width: int = 560, height: int = 150, pad: int = 10) -> dict:
    """26-week trend as two inline-SVG polylines (Unapproved, Unreviewed),
    matching the repo's existing single-series trend_geometry (Overview's
    CIS trend) but over two series and tolerant of the contract's `null`
    unrecorded weeks - a gap in history is skipped, never plotted as zero
    (root AGENTS.md: absence requires authority).

    Fewer than two recorded weeks cannot draw a line (one point, or none, is
    not a trend) - `sparse` is True and the template renders a short text
    state instead, using `first_recorded_week` (the real week_start of the
    earliest recorded point, still an ISO date for the `humandate` filter to
    format) rather than a floating single dot or an empty chart."""
    weeks = raw_trend if isinstance(raw_trend, list) else []
    n = len(weeks)
    empty = {
        "unapproved_points": "", "unreviewed_points": "",
        "unapproved_last": None, "unreviewed_last": None, "labels": [],
        "width": width, "height": height, "hi": 0,
        "sparse": True, "recorded_count": 0, "first_recorded_week": None,
    }
    if not n:
        return empty
    pairs = []
    for week in weeks:
        if not isinstance(week, dict):
            pairs.append((None, None))
            continue
        unapproved, unreviewed = week.get("unapproved_products"), week.get("unreviewed_products")
        pairs.append((
            unapproved if type(unapproved) is int else None,
            unreviewed if type(unreviewed) is int else None,
        ))
    recorded_weeks = [
        w.get("week_start") for w, pair in zip(weeks, pairs, strict=True)
        if isinstance(w, dict) and (pair[0] is not None or pair[1] is not None)
    ]
    recorded_count = len(recorded_weeks)
    if recorded_count < 2:
        return {
            **empty, "recorded_count": recorded_count,
            "first_recorded_week": recorded_weeks[0] if recorded_weeks else None,
        }

    numeric = [v for pair in pairs for v in pair if v is not None]
    hi = max(numeric) if numeric else 0
    span = hi or 1

    def coords(index: int) -> tuple[str, tuple[str, str] | None]:
        points = []
        last_xy = None
        for i, pair in enumerate(pairs):
            value = pair[index]
            if value is None:
                continue
            x = pad + (i * (width - 2 * pad) / max(n - 1, 1))
            y = pad + (height - 2 * pad) * (1 - value / span)
            xy = (str(round(x, 1)), str(round(y, 1)))
            points.append(f"{xy[0]},{xy[1]}")
            last_xy = xy
        return " ".join(points), last_xy

    labels = [
        next((w.get("week_start", "") for w in weeks if isinstance(w, dict)), ""),
        next((w.get("week_start", "") for w in reversed(weeks) if isinstance(w, dict)), ""),
    ]
    unapproved_points, unapproved_last = coords(0)
    unreviewed_points, unreviewed_last = coords(1)
    return {
        "unapproved_points": unapproved_points, "unreviewed_points": unreviewed_points,
        "unapproved_last": unapproved_last, "unreviewed_last": unreviewed_last,
        "labels": labels, "hi": hi, "width": width, "height": height,
        "sparse": False, "recorded_count": recorded_count, "first_recorded_week": None,
    }


@app.get("/reports/software-drift", response_class=HTMLResponse)
def reports_software_drift(request: Request):
    """PAT-2010: the current Unapproved/Unreviewed product list, a 26-week
    trend and the devices carrying the most Unapproved software. Read-only -
    the ticket assigns the quick approve/unapprove control to the New
    Software report only; drift stays a governance view."""
    try:
        data = upstream.get_json("/v1/portal/software/drift", request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if not isinstance(data, dict):
        return _error_page(
            request, upstream.UpstreamError("error", "invalid software drift report"))

    counts_raw = data.get("counts") if isinstance(data.get("counts"), dict) else {}
    counts = {
        key: counts_raw.get(key) if type(counts_raw.get(key)) is int else 0
        for key in ("installed_products", "unapproved", "unreviewed", "approved",
                    "ignored", "mandatory", "unapproved_devices")
    }
    raw_products = data.get("products")
    products = [
        row for row in (
            _drift_product_row(p) for p in raw_products if isinstance(p, dict)
        ) if row is not None
    ] if isinstance(raw_products, list) else []
    products_total = (
        data.get("products_total") if type(data.get("products_total")) is int
        else len(products))

    raw_top_devices = data.get("top_devices")
    top_devices = [
        row for row in (
            _drift_top_device_row(d) for d in raw_top_devices if isinstance(d, dict)
        ) if row is not None
    ] if isinstance(raw_top_devices, list) else []

    return _render(request, "software_report_drift.html", {
        "title": "Unapproved and unreviewed software", "nav": "reports",
        "generated_at": data.get("generated_at"),
        "coverage": _report_coverage_view(data.get("coverage")),
        "counts": counts,
        "products": products, "products_total": products_total,
        "products_truncated": data.get("products_truncated") is True,
        "top_devices": top_devices,
        "trend": _drift_trend_geometry(data.get("trend")),
        "csv_url": "/reports/software-drift.csv",
    })


@app.get("/reports/software-drift.csv")
def reports_software_drift_csv(request: Request):
    try:
        resp = upstream.stream(
            "/v1/portal/software/drift", request.state.jwt, params={"format": "csv"})
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    return _sam_csv_response(resp, "patched-software-drift.csv")


@app.get("/reports/software/approved.csv")
def reports_approved_software_csv(request: Request):
    """The approved-list export button (PAT-2010) - no dedicated HTML page,
    just a proxy of the platform's own CSV, matching the ticket's decision
    that this is an export, not a third report page."""
    try:
        resp = upstream.stream(
            "/v1/portal/software/approved", request.state.jwt, params={"format": "csv"})
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    return _sam_csv_response(resp, "patched-approved-software.csv")


@app.get("/reports", response_class=HTMLResponse)
def reports(request: Request, generated: str = "", generate_error: str = "",
            generate_type: str = "",
            schedule_saved: str = "", schedule_error: str = "",
            schedule_type: str = ""):
    try:
        data = upstream.get_json("/v1/portal/reports", request.state.jwt)
        history = upstream.unwrap_list(data, "reports")
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)

    # PAT-1847: the platform owns the customer-safe report catalogue.  Do not
    # keep a second, inevitably stale list here: an unavailable catalogue
    # means no generation or schedule choices are rendered, never guessed.
    catalogue, catalogue_unavailable = [], False
    try:
        catalogue = _customer_report_catalogue(request.state.jwt)
    except upstream.UpstreamError:
        catalogue_unavailable = True

    # Schedules remain secondary to history.  The collection is authoritative
    # for every report type; it also avoids one request per catalogue card.
    schedules, schedules_unavailable = [], False
    try:
        schedules = upstream.unwrap_list(
            upstream.get_json("/v1/portal/reports/schedules", request.state.jwt),
            "schedules")
    except upstream.UpstreamError:
        schedules_unavailable = True

    schedule_by_type = {
        item.get("report_type"): item for item in schedules
        if isinstance(item, dict) and isinstance(item.get("report_type"), str)
    }
    catalogue_by_type = {
        item.get("type"): item for item in catalogue
        if isinstance(item, dict) and isinstance(item.get("type"), str)
    }
    # A forged/stale query parameter must not select a type the freshly read
    # customer catalogue does not contain.  The first catalogue entry is a
    # display default only; its definition still comes entirely upstream.
    selected_type = schedule_type if schedule_type in catalogue_by_type else next(
        iter(catalogue_by_type), ""
    )
    selected_report = catalogue_by_type.get(selected_type)
    generate_error_report = catalogue_by_type.get(generate_type)
    selected_schedule = schedule_by_type.get(selected_type, {"configured": False})

    return _render(request, "reports.html", {
        "title": "Reports", "nav": "reports", "reports": history,
        "generated": generated == "1",
        "generate_error": generate_error[:200],
        "generate_error_report": generate_error_report,
        "catalogue": catalogue,
        "catalogue_unavailable": catalogue_unavailable,
        "schedules_unavailable": schedules_unavailable,
        "selected_type": selected_type,
        "selected_report": selected_report,
        "schedule": selected_schedule,
        "schedule_summary": _schedule_summary(selected_schedule),
        "schedule_saved": schedule_saved == "1",
        "schedule_error": schedule_error[:200],
        "weekday_names": WEEKDAY_NAMES,
    })


@app.post("/reports/schedule")
async def save_schedule(request: Request):
    """Proxy one catalogue-selected schedule to the platform (PAT-703/1847).
    Empty report_type remains the legacy executive-summary endpoint. The JWT
    is forwarded verbatim; the platform validates the shape, derives the
    tenant server-side and owns next_run_at."""
    # The form posts application/x-www-form-urlencoded; _guarded_form parses
    # it directly (no extra form-parsing dependency) after the size, Origin
    # and CSRF checks (PAT-2105).
    fields, refusal = await _guarded_form(request, "reports_schedule")
    if refusal is not None:
        return refusal
    form = {k: v[0] for k, v in fields.items()}
    cadence = str(form.get("cadence", "")).strip()
    report_type = str(form.get("report_type", "")).strip()
    if report_type:
        try:
            available = await run_in_threadpool(
                _report_type_is_currently_available, request.state.jwt, report_type)
        except upstream.UpstreamError:
            return RedirectResponse(
                url=("/reports?schedule_type=" + quote(report_type, safe="") +
                     "&schedule_error=" + quote(
                         "Report choices could not be checked. Refresh and try again.")),
                status_code=303)
        if not available:
            return RedirectResponse(
                url=("/reports?schedule_type=" + quote(report_type, safe="") +
                     "&schedule_error=" + quote(
                         "That report choice is no longer available.")),
                status_code=303)
    payload = {"cadence": cadence, "enabled": form.get("enabled") == "on"}
    try:
        payload["hour_utc"] = int(str(form.get("hour_utc", "")))
        if cadence == "weekly":
            payload["weekday"] = int(str(form.get("weekday", "")))
        elif cadence == "monthly":
            payload["month_day"] = int(str(form.get("month_day", "")))
    except (TypeError, ValueError):
        return RedirectResponse(
            url="/reports?schedule_error=" + quote("Choose a valid schedule."),
            status_code=303)
    try:
        # Empty preserves the legacy executive-summary form contract for old
        # clients.  New catalogue-driven submissions are always type-scoped.
        path = (f"/v1/portal/reports/schedules/{quote(report_type, safe='')}"
                if report_type else "/v1/portal/reports/schedule")
        await run_in_threadpool(upstream.put_json, path, request.state.jwt, payload)
    except upstream.UpstreamError as exc:
        if exc.kind == "invalid":
            return RedirectResponse(
                url=("/reports?schedule_type=" + quote(report_type, safe="") +
                     "&schedule_error=" + quote(exc.detail[:200])),
                status_code=303)
        return _error_page(request, exc)
    url = "/reports?schedule_saved=1"
    if report_type:
        url += "&schedule_type=" + quote(report_type, safe="")
    return RedirectResponse(url=url, status_code=303)


@app.post("/reports/generate")
async def generate_report(request: Request):
    # No report_type is retained for bookmarked/pre-PAT-1847 forms; platform
    # compatibility selects executive-summary.  Every current UI form submits
    # a catalogue-derived type and the platform rejects an altered value.
    fields, refusal = await _guarded_form(request, "reports_generate")
    if refusal is not None:
        return refusal
    form = {k: v[0] for k, v in fields.items()}
    report_type = str(form.get("report_type", "")).strip()
    if report_type:
        try:
            available = await run_in_threadpool(
                _report_type_is_currently_available, request.state.jwt, report_type)
        except upstream.UpstreamError:
            return RedirectResponse(
                url=("/reports?generate_type=" + quote(report_type, safe="") +
                     "&generate_error=" + quote(
                         "Report choices could not be checked. Refresh and try again.")),
                status_code=303)
        if not available:
            return RedirectResponse(
                url=("/reports?generate_type=" + quote(report_type, safe="") +
                     "&generate_error=" + quote(
                         "That report choice is no longer available.")),
                status_code=303)
    try:
        payload = {"report_type": report_type} if report_type else None
        await run_in_threadpool(
            upstream.post_json, "/v1/portal/reports", request.state.jwt, payload)
    except upstream.UpstreamError as exc:
        if exc.kind == "invalid":
            return RedirectResponse(
                url=("/reports?generate_type=" + quote(report_type, safe="") +
                     "&generate_error=" + quote(exc.detail[:200])),
                status_code=303)
        return _error_page(request, exc)
    return RedirectResponse(url="/reports?generated=1", status_code=303)


# PAT-2405: every generated report has a PDF and a CSV. The portal checks the
# requested format against this fixed set before any upstream call and sends
# it as a query parameter, never inside the path. Response headers fall back
# to values from this table only when the platform omits its own.
REPORT_DOWNLOAD_FORMATS = {
    "pdf": ("application/pdf", "pdf"),
    "csv": ("text/csv; charset=utf-8", "csv"),
}


def _is_csv_not_available(body: str) -> bool:
    """True when the platform's 404 body is exactly the csv_not_available
    marker. The body is only inspected, never shown to the customer."""
    try:
        parsed = json.loads(body)
    except (TypeError, ValueError):
        return False
    return isinstance(parsed, dict) and parsed.get("error") == "csv_not_available"


@app.get("/reports/{report_id}/download")
def download_report(request: Request, report_id: str):
    requested = request.query_params.getlist("format")
    if len(requested) > 1 or (
            requested and requested[0] and requested[0] not in REPORT_DOWNLOAD_FORMATS):
        return _render(request, "error.html", {
            "title": "Download not available",
            "message": "That download format is not available. Reports can be "
                       "downloaded as a PDF or a CSV.",
            "back_url": "/reports", "back_label": "Back to Reports",
        }, status_code=400)
    fmt = requested[0] if requested and requested[0] else "pdf"
    default_type, extension = REPORT_DOWNLOAD_FORMATS[fmt]
    try:
        resp = upstream.stream(f"/v1/portal/reports/{quote(report_id, safe='')}",
                               request.state.jwt, params={"format": fmt})
    except upstream.UpstreamError as exc:
        if fmt == "csv" and exc.kind == "not_found" and _is_csv_not_available(exc.body):
            return _render(request, "error.html", {
                "title": "CSV not available for this report",
                "message": "The CSV is not available for this report because it "
                           "was generated before CSV downloads existed. Generate "
                           "the report again to get both a PDF and a CSV.",
                "back_url": "/reports", "back_label": "Back to Reports",
            }, status_code=404)
        return _error_page(request, exc)
    media_type = resp.headers.get("Content-Type", default_type)
    disposition = resp.headers.get(
        "Content-Disposition",
        f'attachment; filename="patched-report-{report_id}.{extension}"',
    )
    headers = {"Content-Disposition": disposition}
    # The 200 status and these headers are already committed by the time a
    # mid-stream upstream failure can happen, so a truncated transfer can
    # only be made detectable at the framing layer, not by changing the
    # response. Forwarding the upstream Content-Length is what does that:
    # with a declared length, the ASGI server aborts the connection if it
    # ends up short, instead of completing it as a normal, if small, 200 -
    # confirmed by hand against a real upstream reset. Without it, a broken
    # upstream connection produces a clean-looking success with a truncated
    # body, because the portal's JWT middleware (a Starlette
    # BaseHTTPMiddleware) swallows an exception raised this deep in a
    # streaming response rather than propagating it to the client.
    content_length = resp.headers.get("Content-Length")
    if content_length is not None and content_length.isdigit():
        headers["Content-Length"] = content_length

    def body():
        try:
            yield from upstream.iter_stream(resp, chunk_size=65536)
        finally:
            resp.close()

    return StreamingResponse(body(), media_type=media_type, headers=headers)


# ── PAT-2147: SAM report - unsupported software ────────────────────────────
# The first pre-staged software asset management report (PAT-2146):
# contracts/portal-api.md "GET /v1/portal/reports/software/unsupported"
# owns the state classification (Supported / Ending within 90 days /
# Unsupported / Unknown - Unknown is never read as Supported), the basis
# block (evidence time, coverage, what was not counted and why) and the
# Cyber Essentials evidence text. The portal renders what the platform
# sends and invents nothing on top of it - the same "absence requires
# authority" and "CVE/usage claims require evidence" rules root AGENTS.md
# sets for findings apply identically to a lifecycle claim here. Every
# portal role can read this report (no admin-only gate, unlike the one
# governance write on /software/approvals).
SAM_UNSUPPORTED_PAGE_SIZE = 50
SAM_DEVICES_PAGE_SIZE = 50
SAM_STATES = ("unsupported", "ending_within_90_days", "unknown", "supported")
SAM_STATE_LABELS = {
    "unsupported": "Unsupported",
    "ending_within_90_days": "Ending within 90 days",
    "unknown": "Unknown",
    "supported": "Supported",
}
SAM_STATE_PILL_CLASS = {
    "unsupported": "pill-bad",
    "ending_within_90_days": "pill-warn",
    "unknown": "pill-muted",
    "supported": "pill-ok",
}
SAM_KIND_LABELS = {"operating_system": "Operating system", "application": "Application"}
SAM_KIND_FILTERS = ("application", "operating_system")
SAM_PLATFORM_FILTERS = ("macos", "windows")
SAM_PRODUCT_KEY_MAX_CHARS = 512
SAM_DEVICE_ID_MAX_CHARS = 128


def _sam_filter_params(state: str, kind: str, platform: str) -> dict:
    """Only ever the platform's own documented filter values - an
    unrecognised query value is dropped rather than forwarded, matching
    every other filtered read on this portal."""
    params: dict[str, str] = {}
    if state in SAM_STATES:
        params["state"] = state
    if kind in SAM_KIND_FILTERS:
        params["kind"] = kind
    if platform in SAM_PLATFORM_FILTERS:
        params["platform"] = platform
    return params


def _sam_report_url(state: str, kind: str, platform: str, page: int = 1) -> str:
    params: dict[str, str] = {}
    if state:
        params["state"] = state
    if kind:
        params["kind"] = kind
    if platform:
        params["platform"] = platform
    if page > 1:
        params["page"] = str(page)
    query = urlencode(params)
    return "/reports/software/unsupported" + (("?" + query) if query else "")


def _sam_devices_url(product_key: str, state: str, kind: str, platform: str, page: int = 1) -> str:
    params: dict[str, str] = {}
    if product_key:
        params["product_key"] = product_key
    if state:
        params["state"] = state
    if kind:
        params["kind"] = kind
    if platform:
        params["platform"] = platform
    if page > 1:
        params["page"] = str(page)
    query = urlencode(params)
    return "/reports/software/unsupported/devices" + (("?" + query) if query else "")


def _sam_basis_view(raw: dict | None) -> dict:
    """The report's basis block exactly as the platform sent it - nothing
    computed or re-derived here (D14: no figure is invented portal-side).
    `complete` defaults to False on anything malformed or missing: absence
    of the flag must never silently read as full coverage."""
    basis = raw if isinstance(raw, dict) else {}
    not_counted_raw = basis.get("not_counted")
    not_counted = [
        {
            "reason": item.get("reason") if isinstance(item.get("reason"), str) else "",
            "description": (item.get("description")
                            if isinstance(item.get("description"), str) else ""),
            "count": item.get("count") if type(item.get("count")) is int else 0,
        }
        for item in not_counted_raw if isinstance(item, dict)
    ] if isinstance(not_counted_raw, list) else []

    def int_or_none(key):
        value = basis.get(key)
        return value if type(value) is int else None

    return {
        "evidence_newest_at": basis.get("evidence_newest_at"),
        "evidence_oldest_at": basis.get("evidence_oldest_at"),
        "devices_total": int_or_none("devices_total"),
        "devices_assessed": int_or_none("devices_assessed"),
        "devices_stale": int_or_none("devices_stale"),
        "devices_retired": int_or_none("devices_retired"),
        "retired_devices_excluded": basis.get("retired_devices_excluded") is True,
        "lifecycle_source": (basis.get("lifecycle_source")
                             if isinstance(basis.get("lifecycle_source"), str) else None),
        "lifecycle_checked_oldest_at": basis.get("lifecycle_checked_oldest_at"),
        "lifecycle_checked_newest_at": basis.get("lifecycle_checked_newest_at"),
        "not_counted": not_counted,
        "complete": basis.get("complete") is True,
        "statement": basis.get("statement") if isinstance(basis.get("statement"), str) else "",
    }


def _sam_summary_view(raw: dict | None) -> dict:
    """Per-state counts, ordered Unsupported, Ending within 90 days,
    Unknown, Supported - Unsupported first, Unknown shown honestly and
    never folded into Supported (this ticket's own instruction). kpi_items
    is pre-built as (label, value, tone) tuples so the template stays a
    plain macro call rather than re-deriving display strings itself."""
    summary = raw if isinstance(raw, dict) else {}
    states_raw = summary.get("states") if isinstance(summary.get("states"), dict) else {}
    states, kpi_items = [], []
    for state in SAM_STATES:
        entry = states_raw.get(state) if isinstance(states_raw.get(state), dict) else {}
        installs = (entry.get("installation_count")
                   if type(entry.get("installation_count")) is int else 0)
        devices = entry.get("device_count") if type(entry.get("device_count")) is int else 0
        tone = ("bad-text" if state == "unsupported"
                else "warn-text" if state == "ending_within_90_days" else "")
        states.append({
            "state": state, "label": SAM_STATE_LABELS[state],
            "pill_class": SAM_STATE_PILL_CLASS[state],
            "installation_count": installs, "device_count": devices,
        })
        kpi_items.append((
            SAM_STATE_LABELS[state],
            f"{installs} install{'' if installs == 1 else 's'} "
            f"({devices} device{'' if devices == 1 else 's'})",
            tone,
        ))
    return {
        "installation_count": (summary.get("installation_count")
                               if type(summary.get("installation_count")) is int else 0),
        "states": states,
        "kpi_items": kpi_items,
    }


def _sam_cyber_essentials_view(raw: dict | None) -> dict | None:
    """Evidence only, never a pass/fail read (contracts/portal-api.md:
    `position: evidence_only`). None when the platform omits the block
    entirely, so the template can degrade honestly rather than render a
    fabricated all-zero card."""
    if not isinstance(raw, dict):
        return None

    def int_or_none(key):
        value = raw.get(key)
        return value if type(value) is int else None

    return {
        "statement": raw.get("statement") if isinstance(raw.get("statement"), str) else "",
        "devices_assessed": int_or_none("devices_assessed"),
        "devices_with_unsupported_software": int_or_none("devices_with_unsupported_software"),
        "devices_with_unknown_support": int_or_none("devices_with_unknown_support"),
        "unsupported_installation_count": int_or_none("unsupported_installation_count"),
        "complete": raw.get("complete") is True,
    }


def _sam_product_row(raw: dict) -> dict:
    kind = raw.get("kind") if raw.get("kind") in SAM_KIND_FILTERS else ""
    platform = raw.get("platform") if isinstance(raw.get("platform"), str) else ""
    state = raw.get("state") if raw.get("state") in SAM_STATES else "unknown"
    source = raw.get("source") if isinstance(raw.get("source"), dict) else {}
    unknown_reason = raw.get("unknown_reason")
    return {
        "product_key": raw.get("product_key") if isinstance(raw.get("product_key"), str) else "",
        "kind": kind, "kind_label": SAM_KIND_LABELS.get(kind, "Software"),
        "name": (raw.get("name") if isinstance(raw.get("name"), str) and raw.get("name")
                else "Unknown product"),
        "platform": platform,
        "version": (raw.get("version") if isinstance(raw.get("version"), str) and raw.get("version")
                   else None),
        "edition": (raw.get("edition") if isinstance(raw.get("edition"), str) and raw.get("edition")
                   else None),
        "state": state, "state_label": SAM_STATE_LABELS[state],
        "pill_class": SAM_STATE_PILL_CLASS[state],
        "eol_date": raw.get("eol_date") if isinstance(raw.get("eol_date"), str) else None,
        "days_to_eol": raw.get("days_to_eol") if type(raw.get("days_to_eol")) is int else None,
        "device_count": raw.get("device_count") if type(raw.get("device_count")) is int else 0,
        "stale_device_count": (raw.get("stale_device_count")
                               if type(raw.get("stale_device_count")) is int else 0),
        "installation_count": (raw.get("installation_count")
                               if type(raw.get("installation_count")) is int else 0),
        "source_name": source.get("name") if isinstance(source.get("name"), str) else None,
        "source_url": source.get("url") if isinstance(source.get("url"), str) else None,
        "last_checked_at": raw.get("last_checked_at"),
        "unknown_reason": unknown_reason if isinstance(unknown_reason, str) else None,
        "unknown_reason_text": (raw.get("unknown_reason_text")
                                if isinstance(raw.get("unknown_reason_text"), str) else None),
        "note": raw.get("note") if isinstance(raw.get("note"), str) and raw.get("note") else None,
    }


def _sam_device_row(raw: dict) -> dict:
    """A product row's fields (contracts/portal-api.md: 'a row is a product
    row's fields without the counts, plus device_id, hostname,
    device_last_seen and device_stale') plus the device identity."""
    row = _sam_product_row(raw)
    row.update({
        "device_id": raw.get("device_id") if isinstance(raw.get("device_id"), str) else "",
        "hostname": (raw.get("hostname")
                    if isinstance(raw.get("hostname"), str) and raw.get("hostname")
                    else "Unknown device"),
        "device_last_seen": raw.get("device_last_seen"),
        "device_stale": raw.get("device_stale") is True,
    })
    return row


@app.get("/reports/software/unsupported", response_class=HTMLResponse)
def sam_unsupported_software(request: Request):
    """PAT-2147: unsupported-software SAM report. Every portal role can
    read it; state/kind/platform filter and page through the platform's own
    params, and the products table never re-sorts what the platform returns
    (same convention /findings already follows - ordering is the
    platform's job)."""
    state_filter = request.query_params.get("state", "")
    if state_filter not in SAM_STATES:
        state_filter = ""
    kind_filter = request.query_params.get("kind", "")
    if kind_filter not in SAM_KIND_FILTERS:
        kind_filter = ""
    platform_filter = request.query_params.get("platform", "")
    if platform_filter not in SAM_PLATFORM_FILTERS:
        platform_filter = ""
    page_num = _parse_page(request.query_params.get("page", "1"))
    offset = (page_num - 1) * SAM_UNSUPPORTED_PAGE_SIZE

    params = _sam_filter_params(state_filter, kind_filter, platform_filter)
    params["limit"] = SAM_UNSUPPORTED_PAGE_SIZE
    params["offset"] = offset
    try:
        data = upstream.get_json(
            "/v1/portal/reports/software/unsupported", request.state.jwt, params=params)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)

    products_raw = upstream.unwrap_list(data, "products")
    products = [_sam_product_row(p) for p in products_raw if isinstance(p, dict)]
    for p in products:
        p["devices_url"] = _sam_devices_url(
            p["product_key"], state_filter, kind_filter, platform_filter)

    total = data.get("total", len(products)) if isinstance(data, dict) else len(products)
    limit = (data.get("limit", SAM_UNSUPPORTED_PAGE_SIZE)
            if isinstance(data, dict) else SAM_UNSUPPORTED_PAGE_SIZE)
    total_pages = max(1, -(-total // limit)) if limit else 1

    # Same PAT-1201 shape /findings and /software/alerts already follow: an
    # offset past the last row comes back with products=[] and an
    # untrustworthy total, trustworthy as "no rows" only on the first page.
    if not products and offset > 0:
        return RedirectResponse(
            url=_sam_report_url(state_filter, kind_filter, platform_filter), status_code=302)

    summary = _sam_summary_view(data.get("summary") if isinstance(data, dict) else None)
    basis = _sam_basis_view(data.get("basis") if isinstance(data, dict) else None)
    cyber_essentials = _sam_cyber_essentials_view(
        data.get("cyber_essentials") if isinstance(data, dict) else None)

    csv_params = _sam_filter_params(state_filter, kind_filter, platform_filter)
    csv_url = ("/reports/software/unsupported.csv"
              + (("?" + urlencode(csv_params)) if csv_params else ""))

    filter_urls = {"": _sam_report_url("", kind_filter, platform_filter)}
    filter_urls.update({
        s: _sam_report_url(s, kind_filter, platform_filter) for s in SAM_STATES
    })

    return _render(request, "software_report_unsupported.html", {
        "title": "Unsupported software", "nav": "reports",
        "summary": summary, "basis": basis, "cyber_essentials": cyber_essentials,
        "products": products, "total": total,
        "page": page_num, "total_pages": total_pages,
        "state_filter": state_filter, "kind_filter": kind_filter,
        "platform_filter": platform_filter,
        "filter_urls": filter_urls,
        "prev_url": _sam_report_url(state_filter, kind_filter, platform_filter, page_num - 1),
        "next_url": _sam_report_url(state_filter, kind_filter, platform_filter, page_num + 1),
        "csv_url": csv_url,
        "pdf_url": _pdf_twin(csv_url),
    })


def _sam_csv_response(
        resp, default_filename: str = "patched-unsupported-software.csv") -> StreamingResponse:
    """Shared streaming shape for every SAM CSV proxy (PAT-2147/2148/2150) -
    identical to download_report's own approach: forward Content-Length so a
    truncated upstream transfer aborts the connection at the framing layer
    instead of completing as a short, misleadingly-successful 200 (see
    download_report's own comment for the full reasoning). `default_filename`
    only applies when the platform response omits its own
    Content-Disposition - every stub and real response is expected to send
    one, so this is a fallback, not the normal path."""
    headers = {
        "Content-Disposition": resp.headers.get(
            "Content-Disposition", f'attachment; filename="{default_filename}"'),
    }
    content_length = resp.headers.get("Content-Length")
    if content_length is not None and content_length.isdigit():
        headers["Content-Length"] = content_length
    export_rows = resp.headers.get("X-Patched-Export-Rows")
    if export_rows is not None:
        headers["X-Patched-Export-Rows"] = export_rows

    def body():
        try:
            yield from upstream.iter_stream(resp, chunk_size=65536)
        finally:
            resp.close()

    return StreamingResponse(
        body(), media_type=resp.headers.get("Content-Type", "text/csv"), headers=headers)


SAM_FILTER_SPECS = {
    "state": ("State", SAM_STATE_LABELS), "kind": ("Kind", SAM_KIND_LABELS),
    "platform": ("Platform", PLATFORM_FILTER_LABELS),
}


def _sam_unsupported_csv_spec(request: Request) -> _ProxiedCsv:
    params = _sam_filter_params(
        request.query_params.get("state", ""), request.query_params.get("kind", ""),
        request.query_params.get("platform", ""))
    return _ProxiedCsv(
        "software-unsupported", "/v1/portal/reports/software/unsupported", params,
        "patched-unsupported-software.csv", _filter_pairs(params, SAM_FILTER_SPECS))


@app.get("/reports/software/unsupported.csv")
def sam_unsupported_software_csv(request: Request):
    """Proxies the platform's own CSV (contracts/portal-api.md: every
    matching installation row, unpaged, spreadsheet-formula-injection-safe
    cells already applied upstream) rather than re-serialising it
    portal-side - the report's own basis and state logic lives in exactly
    one place this way."""
    return _proxied_csv_response(request, _sam_unsupported_csv_spec(request))


@app.get("/reports/software/unsupported.pdf")
def sam_unsupported_software_pdf(request: Request):
    """PAT-2405: the same rows as the CSV above, as a PDF."""
    return _proxied_csv_pdf_response(request, _sam_unsupported_csv_spec(request))


@app.get("/reports/software/unsupported/devices", response_class=HTMLResponse)
def sam_unsupported_software_devices(request: Request):
    """The per-device drill-down (contracts/portal-api.md 'GET /v1/portal/
    reports/software/unsupported/devices'). Reached filtered to one product
    by clicking through a products-table row, or unfiltered directly."""
    product_key = request.query_params.get("product_key", "")[:SAM_PRODUCT_KEY_MAX_CHARS]
    device_id = request.query_params.get("device_id", "")[:SAM_DEVICE_ID_MAX_CHARS]
    state_filter = request.query_params.get("state", "")
    if state_filter not in SAM_STATES:
        state_filter = ""
    kind_filter = request.query_params.get("kind", "")
    if kind_filter not in SAM_KIND_FILTERS:
        kind_filter = ""
    platform_filter = request.query_params.get("platform", "")
    if platform_filter not in SAM_PLATFORM_FILTERS:
        platform_filter = ""
    page_num = _parse_page(request.query_params.get("page", "1"))
    offset = (page_num - 1) * SAM_DEVICES_PAGE_SIZE

    params = _sam_filter_params(state_filter, kind_filter, platform_filter)
    if product_key:
        params["product_key"] = product_key
    if device_id:
        params["device_id"] = device_id
    params["limit"] = SAM_DEVICES_PAGE_SIZE
    params["offset"] = offset
    try:
        data = upstream.get_json(
            "/v1/portal/reports/software/unsupported/devices", request.state.jwt, params=params)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)

    rows_raw = upstream.unwrap_list(data, "rows")
    rows = [_sam_device_row(r) for r in rows_raw if isinstance(r, dict)]

    total = data.get("total", len(rows)) if isinstance(data, dict) else len(rows)
    limit = (data.get("limit", SAM_DEVICES_PAGE_SIZE)
            if isinstance(data, dict) else SAM_DEVICES_PAGE_SIZE)
    total_pages = max(1, -(-total // limit)) if limit else 1

    if not rows and offset > 0:
        return RedirectResponse(
            url=_sam_devices_url(product_key, state_filter, kind_filter, platform_filter),
            status_code=302)

    basis = _sam_basis_view(data.get("basis") if isinstance(data, dict) else None)

    csv_params = _sam_filter_params(state_filter, kind_filter, platform_filter)
    if product_key:
        csv_params["product_key"] = product_key
    if device_id:
        csv_params["device_id"] = device_id
    csv_url = "/reports/software/unsupported/devices.csv?" + urlencode(csv_params)

    return _render(request, "software_report_unsupported_devices.html", {
        "title": "Unsupported software - devices", "nav": "reports",
        "rows": rows, "basis": basis, "total": total,
        "page": page_num, "total_pages": total_pages,
        "product_key": product_key, "device_id": device_id,
        "state_filter": state_filter, "kind_filter": kind_filter,
        "platform_filter": platform_filter,
        "prev_url": _sam_devices_url(
            product_key, state_filter, kind_filter, platform_filter, page_num - 1),
        "next_url": _sam_devices_url(
            product_key, state_filter, kind_filter, platform_filter, page_num + 1),
        "csv_url": csv_url,
        "pdf_url": _pdf_twin(csv_url),
        "report_url": _sam_report_url(state_filter, kind_filter, platform_filter),
    })


def _sam_unsupported_devices_csv_spec(request: Request) -> _ProxiedCsv:
    product_key = request.query_params.get("product_key", "")[:SAM_PRODUCT_KEY_MAX_CHARS]
    device_id = request.query_params.get("device_id", "")[:SAM_DEVICE_ID_MAX_CHARS]
    params = _sam_filter_params(
        request.query_params.get("state", ""), request.query_params.get("kind", ""),
        request.query_params.get("platform", ""))
    if product_key:
        params["product_key"] = product_key
    if device_id:
        params["device_id"] = device_id
    return _ProxiedCsv(
        "software-unsupported-devices", "/v1/portal/reports/software/unsupported/devices",
        params, "patched-unsupported-software.csv",
        _filter_pairs(params, {**SAM_FILTER_SPECS, "product_key": ("Product", None),
                               "device_id": ("Device", None)}))


@app.get("/reports/software/unsupported/devices.csv")
def sam_unsupported_software_devices_csv(request: Request):
    return _proxied_csv_response(request, _sam_unsupported_devices_csv_spec(request))


@app.get("/reports/software/unsupported/devices.pdf")
def sam_unsupported_software_devices_pdf(request: Request):
    """PAT-2405: the same rows as the devices CSV above, as a PDF."""
    return _proxied_csv_pdf_response(request, _sam_unsupported_devices_csv_spec(request))


# ── PAT-2148: SAM report - remote access tools ──────────────────────────────
# contracts/portal-api.md "GET /v1/portal/reports/software/remote-access"
# (+ "/devices"). Detection is internal/categorytag's live match rules, never
# a materialised-tag read. category distinguishes an MSP's own remote
# monitoring and management tooling (rmm_agent) from every other remote
# access tool (remote_access) so RMM is never presented as an unsanctioned
# finding - the portal renders RMM as its own section, not folded into the
# findings summary. approval_state is the tenant's existing software-approval
# decision (PAT-2007/PAT-2058), never a parallel remote-access allow list;
# the platform already sorts unsanctioned rows first, so this page never
# re-sorts what it is sent (same "absence requires authority" /
# "the platform's job to sort" conventions PAT-2147 above already follows).
REMOTE_ACCESS_PAGE_SIZE = 50
REMOTE_ACCESS_DEVICES_PAGE_SIZE = 50
REMOTE_ACCESS_CATEGORIES = ("remote_access", "rmm_agent")
REMOTE_ACCESS_CATEGORY_LABELS = {"remote_access": "Remote access", "rmm_agent": "RMM agent"}
REMOTE_ACCESS_KIND_FILTERS = ("app", "browser_extension", "package")
REMOTE_ACCESS_KIND_LABELS = {
    "app": "App", "browser_extension": "Browser extension", "package": "Package",
}
REMOTE_ACCESS_PLATFORM_FILTERS = ("macos", "windows")
REMOTE_ACCESS_STATES = ("approved", "unapproved", "unreviewed", "ignored")
# Unsanctioned-first order, matching the platform's own row ordering
# (contracts/portal-api.md: "unapproved, then unreviewed, then ignored sort
# ahead of approved") - used only for the summary card order, never to
# re-sort the products/devices tables themselves.
REMOTE_ACCESS_STATE_ORDER = ("unapproved", "unreviewed", "ignored", "approved")
REMOTE_ACCESS_PILL_CLASS = {
    "unapproved": "pill-bad", "unreviewed": "pill-warn",
    "ignored": "pill-muted", "approved": "pill-ok",
}
REMOTE_ACCESS_PRODUCT_KEY_MAX_CHARS = 512
REMOTE_ACCESS_DEVICE_ID_MAX_CHARS = 128


def _remote_access_filter_params(category: str, kind: str, state: str, platform: str) -> dict:
    """Only ever the platform's own documented filter values - an
    unrecognised query value is dropped rather than forwarded (same
    convention _sam_filter_params already follows above)."""
    params: dict[str, str] = {}
    if category in REMOTE_ACCESS_CATEGORIES:
        params["category"] = category
    if kind in REMOTE_ACCESS_KIND_FILTERS:
        params["kind"] = kind
    if state in REMOTE_ACCESS_STATES:
        params["state"] = state
    if platform in REMOTE_ACCESS_PLATFORM_FILTERS:
        params["platform"] = platform
    return params


def _remote_access_report_url(category: str, kind: str, state: str, platform: str,
                               page: int = 1) -> str:
    params: dict[str, str] = {}
    if category:
        params["category"] = category
    if kind:
        params["kind"] = kind
    if state:
        params["state"] = state
    if platform:
        params["platform"] = platform
    if page > 1:
        params["page"] = str(page)
    query = urlencode(params)
    return "/reports/software/remote-access" + (("?" + query) if query else "")


def _remote_access_devices_url(product_key: str, category: str, kind: str, state: str,
                                platform: str, page: int = 1) -> str:
    params: dict[str, str] = {}
    if product_key:
        params["product_key"] = product_key
    if category:
        params["category"] = category
    if kind:
        params["kind"] = kind
    if state:
        params["state"] = state
    if platform:
        params["platform"] = platform
    if page > 1:
        params["page"] = str(page)
    query = urlencode(params)
    return "/reports/software/remote-access/devices" + (("?" + query) if query else "")


def _report_basis_view(raw: dict | None) -> dict:
    """The evidence-basis block exactly as the platform sent it (shared by
    PAT-2148 and PAT-2150 - the same "no figure invented portal-side" rule
    _sam_basis_view enforces above, minus PAT-2147's lifecycle-only fields
    neither of these two contracts carry). `complete` defaults to False on
    anything malformed or missing: absence of the flag must never silently
    read as full coverage."""
    basis = raw if isinstance(raw, dict) else {}
    not_counted_raw = basis.get("not_counted")
    not_counted = [
        {
            "reason": item.get("reason") if isinstance(item.get("reason"), str) else "",
            "description": (item.get("description")
                            if isinstance(item.get("description"), str) else ""),
            "count": item.get("count") if type(item.get("count")) is int else 0,
        }
        for item in not_counted_raw if isinstance(item, dict)
    ] if isinstance(not_counted_raw, list) else []

    def int_or_none(key):
        value = basis.get(key)
        return value if type(value) is int else None

    return {
        "evidence_newest_at": basis.get("evidence_newest_at"),
        "evidence_oldest_at": basis.get("evidence_oldest_at"),
        "devices_total": int_or_none("devices_total"),
        "devices_assessed": int_or_none("devices_assessed"),
        "devices_stale": int_or_none("devices_stale"),
        "devices_retired": int_or_none("devices_retired"),
        "retired_devices_excluded": basis.get("retired_devices_excluded") is True,
        "not_counted": not_counted,
        "complete": basis.get("complete") is True,
        "statement": basis.get("statement") if isinstance(basis.get("statement"), str) else "",
    }


def _remote_access_state_block(raw: dict | None) -> dict:
    entry = raw if isinstance(raw, dict) else {}
    return {
        "tool_count": entry.get("tool_count") if type(entry.get("tool_count")) is int else 0,
        "installation_count": (entry.get("installation_count")
                               if type(entry.get("installation_count")) is int else 0),
        "device_count": entry.get("device_count") if type(entry.get("device_count")) is int else 0,
    }


def _remote_access_summary_view(raw: dict | None) -> dict:
    """Remote-access approval states drive the findings-style KPI row
    (unsanctioned states first); RMM agents are a wholly separate block so
    an MSP's own tooling is never presented as a finding (this ticket's own
    instruction, and the contract's stated reason for the separate
    category)."""
    summary = raw if isinstance(raw, dict) else {}
    remote_raw = (summary.get("remote_access")
                 if isinstance(summary.get("remote_access"), dict) else {})
    rmm_raw = summary.get("rmm_agents") if isinstance(summary.get("rmm_agents"), dict) else {}

    def build(states_raw):
        states, kpi_items = [], []
        for state in REMOTE_ACCESS_STATE_ORDER:
            block = _remote_access_state_block(states_raw.get(state))
            tone = "bad-text" if state in ("unapproved", "unreviewed") else ""
            states.append({
                "state": state, "label": APPROVAL_STATE_LABELS.get(state, state),
                "pill_class": REMOTE_ACCESS_PILL_CLASS[state], **block,
            })
            kpi_items.append((
                APPROVAL_STATE_LABELS.get(state, state),
                f"{block['tool_count']} tool{'' if block['tool_count'] == 1 else 's'} "
                f"({block['device_count']} device{'' if block['device_count'] == 1 else 's'})",
                tone,
            ))
        return states, kpi_items

    remote_states, remote_kpi_items = build(remote_raw)
    rmm_states, rmm_kpi_items = build(rmm_raw)

    def int_or_zero(key):
        value = summary.get(key)
        return value if type(value) is int else 0

    return {
        "remote_access": remote_states, "kpi_items": remote_kpi_items,
        "rmm": rmm_states, "rmm_kpi_items": rmm_kpi_items,
        "remote_access_tool_count": int_or_zero("remote_access_tool_count"),
        "remote_access_installation_count": int_or_zero("remote_access_installation_count"),
        "rmm_agent_tool_count": int_or_zero("rmm_agent_tool_count"),
        "rmm_agent_installation_count": int_or_zero("rmm_agent_installation_count"),
    }


def _remote_access_product_row(raw: dict) -> dict:
    category = raw.get("category") if raw.get("category") in REMOTE_ACCESS_CATEGORIES else ""
    kind = raw.get("kind") if raw.get("kind") in REMOTE_ACCESS_KIND_FILTERS else ""
    state = raw.get("approval_state") if raw.get("approval_state") in REMOTE_ACCESS_STATES \
        else "unreviewed"
    platform = raw.get("platform") if isinstance(raw.get("platform"), str) else ""
    users_raw = raw.get("users")
    users = [u for u in users_raw if isinstance(u, str)] if isinstance(users_raw, list) else []
    return {
        "product_key": raw.get("product_key") if isinstance(raw.get("product_key"), str) else "",
        "category": category, "category_label": REMOTE_ACCESS_CATEGORY_LABELS.get(category, ""),
        "kind": kind, "kind_label": REMOTE_ACCESS_KIND_LABELS.get(kind, "Software"),
        "name": (raw.get("name") if isinstance(raw.get("name"), str) and raw.get("name")
                else "Unknown product"),
        "platform": platform,
        "identifier": raw.get("identifier") if isinstance(raw.get("identifier"), str) else None,
        "approval_state": state, "approval_state_label": APPROVAL_STATE_LABELS.get(state, state),
        "pill_class": REMOTE_ACCESS_PILL_CLASS.get(state, "pill-muted"),
        "device_count": raw.get("device_count") if type(raw.get("device_count")) is int else 0,
        "stale_device_count": (raw.get("stale_device_count")
                               if type(raw.get("stale_device_count")) is int else 0),
        "installation_count": (raw.get("installation_count")
                               if type(raw.get("installation_count")) is int else 0),
        "users": users,
        "machine_wide_count": (raw.get("machine_wide_count")
                               if type(raw.get("machine_wide_count")) is int else 0),
        "last_seen": raw.get("last_seen"),
    }


def _remote_access_device_row(raw: dict) -> dict:
    """A product row's fields (contracts/portal-api.md: 'a row is a product
    row's fields without the counts, plus device_id, hostname,
    device_last_seen, device_stale, user and machine_wide') plus the
    device identity."""
    row = _remote_access_product_row(raw)
    row.update({
        "device_id": raw.get("device_id") if isinstance(raw.get("device_id"), str) else "",
        "hostname": (raw.get("hostname")
                    if isinstance(raw.get("hostname"), str) and raw.get("hostname")
                    else "Unknown device"),
        "device_last_seen": raw.get("device_last_seen"),
        "device_stale": raw.get("device_stale") is True,
        "user": raw.get("user") if isinstance(raw.get("user"), str) and raw.get("user") else None,
        "machine_wide": raw.get("machine_wide") is True,
    })
    return row


@app.get("/reports/software/remote-access", response_class=HTMLResponse)
def sam_remote_access(request: Request):
    """PAT-2148: remote-access-tools SAM report. Every portal role can read
    it; category/kind/state/platform filter and page through the platform's
    own params, and the products table never re-sorts what the platform
    returns (same convention PAT-2147 follows above)."""
    category_filter = request.query_params.get("category", "")
    if category_filter not in REMOTE_ACCESS_CATEGORIES:
        category_filter = ""
    kind_filter = request.query_params.get("kind", "")
    if kind_filter not in REMOTE_ACCESS_KIND_FILTERS:
        kind_filter = ""
    state_filter = request.query_params.get("state", "")
    if state_filter not in REMOTE_ACCESS_STATES:
        state_filter = ""
    platform_filter = request.query_params.get("platform", "")
    if platform_filter not in REMOTE_ACCESS_PLATFORM_FILTERS:
        platform_filter = ""
    page_num = _parse_page(request.query_params.get("page", "1"))
    offset = (page_num - 1) * REMOTE_ACCESS_PAGE_SIZE

    params = _remote_access_filter_params(
        category_filter, kind_filter, state_filter, platform_filter)
    params["limit"] = REMOTE_ACCESS_PAGE_SIZE
    params["offset"] = offset
    try:
        data = upstream.get_json(
            "/v1/portal/reports/software/remote-access", request.state.jwt, params=params)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)

    products_raw = upstream.unwrap_list(data, "products")
    all_products = [_remote_access_product_row(p) for p in products_raw if isinstance(p, dict)]
    for p in all_products:
        p["devices_url"] = _remote_access_devices_url(
            p["product_key"], category_filter, kind_filter, state_filter, platform_filter)

    total = data.get("total", len(all_products)) if isinstance(data, dict) else len(all_products)
    limit = (data.get("limit", REMOTE_ACCESS_PAGE_SIZE)
            if isinstance(data, dict) else REMOTE_ACCESS_PAGE_SIZE)
    total_pages = max(1, -(-total // limit)) if limit else 1

    # Same PAT-1201 shape /findings, /software/alerts and PAT-2147 above
    # already follow: an offset past the last row comes back with
    # products=[] and an untrustworthy total, trustworthy as "no rows" only
    # on the first page.
    if not all_products and offset > 0:
        return RedirectResponse(
            url=_remote_access_report_url(
                category_filter, kind_filter, state_filter, platform_filter),
            status_code=302)

    # RMM agents are an MSP's own tooling, never a finding (this ticket's own
    # instruction): split them into their own section rather than blending
    # them into the findings table below, even though the platform returns
    # both categories from the one unfiltered read.
    products = [p for p in all_products if p["category"] != "rmm_agent"]
    rmm_products = [p for p in all_products if p["category"] == "rmm_agent"]

    summary = _remote_access_summary_view(data.get("summary") if isinstance(data, dict) else None)
    basis = _report_basis_view(data.get("basis") if isinstance(data, dict) else None)

    csv_params = _remote_access_filter_params(
        category_filter, kind_filter, state_filter, platform_filter)
    csv_url = ("/reports/software/remote-access.csv"
              + (("?" + urlencode(csv_params)) if csv_params else ""))

    return _render(request, "software_report_remote_access.html", {
        "title": "Remote access tools", "nav": "reports",
        "summary": summary, "basis": basis,
        "products": products, "rmm_products": rmm_products, "total": total,
        "page": page_num, "total_pages": total_pages,
        "category_filter": category_filter, "kind_filter": kind_filter,
        "state_filter": state_filter, "platform_filter": platform_filter,
        "report_url": _remote_access_report_url(
            category_filter, kind_filter, state_filter, platform_filter),
        "prev_url": _remote_access_report_url(
            category_filter, kind_filter, state_filter, platform_filter, page_num - 1),
        "next_url": _remote_access_report_url(
            category_filter, kind_filter, state_filter, platform_filter, page_num + 1),
        "csv_url": csv_url,
        "pdf_url": _pdf_twin(csv_url),
    })


REMOTE_ACCESS_FILTER_SPECS = {
    "category": ("Category", REMOTE_ACCESS_CATEGORY_LABELS),
    "kind": ("Kind", REMOTE_ACCESS_KIND_LABELS),
    "state": ("Approval state", {s: s.capitalize() for s in REMOTE_ACCESS_STATES}),
    "platform": ("Platform", PLATFORM_FILTER_LABELS),
}


def _remote_access_csv_spec(request: Request) -> _ProxiedCsv:
    params = _remote_access_filter_params(
        request.query_params.get("category", ""), request.query_params.get("kind", ""),
        request.query_params.get("state", ""), request.query_params.get("platform", ""))
    return _ProxiedCsv(
        "software-remote-access", "/v1/portal/reports/software/remote-access", params,
        "patched-remote-access.csv", _filter_pairs(params, REMOTE_ACCESS_FILTER_SPECS))


@app.get("/reports/software/remote-access.csv")
def sam_remote_access_csv(request: Request):
    """Proxies the platform's own CSV rather than re-serialising it
    portal-side - the report's own approval and category logic lives in
    exactly one place this way (same convention as PAT-2147's CSV proxy)."""
    return _proxied_csv_response(request, _remote_access_csv_spec(request))


@app.get("/reports/software/remote-access.pdf")
def sam_remote_access_pdf(request: Request):
    """PAT-2405: the same rows as the CSV above, as a PDF."""
    return _proxied_csv_pdf_response(request, _remote_access_csv_spec(request))


@app.get("/reports/software/remote-access/devices", response_class=HTMLResponse)
def sam_remote_access_devices(request: Request):
    """The per-installation (and per-user) drill-down (contracts/portal-api.md
    'GET /v1/portal/reports/software/remote-access/devices'). Reached
    filtered to one product by clicking through a products-table row, or
    unfiltered directly."""
    product_key = request.query_params.get(
        "product_key", "")[:REMOTE_ACCESS_PRODUCT_KEY_MAX_CHARS]
    device_id = request.query_params.get("device_id", "")[:REMOTE_ACCESS_DEVICE_ID_MAX_CHARS]
    category_filter = request.query_params.get("category", "")
    if category_filter not in REMOTE_ACCESS_CATEGORIES:
        category_filter = ""
    kind_filter = request.query_params.get("kind", "")
    if kind_filter not in REMOTE_ACCESS_KIND_FILTERS:
        kind_filter = ""
    state_filter = request.query_params.get("state", "")
    if state_filter not in REMOTE_ACCESS_STATES:
        state_filter = ""
    platform_filter = request.query_params.get("platform", "")
    if platform_filter not in REMOTE_ACCESS_PLATFORM_FILTERS:
        platform_filter = ""
    page_num = _parse_page(request.query_params.get("page", "1"))
    offset = (page_num - 1) * REMOTE_ACCESS_DEVICES_PAGE_SIZE

    params = _remote_access_filter_params(
        category_filter, kind_filter, state_filter, platform_filter)
    if product_key:
        params["product_key"] = product_key
    if device_id:
        params["device_id"] = device_id
    params["limit"] = REMOTE_ACCESS_DEVICES_PAGE_SIZE
    params["offset"] = offset
    try:
        data = upstream.get_json(
            "/v1/portal/reports/software/remote-access/devices", request.state.jwt, params=params)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)

    rows_raw = upstream.unwrap_list(data, "rows")
    rows = [_remote_access_device_row(r) for r in rows_raw if isinstance(r, dict)]

    total = data.get("total", len(rows)) if isinstance(data, dict) else len(rows)
    limit = (data.get("limit", REMOTE_ACCESS_DEVICES_PAGE_SIZE)
            if isinstance(data, dict) else REMOTE_ACCESS_DEVICES_PAGE_SIZE)
    total_pages = max(1, -(-total // limit)) if limit else 1

    if not rows and offset > 0:
        return RedirectResponse(
            url=_remote_access_devices_url(
                product_key, category_filter, kind_filter, state_filter, platform_filter),
            status_code=302)

    basis = _report_basis_view(data.get("basis") if isinstance(data, dict) else None)

    csv_params = _remote_access_filter_params(
        category_filter, kind_filter, state_filter, platform_filter)
    if product_key:
        csv_params["product_key"] = product_key
    if device_id:
        csv_params["device_id"] = device_id
    csv_url = "/reports/software/remote-access/devices.csv?" + urlencode(csv_params)

    return _render(request, "software_report_remote_access_devices.html", {
        "title": "Remote access tools - devices", "nav": "reports",
        "rows": rows, "basis": basis, "total": total,
        "page": page_num, "total_pages": total_pages,
        "product_key": product_key, "device_id": device_id,
        "category_filter": category_filter, "kind_filter": kind_filter,
        "state_filter": state_filter, "platform_filter": platform_filter,
        "prev_url": _remote_access_devices_url(
            product_key, category_filter, kind_filter, state_filter, platform_filter, page_num - 1),
        "next_url": _remote_access_devices_url(
            product_key, category_filter, kind_filter, state_filter, platform_filter, page_num + 1),
        "csv_url": csv_url,
        "pdf_url": _pdf_twin(csv_url),
        "report_url": _remote_access_report_url(
            category_filter, kind_filter, state_filter, platform_filter),
    })


def _remote_access_devices_csv_spec(request: Request) -> _ProxiedCsv:
    product_key = request.query_params.get(
        "product_key", "")[:REMOTE_ACCESS_PRODUCT_KEY_MAX_CHARS]
    device_id = request.query_params.get("device_id", "")[:REMOTE_ACCESS_DEVICE_ID_MAX_CHARS]
    params = _remote_access_filter_params(
        request.query_params.get("category", ""), request.query_params.get("kind", ""),
        request.query_params.get("state", ""), request.query_params.get("platform", ""))
    if product_key:
        params["product_key"] = product_key
    if device_id:
        params["device_id"] = device_id
    return _ProxiedCsv(
        "software-remote-access-devices",
        "/v1/portal/reports/software/remote-access/devices", params,
        "patched-remote-access-devices.csv",
        _filter_pairs(params, {**REMOTE_ACCESS_FILTER_SPECS, "product_key": ("Product", None),
                               "device_id": ("Device", None)}))


@app.get("/reports/software/remote-access/devices.csv")
def sam_remote_access_devices_csv(request: Request):
    return _proxied_csv_response(request, _remote_access_devices_csv_spec(request))


@app.get("/reports/software/remote-access/devices.pdf")
def sam_remote_access_devices_pdf(request: Request):
    """PAT-2405: the same rows as the devices CSV above, as a PDF."""
    return _proxied_csv_pdf_response(request, _remote_access_devices_csv_spec(request))


# ── PAT-2150: SAM report - version sprawl ───────────────────────────────────
# contracts/portal-api.md "GET /v1/portal/reports/software/version-sprawl".
# Scope is installed applications only - operating systems are not a
# "product" for sprawl purposes. The platform decides distinct-version
# counting, the major-version comparison and the latest-released source
# precedence; the portal renders exactly what it is sent and invents no
# figure of its own (same D14 rule PAT-2147/PAT-2148 above already follow).
VERSION_SPRAWL_PAGE_SIZE = 50
VERSION_SPRAWL_PLATFORM_FILTERS = ("macos", "windows")


def _version_sprawl_filter_params(platform: str) -> dict:
    params: dict[str, str] = {}
    if platform in VERSION_SPRAWL_PLATFORM_FILTERS:
        params["platform"] = platform
    return params


def _version_sprawl_report_url(platform: str, page: int = 1) -> str:
    params: dict[str, str] = {}
    if platform:
        params["platform"] = platform
    if page > 1:
        params["page"] = str(page)
    query = urlencode(params)
    return "/reports/software/version-sprawl" + (("?" + query) if query else "")


def _version_sprawl_version_row(raw: dict) -> dict:
    return {
        "version": raw.get("version") if isinstance(raw.get("version"), str) else "",
        "device_count": raw.get("device_count") if type(raw.get("device_count")) is int else 0,
        "stale_device_count": (raw.get("stale_device_count")
                               if type(raw.get("stale_device_count")) is int else 0),
    }


def _version_sprawl_source_view(source) -> dict:
    """PAT-2509: what the Latest released cell may show of a product's source.

    The platform sends `name` (a machine name such as "curated_catalogue"),
    `label` (the plain wording), `url` and `checked_at`. Only the label, an
    https link and the check date are returned, so the machine name cannot
    reach a template. A source with no usable label (a platform that predates
    the field) yields nothing at all: the cell then shows the version alone,
    never a link or a date with nothing to attach them to."""
    empty = {"label": None, "url": None, "checked_at": None}
    if not isinstance(source, dict):
        return empty
    label = source.get("label")
    label = label.strip() if isinstance(label, str) else ""
    if not label:
        return empty
    url = source.get("url")
    return {
        "label": label,
        "url": url if isinstance(url, str) and url.startswith("https://") else None,
        "checked_at": _parse_utc(source.get("checked_at")),
    }


def _version_sprawl_product_row(raw: dict) -> dict:
    source = _version_sprawl_source_view(raw.get("latest_released_source"))
    versions_raw = raw.get("versions")
    versions = [_version_sprawl_version_row(v) for v in versions_raw
                if isinstance(v, dict)] if isinstance(versions_raw, list) else []

    def int_or_none(key):
        value = raw.get(key)
        return value if type(value) is int else None

    return {
        "product_key": raw.get("product_key") if isinstance(raw.get("product_key"), str) else "",
        "name": (raw.get("name") if isinstance(raw.get("name"), str) and raw.get("name")
                else "Unknown product"),
        "platform": raw.get("platform") if isinstance(raw.get("platform"), str) else "",
        "distinct_versions": int_or_none("distinct_versions") or 0,
        "oldest_version": (raw.get("oldest_version")
                           if isinstance(raw.get("oldest_version"), str) else None),
        "newest_version": (raw.get("newest_version")
                           if isinstance(raw.get("newest_version"), str) else None),
        "latest_released": (raw.get("latest_released")
                            if isinstance(raw.get("latest_released"), str) else None),
        "latest_released_source_label": source["label"],
        "latest_released_source_url": source["url"],
        "latest_released_checked_at": source["checked_at"],
        "devices_more_than_one_major_behind": (
            int_or_none("devices_more_than_one_major_behind") or 0),
        "devices_not_comparable": int_or_none("devices_not_comparable") or 0,
        # Never 0 when not assessed (D14/D6-style honesty rule): the platform
        # sends a real int only when the product is CVE-mapped at all.
        "cve_count_on_oldest_version": int_or_none("cve_count_on_oldest_version"),
        "cve_not_assessed_on_oldest_version": raw.get("cve_not_assessed_on_oldest_version") is True,
        "device_count": int_or_none("device_count") or 0,
        "stale_device_count": int_or_none("stale_device_count") or 0,
        "versions": versions,
    }


@app.get("/reports/software/version-sprawl", response_class=HTMLResponse)
def sam_version_sprawl(request: Request):
    """PAT-2150: version-sprawl SAM report. Every portal role can read it;
    platform filters and pages through the platform's own params, and the
    products table never re-sorts what the platform returns (it is already
    sorted distinct_versions desc, then devices_more_than_one_major_behind
    desc, then name)."""
    platform_filter = request.query_params.get("platform", "")
    if platform_filter not in VERSION_SPRAWL_PLATFORM_FILTERS:
        platform_filter = ""
    page_num = _parse_page(request.query_params.get("page", "1"))
    offset = (page_num - 1) * VERSION_SPRAWL_PAGE_SIZE

    params = _version_sprawl_filter_params(platform_filter)
    params["limit"] = VERSION_SPRAWL_PAGE_SIZE
    params["offset"] = offset
    try:
        data = upstream.get_json(
            "/v1/portal/reports/software/version-sprawl", request.state.jwt, params=params)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)

    products_raw = upstream.unwrap_list(data, "products")
    products = [_version_sprawl_product_row(p) for p in products_raw if isinstance(p, dict)]

    total = data.get("total", len(products)) if isinstance(data, dict) else len(products)
    limit = (data.get("limit", VERSION_SPRAWL_PAGE_SIZE)
            if isinstance(data, dict) else VERSION_SPRAWL_PAGE_SIZE)
    total_pages = max(1, -(-total // limit)) if limit else 1

    if not products and offset > 0:
        return RedirectResponse(
            url=_version_sprawl_report_url(platform_filter), status_code=302)

    basis = _report_basis_view(data.get("basis") if isinstance(data, dict) else None)

    csv_params = _version_sprawl_filter_params(platform_filter)
    csv_url = ("/reports/software/version-sprawl.csv"
              + (("?" + urlencode(csv_params)) if csv_params else ""))

    return _render(request, "software_report_version_sprawl.html", {
        "title": "Version sprawl", "nav": "reports",
        "basis": basis, "products": products, "total": total,
        "page": page_num, "total_pages": total_pages,
        "platform_filter": platform_filter,
        "prev_url": _version_sprawl_report_url(platform_filter, page_num - 1),
        "next_url": _version_sprawl_report_url(platform_filter, page_num + 1),
        "csv_url": csv_url,
        "pdf_url": _pdf_twin(csv_url),
    })


def _version_sprawl_csv_spec(request: Request) -> _ProxiedCsv:
    params = _version_sprawl_filter_params(request.query_params.get("platform", ""))
    return _ProxiedCsv(
        "software-version-sprawl", "/v1/portal/reports/software/version-sprawl", params,
        "patched-version-sprawl.csv",
        _filter_pairs(params, {"platform": ("Platform", PLATFORM_FILTER_LABELS)}))


@app.get("/reports/software/version-sprawl.csv")
def sam_version_sprawl_csv(request: Request):
    """Proxies the platform's own CSV rather than re-serialising it
    portal-side (same convention as PAT-2147/PAT-2148's CSV proxies)."""
    return _proxied_csv_response(request, _version_sprawl_csv_spec(request))


@app.get("/reports/software/version-sprawl.pdf")
def sam_version_sprawl_pdf(request: Request):
    """PAT-2405: the same rows as the CSV above, as a PDF."""
    return _proxied_csv_pdf_response(request, _version_sprawl_csv_spec(request))


# ── PAT-2151: SAM report - duplicate tools by category ──────────────────────
# contracts/portal-api.md "GET /v1/portal/reports/software/duplicate-tools".
# Detection is internal/categorytag's own match rules (same pattern PAT-2147/
# PAT-2148 use), grouped by product_key so one product's macOS/Windows/
# Homebrew identities count once. A category is flagged at three or more
# distinct products (MinProductsToFlag); the ticket's other "two or more paid
# products" rule needs price data that does not exist yet
# (paid_products_rule_pending, always true today) and is not evaluated here.
# Copy says "consolidation candidates", never "waste" (this ticket's own
# instruction) - Patched observes what is installed, it does not judge it.
DUPLICATE_TOOLS_PAGE_SIZE = 50
DUPLICATE_TOOLS_CATEGORIES = (
    "pdf_editor", "screen_recorder", "vpn_client", "password_manager", "file_sync",
    "video_conferencing", "remote_access", "note_taking",
)
DUPLICATE_TOOLS_KIND_LABELS = {
    "app": "App", "browser_extension": "Browser extension", "package": "Package",
}
DUPLICATE_TOOLS_PRODUCT_KEY_MAX_CHARS = 512


def _duplicate_tools_filter_params(category: str, product_key: str) -> dict:
    """Only ever the platform's own documented filter values - an
    unrecognised query value is dropped rather than forwarded, matching
    every other filtered read on this portal."""
    params: dict[str, str] = {}
    if category in DUPLICATE_TOOLS_CATEGORIES:
        params["category"] = category
    if product_key:
        params["product_key"] = product_key
    return params


def _duplicate_tools_report_url(category: str, page: int = 1) -> str:
    params: dict[str, str] = {}
    if category:
        params["category"] = category
    if page > 1:
        params["page"] = str(page)
    query = urlencode(params)
    return "/reports/software/duplicate-tools" + (("?" + query) if query else "")


def _duplicate_tools_basis_view(raw: dict | None) -> dict:
    """Same shape _report_basis_view already gives PAT-2148/PAT-2150, plus
    this report's own paid_products_rule_pending flag (D14: nothing invented
    - defaults False so absence never silently reads as "rule applied")."""
    basis = _report_basis_view(raw)
    src = raw if isinstance(raw, dict) else {}
    basis["paid_products_rule_pending"] = src.get("paid_products_rule_pending") is True
    return basis


def _duplicate_tools_summary_view(raw: dict | None) -> dict:
    summary = raw if isinstance(raw, dict) else {}

    def int_or_zero(key):
        value = summary.get(key)
        return value if type(value) is int else 0

    categories_assessed = int_or_zero("categories_assessed")
    categories_with_products = int_or_zero("categories_with_products")
    categories_flagged = int_or_zero("categories_flagged")
    product_count = int_or_zero("product_count")
    installation_count = int_or_zero("installation_count")
    kpi_items = [
        ("Categories flagged", f"{categories_flagged} of {categories_assessed}",
         "bad-text" if categories_flagged else ""),
        ("Categories with products", f"{categories_with_products} of {categories_assessed}", ""),
        ("Products", f"{product_count}", ""),
        ("Installations", f"{installation_count}", ""),
    ]
    return {
        "categories_assessed": categories_assessed,
        "categories_with_products": categories_with_products,
        "categories_flagged": categories_flagged,
        "product_count": product_count,
        "installation_count": installation_count,
        "kpi_items": kpi_items,
    }


def _duplicate_tools_product_row(raw: dict) -> dict:
    platforms_raw = raw.get("platforms")
    platforms = ([p for p in platforms_raw if isinstance(p, str)]
                if isinstance(platforms_raw, list) else [])
    kinds_raw = raw.get("kinds")
    kinds = [k for k in kinds_raw if isinstance(k, str)] if isinstance(kinds_raw, list) else []
    users_raw = raw.get("users")
    users = [u for u in users_raw if isinstance(u, str)] if isinstance(users_raw, list) else []
    # Approval-state pills reuse remote access's own map (PAT-2148): both
    # reports read the same four-value PAT-2007 vocabulary
    # (approved/unapproved/unreviewed/ignored), so one pill mapping serves
    # both rather than a second copy drifting from it.
    state = (raw.get("approval_state") if raw.get("approval_state") in APPROVAL_STATE_LABELS
            else "unreviewed")
    return {
        "product_key": raw.get("product_key") if isinstance(raw.get("product_key"), str) else "",
        "category": raw.get("category") if isinstance(raw.get("category"), str) else "",
        "name": (raw.get("name") if isinstance(raw.get("name"), str) and raw.get("name")
                else "Unknown product"),
        "kinds": kinds,
        "kinds_label": (", ".join(DUPLICATE_TOOLS_KIND_LABELS.get(k, k) for k in kinds)
                        if kinds else "Software"),
        "platforms": platforms,
        "approval_state": state, "approval_state_label": APPROVAL_STATE_LABELS.get(state, state),
        "pill_class": REMOTE_ACCESS_PILL_CLASS.get(state, "pill-muted"),
        "device_count": raw.get("device_count") if type(raw.get("device_count")) is int else 0,
        "stale_device_count": (raw.get("stale_device_count")
                               if type(raw.get("stale_device_count")) is int else 0),
        "installation_count": (raw.get("installation_count")
                               if type(raw.get("installation_count")) is int else 0),
        "users": users,
        "machine_wide_count": (raw.get("machine_wide_count")
                               if type(raw.get("machine_wide_count")) is int else 0),
        "last_seen": raw.get("last_seen"),
    }


def _duplicate_tools_category_row(raw: dict) -> dict:
    """A category is only ever sent when at least one product is present
    (contract: "a category with zero matched products is left out
    entirely") - the template never needs to render a zero-product card."""
    products_raw = raw.get("products")
    products = ([_duplicate_tools_product_row(p) for p in products_raw if isinstance(p, dict)]
               if isinstance(products_raw, list) else [])
    category = raw.get("category") if isinstance(raw.get("category"), str) else ""
    return {
        "category": category,
        "display_name": (raw.get("display_name")
                         if isinstance(raw.get("display_name"), str) and raw.get("display_name")
                         else category or "Category"),
        "flagged": raw.get("flagged") is True,
        "product_count": (raw.get("product_count")
                          if type(raw.get("product_count")) is int else len(products)),
        "products": products,
    }


@app.get("/reports/software/duplicate-tools", response_class=HTMLResponse)
def sam_duplicate_tools(request: Request):
    """PAT-2151: duplicate-tools-by-category SAM report. Every portal role
    can read it; category filters and pages through the platform's own
    params. Flagged categories (three or more distinct products) render
    first and expanded; the rest render collapsed - the platform's own row
    order within a page is never re-sorted here (same convention PAT-2147/
    PAT-2148/PAT-2150 already follow)."""
    category_filter = request.query_params.get("category", "")
    if category_filter not in DUPLICATE_TOOLS_CATEGORIES:
        category_filter = ""
    page_num = _parse_page(request.query_params.get("page", "1"))
    offset = (page_num - 1) * DUPLICATE_TOOLS_PAGE_SIZE

    params = _duplicate_tools_filter_params(category_filter, "")
    params["limit"] = DUPLICATE_TOOLS_PAGE_SIZE
    params["offset"] = offset
    try:
        data = upstream.get_json(
            "/v1/portal/reports/software/duplicate-tools", request.state.jwt, params=params)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)

    categories_raw = upstream.unwrap_list(data, "categories")
    all_categories = [
        _duplicate_tools_category_row(c) for c in categories_raw if isinstance(c, dict)
    ]

    total = (data.get("total", len(all_categories))
            if isinstance(data, dict) else len(all_categories))
    limit = (data.get("limit", DUPLICATE_TOOLS_PAGE_SIZE)
            if isinstance(data, dict) else DUPLICATE_TOOLS_PAGE_SIZE)
    total_pages = max(1, -(-total // limit)) if limit else 1

    if not all_categories and offset > 0:
        return RedirectResponse(url=_duplicate_tools_report_url(category_filter), status_code=302)

    flagged_categories = [c for c in all_categories if c["flagged"]]
    unflagged_categories = [c for c in all_categories if not c["flagged"]]

    summary = _duplicate_tools_summary_view(data.get("summary") if isinstance(data, dict) else None)
    basis = _duplicate_tools_basis_view(data.get("basis") if isinstance(data, dict) else None)

    csv_params = _duplicate_tools_filter_params(category_filter, "")
    csv_url = ("/reports/software/duplicate-tools.csv"
              + (("?" + urlencode(csv_params)) if csv_params else ""))

    return _render(request, "software_report_duplicate_tools.html", {
        "title": "Duplicate tools", "nav": "reports",
        "summary": summary, "basis": basis,
        "flagged_categories": flagged_categories, "unflagged_categories": unflagged_categories,
        "total": total, "page": page_num, "total_pages": total_pages,
        "category_filter": category_filter,
        "prev_url": _duplicate_tools_report_url(category_filter, page_num - 1),
        "next_url": _duplicate_tools_report_url(category_filter, page_num + 1),
        "csv_url": csv_url,
        "pdf_url": _pdf_twin(csv_url),
    })


_DUPLICATE_TOOLS_CATEGORY_NAMES = {
    "pdf_editor": "PDF editor", "screen_recorder": "Screen recorder",
    "vpn_client": "VPN client", "password_manager": "Password manager",
    "file_sync": "File sync", "video_conferencing": "Video conferencing",
    "remote_access": "Remote access", "note_taking": "Note taking",
}


def _duplicate_tools_csv_spec(request: Request) -> _ProxiedCsv:
    product_key = request.query_params.get(
        "product_key", "")[:DUPLICATE_TOOLS_PRODUCT_KEY_MAX_CHARS]
    params = _duplicate_tools_filter_params(
        request.query_params.get("category", ""), product_key)
    categories = {c: _DUPLICATE_TOOLS_CATEGORY_NAMES.get(c, _title_label(c))
                  for c in DUPLICATE_TOOLS_CATEGORIES}
    return _ProxiedCsv(
        "software-duplicate-tools", "/v1/portal/reports/software/duplicate-tools", params,
        "patched-duplicate-tools.csv",
        _filter_pairs(params, {"category": ("Category", categories),
                               "product_key": ("Product", None)}))


@app.get("/reports/software/duplicate-tools.csv")
def sam_duplicate_tools_csv(request: Request):
    """Proxies the platform's own CSV - the per-device (and per-user) row
    export behind every figure, unpaged (same convention as PAT-2147/
    PAT-2148/PAT-2150's CSV proxies)."""
    return _proxied_csv_response(request, _duplicate_tools_csv_spec(request))


@app.get("/reports/software/duplicate-tools.pdf")
def sam_duplicate_tools_pdf(request: Request):
    """PAT-2405: the same rows as the CSV above, as a PDF."""
    return _proxied_csv_pdf_response(request, _duplicate_tools_csv_spec(request))


# ── PAT-2152: SAM report - software publishers ───────────────────────────────
# contracts/portal-api.md "GET /v1/portal/reports/software/publishers"
# (+ "/devices"). Publisher identity is code signing evidence only - the
# macOS Team ID or the Windows Authenticode signer pinned to its root - never
# a display name or registry Publisher string, so this report can never show
# a publisher name for anything the platform itself could not verify. Four
# groups, most attention-worthy first: unsigned_or_adhoc, invalid and
# unverified are call-out rows with no publisher identity at all (rendered
# with a plain explanation, never a name); verified is the tenant's actual
# publisher listing with its own Trusted/Not trusted pill (PAT-2121 - this
# tenant's own approval decision, never a judgement on the vendor).
PUBLISHER_PAGE_SIZE = 100
PUBLISHER_DEVICES_PAGE_SIZE = 100
PUBLISHER_GROUPS = ("unsigned_or_adhoc", "invalid", "unverified", "verified")
PUBLISHER_GROUP_LABELS = {
    "unsigned_or_adhoc": "No signing evidence",
    "invalid": "Invalid signature",
    "unverified": "Unverified",
    "verified": "Verified",
}
# Plain, customer-facing explanations (C9) - every call-out group ends the
# same way ("Patched can't verify who published this") so a customer reads
# one consistent reason regardless of which of the three it hits.
PUBLISHER_GROUP_EXPLANATIONS = {
    "unsigned_or_adhoc": "No signing evidence: Patched can't verify who published this.",
    "invalid": "The signature does not check out: Patched can't verify who published this.",
    "unverified": ("The signature checks out but can't be pinned to one publisher: "
                   "Patched can't verify who published this."),
}
PUBLISHER_IDENTITY_BASIS_LABELS = {
    "team_id": "Apple Developer Team ID",
    "apple_signature": "Apple platform signing",
    "authenticode_signer": "Authenticode signer",
    "none": "No signing evidence",
}
PUBLISHER_PLATFORM_FILTERS = ("macos", "windows")
PUBLISHER_KEY_MAX_CHARS = 600
PUBLISHER_PRODUCT_KEY_MAX_CHARS = 512
PUBLISHER_DEVICE_ID_MAX_CHARS = 128


def _publisher_filter_params(group: str, platform: str, publisher_key: str) -> dict:
    params: dict[str, str] = {}
    if group in PUBLISHER_GROUPS:
        params["group"] = group
    if platform in PUBLISHER_PLATFORM_FILTERS:
        params["platform"] = platform
    if publisher_key:
        params["publisher_key"] = publisher_key
    return params


def _publisher_report_url(group: str, platform: str, publisher_key: str, page: int = 1) -> str:
    params: dict[str, str] = {}
    if group:
        params["group"] = group
    if platform:
        params["platform"] = platform
    if publisher_key:
        params["publisher_key"] = publisher_key
    if page > 1:
        params["page"] = str(page)
    query = urlencode(params)
    return "/reports/software/publishers" + (("?" + query) if query else "")


def _publisher_devices_url(product_key: str, device_id: str, group: str, platform: str,
                            publisher_key: str, page: int = 1) -> str:
    params: dict[str, str] = {}
    if product_key:
        params["product_key"] = product_key
    if device_id:
        params["device_id"] = device_id
    if group:
        params["group"] = group
    if platform:
        params["platform"] = platform
    if publisher_key:
        params["publisher_key"] = publisher_key
    if page > 1:
        params["page"] = str(page)
    query = urlencode(params)
    return "/reports/software/publishers/devices" + (("?" + query) if query else "")


def _publisher_row(raw: dict) -> dict:
    group = raw.get("group") if raw.get("group") in PUBLISHER_GROUPS else "unverified"
    platform = raw.get("platform") if isinstance(raw.get("platform"), str) else ""
    identity_basis = (raw.get("identity_basis")
                      if isinstance(raw.get("identity_basis"), str) else "none")
    publisher = (raw.get("publisher")
                if isinstance(raw.get("publisher"), str) and raw.get("publisher") else None)
    signer_class = (raw.get("signer_class")
                   if isinstance(raw.get("signer_class"), str) and raw.get("signer_class")
                   else None)
    return {
        "publisher_key": (raw.get("publisher_key")
                          if isinstance(raw.get("publisher_key"), str) else ""),
        "group": group, "group_label": PUBLISHER_GROUP_LABELS.get(group, group),
        "platform": platform,
        "identity_basis": identity_basis,
        "identity_basis_label": PUBLISHER_IDENTITY_BASIS_LABELS.get(identity_basis, identity_basis),
        # Never a publisher name outside the verified group (this ticket's
        # own instruction) - enforced here rather than trusted to every
        # template render site, even though the contract already sends null
        # for every call-out row.
        "publisher": publisher if group == "verified" else None,
        "trusted": raw.get("trusted") is True,
        "signing": raw.get("signing") if isinstance(raw.get("signing"), str) else "",
        "signer_class": signer_class,
        "notarisation": raw.get("notarisation") if isinstance(raw.get("notarisation"), str) else "",
        "product_count": raw.get("product_count") if type(raw.get("product_count")) is int else 0,
        "device_count": raw.get("device_count") if type(raw.get("device_count")) is int else 0,
        "stale_device_count": (raw.get("stale_device_count")
                               if type(raw.get("stale_device_count")) is int else 0),
        "installation_count": (raw.get("installation_count")
                               if type(raw.get("installation_count")) is int else 0),
    }


def _publisher_device_row(raw: dict) -> dict:
    """A publisher row's fields plus the one installation's own device and
    product identity (contracts/portal-api.md: 'the same ... fields as a
    publisher row, plus product_key, name, identifier and version')."""
    row = _publisher_row(raw)
    row.update({
        "device_id": raw.get("device_id") if isinstance(raw.get("device_id"), str) else "",
        "hostname": (raw.get("hostname")
                    if isinstance(raw.get("hostname"), str) and raw.get("hostname")
                    else "Unknown device"),
        "device_last_seen": raw.get("device_last_seen"),
        "device_stale": raw.get("device_stale") is True,
        "product_key": raw.get("product_key") if isinstance(raw.get("product_key"), str) else "",
        "name": (raw.get("name") if isinstance(raw.get("name"), str) and raw.get("name")
                else "Unknown product"),
        "identifier": raw.get("identifier") if isinstance(raw.get("identifier"), str) else None,
        "version": (raw.get("version") if isinstance(raw.get("version"), str) and raw.get("version")
                   else None),
    })
    return row


def _publisher_summary_view(raw: dict | None) -> dict:
    summary = raw if isinstance(raw, dict) else {}

    def int_or_zero(key):
        value = summary.get(key)
        return value if type(value) is int else 0

    publisher_count = int_or_zero("publisher_count")
    trusted_publisher_count = int_or_zero("trusted_publisher_count")
    untrusted_publisher_count = int_or_zero("untrusted_publisher_count")
    unsigned_installation_count = int_or_zero("unsigned_installation_count")
    invalid_installation_count = int_or_zero("invalid_installation_count")
    unverified_installation_count = int_or_zero("unverified_installation_count")
    installation_count = int_or_zero("installation_count")
    kpi_items = [
        ("No signing evidence",
         f"{unsigned_installation_count} install{'' if unsigned_installation_count == 1 else 's'}",
         "bad-text" if unsigned_installation_count else ""),
        ("Invalid signature",
         f"{invalid_installation_count} install{'' if invalid_installation_count == 1 else 's'}",
         "bad-text" if invalid_installation_count else ""),
        ("Unverified",
         f"{unverified_installation_count} "
         f"install{'' if unverified_installation_count == 1 else 's'}",
         "warn-text" if unverified_installation_count else ""),
        ("Verified publishers",
         f"{publisher_count} publisher{'' if publisher_count == 1 else 's'} "
         f"({trusted_publisher_count} trusted)", ""),
    ]
    return {
        "publisher_count": publisher_count, "trusted_publisher_count": trusted_publisher_count,
        "untrusted_publisher_count": untrusted_publisher_count,
        "unsigned_installation_count": unsigned_installation_count,
        "invalid_installation_count": invalid_installation_count,
        "unverified_installation_count": unverified_installation_count,
        "installation_count": installation_count,
        "kpi_items": kpi_items,
    }


@app.get("/reports/software/publishers", response_class=HTMLResponse)
def sam_publishers(request: Request):
    """PAT-2152: software-publishers SAM report. Every portal role can read
    it; group/platform/publisher_key filter and page through the platform's
    own params. Unsigned, invalid and unverified installs render as call-out
    rows ahead of the verified publisher table - the platform's own row
    order (unsigned, invalid, unverified, then verified) is never re-sorted
    here, only split into two sections for display (same convention PAT-2148
    already follows for RMM agents)."""
    group_filter = request.query_params.get("group", "")
    if group_filter not in PUBLISHER_GROUPS:
        group_filter = ""
    platform_filter = request.query_params.get("platform", "")
    if platform_filter not in PUBLISHER_PLATFORM_FILTERS:
        platform_filter = ""
    publisher_key = request.query_params.get("publisher_key", "")[:PUBLISHER_KEY_MAX_CHARS]
    page_num = _parse_page(request.query_params.get("page", "1"))
    offset = (page_num - 1) * PUBLISHER_PAGE_SIZE

    params = _publisher_filter_params(group_filter, platform_filter, publisher_key)
    params["limit"] = PUBLISHER_PAGE_SIZE
    params["offset"] = offset
    try:
        data = upstream.get_json(
            "/v1/portal/reports/software/publishers", request.state.jwt, params=params)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)

    publishers_raw = upstream.unwrap_list(data, "publishers")
    all_rows = [_publisher_row(p) for p in publishers_raw if isinstance(p, dict)]
    for row in all_rows:
        row["devices_url"] = _publisher_devices_url(
            "", "", row["group"], row["platform"], row["publisher_key"])

    total = data.get("total", len(all_rows)) if isinstance(data, dict) else len(all_rows)
    limit = (data.get("limit", PUBLISHER_PAGE_SIZE)
            if isinstance(data, dict) else PUBLISHER_PAGE_SIZE)
    total_pages = max(1, -(-total // limit)) if limit else 1

    if not all_rows and offset > 0:
        return RedirectResponse(
            url=_publisher_report_url(group_filter, platform_filter, publisher_key),
            status_code=302)

    callout_rows = [r for r in all_rows if r["group"] != "verified"]
    verified_rows = [r for r in all_rows if r["group"] == "verified"]

    summary = _publisher_summary_view(data.get("summary") if isinstance(data, dict) else None)
    basis = _report_basis_view(data.get("basis") if isinstance(data, dict) else None)

    csv_params = _publisher_filter_params(group_filter, platform_filter, publisher_key)
    csv_url = ("/reports/software/publishers.csv"
              + (("?" + urlencode(csv_params)) if csv_params else ""))

    return _render(request, "software_report_publishers.html", {
        "title": "Software publishers", "nav": "reports",
        "summary": summary, "basis": basis,
        "callout_rows": callout_rows, "verified_rows": verified_rows,
        "pub_explanations": PUBLISHER_GROUP_EXPLANATIONS,
        "total": total, "page": page_num, "total_pages": total_pages,
        "group_filter": group_filter, "platform_filter": platform_filter,
        "publisher_key": publisher_key,
        "prev_url": _publisher_report_url(
            group_filter, platform_filter, publisher_key, page_num - 1),
        "next_url": _publisher_report_url(
            group_filter, platform_filter, publisher_key, page_num + 1),
        "csv_url": csv_url,
        "pdf_url": _pdf_twin(csv_url),
    })


PUBLISHER_FILTER_SPECS = {
    "group": ("Publisher group", PUBLISHER_GROUP_LABELS),
    "platform": ("Platform", PLATFORM_FILTER_LABELS),
    "publisher_key": ("Publisher", None),
}


def _publishers_csv_spec(request: Request) -> _ProxiedCsv:
    publisher_key = request.query_params.get("publisher_key", "")[:PUBLISHER_KEY_MAX_CHARS]
    params = _publisher_filter_params(
        request.query_params.get("group", ""), request.query_params.get("platform", ""),
        publisher_key)
    return _ProxiedCsv(
        "software-publishers", "/v1/portal/reports/software/publishers", params,
        "patched-software-publishers.csv", _filter_pairs(params, PUBLISHER_FILTER_SPECS))


@app.get("/reports/software/publishers.csv")
def sam_publishers_csv(request: Request):
    """Proxies the platform's own CSV - contracts/portal-api.md: this is
    the /devices drill-down's own per-installation row export, unpaged, not
    the publisher-summary rows (same "the report's own logic lives in
    exactly one place" convention as every other SAM CSV proxy)."""
    return _proxied_csv_response(request, _publishers_csv_spec(request))


@app.get("/reports/software/publishers.pdf")
def sam_publishers_pdf(request: Request):
    """PAT-2405: the same rows as the CSV above, as a PDF."""
    return _proxied_csv_pdf_response(request, _publishers_csv_spec(request))


@app.get("/reports/software/publishers/devices", response_class=HTMLResponse)
def sam_publishers_devices(request: Request):
    """The per-installation drill-down (contracts/portal-api.md 'GET
    /v1/portal/reports/software/publishers/devices'). Reached filtered to
    one publisher by clicking through a row, or unfiltered directly."""
    product_key = request.query_params.get("product_key", "")[:PUBLISHER_PRODUCT_KEY_MAX_CHARS]
    device_id = request.query_params.get("device_id", "")[:PUBLISHER_DEVICE_ID_MAX_CHARS]
    group_filter = request.query_params.get("group", "")
    if group_filter not in PUBLISHER_GROUPS:
        group_filter = ""
    platform_filter = request.query_params.get("platform", "")
    if platform_filter not in PUBLISHER_PLATFORM_FILTERS:
        platform_filter = ""
    publisher_key = request.query_params.get("publisher_key", "")[:PUBLISHER_KEY_MAX_CHARS]
    page_num = _parse_page(request.query_params.get("page", "1"))
    offset = (page_num - 1) * PUBLISHER_DEVICES_PAGE_SIZE

    params = _publisher_filter_params(group_filter, platform_filter, publisher_key)
    if product_key:
        params["product_key"] = product_key
    if device_id:
        params["device_id"] = device_id
    params["limit"] = PUBLISHER_DEVICES_PAGE_SIZE
    params["offset"] = offset
    try:
        data = upstream.get_json(
            "/v1/portal/reports/software/publishers/devices", request.state.jwt, params=params)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)

    rows_raw = upstream.unwrap_list(data, "rows")
    rows = [_publisher_device_row(r) for r in rows_raw if isinstance(r, dict)]

    total = data.get("total", len(rows)) if isinstance(data, dict) else len(rows)
    limit = (data.get("limit", PUBLISHER_DEVICES_PAGE_SIZE)
            if isinstance(data, dict) else PUBLISHER_DEVICES_PAGE_SIZE)
    total_pages = max(1, -(-total // limit)) if limit else 1

    if not rows and offset > 0:
        return RedirectResponse(
            url=_publisher_devices_url(
                product_key, device_id, group_filter, platform_filter, publisher_key),
            status_code=302)

    basis = _report_basis_view(data.get("basis") if isinstance(data, dict) else None)

    csv_params = _publisher_filter_params(group_filter, platform_filter, publisher_key)
    if product_key:
        csv_params["product_key"] = product_key
    if device_id:
        csv_params["device_id"] = device_id
    csv_url = "/reports/software/publishers/devices.csv?" + urlencode(csv_params)

    return _render(request, "software_report_publishers_devices.html", {
        "title": "Software publishers - devices", "nav": "reports",
        "rows": rows, "basis": basis, "total": total,
        "page": page_num, "total_pages": total_pages,
        "product_key": product_key, "device_id": device_id,
        "group_filter": group_filter, "platform_filter": platform_filter,
        "publisher_key": publisher_key,
        "pub_explanations": PUBLISHER_GROUP_EXPLANATIONS,
        "prev_url": _publisher_devices_url(
            product_key, device_id, group_filter, platform_filter, publisher_key, page_num - 1),
        "next_url": _publisher_devices_url(
            product_key, device_id, group_filter, platform_filter, publisher_key, page_num + 1),
        "csv_url": csv_url,
        "pdf_url": _pdf_twin(csv_url),
        "report_url": _publisher_report_url(group_filter, platform_filter, publisher_key),
    })


def _publishers_devices_csv_spec(request: Request) -> _ProxiedCsv:
    product_key = request.query_params.get("product_key", "")[:PUBLISHER_PRODUCT_KEY_MAX_CHARS]
    device_id = request.query_params.get("device_id", "")[:PUBLISHER_DEVICE_ID_MAX_CHARS]
    publisher_key = request.query_params.get("publisher_key", "")[:PUBLISHER_KEY_MAX_CHARS]
    params = _publisher_filter_params(
        request.query_params.get("group", ""), request.query_params.get("platform", ""),
        publisher_key)
    if product_key:
        params["product_key"] = product_key
    if device_id:
        params["device_id"] = device_id
    return _ProxiedCsv(
        "software-publishers-devices", "/v1/portal/reports/software/publishers/devices",
        params, "patched-software-publishers-devices.csv",
        _filter_pairs(params, {**PUBLISHER_FILTER_SPECS, "product_key": ("Product", None),
                               "device_id": ("Device", None)}))


@app.get("/reports/software/publishers/devices.csv")
def sam_publishers_devices_csv(request: Request):
    return _proxied_csv_response(request, _publishers_devices_csv_spec(request))


@app.get("/reports/software/publishers/devices.pdf")
def sam_publishers_devices_pdf(request: Request):
    """PAT-2405: the same rows as the devices CSV above, as a PDF."""
    return _proxied_csv_pdf_response(request, _publishers_devices_csv_spec(request))


# ── Estate enrolment keys (PAT-2251, platform contract PAT-2250) ──────────
# A reusable, revocable credential for estate rollouts (Intune, Jamf, an
# RMM): one key, many devices, over weeks - unlike the single-use token
# above, which is exchanged once and dies. Redeems at the agent's own
# enrolment step exactly like a single-use token (same field, no agent
# change - contracts/portal-api.md "Tenant enrolment keys (PAT-2250)").
# Guarded exactly like every other write in this repo: _guarded_form (size
# cap, then Origin, then CSRF), then role - admin only, checked here before
# the platform is asked (which enforces the same thing server-side, 403
# admin_role_required). GET /v1/portal/enrolment-keys is every role; only
# the two writes (create, revoke) are admin only.
#
# Security-critical, same shape as the Jamf webhook token (PAT-2145): the
# plaintext is returned exactly once, directly in the create POST's own
# response body - never via a redirect, a flash, a query string or the
# session - with Cache-Control: no-store and Pragma: no-cache, and it must
# never appear in any later GET /install.
ENROLMENT_KEY_LABEL_MAX_CHARS = 100
ENROLMENT_KEY_MAX_DEVICES_LIMIT = 100000
ENROLMENT_KEY_DEFAULT_EXPIRES_DAYS = 30
ENROLMENT_KEY_MAX_EXPIRES_DAYS = 365
INSTALL_RESULT_PARAM = "install_result"

# status -> (label, pill class), precedence per contracts/portal-api.md
# ("revoked, expired, exhausted or active, in that precedence" - the
# platform already applies the precedence; this is display only).
# "exhausted" reads as "Full" in the portal's own house copy.
ENROLMENT_KEY_STATUS_META = {
    "active": ("Active", "pill-ok"),
    "expired": ("Expired", "pill-muted"),
    "revoked": ("Revoked", "pill-muted"),
    "exhausted": ("Full", "pill-warn"),
}


def _enrolment_key_view(row: dict) -> dict:
    status = row.get("status") if isinstance(row.get("status"), str) else ""
    label, pill_class = ENROLMENT_KEY_STATUS_META.get(status, ("Unknown", "pill-muted"))
    return {
        "key_id": row.get("key_id") if isinstance(row.get("key_id"), str) else "",
        "label": row.get("label") if isinstance(row.get("label"), str) else "",
        "key_hint": row.get("key_hint") if isinstance(row.get("key_hint"), str) else "",
        "max_devices": row.get("max_devices") if type(row.get("max_devices")) is int else 0,
        "devices_enrolled":
            row.get("devices_enrolled") if type(row.get("devices_enrolled")) is int else 0,
        "status": status,
        "status_label": label,
        "status_pill_class": pill_class,
        "expires_at": row.get("expires_at"),
        "created_at": row.get("created_at"),
        "created_by": row.get("created_by") if isinstance(row.get("created_by"), str) else "",
        "revoked_at": row.get("revoked_at"),
    }


def _enrolment_keys_view(data) -> list[dict]:
    """Normalise GET /v1/portal/enrolment-keys's {"keys": [...]} into view
    rows for the template. Never carries a plaintext - the list contract
    never returns one (contracts/portal-api.md)."""
    rows = data.get("keys") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return []
    return [_enrolment_key_view(r) for r in rows if isinstance(r, dict)]


def _parse_enrolment_key_create_form(form: dict[str, list[str]]) -> tuple[dict | None, str | None]:
    """Validate the create form the same way the platform will (mirrors
    PortalEnrolmentKeyCreateHandler's own bounds), so an obviously bad
    submission never spends the shared mint rate limit on a call the
    platform would just refuse anyway."""
    label_values = form.get("label", [])
    max_devices_values = form.get("max_devices", [])
    expires_values = form.get("expires_in_days", [])
    if len(label_values) != 1 or len(max_devices_values) != 1 or len(expires_values) > 1:
        return None, "That request could not be read."
    label = label_values[0].strip()
    if not label or len(label) > ENROLMENT_KEY_LABEL_MAX_CHARS or _CONTROL_CHARS_RE.search(label):
        return None, (
            f"Label is required, at most {ENROLMENT_KEY_LABEL_MAX_CHARS} characters, "
            "with no control characters.")
    try:
        max_devices = int(max_devices_values[0])
    except ValueError:
        return None, "Device cap must be a whole number."
    if max_devices < 1 or max_devices > ENROLMENT_KEY_MAX_DEVICES_LIMIT:
        return None, f"Device cap must be between 1 and {ENROLMENT_KEY_MAX_DEVICES_LIMIT}."
    payload: dict = {"label": label, "max_devices": max_devices}
    expires_raw = expires_values[0].strip() if expires_values else ""
    if expires_raw:
        try:
            expires_in_days = int(expires_raw)
        except ValueError:
            return None, "Expiry must be a whole number of days."
        if expires_in_days < 1 or expires_in_days > ENROLMENT_KEY_MAX_EXPIRES_DAYS:
            return None, f"Expiry must be between 1 and {ENROLMENT_KEY_MAX_EXPIRES_DAYS} days."
        payload["expires_in_days"] = expires_in_days
    return payload, None


def _install_redirect(request: Request, payload: dict) -> RedirectResponse:
    """Post-revoke redirect with a signed flash notice, same shape as
    _jamf_redirect/_device_redirect. Never used for create: the plaintext
    must render directly in that POST's own response, not travel via a
    redirect URL."""
    token = _sign_flash(request.state.jwt, payload)
    url = f"/install?{INSTALL_RESULT_PARAM}={quote(token, safe='')}#install-result"
    return RedirectResponse(url=url, status_code=303)


def _install_flash_view(data: dict | None) -> dict | None:
    if not data:
        return None

    def text(key, limit=400):
        value = data.get(key)
        return value[:limit] if isinstance(value, str) else ""

    return {"error": text("error"), "notice": text("notice")}


def _install_error_payload(exc: upstream.UpstreamError, action: str) -> dict:
    if exc.kind == "unavailable":
        return {"error": (
            "The Patched platform could not be reached, so this change may not have been "
            "saved. Refresh the page to check before trying again."
        )}
    if exc.kind == "rate_limited":
        return {"error": (
            "You've created several enrolment credentials recently - please wait a few "
            "minutes before trying again."
        )}
    try:
        body = json.loads(exc.body) if exc.body else {}
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    code = body.get("error") if isinstance(body.get("error"), str) else ""
    message = body.get("message") if isinstance(body.get("message"), str) else ""
    if code == "admin_role_required":
        return {"error": (
            f"Only an administrator on your account can {action}. Nothing was changed."
        )}
    if exc.status == 409:
        return {"error": (
            "Your estate has an active decommission directive, so this change was refused. "
            "Nothing was changed."
        )}
    return {"error": (
        (message[:300] + " Nothing was changed.") if message
        else "The Patched platform refused this change. Nothing was changed."
    )}


def _macos_enrolment_script(token: str, generated_on: str) -> str:
    """Mirrors the admin dashboard's Deploy-agent Path-1 macOS artifact
    (PAT-550) verbatim, so operators and self-serve customers hand out an
    identical script. The token is single-quoted for the shell; a defensive
    '\\'' escape covers the (unexpected) case of a token containing a quote."""
    safe_token = token.replace("'", "'\\''")
    return (
        "#!/bin/sh\n"
        f"# Patched.im enrollment script — generated {generated_on}\n"
        "# Upload to Intune as a Platform Script (Shell, run as root).\n"
        "# This script writes a single-use enrollment token to /etc/patched/enrollment-token.\n"
        "# The Patched agent reads this file on first run to complete enrollment.\n"
        "set -e\n"
        "mkdir -p /etc/patched\n"
        "chmod 700 /etc/patched\n"
        f"printf '%s' '{safe_token}' > /etc/patched/enrollment-token\n"
        "chmod 600 /etc/patched/enrollment-token\n"
        "chown root:wheel /etc/patched/enrollment-token\n"
        'echo "Patched enrollment token installed."'
    )


def _windows_enrolment_cmd(token: str) -> str:
    """Mirrors the admin dashboard's Deploy-agent Path-1 Windows artifact
    (PAT-550). A defensive doubled-quote escape (the Windows Installer CLI's
    own convention for a literal '"' inside a quoted property value) covers
    the unexpected case of a token containing a double quote, matching the
    single-quote guard in _macos_enrolment_script above."""
    safe_token = token.replace('"', '""')
    return f'msiexec /qn /i PatchedAgent.msi ENROLLMENT_TOKEN="{safe_token}"'


def _install_shared_context(jwt_token: str) -> dict:
    """Role (for the estate keys create/revoke controls) and the estate's
    own key list - shared by every /install render. Both fail soft: a
    platform hiccup on either read must not take down the whole page, only
    hide the controls it could not confirm (mirrors devices_jamf_setup's
    own can_edit/role_unavailable, connector/connector_unavailable shape)."""
    can_edit, role_unavailable = False, False
    try:
        can_edit = _portal_role(jwt_token) == "admin"
    except upstream.UpstreamError as exc:
        logger.warning("portal.install.role_fail_soft kind=%s", exc.kind)
        role_unavailable = True
    keys, keys_unavailable = [], False
    try:
        keys = _enrolment_keys_view(upstream.get_json("/v1/portal/enrolment-keys", jwt_token))
    except upstream.UpstreamError as exc:
        logger.warning("portal.install.keys_fail_soft kind=%s", exc.kind)
        keys_unavailable = True
    return {
        "can_edit": can_edit, "role_unavailable": role_unavailable,
        "enrolment_keys": keys, "enrolment_keys_unavailable": keys_unavailable,
    }


@app.get("/install", response_class=HTMLResponse)
def install(request: Request):
    """Pre-generation view: explains the MDM self-serve enrolment flow,
    lists the estate's own enrolment keys (every role reads the list,
    PAT-2251) and offers the one-off 'Generate a one-off install token'
    button (PAT-453). Makes no upstream call for the single-use token
    itself - that generation is a separate POST below - so this view never
    holds or displays a real token; the key list read here never carries a
    plaintext key either (contracts/portal-api.md: the list contract never
    returns one)."""
    return _render(request, "install.html", {
        "title": "Install the agent", "nav": "install",
        "install_result": _install_flash_view(_read_flash(
            request.state.jwt, request.query_params.get(INSTALL_RESULT_PARAM, ""))),
        **_install_shared_context(request.state.jwt),
    })


INSTALL_TOKEN_ADMIN_ONLY = (
    "Only an administrator on your account can generate an install token.")


@app.post("/install/enrolment", response_class=HTMLResponse)
async def generate_enrolment_token(request: Request):
    """Mint a single-use, one-off MDM install token for the caller's own
    tenant (PAT-453; house copy "One-off install token" - distinct from the
    reusable estate enrolment key below, PAT-2251). Proxies
    POST /v1/portal/enrolment exactly like generate_report proxies
    /v1/portal/reports: the JWT is forwarded verbatim, the platform derives
    the tenant and owns rate-limiting (shared with the key mint below).
    The portal is stateless - the token is shown once, in this response,
    rendered straight into the macOS/Windows artifacts, and never logged
    or persisted here. Size, Origin and CSRF are checked first (PAT-2105):
    a cross-site page must not be able to mint tokens against the
    platform's per-tenant rate limit. Admin only (PAT-2407), checked here
    before the platform is asked, in the same position as the estate key
    create below; the platform enforces the same thing server-side."""
    _, refusal = await _guarded_form(request, "install_enrolment")
    if refusal is not None:
        return refusal
    try:
        role = await run_in_threadpool(_portal_role, request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if role != "admin":
        return _approval_refusal(request, 403, INSTALL_TOKEN_ADMIN_ONLY)
    try:
        data = await run_in_threadpool(
            upstream.post_json, "/v1/portal/enrolment", request.state.jwt,
            {"delivery_path": "mdm"})
    except upstream.UpstreamError as exc:
        if exc.kind == "forbidden":
            try:
                body = json.loads(exc.body) if exc.body else {}
            except ValueError:
                body = {}
            if isinstance(body, dict) and body.get("error") == "admin_role_required":
                # Role changed between page load and submit.
                return _approval_refusal(request, 403, INSTALL_TOKEN_ADMIN_ONLY)
        return _error_page(request, exc)
    token = data.get("enrollment_token", "") if isinstance(data, dict) else ""
    if not token:
        return _error_page(request, upstream.UpstreamError(
            "error", "upstream returned no enrollment_token"))
    expires_at = data.get("expires_at") if isinstance(data, dict) else None
    token_id = data.get("token_id") if isinstance(data, dict) else None
    generated_on = datetime.now(UTC).strftime("%Y-%m-%d")
    context = await run_in_threadpool(_install_shared_context, request.state.jwt)
    return _render(request, "install.html", {
        "title": "Install the agent", "nav": "install",
        "token": token,
        "token_id": token_id,
        "expires_at": expires_at,
        "macos_script": _macos_enrolment_script(token, generated_on),
        "windows_cmd": _windows_enrolment_cmd(token),
        **context,
    })


@app.post("/install/enrolment-keys", response_class=HTMLResponse)
async def install_enrolment_key_create(request: Request):
    """PAT-2251: create a reusable estate enrolment key
    (contracts/portal-api.md "Tenant enrolment keys"). Admin only, guarded
    like every other write here (_guarded_form: size cap, then Origin, then
    CSRF; role checked here before the platform is asked, which enforces
    the same thing server-side). The plaintext is returned exactly once,
    directly in this response - never via a redirect, a flash, a query
    string or the session - with Cache-Control: no-store and Pragma:
    no-cache, matching the Jamf webhook token create (PAT-2145)."""
    form, refusal = await _guarded_form(request, "install_enrolment_key_create")
    if refusal is not None:
        return refusal
    try:
        role = await run_in_threadpool(_portal_role, request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if role != "admin":
        return _approval_refusal(
            request, 403,
            "Only an administrator on your account can create an estate enrolment key.")
    payload, error = _parse_enrolment_key_create_form(form)
    if error:
        return _approval_refusal(request, 400, error)
    try:
        data = await run_in_threadpool(
            upstream.post_json, "/v1/portal/enrolment-keys", request.state.jwt, payload)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    key = data.get("enrollment_key", "") if isinstance(data, dict) else ""
    if not key:
        return _error_page(request, upstream.UpstreamError(
            "error", "upstream returned no enrollment_key"))
    context = await run_in_threadpool(_install_shared_context, request.state.jwt)
    resp = _render(request, "install.html", {
        "title": "Install the agent", "nav": "install",
        "key_reveal": {
            "label": data.get("label") if isinstance(data.get("label"), str) else payload["label"],
            "key_hint": data.get("key_hint") if isinstance(data.get("key_hint"), str) else "",
            "max_devices": data.get("max_devices") if type(data.get("max_devices")) is int
                else payload["max_devices"],
            "expires_at": data.get("expires_at"),
            "enrollment_key": key,
        },
        **context,
    })
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.post("/install/enrolment-keys/{key_id}/revoke", response_class=HTMLResponse)
async def install_enrolment_key_revoke(request: Request, key_id: str):
    """PAT-2251: revoke an estate enrolment key. Admin only, same guard
    order as every other write (_guarded_form, then role). New enrolments
    against the key are refused from the moment this commits; devices
    already enrolled keep their credentials (contracts/portal-api.md). The
    confirm step lives in the template as a no-JS <details>/<summary>
    disclosure, the same idiom the Jamf webhook token revoke uses."""
    form, refusal = await _guarded_form(request, "install_enrolment_key_revoke")
    if refusal is not None:
        return refusal
    try:
        role = await run_in_threadpool(_portal_role, request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if role != "admin":
        return _approval_refusal(
            request, 403,
            "Only an administrator on your account can revoke an estate enrolment key.")
    try:
        result = await run_in_threadpool(
            upstream.post_json,
            f"/v1/portal/enrolment-keys/{quote(key_id, safe='')}/revoke",
            request.state.jwt, None)
    except upstream.UpstreamError as exc:
        if exc.kind == "auth":
            return _session_expired_response(request, "upstream")
        return _install_redirect(
            request, _install_error_payload(exc, "revoke an estate enrolment key"))
    changed = bool(result.get("changed")) if isinstance(result, dict) else False
    notice = "Estate enrolment key revoked." if changed else "That key was already revoked."
    return _install_redirect(request, {"notice": notice})


def _support_context(request: Request, value) -> tuple[str, str | None]:
    """Resolve a known portal page; device context needs a fresh scoped read.

    Query strings and fragments are deliberately omitted. Only the canonical
    route is sent on the existing wire, never a client-supplied device name,
    identity, tenant or actor. The device label is display-only.
    """
    path = urlsplit(_feedback_route(value)).path
    for registered in app.routes:
        if "GET" not in (getattr(registered, "methods", None) or set()):
            continue
        if getattr(registered, "response_class", None) != HTMLResponse:
            continue
        match = registered.path_regex.fullmatch(path)
        if not match:
            continue
        params = match.groupdict()
        if "device_id" in params:
            data = upstream.get_json(
                f"/v1/portal/devices/{quote(params['device_id'], safe='')}", request.state.jwt,
            )
            device = data.get("device", data) if isinstance(data, dict) else None
            if (not isinstance(device, dict) or not isinstance(device.get("hostname"), str)
                    or not device["hostname"]):
                raise upstream.UpstreamError("unavailable", status=502)
            return path, device["hostname"]
        if not params:
            return path, None
    return "/", None


def _support_page(
    request: Request, *, route: str = "/", draft: dict | None = None,
    error: str | None = None, status_code: int = 200,
) -> HTMLResponse:
    context_error = None
    try:
        route, device_name = _support_context(request, route)
    except upstream.UpstreamError as exc:
        if exc.kind in {"auth", "forbidden"}:
            return _error_page(request, exc)
        route, device_name = "/", None
        context_error = "Device context is unavailable. Include its name in your description."
    rows, list_error, available = [], None, False
    try:
        data = upstream.get_json("/v1/portal/feedback", request.state.jwt, {"door": "support"})
        rows, available = _feedback_rows(data), True
    except upstream.UpstreamError as exc:
        if exc.kind in {"auth", "forbidden"}:
            return _error_page(request, exc)
        list_error = "Support requests are unavailable. Please try again or email us."
    _remember_feedback_availability(request.state.jwt, available)
    subject = quote("Support request via the Patched portal")
    email = request.state.identity["email"]
    body = quote(f"Signed in as: {email}\n\nHow can we help?\n")
    return _render(request, "support.html", {
        "title": "Support", "nav": "support", "feedback_available": available,
        "mailto": f"mailto:{SUPPORT_EMAIL}?subject={subject}&body={body}",
        "support_route": route, "support_device_name": device_name,
        "support_context_error": context_error, "support_draft": draft,
        "support_error": error, "support_list_error": list_error,
        "support_rows": rows,
        "support_sent": request.query_params.get("sent") == "1",
    }, status_code=status_code)


@app.get("/support", response_class=HTMLResponse)
def support(request: Request, route: str = "/"):
    return _support_page(request, route=route)


def _feedback_rows(data) -> list[dict]:
    """Normalise the platform's tenant-scoped feedback list for rendering."""
    rows = data if isinstance(data, list) else (
        data.get("feedback", data.get("requests", [])) if isinstance(data, dict) else []
    )
    if not isinstance(rows, list):
        return []
    result = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        status = row.get("status") if isinstance(row.get("status"), str) else ""
        result.append({
            "reference": row.get("reference") if isinstance(row.get("reference"), str) else "-",
            "type": FEEDBACK_TYPE_LABELS.get(str(row.get("type", "")), "Feedback"),
            "title": row.get("title") if isinstance(row.get("title"), str) else "Untitled feedback",
            "status": FEEDBACK_STATUS_LABELS.get(status, "Status update"),
            "created_at": row.get("created_at"),
            "last_status_change": row.get("last_status_change"),
        })
    return result


def _feedback_error_message(exc: upstream.UpstreamError) -> str:
    if exc.kind == "rate_limited":
        return "You have sent several feedback items recently. Please wait a moment and try again."
    if exc.kind == "unavailable":
        return "We could not reach the Patched platform. Your feedback may not have been sent."
    if exc.kind == "invalid":
        try:
            body = json.loads(exc.body) if exc.body else {}
        except ValueError:
            body = {}
        message = body.get("message") if isinstance(body, dict) else None
        if isinstance(message, str) and message.strip():
            return message.strip()[:300]
        return "Please check the feedback details and try again."
    return "The Patched platform could not accept that feedback. Please try again."


@app.get("/requests", response_class=HTMLResponse)
def feedback_requests(request: Request):
    """Customer-visible feedback state is read directly from the platform."""
    try:
        data = upstream.get_json("/v1/portal/feedback", request.state.jwt, {"door": "feedback"})
    except upstream.UpstreamError as exc:
        if exc.kind == "not_found":
            _remember_feedback_availability(request.state.jwt, False)
            # Feedback is disabled on this platform. Return to a working page
            # without turning an optional feature into an error screen.
            return RedirectResponse(url="/", status_code=303)
        return _error_page(request, exc)
    _remember_feedback_availability(request.state.jwt, True)
    return _render(request, "feedback_requests.html", {
        "title": "Feedback", "nav": "requests", "feedback_available": True,
        "feedback_rows": _feedback_rows(data),
        # PAT-2216: landing after a no-JavaScript submission. A fixed notice,
        # so nothing from the URL is ever rendered.
        "feedback_sent": request.query_params.get("sent") == "1",
    })


def _feedback_wants_json(request: Request) -> bool:
    """The modal's fetch asks for JSON; a plain browser form post does not."""
    return "application/json" in (request.headers.get("accept") or "").lower()


def _feedback_route(value) -> str:
    """A same-site path for the form's route field and Cancel link, never a
    URL: anything else (another origin, a protocol-relative or backslash
    path a browser would treat as one) falls back to the Overview."""
    if (
        isinstance(value, str) and value.startswith("/") and not value.startswith("//")
        and "\\" not in value and len(value) <= 2000 and not _CONTROL_CHARS_RE.search(value)
    ):
        return value
    return "/"


def _feedback_draft(form) -> dict:
    """The customer's own typed values, handed back after a refusal. Only
    rendered through autoescaped template fields; bounded by the upload cap."""
    def text(name: str) -> str:
        value = form.get(name) if form is not None else None
        return value if isinstance(value, str) else ""
    feedback_type = text("type")
    return {
        "type": feedback_type if feedback_type in FEEDBACK_TYPES else "feature",
        "category": text("category") if text("category") in SUPPORT_CATEGORIES else "not_working",
        "title": text("title"),
        "description": text("description"),
    }


def _feedback_page(
    request: Request, *, route: str = "/", draft: dict | None = None,
    error: str | None = None, status_code: int = 200,
) -> HTMLResponse:
    return _render(request, "feedback.html", {
        "title": "Feedback", "nav": "requests", "feedback_available": True,
        "feedback_page": True, "feedback_route": route,
        "feedback_draft": draft, "feedback_error": error,
    }, status_code=status_code)


@app.get("/feedback", response_class=HTMLResponse)
async def feedback_form_page(request: Request, route: str = "/"):
    """PAT-2216: the feedback form as a page, for a browser without
    JavaScript (the header link lands here; feedback.js opens the modal)."""
    try:
        available = await run_in_threadpool(_feedback_is_available, request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if not available:
        return RedirectResponse(url="/", status_code=303)
    return _feedback_page(request, route=_feedback_route(route))


@app.post("/feedback")
async def submit_feedback(request: Request):
    return await _submit_feedback_door(request, "feedback")


@app.post("/support")
async def submit_support(request: Request):
    return await _submit_feedback_door(request, "support")


async def _submit_feedback_door(request: Request, door: str):
    """Both doors share the existing bounded, authenticated multipart intake."""
    wants_json = _feedback_wants_json(request)
    form, refusal = await _guarded_feedback_form(request)

    async def reply(status: int, message: str, **extra) -> Response:
        if door == "support":
            message = message.replace("your feedback", "your support request").replace(
                "Send feedback", "Send support request")
        if wants_json:
            return JSONResponse({"error": message, **extra}, status_code=status)
        render = _support_page if door == "support" else _feedback_page
        return await run_in_threadpool(
            render, request, route=_feedback_route(form.get("route") if form is not None else None),
            draft=_feedback_draft(form), error=message, status_code=status,
        )

    if refusal is not None:
        if refusal.expired:
            jwt_token = getattr(request.state, "jwt", "") or ""
            extra = {"csrf_token": _csrf_token(jwt_token)} if jwt_token else {}
            return await reply(refusal.status, refusal.message, **extra)
        if wants_json:
            return JSONResponse({"error": refusal.message}, status_code=refusal.status)
        return _approval_refusal(request, refusal.status, refusal.message)

    feedback_type = form.get("type")
    title = form.get("title")
    description = form.get("description")
    route = form.get("route")
    category = form.get("category")
    if door == "support":
        if (feedback_type != "support" or not isinstance(category, str)
                or category not in SUPPORT_CATEGORIES):
            return await reply(422, "Choose a support category.")
        # A description-only form still satisfies the backend's title contract.
        summary = " ".join(description.split()) if isinstance(description, str) else ""
        title = ("Support: " + summary)[:FEEDBACK_TITLE_MAX_CHARS]
    elif feedback_type not in FEEDBACK_TYPES or category not in (None, ""):
        return await reply(422, "Choose Feature request or Design or usability.")
    if (
        not isinstance(title, str)
        or not FEEDBACK_TITLE_MIN_CHARS <= len(title.strip()) <= FEEDBACK_TITLE_MAX_CHARS
    ):
        return await reply(422, "Title must be between 5 and 120 characters.")
    if (
        not isinstance(description, str)
        or not 1 <= len(description.strip()) <= FEEDBACK_DESCRIPTION_MAX_CHARS
    ):
        return await reply(422, "Description must be between 1 and 5,000 characters.")
    if not isinstance(route, str) or _feedback_route(route) != route:
        return await reply(422, "The page route could not be read. Reload and try again.")

    fields = {
        "type": feedback_type,
        "title": title.strip(),
        "description": description.strip(),
        "route": route,
    }
    if door == "support":
        try:
            validated_route, _ = await run_in_threadpool(_support_context, request, route)
        except upstream.UpstreamError as exc:
            if exc.kind in {"auth", "forbidden"}:
                return _error_page(request, exc)
            return await reply(
                502, "Device context is unavailable. Your request has not been sent.")
        if validated_route != urlsplit(route).path:
            return await reply(422, "That page context is unavailable. Open Support again.")
        fields["route"] = validated_route
        fields["category"] = category
    # Neither current door uses severity. Never forward stale bug selections.

    screenshot = form.get("screenshot")
    upload = None
    if screenshot is not None and getattr(screenshot, "filename", ""):
        content_type = getattr(screenshot, "content_type", "")
        if content_type not in FEEDBACK_ALLOWED_SCREENSHOT_TYPES:
            return await reply(422, "Attach a PNG or JPEG screenshot, or remove it.")
        raw = await screenshot.read(FEEDBACK_SCREENSHOT_MAX_BYTES + 1)
        if len(raw) > FEEDBACK_SCREENSHOT_MAX_BYTES:
            return await reply(413, "Screenshots up to 5 MiB are accepted.")
        filename = Path(str(screenshot.filename)).name or "screenshot"
        upload = (filename, raw, content_type)

    try:
        result = await run_in_threadpool(
            upstream.post_multipart, "/v1/portal/feedback", request.state.jwt, fields, upload,
            PORTAL_BUILD, request.headers.get("user-agent", ""),
        )
    except upstream.UpstreamError as exc:
        if exc.kind == "auth":
            return _session_expired_response(request, "upstream")
        if exc.kind == "not_found":
            _remember_feedback_availability(request.state.jwt, False)
            return await reply(
                502, "Submissions are unavailable. Your typed details are still here.")
        logger.warning("portal.feedback.upstream_refused kind=%s status=%s", exc.kind, exc.status)
        status = 429 if exc.kind == "rate_limited" else 502
        return await reply(status, _feedback_error_message(exc))

    reference = result.get("reference") if isinstance(result, dict) else None
    if not isinstance(reference, str) or not reference:
        return await reply(502, "The Patched platform did not confirm a feedback reference.")
    _remember_feedback_availability(request.state.jwt, True)
    if not wants_json:
        destination = "/support" if door == "support" else "/requests"
        return RedirectResponse(url=f"{destination}?sent=1", status_code=303)
    return JSONResponse({"reference": reference}, status_code=201)


# ── AI Tooling (PAT-2022) ────────────────────────────────────────────────
# The product list and collection state are separate platform contracts:
# tagged-products says which observed identities are recognised as AI;
# ai-tooling/summary and /devices say whether each collector block was read.
# Never turn a failed/not_reported collector into a zero, and never parse the
# tagged endpoint's opaque product_key to manufacture an approval identity.
AI_TOOLING_TYPES = {
    "desktop_app": "Desktop app",
    "browser_extension": "Browser extension",
    "ide_extension": "IDE plugin",
    "cli": "CLI",
    "local_runtime": "Local runtime",
    "mcp_server": "MCP server",
}
AI_TOOLING_BLOCKS = (
    ("ide_extensions", "IDE plugins"),
    ("package_managers", "CLI packages"),
    ("local_models", "Local models"),
    ("mcp_servers", "MCP servers"),
)
AI_TOOLING_ITEM_BLOCKS = {block for block, _label in AI_TOOLING_BLOCKS} | {
    "desktop_apps", "browser_extensions",
}
AI_TOOLING_ITEM_POLICY_STATES = {
    "approved", "unapproved", "unreviewed", "ignored", "mandatory",
}
AI_TOOLING_STATUS_LABELS = {
    "complete": "Read completely",
    "partial": "Partially read",
    "not_present": "None reported",
    "failed": "Could not be read",
    "not_reported": "Not yet reported",
}
AI_TOOLING_CVE_IDENTITY = {
    "ide_extension": ("ide_extension", None),
    "npm_package": ("package", "npm"),
    "pip_package": ("package", "PyPI"),
    "local_model_runtime": ("local_runtime", None),
    "mcp_server": ("mcp_server", None),
}
AI_TOOLING_CSV_PAGE_SIZE = 1000
AI_TOOLING_DEVICE_LIST_PAGE_SIZE = 25
AI_TOOLING_IDENTITY_LOCK = (
    "The platform has not supplied an exact approval identity for this row, "
    "so it cannot be changed safely here yet."
)

# PAT-2213: the Products card's filter bar - a Type/State/Assessment
# multi-select dropdown each (data-row-filter="ai_type"/"ai_state"/
# "ai_vulnerability", matching the row attributes tests already assert on),
# replacing the three rows of segmented tabs (17 buttons, most (0) - Andy,
# live, 2026-09-28). State options mirror the four tabs the page already
# exposed (unreviewed/unapproved/approved/ignored); mandatory/mixed rows
# have no tab of their own and remain visible only under "All". Assessment
# stays the same binary split (has findings / none) the old "All
# assessments"/"With findings" pair already used.
AI_TOOLING_STATE_FILTER_OPTIONS = (
    ("unreviewed", "Unreviewed"),
    ("unapproved", "Unapproved"),
    ("approved", "Approved"),
    ("ignored", "Ignored"),
)
AI_TOOLING_STATE_FILTER_LABELS = dict(AI_TOOLING_STATE_FILTER_OPTIONS)
AI_TOOLING_ASSESSMENT_FILTER_OPTIONS = (
    ("has", "With findings"),
    ("none", "No findings recorded"),
)
AI_TOOLING_ASSESSMENT_FILTER_LABELS = dict(AI_TOOLING_ASSESSMENT_FILTER_OPTIONS)


def _ai_nonnegative_int(value, default=0):
    return value if type(value) is int and value >= 0 else default


def _ai_vulnerability_products(raw) -> list | None:
    if not isinstance(raw, list):
        return None
    for row in raw:
        if not isinstance(row, dict):
            return None
        state = row.get("state")
        finding_count = row.get("finding_count")
        highest = row.get("highest_severity")
        valid_state = (
            (state == "assessed" and type(finding_count) is int and finding_count >= 0)
            or (state in ("pending", "not_assessed")
                and finding_count is None and highest is None)
        )
        if not all((
            isinstance(row.get("subject_kind"), str) and bool(row["subject_kind"]),
            row.get("ecosystem") is None or isinstance(row.get("ecosystem"), str),
            isinstance(row.get("identity"), str) and bool(row["identity"]),
            isinstance(row.get("source"), str),
            isinstance(row.get("version"), str) and bool(row["version"]),
            valid_state,
            row.get("reason") is None or isinstance(row.get("reason"), str),
            highest is None or isinstance(highest, str),
            type(row.get("device_count")) is int and row["device_count"] >= 0,
            isinstance(row.get("advisory_sources"), list)
            and all(isinstance(source, str) for source in row["advisory_sources"]),
        )):
            return None
    return raw


def _ai_summary_view(raw: dict) -> dict:
    statuses = raw.get("collection_status")
    statuses = statuses if isinstance(statuses, dict) else {}
    collection = {}
    for block, label in AI_TOOLING_BLOCKS:
        source = statuses.get(block)
        available = isinstance(source, dict) and all(
            type(source.get(status)) is int and source.get(status) >= 0
            for status in AI_TOOLING_STATUS_LABELS
        )
        collection[block] = {
            "label": label, "available": available,
            **{
                status: source.get(status) if available else None
                for status in AI_TOOLING_STATUS_LABELS
            },
        }
    local = raw.get("local_models") if isinstance(raw.get("local_models"), dict) else {}
    models = local.get("models") if isinstance(local.get("models"), dict) else {}
    mcp = raw.get("mcp_servers") if isinstance(raw.get("mcp_servers"), dict) else {}
    return {
        "device_count": _ai_nonnegative_int(raw.get("device_count"), None),
        "devices_with_tooling": _ai_nonnegative_int(raw.get("devices_with_tooling"), None),
        "collection": collection,
        "local_model_devices": _ai_nonnegative_int(models.get("devices"), None),
        "local_model_bytes": local.get("total_bytes")
        if type(local.get("total_bytes")) is int and local.get("total_bytes") >= 0 else None,
        "local_model_lower_bound_devices": _ai_nonnegative_int(
            local.get("lower_bound_devices"), None),
        "mcp_devices": _ai_nonnegative_int(mcp.get("devices"), None),
        "vulnerability_products": _ai_vulnerability_products(
            raw.get("vulnerability_products")),
        "generated_at": raw.get("generated_at"),
    }


def _ai_assessment_unavailable(reason=None) -> dict:
    return {
        "state": "unavailable", "label": "Assessment unavailable",
        "pill_class": "pill-muted", "count": None, "severity": None,
        "filter": "none", "reason": reason, "coverage_incomplete": True,
    }


def _ai_cve_view(
    product: dict, vulnerability_products: list, snapshots_consistent: bool = True,
) -> dict:
    """Conservatively join PAT-2109 exact-version assessment rows to a
    tagged product. A missing or ambiguous join is unavailable, never a
    clean zero. The platform does not currently expose grouped AI-product
    CVE state, so this is limited to the subject kinds whose exact identity
    is present in both response contracts."""
    target = product.get("approval_target")
    identity_kind = target.get("identity_kind") if isinstance(target, dict) else None
    identity_spec = AI_TOOLING_CVE_IDENTITY.get(identity_kind)
    identity = target.get("name") if isinstance(target, dict) else None
    source = target.get("source") if isinstance(target, dict) else None
    raw_versions = product.get("versions")
    if (not identity_spec or not isinstance(identity, str) or not identity
            or not isinstance(source, str) or target.get("type") != "observation"
            or not isinstance(raw_versions, list) or not raw_versions
            or any(not isinstance(v, str) or not v for v in raw_versions)
            or len(set(raw_versions)) != len(raw_versions)
            or not isinstance(vulnerability_products, list)):
        return _ai_assessment_unavailable()

    subject, ecosystem = identity_spec
    by_version = {version: [] for version in raw_versions}
    for row in vulnerability_products:
        if not isinstance(row, dict):
            continue
        if (row.get("subject_kind") != subject or row.get("ecosystem") != ecosystem
                or row.get("identity") != identity or row.get("source") != source):
            continue
        if row.get("version") in by_version:
            by_version[row["version"]].append(row)
    if any(len(rows) != 1 for rows in by_version.values()):
        return _ai_assessment_unavailable("Assessment coverage did not match product versions")
    matches = [by_version[version][0] for version in raw_versions]

    for row in matches:
        state = row.get("state")
        if state == "assessed":
            if type(row.get("finding_count")) is not int or row["finding_count"] < 0:
                return _ai_assessment_unavailable("Malformed assessed finding count")
        elif state in ("pending", "not_assessed"):
            if row.get("finding_count") is not None or row.get("highest_severity") is not None:
                return _ai_assessment_unavailable("Malformed incomplete assessment")
        else:
            return _ai_assessment_unavailable("Unrecognised assessment state")

    assessed = [row for row in matches if row["state"] == "assessed"]
    finding_rows = [row for row in assessed if row["finding_count"] > 0]
    known_count = sum(row["finding_count"] for row in finding_rows)
    severities = [str(row.get("highest_severity") or "").lower() for row in finding_rows]
    severities = [s for s in severities if s in SEVERITY_ORDER]
    severity = min(severities, key=lambda s: SEVERITY_ORDER[s]) if severities else None
    incomplete_state = (
        "pending" if any(row["state"] == "pending" for row in matches)
        else "not_assessed" if any(row["state"] == "not_assessed" for row in matches)
        else None
    )
    if not snapshots_consistent and not known_count and not incomplete_state:
        return _ai_assessment_unavailable("Assessment and product snapshots differ")

    if known_count and len(finding_rows) > 1:
        label = f"Vulnerability findings on {len(finding_rows)} versions"
        pill_class = f"pill-{severity}" if severity else "pill-bad"
        display_count = None
    elif known_count:
        label = f"{known_count} vulnerability finding{'' if known_count == 1 else 's'}"
        if severity:
            label += f" ({severity.capitalize()})"
        pill_class = f"pill-{severity}" if severity else "pill-bad"
        display_count = known_count
    elif incomplete_state:
        label = "Pending" if incomplete_state == "pending" else "Not assessed"
        pill_class = "pill-warn" if incomplete_state == "pending" else "pill-muted"
        display_count = None
    else:
        label, pill_class = "No known vulnerability findings", "pill-ok"
        display_count = 0
    if incomplete_state and known_count:
        label += " · Assessment incomplete"
    elif not snapshots_consistent and known_count:
        label += " · Assessment snapshot incomplete"
    return {
        "state": incomplete_state or ("unavailable" if not snapshots_consistent else "assessed"),
        "label": label, "pill_class": pill_class,
        "count": display_count, "severity": severity,
        "filter": "has" if known_count else "none",
        "reason": next((row.get("reason") for row in matches
                        if row["state"] == incomplete_state), None),
        "coverage_incomplete": bool(incomplete_state) or not snapshots_consistent,
    }


def _ai_approval_target(product: dict) -> dict | None:
    """Return only the server-supplied decision target, narrowed to the
    strict portal write shape. No product field or opaque key is used to
    manufacture a fallback identity."""
    target = product.get("approval_target")
    if not isinstance(target, dict):
        return None
    kind = target.get("type")
    fields = {
        "application": ("platform", "identifier", "team_id"),
        "browser_extension": ("browser", "extension_id"),
        "observation": ("identity_kind", "name", "source"),
    }.get(kind)
    if fields is None:
        return None
    candidate = {"type": kind}
    for field in fields:
        if target.get(field) is not None:
            candidate[field] = target[field]
    parsed = _parse_approval_item(candidate)
    return parsed[0] if parsed else None


def _ai_approval_view(product: dict) -> dict:
    name = product.get("name") if isinstance(product.get("name"), str) else ""
    state = "ignored" if product.get("approval_state") == "unmanaged" else product.get(
        "approval_state")
    if state not in APPROVAL_STATE_LABELS:
        state = None
    if product.get("approval_state") == "mixed":
        view = _approval_view(name, None, None, (
            "This product resolves to different approval states across the estate. "
            "Review its exact identities in Software before changing it."
        ))
        view["approval_state_label"] = "Mixed"
        return view
    if state == "mandatory":
        return _approval_view(name, None, state, MANDATORY_LOCK)
    item = _ai_approval_target(product)
    if not item:
        return _approval_view(name, None, state or "unreviewed", AI_TOOLING_IDENTITY_LOCK)
    # Observation `name` is the policy identity, not a display-only field.
    approval_name = item["name"] if item["type"] == "observation" else name
    return _approval_view(approval_name, item, state or "unreviewed", None)


def _ai_product_valid(product) -> bool:
    if not isinstance(product, dict):
        return False
    versions = product.get("versions")
    platforms = product.get("platforms")
    devices = product.get("devices")
    user_count = product.get("user_count")
    target = product.get("approval_target")
    metering_fields = (
        "metered_installation_count", "unmetered_installation_count",
        "stale_metering_installation_count", "unknown_metering_installation_count",
    )
    if ("last_used_at" not in product
            or product.get("last_used_at") is not None
            and not isinstance(product.get("last_used_at"), str)
            or any(type(product.get(field)) is not int or product[field] < 0
                   for field in metering_fields)):
        return False
    metering_state = product.get("metering_state")
    if product.get("subtype") == "desktop_app":
        if metering_state not in ("metered", "partial", "stale", "unmetered", "unknown"):
            return False
        if metering_state != "metered" and product.get("last_used_at") is not None:
            return False
        if (metering_state == "metered"
                and (product["metered_installation_count"] == 0
                     or any(product[field] for field in metering_fields[1:]))):
            return False
        if (metering_state == "partial"
                and (product["metered_installation_count"] == 0
                     or product["stale_metering_installation_count"] != 0
                     or (product["unmetered_installation_count"] == 0
                         and product["unknown_metering_installation_count"] == 0))):
            return False
        if (metering_state == "stale"
                and product["stale_metering_installation_count"] == 0):
            return False
        if (metering_state == "unmetered"
                and (product["unmetered_installation_count"] == 0
                     or product["metered_installation_count"] != 0
                     or product["stale_metering_installation_count"] != 0
                     or product["unknown_metering_installation_count"] != 0)):
            return False
        if (metering_state == "unknown"
                and (product["unknown_metering_installation_count"] == 0
                     or product["metered_installation_count"] != 0
                     or product["stale_metering_installation_count"] != 0)):
            return False
    elif (metering_state != "not_applicable" or product.get("last_used_at") is not None
          or any(product[field] for field in metering_fields)):
        return False
    return all((
        product.get("category") == "ai_tooling",
        product.get("subtype") in AI_TOOLING_TYPES,
        isinstance(product.get("observation_kind"), str),
        isinstance(product.get("product_key"), str) and bool(product["product_key"]),
        isinstance(product.get("name"), str) and bool(product["name"]),
        product.get("canonical_name") is None
        or isinstance(product.get("canonical_name"), str),
        product.get("vendor") is None or isinstance(product.get("vendor"), str),
        product.get("observed_publisher") is None
        or isinstance(product.get("observed_publisher"), str),
        isinstance(product.get("identifier"), str),
        product.get("browser") is None or isinstance(product.get("browser"), str),
        isinstance(platforms, list) and all(isinstance(v, str) for v in platforms),
        isinstance(versions, list) and all(isinstance(v, str) and v for v in versions),
        len(versions) == len(set(versions)) if isinstance(versions, list) else False,
        type(product.get("version_count")) is int and product["version_count"] >= 0,
        product.get("version_count") == len(versions) if isinstance(versions, list) else False,
        type(product.get("device_count")) is int and product["device_count"] >= 0,
        isinstance(devices, list) and all(isinstance(v, str) and v for v in devices),
        len(devices) == len(set(devices)) if isinstance(devices, list) else False,
        len(devices) <= product.get("device_count", -1)
        if isinstance(devices, list) else False,
        isinstance(product.get("devices_truncated"), bool),
        product.get("devices_truncated") is True
        or len(devices) == product.get("device_count")
        if isinstance(devices, list) else False,
        user_count is None or (type(user_count) is int and user_count >= 0),
        isinstance(product.get("first_seen"), str) and bool(product["first_seen"]),
        isinstance(product.get("last_seen"), str) and bool(product["last_seen"]),
        product.get("approval_state") in (
            "approved", "unapproved", "mandatory", "ignored", "unmanaged",
            "unreviewed", "mixed",
        ),
        isinstance(product.get("match_basis"), list)
        and all(isinstance(v, str) and v for v in product["match_basis"]),
        target is None or (isinstance(target, dict) and _ai_approval_target(product) is not None),
    ))


def _ai_page(data, key: str, requested_limit: int, requested_offset: int,
             row_validator) -> tuple[list, int]:
    if not isinstance(data, dict):
        raise upstream.UpstreamError("error", f"invalid AI tooling {key} response")
    rows = data.get(key)
    total, limit, offset = data.get("total"), data.get("limit"), data.get("offset")
    if (not isinstance(data.get("generated_at"), str) or not data["generated_at"]
            or not isinstance(rows, list) or type(total) is not int or total < 0
            or type(limit) is not int or limit != requested_limit
            or type(offset) is not int or offset != requested_offset
            or len(rows) > limit or offset + len(rows) > total
            or any(not row_validator(row) for row in rows)):
        raise upstream.UpstreamError("error", f"invalid AI tooling {key} response")
    expected = min(limit, max(total - offset, 0))
    if len(rows) != expected:
        raise upstream.UpstreamError("error", f"incomplete AI tooling {key} response")
    return rows, total


def _ai_products_page(
    data, requested_limit: int, requested_offset: int,
) -> tuple[list, int, int, bool]:
    rows, total = _ai_page(
        data, "products", requested_limit, requested_offset, _ai_product_valid)
    distinct = data.get("distinct_device_total")
    estate_too_large = data.get("estate_too_large")
    if (data.get("category") != "ai_tooling" or data.get("subtype") is not None
            or type(distinct) is not int or distinct < 0
            or not isinstance(estate_too_large, bool)):
        raise upstream.UpstreamError("error", "invalid AI tooling product totals")
    return rows, total, distinct, estate_too_large


def _ai_last_used_view(product: dict) -> dict:
    state = product["metering_state"]
    value = product.get("last_used_at")
    if state == "not_applicable":
        return {"state": state, "value": None, "label": "Not collected"}
    if state == "metered":
        return {
            "state": state, "value": value,
            "label": None if value else "No launch recorded",
        }
    labels = {
        "partial": "Partial metering coverage",
        "stale": "Metering evidence is stale",
        "unmetered": "Metering unavailable",
        "unknown": "Metering not reported",
    }
    return {"state": state, "value": value, "label": labels[state]}


def _ai_product_row(
    product: dict, vulnerability_products: list,
    assessment_snapshots_consistent: bool = False,
) -> dict:
    subtype = product.get("subtype") if product.get("subtype") in AI_TOOLING_TYPES else ""
    platforms = product.get("platforms") if isinstance(product.get("platforms"), list) else []
    versions = product.get("versions") if isinstance(product.get("versions"), list) else []
    row = {
        "product_key": product["product_key"],
        "name": product.get("name") or "(unnamed)",
        "type": subtype, "type_label": AI_TOOLING_TYPES.get(subtype, "Other AI tooling"),
        "vendor": product.get("vendor") or product.get("observed_publisher") or "Not verified",
        "vendor_verified": bool(product.get("vendor")),
        "versions": [v for v in versions if isinstance(v, str) and v],
        "version_count": _ai_nonnegative_int(product.get("version_count")),
        "device_count": _ai_nonnegative_int(product.get("device_count")),
        "user_count": _ai_nonnegative_int(product.get("user_count"), None),
        "platforms": [p for p in platforms if isinstance(p, str)],
        "first_seen": product.get("first_seen"), "last_seen": product.get("last_seen"),
        "last_used": _ai_last_used_view(product),
        "raw": product,
    }
    row.update(_ai_approval_view(product))
    raw_state = product.get("approval_state")
    row["approval_filter"] = "ignored" if raw_state == "unmanaged" else (
        raw_state or "unreviewed")
    row["assessment"] = _ai_cve_view(
        product, vulnerability_products, assessment_snapshots_consistent)
    return row


def _ai_device_block(raw, block: str) -> dict:
    def unavailable():
        return {
            "status": "unavailable", "status_label": "Collection unavailable",
            "count": None, "lower_bound": False, "reported_at": None,
            **({"runtime_count": None, "total_bytes": None}
               if block == "local_models" else {}),
        }

    source = raw if isinstance(raw, dict) else None
    if source is None:
        return unavailable()
    status = source.get("collection_status")
    units, items_by_unit = source.get("units"), source.get("items_by_unit")
    authoritative = status in ("complete", "partial", "not_present")
    count = source.get("item_count")
    valid_count = (
        type(count) is int and count >= 0 if authoritative else count is None)
    if (status not in AI_TOOLING_STATUS_LABELS or not isinstance(units, dict)
            or not isinstance(items_by_unit, dict)
            or not isinstance(source.get("lower_bound"), bool)
            or not valid_count
            or not (source.get("reported_at") is None
                    or isinstance(source.get("reported_at"), str))):
        return unavailable()
    view = {
        "status": status, "status_label": AI_TOOLING_STATUS_LABELS[status],
        "count": count, "lower_bound": bool(source.get("lower_bound")),
        "reported_at": source.get("reported_at"),
    }
    if block == "local_models":
        runtime_count, total_bytes = (
            source.get("runtime_installation_count"), source.get("total_bytes"))
        valid_runtime = (
            type(runtime_count) is int and runtime_count >= 0
            and type(total_bytes) is int and total_bytes >= 0
            if authoritative else runtime_count is None and total_bytes is None
        )
        if not valid_runtime:
            return unavailable()
        view["runtime_count"], view["total_bytes"] = runtime_count, total_bytes
    return view


def _ai_device_valid(raw) -> bool:
    return bool(
        isinstance(raw, dict)
        and isinstance(raw.get("device_id"), str) and raw["device_id"]
        and isinstance(raw.get("hostname"), str) and raw["hostname"]
        and isinstance(raw.get("platform"), str) and raw["platform"]
    )


def _ai_device_row(raw: dict) -> dict:
    return {
        "device_id": raw.get("device_id") or "", "hostname": raw.get("hostname") or "(unknown)",
        "platform": raw.get("platform") or "unknown",
        "ide_extensions": _ai_device_block(raw.get("ide_extensions"), "ide_extensions"),
        "package_managers": _ai_device_block(raw.get("package_managers"), "package_managers"),
        "local_models": _ai_device_block(raw.get("local_models"), "local_models"),
        "mcp_servers": _ai_device_block(raw.get("mcp_servers"), "mcp_servers"),
    }


def _ai_item_assessment_identity_matches(item: dict, assessment: dict) -> bool:
    identity_kind = item.get("identity_kind")
    expected_version = item.get("version") or "unknown"
    if item.get("block") == "mcp_servers":
        if assessment.get("subject_kind") == "mcp_server":
            return all((
                assessment.get("ecosystem") is None,
                assessment.get("identity") == item.get("identity"),
                assessment.get("source") == item.get("source"),
                assessment.get("version") == expected_version,
            ))
        package_pairs = {("npm", "npm"), ("PyPI", "PyPI")}
        return all((
            item.get("package_status") == "extracted",
            isinstance(item.get("package"), str) and bool(item["package"]),
            assessment.get("subject_kind") == "package",
            (assessment.get("ecosystem"), assessment.get("source")) in package_pairs,
            assessment.get("identity") == item.get("package"),
            assessment.get("version") == expected_version,
        ))
    identity_specs = {
        "npm_package": ("package", "npm", "npm"),
        "pip_package": ("package", "PyPI", "PyPI"),
        "ide_extension": ("ide_extension", None, item.get("source")),
        "local_model_runtime": ("local_runtime", None, item.get("source")),
    }
    spec = identity_specs.get(identity_kind)
    return bool(spec and all((
        assessment.get("subject_kind") == spec[0],
        assessment.get("ecosystem") == spec[1],
        assessment.get("identity") == item.get("identity"),
        assessment.get("source") == spec[2],
        assessment.get("version") == expected_version,
    )))


def _ai_item_assessment_valid(item: dict, assessment: dict) -> bool:
    if not isinstance(assessment, dict) or not _ai_item_assessment_identity_matches(
        item, assessment,
    ):
        return False
    state, count, severity = (
        assessment.get("state"), assessment.get("finding_count"),
        assessment.get("highest_severity"),
    )
    if state == "assessed":
        if type(count) is not int or count < 0 or not isinstance(severity, (str, type(None))):
            return False
    elif state in ("pending", "not_assessed"):
        if count is not None or severity is not None:
            return False
    else:
        return False
    reason = assessment.get("unsupported_reason")
    if reason is not None and not isinstance(reason, str):
        return False
    provenance = assessment.get("evidence_provenance")
    if not isinstance(provenance, dict) or not all((
        provenance.get("item_id") == item.get("item_id"),
        provenance.get("input_observed_at") == item.get("observed_at"),
        _parse_utc(provenance.get("input_observed_at")) is not None,
        isinstance(provenance.get("fresh"), bool),
        provenance.get("assessed_at") is None
        or _parse_utc(provenance.get("assessed_at")) is not None,
        provenance.get("fresh_until") is None
        or _parse_utc(provenance.get("fresh_until")) is not None,
    )):
        return False
    if state == "assessed" and not all((
        provenance["fresh"], provenance.get("assessed_at"), provenance.get("fresh_until"),
    )):
        return False
    advisories = assessment.get("advisories")
    if not isinstance(advisories, list) or (state != "assessed" and advisories):
        return False
    advisory_keys = set()
    for advisory in advisories:
        if not isinstance(advisory, dict):
            return False
        source, advisory_id = advisory.get("source"), advisory.get("advisory_id")
        canonical, score = advisory.get("canonical_cve_id"), advisory.get("score")
        key = (source, advisory_id)
        if not all((
            isinstance(source, str) and bool(source),
            isinstance(advisory_id, str) and bool(advisory_id),
            key not in advisory_keys,
            canonical is None or isinstance(canonical, str)
            and re.fullmatch(r"CVE-\d{4}-\d{4,}", canonical.upper()),
            advisory.get("severity") is None
            or isinstance(advisory.get("severity"), str),
            score is None or type(score) in (int, float),
            advisory.get("published_at") is None
            or _parse_utc(advisory.get("published_at")) is not None,
            advisory.get("modified_at") is None
            or _parse_utc(advisory.get("modified_at")) is not None,
            _parse_utc(advisory.get("synced_at")) is not None,
        )):
            return False
        advisory_keys.add(key)
    return state != "assessed" or len(advisories) == count


def _ai_item_assessment_view(item: dict) -> dict:
    raw = item.get("assessments")
    if not isinstance(raw, list):
        return _ai_assessment_unavailable()
    if not raw:
        return {
            "state": "not_assessed", "label": "Not assessed",
            "pill_class": "pill-muted", "count": None, "severity": None,
            "filter": "none", "cve_aliases": [], "coverage_incomplete": True,
        }
    known_count, finding_rows, severities, cve_aliases = 0, 0, [], []
    incomplete_state = None
    identities = set()
    for assessment in raw:
        if not _ai_item_assessment_valid(item, assessment):
            return _ai_assessment_unavailable()
        identity = (
            assessment["subject_kind"], assessment.get("ecosystem"),
            assessment["identity"], assessment["source"], assessment["version"],
        )
        if identity in identities:
            return _ai_assessment_unavailable()
        identities.add(identity)
        state, count = assessment.get("state"), assessment.get("finding_count")
        if state == "assessed":
            if type(count) is not int or count < 0:
                return _ai_assessment_unavailable()
            if count:
                known_count += count
                finding_rows += 1
                severity = str(assessment.get("highest_severity") or "").lower()
                if severity in SEVERITY_ORDER:
                    severities.append(severity)
        elif state in ("pending", "not_assessed"):
            if count is not None or assessment.get("highest_severity") is not None:
                return _ai_assessment_unavailable()
            if state == "pending" or incomplete_state is None:
                incomplete_state = state
        else:
            return _ai_assessment_unavailable()
        advisories = assessment["advisories"]
        for advisory in advisories:
            if not isinstance(advisory, dict):
                return _ai_assessment_unavailable()
            alias = advisory.get("canonical_cve_id")
            if isinstance(alias, str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", alias.upper()):
                cve_aliases.append(alias.upper())
    severity = min(severities, key=lambda value: SEVERITY_ORDER[value]) if severities else None
    if known_count:
        label = (f"{known_count} vulnerability finding{'' if known_count == 1 else 's'}"
                 if finding_rows == 1 else f"Vulnerability findings in {finding_rows} assessments")
        if severity:
            label += f" ({severity.capitalize()})"
        if incomplete_state:
            label += " · Assessment incomplete"
        return {
            "state": incomplete_state or "assessed", "label": label,
            "pill_class": f"pill-{severity}" if severity else "pill-bad",
            "count": known_count if finding_rows == 1 else None, "severity": severity,
            "filter": "has", "cve_aliases": sorted(set(cve_aliases)),
            "coverage_incomplete": bool(incomplete_state),
        }
    if incomplete_state:
        return {
            "state": incomplete_state,
            "label": "Pending" if incomplete_state == "pending" else "Not assessed",
            "pill_class": "pill-warn" if incomplete_state == "pending" else "pill-muted",
            "count": None, "severity": None, "filter": "none",
            "cve_aliases": [], "coverage_incomplete": True,
        }
    return {
        "state": "assessed", "label": "No known vulnerability findings",
        "pill_class": "pill-ok", "count": 0, "severity": None,
        "filter": "none", "cve_aliases": [], "coverage_incomplete": False,
    }


def _ai_item_valid(item) -> bool:
    if not isinstance(item, dict):
        return False
    target = item.get("approval_target")
    assessments = item.get("assessments")
    block = item.get("block")
    collection_status = item.get("collection_status")
    if block in ("desktop_apps", "browser_extensions"):
        if collection_status != "current" or item.get("lower_bound") is not False:
            return False
        # The platform's ToolingEvidenceItem omits a null last_used_at.
        if (item.get("last_used_at") is not None
                and not isinstance(item.get("last_used_at"), str)):
            return False
        if block == "desktop_apps":
            if item.get("metering_state") not in ("metered", "stale", "unmetered", "unknown"):
                return False
            if item.get("metering_state") != "metered" and item.get("last_used_at") is not None:
                return False
        elif item.get("metering_state") != "not_applicable" or item.get("last_used_at") is not None:
            return False
    elif collection_status not in AI_TOOLING_STATUS_LABELS:
        return False
    return all((
        isinstance(item.get("item_id"), str) and bool(item["item_id"]),
        isinstance(item.get("device_id"), str) and bool(item["device_id"]),
        isinstance(item.get("hostname"), str) and bool(item["hostname"]),
        isinstance(item.get("platform"), str) and bool(item["platform"]),
        block in AI_TOOLING_ITEM_BLOCKS,
        isinstance(item.get("unit"), str),
        isinstance(item.get("entry_kind"), str) and bool(item["entry_kind"]),
        collection_status in (*AI_TOOLING_STATUS_LABELS, "current"),
        isinstance(item.get("lower_bound"), bool),
        isinstance(item.get("identity_kind"), str) and bool(item["identity_kind"]),
        isinstance(item.get("identity"), str) and bool(item["identity"]),
        isinstance(item.get("source"), str),
        isinstance(item.get("name"), str) and bool(item["name"]),
        item.get("version") is None or isinstance(item.get("version"), str),
        item.get("publisher") is None or isinstance(item.get("publisher"), str),
        isinstance(item.get("observed_at"), str) and bool(item["observed_at"]),
        item.get("policy_state") in AI_TOOLING_ITEM_POLICY_STATES,
        target is None or (isinstance(target, dict)
                           and _ai_approval_target({"approval_target": target}) is not None),
        isinstance(assessments, list),
    ))


def _ai_item_row(item: dict) -> dict:
    details = []
    if item["block"] == "mcp_servers":
        for label, field in (
            ("Transport", "transport"), ("Executable", "runner"),
            ("Package", "package"), ("Host", "host"),
        ):
            value = item.get(field)
            if isinstance(value, str) and value:
                details.append((label, value))
    elif item["block"] == "local_models":
        for label, field in (
            ("Runtime", "runtime"), ("Model", "model_tag"), ("Format", "model_format"),
        ):
            value = item.get(field)
            if isinstance(value, str) and value:
                details.append((label, value))
        if type(item.get("size_bytes")) is int and item["size_bytes"] >= 0:
            details.append(("Size", item["size_bytes"]))
    elif item["block"] == "ide_extensions":
        for label, field in (
            ("Editor", "editor"), ("Editor version", "editor_version"),
            ("Marketplace", "marketplace_source"),
        ):
            value = item.get(field)
            if isinstance(value, str) and value:
                details.append((label, value))
    elif item["block"] == "package_managers":
        for label, field in (("Manager", "package_manager"), ("Scope", "scope")):
            value = item.get(field)
            if isinstance(value, str) and value:
                details.append((label, value))
    product = {
        "name": item["name"], "approval_state": item.get("policy_state"),
        "approval_target": item.get("approval_target"),
    }
    return {
        **item, "details": details, "assessment": _ai_item_assessment_view(item),
        "last_used": _ai_last_used_view(item)
        if item["block"] in ("desktop_apps", "browser_extensions")
        else {"state": "not_applicable", "value": None, "label": "Not collected"},
        **_ai_approval_view(product),
    }


def _ai_all_not_reported(summary: dict) -> bool:
    total = summary["device_count"]
    return type(total) is int and total > 0 and all(
        summary["collection"][block]["available"]
        and summary["collection"][block]["not_reported"] == total
        for block, _label in AI_TOOLING_BLOCKS
    )


def _ai_notification_view(raw) -> dict | None:
    if not isinstance(raw, dict):
        return None
    if (not isinstance(raw.get("new_software_enabled"), bool)
            or not isinstance(raw.get("ai_tooling_notifications_enabled"), bool)):
        return None
    views = {}
    expected_events = {
        "new_software": "software.first_seen",
        "ai_tooling": "ai_tooling.first_seen",
    }
    for key, expected_event in expected_events.items():
        channel = raw.get(key)
        if (not isinstance(channel, dict) or channel.get("event") != expected_event
                or type(channel.get("channels")) is not int or channel["channels"] < 0
                or type(channel.get("digest_hour_utc")) is not int
                or not 0 <= channel["digest_hour_utc"] <= 23):
            return None
        views[key] = {
            "event": channel["event"], "channels": channel["channels"],
            "digest_hour_utc": channel["digest_hour_utc"],
        }
    return {
        "new_software_enabled": raw["new_software_enabled"],
        "ai_tooling_notifications_enabled": raw["ai_tooling_notifications_enabled"],
        **views,
    }


def _ai_notification_flash_view(raw: dict | None) -> dict | None:
    """Both the older single-setting save (`notification_setting`, a bare
    string) and PAT-2213's combined-card save (`notification_settings`, a
    list) flash into the same generic "Notification setting saved" banner
    (templates/ai_tooling.html, templates/software_report_new.html) - the
    banner text never names which setting(s), so both shapes just need to
    resolve to something truthy here."""
    if not isinstance(raw, dict):
        return None
    setting = raw.get("notification_setting")
    if setting in ("ai_tooling", "new_software"):
        return {"setting": setting}
    settings = raw.get("notification_settings")
    if (isinstance(settings, list) and settings
            and all(s in ("ai_tooling", "new_software") for s in settings)):
        return {"settings": settings}
    return None


def _ai_tooling_multiselect(request: Request, param: str, valid_keys) -> list[str]:
    """Parses `?{param}=` the same way `_software_approval_filter` parses
    `?approval=` (PAT-2163): one or more comma-joined values, or several
    same-named params (a plain HTML form with several checked boxes of the
    same name posts one per box - this reads both the same way). An
    unrecognised value (a stale bookmark, a hand-edited URL) is silently
    dropped, never reflected back and never used to filter. Order is the
    order given, de-duplicated on its second occurrence, matching the order
    a chip removes them in."""
    raw_values = [v for v in request.query_params.getlist(param) if v.strip()]
    selected: list[str] = []
    for raw in raw_values:
        for part in raw.split(","):
            part = part.strip()
            if part in valid_keys and part not in selected:
                selected.append(part)
    return selected


def _ai_tooling_filter_bar_view(
    request: Request, type_filter: list[str], state_filter: list[str],
    assessment_filter: list[str], type_counts: dict, state_counts: dict,
    finding_product_count: int, total_products: int, type_labels: dict | None = None,
) -> dict:
    """Shared AI review filters: URL state, removable chips and muted zero
    options. Rows remain rendered, with server-side hidden classes matching
    portal.js, so a filtered link also works before JavaScript or without it.
    Counts describe the loaded product list (or the named device page).
    """
    search = request.query_params.get("search", "").strip()[:200]
    type_labels = type_labels or AI_TOOLING_TYPES
    not_assessed_count = max(0, total_products - finding_product_count)
    assessment_counts = {"has": finding_product_count, "none": not_assessed_count}

    FILTER_PARAMS = ("type", "state", "findings", "search", APPROVAL_RESULT_PARAM,
                     "notification_result")
    kept = [
        (k, v) for k, v in request.query_params.multi_items()
        if k not in FILTER_PARAMS
    ]

    def build_url(next_type: list[str], next_state: list[str], next_assessment: list[str],
                  next_search: str = search) -> str:
        params = list(kept)
        if next_type:
            params.append(("type", ",".join(next_type)))
        if next_state:
            params.append(("state", ",".join(next_state)))
        if next_assessment:
            params.append(("findings", ",".join(next_assessment)))
        if next_search:
            params.append(("search", next_search))
        query = urlencode(params)
        return request.url.path + (f"?{query}" if query else "")

    def build_options(pairs, counts: dict, selected: list[str]) -> list[dict]:
        return [
            {"value": key, "label": label, "count": counts.get(key, 0),
             "selected": key in selected, "muted": counts.get(key, 0) == 0}
            for key, label in pairs
        ]

    type_options = build_options(type_labels.items(), type_counts, type_filter)
    state_options = build_options(
        AI_TOOLING_STATE_FILTER_OPTIONS, state_counts, state_filter)
    assessment_options = build_options(
        AI_TOOLING_ASSESSMENT_FILTER_OPTIONS, assessment_counts, assessment_filter)

    chips = []
    for value in type_filter:
        chips.append({
            "label": type_labels.get(value, value),
            "remove_url": build_url(
                [v for v in type_filter if v != value], state_filter, assessment_filter),
        })
    for value in state_filter:
        chips.append({
            "label": AI_TOOLING_STATE_FILTER_LABELS.get(value, value),
            "remove_url": build_url(
                type_filter, [v for v in state_filter if v != value], assessment_filter),
        })
    for value in assessment_filter:
        chips.append({
            "label": AI_TOOLING_ASSESSMENT_FILTER_LABELS.get(value, value),
            "remove_url": build_url(
                type_filter, state_filter, [v for v in assessment_filter if v != value]),
        })

    if search:
        chips.append({"label": "Search: " + search,
                      "remove_url": build_url(type_filter, state_filter, assessment_filter, "")})

    return {
        "type_options": type_options,
        "state_options": state_options,
        "assessment_options": assessment_options,
        "chips": chips,
        "clear_url": build_url([], [], [], "") if chips else None,
        "search": search,
        "hidden_fields": [{"name": k, "value": v} for k, v in kept
                          if k in ("offset", "device_offset")],
        "multi_filters": [
            {"name": "type", "row_filter": "ai_type", "label": "Type",
             "options": type_options},
            {"name": "state", "row_filter": "ai_state", "label": "Approval",
             "options": state_options},
            {"name": "findings", "row_filter": "ai_vulnerability", "label": "Assessment",
             "options": assessment_options},
        ],
    }



def _ai_review_rows(request: Request, rows: list[dict], *, device: bool = False) -> dict:
    """Presentation only. Keep the platform's approval, assessment and
    collection claims intact while supplying the shared review components.
    Search and filter classes mirror the shared browser predicates.
    """
    type_labels = {**AI_TOOLING_TYPES, **({"local_model": "Local model"} if device else {})}
    types = _ai_tooling_multiselect(request, "type", type_labels)
    states = _ai_tooling_multiselect(request, "state", AI_TOOLING_STATE_FILTER_LABELS)
    assessments = _ai_tooling_multiselect(request, "findings", AI_TOOLING_ASSESSMENT_FILTER_LABELS)
    search = request.query_params.get("search", "").strip()[:200].lower()
    block_types = {"desktop_apps": "desktop_app", "browser_extensions": "browser_extension",
                   "ide_extensions": "ide_extension", "package_managers": "cli",
                   "local_models": "local_runtime", "mcp_servers": "mcp_server"}
    for row in rows:
        row.setdefault("type", "local_model" if row.get("entry_kind") == "model"
                       else block_types.get(row.get("block"), ""))
        # Local models are model evidence, not a claim that a runtime was installed.
        row.setdefault("type_label", "Local model" if row.get("entry_kind") == "model"
                       else AI_TOOLING_TYPES.get(row["type"], "Other AI tooling"))
        row.setdefault("approval_filter", row.get("approval_state") or "unreviewed")
        row["state_label"] = row.get("approval_state_label") or "Unreviewed"
        row["state_class"] = "pill-state--" + {
            "approved": "approved", "unapproved": "unapproved", "ignored": "ignored",
            "unreviewed": "unreviewed",
        }.get(row["approval_filter"], "unknown")
        row["state_title"] = row.get("approval_lock") or ""
        assessment = row["assessment"]
        count = assessment.get("count")
        if assessment["filter"] == "has":
            label = (f"{count} finding{'' if count == 1 else 's'}"
                     if count is not None else "Findings")
            if assessment.get("coverage_incomplete"):
                label += " · Incomplete"
            elif assessment.get("severity"):
                label += " · " + assessment["severity"].capitalize()
        else:
            label = {"unavailable": "Unavailable", "assessed": "No known findings"}.get(
                assessment["state"], assessment["label"])
        row["assessment_label"] = label
        # Evidence identity is independent of approval identity: locked rows have
        # no target, and distinct versions can share one target. The namespace
        # and upstream key keep anchors stable through reordering/pagination.
        basis = json.dumps(["ai-item" if device else "ai-product",
                            row["item_id"] if device else row["product_key"]])
        row["row_id"] = "sw-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]
        values = [row["name"], row["type_label"], row.get("vendor", ""),
                  row.get("source", ""), row.get("identity", ""),
                  row.get("version", "") or "", " ".join(row.get("versions", [])),
                  " ".join(row.get("platforms", [])), row.get("platform", "")]
        row["search_text"] = " ".join(values).lower()
        row["hidden_filter"] = bool(
            types and row["type"] not in types
            or states and row["approval_filter"] not in states
            or assessments and row["assessment"]["filter"] not in assessments)
        row["hidden_search"] = bool(search and search not in row["search_text"])
    visible = [r for r in rows if not r["hidden_filter"] and not r["hidden_search"]]
    for index, row in enumerate(visible):
        row["next_row_id"] = visible[min(index + 1, len(visible) - 1)]["row_id"]
    bar = _ai_tooling_filter_bar_view(
        request, types, states, assessments,
        {key: sum(r["type"] == key for r in rows) for key in type_labels},
        {key: sum(r["approval_filter"] == key for r in rows)
         for key in AI_TOOLING_STATE_FILTER_LABELS},
        sum(r["assessment"]["filter"] == "has" for r in rows), len(rows), type_labels)
    bar["visible_count"] = len(visible)
    return bar



def _ai_page_url(request: Request, parameter: str, offset: int, anchor: str = "") -> str:
    params = [(k, v) for k, v in request.query_params.multi_items()
              if k not in (parameter, APPROVAL_RESULT_PARAM, "notification_result")]
    params.append((parameter, str(offset)))
    return "?" + urlencode(params) + anchor


def _ai_local_ai_support(runtime_count: int, local_model_devices, mcp_devices) -> str:
    """The Local AI tile's secondary line (PAT-2213), folding the old
    separate "Local models"/"MCP servers" KPI tiles into one. Andy's
    complaint on this ticket: "Local models 0 devices next to Products
    Local runtimes (1) reads as a contradiction unless it says a runtime is
    installed with no models pulled" - so that exact case (a runtime
    product is recognised, but no device has reported a local model file
    yet) gets its own plain-English clause rather than a bare "0 models"
    that reads like the runtime doesn't exist. Every figure here is a real
    count already computed elsewhere on this page (runtime_count from the
    Products type tally, local_model_devices/mcp_devices from the
    platform's own summary) - nothing is invented (root AGENTS.md: CVE and
    usage claims require evidence; this generalises to any figure)."""
    if local_model_devices is None or mcp_devices is None:
        return "Local AI coverage is temporarily unavailable"
    runtime_word = "runtime" if runtime_count == 1 else "runtimes"
    if runtime_count > 0 and local_model_devices == 0:
        models_clause = "no models pulled yet"
    else:
        device_word = "device" if local_model_devices == 1 else "devices"
        models_clause = f"models on {local_model_devices} {device_word}"
    mcp_word = "device" if mcp_devices == 1 else "devices"
    return (
        f"{runtime_count} {runtime_word} installed · {models_clause} · "
        f"MCP servers on {mcp_devices} {mcp_word}"
    )


def _ai_summary_tiles(
    summary: dict, type_counts: dict, products_claim_available: bool,
) -> list[dict]:
    """Authoritative summary values and links, now rendered as a compact
    line (PAT-2243). Keep missing counts unavailable and zero counts muted;
    supporting coverage explanations remain below the product list.
    """
    def tile(key, label, value, href, support=None, *, lower_bound=False, warn_on_value=False):
        available = value is not None
        if not available:
            headline, zero = "Unavailable", False
        elif lower_bound and value:
            headline, zero = f"At least {value}", False
        else:
            headline, zero = str(value), value == 0
        return {
            "key": key, "label": label, "headline": headline, "zero": zero,
            "warn": bool(available and value and warn_on_value), "href": href,
            "support": support,
        }

    lower_bound = bool(summary.get("product_counts_are_lower_bounds"))
    runtime_count = type_counts.get("local_runtime", 0) + type_counts.get("mcp_server", 0)
    if not products_claim_available:
        runtime_count = None
    distinct_products = summary.get("distinct_products")
    coverage_support = (
        f"{distinct_products} distinct product{'' if distinct_products == 1 else 's'}"
        if distinct_products is not None else "Distinct product count unavailable"
    )
    local_ai_support = _ai_local_ai_support(
        runtime_count if runtime_count is not None else 0,
        summary.get("local_model_devices"), summary.get("mcp_devices"),
    ) if runtime_count is not None else "Local AI coverage is temporarily unavailable"

    return [
        tile(
            "unreviewed", "Unreviewed", summary.get("unreviewed_count"),
            "/ai-tooling?state=unreviewed#products", lower_bound=lower_bound,
            warn_on_value=True,
        ),
        tile(
            "unapproved", "Unapproved", summary.get("unapproved_count"),
            "/ai-tooling?state=unapproved#products", lower_bound=lower_bound,
            warn_on_value=True,
        ),
        tile(
            "coverage", "Devices with AI tooling", summary.get("devices_with_tooling"),
            "#devices", support=coverage_support,
        ),
        tile(
            "local_ai", "Local runtimes", runtime_count,
            "/ai-tooling?type=local_runtime,mcp_server#products", support=local_ai_support,
        ),
    ]


@app.get("/ai-tooling", response_class=HTMLResponse)
def ai_tooling(request: Request):
    try:
        device_offset = int(request.query_params.get("device_offset", "0"))
        if device_offset < 0:
            raise ValueError
    except ValueError:
        return _approval_refusal(request, 400, "That device page offset is not valid.")
    try:
        raw_summary = upstream.get_json("/v1/portal/ai-tooling/summary", request.state.jwt)
    except upstream.UpstreamError as exc:
        if exc.kind == "not_found":
            return _render(request, "ai_tooling.html", {
                "title": "AI Tooling", "nav": "ai-tooling", "available": False,
            })
        return _error_page(request, exc)
    if not isinstance(raw_summary, dict):
        return _error_page(request, upstream.UpstreamError("error", "invalid AI tooling summary"))
    summary = _ai_summary_view(raw_summary)

    raw_products = None
    products, products_error, products_total, estate_too_large = None, False, 0, False
    distinct_device_total = None
    try:
        data = upstream.get_json("/v1/portal/tagged-products", request.state.jwt,
                                 params={"category": "ai_tooling", "limit": 1000})
        raw_products, products_total, distinct_device_total, estate_too_large = (
            _ai_products_page(data, 1000, 0))
    except upstream.UpstreamError as exc:
        logger.warning("portal.ai_tooling.products_fail_soft kind=%s", exc.kind)
        products_error = True

    if raw_products is not None:
        products = [
            _ai_product_row(
                p, summary["vulnerability_products"],
                False,
            )
            for p in raw_products
        ]

    devices, devices_error, devices_total = None, False, 0
    try:
        data = upstream.get_json("/v1/portal/ai-tooling/devices", request.state.jwt,
                                 params={"limit": AI_TOOLING_DEVICE_LIST_PAGE_SIZE,
                                         "offset": device_offset})
        raw_devices, devices_total = _ai_page(
            data, "devices", AI_TOOLING_DEVICE_LIST_PAGE_SIZE, device_offset,
            _ai_device_valid)
        devices = [_ai_device_row(d) for d in raw_devices]
    except upstream.UpstreamError as exc:
        logger.warning("portal.ai_tooling.devices_fail_soft kind=%s", exc.kind)
        devices_error = True

    try:
        role = _portal_role(request.state.jwt)
        role_unavailable = False
    except upstream.UpstreamError as exc:
        logger.warning("portal.ai_tooling.role_fail_soft kind=%s", exc.kind)
        role, role_unavailable = "viewer", True
    can_edit = role == "admin"

    notifications, notifications_error = None, False
    try:
        notifications = _ai_notification_view(upstream.get_json(
            "/v1/portal/software-notifications", request.state.jwt))
        if notifications is None:
            raise upstream.UpstreamError("error", "invalid software notification settings")
    except upstream.UpstreamError as exc:
        logger.warning("portal.ai_tooling.notifications_fail_soft kind=%s", exc.kind)
        notifications_error = True

    rows = products or []
    products_claim_available = not products_error and not estate_too_large
    product_counts_are_lower_bounds = bool(
        products_claim_available and products is not None and products_total > len(products)
    )
    summary.update({
        "distinct_products": products_total if products_claim_available else None,
        "unreviewed_count": (
            sum(1 for p in rows if p["approval_filter"] == "unreviewed")
            if products_claim_available else None
        ),
        "unapproved_count": (
            sum(1 for p in rows if p["approval_filter"] == "unapproved")
            if products_claim_available else None
        ),
        "product_counts_are_lower_bounds": product_counts_are_lower_bounds,
        "distinct_device_total": (
            distinct_device_total if products_claim_available else None),
    })


    type_counts = {key: sum(1 for p in rows if p["type"] == key) for key in AI_TOOLING_TYPES}
    state_counts = {
        key: sum(1 for p in rows if p["approval_filter"] == key)
        for key in ("unreviewed", "unapproved", "approved", "ignored", "mandatory", "mixed")
    }
    finding_product_count = sum(1 for p in rows if p["assessment"]["filter"] == "has")
    empty_state = None
    if products is not None and not products and not estate_too_large:
        empty_state = "not_reported" if _ai_all_not_reported(summary) else "none_found"
    export_available = bool(
        products is not None and not products_error and not estate_too_large
        and products_total <= AI_TOOLING_CSV_PAGE_SIZE
    )

    filter_bar = _ai_review_rows(request, rows)
    summary_tiles = _ai_summary_tiles(summary, type_counts, products_claim_available)
    for tile in summary_tiles:
        if tile["key"] == "coverage":
            tile["href"] = _ai_page_url(request, "device_offset", 0, "#devices")

    return _render(request, "ai_tooling.html", {
        "title": "AI Tooling", "nav": "ai-tooling", "available": True,
        "summary": summary, "products": products, "products_error": products_error,
        "products_total": products_total, "estate_too_large": estate_too_large,
        "export_available": export_available,
        "devices": devices, "devices_error": devices_error, "devices_total": devices_total,
        "device_offset": device_offset,
        "device_collection_open": "device_offset" in request.query_params,
        "device_previous_url": _ai_page_url(request, "device_offset",
                                           max(0, device_offset - AI_TOOLING_DEVICE_LIST_PAGE_SIZE),
                                           "#devices"),
        "device_next_url": _ai_page_url(request, "device_offset",
                                       device_offset + len(devices or []), "#devices"),
        "device_previous_offset": max(
            0, device_offset - AI_TOOLING_DEVICE_LIST_PAGE_SIZE)
        if devices is not None and device_offset else None,
        "device_next_offset": device_offset + len(devices)
        if devices is not None and device_offset + len(devices) < devices_total else None,
        "type_counts": type_counts, "state_counts": state_counts,
        "finding_product_count": finding_product_count,
        "ai_filter_bar": filter_bar, "summary_tiles": summary_tiles,
        "coverage_gaps": any(not c["available"] or any(c.get(k) for k in
                             ("partial", "failed", "not_reported"))
                             for c in summary["collection"].values()),
        "empty_state": empty_state, "can_edit": can_edit,
        "role_unavailable": role_unavailable,
        "notifications": notifications, "notifications_error": notifications_error,
        "notification_saved": _ai_notification_flash_view(_read_flash(
            request.state.jwt, request.query_params.get("notification_result", ""))),
        "csrf_token": _csrf_token(request.state.jwt) if can_edit else "",
        "return_to": _approval_return_to(
            request.url.path + ("?" + request.url.query if request.url.query else "")),
        "approval_result": _approval_flash_view(_read_flash(
            request.state.jwt, request.query_params.get(APPROVAL_RESULT_PARAM, ""))),
    })


AI_TOOLING_DEVICE_PAGE_SIZE = 100


def _ai_tooling_device_csv_spec(device_id: str) -> _ProxiedCsv:
    return _ProxiedCsv(
        "ai-tooling-device",
        f"/v1/portal/ai-tooling/devices/{quote(device_id, safe='')}/items", {},
        "patched-ai-tooling-device.csv", [("Device", device_id)])


@app.get("/ai-tooling/devices/{device_id}.csv")
def ai_tooling_device_csv(request: Request, device_id: str):
    return _proxied_csv_response(request, _ai_tooling_device_csv_spec(device_id))


@app.get("/ai-tooling/devices/{device_id}.pdf")
def ai_tooling_device_pdf(request: Request, device_id: str):
    """PAT-2405: the same rows as the device CSV, as a PDF."""
    return _proxied_csv_pdf_response(request, _ai_tooling_device_csv_spec(device_id))


@app.get("/ai-tooling/devices/{device_id}", response_class=HTMLResponse)
def ai_tooling_device(request: Request, device_id: str):
    try:
        offset = int(request.query_params.get("offset", "0"))
        if offset < 0:
            raise ValueError
    except ValueError:
        return _approval_refusal(request, 400, "That page offset is not valid.")
    try:
        data = upstream.get_json(
            f"/v1/portal/ai-tooling/devices/{quote(device_id, safe='')}/items",
            request.state.jwt, params={"limit": AI_TOOLING_DEVICE_PAGE_SIZE, "offset": offset})
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    try:
        if not isinstance(data, dict) or data.get("device_id") != device_id:
            raise upstream.UpstreamError("error", "invalid AI tooling device identity")
        raw_items, total = _ai_page(
            data, "items", AI_TOOLING_DEVICE_PAGE_SIZE, offset,
            lambda item: _ai_item_valid(item) and item.get("device_id") == device_id)
        if len({item["hostname"] for item in raw_items}) > 1:
            raise upstream.UpstreamError(
                "error", "conflicting hostnames in AI tooling device items")
    except upstream.UpstreamError as exc:
        logger.warning("portal.ai_tooling_device.invalid_evidence reason=%s", exc)
        return _render(request, "error.html", {
            "title": "AI tooling evidence could not be verified",
            "message": "The platform returned incomplete or inconsistent AI tooling "
                       "evidence for this device. No items are shown. "
                       f"Please try again later or contact {SUPPORT_EMAIL}.",
        }, status_code=502)
    items = [_ai_item_row(item) for item in raw_items]
    hostname = items[0]["hostname"] if items else device_id
    role_unavailable = False
    try:
        role = _portal_role(request.state.jwt)
    except upstream.UpstreamError:
        role = "viewer"
        role_unavailable = True
    filter_bar = _ai_review_rows(request, items, device=True)
    return _render(request, "ai_tooling_device.html", {
        "title": f"AI Tooling · {hostname}", "nav": "ai-tooling",
        "device_id": device_id, "hostname": hostname, "items": items,
        "ai_filter_bar": filter_bar, "role_unavailable": role_unavailable,
        "total": total, "offset": offset, "limit": AI_TOOLING_DEVICE_PAGE_SIZE,
        "previous_url": _ai_page_url(
            request, "offset", max(0, offset - AI_TOOLING_DEVICE_PAGE_SIZE)),
        "next_url": _ai_page_url(request, "offset", offset + AI_TOOLING_DEVICE_PAGE_SIZE),
        "previous_offset": max(0, offset - AI_TOOLING_DEVICE_PAGE_SIZE) if offset else None,
        "next_offset": offset + AI_TOOLING_DEVICE_PAGE_SIZE
        if offset + len(items) < total else None,
        "can_edit": role == "admin", "csrf_token": _csrf_token(request.state.jwt)
        if role == "admin" else "", "return_to": _approval_return_to(
            request.url.path + ("?" + request.url.query if request.url.query else "")),
        "approval_result": _approval_flash_view(_read_flash(
            request.state.jwt, request.query_params.get(APPROVAL_RESULT_PARAM, ""))),
    })


AI_NOTIFICATION_SETTINGS = {
    "ai_tooling_notifications_enabled": "ai_tooling",
    "new_software_enabled": "new_software",
}
AI_NOTIFICATION_SETTINGS_BY_KEY = {v: k for k, v in AI_NOTIFICATION_SETTINGS.items()}
AI_NOTIFICATION_RESULT_PARAM = "notification_result"

# PAT-2010: the New Software report's own settings card posts through this
# exact route (reusing the /ai-tooling toggle code path rather than a second
# copy), so the save must be able to return to either page. Deliberately an
# EXACT-match allowlist, not safe_return_to()/_approval_return_to()'s
# path-prefix-plus-query style: a client-supplied value here gets no benefit
# of the doubt at all - anything other than one of these two literal strings
# (an absolute URL, a protocol-relative "//host", a backslash trick, or this
# same path with a smuggled query string) falls back to "/ai-tooling", the
# toggle's original, unconditional destination.
NOTIFICATION_RETURN_PATHS = ("/ai-tooling", "/reports/new-software")


def _notification_return_to(raw: str) -> str:
    return raw if raw in NOTIFICATION_RETURN_PATHS else "/ai-tooling"


@app.post("/ai-tooling/notifications")
async def ai_tooling_notifications(request: Request):
    form, refusal = await _guarded_form(request, "ai_tooling.notifications")
    if refusal:
        return refusal
    assert form is not None

    # PAT-2213: the AI Tooling page's own notifications card now saves both
    # settings from one Save button (one POST) instead of the older
    # one-row-one-form-one-Save shape ("two saves for one form", Andy's
    # complaint on this ticket) - a `settings` marker field (comma list)
    # plus one `enabled_<key>` checkbox per setting. The New Software
    # report's own settings card (templates/software_report_new.html,
    # PAT-2010) still posts the original one-setting-at-a-time shape
    # (`setting` + `enabled`) unchanged below it - both shapes share this
    # one route, distinguished by which marker field is present, so
    # neither caller's contract moved.
    if "settings" in form:
        return await _ai_tooling_notifications_multi(request, form)

    if set(form) - {CSRF_FIELD, "setting", "enabled", "return_to"}:
        return _approval_refusal(request, 400, "That notification setting is not valid.")
    setting_values, enabled_values = form.get("setting", []), form.get("enabled", [])
    return_to_values = form.get("return_to", [])
    if (len(setting_values) != 1 or setting_values[0] not in AI_NOTIFICATION_SETTINGS
            or len(enabled_values) > 1
            or (enabled_values and enabled_values[0] != "on")
            or len(return_to_values) > 1):
        return _approval_refusal(request, 400, "That notification setting is not valid.")
    return_to = _notification_return_to(return_to_values[0] if return_to_values else "")
    try:
        if _portal_role(request.state.jwt) != "admin":
            return _approval_refusal(
                request, 403,
                "Only an administrator on your account can change notification settings.")
        setting = setting_values[0]
        result = upstream.put_json(
            "/v1/portal/software-notifications", request.state.jwt,
            {setting: bool(enabled_values)})
        if _ai_notification_view(result) is None:
            raise upstream.UpstreamError("error", "invalid notification update response")
    except upstream.UpstreamError as exc:
        if exc.kind == "auth":
            return _session_expired_response(request, "upstream")
        if exc.kind == "forbidden":
            return _approval_refusal(
                request, 403,
                "Only an administrator on your account can change notification settings.")
        return _approval_refusal(
            request, 502, "Notification settings could not be saved. Nothing was changed.")
    saved = AI_NOTIFICATION_SETTINGS[setting]
    flash = _sign_flash(request.state.jwt, {"notification_setting": saved})
    separator = "&" if "?" in return_to else "?"
    return RedirectResponse(
        url=(f"{return_to}{separator}{AI_NOTIFICATION_RESULT_PARAM}="
             f"{quote(flash, safe='')}#notifications"),
        status_code=303)


async def _ai_tooling_notifications_multi(request: Request, form: dict):
    """PAT-2213: the AI Tooling page's combined notifications card - one
    Save button, one POST, both settings. `settings` names which raw keys
    this particular form covers (always both, from the card's own two
    checkboxes today); each is saved with its own sequential
    `PUT /v1/portal/software-notifications` call, one raw key per call,
    exactly the shape `AI_NOTIFICATION_SETTINGS`'s single-setting path
    above already sends - so this stays a portal-side convenience over an
    unchanged upstream contract, never a new multi-key PUT this repo has
    no way to confirm the platform accepts. A partial failure (the first
    call succeeds, the second 5xxs) must not claim nothing changed, so the
    refusal says only the earlier settings may have been saved and asks the
    customer to check the card."""
    allowed = {CSRF_FIELD, "settings", "return_to"} | {
        f"enabled_{key}" for key in AI_NOTIFICATION_SETTINGS_BY_KEY
    }
    if set(form) - allowed:
        return _approval_refusal(request, 400, "That notification setting is not valid.")
    settings_values = form.get("settings", [])
    return_to_values = form.get("return_to", [])
    if len(settings_values) != 1 or len(return_to_values) > 1:
        return _approval_refusal(request, 400, "That notification setting is not valid.")
    requested = [s.strip() for s in settings_values[0].split(",") if s.strip()]
    if (not requested or len(set(requested)) != len(requested)
            or any(key not in AI_NOTIFICATION_SETTINGS_BY_KEY for key in requested)):
        return _approval_refusal(request, 400, "That notification setting is not valid.")
    updates: dict[str, bool] = {}
    for key in requested:
        enabled_values = form.get(f"enabled_{key}", [])
        if len(enabled_values) > 1 or (enabled_values and enabled_values[0] != "on"):
            return _approval_refusal(request, 400, "That notification setting is not valid.")
        updates[AI_NOTIFICATION_SETTINGS_BY_KEY[key]] = bool(enabled_values)
    return_to = _notification_return_to(return_to_values[0] if return_to_values else "")
    saved = 0
    try:
        if _portal_role(request.state.jwt) != "admin":
            return _approval_refusal(
                request, 403,
                "Only an administrator on your account can change notification settings.")
        for raw_key, value in updates.items():
            result = upstream.put_json(
                "/v1/portal/software-notifications", request.state.jwt, {raw_key: value})
            if _ai_notification_view(result) is None:
                raise upstream.UpstreamError("error", "invalid notification update response")
            saved += 1
    except upstream.UpstreamError as exc:
        if exc.kind == "auth":
            return _session_expired_response(request, "upstream")
        if exc.kind == "forbidden":
            return _approval_refusal(
                request, 403,
                "Only an administrator on your account can change notification settings.")
        if saved:
            return _approval_refusal(
                request, 502,
                "Some notification settings could not be saved. Reload the page to see "
                "which settings are now on.")
        return _approval_refusal(
            request, 502, "Notification settings could not be saved. Nothing was changed.")
    flash = _sign_flash(request.state.jwt, {"notification_settings": requested})
    separator = "&" if "?" in return_to else "?"
    return RedirectResponse(
        url=(f"{return_to}{separator}{AI_NOTIFICATION_RESULT_PARAM}="
             f"{quote(flash, safe='')}#notifications"),
        status_code=303)


def _ai_export_products(jwt_token: str) -> tuple[list, bool]:
    """Read one complete bounded tagged-product snapshot for CSV export.

    The platform's generated_at belongs to each response, not to a stable
    pagination snapshot. Fetching another page could therefore duplicate or
    omit products after a same-sized reorder. A total above the platform's
    1,000-row page ceiling is refused rather than producing a partial file.
    """
    data = upstream.get_json("/v1/portal/tagged-products", jwt_token, params={
        "category": "ai_tooling", "limit": AI_TOOLING_CSV_PAGE_SIZE, "offset": 0,
    })
    page, total, _distinct, estate_too_large = _ai_products_page(
        data, AI_TOOLING_CSV_PAGE_SIZE, 0)
    if estate_too_large or total > AI_TOOLING_CSV_PAGE_SIZE:
        return [], True
    return page, False


AI_TOOLING_CSV_COLUMNS = (
    "product", "type", "vendor", "platforms", "versions", "device_count",
    "user_count", "first_seen", "last_seen", "last_used_at", "last_used_state",
    "approval_state", "assessment_state", "vulnerability_finding_count",
    "highest_severity",
)


def _ai_tooling_export_table(request: Request) -> _ExportTable | Response:
    """The one complete bounded product snapshot the AI Tooling CSV holds.
    Raises UpstreamError. An estate over the 1,000 product ceiling gets the
    "Export unavailable" page (returned, not raised), never a partial file."""
    summary = upstream.get_json("/v1/portal/ai-tooling/summary", request.state.jwt)
    if not isinstance(summary, dict):
        raise upstream.UpstreamError("error", "invalid AI tooling summary")
    vulnerabilities = _ai_vulnerability_products(summary.get("vulnerability_products"))
    raw_products, export_too_large = _ai_export_products(request.state.jwt)
    if export_too_large:
        return _render(request, "error.html", {
            "title": "Export unavailable",
            "message": (
                "AI tooling CSV export is limited to 1,000 products. This estate is "
                "larger, so no partial file was created."
            ),
        }, status_code=503)
    products = [
        _ai_product_row(
            p, vulnerabilities,
            False,
        )
        for p in raw_products if isinstance(p, dict)
    ]
    rows = [[_cell(v) for v in (
        product["name"], product["type_label"], product["vendor"],
        ";".join(product["platforms"]), ";".join(product["versions"]),
        product["device_count"], product["user_count"], product["first_seen"],
        product["last_seen"], product["last_used"]["value"],
        product["last_used"]["state"], product["approval_filter"],
        product["assessment"]["state"], product["assessment"]["count"],
        product["assessment"]["severity"],
    )] for product in products]
    return _ExportTable("ai-tooling", "patched-ai-tooling.csv",
                        list(AI_TOOLING_CSV_COLUMNS), rows, [])


@app.get("/ai-tooling.csv")
def ai_tooling_csv(request: Request):
    try:
        table = _ai_tooling_export_table(request)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if not isinstance(table, _ExportTable):
        return table
    return _table_csv_response(table)


@app.get("/ai-tooling.pdf")
def ai_tooling_pdf(request: Request):
    """PAT-2405: the same table as /ai-tooling.csv, as a PDF."""
    try:
        table = _ai_tooling_export_table(request)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if not isinstance(table, _ExportTable):
        return table
    return _table_pdf_response(request, table)


# ── PAT-1927: Cyber Essentials v3.3 readiness ──────────────────────────────
# GET /v1/portal/ce-readiness (contracts/portal-api.md, platform
# go-service/internal/report/portal_ce_readiness.go). Field names below are
# copied verbatim from that contract - this page invents nothing and adds
# no verdict of its own. The endpoint's own words: "This endpoint gives no
# verdict. It never says a device or the estate passes, is compliant, is
# ready or is certified." Every label and reason string here follows that
# same rule - state what the evidence shows, never a pass/fail claim.
#
# Reason codes reuse the Overview cards' own text (query_failed,
# source_not_migrated, no_completed_match_run, version_evidence_pending -
# see OVERVIEW_CARD_REASON_TEXT above) where the contract says the codes
# are shared, plus this endpoint's own device-state and control codes.
CE_REASON_TEXT = {
    "query_failed": OVERVIEW_CARD_REASON_TEXT["query_failed"],
    "source_not_migrated": OVERVIEW_CARD_REASON_TEXT["source_not_migrated"],
    "no_completed_match_run": OVERVIEW_CARD_REASON_TEXT["no_completed_match_run"],
    "version_evidence_pending": OVERVIEW_CARD_REASON_TEXT["version_evidence_pending"],
    "outstanding_items": "has at least one critical or high update outside the 14-day window",
    "control_not_passing": "at least one monitored control is not passing",
    "device_stale": "has not reported in the last 24 hours",
    "device_silent": "has been silent for an extended period",
    "device_no_report_time": "has no recorded report time",
    "cve_match_pending": "vulnerability matching is still queued for this device",
    "advisory_date_unknown": (
        "an update was found with no advisory publication date recorded, "
        "so it cannot be dated"
    ),
    "no_evaluation": "no compliance check has been recorded for this control",
    "evaluation_failed": "the latest compliance check for this control failed",
    "undetermined": "the latest compliance check could not determine a result",
    "evaluation_error": "the latest compliance check for this control errored",
    "not_applicable": "not applicable to this device",
    "edr_unrecognised": "the endpoint protection reported was not recognised",
    "no_edr_evidence": "no endpoint protection evidence is available",
}
CE_REASON_TEXT_DEFAULT = "the reason is not recognised yet"

CE_STATE_LABELS = {
    "not_passing": "Not passing",
    "unknown": "Unknown",
    "no_outstanding_items_evidenced": "No outstanding items evidenced",
}
CE_STATE_PILL = {
    "not_passing": "pill-bad",
    "unknown": "pill-muted",
    "no_outstanding_items_evidenced": "pill-info",
}
CE_CONTROL_STATE_LABELS = {
    "evidenced_ok": "Evidenced OK",
    "not_passing": "Not passing",
    "not_evidenced": "Not evidenced by Patched",
}
CE_CONTROL_PILL = {
    "evidenced_ok": "pill-ok",
    "not_passing": "pill-bad",
    "not_evidenced": "pill-muted",
}
CE_EVIDENCE_LABELS = {"evidenced": "Evidenced", "unknown": "Unknown", "unavailable": "Unavailable"}
CE_EVIDENCE_PILL = {"evidenced": "pill-ok", "unknown": "pill-muted", "unavailable": "pill-bad"}
CE_KEV_LABELS = {"listed": "Listed", "not_listed": "Not listed", "unknown": "Unknown"}
CE_KEV_PILL = {"listed": "pill-bad", "not_listed": "pill-muted", "unknown": "pill-muted"}
CE_BUCKET_LABELS = {"active": "Active", "stale": "Stale", "silent": "Silent", "unknown": "Unknown"}
CE_BUCKET_PILL = {
    "active": "pill-ok", "stale": "pill-warn", "silent": "pill-bad", "unknown": "pill-muted",
}
CE_DUE_BASIS_LABELS = {
    "advisory_published_plus_14_days": "Advisory published date + 14 days",
}


def _ce_reason_text(reason) -> str | None:
    if not reason:
        return None
    return CE_REASON_TEXT.get(reason, CE_REASON_TEXT_DEFAULT)


def _ce_label(mapping: dict, key, default_prefix: str = "") -> str:
    if key in mapping:
        return mapping[key]
    if isinstance(key, str) and key:
        return key.replace("_", " ").capitalize()
    return default_prefix or "-"


def _ce_evidence_view(raw) -> dict:
    raw = raw if isinstance(raw, dict) else {}
    state = raw.get("state") or "unknown"
    return {
        "state": state,
        "label": _ce_label(CE_EVIDENCE_LABELS, state),
        "pill": CE_EVIDENCE_PILL.get(state, "pill-muted"),
        "reason_text": _ce_reason_text(raw.get("reason")),
        "source": raw.get("source"),
        "observed_at": raw.get("observed_at"),
    }


def _ce_kev_view(raw) -> dict:
    raw = raw if isinstance(raw, dict) else {}
    state = raw.get("state") or "unknown"
    return {
        "state": state,
        "label": _ce_label(CE_KEV_LABELS, state),
        "pill": CE_KEV_PILL.get(state, "pill-muted"),
        "reason_text": _ce_reason_text(raw.get("reason")),
        "fetched_at": raw.get("fetched_at"),
    }


def _ce_item_view(raw) -> dict | None:
    if not isinstance(raw, dict):
        return None
    cve_id = raw.get("cve_id")
    if not isinstance(cve_id, str) or not cve_id:
        return None
    due_basis = raw.get("due_basis")
    return {
        "cve_id": cve_id,
        "severity": raw.get("severity") or "low",
        "product": raw.get("product") or "-",
        "installed_version": raw.get("installed_version") or "-",
        "fixed_version": raw.get("fixed_version"),
        "published_at": raw.get("published_at"),
        "due_basis": due_basis,
        "due_basis_label": _ce_label(CE_DUE_BASIS_LABELS, due_basis) if due_basis else None,
        "due_at": raw.get("due_at"),
        "age_days": raw.get("age_days"),
        "days_overdue": raw.get("days_overdue"),
        "kev": _ce_kev_view(raw.get("kev")),
        "source": raw.get("source"),
        "observed_at": raw.get("observed_at"),
    }


# Words that .capitalize() would wrongly lowercase ("Edr coverage").
CE_CONTROL_ACRONYMS = {"edr": "EDR", "cis": "CIS", "av": "AV", "mdm": "MDM"}


def _ce_control_label(control: str) -> str:
    words = control.split("_")
    out = [CE_CONTROL_ACRONYMS.get(w, w) for w in words]
    if out and out[0] == words[0]:
        out[0] = out[0].capitalize()
    return " ".join(out)


def _ce_control_view(raw) -> dict | None:
    if not isinstance(raw, dict):
        return None
    control = raw.get("control")
    if not isinstance(control, str) or not control:
        return None
    state = raw.get("state") or "not_evidenced"
    return {
        "control": control,
        "control_label": _ce_control_label(control),
        "category": raw.get("category"),
        "category_label": _ce_label({}, raw.get("category")) if raw.get("category") else None,
        "state": state,
        "label": _ce_label(CE_CONTROL_STATE_LABELS, state),
        "pill": CE_CONTROL_PILL.get(state, "pill-muted"),
        "reason_text": _ce_reason_text(raw.get("reason")),
        "source": raw.get("source"),
        "rule_key": raw.get("rule_key"),
        "observed_at": raw.get("observed_at"),
    }


def _ce_platform_label(platform) -> str:
    if platform == "macos":
        return "macOS"
    if platform == "windows":
        return "Windows"
    return _ce_label({}, platform)


def _ce_device_view(raw) -> dict | None:
    if not isinstance(raw, dict):
        return None
    device_id = raw.get("device_id")
    if not isinstance(device_id, str) or not device_id:
        return None
    hostname = raw.get("hostname")
    state = raw.get("state") or "unknown"

    reasons_raw = raw.get("state_reasons")
    reason_texts: list[str] = []
    if isinstance(reasons_raw, list):
        for code in reasons_raw:
            text = _ce_reason_text(code) if isinstance(code, str) else None
            if text and text not in reason_texts:
                reason_texts.append(text)

    items_raw = raw.get("items")
    items = [v for v in (
        _ce_item_view(i) for i in items_raw
    ) if v] if isinstance(items_raw, list) else []

    controls_raw = raw.get("controls")
    controls = [v for v in (
        _ce_control_view(c) for c in controls_raw
    ) if v] if isinstance(controls_raw, list) else []
    controls_not_passing = [c for c in controls if c["state"] == "not_passing"]
    controls_not_evidenced = [c for c in controls if c["state"] == "not_evidenced"]

    reporting_raw = raw.get("reporting") if isinstance(raw.get("reporting"), dict) else {}
    bucket = reporting_raw.get("bucket") or "unknown"

    return {
        "device_id": device_id,
        "hostname": hostname if isinstance(hostname, str) and hostname else device_id,
        "platform": raw.get("platform"),
        "platform_label": _ce_platform_label(raw.get("platform")),
        "state": state,
        "state_label": _ce_label(CE_STATE_LABELS, state),
        "state_pill": CE_STATE_PILL.get(state, "pill-muted"),
        "state_reasons": reason_texts,
        "reporting_bucket": bucket,
        "reporting_bucket_label": _ce_label(CE_BUCKET_LABELS, bucket),
        "reporting_pill": CE_BUCKET_PILL.get(bucket, "pill-muted"),
        "last_seen": reporting_raw.get("observed_at"),
        "cve_evidence": _ce_evidence_view(raw.get("cve_evidence")),
        "os_update_evidence": _ce_evidence_view(raw.get("os_update_evidence")),
        # "rows", never "items" - a dict's own bound `.items()` method shadows
        # a same-named key under Jinja's dot-attribute resolution (see
        # _hardware_sub_block's identical comment above).
        "rows": items,
        "overdue_count": len(items),
        "controls": controls,
        "controls_not_passing": controls_not_passing,
        "controls_not_evidenced": controls_not_evidenced,
    }


def _ce_estate_view(raw) -> dict:
    raw = raw if isinstance(raw, dict) else {}

    def _int(key):
        value = raw.get(key)
        return value if type(value) is int else 0

    freshness = raw.get("freshness") if isinstance(raw.get("freshness"), dict) else {}
    return {
        "devices_total": _int("devices_total"),
        "not_passing": _int("not_passing"),
        "with_outstanding_items": _int("with_outstanding_items"),
        "with_controls_not_passing": _int("with_controls_not_passing"),
        "unknown": _int("unknown"),
        "no_outstanding_items_evidenced": _int("no_outstanding_items_evidenced"),
        "retired_excluded": _int("retired_excluded"),
        "source": raw.get("source"),
        "generated_at": freshness.get("generated_at"),
        "observed_at": freshness.get("observed_at"),
    }


@app.get("/ce-readiness", response_class=HTMLResponse)
def ce_readiness(request: Request):
    """PAT-1927: Cyber Essentials v3.3 readiness, per device - what stands
    between each device and the v3.3 14-day critical/high update rule, plus
    the malware protection, firewall and secure configuration controls the
    platform can evidence. Read-only proxy of contracts/portal-api.md's
    GET /v1/portal/ce-readiness; the portal computes nothing here and adds
    no verdict - see that contract's "What this does not claim" section.
    Only a Cyber Essentials assessor certifies an estate."""
    try:
        data = upstream.get_json("/v1/portal/ce-readiness", request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if not isinstance(data, dict):
        return _error_page(
            request, upstream.UpstreamError("error", "invalid CE readiness response"))

    thresholds = data.get("thresholds") if isinstance(data.get("thresholds"), dict) else {}
    devices_raw = data.get("devices")
    devices = [v for v in (
        _ce_device_view(d) for d in devices_raw
    ) if v] if isinstance(devices_raw, list) else []

    return _render(request, "ce_readiness.html", {
        "title": "Cyber Essentials readiness",
        "nav": "ce-readiness",
        "generated_at": data.get("generated_at"),
        "update_due_after_days": thresholds.get("update_due_after_days", 14),
        "cve_matching": _ce_evidence_view(data.get("cve_matching")),
        "estate": _ce_estate_view(data.get("estate")),
        "devices": devices,
        "has_items": any(d["rows"] for d in devices),
        "csv_url": "/ce-readiness.csv",
        "pdf_url": "/ce-readiness.pdf",
    })


@app.get("/ce-readiness.csv")
def ce_readiness_csv(request: Request):
    """PAT-1927/PAT-2010 CSV proxy pattern: stream the platform's own
    ?format=csv response through verbatim (escaping, columns and filename
    are all the platform's, never re-derived here)."""
    try:
        resp = upstream.stream(
            "/v1/portal/ce-readiness", request.state.jwt, params={"format": "csv"})
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    return _sam_csv_response(resp, "ce-readiness.csv")


@app.get("/ce-readiness.pdf")
def ce_readiness_pdf(request: Request):
    """Stream the platform's dated customer evidence pack without recomputing it.

    Tenant scope comes only from the forwarded verified JWT. The shared
    download helper preserves the platform's type, filename and length,
    and closes its response even when a transfer is interrupted.
    """
    try:
        resp = upstream.stream(
            "/v1/portal/ce-readiness", request.state.jwt, params={"format": "pdf"})
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    response = _sam_csv_response(resp, "ce-readiness.pdf")
    response.headers["Cache-Control"] = "private, no-store"
    return response


# ── PAT-2258: cyber insurance evidence pack ────────────────────────────────
# A read-only proxy of contracts/portal-api.md "GET /v1/portal/insurance-
# evidence". The platform computes every answer from its existing read
# models, with its status, source path, freshness and unknown-device count;
# the portal renders exactly that and derives no figure of its own (rubric
# D14). Every portal role can read it, as for /ce-readiness. Status says how
# much of the estate the evidence covers, never whether the answer is good,
# so "Evidenced" takes the neutral info tone rather than green (rubric T6).
INSURANCE_STATUS_LABELS = {
    "evidenced": "Evidenced",
    "partial": "Partly evidenced",
    "unknown": "Unknown",
    "not_evidenced_by_patched": "Not evidenced by Patched",
}
INSURANCE_STATUS_PILL = {
    "evidenced": "pill-info",
    "partial": "pill-warn",
    "unknown": "pill-muted",
    "not_evidenced_by_patched": "pill-muted",
}
INSURANCE_NOT_EVIDENCED = "not_evidenced_by_patched"
# A source path is linked only when it is a plain portal path: never an
# absolute URL, a scheme-relative "//host" or anything carrying a query.
_INSURANCE_SOURCE_PATH_RE = re.compile(r"^/[a-z0-9][a-z0-9/_-]*$|^/$")


def _insurance_text(raw, key) -> str:
    value = raw.get(key)
    return value if isinstance(value, str) else ""


def _insurance_answer_view(raw) -> dict | None:
    if not isinstance(raw, dict):
        return None
    qid = raw.get("id")
    if not isinstance(qid, str) or not qid:
        return None
    status = raw.get("status")
    if status not in INSURANCE_STATUS_LABELS:
        status = "unknown"
    unknown = raw.get("unknown_devices")
    source = raw.get("source") if isinstance(raw.get("source"), dict) else {}
    source_path = source.get("path")
    if not (isinstance(source_path, str) and _INSURANCE_SOURCE_PATH_RE.match(source_path)):
        source_path = None
    return {
        "id": qid,
        "title": _insurance_text(raw, "title") or qid.replace("_", " ").capitalize(),
        "question": _insurance_text(raw, "question"),
        "status": status,
        "status_label": INSURANCE_STATUS_LABELS[status],
        "status_pill": INSURANCE_STATUS_PILL[status],
        "not_evidenced": status == INSURANCE_NOT_EVIDENCED,
        "headline": _insurance_text(raw, "headline"),
        "answer_text": _insurance_text(raw, "answer_text"),
        "basis": _insurance_text(raw, "basis"),
        "unknown_devices": unknown if type(unknown) is int else None,
        "as_of": raw.get("as_of"),
        "oldest_evidence_at": raw.get("oldest_evidence_at"),
        "source_label": source.get("label") if isinstance(source.get("label"), str) else None,
        "source_path": source_path,
    }


@app.get("/reports/insurance-evidence", response_class=HTMLResponse)
def insurance_evidence(request: Request):
    """PAT-2258: the cyber insurance evidence pack. Each renewal-form
    endpoint question with the platform's own answer, status, source,
    freshness and unknown-device count, then the questions Patched cannot
    evidence, which are always listed rather than left out."""
    try:
        data = upstream.get_json("/v1/portal/insurance-evidence", request.state.jwt)
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    if not isinstance(data, dict):
        return _error_page(
            request, upstream.UpstreamError("error", "invalid insurance evidence response"))

    questions_raw = data.get("questions")
    questions = [v for v in (
        _insurance_answer_view(q) for q in questions_raw
    ) if v] if isinstance(questions_raw, list) else []
    evidenced = [q for q in questions if not q["not_evidenced"]]
    not_evidenced = [q for q in questions if q["not_evidenced"]]
    status_counts = {key: 0 for key in INSURANCE_STATUS_LABELS}
    for q in questions:
        status_counts[q["status"]] += 1

    def _int(key):
        value = data.get(key)
        return value if type(value) is int else None

    return _render(request, "insurance_evidence.html", {
        "title": "Cyber insurance evidence",
        "nav": "reports",
        "generated_at": data.get("generated_at"),
        "statement": data.get("statement") if isinstance(data.get("statement"), str) else "",
        "reporting_window_days": _int("reporting_window_days"),
        "devices_in_scope": _int("devices_in_scope"),
        "retired_excluded": _int("retired_excluded"),
        "evidenced": evidenced,
        "not_evidenced": not_evidenced,
        "status_counts": status_counts,
        "status_labels": INSURANCE_STATUS_LABELS,
        "total": len(questions),
        "csv_url": "/reports/insurance-evidence.csv",
        "pdf_url": "/reports/insurance-evidence.pdf",
    })


@app.get("/reports/insurance-evidence.csv")
def insurance_evidence_csv(request: Request):
    """The platform's own one-row-per-question CSV, streamed verbatim
    (escaping, columns and filename are the platform's)."""
    try:
        resp = upstream.stream(
            "/v1/portal/insurance-evidence", request.state.jwt, params={"format": "csv"})
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    return _sam_csv_response(resp, "insurance-evidence.csv")


@app.get("/reports/insurance-evidence.pdf")
def insurance_evidence_pdf(request: Request):
    """The platform's customer PDF of the same pack, streamed verbatim.
    _sam_csv_response is the generic streaming proxy (it takes the media
    type from the platform's own Content-Type), so a PDF streams through it
    with the same truncation guard as every CSV."""
    try:
        resp = upstream.stream(
            "/v1/portal/insurance-evidence", request.state.jwt, params={"format": "pdf"})
    except upstream.UpstreamError as exc:
        return _error_page(request, exc)
    return _sam_csv_response(resp, "insurance-evidence.pdf")


# ── PAT-2157: What's new (customer-facing portal changelog) ────────────────
# Source of truth is data/changelog.json, loaded once below (after every
# route above has registered, so _changelog_known_routes sees the full set,
# including this route itself) and validated at import time - an invalid
# file is a startup-time ValueError, caught by tests/test_pat2157_whats_new.py
# long before it ever reaches a deploy, not something the live page has to
# degrade gracefully around. No upstream call: the changelog is portal-only,
# static, customer-friendly copy, not tenant data.
_CHANGELOG_TAGS = ("New", "Improved", "Fixed")
_CHANGELOG_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CHANGELOG_EM_DASH = "—"
_CHANGELOG_PAT_REF_RE = re.compile(r"\bPAT-\d+\b")
_CHANGELOG_FLEET_RE = re.compile(r"\bfleet\b", re.IGNORECASE)
_CHANGELOG_REQUIRED_FIELDS = ("date", "title", "body", "tag", "link")


def _changelog_known_routes() -> set[str]:
    """Static (no {path param}) GET route paths - the only kind of route a
    changelog entry may link to. A dynamic route (e.g. /devices/{device_id})
    has no single generic URL to point at, so entries link to the nearest
    static list page instead (e.g. /devices)."""
    routes: set[str] = set()
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None) or ()
        if path and "GET" in methods and "{" not in path:
            routes.add(path)
    return routes


def validate_changelog_entry(entry, known_routes: set[str]) -> None:
    """Raises ValueError (with a reason naming the field) on the first
    problem found. Called for every entry at startup against the real data
    file, and directly by tests/test_pat2157_whats_new.py's red-proof
    fixtures - a PAT- reference, an em dash, "fleet", a bad tag, a missing
    date, and a link to a route that does not exist must each raise here."""
    if not isinstance(entry, dict):
        raise ValueError("changelog entry must be a JSON object")
    for field in _CHANGELOG_REQUIRED_FIELDS:
        value = entry.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"changelog entry is missing required field {field!r}")
    date = entry["date"]
    if not _CHANGELOG_DATE_RE.match(date):
        raise ValueError(f"changelog entry date {date!r} is not in YYYY-MM-DD form")
    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError(f"changelog entry date {date!r} is not a real calendar date") from exc
    tag = entry["tag"]
    if tag not in _CHANGELOG_TAGS:
        raise ValueError(f"changelog entry tag {tag!r} is not one of {_CHANGELOG_TAGS}")
    link = entry["link"]
    if link not in known_routes:
        raise ValueError(f"changelog entry link {link!r} does not match a portal route")
    text = f"{entry['title']} {entry['body']}"
    if _CHANGELOG_PAT_REF_RE.search(text):
        raise ValueError("changelog entry references a PAT- ticket number")
    if _CHANGELOG_EM_DASH in text:
        raise ValueError("changelog entry contains an em dash")
    if _CHANGELOG_FLEET_RE.search(text):
        raise ValueError('changelog entry says "fleet" - customer copy says "estate"')


def _load_changelog(path: Path) -> list[dict]:
    raw = json.loads(path.read_text())
    if not isinstance(raw, list):
        raise ValueError("data/changelog.json must be a JSON array of entries")
    known_routes = _changelog_known_routes()
    for entry in raw:
        validate_changelog_entry(entry, known_routes)
    # Stable sort: entries already listed newest-first per date in the data
    # file keep that relative order within a shared date after this re-sort.
    return sorted(raw, key=lambda e: e["date"], reverse=True)


def _changelog_month_groups(entries: list[dict]) -> list[dict]:
    """Buckets already-newest-first entries into {label, entries} groups by
    calendar month, in the same newest-first order."""
    groups: list[dict] = []
    current_key = None
    for entry in entries:
        key = entry["date"][:7]
        if key != current_key:
            label = datetime.strptime(entry["date"], "%Y-%m-%d").strftime("%B %Y")
            groups.append({"label": label, "entries": []})
            current_key = key
        groups[-1]["entries"].append(entry)
    return groups


# Public certificate metadata is platform-owned. No tenant, actor, raw file
# storage or delivery preference is introduced in the portal (PAT-2389).
def _certificate_refusal(request: Request, status: int, message: str):
    return _render(request, "certificates.html", {
        "title": "Certificates", "nav": "certificates", "error": message,
        "rows": [], "can_edit": False,
    }, status_code=status)


def _certificate_upstream_error(request: Request, exc: upstream.UpstreamError):
    status = exc.status if exc.status in (400, 401, 403, 404, 409, 413, 429) else 503
    message = {
        400: "The certificate details were refused. Check the label and public certificate.",
        401: "Your session has expired. Sign in again before changing certificates.",
        403: "Only an administrator can manage uploaded certificates for this estate.",
        404: "That uploaded certificate is no longer available in this estate.",
        409: "That replacement is already tracked. Check the existing certificates.",
        413: "That certificate is too large. Public certificates up to 64 KiB are accepted.",
        429: "Too many certificate requests. Wait a moment and try again.",
    }.get(status, "Certificate tracking is temporarily unavailable. "
          "Refresh Certificates to check whether your change was saved before trying again.")
    # Never echo or log provider bodies: they can contain sensitive diagnostics.
    return _certificate_refusal(request, status, message)


@app.get("/certificates", response_class=HTMLResponse)
def certificate_list(request: Request):
    try:
        raw_rows = upstream.unwrap_list(
            upstream.get_json("/v1/portal/certificates", request.state.jwt), "certificates")
        if any(not isinstance(row, dict) for row in raw_rows):
            raise upstream.UpstreamError("error")
    except upstream.UpstreamError as exc:
        if exc.kind in ("auth", "forbidden", "not_enabled"):
            return _error_page(request, exc)
        if exc.kind == "rate_limited":
            return _certificate_upstream_error(request, exc)
        return _certificate_refusal(request, 503,
            "Certificate tracking is temporarily unavailable. Try again in a moment.")
    try:
        can_edit = _portal_role(request.state.jwt) == "admin"
    except upstream.UpstreamError:
        can_edit = False
    now = datetime.now(UTC)
    return _render(request, "certificates.html", {
        "title": "Certificates", "nav": "certificates", "error": None,
        "rows": [certificates.row_view(row, now) for row in raw_rows], "can_edit": can_edit,
    })


async def _guarded_certificate_form(request: Request):
    """Use the existing Origin/CSRF guards after bounding actual streamed bytes.

    Content-Length is only an early check, not the size authority. Buffering
    at most 96 KiB before form parsing keeps Starlette uploads in memory and
    refuses chunked or falsely declared oversized bodies before spooling.
    """
    def refuse(status, message):
        return None, _certificate_refusal(request, status, message)

    too_large = "That upload was too large. Public certificates up to 64 KiB are accepted."
    length = request.headers.get("content-length")
    if length is not None:
        if not re.fullmatch(r"[0-9]+", length):
            return refuse(400, "That request could not be read.")
        if len(length) > 8 or int(length) > certificates.MAX_BODY_BYTES:
            return refuse(413, too_large)
    try:
        same_origin = _same_origin(request)
    except ValueError:
        same_origin = False
    if not same_origin:
        return refuse(403, _STATE_CHANGE_ORIGIN_REFUSAL)
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > certificates.MAX_BODY_BYTES:
            return refuse(413, too_large)
        raw.extend(chunk)
    # Starlette replays _body to the parser, whose default 1 MiB spool limit
    # cannot be reached by this already-bounded 96 KiB body.
    request._body = bytes(raw)
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type not in ("multipart/form-data", "application/x-www-form-urlencoded"):
        return refuse(400, "Use the certificate form to make this change.")
    try:
        if content_type == "multipart/form-data":
            _, options = parse_options_header(request.headers["content-type"])
            boundary = options.get(b"boundary")
            # Starlette tolerates a missing final boundary, dropping an
            # unfinished file part. Never turn a truncated replacement into
            # a successful label-only edit. Native forms end with this marker.
            if (not boundary or len(boundary) > 70
                    or not raw.rstrip(b"\r\n").endswith(b"\r\n--" + boundary + b"--")):
                return refuse(400, "That upload was incomplete. Choose the file and try again.")
            completed = False

            def multipart_end():
                nonlocal completed
                completed = True

            # Require the standard parser to recognise an actual end event,
            # not merely bytes resembling a terminator inside a malformed part.
            parser = MultipartParser(boundary, {"on_end": multipart_end},
                                     max_size=certificates.MAX_BODY_BYTES)
            parser.write(request._body)
            parser.finalize()
            if not completed:
                return refuse(400, "That upload was incomplete. Choose the file and try again.")
        if content_type == "application/x-www-form-urlencoded":
            # Decode strictly before Starlette's permissive form parser.
            raw.decode("utf-8")
        form = await request.form(max_files=1, max_fields=8)
    except Exception:
        return refuse(400, "That request could not be read.")
    tokens = form.getlist(CSRF_FIELD)
    if (len(tokens) != 1 or not isinstance(tokens[0], str)
            or not re.fullmatch(r"[0-9a-f]{64}", tokens[0])
            or not _csrf_valid(request, tokens[0])):
        await form.close()
        return refuse(403, _STATE_CHANGE_CSRF_REFUSAL)
    return form, None


async def _certificate_mutation(request: Request, operation: str, record_id: str = ""):
    form, refusal = await _guarded_certificate_form(request)
    if refusal is not None:
        return refusal
    try:
        try:
            if await run_in_threadpool(_portal_role, request.state.jwt) != "admin":
                return _certificate_refusal(request, 403,
                    "Only an administrator can manage uploaded certificates for this estate.")
        except upstream.UpstreamError as exc:
            return _certificate_upstream_error(request, exc)
        path = "/v1/portal/certificates"
        if operation != "upload":
            if not certificates.valid_id(record_id):
                return _certificate_refusal(request, 400, "That certificate could not be found.")
            path += f"/{record_id}"
        payload = {}
        if operation != "delete":
            labels = form.getlist("label")
            if len(labels) != 1 or not certificates.valid_label(labels[0]):
                return _certificate_refusal(request, 400,
                    "Enter a label of 1 to 200 characters without control characters.")
            payload["label"] = labels[0].strip()
            uploads = form.getlist("certificate")
            if len(uploads) > 1:
                return _certificate_refusal(request, 400, "Choose one public certificate.")
            upload = uploads[0] if uploads else None
            raw = b""
            if isinstance(upload, UploadFile):
                raw = await upload.read(certificates.MAX_FILE_BYTES + 1)
                # A browser's optional empty file input means a label-only edit.
                if not raw and not upload.filename:
                    upload = None
            elif upload not in (None, ""):
                return _certificate_refusal(request, 400, "Choose a public certificate file.")
            if len(raw) > certificates.MAX_FILE_BYTES:
                return _certificate_refusal(request, 413,
                    "That certificate is too large. Public certificates up to 64 KiB are accepted.")
            if operation == "upload" or upload not in (None, ""):
                try:
                    await run_in_threadpool(certificates.validate_public_certificate, raw)
                except ValueError:
                    return _certificate_refusal(request, 400,
                        "Choose one public X.509 certificate in PEM or DER format. "
                        "Private keys are not accepted.")
                payload["certificate"] = base64.b64encode(raw).decode("ascii")
        try:
            if operation == "delete":
                await run_in_threadpool(upstream.delete_json, path, request.state.jwt)
            else:
                write = upstream.post_json if operation == "upload" else upstream.patch_json
                await run_in_threadpool(write, path, request.state.jwt, payload)
        except upstream.UpstreamError as exc:
            return _certificate_upstream_error(request, exc)
        return RedirectResponse("/certificates", status_code=303)
    finally:
        await form.close()


@app.post("/certificates/upload", response_class=HTMLResponse)
async def certificate_upload(request: Request):
    return await _certificate_mutation(request, "upload")


@app.post("/certificates/{record_id}/update", response_class=HTMLResponse)
async def certificate_update(request: Request, record_id: str):
    return await _certificate_mutation(request, "update", record_id)


@app.post("/certificates/{record_id}/delete", response_class=HTMLResponse)
async def certificate_delete(request: Request, record_id: str):
    return await _certificate_mutation(request, "delete", record_id)


@app.get("/whats-new", response_class=HTMLResponse)
def whats_new(request: Request):
    return _render(request, "whats_new.html", {
        "title": "What's new", "nav": "whats-new",
        "changelog_groups": CHANGELOG_GROUPS,
    })


CHANGELOG_ENTRIES = _load_changelog(BASE_DIR / "data" / "changelog.json")
CHANGELOG_GROUPS = _changelog_month_groups(CHANGELOG_ENTRIES)
CHANGELOG_NEWEST_DATE = CHANGELOG_ENTRIES[0]["date"] if CHANGELOG_ENTRIES else ""
# Every signed-in page's rail needs the newest entry's date (to compare
# against localStorage['patched.whatsNewSeen'] client-side) - a template
# global rather than threading it through every route's own context.
templates.env.globals["changelog_newest_date"] = CHANGELOG_NEWEST_DATE


@app.exception_handler(404)
async def not_found(request: Request, exc):
    return _render(request, "error.html", {
        "title": "Not found",
        "message": "That page does not exist.",
    }, status_code=404)
