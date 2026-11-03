"""Guards PAT-2263 - the device Compliance tab's "Known vulnerable
drivers" section and the Findings page's estate driver-findings section
render without overflow at 1280px and 390px, light and dark, using
fully-populated fixtures so the matches table and the segmented filter
tab are actually exercised.

Red-proof: every assertion here fails before these sections exist (no
#kernel-drivers/#driver-findings element at all) and passes once
templates/device_compliance.html, templates/findings.html and
static/css/portal.css carry them.
"""

from copy import deepcopy

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from tests.conftest import DEVICE_DETAIL, DRIVER_LISTS, STUB_STATE

FULL_KERNEL_DRIVERS = {
    "status": "complete",
    "reported_at": "2026-09-29T09:00:00Z", "observed_at": "2026-09-29T08:59:40Z",
    "errors": [],
    "enforcement": {
        "vulnerable_driver_blocklist": "disabled", "hvci": "off",
        "smart_app_control": "off", "code_integrity_policy": "off",
        "blocklist_enforced": "no",
    },
    "lists": DRIVER_LISTS,
    "summary": {"drivers": 612, "hashed": 610, "unhashed": 2, "listed": 2,
                "listed_malicious": 1, "unknown": 2},
    "drivers": [
        {
            "path": "C:\\Windows\\Temp\\helper.sys", "service_name": "helper",
            "service_type": "kernel", "start_type": "demand", "loaded": True,
            "sources": ["service", "loaded"], "hash_status": "hashed",
            "unhashed_reason": None, "version": "1.0.0.1", "sha256": "a" * 64,
            "authenticode_sha256": None, "reported_at": "2026-09-29T09:00:00Z",
            "first_seen_at": "2026-09-27T09:00:00Z", "match_status": "listed",
            "unknown_reason": None,
            "matches": [{
                "source": "loldrivers", "source_url": "https://www.loldrivers.io/api/drivers.json",
                "category": "malicious", "entry_id": "e-1", "entry_name": "gdrv.sys",
                "hash_kind": "sha256", "hash": "a" * 64, "list_version": "sha256:4be1...",
                "list_fetched_at": "2026-09-26T01:00:00Z", "list_stale": True,
            }],
        },
        {
            "path": "C:\\Windows\\System32\\drivers\\old.sys", "service_name": "old",
            "service_type": "kernel", "start_type": "boot", "loaded": False,
            "sources": ["service"], "hash_status": "hashed", "unhashed_reason": None,
            "version": "2.0.0.0", "sha256": "c" * 64, "authenticode_sha256": None,
            "reported_at": "2026-09-29T09:00:00Z", "first_seen_at": "2026-09-01T09:00:00Z",
            "match_status": "listed", "unknown_reason": None,
            "matches": [{
                "source": "microsoft_driver_blocklist",
                "source_url": "https://aka.ms/VulnerableDriverBlockList", "category": "vulnerable",
                "entry_id": "e-2", "entry_name": "old.sys", "hash_kind": "sha256",
                "hash": "c" * 64, "list_version": "10.0.29545.0",
                "list_fetched_at": "2026-09-29T01:00:00Z", "list_stale": False,
            }],
        },
    ],
    "drivers_truncated": False,
}

OVERFLOW_JS = """
(selector) => {
  const failures = [];
  const card = document.querySelector(selector);
  if (!card) { failures.push(selector + ': not found'); return failures; }
  const cr = card.getBoundingClientRect();
  card.querySelectorAll('*').forEach((el) => {
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) return;
    if (r.right > cr.right + 1 || r.left < cr.left - 1) {
      failures.push(el.tagName + ' ' +
        JSON.stringify((el.textContent || '').trim().slice(0, 40)) +
        ' right=' + r.right.toFixed(1) + ' cardRight=' + cr.right.toFixed(1));
    }
  });
  return failures;
}
"""

DOCUMENT_SCROLLWIDTH_JS = """
() => ({scrollWidth: document.documentElement.scrollWidth,
        clientWidth: document.documentElement.clientWidth})
"""


@pytest.fixture
def full_kernel_drivers_stub():
    detail = deepcopy(DEVICE_DETAIL)
    detail["platform"] = "Windows"
    detail["kernel_drivers"] = FULL_KERNEL_DRIVERS
    STUB_STATE["device_detail_data"] = detail
    yield
    STUB_STATE["device_detail_data"] = None


@pytest.mark.parametrize("color_scheme", ["light", "dark"])
@pytest.mark.parametrize("width", [1280, 390])
def test_kernel_drivers_section_renders_without_overflow(
    browser, harness_url, full_kernel_drivers_stub, color_scheme, width
):
    context = browser.new_context(base_url=harness_url, color_scheme=color_scheme)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    try:
        page = context.new_page()
        page.set_viewport_size({"width": width, "height": 1000})
        page.goto(f"{harness_url}/devices/dev-mac-001/compliance", wait_until="networkidle")

        section = page.locator("#kernel-drivers")
        assert section.count() == 1
        text = section.inner_text()

        overflow = page.evaluate(OVERFLOW_JS, "#kernel-drivers")
        doc = page.evaluate(DOCUMENT_SCROLLWIDTH_JS)
    finally:
        context.close()

    assert "not enforced" in text
    assert "Present and not blocked by Windows" in text
    assert "Present, blocked by Windows" in text
    assert "Malicious" in text
    assert "Stale" in text
    assert not overflow, (
        f"[{width}px, {color_scheme}] element(s) overflowed #kernel-drivers:\n"
        + "\n".join(overflow)
    )
    assert doc["scrollWidth"] <= doc["clientWidth"] + 1, (
        f"[{width}px, {color_scheme}] document scrolls horizontally: {doc}"
    )


@pytest.mark.parametrize("color_scheme", ["light", "dark"])
def test_not_reported_kernel_drivers_shows_macos_wording_without_overflow(
    browser, harness_url, color_scheme
):
    """The default dev-mac-001 stub (platform macOS) carries no
    "kernel_drivers" key at all - the not_reported/absent path, exercised
    here at phone width to prove the muted fallback line never overflows."""
    context = browser.new_context(base_url=harness_url, color_scheme=color_scheme)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 390, "height": 900})
        page.goto(f"{harness_url}/devices/dev-mac-001/compliance", wait_until="networkidle")

        section = page.locator("#kernel-drivers")
        assert section.count() == 1
        text = section.inner_text()

        overflow = page.evaluate(OVERFLOW_JS, "#kernel-drivers")
    finally:
        context.close()

    assert "Driver checks apply to Windows devices." in text
    assert not overflow, (
        f"[{color_scheme}] element(s) overflowed #kernel-drivers:\n" + "\n".join(overflow)
    )


@pytest.mark.parametrize("color_scheme", ["light", "dark"])
@pytest.mark.parametrize("width", [1280, 390])
def test_findings_driver_section_renders_without_overflow(
    browser, harness_url, color_scheme, width
):
    """The default DRIVER_FINDINGS fixture (one critical, blocklist-not-
    enforced match) exercises the estate section and its All/Blocklist-
    not-enforced filter tab with no per-test override needed."""
    context = browser.new_context(base_url=harness_url, color_scheme=color_scheme)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    try:
        page = context.new_page()
        page.set_viewport_size({"width": width, "height": 1000})
        page.goto(f"{harness_url}/findings", wait_until="networkidle")

        section = page.locator("#driver-findings")
        assert section.count() == 1
        text = section.inner_text()

        # Exercise the filter tab itself - clicking it must not introduce
        # overflow (it only toggles a CSS class client-side).
        page.click("#driver-findings [data-filter-tab='not_enforced']")

        overflow = page.evaluate(OVERFLOW_JS, "#driver-findings")
        doc = page.evaluate(DOCUMENT_SCROLLWIDTH_JS)
    finally:
        context.close()

    assert "Known vulnerable drivers" in text
    assert "acme-win-accounts" in text
    assert "Not enforced" in text
    assert not overflow, (
        f"[{width}px, {color_scheme}] element(s) overflowed #driver-findings:\n"
        + "\n".join(overflow)
    )
    assert doc["scrollWidth"] <= doc["clientWidth"] + 1, (
        f"[{width}px, {color_scheme}] document scrolls horizontally: {doc}"
    )
