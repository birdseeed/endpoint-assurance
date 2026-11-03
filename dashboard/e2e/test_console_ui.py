"""
e2e/test_console_ui.py — real-browser click-through coverage for the staff
console (PAT-1021).

Existing coverage under tests/ only ever exercises FastAPI's TestClient and
asserts on raw HTML strings; nothing renders a page or clicks anything, so a
console that renders blank or has dead nav buttons still passes CI green.
These tests close that gap: a genuine Chromium instance loads /console
against a real `uvicorn main:app` subprocess (see conftest.py) and clicks
through the actual nav.
"""

import re

import pytest
import requests
from playwright.sync_api import expect, sync_playwright

# Every direct nav walk (grail rail, ops group, admin group) is expected to
# reach at least this many distinct top-level sections. Belt-and-braces on
# top of the per-click assertions below — catches a future section added to
# templates/console.html but never wired to any nav link. See _SECTIONS /
# _NAV_MAP in console.html for the authoritative list this mirrors loosely
# (home, customers-list, ops, billing, automations, truth, catalogue,
# credentials, docs, leads, logs, reports = 12 today).
MIN_EXPECTED_SECTIONS = 8


def _assert_no_page_errors(page_errors):
    assert page_errors == [], f"uncaught JS errors: {page_errors}"


@pytest.fixture(scope="session")
def browser():
    with sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


@pytest.fixture()
def console_page(browser, dashboard_server, api_headers):
    """A fresh browser context/page per test, authenticated via the shared
    Bearer token on every request, with JS-error and failed-network-request
    collectors wired up before the first navigation.

    Yields (page, page_errors, failed_requests) — the two lists are mutated
    in place as the test drives the page, so a test asserts against them
    after acting.
    """
    context = browser.new_context(extra_http_headers=api_headers)
    page = context.new_page()

    page_errors = []
    failed_requests = []
    page.on("pageerror", lambda exc: page_errors.append(str(exc)))
    page.on(
        "requestfailed",
        lambda req: failed_requests.append(f"{req.method} {req.url} — {req.failure}"),
    )

    page.goto(f"{dashboard_server}/console")

    yield page, page_errors, failed_requests

    context.close()


def _discover_nav_links(page, selector):
    """Query the LIVE DOM (rendered straight from templates/console.html,
    not a copy hardcoded here) for every element under `selector` whose
    onclick directly calls consoleNav('<section>'). Returns
    [{"id": ..., "section": ...}, ...]. Deliberately excludes
    tenantWorkload()/tenantTab() sub-nav, which requires an active tenant
    and isn't a top-level destination.
    """
    return page.eval_on_selector_all(
        selector,
        r"""
        els => els.map(el => {
            const m = (el.getAttribute('onclick') || '').match(/^consoleNav\('([^']+)'\)/);
            return m ? { id: el.id, section: m[1] } : null;
        }).filter(Boolean)
        """,
    )


def _assert_panel_active_and_nonempty(page, section):
    panel = page.locator(f"#section-{section}")
    expect(panel).to_have_class(re.compile(r"\bactive\b"))
    expect(panel).to_be_visible()
    # Auto-retrying text assertion (not a one-shot inner_text() call) so a
    # panel whose content arrives via an async fetch still passes once it
    # renders, rather than racing the network.
    expect(panel).to_contain_text(re.compile(r"\S"), timeout=15000)


def test_console_loads_and_primary_nav_renders(console_page):
    """Task 1: /console loads in real Chromium and the primary nav renders —
    present AND visible, not just present in the HTML source."""
    page, page_errors, failed_requests = console_page

    rail = page.locator("#global-rail")
    expect(rail).to_be_visible()

    grail_items = page.locator("#global-rail .grail-item")
    count = grail_items.count()
    assert count >= 2, f"expected multiple global nav destinations, found {count}"
    for i in range(count):
        expect(grail_items.nth(i)).to_be_visible()

    _assert_no_page_errors(page_errors)
    assert failed_requests == [], f"failed network requests on initial load: {failed_requests}"


def test_click_through_every_nav_tab_switches_panel_with_no_errors(console_page):
    """Task 2 + Task 3: clicking through every top-level nav tab switches the
    visible panel and each panel renders non-empty content, discovered live
    from the DOM rather than a hardcoded list. Zero uncaught JS errors and
    zero failed network requests across the whole walk — the single
    highest-value assertion here, since it is what catches a console that
    renders blank.
    """
    page, page_errors, failed_requests = console_page

    visited = set()

    grail_links = _discover_nav_links(page, "#global-rail a[onclick]")
    assert grail_links, "expected at least one global-rail nav link"

    for link in grail_links:
        page.locator(f"#{link['id']}").click()
        _assert_panel_active_and_nonempty(page, link["section"])
        visited.add(link["section"])

        # Whichever context-nav group this destination revealed (ops or
        # admin — see _applyContextNav in console.html), click through every
        # link now visible inside it.
        for group_id in ("nav-section-ops", "nav-section-admin"):
            group = page.locator(f"#{group_id}")
            classes = group.get_attribute("class") or ""
            if "active" not in classes.split():
                continue
            for sub in _discover_nav_links(page, f"#{group_id} a[onclick]"):
                page.locator(f"#{sub['id']}").click()
                _assert_panel_active_and_nonempty(page, sub["section"])
                visited.add(sub["section"])

    assert len(visited) >= MIN_EXPECTED_SECTIONS, (
        f"only reached {len(visited)} distinct sections ({sorted(visited)}); "
        f"expected at least {MIN_EXPECTED_SECTIONS} — a nav link may be dead"
    )

    _assert_no_page_errors(page_errors)
    assert failed_requests == [], f"failed network requests during nav walk: {failed_requests}"


def test_create_credential_via_ui_is_persisted(console_page, dashboard_server, api_headers):
    """Task 4: a real end-to-end mutation performed by clicking real UI
    controls (Operations -> Credentials -> Add credential -> Save),
    then verified independently by reading the API afterwards — not by
    calling the API from inside the test to perform the mutation itself.

    /api/credentials writes straight to the local sqlite DB (no proxy to
    the external Go API), so it's safe and self-contained for this harness.
    """
    page, page_errors, failed_requests = console_page

    cred_name = "PAT-1021 E2E Test Credential"
    cred_service = "e2e-test-service"

    # Navigate to Credentials through Operations and its Credentials entry.
    page.locator("#grail-operations").click()
    page.locator("#nav-credentials").click()
    _assert_panel_active_and_nonempty(page, "credentials")

    page.locator("#section-credentials button:has-text('Add credential')").click()
    modal = page.locator("#modal-credential")
    expect(modal).to_be_visible()

    page.locator("#cred-name").fill(cred_name)
    page.locator("#cred-service").fill(cred_service)
    page.locator("#cred-modal-save").click()

    expect(modal).to_be_hidden()
    expect(page.locator("#cred-tbody")).to_contain_text(cred_name)

    # Independent verification: read it back over the real HTTP API (not
    # via the page's own fetch), the same way a script/CI check would.
    resp = requests.get(f"{dashboard_server}/api/credentials", headers=api_headers, timeout=10)
    resp.raise_for_status()
    rows = resp.json()
    matches = [r for r in rows if r["name"] == cred_name and r["service"] == cred_service]
    assert len(matches) == 1, (
        f"expected exactly one persisted credential named {cred_name!r}, "
        f"found {len(matches)} in {rows}"
    )

    _assert_no_page_errors(page_errors)
    assert failed_requests == [], f"failed network requests during credential creation: {failed_requests}"


def test_customer_switcher_shows_degraded_state_when_tenant_list_fails(browser, dashboard_server, api_headers):
    """PAT-1370: templates/console.html's DOMContentLoaded handler used to
    call `_ensureTenants(false).then(_populateSwitcher)` with no `.catch()`,
    so a failing /admin/tenants/overview raised an unhandled promise
    rejection on every page load and left the top-bar customer switcher
    looking identical to "there are genuinely no customers" — no signal to
    the operator that anything had gone wrong.

    This intercepts only /admin/tenants/overview with a real Playwright route
    (not a change to the shared stub backend in conftest.py, which every
    other test in this session also relies on) so the fetch genuinely fails,
    then asserts both halves of the fix: the switcher shows a degraded state
    distinguishable from empty, and no unhandled rejection reaches the page.
    """
    context = browser.new_context(extra_http_headers=api_headers)
    page = context.new_page()

    page_errors = []
    # Playwright's pageerror event fires for unhandled promise rejections as
    # well as uncaught exceptions, matching how PAT-1021's suite already
    # detects the bug this fixes.
    page.on("pageerror", lambda exc: page_errors.append(str(exc)))

    page.route(
        "**/admin/tenants/overview",
        lambda route: route.fulfill(
            status=500,
            content_type="application/json",
            body='{"error": "simulated overview failure for PAT-1370"}',
        ),
    )

    page.goto(f"{dashboard_server}/console")

    switcher = page.locator("#tw-switcher")
    expect(switcher).to_be_disabled()
    expect(switcher).to_contain_text("Customer list unavailable")
    expect(page.locator("#topbar-customer")).to_have_class(re.compile(r"\btopbar-customer--degraded\b"))

    _assert_no_page_errors(page_errors)

    context.close()


def test_new_app_approve_uses_source_tenant_and_preserves_existing_policy_metadata(browser, dashboard_server, api_headers):
    """Exercise the rendered New Apps action, not a copied helper contract."""
    context = browser.new_context(extra_http_headers=api_headers)
    page = context.new_page()
    writes = []

    def tenant_api(route):
        request = route.request
        path = request.url.split("?", 1)[0]
        if path.endswith("/app-policies") and request.method == "GET":
            route.fulfill(status=200, content_type="application/json", body='{"policies":[{"id":7,"name":"Browser Example","platform":"macos","policy":"unapproved","notes":"security exception","min_version":"4.2.0","enforcement_tier":"managed"}]}')
        elif path.endswith("/new-apps"):
            route.fulfill(status=200, content_type="application/json", body='{"new_apps":[{"id":"new-a","name":"Browser Example","platform":"macos"}]}')
        elif path.endswith("/app-policies") and request.method == "PUT":
            writes.append((request.url, request.post_data_json))
            route.fulfill(status=200, content_type="application/json", body="{}")
        elif path.endswith("/new-apps/new-a") and request.method == "PUT":
            route.fulfill(status=200, content_type="application/json", body="{}")
        elif path.endswith("/allowlist/scan"):
            route.fulfill(status=200, content_type="application/json", body='{"apps":[],"summary":{}}')
        else:
            route.fulfill(status=200, content_type="application/json", body="{}")

    page.route("**/admin/tenants/tenant-a/**", tenant_api)
    page.goto(f"{dashboard_server}/console")
    page.evaluate("""() => enterTenant({id:'tenant-a',name:'Tenant A',tier:'patch',device_count:1}, 'software-catalogue')""")
    row = page.locator("#as-tbody .sc-new-app-row")
    expect(row).to_contain_text("Browser Example")
    row.locator(".sc-manage-btn").click()
    row.get_by_role("button", name="Approve", exact=True).click()
    page.wait_for_timeout(100)
    assert len(writes) == 1
    assert writes == [(f"{dashboard_server}/admin/tenants/tenant-a/app-policies", {
        "name": "Browser Example", "platform": "macos", "policy": "approved",
        "notes": "security exception", "min_version": "4.2.0", "enforcement_tier": "managed",
    })]
    context.close()


def test_started_new_app_approval_finishes_for_its_source_tenant_after_switch(browser, dashboard_server, api_headers):
    context = browser.new_context(extra_http_headers=api_headers)
    page = context.new_page()
    page.goto(f"{dashboard_server}/console")
    calls = page.evaluate("""async () => {
      const calls = [];
      let finishPolicy;
      adminFetch = function(url, opts) {
        calls.push({url: url, method: (opts && opts.method) || 'GET'});
        if (url.endsWith('/app-policies') && opts && opts.method === 'PUT') {
          return new Promise(function(resolve) { finishPolicy = resolve; });
        }
        return Promise.resolve({});
      };
      let reloads = 0;
      _scReload = function() { reloads += 1; };
      _napLoad = function() {};
      _consoleState.tenantId = 'tenant-a';
      _apoPolicyFetch = PatchedConsoleGovernance.policyFetchState('tenant-a', 'ready');
      _apoData = [];
      const button = document.createElement('button');
      button.setAttribute('data-tenant-id', 'tenant-a');
      button.setAttribute('data-new-app-id', 'new-a');
      button.setAttribute('data-name', 'Example');
      button.setAttribute('data-platform', 'macos');
      _scNewAppApproveClick(button);
      await Promise.resolve();
      _consoleState.tenantId = 'tenant-b';
      _apoPolicyFetch = PatchedConsoleGovernance.policyFetchState('tenant-b', 'ready');
      finishPolicy({});
      await new Promise(function(resolve) { setTimeout(resolve, 25); });
      return {calls: calls, reloads: reloads};
    }""")
    assert {"url": "/admin/tenants/tenant-a/app-policies", "method": "PUT"} in calls["calls"]
    assert {"url": "/admin/tenants/tenant-a/new-apps/new-a", "method": "PUT"} in calls["calls"]
    assert calls["reloads"] == 0
    context.close()


def test_stale_patch_deploy_navigation_cannot_reach_execution(browser, dashboard_server, api_headers):
    """PAT-1481: a stale execution destination resolves to assurance only."""
    context = browser.new_context(extra_http_headers=api_headers)
    page = context.new_page()
    page_errors = []
    page.on("pageerror", lambda exc: page_errors.append(str(exc)))

    tenant_id = "11111111-1111-4111-8111-111111111111"
    execution_requests = []

    def record_execution_request(route):
        execution_requests.append((route.request.method, route.request.url))
        route.abort()

    page.route(f"**/admin/tenants/{tenant_id}/ring-rollouts", record_execution_request)
    page.goto(f"{dashboard_server}/console")
    page.evaluate("""tenantId => enterTenant({id:tenantId,name:'PAT-1481 Browser Tenant',tier:'patch',device_count:2}, 'patch-deploy')""", tenant_id)

    expect(page.locator("#tab-cve-findings")).to_be_visible()
    expect(page.locator("#tab-cve-findings")).to_contain_text("CVE Findings")
    expect(page.locator("#tab-patch-deploy")).to_be_hidden()
    assert page.locator("button.pd-start-rollout").count() == 0
    assert execution_requests == []
    _assert_no_page_errors(page_errors)
    context.close()
