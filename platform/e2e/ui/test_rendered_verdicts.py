"""
e2e/ui/test_rendered_verdicts.py — PAT-739 Task T6

Playwright rendered-DOM verification: proves the dashboard actually renders
each verdict state correctly in the browser, not just serves correct JSON.

Runner:
    cd e2e/ui
    ../.venv/bin/pytest test_rendered_verdicts.py -v          (if venv at e2e/.venv)
    .venv/bin/pytest test_rendered_verdicts.py -v              (if venv at e2e/ui/.venv)
    python test_rendered_verdicts.py                           (plain Python)

Or from repo root:
    e2e/ui/.venv/bin/pytest e2e/ui/test_rendered_verdicts.py -v
"""

import base64
import hashlib
import hmac as hmacmod
import json
import os
import time
import urllib.error
import urllib.request

import pytest
from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_STATE = os.path.join(_HERE, "..", ".state")
_ARTIFACTS = os.path.join(_HERE, "..", "artifacts", "ui-run1")

DASHBOARD_URL = "http://127.0.0.1:18000"
ADMIN_INTERNAL_URL = "http://127.0.0.1:18081"

# Read runtime state
DASHBOARD_API_KEY = open(os.path.join(_STATE, "DASHBOARD_API_KEY")).read().strip()
TENANT_ID = open(os.path.join(_STATE, "TENANT_ID")).read().strip()
ADMIN_API_TOKEN = open(os.path.join(_STATE, "ADMIN_API_TOKEN")).read().strip()


def _admin_get_ready(path, is_ready, timeout=90):
    """GET an admin endpoint, retrying until it 200s AND is_ready(data) is
    true. Device/rule rows are written asynchronously by the extractor after
    run_matrix.py posts, so a 200 with the row simply not there YET (not a
    connection failure) must also retry, not raise immediately."""
    deadline = time.time() + timeout
    last_err = None
    last_data = None
    while time.time() < deadline:
        req = urllib.request.Request(
            f"{ADMIN_INTERNAL_URL}{path}",
            headers={"Authorization": f"Bearer {ADMIN_API_TOKEN}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            if is_ready(data):
                return data
            last_data = data
        except urllib.error.URLError as e:
            last_err = e
        time.sleep(1)
    if last_err is not None:
        raise RuntimeError(f"admin GET {path} never succeeded: {last_err}")
    raise RuntimeError(f"admin GET {path} never became ready; last response: {last_data}")


# Device IDs — resolved by the deterministic serials run_matrix.py assigns
# (Layer A must have already run against this tenant before this suite runs).
# Device UUIDs are DB-generated (gen_random_uuid()), so they differ on every
# fresh stack and cannot be hardcoded. One GET resolves all 4 serials at once
# — avoids 4 redundant full-list fetches (and up to 4x90s of retries) for
# data that's all in a single response.
_NEEDED_SERIALS = {
    "e2e-a-macos-noncompliant": "DEV_NONCOMPLIANT",
    "e2e-a-macos-compliant": "DEV_COMPLIANT",
    "e2e-a-macos-not_applicable-x86_64": "DEV_X86_64",
    "e2e-a-macos-collector_error": "DEV_COLLECTOR_ERROR",
}


def _all_serials_present(data):
    found = {d.get("serial") for d in data.get("devices", [])}
    return _NEEDED_SERIALS.keys() <= found


_devices_data = _admin_get_ready(
    f"/admin/tenants/{TENANT_ID}/devices", _all_serials_present
)
_devices_by_serial = {d["serial"]: d["id"] for d in _devices_data["devices"]}
DEV_NONCOMPLIANT    = _devices_by_serial["e2e-a-macos-noncompliant"]
DEV_COMPLIANT       = _devices_by_serial["e2e-a-macos-compliant"]
DEV_X86_64          = _devices_by_serial["e2e-a-macos-not_applicable-x86_64"]
DEV_COLLECTOR_ERROR = _devices_by_serial["e2e-a-macos-collector_error"]

# Rule keys we assert on
RULE_FILEVAULT   = "cis_macos_2_5_1_1_filevault"
RULE_SECUREBOOT  = "cis_macos_5_x_secure_boot_arm64"

# T2 rule to toggle during manage-controls test (first macos T2 rule).
# compliance_rules.id is likewise DB-generated — resolve by rule_key.
TOGGLE_RULE_KEY = "cis_macos_1_2_update_check_auto"
_rules_data = _admin_get_ready(
    f"/admin/tenant-rules/{TENANT_ID}",
    lambda data: any(r.get("rule_key") == TOGGLE_RULE_KEY for r in data.get("rules", [])),
)
TOGGLE_RULE_ID = next(
    r["rule_id"] for r in _rules_data["rules"] if r["rule_key"] == TOGGLE_RULE_KEY
)

os.makedirs(_ARTIFACTS, exist_ok=True)


# ---------------------------------------------------------------------------
# Session cookie helpers
# ---------------------------------------------------------------------------

def _session_encode(email: str = "dev@local", ttl: int = 43200) -> str:
    """Mint a patched_session cookie value using the same HMAC algorithm as main.py."""
    expiry = int(time.time()) + ttl
    payload = f"{email}|{expiry}"
    b = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    mac = hmacmod.new(
        DASHBOARD_API_KEY.encode(), b.encode(), hashlib.sha256
    ).hexdigest()
    return f"{b}.{mac}"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def browser():
    with sync_playwright() as pw:
        b = pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        yield b
        b.close()


@pytest.fixture(scope="session")
def context(browser: Browser):
    """Browser context with the dashboard session cookie pre-injected."""
    ctx = browser.new_context(
        base_url=DASHBOARD_URL,
        ignore_https_errors=True,
    )
    # Inject a valid patched_session cookie directly — avoids any Secure-over-HTTP
    # edge-cases in headless Chromium when the server sets it on /console load.
    ctx.add_cookies([{
        "name": "patched_session",
        "value": _session_encode(),
        "domain": "127.0.0.1",
        "path": "/",
        "httpOnly": True,
        "secure": False,   # http only — the context is already local
        "sameSite": "Lax",
    }])
    yield ctx
    ctx.close()


@pytest.fixture
def page(context: BrowserContext):
    """Fresh page per test, reusing the authenticated context."""
    p = context.new_page()
    p.set_default_timeout(30_000)
    yield p
    p.close()


# ---------------------------------------------------------------------------
# Navigation helpers
# ---------------------------------------------------------------------------

def _nav_to_device_health(page: Page, tenant_id: str = TENANT_ID):
    """Navigate to the tenant device-health tab and wait for table rows."""
    url = f"{DASHBOARD_URL}/console#tenant/{tenant_id}/device-health"
    page.goto(url, wait_until="domcontentloaded")
    # Wait for the device health table to be populated
    page.wait_for_selector("#dh-tbody tr", timeout=25_000)


def _nav_to_device_detail(page: Page, device_id: str, tenant_id: str = TENANT_ID):
    """Navigate to a specific device's detail panel via JS call."""
    # First navigate to the tenant workspace so _consoleState is populated
    _nav_to_device_health(page, tenant_id)
    # Navigate to device detail via the console's routing function
    page.evaluate(
        "function(did) { consoleNav('device-detail', { deviceId: did }); }",
        device_id,
    )
    # Wait for content to appear
    page.wait_for_selector("#device-detail-content", state="visible", timeout=20_000)
    page.wait_for_selector("#dd-eval-fails-view", state="attached", timeout=10_000)


def _screenshot(page: Page, name: str):
    path = os.path.join(_ARTIFACTS, f"{name}.png")
    page.screenshot(path=path, full_page=True)
    return path


def _find_eval_row_by_rule_key(page: Page, rule_key: str, table_id: str = "dd-eval-fail-tbody"):
    """Return the <tr> locator that contains the given rule_key span in the specified table.

    The device detail has two tables: #dd-eval-fail-tbody (fail/error only, default view)
    and #dd-eval-tbody (all rows, shown after 'Show all' toggle).  Scoping prevents
    Playwright strict-mode violations when both tables are in the DOM simultaneously.
    """
    return page.locator(f"#{table_id} tr:has(span.rule-key-mono:text-is('{rule_key}'))")


# ---------------------------------------------------------------------------
# Assertion 1 — Device Detail: verdict cell rendering per device
# ---------------------------------------------------------------------------

class TestDeviceDetailVerdicts:

    def test_noncompliant_filevault_fail(self, page: Page):
        """e2e-a-macos-noncompliant: filevault row renders s-fail with ✗."""
        _nav_to_device_detail(page, DEV_NONCOMPLIANT)
        # The fail view is shown by default — filevault should be there
        row = _find_eval_row_by_rule_key(page, RULE_FILEVAULT)
        row.wait_for(state="visible", timeout=10_000)
        status_cell = row.locator("span.eval-status")
        assert "s-fail" in status_cell.get_attribute("class"), \
            f"Expected s-fail class, got: {status_cell.get_attribute('class')}"
        # ✗ is HTML entity &#10007; = U+2717 ✗
        text = status_cell.inner_text()
        assert "✗" in text or "Fail" in text, \
            f"Expected ✗ or Fail in text, got: {repr(text)}"
        _screenshot(page, "01a_noncompliant_filevault_fail")

    def test_compliant_filevault_pass(self, page: Page):
        """e2e-a-macos-compliant: filevault row renders s-pass with ✓ (show-all required)."""
        _nav_to_device_detail(page, DEV_COMPLIANT)
        # Default view shows fail/error only; compliant device has none, so
        # the toggle button exists and we click 'Show all' to reveal pass rows.
        toggle_btn = page.locator("#dd-eval-toggle")
        toggle_btn.wait_for(state="visible", timeout=10_000)
        # Click 'Show all' to reveal the full table
        toggle_btn.click()
        # Wait for the full view to appear
        page.wait_for_selector("#dd-eval-full-view", state="visible", timeout=5_000)
        # Full view is #dd-eval-tbody
        row = _find_eval_row_by_rule_key(page, RULE_FILEVAULT, "dd-eval-tbody")
        row.wait_for(state="visible", timeout=5_000)
        status_cell = row.locator("span.eval-status")
        assert "s-pass" in status_cell.get_attribute("class"), \
            f"Expected s-pass class, got: {status_cell.get_attribute('class')}"
        text = status_cell.inner_text()
        assert "✓" in text or "Pass" in text, \
            f"Expected ✓ or Pass in text, got: {repr(text)}"
        _screenshot(page, "01b_compliant_filevault_pass")

    def test_x86_64_secureboot_not_applicable(self, page: Page):
        """e2e-a-macos-not_applicable-x86_64: secure-boot row renders s-na with —."""
        _nav_to_device_detail(page, DEV_X86_64)
        # The secure-boot rule is not_applicable. The fail view shows only fail/error,
        # so not_applicable rows are excluded. We must click 'Show all' to see them.
        toggle_btn = page.locator("#dd-eval-toggle")
        toggle_btn.wait_for(state="visible", timeout=10_000)
        toggle_btn.click()
        page.wait_for_selector("#dd-eval-full-view", state="visible", timeout=5_000)
        # Full view is #dd-eval-tbody
        row = _find_eval_row_by_rule_key(page, RULE_SECUREBOOT, "dd-eval-tbody")
        row.wait_for(state="visible", timeout=5_000)
        status_cell = row.locator("span.eval-status")
        cls = status_cell.get_attribute("class")
        assert "s-na" in cls, \
            f"Expected s-na class, got: {cls}"
        text = status_cell.inner_text()
        # — is &#8212; (em-dash) or 'N/A'
        assert "—" in text or "N/A" in text, \
            f"Expected — or N/A in text, got: {repr(text)}"
        _screenshot(page, "01c_x86_64_secureboot_na")

    def test_collector_error_has_error_row(self, page: Page):
        """e2e-a-macos-collector_error: at least one s-error row renders in fail view."""
        _nav_to_device_detail(page, DEV_COLLECTOR_ERROR)
        # Error evals appear in the fail view by default
        page.wait_for_selector("#dd-eval-fail-tbody tr", timeout=10_000)
        error_cells = page.locator("span.eval-status.s-error")
        count = error_cells.count()
        assert count > 0, f"Expected at least one s-error cell, found {count}"
        # Check the icon: ⚠ is &#9888; = U+26A0 ⚠
        first_text = error_cells.first.inner_text()
        assert "⚠" in first_text or "Error" in first_text, \
            f"Expected ⚠ or Error in error cell text, got: {repr(first_text)}"
        _screenshot(page, "01d_collector_error_error_row")


# ---------------------------------------------------------------------------
# Assertion 2 — Compliance bar: counts match evaluations JSON
# ---------------------------------------------------------------------------

class TestComplianceBar:

    def test_noncompliant_compliance_bar_matches_api(self, page: Page):
        """Compliance bar shows correct counts matching the API JSON."""
        # Load expected counts from the device's evaluations artifact
        artifact = os.path.join(
            _HERE, "..", "artifacts", "layer-a-run1", "devices",
            "e2e-a-macos-noncompliant.evaluations.json",
        )
        with open(artifact) as f:
            data = json.load(f)
        comp = data["compliance"]
        expected = {
            "total": comp["total"],
            "pass": comp["pass"],
            "fail": comp["fail"],
            "not_applicable": comp["not_applicable"],
            "error": comp["error"],
        }

        _nav_to_device_detail(page, DEV_NONCOMPLIANT)
        bar = page.locator("#dd-compliance-bar")
        bar.wait_for(state="visible", timeout=10_000)

        # Extract the rendered numbers from compliance-stat-val elements
        stat_labels = bar.locator(".compliance-stat-label").all_inner_texts()
        stat_vals   = bar.locator(".compliance-stat-val").all_inner_texts()
        rendered = dict(zip(
            [l.strip().lower().replace(" ", "_") for l in stat_labels],
            [v.strip() for v in stat_vals],
        ))

        # Assertions per stat
        for key, exp_val in expected.items():
            label = key.replace("_", " ").title() if key != "not_applicable" else "N/A"
            label_key = key if key != "not_applicable" else "n/a"
            rendered_val = rendered.get(label_key) or rendered.get(key) or rendered.get(label.lower())
            assert rendered_val == str(exp_val), \
                f"Compliance bar mismatch for {key}: expected {exp_val}, rendered {rendered_val}. Full rendered: {rendered}"

        _screenshot(page, "02_compliance_bar_noncompliant")

    def test_compliant_compliance_bar_all_pass(self, page: Page):
        """Compliance bar for compliant device shows 92 total pass, 0 fail."""
        artifact = os.path.join(
            _HERE, "..", "artifacts", "layer-a-run1", "devices",
            "e2e-a-macos-compliant.evaluations.json",
        )
        with open(artifact) as f:
            data = json.load(f)
        comp = data["compliance"]

        _nav_to_device_detail(page, DEV_COMPLIANT)
        bar = page.locator("#dd-compliance-bar")
        bar.wait_for(state="visible", timeout=10_000)

        stat_labels = bar.locator(".compliance-stat-label").all_inner_texts()
        stat_vals   = bar.locator(".compliance-stat-val").all_inner_texts()
        rendered = dict(zip(
            [l.strip().lower() for l in stat_labels],
            [v.strip() for v in stat_vals],
        ))

        # Total must match
        assert rendered.get("total") == str(comp["total"]), \
            f"Total mismatch: {rendered.get('total')} vs {comp['total']}"
        # Fail must be 0
        assert rendered.get("fail") == "0", \
            f"Fail must be 0 on compliant device, got: {rendered.get('fail')}"
        assert rendered.get("pass") == str(comp["pass"]), \
            f"Pass mismatch: {rendered.get('pass')} vs {comp['pass']}"

        _screenshot(page, "02b_compliance_bar_compliant")


# ---------------------------------------------------------------------------
# Assertion 3 — CIS Controls tab: per-rule rows + filevault drill-in
# ---------------------------------------------------------------------------

class TestCISControlsTab:

    def _nav_to_cis_controls(self, page: Page):
        url = f"{DASHBOARD_URL}/console#tenant/{TENANT_ID}/cis-controls"
        page.goto(url, wait_until="domcontentloaded")
        # Wait for CIS table wrapper to appear (means data is loaded)
        page.wait_for_selector("#cis-table-wrap", state="visible", timeout=30_000)
        page.wait_for_selector("#cis-tbody tr", timeout=20_000)

    def test_cis_controls_has_rule_rows(self, page: Page):
        """CIS Controls tab renders per-rule rows with pass-%."""
        self._nav_to_cis_controls(page)
        rows = page.locator("#cis-tbody tr")
        count = rows.count()
        assert count > 0, "No rows in CIS controls table"
        # Each row should have a pass-% column
        first_row = rows.first
        # The row has 7 td cells: severity, title+key, platform, pass, fail, pct-bar, details-btn
        tds = first_row.locator("td")
        assert tds.count() >= 6, f"Expected at least 6 columns, got {tds.count()}"
        _screenshot(page, "03a_cis_controls_rows")

    def test_cis_controls_filevault_row_present(self, page: Page):
        """Filevault rule appears in CIS Controls table."""
        self._nav_to_cis_controls(page)
        filevault_row = page.locator(
            f"#cis-tbody tr[data-rule-key='{RULE_FILEVAULT}']"
        )
        filevault_row.wait_for(state="visible", timeout=10_000)
        # Fail count should be > 0 (multiple e2e devices fail filevault)
        row_cells = filevault_row.locator("td")
        # Cells: sev, title/key, platform, pass count (green), fail count (red), pct-bar, details
        # fail count is 4th cell (index 4, 0-based) — but let's find it by color or position
        # The fail cell has color var(--red) per the rendering code
        fail_cell_text = row_cells.nth(4).inner_text().strip()
        assert fail_cell_text.isdigit() and int(fail_cell_text) > 0, \
            f"Expected positive fail count in CIS filevault row, got: {repr(fail_cell_text)}"
        _screenshot(page, "03b_cis_filevault_row")

    def test_cis_controls_filevault_drill_in(self, page: Page):
        """Clicking filevault row opens drill-in showing failing devices."""
        self._nav_to_cis_controls(page)
        filevault_row = page.locator(
            f"#cis-tbody tr[data-rule-key='{RULE_FILEVAULT}']"
        )
        filevault_row.wait_for(state="visible", timeout=10_000)
        filevault_row.click()
        # Detail panel should appear
        detail_card = page.locator("#cis-detail-card")
        detail_card.wait_for(state="visible", timeout=10_000)
        # The detail card should mention the rule title
        detail_text = detail_card.inner_text()
        assert "FileVault" in detail_text, \
            f"Expected 'FileVault' in detail card, got: {repr(detail_text[:200])}"
        # The device list (failing devices) should also be rendered
        page.wait_for_selector("#cis-detail", state="visible", timeout=5_000)
        _screenshot(page, "03c_cis_filevault_drilldown")


# ---------------------------------------------------------------------------
# Assertion 4 — Compliance Status tab: badge renders with numeric %
# ---------------------------------------------------------------------------

class TestComplianceStatusTab:

    def test_compliance_status_badge_renders(self, page: Page):
        """Compliance Status tab renders a badge (pass/partial/fail) with numeric %."""
        url = f"{DASHBOARD_URL}/console#tenant/{TENANT_ID}/compliance-status"
        page.goto(url, wait_until="domcontentloaded")
        # Wait for the content section to appear
        page.wait_for_selector("#cs-content", state="visible", timeout=30_000)
        # Wait for the badge element
        badge_el = page.locator("#cs-cis-badge")
        badge_el.wait_for(state="visible", timeout=15_000)
        badge_span = badge_el.locator("span.cs-badge")
        badge_span.wait_for(state="visible", timeout=5_000)
        badge_cls = badge_span.get_attribute("class")
        assert any(c in badge_cls for c in ["badge-pass", "badge-partial", "badge-fail"]), \
            f"Expected badge-pass/partial/fail class, got: {badge_cls}"
        badge_text = badge_span.inner_text()
        # Should contain a number followed by "%" — e.g. "23.0% passing"
        assert "%" in badge_text, \
            f"Expected % in badge text, got: {repr(badge_text)}"
        # Extract the numeric part
        import re
        nums = re.findall(r"\d+\.?\d*", badge_text)
        assert nums, f"No numeric value found in badge text: {repr(badge_text)}"
        pct = float(nums[0])
        assert 0 <= pct <= 100, f"Compliance % out of range: {pct}"
        _screenshot(page, "04_compliance_status_badge")

    def test_compliance_status_badge_matches_tenant_pct(self, page: Page):
        """Badge numeric % matches the tenant overview API's compliance_pct."""
        import json as _json
        import re
        import urllib.request
        req = urllib.request.Request(
            f"{DASHBOARD_URL}/admin/tenants/overview",
            headers={"Authorization": f"Bearer {DASHBOARD_API_KEY}"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            tenants = _json.loads(resp.read())["tenants"]
        tenant = next((t for t in tenants if t["id"] == TENANT_ID), None)
        assert tenant, "e2e tenant not found in overview"
        expected_pct = round(tenant["compliance_pct"], 1)

        url = f"{DASHBOARD_URL}/console#tenant/{TENANT_ID}/compliance-status"
        page.goto(url, wait_until="domcontentloaded")
        page.wait_for_selector("#cs-content", state="visible", timeout=30_000)
        badge_span = page.locator("#cs-cis-badge span.cs-badge")
        badge_span.wait_for(state="visible", timeout=15_000)
        badge_text = badge_span.inner_text()
        nums = re.findall(r"\d+\.?\d*", badge_text)
        rendered_pct = float(nums[0])
        assert abs(rendered_pct - expected_pct) < 1.0, \
            f"Badge pct {rendered_pct}% does not match API pct {expected_pct}%"
        _screenshot(page, "04b_compliance_status_pct_match")


# ---------------------------------------------------------------------------
# Assertion 5 — Fleet/customers list: e2e tenant row shows compliance_pct
# ---------------------------------------------------------------------------

class TestFleetCustomersList:

    def test_customers_list_shows_compliance_pct(self, page: Page):
        """e2e-local tenant row in customers list renders a compliance_pct value."""
        url = f"{DASHBOARD_URL}/console#customers-list"
        page.goto(url, wait_until="domcontentloaded")
        # Wait for the customers list to load
        page.wait_for_selector("#cl-content table", timeout=25_000)
        # Find the e2e-local tenant row
        rows = page.locator("#cl-content tbody tr")
        rows.first.wait_for(state="visible", timeout=10_000)
        count = rows.count()
        assert count > 0, "No tenant rows in customers list"

        # Find the row containing "e2e-local"
        e2e_row = None
        for i in range(count):
            row = rows.nth(i)
            text = row.inner_text()
            if "e2e-local" in text:
                e2e_row = row
                break
        assert e2e_row is not None, \
            f"Could not find 'e2e-local' row in customers list. Rows found: {count}"

        # The CIS posture column should have a % value
        row_text = e2e_row.inner_text()
        assert "%" in row_text, \
            f"Expected compliance % in e2e-local row, got: {repr(row_text)}"
        _screenshot(page, "05_customers_list_compliance_pct")

    def test_fleet_view_compliance_pct(self, page: Page):
        """Fleet view (#fleet): e2e-local row renders compliance_pct.

        Structural note: the hash `#fleet` does not directly activate the fleet section
        (the DOMContentLoaded handler only handles 'tenant/...' and 'customers-list'
        hashes; everything else falls to 'home').  We navigate to the console, wait for
        it to initialise, then call consoleNav('fleet') via JS to activate the view.

        NOTE (FINDING): console.html ~line 5400 chains .then(r => r.json()) on
        adminFetch() which already resolves to a parsed JS object.  Whether r.json()
        throws or returns undefined depends on the JS engine; in Chromium it throws
        TypeError, which causes Promise.all to reject, the catch handler fires, and
        the fleet error div becomes visible.  We handle both outcomes.
        """
        # Navigate to console (not the fleet hash — that lands on home per the init logic)
        page.goto(f"{DASHBOARD_URL}/console", wait_until="domcontentloaded")
        # Wait for page to be initialised (sidebar should be visible)
        page.wait_for_selector("#sidebar-app-nav", state="visible", timeout=15_000)

        # Activate the fleet section via the JS routing function
        page.evaluate("consoleNav('fleet')")

        # Wait for the fleet loading spinner to appear then disappear
        # (confirming that _loadFleet() was called and its async work completed)
        page.wait_for_selector("#fleet-loading", state="visible", timeout=10_000)
        page.wait_for_selector("#fleet-loading", state="hidden", timeout=25_000)

        _screenshot(page, "05b_fleet_view")

        # Determine what rendered
        tbl = page.locator("#fleet-tenants-table table")
        err = page.locator("#fleet-error")
        table_visible = tbl.count() > 0 and tbl.first.is_visible()
        error_visible  = err.count() > 0 and err.first.is_visible()

        if table_visible:
            # Fleet rendered correctly — assert e2e-local row shows compliance %
            rows = page.locator("#fleet-tenants-table tbody tr")
            count = rows.count()
            e2e_row = None
            for i in range(count):
                row = rows.nth(i)
                if "e2e-local" in row.inner_text():
                    e2e_row = row
                    break
            assert e2e_row is not None, \
                f"Could not find 'e2e-local' in fleet table ({count} rows)"
            assert "%" in e2e_row.inner_text(), \
                f"Expected % in e2e-local fleet row: {repr(e2e_row.inner_text())}"

        elif error_visible:
            # Fleet shows an error — the known double-.json() bug (PAT-747).
            # Accepting ANY error text here would be a vacuous pass, so xfail:
            # this test starts asserting the table as soon as PAT-747 is fixed.
            err_text = err.first.inner_text()
            _screenshot(page, "05b_fleet_stuck_loading")
            pytest.xfail(
                f"Fleet view broken by double-.json() bug (PAT-747): {err_text!r}"
            )

        else:
            _screenshot(page, "05b_fleet_unexpected_state")
            raise AssertionError(
                "Fleet view: loading spinner finished but neither table nor error appeared. "
                f"table_visible={table_visible}, error_visible={error_visible}. "
                "Customers-list compliance_pct verified in test_customers_list_shows_compliance_pct."
            )


# ---------------------------------------------------------------------------
# Assertion 6 — Manage Controls: T1 locked, T2 toggle, PUT fires, restore
# ---------------------------------------------------------------------------

class TestManageControls:

    def _nav_to_cis_list(self, page: Page):
        url = f"{DASHBOARD_URL}/console#tenant/{TENANT_ID}/cis-controls"
        page.goto(url, wait_until="domcontentloaded")
        page.wait_for_selector("#cis-table-wrap", state="visible", timeout=30_000)

    def test_manage_controls_panel_opens(self, page: Page):
        """Manage Controls panel opens when the gear button is clicked."""
        self._nav_to_cis_list(page)
        # Click the 'Manage controls' button (⚙)
        manage_btn = page.locator("button:has-text('Manage controls')")
        manage_btn.wait_for(state="visible", timeout=10_000)
        manage_btn.click()
        # Manage panel should appear, list/detail should hide
        manage_panel = page.locator("#cis-manage")
        manage_panel.wait_for(state="visible", timeout=10_000)
        # Body should have content
        page.wait_for_selector("#cis-manage-body .cis-manage-platform", timeout=15_000)
        _screenshot(page, "06a_manage_controls_panel")

    def test_t1_rules_are_locked(self, page: Page):
        """T1 rules render with the '🔒 Always on' lock indicator."""
        self._nav_to_cis_list(page)
        page.locator("button:has-text('Manage controls')").click()
        page.wait_for_selector("#cis-manage-body .cis-manage-platform", timeout=15_000)
        # T1 rules should render the cis-alwayson span
        always_on = page.locator("span.cis-alwayson")
        count = always_on.count()
        assert count > 0, "Expected at least one 'Always on' T1 rule indicator"
        first_text = always_on.first.inner_text()
        assert "Always on" in first_text, \
            f"Expected 'Always on' text, got: {repr(first_text)}"
        _screenshot(page, "06b_t1_locked")

    def test_t2_toggle_off_and_restore(self, page: Page):
        """Toggle a T2 rule OFF, assert PUT fires + state changes, then restore ON."""
        self._nav_to_cis_list(page)
        page.locator("button:has-text('Manage controls')").click()
        page.wait_for_selector("#cis-manage-body .cis-manage-platform", timeout=15_000)

        # The toggle checkbox is CSS-hidden (opacity:0; width:0; height:0 in console.css).
        # We interact via the sibling <span class="toggle-slider"> inside the <label>,
        # which is the visible affordance.  The hidden input is used only to read state.
        toggle_id = f"cistog-{TOGGLE_RULE_ID}"
        toggle_input = page.locator(f"#{toggle_id}")
        # Wait for the input to be attached (it's hidden, not absent)
        toggle_input.wait_for(state="attached", timeout=10_000)

        # Verify it's currently checked (enabled) — check the DOM property directly
        assert toggle_input.is_checked(), \
            f"Toggle {toggle_id} should be checked (enabled) initially"

        # The toggle_wrap locator for the "On/Off" label
        toggle_wrap = toggle_input.locator(
            "xpath=ancestor::div[contains(@class,'update-toggle-wrap')]"
        )
        # CSS text-transform:uppercase is applied to .toggle-label, so inner_text()
        # returns "ON" / "OFF" even though the DOM text is "On" / "Off".
        label_before = toggle_wrap.locator(".toggle-label").inner_text().strip().upper()
        assert label_before == "ON", f"Expected label 'ON' (or 'On'), got {repr(label_before)}"

        # Click the visible toggle-slider span to trigger the change event on the input.
        # The slider is a sibling of the hidden input inside the <label>.
        slider = toggle_input.locator("xpath=following-sibling::span[contains(@class,'toggle-slider')]")
        slider.wait_for(state="visible", timeout=5_000)

        # Capture network requests to verify PUT fires
        with page.expect_request(
            lambda req: (
                "/admin/tenant-rules/" in req.url
                and req.method == "PUT"
            ),
            timeout=10_000,
        ) as req_info:
            slider.click()

        # Wait for the request to complete and verify it succeeded
        req = req_info.value
        resp = req.response()
        assert resp.ok, f"PUT request failed: {resp.status}"
        # Wait briefly for optimistic UI update to propagate
        page.wait_for_timeout(500)

        # Assert toggle is now unchecked and label is 'Off'
        assert not toggle_input.is_checked(), "Toggle should be unchecked after clicking"
        label_after = toggle_wrap.locator(".toggle-label").inner_text().strip().upper()
        assert label_after == "OFF", f"Expected label 'OFF' (or 'Off') after unchecking, got {repr(label_after)}"
        _screenshot(page, "06c_t2_toggled_off")

        # ── Restore: click slider again to toggle back ON ────────────────────
        with page.expect_request(
            lambda req: (
                "/admin/tenant-rules/" in req.url
                and req.method == "PUT"
            ),
            timeout=10_000,
        ) as req_info2:
            slider.click()

        resp2 = req_info2.value.response()
        assert resp2.ok, f"Restore PUT request failed: {resp2.status}"
        page.wait_for_timeout(500)

        assert toggle_input.is_checked(), "Toggle should be checked after restoring"
        label_restored = toggle_wrap.locator(".toggle-label").inner_text().strip().upper()
        assert label_restored == "ON", \
            f"Expected label 'ON' (or 'On') after restoring, got {repr(label_restored)}"
        _screenshot(page, "06d_t2_toggled_restored")

        # ── Final verification via GET /admin/tenant-rules ───────────────────
        import json as _json
        import urllib.request
        req2 = urllib.request.Request(
            f"{DASHBOARD_URL}/admin/tenant-rules/{TENANT_ID}",
            headers={"Authorization": f"Bearer {DASHBOARD_API_KEY}"},
        )
        with urllib.request.urlopen(req2, timeout=10) as r:
            rules = _json.loads(r.read())["rules"]
        toggle_rule = next((r for r in rules if r["rule_id"] == TOGGLE_RULE_ID), None)
        assert toggle_rule is not None, f"Rule {TOGGLE_RULE_ID} not found in GET response"
        assert toggle_rule["enabled"] is True, \
            f"Rule should be restored to enabled=True, got enabled={toggle_rule['enabled']}"


# ---------------------------------------------------------------------------
# Plain-Python runner (no pytest required)
# ---------------------------------------------------------------------------

def _run_all_plain():
    """Run all tests without pytest — for `python test_rendered_verdicts.py`."""
    import traceback
    results = {}

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        ctx = browser.new_context(
            base_url=DASHBOARD_URL,
            ignore_https_errors=True,
        )
        ctx.add_cookies([{
            "name": "patched_session",
            "value": _session_encode(),
            "domain": "127.0.0.1",
            "path": "/",
            "httpOnly": True,
            "secure": False,
            "sameSite": "Lax",
        }])

        test_classes = [
            TestDeviceDetailVerdicts,
            TestComplianceBar,
            TestCISControlsTab,
            TestComplianceStatusTab,
            TestFleetCustomersList,
            TestManageControls,
        ]

        for cls in test_classes:
            inst = cls()
            test_methods = [m for m in dir(inst) if m.startswith("test_")]
            for method_name in test_methods:
                method = getattr(inst, method_name)
                pg = ctx.new_page()
                pg.set_default_timeout(30_000)
                label = f"{cls.__name__}.{method_name}"
                try:
                    method(pg)
                    results[label] = "PASS"
                    print(f"  PASS  {label}")
                except Exception as e:
                    results[label] = f"FAIL: {e}"
                    print(f"  FAIL  {label}")
                    traceback.print_exc()
                finally:
                    pg.close()

        ctx.close()
        browser.close()

    print("\n── Summary ──────────────────────────────────────────────────────")
    passes = [k for k, v in results.items() if v == "PASS"]
    fails  = [k for k, v in results.items() if v != "PASS"]
    print(f"  {len(passes)}/{len(results)} tests passed")
    for k in fails:
        print(f"  FAIL  {k}: {results[k]}")
    return len(fails) == 0


if __name__ == "__main__":
    import sys
    ok = _run_all_plain()
    sys.exit(0 if ok else 1)
