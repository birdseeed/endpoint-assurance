"""Production template/scripts in real Chromium, fully offline response fixtures.

Run explicitly with Playwright installed. No preview or invented future helper API.
"""
import copy
import json
import mimetypes
import re
from pathlib import Path
from urllib.parse import urlparse

import jinja2
import pytest
from tests.pat1966_support import CATEGORIES, PROXY, ROOT, assert_owner, feed

ORIGIN = "http://127.0.0.1:1966"
ATTACK = "<img data-pat1966-injected src=x onerror=window.__pat1966Injected=true>"


@pytest.fixture(scope="module")
def chromium():
    from playwright.sync_api import sync_playwright, expect
    expect.set_options(timeout=1200)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        yield browser
        browser.close()


@pytest.fixture
def visit(chromium):
    contexts = []
    violations = []
    def open_page(body=None, status=200, role="owner", width=1440, theme="light", hold=False):
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(ROOT / "templates"), autoescape=True)
        markup = env.get_template("console.html").render(
            console_build_id="pat1966-offline-test", env="local", api_backend="loopback fixture",
            role=role, actor_email=role + "@example.test", device_freshness={"active_max_days": 7, "silent_min_days": 30},
            impersonation=None, imp_expired=False,
        )
        context = chromium.new_context(viewport={"width": width, "height": 1000}, color_scheme=theme)
        contexts.append(context)
        context.add_init_script("localStorage.setItem('patched-theme', " + json.dumps(theme) + ");")
        state = {"body": copy.deepcopy(body if body is not None else feed()), "status": status,
                 "requests": [], "pending": [], "hold": hold}
        def guard(route):
            req = route.request
            parsed = urlparse(req.url)
            state["requests"].append((req.method, parsed.path))
            if not req.url.startswith(ORIGIN + "/") or req.method != "GET":
                violations.append((req.method, req.url))
                route.abort()
                return
            if parsed.path == "/console" or parsed.path.startswith("/console/"):
                route.fulfill(status=200, content_type="text/html", body=markup)
            elif parsed.path.startswith("/static/"):
                path = (ROOT / parsed.path.lstrip("/")).resolve()
                assert path.is_relative_to((ROOT / "static").resolve())
                if path.is_file():
                    route.fulfill(status=200, content_type=mimetypes.guess_type(path)[0] or "text/plain", body=path.read_bytes())
                else:
                    route.fulfill(status=404, body="missing static source")
            elif parsed.path == PROXY:
                if state["hold"]:
                    state["pending"].append(route)
                else:
                    route.fulfill(status=state["status"], content_type="application/json", body=json.dumps(state["body"]))
            else:
                fixtures = {
                    "/admin/tenants/overview": {"tenants": [{"id": "tenant-posture-only", "name": "Posture-only tenant", "device_count": 2, "critical_cves": 20, "cis_score": 10}]},
                    "/admin/tenants/revoked": {"tenants": []},
                    "/api/home/triage": {"tenants": [{"tenant_id": "tenant-posture-only", "critical_cves": 20}], "patch_stats": {"critical": 20}},
                    "/admin/health/proxy": {"service_health": {}},
                    "/admin/automations": {"jobs": []},
                    "/admin/check-status": {"checks": []},
                }
                route.fulfill(status=200 if parsed.path in fixtures else 503,
                              content_type="application/json", body=json.dumps(fixtures.get(parsed.path, {"error": "Offline source unavailable"})))
        context.route("**/*", guard)
        page = context.new_page()
        page.set_default_timeout(1200)
        page.goto(ORIGIN + "/console/test#home", wait_until="domcontentloaded")
        return page, state
    yield open_page
    for context in contexts:
        context.close()
    assert not violations, "Read-only/global-context guard: " + repr(violations)


def exceptions_region(page):
    from playwright.sync_api import expect
    home = page.locator("#section-home")
    expect(home.get_by_role("heading", name="Service exceptions", exact=True)).to_be_visible()
    return home


def test_browser_harness_control_loads_real_home_and_scripts(visit):
    from playwright.sync_api import expect
    page, state = visit()
    expect(page.locator("#section-home h1")).to_be_visible()
    assert page.evaluate("typeof consoleNav") == "function"
    assert any(path == "/static/js/console-work.js" for _, path in state["requests"])
    assert page.evaluate("window.__ROLE") == "owner"


@pytest.mark.parametrize("width", [1440, 1024])
@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("role", ["owner", "consultant"])
def test_exact_service_exceptions_health_rail_and_layout(visit, width, theme, role):
    from playwright.sync_api import expect
    page, state = visit(width=width, theme=theme, role=role)
    home = exceptions_region(page)
    expect(home.get_by_role("heading", name="Service health", exact=True)).to_be_visible()
    expect(home.get_by_text("Latest recorded job failed. The onset time is unknown.", exact=False)).to_be_visible()
    expect(home.get_by_text("Customer receipt is stale.", exact=False)).to_be_visible()
    expect(home.get_by_role("heading", name="Customer attention", exact=True)).to_have_count(0)
    expect(home.locator('[aria-label="Selected customer"]')).to_have_count(0)
    assert ("GET", PROXY) in state["requests"]
    assert ("GET", "/api/home/triage") not in state["requests"], "Home must stop customer-posture fan-out"
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    assert page.evaluate("window.__ROLE") == role
    assert not home.get_by_text("Posture-only tenant", exact=True).count()
    screenshot = Path("/tmp/pat1966-dashboard-prepare-20261004") / ("home-" + str(width) + "-" + theme + "-" + role + ".png")
    assert_owner()
    page.screenshot(path=str(screenshot), full_page=True)


@pytest.mark.parametrize("key,name", CATEGORIES)
def test_each_category_discloses_purpose_source_time_result_reason_action(visit, key, name):
    from playwright.sync_api import expect
    body = feed(False)
    row = next(c for c in body["checks"] if c["id"] == key)
    row.update(availability="unavailable", result="unavailable", checked_at=None,
               last_success_at=None, next_expected_at=None, observations=[])
    page, _ = visit(body)
    home = exceptions_region(page)
    expect(home.get_by_text(name, exact=True).first).to_be_visible()
    # Disclosures may be collapsed, but every field must be available to the operator.
    for detail in home.locator("details").all():
        detail.evaluate("el => el.open = true")
    for text in (row["explanation"], row["source"], row["scope"], row["reason"], row["next_action"]):
        expect(home.get_by_text(text, exact=False).first).to_be_visible()
    expect(home.get_by_text(re.compile("Not checked|Unknown|Not available", re.I)).first).to_be_visible()
    assert not re.search(r"all (?:services |checks )?healthy", home.inner_text(), re.I)


def test_true_empty_and_partial_coverage_are_separate(visit):
    from playwright.sync_api import expect
    page, _ = visit(feed(False))
    home = exceptions_region(page)
    expect(home.get_by_text(re.compile("no (?:current |recorded |service )?exceptions", re.I)).first).to_be_visible()
    expect(home.get_by_text(re.compile("partial", re.I)).first).to_be_visible()
    assert not re.search(r"all (?:services |checks )?healthy", home.inner_text(), re.I)


@pytest.mark.parametrize("failure", ["http", "malformed"])
def test_error_is_unavailable_not_empty_or_healthy(visit, failure):
    from playwright.sync_api import expect
    page, _ = visit({"error": "source unavailable"} if failure == "http" else {"checks": None}, status=503 if failure == "http" else 200)
    home = exceptions_region(page)
    expect(home.get_by_text(re.compile("unavailable|could not|failed to load", re.I)).first).to_be_visible()
    assert not re.search(r"no (?:current |recorded |service )?exceptions|all .*healthy", home.inner_text(), re.I)


def test_loading_does_not_claim_zero_and_refresh_recovers(visit):
    from playwright.sync_api import expect
    page, state = visit(hold=True)
    home = exceptions_region(page)
    expect(home.get_by_text(re.compile("loading.*exceptions|loading.*service", re.I)).first).to_be_visible()
    assert state["pending"], "Production loader must request the real proxy contract"
    assert not re.search(r"no .*exceptions|all .*healthy", home.inner_text(), re.I)
    state["hold"] = False
    for route in state["pending"]:
        route.fulfill(status=503, content_type="application/json", body='{"error":"source unavailable"}')
    expect(home.get_by_text(re.compile("unavailable|failed to load", re.I)).first).to_be_visible()
    home.get_by_role("button", name=re.compile("refresh|retry", re.I)).first.click()
    expect(home.get_by_text("Latest recorded job failed.", exact=False)).to_be_visible()


def test_escape_hostile_text_safe_keyboard_link_and_no_tenant_signal(visit):
    from playwright.sync_api import expect
    body = feed()
    body["exceptions"][0]["reason"] = ATTACK
    page, state = visit(body)
    home = exceptions_region(page)
    expect(home.get_by_text(ATTACK, exact=False)).to_be_visible()
    assert page.locator("img[data-pat1966-injected]").count() == 0
    assert page.evaluate("window.__pat1966Injected !== true")
    link = home.locator('a[href="/console#automations"]').first
    expect(link).to_be_visible()
    link.focus()
    assert link.evaluate("el => el === document.activeElement")
    outline = link.evaluate("el => getComputedStyle(el).outlineStyle")
    assert outline != "none", "Keyboard focus must be visible"
    link.press("Enter")
    expect(page).to_have_url(re.compile(r"#automations$"))
    assert all(method == "GET" for method, _ in state["requests"])
    assert not any("/signal" in path for _, path in state["requests"])


@pytest.mark.parametrize("value", [None, "not-a-time", "2999-01-01T00:00:00Z"])
def test_invalid_source_evidence_cannot_become_current_failure(visit, value):
    body = feed()
    body["exceptions"][0]["evidence_at"] = value
    page, _ = visit(body)
    home = exceptions_region(page)
    assert not home.get_by_text("Latest recorded job failed. The onset time is unknown.", exact=False).count()
    assert re.search("unknown|unavailable|invalid", home.inner_text(), re.I)


@pytest.mark.parametrize("href", ["javascript:alert(1)", "https://example.invalid/steal", "/console#tenant/other", "/console#future-route"])
def test_unknown_or_unsafe_destinations_never_become_links(visit, href):
    body = feed()
    body["exceptions"][0]["deep_link"] = href
    page, _ = visit(body)
    home = exceptions_region(page)
    assert not any(link.get_attribute("href") == href for link in home.locator("a").all())
    assert not page.evaluate("window.__pat1966Injected === true")


def test_old_receipt_is_evidence_age_not_invented_onset_population_or_next_run(visit):
    from playwright.sync_api import expect
    body = feed()
    page, _ = visit(body)
    home = exceptions_region(page)
    expect(home.get_by_text("Customer receipt is stale.", exact=False)).to_be_visible()
    text = home.inner_text()
    assert re.search("onset.*unknown|since.*unknown|onset.*not known", text, re.I)
    assert not re.search(r"population (?:fell|dropped)|missed .*run|next run in|down for", text, re.I)


def test_actual_evidence_and_per_job_success_times_are_available_separately(visit):
    from playwright.sync_api import expect
    body = feed()
    page, _ = visit(body)
    home = exceptions_region(page)
    for detail in home.locator("details").all():
        detail.evaluate("el => el.open = true")
    for row in body["checks"][1]["observations"]:
        expect(home.get_by_text(row["scope"], exact=False).first).to_be_visible()
        for field in ("evidence_at", "last_success_at"):
            # Standard semantic time markup, not an implementation helper name.
            assert home.locator('time').evaluate_all("(els, value) => els.some(el => el.dateTime === value)", row[field]), field + " must retain the actual per-job source time"
    assert not re.search("all jobs.*(?:healthy|recovered)|restore.*successful", home.inner_text(), re.I)
