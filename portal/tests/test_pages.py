"""Integration tests: portal pages rendered against a stubbed platform API.

The stub asserts the CF Access JWT is forwarded verbatim upstream, and can
simulate upstream 401 (identity rejected) and 503 (portal not enabled).
"""

import copy
import csv
import io
from urllib.parse import quote

import main
from tests.conftest import (
    DEVICE_DETAIL,
    ENROLMENT_TOKEN,
    OVERVIEW,
    PDF_BYTES,
    STREAM_FAIL_ACTUAL_BYTES,
    STREAM_FAIL_DECLARED_LENGTH,
    STUB_STATE,
    TEAM_DOMAIN,
)


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


# ── Fail-closed auth at the portal edge ───────────────────────────────────
def test_no_token_gets_signed_out_401(client):
    """A visitor who has never signed in (no token at all) gets the distinct
    signed-out page, not the session-expired copy meant for a lapsed
    session."""
    resp = client.get("/")
    assert resp.status_code == 401
    assert "sign in to patched" in resp.text.lower()
    assert "session has expired" not in resp.text.lower()


def test_bad_token_gets_session_expired_401(client, make_token):
    resp = _get(client, make_token(exp_delta=-120), "/")
    assert resp.status_code == 401
    assert "session has expired" in resp.text.lower()


def test_bad_token_logs_rejection_reason(client, make_token, caplog):
    # PAT-1221: the access log only ever shows the resulting 401, so the
    # actual verify failure (expired vs bad aud/issuer/key) must be logged
    # or an AUD/config mismatch is indistinguishable from a normal expiry.
    with caplog.at_level("WARNING", logger="portal.auth"):
        resp = _get(client, make_token(exp_delta=-120), "/")
    assert resp.status_code == 401
    assert len(caplog.records) == 1
    assert "/" in caplog.records[0].message
    assert "expired" in caplog.records[0].message.lower()


# ── Nav visibility (PAT-1574) ──────────────────────────────────────────────
# Dead-end pages (signed-out, session-expired, not-linked, not-enabled) hide
# the estate nav since every link on it just leads back to the same error.
# Pages reachable to an authenticated user with a working way forward
# (error.html's 404/429/502 branches included) keep it.
def test_no_token_hides_nav(client):
    resp = client.get("/")
    assert resp.status_code == 401
    assert 'href="/devices"' not in resp.text
    assert 'href="/software"' not in resp.text


def test_bad_token_hides_nav(client, make_token):
    resp = _get(client, make_token(exp_delta=-120), "/")
    assert resp.status_code == 401
    assert 'href="/devices"' not in resp.text
    assert 'href="/software"' not in resp.text


def test_valid_token_shows_nav(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    assert 'href="/devices"' in resp.text
    assert 'href="/software"' in resp.text


def test_rendered_page_prefers_versioned_dashboard_favicon_svg(client, make_token):
    """PAT-1572: retain the ICO fallback, then prefer the shared SVG."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    # PAT-2237: the cache-buster is now the file's own content hash
    # (static_url()) rather than a hand-bumped literal.
    favicon_links = (
        '<link rel="icon" type="image/x-icon" '
        f'href="{main.static_url("favicon.ico")}">\n'
        '<link rel="icon" type="image/svg+xml" '
        f'href="{main.static_url("favicon.svg")}">'
    )
    assert favicon_links in resp.text


def test_not_linked_hides_nav(client, make_token):
    STUB_STATE["mode"] = "forbidden403"
    resp = _get(client, make_token(), "/")
    assert resp.status_code == 403
    assert ">Devices<" not in resp.text


def test_not_enabled_hides_nav(client, make_token):
    STUB_STATE["mode"] = "down503"
    resp = _get(client, make_token(), "/")
    assert resp.status_code == 503
    assert ">Devices<" not in resp.text


def test_error_page_shows_nav(client, make_token):
    """Pins the deliberate exception: an authenticated user hitting the
    generic error.html (here via a malformed upstream findings payload, PAT-
    888) keeps the nav - they have a valid identity and a working way out."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["mode"] = "malformed"
    resp = _get(client, token, "/findings")
    assert resp.status_code != 200
    assert ">Devices<" in resp.text


def test_email_header_alone_is_not_trusted(client):
    resp = client.get(
        "/", headers={"Cf-Access-Authenticated-User-Email": "alice@tenant-a.example"}
    )
    assert resp.status_code == 401


def test_cf_authorization_cookie_accepted(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    client.cookies.set("CF_Authorization", token)
    resp = client.get("/")
    assert resp.status_code == 200


def test_healthz_needs_no_auth(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "deployed_sha": None, "deployed_at": None}


def test_healthz_reports_deployed_sha_once_recorded(client, tmp_path, monkeypatch):
    """PAT-1151: deploy/deploy-portal-01.sh writes DEPLOYED_SHA as the last
    step of a deploy; /healthz must surface it without needing a new route
    (main.py's only unauthenticated paths are /healthz and /static/*)."""
    sha_file = tmp_path / "DEPLOYED_SHA"
    sha_file.write_text("DEPLOYED_SHA=abc1234def5678\nDEPLOYED_AT=2026-08-05T12:00:00Z\n")
    monkeypatch.setattr(main, "DEPLOYED_SHA_FILE", sha_file)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {
        "status": "ok",
        "deployed_sha": "abc1234def5678",
        "deployed_at": "2026-08-05T12:00:00Z",
    }


def test_healthz_deployed_sha_missing_key_line_is_null_not_error(client, tmp_path, monkeypatch):
    sha_file = tmp_path / "DEPLOYED_SHA"
    sha_file.write_text("some unrelated content\n")
    monkeypatch.setattr(main, "DEPLOYED_SHA_FILE", sha_file)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "deployed_sha": None, "deployed_at": None}


# ── Maintenance facts summary (PAT-989) ────────────────────────────────────
# main.py never adds a new route for this - it rides the existing /healthz
# response, same as PAT-1151's deployed_sha did. The bounded "maintenance"
# object is aggregate-only: counts and booleans, never unit names, package
# names, or exact versions (see main.py's _maintenance_info() docstring).
def _write_facts(tmp_path, **overrides):
    import json as _json
    from datetime import UTC as _UTC
    from datetime import datetime as _datetime

    facts = {
        "generated_at": _datetime.now(_UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hostname": "patched-portal-01",
        "pending_updates": 24,
        "security_updates": 2,
        "esm_updates": None,
        "pro_attached": False,
        "reboot_required": True,
        "running_kernel": "7.0.0-15-generic",
        "newest_kernel": "7.0.0-28-generic",
        "automatic_reboot_configured": False,
        "third_party_pending": [
            {
                "package": "tailscale",
                "installed": "1.98.8",
                "candidate": "1.102.2",
                "origin": "pkgs.tailscale.com",
            }
        ],
        "timers": [
            {
                "unit": "patched-portal-backup.timer",
                "enabled": "enabled",
                "last_trigger": "2026-08-06T04:06:08Z",
                "last_result": "success",
            },
            {
                "unit": "hetzner-snapshot.timer",
                "enabled": "disabled",
                "last_trigger": None,
                "last_result": "unknown",
            },
            {
                "unit": "patched-broken.timer",
                "enabled": "enabled",
                "last_trigger": "2026-08-06T03:00:00Z",
                "last_result": "failed",
            },
        ],
    }
    facts.update(overrides)
    facts_file = tmp_path / "maintenance.json"
    facts_file.write_text(_json.dumps(facts))
    return facts_file, facts


def test_healthz_reports_bounded_maintenance_summary_when_facts_fresh(
    client, tmp_path, monkeypatch
):
    facts_file, facts = _write_facts(tmp_path)
    monkeypatch.setattr(main, "MAINTENANCE_FACTS_FILE", facts_file)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["maintenance"] == {
        "generated_at": facts["generated_at"],
        "reboot_required": True,
        "security_updates": 2,
        "esm_updates": None,
        "pro_attached": False,
        "automatic_reboot_configured": False,
        "third_party_pending_count": 1,
        "timers_failed_count": 1,
        "timers_disabled_count": 1,
    }
    # No package names, unit names, or exact versions ever leave the box -
    # only the bounded counts/booleans above. Round-trip through JSON so this
    # checks the actual wire text, not just the parsed structure.
    raw = resp.text
    for leaky in (
        "tailscale",
        "1.98.8",
        "1.102.2",
        "patched-portal-backup",
        "hetzner-snapshot",
        "patched-broken",
        '"third_party_pending":',  # the array key, distinct from the allowed *_count field
        '"timers":',  # the array key, distinct from the allowed timers_*_count fields
        "pending_updates",
        "running_kernel",
        "newest_kernel",
        "hostname",
    ):
        assert leaky not in raw, f"{leaky!r} leaked into the public /healthz body"


def test_healthz_preserves_unknown_pro_attachment_as_null(client, tmp_path, monkeypatch):
    """PAT-1796: an unavailable Pro API must not be recast as detached."""
    facts_file, _ = _write_facts(tmp_path, pro_attached=None)
    monkeypatch.setattr(main, "MAINTENANCE_FACTS_FILE", facts_file)

    resp = client.get("/healthz")

    assert resp.status_code == 200
    assert resp.json()["maintenance"]["pro_attached"] is None


def test_healthz_omits_maintenance_when_facts_file_missing(client, tmp_path, monkeypatch):
    monkeypatch.setattr(main, "MAINTENANCE_FACTS_FILE", tmp_path / "does-not-exist.json")
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert "maintenance" not in body
    assert body == {"status": "ok", "deployed_sha": None, "deployed_at": None}


# ── stray_config_backups / systemd_hardening reduction (PAT-1440) ─────────
# These two fields reached prod-01/api-01's dashboard rows the day they were
# added (PAT-1431/1433, PAT-1237) but never portal-01's -- _maintenance_info
# built an explicit allowlist and silently dropped anything not named in it.
# This block is the fix's behaviour matrix: absence-vs-zero stays
# distinguishable, "not available" stays distinct from "clean scan", and no
# path/filename/unit-name ever reaches the wire. See main.py's
# _stray_config_backups_counts()/_systemd_hardening_counts() docstrings and
# tests/test_pat1440_healthz_projection_parity.py for the drift guard on
# every OTHER field the emitter produces.
def test_healthz_carries_stray_config_backups_and_systemd_hardening_counts(
    client, tmp_path, monkeypatch
):
    facts_file, facts = _write_facts(
        tmp_path,
        stray_config_backups=[
            {
                "path": "/etc/patched-portal/portal.env.bak-pat1",
                "mode": "0644",
                "owner": "root",
                "group": "root",
                "group_readable": True,
                "world_readable": False,
                "mode_unknown": False,
            },
            {
                "path": "/etc/patched-portal/z.env.bak-pat3",
                "mode": "0600",
                "owner": "root",
                "group": "root",
                "group_readable": False,
                "world_readable": False,
                "mode_unknown": False,
            },
            {
                "path": "/etc/patched-portal/unreadable.bak-pat9",
                "mode": "unknown",
                "owner": "unknown",
                "group": "unknown",
                "group_readable": None,
                "world_readable": None,
                "mode_unknown": True,
            },
        ],
        systemd_hardening={
            "available": True,
            "units": [
                {
                    "unit": "patched-portal.service",
                    "score": 7.2,
                    "rating": "EXPOSED",
                    "class": "network-facing",
                    "ceiling": 6.0,
                    "over_ceiling": True,
                },
                {
                    "unit": "patched-mystery.service",
                    "score": 4.1,
                    "rating": "MEDIUM",
                    "class": None,
                    "ceiling": None,
                    "over_ceiling": None,
                },
                {
                    "unit": "patched-unjudged.service",
                    "score": None,
                    "rating": None,
                    "class": "network-facing",
                    "ceiling": 6.0,
                    "over_ceiling": None,
                },
                {
                    "unit": "patched-fine.service",
                    "score": 3.0,
                    "rating": "OK",
                    "class": "network-facing",
                    "ceiling": 6.0,
                    "over_ceiling": False,
                },
            ],
        },
    )
    monkeypatch.setattr(main, "MAINTENANCE_FACTS_FILE", facts_file)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    maint = body["maintenance"]
    assert maint["stray_config_backups_count"] == 3
    assert maint["stray_config_backups_readable_count"] == 1
    assert maint["stray_config_backups_unknown_count"] == 1
    assert maint["systemd_hardening_available"] is True
    assert maint["systemd_hardening_over_ceiling_count"] == 1
    assert maint["systemd_hardening_unclassified_count"] == 1
    assert maint["systemd_hardening_unjudged_count"] == 1

    # No leakage: neither field's raw array, nor any path, filename, or
    # .service unit name, ever leaves the box.
    raw = resp.text
    assert '"stray_config_backups":' not in raw
    assert '"systemd_hardening":' not in raw or '"units":' not in raw
    for leaky in (
        "/etc/patched-portal",
        "portal.env.bak-pat1",
        "z.env.bak-pat3",
        "unreadable.bak-pat9",
        "patched-portal.service",
        "patched-mystery.service",
        "patched-unjudged.service",
        "patched-fine.service",
        ".service",
        "network-facing",
        "EXPOSED",
    ):
        assert leaky not in raw, f"{leaky!r} leaked into the public /healthz body"


def test_healthz_stray_config_backups_absent_is_not_present_as_zero(
    client, tmp_path, monkeypatch
):
    """An emitter that predates this field must produce NO
    stray_config_backups_* keys at all -- not zeroed ones. A bare 0 here
    would read identically to 'scanned, found nothing', which is exactly
    the unknown-reads-as-clean shape this ticket exists to close."""
    facts_file, _ = _write_facts(tmp_path)  # _write_facts never sets this key
    monkeypatch.setattr(main, "MAINTENANCE_FACTS_FILE", facts_file)
    resp = client.get("/healthz")
    maint = resp.json()["maintenance"]
    assert "stray_config_backups_count" not in maint
    assert "stray_config_backups_readable_count" not in maint
    assert "stray_config_backups_unknown_count" not in maint


def test_healthz_stray_config_backups_empty_scan_is_present_as_zero(
    client, tmp_path, monkeypatch
):
    """The other half of the same distinction: a real scan that found
    nothing must report present-and-zero, not vanish -- it's a genuinely
    different fact from 'never reported'."""
    facts_file, _ = _write_facts(tmp_path, stray_config_backups=[])
    monkeypatch.setattr(main, "MAINTENANCE_FACTS_FILE", facts_file)
    resp = client.get("/healthz")
    maint = resp.json()["maintenance"]
    assert maint["stray_config_backups_count"] == 0
    assert maint["stray_config_backups_readable_count"] == 0
    assert maint["stray_config_backups_unknown_count"] == 0


def test_healthz_systemd_hardening_absent_is_not_present_as_any_state(
    client, tmp_path, monkeypatch
):
    facts_file, _ = _write_facts(tmp_path)  # _write_facts never sets this key
    monkeypatch.setattr(main, "MAINTENANCE_FACTS_FILE", facts_file)
    resp = client.get("/healthz")
    maint = resp.json()["maintenance"]
    assert "systemd_hardening_available" not in maint
    assert "systemd_hardening_over_ceiling_count" not in maint
    assert "systemd_hardening_unclassified_count" not in maint
    assert "systemd_hardening_unjudged_count" not in maint


def test_healthz_systemd_hardening_unavailable_is_distinct_from_clean_scan(
    client, tmp_path, monkeypatch
):
    """available: false (systemd-analyze missing/broken on the box) must
    report ONLY the availability bool -- no count keys at all -- so it can
    never be mistaken for a scan that ran and found zero units over
    ceiling."""
    facts_file, _ = _write_facts(
        tmp_path, systemd_hardening={"available": False, "units": []}
    )
    monkeypatch.setattr(main, "MAINTENANCE_FACTS_FILE", facts_file)
    resp = client.get("/healthz")
    maint = resp.json()["maintenance"]
    assert maint["systemd_hardening_available"] is False
    assert "systemd_hardening_over_ceiling_count" not in maint
    assert "systemd_hardening_unclassified_count" not in maint
    assert "systemd_hardening_unjudged_count" not in maint


def test_healthz_systemd_hardening_empty_scan_is_present_as_zero(client, tmp_path, monkeypatch):
    facts_file, _ = _write_facts(
        tmp_path, systemd_hardening={"available": True, "units": []}
    )
    monkeypatch.setattr(main, "MAINTENANCE_FACTS_FILE", facts_file)
    resp = client.get("/healthz")
    maint = resp.json()["maintenance"]
    assert maint["systemd_hardening_available"] is True
    assert maint["systemd_hardening_over_ceiling_count"] == 0
    assert maint["systemd_hardening_unclassified_count"] == 0
    assert maint["systemd_hardening_unjudged_count"] == 0


def test_healthz_omits_maintenance_when_facts_stale(client, tmp_path, monkeypatch):
    from datetime import UTC, datetime, timedelta

    stale_at = (datetime.now(UTC) - timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ")
    facts_file, _ = _write_facts(tmp_path, generated_at=stale_at)
    monkeypatch.setattr(main, "MAINTENANCE_FACTS_FILE", facts_file)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert "maintenance" not in resp.json()


def test_healthz_omits_maintenance_when_facts_file_unparseable(client, tmp_path, monkeypatch):
    facts_file = tmp_path / "maintenance.json"
    facts_file.write_text("{not valid json")
    monkeypatch.setattr(main, "MAINTENANCE_FACTS_FILE", facts_file)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert "maintenance" not in body
    assert "not valid json" not in resp.text


def test_static_asset_needs_no_auth(client):
    resp = client.get("/static/css/portal.css")
    assert resp.status_code != 401


def test_exempt_paths_is_the_only_source_of_truth(client):
    """The middleware must consult EXEMPT_PATHS itself (PAT-888), not a
    second hardcoded copy of the same two paths - so every path this
    function calls exempt is provably driven by that tuple."""
    assert main.EXEMPT_PATHS == ("/static/", "/healthz")
    assert main._is_exempt("/healthz")
    assert main._is_exempt("/static/css/portal.css")
    # "/healthz" is an exact match, not a prefix - a similarly named path
    # must still require auth.
    assert not main._is_exempt("/healthzzz")
    assert not main._is_exempt("/staticfoo")
    assert not main._is_exempt("/devices")


def test_lookalike_healthz_path_still_requires_auth(client):
    """Auth runs before routing, so an unauthenticated request to a path
    that merely starts with "/healthz" - not the exact exempt path - must
    still fail closed with 401, never reach routing/404."""
    resp = client.get("/healthzzz")
    assert resp.status_code == 401


# ── Reauth flow (PAT-777) ──────────────────────────────────────────────────
def test_session_expired_clears_stale_cf_cookie(client, make_token):
    """The stale CF_Authorization cookie must be cleared on the
    session-expired response, otherwise a 'Sign in again' click just resends
    the same already-rejected token to Cloudflare Access and the origin
    rejects it again - an invisible loop."""
    resp = _get(client, make_token(exp_delta=-120), "/")
    assert resp.status_code == 401
    set_cookie = resp.headers.get("set-cookie", "")
    assert "CF_Authorization=" in set_cookie
    assert "Max-Age=0" in set_cookie or "max-age=0" in set_cookie.lower()


def test_session_expired_preserves_return_to_path(client, make_token):
    """The 'Sign in again' link must point back at the page the user was on
    (via a validated ?return_to=), not just '/' - that promise is made in
    the page copy itself."""
    resp = _get(client, make_token(exp_delta=-120), "/devices")
    assert resp.status_code == 401
    assert 'href="/?return_to=%2Fdevices"' in resp.text


def test_session_expired_at_root_has_plain_sign_in_link(client, make_token):
    """No point round-tripping a return_to of '/' - keep the link simple."""
    resp = _get(client, make_token(exp_delta=-120), "/")
    assert resp.status_code == 401
    assert 'href="/"' in resp.text


def test_return_to_redirects_after_fresh_login(client, make_token):
    """Once a fresh, valid JWT is presented at '/', a validated return_to
    query param sends the user on to the page they were originally trying to
    reach instead of stranding them at the overview (the reauth loop)."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = client.get(
        "/?return_to=%2Fdevices",
        headers={"Cf-Access-Jwt-Assertion": token},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/devices"


def test_return_to_rejects_open_redirect(client, make_token):
    """A crafted ?return_to= must never send an authenticated user off-site;
    invalid values are ignored and the overview renders normally."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    for evil in ("https://evil.example/", "//evil.example", "/\\evil.example"):
        resp = client.get(
            f"/?return_to={quote(evil, safe='')}",
            headers={"Cf-Access-Jwt-Assertion": token},
            follow_redirects=False,
        )
        assert resp.status_code == 200
        assert "Acme Trust Ltd" in resp.text


def test_upstream_401_also_clears_cookie_and_preserves_return_to(client, make_token):
    """Same reauth treatment applies whether it's our own JWT verification
    that failed or the platform rejecting a JWT we thought was still valid
    (PAT-699 kept the 403 'not linked' path separate - this is only 401)."""
    STUB_STATE["mode"] = "auth401"
    resp = _get(client, make_token(), "/devices")
    assert resp.status_code == 401
    assert "CF_Authorization=" in resp.headers.get("set-cookie", "")
    assert 'href="/?return_to=%2Fdevices"' in resp.text


# ── Pages render tenant data, JWT forwarded verbatim ──────────────────────
def test_overview_renders_tenant_posture(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    assert "Acme Trust Ltd" in resp.text
    assert "84" in resp.text  # CIS score
    assert "alice@tenant-a.example" in resp.text  # signed-in identity
    assert "Critical" in resp.text and "Up to date" in resp.text
    # PAT-1588: coverage card - "Known devices" replaces the overclaiming
    # "In your estate" label, and the two new platform signals render.
    assert "Oldest successful ingest:" in resp.text
    assert "Not a claim of continuous coverage" in resp.text
    assert "15 Dec 2026" in resp.text
    assert "reporting a collection issue" in resp.text
    assert "In your estate" not in resp.text


def test_overview_zero_degraded_devices_shows_no_alarm(client, make_token, monkeypatch):
    """PAT-1588: the common case (no degraded devices) must render nothing
    extra - not a manufactured "all clear" message. Silence is more honest
    than a false all-clear."""
    monkeypatch.setitem(STUB_STATE, "overview_data", {**OVERVIEW, "devices_degraded": 0})
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    assert "reporting a collection issue" not in resp.text


def test_signed_in_page_has_sign_out_link(client, make_token):
    """PAT-1585: a signed-in customer can always end their session. The
    logout endpoint lives on the CF Access team domain, not this origin."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    assert f'href="https://{TEAM_DOMAIN}/cdn-cgi/access/logout"' in resp.text


def test_signed_out_page_has_no_sign_out_link(client, make_token):
    """No session to end, and computing the link needs a verified identity -
    must not appear on a 401/session-expired render."""
    resp = client.get("/devices")  # no Cf-Access-Jwt-Assertion header at all
    assert resp.status_code == 401
    assert "cdn-cgi/access/logout" not in resp.text


def test_devices_roster_renders(client, make_token):
    """PAT-1642: /devices is now grouped by what needs a decision rather
    than a flat roster (see tests/test_devices_groups.py for that page's own
    coverage) - the two devices reporting within the last 3 days land in
    the "reporting normally" group's own browse view, ?view=normal, which
    keeps this device-table rendering coverage (score/encryption) alive."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices?view=normal")
    assert resp.status_code == 200
    assert "acme-mbp-frontdesk" in resp.text
    assert "acme-win-accounts" in resp.text
    assert "Not encrypted" in resp.text
    # PAT-1597: the visible score is rounded ("31"), never the raw float -
    # data-value deliberately keeps the raw float for accurate sorting, so
    # only the rendered span text is asserted here, not the whole page.
    # PAT-2256: it carries its unit and no red/amber/green tone.
    assert '<span class="score">31%</span>' in resp.text


def test_device_detail_renders_summary(client, make_token):
    # PAT-2164: the Summary card (cis_score) stays on the Overview tab.
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices/dev-mac-001")
    assert resp.status_code == 200
    # PAT-1597: cis_score renders rounded ("65"), never the raw float.
    # PAT-2256: with its unit.
    assert "<dd>65%</dd>" in resp.text
    assert "64.70588235294117" not in resp.text


def test_device_compliance_renders_signals(client, make_token):
    # PAT-2164: Compliance signals moved to their own tab.
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices/dev-mac-001/compliance")
    assert resp.status_code == 200
    assert "Firewall enabled" in resp.text
    assert "Enable the application firewall" in resp.text


def test_device_vulnerabilities_renders_apps_with_findings(client, make_token):
    # PAT-2164: Applications with open findings moved to the Vulnerabilities tab.
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices/dev-mac-001/vulnerabilities")
    assert resp.status_code == 200
    assert "CVE-2026-1234" in resp.text
    assert "Confirmed" in resp.text
    assert "125.0.0" in resp.text


def test_device_detail_renders_each_cve_confidence_state(client, make_token, monkeypatch):
    # PAT-2164: Applications with open findings moved to the Vulnerabilities tab.
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = copy.deepcopy(DEVICE_DETAIL)
    detail["apps_with_findings"] = [
        {"app": "VendorApp", "version": "1.0", "cve_ids": [], "max_severity": "high",
         "match_confidence": "version_vendor_confirmed", "fixed_version": "2.0"},
        {"app": "ConfirmedApp", "version": "1.0", "cve_ids": [], "max_severity": "high",
         "match_confidence": "version_confirmed", "fixed_version": "2.0"},
        {"app": "PossibleApp", "version": "1.0", "cve_ids": [], "max_severity": "high",
         "match_confidence": "version_unverified", "fixed_version": "2.0"},
        {"app": "UnknownApp", "version": "1.0", "cve_ids": [], "max_severity": "high",
         "match_confidence": "future_value", "fixed_version": "2.0"},
    ]
    monkeypatch.setitem(STUB_STATE, "device_detail_data", detail)
    resp = _get(client, token, "/devices/dev-mac-001/vulnerabilities")
    assert resp.status_code == 200
    for label in ("Vendor-confirmed", "Confirmed", "Possible", "Unrecognised"):
        assert label in resp.text
    assert "grouped for each application and version across its listed CVEs" in resp.text
    assert "not severity, exploitability or remediation certainty" in resp.text


def test_findings_render_sorted_by_severity(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    # Critical finding must be listed before the high one.
    assert resp.text.index("CVE-2026-0001") < resp.text.index("CVE-2026-1234")
    assert "Confirmed" in resp.text
    assert "Possible" in resp.text
    assert "124.0.5" in resp.text


def test_findings_keep_tenant_wide_rows_and_render_target_versions(client, make_token):
    """PAT-1841: no device enumeration appears in tenant-wide findings, while
    published summaries and fixed-version targets remain visible."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    assert "Affected devices:" not in resp.text
    assert "acme-mbp-frontdesk" not in resp.text
    assert 'href="/devices/dev-mac-001"' not in resp.text
    assert "Use-after-free in the rendering engine." in resp.text
    assert "Installed: 124.0.1" in resp.text
    assert "Target: 124.0.5" in resp.text
    assert "Target: latest vendor release" in resp.text


def test_findings_empty_summary_names_nvd_as_check_route(client, make_token, monkeypatch):
    """PAT-1841: a missing vendor description stays explicit and actionable."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    finding = {
        "cve_id": "CVE-2026-9998",
        "severity": "medium",
        "cvss": 5.0,
        "app": "NoDescriptionApp",
        "version": "1.0",
        "fixed_version": "2.0",
        "devices_affected": 1,
        "first_seen": "2026-12-20T04:00:00Z",
        "summary": "",
    }
    monkeypatch.setitem(STUB_STATE, "findings_data", [finding])
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    assert "No description has been published yet." in resp.text
    assert (
        '<a href="https://nvd.nist.gov/vuln/detail/CVE-2026-9998" '
        'target="_blank" rel="noopener noreferrer">NVD record</a>'
    ) in resp.text
    assert "Target: 2.0" in resp.text


def test_findings_renders_each_cve_confidence_state(client, make_token, monkeypatch):
    """Unknown confidence never silently becomes a confirmed match."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    findings = []
    for index, confidence in enumerate((
        "version_vendor_confirmed", "version_confirmed", "version_unverified", None,
    )):
        finding = {
            "cve_id": f"CVE-2026-999{index}", "severity": "medium", "cvss": 5.0,
            "app": f"ConfidenceApp{index}", "version": "1.0", "devices_affected": 1,
            "first_seen": "2026-12-20T04:00:00Z", "summary": "",
        }
        if confidence is not None:
            finding["match_confidence"] = confidence
        findings.append(finding)
    monkeypatch.setitem(STUB_STATE, "findings_data", findings)
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    for label in ("Vendor-confirmed", "Confirmed", "Possible", "Unrecognised"):
        assert label in resp.text
    assert "not severity, exploitability or remediation certainty" in resp.text


def test_findings_legend_explains_confidence(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    assert "how certain we are that the installed version is affected" in resp.text


# ── PAT-2043: Homebrew source, confidence tier and install reason ─────────
def test_findings_homebrew_high_tier_shows_source_and_confirmed(client, make_token, monkeypatch):
    """A high-confidence Homebrew formula finding shows the Homebrew formula
    source label, the install reason, and is presented as Confirmed - the
    same PAT-1586/PAT-1842 pill wording other software uses. It must never
    be labelled Possible, which would understate a curated, version-in-range
    match (root AGENTS.md: CVE claims require evidence, in both directions)."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    finding = {
        "cve_id": "CVE-2026-8001", "severity": "critical", "cvss": 9.1,
        "app": "openssl@3 (Homebrew formula)", "version": "3.0.1",
        "devices_affected": 2, "first_seen": "2026-12-20T04:00:00Z",
        "summary": "Old OpenSSL formula with a known CVE.",
        "source": "homebrew_formula", "confidence_tier": "high",
        "install_reasons": ["on_request"],
    }
    monkeypatch.setitem(STUB_STATE, "findings_data", [finding])
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    assert "Homebrew formula" in resp.text
    assert "installed on request" in resp.text
    idx = resp.text.index("CVE-2026-8001")
    assert "Confirmed" in resp.text[idx:idx + 2000]
    assert "Possible" not in resp.text[idx:idx + 2000]


def test_findings_homebrew_low_tier_is_not_shown_as_confirmed(client, make_token, monkeypatch):
    """A low-confidence Homebrew cask finding (version not confirmable) reads
    as Possible, the same plain-labelled state used for other software's
    version_unverified rows, never as a confirmed vulnerability."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    finding = {
        "cve_id": "CVE-2026-8002", "severity": "high", "cvss": 7.0,
        "app": "firefox (Homebrew cask)", "version": "HEAD",
        "devices_affected": 1, "first_seen": "2026-12-20T04:00:00Z",
        "summary": "",
        "source": "homebrew_cask", "confidence_tier": "low",
        "install_reasons": ["dependency"],
    }
    monkeypatch.setitem(STUB_STATE, "findings_data", [finding])
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    assert "Homebrew cask" in resp.text
    assert "installed as a dependency" in resp.text
    idx = resp.text.index("CVE-2026-8002")
    assert "Possible" in resp.text[idx:idx + 2000]
    assert "Confirmed" not in resp.text[idx:idx + 2000]


def test_findings_without_homebrew_fields_render_no_homebrew_label(client, make_token):
    """Degrade gracefully against an older platform that never sends
    source/confidence_tier/install_reasons: no crash, no Homebrew label, the
    ordinary match_confidence badge renders exactly as before."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    assert "Homebrew formula" not in resp.text
    assert "Homebrew cask" not in resp.text
    assert "Confirmed" in resp.text
    assert "Possible" in resp.text


def _make_findings(n):
    """A findings set large enough to span multiple 50-row pages (PAT-1201),
    with distinct cvss values so upstream's cvss-desc ordering is unambiguous."""
    return [
        {
            "cve_id": f"CVE-2026-{i:04d}",
            "severity": "medium",
            "cvss": round(9.0 - (i * 0.01), 2),
            "app": f"App{i}",
            "version": "1.0",
            "devices_affected": 1,
            "first_seen": "2026-12-20T04:00:00Z",
            "summary": "",
        }
        for i in range(n)
    ]


def test_findings_pagination_shows_page_count_and_links(client, make_token, monkeypatch):
    """PAT-1201: 120 findings at 50/page is 3 pages; page 2 shows both a
    previous and a next link and the right "Page N of M" status."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(STUB_STATE, "findings_data", _make_findings(120))
    resp = _get(client, token, "/findings?page=2")
    assert resp.status_code == 200
    assert "Page 2 of 3" in resp.text
    assert 'href="/findings?page=1"' in resp.text
    assert 'href="/findings?page=3"' in resp.text
    # The 50 rows on page 2 are CVE-2026-0050 .. CVE-2026-0099 (cvss desc).
    assert "CVE-2026-0050" in resp.text
    assert "CVE-2026-0000" not in resp.text


def test_findings_last_page_has_no_next_link(client, make_token, monkeypatch):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(STUB_STATE, "findings_data", _make_findings(120))
    resp = _get(client, token, "/findings?page=3")
    assert resp.status_code == 200
    assert "Page 3 of 3" in resp.text
    assert 'href="/findings?page=4"' not in resp.text


def test_findings_first_page_has_no_previous_link(client, make_token, monkeypatch):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(STUB_STATE, "findings_data", _make_findings(120))
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    assert "Page 1 of 3" in resp.text
    assert 'href="/findings?page=0"' not in resp.text


def test_findings_page_past_end_redirects_to_page_one(client, make_token, monkeypatch):
    """The platform returns findings=[] and a bogus total=0 for an offset
    past the last row (documented caveat, PAT-1201) - that must never be
    read as "empty tenant" and rendered as a clean empty state. Bouncing
    back to page 1 (the one offset where an empty result is trustworthy)
    is the defensive fallback for a stale bookmark or hand-edited URL."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(STUB_STATE, "findings_data", _make_findings(120))
    resp = client.get(
        "/findings?page=999",
        headers={"Cf-Access-Jwt-Assertion": token},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/findings"


def test_findings_empty_tenant_renders_clean_with_no_pager(client, make_token, monkeypatch):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(STUB_STATE, "findings_data", [])
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    assert "No open CVE findings" in resp.text
    assert "0 open CVE findings" in resp.text
    assert 'class="pager"' not in resp.text


def test_findings_search_placeholder_is_honest_about_page_scope(client, make_token):
    """Andy's decision (2026-08-10): search stays client-side over the
    loaded page only, not the full tenant - the copy must say so rather
    than implying a full-estate search that no longer happens."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/findings")
    assert resp.status_code == 200
    assert "Search CVE, application or severity" not in resp.text
    assert "this page" in resp.text.lower()


# ── Findings CSV export (PAT-1587) ────────────────────────────────────────
def test_findings_csv_export(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/findings.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert resp.headers["content-disposition"] == (
        'attachment; filename="patched-findings.csv"'
    )
    rows = list(csv.reader(io.StringIO(resp.text)))
    assert rows[0] == list(main.FINDINGS_CSV_COLUMNS)
    assert len(rows) == 3  # header + 2 fixture findings
    by_cve = {r[0]: r for r in rows[1:]}
    assert set(by_cve) == {"CVE-2026-1234", "CVE-2026-0001"}
    row = by_cve["CVE-2026-1234"]
    assert row[1] == "high"  # severity
    assert row[3] == "ExampleBrowser"  # app
    assert row[6] == "124.0.5"  # fixed_version
    assert row[7] == "3"  # devices_affected


def test_findings_csv_export_walks_every_page(client, make_token, monkeypatch):
    """PAT-1587: /v1/portal/findings is paginated (PAT-1201) unlike
    /devices.csv's single-shot upstream call - a tenant with more than one
    page (this has happened, a tenant hit 709 rows) must not get a silently
    truncated export. 520 rows forces a second 500-row page."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(STUB_STATE, "findings_data", _make_findings(520))
    resp = _get(client, token, "/findings.csv")
    assert resp.status_code == 200
    rows = list(csv.reader(io.StringIO(resp.text)))
    assert len(rows) == 521  # header + all 520, proving the second page was fetched


def test_findings_csv_requires_auth(client, make_token):
    assert client.get("/findings.csv").status_code == 401
    resp = _get(client, make_token(exp_delta=-120), "/findings.csv")
    assert resp.status_code == 401


def test_reports_history_and_generate(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports")
    assert resp.status_code == 200
    assert "rep-0001" in resp.text

    resp = client.post(
        "/reports/generate",
        headers={"Cf-Access-Jwt-Assertion": token, "Origin": "https://testserver"},
        data={"csrf_token": main._csrf_token(token)},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/reports?generated=1"
    assert STUB_STATE["generate_calls"] == 1


def test_report_download_proxies_pdf(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/rep-0001/download")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/pdf")
    assert "acme-report.pdf" in resp.headers["content-disposition"]
    assert resp.content == PDF_BYTES
    # PAT-888: Content-Length must be forwarded from upstream on a clean
    # download too - it's what makes a *broken* download detectable (see
    # test_report_download_mid_stream_failure_is_not_a_clean_200 below), so
    # a normal download must carry it and it must be correct.
    assert resp.headers["content-length"] == str(len(PDF_BYTES))


def test_report_download_mid_stream_failure_is_not_a_clean_200(client, make_token):
    """PAT-888: an upstream connection reset partway through a report PDF
    must not present as a complete, successful download.

    The portal's global JWT-check middleware is a Starlette
    BaseHTTPMiddleware, which swallows an exception raised deep inside a
    streaming response and finishes the client's connection as if nothing
    went wrong - confirmed by hand against this exact code path before this
    fix, where a reset upstream connection produced a plain 200 with a
    silently truncated body and no signal anything had failed. Forwarding
    the upstream Content-Length closes that gap: it gives the client (and,
    on a real ASGI server, the framing layer itself) something to check the
    delivered bytes against, so a short body is provably short rather than
    indistinguishable from a small-but-complete PDF.
    """
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["mode"] = "stream_fail"
    resp = _get(client, token, "/reports/rep-0001/download")
    # Headers were already committed upstream of the failure - status can't
    # change - but the body must be demonstrably incomplete against the
    # length the portal itself declared to the client.
    assert resp.headers["content-length"] == str(STREAM_FAIL_DECLARED_LENGTH)
    assert len(resp.content) < STREAM_FAIL_DECLARED_LENGTH
    # It must not even coincidentally look like the real, complete report.
    assert resp.content != STREAM_FAIL_ACTUAL_BYTES + b"\x00" * (
        STREAM_FAIL_DECLARED_LENGTH - len(STREAM_FAIL_ACTUAL_BYTES)
    )


def test_support_page_uses_mailto_not_ticketing(client, make_token):
    token = make_token()
    resp = _get(client, token, "/support")
    assert resp.status_code == 200
    assert "mailto:hello@patched.im" in resp.text


# ── Install page (PAT-453): MDM self-serve enrolment ───────────────────────
def _post_enrolment(client, token, **kwargs):
    # PAT-2105: a real form post carries the page's Origin and CSRF token.
    kwargs.setdefault("data", {"csrf_token": main._csrf_token(token)})
    return client.post(
        "/install/enrolment",
        headers={"Cf-Access-Jwt-Assertion": token, "Origin": "https://testserver"},
        follow_redirects=False,
        **kwargs,
    )


def test_install_page_renders_pre_generation_state(client, make_token):
    token = make_token()
    resp = _get(client, token, "/install")
    assert resp.status_code == 200
    assert "Install the agent" in resp.text
    assert "Generate a one-off install token" in resp.text
    # No broken/unreachable download links (the old stub's GitHub links
    # 404'd for non-collaborators — replaced by this self-serve flow).
    assert "github.com/Patched-LTD/updater" not in resp.text
    assert "Download for macOS" not in resp.text
    assert "Download for Windows" not in resp.text


def test_install_page_fails_closed_signed_out(client):
    """Same fail-closed treatment as every other page, even though the
    pre-generation view makes no upstream call — auth happens in middleware
    before the route. No token at all gets the signed-out page, not
    session-expired."""
    resp = client.get("/install")
    assert resp.status_code == 401
    assert "sign in to patched" in resp.text.lower()
    assert "session has expired" not in resp.text.lower()


def test_install_page_fails_closed_with_expired_token(client, make_token):
    resp = _get(client, make_token(exp_delta=-120), "/install")
    assert resp.status_code == 401
    assert "session has expired" in resp.text.lower()


def test_install_page_links_to_full_deployment_guide(client, make_token):
    token = make_token()
    resp = _get(client, token, "/install")
    assert resp.status_code == 200
    assert 'href="https://docs.patched.im/getting-started"' in resp.text


def test_install_get_never_shows_a_token(client, make_token):
    """The pre-generation GET makes no upstream call and must never render
    a real-looking credential."""
    token = make_token()
    resp = _get(client, token, "/install")
    assert resp.status_code == 200
    assert ENROLMENT_TOKEN["enrollment_token"] not in resp.text


def test_generate_enrolment_token_requires_auth(client):
    resp = client.post("/install/enrolment", follow_redirects=False)
    assert resp.status_code == 401
    assert STUB_STATE["enrolment_calls"] == 0


def test_generate_enrolment_token_get_not_allowed(client, make_token):
    """Generation must only ever be reachable via POST."""
    token = make_token()
    resp = client.get("/install/enrolment", headers={"Cf-Access-Jwt-Assertion": token})
    assert resp.status_code == 405


def test_generate_enrolment_token_renders_token_and_both_artifacts(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _post_enrolment(client, token)
    assert resp.status_code == 200
    assert STUB_STATE["enrolment_calls"] == 1
    assert STUB_STATE["enrolment_posts"] == [{"delivery_path": "mdm"}]

    real_token = ENROLMENT_TOKEN["enrollment_token"]
    assert real_token in resp.text
    # macOS artifact: the exact shape the admin dashboard's Deploy-agent
    # Path-1 hands out (PAT-550), token interpolated.
    assert "/etc/patched/enrollment-token" in resp.text
    # Jinja autoescapes the '>' redirect inside <pre><code>; browsers render
    # the entity back to '>', so assert against the escaped HTML here.
    assert f"printf &#39;%s&#39; &#39;{real_token}&#39;" in resp.text
    assert "/etc/patched/enrollment-token\n" in resp.text
    # Windows artifact.
    assert f'msiexec /qn /i PatchedAgent.msi ENROLLMENT_TOKEN=&#34;{real_token}&#34;' in resp.text
    # Expiry, human-formatted.
    assert "13 Jul 2026" in resp.text


def test_generate_enrolment_token_upstream_rate_limited_is_friendly(client, make_token):
    """A 429 from the mint must render a friendly retry message, not a
    generic error page or a crash."""
    token = make_token()
    STUB_STATE["mode"] = "rate429"
    resp = _post_enrolment(client, token)
    assert resp.status_code == 429
    assert "wait" in resp.text.lower()
    assert ENROLMENT_TOKEN["enrollment_token"] not in resp.text


def test_generate_enrolment_token_upstream_401_reauths(client, make_token):
    token = make_token()
    STUB_STATE["mode"] = "auth401"
    resp = _post_enrolment(client, token)
    assert resp.status_code == 401
    assert "session has expired" in resp.text.lower()


def test_generate_enrolment_token_upstream_403_not_linked(client, make_token):
    token = make_token()
    STUB_STATE["mode"] = "forbidden403"
    resp = _post_enrolment(client, token)
    assert resp.status_code == 403


def test_generate_enrolment_token_upstream_not_enabled(client, make_token):
    token = make_token()
    STUB_STATE["mode"] = "down503"
    resp = _post_enrolment(client, token)
    assert resp.status_code == 503


def test_install_page_never_renders_a_hardcoded_credential(client, make_token):
    """Outside of the mocked upstream token that comes back from a genuine
    POST, the page must never contain a real-looking credential."""
    token = make_token()
    resp = _get(client, token, "/install")
    assert resp.status_code == 200
    assert ENROLMENT_TOKEN["enrollment_token"] not in resp.text
    # No leftover static placeholder from the old stub either.
    assert "<enrollment-token>" not in resp.text
    assert "&lt;enrollment-token&gt;" not in resp.text


# ── Upstream failure modes ────────────────────────────────────────────────
def test_upstream_401_shows_reauth_page(client, make_token):
    STUB_STATE["mode"] = "auth401"
    resp = _get(client, make_token(), "/")
    assert resp.status_code == 401
    assert "session has expired" in resp.text.lower()


def test_upstream_403_shows_not_linked_page_without_reauth_cta(client, make_token):
    """PAT-699: 403 means a verified identity with no estate access. It must
    render the distinct not-linked page (403), never the session-expired
    re-auth loop."""
    STUB_STATE["mode"] = "forbidden403"
    resp = _get(client, make_token(), "/")
    assert resp.status_code == 403
    assert "isn't linked to an estate yet" in resp.text
    assert "hello@patched.im" in resp.text
    assert "session has expired" not in resp.text.lower()
    assert "sign in again" not in resp.text.lower()


def test_upstream_503_shows_not_enabled_page(client, make_token):
    STUB_STATE["mode"] = "down503"
    resp = _get(client, make_token(), "/")
    assert resp.status_code == 503
    assert "not yet enabled" in resp.text.lower()


def test_upstream_unreachable_shows_friendly_error(client, make_token, monkeypatch):
    monkeypatch.setenv("PLATFORM_BASE_URL", "http://127.0.0.1:9")  # nothing listens
    resp = _get(client, make_token(), "/")
    assert resp.status_code == 502
    assert "temporarily unavailable" in resp.text.lower()


def test_unexpected_list_shape_renders_error_not_empty_findings(client, make_token):
    """PAT-888: a findings payload that is neither documented shape (bare
    array or {"findings": [...]}) is a platform contract violation, not an
    empty/clean estate. It must render as an error page, never as a
    clean-bill-of-health empty Findings list - that would hide a real
    incident (broken or drifted platform contract) behind a reassuring
    "nothing to report"."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["mode"] = "malformed"
    resp = _get(client, token, "/findings")
    assert resp.status_code != 200
    assert "temporarily unavailable" in resp.text.lower()
    # Must not look like a legitimate empty result.
    assert "no findings" not in resp.text.lower()


def test_unknown_device_shows_not_found(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices/does-not-exist")
    assert resp.status_code == 404


# ── Shell, theme toggle, tier chip (PAT-1641) ───────────────────────────────
def test_no_google_fonts_requested(client, make_token):
    """PAT-1641: the portal loads no web fonts any more - system stacks
    only. A regression here would silently reintroduce a third-party
    network dependency on every page load."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    assert "fonts.googleapis.com" not in resp.text
    assert "fonts.gstatic.com" not in resp.text


def test_theme_toggle_present_on_every_page_including_signed_out(client):
    """The toggle is a client-side preference unrelated to auth state, so it
    must render even on the pages that hide the estate nav (PAT-1574)."""
    resp = client.get("/")
    assert resp.status_code == 401
    assert 'data-theme-choice="light"' in resp.text
    assert 'data-theme-choice="dark"' in resp.text


def test_theme_toggle_present_on_authenticated_page(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    assert 'data-theme-choice="light"' in resp.text
    assert 'data-theme-choice="dark"' in resp.text


def test_theme_bootstrap_script_reads_and_writes_localstorage_safely(client, make_token):
    """PAT-1641: the inline head script must wrap its localStorage read in
    try/catch (a private window or blocked site data throws), and the
    toggle's click handler must wrap its write the same way, so the page
    still renders correctly if storage is unavailable."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    head = resp.text.split("</head>")[0]
    assert "try {" in head and "localStorage.getItem" in head
    assert "localStorage.setItem" in resp.text


def test_tier_chip_never_renders_even_when_platform_sends_a_tier(client, make_token):
    """PAT-2130: the Assurance/Managed tier split (and its PAT-1641 chip) is
    retired - Patched is one plan now (24 Sept revision comment on
    PAT-1602). The portal must not read or render `tier` even if an old or
    misconfigured upstream response still sends one; the reserved
    subscription-state slot stays empty until PAT-2132 fills it."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_data"] = {**OVERVIEW, "tier": "Managed"}
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    assert "tier-chip" not in resp.text
    assert "Managed" not in resp.text
    assert 'data-slot="subscription-state"' in resp.text


def test_tier_chip_absent_on_reports_page(client, make_token):
    """The reports route never carried a live tier field (it calls
    /v1/portal/reports, not /v1/portal/overview) - confirms the retired
    chip stays gone here too."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports")
    assert resp.status_code == 200
    assert "tier-chip" not in resp.text
    assert "ISSUED DOCUMENTS ARE ALWAYS LIGHT" in resp.text


def test_rail_nav_present_for_authenticated_user(client, make_token):
    """The slate rail replaces the old top nav (PAT-1641) but must still
    carry every existing route."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    assert 'class="rail"' in resp.text
    for path in ("/", "/devices", "/findings", "/software", "/reports",
                 "/install", "/support?route=/"):
        assert f'href="{path}"' in resp.text
