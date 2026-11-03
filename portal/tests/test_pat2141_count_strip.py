"""PAT-2141 follow-up (Andy's live feedback, 25 Sept 2026): "Top of the page
should show how many CVEs and Issues there are on the machine and when
clicked, move down to the CVE / CIS section."

PAT-2339 moves these figures into the tabs, retaining all truth and tone guards.

Two view models, `main._device_cve_tile_view` / `main._device_issues_tile_view`,
each reusing data the page already fetches and renders elsewhere rather than
computing a second, independent count:

- **CVEs** reuses the exact `cve_assessment` state/finding_count the CVE
  assessment card already shows, toned by the worst `max_severity` any app
  in `apps_with_findings` carries (the same figure the "Applications with
  open findings" table already shows per row - there is no per-CVE severity
  anywhere in this data).
- **Failing checks** (PAT-2256: it was labelled "CIS issues") counts the same
  `signals` list the Compliance signals table renders (anything not
  pass/compliant/ok/not_applicable is open), toned by the worst
  `severity` among those open signals (the same per-row severity pill that
  table already shows), so the two tiles' tone logic mirrors each other and
  the two numbers can never drift apart.

Per root AGENTS.md's "absence requires authority", neither tile ever
collapses an unknown or unavailable state to a bare 0: pending CVE
assessment reads "Checking", not-yet-assessed reads "Not assessed", no
compliance signals at all reads "Not available" - only a genuine
zero-result reads as the number 0.

**Second follow-up, same day.** The first cut replaced a stale device's CIS
issues count with the word "Stale", which hid a real, currently-visible
failure (cis-2.6 FAIL/recurred) while the CVE tile beside it kept its own
number for the same device - inconsistent, and it hid a known failure. Both
tiles now always show their real count when one exists (`is_count: True`)
and carry a separate `stale` flag the template renders as a small muted
"Evidence stale" sub-line under the number, never in place of it.
"""

from copy import deepcopy
from datetime import UTC, datetime, timedelta

import main
from tests.conftest import DEVICE_DETAIL, STUB_STATE


def _get(client, token, path="/devices/dev-mac-001"):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _recent_iso(days=0.01):
    """A last_seen timestamp recent enough that annotate_device_staleness
    never marks the device stale, whatever wall clock the suite runs on -
    DEVICE_DETAIL's own fixed 2026-07-02 last_seen is stale against any
    real test-run clock after that date."""
    return (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── _device_cve_tile_view ───────────────────────────────────────────────────
def test_cve_tile_assessed_nonzero_tones_by_worst_app_severity():
    apps = [{"app": "A", "max_severity": "critical"}, {"app": "B", "max_severity": "low"}]
    tile = main._device_cve_tile_view({"state": "assessed", "finding_count": 2}, apps, False)
    assert tile == {"value": 2, "tone": "bad-text", "is_count": True, "stale": False}


def test_cve_tile_high_severity_is_bad_text():
    apps = [{"app": "A", "max_severity": "high"}]
    tile = main._device_cve_tile_view({"state": "assessed", "finding_count": 2}, apps, False)
    assert tile["tone"] == "bad-text"


def test_cve_tile_medium_severity_warns():
    apps = [{"app": "A", "max_severity": "medium"}]
    tile = main._device_cve_tile_view({"state": "assessed", "finding_count": 1}, apps, False)
    assert tile["tone"] == "warn-text"


def test_cve_tile_low_only_severity_is_muted():
    apps = [{"app": "A", "max_severity": "low"}]
    tile = main._device_cve_tile_view({"state": "assessed", "finding_count": 1}, apps, False)
    assert tile["tone"] == "mute-text"


def test_cve_tile_assessed_zero_is_a_real_muted_zero():
    tile = main._device_cve_tile_view({"state": "assessed", "finding_count": 0}, [], False)
    assert tile == {"value": 0, "tone": "mute-text", "is_count": True, "stale": False}


def test_cve_tile_nonzero_with_no_severity_detail_stays_bad_not_muted():
    # A contract gap (finding_count > 0 but no matching app in
    # apps_with_findings) must never downplay an unexplained finding to a
    # muted tone.
    tile = main._device_cve_tile_view({"state": "assessed", "finding_count": 3}, [], False)
    assert tile["tone"] == "bad-text"


def test_cve_tile_pending_never_reads_as_zero():
    tile = main._device_cve_tile_view({"state": "pending", "finding_count": None}, [], False)
    assert tile == {"value": "Checking", "tone": "mute-text", "is_count": False, "stale": False}


def test_cve_tile_not_assessed_never_reads_as_zero():
    tile = main._device_cve_tile_view({"state": "not_assessed"}, [], False)
    assert tile == {
        "value": "Not assessed", "tone": "graphite-text", "is_count": False, "stale": False,
    }


def test_cve_tile_missing_state_never_reads_as_zero():
    tile = main._device_cve_tile_view({}, [], False)
    assert tile["value"] == "Not assessed"
    assert tile["is_count"] is False


def test_cve_tile_stale_keeps_the_real_count_and_flags_stale():
    # Andy's follow-up ruling: a stale device still shows its real,
    # already-dated CVE count - never hidden behind a word - with `stale`
    # only adding a caveat sub-line in the template.
    apps = [{"app": "A", "max_severity": "high"}]
    tile = main._device_cve_tile_view({"state": "assessed", "finding_count": 2}, apps, True)
    assert tile == {"value": 2, "tone": "bad-text", "is_count": True, "stale": True}


def test_cve_tile_stale_never_applies_to_the_checking_or_not_assessed_words():
    # Those two states already carry their own uncertainty; no extra
    # "Evidence stale" sub-line under a word instead of a number.
    assert main._device_cve_tile_view({"state": "pending"}, [], True)["stale"] is False
    assert main._device_cve_tile_view({"state": "not_assessed"}, [], True)["stale"] is False


# ── _device_issues_tile_view ────────────────────────────────────────────────
def test_issues_tile_no_signals_reads_not_available_never_zero():
    tile = main._device_issues_tile_view([], False)
    assert tile == {
        "value": "Not available", "tone": "mute-text", "is_count": False, "stale": False,
    }


def test_issues_tile_counts_fail_and_recurred_as_open():
    signals = [
        {"status": "pass", "severity": "low"},
        {"status": "fail", "severity": "high"},
        {"status": "recurred", "severity": "medium"},
        {"status": "compliant", "severity": "critical"},
    ]
    tile = main._device_issues_tile_view(signals, False)
    # 2 open (fail + recurred); worst open severity is "high" -> bad-text.
    assert tile == {"value": 2, "tone": "bad-text", "is_count": True, "stale": False}


def test_issues_tile_medium_only_open_severity_warns():
    signals = [{"status": "fail", "severity": "medium"}]
    tile = main._device_issues_tile_view(signals, False)
    assert tile["tone"] == "warn-text"


def test_issues_tile_low_only_open_severity_is_muted():
    signals = [{"status": "fail", "severity": "low"}]
    tile = main._device_issues_tile_view(signals, False)
    assert tile["tone"] == "mute-text"


def test_issues_tile_open_with_no_severity_detail_stays_bad_not_muted():
    signals = [{"status": "fail"}]
    tile = main._device_issues_tile_view(signals, False)
    assert tile["tone"] == "bad-text"


def test_issues_tile_all_pass_is_a_real_muted_zero():
    signals = [{"status": "pass"}, {"status": "ok"}, {"status": "compliant"}]
    tile = main._device_issues_tile_view(signals, False)
    assert tile == {"value": 0, "tone": "mute-text", "is_count": True, "stale": False}


def test_issues_tile_stale_keeps_the_real_count_and_flags_stale():
    # Andy's follow-up ruling, 25 Sept 2026: the first cut replaced this
    # with the word "Stale", hiding a real, currently-visible failure -
    # never again. The count strip and the Compliance signals table below
    # it must always agree on the number.
    signals = [{"status": "fail", "severity": "critical"}]
    tile = main._device_issues_tile_view(signals, True)
    assert tile == {"value": 1, "tone": "bad-text", "is_count": True, "stale": True}


def test_issues_tile_stale_with_zero_open_signals_is_still_a_real_zero():
    signals = [{"status": "pass"}]
    tile = main._device_issues_tile_view(signals, True)
    assert tile == {"value": 0, "tone": "mute-text", "is_count": True, "stale": True}


# ── Rendered page ────────────────────────────────────────────────────────
def test_device_tabs_renders_above_device_card_with_real_values(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    detail["last_seen"] = _recent_iso()  # not stale - no "Evidence stale" sub-line
    STUB_STATE["device_detail_data"] = detail

    response = _get(client, token)

    assert response.status_code == 200
    body = response.text
    assert 'class="card kpi count-strip"' not in body
    tabs_pos = body.index('class="devices-toolbar device-tab-bar"')
    assert tabs_pos < body.index('id="device-card-title"')
    assert '>Summary<' not in body
    assert 'href="/devices/dev-mac-001/vulnerabilities"' in body
    assert 'href="/devices/dev-mac-001/compliance"' in body
    assert 'id="cve-assessment"' not in body
    assert 'id="compliance-signals"' not in body
    assert "Vulnerabilities (2)" in body
    assert "Compliance (1 failing)" in body
    assert ">Issues<" not in body
    # CVE tile: DEVICE_DETAIL's cve_assessment.finding_count is 2, and
    # ExampleBrowser's own max_severity is "high" -> bad-text.
    assert '<span class="device-tab-label bad-text">Vulnerabilities (2)</span>' in body
    # CIS issues tile: cis-2.6 fails (severity critical), cis-1.1 passes ->
    # 1 open issue, bad-text.
    assert '<span class="device-tab-label bad-text">Compliance (1 failing)</span>' in body
    assert "Evidence stale" not in body


def test_device_tabs_shows_the_real_count_with_a_stale_subline_for_a_stale_device(
    client, make_token,
):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    # DEVICE_DETAIL's own last_seen (2026-07-02) is already stale against
    # any real test-run wall clock - no override needed.
    response = _get(client, token)

    body = response.text
    # Both tiles keep their real numbers - no "Stale" text in place of one.
    assert '<span class="device-tab-label bad-text">Vulnerabilities (2)</span>' in body
    assert '<span class="device-tab-label bad-text">Compliance (1 failing)</span>' in body
    assert ">Stale<" not in body
    assert body.count("device-tab-caveat\">Evidence stale<") == 2


def test_device_tabs_never_shows_zero_for_pending_cve_state(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    detail["last_seen"] = _recent_iso()
    detail["cve_assessment"] = {
        "state": "pending", "last_matched_at": None, "finding_count": None,
        "assessed_products": 0, "pending_products": 1, "not_assessed_products": 0,
    }
    STUB_STATE["device_detail_data"] = detail

    response = _get(client, token)

    body = response.text
    assert '<span class="device-tab-label mute-text">Vulnerabilities (Checking)</span>' in body
    assert 'Vulnerabilities (0)' not in body


def test_device_tabs_never_shows_zero_for_not_assessed_cve_state(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices/dev-mac-003")

    body = response.text
    assert ('<span class="device-tab-label graphite-text">'
            'Vulnerabilities (Not assessed)</span>') in body


def test_summary_no_longer_shows_the_open_findings_row(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert "<dt>Open findings</dt>" not in response.text
