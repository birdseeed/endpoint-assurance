"""PAT-1859: portal renders the platform's CIS control-coverage read model."""

from pathlib import Path

from tests.conftest import CONTROL_COVERAGE, OVERVIEW, STUB_STATE

ROOT = Path(__file__).resolve().parent.parent


def _get(client, token):
    return client.get("/", headers={"Cf-Access-Jwt-Assertion": token})


def test_overview_renders_all_coverage_states_from_one_aggregate_response(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert response.status_code == 200
    assert "How CIS control coverage explains this score" in response.text
    assert "This view does not create a second score, grade or composite" in response.text
    assert "Coverage snapshot 20 Sep 2026 10:15 UTC" in response.text
    for label, value in (
        ("Measured pass", CONTROL_COVERAGE["measurements"]["pass"]),
        ("Evidenced fail", CONTROL_COVERAGE["measurements"]["fail"]),
        ("Undetermined", CONTROL_COVERAGE["measurements"]["undetermined"]),
        ("Not applicable", CONTROL_COVERAGE["measurements"]["not_applicable"]),
        ("Deliberately out of scope", CONTROL_COVERAGE["controls"]["out_of_scope"]),
    ):
        assert f'<div class="kpi__label">{label}</div>' in response.text
        assert f">{value}</div>" in response.text
    assert "It means manual review, not a pass or an automated result." in response.text
    assert "separate from an evidenced fail and is never treated as a pass" in response.text


def test_overview_renders_platforms_benchmarks_and_identifier_buckets_verbatim(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert response.status_code == 200
    assert ">macos</span>" in response.text
    assert ">windows</span>" in response.text
    for benchmark in CONTROL_COVERAGE["benchmarks"]:
        assert benchmark["benchmark"] in response.text
        assert benchmark["benchmark_version"] in response.text
    for label, value in (
        ("CIS-mapped definitions", CONTROL_COVERAGE["identifiers"]["cis_mapped"]),
        ("CIS-unmapped definitions", CONTROL_COVERAGE["identifiers"]["cis_unmapped"]),
        ("Non-CIS definitions", CONTROL_COVERAGE["identifiers"]["non_cis"]),
    ):
        assert f'<div class="kpi__label">{label}</div>' in response.text
        assert f">{value}</div>" in response.text
    assert "CIS-unmapped definitions have no CIS benchmark mapping" in response.text
    assert "non-CIS definitions belong to another control namespace" in response.text
    assert "Neither is shown as a mapped CIS identifier." in response.text


def test_overview_keeps_explicit_zeroes_and_empty_dimensions_distinct(client, make_token):
    zero = {
        "generated_at": "2026-09-20T10:15:00Z",
        "platforms": [],
        "controls": {
            "total": 0, "evaluated": 0, "out_of_scope": 0,
            "undetermined_evaluations": 0,
        },
        "measurements": {"pass": 0, "fail": 0, "undetermined": 0, "not_applicable": 0},
        "identifiers": {"cis_mapped": 0, "cis_unmapped": 0, "non_cis": 0},
        "benchmarks": [],
        "total_zero": True,
    }
    STUB_STATE["control_coverage_data"] = zero
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert response.status_code == 200
    assert "No active platforms returned" in response.text
    assert (
        "No active control definitions are currently returned for this platform mix."
        in response.text
    )
    assert "The explicit zeroes below do not indicate a pass." in response.text
    assert (
        "No active benchmark and version pairs were returned for this platform mix."
        in response.text
    )
    assert response.text.count('>0</div>') >= 11


def test_control_coverage_failure_leaves_existing_overview_available(
    client, make_token, monkeypatch
):
    monkeypatch.setitem(STUB_STATE, "mode", "coverage500")
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert response.status_code == 200
    assert OVERVIEW["tenant_name"] in response.text
    assert "CIS control coverage is temporarily unavailable." in response.text
    assert '<div class="kpi__label">Measured pass</div>' not in response.text


def test_malformed_control_coverage_degrades_without_breaking_overview(client, make_token):
    STUB_STATE["control_coverage_data"] = {"generated_at": "2026-09-20T10:15:00Z"}
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert response.status_code == 200
    assert OVERVIEW["tenant_name"] in response.text
    assert "CIS control coverage is temporarily unavailable." in response.text
    assert '<div class="kpi__label">Measured pass</div>' not in response.text


def test_control_coverage_stays_a_render_only_aggregate_surface():
    source = (ROOT / "main.py").read_text()
    template = (ROOT / "templates" / "overview.html").read_text()

    assert '"/v1/portal/control-coverage"' in source
    overview_source = source[source.index("def overview"):source.index("def devices")]
    assert "get_device_roster(request.state.jwt)" not in overview_source
    assert "kpi_summary" in template
    assert "control_coverage.measurements['pass']" in template
    assert "control_coverage.identifiers.cis_unmapped" in template
