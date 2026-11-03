"""PAT-2028: each product row of GET /v1/portal/software now carries an
estate-wide `cve_assessment` object (contracts/portal-api.md "CVE assessment
state (PAT-2024, extended by PAT-2028)"), rolled up across every installation
of the product in the tenant. The /software page shows each product's state
using PAT-2025's helpers - assessed/pending/not_assessed - and degrades the
same way PAT-2025 already proved for the device-detail and devices-roster
surfaces: a missing field (older platform) or a malformed finding_count on
an assessed row must never read as "No known CVEs" (root AGENTS.md: absence
requires authority, CVE claims require evidence).

Base fixture (tests/conftest.py SOFTWARE_INVENTORY):
  ArchiveTool      assessed, finding_count=0  -> "No known CVEs"
  MeteringGap      pending, finding_count=2   -> "Checking"
  PartialEvidence  assessed, finding_count=4  -> "4 CVEs"
  OldMetering      not_assessed               -> "Not yet assessed"
  UnknownEvidence  assessed, finding_count=1  -> "1 CVE"
"""

from copy import deepcopy

from tests.conftest import SOFTWARE_INVENTORY, STUB_STATE


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _inventory_row(html, name):
    marker = html.find(name)
    assert marker >= 0, f"inventory row for {name!r} was not rendered"
    start = html.rfind("<tr", 0, marker)
    end = html.find("</tr>", marker)
    assert start >= 0 and end >= 0, f"inventory row for {name!r} was malformed"
    return html[start:end + len("</tr>")]


# ── each state on /software ────────────────────────────────────────────────
def test_software_inventory_renders_assessed_clean_state(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _inventory_row(resp.text, "ArchiveTool")
    assert "No known CVEs" in row
    assert "pill-ok" in row


def test_software_inventory_renders_assessed_with_findings_state(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _inventory_row(resp.text, "PartialEvidence")
    assert "4 CVEs" in row
    assert "pill-bad" in row


def test_software_inventory_renders_pending_state(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _inventory_row(resp.text, "MeteringGap")
    assert "Checking" in row
    assert "pill-muted" in row


def test_software_inventory_renders_not_assessed_state_with_explanation(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _inventory_row(resp.text, "OldMetering")
    assert "Not yet assessed" in row
    assert "pill-warn" in row
    assert (
        "Patched has not yet identified this product&#39;s vulnerability source"
        in row
    )
    assert "No known CVEs" not in row


# ── missing-field degradation (older platform) ─────────────────────────────
def test_software_inventory_missing_cve_assessment_field_degrades_to_not_assessed(
    client, make_token, monkeypatch,
):
    older_platform_products = [
        {k: v for k, v in p.items() if k != "cve_assessment"}
        for p in SOFTWARE_INVENTORY["products"]
    ]
    assert all("cve_assessment" not in p for p in older_platform_products)
    monkeypatch.setitem(
        STUB_STATE, "software_inventory_data",
        {**SOFTWARE_INVENTORY, "products": older_platform_products},
    )
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    resp = _get(client, token, "/software")

    assert resp.status_code == 200
    for name in ("ArchiveTool", "MeteringGap", "PartialEvidence", "OldMetering", "UnknownEvidence"):
        row = _inventory_row(resp.text, name)
        assert "Not yet assessed" in row
        assert "No known CVEs" not in row


# ── malformed finding_count never reads as clean ───────────────────────────
def test_software_inventory_assessed_with_malformed_finding_count_degrades(
    client, make_token, monkeypatch,
):
    products = deepcopy(SOFTWARE_INVENTORY["products"])
    products[0]["cve_assessment"] = {
        "state": "assessed", "last_matched_at": "2026-09-20T09:00:00Z",
        "finding_count": "not-a-number",
    }
    monkeypatch.setitem(
        STUB_STATE, "software_inventory_data", {**SOFTWARE_INVENTORY, "products": products},
    )
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    resp = _get(client, token, "/software")

    assert resp.status_code == 200
    row = _inventory_row(resp.text, "ArchiveTool")
    assert "Not yet assessed" in row
    assert "No known CVEs" not in row


def test_software_inventory_never_crashes_on_a_non_dict_cve_assessment(
    client, make_token, monkeypatch,
):
    products = deepcopy(SOFTWARE_INVENTORY["products"])
    products[0]["cve_assessment"] = "not-an-object"
    monkeypatch.setitem(
        STUB_STATE, "software_inventory_data", {**SOFTWARE_INVENTORY, "products": products},
    )
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    resp = _get(client, token, "/software")

    assert resp.status_code == 200
    row = _inventory_row(resp.text, "ArchiveTool")
    assert "Not yet assessed" in row
    assert "No known CVEs" not in row
