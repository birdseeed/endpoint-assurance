"""PAT-2022: customer AI Tooling inventory, governance and coverage."""

import csv
import html as html_module
import io
import json
import re
from copy import deepcopy
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

import main
from tests.conftest import (
    AI_TAGGED_PRODUCTS,
    AI_TOOLING_DEVICE_ITEMS,
    AI_TOOLING_DEVICES,
    AI_TOOLING_SUMMARY,
    STUB_STATE,
)

ORIGIN = "https://testserver"


@pytest.mark.parametrize("device", (False, True))
@pytest.mark.parametrize("locked", (False, True))
def test_ai_review_anchors_follow_upstream_identity_across_reordering(device, locked):
    """Same-name evidence and versions sharing a policy target need distinct anchors."""
    data = AI_TOOLING_DEVICE_ITEMS["items"] if device else AI_TAGGED_PRODUCTS["products"]
    key = "item_id" if device else "product_key"
    source = []
    for index in range(3):
        raw = deepcopy(data[0])
        raw[key] = f"same-name-{index}"
        raw["name"] = "Same AI product"
        raw["version" if device else "versions"] = (
            f"{index}.0" if device else [f"{index}.0"])
        if locked:
            raw["approval_target"] = None
        source.append(raw)

    def anchors(records):
        rows = [main._ai_item_row(raw) if device else main._ai_product_row(raw, [])
                for raw in records]
        request = main.Request({"type": "http", "path": "/ai-tooling", "query_string": b""})
        main._ai_review_rows(request, rows, device=device)
        assert len({row["row_id"] for row in rows}) == len(rows)
        assert all(re.fullmatch(r"sw-[a-f0-9]{12}", row["row_id"]) for row in rows)
        if locked:
            assert all(row["approval_item_json"] is None for row in rows)
        else:
            assert all(row["approval_item_json"] for row in rows)
        return {raw[key]: row["row_id"] for raw, row in zip(records, rows, strict=True)}

    expected = anchors(source)
    assert anchors(list(reversed(source))) == expected
    # Filtering/pagination must not change the anchor of a remaining record either.
    assert anchors(source[1:]) == {raw[key]: expected[raw[key]] for raw in source[1:]}


def _get(client, token, path="/ai-tooling"):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _row(page, name):
    for match in re.finditer(r"<tr[^>]*>.*?</tr>", page, re.DOTALL):
        if f">{name}<" in match.group(0):
            return match.group(0)
    raise AssertionError(f"no row found for {name!r}")


def test_ai_tooling_requires_auth(client):
    assert client.get("/ai-tooling").status_code == 401


def test_ai_tooling_renders_live_summary_products_cve_states_and_privacy(client, make_token):
    response = _get(client, make_token())
    assert response.status_code == 200
    body = response.text
    assert "In development" not in body
    assert "4" in body
    assert "7.0 GB" in body
    for product in ("ChatGPT", "AI Search Helper", "Copilot", "ai-helper"):
        assert product in body
    assert "Desktop app" in body
    assert "Browser extension" in body
    assert "IDE plugin" in body
    assert "CLI" in body
    assert "1 vulnerability finding (High)" in _row(body, "ai-helper")
    assert "Pending" in _row(body, "Copilot")
    assert "Not assessed" in body
    assert 'data-row-filter="ai_type"' in body
    assert 'data-row-filter="ai_state"' in body
    assert 'data-row-filter="ai_vulnerability"' in body
    assert (
        "never prompts, chat history, model output, file contents, keys, MCP arguments or "
        "environment values" in body
    )


def test_ai_tooling_filter_dropdowns_mute_zero_count_options_rather_than_hide(
    client, make_token,
):
    """PAT-2213 (Andy ruling): "zero-count options still shown but muted,
    never hidden silently" - unlike /software's Type/Approval dropdowns,
    which hide a zero-count option outright. The fixture's four products
    have no local_runtime or mcp_server type, so both must still render,
    muted, in the Type dropdown."""
    page = _get(client, make_token()).text
    type_start = page.index('data-row-filter="ai_type"')
    type_block = page[type_start:page.index("</details>", type_start)]
    assert 'value="local_runtime"' in type_block
    assert 'value="mcp_server"' in type_block
    assert "filter-dropdown__option--muted" in type_block
    # The non-zero options are unaffected (not muted).
    assert re.search(
        r'<label class="filter-dropdown__option">\s*'
        r'<input type="checkbox" name="type" value="desktop_app"',
        type_block,
    )


def test_ai_tooling_filter_type_accepts_comma_list_and_repeated_params(client, make_token):
    resp1 = _get(client, make_token(), "/ai-tooling?type=desktop_app,cli")
    dropdown1 = resp1.text[resp1.text.index('data-row-filter="ai_type"'):]
    dropdown1 = dropdown1[:dropdown1.index("</details>")]
    assert 'data-initial="desktop_app,cli"' in dropdown1

    resp2 = _get(client, make_token(), "/ai-tooling?type=desktop_app&type=cli")
    dropdown2 = resp2.text[resp2.text.index('data-row-filter="ai_type"'):]
    dropdown2 = dropdown2[:dropdown2.index("</details>")]
    assert 'data-initial="desktop_app,cli"' in dropdown2


def test_ai_tooling_filter_unknown_values_are_dropped_not_reflected(client, make_token):
    resp = _get(
        client, make_token(),
        "/ai-tooling?type=desktop_app,<script>alert(1)</script>,bogus",
    )
    assert "<script>alert(1)</script>" not in resp.text
    dropdown = resp.text[resp.text.index('data-row-filter="ai_type"'):]
    dropdown = dropdown[:dropdown.index("</details>")]
    assert 'data-initial="desktop_app"' in dropdown


def test_ai_tooling_filter_chips_render_from_query_params_and_combine(client, make_token):
    page = _get(
        client, make_token(), "/ai-tooling?type=desktop_app,cli&state=unreviewed",
    ).text
    chips_start = page.index('<div class="filter-chips"')
    chips = page[chips_start:page.index("</div>", chips_start)]
    assert "Desktop app" in chips
    assert "CLI" in chips
    assert "Unreviewed" in chips
    assert "Clear all" in chips


def test_ai_tooling_unreviewed_summary_leads_and_links_to_filtered_table(client, make_token):
    page = _get(client, make_token()).text
    grid_start = page.index('class="ai-review-summary"')
    tile_start = page.index('<a class="ai-summary__item', grid_start)
    tile = page[tile_start:page.index("</a>", tile_start)]
    assert "Unreviewed" in tile
    assert 'href="/ai-tooling?state=unreviewed#products"' in tile


def test_ai_tooling_zero_summary_is_muted_not_headline_weight(client, make_token, monkeypatch):
    monkeypatch.setitem(
        AI_TAGGED_PRODUCTS, "products",
        [p for p in AI_TAGGED_PRODUCTS["products"] if p["approval_state"] != "unapproved"],
    )
    page = _get(client, make_token()).text
    grid_start = page.index('class="ai-review-summary"')
    unapproved_start = page.index("Unapproved", grid_start)
    tile_start = page.rindex('<a class="ai-summary__item', grid_start, unapproved_start)
    tile = page[tile_start:page.index("</a>", tile_start)]
    assert "ai-summary__item--zero" in tile
    assert "ai-summary__item--zero" in tile


def test_ai_tooling_local_ai_tile_states_runtime_with_no_models_pulled(client, make_token):
    """PAT-2213 (Andy): "Local models 0 devices next to Products Local
    runtimes (1) reads as a contradiction unless it says a runtime is
    installed with no models pulled." """
    data = deepcopy(AI_TAGGED_PRODUCTS)
    data["products"][0].update({
        "subtype": "local_runtime", "last_used_at": None, "metering_state": "not_applicable",
        "metered_installation_count": 0, "unmetered_installation_count": 0,
        "stale_metering_installation_count": 0, "unknown_metering_installation_count": 0,
    })
    STUB_STATE["ai_tagged_products_data"] = data
    summary = deepcopy(AI_TOOLING_SUMMARY)
    summary["local_models"]["models"]["devices"] = 0
    STUB_STATE["ai_tooling_summary_data"] = summary
    page = _get(client, make_token()).text
    assert "1 runtime installed" in page
    assert "no models pulled yet" in page


def test_ai_tooling_approval_uses_shared_route_for_addressable_rows(client, make_token):
    token = make_token()
    page = _get(client, token).text
    ext_row = _row(page, "AI Search Helper")
    match = re.search(r'class="approval-select"[^>]+value="([^"]+)"', ext_row)
    assert match
    item = json.loads(html_module.unescape(match.group(1)))
    assert item == {
        "type": "browser_extension", "browser": "chrome",
        "extension_id": "abcd", "name": "AI Search Helper",
    }

    response = client.post(
        "/software/approvals",
        content=urlencode([
            ("state", "approved"), ("item", json.dumps(item)),
            ("return_to", "/ai-tooling"), ("csrf_token", main._csrf_token(token)),
        ]),
        headers={"Cf-Access-Jwt-Assertion": token, "Origin": ORIGIN,
                 "Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert urlsplit(response.headers["location"]).path == "/ai-tooling"
    assert STUB_STATE["approval_puts"][0]["body"]["items"] == [{
        "type": "browser_extension", "browser": "chrome", "extension_id": "abcd",
    }]


def test_ai_tooling_uses_exact_counts_and_server_approval_target(client, make_token):
    token = make_token()
    page = _get(client, token).text
    # PAT-2243 keeps the same authoritative figure in a compact summary.
    assert re.search(r'<span>Devices with AI tooling</span>\s*<strong>3</strong>', page)
    assert "confirmed lower bound" not in page

    cli_row = _row(page, "ai-helper")
    match = re.search(r'class="approval-select"[^>]+value="([^"]+)"', cli_row)
    assert match
    item = json.loads(html_module.unescape(match.group(1)))
    assert item == {
        "type": "observation", "identity_kind": "npm_package",
        "name": "ai-helper", "source": "npm",
    }
    assert main._ai_summary_view(AI_TOOLING_SUMMARY)["devices_with_tooling"] == 3
    unsafe_without_target = {**AI_TAGGED_PRODUCTS["products"][0], "approval_target": None}
    assert main._ai_approval_view(unsafe_without_target)["approval_item"] is None


def test_shared_approval_route_accepts_exact_tooling_observation_identity(client, make_token):
    token = make_token()
    item = {
        "type": "observation", "identity_kind": "npm_package",
        "name": "@scope/assistant", "source": "npm",
    }
    response = client.post(
        "/software/approvals",
        content=urlencode([
            ("state", "unapproved"), ("item", json.dumps(item)),
            ("return_to", "/ai-tooling"), ("csrf_token", main._csrf_token(token)),
        ]),
        headers={"Cf-Access-Jwt-Assertion": token, "Origin": ORIGIN,
                 "Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert STUB_STATE["approval_puts"][0]["body"]["items"] == [item]


@pytest.mark.parametrize("identity_kind", main.APPROVAL_OBSERVATION_KINDS)
def test_observation_approval_item_accepts_each_allowed_identity_kind(identity_kind):
    parsed = main._parse_approval_item({
        "type": "observation", "identity_kind": identity_kind,
        "name": "  exact-tool-identity  ",
    })

    assert parsed == ({
        "type": "observation", "identity_kind": identity_kind,
        "name": "exact-tool-identity",
    }, "  exact-tool-identity  ")


def test_observation_approval_item_preserves_optional_source_exactly():
    parsed = main._parse_approval_item({
        "type": "observation", "identity_kind": "pip_package",
        "name": "assistant-package", "source": "PyPI",
    })

    assert parsed == ({
        "type": "observation", "identity_kind": "pip_package",
        "name": "assistant-package", "source": "PyPI",
    }, "assistant-package")


@pytest.mark.parametrize("payload", [
    {"type": "observation", "identity_kind": "unknown", "name": "tool"},
    {"type": "observation", "identity_kind": "npm_package"},
    {"type": "observation", "identity_kind": "npm_package", "name": "   "},
    {"type": "observation", "identity_kind": "npm_package", "name": "tool",
     "source": "s" * (main.APPROVAL_MAX_IDENTIFIER_CHARS + 1)},
    {"type": "observation", "identity_kind": "npm_package", "name": "bad\nname"},
    {"type": "observation", "identity_kind": "npm_package", "name": "tool",
     "source": "bad\tsource"},
    {"type": "observation", "identity_kind": "npm_package", "name": "tool",
     "tenant_id": "tenant-a"},
])
def test_observation_approval_item_rejects_invalid_identity_shapes(payload):
    assert main._parse_approval_item(payload) is None


@pytest.mark.parametrize("target", [
    "/ai-tooling",
    "/ai-tooling?type=cli&state=unapproved",
    "/ai-tooling/devices/dev-mac-001",
    "/ai-tooling/devices/dev-mac-001?offset=100",
])
def test_ai_tooling_approval_return_to_accepts_allowlisted_paths(target):
    assert main._approval_return_to(target) == target


@pytest.mark.parametrize("target", [
    "/ai-tooling/devices/../software",
    "/ai-tooling/devices/dev-mac-001/extra",
    "//evil.example/ai-tooling",
    "https://evil.example/ai-tooling",
    "/ai-tooling/devices/" + ("a" * 129),
])
def test_ai_tooling_approval_return_to_rejects_unsafe_or_unlisted_paths(target):
    assert main._approval_return_to(target) == "/software"


def test_ai_tooling_device_collection_detail_keeps_unknown_distinct_from_zero(
    client, make_token,
):
    body = _get(client, make_token()).text
    reported = _row(body, "acme-mbp-frontdesk")
    not_reported = _row(body, "acme-mbp-storeroom")
    assert "2 models" in reported
    assert "1 server" in reported
    assert "7.0 GB" in reported
    assert "not yet reported" in not_reported.lower()
    assert "0 models" not in not_reported
    assert "0 servers" not in not_reported


def test_ai_tooling_device_drilldown_renders_allowlisted_mcp_model_and_assessment(
    client, make_token,
):
    response = _get(client, make_token(), "/ai-tooling/devices/dev-mac-001")
    assert response.status_code == 200
    body = response.text
    for value in (
        "acme-mbp-frontdesk", "ChatGPT", "AI Search Helper", "Llama 3 8B", "4.8 GB",
        "GitHub", "stdio", "npx", "@modelcontextprotocol/server-github", "github.com",
        "1 vulnerability finding", "CVE-2026-1234",
    ):
        assert value in body
    for secret in ("super-secret-value", "/Users/alice", "token=ghp_"):
        assert secret not in body.lower()
    assert 'href="/ai-tooling/devices/dev-mac-001.csv"' in body

    row = _row(body, "GitHub")
    match = re.search(r'class="approval-select"[^>]+value="([^"]+)"', row)
    assert match
    assert json.loads(html_module.unescape(match.group(1))) == {
        "type": "observation", "identity_kind": "mcp_server",
        "name": "github", "source": "claude_desktop",
    }


@pytest.mark.parametrize("block,state,label", [
    ("desktop_apps", "metered", "No launch recorded"),
    ("desktop_apps", "unknown", "Metering not reported"),
    ("desktop_apps", "stale", "Metering evidence is stale"),
    ("desktop_apps", "unmetered", "Metering unavailable"),
    ("browser_extensions", "not_applicable", "Not collected"),
])
def test_ai_tooling_device_accepts_platform_omitted_null_last_used(
    client, make_token, block, state, label,
):
    # ToolingEvidenceItem.LastUsedAt uses omitempty. Production Cursor and Zed
    # have fresh metered rows with a NULL last_used_at, so Go omits the key.
    data = deepcopy(AI_TOOLING_DEVICE_ITEMS)
    item = next(row for row in data["items"] if row["block"] == block)
    del item["last_used_at"]
    item["metering_state"] = state
    STUB_STATE["ai_tooling_device_items_data"] = data

    response = _get(client, make_token(), "/ai-tooling/devices/dev-mac-001")

    assert response.status_code == 200
    assert label in _row(response.text, item["name"])


@pytest.mark.parametrize("mutation", [
    {"last_used_at": 123},
    {"metering_state": "surprise"},
    {"metering_state": "unknown", "last_used_at": "2026-09-29T11:00:00Z"},
    {"device_id": "foreign-device"},
])
def test_ai_tooling_device_invalid_evidence_has_clear_message(
    client, make_token, mutation,
):
    data = deepcopy(AI_TOOLING_DEVICE_ITEMS)
    data["items"][0].update(mutation)
    STUB_STATE["ai_tooling_device_items_data"] = data

    response = _get(client, make_token(), "/ai-tooling/devices/dev-mac-001")

    assert response.status_code == 502
    assert "AI tooling evidence could not be verified" in response.text
    assert "ChatGPT" not in response.text


def test_ai_tooling_device_detail_rejects_conflicting_item_hostnames(client, make_token):
    data = deepcopy(AI_TOOLING_DEVICE_ITEMS)
    data["items"][1]["hostname"] = "different-device-name"
    STUB_STATE["ai_tooling_device_items_data"] = data

    response = _get(client, make_token(), "/ai-tooling/devices/dev-mac-001")

    assert response.status_code == 502
    assert "AI tooling evidence could not be verified" in response.text
    assert "acme-mbp-frontdesk" not in response.text
    assert "different-device-name" not in response.text


def test_ai_tooling_device_detail_renders_explicit_empty_items_state(client, make_token):
    STUB_STATE["ai_tooling_device_items_data"] = {
        **deepcopy(AI_TOOLING_DEVICE_ITEMS), "total": 0, "items": [],
    }

    response = _get(client, make_token(), "/ai-tooling/devices/dev-mac-001")

    assert response.status_code == 200
    assert ">dev-mac-001</h1>" in response.text
    assert "0 of 0" in response.text
    assert "No current AI-tooling items were reported for this device" in response.text
    assert "Collection gaps remain unknown rather than clean" in response.text
    assert "ai-device-items-table" not in response.text


def test_ai_tooling_device_drilldown_csv_and_tenant_safe_not_found(client, make_token):
    token = make_token()
    response = _get(client, token, "/ai-tooling/devices/dev-mac-001.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "ati_mcp_1" in response.text
    assert "ati_app_1" in response.text
    assert "ati_ext_1" in response.text
    assert STUB_STATE["ai_tooling_item_requests"][-1]["jwt"] == token
    assert STUB_STATE["ai_tooling_item_requests"][-1]["query"] == {"format": ["csv"]}

    STUB_STATE["mode"] = "ai_tooling_items_not_found"
    response = _get(client, token, "/ai-tooling/devices/foreign-device")
    assert response.status_code == 404


def test_ai_tooling_device_fixture_contains_no_secret_or_raw_path_fields():
    serialised = json.dumps(AI_TOOLING_DEVICE_ITEMS)
    for forbidden in (
        '"args"', '"environment"', '"headers"', '"key"', '"prompt"',
        '"path"', '"raw_url"',
    ):
        assert forbidden not in serialised


def test_ai_tooling_empty_found_and_not_reported_states_are_distinct(client, make_token):
    STUB_STATE["ai_tagged_products_data"] = {
        "generated_at": "2026-09-27T12:00:00Z", "category": "ai_tooling",
        "subtype": None, "total": 0, "limit": 1000, "offset": 0,
        "estate_too_large": False, "distinct_device_total": 0, "products": [],
    }
    response = _get(client, make_token())
    assert "No AI tooling was found in the evidence reported so far" in response.text

    not_reported = {
        **AI_TOOLING_SUMMARY,
        "collection_status": {
            block: {"complete": 0, "partial": 0, "not_present": 0, "failed": 0,
                    "not_reported": 3}
            for block in ("ide_extensions", "package_managers", "local_models", "mcp_servers")
        },
    }
    STUB_STATE["ai_tooling_summary_data"] = not_reported
    response = _get(client, make_token())
    assert "AI tooling has not been reported by these devices yet" in response.text
    assert "No AI tooling was found" not in response.text


def test_ai_tooling_csv_exports_product_and_assessment_fields(client, make_token):
    response = _get(client, make_token(), "/ai-tooling.csv")
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert {row["product"] for row in rows} == {
        "ChatGPT", "AI Search Helper", "Copilot", "ai-helper",
    }
    cli = next(row for row in rows if row["product"] == "ai-helper")
    # Independent endpoint snapshots cannot authoritatively prove complete
    # coverage, but already-known findings remain visible.
    assert cli["assessment_state"] == "unavailable"
    assert cli["vulnerability_finding_count"] == "1"
    assert cli["highest_severity"] == "high"
    assert "cve_state" not in rows[0]
    assert "cve_count" not in rows[0]


def test_ai_tooling_csv_neutralises_tab_and_carriage_return(client, make_token):
    data = deepcopy(AI_TAGGED_PRODUCTS)
    data["products"] = [
        {**data["products"][0], "name": "\t=TAB"},
        {**data["products"][1], "name": "\r+CR"},
    ]
    STUB_STATE["ai_tagged_products_data"] = data

    response = _get(client, make_token(), "/ai-tooling.csv")
    assert response.status_code == 200
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert [row["product"] for row in rows] == ["'\t=TAB", "'\r+CR"]


def test_ai_tooling_csv_refuses_multi_page_reorder_without_partial_file(
    client, make_token,
):
    template = AI_TAGGED_PRODUCTS["products"][0]
    products = [
        {**deepcopy(template), "name": f"AI product {index}",
         "product_key": f"product:ai-{index}"}
        for index in range(1001)
    ]
    STUB_STATE["ai_tagged_products_data"] = {
        **deepcopy(AI_TAGGED_PRODUCTS), "products": products, "total": len(products),
    }
    STUB_STATE["ai_tagged_products_reorder_after_first"] = True

    response = _get(client, make_token(), "/ai-tooling.csv")

    assert response.status_code == 503
    assert "Export unavailable" in response.text
    assert "1,000 products" in response.text
    assert "product,type,vendor" not in response.text
    assert STUB_STATE["ai_tagged_product_requests"] == [{"limit": 1000, "offset": 0}]


def test_ai_tooling_page_hides_export_when_complete_csv_exceeds_ceiling(
    client, make_token,
):
    template = AI_TAGGED_PRODUCTS["products"][0]
    products = [
        {**deepcopy(template), "name": f"AI product {index}",
         "product_key": f"product:ai-{index}"}
        for index in range(1001)
    ]
    STUB_STATE["ai_tagged_products_data"] = {
        **deepcopy(AI_TAGGED_PRODUCTS), "products": products, "total": len(products),
    }

    response = _get(client, make_token())

    assert response.status_code == 200
    assert 'href="/ai-tooling.csv"' not in response.text
    assert "Complete CSV export is unavailable above 1,000 products" in response.text
    assert "Download the CSV for the complete list" not in response.text


def test_ai_tooling_uses_authoritative_tagged_product_metering_without_side_join(
    client, make_token,
):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    data = deepcopy(AI_TAGGED_PRODUCTS)
    data["products"][0].update({
        "last_used_at": "2026-09-26T08:30:00Z",
        "metered_installation_count": 2,
        "unmetered_installation_count": 0,
        "stale_metering_installation_count": 0,
        "unknown_metering_installation_count": 0,
        "metering_state": "metered",
    })
    STUB_STATE["ai_tagged_products_data"] = data
    STUB_STATE["mode"] = "software500"

    response = _get(client, token)
    assert response.status_code == 200
    chatgpt = _row(response.text, "ChatGPT")
    assert 'data-value="2026-09-26T08:30:00Z"' in chatgpt
    assert STUB_STATE["software_inventory_requests"] == []

    export = _get(client, token, "/ai-tooling.csv")
    rows = list(csv.DictReader(io.StringIO(export.text)))
    exported = next(row for row in rows if row["product"] == "ChatGPT")
    assert exported["last_used_at"] == "2026-09-26T08:30:00Z"
    assert exported["last_used_state"] == "metered"


def test_ai_tooling_last_used_null_is_clean_only_when_fully_metered(client, make_token):
    data = deepcopy(AI_TAGGED_PRODUCTS)
    app = data["products"][0]
    app["last_used_at"] = None
    STUB_STATE["ai_tagged_products_data"] = data

    app.update({
        "metered_installation_count": 2, "unmetered_installation_count": 0,
        "stale_metering_installation_count": 0,
        "unknown_metering_installation_count": 0, "metering_state": "metered",
    })
    assert "No launch recorded" in _row(_get(client, make_token()).text, "ChatGPT")

    app.update({
        "metered_installation_count": 1, "unmetered_installation_count": 1,
        "metering_state": "partial",
    })
    row = _row(_get(client, make_token()).text, "ChatGPT")
    assert "Partial metering coverage" in row
    assert "No launch recorded" not in row

    del app["unknown_metering_installation_count"]
    page = _get(client, make_token()).text
    assert "Products are temporarily unavailable" in page


def test_ai_tooling_evidence_report_comes_from_platform_catalogue(client, make_token):
    response = _get(client, make_token(), "/reports")
    assert response.status_code == 200
    assert "AI Tooling Evidence" in response.text
    assert 'name="report_type" value="ai-tooling-evidence"' in response.text


def test_ai_tooling_assessment_join_requires_exact_source_ecosystem_and_identity():
    product = {
        "subtype": "cli", "name": "assistant", "canonical_name": "assistant",
        "identifier": "assistant", "versions": ["1.2.3"],
        "approval_target": {
            "type": "observation", "identity_kind": "npm_package",
            "name": "assistant", "source": "npm",
        },
    }
    assessments = [
        {
            "subject_kind": "package", "identity": "assistant", "version": "1.2.3",
            "ecosystem": "PyPI", "source": "pypi", "state": "assessed",
            "finding_count": 0, "highest_severity": None,
        },
    ]

    assert main._ai_cve_view(product, assessments)["state"] == "unavailable"

    assessments[0]["ecosystem"] = "npm"
    assert main._ai_cve_view(product, assessments)["state"] == "unavailable"

    assessments[0]["source"] = "npm"
    assert main._ai_cve_view(product, assessments)["state"] == "assessed"


def test_ai_tooling_assessment_requires_one_valid_row_for_every_product_version():
    product = deepcopy(AI_TAGGED_PRODUCTS["products"][3])
    product["versions"] = ["2.4.0", "2.5.0"]
    assessed = deepcopy(AI_TOOLING_SUMMARY["vulnerability_products"][0])

    view = main._ai_cve_view(product, [assessed])
    assert view["state"] == "unavailable"
    assert view["count"] is None

    product["versions"] = ["2.4.0"]
    assert main._ai_cve_view(product, [assessed, deepcopy(assessed)])["state"] == "unavailable"

    malformed = {**assessed, "finding_count": "0"}
    assert main._ai_cve_view(product, [malformed])["state"] == "unavailable"


def test_ai_tooling_known_findings_remain_visible_when_other_version_is_pending(
    client, make_token,
):
    product = deepcopy(AI_TAGGED_PRODUCTS["products"][3])
    product["versions"] = ["2.4.0", "2.5.0"]
    found = {**deepcopy(AI_TOOLING_SUMMARY["vulnerability_products"][0]),
             "finding_count": 2}
    pending = {
        **found, "version": "2.5.0", "state": "pending",
        "reason": "inventory_changed", "finding_count": None,
        "highest_severity": None, "advisory_sources": [],
    }

    view = main._ai_cve_view(product, [found, pending])
    assert view["state"] == "pending"
    assert view["filter"] == "has"
    assert view["count"] == 2
    assert "2 vulnerability findings" in view["label"]
    assert "incomplete" in view["label"].lower()

    tagged = deepcopy(AI_TAGGED_PRODUCTS)
    product["version_count"] = 2
    tagged.update({"products": [product], "total": 1, "distinct_device_total": 1})
    summary = deepcopy(AI_TOOLING_SUMMARY)
    summary["vulnerability_products"] = [found, pending]
    STUB_STATE["ai_tagged_products_data"] = tagged
    STUB_STATE["ai_tooling_summary_data"] = summary
    row = _row(_get(client, make_token()).text, "ai-helper")
    assert 'data-filter-ai_vulnerability="has"' in row
    assert "Assessment incomplete" in row


def test_ai_tooling_cross_endpoint_snapshot_mismatch_never_claims_clean(
    client, make_token,
):
    tagged = deepcopy(AI_TAGGED_PRODUCTS)
    tagged["products"] = [deepcopy(tagged["products"][3])]
    tagged["total"] = 1
    tagged["distinct_device_total"] = 1
    summary = deepcopy(AI_TOOLING_SUMMARY)
    summary["vulnerability_products"] = [{
        **deepcopy(summary["vulnerability_products"][0]),
        "finding_count": 0, "highest_severity": None,
    }]
    STUB_STATE["ai_tagged_products_data"] = tagged
    STUB_STATE["ai_tooling_summary_data"] = summary

    row = _row(_get(client, make_token()).text, "ai-helper")
    assert "Assessment unavailable" in row
    assert "No known vulnerability findings" not in row


def test_ai_tooling_device_assessments_fail_closed_on_bad_join_freshness_or_shape(
    client, make_token,
):
    mutations = (
        lambda assessment: assessment.update({"identity": "different-package"}),
        lambda assessment: assessment.update({"source": "PyPI"}),
        lambda assessment: assessment.update({"version": "9.9.9"}),
        lambda assessment: assessment["evidence_provenance"].update({"fresh": False}),
        lambda assessment: assessment["evidence_provenance"].update(
            {"item_id": "ati_wrong"}),
        lambda assessment: assessment["advisories"][0].update({"source": 7}),
    )
    for mutate in mutations:
        data = deepcopy(AI_TOOLING_DEVICE_ITEMS)
        mutate(data["items"][-1]["assessments"][0])
        STUB_STATE["ai_tooling_device_items_data"] = data
        row = _row(_get(
            client, make_token(), "/ai-tooling/devices/dev-mac-001").text, "GitHub")
        assert "Assessment unavailable" in row
        assert "No known vulnerability findings" not in row

    data = deepcopy(AI_TOOLING_DEVICE_ITEMS)
    data["items"][-1]["assessments"].append(
        deepcopy(data["items"][-1]["assessments"][0]))
    STUB_STATE["ai_tooling_device_items_data"] = data
    row = _row(_get(client, make_token(), "/ai-tooling/devices/dev-mac-001").text, "GitHub")
    assert "Assessment unavailable" in row


def test_ai_tooling_device_unknown_policy_state_fails_closed(client, make_token):
    data = deepcopy(AI_TOOLING_DEVICE_ITEMS)
    data["items"][-1]["policy_state"] = "surprise"
    STUB_STATE["ai_tooling_device_items_data"] = data
    response = _get(client, make_token(), "/ai-tooling/devices/dev-mac-001")
    assert response.status_code == 502


def test_ai_tooling_device_list_paginates_in_compact_pages(client, make_token):
    devices = []
    for index in range(51):
        row = deepcopy(AI_TOOLING_DEVICES["devices"][0])
        row["device_id"] = f"device-{index:03d}"
        row["hostname"] = f"device-{index:03d}"
        devices.append(row)
    STUB_STATE["ai_tooling_devices_data"] = {
        **deepcopy(AI_TOOLING_DEVICES), "total": 51, "devices": devices,
    }

    first = _get(client, make_token()).text
    assert "device-000" in first
    assert "device-025" not in first
    assert 'href="?device_offset=25#devices"' in first

    second = _get(client, make_token(), "/ai-tooling?device_offset=25").text
    assert "device-025" in second
    assert "device-000" not in second
    assert 'href="?device_offset=0#devices"' in second


def test_ai_tooling_malformed_summary_and_device_blocks_stay_unavailable(client, make_token):
    malformed = deepcopy(AI_TOOLING_SUMMARY)
    del malformed["devices_with_tooling"]
    del malformed["collection_status"]["mcp_servers"]
    malformed["local_models"] = {"models": {}}
    STUB_STATE["ai_tooling_summary_data"] = malformed
    devices = deepcopy(AI_TOOLING_DEVICES)
    del devices["devices"][0]["mcp_servers"]
    STUB_STATE["ai_tooling_devices_data"] = devices

    summary = main._ai_summary_view(malformed)
    assert summary["devices_with_tooling"] is None
    assert summary["collection"]["mcp_servers"]["available"] is False
    assert summary["local_model_devices"] is None
    assert main._ai_device_block(None, "mcp_servers")["status"] == "unavailable"

    page = _get(client, make_token()).text
    assert "Coverage unavailable" in page
    assert "Collection unavailable" in _row(page, "acme-mbp-frontdesk")


def test_ai_tooling_malformed_product_and_device_envelopes_fail_closed(client, make_token):
    STUB_STATE["mode"] = "ai_tagged_products_malformed"
    page = _get(client, make_token()).text
    assert "Products are temporarily unavailable" in page
    assert "No AI tooling was found" not in page
    assert _get(client, make_token(), "/ai-tooling.csv").status_code == 502

    STUB_STATE["mode"] = "ai_tagged_products_bad_row"
    assert "Products are temporarily unavailable" in _get(client, make_token()).text

    STUB_STATE["mode"] = "ai_tooling_devices_malformed"
    page = _get(client, make_token()).text
    assert "Device collection is temporarily unavailable" in page
    assert "No devices have reported yet" not in page

    STUB_STATE["mode"] = "ai_tooling_devices_bad_row"
    assert "Device collection is temporarily unavailable" in _get(client, make_token()).text


def test_ai_tooling_uses_vulnerability_finding_language(client, make_token):
    page = _get(client, make_token()).text
    assert "Vulnerability findings" in page
    assert "vulnerability finding" in page
    assert "CVEs" not in page


def test_ai_tooling_notification_settings_are_independent_and_admin_guarded(
    client, make_token,
):
    token = make_token()
    page = _get(client, token).text
    assert "AI tooling first seen" in page
    assert "New software first seen" in page
    # PAT-2213: one shared form/Save for the whole card now, not one per
    # row ("two saves for one form", Andy's complaint on this ticket) -
    # see test_ai_tooling_combined_notifications_save_updates_both below
    # for the new single-POST shape's own coverage.
    assert page.count('action="/ai-tooling/notifications"') == 1

    response = client.post(
        "/ai-tooling/notifications",
        content=urlencode([
            ("setting", "ai_tooling_notifications_enabled"), ("enabled", "on"),
            ("csrf_token", main._csrf_token(token)),
        ]),
        headers={"Cf-Access-Jwt-Assertion": token, "Origin": ORIGIN,
                 "Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert STUB_STATE["software_notification_puts"][-1]["body"] == {
        "ai_tooling_notifications_enabled": True,
    }
    location = response.headers["location"]
    assert "notification_saved" not in location
    flash = parse_qs(urlsplit(location).query)["notification_result"][0]
    assert "Notification setting saved" in _get(client, token, location).text
    assert "Notification setting saved" not in _get(
        client, token, "/ai-tooling?notification_saved=ai_tooling").text
    other_token = make_token(email="other@example.com")
    assert "Notification setting saved" not in _get(
        client, other_token, f"/ai-tooling?notification_result={flash}").text

    response = client.post(
        "/ai-tooling/notifications",
        content=urlencode([
            ("setting", "new_software_enabled"),
            ("csrf_token", main._csrf_token(token)),
        ]),
        headers={"Cf-Access-Jwt-Assertion": token, "Origin": ORIGIN,
                 "Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert STUB_STATE["software_notification_puts"][-1]["body"] == {
        "new_software_enabled": False,
    }

    STUB_STATE["portal_role"] = "viewer"
    before = len(STUB_STATE["software_notification_puts"])
    response = client.post(
        "/ai-tooling/notifications",
        content=urlencode([
            ("setting", "ai_tooling_notifications_enabled"),
            ("csrf_token", main._csrf_token(token)),
        ]),
        headers={"Cf-Access-Jwt-Assertion": token, "Origin": ORIGIN,
                 "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 403
    assert len(STUB_STATE["software_notification_puts"]) == before


def test_ai_tooling_combined_notifications_save_updates_both(client, make_token):
    """PAT-2213: the AI Tooling page's own notifications card save shape -
    one `settings` marker plus one `enabled_<key>` checkbox per setting,
    one POST, saved as two sequential PUTs (the unchanged single-key
    contract, just called twice) rather than a new multi-key upstream
    payload this repo can't confirm the platform accepts."""
    token = make_token()
    response = client.post(
        "/ai-tooling/notifications",
        content=urlencode([
            ("settings", "ai_tooling,new_software"),
            ("enabled_ai_tooling", "on"),
            ("csrf_token", main._csrf_token(token)),
        ]),
        headers={"Cf-Access-Jwt-Assertion": token, "Origin": ORIGIN,
                 "Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    puts = STUB_STATE["software_notification_puts"]
    assert len(puts) == 2
    assert puts[-2]["body"] == {"ai_tooling_notifications_enabled": True}
    assert puts[-1]["body"] == {"new_software_enabled": False}
    location = response.headers["location"]
    assert location.startswith("/ai-tooling?")
    assert "Notification setting saved" in _get(client, token, location).text


def test_ai_tooling_combined_notifications_save_rejects_unknown_fields(client, make_token):
    token = make_token()
    response = client.post(
        "/ai-tooling/notifications",
        content=urlencode([
            ("settings", "ai_tooling,new_software"),
            ("enabled_ai_tooling", "on"),
            ("enabled_bogus", "on"),
            ("csrf_token", main._csrf_token(token)),
        ]),
        headers={"Cf-Access-Jwt-Assertion": token, "Origin": ORIGIN,
                 "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 400
    assert STUB_STATE["software_notification_puts"] == []


def test_ai_tooling_combined_notifications_save_rejects_unknown_setting(client, make_token):
    token = make_token()
    response = client.post(
        "/ai-tooling/notifications",
        content=urlencode([
            ("settings", "ai_tooling,bogus"),
            ("csrf_token", main._csrf_token(token)),
        ]),
        headers={"Cf-Access-Jwt-Assertion": token, "Origin": ORIGIN,
                 "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 400
    assert STUB_STATE["software_notification_puts"] == []


def test_ai_tooling_combined_notifications_save_is_admin_guarded(client, make_token):
    token = make_token()
    STUB_STATE["portal_role"] = "viewer"
    response = client.post(
        "/ai-tooling/notifications",
        content=urlencode([
            ("settings", "ai_tooling,new_software"),
            ("enabled_ai_tooling", "on"),
            ("csrf_token", main._csrf_token(token)),
        ]),
        headers={"Cf-Access-Jwt-Assertion": token, "Origin": ORIGIN,
                 "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 403
    assert STUB_STATE["software_notification_puts"] == []


def test_ai_tooling_notifications_channel_gap_states_plainly(client, make_token, monkeypatch):
    """PAT-2213: "0 configured channels" gave no route to configure one.
    No customer-facing channel-setup route exists anywhere in this repo
    (grepped before writing this), so a zero-channel setting states the
    gap plainly instead of linking anywhere, and never implies Patched
    will set one up for the customer (rubric C1)."""
    from tests.conftest import SOFTWARE_NOTIFICATIONS
    data = deepcopy(SOFTWARE_NOTIFICATIONS)
    data["ai_tooling"]["channels"] = 0
    monkeypatch.setitem(STUB_STATE, "software_notifications_data", data)
    page = _get(client, make_token()).text
    assert "no alert channels are set up for your account yet" in page
    assert "configured channel" in page  # the other (new_software) setting still has one
    assert 'href="/settings' not in page
    assert 'href="/channels' not in page


def test_ai_tooling_notification_settings_fail_closed(client, make_token):
    token = make_token()
    response = client.post(
        "/ai-tooling/notifications",
        content=urlencode([
            ("setting", "ai_tooling_notifications_enabled"), ("enabled", "on"),
            ("csrf_token", "wrong"),
        ]),
        headers={"Cf-Access-Jwt-Assertion": token, "Origin": ORIGIN,
                 "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 403
    assert STUB_STATE["software_notification_puts"] == []

    STUB_STATE["software_notifications_error"] = (500, {"error": "boom"})
    page = _get(client, token).text
    assert "Notification settings are temporarily unavailable" in page
    assert 'action="/ai-tooling/notifications"' not in page


def test_ai_tooling_sections_fail_soft_and_old_platform_is_truthful(client, make_token):
    STUB_STATE["mode"] = "ai_tagged_products_fail"
    response = _get(client, make_token())
    assert response.status_code == 200
    assert "Products are temporarily unavailable" in response.text
    assert "acme-mbp-frontdesk" in response.text

    STUB_STATE["mode"] = "ai_tooling_not_found"
    response = _get(client, make_token())
    assert response.status_code == 200
    assert "AI Tooling data isn't available yet" in response.text


def test_ai_tooling_nav_is_no_longer_a_placeholder(client, make_token):
    body = _get(client, make_token()).text
    assert 'href="/ai-tooling" class="rail__item rail__item--primary active"' in body
    assert 'rail__status">In development' not in body


def test_ai_tooling_fixture_contains_no_secret_mcp_fields():
    serialised = json.dumps(AI_TOOLING_DEVICES)
    for forbidden in ('"args"', '"environment"', '"headers"', '"key"', '"prompt"'):
        assert forbidden not in serialised


def test_ai_tooling_combined_notifications_partial_failure_does_not_claim_nothing_changed(
        client, make_token, monkeypatch):
    """PAT-2213 review: the first PUT saves and the second fails, so the
    refusal must not say "Nothing was changed"."""
    token = make_token()
    real_put = main.upstream.put_json
    calls = {"n": 0}

    def flaky_put(path, jwt, body):
        calls["n"] += 1
        if calls["n"] == 2:
            raise main.upstream.UpstreamError("error", "boom")
        return real_put(path, jwt, body)

    monkeypatch.setattr(main.upstream, "put_json", flaky_put)
    response = client.post(
        "/ai-tooling/notifications",
        content=urlencode([
            ("settings", "ai_tooling,new_software"),
            ("enabled_ai_tooling", "on"),
            ("csrf_token", main._csrf_token(token)),
        ]),
        headers={"Cf-Access-Jwt-Assertion": token, "Origin": ORIGIN,
                 "Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=False,
    )
    assert response.status_code == 502
    assert "Nothing was changed" not in response.text
    assert "Some notification settings could not be saved" in response.text


@pytest.mark.parametrize("path,state", [
    ("/ai-tooling", "unreviewed"),
    ("/ai-tooling/devices/dev-mac-001", "approved"),
])
def test_ai_review_first_paint_search_filters_and_chips(client, make_token, path, state):
    page = _get(client, make_token(), path + "?" + urlencode({
        "type": "desktop_app", "state": state, "search": 'ChatGPT',
    })).text
    chat = _row(page, "ChatGPT")
    other = _row(page, "AI Search Helper")
    assert 'class=" "' in chat
    assert 'row-hide-filter' in other and 'row-hide-search' in other
    assert 'name="search" form="ai-tooling-search-form"' in page
    assert 'value="ChatGPT"' in page
    assert 'Search: ChatGPT' in page
    assert 'href="' + path + '"' in page
    assert chat.count('class="pill pill-state ') == 1
    assert 'class="approval-row-form review-form"' in chat
    assert 'name="return_anchor"' in chat


@pytest.mark.parametrize("path", ["/ai-tooling", "/ai-tooling/devices/dev-mac-001"])
def test_ai_review_role_failure_keeps_state_and_evidence_without_writes(client, make_token, path):
    STUB_STATE["me_status"] = 500
    page = _get(client, make_token(), path).text
    assert "account role could not be checked" in page
    row = _row(page, "ChatGPT")
    assert row.count('class="pill pill-state ') == 1
    assert 'data-approval-row-form' not in row
    assert 'class="approval-select"' not in row
    assert 'Approval history' in row and '<dt>Version' in row


def test_ai_review_device_model_filter_is_not_a_runtime_claim(client, make_token):
    page = _get(client, make_token(),
                "/ai-tooling/devices/dev-mac-001?type=local_model").text
    model = _row(page, "Llama 3 8B")
    assert 'data-filter-ai_type="local_model"' in model
    assert 'row-hide-filter' not in model
    assert 'row-hide-filter' in _row(page, "ChatGPT")
    assert 'Local model (1)' in page


def test_ai_review_empty_filtered_result_is_explicit_without_javascript(client, make_token):
    page = _get(client, make_token(), "/ai-tooling?search=no-such-product").text
    assert 'data-filter-empty>' in page
    assert 'No products match these filters and search.' in page
    assert 'row-hide-search' in _row(page, "ChatGPT")


def test_ai_review_uniform_missing_collectors_remain_unknown(client, make_token):
    page = _get(client, make_token()).text
    row = _row(page, "acme-mbp-storeroom")
    assert 'All four collectors have not yet reported. Coverage is unknown.' in row
    assert row.count('class="pill') == 0
    assert '<details class="card group-card ai-device-coverage" id="devices">' in page
    for label in ("IDE plugins", "CLI packages", "Local models", "MCP servers"):
        assert label in page
