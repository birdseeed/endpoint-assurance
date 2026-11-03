"""Regression coverage for PAT-1157's standalone Hardware inventory page."""

import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text()
CSS = (ROOT / "static" / "css" / "console.css").read_text()


def _function(name: str) -> str:
    start = HTML.index(f"function {name}(")
    brace = HTML.index("{", start)
    depth = 0
    for index in range(brace, len(HTML)):
        if HTML[index] == "{":
            depth += 1
        elif HTML[index] == "}":
            depth -= 1
            if depth == 0:
                return HTML[start:index + 1]
    raise AssertionError(f"unbalanced function {name}")


def _node_json(functions: list[str], expression: str):
    source = "\n".join(_function(name) for name in functions)
    script = f"{source}\nconsole.log(JSON.stringify({expression}));"
    result = subprocess.run(
        ["node", "-e", script], check=True, capture_output=True, text=True
    )
    return json.loads(result.stdout)


def _hardware_panel() -> str:
    start = HTML.index('id="ddtab-inventory"')
    end = HTML.index('<!-- /#ddtab-inventory -->', start)
    return HTML[start:end]


def test_hardware_is_separate_and_precedes_compatible_security_destination():
    nav_start = HTML.index('<nav class="ddw-nav" id="dd-subtab-nav"')
    nav_end = HTML.index("</nav>", nav_start)
    nav = HTML[nav_start:nav_end]
    assert nav.index('data-ddtab="overview"') < nav.index('data-ddtab="inventory"')
    assert nav.index('data-ddtab="inventory"') < nav.index('data-ddtab="hardware"')
    assert "_ddTab('inventory')" in nav
    assert ">Hardware</button>" in nav
    assert 'data-ddtab="hardware" role="tab" aria-label="Security"' in nav
    assert ">Security<span" in nav
    assert "var _DD_TABS = ['overview', 'inventory', 'hardware', 'software', 'patching', 'compliance', 'activity'];" in HTML
    assert "inventory: true" in _function("_ddSyncTabs")


def test_hardware_page_keeps_every_approved_section_visible_without_disclosures():
    panel = _hardware_panel()
    for heading in (
        "Hardware inventory", "Identification", "Compute", "Storage volumes",
        "Physical disks", "Battery", "Hardware attention",
    ):
        assert heading in panel
    for target in (
        "dd-hardware-identification", "dd-hardware-compute",
        "dd-hardware-storage-summary", "dd-hardware-volumes-tbody",
        "dd-hardware-disks-tbody", "dd-hardware-battery",
        "dd-hardware-attention-content", "dd-hardware-age",
    ):
        assert f'id="{target}"' in panel
    assert "<details" not in panel
    assert "accordion" not in panel.lower()


def test_view_model_exposes_all_api_hardware_fields_and_secondary_warnings():
    dev = {
        "hw_model": "MacBookPro18,3",
        "serial": "C02TEST",
        "hw_uuid": "ABC-123",
        "arch": "arm64",
        "last_seen": "2026-08-04T10:00:00Z",
    }
    hardware = {
        "cpu_model": "Apple M1 Pro",
        "cpu_cores": 10,
        "ram_gb": 16,
        "disk_total_gb": 494.4,
        "disk_free_gb": 8.5,
    }
    health = {
        "battery": {"present": True, "condition": "Normal", "max_capacity_pct": 62, "cycle_count": 412},
        "volumes": [{"mount": "/", "total_bytes": 500_000_000_000, "free_bytes": 8_000_000_000, "used_pct": 98}],
        "disks": [{"device_node": "disk0", "smart_status": "Failing", "internal": True, "solid_state": True}],
    }
    result = _node_json(
        ["_ddReported", "_ddGb", "_ddHardwareBytes", "_ddHardwareNumber", "_ddHardwareSmartState", "_ddHardwareInventoryModel"],
        f"_ddHardwareInventoryModel({json.dumps(dev)}, {json.dumps(hardware)}, {json.dumps(health)})",
    )
    assert [item["value"] for item in result["identification"]] == [
        "MacBookPro18,3", "C02TEST", "ABC-123", "arm64",
    ]
    assert [item["value"] for item in result["compute"]] == ["Apple M1 Pro", "10", "16 GB"]
    assert result["storage_summary"] == [
        {"label": "Reported capacity", "value": "494.4 GB"},
        {"label": "Reported free space", "value": "8.5 GB"},
    ]
    assert result["volumes"][0]["mount"] == "/"
    assert result["volumes"][0]["used"] == "98%"
    assert result["disks"][0] == {
        "device": "disk0", "location": "Internal", "media": "Solid state",
        "smart": "Failing", "smart_state": "risk",
    }
    assert [item["value"] for item in result["battery"]] == ["Yes", "Normal", "62%", "412"]
    assert result["warnings"] == [
        "Battery maximum capacity is 62%",
        "Primary storage has 8.5 GB free",
        "SMART status for disk0 is Failing",
    ]
    assert result["evidence_at"] == "2026-08-04T10:00:00Z"


def test_battery_absence_and_missing_health_are_truthful_not_failures():
    absent = _node_json(
        ["_ddReported", "_ddGb", "_ddHardwareBytes", "_ddHardwareNumber", "_ddHardwareSmartState", "_ddHardwareInventoryModel"],
        "_ddHardwareInventoryModel({}, {}, {battery:{present:false},volumes:[],disks:[]})",
    )
    assert [item["value"] for item in absent["battery"]] == [
        "No", "Not applicable", "Not applicable", "Not applicable",
    ]
    assert absent["warnings"] == []
    assert absent["health_reported"] is True

    missing = _node_json(
        ["_ddReported", "_ddGb", "_ddHardwareBytes", "_ddHardwareNumber", "_ddHardwareSmartState", "_ddHardwareInventoryModel"],
        "_ddHardwareInventoryModel({}, {}, null)",
    )
    assert all(item["value"] == "Not reported" for item in missing["identification"])
    assert all(item["value"] == "Not reported" for item in missing["compute"])
    assert all(item["value"] == "Not reported" for item in missing["battery"])
    assert missing["volumes"] == [] and missing["disks"] == []
    assert missing["health_reported"] is False


def test_unknown_smart_malformed_numbers_and_empty_health_never_claim_a_fault_or_all_clear():
    result = _node_json(
        ["_ddReported", "_ddGb", "_ddHardwareBytes", "_ddHardwareNumber", "_ddHardwareSmartState", "_ddHardwareInventoryModel"],
        "_ddHardwareInventoryModel({}, {}, {"
        "battery:{present:true,max_capacity_pct:'unknown'},"
        "volumes:[{mount:'/',used_pct:'unknown'}],"
        "disks:[{device_node:'disk0',smart_status:'Unknown',internal:true,solid_state:true}]"
        "})",
    )
    assert result["battery"][2]["value"] == "Not reported"
    assert result["volumes"][0]["used"] == "Not reported"
    assert result["disks"][0]["smart_state"] == "unknown"
    assert result["warnings"] == []
    assert result["health_reported"] is True

    empty = _node_json(
        ["_ddReported", "_ddGb", "_ddHardwareBytes", "_ddHardwareNumber", "_ddHardwareSmartState", "_ddHardwareInventoryModel"],
        "_ddHardwareInventoryModel({}, {}, {})",
    )
    assert empty["health_reported"] is False

    invalid_free = _node_json(
        ["_ddReported", "_ddGb", "_ddHardwareBytes", "_ddHardwareNumber", "_ddHardwareSmartState", "_ddHardwareInventoryModel"],
        "['',-1,true].map(value => _ddHardwareInventoryModel({}, {}, {volumes:[{mount:'/',free_bytes:value}]}))",
    )
    assert all(item["volumes"][0]["free"] == "Not reported" for item in invalid_free)
    assert all(item["warnings"] == [] for item in invalid_free)

    zero_free = _node_json(
        ["_ddReported", "_ddGb", "_ddHardwareBytes", "_ddHardwareNumber", "_ddHardwareSmartState", "_ddHardwareInventoryModel"],
        "_ddHardwareInventoryModel({}, {}, {volumes:[{mount:'/',free_bytes:0}]})",
    )
    assert zero_free["volumes"][0]["free"] == "0 B"
    assert zero_free["warnings"] == ["Primary storage has 0 B free"]

    system_mounts = _node_json(
        ["_ddReported", "_ddGb", "_ddHardwareBytes", "_ddHardwareNumber", "_ddHardwareSmartState", "_ddHardwareInventoryModel"],
        "_ddHardwareInventoryModel({}, {}, {volumes:["
        "{mount:'/',free_bytes:28624764928},"
        "{mount:'/System/Library/AssetsV2/example',free_bytes:3149824},"
        "{mount:'/System/Volumes/Hardware',free_bytes:519122944}"
        "]})",
    )
    assert len(system_mounts["volumes"]) == 3
    assert system_mounts["warnings"] == []


def test_renderer_reconciles_lists_and_preserves_explicit_empty_rows():
    renderer = _function("_ddRenderHardwareInventory")
    assert "model.volumes.map" in renderer
    assert "model.disks.map" in renderer
    assert "No storage volumes reported" in renderer
    assert "No physical disks reported" in renderer
    assert "Hardware health has not been reported." in renderer
    assert "No hardware warnings were reported in the latest inventory." in renderer
    assert "Last inventory check-in " in renderer
    load = _function("_loadDeviceDetail")
    assert "_ddRenderHardwareInventory(dev, hw0, data.hardware_health || null);" in load


def test_hardware_inventory_is_compact_and_responsive():
    for selector in (
        ".dd-hardware-heading", ".dd-hardware-primary", ".dd-hardware-facts",
        ".dd-hardware-table-wrap", ".dd-hardware-attention",
    ):
        assert selector in CSS
    assert "overflow-x: auto" in CSS
    assert "@media (max-width: 732px)" in CSS
    assert "@media (max-width: 430px)" in CSS
    assert ".dd-hardware-primary { grid-template-columns: 1fr; }" in CSS
    assert ".dd-hardware-facts { grid-template-columns: 1fr; }" in CSS


def test_existing_device_surfaces_and_security_contract_are_preserved():
    for tab in ("overview", "inventory", "hardware", "software", "patching", "compliance", "activity"):
        assert f'id="ddtab-{tab}"' in HTML
    security_start = HTML.index('id="ddtab-hardware"')
    security_end = HTML.index('<!-- /#ddtab-hardware -->', security_start)
    security = HTML[security_start:security_end]
    assert 'aria-label="Security"' in security
    assert "Security overview" in security
    assert "Security signals" in security
    assert "function _ddRenderMachineInformation(" in HTML
    assert "function _ddSetDeviceVerdict(" in HTML
    assert 'id="dd-delete-btn"' in HTML and 'id="dd-revoke-btn"' in HTML
