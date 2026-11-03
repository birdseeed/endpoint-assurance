"""Every CSV the portal writes itself neutralises spreadsheet formulas (PAT-2411).

A cell that starts with =, +, -, @, tab, CR or LF (or has one of =+-@ behind
leading whitespace) is prefixed with a single apostrophe in the CSV, header row
included. The PDF twin keeps sending the real values. CSVs the platform writes
and the portal streams verbatim are out of scope.
"""

import ast
import asyncio
import copy
import csv
import io
from pathlib import Path

import pytest

import main
from tests.conftest import (
    AI_TAGGED_PRODUCTS,
    DEVICES,
    FINDINGS,
    HOMEBREW_CASKS,
    HOMEBREW_FORMULAE,
    LOCAL_ADMINS_DATA,
    STUB_STATE,
)

ROOT = Path(__file__).resolve().parent.parent

BAD = ["=1+1", "+1", "-1", "@x", "\t=1", "\r=1", "\n=1", "   =1"]
GOOD = ["mac-01", "a-b", "1.2.3"]
CELLS = BAD + GOOD


def _guarded(cell):
    return "'" + cell if cell in BAD else cell


# ── stubs: put CELLS into one endpoint-controlled text field per export ──────

def _stub_devices(old=False):
    base = DEVICES["devices"][0]
    devices = []
    for i, cell in enumerate(CELLS):
        d = copy.deepcopy(base)
        d["device_id"] = f"dev-guard-{i}"
        d["hostname"] = cell
        if old:
            d["last_seen"] = "2026-07-01T00:00:00Z"
        devices.append(d)
    STUB_STATE["devices_data"] = {"devices": devices}


def _stub_findings():
    base = FINDINGS[0]
    STUB_STATE["findings_data"] = [
        {**base, "cve_id": f"CVE-2026-9{i:03d}", "app": cell} for i, cell in enumerate(CELLS)]


def _stub_homebrew():
    f0 = HOMEBREW_FORMULAE["formulae"][0]
    STUB_STATE["homebrew_formulae_data"] = {
        **HOMEBREW_FORMULAE, "total": len(CELLS),
        "formulae": [{**f0, "name": cell} for cell in CELLS]}
    STUB_STATE["homebrew_casks_data"] = {**HOMEBREW_CASKS, "total": 0, "casks": []}


def _stub_local_admins():
    base = LOCAL_ADMINS_DATA["devices"][0]
    data = copy.deepcopy(LOCAL_ADMINS_DATA)
    data["devices"] = [{**copy.deepcopy(base), "device_id": f"dev-guard-{i}", "hostname": cell}
                       for i, cell in enumerate(CELLS)]
    STUB_STATE["local_admins_data"] = data


def _stub_ai_tooling():
    base = AI_TAGGED_PRODUCTS["products"][0]
    data = copy.deepcopy(AI_TAGGED_PRODUCTS)
    data["total"] = len(CELLS)
    data["products"] = [
        {**copy.deepcopy(base), "product_key": f"product:guard-{i}", "name": cell}
        for i, cell in enumerate(CELLS)]
    STUB_STATE["ai_tagged_products_data"] = data


ROUTES = [
    ("devices", _stub_devices, "/devices.csv", "/devices.pdf"),
    ("devices-stale", lambda: _stub_devices(old=True), "/devices.csv?stale_days=30",
     "/devices.pdf?stale_days=30"),
    ("findings", _stub_findings, "/findings.csv", "/findings.pdf"),
    ("homebrew", _stub_homebrew, "/homebrew.csv", "/homebrew.pdf"),
    ("local-admins", _stub_local_admins, "/local-admins.csv", "/local-admins.pdf"),
    ("ai-tooling", _stub_ai_tooling, "/ai-tooling.csv", "/ai-tooling.pdf"),
]
IDS = [r[0] for r in ROUTES]


def _get(client, path, token):
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["portal_role"] = "admin"
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


@pytest.fixture(autouse=True)
def _configured(client):
    STUB_STATE["jamf_mode"] = "configured"
    yield


def _csv_cells(response):
    rows = list(csv.reader(io.StringIO(response.content.decode("utf-8-sig")), strict=True))
    return {c for r in rows for c in r}


@pytest.mark.parametrize("route", ROUTES, ids=IDS)
def test_csv_neutralises_every_formula_cell_and_leaves_ordinary_ones(client, make_token, route):
    _, stub, csv_path, _pdf = route
    stub()
    resp = _get(client, csv_path, make_token())
    assert resp.status_code == 200
    cells = _csv_cells(resp)
    for cell in BAD:
        assert "'" + cell in cells, repr(cell)
        assert cell not in cells, f"unguarded {cell!r} in CSV"
    for cell in GOOD:
        assert cell in cells, cell
        assert "'" + cell not in cells, cell


@pytest.mark.parametrize("route", ROUTES, ids=IDS)
def test_pdf_twin_posts_the_real_values(client, make_token, route):
    _, stub, _csv, pdf_path = route
    stub()
    resp = _get(client, pdf_path, make_token())
    assert resp.status_code == 200, resp.text[:300]
    cells = {c for r in STUB_STATE["table_pdf_posts"][-1]["body"]["rows"] for c in r}
    for cell in CELLS:
        assert cell in cells, repr(cell)
        assert "'" + cell not in cells, repr(cell)


def test_header_row_is_guarded_too():
    table = main._ExportTable("x", "x.csv", ["=cmd", "ok", "-h"], [["a", "b", "c"]], [])
    async def drain():
        return [c async for c in main._table_csv_response(table).body_iterator]

    text = "".join(c.decode() if isinstance(c, bytes) else c for c in asyncio.run(drain()))
    assert text.splitlines()[0] == "'=cmd,ok,'-h"


@pytest.mark.parametrize("value,expected", [
    ("=1+1", "'=1+1"), ("+1", "'+1"), ("-5", "'-5"), ("@x", "'@x"),
    ("\t=1", "'\t=1"), ("\r=1", "'\r=1"), ("\n=1", "'\n=1"), ("   =1", "'   =1"),
    (" \t-2", "' \t-2"), ("\nplain", "'\nplain"),
    ("mac-01", "mac-01"), ("a-b", "a-b"), ("1.2.3", "1.2.3"), ("", ""), ("  x=1", "  x=1"),
    (None, ""), (7, "7"),
])
def test_guard_rule(value, expected):
    assert main._csv_formula_guard(value) == expected


# ── structural: no portal-written CSV can bypass the guard ───────────────────

# Routes whose CSV the portal assembles itself: each must go through
# `_table_csv_response`, which always applies `_csv_formula_guard`.
PORTAL_WRITTEN = {"devices_csv", "findings_csv", "homebrew_csv", "local_admins_csv",
                  "ai_tooling_csv"}
# Routes that stream or proxy a CSV the platform wrote (already guarded there).
PLATFORM_STREAMED = {
    "devices_jamf_coverage_csv", "reports_new_software_csv", "reports_software_drift_csv",
    "reports_approved_software_csv", "sam_unsupported_software_csv",
    "sam_unsupported_software_devices_csv", "sam_remote_access_csv",
    "sam_remote_access_devices_csv", "sam_version_sprawl_csv", "sam_duplicate_tools_csv",
    "sam_publishers_csv", "sam_publishers_devices_csv", "ai_tooling_device_csv",
    "ce_readiness_csv", "insurance_evidence_csv",
}


def _tree():
    return ast.parse((ROOT / "main.py").read_text())


def _csv_route_functions(tree):
    found = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for dec in node.decorator_list:
            if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                    and dec.func.attr == "get" and dec.args
                    and isinstance(dec.args[0], ast.Constant)
                    and str(dec.args[0].value).endswith(".csv")):
                found[node.name] = node
    return found


def _called_names(fn):
    return {n.func.id for n in ast.walk(fn)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}


def test_every_csv_route_is_classified_and_portal_written_ones_use_the_shared_writer():
    routes = _csv_route_functions(_tree())
    unclassified = set(routes) - PORTAL_WRITTEN - PLATFORM_STREAMED
    assert not unclassified, (
        f"new .csv route(s) {sorted(unclassified)}: if the portal writes the CSV, add it to "
        "PORTAL_WRITTEN and build it with _table_csv_response; if it streams the platform's "
        "own CSV, add it to PLATFORM_STREAMED")
    assert PORTAL_WRITTEN <= set(routes)
    for name in PORTAL_WRITTEN:
        assert "_table_csv_response" in _called_names(routes[name]), name
    for name in PLATFORM_STREAMED & set(routes):
        assert "_table_csv_response" not in _called_names(routes[name]), name


def test_only_the_shared_writer_touches_csv_writer_or_text_csv():
    tree = _tree()
    offenders = []
    for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
        src = ast.get_source_segment((ROOT / "main.py").read_text(), fn) or ""
        if "csv.writer" in src or "csv.DictWriter" in src:
            offenders.append(fn.name)
    assert sorted(set(offenders)) == ["_csv_line"], offenders
    csv_line = next(n for n in ast.walk(tree)
                    if isinstance(n, ast.FunctionDef) and n.name == "_csv_line")
    assert "_csv_formula_guard" in {n.id for n in ast.walk(csv_line) if isinstance(n, ast.Name)}
    # A CSV response built by hand with a "text/csv" media type, outside the
    # shared writer and the platform-stream helpers, would bypass the guard.
    source = (ROOT / "main.py").read_text()
    literal_fns = []
    for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
        seg = ast.get_source_segment(source, fn) or ""
        if '"text/csv' in seg and fn.name not in {"_table_csv_response", "_sam_csv_response"}:
            literal_fns.append(fn.name)
    assert not literal_fns, literal_fns


def test_the_shared_writer_cannot_be_called_unguarded():
    import inspect
    assert list(inspect.signature(main._table_csv_response).parameters) == ["table"]
    assert list(inspect.signature(main._csv_line).parameters) == ["values"]


def test_the_per_export_guards_are_gone():
    assert not hasattr(main, "_ai_tooling_formula_guard")
    assert not hasattr(main, "_local_admins_formula_guard")
