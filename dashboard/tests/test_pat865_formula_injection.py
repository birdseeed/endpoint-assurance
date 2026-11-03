"""
Tests for PAT-865: formula/CSV injection into the staff-driven CVE scan
report (dashboard/scanner.py), the staff-path sibling of PAT-864 (which
fixed the same defect in the portal's unauthenticated scan.patched.im
funnel, scan/scanner.py there).

Root cause: scanner.py's _gen_report wrote CSV-derived fields (device name,
platform string, CVE inventory OS list / description) straight into docx
table cells without the neutralise_formula()/_nf() treatment that
intune_upload.py already applies at every output boundary in this same
repo. A device name like =cmd|'/c calc'!A1 in an uploaded Intune CSV would
land raw in the delivered .docx and could execute as a formula when opened
in Excel/Word.

Drives the real pipeline (run_scan_from_upload -> _gen_report) with a
malicious device name and reads the generated .docx back to confirm the
cell text actually written is neutralised, not just the helper in isolation.
"""
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import scanner
from docx import Document

FORMULA_PREFIXES = ("=", "+", "-", "@")


@pytest.fixture
def empty_nvd_db():
    """Seed an empty (schema-only) nvd.db at scanner.py's hardcoded db path
    so _scan() finds the file and skips its network sync_nvd_local_dataset()
    fallback. No CVE match is needed for this test, only that the pipeline
    runs to completion and _gen_report renders the tables that carry the
    CSV-derived device name. Backs up / restores any real nvd.db that
    happens to exist on the machine running the test (same convention as
    test_pat572_upload_scan.py's nvd_fixture_db)."""
    db_path = os.path.join(os.path.dirname(scanner.__file__), "nvd.db")
    backup_path = db_path + ".pat865-test-backup"
    had_existing = os.path.exists(db_path)
    if had_existing:
        os.rename(db_path, backup_path)

    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE nvd_cves (cve_id TEXT, cpe_prefix TEXT, description TEXT, "
        "base_score REAL, severity TEXT, published TEXT, configurations TEXT, "
        "PRIMARY KEY(cve_id, cpe_prefix))"
    )
    conn.commit()
    conn.close()

    yield db_path

    os.remove(db_path)
    if had_existing:
        os.rename(backup_path, db_path)


@pytest.mark.parametrize("prefix", FORMULA_PREFIXES)
def test_gen_report_neutralises_formula_device_name(tmp_path, empty_nvd_db, prefix):
    """Regression for PAT-865: an uploaded Intune CSV device name starting
    with a formula-injection prefix (=, +, -, @) must never land raw in a
    docx cell of the staff-generated report; it must come out prefixed
    with a leading apostrophe per neutralise_formula()'s convention."""
    malicious_name = f"{prefix}cmd|'/c calc'!A1"
    devices_csv = (
        "Device name,OS,OS version,Compliance,Last check-in\n"
        f"{malicious_name},Windows,10.0.26100.2161,Compliant,2026-07-01T09:00:00Z\n"
    )
    csv_path = tmp_path / "devices.csv"
    csv_path.write_text(devices_csv, encoding="utf-8")
    out_path = tmp_path / "report.docx"

    scanner.run_scan_from_upload(
        devices_csv_path=str(csv_path),
        apps_file_path=None,
        nvd_api_key="",
        company_name="Acme",
        logo_path=None,
        output_path=str(out_path),
    )

    doc = Document(str(out_path))
    all_cell_texts = [c.text for t in doc.tables for row in t.rows for c in row.cells]

    assert malicious_name not in all_cell_texts, (
        "device name reached a docx cell as a live formula, unneutralised"
    )
    neutralised = "'" + malicious_name
    assert neutralised in all_cell_texts, (
        "neutralised device name not found in any table cell: "
        "expected it prefixed with a leading apostrophe"
    )

    # Device Security Posture table (scanner.py _gen_report, root cause cited
    # in PAT-865): device name is column 0 of the first data row.
    posture_table = doc.tables[2]
    assert posture_table.cell(1, 0).text == neutralised

    # Windows Devices summary table, which carries the same field.
    windows_table = doc.tables[3]
    assert windows_table.cell(1, 0).text == neutralised


def test_neutralise_formula_helper_unit():
    """Direct unit coverage of scanner._nf()/neutralise_formula(), matching
    intune_upload.py's helper of the same name (duplicated locally to avoid
    a circular import: see the comment above the helper in scanner.py)."""
    for prefix in FORMULA_PREFIXES:
        assert scanner.neutralise_formula(f"{prefix}bad") == f"'{prefix}bad"
    assert scanner.neutralise_formula("safe value") == "safe value"
    assert scanner._nf(None) == ""
    assert scanner._nf(123) == "123"
    assert scanner._nf("=1+1") == "'=1+1"
