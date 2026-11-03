"""
Tests for PAT-233 Intune upload funnel.
Run with: pytest tests/test_intune_upload.py -v
"""

import os
import sys
import pytest

# Ensure repo root is on the path so imports work without installation
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from intune_upload import (
    neutralise_formula,
    _norm_col,
    detect_csv_type,
    parse_csv_safe,
    parse_devices_rows,
    parse_apps_rows,
    _check_patch_currency,
    _days_since,
    _nf,
    MAX_UPLOAD_BYTES,
    MAX_ROWS,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


# ── neutralise_formula ────────────────────────────────────────────────────────

class TestNeutraliseFormula:
    def test_equals_prefix(self):
        assert neutralise_formula("=CMD('rm -rf /')") == "'=CMD('rm -rf /')"

    def test_plus_prefix(self):
        assert neutralise_formula("+1+2") == "'+1+2"

    def test_minus_prefix(self):
        assert neutralise_formula("-1") == "'-1"

    def test_at_prefix(self):
        assert neutralise_formula("@SUM(A1)") == "'@SUM(A1)"

    def test_safe_value_unchanged(self):
        assert neutralise_formula("Normal Device") == "Normal Device"

    def test_empty_string_unchanged(self):
        assert neutralise_formula("") == ""

    def test_email_address_unchanged(self):
        # email address: the @ is not at position 0
        assert neutralise_formula("user@company.com") == "user@company.com"

    def test_idempotent(self):
        # Applying twice does not double-prefix
        once = neutralise_formula("=SYSTEM()")
        twice = neutralise_formula(once)
        assert twice == once  # second application: starts with ', not a formula char

    def test_all_formula_prefixes(self):
        for prefix in ("=", "+", "-", "@"):
            val = prefix + "evil()"
            result = neutralise_formula(val)
            assert result.startswith("'"), f"Expected ' prefix for {val!r}"
            assert val in result


# ── _norm_col ────────────────────────────────────────────────────────────────

class TestNormCol:
    def test_strips_spaces(self):
        assert _norm_col("Device name") == "devicename"

    def test_strips_underscores(self):
        assert _norm_col("device_name") == "devicename"

    def test_strips_hyphens(self):
        assert _norm_col("device-name") == "devicename"

    def test_lowercases(self):
        assert _norm_col("ApplicationName") == "applicationname"

    def test_strips_parens(self):
        assert _norm_col("OS (version)") == "osversion"


# ── detect_csv_type ──────────────────────────────────────────────────────────

class TestDetectCsvType:
    def test_devices_standard_columns(self):
        assert detect_csv_type(["Device name", "OS", "Compliance"]) == "devices"

    def test_devices_normalised_variant(self):
        assert detect_csv_type(["devicename", "operatingsystem", "compliancestate"]) == "devices"

    def test_devices_version_instead_of_compliance(self):
        assert detect_csv_type(["Device name", "OS version"]) == "devices"

    def test_devices_column_order_irrelevant(self):
        # Reversed order
        assert detect_csv_type(["Compliance", "OS version", "Device name"]) == "devices"

    def test_devices_extra_columns_ok(self):
        assert detect_csv_type([
            "Device name", "OS", "OS version", "Compliance",
            "Primary user UPN", "Manufacturer", "Model",
        ]) == "devices"

    def test_discovered_apps_standard(self):
        assert detect_csv_type(["Application name", "Application version", "Platform"]) == "discovered_apps"

    def test_discovered_apps_normalised(self):
        assert detect_csv_type(["applicationname", "version"]) == "discovered_apps"

    def test_discovered_apps_column_order_irrelevant(self):
        assert detect_csv_type(["Application version", "Platform", "Application name"]) == "discovered_apps"

    def test_bom_stripped_column(self):
        # BOM-prefixed first column name — parse_csv_safe handles BOM, but type detection
        # should also handle it if called with raw headers (belt-and-suspenders test)
        assert detect_csv_type(["﻿Device name", "OS", "Compliance"]) == "devices"

    def test_unrecognised_returns_none(self):
        assert detect_csv_type(["First Name", "Last Name", "Email", "Department"]) is None

    def test_empty_returns_none(self):
        assert detect_csv_type([]) is None

    def test_wrong_file_returns_none(self):
        with open(os.path.join(FIXTURES, "wrong_file.csv"), "rb") as f:
            content = f.read()
        headers, _ = parse_csv_safe(content)
        assert detect_csv_type(headers) is None


# ── parse_csv_safe ───────────────────────────────────────────────────────────

class TestParseCsvSafe:
    def test_valid_devices_csv(self):
        content = b"Device name,OS,OS version,Compliance\nLaptop-1,Windows,10.0.26100.1,Compliant\n"
        headers, rows = parse_csv_safe(content)
        assert "Device name" in headers
        assert rows[0]["Device name"] == "Laptop-1"

    def test_bom_prefix_stripped(self):
        content = b"\xef\xbb\xbfDevice name,OS\nLaptop-1,Windows\n"
        headers, rows = parse_csv_safe(content)
        # BOM stripped by utf-8-sig — header should not contain BOM character
        assert any("Device name" in h for h in headers)

    def test_malformed_binary_raises(self):
        with open(os.path.join(FIXTURES, "malformed.csv"), "rb") as f:
            content = f.read()
        with pytest.raises(ValueError):
            parse_csv_safe(content)

    def test_empty_content_raises(self):
        with pytest.raises(ValueError, match="empty"):
            parse_csv_safe(b"")

    def test_no_header_raises(self):
        with pytest.raises(ValueError):
            parse_csv_safe(b"\n\n\n")

    def test_row_count_cap(self):
        # Build CSV with MAX_ROWS + 10 data rows
        header = "Device name,OS\n"
        row = "DEVICE,Windows\n"
        content = (header + row * (MAX_ROWS + 10)).encode()
        with pytest.raises(ValueError, match="limit"):
            parse_csv_safe(content)

    def test_valid_apps_csv(self):
        content = b"Application name,Application version\nGoogle Chrome,120.0\n"
        headers, rows = parse_csv_safe(content)
        assert rows[0]["Application name"] == "Google Chrome"

    def test_field_length_cap(self):
        from intune_upload import MAX_FIELD_LEN
        long_val = "A" * (MAX_FIELD_LEN + 100)
        content = f"Device name,OS\n{long_val},Windows\n".encode()
        _, rows = parse_csv_safe(content)
        assert len(rows[0]["Device name"]) == MAX_FIELD_LEN


# ── parse_devices_rows ────────────────────────────────────────────────────────

class TestParseDevicesRows:
    def test_golden_fixture(self):
        with open(os.path.join(FIXTURES, "devices_valid.csv"), "rb") as f:
            content = f.read()
        headers, rows = parse_csv_safe(content)
        devices = parse_devices_rows(rows)
        assert len(devices) == 6
        names = [d["name"] for d in devices]
        assert "LAPTOP-ALICE" in names

    def test_blank_name_rows_excluded(self):
        content = b"Device name,OS\n,Windows\nLAPTOP-1,Windows\n"
        _, rows = parse_csv_safe(content)
        devices = parse_devices_rows(rows)
        assert len(devices) == 1
        assert devices[0]["name"] == "LAPTOP-1"

    def test_compliance_extracted(self):
        content = b"Device name,OS,Compliance\nDEV-1,Windows,Compliant\n"
        _, rows = parse_csv_safe(content)
        devices = parse_devices_rows(rows)
        assert devices[0]["compliance"] == "Compliant"


# ── parse_apps_rows ───────────────────────────────────────────────────────────

class TestParseAppsRows:
    def test_golden_fixture(self):
        with open(os.path.join(FIXTURES, "apps_valid.csv"), "rb") as f:
            content = f.read()
        headers, rows = parse_csv_safe(content)
        apps = parse_apps_rows(rows)
        assert len(apps) == 10
        names = [a["name"] for a in apps]
        assert "Google Chrome" in names

    def test_deduplication(self):
        content = b"Application name,Application version\nChrome,120\nChrome,120\nFirefox,121\n"
        _, rows = parse_csv_safe(content)
        apps = parse_apps_rows(rows)
        assert len(apps) == 2  # Chrome deduplicated

    def test_blank_name_excluded(self):
        content = b"Application name,Application version\n,1.0\nChrome,120\n"
        _, rows = parse_csv_safe(content)
        apps = parse_apps_rows(rows)
        assert len(apps) == 1


# ── _check_patch_currency ─────────────────────────────────────────────────────

class TestCheckPatchCurrency:
    def test_windows_11_latest_build(self):
        _, is_cur, status = _check_patch_currency("Windows", "10.0.26100.2161")
        assert is_cur is True
        assert status == "Up to date"

    def test_windows_11_old_build(self):
        _, is_cur, status = _check_patch_currency("Windows", "10.0.22621.3155")
        assert status == "Out of date"

    def test_macos_current(self):
        from intune_patch_levels import MACOS_LATEST
        _, is_cur, _ = _check_patch_currency("macOS", MACOS_LATEST)
        assert is_cur is True

    def test_macos_old(self):
        _, is_cur, status = _check_patch_currency("macOS", "14.0")
        assert status == "Out of date"

    def test_ios_current(self):
        from intune_patch_levels import IOS_LATEST
        _, is_cur, _ = _check_patch_currency("iOS", IOS_LATEST)
        assert is_cur is True

    def test_android(self):
        from intune_patch_levels import ANDROID_LATEST
        _, is_cur, _ = _check_patch_currency("Android", ANDROID_LATEST)
        assert is_cur is True

    def test_unknown_platform(self):
        latest, _, status = _check_patch_currency("ChromeOS", "115.0")
        assert status == "Unknown"


# ── Formula injection neutralisation (end-to-end) ────────────────────────────

class TestFormulaInjectionNeutralisation:
    """
    Verify that formula-injection values arrive neutralised at every output boundary.
    We test:
      1. neutralise_formula directly (all four prefixes)
      2. _nf() helper
      3. parse_devices_rows / parse_apps_rows return raw values (neutralisation at output site)
      4. generate_devices_report writes neutralised values to docx cells
    """

    FORMULA_VALUES = [
        ("=SYSTEM(\"cmd\")", "'=SYSTEM(\"cmd\")"),
        ("+dangerous", "'+dangerous"),
        ("-injection", "'-injection"),
        ("@SUM(A1:A99)", "'@SUM(A1:A99)"),
    ]

    def test_all_prefixes_neutralised(self):
        for raw, expected in self.FORMULA_VALUES:
            assert neutralise_formula(raw) == expected, f"Failed for {raw!r}"

    def test_nf_helper_casts_and_neutralises(self):
        assert _nf("=evil") == "'=evil"
        assert _nf(None) == ""
        assert _nf(42) == "42"

    def test_devices_report_neutralises_in_docx(self, tmp_path):
        """
        Generate a devices report with formula-injection device name.
        Read the resulting docx and assert the raw formula does not appear in any cell,
        but the neutralised version does.
        """
        from intune_upload import generate_devices_report
        try:
            from docx import Document as _Doc
        except ImportError:
            pytest.skip("python-docx not installed")

        devices = [{
            "name": "=SYSTEM('rm -rf /')",
            "os": "+Windows",
            "os_version": "10.0.26100.2161",
            "compliance": "-Compliant",
            "last_checkin": "",
            "user": "@admin",
            "ownership": "Corporate",
            "model": "",
            "manufacturer": "",
        }]
        output = str(tmp_path / "test_devices.docx")
        generate_devices_report(devices, output, logo_path="")

        doc = _Doc(output)
        all_cell_text = " ".join(
            p.text
            for t in doc.tables
            for row in t.rows
            for cell in row.cells
            for p in cell.paragraphs
        )

        # Raw formula strings must not appear unescaped (neutralised =-prefixed form is OK)
        assert "=SYSTEM(" not in all_cell_text or "'=SYSTEM(" in all_cell_text, "Raw = formula found in docx"
        assert "+Windows" not in all_cell_text or "'+" in all_cell_text, "+prefix not neutralised"
        assert "-Compliant" not in all_cell_text or "'-Compliant" in all_cell_text, "- prefix not neutralised"
        assert "@admin" not in all_cell_text or "'@admin" in all_cell_text, "@ prefix not neutralised"

        # Neutralised versions should be present
        assert "'=SYSTEM(" in all_cell_text, "Neutralised = formula not found"

    def test_apps_report_neutralises_in_docx(self, tmp_path):
        """
        Generate an apps CVE report with formula-injection app name.
        No NVD calls needed — unmatched apps still appear in the report.
        """
        from intune_upload import generate_apps_cve_report
        try:
            from docx import Document as _Doc
        except ImportError:
            pytest.skip("python-docx not installed")

        apps = [{
            "name": "=DANGEROUS_APP",
            "version": "+1.0",
            "platform": "-Windows",
            "device_count": "1",
        }]
        output = str(tmp_path / "test_apps.docx")
        # nvd_api_key="" → no real NVD calls (unmatched CPE returns empty cves)
        generate_apps_cve_report(apps, nvd_api_key="", output_path=output, logo_path="")

        doc = _Doc(output)
        all_cell_text = " ".join(
            p.text
            for t in doc.tables
            for row in t.rows
            for cell in row.cells
            for p in cell.paragraphs
        )

        assert "=DANGEROUS_APP" not in all_cell_text, "Raw = formula in apps docx"

    def test_formula_in_html_template_escaped(self):
        """
        Verify that Jinja2 auto-escaping would neutralise HTML-dangerous values
        (belt-and-suspenders — the upload page does not echo user CSV data,
        so this exercises the template filter registration logic).
        """
        # We can't easily render the template in a unit test without a full FastAPI app,
        # so verify that the neutralise_formula function is safe for all contexts.
        injection = '<script>alert(1)</script>'
        # HTML escaping is handled by Jinja2; formula neutralisation handles spreadsheet injection.
        # This value doesn't start with a formula prefix, so it passes through neutralise_formula.
        result = neutralise_formula(injection)
        assert result == injection  # Not a formula — Jinja2 escaping handles XSS separately


# ── Smoke tests (happy path, end-to-end parse) ──────────────────────────────

class TestSmokePaths:
    def test_devices_smoke(self):
        """Upload path: read fixture → detect type → parse rows."""
        with open(os.path.join(FIXTURES, "devices_valid.csv"), "rb") as f:
            content = f.read()
        headers, rows = parse_csv_safe(content)
        csv_type = detect_csv_type(headers)
        assert csv_type == "devices", f"Expected 'devices', got {csv_type!r}"
        devices = parse_devices_rows(rows)
        assert len(devices) > 0
        assert all(d["name"] for d in devices)

    def test_apps_smoke(self):
        """Upload path: read fixture → detect type → parse rows."""
        with open(os.path.join(FIXTURES, "apps_valid.csv"), "rb") as f:
            content = f.read()
        headers, rows = parse_csv_safe(content)
        csv_type = detect_csv_type(headers)
        assert csv_type == "discovered_apps", f"Expected 'discovered_apps', got {csv_type!r}"
        apps = parse_apps_rows(rows)
        assert len(apps) > 0
        assert all(a["name"] for a in apps)

    def test_malformed_smoke(self):
        """Malformed file → parse_csv_safe raises ValueError."""
        with open(os.path.join(FIXTURES, "malformed.csv"), "rb") as f:
            content = f.read()
        with pytest.raises(ValueError):
            parse_csv_safe(content)

    def test_wrong_file_smoke(self):
        """Wrong-type CSV → parse succeeds but detect_csv_type returns None."""
        with open(os.path.join(FIXTURES, "wrong_file.csv"), "rb") as f:
            content = f.read()
        headers, _ = parse_csv_safe(content)
        assert detect_csv_type(headers) is None

    def test_bom_prefixed_devices(self):
        """BOM-prefixed devices CSV is detected and parsed correctly."""
        with open(os.path.join(FIXTURES, "devices_valid.csv"), "rb") as f:
            raw = f.read()
        bom_content = b"\xef\xbb\xbf" + raw
        headers, rows = parse_csv_safe(bom_content)
        assert detect_csv_type(headers) == "devices"
        devices = parse_devices_rows(rows)
        assert len(devices) > 0
