"""
Intune CSV upload processing — public funnel (PAT-233).
Handles type detection, parsing, and report generation for:
  - Intune Devices export → patch-currency + estate report
  - Intune Discovered Apps export → app CVE report (reuses scanner.py engine)
"""

import csv
import io
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from docx import Document
from docx.shared import Pt, Cm, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT

# Reuse scanner visual helpers and CVE engine (do not fork)
from scanner import (
    _shd, _sc, _hr, _ap, _rule, _apply_table_borders,
    NAVY, ACCENT, WHITE, GREY, DARK, LBG,
    _pscore, _plabel, _phex, _app_cpe, _scan,
)
from intune_patch_levels import (
    WINDOWS_BUILDS, WINDOWS_LATEST_BUILD, MACOS_LATEST, IOS_LATEST, ANDROID_LATEST,
)

# ── Limits ───────────────────────────────────────────────────────────────────
MAX_UPLOAD_BYTES = 10 * 1024 * 1024   # 10 MB
MAX_ROWS = 10_000
MAX_FIELD_LEN = 500
RATE_LIMIT_EMAIL = 3    # max uploads per email per 24 h
RATE_LIMIT_IP = 10      # max uploads per IP per 24 h

_FORMULA_PREFIXES = ('=', '+', '-', '@')


# ── Formula injection neutralisation ────────────────────────────────────────
# Shared helper — call at every output boundary (docx cell, email body, HTML).
def neutralise_formula(value: str) -> str:
    """Prefix formula-injection strings with ' to neutralise spreadsheet execution."""
    if value and value[0] in _FORMULA_PREFIXES:
        return "'" + value
    return value


def _nf(value) -> str:
    """neutralise_formula with safe str cast."""
    return neutralise_formula(str(value)) if value is not None else ""


# ── Column normalisation ─────────────────────────────────────────────────────
def _norm_col(name: str) -> str:
    """Lowercase, strip spaces/underscores/hyphens/parens — for fuzzy column matching."""
    return re.sub(r'[\s_\-()/]', '', name.lstrip('﻿').lower().strip())


# Devices CSV: required column subsets (normalised)
_DEVICES_NAME_COLS = {"devicename", "device", "computername", "hostname", "name"}
_DEVICES_OS_COLS   = {"os", "operatingsystem", "platform", "deviceos"}
_DEVICES_COMP_COLS = {"compliance", "compliancestate", "compliancestatus"}
_DEVICES_VER_COLS  = {"osversion", "version", "operatingsystemversion", "osver"}

# Discovered Apps CSV: required column subsets (normalised)
_APPS_NAME_COLS = {"applicationname", "appname", "application", "name", "softwarename"}
_APPS_VER_COLS  = {"applicationversion", "version", "appversion", "ver", "softwareversion"}


def detect_csv_type(header: list) -> "str | None":
    """
    Return 'devices', 'discovered_apps', or None.
    Tolerant of column-order changes and extra columns.
    """
    normed = {_norm_col(h) for h in header}
    has_device = bool(normed & _DEVICES_NAME_COLS)
    has_os     = bool(normed & _DEVICES_OS_COLS)
    has_comp   = bool(normed & _DEVICES_COMP_COLS)
    has_ver    = bool(normed & _DEVICES_VER_COLS)
    # Devices: device name + at least one of OS/compliance/version
    if has_device and (has_os or has_comp or has_ver):
        return "devices"
    has_app_name = bool(normed & _APPS_NAME_COLS)
    has_app_ver  = bool(normed & _APPS_VER_COLS)
    # Discovered apps: application name + version
    if has_app_name and has_app_ver:
        return "discovered_apps"
    return None


def _get_val(row: dict, candidates: set, default: str = "") -> str:
    """Find a value in a CSV row by normalised column name."""
    for k, v in row.items():
        if _norm_col(k) in candidates:
            return str(v or "").strip()[:MAX_FIELD_LEN]
    return default


# ── CSV parsing ──────────────────────────────────────────────────────────────
def parse_csv_safe(content: bytes) -> tuple:
    """
    Decode and parse CSV bytes safely.
    Returns (headers: list[str], rows: list[dict]).
    Raises ValueError with a user-friendly message on any failure.
    Handles UTF-8 BOM and common encoding quirks.
    """
    if not content:
        raise ValueError("Uploaded file is empty.")

    # Reject binary data — null bytes indicate non-text content
    if b'\x00' in content[:4096]:
        raise ValueError("File appears to contain binary data. Please upload a CSV file.")

    # Decode: utf-8-sig handles BOM, utf-8 for standard exports
    text = None
    for enc in ("utf-8-sig", "utf-8"):
        try:
            text = content.decode(enc)
            break
        except (UnicodeDecodeError, ValueError):
            continue
    if text is None:
        raise ValueError(
            "File could not be decoded as UTF-8. Please export your CSV from Intune using UTF-8 encoding."
        )

    reader = csv.DictReader(io.StringIO(text))
    try:
        headers = list(reader.fieldnames or [])
    except Exception:
        raise ValueError("Could not read the CSV header row.")

    if not headers or all(h.strip() == "" for h in headers):
        raise ValueError("CSV file has no header row.")

    rows = []
    try:
        for i, row in enumerate(reader):
            if i >= MAX_ROWS:
                raise ValueError(f"File exceeds the {MAX_ROWS:,}-row limit. Please trim your export.")
            rows.append({k: (v or "")[:MAX_FIELD_LEN] for k, v in row.items() if k is not None})
    except csv.Error as e:
        raise ValueError(f"CSV parsing error: {e}")

    return headers, rows


# ── Date parsing ─────────────────────────────────────────────────────────────
def _parse_dt(raw: str) -> "datetime | None":
    if not raw:
        return None
    raw = raw.strip()
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y",
        "%m/%d/%Y",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _days_since(raw: str) -> "int | None":
    dt = _parse_dt(raw)
    if dt is None:
        return None
    return max(0, (datetime.now(timezone.utc) - dt).days)


# ── Patch currency ────────────────────────────────────────────────────────────
def _check_patch_currency(os_name: str, version: str) -> tuple:
    """
    Returns (latest_label: str, is_current: bool, status: str).
    status is 'Up to date', 'Out of date', or 'Unknown'.
    """
    os_l = (os_name or "").lower().strip()
    v = re.sub(r'\s*\(.*?\)', '', version or "").strip()

    if "windows" in os_l:
        parts = v.split(".")
        build = parts[2] if len(parts) >= 3 else ""
        try:
            is_w11 = int(build) >= 22000
        except (ValueError, TypeError):
            is_w11 = False
        product = "windows_11" if is_w11 else "windows_10"
        latest_build = WINDOWS_LATEST_BUILD.get(product, "")
        info = WINDOWS_BUILDS.get(latest_build, ("", ""))
        label = (
            f"{info[0].replace('_', ' ').title()} {info[1]} (Build {latest_build})"
            if latest_build else "Unknown"
        )
        if build and latest_build:
            try:
                is_current = int(build) >= int(latest_build)
                return label, is_current, "Up to date" if is_current else "Out of date"
            except (ValueError, TypeError):
                pass
        return label, False, "Unknown"

    if "macos" in os_l:
        def _ver_tup(s):
            try:
                return tuple(int(x) for x in s.split(".")[:2])
            except (ValueError, AttributeError):
                return (0, 0)
        curr = _ver_tup(v)
        latest = _ver_tup(MACOS_LATEST)
        if curr == (0, 0):
            return MACOS_LATEST, False, "Unknown"
        is_cur = curr >= latest
        return MACOS_LATEST, is_cur, "Up to date" if is_cur else "Out of date"

    if "ios" in os_l or "ipad" in os_l:
        def _ver_tup(s):
            try:
                return tuple(int(x) for x in s.split(".")[:2])
            except (ValueError, AttributeError):
                return (0, 0)
        curr = _ver_tup(v)
        latest = _ver_tup(IOS_LATEST)
        if curr == (0, 0):
            return IOS_LATEST, False, "Unknown"
        is_cur = curr >= latest
        return IOS_LATEST, is_cur, "Up to date" if is_cur else "Out of date"

    if "android" in os_l:
        try:
            is_cur = int(v.split(".")[0]) >= int(ANDROID_LATEST.split(".")[0])
            return ANDROID_LATEST, is_cur, "Up to date" if is_cur else "Out of date"
        except (ValueError, IndexError, AttributeError):
            return ANDROID_LATEST, False, "Unknown"

    return "", True, "Unknown"


# ── Row parsers ───────────────────────────────────────────────────────────────
_CHECKIN_COLS = {
    "lastcheckin", "lastsync", "lastsyncdatetime", "checkindate",
    "lastseen", "lastcontact", "lastcheckindate",
}
_USER_COLS = {"primaryuserupn", "user", "userprincipalname", "upn", "primaryuser", "email"}
_OWN_COLS  = {"ownership", "deviceownership", "ownedby", "managementtype"}


def parse_devices_rows(rows: list) -> list:
    """Parse raw CSV rows into normalised device dicts (no side-effects on input)."""
    devices = []
    for row in rows:
        name = _get_val(row, _DEVICES_NAME_COLS)
        if not name:
            continue
        devices.append({
            "name": name,
            "os": _get_val(row, _DEVICES_OS_COLS),
            "os_version": _get_val(row, _DEVICES_VER_COLS),
            "compliance": _get_val(row, _DEVICES_COMP_COLS),
            "last_checkin": _get_val(row, _CHECKIN_COLS),
            "user": _get_val(row, _USER_COLS),
            "ownership": _get_val(row, _OWN_COLS),
            "model": _get_val(row, {"model", "devicemodel"}),
            "manufacturer": _get_val(row, {"manufacturer"}),
        })
    return devices


def parse_apps_rows(rows: list) -> list:
    """Parse raw CSV rows into normalised, deduplicated app dicts."""
    seen = set()
    apps = []
    for row in rows:
        name = _get_val(row, _APPS_NAME_COLS)
        if not name:
            continue
        version = _get_val(row, _APPS_VER_COLS)
        key = (name.lower(), version.lower())
        if key in seen:
            continue
        seen.add(key)
        apps.append({
            "name": name,
            "version": version,
            "platform": _get_val(row, {"platform", "deviceplatform", "os", "operatingsystem"}),
            "device_count": _get_val(row, {
                "numberofdeviceswithapp", "devicecount", "devices", "installcount",
                "numberofinstalls",
            }),
        })
    return apps


# ── Devices report ────────────────────────────────────────────────────────────
def generate_devices_report(devices: list, output_path: str, logo_path: str) -> dict:
    """
    Generate a .docx patch-currency + estate report from parsed device rows.
    All user-supplied cell values are passed through neutralise_formula().
    Returns stats dict for use in the delivery email.
    """
    doc = Document()
    now = datetime.now(timezone.utc)
    for s in doc.sections:
        s.top_margin = s.bottom_margin = s.left_margin = s.right_margin = Cm(2.54)
    doc.styles["Normal"].font.name = "Arial"
    doc.styles["Normal"].font.size = Pt(11)

    # Title page
    for _ in range(2):
        doc.add_paragraph()
    if logo_path and os.path.exists(logo_path):
        lp = doc.add_paragraph()
        lp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        lp.add_run().add_picture(logo_path, width=Inches(3.5))
        lp.paragraph_format.space_after = Pt(20)
    _ap(doc, "Endpoint Security  |  Compliance  |  Patch Management", 11,
        c=GREY, al=WD_ALIGN_PARAGRAPH.CENTER, sa=30)
    _rule(doc)
    _ap(doc, "Intune Device Estate Report", 28, True, ACCENT, WD_ALIGN_PARAGRAPH.CENTER, 30)
    _ap(doc, f"Report Date: {now.strftime('%d %B %Y')}", 12,
        c=DARK, al=WD_ALIGN_PARAGRAPH.CENTER, sa=4)
    _ap(doc, "Classification: Confidential", 11, c=GREY, al=WD_ALIGN_PARAGRAPH.CENTER, sa=4)
    _ap(doc, "Prepared by Patched.im Ltd  |  patched.im", 11, c=GREY, al=WD_ALIGN_PARAGRAPH.CENTER)
    doc.add_page_break()

    _ap(doc, "Note: OS patch currency is assessed against a static reference updated at report-generation time "
        "and may not reflect the very latest releases.", 9, c=GREY, sa=12)

    # Aggregate stats
    total = len(devices)
    by_os = defaultdict(int)
    by_ownership = defaultdict(int)
    by_compliance = defaultdict(int)
    stale_count = 0
    out_of_date_count = 0

    for d in devices:
        by_os[(d.get("os") or "Unknown").strip() or "Unknown"] += 1
        by_ownership[(d.get("ownership") or "Unknown").strip() or "Unknown"] += 1
        comp = (d.get("compliance") or "Unknown").strip() or "Unknown"
        by_compliance[comp] += 1
        days = _days_since(d.get("last_checkin", ""))
        if days is not None and days > 14:
            stale_count += 1
        _, _, status = _check_patch_currency(d.get("os", ""), d.get("os_version", ""))
        if status == "Out of date":
            out_of_date_count += 1

    compliant = sum(v for k, v in by_compliance.items() if k.lower() == "compliant")
    non_compliant = total - compliant

    # Estate summary
    _ap(doc, "Estate Summary", 22, True, NAVY, sa=12)
    _ap(doc, f"This report covers {total} Intune-managed device(s) from your exported inventory.", sa=12)
    t = doc.add_table(2, 4)
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    _apply_table_borders(t)
    for i, h in enumerate(["Total Devices", "Compliant", "Non-Compliant", "Stale (>14 d)"]):
        t.cell(0, i).text = h
        _shd(t.cell(0, i), "1B2A4A")
        _sc(t.cell(0, i), 9, True, WHITE)
    for i, v in enumerate([str(total), str(compliant), str(non_compliant), str(stale_count)]):
        c = t.cell(1, i)
        c.text = v
        _shd(c, LBG)
        _sc(c, 14, True, NAVY)
        for p in c.paragraphs:
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    doc.add_paragraph()
    doc.add_page_break()

    # Patch currency
    _ap(doc, "OS Patch Currency", 22, True, NAVY, sa=8)
    _ap(doc, "Current OS version vs latest known release. "
        "Best-effort against a static reference — may not reflect very recent updates.", sa=12)
    ph = ["Device", "OS", "Current Version", "Latest Known", "Status", "Last Check-in"]
    pt = doc.add_table(1 + len(devices), len(ph))
    pt.alignment = WD_TABLE_ALIGNMENT.LEFT
    _apply_table_borders(pt)
    _hr(pt, ph)
    for ri, d in enumerate(devices, 1):
        os_name = d.get("os", "") or ""
        ver = d.get("os_version", "") or ""
        latest, is_cur, status_lbl = _check_patch_currency(os_name, ver)
        clr = "27AE60" if status_lbl == "Up to date" else "C0392B" if status_lbl == "Out of date" else "999999"
        days = _days_since(d.get("last_checkin", ""))
        ci_disp = f"{days}d ago" if days is not None else (d.get("last_checkin", "") or "Unknown")
        vals = [
            _nf(d.get("name", "Unknown")),
            _nf(os_name),
            _nf(ver),
            _nf(latest) if latest else "Unknown",
            status_lbl,
            _nf(ci_disp),
        ]
        for ci, v in enumerate(vals):
            pt.cell(ri, ci).text = v
            _sc(pt.cell(ri, ci), 9)
        _shd(pt.cell(ri, 4), clr)
        _sc(pt.cell(ri, 4), 9, True, WHITE)
    doc.add_paragraph()
    doc.add_page_break()

    # Compliance breakdown
    _ap(doc, "Compliance State Breakdown", 22, True, NAVY, sa=8)
    _ap(doc, "Compliance states as reported by Microsoft Intune at time of export.", sa=12)
    comp_rows = sorted(by_compliance.items(), key=lambda x: -x[1])
    ct = doc.add_table(1 + max(len(comp_rows), 1), 3)
    ct.alignment = WD_TABLE_ALIGNMENT.LEFT
    _apply_table_borders(ct)
    _hr(ct, ["Compliance State", "Device Count", "% of Fleet"])
    for ri, (state, count) in enumerate(comp_rows, 1):
        pct = f"{round(count / total * 100)}%" if total else "0%"
        for ci, v in enumerate([_nf(state), str(count), pct]):
            ct.cell(ri, ci).text = v
            _sc(ct.cell(ri, ci), 9)
    doc.add_paragraph()

    # Platform breakdown
    _ap(doc, "Platform Breakdown", 16, True, ACCENT, sa=8)
    plat_rows = sorted(by_os.items(), key=lambda x: -x[1])
    ot = doc.add_table(1 + max(len(plat_rows), 1), 3)
    ot.alignment = WD_TABLE_ALIGNMENT.LEFT
    _apply_table_borders(ot)
    _hr(ot, ["Platform", "Device Count", "% of Fleet"])
    for ri, (plat, count) in enumerate(plat_rows, 1):
        pct = f"{round(count / total * 100)}%" if total else "0%"
        for ci, v in enumerate([_nf(plat), str(count), pct]):
            ot.cell(ri, ci).text = v
            _sc(ot.cell(ri, ci), 9)
    doc.add_paragraph()

    # Ownership breakdown
    _ap(doc, "Ownership Breakdown", 16, True, ACCENT, sa=8)
    own_rows = sorted(by_ownership.items(), key=lambda x: -x[1])
    owt = doc.add_table(1 + max(len(own_rows), 1), 3)
    owt.alignment = WD_TABLE_ALIGNMENT.LEFT
    _apply_table_borders(owt)
    _hr(owt, ["Ownership", "Device Count", "% of Fleet"])
    for ri, (own, count) in enumerate(own_rows, 1):
        pct = f"{round(count / total * 100)}%" if total else "0%"
        for ci, v in enumerate([_nf(own), str(count), pct]):
            owt.cell(ri, ci).text = v
            _sc(owt.cell(ri, ci), 9)
    doc.add_paragraph()
    doc.add_page_break()

    # Stale devices
    stale_devices = [
        d for d in devices
        if (_days_since(d.get("last_checkin", "")) or 0) > 14
    ]
    if stale_devices:
        _ap(doc, "Stale Devices (No Check-in > 14 Days)", 22, True, NAVY, sa=8)
        _ap(doc, "These devices have not checked in recently and may be offline, "
            "unmanaged, or decommissioned.", sa=12)
        st = doc.add_table(1 + len(stale_devices), 4)
        st.alignment = WD_TABLE_ALIGNMENT.LEFT
        _apply_table_borders(st)
        _hr(st, ["Device", "OS", "Last Check-in", "Days Since Check-in"])
        for ri, d in enumerate(stale_devices, 1):
            days = _days_since(d.get("last_checkin", ""))
            for ci, v in enumerate([
                _nf(d.get("name", "Unknown")),
                _nf(d.get("os", "")),
                _nf(d.get("last_checkin", "")),
                str(days) if days is not None else "Unknown",
            ]):
                st.cell(ri, ci).text = v
                _sc(st.cell(ri, ci), 9)
        doc.add_paragraph()
        doc.add_page_break()

    # Disclaimer
    _rule(doc)
    _ap(doc,
        "This report was generated by Patched.im Ltd from data provided via Intune CSV export. "
        "OS patch currency is assessed against a static reference and may not reflect the very latest releases. "
        "This report does not constitute a penetration test.",
        9, c=GREY, sa=4)
    _ap(doc, f"Generated: {now.strftime('%d %B %Y %H:%M UTC')}  |  patched.im", 9, c=GREY)

    doc.save(output_path)

    return {
        "total": total,
        "compliant": compliant,
        "non_compliant": non_compliant,
        "stale": stale_count,
        "out_of_date": out_of_date_count,
    }


# ── Discovered-apps CVE report ───────────────────────────────────────────────
def generate_apps_cve_report(apps: list, nvd_api_key: str, output_path: str, logo_path: str) -> dict:
    """
    Run app rows through the existing CVE matching engine (_app_cpe + _scan from scanner.py)
    and generate a .docx report in the same visual style as the existing CVE scan.
    All user-supplied cell values are passed through neutralise_formula().
    Returns stats dict for use in the delivery email.
    """
    doc = Document()
    now = datetime.now(timezone.utc)
    for s in doc.sections:
        s.top_margin = s.bottom_margin = s.left_margin = s.right_margin = Cm(2.54)
    doc.styles["Normal"].font.name = "Arial"
    doc.styles["Normal"].font.size = Pt(11)

    # Title page
    for _ in range(2):
        doc.add_paragraph()
    if logo_path and os.path.exists(logo_path):
        lp = doc.add_paragraph()
        lp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        lp.add_run().add_picture(logo_path, width=Inches(3.5))
        lp.paragraph_format.space_after = Pt(20)
    _ap(doc, "Endpoint Security  |  Compliance  |  Patch Management", 11,
        c=GREY, al=WD_ALIGN_PARAGRAPH.CENTER, sa=30)
    _rule(doc)
    _ap(doc, "Application CVE Vulnerability Assessment", 26, True, ACCENT,
        WD_ALIGN_PARAGRAPH.CENTER, 30)
    _ap(doc, f"Report Date: {now.strftime('%d %B %Y')}", 12,
        c=DARK, al=WD_ALIGN_PARAGRAPH.CENTER, sa=4)
    _ap(doc, "Classification: Confidential", 11, c=GREY, al=WD_ALIGN_PARAGRAPH.CENTER, sa=4)
    _ap(doc, "Prepared by Patched.im Ltd  |  patched.im", 11, c=GREY, al=WD_ALIGN_PARAGRAPH.CENTER)
    doc.add_page_break()

    # CVE scan — reuse scanner.py engine
    cache = {}
    results = []
    for app in apps:
        name = app.get("name", "")
        version = app.get("version", "")
        cpe = _app_cpe(name, version) if name else None
        cves = _scan(cpe, nvd_api_key, cache) if cpe else []
        results.append({
            "name": name,
            "version": version,
            "cpe": cpe,
            "cves": cves,
            "platform": app.get("platform", ""),
        })

    total_apps = len(apps)
    apps_with_cves = sum(1 for r in results if r["cves"])
    matched_cpes = sum(1 for r in results if r["cpe"])

    seen_ids: set = set()
    sev_counts: dict = defaultdict(int)
    for r in results:
        for c in r["cves"]:
            if c["id"] not in seen_ids:
                seen_ids.add(c["id"])
                sev_counts[c["severity"]] += 1
    total_cves = len(seen_ids)

    # Assessment summary
    _ap(doc, "Assessment Summary", 22, True, NAVY, sa=12)
    _ap(doc,
        f"Patched.im scanned {total_apps} application(s) from your Intune Discovered Apps export "
        f"against the NIST National Vulnerability Database.",
        sa=12)
    t = doc.add_table(2, 4)
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    _apply_table_borders(t)
    for i, h in enumerate(["Apps Scanned", "Apps with CVEs", "Unique CVEs", "CPEs Matched"]):
        t.cell(0, i).text = h
        _shd(t.cell(0, i), "1B2A4A")
        _sc(t.cell(0, i), 9, True, WHITE)
    for i, v in enumerate([str(total_apps), str(apps_with_cves), str(total_cves), str(matched_cpes)]):
        c = t.cell(1, i)
        c.text = v
        _shd(c, LBG)
        _sc(c, 14, True, NAVY)
        for p in c.paragraphs:
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    doc.add_paragraph()

    # Severity breakdown
    _ap(doc, "CVE Severity Breakdown", 14, True, ACCENT, sa=8)
    st = doc.add_table(2, 4)
    st.alignment = WD_TABLE_ALIGNMENT.LEFT
    _apply_table_borders(st)
    for i, (lbl, key, clr) in enumerate([
        ("Critical", "CRITICAL", "C0392B"),
        ("High",     "HIGH",     "E67E22"),
        ("Medium",   "MEDIUM",   "F39C12"),
        ("Low",      "LOW",      "27AE60"),
    ]):
        st.cell(0, i).text = lbl
        _shd(st.cell(0, i), clr)
        _sc(st.cell(0, i), 9, True, WHITE)
        st.cell(1, i).text = str(sev_counts.get(key, 0))
        _sc(st.cell(1, i), 12, True, NAVY)
        for p in st.cell(1, i).paragraphs:
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    doc.add_paragraph()
    doc.add_page_break()

    # Vulnerable applications
    vulnerable = sorted(
        [r for r in results if r["cves"]],
        key=lambda x: -len(x["cves"]),
    )
    if vulnerable:
        _ap(doc, "Vulnerable Applications", 22, True, NAVY, sa=8)
        _ap(doc, f"{len(vulnerable)} application(s) with known CVEs.", sa=12)
        ph = ["Application", "Version", "Platform", "CVEs", "Top Severity"]
        vt = doc.add_table(1 + len(vulnerable), len(ph))
        vt.alignment = WD_TABLE_ALIGNMENT.LEFT
        _apply_table_borders(vt)
        _hr(vt, ph)
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        sev_clr  = {"CRITICAL": "C0392B", "HIGH": "E67E22", "MEDIUM": "F39C12", "LOW": "27AE60"}
        for ri, r in enumerate(vulnerable, 1):
            top = max(r["cves"], key=lambda c: sev_rank.get(c["severity"], 0))
            top_sev = top["severity"]
            for ci, v in enumerate([
                _nf(r["name"]),
                _nf(r["version"]),
                _nf(r["platform"]),
                str(len(r["cves"])),
                top_sev,
            ]):
                vt.cell(ri, ci).text = v
                _sc(vt.cell(ri, ci), 9)
            _shd(vt.cell(ri, 4), sev_clr.get(top_sev, "999999"))
            _sc(vt.cell(ri, 4), 9, True, WHITE)
        doc.add_paragraph()
        doc.add_page_break()

    # CVE inventory (same layout as existing scanner _gen_report)
    _ap(doc, "CVE Inventory", 22, True, NAVY, sa=12)
    _ap(doc, "Complete list of unique CVEs discovered across all scanned applications.", sa=12)
    cve_map: dict = {}
    for r in results:
        for c in r["cves"]:
            cid = c["id"]
            if cid not in cve_map:
                cve_map[cid] = {**c, "apps": []}
            cve_map[cid]["apps"].append(_nf(r["name"]))
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_cves = sorted(
        cve_map.values(),
        key=lambda x: (sev_order.get(x["severity"], 99), -(x.get("score") or 0)),
    )
    if sorted_cves:
        tbl = doc.add_table(1 + len(sorted_cves), 5)
        tbl.alignment = WD_TABLE_ALIGNMENT.LEFT
        _apply_table_borders(tbl)
        _hr(tbl, ["CVE ID", "Severity", "Score", "Application(s)", "Description"])
        for ri, cve in enumerate(sorted_cves, 1):
            sev_c = cve["severity"]
            clr = {"CRITICAL": "C0392B", "HIGH": "E67E22", "MEDIUM": "F39C12", "LOW": "27AE60"}.get(sev_c, "999999")
            app_list = ", ".join(cve["apps"][:3]) + (" …" if len(cve["apps"]) > 3 else "")
            vals = [
                cve["id"],
                sev_c,
                str(cve.get("score") or "N/A"),
                app_list,
                (cve.get("description") or "")[:120],
            ]
            for ci, v in enumerate(vals):
                tbl.cell(ri, ci).text = v
                _sc(tbl.cell(ri, ci), 8)
            _shd(tbl.cell(ri, 1), clr)
            _sc(tbl.cell(ri, 1), 8, True, WHITE)
            for p in tbl.cell(ri, 1).paragraphs:
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            for p in tbl.cell(ri, 2).paragraphs:
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    else:
        _ap(doc, "No CVEs detected for matched applications.", sa=12)
    doc.add_paragraph()

    # Unmatched apps note
    no_match = [r for r in results if not r["cpe"]]
    if no_match:
        doc.add_paragraph()
        _ap(doc, "Applications Not Checked", 16, True, ACCENT, sa=8)
        _ap(doc,
            f"{len(no_match)} application(s) could not be matched to a known CPE and were not assessed. "
            "CVE coverage expands as Patched.im's matching catalogue grows.",
            sa=12)
    doc.add_page_break()

    # Recommendations
    _ap(doc, "Recommendations", 22, True, NAVY, sa=12)
    for i, (title, body) in enumerate([
        ("Patch Critical & High CVE Applications Immediately",
         "Address Critical (9.0+) and High (7.0–8.9) severity applications in your next patch cycle."),
        ("Enable Third-Party Patch Management",
         "Patched.im deploys Patch My PC (Windows) and Jamf App Installers (macOS) "
         "to automate third-party application patching at scale."),
        ("Establish a Regular Scan Cadence",
         "Monthly reassessments track remediation progress and catch newly disclosed CVEs."),
    ], 1):
        _ap(doc, f"{i}. {title}", 12, True, ACCENT, sa=4)
        _ap(doc, body, 11, sa=12)

    # Disclaimer
    doc.add_paragraph()
    _rule(doc)
    _ap(doc,
        "This report was generated by Patched.im Ltd using data provided via Intune Discovered Apps CSV export, "
        "cross-referenced against the NIST National Vulnerability Database. "
        "It does not constitute a penetration test. "
        "Application matching uses catalogue keyword matching and may not cover all installed software.",
        9, c=GREY, sa=4)
    _ap(doc, f"Generated: {now.strftime('%d %B %Y %H:%M UTC')}  |  patched.im", 9, c=GREY)

    doc.save(output_path)

    return {
        "total_apps": total_apps,
        "apps_with_cves": apps_with_cves,
        "total_cves": total_cves,
    }
