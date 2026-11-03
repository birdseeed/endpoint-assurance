"""PAT-2520: the scan service names its legal entity "Patched LTD", from one constant.

The constant is ``scanner.LEGAL_NAME``. ``scan/scanner.py`` is the one module
the report generators, ``shared.py`` and the templates all sit downstream of
(``shared`` imports ``intune_upload``, which imports ``scanner``), so it is the
only place a single definition can live without an import cycle.
``shared.LEGAL_NAME`` is that same object and ``shared.templates`` receives it
as the ``legal_name`` / ``legal_line`` Jinja globals.

This file checks what only the scan app's own environment can: the pages the
service renders and the Word documents it generates. The portal's constant, the
static sweep of both services' sources and the check that the two constants
never differ live in ``tests/test_pat2520_legal_name.py``.
"""

import re
from pathlib import Path

import intune_upload
import scanner
import shared
from docx import Document

# The owner's ruling of 2026-10-05, verbatim. Keep in step with
# tests/test_pat2520_legal_name.py (which asserts both services equal it).
RULED_NAME = "Patched LTD"
RULED_LEGAL_LINE = "Patched LTD · Isle of Man · Company No. 139269C"
RULED_FOOTER_TEXT = "© 2026 Patched LTD · Isle of Man · Company No. 139269C"

# Same pattern as the portal-side guard: every spelling of the legal entity,
# case-insensitive, acceptable only when it is exactly RULED_NAME.
LEGAL_NAME_SPELLING = re.compile(
    r"(?<![A-Za-z0-9])patched(?:[. ]?im)?(?: |&nbsp;| )+(?:ltd|limited)\b",
    re.IGNORECASE,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
LOGO = Path(shared.BASE) / "static" / "patched-report-logo.png"


def _old_spellings(text: str) -> list[str]:
    return [m.group(0) for m in LEGAL_NAME_SPELLING.finditer(text) if m.group(0) != RULED_NAME]


def _footer_text(html: str) -> str:
    match = re.search(r'<footer class="footer">(.*?)</footer>', html, re.DOTALL)
    assert match, "page has no footer"
    meta = re.search(r'<div class="footer__meta">(.*?)</div>', match.group(1), re.DOTALL)
    assert meta, "footer has no legal line"
    text = re.sub(r"<[^>]+>", "", meta.group(1))
    text = text.replace("&copy;", "©")
    return re.sub(r"\s+", " ", text).strip()


def _docx_text(path) -> str:
    """Every paragraph, table cell, header and footer of a generated document."""
    doc = Document(str(path))
    parts = [p.text for p in doc.paragraphs]
    for table in doc.tables:
        for row in table.rows:
            parts.extend(cell.text for cell in row.cells)
    for section in doc.sections:
        for story in (section.header, section.footer):
            parts.extend(p.text for p in story.paragraphs)
    return "\n".join(parts)


# ── The constant ─────────────────────────────────────────────────────────────
def test_scan_constants_are_the_ruled_legal_identity():
    assert scanner.LEGAL_NAME == RULED_NAME
    assert scanner.LEGAL_COMPANY_NUMBER == "139269C"
    assert scanner.LEGAL_LINE == RULED_LEGAL_LINE


def test_every_scan_module_uses_the_one_definition():
    assert shared.LEGAL_NAME is scanner.LEGAL_NAME
    assert shared.LEGAL_LINE is scanner.LEGAL_LINE
    assert intune_upload.LEGAL_NAME is scanner.LEGAL_NAME


def test_scan_templates_receive_the_constants_as_globals():
    assert shared.templates.env.globals["legal_name"] == scanner.LEGAL_NAME
    assert shared.templates.env.globals["legal_line"] == scanner.LEGAL_LINE


# ── Rendered pages ───────────────────────────────────────────────────────────
def test_static_scan_pages_footer_and_body_use_the_ruled_name(client):
    for path in ("/public/scan", "/public/intune-upload", "/public/privacy",
                 "/public/intune-instructions"):
        r = client.get(path)
        assert r.status_code == 200, path
        assert _footer_text(r.text) == RULED_FOOTER_TEXT, path
        assert not _old_spellings(r.text), path


def test_privacy_notice_names_the_company_as_patched_ltd(client):
    html = client.get("/public/privacy").text
    assert f"<p>{RULED_NAME}, a company registered in the Isle of Man." in html
    assert f"On {RULED_NAME} infrastructure hosted at Hetzner" in html
    assert f"<p>{RULED_NAME}, Isle of Man." in html


def test_verify_and_done_pages_footer_use_the_ruled_name(client, devices_csv):
    resp = client.post(
        "/public/scan",
        data={"company": "Acme", "email": "legal@test.example", "authorised": "yes",
              "cf-turnstile-response": "x"},
        files={"devices_file": ("devices.csv", devices_csv, "text/csv")},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    scan_id = resp.headers["location"].rsplit("/", 1)[-1]

    for path in (f"/public/scan/verify/{scan_id}", f"/public/scan/done/{scan_id}"):
        r = client.get(path)
        assert r.status_code == 200, path
        assert _footer_text(r.text) == RULED_FOOTER_TEXT, path
        assert not _old_spellings(r.text), path


def test_pricing_enquiry_page_footer_uses_the_ruled_name(client):
    import router

    # A filled honeypot is accepted silently with no database or mail side
    # effect, and renders the same page a real submission does.
    r = client.post(
        "/public/pricing-enquiry",
        data={"name": "Ada", "email": "ada@test.example", "organisation": "Acme",
              router.PRICING_HONEYPOT_FIELD: "bot"},
    )
    assert r.status_code == 200
    assert _footer_text(r.text) == RULED_FOOTER_TEXT
    assert not _old_spellings(r.text)


# ── Generated Word documents ─────────────────────────────────────────────────
def test_cve_scan_report_names_patched_ltd(tmp_path):
    out = tmp_path / "scan.docx"
    scanner.run_scan_from_upload(
        str(FIXTURES / "devices.csv"), None, "", "Acme", str(LOGO), str(out)
    )
    text = _docx_text(out)
    assert f"Prepared by {RULED_NAME}  |  patched.im" in text
    assert f"This report was generated by {RULED_NAME} using data from Microsoft Intune" in text
    assert not _old_spellings(text)


def test_intune_devices_report_names_patched_ltd(tmp_path):
    out = tmp_path / "devices.docx"
    devices = intune_upload.parse_devices_rows([
        {"Device name": "UP-PC-01", "OS": "Windows", "OS version": "10.0.19045.0",
         "Compliance": "Compliant", "Last check-in": "2026-07-01T09:00:00Z"},
    ])
    intune_upload.generate_devices_report(devices, str(out), str(LOGO))
    text = _docx_text(out)
    assert f"Prepared by {RULED_NAME}  |  patched.im" in text
    assert f"This report was generated by {RULED_NAME} from data provided via Intune CSV" in text
    assert not _old_spellings(text)


def test_intune_apps_report_names_patched_ltd(tmp_path):
    out = tmp_path / "apps.docx"
    apps = intune_upload.parse_apps_rows([
        {"Application name": "Example Internal Tool", "Version": "1.0",
         "Platform": "Windows", "Number of devices with app": "3"},
    ])
    intune_upload.generate_apps_cve_report(apps, "", str(out), str(LOGO))
    text = _docx_text(out)
    assert f"Prepared by {RULED_NAME}  |  patched.im" in text
    assert f"This report was generated by {RULED_NAME} using data provided via Intune" in text
    assert not _old_spellings(text)
