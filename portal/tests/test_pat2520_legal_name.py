"""PAT-2520: the legal entity is "Patched LTD", defined once per service.

The company's legal name is Patched LTD (Isle of Man, company number
139269C). "Patched" the product and "patched.im" the domain are fine wherever
they are used that way; only the legal entity name is guarded here.

The portal (``main.py``) and the scan service (``scan/``) are separate
processes with separate trust boundaries, so neither imports the other. Each
holds its own constant (``main.LEGAL_NAME`` and ``scan/scanner.py``'s
``LEGAL_NAME``) and this file fails if they ever differ, if any old spelling
of the name appears in a template or a Python source of either service, or if
a rendered footer stops reading exactly the line the owner ruled.

The scan service's rendered pages and generated Word documents are checked in
``scan/tests/test_pat2520_scan_legal_name.py``, which needs the scan app's own
environment.
"""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path

import main
from tests.conftest import STUB_STATE

ROOT = Path(__file__).resolve().parents[1]

# The owner's ruling of 2026-10-05, verbatim. Do not edit this to make a
# failing check pass: change the constants and this together, on purpose.
RULED_NAME = "Patched LTD"
RULED_COMPANY_NUMBER = "139269C"
RULED_LEGAL_LINE = "Patched LTD · Isle of Man · Company No. 139269C"
RULED_FOOTER_TEXT = "© 2026 Patched LTD · Isle of Man · Company No. 139269C"

# Every spelling of the legal entity other than the ruled one. Matched
# case-insensitively, so "Patched Ltd" and "Patched LTD" both match; a match
# is acceptable only when it is exactly RULED_NAME.
LEGAL_NAME_SPELLING = re.compile(
    r"(?<![A-Za-z0-9])patched(?:[. ]?im)?(?: |&nbsp;| )+(?:ltd|limited)\b",
    re.IGNORECASE,
)

# Not swept: the vendored brand kit is synced verbatim from the branding repo
# and is fixed there, and the changelog is a customer-facing history of what
# was true when each entry was written. Tests and browser suites are not
# shippable copy (and this file holds the patterns it forbids).
SKIP_DIR_NAMES = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache",
    ".ruff_cache", "state", "tests", "e2e",
}
SKIP_RELATIVE_PREFIXES = ("static/vendor/brand/", "data/changelog.json")
SWEPT_SUFFIXES = {
    ".py", ".html", ".js", ".css", ".md", ".txt", ".sh", ".conf", ".service",
    ".timer", ".template", ".yml", ".yaml", ".toml", ".json", ".svg",
}


def _swept_files() -> list[Path]:
    found: list[Path] = []
    for directory, subdirs, names in os.walk(ROOT):
        subdirs[:] = sorted(d for d in subdirs if d not in SKIP_DIR_NAMES)
        for name in sorted(names):
            path = Path(directory) / name
            relative = path.relative_to(ROOT).as_posix()
            if relative.startswith(SKIP_RELATIVE_PREFIXES):
                continue
            if path.suffix.lower() in SWEPT_SUFFIXES:
                found.append(path)
    return found


def _old_spellings(text: str) -> list[str]:
    return [m.group(0) for m in LEGAL_NAME_SPELLING.finditer(text) if m.group(0) != RULED_NAME]


def _scan_constants() -> dict[str, str]:
    """Read the scan service's literal constants without importing it.

    ``scan/shared.py`` creates state directories at import and needs the scan
    test environment, so the portal-side guard parses ``scan/scanner.py`` (the
    one definition, imported by ``scan/intune_upload.py`` and re-exported by
    ``scan/shared.py``) with ``ast`` instead.
    """
    tree = ast.parse((ROOT / "scan" / "scanner.py").read_text(encoding="utf-8"))
    found: dict[str, str] = {}
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in {"LEGAL_NAME", "LEGAL_COMPANY_NUMBER"}
        ):
            found[node.targets[0].id] = ast.literal_eval(node.value)
    return found


def _footer_text(html: str) -> str:
    match = re.search(r'<footer class="footer">(.*?)</footer>', html, re.DOTALL)
    assert match, "page has no footer"
    meta = re.search(r'<div class="footer__meta">(.*?)</div>', match.group(1), re.DOTALL)
    assert meta, "footer has no legal line"
    text = re.sub(r"<[^>]+>", "", meta.group(1))
    text = text.replace("&copy;", "©")
    return re.sub(r"\s+", " ", text).strip()


# ── The constants ────────────────────────────────────────────────────────────
def test_portal_constants_are_the_ruled_legal_identity():
    assert main.LEGAL_NAME == RULED_NAME
    assert main.LEGAL_COMPANY_NUMBER == RULED_COMPANY_NUMBER
    assert main.LEGAL_LINE == RULED_LEGAL_LINE


def test_portal_templates_receive_the_constants_as_globals():
    assert main.templates.env.globals["legal_name"] == main.LEGAL_NAME
    assert main.templates.env.globals["legal_line"] == main.LEGAL_LINE


def test_scan_and_portal_constants_never_differ():
    scan = _scan_constants()
    assert scan == {
        "LEGAL_NAME": main.LEGAL_NAME,
        "LEGAL_COMPANY_NUMBER": main.LEGAL_COMPANY_NUMBER,
    }, "scan/scanner.py and main.py must define the same legal identity"


# ── No old spelling anywhere in shippable sources ────────────────────────────
def test_the_sweep_actually_reaches_the_files_that_carry_the_name():
    """A sweep that silently walked nothing would pass. Pin the files it must
    reach and the ones it must leave alone."""
    swept = {p.relative_to(ROOT).as_posix() for p in _swept_files()}
    for must_reach in (
        "templates/base.html",
        "main.py",
        "scan/scanner.py",
        "scan/intune_upload.py",
        "scan/shared.py",
        "scan/router.py",
        "scan/templates/public_privacy.html",
        "scan/templates/public_scan.html",
        "scan/templates/public_verify.html",
        "scan/templates/public_done.html",
        "scan/templates/public_upload.html",
        "scan/templates/public_instructions.html",
        "scan/templates/public_pricing_enquiry.html",
    ):
        assert must_reach in swept, f"{must_reach} is not covered by the PAT-2520 sweep"
    assert not any(p.startswith(SKIP_RELATIVE_PREFIXES) for p in swept)


def test_no_old_spelling_of_the_legal_name_in_templates_or_python_sources():
    hits = []
    for path in _swept_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            for spelling in _old_spellings(line):
                hits.append(f"{path.relative_to(ROOT).as_posix()}:{number}: {spelling!r}")
    assert not hits, (
        f"the legal name is {RULED_NAME!r}; {len(hits)} old spelling(s) found:\n"
        + "\n".join(hits)
    )


def test_the_spelling_pattern_itself_catches_every_variant_and_spares_the_ruled_name():
    """A guard that cannot fail is not a guard: prove the pattern bites."""
    for old in (
        "Patched.im Ltd",
        "Patched.im LTD",
        "Patched.im Limited",
        "Patched Ltd",
        "Patched Limited",
        "patched.im ltd",
        "PATCHED.IM LIMITED",
        "Patched.im&nbsp;Ltd",
        "Patched.im Ltd",
        "Patched im Ltd",
    ):
        assert _old_spellings(f"Prepared by {old} | patched.im"), old
    for fine in (
        "Patched LTD",
        "Prepared by Patched LTD | patched.im",
        "Patched.im verification code",
        "Patched.im CVE assessment",
        "unpatched limited exposure",
        "patched.im is the domain",
    ):
        assert not _old_spellings(fine), fine


# ── Rendered footers: the signed-in page and every edge page ─────────────────
def test_signed_in_portal_footer_reads_the_ruled_line(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = client.get("/", headers={"Cf-Access-Jwt-Assertion": token})
    assert resp.status_code == 200
    assert _footer_text(resp.text) == RULED_FOOTER_TEXT
    assert not _old_spellings(resp.text)


def test_signed_out_portal_footer_reads_the_ruled_line(client):
    resp = client.get("/")
    assert resp.status_code == 401
    assert _footer_text(resp.text) == RULED_FOOTER_TEXT


def test_session_expired_portal_footer_reads_the_ruled_line(client, make_token):
    resp = client.get("/", headers={"Cf-Access-Jwt-Assertion": make_token(exp_delta=-120)})
    assert resp.status_code == 401
    assert _footer_text(resp.text) == RULED_FOOTER_TEXT


def test_not_linked_portal_footer_reads_the_ruled_line(client, make_token):
    STUB_STATE["mode"] = "forbidden403"
    resp = client.get("/", headers={"Cf-Access-Jwt-Assertion": make_token()})
    assert resp.status_code == 403
    assert _footer_text(resp.text) == RULED_FOOTER_TEXT


def test_not_enabled_portal_footer_reads_the_ruled_line(client, make_token):
    STUB_STATE["mode"] = "down503"
    resp = client.get("/", headers={"Cf-Access-Jwt-Assertion": make_token()})
    assert resp.status_code == 503
    assert _footer_text(resp.text) == RULED_FOOTER_TEXT


def test_error_portal_footer_reads_the_ruled_line(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["mode"] = "malformed"
    resp = client.get("/findings", headers={"Cf-Access-Jwt-Assertion": token})
    assert resp.status_code != 200
    assert _footer_text(resp.text) == RULED_FOOTER_TEXT
