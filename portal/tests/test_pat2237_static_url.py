"""PAT-2237: hashed cache-busters instead of hand-bumped ?v= strings.

Production, 2026-09-28: templates/base.html referenced /static/css/portal.css
with a hand-bumped ?v=2026-09-27-pat-2022 string. Three same-day PRs changed
portal.css without bumping that string, so any browser that had already
visited the portal kept serving the stale, cached stylesheet - live proof was
a card with class ov-card--tone-bad whose computed border was still green.
The same hand-bumped-?v= pattern covered portal.js, feedback.js, the
favicons and, in scan/, site.css and its own favicon.svg copy.

The fix: main.py's static_url() (and scan/shared.py's own copy, for scan's
own static dir) derives the cache-buster from the file's own sha256, so a
changed file always gets a changed URL with nothing to remember to bump.
"""

import re

import pytest

import main

LITERAL_VERSIONED_STATIC_RE = re.compile(r'/static/[^"\']*\?v=')


def _template_files():
    paths = sorted(main.BASE_DIR.joinpath("templates").rglob("*.html"))
    assert paths, "expected to find portal templates to scan"
    return paths


def _scan_template_files():
    scan_templates = main.BASE_DIR / "scan" / "templates"
    paths = sorted(scan_templates.rglob("*.html"))
    assert paths, "expected to find scan templates to scan"
    return paths


# ── (a) no hand-bumped ?v= literal remains anywhere in the templates ──────
@pytest.mark.parametrize("path", _template_files(), ids=lambda p: p.name)
def test_no_literal_versioned_static_url_in_portal_templates(path):
    text = path.read_text()
    matches = LITERAL_VERSIONED_STATIC_RE.findall(text)
    assert not matches, (
        f"{path} still has a hand-bumped /static/...?v= literal: {matches!r} "
        "- use {{ static_url('...') }} instead so the version tracks the "
        "file's own content hash (PAT-2237)."
    )


@pytest.mark.parametrize("path", _scan_template_files(), ids=lambda p: p.name)
def test_no_literal_versioned_static_url_in_scan_templates(path):
    text = path.read_text()
    matches = LITERAL_VERSIONED_STATIC_RE.findall(text)
    assert not matches, (
        f"{path} still has a hand-bumped /static/...?v= literal: {matches!r} "
        "- use {{ static_url('...') }} instead (scan/shared.py's own copy, "
        "PAT-2237)."
    )


# ── (b) static_url() reflects the file's own sha256 ───────────────────────
def test_static_url_uses_first_12_hex_chars_of_file_sha256():
    import hashlib

    path = main.STATIC_DIR / "css" / "portal.css"
    expected = hashlib.sha256(path.read_bytes()).hexdigest()[:12]
    assert main.static_url("css/portal.css") == f"/static/css/portal.css?v={expected}"


# ── (c) the version changes when the file's bytes change ──────────────────
def test_static_url_changes_when_file_bytes_change(tmp_path, monkeypatch):
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    target = static_dir / "probe.css"
    target.write_bytes(b"body { color: red; }")

    monkeypatch.setattr(main, "STATIC_DIR", static_dir.resolve())
    main.static_url.cache_clear()
    try:
        first = main.static_url("probe.css")

        target.write_bytes(b"body { color: blue; }")
        main.static_url.cache_clear()
        second = main.static_url("probe.css")

        assert first != second
        assert first.startswith("/static/probe.css?v=")
        assert second.startswith("/static/probe.css?v=")
    finally:
        main.static_url.cache_clear()


# ── (d) path traversal is refused ──────────────────────────────────────────
def test_static_url_refuses_path_traversal():
    with pytest.raises(ValueError):
        main.static_url("../main.py")


def test_scan_static_url_refuses_path_traversal():
    import sys
    from pathlib import Path

    sys.path.insert(0, str(main.BASE_DIR / "scan"))
    import shared as scan_shared  # noqa: E402

    with pytest.raises(ValueError):
        scan_shared.static_url("../app.py")
    assert isinstance(scan_shared.SCAN_STATIC_DIR, Path)


# ── (e) a rendered page actually carries a hashed portal.css URL ──────────
def test_rendered_home_page_carries_hashed_portal_css_url(client, make_token):
    token = make_token()
    resp = client.get("/", headers={"Cf-Access-Jwt-Assertion": token})
    assert resp.status_code == 200
    match = re.search(r'portal\.css\?v=([0-9a-f]{12})"', resp.text)
    assert match, "expected a hashed portal.css?v=<12 hex chars> URL in the rendered page"


def test_no_template_references_a_static_css_or_js_file_unversioned():
    """PAT-2237 review: a stylesheet or script with no ?v= at all goes
    stale exactly like a hand-bumped one. Every CSS/JS reference must go
    through static_url()."""
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    bare = re.compile(r'(?:href|src)="/static/[^"]+\.(?:css|js)"')
    hits = []
    for folder in ("templates", "scan/templates"):
        for tpl in (root / folder).rglob("*.html"):
            for m in bare.finditer(tpl.read_text()):
                hits.append(f"{tpl.relative_to(root)}: {m.group(0)}")
    assert not hits, "unversioned static assets:\n" + "\n".join(hits)
