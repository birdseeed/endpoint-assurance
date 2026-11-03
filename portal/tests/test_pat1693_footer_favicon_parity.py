"""PAT-1693: keep every public footer and favicon consumer in lockstep."""

from __future__ import annotations

import re
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_TEMPLATE_DIR = ROOT / "scan" / "templates"
SCAN_FOOTER_PARTIAL = SCAN_TEMPLATE_DIR / "_site_footer.html"
SCAN_NAV_PARTIAL = SCAN_TEMPLATE_DIR / "_site_nav.html"
# Every page the scan service renders. Discovered, not listed, so a new page
# cannot be added without the shared header and footer (PAT-2560).
SCAN_TEMPLATES = tuple(sorted(SCAN_TEMPLATE_DIR.glob("public_*.html")))
# PAT-2560: the footer is patched.im's own, as of the 6 Oct 2026 direction
# (the Mac app and its waitlist). Same links, same order as the website.
CANONICAL_LINKS = (
    ("https://patched.im/#what", "What it does"),
    ("https://patched.im/#price", "Price"),
    ("https://patched.im/#who", "Who makes it"),
    ("https://patched.im/privacy.html", "Privacy"),
    ("https://patched.im/cookies.html", "Cookies"),
    ("https://patched.im/terms", "Terms"),
    ("https://patched.im/refunds", "Refunds"),
    ("mailto:hello@patched.im", "Contact"),
)
NAV_LINKS = (
    ("https://patched.im/#what", "What it does"),
    ("https://patched.im/#price", "Price"),
    ("https://patched.im/#who", "Who makes it"),
)
NAV_CTA = '<a class="btn btn--primary" href="https://patched.im/#waitlist">Join the waitlist</a>'
# Links and labels from the site as it was before 6 Oct 2026. None of them may
# come back on a scan page: every one points at a page that has been taken down
# or at the mothballed service.
RETIRED_SITE_REFERENCES = (
    "patched.im/blog",
    "patched.im/pricing",
    "patched.im/security.html",
    "patched.im/about.html",
    "patched.im/assessment",
    "patched.im/projects",
    "patched.im/#offer",
    "docs.patched.im",
    "status.patched.im",
    "app.patched.im",
    "Customer login",
    "Discuss your estate",
)
# PAT-2520: the legal entity is Patched LTD and is defined once per service
# (main.LEGAL_LINE, scan/scanner.py's LEGAL_LINE), so no template spells it out.
# The footer source carries the `legal_line` expression around the year markup;
# what it renders to, "© 2026 Patched LTD · Isle of Man · Company No. 139269C",
# is pinned for both services in tests/test_pat2520_legal_name.py and
# scan/tests/test_pat2520_scan_legal_name.py.
LEGAL_LINE = "&copy; <span data-year>2026</span> {{ legal_line }}"
LOCKUP_HASH = "7ef04361b5021820b11a75dc66f3c11eb1a208a8672cb19ef2202fbc20ca58db"
FAVICON_HASH = "dd7d08ad903ca654d811e092abfa168d833e80d910dcf728b912cf21b663eb5b"
PRIMARY_MARK_HASH = "21b281c624108754210207949fa22f5cd7a8038096dd05fe90ee73021a05449f"
WORDMARK_TAG = (
    '<img src="/static/patched-lockup-onslate.svg" width="136" '
    'height="28" alt="Patched">'
)
# PAT-2237: the ?v= cache-buster is now the asset's own content hash,
# resolved at render time by static_url(), rather than a hand-bumped
# literal in the template source (a hand-bumped literal is exactly what
# let three same-day PRs change portal.css without the browser ever
# seeing a new URL). These constants check the template source calls
# static_url() for the right asset, rather than asserting a version
# string that no longer exists in the source at all.
SCAN_FAVICON = (
    '<link rel="icon" type="image/svg+xml" '
    'href="{{ static_url(\'favicon.svg\') }}">'
)
PORTAL_CSS = '<link rel="stylesheet" href="{{ static_url(\'css/portal.css\') }}">'
SCAN_CSS = '<link rel="stylesheet" href="{{ static_url(\'css/site.css\') }}">'


def _footer(html: str) -> str:
    match = re.search(r'<footer class="footer">(.*?)</footer>', html, re.DOTALL)
    assert match, "missing footer"
    return match.group(1)


def _links(footer: str) -> tuple[tuple[str, str], ...]:
    nav = re.search(
        r'<nav class="footer__links" aria-label="Footer">(.*?)</nav>', footer, re.DOTALL
    )
    assert nav, "missing canonical footer navigation"
    return tuple(re.findall(r'<a href="([^"]+)">([^<]+)</a>', nav.group(1)))


def test_portal_footer_is_wordmark_and_legal_line_only():
    """24 Sept 2026 (Andy): the marketing-site links and the "Read-only view
    of your estate" note came out of the portal footer. The public scan
    pages keep the canonical link set (test below)."""
    html = (ROOT / "templates" / "base.html").read_text()
    footer = _footer(html)
    assert 'class="footer__links"' not in footer
    assert "footer__note" not in footer
    assert WORDMARK_TAG in footer
    assert f'<div class="footer__meta">{LEGAL_LINE}</div>' in footer
    assert PORTAL_CSS in html


def test_scan_footer_partial_is_the_canonical_contract():
    footer = _footer(SCAN_FOOTER_PARTIAL.read_text())
    assert _links(footer) == CANONICAL_LINKS
    assert WORDMARK_TAG in footer
    assert f'<div class="footer__meta">{LEGAL_LINE}</div>' in footer


def test_scan_nav_partial_is_the_site_header():
    html = SCAN_NAV_PARTIAL.read_text()
    nav = re.search(r'<nav class="nav__links" aria-label="Primary">(.*?)</nav>', html, re.DOTALL)
    assert nav, "missing primary navigation"
    assert tuple(re.findall(r'<a href="([^"]+)">([^<]+)</a>', nav.group(1))) == NAV_LINKS
    assert NAV_CTA in html


def test_every_scan_page_takes_its_header_and_footer_from_the_partials():
    assert len(SCAN_TEMPLATES) >= 8, SCAN_TEMPLATES
    for template in SCAN_TEMPLATES:
        html = template.read_text()
        assert html.count('{% include "_site_nav.html" %}') == 1, template
        assert html.count('{% include "_site_footer.html" %}') == 1, template
        # No page carries a header or footer of its own beside the shared one.
        assert '<header class="nav"' not in html, template
        assert '<footer class="footer"' not in html, template
        assert SCAN_FAVICON in html
        assert SCAN_CSS in html
        assert "favicon.ico" not in html


def test_no_scan_template_points_at_the_site_as_it_was():
    for template in sorted(SCAN_TEMPLATE_DIR.glob("*.html")):
        html = template.read_text()
        for retired in RETIRED_SITE_REFERENCES:
            assert retired not in html, (template.name, retired)


def test_footer_grid_and_mobile_contracts_are_present_for_both_services():
    portal_css = (ROOT / "static" / "css" / "portal.css").read_text()
    scan_css = (ROOT / "scan" / "static" / "css" / "site.css").read_text()

    assert "grid-template-areas: 'logo meta';" in portal_css
    assert "grid-template-areas: 'logo' 'meta';" in portal_css
    assert ".footer__logo img { display: block; width: 136px; height: 28px; }" in portal_css
    assert "@media (max-width: 680px)" in portal_css

    assert "grid-template-areas: 'logo links' 'logo meta';" in scan_css
    assert "grid-template-areas: 'logo' 'links' 'meta';" in scan_css
    assert ".footer__logo img { display: block; width: 136px; height: 28px; }" in scan_css
    assert "@media (max-width: 680px)" in scan_css


def test_brand_v3_lockup_and_adaptive_favicon_are_the_canonical_assets_in_served_roots():
    portal_wordmark = ROOT / "static" / "patched-lockup-onslate.svg"
    scan_wordmark = ROOT / "scan" / "static" / "patched-lockup-onslate.svg"
    portal_favicon = ROOT / "static" / "favicon.svg"
    scan_favicon = ROOT / "scan" / "static" / "favicon.svg"

    assert sha256(portal_wordmark.read_bytes()).hexdigest() == LOCKUP_HASH
    assert sha256(scan_wordmark.read_bytes()).hexdigest() == LOCKUP_HASH
    assert sha256(portal_favicon.read_bytes()).hexdigest() == FAVICON_HASH
    assert sha256(scan_favicon.read_bytes()).hexdigest() == FAVICON_HASH
    assert portal_favicon.read_bytes() == scan_favicon.read_bytes()
    assert 'StaticFiles(directory=str(BASE / "static"))' in (ROOT / "scan" / "app.py").read_text()


def test_brand_v3_primary_mark_is_identical_in_both_served_roots():
    portal_mark = ROOT / "static" / "brand" / "patched-mark-primary.svg"
    scan_mark = ROOT / "scan" / "static" / "brand" / "patched-mark-primary.svg"

    assert sha256(portal_mark.read_bytes()).hexdigest() == PRIMARY_MARK_HASH
    assert sha256(scan_mark.read_bytes()).hexdigest() == PRIMARY_MARK_HASH
    assert portal_mark.read_bytes() == scan_mark.read_bytes()
