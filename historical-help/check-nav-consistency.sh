#!/usr/bin/env bash
#
# check-nav-consistency.sh (PAT-1188)
#
# Guards against nav/footer drift across the docs site: every page must ship
# byte-identical <header class="nav">...</header> and <footer class="footer">
# ...</footer> blocks, so the "Guides" dropdown (added in PAT-1188 to fix nav
# overflow) and the footer can't silently diverge page-by-page.
#
# Unlike the marketing site (website/check-nav-consistency.sh), every link
# here already uses the absolute form (e.g. /getting-started.html) on every
# page including index.html, so there is no same-page-anchor exception to
# normalise away — the comparison is a plain byte-for-byte diff.
#
# Usage: bash check-nav-consistency.sh
# Exit 0 = every page's nav and footer match. Exit 1 = prints which files
# differ and how, then fails.

set -euo pipefail
cd "$(dirname "$0")"

pages=(
  index.html
  getting-started.html
  agent-updater.html
  protected.html
  faq.html
  security.html
  privacy.html
  read-your-report.html
  remediation-guide.html
  using-your-portal.html
)

favicon_version='20260926-brand-v3'
stylesheet_version='20260926-brand-v3'
expected_footer_links='<a href="https://patched.im/cyber-essentials">Cyber Essentials</a><a href="https://patched.im/msp">For MSPs</a><a href="https://patched.im/pricing">Pricing</a><a href="https://patched.im/security.html">Security</a><a href="https://patched.im/about.html">About</a><a href="https://patched.im/blog">Blog</a><a href="https://docs.patched.im">Docs</a><a href="https://status.patched.im">Status</a><a href="https://patched.im/privacy.html">Privacy</a><a href="https://patched.im/cookies.html">Cookies</a><a href="mailto:hello@patched.im">Contact</a>'
expected_nav_logo='<a class="nav__logo" href="https://patched.im" aria-label="Patched.im home"><img src="/patched-lockup-horizontal.svg" width="132" height="27" alt="Patched" /></a>'
expected_footer_logo='<div class="footer__logo"><img src="/patched-lockup-horizontal-white.svg" width="132" height="27" alt="Patched" /></div>'
expected_legal_line='Patched.im Ltd · Isle of Man · Company No. 139269C'

# Prints the lines from $1 between the first line matching $2 and the first
# subsequent line matching $3 (inclusive).
extract_block() {
  local file="$1" start="$2" end="$3"
  awk -v start="$start" -v end="$end" '
    $0 ~ start { capture = 1 }
    capture { print }
    capture && $0 ~ end { capture = 0 }
  ' "$file"
}

fail=0
ref_nav=""
ref_footer=""
ref_file=""

for page in "${pages[@]}"; do
  if [[ ! -f "$page" ]]; then
    echo "MISSING: $page not found" >&2
    fail=1
    continue
  fi

  nav=$(extract_block "$page" '<header class="nav">' '</header>')
  footer=$(extract_block "$page" '<footer class="footer">' '</footer>')

  if [[ -z "$nav" ]]; then
    echo "NO NAV FOUND: $page" >&2
    fail=1
    continue
  fi
  if [[ -z "$footer" ]]; then
    echo "NO FOOTER FOUND: $page" >&2
    fail=1
    continue
  fi

  if [[ "$footer" != *"$expected_footer_links"* ]]; then
    echo "FOOTER LINK SET OR ORDER IS NOT CANONICAL: $page" >&2
    fail=1
  fi
  if [[ "$footer" != *"$expected_footer_logo"* ]]; then
    echo "FOOTER LOGO IS NOT THE BRAND V3 REVERSED LOCKUP: $page" >&2
    fail=1
  fi
  if [[ "$nav" != *"$expected_nav_logo"* ]]; then
    echo "NAV LOGO IS NOT THE BRAND V3 PRIMARY LOCKUP: $page" >&2
    fail=1
  fi
  if [[ "$footer" != *"$expected_legal_line"* ]]; then
    echo "FOOTER LEGAL LINE IS MISSING: $page" >&2
    fail=1
  fi

  favicon_links=$(awk '/<head>/{in_head = 1} in_head {print} /<\/head>/{exit}' "$page" | grep -E 'rel="(icon|apple-touch-icon|mask-icon)"' || true)
  if [[ -z "$favicon_links" ]]; then
    echo "NO FAVICON DECLARATIONS: $page" >&2
    fail=1
  elif printf '%s\n' "$favicon_links" | grep -vqF "?v=$favicon_version"; then
    echo "STALE FAVICON DECLARATION: $page" >&2
    fail=1
  fi

  if ! grep -Fq "<link rel=\"stylesheet\" href=\"styles.css?v=$stylesheet_version\" />" "$page"; then
    echo "STALE OR MISSING STYLESHEET CACHE KEY: $page" >&2
    fail=1
  fi

  if [[ -z "$ref_file" ]]; then
    ref_nav="$nav"
    ref_footer="$footer"
    ref_file="$page"
    continue
  fi

  if [[ "$nav" != "$ref_nav" ]]; then
    echo "NAV DIFFERS: $page vs $ref_file" >&2
    diff <(echo "$ref_nav") <(echo "$nav") >&2 || true
    fail=1
  fi
  if [[ "$footer" != "$ref_footer" ]]; then
    echo "FOOTER DIFFERS: $page vs $ref_file" >&2
    diff <(echo "$ref_footer") <(echo "$footer") >&2 || true
    fail=1
  fi
done

if ! grep -Fq "grid-template-columns: auto minmax(0, 1fr);" styles.css ||
   ! grep -Fq "grid-template-areas: 'logo links' 'logo meta';" styles.css ||
   ! grep -Fq "@media (max-width: 680px)" styles.css ||
   ! grep -Fq "grid-template-areas: 'logo' 'links' 'meta';" styles.css; then
  echo "FOOTER GRID OR MOBILE LAYOUT IS MISSING" >&2
  fail=1
fi

if [[ $fail -eq 0 ]]; then
  echo "OK: nav, canonical footer, stylesheet and favicon cache keys, and footer layout are consistent across ${#pages[@]} pages."
  exit 0
else
  exit 1
fi
