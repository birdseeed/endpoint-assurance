#!/usr/bin/env bash
set -euo pipefail
# Brand guard — scans shippable source for copy/font/asset violations.
# Docs (*.md) are intentionally excluded: they quote forbidden terms as
# negative examples. Only source files that produce shipping artefacts are checked.
ALL=$(git ls-files | grep -Ev '^(vendor/|third_party/|.*\.lock|dist/|build/|engine/|menubar/design/|windows/design/|scripts/brand-guard\.sh)')
# Source code only: Swift, C#, XAML, shell, Python, JS/TS
SRC=$(printf '%s\n' "$ALL" | grep -E '\.(swift|cs|xaml|sh|py|js|ts|jsx|tsx)$')
fail=0
check() { # pattern, message
  local hits
  hits=$(printf '%s\n' "$SRC" | xargs -I{} grep -InE "$1" {} 2>/dev/null || true)
  if [ -n "$hits" ]; then echo "BRAND GUARD: $2"; echo "$hits"; fail=1; fi
}
check '\bfleet\b'                 'Use "estate", never "fleet".'
check 'endpoints? closed'         'Metric is "apps patched", not "endpoints closed".'
check 'patched\.io'               'Domain is patched.im, not patched.io.'
check '(closing|open) front'      'Use patching/unpatched language for the posture gauge.'
# Native Swift UI must use the system font — Archivo only in the logo lockup.
SWIFT=$(printf '%s\n' "$SRC" | grep -E '\.swift$' | grep -v 'BrandTokens\.swift')
font_hits=$(printf '%s\n' "$SWIFT" | xargs -I{} grep -InE 'font-family:[^;]*(Archivo|Inter|JetBrains)' {} 2>/dev/null || true)
if [ -n "$font_hits" ]; then echo "BRAND GUARD: Native agent UI must use the OS system font; brand webfonts only in the logo lockup (BrandTokens.swift)."; echo "$font_hits"; fail=1; fi
# Pixel-P must not be used in agent UI — ring mark only (pixel-P is marketing-only).
# Check for PixelMarkView references in Swift files other than its own definition.
pixelmark_uses=$(printf '%s\n' "$SWIFT" | grep -v 'PixelMark\.swift' | xargs -I{} grep -lE '\bPixelMarkView\b' {} 2>/dev/null || true)
if [ -n "$pixelmark_uses" ]; then echo "BRAND GUARD: PixelMarkView referenced in agent UI — replace with RingMarkView (pixel-P is marketing-only)."; echo "$pixelmark_uses"; fail=1; fi
# Self-service panel must not use deprecated posture/deep-link terms.
check 'endpoints? (open|closing)'  'Self-service panel: use patched / patching / unpatched.'
check '"Open Posture"'             'Self-service deep-link label is "Open Self Service".'
[ "$fail" -eq 0 ] && echo "brand-guard: OK"
exit "$fail"
