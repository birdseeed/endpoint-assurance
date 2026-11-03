/*
 * PAT-1103: testable band-drift display helpers for the Billing table and
 * the renewals panel.
 *
 * Pure functions — no DOM — so Node's built-in test runner can exercise the
 * same formatting logic the Console uses. The server (main.py
 * _tenant_band_drift / GET /admin/billing/drift / GET /admin/billing/
 * renewals) is the authority on direction/headroom/streak; this module only
 * formats what it's given for display. Advisory-only surface: nothing here
 * ever writes anything, it only renders what the server already computed.
 */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleDrift = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  // Compact directional glyph for a drift badge. 'none' (still within the
  // band the contract was signed at) gets a neutral dot, never an arrow —
  // an arrow implies movement that isn't actually happening.
  function driftArrow(direction) {
    if (direction === 'above') return '▲'; // ▲
    if (direction === 'below') return '▼'; // ▼
    return '•'; // •
  }

  // CSS modifier suffix for the badge/row — 'above' | 'below' | 'none'.
  // Falls back to 'none' for any unrecognised value so a malformed/missing
  // direction never crashes the render, it just reads as non-drifting.
  function driftBadgeClass(direction) {
    if (direction === 'above') return 'above';
    if (direction === 'below') return 'below';
    return 'none';
  }

  // Human label for the endpoints-of-room-left figure. `headroom` is null
  // when the tenant is already in tail territory drifting further up (no
  // ceiling to measure against) — rendered as "no ceiling", never as "0" or
  // blank, both of which would misread as "right at the edge".
  function driftHeadroomLabel(headroom) {
    if (headroom === null || headroom === undefined) return 'no ceiling';
    var n = Number(headroom);
    if (!isFinite(n)) return '';
    return n + ' to edge';
  }

  // Human label for consecutive months drifted in the current direction.
  // 0 (or missing) renders as '' — a fresh/non-drifting tenant shouldn't
  // show a "0 months" badge, it should show nothing.
  function driftStreakLabel(months) {
    var n = Number(months) || 0;
    if (n <= 0) return '';
    return n + ' mo' + (n === 1 ? '' : 's');
  }

  return {
    driftArrow: driftArrow,
    driftBadgeClass: driftBadgeClass,
    driftHeadroomLabel: driftHeadroomLabel,
    driftStreakLabel: driftStreakLabel,
  };
});
