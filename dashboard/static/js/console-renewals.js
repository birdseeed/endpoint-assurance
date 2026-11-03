/*
 * PAT-1101: testable renewal-view helpers for the Billing section.
 *
 * Pure functions — no DOM — so Node's built-in test runner can exercise the
 * same classification/formatting logic the Console's renewals panel uses.
 * The server (main.py api_billing_renewals) is the authority on which
 * tenants are in the 60-day window and what their contracted-vs-current
 * figures are; this module only formats what it's given for display.
 */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleRenewals = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  // Renewal urgency class for row styling. Overdue (already past the
  // renewal date) is deliberately its own state, never merged into "soon" —
  // the whole point of PAT-1101's renewal view is that an overdue renewal
  // is MORE visible than an upcoming one, not folded away.
  function classifyRenewal(daysUntilRenewal) {
    // Non-author review finding: Number(null) is 0, not NaN — a missing/null
    // field must not silently masquerade as "0 days until renewal" (the
    // most urgent classification). Reject null/undefined explicitly before
    // the numeric coercion, not just non-finite results.
    if (daysUntilRenewal === null || daysUntilRenewal === undefined) return 'unknown';
    var n = Number(daysUntilRenewal);
    if (!isFinite(n)) return 'unknown';
    if (n < 0) return 'overdue';
    if (n <= 14) return 'soon';
    return 'upcoming';
  }

  // Human label for the renewal countdown, e.g. "23 days", "today",
  // "overdue by 5 days".
  function renewalDaysLabel(daysUntilRenewal) {
    // Same Number(null) === 0 trap as classifyRenewal — a missing field must
    // not render as the misleadingly precise "today".
    if (daysUntilRenewal === null || daysUntilRenewal === undefined) return '';
    var n = Number(daysUntilRenewal);
    if (!isFinite(n)) return '';
    if (n === 0) return 'today';
    if (n > 0) return n + ' day' + (n === 1 ? '' : 's');
    var overdue = Math.abs(n);
    return 'overdue by ' + overdue + ' day' + (overdue === 1 ? '' : 's');
  }

  // Sign-prefixed GBP string for a delta (current-band minus contracted),
  // e.g. "+£120.00", "-£45.00", "£0.00". Never hides the sign on zero so a
  // flat delta reads as deliberately flat, not as a missing value.
  function formatDeltaGbp(delta) {
    var n = Number(delta) || 0;
    var sign = n > 0 ? '+' : (n < 0 ? '-' : '');
    var abs = Math.abs(n).toLocaleString('en-GB', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    return sign + '£' + abs;
  }

  // CSS modifier for the delta chip: 'up' (current band would bill more —
  // the underpriced-legacy-contract case), 'down' (would bill less), or
  // 'flat' (no drift at all).
  function deltaClass(delta) {
    var n = Number(delta) || 0;
    if (n > 0) return 'up';
    if (n < 0) return 'down';
    return 'flat';
  }

  return {
    classifyRenewal: classifyRenewal,
    renewalDaysLabel: renewalDaysLabel,
    formatDeltaGbp: formatDeltaGbp,
    deltaClass: deltaClass,
  };
});
