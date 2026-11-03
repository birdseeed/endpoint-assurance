/*
 * PAT-1100: testable billing v3 band-editor helpers.
 *
 * These are pure functions — no DOM — so Node's built-in test runner can
 * exercise the same validation and diff-summary logic the Console's rate
 * config panel uses. The server (main.py _validate_billing_bands) is the
 * authority on what actually gets persisted; this module exists so the
 * browser can validate/preview before it ever sends a PATCH, and so the
 * dangerConfirm() diff preview (PAT-799 pattern) has something sensible to
 * show for a banded structure instead of a flat scalar diff.
 */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleBilling = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  // Parse + validate one tier's raw band rows (as read off the DOM inputs,
  // still strings) into a normalized numeric band list. Mirrors the server's
  // _validate_billing_bands(): max_endpoints must be a strictly increasing
  // positive integer per row; monthly/advisory_hours must be >= 0.
  function parseBandRows(rawRows) {
    if (!Array.isArray(rawRows) || rawRows.length === 0) {
      return { ok: false, error: 'At least one band is required', bands: null };
    }
    var out = [];
    var prevMax = 0;
    for (var i = 0; i < rawRows.length; i++) {
      var row = rawRows[i] || {};
      var maxEndpoints = parseInt(row.max_endpoints, 10);
      var monthly = parseFloat(row.monthly);
      var advisoryHours = parseFloat(row.advisory_hours);
      if (!isFinite(maxEndpoints) || !isFinite(monthly) || !isFinite(advisoryHours)) {
        return { ok: false, error: 'Row ' + (i + 1) + ': all fields must be numbers', bands: null };
      }
      if (maxEndpoints <= prevMax) {
        return { ok: false, error: 'Row ' + (i + 1) + ': endpoint boundary must be greater than the previous band', bands: null };
      }
      if (monthly < 0 || advisoryHours < 0) {
        return { ok: false, error: 'Row ' + (i + 1) + ': monthly and advisory hours must be >= 0', bands: null };
      }
      out.push({ max_endpoints: maxEndpoints, monthly: monthly, advisory_hours: advisoryHours });
      prevMax = maxEndpoints;
    }
    return { ok: true, error: null, bands: out };
  }

  // Human-readable endpoint-range label for band `index` in a (validated,
  // ascending) band list — "1–25", "26–60", etc. Used as a read-only caption
  // next to the editable "Up to endpoints" boundary.
  function bandRangeLabel(bands, index) {
    if (!Array.isArray(bands) || !bands[index]) return '';
    var lower = index === 0 ? 1 : bands[index - 1].max_endpoints + 1;
    var upper = bands[index].max_endpoints;
    return lower + '–' + upper;
  }

  // Label for the implicit tail range above the top band, e.g. "251+".
  function tailRangeLabel(bands) {
    if (!Array.isArray(bands) || !bands.length) return '';
    return (bands[bands.length - 1].max_endpoints + 1) + '+';
  }

  function _bandsEqual(a, b) {
    return JSON.stringify(a) === JSON.stringify(b);
  }

  function _summarizeBands(bands) {
    if (!Array.isArray(bands) || !bands.length) return '(none)';
    var top = bands[bands.length - 1];
    return bands.length + ' band' + (bands.length === 1 ? '' : 's') + ', cap £' + top.monthly + ' at ' + top.max_endpoints + ' ep';
  }

  // Build dangerConfirm()-shaped diff rows { label, before, after } summarising
  // what changed between two v3 rate objects. Intentionally a summary, not a
  // full structural diff — a UX nicety, not load-bearing correctness.
  function buildRatesDiff(before, after) {
    before = before || {};
    after = after || {};
    var rows = [];
    var beforeBands = before.bands || {};
    var afterBands = after.bands || {};
    ['patch', 'full'].forEach(function(tier) {
      if (!_bandsEqual(beforeBands[tier], afterBands[tier])) {
        rows.push({
          label: tier === 'patch' ? 'Patch bands' : 'Full bands',
          before: _summarizeBands(beforeBands[tier]),
          after: _summarizeBands(afterBands[tier]),
        });
      }
    });
    var beforeTail = before.tail_rate_per_endpoint || {};
    var afterTail = after.tail_rate_per_endpoint || {};
    ['patch', 'full'].forEach(function(tier) {
      if (beforeTail[tier] !== afterTail[tier]) {
        rows.push({
          label: (tier === 'patch' ? 'Patch' : 'Full') + ' tail rate £/ep',
          before: beforeTail[tier],
          after: afterTail[tier],
        });
      }
    });
    if (before.annual_discount !== after.annual_discount) {
      rows.push({
        label: 'Annual discount ×',
        before: before.annual_discount,
        after: after.annual_discount,
      });
    }
    return rows;
  }

  return {
    parseBandRows: parseBandRows,
    bandRangeLabel: bandRangeLabel,
    tailRangeLabel: tailRangeLabel,
    buildRatesDiff: buildRatesDiff,
  };
});
