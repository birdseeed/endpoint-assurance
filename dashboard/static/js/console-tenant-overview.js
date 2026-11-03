/*
 * Pure helpers for the tenant Overview screen (PAT-1606), shared by the
 * browser console and Node tests -- same split as console-findings.js
 * (PAT-1607): this module owns the derivations, console.html keeps the
 * transport/DOM concerns.
 *
 * Covers three things:
 *   - deviceLifecycleCoverage: the six-bucket coverage-card breakdown from
 *     PAT-1595's GET /admin/tenants/{id}/device-lifecycle response.
 *   - unapprovedSummary: distinct-product / install counts from
 *     GET /admin/tenants/{id}/app-policy-drift's unapproved_present rows.
 *   - aggregateByKey / rankFindings: the "top findings" ranked list, built
 *     from whatever mix of CVE, CIS and unapproved-software rows the caller
 *     has already normalised into a common {key, count, ...} shape.
 */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleTenantOverview = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  // deviceLifecycleCoverage -- the coverage card's six buckets, computed from
  // PAT-1595's per-device `devices` array (each row carries `bucket`
  // normal|coverage_gap|untracked and `state`
  // reporting|quiet|stale|dormant|removed|never_seen).
  //
  // The ticket names exactly six buckets: reporting, quiet under threshold,
  // stale over threshold, on-list-never-seen, seen-not-on-list, and
  // dispositioned. The backend's six states don't map 1:1 -- it also has a
  // `bucket` dimension, and a `dormant` state PAT-1595 defined as a fourth,
  // further-aged tier of "stale". This function folds dormant into "stale
  // over threshold" for this card (a stale device is already the fact this
  // card needs to surface; the 45-day/89-day distinction between stale and
  // dormant is preserved unchanged in the raw device-lifecycle payload for
  // anyone who needs it, just not broken out as a seventh bucket here) and
  // resolves state vs bucket precedence deliberately:
  //
  //   1. state === 'never_seen'  -> "on their list, never seen"
  //      (always a coverage_gap-bucket device today, since ClassifyState only
  //      returns never_seen when neverSeen or lastSeen is nil.)
  //   2. state === 'removed'     -> "dispositioned" (always 0 today -- no
  //      caller sets activeDisposition yet, see PAT-1825).
  //   3. bucket === 'untracked'  -> "seen, not on their list", regardless of
  //      how fresh that device's own last-seen is. The artboard and ticket
  //      both want one count here, not this bucket split further by state.
  //   4. otherwise (bucket === 'normal', state reporting/quiet/stale/dormant)
  //      -> reporting / quiet / stale.
  //
  // Every device in the payload is routed to exactly one bucket by this
  // order, so `total` always equals `devices.length` exactly -- the
  // acceptance criterion that the six counts never round away a device.
  function deviceLifecycleCoverage(payload) {
    var devices = Array.isArray(payload && payload.devices) ? payload.devices : [];
    var reconciliation = (payload && payload.reconciliation) || {};
    var out = { reporting: 0, quiet: 0, stale: 0, neverSeen: 0, untracked: 0, dispositioned: 0 };
    devices.forEach(function(d) {
      if (!d) return;
      if (d.state === 'never_seen') { out.neverSeen++; return; }
      if (d.state === 'removed')    { out.dispositioned++; return; }
      if (d.bucket === 'untracked') { out.untracked++; return; }
      if (d.state === 'quiet')      { out.quiet++; return; }
      if (d.state === 'stale' || d.state === 'dormant') { out.stale++; return; }
      // 'reporting', and anything unrecognised, defaults to reporting only
      // if the device really is bucket 'normal' with no other signal --
      // otherwise it still needs a home, so count it as reporting rather
      // than silently dropping it out of the total.
      out.reporting++;
    });
    var total = out.reporting + out.quiet + out.stale + out.neverSeen + out.untracked + out.dispositioned;
    return {
      reporting: out.reporting,
      quiet: out.quiet,
      stale: out.stale,
      neverSeen: out.neverSeen,
      untracked: out.untracked,
      dispositioned: out.dispositioned,
      total: total,
      devicesTotal: devices.length,
      // Uploaded rows with no usable identifier at all (bad data in the
      // customer's own list) -- a data-quality note, not a seventh bucket.
      // Never folded into `total`: these aren't devices, they're malformed
      // list rows that Reconcile() could not even attempt to match.
      unmatchableCount: reconciliation.unmatchable_count || 0,
      hasUpload: !!(payload && payload.upload),
    };
  }

  // unapprovedSummary -- distinct-product and install counts from
  // GET /admin/tenants/{id}/app-policy-drift's findings array, filtered to
  // drift_type 'unapproved_present'. "Installs" is the finding count
  // (one row per device); "products" is the count of distinct
  // identifier-or-app_name values across those rows.
  function unapprovedSummary(driftFindings) {
    var rows = (Array.isArray(driftFindings) ? driftFindings : []).filter(function(f) {
      return f && f.drift_type === 'unapproved_present';
    });
    var seen = Object.create(null);
    rows.forEach(function(f) {
      var key = (f.identifier && String(f.identifier).toLowerCase()) ||
                (f.app_name && String(f.app_name).toLowerCase()) || '';
      if (key) seen[key] = true;
    });
    return { installs: rows.length, products: Object.keys(seen).length };
  }

  // aggregateByKey -- groups items sharing the same `key`, summing `count`
  // and keeping the first item's other fields. Used to collapse CIS's
  // per-device rows and app-policy-drift's per-device unapproved rows into
  // one row per rule / product before ranking.
  function aggregateByKey(items) {
    var map = Object.create(null);
    var order = [];
    (items || []).forEach(function(it) {
      if (!it || !it.key) return;
      if (!(it.key in map)) {
        var copy = {};
        for (var k in it) if (Object.prototype.hasOwnProperty.call(it, k)) copy[k] = it[k];
        copy.count = 0;
        map[it.key] = copy;
        order.push(it.key);
      }
      map[it.key].count += (it.count || 0);
    });
    return order.map(function(k) { return map[k]; });
  }

  // rankFindings -- sorts by count descending, takes the top `limit`, and
  // attaches magnitudePct (0-100, relative to the top item's own count in
  // this returned set, per rdx-bar-magnitude usage elsewhere in the
  // console). This is a display proportion, not a severity score.
  function rankFindings(items, limit) {
    limit = limit || 5;
    var sorted = (items || []).slice().sort(function(a, b) { return (b.count || 0) - (a.count || 0); });
    var top = sorted.slice(0, limit);
    var max = 0;
    top.forEach(function(i) { if ((i.count || 0) > max) max = i.count || 0; });
    return top.map(function(i) {
      var copy = {};
      for (var k in i) if (Object.prototype.hasOwnProperty.call(i, k)) copy[k] = i[k];
      copy.magnitudePct = max > 0 ? Math.round((i.count || 0) / max * 100) : 0;
      return copy;
    });
  }

  // magnitudeFillClass -- rdx-bar-magnitude-fill--{danger,warning,neutral}
  // modifier for a finding's severity. Unrecognised/absent severity (e.g.
  // an unapproved-software row, which has no CVSS/CIS severity concept)
  // gets the neutral treatment rather than a fabricated danger/warning.
  function magnitudeFillClass(severity) {
    var s = String(severity || '').toLowerCase();
    if (s === 'critical' || s === 'high') return 'rdx-bar-magnitude-fill--danger';
    if (s === 'medium') return 'rdx-bar-magnitude-fill--warning';
    return 'rdx-bar-magnitude-fill--neutral';
  }

  return {
    deviceLifecycleCoverage: deviceLifecycleCoverage,
    unapprovedSummary: unapprovedSummary,
    aggregateByKey: aggregateByKey,
    rankFindings: rankFindings,
    magnitudeFillClass: magnitudeFillClass,
  };
});
