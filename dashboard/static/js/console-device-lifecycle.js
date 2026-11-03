/*
 * Pure helpers for the Coverage console screen (PAT-1830), following
 * PAT-1607/PAT-1609/PAT-1612's split: this module owns the derivations,
 * console.html keeps the transport/DOM concerns.
 *
 * Backs GET /admin/tenants/{id}/device-lifecycle (PAT-1595, already proxied
 * for Device Health/Findings/Disposition Queue -- see go-service's
 * internal/handlers/device_lifecycle.go and internal/devicelifecycle/
 * reconcile.go). This is the first screen to render the FULL response --
 * every device in every bucket, not just one derived slice of it (the
 * Disposition Queue only ever shows bucket=normal, state in
 * quiet/stale/dormant -- see console-disposition-queue.js's own header).
 *
 * The endpoint computes on every call and keeps no cached snapshot (see the
 * Go handler's own doc comment) -- computed_at is shown so staff know how
 * fresh the figures are, never implied to be a stored report.
 */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleDeviceLifecycle = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  var STATE_LABELS = {
    reporting: 'Reporting',
    quiet: 'Quiet',
    stale: 'Stale',
    dormant: 'Dormant',
    removed: 'Removed (dispositioned)',
    never_seen: 'Never seen'
  };

  var BUCKET_LABELS = {
    normal: 'Normal',
    coverage_gap: 'Coverage gap',
    untracked: 'Untracked'
  };

  // Fixed, meaningful order for the reconciliation cards: the healthy case
  // first, then the two gap types the customer's device list and the
  // agent's own evidence disagree about.
  var BUCKET_ORDER = ['normal', 'coverage_gap', 'untracked'];

  function stateLabel(state) { return STATE_LABELS[state] || String(state || ''); }
  function bucketLabel(bucket) { return BUCKET_LABELS[bucket] || String(bucket || ''); }

  // bucketCards -- the three reconciliation counts in BUCKET_ORDER, each
  // carrying the label and the count the platform itself reported. Never
  // recomputed by counting devices[] client-side -- reconciliation is the
  // platform's own authoritative tally and the two must not be able to
  // silently disagree because of a client-side filtering bug.
  function bucketCards(reconciliation) {
    var r = reconciliation || {};
    return BUCKET_ORDER.map(function(key) {
      return { key: key, label: bucketLabel(key), count: r[key + '_count'] || 0 };
    });
  }

  // thresholdSummary -- plain-text description of the three day thresholds
  // the reconciliation was computed against (read-only in this screen --
  // editing them is a separate ticket, see PAT-1830's brief).
  function daysText(n) {
    return n + ' day' + (n === 1 ? '' : 's');
  }

  function thresholdSummary(thresholds) {
    var t = thresholds || {};
    var quiet = t.quiet_days != null ? daysText(t.quiet_days) : 'an unknown number of days';
    var stale = t.stale_days != null ? daysText(t.stale_days) : 'an unknown number of days';
    var dormant = t.dormant_days != null ? daysText(t.dormant_days) : 'an unknown number of days';
    return 'Quiet after ' + quiet + ', stale after ' + stale + ', dormant after ' + dormant + '.';
  }

  // stateOptionsForBucket -- which state values are ever meaningful for a
  // given bucket, for building the state filter's options. A coverage_gap
  // device has no observed row to classify beyond "never seen" (see the
  // module header) -- never offer a state option that bucket can't produce.
  function stateOptionsForBucket(bucket) {
    if (bucket === 'coverage_gap') return ['never_seen'];
    if (bucket === 'all') return ['reporting', 'quiet', 'stale', 'dormant', 'removed', 'never_seen'];
    return ['reporting', 'quiet', 'stale', 'dormant', 'removed'];
  }

  // filterDevices -- bucket ('all' or a bucket key), state ('all' or a state
  // key) and a free-text search matched case-insensitively against
  // hostname, external_id and device_id. Any of the three may be omitted.
  function filterDevices(devices, opts) {
    opts = opts || {};
    var bucket = opts.bucket || 'all';
    var state = opts.state || 'all';
    var q = String(opts.search || '').trim().toLowerCase();
    return (devices || []).filter(function(d) {
      if (bucket !== 'all' && d.bucket !== bucket) return false;
      if (state !== 'all' && d.state !== state) return false;
      if (q) {
        var hay = [d.hostname, d.external_id, d.device_id].filter(Boolean).join(' ').toLowerCase();
        if (hay.indexOf(q) === -1) return false;
      }
      return true;
    });
  }

  // sortDevicesByLastSeen -- oldest last_seen first by default (most overdue
  // for attention at the top, same convention as the Disposition Queue's
  // sortQueueDevices). A device with no last_seen at all (coverage-gap,
  // never_seen) sorts last regardless of direction -- there is nothing to
  // prioritise about a device with no evidence (absence requires authority).
  // dir: 'asc' (default, oldest first) or 'desc' (most recently seen first).
  function sortDevicesByLastSeen(devices, dir) {
    var mult = dir === 'desc' ? -1 : 1;
    // A malformed (not just absent) last_seen -- Date#getTime() returns NaN,
    // not null -- must fall into the same "nothing to prioritise" tail as a
    // genuinely missing one, or NaN arithmetic below produces an unstable
    // sort order instead of a clean fallback.
    function ts(d) {
      if (!d.last_seen) return null;
      var t = new Date(d.last_seen).getTime();
      return isNaN(t) ? null : t;
    }
    return (devices || []).slice().sort(function(a, b) {
      var la = ts(a);
      var lb = ts(b);
      if (la === null && lb === null) return 0;
      if (la === null) return 1;
      if (lb === null) return -1;
      return (la - lb) * mult;
    });
  }

  // emptyState -- distinguishes an empty devices[] because no device list
  // has ever been uploaded (upload === null -- absence requires authority,
  // an empty table here proves nothing) from a genuinely empty reconciliation
  // on a tenant that has uploaded a list and has no agent evidence either.
  // Returns null when devices[] is non-empty (no empty state to show).
  function emptyState(lifecycle) {
    var devices = (lifecycle && Array.isArray(lifecycle.devices)) ? lifecycle.devices : [];
    if (devices.length > 0) return null;
    return (lifecycle && lifecycle.upload) ? 'no_devices' : 'never_uploaded';
  }

  return {
    STATE_LABELS: STATE_LABELS,
    BUCKET_LABELS: BUCKET_LABELS,
    BUCKET_ORDER: BUCKET_ORDER,
    stateLabel: stateLabel,
    bucketLabel: bucketLabel,
    bucketCards: bucketCards,
    thresholdSummary: thresholdSummary,
    stateOptionsForBucket: stateOptionsForBucket,
    filterDevices: filterDevices,
    sortDevicesByLastSeen: sortDevicesByLastSeen,
    emptyState: emptyState
  };
});
