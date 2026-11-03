(function(root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.PatchedConsoleMetering = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  function platform(app) {
    var value = String(app && app.platform || '').toLowerCase();
    if (value.indexOf('win') !== -1) return 'windows';
    if (value.indexOf('mac') !== -1 || value.indexOf('darwin') !== -1) return 'macos';
    return 'unknown';
  }

  var HEALTH_REASONS = {
    spotlight_disabled: 'Spotlight indexing disabled',
    no_user_session: 'No console user session'
  };

  // collectionHealth — normalises the API's per-app metering_status into the
  // four-value rollup the UI reasons about. 'ok' means at least one device's
  // usage evidence is trustworthy; anything else means Patched cannot vouch
  // for the absence of use it would otherwise report as 'never'.
  function collectionHealth(app) {
    var status = app && app.metering_status;
    if (status === 'ok') return 'ok';
    if (status === 'mixed') return 'mixed';
    if (status === null || status === undefined || status === '' || status === 'unknown') return 'unknown';
    return 'degraded';
  }

  // healthReason — short human label for why usage evidence is absent.
  // Returns '' when health is 'ok' (nothing to explain).
  function healthReason(app) {
    var health = collectionHealth(app);
    if (health === 'ok') return '';
    if (health === 'unknown') return 'No collection reported';
    if (health === 'mixed') return 'Mixed across devices';
    var status = String(app && app.metering_status || '');
    if (HEALTH_REASONS[status]) return HEALTH_REASONS[status];
    var readable = status.replace(/_/g, ' ');
    return readable.charAt(0).toUpperCase() + readable.slice(1);
  }

  function usageState(app, threshold) {
    var days = app && app.days_since_last_use;
    var launches = app && app.total_launch_count;
    if (launches === null || launches === undefined) return 'unavailable';
    if (days === null || days === undefined) {
      if (Number(launches) === 0) {
        return collectionHealth(app) === 'ok' ? 'never' : 'unavailable';
      }
      return 'unavailable';
    }
    return Number(days) >= Number(threshold) ? 'unused' : 'active';
  }

  function matchesView(app, view, threshold) {
    var state = usageState(app, threshold);
    if (view === 'reclaim') return state === 'unused' || state === 'never';
    if (view === 'gaps') return state === 'unavailable';
    return true;
  }

  function filter(apps, options) {
    options = options || {};
    var query = String(options.query || '').trim().toLowerCase();
    var selectedPlatform = options.platform || 'all';
    var threshold = Number(options.threshold || 30);
    var view = options.view || 'reclaim';
    return (apps || []).filter(function(app) {
      var haystack = String(app.name || '') + ' ' + String(app.id || '');
      if (query && haystack.toLowerCase().indexOf(query) === -1) return false;
      if (selectedPlatform !== 'all' && platform(app) !== selectedPlatform) return false;
      return matchesView(app, view, threshold);
    });
  }

  function summary(apps, threshold) {
    var result = { installed: (apps || []).length, unused: 0, never: 0, unavailable: 0 };
    (apps || []).forEach(function(app) {
      var state = usageState(app, threshold || 30);
      if (state === 'unused') result.unused++;
      else if (state === 'never') result.never++;
      else if (state === 'unavailable') result.unavailable++;
    });
    return result;
  }

  function sort(apps, field, ascending, threshold) {
    return (apps || []).slice().sort(function(a, b) {
      var av, bv;
      if (field === 'name') {
        av = String(a.name || a.id || '').toLowerCase();
        bv = String(b.name || b.id || '').toLowerCase();
      } else if (field === 'launches') {
        av = a.total_launch_count == null ? -1 : Number(a.total_launch_count);
        bv = b.total_launch_count == null ? -1 : Number(b.total_launch_count);
      } else if (field === 'devices') {
        av = Number(a.device_count || 0);
        bv = Number(b.device_count || 0);
      } else if (field === 'state') {
        var rank = { unused: 4, never: 3, unavailable: 2, active: 1 };
        av = rank[usageState(a, threshold)];
        bv = rank[usageState(b, threshold)];
      } else {
        var stateRank = { never: 100000, unavailable: -1 };
        av = a.days_since_last_use == null ? (stateRank[usageState(a, threshold)] || -1) : Number(a.days_since_last_use);
        bv = b.days_since_last_use == null ? (stateRank[usageState(b, threshold)] || -1) : Number(b.days_since_last_use);
      }
      if (av < bv) return ascending ? -1 : 1;
      if (av > bv) return ascending ? 1 : -1;
      return String(a.name || '').localeCompare(String(b.name || ''));
    });
  }

  return {
    platform: platform,
    usageState: usageState,
    collectionHealth: collectionHealth,
    healthReason: healthReason,
    matchesView: matchesView,
    filter: filter,
    summary: summary,
    sort: sort
  };
});
