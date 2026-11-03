/* PAT-2374: read projections only. No permissions or lifecycle authority. */
(function(root, factory) {
  var api = factory();
  root.PatchedTenantLifecycle = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';
  function count(value) { return Number.isSafeInteger(value) && value >= 0 ? value : null; }
  function devices(value) {
    var n = count(value);
    return n === null ? 'Device count unknown' : n + ' device' + (n === 1 ? '' : 's');
  }
  function reporting(value) {
    var n = count(value);
    return (n === null ? 'Reporting count unknown' : n + ' reporting') + ' in the last 7 days';
  }
  function healthBucket(row) {
    if (['healthy', 'watch', 'at_risk'].indexOf(row.health_bucket) !== -1) return row.health_bucket;
    var pct = row.compliance_pct;
    if (typeof pct !== 'number' || !Number.isFinite(pct) || pct < 0 || pct > 100) return 'unknown';
    return pct >= 75 ? 'healthy' : pct >= 50 ? 'watch' : 'at_risk';
  }
  function collection(data, key, source) {
    var rows = key ? data && data[key] : data;
    if (!Array.isArray(rows) || rows.some(function(row) { return !row || typeof row !== 'object' || Array.isArray(row); })) {
      throw new Error(source + ' unavailable: invalid response');
    }
    return rows;
  }
  // Epoch rejects A -> B -> A and navigation away; sequence rejects an older
  // refresh of the same source. Success and failure use the identical gate.
  function readScope() {
    var tenant = null, epoch = 0, serial = 0, latest = Object.create(null);
    return {
      context: function(id) {
        if (tenant === id) return false;
        tenant = id; epoch++; latest = Object.create(null); return true;
      },
      begin: function(key, id) {
        var token = { key: key, tenant: id, epoch: epoch, serial: ++serial };
        latest[key] = token.serial; return token;
      },
      owns: function(token, current) {
        return !!token && token.tenant === current && tenant === current &&
          token.epoch === epoch && latest[token.key] === token.serial;
      }
    };
  }
  return { healthBucket: healthBucket, count: count, devices: devices, reporting: reporting, collection: collection, readScope: readScope };
});
