/* PAT-1372: pure Operational Truth presentation helpers for browser and Node. */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleTruth = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  var STATE = {
    red: { key: 'red', label: 'Action required', rank: 0 },
    amber: { key: 'amber', label: 'Evidence missing', rank: 1 },
    green: { key: 'green', label: 'Verified', rank: 2 },
    /* PAT-1342: a manifest entry whose job was deliberately decommissioned
       (truth.py's `retired` block) -- distinct from amber ("nobody has
       wired a collector for this yet") so a retired job never reads as an
       unresolved evidence gap. Ranked last: lower attention than even a
       verified check, but still listed, never dropped. */
    quarantined: { key: 'quarantined', label: 'Quarantined', rank: 3 },
    retired: { key: 'retired', label: 'Retired', rank: 4 }
  };

  function state(value) {
    return STATE[String(value || '').toLowerCase()] || STATE.amber;
  }

  function normalize(check, index) {
    check = check && typeof check === 'object' ? check : {};
    var mapped = state(check.state);
    return {
      index: index,
      id: String(check.id || ''),
      name: String(check.name || check.id || 'Unnamed check'),
      scope: String(check.scope || 'Unknown scope'),
      proves: String(check.proves || ''),
      notes: String(check.notes || ''),
      reason: String(check.reason || 'No evidence detail was returned.'),
      lastSignalAt: String(check.last_signal_at || ''),
      state: mapped.key,
      stateLabel: mapped.label,
      stateRank: mapped.rank
    };
  }

  function prepare(checks) {
    return (Array.isArray(checks) ? checks : []).map(normalize).sort(function(a, b) {
      return a.stateRank - b.stateRank || a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
    });
  }

  function filter(rows, options) {
    options = options || {};
    var query = String(options.query || '').trim().toLowerCase();
    var selectedState = String(options.state || 'all');
    var selectedScope = String(options.scope || 'all');
    return (rows || []).filter(function(row) {
      if (selectedState !== 'all' && row.state !== selectedState) return false;
      if (selectedScope !== 'all' && row.scope !== selectedScope) return false;
      if (!query) return true;
      return [row.name, row.id, row.scope, row.reason, row.proves, row.notes].join(' ').toLowerCase().indexOf(query) !== -1;
    });
  }

  function scopes(rows) {
    var found = {};
    (rows || []).forEach(function(row) { found[row.scope] = true; });
    return Object.keys(found).sort(function(a, b) { return a.localeCompare(b, undefined, { sensitivity: 'base' }); });
  }

  function summary(rows) {
    var result = { red: 0, amber: 0, green: 0, quarantined: 0, retired: 0, total: (rows || []).length };
    (rows || []).forEach(function(row) { result[state(row.state).key]++; });
    return result;
  }

  function concise(value, maxLength) {
    var text = String(value || '').replace(/\s+/g, ' ').trim();
    var limit = Number(maxLength || 150);
    return text.length > limit ? text.slice(0, Math.max(0, limit - 1)).trimEnd() + '…' : text;
  }

  return { state: state, normalize: normalize, prepare: prepare, filter: filter, scopes: scopes, summary: summary, concise: concise };
});
