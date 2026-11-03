(function(root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.PatchedConsoleEnforcement = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  var META = {
    admin_removed: {
      action: 'Administrator removed', category: 'administrator', outcome: 'completed', outcomeLabel: 'Completed'
    },
    admin_removal_skipped: {
      action: 'Administrator removal', category: 'administrator', outcome: 'skipped', outcomeLabel: 'Skipped'
    },
    app_blocked: {
      action: 'Application blocked', category: 'application', outcome: 'completed', outcomeLabel: 'Completed'
    },
    app_block_skipped: {
      action: 'Application block', category: 'application', outcome: 'skipped', outcomeLabel: 'Skipped'
    },
    extension_blocklist_pushed: {
      action: 'Extension blocklist applied', category: 'extension', outcome: 'completed', outcomeLabel: 'Completed'
    },
    extension_removed: {
      action: 'Browser extension removed', category: 'extension', outcome: 'completed', outcomeLabel: 'Completed'
    }
  };

  function meta(eventType) {
    return META[eventType] || {
      action: 'Endpoint enforcement event', category: 'other', outcome: 'recorded', outcomeLabel: 'Recorded'
    };
  }

  function eventTypes(category, outcome) {
    return Object.keys(META).filter(function(eventType) {
      var item = META[eventType];
      return (!category || category === 'all' || item.category === category) &&
        (!outcome || outcome === 'all' || item.outcome === outcome);
    });
  }

  function details(event) {
    var raw = event && event.details;
    var value = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
    var preferred = ['reason', 'method', 'browser', 'profile', 'user_account', 'scope', 'detail', 'result'];
    var keys = preferred.filter(function(key) { return value[key] !== undefined && value[key] !== null && value[key] !== ''; });
    Object.keys(value).sort().forEach(function(key) {
      if (keys.indexOf(key) === -1 && value[key] !== undefined && value[key] !== null && value[key] !== '') keys.push(key);
    });
    return keys.map(function(key) {
      var item = value[key];
      if (typeof item === 'object') item = JSON.stringify(item);
      return { key: key.replace(/_/g, ' '), value: String(item) };
    });
  }

  function detailSummary(event) {
    var rows = details(event);
    if (!rows.length) return 'No additional detail';
    return rows.slice(0, 2).map(function(row) { return row.key + ': ' + row.value; }).join(' · ');
  }

  return { meta: meta, eventTypes: eventTypes, details: details, detailSummary: detailSummary };
});
