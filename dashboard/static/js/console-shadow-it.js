(function(root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.PatchedConsoleShadowIT = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  var CATEGORY_LABELS = {
    gaming: 'Gaming', p2p: 'P2P', remote_access: 'Remote access',
    consumer_cloud: 'Consumer cloud', crypto: 'Crypto', ai_unapproved: 'AI tools',
    policy: 'Policy'
  };

  function text(value) { return String(value == null ? '' : value).trim(); }
  function lower(value) { return text(value).toLowerCase(); }
  function identity(row) {
    var identifier = lower(row && row.identifier);
    return identifier ? 'id:' + identifier : 'name:' + lower(row && (row.app_name || row.shadow_it_name));
  }
  function maxTime(a, b) {
    if (!a) return b || null;
    if (!b) return a;
    return new Date(a).getTime() >= new Date(b).getTime() ? a : b;
  }
  function minTime(a, b) {
    if (!a) return b || null;
    if (!b) return a;
    return new Date(a).getTime() <= new Date(b).getTime() ? a : b;
  }

  function merge(driftFindings, catalogueFindings, exceptions) {
    var groups = {};
    function ensure(key, row) {
      if (!groups[key]) {
        groups[key] = {
          key: key, name: text(row.app_name || row.shadow_it_name) || 'Unknown application',
          identifier: text(row.identifier), category: row.category || 'policy', label: row.shadow_it_label || '',
          sources: [], machines: [], policy: 'review', firstSeen: null, lastSeen: null,
          reason: '', actor: '', claimedActor: '', policyUpdatedAt: null
        };
      }
      return groups[key];
    }
    function addSource(group, source) {
      if (group.sources.indexOf(source) === -1) group.sources.push(source);
    }
    function addMachine(group, row) {
      var id = text(row.device_id);
      if (!id) return;
      var existing = group.machines.find(function(m) { return m.deviceId === id && m.identifier === text(row.identifier); });
      if (!existing) {
        group.machines.push({
          deviceId: id, hostname: text(row.hostname) || id, identifier: text(row.identifier),
          appName: text(row.app_name), firstSeen: row.first_seen || null,
          lastSeen: row.last_seen || row.device_last_seen || null
        });
      } else {
        existing.firstSeen = minTime(existing.firstSeen, row.first_seen);
        existing.lastSeen = maxTime(existing.lastSeen, row.last_seen || row.device_last_seen);
      }
    }

    (driftFindings || []).filter(function(row) { return row.drift_type === 'unapproved_present'; }).forEach(function(row) {
      var group = ensure(identity(row), row);
      addSource(group, 'policy');
      group.policy = 'unapproved';
      group.category = group.category === 'policy' ? 'policy' : group.category;
      group.lastSeen = maxTime(group.lastSeen, row.device_last_seen);
      addMachine(group, row);
    });

    (catalogueFindings || []).forEach(function(row) {
      var group = ensure(identity(row), row);
      addSource(group, 'catalogue');
      group.label = row.shadow_it_label || group.label;
      group.category = row.category || group.category;
      group.firstSeen = minTime(group.firstSeen, row.first_seen);
      group.lastSeen = maxTime(group.lastSeen, row.last_seen);
      group.reason = text(row.reason) || group.reason;
      group.actor = text(row.actor) || group.actor;
      group.claimedActor = text(row.claimed_actor) || group.claimedActor;
      group.policyUpdatedAt = row.policy_updated_at || group.policyUpdatedAt;
      if (row.policy === 'allow') group.policy = 'exception';
      addMachine(group, row);
    });

    (exceptions || []).forEach(function(row) {
      var matching = Object.values(groups).find(function(group) { return group.label && group.label === row.shadow_it_label; });
      var group = matching || ensure('exception:' + lower(row.shadow_it_label), row);
      addSource(group, 'catalogue');
      group.policy = 'exception';
      group.label = row.shadow_it_label || group.label;
      group.category = row.category || group.category;
      group.reason = text(row.reason);
      group.actor = text(row.actor);
      group.claimedActor = text(row.claimed_actor);
      group.policyUpdatedAt = row.updated_at || group.policyUpdatedAt;
    });

    return Object.values(groups).map(function(group) {
      group.sources.sort();
      group.machines.sort(function(a, b) { return a.hostname.localeCompare(b.hostname); });
      return group;
    }).sort(function(a, b) {
      var policyRank = { unapproved: 0, review: 1, exception: 2 };
      return policyRank[a.policy] - policyRank[b.policy] || a.name.localeCompare(b.name);
    });
  }

  function filter(items, options) {
    options = options || {};
    var query = lower(options.query);
    var category = options.category || 'all';
    var source = options.source || 'all';
    var view = options.view || 'needs';
    return (items || []).filter(function(item) {
      if (view === 'exceptions' ? item.policy !== 'exception' : item.policy === 'exception') return false;
      if (category !== 'all' && item.category !== category) return false;
      if (source !== 'all' && item.sources.indexOf(source) === -1) return false;
      if (!query) return true;
      var machineText = item.machines.map(function(machine) { return machine.hostname + ' ' + machine.deviceId; }).join(' ');
      return lower(item.name + ' ' + item.identifier + ' ' + item.label + ' ' + machineText).indexOf(query) !== -1;
    });
  }

  function summary(items) {
    var devices = {};
    var needs = 0;
    var exceptions = 0;
    (items || []).forEach(function(item) {
      if (item.policy === 'exception') exceptions++;
      else {
        needs++;
        item.machines.forEach(function(machine) { devices[machine.deviceId] = true; });
      }
    });
    return { needs: needs, devices: Object.keys(devices).length, exceptions: exceptions };
  }

  function emptyState(context) {
    context = context || {};
    if (context.deviceCount === 0) return { title: 'No endpoint inventory', detail: 'Shadow IT needs installed-software inventory from at least one machine.' };
    if (context.filtered) return { title: 'No results match these filters', detail: 'Clear the filters to return to all current Shadow IT evidence.' };
    if (context.view === 'exceptions') return { title: 'No exceptions recorded', detail: 'Allowed catalogue matches will remain visible here so they can be reviewed or reversed.' };
    if (context.policyCount === 0 && context.catalogueMatchCount === 0) return { title: 'No unapproved policy is configured', detail: 'No risk-catalogue matches were found either. This is not proof that every installed application is approved.' };
    return { title: 'No current Shadow IT findings', detail: 'The latest inventory contains no installed software matching an unapproved policy or the risk catalogue.' };
  }

  function categoryLabel(category) { return CATEGORY_LABELS[category] || text(category).replace(/_/g, ' '); }

  return { identity: identity, merge: merge, filter: filter, summary: summary, emptyState: emptyState, categoryLabel: categoryLabel };
});
