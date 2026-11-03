/*
 * Pure Reports workspace helpers shared by the browser console and Node tests.
 * The UI keeps transport and DOM concerns in console.html; this module owns the
 * truthful labels, summary counts and combined-history ordering.
 */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleReports = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  function deliveryState(value) {
    var state = String(value || '').toLowerCase();
    if (state === 'sent' || state === 'delivered') return { key: 'sent', label: 'Sent' };
    if (state === 'failed' || state === 'error') return { key: 'failed', label: 'Failed' };
    if (state === 'pending' || state === 'generated') return { key: 'not-sent', label: 'Not sent' };
    return { key: 'unknown', label: 'Unknown' };
  }

  function artifactState(record) {
    if (record && record.id) return { key: 'ready', label: 'Ready' };
    return { key: 'recorded', label: 'Recorded' };
  }

  function newestTimestamp(row) {
    return row.createdAt || '';
  }

  function combineHistory(records, deliveries) {
    var normalized = [];
    (records || []).forEach(function(record) {
      normalized.push({
        kind: 'record',
        id: record.id || '',
        name: record.name || 'Evidence report',
        createdAt: record.generated_at || '',
        periodStart: record.period_start || '',
        periodEnd: record.period_end || '',
        artifact: artifactState(record),
        delivery: deliveryState(record.delivery_status),
        recipient: record.recipient || '',
      });
    });
    (deliveries || []).forEach(function(delivery) {
      normalized.push({
        kind: 'delivery',
        id: delivery.id || '',
        name: delivery.report_type || 'Report delivery',
        createdAt: delivery.sent_at || delivery.generated_at || '',
        periodStart: '',
        periodEnd: '',
        artifact: { key: 'recorded', label: 'Recorded' },
        delivery: deliveryState(delivery.status),
        recipient: delivery.recipient || '',
      });
    });
    return normalized.sort(function(a, b) {
      return newestTimestamp(b).localeCompare(newestTimestamp(a));
    });
  }

  function summary(catalog, schedules, records, deliveries) {
    var types = Array.isArray(catalog) ? catalog : [];
    var namedSchedules = Array.isArray(schedules) ? schedules : [];
    return {
      typeCount: types.length,
      enabledCount: types.filter(function(row) { return row.enabled === true; }).length,
      scheduleCount: namedSchedules.length,
      historyCount: (records || []).length + (deliveries || []).length,
    };
  }

  function recipientLabel(row) {
    if (row && row.recipient) return row.recipient;
    if (row && row.primary_contact_email) return row.primary_contact_email;
    return 'Primary contact';
  }

  // closeMenusOutsideClick closes every open "More" menu whose element does
  // not contain the click target (PAT-1741, defect 2 — stacked report-type
  // More menus). The report-type rows' `<details class="rpt-more">` elements
  // share name="rpt-more-group", so opening one natively closes any other
  // sibling (Chrome/Edge 120+, Firefox 125+, Safari 17.4+ — this is a
  // staff-only internal tool, evergreen browsers only). There is no native
  // outside-click-close for <details>; this covers that other half, using
  // the same document-level "outside click" shape as _toggleIdentityMenu's
  // listener above it in console.html. `menus` is any iterable of DOM-like
  // nodes exposing contains()/removeAttribute() (a real NodeList in the
  // browser, plain objects in tests); `target` is the click event's target.
  // Returns the number of menus actually closed, for test assertions.
  function closeMenusOutsideClick(menus, target) {
    var closed = 0;
    (menus || []).forEach(function(menu) {
      if (menu && typeof menu.contains === 'function' && !menu.contains(target)) {
        menu.removeAttribute('open');
        closed++;
      }
    });
    return closed;
  }

  return {
    artifactState: artifactState,
    closeMenusOutsideClick: closeMenusOutsideClick,
    combineHistory: combineHistory,
    deliveryState: deliveryState,
    recipientLabel: recipientLabel,
    summary: summary,
  };
});
