/*
 * PAT-1111: testable tenant agent-decommission presentation helpers.
 *
 * The platform owns the directive and status contracts. This module only
 * normalises those responses for the browser and remains dependency-free so
 * Node's built-in test runner can exercise the same classification used by
 * the Console.
 */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleDecommission = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  var STATUS_META = {
    none: {
      label: 'Not scheduled',
      className: 'dc-state-pending',
      detail: 'No current removal directive is scheduled for this device.',
    },
    pending: {
      label: 'Pending',
      className: 'dc-state-pending',
      detail: 'This device has not acknowledged the current directive.',
    },
    acknowledged: {
      label: 'Acknowledged',
      className: 'dc-state-acknowledged',
      detail: 'The device has verified the directive. Removal is not yet confirmed.',
    },
    removed: {
      label: 'Removed',
      className: 'dc-state-removed',
      detail: 'The device reported that agent removal completed.',
    },
    failed: {
      label: 'Removal failed',
      className: 'dc-state-failed',
      detail: 'The device reported a hard failure while removing the agent.',
    },
    expired_unreachable: {
      label: 'Offline / not seen',
      className: 'dc-state-offline',
      detail: 'The expiry passed without a successful removal report from this device.',
    },
  };

  function statusMeta(status) {
    return STATUS_META[status] || {
      label: 'Unknown',
      className: 'dc-state-unknown',
      detail: 'The platform returned an unrecognised decommission state.',
    };
  }

  function inventoryMap(inventoryDevices) {
    var byId = {};
    (Array.isArray(inventoryDevices) ? inventoryDevices : []).forEach(function(device) {
      var id = device && (device.id || device.device_id);
      if (id) byId[id] = device;
    });
    return byId;
  }

  function buildDeviceRows(statusDevices, inventoryDevices, enrichmentAvailable, directiveMode) {
    var inventory = inventoryMap(inventoryDevices);
    return (Array.isArray(statusDevices) ? statusDevices : []).map(function(device) {
      var inv = inventory[device.device_id] || {};
      var status = directiveMode === 'none' ? 'none' : device.status;
      var meta = statusMeta(status);
      return {
        deviceId: device.device_id || '',
        hostname: device.hostname || inv.hostname || device.device_id || 'Unknown device',
        status: status || 'unknown',
        label: meta.label,
        className: meta.className,
        detail: meta.detail,
        outcome: device.last_reported_outcome || '',
        lastReportedAt: device.last_reported_at || null,
        lastSeen: inv.last_seen || inv.last_check_in || inv.updated_at || null,
        lastSeenAvailable: enrichmentAvailable !== false,
        neverAcknowledged: device.terminal_without_acknowledgement === true,
      };
    });
  }

  function summarize(rows) {
    var counts = {
      total: 0,
      pending: 0,
      acknowledged: 0,
      removed: 0,
      failed: 0,
      expired_unreachable: 0,
      unknown: 0,
      never_acknowledged: 0,
    };
    (Array.isArray(rows) ? rows : []).forEach(function(row) {
      counts.total += 1;
      if (Object.prototype.hasOwnProperty.call(counts, row.status)) counts[row.status] += 1;
      else counts.unknown += 1;
      if (row.neverAcknowledged) counts.never_acknowledged += 1;
    });
    return counts;
  }

  function progressSummary(counts, platformTotal, directiveMode) {
    counts = counts || summarize([]);
    var total = Number(platformTotal);
    if (!Number.isFinite(total) || total < 0) total = counts.total;

    if (directiveMode === 'none') {
      return {
        headline: 'No removal scheduled',
        detail: total + ' registered device' + (total === 1 ? '' : 's') + '. Device states are not pending a current directive.',
      };
    }
    var headline = counts.removed + ' of ' + total + ' removed, ' + counts.pending + ' pending';
    var detail = [];
    if (counts.acknowledged) detail.push(counts.acknowledged + ' acknowledged');
    if (counts.failed) detail.push(counts.failed + ' failed');
    if (counts.expired_unreachable) detail.push(counts.expired_unreachable + ' offline / not seen');
    if (counts.unknown) detail.push(counts.unknown + ' unknown state');
    if (counts.never_acknowledged) detail.push(counts.never_acknowledged + ' never acknowledged');

    var unaccounted = total - counts.total;
    if (unaccounted > 0) detail.push(unaccounted + ' device record' + (unaccounted === 1 ? '' : 's') + ' not returned');
    if (unaccounted < 0) detail.push(Math.abs(unaccounted) + ' device record' + (unaccounted === -1 ? '' : 's') + ' above platform total');

    return {
      headline: headline,
      detail: detail.join(' · ') || 'No other reported states',
    };
  }

  async function fetchAllDevicePages(fetchPage, pageSize, maxPages) {
    pageSize = pageSize || 500;
    maxPages = maxPages || 20;
    var devices = [];
    var complete = false;
    for (var page = 0; page < maxPages; page += 1) {
      var data = await fetchPage({ limit: pageSize, offset: page * pageSize });
      var batch = data && Array.isArray(data.devices) ? data.devices : [];
      devices = devices.concat(batch);
      var hasTotal = data && data.total != null && data.total !== '' && Number.isFinite(Number(data.total));
      var total = hasTotal ? Number(data.total) : null;
      if (hasTotal && devices.length >= total) {
        complete = true;
        break;
      }
      if (batch.length < pageSize) {
        if (hasTotal && total > devices.length) {
          throw new Error('Device inventory pagination ended before the reported total');
        }
        complete = true;
        break;
      }
    }
    if (!complete) throw new Error('Device inventory pagination reached its safety cap');
    return devices;
  }

  function directiveLabel(directive, formatTimestamp) {
    directive = directive || {};
    if (directive.mode === 'expiry') {
      return directive.expires_at
        ? 'Scheduled for ' + formatTimestamp(directive.expires_at)
        : 'Invalid expiry directive';
    }
    if (directive.mode === 'immediate') return 'Immediate removal requested';
    if (directive.mode === 'none' || directive.mode == null) return 'No agent removal scheduled';
    return 'Unknown agent removal directive';
  }

  return {
    buildDeviceRows: buildDeviceRows,
    directiveLabel: directiveLabel,
    fetchAllDevicePages: fetchAllDevicePages,
    progressSummary: progressSummary,
    statusMeta: statusMeta,
    summarize: summarize,
  };
});
