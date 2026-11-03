/*
 * Pure helpers for the Disposition Queue console screen (PAT-1609),
 * following PAT-1607's split: this module owns the derivations, console.html
 * keeps the transport/DOM concerns.
 *
 * Backs GET /admin/tenants/{id}/device-lifecycle (PAT-1595, already proxied
 * for the Devices/Findings screens -- see go-service's
 * internal/handlers/device_lifecycle.go) and GET/POST
 * /admin/tenants/{id}/device-dispositions (PAT-1825 -- see
 * internal/handlers/device_dispositions.go).
 *
 * IMPORTANT -- what the platform does NOT report, and this module therefore
 * does not invent: the design mockup (docs/design/console-redesign/
 * 05-disposition-queue.html) describes automatic "cohort detection" grouping
 * devices that "share a subnet, a silence window and a recorded change".
 * The real device-lifecycle response carries no subnet field and no
 * "recorded change" field -- only bucket, state, external_id, device_id,
 * hostname and last_seen. There is nothing to compute a subnet-based cohort
 * from. candidateCohorts() below groups on the one genuine signal the API
 * actually provides: devices that share both state and the calendar day of
 * their last_seen -- a real measurement of "went quiet together", not a
 * fabricated network signal. It is offered as a starting selection an
 * operator can adjust, never as a claim that these devices share a cause.
 */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleDispositionQueue = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  // Only these three states are ever actionable from this queue. A coverage-gap
  // device (never_seen) has no devices row to hang a disposition off at all --
  // device_dispositions.device_id is a FK to devices(id) -- and bucket=untracked
  // is a different workflow (shadow devices, not "missing from the estate").
  // reporting/removed devices need no decision. See device_lifecycle.go's own
  // doc comment on loadActiveDispositionDeviceIDs for the coverage-gap rule.
  var QUEUE_STATES = ['quiet', 'stale', 'dormant'];

  var STATE_LABELS = {
    reporting: 'Reporting', quiet: 'Quiet', stale: 'Stale', dormant: 'Dormant',
    removed: 'Dispositioned', never_seen: 'Never seen'
  };

  var BUCKET_LABELS = {
    normal: 'On the list, seen', coverage_gap: 'On the list, never seen', untracked: 'Seen, not on the list'
  };

  var VALID_CATEGORIES = ['decommissioned', 'on-leave', 'lost', 'unaccounted'];

  var CATEGORY_LABELS = {
    decommissioned: 'Decommissioned',
    'on-leave': 'On leave',
    lost: 'Lost or stolen',
    unaccounted: 'Unaccounted for'
  };

  function stateLabel(state) { return STATE_LABELS[state] || String(state || ''); }
  function bucketLabel(bucket) { return BUCKET_LABELS[bucket] || String(bucket || ''); }
  function categoryLabel(category) { return CATEGORY_LABELS[category] || String(category || ''); }

  // daysSince -- whole days between lastSeenIso and nowIso (defaults to now),
  // never negative. Returns null when lastSeenIso is absent or unparseable --
  // this must never silently read as "0 days" (absence requires authority).
  function daysSince(lastSeenIso, nowIso) {
    if (!lastSeenIso) return null;
    var last = new Date(lastSeenIso);
    var now = nowIso ? new Date(nowIso) : new Date();
    if (isNaN(last.getTime()) || isNaN(now.getTime())) return null;
    return Math.max(0, Math.floor((now.getTime() - last.getTime()) / 86400000));
  }

  // sortQueueDevices -- oldest last_seen first (most overdue for a decision
  // at the top). A device with no last_seen at all sorts last, never first --
  // there is nothing to decide urgently about a device with no evidence.
  function sortQueueDevices(devices) {
    return (devices || []).slice().sort(function(a, b) {
      var la = a.last_seen ? new Date(a.last_seen).getTime() : Infinity;
      var lb = b.last_seen ? new Date(b.last_seen).getTime() : Infinity;
      return la - lb;
    });
  }

  // queueDevices -- the actionable set: bucket=normal, state in quiet/stale/
  // dormant. Never reporting (nothing to decide), never removed (already
  // dispositioned), never never_seen/coverage_gap or untracked (see the
  // QUEUE_STATES comment above for why both are structurally excluded).
  function queueDevices(lifecycle) {
    var devices = (lifecycle && Array.isArray(lifecycle.devices)) ? lifecycle.devices : [];
    return sortQueueDevices(devices.filter(function(d) {
      return d.bucket === 'normal' && QUEUE_STATES.indexOf(d.state) !== -1;
    }));
  }

  // stateCounts -- per-state counts over an already-filtered queue, for the
  // bucket filter pills (All / Quiet / Stale / Dormant).
  function stateCounts(devices) {
    var counts = { all: (devices || []).length, quiet: 0, stale: 0, dormant: 0 };
    (devices || []).forEach(function(d) {
      if (counts.hasOwnProperty(d.state)) counts[d.state] += 1;
    });
    return counts;
  }

  // filterByState -- 'all' returns everything; otherwise only the matching state.
  function filterByState(devices, state) {
    if (!state || state === 'all') return devices || [];
    return (devices || []).filter(function(d) { return d.state === state; });
  }

  // candidateCohorts -- groups devices sharing both state and the calendar
  // day of last_seen. Only genuinely computable from real API fields (see
  // the module header). Groups of one are not a cohort. Sorted largest
  // first so the biggest genuine grouping surfaces first.
  function candidateCohorts(devices) {
    var groups = {};
    var order = [];
    (devices || []).forEach(function(d) {
      if (!d.last_seen || !d.device_id) return;
      var day = String(d.last_seen).slice(0, 10);
      var key = d.state + '|' + day;
      if (!groups[key]) {
        groups[key] = { state: d.state, lastSeenDate: day, deviceIds: [], hostnames: [] };
        order.push(key);
      }
      groups[key].deviceIds.push(d.device_id);
      groups[key].hostnames.push(d.hostname || d.device_id);
    });
    return order.map(function(k) { return groups[k]; })
      .filter(function(g) { return g.deviceIds.length > 1; })
      .sort(function(a, b) { return b.deviceIds.length - a.deviceIds.length; });
  }

  // cohortForDevice -- the candidate cohort (if any) containing deviceId.
  function cohortForDevice(deviceId, cohorts) {
    if (!deviceId) return null;
    var match = (cohorts || []).find(function(c) { return c.deviceIds.indexOf(deviceId) !== -1; });
    return match || null;
  }

  // cohortSummary -- honest, data-only copy for a candidate cohort. Never
  // claims a shared subnet or a shared cause -- only what was actually
  // measured: same state, same day.
  function cohortSummary(cohort) {
    if (!cohort) return '';
    return cohort.deviceIds.length + ' devices went ' + stateLabel(cohort.state).toLowerCase() +
      ' on the same day (' + cohort.lastSeenDate + '). Deciding them one at a time invites a different answer each time to what may be the same question.';
  }

  // createDispositionPayload -- trims the form into the platform's POST body
  // shape. A single selected device sends device_id; more than one sends
  // device_ids, sharing one server-generated cohort_id -- never one POST per
  // device (writeDisposition + cohortID generation both live in one
  // transaction server-side, see device_dispositions.go).
  function createDispositionPayload(form) {
    form = form || {};
    var ids = (form.deviceIds || []).filter(Boolean);
    var payload = {
      category: String(form.category || '').trim(),
      reported_by: String(form.reportedBy || '').trim(),
      reported_by_role: String(form.reportedByRole || '').trim(),
      channel: String(form.channel || '').trim(),
      note: String(form.note || '').trim()
    };
    if (ids.length === 1) payload.device_id = ids[0];
    else if (ids.length > 1) payload.device_ids = ids;
    return payload;
  }

  // createDispositionPayloadError -- client-side mirror of the platform's own
  // validation (category enum, reported_by required, at least one device),
  // so the form fails fast with a specific message. Returns null when the
  // payload is acceptable to submit.
  function createDispositionPayloadError(payload) {
    payload = payload || {};
    if (!payload.device_id && !(payload.device_ids && payload.device_ids.length)) {
      return 'Select at least one device.';
    }
    if (VALID_CATEGORIES.indexOf(payload.category) === -1) return 'Choose what happened to the device.';
    if (!payload.reported_by) return 'Who said so is required.';
    return null;
  }

  // consequenceText -- the ticket's explicit requirement: before recording,
  // state plainly what it does and does not do. Data-driven from the actual
  // selection, not a static disclaimer -- names the real device count and
  // the real state(s) being moved out of the queue.
  function consequenceText(deviceStates) {
    var states = deviceStates || [];
    var n = states.length;
    if (n === 0) {
      return 'Recording a disposition does not close a finding, improve coverage, or mark a device compliant. It only records what the named contact said, and when.';
    }
    var uniqueStates = [];
    states.forEach(function(s) {
      var label = stateLabel(s).toLowerCase();
      if (uniqueStates.indexOf(label) === -1) uniqueStates.push(label);
    });
    var plural = n === 1 ? 'device' : 'devices';
    return 'This records what the named contact said, nothing more. It does not close a finding, does not improve coverage, and does not mark ' +
      (n === 1 ? 'this device' : 'these devices') + ' compliant. ' + n + ' ' + plural +
      ' move' + (n === 1 ? 's' : '') + ' from ' + uniqueStates.join('/') + ' to dispositioned in the reconciliation.';
  }

  // allShareCohortId -- verifies the create response's own shape: a
  // multi-device write must return one row per device, every row carrying
  // the same server-generated cohort_id (PAT-1609 acceptance criterion --
  // "verify this is what actually happens by reading the create response,
  // don't just assume the request shape guarantees it").
  function allShareCohortId(createResponse, expectedDeviceCount) {
    var rows = (createResponse && createResponse.dispositions) || [];
    if (expectedDeviceCount != null && rows.length !== expectedDeviceCount) return false;
    if (rows.length <= 1) return true;
    var cid = createResponse.cohort_id;
    if (!cid) return false;
    for (var i = 0; i < rows.length; i++) {
      if (rows[i].cohort_id !== cid) return false;
    }
    return true;
  }

  // ingestStatus -- classifies the tenant's device-list upload itself, not
  // the queue. staleUploadDays defaults to the tenant's own dormant_days
  // threshold: the same aging window the platform already uses to call a
  // device dormant is a defensible one to apply to "is this device list
  // itself stale" (no separate threshold exists in the API for this).
  function ingestStatus(lifecycle, now, staleUploadDays) {
    lifecycle = lifecycle || {};
    var upload = lifecycle.upload;
    if (!upload) return 'never_uploaded';
    var uploadedAt = upload.uploaded_at ? new Date(upload.uploaded_at) : null;
    if (!uploadedAt || isNaN(uploadedAt.getTime())) return 'active';
    var nowDate = now ? new Date(now) : new Date();
    var cutoff = staleUploadDays || (lifecycle.thresholds && lifecycle.thresholds.dormant_days) || 45;
    var ageDays = (nowDate.getTime() - uploadedAt.getTime()) / 86400000;
    return ageDays > cutoff ? 'stale_upload' : 'active';
  }

  // emptyQueueState -- distinguishes, per PAT-1609's acceptance criteria and
  // 08-empty-states.html panel 4:
  //   (a) 'healthy'        -- upload present, queue genuinely empty (nothing
  //                            to decide right now).
  //   (b) 'never_uploaded'  -- no device list has ever been uploaded; an
  //                            empty queue here proves nothing.
  //   (c) 'stale_upload'    -- a device list exists but is old enough that an
  //                            empty queue may just mean ingest has stalled.
  // Returns null when the queue is non-empty (no empty state to show at all).
  function emptyQueueState(lifecycle, queue, now) {
    if ((queue || []).length > 0) return null;
    var status = ingestStatus(lifecycle, now);
    if (status === 'never_uploaded') return { kind: 'never_uploaded' };
    if (status === 'stale_upload') {
      return { kind: 'stale_upload', uploadedAt: lifecycle.upload.uploaded_at };
    }
    return { kind: 'healthy', uploadedAt: lifecycle.upload ? lifecycle.upload.uploaded_at : null };
  }

  return {
    QUEUE_STATES: QUEUE_STATES,
    VALID_CATEGORIES: VALID_CATEGORIES,
    STATE_LABELS: STATE_LABELS,
    BUCKET_LABELS: BUCKET_LABELS,
    CATEGORY_LABELS: CATEGORY_LABELS,
    stateLabel: stateLabel,
    bucketLabel: bucketLabel,
    categoryLabel: categoryLabel,
    daysSince: daysSince,
    sortQueueDevices: sortQueueDevices,
    queueDevices: queueDevices,
    stateCounts: stateCounts,
    filterByState: filterByState,
    candidateCohorts: candidateCohorts,
    cohortForDevice: cohortForDevice,
    cohortSummary: cohortSummary,
    createDispositionPayload: createDispositionPayload,
    createDispositionPayloadError: createDispositionPayloadError,
    consequenceText: consequenceText,
    allShareCohortId: allShareCohortId,
    ingestStatus: ingestStatus,
    emptyQueueState: emptyQueueState
  };
});
