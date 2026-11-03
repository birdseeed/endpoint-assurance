const test = require('node:test');
const assert = require('node:assert/strict');
const {
  buildDeviceRows,
  directiveLabel,
  fetchAllDevicePages,
  progressSummary,
  statusMeta,
  summarize,
} = require('../../static/js/console-decommission.js');

test('decommission status keeps hard failure distinct from offline or not seen', () => {
  assert.equal(statusMeta('failed').label, 'Removal failed');
  assert.match(statusMeta('failed').detail, /hard failure/);
  assert.equal(statusMeta('expired_unreachable').label, 'Offline / not seen');
  assert.match(statusMeta('expired_unreachable').detail, /without a successful removal report/);
});

test('device rows retain platform status and merge inventory last seen', () => {
  const rows = buildDeviceRows([
    {
      device_id: 'd-1',
      hostname: 'mac-01',
      status: 'removed',
      last_reported_outcome: 'agent removed',
      last_reported_at: '2026-08-10T10:00:00Z',
      terminal_without_acknowledgement: true,
    },
    { device_id: 'd-2', hostname: 'win-01', status: 'pending' },
  ], [
    { id: 'd-1', last_seen: '2026-08-10T09:59:00Z' },
    { device_id: 'd-2', last_seen: '2026-08-09T08:00:00Z' },
  ]);

  assert.equal(rows[0].lastSeen, '2026-08-10T09:59:00Z');
  assert.equal(rows[0].neverAcknowledged, true);
  assert.equal(rows[1].label, 'Pending');
  assert.equal(rows[1].lastSeen, '2026-08-09T08:00:00Z');
  assert.deepEqual(summarize(rows), {
    total: 2,
    pending: 1,
    acknowledged: 0,
    removed: 1,
    failed: 0,
    expired_unreachable: 0,
    unknown: 0,
    never_acknowledged: 1,
  });
});

test('device rows distinguish unavailable last-seen enrichment from never seen', () => {
  const unavailable = buildDeviceRows([
    { device_id: 'd-1', status: 'pending' },
  ], [], false);
  const availableButNeverSeen = buildDeviceRows([
    { device_id: 'd-1', status: 'pending' },
  ], [], true);

  assert.equal(unavailable[0].lastSeen, null);
  assert.equal(unavailable[0].lastSeenAvailable, false);
  assert.equal(availableButNeverSeen[0].lastSeen, null);
  assert.equal(availableButNeverSeen[0].lastSeenAvailable, true);
});

test('directive label does not claim completion', () => {
  assert.equal(directiveLabel({ mode: 'none' }, String), 'No agent removal scheduled');
  assert.equal(
    directiveLabel({ mode: 'expiry', expires_at: '2026-09-01T00:00:00Z' }, value => value),
    'Scheduled for 2026-09-01T00:00:00Z',
  );
  assert.equal(directiveLabel({ mode: 'immediate' }, String), 'Immediate removal requested');
  assert.equal(directiveLabel({ mode: '<unexpected>' }, String), 'Unknown agent removal directive');
});

test('a none directive never presents registered devices as pending removal', () => {
  const rows = buildDeviceRows([{ device_id: 'd-1', status: 'pending' }], [], true, 'none');
  assert.equal(rows[0].label, 'Not scheduled');
  assert.deepEqual(progressSummary(summarize(rows), 1, 'none'), {
    headline: 'No removal scheduled',
    detail: '1 registered device. Device states are not pending a current directive.',
  });
});

test('progress headline gives removed and pending counts without hiding other states', () => {
  assert.deepEqual(progressSummary({
    total: 40,
    pending: 28,
    acknowledged: 0,
    removed: 12,
    failed: 0,
    expired_unreachable: 0,
    unknown: 0,
    never_acknowledged: 0,
  }, 40), {
    headline: '12 of 40 removed, 28 pending',
    detail: 'No other reported states',
  });

  const mixed = progressSummary({
    total: 40,
    pending: 20,
    acknowledged: 3,
    removed: 12,
    failed: 2,
    expired_unreachable: 2,
    unknown: 1,
    never_acknowledged: 2,
  }, 40);
  assert.equal(mixed.headline, '12 of 40 removed, 20 pending');
  assert.equal(
    mixed.detail,
    '3 acknowledged · 2 failed · 2 offline / not seen · 1 unknown state · 2 never acknowledged',
  );

  const incomplete = progressSummary({
    total: 38,
    pending: 26,
    acknowledged: 0,
    removed: 12,
    failed: 0,
    expired_unreachable: 0,
    unknown: 0,
    never_acknowledged: 0,
  }, 40);
  assert.equal(incomplete.headline, '12 of 40 removed, 26 pending');
  assert.equal(incomplete.detail, '2 device records not returned');
});

test('inventory enrichment fetches beyond 500 devices using bounded offsets', async () => {
  const calls = [];
  const devices = await fetchAllDevicePages(({ limit, offset }) => {
    calls.push({ limit, offset });
    const count = offset === 0 ? 500 : 25;
    return Promise.resolve({
      total: 525,
      devices: Array.from({ length: count }, (_, index) => ({ id: 'd-' + (offset + index) })),
    });
  }, 500, 20);

  assert.equal(devices.length, 525);
  assert.deepEqual(calls, [{ limit: 500, offset: 0 }, { limit: 500, offset: 500 }]);
  assert.equal(devices[524].id, 'd-524');
});

test('inventory enrichment degrades when the safety cap leaves known rows unfetched', async () => {
  await assert.rejects(
    fetchAllDevicePages(({ offset }) => Promise.resolve({
      total: 1001,
      devices: Array.from({ length: 500 }, (_, index) => ({ id: 'd-' + (offset + index) })),
    }), 500, 2),
    /safety cap/,
  );
});

test('inventory enrichment degrades after a full capped page without a confirming total', async () => {
  await assert.rejects(
    fetchAllDevicePages(({ offset }) => Promise.resolve({
      devices: Array.from({ length: 500 }, (_, index) => ({ id: 'd-' + (offset + index) })),
    }), 500, 2),
    /safety cap/,
  );
});

test('inventory enrichment accepts an exact full-page multiple when total confirms completion', async () => {
  const devices = await fetchAllDevicePages(({ offset }) => Promise.resolve({
    total: 1000,
    devices: Array.from({ length: 500 }, (_, index) => ({ id: 'd-' + (offset + index) })),
  }), 500, 2);
  assert.equal(devices.length, 1000);
  assert.equal(devices[999].id, 'd-999');
});
