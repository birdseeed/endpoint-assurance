const test = require('node:test');
const assert = require('node:assert/strict');
const {
  stateLabel,
  bucketLabel,
  categoryLabel,
  daysSince,
  sortQueueDevices,
  queueDevices,
  stateCounts,
  filterByState,
  candidateCohorts,
  cohortForDevice,
  cohortSummary,
  createDispositionPayload,
  createDispositionPayloadError,
  consequenceText,
  allShareCohortId,
  ingestStatus,
  emptyQueueState,
} = require('../../static/js/console-disposition-queue.js');

test('stateLabel/bucketLabel/categoryLabel map known codes and fall back to the raw string', () => {
  assert.equal(stateLabel('stale'), 'Stale');
  assert.equal(stateLabel('removed'), 'Dispositioned');
  assert.equal(stateLabel('made_up'), 'made_up');
  assert.equal(bucketLabel('untracked'), 'Seen, not on the list');
  assert.equal(categoryLabel('on-leave'), 'On leave');
  assert.equal(categoryLabel(''), '');
});

test('daysSince computes whole days and never goes negative, null when last_seen is absent', () => {
  assert.equal(daysSince(null), null);
  assert.equal(daysSince(undefined), null);
  assert.equal(daysSince('2026-09-01T00:00:00Z', '2026-09-04T00:00:00Z'), 3);
  assert.equal(daysSince('2026-09-04T00:00:00Z', '2026-09-01T00:00:00Z'), 0);
});

test('sortQueueDevices orders oldest last_seen first, missing last_seen sorts last', () => {
  const sorted = sortQueueDevices([
    { device_id: 'a', last_seen: '2026-09-10T00:00:00Z' },
    { device_id: 'b', last_seen: null },
    { device_id: 'c', last_seen: '2026-08-01T00:00:00Z' },
  ]);
  assert.deepEqual(sorted.map((d) => d.device_id), ['c', 'a', 'b']);
});

test('queueDevices keeps only bucket=normal with state in quiet/stale/dormant', () => {
  const lifecycle = {
    devices: [
      { bucket: 'normal', state: 'reporting', device_id: 'r1', last_seen: '2026-09-15T00:00:00Z' },
      { bucket: 'normal', state: 'quiet', device_id: 'q1', last_seen: '2026-09-14T00:00:00Z' },
      { bucket: 'normal', state: 'stale', device_id: 's1', last_seen: '2026-09-01T00:00:00Z' },
      { bucket: 'normal', state: 'dormant', device_id: 'd1', last_seen: '2026-08-01T00:00:00Z' },
      { bucket: 'normal', state: 'removed', device_id: 'x1', last_seen: '2026-08-01T00:00:00Z' },
      { bucket: 'coverage_gap', state: 'never_seen', external_id: 'ext-1' },
      { bucket: 'untracked', state: 'quiet', device_id: 'u1', last_seen: '2026-09-14T00:00:00Z' },
    ],
  };
  const queue = queueDevices(lifecycle);
  assert.deepEqual(queue.map((d) => d.device_id), ['d1', 's1', 'q1']);
});

test('queueDevices defaults to an empty array when devices is missing or malformed', () => {
  assert.deepEqual(queueDevices(null), []);
  assert.deepEqual(queueDevices({}), []);
  assert.deepEqual(queueDevices({ devices: 'not-an-array' }), []);
});

test('stateCounts / filterByState', () => {
  const devices = [
    { device_id: 'a', state: 'quiet' },
    { device_id: 'b', state: 'quiet' },
    { device_id: 'c', state: 'stale' },
    { device_id: 'd', state: 'dormant' },
  ];
  assert.deepEqual(stateCounts(devices), { all: 4, quiet: 2, stale: 1, dormant: 1 });
  assert.equal(filterByState(devices, 'all').length, 4);
  assert.deepEqual(filterByState(devices, 'quiet').map((d) => d.device_id), ['a', 'b']);
  assert.deepEqual(filterByState(devices, undefined), devices);
});

test('candidateCohorts groups only on real fields (state + last_seen day), never invents a subnet', () => {
  const devices = [
    { device_id: 'a', state: 'quiet', hostname: 'MT-LAP-0412', last_seen: '2026-09-09T08:42:00Z' },
    { device_id: 'b', state: 'quiet', hostname: 'MT-LAP-0418', last_seen: '2026-09-09T09:10:00Z' },
    { device_id: 'c', state: 'quiet', hostname: 'MT-WIN-1183', last_seen: '2026-09-09T07:00:00Z' },
    { device_id: 'd', state: 'stale', hostname: 'MT-LAP-0221', last_seen: '2026-08-01T00:00:00Z' },
  ];
  const cohorts = candidateCohorts(devices);
  assert.equal(cohorts.length, 1);
  assert.equal(cohorts[0].state, 'quiet');
  assert.equal(cohorts[0].lastSeenDate, '2026-09-09');
  assert.deepEqual(cohorts[0].deviceIds.sort(), ['a', 'b', 'c']);
  // no subnet/network-change field appears anywhere on a cohort
  assert.equal('subnet' in cohorts[0], false);
  assert.equal('recorded_change' in cohorts[0], false);
});

test('candidateCohorts excludes devices with no last_seen and singleton groups', () => {
  const devices = [
    { device_id: 'a', state: 'quiet', last_seen: null },
    { device_id: 'b', state: 'dormant', last_seen: '2026-09-01T00:00:00Z' },
  ];
  assert.deepEqual(candidateCohorts(devices), []);
});

test('cohortForDevice finds the cohort containing a device id, null otherwise', () => {
  const cohorts = [{ state: 'quiet', lastSeenDate: '2026-09-09', deviceIds: ['a', 'b'], hostnames: ['A', 'B'] }];
  assert.equal(cohortForDevice('a', cohorts), cohorts[0]);
  assert.equal(cohortForDevice('z', cohorts), null);
  assert.equal(cohortForDevice(null, cohorts), null);
});

test('cohortSummary states only what was measured (state + day), never a cause', () => {
  const summary = cohortSummary({ state: 'quiet', lastSeenDate: '2026-09-09', deviceIds: ['a', 'b', 'c'], hostnames: [] });
  assert.match(summary, /3 devices went quiet on the same day/);
  assert.match(summary, /2026-09-09/);
  assert.doesNotMatch(summary, /subnet/i);
  assert.equal(cohortSummary(null), '');
});

test('createDispositionPayload sends device_id for one device, device_ids for a cohort', () => {
  const single = createDispositionPayload({
    deviceIds: ['a'], category: 'decommissioned', reportedBy: ' Sarah Voss ',
    reportedByRole: ' IT Manager ', channel: 'email', note: ' confirmed ',
  });
  assert.deepEqual(single, {
    category: 'decommissioned', reported_by: 'Sarah Voss', reported_by_role: 'IT Manager',
    channel: 'email', note: 'confirmed', device_id: 'a',
  });
  assert.equal('device_ids' in single, false);

  const cohort = createDispositionPayload({ deviceIds: ['a', 'b', 'c'], category: 'lost', reportedBy: 'Sarah' });
  assert.deepEqual(cohort.device_ids, ['a', 'b', 'c']);
  assert.equal('device_id' in cohort, false);
});

test('createDispositionPayload drops falsy device ids and handles an empty selection', () => {
  const payload = createDispositionPayload({ deviceIds: [], category: 'lost', reportedBy: 'Sarah' });
  assert.equal('device_id' in payload, false);
  assert.equal('device_ids' in payload, false);
});

test('createDispositionPayloadError requires a selection, a valid category, and reported_by', () => {
  assert.match(createDispositionPayloadError({ category: 'lost', reported_by: 'Sarah' }), /select/i);
  assert.match(createDispositionPayloadError({ device_id: 'a', category: 'bogus', reported_by: 'Sarah' }), /what happened/i);
  assert.match(createDispositionPayloadError({ device_id: 'a', category: 'lost', reported_by: '' }), /who said so/i);
  assert.equal(createDispositionPayloadError({ device_id: 'a', category: 'lost', reported_by: 'Sarah' }), null);
  assert.equal(createDispositionPayloadError({ device_ids: ['a', 'b'], category: 'lost', reported_by: 'Sarah' }), null);
});

test('consequenceText names the real device count and states, never implies compliance or coverage improvement', () => {
  const text = consequenceText(['quiet', 'quiet', 'stale']);
  assert.match(text, /3 devices/);
  assert.match(text, /quiet\/stale/);
  assert.match(text, /does not close a finding/);
  assert.match(text, /does not improve coverage/);
  assert.match(text, /does not mark these devices compliant/);

  const single = consequenceText(['dormant']);
  assert.match(single, /1 device moves/);
  assert.match(single, /this device compliant/);

  assert.match(consequenceText([]), /does not close a finding/);
});

test('allShareCohortId: a single-device write needs no cohort_id, a multi-device write must share one', () => {
  assert.equal(allShareCohortId({ dispositions: [{ device_id: 'a', cohort_id: null }] }), true);
  assert.equal(allShareCohortId({
    cohort_id: 'c-1',
    dispositions: [{ device_id: 'a', cohort_id: 'c-1' }, { device_id: 'b', cohort_id: 'c-1' }],
  }, 2), true);
  assert.equal(allShareCohortId({
    cohort_id: 'c-1',
    dispositions: [{ device_id: 'a', cohort_id: 'c-1' }, { device_id: 'b', cohort_id: null }],
  }), false);
  assert.equal(allShareCohortId({ dispositions: [{ device_id: 'a' }, { device_id: 'b' }] }), false);
  assert.equal(allShareCohortId({ dispositions: [{ device_id: 'a', cohort_id: 'c-1' }] }, 2), false);
});

test('ingestStatus: never_uploaded, active, and stale_upload against the dormant_days threshold', () => {
  assert.equal(ingestStatus({ upload: null }), 'never_uploaded');
  assert.equal(ingestStatus({
    upload: { uploaded_at: '2026-09-16T00:00:00Z' }, thresholds: { dormant_days: 45 },
  }, '2026-09-17T00:00:00Z'), 'active');
  assert.equal(ingestStatus({
    upload: { uploaded_at: '2026-12-01T00:00:00Z' }, thresholds: { dormant_days: 45 },
  }, '2026-09-17T00:00:00Z'), 'stale_upload');
});

test('emptyQueueState distinguishes healthy / never_uploaded / stale_upload, null when the queue has entries', () => {
  assert.equal(emptyQueueState({ upload: { uploaded_at: '2026-09-01T00:00:00Z' } }, [{ device_id: 'a' }]), null);

  const neverUploaded = emptyQueueState({ upload: null }, []);
  assert.equal(neverUploaded.kind, 'never_uploaded');

  const healthy = emptyQueueState(
    { upload: { uploaded_at: '2026-09-16T00:00:00Z' }, thresholds: { dormant_days: 45 } },
    [], '2026-09-17T00:00:00Z'
  );
  assert.equal(healthy.kind, 'healthy');
  assert.equal(healthy.uploadedAt, '2026-09-16T00:00:00Z');

  const stalled = emptyQueueState(
    { upload: { uploaded_at: '2026-12-01T00:00:00Z' }, thresholds: { dormant_days: 45 } },
    [], '2026-09-17T00:00:00Z'
  );
  assert.equal(stalled.kind, 'stale_upload');
});
