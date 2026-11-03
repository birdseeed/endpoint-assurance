const test = require('node:test');
const assert = require('node:assert/strict');
const {
  stateLabel,
  bucketLabel,
  bucketCards,
  thresholdSummary,
  stateOptionsForBucket,
  filterDevices,
  sortDevicesByLastSeen,
  emptyState,
} = require('../../static/js/console-device-lifecycle.js');

test('stateLabel/bucketLabel map known codes and fall back to the raw string', () => {
  assert.equal(stateLabel('stale'), 'Stale');
  assert.equal(stateLabel('never_seen'), 'Never seen');
  assert.equal(stateLabel('made_up'), 'made_up');
  assert.equal(bucketLabel('coverage_gap'), 'Coverage gap');
  assert.equal(bucketLabel('untracked'), 'Untracked');
  assert.equal(bucketLabel(''), '');
});

test('bucketCards reads the platform reconciliation counts, in normal/coverage_gap/untracked order', () => {
  const cards = bucketCards({ normal_count: 40, coverage_gap_count: 3, untracked_count: 5, unmatchable_count: 1 });
  assert.deepEqual(cards.map((c) => c.key), ['normal', 'coverage_gap', 'untracked']);
  assert.deepEqual(cards.map((c) => c.count), [40, 3, 5]);
  assert.equal(cards[1].label, 'Coverage gap');
});

test('bucketCards defaults missing counts to zero rather than throwing', () => {
  assert.deepEqual(bucketCards(null).map((c) => c.count), [0, 0, 0]);
  assert.deepEqual(bucketCards({}).map((c) => c.count), [0, 0, 0]);
});

test('thresholdSummary names all three day thresholds', () => {
  const text = thresholdSummary({ quiet_days: 3, stale_days: 14, dormant_days: 45 });
  assert.match(text, /Quiet after 3 days/);
  assert.match(text, /stale after 14/);
  assert.match(text, /dormant after 45/);
});

test('thresholdSummary pluralizes correctly for a singular 1-day threshold', () => {
  const text = thresholdSummary({ quiet_days: 1, stale_days: 14, dormant_days: 45 });
  assert.match(text, /Quiet after 1 day,/);
  assert.doesNotMatch(text, /Quiet after 1 days/);
});

test('thresholdSummary is defensive against a missing thresholds object', () => {
  assert.doesNotThrow(() => thresholdSummary(null));
  assert.match(thresholdSummary(undefined), /Quiet after an unknown number of days/);
});

test('stateOptionsForBucket: coverage_gap is only ever never_seen', () => {
  assert.deepEqual(stateOptionsForBucket('coverage_gap'), ['never_seen']);
  assert.deepEqual(stateOptionsForBucket('normal'), ['reporting', 'quiet', 'stale', 'dormant', 'removed']);
  assert.deepEqual(stateOptionsForBucket('untracked'), ['reporting', 'quiet', 'stale', 'dormant', 'removed']);
  assert.deepEqual(stateOptionsForBucket('all'), ['reporting', 'quiet', 'stale', 'dormant', 'removed', 'never_seen']);
});

const SAMPLE_DEVICES = [
  { bucket: 'normal', state: 'reporting', device_id: 'd1', hostname: 'MT-LAP-01', last_seen: '2026-09-16T00:00:00Z' },
  { bucket: 'normal', state: 'stale', device_id: 'd2', hostname: 'MT-LAP-02', last_seen: '2026-09-01T00:00:00Z' },
  { bucket: 'coverage_gap', state: 'never_seen', external_id: 'ext-3' },
  { bucket: 'untracked', state: 'quiet', device_id: 'd4', hostname: 'SHADOW-BOX', last_seen: '2026-09-14T00:00:00Z' },
];

test('filterDevices: bucket, state and search all narrow independently, "all" means no filter', () => {
  assert.equal(filterDevices(SAMPLE_DEVICES, {}).length, 4);
  assert.equal(filterDevices(SAMPLE_DEVICES, { bucket: 'all', state: 'all' }).length, 4);
  assert.deepEqual(filterDevices(SAMPLE_DEVICES, { bucket: 'normal' }).map((d) => d.device_id), ['d1', 'd2']);
  assert.deepEqual(filterDevices(SAMPLE_DEVICES, { state: 'never_seen' }).map((d) => d.external_id), ['ext-3']);
  assert.deepEqual(filterDevices(SAMPLE_DEVICES, { search: 'shadow' }).map((d) => d.device_id), ['d4']);
  assert.deepEqual(filterDevices(SAMPLE_DEVICES, { search: 'ext-3' }).map((d) => d.external_id), ['ext-3']);
});

test('filterDevices combines bucket + state + search and defaults to an empty array on malformed input', () => {
  assert.deepEqual(filterDevices(SAMPLE_DEVICES, { bucket: 'normal', state: 'stale' }).map((d) => d.device_id), ['d2']);
  assert.deepEqual(filterDevices(null, {}), []);
  assert.deepEqual(filterDevices(SAMPLE_DEVICES, { bucket: 'normal', search: 'shadow' }), []);
});

test('sortDevicesByLastSeen: oldest first by default, devices with no last_seen always sort last', () => {
  const asc = sortDevicesByLastSeen(SAMPLE_DEVICES, 'asc');
  assert.deepEqual(asc.map((d) => d.device_id || d.external_id), ['d2', 'd4', 'd1', 'ext-3']);
});

test('sortDevicesByLastSeen desc reverses the dated devices but still sorts no-evidence devices last', () => {
  const desc = sortDevicesByLastSeen(SAMPLE_DEVICES, 'desc');
  assert.deepEqual(desc.map((d) => d.device_id || d.external_id), ['d1', 'd4', 'd2', 'ext-3']);
});

test('sortDevicesByLastSeen treats a malformed last_seen the same as a missing one, never NaN-unstable', () => {
  const withGarbage = [
    { device_id: 'good', last_seen: '2026-09-01T00:00:00Z' },
    { device_id: 'garbage', last_seen: 'not-a-real-timestamp' },
    { device_id: 'absent' },
  ];
  const asc = sortDevicesByLastSeen(withGarbage, 'asc');
  assert.equal(asc[0].device_id, 'good');
  assert.deepEqual(asc.slice(1).map((d) => d.device_id).sort(), ['absent', 'garbage']);
});

test('emptyState distinguishes never_uploaded from no_devices, null once devices exist', () => {
  assert.equal(emptyState({ upload: null, devices: [] }), 'never_uploaded');
  assert.equal(emptyState({ upload: { uploaded_at: '2026-09-01T00:00:00Z' }, devices: [] }), 'no_devices');
  assert.equal(emptyState({ upload: null, devices: SAMPLE_DEVICES }), null);
  assert.equal(emptyState({}), 'never_uploaded');
});
