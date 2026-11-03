const test = require('node:test');
const assert = require('node:assert/strict');
const meter = require('../../static/js/console-metering.js');

const apps = [
  { id: 'old', name: 'Old app', platform: 'macOS', days_since_last_use: 45, total_launch_count: 3, device_count: 1 },
  { id: 'never', name: 'Never app', platform: 'macOS', days_since_last_use: null, total_launch_count: 0, device_count: 1, metering_status: 'ok' },
  { id: 'unknown', name: 'Unknown app', platform: 'macOS', days_since_last_use: null, total_launch_count: null, device_count: 1 },
  { id: 'windows', name: 'Windows app', platform: 'Windows', days_since_last_use: null, total_launch_count: null, device_count: 1 },
  { id: 'recent', name: 'Recent app', platform: 'macOS', days_since_last_use: 2, total_launch_count: 9, device_count: 1 },
];

test('usage state fails closed when evidence is missing or Windows is pending', () => {
  assert.equal(meter.usageState(apps[2], 30), 'unavailable');
  assert.equal(meter.usageState(apps[3], 30), 'unavailable');
});

test('Windows can become measured without changing the UI contract', () => {
  assert.equal(meter.usageState({ platform: 'Windows', days_since_last_use: 45, total_launch_count: 2 }, 30), 'unused');
});

test('zero launches with collected macOS evidence is distinct from unavailable', () => {
  assert.equal(meter.usageState(apps[1], 30), 'never');
  assert.equal(meter.usageState(apps[4], 30), 'active');
});

test('reclaim candidates contain only confirmed old or never-launched apps', () => {
  assert.deepEqual(meter.filter(apps, { view: 'reclaim', threshold: 30 }).map(a => a.id), ['old', 'never']);
  assert.deepEqual(meter.filter(apps, { view: 'gaps', threshold: 30 }).map(a => a.id), ['unknown', 'windows']);
});

test('summary never folds unavailable evidence into unused', () => {
  assert.deepEqual(meter.summary(apps, 30), { installed: 5, unused: 1, never: 1, unavailable: 2 });
});

test('search, platform and threshold filters compose', () => {
  assert.deepEqual(meter.filter(apps, { view: 'all', platform: 'macos', query: 'app', threshold: 30 }).map(a => a.id), ['old', 'never', 'unknown', 'recent']);
  assert.deepEqual(meter.filter(apps, { view: 'reclaim', platform: 'macos', threshold: 60 }).map(a => a.id), ['never']);
});

// ── PAT-1320: collection-health-aware usage evidence ────────────────────────

test('never requires metering_status ok, not just zero launches', () => {
  assert.equal(meter.usageState({ days_since_last_use: null, total_launch_count: 0, metering_status: 'ok' }, 30), 'never');
  assert.equal(meter.usageState({ days_since_last_use: null, total_launch_count: 0, metering_status: 'mixed' }, 30), 'unavailable');
  assert.equal(meter.usageState({ days_since_last_use: null, total_launch_count: 0 }, 30), 'unavailable');
});

test('spotlight_disabled with zero launches is unavailable, not never', () => {
  assert.equal(meter.usageState({ days_since_last_use: null, total_launch_count: 0, metering_status: 'spotlight_disabled' }, 30), 'unavailable');
});

test('no_user_session is unavailable', () => {
  assert.equal(meter.usageState({ days_since_last_use: null, total_launch_count: 0, metering_status: 'no_user_session' }, 30), 'unavailable');
});

test('absent metering_status with zero launches is unavailable', () => {
  assert.equal(meter.usageState({ days_since_last_use: null, total_launch_count: 0 }, 30), 'unavailable');
});

test('a real days_since_last_use resolves to unused/active regardless of mixed rollup health', () => {
  assert.equal(meter.usageState({ days_since_last_use: 400, total_launch_count: 5, metering_status: 'mixed' }, 30), 'unused');
  assert.equal(meter.usageState({ days_since_last_use: 2, total_launch_count: 5, metering_status: 'mixed' }, 30), 'active');
});

test('stale telemetry with ok status is unused', () => {
  assert.equal(meter.usageState({ days_since_last_use: 400, total_launch_count: 1, metering_status: 'ok' }, 30), 'unused');
});

test('recently used telemetry with ok status is active', () => {
  assert.equal(meter.usageState({ days_since_last_use: 1, total_launch_count: 40, metering_status: 'ok' }, 30), 'active');
});

test('collectionHealth maps raw metering_status to the four-value rollup', () => {
  assert.equal(meter.collectionHealth({ metering_status: 'ok' }), 'ok');
  assert.equal(meter.collectionHealth({ metering_status: 'mixed' }), 'mixed');
  assert.equal(meter.collectionHealth({ metering_status: 'unknown' }), 'unknown');
  assert.equal(meter.collectionHealth({}), 'unknown');
  assert.equal(meter.collectionHealth({ metering_status: null }), 'unknown');
  assert.equal(meter.collectionHealth({ metering_status: '' }), 'unknown');
  assert.equal(meter.collectionHealth({ metering_status: 'spotlight_disabled' }), 'degraded');
  assert.equal(meter.collectionHealth({ metering_status: 'no_user_session' }), 'degraded');
  assert.equal(meter.collectionHealth({ metering_status: 'some_future_status' }), 'degraded');
});

test('healthReason gives readable labels, including a fallback for unrecognised raw statuses', () => {
  assert.equal(meter.healthReason({ metering_status: 'ok' }), '');
  assert.equal(meter.healthReason({ metering_status: 'mixed' }), 'Mixed across devices');
  assert.equal(meter.healthReason({ metering_status: 'unknown' }), 'No collection reported');
  assert.equal(meter.healthReason({}), 'No collection reported');
  assert.equal(meter.healthReason({ metering_status: 'spotlight_disabled' }), 'Spotlight indexing disabled');
  assert.equal(meter.healthReason({ metering_status: 'no_user_session' }), 'No console user session');
  assert.equal(meter.healthReason({ metering_status: 'disk_permission_denied' }), 'Disk permission denied');
});

test('summary reconciliation: unknown-health rows never land in unused or never', () => {
  var mixedApps = [
    { id: 'ok-never', days_since_last_use: null, total_launch_count: 0, metering_status: 'ok' },
    { id: 'unknown-zero', days_since_last_use: null, total_launch_count: 0, metering_status: 'unknown' },
    { id: 'no-status-zero', days_since_last_use: null, total_launch_count: 0 },
    { id: 'degraded-zero', days_since_last_use: null, total_launch_count: 0, metering_status: 'spotlight_disabled' },
    { id: 'mixed-with-days', days_since_last_use: 90, total_launch_count: 4, metering_status: 'mixed' },
  ];
  assert.deepEqual(meter.summary(mixedApps, 30), { installed: 5, unused: 1, never: 1, unavailable: 3 });
});
