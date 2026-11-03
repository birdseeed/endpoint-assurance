const test = require('node:test');
const assert = require('node:assert/strict');
const {
  deviceLifecycleCoverage,
  unapprovedSummary,
  aggregateByKey,
  rankFindings,
  magnitudeFillClass,
} = require('../../static/js/console-tenant-overview.js');

test('deviceLifecycleCoverage sums exactly to devices.length across all six buckets', () => {
  const payload = {
    reconciliation: { normal_count: 3, coverage_gap_count: 1, untracked_count: 1, unmatchable_count: 2 },
    devices: [
      { bucket: 'normal', state: 'reporting' },
      { bucket: 'normal', state: 'quiet' },
      { bucket: 'normal', state: 'stale' },
      { bucket: 'coverage_gap', state: 'never_seen' },
      { bucket: 'untracked', state: 'reporting' },
    ],
  };
  const cov = deviceLifecycleCoverage(payload);
  assert.equal(cov.reporting, 1);
  assert.equal(cov.quiet, 1);
  assert.equal(cov.stale, 1);
  assert.equal(cov.neverSeen, 1);
  assert.equal(cov.untracked, 1);
  assert.equal(cov.dispositioned, 0);
  assert.equal(cov.total, payload.devices.length);
  assert.equal(cov.total, cov.devicesTotal);
});

test('deviceLifecycleCoverage folds dormant into stale, not a seventh bucket', () => {
  const cov = deviceLifecycleCoverage({
    devices: [
      { bucket: 'normal', state: 'stale' },
      { bucket: 'normal', state: 'dormant' },
    ],
  });
  assert.equal(cov.stale, 2);
  assert.equal(cov.total, 2);
});

test('deviceLifecycleCoverage: an untracked device is counted once regardless of its own freshness state', () => {
  const cov = deviceLifecycleCoverage({
    devices: [
      { bucket: 'untracked', state: 'stale' },
      { bucket: 'untracked', state: 'quiet' },
    ],
  });
  assert.equal(cov.untracked, 2);
  assert.equal(cov.reporting, 0);
  assert.equal(cov.quiet, 0);
  assert.equal(cov.stale, 0);
});

test('deviceLifecycleCoverage: never_seen always wins bucket classification', () => {
  const cov = deviceLifecycleCoverage({
    devices: [{ bucket: 'coverage_gap', state: 'never_seen' }],
  });
  assert.equal(cov.neverSeen, 1);
  assert.equal(cov.total, 1);
});

test('deviceLifecycleCoverage: dispositioned (removed) devices counted, currently always zero in practice', () => {
  const cov = deviceLifecycleCoverage({ devices: [] });
  assert.equal(cov.dispositioned, 0);
  assert.equal(cov.total, 0);
});

test('deviceLifecycleCoverage: unmatchable rows are surfaced but never folded into total', () => {
  const cov = deviceLifecycleCoverage({
    reconciliation: { unmatchable_count: 4 },
    devices: [{ bucket: 'normal', state: 'reporting' }],
  });
  assert.equal(cov.unmatchableCount, 4);
  assert.equal(cov.total, 1);
});

test('deviceLifecycleCoverage: hasUpload reflects whether an upload exists', () => {
  assert.equal(deviceLifecycleCoverage({ upload: null, devices: [] }).hasUpload, false);
  assert.equal(deviceLifecycleCoverage({ upload: { id: 1 }, devices: [] }).hasUpload, true);
});

test('deviceLifecycleCoverage: empty/missing payload never throws and totals zero', () => {
  assert.equal(deviceLifecycleCoverage(null).total, 0);
  assert.equal(deviceLifecycleCoverage({}).total, 0);
});

test('unapprovedSummary counts installs as rows and products as distinct identifiers', () => {
  const sum = unapprovedSummary([
    { drift_type: 'unapproved_present', identifier: 'com.tailscale.ipn', app_name: 'Tailscale' },
    { drift_type: 'unapproved_present', identifier: 'com.tailscale.ipn', app_name: 'Tailscale' },
    { drift_type: 'unapproved_present', identifier: 'com.zoom.zoom', app_name: 'Zoom' },
    { drift_type: 'mandatory_missing', identifier: 'x' },
  ]);
  assert.equal(sum.installs, 3);
  assert.equal(sum.products, 2);
});

test('unapprovedSummary falls back to app_name when identifier is absent', () => {
  const sum = unapprovedSummary([
    { drift_type: 'unapproved_present', app_name: 'Shadow App' },
  ]);
  assert.equal(sum.products, 1);
});

test('unapprovedSummary on empty/missing input never throws', () => {
  assert.deepEqual(unapprovedSummary(null), { installs: 0, products: 0 });
  assert.deepEqual(unapprovedSummary([]), { installs: 0, products: 0 });
});

test('aggregateByKey sums counts for matching keys and preserves first-seen fields', () => {
  const out = aggregateByKey([
    { key: 'cis:rule-1', label: 'Disk encryption off', count: 1 },
    { key: 'cis:rule-1', label: 'Disk encryption off', count: 1 },
    { key: 'cis:rule-2', label: 'Standing local admin', count: 1 },
  ]);
  assert.equal(out.length, 2);
  const rule1 = out.find(o => o.key === 'cis:rule-1');
  assert.equal(rule1.count, 2);
  assert.equal(rule1.label, 'Disk encryption off');
});

test('aggregateByKey skips items with no key', () => {
  const out = aggregateByKey([{ label: 'no key' }, null, { key: 'a', count: 1 }]);
  assert.equal(out.length, 1);
});

test('rankFindings sorts descending and caps at limit', () => {
  const out = rankFindings([
    { key: 'a', count: 5 },
    { key: 'b', count: 61 },
    { key: 'c', count: 30 },
    { key: 'd', count: 1 },
  ], 3);
  assert.deepEqual(out.map(o => o.key), ['b', 'c', 'a']);
});

test('rankFindings magnitudePct is relative to the top item in the returned set', () => {
  const out = rankFindings([{ key: 'a', count: 61 }, { key: 'b', count: 30 }], 5);
  assert.equal(out[0].magnitudePct, 100);
  assert.equal(out[1].magnitudePct, Math.round(30 / 61 * 100));
});

test('rankFindings on empty input returns empty, never throws', () => {
  assert.deepEqual(rankFindings([], 5), []);
  assert.deepEqual(rankFindings(null, 5), []);
});

test('magnitudeFillClass maps severity to the existing rdx-bar-magnitude-fill modifiers', () => {
  assert.equal(magnitudeFillClass('critical'), 'rdx-bar-magnitude-fill--danger');
  assert.equal(magnitudeFillClass('high'), 'rdx-bar-magnitude-fill--danger');
  assert.equal(magnitudeFillClass('medium'), 'rdx-bar-magnitude-fill--warning');
  assert.equal(magnitudeFillClass('low'), 'rdx-bar-magnitude-fill--neutral');
  assert.equal(magnitudeFillClass(undefined), 'rdx-bar-magnitude-fill--neutral');
});
