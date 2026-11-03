const { test } = require('node:test');
const assert = require('node:assert/strict');
const lifecycle = require('../../static/js/console-tenant-lifecycle.js');
test('unknown populations never become zero or reporting totals', () => {
  for (const value of [null, undefined, NaN, -1, '0', {}, 1.5]) {
    assert.equal(lifecycle.count(value), null);
    assert.match(lifecycle.devices(value), /unknown/);
    assert.match(lifecycle.reporting(value), /unknown/);
  }
  assert.equal(lifecycle.devices(0), '0 devices');
  assert.equal(lifecycle.reporting(4), '4 reporting in the last 7 days');
});
test('only successful source-shaped collections prove empty', () => {
  assert.deepEqual(lifecycle.collection({ tenants: [] }, 'tenants', 'overview'), []);
  for (const body of [null, {}, { tenants: null }, { tenants: {} }, { tenants: [null] }]) {
    assert.throws(() => lifecycle.collection(body, 'tenants', 'overview'), /unavailable/);
  }
});
test('late success and error share epoch gate including A-B-A and global navigation', () => {
  const scope = lifecycle.readScope();
  scope.context('a'); const a = scope.begin('access', 'a');
  assert.equal(scope.owns(a, 'a'), true);
  scope.context('b'); const b = scope.begin('access', 'b');
  assert.equal(scope.owns(a, 'b'), false);
  assert.equal(scope.owns(b, 'b'), true);
  scope.context('a'); assert.equal(scope.owns(a, 'a'), false);
  const newerA = scope.begin('access', 'a');
  scope.context(null); assert.equal(scope.owns(newerA, null), false);
});
test('a newer refresh replaces a pending read without cancelling independent sources', () => {
  const scope = lifecycle.readScope(); scope.context('a');
  const old = scope.begin('records', 'a'); const access = scope.begin('access', 'a');
  const current = scope.begin('records', 'a');
  assert.equal(scope.owns(old, 'a'), false);
  assert.equal(scope.owns(current, 'a'), true);
  assert.equal(scope.owns(access, 'a'), true);
  assert.equal(scope.context('a'), false);
  assert.equal(scope.owns(current, 'a'), true);
});

test('health styling accepts only bounded source evidence and never interpolates a hostile bucket', () => {
  assert.equal(lifecycle.healthBucket({}), 'unknown');
  assert.equal(lifecycle.healthBucket({ compliance_pct: null }), 'unknown');
  assert.equal(lifecycle.healthBucket({ health_bucket: '\" onclick=attack', compliance_pct: -1 }), 'unknown');
  assert.equal(lifecycle.healthBucket({ compliance_pct: 20 }), 'at_risk');
});

test('missing or unrecognised report attempt state is unknown, never evidence of non-delivery', () => {
  const reports = require('../../static/js/console-reports.js');
  for (const status of [null, undefined, '', 'future-state']) {
    assert.deepEqual(reports.deliveryState(status), { key: 'unknown', label: 'Unknown' });
  }
});
