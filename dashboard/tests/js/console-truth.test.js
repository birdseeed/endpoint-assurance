const test = require('node:test');
const assert = require('node:assert/strict');
const truth = require('../../static/js/console-truth.js');

const CHECKS = [
  { id: 'ok', name: 'Verified check', scope: 'prod-01', state: 'green', reason: 'current', proves: 'green proof' },
  { id: 'missing', name: 'Missing check', scope: 'api-01', state: 'amber', reason: 'no observation', notes: 'reporter needed' },
  { id: 'failed', name: 'Failed check', scope: 'prod-01', state: 'red', reason: 'timer disabled' },
  { id: 'manual', name: 'Quarantined check', scope: 'github:updater', state: 'quarantined', reason: 'manual compatibility only' },
  { id: 'gone', name: 'Retired check', scope: 'prod-01', state: 'retired', reason: 'retired 2026-08-16: endpoint removed' }
];

test('preparation maps semantic states and keeps worst evidence first', () => {
  const rows = truth.prepare(CHECKS);
  assert.deepEqual(rows.map(row => row.id), ['failed', 'missing', 'ok', 'manual', 'gone']);
  assert.deepEqual(rows.map(row => row.stateLabel), ['Action required', 'Evidence missing', 'Verified', 'Quarantined', 'Retired']);
});

test('retired state is distinct from amber, never an unresolved evidence gap', () => {
  const row = truth.normalize({ id: 'gone', state: 'retired', reason: 'retired 2026-08-16: endpoint removed' }, 0);
  assert.equal(row.state, 'retired');
  assert.equal(row.stateLabel, 'Retired');
});

test('quarantined state is distinct from retired and keeps manual compatibility visible', () => {
  const row = truth.normalize({ id: 'manual', state: 'quarantined', reason: 'manual compatibility only' }, 0);
  assert.equal(row.state, 'quarantined');
  assert.equal(row.stateLabel, 'Quarantined');
});

test('unknown state fails closed as missing evidence', () => {
  const row = truth.normalize({ id: 'future', state: '\"><img src=x onerror=alert(1)>' }, 0);
  assert.equal(row.state, 'amber');
  assert.equal(row.stateLabel, 'Evidence missing');
});

test('search covers identity, scope, evidence, proof and notes', () => {
  const rows = truth.prepare(CHECKS);
  assert.deepEqual(truth.filter(rows, { query: 'disabled' }).map(row => row.id), ['failed']);
  assert.deepEqual(truth.filter(rows, { query: 'reporter needed' }).map(row => row.id), ['missing']);
  assert.deepEqual(truth.filter(rows, { query: 'green proof' }).map(row => row.id), ['ok']);
  assert.deepEqual(truth.filter(rows, { query: 'api-01' }).map(row => row.id), ['missing']);
});

test('state and scope filters compose without mutating the source', () => {
  const rows = truth.prepare(CHECKS);
  const before = rows.map(row => row.id);
  assert.deepEqual(truth.filter(rows, { state: 'red', scope: 'prod-01' }).map(row => row.id), ['failed']);
  assert.deepEqual(rows.map(row => row.id), before);
});

test('summary and scopes reflect the declared rows', () => {
  const rows = truth.prepare(CHECKS);
  assert.deepEqual(truth.summary(rows), { red: 1, amber: 1, green: 1, quarantined: 1, retired: 1, total: 5 });
  assert.deepEqual(truth.scopes(rows), ['api-01', 'github:updater', 'prod-01']);
});

test('concise evidence is bounded while retaining short evidence verbatim', () => {
  assert.equal(truth.concise('short evidence', 20), 'short evidence');
  assert.equal(truth.concise('abcdefghijklmnopqrstuvwxyz', 10), 'abcdefghi…');
});
