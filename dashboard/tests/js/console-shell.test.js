const test = require('node:test');
const assert = require('node:assert/strict');
const shell = require('../../static/js/console-shell.js');
test('shell admits existing global destinations and leaves tenant tab gates to governance', () => {
  for (const name of ['home', 'customers-list', 'ops', 'automations', 'truth', 'reports', 'docs', 'credentials', 'homebrew-review', 'software-identities', 'software-alerts', 'logs']) {
    assert.deepEqual(shell.parseRoute('#' + name), {section: name});
  }
  assert.deepEqual(shell.parseRoute('#catalogue'), {section: 'home'});
  assert.deepEqual(shell.parseRoute('#tenant/a%20b/customer-access'), {section: 'tenant-workspace', tenantId: 'a b', tab: 'customer-access'});
  assert.deepEqual(shell.parseRoute('#tenant/%invalid/account'), {section: 'home'});
});
test('global scope clears selected identity and capability evidence', () => {
  const state = {tenantId: 'a', tenantData: {removal_capability: true}, activeTab: 'account', deviceId: 'one'};
  shell.clearTenant(state);
  for (const value of Object.values(state)) assert.equal(value, null);
});
test('navigation keeps the established canonical console URL and query, pushes user changes and skips duplicates', () => {
  const calls = [];
  const history = {pushState: (...args) => calls.push(['push', ...args]), replaceState: (...args) => calls.push(['replace', ...args])};
  const location = {pathname: '/console', search: '?x=1', hash: '#home'};
  shell.navigate(history, location, 'home', false);
  assert.equal(calls.length, 0);
  shell.navigate(history, location, 'ops', false);
  assert.deepEqual(calls[0], ['push', null, '', '/console?x=1#ops']);
  shell.navigate(history, location, 'customers-list', true);
  assert.equal(calls[1][0], 'replace');
});

test('check labels keep technical keys secondary and stale version meaning explicit', () => {
  assert.equal(shell.checkCopy('deploy_drift').name, 'Dashboard version check');
  assert.match(shell.checkCopy('deploy_drift').explanation, /stale comparison does not prove the release is old/);
  assert.equal(shell.checkCopy('tick_maintenance_drift_check').name, 'Server maintenance checks');
  assert.equal(shell.checkCopy('__proto__').name, 'Service check');
});

test('missing health evidence never fabricates a successful observation', () => {
  const {renderServiceHealth} = require('../../static/js/console-work.js');
  const container = {innerHTML: ''};
  const result = renderServiceHealth(container, {disk_usage: [{}], backup_jobs: [{}], ingestion_freshness: {most_recent_ingest_at: 'invalid'}}, {
    now: Date.UTC(2026, 9, 3), escape: value => String(value), relativeTime: () => 'unknown time'
  });
  assert.deepEqual(result.healthyLabels, []);
  assert.doesNotMatch(container.innerHTML, /Unreachable|0%|All clear|Job failed/);
  assert.match(container.innerHTML, /Receipt time unknown/);
  assert.match(container.innerHTML, /Restore testing: no evidence/);
});
