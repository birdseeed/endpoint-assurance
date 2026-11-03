const test = require('node:test');
const assert = require('node:assert/strict');
const shadow = require('../../static/js/console-shadow-it.js');

const drift = [{
  drift_type: 'unapproved_present', app_name: 'Steam Client', identifier: 'com.valvesoftware.steam',
  device_id: 'device-1', hostname: 'mac-one', device_last_seen: '2026-08-14T08:00:00Z'
}];
const catalogue = [{
  shadow_it_label: 'steam', shadow_it_name: 'Steam', category: 'gaming', app_name: 'Steam Client',
  identifier: 'com.valvesoftware.steam', device_id: 'device-1', hostname: 'mac-one', policy: 'flag',
  first_seen: '2026-08-01T08:00:00Z', last_seen: '2026-08-14T08:00:00Z'
}, {
  shadow_it_label: 'chatgpt', shadow_it_name: 'ChatGPT', category: 'ai_unapproved', app_name: 'ChatGPT',
  identifier: 'com.openai.chat', device_id: 'device-2', hostname: 'mac-two', policy: 'allow',
  first_seen: '2026-08-02T08:00:00Z', last_seen: '2026-08-13T08:00:00Z', reason: 'Approved pilot'
}];
const exceptions = [{
  shadow_it_label: 'chatgpt', shadow_it_name: 'ChatGPT', category: 'ai_unapproved',
  reason: 'Approved pilot', actor: 'admin_shared_token', claimed_actor: 'andy@patched.im', updated_at: '2026-08-10T08:00:00Z'
}, {
  shadow_it_label: 'parsec', shadow_it_name: 'Parsec', category: 'remote_access',
  reason: 'Support exception', actor: 'admin_shared_token', updated_at: '2026-08-09T08:00:00Z'
}];

test('merges policy drift and catalogue evidence without double counting the machine', () => {
  const items = shadow.merge(drift, catalogue, exceptions);
  const steam = items.find(item => item.label === 'steam');
  assert.deepEqual(steam.sources, ['catalogue', 'policy']);
  assert.equal(steam.policy, 'unapproved');
  assert.equal(steam.machines.length, 1);
});

test('keeps current and no-longer-installed exceptions reviewable', () => {
  const items = shadow.merge(drift, catalogue, exceptions);
  assert.deepEqual(shadow.filter(items, { view: 'exceptions' }).map(item => item.label), ['chatgpt', 'parsec']);
  assert.equal(items.find(item => item.label === 'parsec').machines.length, 0);
});

test('search, category and source filters compose over machine identity', () => {
  const items = shadow.merge(drift, catalogue, exceptions);
  assert.deepEqual(shadow.filter(items, { view: 'needs', query: 'mac-one', category: 'gaming', source: 'policy' }).map(item => item.label), ['steam']);
  assert.equal(shadow.filter(items, { view: 'needs', source: 'catalogue' }).length, 1);
});

test('summary counts unique applications, machines and exceptions', () => {
  assert.deepEqual(shadow.summary(shadow.merge(drift, catalogue, exceptions)), { needs: 1, devices: 1, exceptions: 2 });
});

test('empty states do not turn missing policy into a clean bill of health', () => {
  assert.deepEqual(shadow.emptyState({ deviceCount: 3, policyCount: 0, catalogueMatchCount: 0, view: 'needs' }), {
    title: 'No unapproved policy is configured',
    detail: 'No risk-catalogue matches were found either. This is not proof that every installed application is approved.'
  });
  assert.equal(shadow.emptyState({ deviceCount: 0 }).title, 'No endpoint inventory');
  assert.equal(shadow.emptyState({ view: 'exceptions', deviceCount: 3 }).title, 'No exceptions recorded');
  assert.equal(shadow.emptyState({ view: 'exceptions', deviceCount: 3, filtered: true }).title, 'No results match these filters');
});
