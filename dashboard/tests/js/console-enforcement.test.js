const test = require('node:test');
const assert = require('node:assert/strict');
const enforcement = require('../../static/js/console-enforcement.js');

test('every supported enforcement event has readable action and outcome metadata', () => {
  const expected = {
    admin_removed: ['Administrator removed', 'completed'],
    admin_removal_skipped: ['Administrator removal', 'skipped'],
    app_blocked: ['Application blocked', 'completed'],
    app_block_skipped: ['Application block', 'skipped'],
    extension_blocklist_pushed: ['Extension blocklist applied', 'completed'],
    extension_removed: ['Browser extension removed', 'completed'],
  };
  for (const [type, values] of Object.entries(expected)) {
    assert.equal(enforcement.meta(type).action, values[0]);
    assert.equal(enforcement.meta(type).outcome, values[1]);
  }
});

test('action and outcome filters compose into server event types', () => {
  assert.deepEqual(enforcement.eventTypes('administrator', 'all'), ['admin_removed', 'admin_removal_skipped']);
  assert.deepEqual(enforcement.eventTypes('all', 'skipped'), ['admin_removal_skipped', 'app_block_skipped']);
  assert.deepEqual(enforcement.eventTypes('extension', 'completed'), ['extension_blocklist_pushed', 'extension_removed']);
});

test('details are ordered and converted to readable values', () => {
  const event = { details: { scope: 'one_profile', browser: 'chrome', count: 2, nested: { ok: true } } };
  assert.deepEqual(enforcement.details(event), [
    { key: 'browser', value: 'chrome' },
    { key: 'scope', value: 'one_profile' },
    { key: 'count', value: '2' },
    { key: 'nested', value: '{"ok":true}' },
  ]);
  assert.equal(enforcement.detailSummary(event), 'browser: chrome · scope: one_profile');
});

test('missing details fail closed to an explicit empty description', () => {
  assert.deepEqual(enforcement.details({ details: null }), []);
  assert.equal(enforcement.detailSummary({}), 'No additional detail');
});
