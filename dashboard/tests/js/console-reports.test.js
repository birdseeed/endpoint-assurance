const test = require('node:test');
const assert = require('node:assert/strict');
const {
  artifactState,
  closeMenusOutsideClick,
  combineHistory,
  deliveryState,
  recipientLabel,
  summary,
} = require('../../static/js/console-reports.js');

// Minimal DOM-like fake: contains() reports whether `node` is `this` or one
// of the tracked descendants; removeAttribute('open') flips a flag a test
// can assert on. Good enough to exercise closeMenusOutsideClick's real
// contract without pulling in jsdom.
function fakeMenu(descendants) {
  var open = true;
  return {
    get open() { return open; },
    contains: function(node) { return node === this || (descendants || []).indexOf(node) !== -1; },
    removeAttribute: function(name) { if (name === 'open') open = false; },
  };
}

test('downloadable report records expose ready artifact separately from delivery', () => {
  assert.deepEqual(artifactState({ id: 'record-1' }), { key: 'ready', label: 'Ready' });
  assert.deepEqual(deliveryState('pending'), { key: 'not-sent', label: 'Not sent' });
  assert.deepEqual(deliveryState('sent'), { key: 'sent', label: 'Sent' });
  assert.deepEqual(deliveryState('failed'), { key: 'failed', label: 'Failed' });
});

test('history combines artifact records and legacy delivery events newest first', () => {
  const rows = combineHistory([
    { id: 'r1', name: 'Evidence pack', generated_at: '2026-08-10T08:00:00Z', delivery_status: 'pending' },
  ], [
    { report_type: 'cve-report', generated_at: '2026-08-11T09:00:00Z', status: 'generated' },
    { report_type: 'cert-expiry', sent_at: '2026-08-09T09:00:00Z', status: 'sent', recipient: 'cso@example.com' },
  ]);

  assert.deepEqual(rows.map(row => row.name), ['cve-report', 'Evidence pack', 'cert-expiry']);
  assert.equal(rows[0].artifact.label, 'Recorded');
  assert.equal(rows[0].delivery.label, 'Not sent');
  assert.equal(rows[1].artifact.label, 'Ready');
  assert.equal(rows[2].delivery.label, 'Sent');
});

test('report summary keeps report types, enabled types, schedules and history distinct', () => {
  assert.deepEqual(summary(
    [{ enabled: true }, { enabled: false }, { enabled: true }],
    [{ id: 'schedule-1' }],
    [{ id: 'record-1' }, { id: 'record-2' }],
    [{ id: 'delivery-1' }],
  ), {
    typeCount: 3,
    enabledCount: 2,
    scheduleCount: 1,
    historyCount: 3,
  });
});

test('recipient label prefers override, then primary contact, then explicit fallback', () => {
  assert.equal(recipientLabel({ recipient: 'override@example.com', primary_contact_email: 'primary@example.com' }), 'override@example.com');
  assert.equal(recipientLabel({ primary_contact_email: 'primary@example.com' }), 'primary@example.com');
  assert.equal(recipientLabel({}), 'Primary contact');
});

// PAT-1741, defect 2: stacked report-type More menus.
test('closeMenusOutsideClick closes a menu whose element does not contain the click target', () => {
  var menu = fakeMenu();
  var outsideTarget = {};
  var closed = closeMenusOutsideClick([menu], outsideTarget);
  assert.equal(closed, 1);
  assert.equal(menu.open, false);
});

test('closeMenusOutsideClick leaves a menu open when the click target is inside it', () => {
  var insideButton = {};
  var menu = fakeMenu([insideButton]);
  var closed = closeMenusOutsideClick([menu], insideButton);
  assert.equal(closed, 0);
  assert.equal(menu.open, true);
});

test('closeMenusOutsideClick closes every open menu that does not contain the target, leaving the containing one open', () => {
  var summaryOfMenuB = {};
  var menuA = fakeMenu();
  var menuB = fakeMenu([summaryOfMenuB]);
  var closed = closeMenusOutsideClick([menuA, menuB], summaryOfMenuB);
  assert.equal(closed, 1);
  assert.equal(menuA.open, false);
  assert.equal(menuB.open, true);
});

test('closeMenusOutsideClick tolerates an empty or missing menu list', () => {
  assert.equal(closeMenusOutsideClick([], {}), 0);
  assert.equal(closeMenusOutsideClick(null, {}), 0);
});
