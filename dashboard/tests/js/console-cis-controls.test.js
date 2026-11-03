const test = require('node:test');
const assert = require('node:assert/strict');
const cis = require('../../static/js/console-cis-controls.js');

// PAT-1690: a platform-scoped rule (e.g. Windows-only) must never count the
// other platform's devices as implicit passes. The tenant here has 3 devices
// total (2 macOS, 1 Windows); a Windows-only rule was evaluated on 1 device
// and failed on 0 of them.
test('platform-scoped rule denominators use evaluated devices, not the tenant total', () => {
  const windowsOnlyRule = { devices: [], evaluatedDevices: 1 };
  const row = cis.computeRow(windowsOnlyRule, 3);
  assert.equal(row.evaluatedDevices, 1);
  assert.equal(row.failCount, 0);
  assert.equal(row.passCount, 1);
  assert.equal(row.pct, 100);
});

test('a failing device still reduces the pass count within the evaluated denominator', () => {
  const windowsOnlyRule = { devices: [{ device_id: 'win-1' }], evaluatedDevices: 1 };
  const row = cis.computeRow(windowsOnlyRule, 3);
  assert.equal(row.passCount, 0);
  assert.equal(row.pct, 0);
});

test('an all-platform rule evaluated on every device behaves as before', () => {
  const allPlatformRule = { devices: [{ device_id: 'mac-2' }], evaluatedDevices: 3 };
  const row = cis.computeRow(allPlatformRule, 3);
  assert.equal(row.passCount, 2);
  assert.equal(row.pct, 67);
});

test('falls back to the tenant total when evaluatedDevices is missing (older API response)', () => {
  const legacyShapedRule = { devices: [] };
  const row = cis.computeRow(legacyShapedRule, 5);
  assert.equal(row.evaluatedDevices, 5);
  assert.equal(row.passCount, 5);
});

test('zero evaluated devices reports 0% rather than dividing by zero', () => {
  const row = cis.computeRow({ devices: [], evaluatedDevices: 0 }, 3);
  assert.equal(row.pct, 0);
  assert.equal(row.passCount, 0);
});
