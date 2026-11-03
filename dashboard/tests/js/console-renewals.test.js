const test = require('node:test');
const assert = require('node:assert/strict');
const {
  classifyRenewal,
  renewalDaysLabel,
  formatDeltaGbp,
  deltaClass,
} = require('../../static/js/console-renewals.js');

test('classifyRenewal treats a negative days-until as overdue, never merged into soon', () => {
  assert.equal(classifyRenewal(-1), 'overdue');
  assert.equal(classifyRenewal(-30), 'overdue');
});

test('classifyRenewal treats 0-14 days as soon and above that as upcoming', () => {
  assert.equal(classifyRenewal(0), 'soon');
  assert.equal(classifyRenewal(14), 'soon');
  assert.equal(classifyRenewal(15), 'upcoming');
  assert.equal(classifyRenewal(60), 'upcoming');
});

test('classifyRenewal returns unknown for a non-numeric input', () => {
  assert.equal(classifyRenewal(undefined), 'unknown');
  assert.equal(classifyRenewal(NaN), 'unknown');
});

test('classifyRenewal returns unknown for null, not "soon" (Number(null) === 0)', () => {
  // Non-author review finding: Number(null) coerces to 0, which without an
  // explicit null check would misclassify a missing field as the MOST
  // urgent bucket ("soon", since 0 <= 14) rather than "unknown".
  assert.equal(classifyRenewal(null), 'unknown');
});

test('renewalDaysLabel formats future, today, and overdue distinctly', () => {
  assert.equal(renewalDaysLabel(23), '23 days');
  assert.equal(renewalDaysLabel(1), '1 day');
  assert.equal(renewalDaysLabel(0), 'today');
  assert.equal(renewalDaysLabel(-5), 'overdue by 5 days');
  assert.equal(renewalDaysLabel(-1), 'overdue by 1 day');
});

test('renewalDaysLabel returns empty for null/undefined, never "today" (Number(null) === 0)', () => {
  assert.equal(renewalDaysLabel(null), '');
  assert.equal(renewalDaysLabel(undefined), '');
});

test('formatDeltaGbp always signs the value, including a flat zero', () => {
  assert.equal(formatDeltaGbp(120), '+£120.00');
  assert.equal(formatDeltaGbp(-45.5), '-£45.50');
  assert.equal(formatDeltaGbp(0), '£0.00');
});

test('deltaClass maps sign to up/down/flat', () => {
  assert.equal(deltaClass(120), 'up');
  assert.equal(deltaClass(-45.5), 'down');
  assert.equal(deltaClass(0), 'flat');
});
