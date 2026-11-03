const test = require('node:test');
const assert = require('node:assert/strict');
const {
  driftArrow,
  driftBadgeClass,
  driftHeadroomLabel,
  driftStreakLabel,
} = require('../../static/js/console-drift.js');

test('driftArrow returns a distinct glyph per direction, dot for none', () => {
  assert.equal(driftArrow('above'), '▲');
  assert.equal(driftArrow('below'), '▼');
  assert.equal(driftArrow('none'), '•');
});

test('driftBadgeClass maps direction to a CSS modifier, defaulting to none', () => {
  assert.equal(driftBadgeClass('above'), 'above');
  assert.equal(driftBadgeClass('below'), 'below');
  assert.equal(driftBadgeClass('none'), 'none');
  assert.equal(driftBadgeClass(undefined), 'none');
  assert.equal(driftBadgeClass('garbage'), 'none');
});

test('driftHeadroomLabel renders "no ceiling" for null, never 0 or blank', () => {
  // A null headroom means tail territory with nothing above it to measure
  // against -- rendering it as "0" would misread as "right at the edge".
  assert.equal(driftHeadroomLabel(null), 'no ceiling');
  assert.equal(driftHeadroomLabel(undefined), 'no ceiling');
});

test('driftHeadroomLabel renders a numeric headroom, including zero', () => {
  assert.equal(driftHeadroomLabel(34), '34 to edge');
  assert.equal(driftHeadroomLabel(0), '0 to edge');
});

test('driftStreakLabel pluralises correctly and hides a zero/missing streak', () => {
  assert.equal(driftStreakLabel(1), '1 mo');
  assert.equal(driftStreakLabel(3), '3 mos');
  assert.equal(driftStreakLabel(0), '');
  assert.equal(driftStreakLabel(null), '');
  assert.equal(driftStreakLabel(undefined), '');
});
