const test = require('node:test');
const assert = require('node:assert/strict');
const {
  parseBandRows,
  bandRangeLabel,
  tailRangeLabel,
  buildRatesDiff,
} = require('../../static/js/console-billing.js');

test('parseBandRows accepts a valid ascending band list', () => {
  const result = parseBandRows([
    { max_endpoints: '25', monthly: '500', advisory_hours: '2' },
    { max_endpoints: '60', monthly: '750', advisory_hours: '3' },
  ]);
  assert.equal(result.ok, true);
  assert.deepEqual(result.bands, [
    { max_endpoints: 25, monthly: 500, advisory_hours: 2 },
    { max_endpoints: 60, monthly: 750, advisory_hours: 3 },
  ]);
});

test('parseBandRows rejects an empty band list', () => {
  const result = parseBandRows([]);
  assert.equal(result.ok, false);
  assert.match(result.error, /at least one band/i);
});

test('parseBandRows rejects non-increasing endpoint boundaries', () => {
  const result = parseBandRows([
    { max_endpoints: '60', monthly: '750', advisory_hours: '3' },
    { max_endpoints: '25', monthly: '500', advisory_hours: '2' },
  ]);
  assert.equal(result.ok, false);
  assert.match(result.error, /greater than the previous band/i);
});

test('parseBandRows rejects a boundary equal to the previous band (strictly increasing)', () => {
  const result = parseBandRows([
    { max_endpoints: '60', monthly: '750', advisory_hours: '3' },
    { max_endpoints: '60', monthly: '900', advisory_hours: '4' },
  ]);
  assert.equal(result.ok, false);
});

test('parseBandRows rejects negative monthly or advisory hours', () => {
  const negativeMonthly = parseBandRows([{ max_endpoints: '25', monthly: '-1', advisory_hours: '2' }]);
  assert.equal(negativeMonthly.ok, false);

  const negativeHours = parseBandRows([{ max_endpoints: '25', monthly: '500', advisory_hours: '-1' }]);
  assert.equal(negativeHours.ok, false);
});

test('parseBandRows rejects non-numeric fields', () => {
  const result = parseBandRows([{ max_endpoints: 'abc', monthly: '500', advisory_hours: '2' }]);
  assert.equal(result.ok, false);
});

test('bandRangeLabel derives the endpoint range from the previous band boundary', () => {
  const bands = [
    { max_endpoints: 25, monthly: 500, advisory_hours: 2 },
    { max_endpoints: 60, monthly: 750, advisory_hours: 3 },
    { max_endpoints: 120, monthly: 1200, advisory_hours: 4 },
  ];
  assert.equal(bandRangeLabel(bands, 0), '1–25');
  assert.equal(bandRangeLabel(bands, 1), '26–60');
  assert.equal(bandRangeLabel(bands, 2), '61–120');
});

test('tailRangeLabel describes the open range above the top band', () => {
  const bands = [
    { max_endpoints: 25, monthly: 500, advisory_hours: 2 },
    { max_endpoints: 250, monthly: 2000, advisory_hours: 6 },
  ];
  assert.equal(tailRangeLabel(bands), '251+');
});

test('buildRatesDiff reports no rows when nothing changed', () => {
  const rates = {
    bands: { patch: [{ max_endpoints: 25, monthly: 500, advisory_hours: 2 }], full: [] },
    tail_rate_per_endpoint: { patch: 8, full: 16 },
    annual_discount: 0.92,
  };
  const diff = buildRatesDiff(rates, JSON.parse(JSON.stringify(rates)));
  assert.deepEqual(diff, []);
});

test('buildRatesDiff surfaces a changed tier band summary', () => {
  const before = {
    bands: { patch: [{ max_endpoints: 25, monthly: 500, advisory_hours: 2 }], full: [] },
    tail_rate_per_endpoint: { patch: 8, full: 16 },
    annual_discount: 0.92,
  };
  const after = JSON.parse(JSON.stringify(before));
  after.bands.patch[0].monthly = 600;

  const diff = buildRatesDiff(before, after);
  assert.equal(diff.length, 1);
  assert.equal(diff[0].label, 'Patch bands');
  assert.match(diff[0].before, /£500/);
  assert.match(diff[0].after, /£600/);
});

test('buildRatesDiff surfaces tail-rate and annual-discount changes independently', () => {
  const before = {
    bands: { patch: [], full: [] },
    tail_rate_per_endpoint: { patch: 8, full: 16 },
    annual_discount: 0.92,
  };
  const after = {
    bands: { patch: [], full: [] },
    tail_rate_per_endpoint: { patch: 10, full: 16 },
    annual_discount: 0.90,
  };
  const diff = buildRatesDiff(before, after);
  const labels = diff.map(function(row) { return row.label; });
  assert.ok(labels.includes('Patch tail rate £/ep'));
  assert.ok(!labels.includes('Full tail rate £/ep'));
  assert.ok(labels.includes('Annual discount ×'));
});
