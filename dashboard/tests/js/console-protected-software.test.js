const test = require('node:test');
const assert = require('node:assert/strict');
const {
  categoryLabel,
  identityParts,
  hasIdentity,
  groupBySource,
  addPayload,
  addPayloadError,
  changeDetail,
  changeActionLabel,
  overrideRemovePayload,
} = require('../../static/js/console-protected-software.js');

test('categoryLabel maps known codes and falls back to the raw string', () => {
  assert.equal(categoryLabel('edr'), 'EDR');
  assert.equal(categoryLabel('customer_defined'), 'Customer defined');
  assert.equal(categoryLabel('made_up'), 'made_up');
  assert.equal(categoryLabel(''), '');
});

test('identityParts returns only populated identity fields, in fixed order', () => {
  const parts = identityParts({
    bundle_id: 'com.crowdstrike.falcon',
    team_id: null,
    signer: '',
    win_publisher: 'Acme Inc',
    win_product_code: undefined,
    process_name: 'falconctl',
  });
  assert.deepEqual(parts.map((p) => p.field), ['bundle_id', 'win_publisher', 'process_name']);
  assert.equal(parts[0].value, 'com.crowdstrike.falcon');
  assert.equal(parts[0].label, 'Bundle ID');
});

test('hasIdentity is true with any one populated identity field, false with none', () => {
  assert.equal(hasIdentity({ bundle_id: 'com.x.y' }), true);
  assert.equal(hasIdentity({ process_name: 'agent.exe' }), true);
  assert.equal(hasIdentity({}), false);
  assert.equal(hasIdentity({ bundle_id: '   ' }), false);
});

test('groupBySource splits entries by the platform-tagged source, unknown source treated as baseline', () => {
  const entries = [
    { id: 1, source: 'baseline', vendor: 'CrowdStrike' },
    { id: 2, source: 'tenant', vendor: 'Acme Backup' },
    { id: 3, source: 'tenant', vendor: 'Acme EDR' },
    { id: 4 },
  ];
  const grouped = groupBySource(entries);
  assert.equal(grouped.baseline.length, 2);
  assert.equal(grouped.tenant.length, 2);
  assert.deepEqual(grouped.tenant.map((e) => e.id), [2, 3]);
});

test('groupBySource tolerates a missing/empty entries array', () => {
  assert.deepEqual(groupBySource(null), { baseline: [], tenant: [] });
  assert.deepEqual(groupBySource([]), { baseline: [], tenant: [] });
});

test('addPayload trims fields and omits blank identity fields entirely', () => {
  const payload = addPayload({
    category: ' edr ',
    vendor: ' CrowdStrike ',
    product_name: ' Falcon ',
    bundle_id: '  ',
    team_id: ' ABCDE12345 ',
    reason: ' required by policy ',
  });
  assert.equal(payload.category, 'edr');
  assert.equal(payload.vendor, 'CrowdStrike');
  assert.equal(payload.product_name, 'Falcon');
  assert.equal(payload.team_id, 'ABCDE12345');
  assert.equal(payload.reason, 'required by policy');
  assert.equal('bundle_id' in payload, false);
});

test('addPayloadError requires a valid category', () => {
  const err = addPayloadError(addPayload({
    category: 'not_a_real_category', vendor: 'Acme', product_name: 'Agent', bundle_id: 'com.acme.agent',
  }));
  assert.equal(err, 'Choose a category.');
});

test('addPayloadError requires vendor and product_name', () => {
  assert.equal(
    addPayloadError(addPayload({ category: 'edr', product_name: 'Agent', bundle_id: 'com.acme.agent' })),
    'Vendor is required.'
  );
  assert.equal(
    addPayloadError(addPayload({ category: 'edr', vendor: 'Acme', bundle_id: 'com.acme.agent' })),
    'Product name is required.'
  );
});

test('addPayloadError requires at least one identity field', () => {
  const err = addPayloadError(addPayload({ category: 'edr', vendor: 'Acme', product_name: 'Agent' }));
  assert.match(err, /identity field/);
});

test('addPayloadError passes a fully valid payload', () => {
  const payload = addPayload({
    category: 'security', vendor: 'Acme', product_name: 'Shield', process_name: 'shieldd',
  });
  assert.equal(addPayloadError(payload), null);
});

test('changeDetail parses a JSON string, passes through an object, and fails closed on garbage', () => {
  assert.deepEqual(changeDetail({ detail: '{"reason":"no longer used"}' }), { reason: 'no longer used' });
  assert.deepEqual(changeDetail({ detail: { vendor: 'Acme' } }), { vendor: 'Acme' });
  assert.deepEqual(changeDetail({ detail: 'not json' }), {});
  assert.deepEqual(changeDetail({}), {});
  assert.deepEqual(changeDetail(null), {});
});

test('changeActionLabel maps the two known actions and passes through anything else', () => {
  assert.equal(changeActionLabel('added'), 'Added');
  assert.equal(changeActionLabel('baseline_override_removed'), 'Baseline override removed');
  assert.equal(changeActionLabel('mystery'), 'mystery');
});

test('overrideRemovePayload trims the reason and never carries an actor field', () => {
  const payload = overrideRemovePayload('  no longer required  ');
  assert.deepEqual(payload, { reason: 'no longer required' });
  assert.equal('removed_by' in payload, false);
});
