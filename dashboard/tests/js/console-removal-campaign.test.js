const test = require('node:test');
const assert = require('node:assert/strict');
const {
  platformLabel,
  statusLabel,
  evidenceLabel,
  artefactBasisLabel,
  targetLabel,
  targetIdentityParts,
  createPayload,
  createPayloadError,
  cancelPayload,
  cancelPayloadError,
  authorizePayload,
  authorizeReady,
  dryRunBlockReason,
  staleReasons,
  artefactRows,
  enumerationCaveat,
  residueRows,
  exclusion,
  devicesWithoutInventoryNote,
  policyLabel,
  deviceCounts,
  sortCampaigns,
  cancellable,
  dryRunnable,
  authorizable,
} = require('../../static/js/console-removal-campaign.js');

test('platformLabel/statusLabel/evidenceLabel/artefactBasisLabel map known codes and fall back to the raw string', () => {
  assert.equal(platformLabel('macos'), 'macOS');
  assert.equal(platformLabel('made_up'), 'made_up');
  assert.equal(statusLabel('dry_run'), 'Dry run');
  assert.equal(statusLabel(''), '');
  assert.equal(evidenceLabel('identifier_match'), 'Identifier match');
  assert.equal(evidenceLabel('name_match_only'), 'Name match only');
  assert.equal(artefactBasisLabel('observed_and_known'), 'Observed + known');
});

test('targetLabel prefers name, then bundle_id, then team_id, then a placeholder', () => {
  assert.equal(targetLabel({ name: 'Tailscale', bundle_id: 'io.tailscale.ipn' }), 'Tailscale');
  assert.equal(targetLabel({ bundle_id: 'io.tailscale.ipn', team_id: 'ABC123' }), 'io.tailscale.ipn');
  assert.equal(targetLabel({ team_id: 'ABC123' }), 'ABC123');
  assert.equal(targetLabel({}), '(unnamed target)');
});

test('targetIdentityParts returns every populated identity column', () => {
  const parts = targetIdentityParts({ name: 'Tailscale', bundle_id: 'io.tailscale.ipn', team_id: null });
  assert.deepEqual(parts.map((p) => p.field), ['name', 'bundle_id']);
});

test('createPayload trims and omits blank identity fields, never includes created_by', () => {
  const payload = createPayload({
    name: '  Tailscale  ', bundle_id: '', team_id: undefined,
    platform: 'MacOS', reason: ' pilot removal '
  });
  assert.deepEqual(payload, { platform: 'macos', reason: 'pilot removal', name: 'Tailscale' });
  assert.equal('created_by' in payload, false);
});

test('createPayload includes a numeric policy_id when given, omits an unparseable one', () => {
  assert.equal(createPayload({ name: 'X', reason: 'r', policy_id: '42' }).policy_id, 42);
  assert.equal('policy_id' in createPayload({ name: 'X', reason: 'r', policy_id: 'not-a-number' }), false);
  assert.equal('policy_id' in createPayload({ name: 'X', reason: 'r' }), false);
});

test('createPayloadError requires a valid platform, at least one identity field, and a reason', () => {
  assert.equal(createPayloadError({ platform: 'any', name: 'X', reason: 'r' }), null);
  assert.match(createPayloadError({ platform: 'bogus', name: 'X', reason: 'r' }), /platform/i);
  assert.match(createPayloadError({ platform: 'any', reason: 'r' }), /team ID|bundle ID|display name/);
  assert.match(createPayloadError({ platform: 'any', name: 'X', reason: '' }), /reason/i);
});

test('cancelPayload trims the reason; cancelled_by is never part of the shape', () => {
  assert.deepEqual(cancelPayload('  no longer needed  '), { reason: 'no longer needed' });
  assert.equal('cancelled_by' in cancelPayload('x'), false);
});

test('cancelPayloadError requires a non-blank reason', () => {
  assert.equal(cancelPayloadError('abandoned'), null);
  assert.match(cancelPayloadError('   '), /reason/i);
  assert.match(cancelPayloadError(undefined), /reason/i);
});

test('authorizePayload carries authorized_by/authorization_clause/dry_run_id verbatim and an optional numeric policy_id', () => {
  const payload = authorizePayload({
    authorized_by: ' Sarah Voss, IT Manager ',
    authorization_clause: ' MSA clause 7.3 ',
    dry_run_id: 'dry-run-1',
    policy_id: '7'
  });
  assert.deepEqual(payload, {
    authorized_by: 'Sarah Voss, IT Manager',
    authorization_clause: 'MSA clause 7.3',
    dry_run_id: 'dry-run-1',
    policy_id: 7
  });
  assert.equal('policy_id' in authorizePayload({ authorized_by: 'a', authorization_clause: 'b', dry_run_id: 'c' }), false);
});

test('authorizeReady is the structural gate: false unless both authorized_by and authorization_clause are non-empty', () => {
  assert.equal(authorizeReady({ authorized_by: 'Sarah', authorization_clause: 'MSA 7.3' }), true);
  assert.equal(authorizeReady({ authorized_by: '', authorization_clause: 'MSA 7.3' }), false);
  assert.equal(authorizeReady({ authorized_by: 'Sarah', authorization_clause: '   ' }), false);
  assert.equal(authorizeReady({}), false);
});

test('dryRunBlockReason: no dry run at all', () => {
  assert.match(dryRunBlockReason(null), /run a dry run/i);
});

test('dryRunBlockReason: a protected match blocks unconditionally, even ahead of staleness', () => {
  const dryRun = {
    protected_match: { product_name: 'CrowdStrike Falcon' },
    stale: true,
    staleness_reasons: ['inventory has been uploaded since'],
  };
  const reason = dryRunBlockReason(dryRun);
  assert.match(reason, /protected software/i);
  assert.match(reason, /CrowdStrike Falcon/);
});

test('dryRunBlockReason: staleness surfaces every reason verbatim, joined, with a re-run call to action', () => {
  const dryRun = {
    protected_match: null,
    stale: true,
    staleness_reasons: ['dry run was computed 25h ago', 'inventory has been uploaded since'],
  };
  const reason = dryRunBlockReason(dryRun);
  assert.match(reason, /dry run was computed 25h ago; inventory has been uploaded since/);
  assert.match(reason, /re-run the dry run/i);
});

test('dryRunBlockReason: null when the dry run is fresh and unprotected', () => {
  assert.equal(dryRunBlockReason({ protected_match: null, stale: false }), null);
});

test('staleReasons defaults to an empty array when absent or malformed', () => {
  assert.deepEqual(staleReasons(null), []);
  assert.deepEqual(staleReasons({}), []);
  assert.deepEqual(staleReasons({ staleness_reasons: 'not-an-array' }), []);
  assert.deepEqual(staleReasons({ staleness_reasons: ['a', 'b'] }), ['a', 'b']);
});

test('artefactRows / residueRows default to empty arrays, never throw on a missing dry run', () => {
  assert.deepEqual(artefactRows(null), []);
  assert.deepEqual(residueRows(undefined), []);
  assert.deepEqual(artefactRows({ artefacts: [{ path: '/Applications/Tailscale.app' }] }),
    [{ path: '/Applications/Tailscale.app' }]);
});

test('enumerationCaveat is present unless artefact_enumeration_complete is true', () => {
  assert.match(enumerationCaveat({ artefact_enumeration_complete: false }), /may be incomplete/i);
  assert.match(enumerationCaveat(null), /may be incomplete/i);
  assert.equal(enumerationCaveat({ artefact_enumeration_complete: true }), null);
});

test('exclusion is null with no protected_match, populated with the match and excluded count otherwise', () => {
  assert.equal(exclusion({ protected_match: null }), null);
  assert.equal(exclusion(null), null);
  const excl = exclusion({
    protected_match: { product_name: 'Falcon', vendor: 'CrowdStrike' },
    excluded_device_count: 3,
  });
  assert.equal(excl.match.product_name, 'Falcon');
  assert.equal(excl.excludedDeviceCount, 3);
});

test('devicesWithoutInventoryNote is null at zero, singular/plural otherwise, and never claims absence as evidence', () => {
  assert.equal(devicesWithoutInventoryNote({ devices_without_app_inventory: 0 }), null);
  assert.equal(devicesWithoutInventoryNote(null), null);
  assert.match(devicesWithoutInventoryNote({ devices_without_app_inventory: 1 }), /1 device has/);
  assert.match(devicesWithoutInventoryNote({ devices_without_app_inventory: 4 }), /4 devices have/);
});

test('policyLabel resolves against the tenant policy list, falls back to a raw id when not found', () => {
  const policies = [{ id: 7, name: 'Tailscale', platform: 'macos', policy: 'unapproved' }];
  assert.equal(policyLabel(7, policies), 'Tailscale (macOS) — unapproved');
  assert.equal(policyLabel(99, policies), 'Policy #99');
  assert.equal(policyLabel(null, policies), null);
});

test('deviceCounts pulls only fields the dry run actually carries, defaults to zero', () => {
  assert.deepEqual(deviceCounts(null), {
    deviceCount: 0, excludedDeviceCount: 0, withoutInventory: 0, versionCount: 0, artefactCount: 0,
  });
  const counts = deviceCounts({
    device_count: 132, excluded_device_count: 2, devices_without_app_inventory: 5,
    version_spread: [{ version: '1.72' }, { version: '1.88' }],
    artefacts: [{ path: '/a' }, { path: '/b' }, { path: '/c' }],
  });
  assert.deepEqual(counts, { deviceCount: 132, excludedDeviceCount: 2, withoutInventory: 5, versionCount: 2, artefactCount: 3 });
});

test('sortCampaigns orders newest-first by created_at', () => {
  const sorted = sortCampaigns([
    { id: 'a', created_at: '2026-09-01T00:00:00Z' },
    { id: 'b', created_at: '2026-09-17T00:00:00Z' },
    { id: 'c', created_at: '2026-09-10T00:00:00Z' },
  ]);
  assert.deepEqual(sorted.map((c) => c.id), ['b', 'c', 'a']);
});

test('cancellable/dryRunnable/authorizable mirror the state machine exactly', () => {
  assert.equal(cancellable('draft'), true);
  assert.equal(cancellable('dry_run'), true);
  assert.equal(cancellable('authorized'), false);
  assert.equal(cancellable('cancelled'), false);

  assert.equal(dryRunnable('draft'), true);
  assert.equal(dryRunnable('dry_run'), true);
  assert.equal(dryRunnable('authorized'), false);
  assert.equal(dryRunnable('cancelled'), false);

  assert.equal(authorizable('dry_run'), true);
  assert.equal(authorizable('draft'), false);
  assert.equal(authorizable('authorized'), false);
  assert.equal(authorizable('cancelled'), false);
});
