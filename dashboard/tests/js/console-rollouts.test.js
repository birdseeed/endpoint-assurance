const test = require('node:test');
const assert = require('node:assert/strict');
const Rollouts = require('../../static/js/console-rollouts.js');

// PAT-2249: the rollout-create helpers (eligibility, exactCatalogueTarget,
// rolloutBody, creationMatches, the idempotency-key store, impactEstimate,
// installedSpread) were removed with the catalogue review model they
// matched against, so only the read-only evidence helpers are covered here.

test('rollout-create helpers stay removed', () => {
  for (const name of ['eligibility', 'exactCatalogueTarget', 'rolloutBody', 'creationMatches',
                      'idempotencyKey', 'clearIdempotencyKey', 'impactEstimate', 'installedSpread']) {
    assert.equal(name in Rollouts, false, name);
  }
  assert.deepEqual(Object.keys(Rollouts).sort(),
    ['normalPlatform', 'platformState', 'provenanceForRollout', 'waveEvidence']);
});

test('rollout and wave state never promote missing evidence to success', () => {
  assert.equal(Rollouts.platformState('pending'), 'queued');
  assert.equal(Rollouts.platformState('rolling'), 'exposed');
  assert.equal(Rollouts.platformState('completed'), 'succeeded');
  assert.equal(Rollouts.platformState('paused'), 'paused');
  assert.equal(Rollouts.platformState('made-up'), 'unknown');
  assert.deepEqual(Rollouts.waveEvidence({ total:10, installed:3, failed:1, gated:2 }), {
    total:10, succeeded:3, failed:1, gated:2, unknown:4,
  });
});

test('per-device provenance requires exact label and version; unknown stays unknown', () => {
  const records = [
    { hostname:'mac-01', label:'googlechrome', version:'140.0', platform:'macos', outcome:'installed', received_at:'2026-08-21T10:00:00Z' },
    { hostname:'mac-02', app:{ label:'googlechrome', available_version:'140.0' }, platform:'macos', state:'ring_gated' },
    { hostname:'mac-03', label:'googlechrome', version:'139.0', outcome:'installed' },
  ];
  assert.deepEqual(Rollouts.provenanceForRollout(records, { label:'googlechrome', version:'140.0', platform:'macos' }), [
    { device:'mac-01', state:'succeeded', received_at:'2026-08-21T10:00:00Z' },
    { device:'mac-02', state:'unknown', received_at:'' },
  ]);
  assert.equal(Rollouts.provenanceForRollout(null, { label:'googlechrome', version:'140.0' }), null);
});

test('per-device provenance requires an explicit exact platform for platform-bound rollouts', () => {
  const records = [
    { hostname:'mac-exact', label:'googlechrome', version:'140.0', platform:'macOS', outcome:'installed' },
    { hostname:'platform-missing', label:'googlechrome', version:'140.0', outcome:'installed' },
    { hostname:'windows-cross-match', label:'googlechrome', version:'140.0', platform:'windows', outcome:'installed' },
    { hostname:'platform-unknown', label:'googlechrome', version:'140.0', platform:'linux', outcome:'installed' },
  ];

  assert.deepEqual(
    Rollouts.provenanceForRollout(records, { label:'googlechrome', version:'140.0', platform:'macos' }),
    [{ device:'mac-exact', state:'succeeded', received_at:'' }],
  );
});
