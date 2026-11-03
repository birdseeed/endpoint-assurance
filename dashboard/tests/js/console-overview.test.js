const test = require('node:test');
const assert = require('node:assert/strict');
const overview = require('../../static/js/console-overview.js');

// PAT-1809: the tenant Overview hero must never render "Healthy" / score 100
// when one or more of _ov2Load's 5 parallel fetches failed outright, and it
// must not conflate that failure with the genuine "tenant has zero devices"
// case, which has to keep rendering exactly as before.

test('one or more failed fetches renders an explicit unavailable state, never Healthy', () => {
  const hero = overview.resolveHeroState({
    failedFetches: ['needs-attention', 'devices', 'apps', 'certs', 'enrolled-devices'],
    noData: false,
    score: 100,
    verdict: 'Healthy',
    vColor: 'var(--green)',
    issues: [],
  });
  assert.equal(hero.mode, 'unavailable');
  assert.notEqual(hero.verdict, 'Healthy');
  assert.equal(hero.score, null);
  assert.equal(hero.badgeVisible, false);
  assert.match(hero.sub, /unavailable|could not verify/i);
});

test('a single failed fetch is enough to trip unavailable, even with the other 4 succeeding cleanly', () => {
  const hero = overview.resolveHeroState({
    failedFetches: ['devices'],
    noData: false,
    score: 100,
    verdict: 'Healthy',
    vColor: 'var(--green)',
    issues: [],
  });
  assert.equal(hero.mode, 'unavailable');
  assert.match(hero.sub, /devices/);
});

test('unavailable state is textually and colour distinct from both Healthy and No data yet', () => {
  const unavailable = overview.resolveHeroState({ failedFetches: ['devices'], noData: false, issues: [] });
  const noData = overview.resolveHeroState({ failedFetches: [], noData: true, issues: [] });
  const healthy = overview.resolveHeroState({
    failedFetches: [], noData: false, score: 100, verdict: 'Healthy', vColor: 'var(--green)', issues: [],
  });

  assert.notEqual(unavailable.verdict, noData.verdict);
  assert.notEqual(unavailable.verdict, healthy.verdict);
  assert.notEqual(unavailable.vColor, noData.vColor);
  assert.notEqual(unavailable.vColor, healthy.vColor);
  assert.notEqual(unavailable.sub, noData.sub);
});

test('a genuine zero-device tenant (all fetches succeeded) still renders No data yet unchanged', () => {
  const hero = overview.resolveHeroState({
    failedFetches: [],
    noData: true,
    score: null,
    verdict: 'No data yet',
    vColor: 'var(--muted)',
    issues: [],
  });
  assert.equal(hero.mode, 'no-data');
  assert.equal(hero.verdict, 'No data yet');
  assert.equal(hero.vColor, 'var(--muted)');
  assert.equal(hero.sub, 'No device data for this tenant yet.');
  assert.equal(hero.badgeVisible, false);
});

test('failed fetches take priority over a zero device count, even when both are true', () => {
  // e.g. /devices itself is the fetch that failed, so totalDevices fell back
  // to 0 — this must never be read as the genuine no-data case.
  const hero = overview.resolveHeroState({
    failedFetches: ['devices'],
    noData: true,
    issues: [],
  });
  assert.equal(hero.mode, 'unavailable');
  assert.notEqual(hero.verdict, 'No data yet');
});

test('a fully successful load with real data renders the scored state and passes the verdict through', () => {
  const hero = overview.resolveHeroState({
    failedFetches: [],
    noData: false,
    score: 62,
    verdict: 'Needs attention',
    vColor: 'var(--orange)',
    issues: [{ sev: 'warn', n: 3, text: 'devices stale' }],
  });
  assert.equal(hero.mode, 'scored');
  assert.equal(hero.score, 62);
  assert.equal(hero.verdict, 'Needs attention');
  assert.equal(hero.vColor, 'var(--orange)');
  assert.equal(hero.badgeVisible, true);
  assert.equal(hero.sub, '1 issue to work through. Most urgent first below.');
});

test('a fully successful load with zero issues renders the "no open issues" subtext, not Healthy-specific copy', () => {
  const hero = overview.resolveHeroState({
    failedFetches: [],
    noData: false,
    score: 100,
    verdict: 'Healthy',
    vColor: 'var(--green)',
    issues: [],
  });
  assert.equal(hero.mode, 'scored');
  assert.equal(hero.verdict, 'Healthy');
  assert.equal(hero.sub, 'No open issues across this estate.');
});
