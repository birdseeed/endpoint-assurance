const test = require('node:test');
const assert = require('node:assert/strict');
const autos = require('../../static/js/console-automations.js');
const NOW = Date.parse('2026-08-14T12:00:00Z');
test('scheduled automation becomes overdue after its existing cadence times 1.5', () => {
  assert.equal(autos.classify({ job_name: 'health_signals_recompute', recent_runs: [{ status: 'success', started_at: '2026-08-12T23:59:00Z' }] }, NOW).state, 'overdue');
  assert.equal(autos.classify({ job_name: 'health_signals_recompute', recent_runs: [{ status: 'success', started_at: '2026-08-13T01:00:00Z' }] }, NOW).state, 'current');
});
test('no evidence is explicit and never reported as current', () => {
  const result = autos.classify({ job_name: 'new_job', schedule: 'Weekly' }, NOW);
  assert.equal(result.state, 'no-evidence');
  assert.equal(result.ageHours, null);
});
test('warning is fresh evidence, while an old running record is overdue', () => {
  assert.equal(autos.classify({ job_name: 'health_signals_recompute', recent_runs: [{ status: 'warning', started_at: '2026-08-14T11:00:00Z' }] }, NOW).state, 'current');
  assert.equal(autos.classify({ job_name: 'health_signals_recompute', recent_runs: [{ status: 'running', started_at: '2026-08-12T00:00:00Z' }] }, NOW).state, 'overdue');
});
test('unknown persisted status cannot become an HTML class or success label', () => {
  assert.deepEqual(autos.safeRunStatus('\"><img src=x onerror=alert(1)>'), { raw: '', state: 'no-evidence', label: 'No run evidence' });
});
test('quarantined jobs are visibly not scheduled', () => {
  const rows = autos.sortJobs([{ job_name: 'a', recent_runs: [{ status: 'success', started_at: '2026-08-14T11:00:00Z' }] }, { job_name: 'daily_vendor_verify', recent_runs: [{ status: 'failed', started_at: '2026-08-14T11:00:00Z' }] }], NOW);
  assert.equal(rows[1].assessment.state, 'retired');
  assert.equal(rows[1].assessment.lifecycle, 'retired');
  assert.equal(rows[1].assessment.lifecycleLabel, 'Retired daily vendor verification');
  assert.equal(rows[1].assessment.thresholdHours, null);
  assert.equal(autos.expectedIntervalHours('daily_vendor_verify'), null);
});
test('quarantined and retired historical jobs do not classify as active scheduled work', () => {
  const rows = autos.sortJobs([
    { job_name: 'installomator_sync', recent_runs: [{ status: 'failed', started_at: '2026-08-01T11:00:00Z' }] },
    { job_name: 'mirror_pipeline', recent_runs: [{ status: 'success', started_at: '2026-08-01T11:00:00Z' }] }
  ], NOW);
  assert.equal(rows.filter(row => row.assessment.lifecycle === 'scheduled').length, 0);
  assert.deepEqual(rows.map(row => row.assessment.state), ['quarantined', 'quarantined']);
  assert.equal(rows.find(row => row.job.job_name === 'mirror_pipeline').assessment.lifecycleLabel, 'Quarantined manual compatibility');
});
test('no run evidence is ranked before healthy running and current jobs', () => {
  const rows = autos.sortJobs([{ job_name: 'running', recent_runs: [{ status: 'running', started_at: '2026-08-14T11:00:00Z' }] }, { job_name: 'missing' }, { job_name: 'current', recent_runs: [{ status: 'success', started_at: '2026-08-14T11:00:00Z' }] }], NOW);
  assert.deepEqual(rows.map(row => row.assessment.state), ['no-evidence', 'running', 'current']);
});
test('prototype property names remain ordinary scheduled jobs', () => {
  const result = autos.classify({ job_name: 'toString', schedule: 'Weekly' }, NOW);
  assert.equal(result.lifecycle, 'scheduled');
  assert.equal(result.state, 'no-evidence');
  assert.equal(result.thresholdHours, 252);
});
test('summary separates active work from quarantined and retired history', () => {
  const result = autos.summarize([
    { job_name: 'health_signals_recompute', recent_runs: [{ status: 'success', started_at: '2026-08-14T11:00:00Z' }] },
    { job_name: 'installomator_sync' },
    { job_name: 'daily_vendor_verify' },
    { job_name: 'mirror_pipeline' },
    { job_name: 'mirror_pipeline_windows' }
  ], NOW);
  assert.equal(result.scheduled, 1);
  assert.equal(result.historical, 4);
  assert.equal(result.counts.current, 1);
  assert.equal(result.counts.quarantined, 3);
  assert.equal(result.counts.retired, 1);
});
