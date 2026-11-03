'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const service = require('../../static/js/console-service-exceptions.js');
const now = Date.parse('2026-10-04T01:00:00Z');
const at = '2026-10-04T00:00:00Z';
function feed() {
  const ids = ['outgoing_email','scheduled_jobs','customer_access','device_reports','assurance_processing','vulnerability_data','reports','backups','server_health','version_checks','billing'];
  return {observed_at: at, coverage: 'partial', checks: ids.map(id => ({
    id, name: id, explanation: 'Purpose', source: 'Recorded evidence', scope: 'Named host',
    availability: 'degraded', result: 'failed', checked_at: at, last_success_at: null,
    next_expected_at: null, reason: 'Failure observed', next_action: 'Inspect evidence', observations: []
  })), exceptions: [{id: 'scheduled_jobs:job', check_id: 'scheduled_jobs', tenant_id: null,
    scope: 'Named job', since: null, evidence_at: at, reason: 'Failure observed', deep_link: '/console#automations'}]};
}
test('retains supported evidence without promoting partial coverage', () => {
  const data = feed();
  const result = service.project(data, now);
  assert.equal(result.coverage, 'partial');
  assert.deepEqual(result.exceptions, data.exceptions);
  assert.equal(result.checks[1].last_success_at, null);
});
test('quarantines invalid source and preserves an independent exception', () => {
  const data = feed();
  data.exceptions.push({...data.exceptions[0], id: 'device_reports:tenant', check_id: 'device_reports', deep_link: '/console#ops'});
  data.exceptions[0].evidence_at = '2026-10-05T00:00:00Z';
  const result = service.project(data, now);
  assert.equal(result.checks[1].result, 'unknown');
  assert.equal(result.exceptions.length, 1);
  assert.equal(result.exceptions[0].check_id, 'device_reports');
});
for (const value of ['2026-08-30T00:00:00Z', '2027-04-04T00:00:00', '2027-04-04T01:00:00+01:00', null]) {
  test('rejects invalid or non-UTC evidence ' + value, () => {
    const data = feed(); data.exceptions[0].evidence_at = value;
    assert.equal(service.project(data, now).exceptions.length, 0);
  });
}
test('private fields are discarded at every projected level', () => {
  const data = feed(); data.secret = 'PRIVATE'; data.checks[0].job_output = 'PRIVATE'; data.exceptions[0].actor = 'PRIVATE';
  assert.ok(!JSON.stringify(service.project(data, now)).includes('PRIVATE'));
});
test('missing, duplicate and malformed categories cannot become empty success', () => {
  assert.equal(service.project({checks: []}, now), null);
  const data = feed(); data.checks[10] = data.checks[0];
  assert.equal(service.project(data, now), null);
});
test('unsafe destinations and tenant selectors never pass projection', () => {
  for (const link of ['javascript:alert(1)', '//example.test', '/console#tenant/other', '/console#reports']) {
    const data = feed(); data.exceptions[0].deep_link = link;
    assert.equal(service.project(data, now).exceptions.length, 0);
  }
});
test('success history stays with its job and never becomes category recovery', () => {
  const data = feed();
  data.checks[1].observations = [{id: 'job', scope: 'Job', result: 'failed', evidence_at: at, last_success_at: '2026-10-03T00:00:00Z'}];
  const result = service.project(data, now);
  assert.equal(result.checks[1].result, 'failed');
  assert.equal(result.checks[1].last_success_at, null);
  assert.equal(result.checks[1].observations[0].last_success_at, '2026-10-03T00:00:00Z');
});
