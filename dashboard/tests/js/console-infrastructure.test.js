const test = require('node:test');
const assert = require('node:assert/strict');
const { BACKUP_STALE_MS, MAINTENANCE_STALE_MS, backupAssessment, maintenanceAssessment, deployProvenance, shouldSignalTenantEntry, dedupeCheckIncidents, sortIncidents, buildInfrastructureModel } = require('../../static/js/console-infrastructure.js');

const NOW = Date.parse('2026-08-14T12:00:00Z');
function completeProtection() {
  return {
    certs: ['api.patched.im', 'dashboard.patched.im', 'app.patched.im'].map((hostname) => ({ hostname, days_left: 90, not_after: '2026-11-12T12:00:00Z' })),
    firewall: {
      'prod-01-edge': { timer_active: true, last_exit_code: '0', last_apply_timestamp: '2026-08-14T11:00:00Z' },
      'api-01-edge': { timer_active: true, last_exit_code: '0', last_apply_timestamp: '2026-08-14T11:00:00Z' },
    },
  };
}

test('backup evidence older than 26 hours cannot render healthy', () => {
  const now = Date.parse('2026-08-14T12:00:00Z');
  const stale = backupAssessment({ status: 'ok', last_success_at: new Date(now - BACKUP_STALE_MS - 1).toISOString() }, now);
  assert.equal(stale.state, 'high');
  assert.equal(backupAssessment({ status: 'ok' }, now).state, 'unknown');
});

test('dedupeCheckIncidents suppresses a wrapper only when detailed evidence exists', () => {
  const rows = dedupeCheckIncidents([
    { name: 'tick_maintenance_drift_check', state: 'degraded' },
    { name: 'maintenance_prod01', state: 'degraded' },
    { name: 'tick_email_delivery_check', state: 'degraded' },
    { name: 'email_delivery', state: 'degraded' },
    { name: 'tick_deploy_drift_check', state: 'degraded' },
  ]);
  assert.deepEqual(rows.map((row) => row.name), ['maintenance_prod01', 'email_delivery', 'tick_deploy_drift_check']);
});

test('tenant ingest incident uses payload identity and has a tenant action', () => {
  const model = buildInfrastructureModel({
    observed_at: '2026-08-14T12:00:00Z',
    health: { ingest_freshness: { stalest_tenant: { tenant_id: 'tenant-42', tenant_name: 'Acme', hours_stale: 9 } } },
  }, Date.parse('2026-08-14T12:00:00Z'));
  const incident = model.incidents.find((item) => item.issue === 'Tenant ingest is stale');
  assert.equal(incident.scope, 'Acme');
  assert.deepEqual(incident.action, { kind: 'tenant', tenantId: 'tenant-42', tab: 'device-health' });
});

test('missing host telemetry remains unavailable instead of healthy', () => {
  const model = buildInfrastructureModel({}, Date.parse('2026-08-14T12:00:00Z'));
  assert.equal(model.hosts.find((host) => host.host === 'patched-portal-01').service, 'unavailable');
  assert.equal(model.summaries[0].state, 'unknown');
});

test('active local services do not make unavailable API health green', () => {
  const model = buildInfrastructureModel({
    observed_at: '2026-08-14T12:00:00Z',
    health: { error: 'upstream unavailable', services: { 'patched-dashboard': { active: 'active' }, nginx: { active: 'active' } } },
  }, Date.parse('2026-08-14T12:00:00Z'));
  assert.equal(model.summaries[0].state, 'critical');
  assert.equal(model.hosts.find((host) => host.host === 'patched-api-01').state, 'unknown');
  assert.ok(model.incidents.some((item) => item.issue === 'Platform health evidence unavailable'));
});

test('severity ordering retains critical rank zero', () => {
  assert.deepEqual(sortIncidents([
    { severity: 'low', issue: 'low' }, { severity: 'medium', issue: 'medium' },
    { severity: 'critical', issue: 'critical' }, { severity: 'high', issue: 'high' },
  ]).map((item) => item.severity), ['critical', 'high', 'medium', 'low']);
});

test('maintenance scheduler evidence is current, stale, or unknown by evaluation age', () => {
  const now = Date.parse('2026-08-14T12:00:00Z');
  assert.equal(maintenanceAssessment({ state: 'ok', evaluated_at: new Date(now - 60000).toISOString() }, now).state, 'healthy');
  assert.equal(maintenanceAssessment({ state: 'ok', evaluated_at: new Date(now - MAINTENANCE_STALE_MS - 1).toISOString() }, now).state, 'unknown');
  assert.equal(maintenanceAssessment({ state: 'ok' }, now).state, 'unknown');
});

test('protection remains unknown until certificate and both firewall evidence categories exist', () => {
  const now = Date.parse('2026-08-14T12:00:00Z');
  const partial = buildInfrastructureModel({ certs: [{ hostname: 'dashboard', days_left: 90 }], firewall: { 'prod-01-edge': { timer_active: true, last_exit_code: '0', last_apply_timestamp: new Date(now).toISOString() } } }, now);
  assert.equal(partial.summaries[2].state, 'unknown');
  assert.ok(partial.incidents.some((item) => item.issue === 'Firewall evidence incomplete'));
});

test('protection requires evidence for every expected certificate host', () => {
  const payload = completeProtection();
  payload.certs = payload.certs.slice(0, 1);
  assert.equal(buildInfrastructureModel(payload, NOW).summaries[2].state, 'unknown');
});

test('missing certificate expiry cannot be healthy', () => {
  const payload = completeProtection();
  delete payload.certs[1].not_after;
  assert.equal(buildInfrastructureModel(payload, NOW).summaries[2].state, 'unknown');
});

test('firewall edge records require timer, exit, and usable apply evidence', () => {
  const missingExit = completeProtection();
  delete missingExit.firewall['api-01-edge'].last_exit_code;
  assert.equal(buildInfrastructureModel(missingExit, NOW).summaries[2].state, 'unknown');
  const missingApply = completeProtection();
  delete missingApply.firewall['api-01-edge'].last_apply_timestamp;
  assert.equal(buildInfrastructureModel(missingApply, NOW).summaries[2].state, 'unknown');
});

test('payload telemetry remains available to the supporting-details render contract', () => {
  const now = Date.parse('2026-08-14T12:00:00Z');
  const payload = {
    observed_at: new Date(now).toISOString(),
    health: { db_reachable: true, ingest_freshness: { most_recent_ingest_at: '2026-08-14T11:55:00Z' }, services: { 'patched-dashboard': { active: 'active' }, nginx: { active: 'active' } }, disk_usage: [{ host: 'prod-01', used_pct: 20 }] },
    backups: [{ label: 'db', status: 'ok', last_success_at: '2026-08-14T11:00:00Z' }],
    certs: [{ hostname: 'dashboard.patched.im', days_left: 40, not_after: '2026-09-23T00:00:00Z' }],
    firewall: { 'prod-01-edge': { timer_active: true, last_exit_code: '0', last_apply_timestamp: '2026-08-14T11:00:00Z' }, 'api-01-edge': { timer_active: true, last_exit_code: '0', last_apply_timestamp: '2026-08-14T11:00:00Z' } },
    versions: { api: { sha: 'api-sha', build_time: '2026-08-14T10:00:00Z', schema_mig_version: '42' }, dashboard: { sha: 'dash-sha', committed_at: '2026-08-14T09:00:00Z' } },
    partitions: { current_month: '2026-08', months_ahead: 3, partitions: [{ month: '2026-08' }, { month: '2026-09' }] },
    maintenance: [{ box: 'prod-01', state: 'ok', evaluated_at: '2026-08-14T11:30:00Z' }],
  };
  const details = buildInfrastructureModel(payload, now).details;
  assert.equal(details.health.services.nginx.active, 'active');
  assert.equal(details.health.db_reachable, true);
  assert.equal(details.freshness.most_recent_ingest_at, '2026-08-14T11:55:00Z');
  assert.equal(details.versions.api.build_time, '2026-08-14T10:00:00Z');
  assert.equal(details.versions.dashboard.committed_at, '2026-08-14T09:00:00Z');
  assert.equal(details.certs[0].not_after, '2026-09-23T00:00:00Z');
  assert.equal(details.partitions.partitions.length, 2);
  assert.equal(details.maintenanceAssessments[0].age.label, '30m ago');
});

test('read-only Infrastructure tenant navigation does not signal a login', () => {
  assert.equal(shouldSignalTenantEntry(), true);
  assert.equal(shouldSignalTenantEntry({}), true);
  assert.equal(shouldSignalTenantEntry({ readOnly: true }), false);
});

test('deploy provenance reconciles stored deploy drift with current on-box facts', () => {
  assert.equal(deployProvenance({ deployment_match: 'match' }).state, 'healthy');
  assert.equal(deployProvenance({ deployment_match: 'mismatch' }).state, 'critical');
  assert.equal(deployProvenance({}).state, 'unknown');
  const matching = buildInfrastructureModel({
    versions: { dashboard: { deployment_match: 'match', sha: 'a1b2c3d', deployed_sha: 'a1b2c3d4e5f6' } },
    checks_attention: [{ name: 'deploy_drift', state: 'degraded', evaluated_at: '2026-08-14T10:00:00Z' }],
  }, NOW);
  assert.equal(matching.incidents.some((item) => /deployment provenance|Stored deploy drift/.test(item.issue)), false);
  assert.equal(matching.details.checks[0].name, 'deploy_drift');
  const mismatch = buildInfrastructureModel({ versions: { dashboard: { deployment_match: 'mismatch' } } }, NOW);
  assert.ok(mismatch.incidents.some((item) => item.issue === 'Dashboard deployment provenance mismatch'));
  assert.equal(mismatch.incidents.some((item) => item.issue === 'Stored deploy drift observation'), false);
  const freshStored = buildInfrastructureModel({
    versions: { dashboard: { deployment_match: 'unknown' } },
    checks_attention: [{ name: 'deploy_drift', state: 'degraded', evaluated_at: '2026-08-14T11:00:00Z' }],
  }, NOW);
  assert.ok(freshStored.incidents.some((item) => item.issue === 'Stored deploy drift observation'));
  assert.equal(freshStored.incidents.some((item) => item.issue === 'Dashboard deployment provenance unavailable'), false);
  const staleStored = buildInfrastructureModel({
    versions: { dashboard: { deployment_match: 'unknown' } },
    checks_attention: [{ name: 'deploy_drift', state: 'degraded', evaluated_at: '2026-08-14T08:00:00Z' }],
  }, NOW);
  assert.ok(staleStored.incidents.some((item) => item.issue === 'Dashboard deployment provenance unavailable'));
  const unconfiguredStored = buildInfrastructureModel({
    versions: { dashboard: { deployment_match: 'unknown' } },
    checks_attention: [{ name: 'deploy_drift', state: 'unconfigured', evaluated_at: '2026-08-14T11:00:00Z' }],
  }, NOW);
  assert.ok(unconfiguredStored.incidents.some((item) => item.issue === 'Dashboard deployment provenance unavailable'));
});

test('maintenance detail is not repeated from checks_attention', () => {
  const model = buildInfrastructureModel({
    maintenance: [{ box: 'api-01', state: 'degraded', reason: 'updates pending', evaluated_at: '2026-08-14T11:00:00Z' }],
    checks_attention: [
      { name: 'tick_maintenance_drift_check', state: 'degraded' },
      { name: 'maintenance_api01', state: 'degraded' },
    ],
  }, Date.parse('2026-08-14T12:00:00Z'));
  assert.equal(model.incidents.filter((item) => item.scope === 'api-01').length, 1);
  assert.equal(model.details.checks.length, 0);
});
