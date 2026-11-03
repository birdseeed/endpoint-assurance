const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');
const governance = require('../../static/js/console-governance.js');

const consoleHtml = fs.readFileSync(
  path.join(__dirname, '../../templates/console.html'), 'utf8',
);

test('retired tenant hashes resolve to a surviving assurance screen rather than a hidden screen', () => {
  assert.equal(governance.canonicalTenantTab('patch-deploy'), 'cve-findings');
  for (const tab of ['app-control', 'enforcement-audit', 'runbook']) {
    assert.equal(governance.canonicalTenantTab(tab), 'overview', tab);
  }
});

test('removal surfaces fail closed until a tenant explicitly enables removal capability', () => {
  assert.equal(governance.removalCapabilityEnabled(), false);
  assert.equal(governance.removalCapabilityEnabled({ removal_capability: false }), false);
  assert.equal(governance.removalCapabilityEnabled({ removal_capability: 'true' }), false);
  assert.equal(governance.removalCapabilityEnabled({ removal_capability: true }), true);
  assert.equal(governance.canonicalTenantTab('protected-software', {}), 'software-catalogue');
  assert.equal(governance.canonicalTenantTab('removal-campaigns', {}), 'software-catalogue');
  assert.equal(governance.canonicalTenantTab('protected-software', { removal_capability: true }), 'protected-software');
  assert.equal(governance.canonicalTenantTab('removal-campaigns', { removal_capability: true }), 'removal-campaigns');
});

test('retired PAT-1965 console surfaces are not shipped in the DOM', () => {
  for (const id of [
    'acct-view-service',
    'acct-summary-app-control',
    'tab-patch-deploy',
    'tab-app-control',
    'tab-enforcement-audit',
    'tab-runbook',
    'section-billing',
    'section-leads',
    'section-catalogue',
    'home-estate-posture',
  ]) {
    assert.equal(consoleHtml.includes(`id="${id}"`), false, id);
  }
});

test('Customers keeps the active KPI strip without an Advisory hours tile', () => {
  assert.equal(consoleHtml.includes('id="cl-kpi-strip"'), true);
  const renderStart = consoleHtml.indexOf('function _renderCustomerKpiStrip(');
  const renderEnd = consoleHtml.indexOf('// PAT-1605: zero-tenants empty state', renderStart);
  const render = consoleHtml.slice(renderStart, renderEnd);
  assert.equal(render.includes('Advisory hours'), false);
  for (const label of ['Tenants', 'Devices', 'Coverage', 'Open findings', 'CE 14-day breach']) {
    assert.equal(render.includes(label), true, label);
  }
});

test('Overview does not expose a retired enforcement-evidence destination', () => {
  const overview = consoleHtml.slice(
    consoleHtml.indexOf('<div id="tab-overview"'),
    consoleHtml.indexOf('<!-- ═══ Account tab'),
  );
  assert.equal(overview.includes('data-tab="enforcement-audit"'), false);
  assert.equal(overview.includes('View enforcement evidence'), false);
});
