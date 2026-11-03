const test = require('node:test');
const assert = require('node:assert/strict');
const workspace = require('../../static/js/console-account-workspace.js');

test('Account workspace defaults unknown views to the compact Profile view', () => {
  assert.equal(workspace.normaliseView('unknown'), 'profile');
  assert.deepEqual(workspace.viewState('commercial'), [
    { name: 'profile', selected: false, tabIndex: -1 },
    { name: 'commercial', selected: true, tabIndex: 0 },
    { name: 'notifications', selected: false, tabIndex: -1 },
    { name: 'lifecycle', selected: false, tabIndex: -1 },
  ]);
});

test('Account workspace supports standard roving-tab keyboard movement', () => {
  assert.equal(workspace.nextView('profile', 'ArrowLeft'), 'lifecycle');
  assert.equal(workspace.nextView('profile', 'ArrowRight'), 'commercial');
  assert.equal(workspace.nextView('lifecycle', 'Home'), 'profile');
  assert.equal(workspace.nextView('profile', 'End'), 'lifecycle');
});

test('Account summary reports complete named and emailed contacts only', () => {
  assert.equal(workspace.contactCompleteness({
    primary_contact_name: 'Pat', primary_contact_email: 'pat@example.test',
    technical_contact_name: 'Tech', technical_contact_email: '',
    billing_contact_name: 'Billing', billing_contact_email: 'billing@example.test',
  }), '2 / 3 complete');
});

test('tier change always respects the platform canonical App Control response', () => {
  assert.equal(workspace.canonicalAppControl({ app_control_enabled: false }, true), false);
  assert.equal(workspace.canonicalAppControl({ app_control_enabled: true }, false), true);
  assert.equal(workspace.canonicalAppControl({}, true), true);
});

test('each workspace view has one complete panel assignment', () => {
  assert.deepEqual(workspace.panelAssignments(), {
    profile: ['acct-profile-lifecycle', 'acct-profile-primary', 'acct-profile-technical', 'acct-profile-billing', 'acct-profile-notes', 'acct-profile-actions'],
    commercial: ['acct-commercial-plan', 'acct-commercial-settings', 'acct-support-access-section', 'acct-commercial-actions'],
    lifecycle: ['acct-lifecycle-content', 'acct-danger-zone'],
  });
});

test('missing or failed Service module is isolated from the Account workspace', () => {
  assert.deepEqual(workspace.optionalServiceFeature(null), {
    available: false, module: null, controller: null,
  });
  assert.equal(workspace.optionalServiceFeature({
    createOrchestrationController() { throw new Error('module failed'); },
  }).available, false);
  const controller = { state: () => ({}) };
  const serviceModule = { createOrchestrationController: () => controller };
  const feature = workspace.optionalServiceFeature(serviceModule);
  assert.equal(feature.available, true);
  assert.equal(feature.module, serviceModule);
  assert.equal(feature.controller, controller);
});

test('top-level Service bootstrap survives missing and throwing global modules', () => {
  assert.deepEqual(workspace.bootstrapOptionalServiceFeature({}), {
    available: false, module: null, controller: null,
  });
  const brokenRoot = {};
  Object.defineProperty(brokenRoot, 'PatchedConsoleAccountWorkspace', {
    get() { throw new Error('account module load failed'); },
  });
  assert.deepEqual(workspace.bootstrapOptionalServiceFeature(brokenRoot), {
    available: false, module: null, controller: null,
  });
  const root = {
    PatchedConsoleAccountWorkspace: workspace,
    PatchedConsoleServiceEngagement: {
      createOrchestrationController() { throw new Error('service controller failed'); },
    },
  };
  assert.equal(workspace.bootstrapOptionalServiceFeature(root).available, false);
});
