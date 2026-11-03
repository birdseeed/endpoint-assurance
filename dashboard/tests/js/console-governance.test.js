const test = require('node:test');
const assert = require('node:assert/strict');
const governance = require('../../static/js/console-governance.js');

test('stale retired links resolve to a surviving tenant workflow', () => {
  assert.equal(governance.canonicalTenantTab('approved-software'), 'software-catalogue');
  assert.equal(governance.canonicalTenantTab('new-apps'), 'software-catalogue');
  assert.equal(governance.canonicalTenantTab('software-catalogue'), 'software-catalogue');
  assert.equal(governance.canonicalTenantTab('patch-deploy'), 'cve-findings');
});

test('new-app review decisions cannot request package execution', () => {
  assert.equal(governance.newAppDecision('approve'), 'approve');
  assert.equal(governance.newAppDecision('unapprove'), 'remove');
  assert.equal(governance.newAppDecision('defer'), 'defer');
  assert.equal(governance.newAppDecision('approve_no_patch'), null);
  assert.equal(governance.newAppDecision('install'), null);
});

test('policy mutation requires a successful fetch for the current tenant', () => {
  const loading = governance.policyFetchState('tenant-a', 'loading');
  const failed = governance.policyFetchState('tenant-a', 'failed');
  const ready = governance.policyFetchState('tenant-a', 'ready');

  assert.equal(governance.canMutatePolicy(loading, 'tenant-a'), false);
  assert.equal(governance.canMutatePolicy(failed, 'tenant-a'), false);
  assert.equal(governance.canMutatePolicy(ready, 'tenant-b'), false);
  assert.equal(governance.canMutatePolicy(ready, 'tenant-a'), true);
});

test('cached inventory retries policy loading until the current tenant is ready', () => {
  assert.equal(governance.needsPolicyReload(governance.policyFetchState('tenant-a', 'failed'), 'tenant-a'), true);
  assert.equal(governance.needsPolicyReload(governance.policyFetchState('tenant-b', 'ready'), 'tenant-a'), true);
  assert.equal(governance.needsPolicyReload(governance.policyFetchState('tenant-a', 'ready'), 'tenant-a'), false);
});

test('late tenant A inventory cannot replace tenant B or write A identity into B state', () => {
  const requestA = governance.inventoryRequestState('tenant-a', 1);
  const requestB = governance.inventoryRequestState('tenant-b', 2);
  let active = requestB;
  let inventory = null;
  const responseB = { apps: [{ name: 'B App', team_id: 'TEAM-B', app_identity: 'team:team-b' }] };
  const responseA = { apps: [{ name: 'A App', team_id: 'TEAM-A', app_identity: 'team:team-a' }] };

  if (governance.canApplyInventoryResponse(active, requestB, 'tenant-b')) inventory = responseB;
  if (governance.canApplyInventoryResponse(active, requestA, 'tenant-b')) inventory = responseA;

  assert.equal(inventory.apps[0].team_id, 'TEAM-B');
  assert.equal(inventory.apps.some(app => app.team_id === 'TEAM-A'), false);
  assert.equal(governance.inventoryBelongsToTenant('tenant-b', 'tenant-b'), true);
  assert.equal(governance.inventoryBelongsToTenant('tenant-a', 'tenant-b'), false);
});

test('late tenant A new-app response cannot replace tenant B actions', () => {
  const requestA = governance.newAppRequestState('tenant-a', 1);
  const requestB = governance.newAppRequestState('tenant-b', 2);
  assert.equal(governance.canApplyNewAppResponse(requestB, requestA, 'tenant-b'), false);
  assert.equal(governance.canApplyNewAppResponse(requestB, requestB, 'tenant-b'), true);
});

test('cached inventory retries New Apps until its current-tenant response is ready', () => {
  assert.equal(governance.needsNewAppReload(governance.newAppFetchState('tenant-a', 'loading'), 'tenant-a'), true);
  assert.equal(governance.needsNewAppReload(governance.newAppFetchState('tenant-b', 'ready'), 'tenant-a'), true);
  assert.equal(governance.needsNewAppReload(governance.newAppFetchState('tenant-a', 'ready'), 'tenant-a'), false);
});

test('individual decisions refresh while bulk decisions defer to batch completion', () => {
  assert.equal(governance.shouldRefreshNewAppDecision(), true);
  assert.equal(governance.shouldRefreshNewAppDecision({ rethrow: true }), true);
  assert.equal(governance.shouldRefreshNewAppDecision({ deferRefresh: true }), false);
});

test('policy identity keeps same-named macOS and Windows records separate', () => {
  const policies = [
    { id: 11, name: 'Example App', platform: 'macos', policy: 'approved' },
    { id: 22, name: 'Example App', platform: 'windows', policy: 'unapproved' },
    { id: 33, name: 'Example App', platform: 'any', policy: 'mandatory' },
  ];

  assert.notEqual(
    governance.policyIdentity('Example App', 'macos'),
    governance.policyIdentity('example app', 'windows'),
  );
  assert.equal(governance.findPolicy(policies, 'example app', 'macos').id, 11);
  assert.equal(governance.findPolicy(policies, 'EXAMPLE APP', 'windows').id, 22);
  assert.equal(governance.findPolicy(policies, 'Example App', 'any').id, 33);
  assert.equal(governance.findPolicy([{ ...policies[2] }], 'Example App', 'macos').id, 33);
  assert.equal(governance.findPolicy([{ ...policies[2] }], 'Example App', 'windows').id, 33);
  assert.equal(governance.policyPlatform('both'), 'any');
});

test('recorded platform policy removes only that installed identity from review', () => {
  const policies = [{ id: 11, name: 'Example App', platform: 'macos', policy: 'approved' }];

  assert.equal(governance.hasRecordedDecision(policies, { name: 'Example App', platform: 'macos' }), true);
  assert.equal(governance.hasRecordedDecision(policies, { name: 'Example App', platform: 'windows' }), false);
  assert.equal(
    governance.hasRecordedDecision([{ name: 'Example App', platform: 'any', policy: 'approved' }], {
      name: 'Example App', platform: 'windows',
    }),
    true,
  );
  assert.equal(
    governance.hasRecordedDecision([{ name: 'Example App', platform: 'macos', policy: 'unmanaged' }], {
      name: 'Example App', platform: 'macos',
    }),
    false,
  );
});

test('stronger identity takes precedence over an approved same-name policy', () => {
  const policies = [
    { id: 1, name: 'Example App', platform: 'macos', policy: 'approved' },
    { id: 2, team_id: 'TEAM-EXAMPLE', platform: 'any', policy: 'unapproved' },
    { id: 3, bundle_id: 'com.example.app', platform: 'macos', policy: 'approved' },
  ];
  const app = {
    name: 'Example App', platform: 'macos', team_id: 'team-example', identifier: 'com.example.app',
  };

  assert.equal(governance.findPolicy(policies, app).id, 2);
  assert.equal(governance.hasRecordedDecision(policies, app), true);
  assert.equal(governance.policyValue(governance.findPolicy(policies, app)), 'unapproved');
});

test('installed scan contract resolves authoritative Team ID before bundle and name', () => {
  const policies = [
    { id: 1, name: 'Example App', platform: 'macos', policy: 'approved' },
    { id: 2, bundle_id: 'com.example.app', platform: 'macos', policy: 'approved' },
    { id: 3, team_id: 'TEAM-EXAMPLE', platform: 'macos', policy: 'unapproved' },
  ];
  const app = {
    name: 'Example App', platform: 'macos', team_id: 'team-example',
    bundle_id: 'com.example.app', app_identity: 'team:team-example',
    publisher: 'Publisher text is not identity',
  };

  assert.deepEqual(governance.installedAppPolicyIdentity(app), {
    team_id: 'team-example', bundle_id: 'com.example.app', name: 'Example App',
  });
  assert.equal(governance.findInstalledPolicy(policies, app).id, 3);
  assert.deepEqual(governance.installedPolicyMutation(policies, app, 'approved').identity, {
    team_id: 'TEAM-EXAMPLE',
  });
});

test('installed scan contract accepts explicit bundle and name fallbacks', () => {
  const bundleApp = {
    name: 'Bundle App', platform: 'macos', bundle_id: 'com.example.bundle',
    app_identity: 'bundle:com.example.bundle',
  };
  const nameApp = { name: 'Name Only App', platform: 'windows', app_identity: 'name:name only app' };

  assert.deepEqual(governance.installedAppPolicyIdentity(bundleApp), {
    bundle_id: 'com.example.bundle', name: 'Bundle App',
  });
  assert.deepEqual(governance.installedAppPolicyIdentity(nameApp), { name: 'Name Only App' });
});

test('legacy, mismatched, or publisher-derived installed identity fails closed', () => {
  const policy = [{ id: 1, name: 'Example App', platform: 'macos', policy: 'approved' }];
  const legacy = { name: 'Example App', platform: 'macos', identifier: 'com.example.app' };
  const mismatched = {
    name: 'Example App', platform: 'macos', team_id: 'REALTEAM',
    app_identity: 'team:OTHERTEAM', publisher: 'OTHERTEAM',
  };

  for (const app of [legacy, mismatched]) {
    assert.deepEqual(governance.installedAppPolicyIdentity(app), {});
    assert.equal(governance.findInstalledPolicy(policy, app), null);
    assert.equal(governance.installedPolicyMutation(policy, app, 'approved').action, 'unresolved');
  }
});

test('exact platform policy wins over its any fallback for the same strong identity', () => {
  const policies = [
    { id: 1, team_id: 'TEAM-EXAMPLE', platform: 'any', policy: 'unapproved' },
    { id: 2, team_id: 'TEAM-EXAMPLE', platform: 'macos', policy: 'approved' },
  ];

  assert.equal(governance.findPolicy(policies, {
    name: 'Example App', platform: 'macos', team_id: 'team-example',
  }).id, 2);
});

test('an exact unmanaged platform override shadows an any fallback', () => {
  const policies = [
    { id: 1, team_id: 'TEAM-EXAMPLE', platform: 'any', policy: 'approved' },
    { id: 2, team_id: 'TEAM-EXAMPLE', platform: 'macos', policy: 'unmanaged' },
  ];
  const app = { name: 'Example App', platform: 'macos', team_id: 'team-example' };

  assert.equal(governance.findPolicy(policies, app).id, 2);
  assert.equal(governance.policyValue(governance.findPolicy(policies, app)), 'unmanaged');
  assert.equal(governance.hasRecordedDecision(policies, app), false);
});

test('clearing an inherited platform policy never deletes the any fallback', () => {
  const shared = { id: 10, name: 'Example App', platform: 'any', policy: 'approved' };
  const app = { name: 'Example App', platform: 'macos' };
  const clear = governance.policyMutation([shared], app, 'unmanaged');
  const change = governance.policyMutation([shared], app, 'unapproved');

  assert.equal(clear.action, 'noop');
  assert.equal(clear.exact, null);
  assert.equal(change.action, 'upsert');
  assert.equal(change.exact, null);
  assert.deepEqual(change.identity, { name: 'Example App' });
  assert.equal(change.platform, 'macos');
});

test('clear deletes only the exact same-name platform record and preserves its any fallback', () => {
  const policies = [
    { id: 10, name: 'Example App', platform: 'any', policy: 'approved' },
    { id: 11, name: 'Example App', platform: 'macos', policy: 'unapproved' },
    { id: 12, name: 'Example App', platform: 'windows', policy: 'approved' },
  ];

  const clear = governance.policyMutation(policies, {
    name: 'Example App', platform: 'macos',
  }, 'unmanaged');
  assert.equal(clear.action, 'delete');
  assert.equal(clear.exact.id, 11);
  assert.notEqual(clear.exact.id, 10);
  assert.notEqual(clear.exact.id, 12);
});

test('changes for same-name macOS, Windows, and any policies retain their own records', () => {
  const policies = [
    { id: 10, name: 'Example App', platform: 'any', policy: 'approved' },
    { id: 11, name: 'Example App', platform: 'macos', policy: 'unapproved' },
    { id: 12, name: 'Example App', platform: 'windows', policy: 'approved' },
  ];

  const mac = governance.policyMutation(policies, { name: 'Example App', platform: 'macos' }, 'approved');
  const windows = governance.policyMutation(policies, { name: 'Example App', platform: 'windows' }, 'unapproved');
  const any = governance.policyMutation(policies, { name: 'Example App', platform: 'any' }, 'unapproved');

  assert.deepEqual([mac.action, mac.exact.id, mac.platform], ['upsert', 11, 'macos']);
  assert.deepEqual([windows.action, windows.exact.id, windows.platform], ['upsert', 12, 'windows']);
  assert.deepEqual([any.action, any.exact.id, any.platform], ['upsert', 10, 'any']);
});

test('a contradictory stored name is not treated as the same full identity', () => {
  const shared = {
    id: 10, team_id: 'TEAM-EXAMPLE', bundle_id: 'com.example.app', name: 'Example App',
    platform: 'any', policy: 'approved',
  };
  const plan = governance.policyMutation([shared], {
    name: 'Renamed Example', platform: 'macos', team_id: 'team-example', identifier: 'com.example.app',
  }, 'unapproved');

  assert.equal(plan.action, 'upsert');
  assert.deepEqual(plan.identity, {
    team_id: 'team-example', bundle_id: 'com.example.app', name: 'Renamed Example',
  });
  assert.equal(plan.platform, 'macos');
});

test('shared Team ID cannot select or mutate a different bundle policy', () => {
  const appA = {
    id: 1, team_id: 'TEAM-SHARED', bundle_id: 'com.vendor.one', name: 'One',
    platform: 'macos', policy: 'approved', notes: 'One approval',
  };
  const appB = {
    id: 2, team_id: 'TEAM-SHARED', bundle_id: 'com.vendor.two', name: 'Two',
    platform: 'macos', policy: 'unapproved', notes: 'Two review',
  };
  const installedB = {
    team_id: 'TEAM-SHARED', bundle_id: 'com.vendor.two', name: 'Two',
    platform: 'macos', app_identity: 'team:TEAM-SHARED',
  };

  for (const policies of [[appA, appB], [appB, appA]]) {
    assert.equal(governance.findInstalledPolicy(policies, installedB).id, 2);
    const approve = governance.installedPolicyMutation(policies, installedB, 'approved');
    assert.equal(approve.action, 'upsert');
    assert.equal(approve.exact.id, 2);
    assert.deepEqual(approve.identity, {
      team_id: 'TEAM-SHARED', bundle_id: 'com.vendor.two', name: 'Two',
    });
    const clear = governance.installedPolicyMutation(policies, installedB, 'unmanaged');
    assert.equal(clear.exact.id, 2);
  }
});

test('more-specific matching tuple wins over a shared signer-only policy', () => {
  const signer = { id: 1, team_id: 'TEAM-SHARED', platform: 'macos', policy: 'approved' };
  const bundle = { id: 2, bundle_id: 'com.vendor.two', name: 'Two', platform: 'macos', policy: 'unapproved' };
  const app = { team_id: 'TEAM-SHARED', bundle_id: 'com.vendor.two', name: 'Two', platform: 'macos' };
  assert.equal(governance.findPolicy([signer, bundle], app).id, 2);
});

test('new-app decision enriches a unique stronger record and refuses ambiguity', () => {
  const existing = {
    id: 3, team_id: 'TEAM-SHARED', bundle_id: 'com.vendor.two', name: 'Two',
    platform: 'macos', policy: 'unapproved', notes: 'Reviewed exception', min_version: '4.2',
  };
  const discovery = {
    app_identity: 'team:team-shared', team_id: 'team-shared',
    bundle_id: 'com.vendor.two', name: 'Two', platform: 'macos',
  };
  const plan = governance.newAppPolicyMutation([existing], discovery, 'approved');
  assert.equal(plan.exact.id, 3);
  assert.deepEqual(governance.policyUpsertPayload(plan, 'approved'), {
    team_id: 'TEAM-SHARED', bundle_id: 'com.vendor.two', name: 'Two', platform: 'macos',
    policy: 'approved', enforcement_tier: 'report', notes: 'Reviewed exception', min_version: '4.2',
  });
  const ambiguous = governance.newAppPolicyMutation([
    existing,
    { ...existing, id: 4, bundle_id: 'com.vendor.other' },
  ], { app_identity: 'team:team-shared', name: 'Two', platform: 'macos' }, 'approved');
  assert.equal(ambiguous.action, 'unresolved');
});

test('only typed valid Windows Winget evidence resolves or writes a Winget policy', () => {
  const policy = { id: 8, winget_id: 'microsoft.visualstudiocode', platform: 'windows', policy: 'approved' };
  const app = {
    name: 'Visual Studio Code', platform: 'windows', winget_id: 'Microsoft.VisualStudioCode',
    identifier_kind: 'winget', app_identity: 'winget:Microsoft.VisualStudioCode',
  };
  assert.equal(governance.findInstalledPolicy([policy], app).id, 8);
  assert.equal(governance.installedPolicyMutation([policy], app, 'unmanaged').exact.id, 8);
  const discoveryPlan = governance.newAppPolicyMutation([policy], {
    name: 'Visual Studio Code', platform: 'windows',
    app_identity: 'winget:Microsoft.VisualStudioCode',
  }, 'unapproved');
  assert.equal(discoveryPlan.exact.id, 8);
  assert.equal(discoveryPlan.identity.winget_id, 'microsoft.visualstudiocode');

  const newWingetPlan = governance.newAppPolicyMutation([], {
    name: 'Visual Studio Code', platform: 'windows',
    app_identity: 'winget:Microsoft.VisualStudioCode',
  }, 'approved');
  assert.deepEqual(governance.policyUpsertPayload(newWingetPlan, 'approved'), {
    winget_id: 'Microsoft.VisualStudioCode', name: 'Visual Studio Code', platform: 'windows',
    policy: 'approved', enforcement_tier: 'report',
  });
  assert.equal(governance.newAppPolicyMutation([policy], {
    name: 'Visual Studio Code', platform: 'windows', app_identity: 'winget:bad..identifier',
  }, 'approved').action, 'unresolved');

  for (const untrusted of [
    { ...app, identifier_kind: 'native', app_identity: 'bundle:Microsoft.VisualStudioCode', bundle_id: 'Microsoft.VisualStudioCode' },
    { ...app, identifier_kind: '', app_identity: 'bundle:Microsoft.VisualStudioCode', bundle_id: 'Microsoft.VisualStudioCode' },
    { ...app, winget_id: 'bad..identifier', app_identity: 'winget:bad..identifier' },
  ]) {
    assert.equal(governance.findInstalledPolicy([policy], untrusted), null);
    assert.notEqual(governance.installedPolicyMutation([policy], untrusted, 'approved').identity.winget_id, 'microsoft.visualstudiocode');
  }
});

test('New Apps preserves a unique full matching tuple for opposite policies', () => {
  const reviewed = {
    id: 81, bundle_id: 'Microsoft.VisualStudioCode', winget_id: 'Microsoft.VisualStudioCode',
    name: 'Visual Studio Code', platform: 'windows', policy: 'unapproved',
  };
  const wingetDiscovery = {
    name: 'Visual Studio Code', platform: 'windows', app_identity: 'winget:Microsoft.VisualStudioCode',
    bundle_id: 'Microsoft.VisualStudioCode',
  };
  const approved = governance.newAppPolicyMutation([reviewed], wingetDiscovery, 'approved');
  assert.equal(approved.exact.id, 81);
  assert.deepEqual(governance.policyUpsertPayload(approved, 'approved'), {
    bundle_id: 'Microsoft.VisualStudioCode', winget_id: 'Microsoft.VisualStudioCode',
    name: 'Visual Studio Code', platform: 'windows', policy: 'approved', enforcement_tier: 'report',
  });

  const bundleDiscovery = {
    name: 'Visual Studio Code', platform: 'windows', app_identity: 'bundle:Microsoft.VisualStudioCode',
    winget_id: 'Microsoft.VisualStudioCode', identifier_kind: 'winget',
  };
  const unapproved = governance.newAppPolicyMutation([{ ...reviewed, policy: 'approved' }], bundleDiscovery, 'unapproved');
  assert.equal(unapproved.exact.id, 81);
  assert.deepEqual(governance.policyUpsertPayload(unapproved, 'unapproved'), {
    bundle_id: 'Microsoft.VisualStudioCode', winget_id: 'Microsoft.VisualStudioCode',
    name: 'Visual Studio Code', platform: 'windows', policy: 'unapproved', enforcement_tier: 'report',
  });

  const storedSpelling = {
    id: 82, bundle_id: 'com.vendor.MixedCase', name: 'Mixed Case',
    platform: 'macos', policy: 'approved',
  };
  const caseInsensitive = governance.newAppPolicyMutation([storedSpelling], {
    name: 'Mixed Case', platform: 'macos', app_identity: 'bundle:com.vendor.mixedcase',
  }, 'unapproved');
  assert.deepEqual(governance.policyUpsertPayload(caseInsensitive, 'unapproved'), {
    bundle_id: 'com.vendor.MixedCase', name: 'Mixed Case', platform: 'macos',
    policy: 'unapproved', enforcement_tier: 'report',
  });
});

test('New Apps cannot mutate a fuller tuple from one shared identity field', () => {
  const otherApp = {
    id: 83, team_id: 'TEAM-SHARED', bundle_id: 'com.vendor.app-a',
    platform: 'macos', policy: 'approved',
  };
  const discovery = {
    name: 'App B', platform: 'macos', app_identity: 'team:TEAM-SHARED',
  };

  const plan = governance.newAppPolicyMutation([otherApp], discovery, 'unapproved');
  assert.equal(plan.action, 'unresolved');
  assert.notEqual(plan.exact && plan.exact.id, 83);
  assert.notEqual(plan.identity.bundle_id, 'com.vendor.app-a');
});

test('New Apps refuses an ineffective decision against a fuller Winget tuple', () => {
  const existing = {
    id: 84, bundle_id: 'Microsoft.VisualStudioCode', winget_id: 'Microsoft.VisualStudioCode',
    name: 'Visual Studio Code', platform: 'windows', policy: 'unapproved',
  };
  const plan = governance.newAppPolicyMutation([existing], {
    name: 'Visual Studio Code', platform: 'windows',
    app_identity: 'winget:Microsoft.VisualStudioCode',
  }, 'approved');
  assert.equal(plan.action, 'unresolved');
});

test('async tenant switch preserves later pending edits and skips the old reload', async () => {
  const submittedA = {
    allowlist: { a: { tenantId: 'tenant-a', pendingGeneration: 1, name: 'A' } },
    policies: { a: { tenantId: 'tenant-a', pendingGeneration: 2, name: 'A policy' } },
  };
  const snapshot = governance.pendingSaveSnapshot('tenant-a', submittedA.allowlist, submittedA.policies);
  const currentB = {
    allowlist: { b: { tenantId: 'tenant-b', pendingGeneration: 3, name: 'B' } },
    policies: { b: { tenantId: 'tenant-b', pendingGeneration: 4, name: 'B policy' } },
  };

  await Promise.resolve();
  assert.equal(governance.settlePendingSave(snapshot, 'tenant-b', currentB.allowlist, currentB.policies), false);
  assert.deepEqual(Object.keys(currentB.allowlist), ['b']);
  assert.deepEqual(Object.keys(currentB.policies), ['b']);
});

test('same-tenant save completion does not reload over newer staged work', () => {
  const allowlist = {};
  const policies = {
    saved: { tenantId: 'tenant-a', pendingGeneration: 1, name: 'Saved' },
  };
  const snapshot = governance.pendingSaveSnapshot('tenant-a', allowlist, policies);
  policies.later = { tenantId: 'tenant-a', pendingGeneration: 2, name: 'Later' };

  assert.equal(governance.settlePendingSave(snapshot, 'tenant-a', allowlist, policies), false);
  assert.deepEqual(Object.keys(policies), ['later']);
});

test('platform policy precedence is specificity-first and weights Winget above bundle on Windows', () => {
  const policies = [
    { id: 1, bundle_id: 'com.vendor.app', platform: 'windows', policy: 'approved' },
    { id: 2, winget_id: 'vendor.app', platform: 'windows', policy: 'unapproved' },
    { id: 3, bundle_id: 'com.vendor.app', platform: 'macos', policy: 'approved' },
    { id: 4, winget_id: 'vendor.app', platform: 'macos', policy: 'unapproved' },
    { id: 5, team_id: 'TEAM', bundle_id: 'com.vendor.app', platform: 'windows', policy: 'mandatory' },
  ];
  const windows = {
    name: 'App', platform: 'windows', team_id: 'TEAM', bundle_id: 'com.vendor.app',
    winget_id: 'Vendor.App', identifier_kind: 'winget', app_identity: 'winget:Vendor.App',
  };
  const macos = { name: 'App', platform: 'macos', bundle_id: 'com.vendor.app', winget_id: 'Vendor.App' };

  assert.equal(governance.findInstalledPolicy(policies, windows).id, 5, 'higher field count wins first');
  assert.equal(governance.findPolicy(policies.slice(0, 2), windows).id, 2);
  assert.equal(governance.findPolicy(policies.slice(2, 4), macos).id, 3);
});

test('case-insensitive resolver grouping preserves the selected stored tuple for mutation', () => {
  const policy = { id: 10, bundle_id: 'Com.Vendor.App', platform: 'macos', policy: 'approved' };
  const plan = governance.policyMutation([policy], {
    name: 'App', platform: 'macos', bundle_id: 'com.vendor.app',
  }, 'unapproved');
  assert.equal(plan.exact.id, 10);
  assert.deepEqual(governance.policyUpsertPayload(plan, 'unapproved'), {
    bundle_id: 'Com.Vendor.App', platform: 'macos', policy: 'unapproved', enforcement_tier: 'report',
  });
});

test('case-distinct stored tuples use a deterministic id tie-break', () => {
  const upper = { id: 10, bundle_id: 'com.vendor.Two', platform: 'macos', policy: 'approved' };
  const lower = { id: 11, bundle_id: 'com.vendor.two', platform: 'macos', policy: 'unapproved' };
  const app = { name: 'Two', bundle_id: 'com.vendor.two', platform: 'macos', app_identity: 'bundle:com.vendor.two' };
  for (const policies of [[upper, lower], [lower, upper]]) {
    assert.equal(governance.findInstalledPolicy(policies, app).id, 10);
    assert.equal(governance.installedPolicyMutation(policies, app, 'unmanaged').exact.id, 10);
  }
});

test('installed classification upsert retains the existing policy metadata', () => {
  const existing = {
    id: 91, team_id: 'TEAM-EXAMPLE', bundle_id: 'com.example.app', name: 'Example App',
    platform: 'macos', policy: 'approved', enforcement_tier: 'managed',
    notes: 'Approved by security review', min_version: '4.2.0',
  };
  const app = {
    name: 'Example App', platform: 'macos', team_id: 'TEAM-EXAMPLE', bundle_id: 'com.example.app',
    app_identity: 'team:TEAM-EXAMPLE',
  };
  const plan = governance.installedPolicyMutation([existing], app, 'unapproved');
  const payload = governance.policyUpsertPayload(plan, 'unapproved');

  assert.deepEqual(payload, {
    team_id: 'TEAM-EXAMPLE', bundle_id: 'com.example.app', name: 'Example App',
    platform: 'macos', policy: 'unapproved', enforcement_tier: 'managed',
    notes: 'Approved by security review', min_version: '4.2.0',
  });
});

test('missing policy renders as unmanaged without dereferencing null', () => {
  assert.equal(governance.policyValue(null), 'unmanaged');
  assert.equal(governance.policyValue(undefined), 'unmanaged');
  assert.equal(governance.policyValue({ policy: 'approved' }), 'approved');
});

test('retained allowlist approval remains approved without an app-policy record', () => {
  assert.equal(governance.installedEffectivePolicy(null, null, 'allowed'), 'approved');
  assert.equal(governance.installedEffectivePolicy(null, { policy: 'unapproved' }, 'allowed'), 'unapproved');
  assert.equal(governance.installedEffectivePolicy({ policy: 'mandatory' }, { policy: 'approved' }, 'allowed'), 'mandatory');
});

test('inventory-status filters do not compare policy vocabulary', () => {
  const unreviewed = { status: 'unreviewed' };
  const system = { status: 'system_baseline' };

  assert.equal(governance.installedFilterMatches(unreviewed, 'unmanaged', 'unreviewed'), true);
  assert.equal(governance.installedFilterMatches(system, 'unmanaged', 'system_baseline'), true);
  assert.equal(governance.installedFilterMatches(system, 'unmanaged', 'unreviewed'), false);
  assert.equal(governance.installedFilterMatches(unreviewed, 'approved', 'approved'), true);
});
