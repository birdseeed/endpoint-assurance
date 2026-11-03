const test = require('node:test');
const assert = require('node:assert/strict');
const service = require('../../static/js/console-service-engagement.js');
const evidenceContracts = require('../fixtures/pat1051_evidence_contracts.json');

function pageRecord(id, generatedAt = '2026-08-14T10:00:00Z', deliveryStatus = 'sent') {
  return { id, generated_at: generatedAt, delivery_status: deliveryStatus, archived: false };
}

test('service snapshot textareas round-trip bounded line and link shapes', () => {
  assert.deepEqual(service.lines('Decision one\n\n Decision two '), ['Decision one', 'Decision two']);
  assert.deepEqual(service.links('Project | https://linear.app/patched/issue/PAT-1\nhttps://example.test/other'), [
    { label: 'Project', url: 'https://linear.app/patched/issue/PAT-1' },
    { label: 'https://example.test/other', url: 'https://example.test/other' },
  ]);
  assert.equal(service.formatLinks([{ label: 'Project', url: 'https://example.test/p' }]), 'Project | https://example.test/p');
  const canonical = 'Project | https://example.test/p\nhttps://example.test/other';
  assert.equal(service.formatLinks(service.links(canonical)), canonical);
});

test('executive outcomes are derived from evidence rather than editable snapshot fields', () => {
  const outcomes = service.deriveOutcomes({
    attention: evidenceContracts.needs_attention,
    reports: evidenceContracts.report_records,
    metering: evidenceContracts.metering,
  }, { now: '2026-08-15T12:00:00Z' });
  assert.deepEqual(outcomes.map((item) => item.value), [
    '8 current signals', '3 blocked', '1 current delivered report', '2 reclaim candidates',
  ]);
});

test('evidence readiness requires non-archived successfully sent evidence within 90 days', () => {
  function readiness(record, now = '2026-08-15T12:00:00Z') {
    return service.deriveOutcomes({
      attention: evidenceContracts.needs_attention,
      reports: { total: 1, records: [{ id: 'r', generated_at: '2026-08-14T10:00:00Z', delivery_status: 'sent', archived: false, ...record }] },
      metering: evidenceContracts.metering,
    }, { now })[2];
  }
  assert.equal(readiness({}).value, '1 current delivered report');
  assert.equal(readiness({ delivery_status: 'failed' }).value, 'Review evidence');
  assert.equal(readiness({ delivery_status: 'pending' }).value, 'Review evidence');
  assert.equal(readiness({ delivery_status: 'delivered' }).value, 'Unavailable');
  assert.equal(readiness({ archived: true }).value, 'Review evidence');
  assert.equal(readiness({ generated_at: '2026-10-01T10:00:00Z' }).value, 'Review evidence');
  assert.equal(readiness({ generated_at: 'not-a-date' }).value, 'Unavailable');
});

test('malformed or partial backend response shapes fail closed', () => {
  assert.equal(service.validAttention({ summary: { vulnerable: 0, blocked: 0 } }), false);
  assert.equal(service.validAttention(evidenceContracts.needs_attention), true);
  assert.equal(service.validReports({ total: 1, records: [{
    id: 'report-1', generated_at: '2026-08-14T10:00:00Z', delivery_status: 'sent', archived: false,
  }] }), true);
  assert.equal(service.validReports({ ...evidenceContracts.report_records, total: 2 }), false);
  assert.equal(service.validReports({ records: [{}], total: 1, page: 1, per_page: 20 }), false);
  assert.equal(service.validReports({ ...evidenceContracts.report_records, total: -1 }), false);
  assert.equal(service.validReports({ ...evidenceContracts.report_records, total: 1.5 }), false);
  assert.equal(service.validMetering({ apps: [{ days_since_last_use: 40 }] }), false);
  assert.equal(service.validMetering({ ...evidenceContracts.metering, total: 4 }), false);
  assert.equal(service.validReports({ degraded: true, records: [] }), false);
  const outcomes = service.deriveOutcomes({
    attention: { vulnerable: 0, out_of_date: 0, blocked: 0 },
    reports: { records: 'not-an-array' },
    metering: { apps: [{ days_since_last_use: 40 }] },
  });
  assert.deepEqual(outcomes.map((item) => item.value), [
    'Unavailable', 'Unavailable', 'Unavailable', 'Unavailable',
  ]);
});

test('report pages are bounded and reconciled to the declared total', () => {
  assert.equal(service.appendReportPage(null, null, 1, 2000, 25, 2).reason, 'contract_mismatch');
  assert.equal(service.appendReportPage(null, undefined, 1, 2000, 25, 2).reason, 'contract_mismatch');
  const first = service.appendReportPage(null, {
    page: 1, per_page: 2, total: 3, records: [pageRecord('newest'), pageRecord('middle', '2026-08-13T10:00:00Z')],
  }, 1, 10);
  assert.equal(first.valid, true);
  assert.equal(first.done, false);
  assert.equal(first.expectedPages, 2);
  assert.equal(first.pageLimit, 4);
  const complete = service.appendReportPage(first, {
    page: 2, per_page: 2, total: 3, records: [pageRecord('oldest', '2026-08-12T10:00:00Z')],
  }, 2, 10);
  assert.equal(complete.valid, true);
  assert.equal(complete.done, true);
  assert.deepEqual(complete.records.map((record) => record.id), ['newest', 'middle', 'oldest']);
  assert.equal(service.appendReportPage(first, {
    page: 2, per_page: 2, total: 4, records: [pageRecord('oldest', '2026-08-12T10:00:00Z')],
  }, 2, 10).valid, false);
  assert.equal(service.appendReportPage(first, {
    page: 2, per_page: 2, total: 3, records: [pageRecord('newest', '2026-08-12T10:00:00Z')],
  }, 2, 10).valid, false);
  assert.equal(service.appendReportPage(first, {
    page: 2, per_page: 2, total: 3, records: [],
  }, 2, 10).valid, false);
  assert.equal(service.appendReportPage(null, {
    page: 1, per_page: 100, total: 2001, records: [],
  }, 1, 2000).valid, false);
  let pageBound = null;
  for (let page = 1; page <= 25; page++) {
    pageBound = service.appendReportPage(pageBound, {
      page, per_page: 1, total: 30,
      records: [pageRecord(`bounded-${page}`, `2026-08-${String(31 - page).padStart(2, '0')}T10:00:00Z`)],
    }, page, 2000, 25, 2);
    assert.equal(pageBound.valid, true);
  }
  assert.equal(pageBound.done, false);
  assert.equal(service.nextReportPage(pageBound), null);
  assert.equal(service.nextReportPage(null), null);
  assert.equal(service.nextReportPage(undefined), null);
  assert.equal(service.appendReportPage(null, {
    page: 1, per_page: 3, total: 8, records: [pageRecord('one'), pageRecord('two', '2026-08-13T10:00:00Z')],
  }, 1, 2000, 25, 2).valid, false);
  assert.equal(service.appendReportPage(first, {
    page: 2, per_page: 3, total: 3, records: [pageRecord('oldest', '2026-08-12T10:00:00Z')],
  }, 2, 10, 25, 2).valid, false);
});

test('newest-first pagination stops safely at the 90-day boundary despite deep history', () => {
  const cutoff = Date.parse('2026-11-17T00:00:00Z');
  const state = service.appendReportPage(null, {
    page: 1, per_page: 100, total: 5000,
    records: [
      pageRecord('recent', '2026-08-14T10:00:00Z'),
      pageRecord('boundary-old', '2026-11-16T23:59:59Z'),
      pageRecord('older', '2020-01-01T00:00:00Z'),
    ],
  }, 1, 2000, 25, 2, cutoff);
  assert.equal(state.valid, true);
  assert.equal(state.done, true);
  assert.equal(state.cutoffReached, true);
  assert.deepEqual(state.records.map((record) => record.id), ['recent']);
  assert.equal(service.validReports({
    total: state.total, records: state.records,
    completeThroughCutoff: state.completeThroughCutoff,
  }), true);
});

test('typed validation reasons distinguish fetch, degraded, partial and contract drift', () => {
  assert.equal(service.validateAttention(null).reason, 'fetch_failure');
  assert.equal(service.validateAttention({ degraded: true }).reason, 'degraded');
  assert.equal(service.validateReports({ total: 2, records: [pageRecord('one')] }).reason, 'partial');
  assert.equal(service.validateReports({ total: '2', records: [] }).reason, 'contract_mismatch');
  assert.equal(service.validateMetering({ ...evidenceContracts.metering, total: 4 }).reason, 'partial');
  const diagnostics = [
    service.deriveOutcomes({})[0].evidence,
    service.deriveOutcomes({ attention: { degraded: true } })[0].evidence,
    service.deriveOutcomes({ reports: { total: 2, records: [pageRecord('one')] } })[2].evidence,
    service.deriveOutcomes({ reports: { total: 'bad', records: [] } })[2].evidence,
  ];
  assert.match(diagnostics[0], /could not be fetched/);
  assert.match(diagnostics[1], /degraded upstream response/);
  assert.match(diagnostics[2], /incomplete evidence set/);
  assert.match(diagnostics[3], /expected contract/);
});

test('reclaim candidates require healthy metering evidence for stale and never-used apps', () => {
  const metering = JSON.parse(JSON.stringify(evidenceContracts.metering));
  metering.apps[0].metering_status = 'unknown';
  metering.apps[1].metering_status = 'mixed';
  const outcomes = service.deriveOutcomes({
    attention: evidenceContracts.needs_attention,
    reports: evidenceContracts.report_records,
    metering,
  });
  assert.equal(outcomes[3].value, 'None identified');
});

test('metering accepts backend-null usage counters without fabricating a reclaim candidate', () => {
  const metering = {
    tenant_id: 'tenant-1', total: 1,
    apps: [{
      id: 'unknown', name: 'Unknown', platform: 'windows', device_count: 1,
      last_used_at: null, total_launch_count: null, days_since_last_use: null,
      metering_status: 'ok', metering_status_at: null,
    }],
  };
  assert.equal(service.validMetering(metering), true);
  const outcomes = service.deriveOutcomes({
    attention: evidenceContracts.needs_attention,
    reports: evidenceContracts.report_records,
    metering,
  });
  assert.equal(outcomes[3].value, 'None identified');
});

test('unknown metering status fails closed only for licence outcomes and remains cacheable', () => {
  ['ok', 'spotlight_disabled', 'no_user_session', 'unknown', 'mixed'].forEach((status) => {
    const metering = JSON.parse(JSON.stringify(evidenceContracts.metering));
    metering.apps[0].metering_status = status;
    assert.equal(service.validateMetering(metering).ok, true);
  });
  [null, ''].forEach((status) => {
    const metering = JSON.parse(JSON.stringify(evidenceContracts.metering));
    metering.apps[0].metering_status = status;
    assert.equal(service.validateMetering(metering).reason, 'contract_mismatch');
    assert.equal(service.deriveOutcomes({ metering })[3].value, 'Unavailable');
  });
  const metering = JSON.parse(JSON.stringify(evidenceContracts.metering));
  metering.apps[0].metering_status = 'future_status';
  const evidence = {
    attention: evidenceContracts.needs_attention,
    reports: evidenceContracts.report_records,
    metering,
  };
  assert.equal(service.validateMetering(metering).ok, true);
  assert.equal(service.evidenceCacheable(evidence), true);
  assert.deepEqual(service.deriveOutcomes(evidence, { now: '2026-08-15T12:00:00Z' })
    .map((item) => item.value), [
    '8 current signals', '3 blocked', '1 current delivered report', 'Unavailable',
  ]);
});

test('unknown report delivery status fails closed only for readiness and does not abort paging', () => {
  ['pending', 'sent', 'failed'].forEach((status) => {
    assert.equal(service.validateReports({ total: 1, records: [
      pageRecord(`report-${status}`, '2026-08-14T10:00:00Z', status),
    ] }).ok, true);
  });
  [null, ''].forEach((status) => {
    const record = pageRecord('unknown-delivery');
    record.delivery_status = status;
    assert.equal(service.validateReports({ total: 1, records: [record] }).reason, 'contract_mismatch');
  });
  const future = pageRecord('future-report', '2026-08-14T10:00:00Z', 'future');
  const reports = { total: 1, records: [future] };
  const page = service.appendReportPage(null, {
    page: 1, per_page: 100, total: 1, records: [future],
  }, 1, 2000, 25, 2);
  const evidence = {
    attention: evidenceContracts.needs_attention,
    reports,
    metering: evidenceContracts.metering,
  };
  assert.equal(service.validateReports(reports).ok, true);
  assert.equal(page.valid, true);
  assert.equal(page.done, true);
  assert.equal(service.evidenceCacheable(evidence), true);
  assert.deepEqual(service.deriveOutcomes(evidence, { now: '2026-08-15T12:00:00Z' })
    .map((item) => item.value), [
    '8 current signals', '3 blocked', 'Unavailable', '2 reclaim candidates',
  ]);
});

test('save conflict preserves the original token and exposes local and server values', () => {
  const draft = {
    expected_updated_at: '2026-08-15T08:00:00Z',
    service_name: 'Managed Patching',
    named_specialist: 'Draft specialist',
    decisions: ['Keep this unsaved decision'],
    project_links: [{ label: 'Draft project', url: 'https://example.test/draft' }],
  };
  const server = {
    updated_at: '2026-08-15T09:00:00Z',
    service_name: 'Endpoint Assurance',
    named_specialist: 'Server specialist',
    decisions: ['Server decision'],
    project_links: [],
  };
  const result = service.conflictDraft(draft, server);
  assert.notEqual(result.draft, draft);
  assert.equal(result.draft.expected_updated_at, '2026-08-15T08:00:00Z');
  assert.equal(result.draft.service_name, draft.service_name);
  assert.equal(result.draft.named_specialist, draft.named_specialist);
  assert.deepEqual(result.draft.decisions, draft.decisions);
  assert.deepEqual(result.draft.project_links, draft.project_links);
  assert.deepEqual(result.changedFields.sort(), [
    'decisions', 'named_specialist', 'project_links', 'service_name',
  ]);
  assert.deepEqual(result.comparisons.find((item) => item.field === 'service_name'), {
    field: 'service_name', local: 'Managed Patching', server: 'Endpoint Assurance',
  });
  assert.equal(draft.expected_updated_at, '2026-08-15T08:00:00Z');
});

test('DOM conflict flow shows the resolution control and reload re-enables save', () => {
  const elements = {
    'service-conflict': { style: { display: 'none' } },
    'service-conflict-diff': { style: {}, textContent: '' },
    'service-conflict-reload': { style: {}, textContent: 'Reload server version' },
    'service-save-btn': { style: {}, disabled: false },
  };
  const fakeDocument = { getElementById: (id) => elements[id] || null };
  const ui = service.createDOMOrchestrator({ document: fakeDocument });
  const draft = { expected_updated_at: 'old', service_name: 'Managed Patching' };
  const server = { updated_at: 'new', service_name: 'Endpoint Assurance' };
  ui.showConflict(service.conflictDraft(draft, server));
  assert.equal(elements['service-conflict'].style.display, 'block');
  assert.equal(elements['service-conflict-reload'].textContent, 'Reload server version');
  assert.notEqual(elements['service-conflict-reload'].style.display, 'none');
  assert.match(elements['service-conflict-diff'].textContent, /Local: "Managed Patching"/);
  assert.match(elements['service-conflict-diff'].textContent, /Server: "Endpoint Assurance"/);
  assert.equal(elements['service-save-btn'].disabled, true);
  assert.equal(ui.canSave(), false);
  let populated = null;
  assert.equal(ui.reloadConflict((value) => { populated = value; }), server);
  assert.equal(populated, server);
  assert.equal(elements['service-conflict'].style.display, 'none');
  assert.equal(elements['service-save-btn'].disabled, false);
  assert.equal(ui.canSave(), true);
});

test('DOM draft navigation and remove then add retain only the current draft state', () => {
  const controller = service.createOrchestrationController();
  controller.tenantChange('tenant-a');
  const ui = service.createDOMOrchestrator({
    document: { getElementById: () => null }, controller,
  });
  let form = null;
  let outcomes = null;
  const firstDraft = { service_name: 'Endpoint Assurance', named_specialist: 'Unsaved' };
  ui.startDraft('tenant-a', firstDraft, (value) => { form = value; }, (value) => { outcomes = value; });
  assert.equal(form, firstDraft);
  assert.equal(outcomes[0].value, 'Save to load evidence');
  assert.equal(controller.state().engagementLoadedTenant, 'tenant-a');
  assert.equal(controller.state().draftTenant, 'tenant-a');
  const returnFromSubview = controller.activate('tenant-a');
  assert.equal(returnFromSubview.engagement, null);
  assert.equal(returnFromSubview.outcomes, null);
  assert.equal(form.named_specialist, 'Unsaved');

  ui.removeComplete('tenant-a', (value) => { form = value; });
  assert.equal(form, null);
  assert.equal(controller.state().engagementLoadedTenant, null);
  const replacement = { service_name: 'Managed Patching', named_specialist: 'Replacement' };
  ui.startDraft('tenant-a', replacement, (value) => { form = value; }, (value) => { outcomes = value; });
  assert.equal(form, replacement);
  assert.equal(outcomes[0].value, 'Save to load evidence');
  assert.equal(controller.activate('tenant-a').engagement, null);
});

test('purge cleanup failure exposes owner preview and repair actions', () => {
  const elements = {
    'purge-err': { style: { display: 'none' }, textContent: '' },
    'purge-repair-actions': { style: { display: 'none' } },
  };
  const ui = service.createDOMOrchestrator({
    document: { getElementById: (id) => elements[id] || null },
  });
  const callbacks = [];
  const result = {
    headers: { get: (name) => name === 'X-Patched-Local-Cleanup' ? 'service-engagement-failed' : null },
  };
  const failed = ui.handlePurgeResult(
    result,
    () => callbacks.push('clean'),
    () => callbacks.push('cleanup-failed'),
  );
  assert.equal(failed, 'cleanup-failed');
  assert.deepEqual(callbacks, ['cleanup-failed']);
  assert.equal(elements['purge-err'].style.display, 'block');
  assert.match(elements['purge-err'].textContent, /snapshot remains/);
  assert.equal(elements['purge-repair-actions'].style.display, 'block');
  assert.equal(ui.handlePurgeResult(
    { headers: { get: () => null } },
    () => callbacks.push('clean'),
    () => callbacks.push('unexpected-failure'),
  ), 'clean');
  assert.deepEqual(callbacks, ['cleanup-failed', 'clean']);
});

test('orphan request adapter distinguishes success and failure callbacks', async () => {
  const ui = service.createDOMOrchestrator({ document: { getElementById: () => null } });
  const callbacks = [];
  const success = await ui.runOrphanRequest(
    () => Promise.resolve({ engagement: { service_name: 'Endpoint Assurance' } }),
    (value) => callbacks.push(['success', value.engagement.service_name]),
    () => callbacks.push(['failure']),
  );
  assert.equal(success.ok, true);
  assert.equal(success.value.engagement.service_name, 'Endpoint Assurance');
  assert.deepEqual(callbacks, [['success', 'Endpoint Assurance']]);

  const failure = await ui.runOrphanRequest(
    () => Promise.reject(new Error('repair refused')),
    () => callbacks.push(['unexpected-success']),
    (error) => callbacks.push(['failure', error.message]),
  );
  assert.equal(failure.ok, false);
  assert.equal(failure.error.message, 'repair refused');
  assert.deepEqual(callbacks, [
    ['success', 'Endpoint Assurance'],
    ['failure', 'repair refused'],
  ]);
});

test('starting a replacement draft exposes an explicit empty outcome state', () => {
  assert.deepEqual(service.draftOutcomes(), [{
    label: 'Executive outcomes',
    value: 'Save to load evidence',
    state: 'unknown',
    evidence: 'The draft has no outcome evidence yet. Save it to reconcile current evidence.',
  }]);
});

test('tenant and generation gate prevents stale or hidden async responses writing UI', () => {
  const current = {
    requestedTenant: 'tenant-a', currentTenant: 'tenant-a',
    requestedGeneration: 4, currentGeneration: 4, activeView: 'service',
  };
  assert.equal(service.isCurrentLoad(current), true);
  assert.equal(service.isCurrentLoad({ ...current, currentTenant: 'tenant-b' }), false);
  assert.equal(service.isCurrentLoad({ ...current, currentGeneration: 5 }), false);
  assert.equal(service.isCurrentLoad({ ...current, activeView: 'profile' }), false);
  assert.equal(service.ownsLoad({ ...current, activeView: 'profile' }), true);
  assert.equal(service.ownsLoad({ ...current, currentGeneration: 5 }), false);
});

test('hidden success and failure completions are owned for retry but cannot render', () => {
  ['success', 'failure'].forEach(() => {
    const hiddenCompletion = {
      requestedTenant: 'tenant-a', currentTenant: 'tenant-a',
      requestedGeneration: 7, currentGeneration: 7, activeView: null,
    };
    assert.equal(service.isCurrentLoad(hiddenCompletion), false);
    assert.equal(service.ownsLoad(hiddenCompletion), true);
  });
});

test('mutation completion makes hidden delete retry both loads without touching a newer tenant', () => {
  const loaded = { engagementLoadedTenant: 'tenant-a', outcomesLoadedTenant: 'tenant-a' };
  const hidden = service.mutationCompletion(loaded, {
    requestedTenant: 'tenant-a', currentTenant: 'tenant-a',
    requestedGeneration: 7, currentGeneration: 7, activeView: null,
  }, ['engagement', 'outcomes']);
  assert.equal(hidden.action, 'retry');
  assert.deepEqual(hidden.state, { engagementLoadedTenant: null, outcomesLoadedTenant: null });
  assert.deepEqual(service.loadsNeeded(hidden.state, 'tenant-a'), {
    engagement: true, outcomes: true,
  });

  const switched = service.mutationCompletion({
    engagementLoadedTenant: 'tenant-b', outcomesLoadedTenant: 'tenant-b',
  }, {
    requestedTenant: 'tenant-a', currentTenant: 'tenant-b',
    requestedGeneration: 7, currentGeneration: 8, activeView: 'service',
  }, ['engagement', 'outcomes']);
  assert.equal(switched.action, 'ignore');
  assert.deepEqual(switched.state, {
    engagementLoadedTenant: 'tenant-b', outcomesLoadedTenant: 'tenant-b',
  });
});

test('current delete completion renders while retry transition is reserved for owned hidden work', () => {
  const context = {
    requestedTenant: 'tenant-a', currentTenant: 'tenant-a',
    requestedGeneration: 4, currentGeneration: 4, activeView: 'service',
  };
  assert.equal(service.completionAction(context), 'render');
  assert.equal(service.completionAction({ ...context, activeView: null }), 'retry');
  assert.equal(service.completionAction({ ...context, currentGeneration: 5 }), 'ignore');
});

test('stale engagement success or failure cannot advance the current tenant outcomes generation', () => {
  ['success', 'failure'].forEach(() => {
    const controller = service.createOrchestrationController();
    controller.tenantChange('tenant-a');
    const stale = controller.activate('tenant-a').engagement;
    controller.tenantChange('tenant-b');
    const current = controller.activate('tenant-b').engagement;
    const before = controller.state();
    const action = service.settleCompletion(controller, {
      requestedTenant: 'tenant-a', currentTenant: 'tenant-b',
      requestedGeneration: stale.generation,
      currentGeneration: current.generation,
      activeView: 'service',
    }, ['engagement', 'outcomes']);
    const after = controller.state();
    assert.equal(action, 'ignore');
    assert.equal(after.engagementGeneration, before.engagementGeneration);
    assert.equal(after.outcomesGeneration, before.outcomesGeneration);
    assert.equal(after.engagementLoadedTenant, 'tenant-b');
  });
});

test('owned hidden engagement completion marks both loads retryable', () => {
  const controller = service.createOrchestrationController();
  controller.tenantChange('tenant-a');
  const request = controller.activate('tenant-a').engagement;
  const before = controller.state();
  const action = service.settleCompletion(controller, {
    requestedTenant: 'tenant-a', currentTenant: 'tenant-a',
    requestedGeneration: request.generation,
    currentGeneration: request.generation,
    activeView: null,
  }, ['engagement', 'outcomes']);
  const after = controller.state();
  assert.equal(action, 'retry');
  assert.equal(after.engagementLoadedTenant, null);
  assert.equal(after.outcomesLoadedTenant, null);
  assert.equal(after.outcomesGeneration, before.outcomesGeneration + 1);
});

test('template-bound orchestration commands carry real generations and cache outcomes across views', () => {
  let now = 1000;
  const fakeDom = { commands: [] };
  const fakeFetch = [];
  const controller = service.createOrchestrationController({
    now: () => now,
    freshnessMs: 100,
    maxCachedTenants: 2,
    onCommand: (command) => {
      fakeDom.commands.push(command.type);
      if (command.type === 'activate') {
        if (command.engagement) fakeFetch.push({ type: 'engagement', generation: command.engagement.generation });
        if (command.outcomes && !command.outcomes.cached) fakeFetch.push({ type: 'outcomes', generation: command.outcomes.generation });
      } else if (command.type === 'engagement-result' && command.outcomes && !command.outcomes.cached) {
        fakeFetch.push({ type: 'outcomes', generation: command.outcomes.generation });
      } else if (['save', 'remove'].includes(command.type)) {
        fakeFetch.push({ type: command.type, generation: command.generation });
      }
    },
  });
  const changed = controller.tenantChange('tenant-a');
  assert.equal(changed.engagementGeneration, 1);
  assert.equal(changed.outcomesGeneration, 1);
  const activated = controller.activate('tenant-a');
  assert.equal(activated.engagement.generation, 2);
  assert.equal(activated.outcomes, null);
  const firstOutcomes = controller.engagementResult(
    'tenant-a', activated.engagement.generation, { service_name: 'Endpoint Assurance' }
  );
  assert.equal(firstOutcomes.generation, 2);
  const evidence = {
    attention: evidenceContracts.needs_attention,
    reports: evidenceContracts.report_records,
    metering: evidenceContracts.metering,
  };
  assert.equal(controller.storeOutcomes('tenant-a', 2, evidence), true);
  const reopenedAcrossSubview = controller.activate('tenant-a');
  assert.equal(reopenedAcrossSubview.engagement, null);
  assert.equal(reopenedAcrossSubview.outcomes.cached, true);
  assert.equal(reopenedAcrossSubview.outcomes.evidence, evidence);
  const saved = controller.save('tenant-a');
  const removed = controller.remove('tenant-a');
  assert.equal(saved.generation, 3);
  assert.equal(removed.generation, 4);
  controller.retry(['engagement', 'outcomes']);
  const returned = controller.activate('tenant-a');
  assert.equal(returned.engagement.generation, 5);
  assert.equal(returned.outcomes, null);
  const returnedOutcomes = controller.engagementResult(
    'tenant-a', returned.engagement.generation, { service_name: 'Endpoint Assurance' }
  );
  assert.equal(returnedOutcomes.cached, true);
  assert.equal(returnedOutcomes.evidence, evidence);
  assert.deepEqual(fakeDom.commands.slice(0, 6), ['tenant-change', 'activate', 'engagement-result', 'activate', 'save', 'remove']);
  assert.deepEqual(fakeFetch.slice(0, 4), [
    { type: 'engagement', generation: 2 },
    { type: 'outcomes', generation: 2 },
    { type: 'save', generation: 3 },
    { type: 'remove', generation: 4 },
  ]);
  now = 1200;
  controller.retry(['outcomes']);
  const expired = controller.activate('tenant-a');
  assert.equal(expired.outcomes.cached, false);
  assert.equal(expired.outcomes.generation, controller.state().outcomesGeneration);
});

test('null, failed or degraded outcome bundles are never cached and retry immediately', () => {
  [
    { attention: null, reports: evidenceContracts.report_records, metering: evidenceContracts.metering },
    { attention: evidenceContracts.needs_attention, reports: { __evidenceFailure: 'fetch_failure' }, metering: evidenceContracts.metering },
    { attention: evidenceContracts.needs_attention, reports: evidenceContracts.report_records, metering: { degraded: true } },
  ].forEach((evidence) => {
    const controller = service.createOrchestrationController();
    controller.tenantChange('tenant-a');
    const engagement = controller.activate('tenant-a').engagement;
    const outcomes = controller.engagementResult(
      'tenant-a', engagement.generation, { service_name: 'Endpoint Assurance' }
    );
    assert.equal(service.evidenceCacheable(evidence), false);
    assert.equal(controller.storeOutcomes('tenant-a', outcomes.generation, evidence), false);
    assert.equal(controller.state().outcomesLoadedTenant, null);
    const retry = controller.activate('tenant-a').outcomes;
    assert.equal(retry.cached, false);
    assert.ok(retry.generation > outcomes.generation);
  });
});

test('no-service engagement result schedules zero outcome evidence requests', () => {
  const controller = service.createOrchestrationController();
  controller.tenantChange('tenant-none');
  const activation = controller.activate('tenant-none');
  const fakeFetch = [{ type: 'engagement', generation: activation.engagement.generation }];
  const afterNullGet = controller.engagementResult('tenant-none', activation.engagement.generation, null);
  if (afterNullGet) fakeFetch.push({ type: 'outcomes', generation: afterNullGet.generation });
  assert.deepEqual(fakeFetch, [{ type: 'engagement', generation: 2 }]);
  const retry = controller.activate('tenant-none');
  const afterServiceGet = controller.engagementResult(
    'tenant-none', retry.engagement.generation, { service_name: 'Endpoint Assurance' }
  );
  assert.equal(afterServiceGet.generation, 2);
});

test('missing evidence fails closed to explicit unavailable outcomes', () => {
  const outcomes = service.deriveOutcomes({});
  assert.deepEqual(outcomes.map((item) => item.value), [
    'Unavailable', 'Unavailable', 'Unavailable', 'Unavailable',
  ]);
  assert.ok(outcomes.every((item) => item.state === 'unknown'));
});
