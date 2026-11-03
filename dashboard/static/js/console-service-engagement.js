/* PAT-1051: consultancy engagement form and derived executive outcome helpers. */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleServiceEngagement = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  function lines(value) {
    return String(value || '').split(/\r?\n/).map(function(item) { return item.trim(); }).filter(Boolean);
  }

  function formatLines(value) {
    return Array.isArray(value) ? value.join('\n') : '';
  }

  function links(value) {
    return lines(value).map(function(line) {
      var split = line.indexOf('|');
      return split === -1
        ? { label: line, url: line }
        : { label: line.slice(0, split).trim(), url: line.slice(split + 1).trim() };
    });
  }

  function formatLinks(value) {
    return Array.isArray(value) ? value.map(function(link) {
      return (link.label && link.label !== link.url ? link.label + ' | ' : '') + (link.url || '');
    }).join('\n') : '';
  }

  function conflictDraft(draft, server) {
    draft = Object.assign({}, draft || {});
    server = server && typeof server === 'object' ? server : null;
    if (!server || typeof server.updated_at !== 'string' || !server.updated_at) return null;
    var ignored = { expected_updated_at: true, updated_at: true, updated_by: true, tenant_id: true };
    var fields = [];
    var comparisons = [];
    Object.keys(draft).forEach(function(field) {
      if (ignored[field]) return;
      var localValue = draft[field] == null ? null : draft[field];
      var serverValue = server[field] == null ? null : server[field];
      if (JSON.stringify(localValue) !== JSON.stringify(serverValue)) {
        fields.push(field);
        comparisons.push({ field: field, local: localValue, server: serverValue });
      }
    });
    return { draft: draft, server: server, changedFields: fields, comparisons: comparisons };
  }

  function draftOutcomes() {
    return [outcome('Executive outcomes', 'Save to load evidence', 'unknown',
      'The draft has no outcome evidence yet. Save it to reconcile current evidence.')];
  }

  function createDOMOrchestrator(options) {
    options = options || {};
    var documentRef = options.document;
    var controller = options.controller;
    var conflictServer = null;
    var conflictPending = false;
    function element(id) { return documentRef && documentRef.getElementById(id); }
    function clearConflict() {
      conflictServer = null;
      conflictPending = false;
      var panel = element('service-conflict');
      var diff = element('service-conflict-diff');
      var save = element('service-save-btn');
      if (panel) panel.style.display = 'none';
      if (diff) diff.textContent = '';
      if (save) save.disabled = false;
    }
    function showPurgeCleanupFailure(result) {
      var headers = result && result.headers;
      var marker = headers && typeof headers.get === 'function' ?
        headers.get('X-Patched-Local-Cleanup') : null;
      if (marker !== 'service-engagement-failed') return false;
      var error = element('purge-err');
      var actions = element('purge-repair-actions');
      if (error) {
        error.textContent = 'Platform purge succeeded, but the local service snapshot remains. Preview it before repair.';
        error.style.display = 'block';
      }
      if (actions) actions.style.display = 'block';
      return true;
    }
    return {
      canSave: function() { return !conflictPending; },
      clearConflict: clearConflict,
      showConflict: function(conflict) {
        conflictServer = conflict.server;
        conflictPending = true;
        var panel = element('service-conflict');
        var diff = element('service-conflict-diff');
        var save = element('service-save-btn');
        if (diff) diff.textContent = conflict.comparisons.map(function(item) {
          return item.field + '\nLocal: ' + JSON.stringify(item.local) +
            '\nServer: ' + JSON.stringify(item.server);
        }).join('\n\n') || 'Only version metadata differs.';
        if (panel) panel.style.display = 'block';
        if (save) save.disabled = true;
      },
      reloadConflict: function(populate) {
        if (!conflictPending || !conflictServer) return null;
        var server = conflictServer;
        clearConflict();
        if (typeof populate === 'function') populate(server);
        return server;
      },
      startDraft: function(tenantId, draft, populate, renderOutcomes) {
        if (controller && typeof controller.startDraft === 'function') controller.startDraft(tenantId);
        if (typeof populate === 'function') populate(draft);
        if (typeof renderOutcomes === 'function') renderOutcomes(draftOutcomes());
      },
      removeComplete: function(tenantId, populate) {
        if (controller) {
          controller.invalidateEvidence(tenantId);
          controller.retry(['engagement']);
        }
        if (typeof populate === 'function') populate(null);
      },
      showPurgeCleanupFailure: showPurgeCleanupFailure,
      handlePurgeResult: function(result, onClean, onCleanupFailure) {
        if (showPurgeCleanupFailure(result)) {
          if (typeof onCleanupFailure === 'function') onCleanupFailure(result);
          return 'cleanup-failed';
        }
        if (typeof onClean === 'function') onClean(result);
        return 'clean';
      },
      runOrphanRequest: function(request, onSuccess, onFailure) {
        var promise;
        try { promise = request(); } catch (error) { promise = Promise.reject(error); }
        return Promise.resolve(promise).then(function(value) {
          if (typeof onSuccess === 'function') onSuccess(value);
          return { ok: true, value: value };
        }).catch(function(error) {
          if (typeof onFailure === 'function') onFailure(error);
          return { ok: false, error: error };
        });
      },
    };
  }

  function outcome(label, value, state, evidence) {
    return { label: label, value: value, state: state, evidence: evidence };
  }

  function nonNegativeInteger(value) {
    return typeof value === 'number' && Number.isInteger(value) && value >= 0;
  }

  function validAttention(value) {
    return validateAttention(value).ok;
  }

  function validateAttention(value) {
    if (value == null) return { ok: false, reason: 'fetch_failure' };
    if (value.__evidenceFailure) return { ok: false, reason: value.__evidenceFailure };
    if (value.degraded === true) return { ok: false, reason: 'degraded' };
    var summary = value.summary;
    var ok = !!summary && typeof summary === 'object' &&
      nonNegativeInteger(summary.total) &&
      nonNegativeInteger(summary.vulnerable) &&
      nonNegativeInteger(summary.out_of_date) &&
      nonNegativeInteger(summary.blocked);
    return { ok: ok, reason: ok ? null : 'contract_mismatch' };
  }

  function validReports(value) {
    return validateReports(value).ok;
  }

  function validReportRecord(record) {
    return !!record && typeof record === 'object' &&
        typeof record.id === 'string' && record.id.trim() !== '' &&
        typeof record.delivery_status === 'string' && record.delivery_status.trim() !== '' &&
        typeof record.archived === 'boolean' &&
        typeof record.generated_at === 'string' && Number.isFinite(Date.parse(record.generated_at));
  }

  function validateReports(value) {
    if (value == null) return { ok: false, reason: 'fetch_failure' };
    if (value.__evidenceFailure) return { ok: false, reason: value.__evidenceFailure };
    if (value.degraded === true) return { ok: false, reason: 'degraded' };
    if (!nonNegativeInteger(value.total) || !Array.isArray(value.records)) {
      return { ok: false, reason: 'contract_mismatch' };
    }
    if (!value.records.every(validReportRecord)) return { ok: false, reason: 'contract_mismatch' };
    var complete = value.total === value.records.length ||
      (value.completeThroughCutoff === true && value.records.length <= value.total);
    return { ok: complete, reason: complete ? null : 'partial' };
  }

  function appendReportPage(state, payload, requestedPage, maxRecords, maxPages, pageSlack, cutoffMs) {
    state = state || { records: [], ids: {}, total: null, perPage: null };
    maxRecords = nonNegativeInteger(maxRecords) ? maxRecords : 2000;
    maxPages = nonNegativeInteger(maxPages) && maxPages > 0 ? maxPages : 25;
    pageSlack = nonNegativeInteger(pageSlack) ? pageSlack : 2;
    var validEnvelope = !!payload && payload.degraded !== true &&
      nonNegativeInteger(payload.total) && Number.isInteger(payload.page) && payload.page > 0 &&
      Number.isInteger(payload.per_page) && payload.per_page > 0 &&
      payload.page === requestedPage && Array.isArray(payload.records) &&
      payload.records.length <= payload.per_page;
    if (!validEnvelope) {
      return {
        valid: false,
        reason: payload && payload.degraded === true ? 'degraded' : 'contract_mismatch',
        error: 'Invalid or inconsistent report page.',
      };
    }
    var expectedPages = payload.total === 0 ? 1 : Math.ceil(payload.total / payload.per_page);
    var pageLimit = Math.min(expectedPages + pageSlack, maxPages);
    if (requestedPage > pageLimit ||
        (state.total !== null && state.total !== payload.total) ||
        (state.perPage !== null && state.perPage !== payload.per_page)) {
      return {
        valid: false,
        reason: payload && payload.degraded === true ? 'degraded' :
          'partial',
        error: 'Invalid or inconsistent report page.',
      };
    }
    var records = state.records.slice();
    var ids = Object.assign({}, state.ids);
    var cutoffReached = state.cutoffReached === true;
    var previousGeneratedMs = state.previousGeneratedMs == null ? null : state.previousGeneratedMs;
    for (var i = 0; i < payload.records.length; i++) {
      var record = payload.records[i];
      if (!validReportRecord(record) || ids[record.id]) {
        return { valid: false, reason: 'contract_mismatch', error: 'Report pages contained a missing or duplicate record id.' };
      }
      var generatedMs = Date.parse(record.generated_at);
      if (previousGeneratedMs !== null && generatedMs > previousGeneratedMs) {
        return { valid: false, reason: 'contract_mismatch', error: 'Report records were not newest-first.' };
      }
      previousGeneratedMs = generatedMs;
      ids[record.id] = true;
      if (Number.isFinite(cutoffMs) && generatedMs < cutoffMs) {
        cutoffReached = true;
        break;
      }
      records.push(record);
    }
    if (records.length > payload.total || records.length > maxRecords ||
        (!payload.records.length && records.length < payload.total)) {
      return { valid: false, reason: 'partial', error: 'Report pagination ended before the declared total.' };
    }
    if (!cutoffReached && records.length < payload.total && payload.records.length < payload.per_page) {
      return { valid: false, reason: 'partial', error: 'Report pagination returned a short page before completion.' };
    }
    return {
      valid: true,
      done: cutoffReached || records.length === payload.total,
      records: records,
      ids: ids,
      total: payload.total,
      perPage: payload.per_page,
      expectedPages: expectedPages,
      pageLimit: pageLimit,
      cutoffReached: cutoffReached,
      completeThroughCutoff: cutoffReached || records.length === payload.total,
      previousGeneratedMs: previousGeneratedMs,
      nextPage: requestedPage + 1,
    };
  }

  function nextReportPage(state) {
    if (!state || state.valid !== true || state.done === true ||
        !Number.isInteger(state.expectedPages) || !Number.isInteger(state.pageLimit) ||
        !Number.isInteger(state.nextPage) || state.nextPage > state.pageLimit) return null;
    return state.nextPage;
  }

  function validMetering(value) {
    return validateMetering(value).ok;
  }

  function validateMetering(value) {
    if (value == null) return { ok: false, reason: 'fetch_failure' };
    if (value.__evidenceFailure) return { ok: false, reason: value.__evidenceFailure };
    if (value.degraded === true) return { ok: false, reason: 'degraded' };
    var envelope =
      typeof value.tenant_id === 'string' && value.tenant_id.trim() !== '' &&
      nonNegativeInteger(value.total) && Array.isArray(value.apps);
    if (!envelope) return { ok: false, reason: 'contract_mismatch' };
    if (value.total !== value.apps.length) return { ok: false, reason: 'partial' };
    var ok = value.apps.every(function(app) {
      var daysValid = app && (app.days_since_last_use === null ||
        (typeof app.days_since_last_use === 'number' && Number.isFinite(app.days_since_last_use) && app.days_since_last_use >= 0));
      var launchesValid = app && (app.total_launch_count === null ||
        (typeof app.total_launch_count === 'number' && Number.isFinite(app.total_launch_count) && app.total_launch_count >= 0));
      return !!app && typeof app === 'object' && daysValid && launchesValid &&
        typeof app.id === 'string' && typeof app.name === 'string' && typeof app.platform === 'string' &&
        nonNegativeInteger(app.device_count) &&
        Object.prototype.hasOwnProperty.call(app, 'last_used_at') &&
        Object.prototype.hasOwnProperty.call(app, 'metering_status_at') &&
        typeof app.metering_status === 'string' && app.metering_status.trim() !== '';
    });
    return { ok: ok, reason: ok ? null : 'contract_mismatch' };
  }

  function evidenceCacheable(evidence) {
    evidence = evidence || {};
    return validateAttention(evidence.attention).ok &&
      validateReports(evidence.reports).ok &&
      validateMetering(evidence.metering).ok;
  }

  function evidenceDiagnostic(source, validation) {
    var labels = { attention: 'Needs Attention', reports: 'Report records', metering: 'Software metering' };
    var label = labels[source] || 'Evidence';
    var reason = validation && validation.reason;
    if (reason === 'fetch_failure') return label + ' could not be fetched.';
    if (reason === 'degraded') return label + ' reported a degraded upstream response.';
    if (reason === 'partial') return label + ' returned an incomplete evidence set.';
    return label + ' response did not match the expected contract.';
  }

  function isCurrentLoad(context) {
    context = context || {};
    return context.activeView === 'service' &&
      context.requestedTenant === context.currentTenant &&
      context.requestedGeneration === context.currentGeneration;
  }

  function ownsLoad(context) {
    context = context || {};
    return context.requestedTenant === context.currentTenant &&
      context.requestedGeneration === context.currentGeneration;
  }

  function completionAction(context) {
    if (isCurrentLoad(context)) return 'render';
    if (ownsLoad(context)) return 'retry';
    return 'ignore';
  }

  function retryLoads(state, targets) {
    var next = Object.assign({}, state || {});
    targets = Array.isArray(targets) ? targets : [];
    if (targets.indexOf('engagement') !== -1) next.engagementLoadedTenant = null;
    if (targets.indexOf('outcomes') !== -1) next.outcomesLoadedTenant = null;
    return next;
  }

  function loadsNeeded(state, tenantId) {
    state = state || {};
    return {
      engagement: state.engagementLoadedTenant !== tenantId,
      outcomes: state.outcomesLoadedTenant !== tenantId,
    };
  }

  function outcomesForEngagement(engagement, outcomeCommand) {
    return engagement && outcomeCommand ? outcomeCommand : null;
  }

  function mutationCompletion(state, context, retryTargets) {
    var action = completionAction(context);
    return {
      action: action,
      state: action === 'retry' ? retryLoads(state, retryTargets) : Object.assign({}, state || {}),
    };
  }

  function settleCompletion(controller, context, retryTargets) {
    if (!controller || typeof controller.state !== 'function' || typeof controller.retry !== 'function') {
      return 'ignore';
    }
    var transition = mutationCompletion(controller.state(), context, retryTargets);
    if (transition.action === 'retry') controller.retry(retryTargets);
    return transition.action;
  }

  function createOrchestrationController(options) {
    options = options || {};
    var freshnessMs = nonNegativeInteger(options.freshnessMs) ? options.freshnessMs : 60000;
    var maxCachedTenants = nonNegativeInteger(options.maxCachedTenants) && options.maxCachedTenants > 0 ? options.maxCachedTenants : 10;
    var cache = new Map();
    var state = {
      tenant: null,
      engagementGeneration: 0,
      outcomesGeneration: 0,
      engagementLoadedTenant: null,
      outcomesLoadedTenant: null,
      outcomesInFlightTenant: null,
      hasEngagement: false,
      draftTenant: null,
    };
    function now() { return typeof options.now === 'function' ? options.now() : Date.now(); }
    function emit(command) {
      if (typeof options.onCommand === 'function') options.onCommand(command, Object.assign({}, state));
      return command;
    }
    function cacheGet(tenantId) {
      var item = cache.get(tenantId);
      if (!item || now() - item.storedAt > freshnessMs) {
        cache.delete(tenantId);
        return null;
      }
      cache.delete(tenantId);
      cache.set(tenantId, item);
      return item.value;
    }
    function cachePut(tenantId, value) {
      cache.delete(tenantId);
      cache.set(tenantId, { storedAt: now(), value: value });
      while (cache.size > maxCachedTenants) cache.delete(cache.keys().next().value);
    }
    var api = {
      state: function() { return Object.assign({}, state); },
      tenantChange: function(tenantId) {
        state.tenant = tenantId;
        state.engagementGeneration++;
        state.outcomesGeneration++;
        state.engagementLoadedTenant = null;
        state.outcomesLoadedTenant = null;
        state.outcomesInFlightTenant = null;
        state.hasEngagement = false;
        state.draftTenant = null;
        return emit({ type: 'tenant-change', tenantId: tenantId,
          engagementGeneration: state.engagementGeneration,
          outcomesGeneration: state.outcomesGeneration });
      },
      activate: function(tenantId) {
        state.tenant = tenantId;
        var command = { type: 'activate', tenantId: tenantId, engagement: null, outcomes: null };
        if (state.draftTenant === tenantId) return emit(command);
        if (state.engagementLoadedTenant !== tenantId) {
          state.engagementLoadedTenant = tenantId;
          command.engagement = { generation: ++state.engagementGeneration };
          return emit(command);
        }
        if (!state.hasEngagement) return emit(command);
        var cached = cacheGet(tenantId);
        if (cached) {
          state.outcomesLoadedTenant = tenantId;
          state.outcomesInFlightTenant = null;
          command.outcomes = { cached: true, evidence: cached };
        } else if (state.outcomesInFlightTenant !== tenantId) {
          state.outcomesLoadedTenant = tenantId;
          state.outcomesInFlightTenant = tenantId;
          command.outcomes = { cached: false, generation: ++state.outcomesGeneration };
        }
        return emit(command);
      },
      engagementResult: function(tenantId, generation, engagement) {
        if (tenantId !== state.tenant || generation !== state.engagementGeneration) return null;
        state.hasEngagement = !!engagement;
        state.draftTenant = null;
        if (!engagement) {
          state.engagementLoadedTenant = null;
          state.outcomesLoadedTenant = null;
          state.outcomesInFlightTenant = null;
          emit({ type: 'engagement-result', tenantId: tenantId, generation: generation, outcomes: null });
          return null;
        }
        var cached = cacheGet(tenantId);
        if (cached) {
          state.outcomesLoadedTenant = tenantId;
          var cachedCommand = { cached: true, evidence: cached };
          emit({ type: 'engagement-result', tenantId: tenantId, generation: generation, outcomes: cachedCommand });
          return cachedCommand;
        }
        if (state.outcomesInFlightTenant === tenantId) return null;
        state.outcomesLoadedTenant = tenantId;
        state.outcomesInFlightTenant = tenantId;
        var outcomeCommand = { cached: false, generation: ++state.outcomesGeneration };
        emit({ type: 'engagement-result', tenantId: tenantId, generation: generation, outcomes: outcomeCommand });
        return outcomeCommand;
      },
      save: function(tenantId) {
        state.tenant = tenantId;
        state.engagementLoadedTenant = tenantId;
        return emit({ type: 'save', tenantId: tenantId, generation: ++state.engagementGeneration });
      },
      startDraft: function(tenantId) {
        state.tenant = tenantId;
        state.draftTenant = tenantId;
        state.hasEngagement = true;
        state.engagementLoadedTenant = tenantId;
        state.outcomesLoadedTenant = null;
        state.outcomesInFlightTenant = null;
        return emit({ type: 'start-draft', tenantId: tenantId });
      },
      remove: function(tenantId) {
        state.tenant = tenantId;
        state.engagementLoadedTenant = tenantId;
        return emit({ type: 'remove', tenantId: tenantId, generation: ++state.engagementGeneration });
      },
      retry: function(targets) {
        state = Object.assign(state, retryLoads(state, targets));
        if (targets.indexOf('outcomes') !== -1) {
          state.outcomesGeneration++;
          state.outcomesInFlightTenant = null;
        }
        return emit({ type: 'retry', targets: targets.slice() });
      },
      storeOutcomes: function(tenantId, generation, evidence) {
        if (tenantId !== state.tenant || generation !== state.outcomesGeneration) return false;
        if (!evidenceCacheable(evidence)) {
          cache.delete(tenantId);
          state.outcomesLoadedTenant = null;
          state.outcomesInFlightTenant = null;
          return false;
        }
        cachePut(tenantId, evidence);
        state.outcomesLoadedTenant = tenantId;
        state.outcomesInFlightTenant = null;
        return true;
      },
      invalidateEvidence: function(tenantId) {
        cache.delete(tenantId);
        if (state.tenant === tenantId) {
          state.outcomesLoadedTenant = null;
          state.outcomesInFlightTenant = null;
          state.outcomesGeneration++;
        }
      },
    };
    return api;
  }

  function deriveOutcomes(evidence, options) {
    evidence = evidence || {};
    options = options || {};
    var nowMs = options.now ? Date.parse(options.now) : Date.now();
    if (!Number.isFinite(nowMs)) nowMs = Date.now();
    var attentionSource = evidence.attention;
    var attentionValidation = validateAttention(attentionSource);
    var attention = attentionValidation.ok ? attentionSource.summary : null;
    var reports = evidence.reports;
    var metering = evidence.metering;
    var result = [];
    if (!attention) {
      result.push(outcome('Risk posture', 'Unavailable', 'unknown', evidenceDiagnostic('attention', attentionValidation)));
      result.push(outcome('Patch exceptions', 'Unavailable', 'unknown', evidenceDiagnostic('attention', attentionValidation)));
    } else {
      var vulnerable = Number(attention.vulnerable || 0);
      var outdated = Number(attention.out_of_date || 0);
      var blocked = Number(attention.blocked || 0);
      var total = attention.total;
      result.push(outcome('Risk posture', total ? total + ' current signals' : 'No current signals', total ? 'attention' : 'clear', vulnerable + ' vulnerable, ' + outdated + ' out of date, ' + blocked + ' blocked.'));
      result.push(outcome('Patch exceptions', blocked ? blocked + ' blocked' : 'None reported', blocked ? 'attention' : 'clear', 'Derived from the current Needs Attention blocked count.'));
    }
    var reportsValidation = validateReports(reports);
    if (!reportsValidation.ok) {
      result.push(outcome('Evidence readiness', 'Unavailable', 'unknown', evidenceDiagnostic('reports', reportsValidation)));
    } else if (reports.records.some(function(record) {
      return ['pending', 'sent', 'failed'].indexOf(record.delivery_status) === -1;
    })) {
      result.push(outcome('Evidence readiness', 'Unavailable', 'unknown',
        'Report records include a delivery status this console does not yet understand.'));
    } else {
      var maxAgeMs = 90 * 24 * 60 * 60 * 1000;
      var currentReports = reports.records.filter(function(record) {
        var generatedMs = Date.parse(record.generated_at);
        var ageMs = nowMs - generatedMs;
        return !record.archived && record.delivery_status === 'sent' && ageMs >= 0 && ageMs <= maxAgeMs;
      });
      if (currentReports.length) {
        result.push(outcome('Evidence readiness', currentReports.length + ' current delivered report' + (currentReports.length === 1 ? '' : 's'), 'clear', 'Non-archived, successfully sent evidence generated within the documented 90-day readiness window.'));
      } else {
        result.push(outcome('Evidence readiness', 'Review evidence', 'attention', 'No non-archived successfully sent report was generated within the documented 90-day readiness window.'));
      }
    }
    var meteringValidation = validateMetering(metering);
    if (!meteringValidation.ok) {
      result.push(outcome('Licence-cost opportunities', 'Unavailable', 'unknown', evidenceDiagnostic('metering', meteringValidation)));
    } else if (metering.apps.some(function(app) {
      return ['ok', 'spotlight_disabled', 'no_user_session', 'unknown', 'mixed'].indexOf(app.metering_status) === -1;
    })) {
      result.push(outcome('Licence-cost opportunities', 'Unavailable', 'unknown',
        'Software metering includes a collection status this console does not yet understand.'));
    } else {
      var apps = Array.isArray(metering.apps) ? metering.apps : [];
      var reclaim = apps.filter(function(app) {
        var days = Number(app.days_since_last_use);
        var never = app.days_since_last_use == null && typeof app.total_launch_count === 'number' &&
          app.total_launch_count === 0 && app.metering_status === 'ok';
        var stale = app.metering_status === 'ok' && app.days_since_last_use != null &&
          Number.isFinite(days) && days >= 30;
        return never || stale;
      }).length;
      result.push(outcome('Licence-cost opportunities', reclaim ? reclaim + ' reclaim candidates' : 'None identified', reclaim ? 'attention' : 'clear', 'Derived from current software metering at a 30-day threshold.'));
    }
    return result;
  }

  return {
    appendReportPage: appendReportPage,
    completionAction: completionAction,
    conflictDraft: conflictDraft,
    createDOMOrchestrator: createDOMOrchestrator,
    createOrchestrationController: createOrchestrationController,
    deriveOutcomes: deriveOutcomes,
    draftOutcomes: draftOutcomes,
    evidenceCacheable: evidenceCacheable,
    formatLinks: formatLinks,
    formatLines: formatLines,
    isCurrentLoad: isCurrentLoad,
    ownsLoad: ownsLoad,
    mutationCompletion: mutationCompletion,
    settleCompletion: settleCompletion,
    outcomesForEngagement: outcomesForEngagement,
    retryLoads: retryLoads,
    lines: lines,
    links: links,
    loadsNeeded: loadsNeeded,
    nextReportPage: nextReportPage,
    validAttention: validAttention,
    validMetering: validMetering,
    validReports: validReports,
    validateAttention: validateAttention,
    validateMetering: validateMetering,
    validateReports: validateReports,
  };
});
