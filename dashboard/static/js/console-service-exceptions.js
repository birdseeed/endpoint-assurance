/* PAT-1966: partial service evidence, independent of customer posture/context. */
(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.PatchedServiceExceptions = api;
})(typeof window !== 'undefined' ? window : globalThis, function () {
  'use strict';
  var categories = {
    outgoing_email: 'Outgoing email', scheduled_jobs: 'Scheduled jobs',
    customer_access: 'Customer access setup', device_reports: 'Device reports',
    assurance_processing: 'Assurance processing', vulnerability_data: 'Vulnerability data updates',
    reports: 'Report generation and delivery', backups: 'Backups and restore tests',
    server_health: 'Server health', version_checks: 'Software version checks', billing: 'Billing connection'
  };
  var results = ['ok', 'failed', 'stale', 'unknown', 'unavailable'];
  var destinations = ['/console#ops', '/console#automations'];
  function isObject(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
  function string(value) { return typeof value === 'string' && value.trim().length > 0 && value.length <= 4096; }
  function id(value) { return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$/.test(value); }
  function time(value, now, nullable) {
    if (value === null && nullable) return true;
    if (typeof value !== 'string') return false;
    var parts = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|\+00:00)$/.exec(value);
    if (!parts) return false;
    var n = Date.parse(value), d = new Date(n);
    return Number.isFinite(n) && n <= now && +parts[1] >= 1970 &&
      d.getUTCFullYear() === +parts[1] && d.getUTCMonth() + 1 === +parts[2] &&
      d.getUTCDate() === +parts[3] && d.getUTCHours() === +parts[4] &&
      d.getUTCMinutes() === +parts[5] && d.getUTCSeconds() === +parts[6];
  }
  function unknown(key) {
    return {id: key, name: categories[key], explanation: 'Checks recorded ' + categories[key].toLowerCase() + ' evidence.',
      source: 'Service evidence validation', scope: 'Platform service', availability: 'unavailable', result: 'unknown',
      checked_at: null, last_success_at: null, next_expected_at: null, observations: [],
      reason: 'Source evidence is invalid or unavailable; current state is unknown.',
      next_action: 'Inspect the source evidence in Operations and retry.'};
  }
  function observation(row, now) {
    if (!isObject(row) || !id(row.id) || !string(row.scope) || !results.includes(row.result) ||
        !time(row.evidence_at, now, true) || !time(row.last_success_at, now, true) ||
        (['ok', 'failed', 'stale'].includes(row.result) && row.evidence_at === null)) return null;
    return {id: row.id, scope: row.scope, result: row.result, evidence_at: row.evidence_at, last_success_at: row.last_success_at};
  }
  function check(row, now) {
    if (!['available', 'degraded', 'unavailable'].includes(row.availability) || !results.includes(row.result) ||
        !['name', 'explanation', 'source', 'scope', 'reason', 'next_action'].every(function (k) { return string(row[k]); }) ||
        !time(row.checked_at, now, true) || !time(row.last_success_at, now, true) || row.next_expected_at !== null ||
        (row.availability === 'unavailable' && !['unknown', 'unavailable'].includes(row.result)) ||
        (['ok', 'failed', 'stale'].includes(row.result) && row.checked_at === null)) return null;
    var observations = row.observations === undefined ? [] : row.observations;
    if (!Array.isArray(observations) || observations.length > 256) return null;
    observations = observations.map(function (r) { return observation(r, now); });
    if (observations.some(function (r) { return !r; }) || new Set(observations.map(function (r) { return r.id; })).size !== observations.length) return null;
    var out = {};
    ['id', 'name', 'explanation', 'source', 'scope', 'availability', 'result', 'checked_at', 'last_success_at', 'next_expected_at', 'reason', 'next_action'].forEach(function (k) { out[k] = row[k]; });
    out.observations = observations;
    return out;
  }
  function exception(row, now) {
    if (!isObject(row) || !Object.hasOwn(categories, row.check_id) || !id(row.id) || !row.id.startsWith(row.check_id + ':') ||
        !string(row.scope) || !string(row.reason) || !destinations.includes(row.deep_link) ||
        !time(row.evidence_at, now, false) || !time(row.since, now, true) ||
        (row.since !== null && Date.parse(row.since) > Date.parse(row.evidence_at)) ||
        !(row.tenant_id === null || (typeof row.tenant_id === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(row.tenant_id)))) return null;
    var out = {};
    ['id', 'check_id', 'tenant_id', 'scope', 'since', 'evidence_at', 'reason', 'deep_link'].forEach(function (k) { out[k] = row[k]; });
    return out;
  }
  function project(body, now) {
    now = now === undefined ? Date.now() : now;
    if (!isObject(body) || body.coverage !== 'partial' || !time(body.observed_at, now, false) ||
        !Array.isArray(body.checks) || body.checks.length !== 11 || !Array.isArray(body.exceptions) || body.exceptions.length > 512) return null;
    var checks = {}, invalid = new Set(), seen = new Set(), exceptions = [];
    for (var row of body.checks) {
      if (!isObject(row) || !Object.hasOwn(categories, row.id) || Object.hasOwn(checks, row.id)) return null;
      checks[row.id] = check(row, now);
      if (!checks[row.id]) invalid.add(row.id);
    }
    for (var item of body.exceptions) {
      if (!isObject(item) || !Object.hasOwn(categories, item.check_id)) return null;
      var value = exception(item, now);
      if (!value || seen.has(value.id) || !checks[item.check_id] || !['failed', 'stale'].includes(checks[item.check_id].result)) invalid.add(item.check_id);
      else { seen.add(value.id); exceptions.push(value); }
    }
    invalid.forEach(function (key) { checks[key] = unknown(key); });
    return {observed_at: body.observed_at, coverage: 'partial',
      checks: Object.keys(categories).map(function (key) { return checks[key]; }),
      exceptions: exceptions.filter(function (row) { return !invalid.has(row.check_id); }), invalid: invalid.size > 0};
  }
  // All source text uses textContent. No source value becomes HTML or code.
  function element(tag, text, className) {
    var node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  }
  function appendTime(parent, value, missing) {
    if (!value) { parent.append(element('span', missing || 'Unknown')); return; }
    var node = element('time', new Date(value).toLocaleString('en-GB', {timeZone: 'UTC'}) + ' UTC');
    node.dateTime = value;
    node.title = value;
    parent.append(node);
  }
  function field(list, label, value, isTime) {
    list.append(element('dt', label));
    var content = element('dd');
    if (isTime) appendTime(content, value, label === 'Last checked' ? 'Not checked' : 'Unknown');
    else content.textContent = value;
    list.append(content);
  }
  function badge(result) {
    return element('span', {ok: 'Recorded OK', failed: 'Failed', stale: 'Stale evidence', unknown: 'Unknown', unavailable: 'Not available'}[result], 'service-result service-result-' + result);
  }
  function render(container, body) {
    container.replaceChildren();
    var summary = element('p', 'Partial coverage. Unavailable sources remain unknown.', 'service-coverage');
    summary.setAttribute('role', 'status');
    container.append(summary);
    var read = element('p', 'Source read: ', 'service-read-time');
    appendTime(read, body.observed_at);
    container.append(read);
    if (!body.exceptions.length) {
      container.append(element('p', body.invalid ? 'Some source evidence is invalid; exception coverage is unknown.' :
        'No recorded exceptions in the available evidence. This does not establish health for unavailable sources.', 'service-empty'));
    } else {
      var list = element('ul', undefined, 'service-exception-list');
      body.exceptions.forEach(function (row) {
        var item = element('li', undefined, 'service-exception');
        item.append(element('h3', categories[row.check_id]));
        item.append(element('p', row.reason));
        var fields = element('dl', undefined, 'service-evidence-fields');
        field(fields, 'Scope', row.scope);
        field(fields, 'Tenant', row.tenant_id || 'Platform service');
        field(fields, 'Evidence received', row.evidence_at, true);
        field(fields, 'Onset', row.since, true);
        item.append(fields);
        var link = element('a', row.deep_link === '/console#automations' ? 'Inspect job history' : 'Inspect infrastructure', 'service-evidence-link');
        link.href = row.deep_link;
        item.append(link);
        list.append(item);
      });
      container.append(list);
    }
    container.append(element('h3', 'Check coverage', 'service-check-heading'));
    var checks = element('div', undefined, 'service-checks');
    body.checks.forEach(function (row) {
      var detail = element('details', undefined, 'service-check');
      var heading = element('summary');
      heading.append(element('span', row.name), badge(row.result));
      detail.append(heading);
      var content = element('div', undefined, 'service-check-content');
      content.append(element('p', row.explanation));
      var fields = element('dl', undefined, 'service-evidence-fields');
      field(fields, 'Source', row.source);
      field(fields, 'Host / scope', row.scope);
      field(fields, 'Coverage', row.availability === 'degraded' ? 'Partial evidence' : row.availability === 'unavailable' ? 'Not available' : 'Available source');
      field(fields, 'Last checked', row.checked_at, true);
      field(fields, 'Last successful evidence', row.last_success_at, true);
      field(fields, 'Next expected run', row.next_expected_at, true);
      field(fields, 'Reason', row.reason);
      field(fields, 'Next action', row.next_action);
      content.append(fields);
      if (row.observations.length) {
        content.append(element('h4', 'Recorded observations'));
        row.observations.forEach(function (obs) {
          var observation = element('div', undefined, 'service-observation');
          observation.append(element('p', obs.scope), badge(obs.result));
          var times = element('dl', undefined, 'service-evidence-fields');
          field(times, 'Evidence received', obs.evidence_at, true);
          field(times, 'Last successful evidence', obs.last_success_at, true);
          observation.append(times);
          content.append(observation);
        });
      }
      detail.append(content);
      checks.append(detail);
    });
    container.append(checks);
  }
  var sequence = 0, lastLoaded = 0;
  function load(fetch, force) {
    var container = document.getElementById('home-service-exceptions');
    if (!container || (!force && lastLoaded && Date.now() - lastLoaded < 60000)) return;
    var request = ++sequence;
    lastLoaded = 0;
    container.setAttribute('aria-busy', 'true');
    var loading = element('p', 'Loading service exceptions…', 'console-loading');
    loading.setAttribute('role', 'status');
    container.replaceChildren(loading);
    return Promise.resolve().then(function () { return fetch('/admin/service-exceptions/proxy'); }).then(function (data) {
      if (request !== sequence) return;
      var body = project(data);
      if (!body) throw new Error('Invalid service evidence');
      render(container, body);
      lastLoaded = Date.now();
    }).catch(function () {
      if (request !== sequence) return;
      var error = element('p', 'Service exceptions unavailable. Source evidence could not be loaded or validated. Retry to check again.', 'home-inline-unavailable');
      error.setAttribute('role', 'alert');
      var retry = element('button', 'Retry service exceptions');
      retry.addEventListener('click', function () { load(fetch, true); });
      container.replaceChildren(error, retry);
    }).finally(function () { if (request === sequence) container.setAttribute('aria-busy', 'false'); });
  }
  return {project: project, load: load, render: render};
});
