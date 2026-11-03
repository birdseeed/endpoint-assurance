'use strict';
// Deliberately no API client, credentials, persistence or production imports.
const tenants = [
  { id: 'alder', name: 'Sample Alder', state: 'Degraded', access: 'Active', devices: '42', reporting: '31', seen: '12 min ago', onboarding: 'Active', platform: 'Windows + macOS' },
  { id: 'birch', name: 'Sample Birch', state: 'Active', access: 'Active', devices: '18', reporting: '18', seen: '4 min ago', onboarding: 'Active', platform: 'macOS' },
  { id: 'cedar', name: 'Sample Cedar', state: 'New', access: 'Active', devices: '0', reporting: '0', seen: 'No evidence yet', onboarding: 'Onboarding', platform: 'Not yet observed' },
  { id: 'delta', name: 'Sample Delta', state: 'Revoked', access: 'Revoked', devices: '9 historical', reporting: 'Not assessed', seen: 'Historical only', onboarding: 'Unavailable', platform: 'Windows' }
];
const main = document.querySelector('main');
const tenantSelect = document.querySelector('#tenant');
const roleSelect = document.querySelector('#role');
const stateSelect = document.querySelector('#state');
const dialog = document.querySelector('dialog');
const esc = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const badge = (text, type = '') => `<span class="badge ${type}">${esc(text)}</span>`;
const link = (hash, text) => `<a href="#${hash}">${esc(text)}</a>`;
const panel = (title, body) => `<section class="panel"><div class="panel-head"><h2>${title}</h2></div>${body}</section>`;
const table = (caption, heads, rows) => `<div class="table-wrap"><table><caption>${caption}</caption><thead><tr>${heads.map(h => `<th scope="col">${h}</th>`).join('')}</tr></thead><tbody>${rows.map(row => `<tr>${row.map(cell => `<td>${cell}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
const source = text => `<small>${text}</small>`;
const metric = (label, value, detail) => `<div class="metric"><span>${label}</span><strong>${value}</strong><small>${detail}</small></div>`;
let route = 'service';
let currentTenant = null;
function heading(title, subtitle) {
  return `<div class="page-head"><div><p class="eyebrow">OPERATOR WORKSPACE / ${currentTenant ? esc(currentTenant.name) : 'GLOBAL'}</p><h1>${esc(title)}</h1><p class="subtitle">${subtitle}</p></div><div class="stamp">SAMPLE SNAPSHOT<br>02 OCT 2026 · 14:32 UTC</div></div>`;
}
function availability() {
  return panel('Check coverage', `<div class="panel-body stack">
    <div>${badge('Some evidence available', 'success')}<small>Device report receipts, server checks, scheduled jobs and report delivery have sample source coverage.</small></div>
    <div>${badge('Partial evidence', 'warning')}<small>Reporting drops, evaluator delays and vulnerability-processing failures need confirmed measures and limits.</small></div>
    <div>${badge('Not available', 'unavailable')}<small>Intune connection status, signup progress and subscription events have no source here; no counts are inferred.</small></div>
  </div>`);
}
function service() {
  return heading('Service overview', 'Exceptions in Patched’s service. Customer posture stays in the customer portal.') +
    `<div class="metrics">${metric('Service exceptions', '3', 'Illustrative rows from supported source families')}${metric('Tenant-scoped exceptions', '1', 'A report delivery failure, not an estate rating')}${metric('Check coverage', 'Partial', 'Missing evidence is not a healthy result')}</div>` +
    `<div class="split"><div>${panel('Exceptions to investigate', table('Synthetic examples · ordered by service impact · no automatic remediation', ['Exception / evidence', 'Scope', 'Since', 'Next step'], [
      [`${badge('Needs a fresh check', 'unknown')}<strong>Dashboard version check</strong>${source('Checks whether the dashboard files match the last recorded deployment and have no unexpected edits.')}`, 'Service-wide', '14:06 UTC', link('operations', 'Inspect checks')],
      [`${badge('Failed', 'danger')}<strong>Report delivery failed</strong>${source('Delivery evidence; generation failure needs a separate source')}`, link('tenant/alder', 'Sample Alder'), '14:18 UTC', link('support/alder', 'Open support')],
      [`${badge('Needs attention', 'warning')}<strong>Server maintenance checks</strong>${source('Checks server settings for unexpected changes; this sample needs investigation.')}`, 'Service-wide', '14:25 UTC', link('operations', 'Inspect checks')]
    ]))}<p class="subtitle">“Since” is an illustrative incident onset here. Existing check evaluation timestamps alone do not prove onset.</p></div><div class="rail-panel">${panel('Service health', `<div class="panel-body stack"><div><h3>Receiving device reports</h3>${badge('Recent sample received', 'success')}<small>Latest device report received 14:31 UTC; available evidence does not show that every device has reported.</small></div><div><h3>Dashboard version check</h3>${badge('Not recently verified', 'unknown')}<small>Last checked 14:06 UTC. A stale result means this comparison has not been checked recently; it does not mean the release is old.</small></div><div><h3>Server maintenance checks</h3>${badge('Needs investigation', 'warning')}<small>Last checked 14:25 UTC. Checks server settings for unexpected changes.</small></div></div>`)}${availability()}</div></div>`;
}
function tenantRows(search = '', filter = 'all') {
  const rows = tenants.filter(t => t.name.toLowerCase().includes(search.toLowerCase()) && (filter === 'all' || t.state === filter));
  return table('Synthetic tenants · reporting counts are snapshot evidence, not trend detection', ['Tenant', 'Access / state', 'Reporting / known', 'Last evidence', 'Workspace'], rows.map(t => [
    `<strong>${link('tenant/' + t.id, t.name)}</strong>${source(t.platform)}`, `${badge(t.state, t.state === 'Degraded' ? 'warning' : t.state === 'Active' ? 'success' : '')}${source('Access: ' + t.access)}`,
    `${esc(t.reporting)} / ${esc(t.devices)}`, esc(t.seen), link('tenant/' + t.id, 'Open workspace')
  ])) + (!rows.length ? '<div class="state-card"><h2>No matching tenants</h2><p>Change the search or state filter.</p></div>' : '');
}
function directory() {
  return heading('Tenants', 'Identity, access and evidence freshness. Lifecycle controls stay separate from customer-owned settings.') +
    `<div class="metrics">${metric('Sample tenants', '4', 'All records in this preview are invented')}${metric('Reporting evidence', '49 / 60', 'Active access only; no trend implied')}${metric('Awaiting first evidence', '1', 'Not the first-useful-finding onboarding milestone')}</div>` +
    panel('Tenant directory', `<div class="toolbar"><label>Search tenants<input id="search" type="search" placeholder="Search by tenant name"></label><label>Tenant state<select id="filter"><option value="all">All states</option>${['Active', 'Degraded', 'New', 'Revoked'].map(s => `<option>${s}</option>`).join('')}</select></label></div><div id="tenant-rows">${tenantRows()}</div>`);
}
function tenantView(t) {
  const lifecycle = roleSelect.value === 'owner' ? `<p>Existing owner actions retain server authorisation, resource confirmation and audit. Controls below are inert examples.</p><div class="actions"><button disabled>${t.access === 'Revoked' ? 'Restore access' : 'Revoke access'} (preview only)</button><button disabled>Offboarding (preview only)</button></div>` : '<p>Owner role required for lifecycle changes. Consultant access remains governed by the existing server allow-list.</p>';
  return heading(t.name, 'Tenant workspace · Read-only evidence and lifecycle context') +
    `<div class="notice">${badge(t.state, t.state === 'Degraded' ? 'warning' : '')} <strong>Access: ${t.access}</strong> · ${t.platform} · Sample tenant ID: ${t.id}</div>` +
    `<div class="metrics">${metric('Reporting / known devices', `${t.reporting} / ${t.devices}`, 'Snapshot only; not evidence of a sharp drop')}${metric('Last evidence', t.seen, 'Missing evidence never clears a finding')}${metric('Recorded onboarding', t.onboarding, 'Local account field; no first-useful-finding claim')}</div>` +
    `<div class="split"><div>${panel('Customer-owned evidence', table('Support reads · future writes require the on-behalf-of workflow', ['Area', 'Current source', 'Operator treatment'], [
      ['Devices and dispositions', 'Device lifecycle + disposition records', 'Inspect evidence and history'],
      ['Software policy / assurance', 'Policies, CIS and CVE reads', 'Read-only support context'],
      ['Notifications / customer access', 'Webhooks + portal users', 'Inspect available records'],
      ['Benchmark selection / exclusions', badge('Not yet available', 'unavailable'), 'No guessed selection or history']
    ]))}${panel('Lifecycle controls', `<div class="panel-body">${lifecycle}</div>`)}</div><div>${panel('Requested support', `<div class="panel-body"><h3>See the customer’s view</h3><p>The real portal, a reproduced customer role and a tenant-bound, read-only session.</p><a class="button" href="#support/${t.id}">Support entry</a><p class="subtitle">Session capability: not yet available.</p></div>`)}</div></div>`;
}
function support(t) {
  return heading(`Support for ${t.name}`, 'Requested access to the real customer portal. No customer membership is granted.') +
    '<div class="notice warning"><strong>Not yet available.</strong> PAT-1967 must deliver a platform-enforced session before this entry can open the customer portal.</div>' +
    `<div class="split"><div>${panel('View customer portal', `<div class="panel-body"><dl><dt>Tenant</dt><dd>${t.name} · ${t.id}</dd><dt>Staff identity</dt><dd>Sample operator · ${esc(roleSelect.value)}</dd><dt>Required context</dt><dd>Support reference, reason and customer role</dd><dt>Session authority</dt><dd>Read-only, short-lived and immediately revocable</dd><dt>Customer history</dt><dd>Staff identity, reference, reason, role, start, end and expiry</dd></dl><div class="actions support-actions"><button class="primary" id="support-request">Preview support request</button>${link('tenant/' + t.id, 'Back to tenant')}</div></div>`)}${panel('Permanent portal banner contract', '<div class="panel-body"><p class="notice"><strong>Viewing as customer · [tenant name] · [customer role] · Read-only · Expires [server time]</strong></p><p>Shown by the real portal after a verified session. This is a design example, not an active session.</p><p>Page views, existing report downloads and attempted actions are audited. Email, invitations, new exports, webhook tests and configuration writes are denied by the API.</p></div>')}</div><div>${panel('Separate authority', '<div class="panel-body"><h3>On behalf of customer</h3><p>Requested changes leave the read-only session and use a separately authorised, audited workflow.</p><p>No write-mode switch belongs in the support session.</p></div>')}</div></div>`;
}
function operations() {
  return heading('Operations', 'Local operator checks and service records. Each result is a synthetic example; the time shown is when evidence was last checked or received.') +
    `<div class="metrics">${metric('Server checks', 'Sample only', 'No live server check was run for this preview')}${metric('Scheduled jobs', 'Partial sample', 'Missing or old run evidence remains visible')}${metric('Recovery actions', 'Owner controlled', 'Existing confirmation and audit gates remain')}</div>` +
    panel('Local operator checks', table('Existing examples are synthetic; every unintegrated check is explicitly unverified', ['Check', 'What it checks', 'Result and reason', 'Last checked / received'], [
      ['Receiving device reports', 'Shows the latest device report received and the available freshness evidence.', 'Sample report received. Available evidence does not show that every device has reported.', '14:31 UTC'],
      ['Dashboard version check', 'Checks the dashboard files match the last recorded deployment and have no unexpected edits.', 'Not recently verified. This means the comparison is overdue, not that the release is old.', '14:06 UTC'],
      ['Server maintenance checks', 'Checks server settings for unexpected changes, including configuration and security settings.', 'Needs investigation in this sample.', '14:25 UTC'],
      ['Declared server checks', 'Compares expected checks with the evidence recorded for them.', 'Not assessed; no result is available in this sample.', 'Not checked'],
      ['Scheduled jobs', 'Shows scheduled automation runs, next expected run, missed runs and repeated failures.', 'Not checked in this preview. No job run, schedule or trigger was inspected.', 'Not checked'],
      ['Outgoing email', 'Checks whether sending is enabled or in dry-run, authentication and send outcomes, plus bounce evidence where supported. Provider acceptance does not prove recipient receipt.', 'Not checked in this preview. No email setting or delivery evidence was inspected; delivery and bounce evidence may be unavailable.', 'Not checked'],
      ['Customer access setup', 'Compares customer access in the dashboard with the same email in the Cloudflare portal policy; shows pending or failed setup.', 'Not checked in this preview. Provisioning progress may be unavailable until connected.', 'Not checked'],
      ['Assurance processing', 'Checks CIS evaluation and CVE matching processing outcomes.', 'Unavailable until processing evidence and outcome reasons are integrated. No evaluation or matching run was checked.', 'Not checked'],
      ['Vulnerability data updates', 'Checks when vulnerability data was last updated and whether the update completed.', 'Unavailable until update evidence is integrated. No vulnerability data update was checked.', 'Not checked'],
      ['Report generation and delivery', 'Checks report creation separately from delivery to its destination.', 'Unavailable until generation and delivery evidence are integrated. No report was generated or delivered.', 'Not checked'],
      ['Backup jobs / last successful backup', 'Shows when each scheduled backup last completed successfully.', 'Not checked in this preview. No backup completion is demonstrated here.', 'Not checked'],
      ['Backup restore tests', 'Checks whether backup data was restored successfully in a test.', 'Not checked in this preview. Backup completion does not establish restore capability.', 'Not checked'],
      ['Server health', 'Checks service and database health, disk space and certificate expiry.', 'Not checked in this preview. No service, database, disk or certificate evidence was inspected.', 'Not checked'],
      ['Software version checks', 'Checks recorded deployed versions, unexpected file changes and failed deployments.', 'Not checked in this preview. No deployment or version evidence was inspected.', 'Not checked'],
      ['Billing connection and lifecycle', 'Checks provider connectivity, webhook failures and unreconciled lifecycle events once billing integration is available.', 'Unavailable until provider integration is available. No billing connection or lifecycle events were checked.', 'Not checked']
    ])) + panel('Service records', '<div class="panel-body stack"><div><h3>Server and backup records</h3><p>Host, disk, version, partition and backup evidence. Each source can be unavailable; this preview has not checked a backup.</p></div><div><h3>Scheduled jobs</h3><p>Automation run history and guarded triggers. Retired package jobs are historical records, not overdue work.</p></div><div><h3>Check coverage</h3><p>Shows which declared checks have evidence and which observations are missing.</p></div><div><h3>Administration</h3><p>Credentials, documentation and logs remain available under Operations. Logs remain owner-only. No credentials are loaded in this preview.</p></div></div>');
}
function intelligence() {
  return heading('Global intelligence', 'Global products only. Tenant observations and tenant identifiers do not belong in this workspace.') +
    '<div class="notice">Beta scope: navigation and existing read surfaces. Full benchmark publishing and identity curation remain PAT-1968 public-launch work.</div>' +
    panel('Current and planned sources', table('Source availability is from repository inspection, not a runtime API check', ['Surface', 'Source status', 'Beta treatment', 'Follow-up'], [
      ['Homebrew mapping review', badge('Read source exists', 'success'), '<code>/admin/homebrew/review</code><small>Tenant-free mapping evidence</small>', 'Retain existing review permissions'],
      ['Software category catalogue', badge('Read source exists', 'success'), '<code>/admin/shadow-it/catalogue</code><small>Category read, not the full identity review model</small>', 'Validate projection before reuse'],
      ['Benchmark library', badge('Not yet available', 'unavailable'), 'No dashboard library / publishing contract', 'PAT-1968 + PAT-1932'],
      ['Software identity confidence', badge('Not yet available', 'unavailable'), 'No complete global review contract', 'PAT-1968 + PAT-1874 / 1922']
    ])) + panel('Boundary: service queue versus global catalogue', '<div class="panel-body"><p>Software alerts contain tenant context. Keep them in a tenant-scoped support workflow, separate from the global product catalogue.</p><p>The retired deployment catalogue does not return. No installers, package labels, hosted payloads, rollout actions or endpoint actuation are introduced.</p></div>');
}
function render(focus = false) {
  const parts = location.hash.slice(1).split('/');
  route = parts[0] || 'service';
  currentTenant = ['tenant', 'support'].includes(route) ? tenants.find(t => t.id === parts[1]) : null;
  tenantSelect.value = currentTenant ? currentTenant.id : '';
  document.querySelectorAll('nav a').forEach(a => a.setAttribute('aria-current', a.dataset.page === (currentTenant ? 'tenants' : route) ? 'page' : 'false'));
  const state = stateSelect.value;
  main.setAttribute('aria-busy', String(state === 'loading'));
  const unavailable = (['tenant', 'support'].includes(route) && !currentTenant) || !['service', 'tenants', 'tenant', 'support', 'operations', 'intelligence'].includes(route);
  let content = unavailable ? heading('Preview route unavailable', 'This route is retired, unsupported or has no matching synthetic tenant.') + link('service', 'Return to service overview') : route === 'service' ? service() : route === 'tenants' ? directory() : route === 'tenant' ? tenantView(currentTenant) : route === 'support' ? support(currentTenant) : route === 'operations' ? operations() : intelligence();
  if (!unavailable && state === 'loading') content = heading('Loading sample evidence', 'Fixture state; no request is being sent.') + '<div class="state-card" role="status"><p>Waiting for source evidence. No healthy counts inferred.</p><div class="skeleton"></div><div class="skeleton"></div></div>';
  if (!unavailable && state === 'empty') content = heading(route === 'service' ? 'No exceptions in the available sources' : 'No sample records', 'An empty response is different from unavailable source coverage.') + '<div class="state-card"><p>Nothing returned by the available sample sources.</p><p>Unsupported sources remain unavailable; this is not an all-clear.</p></div>' + availability();
  if (!unavailable && state === 'error') content = heading('Sample source failed', 'Evidence cannot be loaded. Previously shown counts are not current.') + '<div class="notice error" role="alert"><p>Source unavailable. No tenant or service health conclusion can be drawn.</p><button id="retry">Retry sample</button></div>';
  if (!unavailable && state === 'degraded') content = '<div class="notice warning" role="status"><strong>Last known sample evidence</strong> · Refresh failed. Snapshot 14:32 UTC is stale; rows below are historical, not current health.</div>' + content;
  main.innerHTML = content;
  document.title = `${main.querySelector('h1').textContent} · Patched local preview`;
  if (focus) main.focus({ preventScroll: true });
}
window.addEventListener('hashchange', () => { if (location.hash === '#content') return; stateSelect.value = 'ready'; render(true); });
tenantSelect.addEventListener('change', () => { location.hash = tenantSelect.value ? `${route === 'support' ? 'support' : 'tenant'}/${tenantSelect.value}` : 'tenants'; });
roleSelect.addEventListener('change', () => render());
stateSelect.addEventListener('change', () => render());
main.addEventListener('input', event => { if (['search', 'filter'].includes(event.target.id)) document.querySelector('#tenant-rows').innerHTML = tenantRows(document.querySelector('#search').value, document.querySelector('#filter').value); });
main.addEventListener('change', event => { if (event.target.id === 'filter') document.querySelector('#tenant-rows').innerHTML = tenantRows(document.querySelector('#search').value, event.target.value); });
main.addEventListener('click', event => {
  if (event.target.id === 'retry') { stateSelect.value = 'ready'; render(true); }
  if (event.target.id === 'support-request') { dialog.querySelector('form').reset(); document.querySelector('#dialog-tenant').textContent = `Tenant: ${currentTenant.name} · ${currentTenant.id}`; dialog.showModal(); document.querySelector('#reference').focus(); }
});
dialog.addEventListener('keydown', event => {
  if (event.key !== 'Tab') return;
  const controls = [...dialog.querySelectorAll('input, textarea, select, button:not(:disabled)')];
  const target = event.shiftKey && document.activeElement === controls[0] ? controls.at(-1) : !event.shiftKey && document.activeElement === controls.at(-1) ? controls[0] : null;
  if (target) { event.preventDefault(); target.focus(); }
});
dialog.addEventListener('close', () => document.querySelector('#support-request')?.focus());
render();
