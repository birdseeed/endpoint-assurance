const test = require('node:test');
const assert = require('node:assert/strict');
const { renderServiceHealth } = require('../../static/js/console-work.js');

// Exercise the existing browser-loaded renderer, not a proposed component API.
const now = Date.UTC(2026, 9, 3, 12);
function render(evidence) {
  const container = { innerHTML: '' };
  const result = renderServiceHealth(container, evidence, {
    now,
    escape: value => String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'),
    relativeTime: () => '1 hour ago',
  });
  return { html: container.innerHTML, result };
}

test('operator checks describe receiving reports and its observation age in plain language', () => {
  const { html } = render({
    db_reachable: true,
    ingestion_freshness: { most_recent_ingest_at: '2026-10-03T11:00:00Z' },
  });
  assert.match(html, /Receiving device reports/i);
  assert.match(html, /1 hour ago/);
  assert.match(html, /not.*all devices|coverage.*unknown|coverage.*not/i);
  assert.doesNotMatch(html, /all devices (are )?reporting/i);
});

test('successful backup job retains its age and distinguishes untested restore evidence', () => {
  const { html } = render({
    db_reachable: true,
    backup_jobs: [{ label: 'Dashboard', status: 'success', last_success_at: '2026-10-03T11:00:00Z' }],
  });
  assert.match(html, /Backups/i);
  assert.match(html, /1 hour ago/);
  assert.match(html, /restore.*(unknown|not tested|not available|no evidence)/i);
  assert.doesNotMatch(html, /restore (verified|successful|tested successfully)/i);
});

test('missing database observation remains unknown rather than an asserted outage', () => {
  const { html } = render({});
  assert.doesNotMatch(html, /Unreachable/);
  assert.match(html, /unknown|unavailable|not assessed/i);
  // Explicit negative evidence must still be a failure, not quietly unknown.
  assert.match(render({ db_reachable: false }).html, /unreachable|failed|unavailable/i);
});
