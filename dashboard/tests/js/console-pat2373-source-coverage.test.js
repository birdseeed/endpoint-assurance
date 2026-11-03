const test = require('node:test');
const assert = require('node:assert/strict');
const { renderServiceHealth } = require('../../static/js/console-work.js');

const now = Date.UTC(2026, 9, 3, 12);
const helpers = {
  now,
  escape: value => String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'),
  relativeTime: value => String(value),
};
function render(source) {
  const container = { innerHTML: '' };
  const result = renderServiceHealth(container, source, helpers);
  return { ...result, html: container.innerHTML };
}
function backupRow(html) {
  return html.match(/<div class="home-health-row">(?:(?!<\/div>)[\s\S])*Backups: source(?:(?!<\/div>)[\s\S])*<\/div>/)[0];
}

test('empty legacy certificate projection cannot establish checked source coverage', () => {
  for (const cert_expiry of [undefined, []]) {
    const result = render({ db_reachable: true, cert_expiry });
    assert.equal(result.healthyLabels.includes('Certificates'), false);
    assert.match(result.html, /Certificates<\/span>[\s\S]*Unknown/);
    assert.match(result.html, /no expiry evidence or check time supplied/);
    assert.deepEqual(result.healthyLabels, ['Database connection']);
  }
  const observed = render({ cert_expiry: [{ days_left: 4 }] });
  assert.match(observed.html, /dot-red[\s\S]*Certificates/);
  assert.match(observed.html, /1 cert expiring/);
  assert.match(render({ cert_expiry: [{ days_left: 20 }] }).html, /dot-amber[\s\S]*Certificates/);
});

test('missing and unrecognised backup outcomes remain unknown with receipt times visible', () => {
  for (const status of [undefined, 'unrecognised']) {
    for (const last_success_at of ['2026-10-03T11:00:00Z', '2026-10-01T11:00:00Z']) {
      const result = render({ backup_jobs: [{ job: 'source', status, last_success_at }] });
      const row = backupRow(result.html);
      assert.match(row, /dot-muted/);
      assert.match(row, /Job status: unknown/);
      assert.doesNotMatch(row, /failed|val-red|dot-red|dot-green/);
      assert.match(row, new RegExp(last_success_at));
      assert.match(row, /Restore evidence: unknown/);
      assert.equal(result.healthyLabels.includes('Backups: source'), false);
    }
  }
});

test('observed backup success, failure and warning retain the 26-hour freshness boundary', () => {
  for (const status of ['ok', 'success']) {
    const fresh = render({ backup_jobs: [{ job: 'source', status, last_success_at: '2026-10-02T10:00:00Z' }] });
    assert.equal(fresh.healthyLabels.includes('Backups: source'), true);
    assert.match(backupRow(fresh.html), /Job status: successful/);
    assert.match(backupRow(fresh.html), /Restore evidence: unknown/);
    const stale = render({ backup_jobs: [{ job: 'source', status, last_success_at: '2026-10-02T09:59:59Z' }] });
    assert.match(backupRow(stale.html), /dot-red/);
    assert.equal(stale.healthyLabels.includes('Backups: source'), false);
  }
  for (const status of ['failed', 'error']) {
    assert.match(backupRow(render({ backup_jobs: [{ job: 'source', status, last_success_at: '2026-10-03T11:00:00Z' }] }).html), /dot-red[\s\S]*Job status: failed/);
    assert.match(backupRow(render({ backup_jobs: [{ job: 'source', status }] }).html), /dot-red[\s\S]*Job failed/);
  }
  assert.match(backupRow(render({ backup_jobs: [{ job: 'source', status: 'warning', last_success_at: '2026-10-03T11:00:00Z' }] }).html), /dot-amber[\s\S]*Job status: warning/);
});
