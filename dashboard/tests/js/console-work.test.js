const test = require('node:test');
const assert = require('node:assert/strict');
const { selectWorkTenant, renderServiceHealth } = require('../../static/js/console-work.js');

function fakeRow(id) {
  const attributes = { 'data-tenant-id': id, 'aria-selected': 'false' };
  const classes = new Set();
  return {
    getAttribute(name) { return attributes[name] || null; },
    setAttribute(name, value) { attributes[name] = value; },
    classList: {
      toggle(name, enabled) { if (enabled) classes.add(name); else classes.delete(name); },
      contains(name) { return classes.has(name); },
    },
  };
}

test('Work selection updates the selected row and inspector without changing scope', () => {
  const rows = [fakeRow('alpha'), fakeRow('bravo')];
  const document = { getElementById(id) {
    return id === 'home-attention-content' ? { querySelectorAll() { return rows; } } : null;
  }};
  let selectedId = null;
  let inspected = null;
  const tenant = selectWorkTenant('bravo', {
    document,
    findTenant(id) { return id === 'bravo' ? { id, name: 'Bravo Ltd' } : null; },
    setSelected(id) { selectedId = id; },
    renderInspector(value) { inspected = value; },
  });

  assert.equal(tenant.name, 'Bravo Ltd');
  assert.equal(selectedId, 'bravo');
  assert.equal(inspected.id, 'bravo');
  assert.equal(rows[0].getAttribute('aria-selected'), 'false');
  assert.equal(rows[0].classList.contains('selected'), false);
  assert.equal(rows[1].getAttribute('aria-selected'), 'true');
  assert.equal(rows[1].classList.contains('selected'), true);
});

test('Work health keeps attention and successful observations inspectable with unknown certificate coverage', () => {
  const container = { innerHTML: '' };
  const now = Date.UTC(2026, 7, 8, 12, 0, 0);
  const result = renderServiceHealth(container, {
    db_reachable: true,
    ingestion_freshness: {
      most_recent_ingest_at: '2026-08-08T11:00:00Z',
      stalest_tenant: { tenant_name: 'Alpha <Co>', hours_stale: 16 },
    },
    backup_jobs: [{ label: 'Dashboard', status: 'failed', last_success_at: '2026-08-07T00:00:00Z' }],
    disk_usage: [{ host: 'patched-prod-01', used_pct: 92.1, used_gb: 92, total_gb: 100 }],
    cert_expiry: [],
  }, {
    now,
    escape(value) { return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); },
    relativeTime() { return 'recently'; },
  });

  assert.equal(result.attentionCount, 4);
  assert.deepEqual(result.healthyLabels, ['Database connection', 'Receiving device reports']);
  assert.match(container.innerHTML, /Alpha &lt;Co&gt; &mdash; 16h since latest receipt/);
  assert.match(container.innerHTML, /Backups: Dashboard/);
  assert.match(container.innerHTML, /92\.1% &mdash; 92 \/ 100 GB/);
  assert.match(container.innerHTML, /2 checks healthy/);
  assert.match(container.innerHTML, /Successful check observations/);
  assert.match(container.innerHTML, /Database connection<\/span>/);
  assert.match(container.innerHTML, /Certificates<\/span>[\s\S]*Unknown/);
  assert.equal((container.innerHTML.match(/dot-red/g) || []).length, 2);
  assert.equal((container.innerHTML.match(/dot-amber/g) || []).length, 1);
  assert.match(container.innerHTML, /Job status: failed/);
});
