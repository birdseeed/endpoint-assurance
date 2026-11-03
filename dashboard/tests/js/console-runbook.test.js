const test = require('node:test');
const assert = require('node:assert/strict');
const runbook = require('../../static/js/console-runbook.js');

const NOTES = [
  { id: 'a', title: 'VPN caveat', body: 'Split-tunnel must stay off.', category: 'technical', pinned: 0 },
  { id: 'b', title: 'Billing contact', body: 'AP contact is finance@example.com.', category: 'billing', pinned: 1 },
  { id: 'c', title: 'Escalation path', body: 'Escalate P1s to the account owner.', category: 'support', pinned: 0 },
];

test('categoryLabel maps known categories and falls back to Other', () => {
  assert.equal(runbook.categoryLabel('technical'), 'Technical');
  assert.equal(runbook.categoryLabel('billing'), 'Billing');
  assert.equal(runbook.categoryLabel('not-a-real-category'), 'Other');
  assert.equal(runbook.categoryLabel(undefined), 'Other');
});

test('categoryOptions covers every known category exactly once', () => {
  const opts = runbook.categoryOptions();
  const values = opts.map(o => o.value);
  assert.deepEqual(values, ['onboarding', 'support', 'deployment', 'reporting', 'billing', 'technical', 'other']);
  assert.deepEqual(opts.find(o => o.value === 'technical'), { value: 'technical', label: 'Technical' });
});

test('filterNotes with no options returns every note unmodified and unreordered', () => {
  const result = runbook.filterNotes(NOTES, {});
  assert.deepEqual(result.map(n => n.id), ['a', 'b', 'c']);
});

test('filterNotes by category keeps only matching notes', () => {
  const result = runbook.filterNotes(NOTES, { category: 'billing' });
  assert.deepEqual(result.map(n => n.id), ['b']);
});

test('filterNotes by pinnedOnly keeps only pinned notes', () => {
  const result = runbook.filterNotes(NOTES, { pinnedOnly: true });
  assert.deepEqual(result.map(n => n.id), ['b']);
});

test('filterNotes by query searches title, body and category label case-insensitively', () => {
  assert.deepEqual(runbook.filterNotes(NOTES, { query: 'split-tunnel' }).map(n => n.id), ['a']);
  assert.deepEqual(runbook.filterNotes(NOTES, { query: 'FINANCE@EXAMPLE.COM' }).map(n => n.id), ['b']);
  assert.deepEqual(runbook.filterNotes(NOTES, { query: 'support' }).map(n => n.id), ['c']);
});

test('filterNotes composes query, category and pinnedOnly together', () => {
  const result = runbook.filterNotes(NOTES, { query: 'escalate', category: 'support', pinnedOnly: false });
  assert.deepEqual(result.map(n => n.id), ['c']);
  assert.deepEqual(runbook.filterNotes(NOTES, { query: 'escalate', category: 'billing' }), []);
});

test('filterNotes does not mutate the source array', () => {
  const before = NOTES.map(n => n.id);
  runbook.filterNotes(NOTES, { query: 'vpn' });
  assert.deepEqual(NOTES.map(n => n.id), before);
});

test('filterNotes tolerates missing/null fields on a note', () => {
  const result = runbook.filterNotes([{ id: 'x' }, null], { query: 'anything' });
  assert.deepEqual(result, []);
  assert.deepEqual(runbook.filterNotes([{ id: 'x' }, null], {}).map(n => n && n.id), ['x', null]);
});

test('escapeHtml neutralises the five HTML metacharacters', () => {
  assert.equal(runbook.escapeHtml(`<script>alert("x")</script>&'`), '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;\'');
});

test('linkifyHtml escapes HTML before linkifying, so markup in a note never survives', () => {
  const out = runbook.linkifyHtml('<img src=x onerror=alert(1)> see https://patched.im/status now');
  assert.ok(out.indexOf('<img') === -1, 'raw <img> must not survive');
  assert.ok(out.indexOf('&lt;img') !== -1);
  assert.ok(out.indexOf('<a href="https://patched.im/status" target="_blank" rel="noopener noreferrer">https://patched.im/status</a>') !== -1);
});

test('linkifyHtml turns newlines into <br> and leaves plain text untouched', () => {
  assert.equal(runbook.linkifyHtml('line one\nline two'), 'line one<br>line two');
  assert.equal(runbook.linkifyHtml('no links here'), 'no links here');
});

test('linkifyHtml handles multiple links in one note without swallowing surrounding text', () => {
  const out = runbook.linkifyHtml('first https://a.example/x then https://b.example/y done');
  assert.equal(
    out,
    'first <a href="https://a.example/x" target="_blank" rel="noopener noreferrer">https://a.example/x</a> then ' +
    '<a href="https://b.example/y" target="_blank" rel="noopener noreferrer">https://b.example/y</a> done'
  );
});
