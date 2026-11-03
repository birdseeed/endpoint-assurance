const test = require('node:test');
const assert = require('node:assert/strict');
const { adminErrorText } = require('../../static/js/console-errors.js');

// PAT-1810: with patched-api-01 unreachable, error banners were showing the
// raw adminFetch() err.body JSON blob (escaped \n and all) instead of a
// clean operator-facing message. adminErrorText() is the fix; these tests
// pin its extraction precedence and fallbacks.

test('adminErrorText prefers parsed.body over detail and error', () => {
  const err = { body: JSON.stringify({ body: 'unauthorized', detail: 'd', error: 'e' }) };
  assert.equal(adminErrorText(err), 'unauthorized');
});

test('adminErrorText falls back to parsed.detail when body is absent', () => {
  const err = { body: JSON.stringify({ detail: 'no such tenant', error: 'e' }) };
  assert.equal(adminErrorText(err), 'no such tenant');
});

test('adminErrorText falls back to parsed.error when body and detail are absent', () => {
  const err = { body: JSON.stringify({ error: 'upstream returned non-JSON', status: 401 }) };
  assert.equal(adminErrorText(err), 'upstream returned non-JSON');
});

test('adminErrorText trims a trailing newline off the extracted text', () => {
  const err = { body: JSON.stringify({ body: 'unauthorized\n' }) };
  assert.equal(adminErrorText(err), 'unauthorized');
});

test('adminErrorText reproduces the PAT-1810 bug report shape cleanly', () => {
  // The exact banner text reported: a raw JSON blob with an escaped \n,
  // from a non-JSON upstream response wrapped by adminFetch.
  const err = { body: '{"error":"upstream returned non-JSON","status":401,"body":"unauthorized\\n"}' };
  const text = adminErrorText(err);
  assert.equal(text, 'unauthorized');
  assert.doesNotMatch(text, /[{}]/);
  assert.doesNotMatch(text, /\\n/);
});

test('adminErrorText returns the raw body string when it is not JSON', () => {
  const err = { body: 'plain text failure' };
  assert.equal(adminErrorText(err), 'plain text failure');
});

test('adminErrorText trims a non-JSON body too', () => {
  const err = { body: 'plain text failure\n' };
  assert.equal(adminErrorText(err), 'plain text failure');
});

test('adminErrorText falls back to err.message when there is no body', () => {
  const err = { message: 'adminFetch /api/x: 500' };
  assert.equal(adminErrorText(err), 'adminFetch /api/x: 500');
});

test('adminErrorText falls back to String(err) when body and message are both absent', () => {
  assert.equal(adminErrorText({}), '[object Object]');
});

test('adminErrorText handles a null/undefined err', () => {
  assert.equal(adminErrorText(null), 'Unknown error');
  assert.equal(adminErrorText(undefined), 'Unknown error');
});
