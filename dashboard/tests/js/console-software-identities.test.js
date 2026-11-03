const test = require('node:test');
const assert = require('node:assert/strict');
const si = require('../../static/js/console-software-identities.js');

// Minimal DOM that records how text is set and refuses innerHTML outright.
function fakeDoc() {
  function node(tag) {
    const n = { tag, className: '', children: [], listeners: {}, _text: '' };
    Object.defineProperty(n, 'innerHTML', { set() { throw new Error('innerHTML must not be used'); }, get() { return ''; } });
    Object.defineProperty(n, 'textContent', {
      get() { return n._text; },
      set(v) { n._text = String(v); n.children = []; },
    });
    n.appendChild = (c) => { n.children.push(c); return c; };
    n.removeChild = (c) => { n.children.splice(n.children.indexOf(c), 1); };
    Object.defineProperty(n, 'firstChild', { get() { return n.children[0] || null; } });
    n.addEventListener = (ev, fn) => { n.listeners[ev] = fn; };
    return n;
  }
  return { createElement: node };
}
const texts = (tr) => tr.children.map((c) => c.textContent);

const HOSTILE = '<img src=x onerror=alert(1)>';
const promotable = {
  platform: 'macos', identity_kind: 'macos_bundle_team', identity_value_normalized: 'com.example.app',
  companion_value_normalized: 'ABCDE12345', observed_names: ['Example', 'Example Pro'],
  device_count: 5, tenant_count: 2, promotable: true, blocked_reason: '',
  evidence: { signing_states: { signed: 3, not_reported: 2 } },
};
const blocked = { ...promotable, identity_value_normalized: 'com.blocked', observed_names: [HOSTILE], promotable: false, blocked_reason: 'no_signed_installation' };

test('companion label follows the platform', () => {
  assert.equal(si.companionLabel('macos'), 'Team ID');
  assert.equal(si.companionLabel('windows'), 'Publisher');
});

const mac = (states) => ({ platform: 'macos', identity_kind: 'macos_bundle_team', evidence: { signing_states: states } });
const win = (states, extra) => ({ platform: 'windows', identity_kind: 'windows_native_publisher', evidence: { signing_states: states, ...extra } });

test('macOS evidence summary uses installs and the real state keys', () => {
  assert.equal(si.evidenceSummary(mac({ signed: 3, unsigned: 0, not_reported: 2 })).split(',')[0], 'Signed on 3 of 5 installs');
  assert.equal(si.evidenceSummary(mac({ signed: 5 })), 'Signed on 5 installs');
  assert.equal(si.evidenceSummary(mac({ signed: 1, not_reported: 2 })), 'Signed on 1 of 3 installs, 2 not reporting');
  assert.equal(si.evidenceSummary(mac({ not_reported: 4 })), 'No signing status reported');
  assert.equal(si.evidenceSummary(mac({})), 'No signing status reported');
  assert.equal(si.evidenceSummary(mac({ signed: 0, adhoc: 0, not_reported: 0 })), 'No signing status reported');
  assert.equal(si.evidenceSummary({}), 'No signing status reported');
  assert.equal(si.evidenceSummary(mac({ signed: 2, adhoc: 1 })), 'Signed on 2 of 3 installs, 1 ad hoc install');
  assert.equal(si.evidenceSummary(mac({ adhoc: 1 })), '1 ad hoc install');
  assert.equal(si.evidenceSummary(mac({ adhoc: 2, unsigned: 1, untrusted: 1, invalid: 1, error: 1 })),
    '2 ad hoc installs, 1 unsigned install, 1 untrusted install, 1 invalid install, 1 install with a signing error');
  assert.ok(!/device|apple/i.test(si.evidenceSummary(mac({ signed: 3, not_reported: 2 }))));
});

test('Windows evidence summary covers roots, keys, unsigned and not reporting', () => {
  assert.equal(si.evidenceSummary(win({ valid: 4 }, { root_kinds: ['microsoft'], authenticode_publisher_key_count: 1 })),
    'Valid signature on 4 installs, Microsoft root');
  assert.equal(si.evidenceSummary(win({ valid: 2, not_reported: 3 }, { root_kinds: ['public'] })),
    'Valid on 2 of 5 installs, public root, 3 not reporting');
  assert.equal(si.evidenceSummary(win({ valid: 4 }, { root_kinds: ['microsoft'], authenticode_publisher_key_count: 2 })),
    'Valid signature on 4 installs, Microsoft root, 2 signing keys');
  assert.equal(si.evidenceSummary(win({ unsigned: 1 })), '1 unsigned install');
  assert.equal(si.evidenceSummary(win({ valid: 3, unsigned: 1, unknown: 0 }, { root_kinds: [] })), 'Valid on 3 of 4 installs, 1 unsigned install');
  assert.equal(si.evidenceSummary(win({ valid: 2 }, { root_kinds: ['enterprise'] })), 'Valid signature on 2 installs, enterprise root');
  assert.equal(si.evidenceSummary(win({ not_reported: 2 })), 'No signing status reported');
  assert.equal(si.evidenceSummary(win({ valid: 1 })), 'Valid signature on 1 install');
  assert.equal(si.evidenceSummary(win({ valid: 1 }, { authenticode_publisher_key_count: 1 })), 'Valid signature on 1 install');
});

test('identity kind is shown in plain words', () => {
  assert.equal(si.identityKindLabel('macos_bundle_team'), 'Bundle ID with Team ID');
  assert.equal(si.identityKindLabel('windows_native_publisher'), 'Identifier with publisher');
});

test('vendor prefills from the first observed publisher on Windows only', () => {
  assert.equal(si.defaultVendor({ platform: 'windows', observed_publishers: ['Contoso Ltd', 'x'] }), 'Contoso Ltd');
  assert.equal(si.defaultVendor({ platform: 'windows' }), '');
  assert.equal(si.defaultVendor({ platform: 'macos', observed_publishers: ['Whoever'] }), '');
});

test('review body carries the four identity fields from the candidate, never the form', () => {
  const body = si.reviewBody(promotable, {
    canonical_name: ' Example ', vendor_name: 'Example Ltd', reason: ' because ',
    identity_value_normalized: 'com.forged', platform: 'windows', actor: 'x',
  });
  assert.deepEqual(body, {
    platform: 'macos', identity_kind: 'macos_bundle_team', identity_value_normalized: 'com.example.app',
    companion_value_normalized: 'ABCDE12345', canonical_name: 'Example', vendor_name: 'Example Ltd', reason: 'because',
  });
});

test('review form needs product, vendor and reason; name prefills from first observed name', () => {
  assert.equal(si.defaultName(promotable), 'Example');
  assert.equal(si.defaultName({}), '');
  assert.match(si.validateReviewForm({ canonical_name: '', vendor_name: 'v', reason: 'r' }), /Product/);
  assert.match(si.validateReviewForm({ canonical_name: 'p', vendor_name: ' ', reason: 'r' }), /Vendor/);
  assert.match(si.validateReviewForm({ canonical_name: 'p', vendor_name: 'v', reason: '' }), /reason/);
  assert.equal(si.validateReviewForm({ canonical_name: 'p', vendor_name: 'v', reason: 'r' }), '');
});

test('candidate rows: Review only on promotable rows for writers, blocked rows greyed with the reason', () => {
  const doc = fakeDoc();
  const tbody = doc.createElement('tbody');
  const reviewed = [];
  si.renderCandidates(doc, tbody, [promotable, blocked], { canWrite: true, onReview: (c) => reviewed.push(c) });
  const [ok, no] = tbody.children;
  assert.equal(ok.className, '');
  assert.equal(no.className, 'swid-blocked');
  assert.equal(texts(ok)[0], 'Example, Example Pro');
  const okAction = ok.children[5];
  assert.equal(okAction.children.length, 1);
  assert.equal(okAction.children[0].textContent, 'Review');
  assert.match(okAction.children[0].className, /owner-only/);
  okAction.children[0].listeners.click();
  assert.deepEqual(reviewed, [promotable]);
  const noAction = no.children[5];
  assert.equal(noAction.children.length, 1);
  assert.equal(noAction.children[0].textContent, 'No install of this identity is reported as signed.');
  assert.equal(noAction.children[0].tag, 'span');
});

test('read-only operators get no Review or Retire controls', () => {
  const doc = fakeDoc();
  const tbody = doc.createElement('tbody');
  si.renderCandidates(doc, tbody, [promotable], { canWrite: false, onReview() {} });
  assert.equal(tbody.children[0].children[5].children.length, 0);
  const atbody = doc.createElement('tbody');
  si.renderAliases(doc, atbody, [{ alias_id: 'a', canonical_name: 'X', retired_at: null }], { canWrite: false, onRetire() {} });
  assert.equal(atbody.children[0].children[7].children.length, 0);
});

test('alias rows: platform, companion beside identity, When prefers last_reviewed_at, Retire only on Live', () => {
  const doc = fakeDoc();
  const tbody = doc.createElement('tbody');
  const retired = [];
  si.renderAliases(doc, tbody, [
    { alias_id: 'a1', canonical_name: 'Live one', vendor_name: null, platform: 'macos', created_by: null, created_at: '2026-10-01T09:00:00Z', last_reviewed_at: '2026-10-03T09:00:00Z', identity_value_normalized: 'id1', companion_value_normalized: 'TEAM123456', retired_at: null },
    { alias_id: 'a2', canonical_name: 'Old one', vendor_name: 'V', platform: 'windows', created_by: 'b@x', created_at: '2026-09-01T09:00:00Z', last_reviewed_at: null, identity_value_normalized: 'id2', companion_value_normalized: 'Contoso Ltd', retired_at: '2026-10-02T09:00:00Z' },
  ], { canWrite: true, onRetire: (a) => retired.push(a.alias_id) });
  const [live, old] = tbody.children;
  assert.equal(live.children[1].textContent, '-');
  assert.equal(live.children[2].textContent, 'macOS');
  assert.equal(live.children[3].children[0].textContent, 'id1');
  assert.equal(live.children[3].children[1].textContent, 'Team ID: TEAM123456');
  assert.equal(live.children[4].textContent, '-');
  assert.equal(live.children[5].textContent, '2026-10-03');
  assert.equal(live.children[6].textContent, 'Live');
  assert.equal(live.children[7].children[0].textContent, 'Retire');
  live.children[7].children[0].listeners.click();
  assert.deepEqual(retired, ['a1']);
  assert.equal(old.children[2].textContent, 'Windows');
  assert.equal(old.children[3].children[1].textContent, 'Publisher: Contoso Ltd');
  assert.equal(old.children[5].textContent, '2026-09-01');
  assert.equal(old.children[6].textContent, 'Retired 2026-10-02');
  assert.equal(old.children[7].children.length, 0);
  assert.equal(old.className, 'swid-retired');
});

test('hostile endpoint strings are inserted as text, never as markup', () => {
  const doc = fakeDoc();
  const tbody = doc.createElement('tbody');
  // fakeDoc throws if innerHTML is ever assigned.
  si.renderCandidates(doc, tbody, [blocked, { ...promotable, companion_value_normalized: HOSTILE }], { canWrite: true, onReview() {} });
  assert.equal(tbody.children[0].children[0].textContent, HOSTILE);
  assert.equal(tbody.children[1].children[2].textContent, HOSTILE);
  const atbody = doc.createElement('tbody');
  si.renderAliases(doc, atbody, [{ alias_id: 'a', platform: 'macos', canonical_name: HOSTILE, vendor_name: HOSTILE, created_by: HOSTILE, identity_value_normalized: HOSTILE, retired_at: null }], { canWrite: true, onRetire() {} });
  assert.equal(atbody.children[0].children[0].textContent, HOSTILE);
  assert.equal(atbody.children[0].children[3].children[0].textContent, HOSTILE);
});

test('Seen on merges devices and tenants; long identity truncates with the full value in title', () => {
  assert.equal(si.seenOn({ device_count: 6, tenant_count: 2 }), '6 devices, 2 tenants');
  assert.equal(si.seenOn({ device_count: 1, tenant_count: 1 }), '1 device, 1 tenant');
  assert.equal(si.seenOn({}), '-');
  const doc = fakeDoc();
  const tbody = doc.createElement('tbody');
  const long = 'x'.repeat(120);
  si.renderCandidates(doc, tbody, [{ ...promotable, identity_value_normalized: long }], { canWrite: true, onReview() {} });
  const row = tbody.children[0];
  assert.equal(row.children.length, 6);
  assert.equal(row.children[1].title, long);
  assert.match(row.children[1].className, /swid-ident/);
  assert.equal(row.children[3].textContent, '5 devices, 2 tenants');
});

test('blocked reason codes map to plain sentences; unknown and missing stay visible', () => {
  const m = {
    bad_signature_present: 'An install of this identity is ad hoc signed, unsigned, untrusted or has an invalid signature.',
    team_id_malformed: 'The Team ID is not a ten character Apple Team ID.',
    no_signed_installation: 'No install of this identity is reported as signed.',
    publisher_missing: 'This identity has no publisher.',
    no_valid_authenticode: 'No install has a valid Authenticode signature. A registry publisher alone is not evidence.',
    enterprise_root_only: 'The valid signatures chain only to an enterprise root, which cannot be checked independently.',
  };
  for (const [code, text] of Object.entries(m)) assert.equal(si.blockedText(code), text);
  assert.equal(si.blockedText('brand_new_code'), 'Cannot be reviewed (brand_new_code).');
  assert.equal(si.blockedText(undefined), 'Cannot be reviewed.');
  assert.equal(si.blockedText(''), 'Cannot be reviewed.');
  assert.equal(si.blockedText('constructor'), 'Cannot be reviewed (constructor).');
  const doc = fakeDoc();
  const tbody = doc.createElement('tbody');
  si.renderCandidates(doc, tbody, [{ ...promotable, promotable: false }, { ...promotable, promotable: false, blocked_reason: HOSTILE }], { canWrite: true, onReview() {} });
  assert.equal(tbody.children[0].children[5].children[0].textContent, 'Cannot be reviewed.');
  assert.equal(tbody.children[1].children[5].children[0].textContent, 'Cannot be reviewed (' + HOSTILE + ').');
});

test('reviewed date, reviewer and status cells do not wrap', () => {
  const doc = fakeDoc();
  const tbody = doc.createElement('tbody');
  si.renderAliases(doc, tbody, [{ alias_id: 'a', canonical_name: 'X', platform: 'macos', created_by: 'andy@patched.im', created_at: '2026-10-03T09:00:00Z', retired_at: null }], { canWrite: false, onRetire() {} });
  const r = tbody.children[0];
  for (const i of [4, 5, 6]) assert.match(r.children[i].className, /swid-nowrap/);
});
