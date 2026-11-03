const test = require('node:test');
const assert = require('node:assert/strict');
const {
  creditPromptVariant,
  shouldOfferApplyCredit,
  applyCreditQuery,
  netFigure,
} = require('../../static/js/console-charges.js');

test('creditPromptVariant only ever fires for charge_type onboarding', () => {
  var data = { available: true, expired: false, charge_id: 'c1', amount: 400, credit_expires_at: '2026-10-01' };
  assert.equal(creditPromptVariant('assessment', data), 'none');
  assert.equal(creditPromptVariant('audit_pack', data), 'none');
  assert.equal(creditPromptVariant('advisory_overflow', data), 'none');
  assert.equal(creditPromptVariant('onboarding', data), 'available');
});

test('creditPromptVariant: no assessment charge exists at all -> none', () => {
  var data = { available: false, expired: false, charge_id: null, amount: null, credit_expires_at: null };
  assert.equal(creditPromptVariant('onboarding', data), 'none');
});

test('creditPromptVariant: unexpired unconsumed credit -> available', () => {
  var data = { available: true, expired: false, charge_id: 'c1', amount: 400, credit_expires_at: '2026-10-01' };
  assert.equal(creditPromptVariant('onboarding', data), 'available');
});

test('creditPromptVariant: expired credit is visibly "expired", never folded into "none"', () => {
  // This is the PAT-1102 acceptance criterion in code: an expired credit
  // must be distinguishable from "no credit exists" everywhere in the UI,
  // not just at the API layer.
  var data = { available: false, expired: true, charge_id: 'c1', amount: 400, credit_expires_at: '2025-01-01' };
  assert.equal(creditPromptVariant('onboarding', data), 'expired');
});

test('creditPromptVariant handles a missing/failed fetch as none, not a crash', () => {
  assert.equal(creditPromptVariant('onboarding', null), 'none');
  assert.equal(creditPromptVariant('onboarding', undefined), 'none');
});

test('shouldOfferApplyCredit requires onboarding type, a charge_id, and available-or-expired', () => {
  var available = { available: true, expired: false, charge_id: 'c1', amount: 400 };
  var expired = { available: false, expired: true, charge_id: 'c1', amount: 400 };
  var none = { available: false, expired: false, charge_id: null, amount: null };

  assert.equal(shouldOfferApplyCredit('onboarding', available), true);
  assert.equal(shouldOfferApplyCredit('onboarding', expired), true);
  assert.equal(shouldOfferApplyCredit('onboarding', none), false);
  assert.equal(shouldOfferApplyCredit('audit_pack', available), false);
  assert.equal(shouldOfferApplyCredit('onboarding', null), false);
});

test('applyCreditQuery only ever sends override_expired=true for an expired credit', () => {
  assert.equal(applyCreditQuery(true), '?override_expired=true');
  assert.equal(applyCreditQuery(false), '');
});

test('netFigure subtracts credits from gross and rounds to pence', () => {
  assert.equal(netFigure(1000, 400), 600);
  assert.equal(netFigure(123.456, 0), 123.46);
  assert.equal(netFigure(100, 100), 0);
});

test('netFigure treats missing/non-numeric inputs as zero rather than NaN', () => {
  assert.equal(netFigure(undefined, undefined), 0);
  assert.equal(netFigure(500, null), 500);
});
