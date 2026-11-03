/*
 * PAT-1102: testable decision logic for the one-off charges + assessment-
 * credit UI (Account tab).
 *
 * Pure functions — no DOM — so the exact three-state acceptance criterion
 * ("no assessment charge exists" / "exists but expired, visibly so" /
 * "exists, unexpired, available") and the two moments it's acted on (the
 * pre-submit prompt on the "Raise a charge" form, and the post-create
 * apply-credit offer) are behaviourally testable independent of rendering.
 * The server (main.py api_available_assessment_credit /
 * api_charge_apply_credit) is the authority on which credit is
 * available/expired/consumed; this module only decides what the UI does
 * with what it's given.
 */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleCharges = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  // Decide whether/how to show the pre-submit assessment-credit prompt on
  // the "Raise a charge" form, given the currently-selected charge_type and
  // the raw available-assessment-credit response (or null/undefined if not
  // yet fetched, or the fetch failed). Only 'onboarding' can ever trigger
  // the prompt — the credit only ever applies against an onboarding charge.
  function creditPromptVariant(chargeType, creditData) {
    if (chargeType !== 'onboarding' || !creditData) return 'none';
    if (creditData.available) return 'available';
    // An expired credit is visibly expired, never silently absent — this is
    // the PAT-1102 acceptance criterion in code: 'none' only ever covers "no
    // assessment charge exists at all", never "exists but expired".
    if (creditData.expired) return 'expired';
    return 'none';
  }

  // Whether a fetched credit record should be offered for application
  // against a charge that was just successfully created. Requires an actual
  // charge_id to apply against — a bare {available:false, expired:false}
  // response has nothing to offer.
  function shouldOfferApplyCredit(chargeType, creditData) {
    return chargeType === 'onboarding' && !!creditData && !!creditData.charge_id &&
      (creditData.available === true || creditData.expired === true);
  }

  // The apply-credit request query string callers should POST with —
  // centralised so ?override_expired=true can never be sent for a
  // non-expired credit (the endpoint doesn't need it there, and sending it
  // unconditionally would blur the "explicit override" signal in server-side
  // logs/audit).
  function applyCreditQuery(expired) {
    return expired ? '?override_expired=true' : '';
  }

  // gross/credits/net are always server-computed and returned on every
  // charge read (create/list/patch/apply-credit) — this is a pure
  // re-derivation kept only as a display fallback, never the figure actually
  // trusted once the server has responded.
  function netFigure(gross, credits) {
    var g = Number(gross) || 0;
    var c = Number(credits) || 0;
    return Math.round((g - c) * 100) / 100;
  }

  return {
    creditPromptVariant: creditPromptVariant,
    shouldOfferApplyCredit: shouldOfferApplyCredit,
    applyCreditQuery: applyCreditQuery,
    netFigure: netFigure,
  };
});
