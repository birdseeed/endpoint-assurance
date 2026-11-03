/*
 * Pure helpers for the Protected Software console screen (PAT-1820),
 * following PAT-1607's split: this module owns the derivations, console.html
 * keeps the transport/DOM concerns.
 *
 * Backs GET/POST /admin/tenants/{id}/protected-software (+ /changes,
 * /{baselineID}/override-remove) -- see go-service's
 * internal/handlers/protected_software.go for the wire shapes this mirrors.
 */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleProtectedSoftware = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  var CATEGORY_LABELS = {
    edr: 'EDR',
    mdm: 'MDM',
    backup: 'Backup',
    security: 'Security',
    patched_agent: 'Patched Agent',
    customer_defined: 'Customer defined'
  };
  var VALID_CATEGORIES = ['edr', 'mdm', 'backup', 'security', 'patched_agent', 'customer_defined'];

  function categoryLabel(category) {
    return CATEGORY_LABELS[category] || String(category || '');
  }

  // The six identity columns the platform accepts (macOS: bundle_id/team_id/
  // signer; Windows: win_publisher/win_product_code; either: process_name).
  // They are not mutually exclusive in the schema, so every populated field
  // is shown, not just the first match -- identityParts() below returns all
  // of them, in this fixed display order.
  var IDENTITY_FIELDS = ['bundle_id', 'team_id', 'signer', 'win_publisher', 'win_product_code', 'process_name'];
  var IDENTITY_LABELS = {
    bundle_id: 'Bundle ID',
    team_id: 'Team ID',
    signer: 'Signer',
    win_publisher: 'Publisher',
    win_product_code: 'Product code',
    process_name: 'Process'
  };

  function identityParts(entry) {
    entry = entry || {};
    return IDENTITY_FIELDS.filter(function(k) {
      return entry[k] !== null && entry[k] !== undefined && String(entry[k]).trim() !== '';
    }).map(function(k) {
      return { field: k, label: IDENTITY_LABELS[k], value: entry[k] };
    });
  }

  function hasIdentity(payload) {
    payload = payload || {};
    return IDENTITY_FIELDS.some(function(k) { return String(payload[k] || '').trim() !== ''; });
  }

  // groupBySource -- splits the effective set's flat entries[] (each tagged
  // source: "baseline"|"tenant" by the platform) into the two console
  // sections. Never re-derives source from anything else -- the platform's
  // LEFT JOIN against protected_software_overrides is the single point of
  // truth for which baseline rows this tenant has opted out of.
  function groupBySource(entries) {
    var baseline = [];
    var tenant = [];
    (entries || []).forEach(function(e) {
      if (!e) return;
      if (e.source === 'tenant') tenant.push(e);
      else baseline.push(e);
    });
    return { baseline: baseline, tenant: tenant };
  }

  // addPayload -- trims the add-protection form fields into the platform's
  // POST body shape. Blank identity fields are omitted entirely (not sent as
  // empty strings) so a later hasIdentity()/addPayloadError() check on the
  // resulting payload behaves the same whether it runs client- or
  // server-side.
  function addPayload(form) {
    form = form || {};
    var payload = {
      category: String(form.category || '').trim(),
      vendor: String(form.vendor || '').trim(),
      product_name: String(form.product_name || '').trim(),
      reason: String(form.reason || '').trim()
    };
    IDENTITY_FIELDS.forEach(function(k) {
      var v = String(form[k] || '').trim();
      if (v) payload[k] = v;
    });
    return payload;
  }

  // addPayloadError -- client-side mirror of the platform's own validation
  // (protectedSoftwareValidCategories, vendor/product_name required, at
  // least one identity field required) so the form fails fast with a
  // specific message instead of a round trip for an obvious 400. Returns
  // null when the payload is acceptable to submit.
  function addPayloadError(payload) {
    payload = payload || {};
    if (VALID_CATEGORIES.indexOf(payload.category) === -1) return 'Choose a category.';
    if (!payload.vendor) return 'Vendor is required.';
    if (!payload.product_name) return 'Product name is required.';
    if (!hasIdentity(payload)) {
      return 'At least one identity field (bundle ID, team ID, signer, publisher, product code or process name) is required.';
    }
    return null;
  }

  // changeDetail -- protected_software_changes.detail is a raw JSON object
  // the platform writes per action (category/vendor/product_name on
  // "added"; reason/category/vendor/product_name on
  // "baseline_override_removed"). Parsed defensively: an absent, already-
  // parsed, or unparseable detail must never break the audit row, it just
  // renders with no extra fields.
  function changeDetail(change) {
    var raw = change && change.detail;
    if (raw && typeof raw === 'object') return raw;
    if (typeof raw === 'string' && raw.trim()) {
      try {
        var parsed = JSON.parse(raw);
        return (parsed && typeof parsed === 'object') ? parsed : {};
      } catch (e) {
        return {};
      }
    }
    return {};
  }

  function changeActionLabel(action) {
    if (action === 'added') return 'Added';
    if (action === 'baseline_override_removed') return 'Baseline override removed';
    return String(action || '');
  }

  // overrideRemovePayload -- the override-remove POST body. reason is
  // required by the platform (400 without it); removed_by is always
  // server-resolved by the dashboard proxy and is not sent from here.
  function overrideRemovePayload(reason) {
    return { reason: String(reason || '').trim() };
  }

  return {
    categoryLabel: categoryLabel,
    identityParts: identityParts,
    hasIdentity: hasIdentity,
    groupBySource: groupBySource,
    addPayload: addPayload,
    addPayloadError: addPayloadError,
    changeDetail: changeDetail,
    changeActionLabel: changeActionLabel,
    overrideRemovePayload: overrideRemovePayload,
    VALID_CATEGORIES: VALID_CATEGORIES,
    CATEGORY_LABELS: CATEGORY_LABELS,
    IDENTITY_FIELDS: IDENTITY_FIELDS,
    IDENTITY_LABELS: IDENTITY_LABELS
  };
});
