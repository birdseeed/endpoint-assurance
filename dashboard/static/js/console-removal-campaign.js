/*
 * Pure helpers for the Removal Campaign console screen (PAT-1612),
 * following PAT-1607's split: this module owns the derivations, console.html
 * keeps the transport/DOM concerns.
 *
 * Backs GET/POST /admin/tenants/{id}/removal-campaigns (+ /{id}, /dry-run,
 * /authorize, /cancel) -- see go-service's
 * internal/handlers/removal_campaigns.go and internal/removal/dryrun.go for
 * the wire shapes this mirrors.
 *
 * IMPORTANT -- what the platform does NOT report, and this module therefore
 * does not invent: there is no agent-facing delivery path yet (evidence
 * before actuation, root AGENTS.md), so a dry-run's `devices` array carries
 * no per-device execution outcome. There is no "deferred, will retry" or
 * "failed" state anywhere in the wire contract -- every matched device is
 * simply in scope, graded only by evidence_basis (identifier_match vs
 * name_match_only). Do not add a deferred/failed split here; there is
 * nothing in the API to back it.
 */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleRemovalCampaign = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  var VALID_PLATFORMS = ['macos', 'windows', 'any'];
  var PLATFORM_LABELS = { macos: 'macOS', windows: 'Windows', any: 'Any platform' };

  var STATUS_LABELS = {
    draft: 'Draft',
    dry_run: 'Dry run',
    authorized: 'Authorised',
    cancelled: 'Cancelled'
  };

  var EVIDENCE_LABELS = {
    identifier_match: 'Identifier match',
    name_match_only: 'Name match only',
    unknown: 'Unknown'
  };

  var ARTEFACT_BASIS_LABELS = {
    observed_paths: 'Observed',
    known_app_bundles: 'Known bundle',
    observed_and_known: 'Observed + known',
    none: 'None'
  };

  function platformLabel(platform) {
    return PLATFORM_LABELS[platform] || String(platform || '');
  }

  function statusLabel(status) {
    return STATUS_LABELS[status] || String(status || '');
  }

  function evidenceLabel(basis) {
    return EVIDENCE_LABELS[basis] || String(basis || '');
  }

  function artefactBasisLabel(basis) {
    return ARTEFACT_BASIS_LABELS[basis] || String(basis || '');
  }

  // targetLabel -- the display name for what a campaign is aimed at, in the
  // same precedence the platform's own identity columns use: display name
  // first (what an operator recognises), then bundle id, then team id.
  function targetLabel(campaign) {
    campaign = campaign || {};
    return campaign.name || campaign.bundle_id || campaign.team_id || '(unnamed target)';
  }

  // targetIdentityParts -- every populated identity column, for a detail
  // view that wants to show all of them rather than just the display label.
  function targetIdentityParts(campaign) {
    campaign = campaign || {};
    var parts = [];
    if (campaign.name) parts.push({ field: 'name', label: 'Display name', value: campaign.name });
    if (campaign.bundle_id) parts.push({ field: 'bundle_id', label: 'Bundle ID', value: campaign.bundle_id });
    if (campaign.team_id) parts.push({ field: 'team_id', label: 'Team ID', value: campaign.team_id });
    return parts;
  }

  // createPayload -- trims the create-campaign form into the platform's POST
  // body shape. Blank identity fields are omitted entirely (not sent as
  // empty strings), matching removalCampaignCreateReq's trimmedOrNil.
  // created_by is never included: the dashboard proxy always stamps it from
  // the authenticated session, same rule as protected-software's added_by.
  function createPayload(form) {
    form = form || {};
    var payload = {
      platform: String(form.platform || 'any').trim().toLowerCase() || 'any',
      reason: String(form.reason || '').trim()
    };
    ['team_id', 'bundle_id', 'name'].forEach(function(k) {
      var v = String(form[k] || '').trim();
      if (v) payload[k] = v;
    });
    if (form.policy_id !== undefined && form.policy_id !== null && String(form.policy_id).trim() !== '') {
      var pid = parseInt(form.policy_id, 10);
      if (!isNaN(pid)) payload.policy_id = pid;
    }
    return payload;
  }

  // createPayloadError -- client-side mirror of the platform's own
  // validation (platform enum, at least one identity field) so the form
  // fails fast with a specific message instead of a round trip for an
  // obvious 400. Reason is required here as a matter of console hygiene
  // (a governance action ought to say why), stricter than the platform,
  // which defaults an absent reason to an empty string rather than
  // rejecting it -- see removal_campaigns migration 0145's `reason TEXT NOT
  // NULL DEFAULT ''`. Returns null when the payload is acceptable to submit.
  function createPayloadError(payload) {
    payload = payload || {};
    if (VALID_PLATFORMS.indexOf(payload.platform) === -1) return 'Choose a platform.';
    if (!payload.team_id && !payload.bundle_id && !payload.name) {
      return 'At least one of team ID, bundle ID or display name is required.';
    }
    if (!payload.reason) return 'A reason is required.';
    return null;
  }

  // cancelPayload / cancelPayloadError -- cancelled_by is always
  // server-stamped by the proxy (the Patched operator abandoning the
  // campaign); the platform's own required field is `reason`, which the
  // Go handler names `Reason` in the request body (stored as
  // cancelled_reason on the row) -- not `cancelled_reason`, a shape this
  // ticket's brief guessed wrong before the handler was read.
  function cancelPayload(reason) {
    return { reason: String(reason || '').trim() };
  }

  function cancelPayloadError(reason) {
    if (!String(reason || '').trim()) return 'A cancellation reason is required.';
    return null;
  }

  // authorizePayload -- authorized_by and authorization_clause are always
  // free text the operator types (naming the CUSTOMER's authorising
  // contact and MSA clause, not the logged-in Patched operator), so unlike
  // created_by/computed_by/cancelled_by they are never server-stamped.
  // dry_run_id pins the authorisation to the exact preview the operator
  // reviewed; policy_id is included only when explicitly chosen (the
  // platform falls back to the campaign's own policy_id otherwise).
  function authorizePayload(form) {
    form = form || {};
    var payload = {
      authorized_by: String(form.authorized_by || '').trim(),
      authorization_clause: String(form.authorization_clause || '').trim(),
      dry_run_id: String(form.dry_run_id || '').trim()
    };
    if (form.policy_id !== undefined && form.policy_id !== null && String(form.policy_id).trim() !== '') {
      var pid = parseInt(form.policy_id, 10);
      if (!isNaN(pid)) payload.policy_id = pid;
    }
    return payload;
  }

  // authorizeReady -- the structural gate PAT-1612 requires client-side:
  // authorizing without a named person and a clause must be impossible to
  // even submit, not merely discouraged. The server enforces the same rule
  // independently (removalAuthorizeReq validation) -- this is defence in
  // depth, never the only check.
  function authorizeReady(form) {
    form = form || {};
    return String(form.authorized_by || '').trim().length > 0 &&
      String(form.authorization_clause || '').trim().length > 0;
  }

  // dryRunBlockReason -- why authorize must be blocked right now, or null
  // when it may proceed (subject to authorizeReady() above and the policy
  // gate the platform enforces server-side). Checked in a fixed order so the
  // most fundamental problem is always the one reported.
  function dryRunBlockReason(dryRun) {
    if (!dryRun) return 'Run a dry run before authorising.';
    if (dryRun.protected_match) {
      return 'The target matches protected software (' + (dryRun.protected_match.product_name || 'protected product') +
        ') and can never be authorised for removal.';
    }
    if (dryRun.stale) {
      var reasons = staleReasons(dryRun);
      return 'This dry run is stale' + (reasons.length ? ': ' + reasons.join('; ') : '') + '. Re-run the dry run before authorising.';
    }
    return null;
  }

  // staleReasons -- staleness_reasons verbatim, defensively defaulted to an
  // empty array. Plural because more than one reason can apply at once
  // (removal.CheckStaleness collects every reason rather than
  // short-circuiting), and every reason is shown -- never just the first.
  function staleReasons(dryRun) {
    return (dryRun && Array.isArray(dryRun.staleness_reasons)) ? dryRun.staleness_reasons : [];
  }

  // artefactRows -- the dry run's own `artefacts` list, already the
  // authoritative "what would be deleted" set. artefact_enumeration_complete
  // is always false in what the platform can compute today (no vendor
  // uninstall manifest), so the caller must render that honestly rather than
  // imply the list is exhaustive -- see enumerationCaveat().
  function artefactRows(dryRun) {
    return (dryRun && Array.isArray(dryRun.artefacts)) ? dryRun.artefacts : [];
  }

  function enumerationCaveat(dryRun) {
    if (dryRun && dryRun.artefact_enumeration_complete) return null;
    return 'This list is what the platform has actually observed or learned, not a vendor uninstall manifest. It may be incomplete.';
  }

  // residueRows -- what a removal leaves behind, always reported as
  // remaining, never as removed. The platform sends a fixed set of generic
  // statements (user data, licence/account state, system-level components) —
  // there is no per-path "kept" list; do not invent one.
  function residueRows(dryRun) {
    return (dryRun && Array.isArray(dryRun.residue)) ? dryRun.residue : [];
  }

  // exclusion -- the one exclusion category the platform actually reports:
  // a protected-software match excludes every matched device at once
  // (protection is scoped to product+tenant, never to a device). Returns
  // null when nothing is excluded. Create already refuses a protected
  // product (PAT-1801), so this should not normally be reachable through
  // this console -- it exists defensively for the case where protection was
  // added after the campaign was drafted, exactly as the authorize handler's
  // own re-check comment describes.
  function exclusion(dryRun) {
    if (!dryRun || !dryRun.protected_match) return null;
    return {
      match: dryRun.protected_match,
      excludedDeviceCount: dryRun.excluded_device_count || 0
    };
  }

  // devicesWithoutInventoryNote -- "absence requires authority" (root
  // AGENTS.md): a device with no application inventory at all is neither in
  // nor out of scope, and must be surfaced as such rather than silently
  // folded into either the matched or the excluded count.
  function devicesWithoutInventoryNote(dryRun) {
    var n = (dryRun && dryRun.devices_without_app_inventory) || 0;
    if (n <= 0) return null;
    return n + (n === 1 ? ' device has' : ' devices have') +
      ' never reported application inventory and cannot be confirmed either way.';
  }

  // policyLabel -- resolves a campaign's policy_id against the tenant's own
  // app-policies list (already fetched elsewhere in the console for the
  // Software Policy tab), falling back to the raw id when the policy row
  // cannot be found (deleted, or the list hasn't loaded).
  function policyLabel(policyId, tenantPolicies) {
    if (policyId === null || policyId === undefined) return null;
    var match = (tenantPolicies || []).find(function(p) { return Number(p.id) === Number(policyId); });
    if (!match) return 'Policy #' + policyId;
    var name = match.name || match.bundle_id || match.team_id || ('Policy #' + policyId);
    return name + ' (' + platformLabel(match.platform) + ') — ' + (match.policy || '');
  }

  // deviceCounts -- the KPI-strip numbers, derived only from fields the
  // dry run actually carries. deviceCount is devices in scope for removal;
  // excludedDeviceCount is protected-exclusion only (see exclusion() above);
  // withoutInventory is the absence-requires-authority bucket.
  function deviceCounts(dryRun) {
    dryRun = dryRun || {};
    return {
      deviceCount: dryRun.device_count || 0,
      excludedDeviceCount: dryRun.excluded_device_count || 0,
      withoutInventory: dryRun.devices_without_app_inventory || 0,
      versionCount: Array.isArray(dryRun.version_spread) ? dryRun.version_spread.length : 0,
      artefactCount: artefactRows(dryRun).length
    };
  }

  // sortCampaigns -- newest first, matching the platform's own ORDER BY
  // created_at DESC on the list route; re-sorted client-side defensively in
  // case a future caller passes an unsorted array.
  function sortCampaigns(campaigns) {
    return (campaigns || []).slice().sort(function(a, b) {
      return String(b.created_at || '').localeCompare(String(a.created_at || ''));
    });
  }

  // cancellable -- mirrors the state machine: cancel is reachable from draft
  // and dry_run only (removal_campaigns migration's
  // removal_campaigns_cancel_fields CHECK + the Go handler's own WHERE
  // clause). Used to hide/disable the Cancel action rather than let an
  // operator discover the 409 the hard way.
  function cancellable(status) {
    return status === 'draft' || status === 'dry_run';
  }

  // dryRunnable -- draft or dry_run may compute a (re)preview; authorized and
  // cancelled are terminal.
  function dryRunnable(status) {
    return status === 'draft' || status === 'dry_run';
  }

  // authorizable -- only a campaign that already has a current dry run may
  // be authorised.
  function authorizable(status) {
    return status === 'dry_run';
  }

  return {
    VALID_PLATFORMS: VALID_PLATFORMS,
    PLATFORM_LABELS: PLATFORM_LABELS,
    STATUS_LABELS: STATUS_LABELS,
    platformLabel: platformLabel,
    statusLabel: statusLabel,
    evidenceLabel: evidenceLabel,
    artefactBasisLabel: artefactBasisLabel,
    targetLabel: targetLabel,
    targetIdentityParts: targetIdentityParts,
    createPayload: createPayload,
    createPayloadError: createPayloadError,
    cancelPayload: cancelPayload,
    cancelPayloadError: cancelPayloadError,
    authorizePayload: authorizePayload,
    authorizeReady: authorizeReady,
    dryRunBlockReason: dryRunBlockReason,
    staleReasons: staleReasons,
    artefactRows: artefactRows,
    enumerationCaveat: enumerationCaveat,
    residueRows: residueRows,
    exclusion: exclusion,
    devicesWithoutInventoryNote: devicesWithoutInventoryNote,
    policyLabel: policyLabel,
    deviceCounts: deviceCounts,
    sortCampaigns: sortCampaigns,
    cancellable: cancellable,
    dryRunnable: dryRunnable,
    authorizable: authorizable
  };
});
