/* PAT-1481: pure tenant-governance routing and review-decision helpers. */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleGovernance = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';
  var STALE_TAB_TARGETS = {
    'approved-software': 'software-catalogue',
    'new-apps': 'software-catalogue',
    'software-catalogue': 'software-catalogue',
    'patch-deploy': 'cve-findings',
    'app-control': 'overview',
    'enforcement-audit': 'overview',
    'runbook': 'overview'
  };
  // The upstream historic record calls an unapproved decision "remove". It
  // records the review outcome only: no endpoint-removal request is created.
  var REVIEW_DECISIONS = { approve: 'approve', unapprove: 'remove', defer: 'defer' };
  // The current tenant-overview contract has no removal-capability field.
  // Only an explicit true value can enable these sensitive screens.
  function removalCapabilityEnabled(tenant) {
    return !!(tenant && tenant.removal_capability === true);
  }

  function canonicalTenantTab(tab, tenant) {
    if (STALE_TAB_TARGETS[tab]) return STALE_TAB_TARGETS[tab];
    if ((tab === 'protected-software' || tab === 'removal-campaigns') &&
        !removalCapabilityEnabled(tenant)) return 'software-catalogue';
    return tab;
  }
  function newAppDecision(action) { return REVIEW_DECISIONS[action] || null; }

  function policyFetchState(tenantId, status) {
    return {
      tenantId: String(tenantId || ''),
      status: status === 'ready' || status === 'failed' ? status : 'loading'
    };
  }

  function canMutatePolicy(state, tenantId) {
    return !!(state && state.status === 'ready' && state.tenantId &&
      state.tenantId === String(tenantId || ''));
  }

  // A cached inventory response does not prove that this tenant's policy
  // response is usable. Returning to a tab after a failed or stale policy
  // fetch must retry the policy request before policy controls are enabled.
  function needsPolicyReload(state, tenantId) {
    return !canMutatePolicy(state, tenantId);
  }

  // Inventory is tenant evidence.  A browser can switch tenants while an
  // allowlist scan is in flight, so both the tenant and request generation
  // must still match before its identity data can enter the active view.
  function inventoryRequestState(tenantId, generation) {
    return { tenantId: String(tenantId || ''), generation: Number(generation) || 0 };
  }

  function canApplyInventoryResponse(current, request, tenantId) {
    return !!(current && request &&
      current.tenantId === String(request.tenantId || '') &&
      current.generation === Number(request.generation) &&
      current.tenantId === String(tenantId || ''));
  }

  // New-app review records are tenant evidence just like installed inventory.
  // A late response must not replace the active tenant's rows or leave actions
  // carrying a different tenant's identity.
  function newAppRequestState(tenantId, generation) {
    return { tenantId: String(tenantId || ''), generation: Number(generation) || 0 };
  }

  function canApplyNewAppResponse(current, request, tenantId) {
    return canApplyInventoryResponse(current, request, tenantId);
  }

  function newAppFetchState(tenantId, status) {
    return { tenantId: String(tenantId || ''), status: status || 'loading' };
  }

  function needsNewAppReload(state, tenantId) {
    return !state || state.tenantId !== String(tenantId || '') || state.status !== 'ready';
  }

  function inventoryBelongsToTenant(inventoryTenantId, tenantId) {
    return !!inventoryTenantId && String(inventoryTenantId) === String(tenantId || '');
  }

  // A single decision should refresh its view immediately. Bulk callers defer
  // that refresh until every decision settles, otherwise the first completion
  // invalidates the policy-ready state needed by its siblings.
  function shouldRefreshNewAppDecision(opts) {
    return !(opts && opts.deferRefresh);
  }

  function policyPlatform(platform) {
    var value = String(platform || '').toLowerCase();
    if (value === 'macos' || value === 'macos_only') return 'macos';
    if (value === 'windows' || value === 'windows_only') return 'windows';
    return 'any';
  }

  function normaliseIdentity(value) {
    return String(value || '').trim().toLowerCase();
  }

  // This is the platform's exact Winget PackageIdentifier production.  It is
  // deliberately checked before normalisation: surrounding whitespace or a
  // malformed native identifier must never acquire Winget policy authority.
  function validWingetID(value) {
    value = String(value || '');
    return value === value.trim() && Array.from(value).length <= 128 &&
      /^[^.\s\\/:*?"<>|\x01-\x1f]{1,32}(\.[^.\s\\/:*?"<>|\x01-\x1f]{1,32}){1,7}$/.test(value);
  }

  function installedWingetID(app) {
    app = app || {};
    var identifier = app.winget_id || app.wingetId || app.bundle_id || app.bundleId || app.identifier || '';
    return policyPlatform(app.platform) === 'windows' && app.identifier_kind === 'winget' && validWingetID(identifier)
      ? identifier : '';
  }

  function policyIdentity(name, platform) {
    return policyPlatform(platform) + '\u0000' + normaliseIdentity(name);
  }

  function appIdentityValue(app, kind) {
    app = app || {};
    var appIdentity = String(app.app_identity || '');
    if (kind === 'team_id') {
      return app.team_id || app.teamId ||
        (appIdentity.indexOf('team:') === 0 ? appIdentity.slice(5) : '');
    }
    if (kind === 'bundle_id') {
      return app.bundle_id || app.bundleId || app.identifier ||
        (appIdentity.indexOf('bundle:') === 0 ? appIdentity.slice(7) : '');
    }
    if (kind === 'winget_id') {
      return installedWingetID(app) ||
        (appIdentity.indexOf('winget:') === 0 && app.identifier_kind === 'winget' && validWingetID(appIdentity.slice(7))
          ? appIdentity.slice(7) : '');
    }
    return app.name || (appIdentity.indexOf('name:') === 0 ? appIdentity.slice(5) : '');
  }

  function policyIdentityPayload(record) {
    var identity = {};
    ['team_id', 'bundle_id', 'winget_id', 'name'].forEach(function(key) {
      if (record && String(record[key] || '').trim()) identity[key] = record[key];
    });
    return identity;
  }

  function appPolicyIdentity(app) {
    var identity = {};
    ['team_id', 'bundle_id', 'winget_id', 'name'].forEach(function(kind) {
      var value = appIdentityValue(app, kind);
      if (String(value || '').trim()) identity[kind] = value;
    });
    return identity;
  }

  // Installed rows must carry the platform's explicit identity contract. A
  // legacy /allowlist/scan response exposed only `identifier`, which meant a
  // browser could silently create a bundle/name policy even when the backend
  // had a stronger Team ID. Require app_identity plus the matching evidence
  // field so a mixed-version deployment fails closed instead.
  function installedPolicyApp(app) {
    app = app || {};
    var appIdentity = String(app.app_identity || '').trim();
    var split = appIdentity.indexOf(':');
    if (split <= 0) return null;
    var kind = appIdentity.slice(0, split);
    var identityValue = normaliseIdentity(appIdentity.slice(split + 1));
    var evidenceValue = '';
    if (kind === 'team') evidenceValue = app.team_id;
    else if (kind === 'bundle') evidenceValue = app.bundle_id;
    else if (kind === 'winget') evidenceValue = installedWingetID(app);
    else if (kind === 'name') evidenceValue = app.name;
    else return null;
    if (!identityValue || normaliseIdentity(evidenceValue) !== identityValue) return null;
    return {
      team_id: app.team_id || '',
      bundle_id: app.bundle_id || '',
      winget_id: installedWingetID(app),
      identifier_kind: app.identifier_kind || '',
      name: app.name || '',
      platform: app.platform || ''
    };
  }

  function installedAppPolicyIdentity(app) {
    var canonical = installedPolicyApp(app);
    return canonical ? appPolicyIdentity(canonical) : {};
  }

  function policyIdentityKey(identity, platform) {
    var values = ['team_id', 'bundle_id', 'winget_id', 'name'].map(function(key) {
      return key + ':' + normaliseIdentity(identity && identity[key]);
    }).join('\u0001');
    return policyPlatform(platform) + '\u0000' + values;
  }

  function logicalPolicyIdentityKey(identity) {
    return ['team_id', 'bundle_id', 'winget_id', 'name'].map(function(key) {
      return key + ':' + normaliseIdentity(identity && identity[key]);
    }).join('\u0001');
  }

  function policyMatchesApp(policy, app) {
    var populated = false;
    var keys = ['team_id', 'bundle_id', 'winget_id', 'name'];
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var expected = normaliseIdentity(policy && policy[key]);
      if (!expected) continue;
      populated = true;
      if (normaliseIdentity(appIdentityValue(app, key)) !== expected) return false;
    }
    return populated;
  }

  function policyPrecedence(policy, platform) {
    var present = function(key) { return normaliseIdentity(policy && policy[key]) !== ''; };
    var rank = present('team_id') ? 8 : 0;
    if (policyPlatform(platform) === 'windows') {
      if (present('winget_id')) rank |= 4;
      if (present('bundle_id')) rank |= 2;
    } else {
      if (present('bundle_id')) rank |= 4;
      if (present('winget_id')) rank |= 2;
    }
    if (present('name')) rank |= 1;
    return rank;
  }

  function policyIdentityFieldCount(policy) {
    return ['team_id', 'bundle_id', 'winget_id', 'name'].filter(function(key) {
      return normaliseIdentity(policy && policy[key]);
    }).length;
  }

  function matchingPolicy(policies, app, platform) {
    var groups = {};
    (policies || []).forEach(function(policy) {
      if (!policyMatchesApp(policy, app)) return;
      var policyScope = policyPlatform(policy && policy.platform);
      if (policyScope !== platform && policyScope !== 'any') return;
      var identity = policyIdentityPayload(policy);
      var key = policyIdentityKey(identity, 'any');
      var current = groups[key];
      if (!current ||
          (policyScope === platform && policyPlatform(current.platform) !== platform) ||
          (policyScope === policyPlatform(current.platform) &&
           (Number(policy.id || 0) < Number(current.id || 0) ||
            (Number(policy.id || 0) === Number(current.id || 0) &&
             policyIdentityKey(identity, policy.platform).localeCompare(
               policyIdentityKey(policyIdentityPayload(current), current.platform)) < 0)))) {
        groups[key] = policy;
      }
    });
    return Object.keys(groups).map(function(key) { return groups[key]; }).sort(function(a, b) {
      return policyIdentityFieldCount(b) - policyIdentityFieldCount(a) ||
        policyPrecedence(b, platform) - policyPrecedence(a, platform) ||
        logicalPolicyIdentityKey(policyIdentityPayload(a)).localeCompare(
          logicalPolicyIdentityKey(policyIdentityPayload(b))) ||
        Number(a.id || 0) - Number(b.id || 0) ||
        policyIdentityKey(policyIdentityPayload(a), a.platform).localeCompare(
          policyIdentityKey(policyIdentityPayload(b), b.platform));
    })[0] || null;
  }

  // This mirrors the platform API's governance precedence.  A stable signer
  // identity beats a bundle identifier, which beats a display name; within
  // each identity, the platform-specific row beats the shared `any` fallback.
  function resolvePolicy(policies, app, platform) {
    if (typeof app === 'string') app = { name: app, platform: platform };
    app = app || {};
    var targetPlatform = policyPlatform(platform || app.platform);
    var policy = matchingPolicy(policies, app, targetPlatform);
    return { policy: policy, platform: targetPlatform };
  }

  function findPolicy(policies, app, platform) {
    return resolvePolicy(policies, app, platform).policy;
  }

  function findInstalledPolicy(policies, app) {
    var canonical = installedPolicyApp(app);
    return canonical ? findPolicy(policies, canonical) : null;
  }

  // The effective policy is for display.  Mutation is deliberately scoped to
  // the exact platform record for that policy identity: clearing a macOS row
  // therefore cannot delete an inherited `any` fallback.
  function policyMutation(policies, app, targetPolicy, platform) {
    if (typeof app === 'string') app = { name: app, platform: platform };
    app = app || {};
    var resolved = resolvePolicy(policies, app, platform);
    var identity = resolved.policy ? policyIdentityPayload(resolved.policy) : appPolicyIdentity(app);
    var exact = Object.keys(identity).length ? (policies || []).filter(function(policy) {
      return policyPlatform(policy && policy.platform) === resolved.platform &&
        policyIdentityKey(policyIdentityPayload(policy), 'any') === policyIdentityKey(identity, 'any');
    }).sort(function(a, b) {
      return Number(a.id || 0) - Number(b.id || 0) ||
        policyIdentityKey(policyIdentityPayload(a), a.platform).localeCompare(
          policyIdentityKey(policyIdentityPayload(b), b.platform));
    })[0] || null : null;
    // The resolver groups case-insensitively, but a mutation must replay the
    // selected row's stored spelling so the platform upsert/delete tuple stays
    // exact and never manufactures a differently-cased identity.
    if (exact) identity = policyIdentityPayload(exact);
    var effectivePolicy = resolved.policy && resolved.policy.policy || 'unmanaged';
    var action = targetPolicy === 'unmanaged'
      ? (exact ? 'delete' : 'noop')
      : (targetPolicy === effectivePolicy ? 'noop' : 'upsert');
    return {
      action: action,
      effective: resolved.policy,
      exact: exact,
      identity: identity,
      platform: resolved.platform,
      key: policyIdentityKey(identity, resolved.platform)
    };
  }

  function installedPolicyMutation(policies, app, targetPolicy) {
    var canonical = installedPolicyApp(app);
    if (!canonical) {
      return { action: 'unresolved', effective: null, exact: null, identity: {}, platform: policyPlatform(app && app.platform), key: '' };
    }
    return policyMutation(policies, canonical, targetPolicy);
  }

  function newAppPolicyMutation(policies, app, targetPolicy) {
    app = app || {};
    var appIdentity = String(app.app_identity || '');
    var split = appIdentity.indexOf(':');
    var kindMap = { team: 'team_id', bundle: 'bundle_id', winget: 'winget_id', name: 'name' };
    var kind = split > 0 ? kindMap[appIdentity.slice(0, split)] : null;
    var value = split > 0 ? appIdentity.slice(split + 1) : '';
    var targetPlatform = policyPlatform(app.platform);
    if (kind === 'winget_id' && (targetPlatform !== 'windows' || !validWingetID(value))) {
      // Do not let malformed or cross-platform typed evidence fall through to
      // a name policy.  That is the mixed-version fail-closed boundary.
      return { action: 'unresolved', effective: null, exact: null, identity: {}, platform: targetPlatform, key: '' };
    }
    // New Apps carries its identity in app_identity, rather than the installed
    // inventory's identifier_kind contract.  A typed, valid Windows Winget
    // identity is therefore authoritative here, but legacy/mixed-version rows
    // still fail closed instead of acquiring Winget authority from a loose
    // identifier field.
    if (kind === 'winget_id') app = Object.assign({}, app, { winget_id: value, identifier_kind: 'winget' });
    var primaryCandidates = (policies || []).filter(function(policy) {
      var scope = policyPlatform(policy && policy.platform);
      if (scope !== targetPlatform && scope !== 'any') return false;
      return kind && policyMatchesIdentityValue(policy && policy[kind], value);
    });
    var candidates = primaryCandidates.filter(function(policy) {
      // The discovery must prove every populated field in a stored tuple.
      // A shared Team ID or package identifier alone cannot authorise a
      // mutation of another application's more-specific policy.
      return policyMatchesApp(policy, app);
    });
    var tuples = {};
    candidates.forEach(function(policy) {
      tuples[policyIdentityKey(policyIdentityPayload(policy), 'any')] = policyIdentityPayload(policy);
    });
    var tupleKeys = Object.keys(tuples);
    if (tupleKeys.length > 1) {
      return { action: 'unresolved', effective: null, exact: null, identity: {}, platform: targetPlatform, key: '' };
    }
    if (tupleKeys.length === 1) {
      // The discovery proves just one component of this stored tuple.  Once it
      // is uniquely identified, mutate its stored tuple directly rather than
      // re-resolving through discovery evidence (which may not carry every
      // field, such as a bundle discovery matching a bundle+Winget record).
      var matched = candidates.filter(function(policy) {
        return policyIdentityKey(policyIdentityPayload(policy), 'any') === tupleKeys[0];
      }).sort(function(a, b) {
        var aExact = policyPlatform(a.platform) === targetPlatform ? 0 : 1;
        var bExact = policyPlatform(b.platform) === targetPlatform ? 0 : 1;
        return aExact - bExact || Number(a.id || 0) - Number(b.id || 0);
      });
      var effective = matched[0] || null;
      var exact = matched.filter(function(policy) {
        return policyPlatform(policy.platform) === targetPlatform;
      })[0] || null;
      // Replay the selected persisted row's original spelling. The logical
      // tuple is matched case-insensitively, but manufacturing the discovery
      // spelling here could create a second row instead of updating the one
      // the operator actually reviewed.
      var identity = policyIdentityPayload(exact || effective);
      var effectivePolicy = effective && effective.policy || 'unmanaged';
      return {
        action: targetPolicy === 'unmanaged' ? (exact ? 'delete' : 'noop') :
          (targetPolicy === effectivePolicy ? 'noop' : 'upsert'),
        effective: effective,
        exact: exact,
        identity: identity,
        platform: targetPlatform,
        key: policyIdentityKey(identity, targetPlatform)
      };
    }
    if (primaryCandidates.length > 0) {
      return { action: 'unresolved', effective: null, exact: null, identity: {}, platform: targetPlatform, key: '' };
    }
    return policyMutation(policies, app, targetPolicy);
  }

  // A save may settle after an operator switches tenant.  Capture the exact
  // entries submitted, including their per-stage generation, and remove only
  // entries that are still the same staged work when the request completes.
  function pendingSaveSnapshot(tenantId, allowlistPending, policyPending) {
    var snapshot = function(pending) {
      return Object.keys(pending || {}).map(function(key) {
        var entry = pending[key];
        return { key: key, entry: entry, generation: entry && entry.pendingGeneration };
      });
    };
    return {
      tenantId: String(tenantId || ''),
      allowlist: snapshot(allowlistPending),
      policies: snapshot(policyPending)
    };
  }

  function settlePendingSave(snapshot, currentTenantId, allowlistPending, policyPending) {
    var removeOwned = function(entries, pending) {
      entries.forEach(function(saved) {
        var current = pending && pending[saved.key];
        if (current === saved.entry && String(current.tenantId || '') === snapshot.tenantId &&
            current.pendingGeneration === saved.generation) delete pending[saved.key];
      });
    };
    snapshot = snapshot || { tenantId: '', allowlist: [], policies: [] };
    removeOwned(snapshot.allowlist || [], allowlistPending);
    removeOwned(snapshot.policies || [], policyPending);
    return String(currentTenantId || '') === snapshot.tenantId &&
      Object.keys(allowlistPending || {}).length === 0 &&
      Object.keys(policyPending || {}).length === 0;
  }

  function policyMatchesIdentityValue(stored, observed) {
    return normaliseIdentity(stored) !== '' && normaliseIdentity(stored) === normaliseIdentity(observed);
  }

  // The policy API's upsert replaces notes and min_version as well as the
  // classification.  Retain the exact record's accepted metadata when only
  // the classification is being changed; this remains a governance record,
  // not an instruction to execute anything on an endpoint.
  function policyUpsertPayload(plan, targetPolicy) {
    plan = plan || {};
    var existing = plan.exact || plan.effective || {};
    var body = Object.assign({}, plan.identity || {}, {
      platform: plan.platform || policyPlatform(existing.platform),
      policy: targetPolicy,
      enforcement_tier: existing.enforcement_tier || 'report'
    });
    if (Object.prototype.hasOwnProperty.call(existing, 'notes')) body.notes = existing.notes;
    if (Object.prototype.hasOwnProperty.call(existing, 'min_version')) body.min_version = existing.min_version;
    return body;
  }

  function hasRecordedDecision(policies, app) {
    var policy = findPolicy(policies, app);
    return !!(policy && policy.policy && policy.policy !== 'unmanaged');
  }

  function policyValue(policy) {
    return policy && typeof policy === 'object' ? (policy.policy || 'unmanaged') : (policy || 'unmanaged');
  }

  function installedEffectivePolicy(pending, saved, allowlistStatus) {
    if (pending && pending.policy) return pending.policy;
    if (saved && saved.policy) return saved.policy;
    if (allowlistStatus === 'mandatory' || allowlistStatus === 'allowed') return 'approved';
    if (allowlistStatus === 'launch_restricted' || allowlistStatus === 'flagged') return 'restrict';
    if (allowlistStatus === 'marked_for_uninstall') return 'uninstall';
    return 'unmanaged';
  }

  function installedFilterMatches(app, effectivePolicy, filter) {
    if (!filter || filter === 'all') return true;
    var status = String(app && app.status || '');
    if (filter === 'unreviewed') return status === 'unreviewed' || status === 'not_in_allowlist';
    if (filter === 'system_baseline') return status === 'system_baseline';
    return effectivePolicy === filter;
  }

  return {
    canonicalTenantTab: canonicalTenantTab,
    removalCapabilityEnabled: removalCapabilityEnabled,
    newAppDecision: newAppDecision,
    policyFetchState: policyFetchState,
    canMutatePolicy: canMutatePolicy,
    needsPolicyReload: needsPolicyReload,
    inventoryRequestState: inventoryRequestState,
    canApplyInventoryResponse: canApplyInventoryResponse,
    newAppRequestState: newAppRequestState,
    canApplyNewAppResponse: canApplyNewAppResponse,
    newAppFetchState: newAppFetchState,
    needsNewAppReload: needsNewAppReload,
    inventoryBelongsToTenant: inventoryBelongsToTenant,
    shouldRefreshNewAppDecision: shouldRefreshNewAppDecision,
    policyPlatform: policyPlatform,
    policyIdentity: policyIdentity,
    policyIdentityPayload: policyIdentityPayload,
    appPolicyIdentity: appPolicyIdentity,
    installedAppPolicyIdentity: installedAppPolicyIdentity,
    policyIdentityKey: policyIdentityKey,
    resolvePolicy: resolvePolicy,
    findPolicy: findPolicy,
    findInstalledPolicy: findInstalledPolicy,
    policyMutation: policyMutation,
    installedPolicyMutation: installedPolicyMutation,
    newAppPolicyMutation: newAppPolicyMutation,
    pendingSaveSnapshot: pendingSaveSnapshot,
    settlePendingSave: settlePendingSave,
    policyUpsertPayload: policyUpsertPayload,
    hasRecordedDecision: hasRecordedDecision,
    policyValue: policyValue,
    installedEffectivePolicy: installedEffectivePolicy,
    installedFilterMatches: installedFilterMatches
  };
});
