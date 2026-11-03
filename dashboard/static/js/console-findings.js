/*
 * Pure Findings helpers (PAT-1607) shared by the browser console and Node
 * tests. Owns the evidence-basis vocabulary, the empty-state selection
 * between "clean" and "cannot say yet" (docs/design/console-redesign/
 * 08-empty-states.html panel 3 -- these two must never share a layout), the
 * PAT-1595 device-lifecycle coverage-exclusion count, and the CVE/CIS
 * remediation-content builders. The UI keeps transport/DOM concerns in
 * console.html; this module owns the derivations so they can be tested
 * without a browser.
 *
 * Ruling (Andy, 2026-09-13): CVE and CIS findings are never interleaved as
 * rows in one table -- two distinct sections, different resolution paths
 * (software update vs MDM configuration profile), different owners. This
 * module keeps that split: cveEvidenceBasis/cisEvidenceBasis are separate
 * functions rather than one dispatched-by-type function, on purpose.
 */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleFindings = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  // Four-tier evidence-basis vocabulary. Weakest tier is the default for
  // anything unclassified -- a finding resting on weaker evidence is
  // labelled, never hidden (root AGENTS.md: "CVE and usage claims require
  // evidence").
  var BASIS_LABELS = {
    confirmed:     'version confirmed',
    name_match:    'name match only',
    unclassified:  'unclassified',
    not_inspected: 'not inspected',
  };
  var BASIS_CLASSES = {
    confirmed:     'rdx-evidence-basis--confirmed',
    name_match:    'rdx-evidence-basis--name-match',
    unclassified:  'rdx-evidence-basis--unclassified',
    not_inspected: 'rdx-evidence-basis--not-inspected',
  };

  function basisLabel(key) { return BASIS_LABELS[key] || BASIS_LABELS.not_inspected; }
  function basisClass(key) { return BASIS_CLASSES[key] || BASIS_CLASSES.not_inspected; }

  // cveEvidenceBasis -- KNOWN GAP (flagged, not silently worked around):
  // GET /admin/tenants/{id}/cve-findings (go-service TenantCVEFindingsHandler,
  // internal/handlers/cve.go) aggregates per CVE across the tenant's devices
  // and does not expose device_cve_findings.match_confidence at all -- unlike
  // the device-scoped DeviceCVEFindingsHandler or the agent-facing
  // /v1/posture findings array, which both carry it. Adding a worst-case
  // aggregate (e.g. MIN over a confidence rank, the same shape the handler
  // already uses for patch_available) is a go-service change, out of this
  // ticket's dashboard-only worktree.
  //
  // This function is forward-compatible: it reads finding.evidence_basis
  // first (the four-tier vocabulary directly, in case a future backend adds
  // it under that name), then finding.match_confidence (today's
  // device_cve_findings vocabulary, in case a future backend forwards that
  // column unchanged), and only falls back to "not_inspected" when neither
  // is present -- which is every CVE finding today. "not_inspected" is the
  // weakest tier, which is the honest label: the console has no confidence
  // signal for this row today, not a fabricated "confirmed".
  function cveEvidenceBasis(finding) {
    var raw = finding && finding.evidence_basis;
    if (raw === 'confirmed' || raw === 'name_match' || raw === 'unclassified' || raw === 'not_inspected') {
      return raw;
    }
    var mc = finding && finding.match_confidence;
    if (mc === 'version_confirmed' || mc === 'version_vendor_confirmed') return 'confirmed';
    if (mc === 'version_unverified') return 'name_match';
    return 'not_inspected';
  }

  // cisEvidenceBasis -- a CIS control evaluation reads the device's actual
  // current signal value (compliance_signals via the evaluator), never a
  // display-name guess, so every CIS finding is genuinely the strongest
  // tier. This is a real property of how compliance_evaluations rows are
  // produced, not a placeholder standing in for missing data.
  function cisEvidenceBasis() { return 'confirmed'; }

  function matchesBasisFilter(basisKey, filterValue) {
    return !filterValue || filterValue === 'all' || basisKey === filterValue;
  }

  function matchesSeverityFilter(severity, filterValue) {
    return !filterValue || filterValue === 'all' || severity === filterValue;
  }

  // coverageFromLifecycle -- PAT-1595's GET /admin/tenants/{id}/device-lifecycle
  // returns one row per device with a `state` (reporting/quiet/stale/dormant/
  // removed/never-seen). Only "reporting" means the device was actually
  // inspected in the current window; every other state is excluded from
  // every finding count and is never counted as passing (root AGENTS.md:
  // "absence requires authority").
  function coverageFromLifecycle(entries) {
    entries = Array.isArray(entries) ? entries : [];
    var total = entries.length;
    var reporting = 0;
    entries.forEach(function(e) {
      if (e && e.state === 'reporting') reporting++;
    });
    return {
      total: total,
      reporting: reporting,
      excluded: total - reporting,
      // fullCoverage is deliberately false for a zero-device tenant --
      // "every device is accounted for" is not a claim you can make about
      // zero devices.
      fullCoverage: total > 0 && reporting === total,
    };
  }

  // emptyStateKind -- which of the panel-3 empty states applies to an empty
  // findings list. They must never share a layout: an empty list during
  // incomplete coverage reads as "cannot say yet", not "clean", because an
  // empty result from partial evidence is not the same claim as an empty
  // result from full evidence.
  function emptyStateKind(coverage) {
    if (!coverage || coverage.total === 0) return 'unknown';
    return coverage.fullCoverage ? 'clean' : 'unknown';
  }

  // summarizeCveDevices -- the expand-panel left half's device breakdown for
  // one CVE, computed from the per-CVE device drill
  // (GET /admin/tenants/{id}/cve-findings/{cveId}/devices), which is the
  // only place installed_version and agent_last_seen exist per device.
  function summarizeCveDevices(devices) {
    devices = Array.isArray(devices) ? devices : [];
    var versions = {};
    var oldestLastSeen = null;
    devices.forEach(function(d) {
      if (d && d.installed_version) versions[d.installed_version] = true;
      if (d && d.agent_last_seen && (!oldestLastSeen || d.agent_last_seen < oldestLastSeen)) {
        oldestLastSeen = d.agent_last_seen;
      }
    });
    return {
      deviceCount: devices.length,
      versionSpread: Object.keys(versions).length,
      oldestLastSeen: oldestLastSeen,
    };
  }

  // cveGuidanceNote -- the CVE expand panel's right half. Deliberately
  // simple per the ticket ("don't over-build a partner-tool integration
  // that doesn't exist yet"): a CVE resolves via a software update, not a
  // generated configuration artefact, so there is no "Generate" button here.
  function cveGuidanceNote(finding) {
    var osFamilies = (finding && finding.os_families) || [];
    var isWindows = osFamilies.indexOf('Windows') !== -1;
    var note = 'Resolved by updating the affected application beyond the vulnerable version range. ' +
      'Patched reports the finding and does not generate a configuration artefact for it — apply the update through the estate’s existing patch or software-update mechanism.';
    if (isWindows) {
      note += ' Windows updates route through a separate partner remediation tool, tracked on its own ticket.';
    }
    return note;
  }

  // ruleIdMap -- GET /admin/tenant-rules/{id} (already used by the CIS
  // Controls tab) is the only admin-facing source of a rule_key -> rule_id
  // mapping; TenantFindingsHandler's findings rows carry rule_key but never
  // the compliance_rules UUID the remediation-artefacts endpoint requires.
  function ruleIdMap(tenantRules) {
    var map = {};
    (Array.isArray(tenantRules) ? tenantRules : []).forEach(function(r) {
      if (r && r.rule_key && r.rule_id) map[r.rule_key] = r.rule_id;
    });
    return map;
  }

  // artefactFilename -- a safe local filename for the downloaded remediation
  // artefact, extension matched to platform (macOS -> .mobileconfig,
  // Windows -> the Intune settings-catalogue JSON payload).
  function artefactFilename(artefact) {
    var ext = artefact && artefact.platform === 'windows' ? 'json' : 'mobileconfig';
    var key = (artefact && artefact.rule_key) || 'remediation';
    return String(key).replace(/[^a-zA-Z0-9_.-]+/g, '-') + '.' + ext;
  }

  // Finding dispositions have deliberately different identity shapes. Keep
  // their keys in one module so the console cannot accidentally apply a CVE's
  // tenant-wide state to a CIS device row (or vice versa).
  function findingDispositionKey(findingKind, finding) {
    finding = finding || {};
    if (findingKind === 'cis' && finding.device_id && finding.rule_key) {
      return 'cis:' + finding.device_id + ':' + finding.rule_key;
    }
    if (findingKind === 'cve' && finding.cve_id) {
      return 'cve:' + finding.cve_id;
    }
    return null;
  }

  function dispositionIndex(dispositions) {
    var index = {};
    (Array.isArray(dispositions) ? dispositions : []).forEach(function(d) {
      if (!d || (d.finding_kind !== 'cis' && d.finding_kind !== 'cve')) return;
      var key = findingDispositionKey(d.finding_kind, d);
      if (key) index[key] = d;
    });
    return index;
  }

  function dispositionForFinding(index, findingKind, finding) {
    var key = findingDispositionKey(findingKind, finding);
    return key && index ? index[key] || null : null;
  }

  function matchesDispositionFilter(disposition, filterValue) {
    if (!filterValue || filterValue === 'all') return true;
    if (filterValue === 'none') return !disposition;
    return !!disposition && disposition.status === filterValue;
  }

  function findingDispositionPayload(findingKind, finding, status, recordedBy, reason) {
    var payload = {
      finding_kind: findingKind,
      status: String(status || '').trim(),
      recorded_by: String(recordedBy || '').trim(),
    };
    var trimmedReason = String(reason || '').trim();
    if (trimmedReason) payload.reason = trimmedReason;
    if (findingKind === 'cis') {
      payload.device_id = finding && finding.device_id;
      payload.rule_key = finding && finding.rule_key;
    } else if (findingKind === 'cve') {
      payload.cve_id = finding && finding.cve_id;
    }
    return payload;
  }

  return {
    basisLabel: basisLabel,
    basisClass: basisClass,
    cveEvidenceBasis: cveEvidenceBasis,
    cisEvidenceBasis: cisEvidenceBasis,
    matchesBasisFilter: matchesBasisFilter,
    matchesSeverityFilter: matchesSeverityFilter,
    coverageFromLifecycle: coverageFromLifecycle,
    emptyStateKind: emptyStateKind,
    summarizeCveDevices: summarizeCveDevices,
    cveGuidanceNote: cveGuidanceNote,
    ruleIdMap: ruleIdMap,
    artefactFilename: artefactFilename,
    findingDispositionKey: findingDispositionKey,
    dispositionIndex: dispositionIndex,
    dispositionForFinding: dispositionForFinding,
    matchesDispositionFilter: matchesDispositionFilter,
    findingDispositionPayload: findingDispositionPayload,
  };
});
