/*
 * PAT-1398 rollout evidence helpers.
 *
 * This module is deliberately dependency-free so the same fail-closed
 * decisions run in the browser and Node's built-in test runner.
 *
 * PAT-2249: the rollout-create helpers (eligibility, exactCatalogueTarget,
 * rolloutBody, creationMatches, the idempotency-key store, impactEstimate
 * and installedSpread) were removed. They matched updates against the
 * catalogue review model, which PAT-2249 retired, and served a create route
 * PAT-2246 had already removed from the platform. The read-only evidence
 * helpers below remain for the retained rollout status view.
 */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleRollouts = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  function normalPlatform(value) {
    value = String(value || '').trim().toLowerCase();
    if (value === 'macos' || value === 'windows') return value;
    return '';
  }

  function platformState(state) {
    var states = {
      pending:'queued', queued:'queued', rolling:'exposed',
      completed:'succeeded', succeeded:'succeeded', failed:'failed', paused:'paused'
    };
    return states[String(state || '').toLowerCase()] || 'unknown';
  }

  function waveEvidence(wave) {
    wave = wave || {};
    var total = Math.max(0, Number(wave.total || 0));
    var succeeded = Math.max(0, Number(wave.installed || 0));
    var failed = Math.max(0, Number(wave.failed || 0));
    var gated = Math.max(0, Number(wave.gated || 0));
    return {
      total:total, succeeded:succeeded, failed:failed, gated:gated,
      unknown:Math.max(0, total - succeeded - failed - gated)
    };
  }

  function recordField(record, names) {
    for (var i = 0; i < names.length; i++) {
      var path = names[i].split('.');
      var value = record;
      for (var j = 0; value != null && j < path.length; j++) value = value[path[j]];
      if (value !== undefined && value !== null && String(value).trim() !== '') return String(value);
    }
    return '';
  }

  function provenanceState(record) {
    var raw = recordField(record || {}, ['outcome','state','action']).toLowerCase();
    if (['queued'].indexOf(raw) !== -1) return 'queued';
    if (['received','delivered','exposed','installing'].indexOf(raw) !== -1) return 'exposed';
    if (['installed','already_current','uptodate','succeeded','install_completed'].indexOf(raw) !== -1) return 'succeeded';
    if (['verification_failed','error','version_blocked','verificationfailed','failed','install_failed'].indexOf(raw) !== -1) return 'failed';
    return 'unknown';
  }

  function provenanceForRollout(records, rollout) {
    if (!Array.isArray(records)) return null;
    var label = String(rollout && rollout.label || '').trim();
    var version = String(rollout && rollout.version || '').trim();
    var declaredPlatform = String(rollout && rollout.platform || '').trim();
    var platform = normalPlatform(declaredPlatform);
    return records.filter(function(record) {
      var recordLabel = recordField(record || {}, ['label','catalog_label','app.label','app']);
      var recordVersion = recordField(record || {}, ['version','available_version','app.available_version']);
      var recordPlatform = normalPlatform(recordField(record || {}, ['platform']));
      return recordLabel === label && recordVersion === version &&
        (!declaredPlatform || (platform && recordPlatform === platform));
    }).map(function(record) {
      return {
        device: recordField(record, ['hostname','device.hostname','device_id','device.hw_uuid']) || 'Unknown device',
        state: provenanceState(record),
        received_at: recordField(record, ['received_at','created_at','timestamp'])
      };
    });
  }

  return {
    normalPlatform:normalPlatform,
    platformState:platformState,
    waveEvidence:waveEvidence,
    provenanceForRollout:provenanceForRollout
  };
});
