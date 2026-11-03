/* PAT-1371: pure automation evidence classification, shared by Console UI/tests. */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleAutomations = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';
  var INTERVALS = { health_signals_recompute: 24 };
  var QUARANTINED = {
    installomator_sync: { state: 'quarantined', label: 'Quarantined legacy execution' },
    daily_vendor_verify: { state: 'retired', label: 'Retired daily vendor verification' },
    mirror_pipeline: { state: 'quarantined', label: 'Quarantined manual compatibility' },
    mirror_pipeline_windows: { state: 'quarantined', label: 'Quarantined manual compatibility' }
  };
  var HINTS = { hourly: 1, daily: 24, weekly: 168, monthly: 720 };
  var STALE_MULTIPLIER = 1.5;
  function owns(object, key) { return Object.prototype.hasOwnProperty.call(object, key); }
  function expectedIntervalHours(name, schedule) {
    if (owns(QUARANTINED, name)) return null;
    if (owns(INTERVALS, name)) return INTERVALS[name];
    var lower = String(schedule || '').toLowerCase();
    for (var key in HINTS) if (lower.indexOf(key) !== -1) return HINTS[key];
    return 24;
  }
  function readableName(name) {
    return String(name || 'Automation').split('_').map(function(word) { return word ? word.charAt(0).toUpperCase() + word.slice(1) : ''; }).join(' ');
  }
  function dateMs(value) { var result = Date.parse(value || ''); return isFinite(result) ? result : null; }
  // Upstream run records are persisted data. Never reflect an arbitrary status
  // into an HTML class or label: unknown values are no evidence, not success.
  function safeRunStatus(value) {
    var raw = String(value || '').toLowerCase();
    if (raw === 'failed') return { raw: raw, state: 'failed', label: 'Failed' };
    if (raw === 'running') return { raw: raw, state: 'running', label: 'Running' };
    if (raw === 'warning') return { raw: raw, state: 'current', label: 'Warning' };
    if (raw === 'success') return { raw: raw, state: 'current', label: 'Current' };
    return { raw: '', state: 'no-evidence', label: 'No run evidence' };
  }
  function classify(job, nowMs) {
    job = job || {}; nowMs = nowMs || Date.now();
    var lifecycle = owns(QUARANTINED, job.job_name) ? QUARANTINED[job.job_name] : null;
    var runs = Array.isArray(job.recent_runs) ? job.recent_runs : [];
    var last = runs[0] || null;
    var lastAt = dateMs((last && (last.started_at || last.finished_at)) || job.last_run);
    if (lifecycle) {
      return { state: lifecycle.state, lifecycle: lifecycle.state, lifecycleLabel: lifecycle.label,
        last: last, lastAt: lastAt, ageHours: lastAt === null ? null : Math.max(0, nowMs - lastAt) / 3600000,
        thresholdHours: null, name: readableName(job.job_name) };
    }
    var thresholdHours = expectedIntervalHours(job.job_name, job.schedule) * STALE_MULTIPLIER;
    var ageHours = lastAt === null ? null : Math.max(0, nowMs - lastAt) / 3600000;
    var status = safeRunStatus(last && last.status);
    var state = status.state === 'failed' ? 'failed' : lastAt === null ? 'no-evidence' : ageHours > thresholdHours ? 'overdue' : status.state;
    return { state: state, lifecycle: 'scheduled', last: last, lastAt: lastAt, ageHours: ageHours, thresholdHours: thresholdHours, name: readableName(job.job_name) };
  }
  function sortJobs(jobs, nowMs) {
    var rank = { failed: 0, overdue: 1, 'no-evidence': 2, running: 3, current: 4, quarantined: 5, retired: 6 };
    return (jobs || []).map(function(job) { return { job: job, assessment: classify(job, nowMs) }; }).sort(function(a, b) {
      return rank[a.assessment.state] - rank[b.assessment.state] || a.assessment.name.localeCompare(b.assessment.name);
    });
  }
  function summarize(jobs, nowMs) {
    var rows = sortJobs(jobs, nowMs);
    var counts = { failed: 0, overdue: 0, running: 0, 'no-evidence': 0, current: 0, quarantined: 0, retired: 0 };
    rows.forEach(function(row) { counts[row.assessment.state]++; });
    var scheduled = rows.filter(function(row) { return row.assessment.lifecycle === 'scheduled'; }).length;
    return { rows: rows, counts: counts, scheduled: scheduled, historical: counts.quarantined + counts.retired };
  }
  return { STALE_MULTIPLIER: STALE_MULTIPLIER, expectedIntervalHours: expectedIntervalHours, readableName: readableName, safeRunStatus: safeRunStatus, classify: classify, sortJobs: sortJobs, summarize: summarize };
});
