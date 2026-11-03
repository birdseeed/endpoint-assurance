/*
 * Testable Work-page behaviour shared by the browser console and Node's
 * built-in test runner. This stays dependency-free: callers provide the small
 * set of browser/global helpers it needs instead of coupling tests to a DOM
 * implementation.
 */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleWork = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  function selectWorkTenant(tenantId, options) {
    var tenant = options.findTenant(tenantId);
    if (!tenant) return null;

    options.setSelected(tenantId);
    var content = options.document.getElementById('home-attention-content');
    if (content) {
      content.querySelectorAll('tr[data-tenant-id]').forEach(function(row) {
        var selected = row.getAttribute('data-tenant-id') === tenantId;
        row.classList.toggle('selected', selected);
        row.setAttribute('aria-selected', selected ? 'true' : 'false');
      });
    }
    options.renderInspector(tenant);
    return tenant;
  }

  function renderServiceHealth(container, serviceHealth, helpers) {
    var escape = helpers.escape;
    var relativeTime = helpers.relativeTime;
    var now = helpers.now == null ? Date.now() : helpers.now;
    var sh = serviceHealth || {};

    function healthRow(dotClass, label, value, valueClass) {
      return '<div class="home-health-row">' +
        '<span class="home-health-dot ' + dotClass + '" aria-hidden="true"></span>' +
        '<span class="home-health-label">' + escape(label) + '</span>' +
        '<span class="home-health-value ' + (valueClass || '') + '">' + value + '</span>' +
        '</div>';
    }

    var attentionRows = [];
    var healthyLabels = [];
    var healthyRows = [];
    function addHealthRow(dotClass, label, value, valueClass) {
      if (dotClass === 'dot-green') {
        healthyLabels.push(label);
        healthyRows.push(healthRow(dotClass, label, value, valueClass));
        return;
      }
      attentionRows.push(healthRow(dotClass, label, value, valueClass));
    }

    var dbOk = sh.db_reachable === true;
    var dbFailed = sh.db_reachable === false;
    addHealthRow(dbOk ? 'dot-green' : (dbFailed ? 'dot-red' : 'dot-muted'), 'Database connection',
      (dbOk ? 'Reachable' : (dbFailed ? 'Unreachable' : 'Unknown')) +
      '. Checks whether the service can reach its database. Last checked: ' +
      (sh.observed_at ? escape(relativeTime(sh.observed_at)) : 'time not supplied'), dbFailed ? 'val-red' : '');

    var freshness = sh.ingestion_freshness || {};
    var lastIngest = freshness.most_recent_ingest_at;
    if (lastIngest) {
      var ingestHours = (now - new Date(lastIngest).getTime()) / 3600000;
      var ingestDot = ingestHours > 24 ? 'dot-red' : (ingestHours > 4 ? 'dot-amber' : 'dot-green');
      var ingestClass = ingestHours > 24 ? 'val-red' : (ingestHours > 4 ? 'val-amber' : '');
      addHealthRow(Number.isFinite(ingestHours) && ingestHours >= 0 ? ingestDot : 'dot-muted', 'Receiving device reports',
        (Number.isFinite(ingestHours) && ingestHours >= 0 ? 'Latest receipt: ' + escape(relativeTime(lastIngest)) : 'Receipt time unknown') +
        '. Shows the latest device report received; this does not prove all devices have reported.', ingestClass);
    } else {
      addHealthRow('dot-muted', 'Receiving device reports', 'Unknown: no receipt time available. Device reporting coverage is unknown.', '');
    }

    var stalest = freshness.stalest_tenant;
    if (stalest && stalest.tenant_name) {
      var lagHours = stalest.hours_stale;
      if (typeof lagHours !== 'number' || !Number.isFinite(lagHours) || lagHours < 0) lagHours = null;
      var lagDot = lagHours === null ? 'dot-muted' : (lagHours > 48 ? 'dot-red' : (lagHours > 12 ? 'dot-amber' : 'dot-green'));
      var lagClass = lagHours > 48 ? 'val-red' : (lagHours > 12 ? 'val-amber' : '');
      var lagValue = escape(stalest.tenant_name) + ' &mdash; ' + (lagHours === null ? 'receipt age unknown' : lagHours.toFixed(0) + 'h since latest receipt');
      if (lagDot === 'dot-green') {
        addHealthRow('dot-green', 'Oldest tenant report receipt', lagValue + '. Compares tenant report receipts; individual device coverage remains unknown.', '');
      } else {
        var lagAttributes = helpers.lagAttributes
          ? helpers.lagAttributes(stalest)
          : ' role="button" tabindex="0" style="cursor:pointer;"';
        attentionRows.push('<div class="home-health-row clickable"' + lagAttributes + '>' +
          '<span class="home-health-dot ' + lagDot + '" aria-hidden="true"></span>' +
          '<span class="home-health-label">' + escape('Oldest tenant report receipt') + '</span>' +
          '<span class="home-health-value ' + (lagClass || '') + '">' + lagValue + '. Compares tenant report receipts; individual device coverage remains unknown.</span>' +
          '</div>');
      }
    }

    var backups = Array.isArray(sh.backup_jobs) ? sh.backup_jobs : [];
    if (backups.length === 0) {
      addHealthRow('dot-muted', 'Backups', 'Unknown: no job evidence or last successful run available. Restore testing: no evidence available.', '');
    } else {
      backups.forEach(function(backup) {
        var label = 'Backups: ' + (backup.label || backup.job || 'job');
        var last = backup.last_success_at;
        var statusOk = backup.status === 'ok' || backup.status === 'success';
        var statusFailed = backup.status === 'failed' || backup.status === 'error';
        var statusWarning = backup.status === 'warning';
        if (!last) {
          addHealthRow(statusFailed ? 'dot-red' : (statusWarning ? 'dot-amber' : 'dot-muted'), label, (statusFailed ? 'Job failed. ' : (statusWarning ? 'Job warning. ' : 'Job status unknown. ')) + 'No successful run time available. Restore testing: no evidence available.', statusFailed ? 'val-red' : (statusWarning ? 'val-amber' : ''));
          return;
        }
        var ageHours = (now - new Date(last).getTime()) / 3600000;
        var bad = ageHours > 26 || statusFailed;
        var validAge = Number.isFinite(ageHours) && ageHours >= 0;
        var relative = escape(relativeTime(last));
        var outcome = statusOk ? 'successful' : (statusFailed ? 'failed' : (statusWarning ? 'warning' : 'unknown'));
        var dot = statusFailed ? 'dot-red' : (statusWarning ? 'dot-amber' : (!statusOk || !validAge ? 'dot-muted' : (bad ? 'dot-red' : 'dot-green')));
        addHealthRow(dot, label,
          'Last successful job: ' + (validAge ? relative : 'time unknown') + '. Job status: ' + outcome + '. Backup completion is not a restore test. Restore evidence: unknown.', dot === 'dot-red' ? 'val-red' : (dot === 'dot-amber' ? 'val-amber' : ''));
      });
    }

    var disks = Array.isArray(sh.disk_usage) ? sh.disk_usage : [];
    if (disks.length === 0) {
      addHealthRow('dot-muted', 'Server storage', 'Unknown: no capacity observation or check time supplied.', '');
    } else {
      disks.forEach(function(disk) {
        var percent = disk.used_pct;
        if (typeof percent !== 'number' || !Number.isFinite(percent) || percent < 0 || percent > 100) {
          addHealthRow('dot-muted', 'Server storage', 'Usage unknown. Last checked: time not supplied.', '');
          return;
        }
        var dotClass = percent >= 85 ? 'dot-red' : (percent >= 70 ? 'dot-amber' : 'dot-green');
        var valueClass = percent >= 85 ? 'val-red' : (percent >= 70 ? 'val-amber' : '');
        var value = percent.toFixed(1) + '% &mdash; ' + escape(disk.used_gb == null ? 'unknown' : disk.used_gb) + ' / ' + escape(disk.total_gb == null ? 'unknown' : disk.total_gb) + ' GB';
        var label = 'Server storage' + (disk.host ? ': ' + disk.host : '');
        value += '. Checks used capacity. Last checked: ' + (disk.observed_at ? escape(relativeTime(disk.observed_at)) : 'time not supplied');
        addHealthRow(dotClass, label, value, valueClass);
      });
    }

    var certificates = Array.isArray(sh.cert_expiry) ? sh.cert_expiry : [];
    // This legacy projection has no source-availability contract. An empty
    // list cannot distinguish a checked source from a failed expiry query.
    if (certificates.length === 0) {
      addHealthRow('dot-muted', 'Certificates', 'Unknown: no expiry evidence or check time supplied.', '');
    } else {
      var expiringSeven = certificates.filter(function(cert) { return typeof cert.days_left === 'number' && cert.days_left <= 7; }).length;
      var expiringThirty = certificates.length;
      var certDot = expiringSeven > 0 ? 'dot-red' : 'dot-amber';
      var certClass = expiringSeven > 0 ? 'val-red' : 'val-amber';
      addHealthRow(certDot, 'Certificates',
        expiringThirty + ' cert' + (expiringThirty !== 1 ? 's' : '') + ' expiring &le;30d. Checks upcoming expiry; last checked: time not supplied.', certClass);
    }

    var healthySummary = healthyLabels.length
      ? '<div class="home-health-summary" title="' + escape(healthyLabels.join(', ')) + '">' +
          '<span class="home-health-dot dot-green" aria-hidden="true"></span>' +
          '<span>' + healthyLabels.length + ' check' + (healthyLabels.length === 1 ? '' : 's') + ' healthy</span>' +
        '</div>'
      : '';
    container.innerHTML = attentionRows.join('') + healthySummary + (healthyRows.length
      ? '<details class="home-health-observations" open><summary>Successful check observations</summary>' + healthyRows.join('') + '</details>' : '');
    return { attentionCount: attentionRows.length, healthyLabels: healthyLabels };
  }

  return { selectWorkTenant: selectWorkTenant, renderServiceHealth: renderServiceHealth };
});
