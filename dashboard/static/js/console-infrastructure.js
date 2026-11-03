/*
 * PAT-1358: pure Infrastructure workspace classification.
 *
 * The Ops endpoint remains the authority for its telemetry. This helper only
 * classifies that payload for display, with no DOM, I/O, or mutation, so the
 * same decision rules are covered by Node tests.
 */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleInfrastructure = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  var BACKUP_STALE_MS = 26 * 60 * 60 * 1000;
  // The scheduler writes maintenance evidence hourly. Two hours permits one
  // delayed run while ensuring a stopped scheduler cannot remain green.
  var MAINTENANCE_STALE_MS = 2 * 60 * 60 * 1000;
  var EXPECTED_CERTIFICATE_HOSTS = ['api.patched.im', 'dashboard.patched.im', 'app.patched.im'];
  var EXPECTED_FIREWALL_EDGES = ['prod-01-edge', 'api-01-edge'];
  var CHECK_WRAPPERS = {
    tick_maintenance_drift_check: /^maintenance_(prod01|api01|portal01)$/,
    tick_email_delivery_check: /^email_delivery$/,
    tick_deploy_drift_check: /^deploy_drift$/,
  };
  var SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

  function validDate(value) {
    var ms = Date.parse(value || '');
    return isFinite(ms) ? ms : null;
  }

  function evidenceAge(value, nowMs) {
    var ms = validDate(value);
    if (ms === null) return { ms: null, label: 'unavailable', freshness: 'unknown' };
    var age = Math.max(0, nowMs - ms);
    var hours = Math.floor(age / 3600000);
    var label = age < 60000 ? 'just now' : age < 3600000
      ? Math.floor(age / 60000) + 'm ago'
      : hours < 24 ? hours + 'h ago' : Math.floor(hours / 24) + 'd ago';
    return { ms: age, label: label, freshness: age > BACKUP_STALE_MS ? 'stale' : 'current' };
  }

  function maintenanceAssessment(row, nowMs) {
    row = row || {};
    var age = evidenceAge(row.evaluated_at, nowMs);
    if (row.state !== 'ok') return { state: stateFrom(row.state), age: age };
    if (age.ms === null || age.ms > MAINTENANCE_STALE_MS) return { state: 'unknown', age: age };
    return { state: 'healthy', age: age };
  }

  function shouldSignalTenantEntry(options) {
    return !(options && options.readOnly === true);
  }

  function certificateEvidence(certs) {
    var byHost = {};
    (certs || []).forEach(function(cert) { if (cert && cert.hostname) byHost[cert.hostname] = cert; });
    var invalid = false;
    var critical = false;
    EXPECTED_CERTIFICATE_HOSTS.forEach(function(host) {
      var cert = byHost[host];
      if (!cert || cert.error || validDate(cert.not_after) === null || !isFinite(Number(cert.days_left))) {
        invalid = true;
        return;
      }
      if (Number(cert.days_left) <= 0) critical = true;
    });
    return { complete: !invalid, critical: critical, byHost: byHost };
  }

  function firewallEvidence(firewall, nowMs) {
    var invalid = false;
    var critical = false;
    EXPECTED_FIREWALL_EDGES.forEach(function(edge) {
      var item = firewall && firewall[edge];
      if (!item || typeof item !== 'object') { invalid = true; return; }
      if (item.timer_active === false || (Object.prototype.hasOwnProperty.call(item, 'last_exit_code') && String(item.last_exit_code) !== '0')) critical = true;
      if (typeof item.timer_active !== 'boolean' || !Object.prototype.hasOwnProperty.call(item, 'last_exit_code') || item.last_exit_code === null || item.last_exit_code === undefined || evidenceAge(item.last_apply_timestamp, nowMs).ms === null) invalid = true;
    });
    return { complete: !invalid, critical: critical };
  }

  function deployProvenance(dashboard) {
    var status = dashboard && dashboard.deployment_match;
    if (status === 'match') return { state: 'healthy' };
    if (status === 'mismatch') return { state: 'critical' };
    return { state: 'unknown' };
  }

  function stateFrom(status, fallback) {
    if (status === 'degraded' || status === 'failed' || status === 'error') return 'critical';
    if (status === 'unconfigured' || status === 'unknown') return 'unknown';
    if (status === 'ok' || status === 'active') return 'healthy';
    return fallback || 'unknown';
  }

  // Suppress a scheduler heartbeat only when its detailed condition is also
  // present. A lone wrapper can still indicate that its scheduler failed.
  function dedupeCheckIncidents(checks) {
    checks = Array.isArray(checks) ? checks.filter(function(c) { return c && c.name; }) : [];
    var names = {};
    checks.forEach(function(check) { names[check.name] = true; });
    return checks.filter(function(check) {
      var matcher = CHECK_WRAPPERS[check.name];
      if (!matcher) return true;
      return !Object.keys(names).some(function(name) { return matcher.test(name); });
    });
  }

  function backupAssessment(backup, nowMs) {
    backup = backup || {};
    var age = evidenceAge(backup.last_success_at, nowMs);
    if (backup.status !== 'ok') return { state: 'critical', age: age };
    if (age.ms === null) return { state: 'unknown', age: age };
    if (age.ms > BACKUP_STALE_MS) return { state: 'high', age: age };
    return { state: 'healthy', age: age };
  }

  function addIncident(items, item) {
    if (!item || !item.issue) return;
    item.severity = item.severity || 'medium';
    items.push(item);
  }

  function sortIncidents(items) {
    return (items || []).slice().sort(function(a, b) {
      var rankA = Object.prototype.hasOwnProperty.call(SEVERITY_RANK, a.severity) ? SEVERITY_RANK[a.severity] : 9;
      var rankB = Object.prototype.hasOwnProperty.call(SEVERITY_RANK, b.severity) ? SEVERITY_RANK[b.severity] : 9;
      return rankA - rankB || a.issue.localeCompare(b.issue);
    });
  }

  function summary(label, state, value, evidence) {
    return { label: label, state: state, value: value, evidence: evidence || 'Evidence unavailable' };
  }

  function buildInfrastructureModel(payload, nowMs) {
    payload = payload && typeof payload === 'object' ? payload : {};
    nowMs = typeof nowMs === 'number' ? nowMs : Date.now();
    var observed = evidenceAge(payload.observed_at, nowMs);
    var observedLabel = observed.ms === null ? 'Live observation unavailable' : 'Observed ' + observed.label;
    var health = payload.health || {};
    var services = health.services || {};
    var disks = Array.isArray(health.disk_usage) ? health.disk_usage : [];
    var freshness = health.ingest_freshness || {};
    var stalest = freshness.stalest_tenant || {};
    var backups = Array.isArray(payload.backups) ? payload.backups : [];
    var certs = Array.isArray(payload.certs) ? payload.certs : [];
    var firewall = payload.firewall || {};
    var maintenance = Array.isArray(payload.maintenance) ? payload.maintenance : [];
    var checks = dedupeCheckIncidents(payload.checks_attention).filter(function(check) {
      // The per-host maintenance rows are the detailed, fixed-scope evidence.
      // Never show the same condition once there and once as a raw check.
      return !/^maintenance_(prod01|api01|portal01)$/.test(check.name);
    });
    var incidents = [];

    var dashboardService = services['patched-dashboard'] || {};
    var nginxService = services.nginx || {};
    var healthError = health.error;
    var availabilityState = 'unknown';
    var explicitLocalServicesHealthy = dashboardService.active === 'active' && nginxService.active === 'active';
    if (health.db_reachable === true && explicitLocalServicesHealthy && !healthError) availabilityState = 'healthy';
    if (healthError) {
      availabilityState = 'critical';
      addIncident(incidents, { severity: 'critical', issue: 'Platform health evidence unavailable', scope: 'patched-api-01', evidence: String(healthError), action: { kind: 'truth' } });
    } else if (health.db_reachable === false) {
      availabilityState = 'critical';
      addIncident(incidents, { severity: 'critical', issue: 'Database unreachable', scope: 'patched-api-01', evidence: observedLabel, action: { kind: 'truth' } });
    } else if (health.db_reachable !== true) {
      addIncident(incidents, { severity: 'medium', issue: 'Database reachability evidence unavailable', scope: 'patched-api-01', evidence: observedLabel, action: { kind: 'truth' } });
    }
    ['patched-dashboard', 'nginx'].forEach(function(name) {
      var service = services[name] || {};
      if (service.active && service.active !== 'active') {
        availabilityState = 'critical';
        addIncident(incidents, { severity: 'critical', issue: name + ' is ' + (service.active || 'unknown'), scope: 'patched-prod-01', evidence: observedLabel, action: { kind: 'truth' } });
      } else if (!service.active) {
        addIncident(incidents, { severity: 'medium', issue: name + ' state unavailable', scope: 'patched-prod-01', evidence: observedLabel, action: { kind: 'truth' } });
      }
    });
    disks.forEach(function(disk) {
      if (Number(disk.used_pct) > 80) {
        addIncident(incidents, { severity: Number(disk.used_pct) > 90 ? 'critical' : 'high', issue: 'Disk capacity above threshold', scope: disk.host || 'unknown host', evidence: observedLabel, action: { kind: 'truth' } });
      }
    });

    var ingestState = freshness.most_recent_ingest_at || stalest.tenant_id ? 'healthy' : 'unknown';
    var staleHours = Number(stalest.hours_stale);
    if (isFinite(staleHours) && staleHours > 6) {
      ingestState = staleHours > 48 ? 'critical' : 'high';
      addIncident(incidents, {
        severity: staleHours > 48 ? 'critical' : 'high',
        issue: 'Tenant ingest is stale',
        scope: stalest.tenant_name || stalest.tenant_id || 'tenant unavailable',
        evidence: staleHours + 'h since tenant evidence',
        action: stalest.tenant_id ? { kind: 'tenant', tenantId: String(stalest.tenant_id), tab: 'device-health' } : { kind: 'truth' },
      });
    }

    var backupStates = backups.map(function(backup) { return backupAssessment(backup, nowMs); });
    var backupsState = backups.length ? 'healthy' : 'unknown';
    backups.forEach(function(backup, index) {
      var assessment = backupStates[index];
      if (assessment.state !== 'healthy') {
        if (assessment.state === 'critical') backupsState = 'critical';
        else if (backupsState !== 'critical') backupsState = assessment.state;
        addIncident(incidents, {
          severity: assessment.state === 'critical' ? 'critical' : assessment.state === 'high' ? 'high' : 'medium',
          issue: assessment.state === 'high' ? 'Backup success evidence is stale' : 'Backup needs attention',
          scope: backup.label || backup.job || 'backup job',
          evidence: assessment.age.label,
          action: { kind: 'truth' },
        });
      }
    });

    var certificateStatus = certificateEvidence(certs);
    var firewallStatus = firewallEvidence(firewall, nowMs);
    var protectionState = certificateStatus.complete && firewallStatus.complete ? 'healthy' : 'unknown';
    if (!certificateStatus.complete) addIncident(incidents, { severity: 'medium', issue: 'Certificate evidence incomplete', scope: 'platform protection', evidence: observedLabel, action: { kind: 'truth' } });
    if (!firewallStatus.complete) addIncident(incidents, { severity: 'medium', issue: 'Firewall evidence incomplete', scope: 'platform protection', evidence: observedLabel, action: { kind: 'truth' } });
    certs.forEach(function(cert) {
      var days = Number(cert.days_left);
      if (cert.error || (isFinite(days) && days <= 0)) {
        protectionState = 'critical';
        addIncident(incidents, { severity: 'critical', issue: cert.error ? 'Certificate evidence unavailable' : 'Certificate expired', scope: cert.hostname || 'certificate', evidence: observedLabel, action: { kind: 'truth' } });
      } else if (isFinite(days) && days < 30) {
        if (protectionState !== 'critical') protectionState = 'high';
        addIncident(incidents, { severity: 'high', issue: 'Certificate expires soon', scope: cert.hostname || 'certificate', evidence: days + 'd remaining', action: { kind: 'truth' } });
      }
    });
    EXPECTED_FIREWALL_EDGES.forEach(function(edge) {
      var item = firewall[edge] || {};
      var age = evidenceAge(item.last_apply_timestamp, nowMs);
      if (item.timer_active === false || (Object.prototype.hasOwnProperty.call(item, 'last_exit_code') && String(item.last_exit_code) !== '0')) {
        protectionState = 'critical';
        addIncident(incidents, { severity: 'critical', issue: item.timer_active === false ? 'Firewall timer inactive' : 'Firewall apply failed', scope: edge, evidence: age.label, action: { kind: 'firewall', edge: edge } });
      }
    });
    if (certificateStatus.critical || firewallStatus.critical) protectionState = 'critical';

    var maintenanceAssessments = maintenance.map(function(row) { return maintenanceAssessment(row, nowMs); });
    var maintenanceState = maintenance.length ? 'healthy' : 'unknown';
    maintenance.forEach(function(row, index) {
      var assessment = maintenanceAssessments[index];
      var rowState = assessment.state;
      if (rowState !== 'healthy') {
        if (rowState === 'critical') maintenanceState = 'critical';
        else if (maintenanceState !== 'critical') maintenanceState = rowState;
        addIncident(incidents, { severity: rowState === 'critical' ? 'critical' : 'medium', issue: row.state === 'ok' ? 'Server maintenance evidence is stale' : 'Server maintenance ' + (row.state || 'unknown'), scope: row.box || 'unknown host', evidence: assessment.age.label, action: { kind: 'truth' } });
      }
    });

    var partition = payload.partitions || {};
    if (partition.warn_short) addIncident(incidents, { severity: 'high', issue: 'Partition horizon is short', scope: 'patched-api-01', evidence: observedLabel, action: { kind: 'truth' } });

    var dashboardVersion = (payload.versions || {}).dashboard || {};
    var provenance = deployProvenance(dashboardVersion);
    var storedDeployDrift = checks.filter(function(check) { return check.name === 'deploy_drift'; })[0];
    if (provenance.state === 'critical') {
      addIncident(incidents, { severity: 'critical', issue: 'Dashboard deployment provenance mismatch', scope: 'patched-prod-01', evidence: observedLabel, action: { kind: 'truth' } });
    } else if (provenance.state === 'unknown') {
      var storedAge = storedDeployDrift && evidenceAge(storedDeployDrift.evaluated_at, nowMs);
      if (storedDeployDrift && storedDeployDrift.state === 'degraded' && storedAge.ms !== null && storedAge.ms <= MAINTENANCE_STALE_MS) {
        addIncident(incidents, { severity: 'high', issue: 'Stored deploy drift observation', scope: 'patched-prod-01', evidence: 'Evaluated ' + storedAge.label, action: { kind: 'truth' }, stored: true });
      } else {
        addIncident(incidents, { severity: 'medium', issue: 'Dashboard deployment provenance unavailable', scope: 'patched-prod-01', evidence: observedLabel, action: { kind: 'truth' } });
      }
    }
    checks.forEach(function(check) {
      var name = check.name || 'scheduler check';
      // Live versions are authoritative for current deploy provenance. A
      // deploy_drift row remains visible as stored evidence but never outranks
      // matching live dashboard/API version facts as a fresh failure.
      var isStoredDeployDrift = name === 'deploy_drift';
      if (isStoredDeployDrift) return;
      addIncident(incidents, {
        severity: check.state === 'degraded' && !isStoredDeployDrift ? 'high' : 'medium',
        issue: name.replace(/_/g, ' '),
        scope: 'scheduler',
        evidence: 'Evaluated ' + evidenceAge(check.evaluated_at, nowMs).label,
        action: { kind: 'truth' },
      });
    });

    incidents = sortIncidents(incidents);

    function summaryValue(state, healthy) {
      if (state === 'healthy') return healthy;
      if (state === 'unknown') return 'Unknown';
      return state === 'critical' ? 'Action required' : 'Needs attention';
    }
    var hostMaintenance = {};
    maintenance.forEach(function(row, index) {
      hostMaintenance[row.box] = { row: row, assessment: maintenanceAssessments[index] };
    });
    var hosts = [
      { host: 'patched-prod-01', service: 'dashboard ' + (dashboardService.active || 'unknown') + '; nginx ' + (nginxService.active || 'unknown'), state: explicitLocalServicesHealthy ? 'healthy' : (dashboardService.active || nginxService.active ? 'critical' : 'unknown'), liveEvidence: observedLabel, maintenance: hostMaintenance['prod-01'] || null },
      { host: 'patched-api-01', service: health.db_reachable === true && !healthError ? 'API database reachable' : health.db_reachable === false ? 'API database unreachable' : 'API reachability unavailable', state: health.db_reachable === true && !healthError ? 'healthy' : health.db_reachable === false ? 'critical' : 'unknown', liveEvidence: observedLabel, maintenance: hostMaintenance['api-01'] || null },
      { host: 'patched-portal-01', service: 'unavailable', state: 'unknown', liveEvidence: 'Live service evidence unavailable', maintenance: hostMaintenance['portal-01'] || null },
    ];

    return {
      summaries: [
        summary('Availability', availabilityState, summaryValue(availabilityState, 'Operating'), observedLabel),
        summary('Ingest', ingestState, summaryValue(ingestState, 'Current'), stalest.tenant_id ? (stalest.tenant_name || stalest.tenant_id) + ': ' + staleHours + 'h' : observedLabel),
        summary('Protection', protectionState, summaryValue(protectionState, 'Current'), observedLabel),
        summary('Backups', backupsState, summaryValue(backupsState, 'Current'), backups.length ? 'Last success: ' + backupStates.map(function(x) { return x.age.label; }).join(', ') : 'Backup evidence unavailable'),
        summary('Server maintenance', maintenanceState, summaryValue(maintenanceState, 'Current'), maintenance.length ? 'Evaluated ' + maintenanceAssessments.map(function(item) { return item.age.label; }).join(', ') : 'Maintenance evidence unavailable'),
      ],
      incidents: incidents,
      hosts: hosts,
      details: { health: health, freshness: freshness, backups: backups, backupStates: backupStates, certs: certs, firewall: firewall, versions: payload.versions || {}, partitions: partition, maintenance: maintenance, maintenanceAssessments: maintenanceAssessments, checks: checks, disks: disks, observed: observedLabel },
    };
  }

  return { BACKUP_STALE_MS: BACKUP_STALE_MS, MAINTENANCE_STALE_MS: MAINTENANCE_STALE_MS, EXPECTED_CERTIFICATE_HOSTS: EXPECTED_CERTIFICATE_HOSTS, EXPECTED_FIREWALL_EDGES: EXPECTED_FIREWALL_EDGES, evidenceAge: evidenceAge, backupAssessment: backupAssessment, maintenanceAssessment: maintenanceAssessment, certificateEvidence: certificateEvidence, firewallEvidence: firewallEvidence, deployProvenance: deployProvenance, shouldSignalTenantEntry: shouldSignalTenantEntry, dedupeCheckIncidents: dedupeCheckIncidents, sortIncidents: sortIncidents, buildInfrastructureModel: buildInfrastructureModel };
});
