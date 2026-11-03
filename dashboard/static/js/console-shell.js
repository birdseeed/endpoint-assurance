/* PAT-2373: shell presentation only. Server permissions remain authoritative. */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleShell = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';
  var globals = ['home', 'customers-list', 'ops', 'automations', 'truth', 'reports', 'docs', 'credentials', 'homebrew-review', 'software-identities', 'software-alerts', 'logs'];
  function parseRoute(hash) {
    var parts = String(hash || '').replace(/^#/, '').split('/');
    if (parts[0] === 'tenant' && parts[1]) {
      try { return { section: 'tenant-workspace', tenantId: decodeURIComponent(parts[1]), tab: parts[2] || null }; }
      catch (_) { return { section: 'home' }; }
    }
    return { section: globals.indexOf(parts[0]) !== -1 ? parts[0] : 'home' };
  }
  function isGlobal(section) { return globals.indexOf(section) !== -1; }
  function clearTenant(state) {
    ['tenantId', 'tenantName', 'tenantTier', 'tenantFleet', 'tenantData', 'activeTab', 'deviceId'].forEach(function(key) { state[key] = null; });
  }
  function navigate(history, location, hash, replace) {
    if (location.hash === '#' + hash && location.pathname === '/console') return;
    history[replace ? 'replaceState' : 'pushState'](null, '', '/console' + location.search + '#' + hash);
  }
  function busy(panel, value) { if (panel) panel.setAttribute('aria-busy', value ? 'true' : 'false'); }
  // Human names describe the source without granting new evidence or scope.
  var checks = {
    deploy_drift: ['Dashboard version check', 'Compares the checked-out files with the recorded deployed revision. A stale comparison does not prove the release is old.'],
    maintenance_prod01: ['Server maintenance checks', 'Checks dashboard server settings for unexpected changes.'],
    maintenance_api01: ['Server maintenance checks', 'Checks API server settings for unexpected changes.'],
    maintenance_portal01: ['Server maintenance checks', 'Checks portal server settings for unexpected changes.'],
    automation_alerts: ['Scheduled job alerts', 'Checks delivery of alerts about scheduled jobs.'],
    automation_digest: ['Scheduled job summary', 'Checks delivery of the scheduled job summary.'],
    email_delivery: ['Email delivery', 'Checks recorded email sending outcomes. Acceptance does not prove recipient receipt.'],
    health_alert_delivery: ['Service alert delivery', 'Checks recorded delivery of service health alerts.'],
    portal_auth: ['Customer sign-in check', 'Checks the recorded portal authentication probe.'],
    rbac_operators: ['Staff access configuration', 'Checks configured staff roles.']
  };
  function checkCopy(id) {
    var key = String(id || '').replace(/^tick_/, '').replace(/_check$/, '');
    if (key === 'maintenance_drift') key = 'maintenance_prod01';
    var copy = Object.prototype.hasOwnProperty.call(checks, key) ? checks[key] : null;
    return copy ? { name: copy[0], explanation: copy[1] } :
      { name: 'Service check', explanation: 'Recorded service check result. Technical identity is available in details.' };
  }
  return { checkCopy: checkCopy, parseRoute: parseRoute, isGlobal: isGlobal, clearTenant: clearTenant, navigate: navigate, busy: busy };
});
