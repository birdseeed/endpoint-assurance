(function(root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.PatchedConsoleCISControls = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  // PAT-1690: a CIS control's pass rate must be measured against the devices
  // actually evaluated against it, not the tenant's raw device total. A
  // platform-scoped rule (e.g. Windows-only) is never evaluated on the other
  // platform's devices at all, so counting them in the denominator silently
  // turns "never evaluated" into an implicit pass and inflates every
  // platform-scoped control's percentage.
  //
  // `control.evaluatedDevices` is the per-rule count from the tenant-rules
  // API (evaluated_devices). `totalDevices` is the tenant's raw device count,
  // used only as a fallback for a control that predates that field (older
  // cached response, or the API not yet carrying it) so this degrades
  // gracefully rather than breaking.
  function computeRow(control, totalDevices) {
    var failCount = (control && control.devices ? control.devices.length : 0);
    var evalCount = (control && typeof control.evaluatedDevices === 'number')
      ? control.evaluatedDevices
      : (totalDevices || 0);
    var passCount = Math.max(0, evalCount - failCount);
    var pct       = evalCount > 0 ? Math.round(passCount / evalCount * 100) : 0;
    return { evaluatedDevices: evalCount, failCount: failCount, passCount: passCount, pct: pct };
  }

  return { computeRow: computeRow };
});
