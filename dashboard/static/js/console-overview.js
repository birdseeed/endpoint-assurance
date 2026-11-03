(function(root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.PatchedConsoleOverview = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  // PAT-1809: decide what the tenant Overview hero should render, given which
  // (if any) of _ov2Load's parallel fetches failed outright.
  //
  // Before this, every fetch failure was swallowed into the same fallback
  // shape a genuinely-empty successful fetch produces (null / []), so a fully
  // failed load (patched-api-01 unreachable) fed zeros into every risk signal
  // and rendered a false "Healthy" / score 100 verdict — the opposite of the
  // truth, which is "we have no idea." This function is the single place that
  // decides between three, and only three, hero states, kept dependency-free
  // (no DOM) so the decision itself is unit-testable:
  //
  //   - 'unavailable' — one or more of the 5 fetches failed. We do not know
  //     the estate's real state. Must never look like 'scored' or 'no-data'.
  //   - 'no-data'      — every fetch succeeded and the tenant genuinely has
  //     zero devices. This is a real, verified fact, not an absence of
  //     evidence — must render unchanged from before this ticket.
  //   - 'scored'        — every fetch succeeded and totalDevices > 0; render
  //     the health score/verdict the caller already computed.
  //
  // failedFetches must be failure-tracked separately from "fetch succeeded,
  // data was empty" by the caller — collapsing those two into one fallback
  // value is exactly the bug this closes.
  function resolveHeroState(input) {
    input = input || {};
    var failedFetches = input.failedFetches || [];

    if (failedFetches.length > 0) {
      return {
        mode: 'unavailable',
        score: null,
        verdict: 'Data unavailable',
        vColor: 'var(--red)',
        sub: 'Could not verify estate health. ' + failedFetches.join(', ') +
          ' failed to load. This is not a clean bill of health; retry once patched-api-01 is reachable.',
        badgeVisible: false,
      };
    }

    if (input.noData) {
      return {
        mode: 'no-data',
        score: null,
        verdict: 'No data yet',
        vColor: 'var(--muted)',
        sub: 'No device data for this tenant yet.',
        badgeVisible: false,
      };
    }

    var issues = input.issues || [];
    return {
      mode: 'scored',
      score: input.score,
      verdict: input.verdict,
      vColor: input.vColor,
      sub: issues.length
        ? issues.length + ' issue' + (issues.length === 1 ? '' : 's') + ' to work through. Most urgent first below.'
        : 'No open issues across this estate.',
      badgeVisible: true,
    };
  }

  return { resolveHeroState: resolveHeroState };
});
