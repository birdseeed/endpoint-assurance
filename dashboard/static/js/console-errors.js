/*
 * PAT-1810: shared adminFetch() error-message extraction.
 *
 * adminFetch() throws an Error whose `.body` is the raw upstream response
 * text (often JSON like {"error":"...","status":401,"body":"...\n"}, but
 * sometimes a plain string). Every console error banner should render a
 * clean operator-facing message, never that raw blob. This is a pure
 * function (no DOM) so Node's built-in test runner can exercise it
 * directly instead of only trusting each call site to parse it the same
 * way.
 */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleErrors = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  // adminErrorText — turn an adminFetch() rejection into operator-facing text.
  //
  // Precedence when err.body parses as JSON: body || detail || error, then
  // the raw body string itself. A trailing newline (upstream error bodies
  // are frequently plain-text lines, e.g. "unauthorized\n") is trimmed so
  // it never shows up as a stray blank line in a banner.
  function adminErrorText(err) {
    var body = err && err.body;
    if (body) {
      try {
        var parsed = JSON.parse(body);
        var text = parsed.body || parsed.detail || parsed.error || body;
        return _trimTrailing(text);
      } catch (_) {
        return _trimTrailing(body);
      }
    }
    return (err && err.message) || String(err || 'Unknown error');
  }

  function _trimTrailing(text) {
    return typeof text === 'string' ? text.replace(/\s+$/, '') : text;
  }

  return {
    adminErrorText: adminErrorText,
  };
});
