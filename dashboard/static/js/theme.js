/* Patched.im dashboard — light/dark theme.
 *
 * Loaded synchronously in <head> so the theme is applied before first
 * paint (no flash). Sets [data-theme] on <html> from the saved
 * preference, falling back to the OS setting. The toggle button is
 * injected into .sidebar on DOMContentLoaded, so no page markup is
 * required — this file is the single source for theming on both the
 * main dashboard (/) and the console (/console).
 */
(function () {
  var KEY = 'patched-theme';

  // The build id is read from this script's own ?v= cache-bust query, which
  // console.html renders from CONSOLE_BUILD_ID in main.py. Deriving it here
  // rather than hardcoding a second copy is deliberate: a hardcoded constant
  // silently drifts every time main.py's build id is bumped, and a mismatch
  // is not a cosmetic bug — the server redirects /console to its build id
  // while this script redirects back to the stale one, producing an infinite
  // redirect loop that presents as a flashing page (worst on mobile). That
  // has now bitten twice (PAT-966, and again on 2026-07-25). There is exactly
  // one source of truth: main.py.
  function consoleBuildId() {
    var el = document.currentScript;
    if (!el) {
      var all = document.getElementsByTagName('script');
      for (var i = 0; i < all.length; i++) {
        if ((all[i].src || '').indexOf('/static/js/theme.js') !== -1) { el = all[i]; break; }
      }
    }
    var m = /[?&]v=([^&]+)/.exec((el && el.src) || '');
    return m ? decodeURIComponent(m[1]) : null;
  }

  function redirectConsoleIfStale() {
    var path = window.location.pathname || '';
    if (!/^\/console(?:\/|$)/.test(path)) return;
    var buildId = consoleBuildId();
    // Fail safe: if the build id can't be determined, do not redirect. A
    // stale console is recoverable; a redirect loop is not.
    if (!buildId) return;
    if (path === '/console/' + buildId) return;
    window.location.replace('/console/' + buildId + (window.location.hash || ''));
  }

  function read() {
    try { return localStorage.getItem(KEY); } catch (e) { return null; }
  }
  function write(v) {
    try { localStorage.setItem(KEY, v); } catch (e) {}
  }
  function systemPref() {
    return (window.matchMedia &&
            window.matchMedia('(prefers-color-scheme: light)').matches)
      ? 'light' : 'dark';
  }
  function current() {
    return document.documentElement.getAttribute('data-theme') === 'light'
      ? 'light' : 'dark';
  }
  function apply(theme) {
    document.documentElement.setAttribute('data-theme', theme);
  }

  // Apply immediately — this runs during <head> parsing, before <body>.
  apply(read() || systemPref());
  redirectConsoleIfStale();

  function paintButton() {
    var btn = document.getElementById('themeToggle');
    if (!btn) return;
    btn.textContent = current() === 'light' ? '☾  Dark' : '☀  Light';
    btn.setAttribute('aria-label', 'Switch to ' +
      (current() === 'light' ? 'dark' : 'light') + ' theme');
  }

  function toggle() {
    var next = current() === 'light' ? 'dark' : 'light';
    apply(next);
    write(next);
    paintButton();
  }
  window.toggleTheme = toggle;

  document.addEventListener('DOMContentLoaded', function () {
    // PAT-1047: the toggle now lives in the top-bar operator identity menu
    // (#theme-toggle-slot), not the old sidebar footer — the identity menu is
    // the one place it's needed in the new single-topbar shell.
    var slot = document.getElementById('theme-toggle-slot');
    if (!slot || document.getElementById('themeToggle')) return;
    var btn = document.createElement('button');
    btn.id = 'themeToggle';
    btn.type = 'button';
    btn.className = 'theme-toggle';
    btn.addEventListener('click', toggle);
    slot.appendChild(btn);
    paintButton();
  });
})();
