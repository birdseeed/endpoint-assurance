// Patched.im docs — site interactions. Vanilla JS, no deps.
(function () {
  var nav = document.querySelector('.nav');
  var btn = document.querySelector('.nav__burger');
  if (btn && nav) {
    btn.addEventListener('click', function () { nav.classList.toggle('open'); });
    document.addEventListener('click', function (e) {
      if (nav.classList.contains('open') && !nav.contains(e.target)) {
        nav.classList.remove('open');
      }
    });
  }

  // "Guides" nav dropdown. CSS :hover/:focus-within already open it for
  // mouse and tab/keyboard users; this click toggle is what makes it work
  // on touch devices (tablets, etc.) that have no hover state, and lets
  // Escape close it again.
  var dropdown = document.querySelector('.nav__dropdown');
  var trigger = dropdown && dropdown.querySelector('.nav__dropdown-trigger');
  if (dropdown && trigger) {
    trigger.addEventListener('click', function (e) {
      e.stopPropagation();
      var isOpen = dropdown.classList.toggle('open');
      trigger.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    });
    document.addEventListener('click', function (e) {
      if (dropdown.classList.contains('open') && !dropdown.contains(e.target)) {
        dropdown.classList.remove('open');
        trigger.setAttribute('aria-expanded', 'false');
      }
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && dropdown.classList.contains('open')) {
        dropdown.classList.remove('open');
        trigger.setAttribute('aria-expanded', 'false');
        trigger.focus();
      }
    });
  }

  // Footer copyright year.
  document.querySelectorAll('[data-year]').forEach(function (e) {
    e.textContent = new Date().getFullYear();
  });
})();
