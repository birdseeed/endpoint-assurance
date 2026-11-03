/* Patched feedback panel: accessible modal behaviour and client-side upload checks. */
(function () {
  "use strict";

  var form = document.getElementById("feedback-form");
  if (!form) return;
  var dialog = document.getElementById("feedback-dialog");
  if (!dialog) return; /* the /feedback page posts as an ordinary form */
  var openers = document.querySelectorAll("[data-feedback-open]");
  var closers = dialog.querySelectorAll("[data-feedback-close]");
  var screenshot = form.querySelector("[data-feedback-screenshot]");
  var preview = form.querySelector("[data-feedback-preview]");
  var previewImage = form.querySelector("[data-feedback-preview-image]");
  var previewName = form.querySelector("[data-feedback-preview-name]");
  var remove = form.querySelector("[data-feedback-remove]");
  var error = form.querySelector("[data-feedback-error]");
  var success = dialog.querySelector("[data-feedback-success]");
  var route = form.querySelector("[data-feedback-route]");
  var routeDisplay = dialog.querySelector("[data-feedback-route-display]");
  var lastFocused = null;
  var objectUrl = null;

  function browserLabel() {
    var ua = navigator.userAgent || "";
    if (/Edg\//.test(ua)) return "Microsoft Edge";
    if (/Firefox\//.test(ua)) return "Firefox";
    if (/Safari\//.test(ua) && !/Chrome\//.test(ua)) return "Safari";
    if (/Chrome\//.test(ua)) return "Chrome";
    return "Your browser";
  }

  function showError(message) {
    error.textContent = message;
    error.hidden = false;
  }

  function clearError() {
    error.textContent = "";
    error.hidden = true;
  }

  function clearPreview() {
    preview.hidden = true;
    previewImage.removeAttribute("src");
    previewName.textContent = "";
    if (objectUrl) { URL.revokeObjectURL(objectUrl); objectUrl = null; }
  }

  function clearScreenshot() {
    screenshot.value = "";
    clearPreview();
  }

  function setScreenshot(file) {
    if (!file) { clearPreview(); return; }
    if ((file.type !== "image/png" && file.type !== "image/jpeg") || file.size > 5 * 1024 * 1024) {
      clearScreenshot();
      showError("Choose a PNG or JPEG screenshot up to 5 MiB.");
      return;
    }
    clearError();
    clearPreview();
    objectUrl = URL.createObjectURL(file);
    previewImage.src = objectUrl;
    previewName.textContent = file.name;
    preview.hidden = false;
  }

  function open(event) {
    if (event) event.preventDefault(); /* the link is the no-script fallback */
    lastFocused = document.activeElement;
    var currentRoute = window.location.pathname + window.location.search + window.location.hash;
    route.value = currentRoute;
    routeDisplay.textContent = currentRoute;
    dialog.querySelector("[data-feedback-browser]").textContent = browserLabel();
    dialog.hidden = false;
    document.body.classList.add("feedback-open");
    success.hidden = true;
    form.hidden = false;
    clearError();
    form.querySelector("#feedback-title-input").focus();
  }

  function close() {
    if (dialog.hidden) return;
    clearScreenshot();
    dialog.hidden = true;
    document.body.classList.remove("feedback-open");
    if (lastFocused && document.contains(lastFocused)) lastFocused.focus();
  }

  openers.forEach(function (opener) { opener.addEventListener("click", open); });
  closers.forEach(function (closer) { closer.addEventListener("click", close); });
  screenshot.addEventListener("change", function () { setScreenshot(screenshot.files[0]); });
  remove.addEventListener("click", clearScreenshot);
  dialog.addEventListener("click", function (event) { if (event.target === dialog) close(); });
  document.addEventListener("keydown", function (event) {
    if (dialog.hidden) return;
    if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); close(); return; }
    if (event.key !== "Tab") return;
    var focusable = Array.prototype.filter.call(dialog.querySelectorAll(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
    ), function (el) { return !el.hidden && el.offsetParent !== null; });
    if (!focusable.length) return;
    var first = focusable[0], last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  });

  function send(retried) {
    var data = new FormData(form);
    return fetch(form.action, {
      method: "POST",
      body: data,
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    })
      .then(function (response) {
        return response.json().catch(function () { return {}; }).then(function (body) {
          return { response: response, body: body };
        });
      })
      .then(function (result) {
        /* PAT-2216: the page's token went stale while it sat open (the
           session renewed). The server hands back a fresh one; send the
           same draft once more rather than asking for a reload. */
        if (result.response.status === 403 && result.body.csrf_token && !retried) {
          form.querySelector('input[name="csrf_token"]').value = result.body.csrf_token;
          return send(true);
        }
        if (!result.response.ok || !result.body.reference) {
          showError(result.body.error || "We could not send your feedback. Your typed details are still here.");
          return;
        }
        form.hidden = true;
        success.hidden = false;
        success.querySelector("[data-feedback-reference]").textContent = result.body.reference;
        success.focus();
      });
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    clearError();
    if (!form.checkValidity()) { form.reportValidity(); return; }
    var submit = form.querySelector('button[type="submit"]');
    submit.disabled = true;
    send(false)
      .catch(function () {
        showError("We could not reach the Patched platform. Your typed details are still here.");
      })
      .finally(function () { submit.disabled = false; });
  });
})();
