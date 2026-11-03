/*
 * PAT-1356: small, dependency-free Account workspace helpers.
 *
 * Keeping the view state here means the keyboard behaviour exercised by the
 * Console is also covered by node:test. The template owns the account data
 * and server calls; this module only owns presentation state.
 */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleAccountWorkspace = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  var VIEWS = ['profile', 'commercial', 'notifications', 'lifecycle'];

  function normaliseView(view) {
    return VIEWS.indexOf(view) !== -1 ? view : 'profile';
  }

  function viewState(view) {
    var selected = normaliseView(view);
    return VIEWS.map(function(name) {
      return { name: name, selected: name === selected, tabIndex: name === selected ? 0 : -1 };
    });
  }

  function contactCompleteness(account) {
    account = account || {};
    var contacts = [
      account.primary_contact_name && account.primary_contact_email,
      account.technical_contact_name && account.technical_contact_email,
      account.billing_contact_name && account.billing_contact_email,
    ];
    return contacts.filter(Boolean).length + ' / 3 complete';
  }

  function panelAssignments() {
    return {
      profile: ['acct-profile-lifecycle', 'acct-profile-primary', 'acct-profile-technical', 'acct-profile-billing', 'acct-profile-notes', 'acct-profile-actions'],
      commercial: ['acct-commercial-plan', 'acct-commercial-settings', 'acct-support-access-section', 'acct-commercial-actions'],
      lifecycle: ['acct-lifecycle-content', 'acct-danger-zone'],
    };
  }

  function canonicalAppControl(response, currentValue) {
    if (response && Object.prototype.hasOwnProperty.call(response, 'app_control_enabled')) {
      return response.app_control_enabled === true;
    }
    return currentValue === true;
  }

  function applyView(rootEl, view) {
    if (!rootEl) return normaliseView(view);
    var selected = normaliseView(view);
    rootEl.setAttribute('data-active-account-view', selected);
    Array.prototype.forEach.call(rootEl.querySelectorAll('[data-account-view-button]'), function(button) {
      var active = button.getAttribute('data-account-view-button') === selected;
      button.setAttribute('aria-selected', active ? 'true' : 'false');
      button.tabIndex = active ? 0 : -1;
    });
    return selected;
  }

  function nextView(view, key) {
    var index = VIEWS.indexOf(normaliseView(view));
    if (key === 'ArrowRight' || key === 'ArrowDown') return VIEWS[(index + 1) % VIEWS.length];
    if (key === 'ArrowLeft' || key === 'ArrowUp') return VIEWS[(index + VIEWS.length - 1) % VIEWS.length];
    if (key === 'Home') return VIEWS[0];
    if (key === 'End') return VIEWS[VIEWS.length - 1];
    return normaliseView(view);
  }

  function optionalServiceFeature(serviceModule, options) {
    if (!serviceModule || typeof serviceModule.createOrchestrationController !== 'function') {
      return { available: false, module: null, controller: null };
    }
    try {
      return {
        available: true,
        module: serviceModule,
        controller: serviceModule.createOrchestrationController(options || {}),
      };
    } catch (error) {
      // Isolating this failure keeps the rest of the Account workspace
      // usable (see the caller's own try/catch), but swallowing it
      // completely left no trace anywhere a failure here could occur
      // without also throwing further up — log so it's diagnosable.
      if (typeof console !== 'undefined' && console.error) {
        console.error('[service-engagement] createOrchestrationController failed', error);
      }
      return { available: false, module: null, controller: null };
    }
  }

  function bootstrapOptionalServiceFeature(root, options) {
    try {
      var accountModule = root && root.PatchedConsoleAccountWorkspace;
      if (!accountModule || typeof accountModule.optionalServiceFeature !== 'function') {
        return { available: false, module: null, controller: null };
      }
      return accountModule.optionalServiceFeature(root.PatchedConsoleServiceEngagement, options || {});
    } catch (error) {
      if (typeof console !== 'undefined' && console.error) {
        console.error('[service-engagement] bootstrap failed', error);
      }
      return { available: false, module: null, controller: null };
    }
  }

  return { applyView: applyView, bootstrapOptionalServiceFeature: bootstrapOptionalServiceFeature, canonicalAppControl: canonicalAppControl, contactCompleteness: contactCompleteness, nextView: nextView, normaliseView: normaliseView, optionalServiceFeature: optionalServiceFeature, panelAssignments: panelAssignments, viewState: viewState };
});
