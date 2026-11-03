/* PAT-1321: pure Runbook presentation helpers for browser and Node.
 * Category labels, note filtering and safe-HTML linkification live here so
 * they're covered by npm run test:console instead of only being reachable
 * through a full DOM render. templates/console.html calls into this module;
 * it holds no DOM/fetch code so it can run standalone in tests. */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleRunbook = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  var CATEGORY_LABELS = {
    onboarding: 'Onboarding',
    support: 'Support',
    deployment: 'Deployment',
    reporting: 'Reporting',
    billing: 'Billing',
    technical: 'Technical',
    other: 'Other'
  };

  function categoryLabel(category) {
    return CATEGORY_LABELS[category] || CATEGORY_LABELS.other;
  }

  function categoryOptions() {
    return Object.keys(CATEGORY_LABELS).map(function(value) {
      return { value: value, label: CATEGORY_LABELS[value] };
    });
  }

  // filterNotes — options: { query, category, pinnedOnly }. Never mutates
  // or re-sorts the input; the server already orders pinned-first /
  // most-recently-updated, and callers rely on that order surviving a filter.
  function filterNotes(notes, options) {
    options = options || {};
    var query = String(options.query || '').trim().toLowerCase();
    var category = String(options.category || 'all');
    var pinnedOnly = !!options.pinnedOnly;
    return (notes || []).filter(function(note) {
      note = note || {};
      if (pinnedOnly && !note.pinned) return false;
      if (category !== 'all' && note.category !== category) return false;
      if (!query) return true;
      var haystack = [note.title, note.body, categoryLabel(note.category)].join(' ').toLowerCase();
      return haystack.indexOf(query) !== -1;
    });
  }

  function escapeHtml(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // linkifyHtml — escapes HTML first, then turns bare http(s) URLs into
  // clickable links and newlines into <br>. Always operates on
  // already-escaped text so it can never introduce raw markup from note
  // content (notes are internal-operator-authored, but still untrusted
  // input rendered via innerHTML).
  function linkifyHtml(text) {
    var escaped = escapeHtml(text).replace(/\n/g, '<br>');
    return escaped.replace(/(https?:\/\/[^\s<]+)/g, function(url) {
      return '<a href="' + url + '" target="_blank" rel="noopener noreferrer">' + url + '</a>';
    });
  }

  return {
    categoryLabel: categoryLabel,
    categoryOptions: categoryOptions,
    filterNotes: filterNotes,
    escapeHtml: escapeHtml,
    linkifyHtml: linkifyHtml
  };
});
