/*
 * PAT-2404: Software identities screen.
 *
 * Staff review software identities that devices reported into the platform's
 * curated identity catalogue, and can withdraw one. The console stores
 * nothing: every read and write is a proxy to the platform. This is an
 * identity catalogue, not a package catalogue, so no installer, label,
 * deployment or update field exists here.
 *
 * Every dynamic string (observed names, publishers, vendor names, reasons)
 * is attacker-influenced, so rows are built with createElement and
 * textContent only. innerHTML is never assigned in this file.
 */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleSoftwareIdentities = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  var PLATFORMS = { macos: 'macOS', windows: 'Windows' };
  var KIND_LABELS = {
    macos_bundle_team: 'Bundle ID with Team ID',
    windows_native_publisher: 'Identifier with publisher'
  };
  // Problem states, in the order they are reported. Counts are installations.
  var PROBLEMS = [
    ['adhoc', 'ad hoc', 'ad hoc'], ['unsigned', 'unsigned', 'unsigned'],
    ['untrusted', 'untrusted', 'untrusted'], ['invalid', 'invalid', 'invalid'],
    ['error', 'with a signing error', 'with a signing error'],
    ['unknown', 'unknown', 'unknown']
  ];

  function str(v) { return v == null ? '' : String(v); }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }
  function installs(n) { return plural(n, 'install', 'installs'); }
  function count(states, key) { var n = Number(states[key]); return n > 0 ? n : 0; }

  function platformLabel(platform) { return PLATFORMS[platform] || str(platform); }
  function companionLabel(platform) { return platform === 'windows' ? 'Publisher' : 'Team ID'; }
  function identityKindLabel(kind) { return KIND_LABELS[kind] || str(kind); }

  // Plain-words evidence summary. The counts are current installations per
  // signing state, so the wording says installs, not devices.
  function evidenceSummary(candidate) {
    var c = candidate || {};
    var ev = c.evidence || {};
    var states = ev.signing_states || {};
    var windows = c.platform === 'windows' || /windows/.test(str(c.identity_kind)) ||
      (!c.platform && states.valid != null);
    var total = 0;
    Object.keys(states).forEach(function(k) { total += count(states, k); });
    var notReported = count(states, 'not_reported');
    if (total === 0 || notReported === total) return 'No signing status reported';

    var good = count(states, windows ? 'valid' : 'signed');
    var parts = [];
    if (good > 0) {
      if (good === total) parts.push((windows ? 'Valid signature on ' : 'Signed on ') + installs(total));
      else parts.push((windows ? 'Valid on ' : 'Signed on ') + good + ' of ' + installs(total));
    }
    var roots = (ev.root_kinds || []).map(function(r) {
      var t = str(r).replace(/_/g, ' ').trim();
      return t === 'microsoft' ? 'Microsoft' : t;
    }).filter(Boolean);
    if (roots.length) parts.push(roots.join(' and ') + ' root');
    var keys = Number(ev.authenticode_publisher_key_count) || 0;
    if (keys > 1) parts.push(keys + ' signing keys');
    PROBLEMS.forEach(function(p) {
      var n = count(states, p[0]);
      if (!n) return;
      parts.push(p[1] === 'with a signing error'
        ? plural(n, 'install', 'installs') + ' with a signing error'
        : n + ' ' + p[1] + ' ' + (n === 1 ? 'install' : 'installs'));
    });
    if (notReported) parts.push(notReported + ' not reporting');
    var out = parts.join(', ');
    return out.charAt(0).toUpperCase() + out.slice(1);
  }

  function defaultName(candidate) {
    var names = (candidate && candidate.observed_names) || [];
    return names.length ? str(names[0]) : '';
  }

  // Windows candidates may carry the observed publisher; macOS leaves it empty.
  function defaultVendor(candidate) {
    var pubs = (candidate && candidate.observed_publishers) || [];
    return candidate && candidate.platform === 'windows' && pubs.length ? str(pubs[0]) : '';
  }

  // The four identity fields are carried verbatim from the candidate row and
  // are never taken from the form.
  function reviewBody(candidate, form) {
    return {
      platform: candidate.platform,
      identity_kind: candidate.identity_kind,
      identity_value_normalized: candidate.identity_value_normalized,
      companion_value_normalized: candidate.companion_value_normalized,
      canonical_name: str(form.canonical_name).trim(),
      vendor_name: str(form.vendor_name).trim(),
      reason: str(form.reason).trim()
    };
  }

  function validateReviewForm(form) {
    if (!str(form.canonical_name).trim()) return 'Product name is required.';
    if (!str(form.vendor_name).trim()) return 'Vendor is required.';
    if (!str(form.reason).trim()) return 'A reason is required.';
    return '';
  }

  function formatDate(iso) {
    if (!iso) return '';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return str(iso);
    return d.toISOString().slice(0, 10);
  }

  // ── DOM building (textContent only) ──────────────────────────────────────

  function el(doc, tag, className, text) {
    var node = doc.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }
  function cell(doc, text, className) { return el(doc, 'td', className || '', text); }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  // Long values truncate with an ellipsis; the full value rides in title.
  function identityCell(doc, value) {
    var td = cell(doc, str(value) || '-', 'swid-mono swid-ident');
    if (value) td.title = str(value);
    return td;
  }

  // The platform sends blocked_reason as a short code; show a plain sentence.
  var BLOCKED = {
    bad_signature_present: 'An install of this identity is ad hoc signed, unsigned, untrusted or has an invalid signature.',
    team_id_malformed: 'The Team ID is not a ten character Apple Team ID.',
    no_signed_installation: 'No install of this identity is reported as signed.',
    publisher_missing: 'This identity has no publisher.',
    no_valid_authenticode: 'No install has a valid Authenticode signature. A registry publisher alone is not evidence.',
    enterprise_root_only: 'The valid signatures chain only to an enterprise root, which cannot be checked independently.'
  };
  function blockedText(code) {
    var c = str(code).trim();
    if (!c) return 'Cannot be reviewed.';
    return Object.prototype.hasOwnProperty.call(BLOCKED, c) ? BLOCKED[c] : 'Cannot be reviewed (' + c + ').';
  }

  function seenOn(c) {
    var d = c.device_count, t = c.tenant_count;
    if (d == null && t == null) return '-';
    return plural(Number(d) || 0, 'device', 'devices') + ', ' + plural(Number(t) || 0, 'tenant', 'tenants');
  }

  function candidateRow(doc, c, opts) {
    var tr = el(doc, 'tr', c.promotable ? '' : 'swid-blocked');
    var names = (c.observed_names || []).map(str).filter(Boolean);
    tr.appendChild(cell(doc, names.length ? names.join(', ') : '-', 'swid-name'));
    tr.appendChild(identityCell(doc, c.identity_value_normalized));
    tr.appendChild(identityCell(doc, c.companion_value_normalized));
    tr.appendChild(cell(doc, seenOn(c)));
    tr.appendChild(cell(doc, evidenceSummary(c), 'swid-evidence'));
    var action = el(doc, 'td', 'swid-action');
    if (c.promotable) {
      if (opts.canWrite) {
        var btn = el(doc, 'button', 'owner-only swid-btn', 'Review');
        btn.type = 'button';
        btn.addEventListener('click', function() { opts.onReview(c); });
        action.appendChild(btn);
      }
    } else {
      action.appendChild(el(doc, 'span', 'swid-reason', blockedText(c.blocked_reason)));
    }
    tr.appendChild(action);
    return tr;
  }

  function renderCandidates(doc, tbody, candidates, opts) {
    clear(tbody);
    candidates.forEach(function(c) { tbody.appendChild(candidateRow(doc, c, opts)); });
  }

  function aliasRow(doc, a, opts) {
    var tr = el(doc, 'tr', a.retired_at ? 'swid-retired' : '');
    tr.appendChild(cell(doc, str(a.canonical_name) || '-', 'swid-name'));
    tr.appendChild(cell(doc, str(a.vendor_name) || '-'));
    tr.appendChild(cell(doc, platformLabel(a.platform) || '-'));
    var idCell = el(doc, 'td', 'swid-mono');
    var idLine = el(doc, 'div', 'swid-ident', str(a.identity_value_normalized) || '-');
    if (a.identity_value_normalized) idLine.title = str(a.identity_value_normalized);
    idCell.appendChild(idLine);
    if (a.companion_value_normalized) {
      idCell.appendChild(el(doc, 'div', 'swid-companion',
        companionLabel(a.platform) + ': ' + str(a.companion_value_normalized)));
    }
    tr.appendChild(idCell);
    tr.appendChild(cell(doc, str(a.created_by) || '-', 'swid-nowrap'));
    tr.appendChild(cell(doc, formatDate(a.last_reviewed_at || a.created_at) || '-', 'swid-nowrap'));
    var status = a.retired_at ? 'Retired ' + formatDate(a.retired_at) : 'Live';
    tr.appendChild(cell(doc, status, 'swid-nowrap'));
    var action = el(doc, 'td', 'swid-action');
    if (!a.retired_at && opts.canWrite) {
      var btn = el(doc, 'button', 'owner-only swid-btn', 'Retire');
      btn.type = 'button';
      btn.addEventListener('click', function() { opts.onRetire(a); });
      action.appendChild(btn);
    }
    tr.appendChild(action);
    return tr;
  }

  function renderAliases(doc, tbody, aliases, opts) {
    clear(tbody);
    aliases.forEach(function(a) { tbody.appendChild(aliasRow(doc, a, opts)); });
  }

  return {
    platformLabel: platformLabel,
    companionLabel: companionLabel,
    evidenceSummary: evidenceSummary,
    seenOn: seenOn,
    blockedText: blockedText,
    identityKindLabel: identityKindLabel,
    defaultName: defaultName,
    defaultVendor: defaultVendor,
    reviewBody: reviewBody,
    validateReviewForm: validateReviewForm,
    formatDate: formatDate,
    renderCandidates: renderCandidates,
    renderAliases: renderAliases
  };
});
