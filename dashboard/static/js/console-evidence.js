/*
 * Pure Evidence workspace helpers (PAT-1613) shared by the browser console and
 * Node tests. Owns the truthful labels and guards around issued report
 * evidence: frozen coverage figures, hashes, supersession display and the
 * pre-issue coverage guard. The UI keeps transport/DOM concerns in
 * console.html; this module owns the derivations so they can be tested
 * without a browser.
 *
 * Backend contract (go-service/internal/handlers/report_delivery.go,
 * migration 0126): a report_records row freezes pdf_sha256/xlsx_sha256,
 * issued_at and coverage_snapshot the moment it is issued, and never changes
 * again except a single one-time superseded_by_report_id write. This module
 * never recomputes any of those figures from live data — it only formats
 * whatever the row already froze.
 */
(function(root, factory) {
  var api = factory();
  root.PatchedConsoleEvidence = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';

  // formatHash renders a stored hex SHA-256 as the artboard's short form
  // ("sha256 4f9c…a1e2"). Returns null when the record has no hash yet
  // (e.g. PDF generation failed and only the XLSX was stored) — callers must
  // render that as an explicit absence, never as a placeholder hash.
  function formatHash(hex) {
    if (!hex || typeof hex !== 'string' || hex.length < 12) return null;
    return 'sha256 ' + hex.slice(0, 4) + '…' + hex.slice(-4);
  }

  // PAT-1741 (defect 4): coverage_snapshot has two write-side shapes today,
  // from two different report handlers in the patched.im Go repo, and this
  // module reads both without unifying them (that would be a backend change,
  // out of this ticket's scope — see go-service/docs/SCHEMA.md for the
  // canonical shape documentation):
  //
  //   1. Scheduled portal report (portalCoverageSnapshot, portal.go):
  //      { source: "portal_overview", devices_total, devices_reporting_24h,
  //        devices_degraded, cis_score_current,
  //        oldest_successful_ingest? }
  //      No findings_total/findings_by_severity — the portal path never
  //      calls addFindingsSnapshot.
  //
  //   2. Console-issued executive summary / correction
  //      (executiveCoverageSnapshot + addFindingsSnapshot, report_delivery.go):
  //      { source: "executive_summary", devices_total, devices_macos,
  //        devices_windows, devices_active_24h, devices_active_7d,
  //        compliance_overall_pct, findings_total?, findings_by_severity? }
  //      findings_* are added by a second write only when the findings query
  //      succeeded at issue time; absent (not zero) otherwise.
  //
  // coverageFromSnapshot below reads devices_total + devices_active_7d only.
  // A portal_overview snapshot has devices_total but not devices_active_7d
  // (it freezes devices_reporting_24h instead — a genuinely different figure,
  // a 24h window rather than 7d), so a portal-sourced row renders "not
  // available" here rather than a wrong or fabricated percentage. That is a
  // fail-safe absence, not a crash and not a fabricated value — consistent
  // with root AGENTS.md's "absence requires authority" — but it does mean
  // scheduled/portal-issued reports never show a coverage percentage in the
  // Evidence tab today. Deliberately not widened to also read
  // devices_reporting_24h: conflating a 24h figure with the 7d one this
  // function reports as "coverage" would misrepresent what was actually
  // measured (root AGENTS.md's CVE/usage "verify ... version semantics"
  // constraint applies equally to a coverage-window claim). Surfacing the
  // portal path's own 24h figure, under its own label, is a separate,
  // deliberate follow-up, not a change folded into this read.
  //
  // findingsFromSnapshot needs no such caveat: a portal_overview snapshot
  // has no findings_total key at all (the portal path never computes one),
  // so it correctly falls through to "not captured" for both an old
  // pre-PAT-1685 executive_summary row and every portal_overview row, old
  // or new alike.

  // coverageFromSnapshot derives a "coverage then" percentage from the
  // frozen coverage_snapshot JSON. Coverage is fraction of the estate that
  // had reported within 7 days at issue time (devices_active_7d /
  // devices_total), which is the closest real, stored measure of "how much
  // of the estate could this report see" — compliance_overall_pct is a
  // different figure (a control-pass score) and is exposed separately, not
  // substituted here. Returns { available:false, reason } rather than 0
  // when there is nothing frozen to read: an issued report with an empty
  // snapshot has no coverage figure, not a zero one.
  function coverageFromSnapshot(snapshot) {
    var s = snapshot && typeof snapshot === 'object' ? snapshot : {};
    var total = Number(s.devices_total);
    var active7d = Number(s.devices_active_7d);
    if (!isFinite(total) || total <= 0) {
      return { available: false, reason: 'no coverage figure was frozen for this report' };
    }
    if (!isFinite(active7d)) {
      return { available: false, reason: 'no coverage figure was frozen for this report' };
    }
    var pct = Math.max(0, Math.min(100, (active7d / total) * 100));
    return {
      available: true,
      pct: pct,
      devicesTotal: total,
      devicesSeen: active7d,
      compliancePct: isFinite(Number(s.compliance_overall_pct)) ? Number(s.compliance_overall_pct) : null,
    };
  }

  // findingsFromSnapshot reads the frozen findings_total/findings_by_severity
  // pair that coverage_snapshot carries as of PAT-1685 (sourced at issue time
  // from the same query TenantCVEFindingsHandler's severity_counts bar uses —
  // see go-service/docs/SCHEMA.md, "Findings figure in coverage_snapshot").
  // Both keys are absent (never present-but-zero) on a legacy row issued
  // before PAT-1685, or one where the findings query failed at issue time —
  // that absence must render as "not captured", never as a fabricated zero.
  // There is deliberately no live-recompute fallback: showing today's
  // findings count next to a frozen report would misrepresent it as also
  // frozen. severityOrder controls display order; a bucket only appears in
  // breakdown when it is present and greater than zero, and an "unknown"
  // bucket is itself only ever present on the row when the backend had at
  // least one such finding to count.
  function findingsFromSnapshot(snapshot) {
    var s = snapshot && typeof snapshot === 'object' ? snapshot : {};
    var total = Number(s.findings_total);
    if (!isFinite(total)) {
      return { available: false, reason: 'not captured at issue time' };
    }
    var bySeverity = (s.findings_by_severity && typeof s.findings_by_severity === 'object') ? s.findings_by_severity : {};
    var severityOrder = ['critical', 'high', 'medium', 'low', 'unknown'];
    var parts = [];
    severityOrder.forEach(function(sev) {
      var n = Number(bySeverity[sev]);
      if (isFinite(n) && n > 0) parts.push(n + ' ' + sev);
    });
    return {
      available: true,
      total: total,
      bySeverity: bySeverity,
      breakdown: parts.join(', '),
    };
  }

  // sentToLabel reads report_records.recipient_summary. In the deployed
  // pipeline this field is written once as '[]' on insert and nothing since
  // has ever populated it (delivery was never wired to a mailer) — so this
  // will read "Not recorded" for every real row today. Kept as a real read
  // rather than hardcoded so it starts working the moment delivery lands.
  function sentToLabel(record) {
    var summary = record && record.recipient_summary;
    if (Array.isArray(summary) && summary.length) {
      return summary.map(function(r) {
        if (typeof r === 'string') return r;
        return (r && (r.label || r.email)) || 'recipient';
      }).join(', ');
    }
    return 'Not recorded';
  }

  // supersessionInfo describes the self-referential relationship carried by
  // supersedes_report_id / superseded_by_report_id. Both fields are
  // immutable-once-set (migration 0126); this only formats what is already
  // on the row, it never creates the link.
  function supersessionInfo(record) {
    var r = record || {};
    var out = { supersedes: null, supersededBy: null };
    if (r.supersedes_report_id) {
      out.supersedes = 'Supersedes #' + shortId(r.supersedes_report_id);
    }
    if (r.superseded_by_report_id) {
      out.supersededBy = 'Superseded by #' + shortId(r.superseded_by_report_id);
    }
    return out;
  }

  function shortId(id) {
    var s = String(id || '');
    return s.length > 8 ? s.slice(0, 8) : s;
  }

  // correctionErrorMessage maps POST .../report-records/generate's
  // supersedes_report_id rejections (go-service/docs/SCHEMA.md, "Issuing a
  // correction (PAT-1685)") to plain operator-facing text. status is the
  // HTTP status code; rawBody is the response body text (JSON or not —
  // parsed defensively, same as every other adminFetch catch in this
  // console). Falls back to whatever the backend said, or a generic message,
  // for any status this table doesn't name.
  function correctionErrorMessage(status, rawBody) {
    var parsed = null;
    try { parsed = JSON.parse(rawBody); } catch (e) { /* not JSON */ }
    var raw = (parsed && parsed.error) || (typeof rawBody === 'string' ? rawBody : '');
    if (status === 409) return 'This report has already been corrected.';
    if (status === 404) return 'That report could not be found, or has not finished issuing yet.';
    if (status === 400) return 'That report could not be identified as a correction target.';
    return raw || 'Failed to issue correction.';
  }

  // canIssueReport is the pre-issue guard: refuse to issue a report when
  // there is no real coverage figure to freeze. estateCoverage is the LIVE
  // estate figure computed for the tenant right now (device count etc,
  // fetched fresh for this check) — not a report's frozen snapshot, since
  // no report exists yet at this point. { fetchOk:false } means the device
  // fetch itself failed, which must also block issuing rather than issue
  // against unknown data.
  function canIssueReport(estateCoverage) {
    var c = estateCoverage || {};
    if (!c.fetchOk) {
      return { allowed: false, reason: 'Coverage could not be determined — device data failed to load. Try again before issuing.' };
    }
    if (!isFinite(Number(c.devicesTotal)) || Number(c.devicesTotal) <= 0) {
      return { allowed: false, reason: 'This estate has no devices on record. A report cannot be issued without a coverage statement to populate.' };
    }
    return { allowed: true, reason: '' };
  }

  // coverageStatementText builds the standing disclaimer paragraph (verbatim
  // shape from docs/design/console-redesign/07-evidence.html) from real,
  // live figures. asOfDate is a pre-formatted date string.
  function coverageStatementText(estateCoverage, asOfDate) {
    var c = estateCoverage || {};
    if (!c.fetchOk || !isFinite(Number(c.devicesTotal))) {
      return 'Coverage could not be determined for this estate right now.';
    }
    var total = Number(c.devicesTotal);
    var seen = isFinite(Number(c.devicesSeen)) ? Number(c.devicesSeen) : 0;
    var unseen = Math.max(0, total - seen);
    var unseenClause = unseen > 0
      ? unseen + (unseen === 1 ? ' device could not be inspected and is listed individually at the end.' : ' devices could not be inspected and are listed individually at the end.')
      : 'Every device on the estate list was inspected.';
    return 'This report covers ' + seen + ' of ' + total + ' devices on the estate list as at ' + asOfDate + '. ' +
      unseenClause + ' They are not represented as compliant. Findings marked version confirmed were read from the ' +
      'installed application. Findings marked name match are weaker and are labelled as such.';
  }

  // assessorPackItems: the 5-part checklist from the artboard. `available`
  // reflects whether this console can back the item with real data today —
  // never a fabricated checkmark. Items 3-5 are not backed by any deployed
  // data model as of PAT-1613 (no CIS-control mapping on findings, no
  // disposition record, no customer-facing action log) and must render as
  // "not yet available", not as done.
  function assessorPackItems() {
    return [
      { n: 1, title: 'Estate inventory at a stated moment', available: true },
      { n: 2, title: 'Coverage statement, including what was not seen', available: true },
      { n: 3, title: 'Findings with their basis, mapped to controls', available: false,
        reason: 'findings are not yet linked to CIS controls in this console' },
      { n: 4, title: 'Dispositions, with who said what and when', available: false,
        reason: 'no disposition record exists yet (PAT-1613 scope gap)' },
      { n: 5, title: 'Actions taken, and by whom', available: false,
        reason: 'no customer-facing action log is exposed yet' },
    ];
  }

  return {
    formatHash: formatHash,
    coverageFromSnapshot: coverageFromSnapshot,
    findingsFromSnapshot: findingsFromSnapshot,
    sentToLabel: sentToLabel,
    supersessionInfo: supersessionInfo,
    correctionErrorMessage: correctionErrorMessage,
    canIssueReport: canIssueReport,
    coverageStatementText: coverageStatementText,
    assessorPackItems: assessorPackItems,
  };
});
