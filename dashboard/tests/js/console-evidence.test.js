const test = require('node:test');
const assert = require('node:assert/strict');
const {
  formatHash,
  coverageFromSnapshot,
  findingsFromSnapshot,
  sentToLabel,
  supersessionInfo,
  correctionErrorMessage,
  canIssueReport,
  coverageStatementText,
  assessorPackItems,
} = require('../../static/js/console-evidence.js');

test('formatHash renders the short form and refuses to invent one', () => {
  assert.equal(formatHash('4f9c1122334455667788990011223344556677889900112233445566778899a1e2'), 'sha256 4f9c…a1e2');
  assert.equal(formatHash(null), null);
  assert.equal(formatHash(''), null);
  assert.equal(formatHash('short'), null);
});

test('coverageFromSnapshot reads devices_active_7d/devices_total, not compliance_overall_pct', () => {
  const cov = coverageFromSnapshot({ devices_total: 248, devices_active_7d: 222, compliance_overall_pct: 91.2 });
  assert.equal(cov.available, true);
  assert.ok(Math.abs(cov.pct - (222 / 248 * 100)) < 0.001);
  assert.equal(cov.devicesTotal, 248);
  assert.equal(cov.devicesSeen, 222);
  assert.equal(cov.compliancePct, 91.2);
});

test('coverageFromSnapshot refuses to show a figure that was never frozen', () => {
  assert.equal(coverageFromSnapshot({}).available, false);
  assert.equal(coverageFromSnapshot(null).available, false);
  assert.equal(coverageFromSnapshot({ devices_total: 0 }).available, false);
});

// PAT-1741, defect 4: two write-side coverage_snapshot shapes exist
// (go-service handlers portal.go's portalCoverageSnapshot and
// report_delivery.go's executiveCoverageSnapshot). Both are read here without
// a crash or a fabricated figure; only the executive_summary shape actually
// carries devices_active_7d, so only it renders a coverage percentage today.
test('coverageFromSnapshot reads the executive_summary shape', () => {
  const cov = coverageFromSnapshot({
    source: 'executive_summary',
    devices_total: 100,
    devices_macos: 60,
    devices_windows: 40,
    devices_active_24h: 88,
    devices_active_7d: 95,
    compliance_overall_pct: 91.2,
  });
  assert.equal(cov.available, true);
  assert.equal(cov.pct, 95);
  assert.equal(cov.devicesTotal, 100);
  assert.equal(cov.devicesSeen, 95);
});

test('coverageFromSnapshot has no crash and no fabricated percentage for the portal_overview shape (devices_reporting_24h, not devices_active_7d)', () => {
  const cov = coverageFromSnapshot({
    source: 'portal_overview',
    devices_total: 100,
    devices_reporting_24h: 88,
    devices_degraded: 3,
    cis_score_current: 74,
  });
  assert.equal(cov.available, false);
  assert.equal(cov.reason, 'no coverage figure was frozen for this report');
});

test('findingsFromSnapshot reads not captured for the portal_overview shape, which never carries findings_total', () => {
  const f = findingsFromSnapshot({
    source: 'portal_overview',
    devices_total: 100,
    devices_reporting_24h: 88,
    devices_degraded: 3,
    cis_score_current: 74,
  });
  assert.equal(f.available, false);
  assert.equal(f.reason, 'not captured at issue time');
});

test('findingsFromSnapshot never fabricates a count the snapshot does not carry', () => {
  const f = findingsFromSnapshot({ devices_total: 10 });
  assert.equal(f.available, false);
  assert.equal(f.reason, 'not captured at issue time');
  assert.equal(findingsFromSnapshot({}).available, false);
  assert.equal(findingsFromSnapshot(null).available, false);
});

test('findingsFromSnapshot renders the frozen findings_total/findings_by_severity when present', () => {
  const f = findingsFromSnapshot({
    findings_total: 9,
    findings_by_severity: { critical: 1, high: 2, medium: 3, low: 1, unknown: 2 },
  });
  assert.equal(f.available, true);
  assert.equal(f.total, 9);
  assert.deepEqual(f.bySeverity, { critical: 1, high: 2, medium: 3, low: 1, unknown: 2 });
  assert.equal(f.breakdown, '1 critical, 2 high, 3 medium, 1 low, 2 unknown');
});

test('findingsFromSnapshot treats a present-but-zero total as real, and omits zero buckets from the breakdown', () => {
  const f = findingsFromSnapshot({ findings_total: 0, findings_by_severity: {} });
  assert.equal(f.available, true);
  assert.equal(f.total, 0);
  assert.equal(f.breakdown, '');
});

test('correctionErrorMessage maps the documented supersedes_report_id rejections to plain language', () => {
  assert.equal(correctionErrorMessage(409, '{"error":"already superseded"}'), 'This report has already been corrected.');
  assert.equal(correctionErrorMessage(404, '{"error":"not found"}'), 'That report could not be found, or has not finished issuing yet.');
  assert.equal(correctionErrorMessage(400, '{"error":"supersedes_report_id must be a UUID"}'), 'That report could not be identified as a correction target.');
  assert.equal(correctionErrorMessage(500, '{"error":"boom"}'), 'boom');
  assert.equal(correctionErrorMessage(500, 'not json'), 'not json');
  assert.equal(correctionErrorMessage(500, ''), 'Failed to issue correction.');
});

test('sentToLabel is honest about the never-wired delivery pipeline', () => {
  assert.equal(sentToLabel({ recipient_summary: [] }), 'Not recorded');
  assert.equal(sentToLabel({}), 'Not recorded');
  assert.equal(sentToLabel({ recipient_summary: [{ email: 's.voss@example.com' }] }), 's.voss@example.com');
  assert.equal(sentToLabel({ recipient_summary: ['auditor@example.com'] }), 'auditor@example.com');
});

test('supersessionInfo formats both directions of the self-reference without inventing either', () => {
  assert.deepEqual(supersessionInfo({}), { supersedes: null, supersededBy: null });
  const original = supersessionInfo({ superseded_by_report_id: 'abcdef12-3456-7890' });
  assert.equal(original.supersedes, null);
  assert.equal(original.supersededBy, 'Superseded by #abcdef12');
  const correction = supersessionInfo({ supersedes_report_id: '11112222-3333' });
  assert.equal(correction.supersedes, 'Supersedes #11112222');
  assert.equal(correction.supersededBy, null);
});

test('canIssueReport blocks on a failed fetch and on zero devices, allows a real estate', () => {
  assert.equal(canIssueReport({ fetchOk: false }).allowed, false);
  assert.equal(canIssueReport({ fetchOk: true, devicesTotal: 0 }).allowed, false);
  assert.equal(canIssueReport({ fetchOk: true, devicesTotal: 12, devicesSeen: 10 }).allowed, true);
});

test('coverageStatementText follows the artboard template from live figures', () => {
  const text = coverageStatementText({ fetchOk: true, devicesTotal: 248, devicesSeen: 222 }, '6 September 2026');
  assert.match(text, /covers 222 of 248 devices/);
  assert.match(text, /as at 6 September 2026/);
  assert.match(text, /26 devices could not be inspected/);
  assert.match(text, /not represented as compliant/);
});

test('coverageStatementText singular unseen device and zero-unseen phrasing', () => {
  assert.match(coverageStatementText({ fetchOk: true, devicesTotal: 5, devicesSeen: 4 }, 'today'), /1 device could not be inspected and is listed/);
  assert.match(coverageStatementText({ fetchOk: true, devicesTotal: 5, devicesSeen: 5 }, 'today'), /Every device on the estate list was inspected/);
});

test('assessorPackItems marks only genuinely backed items available', () => {
  const items = assessorPackItems();
  assert.equal(items.length, 5);
  assert.deepEqual(items.filter(i => i.available).map(i => i.n), [1, 2]);
  assert.deepEqual(items.filter(i => !i.available).map(i => i.n), [3, 4, 5]);
  items.filter(i => !i.available).forEach(i => assert.ok(i.reason && i.reason.length > 0));
});
