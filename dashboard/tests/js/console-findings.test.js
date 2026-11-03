const test = require('node:test');
const assert = require('node:assert/strict');
const {
  basisLabel,
  basisClass,
  cveEvidenceBasis,
  cisEvidenceBasis,
  matchesBasisFilter,
  matchesSeverityFilter,
  coverageFromLifecycle,
  emptyStateKind,
  summarizeCveDevices,
  cveGuidanceNote,
  ruleIdMap,
  artefactFilename,
  findingDispositionKey,
  dispositionIndex,
  dispositionForFinding,
  matchesDispositionFilter,
  findingDispositionPayload,
} = require('../../static/js/console-findings.js');

test('basisLabel/basisClass cover all four tiers and default to the weakest', () => {
  assert.equal(basisLabel('confirmed'), 'version confirmed');
  assert.equal(basisLabel('name_match'), 'name match only');
  assert.equal(basisLabel('unclassified'), 'unclassified');
  assert.equal(basisLabel('not_inspected'), 'not inspected');
  assert.equal(basisLabel('bogus'), 'not inspected');
  assert.equal(basisClass('confirmed'), 'rdx-evidence-basis--confirmed');
  assert.equal(basisClass('bogus'), 'rdx-evidence-basis--not-inspected');
});

test('cveEvidenceBasis defaults to not_inspected -- the platform aggregate has no confidence field yet', () => {
  assert.equal(cveEvidenceBasis({ cve_id: 'CVE-2026-1' }), 'not_inspected');
  assert.equal(cveEvidenceBasis(null), 'not_inspected');
});

test('cveEvidenceBasis reads a forward-compatible evidence_basis field first', () => {
  assert.equal(cveEvidenceBasis({ evidence_basis: 'confirmed' }), 'confirmed');
  assert.equal(cveEvidenceBasis({ evidence_basis: 'name_match' }), 'name_match');
});

test('cveEvidenceBasis maps device_cve_findings.match_confidence vocabulary', () => {
  assert.equal(cveEvidenceBasis({ match_confidence: 'version_confirmed' }), 'confirmed');
  assert.equal(cveEvidenceBasis({ match_confidence: 'version_vendor_confirmed' }), 'confirmed');
  assert.equal(cveEvidenceBasis({ match_confidence: 'version_unverified' }), 'name_match');
  assert.equal(cveEvidenceBasis({ match_confidence: 'something_unknown' }), 'not_inspected');
});

test('cisEvidenceBasis is always confirmed -- CIS reads a real signal, never a display name', () => {
  assert.equal(cisEvidenceBasis(), 'confirmed');
  assert.equal(cisEvidenceBasis({ anything: true }), 'confirmed');
});

test('matchesBasisFilter and matchesSeverityFilter treat all/empty as pass-through', () => {
  assert.equal(matchesBasisFilter('confirmed', 'all'), true);
  assert.equal(matchesBasisFilter('confirmed', ''), true);
  assert.equal(matchesBasisFilter('confirmed', 'name_match'), false);
  assert.equal(matchesBasisFilter('name_match', 'name_match'), true);
  assert.equal(matchesSeverityFilter('high', 'all'), true);
  assert.equal(matchesSeverityFilter('high', 'low'), false);
});

test('coverageFromLifecycle counts only "reporting" devices as inspected in-window', () => {
  const cov = coverageFromLifecycle([
    { state: 'reporting' }, { state: 'reporting' }, { state: 'stale' }, { state: 'never-seen' },
  ]);
  assert.equal(cov.total, 4);
  assert.equal(cov.reporting, 2);
  assert.equal(cov.excluded, 2);
  assert.equal(cov.fullCoverage, false);
});

test('coverageFromLifecycle reports full coverage only when every device is reporting', () => {
  const cov = coverageFromLifecycle([{ state: 'reporting' }, { state: 'reporting' }]);
  assert.equal(cov.excluded, 0);
  assert.equal(cov.fullCoverage, true);
});

test('coverageFromLifecycle refuses to call zero devices "full coverage"', () => {
  assert.equal(coverageFromLifecycle([]).fullCoverage, false);
  assert.equal(coverageFromLifecycle(null).total, 0);
});

test('emptyStateKind picks "unknown" (cannot say yet) over "clean" whenever coverage is incomplete', () => {
  assert.equal(emptyStateKind({ total: 10, reporting: 7, fullCoverage: false }), 'unknown');
  assert.equal(emptyStateKind({ total: 0, reporting: 0, fullCoverage: false }), 'unknown');
});

test('emptyStateKind only returns "clean" for genuine full coverage', () => {
  assert.equal(emptyStateKind({ total: 10, reporting: 10, fullCoverage: true }), 'clean');
});

test('summarizeCveDevices computes distinct version count and the earliest last-seen', () => {
  const s = summarizeCveDevices([
    { installed_version: '1.0', agent_last_seen: '2026-09-01T00:00:00Z' },
    { installed_version: '1.0', agent_last_seen: '2026-09-10T00:00:00Z' },
    { installed_version: '2.0', agent_last_seen: '2026-08-20T00:00:00Z' },
  ]);
  assert.equal(s.deviceCount, 3);
  assert.equal(s.versionSpread, 2);
  assert.equal(s.oldestLastSeen, '2026-08-20T00:00:00Z');
});

test('summarizeCveDevices handles an empty or missing device list', () => {
  const s = summarizeCveDevices([]);
  assert.equal(s.deviceCount, 0);
  assert.equal(s.versionSpread, 0);
  assert.equal(s.oldestLastSeen, null);
  assert.equal(summarizeCveDevices(undefined).deviceCount, 0);
});

test('cveGuidanceNote stays a software-update note and flags Windows separately, never a generated artefact', () => {
  const note = cveGuidanceNote({ os_families: ['macOS'] });
  assert.ok(note.indexOf('update') !== -1);
  assert.ok(note.indexOf('partner remediation tool') === -1);
  const winNote = cveGuidanceNote({ os_families: ['Windows'] });
  assert.ok(winNote.indexOf('partner remediation tool') !== -1);
});

test('ruleIdMap builds rule_key -> rule_id and skips incomplete rows', () => {
  const map = ruleIdMap([
    { rule_key: 'macos.filevault', rule_id: 'r-1' },
    { rule_key: 'no-id' },
    null,
  ]);
  assert.deepEqual(map, { 'macos.filevault': 'r-1' });
});

test('artefactFilename picks the right extension per platform and sanitises the rule key', () => {
  assert.equal(artefactFilename({ platform: 'macos', rule_key: 'macos.filevault' }), 'macos.filevault.mobileconfig');
  assert.equal(artefactFilename({ platform: 'windows', rule_key: 'win/disk enc' }), 'win-disk-enc.json');
  assert.equal(artefactFilename(null), 'remediation.mobileconfig');
});

test('finding disposition identities preserve CIS device scope and CVE tenant scope', () => {
  assert.equal(findingDispositionKey('cis', { device_id: 'device-a', rule_key: 'cis.filevault' }),
    'cis:device-a:cis.filevault');
  assert.equal(findingDispositionKey('cve', { cve_id: 'CVE-2026-0001' }), 'cve:CVE-2026-0001');
  assert.equal(findingDispositionKey('cis', { rule_key: 'cis.filevault' }), null);
  assert.equal(findingDispositionKey('cve', {}), null);
});

test('disposition index joins each exact finding identity only', () => {
  const index = dispositionIndex([
    { finding_kind: 'cis', device_id: 'device-a', rule_key: 'cis.filevault', status: 'acknowledged' },
    { finding_kind: 'cve', cve_id: 'CVE-2026-0001', status: 'risk_accepted' },
  ]);
  assert.equal(dispositionForFinding(index, 'cis', { device_id: 'device-a', rule_key: 'cis.filevault' }).status,
    'acknowledged');
  assert.equal(dispositionForFinding(index, 'cis', { device_id: 'device-b', rule_key: 'cis.filevault' }), null);
  assert.equal(dispositionForFinding(index, 'cve', { cve_id: 'CVE-2026-0001' }).status, 'risk_accepted');
});

test('disposition filters distinguish no disposition from each active status', () => {
  const ack = { status: 'acknowledged' };
  assert.equal(matchesDispositionFilter(null, 'none'), true);
  assert.equal(matchesDispositionFilter(ack, 'none'), false);
  assert.equal(matchesDispositionFilter(ack, 'acknowledged'), true);
  assert.equal(matchesDispositionFilter(ack, 'closed'), false);
  assert.equal(matchesDispositionFilter(null, 'all'), true);
});

test('finding disposition payload uses exactly one supported identity shape and omits blank reason', () => {
  assert.deepEqual(
    findingDispositionPayload('cis', { device_id: 'device-a', rule_key: 'cis.filevault' }, 'closed', 'Jane', ' '),
    { finding_kind: 'cis', device_id: 'device-a', rule_key: 'cis.filevault', status: 'closed', recorded_by: 'Jane' },
  );
  assert.deepEqual(
    findingDispositionPayload('cve', { cve_id: 'CVE-2026-0001' }, 'risk_accepted', 'Jane', 'Accepted until patch'),
    { finding_kind: 'cve', cve_id: 'CVE-2026-0001', status: 'risk_accepted', recorded_by: 'Jane', reason: 'Accepted until patch' },
  );
});
