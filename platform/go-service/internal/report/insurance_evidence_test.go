package report

// PAT-2258 unit tests for the insurance evidence pack's assembly rules,
// driven through buildInsuranceEvidence with hand-built source read models
// (no database). The DB-backed agreement tests, which prove each answer
// matches its source read model for a seeded tenant, live in
// internal/handlers/portal_insurance_evidence_db_test.go.

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/lifecycle"
	"patched.im/api/internal/remoteaccess"
)

var insTestNow = time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)

func insTime(ago time.Duration) *time.Time {
	t := insTestNow.Add(-ago)
	return &t
}

func insCEDevice(id, bucket string, lastSeen *time.Time) CEDevice {
	return CEDevice{DeviceID: id, Hostname: id, Platform: "macos",
		Reporting:   CEReporting{Bucket: bucket, Source: "devices.last_seen", ObservedAt: lastSeen},
		CVEEvidence: CEEvidence{State: CEEvidenceEvidenced, Source: "device_cve_findings"},
		Items:       []CEItem{}, Controls: []CEControl{}}
}

// insFixture is a four-device in-scope estate plus one device the source
// models carry that CE readiness excluded (retired):
//
//	active  reported within 24h   covered, encrypted,  2 admins
//	stale   reported 3 days ago   covered, not enc.,   4 admins
//	silent  last seen 30 days ago covered, encrypted,  1 admin   (never counted)
//	never   no usable report time covered, encrypted,  1 admin   (never counted)
//	retired not in scope          covered, encrypted,  1 admin   (never counted)
func insFixture() *insuranceSources {
	ce := PortalCEReadiness{GeneratedAt: insTestNow, Estate: CEEstate{RetiredExcluded: 1}}
	active := insCEDevice("active", "active", insTime(time.Hour))
	stale := insCEDevice("stale", "stale", insTime(72*time.Hour))
	silent := insCEDevice("silent", "silent", insTime(30*24*time.Hour))
	never := insCEDevice("never", "unknown", nil)
	ce.Devices = []CEDevice{active, stale, silent, never}

	all := []string{"active", "stale", "silent", "never", "retired"}
	edr := &EDRCoverageReport{GeneratedAt: insTestNow}
	enc := &EncryptionPostureReport{GeneratedAt: insTestNow}
	adm := &LocalAdminReport{GeneratedAt: insTestNow}
	for _, id := range all {
		edr.Devices = append(edr.Devices, EDRDevice{DeviceID: id, State: EDRStateCovered, Tools: []string{"Sophos"}})
		fv, state := "On", EncryptionStateEncrypted
		if id == "stale" {
			fv, state = "Off", EncryptionStateNotEncrypted
		}
		enc.Devices = append(enc.Devices, EncryptionRow{DeviceID: id, OS: "macOS", FileVault: strPtr(fv), State: state})
		n, risk := 1, "compliant"
		switch id {
		case "active":
			n = 2
		case "stale":
			n, risk = 4, "at-risk"
		}
		adm.Devices = append(adm.Devices, LocalAdminDevice{DeviceID: id, AdminCount: n, ReportedAdminCount: n, Risk: risk,
			AdminNames: []string{"admin", id + "-user"}})
	}
	return &insuranceSources{now: insTestNow, ce: ce, edr: edr, enc: enc, admin: adm,
		life: &lifecycle.Report{GeneratedAt: insTestNow, Basis: lifecycle.Basis{DevicesAssessed: 4}},
		remote: &remoteaccess.Report{GeneratedAt: insTestNow, Basis: remoteaccess.Basis{DevicesAssessed: 4},
			Summary: remoteaccess.Summary{RemoteAccess: map[string]remoteaccess.StateCount{}}}}
}

func insFind(t *testing.T, p InsuranceEvidence, id string) InsuranceAnswer {
	t.Helper()
	for _, q := range p.Questions {
		if q.ID == id {
			return q
		}
	}
	t.Fatalf("question %q missing from pack", id)
	return InsuranceAnswer{}
}

func insCount(t *testing.T, a InsuranceAnswer, key string, want int) {
	t.Helper()
	got, ok := a.Answer.Counts[key]
	if !ok {
		t.Errorf("%s: counts has no %q (%v)", a.ID, key, a.Answer.Counts)
		return
	}
	if got != want {
		t.Errorf("%s: counts[%q] = %d, want %d", a.ID, key, got, want)
	}
}

// A device that has not reported within 14 days, or has no usable report
// time, is never counted towards a positive figure, even when its last
// evidence was positive; and a device outside the CE readiness scope
// (retired) is not counted at all.
func TestInsuranceEvidence_NotReportingNeverCountsAsCompliant(t *testing.T) {
	p := buildInsuranceEvidence(insFixture())

	edr := insFind(t, p, "edr_coverage")
	if edr.Answer.Value == nil || *edr.Answer.Value != 2 {
		t.Fatalf("edr covered = %v, want 2 (active + stale; silent, never and retired excluded)", edr.Answer.Value)
	}
	insCount(t, edr, "devices_in_scope", 4)
	insCount(t, edr, "not_reporting", 2)
	if edr.Answer.Percentage == nil || *edr.Answer.Percentage != 50.0 {
		t.Errorf("edr percentage = %v, want 50.0 (over every in-scope device)", edr.Answer.Percentage)
	}
	if edr.UnknownDevices == nil || *edr.UnknownDevices != 2 || edr.Status != InsurancePartial {
		t.Errorf("edr unknown = %v status %s, want 2 / partial", edr.UnknownDevices, edr.Status)
	}

	enc := insFind(t, p, "disk_encryption")
	if enc.Answer.Value == nil || *enc.Answer.Value != 1 {
		t.Fatalf("encrypted = %v, want 1 (active only; stale reported off)", enc.Answer.Value)
	}
	insCount(t, enc, "not_encrypted", 1)
	insCount(t, enc, "not_reporting", 2)
	if enc.UnknownDevices == nil || *enc.UnknownDevices != 2 {
		t.Errorf("encryption unknown = %v, want 2", enc.UnknownDevices)
	}

	adm := insFind(t, p, "local_admin_rights")
	if adm.Answer.Value == nil || *adm.Answer.Value != 6 {
		t.Fatalf("admin accounts = %v, want 6 (2 + 4 from reporting devices only)", adm.Answer.Value)
	}
	insCount(t, adm, "devices_with_count", 2)
	insCount(t, adm, "devices_2_or_fewer", 1)
	insCount(t, adm, "devices_3_to_4", 1)
	insCount(t, adm, "not_reporting", 2)
	insCount(t, adm, "distinct_account_names", 3)

	inv := insFind(t, p, "asset_inventory")
	insCount(t, inv, "devices_in_scope", 4)
	insCount(t, inv, "reported_14_days", 2)
	insCount(t, inv, "retired_excluded", 1)
	if inv.UnknownDevices == nil || *inv.UnknownDevices != 2 {
		t.Errorf("inventory unknown = %v, want 2", inv.UnknownDevices)
	}
}

// Every device answering positively but not reporting flips its question to
// partial, never evidenced; an estate where every device reports and is
// covered is the only way to reach evidenced.
func TestInsuranceEvidence_EvidencedOnlyWhenEveryDeviceDeterminate(t *testing.T) {
	s := insFixture()
	s.ce.Devices = s.ce.Devices[:2] // active + stale only
	p := buildInsuranceEvidence(s)
	if got := insFind(t, p, "edr_coverage").Status; got != InsuranceEvidenced {
		t.Errorf("edr status = %s, want evidenced when both in-scope devices are covered and reporting", got)
	}
	s.edr.Devices[0].State = EDRStateUnrecognised
	p = buildInsuranceEvidence(s)
	edr := insFind(t, p, "edr_coverage")
	if edr.Status != InsurancePartial || *edr.UnknownDevices != 1 {
		t.Errorf("unrecognised tool: status %s unknown %v, want partial / 1", edr.Status, *edr.UnknownDevices)
	}
	insCount(t, edr, "unrecognised_tool", 1)
	s.edr.Devices = nil // no evidence for anyone
	if got := insFind(t, buildInsuranceEvidence(s), "edr_coverage").Status; got != InsuranceUnknown {
		t.Errorf("no evidence at all: status %s, want unknown", got)
	}
}

// Patching reuses CE readiness: items past 14 days count wherever they are;
// "nothing outstanding" needs an active device with complete CVE evidence.
func TestInsuranceEvidence_PatchingFromCEReadiness(t *testing.T) {
	s := insFixture()
	d := s.ce.Devices
	d[0].Items = []CEItem{{CVEID: "CVE-1", Severity: "critical", AgeDays: 40}, {CVEID: "CVE-2", Severity: "high", AgeDays: 20}}
	d[2].Items = []CEItem{{CVEID: "CVE-3", Severity: "high", AgeDays: 15}} // silent, still positive evidence
	// d[1] stale, no items: unknown. d[3] no report time: unknown.
	p := buildInsuranceEvidence(s)
	a := insFind(t, p, "patching_speed")
	insCount(t, a, "updates_over_14_days", 3)
	insCount(t, a, "updates_over_30_days", 1)
	insCount(t, a, "critical_over_14_days", 1)
	insCount(t, a, "high_over_14_days", 2)
	insCount(t, a, "devices_over_14_days", 2)
	insCount(t, a, "devices_over_30_days", 1)
	insCount(t, a, "devices_none_outstanding", 0)
	insCount(t, a, "devices_unknown", 2)
	if a.Status != InsurancePartial {
		t.Errorf("patching status = %s, want partial", a.Status)
	}

	// Active device with no items but incomplete CVE evidence is unknown.
	s = insFixture()
	s.ce.Devices = s.ce.Devices[:1]
	s.ce.Devices[0].CVEEvidence.State = CEEvidenceUnknown
	a = insFind(t, buildInsuranceEvidence(s), "patching_speed")
	insCount(t, a, "devices_none_outstanding", 0)
	insCount(t, a, "devices_unknown", 1)
	if a.Status != InsuranceUnknown {
		t.Errorf("status = %s, want unknown", a.Status)
	}
	if !strings.Contains(a.AnswerText, "cannot say") {
		t.Errorf("answer text should say Patched cannot say: %q", a.AnswerText)
	}
}

// PAT-2496: an observed failure must never be reported as unknown. A Windows
// device whose built-in Administrator account was read as enabled has a real
// finding even when it reported no usable admin count, so it is counted as
// enabled and, separately, as having no admin count. A device with both is
// counted once. A built-in account whose state was not established is not an
// observation and is not counted.
func TestInsuranceEvidence_BuiltinAdminEnabledCountedWithoutAdminCount(t *testing.T) {
	s := insFixture()
	byID := map[string]*LocalAdminDevice{}
	for i := range s.admin.Devices {
		byID[s.admin.Devices[i].DeviceID] = &s.admin.Devices[i]
	}
	// active: enabled built-in Administrator, no admin count signal.
	*byID["active"] = LocalAdminDevice{DeviceID: "active", AdminCount: -1, ReportedAdminCount: -1, Risk: "unknown",
		BuiltinAdmin: BuiltinAdminEnabled}
	// stale: enabled built-in Administrator and an admin count of 4.
	byID["stale"].BuiltinAdmin = BuiltinAdminEnabled
	// silent and never are not in the picture: not reporting.

	a := insFind(t, buildInsuranceEvidence(s), "local_admin_rights")
	insCount(t, a, "devices_builtin_admin_enabled", 2)
	insCount(t, a, "devices_with_count", 1)
	insCount(t, a, "admin_accounts", 4)
	insCount(t, a, "no_evidence", 1)
	insCount(t, a, "not_reporting", 2)
	if !strings.Contains(a.AnswerText, "2 devices have the built-in Windows Administrator account enabled") {
		t.Errorf("answer must state both enabled built-in accounts: %q", a.AnswerText)
	}
	if a.UnknownDevices == nil || *a.UnknownDevices != 3 {
		t.Errorf("unknown devices = %v, want 3 (one with no admin count, two not reporting)", a.UnknownDevices)
	}

	// Not established is not an observation.
	s = insFixture()
	for i := range s.admin.Devices {
		if s.admin.Devices[i].DeviceID == "active" {
			s.admin.Devices[i] = LocalAdminDevice{DeviceID: "active", AdminCount: -1, ReportedAdminCount: -1, Risk: "unknown",
				BuiltinAdmin: BuiltinAdminUnknown}
		}
	}
	a = insFind(t, buildInsuranceEvidence(s), "local_admin_rights")
	insCount(t, a, "devices_builtin_admin_enabled", 0)
	insCount(t, a, "no_evidence", 1)
}

func TestInsuranceEvidence_UnsupportedAndRemoteAccess(t *testing.T) {
	s := insFixture()
	s.life.Basis.DevicesAssessed = 3
	s.life.Basis.UnassessedDeviceIDs = []string{"stale"}
	s.life.Rows = []lifecycle.Row{
		{DeviceID: "active", Kind: lifecycle.KindOperatingSystem, State: lifecycle.StateUnsupported},
		{DeviceID: "active", Kind: lifecycle.KindApplication, State: lifecycle.StateUnknown},
		{DeviceID: "stale", Kind: lifecycle.KindOperatingSystem, State: lifecycle.StateSupported},
		{DeviceID: "other", Kind: lifecycle.KindOperatingSystem, State: lifecycle.StateSupported},
		{DeviceID: "other", Kind: lifecycle.KindApplication, State: lifecycle.StateUnsupported},
		{DeviceID: "other", Kind: lifecycle.KindApplication, State: lifecycle.StateUnsupported},
	}
	p := buildInsuranceEvidence(s)
	u := insFind(t, p, "unsupported_software")
	insCount(t, u, "devices_unsupported_os", 1)
	insCount(t, u, "devices_unsupported_software", 1)
	insCount(t, u, "unsupported_software_installations", 2)
	insCount(t, u, "devices_with_any_unsupported", 2)
	// "active" has an unknown app but positive unsupported evidence, so only
	// "stale" (unassessed) is unknown.
	if u.UnknownDevices == nil || *u.UnknownDevices != 1 || u.Status != InsurancePartial {
		t.Errorf("unsupported unknown %v status %s, want 1 / partial", u.UnknownDevices, u.Status)
	}

	// Remote access: a complete basis is still only partial, because
	// detection is catalogue-limited.
	s.remote.Summary.RemoteAccessToolCount = 2
	s.remote.Summary.RemoteAccess = map[string]remoteaccess.StateCount{
		remoteaccess.StateApproved: {Tools: 1}, remoteaccess.StateUnapproved: {Tools: 1}}
	r := insFind(t, buildInsuranceEvidence(s), "remote_access_tools")
	if r.Status != InsurancePartial || r.Reason == nil || *r.Reason != InsuranceReasonCatalogueLimited {
		t.Errorf("remote access status %s reason %v, want partial / catalogue_limited", r.Status, r.Reason)
	}
	insCount(t, r, "approved_tools", 1)
	insCount(t, r, "unapproved_tools", 1)
	if !strings.Contains(r.AnswerText, "not proof that none is installed") {
		t.Errorf("remote access text must carry the detection caveat: %q", r.AnswerText)
	}
}

// Not-evidenced items are always present, in every shape of pack: normal,
// no devices, and every optional source failed.
func TestInsuranceEvidence_NotEvidencedAlwaysPresent(t *testing.T) {
	want := []string{"mfa", "email_security", "backups", "incident_response", "security_training"}
	failed := insFixture()
	boom := errors.New("boom")
	failed.edr, failed.edrErr = nil, boom
	failed.enc, failed.encErr = nil, boom
	failed.admin, failed.admErr = nil, boom
	failed.life, failed.lifErr = nil, lifecycle.ErrEstateTooLarge
	failed.remote, failed.remErr = nil, boom
	empty := insFixture()
	empty.ce.Devices = nil
	empty.life.Basis.DevicesAssessed = 0
	empty.remote.Basis.DevicesAssessed = 0

	for name, s := range map[string]*insuranceSources{"normal": insFixture(), "failed": failed, "empty": empty} {
		t.Run(name, func(t *testing.T) {
			p := buildInsuranceEvidence(s)
			if len(p.Questions) != len(insuranceQuestions) {
				t.Fatalf("questions = %d, want %d", len(p.Questions), len(insuranceQuestions))
			}
			for _, id := range want {
				a := insFind(t, p, id)
				if a.Status != InsuranceNotEvidenced || a.Group != InsuranceGroupNotEvidenced {
					t.Errorf("%s: status %s group %s", id, a.Status, a.Group)
				}
				if !strings.HasPrefix(a.AnswerText, "Not evidenced by Patched.") || a.Source != nil || a.UnknownDevices != nil {
					t.Errorf("%s: %+v", id, a)
				}
			}
			for _, a := range p.Questions {
				if a.Group == InsuranceGroupEvidenced {
					if a.Source == nil || !strings.HasPrefix(a.Source.Path, "/") {
						t.Errorf("%s: evidenced question without a portal source path", a.ID)
					}
					if a.Status == InsuranceNotEvidenced {
						t.Errorf("%s: evidenced group carries not_evidenced status", a.ID)
					}
				}
				if a.Answer.Counts == nil {
					t.Errorf("%s: counts must be an object, never null", a.ID)
				}
			}
			if name == "failed" {
				for _, id := range []string{"edr_coverage", "disk_encryption", "local_admin_rights", "unsupported_software", "remote_access_tools"} {
					a := insFind(t, p, id)
					if a.Status != InsuranceUnknown || a.Answer.Value != nil || len(a.Answer.Counts) != 0 {
						t.Errorf("%s: failed source must be unknown with no figures, got %+v", id, a)
					}
				}
				if r := insFind(t, p, "unsupported_software").Reason; r == nil || *r != InsuranceReasonEstateTooLarge {
					t.Errorf("estate too large reason = %v", r)
				}
			}
		})
	}
}

func TestInsuranceQuestions_OneListUniqueIDs(t *testing.T) {
	seen := map[string]bool{}
	for _, q := range insuranceQuestions {
		if q.ID == "" || q.Title == "" || q.Question == "" || seen[q.ID] {
			t.Errorf("bad or duplicate question %+v", q)
		}
		seen[q.ID] = true
		if (q.answer == nil) == (q.outOfScope == "") {
			t.Errorf("%s: exactly one of answer or outOfScope must be set", q.ID)
		}
		if q.answer != nil && q.Source == nil {
			t.Errorf("%s: evidenced question needs a source", q.ID)
		}
	}
}

// insCopyBanned is the customer copy rule set: no em dash, "estate" not
// "fleet", no ticket ids, no US spellings of the words this copy uses, and
// no statement about cover, premiums or insurability, or a verdict.
var insCopyBanned = regexp.MustCompile(`(?i)—|\bfleet\b|PAT-\d|organization|recognize|\binsurable\b|\bpremiums?\b|\bcompliant\b|\bcertified\b|\bpasses\b|\bguarantee[sd]? (of )?cover|\blower (premium|price)`)

func TestInsuranceEvidence_CustomerCopyRules(t *testing.T) {
	s := insFixture()
	s.ce.Devices[0].Items = []CEItem{{CVEID: "CVE-1", Severity: "critical", AgeDays: 40}}
	s.remote.Summary.RemoteAccessToolCount = 1
	s.remote.Summary.RMMAgentToolCount = 1
	s.remote.Basis.UnassessedDeviceIDs = []string{"silent"}
	for _, p := range []InsuranceEvidence{buildInsuranceEvidence(s), buildInsuranceEvidence(&insuranceSources{now: insTestNow})} {
		texts := []string{p.Statement}
		for _, a := range p.Questions {
			texts = append(texts, a.Title, a.Question, a.Headline, a.AnswerText, a.Basis)
			if a.Source != nil {
				texts = append(texts, a.Source.Label)
			}
		}
		for _, txt := range texts {
			if m := insCopyBanned.FindString(txt); m != "" {
				t.Errorf("banned copy %q in %q", m, txt)
			}
		}
	}
}

// The customer PDF renders every question, the not-evidenced group and the
// statement through the UTF-8 font (no mojibake) under the customer header,
// never the staff mark.
func TestInsuranceEvidencePDF_CustomerRendersEveryQuestion(t *testing.T) {
	d := buildInsuranceEvidence(insFixture())
	d.Tenant = "Acme – Café Ltd"
	pdf, err := RenderInsuranceEvidencePDFCustomer(d)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	text, err := extractReportPDFText(pdf)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	flat := strings.Join(strings.Fields(text), " ")
	if strings.Contains(text, pat2265MojibakeMarker) {
		t.Errorf("PDF text carries mojibake")
	}
	if !strings.Contains(text, "Acme – Café Ltd") {
		t.Errorf("tenant name with en dash and accent did not round-trip")
	}
	for _, want := range []string{"Cyber Insurance Evidence Pack", "Not evidenced by Patched", "Unknown devices: 2", "app.patched.im/ce-readiness"} {
		if !strings.Contains(flat, want) {
			t.Errorf("PDF text missing %q", want)
		}
	}
	for _, q := range d.Questions {
		if !strings.Contains(flat, q.Title) {
			t.Errorf("PDF text missing question %q", q.Title)
		}
	}
	if strings.Contains(text, "Staff") || bytes.Contains(pdf, []byte(pat2264StaffMarkFingerprint)) ||
		!bytes.Contains(pdf, []byte(pat2264CustomerMarkFingerprint)) {
		t.Errorf("customer PDF must carry the customer header, never the staff mark")
	}
}
