package report

// PAT-2496: unit tests for the one definition of a device's encryption state
// (encryption_state.go) and for the surfaces that must carry it unchanged.
// The database-backed tests are encryption_state_db_test.go (the function
// against a schema) and integration/pat2496_encryption_state_test.go (real
// agent payloads, every surface over HTTP).

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestClassifyEncryptionEvaluation(t *testing.T) {
	cases := []struct {
		name     string
		status   *string
		observed *string
		want     string
	}{
		{"pass on", strPtr("pass"), strPtr("On"), EncryptionStateEncrypted},
		{"fail with observed off is never unknown", strPtr("fail"), strPtr("Off"), EncryptionStateNotEncrypted},
		{"fail with an observed value of any kind", strPtr("fail"), strPtr("NotConfigured"), EncryptionStateNotEncrypted},
		{"error with an observed value", strPtr("error"), strPtr("garbled"), EncryptionStateNotEncrypted},
		{"fail with no observed value is unreadable, so unknown", strPtr("fail"), nil, EncryptionStateUnknown},
		{"error with no observed value is not an observation", strPtr("error"), nil, EncryptionStateUnknown},
		{"not applicable", strPtr("not_applicable"), nil, EncryptionStateUnknown},
		{"not applicable with a value", strPtr("not_applicable"), strPtr("On"), EncryptionStateUnknown},
		{"no evaluation at all", nil, nil, EncryptionStateUnknown},
		{"a status this code does not know", strPtr("pending"), strPtr("On"), EncryptionStateUnknown},
		{"an empty status", strPtr(""), strPtr("On"), EncryptionStateUnknown},
	}
	for _, c := range cases {
		if got := classifyEncryptionEvaluation(c.status, c.observed); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// pass never reads as anything but encrypted, and nothing but pass reads as
// encrypted: missing or odd evidence never counts in the customer's favour.
func TestClassifyEncryptionEvaluation_OnlyPassIsEncrypted(t *testing.T) {
	for _, status := range []string{"fail", "error", "not_applicable", "", "PASS", "passed", "ok"} {
		for _, observed := range []*string{nil, strPtr("On"), strPtr("Off"), strPtr("")} {
			if got := classifyEncryptionEvaluation(strPtr(status), observed); got == EncryptionStateEncrypted {
				t.Errorf("status %q observed %v classified as encrypted", status, observed)
			}
		}
	}
}

func TestEncryptionOKFromState(t *testing.T) {
	if v := encryptionOKFromState(EncryptionStateEncrypted); v == nil || !*v {
		t.Errorf("encrypted -> %v, want true", boolPtrStr(v))
	}
	if v := encryptionOKFromState(EncryptionStateNotEncrypted); v == nil || *v {
		t.Errorf("not_encrypted -> %v, want false", boolPtrStr(v))
	}
	for _, s := range []string{EncryptionStateUnknown, "", "On", "weird"} {
		if v := encryptionOKFromState(s); v != nil {
			t.Errorf("%q -> %v, want nil (unknown)", s, boolPtrStr(v))
		}
	}
	if got := encryptionStateOf(map[string]string{"a": EncryptionStateEncrypted}, "b"); got != EncryptionStateUnknown {
		t.Errorf("a device the map does not carry = %q, want unknown", got)
	}
}

// EvalRow.Undetermined is the predicate the portal sends as "undetermined"; it
// must be exactly isUndeterminedEval, the one the reports and roster use.
func TestEvalRowUndetermined_IsTheSharedPredicate(t *testing.T) {
	cases := []struct {
		status   string
		observed *string
		want     bool
	}{
		{"fail", nil, true},
		{"fail", strPtr("Off"), false},
		{"fail", strPtr("NotConfigured"), false},
		{"fail", strPtr(""), false},
		{"error", nil, false},
		{"error", strPtr("x"), false},
		{"pass", nil, false},
		{"pass", strPtr("On"), false},
		{"not_applicable", nil, false},
	}
	for _, c := range cases {
		ev := EvalRow{Status: c.status, ObservedValue: c.observed}
		if got := ev.Undetermined(); got != c.want {
			t.Errorf("%s/%v: Undetermined() = %v, want %v", c.status, c.observed, got, c.want)
		}
		if ev.Undetermined() != isUndeterminedEval(ev) {
			t.Errorf("%s/%v: Undetermined() disagrees with isUndeterminedEval", c.status, c.observed)
		}
	}
}

// pat2496PostureFixture is the customer's case as the posture report holds it
// after FetchEncryptionStates: a Mac with FileVault on, a Windows device with
// BitLocker observed off, and a Windows device that reported no readable state.
func pat2496PostureFixture() EncryptionPostureReport {
	r := EncryptionPostureReport{
		GeneratedAt: insTestNow,
		Tenant:      "Acme",
		Devices: []EncryptionRow{
			{DeviceID: "mac", Hostname: "mac-on", OS: "macOS", FileVault: strPtr("On")},
			{DeviceID: "win-off", Hostname: "win-off", OS: "Windows", BitLocker: strPtr("Off")},
			{DeviceID: "win-unknown", Hostname: "win-unknown", OS: "Windows", BitLocker: strPtr("Unknown")},
		},
	}
	r.applyStates(map[string]string{
		"mac": EncryptionStateEncrypted, "win-off": EncryptionStateNotEncrypted, "win-unknown": EncryptionStateUnknown,
	})
	return r
}

func TestEncryptionPostureApplyStates(t *testing.T) {
	r := pat2496PostureFixture()
	if r.EncryptedCount != 1 || r.UnencryptedCount != 1 || r.UnknownCount != 1 {
		t.Fatalf("counts = %d/%d/%d, want 1/1/1", r.EncryptedCount, r.UnencryptedCount, r.UnknownCount)
	}
	want := []string{EncryptionStateEncrypted, EncryptionStateNotEncrypted, EncryptionStateUnknown}
	for i, d := range r.Devices {
		if d.State != want[i] {
			t.Errorf("%s state = %q, want %q", d.Hostname, d.State, want[i])
		}
	}
	// A device the states map does not carry is unknown, and recounting is
	// idempotent (the counts are derived, never accumulated).
	r.Devices = append(r.Devices, EncryptionRow{DeviceID: "missing", Hostname: "missing"})
	r.applyStates(map[string]string{"mac": EncryptionStateEncrypted, "win-off": EncryptionStateNotEncrypted})
	if r.EncryptedCount != 1 || r.UnencryptedCount != 1 || r.UnknownCount != 2 {
		t.Errorf("recount = %d/%d/%d, want 1/1/2", r.EncryptedCount, r.UnencryptedCount, r.UnknownCount)
	}
}

// The posture report's CSV and PDF carry the same corrected answer: the CSV
// state column and the PDF's counts both read the states applyStates set, and
// the raw BitLocker value shown beside a state is the one the agent sent.
func TestEncryptionPosture_CSVAndPDFCarryTheSameStates(t *testing.T) {
	r := pat2496PostureFixture()

	csvBytes, err := EncryptionPostureCSV(r)
	if err != nil {
		t.Fatalf("csv: %v", err)
	}
	rows := strings.Split(strings.TrimSpace(string(csvBytes)), "\n")
	if len(rows) != 4 {
		t.Fatalf("csv rows = %d, want header + 3 devices:\n%s", len(rows), csvBytes)
	}
	for i, wantState := range []string{"encrypted", "not_encrypted", "unknown"} {
		cells := strings.Split(rows[i+1], ",")
		// generated_at,section,hostname,os,state,filevault,bitlocker,...
		if len(cells) < 7 || cells[1] != "device" || cells[4] != wantState {
			t.Errorf("csv row %d = %q, want state %q", i+1, rows[i+1], wantState)
		}
	}
	if !strings.Contains(rows[2], ",Off,") {
		t.Errorf("csv row for the BitLocker-off device must carry the raw value Off: %q", rows[2])
	}

	for name, render := range map[string]func(EncryptionPostureReport) ([]byte, error){
		"staff": RenderEncryptionPosturePDF, "customer": RenderEncryptionPosturePDFCustomer,
	} {
		pdf, err := render(r)
		if err != nil {
			t.Fatalf("%s pdf: %v", name, err)
		}
		text, err := extractReportPDFText(pdf)
		if err != nil {
			t.Fatalf("%s extract: %v", name, err)
		}
		// The overview band prints every value, then every label.
		flat := strings.Join(strings.Fields(text), " ")
		if !strings.Contains(flat, "1 1 1 3 Encrypted Unencrypted Unknown Total devices") {
			t.Errorf("%s pdf: overview band is not 1 encrypted, 1 unencrypted, 1 unknown of 3: %q", name, flat)
		}
	}
}

// The pack's answer for the customer's three devices: three separate counts,
// the not encrypted device in its own sentence, never merged into unknown. This
// is the exact text a customer reads, so it is pinned.
const pat2496ThreeDeviceAnswer = "1 of 3 devices (33.3%) reports FileVault or BitLocker full-disk encryption turned on. " +
	"1 device reports encryption turned off. " +
	"Encryption is turned off on: WIN-OFF-01. " +
	"1 device is unknown (1 reported no encryption state) and is not counted in your favour."

func pat2496PackFixture() *insuranceSources {
	s := insFixture()
	s.ce.Devices = s.ce.Devices[:2] // active (Mac, encrypted) and stale (Windows, observed off)
	s.ce.Devices[0].Hostname = "MAC-ON-01"
	s.ce.Devices[1].Hostname = "WIN-OFF-01"
	bare := insCEDevice("bare", "active", insTime(2*time.Hour))
	bare.Hostname = "MAC-BARE-01"
	s.ce.Devices = append(s.ce.Devices, bare)
	s.enc = &EncryptionPostureReport{GeneratedAt: insTestNow, Devices: []EncryptionRow{
		{DeviceID: "active", OS: "macOS", FileVault: strPtr("On"), State: EncryptionStateEncrypted},
		{DeviceID: "stale", OS: "Windows", BitLocker: strPtr("Off"), State: EncryptionStateNotEncrypted},
		{DeviceID: "bare", OS: "macOS", State: EncryptionStateUnknown},
	}}
	return s
}

func TestInsuranceEvidence_EncryptionThreeOutcomesAreSeparate(t *testing.T) {
	a := insFind(t, buildInsuranceEvidence(pat2496PackFixture()), "disk_encryption")
	insCount(t, a, "devices_in_scope", 3)
	insCount(t, a, "encrypted", 1)
	insCount(t, a, "not_encrypted", 1)
	insCount(t, a, "no_evidence", 1)
	insCount(t, a, "not_reporting", 0)
	if a.AnswerText != pat2496ThreeDeviceAnswer {
		t.Errorf("answer text\n got: %q\nwant: %q", a.AnswerText, pat2496ThreeDeviceAnswer)
	}
	if a.Status != InsurancePartial || a.UnknownDevices == nil || *a.UnknownDevices != 1 {
		t.Errorf("status %s unknown %v, want partial / 1", a.Status, a.UnknownDevices)
	}
}

// A Windows device with BitLocker on is encrypted in the pack, through the same
// path as a Mac with FileVault on.
func TestInsuranceEvidence_WindowsBitLockerOnIsEncrypted(t *testing.T) {
	s := pat2496PackFixture()
	s.enc.Devices[1] = EncryptionRow{DeviceID: "stale", OS: "Windows", BitLocker: strPtr("On"), State: EncryptionStateEncrypted}
	a := insFind(t, buildInsuranceEvidence(s), "disk_encryption")
	insCount(t, a, "encrypted", 2)
	insCount(t, a, "not_encrypted", 0)
	insCount(t, a, "no_evidence", 1)
	if strings.Contains(a.AnswerText, "turned off") {
		t.Errorf("no device is off, the answer must not say so: %q", a.AnswerText)
	}
}

// The pack counts only a State of encrypted as encrypted. A raw FileVault or
// BitLocker value of On beside a State that is not encrypted, or a row with no
// State, never counts in the customer's favour.
func TestInsuranceEvidence_OnlyStateDecidesEncrypted(t *testing.T) {
	s := pat2496PackFixture()
	s.enc.Devices = []EncryptionRow{
		{DeviceID: "active", OS: "macOS", FileVault: strPtr("On"), State: EncryptionStateUnknown},
		{DeviceID: "stale", OS: "Windows", BitLocker: strPtr("On")},
		{DeviceID: "bare", OS: "macOS", FileVault: strPtr("On"), State: "on"},
	}
	a := insFind(t, buildInsuranceEvidence(s), "disk_encryption")
	insCount(t, a, "encrypted", 0)
	insCount(t, a, "no_evidence", 3)
}

// The pack's PDF carries the corrected answer: the three counts in the answer
// text and the figures in the structured value, rendered from the same
// InsuranceEvidence the JSON and CSV forms are written from.
func TestInsuranceEvidencePDF_CarriesTheThreeOutcomes(t *testing.T) {
	d := buildInsuranceEvidence(pat2496PackFixture())
	pdf, err := RenderInsuranceEvidencePDFCustomer(d)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	text, err := extractReportPDFText(pdf)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	flat := strings.Join(strings.Fields(text), " ")
	for _, want := range []string{
		"1 of 3 devices (33.3%) reports FileVault or BitLocker full-disk encryption turned on.",
		"1 device reports encryption turned off.",
		"1 device is unknown (1 reported no encryption state)",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("PDF text is missing %q", want)
		}
	}
}

// pat2496OffEstate is an estate of reporting devices whose encryption is
// observed off, named by the given hostnames (in the given order), plus
// optional extra devices.
func pat2496OffEstate(hosts ...string) *insuranceSources {
	s := insFixture()
	s.ce.Devices = nil
	s.enc = &EncryptionPostureReport{GeneratedAt: insTestNow}
	for i, h := range hosts {
		id := fmt.Sprintf("off-%02d", i)
		d := insCEDevice(id, "active", insTime(time.Hour))
		d.Hostname = h
		s.ce.Devices = append(s.ce.Devices, d)
		s.enc.Devices = append(s.enc.Devices, EncryptionRow{DeviceID: id, OS: "Windows", BitLocker: strPtr("Off"), State: EncryptionStateNotEncrypted})
	}
	return s
}

func pat2496EncryptionText(t *testing.T, s *insuranceSources) string {
	t.Helper()
	return insFind(t, buildInsuranceEvidence(s), "disk_encryption").AnswerText
}

// Past ten not encrypted devices the answer names ten, in order, and says how
// many more there are.
const pat2496TwelveDeviceAnswer = "0 of 12 devices (0.0%) report FileVault or BitLocker full-disk encryption turned on. " +
	"12 devices report encryption turned off. " +
	"Encryption is turned off on: HOST-A, HOST-B, HOST-C, HOST-D, HOST-E, HOST-F, HOST-G, HOST-H, HOST-I, HOST-J and 2 more."

func TestInsuranceEvidence_EncryptionNamesTheDevicesThatAreOff(t *testing.T) {
	// Twelve devices handed over out of order: the names are sorted, capped
	// at ten, and the rest are counted.
	got := pat2496EncryptionText(t, pat2496OffEstate(
		"HOST-L", "HOST-C", "HOST-A", "HOST-K", "HOST-B", "HOST-F", "HOST-E", "HOST-D", "HOST-J", "HOST-I", "HOST-H", "HOST-G"))
	if got != pat2496TwelveDeviceAnswer {
		t.Errorf("12 devices off\n got: %q\nwant: %q", got, pat2496TwelveDeviceAnswer)
	}

	// Exactly ten: all named, nothing said about more. Eleven: "and 1 more".
	ten := []string{"H10", "H09", "H08", "H07", "H06", "H05", "H04", "H03", "H02", "H01"}
	if got := pat2496EncryptionText(t, pat2496OffEstate(ten...)); !strings.HasSuffix(got, "Encryption is turned off on: H01, H02, H03, H04, H05, H06, H07, H08, H09, H10.") {
		t.Errorf("ten devices off: %q", got)
	}
	if got := pat2496EncryptionText(t, pat2496OffEstate(append(ten, "H11")...)); !strings.HasSuffix(got, "H01, H02, H03, H04, H05, H06, H07, H08, H09, H10 and 1 more.") {
		t.Errorf("eleven devices off: %q", got)
	}

	// One device, singular count wording, one name.
	if got := pat2496EncryptionText(t, pat2496OffEstate("ONLY-ONE")); !strings.Contains(got, "1 device reports encryption turned off. Encryption is turned off on: ONLY-ONE.") {
		t.Errorf("one device off: %q", got)
	}

	// Sorted without regard to case.
	if got := pat2496EncryptionText(t, pat2496OffEstate("zeta", "Alpha", "beta")); !strings.Contains(got, "on: Alpha, beta, zeta.") {
		t.Errorf("case-insensitive order: %q", got)
	}
}

// Nothing is named when nothing is off, and only a device that is in scope,
// reporting and observed off is ever named: never an unknown, an encrypted or
// a not reporting device.
func TestInsuranceEvidence_EncryptionNamesOnlyReportingDevicesObservedOff(t *testing.T) {
	// The fixture has an encrypted Mac and a Windows device off.
	s := pat2496PackFixture()
	s.enc.Devices[1].State = EncryptionStateEncrypted
	if got := pat2496EncryptionText(t, s); strings.Contains(got, "turned off on") || strings.Contains(got, "turned off.") {
		t.Errorf("no device is off, nothing may be named: %q", got)
	}

	// With one device genuinely reporting and off, the sentence exists; the
	// off device that has not reported for 14 days, the one with no usable
	// report time, the unknown reporting device and the encrypted one are not
	// in it.
	s = pat2496OffEstate("REPORTING-OFF", "SILENT-OFF", "NEVER-OFF", "UNKNOWN-HOST", "ENCRYPTED-HOST")
	s.ce.Devices[1].Reporting.Bucket = "silent"
	s.ce.Devices[2].Reporting.Bucket = "unknown"
	s.enc.Devices[3].State = EncryptionStateUnknown
	s.enc.Devices[4].State = EncryptionStateEncrypted
	got := pat2496EncryptionText(t, s)
	if !strings.Contains(got, " 1 device reports encryption turned off. Encryption is turned off on: REPORTING-OFF. ") {
		t.Errorf("only the reporting off device is named: %q", got)
	}
	for _, name := range []string{"SILENT-OFF", "NEVER-OFF", "UNKNOWN-HOST", "ENCRYPTED-HOST"} {
		if strings.Contains(got, name) {
			t.Errorf("%s must not be named: %q", name, got)
		}
	}

	// An off device outside the estate in scope (retired) is not named.
	s = pat2496PackFixture()
	s.enc.Devices = append(s.enc.Devices, EncryptionRow{DeviceID: "retired", Hostname: "RETIRED-HOST", State: EncryptionStateNotEncrypted})
	if got := pat2496EncryptionText(t, s); !strings.Contains(got, "turned off on: WIN-OFF-01.") || strings.Contains(got, "RETIRED-HOST") {
		t.Errorf("a device outside the estate in scope was named: %q", got)
	}
}

// A device with no hostname is shown as "(no hostname)", the placeholder the
// EDR coverage report the pack reads already uses, never as an empty item.
// Control characters cannot break the sentence.
func TestInsuranceEvidence_EncryptionNamesNamelessAndOddHostnames(t *testing.T) {
	got := pat2496EncryptionText(t, pat2496OffEstate("", "  ", "B-HOST"))
	if !strings.Contains(got, "Encryption is turned off on: (no hostname), (no hostname), B-HOST.") {
		t.Errorf("nameless devices: %q", got)
	}
	got = pat2496EncryptionText(t, pat2496OffEstate("evil\nhost\x00name\t1"))
	if !strings.Contains(got, "Encryption is turned off on: evil host name 1.") {
		t.Errorf("control characters: %q", got)
	}
	if strings.ContainsAny(got, "\n\x00\t") {
		t.Errorf("the answer carries a control character: %q", got)
	}
}

// pat2496FormulaHost starts with = and carries PDF string delimiters.
const pat2496FormulaHost = `=HYPERLINK("http://example.invalid/x","(open) \ me")`

// The sentence, hostnames included, reaches the PDF unchanged: the same
// InsuranceEvidence value is rendered, and fpdf's own string escaping carries
// parentheses and backslashes. A hostname that begins with = is a name, not a
// formula, in a PDF.
func TestInsuranceEvidencePDF_CarriesTheNamedDevices(t *testing.T) {
	d := buildInsuranceEvidence(pat2496OffEstate("HOST-B", pat2496FormulaHost, "HOST-A"))
	want := insFind(t, d, "disk_encryption").AnswerText
	if !strings.Contains(want, "Encryption is turned off on: "+pat2496FormulaHost+", HOST-A, HOST-B.") {
		t.Fatalf("answer: %q", want)
	}
	pdf, err := RenderInsuranceEvidencePDFCustomer(d)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	text, err := extractReportPDFText(pdf)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	flat := strings.Join(strings.Fields(text), " ")
	if !strings.Contains(flat, "Encryption is turned off on: "+pat2496FormulaHost+", HOST-A, HOST-B.") {
		t.Errorf("PDF text does not carry the named devices sentence:\n%s", flat)
	}
}

// The posture CSV never prints a blank where a state belongs. A row with no
// state, or one that is not exactly encrypted or not_encrypted, prints unknown.
func TestEncryptionPostureCSV_NoBlankOrOddState(t *testing.T) {
	r := EncryptionPostureReport{GeneratedAt: insTestNow, Devices: []EncryptionRow{
		{DeviceID: "a", Hostname: "no-state", OS: "macOS"},
		{DeviceID: "b", Hostname: "odd-state", OS: "macOS", FileVault: strPtr("On"), State: "on"},
		{DeviceID: "c", Hostname: "encrypted", OS: "macOS", State: EncryptionStateEncrypted},
		{DeviceID: "d", Hostname: "off", OS: "Windows", State: EncryptionStateNotEncrypted},
	}}
	b, err := EncryptionPostureCSV(r)
	if err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimSpace(string(b)), "\n")
	want := map[string]string{"no-state": "unknown", "odd-state": "unknown", "encrypted": "encrypted", "off": "not_encrypted"}
	for _, row := range rows[1:] {
		cells := strings.Split(row, ",")
		if got := cells[4]; got != want[cells[2]] {
			t.Errorf("%s: state cell %q, want %q (row %q)", cells[2], got, want[cells[2]], row)
		}
	}
}
