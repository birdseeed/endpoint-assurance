package jamfcoverage

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Planted personal values: none may survive Parse.
const (
	plantEmail    = "planted.person@example.invalid"
	plantUsername = "planteduser7781"
	plantIP       = "203.0.113.77"
)

func computerFields(serial, udid string, jssID int) map[string]any {
	m := map[string]any{
		"serialNumber": serial, "udid": udid, "jssID": jssID, "deviceName": "Mac-" + serial,
		"model": "MacBookPro18,3", "osVersion": "15.6", "osBuild": "24G84", "managementId": "abc-123",
	}
	for _, f := range PersonalFields {
		m[f] = "pii-" + f
	}
	m["emailAddress"], m["username"], m["ipAddress"], m["reportedIpAddress"] = plantEmail, plantUsername, plantIP, plantIP
	m["realName"] = "Planted Person"
	return m
}

func body(t *testing.T, typ string, event map[string]any, ts int64) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"webhook": map[string]any{"eventTimestamp": ts, "id": 7, "name": "Patched", "webhookEvent": typ},
		"event":   event,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// everyString walks every string field of an Event.
func everyString(ev Event) string {
	var sb strings.Builder
	v := reflect.ValueOf(ev)
	for i := 0; i < v.NumField(); i++ {
		sb.WriteString(fmt.Sprint(v.Field(i).Interface()))
		sb.WriteByte('|')
	}
	return sb.String()
}

func TestParseKeepsIdentifiersOnly(t *testing.T) {
	ts := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	cases := map[string][]byte{
		EventComputerAdded:              body(t, EventComputerAdded, computerFields("C02ABCD1234", "5e0c1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b", 42), ts.UnixMilli()),
		EventComputerInventoryCompleted: body(t, EventComputerInventoryCompleted, computerFields("C02ABCD1234", "5e0c1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b", 42), ts.UnixMilli()),
		EventComputerCheckIn: body(t, EventComputerCheckIn, map[string]any{
			"computer": computerFields("C02ABCD1234", "5e0c1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b", 42),
			"trigger":  "CHECK_IN", "username": plantUsername,
		}, ts.UnixMilli()),
	}
	for typ, b := range cases {
		t.Run(typ, func(t *testing.T) {
			ev, perr := Parse(b)
			if perr != nil {
				t.Fatalf("Parse: %v", perr)
			}
			if ev.Type != typ || !ev.Time.Equal(ts) || ev.SerialNormalized != "C02ABCD1234" ||
				ev.UDIDNormalized != "5E0C1A2B-3C4D-4E5F-8A9B-0C1D2E3F4A5B" || ev.JamfID == nil || *ev.JamfID != 42 ||
				ev.DeviceName != "Mac-C02ABCD1234" || ev.Model != "MacBookPro18,3" || ev.OSVersion != "15.6" {
				t.Fatalf("kept fields wrong: %+v", ev)
			}
			all := everyString(ev)
			for _, p := range []string{plantEmail, plantUsername, plantIP, "Planted Person", "pii-", "24G84", "abc-123", "CHECK_IN"} {
				if strings.Contains(all, p) {
					t.Errorf("personal or unlisted value %q survived Parse: %s", p, all)
				}
			}
		})
	}
}

func TestParseDEP(t *testing.T) {
	ev, perr := Parse(body(t, EventDeviceAddedToDEP, map[string]any{
		"assetTag": "TAG-1", "description": "Planted Person's laptop", "deviceAssignedDate": 1700000000000,
		"deviceEnrollmentProgramInstanceId": 3, "model": "MacBook Air", "serialNumber": " c02dep00001 ",
	}, 0))
	if perr != nil {
		t.Fatalf("Parse: %v", perr)
	}
	if ev.SerialNormalized != "C02DEP00001" || ev.Model != "MacBook Air" || !ev.Time.IsZero() || ev.JamfID != nil {
		t.Fatalf("DEP parse wrong: %+v", ev)
	}
	if s := everyString(ev); strings.Contains(s, "Planted") || strings.Contains(s, "TAG-1") {
		t.Fatalf("DEP personal field kept: %s", s)
	}
}

func TestParseRefusals(t *testing.T) {
	good := computerFields("C02ABCD1234", "", 1)
	cases := []struct {
		name, reason string
		raw          string
	}{
		{"not json", ReasonInvalidPayload, `nope`},
		{"array", ReasonInvalidPayload, `[]`},
		{"unknown top key", ReasonInvalidPayload, `{"webhook":{"webhookEvent":"ComputerAdded"},"event":{"serialNumber":"C02ABCD1234"},"extra":1}`},
		{"fold-variant top key", ReasonInvalidPayload, `{"Webhook":{"webhookEvent":"ComputerAdded"},"event":{"serialNumber":"C02ABCD1234"}}`},
		{"unknown webhook key", ReasonInvalidPayload, `{"webhook":{"webhookEvent":"ComputerAdded","x":1},"event":{"serialNumber":"C02ABCD1234"}}`},
		{"no event type", ReasonInvalidPayload, `{"webhook":{},"event":{"serialNumber":"C02ABCD1234"}}`},
		{"unsupported type", ReasonUnsupportedEvent, `{"webhook":{"webhookEvent":"MobileDeviceCheckIn"},"event":{}}`},
		{"serial wrong type", ReasonInvalidPayload, `{"webhook":{"webhookEvent":"ComputerAdded"},"event":{"serialNumber":123}}`},
		{"jssID negative", ReasonInvalidPayload, `{"webhook":{"webhookEvent":"ComputerAdded"},"event":{"serialNumber":"C02ABCD1234","jssID":-1}}`},
		{"control chars", ReasonInvalidPayload, `{"webhook":{"webhookEvent":"ComputerAdded"},"event":{"serialNumber":"C02AB\nCD1234"}}`},
		{"placeholder serial only", ReasonMissingIdentifier, `{"webhook":{"webhookEvent":"ComputerAdded"},"event":{"serialNumber":"0"}}`},
		{"fold-variant identifier is not an identifier", ReasonMissingIdentifier, `{"webhook":{"webhookEvent":"ComputerAdded"},"event":{"SerialNumber":"C02ABCD1234"}}`},
		{"checkin without computer", ReasonInvalidPayload, `{"webhook":{"webhookEvent":"ComputerCheckIn"},"event":{"serialNumber":"C02ABCD1234"}}`},
		{"serial with punctuation", ReasonInvalidPayload, `{"webhook":{"webhookEvent":"ComputerAdded"},"event":{"serialNumber":"C02-ABCD-1234"}}`},
		{"serial with a format character", ReasonInvalidPayload, "{\"webhook\":{\"webhookEvent\":\"ComputerAdded\"},\"event\":{\"serialNumber\":\"C02AB" + string(rune(0x200b)) + "CD1234\"}}"},
		{"device name with a bidi override", ReasonInvalidPayload, "{\"webhook\":{\"webhookEvent\":\"ComputerAdded\"},\"event\":{\"serialNumber\":\"C02ABCD1234\",\"deviceName\":\"mac" + string(rune(0x202e)) + "01\"}}"},
		{"bad timestamp", ReasonInvalidPayload, `{"webhook":{"webhookEvent":"ComputerAdded","eventTimestamp":"soon"},"event":{"serialNumber":"C02ABCD1234"}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, perr := Parse([]byte(c.raw))
			if perr == nil || perr.Reason != c.reason {
				t.Fatalf("Parse = %v, want reason %s", perr, c.reason)
			}
			if strings.Contains(perr.Message, "C02") {
				t.Fatalf("error message quotes payload content: %s", perr.Message)
			}
		})
	}
	// Unknown event keys are dropped, not refused.
	good["someFutureField"] = "x"
	if _, perr := Parse(body(t, EventComputerAdded, good, 1)); perr != nil {
		t.Fatalf("unknown event key refused: %v", perr)
	}
}

func TestNormalizeInstanceURL(t *testing.T) {
	for in, want := range map[string]string{
		"":                                    "",
		"https://Acme.jamfcloud.com/":         "https://acme.jamfcloud.com",
		"https://jamf.corp.example:8443/path": "https://jamf.corp.example:8443",
	} {
		got, err := NormalizeInstanceURL(in)
		if err != nil || got != want {
			t.Errorf("NormalizeInstanceURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"http://acme.jamfcloud.com", "acme.jamfcloud.com", "https://user:pw@acme.jamfcloud.com", "https://"} {
		if _, err := NormalizeInstanceURL(bad); err == nil {
			t.Errorf("NormalizeInstanceURL(%q) accepted", bad)
		}
	}
}

func TestEnrolledSignal(t *testing.T) {
	s := func(v string) *string { return &v }
	cases := []struct {
		neutral, legacy *string
		want            string
	}{
		{nil, nil, ""},
		{s("Yes"), s("dep=No mdm=No"), "Yes"},
		{s("Unknown"), s("mdm=No"), "Unknown"},
		{nil, s("dep=Yes mdm=No"), "No"},
		{nil, s("mdm=YesPlease"), "Unknown"},
		{nil, s("mdm=Yes mdm=No"), "Unknown"},
	}
	for _, c := range cases {
		if got := EnrolledSignal(c.neutral, c.legacy); got != c.want {
			t.Errorf("EnrolledSignal(%v, %v) = %q, want %q", c.neutral, c.legacy, got, c.want)
		}
	}
}

func TestClassifyMDM(t *testing.T) {
	cases := []struct {
		name     string
		ev       MDMEvidence
		jamfHost string
		want     Classification
	}{
		{"intune", MDMEvidence{AppliedConfigOK: true, ServerURL: "https://i.manage.microsoft.com/DeviceGatewayProxy/ios.ashx"}, "acme.jamfcloud.com",
			Classification{MDMOther, "Microsoft Intune", "i.manage.microsoft.com"}},
		{"unknown vendor", MDMEvidence{AppliedConfigOK: true, ServerURL: "https://mdm.corp.example/mdm"}, "",
			Classification{MDMOther, "", "mdm.corp.example"}},
		{"this jamf", MDMEvidence{AppliedConfigOK: true, ServerURL: "https://jamf.corp.example:8443/mdm/ServerURL"}, "jamf.corp.example",
			Classification{MDMJamfNoEvent, "Jamf", "jamf.corp.example"}},
		{"another jamf instance", MDMEvidence{AppliedConfigOK: true, ServerURL: "https://other.jamfcloud.com/mdm"}, "acme.jamfcloud.com",
			Classification{MDMOther, "Jamf", "other.jamfcloud.com"}},
		{"jamf, no instance claimed, is another MDM", MDMEvidence{AppliedConfigOK: true, ServerURL: "https://acme.jamfcloud.com/mdm"}, "",
			Classification{MDMOther, "Jamf", "acme.jamfcloud.com"}},
		{"ok snapshot, no server", MDMEvidence{AppliedConfigOK: true}, "", Classification{State: MDMUnmanaged}},
		{"signal No", MDMEvidence{EnrolledSignal: "No"}, "", Classification{State: MDMUnmanaged}},
		{"signal Yes", MDMEvidence{EnrolledSignal: "Yes"}, "", Classification{State: MDMEnrolledUnidentified}},
		{"ok snapshot empty but signal Yes", MDMEvidence{AppliedConfigOK: true, EnrolledSignal: "Yes"}, "", Classification{State: MDMEnrolledUnidentified}},
		{"signal Unknown", MDMEvidence{EnrolledSignal: "Unknown"}, "", Classification{State: MDMUnknown}},
		{"nothing", MDMEvidence{}, "", Classification{State: MDMUnknown}},
	}
	for _, c := range cases {
		if got := ClassifyMDM(c.ev, c.jamfHost); got != c.want {
			t.Errorf("%s: ClassifyMDM = %+v, want %+v", c.name, got, c.want)
		}
	}
}

// The fixture the ticket names: a DEP-only Mac, a Mac enrolled in another
// MDM, an unmanaged Mac, a silent Mac and a retired Mac, plus the matching
// edge cases.
func TestReconcileBuckets(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	id := func(n int64) *int64 { return &n }
	jamf := []JamfDevice{
		{ID: 1, Serial: "DEPONLY001", SerialNormalized: "DEPONLY001", DEPAssigned: true, LastEventAt: now.Add(-2 * 24 * time.Hour), DeviceName: "b-dep"},
		{ID: 2, Serial: "SILENT0001", SerialNormalized: "SILENT0001", JamfID: id(2), Enrolled: true, LastEventAt: now.Add(-45 * 24 * time.Hour), DeviceName: "a-silent"},
		{ID: 3, Serial: "RETIRED001", SerialNormalized: "RETIRED001", JamfID: id(3), Enrolled: true, LastEventAt: now},
		{ID: 4, Serial: "BOTH000001", SerialNormalized: "BOTH000001", JamfID: id(4), Enrolled: true, LastEventAt: now},
		// UDID fallback: Patched has a placeholder serial for this Mac.
		{ID: 5, UDID: "aaaaaaaa-1111-2222-3333-444444444444", UDIDNormalized: "AAAAAAAA-1111-2222-3333-444444444444", JamfID: id(5), Enrolled: true, LastEventAt: now},
		// Same UUID as a Patched device but a different real serial: not a match.
		{ID: 6, Serial: "DIFFER0001", SerialNormalized: "DIFFER0001", UDIDNormalized: "BBBBBBBB-1111-2222-3333-444444444444", Enrolled: true, LastEventAt: now},
	}
	devices := []PatchedDevice{
		{ID: "d-other", Hostname: "mac-other", Serial: "OTHER00001", OS: "macOS", MDM: MDMEvidence{AppliedConfigOK: true, ServerURL: "https://a.mosyle.com/mdm"}},
		{ID: "d-unmanaged", Hostname: "mac-unmanaged", Serial: "UNMANAGED1", OS: "macOS", MDM: MDMEvidence{AppliedConfigOK: true}},
		{ID: "d-unknown", Hostname: "mac-unknown", Serial: "UNKNOWN001", OS: "macOS"},
		{ID: "d-retired-jamf", Hostname: "mac-retired", Serial: "RETIRED001", OS: "macOS", Retired: true},
		{ID: "d-retired-alone", Hostname: "mac-retired-2", Serial: "RETIRED002", OS: "macOS", Retired: true},
		{ID: "d-both", Hostname: "mac-both", Serial: "BOTH000001", OS: "macOS"},
		{ID: "d-udid", Hostname: "mac-udid", Serial: "To be filled by O.E.M.", HWUUID: "aaaaaaaa-1111-2222-3333-444444444444", OS: "macOS"},
		{ID: "d-differ", Hostname: "mac-differ", Serial: "DIFFER0002", HWUUID: "bbbbbbbb-1111-2222-3333-444444444444", OS: "macOS", MDM: MDMEvidence{EnrolledSignal: "No"}},
		{ID: "d-win", Hostname: "PC-01", Serial: "WIN0000001", OS: "Windows"},
	}
	res := Reconcile(jamf, devices, "acme.jamfcloud.com")

	var gap []string
	for _, g := range res.Gap {
		gap = append(gap, g.Serial)
	}
	if want := []string{"DIFFER0001", "SILENT0001", "DEPONLY001"}; !reflect.DeepEqual(gap, want) {
		t.Errorf("gap = %v, want %v", gap, want)
	}
	un := map[string]string{}
	for _, u := range res.NotReported {
		un[u.Device.ID] = u.MDM.State + ":" + u.MDM.Vendor
	}
	wantUn := map[string]string{
		"d-other": MDMOther + ":Mosyle", "d-unmanaged": MDMUnmanaged + ":", "d-unknown": MDMUnknown + ":", "d-differ": MDMUnmanaged + ":",
	}
	if !reflect.DeepEqual(un, wantUn) {
		t.Errorf("unmanaged = %v, want %v", un, wantUn)
	}
	cov := map[string]string{}
	for _, p := range res.Covered {
		cov[p.Device.ID] = p.MatchBasis
	}
	if want := map[string]string{"d-both": "serial", "d-udid": "udid"}; !reflect.DeepEqual(cov, want) {
		t.Errorf("covered = %v, want %v", cov, want)
	}
	if res.RetiredExcluded != 1 || res.NonMacExcluded != 1 {
		t.Errorf("retired excluded = %d, non-mac excluded = %d; want 1, 1", res.RetiredExcluded, res.NonMacExcluded)
	}
	if got := SilenceNote(jamf[1].LastEventAt, now); got != "not heard from Jamf in 45 days" {
		t.Errorf("silent note = %q", got)
	}
	if got := SilenceNote(jamf[0].LastEventAt, now); got != "" {
		t.Errorf("recent note = %q, want empty", got)
	}
	for _, note := range []string{SilenceNote(jamf[1].LastEventAt, now)} {
		if strings.Contains(note, "removed") || strings.Contains(note, "unmanaged") {
			t.Errorf("silence reads as removal: %q", note)
		}
	}
}

// Missing platform evidence is visible without changing authoritative identity matches.
func TestReconcileOSNotReported(t *testing.T) {
	devices := []PatchedDevice{
		{ID: "empty"},
		{ID: "blank", Hostname: "b", OS: " \t "},
		{ID: "matched", Hostname: "c", Serial: "MATCH001"},
		{ID: "udid", Hostname: "d", HWUUID: "aaaaaaaa-1111-2222-3333-444444444444"},
		{ID: "retired", Retired: true},
		{ID: "windows", OS: "Windows"},
		{ID: "mac", OS: "macOS"},
	}
	jamf := []JamfDevice{
		{ID: 1, SerialNormalized: "MATCH001"},
		{ID: 2, UDIDNormalized: "AAAAAAAA-1111-2222-3333-444444444444"},
	}
	res := Reconcile(jamf, devices, "")
	var ids []string
	for _, d := range res.OSNotReported {
		ids = append(ids, d.ID)
	}
	if want := []string{"empty", "blank", "matched", "udid"}; !reflect.DeepEqual(ids, want) {
		t.Errorf("OS not reported = %v, want %v", ids, want)
	}
	if res.NonMacExcluded != 1 || len(res.NotReported) != 1 || res.NotReported[0].Device.ID != "mac" {
		t.Errorf("known platform classification = %+v", res)
	}
	if len(res.Covered) != 2 || res.Covered[0].Device.ID != "matched" || res.Covered[1].Device.ID != "udid" || len(res.Gap) != 0 {
		t.Errorf("authoritative matches changed = %+v", res)
	}
}
