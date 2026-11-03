package devicelist

import (
	"strings"
	"testing"
)

func sp(s string) *string { return &s }

func TestNormalizeHostname(t *testing.T) {
	cases := map[string]string{
		"DESKTOP-ROBWIN":        "desktop-robwin", // Windows NetBIOS name, upper case
		"  Desktop-RobWin  ":    "desktop-robwin",
		"mac-01.local":          "mac-01",
		"MAC-01.LOCAL.":         "mac-01",
		"mac-01.":               "mac-01",
		"mac-01...":             "mac-01",
		"pc01.corp.example.com": "pc01.corp.example.com", // FQDN is not reduced to its short name
		"local":                 "local",
		".local":                "",
		"":                      "",
		"   ":                   "",
	}
	for in, want := range cases {
		if got := NormalizeHostname(in); got != want {
			t.Errorf("NormalizeHostname(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeSerial(t *testing.T) {
	if got := NormalizeSerial("  c02abc123 "); got != "C02ABC123" {
		t.Errorf("NormalizeSerial = %q", got)
	}
}

func TestValidateRejectsAndNamesFirstBadIndex(t *testing.T) {
	cases := []struct {
		name  string
		in    []InputEntry
		index int
		code  string
	}{
		{"no identifier", []InputEntry{{Hostname: sp("ok")}, {Hostname: sp("  ")}}, 1, "missing_identifier"},
		{"null both", []InputEntry{{}}, 0, "missing_identifier"},
		{"control char hostname", []InputEntry{{Hostname: sp("a")}, {Hostname: sp("b")}, {Hostname: sp("bad\x07name")}}, 2, "invalid_hostname"},
		{"tab in serial", []InputEntry{{Hostname: sp("a"), Serial: sp("X\tYZW")}}, 0, "invalid_serial"},
		{"hostname too long", []InputEntry{{Hostname: sp(strings.Repeat("a", 256))}}, 0, "invalid_hostname"},
		{"serial too long", []InputEntry{{Serial: sp(strings.Repeat("S", 256))}}, 0, "invalid_serial"},
		{"invalid utf8", []InputEntry{{Hostname: sp("a\xffb")}}, 0, "invalid_hostname"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := Validate(c.in)
			if err == nil {
				t.Fatal("Validate accepted a bad entry")
			}
			if err.Index != c.index || err.Code != c.code {
				t.Fatalf("error = %+v, want index %d code %s", err, c.index, c.code)
			}
			if !strings.Contains(err.Error(), "entries[") {
				t.Fatalf("message %q does not name the row", err.Error())
			}
		})
	}
}

func TestValidateAcceptsLimitsAndCollapsesDuplicates(t *testing.T) {
	in := []InputEntry{
		{Hostname: sp(strings.Repeat("a", 255))},
		{Serial: sp("c02abc"), Hostname: nil},          // serial only is enough
		{Hostname: sp("PC01"), Serial: sp("")},         // empty serial means none
		{Hostname: sp("pc01.local"), Serial: nil},      // duplicate of the above once normalised
		{Hostname: sp("pc01"), Serial: sp(" SN0001 ")}, // distinct: carries a serial
		{Hostname: sp("PC01"), Serial: sp("sn0001")},   // duplicate of the above
		{Hostname: sp("   "), Serial: sp("C02ABC")},    // duplicate of entry 1
	}
	out, dups, err := Validate(in)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(out) != 4 || dups != 3 {
		t.Fatalf("got %d entries, %d duplicates; want 4 and 3: %+v", len(out), dups, out)
	}
	if out[2].Position != 2 || out[2].HostnameNormalized != "pc01" || out[2].SerialNormalized != "" {
		t.Fatalf("entry 2 = %+v", out[2])
	}
	if out[1].Hostname != "" || out[1].SerialNormalized != "C02ABC" {
		t.Fatalf("serial-only entry = %+v", out[1])
	}
}

func mustValidate(t *testing.T, in []InputEntry) []Entry {
	t.Helper()
	out, _, err := Validate(in)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return out
}

func TestReconcileMatchingRules(t *testing.T) {
	devices := []Device{
		{ID: "d1", Hostname: "DESKTOP-ROBWIN", Serial: ""},      // Windows, no serial
		{ID: "d2", Hostname: "mac-01", Serial: "C02AAA"},        // macOS with serial
		{ID: "d3", Hostname: "shared-name", Serial: "SERIAL-B"}, // serial disagrees with the list
		{ID: "d4", Hostname: "unlisted", Serial: "ZZZ9"},        // seen, not on the list
		{ID: "d5", Hostname: "retired-box", Serial: "RRR1", Retired: true},
		{ID: "d6", Hostname: "retired-unlisted", Retired: true}, // retired, not on list: excluded
		{ID: "d7", Hostname: "aaa-unlisted", Serial: ""},        // sorts first
	}
	entries := mustValidate(t, []InputEntry{
		{Hostname: sp("desktop-robwin.local.")},               // 0 hostname match, case and .local
		{Hostname: sp("wrong-name"), Serial: sp(" c02aaa ")},  // 1 serial match beats a hostname mismatch
		{Hostname: sp("shared-name"), Serial: sp("SERIAL-A")}, // 2 both have serials and they differ: no match
		{Hostname: sp("never-seen")},                          // 3 no match
		{Serial: sp("rrr1")},                                  // 4 matches a retired device
		{Hostname: sp("mac-01")},                              // 5 no serial on the entry: hostname decides
	})
	res := Reconcile(entries, devices)

	if res.MatchedCount != 4 || res.MatchedRetiredCount != 1 {
		t.Fatalf("matched = %d (retired %d), want 4 (1)", res.MatchedCount, res.MatchedRetiredCount)
	}
	// PAT-2271: Matched must agree exactly with MatchedCount, and the
	// retired match (entry 4, serial rrr1, against retired device d5) must
	// carry the device's retired flag.
	if len(res.Matched) != res.MatchedCount {
		t.Fatalf("len(Matched) = %d, want %d (MatchedCount)", len(res.Matched), res.MatchedCount)
	}
	matchedByPos := map[int]MatchedPair{}
	for _, m := range res.Matched {
		matchedByPos[m.Entry.Position] = m
	}
	if m, ok := matchedByPos[4]; !ok || m.Device.ID != "d5" || !m.Device.Retired {
		t.Fatalf("matched[4] = %+v, want device d5 with Retired true", m)
	}
	if m, ok := matchedByPos[0]; !ok || m.Device.ID != "d1" || m.Device.Retired {
		t.Fatalf("matched[0] = %+v, want device d1 not retired", m)
	}
	if m, ok := matchedByPos[1]; !ok || m.Device.ID != "d2" || m.Device.Retired {
		t.Fatalf("matched[1] = %+v, want device d2 not retired", m)
	}
	if m, ok := matchedByPos[5]; !ok || m.Device.ID != "d2" {
		t.Fatalf("matched[5] = %+v, want device d2 (hostname match)", m)
	}
	var never []int
	for _, e := range res.OnListNeverSeen {
		never = append(never, e.Position)
	}
	if len(never) != 2 || never[0] != 2 || never[1] != 3 {
		t.Fatalf("on list never seen = %v, want [2 3]", never)
	}
	var seen []string
	for _, d := range res.SeenNotOnList {
		seen = append(seen, d.ID)
	}
	if strings.Join(seen, ",") != "d7,d3,d4" {
		t.Fatalf("seen not on list = %v, want d7,d3,d4 (sorted by hostname, retired excluded)", seen)
	}
}

func TestReconcileDeviceWithoutSerialMatchesSerialEntryByHostname(t *testing.T) {
	entries := mustValidate(t, []InputEntry{{Hostname: sp("PC-01"), Serial: sp("ABC1")}})
	res := Reconcile(entries, []Device{{ID: "d1", Hostname: "pc-01"}})
	if res.MatchedCount != 1 || len(res.SeenNotOnList) != 0 {
		t.Fatalf("result = %+v, want a hostname match when the device has no serial", res)
	}
}

func TestReconcileEmptyInputsGiveEmptySlices(t *testing.T) {
	res := Reconcile(nil, nil)
	if res.OnListNeverSeen == nil || res.SeenNotOnList == nil || res.Matched == nil {
		t.Fatal("result slices must be empty, not nil, so they encode as []")
	}
}

// A live device is reported over a retired one when an entry's candidates
// include both, so Matched stays consistent with MatchedRetiredCount (which
// counts this entry as live, not retired).
func TestReconcileMatchedPrefersLiveDeviceOverRetiredCandidate(t *testing.T) {
	entries := mustValidate(t, []InputEntry{{Hostname: sp("shared-host"), Serial: sp("LIVE-SN")}})
	devices := []Device{
		{ID: "retired-one", Hostname: "shared-host", Retired: true},
		{ID: "live-one", Hostname: "other-host", Serial: "LIVE-SN"},
	}
	res := Reconcile(entries, devices)
	if res.MatchedCount != 1 || res.MatchedRetiredCount != 0 {
		t.Fatalf("matched = %d (retired %d), want 1 (0)", res.MatchedCount, res.MatchedRetiredCount)
	}
	if len(res.Matched) != 1 || res.Matched[0].Device.ID != "live-one" || res.Matched[0].Device.Retired {
		t.Fatalf("Matched = %+v, want the live device reported", res.Matched)
	}
}

func TestPlaceholderSerialsAreNoSerial(t *testing.T) {
	for _, p := range []string{"", "   ", "To be filled by O.E.M.", "Default string", "SYSTEM SERIAL NUMBER",
		"None", "N/A", "Not Specified", "not applicable", "0", "123456789", "0000000000", "FFFFFFFF",
		"xxxx", "abc", " A1 "} {
		if !IsPlaceholderSerial(p) || NormalizeSerial(p) != "" {
			t.Errorf("%q should be a placeholder serial", p)
		}
	}
	for _, real := range []string{"C02XL0GTJGH5", "PF3ABCDE", "0001", "1234567890", "AB12"} {
		if IsPlaceholderSerial(real) || NormalizeSerial(real) == "" {
			t.Errorf("%q should be a real serial", real)
		}
	}
}

func TestPlaceholderSerialFallsBackToHostname(t *testing.T) {
	// Both sides carry placeholders that differ: without the placeholder
	// rule the serials would decide and block this hostname match.
	entries := mustValidate(t, []InputEntry{{Hostname: sp("vm-01"), Serial: sp("To be filled by O.E.M.")}})
	res := Reconcile(entries, []Device{{ID: "d1", Hostname: "VM-01", Serial: "0"}})
	if res.MatchedCount != 1 {
		t.Fatalf("result = %+v, want a hostname match", res)
	}
	// Two unrelated machines sharing a placeholder never match on it.
	entries = mustValidate(t, []InputEntry{{Hostname: sp("vm-a"), Serial: sp("Default string")}})
	res = Reconcile(entries, []Device{{ID: "d2", Hostname: "vm-b", Serial: "Default string"}})
	if res.MatchedCount != 0 {
		t.Fatalf("placeholder serial matched two different machines: %+v", res)
	}
	// A placeholder serial alone is not an identifier.
	if _, _, err := Validate([]InputEntry{{Serial: sp("N/A")}}); err == nil || err.Code != "missing_identifier" {
		t.Fatalf("placeholder-only entry err = %v, want missing_identifier", err)
	}
}

func TestFirstLabelFallback(t *testing.T) {
	t.Run("fqdn entry matches short device name", func(t *testing.T) {
		entries := mustValidate(t, []InputEntry{{Hostname: sp("PC01.corp.example.com")}})
		res := Reconcile(entries, []Device{{ID: "d1", Hostname: "PC01"}})
		if res.MatchedCount != 1 || len(res.SeenNotOnList) != 0 || len(res.OnListNeverSeen) != 0 {
			t.Fatalf("result = %+v, want the FQDN entry to match", res)
		}
	})
	t.Run("short entry matches fqdn device", func(t *testing.T) {
		entries := mustValidate(t, []InputEntry{{Hostname: sp("pc02")}})
		res := Reconcile(entries, []Device{{ID: "d1", Hostname: "pc02.corp.example.com"}})
		if res.MatchedCount != 1 {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("colliding device short names do not match", func(t *testing.T) {
		entries := mustValidate(t, []InputEntry{{Hostname: sp("pc01")}})
		res := Reconcile(entries, []Device{
			{ID: "d1", Hostname: "pc01.a.example.com"},
			{ID: "d2", Hostname: "pc01.b.example.com"},
		})
		if res.MatchedCount != 0 || len(res.SeenNotOnList) != 2 || len(res.OnListNeverSeen) != 1 {
			t.Fatalf("ambiguous label matched: %+v", res)
		}
	})
	t.Run("colliding entries do not match", func(t *testing.T) {
		entries := mustValidate(t, []InputEntry{{Hostname: sp("pc01.a.example.com")}, {Hostname: sp("pc01.b.example.com")}})
		res := Reconcile(entries, []Device{{ID: "d1", Hostname: "pc01"}})
		if res.MatchedCount != 0 || len(res.SeenNotOnList) != 1 {
			t.Fatalf("ambiguous label matched: %+v", res)
		}
	})
	t.Run("fqdn to fqdn in another domain does not match", func(t *testing.T) {
		entries := mustValidate(t, []InputEntry{{Hostname: sp("pc01.a.example.com")}})
		res := Reconcile(entries, []Device{{ID: "d1", Hostname: "pc01.b.example.com"}})
		if res.MatchedCount != 0 {
			t.Fatalf("FQDNs in different domains matched: %+v", res)
		}
	})
	t.Run("differing real serials still rule it out", func(t *testing.T) {
		entries := mustValidate(t, []InputEntry{{Hostname: sp("pc01.corp.example.com"), Serial: sp("SERIAL-A")}})
		res := Reconcile(entries, []Device{{ID: "d1", Hostname: "pc01", Serial: "SERIAL-B"}})
		if res.MatchedCount != 0 {
			t.Fatalf("serial mismatch matched through the fallback: %+v", res)
		}
	})
	t.Run("exact match is consumed first", func(t *testing.T) {
		// pc01 matches pc01 exactly, so the FQDN entry is left alone and
		// has no unmatched partner.
		entries := mustValidate(t, []InputEntry{{Hostname: sp("pc01")}, {Hostname: sp("pc01.corp.example.com")}})
		res := Reconcile(entries, []Device{{ID: "d1", Hostname: "pc01"}})
		if res.MatchedCount != 1 || len(res.OnListNeverSeen) != 1 || res.OnListNeverSeen[0].Position != 1 {
			t.Fatalf("result = %+v", res)
		}
	})
}

func TestCheckFieldRejectsFormatCharacters(t *testing.T) {
	r := func(c rune) string { return string(c) }
	for _, s := range []string{"mac" + r(0x200b) + "01", r(0xfeff) + "C02ABC", "pc" + r(0x202e) + "10", "a" + r(0x00ad) + "b", "x" + r(0x200d) + "y"} {
		if _, bad := CheckField(s); bad == "" {
			t.Errorf("CheckField(%q) accepted a format character", s)
		}
	}
	if v, bad := CheckField("  DESKTOP-ROBWIN.corp  "); bad != "" || v != "DESKTOP-ROBWIN.corp" {
		t.Errorf("plain hostname refused: %q %q", v, bad)
	}
}
