package report

import (
	"encoding/csv"
	"strings"
	"testing"
	"time"
)

func parseCSVForTest(t *testing.T, b []byte) [][]string {
	t.Helper()
	recs, err := csv.NewReader(strings.NewReader(string(b))).ReadAll()
	if err != nil {
		t.Fatalf("csv does not parse: %v", err)
	}
	return recs
}

func noSentinel(t *testing.T, recs [][]string) {
	t.Helper()
	for _, r := range recs {
		for _, c := range r {
			if c == "-1" || c == "'-1" {
				t.Errorf("csv carries the -1 sentinel in row %q", r)
			}
		}
	}
}

func colOf(t *testing.T, header []string, name string) int {
	t.Helper()
	for i, h := range header {
		if h == name {
			return i
		}
	}
	t.Fatalf("no column %q in %q", name, header)
	return -1
}

// PAT-2405: unknown is an empty cell, never a sentinel number. The local-admin
// data model uses AdminCount -1 (Risk "unknown") for "no usable signal".
func TestLocalAdminCSVUnknownCountIsEmpty(t *testing.T) {
	out, err := LocalAdminCSV(LocalAdminReport{GeneratedAt: time.Now(), Devices: []LocalAdminDevice{
		{Hostname: "known", OS: "macOS", AdminCount: 2, Risk: "compliant"},
		{Hostname: "unknown", OS: "Windows", AdminCount: -1, Risk: "unknown"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	recs := parseCSVForTest(t, out)
	count, host, risk := colOf(t, recs[0], "admin_count"), colOf(t, recs[0], "hostname"), colOf(t, recs[0], "risk")
	for _, r := range recs[1:] {
		switch r[host] {
		case "known":
			if r[count] != "2" {
				t.Errorf("known admin_count = %q, want 2", r[count])
			}
		case "unknown":
			if r[count] != "" || r[risk] != "unknown" {
				t.Errorf("unknown device: admin_count %q risk %q, want empty and unknown", r[count], r[risk])
			}
		}
	}
	noSentinel(t, recs)
}

// The executive summary's median days since last patch is -1 with no patch
// history; the PDF omits it, the CSV leaves the value empty.
func TestPortalExecutiveCSVUnknownMedianIsEmpty(t *testing.T) {
	s := ExecutiveSummary{GeneratedAt: time.Now()}
	s.Patching.MedianDaysSinceLastPatch = -1
	out, err := PortalExecutiveCSV(s, PortalOverview{GeneratedAt: time.Now()}, nil, PortalDevicesResult{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range parseCSVForTest(t, out)[1:] {
		if strings.Contains(r[0], "median days since last patch") {
			found = true
			if r[1] != "" {
				t.Errorf("median = %q, want empty", r[1])
			}
		}
	}
	if !found {
		t.Error("median row missing")
	}
	noSentinel(t, parseCSVForTest(t, out))
}

// A zero time (unknown) is an empty cell, not 0001-01-01.
func TestStaleEndpointsCSVZeroTimeIsEmpty(t *testing.T) {
	out, err := StaleEndpointsCSV(StaleEndpointsReport{GeneratedAt: time.Now(), ThresholdDays: 14,
		Retired: []RetiredDevice{{Hostname: "r"}}})
	if err != nil {
		t.Fatal(err)
	}
	recs := parseCSVForTest(t, out)
	for _, name := range []string{"last_seen", "retired_at"} {
		if v := recs[1][colOf(t, recs[0], name)]; v != "" {
			t.Errorf("%s = %q, want empty", name, v)
		}
	}
}
