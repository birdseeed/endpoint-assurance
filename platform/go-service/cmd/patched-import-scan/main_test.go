package main

import (
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/csvparse"
	"patched.im/api/internal/cvematch"
	"patched.im/api/internal/cvescan"
	"patched.im/api/internal/report"
)

// ─── csvparse.ParseCSV ────────────────────────────────────────────────────────

func TestParseCSV_NormalisedHeaders(t *testing.T) {
	const input = `deviceName,appName,appVersion
alice-mbp,Google Chrome,120.0.6099.130
alice-mbp,Dropbox,180.4
bob-mbp,Slack,4.35.131
`
	apps, err := csvparse.ParseCSV(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseCSV error: %v", err)
	}
	if len(apps) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(apps))
	}
	if apps[0].DeviceName != "alice-mbp" || apps[0].AppName != "Google Chrome" || apps[0].AppVersion != "120.0.6099.130" {
		t.Errorf("row 0 mismatch: %+v", apps[0])
	}
	if apps[2].DeviceName != "bob-mbp" || apps[2].AppName != "Slack" {
		t.Errorf("row 2 mismatch: %+v", apps[2])
	}
}

func TestParseCSV_IntuneHeaders(t *testing.T) {
	const input = `Device name,Application,Version
alice-mbp,Microsoft Teams,24.3.0
`
	apps, err := csvparse.ParseCSV(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseCSV (Intune headers) error: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("expected 1 row, got %d", len(apps))
	}
	if apps[0].DeviceName != "alice-mbp" || apps[0].AppName != "Microsoft Teams" || apps[0].AppVersion != "24.3.0" {
		t.Errorf("row mismatch: %+v", apps[0])
	}
}

func TestParseCSV_MissingVersionColumn(t *testing.T) {
	const input = `deviceName,appName
alice-mbp,Google Chrome
`
	apps, err := csvparse.ParseCSV(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseCSV (no version column) error: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("expected 1 row, got %d", len(apps))
	}
	if apps[0].AppVersion != "" {
		t.Errorf("expected empty AppVersion, got %q", apps[0].AppVersion)
	}
}

func TestParseCSV_MissingRequiredColumn(t *testing.T) {
	const input = `appName,appVersion
Google Chrome,120.0
`
	_, err := csvparse.ParseCSV(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error for missing device column, got nil")
	}
}

func TestParseCSV_SkipsBlankAppName(t *testing.T) {
	const input = `deviceName,appName,appVersion
alice-mbp,,
alice-mbp,Google Chrome,120.0
`
	apps, err := csvparse.ParseCSV(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseCSV error: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("expected 1 row (blank skipped), got %d", len(apps))
	}
}

// ─── csvparse.ParseJSON ───────────────────────────────────────────────────────

func TestParseJSON(t *testing.T) {
	const input = `[
		{"deviceName":"alice-mbp","appName":"Google Chrome","appVersion":"120.0.6099.130"},
		{"deviceName":"bob-mbp","appName":"Dropbox","appVersion":"180.4"}
	]`
	apps, err := csvparse.ParseJSON(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseJSON error: %v", err)
	}
	if len(apps) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(apps))
	}
	if apps[1].DeviceName != "bob-mbp" || apps[1].AppName != "Dropbox" {
		t.Errorf("row 1 mismatch: %+v", apps[1])
	}
}

func TestParseJSON_Invalid(t *testing.T) {
	_, err := csvparse.ParseJSON(strings.NewReader(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

// ─── cvescan.GroupByDevice ────────────────────────────────────────────────────

func TestGroupByDevice(t *testing.T) {
	raw := []csvparse.App{
		{DeviceName: "alice-mbp", AppName: "Chrome", AppVersion: "120"},
		{DeviceName: "alice-mbp", AppName: "Dropbox", AppVersion: "180"},
		{DeviceName: "bob-mbp", AppName: "Slack", AppVersion: "4"},
	}
	groups := cvescan.GroupByDevice(raw)
	if len(groups) != 2 {
		t.Fatalf("expected 2 device groups, got %d", len(groups))
	}
	if len(groups["alice-mbp"]) != 2 {
		t.Errorf("alice-mbp should have 2 apps, got %d", len(groups["alice-mbp"]))
	}
	if len(groups["bob-mbp"]) != 1 {
		t.Errorf("bob-mbp should have 1 app, got %d", len(groups["bob-mbp"]))
	}
}

// ─── cvescan.BuildReport ─────────────────────────────────────────────────────

func ptrF64(f float64) *float64 { return &f }

func TestBuildReport(t *testing.T) {
	feed := []cvematch.CVEEntry{
		{
			CVEID:       "CVE-2024-0001",
			Description: "A critical bug in Chrome",
			Score:       ptrF64(9.8),
			Severity:    "CRITICAL",
		},
		{
			CVEID:       "CVE-2024-0002",
			Description: "A high-severity bug in Slack",
			Score:       ptrF64(7.5),
			Severity:    "HIGH",
		},
	}

	deviceFindings := map[string][]cvematch.Finding{
		"alice-mbp": {
			{CVEID: "CVE-2024-0001", Score: ptrF64(9.8), Severity: "CRITICAL", AppName: "Chrome", AppVersion: "120", MatchConfidence: "version_confirmed"},
		},
		"bob-mbp": {
			{CVEID: "CVE-2024-0002", Score: ptrF64(7.5), Severity: "HIGH", AppName: "Slack", AppVersion: "4", MatchConfidence: "version_unverified"},
		},
	}

	now := time.Date(2026, 12, 15, 12, 0, 0, 0, time.UTC)
	r := cvescan.BuildReport(deviceFindings, feed, "Test Tenant", now)

	if r.FormatVersion != report.FreeCVEFormatVersion {
		t.Errorf("FormatVersion = %q, want %q", r.FormatVersion, report.FreeCVEFormatVersion)
	}
	if r.Tenant != "Test Tenant" {
		t.Errorf("Tenant = %q, want %q", r.Tenant, "Test Tenant")
	}
	if r.TotalCVEs != 2 {
		t.Errorf("TotalCVEs = %d, want 2", r.TotalCVEs)
	}
	if r.CriticalCount != 1 {
		t.Errorf("CriticalCount = %d, want 1", r.CriticalCount)
	}
	if r.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", r.HighCount)
	}
	if r.ConfirmedHits != 1 {
		t.Errorf("ConfirmedHits = %d, want 1", r.ConfirmedHits)
	}
	if r.UnverifiedHits != 1 {
		t.Errorf("UnverifiedHits = %d, want 1", r.UnverifiedHits)
	}

	if len(r.CVEs) >= 2 {
		if r.CVEs[0].Severity != "CRITICAL" || r.CVEs[1].Severity != "HIGH" {
			t.Errorf("wrong severity order: %s, %s", r.CVEs[0].Severity, r.CVEs[1].Severity)
		}
	}
	for _, cve := range r.CVEs {
		if cve.CVEID == "CVE-2024-0001" && cve.Description != "A critical bug in Chrome" {
			t.Errorf("CVE-2024-0001 description = %q", cve.Description)
		}
	}
}

func TestBuildReport_DeviceOrdering(t *testing.T) {
	f := cvematch.Finding{CVEID: "CVE-2024-0001", Score: ptrF64(7.5), Severity: "HIGH", AppName: "App", AppVersion: "1.0", MatchConfidence: "version_unverified"}
	deviceFindings := map[string][]cvematch.Finding{
		"zebra-host": {f},
		"alpha-host": {f},
	}

	r := cvescan.BuildReport(deviceFindings, nil, "T", time.Now())

	if len(r.CVEs) != 1 {
		t.Fatalf("expected 1 CVE record, got %d", len(r.CVEs))
	}
	hits := r.CVEs[0].Hits
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits, got %d", len(hits))
	}
	if hits[0].Hostname != "alpha-host" || hits[1].Hostname != "zebra-host" {
		t.Errorf("device order wrong: %v, %v", hits[0].Hostname, hits[1].Hostname)
	}
}

// ─── End-to-end import path ───────────────────────────────────────────────────

func TestImportScanPDF(t *testing.T) {
	mappings := []cvematch.CPEMapping{
		{MatchName: "Google Chrome", CPEVendor: "google", CPEProduct: "chrome"},
	}
	feed := []cvematch.CVEEntry{
		{
			CVEID:       "CVE-2024-1111",
			Description: "Heap overflow in Chrome",
			Score:       ptrF64(9.8),
			Severity:    "CRITICAL",
			Patterns:    []string{"google:chrome"},
			Ranges: []cvematch.CPERange{
				{Vendor: "google", Product: "chrome", VEndExcl: "122.0.0.0"},
			},
		},
	}
	rawApps := []csvparse.App{
		{DeviceName: "import-host", AppName: "Google Chrome", AppVersion: "120.0.6099.130"},
	}

	deviceApps := cvescan.GroupByDevice(rawApps)
	deviceFindings := map[string][]cvematch.Finding{}
	for device, apps := range deviceApps {
		findings := cvematch.Match(apps, mappings, feed, "")
		if len(findings) > 0 {
			deviceFindings[device] = findings
		}
	}

	rpt := cvescan.BuildReport(deviceFindings, feed, "Import Test Co", time.Date(2026, 12, 15, 0, 0, 0, 0, time.UTC))

	if rpt.TotalCVEs != 1 || rpt.ConfirmedHits != 1 {
		t.Fatalf("expected 1 confirmed CVE, got TotalCVEs=%d ConfirmedHits=%d", rpt.TotalCVEs, rpt.ConfirmedHits)
	}

	pdf, err := report.RenderFreeCVEPDF(rpt)
	if err != nil {
		t.Fatalf("RenderFreeCVEPDF error: %v", err)
	}
	if len(pdf) < 2000 {
		t.Errorf("PDF too small: %d bytes", len(pdf))
	}
	if !strings.HasPrefix(string(pdf[:8]), "%PDF-") {
		t.Errorf("output does not start with %%PDF- header")
	}
}
