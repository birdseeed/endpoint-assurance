package report

import "testing"

func TestReportCatalogueIsCompleteUniqueAndImmutable(t *testing.T) {
	got := ReportCatalogue()
	if len(got) != 19 {
		t.Fatalf("catalogue entries = %d, want 19", len(got))
	}
	wantTypes := map[string]bool{
		"executive-summary": true, "cis-compliance": true, "cve-report": true,
		"patch-status": true, "stale-endpoints": true, "cert-expiry": true,
		"software-inventory": true, "app-policy-drift": true,
		"browser-extensions": true, "edr-coverage": true, "device-health": true,
		"encryption-posture": true, "local-admin": true, "device-compliance": true,
		// PAT-2009
		"new-software": true, "software-drift": true, "approved-software": true,
		// PAT-2205
		"ai-tooling-evidence": true,
		// PAT-2258
		"insurance-evidence": true,
	}
	seen := make(map[string]bool, len(got))
	customerFacing := 0
	for _, entry := range got {
		if entry.Type == "" || entry.Label == "" || entry.Description == "" || entry.DefaultFrequency == "" || entry.AdminPDFPath == "" {
			t.Errorf("incomplete registry entry: %+v", entry)
		}
		if seen[entry.Type] {
			t.Errorf("duplicate report type %q", entry.Type)
		}
		if !wantTypes[entry.Type] {
			t.Errorf("unexpected report type %q", entry.Type)
		}
		seen[entry.Type] = true
		if entry.CustomerFacing {
			customerFacing++
		}
	}
	if customerFacing != 14 {
		t.Fatalf("customer-facing entries = %d, want 14", customerFacing)
	}

	got[0].Label = "mutated"
	fresh := ReportCatalogue()
	if fresh[0].Label == "mutated" {
		t.Fatal("ReportCatalogue exposed mutable registry storage")
	}
}

func TestPortalReportCatalogueContainsOnlyApprovedTypes(t *testing.T) {
	want := map[string]bool{
		"executive-summary": true, "cis-compliance": true, "patch-status": true,
		"cve-report": true, "stale-endpoints": true, "encryption-posture": true,
		"cert-expiry": true, "local-admin": true, "edr-coverage": true,
		"new-software": true, "software-drift": true, "approved-software": true,
		"ai-tooling-evidence": true, "insurance-evidence": true,
	}
	got := PortalReportCatalogue()
	if len(got) != len(want) {
		t.Fatalf("portal catalogue entries = %d, want %d", len(got), len(want))
	}
	for _, entry := range got {
		if !want[entry.Type] {
			t.Errorf("unexpected portal report type %q", entry.Type)
		}
		if entry.Subject != SubjectTenant {
			t.Errorf("portal report %q scope = %q, want tenant", entry.Type, entry.Subject)
		}
	}
}

// PAT-2406: the Local Admin report is the one admin-only report. Marking
// another report admin-only, or unmarking this one, is a role ruling and
// must be made here on purpose.
func TestAdminOnlyReportTypesIsExactlyLocalAdmin(t *testing.T) {
	got := AdminOnlyReportTypes()
	if len(got) != 1 || got[0] != "local-admin" {
		t.Fatalf("AdminOnlyReportTypes() = %v, want [local-admin]", got)
	}
	def, found := LookupReportDefinition("local-admin")
	if !found || !def.AdminOnly || !def.CustomerFacing {
		t.Fatalf("local-admin definition = %+v, want customer-facing and admin-only", def)
	}
	flagged := 0
	for _, entry := range PortalReportCatalogue() {
		if entry.AdminOnly {
			flagged++
		}
	}
	if flagged != 1 {
		t.Fatalf("portal catalogue has %d admin-only entries, want 1", flagged)
	}
	got[0] = "mutated"
	if AdminOnlyReportTypes()[0] != "local-admin" {
		t.Fatal("AdminOnlyReportTypes exposed mutable storage")
	}
}
