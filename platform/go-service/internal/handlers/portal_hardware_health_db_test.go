package handlers

// PAT-2130: locks that the Hardware health section of the portal
// executive-summary PDF is no longer gated behind subscription_tier
// "managed" (PAT-686's provisional gate, removed by the 24 September 2026
// ruling "one plan, no report gating" — see the comment in portal.go's
// renderPortalExecutiveSummary and internal/report/portal_pdf.go's
// RenderPortalReportPDF doc comment). Every tenant, assurance included, now
// gets the section. DB-backed; skipped without TEST_DATABASE_URL.

import (
	"context"
	"log/slog"
	"testing"

	"patched.im/api/internal/report"
)

// TestPortalExecutiveSummary_HardwareHealthIncludedForAssuranceTenant proves
// an assurance-tier tenant's portal PDF now includes the Hardware health
// section, which it did not before this ticket (subTierManaged gate).
//
// It renders the report through the exact path POST /v1/portal/reports
// (executive-summary) uses — renderPortalExecutiveSummary — for a tenant
// seeded at the default subscription_tier ("assurance" since migration
// 0138), then independently re-fetches the same underlying data through the
// same report.Fetch* functions and renders it a second time with
// includeHardwareHealth=false: this second render is exactly the byte size
// the old subTierManaged gate would have produced for an assurance tenant,
// since tierAtLeast("assurance", "managed") is false. The handler's own
// render must now be strictly larger.
func TestPortalExecutiveSummary_HardwareHealthIncludedForAssuranceTenant(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat2130-hw-health-assurance")

	var tier string
	if err := pool.QueryRow(ctx, `SELECT subscription_tier FROM tenants WHERE id = $1::uuid`, tenantID).Scan(&tier); err != nil {
		t.Fatalf("read seeded tenant tier: %v", err)
	}
	if tier != "assurance" {
		t.Fatalf("seeded tenant tier = %q, want %q (the default since migration 0138) — fix the fixture, this test only means what it says for an assurance tenant", tier, "assurance")
	}

	logger := slog.Default()

	// Exactly what POST /v1/portal/reports (executive-summary) produces.
	gotPDF, _, err := renderPortalExecutiveSummary(ctx, pool, tenantID, logger)
	if err != nil {
		t.Fatalf("renderPortalExecutiveSummary: %v", err)
	}

	// The same fetch pipeline, rendered with the section forced off — the
	// byte size the pre-PAT-2130 gate would have produced for this tenant.
	summary, err := report.FetchExecutiveSummary(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("fetch summary: %v", err)
	}
	summary.UserAttributionToggle = "off"
	ov, err := report.FetchPortalOverview(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("fetch overview: %v", err)
	}
	findings, err := report.FetchPortalCVEFindings(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("fetch cve findings: %v", err)
	}
	devices, err := report.FetchPortalDevices(ctx, pool, tenantID, portalReportDeviceLimit, 0)
	if err != nil {
		t.Fatalf("fetch devices: %v", err)
	}
	gatedPDF, err := report.RenderPortalReportPDF(summary, ov, findings, devices, false)
	if err != nil {
		t.Fatalf("render without hardware health: %v", err)
	}

	if len(gotPDF) <= len(gatedPDF) {
		t.Fatalf("assurance-tier tenant's portal PDF (%d bytes) is no bigger than the pre-PAT-2130 gated rendering (%d bytes) — Hardware health section is missing",
			len(gotPDF), len(gatedPDF))
	}
}
