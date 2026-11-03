//go:build integration

// GET /v1/portal/applications (PAT-1727) integration tests. Extends the
// GET /v1/portal/unapproved-apps coverage in portal_test.go to the new
// endpoint: policy rows (every tenant_app_policies value, not just
// "unapproved"), undecided applications grouped by identifier or by name,
// the "matching an approved policy never also reads undecided" invariant,
// cross-tenant isolation, platform scoping and the undecided-row cap.
package integration

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"patched.im/api/internal/report"
)

type portalApplicationOut struct {
	Type                   string     `json:"type"`
	Name                   string     `json:"name"`
	Identifier             string     `json:"identifier"`
	PolicyTeamID           *string    `json:"policy_team_id"`
	ProductKey             *string    `json:"product_key"`
	Platform               string     `json:"platform"`
	PolicyState            string     `json:"policy_state"`
	EnforcementTier        string     `json:"enforcement_tier"`
	DeviceCount            int        `json:"device_count"`
	EvidenceBasis          string     `json:"evidence_basis"`
	IdentifierMatchedCount int        `json:"identifier_matched_devices"`
	NameMatchedCount       int        `json:"name_matched_devices"`
	RemovalState           string     `json:"removal_state"`
	VersionCount           int        `json:"version_count"`
	TeamID                 *string    `json:"team_id"`
	SignedBy               *string    `json:"signed_by"`
	Notarized              *bool      `json:"notarized"`
	LatestKnownVersion     *string    `json:"latest_known_version"`
	DevicesBehindCount     *int       `json:"devices_behind_count"`
	DecidedBy              *string    `json:"decided_by"`
	DecidedAt              *time.Time `json:"decided_at"`
	Justification          *string    `json:"justification"`
}

type portalApplicationsOut struct {
	Total          int                    `json:"total"`
	Truncated      bool                   `json:"truncated"`
	EstateTooLarge bool                   `json:"estate_too_large"`
	Applications   []portalApplicationOut `json:"applications"`
}

func findPortalApplication(apps []portalApplicationOut, name string) (portalApplicationOut, bool) {
	for _, a := range apps {
		if a.Name == name {
			return a, true
		}
	}
	return portalApplicationOut{}, false
}

// cleanupTestTenant deletes a test tenant and, via ON DELETE CASCADE
// (devices -> tenants, device_apps -> devices, tenant_app_policies ->
// tenants, portal_users -> tenants), everything this file seeded under it.
//
// The CI job (go-integration-test.yml) runs ./integration/... and
// ./internal/handlers/... back-to-back against the SAME Postgres database,
// not a fresh one per step, so a left-behind device_apps row is visible to
// any later cross-tenant aggregate. This file's row-cap test alone seeds
// 505 distinct single-device app identities ("bundle:com.example.rowcap.*").
// (PAT-2249 retired GET /admin/catalogue/candidates, the unscoped aggregate
// this cleanup was first written to protect; the cleanup stays because
// the shared-database hazard does.) Register this immediately after
// createTestTenant succeeds, before any other seeding, so it always runs
// even if a later seed step in the same test fails.
func cleanupTestTenant(t *testing.T, tenantID string) {
	t.Helper()
	t.Cleanup(func() {
		if _, err := env.pool.Exec(context.Background(),
			`DELETE FROM tenants WHERE id = $1::uuid`, tenantID); err != nil {
			t.Errorf("cleanup tenant %s: %v", tenantID, err)
		}
	})
}

// TestPortalApplicationsPolicyRows seeds one approved and one unapproved
// policy, each with a matching device, and asserts both come back with
// type "application", the correct policy_state, exact device counts and
// removal_state "not_available" — unlike GET /v1/portal/unapproved-apps,
// this endpoint must surface the approved row too.
func TestPortalApplicationsPolicyRows(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-policy-rows")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-apps-policy', gen_random_uuid(), 'host-apps-policy', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'com.example.approvedtool', 'ApprovedTool', 'any', 'approved', 'report'),
		       ($1::uuid, NULL, 'BadTool', 'any', 'unapproved', 'app_management')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed policies: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'ApprovedTool', 'com.example.approvedtool', '1.0.0'),
		       ($1::uuid, 'BadTool', 'com.example.badtool', '2.0.0')
	`, deviceID)
	if err != nil {
		t.Fatalf("seed device_apps: %v", err)
	}

	email := "policyrows@apps-policy-rows.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/applications", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("applications = %d: %s", resp.StatusCode, b)
	}
	var out portalApplicationsOut
	decodeJSON(t, resp, &out)

	approved, ok := findPortalApplication(out.Applications, "ApprovedTool")
	if !ok {
		t.Fatalf("ApprovedTool missing from %+v", out.Applications)
	}
	if approved.Type != "application" || approved.PolicyState != "approved" || approved.DeviceCount != 1 ||
		approved.EvidenceBasis != "identifier_match" || approved.RemovalState != "not_available" {
		t.Errorf("ApprovedTool row = %+v, want type=application policy_state=approved device_count=1 "+
			"evidence_basis=identifier_match removal_state=not_available", approved)
	}

	unapproved, ok := findPortalApplication(out.Applications, "BadTool")
	if !ok {
		t.Fatalf("BadTool missing from %+v", out.Applications)
	}
	if unapproved.PolicyState != "unapproved" || unapproved.DeviceCount != 1 ||
		unapproved.EnforcementTier != "app_management" {
		t.Errorf("BadTool row = %+v, want policy_state=unapproved device_count=1 enforcement_tier=app_management", unapproved)
	}
}

// TestPortalApplicationsUndecidedByIdentifier seeds an installed app with a
// stable identifier and no matching policy at all: it must appear as
// policy_state "undecided" with evidence_basis "identifier_match", grouped
// across both devices that report it.
func TestPortalApplicationsUndecidedByIdentifier(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-undecided-id")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	var deviceIDs [2]string
	for i := range deviceIDs {
		err = env.pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
			VALUES ($1::uuid, $2, gen_random_uuid(), $3, 'macOS', '15.5', '24F74', 'arm64', now())
			RETURNING id::text
		`, tenantID, "SER-undecided-id-"+string(rune('a'+i)), "host-undecided-id-"+string(rune('a'+i))).Scan(&deviceIDs[i])
		if err != nil {
			t.Fatalf("seed device %d: %v", i, err)
		}
		_, err = env.pool.Exec(ctx, `
			INSERT INTO device_apps (device_id, name, identifier, version)
			VALUES ($1::uuid, 'MysteryApp', 'com.example.mysteryapp', '1.0.0')
		`, deviceIDs[i])
		if err != nil {
			t.Fatalf("seed device_apps %d: %v", i, err)
		}
	}

	email := "undecided-id@apps-undecided-id.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/applications", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("applications = %d: %s", resp.StatusCode, b)
	}
	var out portalApplicationsOut
	decodeJSON(t, resp, &out)

	app, ok := findPortalApplication(out.Applications, "MysteryApp")
	if !ok {
		t.Fatalf("MysteryApp missing from %+v", out.Applications)
	}
	if app.PolicyState != "undecided" || app.EvidenceBasis != "identifier_match" ||
		app.Identifier != "com.example.mysteryapp" || app.DeviceCount != 2 || app.Platform != "macos" {
		t.Errorf("MysteryApp row = %+v, want policy_state=undecided evidence_basis=identifier_match "+
			"identifier=com.example.mysteryapp device_count=2 platform=macos", app)
	}
}

// TestPortalApplicationsUndecidedByNameOnly seeds a device_apps row with an
// empty identifier (a legacy/degraded row — current ingestion never writes
// one, see internal/extractor/upsert.go, but the schema does not forbid it)
// and no matching policy: it must still surface as "undecided", grouped by
// name, with evidence_basis "name_match_only" and no identifier in the
// response.
func TestPortalApplicationsUndecidedByNameOnly(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-undecided-name")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-undecided-name', gen_random_uuid(), 'host-undecided-name', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'NamelessApp', '', '1.0.0')
	`, deviceID)
	if err != nil {
		t.Fatalf("seed device_apps: %v", err)
	}

	email := "undecided-name@apps-undecided-name.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/applications", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("applications = %d: %s", resp.StatusCode, b)
	}
	var out portalApplicationsOut
	decodeJSON(t, resp, &out)

	app, ok := findPortalApplication(out.Applications, "NamelessApp")
	if !ok {
		t.Fatalf("NamelessApp missing from %+v", out.Applications)
	}
	if app.PolicyState != "undecided" || app.EvidenceBasis != "name_match_only" || app.Identifier != "" {
		t.Errorf("NamelessApp row = %+v, want policy_state=undecided evidence_basis=name_match_only identifier=\"\"", app)
	}
}

// TestPortalApplicationsPolicyRowDecisionProvenance (PAT-1800) seeds a
// tenant_app_policies row with notes set and asserts the resulting policy
// row carries decided_at (from updated_at) and justification (from notes),
// but decided_by is always nil — tenant_app_policies has no actor column at
// all, unlike tenant_extension_policies' approved_by, so there is genuinely
// no "who" to report. Also seeds a second policy row with blank (default)
// notes and asserts justification reads nil, not an empty string.
func TestPortalApplicationsPolicyRowDecisionProvenance(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-policy-provenance")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, name, platform, policy, enforcement_tier, notes)
		VALUES
			($1::uuid, 'com.example.notedtool', 'NotedTool', 'any', 'approved', 'report', 'Reviewed 2026-09-01, low risk'),
			($1::uuid, 'com.example.blanktool', 'BlankTool', 'any', 'unapproved', 'app_management', '')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed policies: %v", err)
	}

	email := "policyprovenance@apps-policy-provenance.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/applications", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("applications = %d: %s", resp.StatusCode, b)
	}
	var out portalApplicationsOut
	decodeJSON(t, resp, &out)

	noted, ok := findPortalApplication(out.Applications, "NotedTool")
	if !ok {
		t.Fatalf("NotedTool missing from %+v", out.Applications)
	}
	if noted.DecidedBy != nil {
		t.Errorf("NotedTool decided_by = %v, want nil (tenant_app_policies has no actor column)", *noted.DecidedBy)
	}
	if noted.DecidedAt == nil {
		t.Errorf("NotedTool decided_at = nil, want a real timestamp (tenant_app_policies.updated_at)")
	}
	if noted.Justification == nil || *noted.Justification != "Reviewed 2026-09-01, low risk" {
		t.Errorf("NotedTool justification = %v, want %q", noted.Justification, "Reviewed 2026-09-01, low risk")
	}

	blank, ok := findPortalApplication(out.Applications, "BlankTool")
	if !ok {
		t.Fatalf("BlankTool missing from %+v", out.Applications)
	}
	if blank.Justification != nil {
		t.Errorf("BlankTool justification = %v, want nil (empty notes must not read as a real justification)", *blank.Justification)
	}
	if blank.DecidedAt == nil {
		t.Errorf("BlankTool decided_at = nil, want a real timestamp")
	}
}

// TestPortalApplicationsUndecidedDecisionProvenance (PAT-1800) covers the
// undecided half: a tenant_new_apps row recording a real triage decision
// (decision/decided_by/decided_at all set) for the same app must surface
// on the matching "undecided" application row, keyed by the same
// team_id > identifier > name precedence tenant_app_policies matching
// already uses (see report.newAppIdentityKey's doc comment). An undecided
// app with NO tenant_new_apps row at all must read decided_by/decided_at/
// justification all nil — genuinely no decision exists yet, never
// fabricated. justification is always nil on this half even when a
// decision exists: tenant_new_apps carries no free-text field.
func TestPortalApplicationsUndecidedDecisionProvenance(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-undecided-provenance")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-undecided-prov', gen_random_uuid(), 'host-undecided-prov', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	// TriagedApp: a real device_apps row with a team_id, plus a matching
	// tenant_new_apps row (app_identity = "team:" + lower(team_id), the
	// highest-precedence key) whose decision has been set. No
	// tenant_app_policies row exists, so it must still read
	// policy_state=undecided.
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, team_id, version)
		VALUES ($1::uuid, 'TriagedApp', 'com.example.triagedapp', 'TEAM1800X', '1.0.0')
	`, deviceID)
	if err != nil {
		t.Fatalf("seed device_apps TriagedApp: %v", err)
	}
	decidedAt := time.Now().UTC().Add(-24 * time.Hour)
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_new_apps (tenant_id, app_identity, name, platform, decision, decided_by, decided_at)
		VALUES ($1::uuid, 'team:team1800x', 'TriagedApp', 'macos', 'defer', 'ops@example.com', $2)
	`, tenantID, decidedAt)
	if err != nil {
		t.Fatalf("seed tenant_new_apps: %v", err)
	}

	// UntouchedApp: installed, no policy row, no tenant_new_apps row —
	// genuinely no decision has ever been recorded anywhere for it.
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'UntouchedApp', 'com.example.untouchedapp', '1.0.0')
	`, deviceID)
	if err != nil {
		t.Fatalf("seed device_apps UntouchedApp: %v", err)
	}

	email := "undecidedprov@apps-undecided-provenance.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/applications", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("applications = %d: %s", resp.StatusCode, b)
	}
	var out portalApplicationsOut
	decodeJSON(t, resp, &out)

	triaged, ok := findPortalApplication(out.Applications, "TriagedApp")
	if !ok {
		t.Fatalf("TriagedApp missing from %+v", out.Applications)
	}
	if triaged.PolicyState != "undecided" {
		t.Fatalf("TriagedApp policy_state = %q, want undecided (a tenant_new_apps triage decision is not a governance policy)", triaged.PolicyState)
	}
	if triaged.DecidedBy == nil || *triaged.DecidedBy != "ops@example.com" {
		t.Errorf("TriagedApp decided_by = %v, want ops@example.com", triaged.DecidedBy)
	}
	if triaged.DecidedAt == nil {
		t.Errorf("TriagedApp decided_at = nil, want the seeded tenant_new_apps.decided_at")
	}
	if triaged.Justification != nil {
		t.Errorf("TriagedApp justification = %v, want nil (tenant_new_apps has no free-text field)", *triaged.Justification)
	}

	untouched, ok := findPortalApplication(out.Applications, "UntouchedApp")
	if !ok {
		t.Fatalf("UntouchedApp missing from %+v", out.Applications)
	}
	if untouched.DecidedBy != nil || untouched.DecidedAt != nil || untouched.Justification != nil {
		t.Errorf("UntouchedApp provenance = decided_by=%v decided_at=%v justification=%v, want all nil (no decision record exists)",
			untouched.DecidedBy, untouched.DecidedAt, untouched.Justification)
	}
}

// TestPortalApplicationsApprovedNeverAlsoUndecided is the core
// non-conflation invariant (acceptance criterion 2): an app that matches an
// approved policy must appear exactly once, as "approved", never a second
// time as "undecided".
func TestPortalApplicationsApprovedNeverAlsoUndecided(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-approved-not-undecided")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-approved-not-undecided', gen_random_uuid(), 'host-approved-not-undecided', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'KnownGoodApp', 'any', 'approved', 'report')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'KnownGoodApp', 'com.example.knowngoodapp', '1.0.0')
	`, deviceID)
	if err != nil {
		t.Fatalf("seed device_apps: %v", err)
	}

	email := "approved-not-undecided@apps-approved-not-undecided.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/applications", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("applications = %d: %s", resp.StatusCode, b)
	}
	var out portalApplicationsOut
	decodeJSON(t, resp, &out)

	var matches int
	for _, a := range out.Applications {
		if a.Name == "KnownGoodApp" {
			matches++
			if a.PolicyState != "approved" {
				t.Errorf("KnownGoodApp row policy_state = %q, want approved", a.PolicyState)
			}
		}
	}
	if matches != 1 {
		t.Fatalf("KnownGoodApp appears %d times, want exactly 1 (never both approved and undecided)", matches)
	}
}

// TestPortalApplicationsCrossTenantIsolation asserts tenant A's undecided
// application list never includes tenant B's device counts for a
// same-named/same-identifier app — the same PAT-729-shaped leak
// TestPortalUnapprovedAppsCrossTenantSameAppName guards for the policy-row
// path, checked here for the new undecided-grouping query.
func TestPortalApplicationsCrossTenantIsolation(t *testing.T) {
	ctx := t.Context()
	tenantA, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-isolation-a")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	cleanupTestTenant(t, tenantA)
	tenantB, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-isolation-b")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}
	cleanupTestTenant(t, tenantB)

	var deviceA, deviceB string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-isolation-a', gen_random_uuid(), 'host-isolation-a', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantA).Scan(&deviceA)
	if err != nil {
		t.Fatalf("seed device A: %v", err)
	}
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-isolation-b', gen_random_uuid(), 'host-isolation-b', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantB).Scan(&deviceB)
	if err != nil {
		t.Fatalf("seed device B: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'CommonApp', 'com.example.commonapp', '1.0.0')
	`, deviceA)
	if err != nil {
		t.Fatalf("seed tenant A device_apps: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'CommonApp', 'com.example.commonapp', '1.0.0')
	`, deviceB)
	if err != nil {
		t.Fatalf("seed tenant B device_apps: %v", err)
	}

	email := "isolation-a@apps-isolation-a.example"
	mapPortalUser(t, email, tenantA, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/applications", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("applications = %d: %s", resp.StatusCode, b)
	}
	var out portalApplicationsOut
	decodeJSON(t, resp, &out)

	app, ok := findPortalApplication(out.Applications, "CommonApp")
	if !ok {
		t.Fatalf("CommonApp missing from %+v", out.Applications)
	}
	if app.DeviceCount != 1 {
		t.Errorf("device_count = %d, want 1 (tenant B's device must never be counted)", app.DeviceCount)
	}
}

// TestPortalApplicationsPlatformScoped mirrors
// TestPortalUnapprovedAppsPlatformScoped for the undecided path: a windows
// device installs an app while a tenant_app_policies row exists but is
// scoped to macos only — the windows install must NOT be swallowed by that
// policy and must surface as undecided (or, if it were incorrectly matched,
// this test catches it).
func TestPortalApplicationsPlatformScoped(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-platform")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-apps-platform', gen_random_uuid(), 'host-apps-platform', 'Windows', '11', '22H2', 'x64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'MacOnlyPolicyApp', 'macos', 'approved', 'report')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'MacOnlyPolicyApp', 'MacOnlyPolicyApp-{GUID}', '1.0.0')
	`, deviceID)
	if err != nil {
		t.Fatalf("seed device_apps: %v", err)
	}

	email := "platform@apps-platform.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/applications", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("applications = %d: %s", resp.StatusCode, b)
	}
	var out portalApplicationsOut
	decodeJSON(t, resp, &out)

	app, ok := findPortalApplication(out.Applications, "MacOnlyPolicyApp")
	if !ok {
		t.Fatalf("MacOnlyPolicyApp missing from %+v", out.Applications)
	}
	if app.PolicyState != "undecided" || app.Platform != "windows" {
		t.Errorf("MacOnlyPolicyApp row = %+v, want policy_state=undecided platform=windows "+
			"(a macos-only policy must not match a windows install)", app)
	}
	// The macos-scoped policy row's own zero-device count is already covered
	// by TestPortalUnapprovedAppsPlatformScoped in portal_test.go; this
	// test's contribution is the undecided-path platform scoping above.
}

// TestPortalApplicationsUndecidedRowCap seeds more undecided applications
// than portalApplicationsMaxUndecidedRows (lowered for the test) and asserts
// the response caps the list, reports the exact pre-cap total, and sets
// truncated.
func TestPortalApplicationsUndecidedRowCap(t *testing.T) {
	ctx := t.Context()
	restore := report.SetPortalApplicationsMaxSourceRowsForTest(100_000) // keep the source-row guard out of the way
	defer restore()

	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-rowcap")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-apps-rowcap', gen_random_uuid(), 'host-apps-rowcap', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	// 505 distinct undecided identities: over the 500-row display cap,
	// nowhere near the 100,000-row source cap.
	const seeded = 505
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		SELECT $1::uuid,
		       'rowcap-app-' || LPAD(i::text, 3, '0'),
		       'com.example.rowcap.' || LPAD(i::text, 3, '0'),
		       '1.0'
		FROM generate_series(0, $2::int - 1) AS i
	`, deviceID, seeded)
	if err != nil {
		t.Fatalf("seed device_apps: %v", err)
	}

	email := "rowcap@apps-rowcap.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/applications", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("applications = %d: %s", resp.StatusCode, b)
	}
	var out portalApplicationsOut
	decodeJSON(t, resp, &out)

	// Every new tenant is auto-seeded with a handful of first-party "Patched
	// Agent" policy rows (agentidentity.EnsurePatchedAgentPolicies, called
	// from CreateTenantHandler) — policy rows are never capped, so count
	// them separately from the undecided rows this test is actually about,
	// rather than assuming a bare tenant has zero tenant_app_policies rows.
	var policyRows, undecidedRows int
	for _, a := range out.Applications {
		if a.PolicyState == "undecided" {
			undecidedRows++
		} else {
			policyRows++
		}
	}

	if want := policyRows + seeded; out.Total != want {
		t.Errorf("total = %d, want %d (%d policy rows + %d exact pre-cap undecided count)", out.Total, want, policyRows, seeded)
	}
	if undecidedRows != 500 {
		t.Fatalf("undecided rows = %d, want exactly 500 (the undecided row cap; policy rows are never capped)", undecidedRows)
	}
	if !out.Truncated {
		t.Errorf("truncated = false, want true (%d > 500)", seeded)
	}
	if out.EstateTooLarge {
		t.Errorf("estate_too_large = true, want false (the display cap fired, not the source-row guard)")
	}
}

// TestPortalApplicationsSourceRowCap asserts the fail-closed source-row
// guard (mirroring FetchPortalExtensions' PAT-933 pre-check) degrades
// gracefully: policy rows still come back, the undecided section is empty,
// and estate_too_large distinguishes this from an ordinary tenant with no
// undecided applications.
func TestPortalApplicationsSourceRowCap(t *testing.T) {
	ctx := t.Context()
	restore := report.SetPortalApplicationsMaxSourceRowsForTest(5)
	defer restore()

	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-srccap")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-apps-srccap', gen_random_uuid(), 'host-apps-srccap', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'StillVisibleApp', 'any', 'approved', 'report')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		SELECT $1::uuid, 'srccap-app-' || i::text, 'com.example.srccap.' || i::text, '1.0'
		FROM generate_series(0, 9) AS i
	`, deviceID)
	if err != nil {
		t.Fatalf("seed device_apps: %v", err)
	}

	email := "srccap@apps-srccap.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/applications", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("applications = %d, want 200 (fail closed, not 500): %s", resp.StatusCode, b)
	}
	var out portalApplicationsOut
	decodeJSON(t, resp, &out)

	if !out.EstateTooLarge {
		t.Fatalf("estate_too_large = false, want true (10 device_apps rows > lowered cap 5)")
	}
	if !out.Truncated {
		t.Errorf("truncated = false, want true")
	}
	for _, a := range out.Applications {
		if a.PolicyState == "undecided" {
			t.Errorf("undecided row %+v present, want none while the source-row guard is fail-closed", a)
		}
	}
	if _, ok := findPortalApplication(out.Applications, "StillVisibleApp"); !ok {
		t.Errorf("StillVisibleApp (a policy row) missing — policy rows must survive the undecided fail-closed branch")
	}
}

// TestPortalApplicationsVersionSpreadAndSigningMacOS (PAT-1799) seeds an
// undecided macOS app on two devices running different versions, one of
// them carrying codesign signing evidence, and asserts version_count
// reflects the exact distinct-version count and the signing fields surface
// the observed team_id/signed_by/notarized rather than nil.
func TestPortalApplicationsVersionSpreadAndSigningMacOS(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-signing-macos")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	var deviceA, deviceB string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-signing-macos-a', gen_random_uuid(), 'host-signing-macos-a', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceA)
	if err != nil {
		t.Fatalf("seed device A: %v", err)
	}
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-signing-macos-b', gen_random_uuid(), 'host-signing-macos-b', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceB)
	if err != nil {
		t.Fatalf("seed device B: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version, team_id, signer, notarized)
		VALUES ($1::uuid, 'SignedTool', 'com.example.signedtool', '1.0.0', 'ABCDE12345', 'Developer ID Application: Example Inc', true)
	`, deviceA)
	if err != nil {
		t.Fatalf("seed device_apps A: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'SignedTool', 'com.example.signedtool', '2.0.0')
	`, deviceB)
	if err != nil {
		t.Fatalf("seed device_apps B: %v", err)
	}

	email := "signing-macos@apps-signing-macos.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/applications", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("applications = %d: %s", resp.StatusCode, b)
	}
	var out portalApplicationsOut
	decodeJSON(t, resp, &out)

	app, ok := findPortalApplication(out.Applications, "SignedTool")
	if !ok {
		t.Fatalf("SignedTool missing from %+v", out.Applications)
	}
	if app.DeviceCount != 2 || app.VersionCount != 2 {
		t.Errorf("SignedTool device_count/version_count = %d/%d, want 2/2", app.DeviceCount, app.VersionCount)
	}
	if app.TeamID == nil || *app.TeamID != "ABCDE12345" {
		t.Errorf("SignedTool team_id = %v, want ABCDE12345", app.TeamID)
	}
	if app.SignedBy == nil || *app.SignedBy != "Developer ID Application: Example Inc" {
		t.Errorf("SignedTool signed_by = %v, want %q", app.SignedBy, "Developer ID Application: Example Inc")
	}
	if app.Notarized == nil || !*app.Notarized {
		t.Errorf("SignedTool notarized = %v, want true", app.Notarized)
	}
}

// TestPortalApplicationsSigningWindowsUnknown (PAT-1799) seeds a Windows
// undecided app — including notarized=false, exactly what the current
// Windows collector path writes for a signal it never actually populates
// (see internal/extractor/upsert.go) — and asserts the signing fields read
// explicitly nil ("unknown"), never a false "unsigned"/"not notarized"
// verdict.
func TestPortalApplicationsSigningWindowsUnknown(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-signing-windows")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-signing-windows', gen_random_uuid(), 'host-signing-windows', 'Windows', '11', '22H2', 'x64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version, notarized)
		VALUES ($1::uuid, 'WinTool', 'WinTool-{GUID}', '1.0.0', false)
	`, deviceID)
	if err != nil {
		t.Fatalf("seed device_apps: %v", err)
	}

	email := "signing-windows@apps-signing-windows.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/applications", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("applications = %d: %s", resp.StatusCode, b)
	}
	var out portalApplicationsOut
	decodeJSON(t, resp, &out)

	app, ok := findPortalApplication(out.Applications, "WinTool")
	if !ok {
		t.Fatalf("WinTool missing from %+v", out.Applications)
	}
	if app.TeamID != nil || app.SignedBy != nil || app.Notarized != nil {
		t.Errorf("WinTool signing fields = team_id=%v signed_by=%v notarized=%v, want all nil (unknown)",
			app.TeamID, app.SignedBy, app.Notarized)
	}
}

// TestPortalApplicationsPolicyRowSigningAndVersionSpread (PAT-1799) asserts
// version_count/signing are also populated on policy rows (not just
// undecided ones), sourced from the matched device_apps evidence: a policy
// scoped "any" matches one macOS device (carrying signing evidence) and one
// Windows device, and the row's signing fields must reflect the macOS
// evidence, not be nulled out just because a Windows device also matched.
func TestPortalApplicationsPolicyRowSigningAndVersionSpread(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-policy-signing")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	var macDevice, winDevice string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-policy-signing-mac', gen_random_uuid(), 'host-policy-signing-mac', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&macDevice)
	if err != nil {
		t.Fatalf("seed macOS device: %v", err)
	}
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-policy-signing-win', gen_random_uuid(), 'host-policy-signing-win', 'Windows', '11', '22H2', 'x64', now())
		RETURNING id::text
	`, tenantID).Scan(&winDevice)
	if err != nil {
		t.Fatalf("seed windows device: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'com.example.approvedtool', 'ApprovedSignedTool', 'any', 'approved', 'report')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version, team_id, signer, notarized)
		VALUES ($1::uuid, 'ApprovedSignedTool', 'com.example.approvedtool', '3.0.0', 'TEAMID9999', 'Developer ID Application: Approved Co', true)
	`, macDevice)
	if err != nil {
		t.Fatalf("seed macOS device_apps: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'ApprovedSignedTool', 'com.example.approvedtool', '4.0.0')
	`, winDevice)
	if err != nil {
		t.Fatalf("seed windows device_apps: %v", err)
	}

	email := "policy-signing@apps-policy-signing.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/applications", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("applications = %d: %s", resp.StatusCode, b)
	}
	var out portalApplicationsOut
	decodeJSON(t, resp, &out)

	app, ok := findPortalApplication(out.Applications, "ApprovedSignedTool")
	if !ok {
		t.Fatalf("ApprovedSignedTool missing from %+v", out.Applications)
	}
	if app.DeviceCount != 2 || app.VersionCount != 2 {
		t.Errorf("ApprovedSignedTool device_count/version_count = %d/%d, want 2/2", app.DeviceCount, app.VersionCount)
	}
	if app.TeamID == nil || *app.TeamID != "TEAMID9999" {
		t.Errorf("ApprovedSignedTool team_id = %v, want TEAMID9999 (from the macOS-matched device only)", app.TeamID)
	}
	if app.Notarized == nil || !*app.Notarized {
		t.Errorf("ApprovedSignedTool notarized = %v, want true (must not be nulled out by the also-matched Windows device)", app.Notarized)
	}
}

// TestPortalApplicationsUnauthenticated asserts the new route sits behind
// the same portalauth.Middleware as every other /v1/portal/* route.
func TestPortalApplicationsUnauthenticated(t *testing.T) {
	resp := portalDo(t, http.MethodGet, "/v1/portal/applications", "", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// cleanupCatalogEntry deletes a seeded app_catalog_entries row by its
// (globally unique) label. Not covered by cleanupTestTenant's cascade —
// app_catalog_entries has no tenant_id, it is a global product catalogue —
// so every test that seeds one must clean it up itself, or it leaks into
// every later test's catalog matching within the same CI run.
func cleanupCatalogEntry(t *testing.T, label string) {
	t.Helper()
	t.Cleanup(func() {
		if _, err := env.pool.Exec(context.Background(),
			`DELETE FROM app_catalog_entries WHERE label = $1`, label); err != nil {
			t.Errorf("cleanup catalog entry %s: %v", label, err)
		}
	})
}

// TestPortalApplicationsCatalogGapBehindCount (PAT-1728) covers three
// acceptance criteria in one seed: an approved, catalog-matched product with
// one device behind and one current only counts the behind device, and the
// comparison is real semantic version comparison, not string comparison —
// "9.0.0" strictly precedes "10.0.0" numerically but would sort AFTER it as
// a string (the SQL "da.version < ace.latest_version" needs_attention.go
// itself uses would get this backwards), so if this test passes on a naive
// string-comparison implementation, that implementation is wrong. An
// unapproved policy row on the same tenant asserts the PAT-1728 scope
// boundary: catalog gaps are never computed for non-approved/mandatory rows.
func TestPortalApplicationsCatalogGapBehindCount(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-catalog-gap")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)
	cleanupCatalogEntry(t, "pat1728-catalogapp")

	_, err = env.pool.Exec(ctx, `
		INSERT INTO app_catalog_entries (label, name, category, platform, verified_signer, latest_version, verified_at)
		VALUES ('pat1728-catalogapp', 'CatalogApp', 'Productivity', 'macOS', NULL, '10.0.0', now())
	`)
	if err != nil {
		t.Fatalf("seed catalog entry: %v", err)
	}

	var deviceBehind, deviceCurrent string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-catalog-gap-behind', gen_random_uuid(), 'host-catalog-gap-behind', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceBehind)
	if err != nil {
		t.Fatalf("seed behind device: %v", err)
	}
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-catalog-gap-current', gen_random_uuid(), 'host-catalog-gap-current', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceCurrent)
	if err != nil {
		t.Fatalf("seed current device: %v", err)
	}

	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'CatalogApp', 'any', 'approved', 'report'),
		       ($1::uuid, 'UnapprovedCatalogApp', 'any', 'unapproved', 'app_management')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed policies: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'CatalogApp', 'com.example.catalogapp', '9.0.0')
	`, deviceBehind)
	if err != nil {
		t.Fatalf("seed behind device_apps: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'CatalogApp', 'com.example.catalogapp', '10.0.0')
	`, deviceCurrent)
	if err != nil {
		t.Fatalf("seed current device_apps: %v", err)
	}
	// The unapproved policy also gets a matching device so its device_count
	// is non-zero — proving its null catalog fields are a scope decision,
	// not just "no devices to compute from".
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'UnapprovedCatalogApp', 'com.example.unapprovedcatalogapp', '1.0.0')
	`, deviceBehind)
	if err != nil {
		t.Fatalf("seed unapproved device_apps: %v", err)
	}

	email := "catalog-gap@apps-catalog-gap.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/applications", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("applications = %d: %s", resp.StatusCode, b)
	}
	var out portalApplicationsOut
	decodeJSON(t, resp, &out)

	app, ok := findPortalApplication(out.Applications, "CatalogApp")
	if !ok {
		t.Fatalf("CatalogApp missing from %+v", out.Applications)
	}
	if app.DeviceCount != 2 {
		t.Fatalf("CatalogApp device_count = %d, want 2", app.DeviceCount)
	}
	if app.LatestKnownVersion == nil || *app.LatestKnownVersion != "10.0.0" {
		t.Errorf("CatalogApp latest_known_version = %v, want 10.0.0", app.LatestKnownVersion)
	}
	if app.DevicesBehindCount == nil || *app.DevicesBehindCount != 1 {
		t.Errorf("CatalogApp devices_behind_count = %v, want 1 (only the 9.0.0 device, not the 10.0.0 one; "+
			"a string comparison would wrongly read \"9.0.0\" as newer than \"10.0.0\" and report 0)", app.DevicesBehindCount)
	}

	unapproved, ok := findPortalApplication(out.Applications, "UnapprovedCatalogApp")
	if !ok {
		t.Fatalf("UnapprovedCatalogApp missing from %+v", out.Applications)
	}
	if unapproved.LatestKnownVersion != nil || unapproved.DevicesBehindCount != nil {
		t.Errorf("UnapprovedCatalogApp catalog fields = latest=%v behind=%v, want both nil "+
			"(catalog gaps are only computed for approved/mandatory rows)",
			unapproved.LatestKnownVersion, unapproved.DevicesBehindCount)
	}
}

// TestPortalApplicationsCatalogGapJavaUpdateTail (PAT-2044): Java versions
// carry the update number after an underscore. 1.8.0_391 is behind
// 1.8.0_401, although the two share the leading numbers 1.8.0: the version
// order must still read the digits after the underscore.
func TestPortalApplicationsCatalogGapJavaUpdateTail(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-catalog-gap-java")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)
	cleanupCatalogEntry(t, "pat2044-java8")

	if _, err := env.pool.Exec(ctx, `
		INSERT INTO app_catalog_entries (label, name, category, platform, verified_signer, latest_version, verified_at)
		VALUES ('pat2044-java8', 'Pat2044 Java 8', 'Developer Tools', 'macOS', NULL, '1.8.0_401', now())
	`); err != nil {
		t.Fatalf("seed catalog entry: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'Pat2044 Java 8', 'any', 'approved', 'report')
	`, tenantID); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	for _, d := range []struct{ tag, version string }{{"behind", "1.8.0_391"}, {"current", "1.8.0_401"}} {
		var deviceID string
		if err := env.pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
			VALUES ($1::uuid, $2, gen_random_uuid(), $3, 'macOS', '15.5', '24F74', 'arm64', now())
			RETURNING id::text
		`, tenantID, "SER-pat2044-java-"+d.tag, "host-pat2044-java-"+d.tag).Scan(&deviceID); err != nil {
			t.Fatalf("seed %s device: %v", d.tag, err)
		}
		if _, err := env.pool.Exec(ctx, `
			INSERT INTO device_apps (device_id, name, identifier, version)
			VALUES ($1::uuid, 'Pat2044 Java 8', 'com.oracle.java.pat2044', $2)
		`, deviceID, d.version); err != nil {
			t.Fatalf("seed %s device_apps: %v", d.tag, err)
		}
	}

	email := "catalog-gap-java@apps-catalog-gap.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	resp := portalDo(t, http.MethodGet, "/v1/portal/applications", env.idp.token(t, email), nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("applications = %d: %s", resp.StatusCode, b)
	}
	var out portalApplicationsOut
	decodeJSON(t, resp, &out)
	app, ok := findPortalApplication(out.Applications, "Pat2044 Java 8")
	if !ok {
		t.Fatalf("Java missing from %+v", out.Applications)
	}
	if app.LatestKnownVersion == nil || *app.LatestKnownVersion != "1.8.0_401" {
		t.Errorf("latest_known_version = %v, want 1.8.0_401", app.LatestKnownVersion)
	}
	if app.DevicesBehindCount == nil || *app.DevicesBehindCount != 1 {
		t.Errorf("devices_behind_count = %v, want 1 (the 1.8.0_391 device is behind 1.8.0_401)", app.DevicesBehindCount)
	}
}

// TestPortalApplicationsCatalogGapNoMatch (PAT-1728) asserts the evidence
// rule: an approved, catalog-matched-by-nothing product returns null for
// both latest_known_version and devices_behind_count, never a guessed 0 —
// 0 is a real, confident "nothing is behind" answer and must stay
// distinguishable from "we have no catalog evidence for this product".
func TestPortalApplicationsCatalogGapNoMatch(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-catalog-gap-nomatch")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-catalog-gap-nomatch', gen_random_uuid(), 'host-catalog-gap-nomatch', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'NoCatalogEntryApp', 'any', 'approved', 'report')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'NoCatalogEntryApp', 'com.example.nocatalogentryapp', '1.0.0')
	`, deviceID)
	if err != nil {
		t.Fatalf("seed device_apps: %v", err)
	}

	email := "catalog-gap-nomatch@apps-catalog-gap-nomatch.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/applications", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("applications = %d: %s", resp.StatusCode, b)
	}
	var out portalApplicationsOut
	decodeJSON(t, resp, &out)

	app, ok := findPortalApplication(out.Applications, "NoCatalogEntryApp")
	if !ok {
		t.Fatalf("NoCatalogEntryApp missing from %+v", out.Applications)
	}
	if app.DeviceCount != 1 {
		t.Fatalf("NoCatalogEntryApp device_count = %d, want 1", app.DeviceCount)
	}
	if app.LatestKnownVersion != nil {
		t.Errorf("NoCatalogEntryApp latest_known_version = %v, want nil (no matching app_catalog_entries row)", app.LatestKnownVersion)
	}
	if app.DevicesBehindCount != nil {
		t.Errorf("NoCatalogEntryApp devices_behind_count = %v, want nil, not a guessed 0", app.DevicesBehindCount)
	}
}
