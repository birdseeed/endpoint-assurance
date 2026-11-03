//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

// PAT-1726: GET /v1/portal/unapproved-apps and GET /v1/portal/extensions
// carry a removal_state field so a buyer can see whether removal of a
// not-wanted product has been requested, is in progress, or is done,
// instead of only that the product is unwanted. These tests are the
// DB-backed proof for the derivation rules documented in
// contracts/portal-api.md.

// seedExtensionForRemovalState creates one tenant with one device running
// one extension (extension_id "rm-ext", browser "chrome"), returns the
// tenant ID and device ID.
func seedExtensionForRemovalState(t *testing.T, suffix string) (tenantID, deviceID string) {
	t.Helper()
	ctx := context.Background()
	var err error
	tenantID, _, _, err = createTestTenant(env.internalSrv.URL, "portal-rmstate-"+suffix)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, $2, gen_random_uuid(), $3, 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID, "SER-rmstate-"+suffix, "host-rmstate-"+suffix).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_browser_extensions
			(device_id, browser, user_account, profile, extension_id, name, version, risk_level)
		VALUES ($1::uuid, 'chrome', 'andy', 'Default', 'rm-ext', 'RemovalStateExt', '1.0', 'normal')
	`, deviceID)
	if err != nil {
		t.Fatalf("seed extension: %v", err)
	}
	return tenantID, deviceID
}

// seedRemovalRequest inserts a tenant_extension_removal_requests row plus
// its (single) tenant_extension_removal_targets row, mirroring what
// TenantExtensionRemovalCreateHandler does at request time (PAT-1169
// captures targets synchronously — see extension_removals.go). Returns the
// request ID.
func seedRemovalRequest(t *testing.T, tenantID, deviceID string, cancelled bool) int64 {
	t.Helper()
	ctx := context.Background()
	var requestID int64
	err := env.pool.QueryRow(ctx, `
		INSERT INTO tenant_extension_removal_requests
			(tenant_id, browser, extension_id, scope, requested_by, requested_at, fulfilled, cancelled_at)
		VALUES ($1::uuid, 'chrome', 'rm-ext', 'all_devices', 'integration', NOW(),
		        FALSE, CASE WHEN $2 THEN NOW() ELSE NULL END)
		RETURNING id
	`, tenantID, cancelled).Scan(&requestID)
	if err != nil {
		t.Fatalf("seed removal request: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_extension_removal_targets (request_id, device_id, user_account, profile)
		VALUES ($1, $2::uuid, 'andy', 'Default')
	`, requestID, deviceID)
	if err != nil {
		t.Fatalf("seed removal target: %v", err)
	}
	return requestID
}

// completeRemovalTarget marks the request's one seeded target completed
// with verified evidence: a real enforcement_audit row (event_type
// extension_removed) plus completed_at/audit_event_id on the target,
// exactly what applyExtensionRemovalEvidence (enforcement_audit.go) writes
// from a real, non-dry-run extension_removed audit event.
func completeRemovalTarget(t *testing.T, tenantID, deviceID string, requestID int64) {
	t.Helper()
	ctx := context.Background()
	var auditID string
	err := env.pool.QueryRow(ctx, `
		INSERT INTO enforcement_audit (tenant_id, device_id, event_type, subject, details, occurred_at)
		VALUES ($1::uuid, $2, 'extension_removed', 'rm-ext', '{}'::jsonb, NOW())
		RETURNING id::text
	`, tenantID, deviceID).Scan(&auditID)
	if err != nil {
		t.Fatalf("seed enforcement_audit: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		UPDATE tenant_extension_removal_targets
		SET completed_at = NOW(), audit_event_id = $1::uuid
		WHERE request_id = $2 AND device_id = $3::uuid
	`, auditID, requestID, deviceID)
	if err != nil {
		t.Fatalf("complete removal target: %v", err)
	}
	// Mirror applyExtensionRemovalEvidence: a request only becomes
	// fulfilled once every one of its targets has completed.
	var incomplete int
	if err := env.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM tenant_extension_removal_targets
		WHERE request_id = $1 AND completed_at IS NULL
	`, requestID).Scan(&incomplete); err != nil {
		t.Fatalf("count incomplete targets: %v", err)
	}
	if incomplete == 0 {
		_, err = env.pool.Exec(ctx, `
			UPDATE tenant_extension_removal_requests SET fulfilled = TRUE, fulfilled_at = NOW()
			WHERE id = $1
		`, requestID)
		if err != nil {
			t.Fatalf("mark request fulfilled: %v", err)
		}
	}
}

type removalStateExtensionRow struct {
	ExtensionID             string `json:"extension_id"`
	RemovalState            string `json:"removal_state"`
	RemovalTargetsTotal     int    `json:"removal_targets_total"`
	RemovalTargetsCompleted int    `json:"removal_targets_completed"`
	DeviceCount             int    `json:"device_count"`
	Devices                 []struct {
		DeviceID string `json:"device_id"`
		Hostname string `json:"hostname"`
	} `json:"devices"`
}

func fetchExtensionRemovalRow(t *testing.T, tenantID string) removalStateExtensionRow {
	t.Helper()
	email := fmt.Sprintf("rmstate-%s@example.com", tenantID)
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/extensions", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("extensions = %d", resp.StatusCode)
	}
	var out struct {
		Extensions []removalStateExtensionRow `json:"extensions"`
	}
	decodeJSON(t, resp, &out)
	if len(out.Extensions) != 1 {
		t.Fatalf("extensions = %+v, want exactly one row", out.Extensions)
	}
	return out.Extensions[0]
}

func TestPortalExtensionsRemovalStateNotRequested(t *testing.T) {
	tenantID, _ := seedExtensionForRemovalState(t, "none")
	row := fetchExtensionRemovalRow(t, tenantID)
	if row.RemovalState != "not_requested" {
		t.Errorf("removal_state = %q, want not_requested (no removal request seeded)", row.RemovalState)
	}
	if row.RemovalTargetsTotal != 0 || row.RemovalTargetsCompleted != 0 {
		t.Errorf("removal target counts = %d/%d, want 0/0", row.RemovalTargetsCompleted, row.RemovalTargetsTotal)
	}
}

func TestPortalExtensionsRemovalStateRequested(t *testing.T) {
	tenantID, deviceID := seedExtensionForRemovalState(t, "req")
	seedRemovalRequest(t, tenantID, deviceID, false)

	row := fetchExtensionRemovalRow(t, tenantID)
	if row.RemovalState != "requested" {
		t.Errorf("removal_state = %q, want requested (active request, zero completions)", row.RemovalState)
	}
	if row.RemovalTargetsTotal != 1 || row.RemovalTargetsCompleted != 0 {
		t.Errorf("removal target counts = %d/%d, want 0/1", row.RemovalTargetsCompleted, row.RemovalTargetsTotal)
	}
}

// TestPortalExtensionsRemovalStateRequestedWithZeroTargets is the
// defence-in-depth regression test for portalExtensionsRemovalJoin's LEFT
// JOIN to tenant_extension_removal_targets. The admin create handler
// (internal/handlers/extension_removals.go:310-314) never actually commits
// a request with zero captured targets, so this seeds one directly with
// SQL to exercise the read-side guarantee on its own: an active request
// that happens to have no target rows at all must still read "requested",
// never "not_requested" — the request is real, and reporting it as absent
// would hide a live directive from the customer.
func TestPortalExtensionsRemovalStateRequestedWithZeroTargets(t *testing.T) {
	tenantID, _ := seedExtensionForRemovalState(t, "zero-targets")
	ctx := context.Background()

	var requestID int64
	err := env.pool.QueryRow(ctx, `
		INSERT INTO tenant_extension_removal_requests
			(tenant_id, browser, extension_id, scope, requested_by, requested_at, fulfilled)
		VALUES ($1::uuid, 'chrome', 'rm-ext', 'all_devices', 'integration', NOW(), FALSE)
		RETURNING id
	`, tenantID).Scan(&requestID)
	if err != nil {
		t.Fatalf("seed zero-target removal request: %v", err)
	}
	// Deliberately no INSERT into tenant_extension_removal_targets.

	row := fetchExtensionRemovalRow(t, tenantID)
	if row.RemovalState != "requested" {
		t.Errorf("removal_state = %q, want requested (active request exists with zero captured targets)", row.RemovalState)
	}
	if row.RemovalTargetsTotal != 0 || row.RemovalTargetsCompleted != 0 {
		t.Errorf("removal target counts = %d/%d, want 0/0", row.RemovalTargetsCompleted, row.RemovalTargetsTotal)
	}
}

func TestPortalExtensionsRemovalStateInProgress(t *testing.T) {
	tenantID, deviceA := seedExtensionForRemovalState(t, "prog")
	ctx := context.Background()
	// Add a second target device with the same extension so one request
	// captures two targets, only one of which completes.
	var deviceB string
	err := env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-rmstate-prog-b', gen_random_uuid(), 'host-rmstate-prog-b', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceB)
	if err != nil {
		t.Fatalf("seed second device: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_browser_extensions
			(device_id, browser, user_account, profile, extension_id, name, version, risk_level)
		VALUES ($1::uuid, 'chrome', 'andy', 'Default', 'rm-ext', 'RemovalStateExt', '1.0', 'normal')
	`, deviceB)
	if err != nil {
		t.Fatalf("seed second extension row: %v", err)
	}

	var requestID int64
	err = env.pool.QueryRow(ctx, `
		INSERT INTO tenant_extension_removal_requests
			(tenant_id, browser, extension_id, scope, requested_by, requested_at, fulfilled)
		VALUES ($1::uuid, 'chrome', 'rm-ext', 'all_devices', 'integration', NOW(), FALSE)
		RETURNING id
	`, tenantID).Scan(&requestID)
	if err != nil {
		t.Fatalf("seed removal request: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_extension_removal_targets (request_id, device_id, user_account, profile)
		VALUES ($1, $2::uuid, 'andy', 'Default'), ($1, $3::uuid, 'andy', 'Default')
	`, requestID, deviceA, deviceB)
	if err != nil {
		t.Fatalf("seed removal targets: %v", err)
	}

	// Complete only deviceA's target; deviceB's stays open.
	completeRemovalTarget(t, tenantID, deviceA, requestID)

	row := fetchExtensionRemovalRow(t, tenantID)
	if row.RemovalState != "in_progress" {
		t.Errorf("removal_state = %q, want in_progress (1 of 2 targets completed)", row.RemovalState)
	}
	if row.RemovalTargetsTotal != 2 || row.RemovalTargetsCompleted != 1 {
		t.Errorf("removal target counts = %d/%d, want 1/2", row.RemovalTargetsCompleted, row.RemovalTargetsTotal)
	}
}

// TestPortalExtensionsRemovalStateCompleted: every target captured by the
// (single-device) request completes with verified evidence, so the row
// reads "removal_completed". This tenant seeds only one device total, so
// the extension also happens to be gone from the estate here — but that is
// incidental to this test, not what removal_completed asserts. See
// TestPortalExtensionsRemovalStateCompletedButStillInstalledElsewhere for
// the case where a completed scope does NOT mean the estate is clean.
func TestPortalExtensionsRemovalStateCompleted(t *testing.T) {
	tenantID, deviceID := seedExtensionForRemovalState(t, "done")
	requestID := seedRemovalRequest(t, tenantID, deviceID, false)
	completeRemovalTarget(t, tenantID, deviceID, requestID)

	row := fetchExtensionRemovalRow(t, tenantID)
	if row.RemovalState != "removal_completed" {
		t.Errorf("removal_state = %q, want removal_completed (every captured target completed with verified evidence)", row.RemovalState)
	}
	if row.RemovalTargetsTotal != 1 || row.RemovalTargetsCompleted != 1 {
		t.Errorf("removal target counts = %d/%d, want 1/1", row.RemovalTargetsCompleted, row.RemovalTargetsTotal)
	}
}

// TestPortalExtensionsRemovalStateCompletedButStillInstalledElsewhere is the
// PAT-1726 semantic-fix regression test: "removal_completed" must never be
// read as "gone from the estate". A removal request scoped narrowly (here,
// one_profile on deviceA) completes on the one target it captured, but a
// second device (deviceB) has the same extension installed and was never
// part of that request's scope. The row must still appear (extension rows
// come from current inventory, not from removal history), read
// "removal_completed" (the captured scope genuinely completed), and its
// device_count/devices must show the remaining install — the portal's only
// honest signal that the extension is not actually gone.
func TestPortalExtensionsRemovalStateCompletedButStillInstalledElsewhere(t *testing.T) {
	tenantID, deviceA := seedExtensionForRemovalState(t, "partial-scope")
	ctx := context.Background()

	var deviceB string
	err := env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-rmstate-partial-scope-b', gen_random_uuid(), 'host-rmstate-partial-scope-b', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceB)
	if err != nil {
		t.Fatalf("seed second device: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_browser_extensions
			(device_id, browser, user_account, profile, extension_id, name, version, risk_level)
		VALUES ($1::uuid, 'chrome', 'someone-else', 'Default', 'rm-ext', 'RemovalStateExt', '1.0', 'normal')
	`, deviceB)
	if err != nil {
		t.Fatalf("seed second extension row: %v", err)
	}

	// Request scoped to deviceA/"andy"/"Default" only (one_profile) — never
	// captures deviceB's install, which belongs to a different user account.
	var requestID int64
	err = env.pool.QueryRow(ctx, `
		INSERT INTO tenant_extension_removal_requests
			(tenant_id, browser, extension_id, scope, user_account, profile, requested_by, requested_at, fulfilled)
		VALUES ($1::uuid, 'chrome', 'rm-ext', 'one_profile', 'andy', 'Default', 'integration', NOW(), FALSE)
		RETURNING id
	`, tenantID).Scan(&requestID)
	if err != nil {
		t.Fatalf("seed removal request: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_extension_removal_targets (request_id, device_id, user_account, profile)
		VALUES ($1, $2::uuid, 'andy', 'Default')
	`, requestID, deviceA)
	if err != nil {
		t.Fatalf("seed removal target: %v", err)
	}

	completeRemovalTarget(t, tenantID, deviceA, requestID)

	// Simulate deviceA's next inventory upload after the verified removal:
	// it no longer reports the extension. deviceB's row is untouched — it
	// was never in the request's scope and still has it installed. Without
	// this delete, the ident CTE would still see two currently-installed
	// rows and device_count would misleadingly stay 2.
	_, err = env.pool.Exec(ctx, `
		DELETE FROM device_browser_extensions
		WHERE device_id = $1::uuid AND extension_id = 'rm-ext' AND browser = 'chrome'
	`, deviceA)
	if err != nil {
		t.Fatalf("simulate post-removal inventory for deviceA: %v", err)
	}

	row := fetchExtensionRemovalRow(t, tenantID)
	if row.RemovalState != "removal_completed" {
		t.Errorf("removal_state = %q, want removal_completed (the one captured target completed)", row.RemovalState)
	}
	if row.RemovalTargetsTotal != 1 || row.RemovalTargetsCompleted != 1 {
		t.Errorf("removal target counts = %d/%d, want 1/1", row.RemovalTargetsCompleted, row.RemovalTargetsTotal)
	}
	if row.DeviceCount != 1 {
		t.Errorf("device_count = %d, want 1 (deviceB still has the extension installed, outside the completed request's scope)", row.DeviceCount)
	}
	foundDeviceB := false
	for _, d := range row.Devices {
		if d.DeviceID == deviceB {
			foundDeviceB = true
		}
		if d.DeviceID == deviceA {
			t.Errorf("devices = %+v, deviceA should no longer be reporting the extension in inventory", row.Devices)
		}
	}
	if !foundDeviceB {
		t.Errorf("devices = %+v, want deviceB present — removal_completed must not read as the extension being gone from the estate", row.Devices)
	}
}

// TestPortalExtensionsRemovalStateCancelledFoldsToNotRequested: a
// cancelled-only removal history must never render as "removal_completed"
// or "requested" — root AGENTS.md "absence requires authority" plus the
// create-handler's active-request unique index (a cancelled request never
// blocks requesting again) make "not_requested" the honest customer-facing
// state. See extensionRemovalState's doc comment (internal/report/portal_extensions.go).
func TestPortalExtensionsRemovalStateCancelledFoldsToNotRequested(t *testing.T) {
	tenantID, deviceID := seedExtensionForRemovalState(t, "cancel")
	seedRemovalRequest(t, tenantID, deviceID, true)

	row := fetchExtensionRemovalRow(t, tenantID)
	if row.RemovalState != "not_requested" {
		t.Errorf("removal_state = %q, want not_requested (only a cancelled request exists)", row.RemovalState)
	}
}

// TestPortalExtensionsRemovalStateCrossTenantIsolation proves a removal
// request queued in tenant B never leaks into tenant A's row for the same
// (extension_id, browser) pair — the removal LATERAL join in
// portalExtensionsQuery filters on r.tenant_id = $1::uuid, same as every
// other tenant-scoped join in this query.
func TestPortalExtensionsRemovalStateCrossTenantIsolation(t *testing.T) {
	tenantA, _ := seedExtensionForRemovalState(t, "iso-a")
	tenantB, deviceB := seedExtensionForRemovalState(t, "iso-b")
	requestID := seedRemovalRequest(t, tenantB, deviceB, false)
	completeRemovalTarget(t, tenantB, deviceB, requestID)

	rowA := fetchExtensionRemovalRow(t, tenantA)
	if rowA.RemovalState != "not_requested" {
		t.Errorf("CROSS-TENANT LEAK: tenant A removal_state = %q, want not_requested (tenant B's request/completion must not be visible)", rowA.RemovalState)
	}

	rowB := fetchExtensionRemovalRow(t, tenantB)
	if rowB.RemovalState != "removal_completed" {
		t.Errorf("tenant B removal_state = %q, want removal_completed (its own request completed)", rowB.RemovalState)
	}
}

// TestPortalUnapprovedAppsRemovalStateNotAvailable: PAT-1598's
// authorised-removal campaign records carry no delivery pathway and do not
// feed this endpoint, so every row must read "not_available" — never
// "not_requested", which would misrepresent an absent capability as an
// available-but-unused one.
func TestPortalUnapprovedAppsRemovalStateNotAvailable(t *testing.T) {
	ctx := context.Background()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-rmstate-apps")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-rmstate-app', gen_random_uuid(), 'host-rmstate-app', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'NotWantedApp', 'any', 'unapproved', 'app_management')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed unapproved policy: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'NotWantedApp', 'com.example.notwanted', '1.0.0')
	`, deviceID)
	if err != nil {
		t.Fatalf("seed device_apps: %v", err)
	}

	email := "rmstate-apps@example.com"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/unapproved-apps", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unapproved-apps = %d", resp.StatusCode)
	}
	var out struct {
		Apps []struct {
			AppName      string `json:"app_name"`
			RemovalState string `json:"removal_state"`
		} `json:"apps"`
	}
	decodeJSON(t, resp, &out)
	if len(out.Apps) != 1 {
		t.Fatalf("apps = %+v, want exactly one row", out.Apps)
	}
	if out.Apps[0].RemovalState != "not_available" {
		t.Errorf("removal_state = %q, want not_available (no application-removal pathway exists)", out.Apps[0].RemovalState)
	}
}
