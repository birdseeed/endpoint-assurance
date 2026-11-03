//go:build integration

package integration

// PAT-2294: the portal reported "Update state not reported" for every Windows
// device because GET /v1/portal/devices read patch_pending only from
// devices.pending_updates, which the Windows agent never populates. The agent
// sends an os_update verdict instead (stored in device_os_update). These
// tests drive the real portal routes against seeded rows and lock:
//
//   - the roster falls back to the device_os_update verdict when
//     pending_updates is NULL, and a stale or unrecognised verdict never
//     reads as a real answer;
//   - an explicit OS verdict takes precedence over pending_updates,
//     including unknown and stale verdicts; legacy arrays apply only without a row;
//   - GET /v1/portal/devices/{id} carries encryption_ok, patch_pending and
//     findings_open, equal to the same device's roster row.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"
)

type osUpdateSeed struct {
	state string
	// checkedAt nil stores SQL NULL (a row written before migration 0147).
	checkedAt  *time.Time
	reportedAt time.Time
}

type updateStateCase struct {
	hostname       string
	os             string
	pendingUpdates string // SQL literal for devices.pending_updates
	osUpdate       *osUpdateSeed
	want           *bool // expected roster and detail patch_pending
}

func tp(b bool) *bool { return &b }

func tptr(t time.Time) *time.Time { return &t }

// updateStateRosterRow decodes only the fields this ticket concerns.
type updateStateRosterRow struct {
	DeviceID     string `json:"device_id"`
	Hostname     string `json:"hostname"`
	FindingsOpen *int   `json:"findings_open"`
	EncryptionOK *bool  `json:"encryption_ok"`
	PatchPending *bool  `json:"patch_pending"`
}

func updateStateCases(now time.Time) []updateStateCase {
	fresh := now.Add(-time.Hour)
	stale := now.Add(-8 * 24 * time.Hour)
	return []updateStateCase{
		// Windows, pending_updates NULL: the verdict decides.
		{"win-behind", "Windows", "NULL", &osUpdateSeed{"update_required", tptr(fresh), fresh}, tp(true)},
		{"win-current", "Windows", "NULL", &osUpdateSeed{"up_to_date", tptr(fresh), fresh}, tp(false)},
		{"win-recommended", "Windows", "NULL", &osUpdateSeed{"update_recommended", tptr(fresh), fresh}, tp(true)},
		{"win-deadline", "Windows", "NULL", &osUpdateSeed{"deadline_passed", tptr(fresh), fresh}, tp(true)},
		{"win-unsupported", "Windows", "NULL", &osUpdateSeed{"unsupported_hardware", tptr(fresh), fresh}, tp(true)},
		// The agent could not tell, or a future agent sent a state this
		// server does not know: neither is a claim either way.
		{"win-unknown", "Windows", "NULL", &osUpdateSeed{"unknown", tptr(fresh), fresh}, nil},
		{"win-novel-state", "Windows", "NULL", &osUpdateSeed{"restart_pending_maybe", tptr(fresh), fresh}, nil},
		// Never reported at all.
		{"win-no-row", "Windows", "NULL", nil, nil},
		// (c) Older than the roster's evidence freshness window.
		{"win-stale", "Windows", "NULL", &osUpdateSeed{"update_required", tptr(stale), stale}, nil},
		{"win-stale-current", "Windows", "NULL", &osUpdateSeed{"up_to_date", tptr(stale), stale}, nil},
		// An old verdict the agent re-uploaded recently: reported_at is
		// fresh but the verdict is not.
		{"win-cached-verdict", "Windows", "NULL", &osUpdateSeed{"update_required", tptr(stale), fresh}, nil},
		// A row from before checked_at existed falls back to reported_at.
		{"win-legacy-fresh", "Windows", "NULL", &osUpdateSeed{"update_required", nil, fresh}, tp(true)},
		{"win-legacy-stale", "Windows", "NULL", &osUpdateSeed{"update_required", nil, stale}, nil},
		// A fast agent clock: the verdict cannot be newer than its receipt.
		{"win-clock-ahead", "Windows", "NULL", &osUpdateSeed{"update_required", tptr(now.Add(10 * time.Minute)), now.Add(-time.Minute)}, tp(true)},
		// A wildly future checked_at cannot keep an old receipt fresh.
		{"win-clock-far-ahead", "Windows", "NULL", &osUpdateSeed{"up_to_date", tptr(now.Add(30 * 24 * time.Hour)), stale}, nil},
		// PAT-2338: explicit OS evidence wins over conflicting legacy arrays.
		{"mac-pending", "macOS", `'[{"name":"Safari"}]'::jsonb`, &osUpdateSeed{"up_to_date", tptr(fresh), fresh}, tp(false)},
		{"mac-empty", "macOS", `'[]'::jsonb`, &osUpdateSeed{"update_required", tptr(fresh), fresh}, tp(true)},
		{"mac-null-no-row", "macOS", "NULL", nil, nil},
		{"mac-empty-unknown", "macOS", `'[]'::jsonb`, &osUpdateSeed{"unknown", tptr(fresh), fresh}, nil},
		{"mac-empty-unavailable", "macOS", `'[]'::jsonb`, &osUpdateSeed{"unavailable", tptr(fresh), fresh}, nil},
		{"mac-empty-stale", "macOS", `'[]'::jsonb`, &osUpdateSeed{"up_to_date", tptr(stale), fresh}, nil},
		{"mac-pending-stale", "macOS", `'[{"name":"Safari"}]'::jsonb`, &osUpdateSeed{"update_required", tptr(fresh), stale}, nil},
		{"win-empty-unknown", "Windows", `'[]'::jsonb`, &osUpdateSeed{"unknown", tptr(fresh), fresh}, nil},
		{"win-empty-pending", "Windows", `'[]'::jsonb`, &osUpdateSeed{"update_required", tptr(fresh), fresh}, tp(true)},
		{"mac-legacy-empty", "macOS", `'[]'::jsonb`, nil, tp(false)},
		{"mac-legacy-pending", "macOS", `'[{"name":"Safari"}]'::jsonb`, nil, tp(true)},
	}
}

type updateStateFixture struct {
	token     string
	deviceIDs map[string]string // hostname -> device id
	cases     []updateStateCase
}

func seedUpdateStateTenant(t *testing.T, name string) updateStateFixture {
	t.Helper()
	ctx := context.Background()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, name)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)
	email := "viewer@" + name + ".example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)

	now := time.Now().UTC()
	fx := updateStateFixture{
		token:     env.idp.token(t, email),
		deviceIDs: map[string]string{},
		cases:     updateStateCases(now),
	}
	for _, tc := range fx.cases {
		var deviceID string
		err := env.pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen, pending_updates)
			VALUES ($1::uuid, $2, gen_random_uuid(), $2, $3, '15.5', '24F74', 'arm64', $4, `+tc.pendingUpdates+`)
			RETURNING id::text
		`, tenantID, tc.hostname, tc.os, now.Add(-time.Minute)).Scan(&deviceID)
		if err != nil {
			t.Fatalf("seed device %s: %v", tc.hostname, err)
		}
		fx.deviceIDs[tc.hostname] = deviceID
		if tc.osUpdate == nil {
			continue
		}
		var checkedAt any
		if tc.osUpdate.checkedAt != nil {
			checkedAt = *tc.osUpdate.checkedAt
		}
		if _, err := env.pool.Exec(ctx, `
			INSERT INTO device_os_update
				(device_id, installed_os, latest_os, state, severity, security_relevant, checked_at, reported_at)
			VALUES ($1::uuid, '10.0.26100', '10.0.26200', $2, 'medium', true, $3, $4)
		`, deviceID, tc.osUpdate.state, checkedAt, tc.osUpdate.reportedAt); err != nil {
			t.Fatalf("seed device_os_update %s: %v", tc.hostname, err)
		}
	}

	// Give three devices non-trivial encryption and finding figures so the
	// detail-vs-roster comparison is not just null against null.
	//   win-behind:  BitLocker pass, one real fail, one error, one unreadable
	//                fail (excluded from findings_open) => true, 2
	//   win-current: BitLocker real fail => false, 1
	//   mac-pending: FileVault pass, no findings => true, 0
	seedEval := func(host, ruleKey, status string, observed any) {
		t.Helper()
		if _, err := env.pool.Exec(ctx, `
			INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity, benchmark_version)
			SELECT $1::uuid, id, $3, $4, severity, benchmark_version
			FROM compliance_rules WHERE rule_key = $2
		`, fx.deviceIDs[host], ruleKey, status, observed); err != nil {
			t.Fatalf("seed evaluation %s/%s: %v", host, ruleKey, err)
		}
	}
	otherWinRules := func(n int) []string {
		t.Helper()
		rows, err := env.pool.Query(ctx, `
			SELECT rule_key FROM compliance_rules
			WHERE rule_key LIKE 'cis_win_%' AND rule_key <> 'cis_win_18_10_11_bitlocker_os_drive'
			ORDER BY rule_key LIMIT $1
		`, n)
		if err != nil {
			t.Fatalf("list windows rules: %v", err)
		}
		defer rows.Close()
		var keys []string
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				t.Fatalf("scan rule key: %v", err)
			}
			keys = append(keys, k)
		}
		if len(keys) != n {
			t.Fatalf("need %d seeded windows rules, found %d", n, len(keys))
		}
		return keys
	}
	rules := otherWinRules(3)
	seedEval("win-behind", "cis_win_18_10_11_bitlocker_os_drive", "pass", "On")
	seedEval("win-behind", rules[0], "fail", "Disabled")
	seedEval("win-behind", rules[1], "error", nil)
	seedEval("win-behind", rules[2], "fail", nil)
	seedEval("win-current", "cis_win_18_10_11_bitlocker_os_drive", "fail", "Off")
	seedEval("mac-pending", "cis_macos_2_5_1_1_filevault", "pass", "On")
	return fx
}

func fetchUpdateStateRoster(t *testing.T, token string) map[string]updateStateRosterRow {
	t.Helper()
	resp := portalDo(t, http.MethodGet, "/v1/portal/devices?limit=500", token, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("GET /v1/portal/devices = %d: %s", resp.StatusCode, body)
	}
	var out struct {
		Devices []updateStateRosterRow `json:"devices"`
	}
	decodeJSON(t, resp, &out)
	byHost := make(map[string]updateStateRosterRow, len(out.Devices))
	for _, d := range out.Devices {
		byHost[d.Hostname] = d
	}
	return byHost
}

func boolStr(b *bool) string {
	if b == nil {
		return "null"
	}
	if *b {
		return "true"
	}
	return "false"
}

func intStr(n *int) string {
	if n == nil {
		return "null"
	}
	return strconv.Itoa(*n)
}

func sameBool(a, b *bool) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// TestPortalDevicesPatchPendingFromOSUpdateVerdict covers the roster half:
// (a) a Windows device with NULL pending_updates and a fresh device_os_update
// row gets a non-null patch_pending, true and false; (c) a stale row yields
// null; (d) explicit OS evidence outranks pending_updates, even when unknown.
func TestPortalDevicesPatchPendingFromOSUpdateVerdict(t *testing.T) {
	fx := seedUpdateStateTenant(t, "pat2294-roster")
	roster := fetchUpdateStateRoster(t, fx.token)

	for _, tc := range fx.cases {
		row, ok := roster[tc.hostname]
		if !ok {
			t.Errorf("%s missing from roster", tc.hostname)
			continue
		}
		if !sameBool(row.PatchPending, tc.want) {
			t.Errorf("roster %s patch_pending = %s, want %s", tc.hostname, boolStr(row.PatchPending), boolStr(tc.want))
		}
	}

	// The seeded encryption and findings figures are what the detail test
	// compares against; pin them here so a drift in the seed shows up in
	// the roster test rather than as a confusing detail failure.
	wantFig := map[string]struct {
		enc  *bool
		find int
	}{
		"win-behind":  {tp(true), 2},
		"win-current": {tp(false), 1},
		"mac-pending": {tp(true), 0},
		"win-no-row":  {nil, 0},
	}
	for host, want := range wantFig {
		row := roster[host]
		if !sameBool(row.EncryptionOK, want.enc) {
			t.Errorf("roster %s encryption_ok = %s, want %s", host, boolStr(row.EncryptionOK), boolStr(want.enc))
		}
		if row.FindingsOpen == nil || *row.FindingsOpen != want.find {
			t.Errorf("roster %s findings_open = %s, want %d", host, intStr(row.FindingsOpen), want.find)
		}
	}
}

// TestPortalDeviceDetailCarriesRosterSummary covers (b): the detail response
// carries encryption_ok, patch_pending and findings_open, and each equals
// the same device's roster row, for every seeded case including the stale
// and never-reported ones.
func TestPortalDeviceDetailCarriesRosterSummary(t *testing.T) {
	fx := seedUpdateStateTenant(t, "pat2294-detail")
	roster := fetchUpdateStateRoster(t, fx.token)

	for _, tc := range fx.cases {
		resp := portalDo(t, http.MethodGet, "/v1/portal/devices/"+fx.deviceIDs[tc.hostname], fx.token, nil)
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("GET detail %s = %d: %s", tc.hostname, resp.StatusCode, body)
		}
		var detail struct {
			Device map[string]json.RawMessage `json:"device"`
		}
		decodeJSON(t, resp, &detail)

		for _, key := range []string{"encryption_ok", "patch_pending", "findings_open"} {
			if _, ok := detail.Device[key]; !ok {
				t.Errorf("detail %s: device.%s is absent, want present (null is allowed, absent is not)", tc.hostname, key)
			}
		}
		var got updateStateRosterRow
		for key, dst := range map[string]any{
			"encryption_ok": &got.EncryptionOK,
			"patch_pending": &got.PatchPending,
			"findings_open": &got.FindingsOpen,
		} {
			if raw, ok := detail.Device[key]; ok {
				if err := json.Unmarshal(raw, dst); err != nil {
					t.Errorf("detail %s: decode device.%s = %s: %v", tc.hostname, key, raw, err)
				}
			}
		}

		want := roster[tc.hostname]
		if !sameBool(got.PatchPending, want.PatchPending) {
			t.Errorf("detail %s patch_pending = %s, roster says %s", tc.hostname, boolStr(got.PatchPending), boolStr(want.PatchPending))
		}
		if !sameBool(got.PatchPending, tc.want) {
			t.Errorf("detail %s patch_pending = %s, want %s", tc.hostname, boolStr(got.PatchPending), boolStr(tc.want))
		}
		if !sameBool(got.EncryptionOK, want.EncryptionOK) {
			t.Errorf("detail %s encryption_ok = %s, roster says %s", tc.hostname, boolStr(got.EncryptionOK), boolStr(want.EncryptionOK))
		}
		if got.FindingsOpen == nil || want.FindingsOpen == nil || *got.FindingsOpen != *want.FindingsOpen {
			t.Errorf("detail %s findings_open = %s, roster says %s", tc.hostname, intStr(got.FindingsOpen), intStr(want.FindingsOpen))
		}
	}
}

// TestPortalDeviceDetailSummaryStaysTenantScoped locks that the new summary
// read cannot be steered across tenants: another tenant's caller gets the
// same 404 as before, never the figures.
func TestPortalDeviceDetailSummaryStaysTenantScoped(t *testing.T) {
	a := seedUpdateStateTenant(t, "pat2294-scope-a")
	b := seedUpdateStateTenant(t, "pat2294-scope-b")

	resp := portalDo(t, http.MethodGet, "/v1/portal/devices/"+a.deviceIDs["win-behind"], b.token, nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("tenant B reading tenant A's device = %d, want 404: %s", resp.StatusCode, body)
	}

	resp = portalDo(t, http.MethodGet, "/v1/portal/devices/"+b.deviceIDs["win-behind"], b.token, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("tenant B reading its own device = %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()
}
