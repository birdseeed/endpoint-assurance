//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"
)

type portalEvidenceHardwareOut struct {
	Battery *string `json:"battery"`
	Storage *string `json:"storage"`
	Disks   *string `json:"disks"`
}

type portalEvidenceSectionsOut struct {
	Certificates   *string                    `json:"certificates"`
	HardwareHealth *portalEvidenceHardwareOut `json:"hardware_health"`
}

type portalEvidenceOut struct {
	ObservedAt *time.Time                `json:"observed_at"`
	ReceivedAt *time.Time                `json:"received_at"`
	Sections   portalEvidenceSectionsOut `json:"sections"`
	Authority  string                    `json:"authority"`
	Freshness  string                    `json:"freshness"`
}

type portalEvidenceDeviceOut struct {
	Hostname string            `json:"hostname"`
	DeviceID string            `json:"device_id"`
	LastSeen time.Time         `json:"last_seen"`
	Evidence portalEvidenceOut `json:"evidence"`
}

// TestPortalDeviceEvidenceContract exercises the additive response through the
// real portal route. The report-package DB test separately locks raw-row
// ordering and page-bounded query behaviour.
func TestPortalDeviceEvidenceContract(t *testing.T) {
	ctx := context.Background()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-evidence-contract")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	email := "evidence@portal-evidence-contract.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)
	now := time.Now().UTC()

	type evidenceCase struct {
		hostname   string
		receivedAt time.Time
		observedAt time.Time
		payload    map[string]any
		authority  string
		freshness  string
	}
	cases := []evidenceCase{
		{"evidence-complete", now.Add(-time.Minute), now.Add(-2 * time.Minute), map[string]any{
			"collection_status": map[string]any{"certificates": "complete"},
		}, "section_scoped", "fresh"},
		{"evidence-partial", now.Add(-time.Minute), now.Add(-2 * time.Minute), map[string]any{
			"collection_status": map[string]any{"certificates": "partial"},
		}, "presence_only", "fresh"},
		{"evidence-unavailable", now.Add(-time.Minute), now.Add(-2 * time.Minute), map[string]any{
			"hardware_health": map[string]any{"collection_status": map[string]any{"storage": "unavailable"}},
		}, "unavailable", "fresh"},
		{"evidence-missing", now.Add(-time.Minute), now.Add(-2 * time.Minute), map[string]any{}, "unknown", "fresh"},
		{"evidence-malformed", now.Add(-time.Minute), now.Add(-2 * time.Minute), map[string]any{
			"collection_status": map[string]any{"certificates": 42},
		}, "unknown", "fresh"},
		{"evidence-stale", now.Add(-time.Minute), now.Add(-7*24*time.Hour - time.Minute), map[string]any{
			"collection_status": map[string]any{"certificates": "complete"},
		}, "stale", "stale"},
	}

	deviceIDs := make(map[string]string, len(cases))
	for _, tc := range cases {
		var deviceID string
		err := env.pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
			VALUES ($1::uuid, $2, gen_random_uuid(), $2, 'macOS', '15.5', '24F74', 'arm64', $3)
			RETURNING id::text
		`, tenantID, tc.hostname, tc.receivedAt).Scan(&deviceID)
		if err != nil {
			t.Fatalf("seed %s device: %v", tc.hostname, err)
		}
		tc.payload["collected_at"] = tc.observedAt.Format(time.RFC3339)
		body, err := json.Marshal(tc.payload)
		if err != nil {
			t.Fatalf("marshal %s raw payload: %v", tc.hostname, err)
		}
		if _, err := env.pool.Exec(ctx, `
			INSERT INTO raw_payloads (tenant_id, device_id, received_at, body)
			VALUES ($1::uuid, $2::uuid, $3, $4::jsonb)
		`, tenantID, deviceID, tc.receivedAt, body); err != nil {
			t.Fatalf("seed %s raw payload: %v", tc.hostname, err)
		}
		deviceIDs[tc.hostname] = deviceID
	}

	resp := portalDo(t, http.MethodGet, "/v1/portal/devices?limit=10", token, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("portal devices = %d: %s", resp.StatusCode, body)
	}
	defer resp.Body.Close()
	var out struct {
		Devices []portalEvidenceDeviceOut `json:"devices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode portal devices: %v", err)
	}

	byHostname := make(map[string]portalEvidenceDeviceOut)
	for _, row := range out.Devices {
		byHostname[row.Hostname] = row
	}
	for _, tc := range cases {
		row, ok := byHostname[tc.hostname]
		if !ok {
			t.Fatalf("%s missing from tenant-scoped roster", tc.hostname)
		}
		if row.DeviceID == "" || row.LastSeen.IsZero() {
			t.Errorf("%s lost legacy roster fields: %+v", tc.hostname, row)
		}
		if row.Evidence.ObservedAt == nil || row.Evidence.ReceivedAt == nil ||
			row.Evidence.Authority != tc.authority || row.Evidence.Freshness != tc.freshness {
			t.Errorf("%s evidence = %+v, want timestamps and %s/%s",
				tc.hostname, row.Evidence, tc.authority, tc.freshness)
		}
	}
	if got := byHostname["evidence-complete"].Evidence.Sections.Certificates; got == nil || *got != "complete" {
		t.Fatalf("complete section = %v, want certificates=complete", got)
	}
	if got := byHostname["evidence-partial"].Evidence.Sections.Certificates; got == nil || *got != "partial" {
		t.Fatalf("partial section = %v, want certificates=partial", got)
	}
	unavailableHW := byHostname["evidence-unavailable"].Evidence.Sections.HardwareHealth
	if unavailableHW == nil || unavailableHW.Storage == nil || *unavailableHW.Storage != "unavailable" {
		t.Fatalf("unavailable sections = %+v, want hardware_health.storage=unavailable", unavailableHW)
	}
	if got := byHostname["evidence-missing"].Evidence.Sections; got.Certificates != nil || got.HardwareHealth != nil {
		t.Fatalf("missing sections = %+v, want empty", got)
	}
	if got := byHostname["evidence-stale"].Evidence.Sections.Certificates; got == nil || *got != "complete" {
		t.Fatalf("stale section = %v, want retained certificates=complete with stale authority", got)
	}

	// The detail route must expose the exact same platform-owned envelope for
	// the same tenant-scoped device, rather than independently reconstructing
	// or widening evidence authority. This also proves malformed data fails
	// closed on detail just as it does on the roster.
	for _, tc := range cases {
		resp = portalDo(t, http.MethodGet, "/v1/portal/devices/"+deviceIDs[tc.hostname], token, nil)
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("portal device detail %s = %d: %s", tc.hostname, resp.StatusCode, body)
		}
		var detail struct {
			Device portalEvidenceDeviceOut `json:"device"`
		}
		decodeJSON(t, resp, &detail)
		roster := byHostname[tc.hostname]
		if detail.Device.DeviceID != roster.DeviceID || !reflect.DeepEqual(detail.Device.Evidence, roster.Evidence) {
			t.Fatalf("%s detail evidence = %+v, want exact roster evidence %+v", tc.hostname, detail.Device.Evidence, roster.Evidence)
		}
	}
}
