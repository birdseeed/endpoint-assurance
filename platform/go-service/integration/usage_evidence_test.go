//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"patched.im/api/internal/extractor"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"patched.im/api/internal/handlers"
	"patched.im/api/internal/report"
)

// PAT-2328: real authenticated ingestion, extraction, derived read-back and
// tenant-scoped coverage. Historical timestamps are intentionally preserved
// to prove that the current no_record/unavailable state suppresses them.
func TestUsageEvidenceIngestionReadbackAndAuthority(t *testing.T) {
	tn := newCVETestTenant(t, "pat2328-"+randomHex(4))
	other := newCVETestTenant(t, "pat2328-other-"+randomHex(4))
	hw := "aa" + randomHex(3) + "-1111-2222-3333-444455556666"
	old := time.Now().Add(-120 * 24 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	app := cveTestApp{name: "PAT2328 Usage", version: "1", bundle: "com.example.pat2328." + randomHex(4)}
	var deviceID string
	var mutate func(map[string]any)
	post := func(state, status string, dated bool) {
		t.Helper()
		mustPostApps(t, tn, hw, appsPost{schemaV3: true, status: status, apps: []cveTestApp{app}, raw: func(body []byte) []byte {
			var p map[string]any
			if err := json.Unmarshal(body, &p); err != nil {
				t.Fatal(err)
			}
			p["metering_status"] = "ok"
			p["metering_user_hive_count"] = 1
			p["metering_record_count"] = 2
			a := p["apps"].([]any)[0].(map[string]any)
			if state != "" {
				a["usage_evidence"] = state
			}
			if dated {
				a["last_used_at"] = old
				a["launch_count"] = 2
			}
			if mutate != nil {
				mutate(p)
			}
			out, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}})
		if err := env.pool.QueryRow(t.Context(), `SELECT id::text FROM devices WHERE tenant_id=$1::uuid AND hw_uuid=$2::uuid`, tn.tenantID, hw).Scan(&deviceID); err != nil {
			t.Fatal(err)
		}
	}
	assert := func(state string, unused bool, unmetered int) {
		t.Helper()
		var raw *string
		var at *time.Time
		var historical *time.Time
		if err := env.pool.QueryRow(t.Context(), `SELECT usage_evidence,usage_evidence_at,last_used_at FROM device_apps WHERE device_id=$1::uuid AND identifier=$2`, deviceID, app.bundle).Scan(&raw, &at, &historical); err != nil {
			t.Fatal(err)
		}
		if (state == "" && raw != nil) || (state != "" && (raw == nil || *raw != state)) || at == nil || historical == nil {
			t.Fatalf("evidence=%v at=%v historical=%v; want state %q with preserved positive history", raw, at, historical, state)
		}
		page, err := report.FetchPortalSoftware(t.Context(), env.pool, tn.tenantID, "", 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Products) != 1 {
			t.Fatalf("products=%d", len(page.Products))
		}
		got := page.Products[0]
		wantUnused := 0
		if unused {
			wantUnused = 1
		}
		if got.RemovalCandidate != unused || got.UnusedInstallationCount != wantUnused || got.UnmeteredInstallationCount != unmetered {
			t.Errorf("%s coverage=%+v", state, got)
		}
		router := chi.NewRouter()
		router.Get("/admin/tenants/{tenantID}/metering", handlers.MeteringFleetHandler(env.pool))
		router.Get("/admin/tenants/{tenantID}/metering/{appName}", handlers.MeteringBreakdownHandler(env.pool))
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tn.tenantID+"/metering", nil))
		var aggregate struct {
			Apps []struct {
				MeteringStatus string     `json:"metering_status"`
				LastUsedAt     *time.Time `json:"last_used_at"`
			} `json:"apps"`
		}
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &aggregate) != nil || len(aggregate.Apps) != 1 {
			t.Fatalf("aggregate: %s", rr.Body.String())
		}
		if unmetered == 1 && aggregate.Apps[0].MeteringStatus == "ok" {
			t.Errorf("unmetered app projected as ok: %s", rr.Body.String())
		}
		if state == "no_record" || state == "unavailable" || state == "unmapped" {
			if aggregate.Apps[0].LastUsedAt != nil {
				t.Error("aggregate promoted retained usage history")
			}
		}
		rr = httptest.NewRecorder()
		router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tn.tenantID+"/metering/"+url.PathEscape(app.name), nil))
		var breakdown struct {
			Devices []struct {
				UsageEvidence *string `json:"usage_evidence"`
			} `json:"devices"`
		}
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &breakdown) != nil || len(breakdown.Devices) != 1 {
			t.Fatalf("breakdown: %s", rr.Body.String())
		}
		if (state == "" && breakdown.Devices[0].UsageEvidence != nil) || (state != "" && (breakdown.Devices[0].UsageEvidence == nil || *breakdown.Devices[0].UsageEvidence != state)) {
			t.Errorf("breakdown lost state: %s", rr.Body.String())
		}
		hidden, err := report.FetchPortalSoftwareForDevice(t.Context(), env.pool, other.tenantID, deviceID, "", 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		if hidden.Total != 0 || hidden.Coverage.InstallationCount != 0 {
			t.Fatal("another tenant's usage evidence leaked")
		}
	}
	post("recorded", "complete", true)
	assert("recorded", true, 0)
	// A stale app receipt cannot be refreshed by the device heartbeat.
	if _, err := env.pool.Exec(t.Context(), `UPDATE device_apps SET usage_evidence_at=now()-interval '31 days' WHERE device_id=$1::uuid`, deviceID); err != nil {
		t.Fatal(err)
	}
	assert("recorded", false, 0)
	post("recorded", "complete", true)
	mutate = func(p map[string]any) { p["metering_status"] = "userassist_unavailable" }
	post("recorded", "complete", true)
	assert("recorded", false, 1)
	mutate = nil
	post("no_record", "complete", false)
	assert("no_record", false, 0)
	post("unmapped", "complete", false)
	assert("unmapped", false, 1)
	post("unavailable", "complete", true)
	assert("unavailable", false, 1)
	// A stale per-app observation cannot become fresh from the device's heartbeat.
	if _, err := env.pool.Exec(t.Context(), `UPDATE device_apps SET usage_evidence_at=now()-interval '30 days' WHERE device_id=$1::uuid`, deviceID); err != nil {
		t.Fatal(err)
	}
	assert("unavailable", false, 1)
	post("recorded", "partial", true)
	assert("recorded", false, 0)
	// A positive count is a lower bound, not a dated observation.
	mutate = func(p map[string]any) { p["apps"].([]any)[0].(map[string]any)["launch_count"] = 4 }
	post("recorded", "complete", false)
	assert("recorded", false, 0)
	mutate = nil
	post("", "complete", false)
	assert("", false, 0)
	// Re-extract the older positive report after a newer absent observation.
	if _, err := env.pool.Exec(t.Context(), `UPDATE raw_payloads SET extracted_at=NULL, extraction_attempts=0 WHERE tenant_id=$1::uuid AND received_at=(SELECT min(received_at) FROM raw_payloads WHERE tenant_id=$1::uuid)`, tn.tenantID); err != nil {
		t.Fatal(err)
	}
	if err := extractor.ProcessOnce(t.Context(), env.pool); err != nil {
		t.Fatal(err)
	}
	assert("", false, 0)
	// A shared device_apps row cannot claim complete use across unread users.
	mutate = func(p map[string]any) {
		a := p["apps"].([]any)[0].(map[string]any)
		b := map[string]any{}
		for key, value := range a {
			b[key] = value
		}
		b["user_account"], b["usage_evidence"], b["last_used_at"], b["launch_count"] = "alice", "unavailable", nil, nil
		p["apps"] = []any{b, a}
		p["collection_status"].(map[string]any)["apps_users"] = []any{map[string]any{"user_account": "alice", "collection_status": "partial"}}
	}
	post("recorded", "complete", true)
	assert("unavailable", false, 1)
	mutate = nil
	post("recorded", "complete", true)
	assert("recorded", false, 0) // alice's held scope was not read this time
	post("no_record", "complete", false)
	var hives, records *int
	if err := env.pool.QueryRow(t.Context(), `SELECT metering_user_hive_count,metering_record_count FROM devices WHERE id=$1::uuid`, deviceID).Scan(&hives, &records); err != nil {
		t.Fatal(err)
	}
	if hives == nil || *hives != 1 || records == nil || *records != 2 {
		t.Fatal("raw metering counts discarded or invented")
	}
	mutate = func(p map[string]any) {
		delete(p, "metering_user_hive_count")
		delete(p, "metering_record_count")
		delete(p, "metering_status")
	}
	post("no_record", "complete", false)
	assert("no_record", false, 1)
	var health *string
	if err := env.pool.QueryRow(t.Context(), `SELECT metering_status,metering_user_hive_count,metering_record_count FROM devices WHERE id=$1::uuid`, deviceID).Scan(&health, &hives, &records); err != nil {
		t.Fatal(err)
	}
	if health != nil || hives != nil || records != nil {
		t.Fatal("absent report refreshed retained collection health or counts")
	}
	// Public diagnostic projection must expose the exact raw state per app.
	router := chi.NewRouter()
	router.Get("/admin/devices/{deviceID}/apps", handlers.DeviceAppsHandler(env.pool))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/devices/"+deviceID+"/apps", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("read-back=%d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Apps []struct {
			UsageEvidence *string `json:"usage_evidence"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Apps) != 1 || out.Apps[0].UsageEvidence == nil || *out.Apps[0].UsageEvidence != "no_record" {
		t.Fatalf("read-back dropped state: %s", rr.Body.String())
	}
}
