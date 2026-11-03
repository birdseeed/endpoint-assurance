//go:build integration

package integration

// PAT-2135: customer self-service Retire device decisions and the customer
// device list, end to end through the real portal router: roles, tenant
// isolation, idempotency, the append-only audit, the read-side retirement
// object, the stale-count exclusion, device list validation, matching,
// replace semantics and response caps.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/portalauth"
)

type retirementOut struct {
	RetiredAt               time.Time `json:"retired_at"`
	RetiredBy               string    `json:"retired_by"`
	Reason                  *string   `json:"reason"`
	ReportedAfterRetirement bool      `json:"reported_after_retirement"`
}

type retirementWriteOut struct {
	DeviceID   string         `json:"device_id"`
	Retired    bool           `json:"retired"`
	Changed    bool           `json:"changed"`
	Retirement *retirementOut `json:"retirement"`
}

type selfServiceErrorOut struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Items   []struct {
		Index int    `json:"index"`
		Code  string `json:"code"`
	} `json:"items"`
}

func portalCall(t *testing.T, method, path, token, body string) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	resp := portalDo(t, method, path, token, r)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func mustJSON(t *testing.T, b []byte, out any) {
	t.Helper()
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
}

func seedSelfServiceDevice(t *testing.T, tenantID, hostname, serial, osName string, lastSeen time.Time) string {
	t.Helper()
	var serialArg any
	if serial != "" {
		serialArg = serial
	}
	var id string
	if err := env.pool.QueryRow(context.Background(), `
		INSERT INTO devices (tenant_id, serial, hostname, os, os_version, last_seen)
		VALUES ($1::uuid, $2, $3, $4, '1', $5) RETURNING id::text
	`, tenantID, serialArg, hostname, osName, lastSeen).Scan(&id); err != nil {
		t.Fatalf("seed device %s: %v", hostname, err)
	}
	return id
}

func retirementRows(t *testing.T, tenantID, deviceID string) int {
	t.Helper()
	var n int
	if err := env.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM device_retirement_decisions WHERE tenant_id = $1::uuid AND device_id = $2::uuid
	`, tenantID, deviceID).Scan(&n); err != nil {
		t.Fatalf("count decisions: %v", err)
	}
	return n
}

type coverageOut struct {
	Coverage struct {
		DevicesTotal     int  `json:"devices_total"`
		DevicesReporting int  `json:"devices_reporting"`
		DevicesStale     int  `json:"devices_stale"`
		DevicesRetired   int  `json:"devices_retired"`
		Complete         bool `json:"complete"`
	} `json:"coverage"`
}

func TestPortalDeviceRetirement(t *testing.T) {
	a := newApprovalTenant(t, "retire-a", false)
	b := newApprovalTenant(t, "retire-b", false)
	now := time.Now().UTC()
	gone := seedSelfServiceDevice(t, a.tenantID, "OLD-LAPTOP", "", "Windows", now.Add(-40*24*time.Hour))
	fresh := seedSelfServiceDevice(t, a.tenantID, "mac-01", "C02FRESH", "macOS", now.Add(-time.Hour))
	other := seedSelfServiceDevice(t, b.tenantID, "b-device", "", "macOS", now)
	put := func(token, deviceID, body string) (int, []byte) {
		return portalCall(t, http.MethodPut, "/v1/portal/devices/"+deviceID+"/retirement", token, body)
	}

	// Before any decision the quiet device is stale and coverage incomplete.
	var cov coverageOut
	status, body := portalCall(t, http.MethodGet, "/v1/portal/software/new", a.viewerToken, "")
	if status != http.StatusOK {
		t.Fatalf("GET /software/new = %d: %s", status, body)
	}
	mustJSON(t, body, &cov)
	if cov.Coverage.DevicesStale != 1 || cov.Coverage.DevicesRetired != 0 {
		t.Fatalf("coverage before retiring = %+v, want 1 stale and 0 retired", cov.Coverage)
	}

	t.Run("viewer refused", func(t *testing.T) {
		status, body := put(a.viewerToken, gone, `{"retired":true}`)
		var e selfServiceErrorOut
		mustJSON(t, body, &e)
		if status != http.StatusForbidden || e.Error != "admin_role_required" {
			t.Fatalf("viewer PUT = %d %s, want 403 admin_role_required", status, body)
		}
		if n := retirementRows(t, a.tenantID, gone); n != 0 {
			t.Fatalf("viewer wrote %d rows", n)
		}
	})

	t.Run("cross tenant is 404", func(t *testing.T) {
		if status, body := put(a.adminToken, other, `{"retired":true}`); status != http.StatusNotFound {
			t.Fatalf("PUT another tenant's device = %d %s, want 404", status, body)
		}
		if status, body := portalCall(t, http.MethodGet, "/v1/portal/devices/"+other+"/retirement/history", a.adminToken, ""); status != http.StatusNotFound {
			t.Fatalf("history of another tenant's device = %d %s, want 404", status, body)
		}
		if status, _ := put(a.adminToken, "00000000-0000-0000-0000-000000000000", `{"retired":true}`); status != http.StatusNotFound {
			t.Fatalf("PUT unknown device = %d, want 404", status)
		}
		if n := retirementRows(t, b.tenantID, other); n != 0 {
			t.Fatalf("cross-tenant write recorded %d rows", n)
		}
	})

	t.Run("bad bodies", func(t *testing.T) {
		for _, bad := range []string{`{}`, `{"retired":true,"extra":1}`, `{"RETIRED":true}`, `not json`,
			`{"retired":true,"reason":"` + strings.Repeat("x", 501) + `"}`, `{"retired":true,"reason":"bell\u0007"}`} {
			if status, body := put(a.adminToken, gone, bad); status != http.StatusBadRequest {
				t.Errorf("body %.40q = %d %s, want 400", bad, status, body)
			}
		}
		if n := retirementRows(t, a.tenantID, gone); n != 0 {
			t.Fatalf("bad bodies wrote %d rows", n)
		}
	})

	var first retirementWriteOut
	status, body = put(a.adminToken, gone, `{"retired":true,"reason":"  Laptop stolen, written off  "}`)
	if status != http.StatusOK {
		t.Fatalf("retire = %d %s", status, body)
	}
	mustJSON(t, body, &first)
	if !first.Changed || !first.Retired || first.Retirement == nil ||
		first.Retirement.RetiredBy != strings.ToLower(a.adminEmail) ||
		first.Retirement.Reason == nil || *first.Retirement.Reason != "Laptop stolen, written off" ||
		first.Retirement.ReportedAfterRetirement {
		t.Fatalf("retire response = %s", body)
	}

	// Idempotent: the same state again writes nothing.
	var again retirementWriteOut
	status, body = put(a.adminToken, gone, `{"retired":true}`)
	mustJSON(t, body, &again)
	if status != http.StatusOK || again.Changed || again.Retirement == nil || !again.Retirement.RetiredAt.Equal(first.Retirement.RetiredAt) {
		t.Fatalf("second retire = %d %s, want 200 unchanged", status, body)
	}
	if n := retirementRows(t, a.tenantID, gone); n != 1 {
		t.Fatalf("decision rows = %d, want 1", n)
	}

	// Read side: still on the roster, carries the retirement object.
	var roster struct {
		Total   int `json:"total"`
		Devices []struct {
			DeviceID   string         `json:"device_id"`
			Retirement *retirementOut `json:"retirement"`
		} `json:"devices"`
	}
	status, body = portalCall(t, http.MethodGet, "/v1/portal/devices", a.viewerToken, "")
	mustJSON(t, body, &roster)
	if status != http.StatusOK || roster.Total != 2 {
		t.Fatalf("roster = %d %s, want both devices", status, body)
	}
	for _, d := range roster.Devices {
		if (d.DeviceID == gone) != (d.Retirement != nil) {
			t.Fatalf("roster device %s retirement = %+v", d.DeviceID, d.Retirement)
		}
	}

	// Counting: the retired device is counted as retired, not stale.
	status, body = portalCall(t, http.MethodGet, "/v1/portal/software/new", a.viewerToken, "")
	mustJSON(t, body, &cov)
	if status != http.StatusOK || cov.Coverage.DevicesStale != 0 || cov.Coverage.DevicesRetired != 1 ||
		cov.Coverage.DevicesTotal != 2 || cov.Coverage.DevicesReporting != 1 {
		t.Fatalf("coverage after retiring = %d %s", status, body)
	}
	var ov struct {
		DevicesTotal   int        `json:"devices_total"`
		DevicesRetired int        `json:"devices_retired"`
		OldestIngest   *time.Time `json:"oldest_successful_ingest"`
	}
	status, body = portalCall(t, http.MethodGet, "/v1/portal/overview", a.viewerToken, "")
	mustJSON(t, body, &ov)
	if status != http.StatusOK || ov.DevicesTotal != 2 || ov.DevicesRetired != 1 || ov.OldestIngest == nil ||
		ov.OldestIngest.Before(now.Add(-2*time.Hour)) {
		t.Fatalf("overview after retiring = %d %s (the retired device must not set the oldest ingest)", status, body)
	}

	// A report received after retirement flags it, and never unretires it.
	if _, err := env.pool.Exec(context.Background(),
		`UPDATE devices SET last_seen = clock_timestamp() + interval '1 second' WHERE id = $1::uuid`, gone); err != nil {
		t.Fatalf("simulate a later report: %v", err)
	}
	var detail struct {
		Device struct {
			Retirement *retirementOut `json:"retirement"`
		} `json:"device"`
	}
	status, body = portalCall(t, http.MethodGet, "/v1/portal/devices/"+gone, a.viewerToken, "")
	mustJSON(t, body, &detail)
	if status != http.StatusOK || detail.Device.Retirement == nil || !detail.Device.Retirement.ReportedAfterRetirement {
		t.Fatalf("detail after a later report = %d %s, want retired with reported_after_retirement", status, body)
	}
	status, body = portalCall(t, http.MethodGet, "/v1/portal/devices/"+fresh, a.viewerToken, "")
	mustJSON(t, body, &detail)
	if status != http.StatusOK || detail.Device.Retirement != nil {
		t.Fatalf("fresh device detail = %d %s, want retirement null", status, body)
	}

	// Unretire restores, as a new row.
	var undo retirementWriteOut
	status, body = put(a.adminToken, gone, `{"retired":false,"reason":"found it"}`)
	mustJSON(t, body, &undo)
	if status != http.StatusOK || !undo.Changed || undo.Retired || undo.Retirement != nil {
		t.Fatalf("unretire = %d %s", status, body)
	}
	status, body = put(a.adminToken, gone, `{"retired":false}`)
	mustJSON(t, body, &undo)
	if status != http.StatusOK || undo.Changed {
		t.Fatalf("second unretire = %d %s, want unchanged", status, body)
	}
	var hist struct {
		Total      int            `json:"total"`
		Retirement *retirementOut `json:"retirement"`
		Decisions  []struct {
			Action     string  `json:"action"`
			Reason     *string `json:"reason"`
			ActorEmail string  `json:"actor_email"`
		} `json:"decisions"`
	}
	status, body = portalCall(t, http.MethodGet, "/v1/portal/devices/"+gone+"/retirement/history", a.viewerToken, "")
	mustJSON(t, body, &hist)
	if status != http.StatusOK || hist.Total != 2 || len(hist.Decisions) != 2 || hist.Retirement != nil ||
		hist.Decisions[0].Action != "unretire" || hist.Decisions[1].Action != "retire" ||
		hist.Decisions[0].ActorEmail != strings.ToLower(a.adminEmail) {
		t.Fatalf("history = %d %s", status, body)
	}
	status, body = portalCall(t, http.MethodGet, "/v1/portal/overview", a.viewerToken, "")
	mustJSON(t, body, &ov)
	if ov.DevicesRetired != 0 {
		t.Fatalf("overview after unretire = %s, want devices_retired 0", body)
	}

	// The audit is append-only.
	if _, err := env.pool.Exec(context.Background(),
		`UPDATE device_retirement_decisions SET action = 'retire' WHERE device_id = $1::uuid`, gone); err == nil {
		t.Fatal("UPDATE of device_retirement_decisions succeeded; it must be append-only")
	}
	if _, err := env.pool.Exec(context.Background(),
		`DELETE FROM device_retirement_decisions WHERE device_id = $1::uuid`, gone); err == nil {
		t.Fatal("DELETE of device_retirement_decisions succeeded; it must be append-only")
	}
}

// TestPortalDeviceRetirementConcurrentWritesRecordOneRow: two admins retiring
// the same device at once record exactly one decision.
func TestPortalDeviceRetirementConcurrentWritesRecordOneRow(t *testing.T) {
	a := newApprovalTenant(t, "retire-race", false)
	dev := seedSelfServiceDevice(t, a.tenantID, "race-box", "", "macOS", time.Now())
	const n = 8
	results := make(chan int, n)
	for i := 0; i < n; i++ {
		go func() {
			req, _ := http.NewRequest(http.MethodPut, env.publicSrv.URL+"/v1/portal/devices/"+dev+"/retirement",
				strings.NewReader(`{"retired":true}`))
			req.Header.Set(portalauth.Header, a.adminToken)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				results <- 0
				return
			}
			resp.Body.Close()
			results <- resp.StatusCode
		}()
	}
	for i := 0; i < n; i++ {
		if s := <-results; s != http.StatusOK {
			t.Fatalf("concurrent PUT status = %d", s)
		}
	}
	if got := retirementRows(t, a.tenantID, dev); got != 1 {
		t.Fatalf("concurrent retires recorded %d rows, want 1", got)
	}
}

type deviceListOut struct {
	List *struct {
		UploadedBy string  `json:"uploaded_by"`
		Filename   *string `json:"filename"`
		EntryCount int     `json:"entry_count"`
	} `json:"list"`
	Cleared *struct {
		ClearedBy string `json:"cleared_by"`
	} `json:"cleared"`
	MatchedCount        int `json:"matched_count"`
	MatchedRetiredCount int `json:"matched_retired_count"`
	OnListNeverSeen     []struct {
		Index    int     `json:"index"`
		Hostname *string `json:"hostname"`
		Serial   *string `json:"serial"`
	} `json:"on_list_never_seen"`
	OnListNeverSeenTotal int `json:"on_list_never_seen_total"`
	SeenNotOnList        []struct {
		DeviceID string  `json:"device_id"`
		Hostname *string `json:"hostname"`
	} `json:"seen_not_on_list"`
	SeenNotOnListTotal int  `json:"seen_not_on_list_total"`
	Truncated          bool `json:"truncated"`
}

func getDeviceList(t *testing.T, token string) deviceListOut {
	t.Helper()
	status, body := portalCall(t, http.MethodGet, "/v1/portal/device-list", token, "")
	if status != http.StatusOK {
		t.Fatalf("GET /device-list = %d %s", status, body)
	}
	var out deviceListOut
	mustJSON(t, body, &out)
	return out
}

func TestPortalDeviceList(t *testing.T) {
	a := newApprovalTenant(t, "list-a", false)
	b := newApprovalTenant(t, "list-b", false)
	now := time.Now().UTC()
	win := seedSelfServiceDevice(t, a.tenantID, "DESKTOP-ROBWIN", "", "Windows", now)
	mac := seedSelfServiceDevice(t, a.tenantID, "mac-01", "C02AAA", "macOS", now)
	stray := seedSelfServiceDevice(t, a.tenantID, "stray", "S-STRAY", "macOS", now)
	old := seedSelfServiceDevice(t, a.tenantID, "old-box", "", "Windows", now.Add(-60*24*time.Hour))
	seedSelfServiceDevice(t, b.tenantID, "b-only", "", "macOS", now)
	put := func(token, body string) (int, []byte) {
		return portalCall(t, http.MethodPut, "/v1/portal/device-list", token, body)
	}

	if got := getDeviceList(t, a.viewerToken); got.List != nil || got.Cleared != nil || len(got.SeenNotOnList) != 0 {
		t.Fatalf("list before any upload = %+v, want null and empty", got)
	}

	t.Run("viewer refused", func(t *testing.T) {
		status, body := put(a.viewerToken, `{"entries":[{"hostname":"x"}]}`)
		var e selfServiceErrorOut
		mustJSON(t, body, &e)
		if status != http.StatusForbidden || e.Error != "admin_role_required" {
			t.Fatalf("viewer PUT = %d %s", status, body)
		}
		if status, _ := portalCall(t, http.MethodDelete, "/v1/portal/device-list", a.viewerToken, ""); status != http.StatusForbidden {
			t.Fatalf("viewer DELETE = %d", status)
		}
	})

	t.Run("validation", func(t *testing.T) {
		cases := []struct {
			body, code string
			index      int
		}{
			{`{"entries":[]}`, "empty_list", -1},
			{`{"filename":"x.csv"}`, "invalid_request", -1},
			{`{"entries":[{"hostname":"a"},{"hostname":"b"},{"hostname":" ","serial":null}]}`, "invalid_entry", 2},
			{`{"entries":[{"hostname":"a"},{"hostname":"bad\u0001"}]}`, "invalid_entry", 1},
			{`{"entries":[{"hostname":"` + strings.Repeat("h", 256) + `"}]}`, "invalid_entry", 0},
			{`{"entries":[{"hostname":"a","mac":"x"}]}`, "invalid_request", -1},
			{`{"filename":"a\u000d.csv","entries":[{"hostname":"a"}]}`, "invalid_filename", -1},
		}
		for _, c := range cases {
			status, body := put(a.adminToken, c.body)
			var e selfServiceErrorOut
			mustJSON(t, body, &e)
			if status != http.StatusBadRequest || e.Error != c.code {
				t.Errorf("%.50s = %d %s, want 400 %s", c.body, status, body, c.code)
				continue
			}
			if c.index >= 0 && (len(e.Items) != 1 || e.Items[0].Index != c.index || !strings.Contains(e.Message, fmt.Sprintf("entries[%d]", c.index))) {
				t.Errorf("%.50s error = %s, want row index %d", c.body, body, c.index)
			}
		}
		var many strings.Builder
		many.WriteString(`{"entries":[`)
		for i := 0; i <= 10000; i++ {
			if i > 0 {
				many.WriteString(",")
			}
			fmt.Fprintf(&many, `{"hostname":"h%d"}`, i)
		}
		many.WriteString(`]}`)
		if status, body := put(a.adminToken, many.String()); status != http.StatusBadRequest || !strings.Contains(string(body), "too_many_entries") {
			t.Errorf("10001 entries = %d %s", status, body)
		}
		huge := `{"entries":[{"hostname":"` + strings.Repeat("a", 3<<20) + `"}]}`
		if status, _ := put(a.adminToken, huge); status != http.StatusRequestEntityTooLarge {
			t.Errorf("3 MiB body = %d, want 413", status)
		}
		if got := getDeviceList(t, a.viewerToken); got.List != nil {
			t.Fatalf("a refused upload stored a list: %+v", got.List)
		}
	})

	// Retire old-box so the list's view of it is "matched, retired".
	if status, body := portalCall(t, http.MethodPut, "/v1/portal/devices/"+old+"/retirement", a.adminToken, `{"retired":true}`); status != http.StatusOK {
		t.Fatalf("retire old-box = %d %s", status, body)
	}

	status, body := put(a.adminToken, `{"filename":"estate.csv","entries":[
		{"hostname":"desktop-robwin.local."},
		{"hostname":"renamed-mac","serial":" c02aaa "},
		{"hostname":"ghost"},
		{"hostname":"GHOST."},
		{"hostname":"OLD-BOX"}]}`)
	if status != http.StatusOK {
		t.Fatalf("upload = %d %s", status, body)
	}
	var up struct {
		ReceivedCount       int `json:"received_count"`
		DuplicatesCollapsed int `json:"duplicates_collapsed"`
	}
	mustJSON(t, body, &up)
	if up.ReceivedCount != 5 || up.DuplicatesCollapsed != 1 {
		t.Fatalf("upload response = %s", body)
	}

	got := getDeviceList(t, a.viewerToken)
	if got.List == nil || got.List.EntryCount != 4 || got.List.Filename == nil || *got.List.Filename != "estate.csv" ||
		got.List.UploadedBy != strings.ToLower(a.adminEmail) {
		t.Fatalf("list = %+v", got.List)
	}
	if got.MatchedCount != 3 || got.MatchedRetiredCount != 1 {
		t.Fatalf("matched = %d (retired %d), want 3 (1)", got.MatchedCount, got.MatchedRetiredCount)
	}
	if got.OnListNeverSeenTotal != 1 || got.OnListNeverSeen[0].Index != 2 || *got.OnListNeverSeen[0].Hostname != "ghost" {
		t.Fatalf("on list never seen = %+v", got.OnListNeverSeen)
	}
	if got.SeenNotOnListTotal != 1 || got.SeenNotOnList[0].DeviceID != stray {
		t.Fatalf("seen not on list = %+v, want only stray (retired old-box excluded)", got.SeenNotOnList)
	}

	// Tenant B sees none of it.
	if gb := getDeviceList(t, b.adminToken); gb.List != nil || len(gb.SeenNotOnList) != 0 {
		t.Fatalf("tenant B device list = %+v", gb)
	}

	// Replace: a new upload is the whole list; the old one is kept as history.
	if status, body := put(a.adminToken, `{"entries":[{"hostname":"stray"}]}`); status != http.StatusOK {
		t.Fatalf("replace = %d %s", status, body)
	}
	got = getDeviceList(t, a.viewerToken)
	if got.List == nil || got.List.EntryCount != 1 || got.List.Filename != nil || got.MatchedCount != 1 || got.OnListNeverSeenTotal != 0 {
		t.Fatalf("after replace = %+v", got)
	}
	ids := map[string]bool{}
	for _, d := range got.SeenNotOnList {
		ids[d.DeviceID] = true
	}
	if len(ids) != 2 || !ids[win] || !ids[mac] {
		t.Fatalf("after replace, seen not on list = %+v, want the Windows and Mac devices", got.SeenNotOnList)
	}
	var uploads int
	if err := env.pool.QueryRow(context.Background(), `SELECT count(*) FROM device_list_uploads WHERE tenant_id = $1::uuid`, a.tenantID).Scan(&uploads); err != nil || uploads != 2 {
		t.Fatalf("upload history rows = %d (%v), want 2", uploads, err)
	}

	// Clear, then clear again.
	status, body = portalCall(t, http.MethodDelete, "/v1/portal/device-list", a.adminToken, "")
	if status != http.StatusOK || !strings.Contains(string(body), `"changed":true`) {
		t.Fatalf("clear = %d %s", status, body)
	}
	got = getDeviceList(t, a.viewerToken)
	if got.List != nil || got.Cleared == nil || got.Cleared.ClearedBy != strings.ToLower(a.adminEmail) || len(got.SeenNotOnList) != 0 {
		t.Fatalf("after clear = %+v", got)
	}
	status, body = portalCall(t, http.MethodDelete, "/v1/portal/device-list", a.adminToken, "")
	if status != http.StatusOK || !strings.Contains(string(body), `"changed":false`) {
		t.Fatalf("second clear = %d %s", status, body)
	}
}

func TestPortalDeviceListResponseCaps(t *testing.T) {
	a := newApprovalTenant(t, "list-cap", false)
	var sb strings.Builder
	sb.WriteString(`{"entries":[`)
	for i := 0; i < 600; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"hostname":"never-%03d"}`, i)
	}
	sb.WriteString(`]}`)
	if status, body := portalCall(t, http.MethodPut, "/v1/portal/device-list", a.adminToken, sb.String()); status != http.StatusOK {
		t.Fatalf("upload = %d %s", status, body)
	}
	got := getDeviceList(t, a.viewerToken)
	if len(got.OnListNeverSeen) != 500 || got.OnListNeverSeenTotal != 600 || !got.Truncated {
		t.Fatalf("capped list = %d rows, total %d, truncated %v; want 500, 600, true",
			len(got.OnListNeverSeen), got.OnListNeverSeenTotal, got.Truncated)
	}
	if got.OnListNeverSeen[0].Index != 0 || got.OnListNeverSeen[499].Index != 499 {
		t.Fatalf("capped rows are not the first 500 in upload order")
	}
}
