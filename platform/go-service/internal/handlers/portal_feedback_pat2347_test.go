package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"patched.im/api/internal/portalauth"
)

// These acceptance guards use the migrated scratch DB, never DATABASE_URL or
// pgx defaults. CI without a DB may skip; a promised DB must fail closed.
func pat2347FeedbackPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("PATCHED_DB_TESTS_REQUIRED") != "" {
			t.Fatal("PATCHED_DB_TESTS_REQUIRED: TEST_DATABASE_URL absent")
		}
		t.Skip("PAT-2347 HTTP acceptance needs a migrated loopback scratch database")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid TEST_DATABASE_URL")
	}
	loopback := func(host string) bool {
		switch strings.ToLower(strings.Trim(host, "[]")) {
		case "localhost", "127.0.0.1", "::1":
			return true
		}
		return false
	}
	if !loopback(cfg.ConnConfig.Host) {
		t.Fatal("PAT-2347 requires loopback database host")
	}
	for _, fallback := range cfg.ConnConfig.Fallbacks {
		if !loopback(fallback.Host) {
			t.Fatal("PAT-2347 requires loopback fallback hosts")
		}
	}
	name := strings.ToLower(cfg.ConnConfig.Database)
	if !strings.Contains(name, "test") && !strings.Contains(name, "scratch") {
		t.Fatal("PAT-2347 requires a test/scratch-named database")
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = "public"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("cannot create scratch DB pool")
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatal("scratch DB unavailable")
	}
	// Do not create a simplified fixture: the real migration and constraints are
	// part of this proof. Missing schema is a failure, never a skip.
	var ready bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version='0222_feedback_support_design_types')`).Scan(&ready); err != nil || !ready {
		t.Fatal("PAT-2347 requires the real forward migrations through 0222")
	}
	return pool
}

func pat2347Invalid(t *testing.T, status int, header http.Header, body []byte) {
	t.Helper()
	if status != http.StatusBadRequest || !strings.HasPrefix(header.Get("Content-Type"), "application/json") {
		t.Fatalf("refusal = %d %s, want JSON 400: %s", status, header.Get("Content-Type"), body)
	}
	var out struct{ Error, Message string }
	if err := json.Unmarshal(body, &out); err != nil || out.Error != "invalid_feedback" || out.Message == "" {
		t.Fatalf("refusal is not a customer-readable invalid_feedback response: %s", body)
	}
}

func TestPortalFeedbackPAT2347InvalidBeforeDatabase(t *testing.T) {
	identity := portalauth.Identity{TenantID: "11111111-2222-3333-4444-555555555555", Email: "private@example.test"}
	for _, door := range []string{"unknown", "Support", "bug"} {
		t.Run("door_"+door, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/portal/feedback?door="+door, nil)
			req = req.WithContext(portalauth.WithIdentity(req.Context(), identity))
			rec := httptest.NewRecorder()
			PortalFeedbackHandler(nil, true).ServeHTTP(rec, req)
			pat2347Invalid(t, rec.Code, rec.Header(), rec.Body.Bytes())
		})
	}
	for _, tc := range pat2347RefusedForms() {
		t.Run(tc.typ+"_"+tc.category+"_"+tc.severity, func(t *testing.T) {
			fields := map[string]string{"type": tc.typ, "category": tc.category, "severity": tc.severity, "title": "Valid title", "description": "Private description"}
			body, ct := feedbackMultipart(t, fields)
			req := httptest.NewRequest(http.MethodPost, "/v1/portal/feedback", body)
			req.Header.Set("Content-Type", ct)
			req = req.WithContext(portalauth.WithIdentity(req.Context(), identity))
			rec := httptest.NewRecorder()
			// A nil pool panics if validation reaches any database work.
			PortalFeedbackHandler(nil, true).ServeHTTP(rec, req)
			pat2347Invalid(t, rec.Code, rec.Header(), rec.Body.Bytes())
		})
	}
}

type pat2347Form struct{ typ, category, severity string }

func pat2347RefusedForms() []pat2347Form {
	return []pat2347Form{
		{"support", "", ""}, {"support", "unknown", ""},
		{"support", "not_working", "low"}, {"design", "", "low"},
		{"design", "not_working", ""}, {"feature", "account_billing", ""},
		{"question", "findings_or_reports", ""}, {"bug", "not_working", "high"},
	}
}

func TestPortalFeedbackPAT2347HTTPRoundTrips(t *testing.T) {
	pool := pat2347FeedbackPool(t)
	ctx := context.Background()
	// Unique tenants are cleaned up with checked errors; no shared fixture is
	// truncated. The same reporter in both tenants makes tenant scope observable.
	tenant := func() string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, `INSERT INTO tenants(name,bearer_token_hash,hmac_secret) VALUES('PAT-2347 HTTP scratch',decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex')) RETURNING id::text`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1::uuid`, id); err != nil {
				t.Errorf("cleanup scratch tenant: %v", err)
			}
		})
		return id
	}
	a, b, empty := tenant(), tenant(), tenant()
	identities := map[string]portalauth.Identity{
		"a":     {TenantID: a, Email: "private-reporter@example.test"},
		"b":     {TenantID: b, Email: "private-reporter@example.test"},
		"empty": {TenantID: empty, Email: "private-reporter@example.test"},
	}
	handler := PortalFeedbackHandler(pool, true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only test-controlled identities enter context. This does not test JWT
		// verification, which has its own router/auth contract suite.
		id, ok := identities[r.Header.Get("X-Test-Identity")]
		if ok {
			r = r.WithContext(portalauth.WithIdentity(r.Context(), id))
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 10 * time.Second
	request := func(who, method, query string, fields map[string]string) (int, http.Header, []byte) {
		t.Helper()
		var reader io.Reader
		var ct string
		if fields != nil {
			reader, ct = feedbackMultipart(t, fields)
		}
		req, err := http.NewRequest(method, server.URL+"/v1/portal/feedback"+query, reader)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Test-Identity", who)
		req.Header.Set("Content-Type", ct)
		req.Header.Set("X-Tenant-ID", b) // must never override context tenant A
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, resp.Header, raw
	}
	type expectedItem struct {
		typ, category, door, title string
		created, changed           time.Time
	}
	expected := map[string]map[string]expectedItem{"a": {}, "b": {}, "empty": {}}
	valid := []pat2347Form{{"support", "not_working", ""}, {"support", "findings_or_reports", ""}, {"support", "account_billing", ""}, {"design", "", ""}, {"feature", "", ""}, {"bug", "", "high"}, {"question", "", ""}}
	for _, who := range []string{"a", "b"} {
		for _, form := range valid {
			title := "Request " + who + " " + form.typ + " " + form.category
			fields := map[string]string{"type": form.typ, "category": form.category, "severity": form.severity, "title": title, "description": "private description " + who, "tenant_id": b, "reporter_email": "forged@example.test", "route": "/devices?private=yes#private"}
			status, header, raw := request(who, http.MethodPost, "?tenant_id="+b, fields)
			if status != http.StatusCreated || !strings.HasPrefix(header.Get("Content-Type"), "application/json") {
				t.Fatalf("POST %s %+v = %d: %s", who, form, status, raw)
			}
			var result map[string]string
			if err := json.Unmarshal(raw, &result); err != nil || len(result) != 2 || result["reference"] == "" || result["status"] != "received" {
				t.Fatalf("POST result: %s", raw)
			}
			var storedTenant, reporter, typ, category, severity, route string
			var created, changed time.Time
			if err := pool.QueryRow(ctx, `SELECT tenant_id::text,reporter_email,type,COALESCE(category,''),COALESCE(severity,''),route,created_at,status_changed_at FROM feedback WHERE reference=$1`, result["reference"]).Scan(&storedTenant, &reporter, &typ, &category, &severity, &route, &created, &changed); err != nil {
				t.Fatal(err)
			}
			if storedTenant != identities[who].TenantID || reporter != identities[who].Email || typ != form.typ || category != form.category || severity != form.severity || route != "/devices" {
				t.Fatalf("POST did not preserve authenticated tenant/reporter and form: %s %s %s %s %s %s", storedTenant, reporter, typ, category, severity, route)
			}
			door := "feedback"
			if form.typ == "support" || form.typ == "bug" || form.typ == "question" {
				door = "support"
			}
			expected[who][result["reference"]] = expectedItem{typ: form.typ, category: form.category, door: door, title: title, created: created, changed: changed}
		}
	}
	for _, form := range pat2347RefusedForms() {
		status, header, raw := request("a", http.MethodPost, "", map[string]string{"type": form.typ, "category": form.category, "severity": form.severity, "title": "Valid title", "description": "Private description"})
		pat2347Invalid(t, status, header, raw)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM feedback WHERE tenant_id=$1::uuid`, a).Scan(&count); err != nil || count != len(valid) {
		t.Fatalf("invalid POST persisted: count=%d err=%v", count, err)
	}
	for _, who := range []string{"a", "b", "empty"} {
		for _, query := range []string{"", "?door=", "?door=support", "?door=feedback", "?tenant_id=" + b} {
			t.Run(who+query, func(t *testing.T) {
				status, header, raw := request(who, http.MethodGet, query, nil)
				if status != http.StatusOK || !strings.HasPrefix(header.Get("Content-Type"), "application/json") {
					t.Fatalf("GET = %d: %s", status, raw)
				}
				for _, private := range []string{"private-reporter", "forged@example.test", "private description", "reporter_email", "tenant_id", "description", "user_agent", "linear_state", "sync_state"} {
					if strings.Contains(string(raw), private) {
						t.Errorf("public list leaks %q: %s", private, raw)
					}
				}
				var rows []map[string]json.RawMessage
				if err := json.Unmarshal(raw, &rows); err != nil || rows == nil {
					t.Fatalf("GET must be an array: %s", raw)
				}
				door := ""
				if query == "?door=support" {
					door = "support"
				}
				if query == "?door=feedback" {
					door = "feedback"
				}
				want := 0
				for _, item := range expected[who] {
					if door == "" || item.door == door {
						want++
					}
				}
				if len(rows) != want {
					t.Fatalf("GET %s: rows=%d want=%d: %s", query, len(rows), want, raw)
				}
				seen := map[string]bool{}
				var previous time.Time
				for _, row := range rows {
					value := func(key string) string {
						var s string
						if err := json.Unmarshal(row[key], &s); err != nil {
							t.Fatalf("%s missing or wrong JSON type: %s", key, raw)
						}
						return s
					}
					ref := value("reference")
					item, ok := expected[who][ref]
					if !ok || seen[ref] {
						t.Fatalf("foreign or duplicate reference %s: %s", ref, raw)
					}
					seen[ref] = true
					keys := 7
					if item.category != "" {
						keys++
						if value("category") != item.category {
							t.Errorf("category changed: %s", raw)
						}
					} else if _, exists := row["category"]; exists {
						t.Errorf("non-support category must be absent: %s", raw)
					}
					if len(row) != keys {
						t.Errorf("unexpected public fields: %s", raw)
					}
					if value("type") != item.typ || value("door") != item.door || value("title") != item.title || value("status") != "received" || (door != "" && item.door != door) {
						t.Errorf("public projection changed: %s", raw)
					}
					var created, changed time.Time
					if err := json.Unmarshal(row["created_at"], &created); err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(row["last_status_change"], &changed); err != nil {
						t.Fatal(err)
					}
					if !created.Equal(item.created) || !changed.Equal(item.changed) {
						t.Errorf("timestamps changed: %s", raw)
					}
					if !previous.IsZero() && created.After(previous) {
						t.Errorf("list no longer newest first: %s", raw)
					}
					previous = created
				}
			})
		}
	}
}
