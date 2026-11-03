//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

// These acceptance tests use the existing HTTP integration server and real PG
// rows. They intentionally fail with HTTP 404 until the route is implemented
// and mounted. They do not instantiate a future handler or change the router.
const pat1966Path = "/admin/service-exceptions"
const pat1966Private = "PAT1966_PRIVATE_SENTINEL recipient@example.invalid /private/report.pdf"

type pat1966Feed struct {
	ObservedAt time.Time                    `json:"observed_at"`
	Coverage   string                       `json:"coverage"`
	Checks     []map[string]json.RawMessage `json:"checks"`
	Exceptions []map[string]json.RawMessage `json:"exceptions"`
}

func pat1966Get(t *testing.T) pat1966Feed {
	t.Helper()
	resp, err := http.Get(env.internalSrv.URL + pat1966Path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200 (body %q)", pat1966Path, resp.StatusCode, raw)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		t.Fatal("feed must be JSON")
	}
	if strings.Contains(string(raw), pat1966Private) || strings.Contains(string(raw), "PAT1966_PRIVATE_SENTINEL") {
		t.Fatal("private job output/error leaked")
	}
	var f pat1966Feed
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Checks == nil || f.Exceptions == nil {
		t.Fatal("checks and exceptions must always be arrays, not null or missing")
	}
	if f.ObservedAt.IsZero() || f.ObservedAt.After(time.Now().Add(time.Second)) || !strings.HasSuffix(f.ObservedAt.Format(time.RFC3339), "Z") {
		t.Fatalf("invalid observed_at %s", f.ObservedAt)
	}
	for _, e := range f.Exceptions {
		pat1966Times(t, e, "since", "evidence_at")
		link := pat1966String(e, "deep_link")
		u, err := url.Parse(link)
		if err != nil || u.IsAbs() || u.Host != "" || u.Path != "/console" || u.RawQuery != "" || u.Fragment == "" || strings.ContainsAny(link, "\\\r\n") {
			t.Errorf("exception must link to a relative existing console destination: %q", link)
		}
	}

	return f
}

func pat1966String(m map[string]json.RawMessage, key string) string {
	var s string
	_ = json.Unmarshal(m[key], &s)
	return s
}

func pat1966Check(t *testing.T, f pat1966Feed, id string) map[string]json.RawMessage {
	t.Helper()
	for _, c := range f.Checks {
		if pat1966String(c, "id") == id {
			return c
		}
	}
	t.Fatalf("missing check %s", id)
	return nil
}

func pat1966Times(t *testing.T, m map[string]json.RawMessage, keys ...string) {
	t.Helper()
	for _, k := range keys {
		raw, exists := m[k]
		if !exists {
			t.Errorf("missing nullable timestamp %s", k)
			continue
		}
		if string(raw) == "null" {
			continue
		}
		var v time.Time
		if err := json.Unmarshal(raw, &v); err != nil || v.IsZero() {
			t.Errorf("invalid %s: %s", k, raw)
			continue
		}
		if k != "next_expected_at" && v.After(time.Now().Add(time.Second)) {
			t.Errorf("future evidence in %s: %s", k, raw)
		}
	}
}

func TestPAT1966Contract(t *testing.T) {
	f := pat1966Get(t)
	if f.Coverage != "partial" {
		t.Fatalf("unsupported sources require partial coverage, got %q", f.Coverage)
	}
	ids := []string{"outgoing_email", "scheduled_jobs", "customer_access", "device_reports", "assurance_processing", "vulnerability_data", "reports", "backups", "server_health", "version_checks", "billing"}
	seen := map[string]bool{}
	for _, c := range f.Checks {
		id := pat1966String(c, "id")
		if id == "" || seen[id] {
			t.Errorf("empty or duplicate check id %q", id)
		}
		seen[id] = true
		for _, k := range []string{"name", "explanation", "source", "scope", "reason", "next_action"} {
			if pat1966String(c, k) == "" {
				t.Errorf("check %s missing plain-language %s", id, k)
			}
		}
		if a := pat1966String(c, "availability"); a != "available" && a != "degraded" && a != "unavailable" {
			t.Errorf("invalid availability %q", a)
		}
		if r := pat1966String(c, "result"); r != "ok" && r != "failed" && r != "stale" && r != "unknown" && r != "unavailable" {
			t.Errorf("invalid result %q", r)
		}
		pat1966Times(t, c, "checked_at", "last_success_at", "next_expected_at")
	}
	for _, id := range ids {
		pat1966Check(t, f, id)
	}
	for _, e := range f.Exceptions {
		for _, k := range []string{"id", "check_id", "scope", "reason", "deep_link"} {
			if pat1966String(e, k) == "" {
				t.Errorf("exception missing %s", k)
			}
		}
		if !seen[pat1966String(e, "check_id")] {
			t.Error("exception references absent check")
		}
		if _, ok := e["tenant_id"]; !ok {
			t.Error("missing nullable tenant_id")
		}
		pat1966Times(t, e, "since", "evidence_at")
		if string(e["evidence_at"]) == "null" {
			t.Error("exception needs actual source evidence time")
		}
		link := pat1966String(e, "deep_link")
		u, err := url.Parse(link)
		if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(link, "/") || strings.HasPrefix(link, "//") || strings.ContainsAny(link, "\\\r\n") {
			t.Errorf("unsafe console deep link %q", link)
		}
	}
}

func TestPAT1966UnsupportedSources(t *testing.T) {
	// No provider or dashboard-local evidence is provisioned in this API fixture.
	// Report records are frozen pending (0126), not platform delivery telemetry.
	for _, id := range []string{"outgoing_email", "customer_access", "billing", "reports", "assurance_processing", "vulnerability_data", "version_checks"} {
		t.Run(id, func(t *testing.T) {
			f := pat1966Get(t)
			c := pat1966Check(t, f, id)
			if pat1966String(c, "availability") != "unavailable" || pat1966String(c, "result") != "unavailable" {
				t.Fatalf("%s without evidence must be unavailable, not healthy zero: %s", id, c)
			}
			for _, k := range []string{"reason", "next_action"} {
				if pat1966String(c, k) == "" {
					t.Errorf("%s missing %s", id, k)
				}
			}
			for _, k := range []string{"last_success_at", "next_expected_at"} {
				if string(c[k]) != "null" {
					t.Errorf("%s invented %s", id, k)
				}
			}
			for _, e := range f.Exceptions {
				if pat1966String(e, "check_id") == id {
					t.Errorf("unsupported %s manufactured an exception", id)
				}
			}
		})
	}
}

func pat1966Exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := env.pool.Exec(context.Background(), query, args...); err != nil {
		t.Fatal(err)
	}
}

func pat1966Job(t *testing.T, job, status string, at time.Time) time.Time {
	t.Helper()
	finished := at.Add(time.Minute).Truncate(time.Microsecond)
	var id int64
	err := env.pool.QueryRow(context.Background(), `INSERT INTO scheduled_job_runs (job_name, started_at, finished_at, status, output, error_msg) VALUES ($1,$2,$3,$4,$5,$5) RETURNING id`, job, at, finished, status, pat1966Private).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pat1966Exec(t, `DELETE FROM scheduled_job_runs WHERE id=$1`, id) })
	return finished
}

func pat1966JobExceptions(f pat1966Feed, job string) []map[string]json.RawMessage {
	var out []map[string]json.RawMessage
	for _, e := range f.Exceptions {
		raw, _ := json.Marshal(e)
		if pat1966String(e, "check_id") == "scheduled_jobs" && strings.Contains(string(raw), job) {
			out = append(out, e)
		}
	}
	return out
}

func TestPAT1966ActiveJobFailureAndRecovery(t *testing.T) {
	for _, status := range []string{"failed", "warning"} {
		t.Run(status, func(t *testing.T) {
			// Registry-known active job; raw output is deliberately private.
			finished := pat1966Job(t, "health_signals_recompute", status, time.Now().Add(-2*time.Hour))
			f := pat1966Get(t)
			failures := pat1966JobExceptions(f, "health_signals_recompute")
			if len(failures) != 1 {
				t.Fatalf("want one current active-job exception, got %d", len(failures))
			}
			var evidence time.Time
			if err := json.Unmarshal(failures[0]["evidence_at"], &evidence); err != nil || !evidence.Equal(finished) {
				t.Errorf("exception must use actual finished_at %s", finished)
			}
			// Start time is not a proven failure onset. Null explicitly preserves that uncertainty.
			if string(failures[0]["since"]) != "null" {
				t.Error("job start must not invent failure onset")
			}
			if string(pat1966Check(t, f, "scheduled_jobs")["next_expected_at"]) != "null" {
				t.Error("free-text schedules cannot establish next_expected_at")
			}
			pat1966Job(t, "health_signals_recompute", "success", time.Now().Add(-time.Hour))
			if n := len(pat1966JobExceptions(pat1966Get(t), "health_signals_recompute")); n != 0 {
				t.Fatalf("latest success must clear observed failure, got %d", n)
			}
		})
	}
}

func TestPAT1966ActiveJobStaleObservation(t *testing.T) {
	// Existing daily-job UI heuristic is 36 hours; use a safely older observation.
	finished := pat1966Job(t, "health_signals_recompute", "success", time.Now().Add(-40*time.Hour))
	f := pat1966Get(t)
	failures := pat1966JobExceptions(f, "health_signals_recompute")
	if len(failures) != 1 {
		t.Fatalf("40-hour active-job observation must be stale, got %d exceptions", len(failures))
	}
	var evidence time.Time
	if err := json.Unmarshal(failures[0]["evidence_at"], &evidence); err != nil || !evidence.Equal(finished) {
		t.Error("stale exception must retain actual observation time")
	}
	if string(failures[0]["since"]) != "null" {
		t.Error("overdue observation cannot invent failure onset")
	}
}

func TestPAT1966NonActiveJobHistoryExcluded(t *testing.T) {
	for _, job := range []string{"installomator_sync", "mirror_pipeline", "mirror_pipeline_windows"} {
		t.Run(job, func(t *testing.T) {
			pat1966Job(t, job, "failed", time.Now().Add(-72*time.Hour))
			if n := len(pat1966JobExceptions(pat1966Get(t), job)); n != 0 {
				t.Fatalf("retired/quarantined history created %d operating exceptions", n)
			}
		})
	}
}

func TestPAT1966NoHistoryIsUnknown(t *testing.T) {
	// Other fixture tests clean up only their own rows; this test needs no deletion.
	f := pat1966Get(t)
	c := pat1966Check(t, f, "scheduled_jobs")
	if pat1966String(c, "result") == "ok" {
		t.Fatal("no scheduled-job observations cannot be healthy zero")
	}
	c = pat1966Check(t, f, "device_reports")
	if pat1966String(c, "result") == "ok" {
		t.Fatal("empty ingestion cannot prove all devices reporting")
	}
	c = pat1966Check(t, f, "backups")
	if pat1966String(c, "result") == "ok" {
		t.Fatal("no backup heartbeat cannot prove backup/restore health")
	}
}

func TestPAT1966CustomerReceiptScope(t *testing.T) {
	ids := map[string]string{}
	at := time.Now().Add(-72 * time.Hour).Truncate(time.Microsecond)
	for _, kind := range []string{"customer", "internal", "revoked"} {
		id, _, _, err := createTestTenant(env.internalSrv.URL, "pat1966-"+kind+"-"+randomHex(4))
		if err != nil {
			t.Fatal(err)
		}
		ids[kind] = id
		tenantKind := "customer"
		if kind == "internal" {
			tenantKind = "internal"
		}
		pat1966Exec(t, `UPDATE tenants SET tenant_kind=$2 WHERE id=$1::uuid`, id, tenantKind)
		if kind == "revoked" {
			pat1966Exec(t, `UPDATE tenants SET revoked_at=now() WHERE id=$1::uuid`, id)
		}
		pat1966Exec(t, `INSERT INTO raw_payloads (tenant_id, received_at, body) VALUES ($1::uuid,$2,$3::jsonb)`, id, at, `{"private":"PAT1966_PRIVATE_SENTINEL"}`)
		t.Cleanup(func() {
			pat1966Exec(t, `DELETE FROM raw_payloads WHERE tenant_id=$1::uuid`, id)
			pat1966Exec(t, `DELETE FROM tenants WHERE id=$1::uuid`, id)
		})
	}
	f := pat1966Get(t)
	found := false
	for _, e := range f.Exceptions {
		tenant := pat1966String(e, "tenant_id")
		if tenant == ids["internal"] || tenant == ids["revoked"] {
			t.Fatal("non-customer or revoked tenant leaked into operating exceptions")
		}
		if tenant == ids["customer"] && pat1966String(e, "check_id") == "device_reports" {
			found = true
			var evidence time.Time
			if err := json.Unmarshal(e["evidence_at"], &evidence); err != nil || !evidence.Equal(at) {
				t.Error("tenant freshness must retain actual receipt time")
			}
			if string(e["since"]) != "null" {
				t.Error("last receipt is not proven failure onset")
			}
		}
	}
	if !found {
		t.Fatal("72-hour observed customer receipt gap must produce a tenant-scoped exception")
	}
}

func pat1966Counts(t *testing.T) []int64 {
	t.Helper()
	var counts []int64
	for _, table := range []string{"scheduled_job_runs", "raw_payloads", "tenants", "report_records"} {
		var n int64
		if err := env.pool.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		counts = append(counts, n)
	}
	return counts
}

func TestPAT1966ReadOnlyAndDeterministic(t *testing.T) {
	pat1966Job(t, "api01_backup", "failed", time.Now().Add(-time.Hour))
	before := pat1966Counts(t)
	a, b := pat1966Get(t), pat1966Get(t)
	if !reflect.DeepEqual(before, pat1966Counts(t)) {
		t.Fatal("GET changed source row counts")
	}
	for i := range a.Checks {
		delete(a.Checks[i], "checked_at")
	}
	for i := range b.Checks {
		delete(b.Checks[i], "checked_at")
	}
	if !reflect.DeepEqual(a.Checks, b.Checks) || !reflect.DeepEqual(a.Exceptions, b.Exceptions) {
		t.Fatal("identical evidence must have deterministic ordering and content")
	}
}
