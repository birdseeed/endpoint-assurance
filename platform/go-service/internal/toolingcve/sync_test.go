package toolingcve

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMarkPackageAssessmentsPendingPreservesAllErrors(t *testing.T) {
	cause := errors.New("OSV unavailable")
	persistA := errors.New("persist a")
	persistB := errors.New("persist b")
	attempts := 0
	err := markPackageAssessmentsPending([]input{{Ecosystem: "npm", Identity: "a"}, {Ecosystem: "PyPI", Identity: "b"}}, cause, func(in input) error {
		attempts++
		if in.Identity == "a" {
			return persistA
		}
		return persistB
	})
	if attempts != 2 || !errors.Is(err, cause) || !errors.Is(err, persistA) || !errors.Is(err, persistB) {
		t.Fatalf("attempts=%d err=%v", attempts, err)
	}
}

func TestEcosystemAndVersionSafety(t *testing.T) {
	for _, tc := range []struct{ runner, want string }{{"npx", "npm"}, {"pnpm", "npm"}, {"uvx", "PyPI"}, {"pipx", "PyPI"}, {"docker", ""}} {
		r := tc.runner
		if got := ecosystemForRunner(&r); got != tc.want {
			t.Errorf("%s: %q want %q", tc.runner, got, tc.want)
		}
	}
	for _, v := range []string{"1.2", "v1.2.3", "1.2.3.4"} {
		if !safeLlamaVersion(v) {
			t.Errorf("safe %q rejected", v)
		}
	}
	for _, v := range []string{"b1234", "1.2+build", "1_2", "unknown", ""} {
		if safeLlamaVersion(v) {
			t.Errorf("unsafe %q accepted", v)
		}
	}
}

func TestModelsCannotBecomeInputs(t *testing.T) {
	// loadInputs' switch deliberately has no local_model case. Keep the
	// identity vocabulary pin explicit so a later refactor cannot quietly map
	// model files to package or CPE subjects.
	if ecosystemForIdentity("local_model") != "" {
		t.Fatal("model file acquired an ecosystem")
	}
}

func TestOSVProvenanceDoesNotRelabelGHSA(t *testing.T) {
	aliases := []string{"GHSA-abcd-1234-5678"}
	if got := canonicalCVE(aliases); got != "" {
		t.Fatalf("GHSA relabelled as CVE: %q", got)
	}
	aliases = append(aliases, "CVE-2026-12345")
	if got := canonicalCVE(aliases); got != "CVE-2026-12345" {
		t.Fatalf("canonical CVE=%q", got)
	}
}

func TestOSVQueryBatchPagination(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != osvUserAgent {
			t.Fatalf("User-Agent=%q", got)
		}
		if r.URL.Path != "/v1/querybatch" {
			http.NotFound(w, r)
			return
		}
		calls++
		var req osvBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			if len(req.Queries) != 2 {
				t.Fatalf("first batch queries=%d", len(req.Queries))
			}
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-first"}],"next_page_token":"page-2"},{"vulns":[{"id":"PYSEC-only"}]}]}`))
			return
		}
		if len(req.Queries) != 1 || req.Queries[0].PageToken != "page-2" {
			t.Fatalf("pagination request=%+v", req.Queries)
		}
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-9999"}]}]}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL)
	got, err := c.queryBatch(context.Background(), []input{{Ecosystem: "npm", Package: "a", Version: "1"}, {Ecosystem: "PyPI", Package: "b", Version: "2"}})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(got[0]) != 2 || got[0][0] != "GHSA-first" || got[0][1] != "CVE-2026-9999" || len(got[1]) != 1 || got[1][0] != "PYSEC-only" {
		t.Fatalf("calls=%d got=%v", calls, got)
	}
}

func TestOSVClientPackageKeysMatchWireContract(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		var queries []map[string]json.RawMessage
		if err := json.Unmarshal(body["queries"], &queries); err != nil || len(queries) != 1 {
			t.Errorf("invalid queries: %s", body["queries"])
			http.Error(w, "invalid queries", http.StatusBadRequest)
			return
		}
		var pkg map[string]string
		if err := json.Unmarshal(queries[0]["package"], &pkg); err != nil {
			t.Error(err)
			http.Error(w, "invalid package", http.StatusBadRequest)
			return
		}
		if len(pkg) != 2 || pkg["name"] != "jinja2" || pkg["ecosystem"] != "PyPI" {
			t.Errorf("package wire keys must be name/ecosystem: %v", pkg)
			http.Error(w, "invalid query", http.StatusBadRequest)
			return
		}
		if string(queries[0]["version"]) != `"3.1.4"` {
			t.Errorf("version=%s", queries[0]["version"])
		}
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			if _, exists := queries[0]["page_token"]; exists {
				t.Error("initial query has page_token")
			}
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-first"}],"next_page_token":"page-2"}]}`))
			return
		}
		if string(queries[0]["page_token"]) != `"page-2"` {
			t.Errorf("page_token=%s", queries[0]["page_token"])
		}
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-second"}]}]}`))
	}))
	defer srv.Close()
	got, err := NewClient(srv.URL).queryBatch(context.Background(), []input{{Ecosystem: "PyPI", Package: "jinja2", Version: "3.1.4"}})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(got) != 1 || len(got[0]) != 2 || got[0][0] != "GHSA-first" || got[0][1] != "GHSA-second" {
		t.Fatalf("calls=%d results=%v", calls, got)
	}
}

func TestOSVBaseURLValidation(t *testing.T) {
	for _, raw := range []string{"https://api.osv.dev", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		if err := NewClient(raw).configErr; err != nil {
			t.Errorf("%s rejected: %v", raw, err)
		}
	}
	for _, raw := range []string{"http://osv.example.com", "ftp://api.osv.dev", "api.osv.dev", "file:///tmp/osv"} {
		client := NewClient(raw)
		if client.configErr == nil {
			t.Errorf("%s accepted", raw)
			continue
		}
		if _, err := client.queryBatch(context.Background(), []input{{Ecosystem: "npm", Package: "x", Version: "1"}}); err == nil {
			t.Errorf("%s reached request path without configuration error", raw)
		}
	}
	if err := NewClient("").configErr; err != nil {
		t.Fatalf("production default rejected: %v", err)
	}
}

func TestMCPUnsupportedEcosystemReasonTakesPrecedence(t *testing.T) {
	if got := mcpResolutionReason("", "server", false); got != "mcp_ecosystem_unsupported" {
		t.Fatalf("reason=%q", got)
	}
	if got := mcpResolutionReason("npm", "server", false); got != "mcp_exact_version_unavailable" {
		t.Fatalf("reason=%q", got)
	}
	if queueSnapshotLimit != 10000 {
		t.Fatalf("queue snapshot limit=%d", queueSnapshotLimit)
	}
}

func TestOSVSeverityDeterministic(t *testing.T) {
	r := osvRecord{Database: json.RawMessage(`{"severity":"MODERATE"}`), Affected: []osvAffected{
		{EcosystemSpecific: json.RawMessage(`{"severity":"HIGH"}`)},
		{DatabaseSpecific: json.RawMessage(`{"severity":"critical"}`)},
	}}
	if got := osvSeverity(r); got != "CRITICAL" {
		t.Fatalf("severity=%q", got)
	}
	if got := osvSeverity(osvRecord{}); got != "UNKNOWN" {
		t.Fatalf("missing severity=%q", got)
	}
}

func TestSeverityRankTreatsUnexpectedAsUnknown(t *testing.T) {
	if severityRank("vendor-special") != severityRank("UNKNOWN") {
		t.Fatalf("unexpected rank=%d unknown rank=%d", severityRank("vendor-special"), severityRank("UNKNOWN"))
	}
	if severityRank("LOW") <= severityRank("vendor-special") {
		t.Fatalf("LOW rank=%d did not outrank unexpected=%d", severityRank("LOW"), severityRank("vendor-special"))
	}
	if severityRank("") != 0 {
		t.Fatalf("empty sentinel rank=%d", severityRank(""))
	}
}

func TestOSVTopLevelCVSSSeverityAndScore(t *testing.T) {
	for _, tc := range []struct {
		name, vector, wantSeverity string
		wantScore                  float64
	}{
		{"cvss31", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", 9.8},
		{"cvss40", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CRITICAL", 9.3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			severity, score := osvSeverityAndScore(osvRecord{Severity: []osvSeverityEntry{{Type: "CVSS", Score: tc.vector}}})
			if severity != tc.wantSeverity || score == nil || *score != tc.wantScore {
				t.Fatalf("severity=%q score=%v, want %q %.1f", severity, score, tc.wantSeverity, tc.wantScore)
			}
		})
	}
	severity, score := osvSeverityAndScore(osvRecord{Severity: []osvSeverityEntry{{Type: "other", Score: "vendor-high"}}})
	if severity != "UNKNOWN" || score != nil {
		t.Fatalf("unsupported vector must remain honest: severity=%q score=%v", severity, score)
	}
}

func TestPyPINormalisation(t *testing.T) {
	if got := normalisePackage("PyPI", "Foo..Bar__baz"); got != "foo-bar-baz" {
		t.Fatalf("got %q", got)
	}
}
