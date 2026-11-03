package lifecycle

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func noSleep(context.Context, time.Duration) error { return nil }

func testFetcher(url string) *Fetcher {
	return &Fetcher{BaseURL: url, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Sleep: noSleep,
		RequestTimeout: 5 * time.Second, SlugBudget: 10 * time.Second}
}

// The fixtures are the live API responses captured on 2026-09-25.
func TestParseProductLiveShape(t *testing.T) {
	p, err := ParseProduct("macos", "https://example/api/macos/", fixture(t, "macos.json"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Label != "Apple macOS" || p.HTMLURL != "https://endoflife.date/macos" {
		t.Errorf("label/html = %q %q", p.Label, p.HTMLURL)
	}
	byName := map[string]Cycle{}
	for _, c := range p.Cycles {
		byName[c.Name] = c
	}
	if c := byName["14"]; c.EOLDate == nil || c.EOLDate.Format("2006-01-02") != "2026-09-14" || c.IsEOL == nil || !*c.IsEOL {
		t.Errorf("macOS 14 = %+v, want eol 2026-09-14 and isEol", c)
	}
	if c := byName["26"]; c.EOLDate != nil || c.IsEOL == nil || *c.IsEOL || c.LatestVersion != "26.7" {
		t.Errorf("macOS 26 = %+v, want no eol date, maintained, latest 26.7", c)
	}
	if _, ok := byName["10.15"]; !ok {
		t.Error("macOS 10.15 missing")
	}

	w, err := ParseProduct("windows", "https://example/api/windows/", fixture(t, "windows.json"))
	if err != nil {
		t.Fatal(err)
	}
	var w22 *Cycle
	for i := range w.Cycles {
		if w.Cycles[i].Name == "10-22h2" {
			w22 = &w.Cycles[i]
		}
	}
	if w22 == nil || w22.LatestVersion != "10.0.19045" || w22.ExtendedSupportDate == nil ||
		w22.ExtendedSupportDate.Format("2006-01-02") != "2028-10-10" || w22.SupportDate == nil {
		t.Errorf("windows 10-22h2 = %+v", w22)
	}
	// The real Windows data resolves a Pro device on 24H2 and refuses an
	// unreported edition.
	if m := MatchWindows(w.Cycles, "10.0.26100", "", "Microsoft Windows 11 Pro"); m.Cycle == nil || m.Cycle.Name != "11-24h2-w" {
		t.Errorf("real data: 24H2 Pro = %+v", m)
	}
	if m := MatchWindows(w.Cycles, "10.0.26100", "", ""); m.Reason != ReasonEditionUnknown {
		t.Errorf("real data: 24H2 unknown edition = %+v", m)
	}
}

func TestParseProductFailsClosed(t *testing.T) {
	cases := map[string]string{
		"not json":       `<html>`,
		"schema 2":       `{"schema_version":"2.0.0","result":{"releases":[{"name":"1"}]}}`,
		"no releases":    `{"schema_version":"1.2.1","result":{"releases":[]}}`,
		"bad date":       `{"schema_version":"1.2.1","result":{"releases":[{"name":"1","eolFrom":"soon"}]}}`,
		"empty name":     `{"schema_version":"1.2.1","result":{"releases":[{"name":" "}]}}`,
		"duplicate name": `{"schema_version":"1.2.1","result":{"releases":[{"name":"1"},{"name":"1"}]}}`,
	}
	for name, body := range cases {
		if _, err := ParseProduct("x", "u", []byte(body)); err == nil {
			t.Errorf("%s: accepted, want refused", name)
		}
	}
	// A links.html outside endoflife.date is not trusted as the source URL.
	p, err := ParseProduct("x", "u", []byte(`{"schema_version":"1.2.1","result":{"links":{"html":"https://evil.example/"},"releases":[{"name":"1"}]}}`))
	if err != nil || p.HTMLURL != "https://endoflife.date/x" {
		t.Errorf("html url = %q, %v", p.HTMLURL, err)
	}
}

func TestFetchRetriesAndSendsOnlyTheSlug(t *testing.T) {
	var calls atomic.Int32
	body := fixture(t, "macos.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if r.URL.Path != "/api/v1/products/macos/" || r.URL.RawQuery != "" || r.Method != http.MethodGet {
			t.Errorf("request %s %s?%s: want GET of the slug path only", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("request carried credentials")
		}
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "patched-lifecycle-sync/") {
			t.Errorf("user agent = %q", r.Header.Get("User-Agent"))
		}
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	p, err := testFetcher(srv.URL+"/api/v1/products").Fetch(context.Background(), "macos")
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || len(p.Cycles) == 0 {
		t.Errorf("calls = %d, cycles = %d; want a retry then success", calls.Load(), len(p.Cycles))
	}
}

func TestFetchNotFoundIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	if _, err := testFetcher(srv.URL+"/").Fetch(context.Background(), "microsoft-edge"); err == nil {
		t.Fatal("404 accepted")
	}
	if calls.Load() != 1 {
		t.Errorf("calls = %d, want 1 (a 404 is not transient)", calls.Load())
	}
}

func TestFetchSizeCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":"1.2.1","result":{"releases":[{"name":"` + strings.Repeat("a", 5000) + `"}]}}`))
	}))
	defer srv.Close()
	f := testFetcher(srv.URL + "/")
	f.MaxBodyBytes = 1024
	if _, err := f.Fetch(context.Background(), "big"); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("err = %v, want the size cap to refuse", err)
	}
}

func TestFetchRefusesOffHostRedirect(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("followed a redirect to another host")
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/x/", http.StatusMovedPermanently)
	}))
	defer srv.Close()
	if _, err := testFetcher(srv.URL+"/").Fetch(context.Background(), "macos"); err == nil {
		t.Fatal("off-host redirect accepted")
	}
}

func TestFetchRejectsBadSlug(t *testing.T) {
	for _, s := range []string{"", "../etc", "a/b", "UPPER", "a b"} {
		if _, err := testFetcher("http://127.0.0.1:1/").Fetch(context.Background(), s); err == nil {
			t.Errorf("slug %q accepted", s)
		}
	}
}
