package cpepropose

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"patched.im/api/internal/httpretry"
)

func cpeProduct(name string, deprecated bool, title string) map[string]any {
	return map[string]any{"cpe": map[string]any{
		"cpeName": name, "deprecated": deprecated,
		"titles": []map[string]string{{"title": title, "lang": "en"}},
	}}
}

func TestDictionarySearchParsesRanksAndFilters(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if r.URL.Query().Get("keywordSearch") != "Acme Widget" || r.Header.Get("apiKey") != "nvd-test" {
			t.Errorf("request = %s apiKey=%q", r.URL.RawQuery, r.Header.Get("apiKey"))
		}
		if n == 1 {
			// NVD's load-shedding shape: a 200 that claims results but has none.
			_ = json.NewEncoder(w).Encode(map[string]any{"totalResults": 7, "products": []any{}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"totalResults": 6, "products": []any{
			cpeProduct("cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*", false, "Acme Widget 1.0"),
			cpeProduct("cpe:2.3:a:acme:widget:2.0:*:*:*:*:*:*:*", false, "Acme Widget 2.0"),
			cpeProduct("cpe:2.3:a:acme:widget_old:1.0:*:*:*:*:*:*:*", true, "Acme Widget Old"),
			cpeProduct(`cpe:2.3:a:acme\:inc:widget\+\+:1.0:*:*:*:*:*:*:*`, false, "Escaped"),
			cpeProduct("cpe:2.3:o:acme:widget_os:1.0:*:*:*:*:*:*:*", false, "An OS, not an application"),
			cpeProduct("cpe:2.3:h:acme:widget_box:1.0:*:*:*:*:*:*:*", false, "Hardware"),
		}})
	}))
	defer srv.Close()
	d := &Dictionary{BaseURL: srv.URL, APIKey: "nvd-test", HTTP: srv.Client(), Sleep: noSleep}
	got, err := d.Search(context.Background(), "Acme Widget")
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2 (the load-shed page retried)", calls.Load())
	}
	var keys []string
	for _, c := range got {
		keys = append(keys, c.Key())
	}
	want := []string{"acme:widget", `acme\:inc:widget\+\+`, "acme:widget_old"}
	if len(keys) != len(want) {
		t.Fatalf("candidates = %v, want %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("candidates = %v, want %v", keys, want)
		}
	}
	if got[0].Entries != 2 || got[2].Deprecated != true || got[0].Title != "Acme Widget 1.0" {
		t.Fatalf("candidate details = %+v", got)
	}
}

func TestDictionarySearchFatalOnClientError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	d := &Dictionary{BaseURL: srv.URL, HTTP: srv.Client(), Sleep: noSleep}
	_, err := d.Search(context.Background(), "x")
	var he *httpretry.HTTPError
	if !errors.As(err, &he) || he.StatusCode != 404 || calls.Load() != 1 {
		t.Fatalf("err = %v after %d calls, want one fatal 404", err, calls.Load())
	}
	if got, err := d.Search(context.Background(), "  "); err != nil || got != nil || calls.Load() != 1 {
		t.Fatalf("empty keyword made a request or returned %v, %v", got, err)
	}
}

func TestParseCPE23Name(t *testing.T) {
	part, v, p, ok := parseCPE23Name(`cpe:2.3:a:Microsoft:Visual_Studio_Code:1.0:*:*:*:*:*:*:*`)
	if !ok || part != "a" || v != "microsoft" || p != "visual_studio_code" {
		t.Fatalf("got %s %s %s %v", part, v, p, ok)
	}
	for _, bad := range []string{"cpe:/a:x:y", "cpe:2.3:a:*:y:1", "cpe:2.3:a:x", ""} {
		if _, _, _, ok := parseCPE23Name(bad); ok {
			t.Errorf("parseCPE23Name(%q) accepted", bad)
		}
	}
}
