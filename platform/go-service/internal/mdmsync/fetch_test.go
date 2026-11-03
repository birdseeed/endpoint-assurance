package mdmsync

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"patched.im/api/internal/msgraph"
)

// newTestGraphClient wires a real msgraph.Client to a token httptest.Server
// that always succeeds and a Graph httptest.Server driven by graphHandler,
// mirroring internal/msgraph's own newTestClient helper (unexported there,
// so reimplemented minimally here against msgraph's exported surface).
func newTestGraphClient(t *testing.T, graphHandler http.HandlerFunc) *msgraph.Client {
	t.Helper()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	}))
	t.Cleanup(tokenServer.Close)

	graphServer := httptest.NewServer(graphHandler)
	t.Cleanup(graphServer.Close)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mdmsync-test-fixture"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}

	ts := msgraph.NewTokenSource("client-id", msgraph.NewCertificate(cert, key))
	ts.AuthorityBase = tokenServer.URL

	c := msgraph.NewClient(ts)
	c.BaseURL = graphServer.URL
	return c
}

func TestFetchEntraDevices(t *testing.T) {
	var gotPath, gotSelect string
	c := newTestGraphClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotSelect = r.URL.Query().Get("$select")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"deviceId":                      "11111111-1111-1111-1111-111111111111",
					"displayName":                   "WKS-01",
					"operatingSystem":               "Windows",
					"operatingSystemVersion":        "10.0.19045",
					"approximateLastSignInDateTime": "2026-09-01T12:00:00Z",
					"accountEnabled":                true,
					"trustType":                     "AzureAd",
					"isManaged":                     true,
				},
			},
		})
	})

	raw, devices, err := FetchEntraDevices(context.Background(), c, "tenant-a")
	if err != nil {
		t.Fatalf("FetchEntraDevices: %v", err)
	}
	if gotPath != "/devices" {
		t.Errorf("path = %q, want /devices", gotPath)
	}
	if gotSelect == "" {
		t.Error("$select was not passed through")
	}
	if len(raw) != 1 {
		t.Fatalf("got %d raw items, want 1", len(raw))
	}
	if len(devices) != 1 {
		t.Fatalf("got %d devices, want 1", len(devices))
	}
	d := devices[0]
	if d.DeviceID != "11111111-1111-1111-1111-111111111111" || d.DisplayName != "WKS-01" {
		t.Errorf("unexpected device: %+v", d)
	}
	if !d.AccountEnabled || !d.IsManaged || d.TrustType != "AzureAd" {
		t.Errorf("unexpected device flags: %+v", d)
	}
	wantTime, _ := time.Parse(time.RFC3339, "2026-09-01T12:00:00Z")
	if !d.ApproximateLastSignInDateTime.Equal(wantTime) {
		t.Errorf("ApproximateLastSignInDateTime = %v, want %v", d.ApproximateLastSignInDateTime, wantTime)
	}
}

func TestFetchManagedDevices(t *testing.T) {
	var gotPath string
	c := newTestGraphClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id":                      "managed-1",
					"azureADDeviceId":         "11111111-1111-1111-1111-111111111111",
					"deviceName":              "WKS-01",
					"operatingSystem":         "Windows",
					"osVersion":               "10.0.19045",
					"lastSyncDateTime":        "2026-09-10T08:00:00Z",
					"enrolledDateTime":        "2026-07-01T00:00:00Z",
					"complianceState":         "compliant",
					"managedDeviceOwnerType":  "company",
					"managementAgent":         "mdm",
					"deviceRegistrationState": "registered",
				},
				{
					// Managed device with a missing join key — must still
					// decode, not error the whole fetch.
					"id":              "managed-2",
					"azureADDeviceId": "",
					"deviceName":      "NO-JOIN-KEY",
				},
			},
		})
	})

	raw, devices, err := FetchManagedDevices(context.Background(), c, "tenant-a")
	if err != nil {
		t.Fatalf("FetchManagedDevices: %v", err)
	}
	if gotPath != "/deviceManagement/managedDevices" {
		t.Errorf("path = %q, want /deviceManagement/managedDevices", gotPath)
	}
	if len(raw) != 2 {
		t.Fatalf("got %d raw items, want 2", len(raw))
	}
	if len(devices) != 2 {
		t.Fatalf("got %d devices, want 2", len(devices))
	}
	if devices[0].AzureADDeviceID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("unexpected first device: %+v", devices[0])
	}
	if devices[1].AzureADDeviceID != "" || devices[1].DeviceName != "NO-JOIN-KEY" {
		t.Errorf("unexpected second device: %+v", devices[1])
	}
}

// TestFetchEntraDevices_PagesToExhaustion confirms this package reuses
// msgraph's own @odata.nextLink paging rather than reimplementing it.
func TestFetchEntraDevices_PagesToExhaustion(t *testing.T) {
	var mux *http.ServeMux
	c := newTestGraphClient(t, func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r)
	})
	// c.BaseURL is the graph httptest.Server's own URL; page 2's nextLink
	// points back at it so validateNextLink accepts it.
	baseURL := c.BaseURL

	mux = http.NewServeMux()
	mux.HandleFunc("/devices", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value":           []map[string]any{{"deviceId": "d1"}},
			"@odata.nextLink": baseURL + "/devices/page2",
		})
	})
	mux.HandleFunc("/devices/page2", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{{"deviceId": "d2"}},
		})
	})

	_, devices, err := FetchEntraDevices(context.Background(), c, "tenant-a")
	if err != nil {
		t.Fatalf("FetchEntraDevices: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("got %d devices across 2 pages, want 2", len(devices))
	}
}
