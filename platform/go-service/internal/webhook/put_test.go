package webhook

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPutHardenedRefusesInternalAndDNSDestinations(t *testing.T) {
	reached := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	defer srv.Close()
	port := strings.TrimPrefix(srv.URL, "https://127.0.0.1:")
	for _, target := range []string{srv.URL, "https://localhost:" + port, "https://100.64.0.1/upload", "https://169.254.169.254/upload", "https://[::1]/upload", "http://example.test/upload"} {
		if _, err := PutHardened(context.Background(), target, nil, []byte("pixels")); err == nil {
			t.Errorf("unsafe PUT accepted: %s", target)
		}
	}
	if reached {
		t.Fatal("unsafe PUT reached local server")
	}
	if httpClient.CheckRedirect == nil || httpClient.CheckRedirect(nil, nil) == nil {
		t.Fatal("PUT client follows redirects")
	}
}

func TestHardenedPutRequestPreservesUploadBytesAndHeaders(t *testing.T) {
	headers := map[string]string{"Content-Type": "image/png", "Cache-Control": "public, max-age=31536000", "X-Signed": "value"}
	r, err := hardenedRequest(context.Background(), http.MethodPut, "https://storage.example.test/signed", headers, []byte{0, 1, 2, 255})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if r.Method != http.MethodPut || string(body) != string([]byte{0, 1, 2, 255}) || r.ContentLength != 4 {
		t.Fatalf("invalid raw PUT request: %s %v %d", r.Method, body, r.ContentLength)
	}
	for k, v := range headers {
		if r.Header.Get(k) != v {
			t.Errorf("lost %s header", k)
		}
	}
}
