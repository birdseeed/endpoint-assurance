package feedback

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLinearScreenshotUploadRawPUTContract(t *testing.T) {
	shot := &Screenshot{Bytes: []byte{0, 1, 2, 255}, ContentType: "image/png", Filename: "FB-123.png"}
	for _, status := range []int{200, 201, 204, 302, 403, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var in struct {
					Query     string         `json:"query"`
					Variables map[string]any `json:"variables"`
				}
				_ = json.NewDecoder(r.Body).Decode(&in)
				if !strings.Contains(in.Query, "fileUpload(contentType:$contentType,filename:$filename,size:$size)") || in.Variables["size"] != float64(4) || in.Variables["contentType"] != "image/png" || in.Variables["filename"] != "FB-123.png" {
					t.Errorf("wrong upload metadata: %+v", in)
				}
				_, _ = w.Write([]byte(`{"data":{"fileUpload":{"success":true,"uploadFile":{"uploadUrl":"https://storage.example.test/signed?token=secret","assetUrl":"https://cdn.example.test/asset.png","headers":[{"key":"x-upload-signature","value":"signed"},{"key":"content-type","value":"image/custom"}]}}}}`))
			}))
			defer srv.Close()
			c := NewLinearClient("key")
			c.Endpoint, c.HTTP = srv.URL, srv.Client()
			calls := 0
			c.put = func(ctx context.Context, target string, headers map[string]string, body []byte) (int, error) {
				calls++
				if target != "https://storage.example.test/signed?token=secret" || string(body) != string(shot.Bytes) || headers["Content-Type"] != "image/custom" || headers["Cache-Control"] != "public, max-age=31536000" || headers["X-Upload-Signature"] != "signed" {
					t.Errorf("invalid raw PUT:%s %v %v", target, headers, body)
				}
				return status, nil
			}
			asset, err := c.uploadScreenshot(context.Background(), shot)
			if calls != 1 || (err == nil) != (status >= 200 && status < 300) {
				t.Fatalf("upload status%d:asset%q err%v calls%d", status, asset, err, calls)
			}
			if err == nil && asset != "https://cdn.example.test/asset.png" {
				t.Fatalf("wrong asset:%q", asset)
			}
		})
	}
}

func TestLinearScreenshotUploadRefusesUnsafeDestinationBeforePUT(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"fileUpload":{"success":true,"uploadFile":{"uploadUrl":"https://100.100.100.100/upload","assetUrl":"https://cdn.example.test/a","headers":[]}}}}`))
	}))
	defer srv.Close()
	c := NewLinearClient("key")
	c.Endpoint, c.HTTP = srv.URL, srv.Client()
	c.put = func(context.Context, string, map[string]string, []byte) (int, error) {
		t.Fatal("unsafe destination reached PUT")
		return 0, nil
	}
	if _, err := c.uploadScreenshot(context.Background(), &Screenshot{Bytes: []byte("raw"), ContentType: "image/png", Filename: "FB-123.png"}); err == nil {
		t.Fatal("unsafe upload accepted")
	}
}

func TestLinearScreenshotPUTTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"fileUpload":{"success":true,"uploadFile":{"uploadUrl":"https://storage.example.test/upload","assetUrl":"https://cdn.example.test/a"}}}}`))
	}))
	defer srv.Close()
	c := NewLinearClient("key")
	c.Endpoint, c.HTTP = srv.URL, srv.Client()
	failure := errors.New("PUT https://storage.example.test/upload?token=secret: transport failed")
	c.put = func(context.Context, string, map[string]string, []byte) (int, error) { return 0, failure }
	if _, err := c.uploadScreenshot(context.Background(), &Screenshot{Bytes: []byte("raw")}); !errors.Is(err, failure) {
		t.Fatalf("transport error lost:%v", err)
	} else if strings.Contains(err.Error(), "secret") {
		t.Fatalf("signed credentials leaked:%v", err)
	}
}

func TestValidScreenshotAssetURL(t *testing.T) {
	for _, tc := range []struct {
		name  string
		raw   string
		valid bool
	}{
		{name: "percent encoded path and query", raw: "https://cdn.example.test/assets/my%20shot.png?title=hello%20world", valid: true},
		{name: "space", raw: "https://cdn.example.test/assets/my shot.png"},
		{name: "newline", raw: "https://cdn.example.test/assets/a\nb"},
		{name: "control", raw: "https://cdn.example.test/assets/a\x00b"},
		{name: "user info", raw: "https://user:pass@cdn.example.test/assets/a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validScreenshotAssetURL(tc.raw); got != tc.valid {
				t.Fatalf("validScreenshotAssetURL(%q)=%t, want %t", tc.raw, got, tc.valid)
			}
		})
	}
}

func TestLinearScreenshotUploadRejectsInvalidSignedHeaders(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers string
	}{
		{name: "duplicate case insensitive", headers: `[{"key":"X-Signature","value":"one"},{"key":"x-signature","value":"two"}]`},
		{name: "empty name", headers: `[{"key":"","value":"signed"}]`},
		{name: "invalid name", headers: `[{"key":"X Bad","value":"signed"}]`},
		{name: "empty value", headers: `[{"key":"X-Signature","value":""}]`},
		{name: "control value", headers: `[{"key":"X-Signature","value":"signed\r\nnext"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"data":{"fileUpload":{"success":true,"uploadFile":{"uploadUrl":"https://storage.example.test/upload","assetUrl":"https://cdn.example.test/a","headers":` + tc.headers + `}}}}`))
			}))
			defer srv.Close()
			c := NewLinearClient("key")
			c.Endpoint, c.HTTP = srv.URL, srv.Client()
			c.put = func(context.Context, string, map[string]string, []byte) (int, error) {
				t.Fatal("invalid signed headers reached PUT")
				return 0, nil
			}
			if _, err := c.uploadScreenshot(context.Background(), &Screenshot{Bytes: []byte("raw")}); err == nil {
				t.Fatal("invalid signed headers accepted")
			}
		})
	}
}
