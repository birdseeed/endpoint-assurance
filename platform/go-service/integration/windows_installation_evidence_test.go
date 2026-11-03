//go:build integration

package integration

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/agentconfig"
	"patched.im/api/internal/evidencecatalogue"
)

func windowsEvidenceRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, env.publicSrv.URL+"/v1/agent-config", nil)
	if err != nil {
		t.Fatal(err)
	}
	ts, nonce := strconv.FormatInt(time.Now().Unix(), 10), randomHex(16)
	mac := hmac.New(sha256.New, env.hmacSecretRaw)
	_, _ = mac.Write([]byte("patched-hmac-v3\nGET\nagent_config\n" + ts + "\n" + nonce + "\n"))
	req.Header.Set("Authorization", "Bearer "+env.bearerToken)
	req.Header.Set("X-Patched-Signature", hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Patched-Timestamp", ts)
	req.Header.Set("X-Patched-Nonce", nonce)
	return req
}

func TestWindowsInstallationEvidenceRealAuthAndSignedPublication(t *testing.T) {
	for name, mutate := range map[string]func(*http.Request){
		"missing bearer":    func(r *http.Request) { r.Header.Del("Authorization") },
		"wrong bearer":      func(r *http.Request) { r.Header.Set("Authorization", "Bearer unknown") },
		"bad HMAC":          func(r *http.Request) { r.Header.Set("X-Patched-Signature", strings.Repeat("0", 64)) },
		"changed timestamp": func(r *http.Request) { r.Header.Set("X-Patched-Timestamp", "1") },
		"changed nonce":     func(r *http.Request) { r.Header.Set("X-Patched-Nonce", randomHex(16)) },
	} {
		t.Run(name, func(t *testing.T) {
			req := windowsEvidenceRequest(t)
			mutate(req)
			req.Header.Set("If-None-Match", `"anything"`)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("unauthenticated evidence route status=%d", resp.StatusCode)
			}
		})
	}

	req := windowsEvidenceRequest(t)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	responseRaw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("signed publication status=%d body=%s", resp.StatusCode, responseRaw)
	}
	var envelope struct {
		SignedPayload string `json:"signed_payload"`
		Signature     string `json:"signature"`
	}
	if err := json.Unmarshal(responseRaw, &envelope); err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	key, _ := agentconfig.KeyFromSeed(seed)
	raw, err := base64.StdEncoding.DecodeString(envelope.SignedPayload)
	if err != nil {
		t.Fatal(err)
	}
	if err := agentconfig.Verify(key.Public, raw, envelope.Signature); err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Evidence *evidencecatalogue.WindowsDelivery `json:"windows_installation_evidence"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	want, err := evidencecatalogue.EmbeddedWindowsDelivery()
	if err != nil {
		t.Fatalf("load reviewed Windows delivery: %v", err)
	}
	if want.Validate(time.Now().UTC()) == nil {
		if cfg.Evidence == nil || cfg.Evidence.ContentHash != evidencecatalogue.WindowsContentHash || len(cfg.Evidence.Targets) != 0 {
			t.Fatalf("unexpected evidence projection: %s", raw)
		}
	} else if cfg.Evidence != nil {
		t.Fatal("out-of-window compiled publication delivered")
	}

	// A replay must fail even with an ETag from a previously authorised GET.
	req.Header.Set("If-None-Match", resp.Header.Get("ETag"))
	replayed, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer replayed.Body.Close()
	if replayed.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay passed: %d", replayed.StatusCode)
	}

	fresh := windowsEvidenceRequest(t)
	fresh.Header.Set("If-None-Match", resp.Header.Get("ETag"))
	unchanged, err := http.DefaultClient.Do(fresh)
	if err != nil {
		t.Fatal(err)
	}
	defer unchanged.Body.Close()
	if unchanged.StatusCode != http.StatusNotModified {
		t.Fatalf("unchanged publication status=%d", unchanged.StatusCode)
	}
}
