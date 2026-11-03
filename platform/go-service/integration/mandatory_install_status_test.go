//go:build integration

package integration

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestMandatoryInstallStatusPublicRouteStrictV3AndReplay(t *testing.T) {
	ctx := t.Context()
	token := "pat1399-integration-device-" + randomHex(8)
	secret := []byte("pat1399-integration-device-secret")
	tokenHash := sha256.Sum256([]byte(token))
	var deviceID string
	if err := env.pool.QueryRow(ctx, `
		INSERT INTO devices(tenant_id,serial,hostname,os,os_version)
		VALUES($1::uuid,$2,$2,'macos','15.0') RETURNING id::text
	`, env.tenantID, "pat1399-status-"+randomHex(6)).Scan(&deviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO tenant_credentials(tenant_id,device_id,bearer_token_hash,hmac_secret)
		VALUES($1::uuid,$2::uuid,$3,$4)
	`, env.tenantID, deviceID, tokenHash[:], secret); err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"report_id":"invalid"}`)
	unauthReq, err := http.NewRequest(http.MethodPost, env.publicSrv.URL+"/v1/mandatory-install-status", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	unauthResp, err := http.DefaultClient.Do(unauthReq)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, unauthResp.Body)
	unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing bearer status=%d want 401", unauthResp.StatusCode)
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "pat1399-integration-" + randomHex(8)
	v3 := hmac.New(sha256.New, secret)
	v3.Write([]byte("patched-hmac-v3\nPOST\nmandatory_install_status\n" + timestamp + "\n" + nonce + "\n"))
	v3.Write(body)

	request := func(signature string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, env.publicSrv.URL+"/v1/mandatory-install-status", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Patched-Timestamp", timestamp)
		req.Header.Set("X-Patched-Nonce", nonce)
		req.Header.Set("X-Patched-Signature", signature)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	legacy := hmac.New(sha256.New, secret)
	legacy.Write(body)
	legacyResp := request(hex.EncodeToString(legacy.Sum(nil)))
	_, _ = io.Copy(io.Discard, legacyResp.Body)
	legacyResp.Body.Close()
	if legacyResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("legacy body-only HMAC status=%d want 401", legacyResp.StatusCode)
	}

	validSig := hex.EncodeToString(v3.Sum(nil))
	first := request(validSig)
	_, _ = io.Copy(io.Discard, first.Body)
	first.Body.Close()
	if first.StatusCode != http.StatusBadRequest {
		t.Fatalf("strict v3 route status=%d want post-auth 400", first.StatusCode)
	}
	second := request(validSig)
	_, _ = io.Copy(io.Discard, second.Body)
	second.Body.Close()
	if second.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed strict v3 request status=%d want 401", second.StatusCode)
	}
}
