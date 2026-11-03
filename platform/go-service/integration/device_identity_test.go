//go:build integration

package integration

// PAT-2424: GET /v1/device/identity against the real public router, real
// migrations, and credentials issued by the real POST /v1/enrol and
// POST /admin/tenants handlers. The device a caller is told about must be
// decided by its credential row and by nothing in the request.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"patched.im/api/internal/handlers"
	"patched.im/api/internal/ratelimit"
)

type identityCred struct {
	tenantID, deviceID, bearer string
	secret                     []byte
}

// identityAdminServer mounts the production handlers this test needs that the
// shared harness routers do not: token mint, enrol, and the two revokes.
func identityAdminServer(t *testing.T) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	r.Post("/admin/tenants/{tenantID}/bootstrap-tokens", handlers.MintBootstrapTokenHandler(env.pool))
	r.Post("/v1/enrol", handlers.EnrolHandler(env.pool, ratelimit.New(ratelimit.Config{RPM: 6000, Burst: 1000})))
	r.Post("/admin/devices/{deviceID}/revoke", handlers.RevokeDeviceHandler(env.pool))
	r.Delete("/admin/tenants/{tenantID}", handlers.RevokeTenantHandler(env.pool))
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func identityDo(t *testing.T, method, url string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// enrolIdentityDevice enrols a new device through POST /v1/enrol, exactly as an
// agent does, and returns what that response handed the agent.
func enrolIdentityDevice(t *testing.T, admin *httptest.Server, tenantID string) identityCred {
	t.Helper()
	code, raw := identityDo(t, http.MethodPost, admin.URL+"/admin/tenants/"+tenantID+"/bootstrap-tokens", nil)
	if code != http.StatusCreated {
		t.Fatalf("mint token: %d %s", code, raw)
	}
	var minted struct {
		EnrollmentToken string `json:"enrollment_token"`
	}
	if err := json.Unmarshal(raw, &minted); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"enrollment_token": minted.EnrollmentToken, "device_id": identityHWUUID()})
	code, raw = identityDo(t, http.MethodPost, admin.URL+"/v1/enrol", body)
	if code != http.StatusOK {
		t.Fatalf("enrol: %d %s", code, raw)
	}
	var out struct {
		TenantID    string `json:"tenant_id"`
		DeviceID    string `json:"device_id"`
		BearerToken string `json:"bearer_token"`
		HMACSecret  string `json:"hmac_secret"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	secret, err := base64.StdEncoding.DecodeString(out.HMACSecret)
	if err != nil {
		t.Fatal(err)
	}
	return identityCred{tenantID: out.TenantID, deviceID: out.DeviceID, bearer: out.BearerToken, secret: secret}
}

// identityHWUUID is a random v4-shaped hardware UUID for one enrolment.
func identityHWUUID() string {
	h := randomHex(16)
	return h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-8" + h[17:20] + "-" + h[20:32]
}

func identityV3(secret []byte, ts, nonce string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("patched-hmac-v3\nGET\ndevice_identity\n" + ts + "\n" + nonce + "\n"))
	return hex.EncodeToString(mac.Sum(nil))
}

type identityReq struct {
	bearer, sig, ts, nonce, query string
}

func newIdentityReq(c identityCred) identityReq {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "pat2424-" + randomHex(12)
	return identityReq{bearer: c.bearer, sig: identityV3(c.secret, ts, nonce), ts: ts, nonce: nonce}
}

func (q identityReq) send(t *testing.T) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, env.publicSrv.URL+"/v1/device/identity"+q.query, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+q.bearer)
	req.Header.Set("X-Patched-Signature", q.sig)
	req.Header.Set("X-Patched-Timestamp", q.ts)
	req.Header.Set("X-Patched-Nonce", q.nonce)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func wantIdentity(t *testing.T, code int, body string, want identityCred) {
	t.Helper()
	if code != http.StatusOK {
		t.Fatalf("status %d body %q, want 200", code, body)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	if len(got) != 2 || got["tenant_id"] != want.tenantID || got["device_id"] != want.deviceID {
		t.Fatalf("body %q, want exactly tenant_id=%s device_id=%s", body, want.tenantID, want.deviceID)
	}
}

func wantGeneric401(t *testing.T, what string, code int, body string, forbidden ...identityCred) {
	t.Helper()
	if code != http.StatusUnauthorized || body != "unauthorized\n" {
		t.Fatalf("%s: got %d %q, want the generic 401", what, code, body)
	}
	for _, c := range forbidden {
		if strings.Contains(body, c.deviceID) || strings.Contains(body, c.tenantID) {
			t.Fatalf("%s: refusal leaks an identity: %q", what, body)
		}
	}
}

func TestDeviceIdentity_CredentialDecidesTheDevice(t *testing.T) {
	ctx := context.Background()
	admin := identityAdminServer(t)

	tenantA, tenantABearer, tenantASecret, err := createTestTenant(env.internalSrv.URL, "pat2424-a-"+randomHex(4))
	if err != nil {
		t.Fatal(err)
	}
	tenantB, _, _, err := createTestTenant(env.internalSrv.URL, "pat2424-b-"+randomHex(4))
	if err != nil {
		t.Fatal(err)
	}
	a1 := enrolIdentityDevice(t, admin, tenantA)
	a2 := enrolIdentityDevice(t, admin, tenantA)
	b1 := enrolIdentityDevice(t, admin, tenantB)
	if a1.deviceID == a2.deviceID || a1.tenantID != tenantA || b1.tenantID != tenantB {
		t.Fatalf("fixture: a1=%+v a2=%+v b1=%+v", a1, a2, b1)
	}

	var devicesBefore int
	var lastSeenBefore time.Time
	if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM devices WHERE tenant_id IN ($1::uuid,$2::uuid)`, tenantA, tenantB).Scan(&devicesBefore); err != nil {
		t.Fatal(err)
	}
	if err := env.pool.QueryRow(ctx, `SELECT last_seen FROM devices WHERE id=$1::uuid`, a1.deviceID).Scan(&lastSeenBefore); err != nil {
		t.Fatal(err)
	}

	t.Run("own credential returns own device, matching what enrol returned", func(t *testing.T) {
		code, body := newIdentityReq(a1).send(t)
		wantIdentity(t, code, body, a1)
	})

	t.Run("second device in the same tenant gets its own id, never the first's", func(t *testing.T) {
		code, body := newIdentityReq(a2).send(t)
		wantIdentity(t, code, body, a2)
		if strings.Contains(body, a1.deviceID) {
			t.Fatalf("device 2 was told device 1's id: %s", body)
		}
	})

	t.Run("another tenant's device gets its own tenant and device", func(t *testing.T) {
		code, body := newIdentityReq(b1).send(t)
		wantIdentity(t, code, body, b1)
	})

	t.Run("request parameters naming another device or tenant change nothing", func(t *testing.T) {
		q := newIdentityReq(a1)
		q.query = "?device_id=" + a2.deviceID + "&tenant_id=" + tenantB + "&hw_uuid=" + b1.deviceID
		code, body := q.send(t)
		wantIdentity(t, code, body, a1)
	})

	t.Run("bearer of one device with the secret of another is refused", func(t *testing.T) {
		for name, other := range map[string]identityCred{"same tenant": a2, "other tenant": b1} {
			q := newIdentityReq(a1)
			q.sig = identityV3(other.secret, q.ts, q.nonce)
			code, body := q.send(t)
			wantGeneric401(t, name, code, body, a1, a2, b1)
		}
	})

	t.Run("wrong, legacy and wrong-endpoint signatures are refused", func(t *testing.T) {
		q := newIdentityReq(a1)
		q.sig = strings.Repeat("0", 64)
		code, body := q.send(t)
		wantGeneric401(t, "garbage signature", code, body, a1)

		// Body-only HMAC over the empty body: the transition form other
		// endpoints still accept. It binds neither timestamp nor nonce, so
		// this endpoint must not take it.
		q = newIdentityReq(a1)
		legacy := hmac.New(sha256.New, a1.secret)
		q.sig = hex.EncodeToString(legacy.Sum(nil))
		code, body = q.send(t)
		wantGeneric401(t, "legacy body-only signature", code, body, a1)

		// A valid v3 signature for a different endpoint must not transfer.
		q = newIdentityReq(a1)
		other := hmac.New(sha256.New, a1.secret)
		other.Write([]byte("patched-hmac-v3\nGET\nagent_config\n" + q.ts + "\n" + q.nonce + "\n"))
		q.sig = hex.EncodeToString(other.Sum(nil))
		code, body = q.send(t)
		wantGeneric401(t, "agent_config signature", code, body, a1)
	})

	t.Run("a replayed request is refused", func(t *testing.T) {
		q := newIdentityReq(a1)
		code, body := q.send(t)
		wantIdentity(t, code, body, a1)
		code, body = q.send(t)
		wantGeneric401(t, "replay", code, body, a1)
	})

	t.Run("a correctly signed request outside the time window is refused", func(t *testing.T) {
		q := newIdentityReq(a1)
		q.ts = strconv.FormatInt(time.Now().Add(-2*time.Hour).Unix(), 10)
		q.sig = identityV3(a1.secret, q.ts, q.nonce)
		code, body := q.send(t)
		wantGeneric401(t, "stale timestamp", code, body, a1)
	})

	t.Run("a tenant-wide credential is refused distinctly once authenticated, and generically otherwise", func(t *testing.T) {
		tenantWide := identityCred{tenantID: tenantA, bearer: tenantABearer, secret: tenantASecret}
		code, body := newIdentityReq(tenantWide).send(t)
		if code != http.StatusConflict || strings.TrimSpace(body) != `{"error":"device_credential_required"}` {
			t.Fatalf("got %d %q, want 409 device_credential_required", code, body)
		}
		for _, c := range []identityCred{a1, a2} {
			if strings.Contains(body, c.deviceID) || strings.Contains(body, tenantA) {
				t.Fatalf("tenant-wide refusal leaks an identity: %q", body)
			}
		}
		// Holding only the tenant-wide bearer, without its secret, must look
		// exactly like an unknown token.
		q := newIdentityReq(tenantWide)
		q.sig = identityV3(a1.secret, q.ts, q.nonce)
		code, body = q.send(t)
		wantGeneric401(t, "tenant-wide bearer, wrong secret", code, body, a1)

		unknown := identityCred{bearer: "pat2424-unknown-" + randomHex(8), secret: []byte("placeholder")}
		code, body = newIdentityReq(unknown).send(t)
		wantGeneric401(t, "unknown bearer", code, body)

		// A replayed tenant-wide request must not get the distinct answer.
		q = newIdentityReq(tenantWide)
		if code, _ = q.send(t); code != http.StatusConflict {
			t.Fatalf("first tenant-wide request: %d", code)
		}
		code, body = q.send(t)
		wantGeneric401(t, "tenant-wide replay", code, body)
	})

	t.Run("the endpoint created no device and did not touch last_seen", func(t *testing.T) {
		var devicesAfter int
		var lastSeenAfter time.Time
		if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM devices WHERE tenant_id IN ($1::uuid,$2::uuid)`, tenantA, tenantB).Scan(&devicesAfter); err != nil {
			t.Fatal(err)
		}
		if err := env.pool.QueryRow(ctx, `SELECT last_seen FROM devices WHERE id=$1::uuid`, a1.deviceID).Scan(&lastSeenAfter); err != nil {
			t.Fatal(err)
		}
		if devicesAfter != devicesBefore || !lastSeenAfter.Equal(lastSeenBefore) {
			t.Fatalf("devices %d -> %d, last_seen %v -> %v", devicesBefore, devicesAfter, lastSeenBefore, lastSeenAfter)
		}
	})

	t.Run("an expired credential is refused", func(t *testing.T) {
		c := enrolIdentityDevice(t, admin, tenantA)
		hash := sha256.Sum256([]byte(c.bearer))
		if _, err := env.pool.Exec(ctx, `UPDATE tenant_credentials SET expires_at = now() - interval '1 minute' WHERE bearer_token_hash=$1`, hash[:]); err != nil {
			t.Fatal(err)
		}
		code, body := newIdentityReq(c).send(t)
		wantGeneric401(t, "expired credential", code, body, c)
	})

	t.Run("a revoked device credential is refused, and its neighbour still works", func(t *testing.T) {
		code, raw := identityDo(t, http.MethodPost, admin.URL+"/admin/devices/"+a2.deviceID+"/revoke", []byte(`{}`))
		if code != http.StatusOK {
			t.Fatalf("revoke device: %d %s", code, raw)
		}
		code, body := newIdentityReq(a2).send(t)
		wantGeneric401(t, "revoked device", code, body, a2)
		code, body = newIdentityReq(a1).send(t)
		wantIdentity(t, code, body, a1)
	})

	// Last: revoking tenant B must cut off its device and leave tenant A alone.
	t.Run("a revoked tenant's device is refused", func(t *testing.T) {
		code, raw := identityDo(t, http.MethodDelete, admin.URL+"/admin/tenants/"+tenantB, nil)
		if code >= 300 {
			t.Fatalf("revoke tenant: %d %s", code, raw)
		}
		code, body := newIdentityReq(b1).send(t)
		wantGeneric401(t, "revoked tenant", code, body, b1)
		code, body = newIdentityReq(a1).send(t)
		wantIdentity(t, code, body, a1)
	})
}
