package handlers

// PAT-2424: unit tests for GET /v1/device/identity with the auth and lookup
// steps stubbed. The real bearer, HMAC, replay and database path is covered
// end to end by integration/device_identity_test.go.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"patched.im/api/internal/auth"
	"patched.im/api/internal/metrics"
	"patched.im/api/internal/ratelimit"
)

const (
	diTenantID = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	diDeviceID = "d1eebc99-9c0b-4ef8-bb6d-6bb9bd380a22"
)

func diAuth(tenantID, deviceID string, err error) deviceIdentityAuthFn {
	return func(context.Context, string, string, string, string, []byte) (string, string, error) {
		return tenantID, deviceID, err
	}
}

func diExists(ok bool, err error) deviceIdentityExistsFn {
	return func(context.Context, string, string) (bool, error) { return ok, err }
}

func diGet(h http.Handler, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer placeholder")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestDeviceIdentity_Success_ReturnsOnlyTenantAndDevice(t *testing.T) {
	h := newDeviceIdentityHandler(diAuth(diTenantID, diDeviceID, nil), diExists(true, nil), nil, 0, nil)
	rr := diGet(h, "/v1/device/identity")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %q", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 || got["tenant_id"] != diTenantID || got["device_id"] != diDeviceID {
		t.Fatalf("body = %v, want exactly tenant_id and device_id", got)
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "private, no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}
}

// The device comes from the credential. The handler must not even hand the
// request's parameters to the lookup, so nothing a caller sends can steer it.
func TestDeviceIdentity_RequestParametersCannotSelectTheDevice(t *testing.T) {
	const other = "e2ffcd00-ad1c-4f09-8c7e-7cc0ce491b33"
	var asked string
	exists := func(_ context.Context, _, deviceID string) (bool, error) {
		asked = deviceID
		return true, nil
	}
	h := newDeviceIdentityHandler(diAuth(diTenantID, diDeviceID, nil), exists, nil, 0, nil)
	rr := diGet(h, "/v1/device/identity?device_id="+other+"&tenant_id="+other+"&hw_uuid="+other)
	if rr.Code != http.StatusOK || asked != diDeviceID {
		t.Fatalf("status %d, lookup asked for %q; want 200 and %q", rr.Code, asked, diDeviceID)
	}
	if strings.Contains(rr.Body.String(), other) {
		t.Fatalf("response echoes a caller-supplied id: %s", rr.Body.String())
	}
}

func TestDeviceIdentity_AuthFailuresAreUniform401(t *testing.T) {
	for name, err := range map[string]error{
		"missing":       auth.ErrMissingAuth,
		"unknown":       auth.ErrUnknownToken,
		"bad signature": auth.ErrInvalidSignature,
		// A tenant-level credential that did NOT go on to authenticate at
		// tenant level stays indistinguishable from an unknown token.
		"tenant-level unauthenticated": auth.ErrDeviceCredentialRequired,
	} {
		t.Run(name, func(t *testing.T) {
			h := newDeviceIdentityHandler(diAuth("", "", err), diExists(true, nil), nil, 0, nil)
			rr := diGet(h, "/v1/device/identity")
			if rr.Code != http.StatusUnauthorized || rr.Body.String() != "unauthorized\n" {
				t.Fatalf("got %d %q, want the generic 401", rr.Code, rr.Body.String())
			}
		})
	}
}

// An authenticated tenant-level credential (auth returns a tenant and no
// device) gets the distinct refusal, never an identity, and never reaches the
// device lookup.
func TestDeviceIdentity_AuthenticatedTenantLevelCredential_409(t *testing.T) {
	exists := func(context.Context, string, string) (bool, error) {
		t.Fatal("device lookup must not run for a tenant-level credential")
		return false, nil
	}
	h := newDeviceIdentityHandler(diAuth(diTenantID, "", nil), exists, nil, 0, nil)
	before := testutil.ToFloat64(metrics.DeviceCredentialRequiredTotal.WithLabelValues("device_identity"))
	rr := diGet(h, "/v1/device/identity")
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rr.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got["error"] != "device_credential_required" {
		t.Fatalf("body = %v", got)
	}
	if strings.Contains(rr.Body.String(), diTenantID) {
		t.Fatalf("refusal must not carry the tenant id: %s", rr.Body.String())
	}
	if after := testutil.ToFloat64(metrics.DeviceCredentialRequiredTotal.WithLabelValues("device_identity")); after != before+1 {
		t.Fatalf("counter = %v, want %v", after, before+1)
	}
}

func TestDeviceIdentity_DeviceRowMissing_401(t *testing.T) {
	h := newDeviceIdentityHandler(diAuth(diTenantID, diDeviceID, nil), diExists(false, nil), nil, 0, nil)
	rr := diGet(h, "/v1/device/identity")
	if rr.Code != http.StatusUnauthorized || strings.Contains(rr.Body.String(), diDeviceID) {
		t.Fatalf("got %d %q, want the generic 401", rr.Code, rr.Body.String())
	}
}

func TestDeviceIdentity_LookupError_500(t *testing.T) {
	h := newDeviceIdentityHandler(diAuth(diTenantID, diDeviceID, nil), diExists(false, errors.New("db down")), nil, 0, nil)
	if rr := diGet(h, "/v1/device/identity"); rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestDeviceIdentity_RateLimited_429(t *testing.T) {
	rl := ratelimit.New(ratelimit.Config{RPM: 1, Burst: 1})
	h := newDeviceIdentityHandler(diAuth(diTenantID, diDeviceID, nil), diExists(true, nil), rl, time.Minute, nil)
	if rr := diGet(h, "/v1/device/identity"); rr.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", rr.Code)
	}
	rr := diGet(h, "/v1/device/identity")
	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("second request got %d (Retry-After %q), want 429", rr.Code, rr.Header().Get("Retry-After"))
	}
}
