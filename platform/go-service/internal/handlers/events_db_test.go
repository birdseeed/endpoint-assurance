package handlers

// DB-backed tests for POST /v1/events (PAT-1022), driving the REAL exported
// EventsHandler end-to-end — real bearer lookup + real HMAC verification +
// real DB insert into audit_events (migrations/0098_audit_events.sql), not a
// DI stub. Require TEST_DATABASE_URL and are skipped otherwise, matching the
// pattern used throughout this package (see catalogue_signed_db_test.go,
// allowlist_agent_known_path_test.go). Reuses parConnectOrSkip/parSeedTenant
// from allowlist_agent_known_path_test.go (same package).

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/ratelimit"
)

// evV3Sign computes the PAT-1154 v3 signature exactly as
// internal/auth/hmac.go's signedHMAC does, and exactly as both agents
// already compute it (updater/endpoint/patched-update.sh's compute_hmac;
// updater/windows/src/Shared/Auth/HmacSigner.cs). Kept as a small local
// helper rather than exporting the package-internal signedHMAC, matching
// how catalogue_signed_db_test.go computes its own signature independently
// of the auth package it's testing.
func evV3Sign(secret []byte, method, endpointID, ts, nonce string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("patched-hmac-v3\n"))
	mac.Write([]byte(method))
	mac.Write([]byte("\n"))
	mac.Write([]byte(endpointID))
	mac.Write([]byte("\n"))
	mac.Write([]byte(ts))
	mac.Write([]byte("\n"))
	mac.Write([]byte(nonce))
	mac.Write([]byte("\n"))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func evSignedRequest(t *testing.T, bearerToken, hmacSecret string, body []byte) *http.Request {
	t.Helper()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := fmt.Sprintf("pat1022-test-nonce-%d", time.Now().UnixNano())
	sig := evV3Sign([]byte(hmacSecret), http.MethodPost, "events", ts, nonce, body)

	req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("X-Patched-Signature", sig)
	req.Header.Set("X-Patched-Timestamp", ts)
	req.Header.Set("X-Patched-Nonce", nonce)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func evTestRateLimiter() *ratelimit.TenantLimiter {
	return ratelimit.New(ratelimit.Config{RPM: 1000, Burst: 1000})
}

// evUniqueToken appends a per-run nanosecond suffix. Required (not just
// nice-to-have) for any test below that actually inserts an audit_events
// row: once that row exists, the append-only trigger blocks
// parSeedTenant's tenant cleanup (see the comment on
// TestEventsPost_DB_ValidIngestion), which leaves that tenant's row in
// tenant_credentials permanently in place too — and tenant_credentials has
// a real UNIQUE index on bearer_token_hash, so a second run reusing the
// same literal token collides with the first run's now-undeletable row.
// Tests that never reach the DB insert (auth-failure paths) don't need
// this, since their tenant cleanup always succeeds.
func evUniqueToken(base string) string {
	return fmt.Sprintf("%s-%d", base, time.Now().UnixNano())
}

// TestEventsPost_DB_ValidIngestion proves a fully-authenticated, well-formed
// event round-trips: 200 OK, a row lands in audit_events with the fields
// the envelope carried, tenant_id taken from the bearer (not the body).
func TestEventsPost_DB_ValidIngestion(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	bearerToken := evUniqueToken("pat1022-test-token-valid")
	hmacSecret := evUniqueToken("pat1022-test-hmac-secret-valid")
	tenantID := parSeedTenant(t, ctx, pool, "pat1022-valid-tenant", bearerToken, hmacSecret)
	// Best-effort only: once this test inserts a row, audit_events'
	// append-only trigger (0098_audit_events.sql) rejects the DELETE below,
	// and — same as audit_append_only_test.go's aoSeedTenant documents for
	// the other PAT-1133 guarded tables — that also means parSeedTenant's
	// own tenant cleanup silently fails on the FK afterwards. Accepted,
	// matching the established convention for every append-only-guarded
	// audit table in this package; not a leak this test introduces uniquely.
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM audit_events WHERE tenant_id = $1::uuid`, tenantID) })

	handler := EventsHandler(pool, evTestRateLimiter(), 5*time.Minute)

	body := []byte(`{
		"event_type": "version_blocked",
		"tenant_id": "should-be-ignored-not-a-real-uuid",
		"device_id": "PAT1022-DEVICE-1",
		"label": "googlechrome",
		"version": "125.0.6422.60",
		"platform": "macos",
		"timestamp": "2026-12-20T16:00:00Z"
	}`)
	req := evSignedRequest(t, bearerToken, hmacSecret, body)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	eventID, _ := resp["event_id"].(string)
	if eventID == "" {
		t.Fatalf("response missing event_id: %v", resp)
	}

	var gotTenantID, gotDeviceID, gotEventType, gotLabel, gotPlatform string
	err := pool.QueryRow(ctx, `
		SELECT tenant_id::text, device_id, event_type, label, platform
		FROM audit_events WHERE id = $1::uuid
	`, eventID).Scan(&gotTenantID, &gotDeviceID, &gotEventType, &gotLabel, &gotPlatform)
	if err != nil {
		t.Fatalf("query inserted row: %v", err)
	}
	if gotTenantID != tenantID {
		t.Errorf("stored tenant_id = %q, want %q (bearer-derived, body's tenant_id must be ignored)", gotTenantID, tenantID)
	}
	if gotDeviceID != "PAT1022-DEVICE-1" {
		t.Errorf("stored device_id = %q, want PAT1022-DEVICE-1", gotDeviceID)
	}
	if gotEventType != "version_blocked" {
		t.Errorf("stored event_type = %q, want version_blocked (proves migration 0100 widened the DB constraint)", gotEventType)
	}
	if gotLabel != "googlechrome" {
		t.Errorf("stored label = %q, want googlechrome", gotLabel)
	}
	if gotPlatform != "macos" {
		t.Errorf("stored platform = %q, want macos", gotPlatform)
	}
}

// TestEventsPost_DB_MissingBearerRejected asserts the real (non-stubbed)
// auth chain rejects a request with no Authorization header at all.
func TestEventsPost_DB_MissingBearerRejected(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })

	handler := EventsHandler(pool, evTestRateLimiter(), 5*time.Minute)

	body := []byte(`{"event_type":"install_completed","device_id":"d","platform":"macos","timestamp":"2026-12-20T16:00:00Z"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for missing bearer, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestEventsPost_DB_UnknownBearerRejected asserts a well-formed but unknown
// bearer token is rejected.
func TestEventsPost_DB_UnknownBearerRejected(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })

	handler := EventsHandler(pool, evTestRateLimiter(), 5*time.Minute)

	body := []byte(`{"event_type":"install_completed","device_id":"d","platform":"macos","timestamp":"2026-12-20T16:00:00Z"}`)
	req := evSignedRequest(t, "pat1022-this-token-does-not-exist", "irrelevant-secret", body)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for unknown bearer, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestEventsPost_DB_BadHMACRejected asserts a KNOWN bearer token with a
// signature computed under the WRONG secret is rejected — proving the HMAC
// check actually runs and is not short-circuited by a successful bearer
// lookup.
func TestEventsPost_DB_BadHMACRejected(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	bearerToken := "pat1022-test-token-badhmac"
	hmacSecret := "pat1022-test-hmac-secret-badhmac"
	_ = parSeedTenant(t, ctx, pool, "pat1022-badhmac-tenant", bearerToken, hmacSecret)

	handler := EventsHandler(pool, evTestRateLimiter(), 5*time.Minute)

	body := []byte(`{"event_type":"install_completed","device_id":"d","platform":"macos","timestamp":"2026-12-20T16:00:00Z"}`)
	// Sign with the WRONG secret.
	req := evSignedRequest(t, bearerToken, "totally-different-secret", body)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for bad HMAC, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestEventsPost_DB_MalformedPayloadRejected asserts a fully-authenticated
// request with an invalid envelope (unknown event_type) is rejected with
// 400, and — critically — that nothing was written to audit_events despite
// auth succeeding.
func TestEventsPost_DB_MalformedPayloadRejected(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	bearerToken := "pat1022-test-token-malformed"
	hmacSecret := "pat1022-test-hmac-secret-malformed"
	tenantID := parSeedTenant(t, ctx, pool, "pat1022-malformed-tenant", bearerToken, hmacSecret)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM audit_events WHERE tenant_id = $1::uuid`, tenantID) })

	handler := EventsHandler(pool, evTestRateLimiter(), 5*time.Minute)

	body := []byte(`{"event_type":"not_a_real_event_type","device_id":"d","platform":"macos","timestamp":"2026-12-20T16:00:00Z"}`)
	req := evSignedRequest(t, bearerToken, hmacSecret, body)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for unknown event_type, got %d: %s", rr.Code, rr.Body.String())
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id = $1::uuid`, tenantID).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 0 {
		t.Errorf("audit_events has %d rows for a rejected payload, want 0", count)
	}
}

// TestEventsPost_DB_AppendOnlyGuardHolds proves the DB-level append-only
// trigger (trg_audit_events_append_only, migrations/0098_audit_events.sql)
// actually rejects UPDATE/DELETE even for the app's own role — the same
// property the PAT-1133 append-only tables already guarantee. This is a
// property of the migration, not the handler, but belongs here because it's
// the acceptance criterion the ticket's "append-only" requirement is
// actually testing.
func TestEventsPost_DB_AppendOnlyGuardHolds(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	bearerToken := evUniqueToken("pat1022-test-token-appendonly")
	hmacSecret := evUniqueToken("pat1022-test-hmac-secret-appendonly")
	tenantID := parSeedTenant(t, ctx, pool, "pat1022-appendonly-tenant", bearerToken, hmacSecret)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM audit_events WHERE tenant_id = $1::uuid`, tenantID) })

	var eventID string
	err := pool.QueryRow(ctx, `
		INSERT INTO audit_events (tenant_id, device_id, event_type, platform, occurred_at)
		VALUES ($1::uuid, 'dev-appendonly', 'verification_failed', 'macos', now())
		RETURNING id::text
	`, tenantID).Scan(&eventID)
	if err != nil {
		t.Fatalf("seed row: %v", err)
	}

	_, err = pool.Exec(ctx, `UPDATE audit_events SET reason = 'tampered' WHERE id = $1::uuid`, eventID)
	if err == nil {
		t.Fatal("want UPDATE to be rejected by the append-only trigger, got nil error")
	}
	if !strings.Contains(err.Error(), "append-only") {
		t.Errorf("error = %v, want it to mention append-only", err)
	}

	_, err = pool.Exec(ctx, `DELETE FROM audit_events WHERE id = $1::uuid`, eventID)
	if err == nil {
		t.Fatal("want DELETE to be rejected by the append-only trigger, got nil error")
	}
	if !strings.Contains(err.Error(), "append-only") {
		t.Errorf("error = %v, want it to mention append-only", err)
	}
}
