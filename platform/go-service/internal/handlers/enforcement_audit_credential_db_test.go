package handlers

// PAT-1417: this is the real DB -> LookupDeviceByBearer -> enforcement-audit
// handler path for credential states that must remain invisible to the
// DeviceCredentialRequired counter. It uses an isolated scratch schema and
// skips unless TEST_DATABASE_URL identifies a scratch PostgreSQL instance.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"patched.im/api/internal/auth"
	"patched.im/api/internal/metrics"
)

const enforcementAuditCredentialSchema = "pat1417_enforcement_audit_test"

func TestEnforcementAuditIngestTenantCredentialMetricDBContract(t *testing.T) {
	pool := enforcementAuditCredentialPool(t)
	for _, tc := range []struct {
		name       string
		revoked    *time.Time
		expires    *time.Time
		increments bool
	}{
		{name: "live_tenant_level", increments: true},
		{name: "revoked_tenant_level", revoked: timePtr(time.Now().Add(-time.Hour))},
		{name: "expired_tenant_level", expires: timePtr(time.Now().Add(-time.Hour))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := enforcementAuditCredentialSeed(t, pool, tc.revoked, tc.expires)
			authFn := func(ctx context.Context, authHeader, _, _, _ string, _ []byte) (string, string, error) {
				tenantID, deviceID, _, err := auth.LookupDeviceByBearer(ctx, pool, authHeader)
				return tenantID, deviceID, err
			}
			h := newEnforcementAuditIngestHandler(authFn,
				func(context.Context, string, string, []enforcementAuditEvent) (int, error) { return 0, nil }, nil, 0, nil)
			before := testutil.ToFloat64(metrics.DeviceCredentialRequiredTotal.WithLabelValues("enforcement_audit_ingest"))
			req := httptest.NewRequest(http.MethodPost, "/v1/inventory/enforcement-audit", bytes.NewBufferString(`{"events":[]}`))
			req.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			h(response, req)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", response.Code)
			}
			want := before
			if tc.increments {
				want++
			}
			if after := testutil.ToFloat64(metrics.DeviceCredentialRequiredTotal.WithLabelValues("enforcement_audit_ingest")); after != want {
				t.Fatalf("counter for %s credential: got %v, want %v", tc.name, after, want)
			}
		})
	}
}

// TestPostureTenantCredentialMetricDBContract drives the real database lookup
// through posture's enforcement path. A live tenant-level row must increment
// posture, while revoked and expired tenant-level rows are ordinary generic
// 401s and must not create an alerting signal.
func TestPostureTenantCredentialMetricDBContract(t *testing.T) {
	pool := enforcementAuditCredentialPool(t)
	for _, tc := range []struct {
		name       string
		revoked    *time.Time
		expires    *time.Time
		increments bool
	}{
		{name: "live_tenant_level", increments: true},
		{name: "revoked_tenant_level", revoked: timePtr(time.Now().Add(-time.Hour))},
		{name: "expired_tenant_level", expires: timePtr(time.Now().Add(-time.Hour))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := enforcementAuditCredentialSeed(t, pool, tc.revoked, tc.expires)
			authFn := func(ctx context.Context, authHeader, _, _, _ string, _ []byte) (string, string, error) {
				tenantID, deviceID, _, err := auth.LookupDeviceByBearer(ctx, pool, authHeader)
				return tenantID, deviceID, err
			}
			h := newPostureHandler(authFn, pFetchOK(), newTestSigningKey(), nil, 0, nil)
			before := testutil.ToFloat64(metrics.DeviceCredentialRequiredTotal.WithLabelValues("posture"))
			response := postureGet(t, h, "Bearer "+token)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", response.Code)
			}
			want := before
			if tc.increments {
				want++
			}
			if after := testutil.ToFloat64(metrics.DeviceCredentialRequiredTotal.WithLabelValues("posture")); after != want {
				t.Fatalf("counter for %s credential: got %v, want %v", tc.name, after, want)
			}
		})
	}
}

func enforcementAuditCredentialPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed PAT-1417 handler test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("parse TEST_DATABASE_URL: %v", err)
	}
	host := strings.Trim(strings.ToLower(cfg.ConnConfig.Host), "[]")
	if host != "localhost" && host != "127.0.0.1" && host != "::1" {
		t.Fatalf("TEST_DATABASE_URL must use a loopback host, got %q", cfg.ConnConfig.Host)
	}
	if !strings.Contains(strings.ToLower(cfg.ConnConfig.Database), "test") {
		t.Fatalf("TEST_DATABASE_URL database must be explicitly scratch/test-named, got %q", cfg.ConnConfig.Database)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = enforcementAuditCredentialSchema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open scratch pool: %v", err)
	}
	t.Cleanup(pool.Close)
	ctx := context.Background()
	for _, statement := range []string{
		`DROP SCHEMA IF EXISTS ` + enforcementAuditCredentialSchema + ` CASCADE`,
		`CREATE SCHEMA ` + enforcementAuditCredentialSchema,
		// Minimal, schema-isolated mirror of migrations/0001_initial.sql,
		// 0017_tenant_credentials.sql and 0029_device_credentials.sql. These
		// are the exact auth-query columns, with NULL device_id representing a
		// tenant-level credential; no extension or shared schema is mutated.
		`CREATE TABLE tenants (id UUID PRIMARY KEY, revoked_at TIMESTAMPTZ)`,
		`CREATE TABLE tenant_credentials (tenant_id UUID NOT NULL REFERENCES tenants(id), device_id UUID NULL, bearer_token_hash BYTEA NOT NULL, hmac_secret BYTEA NOT NULL, revoked_at TIMESTAMPTZ, expires_at TIMESTAMPTZ)`,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("set up PAT-1417 scratch schema: %v", err)
		}
	}
	return pool
}

func enforcementAuditCredentialSeed(t *testing.T, pool *pgxpool.Pool, revoked, expires *time.Time) string {
	t.Helper()
	ctx := context.Background()
	tenantID := enforcementAuditCredentialUUID(t)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id) VALUES ($1::uuid)`, tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("random token: %v", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	if _, err := pool.Exec(ctx, `INSERT INTO tenant_credentials (tenant_id, device_id, bearer_token_hash, hmac_secret, revoked_at, expires_at) VALUES ($1::uuid, NULL, $2, $3, $4, $5)`, tenantID, hash[:], []byte("test-secret"), revoked, expires); err != nil {
		t.Fatalf("insert credential: %v", err)
	}
	return token
}

func timePtr(value time.Time) *time.Time { return &value }

func enforcementAuditCredentialUUID(t *testing.T) string {
	t.Helper()
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatalf("random UUID: %v", err)
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
}
