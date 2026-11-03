package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"patched.im/api/internal/db"
	"patched.im/api/internal/report"
)

type committedButUnacknowledgedTx struct{ pgx.Tx }

func (tx committedButUnacknowledgedTx) Commit(ctx context.Context) error {
	if err := tx.Tx.Commit(ctx); err != nil {
		return err
	}
	return errors.New("simulated lost COMMIT acknowledgement")
}

// ---------------------------------------------------------------------------
// Pure-logic tests - no DB required
// ---------------------------------------------------------------------------

func TestRevokeTenantHandlerUUIDValidation(t *testing.T) {
	cases := []struct {
		id   string
		want int
	}{
		{"not-a-uuid", http.StatusBadRequest},
		{"gggggggg-0000-0000-0000-000000000000", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			h := RevokeTenantHandler(nil)
			req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+tc.id, nil)
			req = withChiParam(req, "tenantID", tc.id)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Errorf("got %d, want %d", rr.Code, tc.want)
			}
		})
	}
}

func TestRestoreTenantHandlerUUIDValidation(t *testing.T) {
	h := RestoreTenantHandler(nil)
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/bad-id/restore", nil)
	req = withChiParam(req, "tenantID", "bad-id")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", rr.Code)
	}
}

func TestPurgeTenantHandlerUUIDValidation(t *testing.T) {
	h := PurgeTenantHandler(nil)
	req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/bad-id/purge", nil)
	req = withChiParam(req, "tenantID", "bad-id")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", rr.Code)
	}
}

// withChiParam injects a chi URL parameter into the request context.
func withChiParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// ---------------------------------------------------------------------------
// DB round-trip tests - skipped when TEST_DATABASE_URL is not set
// ---------------------------------------------------------------------------

func TestTenantLifecycleDB(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping tenant lifecycle DB round-trip tests")
	}

	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()
	reportRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("REPORT_STORAGE_ROOT", reportRoot)

	// Helper: create a throwaway tenant, clean up after the test.
	createTenant := func(t *testing.T, name string) string {
		t.Helper()
		var id string
		err := pool.QueryRow(ctx, `
			INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
			VALUES ($1, '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
			             '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea)
			RETURNING id::text
		`, name).Scan(&id)
		if err != nil {
			t.Fatalf("createTenant: %v", err)
		}
		t.Cleanup(func() {
			// Best-effort: delete even if the test purged it.
			_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, id)
		})
		return id
	}

	t.Run("revoke sets revoked_at", func(t *testing.T) {
		id := createTenant(t, "lifecycle-revoke-test")

		h := RevokeTenantHandler(pool)
		req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+id, nil)
		req = withChiParam(req, "tenantID", id)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("revoke: got %d, body: %s", rr.Code, rr.Body.String())
		}
		var resp revokeTenantResp
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode revoke resp: %v", err)
		}
		if resp.RevokedAt == "" {
			t.Error("revoked_at should be set")
		}

		// Confirm row in DB.
		var revokedAt *string
		_ = pool.QueryRow(ctx, `SELECT revoked_at::text FROM tenants WHERE id = $1::uuid`, id).Scan(&revokedAt)
		if revokedAt == nil {
			t.Error("revoked_at is NULL in DB after revoke")
		}
	})

	t.Run("revoke is idempotent", func(t *testing.T) {
		id := createTenant(t, "lifecycle-idempotent-test")

		h := RevokeTenantHandler(pool)
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+id, nil)
			req = withChiParam(req, "tenantID", id)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("revoke attempt %d: got %d, body: %s", i+1, rr.Code, rr.Body.String())
			}
		}
	})

	t.Run("revoked tenant excluded from ListTenants", func(t *testing.T) {
		id := createTenant(t, "lifecycle-list-exclude-test")

		// Revoke the tenant.
		_, _ = pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, id)

		h := ListTenantsHandler(pool)
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("list: got %d", rr.Code)
		}
		var resp listTenantsResp
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, entry := range resp.Tenants {
			if entry.ID == id {
				t.Errorf("revoked tenant %s should not appear in ListTenants", id)
			}
		}
	})

	t.Run("ListRevokedTenants shows only revoked", func(t *testing.T) {
		idRevoked := createTenant(t, "lifecycle-revoked-appears")
		idActive := createTenant(t, "lifecycle-active-not-appears")

		_, _ = pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, idRevoked)

		h := ListRevokedTenantsHandler(pool)
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/revoked", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("list revoked: got %d", rr.Code)
		}
		var resp listRevokedTenantsResp
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}

		foundRevoked := false
		for _, e := range resp.Tenants {
			if e.ID == idActive {
				t.Errorf("active tenant %s should not appear in revoked list", idActive)
			}
			if e.ID == idRevoked {
				foundRevoked = true
			}
		}
		if !foundRevoked {
			t.Errorf("revoked tenant %s should appear in revoked list", idRevoked)
		}
	})

	t.Run("restore clears revoked_at", func(t *testing.T) {
		id := createTenant(t, "lifecycle-restore-test")
		_, _ = pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, id)

		h := RestoreTenantHandler(pool)
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+id+"/restore", nil)
		req = withChiParam(req, "tenantID", id)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("restore: got %d, body: %s", rr.Code, rr.Body.String())
		}

		var revokedAt *string
		_ = pool.QueryRow(ctx, `SELECT revoked_at::text FROM tenants WHERE id = $1::uuid`, id).Scan(&revokedAt)
		if revokedAt != nil {
			t.Errorf("revoked_at should be NULL after restore, got %s", *revokedAt)
		}

		// Tenant should reappear in ListTenants.
		lh := ListTenantsHandler(pool)
		lreq := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
		lrr := httptest.NewRecorder()
		lh.ServeHTTP(lrr, lreq)
		var listResp listTenantsResp
		_ = json.NewDecoder(lrr.Body).Decode(&listResp)
		found := false
		for _, e := range listResp.Tenants {
			if e.ID == id {
				found = true
			}
		}
		if !found {
			t.Errorf("restored tenant %s should appear in ListTenants", id)
		}
	})

	t.Run("purge 409 on non-revoked tenant", func(t *testing.T) {
		id := createTenant(t, "lifecycle-purge-409-test")

		h := PurgeTenantHandler(pool)
		req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+id+"/purge", nil)
		req = withChiParam(req, "tenantID", id)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusConflict {
			t.Errorf("purge non-revoked: got %d, want 409", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "offboard before purge") {
			t.Errorf("expected 'offboard before purge' in body, got: %s", rr.Body.String())
		}
	})

	t.Run("purge cascades on revoked tenant", func(t *testing.T) {
		id := createTenant(t, "lifecycle-purge-cascade-test")
		_, _ = pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, id)

		h := PurgeTenantHandler(pool)
		req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+id+"/purge", nil)
		req = withChiParam(req, "tenantID", id)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("purge: got %d, body: %s", rr.Code, rr.Body.String())
		}
		var resp purgeTenantResp
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode purge resp: %v", err)
		}
		if !resp.Purged {
			t.Error("purged should be true")
		}

		// Row should be gone.
		var exists bool
		_ = pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid)`, id).Scan(&exists)
		if exists {
			t.Errorf("tenant %s should be deleted after purge", id)
		}

		// Cleanup is a no-op (already purged) - t.Cleanup will just get ErrNoRows.
	})

	t.Run("purge 404 on nonexistent tenant", func(t *testing.T) {
		const nonexistent = "00000000-0000-0000-0000-000000000001"
		h := PurgeTenantHandler(pool)
		req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+nonexistent+"/purge", nil)
		req = withChiParam(req, "tenantID", nonexistent)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("purge nonexistent: got %d, want 404", rr.Code)
		}
	})

	// PAT-1137: a purge must ANONYMISE, not delete, the governance audit
	// trail (tenant_tier_changes, device_revocations, enrollment_token_audit,
	// tenant_decommission_audit) while still fully erasing everything else
	// (provenance_records, devices, bootstrap_tokens). This is "a test
	// proving purge does what the comment says it does", named explicitly
	// in the ticket.
	t.Run("purge anonymises governance audit rows instead of deleting them", func(t *testing.T) {
		id := createTenant(t, "lifecycle-purge-anonymise-test")

		var deviceID, tokenID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO devices (tenant_id, hostname) VALUES ($1::uuid, 'anon-test-device') RETURNING id::text`,
			id).Scan(&deviceID); err != nil {
			t.Fatalf("insert device: %v", err)
		}
		if err := pool.QueryRow(ctx,
			`INSERT INTO bootstrap_tokens (tenant_id, token_hash, expires_at)
			 VALUES ($1::uuid, '\x00'::bytea, now() + interval '1 day') RETURNING id::text`,
			id).Scan(&tokenID); err != nil {
			t.Fatalf("insert bootstrap token: %v", err)
		}

		if _, err := pool.Exec(ctx, `
			INSERT INTO tenant_tier_changes (tenant_id, from_tier, to_tier, changed_by, claimed_actor, source_addr)
			VALUES ($1::uuid, 'assurance', 'managed', 'admin_shared_token', 'andy@patched.im', '203.0.113.5')
		`, id); err != nil {
			t.Fatalf("insert tenant_tier_changes: %v", err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO device_revocations (tenant_id, device_id, admin_id, action, claimed_actor, source_addr)
			VALUES ($1::uuid, $2::uuid, 'admin_shared_token', 'revoke', 'andy@patched.im', '203.0.113.5')
		`, id, deviceID); err != nil {
			t.Fatalf("insert device_revocations: %v", err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO enrollment_token_audit (tenant_id, token_id, delivery_path, expires_at, actor_email, admin_note)
			VALUES ($1::uuid, $2::uuid, 'mdm', now() + interval '1 day', 'portal-user@customer.com', 'note identifying the requester')
		`, id, tokenID); err != nil {
			t.Fatalf("insert enrollment_token_audit: %v", err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO tenant_decommission_audit (tenant_id, actor, new_mode, purge, reason, claimed_actor, source_addr)
			VALUES ($1::uuid, 'admin_shared_token', 'immediate', true, 'customer requested offboarding', 'andy@patched.im', '203.0.113.5')
		`, id); err != nil {
			t.Fatalf("insert tenant_decommission_audit: %v", err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO provenance_records (tenant_id, body) VALUES ($1::uuid, '{}'::jsonb)
		`, id); err != nil {
			t.Fatalf("insert provenance_records: %v", err)
		}

		_, _ = pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, id)

		h := PurgeTenantHandler(pool)
		req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+id+"/purge", nil)
		req = withChiParam(req, "tenantID", id)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("purge: got %d, body: %s", rr.Code, rr.Body.String())
		}

		// tenant_tier_changes: row survives, shape intact, claimed_actor/
		// source_addr redacted, tenant_id kept (dangling - the tenants row
		// is gone).
		var fromTier, toTier, changedBy, tenantIDOut string
		var claimedActor, sourceAddr *string
		err = pool.QueryRow(ctx, `
			SELECT tenant_id::text, from_tier, to_tier, changed_by, claimed_actor, source_addr
			FROM tenant_tier_changes WHERE tenant_id = $1::uuid
		`, id).Scan(&tenantIDOut, &fromTier, &toTier, &changedBy, &claimedActor, &sourceAddr)
		if err != nil {
			t.Fatalf("tenant_tier_changes should survive purge: %v", err)
		}
		if tenantIDOut != id {
			t.Errorf("tenant_tier_changes.tenant_id = %q, want %q (kept, dangling)", tenantIDOut, id)
		}
		if fromTier != "assurance" || toTier != "managed" {
			t.Errorf("tenant_tier_changes shape not preserved: from=%q to=%q", fromTier, toTier)
		}
		if claimedActor != nil || sourceAddr != nil {
			t.Errorf("tenant_tier_changes identifying fields not anonymised: claimed_actor=%v source_addr=%v", claimedActor, sourceAddr)
		}

		// device_revocations: row survives, action/admin_id preserved,
		// device_id/claimed_actor/source_addr redacted.
		var action, adminID string
		var deviceIDOut *string
		err = pool.QueryRow(ctx, `
			SELECT action, admin_id, device_id::text, claimed_actor, source_addr
			FROM device_revocations WHERE tenant_id = $1::uuid
		`, id).Scan(&action, &adminID, &deviceIDOut, &claimedActor, &sourceAddr)
		if err != nil {
			t.Fatalf("device_revocations should survive purge: %v", err)
		}
		if action != "revoke" {
			t.Errorf("device_revocations shape not preserved: action=%q", action)
		}
		if deviceIDOut != nil || claimedActor != nil || sourceAddr != nil {
			t.Errorf("device_revocations identifying fields not anonymised: device_id=%v claimed_actor=%v source_addr=%v", deviceIDOut, claimedActor, sourceAddr)
		}

		// enrollment_token_audit: row survives, delivery_path preserved,
		// token_id/actor_email/admin_note redacted.
		var deliveryPath string
		var tokenIDOut, actorEmail, adminNote *string
		err = pool.QueryRow(ctx, `
			SELECT delivery_path, token_id::text, actor_email, admin_note
			FROM enrollment_token_audit WHERE tenant_id = $1::uuid
		`, id).Scan(&deliveryPath, &tokenIDOut, &actorEmail, &adminNote)
		if err != nil {
			t.Fatalf("enrollment_token_audit should survive purge: %v", err)
		}
		if deliveryPath != "mdm" {
			t.Errorf("enrollment_token_audit shape not preserved: delivery_path=%q", deliveryPath)
		}
		if tokenIDOut != nil || actorEmail != nil || adminNote != nil {
			t.Errorf("enrollment_token_audit identifying fields not anonymised: token_id=%v actor_email=%v admin_note=%v", tokenIDOut, actorEmail, adminNote)
		}

		// tenant_decommission_audit: row survives (it always did - no FK to
		// begin with), new_mode/purge preserved, reason/claimed_actor/
		// source_addr redacted.
		var newMode string
		var purge bool
		var reason *string
		err = pool.QueryRow(ctx, `
			SELECT new_mode, purge, reason, claimed_actor, source_addr
			FROM tenant_decommission_audit WHERE tenant_id = $1::uuid
		`, id).Scan(&newMode, &purge, &reason, &claimedActor, &sourceAddr)
		if err != nil {
			t.Fatalf("tenant_decommission_audit should survive purge: %v", err)
		}
		if newMode != "immediate" || !purge {
			t.Errorf("tenant_decommission_audit shape not preserved: new_mode=%q purge=%v", newMode, purge)
		}
		if reason != nil || claimedActor != nil || sourceAddr != nil {
			t.Errorf("tenant_decommission_audit identifying fields not anonymised: reason=%v claimed_actor=%v source_addr=%v", reason, claimedActor, sourceAddr)
		}

		// provenance_records, devices, bootstrap_tokens: genuinely gone.
		// PAT-1137 does not widen the purge for anything not on the
		// survive list.
		var provenanceCount, deviceCount, tokenCount int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM provenance_records WHERE tenant_id = $1::uuid`, id).Scan(&provenanceCount)
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM devices WHERE tenant_id = $1::uuid`, id).Scan(&deviceCount)
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM bootstrap_tokens WHERE tenant_id = $1::uuid`, id).Scan(&tokenCount)
		if provenanceCount != 0 {
			t.Errorf("provenance_records should be fully purged, found %d rows", provenanceCount)
		}
		if deviceCount != 0 {
			t.Errorf("devices should be fully purged, found %d rows", deviceCount)
		}
		if tokenCount != 0 {
			t.Errorf("bootstrap_tokens should be fully purged, found %d rows", tokenCount)
		}

		// Best-effort cleanup of the surviving anonymised rows so repeated
		// test runs don't accumulate them - done via a direct anonymising
		// UPDATE-then-can't-DELETE is not available outside the trigger, so
		// this is intentionally a no-op: these rows are SUPPOSED to survive
		// forever (or until the PAT-112 retention sweep exists), and the
		// append-only guard correctly refuses to let this test delete them
		// directly. Matches the polluted-fixture reality already noted for
		// this DB (see AGENTS.md / MEMORY.md); harmless for other tests
		// since every assertion above filters on this test's own tenant_id.
	})

	t.Run("purge anonymises every assessment audit action and removes served bytes", func(t *testing.T) {
		id := createTenant(t, "lifecycle-assessment-audit-anonymise-test")
		const artifactID = "22222222-3333-4444-8555-666666666666"
		if _, err := pool.Exec(ctx, `
			INSERT INTO assessment_artifact_audit
			    (tenant_id, artifact_id, token_id, action, actor, recipient_email, sha256, occurred_at)
			VALUES
			    ($1::uuid, $2::uuid, NULL, 'approved', 'approver@patched.im', NULL, decode(repeat('ab', 32), 'hex'), '2026-08-01T10:00:00Z'),
			    ($1::uuid, $2::uuid, 41, 'token_issued', 'sender@patched.im', 'recipient@example.com', decode(repeat('bc', 32), 'hex'), '2026-08-01T11:00:00Z'),
			    ($1::uuid, $2::uuid, 42, 'downloaded', NULL, 'recipient@example.com', decode(repeat('cd', 32), 'hex'), '2026-08-01T12:00:00Z')
		`, id, artifactID); err != nil {
			t.Fatalf("insert assessment audit actions: %v", err)
		}
		artifactDir := filepath.Join(reportRoot, "assessments", id, artifactID)
		if err := os.MkdirAll(artifactDir, 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(artifactDir, "assessment.pdf"), []byte("approved assessment"), 0640); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, id); err != nil {
			t.Fatal(err)
		}

		h := PurgeTenantHandler(pool)
		req := withChiParam(httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+id+"/purge", nil), "tenantID", id)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("purge: got %d, body: %s", rr.Code, rr.Body.String())
		}
		if _, err := os.Lstat(filepath.Join(reportRoot, "assessments", id)); !os.IsNotExist(err) {
			t.Fatalf("served assessment directory remains after purge: %v", err)
		}

		rows, err := pool.Query(ctx, `
			SELECT action, artifact_id::text, encode(sha256, 'hex'), occurred_at::text,
			       actor, recipient_email, token_id, tenant_purge_anonymized_at
			  FROM assessment_artifact_audit
			 WHERE tenant_id = $1::uuid
			 ORDER BY occurred_at
		`, id)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		wantActions := []string{"approved", "token_issued", "downloaded"}
		seen := 0
		for rows.Next() {
			var action, artifact, hash, occurred string
			var actor, recipient *string
			var token *int64
			var anonymizedAt *time.Time
			if err := rows.Scan(&action, &artifact, &hash, &occurred, &actor, &recipient, &token, &anonymizedAt); err != nil {
				t.Fatal(err)
			}
			if seen >= len(wantActions) || action != wantActions[seen] || artifact != artifactID || len(hash) != 64 || occurred == "" {
				t.Fatalf("governance shape changed: action=%q artifact=%q hash=%q occurred=%q", action, artifact, hash, occurred)
			}
			if actor != nil || recipient != nil || token != nil {
				t.Fatalf("assessment identifiers survived purge: actor=%v recipient=%v token=%v", actor, recipient, token)
			}
			if anonymizedAt == nil {
				t.Fatal("assessment purge did not set its durable anonymisation marker")
			}
			seen++
		}
		if seen != len(wantActions) {
			t.Fatalf("assessment audit rows seen=%d want=%d", seen, len(wantActions))
		}
	})

	t.Run("database delete failure restores quarantined assessment bytes", func(t *testing.T) {
		id := createTenant(t, "lifecycle-assessment-delete-failure-test")
		artifact := filepath.Join(reportRoot, "assessments", id, "artifact", "assessment.pdf")
		if err := os.MkdirAll(filepath.Dir(artifact), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(artifact, []byte("must return"), 0640); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, id); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `
			CREATE OR REPLACE FUNCTION pat1407_test_reject_tenant_delete() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
			    IF OLD.name = 'lifecycle-assessment-delete-failure-test' THEN
			        RAISE EXCEPTION 'PAT-1407 forced delete failure';
			    END IF;
			    RETURN OLD;
			END $$;
			DROP TRIGGER IF EXISTS trg_pat1407_test_reject_tenant_delete ON tenants;
			CREATE TRIGGER trg_pat1407_test_reject_tenant_delete BEFORE DELETE ON tenants
			FOR EACH ROW EXECUTE FUNCTION pat1407_test_reject_tenant_delete();
		`); err != nil {
			t.Fatalf("install delete-failure trigger: %v", err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(ctx, `DROP TRIGGER IF EXISTS trg_pat1407_test_reject_tenant_delete ON tenants`)
			_, _ = pool.Exec(ctx, `DROP FUNCTION IF EXISTS pat1407_test_reject_tenant_delete()`)
		})
		h := PurgeTenantHandler(pool)
		req := withChiParam(httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+id+"/purge", nil), "tenantID", id)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("forced delete failure returned %d, body: %s", rr.Code, rr.Body.String())
		}
		if got, err := os.ReadFile(artifact); err != nil || string(got) != "must return" {
			t.Fatalf("assessment bytes were not restored: %q %v", got, err)
		}
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1::uuid)`, id).Scan(&exists); err != nil || !exists {
			t.Fatalf("tenant delete did not roll back: exists=%v err=%v", exists, err)
		}
	})

	// PAT-2410: generated report files (<root>/<tenant>/<record>/report.pdf and
	// report.csv) are customer data and must go with the tenant.
	issueReport := func(t *testing.T, tenantID, name string) *reportRecord {
		t.Helper()
		rec, err := storeReportRecord(ctx, pool, tenantID, name, nil,
			report.ContentTypeFull, time.Time{}, time.Time{},
			[]byte("pdf for "+name), nil, []byte("csv for "+name),
			"portal", "executive-summary", slog.Default(), nil, nil, nil)
		if err != nil {
			t.Fatalf("storeReportRecord: %v", err)
		}
		return rec
	}
	reportFiles := func(tenantID string, rec *reportRecord) []string {
		dir := filepath.Join(reportRoot, tenantID, rec.ID)
		return []string{filepath.Join(dir, "report.pdf"), filepath.Join(dir, "report.csv")}
	}
	purgeOnce := func(t *testing.T, id string) *httptest.ResponseRecorder {
		t.Helper()
		req := withChiParam(httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+id+"/purge", nil), "tenantID", id)
		rr := httptest.NewRecorder()
		PurgeTenantHandler(pool).ServeHTTP(rr, req)
		return rr
	}

	t.Run("purge removes the tenant's generated report files and nothing else", func(t *testing.T) {
		id := createTenant(t, "lifecycle-report-files-purge-test")
		other := createTenant(t, "lifecycle-report-files-purge-bystander-test")
		rec := issueReport(t, id, "purged")
		otherRec := issueReport(t, other, "bystander")
		otherAssessment := filepath.Join(reportRoot, "assessments", other, "artifact", "assessment.pdf")
		if err := os.MkdirAll(filepath.Dir(otherAssessment), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(otherAssessment, []byte("bystander assessment"), 0640); err != nil {
			t.Fatal(err)
		}
		for _, f := range reportFiles(id, rec) {
			if _, err := os.Stat(f); err != nil {
				t.Fatalf("fixture file missing: %v", err)
			}
		}
		if _, err := pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, id); err != nil {
			t.Fatal(err)
		}
		rr := purgeOnce(t, id)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"purged":true`) {
			t.Fatalf("purge returned %d: %s", rr.Code, rr.Body.String())
		}
		if _, err := os.Lstat(filepath.Join(reportRoot, id)); !os.IsNotExist(err) {
			t.Fatalf("tenant report directory remains after purge: %v", err)
		}
		matches, err := filepath.Glob(filepath.Join(reportRoot, assessmentQuarantineDir, id+"-*"))
		if err != nil || len(matches) != 0 {
			t.Fatalf("quarantine residue remains: %v %v", matches, err)
		}
		for _, f := range append(reportFiles(other, otherRec), otherAssessment) {
			if _, err := os.ReadFile(f); err != nil {
				t.Fatalf("bystander file touched by purge: %v", err)
			}
		}
	})

	t.Run("failed purge leaves report rows and files intact", func(t *testing.T) {
		id := createTenant(t, "lifecycle-assessment-delete-failure-test")
		rec := issueReport(t, id, "must survive")
		if _, err := pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, id); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `
			CREATE OR REPLACE FUNCTION pat1407_test_reject_tenant_delete() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
			    IF OLD.name = 'lifecycle-assessment-delete-failure-test' THEN
			        RAISE EXCEPTION 'PAT-1407 forced delete failure';
			    END IF;
			    RETURN OLD;
			END $$;
			DROP TRIGGER IF EXISTS trg_pat1407_test_reject_tenant_delete ON tenants;
			CREATE TRIGGER trg_pat1407_test_reject_tenant_delete BEFORE DELETE ON tenants
			FOR EACH ROW EXECUTE FUNCTION pat1407_test_reject_tenant_delete();
		`); err != nil {
			t.Fatalf("install delete-failure trigger: %v", err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(ctx, `DROP TRIGGER IF EXISTS trg_pat1407_test_reject_tenant_delete ON tenants`)
			_, _ = pool.Exec(ctx, `DROP FUNCTION IF EXISTS pat1407_test_reject_tenant_delete()`)
		})
		rr := purgeOnce(t, id)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("forced delete failure returned %d: %s", rr.Code, rr.Body.String())
		}
		for i, f := range reportFiles(id, rec) {
			want := []string{"pdf for must survive", "csv for must survive"}[i]
			if got, err := os.ReadFile(f); err != nil || string(got) != want {
				t.Fatalf("report file not restored at %s: %q %v", f, got, err)
			}
		}
		var rows int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM report_records WHERE tenant_id=$1::uuid`, id).Scan(&rows); err != nil || rows != 1 {
			t.Fatalf("report row did not survive the failed purge: rows=%d err=%v", rows, err)
		}
	})

	t.Run("unsafe report directory aborts the purge and restores assessment bytes", func(t *testing.T) {
		id := createTenant(t, "lifecycle-report-files-unsafe-test")
		artifact := filepath.Join(reportRoot, "assessments", id, "artifact", "assessment.pdf")
		if err := os.MkdirAll(filepath.Dir(artifact), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(artifact, []byte("must return"), 0640); err != nil {
			t.Fatal(err)
		}
		// A symlinked tenant report directory is refused, never followed.
		if err := os.Symlink(t.TempDir(), filepath.Join(reportRoot, id)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(filepath.Join(reportRoot, id)) })
		if _, err := pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, id); err != nil {
			t.Fatal(err)
		}
		rr := purgeOnce(t, id)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("unsafe report directory returned %d: %s", rr.Code, rr.Body.String())
		}
		if got, err := os.ReadFile(artifact); err != nil || string(got) != "must return" {
			t.Fatalf("assessment bytes were not restored: %q %v", got, err)
		}
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1::uuid)`, id).Scan(&exists); err != nil || !exists {
			t.Fatalf("tenant was purged despite report quarantine failure: exists=%v err=%v", exists, err)
		}
	})

	t.Run("purge of a tenant with no report directory succeeds", func(t *testing.T) {
		id := createTenant(t, "lifecycle-report-files-absent-test")
		if _, err := pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, id); err != nil {
			t.Fatal(err)
		}
		rr := purgeOnce(t, id)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"purged":true`) {
			t.Fatalf("purge without report directory returned %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("cleanup failure reports residue while served path stays absent", func(t *testing.T) {
		id := createTenant(t, "lifecycle-assessment-cleanup-residue-test")
		lockedDir := filepath.Join(reportRoot, "assessments", id, "artifact")
		if err := os.MkdirAll(lockedDir, 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(lockedDir, "assessment.pdf"), []byte("cleanup pending"), 0640); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, id); err != nil {
			t.Fatal(err)
		}

		var displacedResidue string
		h := purgeTenantHandler(pool.BeginTx, func(q *assessmentQuarantine) {
			residue := filepath.Join(reportRoot, q.residue())
			displacedResidue = residue + ".identity-replaced"
			if err := os.Rename(residue, displacedResidue); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(residue, 0700); err != nil {
				t.Fatal(err)
			}
		}, nil)
		req := withChiParam(httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+id+"/purge", nil), "tenantID", id)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("cleanup residue returned %d, body: %s", rr.Code, rr.Body.String())
		}
		var resp purgeTenantResp
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		if !resp.Purged || !resp.CleanupPending || resp.Residue == "" {
			t.Fatalf("cleanup residue response is not explicit: %+v", resp)
		}
		if _, err := os.Lstat(filepath.Join(reportRoot, "assessments", id)); !os.IsNotExist(err) {
			t.Fatalf("ordinary served path remains: %v", err)
		}
		residue := filepath.Join(reportRoot, resp.Residue)
		if _, err := os.Lstat(residue); err != nil {
			t.Fatalf("reported quarantine residue is absent: %v", err)
		}
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1::uuid)`, id).Scan(&exists); err != nil || exists {
			t.Fatalf("tenant purge did not commit: exists=%v err=%v", exists, err)
		}
		if err := os.RemoveAll(residue); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(displacedResidue); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("cleanup fsync failure never reports a deleted residue", func(t *testing.T) {
		id := createTenant(t, "lifecycle-assessment-cleanup-fsync-test")
		artifact := filepath.Join(reportRoot, "assessments", id, "artifact", "assessment.pdf")
		if err := os.MkdirAll(filepath.Dir(artifact), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(artifact, []byte("remove before fsync failure"), 0640); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, id); err != nil {
			t.Fatal(err)
		}
		originalFsync := assessmentQuarantineFsync
		assessmentQuarantineFsync = func(int) error { return errors.New("forced cleanup fsync failure") }
		t.Cleanup(func() { assessmentQuarantineFsync = originalFsync })

		h := PurgeTenantHandler(pool)
		req := withChiParam(httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+id+"/purge", nil), "tenantID", id)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("cleanup fsync failure returned %d, body: %s", rr.Code, rr.Body.String())
		}
		var resp purgeTenantResp
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		if !resp.Purged || resp.PurgeStatus != "committed_cleanup_durability_unconfirmed" || resp.CleanupPending || resp.Residue != "" {
			t.Fatalf("cleanup fsync response reported ghost residue: %+v", resp)
		}
		if _, err := os.Lstat(filepath.Join(reportRoot, "assessments", id)); !os.IsNotExist(err) {
			t.Fatalf("served assessment path remains: %v", err)
		}
		matches, err := filepath.Glob(filepath.Join(reportRoot, assessmentQuarantineDir, id+"-*"))
		if err != nil || len(matches) != 0 {
			t.Fatalf("deleted quarantine residue was still reported on disk: %v %v", matches, err)
		}
	})

	t.Run("ambiguous commit keeps bytes quarantined without claiming purge success", func(t *testing.T) {
		id := createTenant(t, "lifecycle-assessment-ambiguous-commit-test")
		artifact := filepath.Join(reportRoot, "assessments", id, "artifact", "assessment.pdf")
		if err := os.MkdirAll(filepath.Dir(artifact), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(artifact, []byte("never republish ambiguously committed bytes"), 0640); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, id); err != nil {
			t.Fatal(err)
		}

		beginAmbiguous := func(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
			tx, err := pool.BeginTx(ctx, opts)
			if err != nil {
				return nil, err
			}
			return committedButUnacknowledgedTx{Tx: tx}, nil
		}
		h := purgeTenantHandler(beginAmbiguous, nil, nil)
		req := withChiParam(httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+id+"/purge", nil), "tenantID", id)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("ambiguous commit returned %d: %s", rr.Code, rr.Body.String())
		}
		var resp purgeTenantResp
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		if resp.Purged || resp.PurgeStatus != "commit_outcome_unknown" || !resp.CleanupPending || resp.Residue == "" {
			t.Fatalf("ambiguous response claimed success or omitted residue: %+v", resp)
		}
		if _, err := os.Lstat(filepath.Join(reportRoot, "assessments", id)); !os.IsNotExist(err) {
			t.Fatalf("ambiguous commit republished served bytes: %v", err)
		}
		residue := filepath.Join(reportRoot, resp.Residue)
		if got, err := os.ReadFile(filepath.Join(residue, "artifact", "assessment.pdf")); err != nil || string(got) != "never republish ambiguously committed bytes" {
			t.Fatalf("ambiguous commit did not retain exact residue: %q %v", got, err)
		}
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1::uuid)`, id).Scan(&exists); err != nil || exists {
			t.Fatalf("test commit did not actually commit: exists=%v err=%v", exists, err)
		}
		if err := os.RemoveAll(residue); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("post-rename quarantine failure reports residue without deleting tenant", func(t *testing.T) {
		id := createTenant(t, "lifecycle-assessment-post-rename-failure-test")
		artifact := filepath.Join(reportRoot, "assessments", id, "artifact", "assessment.pdf")
		if err := os.MkdirAll(filepath.Dir(artifact), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(artifact, []byte("retain after quarantine failure"), 0640); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, id); err != nil {
			t.Fatal(err)
		}
		failAfterRename := func(root, tenantID string, expected bool) (*assessmentQuarantine, error) {
			q, err := quarantineAssessmentArtifacts(root, tenantID, expected)
			if err != nil {
				return q, err
			}
			return q, errors.New("simulated post-rename durability failure")
		}
		h := purgeTenantHandler(pool.BeginTx, nil, failAfterRename)
		req := withChiParam(httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+id+"/purge", nil), "tenantID", id)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("post-rename failure returned %d: %s", rr.Code, rr.Body.String())
		}
		var resp purgeTenantResp
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		if resp.Purged || resp.PurgeStatus != "quarantine_failed_residue_retained" || !resp.CleanupPending || resp.Residue == "" {
			t.Fatalf("post-rename failure response was not explicit: %+v", resp)
		}
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1::uuid)`, id).Scan(&exists); err != nil || !exists {
			t.Fatalf("tenant changed after quarantine failure: exists=%v err=%v", exists, err)
		}
		residue := filepath.Join(reportRoot, resp.Residue)
		if got, err := os.ReadFile(filepath.Join(residue, "artifact", "assessment.pdf")); err != nil || string(got) != "retain after quarantine failure" {
			t.Fatalf("post-rename failure residue missing: %q %v", got, err)
		}
		if err := os.RemoveAll(residue); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("post-rename restored failure never claims retained residue", func(t *testing.T) {
		id := createTenant(t, "lifecycle-assessment-post-rename-restored-test")
		if _, err := pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, id); err != nil {
			t.Fatal(err)
		}
		restoredFailure := func(string, string, bool) (*assessmentQuarantine, error) {
			return nil, &postRenameQuarantineError{err: errors.New("simulated verification failure after successful restore"), restored: true}
		}
		h := purgeTenantHandler(pool.BeginTx, nil, restoredFailure)
		req := withChiParam(httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+id+"/purge", nil), "tenantID", id)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		var resp purgeTenantResp
		if rr.Code != http.StatusInternalServerError || json.NewDecoder(rr.Body).Decode(&resp) != nil {
			t.Fatalf("restored post-rename failure response %d: %s", rr.Code, rr.Body.String())
		}
		if resp.Purged || resp.PurgeStatus != "quarantine_failed_restored" || resp.CleanupPending || resp.Residue != "" {
			t.Fatalf("restored failure claimed retained residue: %+v", resp)
		}
	})

	// PAT-1137: the append-only guards must still reject an ordinary
	// UPDATE or DELETE against the newly-guarded survive-list tables from
	// any path other than the anonymisation trigger itself - the security
	// property that must not regress.
	t.Run("append-only guards still reject direct mutation outside anonymisation", func(t *testing.T) {
		id := createTenant(t, "lifecycle-append-only-guard-test")

		if _, err := pool.Exec(ctx, `
			INSERT INTO tenant_tier_changes (tenant_id, from_tier, to_tier, changed_by)
			VALUES ($1::uuid, 'assurance', 'managed', 'admin_shared_token')
		`, id); err != nil {
			t.Fatalf("insert tenant_tier_changes: %v", err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO enrollment_token_audit (tenant_id, token_id, delivery_path, expires_at)
			VALUES ($1::uuid, NULL, 'mdm', now() + interval '1 day')
		`, id); err != nil {
			t.Fatalf("insert enrollment_token_audit: %v", err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO tenant_decommission_audit (tenant_id, actor, new_mode, purge)
			VALUES ($1::uuid, 'admin_shared_token', 'immediate', true)
		`, id); err != nil {
			t.Fatalf("insert tenant_decommission_audit: %v", err)
		}

		cases := []struct {
			name  string
			query string
		}{
			{"tenant_tier_changes UPDATE", `UPDATE tenant_tier_changes SET changed_by = 'tampered' WHERE tenant_id = $1::uuid`},
			{"tenant_tier_changes DELETE", `DELETE FROM tenant_tier_changes WHERE tenant_id = $1::uuid`},
			{"enrollment_token_audit UPDATE", `UPDATE enrollment_token_audit SET admin_note = 'tampered' WHERE tenant_id = $1::uuid`},
			{"enrollment_token_audit DELETE", `DELETE FROM enrollment_token_audit WHERE tenant_id = $1::uuid`},
			{"tenant_decommission_audit UPDATE", `UPDATE tenant_decommission_audit SET reason = 'tampered' WHERE tenant_id = $1::uuid`},
			{"tenant_decommission_audit DELETE", `DELETE FROM tenant_decommission_audit WHERE tenant_id = $1::uuid`},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := pool.Exec(ctx, tc.query, id)
				if err == nil {
					t.Fatalf("%s: expected append-only rejection, got no error", tc.name)
				}
				if !strings.Contains(err.Error(), "append-only") {
					t.Errorf("%s: expected an append-only error, got: %v", tc.name, err)
				}
			})
		}
	})

	t.Run("assessment audit rejects direct mutation and caller-set bypass", func(t *testing.T) {
		id := createTenant(t, "lifecycle-assessment-append-only-test")
		const artifactID = "33333333-4444-4555-8666-777777777777"
		if _, err := pool.Exec(ctx, `
			INSERT INTO assessment_artifact_audit(tenant_id, artifact_id, action, actor, sha256)
			VALUES($1::uuid, $2::uuid, 'approved', 'approver@patched.im', decode(repeat('ef',32),'hex'))
		`, id, artifactID); err != nil {
			t.Fatal(err)
		}
		cases := []string{
			`UPDATE assessment_artifact_audit SET actor=NULL WHERE tenant_id=$1::uuid`,
			`UPDATE assessment_artifact_audit SET action='downloaded' WHERE tenant_id=$1::uuid`,
			`DELETE FROM assessment_artifact_audit WHERE tenant_id=$1::uuid`,
		}
		for _, query := range cases {
			if _, err := pool.Exec(ctx, query, id); err == nil || !strings.Contains(err.Error(), "append-only") {
				t.Fatalf("direct mutation was not rejected for %q: %v", query, err)
			}
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('patched.tenant_purge_anonymizing','on',true)`); err != nil {
			t.Fatal(err)
		}
		_, bypassErr := tx.Exec(ctx, `UPDATE assessment_artifact_audit SET actor=NULL WHERE tenant_id=$1::uuid`, id)
		_ = tx.Rollback(ctx)
		if bypassErr == nil || !strings.Contains(bypassErr.Error(), "append-only") {
			t.Fatalf("caller-set GUC bypassed append-only guard: %v", bypassErr)
		}
		tx, err = pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, truncateErr := tx.Exec(ctx, `TRUNCATE assessment_artifact_audit`)
		_ = tx.Rollback(ctx)
		if truncateErr == nil || !strings.Contains(truncateErr.Error(), "append-only") {
			t.Fatalf("TRUNCATE was not rejected: %v", truncateErr)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO assessment_artifact_audit(tenant_id, artifact_id, action, sha256)
			VALUES($1::uuid, $2::uuid, 'approved', decode(repeat('aa',32),'hex'))
		`, id, artifactID); err == nil || !strings.Contains(err.Error(), "invalid action identity shape") {
			t.Fatalf("anonymised-shaped direct INSERT was not rejected: %v", err)
		}
	})
}
