package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/agentconfig"
	"patched.im/api/internal/envelope"
)

// CreateTenant* lives on the internal Tailscale-bound listener.
//
// Auth posture (MVP): no application-layer auth on this endpoint. It's
// protected by three layers of network restriction instead:
//  1. The Go service binds it to 127.0.0.1:8081 — only Caddy can reach it.
//  2. Caddy's internal site block binds only to the box's Tailscale interface
//     (no public ingress).
//  3. The tailnet ACL allows only `tag:main` to reach `tag:api:8443`.
//
// Layered network restriction is sufficient at MVP. Application-layer
// admin auth (e.g. mTLS or a separate admin bearer) is a v2 hardening.

type createTenantReq struct {
	Name           string `json:"name"`
	IntuneTenantID string `json:"intune_tenant_id,omitempty"`
	Tier           int    `json:"tier,omitempty"`
	ContactName    string `json:"contact_name,omitempty"`
	ContactEmail   string `json:"contact_email,omitempty"`
	ContactRole    string `json:"contact_role,omitempty"`
}

type createTenantResp struct {
	TenantID      string `json:"tenant_id"`
	BearerToken   string `json:"bearer_token"`
	HMACSecretB64 string `json:"hmac_secret_b64"`
	Tier          int    `json:"tier"`
	Warning       string `json:"warning"`
}

type listTenantsEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type listTenantsResp struct {
	Tenants []listTenantsEntry `json:"tenants"`
}

type rotateCredentialsResp struct {
	TenantID      string `json:"tenant_id"`
	CredentialID  int64  `json:"credential_id"`
	BearerToken   string `json:"bearer_token"`
	HMACSecretB64 string `json:"hmac_secret_b64"`
	GraceUntil    string `json:"grace_until"`
	Warning       string `json:"warning"`
}

// ListTenantsHandler returns id + name for every tenant, ordered by name.
// Used by the admin UI to populate the tenant dropdown.
func ListTenantsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "list_tenants")

		rows, err := pool.Query(r.Context(), `SELECT id::text, name FROM tenants WHERE revoked_at IS NULL ORDER BY name`)
		if err != nil {
			logger.Error("query tenants failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var tenants []listTenantsEntry
		for rows.Next() {
			var e listTenantsEntry
			if err := rows.Scan(&e.ID, &e.Name); err != nil {
				logger.Error("scan tenant failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			tenants = append(tenants, e)
		}
		if err := rows.Err(); err != nil {
			logger.Error("iterate tenants failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if tenants == nil {
			tenants = []listTenantsEntry{}
		}

		logger.Info("tenants listed", "count", len(tenants))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(listTenantsResp{Tenants: tenants})
	}
}

func CreateTenantHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "create_tenant")

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<14)) // 16 KB is plenty
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var req createTenantReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}

		// Tenant row, initial credential, pre-approved Patched Agent policies
		// and the T2 baseline, all in one transaction: a failure in any step
		// rolls the whole creation back rather than half-creating a tenant.
		// The steps live in provisionTenant, shared with self-service
		// organisation sign-up (PAT-1883) so the two cannot drift.
		tx, err := pool.Begin(r.Context())
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback(r.Context()) //nolint:errcheck

		created, err := provisionTenant(r.Context(), tx, tenantProvision{
			Name:           req.Name,
			IntuneTenantID: req.IntuneTenantID,
			Tier:           req.Tier,
			ContactName:    req.ContactName,
			ContactEmail:   req.ContactEmail,
			ContactRole:    req.ContactRole,
		})
		if err != nil {
			logger.Error("tenant provisioning failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		tenantID, tier := created.TenantID, created.Tier

		logger.Info("tenant created", "tenant_id", tenantID, "name", req.Name, "tier", tier)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(createTenantResp{
			TenantID:      tenantID,
			BearerToken:   created.BearerToken,
			HMACSecretB64: base64.StdEncoding.EncodeToString(created.HMACSecret),
			Tier:          tier,
			Warning:       "store bearer_token and hmac_secret_b64 immediately — neither is recoverable after this response.",
		})
	}
}

// RotateCredentialsHandler mints a new bearer token + HMAC secret for a
// tenant, inserts the new credential row, and sets the previous active
// credential(s) to expire after the grace window. Both old and new credentials
// are valid during the grace period — the endpoint has time to pick up the new
// creds before the old ones expire.
//
// The new plaintext credentials are returned once in this response; they are
// not recoverable afterwards.
func RotateCredentialsHandler(pool *pgxpool.Pool, defaultGrace time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		logger := slog.With("req_id", reqID, "handler", "rotate_credentials", "tenant_id", tenantID)

		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		// Verify the tenant exists.
		var exists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`,
			tenantID,
		).Scan(&exists); err != nil {
			logger.Error("tenant existence check failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		// Generate new credentials.
		bearerBytes := make([]byte, 32)
		if _, err := rand.Read(bearerBytes); err != nil {
			logger.Error("rand bearer failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		bearerToken := base64.RawURLEncoding.EncodeToString(bearerBytes)
		bearerHash := sha256.Sum256([]byte(bearerToken))

		hmacSecret := make([]byte, 32)
		if _, err := rand.Read(hmacSecret); err != nil {
			logger.Error("rand hmac failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		grace := defaultGrace

		tx, err := pool.Begin(r.Context())
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback(r.Context()) //nolint:errcheck

		// Expire all currently-active credentials for this tenant after the
		// grace window. Only affects rows that don't already have an expires_at.
		graceUntil := time.Now().Add(grace)
		_, err = tx.Exec(r.Context(), `
			UPDATE tenant_credentials
			SET expires_at = $2
			WHERE tenant_id = $1::uuid
			  AND revoked_at IS NULL
			  AND (expires_at IS NULL OR expires_at > now())
		`, tenantID, graceUntil)
		if err != nil {
			logger.Error("expire old credentials failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// PAT-687: encrypt the ACTIVE auth secret at rest; auth/bearer.go decrypts
		// with a plaintext fallback. No-op passthrough when PATCHED_KEK is unset.
		encCredHMAC, err := envelope.Default().EncryptBytes(hmacSecret)
		if err != nil {
			logger.Error("credential hmac_secret encryption failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Insert the new credential row (no expires_at — valid until next rotation).
		var credID int64
		err = tx.QueryRow(r.Context(), `
			INSERT INTO tenant_credentials (tenant_id, bearer_token_hash, hmac_secret)
			VALUES ($1::uuid, $2, $3)
			RETURNING id
		`, tenantID, bearerHash[:], encCredHMAC).Scan(&credID)
		if err != nil {
			logger.Error("insert new credential failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("credentials rotated",
			"credential_id", credID,
			"grace_until", graceUntil.UTC().Format(time.RFC3339),
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(rotateCredentialsResp{
			TenantID:      tenantID,
			CredentialID:  credID,
			BearerToken:   bearerToken,
			HMACSecretB64: base64.StdEncoding.EncodeToString(hmacSecret),
			GraceUntil:    graceUntil.UTC().Format(time.RFC3339),
			Warning:       "store bearer_token and hmac_secret_b64 immediately — neither is recoverable after this response. Old credentials expire at grace_until.",
		})
	}
}

// ---------------------------------------------------------------------------
// Tenant lifecycle — soft-revoke, list revoked, restore, hard-purge
// ---------------------------------------------------------------------------

type revokeTenantResp struct {
	TenantID  string `json:"tenant_id"`
	RevokedAt string `json:"revoked_at"`
}

type revokedTenantEntry struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	RevokedAt string `json:"revoked_at"`
}

type listRevokedTenantsResp struct {
	Tenants []revokedTenantEntry `json:"tenants"`
}

type purgeTenantResp struct {
	TenantID       string `json:"tenant_id"`
	Purged         bool   `json:"purged,omitempty"`
	PurgeStatus    string `json:"purge_status"`
	CleanupPending bool   `json:"cleanup_pending,omitempty"`
	Residue        string `json:"quarantine_residue,omitempty"`
}

func purgeCommitDefinitelyRolledBack(err error) bool {
	if errors.Is(err, pgx.ErrTxCommitRollback) {
		return true
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return strings.HasPrefix(pgErr.Code, "23") || pgErr.Code == "40001" || pgErr.Code == "40002" || pgErr.Code == "40P01"
}

type postRenameQuarantineError struct {
	err      error
	restored bool
}

const defaultTenantPurgeDBTimeout = 5 * time.Minute

// newPurgeRollbackContext builds the context used to unwind a failed tenant
// purge. It exists as a named function purely so the deadline is assertable:
// PAT-1512 found the rollback pinned to a hardcoded 5s while the commit path
// honoured TENANT_PURGE_DB_TIMEOUT (default 5m), so on exactly the
// large-tenant purge the longer timeout exists for, the unwind could expire
// while the commit would not have. Both now read the same source.
func newPurgeRollbackContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), tenantPurgeDBTimeout())
}

func tenantPurgeDBTimeout() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("TENANT_PURGE_DB_TIMEOUT")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			return d
		}
	}
	return defaultTenantPurgeDBTimeout
}

func (e *postRenameQuarantineError) Error() string { return e.err.Error() }
func (e *postRenameQuarantineError) Unwrap() error { return e.err }

// RevokeTenantHandler soft-revokes a tenant by setting revoked_at = now().
// Idempotent: returns 200 with the existing revoked_at if already revoked.
// The tenant's agents will be blocked from ingesting immediately (bearer auth
// checks t.revoked_at IS NULL after this handler runs).
//
// Route: DELETE /admin/tenants/{tenantID}  (soft-revoke, not a purge)
func RevokeTenantHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		logger := slog.With("req_id", reqID, "handler", "revoke_tenant", "tenant_id", tenantID)

		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		// Fetch current revoked_at; 404 if tenant doesn't exist.
		var revokedAt *time.Time
		err := pool.QueryRow(r.Context(),
			`SELECT revoked_at FROM tenants WHERE id = $1::uuid`,
			tenantID,
		).Scan(&revokedAt)
		if err != nil {
			if err == pgx.ErrNoRows {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("revoke tenant check failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Idempotent: already revoked — return existing timestamp.
		if revokedAt != nil {
			logger.Info("tenant already revoked", "revoked_at", revokedAt.UTC().Format(time.RFC3339))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(revokeTenantResp{
				TenantID:  tenantID,
				RevokedAt: revokedAt.UTC().Format(time.RFC3339),
			})
			return
		}

		var newRevokedAt time.Time
		err = pool.QueryRow(r.Context(), `
			UPDATE tenants
			SET revoked_at = now(), updated_at = now()
			WHERE id = $1::uuid
			RETURNING revoked_at
		`, tenantID).Scan(&newRevokedAt)
		if err != nil {
			logger.Error("revoke tenant update failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("tenant revoked", "revoked_at", newRevokedAt.UTC().Format(time.RFC3339))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(revokeTenantResp{
			TenantID:  tenantID,
			RevokedAt: newRevokedAt.UTC().Format(time.RFC3339),
		})
	}
}

// ListRevokedTenantsHandler returns id, name, and revoked_at for every
// revoked (offboarded) tenant, ordered newest-first.
//
// Route: GET /admin/tenants/revoked
func ListRevokedTenantsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "list_revoked_tenants")

		rows, err := pool.Query(r.Context(), `
			SELECT id::text, name, revoked_at
			FROM tenants
			WHERE revoked_at IS NOT NULL
			ORDER BY revoked_at DESC
		`)
		if err != nil {
			logger.Error("query revoked tenants failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var tenants []revokedTenantEntry
		for rows.Next() {
			var e revokedTenantEntry
			var ts time.Time
			if err := rows.Scan(&e.ID, &e.Name, &ts); err != nil {
				logger.Error("scan revoked tenant failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			e.RevokedAt = ts.UTC().Format(time.RFC3339)
			tenants = append(tenants, e)
		}
		if err := rows.Err(); err != nil {
			logger.Error("iterate revoked tenants failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if tenants == nil {
			tenants = []revokedTenantEntry{}
		}

		logger.Info("revoked tenants listed", "count", len(tenants))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(listRevokedTenantsResp{Tenants: tenants})
	}
}

// RestoreTenantHandler clears revoked_at, reinstating a soft-revoked tenant.
// 404 if the tenant doesn't exist; 200 (no-op) if not currently revoked.
//
// Route: POST /admin/tenants/{tenantID}/restore
func RestoreTenantHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		logger := slog.With("req_id", reqID, "handler", "restore_tenant", "tenant_id", tenantID)

		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		// Verify the tenant exists.
		var exists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid)`,
			tenantID,
		).Scan(&exists); err != nil {
			logger.Error("tenant existence check failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		_, err := pool.Exec(r.Context(), `
			UPDATE tenants
			SET revoked_at = NULL, updated_at = now()
			WHERE id = $1::uuid
		`, tenantID)
		if err != nil {
			logger.Error("restore tenant update failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("tenant restored")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"tenant_id": tenantID, "status": "active"})
	}
}

// PurgeTenantHandler hard-deletes a tenant and all child rows via ON DELETE
// CASCADE. Only permitted when the tenant is already revoked — a non-revoked
// tenant returns 409. This operation is irreversible.
//
// Route: DELETE /admin/tenants/{tenantID}/purge
func PurgeTenantHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return purgeTenantHandler(pool.BeginTx, nil, nil)
}

type purgeBeginTx func(context.Context, pgx.TxOptions) (pgx.Tx, error)
type purgeQuarantine func(string, string, bool) (*assessmentQuarantine, error)

// purgeTenantHandler's hook is test-only fault injection at the exact
// post-commit/pre-cleanup boundary.
func purgeTenantHandler(beginTx purgeBeginTx, beforeCleanup func(*assessmentQuarantine), quarantineFn purgeQuarantine) http.HandlerFunc {
	if quarantineFn == nil {
		quarantineFn = quarantineAssessmentArtifacts
	}
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		logger := slog.With("req_id", reqID, "handler", "purge_tenant", "tenant_id", tenantID)

		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		tx, err := beginTx(r.Context(), pgx.TxOptions{})
		if err != nil {
			logger.Error("purge tenant transaction begin failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() {
			rollbackCtx, cancel := newPurgeRollbackContext()
			defer cancel()
			// PAT-1512: do not discard this. The rollback runs after the
			// handler has already written its response, so a failure here is
			// invisible to the caller by construction; the log line is the
			// only place it can surface. pgx still rolls back when the
			// connection is released, so this is not corruption, but this
			// handler's contract is that failure semantics are explicit, and
			// a silently abandoned transaction is not.
			if err := tx.Rollback(rollbackCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
				logger.Warn("purge tenant rollback did not complete cleanly",
					"err", err, "deadline", tenantPurgeDBTimeout())
			}
		}()

		// Lock and recheck revoked_at inside the delete transaction. Restore
		// cannot race this purge between the eligibility check and DELETE.
		var revokedAt *time.Time
		err = tx.QueryRow(r.Context(),
			`SELECT revoked_at FROM tenants WHERE id = $1::uuid FOR UPDATE`,
			tenantID,
		).Scan(&revokedAt)
		if err != nil {
			if err == pgx.ErrNoRows {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("purge tenant check failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Purge is only allowed on already-revoked tenants.
		if revokedAt == nil {
			http.Error(w, "offboard before purge", http.StatusConflict)
			return
		}

		var artifactsExpected bool
		if err := tx.QueryRow(r.Context(),
			`SELECT EXISTS (SELECT 1 FROM assessment_artifacts WHERE tenant_id = $1::uuid)`, tenantID,
		).Scan(&artifactsExpected); err != nil {
			logger.Error("purge tenant assessment metadata check failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		quarantine, err := quarantineFn(reportStorageRoot(), tenantID, artifactsExpected)
		if err != nil {
			var postRenameErr *postRenameQuarantineError
			if errors.As(err, &postRenameErr) && postRenameErr.restored {
				status := "quarantine_failed_restored"
				logger.Error("purge tenant assessment quarantine failed after rename; bytes restored",
					"event", "tenant_purge_not_committed", "purge_status", status,
					"revoked_at", revokedAt.UTC().Format(time.RFC3339), "err", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(purgeTenantResp{TenantID: tenantID, PurgeStatus: status})
				return
			}
			if quarantine != nil {
				status := "quarantine_failed_residue_retained"
				cleanupPending := quarantine.residue() != ""
				if !cleanupPending {
					status = "quarantine_failed_restored_unverified"
				}
				logger.Error("purge tenant assessment quarantine failed after rename",
					"event", "tenant_purge_not_committed", "purge_status", status,
					"revoked_at", revokedAt.UTC().Format(time.RFC3339), "err", err,
					"quarantine_residue", quarantine.residue())
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(purgeTenantResp{TenantID: tenantID, PurgeStatus: status, CleanupPending: cleanupPending, Residue: quarantine.residue()})
				return
			}
			logger.Error("purge tenant assessment quarantine failed before rename", "err", err)
			http.Error(w, "assessment artifact quarantine failed", http.StatusInternalServerError)
			return
		}

		// PAT-2410: generated report files (<root>/<tenantID>/<record>/report.*)
		// follow the same discipline as assessment artefacts: quarantined
		// before the DELETE, restored on any definite pre-commit failure,
		// removed only after the commit. An absent directory is not an error.
		reportQuarantine, err := quarantineReportFiles(reportStorageRoot(), tenantID)
		if err != nil {
			// The assessment bytes already moved; put them back before
			// reporting, so a failed report quarantine leaves the tenant live
			// and whole.
			assessmentRestoreErr := quarantine.Restore()
			residue := quarantine.residue()
			if assessmentRestoreErr == nil {
				residue = ""
			}
			if residue == "" {
				residue = reportQuarantine.residue()
			}
			var postRenameErr *postRenameQuarantineError
			switch {
			case errors.As(err, &postRenameErr) && postRenameErr.restored && assessmentRestoreErr == nil:
				status := "quarantine_failed_restored"
				logger.Error("purge tenant report quarantine failed after rename; bytes restored",
					"event", "tenant_purge_not_committed", "purge_status", status,
					"revoked_at", revokedAt.UTC().Format(time.RFC3339), "err", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(purgeTenantResp{TenantID: tenantID, PurgeStatus: status})
			case reportQuarantine != nil || assessmentRestoreErr != nil:
				status := "quarantine_failed_residue_retained"
				if residue == "" {
					status = "quarantine_failed_restored_unverified"
				}
				logger.Error("purge tenant report quarantine failed",
					"event", "tenant_purge_not_committed", "purge_status", status,
					"revoked_at", revokedAt.UTC().Format(time.RFC3339), "err", err,
					"assessment_restore_err", assessmentRestoreErr, "quarantine_residue", residue)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(purgeTenantResp{TenantID: tenantID, PurgeStatus: status, CleanupPending: residue != "", Residue: residue})
			default:
				logger.Error("purge tenant report quarantine failed before rename", "err", err)
				http.Error(w, "report file quarantine failed", http.StatusInternalServerError)
			}
			return
		}
		// purgeResidue is the first quarantine path still on disk, if any.
		// Both are logged on the failure paths that care.
		purgeResidue := func() string {
			if r := quarantine.residue(); r != "" {
				return r
			}
			return reportQuarantine.residue()
		}

		restoreQuarantine := func(stage string, cause error) purgeTenantResp {
			if restoreErr := errors.Join(quarantine.Restore(), reportQuarantine.Restore()); restoreErr != nil {
				status := "precommit_failed_residue_retained"
				if purgeResidue() == "" {
					status = "precommit_failed_restored_unverified"
				}
				logger.Error("purge tenant assessment restore failed", "event", "tenant_purge_not_committed", "purge_status", status, "revoked_at", revokedAt.UTC().Format(time.RFC3339), "stage", stage, "err", cause, "restore_err", restoreErr, "quarantine_residue", quarantine.residue(), "report_quarantine_residue", reportQuarantine.residue())
				return purgeTenantResp{TenantID: tenantID, PurgeStatus: status, CleanupPending: purgeResidue() != "", Residue: purgeResidue()}
			} else {
				status := "precommit_failed_restored"
				logger.Error("purge tenant failed; assessment and report directories restored", "event", "tenant_purge_not_committed", "purge_status", status, "revoked_at", revokedAt.UTC().Format(time.RFC3339), "stage", stage, "err", cause)
				return purgeTenantResp{TenantID: tenantID, PurgeStatus: status}
			}
		}

		// Once bytes have moved, client cancellation must not interrupt the
		// atomic database decision and manufacture an avoidable unknown outcome.
		commitCtx, cancelCommit := context.WithTimeout(context.WithoutCancel(r.Context()), tenantPurgeDBTimeout())
		defer cancelCommit()
		_, err = tx.Exec(commitCtx,
			`DELETE FROM tenants WHERE id = $1::uuid`,
			tenantID,
		)
		if err != nil {
			resp := restoreQuarantine("delete", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		if err := tx.Commit(commitCtx); err != nil {
			if purgeCommitDefinitelyRolledBack(err) {
				resp := restoreQuarantine("commit_rolled_back", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(resp)
				return
			}
			// Any other Commit error may mean the server committed but the
			// acknowledgement was lost. Republishing bytes could recreate data
			// for a tenant whose database purge succeeded, so keep quarantine.
			logger.Error("tenant purge commit outcome unknown; assessment residue retained",
				"event", "tenant_purge_irreversible",
				"purge_status", "commit_outcome_unknown",
				"revoked_at", revokedAt.UTC().Format(time.RFC3339),
				"quarantine_residue", quarantine.residue(),
				"report_quarantine_residue", reportQuarantine.residue(), "err", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(purgeTenantResp{
				TenantID: tenantID, PurgeStatus: "commit_outcome_unknown",
				CleanupPending: quarantine != nil || reportQuarantine != nil, Residue: purgeResidue(),
			})
			return
		}

		if beforeCleanup != nil {
			beforeCleanup(quarantine)
		}
		// Both cleanups always run: one failing must not strand the other's
		// committed-away bytes.
		if err := errors.Join(quarantine.Cleanup(), reportQuarantine.Cleanup()); err != nil {
			residue := purgeResidue()
			cleanupPending := residue != ""
			purgeStatus := "committed"
			logStatus := "committed_cleanup_pending"
			if !cleanupPending {
				purgeStatus = "committed_cleanup_durability_unconfirmed"
				logStatus = purgeStatus
			}
			logger.Error("tenant purged with assessment cleanup error",
				"event", "tenant_purge_irreversible", "purge_status", logStatus,
				"revoked_at", revokedAt.UTC().Format(time.RFC3339),
				"err", err, "quarantine_residue", residue)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(purgeTenantResp{
				TenantID:       tenantID,
				Purged:         true,
				PurgeStatus:    purgeStatus,
				CleanupPending: cleanupPending,
				Residue:        residue,
			})
			return
		}

		logger.Warn("tenant purged; irreversible", "event", "tenant_purge_irreversible", "purge_status", "committed", "tenant_id", tenantID, "had_revoked_at", revokedAt.UTC().Format(time.RFC3339))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(purgeTenantResp{TenantID: tenantID, Purged: true, PurgeStatus: "committed"})
	}
}

// ---------------------------------------------------------------------------
// PAT-397: Subscription tier switch — PUT /admin/tenant-tier/{tenantID}
// ---------------------------------------------------------------------------

// Subscription tier constants — commercial product tiers.
// Distinct from tenants.tier (CIS collection tier 1/2/3).
//
// PAT-1599: collapsed from a three-value ladder (report/patch/full_endpoint)
// to the internal enum assurance/managed, mirroring the retired buyer-facing
// ladder (PAT-1566). This is also, as of migration 0138, the identical
// vocabulary agent_config.body.tier stores — one vocabulary, two values,
// used identically everywhere. There is no more separate "commercial tier"
// vs "agent-config tier" mapping: agentTierFor(), which used to translate
// between them, is gone because it would now be the identity function.
const (
	subTierAssurance = "assurance"
	subTierManaged   = "managed"
)

// validSubTiers is the complete set of accepted subscription_tier values.
var validSubTiers = map[string]bool{
	subTierAssurance: true,
	subTierManaged:   true,
}

type setTenantTierReq struct {
	SubscriptionTier string `json:"subscription_tier"`
	UpdatedBy        string `json:"updated_by"`
}

type setTenantTierResp struct {
	TenantID           string `json:"tenant_id"`
	SubscriptionTier   string `json:"subscription_tier"`
	AgentConfigTier    string `json:"agent_config_tier"`
	AgentConfigVersion int    `json:"agent_config_version"`
	AppControlEnabled  bool   `json:"app_control_enabled"`
	Warning            string `json:"warning,omitempty"`
}

// SetTenantTierHandler sets a tenant's commercial subscription tier atomically.
//
// In a single transaction it:
//   - Updates tenants.subscription_tier (commercial source of truth).
//   - For managed: sets app_control_enabled=true (unlocks AC surfaces into
//     inert/pre-config state — no enforcement until the operator configures policy).
//   - Upserts agent_config: patches body.tier and bumps config_version so agents
//     pick up the new behavioural mode on their next poll.
//   - Writes one audit record to tenant_tier_changes.
//
// Existing per-lever endpoints (app_updates_default_enabled, allowlist_default_deny,
// per-app policies, platform switches) are unchanged — they are the deliberate
// follow-up hand-configuration step after unlocking a tier.
//
// managed tier note: Graph/GDAP onboarding is NOT a pure switch; the
// endpoint sets the tier and unlocks AC surfaces but includes a warning that
// Graph-dependent enforcement features require separate onboarding (PAT-612).
// This is live, planned Tier 3 orchestration work (Patched driving the
// customer's own Intune via Graph), not the deleted internal/tier3/ inventory
// integration (PAT-911) — see ADR-0010 (go-service/docs/adr/0010-microsoft-graph-scope-reconciliation.md).
//
// Route: PUT /admin/tenant-tier/{tenantID}
func SetTenantTierHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		logger := slog.With("req_id", reqID, "handler", "set_tenant_tier", "tenant_id", tenantID)

		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<14))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var req setTenantTierReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if !validSubTiers[req.SubscriptionTier] {
			http.Error(w, `subscription_tier must be "assurance" or "managed"`, http.StatusBadRequest)
			return
		}
		if req.UpdatedBy == "" {
			req.UpdatedBy = "admin"
		}

		// agent_config.body.tier is written with the identical value as of
		// PAT-1599 (migration 0138) — no more agentTierFor() mapping between a
		// commercial-tier vocabulary and a separate agent-config vocabulary.
		// agentTier is kept as its own local/response name only because
		// setTenantTierResp.AgentConfigTier is a distinct wire field.
		agentTier := req.SubscriptionTier

		// Encode the agent tier as a JSON string value for jsonb_set,
		// e.g. "managed" → `"managed"` (with the JSON double-quotes intact).
		agentTierJSON, err := json.Marshal(agentTier)
		if err != nil {
			logger.Error("marshal agent tier failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Build the full default config body with the new tier set.
		// Used only when no agent_config row exists yet (INSERT path of the upsert).
		defaultBody := agentconfig.DefaultConfigBody()
		defaultBody.Tier = agentTier
		defaultBodyBytes, err := json.Marshal(defaultBody)
		if err != nil {
			logger.Error("marshal default config body failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		ctx := r.Context()
		tx, err := pool.Begin(ctx)
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck

		// Step 1: read current state and verify tenant exists + not revoked.
		// FOR UPDATE locks the row so concurrent tier switches on the same tenant
		// serialise rather than racing.
		var fromTier string
		err = tx.QueryRow(ctx,
			`SELECT subscription_tier FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL FOR UPDATE`,
			tenantID,
		).Scan(&fromTier)
		if err == pgx.ErrNoRows {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}
		if err != nil {
			logger.Error("read tenant tier failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Step 2: update tenants.subscription_tier and unlock entitled feature
		// surfaces into their inert/pre-config state.
		//   managed → app_control_enabled = TRUE
		//             (unlocks AC UI surfaces; no enforcement until policy is set)
		// All other downstream columns are left unchanged — the operator configures
		// them afterwards via existing per-lever endpoints.
		var newAppControlEnabled bool
		err = tx.QueryRow(ctx, `
			UPDATE tenants
			SET subscription_tier   = $2,
			    app_control_enabled = CASE $2::text
			        WHEN 'managed' THEN TRUE
			        ELSE app_control_enabled
			    END,
			    updated_at          = now()
			WHERE id = $1::uuid
			RETURNING app_control_enabled
		`, tenantID, req.SubscriptionTier).Scan(&newAppControlEnabled)
		if err != nil {
			logger.Error("update tenant tier failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Step 3: upsert agent_config — patch body.tier and bump config_version.
		// INSERT path (no existing row): writes the full default body with tier set.
		// UPDATE path (row exists): uses jsonb_set to patch only the tier field,
		// preserving proxy, ring_promotions, log_request, pinned_version, etc.
		var newConfigVersion int
		err = tx.QueryRow(ctx, `
			INSERT INTO agent_config (tenant_id, config_version, body, issued_at, updated_by)
			VALUES ($1::uuid, 1, $2::jsonb, now(), $3)
			ON CONFLICT (tenant_id) DO UPDATE
			    SET config_version = agent_config.config_version + 1,
			        body           = jsonb_set(agent_config.body, '{tier}', $4::jsonb),
			        issued_at      = now(),
			        updated_by     = EXCLUDED.updated_by
			RETURNING config_version
		`, tenantID, defaultBodyBytes, req.UpdatedBy, agentTierJSON).Scan(&newConfigVersion)
		if err != nil {
			logger.Error("upsert agent_config failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Step 4: append audit record. from_tier = prior value (or new tier when
		// no change occurred — idempotent call); to_tier = new value.
		//
		// PAT-1135: changed_by records the server-established shared-token
		// principal, never req.UpdatedBy — the admin surface has no
		// per-person identity to verify that string against. req.UpdatedBy
		// still flows into claimed_actor, untrusted. See
		// internal/handlers/audit_attribution.go. (agent_config.updated_by
		// above is a separate, out-of-scope column — unchanged.)
		actor, claimedActor, sourceAddr := auditAttribution(r, req.UpdatedBy)
		_, err = tx.Exec(ctx, `
			INSERT INTO tenant_tier_changes (tenant_id, from_tier, to_tier, changed_by, claimed_actor, source_addr)
			VALUES ($1::uuid, $2, $3, $4, $5, $6)
		`, tenantID, fromTier, req.SubscriptionTier, actor, claimedActor, sourceAddr)
		if err != nil {
			logger.Error("insert tier audit record failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(ctx); err != nil {
			logger.Error("commit tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("tenant tier set",
			"from_tier", fromTier,
			"to_tier", req.SubscriptionTier,
			"agent_config_tier", agentTier,
			"agent_config_version", newConfigVersion,
			"app_control_enabled", newAppControlEnabled,
		)

		var warning string
		if req.SubscriptionTier == subTierManaged {
			warning = "managed tier requires Graph/GDAP onboarding (PAT-612) before Tier 3 Intune-orchestration enforcement surfaces go live (planned work, see ADR-0010; not the deleted PAT-911 integration). app_control_enabled is now true but no enforcement policy is active until explicitly configured."
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(setTenantTierResp{
			TenantID:           tenantID,
			SubscriptionTier:   req.SubscriptionTier,
			AgentConfigTier:    agentTier,
			AgentConfigVersion: newConfigVersion,
			AppControlEnabled:  newAppControlEnabled,
			Warning:            warning,
		})
	}
}
