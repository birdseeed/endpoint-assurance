package handlers

// Admin: list and revoke unused enrolment (bootstrap) tokens (PAT-2287).
//
// A minted token otherwise ends only when POST /v1/enrol consumes it, when a
// newer email-link mint supersedes it (PAT-836) or when its 24 hours run out.
// Revoke lets an operator end one sooner: a token minted for a machine that
// then cannot be reached, or one pasted somewhere it should not have been.
//
// Both routes are on the internal listener behind ADMIN_API_TOKEN, like the
// mint (cmd/patched-api/main.go). Neither ever returns a token's plaintext
// (never stored) or its hash.

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

// bootstrapTokenView is one row of GET /admin/tenants/{tenantID}/bootstrap-tokens.
// There is deliberately no hash field: the list exists to pick a token to
// revoke, and its id is all that needs.
type bootstrapTokenView struct {
	TokenID      string    `json:"token_id"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	DeliveryPath string    `json:"delivery_path"`
}

// ListBootstrapTokensHandler serves GET /admin/tenants/{tenantID}/bootstrap-tokens:
// the tenant's tokens that /v1/enrol would still accept, newest first. The
// WHERE clause is the consume UPDATE's own predicate in consumeBootstrapToken
// (unconsumed, unexpired, not superseded, not revoked), so a superseded
// email-link token is not listed even though nobody consumed it: it cannot
// enrol anything, so there is nothing to revoke. Tenant-level gates applied at
// enrol time (decommission directive, trial device cap) are not reflected.
//
// 404 when no tenant row exists. An offboarded (revoked) tenant still lists,
// so any token it has outstanding can be found and revoked.
func ListBootstrapTokensHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "list_bootstrap_tokens", "tenant_id", tenantID)

		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		var exists bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid)`, tenantID).Scan(&exists); err != nil {
			logger.Error("tenant lookup failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		rows, err := pool.Query(ctx, `
			SELECT id::text, created_at, expires_at, delivery_path
			FROM bootstrap_tokens
			WHERE tenant_id = $1::uuid
			  AND consumed_at IS NULL AND expires_at > now() AND superseded_at IS NULL
			  AND revoked_at IS NULL
			ORDER BY created_at DESC, id
		`, tenantID)
		if err != nil {
			logger.Error("list bootstrap tokens failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		tokens := []bootstrapTokenView{}
		for rows.Next() {
			var v bootstrapTokenView
			if err := rows.Scan(&v.TokenID, &v.CreatedAt, &v.ExpiresAt, &v.DeliveryPath); err != nil {
				logger.Error("scan bootstrap token failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			tokens = append(tokens, v)
		}
		if err := rows.Err(); err != nil {
			logger.Error("list bootstrap tokens failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"tokens": tokens})
	}
}

// writeBootstrapTokenNotFound is the revoke route's only not-found response.
// A malformed id, an unknown id and another tenant's token all get it.
func writeBootstrapTokenNotFound(w http.ResponseWriter) {
	http.Error(w, "bootstrap token not found", http.StatusNotFound)
}

// RevokeBootstrapTokenHandler serves
// POST /admin/tenants/{tenantID}/bootstrap-tokens/{tokenID}/revoke. It takes
// no body.
//
//   - 200 {token_id, revoked_at, changed}: revoked now (changed true), or
//     already revoked (changed false, revoked_at is the original time, and
//     nothing is written).
//   - 404 "bootstrap token not found": no such token for this tenant. The
//     lookup is scoped to the tenant in the path, so another tenant's token,
//     an unknown id and a malformed id all get the same response and the
//     route cannot be used to learn whether a token id exists elsewhere.
//   - 409: the token was consumed. A device already holds credentials from
//     it, so revoking the token would achieve nothing; revoke the device
//     (POST /admin/devices/{deviceID}/revoke) instead. Nothing is changed.
//
// An expired or superseded token can still be revoked. It is already unusable,
// so this is harmless, and it keeps the call safe to repeat.
//
// The revoke and its enrollment_token_audit row commit together. The mint
// treats its audit insert as best-effort; a revoke does not, because the audit
// row is the only record of who ended the token, so a revoke that cannot be
// recorded is not applied and the operator gets a 500 to retry. The actor is
// adminSharedTokenActor: /admin/* has one shared token and no per-person
// identity (PAT-1135), so that is all the server can vouch for.
//
// Locking: only this bootstrap_tokens row, FOR UPDATE, which is the row
// consumeBootstrapToken's UPDATE locks first. A concurrent enrol and revoke
// therefore serialise on it. If the enrol commits first, this sees
// consumed_at and returns 409. If the revoke commits first, the enrol's UPDATE
// re-checks revoked_at IS NULL, matches nothing, and the caller gets the
// expired response. The audit INSERT's foreign-key check takes a KEY SHARE
// lock on the same row, already held. No tenants row is locked, so this
// cannot deadlock against EnrolHandler's token-then-tenant lock order.
func RevokeBootstrapTokenHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		tokenID := strings.TrimSpace(chi.URLParam(r, "tokenID"))
		logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "revoke_bootstrap_token", "tenant_id", tenantID)

		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		if !looksLikeUUID(tokenID) {
			writeBootstrapTokenNotFound(w)
			return
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(ctx) }() // no-op once Commit has run

		var (
			id                    string
			consumedAt, revokedAt *time.Time
			deliveryPath          string
			expiresAt             time.Time
		)
		err = tx.QueryRow(ctx, `
			SELECT id::text, consumed_at, revoked_at, delivery_path, expires_at
			FROM bootstrap_tokens
			WHERE id = $1::uuid AND tenant_id = $2::uuid
			FOR UPDATE
		`, tokenID, tenantID).Scan(&id, &consumedAt, &revokedAt, &deliveryPath, &expiresAt)
		if isNoRowsErr(err) {
			writeBootstrapTokenNotFound(w)
			return
		}
		if err != nil {
			logger.Error("bootstrap token lookup failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		logger = logger.With("token_id", id)

		if consumedAt != nil {
			logger.Warn("revoke refused: bootstrap token already consumed")
			http.Error(w, "bootstrap token already consumed: a device enrolled with it, so revoke that device instead", http.StatusConflict)
			return
		}

		changed := false
		if revokedAt == nil {
			var at time.Time
			if err := tx.QueryRow(ctx, `
				UPDATE bootstrap_tokens SET revoked_at = now()
				WHERE id = $1::uuid
				RETURNING revoked_at
			`, id).Scan(&at); err != nil {
				logger.Error("bootstrap token revoke failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO enrollment_token_audit (tenant_id, token_id, delivery_path, expires_at, action, actor)
				VALUES ($1::uuid, $2::uuid, $3, $4, 'revoke', $5)
			`, tenantID, id, deliveryPath, expiresAt, adminSharedTokenActor); err != nil {
				logger.Error("bootstrap token revoke audit insert failed; revoke not applied", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			revokedAt = &at
			changed = true
		}

		if err := tx.Commit(ctx); err != nil {
			logger.Error("bootstrap token revoke commit failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("bootstrap token revoked", "changed", changed, "actor", adminSharedTokenActor)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"token_id": id, "revoked_at": revokedAt, "changed": changed})
	}
}
