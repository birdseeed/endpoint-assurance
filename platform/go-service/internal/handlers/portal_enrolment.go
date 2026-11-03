// Portal customer enrolment-token generation (PAT-453) — POST
// /v1/portal/enrolment on the PUBLIC listener, behind portalauth.Middleware
// (CF Access JWT verification, portal_users tenant derivation, per-identity
// rate limit, portal_access_log audit — same as every other /v1/portal/*
// route).
//
// This mints a single-use, 24h agent enrolment token for the caller's OWN
// tenant, through the same mintTenantEnrolmentToken core used by the admin mint
// (enrolment.go). Same invariants as portal.go / portal_schedule.go: tenant
// identity comes ONLY from identity(w, r) (portalauth.FromContext) — no
// client-supplied tenant identifier exists anywhere on this surface. The
// request body's only legal field is an optional delivery_path;
// DisallowUnknownFields rejects anything else outright (including a
// spoofed tenant_id), and there is no code path that lets the caller choose
// the tenant even if such a field were silently accepted.
//
// Unlike the general portal read/write surface, minting a credential-issuing
// token warrants a tighter limit than the shared per-identity
// PORTAL_RATE_LIMIT_RPM (default 120/min) allows. This endpoint is guarded
// by a SEPARATE, per-TENANT limiter (PORTAL_ENROL_MINTS_PER_HOUR, default
// 10, over a PORTAL_ENROL_WINDOW_MINUTES window, default 60) so multiple
// portal users at the same tenant share one mint budget, isolated from
// every other tenant's.
//
// PAT-836: mintTenantEnrolmentToken now supersedes a tenant's prior
// unconsumed token(s) on remint, but ONLY for delivery_path "email-link" —
// "mdm" tokens (the only delivery_path this portal surface ever mints, see
// portalEnrolmentAllowedDeliveryPaths below) are never superseded, by
// design, since fleet enrolment legitimately needs N outstanding tokens for
// N devices enrolling concurrently. So in practice a portal re-mint never
// invalidates a still-outstanding portal-issued token — that behaviour is
// unchanged here and is only observable through the admin mint's
// "email-link" path.
package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/ratelimit"
)

// portalEnrolmentAllowedDeliveryPaths is the portal-facing subset of the
// admin mint's delivery_path enum. "email-link" is an admin/dashboard-only
// delivery mechanism (an operator sends the link manually); the portal
// always mints for MDM/installer delivery, so it's the only value accepted
// here even though mintTenantEnrolmentToken itself still knows about both.
var portalEnrolmentAllowedDeliveryPaths = map[string]bool{"mdm": true}

// portalEnrolmentReq is the only client input. Any other field (including a
// tenant_id) is rejected outright by DisallowUnknownFields — see the
// package doc comment above.
type portalEnrolmentReq struct {
	DeliveryPath string `json:"delivery_path"`
}

type portalEnrolmentResp struct {
	EnrollmentToken string `json:"enrollment_token"`
	TenantID        string `json:"tenant_id"`
	TokenID         string `json:"token_id"`
	ExpiresAt       string `json:"expires_at"`
}

// PortalEnrolmentGenerateHandler mints a single-use, 24h agent enrolment
// token for the caller's own tenant (identity(w, r) only — see package doc).
// Admin only (PAT-2407): any other role gets 403 admin_role_required.
// rl is a dedicated per-tenant limiter, separate from the general portal
// per-identity limiter; nil disables the extra check (still gated by the
// outer portalauth per-identity limiter in that case).
func PortalEnrolmentGenerateHandler(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_enrolment_generate", "tenant_id", id.TenantID)

		// Defence in depth: portalauth always resolves TenantID from a uuid
		// DB column, so this should never fire — but unlike the admin mint
		// handler (which validates the URL-supplied tenantID before calling
		// mintTenantEnrolmentToken), nothing upstream of this handler
		// shape-checks id.TenantID. Fail closed with a clear log rather than
		// letting a malformed value reach the ::uuid cast in the DB query.
		if !looksLikeUUID(id.TenantID) {
			logger.Error("portal identity resolved to a non-UUID tenant_id — refusing to mint")
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<12))
		if err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		var req portalEnrolmentReq
		if len(bytes.TrimSpace(body)) > 0 {
			dec := json.NewDecoder(bytes.NewReader(body))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				// Covers malformed JSON AND any unknown field — including a
				// spoofed "tenant_id" — since DisallowUnknownFields turns
				// that into a decode error too. Either way: reject, don't
				// silently ignore.
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}
		}

		deliveryPath := req.DeliveryPath
		if deliveryPath == "" {
			deliveryPath = "mdm"
		}
		if !portalEnrolmentAllowedDeliveryPaths[deliveryPath] {
			http.Error(w, "delivery_path must be 'mdm'", http.StatusBadRequest)
			return
		}

		// PAT-2407: admin only, enforced the way PortalEnrolmentKeyCreateHandler
		// enforces it. The role is re-read inside the transaction that inserts
		// the token, with the caller's portal_users row held FOR SHARE, so a
		// demotion cannot commit between this check and the insert. A viewer,
		// or a user admitted only through the tenant's email domain (no
		// portal_users row), gets 403 admin_role_required and writes nothing.
		// The check runs before the per-tenant limiter, as it does there, so a
		// refused caller does not spend the tenant's mint budget.
		ctx := r.Context()
		tx, err := pool.Begin(ctx)
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
		if !requirePortalAdmin(ctx, tx, w, id, "mint an enrolment token", logger) {
			return
		}

		// Dedicated per-tenant mint limiter — a separate, much tighter bucket
		// from the general per-identity portal read limit (portalauth
		// Middleware already ran that check before we got here). Keyed by
		// tenant, not identity/email, so it can't be sidestepped by having
		// multiple portal users at the same tenant mint in parallel.
		if rl != nil {
			if allowed, retryAfter := rl.Allow(id.TenantID); !allowed {
				w.Header().Set("Retry-After", fmt.Sprintf("%.0f", retryAfter.Seconds()+1))
				http.Error(w, `{"error":"enrolment mint rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}
		}

		// On tx, not the pool: the insert must sit in the transaction holding
		// the role lock, and a request must not hold one pooled connection
		// while asking for a second (see rowQuerier's doc comment, trial.go).
		res, err := mintTenantEnrolmentTokenOn(ctx, tx, id.TenantID, deliveryPath)
		if err != nil {
			var decErr *tenantDecommissionedError
			switch {
			case errors.Is(err, errInvalidDeliveryPath):
				http.Error(w, "delivery_path must be 'mdm'", http.StatusBadRequest)
			case errors.Is(err, errTenantNotFound):
				// The caller's own tenant is missing/revoked. portalauth
				// already resolved a live tenant for this identity, so this
				// should not happen in practice (e.g. a revocation racing
				// this request) — fail closed rather than leak detail.
				logger.Error("mint: caller's own tenant not found/revoked", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
			case errors.As(err, &decErr):
				// PAT-1757: the caller's own tenant carries an active
				// decommission directive — see tenantDecommissionedError's
				// doc comment (enrolment.go). Same guard as the admin mint,
				// reached here because both handlers share
				// mintTenantEnrolmentToken.
				logger.Warn("mint rejected: tenant has an active decommission directive", "mode", decErr.Mode)
				writeTenantDecommissionedConflict(w, decErr.Mode, decErr.SetAt)
			default:
				logger.Error("mint enrollment token failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
			return
		}

		if err := tx.Commit(ctx); err != nil {
			logger.Error("commit failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// After the commit, on the pool: the audit row references the token
		// row, and its failure must never undo an issued token (same rule as
		// mintTenantEnrolmentToken).
		recordEnrolmentTokenAudit(ctx, pool, id.TenantID, deliveryPath, id.Email, res)

		logger.Info("portal enrolment token minted", "token_id", res.TokenID,
			"expires_at", res.ExpiresAt, "email", id.Email)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(portalEnrolmentResp{
			EnrollmentToken: res.PlaintextToken,
			TenantID:        id.TenantID,
			TokenID:         res.TokenID,
			ExpiresAt:       res.ExpiresAt.Format(time.RFC3339),
		})
	}
}
