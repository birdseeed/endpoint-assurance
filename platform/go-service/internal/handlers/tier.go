package handlers

// PAT-650: server-side subscription-tier enforcement.
//
// tenants.subscription_tier (migration 0056; collapsed to two values by
// migration 0138, PAT-1599) is the commercial source of truth for a
// tenant's product tier: assurance < managed. This file provides the
// enforcement layer that rejects feature calls below the tenant's tier:
//
//   - RequireSubscriptionTier — chi middleware for the internal admin surface
//     (:8081). Resolves the TARGET tenant from the {tenantID} URL param and
//     returns 403 when that tenant's tier is below the route's minimum. The
//     target-tenant check (rather than a caller check — admin callers are
//     Tailscale-gated operators, not tenants) means an operator who has just
//     upgraded a tenant via PUT /admin/tenant-tier/{tenantID} can immediately
//     configure the newly unlocked features.
//
//   - requireTenantTier — helper for public agent routes (:8080), called
//     after bearer + HMAC auth once the tenant is known.
//
// The resolved tier is cached in the request context so a route that both
// passes through the middleware and calls the helper costs one DB read.
//
// PUT /admin/tenant-tier/{tenantID} and the tenant-management routes are
// deliberately NOT gated: they must work at any tier or a tenant could never
// be upgraded (or revoked).

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Exported aliases of the subscription-tier constants (admin.go) so
// cmd/patched-api can wire RequireSubscriptionTier without magic strings.
const (
	TierAssurance = subTierAssurance
	TierManaged   = subTierManaged
)

// subTierRank orders the commercial tiers: assurance < managed.
// Unknown values rank 0, i.e. below assurance — the check fails closed.
var subTierRank = map[string]int{
	subTierAssurance: 1,
	subTierManaged:   2,
}

// tierAtLeast reports whether tier meets minTier. Unknown tier or minTier
// values fail closed (false).
func tierAtLeast(tier, minTier string) bool {
	tr, mr := subTierRank[tier], subTierRank[minTier]
	return tr != 0 && mr != 0 && tr >= mr
}

// errTierTenantNotFound is returned by a tierLoader when the tenant row does
// not exist.
var errTierTenantNotFound = errors.New("tenant not found")

// tierLoader resolves a tenant's subscription_tier. Production code uses
// poolTierLoader; tests inject a stub so the middleware is testable without
// a database.
type tierLoader func(ctx context.Context, tenantID string) (string, error)

// poolTierLoader returns a tierLoader backed by the tenants table.
func poolTierLoader(pool *pgxpool.Pool) tierLoader {
	return func(ctx context.Context, tenantID string) (string, error) {
		var tier string
		err := pool.QueryRow(ctx,
			`SELECT subscription_tier FROM tenants WHERE id = $1::uuid`,
			tenantID,
		).Scan(&tier)
		if err != nil {
			if isNoRowsErr(err) {
				return "", errTierTenantNotFound
			}
			return "", err
		}
		return tier, nil
	}
}

// tenantTierCtxKey keys the per-request subscription-tier cache.
type tenantTierCtxKey struct{}

// tenantTierCtxVal caches one tenant's resolved tier for the request.
type tenantTierCtxVal struct {
	tenantID string
	tier     string
}

// contextWithTenantTier returns ctx with tenantID's subscription tier cached.
func contextWithTenantTier(ctx context.Context, tenantID, tier string) context.Context {
	return context.WithValue(ctx, tenantTierCtxKey{}, tenantTierCtxVal{tenantID: tenantID, tier: tier})
}

// tenantTierFromContext returns the cached tier for tenantID, if present.
func tenantTierFromContext(ctx context.Context, tenantID string) (string, bool) {
	v, ok := ctx.Value(tenantTierCtxKey{}).(tenantTierCtxVal)
	if !ok || v.tenantID != tenantID {
		return "", false
	}
	return v.tier, true
}

// resolveTenantTier returns tenantID's subscription tier, consulting the
// request-context cache before hitting the loader.
func resolveTenantTier(ctx context.Context, load tierLoader, tenantID string) (string, error) {
	if tier, ok := tenantTierFromContext(ctx, tenantID); ok {
		return tier, nil
	}
	return load(ctx, tenantID)
}

// writeTierForbidden writes the canonical PAT-650 tier-gate rejection:
// 403 {"error": "feature requires subscription tier: <minTier>"}.
func writeTierForbidden(w http.ResponseWriter, minTier string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": "feature requires subscription tier: " + minTier,
	})
}

// writeTierJSONError writes a JSON error body with the given status.
func writeTierJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// RequireSubscriptionTier gates an admin route on the TARGET tenant's
// subscription tier. The tenant is taken from the {tenantID} chi URL param;
// requests whose param is missing or not a UUID pass through so the handler's
// own validation returns its canonical 400.
//
// Responses:
//   - tier below minTier   → 403 {"error": "feature requires subscription tier: <minTier>"}
//   - tenant row not found → 404 {"error": "tenant not found"}
//   - lookup failure       → 500 {"error": "subscription tier lookup failed"}
func RequireSubscriptionTier(pool *pgxpool.Pool, minTier string) func(http.Handler) http.Handler {
	return requireSubscriptionTier(poolTierLoader(pool), minTier)
}

// requireSubscriptionTier is the loader-injectable core of
// RequireSubscriptionTier. Tests stub the loader.
func requireSubscriptionTier(load tierLoader, minTier string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
			if !looksLikeUUID(tenantID) {
				// Malformed/missing IDs are the handler's problem (400), not a
				// tier decision. Never a bypass: no valid tenant row can match
				// a non-UUID, so gated queries would fail anyway.
				next.ServeHTTP(w, r)
				return
			}

			tier, err := resolveTenantTier(r.Context(), load, tenantID)
			switch {
			case errors.Is(err, errTierTenantNotFound):
				writeTierJSONError(w, http.StatusNotFound, "tenant not found")
				return
			case err != nil:
				slog.Error("subscription tier lookup failed",
					"tenant_id", tenantID, "min_tier", minTier, "err", err)
				writeTierJSONError(w, http.StatusInternalServerError, "subscription tier lookup failed")
				return
			}

			if !tierAtLeast(tier, minTier) {
				slog.Info("request rejected below subscription tier",
					"tenant_id", tenantID, "tier", tier, "min_tier", minTier, "path", r.URL.Path)
				writeTierForbidden(w, minTier)
				return
			}

			// Cache for any downstream helper on the same request.
			next.ServeHTTP(w, r.WithContext(contextWithTenantTier(r.Context(), tenantID, tier)))
		})
	}
}

// requireTenantTier enforces minTier for an already-authenticated tenant on a
// public agent route. Returns true when the request may proceed; otherwise it
// has written the rejection (403 below tier, 500 on lookup failure — the
// tenant row must exist, auth just resolved it) and the caller must return.
func requireTenantTier(w http.ResponseWriter, r *http.Request, load tierLoader, tenantID, minTier string) bool {
	tier, err := resolveTenantTier(r.Context(), load, tenantID)
	if err != nil {
		slog.Error("subscription tier lookup failed",
			"tenant_id", tenantID, "min_tier", minTier, "err", err)
		writeTierJSONError(w, http.StatusInternalServerError, "subscription tier lookup failed")
		return false
	}
	if !tierAtLeast(tier, minTier) {
		slog.Info("agent request rejected below subscription tier",
			"tenant_id", tenantID, "tier", tier, "min_tier", minTier, "path", r.URL.Path)
		writeTierForbidden(w, minTier)
		return false
	}
	return true
}
