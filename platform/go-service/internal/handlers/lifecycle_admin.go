package handlers

// PAT-2147: staff admin API for software lifecycle mappings (the SAM
// unsupported software report's reviewed product -> endoflife.date links)
// and the lifecycle data refresh. Internal listener only, guarded by
// ADMIN_API_TOKEN through requireInternalToken like every /admin/* route,
// the same posture as the PAT-2046 Homebrew review and PAT-2138 CPE proposal
// admin APIs, whose scWriteJSON / scError / scID / scDecode / scLogger /
// decodeOptionalActor helpers this file reuses. Every mapping write is
// audited in lifecycle_mapping_audit with the PAT-1135 actor split.
//
//	GET  /admin/lifecycle/mappings[?status=proposed|published|rejected]
//	POST /admin/lifecycle/mappings               propose (never affects customers until published)
//	POST /admin/lifecycle/mappings/{id}/publish  publish (the slug must have fetched cycle data)
//	POST /admin/lifecycle/mappings/{id}/reject   reject a proposal, or withdraw a published mapping
//	GET  /admin/lifecycle/products               every slug's fetch state
//	POST /admin/lifecycle/refresh                refetch every active slug, or {"slug": "..."}

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/lifecycle"
)

// lifecycleRefreshTimeout bounds a detached admin-triggered refresh.
const lifecycleRefreshTimeout = 10 * time.Minute

// lifecycleFetcher is the fetcher the admin refresh uses. A variable only so
// an integration test can point it at a local server
// (SetLifecycleFetcherForTest); production never reassigns it.
var lifecycleFetcher = lifecycle.NewFetcher(nil)

// SetLifecycleFetcherForTest replaces the admin refresh's fetcher and returns
// a function that restores it. Test use only.
func SetLifecycleFetcherForTest(f *lifecycle.Fetcher) func() {
	prev := lifecycleFetcher
	lifecycleFetcher = f
	return func() { lifecycleFetcher = prev }
}

// MountLifecycleAdminRoutes registers the routes above. Shared by
// cmd/patched-api and the integration harness so the two cannot drift.
func MountLifecycleAdminRoutes(r chi.Router, pool *pgxpool.Pool) {
	r.Get("/admin/lifecycle/mappings", LifecycleMappingsListHandler(pool))
	r.Post("/admin/lifecycle/mappings", LifecycleMappingProposeHandler(pool))
	r.Post("/admin/lifecycle/mappings/{id}/publish", LifecycleMappingPublishHandler(pool))
	r.Post("/admin/lifecycle/mappings/{id}/reject", LifecycleMappingRejectHandler(pool))
	r.Get("/admin/lifecycle/products", LifecycleProductsHandler(pool))
	r.Post("/admin/lifecycle/refresh", LifecycleRefreshHandler(pool))
}

func lcMapErr(w http.ResponseWriter, logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, lifecycle.ErrNotFound):
		scError(w, http.StatusNotFound, "not found")
	case errors.Is(err, lifecycle.ErrInvalidRequest):
		scError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, lifecycle.ErrConflict), errors.Is(err, lifecycle.ErrRefreshInProgress):
		scError(w, http.StatusConflict, err.Error())
	default:
		logger.Error("lifecycle admin write failed", "err", err)
		scError(w, http.StatusInternalServerError, "internal error")
	}
}

func lcActor(r *http.Request, claimed string) lifecycle.Actor {
	actor, claimedActor, sourceAddr := auditAttribution(r, strings.TrimSpace(claimed))
	return lifecycle.Actor{Actor: actor, Claimed: claimedActor, SourceAddr: sourceAddr}
}

func lcTx(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, logger *slog.Logger, status int, fn func(pgx.Tx) (any, error)) {
	var out any
	err := lifecycle.RetryDeadlock(func() error {
		return pgx.BeginFunc(r.Context(), pool, func(tx pgx.Tx) error {
			var err error
			out, err = fn(tx)
			return err
		})
	})
	if err != nil {
		lcMapErr(w, logger, err)
		return
	}
	scWriteJSON(w, status, out)
}

func LifecycleMappingsListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		switch status {
		case "", lifecycle.StatusProposed, lifecycle.StatusPublished, lifecycle.StatusRejected:
		default:
			scError(w, http.StatusBadRequest, "status must be one of proposed, published, rejected")
			return
		}
		rows, err := lifecycle.List(r.Context(), pool, status)
		if err != nil {
			lcMapErr(w, scLogger(r, "lifecycle_mappings_list"), err)
			return
		}
		scWriteJSON(w, http.StatusOK, map[string]any{"mappings": rows})
	}
}

type lcProposeRequest struct {
	Platform       string `json:"platform"`
	IdentityKind   string `json:"identity_kind"`
	IdentityValue  string `json:"identity_value"`
	CompanionValue string `json:"companion_value"`
	Slug           string `json:"eol_slug"`
	VersionRule    string `json:"version_rule"`
	VersionRegex   string `json:"version_regex"`
	Notes          string `json:"notes"`
	Actor          string `json:"actor"`
	// Rolling opts the mapping into the rolling-release rule (PAT-2171);
	// RollingWindowDays overrides the default window and needs Rolling.
	Rolling           bool `json:"rolling"`
	RollingWindowDays *int `json:"rolling_window_days"`
}

func LifecycleMappingProposeHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req lcProposeRequest
		if !scDecode(w, r, &req) {
			return
		}
		in := lifecycle.ProposeInput{Platform: req.Platform, IdentityKind: req.IdentityKind,
			IdentityValue: req.IdentityValue, CompanionValue: req.CompanionValue, Slug: req.Slug,
			VersionRule: req.VersionRule, VersionRegex: req.VersionRegex, Notes: req.Notes,
			Rolling: req.Rolling, RollingWindowDays: req.RollingWindowDays}
		lcTx(w, r, pool, scLogger(r, "lifecycle_mapping_propose"), http.StatusCreated, func(tx pgx.Tx) (any, error) {
			m, err := lifecycle.Propose(r.Context(), tx, in, lcActor(r, req.Actor))
			return map[string]any{"mapping": m}, err
		})
	}
}

func LifecycleMappingPublishHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := scID(w, r)
		if !ok {
			return
		}
		claimed, ok := decodeOptionalActor(w, r)
		if !ok {
			return
		}
		lcTx(w, r, pool, scLogger(r, "lifecycle_mapping_publish"), http.StatusOK, func(tx pgx.Tx) (any, error) {
			m, err := lifecycle.Publish(r.Context(), tx, id, lcActor(r, claimed))
			return map[string]any{"mapping": m}, err
		})
	}
}

func LifecycleMappingRejectHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := scID(w, r)
		if !ok {
			return
		}
		claimed, ok := decodeOptionalActor(w, r)
		if !ok {
			return
		}
		lcTx(w, r, pool, scLogger(r, "lifecycle_mapping_reject"), http.StatusOK, func(tx pgx.Tx) (any, error) {
			m, err := lifecycle.Reject(r.Context(), tx, id, lcActor(r, claimed))
			return map[string]any{"mapping": m}, err
		})
	}
}

func LifecycleProductsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ps, err := lifecycle.ListProducts(r.Context(), pool, time.Now())
		if err != nil {
			lcMapErr(w, scLogger(r, "lifecycle_products"), err)
			return
		}
		scWriteJSON(w, http.StatusOK, map[string]any{"products": ps, "cache_ttl_days": int(lifecycle.CacheTTL / (24 * time.Hour))})
	}
}

type lcRefreshRequest struct {
	Slug  string `json:"slug"`
	Actor string `json:"actor"`
}

// LifecycleRefreshHandler starts a refresh and answers 202 at once: a full
// refresh can outlast the internal listener's 15 s write timeout. The lock
// is taken before answering, so a 409 means one is already running; the
// outcome is read back from GET /admin/lifecycle/products.
func LifecycleRefreshHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req lcRefreshRequest
		if r.ContentLength != 0 {
			if !scDecode(w, r, &req) {
				return
			}
		}
		logger := scLogger(r, "lifecycle_refresh")
		var slugs []string
		if s := strings.ToLower(strings.TrimSpace(req.Slug)); s != "" {
			if !lifecycle.ValidSlug(s) {
				scError(w, http.StatusBadRequest, "slug must be an endoflife.date product slug")
				return
			}
			slugs = []string{s}
		} else {
			active, err := lifecycle.ActiveSlugs(r.Context(), pool)
			if err != nil {
				lcMapErr(w, logger, err)
				return
			}
			slugs = active
		}
		release, err := lifecycle.Lock(r.Context(), pool)
		if err != nil {
			lcMapErr(w, logger, err)
			return
		}
		actor, _, _ := auditAttribution(r, strings.TrimSpace(req.Actor))
		fetcher := lifecycleFetcher
		go func() {
			defer release()
			ctx, cancel := context.WithTimeout(context.Background(), lifecycleRefreshTimeout)
			defer cancel()
			res, err := fetcher.Refresh(ctx, pool, slugs)
			if err != nil {
				logger.Error("lifecycle refresh failed", "err", err, "actor", actor)
				return
			}
			logger.Info("lifecycle refresh complete", "actor", actor, "succeeded", res.Succeeded, "failed", res.Failed)
		}()
		scWriteJSON(w, http.StatusAccepted, map[string]any{"status": "started", "slugs": slugs})
	}
}
