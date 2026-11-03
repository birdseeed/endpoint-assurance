package handlers

// PAT-2046: staff admin API for the Homebrew CPE review queue (PAT-2023).
// Internal listener only, guarded by ADMIN_API_TOKEN through
// requireInternalToken like every /admin/* route -- the same H1 auth
// posture as PAT-2015's software category admin API
// (software_categories_admin.go), whose scWriteJSON / scError / scID /
// scDecode / scLogger / decodeOptionalActor helpers this file reuses
// directly rather than duplicating. Every write is audited in
// homebrew_review_audit with the PAT-1135 actor split (server-established
// actor, untrusted claimed_actor, source address) -- see auditAttribution.
//
//	GET  /admin/homebrew/review[?status=&kind=&sort=prevalence]  list the queue
//	POST /admin/homebrew/review/{id}/map                         curate cpe_vendor/cpe_product
//	POST /admin/homebrew/review/{id}/accept-suggestion            curate the row's own suggested_cpe_key
//	POST /admin/homebrew/review/{id}/dismiss                      dismiss
//
// A mapping curated here is picked up by the PAT-2045 event path with no
// further action from this file: internal/cvepipeline.SyncMappingSnapshot
// diffs app_cpe_mappings against cve_mapping_snapshot on every drain cycle
// and does not care who wrote the row. See internal/homebrewreview's package
// comment for the full path.

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/homebrewreview"
)

// MountHomebrewReviewAdminRoutes registers the routes above. Shared by
// cmd/patched-api and the integration harness so the two cannot drift.
func MountHomebrewReviewAdminRoutes(r chi.Router, pool *pgxpool.Pool) {
	r.Get("/admin/homebrew/review", HomebrewReviewListHandler(pool))
	r.Post("/admin/homebrew/review/{id}/map", HomebrewReviewMapHandler(pool))
	r.Post("/admin/homebrew/review/{id}/accept-suggestion", HomebrewReviewAcceptSuggestionHandler(pool))
	r.Post("/admin/homebrew/review/{id}/dismiss", HomebrewReviewDismissHandler(pool))
}

// hrMapErr turns a homebrewreview error into a response; anything
// unexpected is logged and reported as a 500. Mirrors scMapErr, adapted to
// this package's own error set (scMapErr's switch is hardcoded to
// categorytag's errors and would fall through to 500 for all of these).
func hrMapErr(w http.ResponseWriter, logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, homebrewreview.ErrNotFound):
		scError(w, http.StatusNotFound, "not found")
	case errors.Is(err, homebrewreview.ErrInvalidRequest), errors.Is(err, homebrewreview.ErrUnknownCPEKey):
		scError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, homebrewreview.ErrConflict):
		scError(w, http.StatusConflict, err.Error())
	default:
		logger.Error("homebrew review write failed", "err", err)
		scError(w, http.StatusInternalServerError, "internal error")
	}
}

// hrActor builds the audit attribution. The body's actor field is a claim
// only and is stored as claimed_actor (PAT-1135), same as scActor.
func hrActor(r *http.Request, claimed string) homebrewreview.Actor {
	actor, claimedActor, sourceAddr := auditAttribution(r, strings.TrimSpace(claimed))
	return homebrewreview.Actor{Actor: actor, Claimed: claimedActor, SourceAddr: sourceAddr}
}

// hrTx runs fn in one transaction, retried once on a deadlock, and writes
// its result or error. Mirrors scTx, calling hrMapErr instead of scMapErr.
func hrTx(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, logger *slog.Logger, status int, fn func(pgx.Tx) (any, error)) {
	var out any
	err := homebrewreview.RetryDeadlock(func() error {
		return pgx.BeginFunc(r.Context(), pool, func(tx pgx.Tx) error {
			var err error
			out, err = fn(tx)
			return err
		})
	})
	if err != nil {
		hrMapErr(w, logger, err)
		return
	}
	scWriteJSON(w, status, out)
}

var hrValidStatuses = map[string]bool{"": true, homebrewreview.StatusPending: true, homebrewreview.StatusMapped: true, homebrewreview.StatusDismissed: true}
var hrValidKinds = map[string]bool{"": true, "formula": true, "cask": true}
var hrValidSorts = map[string]bool{"": true, "recent": true, "prevalence": true}

func HomebrewReviewListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		if !hrValidStatuses[status] {
			scError(w, http.StatusBadRequest, "status must be one of pending, mapped, dismissed")
			return
		}
		kind := strings.TrimSpace(r.URL.Query().Get("kind"))
		if !hrValidKinds[kind] {
			scError(w, http.StatusBadRequest, "kind must be formula or cask")
			return
		}
		sort := strings.TrimSpace(r.URL.Query().Get("sort"))
		if !hrValidSorts[sort] {
			scError(w, http.StatusBadRequest, "sort must be recent or prevalence")
			return
		}
		rows, err := homebrewreview.List(r.Context(), pool, homebrewreview.ListFilter{Status: status, Kind: kind, Sort: sort})
		if err != nil {
			hrMapErr(w, scLogger(r, "homebrew_review_list"), err)
			return
		}
		scWriteJSON(w, http.StatusOK, map[string]any{"reviews": rows})
	}
}

type hrMapRequest struct {
	CPEVendor  string `json:"cpe_vendor"`
	CPEProduct string `json:"cpe_product"`
	Actor      string `json:"actor"`
}

func HomebrewReviewMapHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := scID(w, r)
		if !ok {
			return
		}
		var req hrMapRequest
		if !scDecode(w, r, &req) {
			return
		}
		hrTx(w, r, pool, scLogger(r, "homebrew_review_map"), http.StatusOK, func(tx pgx.Tx) (any, error) {
			row, err := homebrewreview.Map(r.Context(), tx, id, req.CPEVendor, req.CPEProduct, hrActor(r, req.Actor))
			return map[string]any{"review": row}, err
		})
	}
}

type hrAcceptSuggestionRequest struct {
	ConfirmConflict       bool   `json:"confirm_conflict"`
	ConfirmSingleReporter bool   `json:"confirm_single_reporter"`
	Actor                 string `json:"actor"`
}

func HomebrewReviewAcceptSuggestionHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := scID(w, r)
		if !ok {
			return
		}
		var req hrAcceptSuggestionRequest
		if r.ContentLength != 0 {
			if !scDecode(w, r, &req) {
				return
			}
		}
		hrTx(w, r, pool, scLogger(r, "homebrew_review_accept_suggestion"), http.StatusOK, func(tx pgx.Tx) (any, error) {
			row, err := homebrewreview.AcceptSuggestion(r.Context(), tx, id, req.ConfirmConflict, req.ConfirmSingleReporter, hrActor(r, req.Actor))
			return map[string]any{"review": row}, err
		})
	}
}

func HomebrewReviewDismissHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := scID(w, r)
		if !ok {
			return
		}
		claimed, ok := decodeOptionalActor(w, r)
		if !ok {
			return
		}
		hrTx(w, r, pool, scLogger(r, "homebrew_review_dismiss"), http.StatusOK, func(tx pgx.Tx) (any, error) {
			row, err := homebrewreview.Dismiss(r.Context(), tx, id, hrActor(r, claimed))
			return map[string]any{"review": row}, err
		})
	}
}
