package handlers

// PAT-2138: staff admin API for automatic CPE mapping proposals
// (internal/cpepropose). Internal listener only, ADMIN_API_TOKEN through
// requireInternalToken like every /admin/* route; the same helpers and the
// same PAT-1135 audit attribution as the Homebrew review API (PAT-2046).
//
//	GET  /admin/cve-mapping-proposals[?state=&limit=&offset=]  list (default: open)
//	GET  /admin/cve-mapping-proposals/{id}                      one, with blast radius and audit
//	POST /admin/cve-mapping-proposals/{id}/approve              curate (optionally another candidate)
//	POST /admin/cve-mapping-proposals/{id}/reject               reject, or revoke a published mapping
//
// A mapping approved or revoked here reaches every device through the
// existing mapping-publish path (cvepipeline.SyncMappingSnapshot) with no
// further action from this file.

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/cpepropose"
	"patched.im/api/internal/homebrewreview"
)

// MountCPEProposalAdminRoutes registers the routes above. Shared by
// cmd/patched-api and the integration harness so the two cannot drift.
func MountCPEProposalAdminRoutes(r chi.Router, pool *pgxpool.Pool) {
	r.Get("/admin/cve-mapping-proposals", CPEProposalListHandler(pool))
	r.Get("/admin/cve-mapping-proposals/{id}", CPEProposalGetHandler(pool))
	r.Post("/admin/cve-mapping-proposals/{id}/approve", CPEProposalApproveHandler(pool))
	r.Post("/admin/cve-mapping-proposals/{id}/reject", CPEProposalRejectHandler(pool))
}

func cpMapErr(w http.ResponseWriter, logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, cpepropose.ErrNotFound):
		scError(w, http.StatusNotFound, "not found")
	case errors.Is(err, cpepropose.ErrInvalidRequest):
		scError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, cpepropose.ErrConflict):
		scError(w, http.StatusConflict, err.Error())
	default:
		logger.Error("cve mapping proposal request failed", "err", err)
		scError(w, http.StatusInternalServerError, "internal error")
	}
}

func cpActor(r *http.Request, claimed string) cpepropose.Actor {
	actor, claimedActor, sourceAddr := auditAttribution(r, strings.TrimSpace(claimed))
	return cpepropose.Actor{Actor: actor, Claimed: claimedActor, SourceAddr: sourceAddr}
}

func cpTx(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, logger *slog.Logger, fn func(pgx.Tx) (any, error)) {
	var out any
	err := homebrewreview.RetryDeadlock(func() error {
		return pgx.BeginFunc(r.Context(), pool, func(tx pgx.Tx) error {
			var err error
			out, err = fn(tx)
			return err
		})
	})
	if err != nil {
		cpMapErr(w, logger, err)
		return
	}
	scWriteJSON(w, http.StatusOK, out)
}

func CPEProposalListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := scLogger(r, "cve_mapping_proposal_list")
		q := r.URL.Query()
		state := strings.TrimSpace(q.Get("state"))
		if !cpepropose.ValidListState(state) {
			scError(w, http.StatusBadRequest, "state must be one of pending, needs_review, auto_published, approved, rejected, superseded, all")
			return
		}
		limit, offset := 50, 0
		if v := q.Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 200 {
				scError(w, http.StatusBadRequest, "limit must be 1-200")
				return
			}
			limit = n
		}
		if v := q.Get("offset"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				scError(w, http.StatusBadRequest, "offset must be a non-negative integer")
				return
			}
			offset = n
		}
		rows, total, err := cpepropose.List(r.Context(), pool, cpepropose.ListFilter{State: state, Limit: limit, Offset: offset})
		if err != nil {
			cpMapErr(w, logger, err)
			return
		}
		counts, err := cpepropose.Counts(r.Context(), pool)
		if err != nil {
			cpMapErr(w, logger, err)
			return
		}
		status, err := cpepropose.Status(r.Context(), pool)
		if err != nil {
			cpMapErr(w, logger, err)
			return
		}
		scWriteJSON(w, http.StatusOK, map[string]any{
			"status":    status,
			"counts":    counts,
			"total":     total,
			"limit":     limit,
			"offset":    offset,
			"proposals": rows,
		})
	}
}

func CPEProposalGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := scID(w, r)
		if !ok {
			return
		}
		d, err := cpepropose.Get(r.Context(), pool, id)
		if err != nil {
			cpMapErr(w, scLogger(r, "cve_mapping_proposal_get"), err)
			return
		}
		scWriteJSON(w, http.StatusOK, map[string]any{"proposal": d})
	}
}

type cpApproveRequest struct {
	CPEVendor  string `json:"cpe_vendor"`
	CPEProduct string `json:"cpe_product"`
	Actor      string `json:"actor"`
}

func CPEProposalApproveHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := scID(w, r)
		if !ok {
			return
		}
		var req cpApproveRequest
		if r.ContentLength != 0 {
			if !scDecode(w, r, &req) {
				return
			}
		}
		cpTx(w, r, pool, scLogger(r, "cve_mapping_proposal_approve"), func(tx pgx.Tx) (any, error) {
			p, err := cpepropose.Approve(r.Context(), tx, id, req.CPEVendor, req.CPEProduct, cpActor(r, req.Actor))
			return map[string]any{"proposal": p}, err
		})
	}
}

func CPEProposalRejectHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := scID(w, r)
		if !ok {
			return
		}
		claimed, ok := decodeOptionalActor(w, r)
		if !ok {
			return
		}
		cpTx(w, r, pool, scLogger(r, "cve_mapping_proposal_reject"), func(tx pgx.Tx) (any, error) {
			p, err := cpepropose.Reject(r.Context(), tx, id, cpActor(r, claimed))
			return map[string]any{"proposal": p}, err
		})
	}
}
