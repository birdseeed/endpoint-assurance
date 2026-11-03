package handlers

// PAT-2015: staff admin API for the software category tag model (global
// match rules and product-identity tags). Internal listener only, guarded by
// ADMIN_API_TOKEN through requireInternalToken like every /admin/* route.
// Every write is audited in software_category_audit with the PAT-1135 actor
// split (server-established actor, untrusted claimed_actor, source address).
//
// Deliberately not under /admin/catalogue/*: that prefix is the quarantined
// legacy package catalogue, and this model is governance classification, not
// packaging.
//
//	GET  /admin/software-categories                         vocabulary
//	GET  /admin/software-categories/rules[?state=]          list rules
//	POST /admin/software-categories/rules                   create a draft
//	GET  /admin/software-categories/rules/{id}              one rule
//	PUT  /admin/software-categories/rules/{id}              edit (draft or published)
//	POST /admin/software-categories/rules/{id}/publish      chunked backfill, then publish
//	POST /admin/software-categories/rules/{id}/retire       retire + untag
//	GET  /admin/software-categories/rules/{id}/audit        audit trail
//	GET  /admin/software-categories/product-tags[?state=]   list product tags
//	POST /admin/software-categories/product-tags            tag a product
//	POST /admin/software-categories/product-tags/{id}/retire
//	GET  /admin/software-categories/product-tags/{id}/audit
//	POST /admin/software-categories/backfill                re-run everything published

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/categorytag"
)

const maxSoftwareCategoryBodyBytes = 16384

// MountSoftwareCategoryAdminRoutes registers the routes above. Shared by
// cmd/patched-api and the integration harness so the two cannot drift.
func MountSoftwareCategoryAdminRoutes(r chi.Router, pool *pgxpool.Pool) {
	r.Get("/admin/software-categories", SoftwareCategoriesListHandler(pool))
	r.Get("/admin/software-categories/rules", SoftwareCategoryRulesListHandler(pool))
	r.Post("/admin/software-categories/rules", SoftwareCategoryRuleCreateHandler(pool))
	r.Get("/admin/software-categories/rules/{id}", SoftwareCategoryRuleGetHandler(pool))
	r.Put("/admin/software-categories/rules/{id}", SoftwareCategoryRuleUpdateHandler(pool))
	r.Post("/admin/software-categories/rules/{id}/publish", SoftwareCategoryRulePublishHandler(pool))
	r.Post("/admin/software-categories/rules/{id}/retire", SoftwareCategoryRuleRetireHandler(pool))
	r.Get("/admin/software-categories/rules/{id}/audit", softwareCategoryAuditHandler(pool, "rule"))
	r.Get("/admin/software-categories/product-tags", SoftwareCategoryProductTagsListHandler(pool))
	r.Post("/admin/software-categories/product-tags", SoftwareCategoryProductTagCreateHandler(pool))
	r.Post("/admin/software-categories/product-tags/{id}/retire", SoftwareCategoryProductTagRetireHandler(pool))
	r.Get("/admin/software-categories/product-tags/{id}/audit", softwareCategoryAuditHandler(pool, "product_tag"))
	r.Post("/admin/software-categories/backfill", SoftwareCategoryBackfillHandler(pool))
}

func scLogger(r *http.Request, handler string) *slog.Logger {
	return slog.With("req_id", middleware.GetReqID(r.Context()), "handler", handler)
}

func scWriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func scError(w http.ResponseWriter, status int, msg string) {
	scWriteJSON(w, status, map[string]string{"error": msg})
}

// scMapErr turns a categorytag error into a response; anything unexpected is
// logged and reported as a 500.
func scMapErr(w http.ResponseWriter, logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, categorytag.ErrNotFound):
		scError(w, http.StatusNotFound, "not found")
	case errors.Is(err, categorytag.ErrInvalidRule):
		scError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, categorytag.ErrConflict), errors.Is(err, categorytag.ErrDuplicate):
		scError(w, http.StatusConflict, err.Error())
	case errors.Is(err, categorytag.ErrReconcileIncomplete):
		logger.Error("software category reconcile incomplete", "err", err)
		scError(w, http.StatusInternalServerError, err.Error())
	default:
		logger.Error("software category write failed", "err", err)
		scError(w, http.StatusInternalServerError, "internal error")
	}
}

func scID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		scError(w, http.StatusBadRequest, "id must be a positive integer")
		return 0, false
	}
	return id, true
}

func scDecode(w http.ResponseWriter, r *http.Request, out any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxSoftwareCategoryBodyBytes+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		scError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func scState(w http.ResponseWriter, r *http.Request, allowed ...string) (string, bool) {
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if state == "" {
		return "", true
	}
	for _, a := range allowed {
		if state == a {
			return state, true
		}
	}
	scError(w, http.StatusBadRequest, "state must be one of "+strings.Join(allowed, ", "))
	return "", false
}

// scActor builds the audit attribution. The body's actor field is a claim
// only and is stored as claimed_actor (PAT-1135).
func scActor(r *http.Request, claimed string) categorytag.Actor {
	actor, claimedActor, sourceAddr := auditAttribution(r, strings.TrimSpace(claimed))
	return categorytag.Actor{Actor: actor, Claimed: claimedActor, SourceAddr: sourceAddr}
}

// scPool runs a multi-transaction write (edit, publish), retried once on a
// deadlock, and writes its result or error.
func scPool(w http.ResponseWriter, logger *slog.Logger, fn func() (any, error)) {
	var out any
	err := categorytag.RetryDeadlock(func() error {
		var err error
		out, err = fn()
		return err
	})
	if err != nil {
		scMapErr(w, logger, err)
		return
	}
	scWriteJSON(w, http.StatusOK, out)
}

// scTx runs fn in one transaction, retried once on a deadlock, and writes
// its result or error.
func scTx(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, logger *slog.Logger, status int, fn func(pgx.Tx) (any, error)) {
	var out any
	err := categorytag.RetryDeadlock(func() error {
		return pgx.BeginFunc(r.Context(), pool, func(tx pgx.Tx) error {
			var err error
			out, err = fn(tx)
			return err
		})
	})
	if err != nil {
		scMapErr(w, logger, err)
		return
	}
	scWriteJSON(w, status, out)
}

type ruleWriteRequest struct {
	categorytag.RuleSpec
	Actor string `json:"actor"`
}

type ruleWriteResponse struct {
	Rule     categorytag.Rule   `json:"rule"`
	Backfill categorytag.Result `json:"backfill"`
}

// SoftwareCategoriesListHandler returns the category and subtype vocabulary
// plus the rule-type vocabulary the console form needs.
func SoftwareCategoriesListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cats, err := categorytag.ListCategories(r.Context(), pool)
		if err != nil {
			scLogger(r, "software_categories_list").Error("list categories", "err", err)
			scError(w, http.StatusInternalServerError, "internal error")
			return
		}
		scWriteJSON(w, http.StatusOK, map[string]any{
			"categories":       cats,
			"identifier_types": categorytag.IdentifierTypes(),
			"browser_stores":   categorytag.Stores(),
			"ide_marketplaces": categorytag.Marketplaces(),
			"package_sources":  categorytag.PackageSources(),
			"platforms":        []string{categorytag.PlatformMacOS, categorytag.PlatformWindows, categorytag.PlatformAny},
		})
	}
}

func SoftwareCategoryRulesListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, ok := scState(w, r, categorytag.StateDraft, categorytag.StatePublished, categorytag.StateRetired)
		if !ok {
			return
		}
		rules, err := categorytag.ListRules(r.Context(), pool, state)
		if err != nil {
			scMapErr(w, scLogger(r, "software_category_rules_list"), err)
			return
		}
		scWriteJSON(w, http.StatusOK, map[string]any{"rules": rules})
	}
}

func SoftwareCategoryRuleGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := scID(w, r)
		if !ok {
			return
		}
		rule, err := categorytag.GetRule(r.Context(), pool, id)
		if err != nil {
			scMapErr(w, scLogger(r, "software_category_rule_get"), err)
			return
		}
		scWriteJSON(w, http.StatusOK, rule)
	}
}

func SoftwareCategoryRuleCreateHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ruleWriteRequest
		if !scDecode(w, r, &req) {
			return
		}
		scTx(w, r, pool, scLogger(r, "software_category_rule_create"), http.StatusCreated, func(tx pgx.Tx) (any, error) {
			rule, err := categorytag.CreateRule(r.Context(), tx, req.RuleSpec, scActor(r, req.Actor))
			return ruleWriteResponse{Rule: rule}, err
		})
	}
}

func SoftwareCategoryRuleUpdateHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := scID(w, r)
		if !ok {
			return
		}
		var req ruleWriteRequest
		if !scDecode(w, r, &req) {
			return
		}
		scPool(w, scLogger(r, "software_category_rule_update"), func() (any, error) {
			rule, res, err := categorytag.UpdateRule(r.Context(), pool, id, req.RuleSpec, scActor(r, req.Actor))
			return ruleWriteResponse{Rule: rule, Backfill: res}, err
		})
	}
}

type actorOnlyRequest struct {
	Actor string `json:"actor"`
}

// decodeOptionalActor accepts an empty body or {"actor": "..."}.
func decodeOptionalActor(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req actorOnlyRequest
	if r.ContentLength == 0 {
		return "", true
	}
	if !scDecode(w, r, &req) {
		return "", false
	}
	return req.Actor, true
}

// publishTimeout bounds a detached publish backfill.
const publishTimeout = 10 * time.Minute

func SoftwareCategoryRulePublishHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := scID(w, r)
		if !ok {
			return
		}
		claimed, ok := decodeOptionalActor(w, r)
		if !ok {
			return
		}
		scPool(w, scLogger(r, "software_category_rule_publish"), func() (any, error) {
			// Detached from the request so a client disconnect or the 15s write
			// timeout cannot cancel a backfill mid-way (API.md: a publish can
			// finish server side after the client gives up). Bounded on its own.
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), publishTimeout)
			defer cancel()
			rule, res, err := categorytag.PublishRule(ctx, pool, id, scActor(r, claimed))
			return ruleWriteResponse{Rule: rule, Backfill: res}, err
		})
	}
}

func SoftwareCategoryRuleRetireHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := scID(w, r)
		if !ok {
			return
		}
		claimed, ok := decodeOptionalActor(w, r)
		if !ok {
			return
		}
		scTx(w, r, pool, scLogger(r, "software_category_rule_retire"), http.StatusOK, func(tx pgx.Tx) (any, error) {
			rule, res, err := categorytag.RetireRule(r.Context(), tx, id, scActor(r, claimed))
			return ruleWriteResponse{Rule: rule, Backfill: res}, err
		})
	}
}

func softwareCategoryAuditHandler(pool *pgxpool.Pool, entity string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := scID(w, r)
		if !ok {
			return
		}
		entries, err := categorytag.ListAudit(r.Context(), pool, entity, id)
		if err != nil {
			scMapErr(w, scLogger(r, "software_category_audit"), err)
			return
		}
		scWriteJSON(w, http.StatusOK, map[string]any{"entries": entries})
	}
}

func SoftwareCategoryProductTagsListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, ok := scState(w, r, categorytag.StatePublished, categorytag.StateRetired)
		if !ok {
			return
		}
		tags, err := categorytag.ListProductTags(r.Context(), pool, state)
		if err != nil {
			scMapErr(w, scLogger(r, "software_category_product_tags_list"), err)
			return
		}
		scWriteJSON(w, http.StatusOK, map[string]any{"product_tags": tags})
	}
}

type productTagWriteResponse struct {
	ProductTag categorytag.ProductTag `json:"product_tag"`
	Backfill   categorytag.Result     `json:"backfill"`
}

func SoftwareCategoryProductTagCreateHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			categorytag.ProductTagSpec
			Actor string `json:"actor"`
		}
		if !scDecode(w, r, &req) {
			return
		}
		scTx(w, r, pool, scLogger(r, "software_category_product_tag_create"), http.StatusCreated, func(tx pgx.Tx) (any, error) {
			tag, res, err := categorytag.CreateProductTag(r.Context(), tx, req.ProductTagSpec, scActor(r, req.Actor))
			return productTagWriteResponse{ProductTag: tag, Backfill: res}, err
		})
	}
}

func SoftwareCategoryProductTagRetireHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := scID(w, r)
		if !ok {
			return
		}
		claimed, ok := decodeOptionalActor(w, r)
		if !ok {
			return
		}
		scTx(w, r, pool, scLogger(r, "software_category_product_tag_retire"), http.StatusOK, func(tx pgx.Tx) (any, error) {
			tag, res, err := categorytag.RetireProductTag(r.Context(), tx, id, scActor(r, claimed))
			return productTagWriteResponse{ProductTag: tag, Backfill: res}, err
		})
	}
}

// SoftwareCategoryBackfillHandler re-runs every published rule and product
// tag. Idempotent; the recovery path when a device's ingest-time evaluation
// was skipped. It changes no rule, so it writes no audit row.
func SoftwareCategoryBackfillHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res, err := categorytag.ReconcileAll(r.Context(), pool)
		if err != nil {
			scLogger(r, "software_category_backfill").Error("backfill failed", "err", err, "tagged", res.Tagged, "retired", res.Retired)
			scError(w, http.StatusInternalServerError, "backfill failed; it is safe to re-run")
			return
		}
		scWriteJSON(w, http.StatusOK, map[string]any{"backfill": res})
	}
}
