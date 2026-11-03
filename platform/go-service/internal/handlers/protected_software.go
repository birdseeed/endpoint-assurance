package handlers

// PAT-1801: protected software list admin surface.
// PAT-1823: read routes for the same list — console (effective set +
// changelog) and portal (per-product protection status).
//
// Routes:
//
//	POST /admin/tenants/{tenantID}/protected-software
//	    Add a tenant-scoped protection on top of the shared baseline. A
//	    tenant may always add — over-protecting is the safe direction.
//	POST /admin/tenants/{tenantID}/protected-software/{baselineID}/override-remove
//	    The ONLY way to stop enforcing a shared baseline protection for one
//	    tenant. Requires a reason and an actor, and is recorded in
//	    protected_software_changes — never a bare DELETE of the baseline row,
//	    which would unprotect it for every other tenant too.
//	GET /admin/tenants/{tenantID}/protected-software
//	    The effective set for a tenant: baseline rows not overridden for
//	    this tenant, plus the tenant's own additions — each tagged with its
//	    source so the console can distinguish them.
//	GET /admin/tenants/{tenantID}/protected-software/changes
//	    The protected_software_changes changelog for a tenant, newest first.
//	GET /v1/portal/protected-software (public listener, portal-JWT auth —
//	    see portalauth.Middleware, mounted in cmd/patched-api/main.go)
//	    The caller's own effective set, shaped as per-product protection
//	    status. This is a disposition flag, not a visibility filter — it
//	    does not touch device_apps or CVE findings, and a protected product
//	    keeps surfacing its normal findings exactly as before.
//
// Enforcement itself (the actual point of PAT-1801) lives in
// internal/protectedsoftware and is called from each write path this
// ticket found live in this codebase — see app_policies.go's
// TenantAppPoliciesPutHandler for the one enforcement point that exists
// today; see that handler's PAT-1801 comment for why the other two named in
// the ticket (removal requests, removal-campaign scope) are not wired here.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var protectedSoftwareValidCategories = map[string]bool{
	"edr": true, "mdm": true, "backup": true, "security": true,
	"patched_agent": true, "customer_defined": true,
}

type protectedSoftwareRow struct {
	ID             int64   `json:"id"`
	TenantID       *string `json:"tenant_id"`
	Category       string  `json:"category"`
	Vendor         string  `json:"vendor"`
	ProductName    string  `json:"product_name"`
	BundleID       *string `json:"bundle_id"`
	TeamID         *string `json:"team_id"`
	Signer         *string `json:"signer"`
	WinPublisher   *string `json:"win_publisher"`
	WinProductCode *string `json:"win_product_code"`
	ProcessName    *string `json:"process_name"`
	Reason         string  `json:"reason"`
	AddedBy        string  `json:"added_by"`
}

type protectedSoftwareAddReq struct {
	Category       string  `json:"category"`
	Vendor         string  `json:"vendor"`
	ProductName    string  `json:"product_name"`
	BundleID       *string `json:"bundle_id"`
	TeamID         *string `json:"team_id"`
	Signer         *string `json:"signer"`
	WinPublisher   *string `json:"win_publisher"`
	WinProductCode *string `json:"win_product_code"`
	ProcessName    *string `json:"process_name"`
	Reason         string  `json:"reason"`
	AddedBy        string  `json:"added_by"`
}

// ProtectedSoftwareAddHandler serves POST /admin/tenants/{tenantID}/protected-software.
//
// 201 protectedSoftwareRow | 400 bad input | 404 unknown tenant | 409 duplicate identity
func ProtectedSoftwareAddHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "protected_software_add")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 8192))
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}
		var req protectedSoftwareAddReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		req.Category = strings.TrimSpace(req.Category)
		req.Vendor = strings.TrimSpace(req.Vendor)
		req.ProductName = strings.TrimSpace(req.ProductName)
		if !protectedSoftwareValidCategories[req.Category] {
			http.Error(w, "category must be one of: edr, mdm, backup, security, patched_agent, customer_defined", http.StatusBadRequest)
			return
		}
		if req.Vendor == "" || req.ProductName == "" {
			http.Error(w, "vendor and product_name are required", http.StatusBadRequest)
			return
		}
		if req.BundleID == nil && req.TeamID == nil && req.Signer == nil &&
			req.WinPublisher == nil && req.WinProductCode == nil && req.ProcessName == nil {
			http.Error(w, "at least one of bundle_id, team_id, signer, win_publisher, win_product_code, process_name must be provided", http.StatusBadRequest)
			return
		}

		var tenantExists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`, tenantID,
		).Scan(&tenantExists); err != nil || !tenantExists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		var row protectedSoftwareRow
		err = pool.QueryRow(r.Context(), `
			INSERT INTO protected_software
			    (tenant_id, category, vendor, product_name, bundle_id, team_id, signer,
			     win_publisher, win_product_code, process_name, reason, added_by)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			RETURNING id, tenant_id::text, category, vendor, product_name, bundle_id, team_id,
			          signer, win_publisher, win_product_code, process_name, reason, added_by
		`, tenantID, req.Category, req.Vendor, req.ProductName, req.BundleID, req.TeamID, req.Signer,
			req.WinPublisher, req.WinProductCode, req.ProcessName, req.Reason, req.AddedBy,
		).Scan(
			&row.ID, &row.TenantID, &row.Category, &row.Vendor, &row.ProductName, &row.BundleID, &row.TeamID,
			&row.Signer, &row.WinPublisher, &row.WinProductCode, &row.ProcessName, &row.Reason, &row.AddedBy,
		)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				http.Error(w, "an identical protected-software identity already exists for this tenant", http.StatusConflict)
				return
			}
			logger.Error("protected software insert failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		addDetail, err := json.Marshal(map[string]string{
			"category":     row.Category,
			"vendor":       row.Vendor,
			"product_name": row.ProductName,
		})
		if err != nil {
			logger.Error("protected software audit detail marshal failed", "err", err, "tenant_id", tenantID, "entry_id", row.ID)
			addDetail = []byte("{}")
		}
		if _, err := pool.Exec(r.Context(), `
			INSERT INTO protected_software_changes (tenant_id, entry_id, action, actor, detail)
			VALUES ($1::uuid, $2, 'added', $3, $4)
		`, tenantID, row.ID, req.AddedBy, addDetail); err != nil {
			// Non-fatal: the protection itself is written; log and continue
			// rather than rolling back a successful protective write over an
			// audit-log insert failure.
			logger.Error("protected software audit log insert failed", "err", err, "tenant_id", tenantID, "entry_id", row.ID)
		}

		logger.Info("protected software added", "tenant_id", tenantID, "entry_id", row.ID, "category", row.Category)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(row)
	}
}

type protectedSoftwareOverrideRemoveReq struct {
	Reason    string `json:"reason"`
	RemovedBy string `json:"removed_by"`
}

// ProtectedSoftwareOverrideRemoveHandler serves
// POST /admin/tenants/{tenantID}/protected-software/{baselineID}/override-remove.
//
// This is the only path that can stop a shared baseline protection applying
// to one tenant. It never deletes the baseline row (that would unprotect it
// for every tenant); it records an audited, reasoned override instead.
//
// 201 | 400 bad input | 404 unknown tenant or baseline entry | 409 already overridden
func ProtectedSoftwareOverrideRemoveHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "protected_software_override_remove")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		baselineID, err := strconv.ParseInt(strings.TrimSpace(chi.URLParam(r, "baselineID")), 10, 64)
		if err != nil {
			http.Error(w, "baselineID must be an integer", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}
		var req protectedSoftwareOverrideRemoveReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		req.Reason = strings.TrimSpace(req.Reason)
		req.RemovedBy = strings.TrimSpace(req.RemovedBy)
		if req.Reason == "" || req.RemovedBy == "" {
			http.Error(w, "reason and removed_by are both required", http.StatusBadRequest)
			return
		}

		var tenantExists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`, tenantID,
		).Scan(&tenantExists); err != nil || !tenantExists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		// baselineID must reference a shared baseline row (tenant_id IS NULL)
		// — Postgres cannot express this as a CHECK against another table's
		// column, so it is verified here before the override is recorded.
		var category, vendor, productName string
		if err := pool.QueryRow(r.Context(), `
			SELECT category, vendor, product_name FROM protected_software
			WHERE id = $1 AND tenant_id IS NULL
		`, baselineID).Scan(&category, &vendor, &productName); err != nil {
			if err == pgx.ErrNoRows {
				http.Error(w, "baselineID does not reference a shared baseline protected-software entry", http.StatusNotFound)
				return
			}
			logger.Error("baseline lookup failed", "err", err, "baseline_id", baselineID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if _, err := pool.Exec(r.Context(), `
			INSERT INTO protected_software_overrides (tenant_id, baseline_id, reason, removed_by)
			VALUES ($1::uuid, $2, $3, $4)
		`, tenantID, baselineID, req.Reason, req.RemovedBy); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				http.Error(w, "this baseline protection is already overridden for this tenant", http.StatusConflict)
				return
			}
			logger.Error("protected software override insert failed", "err", err, "tenant_id", tenantID, "baseline_id", baselineID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		removeDetail, err := json.Marshal(map[string]string{
			"reason":       req.Reason,
			"category":     category,
			"vendor":       vendor,
			"product_name": productName,
		})
		if err != nil {
			logger.Error("protected software audit detail marshal failed", "err", err, "tenant_id", tenantID, "baseline_id", baselineID)
			removeDetail = []byte("{}")
		}
		if _, err := pool.Exec(r.Context(), `
			INSERT INTO protected_software_changes (tenant_id, entry_id, action, actor, detail)
			VALUES ($1::uuid, $2, 'baseline_override_removed', $3, $4)
		`, tenantID, baselineID, req.RemovedBy, removeDetail,
		); err != nil {
			logger.Error("protected software audit log insert failed", "err", err, "tenant_id", tenantID, "baseline_id", baselineID)
		}

		logger.Info("protected software baseline override recorded", "tenant_id", tenantID, "baseline_id", baselineID)
		w.WriteHeader(http.StatusCreated)
	}
}

// ---------------------------------------------------------------------------
// GET /admin/tenants/{tenantID}/protected-software — effective set
// ---------------------------------------------------------------------------

// protectedSoftwareEffectiveRow is a protected_software row as it applies to
// one tenant: either a shared baseline row this tenant has not overridden,
// or the tenant's own addition. Source distinguishes the two so the console
// can render them differently — a tenant can add or (via override-remove)
// stop enforcing a baseline row, but never edit or delete a baseline row
// itself.
type protectedSoftwareEffectiveRow struct {
	ID             int64   `json:"id"`
	Source         string  `json:"source"` // "baseline" | "tenant"
	Category       string  `json:"category"`
	Vendor         string  `json:"vendor"`
	ProductName    string  `json:"product_name"`
	BundleID       *string `json:"bundle_id"`
	TeamID         *string `json:"team_id"`
	Signer         *string `json:"signer"`
	WinPublisher   *string `json:"win_publisher"`
	WinProductCode *string `json:"win_product_code"`
	ProcessName    *string `json:"process_name"`
	Reason         string  `json:"reason"`
	AddedBy        string  `json:"added_by"`
}

type protectedSoftwareListResp struct {
	TenantID string                          `json:"tenant_id"`
	Entries  []protectedSoftwareEffectiveRow `json:"entries"`
}

// protectedSoftwareEffectiveSetQuery is shared by the console list handler
// and the portal handler below: baseline rows (tenant_id IS NULL) that this
// tenant has NOT overridden via protected_software_overrides, unioned with
// the tenant's own additions (tenant_id = the caller's tenant). Never a
// two-step "fetch baseline then fetch overrides" — the LEFT JOIN keeps this
// a single query with no window for the two halves to disagree.
const protectedSoftwareEffectiveSetQuery = `
	SELECT ps.id, ps.category, ps.vendor, ps.product_name, ps.bundle_id, ps.team_id,
	       ps.signer, ps.win_publisher, ps.win_product_code, ps.process_name,
	       ps.reason, ps.added_by, (ps.tenant_id IS NULL) AS is_baseline
	FROM protected_software ps
	LEFT JOIN protected_software_overrides o
	    ON o.baseline_id = ps.id AND o.tenant_id = $1::uuid
	WHERE (ps.tenant_id IS NULL AND o.id IS NULL) OR ps.tenant_id = $1::uuid
	ORDER BY ps.vendor, ps.product_name
`

// TenantProtectedSoftwareGetHandler serves GET /admin/tenants/{tenantID}/protected-software.
//
// 200 protectedSoftwareListResp | 400 bad tenantID | 404 unknown tenant
func TenantProtectedSoftwareGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "protected_software_get")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		var tenantExists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`, tenantID,
		).Scan(&tenantExists); err != nil || !tenantExists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		rows, err := pool.Query(r.Context(), protectedSoftwareEffectiveSetQuery, tenantID)
		if err != nil {
			logger.Error("protected software effective set query failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var entries []protectedSoftwareEffectiveRow
		for rows.Next() {
			var e protectedSoftwareEffectiveRow
			var isBaseline bool
			if err := rows.Scan(&e.ID, &e.Category, &e.Vendor, &e.ProductName, &e.BundleID, &e.TeamID,
				&e.Signer, &e.WinPublisher, &e.WinProductCode, &e.ProcessName, &e.Reason, &e.AddedBy, &isBaseline); err != nil {
				logger.Error("protected software row scan failed", "err", err, "tenant_id", tenantID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if isBaseline {
				e.Source = "baseline"
			} else {
				e.Source = "tenant"
			}
			entries = append(entries, e)
		}
		if err := rows.Err(); err != nil {
			logger.Error("protected software rows error", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if entries == nil {
			entries = []protectedSoftwareEffectiveRow{}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protectedSoftwareListResp{
			TenantID: tenantID,
			Entries:  entries,
		})
	}
}

// ---------------------------------------------------------------------------
// GET /admin/tenants/{tenantID}/protected-software/changes — changelog
// ---------------------------------------------------------------------------

type protectedSoftwareChangeJSON struct {
	ID        int64           `json:"id"`
	EntryID   *int64          `json:"entry_id"`
	Action    string          `json:"action"`
	Actor     string          `json:"actor"`
	Detail    json.RawMessage `json:"detail"`
	ChangedAt time.Time       `json:"changed_at"`
}

type protectedSoftwareChangesResp struct {
	TenantID string                        `json:"tenant_id"`
	Changes  []protectedSoftwareChangeJSON `json:"changes"`
}

// TenantProtectedSoftwareChangesHandler serves
// GET /admin/tenants/{tenantID}/protected-software/changes — when/why/who
// for every 'added' and 'baseline_override_removed' action recorded for
// this tenant, newest first.
//
// 200 protectedSoftwareChangesResp | 400 bad tenantID | 404 unknown tenant
func TenantProtectedSoftwareChangesHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "protected_software_changes")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		var tenantExists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`, tenantID,
		).Scan(&tenantExists); err != nil || !tenantExists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		rows, err := pool.Query(r.Context(), `
			SELECT id, entry_id, action, actor, detail, changed_at
			FROM protected_software_changes
			WHERE tenant_id = $1::uuid
			ORDER BY changed_at DESC, id DESC
		`, tenantID)
		if err != nil {
			logger.Error("protected software changes query failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var changes []protectedSoftwareChangeJSON
		for rows.Next() {
			var c protectedSoftwareChangeJSON
			var detail []byte
			if err := rows.Scan(&c.ID, &c.EntryID, &c.Action, &c.Actor, &detail, &c.ChangedAt); err != nil {
				logger.Error("protected software change row scan failed", "err", err, "tenant_id", tenantID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			c.Detail = json.RawMessage(detail)
			changes = append(changes, c)
		}
		if err := rows.Err(); err != nil {
			logger.Error("protected software changes rows error", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if changes == nil {
			changes = []protectedSoftwareChangeJSON{}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protectedSoftwareChangesResp{
			TenantID: tenantID,
			Changes:  changes,
		})
	}
}

// ---------------------------------------------------------------------------
// GET /v1/portal/protected-software — portal-scoped protection status
// ---------------------------------------------------------------------------

// portalProtectedSoftwareEntry is one product in the caller's effective
// protected-software set. Protected is always true today — this endpoint
// only ever returns the effective set, never the full software estate — but
// the field is part of the contract so a future "protected: false" row
// (e.g. one the console is considering, or a removed override) can be added
// without a breaking shape change. See the file-level doc comment: this is
// a disposition flag only, never a visibility filter — it does not read
// device_apps or CVE findings, and finding queries are untouched by it.
type portalProtectedSoftwareEntry struct {
	Vendor      string `json:"vendor"`
	ProductName string `json:"product_name"`
	Category    string `json:"category"`
	Protected   bool   `json:"protected"`
}

type portalProtectedSoftwareResp struct {
	Products []portalProtectedSoftwareEntry `json:"products"`
}

// PortalProtectedSoftwareHandler serves GET /v1/portal/protected-software on
// the PUBLIC listener, behind portalauth.Middleware (CF-Access-JWT auth via
// the caller's verified portal identity) — a different auth path from the
// two /admin/tenants/{tenantID}/... routes above, which sit behind
// ADMIN_API_TOKEN on the internal listener. Tenant identity comes only from
// the verified identity, per the portal invariants in portal.go's doc
// comment — never a URL, query or body parameter.
func PortalProtectedSoftwareHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_protected_software", "tenant_id", id.TenantID)

		rows, err := pool.Query(r.Context(), protectedSoftwareEffectiveSetQuery, id.TenantID)
		if err != nil {
			logger.Error("protected software effective set query failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var products []portalProtectedSoftwareEntry
		for rows.Next() {
			var (
				entryID                                                             int64
				category, vendor, productName, reason, addedBy                      string
				bundleID, teamID, signer, winPublisher, winProductCode, processName *string
				isBaseline                                                          bool
			)
			if err := rows.Scan(&entryID, &category, &vendor, &productName, &bundleID, &teamID,
				&signer, &winPublisher, &winProductCode, &processName, &reason, &addedBy, &isBaseline); err != nil {
				logger.Error("protected software row scan failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			products = append(products, portalProtectedSoftwareEntry{
				Vendor:      vendor,
				ProductName: productName,
				Category:    category,
				Protected:   true,
			})
		}
		if err := rows.Err(); err != nil {
			logger.Error("protected software rows error", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if products == nil {
			products = []portalProtectedSoftwareEntry{}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(portalProtectedSoftwareResp{Products: products})
	}
}
