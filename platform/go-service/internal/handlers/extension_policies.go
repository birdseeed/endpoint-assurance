package handlers

// Per-tenant browser-extension policy store + estate scan (PAT-826).
//
// Routes (all on :8081 Tailscale-only admin listener):
//
//	GET    /admin/tenants/{tenantID}/extension-policies           – list policy entries
//	POST   /admin/tenants/{tenantID}/extension-policies           – add entry
//	PUT    /admin/tenants/{tenantID}/extension-policies/{entryID} – update policy / notes
//	DELETE /admin/tenants/{tenantID}/extension-policies/{entryID} – remove entry
//	GET    /admin/tenants/{tenantID}/extension-policies/scan      – match engine → per-extension status
//
// Match: a policy row applies to an observed extension when extension_id is
// equal AND (policy.browser = 'any' OR policy.browser = extension.browser).
//
// Pure policy plane. This ticket stores and reports decisions only — no
// enforcement and no removal drive agent behaviour. That is PAT-828 / PAT-829,
// which read this table once the GitHub-Non-Author-Review gate is satisfied.
//
// PAT-2089: every row carries source ('operator' | 'portal'). Rows written
// here are the operator's: an insert is 'operator', and an update stamps
// 'operator', so editing a customer's portal row adopts it. Only operator rows
// feed the signed App Control blocklist (dbGetExtensionBlocklist). The GET
// list reports each row's source and, on an App Control tenant, lists the
// customer's rows again as portal_suggestions for the operator to review.

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/softwaregov"
)

// ---------------------------------------------------------------------------
// Value sets
// ---------------------------------------------------------------------------

var extensionValidBrowsers = map[string]bool{
	"chrome": true, "edge": true, "firefox": true, "safari": true, "any": true,
}

var extensionValidPolicies = map[string]bool{
	"approved": true, "unapproved": true, "ignored": true,
}

// ---------------------------------------------------------------------------
// Response / request types
// ---------------------------------------------------------------------------

type extensionPolicyJSON struct {
	ID          int64   `json:"id"`
	Browser     string  `json:"browser"`
	ExtensionID string  `json:"extension_id"`
	Name        string  `json:"name"`
	Publisher   *string `json:"publisher"`
	WebstoreID  *string `json:"webstore_id"`
	Policy      string  `json:"policy"`
	ApprovedBy  string  `json:"approved_by"`
	Notes       string  `json:"notes"`
	// Source (PAT-2089) is who set the current decision: operator or portal.
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type extensionPoliciesGetResp struct {
	TenantID string                `json:"tenant_id"`
	Entries  []extensionPolicyJSON `json:"entries"`
	// AppControlEnabled mirrors tenants.app_control_enabled (PAT-2089).
	AppControlEnabled bool `json:"app_control_enabled"`
	// PortalSuggestions (PAT-2089) repeats the entries whose source is
	// 'portal' when App Control is on: the customer's own decisions, which
	// never feed the blocklist, for the operator to adopt or leave. Empty
	// when App Control is off, where no row feeds the blocklist at all.
	PortalSuggestions []extensionPolicyJSON `json:"portal_suggestions"`
}

type extensionPolicyAddReq struct {
	Browser     string  `json:"browser"`
	ExtensionID string  `json:"extension_id"`
	Name        string  `json:"name"`
	Publisher   *string `json:"publisher"`
	WebstoreID  *string `json:"webstore_id"`
	Policy      string  `json:"policy"`
	ApprovedBy  string  `json:"approved_by"`
	Notes       string  `json:"notes"`
}

type extensionPolicyUpdateReq struct {
	Policy string `json:"policy"`
	Notes  string `json:"notes"`
}

type extensionScanSummaryJSON struct {
	TotalFleetExtensions int `json:"total_fleet_extensions"`
	Approved             int `json:"approved"`
	Unapproved           int `json:"unapproved"`
	Ignored              int `json:"ignored"`
	Unreviewed           int `json:"unreviewed"`
}

type extensionScanItemJSON struct {
	Browser     string    `json:"browser"`
	ExtensionID string    `json:"extension_id"`
	Name        string    `json:"name"`
	RiskLevel   string    `json:"risk_level"`
	DeviceCount int       `json:"device_count"`
	LastSeen    time.Time `json:"last_seen"`
	Status      string    `json:"status"`
	EntryID     *int64    `json:"entry_id"`
}

type extensionScanResp struct {
	TenantID    string                   `json:"tenant_id"`
	GeneratedAt time.Time                `json:"generated_at"`
	Summary     extensionScanSummaryJSON `json:"summary"`
	Extensions  []extensionScanItemJSON  `json:"extensions"`
}

// ---------------------------------------------------------------------------
// GET /admin/tenants/{tenantID}/extension-policies
// ---------------------------------------------------------------------------

func TenantExtensionPoliciesGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "extension_policies_get")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		var appControl bool
		if err := pool.QueryRow(r.Context(),
			`SELECT app_control_enabled FROM tenants WHERE id = $1::uuid`, tenantID,
		).Scan(&appControl); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("tenant lookup failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		rows, err := pool.Query(r.Context(), `
			SELECT id, browser, extension_id, name, publisher, webstore_id,
			       policy, approved_by, notes, source, created_at, updated_at
			FROM tenant_extension_policies
			WHERE tenant_id = $1::uuid
			ORDER BY LOWER(name), browser, extension_id
		`, tenantID)
		if err != nil {
			logger.Error("extension policies query failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var entries []extensionPolicyJSON
		suggestions := []extensionPolicyJSON{}
		for rows.Next() {
			var e extensionPolicyJSON
			if err := rows.Scan(&e.ID, &e.Browser, &e.ExtensionID, &e.Name,
				&e.Publisher, &e.WebstoreID, &e.Policy, &e.ApprovedBy, &e.Notes,
				&e.Source, &e.CreatedAt, &e.UpdatedAt); err != nil {
				logger.Error("extension policy row scan failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			entries = append(entries, e)
			if appControl && e.Source == "portal" {
				suggestions = append(suggestions, e)
			}
		}
		if err := rows.Err(); err != nil {
			logger.Error("extension policy rows error", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if entries == nil {
			entries = []extensionPolicyJSON{}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(extensionPoliciesGetResp{
			TenantID:          tenantID,
			Entries:           entries,
			AppControlEnabled: appControl,
			PortalSuggestions: suggestions,
		})
	}
}

// ---------------------------------------------------------------------------
// POST /admin/tenants/{tenantID}/extension-policies
// ---------------------------------------------------------------------------

func TenantExtensionPolicyAddHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "extension_policy_add")

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
		var req extensionPolicyAddReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		if req.Browser == "" {
			req.Browser = "any"
		}
		if req.Policy == "" {
			req.Policy = "approved"
		}

		req.Browser = strings.ToLower(strings.TrimSpace(req.Browser))
		req.ExtensionID = strings.TrimSpace(req.ExtensionID)
		req.Name = strings.TrimSpace(req.Name)

		if req.ExtensionID == "" {
			http.Error(w, "extension_id is required", http.StatusBadRequest)
			return
		}
		if !extensionValidBrowsers[req.Browser] {
			http.Error(w, "browser must be one of: chrome, edge, firefox, safari, any", http.StatusBadRequest)
			return
		}
		if !extensionValidPolicies[req.Policy] {
			http.Error(w, "policy must be one of: approved, unapproved, ignored", http.StatusBadRequest)
			return
		}
		req.Publisher = normalizeOptionalString(req.Publisher)
		req.WebstoreID = normalizeOptionalString(req.WebstoreID)

		if err := ensureTenantExists(r, pool, tenantID); err != nil {
			writeTenantLookupError(w, logger, err)
			return
		}

		// PAT-2007 review: every writer of the tenant policy store takes the
		// tenant policy advisory lock first, so this serialises with the
		// customer portal's approval writes (portal_software_approvals.go).
		tx, err := pool.Begin(r.Context())
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback(r.Context()) //nolint:errcheck // no-op after Commit
		if err := lockMandatoryTenantPolicy(r.Context(), tx, tenantID); err != nil {
			logger.Error("policy lock failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		now := time.Now().UTC()
		var entryID int64
		err = tx.QueryRow(r.Context(), `
			INSERT INTO tenant_extension_policies
			    (tenant_id, browser, extension_id, name, publisher, webstore_id,
			     policy, approved_by, notes, source, created_at, updated_at)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, 'operator', $10, $10)
			RETURNING id
		`, tenantID, req.Browser, req.ExtensionID, req.Name, req.Publisher,
			req.WebstoreID, req.Policy, req.ApprovedBy, req.Notes, now,
		).Scan(&entryID)
		if err != nil {
			if strings.Contains(err.Error(), "unique") {
				http.Error(w, "policy already exists for this tenant/browser/extension", http.StatusConflict)
				return
			}
			logger.Error("extension policy insert failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		var episodeID int64
		if req.Policy == "unapproved" {
			episodeID, err = softwaregov.OpenEpisodeTx(r.Context(), tx, softwaregov.Mark{
				TenantID: tenantID, PolicyKind: softwaregov.TypeBrowserExtension, PolicyID: entryID,
				Source: softwaregov.SourceOperator, MarkedAt: now,
			})
			if err != nil {
				logger.Error("open unapproved episode failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}
		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if episodeID != 0 {
			raiseUnapprovedEpisodes(pool, tenantID, []int64{episodeID}, logger.With("tenant_id", tenantID))
		}
		logger.Info("extension policy added", "tenant_id", tenantID, "entry_id", entryID, "extension_id", req.ExtensionID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(extensionPolicyJSON{
			ID: entryID, Browser: req.Browser, ExtensionID: req.ExtensionID,
			Name: req.Name, Publisher: req.Publisher, WebstoreID: req.WebstoreID,
			Policy: req.Policy, ApprovedBy: req.ApprovedBy, Notes: req.Notes,
			Source: "operator", CreatedAt: now, UpdatedAt: now,
		})
	}
}

// ---------------------------------------------------------------------------
// PUT /admin/tenants/{tenantID}/extension-policies/{entryID}
// ---------------------------------------------------------------------------

func TenantExtensionPolicyUpdateHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "extension_policy_update")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		entryIDStr := strings.TrimSpace(chi.URLParam(r, "entryID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		entryID, err := parseInt64Param(entryIDStr)
		if err != nil {
			http.Error(w, "entryID must be an integer", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}
		var req extensionPolicyUpdateReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if !extensionValidPolicies[req.Policy] {
			http.Error(w, "policy must be one of: approved, unapproved, ignored", http.StatusBadRequest)
			return
		}

		// PAT-2007 review: take the tenant policy advisory lock first, as
		// every policy writer does, so this serialises with portal writes.
		tx, err := pool.Begin(r.Context())
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback(r.Context()) //nolint:errcheck // no-op after Commit
		if err := lockMandatoryTenantPolicy(r.Context(), tx, tenantID); err != nil {
			logger.Error("policy lock failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// PAT-2009: the previous policy, locked, so a transition into
		// unapproved raises the customer's unapproved software alert once.
		var oldPolicy string
		if err := tx.QueryRow(r.Context(), `
			SELECT policy FROM tenant_extension_policies WHERE id = $1 AND tenant_id = $2::uuid FOR UPDATE
		`, entryID, tenantID).Scan(&oldPolicy); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "entry not found", http.StatusNotFound)
				return
			}
			logger.Error("extension policy lookup failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		var updatedAt time.Time
		err = tx.QueryRow(r.Context(), `
			UPDATE tenant_extension_policies
			SET policy = $1, notes = $2, source = 'operator', updated_at = NOW()
			WHERE id = $3 AND tenant_id = $4::uuid
			RETURNING updated_at
		`, req.Policy, req.Notes, entryID, tenantID).Scan(&updatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "entry not found", http.StatusNotFound)
			return
		}
		if err != nil {
			logger.Error("extension policy update failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// PAT-2097: leaving Unapproved resolves the row's open and
		// acknowledged alerts in this transaction.
		if oldPolicy == "unapproved" && req.Policy != "unapproved" {
			if _, err := softwaregov.ResolvePolicyAlertsTx(r.Context(), tx, tenantID, softwaregov.TypeBrowserExtension, entryID, req.Policy,
				softwaregov.Actor{Kind: softwaregov.ActorOperator}); err != nil {
				logger.Error("resolve unapproved alerts failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}
		var episodeID int64
		if req.Policy == "unapproved" && oldPolicy != "unapproved" {
			episodeID, err = softwaregov.OpenEpisodeTx(r.Context(), tx, softwaregov.Mark{
				TenantID: tenantID, PolicyKind: softwaregov.TypeBrowserExtension, PolicyID: entryID,
				Source: softwaregov.SourceOperator, MarkedAt: updatedAt,
			})
			if err != nil {
				logger.Error("open unapproved episode failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}
		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if episodeID != 0 {
			raiseUnapprovedEpisodes(pool, tenantID, []int64{episodeID}, logger.With("tenant_id", tenantID))
		}
		logger.Info("extension policy updated", "tenant_id", tenantID, "entry_id", entryID)
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---------------------------------------------------------------------------
// DELETE /admin/tenants/{tenantID}/extension-policies/{entryID}
// ---------------------------------------------------------------------------

func TenantExtensionPolicyDeleteHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "extension_policy_delete")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		entryIDStr := strings.TrimSpace(chi.URLParam(r, "entryID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		entryID, err := parseInt64Param(entryIDStr)
		if err != nil {
			http.Error(w, "entryID must be an integer", http.StatusBadRequest)
			return
		}

		// PAT-2007 review: take the tenant policy advisory lock first, as
		// every policy writer does, so this serialises with portal writes.
		tx, err := pool.Begin(r.Context())
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback(r.Context()) //nolint:errcheck // no-op after Commit
		if err := lockMandatoryTenantPolicy(r.Context(), tx, tenantID); err != nil {
			logger.Error("policy lock failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		var deletedPolicy string
		err = tx.QueryRow(r.Context(), `
			DELETE FROM tenant_extension_policies WHERE id = $1 AND tenant_id = $2::uuid
			RETURNING policy
		`, entryID, tenantID).Scan(&deletedPolicy)
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "entry not found", http.StatusNotFound)
			return
		}
		if err != nil {
			logger.Error("extension policy delete failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// PAT-2097: deleting an Unapproved row resolves its alerts
		// (policy_removed) in this transaction.
		if deletedPolicy == "unapproved" {
			if _, err := softwaregov.ResolvePolicyAlertsTx(r.Context(), tx, tenantID, softwaregov.TypeBrowserExtension, entryID, "",
				softwaregov.Actor{Kind: softwaregov.ActorOperator}); err != nil {
				logger.Error("resolve unapproved alerts failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		logger.Info("extension policy removed", "tenant_id", tenantID, "entry_id", entryID)
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---------------------------------------------------------------------------
// GET /admin/tenants/{tenantID}/extension-policies/scan
// Match engine: join fleet extension inventory against tenant policy.
// ---------------------------------------------------------------------------

func TenantExtensionPolicyScanHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "extension_policy_scan")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		if err := ensureTenantExists(r, pool, tenantID); err != nil {
			writeTenantLookupError(w, logger, err)
			return
		}

		// Load the tenant's policy rows into memory for in-process matching.
		// A tenant's distinct extensions are typically well under a few hundred.
		type policyEntry struct {
			id      int64
			browser string
			policy  string
		}
		// policies keyed by extension_id → its matching rows. Browser scoping is
		// resolved per-observation below ('any' matches every browser).
		policiesByExt := make(map[string][]policyEntry)
		policyRows, err := pool.Query(r.Context(), `
			SELECT id, browser, extension_id, policy
			FROM tenant_extension_policies WHERE tenant_id = $1::uuid
		`, tenantID)
		if err != nil {
			logger.Error("extension policy fetch failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer policyRows.Close()
		for policyRows.Next() {
			var p policyEntry
			var extID string
			if err := policyRows.Scan(&p.id, &p.browser, &extID, &p.policy); err != nil {
				logger.Error("extension policy scan row failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			policiesByExt[extID] = append(policiesByExt[extID], p)
		}
		if err := policyRows.Err(); err != nil {
			logger.Error("extension policy rows error", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		policyRows.Close()

		// Distinct extensions across the fleet, aggregated per (browser,
		// extension_id). device_count / max(last_seen) come from a GROUP BY;
		// name and risk_level are the most-recently-seen values via a DISTINCT ON
		// join (Postgres has no COUNT(DISTINCT ...) OVER, so the two are split).
		fleetRows, err := pool.Query(r.Context(), `
			SELECT latest.browser, latest.extension_id, latest.name,
			       latest.risk_level, counts.device_count, counts.last_seen
			FROM (
				SELECT DISTINCT ON (dbe.browser, dbe.extension_id)
					dbe.browser, dbe.extension_id, dbe.name, dbe.risk_level
				FROM device_browser_extensions dbe
				JOIN devices d ON d.id = dbe.device_id
				WHERE d.tenant_id = $1::uuid
				ORDER BY dbe.browser, dbe.extension_id, dbe.last_seen DESC
			) latest
			JOIN (
				SELECT dbe.browser, dbe.extension_id,
					COUNT(DISTINCT dbe.device_id) AS device_count,
					MAX(dbe.last_seen) AS last_seen
				FROM device_browser_extensions dbe
				JOIN devices d ON d.id = dbe.device_id
				WHERE d.tenant_id = $1::uuid
				GROUP BY dbe.browser, dbe.extension_id
			) counts
				ON counts.browser = latest.browser
				AND counts.extension_id = latest.extension_id
			ORDER BY LOWER(latest.name), latest.browser, latest.extension_id
		`, tenantID)
		if err != nil {
			logger.Error("fleet extensions fetch failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer fleetRows.Close()

		var items []extensionScanItemJSON
		var summ extensionScanSummaryJSON
		for fleetRows.Next() {
			var browser, extID, name, risk string
			var deviceCount int
			var lastSeen time.Time
			if err := fleetRows.Scan(&browser, &extID, &name, &risk, &deviceCount, &lastSeen); err != nil {
				logger.Error("fleet extension row scan failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			summ.TotalFleetExtensions++

			status := "unreviewed"
			var entryID *int64
			// Match: extension_id equal AND (policy browser 'any' or exact).
			// A browser-specific row wins over an 'any' row for the same ext.
			for _, p := range policiesByExt[extID] {
				if p.browser != "any" && p.browser != browser {
					continue
				}
				matchedID := p.id
				status = p.policy
				entryID = &matchedID
				if p.browser == browser {
					break
				}
			}

			switch status {
			case "approved":
				summ.Approved++
			case "unapproved":
				summ.Unapproved++
			case "ignored":
				summ.Ignored++
			default:
				summ.Unreviewed++
			}

			items = append(items, extensionScanItemJSON{
				Browser: browser, ExtensionID: extID, Name: name,
				RiskLevel: risk, DeviceCount: deviceCount, LastSeen: lastSeen,
				Status: status, EntryID: entryID,
			})
		}
		if err := fleetRows.Err(); err != nil {
			logger.Error("fleet extension rows error", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if items == nil {
			items = []extensionScanItemJSON{}
		}

		logger.Info("extension policy scan complete", "tenant_id", tenantID, "total", summ.TotalFleetExtensions)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(extensionScanResp{
			TenantID:    tenantID,
			GeneratedAt: time.Now().UTC(),
			Summary:     summ,
			Extensions:  items,
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// normalizeOptionalString trims a nullable string field and collapses an
// empty result back to nil, so blank publisher/webstore_id values persist as
// SQL NULL rather than "".
func normalizeOptionalString(s *string) *string {
	if s == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*s)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

// errTenantNotFound is a sentinel returned by ensureTenantExists so callers can
// map it to a 404 without leaking DB details.
var errTenantNotFound = errTenant("tenant not found")

type errTenant string

func (e errTenant) Error() string { return string(e) }

// ensureTenantExists reports nil if the tenant row exists, errTenantNotFound if
// it does not, or the raw DB error otherwise.
func ensureTenantExists(r *http.Request, pool *pgxpool.Pool, tenantID string) error {
	var exists bool
	if err := pool.QueryRow(r.Context(),
		`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid)`, tenantID,
	).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return errTenantNotFound
	}
	return nil
}

// writeTenantLookupError renders the appropriate HTTP status for an
// ensureTenantExists error.
func writeTenantLookupError(w http.ResponseWriter, logger *slog.Logger, err error) {
	if err == errTenantNotFound {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	}
	logger.Error("tenant existence check failed", "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}
