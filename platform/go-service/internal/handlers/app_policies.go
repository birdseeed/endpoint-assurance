package handlers

// CRUD handlers for tenant_app_policies — the per-tenant app-policy store
// introduced by PAT-470. Written by the dashboard (D1/PAT-474), read by the
// posture endpoint (GET /v1/posture) to populate app_policy.apps + app_policy.drift.
//
// Routes (all on the internal admin listener):
//   GET    /admin/tenants/{tenantID}/app-policies         — list policies
//   PUT    /admin/tenants/{tenantID}/app-policies         — upsert a policy entry
//   DELETE /admin/tenants/{tenantID}/app-policies/{entryID} — remove a policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/agentidentity"
	"patched.im/api/internal/notify"
	"patched.im/api/internal/softwaregov"
	"patched.im/api/internal/wingetid"
)

// appPolicyRow mirrors the tenant_app_policies row for JSON serialisation.
type appPolicyRow struct {
	ID              int64   `json:"id"`
	TeamID          *string `json:"team_id"`
	BundleID        *string `json:"bundle_id"`
	WingetID        *string `json:"winget_id"`
	Name            *string `json:"name"`
	Platform        string  `json:"platform"`
	Policy          string  `json:"policy"`
	EnforcementTier string  `json:"enforcement_tier"`
	Notes           string  `json:"notes"`
	MinVersion      *string `json:"min_version"`
	// Source (PAT-2091) is who set the row: operator (this API) or portal
	// (PUT /v1/portal/software-approvals).
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TenantAppPoliciesGetHandler lists all tenant_app_policies rows for a tenant.
//
// GET /admin/tenants/{tenantID}/app-policies
// 200 { "policies": [...] } | 400 bad tenantID | 404 unknown tenant
func TenantAppPoliciesGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "app_policies_get")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		// Verify tenant exists and is not revoked.
		var exists bool
		if err := pool.QueryRow(r.Context(), `
			SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)
		`, tenantID).Scan(&exists); err != nil || !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		rows, err := pool.Query(r.Context(), `
			SELECT id, team_id, bundle_id, winget_id, name, platform, policy,
			       enforcement_tier, notes, min_version, source, created_at, updated_at
			FROM tenant_app_policies
			WHERE tenant_id = $1::uuid
			ORDER BY policy, lower(coalesce(name, winget_id, bundle_id, team_id))
		`, tenantID)
		if err != nil {
			logger.Error("query app policies", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var policies []appPolicyRow
		for rows.Next() {
			var p appPolicyRow
			if err := rows.Scan(
				&p.ID, &p.TeamID, &p.BundleID, &p.WingetID, &p.Name, &p.Platform,
				&p.Policy, &p.EnforcementTier, &p.Notes, &p.MinVersion, &p.Source, &p.CreatedAt, &p.UpdatedAt,
			); err != nil {
				logger.Error("scan app policy row", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			policies = append(policies, p)
		}
		if err := rows.Err(); err != nil {
			logger.Error("rows error", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if policies == nil {
			policies = []appPolicyRow{} // never null in JSON
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"policies": policies})
	}
}

// appPolicyPutResp is the PUT response: the stored row plus, when a
// protected product (PAT-1801) was set unapproved, the same warning fields
// the customer portal returns (PAT-2088).
type appPolicyPutResp struct {
	appPolicyRow
	ProtectedWarning bool                    `json:"protected_warning"`
	Protected        *approvalProtectedMatch `json:"protected"`
}

// appPolicyUpsertRequest is the body accepted by TenantAppPoliciesPutHandler.
type appPolicyUpsertRequest struct {
	TeamID          *string `json:"team_id"`
	BundleID        *string `json:"bundle_id"`
	WingetID        *string `json:"winget_id"`
	Name            *string `json:"name"`
	Platform        string  `json:"platform"`         // macos|windows|any; defaults to "any"
	Policy          string  `json:"policy"`           // mandatory|approved|unapproved|unmanaged
	EnforcementTier string  `json:"enforcement_tier"` // report|report_deploy|app_management|patch|managed; defaults to "report_deploy". Legacy report/app_management are accepted and rewritten to canonical on write — see legacyTierToCanonical.
	Notes           string  `json:"notes"`
	MinVersion      *string `json:"min_version"`
	// PublisherKey exists only so a caller that sends one is refused
	// (PAT-2121): the key is derived server-side from the tenant's own
	// evidence, never accepted. encoding/json matches field names
	// case-insensitively, so any spelling of the key lands here too.
	PublisherKey json.RawMessage `json:"publisher_key"`
}

// legacyTierToCanonical maps the deprecated admin-API enforcement_tier
// spellings to their canonical agent-config equivalents (PAT-1121 step 3 /
// PAT-1250). "report" and "report_deploy" name the same rung; "app_management"
// and "patch" name the same rung. "managed" has always been the shared name
// across both vocabularies, so it needs no entry here.
//
// The DB CHECK constraint (0099_widen_enforcement_tier_check.sql) still
// accepts all five spellings on input and is deliberately NOT narrowed by
// this ticket — legacy acceptance stays in place until every endpoint in the
// estate is confirmed on an agent that emits canonical values (a separate,
// future step). This map is where the server chooses which of the two
// spellings it actually stores and serves back.
var legacyTierToCanonical = map[string]string{
	"report":         "report_deploy",
	"app_management": "patch",
}

// canonicalizeTier rewrites an already-validated enforcement_tier value to
// its canonical spelling. Values with no legacy mapping (already canonical,
// or "managed") pass through unchanged.
func canonicalizeTier(tier string) string {
	if canon, ok := legacyTierToCanonical[tier]; ok {
		return canon
	}
	return tier
}

// TenantAppPoliciesPutHandler upserts a policy entry. Conflicts on the stable
// identity unique index (team_id/bundle_id/name/platform) are resolved by
// updating policy, enforcement_tier, notes, and updated_at.
//
// PUT /admin/tenants/{tenantID}/app-policies
// 200 appPolicyRow | 400 bad input | 404 unknown tenant | 409 constraint violation
func TenantAppPoliciesPutHandler(pool *pgxpool.Pool, notifier *notify.Notifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "app_policies_put")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		var req appPolicyUpsertRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		if req.PublisherKey != nil {
			http.Error(w, "publisher_key is derived by the server from inventory evidence and cannot be set", http.StatusBadRequest)
			return
		}

		// At least one identity field must be set.
		if req.TeamID == nil && req.BundleID == nil && req.WingetID == nil && req.Name == nil {
			http.Error(w, "at least one of team_id, bundle_id, winget_id, name must be provided", http.StatusBadRequest)
			return
		}

		// Apply defaults. The enforcement_tier default is the canonical
		// spelling directly (PAT-1250) — new tenants with no explicit tier
		// get "report_deploy", never the legacy "report". Sourced from
		// agentidentity.DefaultEnforcementTier (PAT-1318) so this handler and
		// the Patched Agent auto-approval seeder share one constant instead
		// of two copies of the same literal drifting apart.
		if req.Platform == "" {
			req.Platform = "any"
		}
		if req.EnforcementTier == "" {
			req.EnforcementTier = agentidentity.DefaultEnforcementTier
		}

		// Validate enum values. Both vocabularies are still accepted on
		// input (0099_widen_enforcement_tier_check.sql widened the DB
		// constraint the same way) — legacy acceptance is not removed by
		// this ticket, only what gets stored/emitted changes.
		validPolicies := map[string]bool{"mandatory": true, "approved": true, "unapproved": true, "unmanaged": true}
		if !validPolicies[req.Policy] {
			http.Error(w, "policy must be mandatory|approved|unapproved|unmanaged", http.StatusBadRequest)
			return
		}
		validPlatforms := map[string]bool{"macos": true, "windows": true, "any": true}
		if !validPlatforms[req.Platform] {
			http.Error(w, "platform must be macos|windows|any", http.StatusBadRequest)
			return
		}
		if req.WingetID != nil {
			canonical := strings.ToLower(strings.TrimSpace(*req.WingetID))
			if req.Platform != "windows" || !wingetid.Valid(*req.WingetID) {
				http.Error(w, "winget_id requires a platform=windows exact package id", http.StatusBadRequest)
				return
			}
			req.WingetID = &canonical
		}
		validTiers := map[string]bool{"report": true, "report_deploy": true, "app_management": true, "patch": true, "managed": true}
		if !validTiers[req.EnforcementTier] {
			http.Error(w, "enforcement_tier must be report|report_deploy|app_management|patch|managed", http.StatusBadRequest)
			return
		}

		// PAT-1250 (PAT-1121 step 3): rewrite a legacy input to its
		// canonical spelling before it ever reaches the INSERT/UPDATE below,
		// so the row is stored — and the response, via RETURNING, echoed —
		// as canonical regardless of which vocabulary the caller used.
		req.EnforcementTier = canonicalizeTier(req.EnforcementTier)

		// Verify tenant exists and is not revoked.
		var exists bool
		if err := pool.QueryRow(r.Context(), `
			SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)
		`, tenantID).Scan(&exists); err != nil || !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		// Snapshot the pre-upsert policy and upsert inside one transaction
		// (PAT-820), locking any existing matching row with FOR UPDATE so two
		// concurrent PUTs for the same identity can't both observe the
		// pre-restriction state and each fire an alert. No prior row means
		// oldPolicy stays "" (a residual race remains only for two concurrent
		// *first-ever* writes to a brand-new identity — nothing exists yet to
		// lock — which is an acceptable, rare edge case here).
		tx, err := pool.Begin(r.Context())
		if err != nil {
			logger.Error("begin tx failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback(r.Context()) //nolint:errcheck // no-op after Commit
		if err := lockMandatoryTenantPolicy(r.Context(), tx, tenantID); err != nil {
			logger.Error("lock mandatory policy authority failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// PAT-1801 / PAT-2088: protected software (EDR, MDM agent, backup
		// agent, Patched's own collector) set to unapproved goes through the
		// one rule the customer portal uses too (checkProtectedUnapprovedApp,
		// protected_unapproved.go): warn and allow, refusing only where the
		// Unapproved would feed enforcement for this tenant. No application
		// Unapproved does today (the reasoning is in that file), so the write
		// succeeds and the response carries protected_warning. It runs on
		// every unapproved write, an idempotent re-save included, and inside
		// this transaction, so a protection added concurrently is either seen
		// here or committed after this write.
		var protected protectedUnapprovedVerdict
		if req.Policy == "unapproved" {
			protected, err = checkProtectedUnapprovedApp(r.Context(), tx, tenantID, appProtectionIdentity{
				Platform: req.Platform, TeamID: req.TeamID, BundleID: req.BundleID,
				WingetID: req.WingetID, Name: req.Name,
			})
			if err != nil {
				logger.Error("protected software check failed", "err", err, "tenant_id", tenantID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if protected.Refuse {
				http.Error(w, fmt.Sprintf(
					"cannot mark %s (category: %s) as unapproved — protected software",
					protected.Match.ProductName, protected.Match.Category,
				), http.StatusConflict)
				return
			}
		}

		var oldPolicy string
		if err := tx.QueryRow(r.Context(), `
			SELECT policy FROM tenant_app_policies
			WHERE tenant_id = $1::uuid
			  AND COALESCE(team_id, '') = COALESCE($2, '')
			  AND COALESCE(bundle_id, '') = COALESCE($3, '')
			  AND COALESCE(winget_id, '') = COALESCE($4, '')
			  AND COALESCE(lower(name), '') = COALESCE(lower($5), '')
			  AND platform = $6
			FOR UPDATE
		`, tenantID, req.TeamID, req.BundleID, req.WingetID, req.Name, req.Platform).Scan(&oldPolicy); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			logger.Error("pre-upsert policy lookup failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// PAT-2121: an approved Windows row records the Authenticode
		// publisher key its product's own evidence agrees on (bundle_id, or
		// winget_id, is the identifier). Every other write stores NULL.
		identifier := ""
		switch {
		case req.BundleID != nil:
			identifier = *req.BundleID
		case req.WingetID != nil:
			identifier = *req.WingetID
		}
		publisherKey, err := approvalPublisherKey(r.Context(), tx, tenantID, req.Platform, identifier, req.Policy)
		if err != nil {
			logger.Error("derive publisher key failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		var p appPolicyRow
		if err := tx.QueryRow(r.Context(), `
			INSERT INTO tenant_app_policies
			    (tenant_id, team_id, bundle_id, winget_id, name, platform, policy, enforcement_tier, notes, min_version,
			     publisher_key, source)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'operator')
			ON CONFLICT (tenant_id,
			    COALESCE(team_id, ''),
			    COALESCE(bundle_id, ''),
			    COALESCE(winget_id, ''),
			    COALESCE(lower(name), ''),
			    platform)
			DO UPDATE SET
			    policy           = EXCLUDED.policy,
			    enforcement_tier = EXCLUDED.enforcement_tier,
			    notes            = EXCLUDED.notes,
			    min_version      = EXCLUDED.min_version,
			    publisher_key    = EXCLUDED.publisher_key,
			    source           = 'operator',
			    updated_at       = now()
			RETURNING id, team_id, bundle_id, winget_id, name, platform, policy,
			          enforcement_tier, notes, min_version, source, created_at, updated_at
		`, tenantID, req.TeamID, req.BundleID, req.WingetID, req.Name,
			req.Platform, req.Policy, req.EnforcementTier, req.Notes, req.MinVersion, publisherKey,
		).Scan(
			&p.ID, &p.TeamID, &p.BundleID, &p.WingetID, &p.Name, &p.Platform,
			&p.Policy, &p.EnforcementTier, &p.Notes, &p.MinVersion, &p.Source, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "tenant_app_policies_tenant_identity_uniq" {
				// Migration 0110 deliberately retains the deployed binary's
				// four-field arbiter during mixed-version rollout. A second
				// Winget-only identity shares that legacy tuple; refuse it
				// explicitly rather than returning 500 or letting old writers
				// update the wrong reviewed policy.
				http.Error(w, "distinct Winget policy conflicts with the temporary mixed-version policy identity", http.StatusConflict)
				return
			}
			logger.Error("upsert app policy", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Removing mandatory status cancels only work that has not started.
		// received/installing/terminal intent is retained unchanged so policy
		// edits can never become an implicit uninstall or erase provenance.
		if oldPolicy == "mandatory" && p.Policy != "mandatory" {
			if err := cancelMandatoryPolicyIntentsTx(r.Context(), tx, tenantID, p.ID, "mandatory policy changed to "+p.Policy); err != nil {
				logger.Error("cancel mandatory intents", "err", err, "tenant_id", tenantID, "policy_id", p.ID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}

		// PAT-2097: leaving Unapproved resolves the policy row's open and
		// acknowledged alerts in this transaction.
		if oldPolicy == "unapproved" && p.Policy != "unapproved" {
			if _, err := softwaregov.ResolvePolicyAlertsTx(r.Context(), tx, tenantID, softwaregov.TypeApplication, p.ID, p.Policy,
				softwaregov.Actor{Kind: softwaregov.ActorOperator}); err != nil {
				logger.Error("resolve unapproved alerts failed", "err", err, "tenant_id", tenantID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}

		// PAT-2009: the customer's unapproved software alert, on the same
		// transition. The episode commits with the policy; the alert goes to
		// the tenant (webhook and contact email), not to Patched staff, after
		// the commit. The staff Slack notice below is separate.
		var episodeID int64
		if p.Policy == "unapproved" && oldPolicy != "unapproved" {
			episodeID, err = softwaregov.OpenEpisodeTx(r.Context(), tx, softwaregov.Mark{
				TenantID: tenantID, PolicyKind: softwaregov.TypeApplication, PolicyID: p.ID,
				Source: softwaregov.SourceOperator, MarkedAt: p.UpdatedAt,
			})
			if err != nil {
				logger.Error("open unapproved episode failed", "err", err, "tenant_id", tenantID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit tx failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if episodeID != 0 {
			raiseUnapprovedEpisodes(pool, tenantID, []int64{episodeID}, logger.With("tenant_id", tenantID))
		}

		// PAT-820: alert only on the first transition into "unapproved" — an
		// idempotent re-save of an already-unapproved entry must not spam Slack.
		if notifier.Enabled() && p.Policy == "unapproved" && oldPolicy != "unapproved" {
			label := ""
			switch {
			case p.Name != nil:
				label = *p.Name
			case p.BundleID != nil:
				label = *p.BundleID
			case p.WingetID != nil:
				label = *p.WingetID
			case p.TeamID != nil:
				label = *p.TeamID
			}
			notifier.Dispatch(r.Context(), notify.Event{
				TenantID:     tenantID,
				Kind:         notify.KindAppLaunchRestricted,
				Label:        label,
				Platform:     p.Platform,
				SourceAction: "app_policy_unapproved",
				Link:         notify.CatalogueLink(tenantID),
				Timestamp:    time.Now().UTC(),
			})
		}

		logger.Info("app policy upserted",
			"tenant_id", tenantID,
			"policy_id", p.ID,
			"policy", p.Policy,
		)
		resp := appPolicyPutResp{appPolicyRow: p}
		if protected.Warn() {
			m := protected.Match
			resp.ProtectedWarning = true
			resp.Protected = &approvalProtectedMatch{Category: m.Category, Vendor: m.Vendor, ProductName: m.ProductName}
			logger.Warn("protected software marked unapproved", "tenant_id", tenantID, "policy_id", p.ID,
				"category", m.Category, "product", m.ProductName)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// TenantAppPoliciesDeleteHandler removes a single policy entry by row ID.
//
// DELETE /admin/tenants/{tenantID}/app-policies/{entryID}
// 204 | 400 bad IDs | 404 not found
func TenantAppPoliciesDeleteHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "app_policies_delete")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		entryID := strings.TrimSpace(chi.URLParam(r, "entryID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		if entryID == "" {
			http.Error(w, "entryID required", http.StatusBadRequest)
			return
		}

		tx, err := pool.BeginTx(r.Context(), pgx.TxOptions{})
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()
		if err := lockMandatoryTenantPolicy(r.Context(), tx, tenantID); err != nil {
			logger.Error("lock mandatory policy authority failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		var deletedID int64
		var deletedPolicy string
		if err := tx.QueryRow(r.Context(), `
			SELECT id,policy FROM tenant_app_policies
			WHERE id = $1 AND tenant_id = $2::uuid FOR UPDATE
		`, entryID, tenantID).Scan(&deletedID, &deletedPolicy); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "policy entry not found", http.StatusNotFound)
				return
			}
			logger.Error("delete app policy", "err", err, "entry_id", entryID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if deletedPolicy == "mandatory" {
			if err := cancelMandatoryPolicyIntentsTx(r.Context(), tx, tenantID, deletedID, "mandatory policy deleted"); err != nil {
				logger.Error("cancel mandatory intents", "err", err, "tenant_id", tenantID, "policy_id", deletedID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}
		// PAT-2097: deleting an Unapproved row resolves its alerts
		// (policy_removed) in this transaction.
		if deletedPolicy == "unapproved" {
			if _, err := softwaregov.ResolvePolicyAlertsTx(r.Context(), tx, tenantID, softwaregov.TypeApplication, deletedID, "",
				softwaregov.Actor{Kind: softwaregov.ActorOperator}); err != nil {
				logger.Error("resolve unapproved alerts failed", "err", err, "tenant_id", tenantID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM tenant_app_policies WHERE id=$1 AND tenant_id=$2::uuid`, deletedID, tenantID); err != nil {
			logger.Error("delete app policy", "err", err, "entry_id", entryID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("app policy deleted", "tenant_id", tenantID, "entry_id", deletedID)
		w.WriteHeader(http.StatusNoContent)
	}
}
