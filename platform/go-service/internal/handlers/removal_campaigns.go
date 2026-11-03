package handlers

// PAT-1598: authorised removal — platform data model and admin API surface.
//
// ── What this file is not ─────────────────────────────────────────────────
// There is no agent-facing route here, and nothing in this file is reachable
// from one. An authorised campaign is a governance record: it says a named
// person authorised removing a named product under a named contract clause,
// against a preview of what that would affect. Acting on it happens in the
// customer's own management platform (Intune, Jamf, Patch My PC, Robopack or
// a ticket), which is the product boundary in root AGENTS.md — evidence
// before actuation.
//
// PAT-1598's own gate is that no removal ships to a customer before the MSA
// contract language exists (PAT-112, not delivered). A capability flag would
// hold that gate only while nobody flipped it. Having no delivery path at
// all holds it whatever any flag says, which is why this slice stops here
// and the follow-up that wires delivery is also where the managed-tier gate
// and fail-closed capability flags get designed.
//
// This is also not the legacy execution path. device_removals_agent.go and
// allowlist_agent.go serve the quarantined pre-vNext uninstall mechanism
// behind legacyExecutionEnabled; root AGENTS.md says preserve it, do not
// extend it. Nothing here reads or writes tenant_allowlists.
// marked_for_uninstall or device_removals, and the legacy gate is untouched.
//
// ── Routes (internal listener, ADMIN_API_TOKEN) ───────────────────────────
//
//	POST /admin/tenants/{tenantID}/removal-campaigns
//	    Create a draft campaign against one product. Refused outright if the
//	    product is protected for this tenant (PAT-1801).
//	GET  /admin/tenants/{tenantID}/removal-campaigns
//	    List campaigns for a tenant, newest first.
//	GET  /admin/tenants/{tenantID}/removal-campaigns/{campaignID}
//	    One campaign with its most recent dry run (including a live
//	    staleness verdict) and its authorisation, if any.
//	POST /admin/tenants/{tenantID}/removal-campaigns/{campaignID}/dry-run
//	    Compute a preview over current inventory and append it as evidence.
//	    Re-runnable at any time; each run appends, none overwrite.
//	POST /admin/tenants/{tenantID}/removal-campaigns/{campaignID}/authorize
//	    Record the authorisation. Every gate is here, and every one of them
//	    is a refusal, not a warning: see RemovalCampaignAuthorizeHandler.
//	POST /admin/tenants/{tenantID}/removal-campaigns/{campaignID}/cancel
//	    Abandon a draft or previewed campaign.
//
// ── State machine ─────────────────────────────────────────────────────────
//
//	draft ──dry-run──> dry_run ──authorize──> authorized   (terminal)
//	  └──────────────cancel──────┴──> cancelled            (terminal)
//
// authorize is reachable only from dry_run, because an authorisation must
// cite a preview and there is none in draft. There is no transition out of
// authorized: the authorisation record is append-only and would stand
// whatever this row said, and while no delivery path exists there is nothing
// queued to revoke. Revocation belongs with delivery, in the follow-up.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/protectedsoftware"
	"patched.im/api/internal/removal"
)

var removalCampaignValidPlatforms = map[string]bool{"macos": true, "windows": true, "any": true}

type removalCampaignRow struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	TeamID          *string    `json:"team_id"`
	BundleID        *string    `json:"bundle_id"`
	Name            *string    `json:"name"`
	Platform        string     `json:"platform"`
	PolicyID        *int64     `json:"policy_id"`
	Status          string     `json:"status"`
	Reason          string     `json:"reason"`
	CreatedBy       string     `json:"created_by"`
	CreatedAt       time.Time  `json:"created_at"`
	StatusChangedAt time.Time  `json:"status_changed_at"`
	CancelledBy     *string    `json:"cancelled_by"`
	CancelledReason *string    `json:"cancelled_reason"`
	CancelledAt     *time.Time `json:"cancelled_at"`
}

func (c removalCampaignRow) target() removal.Target {
	return removal.Target{
		TeamID:   c.TeamID,
		BundleID: c.BundleID,
		Name:     c.Name,
		Platform: c.Platform,
	}
}

const removalCampaignColumns = `
	id::text, tenant_id::text, team_id, bundle_id, name, platform, policy_id, status,
	reason, created_by, created_at, status_changed_at, cancelled_by, cancelled_reason, cancelled_at
`

func scanRemovalCampaign(row pgx.Row) (removalCampaignRow, error) {
	var c removalCampaignRow
	err := row.Scan(&c.ID, &c.TenantID, &c.TeamID, &c.BundleID, &c.Name, &c.Platform, &c.PolicyID,
		&c.Status, &c.Reason, &c.CreatedBy, &c.CreatedAt, &c.StatusChangedAt,
		&c.CancelledBy, &c.CancelledReason, &c.CancelledAt)
	return c, err
}

// ---------------------------------------------------------------------------
// POST /admin/tenants/{tenantID}/removal-campaigns
// ---------------------------------------------------------------------------

type removalCampaignCreateReq struct {
	TeamID    *string `json:"team_id"`
	BundleID  *string `json:"bundle_id"`
	Name      *string `json:"name"`
	Platform  string  `json:"platform"`
	PolicyID  *int64  `json:"policy_id"`
	Reason    string  `json:"reason"`
	CreatedBy string  `json:"created_by"`
}

// RemovalCampaignCreateHandler serves POST /admin/tenants/{tenantID}/removal-campaigns.
//
// The protected-software check runs here as well as at authorisation. Not
// redundancy for its own sake: refusing at creation means a campaign against
// the customer's EDR never exists to be argued about, while the
// authorisation-time check catches a protection added after the campaign was
// drafted. Only the second is load-bearing for safety, and it is the one
// that runs inside the authorising transaction.
//
// 201 removalCampaignRow | 400 bad input | 404 unknown tenant or policy |
// 409 protected product
func RemovalCampaignCreateHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "removal_campaign_create")

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
		var req removalCampaignCreateReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		req.TeamID = trimmedOrNil(req.TeamID)
		req.BundleID = trimmedOrNil(req.BundleID)
		req.Name = trimmedOrNil(req.Name)
		req.CreatedBy = strings.TrimSpace(req.CreatedBy)
		req.Platform = strings.TrimSpace(strings.ToLower(req.Platform))
		if req.Platform == "" {
			req.Platform = "any"
		}
		if !removalCampaignValidPlatforms[req.Platform] {
			http.Error(w, "platform must be one of: macos, windows, any", http.StatusBadRequest)
			return
		}
		if req.TeamID == nil && req.BundleID == nil && req.Name == nil {
			http.Error(w, "at least one of team_id, bundle_id, name must be provided", http.StatusBadRequest)
			return
		}
		if req.CreatedBy == "" {
			http.Error(w, "created_by is required", http.StatusBadRequest)
			return
		}

		var tenantExists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`, tenantID,
		).Scan(&tenantExists); err != nil || !tenantExists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		if req.PolicyID != nil {
			var policySource string
			if err := pool.QueryRow(r.Context(), `
				SELECT source FROM tenant_app_policies WHERE id = $1 AND tenant_id = $2::uuid
			`, *req.PolicyID, tenantID).Scan(&policySource); err != nil {
				if !errors.Is(err, pgx.ErrNoRows) {
					logger.Error("policy lookup failed", "err", err, "tenant_id", tenantID)
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
				http.Error(w, "policy_id does not reference a policy belonging to this tenant", http.StatusNotFound)
				return
			}
			if policySource != "operator" {
				http.Error(w, portalPolicyAdoptionMessage, http.StatusConflict)
				return
			}
		}

		match, err := protectedsoftware.Check(r.Context(), pool, tenantID, protectedsoftware.Identity{
			TeamID:      req.TeamID,
			BundleID:    req.BundleID,
			ProcessName: req.Name,
		})
		if err != nil {
			logger.Error("protected software check failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if match != nil {
			http.Error(w, protectedRemovalMessage(match), http.StatusConflict)
			return
		}

		c, err := scanRemovalCampaign(pool.QueryRow(r.Context(), `
			INSERT INTO removal_campaigns (tenant_id, team_id, bundle_id, name, platform, policy_id, reason, created_by)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)
			RETURNING `+removalCampaignColumns,
			tenantID, req.TeamID, req.BundleID, req.Name, req.Platform, req.PolicyID, req.Reason, req.CreatedBy))
		if err != nil {
			logger.Error("removal campaign insert failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("removal campaign created", "tenant_id", tenantID, "campaign_id", c.ID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(c)
	}
}

// protectedRemovalMessage is the single wording for every refusal caused by
// the protected list, so the create and authorise paths cannot drift into
// saying different things about the same rule.
func protectedRemovalMessage(m *protectedsoftware.Match) string {
	scope := "a protection this tenant added"
	if m.IsBaseline {
		scope = "the shared baseline"
	}
	return fmt.Sprintf(
		"%s (category: %s) is protected software per %s and can never be targeted for removal",
		m.ProductName, m.Category, scope)
}

const portalPolicyAdoptionMessage = "cited policy was set through the portal; an operator must adopt it before it can be used for a removal campaign"

func trimmedOrNil(s *string) *string {
	if s == nil {
		return nil
	}
	t := strings.TrimSpace(*s)
	if t == "" {
		return nil
	}
	return &t
}

// ---------------------------------------------------------------------------
// GET /admin/tenants/{tenantID}/removal-campaigns
// ---------------------------------------------------------------------------

type removalCampaignListResp struct {
	TenantID  string               `json:"tenant_id"`
	Campaigns []removalCampaignRow `json:"campaigns"`
}

// RemovalCampaignListHandler serves GET /admin/tenants/{tenantID}/removal-campaigns.
func RemovalCampaignListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "removal_campaign_list")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		rows, err := pool.Query(r.Context(), `
			SELECT `+removalCampaignColumns+`
			FROM removal_campaigns WHERE tenant_id = $1::uuid
			ORDER BY created_at DESC, id
		`, tenantID)
		if err != nil {
			logger.Error("removal campaign list query failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		campaigns := []removalCampaignRow{}
		for rows.Next() {
			c, err := scanRemovalCampaign(rows)
			if err != nil {
				logger.Error("removal campaign scan failed", "err", err, "tenant_id", tenantID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			campaigns = append(campaigns, c)
		}
		if err := rows.Err(); err != nil {
			logger.Error("removal campaign rows error", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(removalCampaignListResp{TenantID: tenantID, Campaigns: campaigns})
	}
}

// ---------------------------------------------------------------------------
// Dry-run storage and read-back
// ---------------------------------------------------------------------------

// removalDryRunJSON is a stored dry run as returned to a caller. Stale and
// StalenessReasons are computed at read time against the tenant's current
// inventory watermark, never stored: a stored "fresh" flag would itself go
// stale, which is the whole failure this endpoint exists to prevent.
type removalDryRunJSON struct {
	ID                          string          `json:"id"`
	CampaignID                  string          `json:"campaign_id"`
	ComputedAt                  time.Time       `json:"computed_at"`
	ComputedBy                  string          `json:"computed_by"`
	DeviceCount                 int             `json:"device_count"`
	VersionSpread               json.RawMessage `json:"version_spread"`
	Devices                     json.RawMessage `json:"devices"`
	EvidenceBasis               string          `json:"evidence_basis"`
	DevicesWithoutAppInventory  int             `json:"devices_without_app_inventory"`
	Artefacts                   json.RawMessage `json:"artefacts"`
	ArtefactBasis               string          `json:"artefact_basis"`
	ArtefactEnumerationComplete bool            `json:"artefact_enumeration_complete"`
	Residue                     json.RawMessage `json:"residue"`
	ProtectedMatch              json.RawMessage `json:"protected_match"`
	ExcludedDeviceCount         int             `json:"excluded_device_count"`
	InventoryWatermark          *time.Time      `json:"inventory_watermark"`
	Stale                       bool            `json:"stale"`
	StalenessReasons            []string        `json:"staleness_reasons"`
}

const removalDryRunColumns = `
	id::text, campaign_id::text, computed_at, computed_by, device_count, version_spread, devices,
	evidence_basis, devices_without_app_inventory, artefacts, artefact_basis,
	artefact_enumeration_complete, residue, protected_match, excluded_device_count, inventory_watermark
`

func scanRemovalDryRun(row pgx.Row) (removalDryRunJSON, error) {
	var d removalDryRunJSON
	var versionSpread, devices, artefacts, residue, protectedMatch []byte
	err := row.Scan(&d.ID, &d.CampaignID, &d.ComputedAt, &d.ComputedBy, &d.DeviceCount,
		&versionSpread, &devices, &d.EvidenceBasis, &d.DevicesWithoutAppInventory,
		&artefacts, &d.ArtefactBasis, &d.ArtefactEnumerationComplete, &residue,
		&protectedMatch, &d.ExcludedDeviceCount, &d.InventoryWatermark)
	if err != nil {
		return d, err
	}
	d.VersionSpread = json.RawMessage(versionSpread)
	d.Devices = json.RawMessage(devices)
	d.Artefacts = json.RawMessage(artefacts)
	d.Residue = json.RawMessage(residue)
	if protectedMatch != nil {
		d.ProtectedMatch = json.RawMessage(protectedMatch)
	}
	d.StalenessReasons = []string{}
	return d, nil
}

// latestRemovalDryRun returns the campaign's most recent dry run, or
// (zero, false) when it has none.
func latestRemovalDryRun(ctx context.Context, q removal.Querier, campaignID string) (removalDryRunJSON, bool, error) {
	d, err := scanRemovalDryRun(q.QueryRow(ctx, `
		SELECT `+removalDryRunColumns+`
		FROM removal_campaign_dry_runs WHERE campaign_id = $1::uuid
		ORDER BY computed_at DESC, id DESC LIMIT 1
	`, campaignID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return d, false, nil
		}
		return d, false, err
	}
	return d, true, nil
}

// annotateStaleness fills in the live staleness verdict for a stored dry run.
func annotateStaleness(d *removalDryRunJSON, current removal.Watermark) {
	s := removal.CheckStaleness(d.ComputedAt, d.InventoryWatermark, time.Now().UTC(), current)
	d.Stale = s.Stale
	d.StalenessReasons = s.Reasons
	if d.StalenessReasons == nil {
		d.StalenessReasons = []string{}
	}
}

// ---------------------------------------------------------------------------
// GET /admin/tenants/{tenantID}/removal-campaigns/{campaignID}
// ---------------------------------------------------------------------------

type removalAuthorizationJSON struct {
	ID                  string          `json:"id"`
	CampaignID          string          `json:"campaign_id"`
	DryRunID            string          `json:"dry_run_id"`
	AuthorizedBy        string          `json:"authorized_by"`
	AuthorizationClause string          `json:"authorization_clause"`
	PolicyID            *int64          `json:"policy_id"`
	PolicySnapshot      json.RawMessage `json:"policy_snapshot"`
	AuthorizedAt        time.Time       `json:"authorized_at"`
}

type removalCampaignDetailResp struct {
	Campaign      removalCampaignRow        `json:"campaign"`
	LatestDryRun  *removalDryRunJSON        `json:"latest_dry_run"`
	Authorization *removalAuthorizationJSON `json:"authorization"`
	// Delivered is always false and carries no delivery state, because no
	// delivery path exists. It is in the contract so the console can say
	// "authorised, not delivered" honestly today rather than implying that
	// an authorised campaign has reached anything.
	Delivered bool `json:"delivered"`
}

// RemovalCampaignGetHandler serves
// GET /admin/tenants/{tenantID}/removal-campaigns/{campaignID}.
func RemovalCampaignGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "removal_campaign_get")

		tenantID, campaignID, ok := removalCampaignParams(w, r)
		if !ok {
			return
		}

		c, err := scanRemovalCampaign(pool.QueryRow(r.Context(), `
			SELECT `+removalCampaignColumns+`
			FROM removal_campaigns WHERE id = $1::uuid AND tenant_id = $2::uuid
		`, campaignID, tenantID))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "campaign not found", http.StatusNotFound)
				return
			}
			logger.Error("removal campaign lookup failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		resp := removalCampaignDetailResp{Campaign: c}

		dryRun, found, err := latestRemovalDryRun(r.Context(), pool, campaignID)
		if err != nil {
			logger.Error("dry run lookup failed", "err", err, "campaign_id", campaignID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if found {
			current, err := removal.InventoryWatermark(r.Context(), pool, tenantID)
			if err != nil {
				logger.Error("inventory watermark failed", "err", err, "tenant_id", tenantID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			annotateStaleness(&dryRun, current)
			resp.LatestDryRun = &dryRun
		}

		auth, found, err := fetchRemovalAuthorization(r.Context(), pool, campaignID)
		if err != nil {
			logger.Error("authorization lookup failed", "err", err, "campaign_id", campaignID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if found {
			resp.Authorization = &auth
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func fetchRemovalAuthorization(ctx context.Context, q removal.Querier, campaignID string) (removalAuthorizationJSON, bool, error) {
	var a removalAuthorizationJSON
	var snapshot []byte
	err := q.QueryRow(ctx, `
		SELECT id::text, campaign_id::text, dry_run_id::text, authorized_by, authorization_clause,
		       policy_id, policy_snapshot, authorized_at
		FROM removal_campaign_authorizations WHERE campaign_id = $1::uuid
	`, campaignID).Scan(&a.ID, &a.CampaignID, &a.DryRunID, &a.AuthorizedBy, &a.AuthorizationClause,
		&a.PolicyID, &snapshot, &a.AuthorizedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return a, false, nil
		}
		return a, false, err
	}
	a.PolicySnapshot = json.RawMessage(snapshot)
	return a, true, nil
}

// ---------------------------------------------------------------------------
// POST /admin/tenants/{tenantID}/removal-campaigns/{campaignID}/dry-run
// ---------------------------------------------------------------------------

type removalDryRunReq struct {
	ComputedBy string `json:"computed_by"`
}

// RemovalCampaignDryRunHandler serves
// POST /admin/tenants/{tenantID}/removal-campaigns/{campaignID}/dry-run.
//
// The computation itself changes nothing outside this subsystem: it reads
// current inventory and writes one evidence row. Re-running appends another,
// so "what did the authoriser see" survives every recomputation, and a
// campaign in dry_run stays in dry_run.
//
// A target matching more inventory than one preview can enumerate is
// refused, not truncated (removal.ErrTooManyMatches): a partial device list
// presented as the removal scope is a false claim about the estate.
//
// 201 removalDryRunJSON | 400 bad input | 404 unknown tenant/campaign |
// 409 wrong campaign state or too many matches
func RemovalCampaignDryRunHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "removal_campaign_dry_run")

		tenantID, campaignID, ok := removalCampaignParams(w, r)
		if !ok {
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}
		var req removalDryRunReq
		if len(strings.TrimSpace(string(body))) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}
		}
		req.ComputedBy = strings.TrimSpace(req.ComputedBy)
		if req.ComputedBy == "" {
			http.Error(w, "computed_by is required", http.StatusBadRequest)
			return
		}

		c, err := scanRemovalCampaign(pool.QueryRow(r.Context(), `
			SELECT `+removalCampaignColumns+`
			FROM removal_campaigns WHERE id = $1::uuid AND tenant_id = $2::uuid
		`, campaignID, tenantID))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "campaign not found", http.StatusNotFound)
				return
			}
			logger.Error("removal campaign lookup failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if c.Status != "draft" && c.Status != "dry_run" {
			http.Error(w, fmt.Sprintf("campaign is %s; a dry run can only be computed for a draft or previewed campaign", c.Status), http.StatusConflict)
			return
		}

		preview, err := removal.Compute(r.Context(), pool, tenantID, c.target())
		if err != nil {
			if errors.Is(err, removal.ErrTooManyMatches) {
				http.Error(w, fmt.Sprintf(
					"target matches more than %d inventory rows; narrow the campaign identity or platform rather than proceeding on a partial preview",
					removal.MaxMatchedRows), http.StatusConflict)
				return
			}
			logger.Error("dry run compute failed", "err", err, "campaign_id", campaignID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		versionSpread, err := json.Marshal(preview.VersionSpread)
		if err != nil {
			logger.Error("marshal version spread failed", "err", err, "campaign_id", campaignID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		devices, err := json.Marshal(preview.Devices)
		if err != nil {
			logger.Error("marshal devices failed", "err", err, "campaign_id", campaignID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		artefacts, err := json.Marshal(preview.Artefacts)
		if err != nil {
			logger.Error("marshal artefacts failed", "err", err, "campaign_id", campaignID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		residue, err := json.Marshal(preview.Residue)
		if err != nil {
			logger.Error("marshal residue failed", "err", err, "campaign_id", campaignID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		var protectedMatch []byte
		if preview.ProtectedMatch != nil {
			protectedMatch, err = json.Marshal(preview.ProtectedMatch)
			if err != nil {
				logger.Error("marshal protected match failed", "err", err, "campaign_id", campaignID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}

		tx, err := pool.Begin(r.Context())
		if err != nil {
			logger.Error("begin tx failed", "err", err, "campaign_id", campaignID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		stored, err := scanRemovalDryRun(tx.QueryRow(r.Context(), `
			INSERT INTO removal_campaign_dry_runs
			    (campaign_id, tenant_id, computed_at, computed_by, device_count, version_spread, devices,
			     evidence_basis, devices_without_app_inventory, artefacts, artefact_basis,
			     artefact_enumeration_complete, residue, protected_match, excluded_device_count,
			     inventory_watermark)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
			RETURNING `+removalDryRunColumns,
			campaignID, tenantID, preview.ComputedAt, req.ComputedBy, preview.DeviceCount,
			versionSpread, devices, preview.EvidenceBasis, preview.DevicesWithoutAppInventory,
			artefacts, preview.ArtefactBasis, preview.ArtefactEnumerationComplete, residue,
			protectedMatch, preview.ExcludedDeviceCount, preview.InventoryWatermark))
		if err != nil {
			logger.Error("dry run insert failed", "err", err, "campaign_id", campaignID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if c.Status == "draft" {
			if _, err := tx.Exec(r.Context(), `
				UPDATE removal_campaigns SET status = 'dry_run', status_changed_at = now()
				WHERE id = $1::uuid AND status = 'draft'
			`, campaignID); err != nil {
				logger.Error("campaign status update failed", "err", err, "campaign_id", campaignID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err, "campaign_id", campaignID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Freshly computed, so the staleness verdict is computed against the
		// same watermark it just recorded rather than assumed fresh.
		current, err := removal.InventoryWatermark(r.Context(), pool, tenantID)
		if err != nil {
			logger.Error("inventory watermark failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		annotateStaleness(&stored, current)

		logger.Info("removal campaign dry run computed", "campaign_id", campaignID,
			"device_count", stored.DeviceCount, "protected", preview.ProtectedMatch != nil)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(stored)
	}
}

// ---------------------------------------------------------------------------
// POST /admin/tenants/{tenantID}/removal-campaigns/{campaignID}/authorize
// ---------------------------------------------------------------------------

type removalAuthorizeReq struct {
	AuthorizedBy        string `json:"authorized_by"`
	AuthorizationClause string `json:"authorization_clause"`
	PolicyID            *int64 `json:"policy_id"`
	DryRunID            string `json:"dry_run_id"`
}

// RemovalCampaignAuthorizeHandler serves
// POST /admin/tenants/{tenantID}/removal-campaigns/{campaignID}/authorize.
//
// Every gate below is a refusal, never a warning:
//
//  1. authorized_by and authorization_clause must both be present. The
//     clause is free text; this platform does not read MSA content and does
//     not pretend to validate it. What it enforces is that a removal cannot
//     be authorised anonymously or without pointing at something.
//  2. The campaign must be in dry_run. An authorisation cites a preview, and
//     a draft has none.
//  3. The cited dry run must be the campaign's most recent one. A newer
//     preview existing is itself proof the cited one is superseded.
//  4. The cited dry run must not be stale (removal.CheckStaleness). A stale
//     preview is worse than none, so the remedy is always to re-run.
//  5. The target must match no protected_software row for this tenant,
//     re-checked here inside the authorising transaction rather than trusted
//     from the dry run. The dry run's verdict could be minutes old and the
//     protection could have been added since; and a protected product must
//     be impossible to authorise whatever the campaign or its preview says.
//  6. A governance decision must be cited: an operator-owned
//     tenant_app_policies row of this tenant's, with policy 'unapproved'.
//     You may not authorise removing a product your own governance record
//     calls approved, mandatory or unmanaged. Portal decisions must first be
//     adopted by an operator. Its state is snapshotted into the authorisation
//     so the record still answers "authorised against what" after the policy
//     row changes or goes away.
//
// 201 removalAuthorizationJSON | 400 missing authoriser/clause/policy |
// 404 unknown tenant/campaign/dry run/policy | 409 every refusal above
func RemovalCampaignAuthorizeHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "removal_campaign_authorize")

		tenantID, campaignID, ok := removalCampaignParams(w, r)
		if !ok {
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 8192))
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}
		var req removalAuthorizeReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		req.AuthorizedBy = strings.TrimSpace(req.AuthorizedBy)
		req.AuthorizationClause = strings.TrimSpace(req.AuthorizationClause)
		req.DryRunID = strings.TrimSpace(req.DryRunID)
		if req.AuthorizedBy == "" || req.AuthorizationClause == "" {
			http.Error(w, "authorized_by and authorization_clause are both required", http.StatusBadRequest)
			return
		}
		if req.DryRunID != "" && !looksLikeUUID(req.DryRunID) {
			http.Error(w, "dry_run_id must be a UUID", http.StatusBadRequest)
			return
		}

		tx, err := pool.Begin(r.Context())
		if err != nil {
			logger.Error("begin tx failed", "err", err, "campaign_id", campaignID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		// FOR UPDATE: two concurrent authorise calls for the same campaign
		// must not both read status 'dry_run' and both proceed. The UNIQUE
		// constraint on campaign_id would catch the second write anyway; the
		// lock makes it a clean 409 rather than a constraint error.
		c, err := scanRemovalCampaign(tx.QueryRow(r.Context(), `
			SELECT `+removalCampaignColumns+`
			FROM removal_campaigns WHERE id = $1::uuid AND tenant_id = $2::uuid
			FOR UPDATE
		`, campaignID, tenantID))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "campaign not found", http.StatusNotFound)
				return
			}
			logger.Error("removal campaign lookup failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if c.Status != "dry_run" {
			http.Error(w, fmt.Sprintf(
				"campaign is %s; only a campaign with a current dry run can be authorised", c.Status),
				http.StatusConflict)
			return
		}

		// Gate 5 first among the DB checks: a protected product must be
		// refused for being protected, not for some incidental reason that
		// happens to be checked earlier.
		match, err := protectedsoftware.Check(r.Context(), tx, tenantID, c.target().Identity())
		if err != nil {
			logger.Error("protected software check failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if match != nil {
			logger.Warn("removal authorisation refused: protected software",
				"campaign_id", campaignID, "category", match.Category, "product", match.ProductName)
			http.Error(w, protectedRemovalMessage(match), http.StatusConflict)
			return
		}

		dryRun, found, err := latestRemovalDryRun(r.Context(), tx, campaignID)
		if err != nil {
			logger.Error("dry run lookup failed", "err", err, "campaign_id", campaignID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "campaign has no dry run to authorise against", http.StatusNotFound)
			return
		}
		if req.DryRunID != "" && req.DryRunID != dryRun.ID {
			http.Error(w, fmt.Sprintf(
				"dry_run_id %s is not this campaign's most recent dry run (%s); re-run the dry run and authorise against the result",
				req.DryRunID, dryRun.ID), http.StatusConflict)
			return
		}

		current, err := removal.InventoryWatermark(r.Context(), tx, tenantID)
		if err != nil {
			logger.Error("inventory watermark failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if s := removal.CheckStaleness(dryRun.ComputedAt, dryRun.InventoryWatermark, time.Now().UTC(), current); s.Stale {
			http.Error(w, "dry run is stale, re-run it before authorising: "+strings.Join(s.Reasons, "; "),
				http.StatusConflict)
			return
		}

		policyID := req.PolicyID
		if policyID == nil {
			policyID = c.PolicyID
		}
		if policyID == nil {
			http.Error(w, "policy_id is required: an authorisation must cite the governance decision it implements", http.StatusBadRequest)
			return
		}
		var policyState, policySource string
		var policySnapshot []byte
		if err := tx.QueryRow(r.Context(), `
			SELECT policy, source, to_jsonb(tap) FROM tenant_app_policies tap
			WHERE id = $1 AND tenant_id = $2::uuid
		`, *policyID, tenantID).Scan(&policyState, &policySource, &policySnapshot); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "policy_id does not reference a policy belonging to this tenant", http.StatusNotFound)
				return
			}
			logger.Error("policy lookup failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if policyState != "unapproved" {
			http.Error(w, fmt.Sprintf(
				"cited policy is %s; a removal can only be authorised against a policy decision marking the product unapproved", policyState),
				http.StatusConflict)
			return
		}
		if policySource != "operator" {
			http.Error(w, portalPolicyAdoptionMessage, http.StatusConflict)
			return
		}

		var a removalAuthorizationJSON
		var storedSnapshot []byte
		if err := tx.QueryRow(r.Context(), `
			INSERT INTO removal_campaign_authorizations
			    (campaign_id, tenant_id, dry_run_id, authorized_by, authorization_clause, policy_id, policy_snapshot)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7)
			RETURNING id::text, campaign_id::text, dry_run_id::text, authorized_by, authorization_clause,
			          policy_id, policy_snapshot, authorized_at
		`, campaignID, tenantID, dryRun.ID, req.AuthorizedBy, req.AuthorizationClause, *policyID, policySnapshot,
		).Scan(&a.ID, &a.CampaignID, &a.DryRunID, &a.AuthorizedBy, &a.AuthorizationClause,
			&a.PolicyID, &storedSnapshot, &a.AuthorizedAt); err != nil {
			logger.Error("authorization insert failed", "err", err, "campaign_id", campaignID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		a.PolicySnapshot = json.RawMessage(storedSnapshot)

		if _, err := tx.Exec(r.Context(), `
			UPDATE removal_campaigns SET status = 'authorized', status_changed_at = now(), policy_id = $2
			WHERE id = $1::uuid
		`, campaignID, *policyID); err != nil {
			logger.Error("campaign status update failed", "err", err, "campaign_id", campaignID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err, "campaign_id", campaignID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("removal campaign authorised", "campaign_id", campaignID,
			"authorized_by", req.AuthorizedBy, "dry_run_id", dryRun.ID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(a)
	}
}

// ---------------------------------------------------------------------------
// POST /admin/tenants/{tenantID}/removal-campaigns/{campaignID}/cancel
// ---------------------------------------------------------------------------

type removalCancelReq struct {
	CancelledBy string `json:"cancelled_by"`
	Reason      string `json:"reason"`
}

// RemovalCampaignCancelHandler serves
// POST /admin/tenants/{tenantID}/removal-campaigns/{campaignID}/cancel.
//
// Reachable from draft and dry_run only. An authorised campaign is not
// cancellable: its authorisation record is append-only and would still
// stand, so flipping the campaign's status would only make the two disagree.
//
// 200 removalCampaignRow | 400 bad input | 404 unknown tenant/campaign |
// 409 campaign already authorised or cancelled
func RemovalCampaignCancelHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "removal_campaign_cancel")

		tenantID, campaignID, ok := removalCampaignParams(w, r)
		if !ok {
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}
		var req removalCancelReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		req.CancelledBy = strings.TrimSpace(req.CancelledBy)
		req.Reason = strings.TrimSpace(req.Reason)
		if req.CancelledBy == "" || req.Reason == "" {
			http.Error(w, "cancelled_by and reason are both required", http.StatusBadRequest)
			return
		}

		c, err := scanRemovalCampaign(pool.QueryRow(r.Context(), `
			UPDATE removal_campaigns
			SET status = 'cancelled', status_changed_at = now(),
			    cancelled_by = $3, cancelled_reason = $4, cancelled_at = now()
			WHERE id = $1::uuid AND tenant_id = $2::uuid AND status IN ('draft', 'dry_run')
			RETURNING `+removalCampaignColumns,
			campaignID, tenantID, req.CancelledBy, req.Reason))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				// Either it does not exist, or it is not in a cancellable
				// state. Distinguish so the caller is not left guessing.
				var status string
				lookupErr := pool.QueryRow(r.Context(),
					`SELECT status FROM removal_campaigns WHERE id = $1::uuid AND tenant_id = $2::uuid`,
					campaignID, tenantID).Scan(&status)
				if lookupErr != nil {
					http.Error(w, "campaign not found", http.StatusNotFound)
					return
				}
				http.Error(w, fmt.Sprintf("campaign is %s and cannot be cancelled", status), http.StatusConflict)
				return
			}
			logger.Error("removal campaign cancel failed", "err", err, "campaign_id", campaignID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("removal campaign cancelled", "campaign_id", campaignID, "cancelled_by", req.CancelledBy)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c)
	}
}

// removalCampaignParams validates and returns the two URL params every
// per-campaign route shares.
func removalCampaignParams(w http.ResponseWriter, r *http.Request) (tenantID, campaignID string, ok bool) {
	tenantID = strings.TrimSpace(chi.URLParam(r, "tenantID"))
	campaignID = strings.TrimSpace(chi.URLParam(r, "campaignID"))
	if !looksLikeUUID(tenantID) || !looksLikeUUID(campaignID) {
		http.Error(w, "tenantID and campaignID must be UUIDs", http.StatusBadRequest)
		return "", "", false
	}
	return tenantID, campaignID, true
}
