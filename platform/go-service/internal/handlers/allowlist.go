package handlers

// Software allowlist store + installed-vs-approved match engine (PAT-375).
//
// Routes (all on :8081 Tailscale-only admin listener):
//
//	GET  /admin/tenants/{tenantID}/allowlist          – list entries + scan summary
//	POST /admin/tenants/{tenantID}/allowlist          – add entry
//	PUT  /admin/tenants/{tenantID}/allowlist/{id}     – update enforcement / notes
//	DELETE /admin/tenants/{tenantID}/allowlist/{id}   – remove entry
//	PUT  /admin/tenants/{tenantID}/allowlist-policy   – toggle default_deny stance
//	GET  /admin/tenants/{tenantID}/allowlist/scan     – run match engine → per-app status
//
// Match modes (all case-insensitive):
//   - exact_name    : app.name = entry.name
//   - name_publisher: exact_name AND app.publisher = entry.publisher
//   - publisher_only: app.publisher = entry.publisher
//
// ⚠️  Write path: the non-author-review gate before any enforcement action drives
// agent behaviour on customer endpoints. MVP surfaces flag-only intent; actual
// uninstall execution stays in PAT-118/PAT-376 (agent-side, Tier 2+, MSA-auth).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/notify"
	"patched.im/api/internal/wingetid"
)

// ---------------------------------------------------------------------------
// Shared constants / value sets
// ---------------------------------------------------------------------------

var allowlistValidPlatforms = map[string]bool{
	"macos": true, "windows": true, "any": true,
}

var allowlistValidMatchModes = map[string]bool{
	"exact_name": true, "name_publisher": true, "publisher_only": true,
}

var allowlistValidEnforcements = map[string]bool{
	"allowed": true, "flagged": true, "marked_for_uninstall": true, "launch_restricted": true,
}

// allowlistTrustedIdentifierPrefixes holds app identifier (bundle ID / product
// code) prefixes that are always auto-approved as OS-vendor system software,
// in addition to the exact-name matches in allowlist_baseline_apps. This is a
// coarser-grained baseline: it catches system utilities that ship under a
// vendor's namespace but aren't individually enumerated in the baseline table
// (e.g. com.apple.AccessibilityInspector). Add more trusted vendor prefixes
// here as they're identified — no schema change required.
var allowlistTrustedIdentifierPrefixes = []string{
	"com.apple.",
}

// isTrustedSystemIdentifier reports whether identifier belongs to a known
// trusted vendor namespace (see allowlistTrustedIdentifierPrefixes) and
// should therefore be auto-approved as system baseline software.
func isTrustedSystemIdentifier(identifier string) bool {
	for _, prefix := range allowlistTrustedIdentifierPrefixes {
		if strings.HasPrefix(identifier, prefix) {
			return true
		}
	}
	return false
}

// allowlistGroupKey derives a parent-app grouping key from an app identifier
// by joining its first two dot-separated segments (e.g. "us.zoom.xos" ->
// "us.zoom", "com.apple.AccessibilityInspector" -> "com.apple"). Identifiers
// with fewer than three segments (e.g. Windows MSI product codes/GUIDs, which
// have no meaningful dot-hierarchy) yield an empty key, meaning "don't group".
func allowlistGroupKey(identifier, identifierKind, platform string) string {
	segments := strings.Split(identifier, ".")
	if len(segments) < 3 {
		return ""
	}
	group := segments[0] + "." + segments[1]
	if platform != "windows" {
		return group
	}

	// Windows inventory stores native and Winget identifiers in the same
	// column. Keep their dashboard grouping separate, including legacy rows
	// which pre-date explicit identifier typing. Empty covers both NULL legacy
	// rows and empty stored values, which have the same untyped semantics.
	if identifierKind == "" {
		identifierKind = "untyped"
	}
	return identifierKind + ":" + group
}

// ---------------------------------------------------------------------------
// Response / request types
// ---------------------------------------------------------------------------

type allowlistEntryJSON struct {
	ID          int64     `json:"id"`
	Platform    string    `json:"platform"`
	Name        string    `json:"name"`
	Publisher   *string   `json:"publisher"`
	MatchMode   string    `json:"match_mode"`
	Enforcement string    `json:"enforcement"`
	ApprovedBy  string    `json:"approved_by"`
	Notes       string    `json:"notes"`
	ApprovedAt  time.Time `json:"approved_at"`
}

type allowlistSummaryJSON struct {
	TotalFleetApps   int `json:"total_fleet_apps"`
	Approved         int `json:"approved"`
	SystemBaseline   int `json:"system_baseline"`
	Flagged          int `json:"flagged"`
	MarkedUninstall  int `json:"marked_for_uninstall"`
	LaunchRestricted int `json:"launch_restricted"`
	Unreviewed       int `json:"unreviewed"`
}

type allowlistGetResp struct {
	TenantID    string                `json:"tenant_id"`
	DefaultDeny bool                  `json:"default_deny"`
	Entries     []allowlistEntryJSON  `json:"entries"`
	Summary     *allowlistSummaryJSON `json:"summary,omitempty"`
}

type allowlistScanAppJSON struct {
	Name           string    `json:"name"`
	Identifier     string    `json:"identifier"`
	IdentifierKind string    `json:"identifier_kind,omitempty"`
	TeamID         string    `json:"team_id,omitempty"`
	BundleID       string    `json:"bundle_id,omitempty"`
	WingetID       string    `json:"winget_id,omitempty"`
	AppIdentity    string    `json:"app_identity"`
	Publisher      *string   `json:"publisher"`
	Platform       string    `json:"platform"`
	DeviceCount    int       `json:"device_count"`
	LastSeen       time.Time `json:"last_seen"`
	Status         string    `json:"status"`
	EntryID        *int64    `json:"entry_id"`
	GroupKey       string    `json:"group_key,omitempty"`
}

type allowlistScanResp struct {
	TenantID    string                 `json:"tenant_id"`
	DefaultDeny bool                   `json:"default_deny"`
	GeneratedAt time.Time              `json:"generated_at"`
	Summary     allowlistSummaryJSON   `json:"summary"`
	Apps        []allowlistScanAppJSON `json:"apps"`
}

type allowlistAddReq struct {
	Platform    string  `json:"platform"`
	Name        string  `json:"name"`
	Publisher   *string `json:"publisher"`
	MatchMode   string  `json:"match_mode"`
	Enforcement string  `json:"enforcement"`
	ApprovedBy  string  `json:"approved_by"`
	Notes       string  `json:"notes"`
}

type allowlistUpdateReq struct {
	Enforcement string `json:"enforcement"`
	Notes       string `json:"notes"`
}

type allowlistPolicyReq struct {
	DefaultDeny bool `json:"default_deny"`
}

// usableAllowlistIdentityValue keeps placeholder inventory values out of the
// governance identity contract. The raw identifier remains available in the
// legacy `identifier` response field for compatibility, but it must not be
// promoted into a policy identity when it carries no evidence.
func usableAllowlistIdentityValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "unknown") {
		return ""
	}
	return value
}

// allowlistInstalledAppIdentity identifies the strongest installed evidence
// carried by the scan response. Typed Windows Winget evidence must remain
// distinguishable from the compatibility bundle_id field or the dashboard
// could write a bundle policy that the platform's typed resolver never treats
// as Winget authority.
func allowlistInstalledAppIdentity(teamID, bundleID, wingetID, name, platform string) string {
	if teamID = usableAllowlistIdentityValue(teamID); teamID != "" {
		return "team:" + strings.ToLower(teamID)
	}
	if platform == "windows" {
		if wingetID = usableAllowlistIdentityValue(wingetID); wingetID != "" {
			return "winget:" + strings.ToLower(wingetID)
		}
	}
	if bundleID = usableAllowlistIdentityValue(bundleID); bundleID != "" {
		return "bundle:" + strings.ToLower(bundleID)
	}
	if name = usableAllowlistIdentityValue(name); name != "" {
		return "name:" + strings.ToLower(name)
	}
	return ""
}

// allowlistInstalledWingetID admits an identifier to the Windows Winget
// response contract only when the endpoint explicitly typed it as a canonical
// PackageIdentifier. Native and legacy/untyped identifiers remain available
// through the compatibility fields but are never promoted to winget_id.
func allowlistInstalledWingetID(identifier, identifierKind, platform string) string {
	if platform != "windows" || identifierKind != "winget" || !wingetid.Valid(identifier) {
		return ""
	}
	return identifier
}

// ---------------------------------------------------------------------------
// GET /admin/tenants/{tenantID}/allowlist
// ---------------------------------------------------------------------------

func TenantAllowlistGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "allowlist_get")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		var defaultDeny bool
		err := pool.QueryRow(r.Context(),
			`SELECT allowlist_default_deny FROM tenants WHERE id = $1::uuid`, tenantID,
		).Scan(&defaultDeny)
		if err != nil {
			if isNoRows(err) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("tenant lookup failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		rows, err := pool.Query(r.Context(), `
			SELECT id, platform, name, publisher, match_mode, enforcement,
			       approved_by, notes, approved_at
			FROM tenant_allowlists
			WHERE tenant_id = $1::uuid
			ORDER BY LOWER(name), platform
		`, tenantID)
		if err != nil {
			logger.Error("allowlist query failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var entries []allowlistEntryJSON
		for rows.Next() {
			var e allowlistEntryJSON
			if err := rows.Scan(&e.ID, &e.Platform, &e.Name, &e.Publisher,
				&e.MatchMode, &e.Enforcement, &e.ApprovedBy, &e.Notes, &e.ApprovedAt); err != nil {
				logger.Error("allowlist row scan failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			entries = append(entries, e)
		}
		if err := rows.Err(); err != nil {
			logger.Error("allowlist rows error", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if entries == nil {
			entries = []allowlistEntryJSON{}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(allowlistGetResp{
			TenantID:    tenantID,
			DefaultDeny: defaultDeny,
			Entries:     entries,
		})
	}
}

// ---------------------------------------------------------------------------
// POST /admin/tenants/{tenantID}/allowlist
// ---------------------------------------------------------------------------

// allowlistRestrictedHostCount returns a best-effort count of distinct
// devices with an installed app whose name case-insensitively matches name.
// Returns (nil, nil) if the count could not be determined — callers treat
// that as "host count unknown" rather than failing the request.
func allowlistRestrictedHostCount(ctx context.Context, pool *pgxpool.Pool, tenantID, name string) *int {
	var count int
	err := pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT da.device_id)
		FROM device_apps da
		JOIN devices d ON d.id = da.device_id
		WHERE d.tenant_id = $1::uuid AND LOWER(da.name) = LOWER($2)
	`, tenantID, name).Scan(&count)
	if err != nil {
		return nil
	}
	return &count
}

// notifyLaunchRestricted dispatches a KindAppLaunchRestricted Slack/email
// alert (PAT-820) for a first-time transition into enforcement=launch_restricted.
// Fully asynchronous and non-blocking: the host-count lookup is a DB round
// trip, so it (like the notification send itself) must never add latency to
// the persist request — it runs in its own goroutine on a fresh bounded
// context, not the caller's request context, which is typically canceled the
// moment the handler returns.
func notifyLaunchRestricted(pool *pgxpool.Pool, notifier *notify.Notifier, tenantID, name, platform, actor, sourceAction string) {
	if !notifier.Enabled() {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		notifier.Dispatch(ctx, notify.Event{
			TenantID:     tenantID,
			Kind:         notify.KindAppLaunchRestricted,
			Label:        name,
			Actor:        actor,
			Platform:     platform,
			SourceAction: sourceAction,
			HostCount:    allowlistRestrictedHostCount(ctx, pool, tenantID, name),
			Link:         notify.CatalogueLink(tenantID),
			Timestamp:    time.Now().UTC(),
		})
	}()
}

func TenantAllowlistAddHandler(pool *pgxpool.Pool, notifier *notify.Notifier) http.HandlerFunc {
	return tenantAllowlistAddHandler(pool, notifier, false)
}

// TenantAllowlistAddHandlerForLegacyExecutionCompatibility exists only for
// retained compatibility tests. It must never be used in production wiring.
func TenantAllowlistAddHandlerForLegacyExecutionCompatibility(pool *pgxpool.Pool, notifier *notify.Notifier) http.HandlerFunc {
	return tenantAllowlistAddHandler(pool, notifier, true)
}

func tenantAllowlistAddHandler(pool *pgxpool.Pool, notifier *notify.Notifier, legacyExecutionEnabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "allowlist_add")

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
		var req allowlistAddReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		// Defaults
		if req.Platform == "" {
			req.Platform = "any"
		}
		if req.MatchMode == "" {
			req.MatchMode = "exact_name"
		}
		if req.Enforcement == "" {
			req.Enforcement = "allowed"
		}

		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		if !allowlistValidPlatforms[req.Platform] {
			http.Error(w, "platform must be one of: macos, windows, any", http.StatusBadRequest)
			return
		}
		if !allowlistValidMatchModes[req.MatchMode] {
			http.Error(w, "match_mode must be one of: exact_name, name_publisher, publisher_only", http.StatusBadRequest)
			return
		}
		if !allowlistValidEnforcements[req.Enforcement] {
			http.Error(w, "enforcement must be one of: allowed, flagged, marked_for_uninstall, launch_restricted", http.StatusBadRequest)
			return
		}
		if req.MatchMode == "name_publisher" || req.MatchMode == "publisher_only" {
			if req.Publisher == nil || strings.TrimSpace(*req.Publisher) == "" {
				http.Error(w, "publisher is required for match_mode name_publisher / publisher_only", http.StatusBadRequest)
				return
			}
		}
		if !legacyExecutionEnabled && req.Enforcement == "marked_for_uninstall" {
			legacyExecutionDisabledHandler(w, r)
			return
		}

		var tenantExists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid)`, tenantID,
		).Scan(&tenantExists); err != nil {
			logger.Error("tenant existence check failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !tenantExists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		now := time.Now().UTC()
		var entryID int64
		err = pool.QueryRow(r.Context(), `
			INSERT INTO tenant_allowlists
			    (tenant_id, platform, name, publisher, match_mode, enforcement,
			     approved_by, notes, approved_at)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9)
			RETURNING id
		`, tenantID, req.Platform, req.Name, req.Publisher, req.MatchMode,
			req.Enforcement, req.ApprovedBy, req.Notes, now,
		).Scan(&entryID)
		if err != nil {
			if strings.Contains(err.Error(), "unique") {
				http.Error(w, "entry already exists for this tenant/platform/name/match_mode combination", http.StatusConflict)
				return
			}
			logger.Error("allowlist insert failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Audit log
		_, _ = pool.Exec(r.Context(), `
			INSERT INTO tenant_allowlist_changes (tenant_id, entry_id, action, detail)
			VALUES ($1::uuid, $2, 'added', $3)
		`, tenantID, entryID, fmt.Sprintf(`{"name":%q,"enforcement":%q}`, req.Name, req.Enforcement))

		// PAT-820: a brand-new entry created directly at launch_restricted is
		// always a first transition — alert once.
		if req.Enforcement == "launch_restricted" {
			notifyLaunchRestricted(pool, notifier, tenantID, req.Name, req.Platform, req.ApprovedBy, "allowlist_add")
		}

		logger.Info("allowlist entry added", "tenant_id", tenantID, "entry_id", entryID, "name", req.Name)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(allowlistEntryJSON{
			ID: entryID, Platform: req.Platform, Name: req.Name,
			Publisher: req.Publisher, MatchMode: req.MatchMode,
			Enforcement: req.Enforcement, ApprovedBy: req.ApprovedBy,
			Notes: req.Notes, ApprovedAt: now,
		})
	}
}

// ---------------------------------------------------------------------------
// PUT /admin/tenants/{tenantID}/allowlist/{entryID}
// ---------------------------------------------------------------------------

func TenantAllowlistUpdateHandler(pool *pgxpool.Pool, notifier *notify.Notifier) http.HandlerFunc {
	return tenantAllowlistUpdateHandler(pool, notifier, false)
}

// TenantAllowlistUpdateHandlerForLegacyExecutionCompatibility exists only for
// retained compatibility tests. It must never be used in production wiring.
func TenantAllowlistUpdateHandlerForLegacyExecutionCompatibility(pool *pgxpool.Pool, notifier *notify.Notifier) http.HandlerFunc {
	return tenantAllowlistUpdateHandler(pool, notifier, true)
}

func tenantAllowlistUpdateHandler(pool *pgxpool.Pool, notifier *notify.Notifier, legacyExecutionEnabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "allowlist_update")

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
		var req allowlistUpdateReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if !allowlistValidEnforcements[req.Enforcement] {
			http.Error(w, "enforcement must be one of: allowed, flagged, marked_for_uninstall, launch_restricted", http.StatusBadRequest)
			return
		}
		if !legacyExecutionEnabled && req.Enforcement == "marked_for_uninstall" {
			legacyExecutionDisabledHandler(w, r)
			return
		}

		// Snapshot pre-update state and update in a single statement (PAT-820) —
		// the "old" CTE takes a row lock via FOR UPDATE that's held until the
		// UPDATE commits, so two concurrent requests against the same entry
		// cannot both observe the pre-restriction state and each fire an alert.
		var oldEnforcement, entryName, entryPlatform string
		if err := pool.QueryRow(r.Context(), `
			WITH old AS (
				SELECT enforcement, name, platform FROM tenant_allowlists
				WHERE id = $3 AND tenant_id = $4::uuid
				FOR UPDATE
			)
			UPDATE tenant_allowlists
			SET enforcement = $1, notes = $2
			FROM old
			WHERE tenant_allowlists.id = $3 AND tenant_allowlists.tenant_id = $4::uuid
			RETURNING old.enforcement, old.name, old.platform
		`, req.Enforcement, req.Notes, entryID, tenantID,
		).Scan(&oldEnforcement, &entryName, &entryPlatform); err != nil {
			if isNoRows(err) {
				http.Error(w, "entry not found", http.StatusNotFound)
				return
			}
			logger.Error("allowlist update failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		_, _ = pool.Exec(r.Context(), `
			INSERT INTO tenant_allowlist_changes (tenant_id, entry_id, action, detail)
			VALUES ($1::uuid, $2, 'enforcement_changed', $3)
		`, tenantID, entryID, fmt.Sprintf(`{"from":%q,"to":%q}`, oldEnforcement, req.Enforcement))

		// PAT-820: alert only on the first transition into launch_restricted —
		// re-saving an already-restricted entry must not spam Slack.
		if req.Enforcement == "launch_restricted" && oldEnforcement != "launch_restricted" {
			notifyLaunchRestricted(pool, notifier, tenantID, entryName, entryPlatform, "", "allowlist_update")
		}

		logger.Info("allowlist entry updated", "tenant_id", tenantID, "entry_id", entryID)
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---------------------------------------------------------------------------
// DELETE /admin/tenants/{tenantID}/allowlist/{entryID}
// ---------------------------------------------------------------------------

func TenantAllowlistDeleteHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "allowlist_delete")

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

		var name string
		err = pool.QueryRow(r.Context(), `
			DELETE FROM tenant_allowlists WHERE id = $1 AND tenant_id = $2::uuid RETURNING name
		`, entryID, tenantID).Scan(&name)
		if err != nil {
			if isNoRows(err) {
				http.Error(w, "entry not found", http.StatusNotFound)
				return
			}
			logger.Error("allowlist delete failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		_, _ = pool.Exec(r.Context(), `
			INSERT INTO tenant_allowlist_changes (tenant_id, entry_id, action, detail)
			VALUES ($1::uuid, $2, 'removed', $3)
		`, tenantID, entryID, fmt.Sprintf(`{"name":%q}`, name))

		logger.Info("allowlist entry removed", "tenant_id", tenantID, "entry_id", entryID, "name", name)
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---------------------------------------------------------------------------
// PUT /admin/tenants/{tenantID}/allowlist-policy
// ---------------------------------------------------------------------------

func TenantAllowlistPolicyHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "allowlist_policy")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 256))
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}
		var req allowlistPolicyReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		tag, err := pool.Exec(r.Context(), `
			UPDATE tenants SET allowlist_default_deny = $1 WHERE id = $2::uuid
		`, req.DefaultDeny, tenantID)
		if err != nil {
			logger.Error("allowlist policy update failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if tag.RowsAffected() == 0 {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		action := "default_deny_off"
		if req.DefaultDeny {
			action = "default_deny_on"
		}
		_, _ = pool.Exec(r.Context(), `
			INSERT INTO tenant_allowlist_changes (tenant_id, entry_id, action, detail)
			VALUES ($1::uuid, NULL, $2, '{}')
		`, tenantID, action)

		logger.Info("allowlist default_deny updated", "tenant_id", tenantID, "default_deny", req.DefaultDeny)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"tenant_id":    tenantID,
			"default_deny": req.DefaultDeny,
		})
	}
}

// ---------------------------------------------------------------------------
// GET /admin/tenants/{tenantID}/allowlist/scan
// Match engine: join fleet inventory against baseline + tenant allowlist.
// ---------------------------------------------------------------------------

func TenantAllowlistScanHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "allowlist_scan")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		var defaultDeny bool
		err := pool.QueryRow(r.Context(),
			`SELECT allowlist_default_deny FROM tenants WHERE id = $1::uuid`, tenantID,
		).Scan(&defaultDeny)
		if err != nil {
			if isNoRows(err) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("tenant lookup failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Load the tenant's allowlist into memory for in-process matching.
		// Fleet apps are typically < 500 distinct apps; both sets fit easily.
		type allowlistEntry struct {
			id          int64
			platform    string
			name        string
			publisher   *string
			matchMode   string
			enforcement string
		}
		entryRows, err := pool.Query(r.Context(), `
			SELECT id, platform, LOWER(name), publisher, match_mode, enforcement
			FROM tenant_allowlists WHERE tenant_id = $1::uuid
		`, tenantID)
		if err != nil {
			logger.Error("allowlist fetch failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer entryRows.Close()
		var entries []allowlistEntry
		for entryRows.Next() {
			var e allowlistEntry
			if err := entryRows.Scan(&e.id, &e.platform, &e.name, &e.publisher, &e.matchMode, &e.enforcement); err != nil {
				logger.Error("allowlist entry scan failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			entries = append(entries, e)
		}
		entryRows.Close()

		// Load baseline app names (platform-matched) into a set.
		baselineRows, err := pool.Query(r.Context(), `
			SELECT LOWER(name), platform FROM allowlist_baseline_apps
		`)
		if err != nil {
			logger.Error("baseline fetch failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer baselineRows.Close()
		type baselineKey struct{ name, platform string }
		baseline := make(map[baselineKey]bool)
		for baselineRows.Next() {
			var name, platform string
			if err := baselineRows.Scan(&name, &platform); err != nil {
				continue
			}
			baseline[baselineKey{name, platform}] = true
			baseline[baselineKey{name, "any"}] = true
		}
		baselineRows.Close()

		// Fetch distinct fleet apps for this tenant.
		fleetRows, err := pool.Query(r.Context(), `
			SELECT
				da.name,
				da.identifier,
				COALESCE(da.identifier_kind, '') AS identifier_kind,
				da.team_id,
				da.publisher,
				COUNT(DISTINCT da.device_id) AS device_count,
				MAX(da.last_seen) AS last_seen,
				CASE WHEN LOWER(d.os) LIKE 'windows%' THEN 'windows' ELSE 'macos' END AS platform
			FROM device_apps da
			JOIN devices d ON d.id = da.device_id
			WHERE d.tenant_id = $1::uuid
			GROUP BY da.name, da.identifier, COALESCE(da.identifier_kind, ''), da.team_id, da.publisher,
			         CASE WHEN LOWER(d.os) LIKE 'windows%' THEN 'windows' ELSE 'macos' END
			ORDER BY LOWER(da.name),
			         CASE WHEN LOWER(d.os) LIKE 'windows%' THEN 'windows' ELSE 'macos' END
		`, tenantID)
		if err != nil {
			logger.Error("fleet apps fetch failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer fleetRows.Close()

		var apps []allowlistScanAppJSON
		var summ allowlistSummaryJSON
		for fleetRows.Next() {
			var name, identifier, identifierKind string
			var teamID, publisher *string
			var deviceCount int
			var lastSeen time.Time
			var platform string
			if err := fleetRows.Scan(&name, &identifier, &identifierKind, &teamID, &publisher, &deviceCount, &lastSeen, &platform); err != nil {
				logger.Error("fleet row scan failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			lname := strings.ToLower(name)
			lpub := ""
			if publisher != nil {
				lpub = strings.ToLower(*publisher)
			}
			groupKey := allowlistGroupKey(identifier, identifierKind, platform)
			installedTeamID := ""
			if teamID != nil {
				installedTeamID = usableAllowlistIdentityValue(*teamID)
			}
			bundleID := usableAllowlistIdentityValue(identifier)
			wingetID := allowlistInstalledWingetID(identifier, identifierKind, platform)
			appIdentity := allowlistInstalledAppIdentity(installedTeamID, bundleID, wingetID, name, platform)

			summ.TotalFleetApps++

			// 1. Check OS baseline: exact name/platform match in
			// allowlist_baseline_apps, or a trusted vendor identifier prefix.
			if baseline[baselineKey{lname, platform}] || baseline[baselineKey{lname, "any"}] || isTrustedSystemIdentifier(identifier) {
				apps = append(apps, allowlistScanAppJSON{
					Name: name, Identifier: identifier, IdentifierKind: identifierKind, TeamID: installedTeamID, BundleID: bundleID, WingetID: wingetID,
					AppIdentity: appIdentity, Publisher: publisher, Platform: platform,
					DeviceCount: deviceCount, LastSeen: lastSeen,
					Status: "system_baseline", GroupKey: groupKey,
				})
				summ.SystemBaseline++
				continue
			}

			// 2. Check tenant allowlist entries (first match wins)
			matched := false
			for _, e := range entries {
				if e.platform != "any" && e.platform != platform {
					continue
				}
				var hits bool
				switch e.matchMode {
				case "exact_name":
					hits = e.name == lname
				case "name_publisher":
					var epub string
					if e.publisher != nil {
						epub = strings.ToLower(*e.publisher)
					}
					hits = e.name == lname && epub == lpub
				case "publisher_only":
					var epub string
					if e.publisher != nil {
						epub = strings.ToLower(*e.publisher)
					}
					hits = epub != "" && epub == lpub
				}
				if !hits {
					continue
				}
				matched = true
				app := allowlistScanAppJSON{
					Name: name, Identifier: identifier, IdentifierKind: identifierKind, TeamID: installedTeamID, BundleID: bundleID, WingetID: wingetID,
					AppIdentity: appIdentity, Publisher: publisher, Platform: platform,
					DeviceCount: deviceCount, LastSeen: lastSeen,
					Status: e.enforcement, EntryID: &e.id, GroupKey: groupKey,
				}
				apps = append(apps, app)
				switch e.enforcement {
				case "allowed":
					summ.Approved++
				case "flagged":
					summ.Flagged++
				case "marked_for_uninstall":
					summ.MarkedUninstall++
				case "launch_restricted":
					summ.LaunchRestricted++
				}
				break
			}
			if matched {
				continue
			}

			// 3. Not in any list
			status := "unreviewed"
			if defaultDeny {
				status = "not_in_allowlist"
			}
			apps = append(apps, allowlistScanAppJSON{
				Name: name, Identifier: identifier, IdentifierKind: identifierKind, TeamID: installedTeamID, BundleID: bundleID, WingetID: wingetID,
				AppIdentity: appIdentity, Publisher: publisher, Platform: platform,
				DeviceCount: deviceCount, LastSeen: lastSeen,
				Status: status, GroupKey: groupKey,
			})
			summ.Unreviewed++
		}
		if err := fleetRows.Err(); err != nil {
			logger.Error("fleet rows error", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if apps == nil {
			apps = []allowlistScanAppJSON{}
		}

		logger.Info("allowlist scan complete", "tenant_id", tenantID, "total", summ.TotalFleetApps)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(allowlistScanResp{
			TenantID:    tenantID,
			DefaultDeny: defaultDeny,
			GeneratedAt: time.Now().UTC(),
			Summary:     summ,
			Apps:        apps,
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isNoRows(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no rows")
}

func parseInt64Param(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}
