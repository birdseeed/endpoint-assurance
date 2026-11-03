package handlers

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
)

// TenantRules* handlers manage per-tenant rule activation, severity overrides,
// and suppression windows. All live on the internal Tailscale-bound listener.
//
// Auth posture: network-only at MVP — same as other admin handlers. See admin.go.
//
// Routes:
//
//	GET    /admin/tenant-rules/{tenantID}           — list all rules with tenant state
//	PUT    /admin/tenant-rules/{tenantID}/{ruleID}  — upsert a tenant_rules row
//	DELETE /admin/tenant-rules/{tenantID}/{ruleID}  — remove a tenant_rules row

// tenantRuleEntry is one rule in the GET response.
type tenantRuleEntry struct {
	RuleID            string     `json:"rule_id"`
	RuleKey           string     `json:"rule_key"`
	Title             string     `json:"title"`
	Benchmark         string     `json:"benchmark"`
	BenchmarkVersion  string     `json:"benchmark_version"`
	ControlIdentifier *string    `json:"control_identifier"`
	CollectionTier    string     `json:"collection_tier"`
	Platform          string     `json:"platform"`
	GlobalSeverity    string     `json:"global_severity"`
	TenantRuleID      *string    `json:"tenant_rule_id"`
	Enabled           bool       `json:"enabled"`
	OverrideSeverity  *string    `json:"override_severity"`
	Suppressed        bool       `json:"suppressed"`
	SuppressedUntil   *time.Time `json:"suppressed_until"`
	SuppressionReason *string    `json:"suppression_reason"`
	// EvaluatedDevices is the count of distinct tenant devices with a latest
	// compliance_evaluations row for this rule, regardless of pass/fail — the
	// correct denominator for a per-rule pass rate. PAT-1690: the tenant's raw
	// total device count over-counts for platform-scoped rules, since devices
	// on the other platform are never evaluated against them at all.
	EvaluatedDevices int `json:"evaluated_devices"`
}

type tenantRulesListResp struct {
	TenantID string            `json:"tenant_id"`
	Rules    []tenantRuleEntry `json:"rules"`
}

// TenantRulesListHandler returns every compliance rule alongside its per-tenant
// state for the given tenant.
//
// An optional ?platform=macos|windows query param filters results to that
// platform. When absent, all platforms are returned (back-compat).
//
// T1 rules always show enabled=true (they evaluate regardless of tenant_rules).
// T2 rules show enabled=false until an enabled tenant_rules row exists.
func TenantRulesListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenant_rules_list")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		platform := strings.TrimSpace(r.URL.Query().Get("platform"))
		if platform != "" && platform != "macos" && platform != "windows" {
			http.Error(w, `platform must be "macos" or "windows"`, http.StatusBadRequest)
			return
		}

		// Build the query dynamically: add AND cr.platform = $2 when a filter
		// is provided, otherwise return all platforms.
		baseStmt := `
			SELECT
				cr.id::text,
				cr.rule_key,
				cr.title,
				cr.benchmark,
				cr.benchmark_version,
				cr.control_identifier,
				cr.collection_tier,
				cr.platform,
				cr.severity,
				tr.id::text,
				tr.enabled,
				tr.override_severity,
				tr.suppressed_until,
				tr.suppression_reason
			FROM compliance_rules cr
			LEFT JOIN tenant_rules tr
				ON tr.rule_id = cr.id
			   AND tr.tenant_id = $1::uuid
			WHERE cr.enabled = true`

		var rows interface {
			Next() bool
			Scan(...any) error
			Err() error
			Close()
		}
		var queryErr error

		if platform != "" {
			rows, queryErr = pool.Query(r.Context(),
				baseStmt+` AND cr.platform = $2 ORDER BY cr.collection_tier, cr.benchmark, cr.benchmark_version, cr.rule_key`,
				tenantID, platform)
		} else {
			rows, queryErr = pool.Query(r.Context(),
				baseStmt+` ORDER BY cr.platform, cr.collection_tier, cr.benchmark, cr.benchmark_version, cr.rule_key`,
				tenantID)
		}
		if queryErr != nil {
			logger.Error("query tenant rules failed", "err", queryErr, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		now := time.Now()
		var entries []tenantRuleEntry
		for rows.Next() {
			var e tenantRuleEntry
			var trID *string
			var trEnabled *bool
			var suppressedUntil *time.Time

			if err := rows.Scan(
				&e.RuleID, &e.RuleKey, &e.Title, &e.Benchmark, &e.BenchmarkVersion, &e.ControlIdentifier,
				&e.CollectionTier, &e.Platform, &e.GlobalSeverity,
				&trID, &trEnabled, &e.OverrideSeverity,
				&suppressedUntil, &e.SuppressionReason,
			); err != nil {
				logger.Error("scan row failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			e.TenantRuleID = trID
			e.SuppressedUntil = suppressedUntil

			// Effective enabled state.
			switch e.CollectionTier {
			case "T1":
				e.Enabled = true // T1 always evaluates; tenant_rules row only adds overrides
			case "T2":
				e.Enabled = trEnabled != nil && *trEnabled
			}

			// Suppressed = suppressed_until is set and in the future.
			e.Suppressed = suppressedUntil != nil && suppressedUntil.After(now)

			entries = append(entries, e)
		}
		if err := rows.Err(); err != nil {
			logger.Error("iterate rows failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		evaluatedCounts, evalErr := fetchEvaluatedDeviceCounts(r.Context(), pool, tenantID)
		if evalErr != nil {
			logger.Error("query evaluated device counts failed", "err", evalErr, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		for i := range entries {
			entries[i].EvaluatedDevices = evaluatedCounts[entries[i].RuleID]
		}

		if entries == nil {
			entries = []tenantRuleEntry{} // never null in JSON
		}

		logger.Info("tenant rules listed", "tenant_id", tenantID, "platform", platform, "count", len(entries))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tenantRulesListResp{TenantID: tenantID, Rules: entries})
	}
}

// fetchEvaluatedDeviceCounts returns, per rule_id, the count of distinct
// tenant devices that have a latest compliance_evaluations row for that
// rule — regardless of pass/fail/error status. This is the correct
// denominator for a per-rule pass rate (PAT-1690): a platform-scoped rule
// is never evaluated against devices on the other platform, so the
// tenant's raw device total silently counts them as implicit passes.
// Same "latest distinct-on" shape as executive.go's fetchTopFailingControls.
func fetchEvaluatedDeviceCounts(ctx context.Context, pool *pgxpool.Pool, tenantID string) (map[string]int, error) {
	rows, err := pool.Query(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (e.device_id, e.rule_id)
				e.device_id, e.rule_id
			FROM compliance_evaluations e
			JOIN devices d ON d.id = e.device_id
			WHERE d.tenant_id = $1
			ORDER BY e.device_id, e.rule_id, e.evaluated_at DESC
		)
		SELECT rule_id::text, COUNT(DISTINCT device_id)::int
		FROM latest
		GROUP BY rule_id
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("evaluated device counts: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var ruleID string
		var n int
		if err := rows.Scan(&ruleID, &n); err != nil {
			return nil, fmt.Errorf("scan evaluated device count: %w", err)
		}
		counts[ruleID] = n
	}
	return counts, rows.Err()
}

// tenantRulePutReq is the PUT request body.
type tenantRulePutReq struct {
	Enabled           bool    `json:"enabled"`
	OverrideSeverity  *string `json:"override_severity"`  // null = reset to global
	SuppressionReason *string `json:"suppression_reason"` // null = clear
	SuppressedUntil   *string `json:"suppressed_until"`   // RFC3339 or null
}

type tenantRulePutResp struct {
	TenantRuleID      string     `json:"tenant_rule_id"`
	TenantID          string     `json:"tenant_id"`
	RuleID            string     `json:"rule_id"`
	Enabled           bool       `json:"enabled"`
	OverrideSeverity  *string    `json:"override_severity"`
	SuppressionReason *string    `json:"suppression_reason"`
	SuppressedUntil   *time.Time `json:"suppressed_until"`
	ChangesLogged     int        `json:"changes_logged"`
}

// TenantRulesPutHandler upserts a tenant_rules row and records audit log entries
// for each semantic change (enable/disable, severity override, suppression).
func TenantRulesPutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenant_rules_put")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		ruleID := strings.TrimSpace(chi.URLParam(r, "ruleID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		if !looksLikeUUID(ruleID) {
			http.Error(w, "ruleID must be a UUID", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<14))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var req tenantRulePutReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.OverrideSeverity != nil {
			switch *req.OverrideSeverity {
			case "low", "medium", "high", "critical":
			default:
				http.Error(w, "override_severity must be low, medium, high, or critical", http.StatusBadRequest)
				return
			}
		}

		var suppressedUntil *time.Time
		if req.SuppressedUntil != nil {
			t, parseErr := time.Parse(time.RFC3339, *req.SuppressedUntil)
			if parseErr != nil {
				http.Error(w, "suppressed_until must be RFC3339", http.StatusBadRequest)
				return
			}
			suppressedUntil = &t
		}

		tx, err := pool.BeginTx(r.Context(), pgx.TxOptions{})
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		// Read current state for change detection.
		var prevEnabled *bool
		var prevSeverity *string
		var prevSuppressedUntil *time.Time
		err = tx.QueryRow(r.Context(), `
			SELECT enabled, override_severity, suppressed_until
			FROM tenant_rules
			WHERE tenant_id = $1::uuid AND rule_id = $2::uuid
		`, tenantID, ruleID).Scan(&prevEnabled, &prevSeverity, &prevSuppressedUntil)
		rowExisted := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			logger.Error("fetch current state failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Upsert the tenant_rules row.
		var newTenantRuleID string
		err = tx.QueryRow(r.Context(), `
			INSERT INTO tenant_rules
				(tenant_id, rule_id, enabled, override_severity, suppression_reason, suppressed_until)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)
			ON CONFLICT (tenant_id, rule_id) DO UPDATE
				SET enabled            = EXCLUDED.enabled,
				    override_severity  = EXCLUDED.override_severity,
				    suppression_reason = EXCLUDED.suppression_reason,
				    suppressed_until   = EXCLUDED.suppressed_until,
				    updated_at         = now()
			RETURNING id::text
		`, tenantID, ruleID, req.Enabled, req.OverrideSeverity, req.SuppressionReason, suppressedUntil,
		).Scan(&newTenantRuleID)
		if err != nil {
			logger.Error("upsert tenant_rules failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Compute and write audit log entries.
		changes := computeTenantRuleChanges(
			prevEnabled, rowExisted, req.Enabled,
			prevSeverity, req.OverrideSeverity,
			prevSuppressedUntil, suppressedUntil, req.SuppressionReason,
		)
		// PAT-1135: changed_by (via actor below) records the server-
		// established shared-token principal — this request body carries no
		// actor field at all today, so there is no caller-supplied claim to
		// record; claimed_actor stays NULL. source_addr records the
		// observed client IP. See internal/handlers/audit_attribution.go.
		actor, claimedActor, sourceAddr := auditAttribution(r, "")
		for _, ch := range changes {
			if _, err := tx.Exec(r.Context(), `
				INSERT INTO tenant_rule_changes
					(tenant_id, rule_id, change_type,
					 old_enabled, new_enabled,
					 old_severity, new_severity,
					 suppression_reason, suppressed_until,
					 changed_by, claimed_actor, source_addr)
				VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			`, tenantID, ruleID, ch.changeType,
				ch.oldEnabled, ch.newEnabled,
				ch.oldSeverity, ch.newSeverity,
				ch.suppressionReason, ch.suppressedUntil,
				actor, claimedActor, sourceAddr,
			); err != nil {
				logger.Error("insert change log failed", "err", err, "change_type", ch.changeType)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("tenant rule upserted",
			"tenant_id", tenantID,
			"rule_id", ruleID,
			"enabled", req.Enabled,
			"changes_logged", len(changes),
		)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tenantRulePutResp{
			TenantRuleID:      newTenantRuleID,
			TenantID:          tenantID,
			RuleID:            ruleID,
			Enabled:           req.Enabled,
			OverrideSeverity:  req.OverrideSeverity,
			SuppressionReason: req.SuppressionReason,
			SuppressedUntil:   suppressedUntil,
			ChangesLogged:     len(changes),
		})
	}
}

// TenantRulesDeleteHandler removes a tenant_rules row and logs the deactivation.
//
// For T2 rules, removal means the rule is no longer evaluated for the tenant.
// For T1 rules, removal clears any severity override or suppression window
// (the rule continues to evaluate with global defaults).
func TenantRulesDeleteHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenant_rules_delete")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		ruleID := strings.TrimSpace(chi.URLParam(r, "ruleID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		if !looksLikeUUID(ruleID) {
			http.Error(w, "ruleID must be a UUID", http.StatusBadRequest)
			return
		}

		tx, err := pool.BeginTx(r.Context(), pgx.TxOptions{})
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		// Read current state for the audit log before deleting.
		var prevEnabled bool
		var prevSeverity *string
		err = tx.QueryRow(r.Context(), `
			SELECT enabled, override_severity
			FROM tenant_rules
			WHERE tenant_id = $1::uuid AND rule_id = $2::uuid
		`, tenantID, ruleID).Scan(&prevEnabled, &prevSeverity)
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "tenant rule not found", http.StatusNotFound)
			return
		}
		if err != nil {
			logger.Error("fetch tenant rule failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if _, err := tx.Exec(r.Context(), `
			DELETE FROM tenant_rules
			WHERE tenant_id = $1::uuid AND rule_id = $2::uuid
		`, tenantID, ruleID); err != nil {
			logger.Error("delete tenant rule failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		newEnabled := false
		// PAT-1135: see the identical note in TenantRulesPutHandler above —
		// no actor field in this request either, so claimed_actor is NULL.
		actor, claimedActor, sourceAddr := auditAttribution(r, "")
		if _, err := tx.Exec(r.Context(), `
			INSERT INTO tenant_rule_changes
				(tenant_id, rule_id, change_type, old_enabled, new_enabled, old_severity, new_severity, changed_by, claimed_actor, source_addr)
			VALUES ($1::uuid, $2::uuid, 'disabled', $3, $4, $5, NULL, $6, $7, $8)
		`, tenantID, ruleID, prevEnabled, newEnabled, prevSeverity, actor, claimedActor, sourceAddr); err != nil {
			logger.Error("insert change log failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("tenant rule deleted", "tenant_id", tenantID, "rule_id", ruleID)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"deleted": true})
	}
}

// tenantRuleChangeEntry is one row to insert into tenant_rule_changes.
type tenantRuleChangeEntry struct {
	changeType        string
	oldEnabled        *bool
	newEnabled        *bool
	oldSeverity       *string
	newSeverity       *string
	suppressionReason *string
	suppressedUntil   *time.Time
}

// computeTenantRuleChanges diffs old vs new state and returns one entry per
// semantic change. Callers insert one tenant_rule_changes row per entry.
func computeTenantRuleChanges(
	prevEnabled *bool, rowExisted bool, newEnabled bool,
	prevSeverity, newSeverity *string,
	prevSuppressedUntil, newSuppressedUntil *time.Time,
	suppressionReason *string,
) []tenantRuleChangeEntry {
	var out []tenantRuleChangeEntry
	now := time.Now()

	wasEnabled := rowExisted && prevEnabled != nil && *prevEnabled
	if wasEnabled != newEnabled {
		old := wasEnabled
		nw := newEnabled
		ct := "enabled"
		if !newEnabled {
			ct = "disabled"
		}
		out = append(out, tenantRuleChangeEntry{changeType: ct, oldEnabled: &old, newEnabled: &nw})
	}

	prevSev := ""
	if prevSeverity != nil {
		prevSev = *prevSeverity
	}
	newSev := ""
	if newSeverity != nil {
		newSev = *newSeverity
	}
	if prevSev != newSev {
		ct := "severity_overridden"
		if newSeverity == nil {
			ct = "severity_reset"
		}
		out = append(out, tenantRuleChangeEntry{changeType: ct, oldSeverity: prevSeverity, newSeverity: newSeverity})
	}

	wasSuppressed := prevSuppressedUntil != nil && prevSuppressedUntil.After(now)
	isSuppressed := newSuppressedUntil != nil && newSuppressedUntil.After(now)
	if wasSuppressed != isSuppressed {
		ct := "suppressed"
		if !isSuppressed {
			ct = "unsuppressed"
		}
		out = append(out, tenantRuleChangeEntry{
			changeType:        ct,
			suppressionReason: suppressionReason,
			suppressedUntil:   newSuppressedUntil,
		})
	}

	return out
}
