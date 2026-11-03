package handlers

// Trial admin endpoints (PAT-670).
//
// GET  /admin/tenants/trials               — list all is_trial tenants with
//                                            expiry, email-sent status, device
//                                            count, and failing-eval count.
//                                            Optional ?state= filter:
//                                              expiring_soon — within 2 days,
//                                                               email not sent
//                                              expired        — past expiry
//                                            (no filter) — all trial tenants.
//
// POST /admin/tenants/{tenantID}/trial-notify — idempotently set
//                                               upgrade_email_sent_at = now().
//                                               Returns {"ok":true} (200) on
//                                               success, or
//                                               {"ok":true,"already_sent":true}
//                                               (200) if already set.
//
// Routes are registered on the internal :8081 listener (no public auth).
// Static sub-path /admin/tenants/trials must be registered before
// /admin/tenants/{tenantID}/... in chi to avoid routing ambiguity.

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------------------------------------------------------------------------
// GET /admin/tenants/trials
// ---------------------------------------------------------------------------

// trialEntry is one row in the GET /admin/tenants/trials response.
type trialEntry struct {
	TenantID           string     `json:"tenant_id"`
	Name               string     `json:"name"`
	TrialEmail         string     `json:"trial_email"`
	TrialExpiresAt     *time.Time `json:"trial_expires_at"`
	UpgradeEmailSentAt *time.Time `json:"upgrade_email_sent_at"`
	DeviceCount        int        `json:"device_count"`
	FailingEvalCount   int        `json:"failing_eval_count"`
	// UndeterminedEvalCount is the number of the tenant's latest evaluations
	// that resolved to fail with no observed value (PAT-1758/PAT-1762/
	// PAT-1776) — unreadable evidence, not a real observation of
	// non-compliance. Excluded from FailingEvalCount above; reported here so
	// it is never silently dropped.
	UndeterminedEvalCount int `json:"undetermined_eval_count"`
	// State is derived server-side for convenience:
	//   "active"         — running, no email sent
	//   "expiring_soon"  — within 2 days of expiry, email not yet sent
	//   "notified"       — upgrade email was sent
	//   "expired"        — trial_expires_at is in the past
	State string `json:"state"`
}

type trialsListResp struct {
	Trials []trialEntry `json:"trials"`
}

// TrialTenantsListHandler serves GET /admin/tenants/trials.
//
// Query parameters:
//
//	?state=expiring_soon  — within 2 days of expiry AND upgrade_email_sent_at IS NULL
//	?state=expired        — trial_expires_at <= now()
//	(no filter)           — all is_trial non-revoked tenants
//
// Failing eval count is computed from the latest compliance evaluation per
// (device, rule) with status = 'error', or status = 'fail' with a non-nil
// observed value — the same deduplification and undetermined-evidence
// exclusion (PAT-1758/PAT-1762/PAT-1776) used in FetchTenantFindings. A
// 'fail' row with no observed value is unreadable evidence, not a real
// non-compliance finding; it is counted separately as
// undetermined_eval_count.
func TrialTenantsListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "trial_tenants_list")

		stateParam := r.URL.Query().Get("state")

		// Build WHERE clause extension — strings are fully controlled by the
		// switch (no user input interpolated).
		var stateFilter string
		switch stateParam {
		case "expiring_soon":
			stateFilter = `AND t.trial_expires_at > now()
              AND t.trial_expires_at <= now() + interval '2 days'
              AND t.upgrade_email_sent_at IS NULL`
		case "expired":
			stateFilter = `AND t.trial_expires_at <= now()`
		default:
			stateFilter = ""
		}

		query := `
			WITH trial_tenants AS (
				SELECT t.id, t.name, t.trial_email, t.trial_expires_at, t.upgrade_email_sent_at
				FROM tenants t
				WHERE t.is_trial = true
				  AND t.revoked_at IS NULL
				  ` + stateFilter + `
			),
			trial_devices AS (
				SELECT d.id AS device_id, d.tenant_id
				FROM devices d
				WHERE d.tenant_id IN (SELECT id FROM trial_tenants)
			),
			latest_evals AS (
				SELECT DISTINCT ON (ce.device_id, ce.rule_id)
					ce.device_id,
					ce.status,
					ce.observed_value
				FROM compliance_evaluations ce
				WHERE ce.device_id IN (SELECT device_id FROM trial_devices)
				ORDER BY ce.device_id, ce.rule_id, ce.evaluated_at DESC
			),
			-- PAT-1776: a 'fail' row with no observed value is unreadable
			-- evidence (an absent signal, or the collector's literal
			-- "Unknown" sentinel), not a real observation of non-compliance —
			-- same predicate as isUndeterminedEval (internal/report/pdf.go).
			-- Excluded from failing_count; counted separately as
			-- undetermined_count instead of being silently dropped. An
			-- 'error' row is never undetermined by this rule and stays
			-- counted in failing_count. A "NotConfigured" fail has a non-nil
			-- observed value and stays a real, counted fail.
			failing_by_tenant AS (
				SELECT
					td.tenant_id,
					COUNT(*) FILTER (
						WHERE le.status = 'error'
						   OR (le.status = 'fail' AND le.observed_value IS NOT NULL)
					)::int AS failing_count,
					COUNT(*) FILTER (
						WHERE le.status = 'fail' AND le.observed_value IS NULL
					)::int AS undetermined_count
				FROM latest_evals le
				JOIN trial_devices td ON td.device_id = le.device_id
				WHERE le.status IN ('fail', 'error')
				GROUP BY td.tenant_id
			),
			device_count_by_tenant AS (
				SELECT tenant_id, COUNT(*)::int AS device_count
				FROM trial_devices
				GROUP BY tenant_id
			)
			SELECT
				tt.id::text,
				tt.name,
				COALESCE(tt.trial_email, ''),
				tt.trial_expires_at,
				tt.upgrade_email_sent_at,
				COALESCE(dc.device_count,        0)::int,
				COALESCE(fb.failing_count,       0)::int,
				COALESCE(fb.undetermined_count,  0)::int
			FROM trial_tenants tt
			LEFT JOIN device_count_by_tenant dc ON dc.tenant_id = tt.id
			LEFT JOIN failing_by_tenant       fb ON fb.tenant_id = tt.id
			ORDER BY tt.trial_expires_at ASC NULLS LAST
		`

		rows, err := pool.Query(r.Context(), query)
		if err != nil {
			logger.Error("query trial tenants failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var trials []trialEntry
		for rows.Next() {
			var te trialEntry
			if err := rows.Scan(
				&te.TenantID, &te.Name, &te.TrialEmail,
				&te.TrialExpiresAt, &te.UpgradeEmailSentAt,
				&te.DeviceCount, &te.FailingEvalCount, &te.UndeterminedEvalCount,
			); err != nil {
				logger.Error("scan trial row failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			te.State = trialState(te.TrialExpiresAt, te.UpgradeEmailSentAt)
			trials = append(trials, te)
		}
		if err := rows.Err(); err != nil {
			logger.Error("trial tenants rows error", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if trials == nil {
			trials = []trialEntry{}
		}

		logger.Info("trial tenants listed", "count", len(trials), "state_filter", stateParam)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(trialsListResp{Trials: trials})
	}
}

// trialState derives a human-readable state string from expiry and email
// timestamps. Used both in TrialTenantsListHandler and in tests.
func trialState(expiresAt *time.Time, emailSentAt *time.Time) string {
	now := time.Now()
	if expiresAt != nil && now.After(*expiresAt) {
		return "expired"
	}
	if expiresAt != nil && expiresAt.Before(now.Add(2*24*time.Hour)) && emailSentAt == nil {
		return "expiring_soon"
	}
	if emailSentAt != nil {
		return "notified"
	}
	return "active"
}

// ---------------------------------------------------------------------------
// POST /admin/tenants/{tenantID}/trial-notify
// ---------------------------------------------------------------------------

// trialNotifyResp is returned by POST /admin/tenants/{tenantID}/trial-notify.
type trialNotifyResp struct {
	OK          bool `json:"ok"`
	AlreadySent bool `json:"already_sent,omitempty"`
}

// TrialNotifyHandler serves POST /admin/tenants/{tenantID}/trial-notify.
//
// Sets upgrade_email_sent_at = now() idempotently (only if currently NULL).
// Returns:
//   - 200 {"ok":true}                    — marked for the first time
//   - 200 {"ok":true,"already_sent":true} — already marked; no-op
//   - 400                                — tenantID is not a UUID or not a trial tenant
//   - 404                                — tenant not found / revoked
//   - 500                                — database error
func TrialNotifyHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "trial_notify")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		// Fetch current trial state.
		var isTrial bool
		var existingEmailSentAt *time.Time
		err := pool.QueryRow(r.Context(), `
			SELECT is_trial, upgrade_email_sent_at
			FROM tenants
			WHERE id = $1::uuid
			  AND revoked_at IS NULL
		`, tenantID).Scan(&isTrial, &existingEmailSentAt)
		if isNoRowsErr(err) {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}
		if err != nil {
			logger.Error("fetch trial tenant failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !isTrial {
			http.Error(w, "not a trial tenant", http.StatusBadRequest)
			return
		}

		// Idempotent: if email was already sent, return without writing.
		if existingEmailSentAt != nil {
			logger.Info("trial notify already sent",
				"tenant_id", tenantID, "sent_at", existingEmailSentAt)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(trialNotifyResp{OK: true, AlreadySent: true})
			return
		}

		// Mark as notified. The WHERE upgrade_email_sent_at IS NULL is a
		// belt-and-suspenders guard against a concurrent double-write.
		_, err = pool.Exec(r.Context(), `
			UPDATE tenants
			SET upgrade_email_sent_at = now()
			WHERE id = $1::uuid
			  AND upgrade_email_sent_at IS NULL
		`, tenantID)
		if err != nil {
			logger.Error("set upgrade_email_sent_at failed",
				"err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("trial notify marked", "tenant_id", tenantID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(trialNotifyResp{OK: true})
	}
}
