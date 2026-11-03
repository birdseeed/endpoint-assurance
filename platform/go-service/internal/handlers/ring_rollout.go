package handlers

// Ring rollout handlers (PAT-117) — rollout status view and manual controls.
//
// Routes:
//
//	GET  /admin/tenants/{tenantID}/ring-rollouts
//	POST /admin/tenants/{tenantID}/ring-rollouts/{id}/pause
//	POST /admin/tenants/{tenantID}/ring-rollouts/{id}/resume
//	POST /admin/tenants/{tenantID}/ring-rollouts/{id}/skip

import (
	"context"
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

	"patched.im/api/internal/rings"
)

// -- Response types -----------------------------------------------------------

type ringRolloutEntry struct {
	ID             string        `json:"id"`
	Platform       string        `json:"platform"`
	Label          string        `json:"label"`
	Version        string        `json:"version"`
	ApprovedRing   int           `json:"approved_ring"`
	State          string        `json:"state"`
	LastAdvancedAt time.Time     `json:"last_advanced_at"`
	PausedReason   *string       `json:"paused_reason,omitempty"`
	PerRing        []ringWaveBar `json:"per_ring"`
}

type ringWaveBar struct {
	Ring      int `json:"ring"`
	Installed int `json:"installed"`
	Gated     int `json:"gated"`
	Failed    int `json:"failed"`
	Total     int `json:"total"`
}

type ringRolloutsResp struct {
	TenantID string             `json:"tenant_id"`
	Rollouts []ringRolloutEntry `json:"rollouts"`
	// Retained automatic rollout progression is permanently quarantined.
	AutoAdvanceEnabled bool   `json:"auto_advance_enabled"`
	AutoAdvanceNote    string `json:"auto_advance_note,omitempty"`
}

type ringRolloutActionReq struct {
	ChangedBy string `json:"changed_by"`
	Reason    string `json:"reason"`
}

// -- Handlers -----------------------------------------------------------------

// RingRolloutStatusHandler serves the live rollout/wave status for a tenant.
func RingRolloutStatusHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "ring_rollout_status")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		var exists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`,
			tenantID,
		).Scan(&exists); err != nil {
			logger.Error("tenant check failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		rows, err := pool.Query(r.Context(), `
			SELECT id::text, platform, label, version, approved_ring, state, last_advanced_at, paused_reason
			FROM ring_version_approvals
			WHERE tenant_id = $1::uuid AND state IN ('rolling', 'paused')
			ORDER BY last_advanced_at DESC
		`, tenantID)
		if err != nil {
			logger.Error("query rollouts failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var rollouts []ringRolloutEntry
		for rows.Next() {
			var e ringRolloutEntry
			if err := rows.Scan(
				&e.ID, &e.Platform, &e.Label, &e.Version,
				&e.ApprovedRing, &e.State, &e.LastAdvancedAt, &e.PausedReason,
			); err != nil {
				logger.Error("scan rollout row failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			e.PerRing = queryWaveBars(r.Context(), pool, tenantID, e.Platform, e.Label, e.Version, logger)
			rollouts = append(rollouts, e)
		}
		if err := rows.Err(); err != nil {
			logger.Error("iterate rollouts failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if rollouts == nil {
			rollouts = []ringRolloutEntry{}
		}

		logger.Info("ring rollouts listed", "tenant_id", tenantID, "count", len(rollouts))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ringRolloutsResp{
			TenantID:           tenantID,
			Rollouts:           rollouts,
			AutoAdvanceEnabled: false,
			AutoAdvanceNote:    "legacy rollout advancement is permanently quarantined",
		})
	}
}

// RingRolloutPauseHandler pauses a rolling rollout.
func RingRolloutPauseHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return rolloutActionHandler(pool, "pause", "rollout_paused", "rolling", "paused",
		func(a ringRolloutEntry) string { return "manual pause" })
}

// RingRolloutResumeHandler resumes a paused rollout.
// RingRolloutResumeHandler is the production route and cannot enable legacy
// execution.
func RingRolloutResumeHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return legacyExecutionDisabledHandler
}

// RingRolloutResumeHandlerForLegacyExecutionCompatibility exists only for
// retained compatibility tests. It must never be used in production wiring.
func RingRolloutResumeHandlerForLegacyExecutionCompatibility(pool *pgxpool.Pool) http.HandlerFunc {
	return rolloutActionHandler(pool, "resume", "rollout_resumed", "paused", "rolling", nil)
}

// RingRolloutSkipHandler advances a rollout one ring immediately, ignoring soak gap.
// RingRolloutSkipHandler is the production route and cannot enable legacy
// execution.
func RingRolloutSkipHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return ringRolloutSkipHandler(pool, false)
}

// RingRolloutSkipHandlerForLegacyExecutionCompatibility exists only for
// retained compatibility tests. It must never be used in production wiring.
func RingRolloutSkipHandlerForLegacyExecutionCompatibility(pool *pgxpool.Pool) http.HandlerFunc {
	return ringRolloutSkipHandler(pool, true)
}

func ringRolloutSkipHandler(pool *pgxpool.Pool, legacyExecutionEnabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !legacyExecutionEnabled {
			legacyExecutionDisabledHandler(w, r)
			return
		}
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "ring_rollout_skip")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		rolloutID := strings.TrimSpace(chi.URLParam(r, "id"))
		if !looksLikeUUID(tenantID) || !looksLikeUUID(rolloutID) {
			http.Error(w, "invalid UUID", http.StatusBadRequest)
			return
		}

		rawBody, err := io.ReadAll(io.LimitReader(r.Body, 1<<14))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var req ringRolloutActionReq
		_ = json.Unmarshal(rawBody, &req)
		if req.ChangedBy == "" {
			req.ChangedBy = "system"
		}

		tx, err := pool.BeginTx(r.Context(), pgx.TxOptions{})
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		var currentRing int
		var state string
		err = tx.QueryRow(r.Context(),
			`SELECT approved_ring, state FROM ring_version_approvals WHERE id = $1::uuid AND tenant_id = $2::uuid`,
			rolloutID, tenantID,
		).Scan(&currentRing, &state)
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "rollout not found", http.StatusNotFound)
			return
		}
		if err != nil {
			logger.Error("fetch rollout failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// A skip only means anything for an in-flight rollout. 'completed' and
		// 'superseded' are terminal (migrations/0042_patching_rings.sql pins
		// state to those four values), and advancing one of them would resurrect
		// a rollout the state machine has already closed. This check is for the
		// clear error message; the UPDATE below carries the same predicate and
		// is what actually enforces it under concurrency.
		if state != "rolling" && state != "paused" {
			http.Error(w, "rollout is not in rolling or paused state", http.StatusConflict)
			return
		}

		// PAT-1002 (defects 8 and 9). Two changes, both about the same thing:
		// manual skip is now the ONLY way a Windows rollout ever progresses
		// (processApproval skips automatic gating for Windows entirely), so it
		// has to be able to walk a rollout all the way to the end on its own.
		//
		//  a. The next ring comes from the tenant's configured ring list
		//     (rings.NextConfiguredRing) instead of currentRing+1 capped at 3.
		//     Agent ring values are non-contiguous for every ring_count except
		//     4 (ring_count 3 assigns devices to 0, 1 and 3, never 2), so
		//     incrementing numerically spent a skip moving the rollout onto a
		//     ring containing no devices, exposing the update to nobody.
		//  b. Skipping from the final configured ring now COMPLETES the
		//     rollout. Previously it clamped to 3 and left state 'rolling'
		//     forever: completion was only reachable via completeApproval,
		//     which lives on the automatic path and is unreachable while that
		//     path is off, or via emergency-deploy, which demands a reason and
		//     means something else. A Windows rollout could therefore be
		//     driven to GA but never closed out, sitting on the dashboard's
		//     active list indefinitely.
		//
		// ring_count is read per request rather than threaded through, and
		// defaults to 4 when a tenant has no ring config row, which is the
		// contiguous 0-1-2-3 space this handler assumed before.
		//
		// PAT-1002 (second review round): this query deliberately does NOT
		// filter on `enabled`. That asymmetry is intentional, not an oversight.
		//
		// `enabled` gates the AUTOMATIC path only — rings.advanceTenant returns
		// immediately when it is false, and ObserveNewVersions joins
		// tenant_ring_config on enabled = true, so a disabled tenant gets no
		// automatic gating and no new rollout rows. It does not gate manual
		// operator actions: pause, resume, skip and emergency-deploy all act on
		// whatever rollout rows exist, by design, because they are overrides.
		//
		// What ring_count describes is the ring SHAPE — which agent ring values
		// devices are actually assigned to. Disabling rings does not reshuffle
		// anybody: RingConfigPutHandler only calls RecomputeFleet/RecomputeFleetGA
		// when enabled is true, so a tenant disabled after configuring
		// ring_count=3 still has its devices sitting on agent rings 0, 1 and 3.
		// Ignoring that row and falling back to 4 would make a manual skip walk
		// 1 -> 2, a ring holding no devices — the phantom-ring stall this whole
		// ticket is about, reintroduced through the operator's own override.
		// Reading the configured shape regardless of `enabled` is the correct
		// behaviour; only a tenant with no row at all has no shape to read.
		ringCount := 4
		if err := tx.QueryRow(r.Context(),
			`SELECT ring_count FROM tenant_ring_config WHERE tenant_id = $1::uuid`, tenantID,
		).Scan(&ringCount); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			logger.Error("fetch ring config failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		newRing, hasNext := rings.NextConfiguredRing(currentRing, ringCount)
		newState := state
		if state == "paused" {
			newState = "rolling"
		}
		if !hasNext {
			// Already at (or past) the final configured ring: this skip is the
			// completion, not another advance. newRing is unchanged.
			newState = "completed"
		}

		// PAT-1002 (second review round): the UPDATE is guarded by the state and
		// approved_ring this request actually read, and a 0-row result is a
		// conflict rather than a success.
		//
		// Without the guard two concurrent skips on the same rollout both pass
		// the SELECT above (pgx runs at Read Committed, so neither sees the
		// other's uncommitted write), both compute the same "next ring" from the
		// same stale current ring, and both UPDATE. The second overwrites the
		// first with an identical row — so the rollout moves ONE ring while two
		// 200s and two 'rollout_skipped' audit rows say it moved two. The audit
		// log, which is the only record of who advanced what, silently disagrees
		// with reality.
		//
		// The state predicate alone does not close that: a rolling -> rolling
		// skip leaves state unchanged, so the loser's WHERE would still match.
		// Pinning approved_ring to the value this request read makes the write
		// a compare-and-set — the second transaction blocks on the row lock,
		// re-evaluates after the first commits, matches nothing, and returns
		// 409 before it can write its audit row. A skip that legitimately runs
		// after another has committed re-reads the new ring and is unaffected.
		//
		// SELECT ... FOR UPDATE would also work but is strictly more: it holds a
		// write lock from the read onward, serialising even requests that turn
		// out not to conflict. The WHERE guard is enough because the only thing
		// that must not happen twice is the write itself.
		tag, err := tx.Exec(r.Context(), `
			UPDATE ring_version_approvals
			SET approved_ring = $1, state = $2, paused_reason = NULL,
			    last_advanced_at = now(), updated_at = now()
			WHERE id = $3::uuid
			  AND state IN ('rolling', 'paused')
			  AND approved_ring = $4
		`, newRing, newState, rolloutID, currentRing)
		if err != nil {
			logger.Error("skip rollout failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if tag.RowsAffected() == 0 {
			// Another skip (or pause/resume/emergency-deploy) committed against
			// this rollout between our SELECT and our UPDATE. Nothing has been
			// written, the audit insert below never runs, and the caller can
			// re-read and retry.
			logger.Info("skip rollout conflicted — rollout changed concurrently, no-op",
				"tenant_id", tenantID, "rollout_id", rolloutID,
				"expected_ring", currentRing, "expected_state", state)
			http.Error(w, "rollout changed concurrently; re-read and retry", http.StatusConflict)
			return
		}

		if _, err := tx.Exec(r.Context(), `
			INSERT INTO ring_config_changes (tenant_id, change_type, changed_by, old_value, new_value)
			VALUES ($1::uuid, 'rollout_skipped', $2,
			        jsonb_build_object('ring', $3::int),
			        jsonb_build_object('ring', $4::int))
		`, tenantID, req.ChangedBy, currentRing, newRing); err != nil {
			logger.Error("insert audit log failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := rings.PublishRingPromotionsTx(r.Context(), tx, tenantID); err != nil {
			logger.Error("publish rollout decision failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("rollout skipped",
			"tenant_id", tenantID, "rollout_id", rolloutID,
			"from_ring", currentRing, "to_ring", newRing, "state", newState)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id": rolloutID, "approved_ring": newRing, "state": newState,
		})
	}
}

// RingRolloutEmergencyHandler immediately approves a rollout to GA (ring 3),
// bypassing all ring gates. Requires a non-empty reason in the request body.
// Used for zero-day emergency patches.
// RingRolloutEmergencyHandler is the production route and cannot enable
// legacy execution.
func RingRolloutEmergencyHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return ringRolloutEmergencyHandler(pool, false)
}

// RingRolloutEmergencyHandlerForLegacyExecutionCompatibility exists only for
// retained compatibility tests. It must never be used in production wiring.
func RingRolloutEmergencyHandlerForLegacyExecutionCompatibility(pool *pgxpool.Pool) http.HandlerFunc {
	return ringRolloutEmergencyHandler(pool, true)
}

func ringRolloutEmergencyHandler(pool *pgxpool.Pool, legacyExecutionEnabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !legacyExecutionEnabled {
			legacyExecutionDisabledHandler(w, r)
			return
		}
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "ring_rollout_emergency")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		rolloutID := strings.TrimSpace(chi.URLParam(r, "id"))
		if !looksLikeUUID(tenantID) || !looksLikeUUID(rolloutID) {
			http.Error(w, "invalid UUID", http.StatusBadRequest)
			return
		}

		rawBody, err := io.ReadAll(io.LimitReader(r.Body, 1<<14))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var req ringRolloutActionReq
		_ = json.Unmarshal(rawBody, &req)
		if req.Reason == "" {
			http.Error(w, "reason is required for emergency deploy", http.StatusBadRequest)
			return
		}
		if req.ChangedBy == "" {
			req.ChangedBy = "system"
		}

		tx, err := pool.BeginTx(r.Context(), pgx.TxOptions{})
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		var currentRing int
		var state string
		err = tx.QueryRow(r.Context(),
			`SELECT approved_ring, state FROM ring_version_approvals WHERE id = $1::uuid AND tenant_id = $2::uuid`,
			rolloutID, tenantID,
		).Scan(&currentRing, &state)
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "rollout not found", http.StatusNotFound)
			return
		}
		if err != nil {
			logger.Error("fetch rollout failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		newState := "rolling"
		if currentRing == 3 {
			newState = "completed"
		}

		tag, err := tx.Exec(r.Context(), `
			UPDATE ring_version_approvals
			SET approved_ring = 3, state = $1, paused_reason = NULL,
			    last_advanced_at = now(), updated_at = now()
			WHERE id = $2::uuid AND tenant_id = $3::uuid
			  AND state = $4 AND approved_ring = $5
			  AND state IN ('rolling', 'paused')
		`, newState, rolloutID, tenantID, state, currentRing)
		if err != nil {
			logger.Error("emergency deploy failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if tag.RowsAffected() == 0 {
			http.Error(w, "rollout changed concurrently; re-read and retry", http.StatusConflict)
			return
		}

		if _, err := tx.Exec(r.Context(), `
			INSERT INTO ring_config_changes (tenant_id, change_type, changed_by, old_value, new_value)
			VALUES ($1::uuid, 'rollout_emergency_deploy', $2,
			        jsonb_build_object('approved_ring', $3::int),
			        jsonb_build_object('approved_ring', 3, 'reason', $4))
		`, tenantID, req.ChangedBy, currentRing, req.Reason); err != nil {
			logger.Error("insert audit log failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := rings.PublishRingPromotionsTx(r.Context(), tx, tenantID); err != nil {
			logger.Error("publish rollout decision failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("emergency deploy",
			"tenant_id", tenantID, "rollout_id", rolloutID,
			"from_ring", currentRing, "reason", req.Reason)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id": rolloutID, "approved_ring": 3, "state": newState,
		})
	}
}

// legacyExecutionDisabledHandler rejects mutations that could create or widen
// legacy endpoint execution authority. Read-only rollout history and manual
// pause remain available so stale authority can still be inspected and reduced.
func legacyExecutionDisabledHandler(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "legacy execution compatibility is disabled", http.StatusServiceUnavailable)
}

// -- Helpers ------------------------------------------------------------------

// rolloutActionHandler is a generic handler factory for pause and resume.
func rolloutActionHandler(
	pool *pgxpool.Pool,
	action string,
	changeType string,
	requiredState string,
	newState string,
	reasonFn func(ringRolloutEntry) string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "ring_rollout_"+action)

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		rolloutID := strings.TrimSpace(chi.URLParam(r, "id"))
		if !looksLikeUUID(tenantID) || !looksLikeUUID(rolloutID) {
			http.Error(w, "invalid UUID", http.StatusBadRequest)
			return
		}

		rawBody, err := io.ReadAll(io.LimitReader(r.Body, 1<<14))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var req ringRolloutActionReq
		_ = json.Unmarshal(rawBody, &req)
		if req.ChangedBy == "" {
			req.ChangedBy = "system"
		}

		tx, err := pool.BeginTx(r.Context(), pgx.TxOptions{})
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		var current ringRolloutEntry
		err = tx.QueryRow(r.Context(),
			`SELECT id::text, platform, label, version, approved_ring, state
			 FROM ring_version_approvals
			 WHERE id = $1::uuid AND tenant_id = $2::uuid`,
			rolloutID, tenantID,
		).Scan(&current.ID, &current.Platform, &current.Label, &current.Version,
			&current.ApprovedRing, &current.State)
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "rollout not found", http.StatusNotFound)
			return
		}
		if err != nil {
			logger.Error("fetch rollout failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if current.State != requiredState {
			http.Error(w, "rollout is not in "+requiredState+" state", http.StatusConflict)
			return
		}

		reason := ""
		if reasonFn != nil {
			reason = reasonFn(current)
		}
		var reasonPtr *string
		if reason != "" {
			reasonPtr = &reason
		}

		tag, err := tx.Exec(r.Context(), `
			UPDATE ring_version_approvals
			SET state = $1, paused_reason = $2, last_advanced_at = now(), updated_at = now()
			WHERE id = $3::uuid AND tenant_id = $4::uuid
			  AND state = $5 AND approved_ring = $6
		`, newState, reasonPtr, rolloutID, tenantID, requiredState, current.ApprovedRing)
		if err != nil {
			logger.Error("update rollout state failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if tag.RowsAffected() == 0 {
			http.Error(w, "rollout changed concurrently; re-read and retry", http.StatusConflict)
			return
		}

		if _, err := tx.Exec(r.Context(), `
			INSERT INTO ring_config_changes (tenant_id, change_type, label, version, changed_by)
			VALUES ($1::uuid, $2, $3, $4, $5)
		`, tenantID, changeType, current.Label, current.Version, req.ChangedBy); err != nil {
			logger.Error("insert audit log failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := rings.PublishRingPromotionsTx(r.Context(), tx, tenantID); err != nil {
			logger.Error("publish rollout decision failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("rollout "+action,
			"tenant_id", tenantID, "rollout_id", rolloutID,
			"label", current.Label, "version", current.Version)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id": rolloutID, "state": newState,
		})
	}
}

// queryWaveBars fetches per-ring install/gated/failed counts from provenance_records.
//
// PAT-997 follow-up (Codex second pass) found the first version of this fix
// still had three of the same defects as queryFailureRate (advance.go, see
// its doc comment for full detail on each):
//
//   - Version match field was version_after/installed_version, which a failed
//     install never advances — so "failed" could never populate for a
//     genuine failure of the target version. Fixed by matching installed/
//     failed on available_version (the ATTEMPTED version, populated on both
//     outcomes) instead.
//   - No platform scope — e.Platform was never passed in, so macOS and
//     Windows records for the same label+version could bleed into each
//     other's wave bars. Fixed with COALESCE(body->>'platform','macos') = $2.
//   - No record_type guard against a client-forged non-update record (e.g.
//     'app_uninstall') supplying fields that happen to match.
//
// Third review round: the record_type guard above was itself wrong — a
// DENYLIST of just 'app_uninstall' let any OTHER forged record_type (e.g.
// 'inventory') through with update-shaped fields. Changed to an ALLOWLIST:
// permissive of an ABSENT record_type (Windows never sends one), but an
// explicit value must equal 'third_party_update' exactly — nothing else
// passes, forged or otherwise.
//
// One thing NOT changed: unlike queryFailureRate, this display query still
// dedupes to "this device's latest record for this label" WITHOUT also
// requiring that latest record be about the target version (version
// matching moved into the FILTER clauses below, not latest_prov's WHERE).
// That's deliberate, not an oversight: ring_gated records carry NO version
// field on either platform — patched-update.sh's ring_skip path sets
// available_ver="" unconditionally (it never runs the engine at all, so it
// never learns what version was withheld) — so a version-scoped WHERE would
// make "gated" permanently zero for every rollout, the same silent-blind-spot
// shape this whole ticket is about. Picking "latest record for this label,
// any version" and then filtering installed/failed (which DO carry
// available_version) by version in the COUNT FILTER, while counting gated
// without a version filter, is the most the data can honestly support: a
// gated count you can trust exists, in exchange for it meaning "gated on
// SOME version of this label most recently" rather than provably this exact
// one. No test existed for this function before this change; see
// TestQueryWaveBars_* in ring_rollout_db_test.go.
//
// hw_uuid is compared case-insensitively (lower() both sides), matching
// queryFailureRate in advance.go: devices.hw_uuid normalizes to lowercase on
// ::text cast, but macOS's IOPlatformUUID is conventionally uppercase — a
// bare equality check against production data confirmed this silently
// matches nothing otherwise. Not a ::uuid cast on the body-derived side,
// since body is arbitrary client JSON and a malformed value must fail the
// match rather than throw.
//
// Fifth review round: device_rings selected every device in the tenant
// regardless of platform, while only the provenance side was platform-
// filtered — so a mixed macOS/Windows estate had macOS devices diluting a
// Windows rollout's percentages (and vice versa) via the "total" denominator,
// even though "installed"/"gated"/"failed" were already correctly scoped.
// The regression test that existed for this (TestQueryWaveBars_PlatformScoped)
// asserted the WRONG thing — it expected a macOS device to appear in a
// Windows-platform query's Total, locking the defect in rather than catching
// it. Fixed with `AND lower(os) = $2` on device_rings (devices.os is
// "macOS"/"Windows" per migrations/0001_initial.sql; lower() matches the
// same "macos"/"windows" convention used for the platform parameter
// elsewhere in this query and in queryFailureRate).
func queryWaveBars(
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID, platform, label, version string,
	logger *slog.Logger,
) []ringWaveBar {
	rows, err := pool.Query(ctx, `
		WITH device_rings AS (
			SELECT id::text AS device_id,
			       lower(hw_uuid::text) AS hw_uuid,
			       COALESCE(ring_override, ring_computed, 3)::int AS ering
			FROM devices
			WHERE tenant_id = $1::uuid
			  AND lower(os) = $2
		),
		latest_prov AS (
			SELECT DISTINCT ON (lower(pr.body->'device'->>'hw_uuid'))
				lower(pr.body->'device'->>'hw_uuid') AS hw_uuid,
				COALESCE(pr.body->>'outcome', pr.body->>'state') AS outcome_or_state,
				COALESCE(pr.body->'app'->>'available_version', pr.body->>'available_version') AS attempted_version
			FROM provenance_records pr
			WHERE pr.tenant_id = $1::uuid
			  AND COALESCE(pr.body->>'platform', 'macos') = $2
			  AND COALESCE(pr.body->'app'->>'label', pr.body->>'label') = $3
			  AND pr.body->'device'->>'hw_uuid' IS NOT NULL
			  AND COALESCE(pr.body->>'record_type', 'third_party_update') = 'third_party_update'
			ORDER BY lower(pr.body->'device'->>'hw_uuid'), pr.received_at DESC
		)
		SELECT
			dr.ering                                                                                                                                           AS ring,
			COUNT(*) FILTER (WHERE lp.outcome_or_state IN ('installed', 'already_current', 'uptodate') AND lp.attempted_version = $4)                          AS installed,
			COUNT(*) FILTER (WHERE lp.outcome_or_state = 'ring_gated')                                                                                         AS gated,
			COUNT(*) FILTER (WHERE lp.outcome_or_state IN ('verification_failed', 'error', 'version_blocked', 'verificationfailed') AND lp.attempted_version = $4) AS failed,
			COUNT(*)                                                                                                                                           AS total
		FROM device_rings dr
		LEFT JOIN latest_prov lp ON lp.hw_uuid = dr.hw_uuid
		GROUP BY dr.ering
		ORDER BY dr.ering
	`, tenantID, platform, label, version)
	if err != nil {
		logger.Warn("query wave bars failed", "err", err)
		return nil
	}
	defer rows.Close()

	var bars []ringWaveBar
	for rows.Next() {
		var b ringWaveBar
		if err := rows.Scan(&b.Ring, &b.Installed, &b.Gated, &b.Failed, &b.Total); err != nil {
			continue
		}
		bars = append(bars, b)
	}
	return bars
}
