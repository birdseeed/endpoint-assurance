package handlers

// PAT-1399 mandatory-install intents. Evaluation, emergency, retry and
// agent-config delivery were retired with the signed catalogue they verified
// against (PAT-2246), so no new intent can be created or delivered. What
// remains is read-only intent history, authenticated state receipts for any
// intent already delivered, and cancellation when a mandatory policy changes.
// It never executes an installer.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	"patched.im/api/internal/auth"
	"patched.im/api/internal/ratelimit"
)

// Automatic redelivery is deliberately bounded. Three authenticated delivery
// attempts give an offline device a useful recovery window while preventing a
// permanently non-consuming agent from appending retry history forever. After
// this ceiling the expired row is parked for the reasoned admin retry action.
const mandatoryAutomaticRedeliveryMaxAttempts = 3

const mandatoryLastErrorMaxBytes = 1024

// All tenant policy mutation takes this transaction-scoped advisory lock
// before row locks. This single
// order prevents policy->intent and intent->policy deadlocks while preserving
// an atomic current-policy authority decision.
func lockMandatoryTenantPolicy(ctx context.Context, tx pgx.Tx, tenantID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, tenantID+"|mandatory-policy-authority")
	return err
}

// MandatoryInstallIntentsGetHandler exposes current state and immutable target
// provenance for operator reconciliation. Event history remains append-only in
// mandatory_install_intent_events and is summarized by attempt count here.
func MandatoryInstallIntentsGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "mandatory_install_intents_get", "tenant_id", tenantID)
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		limit := 100
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 1 || parsed > 500 {
				http.Error(w, "limit must be between 1 and 500", http.StatusBadRequest)
				return
			}
			limit = parsed
		}
		stateFilter := strings.TrimSpace(r.URL.Query().Get("state"))
		if stateFilter != "" && !map[string]bool{"queued": true, "delivered": true, "received": true, "installing": true, "succeeded": true, "failed": true, "cancelled": true}[stateFilter] {
			http.Error(w, "state filter is invalid", http.StatusBadRequest)
			return
		}
		var after *time.Time
		var afterID *string
		if raw := strings.TrimSpace(r.URL.Query().Get("after")); raw != "" {
			parsed, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				http.Error(w, "after must be RFC3339", http.StatusBadRequest)
				return
			}
			after = &parsed
			rawID := strings.TrimSpace(r.URL.Query().Get("after_id"))
			if !looksLikeUUID(rawID) {
				http.Error(w, "after_id must be a UUID when after is set", http.StatusBadRequest)
				return
			}
			afterID = &rawID
		}
		rows, err := pool.Query(r.Context(), `
			WITH page AS (
				SELECT i.* FROM mandatory_install_intents i
				WHERE i.tenant_id=$1::uuid AND ($2='' OR i.state=$2)
				  AND ($3::timestamptz IS NULL OR i.created_at>$3 OR (i.created_at=$3 AND i.id>$4::uuid))
				ORDER BY i.created_at,i.id LIMIT $5
			)
			SELECT i.id::text,i.device_id::text,i.policy_id,i.catalogue_product_id::text,
			       i.catalogue_target_id::text,i.platform,i.label,i.target_version,
			       i.verified_sha256,i.verified_signer,i.rollout_ring,i.emergency,
			       i.reason,i.state,i.delivery_attempt,i.delivery_id::text,
			       i.delivered_at,i.expires_at,i.completed_at,i.last_error,i.operator_recovery_reason,
			       i.created_at,i.updated_at,
		       (SELECT count(*) FROM mandatory_install_intent_events e WHERE e.intent_id=i.id),now()
			FROM page i ORDER BY i.created_at,i.id`, tenantID, stateFilter, after, afterID, limit)
		if err != nil {
			logger.Error("query mandatory install intents failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		items := []map[string]any{}
		for rows.Next() {
			var id, deviceID, productID, targetID, platform, label, version, sha, signer, reason, state string
			var policyID *int64
			var ring, attempt int
			var emergency bool
			var deliveryID, lastError, operatorRecoveryReason *string
			var deliveredAt, expiresAt, completedAt *time.Time
			var createdAt, updatedAt, dbNow time.Time
			var eventCount int
			if err := rows.Scan(&id, &deviceID, &policyID, &productID, &targetID, &platform, &label, &version, &sha, &signer, &ring, &emergency, &reason, &state, &attempt, &deliveryID, &deliveredAt, &expiresAt, &completedAt, &lastError, &operatorRecoveryReason, &createdAt, &updatedAt, &eventCount, &dbNow); err != nil {
				logger.Error("scan mandatory install intent failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			retryRequired := (state == "delivered" || state == "received" || state == "installing") && expiresAt != nil && !expiresAt.After(dbNow)
			retryReason := ""
			if retryRequired {
				if state == "delivered" {
					if attempt >= mandatoryAutomaticRedeliveryMaxAttempts {
						retryReason = "automatic redelivery attempt ceiling reached; explicit reasoned retry required"
					} else {
						retryReason = "delivery expired before start; authenticated check-in will safely redeliver if durable history still proves no start"
					}
				} else {
					retryReason = "started attempt expired; explicit acknowledged stale-attempt recovery required"
				}
			}
			items = append(items, map[string]any{"id": id, "device_id": deviceID, "policy_id": policyID, "catalogue_product_id": productID, "catalogue_target_id": targetID, "platform": platform, "label": label, "version": version, "sha256": sha, "verified_signer": signer, "rollout_ring": ring, "emergency": emergency, "reason": reason, "state": state, "attempt": attempt, "delivery_id": deliveryID, "delivered_at": deliveredAt, "expires_at": expiresAt, "completed_at": completedAt, "last_error": lastError, "operator_recovery_reason": operatorRecoveryReason, "created_at": createdAt, "updated_at": updatedAt, "event_count": eventCount, "retry_required": retryRequired, "retry_reason": retryReason})
		}
		if err := rows.Err(); err != nil {
			logger.Error("iterate mandatory install intents failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		next := ""
		nextID := ""
		if len(items) == limit {
			next = items[len(items)-1]["created_at"].(time.Time).UTC().Format(time.RFC3339Nano)
			nextID = items[len(items)-1]["id"].(string)
		}
		writeMandatoryJSON(w, http.StatusOK, map[string]any{"intents": items, "next_after": next, "next_after_id": nextID})
	}
}

type mandatoryInstallStatusReq struct {
	ReportID             string `json:"report_id"`
	IntentID             string `json:"intent_id"`
	DeliveryID           string `json:"delivery_id"`
	CatalogueProductID   string `json:"catalogue_product_id"`
	CatalogueTargetID    string `json:"catalogue_target_id"`
	Platform             string `json:"platform"`
	Label                string `json:"label"`
	Version              string `json:"version"`
	SHA256               string `json:"sha256"`
	VerifiedSigner       string `json:"verified_signer"`
	CatalogueContentHash string `json:"catalogue_content_hash"`
	State                string `json:"state"`
	Error                string `json:"error,omitempty"`
}

func mandatoryStatusErrorWithinLimit(value string) bool {
	return len([]byte(value)) <= mandatoryLastErrorMaxBytes
}

var mandatoryTransitions = map[string]map[string]bool{
	"delivered":  {"received": true, "failed": true},
	"received":   {"installing": true, "failed": true},
	"installing": {"succeeded": true, "failed": true},
}

func allowExpiredMandatoryReceipt(state, requestedState string, durableReceived, durableInstalling, operatorStale bool) bool {
	activeDelivery := state == "delivered" || state == "received" || state == "installing"
	if !activeDelivery && !(state == "failed" && operatorStale) {
		return false
	}
	switch requestedState {
	case "succeeded":
		return durableInstalling
	case "failed":
		return state == "received" || state == "installing" || durableReceived || durableInstalling
	default:
		return false
	}
}

func MandatoryInstallStatusHandler(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter, replaySkew time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "mandatory_install_status")
		body, err := readMandatoryInstallStatusBody(w, r)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "read body", 400)
			return
		}
		tenantID, deviceID, secret, err := auth.LookupDeviceByBearer(r.Context(), pool, r.Header.Get("Authorization"))
		if err != nil {
			http.Error(w, "unauthorized", 401)
			return
		}
		if err := auth.VerifyHMACSignedStrict(secret, r.Method, auth.EndpointMandatoryInstallStatus, r.Header.Get("X-Patched-Timestamp"), r.Header.Get("X-Patched-Nonce"), body, r.Header.Get("X-Patched-Signature")); err != nil {
			http.Error(w, "unauthorized", 401)
			return
		}
		if rl != nil {
			if ok, retry := rl.Allow(tenantID); !ok {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retry.Seconds())+1))
				http.Error(w, "rate limit exceeded", 429)
				return
			}
		}
		if err := auth.ValidateTimestamp(r.Header.Get("X-Patched-Timestamp"), replaySkew); err != nil {
			http.Error(w, "unauthorized", 401)
			return
		}
		if err := auth.CheckAndStoreNonce(r.Context(), pool, tenantID, r.Header.Get("X-Patched-Nonce"), replaySkew); err != nil {
			http.Error(w, "unauthorized", 401)
			return
		}
		var req mandatoryInstallStatusReq
		dec := json.NewDecoder(strings.NewReader(string(body)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", 400)
			return
		}
		if err := dec.Decode(&struct{}{}); err != io.EOF {
			http.Error(w, "request body must contain one JSON object", 400)
			return
		}
		if !looksLikeUUID(req.ReportID) || !looksLikeUUID(req.IntentID) || !looksLikeUUID(req.DeliveryID) {
			http.Error(w, "report_id, intent_id and delivery_id must be UUIDs", 400)
			return
		}
		if !map[string]bool{"received": true, "installing": true, "succeeded": true, "failed": true}[req.State] {
			http.Error(w, "state must be received|installing|succeeded|failed", 400)
			return
		}
		if !mandatoryStatusErrorWithinLimit(req.Error) {
			http.Error(w, "error must be at most 1024 bytes", http.StatusBadRequest)
			return
		}
		tx, err := pool.BeginTx(r.Context(), pgx.TxOptions{})
		if err != nil {
			logger.Error("begin transaction failed", "err", err, "tenant_id", tenantID, "device_id", deviceID)
			http.Error(w, "internal error", 500)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()
		var state, productID, targetID, platform, label, version, sha, signer, contentHash string
		var deliveryID *string
		var attempt int
		var expires *time.Time
		var dbNow time.Time
		err = tx.QueryRow(r.Context(), `SELECT state,delivery_id::text,catalogue_product_id::text,catalogue_target_id::text,platform,label,target_version,verified_sha256,verified_signer,catalogue_content_hash,delivery_attempt,expires_at,now() FROM mandatory_install_intents WHERE id=$1::uuid AND tenant_id=$2::uuid AND device_id=$3::uuid FOR UPDATE`, req.IntentID, tenantID, deviceID).Scan(&state, &deliveryID, &productID, &targetID, &platform, &label, &version, &sha, &signer, &contentHash, &attempt, &expires, &dbNow)
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "intent not found", 404)
			return
		}
		if err != nil {
			logger.Error("load mandatory install intent failed", "err", err, "tenant_id", tenantID, "device_id", deviceID, "intent_id", req.IntentID)
			http.Error(w, "internal error", 500)
			return
		}
		if deliveryID == nil || expires == nil || *deliveryID != req.DeliveryID || productID != req.CatalogueProductID || targetID != req.CatalogueTargetID || platform != req.Platform || label != req.Label || version != req.Version || !strings.EqualFold(sha, req.SHA256) || signer != req.VerifiedSigner || contentHash != req.CatalogueContentHash {
			http.Error(w, "intent binding does not match signed delivery", 409)
			return
		}
		var priorState string
		err = tx.QueryRow(r.Context(), `SELECT to_state FROM mandatory_install_intent_events WHERE intent_id=$1::uuid AND report_id=$2::uuid`, req.IntentID, req.ReportID).Scan(&priorState)
		if err == nil {
			if priorState != req.State {
				http.Error(w, "report_id was already used for a different state", 409)
				return
			}
			if err := tx.Commit(r.Context()); err != nil {
				logger.Error("commit idempotent mandatory status failed", "err", err, "tenant_id", tenantID, "device_id", deviceID, "intent_id", req.IntentID)
				http.Error(w, "internal error", 500)
				return
			}
			writeMandatoryJSON(w, 200, map[string]any{"state": state, "idempotent": true})
			return
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			logger.Error("query idempotent mandatory report failed", "err", err, "tenant_id", tenantID, "device_id", deviceID, "intent_id", req.IntentID)
			http.Error(w, "internal error", 500)
			return
		}
		expired := dbNow.After(*expires)
		durableReceived, durableInstalling, operatorStale := false, false, false
		if expired || req.State == "succeeded" {
			if err := tx.QueryRow(r.Context(), `
				SELECT EXISTS (
					SELECT 1 FROM mandatory_install_intent_events
					WHERE intent_id=$1::uuid AND source='device' AND delivery_id=$2::uuid
					  AND attempt=$3 AND from_state='delivered' AND to_state='received'
				), EXISTS (
					SELECT 1
					FROM mandatory_install_intent_events received
					JOIN mandatory_install_intent_events installing
					  ON installing.intent_id=received.intent_id
					 AND installing.delivery_id=received.delivery_id
					 AND installing.attempt=received.attempt
					 AND installing.id>received.id
					WHERE received.intent_id=$1::uuid
					  AND received.delivery_id=$2::uuid AND received.attempt=$3
					  AND received.source='device' AND received.from_state='delivered' AND received.to_state='received'
					  AND installing.source='device' AND installing.from_state='received' AND installing.to_state='installing'
				), EXISTS (
					SELECT 1 FROM mandatory_install_intent_events
					WHERE intent_id=$1::uuid AND delivery_id=$2::uuid AND attempt=$3
					  AND source='retry' AND from_state IN ('received','installing') AND to_state='failed'
					  AND detail->>'acknowledged_duplicate_install_risk'='true'
					  AND detail->>'retry_ready'='true'
				)`, req.IntentID, req.DeliveryID, attempt).Scan(&durableReceived, &durableInstalling, &operatorStale); err != nil {
				logger.Error("query mandatory event chain failed", "err", err, "tenant_id", tenantID, "device_id", deviceID, "intent_id", req.IntentID)
				http.Error(w, "internal error", 500)
				return
			}
		}
		if expired {
			if !allowExpiredMandatoryReceipt(state, req.State, durableReceived, durableInstalling, operatorStale) {
				http.Error(w, "install intent has expired; new work is not authorized", 409)
				return
			}
		} else if !mandatoryTransitions[state][req.State] {
			http.Error(w, fmt.Sprintf("illegal state transition: %s -> %s", state, req.State), 409)
			return
		} else if req.State == "succeeded" && !durableInstalling {
			http.Error(w, "install success requires durable installing evidence for this delivery attempt", 409)
			return
		}
		_, err = tx.Exec(r.Context(), `UPDATE mandatory_install_intents SET state=$2,last_error=NULLIF($3,''),completed_at=CASE WHEN $2 IN ('succeeded','failed') THEN now() ELSE NULL END,updated_at=now() WHERE id=$1::uuid`, req.IntentID, req.State, req.Error)
		if err != nil {
			logger.Error("update mandatory status failed", "err", err, "tenant_id", tenantID, "device_id", deviceID, "intent_id", req.IntentID, "state", req.State)
			http.Error(w, "internal error", 500)
			return
		}
		detail, _ := json.Marshal(map[string]any{"error": req.Error, "accepted_after_expiry": expired, "durable_received_evidence": durableReceived, "durable_installing_evidence": durableInstalling})
		_, err = tx.Exec(r.Context(), `INSERT INTO mandatory_install_intent_events(intent_id,report_id,delivery_id,from_state,to_state,attempt,source,detail) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,'device',$7::jsonb)`, req.IntentID, req.ReportID, req.DeliveryID, state, req.State, attempt, detail)
		if err != nil {
			logger.Error("append mandatory status event failed", "err", err, "tenant_id", tenantID, "device_id", deviceID, "intent_id", req.IntentID, "state", req.State)
			http.Error(w, "internal error", 500)
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit mandatory status failed", "err", err, "tenant_id", tenantID, "device_id", deviceID, "intent_id", req.IntentID, "state", req.State)
			http.Error(w, "internal error", 500)
			return
		}
		writeMandatoryJSON(w, 200, map[string]any{"state": req.State, "idempotent": false})
	}
}

func readMandatoryInstallStatusBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
}

func writeMandatoryJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func cancelMandatoryPolicyIntentsTx(ctx context.Context, tx pgx.Tx, tenantID string, policyID int64, reason string) error {
	// Capture delivery provenance before clearing the active binding. A
	// cancelled intent must no longer look deliverable, but the append-only
	// event must still say whether the cancellation revoked a delivery already
	// issued and exactly which delivery/attempt/expiry that was.
	rows, err := tx.Query(ctx, `
		SELECT id::text,delivery_id::text,delivered_at,expires_at,delivery_attempt,state
		FROM mandatory_install_intents
		WHERE tenant_id=$1::uuid AND policy_id=$2 AND state IN ('queued','delivered')
		ORDER BY id FOR UPDATE`, tenantID, policyID)
	if err != nil {
		return err
	}
	defer rows.Close()
	type cancelled struct {
		id          string
		delivery    *string
		deliveredAt *time.Time
		expiresAt   *time.Time
		attempt     int
		from        string
	}
	var items []cancelled
	for rows.Next() {
		var item cancelled
		if err := rows.Scan(&item.id, &item.delivery, &item.deliveredAt, &item.expiresAt, &item.attempt, &item.from); err != nil {
			return err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	for _, item := range items {
		if item.from == "delivered" {
			var started bool
			// Separate post-lock statement for the same reason as retry: after
			// waiting on a status writer, this fresh snapshot must see its event.
			if err := tx.QueryRow(ctx, `
				SELECT EXISTS (
					SELECT 1 FROM mandatory_install_intent_events
					WHERE intent_id=$1::uuid AND source='device'
					  AND delivery_id=$2::uuid AND attempt=$3
					  AND to_state IN ('received','installing')
				)`, item.id, item.delivery, item.attempt).Scan(&started); err != nil {
				return err
			}
			if started {
				continue
			}
		}
		if _, err := tx.Exec(ctx, `
			UPDATE mandatory_install_intents
			SET state='cancelled',delivery_id=NULL,delivered_at=NULL,expires_at=NULL,
			    completed_at=now(),last_error=$2,updated_at=now()
			WHERE id=$1::uuid`, item.id, reason); err != nil {
			return err
		}
		detail, _ := json.Marshal(map[string]any{
			"reason":             reason,
			"prior_delivered_at": item.deliveredAt,
			"prior_expires_at":   item.expiresAt,
		})
		if _, err := tx.Exec(ctx, `INSERT INTO mandatory_install_intent_events(intent_id,delivery_id,from_state,to_state,attempt,source,detail) VALUES($1::uuid,$2::uuid,$3,'cancelled',$4,'policy',$5::jsonb)`, item.id, item.delivery, item.from, item.attempt, detail); err != nil {
			return err
		}
	}
	return nil
}
