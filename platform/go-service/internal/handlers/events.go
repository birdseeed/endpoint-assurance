package handlers

// POST /v1/events — durable ingestion for the SIEM-style security audit
// event both agents already implement and ship today (PAT-499 agent side;
// PAT-1022 is the platform side that was missing entirely — every event
// 404s until this handler exists). See
// updater/docs/audit-events-contract.md for the wire contract: macOS
// emit_audit_event()/drain_events_queue() (updater/endpoint/patched-update.sh)
// and Windows AuditEventShipper.cs both already build and sign this exact
// envelope.
//
// One event per request (unlike the batched POST /v1/inventory/enforcement-audit)
// — matches the agents' fire-and-forget-per-event design.
//
// Auth: tenant bearer + HMAC-SHA256 v3 signature (X-Patched-Signature +
// X-Patched-Timestamp + X-Patched-Nonce), identical chain to /v1/inventory
// and /v1/provenance — see provenance.go. tenant_id is resolved from the
// bearer token, never trusted from the body (same rule /v1/provenance
// documents in docs/API.md), even though the envelope carries its own
// tenant_id field.
//
// Storage: audit_events (migrations/0098_audit_events.sql) — typed columns,
// not a raw-JSONB archive; see that migration's header for why this differs
// from provenance_records' approach.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/auth"
	"patched.im/api/internal/ratelimit"
)

// validAuditEventTypes is the closed set from
// updater/docs/audit-events-contract.md's "Event types" table. Must be kept
// in sync with AuditEventTypes (Windows,
// updater/windows/src/Shared/Contract/AuditEvent.cs) and the literal
// ev_type strings macOS's emit_audit_event() call sites pass
// (updater/endpoint/patched-update.sh).
var validAuditEventTypes = map[string]bool{
	"verification_passed":       true,
	"verification_failed":       true,
	"install_completed":         true,
	"install_failed":            true,
	"posture_warning":           true,
	"allowlist_tamper_detected": true,
	"version_blocked":           true,
}

// validAuditEventPlatforms is the closed set from the contract's `platform`
// field ("macos" or "windows" only).
var validAuditEventPlatforms = map[string]bool{
	"macos":   true,
	"windows": true,
}

// auditEventEnvelope mirrors the wire envelope exactly (audit-events-contract.md
// "Event envelope"). Pointer fields are optional per the contract's field
// table; empty/absent are both accepted and stored as SQL NULL.
type auditEventEnvelope struct {
	EventType string `json:"event_type"`
	// TenantID is intentionally never read — see package doc comment above.
	// Field kept only so an unknown-field-strict decoder (none is used here,
	// but future-proofing) would not choke on it.
	TenantID       *string `json:"tenant_id"`
	DeviceID       string  `json:"device_id"`
	Label          *string `json:"label"`
	Version        *string `json:"version"`
	VerifiedSigner *string `json:"verified_signer"`
	Reason         *string `json:"reason"`
	Expected       *string `json:"expected"`
	Actual         *string `json:"actual"`
	Platform       string  `json:"platform"`
	Timestamp      string  `json:"timestamp"`
}

// parseAndValidateAuditEvent decodes and validates the envelope against the
// closed contract (event_type, platform, non-empty device_id, RFC3339
// timestamp). Split out from EventsHandler so it can be unit-tested directly
// without an HTTP request or a DB — mirrors how enforcement_audit.go's
// per-event validation loop is unit-testable via its DI seam, but here the
// validation itself has no DB dependency at all, so no seam is needed.
func parseAndValidateAuditEvent(body []byte) (auditEventEnvelope, time.Time, error) {
	if !json.Valid(body) {
		return auditEventEnvelope{}, time.Time{}, fmt.Errorf("body not valid JSON")
	}
	var evt auditEventEnvelope
	if err := json.Unmarshal(body, &evt); err != nil {
		return auditEventEnvelope{}, time.Time{}, fmt.Errorf("body not valid JSON")
	}
	if !validAuditEventTypes[evt.EventType] {
		return auditEventEnvelope{}, time.Time{}, fmt.Errorf("unknown event_type %q", evt.EventType)
	}
	if strings.TrimSpace(evt.DeviceID) == "" {
		return auditEventEnvelope{}, time.Time{}, fmt.Errorf("device_id is required")
	}
	if !validAuditEventPlatforms[evt.Platform] {
		return auditEventEnvelope{}, time.Time{}, fmt.Errorf("unknown platform %q", evt.Platform)
	}
	occurredAt, err := time.Parse(time.RFC3339, evt.Timestamp)
	if err != nil {
		return auditEventEnvelope{}, time.Time{}, fmt.Errorf("timestamp must be RFC3339: %w", err)
	}
	return evt, occurredAt, nil
}

// EventsHandler serves POST /v1/events.
func EventsHandler(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter, replaySkew time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "events")

		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			logger.Warn("read body failed", "err", err)
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}

		tenantID, secret, err := auth.LookupTenantByBearer(r.Context(), pool, r.Header.Get("Authorization"))
		if err != nil {
			logger.Warn("bearer lookup failed", "err", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if allowed, retryAfter := rl.Allow(tenantID); !allowed {
			logger.Warn("rate limit exceeded", "tenant_id", tenantID)
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		if err := auth.VerifyHMACSigned(secret, r.Method, auth.EndpointEvents, r.Header.Get("X-Patched-Timestamp"), r.Header.Get("X-Patched-Nonce"), body, r.Header.Get("X-Patched-Signature")); err != nil {
			logger.Warn("hmac verify failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if err := auth.ValidateTimestamp(r.Header.Get("X-Patched-Timestamp"), replaySkew); err != nil {
			logger.Warn("timestamp validation failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if err := auth.CheckAndStoreNonce(r.Context(), pool, tenantID, r.Header.Get("X-Patched-Nonce"), replaySkew); err != nil {
			logger.Warn("nonce check failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		evt, occurredAt, err := parseAndValidateAuditEvent(body)
		if err != nil {
			logger.Warn("invalid payload", "err", err, "tenant_id", tenantID)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var sourceIPArg any
		if host, _, splitErr := net.SplitHostPort(r.RemoteAddr); splitErr == nil && host != "" {
			sourceIPArg = host
		} else if r.RemoteAddr != "" {
			sourceIPArg = r.RemoteAddr
		}

		eventID, err := dbInsertAuditEvent(r.Context(), pool, tenantID, sourceIPArg, evt, occurredAt)
		if err != nil {
			logger.Error("insert audit_event failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("audit event accepted",
			"tenant_id", tenantID, "event_id", eventID, "event_type", evt.EventType)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     "ok",
			"request_id": reqID,
			"event_id":   eventID,
		})
	}
}

// dbInsertAuditEvent writes one row to audit_events. Optional envelope
// fields are stored as SQL NULL when absent (pgx scans *string fine either
// way).
func dbInsertAuditEvent(ctx context.Context, pool *pgxpool.Pool, tenantID string, sourceIP any, evt auditEventEnvelope, occurredAt time.Time) (string, error) {
	var id string
	err := pool.QueryRow(ctx, `
		INSERT INTO audit_events
		    (tenant_id, device_id, event_type, label, version, verified_signer, reason, expected, actual, platform, source_ip, occurred_at)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id::text
	`, tenantID, strings.TrimSpace(evt.DeviceID), evt.EventType, evt.Label, evt.Version, evt.VerifiedSigner, evt.Reason, evt.Expected, evt.Actual, evt.Platform, sourceIP, occurredAt).Scan(&id)
	if err != nil {
		return "", err
	}
	return id, nil
}
