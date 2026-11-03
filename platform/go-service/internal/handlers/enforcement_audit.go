package handlers

// POST /v1/inventory/enforcement-audit — agent enforcement audit log ingest (PAT-603).
//
// Agents POST a batch of enforcement events at the end of each collection run.
// Auth is the device-level bearer + HMAC-SHA256 + replay headers scheme (same
// as /v1/agent-logs). tenantID and deviceID are derived from the DB credential;
// no client-supplied parameter influences which tenant is written to.
//
// Admin read:
//   GET /admin/tenants/{tenantID}/enforcement-audit
//   Query params: limit (default 100, max 1000), before (RFC3339 cursor on
//   ingested_at), device_id (exact filter), device (partial ID/hostname search),
//   event_type (repeatable or comma-separated).
//   Response: {"events": [...], "next_before": "<RFC3339 or null>"}

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
	"patched.im/api/internal/metrics"
	"patched.im/api/internal/ratelimit"
)

// validEnforcementEventTypes is the closed set of allowed event_type values.
var validEnforcementEventTypes = map[string]bool{
	"admin_removed":              true,
	"admin_removal_skipped":      true,
	"app_blocked":                true,
	"app_block_skipped":          true,
	"extension_blocklist_pushed": true,
	"extension_removed":          true,
}

// -- Request / response types -------------------------------------------------

type enforcementAuditEvent struct {
	EventType  string          `json:"event_type"`
	Subject    string          `json:"subject"`
	Details    json.RawMessage `json:"details"`
	OccurredAt string          `json:"occurred_at"`
}

type enforcementAuditIngestReq struct {
	Events []enforcementAuditEvent `json:"events"`
}

type enforcementAuditEntry struct {
	ID         string          `json:"id"`
	DeviceID   string          `json:"device_id"`
	Hostname   string          `json:"hostname"`
	EventType  string          `json:"event_type"`
	Subject    string          `json:"subject"`
	Details    json.RawMessage `json:"details"`
	OccurredAt time.Time       `json:"occurred_at"`
	IngestedAt time.Time       `json:"ingested_at"`
}

// -- Injectable function types (for testing) ----------------------------------

type enforcementAuditAuthFn func(ctx context.Context, authHeader, sigHeader, ts, nonce string, body []byte) (tenantID, deviceID string, err error)

type enforcementAuditIngestFn func(ctx context.Context, tenantID, deviceID string, events []enforcementAuditEvent) (int, error)

type enforcementAuditListFn func(ctx context.Context, tenantID string, limit int, before *time.Time, deviceFilter, deviceSearch string, eventTypes []string) ([]enforcementAuditEntry, error)

// -- Public constructors ------------------------------------------------------

// EnforcementAuditIngestHandler serves POST /v1/inventory/enforcement-audit.
func EnforcementAuditIngestHandler(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter, replaySkew time.Duration) http.HandlerFunc {
	authFn := func(ctx context.Context, authHeader, sigHeader, ts, nonce string, body []byte) (string, string, error) {
		tenantID, deviceID, secret, err := auth.LookupDeviceByBearer(ctx, pool, authHeader)
		if err != nil {
			return "", "", err
		}
		if err := auth.VerifyHMACSigned(secret, http.MethodPost, auth.EndpointEnforcementAudit, ts, nonce, body, sigHeader); err != nil {
			return "", "", err
		}
		return tenantID, deviceID, nil
	}
	ingestFn := func(ctx context.Context, tenantID, deviceID string, events []enforcementAuditEvent) (int, error) {
		return dbIngestEnforcementAudit(ctx, pool, tenantID, deviceID, events)
	}
	return newEnforcementAuditIngestHandler(authFn, ingestFn, rl, replaySkew, pool)
}

// EnforcementAuditGetHandler serves GET /admin/tenants/{tenantID}/enforcement-audit.
func EnforcementAuditGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	listFn := func(ctx context.Context, tenantID string, limit int, before *time.Time, deviceFilter, deviceSearch string, eventTypes []string) ([]enforcementAuditEntry, error) {
		return dbListEnforcementAudit(ctx, pool, tenantID, limit, before, deviceFilter, deviceSearch, eventTypes)
	}
	return newEnforcementAuditGetHandler(listFn)
}

// -- Handler constructors (injectable for tests) ------------------------------

func newEnforcementAuditIngestHandler(
	authFn enforcementAuditAuthFn,
	ingestFn enforcementAuditIngestFn,
	rl *ratelimit.TenantLimiter,
	replaySkew time.Duration,
	pool *pgxpool.Pool,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "enforcement_audit_ingest")

		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			logger.Warn("read body failed", "err", err)
			http.Error(w, "read body failed", http.StatusBadRequest)
			return
		}

		tenantID, deviceID, err := authFn(r.Context(), r.Header.Get("Authorization"), r.Header.Get("X-Patched-Signature"), r.Header.Get("X-Patched-Timestamp"), r.Header.Get("X-Patched-Nonce"), body)
		if err != nil {
			if errors.Is(err, auth.ErrDeviceCredentialRequired) {
				logger.Warn("auth failed: credential is tenant-level, this endpoint requires a device-scoped credential", "err", err)
				metrics.DeviceCredentialRequiredTotal.WithLabelValues("enforcement_audit_ingest").Inc()
			} else {
				logger.Warn("auth failed", "err", err)
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		logger = logger.With("tenant_id", tenantID, "device_id", deviceID)

		if rl != nil {
			if allowed, retryAfter := rl.Allow(tenantID); !allowed {
				logger.Warn("rate limit exceeded")
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}

		if pool != nil {
			if err := auth.ValidateTimestamp(r.Header.Get("X-Patched-Timestamp"), replaySkew); err != nil {
				logger.Warn("timestamp validation failed", "err", err)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if err := auth.CheckAndStoreNonce(r.Context(), pool, tenantID, r.Header.Get("X-Patched-Nonce"), replaySkew); err != nil {
				logger.Warn("nonce check failed", "err", err)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		var req enforcementAuditIngestReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.Events == nil {
			http.Error(w, "events array is required", http.StatusBadRequest)
			return
		}

		// Validate all events before touching the DB.
		for i, ev := range req.Events {
			if !validEnforcementEventTypes[ev.EventType] {
				http.Error(w, fmt.Sprintf("events[%d]: unknown event_type %q", i, ev.EventType), http.StatusBadRequest)
				return
			}
			if strings.TrimSpace(ev.Subject) == "" {
				http.Error(w, fmt.Sprintf("events[%d]: subject must not be empty", i), http.StatusBadRequest)
				return
			}
			if _, err := time.Parse(time.RFC3339, ev.OccurredAt); err != nil {
				http.Error(w, fmt.Sprintf("events[%d]: occurred_at must be RFC3339", i), http.StatusBadRequest)
				return
			}
		}

		// Empty batch — valid, nothing to store.
		if len(req.Events) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"ingested": 0})
			return
		}

		n, err := ingestFn(r.Context(), tenantID, deviceID, req.Events)
		if err != nil {
			logger.Error("ingest enforcement audit failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("enforcement audit events ingested", "count", n)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"ingested": n})
	}
}

func newEnforcementAuditGetHandler(listFn enforcementAuditListFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		logger := slog.With("req_id", reqID, "handler", "enforcement_audit_get", "tenant_id", tenantID)

		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		// Parse limit.
		limit := 100
		if s := r.URL.Query().Get("limit"); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n <= 0 {
				http.Error(w, "limit must be a positive integer", http.StatusBadRequest)
				return
			}
			if n > 1000 {
				n = 1000
			}
			limit = n
		}

		// Parse before cursor.
		var before *time.Time
		if s := r.URL.Query().Get("before"); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				http.Error(w, "before must be RFC3339", http.StatusBadRequest)
				return
			}
			before = &t
		}

		deviceFilter := strings.TrimSpace(r.URL.Query().Get("device_id"))
		deviceSearch := strings.TrimSpace(r.URL.Query().Get("device"))
		eventTypes, err := parseEnforcementEventTypes(r.URL.Query()["event_type"])
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		events, err := listFn(r.Context(), tenantID, limit, before, deviceFilter, deviceSearch, eventTypes)
		if err != nil {
			logger.Error("list enforcement audit failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if events == nil {
			events = []enforcementAuditEntry{}
		}

		// Compute next_before cursor: the ingested_at of the last returned row.
		var nextBefore any
		if len(events) == limit {
			nextBefore = events[len(events)-1].IngestedAt.UTC().Format(time.RFC3339Nano)
		}

		logger.Info("enforcement audit listed", "count", len(events))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"events":      events,
			"next_before": nextBefore,
		})
	}
}

func parseEnforcementEventTypes(values []string) ([]string, error) {
	seen := make(map[string]bool)
	var eventTypes []string
	for _, value := range values {
		for _, eventType := range strings.Split(value, ",") {
			eventType = strings.TrimSpace(eventType)
			if eventType == "" {
				continue
			}
			if !validEnforcementEventTypes[eventType] {
				return nil, fmt.Errorf("event_type contains unknown value %q", eventType)
			}
			if !seen[eventType] {
				seen[eventType] = true
				eventTypes = append(eventTypes, eventType)
			}
		}
	}
	return eventTypes, nil
}

// -- DB helpers ---------------------------------------------------------------

func dbIngestEnforcementAudit(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string, events []enforcementAuditEvent) (int, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	for _, ev := range events {
		details := []byte("{}")
		if len(ev.Details) > 0 {
			details = ev.Details
		}
		occurredAt, _ := time.Parse(time.RFC3339, ev.OccurredAt) // already validated
		var auditID string
		if err := tx.QueryRow(ctx, `
			INSERT INTO enforcement_audit
			    (tenant_id, device_id, event_type, subject, details, occurred_at)
			VALUES ($1::uuid, $2, $3, $4, $5::jsonb, $6)
			RETURNING id::text
		`, tenantID, deviceID, ev.EventType, strings.TrimSpace(ev.Subject), details, occurredAt).Scan(&auditID); err != nil {
			return 0, err
		}

		if evidence, ok := parseExtensionRemovalEvidence(ev); ok {
			if err := applyExtensionRemovalEvidence(ctx, tx, tenantID, deviceID, auditID, occurredAt, strings.TrimSpace(ev.Subject), evidence); err != nil {
				return 0, err
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(events), nil
}

type extensionRemovalEvidence struct {
	ApprovedBefore time.Time `json:"approved_before"`
	Browser        string    `json:"browser"`
	Profile        string    `json:"profile"`
	UserAccount    string    `json:"user_account"`
	Scope          string    `json:"scope"`
	DryRun         bool      `json:"dry_run"`
}

// parseExtensionRemovalEvidence accepts only a real, fully-addressed removal.
// A dry-run or incomplete detail object remains valid audit evidence but must
// never advance a destructive job's completion state.
func parseExtensionRemovalEvidence(ev enforcementAuditEvent) (extensionRemovalEvidence, bool) {
	var evidence extensionRemovalEvidence
	if ev.EventType != "extension_removed" || len(ev.Details) == 0 {
		return evidence, false
	}
	if err := json.Unmarshal(ev.Details, &evidence); err != nil {
		return extensionRemovalEvidence{}, false
	}
	evidence.Browser = strings.ToLower(strings.TrimSpace(evidence.Browser))
	evidence.Profile = strings.TrimSpace(evidence.Profile)
	evidence.UserAccount = strings.TrimSpace(evidence.UserAccount)
	evidence.Scope = strings.TrimSpace(evidence.Scope)
	if evidence.DryRun || evidence.Browser == "" || evidence.Profile == "" ||
		evidence.UserAccount == "" || evidence.Scope != "one_observation" ||
		evidence.ApprovedBefore.IsZero() {
		return extensionRemovalEvidence{}, false
	}
	return evidence, true
}

// applyExtensionRemovalEvidence marks every currently-uncompleted target row
// matching this evidence as completed — across every active request whose
// scope covers it, not just one.
//
// PAT-1199: two concurrently-active requests with overlapping scope (e.g.
// "one_user andy" and "all_devices") can both capture the same
// (device, browser, extension_id, user_account, profile) install as a
// target — the unique index on tenant_extension_removal_requests only
// dedupes within a single scope, so distinct scopes both queue it. The
// PAT-829 agent contract then physically removes the extension once and
// emits exactly one extension_removed audit event; it never reports twice
// for one install. Matching only one request per event (the previous
// behaviour, via an exact r.requested_at = approved_before equality copied
// from whichever directive the agent happened to echo back) left every
// other overlapping request's target permanently uncompleted — stranded
// short of `completed` with no path forward except manual cancellation.
//
// The fix: a single physical removal satisfies every request whose scope
// covers it. We drop the exact-timestamp match entirely and instead
// complete every request identified by (tenant, browser, extension_id,
// device, user_account, profile) that (a) is still active
// (fulfilled = FALSE, cancelled_at IS NULL), (b) has a target row for this
// exact tuple that isn't completed yet, and (c) was requested at or before
// the moment the removal actually happened (occurredAt >= r.requested_at —
// a request created after the fact must not retroactively claim credit for
// a removal it never asked for). evidence.ApprovedBefore remains a
// required, validated field on the wire (a real observation must carry a
// non-zero approval boundary — see parseExtensionRemovalEvidence) but is no
// longer used to narrow which request(s) this event can complete.
func applyExtensionRemovalEvidence(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, deviceID, auditID string,
	occurredAt time.Time,
	extensionID string,
	evidence extensionRemovalEvidence,
) error {
	// Serialise reports that can advance the same requests. Without this lock,
	// two final targets can each update under separate snapshots, both observe
	// the other as incomplete, and leave a fully-completed request unfulfilled.
	lockRows, err := tx.Query(ctx, `
		SELECT r.id
		FROM tenant_extension_removal_requests r
		JOIN tenant_extension_removal_targets rt ON rt.request_id = r.id
		WHERE r.tenant_id = $1::uuid
		  AND r.browser = $2
		  AND r.extension_id = $3
		  AND r.requested_at <= $4
		  AND r.fulfilled = FALSE
		  AND r.cancelled_at IS NULL
		  AND rt.device_id = $5::uuid
		  AND lower(rt.user_account) = lower($6)
		  AND rt.profile = $7
		ORDER BY r.id
		FOR UPDATE OF r
	`, tenantID, evidence.Browser, extensionID, occurredAt,
		deviceID, evidence.UserAccount, evidence.Profile)
	if err != nil {
		return err
	}
	for lockRows.Next() {
		var requestID int64
		if err := lockRows.Scan(&requestID); err != nil {
			lockRows.Close()
			return err
		}
	}
	if err := lockRows.Err(); err != nil {
		lockRows.Close()
		return err
	}
	lockRows.Close()

	if _, err := tx.Exec(ctx, `
		UPDATE tenant_extension_removal_targets rt
		SET completed_at = $1,
		    audit_event_id = $2::uuid
		FROM tenant_extension_removal_requests r
		WHERE rt.request_id = r.id
		  AND r.tenant_id = $3::uuid
		  AND r.browser = $4
		  AND r.extension_id = $5
		  AND r.requested_at <= $6
		  AND r.fulfilled = FALSE
		  AND r.cancelled_at IS NULL
		  AND rt.device_id = $7::uuid
		  AND lower(rt.user_account) = lower($8)
		  AND rt.profile = $9
		  AND rt.completed_at IS NULL
	`, occurredAt, auditID, tenantID, evidence.Browser, extensionID,
		occurredAt, deviceID, evidence.UserAccount, evidence.Profile); err != nil {
		return err
	}

	// PAT-1199: scope the "mark fulfilled" aggregate to the requests this
	// event could possibly have touched (tenant + browser + extension_id,
	// still active) instead of grouping every row in
	// tenant_extension_removal_targets across every tenant on every ingest.
	_, err = tx.Exec(ctx, `
		UPDATE tenant_extension_removal_requests r
		SET fulfilled = TRUE,
		    fulfilled_at = completed.latest_completed_at
		FROM (
			SELECT rt.request_id, MAX(rt.completed_at) AS latest_completed_at
			FROM tenant_extension_removal_targets rt
			JOIN tenant_extension_removal_requests r2 ON r2.id = rt.request_id
			WHERE r2.tenant_id = $1::uuid
			  AND r2.browser = $2
			  AND r2.extension_id = $3
			  AND r2.fulfilled = FALSE
			  AND r2.cancelled_at IS NULL
			GROUP BY rt.request_id
			HAVING COUNT(*) > 0 AND COUNT(*) = COUNT(rt.completed_at)
		) completed
		WHERE r.id = completed.request_id
		  AND r.tenant_id = $1::uuid
		  AND r.browser = $2
		  AND r.extension_id = $3
		  AND r.fulfilled = FALSE
		  AND r.cancelled_at IS NULL
	`, tenantID, evidence.Browser, extensionID)
	return err
}

func dbListEnforcementAudit(ctx context.Context, pool *pgxpool.Pool, tenantID string, limit int, before *time.Time, deviceFilter, deviceSearch string, eventTypes []string) ([]enforcementAuditEntry, error) {
	args := []any{tenantID, limit}
	q := `
		SELECT ea.id::text, ea.device_id,
		       COALESCE(NULLIF(d.hostname, ''), NULLIF(d.computer_name, ''), ''),
		       ea.event_type, ea.subject, ea.details, ea.occurred_at, ea.ingested_at
		FROM enforcement_audit ea
		LEFT JOIN devices d ON d.tenant_id = ea.tenant_id AND d.id::text = ea.device_id
		WHERE ea.tenant_id = $1::uuid`

	if before != nil {
		args = append(args, *before)
		q += fmt.Sprintf(" AND ea.ingested_at < $%d", len(args))
	}
	if deviceFilter != "" {
		args = append(args, deviceFilter)
		q += fmt.Sprintf(" AND ea.device_id = $%d", len(args))
	}
	if deviceSearch != "" {
		args = append(args, "%"+deviceSearch+"%")
		q += fmt.Sprintf(" AND (ea.device_id ILIKE $%d OR d.hostname ILIKE $%d OR d.computer_name ILIKE $%d)", len(args), len(args), len(args))
	}
	if len(eventTypes) > 0 {
		args = append(args, eventTypes)
		q += fmt.Sprintf(" AND ea.event_type = ANY($%d::text[])", len(args))
	}
	q += " ORDER BY ea.ingested_at DESC LIMIT $2"

	rows, err := pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []enforcementAuditEntry
	for rows.Next() {
		var e enforcementAuditEntry
		if err := rows.Scan(&e.ID, &e.DeviceID, &e.Hostname, &e.EventType, &e.Subject, &e.Details, &e.OccurredAt, &e.IngestedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
