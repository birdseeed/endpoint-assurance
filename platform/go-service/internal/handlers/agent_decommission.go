package handlers

// Agent decommissioning — platform surface (PAT-1108).
//
// This feature is the only irreversible command in the product: once an
// agent removes itself there is no channel left to correct a mistake. Every
// handler in this file is written around one rule — fail closed means DO NOT
// REMOVE — and the tenant-wide directive is set only through an explicit,
// audited admin action that is never a side effect of tenant revoke or
// purge (see admin.go: RevokeTenantHandler, PurgeTenantHandler; neither
// writes tenant_decommission).
//
// Routes:
//
//	PUT  /admin/tenants/{tenantID}/decommission          — set the tenant-wide directive (audited)
//	GET  /admin/tenants/{tenantID}/decommission          — read the current directive
//	GET  /admin/tenants/{tenantID}/decommission/devices  — per-device state, including never-acknowledged devices
//	POST /v1/agent-decommission-status                   — the agent's two-phase status report: "acknowledged" before it acts, the genuine terminal outcome after (PAT-1108 fourth-round finding P1-B)
//
// The three /admin/* routes are staff/admin-only, reached only through the
// Tailscale-bound internal listener (:8081) — same posture as every other
// /admin/* route in this service (see admin.go). No decommission field is
// exposed on any customer-facing (portal) surface; this file never touches
// the portal package or any :8080-public-non-agent route.
//
// POST /v1/agent-decommission-status is on the PUBLIC listener because the
// agent calls it, but it is device-scoped (auth.LookupDeviceByBearer): a
// tenant-wide credential cannot call it, and the device_id is resolved
// exclusively from the authenticated credential, never from the request
// body, so one device can never report status for another.
//
// PAT-1108 fifth-round finding P1-E: a terminal report (removed/failed/
// expired_unreachable) that arrives with no observed phase-1 "acknowledged"
// for its directive_version is a real finding — it means a buggy or
// spurious client could manufacture a sticky, irreversible false "removed"
// without phase 1 ever succeeding. The fix is NOT to reject such reports:
// a device that acknowledged, had that report lost in transit, then
// genuinely completed removal and reported its true last word before
// destroying its own uploader would be rejected right when it has no
// second chance to ever report again — trading a false "removed" for a
// lost real one, which is worse (an agent that silently disappears is
// indistinguishable from one that crashed). Instead the report is always
// accepted, but device_decommission_state.phase1_observed records whether
// phase 1 was actually seen for this directive generation, and
// report.FetchTenantDecommissionDevices surfaces it as
// terminal_without_acknowledgement so an operator can see a manufactured or
// short-circuited removal as visibly anomalous rather than indistinguishable
// from a clean one. See AgentDecommissionStatusHandler's upsert for exactly
// how the column is computed, and contracts/agent-config-schema.md for the
// agent-facing statement that phase 1 is mandatory even though the server
// does not enforce it by rejection.

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

	"patched.im/api/internal/agentconfig"
	"patched.im/api/internal/auth"
	"patched.im/api/internal/metrics"
	"patched.im/api/internal/ratelimit"
	"patched.im/api/internal/report"
)

// ---------------------------------------------------------------------------
// PUT / GET /admin/tenants/{tenantID}/decommission — the tenant-wide directive
// ---------------------------------------------------------------------------

// decommissionDirectiveReq is the PUT request body. Actor identifies who is
// setting the directive, for the audit trail; it defaults to "system" when
// omitted, matching the updated_by convention used by PUT /admin/agent-config.
type decommissionDirectiveReq struct {
	Mode      string  `json:"mode"`
	ExpiresAt *string `json:"expires_at"`
	Purge     bool    `json:"purge"`
	Reason    *string `json:"reason"`
	Actor     string  `json:"actor"`
}

// decommissionDirectiveResp mirrors report.TenantDecommissionDirective.
type decommissionDirectiveResp struct {
	TenantID  string  `json:"tenant_id"`
	Mode      string  `json:"mode"`
	ExpiresAt *string `json:"expires_at"`
	Purge     bool    `json:"purge"`
	Reason    *string `json:"reason"`
	SetBy     string  `json:"set_by"`
	SetAt     string  `json:"set_at"`
}

// validateDecommissionDirectiveReq enforces the same fail-closed contract the
// signer independently re-checks in agentconfig.safeDecommissionPolicy: mode
// must be a recognised value, and mode="expiry" requires a parseable RFC3339
// expires_at. Unlike the signer (which coerces a malformed stored row to
// "none" so it can never be a silent no-op on read), this write path REJECTS
// a malformed request outright — an explicit admin action should fail loudly,
// not be silently downgraded.
func validateDecommissionDirectiveReq(req decommissionDirectiveReq) error {
	if !agentconfig.AllowedDecommissionModes[req.Mode] {
		return fmt.Errorf("mode must be one of none, expiry, immediate, got %q", req.Mode)
	}
	if req.Mode == "expiry" {
		if req.ExpiresAt == nil || strings.TrimSpace(*req.ExpiresAt) == "" {
			return errors.New("expires_at is required when mode is \"expiry\"")
		}
		if _, err := time.Parse(time.RFC3339, *req.ExpiresAt); err != nil {
			return fmt.Errorf("expires_at must be RFC3339, got %q: %w", *req.ExpiresAt, err)
		}
	}
	return nil
}

// TenantDecommissionGetHandler returns the tenant's current decommission
// directive, defaulting to mode="none" when none has ever been set.
func TenantDecommissionGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenant_decommission_get")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		d, err := report.FetchTenantDecommissionDirective(r.Context(), pool, tenantID)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch tenant decommission directive failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(decommissionDirectiveResp{
			TenantID:  d.TenantID,
			Mode:      d.Mode,
			ExpiresAt: d.ExpiresAt,
			Purge:     d.Purge,
			Reason:    d.Reason,
			SetBy:     d.SetBy,
			SetAt:     d.SetAt,
		})
	}
}

// TenantDecommissionPutHandler sets the tenant-wide decommission directive.
// This is the ONLY write path for tenant_decommission — an explicit, audited
// admin action, never a side effect of RevokeTenantHandler or
// PurgeTenantHandler. Every successful call writes exactly one
// tenant_decommission_audit row, whether or not the resulting directive
// differs from the previous one, mirroring TenantPlatformsPutHandler's
// "audit every write" choice (tenant_platforms.go).
func TenantDecommissionPutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenant_decommission_put")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var req decommissionDirectiveReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if err := validateDecommissionDirectiveReq(req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Actor == "" {
			req.Actor = "system"
		}
		// mode != "expiry": expires_at is meaningless and is not stored, so a
		// stray value in the request can never be mistaken for an active
		// expiry later (e.g. after a future mode="expiry" write omits it).
		expiresAt := req.ExpiresAt
		if req.Mode != "expiry" {
			expiresAt = nil
		}
		// Parsed form of expiresAt, for the no-op comparison below only — the
		// DB write still uses the raw string. Already validated as RFC3339 by
		// validateDecommissionDirectiveReq when mode=="expiry", so the parse
		// error is unreachable here.
		var newExpiresAtParsed *time.Time
		if expiresAt != nil {
			if t, parseErr := time.Parse(time.RFC3339, *expiresAt); parseErr == nil {
				newExpiresAtParsed = &t
			}
		}

		tx, err := pool.BeginTx(r.Context(), pgx.TxOptions{})
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		// Confirm the tenant exists, take the row lock this handler's
		// concurrency contract depends on, and capture the prior directive
		// (PAT-1108 finding 3). See lockTenantAndReadDecommissionState's doc
		// comment for why the lock is taken on tenants rather than
		// tenant_decommission itself.
		exists, oldMode, oldExpiresAt, oldPurge, oldReason, oldDirectiveVersion, err := lockTenantAndReadDecommissionState(r.Context(), tx, tenantID)
		if err != nil {
			logger.Error("lock tenant and read decommission state failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		// PAT-1108 finding 1: the directive is delivered inside the same
		// signed envelope as the rest of agent-config, gated by
		// agent_config.config_version. A write that changes the EFFECTIVE
		// directive (mode, expires_at, purge, or — as of PAT-1138, below —
		// reason) must bump that counter so an older-but-still-validly-
		// signed payload can never be replayed after a cancellation, and so
		// an agent that rejects same-version configs still sees the change.
		//
		// PAT-1138: reason is now INCLUDED in this comparison. reason's
		// VALUE still never drives control flow anywhere — the agent never
		// branches on what it says, and neither does the platform — but the
		// signed envelope's decommission block DOES include reason (see
		// agentconfig.DecommissionPolicy), so a reason-only edit changes the
		// signed bytes exactly as a mode/expires_at/purge edit does.
		// Excluding it from directiveChanged (the original PAT-1108 choice)
		// meant a corrected reason was written to the DB but never reached
		// any agent that had already accepted the previous config_version,
		// because anti-rollback rejects a same-version payload as a replay —
		// an operator fixing a wrong reason before an expiry fires, or
		// before a purge lands, had no way to get that correction in front
		// of already-polling agents. The version bump here is driven purely
		// by "the signed bytes changed", never by branching on reason's
		// contents.
		//
		// Accepted consequence: because device_decommission_state is scoped
		// by directive_version (see terminalDecommissionStatuses' doc
		// comment and the WHERE guard in AgentDecommissionStatusHandler),
		// bumping config_version for a reason-only change re-signs and
		// re-delivers the envelope to every device AND resets each device's
		// reported decommission state back to "pending" for the new
		// directive_version — same as for any other directive change.
		// Accepted per PAT-1138 ("correctness beats churn"): the meaningful
		// correction case is fixing reason before an expiry fires or a
		// purge lands, while devices are still pending, so the reset costs
		// nothing in that case. An exactly-identical repeat PUT (including
		// reason unchanged) still does not bump — the predicate below is
		// false in that case — so a duplicate/retried identical PUT still
		// cannot reset every device's reported state back to "pending" via
		// finding 5's directive_version staleness check. Pinned by
		// TestTenantDecommissionPut_NoOpDoesNotBumpVersion (identical
		// repeat, no bump) and TestTenantDecommissionPut_ReasonOnlyChangeBumpsVersion
		// (reason-only edit, bumps).
		directiveChanged := oldMode == nil ||
			*oldMode != req.Mode ||
			oldPurge != req.Purge ||
			!decommissionTimeEqual(oldExpiresAt, newExpiresAtParsed) ||
			!stringPtrEqual(oldReason, req.Reason)

		directiveVersion := oldDirectiveVersion
		if directiveChanged {
			newVersion, bumpErr := bumpAgentConfigVersionForDecommission(r.Context(), tx, tenantID)
			if bumpErr != nil {
				logger.Error("bump agent_config config_version for decommission failed", "err", bumpErr, "tenant_id", tenantID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			directiveVersion = newVersion
		}

		// PAT-1108 second-round finding D: the RETURNING clause captures the
		// authoritative post-write row (mode/expires_at/purge/reason/set_by/
		// set_at, all server-assigned or coalesced by the upsert itself) in
		// the SAME statement that performs the write, inside the SAME
		// transaction. This used to be a separate SELECT issued through the
		// pool AFTER tx.Commit — a transient failure on that unrelated read
		// (a dropped connection, a canceled context, pool exhaustion) turned
		// an already-committed, already-irreversible write into an HTTP 500,
		// inviting an operator to retry an action that had already
		// succeeded. Folding the read into the write's own RETURNING makes
		// success-and-response atomic by construction: there is no code path
		// left where the DB write commits but the handler cannot describe
		// what it wrote. Pinned by
		// TestTenantDecommissionPut_NoPostCommitReadRequired.
		var (
			respMode      string
			respExpiresAt *time.Time
			respPurge     bool
			respReason    *string
			respSetBy     string
			respSetAt     time.Time
		)
		// PAT-1135: set_by (and the audit row's actor below) record the
		// server-established shared-token principal, never req.Actor — the
		// admin surface has no per-person identity to verify that string
		// against. req.Actor still flows into claimed_actor on the audit
		// row below, untrusted. See internal/handlers/audit_attribution.go.
		actor, claimedActor, sourceAddr := auditAttribution(r, req.Actor)
		if err := tx.QueryRow(r.Context(), `
			INSERT INTO tenant_decommission (tenant_id, mode, expires_at, purge, reason, set_by, set_at, directive_version)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, now(), $7)
			ON CONFLICT (tenant_id) DO UPDATE
				SET mode = EXCLUDED.mode,
				    expires_at = EXCLUDED.expires_at,
				    purge = EXCLUDED.purge,
				    reason = EXCLUDED.reason,
				    set_by = EXCLUDED.set_by,
				    set_at = now(),
				    directive_version = EXCLUDED.directive_version
			RETURNING mode, expires_at, purge, reason, set_by, set_at
		`, tenantID, req.Mode, expiresAt, req.Purge, req.Reason, actor, directiveVersion).Scan(
			&respMode, &respExpiresAt, &respPurge, &respReason, &respSetBy, &respSetAt,
		); err != nil {
			logger.Error("upsert tenant_decommission failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// directive_version (PAT-1108 third-round finding A): stamped with
		// the SAME value just written to tenant_decommission.directive_version
		// (directiveVersion, computed above), whether or not this write
		// bumped it. This gives AgentDecommissionStatusHandler's resolution
		// query a complete, gap-free history of "which directive generation
		// was in effect as of directive_version X" to map a reported
		// envelope config_version back to the directive that was actually
		// live at that version.
		if _, err := tx.Exec(r.Context(), `
			INSERT INTO tenant_decommission_audit (tenant_id, actor, old_mode, new_mode, expires_at, purge, reason, directive_version, claimed_actor, source_addr)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`, tenantID, actor, oldMode, req.Mode, expiresAt, req.Purge, req.Reason, directiveVersion, claimedActor, sourceAddr); err != nil {
			logger.Error("insert tenant_decommission_audit failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Warn("tenant decommission directive set — irreversible action",
			"tenant_id", tenantID, "actor", actor, "claimed_actor", req.Actor, "old_mode", oldMode, "new_mode", req.Mode, "purge", req.Purge)

		var respExpiresAtStr *string
		if respExpiresAt != nil {
			s := respExpiresAt.UTC().Format(time.RFC3339)
			respExpiresAtStr = &s
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(decommissionDirectiveResp{
			TenantID:  tenantID,
			Mode:      respMode,
			ExpiresAt: respExpiresAtStr,
			Purge:     respPurge,
			Reason:    respReason,
			SetBy:     respSetBy,
			SetAt:     respSetAt.UTC().Format(time.RFC3339),
		})
	}
}

// lockTenantAndReadDecommissionState confirms tenantID exists and takes the
// row lock TenantDecommissionPutHandler's concurrency contract depends on
// (PAT-1108 finding 3: two concurrent PUTs must never both read the same
// "old" directive), then reads the directive currently visible under that
// lock.
//
// AgentDecommissionStatusHandler also calls this (PAT-1108 fourth-round
// finding P1-1), for the same reason: it must never decide "proceed" based
// on a tenant_decommission read that a concurrent PUT (a cancellation or
// re-issue) could invalidate before the response goes out. Serialising both
// handlers on the same tenants-row lock means a status report and a
// cancelling PUT can never interleave — one fully commits (or rolls back)
// before the other's read of the directive is taken.
//
// dbGetAgentConfig's not-found fallback (agent_config.go) also calls this
// (PAT-1108 fifth-round finding P1-D), for the same reason again: it must
// never sign the synthetic-default config_version alongside a decommission
// directive read from a SEPARATE, unsynchronised query that a concurrent PUT
// could have changed underneath it. reason is returned (in addition to
// mode/expires_at/purge/directive_version) specifically for that caller —
// TenantDecommissionPutHandler and AgentDecommissionStatusHandler both
// discard it, but the signed envelope's decommission block includes reason,
// so dbGetAgentConfig's fallback needs the full policy, not just the fields
// its two sibling callers happen to use.
//
// Concurrency: tx MUST be the caller's open transaction (pgx.Tx), never the
// pool directly — the same contract CheckTrialDeviceCap documents for its
// own tenants-row FOR UPDATE lock (trial.go). tenant_decommission's primary
// key is tenant_id, so a not-yet-existing directive row cannot itself be
// locked with SELECT ... FOR UPDATE — there is nothing there to lock. Locking
// the parent tenants row instead works whether or not a tenant_decommission
// row exists yet: the tenants row always exists (that's what this function
// also confirms), and TenantDecommissionPutHandler is tenant_decommission's
// ONLY writer (see the package doc comment at the top of this file), so
// serialising on the tenants row fully serialises every write to
// tenant_decommission for that tenant. A second concurrent call blocks here
// until the first call's transaction commits or rolls back, so the audit
// trail's old_mode chain can never observe two concurrent writes racing on
// the same prior state.
func lockTenantAndReadDecommissionState(ctx context.Context, tx pgx.Tx, tenantID string) (exists bool, oldMode *string, oldExpiresAt *time.Time, oldPurge bool, oldReason *string, oldDirectiveVersion int, err error) {
	var dummy int
	lockErr := tx.QueryRow(ctx, `SELECT 1 FROM tenants WHERE id = $1::uuid FOR UPDATE`, tenantID).Scan(&dummy)
	if lockErr != nil {
		if errors.Is(lockErr, pgx.ErrNoRows) {
			return false, nil, nil, false, nil, 0, nil
		}
		return false, nil, nil, false, nil, 0, lockErr
	}

	readErr := tx.QueryRow(ctx, `
		SELECT mode, expires_at, purge, reason, directive_version
		FROM tenant_decommission WHERE tenant_id = $1::uuid
	`, tenantID).Scan(&oldMode, &oldExpiresAt, &oldPurge, &oldReason, &oldDirectiveVersion)
	if readErr != nil {
		if errors.Is(readErr, pgx.ErrNoRows) {
			return true, nil, nil, false, nil, 0, nil
		}
		return true, nil, nil, false, nil, 0, readErr
	}
	return true, oldMode, oldExpiresAt, oldPurge, oldReason, oldDirectiveVersion, nil
}

// decommissionTimeEqual reports whether two possibly-nil timestamps represent
// the same instant. Used to decide whether a PUT's expires_at is genuinely
// unchanged from the stored value (PAT-1108 finding 1's no-op comparison).
func decommissionTimeEqual(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// stringPtrEqual reports whether two nullable strings are equal, treating
// two nils as equal and a nil vs non-nil as different.
func stringPtrEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// bumpAgentConfigVersionForDecommission bumps the tenant's
// agent_config.config_version — the SAME anti-rollback counter every other
// agent-config write already uses (dbUpsertAgentConfig, agent_config.go),
// not a new parallel one — inside tx, and returns the resulting value.
//
// PAT-1108 finding 1: the decommission directive is delivered inside the
// same Ed25519-signed envelope as the rest of agent-config
// (agentconfig.Sign takes a single shared config_version). A directive
// change that does not bump this counter can be replayed (an old
// still-validly-signed "immediate" payload remains signable-equivalent after
// a cancellation) or silently never delivered (an agent that rejects
// same-version configs never re-polls a same-version payload). The value
// this function returns is also what finding 5 stamps onto
// tenant_decommission.directive_version, and transitively onto every
// device_decommission_state row reported against that directive.
//
// If the tenant has no agent_config row yet, this creates one — a
// decommission directive must never be unreachable just because the tenant
// has never had any other agent-config write.
//
// PAT-1108 second-round finding A: GET /v1/agent-config's synthetic-default
// branch (agent_config.go, newAgentConfigHandler) already serves
// syntheticDefaultConfigVersion for exactly this "no row yet" tenant. An
// agent that has polled GET /v1/agent-config even once before any directive
// existed may therefore already have accepted that synthetic version. Since
// the anti-rollback rule requires an agent to reject a same-version config
// (a same-version payload must never be treated as new information — see
// agentconfig.Sign's config_version), inserting the tenant's first-ever
// persisted row at that SAME version would mean the directive can be
// silently never delivered: the agent already believes it has seen this
// version and never re-polls it. The first persisted row must therefore
// start strictly above the synthetic default, not merely at some version —
// "strictly above" and "equal to the synthetic default" must never be able
// to silently drift into being the same value again, so this reads directly
// off syntheticDefaultConfigVersion rather than repeating a bare literal.
// Pinned by TestBumpAgentConfigVersionForDecommission_ExceedsSyntheticDefault.
func bumpAgentConfigVersionForDecommission(ctx context.Context, tx pgx.Tx, tenantID string) (int, error) {
	defaultBody, err := json.Marshal(agentconfig.DefaultConfigBody())
	if err != nil {
		return 0, fmt.Errorf("marshal default config body: %w", err)
	}
	const firstPersistedConfigVersion = syntheticDefaultConfigVersion + 1
	var configVersion int
	err = tx.QueryRow(ctx, `
		INSERT INTO agent_config (tenant_id, config_version, body, issued_at, updated_by)
		VALUES ($1::uuid, $3, $2::jsonb, now(), 'system')
		ON CONFLICT (tenant_id) DO UPDATE
			SET config_version = agent_config.config_version + 1,
			    issued_at       = now()
		RETURNING config_version
	`, tenantID, defaultBody, firstPersistedConfigVersion).Scan(&configVersion)
	if err != nil {
		return 0, err
	}
	return configVersion, nil
}

// TenantDecommissionDevicesHandler returns per-device decommission state for
// a tenant, including devices that have never reported any status (PAT-1108).
func TenantDecommissionDevicesHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenant_decommission_devices")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		resp, err := report.FetchTenantDecommissionDevices(r.Context(), pool, tenantID)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch tenant decommission devices failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("tenant decommission devices fetched", "tenant_id", tenantID, "total", resp.Total)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// ---------------------------------------------------------------------------
// POST /v1/agent-decommission-status — the agent's terminal-status report
// ---------------------------------------------------------------------------

// agentReportableDecommissionStatuses is the closed set of statuses the agent
// may report. "pending" is deliberately excluded: it is never written
// directly, only implied by the absence of a row (see
// report.FetchTenantDecommissionDevices).
var agentReportableDecommissionStatuses = map[string]bool{
	"acknowledged":        true,
	"removed":             true,
	"failed":              true,
	"expired_unreachable": true,
}

// terminalDecommissionStatuses is the closed set of device_decommission_state
// values with no valid next state (PAT-1108 finding 4), SCOPED TO A SINGLE
// DIRECTIVE VERSION (PAT-1108 second-round finding C — see the WHERE guard
// doc comment in AgentDecommissionStatusHandler for why the scoping matters).
// State machine, for a given directive_version:
//
//	(no row, meaning "pending")
//	    │
//	    ▼
//	acknowledged  (not terminal — the device has seen the directive but not
//	    │          finished acting on it; further reports are normal)
//	    ▼
//	removed | failed | expired_unreachable  (TERMINAL for THIS directive_version)
//
// A device may also report a terminal status directly from "no row", without
// ever reporting "acknowledged" first — both paths into a terminal status are
// valid. Once a terminal status is stored FOR A GIVEN DIRECTIVE, no later
// report against that SAME directive — however it arrives, in whatever
// order, reporting whatever status — may regress it: a delayed "acknowledged"
// must never overwrite "removed", and a second, differently-stale terminal
// report must not overwrite the first one either. The out-of-order report is
// ignored (200 OK, no status change), not rejected — see
// AgentDecommissionStatusHandler's ON CONFLICT ... WHERE guard — because
// rejecting would just make an about-to-remove-itself agent retry a call
// that can never succeed. "pending" never appears here: it is never written
// directly (see agentReportableDecommissionStatuses) and so cannot be
// terminal by construction.
//
// Terminal-ness does NOT carry across directive versions: a "removed" stored
// against directive N is a description of what happened to directive N, and
// must never be read as blocking a report against a DIFFERENT directive N+1
// — a tenant that cancels and re-issues, or issues a materially new
// directive, always gets a clean slate for that new directive on that
// device, whatever the previous directive's outcome was.
var terminalDecommissionStatuses = map[string]bool{
	"removed":             true,
	"failed":              true,
	"expired_unreachable": true,
}

// unattributedDirectiveVersion is the resolvedDirectiveVersion value used
// in-memory when the agent's report did not say which envelope version it
// acted on (PAT-1108 second-round finding B). It is a value no real
// directive_version can ever take (every real value bumped through
// bumpAgentConfigVersionForDecommission is >= syntheticDefaultConfigVersion+1,
// and every never-set tenant reads as 0 — see the directive_version note in
// migrations/0091_agent_decommission.sql, and, as of PAT-1108 sixth-round
// finding P2, the CHECK constraints in that migration guarantee no stored
// directive_version can ever be negative), so a report carrying it can
// never be mistaken for "attributed to the tenant's current directive". A
// missing directive_version is ALSO always treated as superseded (never
// "proceed") for the same reason — an agent that cannot say which envelope
// it verified cannot be safely told to continue with an irreversible
// action. This is a PURE in-memory resolution sentinel, never actually
// persisted: AgentDecommissionStatusHandler's shouldPersist is false
// whenever resolvedDirectiveVersion is this value (an unattributed report's
// resolvedDirectiveVersion can never equal a stored, non-negative
// currentDirectiveVersion — see isStaleVersion), so the write to
// device_decommission_state.directive_version is never reached with this
// value. An earlier round of this doc comment claimed the opposite (that
// it WAS stored on that column); that was true before the shouldPersist
// gate existed and is not true of the current code.
const unattributedDirectiveVersion = -1

// agentDecommissionStatusReq is the POST body.
//
// DirectiveVersion (PAT-1108 second/third-round findings) is a pointer so a
// genuinely absent field (an agent build that predates this contract change)
// is distinguishable from an explicit 0 — both are handled, but differently:
// absent is untrusted (see unattributedDirectiveVersion); an explicit value
// is the agent_config.config_version the agent last verified before acting —
// the ENVELOPE version, NOT tenant_decommission.directive_version directly
// (PAT-1108 third-round finding A: those two counters diverge the moment any
// unrelated agent-config write, e.g. app_control or tier, bumps config_version
// without touching the directive). The server resolves that envelope version
// to the directive generation actually in effect at it — see
// dbResolveDirectiveForEnvelopeVersion. See contracts/agent-config-schema.md's
// POST /v1/agent-decommission-status section for the wire contract this
// field belongs to, including exactly what the agent must do with the
// "decommission" field in the response.
type agentDecommissionStatusReq struct {
	Status           string `json:"status"`
	Detail           string `json:"detail"`
	DirectiveVersion *int   `json:"directive_version"`
}

// agentDecommissionStatusResp is the POST /v1/agent-decommission-status
// response body (PAT-1108 third-round finding B, revised by fourth-round
// finding P1-2, fifth-round finding P1-A, and sixth-round finding P1-F).
// Decommission is the field the agent MUST check before continuing on the
// strength of this call, and — as of finding P1-F — it means EXACTLY THE
// SAME THING for every phase: "proceed" confirms the directive the agent
// resolved to is still the tenant's current directive AND that it
// CURRENTLY AUTHORISES REMOVAL (mode="immediate", or mode="expiry" with
// expires_at genuinely passed by the SERVER'S clock). "superseded" means
// either is not true — cancelled, superseded by a newer directive, not yet
// actionable, or unattributable — and the agent MUST NOT continue on the
// strength of this report.
//
// This is deliberately uniform across phases (round five briefly gated
// phase 1's "acknowledged" on mere liveness rather than authorisation —
// found wrong by round six's non-author review): the agent's removal
// ATTEMPT happens BETWEEN phase 1 and phase 2, so phase 1's response is the
// ONLY one that can actually prevent an early, unauthorised attempt. A
// phase 2 response that says "too early" arrives after the fact and
// prevents nothing.
//
// RecordedStatus is decoupled from Decommission (finding P1-F): it is
// populated whenever this call's report was PERSISTED, regardless of
// whether Decommission is "proceed" or "superseded" — a phase 1
// "acknowledged" report against a live but not-yet-authorised directive
// persists (RecordedStatus == "acknowledged") while Decommission still
// says "superseded" (removal is not yet authorised). It remains absent
// only when nothing was persisted for this call (a stale-version report,
// or an unauthorised terminal report — see AgentDecommissionStatusHandler's
// shouldPersist). This is deliberately its own field rather than something
// inferable from the HTTP status code alone, so the agent never has to
// guess; per the contract, the agent must never branch control flow on
// RecordedStatus's presence, only ever on Decommission.
type agentDecommissionStatusResp struct {
	Decommission   string `json:"decommission"` // "proceed" | "superseded"
	DeviceID       string `json:"device_id"`
	RecordedStatus string `json:"recorded_status,omitempty"`
}

// dbCurrentEnvelopeVersionForDevice returns the CURRENT agent_config.config_version
// for the tenant that owns deviceID — the same envelope counter GET
// /v1/agent-config signs and serves (PAT-1108 third-round finding A). Falls
// back to syntheticDefaultConfigVersion when the tenant has no agent_config
// row yet, matching exactly what GET /v1/agent-config's synthetic-default
// branch would have served such a tenant (agent_config.go).
//
// q is rowQuerier (trial.go), not *pgxpool.Pool, so AgentDecommissionStatusHandler
// can call this on its own open transaction (PAT-1108 fourth-round finding
// P1-1) rather than acquiring a second pooled connection that would read a
// snapshot inconsistent with the tenants-row lock the same transaction holds.
func dbCurrentEnvelopeVersionForDevice(ctx context.Context, q rowQuerier, deviceID string) (int, error) {
	var v int
	err := q.QueryRow(ctx, `
		SELECT COALESCE(
			(SELECT ac.config_version FROM agent_config ac
			 JOIN devices d ON d.tenant_id = ac.tenant_id
			 WHERE d.id = $1::uuid),
			$2)
	`, deviceID, syntheticDefaultConfigVersion).Scan(&v)
	if err != nil {
		return 0, err
	}
	return v, nil
}

// dbResolveDirectiveForEnvelopeVersion is the PAT-1108 third-round finding A
// resolution: maps an agent-reported envelope agent_config.config_version to
// the directive generation that was ACTUALLY IN EFFECT at that version — the
// tenant_decommission_audit row with the greatest directive_version <=
// envelopeVersion. This is exact, not a heuristic: directive_version is
// stamped from config_version at the moment each directive is written
// (TenantDecommissionPutHandler), both only ever increase, and a directive
// stays in effect until a strictly higher directive_version supersedes it —
// see migrations/0091_agent_decommission.sql's column comment on
// tenant_decommission_audit.directive_version. Returns (0, "none", nil) —
// the same safe/inert default used everywhere else in this file — when no
// directive had been written yet at or before envelopeVersion (e.g. a
// tenant's very first envelope, before any decommission PUT ever happened).
// q is rowQuerier (trial.go) for the same reason as
// dbCurrentEnvelopeVersionForDevice above: called on
// AgentDecommissionStatusHandler's own transaction so the resolution is read
// under the same tenants-row lock as the rest of the proceed/superseded
// decision (PAT-1108 fourth-round finding P1-1).
func dbResolveDirectiveForEnvelopeVersion(ctx context.Context, q rowQuerier, deviceID string, envelopeVersion int) (resolvedDirectiveVersion int, resolvedMode string, err error) {
	err = q.QueryRow(ctx, `
		SELECT tda.directive_version, tda.new_mode
		FROM tenant_decommission_audit tda
		JOIN devices d ON d.tenant_id = tda.tenant_id
		WHERE d.id = $1::uuid AND tda.directive_version <= $2
		ORDER BY tda.directive_version DESC, tda.changed_at DESC, tda.id DESC
		LIMIT 1
	`, deviceID, envelopeVersion).Scan(&resolvedDirectiveVersion, &resolvedMode)
	if err != nil {
		if isNoRowsErr(err) {
			return 0, "none", nil
		}
		return 0, "", err
	}
	return resolvedDirectiveVersion, resolvedMode, nil
}

// AgentDecommissionStatusHandler builds POST /v1/agent-decommission-status —
// the two-phase status-report endpoint (PAT-1108 fourth-round finding P1-B).
// The contract requires the agent to call this TWICE per removal attempt,
// never once: "acknowledged" BEFORE it starts acting on the directive, then
// the GENUINE terminal outcome ("removed" on success, "failed" otherwise)
// AFTER the removal attempt has actually finished — with the agent's own
// uploader/reporting mechanism destroyed only once THAT second call has
// gone through (or its bounded retries are exhausted). Reporting "removed"
// before removal is even attempted — the single-phase design this replaced —
// is exactly what let a removal that subsequently failed leave the platform
// holding a durable, sticky, wrong "removed" record for a device that was
// never actually removed, with no channel left to correct it. See
// contracts/agent-config-schema.md's POST /v1/agent-decommission-status
// section for the full sequence. Auth is the device-level bearer +
// HMAC-SHA256 + replay (timestamp + nonce) scheme (auth.LookupDeviceByBearer),
// identical to POST /v1/inventory/enforcement-audit and the removal-tasks
// report endpoint — a tenant-wide credential cannot call this route, and the
// device_id is resolved exclusively from the authenticated credential, never
// from the request body, so one device can never report status for another.
func AgentDecommissionStatusHandler(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter, replaySkew time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "agent_decommission_status")

		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			logger.Warn("read body failed", "err", err)
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}

		tenantID, deviceID, secret, err := auth.LookupDeviceByBearer(r.Context(), pool, r.Header.Get("Authorization"))
		if err != nil {
			if errors.Is(err, auth.ErrDeviceCredentialRequired) {
				logger.Warn("device bearer lookup failed: credential is tenant-level, this endpoint requires a device-scoped credential", "err", err)
				metrics.DeviceCredentialRequiredTotal.WithLabelValues("agent_decommission_status").Inc()
			} else {
				logger.Warn("device bearer lookup failed", "err", err)
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if rl != nil {
			if allowed, retryAfter := rl.Allow(tenantID); !allowed {
				logger.Warn("rate limit exceeded", "tenant_id", tenantID)
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}

		if err := auth.VerifyHMACSigned(secret, r.Method, auth.EndpointAgentDecommissionStatus, r.Header.Get("X-Patched-Timestamp"), r.Header.Get("X-Patched-Nonce"), body, r.Header.Get("X-Patched-Signature")); err != nil {
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

		var req agentDecommissionStatusReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if !agentReportableDecommissionStatuses[req.Status] {
			http.Error(w, "status must be one of acknowledged, removed, failed, expired_unreachable", http.StatusBadRequest)
			return
		}

		// PAT-1108 fourth-round finding P1-1: validation, the status write,
		// and the decision to respond "proceed" must happen inside ONE
		// transaction that takes the SAME tenants-row FOR UPDATE lock
		// TenantDecommissionPutHandler takes for its own writes (via
		// lockTenantAndReadDecommissionState below). Before this fix, the
		// read of the tenant's current directive, the device_decommission_state
		// write, and the HTTP response were three separate pool operations
		// with no lock between them — a cancellation (or re-issue) could
		// commit in the gap between "we decided this report is current" and
		// "we told the agent to proceed", authorising an irreversible
		// removal for a directive the server had already superseded. Taking
		// the lock here means a concurrent PUT either fully commits before
		// this transaction reads the tenant's state, or blocks until this
		// transaction commits — there is no window where a cancellation can
		// land in between.
		tx, err := pool.BeginTx(r.Context(), pgx.TxOptions{})
		if err != nil {
			logger.Error("begin tx failed", "err", err, "tenant_id", tenantID, "device_id", deviceID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		tenantExists, currentModePtr, currentExpiresAt, _, _, currentDirectiveVersion, err := lockTenantAndReadDecommissionState(r.Context(), tx, tenantID)
		if err != nil {
			logger.Error("lock tenant and read decommission state failed", "err", err, "tenant_id", tenantID, "device_id", deviceID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !tenantExists {
			// A device authenticated successfully via a credential scoped to
			// tenantID, so the tenant row should always exist here. Fail
			// closed rather than guess if it somehow does not — this never
			// grants "proceed", it only ever costs the agent a retry.
			logger.Error("tenant not found for authenticated device", "tenant_id", tenantID, "device_id", deviceID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		currentMode := "none"
		if currentModePtr != nil {
			currentMode = *currentModePtr
		}

		// PAT-1108 third-round finding A: validate the reported value against
		// the tenant's CURRENT ENVELOPE agent_config.config_version — the
		// only version the agent can actually observe — not against
		// tenant_decommission.directive_version. An unrelated agent-config
		// write (app_control, tier, ...) bumps the envelope without ever
		// touching the directive, so validating against directive_version
		// rejected perfectly valid terminal reports for a reason that had
		// nothing to do with decommission. Read on tx (fourth-round finding
		// P1-1) so it is consistent with the locked tenant_decommission read
		// above.
		envelopeVersion, err := dbCurrentEnvelopeVersionForDevice(r.Context(), tx, deviceID)
		if err != nil {
			logger.Error("fetch current envelope config_version failed", "err", err, "tenant_id", tenantID, "device_id", deviceID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		var resolvedDirectiveVersion int
		switch {
		case req.DirectiveVersion == nil:
			// Missing is untrusted, not current: see unattributedDirectiveVersion.
			// An agent that cannot say which envelope it verified can never
			// be told "proceed", and (since unattributedDirectiveVersion is
			// a sentinel no real currentDirectiveVersion can ever equal —
			// see its own doc comment) can never be persisted either, by
			// construction of the isStaleVersion check below.
			resolvedDirectiveVersion = unattributedDirectiveVersion
		case *req.DirectiveVersion < 0:
			http.Error(w, "directive_version must not be negative", http.StatusBadRequest)
			return
		case *req.DirectiveVersion > envelopeVersion:
			// A device cannot have verified an envelope config_version the
			// tenant's agent_config has not reached yet — clock skew, a
			// bug, or a forged report, and none of those should be stored
			// as if plausible.
			logger.Warn("rejected directive_version ahead of tenant's current agent_config.config_version",
				"tenant_id", tenantID, "device_id", deviceID,
				"reported_envelope_version", *req.DirectiveVersion, "current_envelope_version", envelopeVersion)
			http.Error(w, "directive_version is ahead of the tenant's current agent_config.config_version", http.StatusBadRequest)
			return
		default:
			// Resolve the verified envelope version to the directive
			// generation actually in effect at it — see
			// dbResolveDirectiveForEnvelopeVersion's doc comment.
			resolvedDirectiveVersion, _, err = dbResolveDirectiveForEnvelopeVersion(r.Context(), tx, deviceID, *req.DirectiveVersion)
			if err != nil {
				logger.Error("resolve directive for envelope version failed", "err", err, "tenant_id", tenantID, "device_id", deviceID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}

		// PAT-1108 third-round finding B, fourth-round finding P1-2,
		// fifth-round finding P1-A, sixth-round finding P1-F: three
		// SEPARATE decisions, not one collapsed isSuperseded boolean. Every
		// earlier round of this fix conflated at least two of these, which
		// is exactly what the non-author reviewer kept catching:
		//
		//  1. isStaleVersion — has the tenant cancelled or re-issued since
		//     the agent last verified its envelope? Applies uniformly to
		//     every status, terminal or not (finding B, unchanged since).
		//  2. shouldPersist — should THIS report be WRITTEN to
		//     device_decommission_state at all? "acknowledged" only needs
		//     the directive to be LIVE (any mode other than "none") — it
		//     is not itself irreversible, so recording "the device has
		//     seen this and is about to act" must not wait for the
		//     removal window to open (finding P1-A: gating it on
		//     authorisation broke the documented pending -> acknowledged
		//     transition for every not-yet-due mode="expiry" directive). A
		//     TERMINAL report additionally requires the directive to
		//     currently AUTHORISE REMOVAL — recording a terminal outcome
		//     is the platform's confirmation that the irreversible step
		//     was legitimate, so an unauthorised terminal report is still
		//     never persisted (unchanged from finding P1-2; this is
		//     distinct from finding P1-E, which is about an AUTHORISED
		//     terminal report arriving with no prior acknowledged — that
		//     one IS persisted, with phase1_observed=false).
		//  3. isAuthorised — what does the RESPONSE say: may the agent
		//     proceed with (or continue toward) the irreversible step?
		//     THIS is finding P1-F: under the two-phase protocol
		//     (contracts/agent-config-schema.md), the agent's removal
		//     ATTEMPT happens BETWEEN phase 1 (acknowledged) and phase 2
		//     (the terminal report). Gating authorisation only on phase
		//     2's response — as every prior round did — arrives too late
		//     to prevent anything: by the time that response exists,
		//     removal already happened. The ONLY response that can
		//     actually PREVENT an irreversible action is the one the
		//     agent receives BEFORE attempting it, i.e. phase 1's. So
		//     isAuthorised is gated on directiveAuthorisesRemoval for
		//     EVERY phase, including "acknowledged" — a device
		//     acknowledging a live but not-yet-due mode="expiry"
		//     directive gets that report PERSISTED (shouldPersist is
		//     satisfied: version current, directive live) but its
		//     response says "superseded" (isAuthorised is not: the
		//     removal window has not opened), in the SAME call. The
		//     device must not begin removal unless THIS response says
		//     proceed — persisted and authorised are different questions,
		//     and only the second one may ever license the irreversible
		//     step.
		isStaleVersion := resolvedDirectiveVersion != currentDirectiveVersion
		directiveIsLive := currentMode != "none"
		directiveAuthorisesRemoval := currentMode == "immediate" ||
			(currentMode == "expiry" && currentExpiresAt != nil && time.Now().After(*currentExpiresAt))
		isTerminalReport := terminalDecommissionStatuses[req.Status]

		var shouldPersist bool
		if isTerminalReport {
			shouldPersist = !isStaleVersion && directiveAuthorisesRemoval
		} else {
			shouldPersist = !isStaleVersion && directiveIsLive
		}
		isAuthorised := !isStaleVersion && directiveAuthorisesRemoval

		if !shouldPersist {
			// Do NOT run the write below — for a stale-version report that
			// would attribute it to a directive generation that is no
			// longer current (finding B); for an unauthorised terminal
			// report that would record a terminal outcome the platform has
			// not actually confirmed (finding P1-2). This transaction
			// performed no writes (only the FOR UPDATE read lock), so
			// committing it just releases that lock cleanly.
			if err := tx.Commit(r.Context()); err != nil {
				logger.Error("commit failed on non-persisted report", "err", err, "tenant_id", tenantID, "device_id", deviceID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			// Still record that the device made contact — it did act, and
			// that is a real event worth an operator-visible trace — via
			// the same best-effort last_reported_at bump the within-directive
			// stale-report path below uses. Deliberately NOT part of the
			// transaction above: a failure here must not turn a superseded
			// report into a 500 for the agent, and it must not be able to
			// abort the decision transaction either.
			if _, upErr := pool.Exec(r.Context(), `UPDATE device_decommission_state SET last_reported_at = now() WHERE device_id = $1::uuid`, deviceID); upErr != nil {
				logger.Warn("recording superseded decommission report arrival failed (non-fatal)", "err", upErr, "tenant_id", tenantID, "device_id", deviceID)
			}
			logger.Warn("decommission status report not persisted — telling agent to STOP, not proceed with removal",
				"tenant_id", tenantID, "device_id", deviceID, "reported_status", req.Status,
				"resolved_directive_version", resolvedDirectiveVersion, "current_directive_version", currentDirectiveVersion, "current_mode", currentMode)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(agentDecommissionStatusResp{
				Decommission: "superseded",
				DeviceID:     deviceID,
			})
			return
		}

		// status regression guard (PAT-1108 finding 4), SCOPED WITHIN A
		// DIRECTIVE VERSION (PAT-1108 second-round finding C): the ON
		// CONFLICT ... WHERE clause allows the write whenever EITHER
		//   (a) the report is for a STRICTLY NEWER directive_version than
		//       whatever is currently stored — a new (or re-issued)
		//       directive always supersedes any prior directive's outcome,
		//       terminal or not; a terminal result for directive N must
		//       never block a report for directive N+1 (this is exactly
		//       what second-round finding C reported: combined with the
		//       finding 5 stale-read logic, a stuck terminal-for-N row made
		//       the device un-updatable forever once a new directive N+1
		//       was issued), OR
		//   (b) the report is for the SAME directive_version as what's
		//       stored AND that stored status is not yet terminal — the
		//       original finding 4 behaviour, preserved unchanged within a
		//       single directive.
		// A report for an OLDER directive_version than what's already
		// stored is never accepted here either way — see
		// terminalDecommissionStatuses' doc comment; a device can only move
		// forward in directive_version once it has reported anything. By
		// this point resolvedDirectiveVersion == currentDirectiveVersion
		// (the shouldPersist check above already returned otherwise via
		// isStaleVersion), so this is scoped within the SAME directive
		// generation the tenant currently has in effect. RowsAffected()
		// below can then only mean "the WHERE guard suppressed the write",
		// never "no matching device", since the scalar $1 device_id always
		// matches exactly one row or inserts one. Run on tx (fourth-round
		// finding P1-1): the write happens inside the SAME transaction that
		// holds the tenants row lock and made the persistence decision
		// above, so nothing can invalidate that decision before the write
		// and the response it produces both commit together.
		//
		// phase1_observed (PAT-1108 fifth-round finding P1-E): the
		// documented protocol requires "acknowledged" (phase 1) before a
		// terminal outcome (phase 2), but a terminal report that arrives
		// with no observed phase 1 is still ACCEPTED here, never rejected —
		// see the package doc comment and terminalDecommissionStatuses for
		// why rejecting would be the worse trade (it would let a device
		// whose earlier acknowledged report was merely lost in transit
		// never report its genuine last word at all). What changes is
		// whether the record stays honest about what the server actually
		// observed:
		//   - EXCLUDED.status = 'acknowledged': this write IS phase 1,
		//     self-observed — always true.
		//   - otherwise (a terminal status): true only if the row ALREADY
		//     stored (before this write) was 'acknowledged' for THIS SAME
		//     directive_version — i.e. phase 1 genuinely happened for the
		//     directive generation this terminal report describes. An
		//     'acknowledged' row from an OLDER directive generation does
		//     NOT count (the directive_version equality guards this), and
		//     neither does no row at all (first-ever report, straight to
		//     terminal) — both correctly evaluate to false.
		tag, err := tx.Exec(r.Context(), `
			INSERT INTO device_decommission_state (device_id, status, last_reported_outcome, directive_version, phase1_observed, first_reported_at, last_reported_at, updated_at)
			VALUES ($1::uuid, $2, $3, $4, ($2 = 'acknowledged'), now(), now(), now())
			ON CONFLICT (device_id) DO UPDATE
				SET status = EXCLUDED.status,
				    last_reported_outcome = EXCLUDED.last_reported_outcome,
				    directive_version = EXCLUDED.directive_version,
				    phase1_observed = (EXCLUDED.status = 'acknowledged')
				                      OR (device_decommission_state.status = 'acknowledged'
				                          AND device_decommission_state.directive_version = EXCLUDED.directive_version),
				    last_reported_at = now(),
				    updated_at = now()
				WHERE device_decommission_state.directive_version < EXCLUDED.directive_version
				   OR (device_decommission_state.directive_version = EXCLUDED.directive_version
				       AND device_decommission_state.status NOT IN ('removed', 'failed', 'expired_unreachable'))
		`, deviceID, req.Status, req.Detail, resolvedDirectiveVersion)
		if err != nil {
			logger.Error("upsert device_decommission_state failed", "err", err, "tenant_id", tenantID, "device_id", deviceID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		rowsAffected := tag.RowsAffected()

		// Read the persisted status back on the SAME tx, BEFORE commit
		// (PAT-1108 second-round finding D's "no post-commit read required"
		// lesson, applied here too): a separate pool read after commit would
		// not need to observe this transaction's own write via a fresh
		// connection acquisition, reintroducing exactly the false-failure-
		// on-a-committed-write risk finding D fixed for the PUT handler.
		var persistedStatus string
		if err := tx.QueryRow(r.Context(), `SELECT status FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&persistedStatus); err != nil {
			logger.Error("post-write status re-read failed", "err", err, "tenant_id", tenantID, "device_id", deviceID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err, "tenant_id", tenantID, "device_id", deviceID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if rowsAffected == 0 {
			// Stale out-of-order report WITHIN the same directive
			// generation, ignored (not rejected — see
			// terminalDecommissionStatuses' doc comment): a report for the
			// same directive_version as an already-terminal stored status.
			// The true state is left untouched. Still record that the
			// device made contact — cheap, and useful operator signal —
			// without touching the stored outcome. Best-effort, outside the
			// transaction for the same reason as the superseded path above:
			// a failure here must not turn an ignored stale report into a
			// 500 for the agent.
			if _, upErr := pool.Exec(r.Context(), `UPDATE device_decommission_state SET last_reported_at = now() WHERE device_id = $1::uuid`, deviceID); upErr != nil {
				logger.Warn("recording stale decommission report arrival failed (non-fatal)", "err", upErr, "tenant_id", tenantID, "device_id", deviceID)
			}
			logger.Info("stale decommission status report ignored — terminal state already recorded",
				"tenant_id", tenantID, "device_id", deviceID, "reported_status", req.Status)
		} else {
			logger.Warn("device decommission status reported",
				"tenant_id", tenantID, "device_id", deviceID, "status", req.Status)
		}

		// PAT-1108 sixth-round finding P1-F: the response's decommission
		// field is gated on isAuthorised, NOT on shouldPersist — reaching
		// this point only means the write was ATTEMPTED (and, per
		// terminalDecommissionStatuses' stickiness rules above, may or may
		// not have actually changed anything). Authorisation is the
		// SEPARATE question of whether directiveAuthorisesRemoval holds
		// right now. A phase 1 "acknowledged" report against a live but
		// not-yet-due mode="expiry" directive lands exactly here — the
		// write above persisted it — but isAuthorised is false, so the
		// response must still say "superseded": this is the ONLY response
		// the agent sees before it would attempt removal, so it is the
		// only one that can actually prevent an early attempt. HTTP status
		// tracks decommission exactly as it always has: 409 for superseded,
		// 200 (implicit, no explicit WriteHeader) for proceed.
		decommission := "superseded"
		if isAuthorised {
			decommission = "proceed"
		}
		w.Header().Set("Content-Type", "application/json")
		if !isAuthorised {
			w.WriteHeader(http.StatusConflict)
		}
		_ = json.NewEncoder(w).Encode(agentDecommissionStatusResp{
			Decommission:   decommission,
			DeviceID:       deviceID,
			RecordedStatus: persistedStatus,
		})
	}
}
