package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/agentconfig"
	"patched.im/api/internal/auth"
	"patched.im/api/internal/evidencecatalogue"
	"patched.im/api/internal/ratelimit"
	"patched.im/api/internal/rings"
)

// agentConfigResp is the GET /v1/agent-config response.
// signed_payload is the base64-encoded canonical JSON the server signed.
// The agent base64-decodes it, verifies the Ed25519 signature over those exact
// bytes, then json-parses the verified bytes — no client-side reconstruction.
type agentConfigResp struct {
	SignedPayload string `json:"signed_payload"`
	KeyID         string `json:"key_id"`
	Signature     string `json:"signature"`
}

// syntheticDefaultConfigVersion is the config_version the GET /v1/agent-config
// synthetic-default branch (below) serves for a tenant with no agent_config
// row at all. It is the single source of truth for that value — anything else
// that needs to reason about "what version does a not-yet-provisioned tenant
// already look like it has accepted" (e.g. bumpAgentConfigVersionForDecommission
// in agent_decommission.go, PAT-1108 second-round finding A) must derive from
// this constant rather than hard-coding 1 a second time, so the two can never
// silently drift apart again.
const syntheticDefaultConfigVersion = 1

var (
	legacyExecutionActivationOnce sync.Once
	legacyExecutionActivationID   string
	legacyExecutionActivationErr  error
)

// legacyExecutionProcessActivation returns one unpredictable identifier for
// the lifetime of this API process. Every production AgentConfigHandler in the
// process shares it, so rebuilding router wiring cannot manufacture another
// generation. A fresh process, including a redeploy after binary rollback,
// gets a fresh identifier and therefore a fresh durable generation.
func legacyExecutionProcessActivation() (string, error) {
	legacyExecutionActivationOnce.Do(func() {
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			legacyExecutionActivationErr = fmt.Errorf("generate legacy execution quarantine activation: %w", err)
			return
		}
		legacyExecutionActivationID = hex.EncodeToString(nonce[:])
	})
	return legacyExecutionActivationID, legacyExecutionActivationErr
}

// OsUpdatePolicyReq is the os_update_policy section of the admin PUT body.
// Enabled gates whether the policy is written; when false (or omitted) the
// stored policy remains null and no OS-update nudging is active.
// Field names match the C# [JsonPropertyName] annotations in OsUpdatePolicy.cs
// and the agent-side contract shape.
type OsUpdatePolicyReq struct {
	Enabled               bool    `json:"enabled"`
	GraceDays             int     `json:"grace_days"`
	DeferralBudget        int     `json:"deferral_budget"`
	DeferIntervalHours    int     `json:"defer_interval_hours"`
	BlockingWindowDays    int     `json:"blocking_window_days"`
	MinimumAgeDays        int     `json:"minimum_age_days"`
	Deadline              *string `json:"deadline"`
	ExploitedOverridesAge bool    `json:"exploited_overrides_age"`
}

// osUpdatePolicyWire is the shape serialised into the JSONB column and signed
// into the canonical payload. It matches OsUpdatePolicy.cs field names exactly.
type osUpdatePolicyWire struct {
	TargetOs              interface{} `json:"target_os"`
	MinimumAgeDays        int         `json:"minimum_age_days"`
	GraceDays             int         `json:"grace_days"`
	Deadline              *string     `json:"deadline"`
	DeferralBudget        int         `json:"deferral_budget"`
	DeferIntervalHours    int         `json:"defer_interval_hours"`
	BlockingWindowDays    int         `json:"blocking_window_days"`
	ExploitedOverridesAge bool        `json:"exploited_overrides_age"`
}

// BlockingProcessPolicyReq is the blocking_process_policy section of the admin PUT
// body (PAT-296). All fields are pointers so the handler can distinguish "unset"
// (apply the safe schema default) from an explicit value — this matters for
// max_deferrals where 0 is a meaningful setting ("no deferrals allowed"), not an
// absent field. Field names match the agent-config JSON schema.
type BlockingProcessPolicyReq struct {
	Message            *string `json:"message"`
	TimeoutSeconds     *int    `json:"timeout_seconds"`
	MaxDeferrals       *int    `json:"max_deferrals"`
	DeferWindowSeconds *int    `json:"defer_window_seconds"`
	ActionOnTimeout    *string `json:"action_on_timeout"`
}

// Blocking-process-policy schema defaults (PAT-296). Applied server-side when the
// admin omits a field so the stored policy is always fully materialised.
const (
	defaultBlockingTimeoutSeconds     = 300
	defaultBlockingMaxDeferrals       = 2
	defaultBlockingDeferWindowSeconds = 3600
)

// adminAgentConfigReq is the body for PUT /admin/agent-config/{tenantID}.
// log_request is optional; omit or set to null to clear any pending log-request
// directive. When set, it is signed as part of the config body and delivered to
// the target device on its next GET /v1/agent-config poll (PAT-286).
// os_update_policy is optional; omit or set enabled=false to clear any active
// policy (stores null). When enabled=true the policy fields are written to JSONB.
// update_channel is optional; omit to preserve the existing channel (default "stable").
// pinned_version is optional; null/omit clears any pin; a string pins to that version.
// blocked_versions is optional; omit/empty clears any stored blocking list (PAT-1238;
// full-replace, same as every other general field on this endpoint — no
// preserve-on-omit special-casing like ring_promotions/update_channel).
type adminAgentConfigReq struct {
	Tier                        string                           `json:"tier"`
	Proxy                       agentconfig.ProxyConfig          `json:"proxy"`
	LogRequest                  *agentconfig.LogRequestDirective `json:"log_request"`
	OsUpdatePolicy              *OsUpdatePolicyReq               `json:"os_update_policy,omitempty"`
	BlockingProcessPolicy       *BlockingProcessPolicyReq        `json:"blocking_process_policy,omitempty"`       // PAT-296; null/omit clears any stored policy (agent falls back to safe defaults)
	UpdateChannel               *string                          `json:"update_channel,omitempty"`                // "stable" | "beta"; null/omit = keep existing or default
	PinnedVersion               *string                          `json:"pinned_version,omitempty"`                // null = always latest; string = pin to version
	BlockedVersions             map[string][]string              `json:"blocked_versions,omitempty"`              // PAT-1238; label -> blocked version strings; omit/empty clears
	MandatoryInstallIntents     json.RawMessage                  `json:"mandatory_install_intents,omitempty"`     // reserved response-only field; any admin-supplied value is rejected
	WindowsInstallationEvidence json.RawMessage                  `json:"windows_installation_evidence,omitempty"` // reserved response-only evidence
	UpdatedBy                   string                           `json:"updated_by"`
}

// adminAgentConfigResp is returned by the write path.
type adminAgentConfigResp struct {
	TenantID      string `json:"tenant_id"`
	ConfigVersion int    `json:"config_version"`
	KeyID         string `json:"key_id"`
}

// agentConfigRow is the result of reading an agent_config DB row plus the
// tenant-level AC policy sourced from the tenants table.
type agentConfigRow struct {
	TenantID               string
	ConfigVersion          int
	Body                   agentconfig.ConfigBody
	IssuedAt               time.Time
	AppControlEnabled      bool     // mirrors tenants.app_control_enabled (PAT-601)
	AppControlAdmins       []string // mirrors tenants.app_control_approved_admins (PAT-602)
	AppControlAppAllowlist []string // mirrors tenants.app_control_app_allowlist (PAT-602)

	// ExtensionBlocklist is projected from tenant_extension_policies (PAT-826,
	// migration 0071) rows with policy='unapproved' (PAT-828/PAT-832).
	ExtensionBlocklist []agentconfig.ExtensionBlocklistEntry
	// ExtensionRemovals is projected from tenant_extension_removal_requests
	// (migration 0074) rows with fulfilled=false (PAT-829/PAT-832).
	ExtensionRemovals []agentconfig.ExtensionRemovalEntry

	// Decommission mirrors the tenant's tenant_decommission row (PAT-1108, migration
	// 0091). Absence of a row (LEFT JOIN) defaults to agentconfig.DefaultDecommissionPolicy()
	// (mode="none") — the same "absent means inert" contract as a tenant with no
	// app_control row. Never sourced from ConfigBody/agent_config.body: like
	// AppControlPolicy, it lives in its own table so a routine PUT
	// /admin/agent-config (which reconstructs ConfigBody from the request) can
	// never accidentally clear or overwrite it.
	Decommission agentconfig.DecommissionPolicy
}

// agentConfigAuthFn authenticates a GET /v1/agent-config request.
// Returns the resolved tenantID, optional deviceID (empty string for tenant-wide
// credentials), or an error on any auth failure.
// Closed over the pool in production; stubbed in tests.
type agentConfigAuthFn func(ctx context.Context, authHeader, sigHeader, ts, nonce string, body []byte) (tenantID, deviceID string, err error)

// agentConfigGetFn reads the agent_config row for a tenant.
// Returns (row, found=true, nil) when a row exists; (_, false, nil) when absent.
type agentConfigGetFn func(ctx context.Context, tenantID string) (agentConfigRow, bool, error)

// agentConfigUpsertFn writes (insert-or-update) an agent_config row.
// On insert: config_version = 1. On update: config_version += 1.
type agentConfigUpsertFn func(ctx context.Context, tenantID, updatedBy string, body agentconfig.ConfigBody) (agentConfigRow, error)

// agentConfigExistsFn reports whether a tenant row exists (for admin PUT 404 guard).
type agentConfigExistsFn func(ctx context.Context, tenantID string) (bool, error)

// AgentConfigHandler builds the public GET /v1/agent-config handler.
// Auth: bearer + HMAC-SHA256 over the (empty) request body, followed by
// per-tenant rate limiting and replay validation — same chain as /v1/inventory.
//
// Per-device ring injection (PAT-117): if the credential is device-scoped, the
// device's effective ring (COALESCE(ring_override, ring_computed, 3)) is injected
// into the signed payload. Tenant-wide credentials receive ring=3 (GA, safe default).
func AgentConfigHandler(pool *pgxpool.Pool, key *agentconfig.SigningKey, rl *ratelimit.TenantLimiter, replaySkew time.Duration) http.HandlerFunc {
	activationID, activationErr := legacyExecutionProcessActivation()
	authFn := func(ctx context.Context, authHeader, sigHeader, ts, nonce string, body []byte) (string, string, error) {
		// Try device-scoped credential first (PAT-117 ring injection path).
		if tenantID, deviceID, secret, err := auth.LookupDeviceByBearer(ctx, pool, authHeader); err == nil {
			if hmacErr := auth.VerifyHMACSigned(secret, http.MethodGet, auth.EndpointAgentConfig, ts, nonce, body, sigHeader); hmacErr != nil {
				return "", "", hmacErr
			}
			return tenantID, deviceID, nil
		}
		// Fall back to tenant-wide credential (device ring will default to 3/GA).
		tenantID, secret, err := auth.LookupTenantByBearer(ctx, pool, authHeader)
		if err != nil {
			return "", "", err
		}
		if err := auth.VerifyHMACSigned(secret, http.MethodGet, auth.EndpointAgentConfig, ts, nonce, body, sigHeader); err != nil {
			return "", "", err
		}
		return tenantID, "", nil
	}
	getFn := func(ctx context.Context, tenantID string) (agentConfigRow, bool, error) {
		if activationErr != nil {
			return agentConfigRow{}, false, activationErr
		}
		return dbGetQuarantinedAgentConfig(ctx, pool, tenantID, activationID)
	}
	return newAgentConfigHandler(key, authFn, getFn, rl, replaySkew, pool)
}

// dbGetQuarantinedAgentConfig is the production read path for the contained
// agent-config response. Before it reads or signs anything, it durably records
// one generation transition for this tenant and contained process activation.
// That makes a freshly deployed contained process issue a report_deploy/disabled
// envelope strictly newer than every envelope an intervening old executable
// binary could have issued for the same persisted row.
//
// The transition is deliberately lazy rather than migration-backfilled. The
// deployment applies migrations before replacing the binary; bumping versions
// in a migration would allow the old binary to issue an executable envelope at
// the new version in that window. The activation row and version advance below
// commit together only after the contained binary is serving. Repeated GETs
// from the same process observe the durable activation and use the ordinary
// lock-free config read; concurrent first GETs conflict on the activation key
// and only one bumps. Multiple contained processes each advance once on their
// first tenant GET; alternating later requests do not oscillate because every
// process activation remains recorded instead of replacing one last-seen marker.
// A tenant without a row is first materialised at the historical synthetic
// default and then advanced to version 2 in the same transaction.
func dbGetQuarantinedAgentConfig(ctx context.Context, pool *pgxpool.Pool, tenantID, activationID string) (agentConfigRow, bool, error) {
	decodedActivation, decodeErr := hex.DecodeString(activationID)
	if decodeErr != nil || len(decodedActivation) != 32 {
		return agentConfigRow{}, false, errors.New("legacy execution quarantine activation is invalid")
	}
	var alreadyActivated bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM agent_config_legacy_execution_activations
			WHERE tenant_id = $1::uuid AND activation_id = $2
		)
	`, tenantID, activationID).Scan(&alreadyActivated); err != nil {
		return agentConfigRow{}, false, fmt.Errorf("read legacy execution quarantine activation: %w", err)
	}
	if alreadyActivated {
		return dbGetAgentConfig(ctx, pool, tenantID)
	}

	defaultBody, err := json.Marshal(agentconfig.DefaultConfigBody())
	if err != nil {
		return agentConfigRow{}, false, fmt.Errorf("marshal quarantine default config body: %w", err)
	}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return agentConfigRow{}, false, fmt.Errorf("begin legacy execution quarantine activation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO agent_config (
			tenant_id, config_version, body, issued_at, updated_by
		)
		SELECT $1::uuid, $2, $3::jsonb, now(), 'legacy_execution_quarantine'
		FROM tenants
		WHERE id = $1::uuid
		ON CONFLICT (tenant_id) DO NOTHING
	`, tenantID, syntheticDefaultConfigVersion, defaultBody)
	if err != nil {
		return agentConfigRow{}, false, fmt.Errorf("materialize legacy execution quarantine config: %w", err)
	}

	_, err = tx.Exec(ctx, `
		WITH next_generation AS (
			SELECT tenant_id, config_version + 1 AS config_version
			FROM agent_config
			WHERE tenant_id = $1::uuid
			FOR UPDATE
		), activated AS (
			INSERT INTO agent_config_legacy_execution_activations (
				tenant_id, activation_id, config_version, activated_at
			)
			SELECT tenant_id, $2, config_version, now()
			FROM next_generation
			ON CONFLICT (tenant_id, activation_id) DO NOTHING
			RETURNING tenant_id, config_version
		)
		UPDATE agent_config ac
		SET config_version = activated.config_version,
		    issued_at = now(),
		    updated_by = 'legacy_execution_quarantine',
		    legacy_execution_quarantine_version = activated.config_version
		FROM activated
		WHERE ac.tenant_id = activated.tenant_id
	`, tenantID, activationID)
	if err != nil {
		return agentConfigRow{}, false, fmt.Errorf("advance legacy execution quarantine generation: %w", err)
	}

	row, found, err := dbGetAgentConfigViaQuerier(ctx, tx, tenantID)
	if err != nil {
		return agentConfigRow{}, false, err
	}
	if !found {
		return agentConfigRow{}, false, fmt.Errorf("tenant %s has no agent_config after quarantine activation", tenantID)
	}
	if err := tx.Commit(ctx); err != nil {
		return agentConfigRow{}, false, fmt.Errorf("commit legacy execution quarantine activation: %w", err)
	}
	return row, true, nil
}

// AdminAgentConfigPutHandler builds PUT /admin/agent-config/{tenantID}.
// Auth: network-only (Tailscale-bound internal listener) — same posture as all
// other /admin/* endpoints.
func AdminAgentConfigPutHandler(pool *pgxpool.Pool, key *agentconfig.SigningKey) http.HandlerFunc {
	existsFn := func(ctx context.Context, tenantID string) (bool, error) {
		var exists bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid)`, tenantID,
		).Scan(&exists)
		return exists, err
	}
	getExistingFn := func(ctx context.Context, tenantID string) (agentConfigRow, bool, error) {
		return dbGetAgentConfig(ctx, pool, tenantID)
	}
	upsertFn := func(ctx context.Context, tenantID, updatedBy string, body agentconfig.ConfigBody) (agentConfigRow, error) {
		return dbUpsertAgentConfig(ctx, pool, tenantID, updatedBy, body)
	}
	return newAdminAgentConfigPutHandler(key, existsFn, getExistingFn, upsertFn)
}

// newAgentConfigHandler builds the GET handler with injectable functions for testing.
// rl and pool may be nil in unit tests that stub authFn — replay validation is
// skipped when pool is nil.
func newAgentConfigHandler(key *agentconfig.SigningKey, authFn agentConfigAuthFn, getFn agentConfigGetFn, rl *ratelimit.TenantLimiter, replaySkew time.Duration, pool *pgxpool.Pool) http.HandlerFunc {
	publisher := evidencecatalogue.NewWindowsDeliveryPublisher(pool)
	return newAgentConfigHandlerWithEvidence(key, authFn, getFn, rl, replaySkew, pool, func(ctx context.Context) (*evidencecatalogue.WindowsDelivery, error) {
		return publisher.Delivery(ctx, time.Now().UTC())
	})
}

type windowsEvidenceFn func(context.Context) (*evidencecatalogue.WindowsDelivery, error)

func newAgentConfigHandlerWithEvidence(key *agentconfig.SigningKey, authFn agentConfigAuthFn, getFn agentConfigGetFn, rl *ratelimit.TenantLimiter, replaySkew time.Duration, pool *pgxpool.Pool, evidenceFn windowsEvidenceFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "agent_config_get")

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			logger.Warn("read body failed", "err", err)
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}

		tenantID, deviceID, err := authFn(r.Context(), r.Header.Get("Authorization"), r.Header.Get("X-Patched-Signature"), r.Header.Get("X-Patched-Timestamp"), r.Header.Get("X-Patched-Nonce"), body)
		if err != nil {
			logger.Warn("auth failed", "err", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Rate limit — applied after bearer lookup (tenant ID resolved by authFn).
		if rl != nil {
			if allowed, retryAfter := rl.Allow(tenantID); !allowed {
				logger.Warn("rate limit exceeded", "tenant_id", tenantID)
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}

		// Replay protection — pool may be nil in tests.
		if pool != nil {
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
		}

		row, found, err := getFn(r.Context(), tenantID)
		if err != nil {
			logger.Error("get agent_config failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !found {
			// Guard against tenants created between migration and deploy.
			// row.Decommission may already be populated even though found is
			// false — dbGetAgentConfig's not-found branch still consults
			// tenant_decommission directly (PAT-1108 finding 2) — so it must
			// be carried over here, not defaulted away. A getFn stub that
			// returns a genuinely empty row leaves this as the zero value,
			// which safeDecommissionPolicy (agentconfig.Sign) still coerces
			// to the safe "none" default, same as before.
			row = agentConfigRow{
				TenantID:      tenantID,
				ConfigVersion: syntheticDefaultConfigVersion,
				Body:          agentconfig.DefaultConfigBody(),
				IssuedAt:      time.Now().UTC(),
				Decommission:  row.Decommission,
			}
		}

		if pool != nil {
			if err := projectAgentReleaseConfig(r.Context(), pool, tenantID, deviceID, &row); err != nil {
				logger.Error("release authority projection failed", "err", err)
				http.Error(w, "release authority unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		// Never accept a tenant-stored projection. Publication happens only
		// after authentication/replay checks and before any directive holds
		// a database connection. Failure isolates this additive feature.
		row.Body.WindowsInstallationEvidence = nil
		if evidence, evidenceErr := evidenceFn(r.Context()); evidenceErr != nil {
			logger.Warn("Windows installation evidence unavailable; serving config without evidence targets", "err", evidenceErr)
		} else {
			row.Body.WindowsInstallationEvidence = evidence
		}
		// Destructive extension removals are delivered only to an authenticated
		// device that was captured as a target when the operator created the job.
		// Each directive is narrowed to one exact profile, even when the operator
		// selected an estate-wide scope. This prevents a later install/profile from
		// being swept into an already-approved destructive request. Tenant-wide
		// credentials and disabled extension control receive no removal directives.
		if pool != nil {
			if !row.AppControlEnabled || deviceID == "" {
				row.ExtensionRemovals = []agentconfig.ExtensionRemovalEntry{}
			} else {
				row.ExtensionRemovals, err = dbGetExtensionRemovalsForDevice(r.Context(), pool, tenantID, deviceID)
				if err != nil {
					logger.Error("get device extension removals failed", "err", err, "tenant_id", tenantID, "device_id", deviceID)
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
			}
		}

		// Resolve per-device ring (PAT-117). Defaults to 3 (GA) for tenant-wide creds.
		effectiveRing := 3
		if deviceID != "" && pool != nil {
			var ringOverride, ringComputed *int16
			_ = pool.QueryRow(r.Context(),
				`SELECT ring_override, ring_computed FROM devices WHERE id = $1::uuid`,
				deviceID,
			).Scan(&ringOverride, &ringComputed)
			effectiveRing = rings.EffectiveAgentRing(ringOverride, ringComputed)
			// Lazy compute if ring_computed is unset (newly enrolled device).
			if ringComputed == nil && ringOverride == nil {
				// Non-fatal: use default 3 this request; worker will fill it in.
				effectiveRing = 3
			}
		}

		issuedAtStr := row.IssuedAt.UTC().Format(time.RFC3339)
		ac := agentconfig.AppControlPolicy{
			Enabled:            row.AppControlEnabled,
			ApprovedAdmins:     row.AppControlAdmins,
			AppAllowlist:       row.AppControlAppAllowlist,
			ExtensionBlocklist: row.ExtensionBlocklist,
			ExtensionRemovals:  row.ExtensionRemovals,
		}
		// Project the stored commercial/assurance configuration into a
		// fail-closed legacy-agent response immediately before signing. Do not
		// mutate row.Body: assurance/managed (PAT-1599) remains durable tenant
		// policy for the retained assurance and self-update surfaces, but
		// pre-PAT-1134 agents
		// only understand tier and ring_promotions and would otherwise retain
		// application-execution authority.
		responseBody := row.Body
		responseBody.AppControlAuthority = agentconfig.AppControlAuthorityForDurableTier(row.Body.Tier)
		signedBody := conservativeLegacyAgentProjection(responseBody)
		sigB64, keyID, canonical, signErr := agentconfig.Sign(key, signedBody, row.ConfigVersion, issuedAtStr, tenantID, deviceID, effectiveRing, ac, row.Decommission)
		if signErr != nil {
			logger.Error("sign agent_config failed", "err", signErr, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		resp := agentConfigResp{
			SignedPayload: base64.StdEncoding.EncodeToString(canonical),
			KeyID:         keyID,
			Signature:     sigB64,
		}
		encodedResp, err := json.Marshal(resp)
		if err != nil {
			logger.Error("serialize agent_config failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// ETag is a hash of the full canonical signed payload (PAT-868), not just
		// config_version+ring. The PUT handlers that mutate app_control (allowlist,
		// approved_admins, extension blocklist/removals)
		// do not bump config_version, so an ETag derived only from config_version
		// would keep matching a stale If-None-Match after a security-policy change
		// and the device would never learn about it. Hashing the actual canonical
		// bytes — the same bytes agentconfig.Sign just signed — means every signed
		// field is automatically covered, including ones added later; there is no
		// hand-maintained field list to fall out of sync.
		sum := sha256.Sum256(canonical)
		etag := fmt.Sprintf(`"v%d-r%d-%s"`, row.ConfigVersion, effectiveRing, hex.EncodeToString(sum[:]))
		w.Header().Set("ETag", etag)
		if inm := r.Header.Get("If-None-Match"); inm != "" && inm == etag {
			logger.Info("agent_config not modified", "tenant_id", tenantID, "config_version", row.ConfigVersion)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		logger.Info("agent_config served", "tenant_id", tenantID,
			"config_version", row.ConfigVersion, "key_id", keyID)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(append(encodedResp, '\n'))
	}
}

// conservativeLegacyAgentProjection produces the response-only view served
// while the quarantined legacy execution plane is disabled. It deliberately
// leaves durable tenant/commercial policy untouched: callers must pass a value
// and sign the returned copy.
//
// Pre-PAT-1134 agents understand tier and the label-only ring_promotions map,
// but ignore legacy_app_execution_enabled and ring_promotions_scoped. A null
// legacy map alone is not a gate to those clients, so report_deploy is the
// conservative old-understood authority. per_app_patch predates PAT-1134 too,
// is a reserved legacy execution field, and is defensively neutralised even
// though ordinary writes already store it as null.
// Decommission, OS-update/assurance, proxy and updater-channel fields are not
// legacy app execution authority and remain as stored.
//
// PAT-1599 CARVE-OUT: the literal "report_deploy" below is intentionally NOT
// part of the assurance/managed vocabulary collapse (migration 0138) and
// must not be changed by any future grep-driven "zero remaining occurrences"
// sweep for that ticket's retired strings. It is a fixed PAT-1481
// legacy-containment sentinel that already-deployed pre-PAT-1134 agent
// binaries recognize as "safe, non-executing" — independent of whatever the
// durable subscription_tier/agent_config.body.tier vocabulary is. Changing it
// changes nothing for current agents (which read app_control_authority
// instead) but is unverifiable against binaries already running on customer
// endpoints that this repo cannot update. Per root AGENTS.md's quarantine
// rule ("do not extend... preserve only what is needed to isolate it
// safely"), this stays exactly as-is.
func conservativeLegacyAgentProjection(body agentconfig.ConfigBody) agentconfig.ConfigBody {
	body.Tier = "report_deploy" // PAT-1599 carve-out — see comment above, do not change
	body.LegacyAppExecutionEnabled = false
	body.PerAppPatch = json.RawMessage("null")
	body.RingPromotions = json.RawMessage("null")
	body.RingPromotionsScoped = json.RawMessage(`{"macos":null,"windows":null}`)
	return body
}

// newAdminAgentConfigPutHandler builds the write handler with injectable functions.
func newAdminAgentConfigPutHandler(key *agentconfig.SigningKey, existsFn agentConfigExistsFn, getExistingFn agentConfigGetFn, upsertFn agentConfigUpsertFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "admin_agent_config_put")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		var req adminAgentConfigReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if len(req.MandatoryInstallIntents) != 0 {
			http.Error(w, "mandatory_install_intents is a reserved response-only field", http.StatusBadRequest)
			return
		}
		if len(req.WindowsInstallationEvidence) != 0 {
			http.Error(w, "windows_installation_evidence is a reserved response-only field", http.StatusBadRequest)
			return
		}

		if validationErr := validateAgentConfigReq(req); validationErr != nil {
			http.Error(w, validationErr.Error(), http.StatusBadRequest)
			return
		}
		exists, err := existsFn(r.Context(), tenantID)
		if err != nil {
			logger.Error("tenant existence check failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		if req.UpdatedBy == "" {
			req.UpdatedBy = "system"
		}

		osUpdatePolicyRaw, err := buildOsUpdatePolicyRaw(req.OsUpdatePolicy)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Preserve both rollout projections from the existing body. They are
		// owned by the rings rollout worker and must not be clobbered by a
		// general-purpose agent-config write.
		existingRow, _, _ := getExistingFn(r.Context(), tenantID)
		ringPromotions := existingRow.Body.RingPromotions
		if len(ringPromotions) == 0 {
			ringPromotions = json.RawMessage("null")
		}
		ringPromotionsScoped := existingRow.Body.RingPromotionsScoped
		if len(ringPromotionsScoped) == 0 {
			ringPromotionsScoped = json.RawMessage("null")
		}

		// Preserve update_channel from the existing body if the request omits it.
		updateChannel := "stable" // safe default
		if existingRow.Body.UpdateChannel != "" {
			updateChannel = existingRow.Body.UpdateChannel
		}
		if req.UpdateChannel != nil {
			updateChannel = *req.UpdateChannel
		}

		newBody := agentconfig.ConfigBody{
			BlockedVersions:       req.BlockedVersions,
			BlockingProcessPolicy: buildBlockingProcessPolicy(req.BlockingProcessPolicy),
			CatalogScope:          json.RawMessage("null"),
			LogRequest:            req.LogRequest,
			OsUpdatePolicy:        osUpdatePolicyRaw,
			PerAppPatch:           json.RawMessage("null"),
			PinnedVersion:         req.PinnedVersion,
			Proxy:                 req.Proxy,
			RingPromotions:        ringPromotions,
			RingPromotionsScoped:  ringPromotionsScoped,
			ScanCadence:           json.RawMessage("null"),
			Tier:                  req.Tier,
			UpdateChannel:         updateChannel,
		}

		row, err := upsertFn(r.Context(), tenantID, req.UpdatedBy, newBody)
		if err != nil {
			logger.Error("upsert agent_config failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		issuedAtStr := row.IssuedAt.UTC().Format(time.RFC3339)
		// Admin PUT signs with ring=3 (GA), no device_id, and default AC policy —
		// key_id echo-back only; per-device ring, device_id, and AC state are
		// injected at GET time by the public handler.
		_, keyID, _, signErr := agentconfig.Sign(key, row.Body, row.ConfigVersion, issuedAtStr, tenantID, "", 3, agentconfig.AppControlPolicy{}, agentconfig.DecommissionPolicy{})
		if signErr != nil {
			logger.Error("sign after upsert failed", "err", signErr, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("agent_config updated", "tenant_id", tenantID,
			"config_version", row.ConfigVersion, "updated_by", req.UpdatedBy)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(adminAgentConfigResp{
			TenantID:      tenantID,
			ConfigVersion: row.ConfigVersion,
			KeyID:         keyID,
		})
	}
}

// validateAgentConfigReq checks required fields and valid enum values.
func validateAgentConfigReq(req adminAgentConfigReq) error {
	// PAT-1599 (migration 0138): collapsed from report_deploy/patch/managed to
	// the same assurance/managed vocabulary SetTenantTierHandler validates
	// (admin.go validSubTiers) — one vocabulary, used identically everywhere,
	// whether written via PUT /admin/tenant-tier/{tenantID} or here directly.
	switch req.Tier {
	case "assurance", "managed":
	default:
		return fmt.Errorf("tier must be \"assurance\" or \"managed\", got %q", req.Tier)
	}
	if req.UpdateChannel != nil {
		switch *req.UpdateChannel {
		case "stable", "beta":
		default:
			return fmt.Errorf("update_channel must be \"stable\" or \"beta\", got %q", *req.UpdateChannel)
		}
	}
	switch req.Proxy.Mode {
	case "system", "manual", "off":
	default:
		return fmt.Errorf("proxy.mode must be \"system\", \"manual\", or \"off\", got %q", req.Proxy.Mode)
	}
	if req.Proxy.Mode == "manual" && (req.Proxy.Host == nil || *req.Proxy.Host == "") {
		return errors.New("proxy.host is required when proxy.mode is \"manual\"")
	}
	if req.LogRequest != nil {
		lr := req.LogRequest
		if !looksLikeUUID(lr.DeviceID) {
			return errors.New("log_request.device_id must be a UUID")
		}
		if !looksLikeUUID(lr.RequestID) {
			return errors.New("log_request.request_id must be a UUID")
		}
		if lr.MaxBytes <= 0 {
			return errors.New("log_request.max_bytes must be a positive integer")
		}
		if lr.Since != "" {
			if _, err := time.Parse(time.RFC3339, lr.Since); err != nil {
				return fmt.Errorf("log_request.since: %w", err)
			}
		}
		if lr.Until != "" {
			if _, err := time.Parse(time.RFC3339, lr.Until); err != nil {
				return fmt.Errorf("log_request.until: %w", err)
			}
		}
	}
	if p := req.OsUpdatePolicy; p != nil && p.Enabled {
		if p.GraceDays < 1 || p.GraceDays > 90 {
			return errors.New("os_update_policy.grace_days must be between 1 and 90")
		}
		if p.DeferralBudget < 0 || p.DeferralBudget > 10 {
			return errors.New("os_update_policy.deferral_budget must be between 0 and 10")
		}
		if p.DeferIntervalHours < 1 || p.DeferIntervalHours > 168 {
			return errors.New("os_update_policy.defer_interval_hours must be between 1 and 168")
		}
		if p.BlockingWindowDays < 1 || p.BlockingWindowDays > 30 {
			return errors.New("os_update_policy.blocking_window_days must be between 1 and 30")
		}
		if p.MinimumAgeDays < 0 || p.MinimumAgeDays > 30 {
			return errors.New("os_update_policy.minimum_age_days must be between 0 and 30")
		}
		if p.Deadline != nil {
			d := *p.Deadline
			if _, err := time.Parse(time.RFC3339, d); err != nil {
				if _, err2 := time.Parse("2006-01-02", d); err2 != nil {
					return fmt.Errorf("os_update_policy.deadline must be RFC3339 or YYYY-MM-DD, got %q", d)
				}
			}
		}
	}
	if bp := req.BlockingProcessPolicy; bp != nil {
		// action_on_timeout: reject any value outside the allowed set. An empty/
		// omitted action is permitted here and defaulted to notify_only server-side.
		if bp.ActionOnTimeout != nil && *bp.ActionOnTimeout != "" && !agentconfig.AllowedBlockingActions[*bp.ActionOnTimeout] {
			return fmt.Errorf("blocking_process_policy.action_on_timeout must be one of notify_only, prompt_then_quit, skip_run, got %q", *bp.ActionOnTimeout)
		}
		if bp.TimeoutSeconds != nil && (*bp.TimeoutSeconds < agentconfig.MinBlockingTimeoutSeconds || *bp.TimeoutSeconds > agentconfig.MaxBlockingTimeoutSeconds) {
			return fmt.Errorf("blocking_process_policy.timeout_seconds must be between %d and %d", agentconfig.MinBlockingTimeoutSeconds, agentconfig.MaxBlockingTimeoutSeconds)
		}
		if bp.MaxDeferrals != nil && *bp.MaxDeferrals < 0 {
			return errors.New("blocking_process_policy.max_deferrals must be >= 0")
		}
		if bp.DeferWindowSeconds != nil && (*bp.DeferWindowSeconds < agentconfig.MinBlockingDeferWindowSeconds || *bp.DeferWindowSeconds > agentconfig.MaxBlockingDeferWindowSeconds) {
			return fmt.Errorf("blocking_process_policy.defer_window_seconds must be between %d and %d", agentconfig.MinBlockingDeferWindowSeconds, agentconfig.MaxBlockingDeferWindowSeconds)
		}
		if bp.Message != nil && len(*bp.Message) > 500 {
			return errors.New("blocking_process_policy.message must be at most 500 characters")
		}
	}
	for label, versions := range req.BlockedVersions {
		trimmedLabel := strings.TrimSpace(label)
		if trimmedLabel == "" {
			return errors.New("blocked_versions: label must not be empty")
		}
		if strings.ContainsAny(label, "/\\") || strings.Contains(label, "..") {
			return fmt.Errorf("blocked_versions: label %q must not contain path separators or \"..\"", label)
		}
		if len(versions) == 0 {
			return fmt.Errorf("blocked_versions[%q]: must list at least one version", label)
		}
		for _, v := range versions {
			if strings.TrimSpace(v) == "" {
				return fmt.Errorf("blocked_versions[%q]: version entries must not be empty", label)
			}
		}
	}
	return nil
}

// buildBlockingProcessPolicy converts the admin request's blocking_process_policy
// into the *agentconfig.BlockingProcessPolicy stored in ConfigBody (PAT-296).
// Returns nil when the request omits the policy — an omitted policy clears any
// stored one and the agent falls back to its built-in safe defaults (same
// clear-on-omit semantics as os_update_policy). When present, every field is
// materialised: unset numeric/string fields take their safe schema default and,
// critically, action_on_timeout defaults to "notify_only" so the stored policy
// can never instruct the agent to force-quit. Assumes the request already passed
// validateAgentConfigReq.
func buildBlockingProcessPolicy(req *BlockingProcessPolicyReq) *agentconfig.BlockingProcessPolicy {
	if req == nil {
		return nil
	}
	out := &agentconfig.BlockingProcessPolicy{
		ActionOnTimeout:    agentconfig.DefaultBlockingActionOnTimeout,
		TimeoutSeconds:     defaultBlockingTimeoutSeconds,
		MaxDeferrals:       defaultBlockingMaxDeferrals,
		DeferWindowSeconds: defaultBlockingDeferWindowSeconds,
		Message:            req.Message,
	}
	if req.ActionOnTimeout != nil && *req.ActionOnTimeout != "" {
		out.ActionOnTimeout = *req.ActionOnTimeout
	}
	if req.TimeoutSeconds != nil {
		out.TimeoutSeconds = *req.TimeoutSeconds
	}
	if req.MaxDeferrals != nil {
		out.MaxDeferrals = *req.MaxDeferrals
	}
	if req.DeferWindowSeconds != nil {
		out.DeferWindowSeconds = *req.DeferWindowSeconds
	}
	return out
}

// buildOsUpdatePolicyRaw converts the request's os_update_policy into the
// json.RawMessage stored in ConfigBody. Returns json.RawMessage("null") when
// the policy is absent or disabled; otherwise marshals the wire shape.
func buildOsUpdatePolicyRaw(p *OsUpdatePolicyReq) (json.RawMessage, error) {
	if p == nil || !p.Enabled {
		return json.RawMessage("null"), nil
	}
	wire := osUpdatePolicyWire{
		TargetOs:              nil,
		MinimumAgeDays:        p.MinimumAgeDays,
		GraceDays:             p.GraceDays,
		Deadline:              p.Deadline,
		DeferralBudget:        p.DeferralBudget,
		DeferIntervalHours:    p.DeferIntervalHours,
		BlockingWindowDays:    p.BlockingWindowDays,
		ExploitedOverridesAge: p.ExploitedOverridesAge,
	}
	b, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("marshal os_update_policy: %w", err)
	}
	return json.RawMessage(b), nil
}

// dbGetAgentConfig reads the agent_config row for a tenant, joining the
// tenants table to pick up the AC policy fields (PAT-601/602) and
// tenant_decommission to pick up the decommission directive (PAT-1108). Both
// joins are LEFT JOINs: a tenant with no app_control row and no
// tenant_decommission row is not an error, it is the safe/inert default for
// each — FALSE/empty-list for app_control, mode="none" for decommission.
//
// The common case is a single lock-free read via dbGetAgentConfigViaQuerier
// against the pool. Only when that finds no agent_config row at all does
// this function pay for a transaction — see dbGetAgentConfigNotFoundFallback
// for why that path needs one (PAT-1108 fifth-round finding P1-D).
func dbGetAgentConfig(ctx context.Context, pool *pgxpool.Pool, tenantID string) (agentConfigRow, bool, error) {
	row, found, err := dbGetAgentConfigViaQuerier(ctx, pool, tenantID)
	if err != nil {
		return agentConfigRow{}, false, err
	}
	if found {
		return row, true, nil
	}
	return dbGetAgentConfigNotFoundFallback(ctx, pool, tenantID)
}

// dbGetAgentConfigViaQuerier is the actual agent_config read: the main
// LEFT-JOINed SELECT, the body/app-control JSON unmarshals, and the
// extension blocklist/removals reads. It is parameterised over
// dbQuerier (db_querier.go, satisfied by both *pgxpool.Pool and
// pgx.Tx) so it can be called either against the pool directly (the common,
// lock-free fast path) or against an open transaction (PAT-1108 fifth-round
// finding P1-D's re-check under the tenants-row lock, in
// dbGetAgentConfigNotFoundFallback below) — the exact same read, reused
// rather than duplicated, so the two call sites can never silently drift
// apart.
func dbGetAgentConfigViaQuerier(ctx context.Context, q dbQuerier, tenantID string) (agentConfigRow, bool, error) {
	var row agentConfigRow
	var bodyBytes, adminsBytes, allowlistBytes []byte
	var decommissionMode *string
	var decommissionExpiresAt *time.Time
	var decommissionPurge *bool
	var decommissionReason *string
	err := q.QueryRow(ctx, `
		SELECT ac.tenant_id::text, ac.config_version, ac.body, ac.issued_at,
		       COALESCE(t.app_control_enabled, FALSE),
		       COALESCE(t.app_control_approved_admins, '[]'::jsonb),
		       COALESCE(t.app_control_app_allowlist, '[]'::jsonb),
		       td.mode, td.expires_at, td.purge, td.reason
		FROM agent_config ac
		LEFT JOIN tenants t ON t.id = ac.tenant_id
		LEFT JOIN tenant_decommission td ON td.tenant_id = ac.tenant_id
		WHERE ac.tenant_id = $1::uuid
	`, tenantID).Scan(
		&row.TenantID, &row.ConfigVersion, &bodyBytes, &row.IssuedAt,
		&row.AppControlEnabled, &adminsBytes, &allowlistBytes,
		&decommissionMode, &decommissionExpiresAt, &decommissionPurge, &decommissionReason,
	)
	if err != nil {
		if isNoRowsErr(err) {
			return agentConfigRow{}, false, nil
		}
		return agentConfigRow{}, false, err
	}
	if decommissionMode == nil {
		// No tenant_decommission row — safe/inert default, same contract as
		// an explicit mode="none" row.
		row.Decommission = agentconfig.DefaultDecommissionPolicy()
	} else {
		row.Decommission = agentconfig.DecommissionPolicy{Mode: *decommissionMode, Purge: decommissionPurge != nil && *decommissionPurge, Reason: decommissionReason}
		if decommissionExpiresAt != nil {
			s := decommissionExpiresAt.UTC().Format(time.RFC3339)
			row.Decommission.ExpiresAt = &s
		}
	}
	if err := json.Unmarshal(bodyBytes, &row.Body); err != nil {
		return agentConfigRow{}, false, fmt.Errorf("unmarshal agent_config body: %w", err)
	}
	if err := json.Unmarshal(adminsBytes, &row.AppControlAdmins); err != nil {
		return agentConfigRow{}, false, fmt.Errorf("unmarshal app_control_approved_admins: %w", err)
	}
	if err := json.Unmarshal(allowlistBytes, &row.AppControlAppAllowlist); err != nil {
		return agentConfigRow{}, false, fmt.Errorf("unmarshal app_control_app_allowlist: %w", err)
	}
	if row.AppControlAdmins == nil {
		row.AppControlAdmins = []string{}
	}
	if row.AppControlAppAllowlist == nil {
		row.AppControlAppAllowlist = []string{}
	}

	blocklist, err := dbGetExtensionBlocklist(ctx, q, tenantID)
	if err != nil {
		return agentConfigRow{}, false, fmt.Errorf("get extension_blocklist: %w", err)
	}
	row.ExtensionBlocklist = blocklist

	removals, err := dbGetExtensionRemovals(ctx, q, tenantID)
	if err != nil {
		return agentConfigRow{}, false, fmt.Errorf("get extension_removals: %w", err)
	}
	row.ExtensionRemovals = removals

	return row, true, nil
}

// dbGetAgentConfigNotFoundFallback runs when dbGetAgentConfigViaQuerier's
// lock-free read (against the pool) found no agent_config row for the
// tenant at all (PAT-1108 fifth-round finding P1-D).
//
// The bug this closes: the OLD fallback ran a SECOND, INDEPENDENT pool query
// against tenant_decommission ALONE (dbGetTenantDecommissionPolicy, since
// removed), with no lock and no shared transaction with the first read. If
// a decommission PUT committed in the gap between the two reads — creating
// the tenant's FIRST-EVER agent_config row via
// bumpAgentConfigVersionForDecommission, at config_version 2 (see
// syntheticDefaultConfigVersion), alongside the new tenant_decommission row —
// this fallback would still report found=false with the NEW directive's
// mode, and newAgentConfigHandler's synthetic-default branch would sign
// that directive against config_version 1 (the synthetic default), not the
// real, just-committed value of 2. The resulting envelope would be
// internally inconsistent: a device resolving that envelope's
// config_version back to "which directive was in effect" (
// dbResolveDirectiveForEnvelopeVersion, agent_decommission.go) would never
// find this directive there, because it was never actually persisted at
// version 1 — and because anti-rollback logic treats config_version as the
// single source of truth for "is this new information", a device that had
// already accepted the synthetic default at version 1 would treat this
// envelope as a same-version replay and might never re-poll it at all.
//
// The fix follows the same pattern as AgentDecommissionStatusHandler's P1-1
// fix: take the SAME tenants-row FOR UPDATE lock TenantDecommissionPutHandler
// takes (via lockTenantAndReadDecommissionState), and RE-CHECK for the
// agent_config row under that lock, using the exact same
// dbGetAgentConfigViaQuerier read (now against the transaction, not the
// pool) rather than a second, divergent code path:
//
//   - If a racing PUT's agent_config INSERT lands before we take the lock
//     (or we block on the lock until it commits), the re-check under the
//     transaction now SEES that row, and returns found=true with its real
//     config_version — the caller signs the REAL row, never the synthetic
//     one, and the envelope's config_version and decommission block agree.
//   - If no agent_config row exists even under the lock, "no row" is now a
//     fact confirmed at a single consistent point in time, and the
//     decommission fields read by that SAME lockTenantAndReadDecommissionState
//     call (not a separate, unsynchronised query) are what gets returned
//     with found=false.
func dbGetAgentConfigNotFoundFallback(ctx context.Context, pool *pgxpool.Pool, tenantID string) (agentConfigRow, bool, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return agentConfigRow{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	exists, mode, expiresAt, purge, reason, _, err := lockTenantAndReadDecommissionState(ctx, tx, tenantID)
	if err != nil {
		return agentConfigRow{}, false, err
	}
	if !exists {
		// The bearer/device credential that resolved this tenantID already
		// authenticated successfully (newAgentConfigHandler's authFn runs
		// before getFn), so the tenants row should always exist here. Fail
		// closed rather than guess, matching AgentDecommissionStatusHandler's
		// identical !tenantExists branch.
		return agentConfigRow{}, false, fmt.Errorf("tenant %s not found while resolving agent_config not-found fallback", tenantID)
	}

	rowTx, foundTx, err := dbGetAgentConfigViaQuerier(ctx, tx, tenantID)
	if err != nil {
		return agentConfigRow{}, false, err
	}
	if foundTx {
		if err := tx.Commit(ctx); err != nil {
			return agentConfigRow{}, false, err
		}
		return rowTx, true, nil
	}

	dec := agentconfig.DefaultDecommissionPolicy()
	if mode != nil {
		dec = agentconfig.DecommissionPolicy{Mode: *mode, Purge: purge, Reason: reason}
		if expiresAt != nil {
			s := expiresAt.UTC().Format(time.RFC3339)
			dec.ExpiresAt = &s
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return agentConfigRow{}, false, err
	}
	return agentConfigRow{Decommission: dec}, false, nil
}

// dbGetExtensionBlocklist projects the tenant's unapproved extension policies
// (PAT-826, tenant_extension_policies) into the agent's blocklist contract
// (PAT-828), but only for a tenant with App Control switched on
// (tenants.app_control_enabled, the managed tier). For every other tenant it
// returns an empty list (PAT-2007): an unapproved extension there is a
// governance decision, never something an agent acts on, so it must not
// appear in the signed payload at all. Both agents already ignore the list
// when app_control.enabled is false; this makes the server say the same
// thing instead of relying on that. A policy row with browser='any' is fanned out into one concrete
// {chrome,edge,firefox} entry each: the agent's blocklist enforcer only knows
// those three browsers and treats any other browser name as unsupported (a
// silent no-op), so an 'any' policy must be materialised per browser or it would
// enforce nothing. DISTINCT de-duplicates the overlap between an 'any' row and a
// concrete row for the same extension. Only operator-set rows feed it
// (PAT-2089, tenant_extension_policies.source = 'operator'): a customer's
// portal Unapproved is a governance decision on every tenant, so switching
// App Control on later never turns it into browser enforcement nobody chose.
// q is dbQuerier (db_querier.go),
// not *pgxpool.Pool, so dbGetAgentConfigViaQuerier can call this against
// either the pool or an open transaction (PAT-1108 fifth-round finding P1-D).
func dbGetExtensionBlocklist(ctx context.Context, q dbQuerier, tenantID string) ([]agentconfig.ExtensionBlocklistEntry, error) {
	rows, err := q.Query(ctx, `
		SELECT DISTINCT
		       CASE WHEN p.browser = 'any' THEN br.name ELSE p.browser END AS browser,
		       p.extension_id
		FROM tenant_extension_policies p
		JOIN tenants t ON t.id = p.tenant_id AND t.app_control_enabled
		CROSS JOIN (VALUES ('chrome'), ('edge'), ('firefox')) AS br(name)
		WHERE p.tenant_id = $1::uuid
		  AND p.policy = 'unapproved'
		  AND p.source = 'operator'
		  AND (p.browser = 'any' OR p.browser = br.name)
		ORDER BY browser, p.extension_id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []agentconfig.ExtensionBlocklistEntry{}
	for rows.Next() {
		var e agentconfig.ExtensionBlocklistEntry
		if err := rows.Scan(&e.Browser, &e.ExtensionID); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// dbGetExtensionRemovals projects the tenant's pending extension-removal requests
// (migration 0074) into the agent's removal contract (PAT-829). Only active,
// unfulfilled requests are sent; scope/context integrity is guaranteed by the table's CHECK
// constraint and the create handler, so no re-validation is needed here. q is
// dbQuerier (db_querier.go), not *pgxpool.Pool, for the same
// reason as dbGetExtensionBlocklist above.
func dbGetExtensionRemovals(ctx context.Context, q dbQuerier, tenantID string) ([]agentconfig.ExtensionRemovalEntry, error) {
	rows, err := q.Query(ctx, `
		SELECT browser, extension_id, scope, user_account, profile
		FROM tenant_extension_removal_requests
		WHERE tenant_id = $1::uuid
		  AND fulfilled = FALSE
		  AND cancelled_at IS NULL
		ORDER BY requested_at, id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []agentconfig.ExtensionRemovalEntry{}
	for rows.Next() {
		var e agentconfig.ExtensionRemovalEntry
		if err := rows.Scan(&e.Browser, &e.ExtensionID, &e.Scope, &e.UserAccount, &e.Profile); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// dbGetExtensionRemovalsForDevice projects only the exact, still-incomplete
// profiles captured for one authenticated device. Broad operator scopes are
// intentionally compiled down to one_profile directives at delivery time.
func dbGetExtensionRemovalsForDevice(ctx context.Context, q dbQuerier, tenantID, deviceID string) ([]agentconfig.ExtensionRemovalEntry, error) {
	rows, err := q.Query(ctx, `
		SELECT DISTINCT r.requested_at, r.browser, r.extension_id,
		       'one_observation', rt.user_account, rt.profile
		FROM tenant_extension_removal_requests r
		JOIN tenant_extension_removal_targets rt ON rt.request_id = r.id
		WHERE r.tenant_id = $1::uuid
		  AND rt.device_id = $2::uuid
		  AND rt.completed_at IS NULL
		  AND r.fulfilled = FALSE
		  AND r.cancelled_at IS NULL
		ORDER BY r.browser, r.extension_id, rt.user_account, rt.profile
	`, tenantID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []agentconfig.ExtensionRemovalEntry{}
	for rows.Next() {
		var e agentconfig.ExtensionRemovalEntry
		if err := rows.Scan(&e.ApprovedBefore, &e.Browser, &e.ExtensionID, &e.Scope, &e.UserAccount, &e.Profile); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// dbUpsertAgentConfig writes a new or updated agent_config row.
func dbUpsertAgentConfig(ctx context.Context, pool *pgxpool.Pool, tenantID, updatedBy string, body agentconfig.ConfigBody) (agentConfigRow, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return agentConfigRow{}, fmt.Errorf("marshal config body: %w", err)
	}
	var row agentConfigRow
	var outBodyBytes []byte
	err = pool.QueryRow(ctx, `
		INSERT INTO agent_config (tenant_id, config_version, body, issued_at, updated_by)
		VALUES ($1::uuid, 1, $2::jsonb, now(), $3)
		ON CONFLICT (tenant_id) DO UPDATE
			SET config_version = agent_config.config_version + 1,
			    body            = EXCLUDED.body,
			    issued_at       = now(),
			    updated_by      = EXCLUDED.updated_by
		RETURNING tenant_id::text, config_version, body, issued_at
	`, tenantID, bodyBytes, updatedBy).Scan(
		&row.TenantID, &row.ConfigVersion, &outBodyBytes, &row.IssuedAt,
	)
	if err != nil {
		return agentConfigRow{}, err
	}
	if err := json.Unmarshal(outBodyBytes, &row.Body); err != nil {
		return agentConfigRow{}, fmt.Errorf("unmarshal upserted body: %w", err)
	}
	return row, nil
}

// isNoRowsErr reports whether err is a pgx "no rows" error.
func isNoRowsErr(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
