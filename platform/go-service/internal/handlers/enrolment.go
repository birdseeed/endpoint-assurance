package handlers

// Device enrolment endpoints (PAT-23 + PAT-548).
//
// Flow:
//   1. Admin calls POST /admin/tenants/{tenantID}/ca to provision the per-tenant
//      CA (ECDSA P-256 self-signed cert + key). Idempotent — returns the existing
//      CA cert if one is already provisioned.
//   2. Admin calls POST /admin/tenants/{tenantID}/bootstrap-tokens (or the
//      PAT-548 alias /v1/admin/tenants/{tenantID}/enrollment-tokens) to mint a
//      short-lived (24h) one-use token for a provisioning event. An unused
//      token can be listed and revoked early (PAT-2287,
//      bootstrap_token_revoke.go).
//   3. Agent calls POST /v1/enrol with the token + device identity.
//      The platform validates the token, upserts the device record, issues
//      per-device bearer+HMAC credentials, and (if a tenant CA is provisioned)
//      also issues a per-device ECDSA P-256 client cert.
//
// PAT-548 extended the request to accept the new flat format:
//   {"enrollment_token": "...", "device_id": "..."}
// alongside the legacy nested format:
//   {"bootstrap_token": "...", "device": {"hw_uuid": "...", "os": "macos"}}
//
// Idempotency: re-enrolment (wipe/reinstall) reuses the same (tenant_id, hw_uuid)
// slot via ON CONFLICT DO UPDATE, returning fresh credentials each time.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/envelope"
	"patched.im/api/internal/ratelimit"
	"patched.im/api/internal/report"
)

// ─── Admin: provision per-tenant CA ──────────────────────────────────────────

type provisionCAResp struct {
	TenantID  string `json:"tenant_id"`
	CACertPEM string `json:"ca_cert_pem"`
	Created   bool   `json:"created"`
}

// ProvisionTenantCAHandler provisions (or returns the existing) ECDSA P-256
// self-signed CA cert for a tenant. Private key is stored server-side and
// never returned.
func ProvisionTenantCAHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		logger := slog.With("req_id", reqID, "handler", "provision_tenant_ca", "tenant_id", tenantID)

		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		// Return existing CA if already provisioned (idempotent).
		var existingCert string
		err := pool.QueryRow(r.Context(),
			`SELECT ca_cert_pem FROM tenant_ca WHERE tenant_id = $1::uuid`, tenantID).
			Scan(&existingCert)
		if err == nil {
			logger.Info("tenant CA already provisioned — returning existing cert")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(provisionCAResp{
				TenantID:  tenantID,
				CACertPEM: existingCert,
				Created:   false,
			})
			return
		}
		if !isNoRowsErr(err) {
			logger.Error("CA lookup failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Verify tenant exists.
		var exists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`, tenantID).
			Scan(&exists); err != nil || !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		certPEM, keyPEM, err := generateCAKeyPair(tenantID)
		if err != nil {
			logger.Error("CA keypair generation failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// PAT-687: encrypt the CA private key at rest. No-op passthrough when
		// PATCHED_KEK is unset, so nothing breaks before a KEK is provisioned.
		encKeyPEM, err := envelope.Default().EncryptString(keyPEM)
		if err != nil {
			logger.Error("CA key encryption failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if _, err := pool.Exec(r.Context(),
			`INSERT INTO tenant_ca (tenant_id, ca_cert_pem, ca_key_pem) VALUES ($1::uuid, $2, $3)`,
			tenantID, certPEM, encKeyPEM); err != nil {
			logger.Error("CA insert failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("tenant CA provisioned")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(provisionCAResp{
			TenantID:  tenantID,
			CACertPEM: certPEM,
			Created:   true,
		})
	}
}

// ─── Shared: mint an enrolment token ─────────────────────────────────────────

// errInvalidDeliveryPath is a sentinel error from mintTenantEnrolmentToken so
// each caller (admin handler, portal handler) can map it to its own HTTP
// status/body without the shared function knowing about HTTP at all.
// (Tenant-not-found reuses the package-level errTenantNotFound sentinel
// already defined in extension_policies.go — see ensureTenantExists there —
// rather than a second, ==-incompatible sentinel with the same message.)
var errInvalidDeliveryPath = errors.New("invalid delivery_path")

// tenantDecommissionedError is returned by mintTenantEnrolmentToken (PAT-1757)
// when the target tenant carries an active (non-"none") decommission
// directive. Minting a token for such a tenant would let a device enrol into
// a tenant that is scheduled for agent removal — the newly enrolled agent
// would receive, and act on, that directive on its very first config poll:
// enrol, then immediately self-uninstall and purge. Both callers (admin
// mint — MintBootstrapTokenHandler — and the customer-portal mint,
// PortalEnrolmentGenerateHandler in portal_enrolment.go) map this to HTTP
// 409 via writeTenantDecommissionedConflict. There is no override flag: the
// only path past this is clearing the directive first via
// PUT /admin/tenants/{id}/decommission with mode=none.
type tenantDecommissionedError struct {
	Mode  string
	SetAt string
}

func (e *tenantDecommissionedError) Error() string {
	return fmt.Sprintf("tenant has an active decommission directive (mode=%s)", e.Mode)
}

// tenantDecommissionedResp is the shared 409 JSON body for a mint or enrol
// rejected because of an active decommission directive (PAT-1757).
type tenantDecommissionedResp struct {
	Error string `json:"error"`
	Mode  string `json:"mode"`
	SetAt string `json:"set_at,omitempty"`
}

// writeTenantDecommissionedConflict writes the shared 409 response for a
// mint or enrol rejected because the target tenant's decommission directive
// is not mode="none". setAt may be "" when the caller does not have it to
// hand (EnrolHandler's tx-scoped read below only fetches mode) — the mode is
// what actually gates behaviour, so it is always present.
func writeTenantDecommissionedConflict(w http.ResponseWriter, mode, setAt string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(tenantDecommissionedResp{
		Error: fmt.Sprintf("tenant has an active decommission directive (mode=%s); clear it first via PUT /admin/tenants/{id}/decommission with mode=none before minting or enrolling; there is no override", mode),
		Mode:  mode,
		SetAt: setAt,
	})
}

// mintResult is the outcome of mintTenantEnrolmentToken. DeliveryPath is
// deliberately NOT included — callers already hold the deliveryPath they
// passed in (it passes through unmodified), so a mirrored field would be
// redundant.
type mintResult struct {
	TokenID        string
	PlaintextToken string
	ExpiresAt      time.Time
}

// mintTenantEnrolmentToken generates a short-lived (24h) one-use enrolment
// token for tenantID, persists sha256(token) in bootstrap_tokens, and writes
// an enrollment_token_audit row. It is the HTTP-agnostic core shared by:
//
//   - MintBootstrapTokenHandler (admin, POST /admin/tenants/{id}/bootstrap-tokens
//     and its /v1/admin alias) — admin auth is a shared token, so actorEmail
//     is always "" (recorded as NULL) for this path.
//   - PortalEnrolmentGenerateHandler (customer portal, PAT-453,
//     POST /v1/portal/enrolment) — actorEmail is the caller's verified CF
//     Access identity.
//
// Not to be confused with trial.go's package-level mintEnrollmentToken — a
// deliberately minimal helper for the self-serve trial flow (PAT-668) with
// no tenant-revocation check, no delivery_path, and no audit row. That
// function is untouched by PAT-453 or PAT-836; this is a separate, stricter
// path used only by the two callers above. (trial.go's raw INSERT omits
// delivery_path entirely, relying on the DB column default of 'mdm' added by
// migration 0084 — see that migration's comment for why the default is kept
// rather than dropped.)
//
// Validates deliveryPath before the tenant lookup (matching the original
// admin-handler order, preserved for behavioural parity). Does not touch
// token TTL or the /v1/enrol burn logic — those are out of scope for
// PAT-453.
//
// PAT-836: single-use is now scoped, not blanket, invalidate-on-regenerate.
// deliveryPath == "email-link" (single download link, one per tenant)
// supersedes the tenant's prior unconsumed, not-yet-superseded email-link
// token(s) atomically with the new insert. deliveryPath == "mdm" (fleet
// enrolment, N devices enrolling concurrently) never touches any other row —
// multiple outstanding mdm tokens for the same tenant are expected and
// legitimate. Contract: docs/API.md ("Agent enrolment token" section) and
// contracts/portal-api.md ("Agent enrolment token (PAT-453)" section).
func mintTenantEnrolmentToken(ctx context.Context, pool *pgxpool.Pool, tenantID, deliveryPath, actorEmail string) (mintResult, error) {
	res, err := mintTenantEnrolmentTokenOn(ctx, pool, tenantID, deliveryPath)
	if err != nil {
		return mintResult{}, err
	}
	recordEnrolmentTokenAudit(ctx, pool, tenantID, deliveryPath, actorEmail, res)
	return res, nil
}

// mintDB is what mintTenantEnrolmentTokenOn runs on: a *pgxpool.Pool, or a
// pgx.Tx when the caller already holds a transaction (on a pgx.Tx, Begin is
// a savepoint).
type mintDB interface {
	rowQuerier
	Begin(ctx context.Context) (pgx.Tx, error)
}

var (
	_ mintDB = (*pgxpool.Pool)(nil)
	_ mintDB = (pgx.Tx)(nil)
)

// mintTenantEnrolmentTokenOn is mintTenantEnrolmentToken without the audit
// row: the checks and the bootstrap_tokens insert, all on db. PAT-2407 split
// it out so PortalEnrolmentGenerateHandler can run it inside the transaction
// that holds the caller's portal_users row FOR SHARE (requirePortalAdmin),
// on that one connection, and so that a refused caller writes nothing. That
// handler commits and then calls recordEnrolmentTokenAudit itself; the admin
// path goes through mintTenantEnrolmentToken and is unchanged.
func mintTenantEnrolmentTokenOn(ctx context.Context, db mintDB, tenantID, deliveryPath string) (mintResult, error) {
	if deliveryPath != "mdm" && deliveryPath != "email-link" {
		return mintResult{}, errInvalidDeliveryPath
	}

	// Revocation-aware existence check — deliberately NOT the package's
	// shared ensureTenantExists (extension_policies.go), which omits the
	// revoked_at filter. The original inline admin-handler logic always
	// excluded revoked tenants; that must not change.
	//
	// A query error is folded into errTenantNotFound rather than surfaced as
	// a distinct error, matching the ORIGINAL inline admin-handler check
	// (`err != nil || !exists`) byte-for-byte — MintBootstrapTokenHandler
	// must keep returning 404 "tenant not found" on a transient DB error
	// here, not a behaviour-changing 500. The error is still logged here
	// (the original didn't even do that) so a genuine DB fault isn't
	// silently indistinguishable from an actually-missing tenant internally,
	// even though the HTTP response is deliberately unchanged.
	var exists bool
	if err := db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`, tenantID).
		Scan(&exists); err != nil {
		slog.Error("tenant existence lookup failed — treating as not-found for HTTP parity", "err", err, "tenant_id", tenantID)
		return mintResult{}, errTenantNotFound
	}
	if !exists {
		return mintResult{}, errTenantNotFound
	}

	// PAT-1757: refuse to mint for a tenant that carries an active
	// (non-"none") decommission directive — see tenantDecommissionedError's
	// doc comment for why. Reuses report.FetchTenantDecommissionDirective,
	// the same read TenantDecommissionGetHandler already exposes on
	// GET /admin/tenants/{id}/decommission, rather than a parallel query.
	// The revocation-aware exists check just above already confirmed the
	// tenant is live, so a fetch failure here is a genuine transient fault,
	// not a not-found — fail closed rather than mint blind.
	directive, decErr := report.FetchTenantDecommissionDirective(ctx, db, tenantID)
	if decErr != nil {
		return mintResult{}, fmt.Errorf("check decommission directive: %w", decErr)
	}
	if directive.Mode != "none" {
		return mintResult{}, &tenantDecommissionedError{Mode: directive.Mode, SetAt: directive.SetAt}
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return mintResult{}, fmt.Errorf("rand token: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(tokenBytes)
	hash := sha256.Sum256([]byte(plaintext))
	expiresAt := time.Now().UTC().Add(24 * time.Hour)

	// insertToken runs the actual bootstrap_tokens insert against either the
	// pool (mdm — no other statement in play) or a tx (email-link — see
	// below). q is rowQuerier (trial.go) rather than *pgxpool.Pool
	// specifically so both callers share one INSERT rather than two
	// hand-duplicated copies of the same SQL.
	var tokenID string
	insertToken := func(q rowQuerier) error {
		return q.QueryRow(ctx,
			`INSERT INTO bootstrap_tokens (tenant_id, token_hash, expires_at, delivery_path)
			 VALUES ($1::uuid, $2, $3, $4) RETURNING id::text`,
			tenantID, hash[:], expiresAt, deliveryPath).Scan(&tokenID)
	}

	// PAT-836: "email-link" is the single-download-link delivery path — one
	// link per tenant, so minting a new one supersedes the tenant's prior
	// unconsumed email-link token(s). "mdm" is the fleet-enrolment path,
	// where N devices legitimately enrol concurrently against N outstanding
	// tokens, so a mint on that path must never touch any other token.
	//
	// The supersede + insert for "email-link" run in one transaction so a
	// SEQUENTIAL remint (the common case — someone clicks "regenerate")
	// never has a window where an old and a new email-link token are both
	// simultaneously valid (mirrors the tx pattern EnrolHandler already uses
	// for its consume step, below).
	//
	// That alone doesn't cover two truly CONCURRENT email-link mints for the
	// same tenant: under READ COMMITTED, both could run their supersede
	// UPDATE before either INSERT is visible to the other, so neither
	// supersedes the other and two live tokens result. A
	// pg_advisory_xact_lock keyed on the tenant serializes that case.
	// Deliberately NOT a `SELECT ... FROM tenants ... FOR UPDATE` row lock
	// (the pattern CheckTrialDeviceCap uses in trial.go for an analogous
	// problem): EnrolHandler's consume tx locks a bootstrap_tokens row
	// FIRST and only then locks the tenants row (via CheckTrialDeviceCap) —
	// so a tenants-row-first lock here would take the opposite order and
	// deadlock against a concurrent enrolment on the same tenant. An
	// advisory lock lives in its own lock space, entirely separate from row
	// locks, so it cannot deadlock against that ordering.
	if deliveryPath == "email-link" {
		tx, err := db.Begin(ctx)
		if err != nil {
			return mintResult{}, fmt.Errorf("begin mint tx: %w", err)
		}
		defer func() { _ = tx.Rollback(ctx) }() // no-op once Commit has run

		if _, err := tx.Exec(ctx,
			`SELECT pg_advisory_xact_lock(hashtext($1 || ':email-link-mint'))`,
			tenantID); err != nil {
			return mintResult{}, fmt.Errorf("acquire email-link mint lock: %w", err)
		}

		if _, err := tx.Exec(ctx, `
			UPDATE bootstrap_tokens
			SET superseded_at = now()
			WHERE tenant_id = $1::uuid
			  AND delivery_path = 'email-link'
			  AND consumed_at IS NULL
			  AND superseded_at IS NULL
		`, tenantID); err != nil {
			return mintResult{}, fmt.Errorf("supersede prior email-link tokens: %w", err)
		}

		if err := insertToken(tx); err != nil {
			return mintResult{}, fmt.Errorf("token insert: %w", err)
		}

		if err := tx.Commit(ctx); err != nil {
			return mintResult{}, fmt.Errorf("commit mint tx: %w", err)
		}
	} else {
		if err := insertToken(db); err != nil {
			return mintResult{}, fmt.Errorf("token insert: %w", err)
		}
	}

	return mintResult{
		TokenID:        tokenID,
		PlaintextToken: plaintext,
		ExpiresAt:      expiresAt,
	}, nil
}

// recordEnrolmentTokenAudit writes the enrollment_token_audit row for a
// minted (and committed) token. Best effort: a failure is logged, never
// returned.
func recordEnrolmentTokenAudit(ctx context.Context, pool *pgxpool.Pool, tenantID, deliveryPath, actorEmail string, res mintResult) {
	// actor_email is nullable (migration 0077) — pass a typed nil rather
	// than "" so the admin path (no per-user identity) writes SQL NULL, not
	// an empty string.
	var actorArg any
	if actorEmail != "" {
		actorArg = actorEmail
	}
	if _, auditErr := pool.Exec(ctx, `
		INSERT INTO enrollment_token_audit (tenant_id, token_id, delivery_path, expires_at, actor_email)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5)
	`, tenantID, res.TokenID, deliveryPath, res.ExpiresAt, actorArg); auditErr != nil {
		// Non-fatal: matches the original admin-handler behaviour — an audit
		// insert failure must never block issuing the token.
		slog.Warn("enrollment audit log insert failed", "err", auditErr, "tenant_id", tenantID, "token_id", res.TokenID)
	}
}

// ─── Admin: mint bootstrap token ─────────────────────────────────────────────

type mintBootstrapTokenResp struct {
	TokenID         string `json:"token_id"`
	BootstrapToken  string `json:"bootstrap_token"`
	EnrollmentToken string `json:"enrollment_token"` // PAT-548: alias for bootstrap_token
	DeliveryPath    string `json:"delivery_path"`
	ExpiresAt       string `json:"expires_at"`
	Warning         string `json:"warning"`
}

// MintBootstrapTokenHandler generates a short-lived (24h) one-use enrolment
// token for the given tenant. The plaintext token is returned once and is not
// recoverable; store it immediately in the installer or pass it as an env var.
//
// PAT-453: the mint logic itself now lives in mintTenantEnrolmentToken, shared
// with the customer-portal mint endpoint. This handler's behaviour —
// routes, response shape, status codes, error text — is unchanged.
func MintBootstrapTokenHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		logger := slog.With("req_id", reqID, "handler", "mint_bootstrap_token", "tenant_id", tenantID)

		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		deliveryPath := r.URL.Query().Get("path")
		if deliveryPath == "" {
			deliveryPath = "mdm"
		}

		// Admin auth is a shared token, not a per-user identity — actorEmail
		// is always "" here, which mintTenantEnrolmentToken records as NULL.
		res, err := mintTenantEnrolmentToken(r.Context(), pool, tenantID, deliveryPath, "")
		if err != nil {
			var decErr *tenantDecommissionedError
			switch {
			case errors.Is(err, errInvalidDeliveryPath):
				http.Error(w, "path must be 'mdm' or 'email-link'", http.StatusBadRequest)
			case errors.Is(err, errTenantNotFound):
				http.Error(w, "tenant not found", http.StatusNotFound)
			case errors.As(err, &decErr):
				logger.Warn("mint rejected: tenant has an active decommission directive", "mode", decErr.Mode)
				writeTenantDecommissionedConflict(w, decErr.Mode, decErr.SetAt)
			default:
				logger.Error("mint enrollment token failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
			return
		}

		logger.Info("bootstrap token minted", "token_id", res.TokenID, "expires_at", res.ExpiresAt, "delivery_path", deliveryPath)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(mintBootstrapTokenResp{
			TokenID:         res.TokenID,
			BootstrapToken:  res.PlaintextToken,
			EnrollmentToken: res.PlaintextToken,
			DeliveryPath:    deliveryPath,
			ExpiresAt:       res.ExpiresAt.Format(time.RFC3339),
			Warning:         "store enrollment_token immediately — not recoverable after this response.",
		})
	}
}

// ─── Public: enrol device ────────────────────────────────────────────────────

type enrolRequest struct {
	// PAT-548 flat format (preferred): sent by macOS + Windows agents.
	EnrollmentToken string `json:"enrollment_token"`
	DeviceID        string `json:"device_id"`

	// PAT-23 nested format (legacy): kept for backward compatibility.
	BootstrapToken string       `json:"bootstrap_token"`
	Device         deviceClaims `json:"device"`
}

type deviceClaims struct {
	HWUUID       string `json:"hw_uuid"`
	Serial       string `json:"serial"`
	Hostname     string `json:"hostname"`
	ComputerName string `json:"computer_name"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
}

type enrolResponse struct {
	TenantID    string `json:"tenant_id"`
	DeviceID    string `json:"device_id"`
	BearerToken string `json:"bearer_token"`
	HMACSecret  string `json:"hmac_secret"`
	// Legacy PKI fields — populated only when the tenant CA is provisioned.
	CertPEM   string `json:"cert_pem,omitempty"`
	KeyPEM    string `json:"key_pem,omitempty"`
	CACertPEM string `json:"ca_cert_pem,omitempty"`
}

// EnrolHandler is POST /v1/enrol — the device-facing enrolment endpoint.
// Auth is the enrollment_token (or legacy bootstrap_token) in the request body;
// no bearer+HMAC is required (this is the pre-auth provisioning step).
// Rate-limited per tenant.
//
// Accepts both request formats:
//   - New (PAT-548): {"enrollment_token":"…","device_id":"<hw-uuid>"}
//   - Legacy (PAT-23): {"bootstrap_token":"…","device":{"hw_uuid":"…","os":"macos"}}
//
// Always returns HTTP 200 with {tenant_id, device_id, bearer_token, hmac_secret}.
// Returns HTTP 410 Gone if the token is consumed or expired. A token an
// operator revoked (PAT-2287) returns the expired response, byte for byte.
//
// PAT-2250: the same field also carries a reusable tenant enrolment key
// ("pek_…", enrolment_keys.go). A key is not consumed; each enrolment is
// recorded against it and the device cap is enforced under the key row
// lock. A revoked, expired or exhausted key returns 410 like a consumed token.
func EnrolHandler(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "enrol")

		r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
		var req enrolRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		// Accept either field name for the token.
		token := req.EnrollmentToken
		if token == "" {
			token = req.BootstrapToken
		}
		if token == "" {
			http.Error(w, "enrollment_token required", http.StatusBadRequest)
			return
		}

		// Accept either device identity format.
		hwUUID := req.DeviceID
		if hwUUID == "" {
			hwUUID = req.Device.HWUUID
		}
		if !looksLikeUUID(hwUUID) {
			http.Error(w, "device_id must be a UUID", http.StatusBadRequest)
			return
		}

		// OS is optional in the new flat format; validate if provided.
		os := strings.ToLower(req.Device.OS)
		if os != "" && os != "macos" && os != "windows" {
			http.Error(w, "device.os must be 'macos' or 'windows'", http.StatusBadRequest)
			return
		}

		// Validate + atomically consume the token in a single statement, inside
		// a transaction that wraps the whole enrolment. This closes the race
		// (H3) where two concurrent requests both pass a select-then-check gate
		// and each issue credentials against one single-use token. If any
		// downstream step fails, the deferred Rollback un-consumes the token, so
		// a token is never burned without credentials being issued.
		tokenHash := sha256.Sum256([]byte(token))

		tx, err := pool.Begin(r.Context())
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// No-op once Commit has run; otherwise this rolls the enrolment back.
		defer func() { _ = tx.Rollback(r.Context()) }()

		// PAT-2250: a tenant enrolment key ("pek_" prefix) is looked up
		// first, locking its row (the same lock position as the
		// bootstrap_tokens row below; see lockEnrolmentKeyForEnrol for the
		// lock order and the cap). A prefixed value that matches no key
		// falls through to the unchanged single-use token path.
		var tokenID, tenantID string
		var enrolKey *lockedEnrolmentKey
		if isEnrolmentKey(token) {
			k, kerr := lockEnrolmentKeyForEnrol(r.Context(), tx, tokenHash[:], hwUUID)
			if kerr != nil {
				logger.Error("enrolment key lookup failed", "err", kerr)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if k != nil {
				if k.Refusal != "" {
					// 410 like a consumed token: this key will never admit
					// this device again. Neither the plaintext nor its hash
					// is logged, only the key's row id.
					logger.Warn("enrol rejected: enrolment key refused", "enrolment_key_id", k.ID, "tenant_id", k.TenantID, "reason", k.Refusal)
					http.Error(w, "enrollment_token "+k.Refusal, http.StatusGone)
					return
				}
				enrolKey = k
				tenantID = k.TenantID
			}
		}
		if enrolKey == nil {
			var ok bool
			if tokenID, tenantID, ok = consumeBootstrapToken(r.Context(), tx, w, logger, tokenHash); !ok {
				return
			}
		}

		// PAT-1757: refuse to enrol into a tenant that carries an active
		// (non-"none") decommission directive. The token was already
		// consumed by the UPDATE above (closing the H3 concurrent-single-use
		// race), but nothing has committed yet — bailing out here lets the
		// deferred tx.Rollback un-consume it, so this refusal is side-effect
		// free: no credential row is created, and the same token remains
		// usable once the directive is cleared. There is no override flag.
		// Reuses lockTenantAndReadDecommissionState (agent_decommission.go)
		// on THIS tx rather than a second pooled connection or a parallel
		// query — see rowQuerier's doc comment above for why acquiring a
		// second connection here, while this tx already holds one, is a
		// deadlock hazard under concurrent enrolment on a small pool.
		if _, decMode, _, _, _, _, decErr := lockTenantAndReadDecommissionState(r.Context(), tx, tenantID); decErr != nil {
			logger.Error("decommission directive lookup failed", "err", decErr, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		} else if decMode != nil && *decMode != "none" {
			logger.Warn("enrol rejected: tenant has an active decommission directive", "tenant_id", tenantID, "mode", *decMode)
			writeTenantDecommissionedConflict(w, *decMode, "")
			return
		}

		// Rate-limit per tenant (after token identity is known). The deferred
		// rollback un-consumes the token if we bail out here.
		if ok, retryAfter := rl.Allow(tenantID); !ok {
			w.Header().Set("Retry-After", fmt.Sprintf("%.0f", retryAfter.Seconds()))
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}

		if enrolKey != nil {
			logger = logger.With("tenant_id", tenantID, "enrolment_key_id", enrolKey.ID, "hw_uuid", hwUUID)
		} else {
			logger = logger.With("tenant_id", tenantID, "token_id", tokenID, "hw_uuid", hwUUID)
		}

		// PAT-867: reject enrolment for a trial tenant that is expired or
		// already at its device cap. /v1/enrol has no bearer credential at all
		// (identity comes from the enrollment_token consumed above), so this is
		// a direct call rather than anything middleware-based — see trial.go's
		// CheckTrialDeviceCap doc comment.
		//
		// Fails CLOSED: a lookup error aborts the enrolment with 500 (the
		// deferred rollback un-consumes the token). This is a paid-tier device
		// ceiling, so a failure path must never let a capped/expired trial
		// receive credentials. The availability cost is negligible — the check
		// runs on this same tx that must go on to INSERT the device/credential,
		// so a genuine fault fails the enrolment regardless.
		//
		// Runs on tx (not pool) deliberately, for two reasons. (1) We are inside
		// the enrolment transaction, which already holds a pooled connection;
		// acquiring a second connection here would deadlock the pool under
		// concurrent enrolment (see rowQuerier's doc comment and
		// TestEnrolHandler_ConcurrentSingleUse). (2) CheckTrialDeviceCap locks
		// the tenant row FOR UPDATE, which serialises concurrent same-tenant
		// enrolments so the cap COUNT and the device INSERT below are atomic —
		// closing the TOCTOU race where two enrolments at cap-1 (each with its
		// own valid token) both read "under cap" and both insert. That lock is
		// only meaningful inside a transaction, which is another reason this
		// must be tx. See TestCheckTrialDeviceCap_SerializesConcurrentEnrol.
		if capReached, err := CheckTrialDeviceCap(r.Context(), tx, tenantID); err != nil {
			logger.Error("trial device cap check failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		} else if capReached {
			logger.Warn("enrol rejected: trial device cap reached")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPaymentRequired)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "trial_device_cap_reached"})
			return
		}

		// Load the tenant CA — optional. New agents use bearer+HMAC only.
		var caCertPEM, caKeyPEM string
		caErr := tx.QueryRow(r.Context(),
			`SELECT ca_cert_pem, ca_key_pem FROM tenant_ca WHERE tenant_id = $1::uuid`, tenantID).
			Scan(&caCertPEM, &caKeyPEM)
		if caErr != nil && !isNoRowsErr(caErr) {
			logger.Error("CA load failed", "err", caErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		hasCA := caErr == nil

		// PAT-687: decrypt the CA private key. Decrypt-with-plaintext-fallback —
		// rows written before envelope encryption (or while PATCHED_KEK was
		// unset) are returned verbatim.
		if hasCA {
			caKeyPEM, err = envelope.Default().DecryptString(caKeyPEM)
			if err != nil {
				logger.Error("CA key decryption failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}

		// Upsert device record.
		var deviceID string
		if err := tx.QueryRow(r.Context(), `
			INSERT INTO devices (tenant_id, hw_uuid, serial, hostname, computer_name, os, arch)
			VALUES ($1::uuid, $2::uuid, NULLIF($3,''), NULLIF($4,''), NULLIF($5,''), NULLIF($6,''), NULLIF($7,''))
			ON CONFLICT (tenant_id, hw_uuid) DO UPDATE SET
				serial        = EXCLUDED.serial,
				hostname      = EXCLUDED.hostname,
				computer_name = EXCLUDED.computer_name,
				arch          = EXCLUDED.arch,
				last_seen     = now()
			RETURNING id::text
		`, tenantID, hwUUID, req.Device.Serial, req.Device.Hostname,
			req.Device.ComputerName, os, req.Device.Arch).Scan(&deviceID); err != nil {
			logger.Error("device upsert failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// PAT-2250: record this enrolment against the key, in the same tx as
		// the device and credential, while the key row lock taken by
		// lockEnrolmentKeyForEnrol is still held, so the cap count and this
		// insert are atomic with respect to every other enrolment on the key.
		if enrolKey != nil {
			if err := recordEnrolmentKeyUse(r.Context(), tx, enrolKey.ID, tenantID, deviceID, hwUUID); err != nil {
				logger.Error("enrolment key use insert failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}

		// Issue per-device bearer + HMAC credentials.
		bearerBytes := make([]byte, 32)
		if _, err := rand.Read(bearerBytes); err != nil {
			logger.Error("rand bearer failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		bearerToken := base64.RawURLEncoding.EncodeToString(bearerBytes)
		bearerHash := sha256.Sum256([]byte(bearerToken))

		hmacSecretBytes := make([]byte, 32)
		if _, err := rand.Read(hmacSecretBytes); err != nil {
			logger.Error("rand hmac failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// PAT-687: encrypt the ACTIVE auth secret at rest; auth/bearer.go decrypts
		// with a plaintext fallback. No-op passthrough when PATCHED_KEK is unset.
		// Kept inside the enrolment tx so the credential is atomic with the device.
		encHMACSecret, err := envelope.Default().EncryptBytes(hmacSecretBytes)
		if err != nil {
			logger.Error("hmac_secret encryption failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if _, err := tx.Exec(r.Context(), `
			INSERT INTO tenant_credentials (tenant_id, device_id, bearer_token_hash, hmac_secret)
			VALUES ($1::uuid, $2::uuid, $3, $4)
		`, tenantID, deviceID, bearerHash[:], encHMACSecret); err != nil {
			logger.Error("bearer credential insert failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		resp := enrolResponse{
			TenantID:    tenantID,
			DeviceID:    deviceID,
			BearerToken: bearerToken,
			HMACSecret:  base64.StdEncoding.EncodeToString(hmacSecretBytes),
		}

		// Issue per-device client cert if the tenant CA is provisioned (legacy path).
		if hasCA {
			certPEM, keyPEM, serial, notAfter, err := issueDeviceCert(caCertPEM, caKeyPEM, tenantID, deviceID)
			if err != nil {
				logger.Warn("cert issuance failed (non-fatal — bearer creds already issued)", "err", err)
			} else {
				if _, err := tx.Exec(r.Context(), `
					INSERT INTO device_client_certs (tenant_id, device_id, hw_uuid, cert_pem, serial_num, not_after)
					VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6)
					ON CONFLICT (tenant_id, hw_uuid) DO UPDATE SET
						device_id  = EXCLUDED.device_id,
						cert_pem   = EXCLUDED.cert_pem,
						serial_num = EXCLUDED.serial_num,
						not_after  = EXCLUDED.not_after,
						issued_at  = now()
				`, tenantID, deviceID, hwUUID, certPEM, serial, notAfter); err != nil {
					logger.Warn("cert upsert failed (non-fatal)", "err", err)
				} else {
					resp.CertPEM = certPEM
					resp.KeyPEM = keyPEM
					resp.CACertPEM = caCertPEM
				}
			}
		}

		// Commit the enrolment (token consume + credential issue) atomically.
		// The token was already marked consumed at the top of the tx; committing
		// here is what makes that durable. Only now are the returned credentials
		// valid — so we must not have written the response body yet.
		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("enrolment commit failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("device enrolled", "device_id", deviceID, "has_cert", hasCA)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// writeEnrolTokenExpired writes /v1/enrol's refusal for an expired token. A
// revoked token (PAT-2287) gets exactly this response too, from the same
// function, so whoever holds a revoked token cannot tell it was revoked.
func writeEnrolTokenExpired(w http.ResponseWriter) {
	http.Error(w, "enrollment_token expired", http.StatusGone)
}

// consumeBootstrapToken validates and atomically consumes a single-use
// bootstrap token inside the enrolment tx (moved verbatim out of
// EnrolHandler by PAT-2250 so the enrolment-key path can sit beside it; the
// SQL, status codes and messages are unchanged apart from PAT-2287's
// revoked_at gate). ok is false when it has already written the error
// response.
//
// PAT-2287: a revoked token is refused with the expired-token response. It
// takes the same path as an expired one: the same 0-row UPDATE, the same
// diagnostic SELECT, then writeEnrolTokenExpired. Only the server-side log
// line names the real reason.
func consumeBootstrapToken(ctx context.Context, tx pgx.Tx, w http.ResponseWriter, logger *slog.Logger, tokenHash [32]byte) (tokenID, tenantID string, ok bool) {
	err := tx.QueryRow(ctx, `
		UPDATE bootstrap_tokens
		SET consumed_at = now()
		WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now() AND superseded_at IS NULL
		  AND revoked_at IS NULL
		RETURNING id::text, tenant_id::text
	`, tokenHash[:]).Scan(&tokenID, &tenantID)
	if err != nil {
		if !isNoRowsErr(err) {
			logger.Error("token consume failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return "", "", false
		}
		// No row was consumed. Diagnose why (unknown vs consumed vs
		// superseded vs expired) to return the historical status codes.
		//
		// Runs on tx (not pool), like every other query in this handler:
		// a nested pool.Acquire here — while this tx already holds a pooled
		// connection — deadlocks the pool under concurrent enrolment on a
		// small pool (each losing request holds its tx connection and waits
		// for a second that no peer can release). That is exactly the hang
		// TestEnrolHandler_ConcurrentSingleUse reproduces on a few-connection
		// pool (PAT-957). The 0-row UPDATE above took no row lock, and pgx
		// runs at READ COMMITTED, so this statement still sees the latest
		// committed state (a peer's consumed_at/superseded_at once it has
		// committed) — the diagnosis is unchanged, it just no longer needs a
		// second connection.
		var diagConsumed, diagSuperseded, diagRevoked *time.Time
		var diagExpires time.Time
		derr := tx.QueryRow(ctx, `
			SELECT consumed_at, expires_at, superseded_at, revoked_at FROM bootstrap_tokens WHERE token_hash = $1
		`, tokenHash[:]).Scan(&diagConsumed, &diagExpires, &diagSuperseded, &diagRevoked)
		switch {
		case derr != nil && isNoRowsErr(derr):
			logger.Warn("enrol rejected: unknown token")
			http.Error(w, "invalid enrollment_token", http.StatusUnauthorized)
		case derr != nil:
			logger.Error("token lookup failed", "err", derr)
			http.Error(w, "internal error", http.StatusInternalServerError)
		case diagConsumed != nil:
			// "Already consumed" takes precedence over every other state:
			// the device already holds credentials off this token, which
			// is the most definitive terminal state to report regardless
			// of whether the token also happens to be superseded/expired.
			logger.Warn("enrol rejected: token already consumed")
			http.Error(w, "enrollment_token already used", http.StatusGone)
		case diagRevoked != nil:
			// PAT-2287: deliberately indistinguishable from expired on the
			// wire, including an email-link token superseded by a remint
			// before or after revocation.
			logger.Warn("enrol rejected: token revoked (reported to the caller as expired)")
			writeEnrolTokenExpired(w)
		case diagSuperseded != nil:
			// PAT-836: a newer email-link token was minted for this
			// tenant, invalidating this one. Checked before "expired" —
			// a token that is BOTH superseded and expired reports as
			// superseded, since supersession is a deliberate action (a
			// fresh token already exists to use instead) rather than a
			// passive timeout, and is the more actionable diagnosis for
			// whoever is holding the stale link. 410 Gone for the same
			// reason as the other two terminal states below: this token
			// is permanently, never-again valid.
			logger.Warn("enrol rejected: token superseded by a newer token")
			http.Error(w, "enrollment_token superseded by a newer token", http.StatusGone)
		default:
			logger.Warn("enrol rejected: token expired")
			writeEnrolTokenExpired(w)
		}
		return "", "", false
	}
	return tokenID, tenantID, true
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

// generateCAKeyPair creates a self-signed ECDSA P-256 CA cert for the given
// tenant. Returns PEM-encoded cert and PKCS#8 private key.
func generateCAKeyPair(tenantID string) (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate CA key: %w", err)
	}

	serialBytes := make([]byte, 16)
	if _, err := rand.Read(serialBytes); err != nil {
		return "", "", fmt.Errorf("serial rand: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes)

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("Patched Tenant CA — %s", tenantID),
			Organization: []string{"Patched.im"},
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(5 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("create CA cert: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("marshal CA key: %w", err)
	}

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM, nil
}

// issueDeviceCert generates a fresh ECDSA P-256 keypair for the device, signs
// a 1-year client cert with the tenant CA, and returns PEM-encoded cert, key,
// serial number, and expiry. The private key is returned to the caller only —
// it is never stored server-side.
func issueDeviceCert(caCertPEM, caKeyPEM, tenantID, deviceID string) (
	certPEM, keyPEM string, serial int64, notAfter time.Time, err error,
) {
	// Parse tenant CA.
	caCertBlock, _ := pem.Decode([]byte(caCertPEM))
	if caCertBlock == nil {
		return "", "", 0, time.Time{}, fmt.Errorf("failed to decode CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return "", "", 0, time.Time{}, fmt.Errorf("parse CA cert: %w", err)
	}

	caKeyBlock, _ := pem.Decode([]byte(caKeyPEM))
	if caKeyBlock == nil {
		return "", "", 0, time.Time{}, fmt.Errorf("failed to decode CA key PEM")
	}
	caKeyAny, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return "", "", 0, time.Time{}, fmt.Errorf("parse CA key: %w", err)
	}
	caKey, ok := caKeyAny.(*ecdsa.PrivateKey)
	if !ok {
		return "", "", 0, time.Time{}, fmt.Errorf("CA key is not ECDSA")
	}

	// Generate device keypair.
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", 0, time.Time{}, fmt.Errorf("generate device key: %w", err)
	}

	serialBytes := make([]byte, 8)
	if _, err := rand.Read(serialBytes); err != nil {
		return "", "", 0, time.Time{}, fmt.Errorf("serial rand: %w", err)
	}
	serialBig := new(big.Int).SetBytes(serialBytes)
	serialBig.SetBit(serialBig, 63, 0) // keep positive for int64 storage

	now := time.Now().UTC()
	notAfter = now.Add(365 * 24 * time.Hour)

	tmpl := &x509.Certificate{
		SerialNumber: serialBig,
		Subject: pkix.Name{
			CommonName:         deviceID,
			Organization:       []string{"Patched.im"},
			OrganizationalUnit: []string{tenantID},
		},
		NotBefore:   now.Add(-time.Minute),
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &deviceKey.PublicKey, caKey)
	if err != nil {
		return "", "", 0, time.Time{}, fmt.Errorf("create device cert: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(deviceKey)
	if err != nil {
		return "", "", 0, time.Time{}, fmt.Errorf("marshal device key: %w", err)
	}

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM, serialBig.Int64(), notAfter, nil
}
