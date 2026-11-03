package handlers

// POST /v1/trial/provision — self-serve trial tenant provisioning (PAT-668).
//
// Creates a trial tenant with is_trial=true, trial_expires_at=now()+14d,
// trial_device_cap=3. Reuses the PAT-543 enrollment flow (MintBootstrapToken
// helper) to produce a one-use device enrollment token.
//
// Uniqueness: one active trial per email address. A second provision request
// for the same email while an active trial exists returns 409 with the existing
// tenant_id and enrollment URL.
//
// Route: POST /v1/trial/provision  (public :8080 — no bearer/HMAC auth; it IS
// the pre-auth provisioning step, like /v1/enrol). Because it is open, it is
// rate limited per client and globally before anything is read (PAT-2529,
// trial_ratelimit.go).
//
// Trial enforcement (PAT-867): there is no shared bearer-auth middleware on
// the public :8080 listener — InventoryHandler and EnrolHandler each resolve
// tenant identity inline (bearer lookup and enrollment-token consume,
// respectively), so a context-based middleware would never see a tenant ID to
// act on. Enforcement is therefore two direct calls made from the handlers:
//   - InventoryHandler calls CheckTrialExpired after the FULL auth + replay
//     gate (bearer, HMAC, timestamp, nonce) and returns 402
//     {"error":"trial_expired"} for an expired trial tenant. It runs post-auth
//     so the 402 never precedes the second auth factor (no bearer-only oracle).
//   - EnrolHandler calls CheckTrialDeviceCap on its enrolment transaction,
//     after consuming the enrollment token, and returns 402
//     {"error":"trial_device_cap_reached"} for a trial tenant that is expired
//     or already at its device cap.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/envelope"
	"patched.im/api/internal/evaluator"
	"patched.im/api/internal/report"
)

// rowQuerier is the QueryRow subset of both *pgxpool.Pool and pgx.Tx. The
// trial checks accept this rather than *pgxpool.Pool specifically so a caller
// that is already inside a transaction (EnrolHandler) can run the check on its
// own tx connection instead of acquiring a SECOND pooled connection. That
// second acquisition is a real deadlock hazard: under concurrent enrolment,
// every request holds a tx connection while blocked on the single-use token
// row lock, so the winner asking the pool for another connection can wedge the
// whole pool (regression caught by TestEnrolHandler_ConcurrentSingleUse).
type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// compile-time assertions that both concrete types satisfy rowQuerier.
var (
	_ rowQuerier = (*pgxpool.Pool)(nil)
	_ rowQuerier = (pgx.Tx)(nil)
)

const trialDuration = 14 * 24 * time.Hour
const defaultTrialDeviceCap = 3

// trialProvisionReq is the JSON body for POST /v1/trial/provision.
type trialProvisionReq struct {
	Email   string `json:"email"`
	Name    string `json:"name"`
	Company string `json:"company"`
}

// trialProvisionResp is returned on success (201) or idempotent re-request (200).
type trialProvisionResp struct {
	TenantID      string    `json:"tenant_id"`
	EnrollmentURL string    `json:"enrollment_url"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// enrollBaseURL returns the base URL for enrollment links. Configurable via
// ENROLL_BASE_URL env var; defaults to the production installer page.
func enrollBaseURL() string {
	if u := os.Getenv("ENROLL_BASE_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "https://get.patched.im/install"
}

// TrialProvisionHandler serves POST /v1/trial/provision on the public :8080 listener.
//
// PAT-2529: every request is charged to limits (per client, then global)
// before the body is read and before any database work. A nil limits fails
// closed with 503 rather than leaving the route unlimited. See
// trial_ratelimit.go.
func TrialProvisionHandler(pool *pgxpool.Pool, limits *TrialProvisionLimits) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "trial_provision")

		if limits == nil {
			http.Error(w, "trial provisioning not configured", http.StatusServiceUnavailable)
			return
		}
		if ok, retry, scope := limits.Allow(r); !ok {
			limits.refuse(w, logger, retry, scope)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body failed", http.StatusBadRequest)
			return
		}
		var req trialProvisionReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		req.Email = strings.ToLower(strings.TrimSpace(req.Email))
		req.Name = strings.TrimSpace(req.Name)
		req.Company = strings.TrimSpace(req.Company)

		if req.Email == "" || !strings.Contains(req.Email, "@") {
			http.Error(w, "email is required and must be a valid email address", http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}

		// Check for an existing active trial for this email.
		existing, err := lookupActiveTrial(r.Context(), pool, req.Email)
		if err != nil {
			logger.Error("active trial lookup failed", "err", err, "email", req.Email)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if existing != nil {
			// PAT-1757: refuse to re-mint for an existing trial tenant that
			// carries an active (non-"none") decommission directive.
			// lookupActiveTrial's WHERE clause only checks is_trial,
			// trial_expires_at and revoked_at — none of which decommission
			// touches — so a decommissioned-but-not-revoked trial tenant
			// would otherwise still pass as "active" here and get a fresh,
			// usable-looking token. POST /v1/enrol independently refuses
			// that token regardless (EnrolHandler's own PAT-1757 guard), but
			// minting one anyway would hand the customer a dead link with no
			// indication why. mintEnrollmentToken below is this package's
			// OWN deliberately minimal trial-mint helper (see its doc
			// comment) — not mintTenantEnrolmentToken — so it needs its own
			// copy of the guard rather than inheriting one. Reuses
			// report.FetchTenantDecommissionDirective directly against the
			// pool: neither lookupActiveTrial nor mintEnrollmentToken holds
			// an open transaction at this point, so there is no deadlock
			// hazard in acquiring a second pooled connection here.
			directive, dErr := report.FetchTenantDecommissionDirective(r.Context(), pool, existing.TenantID)
			if dErr != nil {
				logger.Error("decommission directive lookup failed", "err", dErr, "tenant_id", existing.TenantID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if directive.Mode != "none" {
				logger.Warn("trial re-provision rejected: tenant has an active decommission directive",
					"tenant_id", existing.TenantID, "mode", directive.Mode)
				writeTenantDecommissionedConflict(w, directive.Mode, directive.SetAt)
				return
			}

			// Idempotent: re-mint a fresh enrollment token for the existing trial
			// (the previous token may have been consumed).
			token, expiresAt, err := mintEnrollmentToken(r.Context(), pool, existing.TenantID)
			if err != nil {
				logger.Error("re-mint enrollment token failed", "err", err, "tenant_id", existing.TenantID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			enrollURL := fmt.Sprintf("%s?token=%s", enrollBaseURL(), token)
			logger.Info("existing active trial — re-sent enrollment link",
				"email", req.Email, "tenant_id", existing.TenantID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(trialProvisionResp{
				TenantID:      existing.TenantID,
				EnrollmentURL: enrollURL,
				ExpiresAt:     expiresAt,
			})
			return
		}

		// Create a new trial tenant.
		tenantID, trialExpiresAt, err := createTrialTenant(r.Context(), pool, req)
		if err != nil {
			logger.Error("create trial tenant failed", "err", err, "email", req.Email)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Mint an enrollment token using the PAT-543 bootstrap_tokens flow.
		token, _, err := mintEnrollmentToken(r.Context(), pool, tenantID)
		if err != nil {
			logger.Error("mint enrollment token failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		enrollURL := fmt.Sprintf("%s?token=%s", enrollBaseURL(), token)
		logger.Info("trial tenant provisioned",
			"tenant_id", tenantID, "email", req.Email, "expires_at", trialExpiresAt)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(trialProvisionResp{
			TenantID:      tenantID,
			EnrollmentURL: enrollURL,
			ExpiresAt:     trialExpiresAt,
		})
	}
}

// -- helpers ------------------------------------------------------------------

type activeTrial struct {
	TenantID  string
	ExpiresAt time.Time
}

// lookupActiveTrial returns the existing active trial for the given email, or
// nil if none exists. An active trial is one where is_trial=true AND
// trial_expires_at > now() AND revoked_at IS NULL.
func lookupActiveTrial(ctx context.Context, pool *pgxpool.Pool, email string) (*activeTrial, error) {
	var tenantID string
	var expiresAt time.Time
	err := pool.QueryRow(ctx, `
		SELECT id::text, trial_expires_at
		FROM tenants
		WHERE trial_email = $1
		  AND is_trial = true
		  AND trial_expires_at > now()
		  AND revoked_at IS NULL
		LIMIT 1
	`, email).Scan(&tenantID, &expiresAt)
	if isNoRowsErr(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &activeTrial{TenantID: tenantID, ExpiresAt: expiresAt}, nil
}

// createTrialTenant inserts a new trial tenant + initial tenant_credentials row
// in a transaction and returns (tenantID, expiresAt, err).
func createTrialTenant(ctx context.Context, pool *pgxpool.Pool, req trialProvisionReq) (string, time.Time, error) {
	expiresAt := time.Now().UTC().Add(trialDuration)
	tenantName := req.Name
	if req.Company != "" {
		tenantName = req.Company + " — " + req.Name
	}

	// Generate per-tenant bearer+HMAC credentials (same flow as CreateTenantHandler).
	bearerBytes := make([]byte, 32)
	if _, err := rand.Read(bearerBytes); err != nil {
		return "", time.Time{}, fmt.Errorf("rand bearer: %w", err)
	}
	bearerToken := base64.RawURLEncoding.EncodeToString(bearerBytes)
	bearerHash := sha256.Sum256([]byte(bearerToken))

	hmacSecret := make([]byte, 32)
	if _, err := rand.Read(hmacSecret); err != nil {
		return "", time.Time{}, fmt.Errorf("rand hmac: %w", err)
	}

	encHMAC, err := envelope.Default().EncryptBytes(hmacSecret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("encrypt hmac: %w", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var tenantID string
	err = tx.QueryRow(ctx, `
		INSERT INTO tenants (
			name, bearer_token_hash, hmac_secret,
			is_trial, trial_expires_at, trial_device_cap, trial_email
		) VALUES ($1, $2, $3, true, $4, $5, $6)
		RETURNING id::text
	`, tenantName, bearerHash[:], encHMAC, expiresAt, defaultTrialDeviceCap, req.Email).Scan(&tenantID)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("insert tenant: %w", err)
	}

	encCredHMAC, err := envelope.Default().EncryptBytes(hmacSecret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("encrypt cred hmac: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO tenant_credentials (tenant_id, bearer_token_hash, hmac_secret)
		VALUES ($1::uuid, $2, $3)
	`, tenantID, bearerHash[:], encCredHMAC)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("insert credential: %w", err)
	}

	// PAT-1794: a trial tenant gets the same T2 compliance-rule baseline as
	// any other tenant — same seeding call as CreateTenantHandler
	// (internal/handlers/admin.go), same transaction, so a seeding failure
	// rolls the whole trial-tenant creation back.
	if err := evaluator.SeedT2Baseline(ctx, tx, tenantID); err != nil {
		return "", time.Time{}, fmt.Errorf("seed T2 baseline: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, err
	}
	return tenantID, expiresAt, nil
}

// mintEnrollmentToken generates a 24h one-use bootstrap token for the given
// tenant and stores it in bootstrap_tokens. Returns the plaintext token.
// Reuses the same logic as MintBootstrapTokenHandler (PAT-543).
func mintEnrollmentToken(ctx context.Context, pool *pgxpool.Pool, tenantID string) (token string, expiresAt time.Time, err error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", time.Time{}, fmt.Errorf("rand token: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(tokenBytes)
	hash := sha256.Sum256([]byte(plaintext))
	expiresAt = time.Now().UTC().Add(24 * time.Hour)

	_, err = pool.Exec(ctx, `
		INSERT INTO bootstrap_tokens (tenant_id, token_hash, expires_at)
		VALUES ($1::uuid, $2, $3)
	`, tenantID, hash[:], expiresAt)
	if err != nil {
		return "", time.Time{}, err
	}
	return plaintext, expiresAt, nil
}

// CheckTrialExpired returns true if tenantID is a trial tenant whose
// trial_expires_at has passed. Non-trial tenants always return false. Called
// directly by InventoryHandler — there is no shared bearer-auth middleware on
// the public listener for this to hook into (see the package doc comment
// above), so a direct call is the enforcement point. It runs only AFTER the
// full auth + replay gate (bearer, HMAC, timestamp, nonce): the 402 is a
// state signal for an authenticated tenant, so it must never precede the
// second auth factor and become a bearer-only trial-status oracle.
//
// A DB error is returned to the caller rather than swallowed. Callers MUST
// fail closed on it (reject the request, e.g. 500) — this is a paid-tier gate,
// so a lookup failure must never let an expired trial through. The caller's
// request touches the same DB either way, so failing closed costs no real
// availability.
func CheckTrialExpired(ctx context.Context, q rowQuerier, tenantID string) (expired bool, err error) {
	var isTrial bool
	var trialExpiresAt *time.Time
	err = q.QueryRow(ctx, `
		SELECT is_trial, trial_expires_at
		FROM tenants WHERE id = $1::uuid
	`, tenantID).Scan(&isTrial, &trialExpiresAt)
	if err != nil {
		return false, err
	}
	if !isTrial {
		return false, nil
	}
	return trialExpiresAt != nil && time.Now().After(*trialExpiresAt), nil
}

// CheckTrialDeviceCap returns true if the tenant is a trial tenant AND either
// its trial has expired or the enrolled device count has reached
// trial_device_cap. Returns false for non-trial tenants. Called directly by
// EnrolHandler after the tenant identity is resolved from the enrollment
// token (the enrolment route has no bearer credential at all, so it was
// never a candidate for a bearer-auth middleware in the first place — this
// function's caller doc comment always intended a direct call here).
//
// Concurrency: q MUST be the enrolment transaction (pgx.Tx), not the pool.
// The tenant row is selected FOR UPDATE, which serialises concurrent
// enrolments for the SAME tenant: enrolment B blocks on the row lock until
// enrolment A commits (or rolls back), so B's device COUNT always observes
// A's inserted device. Without this lock the COUNT-then-INSERT is a TOCTOU
// race — two enrolments at count cap-1, each with its own valid token, could
// both read "under cap" and both insert, overshooting trial_device_cap. The
// lock is held for the remainder of the enrolment tx (through the device +
// credential INSERTs and COMMIT), so the check and the write it guards are
// atomic. Passing the pool here would take the row lock in an implicit,
// immediately-committed transaction and provide no protection at all.
func CheckTrialDeviceCap(ctx context.Context, q rowQuerier, tenantID string) (capReached bool, err error) {
	var isTrial bool
	var trialExpiresAt *time.Time
	var deviceCap int
	err = q.QueryRow(ctx, `
		SELECT is_trial, trial_expires_at, trial_device_cap
		FROM tenants WHERE id = $1::uuid
		FOR UPDATE
	`, tenantID).Scan(&isTrial, &trialExpiresAt, &deviceCap)
	if err != nil {
		return false, err
	}
	if !isTrial {
		return false, nil
	}
	// An expired trial also cannot enrol new devices — this is the only
	// enforcement point for enrolment, so expiry is folded into capReached
	// rather than assuming a separate check runs elsewhere.
	if trialExpiresAt != nil && time.Now().After(*trialExpiresAt) {
		return true, nil
	}

	// Count enrolled (non-revoked) devices. Protected by the tenant-row lock
	// taken above: a concurrent same-tenant enrolment cannot have inserted its
	// device between this COUNT and our own later INSERT without first
	// committing, which it cannot do while we hold the lock.
	var count int
	if err := q.QueryRow(ctx, `
		SELECT COUNT(*) FROM devices d
		JOIN tenant_credentials tc ON tc.device_id = d.id
		WHERE d.tenant_id = $1::uuid
		  AND tc.revoked_at IS NULL
		  AND tc.device_id IS NOT NULL
	`, tenantID).Scan(&count); err != nil {
		return false, err
	}
	return count >= deviceCap, nil
}
