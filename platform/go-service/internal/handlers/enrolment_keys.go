package handlers

// Tenant enrolment keys (PAT-2250).
//
// A bootstrap token (enrolment.go) is single-use and lives 24 hours, so an
// estate rollout through Intune, Jamf or an RMM would need one token per
// device. A tenant enrolment key is one reusable credential for that case:
// up to max_devices distinct devices may redeem it at POST /v1/enrol until it
// expires or a portal admin revokes it. It is supplied alongside the generic
// signed installer, never baked into the package.
//
// Wire compatibility: the key travels in the SAME request field as a
// bootstrap token (enrollment_token, or the legacy bootstrap_token), so the
// MSI ENROLLMENT_TOKEN property and the macOS enrollment.json /
// /etc/patched/enrollment-token paths carry it with no agent change.
//
// Format and storage: the plaintext is "pek_" + base64url(32 random bytes).
// Only SHA-256(plaintext) is stored (tenant_enrolment_keys.key_hash, the
// same hashing bootstrap tokens and bearer credentials use), plus a
// four-character hint so a leaked key can be matched to its row. The
// plaintext is returned once, by the create endpoint, and is never logged or
// put in an error message. Lookup is by hash through a unique index, so the
// plaintext is never compared byte-by-byte against anything stored.
//
// The "pek_" prefix routes the lookup, it does not reserve the namespace: a
// bootstrap token is base64url text and can itself begin with "pek_" (about
// one in 17 million), so a prefixed value that matches no key falls through
// to the unchanged bootstrap-token path rather than being refused.
//
// Portal surface (behind portalauth.Middleware; the tenant always comes from
// the verified identity, never from the request):
//
//	POST /v1/portal/enrolment-keys               create (admin only), returns the plaintext once
//	GET  /v1/portal/enrolment-keys               list (every role), never the plaintext
//	POST /v1/portal/enrolment-keys/{keyID}/revoke revoke (admin only)
//
// Creating and revoking a key is restricted to the admin role, the same rule
// as the other credentials on this surface: the Jamf webhook token and,
// since PAT-2407, the single-use token (POST /v1/portal/enrolment).

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/ratelimit"
)

const (
	enrolmentKeyPrefix = "pek_"

	enrolmentKeyMaxDevicesLimit    = 100000
	enrolmentKeyDefaultExpiresDays = 30
	enrolmentKeyMaxExpiresDays     = 365
	enrolmentKeyLabelMaxChars      = 100
	enrolmentKeyMaxBodyBytes       = 4 << 10
)

// isEnrolmentKey reports whether an enrolment credential should be looked up
// as a tenant enrolment key first. See the package comment: a miss falls
// through to the bootstrap-token path.
func isEnrolmentKey(token string) bool {
	return strings.HasPrefix(token, enrolmentKeyPrefix) && len(token) > len(enrolmentKeyPrefix)
}

// lockedEnrolmentKey is a key row locked FOR UPDATE inside the enrolment tx.
type lockedEnrolmentKey struct {
	ID       string
	TenantID string
	// Refusal is "" when the key admits this device, otherwise the reason
	// ("revoked", "expired" or "device limit reached") the enrolment is
	// refused with 410.
	Refusal string
}

// lockEnrolmentKeyForEnrol finds the key whose hash is keyHash, locks its row
// and decides whether it admits hwUUID. It returns nil, nil when no key has
// that hash (the caller then tries the bootstrap-token path).
//
// Lock order. EnrolHandler's transaction takes, in this order:
//
//  1. the credential row: a bootstrap_tokens row (the consume UPDATE) or,
//     here, a tenant_enrolment_keys row (SELECT ... FOR UPDATE OF k);
//  2. the tenants row, FOR UPDATE (lockTenantAndReadDecommissionState, then
//     CheckTrialDeviceCap re-locks the row it already holds).
//
// The key row lock is taken first, in the same position as the bootstrap
// token row, so the two credential kinds share one order: credential row,
// then tenant row. Nothing in this file takes a tenants row lock at all
// (create only inserts; revoke only updates the key row), so no path locks
// the tenant before a key row and there is no inverse ordering to deadlock
// against. The JOIN to tenants reads revoked_at without locking it
// (FOR UPDATE OF k locks the key row only).
//
// The key row lock is what makes the device cap atomic: two enrolments at
// max_devices-1 serialise on it, so the COUNT below and the use INSERT the
// caller makes later in the same transaction cannot interleave.
//
// Re-enrolment: the cap counts DISTINCT hw_uuid. /v1/enrol already reuses
// the (tenant_id, hw_uuid) device slot on re-enrolment (wipe and reinstall),
// so a device that has already used this key is admitted again without
// consuming a second slot, even when the key is otherwise exhausted. It is
// still refused once the key is revoked or expired.
func lockEnrolmentKeyForEnrol(ctx context.Context, tx pgx.Tx, keyHash []byte, hwUUID string) (*lockedEnrolmentKey, error) {
	var k lockedEnrolmentKey
	var maxDevices int
	var keyRevoked, keyExpired, tenantRevoked bool
	err := tx.QueryRow(ctx, `
		SELECT k.id::text, k.tenant_id::text, k.max_devices,
		       k.revoked_at IS NOT NULL, k.expires_at <= now(), t.revoked_at IS NOT NULL
		FROM tenant_enrolment_keys k
		JOIN tenants t ON t.id = k.tenant_id
		WHERE k.key_hash = $1
		FOR UPDATE OF k
	`, keyHash).Scan(&k.ID, &k.TenantID, &maxDevices, &keyRevoked, &keyExpired, &tenantRevoked)
	if isNoRowsErr(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lock enrolment key: %w", err)
	}
	switch {
	case keyRevoked || tenantRevoked:
		k.Refusal = "revoked"
		return &k, nil
	case keyExpired:
		k.Refusal = "expired"
		return &k, nil
	}

	var used int
	var alreadyCounted bool
	if err := tx.QueryRow(ctx, `
		SELECT count(DISTINCT hw_uuid), COALESCE(bool_or(hw_uuid = $2::uuid), false)
		FROM tenant_enrolment_key_uses
		WHERE key_id = $1::uuid
	`, k.ID, hwUUID).Scan(&used, &alreadyCounted); err != nil {
		return nil, fmt.Errorf("count enrolment key uses: %w", err)
	}
	if !alreadyCounted && used >= maxDevices {
		k.Refusal = "device limit reached"
	}
	if enrolmentKeyAfterCapCount != nil {
		enrolmentKeyAfterCapCount()
	}
	return &k, nil
}

// enrolmentKeyAfterCapCount is a test hook, nil in production. The
// concurrency test uses it to hold each enrolment between its cap COUNT and
// its use INSERT, which widens the race the key row lock exists to close:
// without that lock the test admits more than one device at cap-1.
var enrolmentKeyAfterCapCount func()

// recordEnrolmentKeyUse writes one tenant_enrolment_key_uses row inside the
// enrolment tx, after the device upsert, so the use is atomic with the
// credential it issued.
func recordEnrolmentKeyUse(ctx context.Context, tx pgx.Tx, keyID, tenantID, deviceID, hwUUID string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO tenant_enrolment_key_uses (key_id, tenant_id, device_id, hw_uuid)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid)
	`, keyID, tenantID, deviceID, hwUUID)
	return err
}

// newEnrolmentKey returns a fresh plaintext key, its SHA-256 and its hint.
func newEnrolmentKey() (plaintext string, hash [32]byte, hint string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", hash, "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	plaintext = enrolmentKeyPrefix + secret
	return plaintext, sha256.Sum256([]byte(plaintext)), secret[:4], nil
}

// ─── Portal: create ──────────────────────────────────────────────────────────

type enrolmentKeyCreateReq struct {
	Label         string `json:"label"`
	MaxDevices    int    `json:"max_devices"`
	ExpiresInDays *int   `json:"expires_in_days"`
}

type enrolmentKeyView struct {
	KeyID           string     `json:"key_id"`
	Label           string     `json:"label"`
	KeyHint         string     `json:"key_hint"`
	MaxDevices      int        `json:"max_devices"`
	DevicesEnrolled int        `json:"devices_enrolled"`
	Status          string     `json:"status"`
	ExpiresAt       time.Time  `json:"expires_at"`
	CreatedAt       time.Time  `json:"created_at"`
	CreatedBy       string     `json:"created_by"`
	RevokedAt       *time.Time `json:"revoked_at"`
	RevokedBy       *string    `json:"revoked_by"`
}

type enrolmentKeyCreateResp struct {
	enrolmentKeyView
	EnrollmentKey string `json:"enrollment_key"`
	Warning       string `json:"warning"`
}

// PortalEnrolmentKeyCreateHandler serves POST /v1/portal/enrolment-keys.
// Admin only. Body: {"label": "...", "max_devices": N, "expires_in_days": D}
// (expires_in_days optional, default 30, at most 365). rl is the same
// per-tenant limiter as the single-use mint (PORTAL_ENROL_MINTS_PER_HOUR):
// both issue enrolment credentials, so they share one budget. nil disables it.
func PortalEnrolmentKeyCreateHandler(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "portal_enrolment_key_create", "tenant_id", id.TenantID)
		if !looksLikeUUID(id.TenantID) {
			logger.Error("portal identity resolved to a non-UUID tenant_id, refusing to create a key")
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}

		body, ok := readLimitedBody(w, r, enrolmentKeyMaxBodyBytes)
		if !ok {
			return
		}
		var req enrolmentKeyCreateReq
		if err := decodeStrictJSON(body, &req); err != nil {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request",
				"body must be {\"label\", \"max_devices\", optional \"expires_in_days\"} with no other fields", nil)
			return
		}
		label := strings.TrimSpace(req.Label)
		if label == "" || utf8.RuneCountInString(label) > enrolmentKeyLabelMaxChars || hasControlChars(label) || !utf8.ValidString(label) {
			writeApprovalError(w, http.StatusBadRequest, "invalid_label",
				fmt.Sprintf("label is required, at most %d characters, with no control characters", enrolmentKeyLabelMaxChars), nil)
			return
		}
		if req.MaxDevices < 1 || req.MaxDevices > enrolmentKeyMaxDevicesLimit {
			writeApprovalError(w, http.StatusBadRequest, "invalid_max_devices",
				fmt.Sprintf("max_devices must be between 1 and %d", enrolmentKeyMaxDevicesLimit), nil)
			return
		}
		days := enrolmentKeyDefaultExpiresDays
		if req.ExpiresInDays != nil {
			days = *req.ExpiresInDays
		}
		if days < 1 || days > enrolmentKeyMaxExpiresDays {
			writeApprovalError(w, http.StatusBadRequest, "invalid_expires_in_days",
				fmt.Sprintf("expires_in_days must be between 1 and %d", enrolmentKeyMaxExpiresDays), nil)
			return
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
		if !requirePortalAdmin(ctx, tx, w, id, "create an enrolment key", logger) {
			return
		}

		if rl != nil {
			if allowed, retryAfter := rl.Allow(id.TenantID); !allowed {
				w.Header().Set("Retry-After", fmt.Sprintf("%.0f", retryAfter.Seconds()+1))
				writeApprovalError(w, http.StatusTooManyRequests, "rate_limited", "enrolment credential rate limit exceeded", nil)
				return
			}
		}

		// PAT-1757 parity with the single-use mint: no new enrolment
		// credential for a tenant with an active decommission directive.
		// /v1/enrol refuses such a tenant independently as well. Read on
		// this tx, not report.FetchTenantDecommissionDirective's pool, so a
		// request never holds one pooled connection while asking for a
		// second (the pool deadlock rowQuerier's doc comment describes). No
		// lock: a directive set after this read is still enforced by
		// /v1/enrol at redemption time.
		var decMode, decSetAt *string
		err = tx.QueryRow(ctx, `
			SELECT mode, to_char(set_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
			FROM tenant_decommission WHERE tenant_id = $1::uuid
		`, id.TenantID).Scan(&decMode, &decSetAt)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			logger.Error("decommission directive lookup failed", "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}
		if decMode != nil && *decMode != "none" {
			setAt := ""
			if decSetAt != nil {
				setAt = *decSetAt
			}
			logger.Warn("key create rejected: tenant has an active decommission directive", "mode", *decMode)
			writeTenantDecommissionedConflict(w, *decMode, setAt)
			return
		}

		plaintext, hash, hint, err := newEnrolmentKey()
		if err != nil {
			logger.Error("key generation failed", "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}
		expiresAt := time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour)
		var v enrolmentKeyView
		if err := tx.QueryRow(ctx, `
			INSERT INTO tenant_enrolment_keys (tenant_id, key_hash, key_hint, label, max_devices, expires_at, created_by)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, lower(btrim($7)))
			RETURNING id::text, label, key_hint, max_devices, expires_at, created_at, created_by
		`, id.TenantID, hash[:], hint, label, req.MaxDevices, expiresAt, id.Email).Scan(
			&v.KeyID, &v.Label, &v.KeyHint, &v.MaxDevices, &v.ExpiresAt, &v.CreatedAt, &v.CreatedBy); err != nil {
			logger.Error("key insert failed", "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			logger.Error("commit failed", "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}
		v.KeyHint = enrolmentKeyPrefix + v.KeyHint
		v.Status = "active"

		logger.Info("enrolment key created", "enrolment_key_id", v.KeyID, "max_devices", v.MaxDevices,
			"expires_at", v.ExpiresAt, "email", id.Email)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(enrolmentKeyCreateResp{
			enrolmentKeyView: v,
			EnrollmentKey:    plaintext,
			Warning:          "This key is shown once. Store it now; Patched keeps only a hash.",
		})
	}
}

// ─── Portal: list ────────────────────────────────────────────────────────────

// PortalEnrolmentKeysListHandler serves GET /v1/portal/enrolment-keys: the
// caller's tenant's keys, newest first, with usage and status. Every role
// may read it; it never carries a plaintext key or a hash.
func PortalEnrolmentKeysListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "portal_enrolment_keys_list", "tenant_id", id.TenantID)
		if !looksLikeUUID(id.TenantID) {
			logger.Error("portal identity resolved to a non-UUID tenant_id")
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}
		rows, err := pool.Query(ctx, `
			SELECT k.id::text, k.label, k.key_hint, k.max_devices,
			       (SELECT count(DISTINCT u.hw_uuid) FROM tenant_enrolment_key_uses u WHERE u.key_id = k.id)::int,
			       k.expires_at, k.expires_at <= now(), k.created_at, k.created_by, k.revoked_at, k.revoked_by
			FROM tenant_enrolment_keys k
			WHERE k.tenant_id = $1::uuid
			ORDER BY k.created_at DESC, k.id
		`, id.TenantID)
		if err != nil {
			logger.Error("list keys failed", "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}
		keys := []enrolmentKeyView{}
		for rows.Next() {
			var v enrolmentKeyView
			var expired bool
			if err := rows.Scan(&v.KeyID, &v.Label, &v.KeyHint, &v.MaxDevices, &v.DevicesEnrolled,
				&v.ExpiresAt, &expired, &v.CreatedAt, &v.CreatedBy, &v.RevokedAt, &v.RevokedBy); err != nil {
				rows.Close()
				logger.Error("scan key failed", "err", err)
				writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
				return
			}
			v.KeyHint = enrolmentKeyPrefix + v.KeyHint
			switch {
			case v.RevokedAt != nil:
				v.Status = "revoked"
			case expired:
				v.Status = "expired"
			case v.DevicesEnrolled >= v.MaxDevices:
				v.Status = "exhausted"
			default:
				v.Status = "active"
			}
			keys = append(keys, v)
		}
		if err := rows.Err(); err != nil {
			logger.Error("list keys failed", "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}
}

// ─── Portal: revoke ──────────────────────────────────────────────────────────

// PortalEnrolmentKeyRevokeHandler serves
// POST /v1/portal/enrolment-keys/{keyID}/revoke. Admin only; body empty or
// {}. New enrolments against the key are refused (410) from the moment this
// commits; devices already enrolled keep their credentials. Revoking an
// already revoked key is a no-op (changed false). A key that does not exist
// or belongs to another tenant is 404, indistinguishably.
func PortalEnrolmentKeyRevokeHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		keyID := strings.TrimSpace(chi.URLParam(r, "keyID"))
		logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "portal_enrolment_key_revoke", "tenant_id", id.TenantID)
		if !looksLikeUUID(id.TenantID) {
			logger.Error("portal identity resolved to a non-UUID tenant_id")
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}
		if !looksLikeUUID(keyID) {
			writeApprovalError(w, http.StatusNotFound, "not_found", "enrolment key not found", nil)
			return
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
		if !requirePortalAdmin(ctx, tx, w, id, "revoke an enrolment key", logger) {
			return
		}
		if !requireEmptyOrEmptyObject(w, r) {
			return
		}

		// Locks only the key row (see lockEnrolmentKeyForEnrol's lock-order
		// note). An in-flight enrolment holding the row finishes first; the
		// next one sees revoked_at.
		var revokedAt *time.Time
		err = tx.QueryRow(ctx, `
			SELECT revoked_at FROM tenant_enrolment_keys
			WHERE id = $1::uuid AND tenant_id = $2::uuid
			FOR UPDATE
		`, keyID, id.TenantID).Scan(&revokedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			writeApprovalError(w, http.StatusNotFound, "not_found", "enrolment key not found", nil)
			return
		}
		if err != nil {
			logger.Error("key lookup failed", "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}
		changed := false
		if revokedAt == nil {
			var at time.Time
			if err := tx.QueryRow(ctx, `
				UPDATE tenant_enrolment_keys SET revoked_at = now(), revoked_by = lower(btrim($3))
				WHERE id = $1::uuid AND tenant_id = $2::uuid
				RETURNING revoked_at
			`, keyID, id.TenantID, id.Email).Scan(&at); err != nil {
				logger.Error("key revoke failed", "err", err)
				writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
				return
			}
			revokedAt = &at
			changed = true
		}
		if err := tx.Commit(ctx); err != nil {
			logger.Error("commit failed", "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}
		logger.Info("enrolment key revoked", "enrolment_key_id", keyID, "changed", changed, "email", id.Email)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"key_id": keyID, "revoked_at": revokedAt, "changed": changed})
	}
}
