// Package auth handles incoming request authentication:
// bearer-token tenant lookup and HMAC-SHA256 body signature verification.
package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/envelope"
)

// Public sentinel errors so callers can distinguish reasons in logs without
// leaking detail to the wire (handlers map all of these to a generic 401).
var (
	ErrMissingAuth  = errors.New("missing Authorization header")
	ErrBadAuthForm  = errors.New("Authorization header must be 'Bearer <token>'")
	ErrUnknownToken = errors.New("bearer token not recognised")

	// ErrDeviceCredentialRequired is returned by LookupDeviceByBearer when the
	// presented bearer token matches a live, non-revoked, unexpired
	// tenant_credentials row for a non-revoked tenant, but that row's
	// device_id is NULL: it is a tenant-level credential, not a device-scoped
	// one. This is a distinct diagnostic reason from ErrUnknownToken, for
	// server-side logs and metrics ONLY (PAT-1417) — every caller of
	// LookupDeviceByBearer must keep mapping this, exactly like
	// ErrUnknownToken, to the same generic 401 with the same body. Do not let
	// this leak to the wire: a genuinely unknown token and a tenant-level
	// credential must remain indistinguishable to the client.
	ErrDeviceCredentialRequired = errors.New("bearer token is a tenant-level credential; this endpoint requires a device-scoped credential")
)

// LookupTenantByBearer parses an Authorization header, SHA-256-hashes the
// token, and looks up the tenant. Returns the tenant ID (string UUID) and
// the raw HMAC secret bytes needed for signature verification.
//
// The plaintext token never leaves the request; we only ever store and
// compare its SHA-256 hash.
func LookupTenantByBearer(ctx context.Context, pool *pgxpool.Pool, authHeader string) (tenantID string, hmacSecret []byte, err error) {
	if authHeader == "" {
		return "", nil, ErrMissingAuth
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", nil, ErrBadAuthForm
	}
	tokenHash := sha256.Sum256([]byte(parts[1]))

	var tID string
	var secret []byte
	err = pool.QueryRow(ctx, `
		SELECT tc.tenant_id::text, tc.hmac_secret
		FROM tenant_credentials tc
		JOIN tenants t ON t.id = tc.tenant_id
		WHERE tc.bearer_token_hash = $1
		  AND tc.revoked_at IS NULL
		  AND (tc.expires_at IS NULL OR tc.expires_at > now())
		  AND t.revoked_at IS NULL
	`, tokenHash[:]).Scan(&tID, &secret)
	if err != nil {
		// Uniform "unknown token" — never leak whether the row missed vs. DB error
		return "", nil, fmt.Errorf("%w: %v", ErrUnknownToken, err)
	}
	// PAT-687: decrypt-with-plaintext-fallback. Rows written before envelope
	// encryption (or while PATCHED_KEK was unset) carry no marker and are
	// returned verbatim; a genuine decrypt failure is surfaced as an error so
	// we never authenticate against a corrupt/undecryptable secret.
	secret, err = envelope.Default().DecryptBytes(secret)
	if err != nil {
		return "", nil, fmt.Errorf("decrypt hmac_secret: %w", err)
	}
	return tID, secret, nil
}

// Bearer-auth conventions (PAT-1417)
//
// Agent endpoints in this service pick one of three conventions for how a
// tenant_credentials row authenticates a request. This list is the single
// place that documents the split; do not restate it per handler.
//
//  1. Device-scoped only (LookupDeviceByBearer, this function). The matched
//     row must have device_id set; a tenant-level credential is rejected.
//     Used by: POST /v1/inventory/enforcement-audit, POST /v1/agent-logs,
//     POST /v1/agent-decommission-status, GET/POST
//     /v1/devices/{deviceID}/removal-tasks/{pending,report}. Rule: use this
//     when the record being written is attributed to one specific device and
//     that attribution must be trustworthy (e.g. enforcement_audit.device_id
//     is TEXT NOT NULL and append-only — a wrong or invented device id would
//     silently corrupt an audit trail).
//     GET /v1/device/identity (PAT-2424) is in this group with one
//     difference: it never returns a device for a tenant-level credential,
//     but once such a credential has itself passed LookupTenantByBearer and
//     the strict HMAC, timestamp and nonce checks, it answers 409
//     device_credential_required instead of 401. The caller has by then
//     proved it holds the whole credential, so the answer discloses nothing
//     to anyone else; without that proof it is the same generic 401.
//  2. Tenant-level only (LookupTenantByBearer). No device_id requirement or
//     concept at all. Used by: POST /v1/inventory, allowlist/catalogue agent
//     sync endpoints, events ingestion. Rule: use this when the record or
//     action is inherently tenant-scoped, so there is no attribution to get
//     wrong.
//  3. Device-scoped with tenant-level fallback (try LookupDeviceByBearer,
//     fall back to LookupTenantByBearer on failure). Used by: GET
//     /v1/agent-config, GET /v1/agent/artifact. Rule: use this only when a
//     degraded tenant-level answer is still meaningful (e.g. agent config
//     falls back to a safe default ring) — never when the fallback would
//     have to invent or guess the device identity for a write.
//
// LookupDeviceByBearer is the posture-endpoint counterpart to LookupTenantByBearer.
// It requires the matched credential row to have device_id set — tenant-level
// credentials (device_id IS NULL) are rejected with ErrUnknownToken on the wire
// so the caller cannot distinguish "no such token" from "token exists but is
// tenant-wide". Server-side, callers CAN distinguish the two: this function
// returns ErrDeviceCredentialRequired (satisfies errors.Is directly; no wrap
// needed since it isn't carrying context from an underlying error) instead of
// ErrUnknownToken when the token is valid but tenant-level, so handlers can
// log the real cause and increment a metric while still returning the exact
// same generic 401 to the client.
//
// Returns (tenantID, deviceID, hmacSecret) on success.
func LookupDeviceByBearer(ctx context.Context, pool *pgxpool.Pool, authHeader string) (tenantID, deviceID string, hmacSecret []byte, err error) {
	if authHeader == "" {
		return "", "", nil, ErrMissingAuth
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", "", nil, ErrBadAuthForm
	}
	tokenHash := sha256.Sum256([]byte(parts[1]))

	// No "device_id IS NOT NULL" predicate here (unlike the query this
	// replaced): a tenant-level row must still be found so we can tell it
	// apart, in Go, from a token that matches no row at all. One round trip,
	// no race between "does it exist" and "does it have a device".
	var tID string
	var dID *string
	var secret []byte
	err = pool.QueryRow(ctx, `
		SELECT tc.tenant_id::text, tc.device_id::text, tc.hmac_secret
		FROM tenant_credentials tc
		JOIN tenants t ON t.id = tc.tenant_id
		WHERE tc.bearer_token_hash = $1
		  AND tc.revoked_at IS NULL
		  AND (tc.expires_at IS NULL OR tc.expires_at > now())
		  AND t.revoked_at IS NULL
	`, tokenHash[:]).Scan(&tID, &dID, &secret)
	if err != nil {
		return "", "", nil, fmt.Errorf("%w: %v", ErrUnknownToken, err)
	}
	if dID == nil {
		// No wrap: the query succeeded and this is a successful row read, so
		// there is no underlying error to preserve context for. The sentinel's
		// own message is already the full story.
		return "", "", nil, ErrDeviceCredentialRequired
	}
	// PAT-687: decrypt-with-plaintext-fallback (see LookupTenantByBearer).
	secret, err = envelope.Default().DecryptBytes(secret)
	if err != nil {
		return "", "", nil, fmt.Errorf("decrypt hmac_secret: %w", err)
	}
	return tID, *dID, secret, nil
}
