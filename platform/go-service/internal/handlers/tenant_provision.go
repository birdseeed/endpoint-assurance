package handlers

// provisionTenant is the one place a tenant row and everything a tenant must
// have before first use are created. Two callers share it, so the two cannot
// drift:
//
//   - POST /admin/tenants (CreateTenantHandler, operator, internal listener);
//   - POST /v1/portal/signup/organisation (PAT-1883, a verified person
//     creating their own organisation).
//
// It runs inside the caller's transaction and never commits: a failure in any
// step leaves the caller to roll the whole creation back, so a tenant is never
// half-created.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/jackc/pgx/v5"

	"patched.im/api/internal/agentidentity"
	"patched.im/api/internal/envelope"
	"patched.im/api/internal/evaluator"
)

// tenantProvision is what the caller decides about a new tenant. Optional
// text fields are stored as NULL when empty.
type tenantProvision struct {
	Name           string
	IntuneTenantID string
	// Tier is the CIS collection tier; anything outside 1 to 3 becomes 1.
	Tier         int
	ContactName  string
	ContactEmail string
	ContactRole  string
}

// provisionedTenant is the result. BearerToken and HMACSecret are the
// tenant-level ingest credential in plaintext; only their hash and the
// envelope-encrypted secret are stored, so a caller that does not hand them
// to someone discards the only copy.
type provisionedTenant struct {
	TenantID    string
	BearerToken string
	HMACSecret  []byte
	Tier        int
}

func nullIfBlank(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// provisionTenant inserts the tenant row, its initial credential, the
// pre-approved Patched Agent policies and the T2 compliance baseline.
func provisionTenant(ctx context.Context, tx pgx.Tx, p tenantProvision) (provisionedTenant, error) {
	var out provisionedTenant

	// Bearer token: 32 random bytes, base64url-no-padding for compactness.
	// Stored only as SHA-256 hash; the plaintext is never recoverable.
	bearerBytes := make([]byte, 32)
	if _, err := rand.Read(bearerBytes); err != nil {
		return out, fmt.Errorf("rand bearer: %w", err)
	}
	bearerToken := base64.RawURLEncoding.EncodeToString(bearerBytes)
	bearerHash := sha256.Sum256([]byte(bearerToken))

	// HMAC secret: 32 random bytes, stored raw (envelope-encrypted) because
	// verification needs the actual material.
	hmacSecret := make([]byte, 32)
	if _, err := rand.Read(hmacSecret); err != nil {
		return out, fmt.Errorf("rand hmac: %w", err)
	}

	tier := p.Tier
	if tier < 1 || tier > 3 {
		tier = 1
	}
	appControlEnabled := tier == 3

	// PAT-687: encrypt hmac_secret at rest in the tenants row (the schema's
	// documented "v2 envelope-encrypted"). No-op passthrough when PATCHED_KEK
	// is unset. tenants.hmac_secret is a legacy column; the ACTIVE auth secret
	// is tenant_credentials.hmac_secret (read by auth/bearer.go), which is
	// also envelope-encrypted below with a decrypt-with-plaintext-fallback in
	// the auth hot path.
	encHMAC, err := envelope.Default().EncryptBytes(hmacSecret)
	if err != nil {
		return out, fmt.Errorf("encrypt hmac_secret: %w", err)
	}

	var tenantID string
	err = tx.QueryRow(ctx, `
		INSERT INTO tenants (name, intune_tenant_id, bearer_token_hash, hmac_secret, tier, contact_name, contact_email, contact_role, app_control_enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id::text
	`, p.Name, nullIfBlank(p.IntuneTenantID), bearerHash[:], encHMAC, tier,
		nullIfBlank(p.ContactName), nullIfBlank(p.ContactEmail), nullIfBlank(p.ContactRole), appControlEnabled).Scan(&tenantID)
	if err != nil {
		return out, fmt.Errorf("insert tenant: %w", err)
	}

	// Seed the initial credential row so the hot path (tenant_credentials)
	// is authoritative from first use. PAT-687: encrypt the ACTIVE auth secret
	// at rest; auth/bearer.go decrypts with a plaintext fallback.
	encCredHMAC, err := envelope.Default().EncryptBytes(hmacSecret)
	if err != nil {
		return out, fmt.Errorf("encrypt credential hmac_secret: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant_credentials (tenant_id, bearer_token_hash, hmac_secret)
		VALUES ($1::uuid, $2, $3)
	`, tenantID, bearerHash[:], encCredHMAC); err != nil {
		return out, fmt.Errorf("insert tenant_credential: %w", err)
	}

	// PAT-1318: every Patched Agent identity starts pre-approved. These
	// are trusted first-party platform components, not customer-discovered
	// software awaiting review.
	if err := agentidentity.EnsurePatchedAgentPolicies(ctx, tx, tenantID); err != nil {
		return out, fmt.Errorf("seed patched agent policies: %w", err)
	}

	// PAT-1794: every assessed tenant gets the full T2 compliance-rule
	// baseline enabled by default, not opt-in.
	if err := evaluator.SeedT2Baseline(ctx, tx, tenantID); err != nil {
		return out, fmt.Errorf("seed T2 baseline: %w", err)
	}

	return provisionedTenant{TenantID: tenantID, BearerToken: bearerToken, HMACSecret: hmacSecret, Tier: tier}, nil
}
