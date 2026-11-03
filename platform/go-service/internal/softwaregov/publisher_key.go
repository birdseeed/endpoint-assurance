package softwaregov

import (
	"context"
	"fmt"
	"strings"
)

// PAT-2121: the Windows publisher key an approval records.
//
// When a Windows application is set to approved (the portal write or the
// operator app-policy API), the server derives the product's Authenticode
// publisher key (AuthenticodePublisherKey) from this tenant's own stored
// evidence and writes it to tenant_app_policies.publisher_key. The key is
// never taken from the client. New software urgency (urgency.go) then reads a
// trusted Windows product whose key matches an approved row on a different
// product as low, the twin of the macOS "Team ID already has approved
// products" rule.

// maxPublisherEvidenceTuples bounds the distinct evidence tuples read for one
// product. More than this many cannot agree on one key anyway.
const maxPublisherEvidenceTuples = 32

// windowsApplicationIdentityKinds are the Windows installation identities an
// approval's identifier addresses. Name-based kinds are never included: a
// display name is not an identity an approval can be keyed on.
var windowsApplicationIdentityKinds = []string{"windows_winget", "windows_native_publisher", "windows_native"}

// DeriveAuthenticodePublisherKey returns the Windows publisher key for the
// product this tenant knows by identifier, or "" when there is none.
//
// The evidence is each installation's latest observation, over the same
// basis new software urgency uses: the product's current installations, or
// all of them when every one has been removed. A key is returned only when
// there is at least one installation and every one of them is Authenticode
// valid, chains to a microsoft or public root with a root thumbprint, carries
// a signer, and all of them yield the same key. Anything else (no evidence,
// an unsigned, invalid or unknown installation, an enterprise or unreported
// root, an older agent that sent no root, or installations whose keys
// disagree) returns "": the approval is still recorded, it just vouches for
// no publisher.
func DeriveAuthenticodePublisherKey(ctx context.Context, q Querier, tenantID, identifier string) (string, error) {
	ident := normalisedIdentifier(identifier)
	if ident == "" {
		return "", nil
	}
	rows, err := q.Query(ctx, `
		WITH inst AS (
			SELECT si.removed_at,
			       o.observed_signature_state AS signature_state,
			       o.observed_authenticode_root_kind AS root_kind,
			       o.observed_authenticode_root_thumbprint AS root_thumbprint,
			       o.observed_authenticode_signer AS signer
			FROM software_installations si
			LEFT JOIN software_observations o
			       ON o.id = si.latest_observation_id AND o.tenant_id = si.tenant_id
			WHERE si.tenant_id = $1::uuid
			  AND si.platform = 'windows'
			  AND si.identity_kind = ANY($3)
			  AND si.identity_value_normalized = $2
		), basis AS (
			SELECT * FROM inst
			WHERE removed_at IS NULL OR NOT EXISTS (SELECT 1 FROM inst WHERE removed_at IS NULL)
		)
		SELECT COALESCE(signature_state, ''), COALESCE(root_kind, ''),
		       COALESCE(root_thumbprint, ''), COALESCE(signer, '')
		FROM basis
		GROUP BY 1, 2, 3, 4
		ORDER BY 1, 2, 3, 4
		LIMIT $4
	`, tenantID, ident, windowsApplicationIdentityKinds, maxPublisherEvidenceTuples+1)
	if err != nil {
		return "", fmt.Errorf("publisher key evidence: %w", err)
	}
	defer rows.Close()
	key, tuples, ok := "", 0, true
	for rows.Next() {
		var state, kind, root, signer string
		if err := rows.Scan(&state, &kind, &root, &signer); err != nil {
			return "", fmt.Errorf("scan publisher key evidence: %w", err)
		}
		tuples++
		if !ok {
			continue
		}
		k := ""
		if state == "valid" && (kind == "microsoft" || kind == "public") {
			k = AuthenticodePublisherKey(root, signer)
		}
		switch {
		case k == "":
			ok = false
		case key == "":
			key = k
		case key != k:
			ok = false
		}
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("iterate publisher key evidence: %w", err)
	}
	if !ok || tuples == 0 || tuples > maxPublisherEvidenceTuples {
		return "", nil
	}
	return key, nil
}

// approvedPublisherKeys reads the tenant's approved Windows application
// policies that carry a publisher key: key -> the normalised identifiers of
// the products approved under it. A row with no identifier (name or 'any'
// platform rows never get a key) is not read.
func approvedPublisherKeys(ctx context.Context, q Querier, tenantID string) (map[string]map[string]bool, error) {
	rows, err := q.Query(ctx, `
		SELECT publisher_key, COALESCE(bundle_id, winget_id, '')
		FROM effective_tenant_app_policies($1::uuid)
		WHERE tenant_id = $1::uuid
		  AND policy = 'approved'
		  AND platform = 'windows'
		  AND publisher_key IS NOT NULL
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load approved publisher keys: %w", err)
	}
	defer rows.Close()
	out := map[string]map[string]bool{}
	for rows.Next() {
		var key, ident string
		if err := rows.Scan(&key, &ident); err != nil {
			return nil, fmt.Errorf("scan approved publisher key: %w", err)
		}
		if out[key] == nil {
			out[key] = map[string]bool{}
		}
		out[key][normalisedIdentifier(ident)] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate approved publisher keys: %w", err)
	}
	return out, nil
}

// normalisedIdentifier is the extractor's identity_value_normalized form
// (lower case, whitespace runs collapsed to one space), so a policy's
// identifier compares with software_installations exactly.
func normalisedIdentifier(v string) string {
	return strings.ToLower(strings.Join(strings.Fields(v), " "))
}
