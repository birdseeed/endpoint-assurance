package agentidentity

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// DefaultEnforcementTier is the canonical enforcement_tier written for a
// tenant_app_policies row when nothing more specific applies — the same
// value handlers.TenantAppPoliciesPutHandler (app_policies.go) falls back to
// when a caller supplies none (PAT-1250's canonical "report_deploy" rung:
// advisory only, no blocking action). It is defined here, in this leaf
// package, rather than in the handlers package, so both handlers
// (CreateTenantHandler) and extractor (the new-app sweep) can depend on one
// constant without either package importing the other — handlers already
// imports extractor, so agentidentity must not import handlers.
//
// Never "managed" here: that tier opens the destructive-enforcement gate
// (Intune/MDM blocking), and auto-seeding a Patched Agent's own policy row
// is not the place to opt a tenant into that.
const DefaultEnforcementTier = "report_deploy"

// seedNotesMarker is written to tenant_app_policies.notes for every row this
// package seeds. Keep this string stable and unique — it is how a human (or
// the paired rollback migration) tells a PAT-1318 auto-seeded row apart from
// one an operator created by hand via the admin API.
const seedNotesMarker = "PAT-1318: first-party Patched Agent, auto-approved"

// Querier is satisfied by both *pgxpool.Pool and pgx.Tx (both implement
// Exec with this exact signature), so EnsurePatchedAgentPolicies can run
// standalone — the extractor's per-tenant sweep — or inside an existing
// transaction — CreateTenantHandler, so a seeding failure rolls the whole
// tenant creation back rather than half-creating a tenant.
type Querier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// EnsurePatchedAgentPolicies idempotently seeds one policy='approved' row
// per Identity in Identities for tenantID, so every Patched Agent surface
// starts — and stays — approved and out of the "for review" queue
// (PAT-1318). Safe to call repeatedly, including for a tenant that already
// has rows for some or all of these identities.
//
// This is called once per tenant on EVERY extraction batch
// (extractor/new_apps.go's doDetectNewTenantApps), so the steady state —
// every call after the first, for a tenant that has already converged —
// must not write. It is a single statement,
// `INSERT ... SELECT ... FROM (VALUES ...) WHERE NOT EXISTS (...)`, covering
// every identity in Identities in one round trip: the WHERE NOT EXISTS
// filters out any identity that already has a row for this tenant BEFORE it
// ever reaches the INSERT executor, so a converged tenant's steady-state
// call does zero writes — no heap tuple, no dead tuple, no burned xid,
// nothing for autovacuum to clean up. This is NOT the same as a naive
// multi-row `INSERT ... ON CONFLICT DO NOTHING`: Postgres's speculative-
// insertion protocol for ON CONFLICT always writes the heap tuple first and
// only removes it (a "super-deletion") after the unique-index conflict
// check — for every row, every call — real MVCC cost paid to write nothing,
// on every tenant, every extraction batch, forever. ON CONFLICT DO NOTHING
// is kept below purely as a concurrency backstop for the narrow race
// between this statement's own WHERE NOT EXISTS check and its INSERT (e.g.
// two goroutines converging the same out-of-band tenant concurrently) — not
// as the primary idempotency mechanism.
//
// Deliberately DO NOTHING, not DO UPDATE, on conflict — same reasoning as
// before this restructure: an existing row for one of these identities,
// whatever its policy value, means an operator has already made a
// deliberate decision about it (including, in principle, deliberately
// un-approving a Patched Agent surface), and any existing row already keeps
// the identity out of doDetectNewTenantApps's "for review" queue — that
// anti-join excludes on identity presence alone, not on policy value.
// Reasserting 'approved' over an operator's decision on every batch would
// be exactly the silent audit noise PAT-1318 says this must not create.
func EnsurePatchedAgentPolicies(ctx context.Context, q Querier, tenantID string) error {
	if len(Identities) == 0 {
		return nil
	}

	var valuesSQL strings.Builder
	args := []any{tenantID}
	placeholder := 2 // $1 is tenantID
	for i, id := range Identities {
		if i > 0 {
			valuesSQL.WriteString(", ")
		}
		fmt.Fprintf(&valuesSQL, "($%d::text, $%d::text, $%d::text, $%d::text)",
			placeholder, placeholder+1, placeholder+2, placeholder+3)
		args = append(args, nullIfEmpty(id.TeamID), nullIfEmpty(id.BundleID), nullIfEmpty(id.Name), id.Platform)
		placeholder += 4
	}
	tierArg, notesArg := placeholder, placeholder+1
	args = append(args, DefaultEnforcementTier, seedNotesMarker)

	stmt := fmt.Sprintf(`
		INSERT INTO tenant_app_policies
		    (tenant_id, team_id, bundle_id, name, platform, policy, enforcement_tier, notes)
		SELECT $1::uuid, a.team_id, a.bundle_id, a.name, a.platform, 'approved', $%d, $%d
		FROM (VALUES %s) AS a(team_id, bundle_id, name, platform)
		WHERE NOT EXISTS (
			SELECT 1 FROM tenant_app_policies existing
			WHERE existing.tenant_id = $1::uuid
			  AND COALESCE(lower(existing.name), '') = COALESCE(lower(a.name), '')
			  AND existing.platform                  = a.platform
		)
		ON CONFLICT (tenant_id,
		    COALESCE(team_id, ''),
		    COALESCE(bundle_id, ''),
		    COALESCE(lower(name), ''),
		    platform)
		DO NOTHING
	`, tierArg, notesArg, valuesSQL.String())

	if _, err := q.Exec(ctx, stmt, args...); err != nil {
		return fmt.Errorf("seed patched agent policies for tenant %s: %w", tenantID, err)
	}
	return nil
}

// nullIfEmpty converts an empty identity column to a genuine SQL NULL so the
// insert matches the "exactly one identity column set, the rest NULL" shape
// tenant_app_policies expects (see 0032's has-identity CHECK and the
// COALESCE-based unique index).
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
