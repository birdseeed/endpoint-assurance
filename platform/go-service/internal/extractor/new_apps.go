package extractor

// new_apps.go — post-ingest sweep for new-app discovery (PAT-167).
//
// detectNewTenantApps is called after every extraction batch completes. It
// identifies apps present in a tenant's device_apps that have no matching
// tenant_app_policies row (using the same team_id > bundle_id > name precedence
// as fetchAppPolicy in handlers/posture.go) and upserts a tenant_new_apps row
// for each truly new app. A genuinely new row (not a re-ingest of an existing
// pending item) sends a best-effort Slack/email alert (PAT-819).
//
// rolloverDeferredNewApps promotes deferred rows whose defer_until has passed to
// 'approve_no_patch' — called at the top of each extraction batch.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/agentidentity"
	"patched.im/api/internal/notify"
)

// appCandidate is an app seen in device_apps for a tenant that may warrant a
// tenant_new_apps row.
type appCandidate struct {
	identity           string // mandatoryKey equivalent: team, typed Winget, bundle, or name identity
	name               string
	publisherSignature string // team_id (macOS) or signer (Windows) — may be empty
	platform           string // "macos" | "windows"
}

// detectNewTenantApps runs the post-ingest sweep for one tenant. It:
//  1. Queries all distinct (identity, name, publisher_signature, platform) tuples
//     that exist in device_apps for this tenant but have NO matching
//     tenant_app_policies row under the team_id > bundle_id > name precedence.
//  2. For each unmanaged app, checks app_catalog_entries for a suggested_action.
//  3. Inserts new tenant_new_apps rows (decision=NULL) or updates host_count+updated_at
//     for rows that already exist and are still undecided.
//
// The function is non-fatal: errors are logged but do not fail the extraction batch.
func detectNewTenantApps(ctx context.Context, pool *pgxpool.Pool, tenantID string, notifier *notify.Notifier, logger *slog.Logger) {
	if err := doDetectNewTenantApps(ctx, pool, tenantID, notifier); err != nil {
		logger.Warn("detectNewTenantApps failed (non-fatal)", "err", err, "tenant_id", tenantID)
	}
}

// newAppCandidateRow is one deduplicated (identity, platform) app tuple found
// in device_apps with no matching tenant_app_policies row — a candidate for a
// tenant_new_apps upsert.
type newAppCandidateRow struct {
	identity  string
	name      string
	pubSig    string
	platform  string
	hostCount int
}

func doDetectNewTenantApps(ctx context.Context, pool *pgxpool.Pool, tenantID string, notifier *notify.Notifier) error {
	// PAT-1318: keep the Patched Agent identities converged before running
	// the candidate query below, mirroring the rolloverDeferredNewApps
	// precedent of tidying state at the top of the sweep. This means a
	// tenant created out of band (bypassing CreateTenantHandler's seeding)
	// self-heals on its first extraction batch, and the rows this seeds are
	// already visible to this same batch's anti-join.
	//
	// This holds today for both macOS entries (bundle_id-keyed) and the
	// Windows entry (name-keyed, platform-scoped — see the WHERE NOT EXISTS
	// comment below). It does NOT hold unconditionally forever: the macOS
	// menu bar apps are currently unsigned, so device_apps.team_id reports
	// 'Unknown' for them and app_identity resolves to "bundle:...", which
	// the bundle_id clause matches. Once Developer ID signing lands
	// (macos/lib/apps.sh in the updater repo will then report a real Team
	// ID), app_identity becomes "team:<id>" instead, the bundle clause no
	// longer applies, and these two agentidentity.Identities entries carry
	// no team_id — so both macOS apps will reappear in every tenant's "for
	// review" queue until agentidentity.go is updated to add a TeamID entry
	// for them. See that package's doc comment for the explicit reminder.
	if err := agentidentity.EnsurePatchedAgentPolicies(ctx, pool, tenantID); err != nil {
		return fmt.Errorf("ensure patched agent policies: %w", err)
	}

	// Step 1: Find apps in device_apps for this tenant that have no matching
	// tenant_app_policies row. We replicate the precedence logic:
	//   a) If the app has a team_id, look for a policy with that team_id.
	//   b) Else if Windows inventory explicitly types a Winget ID, use winget_id.
	//   c) Else if the app has an identifier (bundle_id proxy), look for bundle_id.
	//   d) Else match on lower(name).
	//   e) PAT-1318: regardless of (a)-(d), also suppress on a per-axis name
	//      match — see the WHERE NOT EXISTS block below for why.
	//
	// We compute the identity key server-side in SQL so we get exactly one
	// distinct row per (identity, platform) pair across all devices in the tenant.
	//
	// app_catalog_entries.verified_signer joins on device_apps.team_id (macOS)
	// or device_apps.signer (Windows fallback). We prefer team_id.
	//
	// platform derivation: device_apps has no platform column directly; we reach
	// it via devices.os — 'Windows' → 'windows', everything else → 'macos'.
	const candidatesSQL = `
		WITH tenant_devices AS (
			SELECT id, os FROM devices WHERE tenant_id = $1::uuid
		),
		tenant_apps AS (
			SELECT
				da.name,
				da.team_id,
				da.identifier,
				COALESCE(da.identifier_kind, '') AS identifier_kind,
				da.signer,
				CASE WHEN LOWER(td.os) = 'windows' THEN 'windows' ELSE 'macos' END AS platform,
				COUNT(DISTINCT da.device_id) AS host_count
			FROM device_apps da
			JOIN tenant_devices td ON td.id = da.device_id
			WHERE da.name IS NOT NULL AND da.name <> ''
			  AND da.identifier IS NOT NULL AND da.identifier <> '' AND da.identifier <> 'Unknown'
			GROUP BY da.name, da.team_id, da.identifier, COALESCE(da.identifier_kind, ''), da.signer, CASE WHEN LOWER(td.os) = 'windows' THEN 'windows' ELSE 'macos' END
		),
		-- Compute the mandatoryKey for each app.
		-- Precedence: team_id > typed Windows Winget ID > bundle proxy > lower(name)
		keyed AS (
			SELECT
				ta.name,
				ta.team_id,
				ta.identifier,
				ta.identifier_kind,
				ta.signer,
				ta.platform,
				ta.host_count,
				CASE
					WHEN ta.team_id IS NOT NULL AND ta.team_id <> '' AND ta.team_id <> 'Unknown'
						THEN 'team:' || lower(ta.team_id)
					WHEN ta.platform = 'windows' AND ta.identifier_kind = 'winget'
						THEN 'winget:' || lower(ta.identifier)
					WHEN ta.identifier IS NOT NULL AND ta.identifier <> ''
						THEN 'bundle:' || lower(ta.identifier)
					ELSE 'name:' || lower(ta.name)
				END AS app_identity,
				CASE
					WHEN ta.team_id IS NOT NULL AND ta.team_id <> '' AND ta.team_id <> 'Unknown'
						THEN ta.team_id
					ELSE ta.signer
				END AS publisher_signature
			FROM tenant_apps ta
		),
		-- Deduplicate by (app_identity, platform) — take the max host_count and
		-- the most descriptive name (longest, as a tiebreak heuristic).
		deduped AS (
			SELECT DISTINCT ON (app_identity, platform)
				app_identity,
				name,
				team_id,
				identifier,
				identifier_kind,
				publisher_signature,
				platform,
				host_count
			FROM keyed
			ORDER BY app_identity, platform, host_count DESC, length(name) DESC
		),
		-- Load all policies for this tenant (we'll do matching in Go to stay
		-- faithful to the exact precedence logic in fetchAppPolicy).
		-- platform is carried through only for the PAT-1318 name-match clause
		-- below — the three original precedence clauses do not use it (see
		-- that clause's comment for why this asymmetry is deliberate).
		policies AS (
			SELECT team_id, bundle_id, winget_id, name AS policy_name, platform
			FROM effective_tenant_app_policies($1::uuid)
			WHERE tenant_id = $1::uuid
		)
		SELECT
			d.app_identity,
			d.name,
			d.publisher_signature,
			d.platform,
			d.host_count
		FROM deduped d
			-- Exclude an app only when one platform-applicable policy matches
			-- every identity field that policy populated. This mirrors
			-- policyMatchesInstalledApp: a Winget ID, bundle ID, Team ID or name
			-- is not an alternative key once the stored policy records a fuller
			-- tuple. Name-only policies remain intentionally broad, including
			-- the Windows Patched Agent identity whose registry key changes by
			-- release, but cannot suppress a different platform.
			WHERE NOT EXISTS (
				SELECT 1 FROM policies p
				WHERE (p.platform = d.platform OR p.platform = 'any')
				  AND (NULLIF(p.team_id, '') IS NULL
				       OR lower(p.team_id) = lower(COALESCE(d.team_id, '')))
				  AND (NULLIF(p.bundle_id, '') IS NULL
				       OR lower(p.bundle_id) = lower(COALESCE(d.identifier, '')))
				  AND (NULLIF(p.winget_id, '') IS NULL
				       OR (d.platform = 'windows' AND d.identifier_kind = 'winget'
				           AND lower(p.winget_id) = lower(COALESCE(d.identifier, ''))))
				  AND (NULLIF(p.policy_name, '') IS NULL
				       OR lower(p.policy_name) = lower(COALESCE(d.name, '')))
				  AND (NULLIF(p.team_id, '') IS NOT NULL
				       OR NULLIF(p.bundle_id, '') IS NOT NULL
				       OR NULLIF(p.winget_id, '') IS NOT NULL
				       OR NULLIF(p.policy_name, '') IS NOT NULL)
			)
	`

	rows, err := pool.Query(ctx, candidatesSQL, tenantID)
	if err != nil {
		return fmt.Errorf("query candidates: %w", err)
	}
	defer rows.Close()

	var candidates []newAppCandidateRow
	for rows.Next() {
		var r newAppCandidateRow
		var pubSig *string
		if err := rows.Scan(&r.identity, &r.name, &pubSig, &r.platform, &r.hostCount); err != nil {
			return fmt.Errorf("scan candidate: %w", err)
		}
		if pubSig != nil {
			r.pubSig = *pubSig
		}
		candidates = append(candidates, r)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate candidates: %w", err)
	}
	if len(candidates) == 0 {
		return nil
	}

	// Step 2 + 3: For each candidate, look up suggested_action from catalog and
	// upsert into tenant_new_apps.
	//
	// suggested_action logic (mirrors the brief):
	//   - 'approve'  when there's a catalog entry with matching verified_signer
	//   - 'defer'    otherwise (unknown/unsigned app)
	for _, c := range candidates {
		suggestedAction := suggestedActionForApp(ctx, pool, c.pubSig, c.identity, c.platform)

		// RETURNING (xmax = 0) tells us whether this statement actually performed
		// an INSERT (xmax = 0, a brand-new row — genuinely new detection) versus
		// an in-place DO UPDATE of an existing pending row (xmax set, a re-ingest
		// of the same still-undecided app). When the WHERE clause on DO UPDATE
		// doesn't match — i.e. the existing row already has a decision (deferred
		// or resolved) — Postgres performs neither an insert nor an update and
		// RETURNING yields no row at all (pgx.ErrNoRows). PAT-819 alerts only on
		// the genuine-insert case, so duplicate/deferred/resolved rows never
		// trigger a Slack message.
		const upsertSQL = `
			INSERT INTO tenant_new_apps (
				tenant_id, app_identity, name, publisher_signature, platform,
				host_count, suggested_action
			) VALUES (
				$1::uuid, $2, $3, NULLIF($4, ''), $5,
				$6, $7
			)
			ON CONFLICT (tenant_id, app_identity) DO UPDATE SET
				host_count       = EXCLUDED.host_count,
				updated_at       = now()
			WHERE tenant_new_apps.decision IS NULL
			RETURNING (xmax = 0) AS inserted, first_seen
		`
		var isNewRow bool
		var firstSeen time.Time
		err := pool.QueryRow(ctx, upsertSQL,
			tenantID, c.identity, c.name, c.pubSig, c.platform,
			c.hostCount, suggestedAction,
		).Scan(&isNewRow, &firstSeen)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue // existing row already decided — no-op, no alert
			}
			return fmt.Errorf("upsert tenant_new_apps %q: %w", c.identity, err)
		}

		if isNewRow {
			notifyNewAppDetected(notifier, tenantID, c, suggestedAction, firstSeen)
		}
	}
	return nil
}

// notifyNewAppDetected dispatches a KindNewAppDetected Slack/email alert
// (PAT-819) for a brand-new tenant_new_apps row. Delivery is fully best-effort
// via Notifier.Dispatch, which sends on its own goroutine and logs failures —
// it never blocks or fails the extraction sweep.
func notifyNewAppDetected(notifier *notify.Notifier, tenantID string, c newAppCandidateRow, suggestedAction string, firstSeen time.Time) {
	if !notifier.Enabled() {
		return
	}
	hostCount := c.hostCount
	notifier.Dispatch(context.Background(), notify.Event{
		TenantID:           tenantID,
		Kind:               notify.KindNewAppDetected,
		Label:              c.name,
		Platform:           c.platform,
		PublisherSignature: c.pubSig,
		SuggestedAction:    suggestedAction,
		HostCount:          &hostCount,
		FirstSeen:          firstSeen,
		Timestamp:          firstSeen,
		Link:               notify.NewAppsCatalogueLink(tenantID),
	})
}

// suggestedActionForApp returns "approve" when a catalog entry exists for this
// app (matched on publisher_signature / signer-first, then name), or "defer"
// for unknowns. This mirrors the join surface described in 0030_app_catalog_entries.sql.
func suggestedActionForApp(ctx context.Context, pool *pgxpool.Pool, publisherSig, identity, platform string) string {
	// Normalise platform to catalog style ("macOS" / "Windows").
	catalogPlatform := "macOS"
	if strings.EqualFold(platform, "windows") {
		catalogPlatform = "Windows"
	}

	// Try signer-first match.
	if publisherSig != "" {
		var count int
		if err := pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM app_catalog_entries
			WHERE verified_signer = $1
			  AND platform = $2
		`, publisherSig, catalogPlatform).Scan(&count); err == nil && count > 0 {
			return "approve"
		}
	}

	// Fallback: name match from identity key.
	// We only attempt a name lookup when identity starts with "name:".
	if strings.HasPrefix(identity, "name:") {
		appName := identity[5:] // strip "name:" prefix
		var count int
		if err := pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM app_catalog_entries
			WHERE lower(name) = lower($1)
			  AND platform = $2
		`, appName, catalogPlatform).Scan(&count); err == nil && count > 0 {
			return "approve"
		}
	}

	return "defer"
}

// rolloverDeferredNewApps promotes deferred tenant_new_apps rows whose defer_until
// has passed to 'approve_no_patch'. Called at the top of each extraction batch so
// the rollover is applied lazily on the next active extraction cycle.
func rolloverDeferredNewApps(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) {
	tag, err := pool.Exec(ctx, `
		UPDATE tenant_new_apps
		SET decision   = 'approve_no_patch',
		    updated_at = now()
		WHERE decision = 'defer'
		  AND defer_until < now()
	`)
	if err != nil {
		logger.Warn("rolloverDeferredNewApps failed (non-fatal)", "err", err)
		return
	}
	if tag.RowsAffected() > 0 {
		logger.Info("rolled over deferred new-app rows", "count", tag.RowsAffected())
	}
}
