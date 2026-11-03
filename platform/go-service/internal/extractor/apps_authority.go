package extractor

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"patched.im/api/internal/metrics"
)

// PAT-2063: absence requires authority for applications too.
//
// upsertApps used to end every ingest by deleting every device_apps row the
// payload did not reconfirm. Neither agent can tell the server that its app
// scan fell short: the macOS collector sends "[]" or a shortened list when
// find or a bundle read fails (updater macos/lib/apps.sh, stubbed "[]" in
// patched-collect.sh), and the Windows scanner drops a registry hive or key
// it cannot read and ships the rest (InstalledAppScanner.cs). The missing
// apps then vanished, their CVE findings were pruned by the re-match their
// removal queued, and the all_software scope closed their installations.
//
// Two layers now decide whether an ingest may treat an unreported app as
// gone:
//
//  1. collection_status.apps, an optional explicit signal. "complete" on a
//     schema v3 payload prunes unconditionally, so a genuine mass uninstall
//     or rebuild still clears. "partial" and "unavailable" upsert what was
//     sent and prune nothing. A status that contradicts the array
//     ("unavailable" with apps listed, or "complete" with no apps array)
//     withholds authority without rejecting the inventory, the PAT-2055
//     pattern.
//  2. With no signal (every agent released before PAT-2063), a safety valve.
//     The report is not trusted to prove removals when it reconfirms none of
//     the device's current applications, or when more than
//     appsPruneValveMinRemoved identifiers AND more than
//     appsPruneValveMaxFraction of them would disappear at once.
//
// A withheld report still upserts every app it sent; only the prune and the
// application absence scopes are held. Everything happens in the ingest
// transaction, so readers never see a half-updated inventory.
//
// A hold must not become permanent. Held rows keep their old last_seen, so
// every later no-signal report counts the same vanished identifiers and
// holds again, and only an explicit "complete" would ever release it. Two
// narrower prunes therefore still run while a report is held:
//
//   - Superseded versions always prune (pruneSupersededApps). A stale row
//     whose identifier this report reconfirmed at another version is not an
//     absence claim: the app is present, just not at that version. Without
//     this, a held device kept every pre-upgrade row, and the nightly CVE
//     sync re-raised the old version's findings indefinitely.
//   - Time release, for the ratio case only (pruneLongUnseenApps). When the
//     valve holds on the size of the drop but the report does reconfirm some
//     of the device's apps, identifiers not seen at any version for
//     appsPruneValveReleaseAfter are pruned. The recently seen rest of the
//     vanished set stays held. A report that reconfirms nothing gets no time
//     release: an empty or fully skipped list never deletes anything, and
//     only "complete" clears such a device.
//
// Both queue CVE removals like the normal prune. Neither grants the
// application absence scopes for that ingest: the report is still not
// authoritative about what it left out.
//
// PAT-2075: everything above governs the machine-wide scope only, the apps
// rows sent with no user_account (every row an agent before PAT-2075 sends).
// The counts, the valve and both release rules read and release machine-wide
// assertions (device_apps.machine_wide); "reconfirmed" means listed by this
// report's machine-wide rows (the ids upsertApps collected). Releasing a
// machine-wide assertion deletes the device_apps row only when no per-user
// scope still holds it; otherwise the row stays, owned by its users. Per-user
// scopes have their own authority, collection_status.apps_users, and no
// valve: see apps_users.go.
//
// Windows caveat: an MSI identifier is the ProductCode GUID, which changes
// on a major upgrade. There an upgrade reads as one identifier removed and
// another added rather than as a version change, so the old identifier
// counts towards the valve and is not caught by the superseded-version
// prune. The time release bounds how long such a row can linger.

// appsPruneValveMinRemoved and appsPruneValveMaxFraction set the no-signal
// safety valve. Both must be exceeded for the valve to hold the prune.
//
// The absolute floor (more than 5 identifiers) keeps ordinary churn working:
// one hourly or daily report rarely sees more than a handful of genuine
// uninstalls, so removing 1 of 20 apps, or 5 of 8, still prunes normally.
//
// The fraction (more than half of the device's current identifiers) is the
// failure shape the valve exists to catch: a collector that dies part way,
// loses a registry hive or loses access to a directory drops a large share
// of the list in one go, while real users do not uninstall most of their
// software between two reports. Version upgrades do not count towards
// either threshold, because an identifier still reported at a new version
// is present, not removed; that keeps a macOS or Office upgrade that bumps
// dozens of bundle versions from tripping the valve.
//
// The valve is a backstop, not authority. A partial scan that loses less
// than half the list still prunes on an agent that sends no signal, which
// is why the agents are asked to send collection_status.apps.
//
// appsPruneValveReleaseAfter is how long an identifier held by the valve's
// ratio test may go unseen at any version before it is pruned anyway. A
// week covers a collector that fails for a few consecutive days, while
// bounding how long a genuinely removed app (or a Windows MSI ProductCode
// replaced by a major upgrade) can keep a CVE finding open.
const (
	appsPruneValveMinRemoved   = 5
	appsPruneValveMaxFraction  = 0.5
	appsPruneValveReleaseAfter = 7 * 24 * time.Hour
)

// appsSignal is the explicit collection_status.apps verdict, resolved.
type appsSignal int

const (
	// appsSignalNone: no usable explicit signal; the safety valve decides.
	appsSignalNone appsSignal = iota
	// appsSignalComplete: the agent says the array is the whole inventory.
	appsSignalComplete
	// appsSignalIncomplete: partial, unavailable or inconsistent. Upsert
	// what was sent, prune nothing, withhold application absence scopes.
	appsSignalIncomplete
)

// resolveAppsSignal reads collection_status.apps against the apps array. The
// returned reason is the AppsPruneWithheldTotal label for an incomplete
// signal, and a log detail for an inconsistent one.
func resolveAppsSignal(p *payload) (signal appsSignal, reason, detail string) {
	raw := ""
	if p.CollectionStatus != nil {
		raw = p.CollectionStatus.Apps
	}
	if raw == "" {
		return appsSignalNone, "", ""
	}
	status, known := normaliseCollectionStatus(raw)
	if !known {
		// ValidatePayload rejects an unknown value with a 400 before
		// storage; this is defence in depth for rows stored earlier.
		return appsSignalIncomplete, "inconsistent", "unrecognised_status"
	}
	switch status {
	case statusComplete:
		if !p.AppsPresent {
			return appsSignalIncomplete, "inconsistent", "complete_without_apps_array"
		}
		if p.SchemaVersion < 3 {
			// Inventory authority is a schema v3 contract (see
			// clearLegacyInventoryAuthority). A legacy payload claiming
			// complete gets the same treatment as one that says nothing.
			return appsSignalNone, "", ""
		}
		return appsSignalComplete, "", ""
	case statusPartial:
		return appsSignalIncomplete, "partial", ""
	default: // statusUnavailable
		// PAT-2075: collection_status.apps speaks for the machine-wide
		// scope, so only machine-wide rows contradict "unavailable".
		// Per-user rows sent beside it are governed by apps_users.
		if hasMachineWideApps(p.Apps) {
			return appsSignalIncomplete, "inconsistent", "unavailable_with_apps_listed"
		}
		return appsSignalIncomplete, "unavailable", ""
	}
}

// hasMachineWideApps reports whether any app row carries no user_account.
func hasMachineWideApps(apps []appPart) bool {
	for _, a := range apps {
		if user, _ := appsUserKey(a.UserAccount); user == "" {
			return true
		}
	}
	return false
}

// appsPruneDecision is what upsertApps did about unreported rows.
type appsPruneDecision struct {
	Pruned bool
	// Reason is set when Pruned is false and something was held back.
	Reason string
	// Current and Removed are distinct identifiers before this ingest and
	// the ones this report no longer lists at any version.
	Current, Removed int
	// Superseded counts old-version rows released while held because their
	// identifier was reconfirmed at another version. Released counts
	// identifiers released while held because they had gone unseen for
	// appsPruneValveReleaseAfter. Both are zero when Pruned is true.
	// "Released" means the machine-wide assertion was dropped; the row is
	// deleted unless a per-user scope still holds it (PAT-2075).
	Superseded, Released int
	// UserScopesPruned counts per-user scope rows pruned for users this
	// report listed as complete, and UserRowsDeleted the device_apps rows
	// that left with no scope at all (PAT-2075). Independent of Pruned.
	UserScopesPruned, UserRowsDeleted int
	// DroppedOverlong counts app rows not stored because their
	// user_account exceeds appsMaxUserAccountLen (see appsUserKey).
	DroppedOverlong int
	// PAT-2075 legacy user-located rows (apps_legacy_user.go). LegacyHeld
	// is the ids of the rows this report had no authority over; they are
	// excluded from every machine-wide prune. LegacyRehomed counts rows
	// handed to a user scope on positive evidence, LegacyOwnerPruned rows
	// released by their owner's complete report, and LegacyRowsDeleted the
	// device_apps rows either of those deleted.
	LegacyHeld                                          []int64
	LegacyRehomed, LegacyOwnerPruned, LegacyRowsDeleted int
	// UserScopesSeen is the (row, user) pairs this report listed. The
	// software-policy lifecycle holds every other per-user scope row.
	UserScopesSeen appUserScopeSet
}

// DeletedWhileHeld reports whether a held report still released machine-wide
// rows through the superseded-version or time-release prunes.
func (d appsPruneDecision) DeletedWhileHeld() bool {
	return d.Superseded > 0 || d.Released > 0
}

// MayHaveRemovedRows reports whether this ingest may have deleted
// device_apps rows, so the CVE re-match must consider removals. Held rows
// stay in device_apps, so the before/after diff cannot report them removed.
func (d appsPruneDecision) MayHaveRemovedRows() bool {
	return d.Pruned || d.DeletedWhileHeld() || d.UserRowsDeleted > 0 || d.LegacyRowsDeleted > 0
}

// countAppIdentifiers returns the number of distinct identifiers the
// machine-wide scope currently asserts for the device. Called before the
// upsert loop.
func countAppIdentifiers(ctx context.Context, tx pgx.Tx, deviceID string) (int, error) {
	var n int
	if err := tx.QueryRow(ctx,
		`SELECT count(DISTINCT identifier) FROM device_apps WHERE device_id = $1 AND machine_wide`,
		deviceID,
	).Scan(&n); err != nil {
		return 0, fmt.Errorf("count device_apps for device %s: %w", deviceID, err)
	}
	return n, nil
}

// countVanishedIdentifiers returns the distinct machine-wide identifiers
// with no row among machineIDs, the rows this report's machine-wide entries
// upserted, and the ones with at least one. Must run after the upsert loop.
// machineIDs must be non-nil: a NULL array would match nothing.
func countVanishedIdentifiers(ctx context.Context, tx pgx.Tx, deviceID string, machineIDs []int64) (vanished, reconfirmed int, err error) {
	if err := tx.QueryRow(ctx, `
		SELECT
			count(DISTINCT identifier) FILTER (WHERE NOT fresh),
			count(DISTINCT identifier) FILTER (WHERE fresh)
		FROM (
			SELECT identifier, bool_or(id = ANY($2::bigint[])) AS fresh
			FROM device_apps
			WHERE device_id = $1 AND machine_wide
			GROUP BY identifier
		) per_identifier
	`, deviceID, machineIDs).Scan(&vanished, &reconfirmed); err != nil {
		return 0, 0, fmt.Errorf("count vanished device_apps for device %s: %w", deviceID, err)
	}
	return vanished, reconfirmed, nil
}

// appsValveHolds reports whether the no-signal safety valve withholds the
// prune. current is the distinct identifier count before the ingest.
func appsValveHolds(current, vanished, reconfirmed int) bool {
	if vanished == 0 {
		return false
	}
	// A report that reconfirms nothing the device had (an empty list, or
	// one whose every entry was skipped) never wipes a device.
	if reconfirmed == 0 && current > 0 {
		return true
	}
	return vanished > appsPruneValveMinRemoved &&
		float64(vanished) > appsPruneValveMaxFraction*float64(current)
}

// releaseMachineRows drops the machine-wide assertion from the device's
// machine-wide rows that this report's machine-wide entries did not upsert
// (not in machineIDs), that are not held legacy user-located rows (protect,
// see apps_legacy_user.go) and that match filter, an extra SQL predicate over
// device_apps columns ($1 is the device, $2 machineIDs, $3 protect, extra
// args from $4). protect must be non-nil: a NULL array would match nothing.
// A row no per-user scope holds is deleted; one a per-user scope still
// holds stays, with machine_wide cleared. It returns the rows released and
// the distinct identifiers among them.
func releaseMachineRows(ctx context.Context, tx pgx.Tx, deviceID string, machineIDs, protect []int64, filter string, extra ...any) (rowsReleased, identifiers int, err error) {
	if protect == nil {
		protect = []int64{}
	}
	args := append([]any{deviceID, machineIDs, protect}, extra...)
	if err := tx.QueryRow(ctx, `
		WITH stale AS (
			SELECT id, identifier FROM device_apps
			WHERE device_id = $1 AND machine_wide
			  AND NOT (id = ANY($2::bigint[]))
			  AND NOT (id = ANY($3::bigint[]))`+filter+`
		), demoted AS (
			UPDATE device_apps d SET machine_wide = FALSE
			FROM stale
			WHERE d.id = stale.id
			  AND EXISTS (SELECT 1 FROM device_app_user_scopes s WHERE s.device_app_id = d.id)
			RETURNING d.id
		), deleted AS (
			DELETE FROM device_apps d
			USING stale
			WHERE d.id = stale.id
			  AND NOT EXISTS (SELECT 1 FROM device_app_user_scopes s WHERE s.device_app_id = d.id)
			RETURNING d.id
		)
		SELECT (SELECT count(*) FROM demoted) + (SELECT count(*) FROM deleted),
		       (SELECT count(DISTINCT identifier) FROM stale)
	`, args...).Scan(&rowsReleased, &identifiers); err != nil {
		return 0, 0, err
	}
	return rowsReleased, identifiers, nil
}

// pruneSupersededApps releases stale machine-wide rows whose identifier this
// report's machine-wide entries listed at another version, i.e. versions
// replaced by the one just reported.
func pruneSupersededApps(ctx context.Context, tx pgx.Tx, deviceID string, machineIDs []int64, d *appsPruneDecision) error {
	n, _, err := releaseMachineRows(ctx, tx, deviceID, machineIDs, d.LegacyHeld, `
			  AND identifier IN (
				SELECT identifier FROM device_apps
				WHERE device_id = $1 AND id = ANY($2::bigint[])
			  )`)
	if err != nil {
		return fmt.Errorf("prune superseded device_apps for device %s: %w", deviceID, err)
	}
	d.Superseded = n
	return nil
}

// pruneLongUnseenApps releases every machine-wide row of an identifier whose
// newest machine-wide last_seen, across all its versions, is older than
// appsPruneValveReleaseAfter. The caller runs it only when the valve holds
// on the ratio test with at least one identifier reconfirmed.
//
// receivedAt (this report's raw_payloads.received_at) anchors the release
// window, not now() (PAT-2102 follow-up). device_apps.last_seen is itself
// stamped from received_at, not extraction wall-clock time, so comparing it
// against now() re-introduces the same bug one level up: a backlogged
// report extracted late would compare old evidence against today and
// release identifiers that, relative to the evidence, were seen well within
// the window — an absence decision made on an extraction-lag artefact
// rather than the evidence itself (Hard Constraint: "absence requires
// authority"). Anchoring to receivedAt keeps the window meaningful no
// matter when extraction actually runs.
func pruneLongUnseenApps(ctx context.Context, tx pgx.Tx, deviceID string, receivedAt time.Time, machineIDs []int64, d *appsPruneDecision) error {
	_, released, err := releaseMachineRows(ctx, tx, deviceID, machineIDs, d.LegacyHeld, `
			  AND identifier IN (
				SELECT identifier FROM device_apps
				WHERE device_id = $1 AND machine_wide
				GROUP BY identifier
				HAVING max(last_seen) < $4::timestamptz - make_interval(secs => $5)
			  )`, receivedAt, appsPruneValveReleaseAfter.Seconds())
	if err != nil {
		return fmt.Errorf("time-release held device_apps for device %s: %w", deviceID, err)
	}
	d.Released = released
	return nil
}

// recordAppsWithheld logs and counts one withheld prune. A held report whose
// vanished identifiers were all time-released holds nothing back, so it has
// no Reason and is logged at info level without touching the metric.
func recordAppsWithheld(logger *slog.Logger, deviceID string, d appsPruneDecision, detail string) {
	if d.Reason == "" {
		if logger != nil && d.DeletedWhileHeld() {
			logger.Info("apps: held report pruned superseded or long-unseen apps only",
				"device_id", deviceID, "current_identifiers", d.Current,
				"superseded_rows", d.Superseded, "released_identifiers", d.Released)
		}
		return
	}
	metrics.AppsPruneWithheldTotal.WithLabelValues(d.Reason).Inc()
	if logger == nil {
		return
	}
	attrs := []any{"device_id", deviceID, "reason", d.Reason,
		"current_identifiers", d.Current, "unreported_identifiers", d.Removed}
	if d.Superseded > 0 {
		attrs = append(attrs, "superseded_rows", d.Superseded)
	}
	if d.Released > 0 {
		attrs = append(attrs, "released_identifiers", d.Released)
	}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	switch d.Reason {
	case "partial", "unavailable":
		logger.Info("apps: collection incomplete; unreported apps kept", attrs...)
	default:
		logger.Warn("apps: report not trusted to prove removals; unreported apps kept", attrs...)
	}
}
