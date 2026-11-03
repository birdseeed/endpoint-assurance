package extractor

// PAT-2075: legacy user-located machine-scope rows.
//
// A macOS agent before PAT-2075 walked /Users/*/Applications as part of its
// machine-wide scan, so an app in a user's ~/Applications is stored as an
// ordinary machine_wide device_apps row whose path lies in that user's home.
// The PAT-2075 agent reports the same app under a per-user scope instead and
// its collection_status.apps = complete covers the machine roots only. Left
// alone, the first complete machine-wide report from the new agent would
// prune every such row whose user was logged off, partially read or not
// resolved: an installed app would vanish and its CVE finding, installation
// and policy finding would close on a report with no authority over that
// home (Hard Constraint: absence requires authority).
//
// A report that carries collection_status.apps_users (any agent that scopes
// users itself; the key may be an empty array) therefore has no machine-wide
// authority over a machine_wide row whose stored path is
// /Users/<segment>/... with <segment> other than Shared. A report without
// the key comes from an agent whose complete does cover /Users/*/Applications
// and prunes exactly as before.
//
// Such a row is resolved only by:
//
//   - positive evidence (re-home): this report lists the same identifier
//     under a user scope, either at the row's stored path or for a user whose
//     apps_users home equals the row's home directory. The same version is
//     the same device_apps row, which loses its machine-wide assertion and
//     keeps the user's scope. Another version at the row's stored path is the
//     same installation upgraded: the old row is released and the new row
//     inherits its first_seen.
//   - the owner's authority: apps_users lists a user as complete with a home
//     equal to the row's home directory, and that user did not list the app.
//     The machine-wide assertion is released, like a per-user prune.
//
// Otherwise the row is held, with no timer: the full prune, the
// superseded-version prune and the time release all skip it, the installation
// closure and the software-policy lifecycle treat it as present, its usage
// evidence stops counting as complete, and the run's coverage counts it in
// apps_legacy_user_held.
//
// Ownership comes from data, never from a path basename: an account name and
// its home directory name can differ. A home is honoured only when it is
// exactly /Users/<segment> (no trailing slash, no "." or ".." segment, not
// /Users/Shared), claimed by one user, and that user claims no other home.
// The row's home is compared for equality, never as a prefix.
//
// Windows never has such rows: its agents never reported per-user hives
// machine-wide and send no path. The rule is keyed on the stored path shape,
// not on the platform.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const legacyUsersRoot = "/Users/"

// legacyUserHome reports whether home is exactly /Users/<segment> for a
// segment that can be a user's home directory. Nothing is normalised: a
// trailing slash, a relative path or a "." or ".." segment is not a home.
func legacyUserHome(home string) bool {
	if !strings.HasPrefix(home, legacyUsersRoot) {
		return false
	}
	seg := home[len(legacyUsersRoot):]
	return seg != "" && seg != "." && seg != ".." && seg != "Shared" &&
		!strings.ContainsAny(seg, "/\x00")
}

// legacyRowHome returns the home directory a stored app path lies in, or
// false when the path is not inside a user's home. /Users/Shared is nobody's
// home, and an entry directly under /Users is not inside one.
func legacyRowHome(path string) (string, bool) {
	if !strings.HasPrefix(path, legacyUsersRoot) {
		return "", false
	}
	rest := path[len(legacyUsersRoot):]
	i := strings.IndexByte(rest, '/')
	if i <= 0 || i == len(rest)-1 {
		return "", false
	}
	home := legacyUsersRoot + rest[:i]
	return home, legacyUserHome(home)
}

// legacyUserHold is what this report's apps_users block says about homes.
type legacyUserHold struct {
	// Active: the report carries apps_users, so its machine-wide scope does
	// not cover user homes.
	Active bool
	// homeOf maps a user to its one uncontested home, whatever the user's
	// collection status. It is evidence about where a listed app lives.
	homeOf map[string]string
	// owner maps a home to the user with authority over it: homeOf, and the
	// user is complete in this report.
	owner map[string]string
}

// resolveLegacyUserHold reads the homes in collection_status.apps_users.
// completeUsers is appsUserCompleteSet's result, so an owner already needs a
// schema v3 payload with an apps array and every entry of the user complete.
func resolveLegacyUserHold(p *payload, completeUsers []string) legacyUserHold {
	var h legacyUserHold
	if p.CollectionStatus == nil || p.CollectionStatus.AppsUsers == nil {
		return h
	}
	h.Active = true
	h.homeOf = map[string]string{}
	h.owner = map[string]string{}
	claimed := map[string]map[string]bool{}   // user -> every home value sent
	claimants := map[string]map[string]bool{} // home -> users sending it
	for _, u := range p.CollectionStatus.AppsUsers {
		user, valid := appsUserKey(u.UserAccount)
		if user == "" || !valid || u.Home == nil {
			continue
		}
		if claimed[user] == nil {
			claimed[user] = map[string]bool{}
		}
		claimed[user][*u.Home] = true
		if claimants[*u.Home] == nil {
			claimants[*u.Home] = map[string]bool{}
		}
		claimants[*u.Home][user] = true
	}
	complete := map[string]bool{}
	for _, user := range completeUsers {
		complete[user] = true
	}
	for user, homes := range claimed {
		if len(homes) != 1 {
			continue
		}
		for home := range homes {
			if !legacyUserHome(home) || len(claimants[home]) != 1 {
				continue
			}
			h.homeOf[user] = home
			if complete[user] {
				h.owner[home] = user
			}
		}
	}
	return h
}

// legacyUserRow is one stored machine-wide row located in a user's home, as
// it stood before this report's upserts.
type legacyUserRow struct {
	id         int64
	identifier string
	path, home string
	firstSeen  time.Time
}

// legacyUserSighting is one per-user app row of this report.
type legacyUserSighting struct {
	appID      int64
	user, path string
}

// loadLegacyUserRows snapshots the device's legacy user-located rows. It must
// run before the upsert loop: an upsert of the same identifier and version
// overwrites the stored path, which is the only record of where the legacy
// row lives.
func loadLegacyUserRows(ctx context.Context, tx pgx.Tx, deviceID string) ([]legacyUserRow, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, identifier, path, first_seen FROM device_apps
		WHERE device_id = $1::uuid AND machine_wide AND left(path, 7) = '/Users/'
		ORDER BY id`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("load legacy user-located apps for device %s: %w", deviceID, err)
	}
	defer rows.Close()
	var out []legacyUserRow
	for rows.Next() {
		var r legacyUserRow
		if err := rows.Scan(&r.id, &r.identifier, &r.path, &r.firstSeen); err != nil {
			return nil, fmt.Errorf("scan legacy user-located app: %w", err)
		}
		home, ok := legacyRowHome(r.path)
		if !ok {
			continue
		}
		r.home = home
		out = append(out, r)
	}
	return out, rows.Err()
}

// releaseLegacyUserRow drops one row's machine-wide assertion: the row is
// deleted unless a per-user scope still holds it.
func releaseLegacyUserRow(ctx context.Context, tx pgx.Tx, id int64) (deleted bool, err error) {
	var n int
	if err := tx.QueryRow(ctx, `
		WITH demoted AS (
			UPDATE device_apps d SET machine_wide = FALSE
			WHERE d.id = $1
			  AND EXISTS (SELECT 1 FROM device_app_user_scopes s WHERE s.device_app_id = d.id)
			RETURNING d.id
		), deleted AS (
			DELETE FROM device_apps d
			WHERE d.id = $1
			  AND NOT EXISTS (SELECT 1 FROM device_app_user_scopes s WHERE s.device_app_id = d.id)
			RETURNING d.id
		)
		SELECT count(*) FROM deleted
	`, id).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// resolveLegacyUserRows decides each legacy user-located row this report did
// not reconfirm machine-wide: re-homed, released by its owner, or held. It
// runs after the upsert loop and before every machine-wide prune, and records
// the outcome on d. The held ids must be excluded from those prunes.
func resolveLegacyUserRows(ctx context.Context, tx pgx.Tx, deviceID string, hold legacyUserHold, legacy []legacyUserRow, sightings map[string][]legacyUserSighting, machineIDs []int64, d *appsPruneDecision) error {
	// Non-nil, so the SQL array is empty rather than NULL.
	d.LegacyHeld = []int64{}
	if !hold.Active || len(legacy) == 0 {
		return nil
	}
	machine := make(map[int64]bool, len(machineIDs))
	for _, id := range machineIDs {
		machine[id] = true
	}
	for _, row := range legacy {
		if machine[row.id] {
			// Listed machine-wide by this report: an ordinary row again.
			continue
		}
		var sameRow, sameInstall bool
		var successor int64
		for _, s := range sightings[row.identifier] {
			inPlace := s.path == row.path
			if s.appID == row.id {
				sameRow = true
				if inPlace || hold.homeOf[s.user] == row.home {
					sameInstall = true
				}
			} else if inPlace {
				successor = s.appID
			}
		}
		switch {
		case sameInstall:
			if _, err := tx.Exec(ctx, `UPDATE device_apps SET machine_wide = FALSE WHERE id = $1`, row.id); err != nil {
				return fmt.Errorf("re-home legacy app for device %s: %w", deviceID, err)
			}
			d.LegacyRehomed++
			continue
		case successor != 0:
			// The same installation at a new version. The new row
			// carries the history; the old version is not installed.
			if _, err := tx.Exec(ctx, `UPDATE device_apps SET first_seen = LEAST(first_seen, $2) WHERE id = $1`,
				successor, row.firstSeen); err != nil {
				return fmt.Errorf("carry legacy app history for device %s: %w", deviceID, err)
			}
			deleted, err := releaseLegacyUserRow(ctx, tx, row.id)
			if err != nil {
				return fmt.Errorf("release superseded legacy app for device %s: %w", deviceID, err)
			}
			if deleted {
				d.LegacyRowsDeleted++
			}
			d.LegacyRehomed++
			continue
		}
		if _, owned := hold.owner[row.home]; owned {
			// The owner was read in full and did not list it.
			deleted, err := releaseLegacyUserRow(ctx, tx, row.id)
			if err != nil {
				return fmt.Errorf("owner prune of legacy app for device %s: %w", deviceID, err)
			}
			if deleted {
				d.LegacyRowsDeleted++
			}
			d.LegacyOwnerPruned++
			continue
		}
		if sameRow {
			// Another user listed the same identifier and version, and
			// the upsert put that user's path on the shared row. That is
			// not evidence about this home: restore the stored path so
			// the row stays resolvable by its real owner.
			if _, err := tx.Exec(ctx, `UPDATE device_apps SET path = $2 WHERE id = $1`, row.id, row.path); err != nil {
				return fmt.Errorf("restore legacy app path for device %s: %w", deviceID, err)
			}
		}
		d.LegacyHeld = append(d.LegacyHeld, row.id)
	}
	if len(d.LegacyHeld) == 0 {
		return nil
	}
	// A held row is not refreshed by this report, so its usage evidence is
	// not current: it must not support an unused-software conclusion.
	if _, err := tx.Exec(ctx, `
		UPDATE device_apps SET usage_evidence_complete = FALSE
		WHERE id = ANY($1::bigint[]) AND usage_evidence_complete IS TRUE`, d.LegacyHeld); err != nil {
		return fmt.Errorf("withhold usage authority of held legacy apps for device %s: %w", deviceID, err)
	}
	return nil
}

// loadHeldLegacyApps returns the held legacy user-located rows as apps, for
// the absence consumers that do not read device_apps: the software-policy
// lifecycle evaluates them as present and the installation closure skips
// their identities.
func loadHeldLegacyApps(ctx context.Context, tx pgx.Tx, ids []int64) ([]appPart, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT name, COALESCE(version, ''), identifier, COALESCE(identifier_kind, ''),
		       COALESCE(team_id, ''), COALESCE(publisher, ''), COALESCE(signer, ''), COALESCE(path, '')
		FROM device_apps WHERE id = ANY($1::bigint[]) ORDER BY id`, ids)
	if err != nil {
		return nil, fmt.Errorf("load held legacy user-located apps: %w", err)
	}
	defer rows.Close()
	var out []appPart
	for rows.Next() {
		var a appPart
		if err := rows.Scan(&a.Name, &a.Version, &a.Identifier, &a.IdentifierKind,
			&a.TeamID, &a.Publisher, &a.SignedBy, &a.Path); err != nil {
			return nil, fmt.Errorf("scan held legacy user-located app: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// heldLegacyInstallationSQL is appended to the installation closure for the
// application absence scopes: an installation whose identity a held legacy
// row carries is not closed. $6 is heldLegacyInstallationValues.
const heldLegacyInstallationSQL = `
			  AND NOT (si.identity_value_normalized = ANY($6::text[]))`

// heldLegacyInstallationValues is the normalised identity values of the held
// rows, matched against software_installations.identity_value_normalized.
func heldLegacyInstallationValues(apps []appPart) []string {
	out := []string{}
	for _, a := range apps {
		out = append(out, normalizedIdentityValue(a.Identifier))
	}
	return out
}
