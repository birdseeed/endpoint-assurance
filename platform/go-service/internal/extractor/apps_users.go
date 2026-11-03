package extractor

// PAT-2075: per-user application scopes.
//
// Per-user installs (Windows HKU\<SID>\...\Uninstall, macOS ~/Applications)
// can only be read while their owner is logged in. Before PAT-2075 every
// device_apps row belonged to one device-wide scope, so once an agent sent
// per-user apps, a report taken after the user logged off would prune them
// under collection_status.apps = complete (PAT-2063) and close their
// installations and CVE findings. A logged-off user is not an uninstall.
//
// device_apps stays the device projection, one row per (device_id,
// identifier, version), and every reader keeps that shape. Migration 0180
// records who asserts each row:
//
//   - device_apps.machine_wide: the machine-wide scope (apps rows with no
//     user_account) lists it. Governed exactly as before PAT-2075 by
//     collection_status.apps and the safety valve in apps_authority.go,
//     which now count and prune machine-wide assertions only. A per-user row
//     of an absent user is never counted towards the valve.
//   - device_app_user_scopes: one row per (device_apps row, user) for each
//     user whose per-user inventory listed it, stamped only by that user's
//     own report.
//
// Pruning a scope removes that scope's assertion. The device_apps row itself
// is deleted only when no scope asserts it any more, so an app installed
// machine-wide and per-user, or by two users, is one row until the last
// installation is gone. CVE matching, ChangedProducts and the nightly sync
// read device_apps and so see a per-user app once per device, exactly like a
// machine-wide one, and never see a held per-user app as removed.
//
// A per-user scope row is pruned only when this report's
// collection_status.apps_users lists its user as "complete" (schema v3, with
// an apps array). A user missing from apps_users (logged off), or listed as
// "partial" or "unavailable", keeps every row. There is no safety valve and
// no time release for per-user scopes: nothing is pruned without an explicit
// complete, which is the stricter of the two PAT-2063 layers.
//
// The absence consumers that do not read device_apps are told about held
// per-user apps separately: the installation closure skips any installation
// whose identity a remaining per-user scope still holds
// (heldUserScopeInstallationSQL), and the software-policy lifecycle evaluates
// the report's apps plus the held per-user apps (loadHeldUserApps).

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// appsMaxUserAccountLen bounds device_app_user_scopes.user_account (0180),
// the same 128 characters as the browser extension user bound.
const appsMaxUserAccountLen = 128

// appsUserKey is the stored form of a user_account value: trimmed, never
// truncated. The app row and the apps_users entry go through the same
// function so they compare equal. valid is false for a value longer than
// appsMaxUserAccountLen. Truncating it, as the browser extension path does,
// would let two users that share a 128-character prefix collapse into one
// key, so one user's "complete" report could prune the other's rows. An
// over-long key is therefore never stored and never grants authority: its
// app rows are dropped (upsertApps counts them in
// appsPruneDecision.DroppedOverlong) and its apps_users entry is ignored,
// which leaves that user with no authority, the same as "partial".
func appsUserKey(s string) (key string, valid bool) {
	key = strings.TrimSpace(s)
	return key, utf8.RuneCountInString(key) <= appsMaxUserAccountLen
}

// appUserScopeSet is the (device_apps row, user) pairs this report listed,
// collected by upsertApps. Pruning and holding per-user scopes is decided by
// membership in this set, not by comparing last_seen with the transaction
// time, so a scope row stamped by a stepped or skewed clock is still judged
// by what this report actually listed.
type appUserScopeSet struct {
	AppIDs []int64
	Users  []string
}

func (s *appUserScopeSet) add(appID int64, user string) {
	s.AppIDs = append(s.AppIDs, appID)
	s.Users = append(s.Users, user)
}

// sqlArgs returns non-nil slices, so an empty set is an empty SQL array
// rather than NULL (a NULL array would make NOT IN match nothing).
func (s appUserScopeSet) sqlArgs() ([]int64, []string) {
	ids, users := s.AppIDs, s.Users
	if ids == nil {
		ids = []int64{}
	}
	if users == nil {
		users = []string{}
	}
	return ids, users
}

// notReconfirmedSQL is true for a device_app_user_scopes row (alias) that is
// not among the pairs passed as $idsArg::bigint[] and $usersArg::text[].
func notReconfirmedSQL(alias string, idsArg, usersArg int) string {
	return fmt.Sprintf(`(%[1]s.device_app_id, %[1]s.user_account) NOT IN (
			SELECT r.id, r.usr FROM unnest($%[2]d::bigint[], $%[3]d::text[]) AS r(id, usr))`, alias, idsArg, usersArg)
}

// appsUserCompleteSet returns the users whose per-user rows this report may
// prune, and whether the payload sent an apps_users block at all.
//
// Authority needs a schema v3 payload that carries an apps array. An entry
// with an empty user_account is ignored. Two entries for one user merge
// least authoritative wins: the user is complete only if every entry says
// complete.
func appsUserCompleteSet(p *payload) (complete []string, sent bool) {
	if p.CollectionStatus == nil || p.CollectionStatus.AppsUsers == nil {
		return nil, false
	}
	if p.SchemaVersion < 3 || !p.AppsPresent {
		return nil, true
	}
	verdict := map[string]bool{}
	var order []string
	for _, u := range p.CollectionStatus.AppsUsers {
		user, valid := appsUserKey(u.UserAccount)
		if user == "" || !valid {
			// Over-long: no authority for anyone (see appsUserKey).
			continue
		}
		status, known := normaliseCollectionStatus(u.CollectionStatus)
		isComplete := known && status == statusComplete
		prev, seen := verdict[user]
		if !seen {
			order = append(order, user)
			verdict[user] = isComplete
			continue
		}
		verdict[user] = prev && isComplete
	}
	for _, user := range order {
		if verdict[user] {
			complete = append(complete, user)
		}
	}
	return complete, true
}

// upsertAppUserScope records that user's per-user inventory listed the
// device_apps row appID in this report. last_seen is stamped from
// receivedAt (raw_payloads.received_at), not now() at extraction time, and
// GREATEST-ed against the existing value on conflict — same PAT-2102 fix as
// devices.last_seen and device_apps.last_seen, for the same reason: a
// backlogged or replayed extraction must not make this scope's evidence
// look fresher than it is. Note this column is documentational only — the
// comment on appUserScopeSet above records that pruning/holding decisions
// are made by report membership, never by comparing this timestamp.
func upsertAppUserScope(ctx context.Context, tx pgx.Tx, appID int64, deviceID, user, fingerprint string, receivedAt time.Time) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_app_user_scopes (device_app_id, device_id, user_account, identity_fingerprint, last_seen)
		VALUES ($1, $2::uuid, $3, $4, $5)
		ON CONFLICT (device_app_id, user_account) DO UPDATE SET
			identity_fingerprint = EXCLUDED.identity_fingerprint,
			last_seen            = GREATEST(device_app_user_scopes.last_seen, EXCLUDED.last_seen)
	`, appID, deviceID, user, fingerprint, receivedAt); err != nil {
		return fmt.Errorf("upsert per-user app scope for device %s: %w", deviceID, err)
	}
	return nil
}

// pruneCompleteUserScopes deletes the per-user scope rows of each user this
// report lists as complete that are not in seen, the pairs this report
// listed, then deletes any device_apps row left with no scope at all (not
// machine-wide, no user). Runs after the upsert loop.
func pruneCompleteUserScopes(ctx context.Context, tx pgx.Tx, deviceID string, users []string, seen appUserScopeSet, d *appsPruneDecision) error {
	if len(users) == 0 {
		return nil
	}
	ids, seenUsers := seen.sqlArgs()
	rows, err := tx.Query(ctx, `
		DELETE FROM device_app_user_scopes s
		WHERE s.device_id = $1::uuid
		  AND s.user_account = ANY($2::text[])
		  AND `+notReconfirmedSQL("s", 3, 4)+`
		RETURNING s.device_app_id
	`, deviceID, users, ids, seenUsers)
	if err != nil {
		return fmt.Errorf("prune per-user app scopes for device %s: %w", deviceID, err)
	}
	var released []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("scan pruned per-user app scope: %w", err)
		}
		released = append(released, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate pruned per-user app scopes: %w", err)
	}
	d.UserScopesPruned = len(released)
	if len(released) == 0 {
		return nil
	}
	tag, err := tx.Exec(ctx, `
		DELETE FROM device_apps d
		WHERE d.id = ANY($1::bigint[])
		  AND NOT d.machine_wide
		  AND NOT EXISTS (SELECT 1 FROM device_app_user_scopes s WHERE s.device_app_id = d.id)
	`, released)
	if err != nil {
		return fmt.Errorf("delete unasserted device_apps for device %s: %w", deviceID, err)
	}
	d.UserRowsDeleted = int(tag.RowsAffected())
	return nil
}

// heldUserScopeInstallationSQL is appended to the installation closure for
// the application absence scopes: an installation whose identity a
// remaining per-user scope still holds is not closed, whichever report left
// it out. si is the software_installations alias.
const heldUserScopeInstallationSQL = `
			  AND NOT EXISTS (
				SELECT 1 FROM device_app_user_scopes das
				WHERE das.device_id = si.device_id
				  AND das.identity_fingerprint = si.identity_fingerprint
			  )`

// loadHeldUserApps returns the device's apps that a per-user scope still
// holds although this report did not list them for that user: the apps of
// users who were logged off, or read only partially. The software-policy
// lifecycle adds them to the report's apps, so a held per-user app is
// neither "removed" (closing an unapproved-present finding) nor "missing"
// (opening a mandatory-missing one). seen is the pairs this report listed
// (upsertApps). Runs after upsertApps in the same transaction.
func loadHeldUserApps(ctx context.Context, tx pgx.Tx, deviceID string, seen appUserScopeSet) ([]appPart, error) {
	ids, users := seen.sqlArgs()
	rows, err := tx.Query(ctx, `
		SELECT d.name, COALESCE(d.version, ''), d.identifier, COALESCE(d.identifier_kind, ''),
		       COALESCE(d.team_id, ''), COALESCE(d.publisher, ''), COALESCE(d.signer, ''),
		       min(s.user_account)
		FROM device_apps d
		JOIN device_app_user_scopes s ON s.device_app_id = d.id
		WHERE d.device_id = $1::uuid
		  AND `+notReconfirmedSQL("s", 2, 3)+`
		GROUP BY d.id
		ORDER BY d.id
	`, deviceID, ids, users)
	if err != nil {
		return nil, fmt.Errorf("load held per-user apps for device %s: %w", deviceID, err)
	}
	defer rows.Close()
	var out []appPart
	for rows.Next() {
		var a appPart
		if err := rows.Scan(&a.Name, &a.Version, &a.Identifier, &a.IdentifierKind,
			&a.TeamID, &a.Publisher, &a.SignedBy, &a.UserAccount); err != nil {
			return nil, fmt.Errorf("scan held per-user app: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
