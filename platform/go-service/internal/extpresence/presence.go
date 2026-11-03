// Package extpresence decides whether a device_browser_extensions row still
// counts as present (PAT-2055).
//
// device_browser_extensions never deletes: every ingest that reports an
// extension refreshes last_seen, and one that does not simply leaves the row
// ageing. "Not seen recently" is therefore not evidence of removal. A report
// that left out a profile it could not read, or a user crowded out by a
// collector cap, looks identical to one where the extension was uninstalled.
//
// The browser_extensions_status block (migration 0177) supplies the missing
// authority. A reader may conclude an extension is gone only when a complete
// (or not_present), uncapped report arrived strictly after the extension's
// last_seen, either for the whole device or for that extension's own user
// and browser. Strictly after, because the report that listed the extension
// stamped its last_seen and its own last_complete_at with the same now().
//
// A device that has never sent the block (an agent that predates PAT-2055)
// keeps whatever rule the caller used before, exactly.
//
// Safari rows (PAT-2064) are a deliberate carve-out from the device-level
// branch of AbsenceAuthorisedSQL: browser_extensions_status has no Safari
// vocabulary at all. They have their own branch instead (PAT-2067), fed by
// collection_status.safari_extensions. See that function's doc comment.
package extpresence

import "fmt"

// AbsenceAuthorisedSQL returns a SQL boolean expression: true when an
// authoritative report proves the device_browser_extensions row aliased dbe
// is no longer on its device.
//
// The device-level branch (browser_extension_device_state) is keyed on
// device_id alone, with no browser or user column, because it speaks for the
// whole device: a report complete (or not_present), uncapped, for every
// user's chrome/edge/firefox. browser_extensions_status only ever enumerates
// chrome, edge and firefox (browserExtensionStatusBrowsers) — Safari has no
// place in that completeness claim at all. Before PAT-2064, that was
// harmless because Safari rows never existed here; now that Safari rows are
// stored under the SafariSystemSentinel user_account, a device-wide
// "complete" report that never looked at Safari would otherwise still count
// as authority to mark a still-installed Safari extension gone — an
// incomplete report closing a finding it never touched, which is exactly
// what "absence requires authority" forbids. The dbe.browser <> 'safari'
// guard withholds this branch for Safari rows.
//
// The per-pair branch (browser_extension_collection_state) already excludes
// Safari on its own: bes_p.browser is only ever chrome, edge or firefox
// (browserExtensionPairStates only walks browserExtensionStatusBrowsers), so
// it can never match a Safari row's bes_p.browser = %[1]s.browser predicate.
//
// The Safari branch (PAT-2067) is the only way a Safari row becomes absent:
// browser_extension_device_state.safari_complete_at, set only by a report
// whose collection_status.safari_extensions was "complete" (schema v3, with
// a browser_extensions array, uncapped), must be strictly after the row's
// last_seen. "partial" and "unavailable" never set it, and a device that has
// never sent the signal has it NULL, so its Safari rows are never absent.
// The column is per device, not per user: the agent walks Safari app
// extensions once for the whole machine. It never authorises a chrome, edge
// or firefox row, and chrome/edge/firefox completeness never authorises a
// Safari row.
func AbsenceAuthorisedSQL(dbe string) string {
	return fmt.Sprintf(`((%[1]s.browser <> 'safari' AND EXISTS (SELECT 1 FROM browser_extension_device_state bes_d
		WHERE bes_d.device_id = %[1]s.device_id AND bes_d.last_complete_at > %[1]s.last_seen))
	OR (%[1]s.browser = 'safari' AND EXISTS (SELECT 1 FROM browser_extension_device_state bes_s
		WHERE bes_s.device_id = %[1]s.device_id AND bes_s.safari_complete_at > %[1]s.last_seen))
	OR EXISTS (SELECT 1 FROM browser_extension_collection_state bes_p
		WHERE bes_p.device_id = %[1]s.device_id
		  AND bes_p.user_account = %[1]s.user_account
		  AND bes_p.browser = %[1]s.browser
		  AND bes_p.last_complete_at > %[1]s.last_seen))`, dbe)
}

// StatusKnownSQL returns a SQL boolean expression: true when the device of
// the row aliased dbe has sent a browser_extensions_status block at least once.
func StatusKnownSQL(dbe string) string {
	return fmt.Sprintf(`EXISTS (SELECT 1 FROM browser_extension_device_state bes_k
		WHERE bes_k.device_id = %s.device_id)`, dbe)
}

// PresentSQL returns a SQL boolean expression that is true while the row
// aliased dbe counts as present. legacyPresent is the caller's pre-PAT-2055
// presence expression; it alone decides for a device that has never sent the
// status block. For any other device, only an authoritative report after
// last_seen makes the row absent: a partial, capped or failed report never
// does, however old the row.
func PresentSQL(dbe, legacyPresent string) string {
	return fmt.Sprintf(`(CASE WHEN %s THEN NOT %s ELSE (%s) END)`,
		StatusKnownSQL(dbe), AbsenceAuthorisedSQL(dbe), legacyPresent)
}
