package report

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// derefOrEmpty returns "" for a nil pointer, otherwise the pointed-to
// string. Used for devices.collection_status->>'local_admins' (PAT-2215),
// where NULL means the key was never written, not that it was written empty.
func derefOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// LocalAdminDevice holds privileged-access info for one device.
type LocalAdminDevice struct {
	// DeviceID (PAT-2215) is the device's UUID, added so a consumer (the
	// portal's /v1/portal/local-admins) can link a row straight to that
	// device's own Compliance tab. Unused by the PDF renderer, which never
	// needed a per-device link.
	DeviceID   string
	Hostname   string
	OS         string
	AdminCount int
	// Risk: "compliant" (≤2), "at-risk" (3-4), "critical" (≥5)
	Risk string
	// AdminNames is the local_admin_accounts roster for this device (PAT-1974),
	// sorted by name. Empty whenever no roster has ever been ingested for the
	// device — an older agent (pre updater PR #631), or a device whose most
	// recent local_admins collection was "unavailable"/"partial" with nothing
	// stored yet. Never treated as "this device has no admins": AdminCount,
	// sourced from the separate compliance_signals scalar, is the authority
	// for that; this field is display evidence only.
	AdminNames []string
	// AdminAccounts (PAT-2215) is the same local_admin_accounts roster as
	// AdminNames, in the same order, but carrying each entry's own
	// principal_type/builtin/sid/account_state rather than just its name —
	// what /v1/portal/local-admins needs to label a Windows directory group
	// as a group and an unresolved SID as unresolved (PAT-1974's own
	// principal_type rule), rather than guessing from the name string. Built
	// from the identical LATERAL join AdminNames already reads, so the two
	// never disagree.
	AdminAccounts []LocalAdminAccount
	// LocalAdminsCollectionStatus (PAT-2215) is devices.collection_status's
	// own "local_admins" key exactly as stored (PAT-1974's own
	// upsertCollectionStatus): "complete", "partial", "unavailable", or ""
	// when the key was never written (an agent predating PAT-1974, or one
	// that has not reported since). This is the roster's own read state —
	// distinct from ReportedAdminCount, which comes from the separate
	// local_admin_count compliance signal and can be present even when the
	// roster itself could not be read.
	LocalAdminsCollectionStatus string
	// ReportedAdminCount is the local_admin_count signal exactly as the agent
	// reported it (-1 when no usable signal). AdminCount is the count the
	// risk band is assessed on: the same number, less any Windows built-in
	// RID-500 Administrator the agent read as disabled (PAT-1992).
	ReportedAdminCount int
	// BuiltinAdmin is the built-in Administrator verdict (PAT-1992), one of
	// the BuiltinAdmin* constants. See assessBuiltinAdmin.
	BuiltinAdmin string
	// BuiltinAdminNote is the plain-language explanation of BuiltinAdmin,
	// carried as evidence so a verdict never implies a check that did not
	// happen (in particular on macOS, where no built-in check applies).
	BuiltinAdminNote string
}

// LocalAdminAccount is one local_admin_accounts row (PAT-1974/1992), as read
// for a per-principal view rather than the PDF's plain name list.
type LocalAdminAccount struct {
	Name string
	// PrincipalType is one of local_admin_accounts' own CHECK values: "user"
	// (an individual account, local or directory-sourced), "group" (a
	// directory-sourced group principal such as Domain Admins — its own
	// membership is opaque to the device and it is never itself a person),
	// or "unresolved" (a SID the device could not resolve to a name or
	// kind — counted, never guessed at).
	PrincipalType string
	// Builtin is true only for the platform's built-in administrator
	// identity (Windows RID-500).
	Builtin bool
	// Sid is the Windows SID string, nil on macOS or when not carried.
	Sid *string
	// AccountState is the built-in RID-500 Administrator's enabled state
	// (PAT-1992): "enabled" | "disabled" | "unknown", or nil when never
	// reported (older agent, a non-built-in entry, or macOS).
	AccountState *string
}

// Built-in Administrator verdicts (PAT-1992).
const (
	// BuiltinAdminDisabled: every built-in RID-500 entry was read as
	// disabled. Low risk (common hardened-image state); excluded from the
	// standing-admin count the risk band is assessed on.
	BuiltinAdminDisabled = "disabled"
	// BuiltinAdminEnabled: at least one built-in RID-500 entry was read as
	// enabled. A real finding: it stays in the count, and the device is
	// rated at least "at-risk" whatever the count (never "compliant").
	BuiltinAdminEnabled = "enabled"
	// BuiltinAdminUnknown: a built-in entry's state was reported as
	// "unknown" or never reported (older agent). Neither a pass nor a fail:
	// the entry stays in the count exactly as before PAT-1992.
	BuiltinAdminUnknown = "unknown"
	// BuiltinAdminNone: a Windows roster is on file and carries no built-in
	// RID-500 entry, or no roster has been ingested yet. No adjustment.
	BuiltinAdminNone = "none"
	// BuiltinAdminNotApplicable: not a Windows device. The built-in account
	// adjustment is Windows-only; the verdict rests on the roster and count
	// as reported.
	BuiltinAdminNotApplicable = "not-applicable"
)

// builtinAdminEntry is one local_admin_accounts row flagged builtin, as read
// for the built-in Administrator rule.
type builtinAdminEntry struct {
	Sid           *string
	PrincipalType string
	AccountState  *string
}

// isBuiltinRID500 identifies the Windows built-in Administrator the same way
// the Windows agent does (Patched-LTD/updater LocalAdminLogic.cs): the entry
// carries builtin=true, which the agent sets only when the SID's relative
// identifier is exactly 500, and the stored SID ends in "-500". Requiring the
// SID as well as the flag means a malformed builtin=true entry without a
// RID-500 SID can never be excluded from the count. The agent only ever reads
// account_state for an entry that carries a SID, so no genuine disabled state
// is lost by this.
func isBuiltinRID500(e builtinAdminEntry) bool {
	return e.Sid != nil && strings.HasSuffix(*e.Sid, "-500")
}

// assessBuiltinAdmin is the consuming rule for local_admins.accounts[].
// account_state (PAT-1992). builtins are the device's roster entries flagged
// builtin=true; reportedCount is the local_admin_count signal (-1 when there
// is no usable signal). It returns the verdict, the count to assess the risk
// band on, and the explanatory note.
//
// Windows, per built-in RID-500 entry:
//   - "disabled" → low risk; excluded from the assessed count, unless the
//     entry is a group principal (groups are never in local_admin_count, so
//     there is nothing to exclude).
//   - "enabled"  → a real finding; stays in the count, and the device verdict
//     is BuiltinAdminEnabled whatever the other entries say. The caller then
//     rates the device at least "at-risk" (see FetchLocalAdminReport).
//   - "unknown" or absent → neither pass nor fail; stays in the count, the
//     same as before this field existed. Never treated as "disabled".
//
// A domain-joined machine can legitimately carry two RID-500 entries (its own
// and the domain's), so each entry is judged on its own. Nothing is excluded
// when there is no usable count signal: absence requires authority, and an
// adjustment to a count that does not exist would invent one.
//
// macOS (and any other non-Windows OS): the agent filters root out of the
// roster, so there is no built-in entry to judge. The adjustment is
// Windows-only and a macOS verdict rests on the roster and count exactly as
// reported. It returns BuiltinAdminNotApplicable with a note that says so,
// rather than silently implying a built-in check happened.
func assessBuiltinAdmin(os string, builtins []builtinAdminEntry, reportedCount int) (verdict string, assessedCount int, note string) {
	assessedCount = reportedCount
	if os != "Windows" {
		if os == "macOS" {
			return BuiltinAdminNotApplicable, assessedCount,
				"No built-in account check on macOS: the agent leaves root out of the admin roster, so this verdict is based on the roster and count as reported."
		}
		return BuiltinAdminNotApplicable, assessedCount,
			"The built-in Administrator check applies to Windows only; this verdict is based on the roster and count as reported."
	}

	var disabled, excludable, enabled, undetermined int
	for _, e := range builtins {
		if !isBuiltinRID500(e) {
			continue
		}
		switch {
		case e.AccountState != nil && *e.AccountState == "disabled":
			disabled++
			if e.PrincipalType != "group" {
				excludable++
			}
		case e.AccountState != nil && *e.AccountState == "enabled":
			enabled++
		default:
			// "unknown", absent, or anything unrecognised: no conclusion.
			undetermined++
		}
	}

	if reportedCount >= 0 && excludable > 0 {
		excluded := excludable
		if excluded > reportedCount {
			excluded = reportedCount
		}
		assessedCount = reportedCount - excluded
	}

	switch {
	case enabled > 0:
		return BuiltinAdminEnabled, assessedCount,
			"The built-in Administrator account is enabled. It should normally be disabled, so this device is rated at least At Risk."
	case undetermined > 0:
		return BuiltinAdminUnknown, assessedCount,
			"A built-in Administrator account's state was not established, so that account is still counted."
	case disabled > 0:
		if reportedCount < 0 {
			return BuiltinAdminDisabled, assessedCount,
				"The built-in Administrator account is disabled. No admin count was reported, so nothing was excluded."
		}
		return BuiltinAdminDisabled, assessedCount,
			"The built-in Administrator account is disabled, so it is not counted as a standing admin."
	default:
		return BuiltinAdminNone, assessedCount, ""
	}
}

// LocalAdminReport contains fleet-wide local admin exposure data.
type LocalAdminReport struct {
	GeneratedAt    time.Time
	Tenant         string
	Devices        []LocalAdminDevice
	TotalDevices   int
	CompliantCount int // ≤2 admins
	AtRiskCount    int // 3-4 admins
	CriticalCount  int // ≥5 admins
	UnknownCount   int // no signal collected
	// BuiltinEnabledCount is the number of Windows devices whose built-in
	// RID-500 Administrator was read as enabled (PAT-1992).
	BuiltinEnabledCount int
	// BuiltinDisabledExcludedCount is the number of Windows devices whose
	// assessed count excludes a disabled built-in Administrator (PAT-1992).
	BuiltinDisabledExcludedCount int
}

// FetchLocalAdminReport fetches local admin count data for a tenant.
// Data source: compliance_signals key = 'local_admin_count' (CIS macOS 5.8 / Windows equivalent).
// Devices with no signal are included with AdminCount=-1 and Risk="unknown".
func FetchLocalAdminReport(ctx context.Context, pool *pgxpool.Pool, tenantID string) (LocalAdminReport, error) {
	var r LocalAdminReport
	r.GeneratedAt = time.Now().UTC()

	err := pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id = $1`, tenantID).Scan(&r.Tenant)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return r, ErrTenantNotFound
		}
		return r, fmt.Errorf("fetch tenant: %w", err)
	}

	// LEFT JOIN so devices with no local_admin_count signal still appear.
	// The names LATERAL (PAT-1974) is independent evidence from the roster
	// table, not derived from admin_count_str — a device can have a count
	// signal with no roster yet (older agent) or vice versa.
	//
	// PAT-2215: the names LATERAL now also carries each entry's own
	// principal_type/builtin/sid/account_state, in the same
	// ORDER BY la.name as the plain names array, so AdminAccounts and
	// AdminNames below can never disagree about ordering or membership —
	// one query, one roster read, two shapes of the same rows (the PDF's
	// plain name list, and /v1/portal/local-admins' per-principal view).
	// d.id and d.collection_status->>'local_admins' are new selected
	// columns, not new joins, so this stays the one existing report query
	// per this ticket's own instruction to reuse it rather than add a
	// second one.
	rows, err := pool.Query(ctx, `
		SELECT d.id::text,
		       d.hostname,
		       d.os,
		       d.collection_status->>'local_admins' AS la_collection_status,
		       cs.value AS admin_count_str,
		       COALESCE(names.names, ARRAY[]::text[]) AS admin_names,
		       COALESCE(names.types, ARRAY[]::text[]) AS admin_types,
		       COALESCE(names.builtins, ARRAY[]::boolean[]) AS admin_builtins,
		       COALESCE(names.sids, ARRAY[]::text[]) AS admin_sids,
		       COALESCE(names.states, ARRAY[]::text[]) AS admin_states,
		       COALESCE(bi.sids, ARRAY[]::text[]) AS builtin_sids,
		       COALESCE(bi.types, ARRAY[]::text[]) AS builtin_types,
		       COALESCE(bi.states, ARRAY[]::text[]) AS builtin_states
		FROM devices d
		LEFT JOIN LATERAL (
		    SELECT cs2.value
		    FROM compliance_signals cs2
		    WHERE cs2.device_id = d.id
		      AND cs2.key = 'local_admin_count'
		    ORDER BY cs2.observed_at DESC
		    LIMIT 1
		) cs ON true
		LEFT JOIN LATERAL (
		    SELECT array_agg(la.name ORDER BY la.name) AS names,
		           array_agg(la.principal_type ORDER BY la.name) AS types,
		           array_agg(la.builtin ORDER BY la.name) AS builtins,
		           array_agg(la.sid ORDER BY la.name) AS sids,
		           array_agg(la.account_state ORDER BY la.name) AS states
		    FROM local_admin_accounts la
		    WHERE la.device_id = d.id
		) names ON true
		LEFT JOIN LATERAL (
		    -- PAT-1992: the built-in entries and their account_state, judged
		    -- by assessBuiltinAdmin. Parallel arrays in the same order; a NULL
		    -- sid or state is kept as NULL, never coerced to a value.
		    SELECT array_agg(la.sid ORDER BY la.id) AS sids,
		           array_agg(la.principal_type ORDER BY la.id) AS types,
		           array_agg(la.account_state ORDER BY la.id) AS states
		    FROM local_admin_accounts la
		    WHERE la.device_id = d.id
		      AND la.builtin
		) bi ON true
		WHERE d.tenant_id = $1
		ORDER BY
		    CASE WHEN cs.value ~ '^[0-9]+$' THEN cs.value::integer
		         ELSE 0
		    END DESC,
		    d.hostname
	`, tenantID)
	if err != nil {
		return r, fmt.Errorf("fetch local admin signals: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var deviceID string
		// devices.hostname and devices.os are nullable (a device that has
		// reported nothing else carries neither), so they scan as pointers
		// and an absent value reads as "" here, which fallback renders as
		// the usual dash (PAT-2538).
		var hostnamePtr, osPtr *string
		var laCollectionStatus *string
		var adminCountStr *string
		var adminNames, adminSids, adminStates []*string
		var adminTypes []string
		var adminBuiltins []bool
		var builtinSids, builtinStates []*string
		var builtinTypes []string
		if err := rows.Scan(&deviceID, &hostnamePtr, &osPtr, &laCollectionStatus, &adminCountStr,
			&adminNames, &adminTypes, &adminBuiltins, &adminSids, &adminStates,
			&builtinSids, &builtinTypes, &builtinStates); err != nil {
			return r, fmt.Errorf("scan local admin row: %w", err)
		}
		hostname, os := derefOrEmpty(hostnamePtr), derefOrEmpty(osPtr)
		if len(builtinSids) != len(builtinStates) || len(builtinSids) != len(builtinTypes) {
			return r, fmt.Errorf("built-in admin arrays out of step for %q: %d sids, %d types, %d states", hostname, len(builtinSids), len(builtinTypes), len(builtinStates))
		}
		builtins := make([]builtinAdminEntry, len(builtinSids))
		for i := range builtinSids {
			builtins[i] = builtinAdminEntry{Sid: builtinSids[i], PrincipalType: builtinTypes[i], AccountState: builtinStates[i]}
		}
		if len(adminNames) != len(adminTypes) || len(adminNames) != len(adminBuiltins) ||
			len(adminNames) != len(adminSids) || len(adminNames) != len(adminStates) {
			return r, fmt.Errorf("admin roster arrays out of step for %q: %d names, %d types, %d builtins, %d sids, %d states",
				hostname, len(adminNames), len(adminTypes), len(adminBuiltins), len(adminSids), len(adminStates))
		}
		plainNames := make([]string, len(adminNames))
		accounts := make([]LocalAdminAccount, len(adminNames))
		for i, namePtr := range adminNames {
			name := ""
			if namePtr != nil {
				name = *namePtr
			}
			plainNames[i] = name
			accounts[i] = LocalAdminAccount{
				Name: name, PrincipalType: adminTypes[i], Builtin: adminBuiltins[i],
				Sid: adminSids[i], AccountState: adminStates[i],
			}
		}

		dev := LocalAdminDevice{
			DeviceID:                    deviceID,
			Hostname:                    fallback(hostname),
			OS:                          fallback(os),
			AdminNames:                  plainNames,
			AdminAccounts:               accounts,
			LocalAdminsCollectionStatus: derefOrEmpty(laCollectionStatus),
		}

		reported := -1
		if adminCountStr != nil {
			if n, err := strconv.Atoi(*adminCountStr); err == nil {
				reported = n
			}
		}
		dev.ReportedAdminCount = reported
		verdict, assessed, note := assessBuiltinAdmin(os, builtins, reported)
		dev.BuiltinAdmin = verdict
		dev.BuiltinAdminNote = note
		if verdict == BuiltinAdminEnabled {
			r.BuiltinEnabledCount++
		}
		if assessed < reported {
			r.BuiltinDisabledExcludedCount++
		}

		if reported < 0 {
			dev.AdminCount = -1
			dev.Risk = "unknown"
			r.UnknownCount++
		} else {
			dev.AdminCount = assessed
			switch {
			case assessed <= 2 && verdict != BuiltinAdminEnabled:
				dev.Risk = "compliant"
				r.CompliantCount++
			case assessed <= 4:
				// Includes a device with 2 or fewer admins whose built-in
				// Administrator is enabled: that is never "compliant".
				dev.Risk = "at-risk"
				r.AtRiskCount++
			default:
				dev.Risk = "critical"
				r.CriticalCount++
			}
		}
		r.Devices = append(r.Devices, dev)
	}
	if err := rows.Err(); err != nil {
		return r, fmt.Errorf("iterate local admin rows: %w", err)
	}
	r.TotalDevices = len(r.Devices)
	return r, nil
}
