// Package remoteaccess owns PAT-2148's SAM report: every remote access tool
// and RMM agent across the estate, by device and (PAT-2075, where present)
// by user, with the tenant's own existing software-approval state.
//
// Detection is internal/categorytag's own match rules (categories
// "remote_access" and "rmm_agent"), evaluated directly against the tenant's
// live software_installations and device_browser_extensions rows with
// categorytag.Matches -- the same pure function the rule reconciler uses --
// so this report is never stale relative to a materialised-tag backfill and
// never disagrees with /v1/portal/tagged-products about what a rule matches.
//
// Sanctioned vs unsanctioned is the tenant's existing approval state
// (internal/softwaregov's tenant_app_policies / tenant_extension_policies /
// tenant_homebrew_policies resolution, PAT-2007/PAT-2058), never a second,
// parallel list: Approved is sanctioned, Unapproved and Unreviewed are
// flagged, Ignored is shown as ignored. RMM agents are counted apart in the
// summary so an MSP's own tooling is never presented as an unsanctioned
// remote-access finding.
//
// Nothing here changes a device or tells an agent to act.
package remoteaccess

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"patched.im/api/internal/categorytag"
	"patched.im/api/internal/deviceretirement"
	"patched.im/api/internal/softwaregov"
)

// Category keys, as seeded by migration 0197.
const (
	CategoryRemoteAccess = "remote_access"
	CategoryRMMAgent     = "rmm_agent"
)

// Approval states, PAT-2007's vocabulary, re-exported so a caller need not
// import softwaregov just to compare a state.
const (
	StateApproved   = softwaregov.StateApproved
	StateUnapproved = softwaregov.StateUnapproved
	StateUnreviewed = softwaregov.StateUnreviewed
	StateIgnored    = softwaregov.StateIgnored
)

// MaxReportRows bounds one tenant's load. Over it the report fails closed,
// never a partial answer, matching PAT-2147's own cap.
const MaxReportRows = softwaregov.MaxEstateRows

// ErrEstateTooLarge means the tenant's inventory exceeds MaxReportRows.
var ErrEstateTooLarge = errors.New("remoteaccess: estate inventory exceeds the load cap")

// Statement is the report's standing caveat: detection is catalogue-limited,
// so absence of a finding is never evidence of absence of a tool.
const Statement = "Every remote access tool and RMM agent Patched's category rules recognise, by device and " +
	"user where a per-user install is reported, with your tenant's existing software approval state. Detection " +
	"covers only the tools this catalogue recognises: a device reporting none of them is not evidence that no " +
	"remote access tool is installed, only that none of the catalogued ones were found. It is not an audit or a " +
	"compliance position."

// Definition names the saved report definition (PAT-2146: each SAM report is
// a saved definition over existing read APIs).
type Definition struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	Title   string `json:"title"`
}

// ReportDefinition is the one saved definition of this report.
var ReportDefinition = Definition{ID: "sam.remote-access", Version: 1, Title: "Remote access tools"}

// Kinds a row can be. Values match internal/categorytag's own Observation
// kinds, so a caller never needs a second vocabulary: "app" covers ordinary
// applications and Homebrew casks/formulae alike (they are all
// software_installations rows), "browser_extension" is a browser extension.
const (
	KindApp              = categorytag.KindApp
	KindBrowserExtension = categorytag.KindBrowserExtension
	KindPackage          = categorytag.KindPackage
)

// Row is one product on one device (and, where reported, one user).
type Row struct {
	DeviceID       string    `json:"device_id"`
	Hostname       string    `json:"hostname"`
	DeviceLastSeen time.Time `json:"device_last_seen"`
	DeviceStale    bool      `json:"device_stale"`
	Category       string    `json:"category"`
	Kind           string    `json:"kind"`
	ProductKey     string    `json:"product_key"`
	Name           string    `json:"name"`
	Platform       string    `json:"platform"`
	Identifier     string    `json:"identifier"`
	Version        string    `json:"version,omitempty"`
	ApprovalState  string    `json:"approval_state"`
	// User is the account a per-user install (PAT-2075) or a per-user
	// browser extension belongs to. Nil means the row is machine-wide, or
	// no per-user scope was reported for it: MachineWide says which.
	User        *string   `json:"user"`
	MachineWide bool      `json:"machine_wide"`
	LastSeen    time.Time `json:"last_seen"`
}

// ProductRow groups Rows by product and outcome, for the report's paged
// top-level listing.
type ProductRow struct {
	ProductKey       string `json:"product_key"`
	Category         string `json:"category"`
	Kind             string `json:"kind"`
	Name             string `json:"name"`
	Platform         string `json:"platform"`
	Identifier       string `json:"identifier"`
	ApprovalState    string `json:"approval_state"`
	DeviceCount      int    `json:"device_count"`
	StaleDeviceCount int    `json:"stale_device_count"`
	// Installations counts every matching installation or extension row
	// (a device with the tool for two users counts twice).
	Installations int      `json:"installation_count"`
	Users         []string `json:"users"`
	// MachineWideCount is how many of this product's matching rows carry no
	// per-user scope (machine-wide or unknown).
	MachineWideCount int       `json:"machine_wide_count"`
	LastSeen         time.Time `json:"last_seen"`
}

// StateCount is one approval state's totals within one category.
type StateCount struct {
	Tools         int `json:"tool_count"`
	Installations int `json:"installation_count"`
	Devices       int `json:"device_count"`
}

// Summary is the per-category, per-state totals. RMMAgents is kept apart
// from RemoteAccess so an MSP's own tooling is never added into the
// remote-access finding counts.
type Summary struct {
	RemoteAccess             map[string]StateCount `json:"remote_access"`
	RMMAgents                map[string]StateCount `json:"rmm_agents"`
	RemoteAccessToolCount    int                   `json:"remote_access_tool_count"`
	RemoteAccessInstallCount int                   `json:"remote_access_installation_count"`
	RMMAgentToolCount        int                   `json:"rmm_agent_tool_count"`
	RMMAgentInstallCount     int                   `json:"rmm_agent_installation_count"`
}

// NotCounted is one class of evidence the report deliberately leaves out.
type NotCounted struct {
	Reason      string `json:"reason"`
	Description string `json:"description"`
	Count       int    `json:"count"`
}

// Basis states what the answer rests on, in the same shape PAT-2147 uses.
type Basis struct {
	GeneratedAt             time.Time    `json:"generated_at"`
	EvidenceNewestAt        *time.Time   `json:"evidence_newest_at"`
	EvidenceOldestAt        *time.Time   `json:"evidence_oldest_at"`
	DevicesTotal            int          `json:"devices_total"`
	DevicesAssessed         int          `json:"devices_assessed"`
	DevicesReporting        int          `json:"devices_reporting"`
	DevicesStale            int          `json:"devices_stale"`
	DevicesWithoutInventory int          `json:"devices_without_inventory"`
	StaleAfterDays          int          `json:"stale_after_days"`
	RetiredDevicesExcluded  bool         `json:"retired_devices_excluded"`
	DevicesRetired          int          `json:"devices_retired"`
	NotCounted              []NotCounted `json:"not_counted"`
	// UnassessedDeviceIDs lists the assessed devices whose evidence is not
	// current: stale (not seen within StaleAfterDays) or reporting no
	// software inventory at all. Internal only (never serialised): the
	// insurance evidence pack (PAT-2258) counts them as unknown, which
	// DevicesStale + DevicesWithoutInventory cannot do exactly because one
	// device can be both.
	UnassessedDeviceIDs []string `json:"-"`
	Complete            bool     `json:"complete"`
	Statement           string   `json:"statement"`
	Notes               []string `json:"notes"`
}

// Report is one tenant's remote access report.
type Report struct {
	Definition  Definition   `json:"definition"`
	GeneratedAt time.Time    `json:"generated_at"`
	Summary     Summary      `json:"summary"`
	Basis       Basis        `json:"basis"`
	Products    []ProductRow `json:"-"`
	Rows        []Row        `json:"-"`
}

type deviceFacts struct {
	ID, Hostname, Platform string
	LastSeen               time.Time
	Stale, HasInventory    bool
}

func platformOf(os string) string {
	switch strings.ToLower(strings.TrimSpace(os)) {
	case "macos":
		return "macos"
	case "windows":
		return "windows"
	}
	return ""
}

// catRule is one published software_category_rules row for the two
// categories this report evaluates.
type catRule struct {
	categorytag.RuleSpec
}

func loadCategoryRules(ctx context.Context, db softwaregov.Querier) ([]catRule, error) {
	rows, err := db.Query(ctx, `
		SELECT identifier_type, identifier_value, qualifier, platform, category_key, subtype_key
		FROM software_category_rules
		WHERE state = 'published' AND category_key = ANY($1::text[])`,
		[]string{CategoryRemoteAccess, CategoryRMMAgent})
	if err != nil {
		return nil, fmt.Errorf("load category rules: %w", err)
	}
	defer rows.Close()
	var out []catRule
	for rows.Next() {
		var r catRule
		if err := rows.Scan(&r.IdentifierType, &r.IdentifierValue, &r.Qualifier, &r.Platform,
			&r.CategoryKey, &r.SubtypeKey); err != nil {
			return nil, fmt.Errorf("scan category rule: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// matchedRule reports the first published rule (of either category) that
// matches an observation, and its category/subtype. A given observation is
// deliberately assigned to only one category: remote_access and rmm_agent
// rules never target the same real product, but if a future rule pair ever
// did overlap, matchedRule keeps the report's per-installation grouping
// simple by taking the first configured match.
func matchedRule(rules []catRule, o categorytag.Observation) (catRule, bool) {
	for _, r := range rules {
		if categorytag.Matches(r.RuleSpec, o) {
			return r, true
		}
	}
	return catRule{}, false
}

// Build computes the report for one tenant. tenantID must come from an
// authenticated identity; every query is scoped to it.
func Build(ctx context.Context, db softwaregov.Querier, tenantID string, now time.Time) (Report, error) {
	now = now.UTC()
	rep := Report{Definition: ReportDefinition, GeneratedAt: now}
	staleCut := now.Add(-softwaregov.StaleAfter)

	var total int
	if err := db.QueryRow(ctx, `
		SELECT count(*)::int FROM software_installations
		WHERE tenant_id = $1::uuid AND removed_at IS NULL`, tenantID).Scan(&total); err != nil {
		return rep, fmt.Errorf("count installations: %w", err)
	}
	if total > MaxReportRows {
		return rep, ErrEstateTooLarge
	}

	rules, err := loadCategoryRules(ctx, db)
	if err != nil {
		return rep, err
	}

	pol, err := softwaregov.LoadPolicies(ctx, db, tenantID)
	if err != nil {
		return rep, fmt.Errorf("load policies: %w", err)
	}

	// Devices.
	drows, err := db.Query(ctx, `
		SELECT d.id::text, COALESCE(NULLIF(d.computer_name, ''), NULLIF(d.hostname, ''), ''),
		       COALESCE(d.os, ''), d.last_seen,
		       EXISTS (SELECT 1 FROM software_installations si
		               WHERE si.device_id = d.id AND si.tenant_id = d.tenant_id AND si.removed_at IS NULL),
		       r.retired
		FROM devices d
		CROSS JOIN LATERAL (SELECT `+deviceretirement.RetiredSQL("d")+` AS retired) r
		WHERE d.tenant_id = $1::uuid
		ORDER BY d.id`, tenantID)
	if err != nil {
		return rep, fmt.Errorf("load devices: %w", err)
	}
	devices := map[string]*deviceFacts{}
	unrecognised, retired := 0, 0
	for drows.Next() {
		var d deviceFacts
		var os string
		var isRetired bool
		if err := drows.Scan(&d.ID, &d.Hostname, &os, &d.LastSeen, &d.HasInventory, &isRetired); err != nil {
			drows.Close()
			return rep, fmt.Errorf("scan device: %w", err)
		}
		d.Platform = platformOf(os)
		d.Stale = d.LastSeen.Before(staleCut)
		rep.Basis.DevicesTotal++
		if isRetired {
			retired++
			continue
		}
		if d.Platform == "" {
			unrecognised++
			continue
		}
		dd := d
		devices[d.ID] = &dd
	}
	drows.Close()
	if err := drows.Err(); err != nil {
		return rep, err
	}

	// Applications, Homebrew formulae/casks: every non-removed
	// software_installations row, with its latest observation's team id and
	// signer (for match evaluation and Windows approval resolution) and the
	// distinct per-user scopes (PAT-2075) that still hold it.
	irows, err := db.Query(ctx, `
		SELECT si.device_id::text, si.platform, si.identity_kind, si.identity_value_normalized,
		       si.companion_value_normalized,
		       COALESCE(so.observed_team_id,
		                CASE WHEN si.identity_kind = 'macos_bundle_team' THEN si.companion_value_normalized END, ''),
		       COALESCE(so.observed_signer, ''),
		       COALESCE(so.observed_name, si.current_name),
		       COALESCE(so.observed_name IS NULL OR so.observed_name = 'unknown software'
		           OR so.observed_name = so.observed_path OR so.observed_name = so.observed_identifier, true),
		       si.current_name, COALESCE(si.current_version, ''),
		       COALESCE(u.users, ARRAY[]::text[])
		FROM software_installations si
		LEFT JOIN software_observations so ON so.id = si.latest_observation_id
		LEFT JOIN LATERAL (
		    SELECT array_agg(DISTINCT das.user_account ORDER BY das.user_account) AS users
		    FROM device_app_user_scopes das
		    WHERE das.device_id = si.device_id AND das.identity_fingerprint = si.identity_fingerprint
		) u ON true
		WHERE si.tenant_id = $1::uuid AND si.removed_at IS NULL`, tenantID)
	if err != nil {
		return rep, fmt.Errorf("load installations: %w", err)
	}
	for irows.Next() {
		var deviceID, platform, identityKind, identityValue, companion, teamID, signer, obsName string
		var nameUnknown bool
		var currentName, currentVersion string
		var users []string
		if err := irows.Scan(&deviceID, &platform, &identityKind, &identityValue, &companion, &teamID, &signer,
			&obsName, &nameUnknown, &currentName, &currentVersion, &users); err != nil {
			irows.Close()
			return rep, fmt.Errorf("scan installation: %w", err)
		}
		d := devices[deviceID]
		if d == nil {
			continue // a retired or unrecognised-platform device
		}
		kind, obs := categorytag.InstallationObservation(identityKind, identityValue, companion)
		if kind != categorytag.KindApp {
			obs.Platform = platform
			obs.IdentityKind, obs.IdentityValue = identityKind, identityValue
		} else {
			obs.Platform, obs.IdentityKind, obs.IdentityValue = platform, identityKind, identityValue
			obs.TeamID, obs.Signer, obs.Name, obs.NameUnknown = teamID, signer, obsName, nameUnknown
		}
		rule, ok := matchedRule(rules, obs)
		if !ok {
			continue
		}
		state := resolveInstallState(pol, kind, identityKind, identityValue, companion, teamID, signer, currentName, d.Platform)
		appendRows(&rep, d, rule, kind, identityKind, identityValue, currentName, currentVersion, state, users)
	}
	irows.Close()
	if err := irows.Err(); err != nil {
		return rep, err
	}

	// Browser extensions. Each row is already per-user (device_browser_
	// extensions' unique key includes user_account); Safari's fixed
	// sentinel means "no real user" (PAT-2064), read as machine-wide.
	erows, err := db.Query(ctx, `
		SELECT dbe.device_id::text, dbe.browser, dbe.extension_id, dbe.name, COALESCE(dbe.version, ''), dbe.user_account
		FROM device_browser_extensions dbe
		JOIN devices d ON d.id = dbe.device_id
		WHERE d.tenant_id = $1::uuid`, tenantID)
	if err != nil {
		return rep, fmt.Errorf("load browser extensions: %w", err)
	}
	for erows.Next() {
		var deviceID, browser, extID, name, version, user string
		if err := erows.Scan(&deviceID, &browser, &extID, &name, &version, &user); err != nil {
			erows.Close()
			return rep, fmt.Errorf("scan browser extension: %w", err)
		}
		d := devices[deviceID]
		if d == nil {
			continue
		}
		obs := categorytag.Observation{Kind: categorytag.KindBrowserExtension, Platform: d.Platform,
			Identifier: extID, Browser: browser}
		rule, ok := matchedRule(rules, obs)
		if !ok {
			continue
		}
		state := pol.ResolveExtension(browser, extID)
		var users []string
		if user != "" && user != safariSystemUser {
			users = []string{user}
		}
		appendRows(&rep, d, rule, categorytag.KindBrowserExtension, "browser_extension", extID, name, version, state, users)
	}
	erows.Close()
	if err := erows.Err(); err != nil {
		return rep, err
	}

	finish(&rep, devices, unrecognised, retired)
	return rep, nil
}

// safariSystemUser mirrors internal/extractor.SafariSystemSentinel: the
// fixed value device_browser_extensions.user_account carries for a Safari
// row, which has no real per-user account (PAT-2064). Kept as a local,
// documented constant rather than importing internal/extractor.
const safariSystemUser = "_system"

// resolveInstallState resolves one installation's approval state: Homebrew
// formulae/casks go through the homebrew policy table by (kind, name, tap);
// everything else goes through the application policy index.
func resolveInstallState(pol softwaregov.Policies, kind, identityKind, identityValue, companion, teamID, signer, name, devicePlatform string) string {
	switch identityKind {
	case "homebrew_formula":
		return pol.ResolveHomebrew("formula", identityValue, companion)
	case "homebrew_cask":
		return pol.ResolveHomebrew("cask", identityValue, companion)
	}
	_ = kind
	// device_apps.team_id conflates the two platform concepts apppolicy
	// resolves against: the macOS Team ID and, on Windows, the Authenticode
	// publisher/signer. The observation domain keeps these as two separate
	// fields (observed_team_id, observed_signer); merge them here the same
	// way so ResolveApp sees exactly what device_apps would have shown it.
	identity := teamID
	if identity == "" {
		identity = signer
	}
	return pol.ResolveApp(identity, identityValue, identityKind, name, devicePlatform)
}

func appendRows(rep *Report, d *deviceFacts, rule catRule, kind, identityKind, identifier, name, version, state string, users []string) {
	pk := rule.CategoryKey + ":" + kind + ":" + strings.ToLower(strings.TrimSpace(identifier))
	if len(users) == 0 {
		rep.Rows = append(rep.Rows, Row{
			DeviceID: d.ID, Hostname: d.Hostname, DeviceLastSeen: d.LastSeen, DeviceStale: d.Stale,
			Category: rule.CategoryKey, Kind: kind, ProductKey: pk, Name: name, Platform: d.Platform,
			Identifier: identifier, Version: version, ApprovalState: state, User: nil, MachineWide: true,
			LastSeen: d.LastSeen,
		})
		return
	}
	for _, u := range users {
		user := u
		rep.Rows = append(rep.Rows, Row{
			DeviceID: d.ID, Hostname: d.Hostname, DeviceLastSeen: d.LastSeen, DeviceStale: d.Stale,
			Category: rule.CategoryKey, Kind: kind, ProductKey: pk, Name: name, Platform: d.Platform,
			Identifier: identifier, Version: version, ApprovalState: state, User: &user, MachineWide: false,
			LastSeen: d.LastSeen,
		})
	}
}

var stateRank = map[string]int{StateUnapproved: 0, StateUnreviewed: 1, StateIgnored: 2, StateApproved: 3}

func finish(rep *Report, devices map[string]*deviceFacts, unrecognised, retired int) {
	now := rep.GeneratedAt
	sum := Summary{RemoteAccess: map[string]StateCount{}, RMMAgents: map[string]StateCount{}}
	for _, s := range []string{StateApproved, StateUnapproved, StateUnreviewed, StateIgnored} {
		sum.RemoteAccess[s] = StateCount{}
		sum.RMMAgents[s] = StateCount{}
	}

	type group struct {
		row         ProductRow
		devices     map[string]bool
		stale       map[string]bool
		users       map[string]bool
		machineWide int
	}
	groups := map[string]*group{}
	var order []string
	stateDevices := map[string]map[string]map[string]bool{ // category -> state -> deviceID
		CategoryRemoteAccess: {}, CategoryRMMAgent: {},
	}
	stateTools := map[string]map[string]map[string]bool{ // category -> state -> productKey
		CategoryRemoteAccess: {}, CategoryRMMAgent: {},
	}
	for _, s := range []string{StateApproved, StateUnapproved, StateUnreviewed, StateIgnored} {
		stateDevices[CategoryRemoteAccess][s] = map[string]bool{}
		stateDevices[CategoryRMMAgent][s] = map[string]bool{}
		stateTools[CategoryRemoteAccess][s] = map[string]bool{}
		stateTools[CategoryRMMAgent][s] = map[string]bool{}
	}

	for _, r := range rep.Rows {
		if r.Category == CategoryRemoteAccess {
			sc := sum.RemoteAccess[r.ApprovalState]
			sc.Installations++
			sum.RemoteAccess[r.ApprovalState] = sc
			sum.RemoteAccessInstallCount++
			stateDevices[CategoryRemoteAccess][r.ApprovalState][r.DeviceID] = true
			stateTools[CategoryRemoteAccess][r.ApprovalState][r.ProductKey] = true
		} else {
			sc := sum.RMMAgents[r.ApprovalState]
			sc.Installations++
			sum.RMMAgents[r.ApprovalState] = sc
			sum.RMMAgentInstallCount++
			stateDevices[CategoryRMMAgent][r.ApprovalState][r.DeviceID] = true
			stateTools[CategoryRMMAgent][r.ApprovalState][r.ProductKey] = true
		}

		g := groups[r.ProductKey]
		if g == nil {
			g = &group{row: ProductRow{
				ProductKey: r.ProductKey, Category: r.Category, Kind: r.Kind, Name: r.Name, Platform: r.Platform,
				Identifier: r.Identifier, ApprovalState: r.ApprovalState,
			}, devices: map[string]bool{}, stale: map[string]bool{}, users: map[string]bool{}}
			groups[r.ProductKey] = g
			order = append(order, r.ProductKey)
		}
		g.row.Installations++
		g.devices[r.DeviceID] = true
		if r.DeviceStale {
			g.stale[r.DeviceID] = true
		}
		if r.User != nil {
			g.users[*r.User] = true
		} else {
			g.machineWide++
		}
		if r.LastSeen.After(g.row.LastSeen) {
			g.row.LastSeen = r.LastSeen
		}
	}
	rep.Summary = sum

	for _, key := range order {
		g := groups[key]
		g.row.DeviceCount = len(g.devices)
		g.row.StaleDeviceCount = len(g.stale)
		g.row.MachineWideCount = g.machineWide
		users := make([]string, 0, len(g.users))
		for u := range g.users {
			users = append(users, u)
		}
		sort.Strings(users)
		g.row.Users = users
		rep.Products = append(rep.Products, g.row)
	}

	for _, s := range []string{StateApproved, StateUnapproved, StateUnreviewed, StateIgnored} {
		ra := sum.RemoteAccess[s]
		ra.Devices = len(stateDevices[CategoryRemoteAccess][s])
		ra.Tools = len(stateTools[CategoryRemoteAccess][s])
		sum.RemoteAccess[s] = ra
		rm := sum.RMMAgents[s]
		rm.Devices = len(stateDevices[CategoryRMMAgent][s])
		rm.Tools = len(stateTools[CategoryRMMAgent][s])
		sum.RMMAgents[s] = rm
	}
	toolSet := map[string]bool{}
	for _, p := range rep.Products {
		if p.Category == CategoryRemoteAccess {
			toolSet[p.ProductKey] = true
		}
	}
	sum.RemoteAccessToolCount = len(toolSet)
	rmmSet := map[string]bool{}
	for _, p := range rep.Products {
		if p.Category == CategoryRMMAgent {
			rmmSet[p.ProductKey] = true
		}
	}
	sum.RMMAgentToolCount = len(rmmSet)
	rep.Summary = sum

	sort.SliceStable(rep.Products, func(i, j int) bool {
		a, b := rep.Products[i], rep.Products[j]
		if stateRank[a.ApprovalState] != stateRank[b.ApprovalState] {
			return stateRank[a.ApprovalState] < stateRank[b.ApprovalState]
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if !strings.EqualFold(a.Name, b.Name) {
			return strings.ToLower(a.Name) < strings.ToLower(b.Name)
		}
		return a.ProductKey < b.ProductKey
	})
	sort.SliceStable(rep.Rows, func(i, j int) bool {
		a, b := rep.Rows[i], rep.Rows[j]
		if stateRank[a.ApprovalState] != stateRank[b.ApprovalState] {
			return stateRank[a.ApprovalState] < stateRank[b.ApprovalState]
		}
		if a.Hostname != b.Hostname {
			return a.Hostname < b.Hostname
		}
		if a.DeviceID != b.DeviceID {
			return a.DeviceID < b.DeviceID
		}
		if a.ProductKey != b.ProductKey {
			return a.ProductKey < b.ProductKey
		}
		au, bu := "", ""
		if a.User != nil {
			au = *a.User
		}
		if b.User != nil {
			bu = *b.User
		}
		return au < bu
	})

	b := Basis{
		GeneratedAt: now, StaleAfterDays: int(softwaregov.StaleAfter / (24 * time.Hour)),
		DevicesTotal: rep.Basis.DevicesTotal, RetiredDevicesExcluded: true, DevicesRetired: retired,
		Statement: Statement,
		Notes: []string{
			"Devices your organisation has retired are left out of every figure and listed here as not counted. A device that has not reported for 14 days is still counted, marked stale, with the age of its evidence.",
			"Approval state is your tenant's own existing decision on each product (the same state PUT /v1/portal/software-approvals writes and GET /v1/portal/software/drift reads), never a separate remote-access allow list.",
		},
	}
	for _, d := range devices {
		b.DevicesAssessed++
		if d.Stale {
			b.DevicesStale++
		} else {
			b.DevicesReporting++
		}
		if !d.HasInventory {
			b.DevicesWithoutInventory++
		}
		if d.Stale || !d.HasInventory {
			b.UnassessedDeviceIDs = append(b.UnassessedDeviceIDs, d.ID)
		}
		t := d.LastSeen.UTC()
		if b.EvidenceNewestAt == nil || t.After(*b.EvidenceNewestAt) {
			tt := t
			b.EvidenceNewestAt = &tt
		}
		if b.EvidenceOldestAt == nil || t.Before(*b.EvidenceOldestAt) {
			tt := t
			b.EvidenceOldestAt = &tt
		}
	}
	b.NotCounted = []NotCounted{
		{Reason: "retired_devices", Description: "devices your organisation has retired", Count: retired},
		{Reason: "unrecognised_platform", Description: "devices reporting an operating system other than macOS or Windows", Count: unrecognised},
	}
	b.Complete = b.DevicesAssessed > 0 && b.DevicesStale == 0 && b.DevicesWithoutInventory == 0 && unrecognised == 0
	rep.Basis = b
}
