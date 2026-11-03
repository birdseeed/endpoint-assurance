// Package duplicatetools owns PAT-2151's SAM report (PAT-2146): within a
// curated set of categories where an estate commonly runs several competing
// products doing the same job -- PDF editors, screen recorders, VPN clients,
// password managers, file sync clients, video conferencing, remote access
// tools and note-taking apps -- the distinct products present, their install
// counts and users, so consolidation opportunities are visible without
// needing price data.
//
// Detection is internal/categorytag's own match rules (migration 0198's
// seeded identities, plus remote_access reused as-is from PAT-2148's
// migration 0197), evaluated directly against the tenant's live
// software_installations and device_browser_extensions rows with
// categorytag.Matches -- the same pure function the rule reconciler and
// internal/remoteaccess use -- so this report is never stale relative to a
// materialised-tag backfill and never disagrees with /v1/portal/tagged-
// products about what a rule matches.
//
// Grouping is by each matched rule's product_key (software_category_rules.
// product_key, migration 0198), not by raw identifier: one product's macOS
// bundle, Windows winget package and Homebrew cask are three different
// identifiers but one product, and counting them as three would misreport a
// single dual-platform tool as itself a duplicate. A rule with no
// product_key (every rule outside this report's eight categories --
// ai_tooling, rmm_agent) is never selected, so it can never appear here.
//
// Flag rule: a category is flagged when three or more distinct products are
// present in the tenant's own estate (MinProductsToFlag). The ticket's other
// rule -- two or more PAID products duplicated -- needs licence or price
// data that does not exist yet; PAT-2143's price catalogue adds it. That
// rule is deliberately NOT implemented here -- see Statement and the
// contract. A product with no category tag never appears in a duplicate
// group: that falls out of categorytag's own matching (an untagged
// installation is never selected), not a separate exclusion rule.
package duplicatetools

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

// Category keys. remote_access is reused from PAT-2148 (migration 0197,
// backfilled with product_key by migration 0198); the other seven are seeded
// fresh by migration 0198.
const (
	CategoryPDFEditor         = "pdf_editor"
	CategoryScreenRecorder    = "screen_recorder"
	CategoryVPNClient         = "vpn_client"
	CategoryPasswordManager   = "password_manager"
	CategoryFileSync          = "file_sync"
	CategoryVideoConferencing = "video_conferencing"
	CategoryRemoteAccess      = "remote_access"
	CategoryNoteTaking        = "note_taking"
)

// Categories is every category this report evaluates. Order here is the
// ticket's own listing; Build sorts its output by display name, not this
// order, so this slice is only the query scope.
var Categories = []string{
	CategoryPDFEditor, CategoryScreenRecorder, CategoryVPNClient, CategoryPasswordManager,
	CategoryFileSync, CategoryVideoConferencing, CategoryRemoteAccess, CategoryNoteTaking,
}

// MinProductsToFlag: a category with this many or more distinct products
// present in the estate is a consolidation candidate.
const MinProductsToFlag = 3

// Approval states, PAT-2007's vocabulary, re-exported so a caller need not
// import softwaregov just to compare a state.
const (
	StateApproved   = softwaregov.StateApproved
	StateUnapproved = softwaregov.StateUnapproved
	StateUnreviewed = softwaregov.StateUnreviewed
	StateIgnored    = softwaregov.StateIgnored
)

// MaxReportRows bounds one tenant's load. Over it the report fails closed,
// never a partial answer, matching PAT-2147/PAT-2148's own cap.
const MaxReportRows = softwaregov.MaxEstateRows

// ErrEstateTooLarge means the tenant's inventory exceeds MaxReportRows.
var ErrEstateTooLarge = errors.New("duplicatetools: estate inventory exceeds the load cap")

// Statement is the report's standing caveat.
//
// Customer copy: no "--", no "ticket" and no internal references (the portal
// renders it verbatim; PAT-2303). The paid-products sentence is Andy's wording
// from PAT-2253.
const Statement = "Categories where Patched's curated category rules recognise three or more distinct products " +
	"installed across your estate, which makes each one a consolidation candidate. This is shown without " +
	"needing licence or price data. Detection covers only the products this catalogue recognises: a category " +
	"showing fewer than three products is not evidence that fewer are actually installed, only that fewer of " +
	"the catalogued ones were found. A second rule, two or more paid products in a category, needs licence data " +
	"and is not applied yet. It is not an audit or a compliance position."

// Definition names the saved report definition (PAT-2146: each SAM report is
// a saved definition over existing read APIs).
type Definition struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	Title   string `json:"title"`
}

// ReportDefinition is the one saved definition of this report.
var ReportDefinition = Definition{ID: "sam.duplicate-tools", Version: 1, Title: "Duplicate tools by category"}

// Kinds a row can be. Values match internal/categorytag's own Observation
// kinds: "app" covers ordinary applications and Homebrew casks/formulae
// alike (they are all software_installations rows), "browser_extension" is a
// browser extension (only remote_access's Chrome Remote Desktop rule uses
// this kind today).
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
	ProductKey     string    `json:"product_key"`
	ProductName    string    `json:"product_name"`
	Kind           string    `json:"kind"`
	Platform       string    `json:"platform"`
	Identifier     string    `json:"identifier"`
	Name           string    `json:"name"`
	Version        string    `json:"version,omitempty"`
	ApprovalState  string    `json:"approval_state"`
	// User is the account a per-user install (PAT-2075) or a per-user
	// browser extension belongs to. Nil means the row is machine-wide, or no
	// per-user scope was reported for it: MachineWide says which.
	User        *string   `json:"user"`
	MachineWide bool      `json:"machine_wide"`
	LastSeen    time.Time `json:"last_seen"`
}

// ProductRow groups Rows by product across every platform it was seen on,
// so one dual-platform product is one row, not two. Platforms is deliberately
// plural (unlike internal/remoteaccess's single Platform) because that
// cross-platform grouping is this report's whole point: a product's macOS
// and Windows identities count as one product for the flag rule.
type ProductRow struct {
	ProductKey  string   `json:"product_key"`
	Category    string   `json:"category"`
	Name        string   `json:"name"`
	Kinds       []string `json:"kinds"`
	Platforms   []string `json:"platforms"`
	Identifiers []string `json:"identifiers"`
	// ApprovalState is the least favourable state across this product's rows
	// (unapproved, then unreviewed, then ignored, then approved), the same
	// precedence internal/remoteaccess sorts by: a product approved on one
	// platform and unreviewed on another is surfaced as unreviewed, never
	// silently shown as approved. Per-installation state is still available
	// from GET /v1/portal/software/drift and the CSV export of this report.
	ApprovalState    string   `json:"approval_state"`
	DeviceCount      int      `json:"device_count"`
	StaleDeviceCount int      `json:"stale_device_count"`
	Installations    int      `json:"installation_count"`
	Users            []string `json:"users"`
	// MachineWideCount is how many of this product's matching rows carry no
	// per-user scope (machine-wide or unknown).
	MachineWideCount int       `json:"machine_wide_count"`
	LastSeen         time.Time `json:"last_seen"`
}

// CategoryRow is one category's consolidation view: the products present,
// whether the category is flagged, and how many distinct products drove
// that flag.
type CategoryRow struct {
	Category     string       `json:"category"`
	DisplayName  string       `json:"display_name"`
	Flagged      bool         `json:"flagged"`
	ProductCount int          `json:"product_count"`
	Products     []ProductRow `json:"products"`
}

// Summary is the report's headline totals.
type Summary struct {
	CategoriesAssessed int `json:"categories_assessed"`
	// CategoriesWithProducts is how many of CategoriesAssessed have at least
	// one product present in the estate.
	CategoriesWithProducts int `json:"categories_with_products"`
	CategoriesFlagged      int `json:"categories_flagged"`
	ProductCount           int `json:"product_count"`
	InstallationCount      int `json:"installation_count"`
}

// NotCounted is one class of evidence the report deliberately leaves out.
type NotCounted struct {
	Reason      string `json:"reason"`
	Description string `json:"description"`
	Count       int    `json:"count"`
}

// Basis states what the answer rests on, in the same shape PAT-2147/PAT-2148
// use.
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
	// PaidRulePending records that the ticket's "two or more paid products"
	// flag rule is not evaluated: it needs PAT-2143's price catalogue, which
	// does not exist yet. Always true today; kept as a field (rather than a
	// note string alone) so a caller can key logic on it without parsing
	// prose, and so it stops being true the day that catalogue lands and
	// this report is extended to use it.
	PaidRulePending bool     `json:"paid_products_rule_pending"`
	Complete        bool     `json:"complete"`
	Statement       string   `json:"statement"`
	Notes           []string `json:"notes"`
}

// Report is one tenant's duplicate-tools report.
type Report struct {
	Definition  Definition    `json:"definition"`
	GeneratedAt time.Time     `json:"generated_at"`
	Summary     Summary       `json:"summary"`
	Basis       Basis         `json:"basis"`
	Categories  []CategoryRow `json:"categories"`
	Rows        []Row         `json:"-"`
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

// catRule is one published software_category_rules row in one of this
// report's eight categories, with a non-NULL product_key.
type catRule struct {
	categorytag.RuleSpec
	ProductKey string
}

func loadCategoryRules(ctx context.Context, db softwaregov.Querier) ([]catRule, error) {
	rows, err := db.Query(ctx, `
		SELECT identifier_type, identifier_value, qualifier, platform, category_key, subtype_key, product_key
		FROM software_category_rules
		WHERE state = 'published' AND category_key = ANY($1::text[]) AND product_key IS NOT NULL`,
		Categories)
	if err != nil {
		return nil, fmt.Errorf("load category rules: %w", err)
	}
	defer rows.Close()
	var out []catRule
	for rows.Next() {
		var r catRule
		if err := rows.Scan(&r.IdentifierType, &r.IdentifierValue, &r.Qualifier, &r.Platform,
			&r.CategoryKey, &r.SubtypeKey, &r.ProductKey); err != nil {
			return nil, fmt.Errorf("scan category rule: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func loadCategoryDisplayNames(ctx context.Context, db softwaregov.Querier) (map[string]string, error) {
	rows, err := db.Query(ctx, `SELECT key, display_name FROM software_categories WHERE key = ANY($1::text[])`, Categories)
	if err != nil {
		return nil, fmt.Errorf("load categories: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, n string
		if err := rows.Scan(&k, &n); err != nil {
			return nil, fmt.Errorf("scan category: %w", err)
		}
		out[k] = n
	}
	return out, rows.Err()
}

// matchedRule reports the first published, product-keyed rule that matches
// an observation. A given observation is deliberately assigned to only one
// product: two rules for different products should never both match the
// same real identifier, but if they ever did, matchedRule keeps this
// report's grouping simple by taking the first configured match, the same
// convention internal/remoteaccess uses.
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
	displayNames, err := loadCategoryDisplayNames(ctx, db)
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
		state := resolveInstallState(pol, identityKind, identityValue, companion, teamID, signer, currentName, d.Platform)
		appendRows(&rep, d, rule, kind, currentName, currentVersion, identityValue, state, users)
	}
	irows.Close()
	if err := irows.Err(); err != nil {
		return rep, err
	}

	// Browser extensions: today only remote_access's Chrome Remote Desktop
	// rule matches a browser_extension identity. Each row is already
	// per-user (device_browser_extensions' unique key includes user_account).
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
		appendRows(&rep, d, rule, categorytag.KindBrowserExtension, name, version, extID, state, users)
	}
	erows.Close()
	if err := erows.Err(); err != nil {
		return rep, err
	}

	finish(&rep, devices, displayNames, unrecognised, retired)
	return rep, nil
}

// safariSystemUser mirrors internal/extractor.SafariSystemSentinel and
// internal/remoteaccess's own copy of the same constant: the fixed value
// device_browser_extensions.user_account carries for a Safari row, which has
// no real per-user account (PAT-2064).
const safariSystemUser = "_system"

// resolveInstallState resolves one installation's approval state, the same
// resolution internal/remoteaccess and the drift/posture surfaces use:
// Homebrew formulae/casks go through the homebrew policy table by (kind,
// name, tap); everything else goes through the application policy index.
func resolveInstallState(pol softwaregov.Policies, identityKind, identityValue, companion, teamID, signer, name, devicePlatform string) string {
	switch identityKind {
	case "homebrew_formula":
		return pol.ResolveHomebrew("formula", identityValue, companion)
	case "homebrew_cask":
		return pol.ResolveHomebrew("cask", identityValue, companion)
	}
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

func appendRows(rep *Report, d *deviceFacts, rule catRule, kind, name, version, identifier, state string, users []string) {
	pk := rule.CategoryKey + ":" + rule.ProductKey
	if len(users) == 0 {
		rep.Rows = append(rep.Rows, Row{
			DeviceID: d.ID, Hostname: d.Hostname, DeviceLastSeen: d.LastSeen, DeviceStale: d.Stale,
			Category: rule.CategoryKey, ProductKey: pk, ProductName: rule.ProductKey, Kind: kind,
			Platform: d.Platform, Identifier: identifier, Name: name, Version: version, ApprovalState: state,
			User: nil, MachineWide: true, LastSeen: d.LastSeen,
		})
		return
	}
	for _, u := range users {
		user := u
		rep.Rows = append(rep.Rows, Row{
			DeviceID: d.ID, Hostname: d.Hostname, DeviceLastSeen: d.LastSeen, DeviceStale: d.Stale,
			Category: rule.CategoryKey, ProductKey: pk, ProductName: rule.ProductKey, Kind: kind,
			Platform: d.Platform, Identifier: identifier, Name: name, Version: version, ApprovalState: state,
			User: &user, MachineWide: false, LastSeen: d.LastSeen,
		})
	}
}

// stateRank orders approval states from least to most favourable, the same
// precedence internal/remoteaccess sorts products by: an unsanctioned state
// always outranks a sanctioned one.
var stateRank = map[string]int{StateUnapproved: 0, StateUnreviewed: 1, StateIgnored: 2, StateApproved: 3}

func addStrings(set map[string]bool, order *[]string, s string) {
	if s == "" || set[s] {
		return
	}
	set[s] = true
	*order = append(*order, s)
}

func finish(rep *Report, devices map[string]*deviceFacts, displayNames map[string]string, unrecognised, retired int) {
	now := rep.GeneratedAt

	type group struct {
		row       ProductRow
		devices   map[string]bool
		stale     map[string]bool
		users     map[string]bool
		platforms map[string]bool
		platOrder []string
		kinds     map[string]bool
		kindOrder []string
		idents    map[string]bool
		identOrd  []string
		machine   int
	}
	groups := map[string]*group{}      // product key ("category:product_key")
	var order []string                 // insertion order of groups
	catGroups := map[string][]string{} // category -> product keys seen

	for _, r := range rep.Rows {
		g := groups[r.ProductKey]
		if g == nil {
			g = &group{
				row:     ProductRow{ProductKey: r.ProductKey, Category: r.Category, Name: r.ProductName},
				devices: map[string]bool{}, stale: map[string]bool{}, users: map[string]bool{},
				platforms: map[string]bool{}, kinds: map[string]bool{}, idents: map[string]bool{},
			}
			groups[r.ProductKey] = g
			order = append(order, r.ProductKey)
			catGroups[r.Category] = append(catGroups[r.Category], r.ProductKey)
		}
		g.row.Installations++
		g.devices[r.DeviceID] = true
		if r.DeviceStale {
			g.stale[r.DeviceID] = true
		}
		if r.User != nil {
			g.users[*r.User] = true
		} else {
			g.machine++
		}
		addStrings(g.platforms, &g.platOrder, r.Platform)
		addStrings(g.kinds, &g.kindOrder, r.Kind)
		addStrings(g.idents, &g.identOrd, r.Identifier)
		if g.row.ApprovalState == "" || stateRank[r.ApprovalState] < stateRank[g.row.ApprovalState] {
			g.row.ApprovalState = r.ApprovalState
		}
		if r.LastSeen.After(g.row.LastSeen) {
			g.row.LastSeen = r.LastSeen
		}
		// Prefer a real observed name over the bare product key if one was
		// seen; keep the first one found, for stable output.
		if g.row.Name == r.ProductName && r.Name != "" {
			g.row.Name = r.Name
		}
	}

	sort.Strings(order) // stable, deterministic product ordering within a category
	for _, key := range order {
		g := groups[key]
		g.row.DeviceCount = len(g.devices)
		g.row.StaleDeviceCount = len(g.stale)
		g.row.MachineWideCount = g.machine
		users := make([]string, 0, len(g.users))
		for u := range g.users {
			users = append(users, u)
		}
		sort.Strings(users)
		g.row.Users = users
		sort.Strings(g.platOrder)
		sort.Strings(g.kindOrder)
		sort.Strings(g.identOrd)
		g.row.Platforms = g.platOrder
		g.row.Kinds = g.kindOrder
		g.row.Identifiers = g.identOrd
	}

	var cats []CategoryRow
	sum := Summary{}
	for _, key := range Categories {
		productKeys := catGroups[key]
		if len(productKeys) == 0 {
			continue // never surface an empty category row
		}
		sum.CategoriesWithProducts++
		sort.Strings(productKeys)
		var products []ProductRow
		for _, pk := range productKeys {
			products = append(products, groups[pk].row)
		}
		sort.SliceStable(products, func(i, j int) bool {
			if products[i].Installations != products[j].Installations {
				return products[i].Installations > products[j].Installations
			}
			return products[i].Name < products[j].Name
		})
		flagged := len(products) >= MinProductsToFlag
		if flagged {
			sum.CategoriesFlagged++
		}
		sum.ProductCount += len(products)
		for _, p := range products {
			sum.InstallationCount += p.Installations
		}
		name := displayNames[key]
		if name == "" {
			name = key
		}
		cats = append(cats, CategoryRow{Category: key, DisplayName: name, Flagged: flagged,
			ProductCount: len(products), Products: products})
	}
	sort.SliceStable(cats, func(i, j int) bool {
		if cats[i].Flagged != cats[j].Flagged {
			return cats[i].Flagged // flagged categories first
		}
		return cats[i].DisplayName < cats[j].DisplayName
	})
	sum.CategoriesAssessed = len(Categories)
	rep.Categories = cats
	rep.Summary = sum

	sort.SliceStable(rep.Rows, func(i, j int) bool {
		a, b := rep.Rows[i], rep.Rows[j]
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.ProductKey != b.ProductKey {
			return a.ProductKey < b.ProductKey
		}
		if a.Hostname != b.Hostname {
			return a.Hostname < b.Hostname
		}
		if a.DeviceID != b.DeviceID {
			return a.DeviceID < b.DeviceID
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
		PaidRulePending: true, Statement: Statement,
		Notes: []string{
			"Devices your organisation has retired are left out of every figure and listed here as not counted. A device that has not reported for 14 days is still counted, marked stale, with the age of its evidence.",
			"A category is only as complete as its curated identities: a product not yet in Patched's catalogue for this category is never counted, so a category showing two products or none may still have real duplication Patched cannot yet see.",
			"The paid-products flag rule (two or more paid products in a category) is not evaluated: it needs a licence or price catalogue, which does not exist yet (see basis.paid_products_rule_pending).",
			"Approval state is your tenant's own existing decision on each installation (the same state PUT /v1/portal/software-approvals writes and GET /v1/portal/software/drift reads); a product's approval_state here is the least favourable state across its platforms, never a separate duplicate-tools allow list.",
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
