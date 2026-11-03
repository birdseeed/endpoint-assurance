package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"patched.im/api/internal/deviceretirement"
	"patched.im/api/internal/softwaregov"
)

// MaxReportRows bounds one tenant's load. Over it the report fails closed
// (ErrEstateTooLarge), never a partial answer.
const MaxReportRows = softwaregov.MaxEstateRows

// ErrEstateTooLarge means the tenant's inventory exceeds MaxReportRows.
var ErrEstateTooLarge = errors.New("lifecycle: estate inventory exceeds the load cap")

// Kinds of report row.
const (
	KindApplication     = "application"
	KindOperatingSystem = "operating_system"
)

// Definition names the saved report definition a response was computed
// from, so a reader can tell which rules produced it.
type Definition struct {
	ID                   string `json:"id"`
	Version              int    `json:"version"`
	Title                string `json:"title"`
	EndingWindowDays     int    `json:"ending_window_days"`
	LifecycleCacheTTLDay int    `json:"lifecycle_cache_ttl_days"`
	StaleAfterDays       int    `json:"stale_after_days"`
	LifecycleSource      string `json:"lifecycle_source"`
}

// ReportDefinition is the one saved definition of this report (PAT-2146:
// each SAM report is a saved definition over existing read APIs).
var ReportDefinition = Definition{
	ID:                   "sam.unsupported-software",
	Version:              1,
	Title:                "Unsupported software",
	EndingWindowDays:     EndingWindowDays,
	LifecycleCacheTTLDay: int(CacheTTL / (24 * time.Hour)),
	StaleAfterDays:       int(softwaregov.StaleAfter / (24 * time.Hour)),
	LifecycleSource:      SourceName,
}

// Source is the lifecycle source of a row.
type Source struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
	URL  string `json:"url"`
}

// Row is one installation (or one device's operating system) and its state.
type Row struct {
	DeviceID       string     `json:"device_id"`
	Hostname       string     `json:"hostname"`
	DeviceLastSeen time.Time  `json:"device_last_seen"`
	DeviceStale    bool       `json:"device_stale"`
	Kind           string     `json:"kind"`
	ProductKey     string     `json:"product_key"`
	Name           string     `json:"name"`
	Platform       string     `json:"platform"`
	Version        string     `json:"version"`
	Edition        string     `json:"edition,omitempty"`
	State          string     `json:"state"`
	Cycle          *string    `json:"cycle"`
	EOLDate        *string    `json:"eol_date"`
	DaysToEOL      *int       `json:"days_to_eol"`
	Source         *Source    `json:"source"`
	LastCheckedAt  *time.Time `json:"last_checked_at"`
	Reason         *string    `json:"unknown_reason"`
	ReasonText     *string    `json:"unknown_reason_text"`
	Note           *string    `json:"note"`
}

// ProductRow groups rows by product, version and outcome.
type ProductRow struct {
	ProductKey        string     `json:"product_key"`
	Kind              string     `json:"kind"`
	Name              string     `json:"name"`
	Platform          string     `json:"platform"`
	Version           string     `json:"version"`
	Edition           string     `json:"edition,omitempty"`
	State             string     `json:"state"`
	Cycle             *string    `json:"cycle"`
	EOLDate           *string    `json:"eol_date"`
	DaysToEOL         *int       `json:"days_to_eol"`
	DeviceCount       int        `json:"device_count"`
	StaleDeviceCount  int        `json:"stale_device_count"`
	InstallationCount int        `json:"installation_count"`
	Source            *Source    `json:"source"`
	LastCheckedAt     *time.Time `json:"last_checked_at"`
	Reason            *string    `json:"unknown_reason"`
	ReasonText        *string    `json:"unknown_reason_text"`
	Note              *string    `json:"note"`
}

// StateCount is one state's totals.
type StateCount struct {
	Installations int `json:"installation_count"`
	Devices       int `json:"device_count"`
}

// Summary is the per-state totals.
type Summary struct {
	States          map[string]StateCount `json:"states"`
	UnknownByReason map[string]int        `json:"unknown_by_reason"`
	Installations   int                   `json:"installation_count"`
}

// NotCounted is one class of evidence the report deliberately leaves out.
type NotCounted struct {
	Reason      string `json:"reason"`
	Description string `json:"description"`
	Count       int    `json:"count"`
}

// Basis states what the answer rests on.
type Basis struct {
	GeneratedAt              time.Time    `json:"generated_at"`
	EvidenceNewestAt         *time.Time   `json:"evidence_newest_at"`
	EvidenceOldestAt         *time.Time   `json:"evidence_oldest_at"`
	DevicesTotal             int          `json:"devices_total"`
	DevicesAssessed          int          `json:"devices_assessed"`
	DevicesReporting         int          `json:"devices_reporting"`
	DevicesStale             int          `json:"devices_stale"`
	DevicesWithoutInventory  int          `json:"devices_without_inventory"`
	StaleAfterDays           int          `json:"stale_after_days"`
	LifecycleSource          string       `json:"lifecycle_source"`
	LifecycleCheckedOldestAt *time.Time   `json:"lifecycle_checked_oldest_at"`
	LifecycleCheckedNewestAt *time.Time   `json:"lifecycle_checked_newest_at"`
	RetiredDevicesExcluded   bool         `json:"retired_devices_excluded"`
	DevicesRetired           int          `json:"devices_retired"`
	NotCounted               []NotCounted `json:"not_counted"`
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

// Statement is the report's standing caveat.
const Statement = "An estimate from the software and operating system versions your devices reported, " +
	"compared with public end of support dates from endoflife.date. It is not an audit or a compliance " +
	"position. Unknown means Patched could not determine support; it never means supported."

// Report is one tenant's unsupported software report.
type Report struct {
	Definition      Definition              `json:"definition"`
	GeneratedAt     time.Time               `json:"generated_at"`
	Summary         Summary                 `json:"summary"`
	Basis           Basis                   `json:"basis"`
	CyberEssentials CyberEssentialsEvidence `json:"cyber_essentials"`
	Products        []ProductRow            `json:"-"`
	Rows            []Row                   `json:"-"`
}

type deviceFacts struct {
	ID, Hostname, Platform, OSVersion, OSBuild, OSCaption string
	LastSeen                                              time.Time
	Stale, HasInventory                                   bool
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

func strp(s string) *string { return &s }

func fmtDate(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format("2006-01-02")
	return &s
}

// countInstallations returns the tenant's current, live installation count
// (removed_at IS NULL), unfiltered by identity kind. Every report over
// software_installations shares this one estate-size cap check
// (MaxReportRows) so two reports never disagree on when an estate is too
// large to assess in one request.
func countInstallations(ctx context.Context, db DB, tenantID string) (int, error) {
	var total int
	if err := db.QueryRow(ctx, `
		SELECT count(*)::int FROM software_installations
		WHERE tenant_id = $1::uuid AND removed_at IS NULL`, tenantID).Scan(&total); err != nil {
		return 0, fmt.Errorf("count installations: %w", err)
	}
	return total, nil
}

// loadDeviceFacts loads every device in the tenant, classifying it into the
// non-retired, recognised-platform set (devices, order) a report assesses,
// plus how many were excluded for an unrecognised platform or because the
// customer retired them (PAT-2135). Shared by every report over
// software_installations so retirement and platform recognition are applied
// identically everywhere.
func loadDeviceFacts(ctx context.Context, db DB, tenantID string, staleCut time.Time) (devices map[string]*deviceFacts, order []*deviceFacts, unrecognised, retired int, err error) {
	drows, err := db.Query(ctx, `
		SELECT d.id::text, COALESCE(NULLIF(d.computer_name, ''), NULLIF(d.hostname, ''), ''),
		       COALESCE(d.os, ''), COALESCE(d.os_version, ''), COALESCE(d.os_build, ''), COALESCE(d.os_caption, ''),
		       d.last_seen,
		       EXISTS (SELECT 1 FROM software_installations si
		               WHERE si.device_id = d.id AND si.tenant_id = d.tenant_id AND si.removed_at IS NULL),
		       r.retired
		FROM devices d
		CROSS JOIN LATERAL (SELECT `+deviceretirement.RetiredSQL("d")+` AS retired) r
		WHERE d.tenant_id = $1::uuid
		ORDER BY d.id`, tenantID)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("load devices: %w", err)
	}
	devices = map[string]*deviceFacts{}
	for drows.Next() {
		var d deviceFacts
		var os string
		var isRetired bool
		if err := drows.Scan(&d.ID, &d.Hostname, &os, &d.OSVersion, &d.OSBuild, &d.OSCaption, &d.LastSeen, &d.HasInventory, &isRetired); err != nil {
			drows.Close()
			return nil, nil, 0, 0, fmt.Errorf("scan device: %w", err)
		}
		d.Platform = platformOf(os)
		d.Stale = d.LastSeen.Before(staleCut)
		// PAT-2135: a device the customer retired is excluded from every row,
		// the drill-down and the counts, and reported in the basis.
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
		order = append(order, &dd)
	}
	drows.Close()
	if err := drows.Err(); err != nil {
		return nil, nil, 0, 0, err
	}
	return devices, order, unrecognised, retired, nil
}

// Build computes the report for one tenant. tenantID must come from an
// authenticated identity; every query is scoped to it.
func Build(ctx context.Context, db DB, tenantID string, now time.Time) (Report, error) {
	now = now.UTC()
	rep := Report{Definition: ReportDefinition, GeneratedAt: now}
	staleCut := now.Add(-softwaregov.StaleAfter)

	total, err := countInstallations(ctx, db, tenantID)
	if err != nil {
		return rep, err
	}
	if total > MaxReportRows {
		return rep, ErrEstateTooLarge
	}

	devices, order, unrecognised, retired, err := loadDeviceFacts(ctx, db, tenantID, staleCut)
	if err != nil {
		return rep, err
	}
	rep.Basis.DevicesTotal = len(devices) + unrecognised + retired

	mappings, slugs, err := loadPublished(ctx, db)
	if err != nil {
		return rep, err
	}
	products, err := LoadProducts(ctx, db, slugs)
	if err != nil {
		return rep, err
	}
	lookup := func(k identityKey) (*MappingRef, *Product) {
		pm, ok := mappings[k]
		if !ok {
			return nil, nil
		}
		ref := pm.Ref
		return &ref, products[ref.Slug]
	}

	// Operating system rows, one per device.
	for _, d := range order {
		ref, prod := lookup(identityKey{Platform: d.Platform, Kind: IdentityKindOS, Value: d.Platform})
		os := &OSInput{Version: d.OSVersion, Build: d.OSBuild, Caption: d.OSCaption}
		ev := Evaluate(ref, prod, "", os, now)
		name := "macOS"
		version := d.OSVersion
		edition := ""
		if d.Platform == "windows" {
			name = "Windows"
			if b, ok := WindowsBuild(d.OSVersion, d.OSBuild); ok {
				version = fmt.Sprintf("10.0.%d", b)
				if b < 10000 {
					version = strings.TrimSpace(d.OSVersion)
				}
			}
			edition = strings.TrimSpace(d.OSCaption)
		}
		rep.Rows = append(rep.Rows, makeRow(d, KindOperatingSystem, "os:"+d.Platform, name, version, edition, ev))
	}

	// Application rows.
	irows, err := db.Query(ctx, `
		SELECT si.device_id::text, si.platform, si.identity_kind, si.identity_value_normalized,
		       si.companion_value_normalized, si.identity_fingerprint, si.current_name,
		       COALESCE(si.current_version, '')
		FROM software_installations si
		WHERE si.tenant_id = $1::uuid AND si.removed_at IS NULL AND si.identity_kind = ANY($2)
		ORDER BY si.device_id, si.identity_fingerprint`, tenantID, ReportIdentityKinds)
	if err != nil {
		return rep, fmt.Errorf("load installations: %w", err)
	}
	for irows.Next() {
		var deviceID, platform, kind, value, companion, fp, name, version string
		if err := irows.Scan(&deviceID, &platform, &kind, &value, &companion, &fp, &name, &version); err != nil {
			irows.Close()
			return rep, fmt.Errorf("scan installation: %w", err)
		}
		d := devices[deviceID]
		if d == nil {
			continue // a retired or unrecognised-platform device, counted in basis
		}
		ref, prod := lookup(identityKey{Platform: platform, Kind: kind, Value: value, Companion: companion})
		ev := Evaluate(ref, prod, version, nil, now)
		rep.Rows = append(rep.Rows, makeRow(d, KindApplication, "app:"+fp, name, version, "", ev))
	}
	irows.Close()
	if err := irows.Err(); err != nil {
		return rep, err
	}

	// Installations outside the report, by class.
	var tooling, taps int
	if err := db.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE si.identity_kind <> 'homebrew_tap')::int,
		       count(*) FILTER (WHERE si.identity_kind = 'homebrew_tap')::int
		FROM software_installations si
		JOIN devices d ON d.id = si.device_id AND d.tenant_id = si.tenant_id
		WHERE si.tenant_id = $1::uuid AND si.removed_at IS NULL AND NOT (si.identity_kind = ANY($2))
		  AND NOT (`+deviceretirement.RetiredSQL("d")+`)`,
		tenantID, ReportIdentityKinds).Scan(&tooling, &taps); err != nil {
		return rep, fmt.Errorf("count excluded installations: %w", err)
	}

	finish(&rep, order, unrecognised, retired, tooling, taps)
	return rep, nil
}

func makeRow(d *deviceFacts, kind, key, name, version, edition string, ev Evaluation) Row {
	r := Row{
		DeviceID: d.ID, Hostname: d.Hostname, DeviceLastSeen: d.LastSeen.UTC(), DeviceStale: d.Stale,
		Kind: kind, ProductKey: key, Name: name, Platform: d.Platform, Version: version, Edition: edition,
		State: ev.State, DaysToEOL: ev.DaysToEOL, LastCheckedAt: ev.LastCheckedAt,
	}
	if ev.Slug != "" {
		r.Source = &Source{Name: SourceName, Slug: ev.Slug, URL: ev.SourceURL}
	}
	if ev.Cycle != nil {
		r.Cycle = strp(ev.Cycle.Name)
		r.EOLDate = fmtDate(ev.Cycle.EOLDate)
	}
	if ev.State == StateUnknown {
		r.Reason = strp(ev.Reason)
		r.ReasonText = strp(ReasonText[ev.Reason])
	}
	if ev.Note != "" {
		r.Note = strp(ev.Note)
	}
	return r
}

var stateRank = map[string]int{StateUnsupported: 0, StateEndingSoon: 1, StateUnknown: 2, StateSupported: 3}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// finish derives the summary, product rows, basis and Cyber Essentials
// evidence from the rows.
func finish(rep *Report, devices []*deviceFacts, unrecognised, retired, tooling, taps int) {
	now := rep.GeneratedAt
	sum := Summary{States: map[string]StateCount{}, UnknownByReason: map[string]int{}}
	stateDevices := map[string]map[string]bool{}
	for _, s := range States {
		sum.States[s] = StateCount{}
		stateDevices[s] = map[string]bool{}
	}
	type group struct {
		row     ProductRow
		devices map[string]bool
		stale   map[string]bool
		names   map[string]int
	}
	groups := map[string]*group{}
	var groupOrder []string
	var checkedOldest, checkedNewest *time.Time
	for _, r := range rep.Rows {
		sc := sum.States[r.State]
		sc.Installations++
		sum.States[r.State] = sc
		stateDevices[r.State][r.DeviceID] = true
		sum.Installations++
		if r.Reason != nil {
			sum.UnknownByReason[*r.Reason]++
		}
		if t := r.LastCheckedAt; t != nil {
			if checkedOldest == nil || t.Before(*checkedOldest) {
				tt := *t
				checkedOldest = &tt
			}
			if checkedNewest == nil || t.After(*checkedNewest) {
				tt := *t
				checkedNewest = &tt
			}
		}
		gk := strings.Join([]string{r.ProductKey, r.Version, r.Edition, r.State, derefStr(r.Cycle), derefStr(r.Reason)}, "\x1f")
		g := groups[gk]
		if g == nil {
			g = &group{row: ProductRow{
				ProductKey: r.ProductKey, Kind: r.Kind, Platform: r.Platform, Version: r.Version, Edition: r.Edition,
				State: r.State, Cycle: r.Cycle, EOLDate: r.EOLDate, DaysToEOL: r.DaysToEOL, Source: r.Source,
				LastCheckedAt: r.LastCheckedAt, Reason: r.Reason, ReasonText: r.ReasonText, Note: r.Note,
			}, devices: map[string]bool{}, stale: map[string]bool{}, names: map[string]int{}}
			groups[gk] = g
			groupOrder = append(groupOrder, gk)
		}
		g.row.InstallationCount++
		g.devices[r.DeviceID] = true
		if r.DeviceStale {
			g.stale[r.DeviceID] = true
		}
		g.names[r.Name]++
	}
	for _, s := range States {
		sc := sum.States[s]
		sc.Devices = len(stateDevices[s])
		sum.States[s] = sc
	}
	rep.Summary = sum

	for _, gk := range groupOrder {
		g := groups[gk]
		g.row.DeviceCount = len(g.devices)
		g.row.StaleDeviceCount = len(g.stale)
		best, bestN := "", -1
		for n, c := range g.names {
			if c > bestN || (c == bestN && n < best) {
				best, bestN = n, c
			}
		}
		g.row.Name = best
		rep.Products = append(rep.Products, g.row)
	}
	sort.SliceStable(rep.Products, func(i, j int) bool {
		a, b := rep.Products[i], rep.Products[j]
		if stateRank[a.State] != stateRank[b.State] {
			return stateRank[a.State] < stateRank[b.State]
		}
		if (a.DaysToEOL == nil) != (b.DaysToEOL == nil) {
			return a.DaysToEOL != nil
		}
		if a.DaysToEOL != nil && *a.DaysToEOL != *b.DaysToEOL {
			return *a.DaysToEOL < *b.DaysToEOL
		}
		if a.Kind != b.Kind {
			return a.Kind == KindOperatingSystem
		}
		if !strings.EqualFold(a.Name, b.Name) {
			return strings.ToLower(a.Name) < strings.ToLower(b.Name)
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.ProductKey < b.ProductKey
	})
	sort.SliceStable(rep.Rows, func(i, j int) bool {
		a, b := rep.Rows[i], rep.Rows[j]
		if stateRank[a.State] != stateRank[b.State] {
			return stateRank[a.State] < stateRank[b.State]
		}
		if a.Hostname != b.Hostname {
			return a.Hostname < b.Hostname
		}
		if a.DeviceID != b.DeviceID {
			return a.DeviceID < b.DeviceID
		}
		if a.Kind != b.Kind {
			return a.Kind == KindOperatingSystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ProductKey < b.ProductKey
	})

	b := Basis{
		GeneratedAt: now, StaleAfterDays: int(softwaregov.StaleAfter / (24 * time.Hour)),
		LifecycleSource: SourceName, LifecycleCheckedOldestAt: checkedOldest, LifecycleCheckedNewestAt: checkedNewest,
		Statement: Statement, DevicesTotal: rep.Basis.DevicesTotal,
		RetiredDevicesExcluded: true, DevicesRetired: retired,
		Notes: []string{
			"Devices your organisation has retired are left out of every figure and listed here as not counted. A device that has not reported for 14 days is still counted, marked stale, with the age of its evidence.",
			"Supported, Ending within 90 days and Unsupported rely on a staff-reviewed mapping from the installed product to its endoflife.date entry. A product with no reviewed mapping reads Unknown.",
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
		{Reason: "developer_tooling", Description: "IDE extensions, language packages, local models and MCP servers are not assessed by this report", Count: tooling},
		{Reason: "homebrew_taps", Description: "Homebrew taps are package sources, not installed software", Count: taps},
	}
	b.Complete = b.DevicesAssessed > 0 && b.DevicesStale == 0 && b.DevicesWithoutInventory == 0 &&
		unrecognised == 0 && sum.States[StateUnknown].Installations == 0
	rep.Basis = b
	rep.CyberEssentials = cyberEssentials(rep)
}

// CyberEssentialsEvidence is the shape PAT-1927's Cyber Essentials
// readiness view consumes: the Unsupported findings as evidence against the
// security update management requirement (in-scope software must be
// licensed and supported). It is evidence only, never a pass or fail.
type CyberEssentialsEvidence struct {
	Requirement                    string     `json:"requirement"`
	EvidenceKind                   string     `json:"evidence_kind"`
	Position                       string     `json:"position"`
	Statement                      string     `json:"statement"`
	EvidenceAt                     time.Time  `json:"evidence_at"`
	DevicesAssessed                int        `json:"devices_assessed"`
	DevicesWithUnsupportedSoftware int        `json:"devices_with_unsupported_software"`
	DevicesWithUnknownSupport      int        `json:"devices_with_unknown_support"`
	UnsupportedInstallationCount   int        `json:"unsupported_installation_count"`
	Complete                       bool       `json:"complete"`
	Devices                        []CEDevice `json:"devices"`
}

// CEDevice is one device carrying unsupported software.
type CEDevice struct {
	DeviceID       string    `json:"device_id"`
	Hostname       string    `json:"hostname"`
	DeviceLastSeen time.Time `json:"device_last_seen"`
	DeviceStale    bool      `json:"device_stale"`
	Unsupported    []CEItem  `json:"unsupported"`
}

// CEItem is one unsupported installation on a device.
type CEItem struct {
	Kind          string     `json:"kind"`
	ProductKey    string     `json:"product_key"`
	Name          string     `json:"name"`
	Version       string     `json:"version"`
	Cycle         *string    `json:"cycle"`
	EOLDate       *string    `json:"eol_date"`
	Source        *Source    `json:"source"`
	LastCheckedAt *time.Time `json:"last_checked_at"`
	Note          *string    `json:"note"`
}

func cyberEssentials(rep *Report) CyberEssentialsEvidence {
	ce := CyberEssentialsEvidence{
		Requirement:  "security_update_management",
		EvidenceKind: "unsupported_software",
		Position:     "evidence_only",
		Statement: "Cyber Essentials requires in-scope software to be licensed and supported. These devices " +
			"reported software past its vendor's end of support. This is evidence for a readiness review, not an assessment result.",
		EvidenceAt:      rep.GeneratedAt,
		DevicesAssessed: rep.Basis.DevicesAssessed,
		Complete:        rep.Basis.Complete,
		Devices:         []CEDevice{},
	}
	byDevice := map[string]int{} // index into ce.Devices
	unknownDevices := map[string]bool{}
	for _, r := range rep.Rows {
		switch r.State {
		case StateUnknown:
			unknownDevices[r.DeviceID] = true
		case StateUnsupported:
			ce.UnsupportedInstallationCount++
			i, ok := byDevice[r.DeviceID]
			if !ok {
				ce.Devices = append(ce.Devices, CEDevice{DeviceID: r.DeviceID, Hostname: r.Hostname,
					DeviceLastSeen: r.DeviceLastSeen, DeviceStale: r.DeviceStale, Unsupported: []CEItem{}})
				i = len(ce.Devices) - 1
				byDevice[r.DeviceID] = i
			}
			ce.Devices[i].Unsupported = append(ce.Devices[i].Unsupported, CEItem{Kind: r.Kind, ProductKey: r.ProductKey,
				Name: r.Name, Version: r.Version, Cycle: r.Cycle, EOLDate: r.EOLDate, Source: r.Source,
				LastCheckedAt: r.LastCheckedAt, Note: r.Note})
		}
	}
	ce.DevicesWithUnsupportedSoftware = len(ce.Devices)
	ce.DevicesWithUnknownSupport = len(unknownDevices)
	return ce
}

// FetchCyberEssentialsEvidence is the entry point for PAT-1927: the
// Unsupported evidence for one tenant, computed from the same report.
func FetchCyberEssentialsEvidence(ctx context.Context, db DB, tenantID string, now time.Time) (CyberEssentialsEvidence, error) {
	rep, err := Build(ctx, db, tenantID, now)
	if err != nil {
		return CyberEssentialsEvidence{}, err
	}
	return rep.CyberEssentials, nil
}
