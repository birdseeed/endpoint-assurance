package driverblock

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Read models for GET /v1/portal/devices/{id} (kernel_drivers) and
// GET /v1/portal/driver-findings. Every query is scoped to the caller's
// tenant; the list tables are global and only ever joined onto a tenant's
// own driver rows, so a list entry can decorate a tenant's driver but can
// never introduce another tenant's.
//
// Match semantics, per driver row:
//
//   - "listed": at least one of the row's reported hashes (flat SHA-256,
//     flat SHA-1, Authenticode SHA-256, Authenticode SHA-1) equals a listed
//     hash of the same kind. File names play no part.
//   - "no_hash_match": the row was hashed and at least one list has been
//     fetched successfully, and nothing matched. This is not "safe" and not
//     "not on Microsoft's list": Microsoft's signer and file-attribute rules
//     are not evaluated, and a list can be stale (see ListState.Stale).
//   - "unknown": the row carries no hash (the agent could not read the file,
//     refused a reparse point, hit a bound, or the file is missing), or no
//     list has ever been fetched.

const (
	MatchListed      = "listed"
	MatchNoHashMatch = "no_hash_match"
	MatchUnknown     = "unknown"

	UnknownNotHashed        = "not_hashed"
	UnknownListsUnavailable = "lists_unavailable"

	StatusNotReported = "not_reported"

	// DeviceDriversMax bounds the rows returned on the device view: listed
	// rows first, then unknown rows. Clean rows are counted, not listed.
	DeviceDriversMax = 200
)

// ListState is one list's provenance as a reader sees it.
type ListState struct {
	Source      string     `json:"source"`
	SourceURL   string     `json:"source_url"`
	Status      string     `json:"status"` // succeeded | failed | never_fetched
	FetchedAt   *time.Time `json:"fetched_at"`
	AttemptedAt *time.Time `json:"attempted_at"`
	Revision    string     `json:"list_version"`
	EntryCount  int        `json:"entry_count"`
	Stale       bool       `json:"stale"`
}

// Match is one list entry a driver's hash is on.
type Match struct {
	Source        string    `json:"source"`
	SourceURL     string    `json:"source_url"`
	Category      string    `json:"category"`
	EntryID       string    `json:"entry_id"`
	EntryName     string    `json:"entry_name"`
	HashKind      string    `json:"hash_kind"`
	Hash          string    `json:"hash"`
	ListVersion   string    `json:"list_version"`
	ListFetchedAt time.Time `json:"list_fetched_at"`
	ListStale     bool      `json:"list_stale"`
}

// Enforcement is the device's newest reported blocklist enforcement state.
type Enforcement struct {
	VulnerableDriverBlocklist string `json:"vulnerable_driver_blocklist"`
	HVCI                      string `json:"hvci"`
	SmartAppControl           string `json:"smart_app_control"`
	CodeIntegrityPolicy       string `json:"code_integrity_policy"`
	BlocklistEnforced         string `json:"blocklist_enforced"`
}

// DriverRow is one current driver row with its match outcome.
type DriverRow struct {
	Path               *string   `json:"path"`
	ServiceName        *string   `json:"service_name"`
	ServiceType        *string   `json:"service_type"`
	StartType          *string   `json:"start_type"`
	Loaded             *bool     `json:"loaded"`
	Sources            []string  `json:"sources"`
	HashStatus         string    `json:"hash_status"`
	UnhashedReason     *string   `json:"unhashed_reason"`
	Version            *string   `json:"version"`
	SHA256             *string   `json:"sha256"`
	AuthenticodeSHA256 *string   `json:"authenticode_sha256"`
	ReportedAt         time.Time `json:"reported_at"`
	FirstSeenAt        time.Time `json:"first_seen_at"`
	MatchStatus        string    `json:"match_status"`
	UnknownReason      *string   `json:"unknown_reason"`
	Matches            []Match   `json:"matches"`
	driverKey          string
	sortKey            string
}

// DeviceSummary counts a device's current rows by outcome.
type DeviceSummary struct {
	Drivers         int `json:"drivers"`
	Hashed          int `json:"hashed"`
	Unhashed        int `json:"unhashed"`
	Listed          int `json:"listed"`
	ListedMalicious int `json:"listed_malicious"`
	Unknown         int `json:"unknown"`
}

// DeviceDrivers is the device view.
type DeviceDrivers struct {
	Status           string        `json:"status"` // not_reported | complete | partial | unavailable
	ReportedAt       *time.Time    `json:"reported_at"`
	ObservedAt       *time.Time    `json:"observed_at"`
	Errors           []string      `json:"errors"`
	Enforcement      *Enforcement  `json:"enforcement"`
	Lists            []ListState   `json:"lists"`
	Summary          DeviceSummary `json:"summary"`
	Drivers          []DriverRow   `json:"drivers"`
	DriversTruncated bool          `json:"drivers_truncated"`
}

// ListStates returns every source's provenance, in Sources order, including
// sources never fetched.
func ListStates(states map[string]SourceState, now time.Time) []ListState {
	out := make([]ListState, 0, len(Sources))
	for _, source := range Sources {
		authority, _ := AuthorityURL(source)
		st, ok := states[source]
		if !ok {
			out = append(out, ListState{Source: source, SourceURL: authority, Status: "never_fetched", Stale: true})
			continue
		}
		attempted := st.AttemptedAt.UTC()
		out = append(out, ListState{
			Source: source, SourceURL: st.SourceURL, Status: st.Status, FetchedAt: utcPtr(st.FetchedAt),
			AttemptedAt: &attempted, Revision: st.SourceRevision, EntryCount: st.EntryCount, Stale: st.Stale(now),
		})
	}
	return out
}

func anyListFetched(states map[string]SourceState) bool {
	for _, st := range states {
		if st.FetchedAt != nil {
			return true
		}
	}
	return false
}

// FetchDevice reads one device's driver view, scoped to tenantID. No state
// row is "not_reported", never an error.
func FetchDevice(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string, now time.Time) (DeviceDrivers, error) {
	out := DeviceDrivers{Status: StatusNotReported, Errors: []string{}, Lists: []ListState{}, Drivers: []DriverRow{}}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, fmt.Errorf("begin device driver read: %w", err)
	}
	defer tx.Rollback(ctx)

	states, err := LoadSourceStates(ctx, tx)
	if err != nil {
		return out, fmt.Errorf("load driver list state: %w", err)
	}
	out.Lists = ListStates(states, now)

	var (
		status     string
		errs       []string
		reportedAt time.Time
		observedAt *time.Time
		enf        Enforcement
	)
	err = tx.QueryRow(ctx, `SELECT collection_status, errors, reported_at, observed_at,
			vulnerable_driver_blocklist, hvci, smart_app_control, code_integrity_policy, blocklist_enforced
		FROM device_kernel_driver_state
		WHERE device_id = $1::uuid AND tenant_id = $2::uuid`, deviceID, tenantID).Scan(
		&status, &errs, &reportedAt, &observedAt,
		&enf.VulnerableDriverBlocklist, &enf.HVCI, &enf.SmartAppControl, &enf.CodeIntegrityPolicy, &enf.BlocklistEnforced)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, tx.Commit(ctx)
	}
	if err != nil {
		return out, fmt.Errorf("read device driver state: %w", err)
	}
	out.Status = status
	reported := reportedAt.UTC()
	out.ReportedAt = &reported
	out.ObservedAt = utcPtr(observedAt)
	if errs != nil {
		out.Errors = errs
	}
	out.Enforcement = &enf

	rows, err := loadDriverRows(ctx, tx, tenantID, deviceID)
	if err != nil {
		return out, err
	}
	if err := attachMatches(ctx, tx, tenantID, deviceID, rows, states, now); err != nil {
		return out, err
	}
	if err := tx.Commit(ctx); err != nil {
		return out, fmt.Errorf("commit device driver read: %w", err)
	}

	listsFetched := anyListFetched(states)
	var shown []DriverRow
	for i := range rows {
		r := &rows[i]
		classify(r, listsFetched)
		out.Summary.Drivers++
		if r.HashStatus == "hashed" {
			out.Summary.Hashed++
		} else {
			out.Summary.Unhashed++
		}
		switch r.MatchStatus {
		case MatchListed:
			out.Summary.Listed++
			if hasMalicious(r.Matches) {
				out.Summary.ListedMalicious++
			}
			shown = append(shown, *r)
		case MatchUnknown:
			out.Summary.Unknown++
			shown = append(shown, *r)
		}
	}
	sort.SliceStable(shown, func(i, j int) bool {
		a, b := rank(shown[i]), rank(shown[j])
		if a != b {
			return a < b
		}
		return shown[i].sortKey < shown[j].sortKey
	})
	if len(shown) > DeviceDriversMax {
		shown = shown[:DeviceDriversMax]
		out.DriversTruncated = true
	}
	if shown != nil {
		out.Drivers = shown
	}
	return out, nil
}

func rank(r DriverRow) int {
	switch {
	case r.MatchStatus == MatchListed && hasMalicious(r.Matches):
		return 0
	case r.MatchStatus == MatchListed:
		return 1
	default:
		return 2
	}
}

func hasMalicious(matches []Match) bool {
	for _, m := range matches {
		if m.Category == CategoryMalicious {
			return true
		}
	}
	return false
}

func classify(r *DriverRow, listsFetched bool) {
	switch {
	case len(r.Matches) > 0:
		r.MatchStatus = MatchListed
	case r.HashStatus != "hashed":
		r.MatchStatus = MatchUnknown
		reason := UnknownNotHashed
		r.UnknownReason = &reason
	case !listsFetched:
		r.MatchStatus = MatchUnknown
		reason := UnknownListsUnavailable
		r.UnknownReason = &reason
	default:
		r.MatchStatus = MatchNoHashMatch
	}
	if r.Matches == nil {
		r.Matches = []Match{}
	}
	if r.Sources == nil {
		r.Sources = []string{}
	}
}

type querier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// loadDriverRows reads a device's current rows, ordered by key.
func loadDriverRows(ctx context.Context, q querier, tenantID, deviceID string) ([]DriverRow, error) {
	rows, err := q.Query(ctx, `SELECT driver_key, path, service_name, service_type, start_type, loaded, sources,
			hash_status, unhashed_reason, version, sha256, authenticode_sha256, reported_at, first_seen_at
		FROM device_kernel_drivers
		WHERE device_id = $1::uuid AND tenant_id = $2::uuid
		ORDER BY driver_key`, deviceID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read device driver rows: %w", err)
	}
	defer rows.Close()
	var out []DriverRow
	for rows.Next() {
		var r DriverRow
		if err := rows.Scan(&r.driverKey, &r.Path, &r.ServiceName, &r.ServiceType, &r.StartType, &r.Loaded, &r.Sources,
			&r.HashStatus, &r.UnhashedReason, &r.Version, &r.SHA256, &r.AuthenticodeSHA256, &r.ReportedAt, &r.FirstSeenAt); err != nil {
			return nil, err
		}
		r.ReportedAt = r.ReportedAt.UTC()
		r.FirstSeenAt = r.FirstSeenAt.UTC()
		r.sortKey = r.driverKey
		out = append(out, r)
	}
	return out, rows.Err()
}

// matchSQL joins a tenant's driver rows to the list by hash kind and value.
// $1 tenant; $2 device (NULL for the whole tenant).
const matchSQL = `
	SELECT d.device_id::text, d.driver_key, e.source, e.category, e.entry_id, e.entry_name, h.kind, h.hash,
	       e.source_revision, e.fetched_at
	FROM device_kernel_drivers d
	CROSS JOIN LATERAL (VALUES
		('sha256', d.sha256), ('sha1', d.sha1),
		('authenticode_sha256', d.authenticode_sha256), ('authenticode_sha1', d.authenticode_sha1)
	) AS h(kind, hash)
	JOIN driver_blocklist_entries e ON e.hash_kind = h.kind AND e.hash = h.hash
	WHERE d.tenant_id = $1::uuid
	  AND ($2::uuid IS NULL OR d.device_id = $2::uuid)
	  AND d.hash_status = 'hashed'
	  AND h.hash IS NOT NULL
	ORDER BY d.device_id, d.driver_key, e.source, e.entry_id, h.kind`

func attachMatches(ctx context.Context, q querier, tenantID, deviceID string, rows []DriverRow, states map[string]SourceState, now time.Time) error {
	byKey := make(map[string]*DriverRow, len(rows))
	for i := range rows {
		byKey[rows[i].driverKey] = &rows[i]
	}
	res, err := q.Query(ctx, matchSQL, tenantID, deviceID)
	if err != nil {
		return fmt.Errorf("match device drivers: %w", err)
	}
	defer res.Close()
	for res.Next() {
		var devID, key string
		var m Match
		if err := res.Scan(&devID, &key, &m.Source, &m.Category, &m.EntryID, &m.EntryName, &m.HashKind, &m.Hash,
			&m.ListVersion, &m.ListFetchedAt); err != nil {
			return err
		}
		decorate(&m, states, now)
		if r := byKey[key]; r != nil {
			r.Matches = append(r.Matches, m)
		}
	}
	return res.Err()
}

func decorate(m *Match, states map[string]SourceState, now time.Time) {
	m.ListFetchedAt = m.ListFetchedAt.UTC()
	m.SourceURL, _ = AuthorityURL(m.Source)
	st, ok := states[m.Source]
	m.ListStale = !ok || st.Stale(now)
}

// ---------------------------------------------------------------------------
// Estate findings
// ---------------------------------------------------------------------------

// Finding is one listed driver on one device.
type Finding struct {
	DeviceID          string    `json:"device_id"`
	Hostname          string    `json:"hostname"`
	Path              *string   `json:"path"`
	ServiceName       *string   `json:"service_name"`
	StartType         *string   `json:"start_type"`
	Loaded            *bool     `json:"loaded"`
	Version           *string   `json:"version"`
	SHA256            *string   `json:"sha256"`
	ReportedAt        time.Time `json:"reported_at"`
	FirstSeenAt       time.Time `json:"first_seen_at"`
	Category          string    `json:"category"` // malicious when any match is malicious
	BlocklistEnforced string    `json:"blocklist_enforced"`
	Matches           []Match   `json:"matches"`
}

// EstateSummary counts the tenant's devices by what they reported.
type EstateSummary struct {
	DevicesReporting       int            `json:"devices_reporting"`
	DevicesUnavailable     int            `json:"devices_unavailable"`
	DevicesWithListed      int            `json:"devices_with_listed_drivers"`
	DevicesWithUnhashed    int            `json:"devices_with_unhashed_drivers"`
	ListedDrivers          int            `json:"listed_drivers"`
	ListedMaliciousDrivers int            `json:"listed_malicious_drivers"`
	BlocklistEnforced      map[string]int `json:"blocklist_enforced"`
}

// EstateFindings is one page of the tenant's listed drivers.
type EstateFindings struct {
	Lists    []ListState   `json:"lists"`
	Summary  EstateSummary `json:"summary"`
	Total    int           `json:"total"`
	Findings []Finding     `json:"findings"`
}

// FetchEstate reads one page of the tenant's findings (malicious first, then
// loaded, then by hostname and path) plus the estate summary.
func FetchEstate(ctx context.Context, pool *pgxpool.Pool, tenantID string, limit, offset int, now time.Time) (EstateFindings, error) {
	out := EstateFindings{Lists: []ListState{}, Findings: []Finding{},
		Summary: EstateSummary{BlocklistEnforced: map[string]int{"yes": 0, "no": 0, "unknown": 0}}}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, fmt.Errorf("begin driver findings read: %w", err)
	}
	defer tx.Rollback(ctx)

	states, err := LoadSourceStates(ctx, tx)
	if err != nil {
		return out, fmt.Errorf("load driver list state: %w", err)
	}
	out.Lists = ListStates(states, now)

	// Device-level summary.
	srows, err := tx.Query(ctx, `SELECT s.collection_status, s.blocklist_enforced,
			EXISTS (SELECT 1 FROM device_kernel_drivers d
			        WHERE d.device_id = s.device_id AND d.tenant_id = s.tenant_id AND d.hash_status = 'unhashed')
		FROM device_kernel_driver_state s
		WHERE s.tenant_id = $1::uuid`, tenantID)
	if err != nil {
		return out, fmt.Errorf("read driver state summary: %w", err)
	}
	for srows.Next() {
		var status, enforced string
		var unhashed bool
		if err := srows.Scan(&status, &enforced, &unhashed); err != nil {
			srows.Close()
			return out, err
		}
		out.Summary.DevicesReporting++
		if status == "unavailable" {
			out.Summary.DevicesUnavailable++
		}
		if unhashed {
			out.Summary.DevicesWithUnhashed++
		}
		out.Summary.BlocklistEnforced[enforced]++
	}
	srows.Close()
	if err := srows.Err(); err != nil {
		return out, err
	}

	// Every match in the tenant, grouped per (device, driver).
	type key struct{ device, driver string }
	grouped := map[key][]Match{}
	mrows, err := tx.Query(ctx, matchSQL, tenantID, nil)
	if err != nil {
		return out, fmt.Errorf("match tenant drivers: %w", err)
	}
	for mrows.Next() {
		var k key
		var m Match
		if err := mrows.Scan(&k.device, &k.driver, &m.Source, &m.Category, &m.EntryID, &m.EntryName, &m.HashKind, &m.Hash,
			&m.ListVersion, &m.ListFetchedAt); err != nil {
			mrows.Close()
			return out, err
		}
		decorate(&m, states, now)
		grouped[k] = append(grouped[k], m)
	}
	mrows.Close()
	if err := mrows.Err(); err != nil {
		return out, err
	}

	// The listed rows themselves, in one query.
	frows, err := tx.Query(ctx, `SELECT d.device_id::text, d.driver_key,
			COALESCE(dev.hostname, dev.serial, d.device_id::text),
			d.path, d.service_name, d.start_type, d.loaded, d.version, d.sha256, d.reported_at, d.first_seen_at,
			COALESCE(s.blocklist_enforced, 'unknown')
		FROM device_kernel_drivers d
		JOIN devices dev ON dev.id = d.device_id AND dev.tenant_id = d.tenant_id
		LEFT JOIN device_kernel_driver_state s ON s.device_id = d.device_id AND s.tenant_id = d.tenant_id
		WHERE d.tenant_id = $1::uuid AND d.hash_status = 'hashed'
		  AND EXISTS (SELECT 1 FROM driver_blocklist_entries e
		              WHERE (e.hash_kind = 'sha256' AND e.hash = d.sha256)
		                 OR (e.hash_kind = 'sha1' AND e.hash = d.sha1)
		                 OR (e.hash_kind = 'authenticode_sha256' AND e.hash = d.authenticode_sha256)
		                 OR (e.hash_kind = 'authenticode_sha1' AND e.hash = d.authenticode_sha1))`, tenantID)
	if err != nil {
		return out, fmt.Errorf("read listed drivers: %w", err)
	}
	findings := make([]Finding, 0, len(grouped))
	devicesListed := map[string]bool{}
	for frows.Next() {
		var f Finding
		var k key
		if err := frows.Scan(&k.device, &k.driver, &f.Hostname, &f.Path, &f.ServiceName, &f.StartType,
			&f.Loaded, &f.Version, &f.SHA256, &f.ReportedAt, &f.FirstSeenAt, &f.BlocklistEnforced); err != nil {
			frows.Close()
			return out, err
		}
		matches := grouped[k]
		if len(matches) == 0 {
			continue // both reads are one repeatable-read snapshot; defensive only
		}
		f.DeviceID = k.device
		f.ReportedAt = f.ReportedAt.UTC()
		f.FirstSeenAt = f.FirstSeenAt.UTC()
		f.Matches = matches
		f.Category = CategoryVulnerable
		if hasMalicious(matches) {
			f.Category = CategoryMalicious
			out.Summary.ListedMaliciousDrivers++
		}
		out.Summary.ListedDrivers++
		devicesListed[f.DeviceID] = true
		findings = append(findings, f)
	}
	frows.Close()
	if err := frows.Err(); err != nil {
		return out, err
	}
	if err := tx.Commit(ctx); err != nil {
		return out, fmt.Errorf("commit driver findings read: %w", err)
	}
	out.Summary.DevicesWithListed = len(devicesListed)

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if (a.Category == CategoryMalicious) != (b.Category == CategoryMalicious) {
			return a.Category == CategoryMalicious
		}
		al, bl := a.Loaded != nil && *a.Loaded, b.Loaded != nil && *b.Loaded
		if al != bl {
			return al
		}
		if a.Hostname != b.Hostname {
			return a.Hostname < b.Hostname
		}
		if a.DeviceID != b.DeviceID {
			return a.DeviceID < b.DeviceID
		}
		return deref(a.Path)+"\x00"+deref(a.ServiceName) < deref(b.Path)+"\x00"+deref(b.ServiceName)
	})
	out.Total = len(findings)
	if offset < len(findings) {
		end := offset + limit
		if end > len(findings) {
			end = len(findings)
		}
		out.Findings = findings[offset:end]
	}
	return out, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
