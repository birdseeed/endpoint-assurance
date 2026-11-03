package cpepropose

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/cvelifecycle"
	"patched.im/api/internal/cvematch"
)

// Proposal states (cpe_mapping_proposals.state).
const (
	StatePending       = "pending"
	StateNeedsReview   = "needs_review"
	StateAutoPublished = "auto_published"
	StateApproved      = "approved"
	StateRejected      = "rejected"
	StateSuperseded    = "superseded"
	// StateExpired: an open proposal no active device has reported for 30
	// days. Reopened to pending if the product is reported again.
	StateExpired = "expired"
)

// Admission caps (PAT-2138 security review, P2). Endpoint-reported names are
// attacker-controllable: without bounds one tenant's payloads could grow the
// table, the staff queue and the NVD and model calls behind it without limit.
// Vars so tests can exercise them.
var (
	// MaxOpenProposals bounds pending plus needs_review proposals together:
	// ingest admits no new name while the open queue is this long.
	MaxOpenProposals = 5000
	// MaxNewProposalsPerPayload bounds the new proposals one ingest (one
	// device payload) may create.
	MaxNewProposalsPerPayload = 200
	// MaxNewProposalsPerTenantPerDay bounds the new proposals one tenant's
	// ingests may create in any rolling 24 hours.
	MaxNewProposalsPerTenantPerDay = 1000
	// MaxOpenProposalsPerTenant bounds the open proposals (pending and
	// needs_review, private ones included) one tenant first reported.
	MaxOpenProposalsPerTenant = 1000
)

// staleSeen is how old last_seen_at must be before ingest refreshes it.
const staleSeen = time.Hour

// maxNameRunes bounds a proposal's name, matching the table's CHECK.
const maxNameRunes = 200

// activeDeviceWindow matches the CVE matchers' device scope.
const activeDeviceWindow = cvematch.ActiveDeviceWindow

// DB is the subset of pgx shared by a pool, a connection and a transaction.
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// NormalizeName is the identity a proposal is recorded once for: lower case,
// trimmed, whitespace runs collapsed to one space. "" when the name is empty,
// too long or not valid UTF-8.
//
// It is byte-for-byte the SQL function cpe_normalize_name (migration 0192),
// which every query comparing a name with a proposal uses, so Go and the
// database always agree whatever the collation: only ASCII A-Z is lowered,
// and only ASCII whitespace (space, tab, LF, CR, FF, VT) is collapsed and
// trimmed. Non-ASCII letters and Unicode spaces are kept as they are.
func NormalizeName(name string) string {
	if !utf8.ValidString(name) {
		return ""
	}
	var b strings.Builder
	pendingSpace := false
	for _, r := range name {
		if isASCIISpace(r) {
			pendingSpace = b.Len() > 0
			continue
		}
		if pendingSpace {
			b.WriteByte(' ')
			pendingSpace = false
		}
		b.WriteRune(asciiLower(r))
	}
	n := b.String()
	if n == "" || utf8.RuneCountInString(n) > maxNameRunes {
		return ""
	}
	return n
}

func isASCIISpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	}
	return false
}

func asciiLower(r rune) rune {
	if 'A' <= r && r <= 'Z' {
		return r + ('a' - 'A')
	}
	return r
}

// ProposalPlatform maps a device platform (cvematch vocabulary) to the
// proposal platform. Only macOS and Windows devices produce proposals: an
// unrecognised platform matches only "any" mappings, and guessing one for it
// would be worse than proposing nothing.
func ProposalPlatform(devicePlatform string) (string, bool) {
	switch devicePlatform {
	case cvematch.PlatformMacOS, cvematch.PlatformWindows:
		return devicePlatform, true
	}
	return "", false
}

// eligibleName reports whether a display name can be proposed at all: not the
// OS pseudo-app (the vendor-advisory matcher owns it), not a Homebrew display
// name (the Homebrew review queue owns those), and carrying at least one
// letter or digit so it can form an NVD keyword.
func eligibleName(name string) bool {
	if NormalizeName(name) == "" {
		return false
	}
	for _, os := range cvelifecycle.OSPseudoAppNames {
		if name == os {
			return false
		}
	}
	if _, _, ok := cvelifecycle.ParseHomebrewAppName(name); ok {
		return false
	}
	return strings.IndexFunc(name, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }) >= 0
}

// Unmapped returns the names, of those given, that no mapping covers on
// platform, in the order given with duplicates (by normalised name) removed.
// Mapped is decided exactly as the matcher decides it: cvematch's word-token
// rule, then the PAT-2029 platform filter.
func Unmapped(names []string, platform string, mappings []cvematch.CPEMapping) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		if !eligibleName(n) {
			continue
		}
		key := NormalizeName(n)
		if seen[key] {
			continue
		}
		if len(cvematch.FilterMappingsForPlatform(cvematch.MappingsFor(n, mappings), platform)) > 0 {
			continue
		}
		seen[key] = true
		out = append(out, n)
	}
	return out
}

// RecordUnmapped records a proposal for each name no mapping covers on the
// device's platform. It runs inside the extractor's ingest transaction (under
// a savepoint), so it only writes the database: candidates and the model
// choice come later from the worker. Its state is never changed here, so a
// staff rejection sticks. Returns the number of rows inserted or refreshed.
//
// tenantID is the ingesting tenant, used only for the per-tenant admission
// caps (cpe_proposal_origins); it is never written to the proposal. ""
// (the operator's Backfill) skips the per-payload and per-tenant caps; the
// open-queue cap always applies.
//
// Locking (security review P2/P3): an ingest never waits on another
// ingest's proposal row. Names already proposed are found with a plain read
// and never re-inserted (an INSERT ... ON CONFLICT on a row another open
// transaction has updated would wait for it). Their last_seen_at is
// refreshed at most hourly, only for rows no other transaction holds (FOR
// UPDATE SKIP LOCKED): a skipped refresh is only an hour's staleness, and
// the next report refreshes it. New names are inserted ON CONFLICT DO
// NOTHING; the one remaining wait is two ingests inserting the same
// never-seen name at the same moment, which lasts until the first commits
// and happens once per product.
//
// On a database without the 0192 tables it returns an error that
// IsUndefinedTable recognises. It never swallows that error itself: inside a
// transaction the failed statement has already aborted it, so the caller must
// roll its savepoint back (the extractor does, and logs it quietly).
func RecordUnmapped(ctx context.Context, q DB, tenantID, devicePlatform string, names []string, mappings []cvematch.CPEMapping) (int, error) {
	platform, ok := ProposalPlatform(devicePlatform)
	if !ok {
		return 0, nil
	}
	unmapped := Unmapped(names, platform, mappings)
	if len(unmapped) == 0 {
		return 0, nil
	}
	display := map[string]string{}
	normalized := make([]string, 0, len(unmapped))
	for _, n := range unmapped {
		k := NormalizeName(n)
		normalized = append(normalized, k)
		display[k] = strings.Join(strings.Fields(n), " ")
	}
	sort.Strings(normalized)

	existing := map[string]bool{}
	var expired []string
	rows, err := q.Query(ctx, `
		SELECT normalized_name, state FROM cpe_mapping_proposals
		WHERE platform = $1 AND normalized_name = ANY($2::text[])`, platform, normalized)
	if err != nil {
		return 0, fmt.Errorf("read existing cpe mapping proposals: %w", err)
	}
	for rows.Next() {
		var k, state string
		if err := rows.Scan(&k, &state); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan existing cpe mapping proposal: %w", err)
		}
		existing[k] = true
		if state == StateExpired {
			expired = append(expired, k)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("read existing cpe mapping proposals: %w", err)
	}

	recorded := 0
	if len(existing) > len(expired) {
		tag, err := q.Exec(ctx, `
			UPDATE cpe_mapping_proposals SET last_seen_at = now()
			WHERE id IN (
				SELECT id FROM cpe_mapping_proposals
				WHERE platform = $1 AND normalized_name = ANY($2::text[])
				  AND state <> 'expired'
				  AND last_seen_at < now() - make_interval(secs => $3)
				ORDER BY id
				FOR UPDATE SKIP LOCKED
			)`, platform, normalized, staleSeen.Seconds())
		if err != nil {
			return 0, fmt.Errorf("refresh cpe mapping proposals: %w", err)
		}
		recorded += int(tag.RowsAffected())
	}

	var fresh []string
	for _, k := range normalized {
		if !existing[k] {
			fresh = append(fresh, k)
		}
	}
	if len(fresh) == 0 && len(expired) == 0 {
		return recorded, nil
	}
	room, err := admissionRoom(ctx, q, tenantID)
	if err != nil {
		return recorded, err
	}
	if room <= 0 {
		return recorded, nil
	}
	// A product that expired and is reported again is reopened, within the
	// same admission room as a new one.
	if len(expired) > 0 {
		n, err := reopenExpired(ctx, q, tenantID, platform, expired, room)
		if err != nil {
			return recorded, err
		}
		recorded += n
		room -= n
	}
	if room <= 0 || len(fresh) == 0 {
		return recorded, nil
	}
	if len(fresh) > room {
		fresh = fresh[:room]
	}
	freshDisplay := make([]string, len(fresh))
	for i, k := range fresh {
		freshDisplay[i] = display[k]
	}
	ids, err := collectIDs(q.Query(ctx, `
		INSERT INTO cpe_mapping_proposals (platform, normalized_name, display_name)
		SELECT $1, u.n, u.d FROM unnest($2::text[], $3::text[]) AS u(n, d)
		ORDER BY u.n
		ON CONFLICT (platform, normalized_name) DO NOTHING
		RETURNING id
	`, platform, fresh, freshDisplay))
	if err != nil {
		return recorded, fmt.Errorf("record cpe mapping proposals: %w", err)
	}
	if err := recordOrigins(ctx, q, tenantID, ids); err != nil {
		return recorded, err
	}
	return recorded + len(ids), nil
}

func collectIDs(rows pgx.Rows, err error) ([]int64, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// recordOrigins attributes admitted proposals to the ingesting tenant, for
// the per-tenant caps. Internal only: never returned by the admin API, never
// sent anywhere.
func recordOrigins(ctx context.Context, q DB, tenantID string, ids []int64) error {
	if tenantID == "" || len(ids) == 0 {
		return nil
	}
	if _, err := q.Exec(ctx, `
		INSERT INTO cpe_proposal_origins (proposal_id, tenant_id, admitted_at)
		SELECT unnest($2::bigint[]), $1::uuid, now()
		ON CONFLICT (proposal_id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id, admitted_at = EXCLUDED.admitted_at
	`, tenantID, ids); err != nil {
		return fmt.Errorf("record cpe proposal origins: %w", err)
	}
	return nil
}

// reopenExpired returns up to limit expired proposals among names to
// pending, audited as 'reopen', skipping any row another transaction holds.
func reopenExpired(ctx context.Context, q DB, tenantID, platform string, names []string, limit int) (int, error) {
	ids, err := collectIDs(q.Query(ctx, `
		UPDATE cpe_mapping_proposals SET state = 'pending', state_reason = NULL, next_attempt_at = now(),
			last_seen_at = now(), decided_at = NULL, decided_by = NULL, updated_at = now()
		WHERE id IN (
			SELECT id FROM cpe_mapping_proposals
			WHERE platform = $1 AND normalized_name = ANY($2::text[]) AND state = 'expired'
			ORDER BY id LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id`, platform, names, limit))
	if err != nil {
		return 0, fmt.Errorf("reopen expired cpe mapping proposals: %w", err)
	}
	reason := ReasonNotSeen30Days
	before := proposalSnapshot{State: StateExpired, StateReason: &reason}
	for _, id := range ids {
		after, err := snapshotProposal(ctx, q, id)
		if err != nil {
			return 0, err
		}
		if err := writeAudit(ctx, q, id, "reopen", Actor{Actor: SystemActor}, &before, after); err != nil {
			return 0, err
		}
	}
	return len(ids), recordOrigins(ctx, q, tenantID, ids)
}

// countedOpenSQL selects the open proposals that count against the global
// cap: every open one except those held back as single_tenant, which
// cost no outbound call and which a flood of invented names would otherwise
// use to exhaust the cap for every tenant (re-review P2-c). The per-tenant
// open cap still counts them.
const countedOpenSQL = `(state = 'pending' OR (state = 'needs_review' AND state_reason IS DISTINCT FROM 'single_tenant'))`

// admissionRoom is how many new proposals this ingest may create: the room
// under MaxOpenProposals (open proposals other than single_tenant)
// and, for a tenant's ingest, under MaxNewProposalsPerPayload, the tenant's
// rolling-24-hour allowance and its cap on open proposals it first
// reported. Counted once per call, so soft under concurrency (like the CVE
// match queue's cap); counting never waits on another ingest.
func admissionRoom(ctx context.Context, q DB, tenantID string) (int, error) {
	var open int
	if err := q.QueryRow(ctx, `
		SELECT count(*)::int FROM (
			SELECT 1 FROM cpe_mapping_proposals WHERE `+countedOpenSQL+` LIMIT $1
		) p`, MaxOpenProposals).Scan(&open); err != nil {
		return 0, fmt.Errorf("count open cpe mapping proposals: %w", err)
	}
	room := MaxOpenProposals - open
	if tenantID == "" {
		return room, nil
	}
	room = min(room, MaxNewProposalsPerPayload)
	var today, tenantOpen int
	if err := q.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE o.admitted_at > now() - INTERVAL '24 hours')::int,
		       count(*) FILTER (WHERE p.state IN ('pending', 'needs_review'))::int
		FROM cpe_proposal_origins o
		JOIN cpe_mapping_proposals p ON p.id = o.proposal_id
		WHERE o.tenant_id = $1::uuid`, tenantID).Scan(&today, &tenantOpen); err != nil {
		return 0, fmt.Errorf("count tenant cpe proposal admissions: %w", err)
	}
	room = min(room, MaxNewProposalsPerTenantPerDay-today)
	return min(room, MaxOpenProposalsPerTenant-tenantOpen), nil
}

// BackfillResult summarises one Backfill run.
type BackfillResult struct {
	Products int // distinct (platform, name) observed on active devices
	Unmapped int // of those, with no mapping on their platform
	Recorded int // rows inserted or refreshed
}

// Backfill records a proposal for every product installed on an active device
// that no mapping covers on its platform. Idempotent: an existing proposal is
// never duplicated or reset, so running it twice records nothing new.
func Backfill(ctx context.Context, pool *pgxpool.Pool) (BackfillResult, error) {
	var res BackfillResult
	mappings, err := loadAppMappings(ctx, pool)
	if err != nil {
		return res, err
	}
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT da.name, COALESCE(d.os, '')
		FROM device_apps da
		JOIN devices d ON d.id = da.device_id
		WHERE d.last_seen > NOW() - INTERVAL '`+activeDeviceWindow+`'
		  AND NOT `+webAppWrapperSQL("$1", "$2")+`
	`, webAppIdentifierPattern, webAppPathPattern)
	if err != nil {
		return res, fmt.Errorf("load installed products: %w", err)
	}
	byPlatform := map[string][]string{}
	for rows.Next() {
		var name, os string
		if err := rows.Scan(&name, &os); err != nil {
			rows.Close()
			return res, fmt.Errorf("scan installed product: %w", err)
		}
		p, ok := ProposalPlatform(cvematch.NormalizeDevicePlatform(os))
		if !ok {
			continue
		}
		byPlatform[p] = append(byPlatform[p], name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, fmt.Errorf("iterate installed products: %w", err)
	}
	platforms := make([]string, 0, len(byPlatform))
	for p := range byPlatform {
		platforms = append(platforms, p)
	}
	sort.Strings(platforms)
	for _, p := range platforms {
		names := byPlatform[p]
		sort.Strings(names)
		seen := map[string]bool{}
		for _, n := range names {
			if k := NormalizeName(n); k != "" && !seen[k] {
				seen[k] = true
				res.Products++
			}
		}
		res.Unmapped += len(Unmapped(names, p, mappings))
		n, err := RecordUnmapped(ctx, pool, "", p, names, mappings)
		if err != nil {
			return res, err
		}
		res.Recorded += n
	}
	return res, nil
}

// loadAppMappings reads the application mappings the matchers use
// (cvepipeline.LoadMappings' rule, repeated here because cvepipeline imports
// this package for the portal's under-review lookup).
func loadAppMappings(ctx context.Context, q DB) ([]cvematch.CPEMapping, error) {
	rows, err := q.Query(ctx, `
		SELECT match_name, cpe_vendor, cpe_product, platform, review_state
		FROM app_cpe_mappings
		WHERE source_type = 'app_name' AND review_state IN ('curated', 'auto')
		ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("load cpe mappings: %w", err)
	}
	defer rows.Close()
	var out []cvematch.CPEMapping
	for rows.Next() {
		var m cvematch.CPEMapping
		if err := rows.Scan(&m.MatchName, &m.CPEVendor, &m.CPEProduct, &m.Platform, &m.ReviewState); err != nil {
			return nil, fmt.Errorf("scan cpe mapping: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// IsUndefinedTable reports a missing table (SQLSTATE 42P01): the binary is
// running ahead of migration 0192.
func IsUndefinedTable(err error) bool { return isUndefinedTable(err) }

func isUndefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}
