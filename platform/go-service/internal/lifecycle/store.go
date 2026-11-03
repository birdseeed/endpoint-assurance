package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Mapping statuses.
const (
	StatusProposed  = "proposed"
	StatusPublished = "published"
	StatusRejected  = "rejected"
)

// IdentityKindOS is the identity kind of an operating-system mapping.
const IdentityKindOS = "os"

var (
	// ErrNotFound: no mapping with that id.
	ErrNotFound = errors.New("not found")
	// ErrConflict: the mapping is not in a state the action allows, a live
	// mapping already covers the identity, or the slug has no fetched data.
	ErrConflict = errors.New("conflict")
	// ErrInvalidRequest: the request itself is invalid.
	ErrInvalidRequest = errors.New("invalid request")
)

// DB is the subset of pgx shared by a pool and a transaction.
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Actor is the audit attribution for one admin write (PAT-1135 split).
type Actor struct {
	Actor      string
	Claimed    *string
	SourceAddr *string
}

// appIdentityKinds are the software_installations identity kinds a mapping
// may name, by platform. Name-only kinds (display_name, name_publisher) are
// deliberately absent: a display name is not product identity.
var appIdentityKinds = map[string]string{
	"macos_bundle_team":        "macos",
	"macos_bundle":             "macos",
	"homebrew_formula":         "macos",
	"homebrew_cask":            "macos",
	"windows_winget":           "windows",
	"windows_native_publisher": "windows",
	"windows_native":           "windows",
}

// ReportIdentityKinds are the installation kinds the report assesses:
// applications (including name-only ones, which can only ever read Unknown
// because no mapping may name them) and Homebrew formulae and casks.
// Developer tooling (IDE extensions, language packages, local models, MCP
// servers) and Homebrew taps are outside the report and counted in its
// basis as not counted.
var ReportIdentityKinds = []string{
	"macos_bundle_team", "macos_bundle", "windows_winget", "windows_native_publisher",
	"windows_native", "name_publisher", "display_name", "homebrew_formula", "homebrew_cask",
}

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,99}$`)

// ValidSlug reports whether s is a well-formed endoflife.date product slug.
func ValidSlug(s string) bool { return slugRE.MatchString(s) && !strings.Contains(s, "..") }

// normalizeValue matches the extractor's normalizedIdentityValue: lower
// case, whitespace runs collapsed, trimmed.
func normalizeValue(v string) string {
	return strings.ToLower(strings.Join(strings.Fields(v), " "))
}

// normalizeCompanion matches the extractor: a Team ID is upper case, every
// other companion (publisher, tap) is normalised like the value.
func normalizeCompanion(kind, v string) string {
	if kind == "macos_bundle_team" {
		return strings.ToUpper(strings.Join(strings.Fields(v), " "))
	}
	return normalizeValue(v)
}

// Mapping is one lifecycle_mappings row, plus (on List) live context for
// review: the slug's fetch state and how many current installations across
// every tenant the identity covers. Counts only; no tenant or device id.
// RollingWindowDays is set when the mapping uses the rolling-release rule
// (PAT-2171) and nil for the ordinary end of support rule.
type Mapping struct {
	ID                 int64      `json:"id"`
	Platform           string     `json:"platform"`
	IdentityKind       string     `json:"identity_kind"`
	IdentityValue      string     `json:"identity_value"`
	CompanionValue     string     `json:"companion_value"`
	Slug               string     `json:"eol_slug"`
	VersionRule        string     `json:"version_rule"`
	VersionRegex       *string    `json:"version_regex"`
	RollingWindowDays  *int       `json:"rolling_window_days"`
	Status             string     `json:"status"`
	Notes              string     `json:"notes"`
	ProposedBy         string     `json:"proposed_by"`
	ProposedAt         time.Time  `json:"proposed_at"`
	ReviewedBy         *string    `json:"reviewed_by"`
	ReviewedAt         *time.Time `json:"reviewed_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	LifecycleFetchedAt *time.Time `json:"lifecycle_fetched_at,omitempty"`
	LifecycleCycles    *int       `json:"lifecycle_cycle_count,omitempty"`
	LifecycleError     *string    `json:"lifecycle_last_error,omitempty"`
	InstallationCount  *int       `json:"estate_installation_count,omitempty"`
}

const mappingColumns = `id, platform, identity_kind, identity_value_normalized, companion_value_normalized,
	eol_slug, version_rule, version_regex, rolling_window_days, status, notes, proposed_by, proposed_at, reviewed_by, reviewed_at, updated_at`

func scanMapping(row pgx.Row) (Mapping, error) {
	var m Mapping
	err := row.Scan(&m.ID, &m.Platform, &m.IdentityKind, &m.IdentityValue, &m.CompanionValue,
		&m.Slug, &m.VersionRule, &m.VersionRegex, &m.RollingWindowDays, &m.Status, &m.Notes, &m.ProposedBy, &m.ProposedAt,
		&m.ReviewedBy, &m.ReviewedAt, &m.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Mapping{}, ErrNotFound
	}
	return m, err
}

// List returns mappings, optionally filtered by status, each with its slug's
// fetch state and its live estate installation count.
func List(ctx context.Context, db DB, status string) ([]Mapping, error) {
	rows, err := db.Query(ctx, `
		SELECT m.id, m.platform, m.identity_kind, m.identity_value_normalized, m.companion_value_normalized,
		       m.eol_slug, m.version_rule, m.version_regex, m.rolling_window_days, m.status, m.notes, m.proposed_by, m.proposed_at,
		       m.reviewed_by, m.reviewed_at, m.updated_at,
		       p.fetched_at, p.cycle_count, p.last_error,
		       CASE WHEN m.identity_kind = 'os' THEN
		            (SELECT count(*) FROM devices d
		              WHERE (m.platform = 'macos' AND d.os = 'macOS') OR (m.platform = 'windows' AND d.os = 'Windows'))
		       ELSE
		            (SELECT count(*) FROM software_installations si
		              WHERE si.removed_at IS NULL AND si.platform = m.platform
		                AND si.identity_kind = m.identity_kind
		                AND si.identity_value_normalized = m.identity_value_normalized
		                AND si.companion_value_normalized = m.companion_value_normalized)
		       END::int
		FROM lifecycle_mappings m
		LEFT JOIN lifecycle_products p ON p.slug = m.eol_slug
		WHERE ($1 = '' OR m.status = $1)
		ORDER BY m.status, m.eol_slug, m.id`, status)
	if err != nil {
		return nil, fmt.Errorf("list lifecycle mappings: %w", err)
	}
	defer rows.Close()
	out := []Mapping{}
	for rows.Next() {
		var m Mapping
		var cycles *int
		var count int
		if err := rows.Scan(&m.ID, &m.Platform, &m.IdentityKind, &m.IdentityValue, &m.CompanionValue,
			&m.Slug, &m.VersionRule, &m.VersionRegex, &m.RollingWindowDays, &m.Status, &m.Notes, &m.ProposedBy, &m.ProposedAt,
			&m.ReviewedBy, &m.ReviewedAt, &m.UpdatedAt,
			&m.LifecycleFetchedAt, &cycles, &m.LifecycleError, &count); err != nil {
			return nil, fmt.Errorf("scan lifecycle mapping: %w", err)
		}
		m.LifecycleCycles = cycles
		m.InstallationCount = &count
		out = append(out, m)
	}
	return out, rows.Err()
}

// ProposeInput is a new mapping.
type ProposeInput struct {
	Platform       string
	IdentityKind   string
	IdentityValue  string
	CompanionValue string
	Slug           string
	VersionRule    string
	VersionRegex   string
	Notes          string
	// Rolling opts the mapping into the rolling-release rule (PAT-2171).
	// RollingWindowDays is the window in days; nil with Rolling set means
	// DefaultRollingWindowDays. Validate resolves it.
	Rolling           bool
	RollingWindowDays *int
}

// Validate normalises and checks a proposal.
func (in *ProposeInput) Validate() error {
	in.Platform = strings.TrimSpace(in.Platform)
	in.IdentityKind = strings.TrimSpace(in.IdentityKind)
	in.Slug = strings.ToLower(strings.TrimSpace(in.Slug))
	in.VersionRule = strings.TrimSpace(in.VersionRule)
	in.Notes = strings.TrimSpace(in.Notes)
	if in.Platform != "macos" && in.Platform != "windows" {
		return fmt.Errorf("%w: platform must be macos or windows", ErrInvalidRequest)
	}
	if !ValidSlug(in.Slug) {
		return fmt.Errorf("%w: eol_slug must be an endoflife.date product slug (lower case letters, digits, . _ + -)", ErrInvalidRequest)
	}
	if len(in.Notes) > 1000 {
		return fmt.Errorf("%w: notes must be at most 1000 characters", ErrInvalidRequest)
	}
	if in.RollingWindowDays != nil && !in.Rolling {
		return fmt.Errorf("%w: rolling_window_days needs rolling: true", ErrInvalidRequest)
	}
	if in.Rolling {
		if in.IdentityKind == IdentityKindOS {
			return fmt.Errorf("%w: rolling applies only to application mappings, not the operating system", ErrInvalidRequest)
		}
		days := DefaultRollingWindowDays
		if in.RollingWindowDays != nil {
			days = *in.RollingWindowDays
		}
		if days < 1 || days > MaxRollingWindowDays {
			return fmt.Errorf("%w: rolling_window_days must be between 1 and %d", ErrInvalidRequest, MaxRollingWindowDays)
		}
		in.RollingWindowDays = &days
	}
	if in.IdentityKind == IdentityKindOS {
		in.IdentityValue = in.Platform
		in.CompanionValue = ""
		want := RuleMacOSMajor
		if in.Platform == "windows" {
			want = RuleWindowsBuild
		}
		if in.VersionRule != want {
			return fmt.Errorf("%w: an os mapping on %s must use version_rule %s", ErrInvalidRequest, in.Platform, want)
		}
		if in.VersionRegex != "" {
			return fmt.Errorf("%w: version_regex applies only to version_rule regex", ErrInvalidRequest)
		}
		return nil
	}
	platform, ok := appIdentityKinds[in.IdentityKind]
	if !ok {
		return fmt.Errorf("%w: identity_kind must be os or one of macos_bundle_team, macos_bundle, homebrew_formula, homebrew_cask, windows_winget, windows_native_publisher, windows_native (a display name is not product identity)", ErrInvalidRequest)
	}
	if platform != in.Platform {
		return fmt.Errorf("%w: identity_kind %s is a %s identity", ErrInvalidRequest, in.IdentityKind, platform)
	}
	in.IdentityValue = normalizeValue(in.IdentityValue)
	in.CompanionValue = normalizeCompanion(in.IdentityKind, in.CompanionValue)
	if in.IdentityValue == "" || len(in.IdentityValue) > 512 || len(in.CompanionValue) > 512 {
		return fmt.Errorf("%w: identity_value is required and at most 512 characters", ErrInvalidRequest)
	}
	if in.IdentityKind == "macos_bundle_team" && in.CompanionValue == "" {
		return fmt.Errorf("%w: a macos_bundle_team identity needs its Team ID as companion_value", ErrInvalidRequest)
	}
	switch in.VersionRule {
	case RuleMajor, RuleMajorMinor:
		if in.VersionRegex != "" {
			return fmt.Errorf("%w: version_regex applies only to version_rule regex", ErrInvalidRequest)
		}
	case RuleRegex:
		if err := ValidateRegex(in.VersionRegex); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
		}
	default:
		return fmt.Errorf("%w: version_rule must be major, major_minor or regex for an application", ErrInvalidRequest)
	}
	return nil
}

func writeAudit(ctx context.Context, tx pgx.Tx, mappingID int64, action string, actor Actor, before, after any) error {
	var beforeJSON any
	if before != nil {
		b, err := json.Marshal(before)
		if err != nil {
			return err
		}
		beforeJSON = string(b)
	}
	a, err := json.Marshal(after)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO lifecycle_mapping_audit (mapping_id, action, actor, claimed_actor, source_addr, before, after)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb)`,
		mappingID, action, actor.Actor, actor.Claimed, actor.SourceAddr, beforeJSON, string(a)); err != nil {
		return fmt.Errorf("write lifecycle mapping audit: %w", err)
	}
	return nil
}

// Propose records a new proposed mapping. It changes nothing a customer
// sees until published. 409 when a live mapping already covers the identity.
func Propose(ctx context.Context, tx pgx.Tx, in ProposeInput, actor Actor) (Mapping, error) {
	if err := in.Validate(); err != nil {
		return Mapping{}, err
	}
	var regex any
	if in.VersionRule == RuleRegex {
		regex = in.VersionRegex
	}
	m, err := scanMapping(tx.QueryRow(ctx, `
		INSERT INTO lifecycle_mappings
			(platform, identity_kind, identity_value_normalized, companion_value_normalized,
			 eol_slug, version_rule, version_regex, rolling_window_days, notes, proposed_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING `+mappingColumns,
		in.Platform, in.IdentityKind, in.IdentityValue, in.CompanionValue, in.Slug, in.VersionRule, regex,
		in.RollingWindowDays, in.Notes, actor.Actor))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return Mapping{}, fmt.Errorf("%w: a proposed or published mapping already covers this product identity", ErrConflict)
		}
		return Mapping{}, err
	}
	if err := writeAudit(ctx, tx, m.ID, "propose", actor, nil, m); err != nil {
		return Mapping{}, err
	}
	return m, nil
}

func lockMapping(ctx context.Context, tx pgx.Tx, id int64) (Mapping, error) {
	return scanMapping(tx.QueryRow(ctx, `SELECT `+mappingColumns+` FROM lifecycle_mappings WHERE id = $1 FOR UPDATE`, id))
}

// Publish makes a proposed mapping drive customer output. The slug must
// already have fetched cycle data: publishing against a slug that has never
// been fetched is refused, which also catches a mistyped slug before it
// reaches a customer.
func Publish(ctx context.Context, tx pgx.Tx, id int64, actor Actor) (Mapping, error) {
	before, err := lockMapping(ctx, tx, id)
	if err != nil {
		return Mapping{}, err
	}
	if before.Status != StatusProposed {
		return Mapping{}, fmt.Errorf("%w: mapping is %s, not proposed", ErrConflict, before.Status)
	}
	var cycles int
	err = tx.QueryRow(ctx, `SELECT cycle_count FROM lifecycle_products WHERE slug = $1 AND fetched_at IS NOT NULL`, before.Slug).Scan(&cycles)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && cycles == 0) {
		return Mapping{}, fmt.Errorf("%w: no lifecycle data has been fetched for %s; run a refresh and check the cycles first", ErrConflict, before.Slug)
	}
	if err != nil {
		return Mapping{}, err
	}
	after, err := scanMapping(tx.QueryRow(ctx, `
		UPDATE lifecycle_mappings SET status = 'published', reviewed_by = $2, reviewed_at = now(), updated_at = now()
		WHERE id = $1 RETURNING `+mappingColumns, id, actor.Actor))
	if err != nil {
		return Mapping{}, err
	}
	if err := writeAudit(ctx, tx, id, "publish", actor, before, after); err != nil {
		return Mapping{}, err
	}
	return after, nil
}

// Reject rejects a proposed mapping, or withdraws a published one (its rows
// read Unknown again from the next report). A rejected row frees the
// identity for a corrected proposal.
func Reject(ctx context.Context, tx pgx.Tx, id int64, actor Actor) (Mapping, error) {
	before, err := lockMapping(ctx, tx, id)
	if err != nil {
		return Mapping{}, err
	}
	action := "reject"
	switch before.Status {
	case StatusProposed:
	case StatusPublished:
		action = "withdraw"
	default:
		return Mapping{}, fmt.Errorf("%w: mapping is already rejected", ErrConflict)
	}
	after, err := scanMapping(tx.QueryRow(ctx, `
		UPDATE lifecycle_mappings SET status = 'rejected', reviewed_by = $2, reviewed_at = now(), updated_at = now()
		WHERE id = $1 RETURNING `+mappingColumns, id, actor.Actor))
	if err != nil {
		return Mapping{}, err
	}
	if err := writeAudit(ctx, tx, id, action, actor, before, after); err != nil {
		return Mapping{}, err
	}
	return after, nil
}

// ProductStatus is one lifecycle_products row for the admin API.
type ProductStatus struct {
	Slug          string     `json:"slug"`
	Label         *string    `json:"label"`
	HTMLURL       *string    `json:"html_url"`
	FetchedAt     *time.Time `json:"fetched_at"`
	LastAttemptAt time.Time  `json:"last_attempt_at"`
	LastError     *string    `json:"last_error"`
	CycleCount    int        `json:"cycle_count"`
	Stale         bool       `json:"stale"`
}

// ListProducts returns every fetched or attempted slug.
func ListProducts(ctx context.Context, db DB, now time.Time) ([]ProductStatus, error) {
	rows, err := db.Query(ctx, `
		SELECT slug, label, html_url, fetched_at, last_attempt_at, last_error, cycle_count
		FROM lifecycle_products ORDER BY slug`)
	if err != nil {
		return nil, fmt.Errorf("list lifecycle products: %w", err)
	}
	defer rows.Close()
	out := []ProductStatus{}
	for rows.Next() {
		var p ProductStatus
		if err := rows.Scan(&p.Slug, &p.Label, &p.HTMLURL, &p.FetchedAt, &p.LastAttemptAt, &p.LastError, &p.CycleCount); err != nil {
			return nil, err
		}
		p.Stale = p.FetchedAt == nil || now.Sub(*p.FetchedAt) > CacheTTL
		out = append(out, p)
	}
	return out, rows.Err()
}

// LoadProducts loads the named slugs with their cycles. A slug with no row
// is absent from the map (never fetched).
func LoadProducts(ctx context.Context, db DB, slugs []string) (map[string]*Product, error) {
	out := map[string]*Product{}
	if len(slugs) == 0 {
		return out, nil
	}
	rows, err := db.Query(ctx, `
		SELECT slug, COALESCE(label, ''), COALESCE(html_url, ''), fetched_at
		FROM lifecycle_products WHERE slug = ANY($1)`, slugs)
	if err != nil {
		return nil, fmt.Errorf("load lifecycle products: %w", err)
	}
	for rows.Next() {
		p := &Product{}
		if err := rows.Scan(&p.Slug, &p.Label, &p.HTMLURL, &p.FetchedAt); err != nil {
			rows.Close()
			return nil, err
		}
		out[p.Slug] = p
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	crows, err := db.Query(ctx, `
		SELECT slug, cycle, COALESCE(label, ''), release_date, eol_date, is_eol, support_date,
		       extended_support_date, COALESCE(latest_version, ''), is_lts
		FROM lifecycle_cycles WHERE slug = ANY($1) ORDER BY slug, release_date DESC NULLS LAST, cycle`, slugs)
	if err != nil {
		return nil, fmt.Errorf("load lifecycle cycles: %w", err)
	}
	defer crows.Close()
	for crows.Next() {
		var slug string
		var c Cycle
		if err := crows.Scan(&slug, &c.Name, &c.Label, &c.ReleaseDate, &c.EOLDate, &c.IsEOL, &c.SupportDate,
			&c.ExtendedSupportDate, &c.LatestVersion, &c.IsLTS); err != nil {
			return nil, err
		}
		if p := out[slug]; p != nil {
			p.Cycles = append(p.Cycles, c)
		}
	}
	return out, crows.Err()
}

// identityKey is a mapping's canonical product identity.
type identityKey struct {
	Platform, Kind, Value, Companion string
}

// publishedMapping is a published row as the report uses it.
type publishedMapping struct {
	ID  int64
	Ref MappingRef
}

// loadPublished returns every published mapping keyed by identity.
func loadPublished(ctx context.Context, db DB) (map[identityKey]publishedMapping, []string, error) {
	rows, err := db.Query(ctx, `
		SELECT id, platform, identity_kind, identity_value_normalized, companion_value_normalized,
		       eol_slug, version_rule, COALESCE(version_regex, ''), COALESCE(rolling_window_days, 0)
		FROM lifecycle_mappings WHERE status = 'published'`)
	if err != nil {
		return nil, nil, fmt.Errorf("load published lifecycle mappings: %w", err)
	}
	defer rows.Close()
	out := map[identityKey]publishedMapping{}
	seen := map[string]bool{}
	var slugs []string
	for rows.Next() {
		var k identityKey
		var pm publishedMapping
		if err := rows.Scan(&pm.ID, &k.Platform, &k.Kind, &k.Value, &k.Companion,
			&pm.Ref.Slug, &pm.Ref.Rule.Kind, &pm.Ref.Rule.Regex, &pm.Ref.RollingWindowDays); err != nil {
			return nil, nil, err
		}
		out[k] = pm
		if !seen[pm.Ref.Slug] {
			seen[pm.Ref.Slug] = true
			slugs = append(slugs, pm.Ref.Slug)
		}
	}
	return out, slugs, rows.Err()
}

// RetryDeadlock runs fn and, on a PostgreSQL deadlock (40P01), once more.
// Every write here is safe to repeat: a second attempt against an already
// changed row fails as a conflict.
func RetryDeadlock(fn func() error) error {
	err := fn()
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "40P01" {
		return fn()
	}
	return err
}
