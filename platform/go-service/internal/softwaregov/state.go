// Package softwaregov owns PAT-2009's software governance reporting and the
// customer alert for unapproved software.
//
// Everything here is tenant scoped by an explicit tenant id that callers take
// from an authenticated identity (portal JWT, admin route, or the extraction
// row being processed). No query reads another tenant's rows.
//
// Presence comes from the current inventory snapshot (device_apps and
// device_browser_extensions). Approval state comes from the tenant policy
// store, resolved per device with the same resolver the drift, posture and
// finding lifecycle surfaces use (apppolicy.Index.Resolve for applications,
// exact browser before 'any' for extensions), so a product can never read
// Unapproved here and Approved on another page.
//
// Nothing in this package changes a device or tells an agent to act. It
// reports and notifies; remediation belongs to the customer's own management
// platform.
package softwaregov

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"patched.im/api/internal/apppolicy"
	"patched.im/api/internal/deviceretirement"
)

// Querier is satisfied by *pgxpool.Pool and pgx.Tx.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Portal approval states, the vocabulary of PAT-2007.
const (
	StateApproved   = "approved"
	StateUnapproved = "unapproved"
	StateUnreviewed = "unreviewed"
	StateIgnored    = "ignored"
	StateMandatory  = "mandatory"
)

// Product types, as PAT-2007 names them. TypeHomebrewFormula and
// TypeHomebrewCask (PAT-2058) join the model with the same resolver, the
// same software_approval_decisions audit table and the same write endpoint;
// they carry no policy_kind of their own in software_unapproved_episodes,
// deliberately excluded from unapproved-alert generation (see alerts.go).
const (
	TypeApplication      = "application"
	TypeBrowserExtension = "browser_extension"
	TypeHomebrewFormula  = "homebrew_formula"
	TypeHomebrewCask     = "homebrew_cask"
	TypeObservation      = "observation"
)

// StaleAfter is how old a device's last report may be before its evidence is
// called stale. It matches the portal's stale endpoints report (14 days).
const StaleAfter = 14 * 24 * time.Hour

// MaxEstateRows bounds one estate load. Inventory rows are customer telemetry,
// so the load fails closed with ErrEstateTooLarge rather than running an
// unbounded scan.
const MaxEstateRows = 250000

// ErrEstateTooLarge means the tenant's current inventory exceeds
// MaxEstateRows. Callers report the figures as unavailable, never as zero.
var ErrEstateTooLarge = errors.New("softwaregov: estate inventory exceeds the load cap")

var teamIDPattern = regexp.MustCompile(`^[A-Z0-9]{10}$`)

// stateRank orders states for "worst state of a product": a product that is
// Unapproved on one device and Unreviewed on another counts as Unapproved.
var stateRank = map[string]int{
	StateUnapproved: 5,
	StateUnreviewed: 4,
	StateMandatory:  3,
	StateApproved:   2,
	StateIgnored:    1,
}

// Product is one software product as the portal addresses it. ProductKey is
// PAT-2007's key, so a row here can be passed straight back to
// PUT /v1/portal/software-approvals.
type Product struct {
	Type        string `json:"type"`
	ProductKey  string `json:"product_key"`
	Name        string `json:"name"`
	Platform    string `json:"platform,omitempty"`
	Identifier  string `json:"identifier,omitempty"`
	TeamID      string `json:"team_id,omitempty"`
	Browser     string `json:"browser,omitempty"`
	ExtensionID string `json:"extension_id,omitempty"`
	// Tap (PAT-2058, homebrew_formula/homebrew_cask only) is the normalised
	// tap this identity was resolved against: "" for the package's own
	// default tap (homebrew/core for a formula, homebrew/cask for a cask) or
	// an unrecorded tap, otherwise the third-party tap. See
	// NormalizeHomebrewTap.
	Tap               string `json:"tap,omitempty"`
	ObservationKind   string `json:"observation_kind,omitempty"`
	ObservationSource string `json:"observation_source,omitempty"`
}

// Presence is one device a product is currently reported on.
type Presence struct {
	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
	Platform string `json:"platform"`
	// ObservedSince is the earliest first_seen among the product's current
	// inventory rows on this device. A version upgrade starts a new row, so
	// this is "present in its current form since", not first install.
	ObservedSince time.Time `json:"observed_since"`
	// LastSeen is the device's last report; Stale is LastSeen older than
	// StaleAfter. A stale device's presence is old evidence, not current.
	LastSeen time.Time `json:"last_seen"`
	Stale    bool      `json:"stale"`
}

// Assessment is one product at one resolved approval state, with the devices
// that resolve to it. A product usually has one assessment; it has more only
// when different devices resolve it to different policies.
type Assessment struct {
	Product
	State string
	// PolicyKind is TypeApplication or TypeBrowserExtension for a policy row,
	// "" when unreviewed.
	PolicyKind      string
	PolicyID        int64
	PolicyUpdatedAt *time.Time
	Devices         []Presence
}

// Estate is the tenant's current governance picture.
type Estate struct {
	AsOf         time.Time
	DevicesTotal int
	DevicesStale int
	// DevicesWithoutInventory have reported no application at all, so
	// nothing about their software can be concluded.
	DevicesWithoutInventory int
	// DevicesRetired (PAT-2135) are devices the customer has retired. They
	// stay in DevicesTotal but are counted here instead of in DevicesStale
	// or DevicesWithoutInventory, and OldestDeviceLastSeen ignores them.
	DevicesRetired                int
	DevicesWithUnavailableTooling int
	OldestDeviceLastSeen          *time.Time
	Assessments                   []Assessment
}

type appPolicyRow struct {
	policy    apppolicy.Policy
	updatedAt time.Time
}

type extPolicyRow struct {
	id        int64
	browser   string
	extension string
	policy    string
	updatedAt time.Time
}

// homebrewPolicyRow is one tenant_homebrew_policies row (PAT-2058).
type homebrewPolicyRow struct {
	id        int64
	kind      string
	name      string
	tap       string
	policy    string
	updatedAt time.Time
}

type observationPolicyRow struct {
	id                         int64
	kind, name, source, policy string
	updatedAt                  time.Time
}

type policies struct {
	apps         map[int64]appPolicyRow
	appIndex     apppolicy.Index
	exts         map[string]extPolicyRow         // browser + "\x00" + extension id
	homebrew     map[string]homebrewPolicyRow    // kind + "\x00" + name + "\x00" + tap
	observations map[string]observationPolicyRow // kind + name + source
}

// homebrewPolicyKey builds the lookup key for policies.homebrew: an exact
// match on kind, name and the normalised tap. No fuzzy fallback -- a
// formula's or cask's identity is already the package's own namespace
// (PAT-2013), not the fuzzy multi-signal identity apps need.
func homebrewPolicyKey(kind, name, tap string) string {
	return kind + "\x00" + name + "\x00" + NormalizeHomebrewTap(kind, tap)
}

var observationPolicyKinds = map[string]bool{
	"ide_extension": true, "npm_package": true, "pip_package": true,
	"local_model": true, "local_model_runtime": true, "mcp_server": true,
}

// ObservationPolicyKind reports whether an identity kind is a named,
// decision-safe PAT-2021 tooling identity. The *_unidentified and unnamed
// evidence kinds intentionally return false.
func ObservationPolicyKind(kind string) bool { return observationPolicyKinds[kind] }

func observationPolicyKey(kind, name, source string) string {
	return kind + "\x00" + name + "\x00" + source
}

func loadPolicies(ctx context.Context, q Querier, tenantID string) (policies, error) {
	p := policies{apps: map[int64]appPolicyRow{}, exts: map[string]extPolicyRow{}, homebrew: map[string]homebrewPolicyRow{}, observations: map[string]observationPolicyRow{}}
	rows, err := q.Query(ctx, `
		SELECT id, team_id, bundle_id, winget_id, name, platform, policy, enforcement_tier, min_version, updated_at, source
		FROM effective_tenant_app_policies($1::uuid)
		WHERE tenant_id = $1::uuid
	`, tenantID)
	if err != nil {
		return p, fmt.Errorf("load app policies: %w", err)
	}
	var list []apppolicy.Policy
	for rows.Next() {
		var r appPolicyRow
		if err := rows.Scan(&r.policy.ID, &r.policy.TeamID, &r.policy.BundleID, &r.policy.WingetID,
			&r.policy.Name, &r.policy.Platform, &r.policy.Policy, &r.policy.EnforcementTier,
			&r.policy.MinVersion, &r.updatedAt, &r.policy.Source); err != nil {
			rows.Close()
			return p, fmt.Errorf("scan app policy: %w", err)
		}
		p.apps[r.policy.ID] = r
		list = append(list, r.policy)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return p, fmt.Errorf("iterate app policies: %w", err)
	}
	p.appIndex = apppolicy.BuildIndex(list)

	rows, err = q.Query(ctx, `
		SELECT id, browser, extension_id, policy, updated_at
		FROM tenant_extension_policies
		WHERE tenant_id = $1::uuid
	`, tenantID)
	if err != nil {
		return p, fmt.Errorf("load extension policies: %w", err)
	}
	for rows.Next() {
		var r extPolicyRow
		if err := rows.Scan(&r.id, &r.browser, &r.extension, &r.policy, &r.updatedAt); err != nil {
			rows.Close()
			return p, fmt.Errorf("scan extension policy: %w", err)
		}
		p.exts[r.browser+"\x00"+r.extension] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return p, fmt.Errorf("iterate extension policies: %w", err)
	}

	rows, err = q.Query(ctx, `
		SELECT id, kind, name, tap, policy, updated_at
		FROM tenant_homebrew_policies
		WHERE tenant_id = $1::uuid
	`, tenantID)
	if err != nil {
		return p, fmt.Errorf("load homebrew policies: %w", err)
	}
	for rows.Next() {
		var r homebrewPolicyRow
		if err := rows.Scan(&r.id, &r.kind, &r.name, &r.tap, &r.policy, &r.updatedAt); err != nil {
			rows.Close()
			return p, fmt.Errorf("scan homebrew policy: %w", err)
		}
		p.homebrew[homebrewPolicyKey(r.kind, r.name, r.tap)] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return p, fmt.Errorf("iterate homebrew policies: %w", err)
	}

	rows, err = q.Query(ctx, `
		SELECT id, identity_kind, name, source, policy, updated_at
		FROM tenant_observation_policies
		WHERE tenant_id = $1::uuid
	`, tenantID)
	if err != nil {
		return p, fmt.Errorf("load observation policies: %w", err)
	}
	for rows.Next() {
		var r observationPolicyRow
		if err := rows.Scan(&r.id, &r.kind, &r.name, &r.source, &r.policy, &r.updatedAt); err != nil {
			rows.Close()
			return p, fmt.Errorf("scan observation policy: %w", err)
		}
		p.observations[observationPolicyKey(r.kind, r.name, r.source)] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return p, fmt.Errorf("iterate observation policies: %w", err)
	}
	return p, nil
}

// AppPolicyState maps a tenant_app_policies.policy value to the portal state.
func AppPolicyState(policy string) string {
	switch policy {
	case "unmanaged":
		return StateIgnored
	case "":
		return StateUnreviewed
	}
	return policy
}

// resolveApp returns the state and policy row for one installed application.
func (p policies) resolveApp(teamID, identifier, identifierKind, name, deviceOS string) (string, *appPolicyRow) {
	policy, ok := p.appIndex.Resolve(teamID, identifier, identifierKind, name, deviceOS)
	if !ok {
		return StateUnreviewed, nil
	}
	row := p.apps[policy.ID]
	return AppPolicyState(policy.Policy), &row
}

// resolveExtension applies the portal extension rule: a row for the exact
// browser wins over an 'any' row.
func (p policies) resolveExtension(browser, extensionID string) (string, *extPolicyRow) {
	if r, ok := p.exts[browser+"\x00"+extensionID]; ok {
		return r.policy, &r
	}
	if r, ok := p.exts["any\x00"+extensionID]; ok {
		return r.policy, &r
	}
	return StateUnreviewed, nil
}

// resolveHomebrew returns the state and policy row for one current formula
// or cask entry, by exact (kind, name, tap) match. Same vocabulary as
// AppPolicyState (” unreviewed, 'unmanaged' ignored, otherwise the policy
// value itself); homebrew policy rows never carry 'mandatory'.
func (p policies) resolveHomebrew(kind, name, tap string) (string, *homebrewPolicyRow) {
	if r, ok := p.homebrew[homebrewPolicyKey(kind, name, tap)]; ok {
		return AppPolicyState(r.policy), &r
	}
	return StateUnreviewed, nil
}

func (p policies) resolveObservation(kind, name, source string) (string, *observationPolicyRow) {
	if !observationPolicyKinds[kind] {
		return StateUnreviewed, nil
	}
	if r, ok := p.observations[observationPolicyKey(kind, name, source)]; ok {
		return AppPolicyState(r.policy), &r
	}
	return StateUnreviewed, nil
}

// ApplicationKey builds PAT-2007's product key for an application.
func ApplicationKey(platform, identifier, teamID string) string {
	key := "application:" + platform + ":" + strings.ToLower(strings.TrimSpace(identifier))
	if teamID != "" {
		key += ":" + teamID
	}
	return key
}

// ExtensionKey builds PAT-2007's product key for a browser extension.
func ExtensionKey(browser, extensionID string) string {
	return "browser_extension:" + browser + ":" + extensionID
}

// ObservationKey is an opaque, stable portal and audit-history key for one
// named tooling observation identity. It is never parsed by the server.
func ObservationKey(kind, name, source string) string {
	return "observation:" + kind + ":" + name + ":" + source
}

// homebrewDefaultTap is the tap PAT-2013's collector assumes when a formula
// or cask's own tap is not the point of interest: homebrew/core for a
// formula, homebrew/cask for a cask.
func homebrewDefaultTap(kind string) string {
	if kind == "cask" {
		return "homebrew/cask"
	}
	return "homebrew/core"
}

// NormalizeHomebrewTap (PAT-2058) lower-cases and trims a formula or cask's
// tap and collapses it to "" whenever it is the package's own default tap
// (homebrew/core for a formula, homebrew/cask for a cask) or was not
// recorded at all. A formula or cask reported with an explicit default tap
// and one reported with no tap therefore resolve to the same identity and
// the same product key; any other tap stays distinct, because a same-named
// package in a third-party tap is a different package (AGENTS.md "identity
// is not packaging"). kind is "formula" or "cask".
func NormalizeHomebrewTap(kind, tap string) string {
	t := strings.ToLower(strings.Join(strings.Fields(tap), " "))
	if t == homebrewDefaultTap(kind) {
		return ""
	}
	return t
}

// homebrewKey builds PAT-2007/PAT-2058's product key for a Homebrew formula
// or cask: "homebrew:<kind>:<name>", tap-qualified as
// "homebrew:<kind>:<tap>/<name>" only when the tap is not the package's own
// default (NormalizeHomebrewTap), since a bare name is ambiguous across
// taps but the default tap is not worth spelling out on every key.
func homebrewKey(kind, name, tap string) string {
	n := strings.ToLower(strings.Join(strings.Fields(name), " "))
	key := "homebrew:" + kind + ":" + n
	if t := NormalizeHomebrewTap(kind, tap); t != "" {
		key = "homebrew:" + kind + ":" + t + "/" + n
	}
	return key
}

// HomebrewFormulaKey builds PAT-2058's product key for a Homebrew formula.
func HomebrewFormulaKey(name, tap string) string { return homebrewKey("formula", name, tap) }

// HomebrewCaskKey builds PAT-2058's product key for a Homebrew cask.
func HomebrewCaskKey(name, tap string) string { return homebrewKey("cask", name, tap) }

// normalisedTeamID keeps a macOS Team ID only when it has the Apple shape; a
// Windows device_apps.team_id is a publisher name and is not part of the key.
func normalisedTeamID(platform, teamID string) string {
	if platform != "macos" {
		return ""
	}
	t := strings.ToUpper(strings.TrimSpace(teamID))
	if !teamIDPattern.MatchString(t) {
		return ""
	}
	return t
}

// AuthenticodePublisherKeyPrefix starts every Windows publisher key.
const AuthenticodePublisherKeyPrefix = "authenticode:"

// AuthenticodePublisherKey is the Windows counterpart of normalisedTeamID
// (PAT-2121): the stable publisher identity an approval can record and a
// later product can be matched against. The key is
//
//	authenticode:<root thumbprint>:<normalised leaf Subject DN>
//
// The root thumbprint is the SHA-256 of the trust anchor the agent's
// WinVerifyTrust verdict rests on (0188), lowercase hex, and pins the
// publisher to one chain: a lookalike Subject DN issued under another root
// never shares the key. The leaf thumbprint is deliberately not used, because
// it changes every time the publisher renews its certificate.
//
// The Subject DN is normalised deterministically and conservatively:
// leading and trailing whitespace is trimmed and every run of Unicode
// whitespace inside it becomes one ASCII space. Case is kept, RDN order is
// kept, and nothing around the "," or "=" separators is re-spaced, so
// "CN=A, O=B" and "CN=A,O=B" are different keys. Any difference the rule does
// not remove makes two products not match, which fails towards Medium, never
// towards Low.
//
// It returns "" (no key) when the root thumbprint is not 64 lowercase hex
// characters after trimming, or the normalised DN is empty, too long (over
// 512 characters, the 0186 bound) or carries a control character. It does
// not judge the root kind: callers give it only a microsoft or public root
// (an enterprise root never gets a key).
func AuthenticodePublisherKey(rootThumbprint, subjectDN string) string {
	root := strings.TrimSpace(rootThumbprint)
	if !sha256HexPattern.MatchString(root) {
		return ""
	}
	dn := strings.Join(strings.Fields(subjectDN), " ")
	if dn == "" || utf8.RuneCountInString(dn) > 512 || !utf8.ValidString(dn) ||
		strings.IndexFunc(dn, unicode.IsControl) >= 0 {
		return ""
	}
	return AuthenticodePublisherKeyPrefix + root + ":" + dn
}

var sha256HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type assessmentKey struct {
	productKey string
	state      string
	policyKind string
	policyID   int64
}

type builder struct {
	asOf        time.Time
	assessments map[assessmentKey]*Assessment
	presence    map[assessmentKey]map[string]*Presence
	// devProduct (PAT-2095) is the product as one device reports it, with the
	// lexically smallest name that device reports, for the per-device
	// Unapproved-present summary rows.
	devProduct map[assessmentKey]map[string]*Product
}

func newBuilder(asOf time.Time) *builder {
	return &builder{asOf: asOf, assessments: map[assessmentKey]*Assessment{},
		presence: map[assessmentKey]map[string]*Presence{}, devProduct: map[assessmentKey]map[string]*Product{}}
}

func (b *builder) add(product Product, state, policyKind string, policyID int64, policyUpdated *time.Time,
	deviceID, hostname, platform string, lastSeen, firstSeen time.Time) {
	k := assessmentKey{productKey: product.ProductKey, state: state, policyKind: policyKind, policyID: policyID}
	a, ok := b.assessments[k]
	if !ok {
		a = &Assessment{Product: product, State: state, PolicyKind: policyKind, PolicyID: policyID, PolicyUpdatedAt: policyUpdated}
		b.assessments[k] = a
		b.presence[k] = map[string]*Presence{}
		b.devProduct[k] = map[string]*Product{}
	} else if product.Name < a.Name {
		// Deterministic label: the lexically smallest observed name, the
		// same rule GET /v1/portal/software uses.
		a.Name = product.Name
	}
	pr, ok := b.presence[k][deviceID]
	if !ok {
		b.presence[k][deviceID] = &Presence{
			DeviceID: deviceID, Hostname: hostname, Platform: platform,
			ObservedSince: firstSeen.UTC(), LastSeen: lastSeen.UTC(),
			Stale: lastSeen.Before(b.asOf.Add(-StaleAfter)),
		}
		p := product
		b.devProduct[k][deviceID] = &p
		return
	}
	if firstSeen.Before(pr.ObservedSince) {
		pr.ObservedSince = firstSeen.UTC()
	}
	if dp := b.devProduct[k][deviceID]; product.Name < dp.Name {
		dp.Name = product.Name
	}
}

func (b *builder) result() []Assessment {
	out := make([]Assessment, 0, len(b.assessments))
	for k, a := range b.assessments {
		devs := make([]Presence, 0, len(b.presence[k]))
		for _, pr := range b.presence[k] {
			devs = append(devs, *pr)
		}
		sort.Slice(devs, func(i, j int) bool {
			if devs[i].Hostname != devs[j].Hostname {
				return devs[i].Hostname < devs[j].Hostname
			}
			return devs[i].DeviceID < devs[j].DeviceID
		})
		a.Devices = devs
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool {
		if ri, rj := stateRank[out[i].State], stateRank[out[j].State]; ri != rj {
			return ri > rj
		}
		if len(out[i].Devices) != len(out[j].Devices) {
			return len(out[i].Devices) > len(out[j].Devices)
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].ProductKey != out[j].ProductKey {
			return out[i].ProductKey < out[j].ProductKey
		}
		return out[i].PolicyID < out[j].PolicyID
	})
	return out
}

// loadAssessments resolves every current application and extension row for
// the tenant, or for one device when deviceID is non-empty.
func loadAssessments(ctx context.Context, q Querier, tenantID, deviceID string, asOf time.Time) ([]Assessment, error) {
	pol, err := loadPolicies(ctx, q, tenantID)
	if err != nil {
		return nil, err
	}
	var devices []string
	if deviceID != "" {
		devices = []string{deviceID}
	}
	b, err := scanInventory(ctx, q, tenantID, devices, pol, asOf)
	if err != nil {
		return nil, err
	}
	return b.result(), nil
}

// scanInventory resolves the current application, extension and Homebrew
// rows of the tenant against pol, for every device when devices is nil and
// for exactly those devices otherwise. It is the one resolution path: the
// full estate load and the PAT-2095 per-device summary refresh both use it,
// so the two cannot resolve a product differently.
func scanInventory(ctx context.Context, q Querier, tenantID string, devices []string, pol policies, asOf time.Time) (*builder, error) {
	b := newBuilder(asOf)
	var devArg any
	if devices != nil {
		devArg = devices
	}

	rows, err := q.Query(ctx, `
		SELECT d.id::text, COALESCE(d.hostname, ''), COALESCE(d.os, ''), d.last_seen,
		       da.identifier, COALESCE(da.identifier_kind, ''), COALESCE(da.team_id, ''), da.name, da.first_seen
		FROM device_apps da
		JOIN devices d ON d.id = da.device_id
		WHERE d.tenant_id = $1::uuid
		  AND ($2::uuid[] IS NULL OR d.id = ANY($2::uuid[]))
		LIMIT $3
	`, tenantID, devArg, MaxEstateRows+1)
	if err != nil {
		return nil, fmt.Errorf("load device apps: %w", err)
	}
	n := 0
	for rows.Next() {
		n++
		if n > MaxEstateRows {
			rows.Close()
			return nil, ErrEstateTooLarge
		}
		var devID, host, osName, identifier, kind, team, name string
		var lastSeen, firstSeen time.Time
		if err := rows.Scan(&devID, &host, &osName, &lastSeen, &identifier, &kind, &team, &name, &firstSeen); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan device app: %w", err)
		}
		platform := apppolicy.DevicePlatform(osName)
		teamKey := normalisedTeamID(platform, team)
		ident := strings.TrimSpace(identifier)
		product := Product{
			Type: TypeApplication, ProductKey: ApplicationKey(platform, ident, teamKey),
			Name: name, Platform: platform, Identifier: ident, TeamID: teamKey,
		}
		state, row := pol.resolveApp(team, identifier, kind, name, osName)
		policyKind, policyID := "", int64(0)
		var updated *time.Time
		if row != nil {
			policyKind, policyID = TypeApplication, row.policy.ID
			u := row.updatedAt
			updated = &u
		}
		b.add(product, state, policyKind, policyID, updated, devID, host, platform, lastSeen, firstSeen)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate device apps: %w", err)
	}

	rows, err = q.Query(ctx, `
		SELECT d.id::text, COALESCE(d.hostname, ''), COALESCE(d.os, ''), d.last_seen,
		       dbe.browser, dbe.extension_id, dbe.name, dbe.first_seen
		FROM device_browser_extensions dbe
		JOIN devices d ON d.id = dbe.device_id
		WHERE d.tenant_id = $1::uuid
		  AND ($2::uuid[] IS NULL OR d.id = ANY($2::uuid[]))
		LIMIT $3
	`, tenantID, devArg, MaxEstateRows+1-n)
	if err != nil {
		return nil, fmt.Errorf("load browser extensions: %w", err)
	}
	m := 0
	for rows.Next() {
		m++
		if n+m > MaxEstateRows {
			rows.Close()
			return nil, ErrEstateTooLarge
		}
		var devID, host, osName, browser, extID, name string
		var lastSeen, firstSeen time.Time
		if err := rows.Scan(&devID, &host, &osName, &lastSeen, &browser, &extID, &name, &firstSeen); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan browser extension: %w", err)
		}
		product := Product{
			Type: TypeBrowserExtension, ProductKey: ExtensionKey(browser, extID),
			Name: name, Browser: browser, ExtensionID: extID,
		}
		state, row := pol.resolveExtension(browser, extID)
		policyKind, policyID := "", int64(0)
		var updated *time.Time
		if row != nil {
			policyKind, policyID = TypeBrowserExtension, row.id
			u := row.updatedAt
			updated = &u
		}
		b.add(product, state, policyKind, policyID, updated, devID, host, apppolicy.DevicePlatform(osName), lastSeen, firstSeen)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate browser extensions: %w", err)
	}

	// PAT-2058: current Homebrew formulae and casks, joined through the same
	// evidence PAT-2032's homebrewCurrentCTE reads (internal/report), but
	// scoped to package_kind IN ('formula','cask') -- taps are not
	// approvable. identity_value_normalized/companion_value_normalized are
	// the same normalised name/tap the extractor already computed
	// (deriveHomebrewIdentity), so no re-normalisation happens here beyond
	// NormalizeHomebrewTap's default-tap collapse.
	rows, err = q.Query(ctx, `
		SELECT d.id::text, COALESCE(d.hostname, ''), d.last_seen,
		       ce.package_kind, h.name, so.identity_value_normalized, so.companion_value_normalized,
		       COALESCE(si.first_seen_at, ce.observed_at),
		       EXISTS (
		           SELECT 1 FROM homebrew_cask_app_links l
		           JOIN software_installations ai
		             ON ai.id = l.app_installation_id AND ai.tenant_id = l.tenant_id
		            AND ai.device_id = l.device_id AND ai.removed_at IS NULL
		           WHERE l.cask_installation_id = si.id AND l.tenant_id = $1::uuid
		       )
		FROM homebrew_current_entries ce
		JOIN devices d ON d.id = ce.device_id AND d.tenant_id = $1::uuid
		JOIN homebrew_device_state s ON s.device_id = ce.device_id AND s.tenant_id = $1::uuid
		JOIN homebrew_observation_details h
		  ON h.inventory_run_id = ce.inventory_run_id AND h.device_id = ce.device_id
		 AND h.package_kind = ce.package_kind AND h.prefix = ce.prefix AND h.name = ce.name
		 AND (h.package_kind <> 'formula' OR h.version = ce.version_key)
		 AND h.tenant_id = $1::uuid
		JOIN software_observations so ON so.id = h.observation_id AND so.tenant_id = h.tenant_id
		LEFT JOIN software_installations si
		  ON si.tenant_id = $1::uuid AND si.device_id = ce.device_id AND si.identity_fingerprint = so.identity_fingerprint
		WHERE ce.tenant_id = $1::uuid
		  AND ce.package_kind IN ('formula', 'cask')
		  AND (s.authority_at IS NULL OR ce.observed_at >= s.authority_at)
		  AND ($2::uuid[] IS NULL OR d.id = ANY($2::uuid[]))
		LIMIT $3
	`, tenantID, devArg, MaxEstateRows+1-n-m)
	if err != nil {
		return nil, fmt.Errorf("load homebrew entries: %w", err)
	}
	k := 0
	for rows.Next() {
		k++
		if n+m+k > MaxEstateRows {
			rows.Close()
			return nil, ErrEstateTooLarge
		}
		var devID, host, kind, observedName, name, tap string
		var linkedToApp bool
		var lastSeen, firstSeen time.Time
		if err := rows.Scan(&devID, &host, &lastSeen, &kind, &observedName, &name, &tap, &firstSeen, &linkedToApp); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan homebrew entry: %w", err)
		}
		// A linked cask is the installation mechanism for an application,
		// not a second governance product. Its Homebrew API row inherits the
		// linked application's policy below in report/portal_homebrew.go; the
		// estate/drift path deliberately counts the app only.
		if kind == "cask" && linkedToApp {
			continue
		}
		productType, key := TypeHomebrewFormula, HomebrewFormulaKey(name, tap)
		if kind == "cask" {
			productType, key = TypeHomebrewCask, HomebrewCaskKey(name, tap)
		}
		product := Product{
			Type: productType, ProductKey: key, Name: observedName,
			Platform: "macos", Identifier: name, Tap: NormalizeHomebrewTap(kind, tap),
		}
		state, row := pol.resolveHomebrew(kind, name, tap)
		policyKind, policyID := "", int64(0)
		var updated *time.Time
		if row != nil {
			policyKind, policyID = productType, row.id
			u := row.updatedAt
			updated = &u
		}
		b.add(product, state, policyKind, policyID, updated, devID, host, "macos", lastSeen, firstSeen)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate homebrew entries: %w", err)
	}

	// PAT-2031: the named tooling identities live on the normal software
	// observation seam but have their own absence authority. Resolve only
	// current entries whose block and unit both remain readable. This mirrors
	// report.toolingCurrentCTE without importing the report package, keeping
	// the governance resolver independent of presentation code.
	rows, err = q.Query(ctx, `
		SELECT d.id::text, COALESCE(d.hostname, ''), COALESCE(d.os, ''), d.last_seen,
		       so.identity_kind, so.identity_value_normalized, so.companion_value_normalized,
		       COALESCE(si.current_name, so.observed_name), COALESCE(si.first_seen_at, c.observed_at)
		FROM tooling_current_entries c
		JOIN tooling_device_state s
		  ON s.device_id = c.device_id AND s.tenant_id = c.tenant_id AND s.block = c.block
		JOIN devices d ON d.id = c.device_id AND d.tenant_id = c.tenant_id
		JOIN software_observations so ON so.id = c.observation_id AND so.tenant_id = c.tenant_id
		LEFT JOIN software_installations si
		  ON si.tenant_id = c.tenant_id AND si.device_id = c.device_id
		 AND si.identity_fingerprint = so.identity_fingerprint AND si.removed_at IS NULL
		WHERE c.tenant_id = $1::uuid
		  AND s.collection_status IN ('complete', 'partial', 'not_present')
		  AND COALESCE(s.unit_statuses ->> c.unit, s.collection_status) IN ('complete', 'partial', 'not_present')
		  AND c.observed_at >= COALESCE((s.authority ->> c.unit)::timestamptz, '-infinity'::timestamptz)
		  AND ($2::uuid[] IS NULL OR d.id = ANY($2::uuid[]))
		  AND so.identity_kind IN ('ide_extension', 'npm_package', 'pip_package',
		                           'local_model', 'local_model_runtime', 'mcp_server')
		LIMIT $3
	`, tenantID, devArg, MaxEstateRows+1-n-m-k)
	if err != nil {
		return nil, fmt.Errorf("load tooling entries: %w", err)
	}
	tooling := 0
	for rows.Next() {
		tooling++
		if n+m+k+tooling > MaxEstateRows {
			rows.Close()
			return nil, ErrEstateTooLarge
		}
		var devID, host, osName, kind, name, source, observedName string
		var lastSeen, firstSeen time.Time
		if err := rows.Scan(&devID, &host, &osName, &lastSeen, &kind, &name, &source, &observedName, &firstSeen); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan tooling entry: %w", err)
		}
		product := Product{Type: TypeObservation, ProductKey: ObservationKey(kind, name, source),
			Name: observedName, Platform: apppolicy.DevicePlatform(osName), Identifier: name,
			ObservationKind: kind, ObservationSource: source}
		state, row := pol.resolveObservation(kind, name, source)
		policyKind, policyID := "", int64(0)
		var updated *time.Time
		if row != nil {
			policyKind, policyID = TypeObservation, row.id
			u := row.updatedAt
			updated = &u
		}
		b.add(product, state, policyKind, policyID, updated, devID, host, product.Platform, lastSeen, firstSeen)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tooling entries: %w", err)
	}
	return b, nil
}

// LoadEstate resolves the tenant's whole current inventory.
func LoadEstate(ctx context.Context, q Querier, tenantID string, asOf time.Time) (Estate, error) {
	e := Estate{AsOf: asOf.UTC()}
	var oldest *time.Time
	if err := q.QueryRow(ctx, `
		SELECT count(*)::int,
		       count(*) FILTER (WHERE NOT r.retired AND d.last_seen < $2)::int,
		       count(*) FILTER (WHERE NOT r.retired AND NOT EXISTS (SELECT 1 FROM device_apps da WHERE da.device_id = d.id))::int,
		       min(d.last_seen) FILTER (WHERE NOT r.retired),
		       count(*) FILTER (WHERE r.retired)::int
		FROM devices d
		CROSS JOIN LATERAL (SELECT `+deviceretirement.RetiredSQL("d")+` AS retired) r
		WHERE d.tenant_id = $1::uuid
	`, tenantID, asOf.Add(-StaleAfter)).Scan(&e.DevicesTotal, &e.DevicesStale, &e.DevicesWithoutInventory, &oldest, &e.DevicesRetired); err != nil {
		return e, fmt.Errorf("device coverage: %w", err)
	}
	if oldest != nil {
		o := oldest.UTC()
		e.OldestDeviceLastSeen = &o
	}
	if err := q.QueryRow(ctx, `
		SELECT count(*)::int FROM devices d
		CROSS JOIN LATERAL (SELECT `+deviceretirement.RetiredSQL("d")+` AS retired) r
		WHERE d.tenant_id = $1::uuid AND NOT r.retired
		  AND (SELECT count(*) FROM tooling_device_state s
		       WHERE s.tenant_id = d.tenant_id AND s.device_id = d.id
		         AND s.block IN ('ide_extensions','package_managers','local_models','mcp_servers')
		         AND s.collection_status IN ('complete','not_present')
		         AND COALESCE(s.truncated, FALSE) = FALSE
		         AND s.reported_at > '-infinity'::timestamptz
		         AND NOT EXISTS (SELECT 1 FROM jsonb_each_text(COALESCE(s.unit_statuses, '{}'::jsonb)) u WHERE u.value NOT IN ('complete','not_present'))
		      ) <> 4
	`, tenantID).Scan(&e.DevicesWithUnavailableTooling); err != nil {
		return e, fmt.Errorf("tooling coverage: %w", err)
	}
	assessments, err := loadAssessments(ctx, q, tenantID, "", asOf)
	if err != nil {
		return e, err
	}
	e.Assessments = assessments
	return e, nil
}

// Coverage is the evidence behind a governance figure. Complete is false
// whenever a device is stale or has reported no applications, because then
// "nothing unapproved" or "nothing new" cannot be claimed for the whole
// estate.
//
// PAT-2135: a device the customer has retired is counted in DevicesRetired,
// not in DevicesStale or DevicesWithoutInventory, so it no longer holds
// Complete false. devices_total = devices_reporting + devices_stale +
// devices_retired.
type Coverage struct {
	DevicesTotal            int `json:"devices_total"`
	DevicesReporting        int `json:"devices_reporting"`
	DevicesStale            int `json:"devices_stale"`
	DevicesRetired          int `json:"devices_retired"`
	DevicesWithoutInventory int `json:"devices_without_inventory"`
	// ToolingEvidenceComplete is distinct from Complete: application-only
	// urgency keeps its existing coverage rule, while tooling review/drift
	// callers can see when a device lacks authoritative
	// tooling-block evidence.
	DevicesWithUnavailableTooling int        `json:"devices_with_unavailable_tooling"`
	ToolingEvidenceComplete       bool       `json:"tooling_evidence_complete"`
	OldestDeviceLastSeen          *time.Time `json:"oldest_device_last_seen"`
	StaleAfterDays                int        `json:"stale_after_days"`
	Complete                      bool       `json:"complete"`
}

// CoverageOf summarises an estate's evidence.
func CoverageOf(e Estate) Coverage {
	return Coverage{
		DevicesTotal:                  e.DevicesTotal,
		DevicesReporting:              e.DevicesTotal - e.DevicesStale - e.DevicesRetired,
		DevicesStale:                  e.DevicesStale,
		DevicesRetired:                e.DevicesRetired,
		DevicesWithoutInventory:       e.DevicesWithoutInventory,
		DevicesWithUnavailableTooling: e.DevicesWithUnavailableTooling,
		OldestDeviceLastSeen:          e.OldestDeviceLastSeen,
		StaleAfterDays:                int(StaleAfter / (24 * time.Hour)),
		Complete:                      e.DevicesTotal-e.DevicesRetired > 0 && e.DevicesStale == 0 && e.DevicesWithoutInventory == 0,
		ToolingEvidenceComplete:       e.DevicesWithUnavailableTooling == 0,
	}
}

// Policies is the tenant's resolved policy indices (applications, browser
// extensions, Homebrew and named tooling observations), exported so another report can resolve the exact
// same approval state this package uses without a parallel list or a second
// copy of the resolution rules -- a product can never read Unapproved on one
// report and Approved on another. PAT-2148 (the remote access / RMM report)
// is the first caller outside this package.
type Policies struct{ p policies }

// LoadPolicies loads one tenant's policy rows once, for resolving many
// products against them (LoadEstate does the same internally).
func LoadPolicies(ctx context.Context, q Querier, tenantID string) (Policies, error) {
	p, err := loadPolicies(ctx, q, tenantID)
	return Policies{p}, err
}

// ResolveApp resolves one application's approval state exactly as the drift,
// posture and finding-lifecycle surfaces do (apppolicy.Index.Resolve).
// identifierKind matters only to recognise a Windows winget identity; pass
// through the installation's own identity_kind (a "windows_winget" value
// from the software observation domain is treated the same as device_apps'
// "winget").
func (pp Policies) ResolveApp(teamID, identifier, identifierKind, name, deviceOS string) string {
	if identifierKind == "windows_winget" {
		identifierKind = "winget"
	}
	state, _ := pp.p.resolveApp(teamID, identifier, identifierKind, name, deviceOS)
	return state
}

// ResolveExtension resolves one browser extension's approval state: the
// exact browser wins over an 'any' row.
func (pp Policies) ResolveExtension(browser, extensionID string) string {
	state, _ := pp.p.resolveExtension(browser, extensionID)
	return state
}

// ResolveHomebrew resolves one formula's or cask's approval state by exact
// (kind, name, tap) match. kind is "formula" or "cask".
func (pp Policies) ResolveHomebrew(kind, name, tap string) string {
	state, _ := pp.p.resolveHomebrew(kind, name, tap)
	return state
}

// ResolveObservation resolves one named PAT-2021 observation by exact
// identity kind, normalised name and source. Unidentified kinds always read
// unreviewed and are deliberately not policy targets.
func (pp Policies) ResolveObservation(kind, name, source string) string {
	state, _ := pp.p.resolveObservation(kind, name, source)
	return state
}
