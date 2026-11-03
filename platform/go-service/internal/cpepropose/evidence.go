package cpepropose

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"patched.im/api/internal/cvematch"
)

// maxTuplesPerTenant bounds the distinct evidence tuples read for one
// product from one tenant. A tenant reporting more variants than this
// cannot agree on one signer anyway; hitting the bound marks the evidence
// truncated (Evidence.TooManyTuples), which never publishes; the re-check
// still demotes on what it read when that already meets its rule.
const maxTuplesPerTenant = 20

// Evidence is what the worker knows about one proposed product, estate-wide.
//
// It is stored in the global cpe_mapping_proposals.evidence column and its
// Product part is the only endpoint-derived data that leaves the platform
// (the model prompt; the NVD keyword is derived from the same normalised
// name). A product leaves the platform at all only when it is Eligible
// (PAT-2138 re-review, P2-b). What leaves is limited to what cannot identify
// a tenant, a device or a person:
//
//   - the normalised product name;
//   - signer values that are in the curated cpe_vendor_aliases table, and
//     only from installations whose signature is a public one (publicSigner):
//     the table's own alias_value for a Windows Subject O= or a macOS Team
//     ID. A signer that is not aliased (a customer's own Developer ID or
//     code-signing certificate, whose O= is the customer's legal name) never
//     leaves and is never stored.
//
// Versions, bundle and package identifiers, registry publisher strings,
// full signer DNs and developer-certificate names (which carry a person's
// name) are never read into it. Counts are aggregates only; tenant ids are
// read into Installations for the tenant counts and never serialised.
type Evidence struct {
	Product ProductEvidence `json:"product"`
	// Installations holds one entry per distinct evidence tuple per tenant
	// (not per installation). Never serialised.
	Installations []Installation `json:"-"`
	TooManyTuples bool           `json:"-"`
	InstallCount  int            `json:"installations"`
	// InstallTenants is how many distinct tenants have a current
	// installation.
	InstallTenants  int           `json:"install_tenants"`
	AffectedDevices int           `json:"affected_devices"`
	AffectedTenants int           `json:"affected_tenants"`
	Corroboration   Corroboration `json:"corroboration"`
	// SignerFingerprint summarises the signer evidence the gate reads (each
	// distinct tuple reduced to an aliased signer value or a category), so a
	// corroboration_lost proposal is offered to the gate again only when it
	// changes. Carries no unaliased signer value.
	SignerFingerprint string `json:"signer_fingerprint,omitempty"`
	// ProductNameMatch is the gate's ProductMatches result for the chosen
	// candidate (nil when the model chose none).
	ProductNameMatch *bool `json:"product_name_match,omitempty"`
	// RecheckReason is the check an automatic mapping's periodic re-check
	// found failing; with RecheckDissentTenants of RecheckTenants tenants
	// dissenting. Set with corroboration_lost, and also on a kept automatic
	// mapping when the dissent was too narrow to demote it.
	RecheckReason         string `json:"recheck_reason,omitempty"`
	RecheckDissentTenants int    `json:"recheck_dissent_tenants,omitempty"`
	RecheckTenants        int    `json:"recheck_tenants,omitempty"`
	// OtherCoveredNames: see GateInput. Installed names from any tenant, so
	// never stored in the global evidence column; the admin detail route
	// computes covered_names live for staff.
	OtherCoveredNames []string `json:"-"`
}

var asciiTokenSplit = regexp.MustCompile(`[^a-z0-9]+`)

// MinOutboundTenants is how many distinct tenants must report a normalised
// product name before anything about it may leave the platform (Andy's
// ruling, 2026-09-25). Nothing else makes a product eligible: not a public
// signature (enterprises sign in-house tools with public code-signing CAs
// and Developer ID, Apple Business Manager custom apps carry the App
// Store's signature), and not an aliased vendor signer (a browser's web-app
// wrapper for one customer's intranet carries the browser vendor's Team
// ID). An aliased signer is corroboration only.
const MinOutboundTenants = 2

// Tenants is how many distinct tenants report the product: the larger of
// the current installations' tenants and the active devices' tenants, both
// counting only current customer tenants on active devices
// (currentCustomerTenantSQL): never Patched's internal tenants, a revoked or
// decommissioning tenant, an expired trial, or a device not seen within the
// active window.
func (ev Evidence) Tenants() int { return max(ev.InstallTenants, ev.AffectedTenants) }

// Eligible reports whether anything about the product may leave the
// platform (NVD keyword, model prompt): only when MinOutboundTenants
// distinct tenants report it.
func (ev Evidence) Eligible() bool { return ev.Tenants() >= MinOutboundTenants }

// aliasIndex maps (alias kind, normalised signer value) to the table's own
// alias_value.
type aliasIndex map[[2]string]string

func indexAliases(aliases []Alias) aliasIndex {
	ix := aliasIndex{}
	for _, a := range aliases {
		v := a.Value
		if a.Kind == aliasKindSubjectOrg {
			v = normalizeOrg(v)
		}
		ix[[2]string{a.Kind, v}] = a.Value
	}
	return ix
}

// aliasedSigner returns the curated alias_value for the installation's
// public signer, or false when it has no public signer or it is not aliased.
func (ix aliasIndex) aliasedSigner(platform string, in Installation) (string, string, bool) {
	kind, value, ok := publicSigner(platform, in)
	if !ok {
		return "", "", false
	}
	k := value
	if kind == aliasKindSubjectOrg {
		k = normalizeOrg(value)
	}
	canonical, ok := ix[[2]string{kind, k}]
	return kind, canonical, ok
}

// signerClass reduces an installation's signer evidence to what the gate
// distinguishes, without any unaliased value: the aliased signer, or a
// category.
func (ix aliasIndex) signerClass(platform string, in Installation) string {
	if kind, v, ok := ix.aliasedSigner(platform, in); ok {
		return kind + ":" + v
	}
	if _, _, ok := publicSigner(platform, in); ok {
		return "public_unaliased"
	}
	return "untrusted_or_absent:" + strings.ToLower(in.SigningStatus+"/"+in.SignatureState+"/"+in.RootKind)
}

// loadEvidence reads the product's current installations (latest
// observation of each, software_installations not removed) on the proposal's
// platform, by normalised name, plus live affected-device and tenant counts
// from device_apps on active devices, the rows the matcher reads. Only the
// signer authority (the macOS signer's text before its first colon, e.g.
// "Developer ID Application") is read, never the rest of the signer string.
func loadEvidence(ctx context.Context, q DB, platform, normalized string, aliases []Alias) (Evidence, error) {
	ev := Evidence{Product: ProductEvidence{Name: normalized, Platform: platform}}
	ix := indexAliases(aliases)
	// Distinct evidence tuples are capped PER TENANT, so every tenant
	// reporting the product is represented however many variants another
	// tenant reports; a tenant over the cap marks the evidence truncated
	// (TooManyTuples): never publishes; see recheckAuto for demotion.
	rows, err := q.Query(ctx, `
		SELECT tenant, status, team, state, root, dn, authority, n, rn
		FROM (
			SELECT si.tenant_id::text AS tenant,
			       COALESCE(o.observed_signing_status, '') AS status, COALESCE(o.observed_team_id, '') AS team,
			       COALESCE(o.observed_signature_state, '') AS state, COALESCE(o.observed_authenticode_root_kind, '') AS root,
			       COALESCE(o.observed_authenticode_signer, '') AS dn,
			       btrim(split_part(COALESCE(o.observed_signer, ''), ':', 1)) AS authority, count(*)::int AS n,
			       row_number() OVER (PARTITION BY si.tenant_id::text ORDER BY count(*) DESC,
			           COALESCE(o.observed_signing_status, ''), COALESCE(o.observed_team_id, ''),
			           COALESCE(o.observed_signature_state, ''), COALESCE(o.observed_authenticode_root_kind, ''),
			           COALESCE(o.observed_authenticode_signer, ''),
			           btrim(split_part(COALESCE(o.observed_signer, ''), ':', 1))) AS rn
			FROM software_installations si
			JOIN devices dv ON dv.id = si.device_id AND dv.tenant_id = si.tenant_id
			JOIN tenants tn ON tn.id = si.tenant_id
			LEFT JOIN software_observations o
			       ON o.id = si.latest_observation_id AND o.tenant_id = si.tenant_id
			WHERE si.platform = $1
			  AND si.removed_at IS NULL
			  AND dv.last_seen > NOW() - INTERVAL '`+activeDeviceWindow+`'
			  AND `+currentCustomerTenantSQL("tn")+`
			  AND cpe_normalize_name(si.current_name) = $2
			GROUP BY 1, 2, 3, 4, 5, 6, 7
		) t
		WHERE rn <= $3
		ORDER BY tenant, rn
	`, platform, normalized, maxTuplesPerTenant+1)
	if err != nil {
		return ev, fmt.Errorf("load installation evidence: %w", err)
	}
	tenants := map[string]bool{}
	classes := map[string]bool{}
	for rows.Next() {
		var in Installation
		var n int
		var rn int
		if err := rows.Scan(&in.Tenant, &in.SigningStatus, &in.TeamID, &in.SignatureState, &in.RootKind,
			&in.SubjectDN, &in.Authority, &n, &rn); err != nil {
			rows.Close()
			return ev, fmt.Errorf("scan installation evidence: %w", err)
		}
		if rn > maxTuplesPerTenant {
			ev.TooManyTuples = true
			continue
		}
		in.Platform = platform
		tenants[in.Tenant] = true
		ev.InstallCount += n
		ev.Installations = append(ev.Installations, in)
		classes[ix.signerClass(platform, in)] = true
		if kind, value, ok := ix.aliasedSigner(platform, in); ok {
			switch kind {
			case aliasKindTeamID:
				ev.Product.TeamIDs = appendUnique(ev.Product.TeamIDs, value)
			case aliasKindSubjectOrg:
				ev.Product.Publishers = appendUnique(ev.Product.Publishers, value)
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ev, fmt.Errorf("iterate installation evidence: %w", err)
	}
	ev.InstallTenants = len(tenants)
	ev.SignerFingerprint = fingerprint(classes, ev.TooManyTuples)

	if err := q.QueryRow(ctx, `
		SELECT count(DISTINCT d.id)::int, count(DISTINCT d.tenant_id)::int
		FROM device_apps da
		JOIN devices d ON d.id = da.device_id
		JOIN tenants tn ON tn.id = d.tenant_id
		WHERE d.last_seen > NOW() - INTERVAL '`+activeDeviceWindow+`'
		  AND `+currentCustomerTenantSQL("tn")+`
		  AND (CASE WHEN d.os ILIKE 'windows%' THEN 'windows'
		            WHEN d.os ILIKE 'mac%' OR d.os ILIKE 'darwin%' THEN 'macos' END) = $1
		  AND cpe_normalize_name(da.name) = $2
	`, platform, normalized).Scan(&ev.AffectedDevices, &ev.AffectedTenants); err != nil {
		return ev, fmt.Errorf("count affected devices: %w", err)
	}
	return ev, nil
}

// maxCoveredNames bounds the names coveredNames returns (the admin detail
// route's blast-radius list; the gate only needs to know whether any exist).
const maxCoveredNames = 200

// coveredNames lists installed product names on active devices of the
// platform, other than displayName's own normalised name, that displayName
// would cover as a match_name: under the automatic-mapping rule
// (cvematch.ExactNameMatches) when exact, else under a curated mapping's
// word-token rule (cvematch.NameMatches: "Notion" also covers "Notion Helper
// (Renderer)"). The gate reads the exact form, since what it publishes is an
// automatic mapping; staff read the curated form, since approving curates.
//
// The database narrows the scan with a necessary condition of the Go rule
// (exact: the same token string; curated: every token appears in the lower
// case name), Go applies the rule itself, and at most maxCoveredNames are
// returned, sorted.
func coveredNames(ctx context.Context, q DB, platform, displayName string, exact bool) ([]string, error) {
	tokens := cpeTokenSplitASCII(displayName)
	if len(tokens) == 0 {
		return nil, nil
	}
	cond := `cpe_name_tokens(da.name) = $2`
	arg := any(strings.Join(tokens, " "))
	if !exact {
		cond = `lower(da.name) LIKE ALL ($2::text[])`
		likes := make([]string, len(tokens))
		for i, t := range tokens {
			likes[i] = "%" + t + "%"
		}
		arg = likes
	}
	rows, err := q.Query(ctx, `
		SELECT DISTINCT da.name
		FROM device_apps da
		JOIN devices d ON d.id = da.device_id
		WHERE d.last_seen > NOW() - INTERVAL '`+activeDeviceWindow+`'
		  AND (CASE WHEN d.os ILIKE 'windows%' THEN 'windows'
		            WHEN d.os ILIKE 'mac%' OR d.os ILIKE 'darwin%' THEN 'macos' END) = $1
		  AND `+cond+`
		ORDER BY da.name
		LIMIT $3
	`, platform, arg, 20*maxCoveredNames)
	if err != nil {
		return nil, fmt.Errorf("load installed names: %w", err)
	}
	defer rows.Close()
	own := NormalizeName(displayName)
	match := cvematch.NameMatches
	if exact {
		match = cvematch.ExactNameMatches
	}
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("scan installed name: %w", err)
		}
		if NormalizeName(n) == own {
			continue
		}
		if match(n, displayName) {
			out = append(out, n)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate installed names: %w", err)
	}
	sort.Strings(out)
	if len(out) > maxCoveredNames {
		out = out[:maxCoveredNames]
	}
	return out, nil
}

// cpeTokenSplitASCII is the SQL function cpe_name_tokens in Go: ASCII
// lowered, split on anything not an ASCII letter or digit. It only narrows
// the database scan; cvematch's own rule then decides.
func cpeTokenSplitASCII(name string) []string {
	var out []string
	lowered := strings.Map(asciiLower, name)
	for _, t := range asciiTokenSplit.Split(lowered, -1) {
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// annotateCVECounts sets each candidate's CVECount from the local feed.
func annotateCVECounts(ctx context.Context, q DB, cands []Candidate) error {
	if len(cands) == 0 {
		return nil
	}
	keys := make([]string, len(cands))
	for i, c := range cands {
		keys[i] = c.Key()
	}
	rows, err := q.Query(ctx, `
		SELECT k, count(e.cve_id)::int
		FROM unnest($1::text[]) AS k
		LEFT JOIN cve_feed_entries e ON e.cpe_patterns @> ARRAY[k]
		GROUP BY k
	`, keys)
	if err != nil {
		return fmt.Errorf("count candidate cves: %w", err)
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return fmt.Errorf("scan candidate cve count: %w", err)
		}
		counts[k] = n
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range cands {
		cands[i].CVECount = counts[cands[i].Key()]
	}
	return nil
}

func appendUnique(list []string, v string) []string {
	if v == "" || len(list) >= 10 {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func fingerprint(classes map[string]bool, truncated bool) string {
	keys := make([]string, 0, len(classes))
	for k := range classes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if truncated {
		keys = append(keys, "truncated")
	}
	sum := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	return hex.EncodeToString(sum[:8])
}
