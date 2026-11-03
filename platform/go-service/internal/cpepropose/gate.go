package cpepropose

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// needs_review reasons (cpe_mapping_proposals.state_reason). Each names the
// first gate that stopped an automatic publish.
const (
	ReasonNVDUnavailable       = "nvd_unavailable"
	ReasonNoCandidates         = "no_candidates"
	ReasonModelUnavailable     = "model_unavailable"
	ReasonModelInvalidResponse = "model_invalid_response"
	ReasonModelChoseNone       = "model_chose_none"
	ReasonModelNotConfident    = "model_not_confident"
	ReasonCandidateDeprecated  = "candidate_deprecated"
	ReasonAutoPublishDisabled  = "auto_publish_disabled"
	ReasonNoSignerEvidence     = "no_signer_evidence"
	ReasonSignerUntrusted      = "signer_untrusted"
	ReasonSignerInconsistent   = "signer_inconsistent"
	ReasonSignerNotAliased     = "signer_not_aliased"
	ReasonSignerVendorMismatch = "signer_vendor_mismatch"
	ReasonMatchNameTooBroad    = "match_name_too_broad"
	// ReasonSingleTenant: fewer than MinOutboundTenants distinct tenants
	// report the product, so it may be one customer's own or in-house
	// software (a signature, even an aliased vendor's, does not change
	// that). Nothing about it leaves the platform: no NVD search, no model
	// call, never named in the Linear digest. Re-read from local data daily,
	// in case a second tenant starts reporting it.
	ReasonSingleTenant = "single_tenant"
	// ReasonProductNameMismatch: the chosen CPE product does not name the
	// installed product (ProductMatches), whatever the model and the signer
	// say.
	ReasonProductNameMismatch = "product_name_mismatch"
	// ReasonCorroborationLost: an automatic mapping's periodic re-check
	// found current evidence that no longer passes the gate; the mapping was
	// removed and the proposal returned to staff. The failing check is in
	// evidence.recheck_reason.
	ReasonCorroborationLost = "corroboration_lost"
	// ReasonMappingDeleted: an automatic mapping was deleted by another path
	// (not the admin API); the proposal returned to staff.
	ReasonMappingDeleted = "mapping_deleted"
	// ReasonCandidateHasNoCVEs: the chosen candidate has no CVE in the local
	// feed. Publishing it would show the product as "assessed, no known
	// CVEs" on the strength of a CPE nothing is filed under, which is as
	// likely a thin or wrong sibling CPE as a clean product.
	ReasonCandidateHasNoCVEs = "candidate_has_no_cves"
	// ReasonModelZDRUnconfirmed (proposer status only): a model provider key
	// is configured (any of ANTHROPIC_API_KEY, or CPE_MODEL_API_KEY with
	// nvidia/openai) but CPE_MODEL_ZDR_CONFIRMED is not true, so the model
	// is never called; proposals go to staff as model_unavailable.
	ReasonModelZDRUnconfirmed = "model_zdr_unconfirmed"
	// ReasonNotSeen30Days (state expired): no active device has reported
	// the product for 30 days.
	ReasonNotSeen30Days = "not_seen_30_days"
	// ReasonAmbiguousCandidates: another current candidate of the same
	// vendor also names the product (ProductMatches) and has more CVEs in the
	// local feed, so which CPE NVD files this product under is a judgement
	// for staff.
	ReasonAmbiguousCandidates = "ambiguous_candidates"
	ReasonRevoked             = "revoked"
	ReasonRejectedByStaff     = "rejected_by_staff"
	ReasonMappedByOtherPath   = "mapped_by_other_path"
)

// Installation is one current installation's signing evidence, from its
// latest software observation.
type Installation struct {
	Platform       string
	SigningStatus  string // macOS: signed | adhoc | unsigned | error | untrusted | invalid | "" (not reported)
	TeamID         string // macOS
	SignatureState string // Windows: valid | invalid | unsigned | unknown | ""
	RootKind       string // Windows: microsoft | public | enterprise | ""
	SubjectDN      string // Windows leaf Subject DN (only beside valid); only its O= is ever used
	// Authority is the macOS signer's certificate kind: the observed signer
	// up to its first colon ("Developer ID Application", "Apple Mac OS
	// Application Signing", "Apple Development", ...). The rest of the
	// signer string is never read.
	Authority string
	// Tenant is the reporting tenant's id, for per-tenant counts in memory
	// only; never serialised, never sent anywhere.
	Tenant string
}

// Alias kinds (cpe_vendor_aliases.alias_kind).
const (
	aliasKindTeamID     = "macos_team_id"
	aliasKindSubjectOrg = "windows_subject_org"
)

// publicMacAuthorities are the macOS signing certificate kinds Apple issues
// only for public distribution, whose Team ID names the publishing
// organisation: Developer ID (notarised distribution outside the store) and
// the App Store's own re-signing. "Apple Development" / "Mac Developer"
// (development builds, the certificate names a person), "Software Signing"
// (Apple's platform binaries, no Team ID) and anything unrecognised are not.
var publicMacAuthorities = map[string]bool{
	"Developer ID Application":            true,
	"Apple Mac OS Application Signing":    true,
	"Apple iPhone OS Application Signing": true,
}

// publicSigner returns the installation's public-distribution signer: a
// macOS Team ID (status signed or not reported, Team ID of Apple's shape,
// public-distribution authority) or a Windows Subject O= (Authenticode
// valid, Microsoft or public root). ok is false for anything else: unsigned,
// ad hoc, development-signed, enterprise-root-signed, invalid or not
// reported. The value is the only signer data that may leave the platform.
func publicSigner(platform string, in Installation) (kind, value string, ok bool) {
	switch platform {
	case "macos":
		switch strings.ToLower(in.SigningStatus) {
		case "", "signed":
		default:
			return "", "", false
		}
		team := strings.ToUpper(strings.TrimSpace(in.TeamID))
		if !teamIDShape.MatchString(team) || !publicMacAuthorities[strings.TrimSpace(in.Authority)] {
			return "", "", false
		}
		return aliasKindTeamID, team, true
	case "windows":
		if !strings.EqualFold(in.SignatureState, "valid") {
			return "", "", false
		}
		switch strings.ToLower(in.RootKind) {
		case "microsoft", "public":
		default:
			return "", "", false
		}
		org := strings.Join(strings.Fields(SubjectOrganization(in.SubjectDN)), " ")
		if org == "" {
			return "", "", false
		}
		return aliasKindSubjectOrg, org, true
	}
	return "", "", false
}

// Alias is one cpe_vendor_aliases row.
type Alias struct {
	Kind, Value, Vendor string
}

// Corroboration is the deterministic signer check's result.
type Corroboration struct {
	OK      bool     `json:"ok"`
	Reason  string   `json:"reason,omitempty"`
	Signer  string   `json:"signer,omitempty"`  // the one Team ID or Subject O the installations agree on; only kept when aliased
	Vendors []string `json:"vendors,omitempty"` // the CPE vendors that signer is aliased to
	// Installations is how many current installations the check read.
	Installations int `json:"installations"`
}

var teamIDShape = regexp.MustCompile(`^[A-Z0-9]{10}$`)

// Corroborate decides, without the model, whether the product's signing
// evidence independently names vendor. Every current installation must
// carry usable evidence and agree on one signer, and that signer must be
// aliased to vendor in the curated table:
//
//   - macOS: a Team ID of Apple's shape, on a public-distribution
//     certificate (Developer ID or the App Store; publicMacAuthorities).
//     An installation whose collector
//     explicitly reported anything but "signed" (adhoc, unsigned, error,
//     untrusted, invalid) never corroborates, even with a Team ID beside it
//     (PAT-2117: a forged or tampered signature can carry any Team ID).
//     An installation from an agent that reports no signing status is judged
//     on its Team ID alone, the rule new-software urgency already applies.
//   - Windows: Authenticode valid, chained to a microsoft or public root
//     (never enterprise, whose trust the platform cannot check), with the
//     leaf Subject's O= (organisation) as the signer.
//
// No installations at all is ReasonNoSignerEvidence: a name-only product is
// never corroborated.
func Corroborate(platform string, installs []Installation, aliases []Alias, vendor string) Corroboration {
	c := Corroboration{Installations: len(installs)}
	if len(installs) == 0 {
		c.Reason = ReasonNoSignerEvidence
		return c
	}
	signers := map[string]bool{}
	for _, in := range installs {
		var s string
		switch platform {
		case "macos":
			switch strings.ToLower(in.SigningStatus) {
			case "", "signed":
			default:
				c.Reason = ReasonSignerUntrusted
				return c
			}
			s = strings.ToUpper(strings.TrimSpace(in.TeamID))
			if !teamIDShape.MatchString(s) {
				c.Reason = ReasonNoSignerEvidence
				return c
			}
			// A development certificate, Apple's platform signing or an
			// unknown authority never corroborates, even with a Team ID.
			if !publicMacAuthorities[strings.TrimSpace(in.Authority)] {
				c.Reason = ReasonSignerUntrusted
				return c
			}
		case "windows":
			switch strings.ToLower(in.SignatureState) {
			case "valid":
			case "":
				c.Reason = ReasonNoSignerEvidence
				return c
			default:
				c.Reason = ReasonSignerUntrusted
				return c
			}
			switch strings.ToLower(in.RootKind) {
			case "microsoft", "public":
			default:
				c.Reason = ReasonSignerUntrusted
				return c
			}
			s = normalizeOrg(SubjectOrganization(in.SubjectDN))
			if s == "" {
				c.Reason = ReasonNoSignerEvidence
				return c
			}
		default:
			c.Reason = ReasonNoSignerEvidence
			return c
		}
		signers[s] = true
	}
	if len(signers) != 1 {
		c.Reason = ReasonSignerInconsistent
		return c
	}
	for s := range signers {
		c.Signer = s
	}
	kind := aliasKindTeamID
	if platform == "windows" {
		kind = aliasKindSubjectOrg
	}
	vendorSet := map[string]bool{}
	for _, a := range aliases {
		if a.Kind != kind {
			continue
		}
		v := a.Value
		if kind == aliasKindSubjectOrg {
			v = normalizeOrg(v)
		}
		if v == c.Signer {
			vendorSet[a.Vendor] = true
		}
	}
	for v := range vendorSet {
		c.Vendors = append(c.Vendors, v)
	}
	sort.Strings(c.Vendors)
	switch {
	case len(vendorSet) == 0:
		c.Reason = ReasonSignerNotAliased
		// An unaliased signer may be one customer's own Developer ID team
		// or its legal name (a Windows O=): it is never kept in the
		// Corroboration, which is stored in the global evidence column and
		// shown on the admin API (re-review P2-2).
		c.Signer = ""
	case !vendorSet[strings.ToLower(vendor)]:
		c.Reason = ReasonSignerVendorMismatch
	default:
		c.OK = true
	}
	return c
}

// normalizeOrg compares organisation names case-insensitively with
// whitespace collapsed; punctuation and legal suffixes are kept, so
// "Microsoft Corporation" and "Microsoft Corp" stay different (fails towards
// review, never towards publish).
func normalizeOrg(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// SubjectOrganization returns the O= value of an X.500 Subject DN as Windows
// renders it ("CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond,
// S=Washington, C=US"), honouring double quotes and backslash escapes. ""
// when there is no O= or more than one.
func SubjectOrganization(dn string) string {
	var parts []string
	var cur strings.Builder
	inQuote, escaped := false, false
	for _, r := range dn {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '"':
			inQuote = !inQuote
		case (r == ',' || r == ';') && !inQuote:
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	parts = append(parts, cur.String())
	org, count := "", 0
	for _, p := range parts {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "O") {
			continue
		}
		org = strings.TrimSpace(v)
		count++
	}
	if count != 1 {
		return ""
	}
	return org
}

// GateInput is everything the auto-publish decision reads. Every field is
// computed deterministically outside the model except Choice.
type GateInput struct {
	AutoPublishEnabled bool
	// NormalizedName is the proposal's normalised product name, which the
	// chosen candidate's CPE product must name (ProductMatches).
	NormalizedName string
	Candidates     []Candidate
	Choice         ModelChoice
	ModelErr       error // from the Chooser (nil when it answered)
	Corroboration  Corroboration
	// OtherCoveredNames are installed product names, other than this
	// proposal's own, that the display name would cover as an automatic
	// mapping's match_name (cvematch.ExactNameMatches: same word tokens,
	// e.g. "Zoom." beside "Zoom"). An automatic mapping never covers a
	// longer name ("Zoom Helper"), so a one-word match_name cannot silently
	// cover a product installed later.
	OtherCoveredNames []string
}

// Decision is the gate's outcome.
type Decision struct {
	State   string // StateAutoPublished or StateNeedsReview
	Reason  string // set for needs_review
	Vendor  string // the chosen candidate, when the model chose one
	Product string
}

// Decide is the auto-publish gate. It publishes only when every condition
// holds; the first failing condition is the needs_review reason. The model's
// answer is one input among several and can never publish on its own.
func Decide(in GateInput) Decision {
	review := func(reason string) Decision {
		d := Decision{State: StateNeedsReview, Reason: reason}
		if cand, ok := candidateByKey(in.Candidates, in.Choice.Choice); ok {
			d.Vendor, d.Product = cand.Vendor, cand.Product
		}
		return d
	}
	if len(in.Candidates) == 0 {
		return Decision{State: StateNeedsReview, Reason: ReasonNoCandidates}
	}
	if in.ModelErr != nil {
		if errors.Is(in.ModelErr, ErrInvalidModelResponse) {
			return Decision{State: StateNeedsReview, Reason: ReasonModelInvalidResponse}
		}
		return Decision{State: StateNeedsReview, Reason: ReasonModelUnavailable}
	}
	if in.Choice.Choice == "" || in.Choice.Choice == ChoiceNone {
		return Decision{State: StateNeedsReview, Reason: ReasonModelChoseNone}
	}
	cand, ok := candidateByKey(in.Candidates, in.Choice.Choice)
	if !ok {
		// Unreachable through AnthropicChooser, which only returns supplied
		// keys; checked again because a Chooser is an interface.
		return Decision{State: StateNeedsReview, Reason: ReasonModelInvalidResponse}
	}
	if in.Choice.Confidence != ConfidenceHigh {
		return review(ReasonModelNotConfident)
	}
	if cand.Deprecated {
		return review(ReasonCandidateDeprecated)
	}
	// Product-level corroboration, outside the model: the signer check below
	// only pins the vendor, so a model steered to the wrong product of the
	// right vendor is stopped here.
	if !ProductMatches(in.NormalizedName, cand.Vendor, cand.Product) {
		return review(ReasonProductNameMismatch)
	}
	for _, other := range in.Candidates {
		if other.Key() == cand.Key() || other.Deprecated || other.Vendor != cand.Vendor {
			continue
		}
		if other.CVECount > cand.CVECount && ProductMatches(in.NormalizedName, other.Vendor, other.Product) {
			return review(ReasonAmbiguousCandidates)
		}
	}
	if cand.CVECount == 0 {
		return review(ReasonCandidateHasNoCVEs)
	}
	if !in.Corroboration.OK {
		reason := in.Corroboration.Reason
		if reason == "" {
			reason = ReasonNoSignerEvidence
		}
		return review(reason)
	}
	if len(in.OtherCoveredNames) > 0 {
		return review(ReasonMatchNameTooBroad)
	}
	if !in.AutoPublishEnabled {
		return review(ReasonAutoPublishDisabled)
	}
	return Decision{State: StateAutoPublished, Vendor: cand.Vendor, Product: cand.Product}
}

func candidateByKey(cands []Candidate, key string) (Candidate, bool) {
	for _, c := range cands {
		if c.Key() == key {
			return c, true
		}
	}
	return Candidate{}, false
}

// loadAliases reads the curated vendor alias table.
func loadAliases(ctx context.Context, q DB) ([]Alias, error) {
	rows, err := q.Query(ctx, `SELECT alias_kind, alias_value, cpe_vendor FROM cpe_vendor_aliases ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("load vendor aliases: %w", err)
	}
	defer rows.Close()
	var out []Alias
	for rows.Next() {
		var a Alias
		if err := rows.Scan(&a.Kind, &a.Value, &a.Vendor); err != nil {
			return nil, fmt.Errorf("scan vendor alias: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
