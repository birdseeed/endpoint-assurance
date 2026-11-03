// Package evidencecatalogue provides reviewed installation-confidence evidence.
//
// The catalogue is evidence and governance data only. It has no package,
// installer, deployment, remediation, or endpoint-actuation authority.
package evidencecatalogue

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const SchemaVersion = 1

var (
	//go:embed catalogue.v1.json
	embeddedCatalogue []byte

	idPattern            = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)
	teamIDPattern        = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	codeDirectoryPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256Pattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	bundleIDPattern      = regexp.MustCompile(`^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*$`)
	// wingetIDPattern intentionally mirrors Microsoft's authoritative
	// PackageIdentifier regex, including its negated class (which permits
	// Unicode): https://github.com/microsoft/winget-cli/blob/master/schemas/JSON/manifests/latest/manifest.singleton.latest.json
	// NUL is rejected separately below because the upstream class starts at
	// U+0001 and NUL is not useful catalogue identity data.
	wingetIDPattern       = regexp.MustCompile(`^[^\.\s\\/:*?"<>|\x01-\x1f]{1,32}(\.[^\.\s\\/:*?"<>|\x01-\x1f]{1,32}){1,7}$`)
	msixNamePattern       = regexp.MustCompile(`^[A-Za-z0-9.-]{3,50}$`)
	msixPublisherPattern  = regexp.MustCompile(`(?i)^[a-hj-km-np-tv-z0-9]{13}$`)
	msiUpgradeCodePattern = regexp.MustCompile(`^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$`)
	dnAttributePattern    = regexp.MustCompile(`^(CN|L|O|OU|E|C|S|STREET|T|G|I|SN|DC|SERIALNUMBER|Description|PostalCode|POBox|Phone|X21Address|dnQualifier|OID\.(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))+)$`)
)

type Catalogue struct {
	SchemaVersion    int     `json:"schema_version"`
	CatalogueVersion string  `json:"catalogue_version"`
	PublishedAt      string  `json:"published_at"`
	Entries          []Entry `json:"entries"`
}

type Entry struct {
	ID                string             `json:"id"`
	Rationale         string             `json:"rationale"`
	CanonicalIdentity CanonicalIdentity  `json:"canonical_identity"`
	Platform          string             `json:"platform"`
	StableIdentifiers []StableIdentifier `json:"stable_identifiers"`
	PermittedPaths    []string           `json:"permitted_paths"`
	ExpectedSigner    Signer             `json:"expected_signer"`
	Sources           []SourceProvenance `json:"sources"`
	Review            ReviewProvenance   `json:"review"`
}

type CanonicalIdentity struct {
	ProductKey  string `json:"product_key"`
	ProductName string `json:"product_name"`
	VendorName  string `json:"vendor_name"`
}

type StableIdentifier struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type Signer struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type SourceProvenance struct {
	Kind       string `json:"kind"`
	URL        string `json:"url"`
	Supports   string `json:"supports"`
	ReviewedAt string `json:"reviewed_at"`
}

type ReviewProvenance struct {
	Reference         string `json:"reference"`
	Method            string `json:"method"`
	ReviewedAt        string `json:"reviewed_at"`
	ArtifactVersion   string `json:"artifact_version"`
	CodeDirectoryHash string `json:"code_directory_hash,omitempty"`
	ArtifactSHA256    string `json:"artifact_sha256,omitempty"`
}

type Observation struct {
	Platform        string
	IdentifierKind  string
	IdentifierValue string
	Path            string
	SignerKind      string
	SignerValue     string
}

type MatchStatus string

const (
	MatchExpected       MatchStatus = "expected"
	MatchUnexpectedPath MatchStatus = "unexpected_path"
	MatchSignerMismatch MatchStatus = "signer_mismatch"
	MatchUnrecognised   MatchStatus = "unrecognised"
)

type MatchResult struct {
	Status  MatchStatus
	EntryID string
}

type Matcher struct {
	byIdentifier map[string]matchCandidate
}

type matchCandidate struct {
	entryID        string
	platform       string
	expectedSigner Signer
	permittedPaths []string
}

// LoadEmbedded loads and validates the reviewed catalogue shipped with this
// package. Loading it does not activate any endpoint behaviour.
func LoadEmbedded() (*Catalogue, error) {
	return Parse(embeddedCatalogue)
}

// Parse rejects unknown JSON fields and then applies the semantic validator.
func Parse(data []byte) (*Catalogue, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var catalogue Catalogue
	if err := decoder.Decode(&catalogue); err != nil {
		return nil, fmt.Errorf("decode evidence catalogue: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode evidence catalogue: trailing JSON value")
	}
	if err := Validate(&catalogue); err != nil {
		return nil, err
	}
	return &catalogue, nil
}

func Validate(catalogue *Catalogue) error {
	if catalogue == nil {
		return errors.New("evidence catalogue is nil")
	}
	if catalogue.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %d", SchemaVersion)
	}
	if !idPattern.MatchString(catalogue.CatalogueVersion) {
		return errors.New("catalogue_version must be a lowercase version token")
	}
	if _, err := time.Parse(time.RFC3339, catalogue.PublishedAt); err != nil {
		return errors.New("published_at must be RFC3339")
	}
	if len(catalogue.Entries) == 0 {
		return errors.New("entries must not be empty")
	}

	ids := make(map[string]struct{}, len(catalogue.Entries))
	identities := make(map[string]string, len(catalogue.Entries))
	for i := range catalogue.Entries {
		entry := &catalogue.Entries[i]
		prefix := fmt.Sprintf("entries[%d]", i)
		if err := validateEntry(entry, prefix); err != nil {
			return err
		}
		if _, exists := ids[entry.ID]; exists {
			return fmt.Errorf("%s.id duplicates %q", prefix, entry.ID)
		}
		ids[entry.ID] = struct{}{}
		for _, identifier := range entry.StableIdentifiers {
			key := identifierKey(entry.Platform, identifier.Kind, identifier.Value)
			if prior, exists := identities[key]; exists {
				return fmt.Errorf("%s stable identity duplicates entry %q", prefix, prior)
			}
			identities[key] = entry.ID
		}
	}
	return nil
}

func validateEntry(entry *Entry, prefix string) error {
	if !idPattern.MatchString(entry.ID) {
		return fmt.Errorf("%s.id must be a lowercase canonical token", prefix)
	}
	if strings.TrimSpace(entry.Rationale) == "" {
		return fmt.Errorf("%s.rationale is required", prefix)
	}
	if !idPattern.MatchString(entry.CanonicalIdentity.ProductKey) ||
		strings.TrimSpace(entry.CanonicalIdentity.ProductName) == "" ||
		strings.TrimSpace(entry.CanonicalIdentity.VendorName) == "" {
		return fmt.Errorf("%s canonical_identity is incomplete", prefix)
	}
	if entry.Platform != "macos" && entry.Platform != "windows" {
		return fmt.Errorf("%s.platform must be macos or windows", prefix)
	}
	if len(entry.StableIdentifiers) == 0 {
		return fmt.Errorf("%s.stable_identifiers is required; display name matching is prohibited", prefix)
	}

	identifierKinds := make(map[string]struct{}, len(entry.StableIdentifiers))
	for j, identifier := range entry.StableIdentifiers {
		if err := validateIdentifier(entry.Platform, identifier); err != nil {
			return fmt.Errorf("%s.stable_identifiers[%d]: %w", prefix, j, err)
		}
		if _, exists := identifierKinds[identifier.Kind]; exists {
			return fmt.Errorf("%s.stable_identifiers[%d].kind duplicates %q", prefix, j, identifier.Kind)
		}
		identifierKinds[identifier.Kind] = struct{}{}
	}
	if entry.Platform == "macos" {
		if _, ok := identifierKinds["bundle_id"]; !ok {
			return fmt.Errorf("%s requires a bundle_id", prefix)
		}
		if entry.ExpectedSigner.Kind != "apple_team_id" || !teamIDPattern.MatchString(entry.ExpectedSigner.Value) {
			return fmt.Errorf("%s expected_signer must contain a valid apple_team_id", prefix)
		}
	} else {
		if entry.ExpectedSigner.Kind != "authenticode_subject" || !validAuthenticodeSubject(entry.ExpectedSigner.Value) {
			return fmt.Errorf("%s expected_signer must contain an authenticode_subject", prefix)
		}
	}

	if len(entry.PermittedPaths) == 0 {
		return fmt.Errorf("%s.permitted_paths is required", prefix)
	}
	paths := make(map[string]struct{}, len(entry.PermittedPaths))
	for j, path := range entry.PermittedPaths {
		if !validPath(entry.Platform, path) {
			return fmt.Errorf("%s.permitted_paths[%d] must be an exact absolute path without wildcards", prefix, j)
		}
		normalized := normalizePath(entry.Platform, path)
		if _, exists := paths[normalized]; exists {
			return fmt.Errorf("%s.permitted_paths[%d] is duplicated", prefix, j)
		}
		paths[normalized] = struct{}{}
	}

	if len(entry.Sources) == 0 {
		return fmt.Errorf("%s.sources is required", prefix)
	}
	for j, source := range entry.Sources {
		if source.Kind != "primary_vendor" || strings.TrimSpace(source.Supports) == "" {
			return fmt.Errorf("%s.sources[%d] must record primary_vendor support provenance", prefix, j)
		}
		parsed, err := url.Parse(source.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return fmt.Errorf("%s.sources[%d].url must be an absolute HTTPS vendor URL", prefix, j)
		}
		if _, err := time.Parse(time.RFC3339, source.ReviewedAt); err != nil {
			return fmt.Errorf("%s.sources[%d].reviewed_at must be RFC3339", prefix, j)
		}
	}
	if entry.Review.Reference == "" || entry.Review.ArtifactVersion == "" {
		return fmt.Errorf("%s.review is incomplete", prefix)
	}
	if entry.Platform == "macos" && (entry.Review.Method != "codesign_bundle_inspection" ||
		!codeDirectoryPattern.MatchString(entry.Review.CodeDirectoryHash) || entry.Review.ArtifactSHA256 != "") {
		return fmt.Errorf("%s.review must contain macOS code-signing evidence", prefix)
	}
	if entry.Platform == "windows" && (entry.Review.Method != "authenticode_artifact_inspection" ||
		!sha256Pattern.MatchString(entry.Review.ArtifactSHA256) || entry.Review.CodeDirectoryHash != "") {
		return fmt.Errorf("%s.review must contain Windows Authenticode artifact evidence", prefix)
	}
	if _, err := time.Parse(time.RFC3339, entry.Review.ReviewedAt); err != nil {
		return fmt.Errorf("%s.review.reviewed_at must be RFC3339", prefix)
	}
	return nil
}

func validateIdentifier(platform string, identifier StableIdentifier) error {
	if strings.TrimSpace(identifier.Value) == "" || identifier.Value != strings.TrimSpace(identifier.Value) {
		return errors.New("identifier value is required and must not have surrounding whitespace")
	}
	switch platform {
	case "macos":
		if identifier.Kind != "bundle_id" {
			return errors.New("macos supports only bundle_id stable identifiers")
		}
		if !bundleIDPattern.MatchString(identifier.Value) {
			return errors.New("bundle_id must contain only alphanumeric characters, hyphens, and period-separated components")
		}
	case "windows":
		switch identifier.Kind {
		case "winget_id":
			if strings.ContainsRune(identifier.Value, '\x00') || utf8.RuneCountInString(identifier.Value) > 128 || !wingetIDPattern.MatchString(identifier.Value) {
				return errors.New("winget_id must follow the Microsoft PackageIdentifier format")
			}
		case "msix_package_family_name":
			if !validMSIXPackageFamilyName(identifier.Value) {
				return errors.New("msix_package_family_name must contain a valid package Name and 13-character PublisherId")
			}
		case "msi_upgrade_code":
			if !msiUpgradeCodePattern.MatchString(identifier.Value) {
				return errors.New("msi_upgrade_code must be an uppercase braced GUID")
			}
		default:
			return errors.New("unsupported Windows stable identifier kind")
		}
	}
	return nil
}

func validPath(platform, path string) bool {
	if path == "" || path != strings.TrimSpace(path) || strings.ContainsAny(path, "*?[]") {
		return false
	}
	if platform == "macos" {
		return strings.HasPrefix(path, "/Applications/") && filepath.IsAbs(path) && filepath.Clean(path) == path
	}
	if len(path) < 4 || path[1] != ':' || path[2] != '\\' {
		return false
	}
	if !((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) || strings.ContainsAny(path, "/\x00") {
		return false
	}
	for _, segment := range strings.Split(path[3:], `\`) {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validMSIXPackageFamilyName(value string) bool {
	separator := strings.LastIndexByte(value, '_')
	if separator < 0 || strings.IndexByte(value, '_') != separator {
		return false
	}
	name, publisherID := value[:separator], value[separator+1:]
	if !msixNamePattern.MatchString(name) || !msixPublisherPattern.MatchString(publisherID) {
		return false
	}
	lowerName := strings.ToLower(name)
	reserved := []string{"con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"}
	if strings.HasSuffix(name, ".") || strings.HasPrefix(lowerName, "xn--") || strings.Contains(lowerName, ".xn--") {
		return false
	}
	for _, word := range reserved {
		if lowerName == word || strings.HasPrefix(lowerName, word+".") {
			return false
		}
	}
	return true
}

func validAuthenticodeSubject(value string) bool {
	if value != strings.TrimSpace(value) || len(value) < 3 || len(value) > 8192 || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	if strings.Contains(value, "=") {
		return validDistinguishedName(value)
	}

	letters, alphanumeric := 0, 0
	for _, current := range value {
		switch {
		case unicode.IsLetter(current):
			letters++
			alphanumeric++
		case unicode.IsDigit(current):
			alphanumeric++
		case current == ' ' || strings.ContainsRune(".,&'()+-_", current):
		default:
			return false
		}
	}
	return letters > 0 && alphanumeric >= 2
}

func validDistinguishedName(value string) bool {
	parts, ok := splitDistinguishedName(value)
	if !ok {
		return false
	}
	hasCommonName := false
	for _, part := range parts {
		attribute, rawValue, found := strings.Cut(part, "=")
		if !found || !dnAttributePattern.MatchString(attribute) || !validDistinguishedNameValue(rawValue) {
			return false
		}
		hasCommonName = hasCommonName || attribute == "CN"
	}
	return hasCommonName
}

func splitDistinguishedName(value string) ([]string, bool) {
	var parts []string
	start := 0
	inQuotes := false
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '"':
			if inQuotes && index+1 < len(value) && value[index+1] == '"' {
				index++
				continue
			}
			inQuotes = !inQuotes
		case ',':
			if inQuotes {
				continue
			}
			if index+1 >= len(value) || value[index+1] != ' ' {
				return nil, false
			}
			parts = append(parts, value[start:index])
			start = index + 2
			index++
		}
	}
	if inQuotes {
		return nil, false
	}
	parts = append(parts, value[start:])
	return parts, len(parts) > 0
}

func validDistinguishedNameValue(value string) bool {
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	if value[0] == '"' {
		if len(value) < 3 || value[len(value)-1] != '"' {
			return false
		}
		inner := value[1 : len(value)-1]
		for index := 0; index < len(inner); index++ {
			if inner[index] == '"' {
				if index+1 >= len(inner) || inner[index+1] != '"' {
					return false
				}
				index++
			}
		}
		return inner != ""
	}
	return value == strings.TrimSpace(value) && !strings.ContainsAny(value, `,+="<>#;`)
}

func identifierKey(platform, kind, value string) string {
	return strings.Join([]string{platform, kind, strings.ToLower(strings.TrimSpace(value))}, "\x1f")
}

func normalizePath(platform, path string) string {
	if platform == "windows" {
		return strings.ToLower(path)
	}
	return path
}

func NewMatcher(catalogue *Catalogue) (*Matcher, error) {
	if err := Validate(catalogue); err != nil {
		return nil, err
	}
	matcher := &Matcher{byIdentifier: make(map[string]matchCandidate)}
	for i := range catalogue.Entries {
		entry := &catalogue.Entries[i]
		paths := make([]string, 0, len(entry.PermittedPaths))
		for _, path := range entry.PermittedPaths {
			paths = append(paths, normalizePath(entry.Platform, path))
		}
		sort.Strings(paths)
		candidate := matchCandidate{
			entryID:        entry.ID,
			platform:       entry.Platform,
			expectedSigner: entry.ExpectedSigner,
			permittedPaths: paths,
		}
		for _, identifier := range entry.StableIdentifiers {
			matcher.byIdentifier[identifierKey(entry.Platform, identifier.Kind, identifier.Value)] = candidate
		}
	}
	return matcher, nil
}

// Match requires a stable platform identifier before considering signer and
// path evidence. Display names are neither accepted nor consulted.
func (matcher *Matcher) Match(observation Observation) MatchResult {
	candidate, ok := matcher.byIdentifier[identifierKey(observation.Platform, observation.IdentifierKind, observation.IdentifierValue)]
	if !ok {
		return MatchResult{Status: MatchUnrecognised}
	}
	if observation.SignerKind != candidate.expectedSigner.Kind || !signerMatches(candidate, observation.SignerValue) {
		return MatchResult{Status: MatchSignerMismatch, EntryID: candidate.entryID}
	}
	observedPath := normalizePath(candidate.platform, observation.Path)
	index := sort.SearchStrings(candidate.permittedPaths, observedPath)
	if index == len(candidate.permittedPaths) || candidate.permittedPaths[index] != observedPath {
		return MatchResult{Status: MatchUnexpectedPath, EntryID: candidate.entryID}
	}
	return MatchResult{Status: MatchExpected, EntryID: candidate.entryID}
}

func signerMatches(candidate matchCandidate, observed string) bool {
	observed = strings.TrimSpace(observed)
	if candidate.platform == "windows" {
		return strings.EqualFold(observed, candidate.expectedSigner.Value)
	}
	return observed == candidate.expectedSigner.Value
}
