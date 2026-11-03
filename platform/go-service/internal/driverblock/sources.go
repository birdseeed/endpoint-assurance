// Package driverblock ingests the published vulnerable driver lists and
// matches the kernel driver hashes Windows agents report against them
// (PAT-2263). It answers "is a known vulnerable driver present, and is
// Windows blocking it" for every vendor, with no connector.
//
// Two sources, refreshed nightly by patched-cve-sync:
//
//   - Microsoft's recommended driver block rules, the vulnerable driver
//     blocklist Microsoft documents at
//     https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules
//     and publishes as a zip at https://aka.ms/VulnerableDriverBlockList
//     (VulnerableDriverBlockList/DriverPolicy_Enforced.xml, a SiPolicy). Its
//     FileRules Deny Hash attributes are Authenticode (PE image) hashes:
//     "Hash Sha1" and "Hash Sha256" rules are stored; "Hash Page" rules are
//     WDAC page hashes, which the agent does not compute, and are skipped.
//     Signer-based rules (Signer, FileAttrib by name and version) are not
//     evaluated: this is hash matching only, so no match is never "not on
//     Microsoft's list".
//   - loldrivers.io, https://www.loldrivers.io/api/drivers.json: each driver's
//     KnownVulnerableSamples carry flat SHA256/SHA1 and Authentihash
//     SHA256/SHA1. Category "vulnerable driver" is stored as 'vulnerable' and
//     "malicious" as 'malicious', kept apart; any other category is skipped.
//
// Matching is by hash only, never by file name: a renamed file with a listed
// hash matches, a same-named file with another hash does not. SHA-1 is stored
// unless the same record carries a SHA-256 of the same kind (flat or
// Authenticode): the loldrivers.io sample itself, or for Microsoft the
// rule's own ID-paired _SHA256 rule. Every other distinct hash is kept. The
// agent always sends both digests of a file together, so dropping a paired
// SHA-1 never loses a comparison, and a SHA-1 collision cannot manufacture a
// finding where a SHA-256 was available.
//
// Fail closed: a failed or implausible refresh records the failure and its
// time and leaves the last good list in place; it never empties the list.
package driverblock

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	SourceMicrosoft  = "microsoft_driver_blocklist"
	SourceLOLDrivers = "loldrivers"

	// MicrosoftURL is the documented download for the recommended driver
	// block rules (it redirects to download.microsoft.com).
	MicrosoftURL = "https://aka.ms/VulnerableDriverBlockList"
	// LOLDriversURL is the published loldrivers.io API document.
	LOLDriversURL = "https://www.loldrivers.io/api/drivers.json"

	CategoryVulnerable = "vulnerable"
	CategoryMalicious  = "malicious"

	HashSHA256             = "sha256"
	HashSHA1               = "sha1"
	HashAuthenticodeSHA256 = "authenticode_sha256"
	HashAuthenticodeSHA1   = "authenticode_sha1"

	// Source document bounds. The live zip is about 330 KB with a 545 KB
	// policy inside; the live loldrivers.io document is about 33 MB.
	maxMicrosoftDocumentBytes = 16 << 20
	maxMicrosoftPolicyBytes   = 32 << 20
	maxLOLDriversBytes        = 128 << 20

	maxEntryIDRunes   = 128
	maxEntryNameRunes = 256
	maxRevisionRunes  = 128
)

// Sources lists every source in a fixed order.
var Sources = []string{SourceMicrosoft, SourceLOLDrivers}

// AuthorityURL is the canonical URL kept as provenance for a source.
// Retrieval may use a controlled mirror, but it cannot change this.
func AuthorityURL(source string) (string, error) {
	switch source {
	case SourceMicrosoft:
		return MicrosoftURL, nil
	case SourceLOLDrivers:
		return LOLDriversURL, nil
	default:
		return "", fmt.Errorf("unknown driver blocklist source %q", source)
	}
}

// Entry is one listed hash.
type Entry struct {
	HashKind  string
	Hash      string
	EntryID   string
	EntryName string
	Category  string
}

// Snapshot is one complete, successfully parsed source retrieval.
type Snapshot struct {
	Source         string
	SourceURL      string
	FetchedAt      time.Time
	SourceRevision string
	Entries        []Entry
	// Skipped counts list rules or samples that carried nothing matchable
	// (page hashes, malformed or missing hashes, unknown categories).
	Skipped int
}

var (
	sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sha1Hex   = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// Parse parses a source document of the named source.
func Parse(source string, data []byte, fetchedAt time.Time) (Snapshot, error) {
	switch source {
	case SourceMicrosoft:
		return ParseMicrosoft(data, fetchedAt)
	case SourceLOLDrivers:
		return ParseLOLDrivers(data, fetchedAt)
	default:
		return Snapshot{}, fmt.Errorf("unknown driver blocklist source %q", source)
	}
}

// ---------------------------------------------------------------------------
// Microsoft recommended driver block rules
// ---------------------------------------------------------------------------

type siPolicy struct {
	XMLName   xml.Name `xml:"SiPolicy"`
	VersionEx string   `xml:"VersionEx"`
	FileRules struct {
		Deny []siRule `xml:"Deny"`
	} `xml:"FileRules"`
}

type siRule struct {
	ID           string `xml:"ID,attr"`
	FriendlyName string `xml:"FriendlyName,attr"`
	Hash         string `xml:"Hash,attr"`
}

const siPolicyNamespace = "urn:schemas-microsoft-com:sipolicy"

// ParseMicrosoft parses the VulnerableDriverBlockList zip (or, for a replay
// file, the DriverPolicy_Enforced.xml inside it). The list version is the
// policy's VersionEx.
func ParseMicrosoft(data []byte, fetchedAt time.Time) (Snapshot, error) {
	policy := data
	if bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		var err error
		if policy, err = policyFromZip(data); err != nil {
			return Snapshot{}, err
		}
	}
	policy = bytes.TrimPrefix(policy, []byte("\xef\xbb\xbf"))
	if len(policy) > maxMicrosoftPolicyBytes {
		return Snapshot{}, fmt.Errorf("parse Microsoft driver blocklist: policy exceeds %d bytes", maxMicrosoftPolicyBytes)
	}
	var doc siPolicy
	if err := xml.Unmarshal(policy, &doc); err != nil {
		return Snapshot{}, fmt.Errorf("parse Microsoft driver blocklist: %w", err)
	}
	if doc.XMLName.Space != siPolicyNamespace {
		return Snapshot{}, errors.New("parse Microsoft driver blocklist: not a SiPolicy document")
	}
	revision := strings.TrimSpace(doc.VersionEx)
	if revision == "" || utf8.RuneCountInString(revision) > maxRevisionRunes {
		return Snapshot{}, errors.New("parse Microsoft driver blocklist: VersionEx missing or unusable")
	}

	type candidate struct {
		kind, hash, id, stem string
	}
	var candidates []candidate
	hasSHA256 := map[string]bool{}
	skipped := 0
	for _, rule := range doc.FileRules.Deny {
		raw := strings.TrimSpace(rule.Hash)
		if raw == "" {
			continue // a FileName/version rule, not a hash rule
		}
		name := strings.TrimSpace(rule.FriendlyName)
		id := strings.TrimSpace(rule.ID)
		if strings.Contains(strings.ToLower(name), "hash page") || strings.HasSuffix(strings.ToUpper(id), "_PAGE") {
			skipped++ // WDAC page hash: not computed by the agent
			continue
		}
		hash := strings.ToLower(raw)
		var kind string
		switch {
		case sha256Hex.MatchString(hash):
			kind = HashAuthenticodeSHA256
		case sha1Hex.MatchString(hash):
			kind = HashAuthenticodeSHA1
		default:
			skipped++
			continue
		}
		if id == "" || utf8.RuneCountInString(id) > maxEntryIDRunes {
			skipped++
			continue
		}
		stem := microsoftStem(name)
		if kind == HashAuthenticodeSHA256 {
			hasSHA256[stem+"\x00"+strings.ToUpper(id)] = true
		}
		candidates = append(candidates, candidate{kind: kind, hash: hash, id: id, stem: stem})
	}

	var entries []Entry
	for _, c := range candidates {
		if c.kind == HashAuthenticodeSHA1 && hasSHA256[c.stem+"\x00"+sha256Partner(c.id)] {
			// This rule's own SHA-256 partner is listed (same FriendlyName
			// stem, ID ending _SHA256 for _SHA1): the agent always sends both
			// digests of a file together, so the SHA-256 compares wherever
			// the SHA-1 could. A SHA-1 without its own partner is kept, even
			// when another rule shares its stem.
			continue
		}
		entries = append(entries, Entry{
			HashKind: c.kind, Hash: c.hash, EntryID: c.id,
			EntryName: boundRunes(c.stem, maxEntryNameRunes), Category: CategoryVulnerable,
		})
	}
	if len(entries) == 0 {
		return Snapshot{}, errors.New("parse Microsoft driver blocklist: no hash rules")
	}
	return Snapshot{
		Source: SourceMicrosoft, SourceURL: MicrosoftURL, FetchedAt: fetchedAt.UTC(),
		SourceRevision: revision, Entries: dedupe(entries), Skipped: skipped,
	}, nil
}

// sha256Partner is the ID Microsoft gives a SHA-1 hash rule's SHA-256
// counterpart (ID_DENY_X_SHA1 -> ID_DENY_X_SHA256); "" when the ID has no
// SHA1 suffix, so such a rule is never treated as paired.
func sha256Partner(id string) string {
	upper := strings.ToUpper(id)
	if !strings.HasSuffix(upper, "_SHA1") {
		return ""
	}
	return strings.TrimSuffix(upper, "_SHA1") + "_SHA256"
}

// microsoftStem groups a rule's SHA-1 and SHA-256 hash rules: their
// FriendlyNames differ only by a " Hash Sha1" / " Hash Sha256" suffix.
func microsoftStem(name string) string {
	lower := strings.ToLower(name)
	for _, suffix := range []string{" hash sha256", " hash sha1"} {
		if strings.HasSuffix(lower, suffix) {
			return strings.TrimSpace(name[:len(name)-len(suffix)])
		}
	}
	return name
}

func policyFromZip(data []byte) ([]byte, error) {
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("parse Microsoft driver blocklist: open zip: %w", err)
	}
	var found *zip.File
	for _, f := range archive.File {
		if strings.EqualFold(path.Base(f.Name), "DriverPolicy_Enforced.xml") {
			if found != nil {
				return nil, errors.New("parse Microsoft driver blocklist: more than one DriverPolicy_Enforced.xml")
			}
			found = f
		}
	}
	if found == nil {
		return nil, errors.New("parse Microsoft driver blocklist: DriverPolicy_Enforced.xml not in the zip")
	}
	if found.UncompressedSize64 > maxMicrosoftPolicyBytes {
		return nil, fmt.Errorf("parse Microsoft driver blocklist: policy exceeds %d bytes", maxMicrosoftPolicyBytes)
	}
	rc, err := found.Open()
	if err != nil {
		return nil, fmt.Errorf("parse Microsoft driver blocklist: open policy: %w", err)
	}
	defer rc.Close()
	policy, err := io.ReadAll(io.LimitReader(rc, maxMicrosoftPolicyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("parse Microsoft driver blocklist: read policy: %w", err)
	}
	if len(policy) > maxMicrosoftPolicyBytes {
		return nil, fmt.Errorf("parse Microsoft driver blocklist: policy exceeds %d bytes", maxMicrosoftPolicyBytes)
	}
	return policy, nil
}

// ---------------------------------------------------------------------------
// loldrivers.io
// ---------------------------------------------------------------------------

type lolDriver struct {
	ID       string           `json:"Id"`
	Category string           `json:"Category"`
	Tags     []any            `json:"Tags"`
	Samples  []map[string]any `json:"KnownVulnerableSamples"`
}

// ParseLOLDrivers parses the loldrivers.io drivers.json document. The source
// publishes no version, so the list version is the SHA-256 of the document.
// Individual malformed samples are skipped (counted), so one bad record
// cannot stall the whole feed; a document with nothing matchable is refused.
func ParseLOLDrivers(data []byte, fetchedAt time.Time) (Snapshot, error) {
	if len(data) > maxLOLDriversBytes {
		return Snapshot{}, fmt.Errorf("parse loldrivers.io: document exceeds %d bytes", maxLOLDriversBytes)
	}
	var drivers []lolDriver
	if err := json.Unmarshal(data, &drivers); err != nil {
		return Snapshot{}, fmt.Errorf("parse loldrivers.io: %w", err)
	}
	digest := sha256.Sum256(data)
	revision := "sha256:" + hex.EncodeToString(digest[:])

	var entries []Entry
	skipped := 0
	for _, d := range drivers {
		var category string
		switch strings.ToLower(strings.TrimSpace(d.Category)) {
		case "vulnerable driver":
			category = CategoryVulnerable
		case "malicious":
			category = CategoryMalicious
		default:
			skipped++
			continue
		}
		id := strings.TrimSpace(d.ID)
		if id == "" || utf8.RuneCountInString(id) > maxEntryIDRunes {
			skipped++
			continue
		}
		name := ""
		for _, s := range d.Samples {
			if f, ok := s["Filename"].(string); ok && strings.TrimSpace(f) != "" {
				name = strings.TrimSpace(f)
				break
			}
		}
		if name == "" {
			for _, t := range d.Tags {
				if s, ok := t.(string); ok && strings.TrimSpace(s) != "" {
					name = strings.TrimSpace(s)
					break
				}
			}
		}
		name = boundRunes(name, maxEntryNameRunes)

		matchable := 0
		for _, s := range d.Samples {
			add := func(kind, hash string) {
				entries = append(entries, Entry{HashKind: kind, Hash: hash, EntryID: id, EntryName: name, Category: category})
				matchable++
			}
			flat256, flat1 := hexField(s["SHA256"], sha256Hex), hexField(s["SHA1"], sha1Hex)
			if flat256 != "" {
				add(HashSHA256, flat256)
			} else if flat1 != "" {
				add(HashSHA1, flat1)
			}
			if auth, ok := s["Authentihash"].(map[string]any); ok {
				auth256, auth1 := hexField(auth["SHA256"], sha256Hex), hexField(auth["SHA1"], sha1Hex)
				if auth256 != "" {
					add(HashAuthenticodeSHA256, auth256)
				} else if auth1 != "" {
					add(HashAuthenticodeSHA1, auth1)
				}
			}
		}
		if matchable == 0 {
			skipped++
		}
	}
	if len(entries) == 0 {
		return Snapshot{}, errors.New("parse loldrivers.io: no matchable hashes")
	}
	return Snapshot{
		Source: SourceLOLDrivers, SourceURL: LOLDriversURL, FetchedAt: fetchedAt.UTC(),
		SourceRevision: revision, Entries: dedupe(entries), Skipped: skipped,
	}, nil
}

func hexField(v any, re *regexp.Regexp) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	s = strings.ToLower(strings.TrimSpace(s))
	if !re.MatchString(s) {
		return ""
	}
	return s
}

func dedupe(entries []Entry) []Entry {
	seen := make(map[[3]string]bool, len(entries))
	out := entries[:0]
	for _, e := range entries {
		key := [3]string{e.HashKind, e.Hash, e.EntryID}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, e)
	}
	return out
}

// boundRunes makes list text safe to store and show: valid UTF-8, no
// control or format characters, at most max runes.
func boundRunes(s string, max int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	s = strings.Map(func(r rune) rune {
		// Format characters too: a bidi override in a list entry name could
		// make the portal show a different file name than the one listed.
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max])
}
