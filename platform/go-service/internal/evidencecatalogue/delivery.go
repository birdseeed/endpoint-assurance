package evidencecatalogue

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Publication metadata is reviewed release data, not derived from wall-clock
// time, tenant configuration, process activation, or an execution catalogue.
const (
	WindowsDeliveryVersion  int64 = 1
	WindowsCatalogueVersion       = "2026.09.20.1"
	WindowsContentHash            = "a3ea6bba02d8766c4f8432a04caf26154929651cb4722909b7f04df44922df5c"
	WindowsPublishedAt            = "2026-09-20T00:00:00Z"
	WindowsExpiresAt              = "2026-12-19T00:00:00Z"
	MaxWindowsTargets             = 24
)

// ProductCode and UpgradeCode share a GUID spelling, but are different MSI
// identities. Keep the delivery validator named for its ProductCode contract;
// matching the syntax never authorises converting an UpgradeCode into one.
var msiProductCodePattern = regexp.MustCompile(`^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$`)

// WindowsTarget identifies evidence to observe, never software to execute.
// Alphabetical field order is part of the canonical content-hash contract.
type WindowsTarget struct {
	AuthenticodeSubject string `json:"authenticode_subject"`
	ExecutablePath      string `json:"executable_path"`
	IdentityKind        string `json:"identity_kind"`
	IdentityValue       string `json:"identity_value"`
	InstallPath         string `json:"install_path"`
}

type WindowsDelivery struct {
	CatalogueVersion string          `json:"catalogue_version"`
	ContentHash      string          `json:"content_hash"`
	DeliveryVersion  int64           `json:"delivery_version"`
	ExpiresAt        string          `json:"expires_at"`
	PublishedAt      string          `json:"published_at"`
	SchemaVersion    int             `json:"schema_version"`
	Targets          []WindowsTarget `json:"targets"`
}

// EmbeddedWindowsDelivery is the sole production source. The existing
// catalogue has no reviewed executable/install path pairs, so any Windows
// entry fails closed until PAT-1922 explicitly extends the evidence source.
func EmbeddedWindowsDelivery() (*WindowsDelivery, error) {
	catalogue, err := LoadEmbedded()
	if err != nil {
		return nil, err
	}
	return deriveWindowsDelivery(catalogue)
}

func deriveWindowsDelivery(catalogue *Catalogue) (*WindowsDelivery, error) {
	if err := Validate(catalogue); err != nil {
		return nil, err
	}
	for _, entry := range catalogue.Entries {
		if entry.Platform == "windows" {
			return nil, errors.New("Windows evidence lacks reviewed executable/install path pairs; PAT-1922 required")
		}
	}
	if catalogue.CatalogueVersion != WindowsCatalogueVersion {
		return nil, errors.New("Windows publication requires reviewed catalogue version metadata")
	}
	delivery := &WindowsDelivery{
		CatalogueVersion: catalogue.CatalogueVersion,
		DeliveryVersion:  WindowsDeliveryVersion,
		ExpiresAt:        WindowsExpiresAt, PublishedAt: WindowsPublishedAt,
		SchemaVersion: SchemaVersion, Targets: []WindowsTarget{},
	}
	hash, err := delivery.CanonicalContentHash()
	if err != nil {
		return nil, err
	}
	delivery.ContentHash = hash
	if hash != WindowsContentHash {
		return nil, errors.New("Windows publication differs from reviewed content hash")
	}
	return delivery, nil
}

// CanonicalContentHash binds the data version and every target. Publication
// metadata is separately bound by both the ledger and the Ed25519 signature.
func (d *WindowsDelivery) CanonicalContentHash() (string, error) {
	content := struct {
		CatalogueVersion string          `json:"catalogue_version"`
		SchemaVersion    int             `json:"schema_version"`
		Targets          []WindowsTarget `json:"targets"`
	}{d.CatalogueVersion, d.SchemaVersion, d.Targets}
	raw, err := json.Marshal(content)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:]), nil
}

func (d *WindowsDelivery) Validate(now time.Time) error {
	if d == nil || d.SchemaVersion != SchemaVersion || d.DeliveryVersion < 1 || !idPattern.MatchString(d.CatalogueVersion) {
		return errors.New("invalid Windows delivery version")
	}
	published, err := time.Parse(time.RFC3339, d.PublishedAt)
	if err != nil || d.PublishedAt != published.UTC().Format(time.RFC3339) {
		return errors.New("invalid Windows delivery publication time")
	}
	expires, err := time.Parse(time.RFC3339, d.ExpiresAt)
	if err != nil || d.ExpiresAt != expires.UTC().Format(time.RFC3339) || !expires.After(published) || expires.Sub(published) > 90*24*time.Hour || now.Before(published) || !now.Before(expires) {
		return errors.New("Windows delivery outside its reviewed validity window")
	}
	if d.Targets == nil || len(d.Targets) > MaxWindowsTargets {
		return errors.New("Windows delivery requires an array of at most 24 targets")
	}
	previous := ""
	for i, target := range d.Targets {
		if err := target.Validate(); err != nil {
			return fmt.Errorf("Windows target %d: %w", i, err)
		}
		key := target.IdentityKind + "\x00" + target.IdentityValue
		if i > 0 && key <= previous {
			return errors.New("Windows targets must be unique and sorted by identity kind, value, install path, executable path")
		}
		previous = key
	}
	hash, err := d.CanonicalContentHash()
	if err != nil || !sha256Pattern.MatchString(d.ContentHash) || hash != d.ContentHash {
		return errors.New("Windows delivery content hash mismatch")
	}
	return nil
}

func (t WindowsTarget) Validate() error {
	if t.IdentityKind != "windows_msi_product_code" || !msiProductCodePattern.MatchString(t.IdentityValue) {
		return errors.New("v1 requires a canonical uppercase braced MSI ProductCode; UpgradeCode, Winget and MSIX are unsupported")
	}
	if !validAuthenticodeSubject(t.AuthenticodeSubject) || strings.IndexFunc(t.AuthenticodeSubject, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return errors.New("authoritative Authenticode subject required")
	}
	if !exactWindowsDeliveryPath(t.InstallPath) || !exactWindowsDeliveryPath(t.ExecutablePath) ||
		!strings.HasPrefix(strings.ToLower(t.ExecutablePath), strings.ToLower(t.InstallPath)+`\`) ||
		!strings.HasSuffix(strings.ToLower(t.ExecutablePath), ".exe") {
		return errors.New("exact install directory and contained executable path required")
	}
	return nil
}

func exactWindowsDeliveryPath(path string) bool {
	if !validPath("windows", path) || len(path) > 1024 || strings.ContainsAny(path[3:], `:"<>|%`) {
		return false
	}
	for _, segment := range strings.Split(path[3:], `\`) {
		if strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
			return false
		}
		base := strings.ToUpper(strings.SplitN(segment, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" ||
			(len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9') {
			return false
		}
		for _, r := range segment {
			if r < 32 || r == 127 {
				return false
			}
		}
	}
	return true
}
