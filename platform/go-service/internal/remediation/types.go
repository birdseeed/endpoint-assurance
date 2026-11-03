// Package remediation generates per-platform remediation artefacts for
// advisory CIS/config findings (PAT-1549): a signed .mobileconfig for macOS
// (which Jamf also accepts directly — no separate Jamf generator), and an
// Intune settings-catalogue JSON payload for Windows. Group Policy/ADMX is
// explicitly out of scope at launch.
//
// Scope boundary: this package only ever receives a compliance_rules row.
// CVE findings (device_cve_findings / cve_feed_entries, migration 0025)
// have no rule_id and are never routed here — see the file-level comment on
// migrations/0141_remediation_artefacts.sql for why there is no separate
// "rule type" flag to check.
//
// Product boundary this package holds: Patched produces the artefact: the
// customer applies it themselves, in their own management platform. Nothing
// here calls out to Jamf or Intune, and nothing here assumes the artefact
// was applied — see the extractor's auto-detection hook
// (internal/extractor/upsert.go, markArtefactsApplied) for how "applied"
// state is derived purely from later observed posture, never asked.
//
// Coverage is deliberately partial: GenerateInput.Rule.RuleKey must have a
// curated entry in mapping.go before Generate will produce anything. A rule
// with no known, confidently-sourced remediation payload returns
// ErrNoMapping rather than fabricating a plausible-looking one — the same
// "evidence before assertion" posture the root AGENTS.md hard constraints
// require for CVE and usage claims, applied here to remediation claims.
package remediation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// RuleContext is the subset of a compliance_rules row Generate needs. Callers
// (internal/handlers/remediation_artefacts.go) fetch this from the DB; this
// package has no DB dependency of its own, matching the
// internal/devicelifecycle convention of pure, DB-free generation/decision
// logic with unit-testable boundary cases.
type RuleContext struct {
	RuleID           string
	RuleKey          string
	Title            string
	Description      string
	Severity         string
	Platform         string // "macos" | "windows" | "cross-platform"
	SignalKey        string
	Comparator       string
	ExpectedValues   []string
	BenchmarkVersion string
}

// GenerateInput is everything Generate needs to build one artefact.
// ObservedPriorValue is the observed_value read from the most recent FAILING
// compliance_evaluations row for (DeviceID, Rule.RuleID) — captured for
// storage (ruling 3: a future PAT-1665 rollback generator consumes it) but
// not otherwise used by generation itself.
type GenerateInput struct {
	TenantID           string
	DeviceID           string
	Rule               RuleContext
	ObservedPriorValue *string
	GeneratedAt        time.Time // UTC; caller supplies so payload and DB row agree exactly
}

// GenerateResult is the generated artefact body plus its content hash.
type GenerateResult struct {
	Platform    string
	Payload     []byte
	ContentHash string // lowercase hex sha256(Payload)
}

// ErrUnsupportedPlatform is returned for a rule whose platform is not
// exactly "macos" or "windows" — a "cross-platform" compliance_rules row has
// no single artefact format to generate and is out of this ticket's scope.
var ErrUnsupportedPlatform = errors.New("remediation: rule platform has no single-format generator (macos or windows only)")

// ErrNoMapping is returned when RuleKey has no curated entry in mapping.go.
// This is the fail-closed path: Generate never invents a remediation
// payload for a control it does not have a confidently-sourced mapping for.
var ErrNoMapping = errors.New("remediation: no known remediation payload mapping for this rule")

// Generate dispatches to the macOS or Windows builder by Rule.Platform and
// hashes the result. Both builders return ErrNoMapping for an unmapped
// RuleKey.
func Generate(in GenerateInput) (GenerateResult, error) {
	var payload []byte
	var err error

	switch in.Rule.Platform {
	case "macos":
		payload, err = buildMobileconfig(in)
	case "windows":
		payload, err = buildIntuneSettingsCatalogue(in)
	default:
		return GenerateResult{}, ErrUnsupportedPlatform
	}
	if err != nil {
		return GenerateResult{}, err
	}

	sum := sha256.Sum256(payload)
	return GenerateResult{
		Platform:    in.Rule.Platform,
		Payload:     payload,
		ContentHash: hex.EncodeToString(sum[:]),
	}, nil
}

// HasMapping reports whether RuleKey has a curated remediation mapping for
// platform, without building the payload. Used by the admin list/candidate
// surface to say "generatable" without paying for a full build.
func HasMapping(platform, ruleKey string) bool {
	switch platform {
	case "macos":
		_, ok := macOSMappings[ruleKey]
		return ok
	case "windows":
		_, ok := windowsMappings[ruleKey]
		return ok
	default:
		return false
	}
}
