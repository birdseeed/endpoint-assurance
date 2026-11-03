// Package agentconfig defines the per-tenant agent configuration schema and
// Ed25519 signing logic for GET /v1/agent-config.
package agentconfig

import (
	"encoding/json"
	"time"

	"patched.im/api/internal/evidencecatalogue"
)

// AppControlPolicy is the Application Control enforcement block delivered in
// the signed agent config (PAT-601). Agents gate all AC enforcement on the
// Enabled flag and trust the lists only because they arrive in the signed payload.
//
// Fields are declared alphabetically for stable JSON serialisation — the struct
// is included in the Ed25519-signed canonical payload first (sorts before
// "catalog_scope"). Existing agents that do not know this field will fail
// signature verification; this is intentional and gates AC enforcement on an
// agent build that reads the field (same pattern as log_request/PAT-286,
// report_user_attribution/PAT-116, ring/PAT-117).
type AppControlPolicy struct {
	AppAllowlist       []string                  `json:"app_allowlist"`       // bundle IDs (macOS) or process names (Windows); empty = allowlist enforcement disabled
	ApprovedAdmins     []string                  `json:"approved_admins"`     // usernames permitted in the local admin/Administrators group
	Enabled            bool                      `json:"enabled"`             // when false, agents skip all AC enforcement
	ExtensionBlocklist []ExtensionBlocklistEntry `json:"extension_blocklist"` // PAT-828: browser extensions to block via managed policy; empty = block nothing
	ExtensionRemovals  []ExtensionRemovalEntry   `json:"extension_removals"`  // PAT-829: browser extensions to destructively remove; empty = remove nothing
}

// ExtensionBlocklistEntry is one unapproved-extension entry the agent blocks via
// browser-managed policy (PAT-828). Keyed on (browser, extension_id) — the only
// stable identity a browser extension carries. Mirrors the C# ExtensionBlocklistEntry.
//
// Fields are declared alphabetically for stable JSON serialisation.
type ExtensionBlocklistEntry struct {
	Browser     string `json:"browser"`      // "chrome" | "edge" | "firefox" — never "any" (fanned out server-side)
	ExtensionID string `json:"extension_id"` // the extension identifier in that browser's own id form
}

// ExtensionRemovalEntry is one destructive-removal directive (PAT-829). Identifies
// the extension by (browser, extension_id) plus an explicit Scope bounding how
// widely the agent deletes it. UserAccount/Profile narrow the target and are
// required by the correspondingly narrow scopes (validated server-side before the
// request is stored). Mirrors the C# ExtensionRemovalEntry wire shape.
//
// Fields are declared alphabetically for stable JSON serialisation. UserAccount
// and Profile serialise as null (not omitted) when a scope does not use them, so
// the canonical payload round-trips exactly as the agent parses it.
type ExtensionRemovalEntry struct {
	ApprovedBefore *time.Time `json:"approved_before,omitempty"` // observed install must not be newer than this approval boundary
	Browser        string     `json:"browser"`                   // "chrome" | "edge" | "firefox"
	ExtensionID    string     `json:"extension_id"`              // the extension identifier in that browser's own id form
	Profile        *string    `json:"profile"`                   // exact browser-profile dir
	Scope          string     `json:"scope"`                     // delivered removal uses "one_observation"
	UserAccount    *string    `json:"user_account"`              // exact OS account
}

// DecommissionPolicy is the tenant-wide agent-decommission directive
// (PAT-1108). Always present in the signed canonical payload (never omitted,
// never null) — mode "none" is the safe, inert default, exactly like
// AppControlPolicy's enabled=false default, and is byte-for-byte what every
// tenant without an explicit directive signs.
//
// This is the ONLY irreversible directive in the whole contract: once an
// agent removes itself there is no channel left to correct a mistake. The
// server-side contract is built around that fact — "no directive" and
// "mode=none" are indistinguishable by construction (see
// DefaultDecommissionPolicy and safeDecommissionPolicy in signing.go), and
// Reason is carried for audit/operator visibility only. It MUST NEVER be
// evaluated as part of any control-flow decision, here or on the agent.
//
// Fields are declared alphabetically for stable JSON serialisation, matching
// the canonical signed-payload convention.
type DecommissionPolicy struct {
	ExpiresAt *string `json:"expires_at"` // RFC3339 UTC; required (non-null) when Mode == "expiry"; ignored otherwise
	Mode      string  `json:"mode"`       // "none" (default, inert) | "expiry" | "immediate"
	Purge     bool    `json:"purge"`      // when true, also remove locally cached artefacts, not just the uploader/daemon
	Reason    *string `json:"reason"`     // operator-supplied context; recorded/surfaced only, NEVER a control-flow input
}

// DefaultDecommissionPolicy returns the safe, inert default: mode "none",
// every other field zero. This is what every tenant without an explicit
// directive signs, and what a malformed/unparseable stored directive is
// coerced to before signing — see safeDecommissionPolicy in signing.go.
func DefaultDecommissionPolicy() DecommissionPolicy {
	return DecommissionPolicy{Mode: "none"}
}

// BlockingProcessPolicy is the per-tenant close-to-update policy (PAT-296): it
// controls how the agent behaves when an app that must close to update is still
// running. It is optional — absent (nil) means the agent applies its own built-in
// safe defaults (notify_only, 2 deferrals, 300s). When present it is delivered in
// the Ed25519-signed canonical payload so the agent can trust it.
//
// Safety invariant: an absent or malformed policy must NEVER cause the agent to
// force-quit a running app. ActionOnTimeout defaults to "notify_only" server-side
// (see the admin write path) and any unrecognised value is coerced to
// "notify_only" before signing (see signing.go) — the agent enforces the same
// minimum-safe default independently.
//
// Fields are declared alphabetically for stable JSON serialisation, matching the
// canonical signed-payload convention. Message is a pointer so it round-trips as
// null (tenant has no custom copy → agent uses its built-in message) rather than
// an empty string.
type BlockingProcessPolicy struct {
	ActionOnTimeout    string  `json:"action_on_timeout"`    // "notify_only" (default, never force-quits) | "prompt_then_quit" | "skip_run"
	DeferWindowSeconds int     `json:"defer_window_seconds"` // how long a single deferral postpones the prompt
	MaxDeferrals       int     `json:"max_deferrals"`        // max user deferrals per app per cycle; 0 = none allowed
	Message            *string `json:"message"`              // tenant-brandable prompt copy; null = agent's built-in default
	TimeoutSeconds     int     `json:"timeout_seconds"`      // seconds to wait for the process to exit before ActionOnTimeout
}

// ProxyConfig is the proxy section of the agent config.
// Fields are declared alphabetically so encoding/json emits them in
// stable, sorted key order — matching the canonical signed payload.
type ProxyConfig struct {
	AuthRef           *string `json:"auth_ref"`
	BypassWhenOffCorp bool    `json:"bypass_when_off_corp"`
	Host              *string `json:"host"`
	Mode              string  `json:"mode"`
	PacURL            *string `json:"pac_url"`
	Port              *int    `json:"port"`
	Type              *string `json:"type"`
}

// LogRequestDirective is the optional on-demand log-collection directive (PAT-286).
// When present in the agent config, the agent whose device_id matches the
// directive collects and uploads a log bundle to POST /v1/agent-logs.
//
// Fields are declared alphabetically for stable JSON serialisation — the struct
// is included in the Ed25519-signed canonical payload.
type LogRequestDirective struct {
	Components []string `json:"components"` // log components to collect, e.g. ["updater","collector"]
	DeviceID   string   `json:"device_id"`  // UUID of the target device
	MaxBytes   int      `json:"max_bytes"`  // max compressed bundle size the agent should produce
	RequestID  string   `json:"request_id"` // UUID — idempotency key end-to-end
	Since      string   `json:"since"`      // RFC3339 start of log range (inclusive)
	Until      string   `json:"until"`      // RFC3339 end of log range (exclusive)
}

// ConfigBody holds the config fields stored in the agent_config.body JSONB
// column. Reserved keys are null by default and populated by future features.
//
// Fields are declared alphabetically so the canonical signed payload is always
// produced with stable, sorted key order (encoding/json respects declaration
// order for structs).
type ConfigBody struct {
	AppControlAuthority         string                             `json:"-"`                                 // PAT-1481: response-only retained application-control authority. Derived from durable tier immediately before the legacy tier projection; never persisted.
	BlockedVersions             map[string][]string                `json:"blocked_versions,omitempty"`        // PAT-1238: Installomator/winget label -> blocked version strings. Agent must never let a listed version reach "installed". Empty/absent = no version blocked for any label.
	BlockingProcessPolicy       *BlockingProcessPolicy             `json:"blocking_process_policy,omitempty"` // PAT-296: null/absent = agent safe defaults (notify_only). omitempty keeps existing tenants' stored/canonical bytes byte-identical.
	CatalogScope                json.RawMessage                    `json:"catalog_scope"`
	LegacyAppExecutionEnabled   bool                               `json:"legacy_app_execution_enabled"` // PAT-1481: signed runtime authority gate for quarantined legacy app execution only. Safe default false.
	LogRequest                  *LogRequestDirective               `json:"log_request"`                  // PAT-286 — null when no request pending
	OsUpdatePolicy              json.RawMessage                    `json:"os_update_policy"`
	PerAppPatch                 json.RawMessage                    `json:"per_app_patch"`
	PinnedVersion               *string                            `json:"pinned_version"` // PAT-108: null = always latest; string = pin to specific version
	Proxy                       ProxyConfig                        `json:"proxy"`
	ReportUserAttribution       string                             `json:"report_user_attribution"` // PAT-116: "off" | "local_part" | "full_upn". Default "off". PII — see PAT-112 DPA.
	RingPromotions              json.RawMessage                    `json:"ring_promotions"`         // PAT-117: per-label version approvals written by the rings rollout worker. null = no active rollouts.
	RingPromotionsScoped        json.RawMessage                    `json:"ring_promotions_scoped"`  // PAT-1134: platform-aware rollout decisions. Present (including {}) once the rollout worker has published.
	ScanCadence                 json.RawMessage                    `json:"scan_cadence"`
	Tier                        string                             `json:"tier"`
	UpdateChannel               string                             `json:"update_channel"` // PAT-108: "stable" | "beta". Default "stable".
	UpdateChannelSource         string                             `json:"-"`              // PAT-2005: signed response-only origin; omitted when not authoritative.
	DeviceChannelOverrides      map[string]string                  `json:"-"`              // PAT-2004: response-only, tenant-wide signed projection.
	WindowsInstallationEvidence *evidencecatalogue.WindowsDelivery `json:"-"`              // PAT-1921: response-only, exclusively validated embedded evidence.
}

// DefaultConfigBody returns the safe default for any new or backfilled tenant.
// tier = "assurance" is the conservative default: collect and report, no
// endpoint actuation (PAT-1599, migration 0138 — collapsed from the retired
// "report_deploy" value).
func DefaultConfigBody() ConfigBody {
	return ConfigBody{
		AppControlAuthority:       AppControlAuthorityReport,
		CatalogScope:              json.RawMessage("null"),
		LegacyAppExecutionEnabled: false,
		LogRequest:                nil,
		OsUpdatePolicy:            json.RawMessage("null"),
		PerAppPatch:               json.RawMessage("null"),
		PinnedVersion:             nil,
		Proxy:                     ProxyConfig{Mode: "system"},
		ReportUserAttribution:     "off", // privacy default — no PII in reports until explicitly enabled (PAT-112 DPA)
		RingPromotions:            json.RawMessage("null"),
		RingPromotionsScoped:      json.RawMessage("null"),
		ScanCadence:               json.RawMessage("null"),
		Tier:                      "assurance",
		UpdateChannel:             "stable",
	}
}
