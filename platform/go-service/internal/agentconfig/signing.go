package agentconfig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"patched.im/api/internal/evidencecatalogue"
)

// canonicalPayload is the deterministically-serialised struct that the server
// signs and the agent verifies. Fields are declared alphabetically — Go's
// encoding/json marshals struct fields in declaration order, so this produces
// stable, sorted JSON keys with no custom marshaling needed.
//
// The agent rebuilds this same struct from the GET response (omitting
// "signature" and "key_id") and marshals it identically to verify the
// signature. The canonical layout is documented in contracts/agent-config-schema.md.
//
// app_control (PAT-601) is the first field alphabetically. app_control_authority
// (PAT-1481) follows it and is the separately scoped authority for retained
// application-control paths; it does not grant legacy package execution.
// It is always present (never null) — enabled=false with empty lists is the safe
// default when AC is not provisioned. Existing agents that do not know this field
// will fail signature verification; this is intentional and gates AC enforcement
// on an agent build that reads the field.
//
// log_request (PAT-286) is inserted alphabetically between issued_at and
// os_update_policy. Existing agents that do not know this field will fail
// signature verification when log_request is non-null; this is intentional —
// agents must be updated before log collection is activated (pre-customer-ship
// gate, GitHub-Non-Author-Review).
//
// report_user_attribution (PAT-116) is inserted alphabetically between proxy
// and scan_cadence. Default is "off" — no PII in reports until explicitly
// enabled (PAT-112 DPA dependency). Agents that do not know this field will
// fail signature verification when it is non-"off"; this is acceptable since
// the feature requires an agent build that reads the field.
//
// ring (PAT-117) is the per-device ring integer (0-3); it sorts after
// report_user_attribution ("ri" > "re") and before ring_promotions.
// ring_promotions is the conservative legacy projection and
// ring_promotions_scoped is the authoritative platform-aware projection. They
// sort before scan_cadence and are signed as transmitted bytes, so clients that
// do not know the scoped field continue to verify and consume the legacy map.
//
// blocked_versions (PAT-1238) sorts alphabetically between app_control and
// blocking_process_policy ("blocke" < "blocki"). It is omitempty: a tenant that
// has never set it signs canonical bytes byte-identical to before this field
// existed. When present, agents that predate PAT-1238 simply ignore the unknown
// field after verifying, same forward-compatibility guarantee as every other
// field in this contract.
//
// blocking_process_policy (PAT-296) sorts alphabetically between app_control and
// catalog_scope ("app" < "blo" < "cat"). It is omitempty: when the tenant has no
// policy the field is omitted entirely, so existing tenants' canonical bytes (and
// therefore signatures) are byte-identical to before this field existed — a body
// without the policy verifies exactly as it did pre-PAT-296. When present, agents
// that predate PAT-296 simply ignore the unknown field after verifying (the agent
// verifies the transmitted signed bytes as-is and does NOT reconstruct — see
// endpoint/verify-agent-config.py and windows/src/Service/AgentConfigFetcher.cs in
// Patched-LTD/updater), so adding it is backward-compatible with the whole fleet.
//
// decommission (PAT-1108) is the tenant-wide agent-decommission directive. It
// sorts after config_version and before device_id ("config_version" <
// "decommission" < "device_id") and is always present, never omitted — unlike
// blocking_process_policy, there is deliberately no omitempty here, because
// this is the one directive where "the platform forgot to say anything" and
// "the platform explicitly said do nothing" must be the exact same signed
// bytes: mode="none" (see DefaultDecommissionPolicy). Fail-closed is enforced
// twice: the admin write path validates every field before it is stored, and
// safeDecommissionPolicy (below) is the defense-in-depth pass immediately
// before signing — a malformed stored/legacy row can never enter the signed
// bytes as anything other than the inert "none" directive. This is the only
// irreversible directive in the contract; see the doc comment on
// DecommissionPolicy in schema.go.
//
// device_id (PAT-1026) is the requesting device's own platform device id — the
// same identifier space as devices.id / tenant_credentials.device_id, not the
// macOS IOPlatformUUID. It sorts after decommission and before issued_at
// ("decommission" < "device_id" < "issued_at"). Like ring (PAT-117), it is
// resolved per-request from the authenticated credential and is never part of
// the stored ConfigBody: a device-scoped credential yields its own device id; a
// tenant-wide credential yields the empty string, since no single device id
// would be correct for it. It is always present (never omitted) so the field
// position is stable across every response.
//
// legacy_app_execution_enabled (PAT-1481) is the signed, runtime-derived
// authority gate for quarantined legacy application execution. It is always
// present and defaults false. It deliberately does not replace tier: tier
// remains available to application-control and extension-assurance reporting
// paths that are not legacy execution authority.
type canonicalPayload struct {
	AppControl                  AppControlPolicy                   `json:"app_control"`
	AppControlAuthority         string                             `json:"app_control_authority"`
	BlockedVersions             map[string][]string                `json:"blocked_versions,omitempty"`
	BlockingProcessPolicy       *BlockingProcessPolicy             `json:"blocking_process_policy,omitempty"`
	CatalogScope                json.RawMessage                    `json:"catalog_scope"`
	ConfigVersion               int                                `json:"config_version"`
	Decommission                DecommissionPolicy                 `json:"decommission"`
	DeviceChannelOverrides      map[string]string                  `json:"device_channel_overrides,omitempty"`
	DeviceID                    string                             `json:"device_id"`
	IssuedAt                    string                             `json:"issued_at"`
	LegacyAppExecutionEnabled   bool                               `json:"legacy_app_execution_enabled"`
	LogRequest                  *LogRequestDirective               `json:"log_request"`
	OsUpdatePolicy              json.RawMessage                    `json:"os_update_policy"`
	PerAppPatch                 json.RawMessage                    `json:"per_app_patch"`
	PinnedVersion               *string                            `json:"pinned_version"`
	Proxy                       ProxyConfig                        `json:"proxy"`
	ReportUserAttribution       string                             `json:"report_user_attribution"`
	Ring                        int                                `json:"ring"`
	RingPromotions              json.RawMessage                    `json:"ring_promotions"`
	RingPromotionsScoped        json.RawMessage                    `json:"ring_promotions_scoped"`
	ScanCadence                 json.RawMessage                    `json:"scan_cadence"`
	TenantID                    string                             `json:"tenant_id"`
	Tier                        string                             `json:"tier"`
	UpdateChannel               string                             `json:"update_channel"`
	UpdateChannelSource         string                             `json:"update_channel_source,omitempty"`
	WindowsInstallationEvidence *evidencecatalogue.WindowsDelivery `json:"windows_installation_evidence,omitempty"`
}

// SigningKey wraps an Ed25519 private key with its derived public key and key ID.
type SigningKey struct {
	Private   ed25519.PrivateKey
	Public    ed25519.PublicKey
	KeyID     string // first 8 bytes of SHA-256(pubkey) as lowercase hex
	PubKeyB64 string // base64 std encoding of the public key (for agent pinning / PAT-282)
}

// LoadSigningKey reads the Ed25519 signing key from the AGENT_CONFIG_SIGNING_KEY
// environment variable. The value must be a base64-std-encoded 32-byte seed.
// Logs the public key so it can be pinned in the agent (PAT-282).
func LoadSigningKey() (*SigningKey, error) {
	raw := os.Getenv("AGENT_CONFIG_SIGNING_KEY")
	if raw == "" {
		return nil, errors.New("AGENT_CONFIG_SIGNING_KEY env var not set")
	}
	seed, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("AGENT_CONFIG_SIGNING_KEY: base64 decode: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("AGENT_CONFIG_SIGNING_KEY: expected %d-byte seed, got %d bytes", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	h := sha256.Sum256(pub)
	return &SigningKey{
		Private:   priv,
		Public:    pub,
		KeyID:     hex.EncodeToString(h[:8]),
		PubKeyB64: base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// KeyFromSeed builds a SigningKey from a raw 32-byte Ed25519 seed.
// Useful for tests that need a deterministic key without going through the env-var path.
func KeyFromSeed(seed []byte) (*SigningKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("KeyFromSeed: expected %d-byte seed, got %d bytes", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	h := sha256.Sum256(pub)
	return &SigningKey{
		Private:   priv,
		Public:    pub,
		KeyID:     hex.EncodeToString(h[:8]),
		PubKeyB64: base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// Sign builds the canonical payload from the given config parameters and signs
// it with the Ed25519 private key. Returns (signatureBase64, keyID, canonicalBytes).
//
// issuedAt must be an RFC3339 UTC timestamp string — the caller formats it.
// deviceID is the requesting device's own platform device id (PAT-1026); pass
// the empty string for tenant-wide credentials, where no single device id is
// correct. ring is the per-device ring integer (0-3); pass 3 (GA) for tenant-wide
// credentials where the device identity is unknown. appControl carries the AC
// enforcement policy; its slices are normalised to empty (never nil) so the
// canonical JSON is stable. The canonical bytes are what the agent must
// re-produce to verify the signature.
func Sign(key *SigningKey, body ConfigBody, configVersion int, issuedAt, tenantID, deviceID string, ring int, appControl AppControlPolicy, decommission DecommissionPolicy) (string, string, []byte, error) {
	if key == nil || len(key.Private) != ed25519.PrivateKeySize || strings.TrimSpace(key.KeyID) == "" {
		return "", "", nil, errors.New("agent config signing key is invalid")
	}
	// Normalise slices: nil → empty so encoding/json emits [] not null.
	if appControl.ApprovedAdmins == nil {
		appControl.ApprovedAdmins = []string{}
	}
	if appControl.AppAllowlist == nil {
		appControl.AppAllowlist = []string{}
	}
	if appControl.ExtensionBlocklist == nil {
		appControl.ExtensionBlocklist = []ExtensionBlocklistEntry{}
	}
	if appControl.ExtensionRemovals == nil {
		appControl.ExtensionRemovals = []ExtensionRemovalEntry{}
	}
	cp := canonicalPayload{
		AppControl:                  appControl,
		AppControlAuthority:         safeAppControlAuthority(body.AppControlAuthority),
		BlockedVersions:             body.BlockedVersions,
		BlockingProcessPolicy:       safeBlockingProcessPolicy(body.BlockingProcessPolicy),
		CatalogScope:                coerceRaw(body.CatalogScope),
		ConfigVersion:               configVersion,
		Decommission:                safeDecommissionPolicy(decommission),
		DeviceChannelOverrides:      body.DeviceChannelOverrides,
		DeviceID:                    deviceID,
		IssuedAt:                    issuedAt,
		LegacyAppExecutionEnabled:   body.LegacyAppExecutionEnabled,
		LogRequest:                  body.LogRequest,
		OsUpdatePolicy:              coerceRaw(body.OsUpdatePolicy),
		PerAppPatch:                 coerceRaw(body.PerAppPatch),
		PinnedVersion:               body.PinnedVersion,
		Proxy:                       body.Proxy,
		ReportUserAttribution:       body.ReportUserAttribution,
		Ring:                        ring,
		RingPromotions:              coerceRaw(body.RingPromotions),
		RingPromotionsScoped:        coerceRaw(body.RingPromotionsScoped),
		ScanCadence:                 coerceRaw(body.ScanCadence),
		TenantID:                    tenantID,
		Tier:                        body.Tier,
		UpdateChannel:               body.UpdateChannel,
		UpdateChannelSource:         body.UpdateChannelSource,
		WindowsInstallationEvidence: body.WindowsInstallationEvidence,
	}
	canonical, err := json.Marshal(cp)
	if err != nil {
		return "", "", nil, fmt.Errorf("canonical marshal: %w", err)
	}
	sig := ed25519.Sign(key.Private, canonical)
	return base64.StdEncoding.EncodeToString(sig), key.KeyID, canonical, nil
}

const (
	AppControlAuthorityReport  = "report"
	AppControlAuthorityBlock   = "block"
	AppControlAuthorityEnforce = "enforce"
)

// AppControlAuthorityForDurableTier maps durable tenant tiers to the retained
// application-control authority. Unknown, malformed, and missing tiers fail
// closed to report. Callers must do this before projecting the response tier
// for legacy execution containment.
//
// PAT-1599: collapsed from a three-way switch (report_deploy/patch/managed ->
// report/block/enforce) to two, following the subscription_tier vocabulary
// collapse to assurance/managed. This is a direct, mechanical consequence of
// Andy's ruling on that ticket: "assurance... changes nothing on the
// endpoint, ever" means assurance can never carry blocking authority, and
// "managed - everything above, plus action under authorisation" means
// managed keeps full enforcement. AppControlAuthorityBlock ("block") is no
// longer produced by this function but stays defined and defensively
// accepted by safeAppControlAuthority below - it remains a valid signed
// wire value in the shared contract even though nothing here emits it now.
func AppControlAuthorityForDurableTier(tier string) string {
	switch tier {
	case "assurance":
		return AppControlAuthorityReport
	case "managed":
		return AppControlAuthorityEnforce
	default:
		return AppControlAuthorityReport
	}
}

func safeAppControlAuthority(authority string) string {
	switch authority {
	case AppControlAuthorityReport, AppControlAuthorityBlock, AppControlAuthorityEnforce:
		return authority
	default:
		return AppControlAuthorityReport
	}
}

// SignBytes signs already-canonical bytes with the Ed25519 private key and
// returns (signatureBase64, keyID). It is the shared low-level primitive behind
// both the agent-config signer (Sign, above) and the posture signer (PAT-910),
// so the two wire formats use identical key management, the same key_id
// derivation, and the same {signed_payload, key_id, signature} envelope. There
// is deliberately no second signing scheme: sign the exact canonical bytes you
// intend to transmit, and transmit those same bytes as base64(signed_payload)
// so the endpoint verifies over the transmitted bytes without reconstruction.
func SignBytes(key *SigningKey, canonical []byte) (sigBase64, keyID string) {
	sig := ed25519.Sign(key.Private, canonical)
	return base64.StdEncoding.EncodeToString(sig), key.KeyID
}

// Verify checks that sigBase64 is a valid Ed25519 signature over canonical
// under pub. Used in tests and by the agent SDK.
func Verify(pub ed25519.PublicKey, canonical []byte, sigBase64 string) error {
	sig, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

// AllowedBlockingActions is the set of valid action_on_timeout values (PAT-296).
// Exposed so the admin write-path validation and the signer share one source of
// truth. Any value outside this set is treated as the safe "notify_only" default.
var AllowedBlockingActions = map[string]bool{
	"notify_only":      true, // SAFE DEFAULT — surfaces a notification, never force-quits
	"prompt_then_quit": true,
	"skip_run":         true,
}

// DefaultBlockingActionOnTimeout is the minimum-safe action the agent must fall
// back to for an absent/empty/unrecognised policy — it never force-quits an app.
const DefaultBlockingActionOnTimeout = "notify_only"

// Blocking-process-policy safe ranges (PAT-296), shared by the admin write-path
// validator and the signer's fail-closed pass so the two never drift. A policy
// whose numerics fall outside these bounds is treated as malformed.
const (
	MinBlockingTimeoutSeconds     = 30
	MaxBlockingTimeoutSeconds     = 86400
	MinBlockingDeferWindowSeconds = 60
	MaxBlockingDeferWindowSeconds = 86400
)

// blockingPolicyIsWellFormed reports whether every field of p is within the same
// validated safe range the admin write-path enforces. Only a well-formed policy
// may carry a non-notify (potentially app-closing) action into the signed bytes.
// Note: notify_only is the safe action and never quits regardless of numerics, so
// out-of-range numerics matter only because they must not accompany a quitting
// action — the signer handles that by coercing the action, not the numerics.
func blockingPolicyIsWellFormed(p BlockingProcessPolicy) bool {
	if !AllowedBlockingActions[p.ActionOnTimeout] {
		return false
	}
	if p.TimeoutSeconds < MinBlockingTimeoutSeconds || p.TimeoutSeconds > MaxBlockingTimeoutSeconds {
		return false
	}
	if p.MaxDeferrals < 0 {
		return false
	}
	if p.DeferWindowSeconds < MinBlockingDeferWindowSeconds || p.DeferWindowSeconds > MaxBlockingDeferWindowSeconds {
		return false
	}
	return true
}

// safeBlockingProcessPolicy is a defense-in-depth pass applied to every policy
// immediately before it enters the signed canonical payload. It returns nil
// unchanged (absent policy → agent applies its own built-in safe defaults) and
// otherwise returns a copy whose action_on_timeout is coerced to "notify_only"
// whenever the policy is malformed in ANY field — an unknown/empty action, or a
// dangerous-but-valid action ("prompt_then_quit"/"skip_run") paired with
// out-of-safe-range numerics (e.g. timeout_seconds<=0, max_deferrals<0,
// defer_window_seconds<=0) that could drive an effectively-immediate force-quit.
// The admin PUT validator guards new writes; this is the boundary for stored or
// legacy rows. It guarantees the signed bytes can NEVER instruct the agent to
// close/kill an app on a malformed directive, and copies rather than mutating the
// caller's struct so the stored body is left untouched. nil policy stays nil so
// the field is omitted — canonical bytes remain byte-identical for policy-less
// tenants.
func safeBlockingProcessPolicy(p *BlockingProcessPolicy) *BlockingProcessPolicy {
	if p == nil {
		return nil
	}
	out := *p
	if !blockingPolicyIsWellFormed(out) {
		// Fail closed: never sign a (potentially app-closing) action on a
		// malformed policy. notify_only never force-quits, whatever the numerics.
		out.ActionOnTimeout = DefaultBlockingActionOnTimeout
	}
	return &out
}

// AllowedDecommissionModes is the set of valid decommission.mode values
// (PAT-1108). Exposed so the admin write-path validator and the signer share
// one source of truth, the same pattern as AllowedBlockingActions. Any value
// outside this set is treated as the safe "none" default.
var AllowedDecommissionModes = map[string]bool{
	"none":      true, // SAFE DEFAULT — inert, agent takes no action
	"expiry":    true,
	"immediate": true,
}

// decommissionIsWellFormed reports whether p is safe to sign as-is. This is
// deliberately narrow and fails closed on anything it cannot positively
// confirm: an unrecognised mode, or mode="expiry" with a missing or
// unparseable expires_at (an agent must never guess a date, and neither may
// the signer). mode="none" and mode="immediate" carry no other required
// field, so they are well-formed by definition once the mode itself is valid.
func decommissionIsWellFormed(p DecommissionPolicy) bool {
	if !AllowedDecommissionModes[p.Mode] {
		return false
	}
	if p.Mode == "expiry" {
		if p.ExpiresAt == nil || strings.TrimSpace(*p.ExpiresAt) == "" {
			return false
		}
		if _, err := time.Parse(time.RFC3339, *p.ExpiresAt); err != nil {
			return false
		}
	}
	return true
}

// safeDecommissionPolicy is the defense-in-depth pass applied to every
// decommission directive immediately before it enters the signed canonical
// payload (PAT-1108) — this is the server-side half of "fail closed means DO
// NOT REMOVE". The admin write path (internal/handlers/agent_decommission.go)
// validates a new directive before it is stored; this is the boundary for
// whatever is actually in the tenant_decommission row at sign time, so a
// stored value that is malformed for any reason — a hand-edited row, a future
// schema drift, a nil ExpiresAt slipping past a caller that forgot to check —
// can NEVER be signed as anything other than the fully inert
// DefaultDecommissionPolicy(). It never returns a directive whose Mode is
// outside AllowedDecommissionModes, and never returns mode="expiry" without a
// verified-parseable ExpiresAt. Reason and Purge are also cleared on coercion
// so a rejected directive can never signal partial state to the agent.
func safeDecommissionPolicy(p DecommissionPolicy) DecommissionPolicy {
	if !decommissionIsWellFormed(p) {
		return DefaultDecommissionPolicy()
	}
	return p
}

// coerceRaw returns r unchanged if non-empty, otherwise returns the JSON null literal.
// This ensures reserved fields always appear as "null" in the canonical payload
// rather than being omitted, which would change the signed bytes.
func coerceRaw(r json.RawMessage) json.RawMessage {
	if len(r) == 0 {
		return json.RawMessage("null")
	}
	return r
}
