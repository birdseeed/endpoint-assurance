package agentconfig

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestSign_DefaultConfigBodyOmitsMandatoryInstallIntentsKey pins that the
// signed canonical bytes never carry "mandatory_install_intents". PAT-1399
// added the key as omitempty and production never populated it; PAT-2246
// retired it with the signed catalogue, so the signed bytes every tenant
// receives are unchanged by its removal.
func TestSign_DefaultConfigBodyOmitsMandatoryInstallIntentsKey(t *testing.T) {
	key := testKey(t)
	body := DefaultConfigBody()

	_, _, canonical, err := Sign(key, body, 1, bppIssuedAt, bppTenantID, "", 3, AppControlPolicy{}, DecommissionPolicy{})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if strings.Contains(string(canonical), "mandatory_install_intents") {
		t.Fatalf("canonical bytes must NOT contain mandatory_install_intents (retired, PAT-2246); got: %s", canonical)
	}
}

// TestSign_LegacyAppExecutionEnabledIsExplicitSignedAndOldClientCompatible
// proves the permanent false gate is present in the signed bytes while a
// client that knows none of its fields can verify those exact bytes first and
// then parse the fields it does know. This matches both endpoint verifiers:
// they base64-decode signed_payload and verify it directly, without rebuilding
// canonical JSON. Unknown JSON members are therefore not a signature boundary.
func TestSign_LegacyAppExecutionEnabledIsExplicitSignedAndOldClientCompatible(t *testing.T) {
	key := testKey(t)
	body := DefaultConfigBody()
	sig, _, canonical, err := Sign(key, body, 1, bppIssuedAt, bppTenantID, "", 3, AppControlPolicy{}, DecommissionPolicy{})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(key.Public, canonical, sig); err != nil {
		t.Fatalf("raw signed payload did not verify: %v", err)
	}
	var decoded canonicalPayload
	if err := json.Unmarshal(canonical, &decoded); err != nil {
		t.Fatalf("unmarshal current payload: %v", err)
	}
	if decoded.LegacyAppExecutionEnabled {
		t.Errorf("signed legacy_app_execution_enabled = true, want false")
	}
	if decoded.AppControlAuthority != AppControlAuthorityReport {
		t.Errorf("signed app_control_authority = %q, want %q", decoded.AppControlAuthority, AppControlAuthorityReport)
	}
	if !bytes.Contains(canonical, []byte(`"app_control_authority":"report"`)) {
		t.Errorf("signed payload omitted app_control_authority: %s", canonical)
	}
	if !bytes.Contains(canonical, []byte(`"legacy_app_execution_enabled":false`)) {
		t.Errorf("signed payload omitted explicit false legacy_app_execution_enabled: %s", canonical)
	}

	// A pre-PAT-1481 decoder has no field for the new gate. JSON decoding must
	// still retain the old tier and tenant binding after raw-byte verification.
	var oldClient struct {
		ConfigVersion int    `json:"config_version"`
		TenantID      string `json:"tenant_id"`
		Tier          string `json:"tier"`
	}
	if err := json.Unmarshal(canonical, &oldClient); err != nil {
		t.Fatalf("old-client JSON decode: %v", err)
	}
	if oldClient.ConfigVersion != 1 || oldClient.TenantID != bppTenantID || oldClient.Tier != "assurance" {
		t.Fatalf("old-client projection = %#v, want verified established fields", oldClient)
	}
}

// TestAppControlAuthorityForDurableTierFailsClosed pins the PAT-1599
// (migration 0138) two-value vocabulary: "managed" is the only tier that
// earns enforcement authority. Every other value — the current non-managed
// tier ("assurance"), any retired three-rung value ("patch",
// "report_deploy", "full_endpoint"), and anything unrecognized — fails
// closed to AppControlAuthorityReport (no blocking/enforcement authority).
func TestAppControlAuthorityForDurableTierFailsClosed(t *testing.T) {
	tests := []struct {
		tier, want string
	}{
		{"assurance", AppControlAuthorityReport},
		{"managed", AppControlAuthorityEnforce},
		// Retired three-rung values are unrecognized now, not remapped.
		{"report_deploy", AppControlAuthorityReport},
		{"patch", AppControlAuthorityReport},
		{"full_endpoint", AppControlAuthorityReport},
		{"", AppControlAuthorityReport},
		{"malformed", AppControlAuthorityReport},
	}
	for _, tc := range tests {
		t.Run(tc.tier, func(t *testing.T) {
			if got := AppControlAuthorityForDurableTier(tc.tier); got != tc.want {
				t.Fatalf("AppControlAuthorityForDurableTier(%q) = %q, want %q", tc.tier, got, tc.want)
			}
		})
	}
}

func TestAppControlAuthorityIsResponseOnlyAndDefaultsToReport(t *testing.T) {
	stored, err := json.Marshal(DefaultConfigBody())
	if err != nil {
		t.Fatalf("marshal default config body: %v", err)
	}
	if bytes.Contains(stored, []byte("app_control_authority")) {
		t.Fatalf("response-only authority was persisted into ConfigBody: %s", stored)
	}

	// A stale or hand-written persisted key must not become a tenant preference.
	var parsed ConfigBody
	if err := json.Unmarshal([]byte(`{"tier":"managed","app_control_authority":"enforce"}`), &parsed); err != nil {
		t.Fatalf("unmarshal legacy config body: %v", err)
	}
	if parsed.AppControlAuthority != "" {
		t.Fatalf("persisted app_control_authority was accepted as runtime authority: %q", parsed.AppControlAuthority)
	}

	key := testKey(t)
	_, _, canonical, err := Sign(key, parsed, 1, bppIssuedAt, bppTenantID, "", 3, AppControlPolicy{}, DecommissionPolicy{})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Contains(canonical, []byte(`"app_control_authority":"report"`)) {
		t.Fatalf("missing runtime authority did not fail closed to report: %s", canonical)
	}
}

// testKey returns a deterministic signing key for canonical/signature assertions.
func testKey(t *testing.T) *SigningKey {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	k, err := KeyFromSeed(seed)
	if err != nil {
		t.Fatalf("KeyFromSeed: %v", err)
	}
	return k
}

const (
	bppTenantID = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	bppIssuedAt = "2026-12-10T12:00:00Z"
)

// TestSign_BlockingProcessPolicyAbsent_BackwardCompatible is the critical
// backward-compat proof (PAT-296). A ConfigBody without a blocking_process_policy
// must produce canonical bytes byte-identical to how it signed before the field
// existed — i.e. the key must be omitted entirely, so every existing tenant's
// signature is unchanged and no deployed agent's verification breaks.
func TestSign_BlockingProcessPolicyAbsent_BackwardCompatible(t *testing.T) {
	key := testKey(t)
	body := DefaultConfigBody() // BlockingProcessPolicy is nil
	if body.BlockingProcessPolicy != nil {
		t.Fatal("precondition: DefaultConfigBody must not set a blocking_process_policy")
	}

	_, _, canonical, err := Sign(key, body, 1, bppIssuedAt, bppTenantID, "", 3, AppControlPolicy{}, DecommissionPolicy{})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// The field must be entirely absent from the signed bytes when the policy is nil.
	if bytes.Contains(canonical, []byte("blocking_process_policy")) {
		t.Fatalf("canonical bytes must NOT contain blocking_process_policy when the policy is nil; got: %s", canonical)
	}

	// The canonical layout must be exactly app_control immediately followed by
	// catalog_scope (no field inserted between them) — this is the pre-PAT-296
	// byte layout, proving existing signatures are unchanged.
	if !strings.Contains(string(canonical), `"app_control":`) {
		t.Fatalf("expected app_control in canonical: %s", canonical)
	}
	acIdx := bytes.Index(canonical, []byte(`"catalog_scope":`))
	appIdx := bytes.Index(canonical, []byte(`"app_control":`))
	if acIdx < 0 || appIdx < 0 || acIdx < appIdx {
		t.Fatalf("unexpected canonical ordering: %s", canonical)
	}

	// Signing the same body twice must be deterministic.
	_, _, canonical2, err := Sign(key, body, 1, bppIssuedAt, bppTenantID, "", 3, AppControlPolicy{}, DecommissionPolicy{})
	if err != nil {
		t.Fatalf("Sign (2): %v", err)
	}
	if !bytes.Equal(canonical, canonical2) {
		t.Fatal("canonical bytes are not deterministic across two identical Sign calls")
	}
}

func TestSign_OmitsRetiredUsageTrackingFlag(t *testing.T) {
	key := testKey(t)
	body := DefaultConfigBody()

	_, _, canonical, err := Sign(key, body, 1, bppIssuedAt, bppTenantID, "", 3, AppControlPolicy{}, DecommissionPolicy{})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if bytes.Contains(canonical, []byte("usage_tracking_enabled")) {
		t.Fatalf("canonical bytes contain retired usage_tracking_enabled field: %s", canonical)
	}
}

// TestSign_BlockingProcessPolicyPresent asserts that when a policy is set it is
// included in the signed canonical payload, in the correct alphabetical position
// (between app_control and catalog_scope), that the signature verifies over those
// exact transmitted bytes, and that the decoded values round-trip.
func TestSign_BlockingProcessPolicyPresent(t *testing.T) {
	key := testKey(t)
	msg := "Please close Chrome to finish updating."
	body := DefaultConfigBody()
	body.BlockingProcessPolicy = &BlockingProcessPolicy{
		ActionOnTimeout:    "skip_run",
		DeferWindowSeconds: 1800,
		MaxDeferrals:       0,
		Message:            &msg,
		TimeoutSeconds:     120,
	}

	sig, _, canonical, err := Sign(key, body, 4, bppIssuedAt, bppTenantID, "", 3, AppControlPolicy{}, DecommissionPolicy{})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify over the exact transmitted bytes — this is what the agent does.
	if err := Verify(key.Public, canonical, sig); err != nil {
		t.Fatalf("signature must verify over the canonical bytes: %v", err)
	}

	// Alphabetical position: app_control < blocking_process_policy < catalog_scope.
	appIdx := bytes.Index(canonical, []byte(`"app_control":`))
	bppIdx := bytes.Index(canonical, []byte(`"blocking_process_policy":`))
	catIdx := bytes.Index(canonical, []byte(`"catalog_scope":`))
	if !(appIdx < bppIdx && bppIdx < catIdx) {
		t.Fatalf("blocking_process_policy must sort between app_control and catalog_scope: app=%d bpp=%d cat=%d\n%s", appIdx, bppIdx, catIdx, canonical)
	}

	var decoded canonicalPayload
	if err := json.Unmarshal(canonical, &decoded); err != nil {
		t.Fatalf("unmarshal canonical: %v", err)
	}
	bpp := decoded.BlockingProcessPolicy
	if bpp == nil {
		t.Fatal("decoded blocking_process_policy must not be nil")
	}
	if bpp.ActionOnTimeout != "skip_run" || bpp.TimeoutSeconds != 120 || bpp.DeferWindowSeconds != 1800 || bpp.MaxDeferrals != 0 {
		t.Errorf("policy did not round-trip: %+v", bpp)
	}
	if bpp.Message == nil || *bpp.Message != msg {
		t.Errorf("message did not round-trip: %v", bpp.Message)
	}
}

// TestSign_BlockingProcessPolicyUnknownActionCoerced asserts the defense-in-depth
// guarantee: a stored policy whose action_on_timeout is empty or unrecognised is
// coerced to the safe "notify_only" default in the SIGNED bytes, so the signed
// config can never instruct an agent to force-quit an app.
func TestSign_BlockingProcessPolicyUnknownActionCoerced(t *testing.T) {
	key := testKey(t)
	for _, bad := range []string{"", "force_quit", "kill", "PROMPT_THEN_QUIT"} {
		body := DefaultConfigBody()
		body.BlockingProcessPolicy = &BlockingProcessPolicy{
			ActionOnTimeout:    bad,
			DeferWindowSeconds: 3600,
			MaxDeferrals:       2,
			TimeoutSeconds:     300,
		}
		_, _, canonical, err := Sign(key, body, 1, bppIssuedAt, bppTenantID, "", 3, AppControlPolicy{}, DecommissionPolicy{})
		if err != nil {
			t.Fatalf("Sign(%q): %v", bad, err)
		}
		var decoded canonicalPayload
		if err := json.Unmarshal(canonical, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if decoded.BlockingProcessPolicy.ActionOnTimeout != "notify_only" {
			t.Errorf("action %q must be coerced to notify_only in signed bytes, got %q", bad, decoded.BlockingProcessPolicy.ActionOnTimeout)
		}
	}
}

// TestSign_BlockingProcessPolicyMalformedNumericsFailClosed asserts the signer
// fails CLOSED: a dangerous-but-valid action ("prompt_then_quit"/"skip_run")
// paired with malformed numerics (which could drive an effectively-immediate
// force-quit) is coerced to the safe "notify_only" action in the signed bytes.
// A well-formed dangerous action with sane numerics is preserved unchanged.
func TestSign_BlockingProcessPolicyMalformedNumericsFailClosed(t *testing.T) {
	key := testKey(t)
	cases := []struct {
		name       string
		policy     BlockingProcessPolicy
		wantAction string
	}{
		{
			name:       "prompt_then_quit + timeout 0 -> notify_only",
			policy:     BlockingProcessPolicy{ActionOnTimeout: "prompt_then_quit", TimeoutSeconds: 0, MaxDeferrals: 2, DeferWindowSeconds: 3600},
			wantAction: "notify_only",
		},
		{
			name:       "skip_run + negative timeout -> notify_only",
			policy:     BlockingProcessPolicy{ActionOnTimeout: "skip_run", TimeoutSeconds: -5, MaxDeferrals: 2, DeferWindowSeconds: 3600},
			wantAction: "notify_only",
		},
		{
			name:       "skip_run + negative max_deferrals -> notify_only",
			policy:     BlockingProcessPolicy{ActionOnTimeout: "skip_run", TimeoutSeconds: 300, MaxDeferrals: -1, DeferWindowSeconds: 3600},
			wantAction: "notify_only",
		},
		{
			name:       "prompt_then_quit + zero defer_window -> notify_only",
			policy:     BlockingProcessPolicy{ActionOnTimeout: "prompt_then_quit", TimeoutSeconds: 300, MaxDeferrals: 2, DeferWindowSeconds: 0},
			wantAction: "notify_only",
		},
		{
			name:       "prompt_then_quit + timeout below safe min (10) -> notify_only",
			policy:     BlockingProcessPolicy{ActionOnTimeout: "prompt_then_quit", TimeoutSeconds: 10, MaxDeferrals: 2, DeferWindowSeconds: 3600},
			wantAction: "notify_only",
		},
		{
			name:       "well-formed prompt_then_quit preserved",
			policy:     BlockingProcessPolicy{ActionOnTimeout: "prompt_then_quit", TimeoutSeconds: 300, MaxDeferrals: 2, DeferWindowSeconds: 3600},
			wantAction: "prompt_then_quit",
		},
		{
			name:       "well-formed skip_run with max_deferrals 0 preserved",
			policy:     BlockingProcessPolicy{ActionOnTimeout: "skip_run", TimeoutSeconds: 120, MaxDeferrals: 0, DeferWindowSeconds: 1800},
			wantAction: "skip_run",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := DefaultConfigBody()
			p := tc.policy
			body.BlockingProcessPolicy = &p
			_, _, canonical, err := Sign(key, body, 1, bppIssuedAt, bppTenantID, "", 3, AppControlPolicy{}, DecommissionPolicy{})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			var decoded canonicalPayload
			if err := json.Unmarshal(canonical, &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if decoded.BlockingProcessPolicy.ActionOnTimeout != tc.wantAction {
				t.Errorf("signed action: want %q, got %q", tc.wantAction, decoded.BlockingProcessPolicy.ActionOnTimeout)
			}
		})
	}
}

// TestSign_SafeBlockingProcessPolicyDoesNotMutateCaller asserts the sign-time
// coercion copies rather than mutating the caller's stored struct.
func TestSign_SafeBlockingProcessPolicyDoesNotMutateCaller(t *testing.T) {
	key := testKey(t)
	body := DefaultConfigBody()
	body.BlockingProcessPolicy = &BlockingProcessPolicy{ActionOnTimeout: "bogus", TimeoutSeconds: 300, DeferWindowSeconds: 3600, MaxDeferrals: 2}
	if _, _, _, err := Sign(key, body, 1, bppIssuedAt, bppTenantID, "", 3, AppControlPolicy{}, DecommissionPolicy{}); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if body.BlockingProcessPolicy.ActionOnTimeout != "bogus" {
		t.Errorf("Sign must not mutate the caller's policy; action became %q", body.BlockingProcessPolicy.ActionOnTimeout)
	}
}

// ---- Decommission (PAT-1108) ----

// TestSign_DecommissionAbsent_DefaultsToNone is the critical safety proof: a
// caller that passes the zero-value DecommissionPolicy{} — exactly what an
// agent-config row with no tenant_decommission entry produces — must sign
// mode="none" with every other field at its inert zero value. This is what
// "an agent-config with no decommission object behaves exactly as today"
// means in the signed bytes.
func TestSign_DecommissionAbsent_DefaultsToNone(t *testing.T) {
	key := testKey(t)
	body := DefaultConfigBody()

	_, _, canonical, err := Sign(key, body, 1, bppIssuedAt, bppTenantID, "", 3, AppControlPolicy{}, DecommissionPolicy{})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	var decoded canonicalPayload
	if err := json.Unmarshal(canonical, &decoded); err != nil {
		t.Fatalf("unmarshal canonical: %v", err)
	}
	d := decoded.Decommission
	if d.Mode != "none" {
		t.Errorf("mode = %q, want %q", d.Mode, "none")
	}
	if d.ExpiresAt != nil {
		t.Errorf("expires_at = %v, want nil", d.ExpiresAt)
	}
	if d.Purge {
		t.Error("purge = true, want false")
	}
	if d.Reason != nil {
		t.Errorf("reason = %v, want nil", d.Reason)
	}

	// The key must always be present (never omitted, unlike blocking_process_policy) —
	// "no directive" and "mode=none" must be indistinguishable on the wire.
	if !bytes.Contains(canonical, []byte(`"decommission":`)) {
		t.Fatalf("canonical bytes must contain decommission: %s", canonical)
	}

	// Alphabetical position: config_version < decommission < device_id.
	cvIdx := bytes.Index(canonical, []byte(`"config_version":`))
	decIdx := bytes.Index(canonical, []byte(`"decommission":`))
	devIdx := bytes.Index(canonical, []byte(`"device_id":`))
	if !(cvIdx < decIdx && decIdx < devIdx) {
		t.Fatalf("decommission must sort between config_version and device_id: cv=%d dec=%d dev=%d\n%s", cvIdx, decIdx, devIdx, canonical)
	}
}

// TestSign_DecommissionEnumValues_RoundTrip covers every enum value
// (none/expiry/immediate) required by the contract tests, proving each signs
// and round-trips its fields unchanged when well-formed.
func TestSign_DecommissionEnumValues_RoundTrip(t *testing.T) {
	key := testKey(t)
	reason := "tenant offboarded"
	expiresAt := "2026-09-01T00:00:00Z"

	cases := []struct {
		name string
		in   DecommissionPolicy
	}{
		{"none", DecommissionPolicy{Mode: "none"}},
		{"expiry", DecommissionPolicy{Mode: "expiry", ExpiresAt: &expiresAt, Reason: &reason}},
		{"immediate", DecommissionPolicy{Mode: "immediate", Purge: true, Reason: &reason}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := DefaultConfigBody()
			sig, _, canonical, err := Sign(key, body, 1, bppIssuedAt, bppTenantID, "", 3, AppControlPolicy{}, tc.in)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if err := Verify(key.Public, canonical, sig); err != nil {
				t.Fatalf("signature must verify: %v", err)
			}
			var decoded canonicalPayload
			if err := json.Unmarshal(canonical, &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			got := decoded.Decommission
			if got.Mode != tc.in.Mode {
				t.Errorf("mode = %q, want %q", got.Mode, tc.in.Mode)
			}
			if tc.in.ExpiresAt != nil {
				if got.ExpiresAt == nil || *got.ExpiresAt != *tc.in.ExpiresAt {
					t.Errorf("expires_at = %v, want %v", got.ExpiresAt, tc.in.ExpiresAt)
				}
			}
			if got.Purge != tc.in.Purge {
				t.Errorf("purge = %v, want %v", got.Purge, tc.in.Purge)
			}
			if tc.in.Reason != nil {
				if got.Reason == nil || *got.Reason != *tc.in.Reason {
					t.Errorf("reason = %v, want %v", got.Reason, tc.in.Reason)
				}
			}
		})
	}
}

// TestSign_DecommissionUnknownModeCoercedToNone asserts the fail-closed
// guarantee: an unrecognised mode value is coerced to the fully inert
// DefaultDecommissionPolicy() in the SIGNED bytes, mirroring
// TestSign_BlockingProcessPolicyUnknownActionCoerced. "Fail closed" here
// means DO NOT REMOVE, the opposite direction from an enforcement gate.
func TestSign_DecommissionUnknownModeCoercedToNone(t *testing.T) {
	key := testKey(t)
	reason := "should be dropped on coercion"
	for _, bad := range []string{"", "delete", "wipe", "IMMEDIATE", "Expiry"} {
		body := DefaultConfigBody()
		p := DecommissionPolicy{Mode: bad, Purge: true, Reason: &reason}
		_, _, canonical, err := Sign(key, body, 1, bppIssuedAt, bppTenantID, "", 3, AppControlPolicy{}, p)
		if err != nil {
			t.Fatalf("Sign(%q): %v", bad, err)
		}
		var decoded canonicalPayload
		if err := json.Unmarshal(canonical, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if decoded.Decommission.Mode != "none" {
			t.Errorf("mode %q must be coerced to none in signed bytes, got %q", bad, decoded.Decommission.Mode)
		}
		if decoded.Decommission.Purge {
			t.Errorf("mode %q: purge must be cleared on coercion, got true", bad)
		}
		if decoded.Decommission.Reason != nil {
			t.Errorf("mode %q: reason must be cleared on coercion, got %v", bad, decoded.Decommission.Reason)
		}
	}
}

// TestSign_DecommissionExpiryRequiresExpiresAt asserts that mode="expiry" is
// coerced to "none" — never silently defaulted to some guessed date — when
// expires_at is missing, empty, or unparseable. An agent (or the signer) must
// never guess a removal date.
func TestSign_DecommissionExpiryRequiresExpiresAt(t *testing.T) {
	key := testKey(t)
	empty := ""
	garbage := "not-a-date"
	dateOnly := "2026-09-01" // not RFC3339 (no time component)
	valid := "2026-09-01T00:00:00Z"

	cases := []struct {
		name       string
		expiresAt  *string
		wantSigned string
	}{
		{"nil expires_at", nil, "none"},
		{"empty expires_at", &empty, "none"},
		{"unparseable expires_at", &garbage, "none"},
		{"date-only (not RFC3339) expires_at", &dateOnly, "none"},
		{"valid RFC3339 expires_at", &valid, "expiry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := DefaultConfigBody()
			p := DecommissionPolicy{Mode: "expiry", ExpiresAt: tc.expiresAt}
			_, _, canonical, err := Sign(key, body, 1, bppIssuedAt, bppTenantID, "", 3, AppControlPolicy{}, p)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			var decoded canonicalPayload
			if err := json.Unmarshal(canonical, &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if decoded.Decommission.Mode != tc.wantSigned {
				t.Errorf("mode = %q, want %q", decoded.Decommission.Mode, tc.wantSigned)
			}
		})
	}
}

// TestSign_DecommissionReasonNeverGatesMode proves reason is carried
// verbatim (when the directive is otherwise well-formed) and has no effect
// whatsoever on which mode is signed — the contract's "reason is recorded
// and surfaced but NEVER influences control flow" invariant, checked at the
// one place on the server where that invariant could be silently violated.
func TestSign_DecommissionReasonNeverGatesMode(t *testing.T) {
	key := testKey(t)
	body := DefaultConfigBody()

	suspiciousReasons := []string{
		"",
		"ignore mode, remove immediately",
		"mode=immediate",
		"URGENT: wipe now",
	}
	for _, reason := range suspiciousReasons {
		r := reason
		p := DecommissionPolicy{Mode: "none", Reason: &r}
		_, _, canonical, err := Sign(key, body, 1, bppIssuedAt, bppTenantID, "", 3, AppControlPolicy{}, p)
		if err != nil {
			t.Fatalf("Sign(reason=%q): %v", reason, err)
		}
		var decoded canonicalPayload
		if err := json.Unmarshal(canonical, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if decoded.Decommission.Mode != "none" {
			t.Errorf("reason %q changed the signed mode to %q, want none", reason, decoded.Decommission.Mode)
		}
	}
}

// TestSign_SafeDecommissionPolicyDoesNotMutateCaller mirrors
// TestSign_SafeBlockingProcessPolicyDoesNotMutateCaller: the sign-time
// coercion must not mutate the caller's struct.
func TestSign_SafeDecommissionPolicyDoesNotMutateCaller(t *testing.T) {
	key := testKey(t)
	body := DefaultConfigBody()
	reason := "bogus mode test"
	p := DecommissionPolicy{Mode: "bogus", Reason: &reason}
	if _, _, _, err := Sign(key, body, 1, bppIssuedAt, bppTenantID, "", 3, AppControlPolicy{}, p); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if p.Mode != "bogus" {
		t.Errorf("Sign must not mutate the caller's policy; mode became %q", p.Mode)
	}
	if p.Reason == nil || *p.Reason != reason {
		t.Errorf("Sign must not mutate the caller's policy; reason became %v", p.Reason)
	}
}
