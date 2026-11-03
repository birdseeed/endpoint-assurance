package notifications

import (
	"errors"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/webhook"
)

// TestIdempotencyKeyIsDeterministicAndDistinct pins the property the unique
// index depends on: the same (channel, event, subject) always produces the same
// key, and changing any one component produces a different one. If this stopped
// holding, either a replay would send twice or two different events would
// collide and one would be silently dropped.
func TestIdempotencyKeyIsDeterministicAndDistinct(t *testing.T) {
	const channel = "11111111-1111-1111-1111-111111111111"
	const other = "22222222-2222-2222-2222-222222222222"
	subject := "cis/device-1/audit_pam_su@2026-09-20T10:00:00Z"

	base := IdempotencyKey(channel, webhook.EventFindingOpened, subject)
	if base != IdempotencyKey(channel, webhook.EventFindingOpened, subject) {
		t.Fatal("identical inputs produced different keys")
	}
	if len(base) != 64 {
		t.Fatalf("key should be a 64-char sha256 hex string, got %d chars", len(base))
	}

	distinct := map[string]string{
		"different channel": IdempotencyKey(other, webhook.EventFindingOpened, subject),
		"different event":   IdempotencyKey(channel, webhook.EventVerificationPassed, subject),
		"different subject": IdempotencyKey(channel, webhook.EventFindingOpened, subject+"x"),
	}
	for name, key := range distinct {
		if key == base {
			t.Errorf("%s produced the same key as the base triple", name)
		}
	}

	// The separator must not be forgeable: moving a boundary between components
	// has to change the key, or two different triples could collide.
	a := IdempotencyKey("ab", webhook.EventFindingOpened, "c")
	b := IdempotencyKey("a", webhook.EventFindingOpened, "bc")
	if a == b {
		t.Error("component boundary is forgeable: ab|c collided with a|bc")
	}
}

// TestMeetsThreshold covers the severity filter, including the deliberate
// choice that an ungraded event is delivered rather than suppressed.
func TestMeetsThreshold(t *testing.T) {
	tests := []struct {
		name      string
		event     string
		threshold string
		want      bool
	}{
		{"equal passes", SeverityHigh, SeverityHigh, true},
		{"above passes", SeverityCritical, SeverityHigh, true},
		{"below suppressed", SeverityLow, SeverityHigh, false},
		{"medium below high", SeverityMedium, SeverityHigh, false},
		{"everything clears low", SeverityLow, SeverityLow, true},
		{"case insensitive", "CRITICAL", "High", true},
		{"whitespace tolerated", "  high  ", "medium", true},
		{"ungraded event delivered", "", SeverityCritical, true},
		{"unknown grade delivered", "catastrophic", SeverityCritical, true},
		{"unknown threshold does not suppress", SeverityLow, "spicy", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MeetsThreshold(tt.event, tt.threshold); got != tt.want {
				t.Errorf("MeetsThreshold(%q, %q) = %v, want %v", tt.event, tt.threshold, got, tt.want)
			}
		})
	}
}

// TestRedactErrorRemovesSecretsAndBounds proves a stored delivery error cannot
// carry a credential or grow without limit.
func TestRedactErrorRemovesSecretsAndBounds(t *testing.T) {
	tests := []struct {
		name       string
		in         error
		mustNot    string
		mustHave   string
		exactEmpty bool
	}{
		{
			name:     "query string removed",
			in:       errors.New(`Post "https://hooks.example.com/x?token=placeholdervalue": dial error`),
			mustNot:  "placeholdervalue",
			mustHave: "[redacted]",
		},
		{
			name:     "bearer token removed",
			in:       errors.New("auth failed with Bearer eyJhbGciOiJIUzI1NiJ9"),
			mustNot:  "eyJhbGciOiJIUzI1NiJ9",
			mustHave: "[redacted]",
		},
		{
			name:     "client secret removed",
			in:       errors.New("token request rejected: client_secret=Q~supersecret"),
			mustNot:  "supersecret",
			mustHave: "[redacted]",
		},
		{
			name:       "nil error yields nothing",
			in:         nil,
			exactEmpty: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactError(tt.in)
			if tt.exactEmpty {
				if got != "" {
					t.Fatalf("expected empty string, got %q", got)
				}
				return
			}
			if strings.Contains(got, tt.mustNot) {
				t.Errorf("redacted error still contains %q: %q", tt.mustNot, got)
			}
			if !strings.Contains(got, tt.mustHave) {
				t.Errorf("redacted error is missing %q: %q", tt.mustHave, got)
			}
		})
	}

	long := errors.New(strings.Repeat("e", maxStoredErrorLen*3))
	got := redactError(long)
	if len(got) > maxStoredErrorLen+3 {
		t.Errorf("redacted error was not truncated: %d chars", len(got))
	}

	multiline := redactError(errors.New("line one\nline two\rline three"))
	if strings.ContainsAny(multiline, "\n\r") {
		t.Errorf("redacted error kept newlines: %q", multiline)
	}
}

// TestChannelSpecRejectsSSRFDestinations is the configuration-time half of the
// SSRF defence. The authoritative half runs at dial time and is tested in
// internal/webhook; this one proves an obviously internal address cannot even
// be stored.
func TestChannelSpecRejectsSSRFDestinations(t *testing.T) {
	blocked := []struct {
		name string
		url  string
	}{
		{"loopback v4", "https://127.0.0.1/hook"},
		{"loopback v4 alternate", "https://127.1.2.3/hook"},
		{"loopback v6", "https://[::1]/hook"},
		{"unspecified v4", "https://0.0.0.0/hook"},
		{"unspecified v6", "https://[::]/hook"},
		{"rfc1918 ten", "https://10.0.0.5/hook"},
		{"rfc1918 172", "https://172.16.4.1/hook"},
		{"rfc1918 192", "https://192.168.1.1/hook"},
		{"cloud metadata", "https://169.254.169.254/latest/meta-data"},
		{"link local v6", "https://[fe80::1]/hook"},
		{"unique local v6", "https://[fd00::1]/hook"},
		{"cgnat tailscale low", "https://100.64.0.1/hook"},
		{"cgnat tailscale high", "https://100.127.255.254/hook"},
		{"ipv4 mapped loopback", "https://[::ffff:127.0.0.1]/hook"},
		{"multicast", "https://239.1.2.3/hook"},
		{"plain http", "http://example.com/hook"},
		{"no scheme", "example.com/hook"},
		{"no host", "https:///hook"},
		{"empty", ""},
	}
	for _, tt := range blocked {
		t.Run(tt.name, func(t *testing.T) {
			spec := ChannelSpec{
				Type:   ChannelWebhook,
				Name:   "test",
				Events: []string{string(webhook.EventFindingOpened)},
				URL:    tt.url,
			}
			err := spec.Validate()
			if err == nil {
				t.Fatalf("destination %q was accepted", tt.url)
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Errorf("expected a ValidationError so the caller gets 400, got %T", err)
			}
		})
	}

	allowed := ChannelSpec{
		Type:   ChannelWebhook,
		Name:   "test",
		Events: []string{string(webhook.EventFindingOpened)},
		URL:    "https://hooks.example.com/patched",
	}
	if err := allowed.Validate(); err != nil {
		t.Fatalf("a public https destination should be accepted: %v", err)
	}
}

// TestChannelSpecValidation covers the rest of the configuration contract.
func TestChannelSpecValidation(t *testing.T) {
	validEvents := []string{string(webhook.EventFindingOpened)}

	tests := []struct {
		name    string
		spec    ChannelSpec
		wantErr string
	}{
		{
			name:    "unknown channel type",
			spec:    ChannelSpec{Type: "carrier-pigeon", Name: "n", Events: validEvents},
			wantErr: "channel_type must be",
		},
		{
			name:    "name required",
			spec:    ChannelSpec{Type: ChannelEmail, Name: "   ", Events: validEvents, Recipients: []string{"a@example.com"}},
			wantErr: "name is required",
		},
		{
			name:    "events required",
			spec:    ChannelSpec{Type: ChannelEmail, Name: "n", Recipients: []string{"a@example.com"}},
			wantErr: "events must not be empty",
		},
		{
			name:    "unknown event",
			spec:    ChannelSpec{Type: ChannelEmail, Name: "n", Events: []string{"finding.invented"}, Recipients: []string{"a@example.com"}},
			wantErr: "unknown event type",
		},
		{
			name: "test.ping is not subscribable",
			spec: ChannelSpec{Type: ChannelEmail, Name: "n", Events: []string{string(webhook.EventTestPing)},
				Recipients: []string{"a@example.com"}},
			wantErr: "unknown event type",
		},
		{
			name: "legacy score.changed is not a channel event",
			spec: ChannelSpec{Type: ChannelEmail, Name: "n", Events: []string{string(webhook.EventScoreChanged)},
				Recipients: []string{"a@example.com"}},
			wantErr: "unknown event type",
		},
		{
			name: "duplicate event",
			spec: ChannelSpec{Type: ChannelEmail, Name: "n", Events: []string{validEvents[0], validEvents[0]},
				Recipients: []string{"a@example.com"}},
			wantErr: "listed twice",
		},
		{
			name: "bad severity",
			spec: ChannelSpec{Type: ChannelEmail, Name: "n", Events: validEvents, MinSeverity: "urgent",
				Recipients: []string{"a@example.com"}},
			wantErr: "min_severity must be",
		},
		{
			name:    "email needs recipients",
			spec:    ChannelSpec{Type: ChannelEmail, Name: "n", Events: validEvents},
			wantErr: "at least one recipient",
		},
		{
			name: "email rejects a destination url",
			spec: ChannelSpec{Type: ChannelEmail, Name: "n", Events: validEvents,
				Recipients: []string{"a@example.com"}, URL: "https://example.com/x"},
			wantErr: "destination_url is not valid",
		},
		{
			name: "email rejects a malformed address",
			spec: ChannelSpec{Type: ChannelEmail, Name: "n", Events: validEvents,
				Recipients: []string{"not-an-address"}},
			wantErr: "not a valid email address",
		},
		{
			name: "email rejects a duplicate address",
			spec: ChannelSpec{Type: ChannelEmail, Name: "n", Events: validEvents,
				Recipients: []string{"a@example.com", "A@Example.com"}},
			wantErr: "listed twice",
		},
		{
			name: "webhook rejects recipients",
			spec: ChannelSpec{Type: ChannelWebhook, Name: "n", Events: validEvents,
				URL: "https://example.com/x", Recipients: []string{"a@example.com"}},
			wantErr: "recipients are not valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.Validate()
			if err == nil {
				t.Fatalf("expected an error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}

	// min_severity defaults rather than failing when left out.
	spec := ChannelSpec{Type: ChannelEmail, Name: "n", Events: validEvents, Recipients: []string{"a@example.com"}}
	if err := spec.Validate(); err != nil {
		t.Fatalf("valid email spec rejected: %v", err)
	}
	if spec.MinSeverity != SeverityLow {
		t.Errorf("min_severity should default to low, got %q", spec.MinSeverity)
	}
}

// TestEventForLifecycleMapping pins which lifecycle transitions are notifiable.
// The negative cases matter as much as the positive ones: currently_observed is
// the daily restatement of an already-notified failure, and the operator-action
// events are the customer's own actions coming back at them.
func TestEventForLifecycleMapping(t *testing.T) {
	notifiable := map[string]webhook.EventKind{
		"first_observed":       webhook.EventFindingOpened,
		"recurred":             webhook.EventFindingRecurred,
		"verification_unknown": webhook.EventEvidenceStale,
		"verified_fixed":       webhook.EventVerificationPassed,
		"still_failing":        webhook.EventVerificationFailed,
	}
	for lifecycleType, want := range notifiable {
		got, ok := EventForLifecycle(lifecycleType)
		if !ok {
			t.Errorf("%s should be notifiable", lifecycleType)
			continue
		}
		if got != want {
			t.Errorf("%s mapped to %s, want %s", lifecycleType, got, want)
		}
	}

	silent := []string{
		"currently_observed", "acknowledged", "risk_accepted",
		"guidance_issued", "customer_applied", "pending_verification", "", "nonsense",
		// PAT-2107: a matcher correction is not a customer-facing transition.
		// In particular it is never verification.passed.
		"withdrawn",
	}
	for _, lifecycleType := range silent {
		if _, ok := EventForLifecycle(lifecycleType); ok {
			t.Errorf("%q should not raise a notification", lifecycleType)
		}
	}
}

// TestSubjectDiscriminatesByEvidenceTime proves two genuine transitions of the
// same kind on the same finding do not collide, while a replay of the same one
// does. This is what stops a second recurrence being swallowed as a duplicate.
func TestSubjectDiscriminatesByEvidenceTime(t *testing.T) {
	device := "device-1"
	first := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	second := first.Add(48 * time.Hour)

	a := Subject("cis", &device, "audit_pam_su", first)
	replay := Subject("cis", &device, "audit_pam_su", first)
	later := Subject("cis", &device, "audit_pam_su", second)

	if a != replay {
		t.Error("the same transition produced two subjects, so a replay would send twice")
	}
	if a == later {
		t.Error("a later transition collided with the earlier one, so it would be dropped")
	}

	// A tenant-scoped CVE finding has no device.
	cve := Subject("cve", nil, "CVE-2026-0001", first)
	if !strings.HasPrefix(cve, "cve/-/CVE-2026-0001@") {
		t.Errorf("unexpected device-less subject shape: %q", cve)
	}

	// A different device is a different finding.
	otherDevice := "device-2"
	if Subject("cis", &otherDevice, "audit_pam_su", first) == a {
		t.Error("two devices produced the same subject")
	}
}

// TestClampPageSizeIsBounded proves no caller can ask for an unbounded listing.
func TestClampPageSizeIsBounded(t *testing.T) {
	if got := ClampPageSize(0); got != DefaultDeliveryPageSize {
		t.Errorf("unspecified limit should default to %d, got %d", DefaultDeliveryPageSize, got)
	}
	if got := ClampPageSize(-5); got != DefaultDeliveryPageSize {
		t.Errorf("negative limit should default to %d, got %d", DefaultDeliveryPageSize, got)
	}
	if got := ClampPageSize(1_000_000); got != MaxDeliveryPageSize {
		t.Errorf("huge limit should clamp to %d, got %d", MaxDeliveryPageSize, got)
	}
	if got := ClampPageSize(10); got != 10 {
		t.Errorf("a reasonable limit should pass through, got %d", got)
	}
}

// TestValidDeliveryState keeps the listing filter aligned with the CHECK
// constraint in migration 0157.
func TestValidDeliveryState(t *testing.T) {
	for _, s := range []string{"", StatePending, StateDelivered, StateDeadLetter} {
		if !ValidDeliveryState(s) {
			t.Errorf("%q should be a valid filter", s)
		}
	}
	for _, s := range []string{"failed", "queued", "DELIVERED", "dead-letter"} {
		if ValidDeliveryState(s) {
			t.Errorf("%q should not be a valid filter", s)
		}
	}
}

// TestHighestSeverityRanksRatherThanSorts is the guard for the bug this helper
// exists to prevent. Severity is stored as text in several tables, and sorted
// alphabetically "critical" comes before "low", so a SQL max() or a string
// comparison grades a critical finding as the lowest one present. Every case
// here mixes ranks whose correct answer differs from the alphabetical one.
func TestHighestSeverityRanksRatherThanSorts(t *testing.T) {
	tests := []struct {
		name       string
		candidates []string
		want       string
	}{
		{"critical beats low", []string{"CRITICAL", "LOW"}, SeverityCritical},
		{"order does not matter", []string{"LOW", "CRITICAL"}, SeverityCritical},
		{"high beats medium", []string{"HIGH", "MEDIUM"}, SeverityHigh},
		{"medium beats low", []string{"LOW", "MEDIUM"}, SeverityMedium},
		{"all four", []string{"low", "medium", "high", "critical"}, SeverityCritical},
		{"feed NONE never wins", []string{"NONE", "LOW"}, SeverityLow},
		{"NONE alone grades nothing", []string{"NONE"}, ""},
		{"unknown never wins", []string{"catastrophic", "medium"}, SeverityMedium},
		{"only unknown grades nothing", []string{"catastrophic", "spicy"}, ""},
		{"case and whitespace tolerated", []string{"  cRiTiCaL  "}, SeverityCritical},
		{"empty string ignored", []string{"", "high"}, SeverityHigh},
		{"no candidates", nil, ""},
		{"empty slice", []string{}, ""},
		{"duplicates are harmless", []string{"high", "high", "low"}, SeverityHigh},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HighestSeverity(tt.candidates); got != tt.want {
				t.Errorf("HighestSeverity(%v) = %q, want %q", tt.candidates, got, tt.want)
			}
		})
	}

	// The result must always be usable by the threshold filter, which is the
	// only reason this function exists.
	for _, candidates := range [][]string{{"CRITICAL", "LOW"}, {"HIGH"}, {"medium", "NONE"}} {
		got := HighestSeverity(candidates)
		if !ValidSeverity(got) {
			t.Errorf("HighestSeverity(%v) returned %q, which MeetsThreshold cannot grade", candidates, got)
		}
	}

	// A lexical maximum would pick "low" from this set. Pin the difference
	// explicitly so the two can never be confused again.
	lexicalMax := ""
	for _, c := range []string{"critical", "low"} {
		if c > lexicalMax {
			lexicalMax = c
		}
	}
	if HighestSeverity([]string{"critical", "low"}) == lexicalMax {
		t.Error("HighestSeverity agreed with the lexical maximum, so it is sorting rather than ranking")
	}
}
