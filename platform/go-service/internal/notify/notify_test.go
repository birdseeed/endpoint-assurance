package notify

// Tests for the KindAppLaunchRestricted notification path (PAT-820).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBuildAppLaunchRestrictedMessageIncludesRequiredFields(t *testing.T) {
	hosts := 4
	e := Event{
		TenantID:     "tenant-123",
		Kind:         KindAppLaunchRestricted,
		Label:        "Zoom",
		Platform:     "macos",
		Actor:        "andy@patched.im",
		SourceAction: "allowlist_update",
		HostCount:    &hosts,
		Link:         "https://dashboard.patched.im/tenants/tenant-123/catalogue",
		Timestamp:    time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC),
	}
	msg := buildSlackMessage(e)

	for _, want := range []string{
		"tenant-123",
		"Zoom",
		"macos",
		"andy@patched.im",
		"allowlist_update",
		"4",
		"https://dashboard.patched.im/tenants/tenant-123/catalogue",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q: %s", want, msg)
		}
	}
}

func TestBuildAppLaunchRestrictedMessageUnknownFields(t *testing.T) {
	e := Event{
		TenantID:     "tenant-123",
		Kind:         KindAppLaunchRestricted,
		Label:        "Zoom",
		SourceAction: "app_policy_unapproved",
	}
	msg := buildSlackMessage(e)
	if !strings.Contains(msg, "Actor: unknown") {
		t.Errorf("expected unknown actor placeholder, got: %s", msg)
	}
	if !strings.Contains(msg, "Hosts affected: unknown") {
		t.Errorf("expected unknown host count placeholder, got: %s", msg)
	}
	if !strings.Contains(msg, "Platform: unknown") {
		t.Errorf("expected unknown platform placeholder, got: %s", msg)
	}
	if strings.Contains(msg, "Software Catalogue:") {
		t.Errorf("expected no catalogue link line when Link is empty, got: %s", msg)
	}
}

// TestSendSlackSuccess verifies a 2xx response is treated as delivered.
func TestSendSlackSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := &Notifier{slackURL: srv.URL}
	if err := n.sendSlack(Event{Kind: KindAppLaunchRestricted, TenantID: "t1", Label: "App"}); err != nil {
		t.Fatalf("sendSlack: unexpected error: %v", err)
	}
}

// TestSendSlackDeliveryFailureIsReturnedNotPanicked verifies a failing Slack
// webhook returns an error (which Dispatch logs) rather than panicking or
// blocking — the acceptance criterion is that delivery failure never fails
// the caller's persist action, which Dispatch's fire-and-forget goroutine
// already guarantees.
func TestSendSlackDeliveryFailureIsReturnedNotPanicked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	n := &Notifier{slackURL: srv.URL}
	err := n.sendSlack(Event{Kind: KindAppLaunchRestricted, TenantID: "t1", Label: "App"})
	if err == nil {
		t.Fatal("expected an error for a 500 response, got nil")
	}
}

// TestDispatchMissingSlackConfigDoesNotCallOut verifies that Dispatch never
// attempts an HTTP call when NOTIFY_SLACK_WEBHOOK_URL (slackURL) is unset —
// i.e. missing Slack config is a silent no-op, not an error.
func TestDispatchMissingSlackConfigDoesNotCallOut(t *testing.T) {
	var called int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&called, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Notifier with slackURL intentionally left empty — mirrors New() when
	// NOTIFY_SLACK_WEBHOOK_URL is unset.
	n := &Notifier{}
	n.Dispatch(context.Background(), Event{Kind: KindAppLaunchRestricted, TenantID: "t1", Label: "App"})

	// Dispatch is fire-and-forget; give any (unwanted) goroutine a moment to
	// run before asserting it never reached the test server.
	time.Sleep(50 * time.Millisecond)
	if atomic.LoadInt32(&called) != 0 {
		t.Fatal("expected no HTTP call with missing Slack config, but one was made")
	}
}

func TestCatalogueLinkDefaultAndOverride(t *testing.T) {
	if got, want := CatalogueLink("tenant-abc"), "https://dashboard.patched.im/tenants/tenant-abc/catalogue"; got != want {
		t.Errorf("default link: got %q, want %q", got, want)
	}

	t.Setenv("DASHBOARD_BASE_URL", "https://dash.example.com/")
	if got, want := CatalogueLink("tenant-abc"), "https://dash.example.com/tenants/tenant-abc/catalogue"; got != want {
		t.Errorf("overridden link: got %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// KindNewAppDetected (PAT-819)
// ---------------------------------------------------------------------------

func TestBuildNewAppDetectedMessageIncludesRequiredFields(t *testing.T) {
	hosts := 3
	e := Event{
		TenantID:           "tenant-456",
		Kind:               KindNewAppDetected,
		Label:              "Notion",
		Platform:           "macos",
		PublisherSignature: "EQHXZ8M8AV",
		SuggestedAction:    "defer",
		HostCount:          &hosts,
		FirstSeen:          time.Date(2026, 7, 10, 9, 30, 0, 0, time.UTC),
		Link:               "https://dashboard.patched.im/tenants/tenant-456/catalogue?status=new",
	}
	msg := buildSlackMessage(e)

	for _, want := range []string{
		"tenant-456",
		"Notion",
		"macos",
		"EQHXZ8M8AV",
		"defer",
		"3",
		"2026-07-10T09:30:00Z",
		"https://dashboard.patched.im/tenants/tenant-456/catalogue?status=new",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q: %s", want, msg)
		}
	}
}

func TestBuildNewAppDetectedMessageUnknownFields(t *testing.T) {
	e := Event{
		TenantID: "tenant-456",
		Kind:     KindNewAppDetected,
		Label:    "Mystery App",
	}
	msg := buildSlackMessage(e)
	if !strings.Contains(msg, "Platform: unknown") {
		t.Errorf("expected unknown platform placeholder, got: %s", msg)
	}
	if !strings.Contains(msg, "Publisher/signature: unknown") {
		t.Errorf("expected unknown publisher placeholder, got: %s", msg)
	}
	if !strings.Contains(msg, "Hosts: unknown") {
		t.Errorf("expected unknown host count placeholder, got: %s", msg)
	}
	if !strings.Contains(msg, "Suggested action: unknown") {
		t.Errorf("expected unknown suggested action placeholder, got: %s", msg)
	}
	if strings.Contains(msg, "Software Catalogue (New):") {
		t.Errorf("expected no catalogue link line when Link is empty, got: %s", msg)
	}
}

func TestNewAppsCatalogueLinkAppendsStatusFilter(t *testing.T) {
	if got, want := NewAppsCatalogueLink("tenant-abc"), "https://dashboard.patched.im/tenants/tenant-abc/catalogue?status=new"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestConfiguredChannelCount (PAT-1215) pins ConfiguredChannelCount's
// zero/one/several cases — the field GET /admin/health now reports so an
// operator can tell "no channels configured, alerts are dark" apart from
// "channels configured". Dispatch's silent no-op behaviour on missing config
// (TestDispatchMissingSlackConfigDoesNotCallOut above) is unchanged by this;
// this only makes that state observable elsewhere.
func TestConfiguredChannelCount(t *testing.T) {
	tests := []struct {
		name string
		n    *Notifier
		want int
	}{
		{"nil notifier", nil, 0},
		{"zero-value notifier, nothing configured", &Notifier{}, 0},
		{"slack only", &Notifier{slackURL: "https://hooks.slack.example/abc"}, 1},
		{"email only", &Notifier{smtpHost: "smtp.example.com", smtpTo: []string{"ops@patched.im"}}, 1},
		{
			"email host set but no recipients — still not configured",
			&Notifier{smtpHost: "smtp.example.com"},
			0,
		},
		{
			"both channels configured",
			&Notifier{slackURL: "https://hooks.slack.example/abc", smtpHost: "smtp.example.com", smtpTo: []string{"ops@patched.im"}},
			2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.n.ConfiguredChannelCount(); got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}
