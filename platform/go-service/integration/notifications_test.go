//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/envelope"
	"patched.im/api/internal/graphmail"
	"patched.im/api/internal/notifications"
	"patched.im/api/internal/webhook"
)

// PAT-1888 notification channels, against a real database.
//
// The webhook transport is faked throughout this file for one reason: the
// production transport refuses loopback destinations, which is exactly where an
// httptest server lives. That refusal is the SSRF control working, and it is
// tested directly in internal/webhook/deliver_test.go. What is tested here is
// everything the database is load-bearing for: tenant isolation, idempotency,
// the retry budget, the dead-letter transition, and the promise that none of it
// can touch finding truth.

// notificationStub is the swappable delivery behaviour for one test.
type notificationStub struct {
	mu        sync.Mutex
	status    int
	err       error
	mailErr   error
	calls     int
	bodies    [][]byte
	headers   []map[string]string
	mailCalls []graphmail.Message
}

var stub = &notificationStub{status: http.StatusOK}

func (s *notificationStub) reset(status int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status, s.err, s.mailErr = status, err, nil
	s.calls = 0
	s.bodies = nil
	s.headers = nil
	s.mailCalls = nil
}

func (s *notificationStub) post(_ context.Context, _ string, headers map[string]string, body []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.bodies = append(s.bodies, append([]byte(nil), body...))
	copied := map[string]string{}
	for k, v := range headers {
		copied[k] = v
	}
	s.headers = append(s.headers, copied)
	return s.status, s.err
}

func (s *notificationStub) Send(_ context.Context, msg graphmail.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mailCalls = append(s.mailCalls, msg)
	return s.mailErr
}

func (s *notificationStub) From() string { return "noreply@example.test" }

func (s *notificationStub) attempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// testNotificationDispatcher is used by the integration internal router and by
// the tests in this file, so the HTTP test-event path and the sweeper path
// share one fake transport.
func testNotificationDispatcher(pool *pgxpool.Pool) *notifications.Dispatcher {
	return notifications.NewDispatcher(pool, stub, notifications.WithTransport(stub.post))
}

// createNotificationChannel posts a channel and returns its id plus the
// create-time response body.
func createNotificationChannel(t *testing.T, tenantID string, body map[string]any) (string, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(
		env.internalSrv.URL+"/admin/tenants/"+tenantID+"/notification-channels",
		"application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}
	defer resp.Body.Close()
	var decoded map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&decoded)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create channel returned %d: %v", resp.StatusCode, decoded)
	}
	id, _ := decoded["id"].(string)
	if id == "" {
		t.Fatalf("create channel returned no id: %v", decoded)
	}
	return id, decoded
}

func defaultWebhookChannel(name string) map[string]any {
	return map[string]any{
		"channel_type":    "webhook",
		"name":            name,
		"destination_url": "https://hooks.example.com/patched",
		"events":          webhook.FindingEvents,
		"min_severity":    "low",
	}
}

// newNotificationTenant makes an independent tenant.
//
// Every test in this file gets its own, because a channel subscribes to a
// tenant's events and a shared tenant would make one test's channel receive
// another test's events. That is the isolation boundary under test, so leaning
// on it here also exercises it.
func newNotificationTenant(t *testing.T) string {
	t.Helper()
	id, _, _, err := createTestTenant(env.internalSrv.URL, "notifications-"+randomSuffix())
	if err != nil {
		t.Fatalf("create test tenant: %v", err)
	}
	return id
}

// deliveryRow is one delivery read straight from the database, which is how
// every per-channel assertion in this file is made: the sweeper is global, so
// counting stub calls would count other tests' deliveries too.
type deliveryRow struct {
	State         string
	FailureReason *string
	LastError     *string
	Attempts      int
	NextAttemptAt *string
	EventType     string
	Subject       string
}

func readDelivery(t *testing.T, channelID string) deliveryRow {
	t.Helper()
	var row deliveryRow
	if err := env.pool.QueryRow(context.Background(), `
		SELECT state, failure_reason, last_error, attempt_count,
		       next_attempt_at::text, event_type, subject
		FROM notification_deliveries
		WHERE channel_id = $1::uuid
		ORDER BY id
		LIMIT 1
	`, channelID).Scan(&row.State, &row.FailureReason, &row.LastError, &row.Attempts,
		&row.NextAttemptAt, &row.EventType, &row.Subject); err != nil {
		t.Fatalf("read delivery for channel %s: %v", channelID, err)
	}
	return row
}

func countDeliveries(t *testing.T, channelID string) int {
	t.Helper()
	var n int
	if err := env.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM notification_deliveries WHERE channel_id = $1::uuid`, channelID).Scan(&n); err != nil {
		t.Fatalf("count deliveries: %v", err)
	}
	return n
}

var suffixCounter struct {
	sync.Mutex
	n int
}

func randomSuffix() string {
	suffixCounter.Lock()
	defer suffixCounter.Unlock()
	suffixCounter.n++
	return fmt.Sprintf("%d", suffixCounter.n)
}

// hexSecretPattern matches the 64-char hex signing secret, so a response can be
// checked for one even if it were returned under some unexpected key.
var hexSecretPattern = regexp.MustCompile(`[0-9a-f]{64}`)

// TestNotificationSecretIsReturnedExactlyOnce proves the signing secret is
// readable at creation and never again, through any surface.
func TestNotificationSecretIsReturnedExactlyOnce(t *testing.T) {
	withEnvelopeKEK(t)
	tenantID := newNotificationTenant(t)
	channelID, created := createNotificationChannel(t, tenantID, defaultWebhookChannel("secret-once"))

	secret, _ := created["secret"].(string)
	if len(secret) != 64 {
		t.Fatalf("create should return a 64-char secret, got %q", secret)
	}

	surfaces := map[string]string{
		"list":       "/admin/tenants/" + env.tenantID + "/notification-channels",
		"deliveries": "/admin/tenants/" + env.tenantID + "/notification-channels/" + channelID + "/deliveries",
		"dead letter": "/admin/tenants/" + env.tenantID +
			"/notification-deliveries?state=dead_letter",
	}
	for name, path := range surfaces {
		resp, err := http.Get(env.internalSrv.URL + path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		body := readAllString(t, resp)
		resp.Body.Close()
		if strings.Contains(body, secret) {
			t.Errorf("%s response leaked the signing secret", name)
		}
		if hexSecretPattern.MatchString(strings.ReplaceAll(body, channelID, "")) {
			t.Errorf("%s response contains something shaped like a secret: %s", name, body)
		}
	}

	// An update must not return it either, and must not be able to change it.
	updateBody, _ := json.Marshal(map[string]any{"min_severity": "high"})
	req, _ := http.NewRequest(http.MethodPut,
		env.internalSrv.URL+"/admin/tenants/"+env.tenantID+"/notification-channels/"+channelID,
		strings.NewReader(string(updateBody)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	updated := readAllString(t, resp)
	resp.Body.Close()
	if strings.Contains(updated, secret) {
		t.Error("update response leaked the signing secret")
	}

	// And the stored copy must be encrypted rather than the plaintext.
	var stored string
	if err := env.pool.QueryRow(context.Background(),
		`SELECT secret FROM notification_channels WHERE id = $1::uuid`, channelID).Scan(&stored); err != nil {
		t.Fatalf("read stored secret: %v", err)
	}
	if stored == secret {
		t.Error("the signing secret is stored in plaintext")
	}
	if !strings.HasPrefix(stored, "penc1:") {
		t.Errorf("the stored secret is not envelope-encrypted: %q", firstChars(stored, 12))
	}
}

// TestNotificationTenantIsolation proves one tenant cannot see, change, test or
// delete another's channel, and that the refusal is a 404 rather than a 403 so
// it does not confirm the id exists.
func TestNotificationTenantIsolation(t *testing.T) {
	victimTenant := newNotificationTenant(t)
	victimID, _ := createNotificationChannel(t, victimTenant, defaultWebhookChannel("victim"))
	otherTenant := newNotificationTenant(t)

	base := env.internalSrv.URL + "/admin/tenants/" + otherTenant + "/notification-channels/" + victimID
	updateBody := `{"enabled":false}`

	cases := []struct {
		name   string
		method string
		url    string
		body   string
	}{
		{"read deliveries", http.MethodGet, base + "/deliveries", ""},
		{"update", http.MethodPut, base, updateBody},
		{"delete", http.MethodDelete, base, ""},
		{"send test", http.MethodPost, base + "/test", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, tc.url, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s returned %d, want 404 (a 403 would confirm the channel exists)", tc.name, resp.StatusCode)
			}
		})
	}

	// The other tenant's listing must not include it either.
	resp, err := http.Get(env.internalSrv.URL + "/admin/tenants/" + otherTenant + "/notification-channels")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	body := readAllString(t, resp)
	resp.Body.Close()
	if strings.Contains(body, victimID) {
		t.Error("another tenant's channel appeared in the listing")
	}

	// And the victim's channel is untouched.
	var enabled bool
	if err := env.pool.QueryRow(context.Background(),
		`SELECT enabled FROM notification_channels WHERE id = $1::uuid`, victimID).Scan(&enabled); err != nil {
		t.Fatalf("read victim channel: %v", err)
	}
	if !enabled {
		t.Error("a cross-tenant update changed the victim channel")
	}
}

// TestNotificationDeliveryIsIdempotent proves a replayed trigger enqueues once.
func TestNotificationDeliveryIsIdempotent(t *testing.T) {
	tenantID := newNotificationTenant(t)
	channelID, _ := createNotificationChannel(t, tenantID, defaultWebhookChannel("idempotent"))
	ctx := context.Background()

	ev := notifications.Event{
		TenantID: tenantID,
		Type:     webhook.EventFindingOpened,
		Subject:  "cis/device-idem/rule-a@2026-09-20T10:00:00Z",
		Severity: "high",
		Data:     map[string]any{"rule_key": "rule-a"},
	}

	first, err := notifications.Notify(ctx, env.pool, ev)
	if err != nil {
		t.Fatalf("first notify: %v", err)
	}
	if first != 1 {
		t.Fatalf("first notify enqueued %d deliveries, want 1", first)
	}

	for i := 0; i < 3; i++ {
		again, err := notifications.Notify(ctx, env.pool, ev)
		if err != nil {
			t.Fatalf("replay %d: %v", i, err)
		}
		if again != 0 {
			t.Errorf("replay %d enqueued %d deliveries, want 0", i, again)
		}
	}

	if rows := countDeliveries(t, channelID); rows != 1 {
		t.Errorf("four triggers produced %d delivery rows, want 1", rows)
	}

	// A later transition on the same finding is a new subject, so it is not
	// swallowed as a duplicate.
	later := ev
	later.Subject = "cis/device-idem/rule-a@2026-09-22T10:00:00Z"
	if n, err := notifications.Notify(ctx, env.pool, later); err != nil || n != 1 {
		t.Errorf("a later transition enqueued %d (err %v), want 1", n, err)
	}
}

// TestNotificationSeverityThreshold proves the per-channel filter, including
// that an ungraded event is still delivered.
func TestNotificationSeverityThreshold(t *testing.T) {
	spec := defaultWebhookChannel("threshold")
	spec["min_severity"] = "high"
	tenantID := newNotificationTenant(t)
	channelID, _ := createNotificationChannel(t, tenantID, spec)
	ctx := context.Background()

	cases := []struct {
		severity string
		want     int
	}{
		{"low", 0},
		{"medium", 0},
		{"high", 1},
		{"critical", 1},
		{"", 1}, // ungraded: never suppressed
	}
	for _, tc := range cases {
		n, err := notifications.Notify(ctx, env.pool, notifications.Event{
			TenantID: tenantID,
			Type:     webhook.EventFindingOpened,
			Subject:  "cis/device-threshold/rule-" + tc.severity + "@2026-09-20T10:00:00Z",
			Severity: tc.severity,
		})
		if err != nil {
			t.Fatalf("notify %q: %v", tc.severity, err)
		}
		if n != tc.want {
			t.Errorf("severity %q enqueued %d, want %d", tc.severity, n, tc.want)
		}
	}

	if rows := countDeliveries(t, channelID); rows != 3 {
		t.Errorf("a high-threshold channel took %d of 5 events, want 3", rows)
	}
}

// TestNotificationDisabledChannelStopsDelivery proves the documented rollback:
// disabling a channel stops delivery while keeping configuration and history.
func TestNotificationDisabledChannelStopsDelivery(t *testing.T) {
	tenantID := newNotificationTenant(t)
	channelID, _ := createNotificationChannel(t, tenantID, defaultWebhookChannel("rollback"))
	ctx := context.Background()

	if _, err := notifications.Notify(ctx, env.pool, notifications.Event{
		TenantID: tenantID, Type: webhook.EventFindingOpened,
		Subject: "cis/device-rollback/rule@2026-09-20T10:00:00Z",
	}); err != nil {
		t.Fatalf("notify: %v", err)
	}

	disable, _ := json.Marshal(map[string]any{"enabled": false})
	req, _ := http.NewRequest(http.MethodPut,
		env.internalSrv.URL+"/admin/tenants/"+tenantID+"/notification-channels/"+channelID,
		strings.NewReader(string(disable)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	resp.Body.Close()

	// A disabled channel takes no new events.
	n, err := notifications.Notify(ctx, env.pool, notifications.Event{
		TenantID: tenantID, Type: webhook.EventFindingOpened,
		Subject: "cis/device-rollback/rule@2026-09-21T10:00:00Z",
	})
	if err != nil {
		t.Fatalf("notify while disabled: %v", err)
	}
	if n != 0 {
		t.Errorf("a disabled channel accepted %d events, want 0", n)
	}

	// And the queued one is not swept: the sweeper joins on enabled channels
	// only, so the row stays pending with no attempt against it.
	stub.reset(http.StatusOK, nil)
	sweepDue(t)
	row := readDelivery(t, channelID)
	if row.Attempts != 0 {
		t.Errorf("a disabled channel delivered its queued event (%d attempts)", row.Attempts)
	}
	if row.State != notifications.StatePending {
		t.Errorf("the queued delivery state = %q, want %q", row.State, notifications.StatePending)
	}

	// The history survives.
	if rows := countDeliveries(t, channelID); rows != 1 {
		t.Errorf("disabling a channel lost its history: %d rows, want 1", rows)
	}

	// And it stays visible to the owner. Disabling is the documented rollback,
	// so the retained retry state has to be inspectable: a queued delivery that
	// vanished from the listing would be indistinguishable from one that was
	// never enqueued.
	listResp, err := http.Get(env.internalSrv.URL + "/admin/tenants/" + tenantID +
		"/notification-channels/" + channelID + "/deliveries?state=pending")
	if err != nil {
		t.Fatalf("deliveries listing: %v", err)
	}
	var listing struct {
		Deliveries []struct {
			State string `json:"state"`
		} `json:"deliveries"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listing); err != nil {
		t.Fatalf("decode listing: %v", err)
	}
	listResp.Body.Close()
	if len(listing.Deliveries) != 1 || listing.Deliveries[0].State != notifications.StatePending {
		t.Errorf("a disabled channel's pending delivery is not visible to its owner: %+v", listing.Deliveries)
	}
}

// TestNotificationRetryCapAndDeadLetter drives a failing destination to its
// bounded end state and proves the terminal row is listable by the owner.
func TestNotificationRetryCapAndDeadLetter(t *testing.T) {
	tenantID := newNotificationTenant(t)
	channelID, _ := createNotificationChannel(t, tenantID, defaultWebhookChannel("dead-letter"))
	ctx := context.Background()

	if _, err := notifications.Notify(ctx, env.pool, notifications.Event{
		TenantID: tenantID, Type: webhook.EventVerificationFailed,
		Subject: "cis/device-dl/rule@2026-09-20T10:00:00Z", Severity: "critical",
	}); err != nil {
		t.Fatalf("notify: %v", err)
	}

	stub.reset(http.StatusInternalServerError, nil)

	// The sweeper honours next_attempt_at, so the backoff is short-circuited
	// here rather than waited out. Every other part of the path is real.
	for i := 0; i < notifications.MaxAttempts+2; i++ {
		if _, err := env.pool.Exec(ctx, `
			UPDATE notification_deliveries SET next_attempt_at = now()
			WHERE channel_id = $1::uuid AND state = 'pending'
		`, channelID); err != nil {
			t.Fatalf("advance retry clock: %v", err)
		}
		sweepDue(t)
	}

	row := readDelivery(t, channelID)
	if row.State != notifications.StateDeadLetter {
		t.Fatalf("state = %q, want %q", row.State, notifications.StateDeadLetter)
	}
	if row.FailureReason == nil || *row.FailureReason != notifications.ReasonMaxAttempts {
		t.Errorf("failure_reason = %v, want %q", row.FailureReason, notifications.ReasonMaxAttempts)
	}
	if row.Attempts != notifications.MaxAttempts {
		t.Errorf("attempt_count = %d, want exactly %d: the retry budget is not bounded where it is documented",
			row.Attempts, notifications.MaxAttempts)
	}
	if row.NextAttemptAt != nil {
		t.Errorf("a dead-lettered row still has next_attempt_at = %v, so it would be retried forever", *row.NextAttemptAt)
	}
	if row.LastError == nil || *row.LastError == "" {
		t.Error("a dead-lettered row carries no last_error, so an owner cannot see why")
	}

	// The owner can see it, on a bounded page.
	resp, err := http.Get(env.internalSrv.URL + "/admin/tenants/" + tenantID +
		"/notification-deliveries?state=dead_letter&limit=1000")
	if err != nil {
		t.Fatalf("dead-letter listing: %v", err)
	}
	defer resp.Body.Close()
	var listing struct {
		Deliveries []struct {
			ChannelID     string  `json:"channel_id"`
			State         string  `json:"state"`
			FailureReason *string `json:"failure_reason"`
		} `json:"deliveries"`
		Limit int `json:"limit"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listing); err != nil {
		t.Fatalf("decode listing: %v", err)
	}
	if listing.Limit > notifications.MaxDeliveryPageSize {
		t.Errorf("limit %d exceeds the page cap %d", listing.Limit, notifications.MaxDeliveryPageSize)
	}
	found := false
	for _, d := range listing.Deliveries {
		if d.ChannelID == channelID {
			found = true
			if d.State != notifications.StateDeadLetter {
				t.Errorf("listed state = %q", d.State)
			}
		}
	}
	if !found {
		t.Error("the dead-lettered delivery was not listed for its owner")
	}
}

// TestNotificationFailureDoesNotTouchFindingTruth is the ticket's third
// acceptance criterion, asserted against the database rather than argued from
// the code: a completely failed delivery run changes no lifecycle row, no
// compliance evaluation and no finding.
func TestNotificationFailureDoesNotTouchFindingTruth(t *testing.T) {
	tenantID := newNotificationTenant(t)
	channelID, _ := createNotificationChannel(t, tenantID, defaultWebhookChannel("isolation"))
	ctx := context.Background()

	before := snapshotFindingTruth(t)

	if _, err := notifications.Notify(ctx, env.pool, notifications.Event{
		TenantID: tenantID, Type: webhook.EventEvidenceStale,
		Subject: "cis/device-truth/rule@2026-09-20T10:00:00Z",
	}); err != nil {
		t.Fatalf("notify: %v", err)
	}

	stub.reset(0, fmt.Errorf("dial tcp: connection refused"))
	for i := 0; i < notifications.MaxAttempts+1; i++ {
		if _, err := env.pool.Exec(ctx, `
			UPDATE notification_deliveries SET next_attempt_at = now()
			WHERE channel_id = $1::uuid AND state = 'pending'
		`, channelID); err != nil {
			t.Fatalf("advance retry clock: %v", err)
		}
		sweepDue(t)
	}

	after := snapshotFindingTruth(t)
	if before != after {
		t.Errorf("a failed delivery run changed finding state:\n before %+v\n after  %+v", before, after)
	}

	if row := readDelivery(t, channelID); row.State != notifications.StateDeadLetter {
		t.Errorf("the failure was not recorded as terminal: state = %q", row.State)
	}
}

// TestNotificationTestEventFabricatesNothing proves the test endpoint answers
// the "does my channel work" question without inventing a finding.
func TestNotificationTestEventFabricatesNothing(t *testing.T) {
	tenantID := newNotificationTenant(t)
	channelID, _ := createNotificationChannel(t, tenantID, defaultWebhookChannel("test-event"))
	ctx := context.Background()

	before := snapshotFindingTruth(t)
	stub.reset(http.StatusOK, nil)

	resp, err := http.Post(env.internalSrv.URL+"/admin/tenants/"+tenantID+
		"/notification-channels/"+channelID+"/test", "application/json", nil)
	if err != nil {
		t.Fatalf("test event: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("test event returned %d", resp.StatusCode)
	}
	var result struct {
		DeliveryID int64  `json:"delivery_id"`
		State      string `json:"state"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.State != notifications.StateDelivered {
		t.Errorf("test event state = %q, want %q", result.State, notifications.StateDelivered)
	}

	after := snapshotFindingTruth(t)
	if before != after {
		t.Errorf("the test event created finding state:\n before %+v\n after  %+v", before, after)
	}

	var eventType, subject string
	if err := env.pool.QueryRow(ctx, `
		SELECT event_type, subject FROM notification_deliveries WHERE id = $1
	`, result.DeliveryID).Scan(&eventType, &subject); err != nil {
		t.Fatalf("read test delivery: %v", err)
	}
	if eventType != string(webhook.EventTestPing) {
		t.Errorf("test delivery event_type = %q, want test.ping", eventType)
	}
	if !strings.HasPrefix(subject, "test/") {
		t.Errorf("test delivery subject = %q, want a test/ prefix", subject)
	}

	// The payload must be unmistakably synthetic.
	stub.mu.Lock()
	bodies := stub.bodies
	headers := stub.headers
	stub.mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("expected exactly one send, got %d", len(bodies))
	}
	body := string(bodies[0])
	if !strings.Contains(body, `"test":true`) || !strings.Contains(body, "not a finding") {
		t.Errorf("the test payload is not clearly labelled: %s", body)
	}
	if headers[0]["X-Patched-Signature"] == "" || headers[0]["X-Patched-Timestamp"] == "" {
		t.Error("the test delivery was not signed like a real one")
	}

	// Repeating the test must send again rather than dedupe against the first.
	resp2, err := http.Post(env.internalSrv.URL+"/admin/tenants/"+tenantID+
		"/notification-channels/"+channelID+"/test", "application/json", nil)
	if err != nil {
		t.Fatalf("second test event: %v", err)
	}
	resp2.Body.Close()
	if stub.attempts() != 2 {
		t.Errorf("a repeated test event sent %d times, want 2", stub.attempts())
	}
}

// TestNotificationEmailChannelWithoutMailerDeadLetters proves the degraded case
// is visible: an unconfigured mailer produces a recorded failure naming the
// missing configuration, never a silent no-op.
func TestNotificationEmailChannelWithoutMailerDeadLetters(t *testing.T) {
	tenantID := newNotificationTenant(t)
	channelID, created := createNotificationChannel(t, tenantID, map[string]any{
		"channel_type": "email",
		"name":         "email-unconfigured",
		"recipients":   []string{"owner@example.test"},
		"events":       []string{string(webhook.EventFindingOpened)},
	})
	if _, ok := created["secret"]; ok {
		t.Error("an email channel must not be issued a signing secret")
	}
	ctx := context.Background()

	if _, err := notifications.Notify(ctx, env.pool, notifications.Event{
		TenantID: tenantID, Type: webhook.EventFindingOpened,
		Subject: "cis/device-email/rule@2026-09-20T10:00:00Z",
	}); err != nil {
		t.Fatalf("notify: %v", err)
	}

	// A dispatcher with no mail sender, which is what an unconfigured
	// GRAPH_MAIL_* environment produces.
	notifications.NewSweeper(notifications.NewDispatcher(env.pool, nil,
		notifications.WithTransport(stub.post))).SweepOnce(ctx)

	row := readDelivery(t, channelID)
	if row.State != notifications.StateDeadLetter {
		t.Fatalf("state = %q, want %q", row.State, notifications.StateDeadLetter)
	}
	if row.FailureReason == nil || *row.FailureReason != notifications.ReasonUndeliverable {
		t.Errorf("failure_reason = %v, want %q", row.FailureReason, notifications.ReasonUndeliverable)
	}
	if row.LastError == nil || !strings.Contains(*row.LastError, "not configured") {
		t.Errorf("last_error should name the missing configuration, got %v", row.LastError)
	}
}

// TestNotificationEmailChannelDeliversThroughGraph proves the email path
// records a delivery when the mailer is present.
func TestNotificationEmailChannelDeliversThroughGraph(t *testing.T) {
	tenantID := newNotificationTenant(t)
	channelID, _ := createNotificationChannel(t, tenantID, map[string]any{
		"channel_type": "email",
		"name":         "email-configured",
		"recipients":   []string{"owner@example.test", "security@example.test"},
		"events":       []string{string(webhook.EventEvidenceStale)},
	})
	ctx := context.Background()

	stub.reset(http.StatusOK, nil)
	if _, err := notifications.Notify(ctx, env.pool, notifications.Event{
		TenantID: tenantID, Type: webhook.EventEvidenceStale,
		Subject: "cis/device-email2/rule@2026-09-20T10:00:00Z",
	}); err != nil {
		t.Fatalf("notify: %v", err)
	}

	notifications.NewSweeper(notifications.NewDispatcher(env.pool, stub,
		notifications.WithTransport(stub.post))).SweepOnce(ctx)

	if row := readDelivery(t, channelID); row.State != notifications.StateDelivered {
		t.Fatalf("state = %q, want %q", row.State, notifications.StateDelivered)
	}

	stub.mu.Lock()
	sent := stub.mailCalls
	stub.mu.Unlock()
	if len(sent) != 1 {
		t.Fatalf("expected one email, got %d", len(sent))
	}
	if len(sent[0].To) != 2 {
		t.Errorf("both recipients should be addressed, got %v", sent[0].To)
	}
	if !strings.Contains(strings.ToLower(sent[0].Body), "has not been cleared") {
		t.Errorf("a stale-evidence email must not imply the finding cleared: %s", sent[0].Body)
	}
}

// TestNotificationChannelRejectsInternalDestination proves the SSRF refusal is
// wired all the way through the HTTP surface, not only into the validator.
func TestNotificationChannelRejectsInternalDestination(t *testing.T) {
	tenantID := newNotificationTenant(t)
	for _, target := range []string{
		"https://169.254.169.254/latest/meta-data/",
		"https://127.0.0.1/hook",
		"https://10.0.0.1/hook",
		"https://100.64.1.1/hook",
		"https://[::1]/hook",
		"http://example.com/hook",
	} {
		spec := defaultWebhookChannel("ssrf")
		spec["destination_url"] = target
		raw, _ := json.Marshal(spec)
		resp, err := http.Post(env.internalSrv.URL+"/admin/tenants/"+tenantID+"/notification-channels",
			"application/json", strings.NewReader(string(raw)))
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		body := readAllString(t, resp)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("destination %s was accepted with status %d: %s", target, resp.StatusCode, body)
		}
	}
}

// TestNotificationUndecryptableSecretDeadLettersAndDoesNotStarve covers the
// poison-row case: a channel whose stored signing secret cannot be unwrapped,
// which is what a rotated or removed PATCHED_KEK produces.
//
// Before the fix the sweeper logged and skipped such a row, leaving it pending
// with next_attempt_at untouched. It was therefore re-selected every tick
// forever, and because the due query is ORDER BY next_attempt_at LIMIT n,
// enough of them at the head of the queue would push healthy deliveries out of
// the batch entirely. The assertions below pin both halves: the poison row
// reaches a terminal state exactly once, and a healthy delivery queued behind
// it is still delivered in the same sweep.
func TestNotificationUndecryptableSecretDeadLettersAndDoesNotStarve(t *testing.T) {
	tenantID := newNotificationTenant(t)
	poisonID, _ := createNotificationChannel(t, tenantID, defaultWebhookChannel("poison"))
	healthyID, _ := createNotificationChannel(t, tenantID, defaultWebhookChannel("healthy"))
	ctx := context.Background()

	// This suite runs with PATCHED_KEK unset, so a marked value is exactly the
	// production shape of "encrypted with a key this process does not have".
	if _, err := env.pool.Exec(ctx, `
		UPDATE notification_channels SET secret = 'penc1:dGhpcyBpcyBub3QgYSB2YWxpZCBlbnZlbG9wZQ=='
		WHERE id = $1::uuid
	`, poisonID); err != nil {
		t.Fatalf("poison the stored secret: %v", err)
	}

	for _, channel := range []string{poisonID, healthyID} {
		if _, err := notifications.Notify(ctx, env.pool, notifications.Event{
			TenantID: tenantID, Type: webhook.EventFindingOpened,
			Subject: "cis/device-poison/rule-" + channel + "@2026-09-20T10:00:00Z",
		}); err != nil {
			t.Fatalf("notify: %v", err)
		}
	}

	// Put the poison row at the head of the queue, which is where it would do
	// the damage.
	if _, err := env.pool.Exec(ctx, `
		UPDATE notification_deliveries SET next_attempt_at = now() - interval '1 hour'
		WHERE channel_id = $1::uuid
	`, poisonID); err != nil {
		t.Fatalf("order the queue: %v", err)
	}

	stub.reset(http.StatusOK, nil)
	sweepDue(t)

	poison := readDelivery(t, poisonID)
	if poison.State != notifications.StateDeadLetter {
		t.Fatalf("poison delivery state = %q, want %q", poison.State, notifications.StateDeadLetter)
	}
	if poison.FailureReason == nil || *poison.FailureReason != notifications.ReasonUndeliverable {
		t.Errorf("failure_reason = %v, want %q", poison.FailureReason, notifications.ReasonUndeliverable)
	}
	if poison.LastError == nil || !strings.Contains(*poison.LastError, "could not be decrypted") {
		t.Errorf("last_error should name the fault, got %v", poison.LastError)
	}
	if poison.LastError != nil && strings.Contains(*poison.LastError, "penc1:") {
		t.Errorf("last_error leaked stored ciphertext: %q", *poison.LastError)
	}
	if poison.NextAttemptAt != nil {
		t.Errorf("a dead-lettered poison row kept next_attempt_at = %v, so it would be re-selected", *poison.NextAttemptAt)
	}

	// The healthy delivery behind it went out in the same sweep.
	if healthy := readDelivery(t, healthyID); healthy.State != notifications.StateDelivered {
		t.Errorf("a healthy delivery queued behind the poison row was starved: state = %q", healthy.State)
	}

	// A second sweep must not touch the poison row again.
	attemptsAfterFirst := poison.Attempts
	sweepDue(t)
	if again := readDelivery(t, poisonID); again.Attempts != attemptsAfterFirst {
		t.Errorf("the poison row was re-selected: attempt_count went %d -> %d",
			attemptsAfterFirst, again.Attempts)
	}

	// The owner can see it.
	resp, err := http.Get(env.internalSrv.URL + "/admin/tenants/" + tenantID +
		"/notification-deliveries?state=dead_letter")
	if err != nil {
		t.Fatalf("dead-letter listing: %v", err)
	}
	defer resp.Body.Close()
	var listing struct {
		Deliveries []struct {
			ChannelID     string  `json:"channel_id"`
			FailureReason *string `json:"failure_reason"`
		} `json:"deliveries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listing); err != nil {
		t.Fatalf("decode listing: %v", err)
	}
	found := false
	for _, d := range listing.Deliveries {
		if d.ChannelID == poisonID {
			found = true
		}
	}
	if !found {
		t.Error("the undecryptable-secret delivery is not in the owner's dead-letter listing")
	}
}

// TestNotificationBlockedDestinationErrorIsSanitised is the PAT-1956
// acceptance test: a channel pointed at a hostname that resolves to a private
// address dead-letters with a last_error an owner can read safely.
//
// Hostnames are accepted at channel configuration time by design (DNS can
// change afterwards), so "localhost" passes creation here exactly as a tenant
// owner's own internal-looking name would, and is only refused at dial time by
// the SSRF guard. This is the real production shape from PAT-1888 evidence:
// "Post \"https://localhost/hook\": dial tcp [::1]:443: ...". The dispatcher
// used here carries no WithTransport override, so the delivery goes through
// the genuine webhook.PostHardened transport and a real DNS resolution,
// not a stub standing in for one.
func TestNotificationBlockedDestinationErrorIsSanitised(t *testing.T) {
	tenantID := newNotificationTenant(t)
	spec := defaultWebhookChannel("localhost-fixture")
	spec["destination_url"] = "https://localhost/hook"
	channelID, _ := createNotificationChannel(t, tenantID, spec)

	realDispatcher := notifications.NewDispatcher(env.pool, nil) // no stub: real transport
	_, state, err := realDispatcher.SendTest(context.Background(), channelID, tenantID)
	if err != nil {
		t.Fatalf("SendTest: %v", err)
	}
	if state != notifications.StateDeadLetter {
		t.Fatalf("state = %q, want %q", state, notifications.StateDeadLetter)
	}

	row := readDelivery(t, channelID)
	if row.State != notifications.StateDeadLetter {
		t.Fatalf("persisted state = %q, want %q", row.State, notifications.StateDeadLetter)
	}
	if row.FailureReason == nil || *row.FailureReason != notifications.ReasonUndeliverable {
		t.Errorf("failure_reason = %v, want %q: the refusal itself must not change", row.FailureReason, notifications.ReasonUndeliverable)
	}
	if row.Attempts != 1 {
		t.Errorf("attempt_count = %d, want 1: a blocked destination must not be retried", row.Attempts)
	}
	if row.NextAttemptAt != nil {
		t.Errorf("a dead-lettered blocked destination kept next_attempt_at = %v", *row.NextAttemptAt)
	}

	if row.LastError == nil || *row.LastError == "" {
		t.Fatal("a dead-lettered row carries no last_error, so an owner cannot see why")
	}
	// The absence assertions are the point of this test: the configured
	// hostname and every shape the SSRF guard's own error could have
	// resolved it to must all be gone from the owner-visible column.
	for _, leak := range []string{"localhost", "127.0.0.1", "::1", "[::1]", "dial tcp"} {
		if strings.Contains(*row.LastError, leak) {
			t.Errorf("last_error %q leaks %q", *row.LastError, leak)
		}
	}
	if !strings.Contains(*row.LastError, "not permitted") {
		t.Errorf("last_error %q should say the address is not permitted", *row.LastError)
	}
}

// sweepDue runs one full sweeper tick against the fake transport and waits for
// it to finish.
func sweepDue(t *testing.T) {
	t.Helper()
	notifications.NewSweeper(
		notifications.NewDispatcher(env.pool, stub, notifications.WithTransport(stub.post)),
	).SweepOnce(context.Background())
}

// findingTruth is the state a notification must never be able to change.
type findingTruth struct {
	LifecycleEvents int
	Evaluations     int
	CVEFindings     int
}

func snapshotFindingTruth(t *testing.T) findingTruth {
	t.Helper()
	var got findingTruth
	ctx := context.Background()
	if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM finding_lifecycle_events`).Scan(&got.LifecycleEvents); err != nil {
		t.Fatalf("count lifecycle events: %v", err)
	}
	if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM compliance_evaluations`).Scan(&got.Evaluations); err != nil {
		t.Fatalf("count evaluations: %v", err)
	}
	if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM device_cve_findings`).Scan(&got.CVEFindings); err != nil {
		t.Fatalf("count cve findings: %v", err)
	}
	return got
}

// withEnvelopeKEK turns on envelope encryption for the duration of one test.
//
// The rest of this suite runs with PATCHED_KEK unset, where the envelope
// helpers are a documented passthrough, so a secret-at-rest assertion needs the
// key present to mean anything. The process-wide default is restored on
// cleanup by unsetting the variable and re-initialising, so no other test sees
// the change.
func withEnvelopeKEK(t *testing.T) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	t.Setenv(envelope.EnvVar, base64.StdEncoding.EncodeToString(key))
	if _, err := envelope.Init(); err != nil {
		t.Fatalf("enable envelope encryption: %v", err)
	}
	t.Cleanup(func() {
		os.Unsetenv(envelope.EnvVar)
		if _, err := envelope.Init(); err != nil {
			t.Fatalf("restore envelope default: %v", err)
		}
	})
}

// readAllString drains a response body into a string for substring assertions.
func readAllString(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return string(body)
}

func firstChars(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
