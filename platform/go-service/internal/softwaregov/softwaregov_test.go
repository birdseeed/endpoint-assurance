package softwaregov

import (
	"strings"
	"testing"
	"time"
)

func presence(id, host string, stale bool) Presence {
	t := time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC)
	return Presence{DeviceID: id, Hostname: host, Platform: "macos", ObservedSince: t, LastSeen: t, Stale: stale}
}

func app(key, name string) Product {
	return Product{Type: TypeApplication, ProductKey: key, Name: name, Platform: "macos", Identifier: strings.TrimPrefix(key, "application:macos:")}
}

func TestCountStatesUsesWorstStatePerProduct(t *testing.T) {
	assessments := []Assessment{
		// One product Unapproved on one device and Unreviewed on another
		// counts once, as Unapproved.
		{Product: app("application:macos:com.a", "A"), State: StateUnapproved, PolicyID: 1, Devices: []Presence{presence("d1", "h1", false)}},
		{Product: app("application:macos:com.a", "A"), State: StateUnreviewed, Devices: []Presence{presence("d2", "h2", false)}},
		{Product: app("application:macos:com.b", "B"), State: StateUnreviewed, Devices: []Presence{presence("d1", "h1", false)}},
		{Product: app("application:macos:com.c", "C"), State: StateApproved, PolicyID: 2, Devices: []Presence{presence("d2", "h2", false)}},
		{Product: app("application:macos:com.d", "D"), State: StateIgnored, PolicyID: 3, Devices: []Presence{presence("d2", "h2", false)}},
	}
	c := CountStates(assessments)
	if c.InstalledProducts != 4 || c.Unapproved != 1 || c.Unreviewed != 1 || c.Approved != 1 || c.Ignored != 1 {
		t.Fatalf("counts = %+v", c)
	}
	if c.UnapprovedDevices != 1 {
		t.Fatalf("unapproved devices = %d, want 1 (only d1 resolves Unapproved)", c.UnapprovedDevices)
	}

	products := DriftProducts(assessments)
	if len(products) != 2 || products[0].ProductKey != "application:macos:com.a" || products[0].ApprovalState != StateUnapproved {
		t.Fatalf("drift products = %+v", products)
	}
	if products[0].DeviceCount != 2 {
		t.Fatalf("a product's device count covers every device it is on, got %d", products[0].DeviceCount)
	}
	for _, p := range products {
		if p.ApprovalState == StateApproved || p.ApprovalState == StateIgnored {
			t.Fatalf("Approved or Ignored product in drift list: %+v", p)
		}
	}
}

func TestTopUnapprovedDevicesRanksByDistinctProducts(t *testing.T) {
	assessments := []Assessment{
		{Product: app("application:macos:com.a", "A"), State: StateUnapproved, PolicyID: 1,
			Devices: []Presence{presence("d1", "alpha", false), presence("d2", "bravo", true)}},
		{Product: app("application:macos:com.b", "B"), State: StateUnapproved, PolicyID: 2,
			Devices: []Presence{presence("d2", "bravo", true)}},
		{Product: app("application:macos:com.c", "C"), State: StateUnreviewed,
			Devices: []Presence{presence("d1", "alpha", false), presence("d3", "charlie", false)}},
	}
	top := TopUnapprovedDevices(assessments, 10)
	if len(top) != 2 || top[0].Hostname != "bravo" || top[0].UnapprovedProductCount != 2 || !top[0].Stale {
		t.Fatalf("top devices = %+v", top)
	}
	if top[1].Hostname != "alpha" || top[1].UnapprovedProductCount != 1 {
		t.Fatalf("second device = %+v", top[1])
	}
	if got := TopUnapprovedDevices(assessments, 1); len(got) != 1 {
		t.Fatalf("limit not applied: %d", len(got))
	}
}

func TestWeekStartAndDailySlotAreUTC(t *testing.T) {
	// Thursday 24 Sep 2026 00:30 in BST is Wednesday 23:30 UTC: the week
	// still starts Monday 21 Sep and the slot is Wednesday's.
	bst := time.FixedZone("BST", 3600)
	now := time.Date(2026, 9, 24, 0, 30, 0, 0, bst)
	if got := WeekStart(now).Format("2006-01-02"); got != "2026-09-21" {
		t.Fatalf("week start = %s", got)
	}
	if got := DailySlot(now, DigestHourUTC); !got.Equal(time.Date(2026, 9, 23, 7, 0, 0, 0, time.UTC)) {
		t.Fatalf("slot before 07:00 UTC = %s", got)
	}
	later := time.Date(2026, 9, 24, 7, 0, 0, 0, time.UTC)
	if got := DailySlot(later, DigestHourUTC); !got.Equal(later) {
		t.Fatalf("slot at 07:00 UTC = %s", got)
	}
	sunday := time.Date(2026, 9, 27, 23, 59, 0, 0, time.UTC)
	if got := WeekStart(sunday).Format("2006-01-02"); got != "2026-09-21" {
		t.Fatalf("Sunday belongs to the week that started on Monday, got %s", got)
	}
}

func TestValidEmail(t *testing.T) {
	for _, ok := range []string{"it@customer.example", "a.b+c@sub.example.co.uk"} {
		if !validEmail(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "no-at", "@example.com", "a@b", "a@@b.com", "a b@c.com", "a@b.com\r\nBcc: x@y.com", "a@b.com,c@d.com", "a@.com"} {
		if validEmail(bad) {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func assertCustomerCopy(t *testing.T, label, text string) {
	t.Helper()
	for _, banned := range []string{"—", "–", "fleet", "Fleet", "specialist", "mailto:"} {
		if strings.Contains(text, banned) {
			t.Errorf("%s contains %q:\n%s", label, banned, text)
		}
	}
}

func TestMarkedEmailCopy(t *testing.T) {
	by := "alice@customer.example"
	p := AlertPayload{
		AlertID: 7, Trigger: TriggerMarked, MarkedBy: &by, MarkedVia: SourcePortal,
		MarkedAt: time.Date(2026, 9, 24, 14, 5, 0, 0, time.UTC), DeviceCount: 2,
		Products: []AlertProduct{{
			Product:     Product{Type: TypeApplication, Name: "Tor Browser", Platform: "macos", Identifier: "org.torproject.torbrowser", TeamID: "MADPSAYN6T"},
			DeviceCount: 2,
			Devices: []AlertDevice{
				{DeviceID: "d1", Hostname: "mac-01", Platform: "macos", LastSeen: time.Date(2026, 9, 24, 13, 50, 0, 0, time.UTC)},
				{DeviceID: "d2", Hostname: "mac-02\r\nBcc: evil@example.com", Platform: "macos", LastSeen: time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC), Stale: true},
			},
		}},
	}
	subject, body := RenderMarkedEmail(p, "Acme Ltd", "it@acme.example")
	if subject != "Patched: Tor Browser marked Unapproved and found on 2 devices" {
		t.Fatalf("subject = %q", subject)
	}
	for _, want := range []string{
		"installed on 2 devices in your estate",
		"Marked by: alice@customer.example in the Patched portal",
		"Marked at: 24 Sep 2026 14:05 UTC",
		"Team ID: MADPSAYN6T",
		"mac-01 (macOS), last reported 24 Sep 2026 13:50 UTC",
		"not reported for over 14 days",
		"It does not remove it.",
		"it@acme.example is the contact address for Acme Ltd",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "\r") || strings.Contains(body, "\nBcc:") {
		t.Fatalf("a hostname broke out of its line:\n%s", body)
	}
	assertCustomerCopy(t, "marked email", subject+body)

	p.MarkedBy, p.MarkedVia = nil, SourceOperator
	_, body = RenderMarkedEmail(p, "Acme Ltd", "it@acme.example")
	if !strings.Contains(body, "Marked by: your Patched operator") {
		t.Fatalf("operator attribution missing:\n%s", body)
	}
}

func TestDigestEmailGroupsByProduct(t *testing.T) {
	mk := func(policyID int64, name, dev, host string) AlertPayload {
		return AlertPayload{
			Trigger: TriggerObserved, Policy: AlertPolicy{Kind: TypeApplication, ID: policyID},
			MarkedVia: "unknown", DeviceCount: 1,
			Products: []AlertProduct{{Product: Product{Type: TypeApplication, ProductKey: "k" + name, Name: name, Platform: "windows", Identifier: name},
				DeviceCount: 1, Devices: []AlertDevice{{DeviceID: dev, Hostname: host, Platform: "windows", LastSeen: time.Now()}}}},
		}
	}
	subject, body := RenderDigestEmail([]AlertPayload{
		mk(1, "Utorrent", "d1", "pc-01"), mk(1, "Utorrent", "d2", "pc-02"), mk(2, "Zoom Old", "d1", "pc-01"),
	}, nil, "Acme Ltd", "it@acme.example")
	if subject != "Patched: unapproved software found on 2 devices" {
		t.Fatalf("subject = %q", subject)
	}
	if !strings.Contains(body, "2 products on 2 devices") || !strings.Contains(body, "Newly found on (2)") ||
		!strings.Contains(body, "Marked Unapproved by not recorded") {
		t.Fatalf("digest body:\n%s", body)
	}
	if strings.Index(body, "Utorrent") > strings.Index(body, "Zoom Old") {
		t.Fatalf("the most widespread product should come first:\n%s", body)
	}
	assertCustomerCopy(t, "digest email", subject+body)
}

// PAT-2097: a re-open is reported in the digest, in its own section, and
// counts towards the devices in the subject.
func TestDigestEmailListsReopened(t *testing.T) {
	mk := func(name, dev, host string) AlertPayload {
		return AlertPayload{
			Trigger: "reopened", Policy: AlertPolicy{Kind: TypeApplication, ID: 9}, MarkedVia: "unknown", DeviceCount: 1,
			Products: []AlertProduct{{Product: Product{Type: TypeApplication, ProductKey: "k" + name, Name: name, Platform: "macos", Identifier: name},
				DeviceCount: 1, Devices: []AlertDevice{{DeviceID: dev, Hostname: host, Platform: "macos", LastSeen: time.Now()}}}},
		}
	}
	subject, body := RenderDigestEmail(nil, []AlertPayload{mk("Torrent Thing", "d9", "mac-09")}, "Acme Ltd", "it@acme.example")
	if subject != "Patched: unapproved software found on 1 device" {
		t.Fatalf("subject = %q", subject)
	}
	if !strings.Contains(body, "Found again on (1)") || !strings.Contains(body, "mac-09") ||
		strings.Contains(body, "had not been reported before") {
		t.Fatalf("reopen-only digest body:\n%s", body)
	}
	assertCustomerCopy(t, "reopen digest email", subject+body)
}
