package ratelimit_test

import (
	"testing"
	"time"

	"patched.im/api/internal/ratelimit"
)

func TestAllow_UnderBurst(t *testing.T) {
	rl := ratelimit.New(ratelimit.Config{RPM: 60, Burst: 5})
	for i := 0; i < 5; i++ {
		allowed, _ := rl.Allow("t1")
		if !allowed {
			t.Fatalf("request %d denied unexpectedly (burst=5)", i+1)
		}
	}
}

func TestAllow_DeniedAfterBurst(t *testing.T) {
	rl := ratelimit.New(ratelimit.Config{RPM: 60, Burst: 3})
	for i := 0; i < 3; i++ {
		rl.Allow("t1")
	}
	allowed, retryAfter := rl.Allow("t1")
	if allowed {
		t.Fatal("expected deny after burst exhaustion")
	}
	if retryAfter <= 0 {
		t.Fatalf("expected positive retryAfter, got %v", retryAfter)
	}
}

func TestAllow_IsolatesTenants(t *testing.T) {
	rl := ratelimit.New(ratelimit.Config{RPM: 60, Burst: 2})
	rl.Allow("t1")
	rl.Allow("t1")
	denied, _ := rl.Allow("t1")
	if denied {
		t.Fatal("t1 should be denied")
	}
	allowed, _ := rl.Allow("t2")
	if !allowed {
		t.Fatal("t2 should be allowed (separate bucket)")
	}
}

func TestAllow_RecoveryAfterWait(t *testing.T) {
	// 120 rpm = 2 tokens/sec. Burst 1. Exhaust, sleep slightly over 0.5s, retry.
	rl := ratelimit.New(ratelimit.Config{RPM: 120, Burst: 1})
	rl.Allow("t1") // consume the burst
	denied, _ := rl.Allow("t1")
	if denied {
		t.Fatal("first request after burst should already be denied")
	}
	time.Sleep(600 * time.Millisecond) // wait for ~1 token to refill
	allowed, _ := rl.Allow("t1")
	if !allowed {
		t.Fatal("expected allow after token refill")
	}
}

func TestAllow_RetryAfterIsPositiveOnDeny(t *testing.T) {
	rl := ratelimit.New(ratelimit.Config{RPM: 60, Burst: 1})
	rl.Allow("t1") // drain
	ok, d := rl.Allow("t1")
	if ok {
		t.Skip("token refilled between calls")
	}
	if d <= 0 || d > 2*time.Second {
		t.Fatalf("unexpected retryAfter %v", d)
	}
}

// ---------------------------------------------------------------------------
// Config.Period (PAT-453) — the generalized-window behaviour the portal
// enrolment-mint limiter depends on. Without these, RPM/Burst-only tests
// above never exercise Period at all (it stays at its zero value throughout),
// so the actual "N requests per Period" rate scaling was previously unproven.
// ---------------------------------------------------------------------------

// TestAllow_CustomPeriod_ScalesRateNotPerMinute proves RPM is interpreted
// against the configured Period, not always "per minute": with Period: Hour,
// RPM/Burst: 10, the burst drains after 10 immediate requests and the next
// denial's retryAfter reflects an hourly (not a 60x-faster minutely) refill
// rate — roughly 6 minutes per token, nowhere near the ~1 second a per-minute
// interpretation of RPM=10 would produce.
func TestAllow_CustomPeriod_ScalesRateNotPerMinute(t *testing.T) {
	rl := ratelimit.New(ratelimit.Config{RPM: 10, Burst: 10, Period: time.Hour})
	for i := 0; i < 10; i++ {
		allowed, _ := rl.Allow("tenant-hourly")
		if !allowed {
			t.Fatalf("request %d denied unexpectedly (burst=10)", i+1)
		}
	}
	allowed, retryAfter := rl.Allow("tenant-hourly")
	if allowed {
		t.Fatal("expected deny after the hourly burst of 10 is exhausted")
	}
	// 10 requests/hour == 1 token every 6 minutes. A per-minute
	// misinterpretation (the pre-PAT-453 only behaviour) would instead
	// produce a retryAfter on the order of ~6 seconds (10/min => 1 token per
	// 6s). Assert we're clearly in "minutes", not "single-digit seconds".
	if retryAfter < 5*time.Minute || retryAfter > 7*time.Minute {
		t.Fatalf("retryAfter = %v, want ~6 minutes (10 requests/hour)", retryAfter)
	}
}

// TestAllow_CustomPeriod_IsolatesFromDefaultPeriodTenants confirms a
// Period-scoped limiter still isolates buckets per tenant key exactly like
// the default (per-minute) limiter — Period only changes the refill rate,
// never the per-tenant keying.
func TestAllow_CustomPeriod_IsolatesFromDefaultPeriodTenants(t *testing.T) {
	rl := ratelimit.New(ratelimit.Config{RPM: 2, Burst: 2, Period: time.Hour})
	rl.Allow("a")
	rl.Allow("a")
	if allowed, _ := rl.Allow("a"); allowed {
		t.Fatal("tenant a should be denied after exhausting its hourly burst of 2")
	}
	if allowed, _ := rl.Allow("b"); !allowed {
		t.Fatal("tenant b should be allowed — separate bucket, unaffected by a's exhaustion")
	}
}

func TestBlockedDoesNotConsumeOrCreate(t *testing.T) {
	tl := ratelimit.New(ratelimit.Config{RPM: 1, Burst: 2})
	for i := 0; i < 1000; i++ {
		if tl.Blocked("probe") {
			t.Fatal("an unseen key is blocked")
		}
	}
	// Blocked created no entry: the first real Allow still has the full burst.
	if ok, _ := tl.Allow("probe"); !ok {
		t.Fatal("first Allow after probing refused")
	}
	if tl.Blocked("probe") {
		t.Fatal("blocked with one token left")
	}
	tl.Allow("probe")
	if !tl.Blocked("probe") {
		t.Fatal("not blocked with no tokens")
	}
	if !tl.Blocked("probe") {
		t.Fatal("Blocked consumed or refilled a token")
	}
}
