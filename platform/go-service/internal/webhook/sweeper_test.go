package webhook

import (
	"context"
	"sync"
	"testing"
	"time"

	"patched.im/api/internal/envelope"
)

// TestDecideOutcome pins the shared retry-decision logic used by both the
// in-memory attempt() path and the DB-backed Sweeper. If these two ever diverge
// the sweeper would retry deliveries the live dispatcher considered permanent
// (or vice versa), so the logic lives in one pure function guarded here.
func TestDecideOutcome(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		netErr      bool
		attempt     int
		want        retryOutcome
		wantBackoff time.Duration
	}{
		{"2xx delivered", 200, false, 1, outcomeSuccess, 0},
		{"201 delivered mid-run", 201, false, 3, outcomeSuccess, 0},
		{"299 delivered", 299, false, 1, outcomeSuccess, 0},
		{"400 permanent", 400, false, 1, outcomePermanent, 0},
		{"404 permanent", 404, false, 2, outcomePermanent, 0},
		{"499 permanent", 499, false, 1, outcomePermanent, 0},
		{"500 retriable", 500, false, 1, outcomeRetry, RetryBackoff(2)},
		{"502 retriable later attempt", 502, false, 3, outcomeRetry, RetryBackoff(4)},
		{"network error retriable", 0, true, 2, outcomeRetry, RetryBackoff(3)},
		{"503 give up at cap", 503, false, maxAttempts, outcomeGiveUp, 0},
		{"network give up at cap", 0, true, maxAttempts, outcomeGiveUp, 0},
		{"retriable one below cap", 500, false, maxAttempts - 1, outcomeRetry, RetryBackoff(maxAttempts)},
		// A 2xx at the cap still wins over give-up (success is checked first).
		{"success at cap beats give up", 200, false, maxAttempts, outcomeSuccess, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, backoff := decideOutcome(tt.status, tt.netErr, tt.attempt)
			if got != tt.want {
				t.Errorf("decideOutcome(%d, %v, %d) outcome = %v, want %v",
					tt.status, tt.netErr, tt.attempt, got, tt.want)
			}
			if backoff != tt.wantBackoff {
				t.Errorf("decideOutcome(%d, %v, %d) backoff = %v, want %v",
					tt.status, tt.netErr, tt.attempt, backoff, tt.wantBackoff)
			}
		})
	}
}

// TestSweeperClaimReleaseGuardsDoubleProcessing verifies the in-flight set stops
// the same delivery id being picked up twice across overlapping ticks.
func TestSweeperClaimReleaseGuardsDoubleProcessing(t *testing.T) {
	s := NewSweeper(nil)

	if !s.claim(42) {
		t.Fatal("first claim of id 42 should succeed")
	}
	if s.claim(42) {
		t.Fatal("second claim of in-flight id 42 should fail")
	}
	// A different id is independent.
	if !s.claim(43) {
		t.Fatal("claim of distinct id 43 should succeed")
	}

	s.release(42)
	if !s.claim(42) {
		t.Fatal("claim after release should succeed again")
	}
}

// TestNewSweeperDefaultsAndOptions checks constructor defaults and that options
// override them (ignoring non-positive values).
func TestNewSweeperDefaultsAndOptions(t *testing.T) {
	def := NewSweeper(nil)
	if def.interval != defaultSweepInterval || def.batch != defaultSweepBatch || def.workers != defaultSweepWorkers {
		t.Fatalf("unexpected defaults: interval=%v batch=%d workers=%d",
			def.interval, def.batch, def.workers)
	}

	s := NewSweeper(nil,
		WithInterval(5*time.Second),
		WithBatchSize(10),
		WithWorkers(2),
		WithInterval(0),   // ignored
		WithBatchSize(-1), // ignored
		WithWorkers(0),    // ignored
	)
	if s.interval != 5*time.Second || s.batch != 10 || s.workers != 2 {
		t.Fatalf("options not applied correctly: interval=%v batch=%d workers=%d",
			s.interval, s.batch, s.workers)
	}
}

// TestSafeSweepRecoversPanic proves a panicking sweep tick does not crash the
// process (PAT-867). chi's middleware.Recoverer only guards HTTP handler
// goroutines — this background ticker had no equivalent, so an unrecovered
// panic here would previously take down the entire patched-api binary.
//
// A nil pool is used to trigger a genuine panic inside s.sweep's DB call
// (the same nil-pool-panics convention already used elsewhere in this repo,
// e.g. enrolment_test.go's TestEnrolHandler_NewFlatFormatPassesValidation).
// Before safeSweep existed, calling s.sweep directly here would panic and
// fail this test's whole process; after the fix, safeSweep recovers and the
// test completes normally.
func TestSafeSweepRecoversPanic(t *testing.T) {
	s := NewSweeper(nil)
	sem := make(chan struct{}, 1)
	var wg sync.WaitGroup

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.safeSweep(context.Background(), sem, &wg)
	}()

	select {
	case <-done:
		// safeSweep returned normally — the panic was recovered.
	case <-time.After(5 * time.Second):
		t.Fatal("safeSweep did not return — panic may have propagated instead of recovering")
	}
}

// TestDispatchOneRecoversPanic proves a panicking per-delivery goroutine
// (s.process) is recovered independently of the sweep-tick-level recovery in
// safeSweep, and still releases its semaphore slot / in-flight claim / wg
// count so the sweeper keeps functioning on the next tick.
func TestDispatchOneRecoversPanic(t *testing.T) {
	s := NewSweeper(nil, WithWorkers(1))
	sem := make(chan struct{}, 1)
	var wg sync.WaitGroup

	sem <- struct{}{} // simulate dispatchOne's caller having acquired the slot
	if !s.claim(99) {
		t.Fatal("claim of fresh id 99 should succeed")
	}

	// d.url is empty and d.secret is empty; process() will attempt an HTTP
	// POST to an empty URL, which errors rather than panics via the real
	// client — so instead we rely on the nil pool inside recordAttempt (called
	// from process on any outcome) to produce the panic deterministically.
	d := dueDelivery{id: 99, webhookID: "wh-1", payload: []byte("{}"), attemptCount: 0, url: "", secret: ""}
	s.dispatchOne(context.Background(), d, sem, &wg)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// dispatchOne's goroutine finished — panic (if any) was recovered and
		// cleanup defers (wg.Done, sem release, s.release) still ran.
	case <-time.After(5 * time.Second):
		t.Fatal("dispatchOne goroutine did not finish — panic may have propagated")
	}

	// Confirm cleanup ran: the slot was released back...
	select {
	case sem <- struct{}{}:
	default:
		t.Error("semaphore slot was not released after dispatchOne's goroutine finished")
	}
	// ...and the in-flight claim was released, so id 99 can be claimed again.
	if !s.claim(99) {
		t.Error("id 99 was not released from the in-flight set")
	}
}

// TestResolveHookSecretSignsWithPlaintext guards the PAT-2009 sweeper fix:
// with PATCHED_KEK set the stored secret is "penc1:..." ciphertext, and a
// sweeper that signed with the stored value would send a signature no
// receiver can verify. The key used must be the plaintext the customer was
// shown, for encrypted and legacy plaintext rows alike.
func TestResolveHookSecretSignsWithPlaintext(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	env, err := envelope.New(key)
	if err != nil {
		t.Fatal(err)
	}
	const plain = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	stored, err := env.EncryptString(plain)
	if err != nil {
		t.Fatal(err)
	}
	if stored == plain {
		t.Fatal("test setup: the secret was not encrypted")
	}
	got, err := resolveHookSecret(env, stored)
	if err != nil {
		t.Fatalf("resolve encrypted secret: %v", err)
	}
	if string(got) != plain {
		t.Fatalf("resolved secret = %q, want the plaintext", got)
	}
	body := []byte(`{"event_type":"software.unapproved_detected"}`)
	if Sign(got, body) != Sign([]byte(plain), body) || Sign(got, body) == Sign([]byte(stored), body) {
		t.Fatal("signature must be computed with the plaintext secret, not the stored ciphertext")
	}

	legacy, err := resolveHookSecret(env, plain)
	if err != nil || string(legacy) != plain {
		t.Fatalf("legacy plaintext row: got %q, %v", legacy, err)
	}
}
