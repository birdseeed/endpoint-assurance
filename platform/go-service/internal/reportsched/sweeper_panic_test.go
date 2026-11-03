package reportsched

// PAT-867: proves a panicking sweep tick does not crash the process. chi's
// middleware.Recoverer only guards HTTP handler goroutines — this background
// ticker had no equivalent, so an unrecovered panic in processOne (a bad
// schedule row, a bug in the injected GenerateFunc) would previously take
// down the entire patched-api binary.

import (
	"context"
	"testing"
	"time"
)

// TestSafeSweepRecoversPanic uses a nil pool to trigger a genuine panic inside
// Sweep -> processOne's s.pool.Begin call (the same nil-pool-panics
// convention already used elsewhere in this repo, e.g. the webhook package's
// own TestSafeSweepRecoversPanic and enrolment_test.go's
// TestEnrolHandler_NewFlatFormatPassesValidation). Before safeSweep existed,
// calling s.Sweep directly here would panic and crash this test's whole
// process; after the fix, safeSweep recovers and the test completes normally.
func TestSafeSweepRecoversPanic(t *testing.T) {
	s := New(nil, nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.safeSweep(context.Background())
	}()

	select {
	case <-done:
		// safeSweep returned normally — the panic was recovered.
	case <-time.After(5 * time.Second):
		t.Fatal("safeSweep did not return — panic may have propagated instead of recovering")
	}
}
