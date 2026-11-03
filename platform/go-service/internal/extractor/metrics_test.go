package extractor

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"patched.im/api/internal/metrics"
)

// TestRecordProcessError_DeadLetterBoundary pins down the exact behaviour
// PAT-1377's DeadLetterRows rule depends on: "dead_letter" must increment
// only on the attempt that reaches maxAttempts, not on every failure, and
// "error" must increment on every failure including that one. claimBatch
// only ever claims rows WHERE extraction_attempts < maxAttempts, so
// row.Attempts == maxAttempts (post-increment) is the exact signal that this
// failure permanently exhausts retries.
func TestRecordProcessError_DeadLetterBoundary(t *testing.T) {
	metrics.ExtractorRowsProcessed.Reset()

	// One attempt below the cap: ordinary retryable failure.
	recordProcessError(maxAttempts - 1)
	if got := testutil.ToFloat64(metrics.ExtractorRowsProcessed.WithLabelValues("error")); got != 1 {
		t.Errorf("error counter after below-cap failure: got %v want 1", got)
	}
	if got := testutil.ToFloat64(metrics.ExtractorRowsProcessed.WithLabelValues("dead_letter")); got != 0 {
		t.Errorf("dead_letter counter after below-cap failure: got %v want 0", got)
	}

	// The attempt that hits the cap: this is the row's last-ever claim
	// (claimBatch's WHERE excludes attempts >= maxAttempts), so it must also
	// count as dead_letter.
	recordProcessError(maxAttempts)
	if got := testutil.ToFloat64(metrics.ExtractorRowsProcessed.WithLabelValues("error")); got != 2 {
		t.Errorf("error counter after at-cap failure: got %v want 2", got)
	}
	if got := testutil.ToFloat64(metrics.ExtractorRowsProcessed.WithLabelValues("dead_letter")); got != 1 {
		t.Errorf("dead_letter counter after at-cap failure: got %v want 1", got)
	}
}

// TestRecordProcessError_NeverExceedsCap documents why attempts can never
// exceed maxAttempts in practice (claimBatch's WHERE clause guarantees it),
// and that the boundary check still behaves sanely (>=, not ==) if that
// invariant were ever violated.
func TestRecordProcessError_NeverExceedsCap(t *testing.T) {
	metrics.ExtractorRowsProcessed.Reset()

	recordProcessError(maxAttempts + 1)
	if got := testutil.ToFloat64(metrics.ExtractorRowsProcessed.WithLabelValues("dead_letter")); got != 1 {
		t.Errorf("dead_letter counter for attempts beyond cap: got %v want 1", got)
	}
}
