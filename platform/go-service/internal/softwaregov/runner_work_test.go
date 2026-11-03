package softwaregov

import (
	"context"
	"testing"
	"time"

	"patched.im/api/internal/graphmail"
)

func TestRunnerWorkDeadlineComposition(t *testing.T) {
	// Raising keeps its two-minute total cap; preparation must have more
	// headroom than the 30-second allowance exceeded by the CI estate test.
	if summaryWorkTimeout != 90*time.Second || markedBatchTimeout != 120*time.Second {
		t.Fatal("unexpected preparation or marked batch calibration")
	}
	for _, tc := range []struct {
		name       string
		parent     time.Duration
		wantBudget time.Duration
	}{
		{"marked batch", markedBatchTimeout, summaryWorkTimeout},
		{"maintenance phase", time.Minute, time.Minute},
		{"short caller", time.Second, time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent, cancel := context.WithTimeout(context.Background(), tc.parent)
			defer cancel()
			parentDeadline, _ := parent.Deadline()
			before := time.Now()
			if err := boundedWork(parent, summaryWorkTimeout, func(work context.Context) error {
				deadline, ok := work.Deadline()
				if !ok {
					t.Fatal("work has no deadline")
				}
				if tc.parent <= summaryWorkTimeout {
					if !deadline.Equal(parentDeadline) {
						t.Fatalf("work extended parent deadline: %v != %v", deadline, parentDeadline)
					}
				} else if deadline.Before(before.Add(tc.wantBudget)) || deadline.After(time.Now().Add(tc.wantBudget)) {
					t.Fatalf("work budget is not %s: deadline=%v", tc.wantBudget, deadline)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if parent.Err() != nil {
				t.Fatal("finishing child work cancelled its parent")
			}
		})
	}
}

func TestMailUncertainAcceptanceRetainsAtLeastOncePolicy(t *testing.T) {
	if !classifyMailError(&graphmail.DeliveryUncertainError{}) {
		t.Fatal("uncertain Graph acceptance must remain retriable for software-governance alerts")
	}
}
