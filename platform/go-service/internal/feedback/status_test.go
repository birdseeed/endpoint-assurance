package feedback

import (
	"errors"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/graphmail"
)

func TestStatusForLinearExactUmbrellaMapping(t *testing.T) {
	for _, tc := range []struct {
		state  string
		labels []string
		typ    string
		want   string
		known  bool
	}{
		{"Backlog", []string{"needs-triage"}, TypeBug, StatusReceived, true},
		{"Backlog", []string{"claude-triaged"}, TypeFeature, StatusReceived, true},
		{"Backlog", nil, TypeBug, StatusPlanned, true},
		{"Todo", nil, TypeBug, StatusPlanned, true},
		{"Blocked", nil, TypeFeature, StatusPlanned, true},
		{"RoadMap", nil, TypeFeature, StatusRoadmap, true},
		{"In Progress", nil, TypeBug, StatusInProgress, true},
		{"In Review", nil, TypeBug, StatusInProgress, true},
		{"Done", nil, TypeQuestion, StatusShipped, true},
		{"Canceled", nil, TypeQuestion, StatusClosedNotPlanned, true},
		{"Duplicate", nil, TypeFeature, StatusClosedMerged, true},
		{"Todo", nil, TypeQuestion, StatusReceived, true},
		{"Backlog", nil, TypeQuestion, StatusReceived, true},
		{"Unknown", nil, TypeBug, "", false},
	} {
		got, known := statusForLinear(tc.state, tc.labels, tc.typ)
		if got != tc.want || known != tc.known {
			t.Errorf("state=%q labels=%v type=%q got=%q/%t want=%q/%t", tc.state, tc.labels, tc.typ, got, known, tc.want, tc.known)
		}
	}
}

func TestFeedbackStatusEmailContent(t *testing.T) {
	for _, status := range []string{StatusShipped, StatusClosedNotPlanned, StatusClosedMerged} {
		subject, body := renderFeedbackStatusEmail("FB-42", "A customer title\nwith a break", status)
		for _, want := range []string{"FB-42", "A customer title with a break"} {
			if !strings.Contains(subject+body, want) {
				t.Errorf("status %s missing %q: %s / %s", status, want, subject, body)
			}
		}
		if strings.Contains(subject+body, "linear.app") || strings.Contains(subject+body, "PAT-") {
			t.Errorf("status %s leaked Linear data", status)
		}
		merged := strings.Contains(body, "This has been merged with an existing request.")
		if merged != (status == StatusClosedMerged) {
			t.Errorf("status %s merged line=%t", status, merged)
		}
	}
}

func TestFeedbackEmailFailureClassificationAndBackoff(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{graphmail.ErrNotConfigured, false},
		{&graphmail.SendError{Status: 400}, false},
		{&graphmail.SendError{Status: 429}, true},
		{&graphmail.TokenError{Status: 401}, false},
		{errors.New("network reset"), true},
	} {
		if got := feedbackEmailRetriable(tc.err); got != tc.want {
			t.Errorf("%T retriable=%t want %t", tc.err, got, tc.want)
		}
	}
	if feedbackEmailBackoff(1) != time.Minute || feedbackEmailBackoff(99) != time.Hour {
		t.Fatal("feedback email backoff is not bounded")
	}
	if !feedbackEmailUncertain(&graphmail.DeliveryUncertainError{}) || feedbackEmailUncertain(errors.New("pre-send failure")) {
		t.Fatal("uncertain Graph delivery classification is wrong")
	}
}

func TestReconcileBackoffBounded(t *testing.T) {
	if reconcileBackoff(1) != time.Hour || reconcileBackoff(99) != 24*time.Hour {
		t.Fatal("reconciliation backoff is not bounded")
	}
}
