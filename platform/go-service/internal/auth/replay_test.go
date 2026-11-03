package auth_test

import (
	"fmt"
	"testing"
	"time"

	"patched.im/api/internal/auth"
)

func TestValidateTimestamp_Fresh(t *testing.T) {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	if err := auth.ValidateTimestamp(ts, 300*time.Second); err != nil {
		t.Fatalf("fresh timestamp rejected: %v", err)
	}
}

func TestValidateTimestamp_Missing(t *testing.T) {
	err := auth.ValidateTimestamp("", 300*time.Second)
	if err != auth.ErrMissingTimestamp {
		t.Fatalf("expected ErrMissingTimestamp, got %v", err)
	}
}

func TestValidateTimestamp_Malformed(t *testing.T) {
	err := auth.ValidateTimestamp("not-a-number", 300*time.Second)
	if err != auth.ErrBadTimestamp {
		t.Fatalf("expected ErrBadTimestamp, got %v", err)
	}
}

func TestValidateTimestamp_TooOld(t *testing.T) {
	old := fmt.Sprintf("%d", time.Now().Add(-10*time.Minute).Unix())
	err := auth.ValidateTimestamp(old, 300*time.Second)
	if err == nil {
		t.Fatal("expected error for 10-min-old timestamp")
	}
}

func TestValidateTimestamp_TooFarFuture(t *testing.T) {
	future := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	err := auth.ValidateTimestamp(future, 300*time.Second)
	if err == nil {
		t.Fatal("expected error for 10-min future timestamp")
	}
}

func TestValidateTimestamp_EdgeWithinSkew(t *testing.T) {
	edge := fmt.Sprintf("%d", time.Now().Add(-299*time.Second).Unix())
	if err := auth.ValidateTimestamp(edge, 300*time.Second); err != nil {
		t.Fatalf("timestamp at edge of window should be valid: %v", err)
	}
}

func TestValidateTimestamp_EdgeOutsideSkew(t *testing.T) {
	edge := fmt.Sprintf("%d", time.Now().Add(-301*time.Second).Unix())
	err := auth.ValidateTimestamp(edge, 300*time.Second)
	if err == nil {
		t.Fatal("timestamp just outside window should be invalid")
	}
}
