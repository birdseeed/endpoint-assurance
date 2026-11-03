package protectedsoftware

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func strp(s string) *string { return &s }

type captureQuerier struct{ queries []string }

func (q *captureQuerier) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	q.queries = append(q.queries, sql)
	return absentRow{}
}

type absentRow struct{}

func (absentRow) Scan(...any) error { return pgx.ErrNoRows }

func TestProductNameDoesNotMatchProcessNameOrOverrideStrongIdentity(t *testing.T) {
	q := &captureQuerier{}
	if _, err := Check(context.Background(), q, "tenant", Identity{ProductName: strp("Agent.exe")}); err != nil {
		t.Fatal(err)
	}
	if len(q.queries) != 1 || !strings.Contains(q.queries[0], "lower(ps.product_name)") || strings.Contains(q.queries[0], "ps.process_name") {
		t.Fatalf("display name queried executable identity: %v", q.queries)
	}
	q.queries = nil
	if _, err := Check(context.Background(), q, "tenant", Identity{BundleID: strp("com.example.other"), ProductName: strp("Agent.exe")}); err != nil {
		t.Fatal(err)
	}
	if len(q.queries) != 1 || !strings.Contains(q.queries[0], "lower(ps.bundle_id)") || strings.Contains(q.queries[0], "lower(ps.product_name)") {
		t.Fatalf("failed strong identity fell back to display name: %v", q.queries)
	}
}

// TestCheck_NoIdentityAtAll proves Check never queries the database (and
// therefore never matches anything) for an Identity with no fields set at
// all — the fail-closed contract this package exists to hold: absence of
// any identifier must never be treated as a match.
func TestCheck_NoIdentityAtAll(t *testing.T) {
	match, err := Check(context.Background(), panicQuerier{}, "tenant", Identity{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match != nil {
		t.Fatalf("empty identity matched: %+v", match)
	}
}

// panicQuerier fails the test if Check ever issues a query for an empty
// Identity — proving the fail-closed, no-DB-round-trip short circuit.
type panicQuerier struct{}

func (panicQuerier) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	panic("Check must not query the database for an empty Identity")
}

func TestHasStrongIdentifier(t *testing.T) {
	cases := []struct {
		name string
		id   Identity
		want bool
	}{
		{"nothing set", Identity{}, false},
		{"team id only", Identity{TeamID: strp("TEAM123")}, true},
		{"bundle id only", Identity{BundleID: strp("com.example.app")}, true},
		{"publisher without product code", Identity{WinPublisher: strp("Example Inc.")}, false},
		{"product code without publisher", Identity{WinProductCode: strp("{GUID}")}, false},
		{"publisher and product code", Identity{WinPublisher: strp("Example Inc."), WinProductCode: strp("{GUID}")}, true},
		{"process name only is not strong", Identity{ProcessName: strp("Example.exe")}, false},
		{"blank team id string does not count", Identity{TeamID: strp("  ")}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.id.hasStrongIdentifier(); got != c.want {
				t.Fatalf("hasStrongIdentifier() = %v, want %v", got, c.want)
			}
		})
	}
}
