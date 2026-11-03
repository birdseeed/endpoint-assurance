package extractor

// PAT-1992: local_admins.accounts[].account_state, the Windows agent's read
// of the built-in RID-500 Administrator's enabled state. Covers the
// validation gate (enum, type), payload decoding, and persistence under the
// complete/partial semantics upsertLocalAdmins already enforces.

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func pat1992PayloadWithAccount(t *testing.T, account map[string]any) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(loadFixture(t), &m); err != nil {
		t.Fatalf("unmarshal base: %v", err)
	}
	m["local_admins"] = map[string]any{
		"collection_status": "complete",
		"accounts":          []any{account},
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func pat1992BuiltinAccount(state any, include bool) map[string]any {
	a := map[string]any{
		"name":           "MACHINE\\Administrator",
		"principal_type": "user",
		"builtin":        true,
		"sid":            "S-1-5-21-1-2-3-500",
	}
	if include {
		a["account_state"] = state
	}
	return a
}

func TestLocalAdminsValidateAccountStateEnum(t *testing.T) {
	for _, st := range []string{"enabled", "disabled", "unknown"} {
		if err := ValidatePayload(pat1992PayloadWithAccount(t, pat1992BuiltinAccount(st, true))); err != nil {
			t.Errorf("account_state %q: want accepted, got %v", st, err)
		}
	}

	// Absent key: an agent that predates the field. Must still be accepted.
	if err := ValidatePayload(pat1992PayloadWithAccount(t, pat1992BuiltinAccount(nil, false))); err != nil {
		t.Errorf("account_state absent: want accepted, got %v", err)
	}
	// Explicit null is treated as absent, the same as sid.
	if err := ValidatePayload(pat1992PayloadWithAccount(t, pat1992BuiltinAccount(nil, true))); err != nil {
		t.Errorf("account_state null: want accepted (treated as absent), got %v", err)
	}

	for _, st := range []string{"", "Disabled", "DISABLED", "locked", "true"} {
		err := ValidatePayload(pat1992PayloadWithAccount(t, pat1992BuiltinAccount(st, true)))
		if err == nil || !strings.Contains(err.Error(), "account_state") {
			t.Errorf("account_state %q: want an account_state enum error, got %v", st, err)
		}
	}

	for _, v := range []any{true, false, 0, 1.5, []any{"disabled"}, map[string]any{"state": "disabled"}} {
		err := ValidatePayload(pat1992PayloadWithAccount(t, pat1992BuiltinAccount(v, true)))
		if err == nil || !strings.Contains(err.Error(), "account_state: must be a string") {
			t.Errorf("account_state %#v: want a must-be-a-string error, got %v", v, err)
		}
	}
}

func TestLocalAdminsPayloadDecodesAccountState(t *testing.T) {
	var p payload
	if err := json.Unmarshal(pat1992PayloadWithAccount(t, pat1992BuiltinAccount("disabled", true)), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.LocalAdmins == nil || len(p.LocalAdmins.Accounts) != 1 {
		t.Fatalf("LocalAdmins: got %+v", p.LocalAdmins)
	}
	if got := p.LocalAdmins.Accounts[0].AccountState; got == nil || *got != "disabled" {
		t.Errorf("AccountState: got %v, want disabled", got)
	}

	for _, include := range []bool{false, true} { // absent, then explicit null
		var p2 payload
		if err := json.Unmarshal(pat1992PayloadWithAccount(t, pat1992BuiltinAccount(nil, include)), &p2); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got := p2.LocalAdmins.Accounts[0].AccountState; got != nil {
			t.Errorf("AccountState (null key present=%v): got %q, want nil", include, *got)
		}
	}
}

func pat1992AccountState(t *testing.T, ctx context.Context, tx pgx.Tx, deviceID, name string) *string {
	t.Helper()
	var st *string
	if err := tx.QueryRow(ctx,
		`SELECT account_state FROM local_admin_accounts WHERE device_id = $1::uuid AND name = $2`,
		deviceID, name,
	).Scan(&st); err != nil {
		t.Fatalf("select account_state for %q: %v", name, err)
	}
	return st
}

func stateString(p *string) string {
	if p == nil {
		return "<NULL>"
	}
	return *p
}

// TestLocalAdminsAccountStatePersistence: complete stores what was sent;
// partial with the key absent keeps a stored state; partial with an explicit
// value overwrites; a later complete without the key resets to NULL (the
// roster is replaced in full, and a stale state is not carried across).
func TestLocalAdminsAccountStatePersistence(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping local_admins account_state DB test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newLocalAdminsTestDevice(t, ctx, tx, "PAT1992STATE001")
	const admin = "MACHINE\\Administrator"
	const alice = "MACHINE\\alice"
	sid500 := "S-1-5-21-1-2-3-500"

	// 1. complete with disabled on the built-in; alice has no state.
	if _, err := upsertLocalAdmins(ctx, tx, deviceID, &localAdminsPart{
		CollectionStatus: "complete",
		Accounts: []localAdminPart{
			{Name: admin, PrincipalType: "user", Builtin: true, Sid: &sid500, AccountState: strPtr("disabled")},
			{Name: alice, PrincipalType: "user", Sid: strPtr("S-1-5-21-1-2-3-1001")},
		},
	}, nil); err != nil {
		t.Fatalf("complete upsert: %v", err)
	}
	if got := pat1992AccountState(t, ctx, tx, deviceID, admin); stateString(got) != "disabled" {
		t.Errorf("after complete: built-in state = %s, want disabled", stateString(got))
	}
	if got := pat1992AccountState(t, ctx, tx, deviceID, alice); got != nil {
		t.Errorf("after complete: alice state = %s, want NULL", stateString(got))
	}

	// 2. partial re-sending the built-in WITHOUT account_state must not blank it.
	if _, err := upsertLocalAdmins(ctx, tx, deviceID, &localAdminsPart{
		CollectionStatus: "partial",
		Accounts: []localAdminPart{
			{Name: admin, PrincipalType: "user", Builtin: true, Sid: &sid500},
		},
	}, nil); err != nil {
		t.Fatalf("partial upsert (absent state): %v", err)
	}
	if got := pat1992AccountState(t, ctx, tx, deviceID, admin); stateString(got) != "disabled" {
		t.Errorf("after partial with state absent: built-in state = %s, want disabled (preserved)", stateString(got))
	}

	// 2b. partial carrying an explicit JSON null decodes to nil and is
	// treated as absent: the stored state survives.
	var nullPart localAdminsPart
	if err := json.Unmarshal([]byte(`{"collection_status":"partial","accounts":[{"name":"MACHINE\\Administrator","principal_type":"user","builtin":true,"sid":"S-1-5-21-1-2-3-500","account_state":null}]}`), &nullPart); err != nil {
		t.Fatalf("unmarshal null partial: %v", err)
	}
	if nullPart.Accounts[0].AccountState != nil {
		t.Fatalf("explicit null must decode to nil, got %q", *nullPart.Accounts[0].AccountState)
	}
	if _, err := upsertLocalAdmins(ctx, tx, deviceID, &nullPart, nil); err != nil {
		t.Fatalf("partial upsert (null state): %v", err)
	}
	if got := pat1992AccountState(t, ctx, tx, deviceID, admin); stateString(got) != "disabled" {
		t.Errorf("after partial with state null: built-in state = %s, want disabled (preserved)", stateString(got))
	}

	// 3. partial with an explicit value is newer evidence and overwrites.
	if _, err := upsertLocalAdmins(ctx, tx, deviceID, &localAdminsPart{
		CollectionStatus: "partial",
		Accounts: []localAdminPart{
			{Name: admin, PrincipalType: "user", Builtin: true, Sid: &sid500, AccountState: strPtr("unknown")},
		},
	}, nil); err != nil {
		t.Fatalf("partial upsert (explicit unknown): %v", err)
	}
	if got := pat1992AccountState(t, ctx, tx, deviceID, admin); stateString(got) != "unknown" {
		t.Errorf("after partial with explicit unknown: built-in state = %s, want unknown", stateString(got))
	}

	// 4. partial inserting a new entry stores its state.
	if _, err := upsertLocalAdmins(ctx, tx, deviceID, &localAdminsPart{
		CollectionStatus: "partial",
		Accounts: []localAdminPart{
			{Name: "CONTOSO\\Administrator", PrincipalType: "user", Builtin: true, Sid: strPtr("S-1-5-21-9-9-9-500"), AccountState: strPtr("enabled")},
		},
	}, nil); err != nil {
		t.Fatalf("partial upsert (new entry): %v", err)
	}
	if got := pat1992AccountState(t, ctx, tx, deviceID, "CONTOSO\\Administrator"); stateString(got) != "enabled" {
		t.Errorf("partial-inserted entry state = %s, want enabled", stateString(got))
	}

	// 5. unavailable writes nothing, state included.
	if _, err := upsertLocalAdmins(ctx, tx, deviceID, &localAdminsPart{
		CollectionStatus: "unavailable",
		Accounts: []localAdminPart{
			{Name: admin, PrincipalType: "user", Builtin: true, Sid: &sid500, AccountState: strPtr("enabled")},
		},
	}, nil); err != nil {
		t.Fatalf("unavailable upsert: %v", err)
	}
	if got := pat1992AccountState(t, ctx, tx, deviceID, admin); stateString(got) != "unknown" {
		t.Errorf("after unavailable: built-in state = %s, want unknown (untouched)", stateString(got))
	}

	// 6. complete without the key: roster replaced in full, state NULL.
	if _, err := upsertLocalAdmins(ctx, tx, deviceID, &localAdminsPart{
		CollectionStatus: "complete",
		Accounts: []localAdminPart{
			{Name: admin, PrincipalType: "user", Builtin: true, Sid: &sid500},
		},
	}, nil); err != nil {
		t.Fatalf("second complete upsert: %v", err)
	}
	if got := pat1992AccountState(t, ctx, tx, deviceID, admin); got != nil {
		t.Errorf("after complete with state absent: built-in state = %s, want NULL", stateString(got))
	}
}
