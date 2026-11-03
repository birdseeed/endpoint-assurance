//go:build integration

package integration

// PAT-1992: an updated Windows agent's payload carrying
// local_admins.accounts[].account_state must be accepted end to end (not
// 400'd by the schema gate), and each state must land in
// local_admin_accounts.account_state against the real migrated schema.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"patched.im/api/internal/extractor"
)

func TestInventoryLocalAdminAccountStateRoundTrip(t *testing.T) {
	ctx := context.Background()
	body := fixtureData(t, "valid", "with-local-admins-account-state-windows.json")

	resp := postInventory(t, signedInventoryRequest(t, body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /v1/inventory: want 200, got %d: %s", resp.StatusCode, raw)
	}
	var ingest struct {
		RawPayloadID int64 `json:"raw_payload_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ingest); err != nil {
		t.Fatalf("decode ingest response: %v", err)
	}
	if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	assertNoExtractionError(t, ingest.RawPayloadID)

	rows, err := env.pool.Query(ctx, `
		SELECT la.name, la.account_state
		FROM local_admin_accounts la
		JOIN devices d ON d.id = la.device_id
		WHERE d.tenant_id = $1::uuid AND d.serial = 'PAT1992WIN01'
	`, env.tenantID)
	if err != nil {
		t.Fatalf("query local_admin_accounts: %v", err)
	}
	defer rows.Close()
	got := map[string]*string{}
	for rows.Next() {
		var name string
		var state *string
		if err := rows.Scan(&name, &state); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[name] = state
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	want := map[string]string{
		`DESKTOP-PAT1992\Administrator`: "disabled",
		`CONTOSO\Administrator`:         "unknown",
		`DESKTOP-PAT1992\alice`:         "<NULL>",
	}
	if len(got) != len(want) {
		t.Fatalf("roster: got %d rows %v, want %d", len(got), got, len(want))
	}
	for name, w := range want {
		st, ok := got[name]
		if !ok {
			t.Errorf("roster missing %q", name)
			continue
		}
		g := "<NULL>"
		if st != nil {
			g = *st
		}
		if g != w {
			t.Errorf("%s account_state: got %s, want %s", name, g, w)
		}
	}
}
