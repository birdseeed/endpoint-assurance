package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMandatoryInstallStatusBodyLimitIsExact(t *testing.T) {
	exact := strings.Repeat("a", maxBodyBytes)
	req := httptest.NewRequest(http.MethodPost, "/v1/mandatory-install-status", strings.NewReader(exact))
	body, err := readMandatoryInstallStatusBody(httptest.NewRecorder(), req)
	if err != nil || len(body) != maxBodyBytes {
		t.Fatalf("exact-limit body len=%d err=%v", len(body), err)
	}

	prefix := `{}` + strings.Repeat(" ", maxBodyBytes-2)
	timestamp, nonce, secret := fmt.Sprintf("%d", time.Now().Unix()), "pat1399-oversize-nonce", "prefix-signing-secret"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(http.MethodPost + "\nmandatory_install_status\n" + timestamp + "\n" + nonce + "\n" + prefix))
	req = httptest.NewRequest(http.MethodPost, "/v1/mandatory-install-status", strings.NewReader(prefix+"x"))
	req.Header.Set("X-Patched-Timestamp", timestamp)
	req.Header.Set("X-Patched-Nonce", nonce)
	req.Header.Set("X-Patched-Signature", hex.EncodeToString(mac.Sum(nil)))
	rr := httptest.NewRecorder()
	// A signed, valid-JSON prefix exactly at the limit plus one trailing byte
	// must fail before authentication or parsing. A nil pool makes accidental
	// continuation immediately visible as a test failure.
	MandatoryInstallStatusHandler(nil, nil, 5*time.Minute)(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("signed prefix plus trailing byte status=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestMandatoryIntentStateMachineFailsClosed(t *testing.T) {
	allowed := []struct{ from, to string }{{"delivered", "received"}, {"delivered", "failed"}, {"received", "installing"}, {"received", "failed"}, {"installing", "succeeded"}, {"installing", "failed"}}
	for _, tr := range allowed {
		if !mandatoryTransitions[tr.from][tr.to] {
			t.Errorf("missing %s -> %s", tr.from, tr.to)
		}
	}
	for _, tr := range [][2]string{{"delivered", "succeeded"}, {"received", "succeeded"}, {"failed", "installing"}, {"cancelled", "received"}, {"succeeded", "installing"}} {
		if mandatoryTransitions[tr[0]][tr[1]] {
			t.Errorf("unsafe transition admitted: %s -> %s", tr[0], tr[1])
		}
	}
}

func TestExpiredMandatoryReceiptRequiresStartedTerminalWork(t *testing.T) {
	for _, tc := range []struct {
		state, requested  string
		durableReceived   bool
		durableInstalling bool
		want              bool
	}{
		{"received", "succeeded", true, false, false},
		{"installing", "succeeded", true, false, false},
		{"installing", "succeeded", true, true, true},
		{"installing", "failed", true, false, true},
		{"delivered", "succeeded", true, false, false},
		{"delivered", "succeeded", true, true, true},
		{"delivered", "failed", true, false, true},
		{"delivered", "failed", false, false, false},
		{"delivered", "received", true, true, false},
		{"received", "installing", true, false, false},
		{"queued", "failed", true, true, false},
	} {
		if got := allowExpiredMandatoryReceipt(tc.state, tc.requested, tc.durableReceived, tc.durableInstalling, false); got != tc.want {
			t.Errorf("allowExpiredMandatoryReceipt(%q,%q,%t,%t)=%t want %t", tc.state, tc.requested, tc.durableReceived, tc.durableInstalling, got, tc.want)
		}
	}
	if !allowExpiredMandatoryReceipt("failed", "succeeded", true, true, true) {
		t.Fatal("operator-stale started attempt could not report its exact late success")
	}
	if allowExpiredMandatoryReceipt("failed", "succeeded", true, true, false) {
		t.Fatal("ordinary terminal failure could be overwritten")
	}
}

func TestMandatoryStatusErrorByteLimit(t *testing.T) {
	if !mandatoryStatusErrorWithinLimit(strings.Repeat("x", 1024)) {
		t.Fatal("exact 1024-byte error was rejected")
	}
	if mandatoryStatusErrorWithinLimit(strings.Repeat("x", 1025)) {
		t.Fatal("1025-byte error was accepted")
	}
	if mandatoryStatusErrorWithinLimit(strings.Repeat("é", 513)) {
		t.Fatal("limit counted runes instead of UTF-8 bytes")
	}
}

func TestMandatoryIntentMigrationHasNoExecutionSurface(t *testing.T) {
	raw, err := os.ReadFile("../../migrations/0110_mandatory_install_intents.sql")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ToLower(string(raw))
	for _, state := range []string{"queued", "delivered", "received", "installing", "succeeded", "failed", "cancelled"} {
		if !strings.Contains(s, "'"+state+"'") {
			t.Errorf("migration lacks state %s", state)
		}
	}
	for _, forbidden := range []string{"sudo ", "/bin/sh", "powershell", "installomator", "create extension"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("migration contains execution surface %q", forbidden)
		}
	}
	for _, required := range []string{"windows_winget_inventory_complete", "windows_winget_inventory_schema", "identifier_kind"} {
		if !strings.Contains(s, required) {
			t.Errorf("migration lacks fail-closed Windows inventory capability field %s", required)
		}
	}
	if strings.Contains(s, "state <> 'queued'") {
		t.Fatal("delivery completeness CHECK admits delivery-shaped cancelled rows")
	}
	if !strings.Contains(s, "state in ('delivered','received','installing','succeeded','failed')") {
		t.Fatal("delivery completeness CHECK does not enumerate only delivery-bearing states")
	}
	if !strings.Contains(s, "mandatory_install_intents_current_uq") || !strings.Contains(s, "where state <> 'cancelled'") {
		t.Fatal("migration lacks partial current-intent uniqueness that retains cancelled history")
	}
	if !strings.Contains(s, "catalogue_product_id  uuid not null references catalogue_products(id) on delete restrict") ||
		!strings.Contains(s, "catalogue_target_id   uuid not null references catalogue_platform_targets(id) on delete restrict") {
		t.Fatal("migration does not explicitly retain durable product/target provenance")
	}
	if !strings.Contains(s, "rollout_id            uuid references ring_version_approvals(id) on delete set null") {
		t.Fatal("migration does not explicitly preserve intent snapshots when rollout history is purged")
	}
	if !strings.Contains(s, "octet_length(reason) <= 1024") {
		t.Fatal("migration does not bound durable operator reasons")
	}
	if !strings.Contains(s, "octet_length(last_error) <= 1024") {
		t.Fatal("migration does not bound device-supplied durable error text")
	}
	if !strings.Contains(s, "operator_recovery_reason") {
		t.Fatal("migration lacks durable operator stale-recovery provenance")
	}
	if !strings.Contains(s, "grant update (mandatory_installed_identity) on catalogue_platform_targets to patched") {
		t.Fatal("migration lacks least-privilege catalogue identity synchronization grant")
	}
	rollback, err := os.ReadFile("../../migrations/0110_mandatory_install_intents_rollback.sql")
	if err != nil {
		t.Fatal(err)
	}
	rollbackText := strings.ToLower(string(rollback))
	if !strings.Contains(rollbackText, "durable mandatory install intent/event evidence exists") {
		t.Fatal("rollback does not refuse destructive removal of durable intent evidence")
	}
	if strings.Contains(rollbackText, "drop column if exists winget_id") ||
		!strings.Contains(rollbackText, "winget_id deliberately remains") {
		t.Fatal("rollback would destroy or reject an existing Winget-only policy")
	}
	if !strings.Contains(s, "tenant_app_policies_tenant_identity_v2_uniq") ||
		!strings.Contains(s, "keep the deployed binary's four-field on conflict arbiter") ||
		!strings.Contains(rollbackText, "tenant_app_policies_tenant_identity_uniq") ||
		!strings.Contains(rollbackText, "distinct policies collide under the legacy tenant app policy identity") {
		t.Fatal("migration/rollback lacks mixed-version old-writer ON CONFLICT compatibility and collision refusal")
	}
	if !strings.Contains(s, ") not valid") || !strings.Contains(s, "validate constraint ring_config_changes_change_type_check") {
		t.Fatal("migration does not replace the audit vocabulary check using NOT VALID then VALIDATE")
	}
}

func TestMandatoryMigrationPreservesOldPolicyWriterConflictArbiterDB(t *testing.T) {
	pool := parConnectOrSkip(t)
	defer pool.Close()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var tenantID string
	if err := tx.QueryRow(ctx, `INSERT INTO tenants(name,bearer_token_hash,hmac_secret) VALUES('pat1399-mixed-writer','\x00','\x00') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	oldWriter := `INSERT INTO tenant_app_policies(tenant_id,name,platform,policy,enforcement_tier)
		VALUES($1::uuid,'Legacy App','windows','approved','patch')
		ON CONFLICT(tenant_id,COALESCE(team_id,''),COALESCE(bundle_id,''),COALESCE(lower(name),''),platform)
		DO UPDATE SET policy=EXCLUDED.policy RETURNING id`
	var firstID, secondID int64
	if err := tx.QueryRow(ctx, oldWriter, tenantID).Scan(&firstID); err != nil {
		t.Fatalf("deployed old writer lost its four-field arbiter after 0110: %v", err)
	}
	if err := tx.QueryRow(ctx, oldWriter, tenantID).Scan(&secondID); err != nil || firstID != secondID {
		t.Fatalf("old writer conflict update failed id=%d/%d err=%v", firstID, secondID, err)
	}
	var legacy, expanded bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE indexname='tenant_app_policies_tenant_identity_uniq'), EXISTS(SELECT 1 FROM pg_indexes WHERE indexname='tenant_app_policies_tenant_identity_v2_uniq')`).Scan(&legacy, &expanded); err != nil || !legacy || !expanded {
		t.Fatalf("mixed-version arbiters legacy=%t expanded=%t err=%v", legacy, expanded, err)
	}
}

// TestMandatoryStatusCrossDeviceAndCrossTenant404DB proves that POST
// /v1/mandatory-install-status's `WHERE id=$1::uuid AND tenant_id=$2::uuid
// AND device_id=$3::uuid` ownership predicate (tenantID/deviceID resolved
// from the authenticated credential, never the request body) produces zero
// rows — a plain 404 "intent not found", never a state change — when the
// caller is not the exact device the intent is bound to, whether that
// mismatch is another device in the same tenant or a device belonging to an
// entirely different tenant.
func TestMandatoryStatusCrossDeviceAndCrossTenant404DB(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('mandatory_install_intents') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		t.Skip("migration 0110 not applied to TEST_DATABASE_URL")
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	token := "pat1399-404-token-" + suffix
	secret := "pat1399404" + strings.Repeat("s", 32) + suffix
	tenantID := parSeedTenant(t, ctx, pool, "pat1399-404-"+suffix, token, secret)

	otherToken := "pat1399-404-other-token-" + suffix
	otherSecret := strings.Repeat("o", 32) + suffix
	otherTenantID := parSeedTenant(t, ctx, pool, "pat1399-404-other-"+suffix, otherToken, otherSecret)

	var deviceA, deviceB, deviceOtherTenant string
	if err := pool.QueryRow(ctx, `INSERT INTO devices(tenant_id,serial,hw_uuid,hostname,os,ring_computed) VALUES($1::uuid,$2,gen_random_uuid(),'device-a','macOS',0) RETURNING id::text`, tenantID, "pat1399-404-a-"+suffix).Scan(&deviceA); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO devices(tenant_id,serial,hw_uuid,hostname,os,ring_computed) VALUES($1::uuid,$2,gen_random_uuid(),'device-b','macOS',0) RETURNING id::text`, tenantID, "pat1399-404-b-"+suffix).Scan(&deviceB); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO devices(tenant_id,serial,hw_uuid,hostname,os,ring_computed) VALUES($1::uuid,$2,gen_random_uuid(),'device-other-tenant','macOS',0) RETURNING id::text`, otherTenantID, "pat1399-404-c-"+suffix).Scan(&deviceOtherTenant); err != nil {
		t.Fatal(err)
	}

	deviceAToken := token + "-device-a"
	deviceATokenHash := sha256.Sum256([]byte(deviceAToken))
	if _, err := pool.Exec(ctx, `INSERT INTO tenant_credentials(tenant_id,bearer_token_hash,hmac_secret,device_id) VALUES($1::uuid,$2,$3,$4::uuid)`, tenantID, deviceATokenHash[:], []byte(secret), deviceA); err != nil {
		t.Fatal(err)
	}
	deviceBToken := token + "-device-b"
	deviceBTokenHash := sha256.Sum256([]byte(deviceBToken))
	if _, err := pool.Exec(ctx, `INSERT INTO tenant_credentials(tenant_id,bearer_token_hash,hmac_secret,device_id) VALUES($1::uuid,$2,$3,$4::uuid)`, tenantID, deviceBTokenHash[:], []byte(secret), deviceB); err != nil {
		t.Fatal(err)
	}
	otherDeviceToken := otherToken + "-device"
	otherDeviceTokenHash := sha256.Sum256([]byte(otherDeviceToken))
	if _, err := pool.Exec(ctx, `INSERT INTO tenant_credentials(tenant_id,bearer_token_hash,hmac_secret,device_id) VALUES($1::uuid,$2,$3,$4::uuid)`, otherTenantID, otherDeviceTokenHash[:], []byte(otherSecret), deviceOtherTenant); err != nil {
		t.Fatal(err)
	}

	var productID string
	if err := pool.QueryRow(ctx, `INSERT INTO catalogue_products(product_key,display_name) VALUES($1,'PAT 1399 404 Example') RETURNING id::text`, "pat1399-404-product-"+suffix).Scan(&productID); err != nil {
		t.Fatal(err)
	}
	var targetID string
	if err := pool.QueryRow(ctx, `INSERT INTO catalogue_platform_targets(product_id,platform,state) VALUES($1::uuid,'macos','published') RETURNING id::text`, productID).Scan(&targetID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1::uuid`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1::uuid`, otherTenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM catalogue_products WHERE id=$1::uuid`, productID)
	})

	label := "pat1399-404-label-" + suffix
	sha := strings.Repeat("a", 64)
	contentHash := strings.Repeat("b", 64)
	var intentID, deliveryID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO mandatory_install_intents (
			tenant_id, device_id, catalogue_product_id, catalogue_target_id,
			platform, label, installed_identity, target_version, verified_sha256,
			verified_signer, catalogue_content_hash, catalogue_generated_at, verified_at,
			rollout_ring, reason, state, delivery_id, delivered_at, expires_at
		) VALUES (
			$1::uuid, $2::uuid, $3::uuid, $4::uuid,
			'macos', $5, 'bundle:com.example.pat1399404', '1.0', $6,
			'TEAM1399', $7, now(), now(),
			0, 'cross-device 404 test', 'delivered', gen_random_uuid(), now(), now() + interval '30 minutes'
		) RETURNING id::text, delivery_id::text`,
		tenantID, deviceA, productID, targetID, label, sha, contentHash).Scan(&intentID, &deliveryID); err != nil {
		t.Fatal(err)
	}

	statusBody := fmt.Sprintf(`{"report_id":%q,"intent_id":%q,"delivery_id":%q,"catalogue_product_id":%q,"catalogue_target_id":%q,"platform":"macos","label":%q,"version":"1.0","sha256":%q,"verified_signer":"TEAM1399","catalogue_content_hash":%q,"state":"received"}`,
		"f3990000-0000-4000-8000-f39900000001", intentID, deliveryID, productID, targetID, label, sha, contentHash)

	callStatus := func(bearer, hmacSecret string) *httptest.ResponseRecorder {
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		nonce := fmt.Sprintf("pat1399-404-nonce-%d", time.Now().UnixNano())
		mac := hmac.New(sha256.New, []byte(hmacSecret))
		mac.Write([]byte("patched-hmac-v3\n" + http.MethodPost + "\nmandatory_install_status\n" + timestamp + "\n" + nonce + "\n" + statusBody))
		req := httptest.NewRequest(http.MethodPost, "/v1/mandatory-install-status", strings.NewReader(statusBody))
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("X-Patched-Timestamp", timestamp)
		req.Header.Set("X-Patched-Nonce", nonce)
		req.Header.Set("X-Patched-Signature", hex.EncodeToString(mac.Sum(nil)))
		rr := httptest.NewRecorder()
		MandatoryInstallStatusHandler(pool, nil, 5*time.Minute)(rr, req)
		return rr
	}

	// Cross-device, same tenant: device B references device A's intent.
	if rr := callStatus(deviceBToken, secret); rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "intent not found") {
		t.Fatalf("cross-device status: want 404 'intent not found', got %d %s", rr.Code, rr.Body.String())
	}

	// Cross-tenant: a device belonging to an entirely different tenant
	// references tenant A's intent.
	if rr := callStatus(otherDeviceToken, otherSecret); rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "intent not found") {
		t.Fatalf("cross-tenant status: want 404 'intent not found', got %d %s", rr.Code, rr.Body.String())
	}

	// Sanity: the exact owning device (device A) can still reach it — proves
	// the two 404s above were a real ownership predicate, not a broken fixture.
	if rr := callStatus(deviceAToken, secret); rr.Code != http.StatusOK {
		t.Fatalf("owning device status: want 200, got %d %s", rr.Code, rr.Body.String())
	}

	// The intent must not have moved state despite the two rejected
	// cross-identity attempts — a 404 must never be a side-channel state change.
	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM mandatory_install_intents WHERE id=$1::uuid`, intentID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "received" {
		t.Fatalf("state after owner-only transition = %q, want received", state)
	}
}
