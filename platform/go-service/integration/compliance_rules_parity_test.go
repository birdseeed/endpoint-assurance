//go:build integration

package integration

// PAT-2059: migration 0033_compliance_findings_rules.sql sits below
// patched-api-01's MIGRATION_FLOOR=56 and was never recorded as applied on
// that box, so its four rule_keys were missing from compliance_rules there:
//   patched_macos_disk_encryption_off
//   patched_win_disk_encryption_off
//   patched_macos_removable_storage_unencrypted
//   patched_win_removable_storage_unencrypted
// A device reporting FileVault or BitLocker disabled therefore never got a
// finding on prod: there was no rule for its "disk_encryption_off" signal to
// evaluate against. 0174_compliance_rules_parity.sql backfills the four rows
// idempotently.
//
// This test asserts the fix end to end: post a macOS payload with a
// disk_encryption_off finding (FileVault off) and a Windows payload with the
// same finding (BitLocker off), run the extractor, and confirm each device
// gets a 'fail' compliance_evaluations row against its platform's
// patched_*_disk_encryption_off rule.
//
// This test package builds against whatever migrations/ currently holds, so
// it is green against the repo as committed (0174 present). The red/green
// proof that 0174 is what makes it pass — moving 0033 and 0174 out of
// migrations/, rebuilding a fresh TEST_DATABASE_URL database, and confirming
// this test fails with zero compliance_evaluations rows for these rule_keys
// before restoring both files — was run manually during PAT-2059's
// implementation and is not re-run by CI on every commit.

import (
	"context"
	"io"
	"net/http"
	"testing"

	"patched.im/api/internal/extractor"
)

func TestComplianceRulesParity_DiskEncryptionFindingMacOS(t *testing.T) {
	ctx := context.Background()
	body := fixtureData(t, "valid", "with-disk-encryption-finding-macos.json")

	resp := postInventory(t, signedInventoryRequest(t, body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /v1/inventory: want 200, got %d: %s", resp.StatusCode, raw)
	}
	if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}

	assertDiskEncryptionFindingEvaluated(t, "PAT2059MAC01", "patched_macos_disk_encryption_off")
}

func TestComplianceRulesParity_DiskEncryptionFindingWindows(t *testing.T) {
	ctx := context.Background()
	body := fixtureData(t, "valid", "with-disk-encryption-finding-windows.json")

	resp := postInventory(t, signedInventoryRequest(t, body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /v1/inventory: want 200, got %d: %s", resp.StatusCode, raw)
	}
	if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}

	assertDiskEncryptionFindingEvaluated(t, "PAT2059WIN01", "patched_win_disk_encryption_off")
}

// assertDiskEncryptionFindingEvaluated confirms the device got exactly one
// 'fail' compliance_evaluations row against ruleKey. Before 0174 this rule
// row does not exist on a prod-shaped database, so the query returns zero
// rows instead of a 'fail' one — that absence is the failure mode 0174 fixes.
func assertDiskEncryptionFindingEvaluated(t *testing.T, serial, ruleKey string) {
	t.Helper()
	ctx := context.Background()

	var count int
	var status string
	err := env.pool.QueryRow(ctx, `
		SELECT count(*), coalesce(min(ce.status), '')
		FROM compliance_evaluations ce
		JOIN devices d ON d.id = ce.device_id
		JOIN compliance_rules cr ON cr.id = ce.rule_id
		WHERE d.serial = $1 AND cr.rule_key = $2
	`, serial, ruleKey).Scan(&count, &status)
	if err != nil {
		t.Fatalf("query compliance_evaluations for %s/%s: %v", serial, ruleKey, err)
	}
	if count == 0 {
		t.Fatalf("no compliance_evaluations row for device %s against rule %s — "+
			"rule missing from compliance_rules (the PAT-2059/0174 gap) or the "+
			"finding was not evaluated", serial, ruleKey)
	}
	if count != 1 {
		t.Fatalf("device %s / rule %s: want exactly 1 evaluation, got %d", serial, ruleKey, count)
	}
	if status != "fail" {
		t.Errorf("device %s / rule %s: want status=fail, got %q", serial, ruleKey, status)
	}
}
