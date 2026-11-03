package cpepropose

import "fmt"

// currentCustomerTenantSQL is the one definition of a tenant that counts
// wherever a tenant count gates anything in the proposer: outbound
// eligibility (MinOutboundTenants), publish, the re-check's tenant votes and
// the digest's hold-back (PAT-2138 re-review, P2-1). t is the SQL alias of
// a tenants row. A tenant counts only when it is a current customer:
//
//   - tenant_kind = 'customer' (never Patched's own internal and staging
//     tenants);
//   - not revoked (revoked_at IS NULL: a revoked tenant cannot ingest);
//   - not a trial at all (is_trial). A trial is self-provisioned without
//     email verification (POST /v1/trial/provision), so counting even an
//     active one would let one person open two trials and meet the
//     two-customer rule alone (PAT-2138 fifth review, P2-1);
//   - not being decommissioned (any tenant_decommission directive other
//     than mode 'none').
//
// Its installations must also sit on active devices (last seen within
// cvematch.ActiveDeviceWindow), which each query applies through its
// devices join on (id, tenant_id).
func currentCustomerTenantSQL(t string) string {
	return fmt.Sprintf(`(%[1]s.tenant_kind = 'customer'
		AND %[1]s.revoked_at IS NULL
		AND NOT COALESCE(%[1]s.is_trial, false)
		AND NOT EXISTS (SELECT 1 FROM tenant_decommission tdc WHERE tdc.tenant_id = %[1]s.id AND tdc.mode <> 'none'))`, t)
}
