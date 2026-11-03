package handlers

// Compatibility-shaped wrappers keep the handler call sites and focused
// resolver tests small while the actual policy contract lives in apppolicy
// for reuse by endpoint lifecycle evaluation.

import "patched.im/api/internal/apppolicy"

type tenantPolicy = apppolicy.Policy
type installedAppPolicyIdentity = apppolicy.InstalledIdentity

type tenantPolicyIndex struct{ canonical apppolicy.Index }

func buildTenantPolicyIndex(policies []tenantPolicy) tenantPolicyIndex {
	return tenantPolicyIndex{canonical: apppolicy.BuildIndex(policies)}
}

func (index tenantPolicyIndex) resolveAppPolicy(teamID, bundleID, identifierKind, name, deviceOS string) (tenantPolicy, bool) {
	return index.canonical.Resolve(teamID, bundleID, identifierKind, name, deviceOS)
}

func devicePolicyPlatform(deviceOS string) string { return apppolicy.DevicePlatform(deviceOS) }

func installedWingetID(identifier, identifierKind, deviceOS string) string {
	return apppolicy.InstalledWingetID(identifier, identifierKind, deviceOS)
}

func policyMatchesInstalledApp(policy tenantPolicy, installed installedAppPolicyIdentity) bool {
	return apppolicy.Matches(policy, installed)
}

func tenantPolicyIdentityKey(policy tenantPolicy) string { return apppolicy.IdentityKey(policy) }

func effectiveTenantPolicies(policies []tenantPolicy, deviceOS string) []tenantPolicy {
	return apppolicy.EffectivePolicies(policies, deviceOS)
}
