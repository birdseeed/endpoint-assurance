# ADR-0012: Tier 3 Graph access model, full options analysis (companion to ADR-0003)

**Vocabulary note (2026-09-13, PAT-1700):** buyer-facing tiers were retired on 2026-09-11 (PAT-1566); the internal enum is now `assurance` and `managed`. "Tier 3" below means Full Endpoint Management, which maps to `managed`. The decision text is unchanged.

**Renumbering note (2026-09-13, PAT-1700):** this file used to sit at `0003-tier3-graph-access-full.md`, duplicating ADR-0003's number. It is not a separate decision from ADR-0003: it is the full options analysis behind that same decision, kept as a companion document, so it is renumbered here to ADR-0012 rather than folded, to preserve the existing summary/full-detail split and the cross-references both files already carry. No content below this note was changed.

**Status:** Superseded by [ADR-0010](0010-microsoft-graph-scope-reconciliation.md) (2026-08-14). Originally: Proposed (spike output — PAT-350); the implementation this document specifies was later deleted under PAT-911 (2026-07-14) — see the summary ADR, [0003-tier3-graph-access.md](0003-tier3-graph-access.md), for that history. Retained in full as reference material: the GDAP rules verification, credential custody model, and per-tenant consent flow below remain valid if Tier 3 orchestration is rebuilt.
**Deciders:** Andy (sole maintainer, pre-incorporation)
**Security review gate:** GitHub-Non-Author-Review (non-author review before first Tier 3 customer)
**Spike:** PAT-350 — this document; blocks PAT-351 (policy-set authoring model)

---

## Context

Patched's Tier 3 offering is an orchestration layer that applies CIS-aligned Intune policy-sets into each customer's own Intune tenant via Microsoft Graph. The fundamental identity question: **how does Patched's control plane authenticate and authorise writes into a tenant it does not own?**

The answer drives every Tier 3 design decision downstream:
- How are secrets stored and rotated (one secret vs one-per-customer)?
- How is consent granted per customer (manual step vs fully automated)?
- How is access revoked when a customer offboards?
- What auditable evidence exists of every write operation?
- What Microsoft partner programme obligations does Patched need to meet?

Microsoft's partner/identity rules shift frequently. This ADR was written against the state with citations to Microsoft Learn. Verify the GDAP and permission sections before first Tier 3 customer onboarding.

---

## Graph endpoints and minimum permission requirements

These are the Intune Graph resources that cover the full Tier 3 enforcement surface.

| Resource | Graph path | API version | Permission required |
|---|---|---|---|
| Settings Catalog policies (macOS/Windows config) | `deviceManagement/configurationPolicies` | **beta only** | `DeviceManagementConfiguration.ReadWrite.All` |
| Legacy device configurations (incl. macOS custom `.mobileconfig`) | `deviceManagement/deviceConfigurations` | v1.0 | `DeviceManagementConfiguration.ReadWrite.All` |
| Compliance policies | `deviceManagement/deviceCompliancePolicies` | v1.0 | `DeviceManagementConfiguration.ReadWrite.All` |
| Remediation scripts | `deviceManagement/deviceHealthScripts` | v1.0 | `DeviceManagementScripts.ReadWrite.All` |
| Platform scripts | `deviceManagement/deviceManagementScripts` | v1.0 | `DeviceManagementScripts.ReadWrite.All` |

**Minimum application permission set (two scopes):**

1. `DeviceManagementConfiguration.ReadWrite.All` — covers config profiles, compliance policies, and Settings Catalog.
2. `DeviceManagementScripts.ReadWrite.All` — covers remediation and detection scripts.

> ⚠️ **July 2025 change:** As of July 31, 2025, `DeviceManagementConfiguration.ReadWrite.All` no longer covers script endpoints. `DeviceManagementScripts.ReadWrite.All` became the required permission for `deviceHealthScripts`, `deviceManagementScripts`, `deviceShellScripts`, `deviceComplianceScripts`, and `deviceCustomAttributeShellScripts`. Requesting only `DeviceManagementConfiguration.ReadWrite.All` for scripts silently fails (403) against the new enforcement. Request **both** scopes.
>
> Source: [How to Use Microsoft Entra ID to Access Intune APIs](https://learn.microsoft.com/en-us/intune/intune-service/developer/intune-graph-apis)

**Notably NOT included** (not needed for Tier 3 enforcement scope):
- `DeviceManagementApps.ReadWrite.All` — app deployment (out of scope).
- `DeviceManagementManagedDevices.ReadWrite.All` — managed device actions (wipe, retire, etc.).
- `DeviceManagementServiceConfig.ReadWrite.All` — enrollment configuration.
- `DeviceManagementManagedDevices.PrivilegedOperations.All` — remote actions.

`configurationPolicies` (Settings Catalog) is a **beta API only**. Microsoft supports beta Intune Graph APIs in production scenarios (no v1.0 equivalent exists), but the API carries standard beta caveats: breaking changes can occur without versioning notice. This is an accepted risk given that every commercial MDM tool in the market uses these same beta endpoints.

Source: [Working with Intune in Microsoft Graph](https://learn.microsoft.com/en-us/graph/api/resources/intune-graph-overview?view=graph-rest-1.0)

---

## GDAP rules verification

### What GDAP is

Granular Delegated Admin Privileges replaces the legacy DAP (Delegated Admin Privileges) model. GDAP is time-bounded, role-scoped, and follows Zero Trust. Legacy DAP is deprecated and not backward compatible with GDAP.

Source: [GDAP introduction](https://learn.microsoft.com/en-us/partner-center/customers/gdap-introduction)

### Role required for Intune configuration writes

**Intune Administrator** is the correct and only fully-privileged write role for all Intune operations via Graph under GDAP. This covers "all aspects of the Intune product" per the GDAP role-by-task guidance.

Source: [GDAP role guidance by task](https://learn.microsoft.com/en-us/partner-center/customers/gdap-least-privileged-roles-by-task) — [Workloads supported by GDAP](https://learn.microsoft.com/en-us/partner-center/customers/gdap-supported-workloads)

### Legacy auto-consent (preconsent) is gone under GDAP

Under the legacy DAP/AdminAgent model, a partner app could be pre-consented across all customer tenants automatically. **This preconsent model does not exist under GDAP.** Each customer tenant requires explicit consent.

> "With the DAP admin agent model, you can grant your partner-managed app a set of configured permissions for all your customers in your tenant without review. This process is called preconsent... This legacy behavior doesn't align with the minimum-rights concept in the Microsoft identity platform."

Source: [Migrate CPV/CSP applications to use GDAP](https://learn.microsoft.com/en-us/partner-center/developer/gdap-and-secure-application-model)

### Consent flow for app-only (client credentials) — critical constraint

> "Explicit application-only consent to a customer tenant isn't supported for third-party application developers who use GDAP. Such application-only consent isn't compatible with the time-limited minimum-rights contract that GDAP manages."
>
> "If the app uses application only permissions, it must be manually consented to, either by the partner or customer having any of the three roles (Cloud Application Administrator, Application Administrator), using tenant-wide admin consent URL."

Source: [GDAP FAQ](https://learn.microsoft.com/en-us/partner-center/customers/gdap-faq)

**What this means in practice:** The programmatic consent API (`New-PartnerCustomerApplicationConsent`, Partner Center REST) only covers **delegated** permissions. For the client-credentials (app-only) flow that Patched's automation uses, consent in each customer tenant must be granted via:

```
https://login.microsoftonline.com/{customer-tenant-id}/adminconsent?client_id={patched-app-client-id}
```

A human with Global Administrator, Cloud Application Administrator, or Application Administrator in the customer tenant must open this URL and approve. This can be the partner (via GDAP relationship with the Application Administrator role included) or the customer's own admin. It is a one-time step per customer tenant.

After consent is granted, the cross-tenant token acquisition works as:

```
POST https://login.microsoftonline.com/{CUSTOMER_TENANT_ID}/oauth2/v2.0/token
body: grant_type=client_credentials&client_id={PATCHED_APP_CLIENT_ID}&client_secret={SECRET}&scope=https://graph.microsoft.com/.default
```

The customer tenant's Entra ID validates Patched's app credentials because the app has been consented there. The resulting token is scoped to the customer tenant and carries the application permissions.

### GDAP-unsupported Intune operations

The following Intune operations do **not** work under GDAP:

- Microsoft Tunnel server enrollment
- Intune Connector for Active Directory (install/configure)
- Mobile Threat Defense connector (install/configure)
- Microsoft Defender for Endpoint connector (install/configure)
- Any other Intune connector install/configuration (list is explicitly non-exhaustive)

Source: [Workloads supported by GDAP — Intune section](https://learn.microsoft.com/en-us/partner-center/customers/gdap-supported-workloads)

**Patched's enforcement paths:** configurationPolicies, deviceConfigurations (including custom `.mobileconfig`), deviceCompliancePolicies, deviceHealthScripts, deviceManagementScripts. **None of these hit the GDAP-unsupported list.** The Tier 3 enforcement surface is clear of GDAP blockers.

Note: Apple DEP/ADE connector, Android Enterprise enrollment connector, and Apple MDM Push Certificate are not explicitly named in the GDAP-unsupported list but likely fall under the "not limited to" language. Patched does not need to configure these connectors — that prerequisite is on the customer to have set up before Tier 3 onboarding.

### CSP program prerequisites

GDAP is a CSP program feature. Patched must be enrolled as one of:
- Direct-bill partner
- Indirect provider
- Indirect reseller

All paths require: Microsoft AI Cloud Partner Program membership + Microsoft Partner Agreement accepted + production Partner Center tenant with an Admin Agent role.

The Microsoft Action Pack does not grant GDAP access. There is no simpler programme that provides GDAP capabilities.

Source: [Supported CSP partner relationships](https://learn.microsoft.com/en-us/partner-center/enroll/csp-supported-partner-relationships)

---

## Decision

**Recommended architecture: one multi-tenant Entra app exercised through GDAP-scoped access, with manual admin consent URL per customer tenant.**

Specifically:
- One app registration in Patched's Entra ID tenant (never re-registered per customer).
- Multi-tenant supported account types.
- Two application permissions: `DeviceManagementConfiguration.ReadWrite.All` + `DeviceManagementScripts.ReadWrite.All`.
- Client certificate preferred over client secret for production (see credential custody section below).
- Per-customer onboarding step: GDAP relationship established (Intune Administrator + Application Administrator roles) → partner opens admin consent URL in customer tenant → one-time approval → token acquisition works.
- Token is acquired against the **customer tenant's** authority endpoint (`login.microsoftonline.com/{customer-tenant-id}/...`), not Patched's. Patched's credentials (client_id + cert/secret) are stable across all customers.

**Near-term pragmatic path (pre-CSP enrollment):**

CSP enrollment takes time. For the first Tier 3 customers before CSP is active, use the **fallback path** (Option B below): customer's own admin grants consent manually via the admin consent URL. This removes the GDAP relationship dependency entirely and enables Tier 3 operations with no CSP prerequisite. The token-acquisition mechanics are identical — only the consent grant process differs.

Migrate to the GDAP path (Option A) once CSP is enrolled and a Tier 3 customer pipeline exists.

---

## Options considered

### Option A: Multi-tenant app + GDAP (recommended target state)

| Dimension | Assessment |
|---|---|
| Access model | Partner's app is consented in customer tenant via GDAP-facilitated admin consent URL |
| Credential count | One (app secret/cert in Patched control plane) — not per-customer |
| Revocation | Two levers: GDAP relationship expiry/termination + app consent revocation |
| Audit trail | Partner Center relationship log + Entra sign-in logs in customer tenant |
| Prerequisite | CSP programme enrollment; GDAP relationship per customer |
| Permission granularity | Time-boxed relationship with Intune Administrator role; can be narrowed per-customer |
| Automation of consent | App-only consent cannot be automated under GDAP — manual URL per customer |

**Pros:** Time-bounded access (GDAP expiry), dual-lever revocation, Partner Center audit trail, aligns with Microsoft's stated partner security model. Customer can terminate the relationship without involving Patched.

**Cons:** CSP enrollment has lead time (weeks). GDAP relationship must be established per customer before onboarding can proceed. App-only consent cannot be automated — always a manual URL-click per customer onboarding.

### Option B: Multi-tenant app + manual admin consent, no GDAP (near-term / fallback)

| Dimension | Assessment |
|---|---|
| Access model | Customer admin grants consent directly via admin consent URL |
| Credential count | One (same as Option A) |
| Revocation | Single lever: customer admin removes app consent in Entra ID > Enterprise Applications |
| Audit trail | Entra sign-in logs in customer tenant only; no Partner Center layer |
| Prerequisite | None — no CSP or GDAP required |
| Permission granularity | Coarser — no time-boxing, no GDAP role scoping |
| Automation of consent | Same as Option A for app-only: manual URL per customer |

**Pros:** No CSP/GDAP prerequisite. Simplest possible model. Token mechanics identical to Option A. Appropriate for first 1-2 Tier 3 customers before CSP is enrolled.

**Cons:** No time-boxing. If Patched's app credentials are compromised, revocation requires customer to act in their own tenant (no Partner Center override). No GDAP relationship structure to lean on for audit. Harder to systematically manage at scale (many customers, no unified Partner Center view of relationships).

### Option C: Per-customer app registration

Register a separate Entra app in Patched's tenant for each customer, with the customer's admin granting consent to their specific app.

**Rejected.** Multiplies secret/cert management burden by customer count. No revocation advantage over Option B. Increases blast radius of a key compromise (no separation benefit since all apps are in Patched's tenant). Operationally unscalable. No GDAP parallel structure.

### Option D: Customer-tenant managed identity

Create an Azure managed identity in the customer's own Azure subscription and have Patched impersonate it.

**Rejected.** Requires the customer to have Azure (not just M365/Intune). Most target SMEs are M365-only (no Azure subscription). Creates customer-tenant infrastructure that Patched has to manage remotely. No network access to the customer's Azure management plane without VPN or Azure Arc. Not a realistic model for SME targets.

---

## Credential custody

The recommended model stores **one** credential set (client secret or certificate) in Patched's control plane:

```
Patched control plane (example-api-host)
  └── App credential (client secret or cert private key)
      └── Used for ALL customer tenants (cross-tenant token acquisition)
```

This is a **high-value credential**: compromise grants access to every customer tenant where the app is consented. Mitigation:

- **Certificate preferred over secret** for production. A certificate's private key never leaves the key store; a client secret is a naked string. Use a self-signed cert with the public key uploaded to the app registration; store the private key in an HSM or secrets manager.
- **Secret if using client secret:** minimum 24-character random string, stored in environment variable / secrets manager on `example-api-host` (never committed). Rotate on a schedule and immediately on any suspected compromise. Rotation is a Patched-side operation only — no customer action required.
- **Revocation story on compromise:** Patched rotates the credential in Patched's Entra ID immediately → all tokens using the old credential are invalidated within their remaining TTL (max 1 hour for client-credentials tokens). No customer-side action needed for the credential itself; per-tenant app consent remains intact.

**Near-term (pre-HSM):** `PATCHED_GRAPH_CLIENT_SECRET` environment variable on `example-api-host`, in `/etc/patched-api/env`, restricted to root. This matches the existing pattern for bearer token and HMAC keys. Flag for GitHub-Non-Author-Review.

---

## Per-tenant consent flow (step by step)

**Option A (GDAP path, target state):**

1. Patched establishes a GDAP relationship with the customer in Partner Center. Roles: **Intune Administrator** (for Graph operations) + **Cloud Application Administrator** or **Application Administrator** (to grant app consent).
2. Patched engineer uses their GDAP delegated access to open the admin consent URL in the customer tenant:
   ```
   https://login.microsoftonline.com/{customer-tenant-id}/adminconsent?client_id={patched-app-client-id}
   ```
3. The engineer signs in with their Patched identity (delegated via GDAP), approves consent. This grants `DeviceManagementConfiguration.ReadWrite.All` and `DeviceManagementScripts.ReadWrite.All` as application permissions in the customer tenant.
4. Patched records the customer's `tenantId` in the `tenants` table (`intune_tenant_id` column, already present).
5. Control plane acquires tokens using `intune_tenant_id` as the authority, with Patched's static app credentials.

**Option B (plain consent, near-term):**

1. Patched sends the customer's admin the admin consent URL.
2. Customer admin opens the URL, signs in, approves.
3. Patched records the customer's `tenantId`.
4. Same token acquisition as Option A.

---

## Open items

1. **Cross-tenant GDAP proof requires a second tenant.** The proof in `main.go` runs against a single tenant (Patched's own). Proving cross-tenant delegation end-to-end requires a throwaway M365 dev tenant acting as mock customer — set `PATCHED_TENANT_ID` to that tenant's ID, with the app consented there. Defer to first real Tier 3 onboarding unless a dev tenant is spun up for testing.

2. **CSP enrollment timeline.** CSP indirect reseller is the practical path for a small MSP. Lead time: application, MPA acceptance, vetting. Start the application when Tier 3 pipeline has 1+ warm prospects (IoM Steam Packet per PAT-194 is the trigger). Note: as of September 1, 2025, indirect resellers also need an active CSP indirect reseller tenant + verified PLA ID.

3. **Certificate vs secret decision.** For the first Tier 3 customer, a client secret is acceptable if stored per the custody policy above. Migrate to a certificate (self-signed, private key in a secrets manager) before Tier 3 reaches more than 2-3 customers. Flag for GitHub-Non-Author-Review.

4. **`configurationPolicies` beta API acceptance.** The Settings Catalog endpoint (`/beta/deviceManagement/configurationPolicies`) is beta-only. Accept this risk — it is the only API surface for modern Settings Catalog, and all commercial competitors use it. Track Microsoft Graph changelog for graduation to v1.0 or breaking changes.

5. **Tenant isolation model.** The single credential operates across all consented customer tenants. The only isolation is per-tenant consent scope. Verify that a token acquired for tenant A cannot be used against tenant B (it cannot — JWT audience claim is tenant-specific, confirmed by Azure AD design).

6. **GDAP unsupported connector operations.** If a Tier 3 customer does not have Apple DEP/ADE or Android Enterprise connectors configured, Patched cannot set these up under GDAP. This is an onboarding prerequisite — customer must have enrollment infrastructure in place. Document this in Tier 3 onboarding checklist.

---

## Consequences

**What becomes possible:**

- Token acquisition against any consented customer tenant is a single Go function call with stable Patched credentials.
- Offboarding: customer revokes app consent in their Entra ID — access is cut immediately. Under GDAP path, Patched can also terminate the relationship from Partner Center.
- Audit: every Graph API call appears in the customer tenant's Entra ID sign-in logs under the app's service principal.
- Policy-set authoring (PAT-351) can proceed — this ADR settles the auth model it depends on.

**What becomes harder:**

- Customer onboarding always has a manual consent step. This cannot be eliminated for app-only permissions under GDAP. Budget 10–15 minutes per customer for the consent URL flow.
- Credential compromise is a fleet-wide event (all consented customers). Mitigation is cert-over-secret + fast rotation.
- CSP enrollment is a business process obligation, not a code change.

---

## Security note for GitHub-Non-Author-Review

- Single credential across all customer tenants: flag for non-author review of custody model.
- Admin consent URL flow: confirm there is no phishing vector in the runbook (URL is constructed programmatically, not pasted from an email).
- Token TTL: client-credentials tokens are max 3600 seconds; Patched should not cache beyond that. Implement token refresh in the Go service, not in env vars.
- `DeviceManagementScripts.ReadWrite.All` is a powerful scope — permits arbitrary shell script creation on managed devices. Scope justification: Patched's remediation scripts are the mechanism for CIS controls that are not expressible as Settings Catalog settings alone (e.g. macOS script-driven controls). Narrow to `Read` only until the first script deployment is implemented.
