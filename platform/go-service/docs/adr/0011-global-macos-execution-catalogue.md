# ADR-0011: Global curated macOS execution catalogue

**Status:** Accepted (2026-09-07)
**Date:** 2026-09-07
**Decider:** Andy
**Related:** PAT-1481, PAT-919, PAT-1298, PAT-806, PAT-941, PAT-1474
**Supersedes:** ADR-0007's requirement for Windows and macOS actuation parity. Assurance parity remains binding.

---

## Context

Patched is reinstating third-party patching as an optional macOS capability. Windows application deployment remains with Patch My PC, Robopack, Intune or another customer management platform. This is intended to differentiate Patched for customers that do not have Jamf or another suitable macOS patching mechanism without rebuilding the former broad packaging product.

The earlier implementation contains useful controls, but its domains overlap:

- `software_products` and `software_product_aliases` own curated package-neutral identity.
- `catalogue_products` and `catalogue_platform_targets` own legacy execution review and pipeline state.
- `app_catalog_entries` is a legacy latest-version projection used by posture.
- `tenant_app_policies` owns tenant governance policy but does not express independently verified install and uninstall capability.
- `tenant_catalogue` and `tenant_allowlists` are legacy per-tenant execution stores.
- `known_app_bundles` is global observed path evidence useful to removal, but is not removal authority.
- `discovery_jobs` models the retired broad nightly mirror and verification pipeline.
- `mandatory_install_intents` contains strong delivery-binding patterns, but its cross-platform mandatory-install scope no longer matches the product boundary.

The former automation also verified and fanned work out across Installomator's long tail. That produced disproportionate GitHub Actions spend, particularly on macOS runners, without customer demand. PAT-1474 therefore made the broad verifier, mirror, smoke and behavioural workflows manual-only. This ADR preserves that quarantine.

## Decision

### 1. Assurance remains platform-neutral; execution does not

Inventory, identity, findings, evidence and governance remain equivalent across Windows and macOS. New Patched application execution is macOS-only.

Windows policy may still produce findings and remediation exports. It must not create Patched install, update or uninstall authority.

### 2. One global catalogue, separate tenant authority

There is one signed execution catalogue with `scope = "global"`, consumed identically by every tenant. It contains only public product identity and verified macOS execution capability. It contains no tenant identifier, customer name, policy, device scope or requesting actor.

Tenant-specific signed configuration supplies the independent authorisation and targeting. An endpoint may act only on the intersection of:

1. a currently verified operation in the global signed catalogue;
2. an active tenant execution policy for that exact product, platform and operation; and
3. a short-lived device-bound execution intent derived from both.

Possession of any one or two of those artefacts is insufficient.

### 3. Package-neutral identity remains canonical

`software_products` and reviewed `software_product_aliases` remain the source of product identity. Execution metadata must reference that identity rather than create a third independent product namespace.

During migration, each retained `catalogue_products` row gains a unique `software_product_id`. New execution catalogue rows require that link. `catalogue_platform_targets.identity`, labels, installer names and signing identities remain evidence or resolver keys, not product identity.

An execution policy may be requested only for a resolved product with an exact or high-confidence reviewed alias. A display name alone, or a Team ID shared by several applications, cannot authorise catalogue promotion.

### 4. Install, update and uninstall are independent capabilities

Add a global operation record beneath each macOS catalogue target. Conceptually:

```text
catalogue_target_operations
  target_id
  operation             install | update | uninstall
  state                 pending_verification | verified | blocked | suspended | retired
  recipe_revision
  verified_release_id   nullable for uninstall
  verified_at
  verification_detail
```

Installation and update require a vendor-direct source, artifact hash, accepted Team ID, Apple signature and notarisation evidence, plus a supported installer recipe. Uninstall requires exact installed identity and a separately reviewed removal recipe. An observed `known_app_bundles` path may inform that recipe but can never make it verified by itself.

Suspending one operation does not silently suspend or approve another. For example, a product may remain safe to uninstall when installation is blocked because the vendor artifact changed.

### 5. Tenant policy automatically enrols missing software

The dashboard may present governance and execution settings in one policy workflow, but their database responsibilities remain separate. Add a tenant execution-policy record linked to the global product and macOS target. Conceptually:

```text
tenant_app_execution_policies
  tenant_id
  software_product_id
  catalogue_target_id
  install_enabled
  update_enabled
  uninstall_enabled
  scope
  activation_state       pending_catalogue | active | blocked | disabled
  policy_generation
  requested_by
  requested_at
```

When an operator enables install, update or uninstall, one transaction must:

1. resolve and lock the canonical software identity;
2. create or reuse the single global macOS target;
3. create missing requested operations as `pending_verification`;
4. upsert the tenant execution policy as `pending_catalogue` unless every requested operation is already verified;
5. append policy and catalogue-enrolment audit records; and
6. insert or coalesce durable verification work through a transactional outbox.

The unique global identity constraint and transaction lock make concurrent requests from several tenants converge on one target and one operation record. Repeating the same request is idempotent.

Automatic addition therefore means automatic **enrolment**, not automatic approval. No install, update or uninstall intent is issued while a requested operation is pending, blocked, suspended or retired.

Inventory observation alone does not enrol all discovered applications. The trigger is an explicit tenant execution-policy request. Private or customer-internal software may create a pending record for review, but cannot be published in the global catalogue if doing so would disclose customer information or require a tenant-private source. It remains blocked and must use the customer's deployment mechanism.

### 6. Verification work is demand-driven and bounded

GitHub Actions is an execution venue for Apple-specific checks, not the catalogue database or queue.

The platform stores durable verification requests and coalesces them by:

- catalogue target;
- operation;
- candidate version;
- normalised vendor-source URL hash;
- artifact hash when known; and
- recipe revision.

Cheap release discovery and HTTP metadata checks run on Patched's Linux infrastructure for only:

- the deliberately curated core; and
- products referenced by at least one active or pending tenant execution policy.

A macOS runner is dispatched only for first onboarding, a detected new release, a changed recipe or an explicit diagnostic. Each dispatch receives a bounded batch, processes it sequentially and cannot expand its own matrix. The initial implementation cap is five targets per job with one paid catalogue-verification job running at a time. Excess work remains queued for a later dispatch and is reported visibly.

Every new artifact still requires Apple signature, Team ID and notarisation verification. Full install-and-launch smoke testing is required for first onboarding, recipe changes and an explicitly recorded risk exception, rather than automatically for every routine version using an unchanged verified recipe. Behavioural analysis remains manual and exceptional.

There is no scheduled GitHub Actions sweep of the Installomator manifest, no automatic mirror job, no upstream-label replication and no downstream smoke or behavioural fan-out. The manual legacy diagnostics remain unable to sign or publish.

### 7. Publication and endpoint authority fail closed

Only `verified` macOS operations are emitted into the signed global catalogue. The signed entry binds:

- canonical software product and catalogue target identifiers;
- platform and operation;
- resolver or recipe revision;
- version and artifact SHA-256 where applicable;
- accepted Team ID and notarisation result;
- installed bundle identity;
- verification time; and
- catalogue generation and anti-rollback data.

Publication is atomic. A failed target cannot remove or weaken unrelated last-known-good entries. Suspension publishes the loss of authority in a newer generation; endpoints retain evidence but must not begin new work from an older cached generation.

Device execution uses a macOS-only intent model with the binding and append-only delivery properties proven by `mandatory_install_intents`: exact device, tenant policy generation, target, operation, version or removal recipe, catalogue content hash, expiry, attempt and state history. The successor must not inherit the Windows execution path merely because the legacy table was platform-neutral.

### 8. The curated core is evidence-led

No catalogue size is promised in advance. An initial named core is accepted only where each product has:

- stable reviewed identity;
- a legitimate vendor-direct source;
- operation-specific supported recipes;
- verifiable signing and notarisation evidence;
- licensing terms compatible with the operation; and
- a bounded maintenance owner and suspension rule.

Customer onboarding grows the same global catalogue. A release verified for one tenant is reused by every tenant, while policy remains tenant-specific.

## Migration plan

1. **Keep quarantine intact.** Do not change the manual-only legacy workflows or ship the executor while the new contracts are designed.
2. **Unify identity.** Link retained `catalogue_products` to `software_products`, reconcile duplicates and refuse ambiguous backfill rather than guessing.
3. **Add operation and tenant-policy state.** Introduce global operation records, tenant execution policies, audit and the transactional verification outbox. These are initially non-actuating.
4. **Build the read and review surfaces.** Show pending, verified, blocked and suspended states and the difference between catalogue enrolment and tenant activation.
5. **Replace discovery.** Run Linux metadata discovery for the eligible set and bounded macOS verification only for concrete changed work.
6. **Publish a versioned global catalogue.** Add operation-specific entries while retaining strict `scope = "global"`, signature and anti-rollback verification.
7. **Add the macOS consumer.** Implement device-bound intents and post-operation evidence in a separately releasable module. Keep the assurance-only bundle available.
8. **Prove and release.** Complete GitHub-Non-Author-Review, hostile contract tests, cost measurement and installed macOS evidence before customer use.
9. **Retire duplicate legacy stores.** Only after consumers have moved, remove `tenant_catalogue`, package execution use of `tenant_allowlists`, and legacy `app_catalog_entries` authority. If posture still needs `app_catalog_entries`, make it a read-only projection of verified global releases rather than an independent source.

## Required tests

- Two tenants requesting the same absent product and operation create one global target, one operation and one verification job.
- A policy created while verification is pending remains non-actionable.
- Verification failure or suspension prevents new intent creation without deleting audit history.
- Install verification cannot authorise uninstall, and uninstall verification cannot authorise install.
- Name-only and signer-only ambiguity fail closed.
- A Windows policy cannot create Patched execution work.
- The global signed artefact contains no tenant-derived fields.
- A stale or rolled-back catalogue cannot combine with a newer tenant policy.
- A batch over the configured cap leaves deterministic queued work and creates no additional matrix jobs.
- Removing policy cancels only unstarted work and never implies the opposite operation.
- Successful endpoint status includes exact post-operation installed or absent evidence; absence is accepted only from a complete authoritative inventory.

## Consequences

Patched gains a differentiated macOS patching capability without taking on Windows deployment or speculative maintenance of Installomator's catalogue. Customer demand grows one reusable global asset rather than creating per-tenant package definitions.

The main cost is a deliberate multi-stage state model: policy requests can remain pending while global verification completes. That delay is preferable to turning one tenant's policy edit into immediate global execution authority.

The legacy code remains useful evidence and may supply reviewed components, but it is not the architecture. Any reuse must prove that it preserves the identity boundary, operation-specific verification, cost caps and three-part endpoint authority defined here.
