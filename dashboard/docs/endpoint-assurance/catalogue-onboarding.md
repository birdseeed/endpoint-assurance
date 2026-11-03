# Customer application catalogue onboarding

**Ticket: PAT-1298.** This is the operating and commercial contract for
assessing a customer's line-of-business applications for the Patched software
catalogue. It applies during Endpoint Assurance onboarding and throughout a
Managed Patching or Full Endpoint Management service.

The customer buys specialist judgement about whether an application can be
managed safely. A product name in an inventory is not evidence that Patched can
verify or update it. Never claim catalogue coverage until the evidence below is
recorded and the application has passed the live verifier.

## Intake record

Start from Section F of `scoping-questionnaire.md`. Create one record per
application and retain:

- vendor, product, platform, processor architecture and deployed version;
- approximate device or user count, business owner and business criticality;
- the customer's current update method and maintenance window constraints;
- the vendor's first-party download and version-reference locations;
- installer format, expected payload and any authenticated, licensed or
  customer-specific download constraint;
- the customer approver for adding it to the approved software catalogue.

Inventory discovery can add a missing application to this intake. It does not
silently approve it or turn it into managed coverage.

## What “we verify your apps” means

An application is **verified and manageable** only when Patched can establish
all of the following from stable, first-party evidence:

1. A version reference that can identify the current vendor release without
   scraping an ambiguous marketing page or trusting a third-party catalogue.
2. A reproducible vendor download path for the expected platform and
   architecture. Redirects must still terminate at a vendor-controlled source.
3. The expected installer and payload type, including the exact package or
   application selected from a container where more than one could match.
4. A pinned publisher identity: Apple Team ID and valid code signature plus
   notarization where applicable on macOS, or the expected Authenticode signer
   and valid signature on Windows.
5. A recorded digest and provenance result for the inspected artefact, with
   malware-verdict handling under the current catalogue policy.
6. A nightly verifier path that repeats version, source, signature, payload and
   integrity checks before publication. The application must produce a current
   passing result before it can be allowlisted for managed installation.

Record the evidence source, expected values, verification date and reviewer.
Changing vendor ownership, signer identity, download host, payload layout or
installer type invalidates the prior acceptance and returns the application to
review.

## Fail-closed dispositions

Give every intake record one visible disposition:

- **Verified and manageable:** all evidence above is complete and the nightly
  verifier can exercise it. Managed installation remains subject to the
  customer's tier, policy and explicit allowlist.
- **Protected, advisory only:** the application is important enough to retain,
  but a stable version, source, signer or payload contract cannot be verified.
  Patched reports the limitation and does not automate installation or claim
  patch coverage.
- **Unsupported or manual:** the installer is only available through an
  interactive or customer-specific portal, requires repackaging, has no
  trustworthy publisher identity, or otherwise cannot be handled safely by the
  current agent. Record the customer's existing manual owner and process.

An alert, verification error or unsupported result is evidence of a gap, not a
healthy result. Do not hide it by removing the application from the record or
substituting an unverified third-party source.

## Commercial boundary

The initial assessment of the customer's declared line-of-business
applications is onboarding work and must be reflected in the scoped onboarding
fee. The questionnaire's internal banding accounts for a large or difficult
application set before the order is signed.

During an active recurring service, assessing ordinary additions needed to
keep the agreed in-scope estate current draws from the included specialist time
and is recorded in the customer's service plan. This is intentionally not a
per-label surcharge. Maintenance needed to restore verification for an
already-accepted catalogue entry is a service-integrity obligation, not
billable catalogue onboarding.

Quote separately, in advance, when the request is materially different work:

- a bulk application migration or a newly acquired business unit or estate;
- custom packaging, repackaging or installer engineering;
- vendor remediation or reverse engineering needed to create a trustworthy
  source, signature or version contract;
- a project deadline or volume that cannot be met within the agreed recurring
  specialist capacity.

If a mid-term request crosses that boundary, keep the application visible as
protected/advisory or unsupported/manual until the customer accepts the project
scope. Commercial deferral must never turn an unverified application into
managed coverage.

## Customer record and review

For each application, retain the intake record, disposition, evidence links,
customer approver, decision date and any exception or manual owner. Review open
protected/advisory and unsupported/manual records at the agreed service cadence
and include the next action in the customer's 90-day plan. Link engineering or
vendor-remediation work to its delivery ticket rather than duplicating project
management in the customer record.
