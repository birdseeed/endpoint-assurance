# Endpoint Assurance case study

## The problem

Most endpoint management tools will happily tell you a device exists and is checking in, but that is a long way from knowing whether the software on it is authorised, whether its security controls are actually working, or whether the evidence you are looking at is current. Patched Endpoint Assurance tried to close that gap by pulling inventory, configuration checks, software governance, CVE findings and audit reports into one place, while being explicit about anything it could not see.

I deliberately kept it as an observation and verification layer rather than another management tool, so remediation went back through the customer's own Intune, Jamf or patching platform. Some of the older code in the agents folder still contains patching and deployment work from before I settled on that boundary.

## Architecture

The agents posted inventory to a Go API, which authenticated the request and stored the raw payload. A separate asynchronous extractor then turned those payloads into device, application and compliance tables in PostgreSQL. Splitting receipt from interpretation meant I could test the ingestion contract and the reporting logic independently.

The customer portal was a separate, stateless FastAPI application that used verified Cloudflare Access identity and only ever read data scoped to the customer's own tenant. The staff dashboard was a different Python service again. Keeping customer, staff and data handling apart meant a mistake in one could not hand someone the authority of another.

The rule that shaped most of the design was that an unknown is never counted as safe. If a device did not report its OS version, if its encryption state could not be read, or if a report page came back incomplete, it shows as unknown rather than quietly passing. The [architecture overview](../platform/docs/architecture-overview.md) is the system map, and the [deployment log](../platform/go-service/docs/architecture.md) records how it was actually run.

## Three pieces of code worth reading

**Encryption state, end to end.** The [end to end regression test](../platform/go-service/integration/pat2496_encryption_state_test.go) posts realistic agent payloads through ingestion and extraction, then checks the result on the device roster, device page, insurance view and reports. I wrote it this way because an earlier test had seeded a key the real agent never sent, so it passed while the product showed the wrong answer. Testing through the real path is what caught it.

**A summary that has to agree with the full calculation.** The [software presence equivalence test](../platform/go-service/integration/unapproved_presence_equivalence_test.go) randomly changes synthetic estates and compares the precomputed summary against a full recalculation. The [concurrency tests](../platform/go-service/integration/unapproved_presence_concurrency_test.go) then run ingestion, policy changes, rebuilds and retries against each other to make sure the summary does not drift under load.

**Tenant boundaries and request signing.** [Portal authorisation](../platform/go-service/internal/portalauth) keeps every query inside a tenant, and [request authentication](../platform/go-service/internal/auth) signs agent requests with HMAC bound to a timestamp and nonce so a captured request cannot be replayed.

## Testing

By 6 October the platform had 123 route parity checks and synthetic coverage across 14 report types, and the portal's recorded runs covered 2,814 unit test cases and 981 browser test cases, counting parametrised cases, alongside read only checks against the running service on desktop and phone. Those numbers are from the runs at the time; I have not rerun the whole suite against this combined repository. [TESTING.md](../platform/go-service/docs/TESTING.md) describes the local and database backed test gates.

## How I worked

I was the only engineer, and I owned the product, the architecture, the security boundaries and every decision about what was accepted and released. The code was written with AI assistance. Every piece of work was a ticket with its own tests and evidence, changes went through pull requests and CI, a second model reviewed each change for correctness and security before it could be closed, and deployments were read back from the servers to confirm what was actually running.

## Why it stopped

The service never opened public signup. By October I had concluded that the SaaS market was crowded, that running a multi tenant service on my own carried more administration than it was worth, and that I would rather go back to the consumer Mac updater that was the original idea behind Patched. I retired the service permanently on 7 October 2026 and decommissioned the infrastructure.

## About this snapshot

This repository combines five original repositories into one, with a fresh history. Old GitHub Actions workflows are kept in `ci-archive` folders so they do not run, the generated CVE sync binary is excluded, and server addresses, hostnames and tokens in the documentation have been replaced with placeholders. Some scripts and docs still refer to the original repository layout.

On 1 and 2 November I hardened two authentication paths: agent requests can no longer be signed over the body alone, and dashboard sessions are now bound to verified Cloudflare Access tokens. Both are described in [SECURITY.md](../SECURITY.md).
