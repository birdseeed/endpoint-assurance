# Patched Endpoint Assurance

Patched Endpoint Assurance was a Windows and macOS inventory, security assurance and software governance platform that I designed and built in 2026 under Patched.im Ltd, my Isle of Man company. It told an organisation what was actually on its estate, what had changed, what was vulnerable and whether its controls were really working, and then pointed remediation back into the customer's own Intune, Jamf or patching tooling rather than trying to replace it. I retired the service on 7 October 2026 and have published the source here as a portfolio piece, so it is archived code rather than something you should deploy.

## How it was built

The platform ran on three Hetzner VPS hosts, each with a single job, so that load or a fault in one area could not take down another:

| Host | Role |
| --- | --- |
| Server 1 | Operator console, internal dashboard and the PostgreSQL database |
| Server 2 | Customer portal |
| Server 3 | Agent API ingestion |

The hosts talked to each other privately over Tailscale, so nothing administrative was exposed to the public internet, and I chose Tailscale deliberately so the hosts could be moved to AWS or Azure later without redesigning how they reached each other. Public traffic came in through Cloudflare, with Cloudflare Access in front of the portal and console. Backups were encrypted with Restic and stored off site in Cloudflare R2, monitoring and alerting ran through Zabbix, and Better Stack provided external uptime checks and the public status page for customers. The backup helper and monitoring configuration are not included in this repository.

Keeping ingestion on its own host meant a flood of endpoint check ins could not slow the customer portal, and customers never touched the box holding the operator tooling and the data. The weak point, and the first thing I would change if it had grown, was the database sharing a host with the operator console rather than having its own host or a managed service.

All changes went through Git, pull requests and CI rather than being made by hand on the servers, with builds running on isolated, self hosted GitHub Actions runners on my own Proxmox box. The code itself was written with AI assistance, while I owned the product, the architecture, the requirements and every acceptance decision. Work was planned as tickets in Linear, each carrying its own tests and evidence, and every change was reviewed by a second model before it could be closed.

## What is in the repository

| Folder | What it is |
| --- | --- |
| [platform/go-service](platform/go-service) | The Go ingestion API. It authenticates agent requests, stores the raw payloads, and an asynchronous extractor then derives device, application and compliance tables in PostgreSQL, so receiving data and interpreting it stay separate |
| [portal](portal) | The customer portal, a stateless FastAPI application using verified Cloudflare Access identity and tenant scoped reads |
| [dashboard](dashboard) | The internal operator console, a separate Python service |
| [agents](agents) | The endpoint collectors: shell based for macOS and C# for Windows, plus a forked copy of Installomator |
| [historical-help](historical-help) | The customer help pages as they were |
| [docs](docs) | The case study, security review and verification notes |

If you only have a few minutes, I would start with these:

| Area | Where to look |
| --- | --- |
| Overall design | [Case study](docs/portfolio-case-study.md) and [architecture overview](platform/docs/architecture-overview.md) |
| Ingestion and payloads | [Go service](platform/go-service) and [payload schema](platform/go-service/docs/PAYLOAD_SCHEMA.md) |
| Tenant and request boundaries | [Request authentication](platform/go-service/internal/auth) and [portal authorisation](platform/go-service/internal/portalauth) |
| Treating missing evidence honestly | [Evaluator](platform/go-service/internal/evaluator) and the [encryption state regression test](platform/go-service/integration/pat2496_encryption_state_test.go) |
| Summaries that must match the full calculation | [Equivalence test](platform/go-service/integration/unapproved_presence_equivalence_test.go) and [concurrency test](platform/go-service/integration/unapproved_presence_concurrency_test.go) |

A design rule that runs through all of it is that an unknown is never counted as safe. If an agent could not read a device's encryption state, or a report page came back incomplete, that device is shown as unknown rather than quietly passing.

## Status and limitations

This is a snapshot of five original repositories combined into one, with a fresh Git history. The infrastructure it describes has been decommissioned, and hostnames, IP addresses and tokens in the documentation have been replaced with placeholders. Historical test results are recorded with their dates and scope in the case study, but nothing here has been rebuilt or reverified as a whole, so do not run its deployment, installation or scheduling scripts. Two authentication fixes and some later security and dependency updates were made after the original snapshot, and these are recorded in [SECURITY.md](SECURITY.md).

## Licence

Copyright 2026 Patched.im Ltd. All rights reserved. The source is published so it can be read and reviewed; no licence to reuse it is granted. Third party material keeps its own terms, including the Installomator engine under [Apache 2.0](agents/engine/LICENSE), and these are listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
