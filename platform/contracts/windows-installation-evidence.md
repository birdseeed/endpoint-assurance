# Windows installation evidence delivery (PAT-1921)

`windows_installation_evidence` is an additive, response-only member of the
existing Ed25519-signed `GET /v1/agent-config` payload. Bearer/HMAC, timestamp,
nonce and rate checks precede publication and conditional responses. Older
agents verify received bytes and ignore the unknown member. There is no new
endpoint, key, execution authority or tenant/admin setting.

The first reviewed publication is:

```json
{"catalogue_version":"2026.09.20.1","content_hash":"a3ea6bba02d8766c4f8432a04caf26154929651cb4722909b7f04df44922df5c","delivery_version":1,"expires_at":"2026-12-19T00:00:00Z","published_at":"2026-09-20T00:00:00Z","schema_version":1,"targets":[]}
```

Its source is exclusively the validated embedded PAT-1874 evidence catalogue.
Every source entry passes provenance validation before projection. The source
has 24 macOS entries and zero Windows entries: `targets:[]` is a valid inactive
publication requiring zero probes. Package labels, execution-catalogue data,
tenant policy, display names and signer-only matches are never target sources.
Admin PUT rejects this member, including `null`; stored config cannot persist it.

## Targets and canonical hash

Version 1 permits at most 24 target records with these exact fields:

| Field | Requirement |
|---|---|
| `identity_kind` | Exactly `windows_msi_product_code` |
| `identity_value` | Reviewed MSI ProductCode, uppercase braced GUID |
| `authenticode_subject` | Reviewed certificate subject |
| `install_path` | Exact drive-rooted Windows installation directory |
| `executable_path` | Exact `.exe` path contained beneath that directory |

ProductCode is not UpgradeCode. PAT-1874 currently supports UpgradeCode,
Winget ID and MSIX family evidence; none may be converted into a ProductCode.
It lacks explicit reviewed install/executable path pairs. Current derivation
therefore rejects **any** nonempty Windows source until PAT-1922 extends that
source explicitly. This wire shape does not admit or invent Windows products.
Any unreviewed Windows catalogue entry disables the entire Windows evidence
delivery until PAT-1922 reviews and supports the source evidence. It is not
silently skipped, and no partial target list is delivered.

Target keys are alphabetic. Targets sort ordinally by identity kind, identity
value, install path, executable path, then Authenticode subject. Identity
kind/value must be unique. Relative/UNC paths, environment expansion, wildcards,
traversal, alternate streams, control bytes and trailing-dot/space components
are invalid. No target may select software using a display name or broad search.

`content_hash` is lowercase SHA-256 over UTF-8 compact JSON with exactly these
keys in this order: `catalogue_version`, `schema_version`, `targets`. Strings
use Go `encoding/json` escaping, including `\u003c`, `\u003e`, `\u0026`,
`\u2028` and `\u2029`. Receivers can construct this preimage from those three
values' **raw JSON substrings in the verified payload**, avoiding serializer
differences. The empty publication's preimage is exactly:

```json
{"catalogue_version":"2026.09.20.1","schema_version":1,"targets":[]}
```

Publication metadata is separately covered by the existing Ed25519 signature.
UTC RFC3339 timestamps use seconds and `Z`. Accept only
`published_at <= now < expires_at`, a positive validity interval no longer than
90 days, schema 1 and a positive signed 64-bit delivery version. Expiry is
absolute: polling, process restart and HTTP 304 never refresh it.

## Failure and mixed-version behaviour

Receivers durably retain the highest accepted delivery version and its exact
publication identity. Reject lower versions and same versions with changed
content or metadata. A newer accepted empty list clears earlier targets.
Missing, null, malformed, expired or unsupported evidence means zero probes
for that run. Never resurrect cached targets or reset the high-water mark.
Invalid evidence must not block unrelated signed configuration. HTTP 304 does
not extend evidence expiry. These rules hold across process and binary rollback.

The API uses immutable global history from migration
`0155_windows_installation_evidence_deliveries`. An empty ledger admits only
version 1; a matching head is reused unchanged. New publications must be exactly
`head + 1`. A downgrade, jump, same-version change, missing ledger/schema,
invalid source or expired metadata omits only this feature and emits a degraded
warning log. It cannot create synthetic fresh empty authority or block unrelated
decommission, assurance or self-update configuration. Full-payload ETags change
when this member changes or disappears.

The publication comparison includes the entire document, not just its hash.
The database serialises insertion, enforces sequential revisions and forbids
UPDATE, DELETE and TRUNCATE. The app role has only SELECT and INSERT. This
guards binary rollback, not a privileged database owner deliberately bypassing
triggers or restoring stale backups. Database recovery must retain/recover all
publication history; surviving endpoint high-water marks still reject replay.

Each handler caches only successful ledger admission. Concurrent first requests
share that admission; transient failures retry. Every cached response is
revalidated against the current request time and checked against the durable
head using a lock-free SELECT, without a publication transaction or advisory
lock. A newer publication from another process therefore disables an older
handler's cached delivery immediately on its next head check. Responses are
copied, and caches are never shared across handlers or database pools.

## Publication, renewal and rollback runbook

1. Apply migration 0155 before deploying the API. Retain the ledger on binary
   rollback. The rollback migration refuses to remove populated history, even
   where recorded target arrays are empty; only an unused ledger is removable.
2. For reviewed content changes, renewal or intentional evidence rollback,
   update `internal/evidencecatalogue/delivery.go`: increment
   `WindowsDeliveryVersion` by one and set the reviewed catalogue version/hash
   and fixed publication/expiry window. An intentional rollback may reuse an
   earlier content hash at the higher revision. Run source, delivery, signature
   and database tests together. No HTTP/admin publication route exists.
3. Deploy sequential publications. A fresh database cannot bootstrap from a
   later version: restore its immutable delivery history or deliberately replay
   reviewed prior publications within their validity windows. Do not reset
   device high-water marks. Expired history must be restored from backup rather
   than republished to manufacture freshness.
4. A pre-PAT-1921 binary omits this field; an older PAT-1921 binary sees the
   higher ledger head and omits it. Updated agents perform zero evidence probes
   in either case. Restore the current binary or publish reviewed rollback
   content at the next delivery version to resume.

This is evidence collection only. It does not authorise installation or assert
completeness, absence, approval, current version or remediation.
