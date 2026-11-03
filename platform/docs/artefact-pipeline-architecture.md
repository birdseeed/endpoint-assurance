# Artefact pipeline — architecture

**Status:** Source-verification agent (PAT-52, `verifier/verify.py`) runs daily. No deployment pipeline yet. This doc covers the planned vetted-artefact pipeline as a Phase 2 deliverable.

---

## What the artefact pipeline is

The artefact pipeline is a Patched-operated trust layer between vendor releases and managed endpoints. Its job is to take an app defined in the `engine/labels/` manifest, verify it against its upstream source, sign off on its integrity, and make it available to the endpoint update daemon (`endpoint/patched-update.sh`) through a signed deployment record.

**Why it exists:**

The update daemon currently fetches apps directly from vendor URLs at install time. This is the same model as upstream Installomator — it trusts the vendor CDN to always serve the right binary. The risks are:

1. **Transient CDN substitution or compromise:** the binary served at install time is not the binary that was audited.
2. **No Patched-side record:** no proof that a specific binary was installed to a specific endpoint on a specific date, only the vendor's CDN log.
3. **No per-tenant control:** no tenant-level gate between "app is in the manifest" and "app is deployed to this fleet."

The artefact pipeline makes all three properties enforceable.

---

## Current state (Phase 1)

### What exists today

| Component | File | What it does |
|---|---|---|
| Label manifest | `engine/labels/*.json` | Source of truth for app definitions: vendor URLs, expected Team ID, hash where available |
| CI label gate | `ci/validate-labels.py` | Rejects labels with non-HTTPS URLs, missing Team IDs, or schema violations |
| Source verifier | `verifier/verify.py` | Daily: downloads each app, checks codesign Team ID + notarisation, emits a status report |
| Endpoint allowlist | `endpoint/labels-allowlist.txt` | Generated from manifest; controls what the endpoint daemon will install |
| Endpoint daemon | `endpoint/patched-update.sh` | Runs Installomator labels for apps on the allowlist; fetches from vendor CDN at install time |

### What's missing for a full pipeline

- No per-artefact hash is captured and signed — the verifier checks the binary's Team ID but does not emit a signed SBOM or hash manifest.
- No staging catalog — there is no server-side record mapping `(label, version, vendor hash)` to a signed deployment record.
- No tenant-level deployment gate — once a label is in the allowlist, the daemon will install it without per-tenant approval.
- No immutable artefact store — binaries are re-fetched from vendor CDN on every install; no Patched-cached copy.

---

## Planned pipeline (Phase 2)

### Components

```
Vendor CDN / GitHub Releases
       │
       ▼
┌─────────────────────────┐
│  Source verifier (daily) │  verifier/verify.py (exists, runs on example-prod-host)
│  - Download binary       │
│  - Check codesign Team ID│
│  - Check notarisation    │
│  - Compute SHA-256       │
│  - Compare to manifest   │
└──────────┬──────────────┘
           │  verified artefact record
           ▼
┌─────────────────────────┐
│  Staging catalog (new)   │  patched-api: POST /admin/artefacts
│  - Per-label, per-version│
│  - Vendor hash + Patched │
│    hash + Team ID        │
│  - Ed25519 signed entry  │
│  - Status: pending/good/ │
│    revoked               │
└──────────┬──────────────┘
           │  signed deployment record
           ▼
┌─────────────────────────┐
│  Endpoint daemon         │  endpoint/patched-update.sh
│  - Fetches signed record │
│    before each install   │
│  - Verifies Ed25519 sig  │
│  - Matches vendor hash   │
│    at download time      │
│  - Reports install result│
└─────────────────────────┘
```

### Verification steps

For each label, the daily verifier pipeline runs:

| Step | What | Pass criteria |
|---|---|---|
| 1. Resolve URL | Download the binary at the manifest's `downloadURL` (or resolve the `appNewURL` for dynamic labels) | HTTP 200; < 600s download |
| 2. Compute hash | SHA-256 of the downloaded binary | — |
| 3. Compare to manifest | If the manifest includes `expectedSHA256`, compare | Match |
| 4. Codesign check | `codesign --verify --strict` + extract `TeamIdentifier` | Matches `expected_team_id` from manifest |
| 5. Notarisation check | `spctl --assess --type execute` or `xcrun stapler validate` | Notarised (or flagged as `notarisation: not_required` in manifest) |
| 6. Version check | Extract `CFBundleShortVersionString` via PlistBuddy / pkgutil | Matches `appNewVersion` in manifest label |
| 7. Emit record | Write verified record to staging catalog | — |

If any step fails, the label is flagged `status: failed` and a verification failure event is emitted. The existing label is not revoked automatically — a human reviews failures before promoting to `status: revoked`.

### Staging catalog schema (proposed)

```sql
CREATE TABLE artefact_records (
  id             bigserial PRIMARY KEY,
  label          text NOT NULL,              -- matches engine/labels/<label>.json filename
  version        text NOT NULL,
  vendor_url     text NOT NULL,
  vendor_sha256  text NOT NULL,              -- SHA-256 at time of verification
  team_id        text NOT NULL,              -- Apple Team ID verified by codesign
  notarised      boolean NOT NULL,
  status         text NOT NULL,              -- 'pending' | 'good' | 'failed' | 'revoked'
  signature      text NOT NULL,             -- Ed25519(label||version||vendor_sha256||status) base64
  verified_at    timestamptz NOT NULL DEFAULT now(),
  revoked_at     timestamptz,
  revoked_reason text
);

CREATE UNIQUE INDEX artefact_records_label_version ON artefact_records (label, version);
CREATE INDEX artefact_records_status ON artefact_records (status, label);
```

The `signature` column signs the concatenation of `label + version + vendor_sha256 + status` using the same Ed25519 key as agent-config responses. The endpoint daemon verifies this signature before accepting the deployment record.

### Endpoint daemon integration

Before installing a label, the daemon:

1. Calls `GET /v1/artefact/<label>?version=<version>` (new endpoint, authenticated with tenant bearer + HMAC).
2. Receives the signed artefact record: `{vendor_url, vendor_sha256, team_id, status, signature}`.
3. Verifies the Ed25519 signature against the embedded public key.
4. Downloads the binary from `vendor_url`.
5. Computes SHA-256 of the downloaded binary; must match `vendor_sha256`.
6. Proceeds with Installomator install.
7. Reports install result to `/v1/install-result` (new endpoint).

If the artefact record is missing, `status != good`, or the hash does not match, the install is aborted and the failure is reported.

### Tenant-level deployment gate

The artefact pipeline enables tenant-level gates:

- **Approved apps** (from tenant app policy): endpoint daemon only requests artefact records for apps in the tenant's approved list.
- **Pending approval:** a tenant admin can see the staged artefact record (via dashboard) before it's installed to their fleet — this is the "per-tenant release management" feature.
- **Revocation:** setting `status: revoked` in the staging catalog is sufficient to stop new installs of that version immediately. Active installs are not terminated (no remote control) but the revoked version is not re-installed on next run.

---

## Artefact caching (Phase 3, optional)

The current model still fetches from vendor CDN at install time — the artefact record guarantees the hash will be checked, but does not eliminate CDN dependency.

For high-assurance deployments:

1. Patched caches verified binaries to Cloudflare R2 (`patched-artefacts` bucket).
2. The artefact record includes `patched_url` (Cloudflare R2 URL signed with R2 token).
3. Endpoint daemon downloads from `patched_url` instead of `vendor_url`.
4. Patched CDN URL is TLS + CF Access gated (tenant bearer in the request header).

This adds: R2 storage cost, a cache-invalidation problem on vendor URL changes, and a dependency on Patched CDN availability for endpoint installs. Deferred until a customer requirement demands it.

---

## Current gaps vs Phase 2

| Gap | Current state | Phase 2 fix |
|---|---|---|
| No per-artefact signed record | Verifier emits a log; no DB record, no signature | `artefact_records` table + Ed25519 signature |
| No install-time hash check | Endpoint daemon trusts vendor CDN | Daemon fetches signed record + checks hash post-download |
| No per-tenant deployment gate | Any label in allowlist is installable | App policy + artefact record check before install |
| No install result reporting | No server-side record of what was installed when | `POST /v1/install-result` endpoint |
| Verifier runs from prod-01 only | Single point of verification failure | Acceptable at Phase 2 scale; Phase 3: distributed verification |
| No revocation surface | Can only suppress via allowlist update | `status: revoked` in artefact_records + daemon checks status |

---

## Related docs

- `docs/label-manifest-format.md` — label record format; `expected_team_id` and URL rules
- `docs/installomator-security-review.md` — threat model for the current update engine
- `docs/download-architecture.md` — static vs resolved download model
- `docs/verification-agent-design.md` — daily verification agent design (PAT-52)
- `verifier/verify.py` — current verification agent source
- `contracts/label.schema.json` — authoritative label record schema
