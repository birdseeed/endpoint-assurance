# Signing key architecture — Patched

Three independent Ed25519 signing key pairs protect the delivery chain.
They must never share a private key or a `key_id`.

## Key inventory

| Purpose | Key name | `key_id` | Who signs | Who verifies |
|---|---|---|---|---|
| Agent-config | `AGENT_CONFIG_SIGNING_KEY` | `ecd47f2c5b3d5705` (placeholder → replace via PAT-497) | Platform's config service (`patched-api`) | `endpoint/verify-agent-config.py` (macOS + Windows) |
| Verified catalogue | `CATALOGUE_SIGNING_KEY` | *(distinct value — set in `CATALOGUE_SIGNING_KEY_ID` CI secret; never checked into this repo, server-side per `AGENTS.md`'s key table)* | **Retired 2026-09-29 (PAT-2247).** Formerly `verifier/sign-catalogue.py` (daily CI job, deleted with `.github/workflows/daily-vendor-verify.yml`) | No agent since PAT-2245 (2026-09-29) retired the signed app catalogue from both agents |
| Windows artifact metadata | `ARTIFACT_METADATA_SIGNING_KEY` | **NOT YET PROVISIONED** (PAT-1248) — placeholder in `ArtifactTrust.cs`, deliberately not a plausible key id | `verifier/sign-artifact-metadata.py`, wired into `windows-agent-release.yml` | `windows/src/Service/BootstrapUpdater.cs` (Windows self-update only) via the pinned key in `windows/src/Shared/Verification/ArtifactTrust.cs` |

## Why separate keys

A single compromised key would allow an attacker to forge a malicious
hash catalogue (changing what SHA-256 hashes are considered valid), a
fake agent-config (disabling verification or redirecting to attacker-controlled
URLs), or a fake self-update artifact for every Windows endpoint. Separate keys
with separate HSM IAM policies mean:

- The CI job that runs the daily verifier can access only `CATALOGUE_SIGNING_KEY`.
- Only the platform's config service API process can access `AGENT_CONFIG_SIGNING_KEY`.
- Only the Windows release workflow can access `ARTIFACT_METADATA_SIGNING_KEY`.
- Compromise of one job or one secret does not give an attacker any of the others.

`ARTIFACT_METADATA_SIGNING_KEY` (PAT-1248) replaces an earlier, rejected design:
the obvious fix for Windows self-update — writing `ARTIFACT_SIGNING_KEY` (a
*symmetric* HMAC secret also used to sign the release MSI for out-of-band
human verification, see `docs/agent-release-runbook.md`) to every endpoint —
was rejected because it would let one compromised device forge artifacts
estate-wide. An Ed25519 key pair lets endpoints verify with a public key that
carries no forging power, matching the pattern already used for the catalogue
and agent-config channels.

## Current state

Both keys use placeholder values — the same public key bytes pinned in the
verifier scripts. This is safe for development but **must be replaced before
production deployment** (see PAT-497 — HSM-backed key provisioning + rotation
runbook).

The agent-config key_id (`ecd47f2c5b3d5705`) is hardcoded in:
- `endpoint/verify-agent-config.py` (`_PINNED_KEY_ID`)
- `Ed25519Verifier.cs` (Windows), shared by `AgentConfig.cs`, `AgentConfigFetcher.cs`,
  `ProxyConfig.cs` and `AllowlistSignatureVerifier.cs`. It is *not* a catalogue verifier;
  repointing it at the catalogue key would break those trust chains.

No agent pins the catalogue key any more. PAT-2245 (2026-09-29) retired the signed app
catalogue from both agents: `endpoint/verify-catalogue.py`, `patched-fetch-catalogue.sh`,
the Windows `CatalogueFetcher`/`CatalogueTrust` pair and the `catalogue-pin-guard`
workflow are deleted. A catalogue key rotation therefore needs no agent release.

### Catalogue signing key: retired (PAT-2247, 2026-09-29)

Patched does not maintain a proprietary package catalogue and never patches
(Andy's ruling, 2026-09-28; ADR-0011 is dead). With PAT-2245 having already
removed every agent-side consumer of a signed catalogue, PAT-2247 removed the
producer side in the `updater` repo: `.github/workflows/daily-vendor-verify.yml`
(the only caller of `verifier/sign-catalogue.py` and the only holder of
`CATALOGUE_SIGNING_KEY_B64`/`CATALOGUE_PUBLISHER_TOKEN`), `verifier/sign-catalogue.py`
itself, and the mirror-pipeline workflows that consumed the published catalogue
are all deleted. `CATALOGUE_SIGNING_KEY` is retired in full — there is no
remaining signer and no remaining verifier anywhere in this repo or its agents.

**Pending Andy, not done here:** this ticket is code-only and does not hold or
touch any secret. The `CATALOGUE_SIGNING_KEY_B64` / `CATALOGUE_SIGNING_KEY_ID`
/ `CATALOGUE_SIGNING_PUBKEY_B64` values and the `CATALOGUE_PUBLISHER_TOKEN`
secret (repo- and server-side, see `patched.im`) still exist and their deletion
is Andy's action, not automated by this change.

**Unaffected:** the agent-config key (`ecd47f2c5b3d5705`) and the artifact
metadata key (`1c6ffd04c60dd94d`) are separate key pairs (see the table above)
and neither this ticket nor the catalogue retirement touches them. Both remain
referenced by live workflows — `AGENT_CONFIG_SIGNING_KEY` by the macOS/Windows
agent-config verifiers (`endpoint/verify-agent-config.py`,
`windows/src/Shared/Config/Ed25519Verifier.cs`), and
`ARTIFACT_METADATA_SIGNING_KEY` by `.github/workflows/agent-release-promote.yml`
and `.github/workflows/windows-agent-release.yml` (Windows self-update
artifact signing) — confirmed still present and unchanged by this ticket.

## Key rotation procedure

See `docs/key-rotation-runbook.md` (PAT-497) for the step-by-step HSM
provisioning, rotation, and agent rollout procedure.

## Enforcement

`verifier/sign-catalogue.py` **rejects** a `--key-id` that matches the
agent-config key_id at runtime (PAT-516). `verifier/sign-artifact-metadata.py`
extends this to the third purpose: it rejects a `--key-id` matching EITHER
the agent-config key_id or the catalogue key_id (PAT-1248). This prevents
accidental reuse even if CI secrets are misconfigured.

## Wire format (shared by all three channels)

```json
{
  "signed_payload": "<base64 of canonical JSON bytes>",
  "signature":      "<base64 of 64-byte Ed25519 signature>",
  "key_id":         "<16-char hex key identifier>"
}
```

Endpoints verify the `key_id` against their pinned key before accepting the
payload. An agent-config `key_id` presented on the catalogue channel (or vice
versa) will be rejected because the pinned public key in each verifier is
different.

## Publication boundary (PAT-1226)

> **Retired by PAT-2247 (2026-09-29).** The workflow this section describes
> (`.github/workflows/daily-vendor-verify.yml`) is deleted, not merely
> quarantined — see "Catalogue signing key: retired" above. Kept below for
> historical record of the mechanics.

> **Quarantined by PAT-1474.** Automatic verification, signing and publication
> no longer have a schedule. The last accepted signed catalogue remains the
> frozen compatibility artifact until installed legacy consumers are removed or
> a separately reviewed compatibility publication is authorised. Existing
> freshness gates make package installation fail closed as that artifact ages.
> The workflow
> keeps the former publication steps dormant and manual diagnostics receive no
> signing or publisher credential.

In the former scheduled publication path, CI signed the raw catalogue,
commits that exact envelope to `verifier-state`, and posts the same bytes to
`https://example-api-host.example-tailnet.ts.net:8443/admin/catalogue/signed` through
the existing `tag:ci` Tailscale connection. The request uses the dedicated
`CATALOGUE_PUBLISHER_TOKEN`, not `ADMIN_API_TOKEN` or a dashboard credential.
The platform accepts that token only for this one POST route, compares it in
constant time, and retains its signature, global-scope, freshness, and rollback
checks before replacing the last known good catalogue.

The workflow compares the worktree envelope hash with the committed local
`verifier-state` byte stream before a normal non-force push or platform post.
A push failure stops the job, so the publish step is unreachable. It logs only
the content hash, `generated_at`, and HTTP status on success. On failure it
retains a response body only in a temporary file, then emits at most 512
sanitised characters with the bearer, exact envelope, named sensitive fields,
and large encoded values redacted before failing.

The internal `:8443` Caddy site presents an internal-CA certificate, so this
single Tailscale-only curl uses `--insecure`; there is no existing runner CA
bundle to reuse. Transport peer authenticity comes from the `tag:ci` to
`tag:api` Tailscale ACL and bind, with the dedicated application bearer as an
independent check. `--insecure` is not acceptable for public endpoints or a
general curl pattern. Authentication, validation, or transport failure fails
the workflow without publishing a replacement.

## Catalogue scope: global by design (PAT-919)

The verified catalogue is **one artifact shared by every tenant** — it is not,
and does not need to be, tenant-bound. Tenant binding was evaluated (PAT-895 /
PAT-919) and rejected: per-tenant signing would require exposing a signing key
to a live, per-request process, which contradicts the key-separation model
above (`CATALOGUE_SIGNING_KEY` is restricted to the offline daily CI job —
see `verifier/sign-catalogue.py` — and is never handed to a live API process).
A shared "these hashes are verified-safe" list also has no obvious reason to
differ per tenant.

Instead, the signed payload carries a mandatory `"scope": "global"` claim — a
domain-separation marker, not a variable field. It was enforced fail-closed in
two places:

- `verifier/sign-catalogue.py` refuses to sign a payload whose `scope` is
  missing or not exactly `"global"`.
- The agent verifier that rejected a payload whose `scope` was missing or not
  exactly `"global"` was deleted with the rest of the agent-side catalogue in
  PAT-2245.

Any future per-tenant catalogue format must revisit this signing architecture
(see "Why separate keys" above) and **must** use a different `scope` value —
never `"global"` — so the two formats can never be confused with, or replayed
as, each other.

## Windows verification evidence key (PAT-1399)

> **Retired 2026-09-30 (PAT-2308).** The producer (`mirror-pipeline-windows.yml`)
> and consumer (`daily-vendor-verify.yml`) went with PAT-2247, and
> `verifier/verify.py` with PAT-2304. PAT-2308 deleted what was left:
> `verifier/windows_evidence_attestation.py` and the committed pin
> `verifier/windows-evidence-public-key.json` (key id `954bb105dcbf3e97`). No
> workflow reads the `WINDOWS_EVIDENCE_*` secrets or variables named below;
> deleting them is Andy's. This section is history only.

Windows Authenticode inspection runs only on the scheduled Windows mirror
runner. Each successful candidate and the reconciled verifier-state entry are
signed with a dedicated Ed25519 key before the daily macOS verifier can include
them in the global catalogue. The daily verifier checks the pinned public key,
canonical payload bytes, key id, Windows runner claim, verification method and
fourteen-day freshness before the separate catalogue signing key is used. The
runner also signs one whole-state envelope binding its run id, ordered entry-set
hash and the baseline snapshot used by that Windows run. The daily signer fetches
the current baseline and reconciles every signed entry independently against its
exact product key, identity, published version/SHA and reviewed version/SHA/signer.
A changed or removed authority omits only that entry; routine target additions,
delivery-mode edits, display metadata, job bookkeeping and timestamps do not
globally invalidate unrelated evidence. The signed entry-set plus the previous
publication retention floor detects unauthorized deletion or replay-driven
shrinkage. This deliberately prefers per-entry availability over treating every
legitimate baseline evolution as a global integrity failure. Tampered
cryptographic evidence blocks publication. Missing or stale entries are omitted
individually with explicit warnings, and an independent previous-publication
floor blocks a non-empty Windows catalogue from silently collapsing to zero or
shrinking below the configured retention threshold.

Repository configuration required for the canonical scheduled workflows:

- `WINDOWS_EVIDENCE_ENABLED`: repository variable, exactly `true` only after
  every key prerequisite below is configured; while false, new Windows evidence
  is omitted with a warning. If a prior signed Windows set is non-empty, the
  catalogue is preserved and publication blocked unless the separately reviewed
  `WINDOWS_EVIDENCE_DISABLE_ACK=remove-windows-authority` repository variable
  explicitly acknowledges destructive removal;
- `WINDOWS_EVIDENCE_SIGNING_KEY_B64`: secret, distinct 32-byte Ed25519 seed;
- `WINDOWS_EVIDENCE_SIGNING_KEY_ID`: secret, first eight SHA-256 bytes of the
  corresponding raw public key as 16 lowercase hex characters;
- `verifier/windows-evidence-public-key.json`: a separately reviewed, committed
  schema-1 manifest containing the active raw public key and its derived key id.
  No repository variable is a trust anchor. This file is intentionally absent
  from PAT-1399 until the real key is supplied and reviewed, so enabled
  preflight fails closed while the default disabled rollout continues macOS;
- `PROD01_SSH_KNOWN_HOSTS`: secret containing the pinned
  `example-prod-host` SSH host-key line. Workflows use `HostKeyAlias` and strict
  host-key checking before any remote shell reads `ADMIN_API_TOKEN`.

The Windows seed is exposed only to the canonical scheduled Windows job, never
workflow dispatch or the daily catalogue signer. The committed public key and id are not
catalogue-signing authority. The discovery adapter schedules each unchanged
target for a real download and repeated ClamAV, Authenticode and Winget hash
check every seven days. The fourteen-day freshness window permits one missed
weekly re-attestation without laundering timestamps; after that, an entry ages out visibly and the Windows publication
floor decides whether the signed catalogue may advance. Retired targets are
pruned only when the authoritative baseline retains at least 90% of the prior
state, and the finalized evidence has its own 90%/non-zero floor. Persistently
failing targets age out individually when that floor permits. Stored state alone
never refreshes `verified_at`. Per-label mirror failures remain visible and keep
the workflow red, but do not suppress reconciliation of independently successful
candidates or retirement of stale entries. Failure to obtain the authoritative
post-publish baseline excludes Windows with a typed integrity alert and leaves
the run non-green, while macOS verification, report and state generation still
complete. No stale Windows entry is republished.

Windows catalogue target identity and installed-inventory identity are distinct
claims. Discovery and the deployed platform catalogue continue to address a
reviewed target as canonical `pkg:<lowercase-winget-id>`; the independently
attested entry additionally carries `installed_identity` as canonical
`winget:<lowercase-winget-id>`. This avoids changing the existing catalogue
lookup namespace while giving PAT-1399 an exact inventory key. Deploy the
platform consumer that understands the signed `installed_identity` before
enabling this producer with `WINDOWS_EVIDENCE_ENABLED=true`; disabled evidence
does not remove or rewrite the existing macOS catalogue.

The platform signs macOS and Windows targets in one global envelope. Therefore a
Windows publication-floor breach blocks advancement of the entire signed
catalogue, including otherwise healthy macOS changes. This is intentional: the
current byte-identity publication API has no independently versioned Windows
sub-envelope, and publishing a new global envelope with silently removed Windows
authority would be worse than a visible catalogue stall.
The candidate is built and floor-checked in memory; on any block, the previous
catalogue bytes remain untouched, so a collapsed set cannot become tomorrow's
baseline merely because its report/state evidence was committed.

Windows candidate evidence remains schema version 2. Persisted whole-state
evidence schema version 3 is the sole accepted format and contains both signed
per-entry envelopes and the independently signed full-state/baseline binding. Evolution
requires a consumer-first release that explicitly dual-reads the old and new
signed schemas, followed by the producer version bump, then later retirement of
the old reader. An unsigned v1 document is never a compatibility format and is
rejected. Catalogue target keys remain `pkg:` (or safe legacy `name:` for mirror
delivery only); mandatory installed identity remains the separately signed
`winget:` claim.
