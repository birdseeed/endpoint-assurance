# Ed25519 signing key runbook

Covers the Ed25519 signing keys used across the estate:
- Agent-config responses from the platform (`/v1/agent-config`)
- The verified label catalogue (`verifier/catalogue/latest.signed.json`)
- The Windows allowlist (`windows-allowlist.json.sig`, PAT-511). **Retired
  2026-09-30 (PAT-2304):** the allowlist, its signature and its signing
  workflow are deleted. It was signed with `ALLOWLIST_SIGNING_KEY_B64`, a
  copy of the agent-config private key, and that repository secret is due
  for deletion.
- Windows agent self-update artifact metadata (PAT-1248, see the "artifact
  metadata" baseline below — provisioned 2026-08-11, PAT-1255)

**These are no longer one shared key.** PAT-516 split the catalogue onto its own dedicated key, separate from the agent-config key. Do not present the agent-config key as the catalogue key anywhere in this document, in rotation steps, or in `CATALOGUE_SIGNING_*` env values — that exact mistake caused PAT-996 (CI signed with the catalogue key while every endpoint still pinned the agent-config key; every endpoint rejected the catalogue).

Ticket: PAT-497 (original rotation runbook). Current-state custody note and
HSM-migration tracking: PAT-1312.

---

## Key baseline — agent-config

| Field | Value |
|---|---|
| Algorithm | Ed25519 |
| Key ID | `ecd47f2c5b3d5705` (first 8 bytes of SHA-256 of the public key) |
| Public key (base64) | `a3voEh/OojvVNeRUrP6iE68bqFAfEUPFUDth77oevV0=` |
| Created | 2026 (exact date not recorded at creation) |
| Created by | Andy Bridson |
| Current storage | GitHub Actions secret `AGENT_CONFIG_SIGNING_KEY` |
| Rotation status | Never rotated |
| Verification locations | `Ed25519Verifier.cs` (Windows agent; it also backed Windows-allowlist verification, PAT-511, retired 2026-09-30 by PAT-2304), `verify-agent-config.py` (macOS agent) |

## Key baseline — catalogue

Separate key since PAT-516; do not confuse with the agent-config key above.

| Field | Value |
|---|---|
| Algorithm | Ed25519 |
| Key ID | `734eba29d9f804a0` (first 8 bytes of SHA-256 of the public key) |
| Public key (base64) | `MdZjJUY8YEIV1hEg64ALirZtL4fn1EkaVjOFhjX7RSM=` |
| Created | 2026 (PAT-516) |
| Created by | Andy Bridson |
| Current storage | GitHub Actions secret `CATALOGUE_SIGNING_KEY_B64` (CI, private half); server env `CATALOGUE_SIGNING_KEY_ID` / `CATALOGUE_SIGNING_PUBKEY_B64` on api-01 |
| Rotation status | Never rotated |
| Verification locations | None on endpoints since PAT-2245 retired the signed app catalogue from both agents (the macOS `verify-catalogue.py` and the Windows `CatalogueTrust` pin are deleted) |

## Key baseline — artifact metadata (Windows self-update)

**PROVISIONED 2026-08-11 (PAT-1255).** Separate key since PAT-1248; do not
confuse with the agent-config or catalogue keys above. Windows self-update
(`windows/src/Service/BootstrapUpdater.cs`) verifies against this key's public
half, pinned in `ArtifactTrust`. The "Assert self-update artifact trust key is
provisioned" gate in `windows-agent-release.yml` refuses to publish a release
while the placeholder is present.

| Field | Value |
|---|---|
| Algorithm | Ed25519 |
| Key ID | `1c6ffd04c60dd94d` |
| Public key (base64) | `yYFmWA8rvRsalWAMP2B/JnIEQ5FX1cql+MK7LS+SOd0=` |
| Created | 2026-08-11 (PAT-1255) |
| Created by | Andy Bridson |
| Current storage | GitHub Actions secrets `ARTIFACT_METADATA_SIGNING_KEY` (private half) and `ARTIFACT_METADATA_SIGNING_KEY_ID` on `Patched-LTD/updater` |
| Rotation status | Never rotated |
| Generation method | `tools/generate-signing-key.py`, locally. **Does not meet the documented Cloud HSM standard** — see the note below |
| Verification locations | `windows/src/Service/BootstrapUpdater.cs` via `windows/src/Shared/Verification/ArtifactTrust.cs` (Windows agent only — macOS self-update is out of scope, tracked separately, PAT-1073) |

**On the generation method, recorded rather than glossed.** The tool this key
was generated with carries a "NEVER use this tool to generate the production
key" warning, and the Target state section below specifies GCP Cloud HSM. This
key does not meet that bar. Neither do the other two: the agent-config and
catalogue keys are both software-generated and both live in GitHub Actions
secrets, exactly like this one. Cloud HSM remains planned, not built.

Andy's call, 2026-08-11: provision this key consistently with the two that
already exist rather than block Windows self-update behind standing up Cloud
HSM, and migrate all three together later. So the gap here is estate-wide and
pre-existing, not something new this key introduced — but it is a real gap and
should be closed for all three at once, not piecemeal.

To provision (historical — this key is now provisioned): generate a key pair
the same way as the catalogue key (see
[Rotation procedure](#rotation-procedure) below, substituting
`ARTIFACT_METADATA_SIGNING_KEY` throughout — production MUST be generated
inside GCP Cloud HSM, never with `tools/generate-signing-key.py`), then:

1. Set `ARTIFACT_METADATA_SIGNING_KEY` / `ARTIFACT_METADATA_SIGNING_KEY_ID` as
   GitHub Actions secrets on `Patched-LTD/updater`.
2. Replace `ArtifactTrust.ProductionKeyId` / `ProductionPublicKeyBase64` in
   `windows/src/Shared/Verification/ArtifactTrust.cs` with the real values.
3. Confirm the release gate now passes: `windows-agent-release.yml`'s "Assert
   self-update artifact trust key is provisioned" step greps `ArtifactTrust.cs`
   for the placeholder marker and hard-fails while it is present. Both the key
   id AND the public key must be replaced — `IsProvisioned` checks both, so a
   half-replaced pair still counts as unprovisioned.
4. Ship a new Windows agent release — the next `windows-agent-release.yml`
   run will sign artifact metadata automatically once the secret is set (see
   its "Assert artifact metadata was signed when expected" gate).

### Auditor Q&A

**Where is the private key stored?** In GitHub Actions repository secrets. Access is restricted to the repository owner (Andy) and GitHub Actions runners. No human can read a GitHub Actions secret after it is set; the value is only injected into CI runs.

**Who has access?** Andy Bridson (sole repository admin). No other person has access.

**Has it ever been rotated?** No. Rotation is planned as part of the HSM migration (see below).

**What is the rotation procedure?** See the [Rotation procedure](#rotation-procedure) section.

---

## Custody note — current posture (for security questionnaires and audits)

Three Ed25519 key pairs protect the delivery chain, purpose-separated so a
compromise of one key's scope does not compromise the others:

| Purpose | Key ID |
|---|---|
| Agent-config | `ecd47f2c5b3d5705` |
| Catalogue | `734eba29d9f804a0` |
| Artifact metadata (Windows self-update) | `1c6ffd04c60dd94d` |

All three are software-generated. The private half of each lives only in
GitHub Actions secrets (see each key baseline above for the exact secret
names) — no human can read a GitHub Actions secret once it is set; the value
is only injected into CI runs. Private key material is never present on any
endpoint.

The symmetric `ARTIFACT_SIGNING_KEY` (the release-MSI HMAC secret used for
out-of-band human verification of a release, see
`docs/agent-release-runbook.md`) is a related but separate control, not one
of the three Ed25519 keys above. It exists only as a GitHub Actions secret
consumed at CI signing time and supplied by a human operator out-of-band
(`tools/verify-agent-release.py --key-file`, or the environment variable)
when independently verifying a release. It is deliberately absent from
`example-api-host` — a compromised API process cannot forge artifacts with a
key it never holds — and deliberately never shipped to any endpoint, macOS or
Windows — one compromised device cannot forge artifacts for the whole
estate. `ArtifactTrust.cs` (above) is what replaced the design that would
have shipped this key to Windows endpoints for self-update verification,
precisely because of that estate-wide forgery risk.

**HSM migration.** Cloud HSM custody (see "Target state" below) is the
planned direction, not the current state, for all three keys. Andy's call,
2026-08-11: provision each key consistently with what already exists rather
than block delivery behind standing up an HSM, and migrate all three keys
together later, not one at a time. Tracked at PAT-1312.

---

## Target state: GCP Cloud HSM (planned)

The production target is a GCP Cloud KMS key protected by Cloud HSM:

- **Key type:** `EC_SIGN_ED25519` (supported since GCP KMS Cloud HSM GA)
- **Key ring:** `projects/patched-prod/locations/europe-west1/keyRings/signing`
- **Key:** `catalogue-signing`
- **IAM:** CI service account (Workload Identity Federation via OIDC from GitHub Actions) granted `roles/cloudkms.signerVerifier` on the key only; no human has `roles/cloudkms.cryptoKeyVersions.useToSign`
- **No key export:** HSM keys cannot be exported; private material never leaves GCP

### Why GCP over AWS KMS

AWS KMS does not natively support Ed25519 signing as of 2026. GCP Cloud KMS `EC_SIGN_ED25519` produces 64-byte raw signatures compatible with the existing BouncyCastle `Ed25519Signer` verification on both endpoints without any protocol change.

### CI signing with GCP KMS

```yaml
# In .github/workflows/daily-vendor-verify.yml (or similar)
- uses: google-github-actions/auth@v2
  with:
    workload_identity_provider: projects/123456/locations/global/workloadIdentityPools/github/providers/github
    service_account: catalogue-signing-sa@patched-prod.iam.gserviceaccount.com

- name: Sign catalogue
  run: |
    pip install google-cloud-kms --quiet
    python3 verifier/sign-catalogue.py \
      --input  verifier/catalogue/latest.json \
      --kms-key-resource "$GCP_KMS_KEY_RESOURCE" \
      --key-id "$CATALOGUE_SIGNING_KEY_ID" \
      --output verifier/catalogue/latest.signed.json
  env:
    GCP_KMS_KEY_RESOURCE: ${{ vars.GCP_KMS_KEY_RESOURCE }}
    CATALOGUE_SIGNING_KEY_ID: ${{ vars.CATALOGUE_SIGNING_KEY_ID }}
```

No secret injection — Workload Identity Federation gives the runner OIDC credentials scoped to the single KMS operation.

### Setup checklist (one-time)

- [ ] Create GCP project `patched-prod` (or reuse existing)
- [ ] Enable Cloud KMS API
- [ ] Create key ring `signing` in `europe-west1`
- [ ] Create `catalogue-signing` key (type: `EC_SIGN_ED25519`, protection level: `HSM`)
- [ ] Export the public key from GCP KMS (this is safe — only the public key)
- [ ] Compute new `key_id` = first 16 hex chars of SHA-256 of the raw public key bytes
- [ ] Create `catalogue-signing-sa` service account with `roles/cloudkms.signerVerifier` on the key only
- [ ] Configure Workload Identity Federation for this repository
- [ ] Roll the key (see [Rotation procedure](#rotation-procedure) below)

---

## Rotation procedure

Key rotation has two phases: **staged transition** (both keys trusted) then **old key revocation**.

### Phase 1 — generate and deploy the new key

1. **Generate the new key** in GCP Cloud HSM (target state) or via the tool for dev/staging:

   ```sh
   # Production: generate inside GCP Cloud HSM (no export)
   gcloud kms keys versions create \
     --key catalogue-signing \
     --keyring signing \
     --location europe-west1 \
     --project patched-prod
   # Note the new version number; export the public key via GCP Console or:
   gcloud kms keys versions get-public-key 2 \
     --key catalogue-signing --keyring signing --location europe-west1 --project patched-prod
   ```

   ```sh
   # Dev/staging: generate a local key pair (NOT for production)
   python3 tools/generate-signing-key.py
   # Save CATALOGUE_SIGNING_KEY_B64 as a new GitHub Actions secret
   ```

2. **Compute the new key_id** = first 16 hex chars of SHA-256 of the 32-byte raw public key.

3. **Update `Ed25519Verifier.cs`** to trust BOTH old and new keys during the transition window:

   ```csharp
   // Transition: trust both keys until all agents have updated
   internal static bool Verify(byte[] message, byte[] signature, string keyId)
   {
       byte[] pubKey = keyId switch {
           PinnedKeyId    => Convert.FromBase64String(PinnedPubKeyBase64),
           NewPinnedKeyId => Convert.FromBase64String(NewPinnedPubKeyBase64),
           _ => null,
       };
       return pubKey is not null && Ed25519Verifier.Verify(pubKey, message, signature);
   }
   ```

   Ship this as a new agent release. Wait until >95% of endpoints are on the new agent.

4. **Begin signing with the new key** (update CI to use new KMS key version or new seed).

5. **Bump `key_id`** in the signed envelopes — endpoints now verify with the new key.

### Phase 2 — revoke the old key (4 weeks after Phase 1)

1. Confirm all active endpoints report the new key_id (check platform logs).
2. Remove the old key from `Ed25519Verifier.cs` — ship another agent release.
3. Disable/delete the old KMS key version (GCP) or archive the GitHub Actions secret.
4. Update the baseline in this document.

### Emergency rotation (key compromise suspected)

1. Immediately disable the suspect key in GCP KMS (or remove the GitHub Actions secret).
2. Generate a new key and push an agent release with only the new key trusted (no transition window — all endpoints will reject signed payloads from the old key until they update).
3. Contact affected tenants.
4. Post an incident record.

---

## Verification — how endpoints verify

### Windows (`Ed25519Verifier.cs`)

```csharp
internal const string PinnedPubKeyBase64 = "a3voEh/OojvVNeRUrP6iE68bqFAfEUPFUDth77oevV0=";
internal const string PinnedKeyId        = "ecd47f2c5b3d5705";
```

`AgentConfigFetcher.VerifyAndCache()` rejects any envelope whose `key_id` does not match `PinnedKeyId`. A rotation must update both constants and ship a new agent.

### macOS (`verify-agent-config.py`)

Equivalent pinned-key verification over the signed envelope. Same rotation path.

### Windows artifact metadata (`ArtifactTrust.cs`, PAT-1248)

```csharp
public const string ProductionKeyId = "1c6ffd04c60dd94d"; // PAT-1255, provisioned 2026-08-11
public const string ProductionPublicKeyBase64 = "yYFmWA8rvRsalWAMP2B/JnIEQ5FX1cql+MK7LS+SOd0=";
```

Both constants now hold the real, provisioned values (PAT-1255, 2026-08-11),
so `ArtifactTrust.ProductionKeyIsProvisioned` is true in production.
`BootstrapUpdater` rejects any envelope whose `key_id` does not match
`ArtifactTrust.Production.KeyId`, and still refuses to even attempt
verification if either constant is ever reverted to a placeholder value —
see `ArtifactTrust.IsProvisioned` in
`windows/src/Shared/Verification/ArtifactTrust.cs`. Windows only — macOS does
not use this scheme (PAT-1073).

---

## Useful commands

```sh
# Inspect current prod key
python3 tools/generate-signing-key.py --from-seed "$CATALOGUE_SIGNING_KEY_B64"

# Sign the catalogue (local seed, dev only)
python3 verifier/sign-catalogue.py \
  --input  verifier/catalogue/latest.json \
  --key    "$CATALOGUE_SIGNING_KEY_B64" \
  --key-id "$CATALOGUE_SIGNING_KEY_ID" \
  --output verifier/catalogue/latest.signed.json

# Sign the catalogue (GCP KMS, production)
python3 verifier/sign-catalogue.py \
  --input  verifier/catalogue/latest.json \
  --kms-key-resource "projects/patched-prod/locations/europe-west1/keyRings/signing/cryptoKeys/catalogue-signing/cryptoKeyVersions/1" \
  --key-id "$CATALOGUE_SIGNING_KEY_ID" \
  --output verifier/catalogue/latest.signed.json
```

The Windows allowlist signing command that used to follow here was removed on
2026-09-30 (PAT-2304): the allowlist and its signing script are deleted.
