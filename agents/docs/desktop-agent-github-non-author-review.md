# GitHub-Non-Author-Review endpoint-trust review packet — desktop agent (posture chain)

**Status:** review evidence for the desktop agent surfaces before first customer
ship. **This is a review packet, not a self-approval** — it assembles the evidence
a GitHub-Non-Author-Review reviewer needs and flags residual items. The agent ships to client
machines, so it is a supply-chain gate.

**Scope of this packet:** the desktop chain U0–U5 — the shared posture read-client
(U0), the Windows Self Service presenter (U3), the Windows tray-flyout presenter
(U4), and the scan-now / user-uninstall wiring (U5). The macOS Self Service / menu
bar surfaces are being built by a separate agent and must be reviewed alongside
this packet before macOS ships. Pre-existing agent components (collector, update
daemon/Service, agent-config, provenance, uninstall engine) are in scope only where
the desktop chain touches them.

Claims below marked **[verified]** were checked against the code at review time;
**[design]** describes intended behaviour whose view-layer wiring is Windows-only
and not yet build-verified (see Residual items).

---

## 1. Credential handling

**One credential path, never in user space.**

- Credentials live only in the privileged context:
  - macOS: `/etc/patched/{tenant-id,bearer-token,hmac-secret}` — mode `600`,
    `root:wheel` (`macos/install.sh`), read only by the root LaunchDaemon
    (`patched-upload.sh`).
  - Windows: Windows Credential Manager under LocalSystem
    (`Shared/Auth/CredentialStore.cs`: `PatchedAgent/{TenantId,BearerToken,HmacSecret}`,
    DPAPI, `CRED_PERSIST_LOCAL_MACHINE`), with env-var / `%ProgramData%\Patched\creds`
    fallbacks for pilot provisioning.
- **The user-space UI surfaces hold no secrets and make no network calls. [verified]**
  - `grep` over `windows/src/Tray` and `windows/src/Shared/SelfService` for
    `CredentialStore | HmacSigner | BearerToken | HmacSecret` → **no matches**.
  - `grep` over the same for `HttpClient | WebRequest | Socket` → **no matches**.
  - The UI reads a world-readable cache file only (§2); it cannot authenticate to
    the API even if compromised.
- **No second secret path introduced.** The U0 posture fetch reuses the exact
  bearer + HMAC store and signer the inventory poster already uses
  (`PostureFetcher` → `CredentialStore` + `HmacSigner`, mirroring
  `AgentConfigFetcher`). No new key material, no new storage location. **[verified]**

## 2. Read-client auth path (`GET /v1/posture`)

- The privileged context fetches posture and writes a **world-readable**
  `posture.json`; the UI reads that last-known-good cache. This mirrors the
  existing `update-status.json` writer/reader split, so the trust boundary is
  unchanged by the desktop chain.
  - Windows: `Service/PostureFetcher.cs` — `IHttpClientFactory("patched")`,
    `Authorization: Bearer …`, `X-Patched-Signature` = HMAC-SHA256 over an **empty
    body** (GET), atomic write to `%ProgramData%\Patched\posture.json`. Fail-safe:
    any network/HTTP/parse error leaves the prior cache untouched. **[verified]**
  - macOS: `fetch_posture` in `patched-upload.sh` — same headers, empty-body HMAC,
    atomic write to `/Library/Application Support/Patched/posture.json` (mode 644),
    non-fatal to the inventory upload. **[verified]**
- The cache reader is read-only and crash-safe: `Shared/Posture/PostureReader.cs`
  (Windows) and `menubar/PatchedUpdater/PostureStore.swift` (macOS) return
  last-known-good, surface staleness, and never throw on a missing/corrupt cache.
  Malformed JSON is rejected at write time (validated before the atomic move). **[verified]**
- Device identity in the posture response is **server-derived from the credential**,
  never client-supplied (per the contract `contracts/posture.schema.json`).

## 3. No-install guarantee

**The desktop UI cannot deploy or remove software. [verified]**

- The Self Service and tray presenters (`Shared/SelfService/*`) produce immutable
  view-models only. There is no package-engine reference, no process launch, no
  installer invocation anywhere in the UI/presenter layer.
- Patch & Deploy and Uninstall are **gated affordances** routed through one seam
  (`Shared/Posture/PostureModels.cs` → `PostureGating`): `"patch"` is the only
  actuating tier (matching the Service's real deploy gate,
  `PatchedWorker` `config.Tier == "patch"`); every other tier renders the control
  present-but-locked. Mandatory apps never expose Uninstall. **[verified — presenter
  tests assert the gating: `SelfServicePresenterTests`, `PostureModelsTests`]**
- The only privileged actors that install/remove are the Service / update daemon,
  which already gate on the signed agent-config tier. The UI's most privileged act
  is to drop a **trigger file** into the ACL-hardened trigger directory
  (`Tray/TriggerWriter.cs` → `TriggerAcl`); the Service decides whether to honour
  it (and downgrades deploy→scan when the tier is not `patch`). **[verified]**
- Net: even a fully compromised UI process can request, not perform, a change; the
  privileged tier gate is the enforcement point.

## 4. Network surface

Runtime egress is to patched.im (Cloudflare-fronted, `https://api.patched.im`,
overridable only via `PATCHED_API_URL` for testing) on these endpoints **[verified
by `grep -roE '/v1/[a-z-]+'`]**:

| Endpoint | Method | Actor | Introduced by |
|---|---|---|---|
| `/v1/inventory` | POST | privileged collector/Service | pre-existing |
| `/v1/posture` | GET | privileged fetcher | **this chain (U0)** |
| `/v1/agent-config` | GET | Service (Ed25519-verified) | pre-existing |
| `/v1/provenance` | POST | Service | pre-existing |
| `/v1/allowlist` | GET | Service | pre-existing |

- **The desktop chain adds exactly one endpoint: `GET /v1/posture`.** No new hosts.
- One third-party read exists in the macOS OS-update path: the SOFA feed
  `https://sofafeed.macadmins.io/v1/macos_data_feed.json` (`endpoint/patched-update.sh`)
  — pre-existing, public, read-only, no credentials. Out of scope for this chain
  but noted for completeness.
- All egress on Windows routes through the per-request `DynamicWebProxy`
  (agent-config-driven), so the posture fetch honours the tenant proxy policy. **[verified]**

## 5. Design-conformance checklist (binding spec)

From `updater/CLAUDE.md` "Desktop UI — canonical design spec (BINDING)" and the
`*/design/` boards. Presenter-level items are verified; pixel/visual items are
deferred to the Windows view shell and the macOS agent's review.

| Requirement | Status |
|---|---|
| System font (Segoe UI / SF Pro; Cascadia/SF Mono for evidence) | **[design]** — documented in `src/SelfService/README.md`; enforced in the view shell |
| One accent `#F5530A`, ≤ ~2% | **[design]** — token documented; view shell |
| Pixel-P mark drawn in code; word-only "Patched" header | **[design]** — view shell |
| Honest tier gating — present but gated, never dead/fake | **[verified]** — `PostureGating`, presenter tests |
| CIS renders "X of N" from payload, never hardcoded 142 | **[verified]** — `Benchmark.CoverageText` = implemented/benchmark_total; tested |
| "Required" badge for mandatory; tier-gated Uninstall for `user_removable` | **[verified]** — `CatalogAppVm.IsRequired/ShowUninstall/UninstallGated`; tested |
| Drift surfaced (unapproved present / mandatory missing) | **[verified]** — presenter + tests |
| No MDM / no remote control — user actions every change | **[verified]** — §3; UI only requests |
| Provenance everywhere (verified source per version/install) | **[verified]** — `UpdateRowVm.ProvenanceText`; CVE `VersionConfirmed` |
| Platform parity (Edge↔Safari, BitLocker↔FileVault, CIS Win11↔macOS) | **[verified]** — single platform-neutral posture contract + shared presenter |
| Copy "estate" not "fleet", no em dashes | **[verified]** — strings reviewed |

## 6. Scan-now and user-Uninstall wiring (U5)

- **Scan now** is a **local, user-initiated** trigger only — no remote control, no
  MDM. The UI drops a scan trigger into the ACL-hardened trigger directory the
  Service/daemon already watches; the Service runs a local collect+scan cycle and
  refreshes posture, which the UI re-renders. **[design]** — the trigger seam and
  Service handling exist (`TriggerWriter` / `TriggerAcl` / `PatchedWorker`); the
  Self Service "Scan now" button binding is part of the Windows view shell.
- **User Uninstall** is wired to the **existing agent uninstall act** (the Approved
  Software / allowlist seam, PAT-375/376 — "agent owns the act"), user-initiated
  only, tier-gated to App Management and policy-gated to `user_removable`, with the
  result reflected back through posture. No silent/remote removal. **[design]** —
  the gating decision is verified in the presenter (`canUninstall`); the act
  dispatch + result round-trip is Windows view + Service wiring.

## 7. Residual items before first customer ship

1. **Windows view shells (U3/U4) and the scan-now / uninstall button wiring** must
   be built and verified on Windows (they cannot compile on macOS/CI-Linux). The
   tested presenters carry the logic; the views are mechanical bindings.
   `windows/src/SelfService/README.md` specifies the WPF shell.
2. **macOS Self Service / menu bar surfaces** (separate agent) must clear this same
   checklist and be folded into the GitHub-Non-Author-Review review before macOS ships.
3. **Service-side `PostureFetcher`** compiles only on Windows (net8.0-windows); it
   mirrors the verified `AgentConfigFetcher` GET path and uses only `Shared` types
   + `HttpClient`. Confirm on a Windows build.
4. **End-to-end verification is pending the platform chain deploy** of `/v1/posture`
   (U5 verifies once the server endpoint is live).

## Recommendation

The trust-relevant foundations are sound and **[verified]**: no credentials or
network in user space, one reused secret path, a single new read-only endpoint, and
a UI that can only *request* — never perform — installs/removals, with honest
tier gating enforced in one tested seam. **GitHub-Non-Author-Review sign-off should be withheld until
the residual items above are closed** — in particular the Windows view-shell build,
the macOS surfaces' review, and end-to-end verification against the live
`/v1/posture` endpoint.
