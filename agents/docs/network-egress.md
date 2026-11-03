# Network egress — Patched agent

> **SUPERSEDED:** Section 5 below ("Mirror mode roadmap impact") describes an earlier architectural direction. As of [ADR-001: Vendor-direct delivery is the default; the mirror is dormant](./adr/ADR-001-vendor-direct-delivery.md) (2026-07-25), full mirror mode is no longer the long-term goal. Vendor-direct download is the default, and mirroring is kept dormant as a narrow, earned exception. This document is retained as the historical record of egress cost analysis.

All agent communications are **HTTPS/TLS 1.2+ on port 443**. No other ports are required.
This document is the authoritative allow-list for firewall and proxy teams.

## Summary

| Destination | Purpose | Platforms | Required |
|---|---|---|---|
| `api.patched.im:443` | Platform API (all endpoints) | macOS + Windows | Yes |
| Vendor CDNs (variable — see below) | App installer downloads | macOS (until mirror mode) | Yes |
| `*.winget.microsoft.com:443` / MS CDNs | winget package resolution + download (non-mirrored Windows labels) | Windows | Yes |
| `mirror.patched.im:443` | Patched CDN — mirrored installer download | macOS + Windows (per mirrored label) | Yes for mirrored labels |
| `community.chocolatey.org:443` | Chocolatey package metadata (optional engine) | Windows | If Chocolatey engine used |
| `packages.chocolatey.org:443` | Chocolatey package downloads (optional engine) | Windows | If Chocolatey engine used |

Verifier pipeline connections (CI only — **not made by endpoint agents**) are listed separately below.

---

## 1. Platform API — `https://api.patched.im`

All agent-to-platform calls go to a single base URL. The path below the base URL indicates
the operation.

| Method | Path | Description | Platforms | Cadence |
|---|---|---|---|---|
| `GET` | `/v1/agent-config` | Fetch signed agent-config (Ed25519-verified before use) | macOS + Windows | Every 15 min |
| `POST` | `/v1/inventory` | Upload device inventory (apps, OS, compliance posture) | macOS + Windows | On schedule (daily or event-driven) |
| `GET` | `/v1/posture` | Fetch device posture result | macOS + Windows | On schedule |
| `POST` | `/v1/provenance` | Record install/update event with verified publisher + hash | macOS + Windows | After each install |
| `GET` | `/v1/allowlist/pending-removals` | Fetch app-removal queue from platform | macOS + Windows | On schedule |
| `POST` | `/v1/agent-logs` | On-demand log upload (triggered by `log_request` in agent-config) | macOS | On demand |

**Authentication:** bearer token + HMAC-SHA256 per-request signature (tenant credential, not a
user credential). Credentials are stored in `/etc/patched/` (macOS) or Windows Credential Manager.

**Egress allow-rule:** `api.patched.im` port 443 TCP outbound. No wildcard subdomain needed.

---

## 2. App installer downloads — macOS

### Pre-mirror mode (current default)

Before PAT-500 (phase 2 mirror pipeline) is active for a label, the macOS agent downloads
installers directly from the vendor's CDN. Every download is verified before installation:
- **Team ID** (Apple Developer Team): verified by `spctl`
- **Notarization**: verified by `spctl`
- **SHA-256 content hash**: verified against the signed Patched catalogue (PAT-495)

Because the macOS label set spans multiple vendors, there is no fixed list of CDN hostnames.
All downloads are:
- HTTPS only (enforced at runtime and at label-authoring time)
- Port 443 only
- From well-known vendor domains (e.g. `dl.google.com`, `download.cdn.mozilla.net`, etc.)

**Enterprise deployment option:** configure the agent's system HTTP proxy (PAT-309) to route
all CDN traffic through a corporate proxy — the agent honours HTTPS_PROXY / PAC and the
proxy mode specified in agent-config. This avoids the need for per-hostname allow-rules.

### Mirror mode (PAT-500, in progress for top-30 labels)

When `patched.mirror: true` is set for a label, the agent fetches from the Patched-controlled
CDN instead of the vendor. The CDN hostname will be published here once PAT-500 is live.
SHA-256 is still verified against the signed catalogue.

**Full mirror mode (PAT-501, planned):** all ~1,108 labels served from the Patched CDN,
collapsing all vendor CDN egress to a single origin. When complete, this table simplifies
to one row.

---

## 3. App installer downloads — Windows

The Windows agent uses the winget CLI to resolve and install packages.
winget communicates with Microsoft's winget infrastructure:

| Destination | Purpose |
|---|---|
| `*.winget.microsoft.com` | winget source manifest resolution |
| `wingetrun.azureedge.net` (or current Azure CDN hostname) | Package manifest CDN |
| Vendor download URLs | Actual installer download (per winget package definition) |

All winget traffic is HTTPS. The specific Microsoft CDN hostnames may change; consult
[Microsoft's winget documentation](https://learn.microsoft.com/en-us/windows/package-manager/winget/)
for the current canonical list.

**Authenticode + SHA-256 verification** is performed on the downloaded installer before
`winget install` proceeds (PAT-305, PAT-495).

### Mirror & pin-vendor modes — Windows (PAT-823 / PAT-840)

When a Windows allowlist entry is `mirror: true` **or**
`install_mode: vendor_pinned`, the agent does **not** use winget or Chocolatey at
install time. It fetches the pinned installer over HTTPS and runs it directly, with
no unpinned fallback. The download destination depends on the mode:

| Mode | Destination | Purpose |
|---|---|---|
| `mirror` | `mirror.patched.im` | Pinned MSI download (`windows/<label>/<version>/…`) |
| `vendor_pinned` | The label's `pinned_url` host (a first-party vendor domain, e.g. `dl.google.com`) | Pinned MSI download directly from the vendor — **not** re-hosted |

In both modes the agent hard-verifies the downloaded bytes against `pinned_sha256`,
re-checks the Authenticode publisher, and then runs `msiexec /i … /quiet
/norestart`. For a `mirror` label the only install-time destinations are
`api.patched.im` and `mirror.patched.im`. For a `vendor_pinned` label they are
`api.patched.im` and the vendor's own `pinned_url` host (e.g. `dl.google.com` for
Chrome) — never `mirror.patched.im`, since pinned labels are never re-hosted.
Non-mirrored/non-pinned labels keep the winget path above. See
`docs/windows-mirror-pipeline.md` for the design and the CI pipeline that produces
the pinned artifacts.

The winget/Chocolatey hosts above are consulted **only for non-mirrored labels**. As
labels move onto the mirror, the winget/Chocolatey rows become unnecessary for those
labels — the long-term goal (parity with macOS full-mirror mode) is `api.patched.im` +
`mirror.patched.im` only. Two Windows entries (`1password`, `zoom`) are on the mirror
today — a legacy holdover from before the vendor-pinned migration (PAT-840), not a
deliberately-cleared ADR-001 exception. Beyond those two, mirroring activates per-label
once its Windows redistribution sign-off flips `mirror_eula_approved` to true.

### Chocolatey engine (optional)

If the Chocolatey package engine is enabled:

| Destination | Purpose |
|---|---|
| `community.chocolatey.org` | Package metadata lookup |
| `packages.chocolatey.org` | Package download |

Chocolatey support is an optional engine; it may not be active in all deployments.

---

## 4. Verifier pipeline (CI only — NOT endpoint agent traffic)

These connections are made by the daily `verifier/verify.py` GitHub Actions job, **not** by
the endpoint agent. They do not need to be in endpoint firewall rules.

**Retired 2026-09-30 (PAT-2304):** `verifier/verify.py` and both mirror
pipelines are deleted, and their workflows went with PAT-2247, so nothing in
this section makes these connections any more. Kept as history.

| Destination | Purpose | Ticket |
|---|---|---|
| `www.virustotal.com/api/v3/` | Hash lookup + artifact submission for 70+ AV engine scan | PAT-503 |
| `formulae.brew.sh/api/cask/` | Homebrew Cask hash cross-reference | PAT-502 |
| `github.com/microsoft/winget-pkgs` | winget community manifest hash cross-reference | PAT-502 |
| `api.github.com` / `raw.githubusercontent.com` | winget-pkgs manifest resolution (vendor URL + cross-hash oracle) for the Windows mirror pipeline | PAT-823 |
| Vendor download URLs (e.g. `zoom.us`) | Artifact download for hash computation + mirror publish | Verifier + mirror pipelines |

---

## 5. Mirror mode roadmap impact

**Superseded by ADR-001:** This section describes full mirror mode as the long-term goal. As of ADR-001 (2026-07-25), vendor-direct delivery is the default; mirroring is kept dormant as an earned exception only.

| Mode | Vendor CDN egress | Patched CDN egress |
|---|---|---|
| Current (direct) | Variable — per-label vendor hostnames | None |
| PAT-500 (top-30 mirrored) | Reduced by ~30 labels | Single Patched CDN origin |
| PAT-501 (full mirror) | **Zero** | Single Patched CDN origin *(superseded: not the target architecture)* |

Full mirror mode was previously the long-term goal *(superseded by ADR-001)*. Under the current architecture, the common-case egress allow-list is vendor CDNs (variable per app). Enterprise customers requiring single-domain egress can enable mirroring for their app set as an earned exception, which would produce the simplest egress profile: `api.patched.im` and `mirror.patched.im` only.

---

## Proxy support

Both the macOS and Windows agents honour the proxy configuration in the signed agent-config
(`/v1/agent-config`). Supported proxy modes:

- **System proxy** (WinHTTP/PAC on Windows; `networksetup` proxy on macOS)
- **Manual proxy** (explicit host:port, with optional credentials from Credential Manager / Keychain)
- **Direct** (force no proxy for agent traffic)

The proxy resolver re-reads the agent-config on every request, so a proxy configuration change
takes effect without restarting the agent.

---

*Last updated: 2026-07-13 (PAT-840 — added Windows pin-vendor mode: pinned installs
direct from a first-party vendor `pinned_url`, e.g. `dl.google.com`, no re-host).
Update this document when new platform endpoints are added or mirror mode is activated for
additional labels.*
