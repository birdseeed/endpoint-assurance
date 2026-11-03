# Network topology

**Status:** Live

---

## Overview

Two Hetzner VPS boxes, a Tailscale overlay for admin access, and Cloudflare as the public-internet edge for both boxes.

```
                     ┌──────────────────────────────────────┐
                     │           Cloudflare edge            │
                     │  api.patched.im   patched.im         │
                     │  dashboard.patched.im (+ CF Access)  │
                     └────────────┬──────────────┬──────────┘
                                  │              │
              ┌───────────────────▼──┐   ┌───────▼──────────────────┐
              │   example-api-host      │   │    example-prod-host       │
              │   Hetzner CPX22 x86   │   │    Hetzner CAX21 Arm64   │
              │   Helsinki (HEL1)     │   │    Nuremberg (NBG1)      │
              │   203.0.113.20       │   │    203.0.113.10        │
              │                       │   │                          │
              │  Caddy :443           │   │  Caddy :443              │
              │  Go :8080 (public)    │   │  patched-dashboard       │
              │  Go :8081 (Tailscale) │   │  (SQLite, www-data)      │
              │  Postgres 16 :5432    │   │  hetzner-fw-refresh.timer│
              └─────────┬─────────────┘   └───────────┬──────────────┘
                        │                              │
                        │       Tailscale WireGuard mesh (patched tailnet)
                        │         .example-tailnet.ts.net
                        │                              │
                        └──────────────────────────────┘
```

---

## Public DNS (Cloudflare)

All public hostnames are orange-cloud proxied — the origin IP is hidden from DNS. Cloudflare handles DDoS scrubbing, WAF, and TLS at the edge.

| Hostname | CF Proxy | Backend | Notes |
|---|---|---|---|
| `api.patched.im` | Orange-cloud | `example-api-host` :443 | Ingestion endpoint for all endpoints |
| `patched.im` | Orange-cloud | `example-prod-host` :443 | Marketing site |
| `dashboard.patched.im` | Orange-cloud + CF Access | `example-prod-host` :443 | Ops dashboard — team only |

**CF Access gate:** `dashboard.patched.im` has a Cloudflare Access policy requiring Google SSO authentication (team email domain only) before the request reaches the origin. Unauthenticated requests get a CF login page, not a 401 from Caddy.

### Egress rules applied by Cloudflare

- WAF: default ruleset enabled.
- Rate limiting: Cloudflare-level for volumetric DDoS. Application-level per-tenant rate limiting (60 rpm, burst 10) is enforced by the Go service on `example-api-host`.
- HTTP/3 (QUIC): supported at the Cloudflare edge; origin connection is HTTP/2 over TLS 1.3.

---

## Hetzner Cloud Firewalls

### `example-api-host-edge`

Applies to `example-api-host`. Only Cloudflare CIDR ranges are allowed on 80/443:

| Port | Protocol | Source | Purpose |
|---|---|---|---|
| 80 | TCP | CF CIDR ranges | CF HTTP (redirect to HTTPS) |
| 443 | TCP + UDP | CF CIDR ranges | CF HTTPS + HTTP/3 |
| 41641 | UDP | Any | Tailscale WireGuard |
| 22 | TCP | — | Blocked |

**Refresh:** `hetzner-firewall-apply-api.timer` on `example-prod-host` queries Cloudflare's published CIDR list (`https://www.cloudflare.com/ips-v4`, `ips-v6`) daily and updates this firewall via the Hetzner Cloud API.

### `example-prod-host-edge`

Equivalent configuration for `example-prod-host`:

| Port | Protocol | Source | Purpose |
|---|---|---|---|
| 80 | TCP | CF CIDR ranges | CF HTTP |
| 443 | TCP + UDP | CF CIDR ranges | CF HTTPS |
| 41641 | UDP | Any | Tailscale WireGuard |
| 22 | TCP | — | Blocked |

---

## Tailscale overlay (admin and control plane)

**Tailnet:** `patched` (MagicDNS suffix `.example-tailnet.ts.net`)

| Node | Tailscale IPv4 | MagicDNS name |
|---|---|---|
| `example-api-host` | `100.64.10.1` | `example-api-host.example-tailnet.ts.net` |
| `example-prod-host` | `100.64.10.2` | `example-prod-host.example-tailnet.ts.net` |
| Andy's Mac | (dynamic) | `(andy-mbp).example-tailnet.ts.net` |

**Access model:**
- Admin SSH to all boxes: Tailscale-only. TCP 22 is closed at the Hetzner FW. `ssh root@<tailscale-ip>` is the only shell path.
- `example-api-host` internal admin API: `https://example-api-host.example-tailnet.ts.net:8443` — Tailscale-only, no public DNS record. Go `:8081` is the admin + Prometheus listener; Caddy proxies it on the Tailscale interface at `:8443`.
- Dashboard → api-01 admin API: `example-prod-host` connects to api-01 over Tailscale (`example-api-host.example-tailnet.ts.net:8443`).

**ACLs:** versioned in `api-vps-artefacts/tailscale-acl.json` and validated by `.github/workflows/validate-tailscale-acl.yml` on every PR.

---

## TLS map

| Surface | Termination | Cert | Notes |
|---|---|---|---|
| Public `api.patched.im` | Cloudflare edge → Caddy on api-01 | CF Origin Cert (`*.patched.im`, ~2041) | CF handles browser TLS; origin-cert secures the CF→Caddy leg |
| Public `patched.im` + `dashboard.patched.im` | Cloudflare edge → Caddy on prod-01 | CF Origin Cert (`*.patched.im`, ~2041) | Same wildcard cert |
| Tailscale admin (`example-api-host.example-tailnet.ts.net:8443`) | Caddy on api-01 | Caddy-managed internal cert (`tls internal`) | WireGuard already encrypts the link; TLS here is belt-and-suspenders for gRPC/HTTP2 framing |
| Postgres on api-01 | — | — | Listens on `127.0.0.1` and Tailscale IP only; WireGuard encrypts the Tailscale leg |

---

## Traffic flows

### Endpoint → api.patched.im (POST /v1/inventory)

```
Managed endpoint (anywhere on the internet)
  → Cloudflare edge (WAF + rate-limit scrubbing)
  → Caddy on example-api-host :443 (TLS termination, CF Origin Cert)
  → Go service :8080 (bearer auth + HMAC verify + rate-limit enforcement)
  → Postgres :5432 on 127.0.0.1
```

### Team browser → dashboard.patched.im

```
Team browser
  → Cloudflare Access (Google SSO gate — rejects if not authed)
  → Cloudflare edge (orange-cloud proxy)
  → Caddy on example-prod-host :443
  → patched-dashboard (SQLite, localhost)
```

### patched-dashboard → api-01 admin API

```
patched-dashboard on prod-01
  → Tailscale WireGuard (example-api-host.example-tailnet.ts.net)
  → Caddy on api-01 :8443 (Tailscale interface only)
  → Go service :8081 (admin API — no application-layer auth; Tailscale membership is the gate)
  → Postgres :5432 on 127.0.0.1
```

### api-01 → Cloudflare R2 (nightly Restic, 03:00 UTC)

```
example-api-host
  → HTTPS (Restic S3 protocol)
  → Cloudflare R2 endpoint (s3.<account-id>.r2.cloudflarestorage.com)
  → patched-backups bucket
```

---

## Postgres network posture

Postgres on `example-api-host` listens on two interfaces only:

| Interface | Address | Access |
|---|---|---|
| Loopback | `127.0.0.1:5432` | Go service (local) |
| Tailscale | `100.64.10.1:5432` | `pg_hba.conf` restricts to `100.64.0.0/10` (Tailscale CGNAT range) |

Public interface (`0.0.0.0`) is NOT in the listen set. UFW also drops inbound 5432 on `eth0`. Postgres is not reachable from the public internet.

---

## Egress from example-api-host

| Destination | Protocol | Purpose |
|---|---|---|
| Cloudflare R2 | HTTPS | Restic nightly backup |
| Tailscale SaaS coordination plane | HTTPS + UDP 41641 | WireGuard key negotiation |

No other programmatic egress from api-01.

## Egress from example-prod-host

| Destination | Protocol | Purpose |
|---|---|---|
| Hetzner Cloud API | HTTPS | `hetzner-firewall-apply-api.timer` — daily CF CIDR refresh |
| `cloudflare.com` (IP list) | HTTPS | CF CIDR list download |
| Tailscale SaaS coordination plane | HTTPS + UDP 41641 | WireGuard key negotiation |
| `example-api-host.example-tailnet.ts.net:8443` | Tailscale HTTPS | Dashboard → admin API |

---

## Emergency access (origin bypass)

If Cloudflare is unavailable and origin access is needed:

```bash
# Add a temporary Hetzner FW rule allowing your IP on 443
# Hetzner console → Firewalls → example-api-host-edge → Add Rule → Inbound TCP 443 your-ip/32
# Do the work
# Remove the rule immediately after
```

Never leave a bypass rule in place — the origin IPs are not hardened for direct internet exposure.

---

## Related docs

- `docs/architecture-overview.md` - api-01 stack (auth, Postgres, services); consolidated there under PAT-1057
- `go-service/docs/architecture.md` - api-01 deploy log and current-state block
- `docs/prod-01-architecture.md` — prod-01 services and recovery
- `api-vps-artefacts/BACKUP_DR.md` — backup strategy and DR procedures
- `api-vps-artefacts/OPERATIONS.md` — runbooks (service-level, not network-level)
- `api-vps-artefacts/tailscale-acl.json` — Tailscale ACL policy (versioned)
