#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Apply Hetzner Cloud Firewall rules for patched-prod-01
# ─────────────────────────────────────────────────────────────────────────────
# Designed to live on the box at /opt/patched-dashboard/deploy/ and run on a
# schedule via systemd timer. Also fine to invoke ad-hoc by hand.
#
# Generates a complete inbound rule set and applies it via
# `hcloud firewall replace-rules`:
#
#   - TCP 80, 443  : from Cloudflare's published edge ranges (v4 + v6).
#                    This is the only public ingress to the dashboard.
#   - UDP 41641    : from anywhere. Tailscale direct-connect endpoint —
#                    needed for peer-to-peer WireGuard tunnels. Omit to
#                    force DERP relay (works, slightly more latency).
#   - ICMP         : from anywhere. Ping/diagnostics from external hosts.
#
# No public SSH at the Hetzner edge by design. Admin access goes via:
#   - Tailscale (`ssh root@patched-prod-01`)  — WireGuard tunnel arrives
#     on UDP 41641, decapsulates to `tailscale0`, bypasses this firewall
#     entirely. Tailscale ACLs control who can connect.
#   - Hetzner Cloud Console → Server → Console — browser TTY independent
#     of network. Use this if Tailscale ever breaks.
#
# Tailscale CGNAT (100.64.0.0/10) belongs in UFW only, not here — Tailscale
# packets don't traverse the Hetzner edge filter on the destination port.
#
# `replace-rules` overwrites the entire ruleset on the firewall by design —
# this script is the source of truth. Anything hand-edited in the Hetzner
# console gets reverted on the next timer run.
#
# Usage:
#   hetzner-firewall-apply.sh <firewall-name> [--yes]
#
# Flags:
#   --yes        Skip the confirmation prompt. Required when running
#                non-interactively (cron/systemd). Auto-set when no TTY.
#
# Exit codes:
#   0  success — rules applied (or already in desired state)
#   1  usage / preflight failure
#   2  network failure fetching CF ranges
#   3  hcloud auth or API failure
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

FIREWALL_NAME="${1:-}"
ASSUME_YES=0
for arg in "${@:2}"; do
    case "$arg" in
        --yes|-y) ASSUME_YES=1 ;;
        *) echo "ERR: unknown flag: $arg" >&2; exit 1 ;;
    esac
done

# Non-interactive when stdout isn't a TTY (cron/systemd context)
if [ ! -t 1 ]; then
    ASSUME_YES=1
fi

if [ -z "$FIREWALL_NAME" ]; then
    echo "Usage: $0 <firewall-name> [--yes]" >&2
    echo "       (run \`hcloud firewall list\` to see available firewalls)" >&2
    exit 1
fi

# ── Preflight ──
for tool in hcloud jq curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERR: $tool not installed." >&2
        exit 1
    fi
done

if ! hcloud firewall describe "$FIREWALL_NAME" >/dev/null 2>&1; then
    echo "ERR: firewall '$FIREWALL_NAME' not found, or hcloud not authed." >&2
    echo "     Try: hcloud firewall list" >&2
    exit 3
fi

# ── Fetch Cloudflare ranges (fail closed) ──
echo "→ Fetching Cloudflare IP ranges..."
CF_V4=$(curl -fsS --max-time 10 https://www.cloudflare.com/ips-v4 || true)
CF_V6=$(curl -fsS --max-time 10 https://www.cloudflare.com/ips-v6 || true)
if [ -z "$CF_V4" ] || [ -z "$CF_V6" ]; then
    echo "ERR: failed to fetch Cloudflare IP ranges; refusing to apply partial rules." >&2
    exit 2
fi
CF_V4_COUNT=$(echo "$CF_V4" | grep -c .)
CF_V6_COUNT=$(echo "$CF_V6" | grep -c .)
echo "  Got $CF_V4_COUNT IPv4 ranges and $CF_V6_COUNT IPv6 ranges"

# ── Build the rule set ──
CF_ALL_CIDRS=$( (echo "$CF_V4"; echo "$CF_V6") | jq -R 'select(length > 0)' | jq -s .)
ANY_V4_V6=$(jq -n '["0.0.0.0/0", "::/0"]')

RULES=$(jq -n \
    --argjson cf "$CF_ALL_CIDRS" \
    --argjson any "$ANY_V4_V6" \
    --argjson ts_cgnat '["100.64.0.0/10"]' \
    '[
        {direction: "in", protocol: "tcp",  port: "22",    source_ips: $ts_cgnat, destination_ips: [], description: "SSH from Tailscale"},
        {direction: "in", protocol: "tcp",  port: "80",    source_ips: $cf,  destination_ips: [], description: "HTTP from Cloudflare"},
        {direction: "in", protocol: "tcp",  port: "443",   source_ips: $cf,  destination_ips: [], description: "HTTPS from Cloudflare"},
        {direction: "in", protocol: "udp",  port: "41641", source_ips: $any, destination_ips: [], description: "Tailscale direct-connect"},
        {direction: "in", protocol: "icmp",                source_ips: $any, destination_ips: [], description: "ICMP (ping/diagnostics)"}
    ]')

# ── Diff current vs proposed ──
CURRENT_RULES=$(hcloud firewall describe "$FIREWALL_NAME" -o json | jq '.rules')

# Compare by sorted JSON — true equality, ignoring rule order
if [ "$(echo "$CURRENT_RULES" | jq -cS .)" = "$(echo "$RULES" | jq -cS .)" ]; then
    echo "✓ Firewall '$FIREWALL_NAME' already in desired state. No changes."
    exit 0
fi

echo ""
echo "→ Will apply $(echo "$RULES" | jq 'length') rules to firewall '$FIREWALL_NAME':"
echo "$RULES" | jq -r '
    .[] | "    \(.direction) \(.protocol)\(if .port then "/" + .port else "" end) " +
          "from \(.source_ips | length) source\(if (.source_ips | length) > 1 then "s" else "" end) " +
          "— \(.description)"'

# ── Confirm (skipped when --yes or no TTY) ──
if [ "$ASSUME_YES" -eq 0 ]; then
    echo ""
    read -r -p "Apply these rules? Type 'yes' to proceed: " confirm
    if [ "$confirm" != "yes" ]; then
        echo "Aborted. No changes made."
        exit 0
    fi
fi

echo "→ Applying..."
echo "$RULES" | hcloud firewall replace-rules "$FIREWALL_NAME" --rules-file -

echo "✓ Done. Verify in console.hetzner.cloud → Firewalls → $FIREWALL_NAME"
