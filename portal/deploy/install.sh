#!/usr/bin/env bash
# Patched customer portal - idempotent installer for the app.patched.im VPS.
#
# Run as root from a checkout of this repo on the box:
#   sudo bash deploy/install.sh
#
# Safe to re-run: every step checks before it changes anything. Re-running
# after a git pull is the supported upgrade path.
#
# What it does:
#   1. OS packages (nginx, python3-venv, ufw, rsync)
#   2. System user `portal` (no shell, no home login)
#   3. App code -> /opt/patched-portal + venv + pip install
#   4. /etc/patched-portal/env from deploy/env.template (never overwritten)
#   5. TLS: self-signed placeholder if no cert present (replace with a
#      Cloudflare Origin Certificate - see deploy/RUNBOOK.md)
#   6. systemd unit (patched-portal.service) enabled + (re)started
#   7. patched-maintenance-facts.service + .timer (PAT-1439/PAT-1438):
#      daemon-reload'd and the TIMER (never the oneshot .service) enabled
#      + restarted, then verified enabled and active
#   8. nginx site for app.patched.im
#   9. ufw per PAT-410: inbound 443/80 from Cloudflare ranges only,
#      SSH over Tailscale only, outbound restricted, tailnet
#      data-plane ports explicitly denied outbound
set -euo pipefail

APP_DIR=/opt/patched-portal
ENV_DIR=/etc/patched-portal
ENV_FILE=$ENV_DIR/env
CERT=/etc/ssl/app.patched.im.pem
KEY=/etc/ssl/app.patched.im.key
REPO_DIR=$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

for required_source in deploy/patched-portal.service deploy/patched-maintenance-facts.service deploy/patched-maintenance-facts.timer deploy/verify-systemd-hardening-floor.sh deploy/install-verified-systemd-service.sh requirements.lock; do
  [[ -f "$REPO_DIR/$required_source" && ! -L "$REPO_DIR/$required_source" ]] || { echo "Incomplete portal deployment source: $required_source" >&2; exit 1; }
done
# PAT-1893: requirements.lock is the hash-locked runtime dependency set. An
# empty lock would install nothing and the app would fail to import at
# startup instead of failing here, before any change to the box.
[[ -s "$REPO_DIR/requirements.lock" ]] || { echo "Incomplete portal deployment source: requirements.lock is empty" >&2; exit 1; }
for required_helper in deploy/verify-systemd-hardening-floor.sh deploy/install-verified-systemd-service.sh; do
  [[ -x "$REPO_DIR/$required_helper" ]] || { echo "Portal deployment helper is not executable: $required_helper" >&2; exit 1; }
  bash -n "$REPO_DIR/$required_helper" || { echo "Portal deployment helper has invalid shell syntax: $required_helper" >&2; exit 1; }
done

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash deploy/install.sh" >&2
  exit 1
fi
allowed_source_uid="${SUDO_UID:-0}"
for trusted_dir in "$REPO_DIR" "$REPO_DIR/deploy"; do
  [[ -d "$trusted_dir" && ! -L "$trusted_dir" ]] || { echo "Portal deployment path is not a real directory: $trusted_dir" >&2; exit 1; }
  owner="$(stat -c '%u' "$trusted_dir")"; mode="$(stat -c '%a' "$trusted_dir")"
  [[ "$owner" == 0 || "$owner" == "$allowed_source_uid" ]] || { echo "Portal deployment path has unexpected owner: $trusted_dir" >&2; exit 1; }
  (( (8#$mode & 0022) == 0 )) || { echo "Portal deployment path is group/world writable: $trusted_dir" >&2; exit 1; }
done

helper="$REPO_DIR/deploy/install-verified-systemd-service.sh"
exec {helper_fd}<"$helper"
fd_owner="$(stat -Lc '%u' "/proc/$$/fd/$helper_fd")"; fd_mode="$(stat -Lc '%a' "/proc/$$/fd/$helper_fd")"
[[ "$fd_owner" == 0 || "$fd_owner" == "$allowed_source_uid" ]] || { echo "Portal deployment helper owner changed during validation" >&2; exit 1; }
(( (8#$fd_mode & 0022) == 0 )) || { echo "Portal deployment helper is writable by group/world" >&2; exit 1; }
# shellcheck source=deploy/install-verified-systemd-service.sh
# shellcheck disable=SC1094
source "/dev/fd/$helper_fd"
exec {helper_fd}<&-

echo "== 1/9 OS packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nginx python3-venv ufw rsync openssl >/dev/null

echo "== 2/9 System user"
if ! id -u portal >/dev/null 2>&1; then
  useradd --system --shell /usr/sbin/nologin --home-dir "$APP_DIR" --no-create-home portal
fi

echo "== 3/9 App code + venv"
mkdir -p "$APP_DIR"
rsync -a --delete \
  --exclude '.git' --exclude '.venv' --exclude 'venv' --exclude '__pycache__' \
  --exclude '.pytest_cache' --exclude '.ruff_cache' --exclude 'tests' \
  --exclude 'e2e' --exclude 'requirements-e2e.txt' \
  "$REPO_DIR"/ "$APP_DIR"/
if [[ ! -x $APP_DIR/venv/bin/python ]]; then
  python3 -m venv "$APP_DIR/venv"
fi
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
# PAT-1893: install from the hash-locked, fully-pinned requirements.lock
# (pip-compile --generate-hashes), not the floating requirements.txt.
# requirements.txt still declares the direct runtime deps for humans/CI;
# every install here, including a rollback to an older commit, resolves the
# exact dependency set that commit's lock file pins rather than whatever is
# newest on PyPI at deploy time.
"$APP_DIR/venv/bin/pip" install --quiet --require-hashes -r "$APP_DIR/requirements.lock"
# Read-only for the service user: root owns, group portal may read/traverse.
chown -R root:portal "$APP_DIR"
chmod -R g+rX,o-rwx "$APP_DIR"

echo "== 4/9 Environment file"
mkdir -p "$ENV_DIR"
if [[ ! -f $ENV_FILE ]]; then
  cp "$REPO_DIR/deploy/env.template" "$ENV_FILE"
  echo "   NOTE: fill in $ENV_FILE (PORTAL_ACCESS_TEAM_DOMAIN, PORTAL_ACCESS_AUD)"
fi
chown root:portal "$ENV_FILE"
chmod 640 "$ENV_FILE"

echo "== 5/9 TLS certificate"
if [[ ! -f $CERT || ! -f $KEY ]]; then
  echo "   No cert at $CERT - generating a self-signed placeholder."
  echo "   Replace with a Cloudflare Origin Certificate (RUNBOOK step 5),"
  echo "   then set the Cloudflare SSL mode to Full (strict)."
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -subj "/CN=app.patched.im" -keyout "$KEY" -out "$CERT" >/dev/null 2>&1
fi
chmod 600 "$KEY"

echo "== 6/9 systemd unit"
install_and_verify_service patched-portal.service || exit 1
systemctl enable --now patched-portal.service
systemctl restart patched-portal.service

echo "== 7/9 patched-maintenance-facts systemd units"
# PAT-1439/PAT-1438: patched-maintenance-facts.service (hardened under
# PAT-1439 -- see patched.im/docs/systemd-hardening-floor.md) + .timer
# previously had NO deploy path in this installer at all -- hand-installed
# once and never touched again, which is exactly how the unit went 12 days
# over its own hardening ceiling unnoticed. A unit file is not live just
# because it was copied: systemd must be told to reread it (daemon-reload)
# before the change takes effect, and the TIMER -- never the oneshot
# .service, which would just fire an off-schedule run -- must be
# re-enabled/restarted to pick up the new definition.
install_and_verify_service patched-maintenance-facts.service || exit 1
install_systemd_timer_atomically patched-maintenance-facts.timer || exit 1
systemctl enable --now patched-maintenance-facts.timer
systemctl restart patched-maintenance-facts.timer
# Verify the result rather than trusting the copy: a daemon-reload or
# enable that silently no-op'd would leave the box running a stale
# in-memory unit definition even though this step "succeeded".
# Check the .service LOADS, not just that the timer is enabled/active
# (PAT-1439 non-author review). `systemctl enable --now <timer>` succeeds
# even when the .service it triggers failed to parse -- the timer is a
# separate unit, and its own state says nothing about whether the thing it
# fires can run. A malformed directive would sit green here and only
# surface as a failed job on the next hourly firing, in journald.
mf_load_state="$(systemctl show patched-maintenance-facts.service -p LoadState --value 2>/dev/null || true)"
if [ "$mf_load_state" != "loaded" ]; then
  echo "ERROR: patched-maintenance-facts.service did not load after daemon-reload (LoadState=${mf_load_state:-unknown}); the timer may be enabled but has nothing runnable to fire" >&2
  exit 1
fi

if ! systemctl is-enabled --quiet patched-maintenance-facts.timer; then
  echo "ERROR: patched-maintenance-facts.timer is not enabled after install" >&2
  exit 1
fi
if ! systemctl is-active --quiet patched-maintenance-facts.timer; then
  echo "ERROR: patched-maintenance-facts.timer is not active after install" >&2
  exit 1
fi

echo "== 8/9 nginx"
cp "$REPO_DIR/deploy/nginx-portal.conf" /etc/nginx/sites-available/app.patched.im
ln -sf /etc/nginx/sites-available/app.patched.im /etc/nginx/sites-enabled/app.patched.im
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable --now nginx
systemctl reload nginx

echo "== 9/9 ufw (PAT-410 posture)"
# Fetch current Cloudflare ranges; fall back to the baked-in list if offline.
CF_V4=$(curl -fsS --max-time 10 https://www.cloudflare.com/ips-v4 2>/dev/null || true)
CF_V6=$(curl -fsS --max-time 10 https://www.cloudflare.com/ips-v6 2>/dev/null || true)
if [[ -z $CF_V4 ]]; then
  CF_V4="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22"
fi
if [[ -z $CF_V6 ]]; then
  CF_V6="2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32"
fi

ufw --force default deny incoming
ufw --force default deny outgoing
ufw --force default deny routed

# Inbound: HTTPS/HTTP from Cloudflare only; SSH over the tailnet only.
for cidr in $CF_V4 $CF_V6; do
  ufw allow from "$cidr" to any port 443 proto tcp >/dev/null
  ufw allow from "$cidr" to any port 80 proto tcp >/dev/null
done
ufw allow in on tailscale0 to any port 22 proto tcp >/dev/null

# Belt-and-braces (the tailnet ACL is the primary control, PAT-410 PR #216):
# a compromised portal must not be able to initiate tailnet data-plane calls.
ufw deny out on tailscale0 to any port 8081 proto tcp >/dev/null
ufw deny out on tailscale0 to any port 8443 proto tcp >/dev/null
ufw deny out on tailscale0 to any port 5432 proto tcp >/dev/null

# Outbound: DNS, HTTP(S) (platform API via CF + OS updates), NTP, Tailscale.
ufw allow out 53 >/dev/null
ufw allow out 80/tcp >/dev/null
ufw allow out 443/tcp >/dev/null
ufw allow out 123/udp >/dev/null
ufw allow out 41641/udp >/dev/null

ufw --force enable
ufw reload >/dev/null

echo
echo "Done. Next steps (deploy/RUNBOOK.md):"
echo "  - fill $ENV_FILE, then: systemctl restart patched-portal"
echo "  - install the Cloudflare Origin Certificate at $CERT / $KEY"
echo "  - smoke test: curl -s https://127.0.0.1/healthz -k -H 'Host: app.patched.im'"
systemctl --no-pager --lines 0 status patched-portal.service || true
