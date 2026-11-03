#!/usr/bin/env bash
# Patched public CVE scan service — idempotent installer for scan.patched.im.
#
# Runs on patched-portal-01 alongside the portal (separate system user, separate
# systemd unit, separate nginx vhost). The normal source is the complete,
# CI-staged checkout at /opt/patched-deploy-staging/portal. Do not deploy from
# the historical /opt/src/portal checkout.
#
# Safe to re-run: every step checks before it changes anything. The installer
# verifies its complete source manifest before any host change, and before the
# rsync --delete that updates the live app directory.
#
# What it does:
#   1. OS packages (nginx, python3-venv, rsync, openssl)
#   2. System user `scan` (no shell, no home login)
#   3. scan/ code -> /opt/patched-scan + venv + pip install
#   4. /etc/patched-scan/env from deploy/env-scan.template (never overwritten)
#   5. TLS: self-signed placeholder if no cert present (replace with a
#      Cloudflare Origin Certificate — see deploy/RUNBOOK-scan.md)
#   6. systemd unit (patched-scan.service) enabled + (re)started
#   7. nvd refresh timer (patched-scan-nvd-refresh.timer) enabled — daily NVD
#      dataset refresh, no more manual/undocumented-cadence operator step
#   8. nginx vhost for scan.patched.im
#
# NOTE ON ufw: the box's ufw posture (443/80 from Cloudflare only, SSH via the
# tailnet, restricted outbound) is owned by deploy/install.sh (the portal
# installer). This script deliberately does NOT touch ufw — nginx already admits
# CF traffic and proxies scan.patched.im to 127.0.0.1:8001. If this box is NOT
# already running the portal, run deploy/install.sh first to establish ufw.
#
# REQUIRED ENV (fill in /etc/patched-scan/env after first run, then restart):
#   GRAPH_MAIL_TENANT_ID / GRAPH_MAIL_CLIENT_ID / GRAPH_MAIL_CLIENT_SECRET
#   MAIL_SENDER                (mailbox the service sends AS)
#   TURNSTILE_SECRET           (server-side verify; MUST be set in prod)
#   TURNSTILE_SECRET_KEY       (legacy alias — set the same value)
#   TURNSTILE_SITE_KEY         (public site key rendered into the forms)
#   PUBLIC_BASE_URL=https://scan.patched.im
#   PUBLIC_RETENTION_DAYS=30
#   EMAIL_DRY_RUN              (blank in prod; any value = log-only)
#
# AFTER INSTALL: seed the NVD dataset (the app refuses scans until it exists):
#   sudo -u scan NVD_DB_PATH=/var/lib/patched-scan/nvd.db \
#     /opt/patched-scan/venv/bin/python /opt/patched-scan/bin/refresh-nvd.py
set -euo pipefail

APP_DIR=/opt/patched-scan
ENV_DIR=/etc/patched-scan
ENV_FILE=$ENV_DIR/env
CERT=/etc/ssl/scan.patched.im.pem
KEY=/etc/ssl/scan.patched.im.key
REPO_DIR=$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

# Every runtime file the installer copies or subsequently reads must exist in
# the source tree before rsync --delete can touch /opt/patched-scan. Keep this
# explicit manifest in sync with scan/ deliberately: a newly added runtime
# file must make a staged-source omission fail closed, not look like a valid
# deployment that deleted the file from the live service.
readonly REQUIRED_SOURCE_FILES=(
  "deploy/env-scan.template"
  "deploy/nginx-scan.conf"
  "deploy/patched-scan.service"
  "deploy/patched-scan-nvd-refresh.service"
  "deploy/patched-scan-nvd-refresh.timer"
  "deploy/install-verified-systemd-service.sh"
  "deploy/verify-systemd-hardening-floor.sh"
  "scan/app.py"
  "scan/bin/refresh-nvd.py"
  "scan/bin/waitlist.py"
  "scan/db.py"
  "scan/intune_patch_levels.py"
  "scan/intune_upload.py"
  "scan/requirements.txt"
  "scan/requirements.lock"
  "scan/router.py"
  "scan/scanner.py"
  "scan/shared.py"
  "scan/static/css/public-brand.css"
  "scan/static/css/site.css"
  "scan/static/brand/patched-mark-primary.svg"
  "scan/static/favicon.svg"
  "scan/static/patched-lockup-onslate.svg"
  "scan/static/patched-report-logo.png"
  "scan/templates/_site_footer.html"
  "scan/templates/_site_nav.html"
  "scan/templates/public_done.html"
  "scan/templates/public_instructions.html"
  "scan/templates/public_pricing_enquiry.html"
  "scan/templates/public_privacy.html"
  "scan/templates/public_scan.html"
  "scan/templates/public_scan_unavailable.html"
  "scan/templates/public_upload.html"
  "scan/templates/public_verify.html"
  "scan/templates/public_waitlist.html"
)

validate_source_tree() {
  local source_dir="$1" relative_path missing=0

  for relative_path in "${REQUIRED_SOURCE_FILES[@]}"; do
    if [[ ! -f "$source_dir/$relative_path" || -L "$source_dir/$relative_path" ]]; then
      echo "Incomplete scan deployment source: missing or non-regular $relative_path" >&2
      missing=1
    fi
  done

  if [[ ! -s "$source_dir/scan/requirements.txt" ]]; then
    echo "Incomplete scan deployment source: scan/requirements.txt is empty" >&2
    missing=1
  fi
  # PAT-1893: scan/requirements.lock is the hash-locked runtime dependency
  # set. An empty lock would install nothing and the app would fail to
  # import at startup instead of failing here, before any host change.
  if [[ ! -s "$source_dir/scan/requirements.lock" ]]; then
    echo "Incomplete scan deployment source: scan/requirements.lock is empty" >&2
    missing=1
  fi
  for relative_path in deploy/install-verified-systemd-service.sh deploy/verify-systemd-hardening-floor.sh; do
    if [[ ! -x "$source_dir/$relative_path" ]] || ! bash -n "$source_dir/$relative_path"; then
      echo "Incomplete scan deployment source: helper is not executable shell: $relative_path" >&2
      missing=1
    fi
  done

  if [[ "$missing" -ne 0 ]]; then
    echo "Refusing to rsync --delete into $APP_DIR from incomplete source $source_dir" >&2
    return 1
  fi
}

if [[ "${1:-}" == "--check-source" ]]; then
  if [[ $# -ne 2 ]]; then
    echo "Usage: $0 --check-source <source-dir>" >&2
    exit 2
  fi
  validate_source_tree "$2"
  echo "Complete scan deployment source: $2"
  exit 0
fi

if [[ $# -ne 0 ]]; then
  echo "Usage: $0 [--check-source <source-dir>]" >&2
  exit 2
fi

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash deploy/install-scan.sh" >&2
  exit 1
fi

validate_source_tree "$REPO_DIR"
allowed_source_uid="${SUDO_UID:-0}"
for trusted_dir in "$REPO_DIR" "$REPO_DIR/deploy"; do
  [[ -d "$trusted_dir" && ! -L "$trusted_dir" ]] || { echo "Scan deployment path is not a real directory: $trusted_dir" >&2; exit 1; }
  owner="$(stat -c '%u' "$trusted_dir")"; mode="$(stat -c '%a' "$trusted_dir")"
  [[ "$owner" == 0 || "$owner" == "$allowed_source_uid" ]] || { echo "Scan deployment path has unexpected owner: $trusted_dir" >&2; exit 1; }
  (( (8#$mode & 0022) == 0 )) || { echo "Scan deployment path is group/world writable: $trusted_dir" >&2; exit 1; }
done

# Source executable deployment logic only after its regular-file, mode and
# syntax contract has been checked above.
helper="$REPO_DIR/deploy/install-verified-systemd-service.sh"
exec {helper_fd}<"$helper"
fd_owner="$(stat -Lc '%u' "/proc/$$/fd/$helper_fd")"; fd_mode="$(stat -Lc '%a' "/proc/$$/fd/$helper_fd")"
[[ "$fd_owner" == 0 || "$fd_owner" == "$allowed_source_uid" ]] || { echo "Scan deployment helper owner changed during validation" >&2; exit 1; }
(( (8#$fd_mode & 0022) == 0 )) || { echo "Scan deployment helper is writable by group/world" >&2; exit 1; }
# shellcheck source=deploy/install-verified-systemd-service.sh
# shellcheck disable=SC1094
source "/dev/fd/$helper_fd"
exec {helper_fd}<&-

echo "== 1/8 OS packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nginx python3-venv rsync openssl >/dev/null

echo "== 2/8 System user"
if ! id -u scan >/dev/null 2>&1; then
  useradd --system --shell /usr/sbin/nologin --home-dir "$APP_DIR" --no-create-home scan
fi

echo "== 3/8 App code + venv"
mkdir -p "$APP_DIR"
# Only the scan/ subtree ships to the box. Exclude tests + caches + any local
# state that may exist in a dev checkout.
rsync -a --delete \
  --exclude '.git' --exclude '.venv' --exclude 'venv' --exclude '__pycache__' \
  --exclude '.pytest_cache' --exclude '.ruff_cache' --exclude 'tests' \
  --exclude 'state' --exclude 'nvd.db' \
  "$REPO_DIR"/scan/ "$APP_DIR"/
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
# Read-only for the service user: root owns, group scan may read/traverse.
chown -R root:scan "$APP_DIR"
chmod -R g+rX,o-rwx "$APP_DIR"

echo "== 4/8 Environment file"
mkdir -p "$ENV_DIR"
if [[ ! -f $ENV_FILE ]]; then
  cp "$REPO_DIR/deploy/env-scan.template" "$ENV_FILE"
  echo "   NOTE: fill in $ENV_FILE (Graph mail + Turnstile), then restart."
fi
chown root:scan "$ENV_FILE"
chmod 640 "$ENV_FILE"

echo "== 5/8 TLS certificate"
if [[ ! -f $CERT || ! -f $KEY ]]; then
  echo "   No cert at $CERT — generating a self-signed placeholder."
  echo "   Replace with a Cloudflare Origin Certificate (RUNBOOK-scan step 5),"
  echo "   then set the Cloudflare SSL mode to Full (strict)."
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -subj "/CN=scan.patched.im" -keyout "$KEY" -out "$CERT" >/dev/null 2>&1
fi
chmod 600 "$KEY"

echo "== 6/8 systemd unit"
install_and_verify_service patched-scan.service || exit 1
systemctl enable --now patched-scan.service
systemctl restart patched-scan.service

echo "== 7/8 nvd refresh timer"
install_and_verify_service patched-scan-nvd-refresh.service || exit 1
install_systemd_timer_atomically patched-scan-nvd-refresh.timer || exit 1
systemctl enable --now patched-scan-nvd-refresh.timer

echo "== 8/8 nginx"
cp "$REPO_DIR/deploy/nginx-scan.conf" /etc/nginx/sites-available/scan.patched.im
ln -sf /etc/nginx/sites-available/scan.patched.im /etc/nginx/sites-enabled/scan.patched.im
nginx -t
systemctl reload nginx

echo
echo "Done. Next steps (deploy/RUNBOOK-scan.md):"
echo "  - fill $ENV_FILE, then: systemctl restart patched-scan"
echo "  - install the Cloudflare Origin Certificate at $CERT / $KEY"
echo "  - seed the NVD dataset:"
echo "      sudo -u scan NVD_DB_PATH=/var/lib/patched-scan/nvd.db \\"
echo "        $APP_DIR/venv/bin/python $APP_DIR/bin/refresh-nvd.py"
echo "  - smoke test: curl -s http://127.0.0.1:8001/healthz"
systemctl --no-pager --lines 0 status patched-scan.service || true
