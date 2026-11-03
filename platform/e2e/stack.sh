#!/usr/bin/env bash
# e2e/stack.sh — bring the Patched E2E stack up/down/status.
#
# Usage:
#   e2e/stack.sh up      — start everything, idempotent
#   e2e/stack.sh down    — stop everything and remove the DB
#   e2e/stack.sh status  — show what is running
#
# Postgres: prefers Docker (container patched-e2e-pg, port 55432).
# Falls back to a local pg_ctl-managed cluster when Docker is not available.
# In either case the DATABASE_URL is postgres://patched_e2e:patched_e2e@127.0.0.1:55432/patched_e2e.
#
# State lives in e2e/.state/ (gitignored). All secrets are regenerated on
# first run and reused on subsequent runs.
set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GOSERVICE_DIR="$REPO_ROOT/go-service"
MIGRATIONS_DIR="$GOSERVICE_DIR/migrations"
# Dashboard read-only clone (never modify).
DASHBOARD_DIR="/Users/andybridson/Development/Patched.im/dashboard"
STATE="$SCRIPT_DIR/.state"

# ---------------------------------------------------------------------------
# Ports and credentials
# ---------------------------------------------------------------------------
PG_PORT=55432
API_PUBLIC_PORT=18080
API_INTERNAL_PORT=18081
DASHBOARD_PORT=18000

PG_CONTAINER="patched-e2e-pg"
PG_DB="patched_e2e"
PG_USER="patched_e2e"
PG_PASS="patched_e2e"
DATABASE_URL="postgres://${PG_USER}:${PG_PASS}@127.0.0.1:${PG_PORT}/${PG_DB}?sslmode=disable"

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------
log()  { printf '[stack] %s\n' "$*"; }
die()  { printf '[stack] ERROR: %s\n' "$*" >&2; exit 1; }
ok()   { printf '[stack] OK: %s\n' "$*"; }

# Write a value to a state file.
state_set() {
    local key="$1"
    local val="$2"
    printf '%s' "$val" > "$STATE/$key"
}

# Read a value from a state file, or empty string if missing.
state_get() {
    local key="$1"
    if [[ -f "$STATE/$key" ]]; then
        cat "$STATE/$key"
    else
        printf ''
    fi
}

# Check whether a PID is alive.
pid_alive() {
    local pid="$1"
    if [[ -z "$pid" ]]; then
        return 1
    fi
    kill -0 "$pid" 2>/dev/null
}

# Kill all processes listening on a TCP port (macOS lsof).
kill_port() {
    local port="$1"
    local pids
    pids="$(lsof -ti ":$port" -sTCP:LISTEN 2>/dev/null)" || pids=""
    if [[ -n "$pids" ]]; then
        # shellcheck disable=SC2086
        kill -15 $pids 2>/dev/null || true
        sleep 1
        # shellcheck disable=SC2086
        kill -9 $pids 2>/dev/null || true
    fi
}

# Check that a TCP port is free before spawning a service.
# If occupied by a process matching expected_pattern, kill it (orphan from a
# prior dead "go run" or uvicorn parent) and proceed.
# If occupied by something else, die with a clear message.
check_port_free() {
    local port="$1"
    local expected_pattern="$2"
    local label="$3"
    local occupant_pids occupant_pid occupant_cmd
    occupant_pids="$(lsof -ti ":$port" -sTCP:LISTEN 2>/dev/null)" || occupant_pids=""
    if [[ -z "$occupant_pids" ]]; then
        return 0
    fi
    # Identify the first occupant for the command check / die message.
    occupant_pid="$(printf '%s' "$occupant_pids" | head -1)"
    occupant_cmd="$(ps -p "$occupant_pid" -o command= 2>/dev/null)" || occupant_cmd=""
    if printf '%s' "$occupant_cmd" | grep -q "$expected_pattern"; then
        log "Port $port occupied by orphaned $label process (pid $occupant_pid) — killing orphan..."
        # shellcheck disable=SC2086
        kill -15 $occupant_pids 2>/dev/null || true
        sleep 1
        # shellcheck disable=SC2086
        kill -9 $occupant_pids 2>/dev/null || true
    else
        die "Port $port is occupied by PID $occupant_pid (${occupant_cmd:-unknown}) which is not a $label process. Free port $port and retry."
    fi
}

# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------

# Detect usable Docker CLI.  Returns 0 if docker is present and responding.
detect_docker() {
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

pg_up_docker() {
    log "Starting Postgres 16 in Docker (container: $PG_CONTAINER)..."
    # Check if container already exists and is running.
    if docker inspect "$PG_CONTAINER" >/dev/null 2>&1; then
        local status
        status="$(docker inspect -f '{{.State.Status}}' "$PG_CONTAINER")"
        if [[ "$status" == "running" ]]; then
            log "Container $PG_CONTAINER already running."
            return 0
        fi
        log "Container exists but not running (status: $status), removing..."
        docker rm -f "$PG_CONTAINER" >/dev/null
    fi
    docker run -d \
        --name "$PG_CONTAINER" \
        -e POSTGRES_USER="$PG_USER" \
        -e POSTGRES_PASSWORD="$PG_PASS" \
        -e POSTGRES_DB="$PG_DB" \
        -p "127.0.0.1:${PG_PORT}:5432" \
        postgres:16 >/dev/null
    state_set PG_MODE docker
    log "Container started."
}

pg_down_docker() {
    log "Removing Postgres container $PG_CONTAINER..."
    if docker inspect "$PG_CONTAINER" >/dev/null 2>&1; then
        docker rm -f "$PG_CONTAINER" >/dev/null
        log "Container removed."
    else
        log "Container not found, nothing to remove."
    fi
}

# ---------------------------------------------------------------------------
# Native pg_ctl helpers
# ---------------------------------------------------------------------------

# Best-effort: find a usable pg_ctl from the full postgres installation.
# Prefer the versioned Homebrew keg (has postgres binary alongside it) over
# libpq shims in /opt/homebrew/bin which lack the server binary.
find_pg_bin() {
    local bin="$1"
    # Versioned kegs: 17 first, then 16.
    for pg_dir in \
        /opt/homebrew/opt/postgresql@17/bin \
        /opt/homebrew/opt/postgresql@16/bin \
        /opt/homebrew/opt/postgresql/bin; do
        if [[ -x "$pg_dir/$bin" && -x "$pg_dir/postgres" ]]; then
            printf '%s/%s' "$pg_dir" "$bin"
            return 0
        fi
    done
    # Fall back to PATH, but only if the companion postgres binary is there too.
    local found
    found="$(command -v "$bin" 2>/dev/null)" || found=""
    if [[ -n "$found" ]]; then
        local pg_dir2
        pg_dir2="$(dirname "$found")"
        if [[ -x "$pg_dir2/postgres" ]]; then
            printf '%s' "$found"
            return 0
        fi
    fi
    printf ''
}

find_pg_ctl()   { find_pg_bin pg_ctl; }
find_initdb()   { find_pg_bin initdb; }
find_createdb() {
    # createdb just needs libpq; any version is fine.
    for pg_dir in \
        /opt/homebrew/opt/postgresql@17/bin \
        /opt/homebrew/opt/postgresql@16/bin; do
        if [[ -x "$pg_dir/createdb" ]]; then
            printf '%s/createdb' "$pg_dir"
            return 0
        fi
    done
    command -v createdb 2>/dev/null || printf ''
}

pg_up_native() {
    local pg_ctl initdb_cmd createdb_cmd
    pg_ctl="$(find_pg_ctl)"
    initdb_cmd="$(find_initdb)"
    createdb_cmd="$(find_createdb)"

    if [[ -z "$pg_ctl" || -z "$initdb_cmd" ]]; then
        die "Docker is not available and pg_ctl/initdb not found. Install Docker Desktop or PostgreSQL."
    fi

    local pgdata="$STATE/pgdata"
    local pglog="$STATE/pg.log"
    local pg_pid_file="$STATE/pg_native.pid"

    # If already running, check if it's healthy.
    if [[ -f "$pg_pid_file" ]]; then
        local existing_pid
        existing_pid="$(cat "$pg_pid_file")"
        if pid_alive "$existing_pid"; then
            log "Native Postgres already running (pid $existing_pid)."
            return 0
        fi
        log "Stale native Postgres pid, restarting..."
        rm -f "$pg_pid_file"
    fi

    # Initialise the cluster if it doesn't exist.
    if [[ ! -d "$pgdata" ]]; then
        log "Initialising PostgreSQL cluster at $pgdata..."
        "$initdb_cmd" \
            -D "$pgdata" \
            -U "$PG_USER" \
            --auth=trust \
            --encoding=UTF8 \
            --locale=C \
            >/dev/null 2>&1
        log "Cluster initialised."
    fi

    # Start postgres on the E2E port with a unix socket in /tmp.
    log "Starting native PostgreSQL on port $PG_PORT..."
    "$pg_ctl" -D "$pgdata" -l "$pglog" \
        -o "-p $PG_PORT -k /tmp -c listen_addresses='127.0.0.1'" \
        start -w -t 30
    log "PostgreSQL started."
    state_set PG_MODE native

    # Wait for pg to accept connections.
    local i=0
    while ! pg_ready >/dev/null 2>&1; do
        i=$((i + 1))
        if [[ $i -gt 20 ]]; then
            die "Native Postgres did not become ready in time."
        fi
        sleep 1
    done

    # Create the database (createdb idempotent: ignore "already exists" error).
    if ! psql -h 127.0.0.1 -p "$PG_PORT" -U "$PG_USER" -lqt 2>/dev/null | cut -d'|' -f1 | grep -qw "$PG_DB"; then
        if [[ -n "$createdb_cmd" ]]; then
            "$createdb_cmd" -h 127.0.0.1 -p "$PG_PORT" -U "$PG_USER" "$PG_DB" 2>/dev/null || true
        else
            psql -h 127.0.0.1 -p "$PG_PORT" -U "$PG_USER" \
                -c "CREATE DATABASE $PG_DB;" 2>/dev/null || true
        fi
    fi
    log "Database $PG_DB ready."

    # Record the postmaster pid for teardown.
    local pm_pid
    pm_pid="$(head -1 "$pgdata/postmaster.pid" 2>/dev/null)" || pm_pid=""
    if [[ -n "$pm_pid" ]]; then
        state_set pg_native_pid "$pm_pid"
        printf '%s' "$pm_pid" > "$pg_pid_file"
    fi
}

pg_down_native() {
    local pg_ctl
    pg_ctl="$(find_pg_ctl)"
    if [[ -z "$pg_ctl" ]]; then
        return 0
    fi
    local pgdata="$STATE/pgdata"
    if [[ ! -d "$pgdata" ]]; then
        log "No native Postgres cluster found."
        return 0
    fi
    log "Stopping native PostgreSQL..."
    "$pg_ctl" -D "$pgdata" stop -m fast 2>/dev/null || true
    rm -f "$STATE/pg_native.pid"
    log "Native PostgreSQL stopped."
    # Remove the data dir on down to allow a clean restart.
    rm -rf "$pgdata"
    log "Cluster data removed."
}

# ---------------------------------------------------------------------------
# Postgres readiness
# ---------------------------------------------------------------------------
pg_ready() {
    pg_isready -h 127.0.0.1 -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" -q 2>/dev/null
}

wait_for_pg() {
    log "Waiting for Postgres on port $PG_PORT..."
    local i=0
    while ! pg_ready; do
        i=$((i + 1))
        if [[ $i -gt 60 ]]; then
            die "Postgres did not become ready within 60s."
        fi
        sleep 1
    done
    ok "Postgres ready."
}

# ---------------------------------------------------------------------------
# Migrations
# ---------------------------------------------------------------------------
apply_migrations() {
    local marker="$STATE/migrations_applied"

    # Count non-rollback migration files — the authoritative target.
    local file_count
    file_count="$(find "$MIGRATIONS_DIR" -maxdepth 1 -name "*.sql" \
        ! -name "*_rollback.sql" \
        ! -name "check-*.sh" \
        | wc -l | tr -d ' ')"

    # Derive migration state from the database, not from a marker file, so that
    # a fresh database after 'stack.sh down' is never silently skipped.
    local table_exists applied_count
    table_exists="$(psql -h 127.0.0.1 -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" \
        -tAc "SELECT to_regclass('public.schema_migrations') IS NOT NULL" \
        2>/dev/null)" || table_exists="f"

    if [[ "$table_exists" == "t" ]]; then
        applied_count="$(psql -h 127.0.0.1 -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" \
            -tAc "SELECT count(*) FROM schema_migrations" \
            2>/dev/null)" || applied_count=0

        if [[ "$applied_count" -ge "$file_count" ]]; then
            log "Migrations already applied ($applied_count/$file_count in schema_migrations). Skipping."
            return 0
        fi

        if [[ "$applied_count" -gt 0 && "$applied_count" -lt "$file_count" ]]; then
            die "Partial migrations detected ($applied_count/$file_count applied). Database is in an unexpected state — run 'e2e/stack.sh down' first to reset, then 'e2e/stack.sh up' for a clean start."
        fi
        # applied_count = 0 but table exists: treat as fresh, fall through to apply.
    fi

    log "Applying migrations ($file_count files)..."

    # Create the 'patched' role so GRANT TO patched statements in older
    # migrations do not error.  The app connects as patched_e2e (superuser),
    # so the grants themselves are not needed for functionality.
    psql -h 127.0.0.1 -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" \
        -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='patched') THEN CREATE ROLE patched; END IF; END \$\$;" \
        2>/dev/null || true

    # Apply all non-rollback SQL files in lexicographic (filename) order.
    local mfile
    while IFS= read -r mfile; do
        local fname version
        fname="$(basename "$mfile")"
        version="${fname%.sql}"
        log "  Applying $fname..."
        psql -h 127.0.0.1 -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" \
            -v ON_ERROR_STOP=0 \
            -f "$mfile" >/dev/null 2>&1 || {
            log "  WARNING: $fname had errors (may be expected for already-existing objects)."
        }
        # Record this migration in schema_migrations.  ON CONFLICT handles files
        # that already INSERT into the table themselves (e.g. 0001_initial.sql).
        # Errors are ignored: the table may not yet exist until 0001 creates it.
        psql -h 127.0.0.1 -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" \
            -tAc "INSERT INTO schema_migrations(version) VALUES ('$version') ON CONFLICT DO NOTHING" \
            >/dev/null 2>&1 || true
    done < <(find "$MIGRATIONS_DIR" -maxdepth 1 -name "*.sql" \
        ! -name "*_rollback.sql" \
        ! -name "check-*.sh" \
        | sort)

    # Informational breadcrumb only — the DB query above is the real gate.
    touch "$marker"
    ok "Migrations applied."
}

# ---------------------------------------------------------------------------
# Secret generation
# ---------------------------------------------------------------------------
generate_secrets() {
    mkdir -p "$STATE"
    local changed=false

    if [[ ! -f "$STATE/ADMIN_API_TOKEN" ]]; then
        state_set ADMIN_API_TOKEN "$(openssl rand -hex 32)"
        changed=true
    fi

    if [[ ! -f "$STATE/AGENT_CONFIG_SIGNING_KEY" ]]; then
        # 32 random bytes, base64-standard-encoded (the format LoadSigningKey expects).
        state_set AGENT_CONFIG_SIGNING_KEY "$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64)"
        changed=true
    fi

    if [[ ! -f "$STATE/DASHBOARD_API_KEY" ]]; then
        state_set DASHBOARD_API_KEY "$(openssl rand -hex 32)"
        changed=true
    fi

    if [[ "$changed" == "true" ]]; then
        log "Secrets generated."
    else
        log "Reusing existing secrets."
    fi
}

# ---------------------------------------------------------------------------
# patched-api
# ---------------------------------------------------------------------------
start_api() {
    local admin_token signing_key api_pid
    admin_token="$(state_get ADMIN_API_TOKEN)"
    signing_key="$(state_get AGENT_CONFIG_SIGNING_KEY)"

    # Check if already running.
    api_pid="$(state_get API_PID)"
    if [[ -n "$api_pid" ]] && pid_alive "$api_pid"; then
        log "patched-api already running (pid $api_pid)."
        return 0
    fi

    # Verify both API ports are free before spawning.  If occupied by a
    # patched-api orphan (a "go run" child that survived a dead parent) kill
    # it and proceed; if occupied by anything else, die clearly.
    check_port_free "$API_PUBLIC_PORT"   "patched-api" "patched-api"
    check_port_free "$API_INTERNAL_PORT" "patched-api" "patched-api"

    log "Starting patched-api..."
    (
        cd "$GOSERVICE_DIR"
        DATABASE_URL="$DATABASE_URL" \
        LISTEN_PUBLIC="127.0.0.1:${API_PUBLIC_PORT}" \
        LISTEN_INTERNAL="127.0.0.1:${API_INTERNAL_PORT}" \
        ADMIN_API_TOKEN="$admin_token" \
        AGENT_CONFIG_SIGNING_KEY="$signing_key" \
        RATE_LIMIT_RPM=100000 \
        RATE_LIMIT_BURST=10000 \
        go run ./cmd/patched-api \
            >"$STATE/api.log" 2>&1 &
        printf '%d' $! > "$STATE/API_PID"
    )
    # The subshell writes the PID file; give it a moment.
    sleep 1
    api_pid="$(cat "$STATE/API_PID" 2>/dev/null)"
    log "patched-api started (pid $api_pid)."
}

wait_for_api() {
    log "Waiting for patched-api /health on port $API_PUBLIC_PORT..."
    local i=0
    while true; do
        if curl -sf "http://127.0.0.1:${API_PUBLIC_PORT}/health" >/dev/null 2>&1; then
            ok "patched-api healthy."
            return 0
        fi
        i=$((i + 1))
        if [[ $i -gt 120 ]]; then
            die "patched-api did not become healthy within 120s. Check $STATE/api.log."
        fi
        sleep 1
    done
}

# ---------------------------------------------------------------------------
# patched-extractor
# ---------------------------------------------------------------------------
start_extractor() {
    local ext_pid
    ext_pid="$(state_get EXTRACTOR_PID)"
    if [[ -n "$ext_pid" ]] && pid_alive "$ext_pid"; then
        log "patched-extractor already running (pid $ext_pid)."
        return 0
    fi

    log "Starting patched-extractor..."
    (
        cd "$GOSERVICE_DIR"
        DATABASE_URL="$DATABASE_URL" \
        EXTRACTOR_POLL_EVERY=5s \
        go run ./cmd/patched-extractor \
            >"$STATE/extractor.log" 2>&1 &
        printf '%d' $! > "$STATE/EXTRACTOR_PID"
    )
    sleep 1
    ext_pid="$(cat "$STATE/EXTRACTOR_PID" 2>/dev/null)"
    log "patched-extractor started (pid $ext_pid)."
}

# ---------------------------------------------------------------------------
# Tenant bootstrap
# ---------------------------------------------------------------------------
bootstrap_tenant() {
    if [[ -f "$STATE/TENANT_ID" ]]; then
        log "Tenant already bootstrapped ($(state_get TENANT_ID))."
        return 0
    fi

    log "Bootstrapping E2E tenant..."
    local admin_token resp tenant_id bearer hmac_b64
    admin_token="$(state_get ADMIN_API_TOKEN)"

    resp="$(curl -sf \
        -X POST "http://127.0.0.1:${API_INTERNAL_PORT}/admin/tenants" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${admin_token}" \
        -d '{"name":"e2e-local"}')"

    tenant_id="$(printf '%s' "$resp" | python3 -c 'import sys,json; print(json.load(sys.stdin)["tenant_id"])')"
    bearer="$(printf '%s' "$resp" | python3 -c 'import sys,json; print(json.load(sys.stdin)["bearer_token"])')"
    hmac_b64="$(printf '%s' "$resp" | python3 -c 'import sys,json; print(json.load(sys.stdin)["hmac_secret_b64"])')"

    state_set TENANT_ID "$tenant_id"
    state_set BEARER_TOKEN "$bearer"
    state_set HMAC_SECRET_B64 "$hmac_b64"

    ok "Tenant created: $tenant_id"
}

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
start_dashboard() {
    local dash_pid
    dash_pid="$(state_get DASHBOARD_PID)"
    if [[ -n "$dash_pid" ]] && pid_alive "$dash_pid"; then
        log "Dashboard already running (pid $dash_pid)."
        return 0
    fi

    if [[ ! -d "$DASHBOARD_DIR" ]]; then
        die "Dashboard directory not found: $DASHBOARD_DIR"
    fi

    local admin_token dashboard_key
    admin_token="$(state_get ADMIN_API_TOKEN)"
    dashboard_key="$(state_get DASHBOARD_API_KEY)"

    # Run from an isolated copy so the E2E dashboard never reads or writes the
    # real ops data (dashboard.db, reports/) in the shared clone.
    local run_dir="$STATE/dashboard-run"
    mkdir -p "$run_dir"
    rsync -a --delete \
        --exclude 'dashboard.db*' --exclude 'reports/' --exclude '__pycache__/' \
        --exclude '.git/' --exclude 'nvd.db' --exclude 'public_scans/' \
        "$DASHBOARD_DIR/" "$run_dir/"

    # Verify the dashboard port is free before spawning.  If occupied by a
    # uvicorn orphan, kill it and proceed; otherwise die clearly.
    check_port_free "$DASHBOARD_PORT" "uvicorn" "dashboard"

    log "Starting dashboard on port $DASHBOARD_PORT (isolated copy: $run_dir)..."
    (
        cd "$run_dir"
        PATCHED_API_INTERNAL="http://127.0.0.1:${API_INTERNAL_PORT}" \
        ADMIN_API_TOKEN="$admin_token" \
        DASHBOARD_API_KEY="$dashboard_key" \
        DASHBOARD_ENV=local \
        uvicorn main:app \
            --host 127.0.0.1 \
            --port "$DASHBOARD_PORT" \
            --no-access-log \
            >"$STATE/dashboard.log" 2>&1 &
        printf '%d' $! > "$STATE/DASHBOARD_PID"
    )
    sleep 1
    dash_pid="$(cat "$STATE/DASHBOARD_PID" 2>/dev/null)"
    log "Dashboard started (pid $dash_pid)."
}

wait_for_dashboard() {
    log "Waiting for dashboard HTTP 200 on port $DASHBOARD_PORT..."
    local i=0
    while true; do
        local status
        status="$(curl -so /dev/null -w '%{http_code}' \
            "http://127.0.0.1:${DASHBOARD_PORT}/" 2>/dev/null)" || status="000"
        if [[ "$status" == "200" || "$status" == "302" ]]; then
            ok "Dashboard healthy (HTTP $status)."
            return 0
        fi
        i=$((i + 1))
        if [[ $i -gt 60 ]]; then
            die "Dashboard did not become healthy within 60s. Check $STATE/dashboard.log."
        fi
        sleep 1
    done
}

# ---------------------------------------------------------------------------
# Stop helpers
# ---------------------------------------------------------------------------
kill_pid_file() {
    local label="$1"
    local pid_file="$STATE/$2"
    local expected_pattern="$3"
    if [[ ! -f "$pid_file" ]]; then
        return 0
    fi
    local pid
    pid="$(cat "$pid_file")"
    if pid_alive "$pid"; then
        # Verify the live process is actually what we recorded.  A stale PID
        # file can point to a recycled PID that now belongs to an unrelated
        # process; killing it would be data-corrupting.
        local live_cmd
        live_cmd="$(ps -p "$pid" -o command= 2>/dev/null)" || live_cmd=""
        if ! printf '%s' "$live_cmd" | grep -q "$expected_pattern"; then
            log "WARNING: stale PID file for $label — expected '$expected_pattern', process is now '${live_cmd:-gone}' — not killing."
            rm -f "$pid_file"
            return 0
        fi
        log "Stopping $label (pid $pid)..."
        kill "$pid" 2>/dev/null || true
        # Kill child processes (go run spawns the actual binary as a child).
        pkill -P "$pid" 2>/dev/null || true
        sleep 2
        if pid_alive "$pid"; then
            kill -9 "$pid" 2>/dev/null || true
            pkill -9 -P "$pid" 2>/dev/null || true
        fi
        log "$label stopped."
    else
        log "$label not running (stale pid $pid)."
    fi
    rm -f "$pid_file"
}

stop_all_processes() {
    kill_pid_file "Dashboard"          DASHBOARD_PID  "uvicorn"
    kill_pid_file "patched-extractor"  EXTRACTOR_PID  "patched-extractor"
    kill_pid_file "patched-api"        API_PID        "patched-api"
    # Catch orphaned go-run child binaries: 'go run' forks the compiled binary as
    # a child which can outlive the parent go process (gets reparented to launchd).
    # Kill anything still listening on our E2E ports.
    kill_port "$DASHBOARD_PORT"
    kill_port "$API_INTERNAL_PORT"
    kill_port "$API_PUBLIC_PORT"
    # Belt-and-suspenders: kill by name in case lsof missed them.
    pkill -f 'exe/patched-api' 2>/dev/null || true
    pkill -f 'exe/patched-extractor' 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
cmd_up() {
    mkdir -p "$STATE"
    log "=== Patched E2E stack: UP ==="

    # 1. Postgres
    if detect_docker; then
        pg_up_docker
    else
        log "Docker not available — using native PostgreSQL."
        pg_up_native
    fi

    # 2. Wait for Postgres
    wait_for_pg

    # 3. Generate secrets (idempotent)
    generate_secrets

    # 4. Apply migrations (idempotent via marker file)
    apply_migrations

    # 5. Start API (idempotent)
    start_api
    wait_for_api

    # 6. Bootstrap tenant (idempotent)
    bootstrap_tenant

    # 7. Start extractor (idempotent)
    start_extractor

    # 8. Start dashboard (idempotent)
    start_dashboard
    wait_for_dashboard

    log "=== Stack UP. State in $STATE/ ==="
    printf '\n'
    cmd_status
}

cmd_down() {
    log "=== Patched E2E stack: DOWN ==="

    stop_all_processes

    local pg_mode
    pg_mode="$(state_get PG_MODE)"
    if [[ "$pg_mode" == "docker" ]]; then
        pg_down_docker
    else
        pg_down_native
    fi

    # Clean up state so next 'up' does a fresh bootstrap.
    rm -rf "$STATE"
    log "State cleared."

    log "=== Stack DOWN ==="
}

cmd_status() {
    printf '[stack] === Patched E2E status ===\n'
    local pg_mode
    pg_mode="$(state_get PG_MODE)"

    # Postgres
    if pg_ready 2>/dev/null; then
        printf '[stack] Postgres      : RUNNING  (127.0.0.1:%d, mode=%s)\n' "$PG_PORT" "${pg_mode:-unknown}"
    else
        printf '[stack] Postgres      : NOT READY\n'
    fi

    # API
    local api_pid
    api_pid="$(state_get API_PID)"
    if [[ -n "$api_pid" ]] && pid_alive "$api_pid"; then
        local health
        health="$(curl -sf "http://127.0.0.1:${API_PUBLIC_PORT}/health" 2>/dev/null)" || health="?"
        printf '[stack] patched-api   : RUNNING  (pid %s, /health: %s)\n' "$api_pid" "$health"
    else
        printf '[stack] patched-api   : NOT RUNNING\n'
    fi

    # Extractor
    local ext_pid
    ext_pid="$(state_get EXTRACTOR_PID)"
    if [[ -n "$ext_pid" ]] && pid_alive "$ext_pid"; then
        printf '[stack] p-extractor   : RUNNING  (pid %s)\n' "$ext_pid"
    else
        printf '[stack] p-extractor   : NOT RUNNING\n'
    fi

    # Dashboard
    local dash_pid
    dash_pid="$(state_get DASHBOARD_PID)"
    if [[ -n "$dash_pid" ]] && pid_alive "$dash_pid"; then
        local dash_status
        dash_status="$(curl -so /dev/null -w '%{http_code}' \
            "http://127.0.0.1:${DASHBOARD_PORT}/" 2>/dev/null)" || dash_status="000"
        printf '[stack] Dashboard     : RUNNING  (pid %s, HTTP %s)\n' "$dash_pid" "$dash_status"
    else
        printf '[stack] Dashboard     : NOT RUNNING\n'
    fi

    # Tenant
    local tenant_id
    tenant_id="$(state_get TENANT_ID)"
    if [[ -n "$tenant_id" ]]; then
        printf '[stack] Tenant        : %s\n' "$tenant_id"
    else
        printf '[stack] Tenant        : not bootstrapped\n'
    fi
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
case "${1:-}" in
    up)     cmd_up ;;
    down)   cmd_down ;;
    status) cmd_status ;;
    *)
        printf 'Usage: %s up|down|status\n' "$0" >&2
        exit 1
        ;;
esac
