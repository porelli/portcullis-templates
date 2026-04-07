#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# Shared test library for Portcullis app auth tests.
#
# Source from each test script:
#   cd "$(dirname "$0")/../.."
#   source tests/lib.sh
#
# QUIRKS & GOTCHAS (read before editing):
#
# 1. BASH ARITHMETIC UNDER set -e
#    Never use (( COUNT++ )) — when COUNT is 0, bash evaluates the
#    expression as 0 (falsy) and returns exit code 1, which kills
#    the script under set -e. Use COUNT=$((COUNT + 1)) instead.
#
# 2. TRAP EXIT + set -e INTERACTION
#    The `trap report EXIT` runs when the script exits for ANY reason
#    including set -e failures. The trap does NOT override the exit
#    code — if set -e killed the script, exit code 1 propagates even
#    if report() doesn't call exit. This means any unguarded failure
#    in a test script will show "0 FAILED, N passed" but still exit 1.
#
# 3. _find_compose AND set -e
#    _find_compose returns 1 when no file is found. If called as
#    VAR=$(_find_compose "app"), set -e kills the script before the
#    caller can handle the error. Always use || to guard:
#      compose_path=$(_find_compose "$app") || { fail "not found"; return 1; }
#    Or in tests that do inline lookup, use || true:
#      COMPOSE=$(_find_compose "$APP_ID" || true)
#
# 4. RESOLVE_OPTS WILDCARD
#    curl's --resolve flag does NOT support glob patterns. The
#    "*.domain:443:127.0.0.1" syntax is accepted by curl but only
#    matches literal "*", not wildcards. In CI, tests that need HTTPS
#    access to Traefik-routed apps should use container IPs directly
#    instead of going through Traefik. RESOLVE_OPTS is kept for
#    reference but is unreliable in CI.
#
# 5. CROSS-NETWORK DNS (ISOLATED APPS)
#    App containers are on the portcullis-proxy network (for Traefik)
#    and their own default network. They CANNOT reach core services
#    (keycloak, lldap, postgres) by DNS name — this is by design.
#    Tests must NOT assert_container_can_reach "http://keycloak:8080/..."
#    For OIDC connectivity, check env var configuration instead.
#
# 6. PROJECT_DIR vs TEMPLATES_DIR
#    In CI, these point to different directories:
#      PROJECT_DIR  = core repo checkout (has .env, certs/, scripts/)
#      TEMPLATES_DIR = templates repo checkout (has <app>/compose.yml)
#    Compose files are found via TEMPLATES_DIR but --project-directory
#    is PROJECT_DIR (so ./certs/ and ./scripts/ paths resolve from core).
#    The --project-directory must be the HOST path for Docker bind mount
#    resolution when Hub runs inside a container.
#
# 7. CONTAINER NAMING
#    compose_up uses -p portcullis, so containers are named
#    portcullis-<service>-1. app_container_ip looks for this pattern.
#    If a compose file has service "wiki" under project "portcullis",
#    the container is "portcullis-wiki-1".
#
# 8. IMAGE PULL TIMES IN CI
#    GitHub Actions runners pull images on every job (no daemon cache
#    between jobs). Large images (GitLab 2GB+, Plex 500MB+) can take
#    60+ seconds, eating into wait_for_url timeouts. For unreliable
#    apps, prefer static compose-config tests over container tests.
#
# 9. PORT CONFLICTS
#    Apps binding host ports (AdGuard/Pi-hole on port 53) may conflict
#    with the CI runner's systemd-resolved. Container tests for these
#    apps are unreliable. Use static tests instead.
#
# 10. STATIC vs CONTAINER TESTS
#     Two test patterns exist:
#     - Static: grep compose.yml for labels/env/ports (no Docker needed)
#     - Container: compose_up + wait_for_url + curl (needs Docker + infra)
#     Static tests are faster and more reliable. Container tests verify
#     actual app behavior but are flaky in CI. Prefer static for:
#     apps with port conflicts, very large images, complex startup, or
#     apps that need mounted content files (docs site).
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Config ─────────────────────────────────────────────────
DOMAIN="${PORTCULLIS_DOMAIN:-portcullis.local}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
LLDAP_URL="${LLDAP_URL:-http://localhost:17170}"
LLDAP_PASS="${LLDAP_ADMIN_PASSWORD:-ci-lldap-pass}"
KC_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KC_PASS="${KEYCLOAK_ADMIN_PASSWORD:-ci-admin-pass}"
PROJECT_DIR="${PROJECT_DIR:-.}"

# QUIRK #4: Wildcard in --resolve doesn't actually work in curl.
# Kept for reference; tests should use container IPs directly.
RESOLVE_OPTS="--resolve *.${DOMAIN}:443:127.0.0.1 --cacert certs/ca-chain.crt"

# QUIRK #1: Use $((X + 1)) not ((X++)) to avoid exit code 1 when X=0.
PASS_COUNT=0
FAIL_COUNT=0
TEST_NAME="${TEST_NAME:-unknown}"

# ── Output ─────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { PASS_COUNT=$((PASS_COUNT + 1)); echo -e "  ${GREEN}PASS${NC} $*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); echo -e "  ${RED}FAIL${NC} $*"; }
info() { echo -e "  ${YELLOW}INFO${NC} $*"; }
section() { echo -e "\n=== $* ==="; }

# QUIRK #2: trap runs on any exit. If set -e killed the script,
# the original non-zero exit code is preserved even though report()
# doesn't call exit when FAIL_COUNT=0.
report() {
  echo ""
  if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "${RED}$TEST_NAME: $FAIL_COUNT FAILED, $PASS_COUNT passed${NC}"
    exit 1
  else
    echo -e "${GREEN}$TEST_NAME: All $PASS_COUNT tests passed${NC}"
  fi
}
trap report EXIT

# ── Wait helpers ───────────────────────────────────────────
wait_for_url() {
  local url="$1" timeout="${2:-60}" label="${3:-$1}"
  info "Waiting for $label..."
  for i in $(seq 1 "$timeout"); do
    if curl -sf -o /dev/null "$url" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  # QUIRK #8: In CI, image pull eats into this timeout.
  # Increase timeout for large apps or use static tests.
  fail "Timeout waiting for $label ($url)"
  return 1
}

wait_for_container() {
  local name="$1" timeout="${2:-60}"
  info "Waiting for container $name..."
  for i in $(seq 1 "$timeout"); do
    if docker inspect "$name" --format '{{.State.Running}}' 2>/dev/null | grep -q true; then
      return 0
    fi
    sleep 1
  done
  fail "Container $name not running after ${timeout}s"
  return 1
}

# ── Keycloak helpers ───────────────────────────────────────
keycloak_admin_token() {
  curl -sf "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
    -d "client_id=admin-cli" \
    -d "username=$KC_ADMIN" \
    -d "password=$KC_PASS" \
    -d "grant_type=password" | jq -r '.access_token'
}

keycloak_user_token() {
  local user="$1" password="$2" client_id="${3:-portcullis-forward-auth}" client_secret="${4:-${FORWARD_AUTH_CLIENT_SECRET:-ci-forward-auth-secret}}"
  curl -sf "$KEYCLOAK_URL/realms/portcullis/protocol/openid-connect/token" \
    -d "client_id=$client_id" \
    -d "client_secret=$client_secret" \
    -d "username=$user" \
    -d "password=$password" \
    -d "grant_type=password" \
    -d "scope=openid email profile groups" | jq -r '.access_token'
}

keycloak_enable_direct_grant() {
  local client_id="$1"
  local token
  token=$(keycloak_admin_token)
  local uuid
  uuid=$(curl -sf "$KEYCLOAK_URL/admin/realms/portcullis/clients?clientId=$client_id" \
    -H "Authorization: Bearer $token" | jq -r '.[0].id')
  curl -sf -o /dev/null -X PUT "$KEYCLOAK_URL/admin/realms/portcullis/clients/$uuid" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -d "{\"clientId\":\"$client_id\",\"directAccessGrantsEnabled\":true}"
}

keycloak_register_client() {
  local client_id="$1" secret="$2" redirect_uri="$3"
  local token
  token=$(keycloak_admin_token)
  curl -sf -o /dev/null -w "%{http_code}" \
    "$KEYCLOAK_URL/admin/realms/portcullis/clients" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -d "{
      \"clientId\":\"$client_id\",
      \"enabled\":true,
      \"protocol\":\"openid-connect\",
      \"publicClient\":false,
      \"secret\":\"$secret\",
      \"redirectUris\":[\"$redirect_uri\"],
      \"standardFlowEnabled\":true,
      \"directAccessGrantsEnabled\":true
    }"
}

# ── LLDAP helpers ──────────────────────────────────────────
lldap_token() {
  curl -sf "$LLDAP_URL/auth/simple/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"$LLDAP_PASS\"}" | jq -r '.token'
}

lldap_graphql() {
  local query="$1"
  local token
  token=$(lldap_token)
  curl -sf "$LLDAP_URL/api/graphql" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"$query\"}"
}

lldap_create_user() {
  local username="$1" email="$2" password="${3:-}"
  lldap_graphql "mutation { createUser(user: {id: \\\"$username\\\", email: \\\"$email\\\"}) { id } }" > /dev/null 2>&1 || true
  if [ -n "$password" ]; then
    local token
    token=$(lldap_token)
    curl -sf -o /dev/null "$LLDAP_URL/api/graphql" \
      -H "Authorization: Bearer $token" \
      -H "Content-Type: application/json" \
      -d "{\"query\":\"mutation { updateUser(user: {id: \\\"$username\\\"}) { ok } }\"}" 2>/dev/null || true
  fi
}

lldap_create_group() {
  local name="$1"
  local result
  result=$(lldap_graphql "mutation { createGroup(name: \\\"$name\\\") { id } }" 2>/dev/null || true)
  echo "$result" | jq -r '.data.createGroup.id // empty' 2>/dev/null
}

lldap_add_to_group() {
  local user="$1" group_id="$2"
  lldap_graphql "mutation { addUserToGroup(userId: \\\"$user\\\", groupId: $group_id) { ok } }" > /dev/null 2>&1 || true
}

lldap_sync_keycloak() {
  local token
  token=$(keycloak_admin_token)
  local ldap_id
  ldap_id=$(curl -sf "$KEYCLOAK_URL/admin/realms/portcullis/components" \
    -H "Authorization: Bearer $token" | jq -r '.[] | select(.providerId=="ldap") | .id')
  if [ -n "$ldap_id" ]; then
    local mapper_id
    mapper_id=$(curl -sf "$KEYCLOAK_URL/admin/realms/portcullis/components?parent=$ldap_id" \
      -H "Authorization: Bearer $token" | jq -r '.[] | select(.providerId=="group-ldap-mapper") | .id')
    if [ -n "$mapper_id" ]; then
      curl -sf -o /dev/null -X POST \
        "$KEYCLOAK_URL/admin/realms/portcullis/user-storage/$ldap_id/mappers/$mapper_id/sync?direction=fedToKeycloak" \
        -H "Authorization: Bearer $token"
    fi
    curl -sf -o /dev/null -X POST \
      "$KEYCLOAK_URL/admin/realms/portcullis/user-storage/$ldap_id/sync?action=triggerFullSync" \
      -H "Authorization: Bearer $token"
  fi
}

# ── Assertions ─────────────────────────────────────────────
assert_http_code() {
  local url="$1" expected="$2"
  shift 2
  local actual
  # QUIRK #4: RESOLVE_OPTS uses a glob that curl doesn't actually expand.
  # Use container IPs for reliable CI testing instead of Traefik routing.
  actual=$(curl -sf -o /dev/null -w "%{http_code}" $RESOLVE_OPTS "$@" "$url" 2>/dev/null || echo "000")
  if [ "$actual" = "$expected" ]; then
    pass "$url → HTTP $actual"
  else
    fail "$url → expected HTTP $expected, got $actual"
  fi
}

assert_redirect_to_keycloak() {
  local url="$1"
  shift
  # QUIRK #4: This function relies on RESOLVE_OPTS which is unreliable.
  # Prefer static compose-config tests for forward-auth apps in CI.
  local location
  location=$(curl -sf -o /dev/null -w "%{redirect_url}" -L --max-redirs 0 $RESOLVE_OPTS "$@" "$url" 2>/dev/null || true)
  if echo "$location" | grep -q "auth\.$DOMAIN"; then
    pass "$url → redirects to Keycloak"
  else
    local location2
    location2=$(curl -sf -o /dev/null -w "%{redirect_url}" -L --max-redirs 2 $RESOLVE_OPTS "$@" "$url" 2>/dev/null || true)
    if echo "$location2" | grep -q "auth\.$DOMAIN"; then
      pass "$url → redirects to Keycloak (via oauth2-proxy)"
    else
      fail "$url → expected redirect to Keycloak, got: $location"
    fi
  fi
}

assert_redirect_contains() {
  local url="$1" expected="$2"
  shift 2
  local location
  location=$(curl -sf -o /dev/null -w "%{redirect_url}" --max-redirs 5 -L $RESOLVE_OPTS "$@" "$url" 2>/dev/null || true)
  if echo "$location" | grep -q "$expected"; then
    pass "$url → redirect contains '$expected'"
  else
    fail "$url → redirect does not contain '$expected', got: $location"
  fi
}

assert_body_contains() {
  local url="$1" expected="$2"
  shift 2
  local body
  body=$(curl -sf $RESOLVE_OPTS "$@" "$url" 2>/dev/null || echo "")
  if echo "$body" | grep -q "$expected"; then
    pass "$url → body contains '$expected'"
  else
    fail "$url → body does not contain '$expected'"
  fi
}

assert_container_can_reach() {
  # QUIRK #5: App containers are on isolated networks and CANNOT reach
  # core services (keycloak, lldap) by DNS. Don't use this to test
  # OIDC discovery — check env var configuration instead.
  local container="$1" url="$2"
  if docker exec "$container" curl -sf "$url" > /dev/null 2>&1; then
    pass "$container can reach $url"
  else
    if docker exec "$container" wget -qO- "$url" > /dev/null 2>&1; then
      pass "$container can reach $url"
    else
      fail "$container cannot reach $url"
    fi
  fi
}

# ── Compose helpers ────────────────────────────────────────
# QUIRK #6: TEMPLATES_DIR and PROJECT_DIR serve different purposes.
# TEMPLATES_DIR = where compose files live (templates repo)
# PROJECT_DIR   = where .env and certs/ live (core repo)
TEMPLATES_DIR="${TEMPLATES_DIR:-$PROJECT_DIR/templates}"

_find_compose() {
  # QUIRK #3: Returns exit 1 when not found. Guard with || to avoid
  # set -e killing the caller. See header comment for details.
  local app_id="$1"
  for p in "$TEMPLATES_DIR/$app_id/compose.yml" "templates/$app_id/compose.yml" "$app_id/compose.yml"; do
    [ -f "$p" ] && echo "$p" && return 0
  done
  return 1
}

compose_up() {
  local app_id="$1"
  local compose_path
  # QUIRK #3: Guard _find_compose with || to prevent set -e exit.
  compose_path=$(_find_compose "$app_id") || { fail "compose.yml not found for $app_id"; return 1; }
  info "Starting $app_id..."
  # QUIRK #7: -p portcullis means containers are named portcullis-<service>-1.
  # QUIRK #6: --project-directory is PROJECT_DIR (core repo) so ./certs/
  # bind mounts resolve correctly even though the compose file is elsewhere.
  COMPOSE_IGNORE_ORPHANS=true docker compose \
    -p portcullis \
    -f "$compose_path" \
    --project-directory "$PROJECT_DIR" \
    --env-file "$PROJECT_DIR/.env" \
    up -d --no-deps 2>&1 | tail -5
}

compose_down() {
  local app_id="$1"
  local compose_path
  compose_path=$(_find_compose "$app_id") || return 0
  COMPOSE_IGNORE_ORPHANS=true docker compose \
    -p portcullis \
    -f "$compose_path" \
    --project-directory "$PROJECT_DIR" \
    --env-file "$PROJECT_DIR/.env" \
    down 2>&1 | tail -3
}

app_container_ip() {
  # QUIRK #7: Container names follow the pattern portcullis-<service>-1.
  # Returns the first non-empty IP across all networks. If the container
  # is on multiple networks (default + portcullis-proxy), either IP works
  # for direct HTTP access from the CI host.
  local app_id="$1" service="${2:-$1}"
  docker inspect "portcullis-${service}-1" --format '{{range $net, $conf := .NetworkSettings.Networks}}{{if $conf.IPAddress}}{{$conf.IPAddress}}{{end}} {{end}}' 2>/dev/null | awk '{print $1}'
}

app_logs() {
  local app_id="$1" lines="${2:-20}"
  local compose_path
  compose_path=$(_find_compose "$app_id") || return 0
  COMPOSE_IGNORE_ORPHANS=true docker compose \
    -p portcullis \
    -f "$compose_path" \
    --project-directory "$PROJECT_DIR" \
    --env-file "$PROJECT_DIR/.env" \
    logs --tail "$lines" --no-color 2>&1
}
