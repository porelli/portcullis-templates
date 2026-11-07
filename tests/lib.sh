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
#    GitHub Actions runners start with an empty daemon. test-apps.yml
#    loads the app's images from a cache warmed on pushes to main (see
#    tests/app-images.sh) before the test runs, but a cache miss (new
#    image version, evicted entry) means compose_up pulls them. Large
#    images (GitLab 2GB+, Plex 500MB+) can take 60+ seconds, eating into
#    wait_for_url timeouts. For unreliable apps, prefer static
#    compose-config tests over container tests.
#
# 9. HOST PORT BINDINGS
#    Apps binding host ports (e.g. AdGuard/Pi-hole on 53) declare them in
#    manifest.yaml under "ports:". The Hub emits the effective bindings
#    into a per-app compose override — base compose.yml files must not
#    contain "ports:" for anything the manifest declares. CI tests for
#    these apps use static manifest checks, not container boots, because
#    the runner's systemd-resolved would fight over 53.
#
# 10. STATIC vs CONTAINER TESTS
#     Two test patterns exist:
#     - Static: grep compose.yml for labels/env/ports (no Docker needed)
#     - Container: compose_up + wait_for_url + curl (needs Docker + infra)
#     Static tests are faster and more reliable. Container tests verify
#     actual app behavior but are flaky in CI. Prefer static for:
#     apps with port conflicts, very large images, complex startup, or
#     apps that need mounted content files (docs site).
#
# 11. PER-APP GENERATED ENV
#     The Hub writes every manifest env var with "generate: random" into a
#     per-app .env (32 hex chars). Compose files may therefore require them
#     with ${VAR:?...}. CI only has the core .env, so compose_up/down/logs
#     call _export_manifest_env to export a random value for each such var
#     that is not already set (shell env wins over --env-file).
#
# 12. PUBLIC EXCEPTIONS (auth.public_access)
#     compose.yml never carries the public router: the Hub generates it in
#     the per-app override when the exception is on (see the Hub's
#     internal/hub/public.go). Tests emulate that override with
#     write_public_override and pass it to compose_up via COMPOSE_OVERRIDE,
#     and give core's real public guard (group-gate /public-guard, policy
#     file at core's version, policy_version) its entry with write_public_policy. Keep the header and
#     extension lists below in sync with the Hub.
#
# 13. INSTANCE VARIABLES (contract v2)
#     The Hub writes PORTCULLIS_INSTANCE, PORTCULLIS_HOST_<ROUTER>,
#     PORTCULLIS_OIDC_CLIENT_ID(_<KEY>), PORTCULLIS_ACCESS_GROUP and
#     PORTCULLIS_ADMIN_GROUP into every instance's .env. CI runs the default
#     instance: compose_up/down/logs call _export_instance_env, which exports
#     the default instance's values (<sub>.$DOMAIN for each host router, the
#     manifest's first client_id and groups). Volumes of multi templates have
#     no name: in compose.yml; the Hub names them portcullis_<key> for the
#     default instance, which is what "-p portcullis" (QUIRK #7) gives too.
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Config ─────────────────────────────────────────────────
DOMAIN="${PORTCULLIS_DOMAIN:-portcullis.local}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
LLDAP_URL="${LLDAP_URL:-http://localhost:17170}"
PROJECT_DIR="${PROJECT_DIR:-.}"
# Core credentials: the environment (CI exports them), else core's .env as
# generated by `portcullis init --env-only` (parsed, never sourced). There
# are no built-in defaults: core generates every secret.
_core_env() {
  local v="${!1:-}"
  if [ -z "$v" ] && [ -f "$PROJECT_DIR/.env" ]; then
    v=$(grep -m1 "^$1=" "$PROJECT_DIR/.env" | cut -d= -f2- || true)
  fi
  printf '%s' "$v"
}
LLDAP_PASS="$(_core_env LLDAP_ADMIN_PASSWORD)"
KC_ADMIN="$(_core_env KEYCLOAK_ADMIN)"
KC_ADMIN="${KC_ADMIN:-admin}"
KC_PASS="$(_core_env KEYCLOAK_ADMIN_PASSWORD)"

# QUIRK #4: Wildcard in --resolve doesn't actually work in curl.
# Kept for reference; tests should use container IPs directly.
# --cacert only when core's CA exists: curl >= 8.18 (ubuntu-26.04) refuses to
# run at all (exit 2, "000" here) when the --cacert file is missing, even for
# plain-HTTP URLs; the old relative certs/ca-chain.crt never existed in the
# templates checkout.
RESOLVE_OPTS="--resolve *.${DOMAIN}:443:127.0.0.1"
[ ! -f "$PROJECT_DIR/certs/ca-chain.crt" ] || RESOLVE_OPTS="$RESOLVE_OPTS --cacert $PROJECT_DIR/certs/ca-chain.crt"

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
  for _ in $(seq 1 "$timeout"); do
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
  for _ in $(seq 1 "$timeout"); do
    if docker inspect "$name" --format '{{.State.Running}}' 2>/dev/null | grep -q true; then
      return 0
    fi
    sleep 1
  done
  fail "Container $name not running after ${timeout}s"
  return 1
}

# ── Keycloak helpers ───────────────────────────────────────
# Sign-in to the portcullis realm is passkey-only (core): no user has a
# password and no client allows the direct (password) grant, so a test
# cannot obtain a user token or session. Core's own browser e2e redeems a
# setup link (`./portcullis invite`) with a virtual WebAuthn authenticator.
# App tests therefore assert the unauthenticated side (redirect to
# auth.<domain>, public guard refusals) and header trust
# (assert_traefik_only_trust, assert_spoofed_identity_rejected).
#
# Admin API token (master realm, admin-cli), as core's CI gets it. Secrets
# go on stdin, never on argv.
keycloak_admin_token() {
  printf '%s' "$KC_PASS" | curl -sf "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
    --data-urlencode "client_id=admin-cli" \
    --data-urlencode "username=$KC_ADMIN" \
    --data-urlencode "grant_type=password" \
    --data-urlencode "password@-" | jq -r '.access_token'
}

# ── LLDAP helpers ──────────────────────────────────────────
lldap_token() {
  LLDAP_PASS="$LLDAP_PASS" jq -nc '{username: "admin", password: env.LLDAP_PASS}' \
    | curl -sf "$LLDAP_URL/auth/simple/login" -H "Content-Type: application/json" -d @- | jq -r '.token'
}

lldap_graphql() {
  local query="$1"
  local token
  token=$(lldap_token)
  jq -nc --arg q "$query" '{query: $q}' | curl -sf "$LLDAP_URL/api/graphql" \
    -H @<(printf 'Authorization: Bearer %s\n' "$token") \
    -H "Content-Type: application/json" \
    -d @-
}

# Users get no password (passkey-only sign-in).
lldap_create_user() {
  local username="$1" email="$2"
  lldap_graphql "mutation { createUser(user: {id: \"$username\", email: \"$email\"}) { id } }" > /dev/null 2>&1 || true
}

lldap_create_group() {
  local name="$1"
  local result
  result=$(lldap_graphql "mutation { createGroup(name: \"$name\") { id } }" 2>/dev/null || true)
  echo "$result" | jq -r '.data.createGroup.id // empty' 2>/dev/null
}

lldap_add_to_group() {
  local user="$1" group_id="$2"
  lldap_graphql "mutation { addUserToGroup(userId: \"$user\", groupId: $group_id) { ok } }" > /dev/null 2>&1 || true
}

lldap_sync_keycloak() {
  local token
  token=$(keycloak_admin_token)
  local ldap_id
  ldap_id=$(curl -sf "$KEYCLOAK_URL/admin/realms/portcullis/components" \
    -H @<(printf 'Authorization: Bearer %s\n' "$token") | jq -r '.[] | select(.providerId=="ldap") | .id')
  if [ -n "$ldap_id" ]; then
    local mapper_id
    mapper_id=$(curl -sf "$KEYCLOAK_URL/admin/realms/portcullis/components?parent=$ldap_id" \
      -H @<(printf 'Authorization: Bearer %s\n' "$token") | jq -r '.[] | select(.providerId=="group-ldap-mapper") | .id')
    if [ -n "$mapper_id" ]; then
      curl -sf -o /dev/null -X POST \
        "$KEYCLOAK_URL/admin/realms/portcullis/user-storage/$ldap_id/mappers/$mapper_id/sync?direction=fedToKeycloak" \
        -H @<(printf 'Authorization: Bearer %s\n' "$token")
    fi
    curl -sf -o /dev/null -X POST \
      "$KEYCLOAK_URL/admin/realms/portcullis/user-storage/$ldap_id/sync?action=triggerFullSync" \
      -H @<(printf 'Authorization: Bearer %s\n' "$token")
  fi
}

# ── Assertions ─────────────────────────────────────────────
assert_http_code() {
  local url="$1" expected="$2"
  shift 2
  local actual
  # QUIRK #4: RESOLVE_OPTS uses a glob that curl doesn't actually expand.
  # Use container IPs for reliable CI testing instead of Traefik routing.
  # No -f: with it curl exits non-zero on 4xx/5xx and "000" would be
  # appended to the code it already printed.
  actual=$(curl -s -o /dev/null -w "%{http_code}" $RESOLVE_OPTS "$@" "$url" 2>/dev/null) || actual="000"
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

# Header-auth apps must accept identity headers only from Traefik, whose
# static IP on portcullis-proxy is PORTCULLIS_TRAEFIK_IP (core .env).
# Static check: the given setting line references PORTCULLIS_TRAEFIK_IP and
# the compose file has no catch-all trust ("**", 0.0.0.0/0, ::/0).
assert_traefik_only_trust() {
  local compose="$1" setting="$2"
  if grep -Eq "^[[:space:]]*${setting}:[[:space:]]*\\\$\\{PORTCULLIS_TRAEFIK_IP:-" "$compose"; then
    pass "$setting restricted to \${PORTCULLIS_TRAEFIK_IP}"
  else
    fail "$setting is not restricted to \${PORTCULLIS_TRAEFIK_IP}"
  fi
  if grep -Eq '"\*\*"|0\.0\.0\.0/0|::/0' "$compose"; then
    fail "compose trusts every peer (\"**\", 0.0.0.0/0 or ::/0)"
  else
    pass "No catch-all proxy trust in compose"
  fi
}

# Runtime check: a request carrying X-Forwarded-User straight from the CI
# host (not Traefik) must not be answered with 2xx.
assert_spoofed_identity_rejected() {
  local url="$1" expected="${2:-403}"
  shift 2 || shift $#
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Forwarded-User: admin" "$@" "$url" 2>/dev/null || true)
  if [ "$expected" = "non-2xx" ]; then
    case "$code" in
      2??|000|"") fail "$url with spoofed X-Forwarded-User → HTTP ${code:-none} (expected rejection)" ;;
      *) pass "$url with spoofed X-Forwarded-User → HTTP $code (rejected)" ;;
    esac
  elif [ "$code" = "$expected" ]; then
    pass "$url with spoofed X-Forwarded-User → HTTP $code"
  else
    fail "$url with spoofed X-Forwarded-User → expected HTTP $expected, got ${code:-none}"
  fi
}

# Same for X-Forwarded-Email (group-gate forwards the user-editable LLDAP
# email in it; apps may show it, never key accounts on it).
assert_spoofed_email_rejected() {
  local url="$1" expected="${2:-403}"
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Forwarded-Email: admin@example.com" "$url" 2>/dev/null || true)
  if [ "$code" = "$expected" ]; then
    pass "$url with spoofed X-Forwarded-Email → HTTP $code"
  else
    fail "$url with spoofed X-Forwarded-Email → expected HTTP $expected, got ${code:-none}"
  fi
}

# Static check: compose sets `KEY: value` (exact, optional quotes).
# Identity must never be keyed on the user-editable email.
assert_compose_setting() {
  local compose="$1" key="$2" value="$3"
  if grep -Eq "^[[:space:]]*${key}:[[:space:]]*[\"']?${value}[\"']?[[:space:]]*(#.*)?$" "$compose"; then
    pass "$key: $value"
  else
    fail "$key is not '$value' in $compose"
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

# QUIRK #11: print the env keys a manifest marks "generate: random".
# Minimal line-based parser (no yq dependency) for the flat env: list format
# used by every manifest in this repo.
_manifest_random_env_keys() {
  awk '
    /^[^[:space:]#]/ { in_env = ($0 ~ /^env:/); key = ""; next }
    in_env && /^[[:space:]]*-[[:space:]]*key:/ {
      sub(/^[[:space:]]*-[[:space:]]*key:[[:space:]]*/, "")
      sub(/[[:space:]]*(#.*)?$/, "")
      gsub(/["\047]/, "")
      key = $0; next
    }
    in_env && /^[[:space:]]*-/ { key = ""; next }
    in_env && /^[[:space:]]*generate:[[:space:]]*["\047]?random/ { if (key != "") print key; key = "" }
  ' "$1"
}

# QUIRK #11: mirror the Hub's generateAppEnv for CI.
_export_manifest_env() {
  local compose_path="$1" manifest key
  manifest="$(dirname "$compose_path")/manifest.yaml"
  [ -f "$manifest" ] || return 0
  while IFS= read -r key; do
    [ -n "$key" ] || continue
    if [ -z "${!key:-}" ]; then
      export "$key=$(openssl rand -hex 16)"
    fi
  done < <(_manifest_random_env_keys "$manifest")
}

# QUIRK #13: mirror the Hub's instance variables for the default instance.
_export_instance_env() {
  local compose_path="$1" manifest var sub key cid first="" group
  manifest="$(dirname "$compose_path")/manifest.yaml"
  PORTCULLIS_INSTANCE="$(basename "$(dirname "$compose_path")")"
  export PORTCULLIS_INSTANCE
  while read -r var sub; do
    [ -n "$var" ] && export "$var=$sub.$DOMAIN"
  done < <(grep -oE '\$\{PORTCULLIS_HOST_[A-Z0-9_]+:-[a-z0-9-]+\.portcullis\.local\}' "$compose_path" \
    | sed -E 's/^\$\{(PORTCULLIS_HOST_[A-Z0-9_]+):-([a-z0-9-]+)\.portcullis\.local\}$/\1 \2/' | sort -u)
  [ -f "$manifest" ] || return 0
  while read -r cid; do
    [ -n "$cid" ] || continue
    [ -n "$first" ] || first="$cid"
    key=$(printf '%s' "$cid" | tr '[:lower:].-' '[:upper:]__')
    export "PORTCULLIS_OIDC_CLIENT_ID_$key=$cid"
  done < <(sed -n 's/^[[:space:]]*-[[:space:]]*client_id:[[:space:]]*["\047]\{0,1\}\([A-Za-z0-9_.-]*\).*/\1/p' "$manifest")
  export PORTCULLIS_OIDC_CLIENT_ID="$first"
  group=$(sed -n 's/^  access_group:[[:space:]]*["\047]\{0,1\}\([A-Za-z0-9_.-]*\).*/\1/p' "$manifest")
  export PORTCULLIS_ACCESS_GROUP="$group"
  group=$(sed -n 's/^  admin_group:[[:space:]]*["\047]\{0,1\}\([A-Za-z0-9_.-]*\).*/\1/p' "$manifest")
  export PORTCULLIS_ADMIN_GROUP="$group"
}

compose_up() {
  local app_id="$1"
  local compose_path
  # QUIRK #3: Guard _find_compose with || to prevent set -e exit.
  compose_path=$(_find_compose "$app_id") || { fail "compose.yml not found for $app_id"; return 1; }
  _export_manifest_env "$compose_path"
  _export_instance_env "$compose_path"
  info "Starting $app_id..."
  # QUIRK #12: extra -f for an emulated Hub override (COMPOSE_OVERRIDE).
  local extra=()
  if [ -n "${COMPOSE_OVERRIDE:-}" ]; then extra=(-f "$COMPOSE_OVERRIDE"); fi
  # QUIRK #7: -p portcullis means containers are named portcullis-<service>-1.
  # QUIRK #6: --project-directory is PROJECT_DIR (core repo) so ./certs/
  # bind mounts resolve correctly even though the compose file is elsewhere.
  COMPOSE_IGNORE_ORPHANS=true docker compose \
    -p portcullis \
    -f "$compose_path" ${extra[@]+"${extra[@]}"} \
    --project-directory "$PROJECT_DIR" \
    --env-file "$PROJECT_DIR/.env" \
    up -d --no-deps 2>&1 | tail -5
}

compose_down() {
  local app_id="$1"
  local compose_path
  compose_path=$(_find_compose "$app_id") || return 0
  _export_manifest_env "$compose_path"
  _export_instance_env "$compose_path"
  # QUIRK #12: extra -f for an emulated Hub override (COMPOSE_OVERRIDE).
  local extra=()
  if [ -n "${COMPOSE_OVERRIDE:-}" ]; then extra=(-f "$COMPOSE_OVERRIDE"); fi
  COMPOSE_IGNORE_ORPHANS=true docker compose \
    -p portcullis \
    -f "$compose_path" ${extra[@]+"${extra[@]}"} \
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
  _export_manifest_env "$compose_path"
  _export_instance_env "$compose_path"
  COMPOSE_IGNORE_ORPHANS=true docker compose \
    -p portcullis \
    -f "$compose_path" \
    --project-directory "$PROJECT_DIR" \
    --env-file "$PROJECT_DIR/.env" \
    logs --tail "$lines" --no-color 2>&1
}

# ── Public exceptions (QUIRK #12) ──────────────────────────
# Mirror of the Hub's coreIdentityHeaders + credentialHeaders
# (internal/hub/public.go); the manifest's auth.identity_headers,
# public_access.credential_headers and every settings header delivery
# (header: {name: X-Forwarded-Attr-...}, flow form as used in this repo) are
# added, all also in underscore form.
PUBLIC_CORE_HEADERS=(Remote-Email Remote-Groups Remote-Name Remote-User
  X-Auth-Request-Access-Token X-Auth-Request-Email X-Auth-Request-Groups
  X-Auth-Request-Preferred-Username X-Auth-Request-User
  X-Forwarded-Access-Token X-Forwarded-Email X-Forwarded-Groups
  X-Forwarded-Preferred-Username X-Forwarded-User)

_public_strip_headers() {
  local manifest="$1" h
  {
    printf '%s\n' "${PUBLIC_CORE_HEADERS[@]}" Authorization Proxy-Authorization
    sed -n 's/^  identity_headers:[[:space:]]*\[\(.*\)\].*/\1/p' "$manifest" | tr ',' '\n' | tr -d ' "\047'
    _manifest_public_list "$manifest" credential_headers
    sed -n 's/.*header:[[:space:]]*{[[:space:]]*name:[[:space:]]*["\047]\{0,1\}\(X-Forwarded-Attr-[A-Za-z0-9-]*\).*/\1/p' "$manifest"
  } | while read -r h; do
    [ -n "$h" ] || continue
    echo "$h"
    echo "${h//-/_}"
  done | LC_ALL=C sort -u
}

# Print "<prefix> <supporting 0|1> <exact 0|1>" for each auth.public_access
# path of a manifest (block-style list as used in this repo).
_manifest_public_paths() {
  awk '
    function flush() { if (prefix != "") print prefix, sup, ex; prefix = ""; sup = 0; ex = 0 }
    /^  public_access:/ { in_pa = 1; next }
    in_pa && /^ {0,2}[^ #]/ { flush(); in_pa = 0 }
    in_pa && /^[[:space:]]*- prefix:/ {
      flush()
      v = $0; sub(/^[[:space:]]*- prefix:[[:space:]]*/, "", v); sub(/[[:space:]]*(#.*)?$/, "", v); gsub(/["\047]/, "", v)
      prefix = v; next
    }
    in_pa && /^[[:space:]]*supporting:[[:space:]]*true/ { sup = 1 }
    in_pa && /^[[:space:]]*exact:[[:space:]]*true/ { ex = 1 }
    END { flush() }
  ' "$1"
}

# _manifest_public_list <manifest> <key>: items of a flow list under
# auth.public_access (e.g. credential_cookies: [a, b]).
_manifest_public_list() {
  sed -n "s/^    $2:[[:space:]]*\\[\\(.*\\)\\].*/\\1/p" "$1" | tr ',' '\n' | tr -d ' "\047' | sed '/^$/d'
}

# public_routed_prefixes <manifest> <all|listed> [token...]
# The entries the Hub routes (PublicPlan.Effective), sorted: "p" prefix,
# "=p" exact path, "~p" static files under p.
public_routed_prefixes() {
  local manifest="$1" mode="$2" prefix sup ex tok enc
  shift 2
  if [ "$mode" = listed ] && [ $# -eq 0 ]; then return 0; fi
  while read -r prefix sup ex; do
    prefix="${prefix%/}"
    enc="$prefix"
    if [ "$ex" = 1 ]; then enc="=$prefix"; elif [ "$sup" = 1 ]; then enc="~$prefix"; fi
    case "$prefix" in
      *\{token\}*)
        if [ "$mode" = listed ]; then
          for tok in "$@"; do echo "${prefix/\{token\}/$tok}"; done
        else
          echo "${prefix%%/\{token\}*}"
        fi ;;
      *)
        if [ "$sup" = 1 ] || [ "$mode" != listed ]; then echo "$enc"; fi ;;
    esac
  done < <(_manifest_public_paths "$manifest") | LC_ALL=C sort -u
}

# Mirror of the Hub's StaticExtensions (internal/templates/public.go).
PUBLIC_STATIC_EXTS="avif|css|eot|gif|ico|jpeg|jpg|js|map|mjs|otf|png|svg|ttf|webp|woff|woff2"

# _public_matchers <entry>: Traefik matchers for one routed entry, with
# backslashes doubled for a YAML double-quoted scalar.
_public_matchers() {
  local e="$1" p
  case "$e" in
    =*) echo "Path(\`${e#=}\`)" ;;
    ~*) p="${e#\~}"; echo "PathRegexp(\`^${p//./\\\\.}(/[A-Za-z0-9_~@+-]+)*/[A-Za-z0-9_~@+-][A-Za-z0-9._~@+-]*\\\\.($PUBLIC_STATIC_EXTS)\$\$\`)" ;;
    *) echo "Path(\`$e\`) || PathPrefix(\`$e/\`)" ;;
  esac
}

# write_public_override <app> <service> <host-arg> <tier> <out> <entry...>
# Writes the labels the Hub generates for a public router: every router of
# the compose file gets <tier> (one TLS tier per host), plus
# portcullis-public-<app> without forward-auth, behind core's public guard
# (see write_public_policy) and the strip middleware. Entries as printed by
# public_routed_prefixes.
write_public_override() {
  local app="$1" svc="$2" host="$3" tier="$4" out="$5" compose manifest r e rule="" hdr
  shift 5
  compose=$(_find_compose "$app") || { fail "compose.yml not found for $app"; return 1; }
  manifest="$(dirname "$compose")/manifest.yaml"
  for e in "$@"; do
    rule="${rule:+$rule || }$(_public_matchers "$e")"
  done
  rule="Host(\`$host\`) && ($rule)"
  # The Traefik service the public router targets: the template's only one
  # (as the Hub's PublicPlan picks it), else one named like the compose service.
  local tsvc
  tsvc=$(grep -oE 'traefik\.http\.services\.[^.]+\.' "$compose" | sort -u)
  if [ "$(printf '%s\n' "$tsvc" | grep -c .)" = 1 ]; then
    tsvc=$(printf '%s' "$tsvc" | sed -E 's/^traefik\.http\.services\.([^.]+)\.$/\1/')
  else
    tsvc="$svc"
  fi
  {
    echo "services:"
    echo "  $svc:"
    echo "    labels:"
    grep -oE 'traefik\.http\.routers\.[^.]+\.rule' "$compose" | sed -E 's/^traefik\.http\.routers\.([^.]+)\.rule$/\1/' | sort -u | while read -r r; do
      echo "      traefik.http.routers.$r.tls.options: $tier"
    done
    echo "      traefik.http.routers.portcullis-public-$app.rule: \"$rule\""
    echo "      traefik.http.routers.portcullis-public-$app.entrypoints: websecure"
    echo "      traefik.http.routers.portcullis-public-$app.tls: \"true\""
    echo "      traefik.http.routers.portcullis-public-$app.tls.options: $tier"
    echo "      traefik.http.routers.portcullis-public-$app.priority: \"10000\""
    echo "      traefik.http.routers.portcullis-public-$app.middlewares: portcullis-public-guard@docker,portcullis-public-strip-$app@docker,rate-limit@file,security-headers@file"
    echo "      traefik.http.routers.portcullis-public-$app.service: \"$tsvc\""
    _public_strip_headers "$manifest" | while read -r hdr; do
      echo "      traefik.http.middlewares.portcullis-public-strip-$app.headers.customrequestheaders.$hdr: \"\""
    done
  } > "$out"
}

# public_published_entries <manifest> <all|listed>: what the Hub publishes
# for core's public guard (PublicPlan.Effective's published list: listed
# mode keeps {token}).
public_published_entries() {
  local manifest="$1" mode="$2" prefix sup ex enc
  while read -r prefix sup ex; do
    prefix="${prefix%/}"
    enc="$prefix"
    if [ "$ex" = 1 ]; then enc="=$prefix"; elif [ "$sup" = 1 ]; then enc="~$prefix"; fi
    case "$prefix" in
      *\{token\}*) if [ "$mode" = listed ]; then echo "$prefix"; else echo "${prefix%%/\{token\}*}"; fi ;;
      *) if [ "$sup" = 1 ] || [ "$mode" != listed ]; then echo "$enc"; fi ;;
    esac
  done < <(_manifest_public_paths "$manifest") | LC_ALL=C sort -u
}

# policy_version: the policy-file version core's group-gate serves
# (POLICY_VERSION in core's group-gate/group-gate.py; any other version is
# denied, fail closed), like tests/e2e/app_signin.py. Version 5 keys the
# maps by full hostname, earlier ones by subdomain.
policy_version() {
  local v
  v=$(sed -n 's/^POLICY_VERSION[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' \
    "$PROJECT_DIR/group-gate/group-gate.py" 2>/dev/null | head -1)
  [ -n "$v" ] || { fail "cannot read POLICY_VERSION from $PROJECT_DIR/group-gate/group-gate.py"; return 1; }
  echo "$v"
}

# write_public_policy <subdomain> <manifest> <all|listed>: the policy file
# (core's version) the Hub would write for this public exception, into
# core's hub_data volume, so core's real public guard (group-gate
# /public-guard) runs in the test. clear_public_policy empties it again.
write_public_policy() {
  local sub="$1" manifest="$2" mode="$3" pattern ver key
  ver=$(policy_version) || return 1
  key="$sub"
  [ "$ver" -lt 5 ] || key="$sub.$DOMAIN"
  pattern=$(sed -n "s/^    token_pattern:[[:space:]]*['\"]\\(.*\\)['\"][[:space:]]*$/\\1/p" "$manifest")
  public_published_entries "$manifest" "$mode" | jq -R . | jq -s \
    --arg sub "$key" --argjson ver "$ver" --arg pattern "$pattern" --arg exts "$PUBLIC_STATIC_EXTS" \
    --argjson extra_exts "$(_manifest_public_list "$manifest" static_extensions | jq -R . | jq -s .)" \
    --argjson headers "$(_manifest_public_list "$manifest" credential_headers | jq -R . | jq -s .)" \
    --argjson cookies "$(_manifest_public_list "$manifest" credential_cookies | jq -R . | jq -s .)" \
    --argjson query "$(_manifest_public_list "$manifest" credential_query | jq -R . | jq -s .)" '
      {version: $ver, public_paths: {($sub): ({
        paths: map(if startswith("=") then {path: .[1:], match: "exact"}
                   elif startswith("~") then {path: .[1:], match: "static"}
                   else {path: ., match: "prefix"} end),
        static_extensions: (($exts | split("|")) + $extra_exts | unique),
        credential_headers: (["Authorization", "Proxy-Authorization"] + $headers),
        credential_cookies: $cookies, credential_query: $query}
        + (if $pattern != "" then {token_pattern: $pattern} else {} end))}}' | _hub_data_write
}

clear_public_policy() {
  local ver
  ver=$(policy_version) || return 1
  printf '{"version": %s}' "$ver" | _hub_data_write
}

# Write stdin as group-gate-policy.json into core's hub_data volume
# (atomically), using the image group-gate already runs (no extra pull).
_hub_data_write() {
  local cid image
  cid=$(docker ps -q --filter label=com.docker.compose.project=portcullis --filter label=com.docker.compose.service=group-gate | head -1)
  [ -n "$cid" ] || { fail "group-gate is not running"; return 1; }
  image=$(docker inspect -f '{{.Config.Image}}' "$cid")
  docker run --rm -i --user 0 --entrypoint sh -v portcullis_hub_data:/d "$image" \
    -c 'cat > /d/.policy.tmp && chmod 644 /d/.policy.tmp && mv /d/.policy.tmp /d/group-gate-policy.json'
}

# via_traefik <host> <path> [curl args...]: "<code> <redirect_url>" of an
# HTTPS request through Traefik on the CI host (no client certificate).
via_traefik() {
  local host="$1" path="$2"
  shift 2
  curl -sk -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 15 \
    --resolve "$host:443:127.0.0.1" "$@" "https://$host$path" 2>/dev/null || echo "000 "
}

# assert_public_path <host> <path> [curl args...]: answered by the app, not
# sent to Keycloak.
assert_public_path() {
  local out code loc host="$1" path="$2"
  shift 2
  out=$(via_traefik "$host" "$path" "$@"); code=${out%% *}; loc=${out#* }
  if echo "$loc" | grep -q "auth\.$DOMAIN"; then
    fail "public $path → redirected to Keycloak ($code $loc)"
  elif [ "$code" = 403 ]; then
    fail "public $path → HTTP 403 (refused by the public guard: wrong policy file or path list?)"
  elif [ "$code" = 000 ] || [ "$code" = 502 ] || [ "$code" = 421 ] || [ "$code" -ge 500 ] 2>/dev/null; then
    fail "public $path → HTTP $code (not answered by the app)"
  else
    pass "public $path → HTTP $code, no Keycloak redirect"
  fi
}

# assert_public_refused <host> <path> [curl args...]: core's public guard
# answers 403 (a credential, or a path outside the published patterns).
assert_public_refused() {
  local out code loc host="$1" path="$2"
  shift 2
  out=$(via_traefik "$host" "$path" "$@"); code=${out%% *}; loc=${out#* }
  if [ "$code" = 403 ] && [ -z "$loc" ]; then
    pass "public $path ${*:+($*)} → refused by the public guard (403)"
  else
    fail "public $path ${*:+($*)} → expected 403 from the public guard, got $code ${loc:-<none>}"
  fi
}

# assert_gated_path <host> <path> [curl args...]: still behind forward-auth.
assert_gated_path() {
  local out code loc host="$1" path="$2"
  shift 2
  out=$(via_traefik "$host" "$path" "$@"); code=${out%% *}; loc=${out#* }
  if echo "$loc" | grep -q "auth\.$DOMAIN"; then
    pass "gated $path → HTTP $code to Keycloak"
  else
    fail "gated $path → expected a redirect to auth.$DOMAIN, got $code ${loc:-<none>}"
  fi
}

# ── Data files (settings file delivery, contract §13.7) ────
# write_appfiles_override <app> <name> <json> <out>: emulate the Hub's
# delivery of the manifest's files[] entry <name>: <json> is written as
# <name>.json into a temporary directory (APPFILES_DIR/<app>/<name>, mode
# 0640 group 10001 like the Hub's, 0644 when the group can't be set), and
# <out> becomes a compose override that bind-mounts that directory (never the
# single file: the Hub replaces it by rename) read-only at the entry's mount
# in its service. Use <out> as COMPOSE_OVERRIDE. Change the file later with
# write_appfile <app> <name> <json> (or delete it) and restart the service.
write_appfiles_override() {
  local app="$1" name="$2" json="$3" out="$4" compose manifest svc mount
  compose=$(_find_compose "$app") || { fail "compose.yml not found for $app"; return 1; }
  manifest="$(dirname "$compose")/manifest.yaml"
  svc=$(yq -r ".files[] | select(.name == \"$name\") | .service" "$manifest")
  mount=$(yq -r ".files[] | select(.name == \"$name\") | .mount" "$manifest")
  if [ -z "$svc" ] || [ "$svc" = null ] || [ -z "$mount" ] || [ "$mount" = null ]; then
    fail "$app: no files[] entry $name in the manifest"; return 1
  fi
  APPFILES_DIR="${APPFILES_DIR:-$(mktemp -d)}"
  export APPFILES_DIR
  mkdir -p "$APPFILES_DIR/$app/$name"
  chmod 0755 "$APPFILES_DIR" "$APPFILES_DIR/$app" "$APPFILES_DIR/$app/$name"
  write_appfile "$app" "$name" "$json" || return 1
  printf 'services:\n  %s:\n    volumes:\n      - type: bind\n        source: %s\n        target: %s\n        read_only: true\n' \
    "$svc" "$APPFILES_DIR/$app/$name" "$mount" > "$out"
}

# write_appfile <app> <name> <json>: (re)write the data file atomically.
write_appfile() {
  local dir="$APPFILES_DIR/$1/$2" tmp
  [ -d "$dir" ] || { fail "write_appfiles_override $1 $2 first"; return 1; }
  tmp="$dir/.$2.json.tmp"
  printf '%s' "$3" > "$tmp"
  if chgrp 10001 "$tmp" 2>/dev/null || sudo -n chgrp 10001 "$tmp" 2>/dev/null; then
    chmod 0640 "$tmp" 2>/dev/null || sudo -n chmod 0640 "$tmp"
  else
    info "data file group 10001 not settable here: $2.json is 0644"
    chmod 0644 "$tmp"
  fi
  mv -f "$tmp" "$dir/$2.json" 2>/dev/null || sudo -n mv -f "$tmp" "$dir/$2.json"
}
