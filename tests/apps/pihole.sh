#!/usr/bin/env bash
# Test: Pi-hole (forward-auth + group-gate; no Pi-hole password, web ACL)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="pihole"
section "Pi-hole"

APP_ID=pihole

COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }

# Traefik routing enabled
if grep -q 'traefik.enable.*true' "$COMPOSE"; then
  pass "Traefik routing enabled"
else
  fail "Traefik routing not configured"
fi

# Forward-auth + group-gate middleware
if grep -q 'portcullis-auth@docker' "$COMPOSE" && grep -q 'portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Missing forward-auth or group-gate middleware in compose"
fi

# No second login: empty password, web server only for Traefik + loopback,
# Host check against the instance hostname
assert_compose_setting "$COMPOSE" FTLCONF_webserver_api_password '""'
if grep -Eq '^[[:space:]]*FTLCONF_webserver_acl:[[:space:]]*\+\$\{PORTCULLIS_TRAEFIK_SOURCE:-172\.31\.250\.2/32\},\+127\.0\.0\.1,\+\[::1\][[:space:]]*$' "$COMPOSE"; then
  pass "FTLCONF_webserver_acl allows only \${PORTCULLIS_TRAEFIK_SOURCE} and loopback"
else
  fail "FTLCONF_webserver_acl must be +\${PORTCULLIS_TRAEFIK_SOURCE:-172.31.250.2/32},+127.0.0.1,+[::1]"
fi
assert_compose_setting "$COMPOSE" FTLCONF_webserver_domain '\$\{PORTCULLIS_HOST_PIHOLE:-pihole\.portcullis\.local\}'

# Service port matches Traefik label
if grep -q 'loadbalancer.server.port.*80' "$COMPOSE"; then
  pass "Traefik loadbalancer port is 80"
else
  fail "Traefik loadbalancer port mismatch (expected 80)"
fi

# DNS ports declared in manifest (Hub writes bindings into the per-app override)
MANIFEST="$(dirname "$COMPOSE")/manifest.yaml"
if grep -q 'PIHOLE_DNS_TCP_HOST' "$MANIFEST" && grep -q 'PIHOLE_DNS_UDP_HOST' "$MANIFEST"; then
  pass "DNS ports declared in manifest"
else
  fail "DNS ports not declared in manifest"
fi

compose_up "$APP_ID"
IP=$(app_container_ip "$APP_ID")
C=portcullis-pihole-1

# Wait until FTL answers inside the container (loopback is allowed)
for _ in $(seq 1 60); do
  docker exec "$C" curl -sf -o /dev/null http://127.0.0.1/api/info/version 2>/dev/null && break
  sleep 2
done
if docker exec "$C" curl -sf http://127.0.0.1/api/info/version 2>/dev/null | grep -q '"version"'; then
  pass "API answers on loopback without a password"
else
  fail "API does not answer on loopback without a password"
fi

# Any peer but Traefik (here: the CI host) is refused by the web server ACL:
# civetweb accepts the connection and drops it (curl: empty reply / reset)
# or answers 403; never a page.
for path in /api/info/version /admin/; do
  rc=0
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://${IP}${path}" 2>/dev/null) || rc=$?
  case "$code:$rc" in
    403:*|000:52|000:56) pass "$path from a non-Traefik peer refused (HTTP $code, curl $rc)" ;;
    *) fail "$path from a non-Traefik peer: HTTP $code, curl $rc (expected refusal)" ;;
  esac
done

compose_down "$APP_ID"
