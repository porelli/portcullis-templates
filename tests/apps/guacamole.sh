#!/usr/bin/env bash
# Test: Apache Guacamole (forward-auth + HTTP header auth)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="guacamole"
section "Guacamole"

APP_ID=guacamole
SUBDOMAIN=remote

COMPOSE=$(_find_compose "$APP_ID" || true)

# Static: header auth uses the image's HEADER_ENABLED switch, behind forward-auth
if grep -q 'HEADER_ENABLED: "true"' "$COMPOSE" && grep -q 'HTTP_AUTH_HEADER: X-Forwarded-User' "$COMPOSE"; then
  pass "Header auth enabled (HEADER_ENABLED + HTTP_AUTH_HEADER)"
else
  fail "Header auth not configured (expected HEADER_ENABLED and HTTP_AUTH_HEADER)"
fi

if grep -q 'portcullis-auth@docker,portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Forward-auth + group-gate middleware missing"
fi

# Static: default guacadmin/guacadmin password is replaced at DB init
if grep -q "WHERE e.name = 'guacadmin'" "$COMPOSE" && grep -q 'GUACAMOLE_ADMIN_PASSWORD' "$COMPOSE"; then
  pass "guacadmin default password replaced at DB init"
else
  fail "guacadmin default password is not replaced"
fi

# Static: the header extension has no allowlist; a Tomcat RewriteValve
# rejects X-Forwarded-User from any peer other than Traefik
assert_traefik_only_trust "$COMPOSE" PORTCULLIS_TRAEFIK_IP
if grep -q 'org.apache.catalina.valves.rewrite.RewriteValve' "$COMPOSE" && grep -q 'RewriteRule .\* - \[F\]' "$COMPOSE"; then
  pass "RewriteValve forbids X-Forwarded-User from non-Traefik peers"
else
  fail "RewriteValve guarding X-Forwarded-User is missing"
fi

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:8080/guacamole/" 90 "$APP_ID"

# Homepage should return the Guacamole login page
BODY=$(curl -sf "http://${IP}:8080/guacamole/" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "guacamole"; then
  pass "/ → Guacamole login page returned"
else
  fail "/ → Guacamole login page not found"
fi

# The CI host is not Traefik: the token endpoint must refuse a spoofed header
assert_spoofed_identity_rejected "http://${IP}:8080/guacamole/api/tokens" 403 -X POST

compose_down "$APP_ID"
