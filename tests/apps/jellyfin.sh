#!/usr/bin/env bash
# Test: Jellyfin (native OIDC + SSO plugin + group enforcement)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="jellyfin"
section "Jellyfin"

APP_ID=jellyfin

# Static: SSO plugin keys users on the LLDAP username, requests no email
SETUP="$(dirname "$(_find_compose "$APP_ID")")/setup.py"
if grep -q '"DefaultUsernameClaim": "preferred_username"' "$SETUP" && ! grep -q '"email"' "$SETUP"; then
  pass "SSO plugin DefaultUsernameClaim=preferred_username, no email scope"
else
  fail "SSO plugin must use DefaultUsernameClaim preferred_username and no email scope"
fi

# Static: no package installs at runtime; the SSO plugin is pinned by
# version + SHA-256 and installed before Jellyfin starts
DIR="$(dirname "$(_find_compose "$APP_ID")")"
if ! grep -qE 'pip3? install' "$DIR/compose.yml" && grep -qE '^SHA256 = "[0-9a-f]{64}"$' "$DIR/plugin.py" \
    && grep -q 'condition: service_completed_successfully' "$DIR/compose.yml"; then
  pass "SSO plugin pinned (version + sha256), installed before Jellyfin, no pip"
else
  fail "SSO plugin must be pinned by sha256 in plugin.py and installed by jellyfin-plugin (no pip)"
fi

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
# Jellyfin needs extra time — setup sidecar runs first
wait_for_url "http://${IP}:8096" 120 "$APP_ID"

# Wait for setup sidecar to finish (if it exists)
info "Waiting for setup sidecar to complete..."
SETUP_RC=$(docker wait "portcullis-jellyfin-setup-1" 2>/dev/null || echo "?")
if [ "$SETUP_RC" = "0" ]; then
  pass "jellyfin-setup completed"
else
  docker logs "portcullis-jellyfin-setup-1" 2>&1 | tail -30 || true
  fail "jellyfin-setup exited $SETUP_RC"
fi

# Jellyfin should respond on its web endpoint
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "http://${IP}:8096/web/index.html" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 400 ]; then
  pass "/web/index.html -> HTTP $HTTP_CODE"
else
  fail "/web/index.html -> expected HTTP 2xx/3xx, got $HTTP_CODE"
fi

# Public info endpoint should respond
BODY=$(curl -sf "http://${IP}:8096/System/Info/Public" 2>/dev/null || echo "{}")
if echo "$BODY" | grep -qi "ServerName\|ProductName\|jellyfin"; then
  pass "/System/Info/Public -> Jellyfin info returned"
else
  fail "/System/Info/Public -> Jellyfin info not found"
fi

# The local admin has no password login on the ungated router any more
AUTH_HDR='MediaBrowser Client="ci", Device="ci", DeviceId="ci", Version="1.0"'
LOGIN_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://${IP}:8096/Users/AuthenticateByName" \
  -H "Authorization: $AUTH_HDR" -H 'Content-Type: application/json' \
  --data "{\"Username\":\"admin\",\"Pw\":\"${JELLYFIN_ADMIN_PASSWORD:-}\"}" 2>/dev/null || echo "000")
if [ -n "${JELLYFIN_ADMIN_PASSWORD:-}" ] && [ "$LOGIN_CODE" != "200" ] && [ "$LOGIN_CODE" != "000" ]; then
  pass "local admin password login refused (HTTP $LOGIN_CODE)"
else
  fail "local admin password login not refused (HTTP $LOGIN_CODE)"
fi

compose_down "$APP_ID"
