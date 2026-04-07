#!/usr/bin/env bash
# Test: Vaultwarden (native OIDC SSO)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="vaultwarden"
section "Vaultwarden"

APP_ID=vaultwarden
SUBDOMAIN=passwords

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:80" 60 "$APP_ID"

# Homepage should contain SSO-related content
BODY=$(curl -sf "http://${IP}:80/" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "bitwarden\|vaultwarden\|<html"; then
  pass "/ -> Vaultwarden page returned"
else
  fail "/ -> Vaultwarden page not found"
fi

# Verify SSO is enabled via environment
SSO_ENABLED=$(docker exec "portcullis-${APP_ID}-1" printenv SSO_ENABLED 2>/dev/null || echo "")
if [ "$SSO_ENABLED" = "true" ]; then
  pass "SSO_ENABLED=true"
else
  fail "SSO_ENABLED expected 'true', got '$SSO_ENABLED'"
fi

compose_down "$APP_ID"
