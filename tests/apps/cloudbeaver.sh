#!/usr/bin/env bash
# Test: CloudBeaver (header-auth behind nginx gate + forward-auth + group-gate)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="cloudbeaver"
section "CloudBeaver"

APP_ID=cloudbeaver

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:8978" 60 "$APP_ID"

# CloudBeaver should return HTML
BODY=$(curl -sf "http://${IP}:8978/" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "cloudbeaver\|<html"; then
  pass "/ -> CloudBeaver page returned"
else
  fail "/ -> CloudBeaver page not found"
fi

# Verify compose has forward-auth + group-gate middleware
COMPOSE=$(_find_compose "$APP_ID")
if grep -q 'portcullis-auth@docker' "$COMPOSE" && grep -q 'portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Missing forward-auth or group-gate middleware in compose"
fi

# Static: CloudBeaver itself stays off portcullis-proxy; only the gate is
# routed by Traefik and it trusts X-Forwarded-User from Traefik alone
assert_traefik_only_trust "$COMPOSE" PORTCULLIS_TRAEFIK_IP
CB_NETS=$(docker compose -f "$COMPOSE" --project-directory "$PROJECT_DIR" config --format json 2>/dev/null \
  | jq -r '.services.cloudbeaver.networks // {} | keys | join(",")' 2>/dev/null || echo "")
if [ "$CB_NETS" = "default" ]; then
  pass "cloudbeaver is on the default network only"
else
  fail "cloudbeaver networks: expected 'default', got '$CB_NETS'"
fi

GATE_IP=$(app_container_ip "$APP_ID" cloudbeaver-gate)
assert_http_code "http://${GATE_IP}:8978/" 200
assert_spoofed_identity_rejected "http://${GATE_IP}:8978/" 403

compose_down "$APP_ID"
