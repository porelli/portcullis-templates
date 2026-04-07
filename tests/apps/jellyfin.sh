#!/usr/bin/env bash
# Test: Jellyfin (native OIDC + SSO plugin + group enforcement)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="jellyfin"
section "Jellyfin"

APP_ID=jellyfin
SUBDOMAIN=media

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
# Jellyfin needs extra time — setup sidecar runs first
wait_for_url "http://${IP}:8096" 120 "$APP_ID"

# Wait for setup sidecar to finish (if it exists)
info "Waiting for setup sidecar to complete..."
docker wait "portcullis-jellyfin-setup-1" 2>/dev/null || true

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

compose_down "$APP_ID"
